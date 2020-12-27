{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
-- | This library implements a parser for the Portable Executable format
--
-- The usage pattern of the library is to first parse 'BS.ByteString's into a
-- 'PEHeaderInfo', which can be inspected to determine the architecture and
-- other relevant information.  The 'PEHeaderInfo' can then be parsed into a
-- full 'PE' structure.
--
-- The two-phased parsing allows the errors to be separated out, supporting some
-- binary analysis even if parsing some sections fails.
--
-- Design goals:
--
-- * The library should never call error (unless there is a proof that it cannot fail)
-- * Magic strings are never stored
-- * Un-parsed data should be preserved so that it can be reproduced into a new PE file as losslessly as possible
--
-- Note that Portable Executable container values are always Little Endian (even if code/data are Big Endian)
module PE.Parser (
  -- * Headers
  decodePEHeaderInfo,
  validatePEHeaderInfo,
  PEHeaderInfo(..),
  parsePEHeaderInfo,
  ppPEHeaderInfo,
  -- ** Top-level header structures
  module PPH,
  -- ** Architecture size handling
  PPW.PEClass(..),
  PPW.PEWord,
  -- ** Data Directories
  module PPDDE,
  -- ** Sections
  module PPS,
  Section(..),
  getSection,
  HasDataDirectoryEntry(..),
  getDataDirectoryEntry,
  SomeDataDirectoryEntry(..),
  allDataDirectoryEntries,
  -- ** Pre-defined machine types
  module PPM,
  -- ** Subsystems
  module PPSu,
  -- ** Flags
  -- *** Characteristics
  module PPC,
  -- *** DLL Flags
  module PPDLL,
  -- ** Directory Entries
  -- *** Export Directory Table
  module PPEDT,
  -- *** Import Directory Table
  module PPIDT,
  -- *** Base Relocation Table
  module PPBR,
  -- *** Exception Table
  module PPET,
  -- * Exceptions
  PEException(..)
  ) where

import           Control.Monad ( replicateM )
import qualified Control.Monad.Catch as X
import qualified Data.Binary.Get as G
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Foldable as F
import qualified Data.Functor.Const as FC
import qualified Data.Functor.Identity as FI
import           Data.Int ( Int64 )
import           Data.Kind ( Type )
import           Data.Parameterized.Some ( Some(..) )
import           Data.Proxy ( Proxy(..) )
import           Data.Word ( Word16, Word32 )
import qualified Prettyprinter as PP

import           PE.Parser.BaseRelocation as PPBR
import           PE.Parser.Characteristics as PPC
import           PE.Parser.DLLFlags as PPDLL
import           PE.Parser.DataDirectoryEntry as PPDDE
import           PE.Parser.ExceptionTable as PPET
import           PE.Parser.ExportDirectoryTable as PPEDT
import           PE.Parser.Headers as PPH
import           PE.Parser.ImportDirectoryTable as PPIDT
import           PE.Parser.Machine as PPM
import           PE.Parser.PEWord as PPW
import           PE.Parser.SectionHeader as PPS
import           PE.Parser.Subsystem as PPSu


parseSectionTable :: Word16 -> G.Get [PPS.SectionHeader]
parseSectionTable numEntries = replicateM (fromIntegral numEntries) PPS.parseSectionHeader

-- | This combined header includes information that should probably never fail
-- to parse:
--
-- * The DOSHeader
-- * The PE Header
-- * The PE Optional Header
--
-- The intent is that this is parsed initially and inspected to determine the
-- architecture.  A subsequent parsing pass can then extract the full PE
-- structure.  There are more potential failure points when decoding the actual
-- sections, and separating the two at least makes it possible to analyze a
-- header.
--
-- The @f@ parameter is the "container" for the PEOptionalHeader, which is
-- optional for COFF object files but not for executable files.  After
-- validation, this can be converted from a 'Maybe' to an 'Identity', so that
-- code requiring the 'PEOptionalHeader' can express that dependency.
--
-- The 'PEHeaderInfo' retains the bytestring it was parsed from so that the
-- second phase (parsing out section contents) is guaranteed to work on the same
-- bytestring.
data PEHeaderInfo f w =
  PEHeaderInfo { dosHeader :: PPH.DOSHeader
               , peHeader :: PPH.PEHeader
               , peOptionalHeader :: f (PPH.PEOptionalHeader w)
               , peSectionHeaders :: [PPS.SectionHeader]
               , peContents :: BSL.ByteString
               }

deriving instance (Show (f (PPH.PEOptionalHeader w))) => Show (PEHeaderInfo f w)


ppPEHeaderInfo :: PEHeaderInfo Maybe w -> PP.Doc ann
ppPEHeaderInfo phi =
  PP.vsep [ PPH.ppPEHeader (peHeader phi)
          -- FIXME: Add a header to mark out the optional headers
          , maybe mempty (PPH.ppPEOptionalHeader (peSectionHeaders phi)) (peOptionalHeader phi)
          , PP.pretty "Sections:"
          , PP.indent 4 (PP.vsep (map ppsh (zip [0..] (peSectionHeaders phi))))
          ]
  where
    ppsh (idx, shdr) =
      PP.vsep [ PP.pretty "Section " <> PP.pretty (idx :: Int)
              , PP.indent 4 (PPS.ppSectionHeader shdr)
              ]

parsePEHeaderInfo :: BSL.ByteString -> G.Get (Some (PEHeaderInfo Maybe))
parsePEHeaderInfo contents = do
  -- We record the initial offset, as the PEOffset within the DOS header is
  -- relative to this number.  We could assume it to be zero, but this parser
  -- could in theory be run in some other context where it is not.
  initialOffset <- G.bytesRead
  dh <- PPH.parseDOSHeader
  G.skip (fromIntegral (PPH.dosHeaderPEOffset dh - PPH.dosHeaderSize - fromIntegral initialOffset))

  -- Immediately followed by the PE Header (which checks the magic signature)
  peh <- PPH.parsePEHeader

  case PPH.peHeaderSizeOfOptionalHeader peh of
    0 -> do
      secTable <- parseSectionTable (PPH.peHeaderNumberOfSections peh)
      let hdr = PEHeaderInfo { dosHeader = dh
                             , peHeader = peh
                             , peOptionalHeader = Nothing
                             , peSectionHeaders = secTable
                             , peContents = contents
                             }
      return (Some hdr)
    optHeaderSize -> do
      -- Immediately followed by the PE Optional Header (which has its size
      -- quantified away because we can't know until we start parsing it)
      Some peoh <- PPH.parsePEOptionalHeader optHeaderSize
      secTable <- parseSectionTable (PPH.peHeaderNumberOfSections peh)
      let hdr = PEHeaderInfo { dosHeader = dh
                             , peHeader = peh
                             , peOptionalHeader = Just peoh
                             , peSectionHeaders = secTable
                             , peContents = contents
                             }
      return (Some hdr)


decodePEHeaderInfo :: BSL.ByteString -> Either (Int64, String) (Some (PEHeaderInfo Maybe))
decodePEHeaderInfo bs =
  case G.runGetOrFail (parsePEHeaderInfo bs) bs of
    Left (_, off, msg) -> Left (off, msg)
    Right (_, _, phi) -> Right phi

validatePEHeaderInfo :: PEHeaderInfo Maybe w -> Either (PEHeaderInfo (FC.Const ()) w) (PEHeaderInfo FI.Identity w)
validatePEHeaderInfo phi =
  case peOptionalHeader phi of
    Just optHdr ->
      Right PEHeaderInfo { dosHeader = dosHeader phi
                         , peHeader = peHeader phi
                         , peOptionalHeader = FI.Identity optHdr
                         , peSectionHeaders = peSectionHeaders phi
                         , peContents = peContents phi
                         }
    Nothing ->
      Left PEHeaderInfo { dosHeader = dosHeader phi
                        , peHeader = peHeader phi
                        , peOptionalHeader = FC.Const ()
                        , peSectionHeaders = peSectionHeaders phi
                        , peContents = peContents phi
                        }

data Section =
  Section { sectionHeader :: PPS.SectionHeader
          , sectionContents :: BSL.ByteString
          }

-- | Look up the contents of a 'Section'
--
-- This could fail if the data is missing from the underlying bytestring
getSection :: (X.MonadThrow m) => PEHeaderInfo f w -> PPS.SectionHeader -> m Section
getSection phi secHeader = do
  if BSL.length content == fromIntegral (PPS.sectionHeaderSizeOfRawData secHeader)
    then return Section { sectionHeader = secHeader
                        , sectionContents = content
                        }
    else X.throwM (SectionContentsSizeMismatch secHeader (BSL.length (peContents phi)))
  where
    prefix = BSL.drop (fromIntegral (PPS.sectionHeaderPointerToRawData secHeader)) (peContents phi)
    content = BSL.take (fromIntegral (PPS.sectionHeaderSizeOfRawData secHeader)) prefix

data Warning = Warning
  deriving (Show)

data PEException = MissingDirectoryEntry (Some PPDDE.DataDirectoryEntryName)
                 -- ^ The named 'DataDirectoryEntry' is not present in the file (the table entry is missing or zero)
                 | DirectoryEntryAddressNotMapped [PPS.SectionHeader] PPDDE.DataDirectoryEntry
                 -- ^ The address named in the 'DataDirectoryEntry' is not mapped in any of the sections defined in the executable
                 | DirectoryEntryParseFailure (Some PPDDE.DataDirectoryEntryName) PPDDE.DataDirectoryEntry Int64 String
                 -- ^ The 'DataDirectoryEntry' named could not be parsed
                 | SectionContentsSizeMismatch PPS.SectionHeader Int64
                 -- ^ The given 'PPS.SectionHeader' declares an offset (and
                 -- size) for this section that does not match the available
                 -- byte count in the bytestring
  deriving (Show)

instance X.Exception PEException

class HasDataDirectoryEntry (entry :: PPDDE.DataDirectoryEntryKind) where
  type DataDirectoryEntryType entry :: Type
  dataDirectoryEntryParser :: proxy entry -> PPH.PEHeader -> Word32 -> G.Get (DataDirectoryEntryType entry)
  ppDataDirectoryEntryValue :: proxy entry -> DataDirectoryEntryType entry -> PP.Doc ann

instance HasDataDirectoryEntry 'PPDDE.ExportTableK where
  type DataDirectoryEntryType 'PPDDE.ExportTableK = PPEDT.ExportDirectoryTable
  dataDirectoryEntryParser _ _ _ = PPEDT.parseExportDirectoryTable
  ppDataDirectoryEntryValue _ = PPEDT.ppExportDirectoryTable

instance HasDataDirectoryEntry 'PPDDE.ImportTableK where
  type DataDirectoryEntryType 'PPDDE.ImportTableK = PPIDT.ImportDirectoryTable
  dataDirectoryEntryParser _ _ _ = PPIDT.parseImportDirectoryTable
  ppDataDirectoryEntryValue _ = PPIDT.ppImportDirectoryTable

instance HasDataDirectoryEntry 'PPDDE.BaseRelocationTableK where
  type DataDirectoryEntryType 'PPDDE.BaseRelocationTableK = PPBR.BaseRelocationBlock
  dataDirectoryEntryParser _ _ _ = PPBR.parseBaseRelocationBlock
  ppDataDirectoryEntryValue _ = PPBR.ppBaseRelocationBlock

instance HasDataDirectoryEntry 'PPDDE.ExceptionTableK where
  type DataDirectoryEntryType 'PPDDE.ExceptionTableK = PPET.ExceptionTable
  dataDirectoryEntryParser _ = PPET.parseExceptionTable
  ppDataDirectoryEntryValue _ = PPET.ppExceptionTable

-- | An existential wrapper around 'PPDE.DataDirectoryEntry' that captures the
-- 'HasDataDirectoryEntry' constraint
data SomeDataDirectoryEntry where
  SomeDataDirectoryEntry :: (HasDataDirectoryEntry entry) => PPDDE.DataDirectoryEntryName entry -> SomeDataDirectoryEntry

-- | All 'PPDE.DataDirectoryEntry' values that can be deeply inspected by this library
allDataDirectoryEntries :: [SomeDataDirectoryEntry]
allDataDirectoryEntries =
  [ SomeDataDirectoryEntry PPDDE.ExportTableEntry
  , SomeDataDirectoryEntry PPDDE.ImportTableEntry
  , SomeDataDirectoryEntry PPDDE.BaseRelocationTableEntry
  , SomeDataDirectoryEntry PPDDE.ExceptionTableEntry
  ]

-- | Parse the contents of the a 'PPDDE.DataDirectoryEntry' (given the name of
-- that entry) from the file, if it is present.
--
-- The type of the return value is determined by the type family
-- 'DataDirectoryEntryType' (i.e., the table type of the 'PPDDE.ExportTable' is
-- 'PPEDT.ExportDataTable')
--
-- This can fail (via 'X.MonadThrow') if the PE does not contain a the table
-- entry (i.e., it is not in the Data Directory or is marked as explicitly not
-- present in the Data Directory).n Export Directory Table (i.e., if it is not a
-- DLL), or if no mapped section contains the address named in the export
-- directory table descriptor.
getDataDirectoryEntry :: forall entry w m
                       . (X.MonadThrow m, HasDataDirectoryEntry entry)
                      => PPDDE.DataDirectoryEntryName entry
                       -- ^ The data directory entry whose contents should be extracted
                      -> PEHeaderInfo FI.Identity w
                      -- ^ The PE header to parse
                      -> m (DataDirectoryEntryType entry)
getDataDirectoryEntry dirEntryName phi = do
  let optHeader = FI.runIdentity (peOptionalHeader phi)
  let entries = PPH.peOptionalHeaderIndexDirectoryEntries optHeader
  case F.find (PPDDE.isDirectoryEntry dirEntryName) entries of
    Nothing -> X.throwM (MissingDirectoryEntry (Some dirEntryName))
    Just (_, dde) -> do
      let secHeaders = peSectionHeaders phi
      case PPDDE.findDataDirectoryEntrySection secHeaders dde of
        Nothing -> X.throwM (DirectoryEntryAddressNotMapped secHeaders dde)
        Just containingSection -> do
          let offsetInSection = PPDDE.dataDirectoryEntryAddress dde - PPS.sectionHeaderVirtualAddress containingSection
          sec <- getSection phi containingSection
          let tableStart = BSL.drop (fromIntegral offsetInSection) (sectionContents sec)
          let parser = dataDirectoryEntryParser (Proxy @entry) (peHeader phi) (PPDDE.dataDirectoryEntrySize dde)
          case G.runGetOrFail parser tableStart of
            Left (_, errOff, msg) -> X.throwM (DirectoryEntryParseFailure (Some dirEntryName) dde errOff msg)
            Right (_, _, edt) -> return edt

