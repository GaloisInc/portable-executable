{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE UndecidableInstances #-}
-- | This library implements a parser for the Portable Executable format
--
-- The usage pattern of the library is to first parse 'BS.ByteString's into a
-- 'PEHeaderInfo', which can be inspected to determine the architecture and
-- other relevant information.  The 'PEHeaderInfo' can then be used to parse out
-- section contents and more specialized metadata tables.
--
-- The two-phased parsing allows the errors to be separated out, supporting some
-- binary analysis even if parsing some sections fails.
--
-- = Design goals
--
-- * The library should never call error (unless there is a proof that it cannot fail)
-- * Magic strings are never stored
-- * Un-parsed data should be preserved so that it can be reproduced into a new PE file as losslessly as possible
--
--
-- = PE Concepts
--
-- == Endianness
--
-- The Portable Executable container format is always Little Endian, even if
-- code/data are Big Endian.
--
-- == Image Base
--
-- The Image Base applies to executable images (executables and DLLs) that are
-- mapped into memory at run-time.  The requested Image Base is specified in the
-- 'PPH.PEOptionalHeader' (which is not optional for executables or DLLs).  The
-- image base is the absolute address (in either a 32 bit or 64 bit address
-- space) that the image is mapped at.
--
-- Relocations are applied based on the /difference/ between the actual image
-- base chosen and the initial requested base address.
--
-- == Relative Virtual Addresses
--
-- Most addresses in a PE file are specified as Relative Virtual Addresses
-- (RVAs).  These are (unsigned) 32 bit offsets from the Image Base.
--
-- == 'PPW.PEWord'
--
-- The 'PPW.PEWord' type represents values that depend on the pointer size of an
-- architecture. In practice, this just means that the value can be either 32 or
-- 64 bits.  There are a number of helpers for working with these variable size
-- words.
--
-- = Usage Example
--
-- Typical use of this library looks something like:
--
-- >>> import qualified Data.ByteString.Lazy as BSL
-- >>> import           Data.Parameterized.Some ( Some(..) )
-- >>> import qualified PE.Parser as PE
-- >>> :{
-- parsePEFile :: FilePath -> IO ()
-- parsePEFile peFilePath = do
--   bytes <- BSL.readFile peFilePath
--   case PE.decodePEHeaderInfo bytes of
--     Left (off, msg) -> fail ("Error parsing PE file at offset " ++ show off ++ ": " ++ msg)
--     Right (Some header) -> do
--       -- Print out the contents of all of the headers that are present
--       putStrLn (show (PE.ppPEHeaderInfo header))
--       case PE.validatePEHeaderInfo header of
--         Left {} -> do
--           -- There is no PE Optional Header (and thus no Data Directory)
--           return ()
--         Right allHeaders -> do
--           exceptionTable <- PE.getDataDirectoryEntry PE.ExceptionTableEntry allHeaders
--           putStrLn (show (PE.ppExceptionTable exceptionTable))
-- :}
module PE.Parser (
  -- * Top-level API
  decodePEHeaderInfo,
  validatePEHeaderInfo,
  PEHeaderInfo(..),
  parsePEHeaderInfo,
  ppPEHeaderInfo,
  -- * Top-level header structures
  module PPH,
  -- ** Sections
  module PPS,
  Section(..),
  getSection,
  -- ** Data Directories
  module PPDDE,
  HasDataDirectoryEntry(..),
  getDataDirectoryEntry,
  SomeDataDirectoryEntry(..),
  allDataDirectoryEntries,
  -- ** Architecture size handling
  PPW.PEClass(..),
  PPW.PEWord,
  PPW.PEConstraints,
  PPW.withPEConstraints,
  -- ** Pre-defined machine types
  module PPM,
  -- ** Subsystems
  module PPSu,
  -- ** Flags
  -- *** File Flags
  module PPFF,
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
import           PE.Parser.FileFlags as PPFF
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
-- validation, this can be converted from a 'Maybe' to an 'FI.Identity', so that
-- code requiring the 'PPH.PEOptionalHeader' can express that dependency.
--
-- The 'PEHeaderInfo' retains the bytestring it was parsed from so that the
-- second phase (parsing out section contents) is guaranteed to work on the same
-- bytestring.
data PEHeaderInfo f w =
  PEHeaderInfo { dosHeader :: PPH.DOSHeader
               -- ^ The legacy DOS header; the contents are mostly ignored
               -- except for verifying the signature and the pointer to the
               -- actual 'PPH.PEHeader'
               , peHeader :: PPH.PEHeader
               -- ^ The required 'PPH.PEHeader', which contains basic
               -- information about the binary
               , peOptionalHeader :: f (PPH.PEOptionalHeader w)
               -- ^ The 'PPH.PEOptionalHeader', which is only optional for
               -- object files.
               , peSectionHeaders :: [PPS.SectionHeader]
               -- ^ Parsed 'PPS.SectionHeader's
               , peContents :: BSL.ByteString
               -- ^ The original contents from which the 'PEHeaderInfo' was
               -- parsed; this is retained so that later decoding passes always
               -- reference the correct 'BSL.ByteString'
               }

deriving instance (Show (f (PPH.PEOptionalHeader w))) => Show (PEHeaderInfo f w)

-- | Pretty print a 'PEHeaderInfo'
--
-- Note that this prints the 'PPH.PEOptionalHeader' if it is present
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

-- | Parse a single 'PEHeaderInfo'
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

-- | Decode a 'BSL.ByteString' into a 'PEHeaderInfo'
--
-- There are a few parsing failures that can occur here.  Some failures arise
-- when correlated values (e.g., duplicate claims of object sizes) do not match.
-- The 'PEHeaderInfo' type is parameterized by a "container".  This parser
-- returns a 'Maybe' as the container, as there is no guarantee that the PE
-- Optional Header is present.  In particular, object files often elide the
-- Optional Header.
--
-- The error case reports the offset at which the error occurred in the byte
-- stream, along with a descriptive message.
decodePEHeaderInfo :: BSL.ByteString
                   -> Either (Int64, String) (Some (PEHeaderInfo Maybe))
decodePEHeaderInfo bs =
  case G.runGetOrFail (parsePEHeaderInfo bs) bs of
    Left (_, off, msg) -> Left (off, msg)
    Right (_, _, phi) -> Right phi

-- | Traverse a 'PEHeaderInfo' and resolve the 'Maybe' field
--
-- * In the 'Left' case, there is no PE Optional Header and the slot is filled in
--   by a dummy @'FC.Const' ()@ as a static proof that it is not present.
--
-- * In the 'Right' case, there is a PE Optional Header; it is held in a
--   'FI.Identity' wrapper to prove that it is always present.
--
-- This function is useful to examine binaries when the Optional Header is
-- expected.  Some of the functions for deeper inspection of binaries require
-- the 'FI.Identity' version of the 'PEHeaderInfo' to prove that the header is
-- present (e.g., for inspecting Data Directory entries).
validatePEHeaderInfo :: PEHeaderInfo Maybe w
                     -> Either (PEHeaderInfo (FC.Const ()) w) (PEHeaderInfo FI.Identity w)
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

-- | The contents of a decoded section
data Section =
  Section { sectionHeader :: PPS.SectionHeader
          -- ^ The section header
          , sectionContents :: BSL.ByteString
          -- ^ The raw section contents
          --
          -- This data is uninterpreted
          }

-- | Look up the contents of a 'Section'
--
-- Note that the 'PPS.SectionHeader' should come from the same 'PEHeaderInfo'
--
-- This could fail if the data is missing from the underlying bytestring
--
-- FIXME: This could be safer if the 'PPS.SectionHeader' had a type parameter to
-- tie it to the header info (and also connect it to the sections)
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

-- | Errors that can occur while decoding sections or data directory entries
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

-- | This class provides a uniform interface for parsing Data Directory Entires
-- into their actual values (usually a table of some sort)
--
-- Users should probably not need this (though 'ppDataDirectoryEntryValue' could be useful)
class HasDataDirectoryEntry (entry :: PPDDE.DataDirectoryEntryKind) where
  -- | The parsed table type that is parsed from this Data Directory entry
  type DataDirectoryEntryType entry :: Type
  -- | The parser to parse a table entry
  --
  -- The parser is given the (machine word independent) 'PPH.PEHeader' and the
  -- size of the data value to parse
  dataDirectoryEntryParser :: proxy entry -> PPH.PEHeader -> Word32 -> G.Get (DataDirectoryEntryType entry)
  -- | Pretty print the data value
  ppDataDirectoryEntryValue :: proxy entry -> DataDirectoryEntryType entry -> PP.Doc ann

instance HasDataDirectoryEntry PPDDE.ExportTableK where
  type DataDirectoryEntryType PPDDE.ExportTableK = PPEDT.ExportDirectoryTable
  dataDirectoryEntryParser _ _ _ = PPEDT.parseExportDirectoryTable
  ppDataDirectoryEntryValue _ = PPEDT.ppExportDirectoryTable

instance HasDataDirectoryEntry PPDDE.ImportTableK where
  type DataDirectoryEntryType PPDDE.ImportTableK = PPIDT.ImportDirectoryTable
  dataDirectoryEntryParser _ _ _ = PPIDT.parseImportDirectoryTable
  ppDataDirectoryEntryValue _ = PPIDT.ppImportDirectoryTable

instance HasDataDirectoryEntry PPDDE.BaseRelocationTableK where
  type DataDirectoryEntryType PPDDE.BaseRelocationTableK = PPBR.BaseRelocationBlock
  dataDirectoryEntryParser _ _ _ = PPBR.parseBaseRelocationBlock
  ppDataDirectoryEntryValue _ = PPBR.ppBaseRelocationBlock

instance HasDataDirectoryEntry PPDDE.ExceptionTableK where
  type DataDirectoryEntryType PPDDE.ExceptionTableK = PPET.ExceptionTable
  dataDirectoryEntryParser _ = PPET.parseExceptionTable
  ppDataDirectoryEntryValue _ = PPET.ppExceptionTable

-- | An existential wrapper around 'PPDE.DataDirectoryEntry' that captures the
-- 'HasDataDirectoryEntry' constraint
data SomeDataDirectoryEntry where
  SomeDataDirectoryEntry :: (HasDataDirectoryEntry entry) => PPDDE.DataDirectoryEntryName entry -> SomeDataDirectoryEntry

-- | All 'PPDE.DataDirectoryEntry' values that can be deeply inspected by this
-- library (i.e., parsed out using 'HasDataDirectoryEntry')
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
  case F.find (PPDDE.isDataDirectoryEntry dirEntryName) entries of
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

