{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
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
  DOSHeader(..),
  PEHeader(..),
  ppPEHeader,
  PEOptionalHeader(..),
  -- ** Architecture size handling
  PPW.PEClass(..),
  PPW.PEWord,
  -- ** Data Directories
  DataDirectoryEntry(..),
  parseDataDirectoryEntry,
  ppDataDirectoryEntry,
  DataDirectoryEntryName(..),
  -- ** Sections
  module PPS,
  Section(..),
  getSection,
  getExportDirectoryTable,
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
  module PPEDT
  ) where

import           Control.Monad ( replicateM, unless )
import qualified Control.Monad.Catch as X
import qualified Control.Monad.Fail as MF
import qualified Data.Binary.Get as G
import qualified Data.ByteString.Lazy as BSL
import           Data.Char ( ord )
import qualified Data.Foldable as F
import qualified Data.Functor.Const as FC
import qualified Data.Functor.Identity as FI
import           Data.Int ( Int64 )
import           Data.Maybe ( fromMaybe, mapMaybe )
import qualified Data.Parameterized.NatRepr as PN
import           Data.Parameterized.Some ( Some(..) )
import qualified Data.Parameterized.Vector as PV
import           Data.Word ( Word8, Word16, Word32 )
import qualified Prettyprinter as PP
import qualified Prettyprinter.Render.String as PPRS

import qualified PE.Parser.Characteristics as PPC
import qualified PE.Parser.DLLFlags as PPDLL
import qualified PE.Parser.ExportDirectoryTable as PPEDT
import qualified PE.Parser.Machine as PPM
import qualified PE.Parser.Pretty as PPP
import qualified PE.Parser.PEWord as PPW
import qualified PE.Parser.SectionHeader as PPS
import qualified PE.Parser.Subsystem as PPSu
import qualified PE.Parser.Vector as PPV

-- | A wrapper around 'MF.fail' that accepts formatted prettyprinter 'PP.Doc's
failDoc :: (MF.MonadFail m) => PP.Doc ann -> m a
failDoc d = MF.fail (PPRS.renderString (PP.layoutCompact d))

-- | The DOS header is the first 64 bytes of the file
--
-- There are two relevant bits of information:
--
-- * The first two bytes are 0x4d 0x5a (in ASCII: MZ)
-- * The last four bytes are an offset into the file (from the start) indicating the start of the PE header
--
-- This structure preserves the bytes between the signature and the offset (for
-- other analysis, if desired).  It does not store the signature.  The offset is
-- its own field (and needs to be appended to the freeform contents to rebuild a
-- DOSHeader).
data DOSHeader =
  DOSHeader { dosHeaderContents :: PV.Vector 58 Word8
            -- ^ The DOS header contents (except for the signature bytes and the PE header offset)
            , dosHeaderPEOffset :: Word32
            }
  deriving (Show)

parseDOSHeader :: G.Get DOSHeader
parseDOSHeader = do
  sig1 <- G.getWord8
  sig2 <- G.getWord8
  unless (fromIntegral sig1 == ord 'M' && fromIntegral sig2 == ord 'Z') $ do
    failDoc (PP.pretty "Invalid DOS Header signature: " <> PPP.ppList (fmap PPP.ppHex [sig1, sig2]))
  -- This is passing 57, but actually gets 58 bytes due to how the types work out
  bytes <- PPV.getVecN (PN.knownNat @57)
  offset <- G.getWord32le
  return DOSHeader { dosHeaderContents = bytes
                   , dosHeaderPEOffset = offset
                   }

-- | The total size of the 'DOSHeader' on disk/in the file
dosHeaderSize :: Word32
dosHeaderSize = 64

data PEHeader =
  PEHeader { peHeaderMachine :: PPM.Machine
           , peHeaderNumberOfSections :: Word16
           , peHeaderTimeDateStamp :: Word32
           -- ^ The low 32 bits of the number of seconds since the unix epoch
           -- that the PE file was created at
           , peHeaderPointerToSymbolTable :: Word32
           -- ^ The file offset of the COFF symbol table (zero if there is no
           -- COFF symbol table)
           --
           -- NOTE: COFF symbol tables are deprecated, so this should be zero
           , peHeaderNumberOfSymbols :: Word32
           -- ^ The number of entries in the COFF symbol table
           --
           -- NOTE: COFF symbol tables are deprecated, so this should be zero
           -- (but this information must be preserved to compute the offset of
           -- the string table)
           , peHeaderSizeOfOptionalHeader :: Word16
           , peHeaderCharacteristics :: PPC.Characteristics
           }
  deriving (Show)

ppPEHeader :: PEHeader -> PP.Doc ann
ppPEHeader h =
  PP.vsep [ PP.pretty "Machine: " <> PPM.ppMachine (peHeaderMachine h)
          , PP.pretty "Section Count: " <> PP.pretty (peHeaderNumberOfSections h)
          , PP.pretty "Timestamp: " <> PP.pretty (peHeaderTimeDateStamp h)
          , PP.pretty "Pointer to COFF Symbol Table (deprecated): " <> PP.pretty (peHeaderPointerToSymbolTable h)
          , PP.pretty "Number of COFF symbols (deprecated): " <> PP.pretty (peHeaderNumberOfSymbols h)
          , PP.pretty "Size of PE Optional Header: " <> PPP.ppBytes (peHeaderSizeOfOptionalHeader h)
          , PP.pretty "Characteristics: " <> PPC.ppCharacteristics (peHeaderCharacteristics h)
          ]

parsePEHeader :: G.Get PEHeader
parsePEHeader = do
  -- Verify the PE signature, which should be here
  --
  -- The signature is PE\0\0
  p <- G.getWord8
  e <- G.getWord8
  z1 <- G.getWord8
  z2 <- G.getWord8
  unless (fromIntegral p == ord 'P' && fromIntegral e == ord 'E' && z1 == 0 && z2 == 0) $ do
    failDoc (PP.pretty "Invalid PE Header signature: " <> PPP.ppList (fmap PPP.ppHex [p, e, z1, z2]))
  m <- PPM.parseMachine
  numSections <- G.getWord16le
  timestamp <- G.getWord32le
  stPtr <- G.getWord32le
  numSymbols <- G.getWord32le
  optHeaderSize <- G.getWord16le
  ch <- PPC.parseCharacteristics

  return PEHeader { peHeaderMachine = m
                  , peHeaderNumberOfSections = numSections
                  , peHeaderTimeDateStamp = timestamp
                  , peHeaderPointerToSymbolTable = stPtr
                  , peHeaderNumberOfSymbols = numSymbols
                  , peHeaderSizeOfOptionalHeader = optHeaderSize
                  , peHeaderCharacteristics = ch
                  }


data DataDirectoryEntry =
  DataDirectoryEntry { dataDirectoryEntryAddress :: Word32
                     , dataDirectoryEntrySize :: Word32
                     }
  deriving (Show)

-- | Names of each of entry in the Data Directory
--
-- These are in ordinal order (and that is important)
data DataDirectoryEntryName = ExportTable
                            | ImportTable
                            | ResourceTable
                            | ExceptionTable
                            | CertificateTable
                            | BaseRelocationTable
                            | Debug
                            | Architecture
                            | GlobalPtr
                            | TLSTable
                            | LoadConfigTable
                            | BoundImportTable
                            | ImportAddressTable
                            | DelayImportDescriptor
                            | CLRRuntimeHeader
                            deriving (Show, Bounded, Enum, Eq)

ppDataDirectoryEntryName :: DataDirectoryEntryName -> PP.Doc ann
ppDataDirectoryEntryName n =
  case n of
    ExportTable -> PP.pretty "Export Table"
    ImportTable -> PP.pretty "Import Table"
    ResourceTable -> PP.pretty "Resource Table"
    ExceptionTable -> PP.pretty "Exception Table"
    CertificateTable -> PP.pretty "Certificate Table"
    BaseRelocationTable -> PP.pretty "Base Relocation Table"
    Debug -> PP.pretty "Debug"
    Architecture -> PP.pretty "Architecture"
    GlobalPtr -> PP.pretty "Global Ptr"
    TLSTable -> PP.pretty "TLS Table"
    LoadConfigTable -> PP.pretty "Load Config Table"
    BoundImportTable -> PP.pretty "Bound Import Table"
    ImportAddressTable -> PP.pretty "Import Address Table"
    DelayImportDescriptor -> PP.pretty "Delay Import Descriptor"
    CLRRuntimeHeader -> PP.pretty "CLR Runtime Header"

parseDataDirectoryEntry :: G.Get DataDirectoryEntry
parseDataDirectoryEntry = do
  addr <- G.getWord32le
  size <- G.getWord32le
  return DataDirectoryEntry { dataDirectoryEntryAddress = addr
                            , dataDirectoryEntrySize = size
                            }

ppDataDirectoryEntry :: [PPS.SectionHeader] -> (DataDirectoryEntryName, DataDirectoryEntry) -> Maybe (PP.Doc ann)
ppDataDirectoryEntry secHeaders (entryName, dde)
  | dataDirectoryEntryAddress dde == 0 = Nothing
  | otherwise =
    Just $ PP.hcat [ PPP.ppHex (dataDirectoryEntryAddress dde)
                   , PP.pretty " "
                   , PP.parens (PPP.ppBytes (dataDirectoryEntrySize dde))
                   , PP.pretty " "
                   , PP.parens (ppDataDirectoryEntryName entryName <> inSec)
                   ]
  where
    inSec = fromMaybe mempty $ do
      hdr <- findDataDirectoryEntrySection secHeaders dde
      return (PP.pretty " in section " <> PP.pretty (PPS.sectionHeaderNameText hdr))

findDataDirectoryEntrySection :: [PPS.SectionHeader] -> DataDirectoryEntry -> Maybe PPS.SectionHeader
findDataDirectoryEntrySection secHeaders dde =
  F.find (sectionContains (dataDirectoryEntryAddress dde)) secHeaders

sectionContains :: Word32 -> PPS.SectionHeader -> Bool
sectionContains addr hdr = addr >= secStart && addr < secEnd
  where
    secStart = PPS.sectionHeaderVirtualAddress hdr
    secEnd = secStart + PPS.sectionHeaderVirtualSize hdr

-- | The "Optional" PE Header
--
-- This isn't very optional most of the time, but it isn't clear that it is
-- always a required extension.  The @w@ parameter is a type-level nat that is
-- either 32 or 64, depending on the header version/target system.
--
-- It is optional for object files.
data PEOptionalHeader w =
  PEOptionalHeader { peOptionalHeaderClass :: PPW.PEClass w
                   -- ^ This is a value-level representative of the type
                   -- parameter @w@; it is not actually part of the structure on
                   -- disk (though it is derived from the signature)
                   , peOptionalHeaderMajorLinkerVersion :: Word8
                   , peOptionalHeaderMinorLinkerVersion :: Word8
                   , peOptionalHeaderSizeOfCode :: Word32
                   , peOptionalHeaderSizeOfInitializedData :: Word32
                   , peOptionalHeaderSizeOfUninitializedData :: Word32
                   , peOptionalHeaderAddressOfEntryPoint :: Word32
                   -- ^ Note that this is known as the Relative Virtual Address
                   -- (RVA), and is an offset from the load location of the
                   -- executable/module if ASLR is enabled (hence being 32 bits
                   -- instead of the word size).
                   , peOptionalHeaderBaseOfCode :: Word32
                   -- ^ The RVA of the start of the code section
                   , peOptionalHeaderBaseOfData :: Word32
                   -- ^ The RVA of the start of the data section
                   --
                   -- NOTE: This field is *not* present in the header in the
                   -- PE32+ (i.e., PE64) version of the header.  This struct
                   -- will still have it, but with a value of zero.
                   , peOptionalHeaderImageBase :: PPW.PEWord w
                   -- ^ This is the full virtual address at which an executable
                   -- will be memory-mapped (presumably when executable-level
                   -- ASLR is not enabled)
                   , peOptionalHeaderSectionAlignment :: Word32
                   , peOptionalHeaderFileAlignment :: Word32
                   , peOptionalHeaderMajorOperatingSystemVersion :: Word16
                   , peOptionalHeaderMinorOperatingSystemVersion :: Word16
                   , peOptionalHeaderMajorImageVersion :: Word16
                   , peOptionalHeaderMinorImageVersion :: Word16
                   , peOptionalHeaderMajorSubsystemVersion :: Word16
                   , peOptionalHeaderMinorSubsystemVersion :: Word16
                   , peOptionalHeaderWin32VersionValue :: Word32
                   , peOptionalHeaderSizeOfImage :: Word32
                   , peOptionalHeaderSizeOfHeaders :: Word32
                   , peOptionalHeaderChecksum :: Word32
                   , peOptionalHeaderSubsystem :: PPSu.Subsystem
                   , peOptionalHeaderDLLCharacteristics :: PPDLL.DLLFlags
                   , peOptionalHeaderSizeOfStackReserve :: PPW.PEWord w
                   , peOptionalHeaderSizeOfStackCommit :: PPW.PEWord w
                   , peOptionalHeaderSizeOfHeapReserve :: PPW.PEWord w
                   , peOptionalHeaderSizeOfHeapCommit :: PPW.PEWord w
                   , peOptionalHeaderLoaderFlags :: Word32
                   , peOptionalHeaderDataDirectory :: [DataDirectoryEntry]
                   -- ^ Note: The on-disk file actually has a number of entries
                   -- here; the header parser parses them all out
                   --
                   -- Empty 'DataDirectoryEntries' are included because they are
                   -- present in the on-disk file.  The position in the table is
                   -- important, as each index corresponds to a specific table
                   -- entry (see 'DataDirectoryEntryName' for supported values).
                   -- This format is also useful, as it allows us to robustly
                   -- parse unrecognized table values.
                   }

deriving instance (PPW.PEConstraints w) => Show (PEOptionalHeader w)

ppPEOptionalHeaders :: [PPS.SectionHeader] -> PEOptionalHeader w -> PP.Doc ann
ppPEOptionalHeaders secHeaders oh = PPW.withPEConstraints (peOptionalHeaderClass oh) $
  PP.vsep [ PP.pretty "PE Format: " <> PPW.ppPEClass (peOptionalHeaderClass oh)
          , PP.pretty "Linker Version: " <> PPP.ppVersion (peOptionalHeaderMajorLinkerVersion oh, peOptionalHeaderMinorLinkerVersion oh)
          , PP.pretty "Size of code: " <> PPP.ppBytes (peOptionalHeaderSizeOfCode oh)
          , PP.pretty "Size of Initialized data: " <> PPP.ppBytes (peOptionalHeaderSizeOfInitializedData oh)
          , PP.pretty "Size of Uninitialized data: " <> PPP.ppBytes (peOptionalHeaderSizeOfUninitializedData oh)
          , PP.pretty "Address of entry point: " <> PPP.ppHex (peOptionalHeaderAddressOfEntryPoint oh)
          , PP.pretty "Base of Code: " <> PPP.ppHex (peOptionalHeaderBaseOfCode oh)
          , PP.pretty "Base of Data: " <> PPP.ppHex (peOptionalHeaderBaseOfData oh)
          , PP.pretty "Image Base: " <> PPP.ppHex (peOptionalHeaderImageBase oh)
          , PP.pretty "Section Align: " <> PPP.ppHex (peOptionalHeaderSectionAlignment oh)
          , PP.pretty "File Align: " <> PPP.ppHex (peOptionalHeaderFileAlignment oh)
          , PP.pretty "OS Version: " <> PPP.ppVersion (peOptionalHeaderMajorOperatingSystemVersion oh, peOptionalHeaderMinorOperatingSystemVersion oh)
          , PP.pretty "Image Version: " <> PPP.ppVersion (peOptionalHeaderMajorImageVersion oh, peOptionalHeaderMinorImageVersion oh)
          , PP.pretty "Subsystem Version: " <> PPP.ppVersion (peOptionalHeaderMajorSubsystemVersion oh, peOptionalHeaderMinorSubsystemVersion oh)
          , PP.pretty "Win32 Version: " <> PP.pretty (peOptionalHeaderWin32VersionValue oh)
          , PP.pretty "Size of Image: " <> PPP.ppBytes (peOptionalHeaderSizeOfImage oh)
          , PP.pretty "Size of Headers: " <> PPP.ppBytes (peOptionalHeaderSizeOfHeaders oh)
          , PP.pretty "Subsystem: " <> PPSu.ppSubsystem (peOptionalHeaderSubsystem oh)
          , PP.pretty "DLL Characteristics: " <> PPDLL.ppDLLFlags (peOptionalHeaderDLLCharacteristics oh)
          , PP.pretty "Size of Stack Reserve: " <> PPP.ppBytes (peOptionalHeaderSizeOfStackReserve oh)
          , PP.pretty "Size of Stack Commit: " <> PPP.ppBytes (peOptionalHeaderSizeOfStackCommit oh)
          , PP.pretty "Size of Heap Reserve: " <> PPP.ppBytes (peOptionalHeaderSizeOfHeapReserve oh)
          , PP.pretty "Size of Heap Commit: " <> PPP.ppBytes (peOptionalHeaderSizeOfHeapCommit oh)
          , PP.pretty "Loader Flags: " <> PPP.ppHex (peOptionalHeaderLoaderFlags oh)
          , PP.pretty "Data Directory"
          , PP.indent 4 (PP.vcat (mapMaybe (ppDataDirectoryEntry secHeaders) (indexDirectoryEntries oh)))
          ]

indexDirectoryEntries :: PEOptionalHeader w -> [(DataDirectoryEntryName, DataDirectoryEntry)]
indexDirectoryEntries oh =
  zip dirEntryNames (peOptionalHeaderDataDirectory oh)
  where
    dirEntryNames = [minBound .. maxBound]

parsePEOptionalHeader :: Word16 -> G.Get (Some PEOptionalHeader)
parsePEOptionalHeader optHeaderSize = do
  -- Parse the 2 byte signature and decide if this is a PE32 (0x10b) or a PE64 (0x20b)
  sig <- G.getWord16le
  case sig of
    0x10b -> Some <$> parsePEOptionalHeaderAs optHeaderSize PPW.PEClass32
    0x20b -> Some <$> parsePEOptionalHeaderAs optHeaderSize PPW.PEClass64
    _ -> failDoc (PP.pretty "Unexpected PE Optional Header signature: " <> PPP.ppHex sig)

parsePEOptionalHeaderAs :: (PPW.PEConstraints w) => Word16 -> PPW.PEClass w -> G.Get (PEOptionalHeader w)
parsePEOptionalHeaderAs optHeaderSize peClass = do
  optHeaderStart <- G.bytesRead

  majorLinker <- G.getWord8
  minorLinker <- G.getWord8
  sizeOfCode <- G.getWord32le
  sizeOfInitData <- G.getWord32le
  sizeOfUninitData <- G.getWord32le
  entryPoint <- G.getWord32le
  baseOfCode <- G.getWord32le
  baseOfData <- case peClass of
    PPW.PEClass32 -> G.getWord32le
    PPW.PEClass64 -> return 0
  imageBase <- PPW.parsePEWord peClass
  secAlign <- G.getWord32le
  fileAlign <- G.getWord32le
  majorOSVersion <- G.getWord16le
  minorOSVersion <- G.getWord16le
  majorImage <- G.getWord16le
  minorImage <- G.getWord16le
  majorSubsystem <- G.getWord16le
  minorSubsystem <- G.getWord16le
  win32Version <- G.getWord32le
  sizeOfImage <- G.getWord32le
  sizeOfHeaders <- G.getWord32le
  checksum <- G.getWord32le
  subsystem <- PPSu.parseSubsystem
  dllChar <- PPDLL.parseDLLFlags
  stackReserve <- PPW.parsePEWord peClass
  stackCommit <- PPW.parsePEWord peClass
  heapReserve <- PPW.parsePEWord peClass
  heapCommit <- PPW.parsePEWord peClass
  loaderFlags <- G.getWord32le
  numRva <- G.getWord32le


  -- Note: it is invalid to read more bytes than 'optHeaderSize', as that is the
  -- ultimate arbiter of the size of this table.  If there is an inconsistency
  -- between that and the size of the Data Directory, we can throw an error
  -- here... but we might just want to make it a warning
  dataEntries <- replicateM (fromIntegral numRva) parseDataDirectoryEntry

  optHeaderEnd <- G.bytesRead

  -- Here we are checking the consistency of the declared header size against
  -- what we have actually parsed (given the value of 'numRva', which defines
  -- the length of the variable bit of the headers.
  --
  -- Note that we have to add 2 because the two bytes of the signature are
  -- actually parsed before this function (so that we can determine the size of
  -- some fields)
  unless (fromIntegral optHeaderSize == optHeaderEnd - optHeaderStart + 2) $ do
    failDoc $ PP.hsep [ PP.pretty "The declared PE Optional Header size ("
                      , PP.pretty optHeaderSize
                      , PP.pretty ") does not match the actual size implied by the architecture and data directory entry count ("
                      , PP.pretty (optHeaderEnd - optHeaderStart)
                      , PP.pretty ") PE format is "
                      , PPW.ppPEClass peClass
                      ]

  return PEOptionalHeader { peOptionalHeaderClass = peClass
                          , peOptionalHeaderMajorLinkerVersion = majorLinker
                          , peOptionalHeaderMinorLinkerVersion = minorLinker
                          , peOptionalHeaderSizeOfCode = sizeOfCode
                          , peOptionalHeaderSizeOfInitializedData = sizeOfInitData
                          , peOptionalHeaderSizeOfUninitializedData = sizeOfUninitData
                          , peOptionalHeaderAddressOfEntryPoint = entryPoint
                          , peOptionalHeaderBaseOfCode = baseOfCode
                          , peOptionalHeaderBaseOfData = baseOfData
                          , peOptionalHeaderImageBase = imageBase
                          , peOptionalHeaderSectionAlignment = secAlign
                          , peOptionalHeaderFileAlignment = fileAlign
                          , peOptionalHeaderMajorOperatingSystemVersion = majorOSVersion
                          , peOptionalHeaderMinorOperatingSystemVersion = minorOSVersion
                          , peOptionalHeaderMajorImageVersion = majorImage
                          , peOptionalHeaderMinorImageVersion = minorImage
                          , peOptionalHeaderMajorSubsystemVersion = majorSubsystem
                          , peOptionalHeaderMinorSubsystemVersion = minorSubsystem
                          , peOptionalHeaderWin32VersionValue = win32Version
                          , peOptionalHeaderSizeOfImage = sizeOfImage
                          , peOptionalHeaderSizeOfHeaders = sizeOfHeaders
                          , peOptionalHeaderChecksum = checksum
                          , peOptionalHeaderSubsystem = subsystem
                          , peOptionalHeaderDLLCharacteristics = dllChar
                          , peOptionalHeaderSizeOfStackReserve = stackReserve
                          , peOptionalHeaderSizeOfStackCommit = stackCommit
                          , peOptionalHeaderSizeOfHeapReserve = heapReserve
                          , peOptionalHeaderSizeOfHeapCommit = heapCommit
                          , peOptionalHeaderLoaderFlags = loaderFlags
                          , peOptionalHeaderDataDirectory = dataEntries
                          }


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
  PEHeaderInfo { dosHeader :: DOSHeader
               , peHeader :: PEHeader
               , peOptionalHeader :: f (PEOptionalHeader w)
               , peSectionHeaders :: [PPS.SectionHeader]
               , peContents :: BSL.ByteString
               }

deriving instance (Show (f (PEOptionalHeader w))) => Show (PEHeaderInfo f w)


ppPEHeaderInfo :: PEHeaderInfo Maybe w -> PP.Doc ann
ppPEHeaderInfo phi =
  PP.vsep [ ppPEHeader (peHeader phi)
          -- FIXME: Add a header to mark out the optional headers
          , maybe mempty (ppPEOptionalHeaders (peSectionHeaders phi)) (peOptionalHeader phi)
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
  dh <- parseDOSHeader
  G.skip (fromIntegral (dosHeaderPEOffset dh - dosHeaderSize - fromIntegral initialOffset))

  -- Immediately followed by the PE Header (which checks the magic signature)
  peh <- parsePEHeader

  case peHeaderSizeOfOptionalHeader peh of
    0 -> do
      secTable <- parseSectionTable (peHeaderNumberOfSections peh)
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
      Some peoh <- parsePEOptionalHeader optHeaderSize
      secTable <- parseSectionTable (peHeaderNumberOfSections peh)
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

data PEException = MissingDirectoryEntry DataDirectoryEntryName
                 -- ^ The named 'DataDirectoryEntry' is not present in the file (the table entry is missing or zero)
                 | DirectoryEntryAddressNotMapped [PPS.SectionHeader] DataDirectoryEntry
                 -- ^ The address named in the 'DataDirectoryEntry' is not mapped in any of the sections defined in the executable
                 | DirectoryEntryParseFailure DataDirectoryEntryName DataDirectoryEntry Int64 String
                 -- ^ The 'DataDirectoryEntry' named could not be parsed
                 | SectionContentsSizeMismatch PPS.SectionHeader Int64
                 -- ^ The given 'PPS.SectionHeader' declares an offset (and
                 -- size) for this section that does not match the available
                 -- byte count in the bytestring
  deriving (Show)

instance X.Exception PEException

-- | Parse the contents of the 'PPEDT.ExportDirectoryTable'
--
-- This can fail (via 'X.MonadThrow') if the PE does not contain an Export
-- Directory Table (i.e., if it is not a DLL), or if no mapped section contains
-- the address named in the export directory table descriptor.
getExportDirectoryTable :: (X.MonadThrow m)
                        => PEHeaderInfo FI.Identity w
                        -> m (PPEDT.ExportDirectoryTable)
getExportDirectoryTable phi = do
  let optHeader = FI.runIdentity (peOptionalHeader phi)
  let entries = indexDirectoryEntries optHeader
  case F.find (isDirectoryEntry ExportTable) entries of
    Nothing -> X.throwM (MissingDirectoryEntry ExportTable)
    Just (_, dde) -> do
      let secHeaders = peSectionHeaders phi
      case findDataDirectoryEntrySection secHeaders dde of
        Nothing -> X.throwM (DirectoryEntryAddressNotMapped secHeaders dde)
        Just containingSection -> do
          let offsetInSection = dataDirectoryEntryAddress dde - PPS.sectionHeaderVirtualAddress containingSection
          sec <- getSection phi containingSection
          let tableStart = BSL.drop (fromIntegral offsetInSection) (sectionContents sec)
          case G.runGetOrFail PPEDT.parseExportDirectoryTable tableStart of
            Left (_, errOff, msg) -> X.throwM (DirectoryEntryParseFailure ExportTable dde errOff msg)
            Right (_, _, edt) -> return edt

isDirectoryEntry :: DataDirectoryEntryName -> (DataDirectoryEntryName, a) -> Bool
isDirectoryEntry name (entryName, _) = name == entryName
