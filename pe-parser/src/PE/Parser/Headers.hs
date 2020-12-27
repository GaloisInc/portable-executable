{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}
module PE.Parser.Headers (
  DOSHeader(..),
  parseDOSHeader,
  dosHeaderSize,
  PEHeader(..),
  parsePEHeader,
  ppPEHeader,
  PEOptionalHeader(..),
  peOptionalHeaderIndexDirectoryEntries,
  parsePEOptionalHeader,
  ppPEOptionalHeader
  ) where

import           Control.Monad ( replicateM, unless )
import qualified Data.Binary.Get as G
import           Data.Char ( ord )
import           Data.Maybe ( mapMaybe )
import qualified Data.Parameterized.NatRepr as PN
import           Data.Parameterized.Some ( Some(..) )
import qualified Data.Parameterized.Vector as PV
import           Data.Word ( Word8, Word16, Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.FileFlags as PPFF
import qualified PE.Parser.DLLFlags as PPDLL
import qualified PE.Parser.DataDirectoryEntry as PPDDE
import qualified PE.Parser.Machine as PPM
import qualified PE.Parser.PEWord as PPW
import qualified PE.Parser.Pretty as PPP
import qualified PE.Parser.SectionHeader as PPS
import qualified PE.Parser.Subsystem as PPSu
import qualified PE.Parser.Vector as PPV

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
            -- ^ The offset from the /start of the file/ of the 'PEHeader'
            }
  deriving (Show)

-- | Parse a single 'DOSHeader'
--
-- This fails (safely, via 'fail' in the 'G.Get' monad) if the signature does
-- not match the expected ASCII "MZ".
parseDOSHeader :: G.Get DOSHeader
parseDOSHeader = do
  sig1 <- G.getWord8
  sig2 <- G.getWord8
  unless (fromIntegral sig1 == ord 'M' && fromIntegral sig2 == ord 'Z') $ do
    PPP.failDoc (PP.pretty "Invalid DOS Header signature: " <> PPP.ppList (fmap PPP.ppHex [sig1, sig2]))
  -- This is passing 57, but actually gets 58 bytes due to how the types work out
  bytes <- PPV.getVecN (PN.knownNat @57)
  offset <- G.getWord32le
  return DOSHeader { dosHeaderContents = bytes
                   , dosHeaderPEOffset = offset
                   }

-- | The total size of the 'DOSHeader' on disk/in the file
dosHeaderSize :: Word32
dosHeaderSize = 64

-- | The basic PE file header
--
-- This is the mandatory header present in every PE file.
data PEHeader =
  PEHeader { peHeaderMachine :: PPM.Machine
           -- ^ The tag describing the architecture of the machine
           , peHeaderNumberOfSections :: Word16
           -- ^ The number of sections (which occur after the PE Optional Header)
           , peHeaderTimeDateStamp :: Word32
           -- ^ The low 32 bits of the number of seconds since the unix epoch
           -- that the PE file was created at
           , peHeaderPointerToSymbolTable :: Word32
           -- ^ The file offset of the COFF symbol table (zero if there is no
           -- COFF symbol table)
           --
           -- NOTE: COFF symbol tables are deprecated, so tphis should be zero
           , peHeaderNumberOfSymbols :: Word32
           -- ^ The number of entries in the COFF symbol table
           --
           -- NOTE: COFF symbol tables are deprecated, so this should be zero
           -- (but this information must be preserved to compute the offset of
           -- the string table)
           , peHeaderSizeOfOptionalHeader :: Word16
           -- ^ The number of bytes in the PE Optional Header (which is variable
           -- given that the set of data directory entries is extensible)
           , peHeaderFileFlags :: PPFF.FileFlags
           -- ^ Flags describing the features of the PE file
           }
  deriving (Show)

-- | Pretty print the fields of the mandatory 'PEHeader'
--
-- This prints only the fields (with no indentation).
ppPEHeader :: PEHeader -> PP.Doc ann
ppPEHeader h =
  PP.vsep [ PP.pretty "Machine: " <> PPM.ppMachine (peHeaderMachine h)
          , PP.pretty "Section Count: " <> PP.pretty (peHeaderNumberOfSections h)
          , PP.pretty "Timestamp: " <> PP.pretty (peHeaderTimeDateStamp h)
          , PP.pretty "Pointer to COFF Symbol Table (deprecated): " <> PP.pretty (peHeaderPointerToSymbolTable h)
          , PP.pretty "Number of COFF symbols (deprecated): " <> PP.pretty (peHeaderNumberOfSymbols h)
          , PP.pretty "Size of PE Optional Header: " <> PPP.ppBytes (peHeaderSizeOfOptionalHeader h)
          , PP.pretty "FileFlags: " <> PPFF.ppFileFlags (peHeaderFileFlags h)
          ]

-- | Parse a single copy of the mandatory 'PEHeader'
--
-- This can fail (safely via the 'fail' method in the 'G.Get' monad) if the
-- signature is invalid (expected: PE\0\0).
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
    PPP.failDoc (PP.pretty "Invalid PE Header signature: " <> PPP.ppList (fmap PPP.ppHex [p, e, z1, z2]))
  m <- PPM.parseMachine
  numSections <- G.getWord16le
  timestamp <- G.getWord32le
  stPtr <- G.getWord32le
  numSymbols <- G.getWord32le
  optHeaderSize <- G.getWord16le
  ch <- PPFF.parseFileFlags

  return PEHeader { peHeaderMachine = m
                  , peHeaderNumberOfSections = numSections
                  , peHeaderTimeDateStamp = timestamp
                  , peHeaderPointerToSymbolTable = stPtr
                  , peHeaderNumberOfSymbols = numSymbols
                  , peHeaderSizeOfOptionalHeader = optHeaderSize
                  , peHeaderFileFlags = ch
                  }

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
                   -- ^ The major version of the linker used to create the file
                   , peOptionalHeaderMinorLinkerVersion :: Word8
                   -- ^ The minor version of the linker used to create the file
                   , peOptionalHeaderSizeOfCode :: Word32
                   -- ^ The number of bytes of the .text section
                   , peOptionalHeaderSizeOfInitializedData :: Word32
                   -- ^ The number of bytes of initialized data in the .data section
                   , peOptionalHeaderSizeOfUninitializedData :: Word32
                   -- ^ The number of bytes of uninitialized data
                   -- (zero-initialized) in the .data section
                   , peOptionalHeaderAddressOfEntryPoint :: Word32
                   -- ^ The address of the entry point, if any; note that object
                   -- files and DLLs do not require entry points.
                   --
                   -- Note that this is a Relative Virtual Address (RVA), and is
                   -- an offset from the load location of the executable/module
                   -- if ASLR is enabled (hence being 32 bits instead of the
                   -- word size).
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
                   -- ^ The alignment of sections in memory, which must be
                   -- greater than or equal to the file alignment
                   , peOptionalHeaderFileAlignment :: Word32
                   -- ^ The alignment of sections in the file (i.e., offset).
                   --
                   -- This must be a power of two.  The default is 512.  If it
                   -- is less than the page size, it must equal the section
                   -- alignment.
                   , peOptionalHeaderMajorOperatingSystemVersion :: Word16
                   -- ^ The required major OS version
                   , peOptionalHeaderMinorOperatingSystemVersion :: Word16
                   -- ^ The required minor OS version
                   , peOptionalHeaderMajorImageVersion :: Word16
                   -- ^ The major version of the image
                   , peOptionalHeaderMinorImageVersion :: Word16
                   -- ^ The minor version of the image
                   , peOptionalHeaderMajorSubsystemVersion :: Word16
                   -- ^ The major version of the subsystem
                   , peOptionalHeaderMinorSubsystemVersion :: Word16
                   -- ^ The minor version of the subsystem
                   , peOptionalHeaderWin32VersionValue :: Word32
                   -- ^ Reserved, must be zero
                   , peOptionalHeaderSizeOfImage :: Word32
                   -- ^ The size in bytes of the image (including all headers).
                   --
                   -- This is required to be a multiple of the section alignment
                   , peOptionalHeaderSizeOfHeaders :: Word32
                   -- ^ The sum of the sizes of the DOS header, PE headers, and
                   -- section headers (rounded up to the nearest multiple of the
                   -- file alignment)
                   , peOptionalHeaderChecksum :: Word32
                   -- ^ A checksum of the image (checked for some system DLLs)
                   , peOptionalHeaderSubsystem :: PPSu.Subsystem
                   -- ^ The subsystem that this image targets (e.g., Windows CLI
                   -- or Windows GUI)
                   , peOptionalHeaderDLLCharacteristics :: PPDLL.DLLFlags
                   -- ^ Flags for the features used by this DLL, if applicable
                   , peOptionalHeaderSizeOfStackReserve :: PPW.PEWord w
                   -- ^ Number of bytes of memory reserved for the stack
                   , peOptionalHeaderSizeOfStackCommit :: PPW.PEWord w
                   -- ^ Number of bytes of memory initially committed for the stack
                   , peOptionalHeaderSizeOfHeapReserve :: PPW.PEWord w
                   -- ^ Number of bytes of heap memory to reserve
                   , peOptionalHeaderSizeOfHeapCommit :: PPW.PEWord w
                   -- ^ Number of bytes of heap memory initially committed
                   , peOptionalHeaderLoaderFlags :: Word32
                   -- ^ Reserved (must be zero)
                   , peOptionalHeaderDataDirectory :: [PPDDE.DataDirectoryEntry]
                   -- ^ Note: The on-disk file actually has a number of entries
                   -- here; the header parser parses them all out
                   --
                   -- Empty 'PPDDE.DataDirectoryEntries' are included because they are
                   -- present in the on-disk file.  The position in the table is
                   -- important, as each index corresponds to a specific table
                   -- entry (see 'PPDDE.DataDirectoryEntryName' for supported values).
                   -- This format is also useful, as it allows us to robustly
                   -- parse unrecognized table values.
                   }

deriving instance (PPW.PEConstraints w) => Show (PEOptionalHeader w)

-- | Pretty print the 'PEOptionalHeader'
--
-- This includes the Data Directory entries, which require the
-- 'PPS.SectionHeader's to fully interpret
ppPEOptionalHeader :: [PPS.SectionHeader] -> PEOptionalHeader w -> PP.Doc ann
ppPEOptionalHeader secHeaders oh = PPW.withPEConstraints (peOptionalHeaderClass oh) $
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
          , PP.indent 4 (PP.vcat (mapMaybe (PPDDE.ppDataDirectoryEntry secHeaders) (peOptionalHeaderIndexDirectoryEntries oh)))
          ]

-- | Pair up each 'PPDDE.DataDirectoryEntry' with its corresponding 'PPDDE.DataDirectoryEntryName'
--
-- Data directory entries are identified by their index into the data directory
-- entry table (with absent entries being zeroed out).  This assigns the names
-- to each entry for easier interpretation.
peOptionalHeaderIndexDirectoryEntries :: PEOptionalHeader w -> [(Some PPDDE.DataDirectoryEntryName, PPDDE.DataDirectoryEntry)]
peOptionalHeaderIndexDirectoryEntries oh =
  zip PPDDE.allDataDirectoryEntryNames (peOptionalHeaderDataDirectory oh)

-- | Parse a single 'PEOptionalHeader'
--
-- The pointer size is encoded in the 'PPW.PEClass', but quantified out in the
-- return value because we can't determine it until we read the signature.
--
-- This function can fail (safely via 'fail' in 'G.Get') if:
--
-- * The signature is not recognized (only PE32 and PE32+ are supported)
-- * The size declared in the 'PEHeader' does not match its actual size (implied
--   by the count of data directory entries)
parsePEOptionalHeader :: Word16
                      -- ^ The size of the PE Optional Header declared in the 'PEHeader'
                      -> G.Get (Some PEOptionalHeader)
parsePEOptionalHeader optHeaderSize = do
  -- Parse the 2 byte signature and decide if this is a PE32 (0x10b) or a PE64 (0x20b)
  sig <- G.getWord16le
  case sig of
    0x10b -> Some <$> parsePEOptionalHeaderAs optHeaderSize PPW.PEClass32
    0x20b -> Some <$> parsePEOptionalHeaderAs optHeaderSize PPW.PEClass64
    _ -> PPP.failDoc (PP.pretty "Unexpected PE Optional Header signature: " <> PPP.ppHex sig)

-- | Parse a single 'PEOptionalHeader' given the determined 'PPW.PEClass' (which
-- fixes the pointer size)
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
  dataEntries <- replicateM (fromIntegral numRva) PPDDE.parseDataDirectoryEntry

  optHeaderEnd <- G.bytesRead

  -- Here we are checking the consistency of the declared header size against
  -- what we have actually parsed (given the value of 'numRva', which defines
  -- the length of the variable bit of the headers.
  --
  -- Note that we have to add 2 because the two bytes of the signature are
  -- actually parsed before this function (so that we can determine the size of
  -- some fields)
  unless (fromIntegral optHeaderSize == optHeaderEnd - optHeaderStart + 2) $ do
    PPP.failDoc $ PP.hsep [ PP.pretty "The declared PE Optional Header size ("
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
