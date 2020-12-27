{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
module PE.Parser.SectionHeader (
  SectionHeader(..),
  sectionHeaderNameText,
  parseSectionHeader,
  ppSectionHeader,
  sectionContains,
  -- * Flags
  SectionFlags,
  SectionFlag,
  sectionFlags,
  hasSectionFlag,
  ppSectionFlag,
  ppSectionFlags,
  parseSectionFlags,
  -- ** Pre-defined flag constants
  pattern SCN_TYPE_NO_PAD,
  pattern SCN_CNT_CODE,
  pattern SCN_CNT_INITIALIZED_DATA,
  pattern SCN_CNT_UNINITIALIZED_DATA,
  pattern SCN_LNK_OTHER,
  pattern SCN_LNK_INFO,
  pattern SCN_LNK_REMOVE,
  pattern SCN_LNK_COMDAT,
  pattern SCN_GPREL,
  pattern SCN_MEM_PURGEABLE,
  pattern SCN_MEM_16BIT,
  pattern SCN_MEM_LOCKED,
  pattern SCN_MEM_PRELOAD,
  pattern SCN_ALIGN_1BYTES,
  pattern SCN_ALIGN_2BYTES,
  pattern SCN_ALIGN_4BYTES,
  pattern SCN_ALIGN_8BYTES,
  pattern SCN_ALIGN_16BYTES,
  pattern SCN_ALIGN_32BYTES,
  pattern SCN_ALIGN_64BYTES,
  pattern SCN_ALIGN_128BYTES,
  pattern SCN_ALIGN_256BYTES,
  pattern SCN_ALIGN_512BYTES,
  pattern SCN_ALIGN_1024BYTES,
  pattern SCN_ALIGN_2048BYTES,
  pattern SCN_ALIGN_4096BYTES,
  pattern SCN_ALIGN_8192BYTES,
  pattern SCN_LNK_NRELOC_OVFL,
  pattern SCN_MEM_DISCARDABLE,
  pattern SCN_MEM_NOT_CACHED,
  pattern SCN_MEM_NOT_PAGED,
  pattern SCN_MEM_SHARED,
  pattern SCN_MEM_EXECUTE,
  pattern SCN_MEM_READ,
  pattern SCN_MEM_WRITE
  ) where

import qualified Data.Binary.Get as G
import           Data.Bits ( (.|.), (.&.), bit, testBit )
import qualified Data.ByteString as BS
import qualified Data.Parameterized.NatRepr as PN
import qualified Data.Parameterized.Vector as PV
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Encoding.Error as TE
import           Data.Word ( Word8, Word16, Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.Pretty as PPP
import qualified PE.Parser.Vector as PPV

-- | A 'SectionHeader'
--
-- These are placed after the PE Optional Header and describe the location in
-- memory (and in the file) of sections.  The data needs to be resolved
-- separately (see 'PE.Parser.getSection')
data SectionHeader =
  SectionHeader { sectionHeaderName :: PV.Vector 8 Word8
                -- ^ The documentation says that this is UTF-8 encoded, but it
                -- probably isn't a great idea to trust that.  There is a
                -- separate combinator to attempt that interpretation (with a
                -- lenient decoding).
                --
                -- We keep the raw bytes to make it reproducible
                , sectionHeaderVirtualSize :: Word32
                -- ^ The size (in bytes) of the section in memory; only valid
                -- for executables (or presumably DLLs)
                , sectionHeaderVirtualAddress :: Word32
                -- ^ The RVA of the section when it is mapped in memory
                , sectionHeaderSizeOfRawData :: Word32
                -- ^ The size (in bytes) of the section on disk (this could be
                -- less than or equal to the virtual size in memory, in which
                -- case the remaining bytes are zero-initialized)
                , sectionHeaderPointerToRawData :: Word32
                -- ^ The offset into the file of the first page of the
                -- data for this section
                , sectionHeaderPointerToRelocations :: Word32
                -- ^ The offset of the beginning of the relocation entries for
                -- this section.  This should be zero for executables (or if
                -- there are no relocations).
                , sectionHeaderPointerToLinnumbers :: Word32
                -- ^ File pointer to the beginning of the line number entries
                -- for the section; this should be 0 because COFF debugging info
                -- is deprecated.
                , sectionHeaderNumberOfRelocations :: Word16
                -- ^ The number of relocations in this section
                , sectionHeaderNumberOfLinenumbers :: Word16
                -- ^ This should also be 0 because COFF debugging is deprecated
                , sectionHeaderCharacteristics :: SectionFlags
                -- ^ The flags describing the needs of this section
                }
  deriving (Show)

-- | Do a best-effort rendering of the name of this 'SectionHeader' as 'T.Text'
--
-- The encoding, according to the spec, is UTF-8.  However, there is no
-- guarantee, so this function does a lenient decoding.
sectionHeaderNameText :: SectionHeader -> T.Text
sectionHeaderNameText h =
  TE.decodeUtf8With TE.lenientDecode bs
  where
    bs = BS.pack (PV.toList (sectionHeaderName h))

-- | Return 'True' if the section described by this 'SectionHeader' contains the given RVA ('Word32')
sectionContains :: Word32
                -- ^ The Relative Virtual Address (RVA) to test
                -> SectionHeader
                -- ^ The section
                -> Bool
sectionContains addr hdr = addr >= secStart && addr < secEnd
  where
    secStart = sectionHeaderVirtualAddress hdr
    secEnd = secStart + sectionHeaderVirtualSize hdr

-- | Pretty print a 'SectionHeader'
--
-- This prints out the fields with no indentation or additional adornments
ppSectionHeader :: SectionHeader -> PP.Doc ann
ppSectionHeader hdr =
  PP.vsep [ PP.pretty "Name: " <> PP.pretty (sectionHeaderNameText hdr)
          , PP.pretty "Virtual Size: " <> PPP.ppBytes (sectionHeaderVirtualSize hdr)
          , PP.pretty "Virtual Address: " <> PPP.ppHex (sectionHeaderVirtualAddress hdr)
          , PP.pretty "Data Size: " <> PPP.ppBytes (sectionHeaderSizeOfRawData hdr)
          , PP.pretty "Pointer to Data (offset): " <> PP.pretty (sectionHeaderPointerToRawData hdr)
          , PP.pretty "Pointer to Relocations (offset): " <> PP.pretty (sectionHeaderPointerToRelocations hdr)
          , PP.pretty "Pointer to Line Numbers (offset, deprecated): " <> PP.pretty (sectionHeaderPointerToLinnumbers hdr)
          , PP.pretty "Number of Relocations: " <> PP.pretty (sectionHeaderNumberOfRelocations hdr)
          , PP.pretty "Number of Line Numbers (deprecated): " <> PP.pretty (sectionHeaderNumberOfLinenumbers hdr)
          , PP.pretty "Flags: " <> ppSectionFlags (sectionHeaderCharacteristics hdr)
          ]

-- | Parse a single 'SectionHeader'
parseSectionHeader :: G.Get SectionHeader
parseSectionHeader = do
  secName <- PPV.getVecN (PN.knownNat @7)
  virtSize <- G.getWord32le
  virtAddr <- G.getWord32le
  sizeOfData <- G.getWord32le
  pointerToData <- G.getWord32le
  pointerToRelocs <- G.getWord32le
  pointerToLines <- G.getWord32le
  numRelocs <- G.getWord16le
  numLines <- G.getWord16le
  chars <- parseSectionFlags
  return SectionHeader { sectionHeaderName = secName
                       , sectionHeaderVirtualSize = virtSize
                       , sectionHeaderVirtualAddress = virtAddr
                       , sectionHeaderSizeOfRawData = sizeOfData
                       , sectionHeaderPointerToRawData = pointerToData
                       , sectionHeaderPointerToRelocations = pointerToRelocs
                       , sectionHeaderPointerToLinnumbers = pointerToLines
                       , sectionHeaderNumberOfRelocations = numRelocs
                       , sectionHeaderNumberOfLinenumbers = numLines
                       , sectionHeaderCharacteristics = chars
                       }

-- | A single section capability/requirement flag
--
-- Flags are bitmasks
newtype SectionFlag = SectionFlag { getFlag :: Word32 }
  deriving (Show)

-- | A set of 'SectionFlag's bitwise ORed together
newtype SectionFlags = SectionFlags Word32
  deriving (Show)

-- | Parse a (bit) set of 'SectionFlags'
parseSectionFlags :: G.Get SectionFlags
parseSectionFlags = SectionFlags <$> G.getWord32le

-- | The section should not be padded
--
-- Only valid for object files
pattern SCN_TYPE_NO_PAD :: SectionFlag
pattern SCN_TYPE_NO_PAD = SectionFlag 0x00000008
{-# DEPRECATED SCN_TYPE_NO_PAD "Use SCN_ALIGN_1BYTES" #-}

-- | The section contains executable code
pattern SCN_CNT_CODE :: SectionFlag
pattern SCN_CNT_CODE = SectionFlag 0x00000020

-- | The section contains initialized data
pattern SCN_CNT_INITIALIZED_DATA :: SectionFlag
pattern SCN_CNT_INITIALIZED_DATA = SectionFlag 0x00000040

-- | The section contains uninitialized data
pattern SCN_CNT_UNINITIALIZED_DATA :: SectionFlag
pattern SCN_CNT_UNINITIALIZED_DATA = SectionFlag 0x00000080

-- | Reserved
pattern SCN_LNK_OTHER :: SectionFlag
pattern SCN_LNK_OTHER = SectionFlag 0x00000100

-- | The section contains comments
--
-- Only valid for object files
pattern SCN_LNK_INFO :: SectionFlag
pattern SCN_LNK_INFO = SectionFlag 0x00000200

-- | The section should not be included in an image
--
-- Only valid for object files
pattern SCN_LNK_REMOVE :: SectionFlag
pattern SCN_LNK_REMOVE = SectionFlag 0x00000800

-- | The section includes COMDAT data
--
-- COMDAT data is data that can be defined multiple times (with deduplication
-- handled by the linker).
--
-- Only valid for object files
pattern SCN_LNK_COMDAT :: SectionFlag
pattern SCN_LNK_COMDAT = SectionFlag 0x00001000

-- | The section contains data accessed through the global pointer
pattern SCN_GPREL :: SectionFlag
pattern SCN_GPREL = SectionFlag 0x00008000

-- | Reserved
pattern SCN_MEM_PURGEABLE :: SectionFlag
pattern SCN_MEM_PURGEABLE = SectionFlag 0x00020000

-- | Reserved
pattern SCN_MEM_16BIT :: SectionFlag
pattern SCN_MEM_16BIT = SectionFlag 0x00020000

-- | Reserved
pattern SCN_MEM_LOCKED :: SectionFlag
pattern SCN_MEM_LOCKED = SectionFlag 0x00040000

-- | Reserved
pattern SCN_MEM_PRELOAD :: SectionFlag
pattern SCN_MEM_PRELOAD = SectionFlag 0x00080000

-- | Align to 1 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_1BYTES :: SectionFlag
pattern SCN_ALIGN_1BYTES = SectionFlag 0x00100000

-- | Align to 2 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_2BYTES :: SectionFlag
pattern SCN_ALIGN_2BYTES = SectionFlag 0x00200000

-- | Align to 4 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_4BYTES :: SectionFlag
pattern SCN_ALIGN_4BYTES = SectionFlag 0x00300000

-- | Align to 8 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_8BYTES :: SectionFlag
pattern SCN_ALIGN_8BYTES = SectionFlag 0x00400000

-- | Align to 16 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_16BYTES :: SectionFlag
pattern SCN_ALIGN_16BYTES = SectionFlag 0x00500000

-- | Align to 32 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_32BYTES :: SectionFlag
pattern SCN_ALIGN_32BYTES = SectionFlag 0x00600000

-- | Align to 64 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_64BYTES :: SectionFlag
pattern SCN_ALIGN_64BYTES = SectionFlag 0x00700000

-- | Align to 128 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_128BYTES :: SectionFlag
pattern SCN_ALIGN_128BYTES = SectionFlag 0x00800000

-- | Align to 256 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_256BYTES :: SectionFlag
pattern SCN_ALIGN_256BYTES = SectionFlag 0x00900000

-- | Align to 512 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_512BYTES :: SectionFlag
pattern SCN_ALIGN_512BYTES = SectionFlag 0x00A00000

-- | Align to 1024 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_1024BYTES :: SectionFlag
pattern SCN_ALIGN_1024BYTES = SectionFlag 0x00B00000

-- | Align to 2048 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_2048BYTES :: SectionFlag
pattern SCN_ALIGN_2048BYTES = SectionFlag 0x00C00000

-- | Align to 4096 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_4096BYTES :: SectionFlag
pattern SCN_ALIGN_4096BYTES = SectionFlag 0x00D00000

-- | Align to 8192 byte boundaries
--
-- Only valid for object files
pattern SCN_ALIGN_8192BYTES :: SectionFlag
pattern SCN_ALIGN_8192BYTES = SectionFlag 0x00E00000

-- | The section contains extended relocations
pattern SCN_LNK_NRELOC_OVFL :: SectionFlag
pattern SCN_LNK_NRELOC_OVFL = SectionFlag 0x01000000

-- | The section can be discarded as needed
pattern SCN_MEM_DISCARDABLE :: SectionFlag
pattern SCN_MEM_DISCARDABLE = SectionFlag 0x02000000

-- | The section cannot be cached
pattern SCN_MEM_NOT_CACHED :: SectionFlag
pattern SCN_MEM_NOT_CACHED = SectionFlag 0x04000000

-- | The section is not pageable
pattern SCN_MEM_NOT_PAGED :: SectionFlag
pattern SCN_MEM_NOT_PAGED = SectionFlag 0x08000000

-- | The section can be placed in shared memory
pattern SCN_MEM_SHARED :: SectionFlag
pattern SCN_MEM_SHARED = SectionFlag 0x10000000

-- | The section can be executed as code
pattern SCN_MEM_EXECUTE :: SectionFlag
pattern SCN_MEM_EXECUTE = SectionFlag 0x20000000

-- | The section can be read
pattern SCN_MEM_READ :: SectionFlag
pattern SCN_MEM_READ = SectionFlag 0x40000000

-- | The section can be written
pattern SCN_MEM_WRITE :: SectionFlag
pattern SCN_MEM_WRITE = SectionFlag 0x80000000

-- | Construct a set of flags from a list of 'SectionFlag'
sectionFlags :: [SectionFlag] -> SectionFlags
sectionFlags = SectionFlags . foldr (.|.) 0 . map getFlag

-- | Test to see if a single 'SectionFlag' is set
hasSectionFlag :: SectionFlags -> SectionFlag -> Bool
hasSectionFlag (SectionFlags w) (SectionFlag f) = w .&. f /= 0

-- | Pretty print a set of 'SectionFlag' in a list format
ppSectionFlags :: SectionFlags -> PP.Doc ann
ppSectionFlags (SectionFlags w) =
  PP.brackets (PP.hsep (PP.punctuate PP.comma docs))
  where
    docs = [ ppSectionFlag (SectionFlag (bit bitNum))
           | bitNum <- [0..31]
           , testBit w bitNum
           ]

-- | Pretty print a single 'SectionFlag'
ppSectionFlag :: SectionFlag -> PP.Doc ann
ppSectionFlag sf =
  case sf of
    SCN_TYPE_NO_PAD -> PP.pretty "SCN_TYPE_NO_PAD"
    SCN_CNT_CODE -> PP.pretty "SCN_CNT_CODE"
    SCN_CNT_INITIALIZED_DATA -> PP.pretty "SCN_CNT_INITIALIZED_DATA"
    SCN_CNT_UNINITIALIZED_DATA -> PP.pretty "SCN_CNT_UNINITIALIZED_DATA"
    SCN_LNK_OTHER -> PP.pretty "SCN_LNK_OTHER"
    SCN_LNK_INFO -> PP.pretty "SCN_LNK_INFO"
    SCN_LNK_REMOVE -> PP.pretty "SCN_LNK_REMOVE"
    SCN_LNK_COMDAT -> PP.pretty "SCN_LNK_COMDAT"
    SCN_GPREL -> PP.pretty "SCN_GPREL"
    SCN_MEM_PURGEABLE -> PP.pretty "SCN_MEM_PURGEABLE"
    SCN_MEM_16BIT -> PP.pretty "SCN_MEM_16BIT"
    SCN_MEM_LOCKED -> PP.pretty "SCN_MEM_LOCKED"
    SCN_MEM_PRELOAD -> PP.pretty "SCN_MEM_PRELOAD"
    SCN_ALIGN_1BYTES -> PP.pretty "SCN_ALIGN_1BYTES"
    SCN_ALIGN_2BYTES -> PP.pretty "SCN_ALIGN_2BYTES"
    SCN_ALIGN_4BYTES -> PP.pretty "SCN_ALIGN_4BYTES"
    SCN_ALIGN_8BYTES -> PP.pretty "SCN_ALIGN_8BYTES"
    SCN_ALIGN_16BYTES -> PP.pretty "SCN_ALIGN_16BYTES"
    SCN_ALIGN_32BYTES -> PP.pretty "SCN_ALIGN_32BYTES"
    SCN_ALIGN_64BYTES -> PP.pretty "SCN_ALIGN_64BYTES"
    SCN_ALIGN_128BYTES -> PP.pretty "SCN_ALIGN_128BYTES"
    SCN_ALIGN_256BYTES -> PP.pretty "SCN_ALIGN_256BYTES"
    SCN_ALIGN_512BYTES -> PP.pretty "SCN_ALIGN_512BYTES"
    SCN_ALIGN_1024BYTES -> PP.pretty "SCN_ALIGN_1024BYTES"
    SCN_ALIGN_2048BYTES -> PP.pretty "SCN_ALIGN_2048BYTES"
    SCN_ALIGN_4096BYTES -> PP.pretty "SCN_ALIGN_4096BYTES"
    SCN_ALIGN_8192BYTES -> PP.pretty "SCN_ALIGN_8192BYTES"
    SCN_LNK_NRELOC_OVFL -> PP.pretty "SCN_LNK_NRELOC_OVFL"
    SCN_MEM_DISCARDABLE -> PP.pretty "SCN_MEM_DISCARDABLE"
    SCN_MEM_NOT_CACHED -> PP.pretty "SCN_MEM_NOT_CACHED"
    SCN_MEM_NOT_PAGED -> PP.pretty "SCN_MEM_NOT_PAGED"
    SCN_MEM_SHARED -> PP.pretty "SCN_MEM_SHARED"
    SCN_MEM_EXECUTE -> PP.pretty "SCN_MEM_EXECUTE"
    SCN_MEM_READ -> PP.pretty "SCN_MEM_READ"
    SCN_MEM_WRITE -> PP.pretty "SCN_MEM_WRITE"
    SectionFlag f -> PP.pretty "SectionFlag" <> PP.brackets (PP.pretty f)
