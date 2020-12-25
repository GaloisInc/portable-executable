{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
module PE.Parser.SectionHeader (
  SectionHeader(..),
  sectionHeaderNameText,
  parseSectionHeader,
  ppSectionHeader,
  -- * Flags
  SectionFlags,
  SectionFlag,
  sectionFlags,
  hasSectionFlag,
  ppSectionFlag,
  ppSectionFlags,
  parseSectionFlags,
  -- ** Pre-defined flag constants
  pattern PE_SCN_TYPE_NO_PAD,
  pattern PE_SCN_CNT_CODE,
  pattern PE_SCN_CNT_INITIALIZED_DATA,
  pattern PE_SCN_CNT_UNINITIALIZED_DATA,
  pattern PE_SCN_LNK_OTHER,
  pattern PE_SCN_LNK_INFO,
  pattern PE_SCN_LNK_REMOVE,
  pattern PE_SCN_LNK_COMDAT,
  pattern PE_SCN_GPREL,
  pattern PE_SCN_MEM_PURGEABLE,
  pattern PE_SCN_MEM_16BIT,
  pattern PE_SCN_MEM_LOCKED,
  pattern PE_SCN_MEM_PRELOAD,
  pattern PE_SCN_ALIGN_1BYTES,
  pattern PE_SCN_ALIGN_2BYTES,
  pattern PE_SCN_ALIGN_4BYTES,
  pattern PE_SCN_ALIGN_8BYTES,
  pattern PE_SCN_ALIGN_16BYTES,
  pattern PE_SCN_ALIGN_32BYTES,
  pattern PE_SCN_ALIGN_64BYTES,
  pattern PE_SCN_ALIGN_128BYTES,
  pattern PE_SCN_ALIGN_256BYTES,
  pattern PE_SCN_ALIGN_512BYTES,
  pattern PE_SCN_ALIGN_1024BYTES,
  pattern PE_SCN_ALIGN_2048BYTES,
  pattern PE_SCN_ALIGN_4096BYTES,
  pattern PE_SCN_ALIGN_8192BYTES,
  pattern PE_SCN_LNK_NRELOC_OVFL,
  pattern PE_SCN_MEM_DISCARDABLE,
  pattern PE_SCN_MEM_NOT_CACHED,
  pattern PE_SCN_MEM_NOT_PAGED,
  pattern PE_SCN_MEM_SHARED,
  pattern PE_SCN_MEM_EXECUTE,
  pattern PE_SCN_MEM_READ,
  pattern PE_SCN_MEM_WRITE
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

data SectionHeader =
  SectionHeader { sectionHeaderName :: PV.Vector 8 Word8
                -- ^ The documentation says that this is UTF-8 encoded, but it
                -- probably isn't a great idea to trust that.  There is a
                -- separate combinator to attempt that interpretation (with a
                -- lenient decoding).
                --
                -- We keep the raw bytes to make it reproducible
                , sectionHeaderVirtualSize :: Word32
                , sectionHeaderVirtualAddress :: Word32
                , sectionHeaderSizeOfRawData :: Word32
                , sectionHeaderPointerToRawData :: Word32
                , sectionHeaderPointerToRelocations :: Word32
                , sectionHeaderPointerToLinnumbers :: Word32
                -- ^ File pointer to the beginning of the line number entries
                -- for the section; this should be 0 because COFF debugging info
                -- is deprecated.
                , sectionHeaderNumberOfRelocations :: Word16
                , sectionHeaderNumberOfLinenumbers :: Word16
                -- ^ This should also be 0 because COFF debugging is deprecated
                , sectionHeaderCharacteristics :: SectionFlags
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

newtype SectionFlag = SectionFlag { getFlag :: Word32 }
  deriving (Show)

newtype SectionFlags = SectionFlags Word32
  deriving (Show)

parseSectionFlags :: G.Get SectionFlags
parseSectionFlags = SectionFlags <$> G.getWord32le

pattern PE_SCN_TYPE_NO_PAD :: SectionFlag
pattern PE_SCN_TYPE_NO_PAD = SectionFlag 0x00000008

pattern PE_SCN_CNT_CODE :: SectionFlag
pattern PE_SCN_CNT_CODE = SectionFlag 0x00000020

pattern PE_SCN_CNT_INITIALIZED_DATA :: SectionFlag
pattern PE_SCN_CNT_INITIALIZED_DATA = SectionFlag 0x00000040

pattern PE_SCN_CNT_UNINITIALIZED_DATA :: SectionFlag
pattern PE_SCN_CNT_UNINITIALIZED_DATA = SectionFlag 0x00000080

pattern PE_SCN_LNK_OTHER :: SectionFlag
pattern PE_SCN_LNK_OTHER = SectionFlag 0x00000100

pattern PE_SCN_LNK_INFO :: SectionFlag
pattern PE_SCN_LNK_INFO = SectionFlag 0x00000200

pattern PE_SCN_LNK_REMOVE :: SectionFlag
pattern PE_SCN_LNK_REMOVE = SectionFlag 0x00000800

pattern PE_SCN_LNK_COMDAT :: SectionFlag
pattern PE_SCN_LNK_COMDAT = SectionFlag 0x00001000

pattern PE_SCN_GPREL :: SectionFlag
pattern PE_SCN_GPREL = SectionFlag 0x00008000

pattern PE_SCN_MEM_PURGEABLE :: SectionFlag
pattern PE_SCN_MEM_PURGEABLE = SectionFlag 0x00020000

pattern PE_SCN_MEM_16BIT :: SectionFlag
pattern PE_SCN_MEM_16BIT = SectionFlag 0x00020000

pattern PE_SCN_MEM_LOCKED :: SectionFlag
pattern PE_SCN_MEM_LOCKED = SectionFlag 0x00040000

pattern PE_SCN_MEM_PRELOAD :: SectionFlag
pattern PE_SCN_MEM_PRELOAD = SectionFlag 0x00080000

pattern PE_SCN_ALIGN_1BYTES :: SectionFlag
pattern PE_SCN_ALIGN_1BYTES = SectionFlag 0x00100000

pattern PE_SCN_ALIGN_2BYTES :: SectionFlag
pattern PE_SCN_ALIGN_2BYTES = SectionFlag 0x00200000

pattern PE_SCN_ALIGN_4BYTES :: SectionFlag
pattern PE_SCN_ALIGN_4BYTES = SectionFlag 0x00300000

pattern PE_SCN_ALIGN_8BYTES :: SectionFlag
pattern PE_SCN_ALIGN_8BYTES = SectionFlag 0x00400000

pattern PE_SCN_ALIGN_16BYTES :: SectionFlag
pattern PE_SCN_ALIGN_16BYTES = SectionFlag 0x00500000

pattern PE_SCN_ALIGN_32BYTES :: SectionFlag
pattern PE_SCN_ALIGN_32BYTES = SectionFlag 0x00600000

pattern PE_SCN_ALIGN_64BYTES :: SectionFlag
pattern PE_SCN_ALIGN_64BYTES = SectionFlag 0x00700000

pattern PE_SCN_ALIGN_128BYTES :: SectionFlag
pattern PE_SCN_ALIGN_128BYTES = SectionFlag 0x00800000

pattern PE_SCN_ALIGN_256BYTES :: SectionFlag
pattern PE_SCN_ALIGN_256BYTES = SectionFlag 0x00900000

pattern PE_SCN_ALIGN_512BYTES :: SectionFlag
pattern PE_SCN_ALIGN_512BYTES = SectionFlag 0x00A00000

pattern PE_SCN_ALIGN_1024BYTES :: SectionFlag
pattern PE_SCN_ALIGN_1024BYTES = SectionFlag 0x00B00000

pattern PE_SCN_ALIGN_2048BYTES :: SectionFlag
pattern PE_SCN_ALIGN_2048BYTES = SectionFlag 0x00C00000

pattern PE_SCN_ALIGN_4096BYTES :: SectionFlag
pattern PE_SCN_ALIGN_4096BYTES = SectionFlag 0x00D00000

pattern PE_SCN_ALIGN_8192BYTES :: SectionFlag
pattern PE_SCN_ALIGN_8192BYTES = SectionFlag 0x00E00000

pattern PE_SCN_LNK_NRELOC_OVFL :: SectionFlag
pattern PE_SCN_LNK_NRELOC_OVFL = SectionFlag 0x01000000

pattern PE_SCN_MEM_DISCARDABLE :: SectionFlag
pattern PE_SCN_MEM_DISCARDABLE = SectionFlag 0x02000000

pattern PE_SCN_MEM_NOT_CACHED :: SectionFlag
pattern PE_SCN_MEM_NOT_CACHED = SectionFlag 0x04000000

pattern PE_SCN_MEM_NOT_PAGED :: SectionFlag
pattern PE_SCN_MEM_NOT_PAGED = SectionFlag 0x08000000

pattern PE_SCN_MEM_SHARED :: SectionFlag
pattern PE_SCN_MEM_SHARED = SectionFlag 0x10000000

pattern PE_SCN_MEM_EXECUTE :: SectionFlag
pattern PE_SCN_MEM_EXECUTE = SectionFlag 0x20000000

pattern PE_SCN_MEM_READ :: SectionFlag
pattern PE_SCN_MEM_READ = SectionFlag 0x40000000

pattern PE_SCN_MEM_WRITE :: SectionFlag
pattern PE_SCN_MEM_WRITE = SectionFlag 0x80000000

sectionFlags :: [SectionFlag] -> SectionFlags
sectionFlags = SectionFlags . foldr (.|.) 0 . map getFlag

hasSectionFlag :: SectionFlags -> SectionFlag -> Bool
hasSectionFlag (SectionFlags w) (SectionFlag f) = w .&. f /= 0

ppSectionFlags :: SectionFlags -> PP.Doc ann
ppSectionFlags (SectionFlags w) =
  PP.brackets (PP.hsep (PP.punctuate PP.comma docs))
  where
    docs = [ ppSectionFlag (SectionFlag (bit bitNum))
           | bitNum <- [0..31]
           , testBit w bitNum
           ]

ppSectionFlag :: SectionFlag -> PP.Doc ann
ppSectionFlag sf =
  case sf of
    PE_SCN_TYPE_NO_PAD -> PP.pretty "PE_SCN_TYPE_NO_PAD"
    PE_SCN_CNT_CODE -> PP.pretty "PE_SCN_CNT_CODE"
    PE_SCN_CNT_INITIALIZED_DATA -> PP.pretty "PE_SCN_CNT_INITIALIZED_DATA"
    PE_SCN_CNT_UNINITIALIZED_DATA -> PP.pretty "PE_SCN_CNT_UNINITIALIZED_DATA"
    PE_SCN_LNK_OTHER -> PP.pretty "PE_SCN_LNK_OTHER"
    PE_SCN_LNK_INFO -> PP.pretty "PE_SCN_LNK_INFO"
    PE_SCN_LNK_REMOVE -> PP.pretty "PE_SCN_LNK_REMOVE"
    PE_SCN_LNK_COMDAT -> PP.pretty "PE_SCN_LNK_COMDAT"
    PE_SCN_GPREL -> PP.pretty "PE_SCN_GPREL"
    PE_SCN_MEM_PURGEABLE -> PP.pretty "PE_SCN_MEM_PURGEABLE"
    PE_SCN_MEM_16BIT -> PP.pretty "PE_SCN_MEM_16BIT"
    PE_SCN_MEM_LOCKED -> PP.pretty "PE_SCN_MEM_LOCKED"
    PE_SCN_MEM_PRELOAD -> PP.pretty "PE_SCN_MEM_PRELOAD"
    PE_SCN_ALIGN_1BYTES -> PP.pretty "PE_SCN_ALIGN_1BYTES"
    PE_SCN_ALIGN_2BYTES -> PP.pretty "PE_SCN_ALIGN_2BYTES"
    PE_SCN_ALIGN_4BYTES -> PP.pretty "PE_SCN_ALIGN_4BYTES"
    PE_SCN_ALIGN_8BYTES -> PP.pretty "PE_SCN_ALIGN_8BYTES"
    PE_SCN_ALIGN_16BYTES -> PP.pretty "PE_SCN_ALIGN_16BYTES"
    PE_SCN_ALIGN_32BYTES -> PP.pretty "PE_SCN_ALIGN_32BYTES"
    PE_SCN_ALIGN_64BYTES -> PP.pretty "PE_SCN_ALIGN_64BYTES"
    PE_SCN_ALIGN_128BYTES -> PP.pretty "PE_SCN_ALIGN_128BYTES"
    PE_SCN_ALIGN_256BYTES -> PP.pretty "PE_SCN_ALIGN_256BYTES"
    PE_SCN_ALIGN_512BYTES -> PP.pretty "PE_SCN_ALIGN_512BYTES"
    PE_SCN_ALIGN_1024BYTES -> PP.pretty "PE_SCN_ALIGN_1024BYTES"
    PE_SCN_ALIGN_2048BYTES -> PP.pretty "PE_SCN_ALIGN_2048BYTES"
    PE_SCN_ALIGN_4096BYTES -> PP.pretty "PE_SCN_ALIGN_4096BYTES"
    PE_SCN_ALIGN_8192BYTES -> PP.pretty "PE_SCN_ALIGN_8192BYTES"
    PE_SCN_LNK_NRELOC_OVFL -> PP.pretty "PE_SCN_LNK_NRELOC_OVFL"
    PE_SCN_MEM_DISCARDABLE -> PP.pretty "PE_SCN_MEM_DISCARDABLE"
    PE_SCN_MEM_NOT_CACHED -> PP.pretty "PE_SCN_MEM_NOT_CACHED"
    PE_SCN_MEM_NOT_PAGED -> PP.pretty "PE_SCN_MEM_NOT_PAGED"
    PE_SCN_MEM_SHARED -> PP.pretty "PE_SCN_MEM_SHARED"
    PE_SCN_MEM_EXECUTE -> PP.pretty "PE_SCN_MEM_EXECUTE"
    PE_SCN_MEM_READ -> PP.pretty "PE_SCN_MEM_READ"
    PE_SCN_MEM_WRITE -> PP.pretty "PE_SCN_MEM_WRITE"
    SectionFlag f -> PP.pretty "SectionFlag" <> PP.brackets (PP.pretty f)
