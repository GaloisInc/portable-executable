{-# LANGUAGE PatternSynonyms #-}
-- | PE file characteristics
--
-- Note that the 'FileFlags' type is a bitmask, and can thus represent
-- multiple of the named constants.
--
-- The individual allowable values are 'FileFlag'
module PE.Parser.FileFlags (
  FileFlags,
  FileFlag,
  hasFileFlag,
  fileFlags,
  ppFileFlags,
  ppFileFlag,
  parseFileFlags,
  -- *** FileFlag definitions
  pattern PE_RELOCS_STRIPPED,
  pattern PE_EXECUTABLE_IMAGE,
  pattern PE_LINE_NUMS_STRIPPED,
  pattern PE_LOCAL_SYMS_STRIPPED,
  pattern PE_AGGRESSIVE_WS_TRIM,
  pattern PE_LARGE_ADDRESS_AWARE,
  pattern PE_RESERVED_CHARACTERISTIC,
  pattern PE_BYTES_REVERSED_LO,
  pattern PE_32BIT_MACHINE,
  pattern PE_DEBUG_STRIPPED,
  pattern PE_REMOVABLE_RUN_FROM_SWAP,
  pattern PE_NET_RUN_FROM_SWAP,
  pattern PE_SYSTEM,
  pattern PE_DLL,
  pattern PE_UP_SYSTEM_ONLY,
  pattern PE_BYTES_REVERSED_HI
  ) where

import           Data.Bits ( (.|.), (.&.), bit, testBit )
import qualified Data.Binary.Get as G
import           Data.Word ( Word16 )
import qualified Prettyprinter as PP

-- | A bitset of flags describing the features of the PE file
newtype FileFlags = FileFlags Word16
  deriving (Show)

-- | Note that while this is a bitmask, it is defined as @COMPLETE@ here because
-- every bit is accounted for.
newtype FileFlag = FileFlag { getMask :: Word16 }
  deriving (Show)

-- | Test if a given 'FileFlag' is set
hasFileFlag :: FileFlags -> FileFlag -> Bool
hasFileFlag (FileFlags w) (FileFlag m) = w .&. m /= 0

-- | Construct 'FileFlags' out of a set of individual 'FileFlags'
fileFlags :: [FileFlag] -> FileFlags
fileFlags = FileFlags . foldr (.|.) 0 . map getMask

{-# COMPLETE PE_RELOCS_STRIPPED, PE_EXECUTABLE_IMAGE, PE_LINE_NUMS_STRIPPED, PE_LOCAL_SYMS_STRIPPED,
             PE_AGGRESSIVE_WS_TRIM, PE_LARGE_ADDRESS_AWARE, PE_RESERVED_CHARACTERISTIC, PE_BYTES_REVERSED_LO,
             PE_32BIT_MACHINE, PE_DEBUG_STRIPPED, PE_REMOVABLE_RUN_FROM_SWAP, PE_NET_RUN_FROM_SWAP,
             PE_SYSTEM, PE_DLL, PE_UP_SYSTEM_ONLY, PE_BYTES_REVERSED_HI #-}

-- | The file has no base relocations and must be loaded at its preferred base address
--
-- Images only
pattern PE_RELOCS_STRIPPED :: FileFlag
pattern PE_RELOCS_STRIPPED = FileFlag 0x0001

-- | This is an executable image that can be run directly
pattern PE_EXECUTABLE_IMAGE :: FileFlag
pattern PE_EXECUTABLE_IMAGE = FileFlag 0x0002

-- | COFF line numbers have been stripped
--
-- Deprecated (should be zero)
pattern PE_LINE_NUMS_STRIPPED :: FileFlag
pattern PE_LINE_NUMS_STRIPPED = FileFlag 0x0004

-- | COFF symbol table entries have been stripped
--
-- Deprecated (should be zero)
pattern PE_LOCAL_SYMS_STRIPPED :: FileFlag
pattern PE_LOCAL_SYMS_STRIPPED = FileFlag 0x0008

-- | Aggressively trim the working setup
--
-- Deprecated (since Windows 2000)
pattern PE_AGGRESSIVE_WS_TRIM :: FileFlag
pattern PE_AGGRESSIVE_WS_TRIM = FileFlag 0x0010

-- | The application can handle addresses larger than 2GB
pattern PE_LARGE_ADDRESS_AWARE :: FileFlag
pattern PE_LARGE_ADDRESS_AWARE = FileFlag 0x0020

-- | This value is reserved for future use (but included for pattern completeness)
pattern PE_RESERVED_CHARACTERISTIC :: FileFlag
pattern PE_RESERVED_CHARACTERISTIC = FileFlag 0x0040

-- | Little endian
--
-- This flag is deprecated and should be zero
pattern PE_BYTES_REVERSED_LO :: FileFlag
pattern PE_BYTES_REVERSED_LO = FileFlag 0x0080

-- | The machine uses a 32 bit architecture
pattern PE_32BIT_MACHINE :: FileFlag
pattern PE_32BIT_MACHINE = FileFlag 0x0100

-- | Debugging information has been removed from the file
pattern PE_DEBUG_STRIPPED :: FileFlag
pattern PE_DEBUG_STRIPPED = FileFlag 0x0200

-- | Fully load the executable image into swap space if it is located on removable media
pattern PE_REMOVABLE_RUN_FROM_SWAP :: FileFlag
pattern PE_REMOVABLE_RUN_FROM_SWAP = FileFlag 0x0400

-- | Fully load the executable image into swap space if it is located on network media
pattern PE_NET_RUN_FROM_SWAP :: FileFlag
pattern PE_NET_RUN_FROM_SWAP = FileFlag 0x0800

-- | The image is a system program (not a user program)
pattern PE_SYSTEM :: FileFlag
pattern PE_SYSTEM = FileFlag 0x1000

-- | The image file is a DLL
pattern PE_DLL :: FileFlag
pattern PE_DLL = FileFlag 0x2000

-- | Uni-processor system only
pattern PE_UP_SYSTEM_ONLY :: FileFlag
pattern PE_UP_SYSTEM_ONLY = FileFlag 0x4000

-- | Big endian
--
-- This flag is deprecated and should be zero
pattern PE_BYTES_REVERSED_HI :: FileFlag
pattern PE_BYTES_REVERSED_HI = FileFlag 0x8000

-- | Parse 'FileFlags'
parseFileFlags :: G.Get FileFlags
parseFileFlags = FileFlags <$> G.getWord16le

-- | Pretty print a set of 'FileFlags' in a list format
ppFileFlags :: FileFlags -> PP.Doc a
ppFileFlags (FileFlags w) =
  PP.brackets (PP.hsep (PP.punctuate PP.comma docs))
  where
    docs = [ ppFileFlag (FileFlag (bit bitNum))
           | bitNum <- [0..15]
           , testBit w bitNum
           ]

-- | Pretty print a single 'FileFlag'
ppFileFlag :: FileFlag -> PP.Doc a
ppFileFlag c =
  case c of
    PE_RELOCS_STRIPPED -> PP.pretty "PE_RELOCS_STRIPPED"
    PE_EXECUTABLE_IMAGE -> PP.pretty "PE_EXECUTABLE_IMAGE"
    PE_LINE_NUMS_STRIPPED -> PP.pretty "PE_LINE_NUMS_STRIPPED"
    PE_LOCAL_SYMS_STRIPPED -> PP.pretty "PE_LOCAL_SYMS_STRIPPED"
    PE_AGGRESSIVE_WS_TRIM -> PP.pretty "PE_AGGRESSIVE_WS_TRIM"
    PE_LARGE_ADDRESS_AWARE -> PP.pretty "PE_LARGE_ADDRESS_AWARE"
    PE_RESERVED_CHARACTERISTIC -> PP.pretty "PE_RESERVED_CHARACTERISTIC"
    PE_BYTES_REVERSED_LO -> PP.pretty "PE_BYTES_REVERSED_LO"
    PE_32BIT_MACHINE -> PP.pretty "PE_32BIT_MACHINE"
    PE_DEBUG_STRIPPED -> PP.pretty "PE_DEBUG_STRIPPED"
    PE_REMOVABLE_RUN_FROM_SWAP -> PP.pretty "PE_REMOVABLE_RUN_FROM_SWAP"
    PE_NET_RUN_FROM_SWAP -> PP.pretty "PE_NET_RUN_FROM_SWAP"
    PE_SYSTEM -> PP.pretty "PE_SYSTEM"
    PE_DLL -> PP.pretty "PE_DLL"
    PE_UP_SYSTEM_ONLY -> PP.pretty "PE_UP_SYSTEM_ONLY"
    PE_BYTES_REVERSED_HI -> PP.pretty "PE_BYTES_REVERSED_HI"
