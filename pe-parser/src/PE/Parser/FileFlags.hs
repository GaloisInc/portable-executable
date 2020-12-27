{-# LANGUAGE PatternSynonyms #-}
-- | PE file characteristics
--
-- Note that the 'Characteristics' type is a bitmask, and can thus represent
-- multiple of the named constants.
--
-- The individual allowable values are 'Characteristic'
module PE.Parser.FileFlags (
  FileFlags,
  FileFlag,
  hasFileFlag,
  fileFlags,
  ppFileFlags,
  ppFileFlag,
  parseFileFlags,
  -- * FileFlag definitions
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

newtype FileFlags = FileFlags Word16
  deriving (Show)

-- | Note that while this is a bitmask, it is defined as @COMPLETE@ here because
-- every bit is accounted for.
newtype FileFlag = FileFlag { getMask :: Word16 }
  deriving (Show)

hasFileFlag :: FileFlags -> FileFlag -> Bool
hasFileFlag (FileFlags w) (FileFlag m) = w .&. m /= 0

fileFlags :: [FileFlag] -> FileFlags
fileFlags = FileFlags . foldr (.|.) 0 . map getMask

{-# COMPLETE PE_RELOCS_STRIPPED, PE_EXECUTABLE_IMAGE, PE_LINE_NUMS_STRIPPED, PE_LOCAL_SYMS_STRIPPED,
             PE_AGGRESSIVE_WS_TRIM, PE_LARGE_ADDRESS_AWARE, PE_RESERVED_CHARACTERISTIC, PE_BYTES_REVERSED_LO,
             PE_32BIT_MACHINE, PE_DEBUG_STRIPPED, PE_REMOVABLE_RUN_FROM_SWAP, PE_NET_RUN_FROM_SWAP,
             PE_SYSTEM, PE_DLL, PE_UP_SYSTEM_ONLY, PE_BYTES_REVERSED_HI #-}

pattern PE_RELOCS_STRIPPED :: FileFlag
pattern PE_RELOCS_STRIPPED = FileFlag 0x0001

pattern PE_EXECUTABLE_IMAGE :: FileFlag
pattern PE_EXECUTABLE_IMAGE = FileFlag 0x0002


pattern PE_LINE_NUMS_STRIPPED :: FileFlag
pattern PE_LINE_NUMS_STRIPPED = FileFlag 0x0004

pattern PE_LOCAL_SYMS_STRIPPED :: FileFlag
pattern PE_LOCAL_SYMS_STRIPPED = FileFlag 0x0008

pattern PE_AGGRESSIVE_WS_TRIM :: FileFlag
pattern PE_AGGRESSIVE_WS_TRIM = FileFlag 0x0010

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

pattern PE_32BIT_MACHINE :: FileFlag
pattern PE_32BIT_MACHINE = FileFlag 0x0100

pattern PE_DEBUG_STRIPPED :: FileFlag
pattern PE_DEBUG_STRIPPED = FileFlag 0x0200

pattern PE_REMOVABLE_RUN_FROM_SWAP :: FileFlag
pattern PE_REMOVABLE_RUN_FROM_SWAP = FileFlag 0x0400

pattern PE_NET_RUN_FROM_SWAP :: FileFlag
pattern PE_NET_RUN_FROM_SWAP = FileFlag 0x0800

pattern PE_SYSTEM :: FileFlag
pattern PE_SYSTEM = FileFlag 0x1000

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


parseFileFlags :: G.Get FileFlags
parseFileFlags = FileFlags <$> G.getWord16le

ppFileFlags :: FileFlags -> PP.Doc a
ppFileFlags (FileFlags w) =
  PP.brackets (PP.hsep (PP.punctuate PP.comma docs))
  where
    docs = [ ppFileFlag (FileFlag (bit bitNum))
           | bitNum <- [0..15]
           , testBit w bitNum
           ]

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
