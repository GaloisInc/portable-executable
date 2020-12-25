{-# LANGUAGE PatternSynonyms #-}
-- | PE file characteristics
--
-- Note that the 'Characteristics' type is a bitmask, and can thus represent
-- multiple of the named constants.
--
-- The individual allowable values are 'Characteristic'
module PE.Parser.Characteristics (
  Characteristics,
  Characteristic,
  hasCharacteristic,
  characteristics,
  ppCharacteristics,
  ppCharacteristic,
  parseCharacteristics,
  -- * Characteristic definitions
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

newtype Characteristics = Characteristics Word16
  deriving (Show)

-- | Note that while this is a bitmask, it is defined as @COMPLETE@ here because
-- every bit is accounted for.
newtype Characteristic = Characteristic { getMask :: Word16 }
  deriving (Show)

hasCharacteristic :: Characteristics -> Characteristic -> Bool
hasCharacteristic (Characteristics w) (Characteristic m) = w .&. m /= 0

characteristics :: [Characteristic] -> Characteristics
characteristics = Characteristics . foldr (.|.) 0 . map getMask

{-# COMPLETE PE_RELOCS_STRIPPED, PE_EXECUTABLE_IMAGE, PE_LINE_NUMS_STRIPPED, PE_LOCAL_SYMS_STRIPPED,
             PE_AGGRESSIVE_WS_TRIM, PE_LARGE_ADDRESS_AWARE, PE_RESERVED_CHARACTERISTIC, PE_BYTES_REVERSED_LO,
             PE_32BIT_MACHINE, PE_DEBUG_STRIPPED, PE_REMOVABLE_RUN_FROM_SWAP, PE_NET_RUN_FROM_SWAP,
             PE_SYSTEM, PE_DLL, PE_UP_SYSTEM_ONLY, PE_BYTES_REVERSED_HI #-}

pattern PE_RELOCS_STRIPPED :: Characteristic
pattern PE_RELOCS_STRIPPED = Characteristic 0x0001

pattern PE_EXECUTABLE_IMAGE :: Characteristic
pattern PE_EXECUTABLE_IMAGE = Characteristic 0x0002


pattern PE_LINE_NUMS_STRIPPED :: Characteristic
pattern PE_LINE_NUMS_STRIPPED = Characteristic 0x0004

pattern PE_LOCAL_SYMS_STRIPPED :: Characteristic
pattern PE_LOCAL_SYMS_STRIPPED = Characteristic 0x0008

pattern PE_AGGRESSIVE_WS_TRIM :: Characteristic
pattern PE_AGGRESSIVE_WS_TRIM = Characteristic 0x0010

pattern PE_LARGE_ADDRESS_AWARE :: Characteristic
pattern PE_LARGE_ADDRESS_AWARE = Characteristic 0x0020

-- | This value is reserved for future use (but included for pattern completeness)
pattern PE_RESERVED_CHARACTERISTIC :: Characteristic
pattern PE_RESERVED_CHARACTERISTIC = Characteristic 0x0040

-- | Little endian
--
-- This flag is deprecated and should be zero
pattern PE_BYTES_REVERSED_LO :: Characteristic
pattern PE_BYTES_REVERSED_LO = Characteristic 0x0080

pattern PE_32BIT_MACHINE :: Characteristic
pattern PE_32BIT_MACHINE = Characteristic 0x0100

pattern PE_DEBUG_STRIPPED :: Characteristic
pattern PE_DEBUG_STRIPPED = Characteristic 0x0200

pattern PE_REMOVABLE_RUN_FROM_SWAP :: Characteristic
pattern PE_REMOVABLE_RUN_FROM_SWAP = Characteristic 0x0400

pattern PE_NET_RUN_FROM_SWAP :: Characteristic
pattern PE_NET_RUN_FROM_SWAP = Characteristic 0x0800

pattern PE_SYSTEM :: Characteristic
pattern PE_SYSTEM = Characteristic 0x1000

pattern PE_DLL :: Characteristic
pattern PE_DLL = Characteristic 0x2000

-- | Uni-processor system only
pattern PE_UP_SYSTEM_ONLY :: Characteristic
pattern PE_UP_SYSTEM_ONLY = Characteristic 0x4000

-- | Big endian
--
-- This flag is deprecated and should be zero
pattern PE_BYTES_REVERSED_HI :: Characteristic
pattern PE_BYTES_REVERSED_HI = Characteristic 0x8000


parseCharacteristics :: G.Get Characteristics
parseCharacteristics = Characteristics <$> G.getWord16le

ppCharacteristics :: Characteristics -> PP.Doc a
ppCharacteristics (Characteristics w) =
  PP.brackets (PP.hsep (PP.punctuate PP.comma docs))
  where
    docs = [ ppCharacteristic (Characteristic (bit bitNum))
           | bitNum <- [0..15]
           , testBit w bitNum
           ]

ppCharacteristic :: Characteristic -> PP.Doc a
ppCharacteristic c =
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
