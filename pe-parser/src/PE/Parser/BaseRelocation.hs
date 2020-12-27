{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
module PE.Parser.BaseRelocation (
  RelocationType,
  BaseRelocationBlock(..),
  RelocationBlockEntry(..),
  ppRelocationType,
  ppRelocationBlockEntry,
  ppBaseRelocationBlock,
  parseRelocationBlockEntry,
  parseBaseRelocationBlock,
  -- * Relocation's
  pattern REL_BASED_ABSOLUTE,
  pattern REL_BASED_HIGH,
  pattern REL_BASED_LOW,
  pattern REL_BASED_HIGHLOW,
  pattern REL_BASED_HIGHADJ,
  pattern REL_BASED_MIPS_JMPADDR,
  pattern REL_BASED_ARM_MOV32,
  pattern REL_BASED_RISCV_HIGH20,
  pattern REL_BASED_THUMB_MOV32,
  pattern REL_BASED_RISCV_LOW12I,
  pattern REL_BASED_RISCV_LOW12S,
  pattern REL_BASED_MIPS_JMPADDR16,
  pattern REL_BASED_DIR64
  ) where

import           Control.Monad ( replicateM )
import qualified Data.Binary.Get as G
import qualified Data.Bits as DB
import           Data.Bits ( (.&.) )
import qualified Data.BitVector.Sized as BVS
import qualified Data.Parameterized.NatRepr as PN
import           Data.Word ( Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.Pretty as PPP

-- | The type of Base Relocation
--
-- See the predefined constants for supported relocations
newtype RelocationType = RelocationType (BVS.BV 4)
  deriving (Show)

-- | A base relocation entry
--
-- Relocations are applied based on the /difference/ computed between the
-- preferred base address of an image and its actual base address.
data RelocationBlockEntry =
  RelocationBlockEntry { relocationBlockEntryType :: RelocationType
                       -- ^ The type of the relocation
                       , relocationBlockEntryOffset :: BVS.BV 12
                       -- ^ The offset of the relocation
                       --
                       -- It is stored as a bitvector to allow us to interpret
                       -- it as either signed or unsigned as needed
                       }
  deriving (Show)

-- | A block of base relocation subject to the same page offset
--
-- These are Base Relocations because they are applied in response to the Image
-- Base being relocated from the requested value
data BaseRelocationBlock =
  BaseRelocationBlock { baseRelocationPageRVA :: Word32
                      -- ^ The Image Base plus this RVA are added to the offset
                      -- in each 'RelocationBlockEntry' in this block to
                      -- determine where the relocation is applied
                      , baseRelocationEntries :: [RelocationBlockEntry]
                      -- ^ On disk, this list is represented by a Word32 (Block
                      -- Size) that says how many bytes are occupied by the
                      -- table (the RVA, the Size, and all of the entries); they
                      -- are decoded into relocation entries in this structure
                      }
  deriving (Show)

-- | Parse a block of relocations
parseBaseRelocationBlock :: G.Get BaseRelocationBlock
parseBaseRelocationBlock = do
  pageRVA <- G.getWord32le
  totalSize <- G.getWord32le

  let headerSizeBytes = 8
  let entryBytes = totalSize - headerSizeBytes
  -- Each entry is 2 bytes
  let entryCount = entryBytes `div` 2
  entries <- replicateM (fromIntegral entryCount) parseRelocationBlockEntry
  return BaseRelocationBlock { baseRelocationPageRVA = pageRVA
                             , baseRelocationEntries = entries
                             }

-- | Parse a single relocation entry
parseRelocationBlockEntry :: G.Get RelocationBlockEntry
parseRelocationBlockEntry = do
  w16 <- G.getWord16le
  -- Take 4 bits as the type, and 12 bits as the offset
  let rt = w16 `DB.shiftR` 12
  let rel = RelocationType (BVS.mkBV PN.knownNat (toInteger rt))
  let mask = 0b0000111111111111
  let offset = w16 .&. mask
  return RelocationBlockEntry { relocationBlockEntryType = rel
                              , relocationBlockEntryOffset = BVS.mkBV PN.knownNat (toInteger offset)
                              }

-- | Pretty print a single relocation entry
ppRelocationBlockEntry :: RelocationBlockEntry -> PP.Doc ann
ppRelocationBlockEntry rbe =
  ppRelocationType (relocationBlockEntryType rbe) <> PP.brackets (PP.pretty (BVS.asUnsigned off))
  where
    off = relocationBlockEntryOffset rbe

-- | Print a block of relocations
ppBaseRelocationBlock :: BaseRelocationBlock -> PP.Doc ann
ppBaseRelocationBlock brb =
  PP.vcat [ PP.pretty "Base Relocation Block" <> PP.parens (PPP.ppHex (baseRelocationPageRVA brb))
          , PP.indent 4 (PP.vcat relocs)
          ]
  where
    relocs = map ppRelocationBlockEntry (baseRelocationEntries brb)

-- | This relocation is skipped (and can be used to pad a block).
pattern REL_BASED_ABSOLUTE :: RelocationType
pattern REL_BASED_ABSOLUTE <- RelocationType (BVS.BV 0) where
  REL_BASED_ABSOLUTE = RelocationType (BVS.mkBV PN.knownNat 0)

-- | Add the high 16 bits of the computed /difference/ to the 16 bit field at
-- the offset.  The 16 bit field is the high 16 bits of a 32 bit word.
pattern REL_BASED_HIGH :: RelocationType
pattern REL_BASED_HIGH <- RelocationType (BVS.BV 1) where
  REL_BASED_HIGH = RelocationType (BVS.mkBV PN.knownNat 1)

-- | Add the high 16 bits of the computed /difference/ to the 16 bit field at
-- the offset.  The 16 bit field is the low 16 bits of a 32 bit word.
pattern REL_BASED_LOW :: RelocationType
pattern REL_BASED_LOW <- RelocationType (BVS.BV 2) where
  REL_BASED_LOW = RelocationType (BVS.mkBV PN.knownNat 2)

-- | Apply all 32 bits of the /difference/ to the 32 bit field at the offset.
pattern REL_BASED_HIGHLOW :: RelocationType
pattern REL_BASED_HIGHLOW <- RelocationType (BVS.BV 3) where
  REL_BASED_HIGHLOW = RelocationType (BVS.mkBV PN.knownNat 3)

-- | This is similar to 'REL_BASED_HIGH', but followed by a paired
-- 'REL_BASED_LOW' relocation.
pattern REL_BASED_HIGHADJ :: RelocationType
pattern REL_BASED_HIGHADJ <- RelocationType (BVS.BV 4) where
  REL_BASED_HIGHADJ = RelocationType (BVS.mkBV PN.knownNat 4)

-- | When the machine is MIPS, the relocation is applied to a jump instruction.
pattern REL_BASED_MIPS_JMPADDR :: RelocationType
pattern REL_BASED_MIPS_JMPADDR <- RelocationType (BVS.BV 5) where
  REL_BASED_MIPS_JMPADDR = RelocationType (BVS.mkBV PN.knownNat 5)

-- | When the machine is ARM/Thumb, the relocation is applied to a symbol
-- spanning a MOVW\/MOVT instruction pair.
pattern REL_BASED_ARM_MOV32 :: RelocationType
pattern REL_BASED_ARM_MOV32 <- RelocationType (BVS.BV 5) where
  REL_BASED_ARM_MOV32 = RelocationType (BVS.mkBV PN.knownNat 5)

-- | When the machine is RISC-V, the relocation is applied to the high 20 bits
-- of a 32 bit absolute address.
pattern REL_BASED_RISCV_HIGH20 :: RelocationType
pattern REL_BASED_RISCV_HIGH20 <- RelocationType (BVS.BV 5) where
  REL_BASED_RISCV_HIGH20 = RelocationType (BVS.mkBV PN.knownNat 5)

-- | When the machine is Thumb, the relocation is applied to a symbol
-- spanning a MOVW\/MOVT instruction pair.
pattern REL_BASED_THUMB_MOV32 :: RelocationType
pattern REL_BASED_THUMB_MOV32 <- RelocationType (BVS.BV 7) where
  REL_BASED_THUMB_MOV32 = RelocationType (BVS.mkBV PN.knownNat 7)

-- | When the machine is RISC-V, the base relocation applies to the low 12 bits
-- of a 32 bit absolute address formed by an I-type instruction.
pattern REL_BASED_RISCV_LOW12I :: RelocationType
pattern REL_BASED_RISCV_LOW12I <- RelocationType (BVS.BV 7) where
  REL_BASED_RISCV_LOW12I = RelocationType (BVS.mkBV PN.knownNat 7)

-- | When the machine is RISC-V, the base relocation applies to the low 12 bits
-- of a 32 bit absolute address formed by an S-type instruction.
pattern REL_BASED_RISCV_LOW12S :: RelocationType
pattern REL_BASED_RISCV_LOW12S <- RelocationType (BVS.BV 8) where
  REL_BASED_RISCV_LOW12S = RelocationType (BVS.mkBV PN.knownNat 8)

-- | When the machine is MIPS16, the base relocation is applied to a jump
-- instruction.
pattern REL_BASED_MIPS_JMPADDR16 :: RelocationType
pattern REL_BASED_MIPS_JMPADDR16 <- RelocationType (BVS.BV 9) where
  REL_BASED_MIPS_JMPADDR16 = RelocationType (BVS.mkBV PN.knownNat 9)

-- | The base relocation applies the /difference/ to a 64 bit field at offset
pattern REL_BASED_DIR64 :: RelocationType
pattern REL_BASED_DIR64 <- RelocationType (BVS.BV 10) where
  REL_BASED_DIR64 = RelocationType (BVS.mkBV PN.knownNat 10)

-- | Pretty print a 'RelocationType'
ppRelocationType :: RelocationType -> PP.Doc ann
ppRelocationType rt =
  case rt of
    REL_BASED_ABSOLUTE -> PP.pretty "REL_BASED_ABSOLUTE"
    REL_BASED_HIGH -> PP.pretty "REL_BASED_HIGH"
    REL_BASED_LOW -> PP.pretty "REL_BASED_LOW"
    REL_BASED_HIGHLOW -> PP.pretty "REL_BASED_HIGHLOW"
    REL_BASED_HIGHADJ -> PP.pretty "REL_BASED_HIGHADJ"
    REL_BASED_MIPS_JMPADDR -> PP.pretty "REL_BASED_MIPS_JMPADDR"
    REL_BASED_ARM_MOV32 -> PP.pretty "REL_BASED_ARM_MOV32"
    REL_BASED_RISCV_HIGH20 -> PP.pretty "REL_BASED_RISCV_HIGH20"
    REL_BASED_THUMB_MOV32 -> PP.pretty "REL_BASED_THUMB_MOV32"
    REL_BASED_RISCV_LOW12I -> PP.pretty "REL_BASED_RISCV_LOW12I"
    REL_BASED_RISCV_LOW12S -> PP.pretty "REL_BASED_RISCV_LOW12S"
    REL_BASED_MIPS_JMPADDR16 -> PP.pretty "REL_BASED_MIPS_JMPADDR16"
    REL_BASED_DIR64 -> PP.pretty "REL_BASED_DIR64"
    RelocationType (BVS.BV bv) -> PP.pretty "RelocationType" <> PP.brackets (PP.pretty bv)
