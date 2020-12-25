{-# LANGUAGE PatternSynonyms #-}
-- | Portable Executable machine specifications
--
-- The pre-defined names are taken from:
--
-- https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
module PE.Parser.Machine (
  Machine,
  ppMachine,
  parseMachine,
  -- * Pre-defined machine values
  pattern PE_MACHINE_Unknown,
  pattern PE_MACHINE_AM33,
  pattern PE_MACHINE_AMD64,
  pattern PE_MACHINE_ARM,
  pattern PE_MACHINE_ARM64,
  pattern PE_MACHINE_ARMNT,
  pattern PE_MACHINE_EBC,
  pattern PE_MACHINE_I386,
  pattern PE_MACHINE_IA64,
  pattern PE_MACHINE_M32R,
  pattern PE_MACHINE_MIPS16,
  pattern PE_MACHINE_MIPSFPU,
  pattern PE_MACHINE_MIPSFPU16,
  pattern PE_MACHINE_POWERPC,
  pattern PE_MACHINE_POWERPCFP,
  pattern PE_MACHINE_R4000,
  pattern PE_MACHINE_RISCV32,
  pattern PE_MACHINE_RISCV64,
  pattern PE_MACHINE_RISCV128,
  pattern PE_MACHINE_SH3,
  pattern PE_MACHINE_SH3DSP,
  pattern PE_MACHINE_SH4,
  pattern PE_MACHINE_SH5,
  pattern PE_MACHINE_Thumb,
  pattern PE_MACHINE_WCEMIPSV2
  ) where

import qualified Data.Binary.Get as G
import           Data.Word ( Word16 )
import           Numeric ( showHex )
import qualified Prettyprinter as PP

newtype Machine = Machine Word16
  deriving (Show)

parseMachine :: G.Get Machine
parseMachine = Machine <$> G.getWord16le

pattern PE_MACHINE_Unknown :: Machine
pattern PE_MACHINE_Unknown = Machine 0

pattern PE_MACHINE_AM33 :: Machine
pattern PE_MACHINE_AM33 = Machine 0x1d3

pattern PE_MACHINE_AMD64 :: Machine
pattern PE_MACHINE_AMD64 = Machine 0x8664

pattern PE_MACHINE_ARM :: Machine
pattern PE_MACHINE_ARM = Machine 0x1c0

pattern PE_MACHINE_ARM64 :: Machine
pattern PE_MACHINE_ARM64 = Machine 0xaa64

pattern PE_MACHINE_ARMNT :: Machine
pattern PE_MACHINE_ARMNT = Machine 0x1c4

pattern PE_MACHINE_EBC :: Machine
pattern PE_MACHINE_EBC = Machine 0xebc

pattern PE_MACHINE_I386 :: Machine
pattern PE_MACHINE_I386 = Machine 0x14c

pattern PE_MACHINE_IA64 :: Machine
pattern PE_MACHINE_IA64 = Machine 0x200

pattern PE_MACHINE_M32R :: Machine
pattern PE_MACHINE_M32R = Machine 0x9041

pattern PE_MACHINE_MIPS16 :: Machine
pattern PE_MACHINE_MIPS16 = Machine 0x266

pattern PE_MACHINE_MIPSFPU :: Machine
pattern PE_MACHINE_MIPSFPU = Machine 0x366

pattern PE_MACHINE_MIPSFPU16 :: Machine
pattern PE_MACHINE_MIPSFPU16 = Machine 0x466

-- | PowerPC (little endian)
pattern PE_MACHINE_POWERPC :: Machine
pattern PE_MACHINE_POWERPC = Machine 0x1f0

-- | PowerPC with floating point support
pattern PE_MACHINE_POWERPCFP :: Machine
pattern PE_MACHINE_POWERPCFP = Machine 0x1f1

pattern PE_MACHINE_R4000 :: Machine
pattern PE_MACHINE_R4000 = Machine 0x166

pattern PE_MACHINE_RISCV32 :: Machine
pattern PE_MACHINE_RISCV32 = Machine 0x5032

pattern PE_MACHINE_RISCV64 :: Machine
pattern PE_MACHINE_RISCV64 = Machine 0x5064

pattern PE_MACHINE_RISCV128 :: Machine
pattern PE_MACHINE_RISCV128 = Machine 0x5128

pattern PE_MACHINE_SH3 :: Machine
pattern PE_MACHINE_SH3 = Machine 0x1a2

pattern PE_MACHINE_SH3DSP :: Machine
pattern PE_MACHINE_SH3DSP = Machine 0x1a3

pattern PE_MACHINE_SH4 :: Machine
pattern PE_MACHINE_SH4 = Machine 0x1a6

pattern PE_MACHINE_SH5 :: Machine
pattern PE_MACHINE_SH5 = Machine 0x1a8

pattern PE_MACHINE_Thumb :: Machine
pattern PE_MACHINE_Thumb = Machine 0x1c2

pattern PE_MACHINE_WCEMIPSV2 :: Machine
pattern PE_MACHINE_WCEMIPSV2 = Machine 0x168

ppMachine :: Machine -> PP.Doc a
ppMachine m =
  case m of
    PE_MACHINE_Unknown -> PP.pretty "PE_MACHINE_Unknown"
    PE_MACHINE_AM33 -> PP.pretty "PE_MACHINE_AM33"
    PE_MACHINE_AMD64 -> PP.pretty "PE_MACHINE_AMD64"
    PE_MACHINE_ARM -> PP.pretty "PE_MACHINE_ARM"
    PE_MACHINE_ARM64 -> PP.pretty "PE_MACHINE_ARM64"
    PE_MACHINE_ARMNT -> PP.pretty "PE_MACHINE_ARMNT"
    PE_MACHINE_EBC -> PP.pretty "PE_MACHINE_EBC"
    PE_MACHINE_I386 -> PP.pretty "PE_MACHINE_I386"
    PE_MACHINE_IA64 -> PP.pretty "PE_MACHINE_IA64"
    PE_MACHINE_M32R -> PP.pretty "PE_MACHINE_M32R"
    PE_MACHINE_MIPS16 -> PP.pretty "PE_MACHINE_MIPS16"
    PE_MACHINE_MIPSFPU -> PP.pretty "PE_MACHINE_MIPSFPU"
    PE_MACHINE_MIPSFPU16 -> PP.pretty "PE_MACHINE_MIPSFPU16"
    PE_MACHINE_POWERPC -> PP.pretty "PE_MACHINE_POWERPC"
    PE_MACHINE_POWERPCFP -> PP.pretty "PE_MACHINE_POWERPCFP"
    PE_MACHINE_R4000 -> PP.pretty "PE_MACHINE_R4000"
    PE_MACHINE_RISCV32 -> PP.pretty "PE_MACHINE_RISCV32"
    PE_MACHINE_RISCV64 -> PP.pretty "PE_MACHINE_RISCV64"
    PE_MACHINE_RISCV128 -> PP.pretty "PE_MACHINE_RISCV128"
    PE_MACHINE_SH3 -> PP.pretty "PE_MACHINE_SH3"
    PE_MACHINE_SH3DSP -> PP.pretty "PE_MACHINE_SH3DSP"
    PE_MACHINE_SH4 -> PP.pretty "PE_MACHINE_SH4"
    PE_MACHINE_SH5 -> PP.pretty "PE_MACHINE_SH5"
    PE_MACHINE_Thumb -> PP.pretty "PE_MACHINE_Thumb"
    PE_MACHINE_WCEMIPSV2 -> PP.pretty "PE_MACHINE_WCEMIPSV2"
    (Machine mid) -> PP.pretty "PE_MACHINE" <> PP.brackets (PP.pretty (showHex mid ""))
