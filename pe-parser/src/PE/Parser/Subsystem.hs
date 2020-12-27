{-# LANGUAGE PatternSynonyms #-}
module PE.Parser.Subsystem (
  Subsystem,
  parseSubsystem,
  ppSubsystem,
  -- *** Known 'Subsystem' constants
  pattern PE_SUBSYSTEM_UNKNOWN,
  pattern PE_SUBSYSTEM_NATIVE,
  pattern PE_SUBSYSTEM_WINDOWS_GUI,
  pattern PE_SUBSYSTEM_WINDOWS_CUI,
  pattern PE_SUBSYSTEM_OS2_CUI,
  pattern PE_SUBSYSTEM_POSIX_CUI,
  pattern PE_SUBSYSTEM_NATIVE_WINDOWS,
  pattern PE_SUBSYSTEM_WINDOWS_CE_GUI,
  pattern PE_SUBSYSTEM_EFI_APPLICATION,
  pattern PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER ,
  pattern PE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
  pattern PE_SUBSYSTEM_EFI_ROM,
  pattern PE_SUBSYSTEM_XBOX,
  pattern PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
  ) where

import qualified Data.Binary.Get as G
import           Data.Word ( Word16 )
import qualified Prettyprinter as PP

-- | The execution subsystem targeted by a binary
--
-- This is stored in the 'PE.Parser.PEOptionalHeader' for executable images, and
-- determines the low-level system call profile that the program has access to.
newtype Subsystem = Subsystem Word16
  deriving (Show)

-- | Parse a 'Subsystem'
--
-- Note that the parsed subsystem might not match any of the known constants
-- (the binary probably wouldn't run, but anything could be encoded in this 16
-- bit field).
parseSubsystem :: G.Get Subsystem
parseSubsystem = Subsystem <$> G.getWord16le

-- | Unknown subsystem
pattern PE_SUBSYSTEM_UNKNOWN :: Subsystem
pattern PE_SUBSYSTEM_UNKNOWN = Subsystem 0

-- | Device drivers and native Windows processes
pattern PE_SUBSYSTEM_NATIVE :: Subsystem
pattern PE_SUBSYSTEM_NATIVE = Subsystem 1

-- | The graphical Windows subsystem
pattern PE_SUBSYSTEM_WINDOWS_GUI :: Subsystem
pattern PE_SUBSYSTEM_WINDOWS_GUI = Subsystem 2

-- | The console subsystem
pattern PE_SUBSYSTEM_WINDOWS_CUI :: Subsystem
pattern PE_SUBSYSTEM_WINDOWS_CUI = Subsystem 3

-- | The OS/2 compatibility subsystem
pattern PE_SUBSYSTEM_OS2_CUI :: Subsystem
pattern PE_SUBSYSTEM_OS2_CUI = Subsystem 5

-- | The POSIX console subsystem
pattern PE_SUBSYSTEM_POSIX_CUI :: Subsystem
pattern PE_SUBSYSTEM_POSIX_CUI = Subsystem 7

-- | The Windows 9x driver
pattern PE_SUBSYSTEM_NATIVE_WINDOWS :: Subsystem
pattern PE_SUBSYSTEM_NATIVE_WINDOWS = Subsystem 8

-- | Windows CE subsystem
pattern PE_SUBSYSTEM_WINDOWS_CE_GUI :: Subsystem
pattern PE_SUBSYSTEM_WINDOWS_CE_GUI = Subsystem 9

-- | An EFI program (probably not actually running under Windows)
pattern PE_SUBSYSTEM_EFI_APPLICATION :: Subsystem
pattern PE_SUBSYSTEM_EFI_APPLICATION = Subsystem 10

-- | EFI boot services
pattern PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER :: Subsystem
pattern PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = Subsystem 11

-- | EFI run-time services
pattern PE_SUBSYSTEM_EFI_RUNTIME_DRIVER :: Subsystem
pattern PE_SUBSYSTEM_EFI_RUNTIME_DRIVER = Subsystem 12

-- | EFI ROM image
pattern PE_SUBSYSTEM_EFI_ROM :: Subsystem
pattern PE_SUBSYSTEM_EFI_ROM = Subsystem 13

-- | XBox program
pattern PE_SUBSYSTEM_XBOX :: Subsystem
pattern PE_SUBSYSTEM_XBOX = Subsystem 14

-- | Windows bootloader application
pattern PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION :: Subsystem
pattern PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = Subsystem 16

-- | Pretty print a 'Subsystem'
ppSubsystem :: Subsystem -> PP.Doc ann
ppSubsystem s =
  case s of
    PE_SUBSYSTEM_UNKNOWN -> PP.pretty "PE_SUBSYSTEM_UNKNOWN"
    PE_SUBSYSTEM_NATIVE -> PP.pretty "PE_SUBSYSTEM_NATIVE"
    PE_SUBSYSTEM_WINDOWS_GUI -> PP.pretty "PE_SUBSYSTEM_WINDOWS_GUI"
    PE_SUBSYSTEM_WINDOWS_CUI -> PP.pretty "PE_SUBSYSTEM_WINDOWS_CUI"
    PE_SUBSYSTEM_OS2_CUI -> PP.pretty "PE_SUBSYSTEM_OS2_CUI"
    PE_SUBSYSTEM_POSIX_CUI -> PP.pretty "PE_SUBSYSTEM_POSIX_CUI"
    PE_SUBSYSTEM_NATIVE_WINDOWS -> PP.pretty "PE_SUBSYSTEM_NATIVE_WINDOWS"
    PE_SUBSYSTEM_WINDOWS_CE_GUI -> PP.pretty "PE_SUBSYSTEM_WINDOWS_CE_GUI"
    PE_SUBSYSTEM_EFI_APPLICATION -> PP.pretty "PE_SUBSYSTEM_EFI_APPLICATION"
    PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  -> PP.pretty "PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"
    PE_SUBSYSTEM_EFI_RUNTIME_DRIVER -> PP.pretty "PE_SUBSYSTEM_EFI_RUNTIME_DRIVER"
    PE_SUBSYSTEM_EFI_ROM -> PP.pretty "PE_SUBSYSTEM_EFI_ROM"
    PE_SUBSYSTEM_XBOX -> PP.pretty "PE_SUBSYSTEM_XBOX"
    PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION -> PP.pretty "PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"
    Subsystem w -> PP.pretty "Subsystem" <> PP.brackets (PP.pretty w)
