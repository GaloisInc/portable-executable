{-# LANGUAGE PatternSynonyms #-}
module PE.Parser.Subsystem (
  -- * Subsystem definitions
  Subsystem,
  parseSubsystem,
  ppSubsystem,
  -- * Known 'Subsystem' constants
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


newtype Subsystem = Subsystem Word16
  deriving (Show)

parseSubsystem :: G.Get Subsystem
parseSubsystem = Subsystem <$> G.getWord16le

pattern PE_SUBSYSTEM_UNKNOWN :: Subsystem
pattern PE_SUBSYSTEM_UNKNOWN = Subsystem 0

pattern PE_SUBSYSTEM_NATIVE :: Subsystem
pattern PE_SUBSYSTEM_NATIVE = Subsystem 1

pattern PE_SUBSYSTEM_WINDOWS_GUI :: Subsystem
pattern PE_SUBSYSTEM_WINDOWS_GUI = Subsystem 2

pattern PE_SUBSYSTEM_WINDOWS_CUI :: Subsystem
pattern PE_SUBSYSTEM_WINDOWS_CUI = Subsystem 3

pattern PE_SUBSYSTEM_OS2_CUI :: Subsystem
pattern PE_SUBSYSTEM_OS2_CUI = Subsystem 5

pattern PE_SUBSYSTEM_POSIX_CUI :: Subsystem
pattern PE_SUBSYSTEM_POSIX_CUI = Subsystem 7

pattern PE_SUBSYSTEM_NATIVE_WINDOWS :: Subsystem
pattern PE_SUBSYSTEM_NATIVE_WINDOWS = Subsystem 8

pattern PE_SUBSYSTEM_WINDOWS_CE_GUI :: Subsystem
pattern PE_SUBSYSTEM_WINDOWS_CE_GUI = Subsystem 9

pattern PE_SUBSYSTEM_EFI_APPLICATION :: Subsystem
pattern PE_SUBSYSTEM_EFI_APPLICATION = Subsystem 10

pattern PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER :: Subsystem
pattern PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = Subsystem 11

pattern PE_SUBSYSTEM_EFI_RUNTIME_DRIVER :: Subsystem
pattern PE_SUBSYSTEM_EFI_RUNTIME_DRIVER = Subsystem 12

pattern PE_SUBSYSTEM_EFI_ROM :: Subsystem
pattern PE_SUBSYSTEM_EFI_ROM = Subsystem 13

pattern PE_SUBSYSTEM_XBOX :: Subsystem
pattern PE_SUBSYSTEM_XBOX = Subsystem 14

pattern PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION :: Subsystem
pattern PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = Subsystem 16

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
