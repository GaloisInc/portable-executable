{-# LANGUAGE PatternSynonyms #-}
module PE.Parser.DLLFlags (
  DLLFlag,
  DLLFlags,
  parseDLLFlags,
  ppDLLFlags,
  ppDLLFlag,
  hasDLLFlag,
  dllFlags,
  pattern PE_DLL_HIGH_ENTROPY_VA,
  pattern PE_DLL_DYNAMIC_BASE,
  pattern PE_DLL_FORCE_INTEGRITY,
  pattern PE_DLL_NX_COMPAT,
  pattern PE_DLL_NO_ISOLATION,
  pattern PE_DLL_NO_SEH,
  pattern PE_DLL_NO_BIND,
  pattern PE_DLL_APPCONTAINER,
  pattern PE_DLL_WDM_DRIVER,
  pattern PE_DLL_GUARD_CF,
  pattern PE_DLL_TERMINAL_SERVER_AWARE
  ) where

import qualified Data.Binary.Get as G
import           Data.Bits ( (.|.), (.&.), bit, testBit )
import           Data.Word ( Word16 )
import qualified Prettyprinter as PP

import qualified PE.Parser.Pretty as PPP

newtype DLLFlag = DLLFlag { getMask :: Word16 }
  deriving (Show)

newtype DLLFlags = DLLFlags Word16
  deriving (Show)

pattern PE_DLL_HIGH_ENTROPY_VA :: DLLFlag
pattern PE_DLL_HIGH_ENTROPY_VA = DLLFlag 0x0020

pattern PE_DLL_DYNAMIC_BASE :: DLLFlag
pattern PE_DLL_DYNAMIC_BASE = DLLFlag 0x0040

pattern PE_DLL_FORCE_INTEGRITY :: DLLFlag
pattern PE_DLL_FORCE_INTEGRITY = DLLFlag 0x0080

pattern PE_DLL_NX_COMPAT :: DLLFlag
pattern PE_DLL_NX_COMPAT = DLLFlag 0x0100

pattern PE_DLL_NO_ISOLATION :: DLLFlag
pattern PE_DLL_NO_ISOLATION = DLLFlag 0x0200

pattern PE_DLL_NO_SEH :: DLLFlag
pattern PE_DLL_NO_SEH = DLLFlag 0x0400

pattern PE_DLL_NO_BIND :: DLLFlag
pattern PE_DLL_NO_BIND = DLLFlag 0x0800

pattern PE_DLL_APPCONTAINER :: DLLFlag
pattern PE_DLL_APPCONTAINER = DLLFlag 0x1000

pattern PE_DLL_WDM_DRIVER :: DLLFlag
pattern PE_DLL_WDM_DRIVER = DLLFlag 0x2000

pattern PE_DLL_GUARD_CF :: DLLFlag
pattern PE_DLL_GUARD_CF = DLLFlag 0x4000

pattern PE_DLL_TERMINAL_SERVER_AWARE :: DLLFlag
pattern PE_DLL_TERMINAL_SERVER_AWARE = DLLFlag 0x8000

parseDLLFlags :: G.Get DLLFlags
parseDLLFlags = DLLFlags <$> G.getWord16le

dllFlags :: [DLLFlag] -> DLLFlags
dllFlags = DLLFlags . foldr (.|.) 0 . map getMask

hasDLLFlag :: DLLFlags -> DLLFlag -> Bool
hasDLLFlag (DLLFlags w) (DLLFlag m) = w .&. m /= 0

ppDLLFlag :: DLLFlag -> PP.Doc ann
ppDLLFlag f =
  case f of
    PE_DLL_HIGH_ENTROPY_VA -> PP.pretty "PE_DLL_HIGH_ENTROPY_VA"
    PE_DLL_DYNAMIC_BASE -> PP.pretty "PE_DLL_DYNAMIC_BASE"
    PE_DLL_FORCE_INTEGRITY -> PP.pretty "PE_DLL_FORCE_INTEGRITY"
    PE_DLL_NX_COMPAT -> PP.pretty "PE_DLL_NX_COMPAT"
    PE_DLL_NO_ISOLATION -> PP.pretty "PE_DLL_NO_ISOLATION"
    PE_DLL_NO_SEH -> PP.pretty "PE_DLL_NO_SEH"
    PE_DLL_NO_BIND -> PP.pretty "PE_DLL_NO_BIND"
    PE_DLL_APPCONTAINER -> PP.pretty "PE_DLL_APPCONTAINER"
    PE_DLL_WDM_DRIVER -> PP.pretty "PE_DLL_WDM_DRIVER"
    PE_DLL_GUARD_CF -> PP.pretty "PE_DLL_GUARD_CF"
    PE_DLL_TERMINAL_SERVER_AWARE -> PP.pretty "PE_DLL_TERMINAL_SERVER_AWARE"
    DLLFlag w -> PP.pretty "DLLFlag" <> PP.brackets (PPP.ppHex w)

ppDLLFlags :: DLLFlags -> PP.Doc ann
ppDLLFlags (DLLFlags w) =
  PP.brackets (PP.hsep (PP.punctuate PP.comma docs))
  where
    docs = [ ppDLLFlag (DLLFlag (bit bitNum))
           | bitNum <- [0..15]
           , testBit w bitNum
           ]
