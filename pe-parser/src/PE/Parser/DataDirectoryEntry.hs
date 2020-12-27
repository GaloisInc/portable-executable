{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
module PE.Parser.DataDirectoryEntry (
  DataDirectoryEntry(..),
  DataDirectoryEntryKind(..),
  DataDirectoryEntryName(..),
  allDataDirectoryEntryNames,
  findDataDirectoryEntrySection,
  ppDataDirectoryEntryName,
  ppDataDirectoryEntry,
  parseDataDirectoryEntry,
  isDirectoryEntry
  ) where

import qualified Data.Binary.Get as G
import qualified Data.Foldable as F
import           Data.Maybe ( fromMaybe, isJust )
import qualified Data.Parameterized.Classes as PC
import           Data.Parameterized.Some ( Some(..) )
import qualified Data.Parameterized.TH.GADT as PTG
import           Data.Word ( Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.Pretty as PPP
import qualified PE.Parser.SectionHeader as PPS

data DataDirectoryEntry =
  DataDirectoryEntry { dataDirectoryEntryAddress :: Word32
                     , dataDirectoryEntrySize :: Word32
                     }
  deriving (Show)

data DataDirectoryEntryKind = ExportTableK
                            | ImportTableK
                            | ResourceTableK
                            | ExceptionTableK
                            | CertificateTableK
                            | BaseRelocationTableK
                            | DebugK
                            | ArchitectureK
                            | GlobalPtrK
                            | TLSTableK
                            | LoadConfigTableK
                            | BoundImportTableK
                            | ImportAddressTableK
                            | DelayImportDescriptorK
                            | CLRRuntimeHeaderK

-- | Names of each of entry in the Data Directory
--
-- These are in ordinal order (and that is important)
data DataDirectoryEntryName entry where
  ExportTableEntry :: DataDirectoryEntryName 'ExportTableK
  ImportTableEntry :: DataDirectoryEntryName 'ImportTableK
  ResourceTableEntry :: DataDirectoryEntryName 'ResourceTableK
  ExceptionTableEntry :: DataDirectoryEntryName 'ExceptionTableK
  CertificateTableEntry :: DataDirectoryEntryName 'CertificateTableK
  BaseRelocationTableEntry :: DataDirectoryEntryName 'BaseRelocationTableK
  DebugEntry :: DataDirectoryEntryName 'DebugK
  ArchitectureEntry :: DataDirectoryEntryName 'ArchitectureK
  GlobalPtrEntry :: DataDirectoryEntryName 'GlobalPtrK
  TLSTableEntry :: DataDirectoryEntryName 'TLSTableK
  LoadConfigTableEntry :: DataDirectoryEntryName 'LoadConfigTableK
  BoundImportTableEntry :: DataDirectoryEntryName 'BoundImportTableK
  ImportAddressTableEntry :: DataDirectoryEntryName 'ImportAddressTableK
  DelayImportDescriptorEntry :: DataDirectoryEntryName 'DelayImportDescriptorK
  CLRRuntimeHeaderEntry :: DataDirectoryEntryName 'CLRRuntimeHeaderK

$(return [])

instance PC.ShowF DataDirectoryEntryName where
  showsPrecF = $(PTG.structuralShowsPrec [t| DataDirectoryEntryName |])

deriving instance Show (DataDirectoryEntryName entry)

instance PC.TestEquality DataDirectoryEntryName where
  testEquality = $(PTG.structuralTypeEquality [t| DataDirectoryEntryName |] [])

allDataDirectoryEntryNames :: [Some DataDirectoryEntryName]
allDataDirectoryEntryNames =
  [ Some ExportTableEntry
  , Some ImportTableEntry
  , Some ResourceTableEntry
  , Some ExceptionTableEntry
  , Some CertificateTableEntry
  , Some BaseRelocationTableEntry
  , Some DebugEntry
  , Some ArchitectureEntry
  , Some GlobalPtrEntry
  , Some TLSTableEntry
  , Some LoadConfigTableEntry
  , Some BoundImportTableEntry
  , Some ImportAddressTableEntry
  , Some DelayImportDescriptorEntry
  , Some CLRRuntimeHeaderEntry
  ]

isDirectoryEntry :: DataDirectoryEntryName entry -> (Some DataDirectoryEntryName, a) -> Bool
isDirectoryEntry name (Some entryName, _) = isJust (PC.testEquality name entryName)

ppDataDirectoryEntryName :: DataDirectoryEntryName entry -> PP.Doc ann
ppDataDirectoryEntryName n =
  case n of
    ExportTableEntry -> PP.pretty "Export Table"
    ImportTableEntry -> PP.pretty "Import Table"
    ResourceTableEntry -> PP.pretty "Resource Table"
    ExceptionTableEntry -> PP.pretty "Exception Table"
    CertificateTableEntry -> PP.pretty "Certificate Table"
    BaseRelocationTableEntry -> PP.pretty "Base Relocation Table"
    DebugEntry -> PP.pretty "Debug"
    ArchitectureEntry -> PP.pretty "Architecture"
    GlobalPtrEntry -> PP.pretty "Global Ptr"
    TLSTableEntry -> PP.pretty "TLS Table"
    LoadConfigTableEntry -> PP.pretty "Load Config Table"
    BoundImportTableEntry -> PP.pretty "Bound Import Table"
    ImportAddressTableEntry -> PP.pretty "Import Address Table"
    DelayImportDescriptorEntry -> PP.pretty "Delay Import Descriptor"
    CLRRuntimeHeaderEntry -> PP.pretty "CLR Runtime Header"

parseDataDirectoryEntry :: G.Get DataDirectoryEntry
parseDataDirectoryEntry = do
  addr <- G.getWord32le
  size <- G.getWord32le
  return DataDirectoryEntry { dataDirectoryEntryAddress = addr
                            , dataDirectoryEntrySize = size
                            }

ppDataDirectoryEntry :: [PPS.SectionHeader] -> (Some DataDirectoryEntryName, DataDirectoryEntry) -> Maybe (PP.Doc ann)
ppDataDirectoryEntry secHeaders (Some entryName, dde)
  | dataDirectoryEntryAddress dde == 0 = Nothing
  | otherwise =
    Just $ PP.hcat [ PPP.ppHex (dataDirectoryEntryAddress dde)
                   , PP.pretty " "
                   , PP.parens (PPP.ppBytes (dataDirectoryEntrySize dde))
                   , PP.pretty " "
                   , PP.parens (ppDataDirectoryEntryName entryName <> inSec)
                   ]
  where
    inSec = fromMaybe mempty $ do
      hdr <- findDataDirectoryEntrySection secHeaders dde
      return (PP.pretty " in section " <> PP.pretty (PPS.sectionHeaderNameText hdr))

findDataDirectoryEntrySection :: [PPS.SectionHeader] -> DataDirectoryEntry -> Maybe PPS.SectionHeader
findDataDirectoryEntrySection secHeaders dde =
  F.find (PPS.sectionContains (dataDirectoryEntryAddress dde)) secHeaders
