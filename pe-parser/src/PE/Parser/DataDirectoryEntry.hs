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
  ExportTable :: DataDirectoryEntryName 'ExportTableK
  ImportTable :: DataDirectoryEntryName 'ImportTableK
  ResourceTable :: DataDirectoryEntryName 'ResourceTableK
  ExceptionTable :: DataDirectoryEntryName 'ExceptionTableK
  CertificateTable :: DataDirectoryEntryName 'CertificateTableK
  BaseRelocationTable :: DataDirectoryEntryName 'BaseRelocationTableK
  Debug :: DataDirectoryEntryName 'DebugK
  Architecture :: DataDirectoryEntryName 'ArchitectureK
  GlobalPtr :: DataDirectoryEntryName 'GlobalPtrK
  TLSTable :: DataDirectoryEntryName 'TLSTableK
  LoadConfigTable :: DataDirectoryEntryName 'LoadConfigTableK
  BoundImportTable :: DataDirectoryEntryName 'BoundImportTableK
  ImportAddressTable :: DataDirectoryEntryName 'ImportAddressTableK
  DelayImportDescriptor :: DataDirectoryEntryName 'DelayImportDescriptorK
  CLRRuntimeHeader :: DataDirectoryEntryName 'CLRRuntimeHeaderK

$(return [])

instance PC.ShowF DataDirectoryEntryName where
  showsPrecF = $(PTG.structuralShowsPrec [t| DataDirectoryEntryName |])

deriving instance Show (DataDirectoryEntryName entry)

instance PC.TestEquality DataDirectoryEntryName where
  testEquality = $(PTG.structuralTypeEquality [t| DataDirectoryEntryName |] [])

allDataDirectoryEntryNames :: [Some DataDirectoryEntryName]
allDataDirectoryEntryNames =
  [ Some ExportTable
  , Some ImportTable
  , Some ResourceTable
  , Some ExceptionTable
  , Some CertificateTable
  , Some BaseRelocationTable
  , Some Debug
  , Some Architecture
  , Some GlobalPtr
  , Some TLSTable
  , Some LoadConfigTable
  , Some BoundImportTable
  , Some ImportAddressTable
  , Some DelayImportDescriptor
  , Some CLRRuntimeHeader
  ]

isDirectoryEntry :: DataDirectoryEntryName entry -> (Some DataDirectoryEntryName, a) -> Bool
isDirectoryEntry name (Some entryName, _) = isJust (PC.testEquality name entryName)

ppDataDirectoryEntryName :: DataDirectoryEntryName entry -> PP.Doc ann
ppDataDirectoryEntryName n =
  case n of
    ExportTable -> PP.pretty "Export Table"
    ImportTable -> PP.pretty "Import Table"
    ResourceTable -> PP.pretty "Resource Table"
    ExceptionTable -> PP.pretty "Exception Table"
    CertificateTable -> PP.pretty "Certificate Table"
    BaseRelocationTable -> PP.pretty "Base Relocation Table"
    Debug -> PP.pretty "Debug"
    Architecture -> PP.pretty "Architecture"
    GlobalPtr -> PP.pretty "Global Ptr"
    TLSTable -> PP.pretty "TLS Table"
    LoadConfigTable -> PP.pretty "Load Config Table"
    BoundImportTable -> PP.pretty "Bound Import Table"
    ImportAddressTable -> PP.pretty "Import Address Table"
    DelayImportDescriptor -> PP.pretty "Delay Import Descriptor"
    CLRRuntimeHeader -> PP.pretty "CLR Runtime Header"

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
