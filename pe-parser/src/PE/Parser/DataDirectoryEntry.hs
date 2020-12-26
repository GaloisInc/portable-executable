module PE.Parser.DataDirectoryEntry (
  DataDirectoryEntry(..),
  DataDirectoryEntryName(..),
  findDataDirectoryEntrySection,
  ppDataDirectoryEntryName,
  ppDataDirectoryEntry,
  parseDataDirectoryEntry,
  isDirectoryEntry
  ) where

import qualified Data.Binary.Get as G
import qualified Data.Foldable as F
import           Data.Maybe ( fromMaybe )
import           Data.Word ( Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.Pretty as PPP
import qualified PE.Parser.SectionHeader as PPS

data DataDirectoryEntry =
  DataDirectoryEntry { dataDirectoryEntryAddress :: Word32
                     , dataDirectoryEntrySize :: Word32
                     }
  deriving (Show)

-- | Names of each of entry in the Data Directory
--
-- These are in ordinal order (and that is important)
data DataDirectoryEntryName = ExportTable
                            | ImportTable
                            | ResourceTable
                            | ExceptionTable
                            | CertificateTable
                            | BaseRelocationTable
                            | Debug
                            | Architecture
                            | GlobalPtr
                            | TLSTable
                            | LoadConfigTable
                            | BoundImportTable
                            | ImportAddressTable
                            | DelayImportDescriptor
                            | CLRRuntimeHeader
                            deriving (Show, Bounded, Enum, Eq)

isDirectoryEntry :: DataDirectoryEntryName -> (DataDirectoryEntryName, a) -> Bool
isDirectoryEntry name (entryName, _) = name == entryName

ppDataDirectoryEntryName :: DataDirectoryEntryName -> PP.Doc ann
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

ppDataDirectoryEntry :: [PPS.SectionHeader] -> (DataDirectoryEntryName, DataDirectoryEntry) -> Maybe (PP.Doc ann)
ppDataDirectoryEntry secHeaders (entryName, dde)
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
