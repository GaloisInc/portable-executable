{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
module PE.Parser.DataDirectoryEntry (
  DataDirectoryEntry(..),
  DataDirectoryEntryName(..),
  allDataDirectoryEntryNames,
  findDataDirectoryEntrySection,
  ppDataDirectoryEntryName,
  ppDataDirectoryEntry,
  parseDataDirectoryEntry,
  isDataDirectoryEntry,
  DataDirectoryEntryKind,
  ExportTableK,
  ImportTableK,
  ResourceTableK,
  ExceptionTableK,
  CertificateTableK,
  BaseRelocationTableK,
  DebugK,
  ArchitectureK,
  GlobalPtrK,
  TLSTableK,
  LoadConfigTableK,
  BoundImportTableK,
  ImportAddressTableK,
  DelayImportDescriptorK,
  CLRRuntimeHeaderK
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

-- | This is really a *descriptor* of the actual entry, which is mapped in
-- memory somewhere.  These descriptors are held in the PE Optional Header.  The
-- actual contents of each entry must be looked up in the relevant section.
data DataDirectoryEntry =
  DataDirectoryEntry { dataDirectoryEntryAddress :: Word32
                     -- ^ The RVA of the entry (which should be in a mapped section)
                     , dataDirectoryEntrySize :: Word32
                     -- ^ The number of bytes occupied by the entry
                     }
  deriving (Show)

-- | Data kinds for Data Directory entry names
--
-- These are only mean to be used as kinds and not at the data level at all
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

type ExportTableK = 'ExportTableK
type ImportTableK = 'ImportTableK
type ResourceTableK = 'ResourceTableK
type ExceptionTableK = 'ExceptionTableK
type CertificateTableK = 'CertificateTableK
type BaseRelocationTableK = 'BaseRelocationTableK
type DebugK = 'DebugK
type ArchitectureK = 'ArchitectureK
type GlobalPtrK = 'GlobalPtrK
type TLSTableK = 'TLSTableK
type LoadConfigTableK = 'LoadConfigTableK
type BoundImportTableK = 'BoundImportTableK
type ImportAddressTableK = 'ImportAddressTableK
type DelayImportDescriptorK = 'DelayImportDescriptorK
type CLRRuntimeHeaderK = 'CLRRuntimeHeaderK

-- | Names of each of entry in the Data Directory
--
-- These are in ordinal order (and that is important)
data DataDirectoryEntryName entry where
  -- | A table describing the functions exported by this image for use by others (used for DLLs)
  ExportTableEntry :: DataDirectoryEntryName ExportTableK
  -- | A table describing the external functions referenced by this image
  ImportTableEntry :: DataDirectoryEntryName ImportTableK
  -- | A (hierarchical arrangement of) table(s) describing resources used by the image
  ResourceTableEntry :: DataDirectoryEntryName ResourceTableK
  -- | A table of exception handler descriptors (whose formats are architecture-specific)
  ExceptionTableEntry :: DataDirectoryEntryName ExceptionTableK
  -- | A table containing certificates used by or attesting to the integrity of the image
  CertificateTableEntry :: DataDirectoryEntryName CertificateTableK
  -- | A table describing relocations
  BaseRelocationTableEntry :: DataDirectoryEntryName BaseRelocationTableK
  -- | Debug information embedded in the binary (and potentially mapped into memory)
  DebugEntry :: DataDirectoryEntryName DebugK
  -- | Reserved
  ArchitectureEntry :: DataDirectoryEntryName ArchitectureK
  -- | The RVA of a value to be stored in the Global Pointer register
  GlobalPtrEntry :: DataDirectoryEntryName GlobalPtrK
  -- | A table describing TLS memory
  TLSTableEntry :: DataDirectoryEntryName TLSTableK
  -- | Legacy Structured Exception Handling support in Windows NT
  LoadConfigTableEntry :: DataDirectoryEntryName LoadConfigTableK
  -- | A table describing bound imports
  BoundImportTableEntry :: DataDirectoryEntryName BoundImportTableK
  -- | Support for lazy loading of symbols, overwritten by the loader at run time
  ImportAddressTableEntry :: DataDirectoryEntryName ImportAddressTableK
  -- | Support for lazy loading of DLLs
  DelayImportDescriptorEntry :: DataDirectoryEntryName DelayImportDescriptorK
  -- | This is an extension header supporting CLR (i.e., .NET) applications
  CLRRuntimeHeaderEntry :: DataDirectoryEntryName CLRRuntimeHeaderK

$(return [])

instance PC.ShowF DataDirectoryEntryName where
  showsPrecF = $(PTG.structuralShowsPrec [t| DataDirectoryEntryName |])

deriving instance Show (DataDirectoryEntryName entry)

instance PC.TestEquality DataDirectoryEntryName where
  testEquality = $(PTG.structuralTypeEquality [t| DataDirectoryEntryName |] [])

-- | The full set of known Data Directory entries
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

-- | Test if the given 'DataDirectoryEntryName' matches the first element of the
-- pair.  This is intended to be used as the predicate to
-- 'findDataDirectoryEntrySection'.
isDataDirectoryEntry :: DataDirectoryEntryName entry -> (Some DataDirectoryEntryName, a) -> Bool
isDataDirectoryEntry name (Some entryName, _) = isJust (PC.testEquality name entryName)

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
