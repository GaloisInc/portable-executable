module PE.Parser.ExportDirectoryTable (
  ExportDirectoryTable(..),
  parseExportDirectoryTable,
  ppExportDirectoryTable
  ) where

import qualified Data.Binary.Get as G
import           Data.Word ( Word16, Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.Pretty as PPP

-- | The contents of the Export Directory Table
--
-- Describes the contents of the export data section
data ExportDirectoryTable =
  ExportDirectoryTable { exportDirectoryTableFlags :: Word32
                       -- ^ Reserved, must be 0
                       , exportDirectoryTableTimestamp :: Word32
                       -- ^ The time and date that the table was created
                       , exportDirectoryTableMajorVersion :: Word16
                       -- ^ Major version number
                       , exportDirectoryTableMinorVersion :: Word16
                       -- ^ Minor version number
                       , exportDirectoryTableNameRVA :: Word32
                       -- ^ The address of a(n ASCII) scring containing the name
                       -- of the DLL; relative to the Image Base
                       --
                       -- FIXME: We could parameterize this type to have either
                       -- the RVA or the resolved name
                       , exportDirectoryTableOrdinalBase :: Word32
                       -- ^ The starting number of exports in this image; usually 1
                       , exportDirectoryTableAddressTableEntries :: Word32
                       -- ^ The number of entries in the Export Address Table
                       , exportDirectoryTableNumberOfNamePointers :: Word32
                       -- ^ Number of entries in the Name Pointer Table (also
                       -- the number of entries in the Ordinal Table)
                       , exportDirectoryTableExportAddressTableRVA :: Word32
                       -- ^ The address of the Export Address Table (relative to
                       -- the Image Base)
                       , exportDirectoryTableNamePointerRVA :: Word32
                       -- ^ Address of the table containing names of exported
                       -- functions (relative to the Image Base); the number of
                       -- entries is given by
                       -- 'exportDirectoryTableNumberOfNamePointers'
                       , exportDirectoryTableOrdinalTableRVA :: Word32
                       -- ^ The address of the ordinal table relative to the
                       -- Image Base
                       }
  deriving (Show)

ppExportDirectoryTable :: ExportDirectoryTable -> PP.Doc ann
ppExportDirectoryTable edt =
  PP.vsep [ PP.pretty "Export Directory Table"
          , PP.indent 4 (PP.vsep fields)
          ]
  where
    fields = [ PP.pretty "Flags: " <> PP.pretty (exportDirectoryTableFlags edt)
             , PP.pretty "Timestamp: " <> PP.pretty (exportDirectoryTableTimestamp edt)
             , PP.pretty "Version: " <> PPP.ppVersion (exportDirectoryTableMajorVersion edt, exportDirectoryTableMinorVersion edt)
             -- FIXME: Resolve the name
             , PP.pretty "Name Address: " <> PPP.ppHex (exportDirectoryTableNameRVA edt)
             , PP.pretty "Ordinal Base: " <> PP.pretty (exportDirectoryTableOrdinalBase edt)
             , PP.pretty "Address Table Entries: " <> PP.pretty (exportDirectoryTableAddressTableEntries edt)
             , PP.pretty "Number of Name Pointers: " <> PP.pretty (exportDirectoryTableNumberOfNamePointers edt)
             , PP.pretty "Export Address Table Address: " <> PPP.ppHex (exportDirectoryTableExportAddressTableRVA edt)
             , PP.pretty "Name Pointer Address: " <> PPP.ppHex (exportDirectoryTableNamePointerRVA edt)
             , PP.pretty "Ordinal Table Address: " <> PPP.ppHex (exportDirectoryTableOrdinalTableRVA edt)
             ]

parseExportDirectoryTable :: G.Get ExportDirectoryTable
parseExportDirectoryTable = do
  flags <- G.getWord32le
  time <- G.getWord32le
  majorVersion <- G.getWord16le
  minorVersion <- G.getWord16le
  nameRVA <- G.getWord32le
  ordinalBase <- G.getWord32le
  addressTableEntries <- G.getWord32le
  numNamePtrs <- G.getWord32le
  exportAddressTableRVA <- G.getWord32le
  namePointerRVA <- G.getWord32le
  ordinalTableRVA <- G.getWord32le

  return ExportDirectoryTable { exportDirectoryTableFlags = flags
                              , exportDirectoryTableTimestamp = time
                              , exportDirectoryTableMajorVersion = majorVersion
                              , exportDirectoryTableMinorVersion = minorVersion
                              , exportDirectoryTableNameRVA = nameRVA
                              , exportDirectoryTableOrdinalBase = ordinalBase
                              , exportDirectoryTableAddressTableEntries = addressTableEntries
                              , exportDirectoryTableNumberOfNamePointers = numNamePtrs
                              , exportDirectoryTableExportAddressTableRVA = exportAddressTableRVA
                              , exportDirectoryTableNamePointerRVA = namePointerRVA
                              , exportDirectoryTableOrdinalTableRVA = ordinalTableRVA
                              }
