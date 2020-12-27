module PE.Parser.ImportDirectoryTable (
  ImportDirectoryTable(..),
  parseImportDirectoryTable,
  ppImportDirectoryTable
  ) where

import qualified Data.Binary.Get as G
import           Data.Word ( Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.PEWord as PPW
import qualified PE.Parser.Pretty as PPP

-- | The header table describing import information for the image
data ImportDirectoryTable =
  ImportDirectoryTable { importDirectoryTableLookupTableRVA :: Word32
                       -- ^ The RVA of the Import Lookup Table
                       , importDirectoryTableTimestamp :: Word32
                       -- ^ The timestamp is zero until the image is bound, at
                       -- which point it is set to record the binding time
                       , importDirectoryTableForwarderChain :: Word32
                       -- ^ The index of the first forward chain
                       , importDirectoryTableNameRVA :: Word32
                       -- ^ The RVA of an ASCII string name of the DLL
                       , importDirectoryTableAddressTableRVA :: Word32
                       -- ^ The RVA of the Import Address Table (the thunk table)
                       }
  deriving (Show)

-- | Parse an 'ImportDirectoryTable'
parseImportDirectoryTable :: G.Get ImportDirectoryTable
parseImportDirectoryTable = do
  ltRVA <- G.getWord32le
  time <- G.getWord32le
  forward <- G.getWord32le
  nameRVA <- G.getWord32le
  atRVA <- G.getWord32le

  return ImportDirectoryTable { importDirectoryTableLookupTableRVA = ltRVA
                              , importDirectoryTableTimestamp = time
                              , importDirectoryTableForwarderChain = forward
                              , importDirectoryTableNameRVA = nameRVA
                              , importDirectoryTableAddressTableRVA = atRVA
                              }

instance PPW.StructureSize ImportDirectoryTable where
  structureSize _ _ = 20

-- | Pretty print an 'ImportDirectoryTable'
ppImportDirectoryTable :: ImportDirectoryTable -> PP.Doc ann
ppImportDirectoryTable idt =
  PP.vcat [ PP.pretty "Import Directory Table"
          , PP.indent 4 (PP.vcat items)
          ]
  where
    items = [ PP.pretty "Lookup Table Address: " <> PPP.ppHex (importDirectoryTableLookupTableRVA idt)
            , PP.pretty "Timestamp: " <> PP.pretty (importDirectoryTableTimestamp idt)
            , PP.pretty "Forwarder Chain: " <> PP.pretty (importDirectoryTableForwarderChain idt)
            , PP.pretty "Name Address: " <> PPP.ppHex (importDirectoryTableNameRVA idt)
            , PP.pretty "Address Table Address: " <> PPP.ppHex (importDirectoryTableAddressTableRVA idt)
            ]
