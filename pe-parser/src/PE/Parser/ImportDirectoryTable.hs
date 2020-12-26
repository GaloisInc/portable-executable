module PE.Parser.ImportDirectoryTable (
  ImportDirectoryTable(..),
  parseImportDirectoryTable,
  ppImportDirectoryTable,
  importDirectoryTableSize
  ) where

import qualified Data.Binary.Get as G
import           Data.Word ( Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.Pretty as PPP

data ImportDirectoryTable =
  ImportDirectoryTable { importDirectoryTableLookupTableRVA :: Word32
                       , importDirectoryTableTimestamp :: Word32
                       , importDirectoryTableForwarderChain :: Word32
                       , importDirectoryTableNameRVA :: Word32
                       , importDirectoryTableAddressTableRVA :: Word32
                       }
  deriving (Show)

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

importDirectoryTableSize :: Word32
importDirectoryTableSize = 20

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
