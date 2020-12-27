{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Main ( main ) where

import qualified Data.ByteString.Lazy as BSL
import qualified Data.Foldable as F
import qualified Data.Map.Strict as Map
import           Data.Parameterized.Some ( Some(..) )
import           Data.Proxy ( Proxy(..) )
import qualified Options.Applicative as O
import qualified Prettyprinter as PP
import qualified Prettyprinter.Render.String as PPS
import qualified System.Exit as IOE
import qualified System.IO as IO

import qualified PE.Parser as PE

dataDirectoryNames :: Map.Map String (PE.SomeDataDirectoryEntry)
dataDirectoryNames =
  Map.fromList [ (name, entry)
               | entry <- PE.allDataDirectoryEntries
               , PE.SomeDataDirectoryEntry e <- return entry
               , let name = show e
               ]

readDataDirectoryName :: String -> Maybe (PE.SomeDataDirectoryEntry)
readDataDirectoryName s = Map.lookup s dataDirectoryNames

data Options =
  Options { peFilePath :: FilePath
          , dataEntries :: [PE.SomeDataDirectoryEntry]
          }

options :: O.Parser Options
options = Options <$> O.strArgument (O.help "The PE file to parse")
                  <*> O.many (O.option (O.maybeReader readDataDirectoryName)
                      ( O.long "data-entry"
                      <> O.help (pp dataEntryHelp)
                      ))
  where
    dataEntryHelp = PP.hsep [ PP.pretty "Show the named data directory entry; allowable values are "
                            , PP.list (fmap PP.pretty (Map.keys dataDirectoryNames))
                            ]

main :: IO ()
main = readpe =<< O.execParser opts
  where
    opts = O.info (options O.<**> O.helper)
                  ( O.fullDesc
                  <> O.progDesc "A viewer for Portable Executable (PE) metadata"
                  <> O.header "readpe"
                  )

readpe :: Options -> IO ()
readpe opts = do
  bytes <- BSL.readFile (peFilePath opts)
  case PE.decodePEHeaderInfo bytes of
    Left (off, msg) -> do
      IO.hPutStrLn IO.stderr ("Error parsing PE file at offset " ++ show off ++ ": " ++ msg)
      IOE.exitFailure
    Right (Some peHdr) -> do
      putStrLn ("Binary: " ++ (peFilePath opts))
      putStrLn (pp (PE.ppPEHeaderInfo peHdr))
      case PE.validatePEHeaderInfo peHdr of
        Left {}
          | null (dataEntries opts) -> return ()
          | otherwise -> do
              IO.hPutStrLn IO.stderr "No Optional PEHeader, no data directory entries present"
        Right idPEHdr -> do
          F.forM_ (dataEntries opts) $ \(PE.SomeDataDirectoryEntry (dataDirEntryName :: PE.DataDirectoryEntryName entry)) -> do
            case PE.getDataDirectoryEntry dataDirEntryName idPEHdr of
              Left err -> do
                IO.hPutStrLn IO.stderr ("Error while attempting to parse data directory entry " ++ show dataDirEntryName)
                IO.hPutStrLn IO.stderr (show err)
              Right dirEntryValue -> do
                putStrLn ("Directory Entry: " ++ show (PE.ppDataDirectoryEntryName dataDirEntryName))
                let doc = PE.ppDataDirectoryEntryValue (Proxy @entry) dirEntryValue
                putStrLn (pp doc)

pp :: PP.Doc ann -> String
pp = PPS.renderString . PP.layoutPretty PP.defaultLayoutOptions
