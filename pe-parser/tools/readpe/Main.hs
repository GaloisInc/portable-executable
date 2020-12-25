module Main ( main ) where

import qualified Data.ByteString.Lazy as BSL
import           Data.Parameterized.Some ( Some(..) )
import qualified Options.Applicative as O
import qualified Prettyprinter as PP
import qualified Prettyprinter.Render.String as PPS
import qualified System.IO as IO
import qualified System.Exit as IOE

import qualified PE.Parser as PE

data Options =
  Options { peFilePath :: FilePath
          }

options :: O.Parser Options
options = Options <$> O.strArgument (O.help "The PE file to parse")

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
      putStrLn (PPS.renderString (PP.layoutPretty PP.defaultLayoutOptions (PE.ppPEHeaderInfo peHdr)))
