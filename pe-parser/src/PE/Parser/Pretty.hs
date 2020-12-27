module PE.Parser.Pretty (
  ppList,
  ppHex,
  ppVersion,
  ppBytes,
  failDoc
  ) where

import qualified Control.Monad.Fail as MF
import           Numeric ( showHex )
import qualified Prettyprinter as PP
import qualified Prettyprinter.Render.String as PPRS

-- | A wrapper around 'MF.fail' that accepts formatted prettyprinter 'PP.Doc's
failDoc :: (MF.MonadFail m) => PP.Doc ann -> m a
failDoc d = MF.fail (PPRS.renderString (PP.layoutCompact d))

ppList :: [PP.Doc a] -> PP.Doc a
ppList = PP.brackets . PP.hsep . PP.punctuate PP.comma

ppHex :: (Show a, Integral a) => a -> PP.Doc ann
ppHex a = PP.pretty "0x" <> PP.pretty (showHex a "")


ppVersion :: (PP.Pretty a1, PP.Pretty a2) => (a1, a2) -> PP.Doc ann
ppVersion (major, minor) = PP.parens (PP.pretty major <> PP.pretty ", " <> PP.pretty minor)

ppBytes :: PP.Pretty a => a -> PP.Doc ann
ppBytes num = PP.pretty num <> PP.pretty " bytes"
