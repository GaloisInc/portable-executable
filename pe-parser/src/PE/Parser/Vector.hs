{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
-- | Helpers for dealing with fixed-sized vectors
module PE.Parser.Vector (
  getVecN
  ) where

import qualified Data.Binary.Get as G
import qualified Data.Parameterized.NatRepr as PN
import qualified Data.Parameterized.Vector as PV
import           Data.Word ( Word8 )
import           GHC.TypeLits ( type (+) )

-- | Get a fixed-length vector of bytes
--
-- Note that the provided 'PN.NatRepr' is one less than the target size
getVecN :: PN.NatRepr n -> G.Get (PV.Vector (n + 1) Word8)
getVecN repr = PV.generateM repr (\_rep -> G.getWord8)
