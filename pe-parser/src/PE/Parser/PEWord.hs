{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
-- | Definitions of types for types that change sizes in different PE variants (i.e., PE32 vs PE64)
module PE.Parser.PEWord (
  PEConstraints,
  withPEConstraints,
  PEWord,
  parsePEWord,
  -- *
  PEClass(..),
  ppPEClass
  ) where

import qualified Data.Binary.Get as G
import           Data.Word ( Word32, Word64 )
import qualified Prettyprinter as PP


type PEConstraints w = ( PP.Pretty (PEWord w)
                       , Show (PEWord w)
                       , Integral (PEWord w)
                       )

data PEClass w where
  PEClass32 :: PEClass 32
  PEClass64 :: PEClass 64

instance Show (PEClass w) where
  show c =
    case c of
      PEClass32 -> "PEClass32"
      PEClass64 -> "PEClass64"

ppPEClass :: PEClass w -> PP.Doc ann
ppPEClass c =
  case c of
    PEClass32 -> PP.pretty "PE32"
    PEClass64 -> PP.pretty "PE32+"

-- | The type family computing the underlying type used to represent
-- architecture-specific word sizes
type family PEWord w where
  PEWord 32 = Word32
  PEWord 64 = Word64

parsePEWord :: PEClass w -> G.Get (PEWord w)
parsePEWord c =
  case c of
    PEClass32 -> G.getWord32le
    PEClass64 -> G.getWord64le

withPEConstraints :: PEClass w -> (PEConstraints w => a) -> a
withPEConstraints c k =
  case c of
    PEClass32 -> k
    PEClass64 -> k
