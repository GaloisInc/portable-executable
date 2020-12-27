{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
-- | Definitions of types for types that change sizes in different PE variants (i.e., PE32 vs PE64)
module PE.Parser.PEWord (
  PEConstraints,
  withPEConstraints,
  PEWord,
  parsePEWord,
  PEClass(..),
  ppPEClass,
  StructureSize(..)
  ) where

import qualified Data.Binary.Get as G
import           Data.Word ( Word32, Word64 )
import qualified Prettyprinter as PP

-- | The constraints required to interact with 'PEWord's (they must be integral and showable)
type PEConstraints w = ( PP.Pretty (PEWord w)
                       , Show (PEWord w)
                       , Integral (PEWord w)
                       )

-- | A value-level representative for machine word sizes
--
-- This representative is stored in the PE Optional Header to determine the size
-- of 'PEWord's
data PEClass w where
  PEClass32 :: PEClass 32
  PEClass64 :: PEClass 64

instance Show (PEClass w) where
  show c =
    case c of
      PEClass32 -> "PEClass32"
      PEClass64 -> "PEClass64"

-- | Pretty print the word size representative
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

-- | Parse a machine-specific word
parsePEWord :: PEClass w -> G.Get (PEWord w)
parsePEWord c =
  case c of
    PEClass32 -> G.getWord32le
    PEClass64 -> G.getWord64le

-- | Recover 'PEConstraints'
withPEConstraints :: PEClass w -> (PEConstraints w => a) -> a
withPEConstraints c k =
  case c of
    PEClass32 -> k
    PEClass64 -> k

-- | Compute the size of structures
class StructureSize a where
  -- | The size in bytes of the given structure
  structureSize :: a -> PEClass w -> Word32

instance (a ~ PEWord w) => StructureSize a where
  structureSize _ c =
    case c of
      PEClass32 -> 4
      PEClass64 -> 8
