{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
module PE.Parser.ExceptionTable (
  ExceptionTable(..),
  ExceptionTableEntry,
  ExceptionTableFormat,
  IntelK,
  MIPSK,
  CompactK,
  MIPSExceptionTableEntry(..),
  IntelExceptionTableEntry(..),
  CompactExceptionTableEntry(..),
  ExceptionTableRepr(..),
  machineExceptionRepr,
  parseExceptionTable,
  parseExceptionTableEntry,
  ppExceptionTableEntry,
  ppExceptionTable
  ) where

import           Control.Monad ( replicateM )
import qualified Control.Monad.Fail as MF
import qualified Data.Binary.Get as G
import qualified Data.BitVector.Sized as BVS
import qualified Data.Bits as DB
import qualified Data.Foldable as F
import qualified Data.Parameterized.Classes as PC
import qualified Data.Parameterized.NatRepr as PN
import           Data.Parameterized.Some ( Some(..) )
import qualified Data.Parameterized.TH.GADT as PTG
import qualified Data.Vector as V
import           Data.Word ( Word32 )
import qualified Prettyprinter as PP

import qualified PE.Parser.Headers as PPH
import qualified PE.Parser.Machine as PPM
import qualified PE.Parser.Pretty as PPP

-- | An exception table entry for 32 bit MIPS
data MIPSExceptionTableEntry =
  MIPSExceptionTableEntry { mipsExceptionBeginAddress :: Word32
                     -- ^ The RVA of the function entry
                     , mipsExceptionEndAddress :: Word32
                     -- ^ The RVA of the function exit
                     , mipsExceptionHandlerPointer :: Word32
                     -- ^ The RVA of the exception handler
                     , mipsExceptionHandlerData :: Word32
                     -- ^ The RVA of additional data to be passed to the handler
                     , mipsExceptionPrologEndAddress :: Word32
                     -- ^ The RVA of the end of the function prolog
                     }
  deriving (Show)

-- | An exception table entry for x86, x86_64, or Itanium
data IntelExceptionTableEntry =
  IntelExceptionTableEntry { intelExceptionBeginAddress :: Word32
                      -- ^ The begin RVA of the function
                      , intelExceptionEndAddress :: Word32
                      -- ^ The end RVA of the function
                      , intelExceptionUnwindInformation :: Word32
                      -- ^ The RVA of the unwind information
                      }
  deriving (Show)

-- | A compact exception table format used on ARM, PowerPC, SH3, SH4 Windows CE
data CompactExceptionTableEntry =
  CompactExceptionTableEntry { compactExceptionBeginAddress :: Word32
                        -- ^ The RVA of the function entry
                        , compactExceptionPrologLength :: BVS.BV 8
                        -- ^ The number of instructions in the function prolog
                        , compactExceptionFunctionLength :: BVS.BV 22
                        -- ^ The number of instructions in the function
                        , compactException32Bit :: Bool
                        -- ^ If set, the function consists of 32 bit
                        -- instructions (otherwise, 16)
                        , compactExceptionExceptionFlag :: Bool
                        -- ^ If set, an exception handler exists for the
                        -- function
                        }
  deriving (Show)

-- | A type-level data kind distinguishing the various Exception Table formats
data ExceptionTableFormat = MIPSK | IntelK | CompactK

type MIPSK = 'MIPSK
type IntelK = 'IntelK
type CompactK = 'CompactK

-- | A value-level representative of the ExceptionTable format
data ExceptionTableRepr (format :: ExceptionTableFormat) where
  MIPSExceptionRepr :: ExceptionTableRepr MIPSK
  IntelExceptionRepr :: ExceptionTableRepr IntelK
  CompactExceptionRepr :: ExceptionTableRepr CompactK

-- | Compute the size of an Exception Table entry
exceptionTableEntrySize :: ExceptionTableRepr format -> Word32
exceptionTableEntrySize rep =
  case rep of
    MIPSExceptionRepr -> 20
    IntelExceptionRepr -> 12
    CompactExceptionRepr -> 8

$(return [])

instance PC.TestEquality ExceptionTableRepr where
  testEquality = $(PTG.structuralTypeEquality [t|ExceptionTableRepr|] [])

instance PC.ShowF ExceptionTableRepr where
  showsPrecF = $(PTG.structuralShowsPrec [t|ExceptionTableRepr|])

$(return [])

instance Show (ExceptionTableRepr format) where
  show = PC.showF

-- | Map the type-level Exception Table specifier to its corresponding value type
type family ExceptionTableEntry format where
  ExceptionTableEntry MIPSK = MIPSExceptionTableEntry
  ExceptionTableEntry IntelK = IntelExceptionTableEntry
  ExceptionTableEntry CompactK = CompactExceptionTableEntry

-- | An existential wrapper around collections of 'ExceptionTableEntry's,
-- wrapped up with the relevant value-level representative
data ExceptionTable =
  forall format .
  ExceptionTable { exceptionTableRepr :: ExceptionTableRepr format
                 -- ^ The value level representative
                 , exceptionTableEntries :: V.Vector (ExceptionTableEntry format)
                 -- ^ The collection of Exception Table entries (all guaranteed to be the same format)
                 }

instance Show ExceptionTable where
  show (ExceptionTable repr entries) =
    case repr of
      MIPSExceptionRepr -> concat [ "ExceptionTable "
                                  , show repr
                                  , " "
                                  , show entries
                                  ]
      IntelExceptionRepr -> concat [ "ExceptionTable "
                                   , show repr
                                   , " "
                                   , show entries
                                   ]
      CompactExceptionRepr -> concat [ "ExceptionTable "
                                     , show repr
                                     , " "
                                     , show entries
                                     ]

-- | Look up the 'ExceptionTableRepr' for the given 'PPM.Machine'
--
-- This can fail, because there are not exception table formats prescribed for
-- all of the architectures.
machineExceptionRepr :: PPM.Machine -> Maybe (Some ExceptionTableRepr)
machineExceptionRepr m =
  case m of
    PPM.PE_MACHINE_AMD64 -> Just (Some IntelExceptionRepr)
    PPM.PE_MACHINE_IA64 -> Just (Some IntelExceptionRepr)
    PPM.PE_MACHINE_I386 -> Just (Some IntelExceptionRepr)
    PPM.PE_MACHINE_MIPSFPU -> Just (Some MIPSExceptionRepr)
    PPM.PE_MACHINE_R4000 -> Just (Some MIPSExceptionRepr)
    PPM.PE_MACHINE_ARM -> Just (Some CompactExceptionRepr)
    PPM.PE_MACHINE_ARMNT -> Just (Some CompactExceptionRepr)
    PPM.PE_MACHINE_Thumb -> Just (Some CompactExceptionRepr)
    PPM.PE_MACHINE_POWERPC -> Just (Some CompactExceptionRepr)
    PPM.PE_MACHINE_POWERPCFP -> Just (Some CompactExceptionRepr)
    PPM.PE_MACHINE_SH3 -> Just (Some CompactExceptionRepr)
    PPM.PE_MACHINE_SH4 -> Just (Some CompactExceptionRepr)
    PPM.PE_MACHINE_WCEMIPSV2 -> Just (Some CompactExceptionRepr)
    _ -> Nothing

-- | Parse an Exception Table entry (of the given format)
parseExceptionTableEntry :: ExceptionTableRepr format -> G.Get (ExceptionTableEntry format)
parseExceptionTableEntry repr =
  case repr of
    MIPSExceptionRepr -> do
      begin <- G.getWord32le
      end <- G.getWord32le
      handlerRVA <- G.getWord32le
      dataRVA <- G.getWord32le
      prologEndAddr <- G.getWord32le
      return MIPSExceptionTableEntry { mipsExceptionBeginAddress = begin
                                , mipsExceptionEndAddress = end
                                , mipsExceptionHandlerPointer = handlerRVA
                                , mipsExceptionHandlerData = dataRVA
                                , mipsExceptionPrologEndAddress = prologEndAddr
                                }
    IntelExceptionRepr -> do
      begin <- G.getWord32le
      end <- G.getWord32le
      unwind <- G.getWord32le
      return IntelExceptionTableEntry { intelExceptionBeginAddress = begin
                                 , intelExceptionEndAddress = end
                                 , intelExceptionUnwindInformation = unwind
                                 }
    CompactExceptionRepr -> do
      begin <- G.getWord32le
      w32 <- G.getWord32le
      -- Grab the high 8 bits
      let prologLen = w32 `DB.shiftR` 24
      let funLen = (w32 `DB.shiftL` 8) `DB.shiftR` 10
      return CompactExceptionTableEntry { compactExceptionBeginAddress = begin
                                   , compactExceptionPrologLength = BVS.mkBV PN.knownNat (toInteger prologLen)
                                   , compactExceptionFunctionLength = BVS.mkBV PN.knownNat (toInteger funLen)
                                   , compactException32Bit = DB.testBit w32 1
                                   , compactExceptionExceptionFlag = DB.testBit w32 0
                                   }

-- | Pretty print an Exception Table entry
ppExceptionTableEntry :: ExceptionTableRepr format -> ExceptionTableEntry format -> PP.Doc ann
ppExceptionTableEntry repr tbl =
  case repr of
    MIPSExceptionRepr ->
      PP.vcat [ PP.pretty "Begin RVA: " <> PPP.ppHex (mipsExceptionBeginAddress tbl)
              , PP.pretty "End RVA: " <> PPP.ppHex (mipsExceptionEndAddress tbl)
              , PP.pretty "Handler Function RVA: " <> PPP.ppHex (mipsExceptionHandlerPointer tbl)
              , PP.pretty "Handler Data RVA: " <> PPP.ppHex (mipsExceptionHandlerData tbl)
              , PP.pretty "Prolog End RVA: " <> PPP.ppHex (mipsExceptionPrologEndAddress tbl)
              ]
    IntelExceptionRepr ->
      PP.vcat [ PP.pretty "Begin RVA: " <> PPP.ppHex (intelExceptionBeginAddress tbl)
              , PP.pretty "End RVA: " <> PPP.ppHex (intelExceptionEndAddress tbl)
              , PP.pretty "Unwind Information RVA: " <> PPP.ppHex (intelExceptionUnwindInformation tbl)
              ]
    CompactExceptionRepr ->
      PP.vcat [ PP.pretty "Begin RVA: " <> PPP.ppHex (compactExceptionBeginAddress tbl)
              , PP.pretty "Prolog Length: " <> PP.pretty (BVS.asUnsigned (compactExceptionPrologLength tbl))
              , PP.pretty "Function Length: " <> PP.pretty (BVS.asUnsigned (compactExceptionFunctionLength tbl))
              , PP.pretty "Is 32 bit: " <> PP.pretty (compactException32Bit tbl)
              , PP.pretty "Has Handler: " <> PP.pretty (compactExceptionExceptionFlag tbl)
              ]

-- | Pretty print an 'ExceptionTable'
ppExceptionTable :: ExceptionTable -> PP.Doc ann
ppExceptionTable (ExceptionTable repr entries) =
  PP.vcat (fmap ppEntry (zip [0..] (F.toList entries)))
  where
    ppEntry (idx, entry) =
      PP.vcat [ PP.pretty "Entry " <> PP.pretty (idx :: Int)
              , PP.indent 4 (ppExceptionTableEntry repr entry)
              ]

-- | Parse an entire Exception Table
--
-- This uses the 'PPH.PEHeader' to determine the machine type.  The table size
-- is required to determine the number of entries to parse; this size is taken
-- from the Data Directory Entry for the Exception Table.
--
-- Note that this can fail (safely via 'fail' in 'G.Get') if there is no
-- Exception Header table format defined for the 'PE.Parser.Machine.Machine'
-- architecture specified in the 'PPH.PEHeader'.
parseExceptionTable :: PPH.PEHeader
                    -> Word32
                    -- ^ Table size (according to the Directory Entry)
                    -> G.Get ExceptionTable
parseExceptionTable hdr numBytes =
  case machineExceptionRepr (PPH.peHeaderMachine hdr) of
    Nothing -> MF.fail ("No ExceptionTable format defined for machine " ++ show (PPH.peHeaderMachine hdr))
    Just (Some repr) -> do
      let entrySize = exceptionTableEntrySize repr
      if | numBytes `mod` entrySize /= 0 ->
           PPP.failDoc (PP.pretty "Exception table entry size "
                        <> PP.parens (PP.pretty entrySize)
                        <> PP.pretty " does not evenly divide the table size "
                        <> PP.parens (PP.pretty numBytes))
         | otherwise -> do
             let numEntries = numBytes `div` entrySize
             entries <- replicateM (fromIntegral numEntries) (parseExceptionTableEntry repr)
             return ExceptionTable { exceptionTableRepr = repr
                                   , exceptionTableEntries = V.fromList entries
                                   }
