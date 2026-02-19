module Test.SHA256.Bench where

import Prelude

import Crypto.SHA256 (SHA2(..), hash, hmacSha256Bytes)
import Data.Array as A
import Effect (Effect)
import Effect.Console (log)
import Test.SHA256 as SHA256Tests

-------------------------------------------------------------------------------
-- FFI
-------------------------------------------------------------------------------

foreign import performanceNow :: Effect Number
foreign import defer :: forall a. (Unit -> a) -> Effect a
foreign import intToNumber :: Int -> Number

-------------------------------------------------------------------------------
-- Timing Helpers
-------------------------------------------------------------------------------

timeN :: Int -> Effect Unit -> Effect Number
timeN n action = do
  t0 <- performanceNow
  go 0
  t1 <- performanceNow
  pure (t1 - t0)
  where
  go i
    | i >= n = pure unit
    | otherwise = action *> go (i + 1)

report :: String -> Int -> Int -> Number -> Effect Unit
report label iterations inputBytes ms = do
  let
    throughputMBs =
      if ms > 0.0 then
        (intToNumber (iterations * inputBytes) / 1048576.0) / (ms / 1000.0)
      else 0.0
    opsPerSec =
      if ms > 0.0 then intToNumber iterations / (ms / 1000.0)
      else 0.0
  log $ "  " <> label
    <> "  " <> show iterations <> " iters"
    <> "  " <> show ms <> " ms"
    <> "  " <> show opsPerSec <> " ops/s"
    <> "  " <> show throughputMBs <> " MB/s"

-------------------------------------------------------------------------------
-- Benchmarks
-------------------------------------------------------------------------------

benchSuite :: Effect Unit
benchSuite = do
  log "═══════════════════════════════════════════════════════════"
  log "  SHA-256 Benchmarks (Chez Scheme / purescm)"
  log "═══════════════════════════════════════════════════════════"

  log "\n── SHA-256 (small inputs) ─────────────────────────────"
  let iters = 500

  do
    let input = ([] :: Array Int)
    ms <- timeN iters (void $ defer \_ -> hash SHA2_256 input)
    report "empty (0 B)" iters 0 ms

  do
    let input = A.replicate 32 0
    ms <- timeN iters (void $ defer \_ -> hash SHA2_256 input)
    report "32 B       " iters 32 ms

  do
    let input = A.replicate 55 0
    ms <- timeN iters (void $ defer \_ -> hash SHA2_256 input)
    report "55 B (1blk)" iters 55 ms

  do
    let input = A.replicate 64 0
    ms <- timeN iters (void $ defer \_ -> hash SHA2_256 input)
    report "64 B (2blk)" iters 64 ms

  log "\n── SHA-256 (multi-block) ──────────────────────────────"
  let itersM = 100

  do
    let input = A.replicate 512 0
    ms <- timeN itersM (void $ defer \_ -> hash SHA2_256 input)
    report "512 B      " itersM 512 ms

  do
    let input = A.replicate 1024 0
    ms <- timeN itersM (void $ defer \_ -> hash SHA2_256 input)
    report "1 KiB      " itersM 1024 ms

  do
    let input = A.replicate 4096 0
    ms <- timeN itersM (void $ defer \_ -> hash SHA2_256 input)
    report "4 KiB      " itersM 4096 ms

  log "\n── SHA-256 (large inputs) ─────────────────────────────"
  let itersL = 10

  do
    let input = A.replicate 65536 0
    ms <- timeN itersL (void $ defer \_ -> hash SHA2_256 input)
    report "64 KiB     " itersL 65536 ms

  do
    let input = A.replicate 1048576 0
    ms <- timeN itersL (void $ defer \_ -> hash SHA2_256 input)
    report "1 MiB      " itersL 1048576 ms

  log "\n── SHA-224 vs SHA-256 (256 B input) ───────────────────"
  let itersV = 200

  do
    let input = A.replicate 256 0
    ms224 <- timeN itersV (void $ defer \_ -> hash SHA2_224 input)
    report "SHA-224    " itersV 256 ms224
    ms256 <- timeN itersV (void $ defer \_ -> hash SHA2_256 input)
    report "SHA-256    " itersV 256 ms256

  log "\n── HMAC-SHA256 ───────────────────────────────────────"
  let itersH = 200

  do
    let key = A.replicate 32 0xAA
        msg32 = A.replicate 32 0
    ms <- timeN itersH (void $ defer \_ -> hmacSha256Bytes key msg32)
    report "32 B msg   " itersH 32 ms

  do
    let key = A.replicate 32 0xAA
        msg256 = A.replicate 256 0
    ms <- timeN itersH (void $ defer \_ -> hmacSha256Bytes key msg256)
    report "256 B msg  " itersH 256 ms

  do
    let key = A.replicate 32 0xAA
        msg1k = A.replicate 1024 0
    ms <- timeN itersH (void $ defer \_ -> hmacSha256Bytes key msg1k)
    report "1 KiB msg  " itersH 1024 ms

  log "\n═══════════════════════════════════════════════════════════"
  log "  Done."
  log "═══════════════════════════════════════════════════════════"


main :: Effect Unit
main = do
  SHA256Tests.main
  log ""
  benchSuite