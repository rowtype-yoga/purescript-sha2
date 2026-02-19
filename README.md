# SHA-256 for PureScript — Chez Scheme Backend

A PureScript implementation of SHA-2 (FIPS 180-4) and HMAC-SHA256 (RFC 2104)
targeting the [purescm](https://github.com/purescm/purescm) Chez Scheme backend,
with an optimized Scheme FFI that achieves **32 MB/s** SHA-256 throughput and
**943K ops/s** on empty inputs.

## Why a Chez Backend?

The JavaScript backend limits PureScript's `Int` to 32-bit signed range
`[-2^31, 2^31-1]`. On Chez Scheme, integers are arbitrary-precision with
hardware fixnums up to 61 bits. SHA-256 operates entirely on 32-bit words,
which sit comfortably inside a single Chez fixnum with room to spare —
no overflow risk, no bignum allocation, just clean fixnum arithmetic
throughout the entire computation.

The PureScript interface is identical across backends:

```purescript
import Crypto.SHA256 (sha256, hmacSha256, toString)

toString (sha256 "hello world")
toString (hmacSha256 "key" "message")
```

## Performance

SHA-256 throughput on 1 MiB input (higher is better):

| Implementation | MB/s |
|---|---|
| **Chez Scheme FFI (this library)** | **32** |
| Pure PureScript (no FFI) | ~1 |

### Benchmark Results

```
── SHA-256 (small inputs) ─────────────────────────────
  empty (0 B)  500 iters  0.53 ms   943K ops/s    0.0 MB/s
  32 B         500 iters  0.73 ms   687K ops/s   21.0 MB/s
  55 B (1blk)  500 iters  0.91 ms   551K ops/s   28.9 MB/s
  64 B (2blk)  500 iters  1.39 ms   360K ops/s   22.0 MB/s

── SHA-256 (multi-block) ──────────────────────────────
  512 B        100 iters  1.61 ms    62K ops/s   30.3 MB/s
  1 KiB        100 iters  3.59 ms    28K ops/s   27.2 MB/s
  4 KiB        100 iters 11.69 ms   8.6K ops/s   33.4 MB/s

── SHA-256 (large inputs) ─────────────────────────────
  64 KiB        10 iters 18.30 ms    546 ops/s   34.2 MB/s
  1 MiB         10 iters  312  ms     32 ops/s   32.1 MB/s

── HMAC-SHA256 ───────────────────────────────────────
  32 B msg     200 iters  1.07 ms   187K ops/s    5.7 MB/s
  256 B msg    200 iters  2.71 ms    74K ops/s   18.0 MB/s
  1 KiB msg    200 iters  7.33 ms    27K ops/s   26.7 MB/s
```

Small-input overhead is remarkably low: 943K ops/s for empty strings,
meaning per-hash setup cost is ~1 µs.

### Key Techniques

- **Named-let compression loop**: The 64-round compression function uses
  8 working variables (`a`–`h`) as `named-let` loop parameters, giving
  Chez's optimizer the best chance to keep them in registers:

  ```scheme
  (let loop ([j 0]
             [a (vector-ref h 0)] [b (vector-ref h 1)]
             [c (vector-ref h 2)] [d (vector-ref h 3)]
             [e (vector-ref h 4)] [f (vector-ref h 5)]
             [g (vector-ref h 6)] [hv (vector-ref h 7)])
    ...)
  ```

- **`(optimize-level 3)`**: Maximum Chez compiler optimization —
  aggressive inlining, constant folding, and unsafe arithmetic.

- **Safe shift macros**: `fxsll` raises an exception if the result
  exceeds fixnum range. The `sll32` macro pre-masks input bits to
  guarantee the shifted result stays within 32 bits:

  ```scheme
  (define-syntax sll32
    (syntax-rules ()
      [(_ x n) (fxsll (fxlogand x (fxsrl #xFFFFFFFF n)) n)]))

  (define-syntax rotr32
    (syntax-rules ()
      [(_ x n) (fxlogior (fxsrl x n) (sll32 x (fx- 32 n)))]))
  ```

- **Bytevector I/O**: Message schedule loading, padding, and HMAC key
  operations all work on native bytevectors, converting to/from
  flexvectors only at the PureScript boundary.

### What We Tried That Didn't Help

Several "obvious" optimizations turned out to be neutral or harmful:

- **Module-level reusable W vector** — broke Chez optimizer assumptions
  about local scope; 11% regression
- **Pre-adding K\[j\] into W\[j\]** — 64 extra additions didn't justify
  removing 64 vector-refs
- **`bytevector-u32-ref` big-endian** — byte-swapping overhead on x86
  worse than manual shifts
- **Reduced masking / micro-optimized ch/maj** — noise-level impact

Lesson: Chez's native compiler at `(optimize-level 3)` already does
excellent work. Fighting it with "clever" optimizations backfires. The
`named-let` with local variables was already optimal.

## Architecture

```
src/
  Crypto/
    SHA256.purs        -- Public API (Hashable, Digest, SHA2 variants, HMAC)
    SHA256.ss          -- Chez FFI: compression function, HMAC, hex utilities
test/
  Test/
    Main.purs          -- Entry point (tests, optional benchmarks)
    Main.ss            -- Chez FFI: BENCH env var check
    SHA256.purs        -- 20 test vectors (FIPS 180-4 + RFC 4231)
    SHA256/
      Bench.purs       -- Throughput benchmarks
      Bench.ss         -- Chez FFI: performanceNow, defer, intToNumber
```

Everything lives in a single `.ss` file — SHA-256's 32-bit operations
map directly to Chez fixnum primitives with no additional modules needed.

## Building

Requires [purescm](https://github.com/purescm/purescm) and Chez Scheme.

```bash
spago build
purescm run --main Test.Main            # tests only
BENCH=1 purescm run --main Test.Main    # tests + benchmarks
```

## Test Vectors

20 vectors covering:

- **SHA-256**: NIST FIPS 180-4 §B.1–B.3 (empty, "abc", 56-byte, 112-byte),
  1 million `a`s, single byte, boundary cases (55 and 56 bytes), raw bytes
- **SHA-224**: NIST FIPS 180-4 (empty, "abc", 56-byte)
- **HMAC-SHA256**: RFC 4231 Test Cases 1–4 and 6 (including 131-byte key
  that triggers key pre-hashing)
- **Digest operations**: Eq instance, fromHex roundtrip

## Notes on Chez Scheme's Integer Model

- **Fixnums**: On 64-bit Chez, fixnums cover `[-2^60, 2^60-1]` (61 bits,
  3 tag bits). SHA-256's 32-bit values sit well within this range — no
  bignum risk at all.
- **Safe shifts**: `fxsll` raises an exception if the result exceeds
  fixnum range. The `sll32` macro pre-masks input bits to guarantee
  the shifted result stays within 32 bits.
- **All intermediates masked**: Every addition result is masked with
  `#xFFFFFFFF` to stay 32-bit. On Chez 10's 61-bit fixnums, this
  guarantees zero bignum allocation throughout the entire computation.

## FFI Conventions

The `.ss` file uses the purescm library convention:

```scheme
(library (Crypto.SHA256 foreign)
  (export sha256Bv sha224Bv hmacSha256Bv
          stringToUtf8Bv bytesToHex hexToByteArray
          arrayToByteArray byteArrayToArray
          eqByteArray byteArrayLength)
  (import (chezscheme)
          (purescm pstring)
          (srfi :214)
          (purescm bytevector))
  ...)
```

The library name is `(<ModuleName> foreign)` where `<ModuleName>` matches
the PureScript module name. All multi-argument functions must be curried
(nested lambdas) to match PureScript's calling convention. PureScript
`Array` maps to SRFI 214 flexvectors in purescm. The `ByteArray` opaque
type maps to native Chez bytevectors.

## References

- [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) — Secure Hash Standard (SHA-256, SHA-224)
- [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) — HMAC: Keyed-Hashing for Message Authentication
- [RFC 4231](https://datatracker.ietf.org/doc/html/rfc4231) — HMAC-SHA256 Test Vectors