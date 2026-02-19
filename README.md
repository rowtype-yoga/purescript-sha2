# purescript-sha2

SHA-2 (FIPS 180-4) cryptographic hash functions and HMAC-SHA256 (RFC 2104) for PureScript, with optimized native FFI for the **JavaScript** (Node.js) backend.

Verified against NIST FIPS 180-4 and RFC 4231 test vectors.



### Features

- SHA-256 and SHA-224 hash functions
- HMAC-SHA256 message authentication
- `Hashable` typeclass for `String` and `Buffer` inputs
- `Digest` newtype with `Eq` and `Show` instances
- Hex encoding/decoding
- 8× unrolled compression function with `Int32Array` message schedule
- **110 MB/s** SHA-256 throughput on Node.js



### Install

Add to your `spago.yaml` dependencies:

```yaml
workspace:
  extra_packages:
    sha256:
      git: https://github.com/pissiboi/purescript-sha256.git
      ref: main
      subdir: null

package:
  dependencies:
    - sha256
```

##### Nix

A flake is provided for development:

```bash
nix develop
spago build
spago test            # tests only
spago test -- --bench # tests + benchmarks
```



### Examples


##### Hash a string

```haskell
import Crypto.SHA256 (sha256, toString)

toString (sha256 "purescript ftw")
-- "e3b0c44298fc1c149afbf4c8996fb924..."
```


##### Hash a Buffer

```haskell
import Crypto.SHA256 (sha256, toString)
import Node.Buffer as Buffer

main = do
  buf <- Buffer.fromArray [0xDE, 0xAD, 0xBE, 0xEF]
  log (toString (sha256 buf))
```


##### Compare digests

```haskell
import Crypto.SHA256 (sha256)

sameDigest = sha256 "hello" == sha256 "hello"
-- true

differentDigest = sha256 "hello" == sha256 "world"
-- false
```


##### HMAC-SHA256

```haskell
import Crypto.SHA256 (hmacSha256, hmacSha256Buf, toString)
import Node.Buffer as Buffer

-- String key and message
toString (hmacSha256 "secret-key" "message to authenticate")

-- Buffer key and message (zero-copy)
main = do
  key <- Buffer.fromArray [0x01, 0x02, 0x03, 0x04]
  msg <- Buffer.fromString "payload" Buffer.UTF8
  log (toString (hmacSha256Buf key msg))
```


##### Hex decoding

```haskell
import Crypto.SHA256 (sha256, toString, fromHex)

main = do
  let digest = sha256 "hello"
  let hex    = toString digest
  let round  = fromHex hex  -- Just (Digest ...)
  log (show (map toString round))
```



### API

| Function | Type | Description |
|---|---|---|
| `hash` | `SHA2 -> a -> Digest` | Hash any `Hashable` (String or Buffer) |
| `sha256` | input `-> Digest` | SHA-256 (32 bytes) |
| `sha224` | input `-> Digest` | SHA-224 (28 bytes) |
| `hmacSha256` | `String -> String -> Digest` | HMAC-SHA256 with string key/message |
| `hmacSha256Buf` | `Buffer -> Buffer -> Digest` | HMAC-SHA256 with Buffer key/message |
| `toString` | `Digest -> String` | Hex-encode a digest |
| `fromHex` | `String -> Maybe Digest` | Decode hex to a digest |
| `exportToBuffer` | `Digest -> Buffer` | Extract raw Buffer from digest |
| `importFromBuffer` | `Buffer -> Maybe Digest` | Wrap a Buffer as a digest |



### Running tests

```bash
spago test            # tests only
spago test -- --bench # tests + benchmarks
```

```
SHA-2 (FIPS 180-4) Test Suite

  ✓ SHA-256("")
  ✓ SHA-256("abc")
  ✓ SHA-256("abcdbcde...nopq")
  ✓ SHA-256("abcdefgh...nopqrstu")
  ✓ SHA-256(1M × 0x61)
  ✓ SHA-256("a")
  ✓ SHA-256(55 × 0x61, 1 block)
  ✓ SHA-256(56 × 0x61, 2 blocks)
  ✓ SHA-256([0xde,0xad,0xbe,0xef])
  ✓ SHA-224("")
  ✓ SHA-224("abc")
  ✓ SHA-224("abcdbcde...nopq")
  ✓ Digest Eq (same input)
  ✓ Digest Eq (different input)
  ✓ fromHex roundtrip
  ✓ HMAC-SHA256 (RFC4231 TC1)
  ✓ HMAC-SHA256 (RFC4231 TC2)
  ✓ HMAC-SHA256 (RFC4231 TC3)
  ✓ HMAC-SHA256 (RFC4231 TC4)
  ✓ HMAC-SHA256 (RFC4231 TC6, long key)

20 passed, 0 failed
```



### Performance

SHA-256 throughput on 1 MiB input (higher is better):

| Implementation | MB/s |
|---|---|
| **Node.js FFI (this library)** | **110** |
| js-sha256 (reference JS) | ~90 |
| noble/hashes (JS) | ~55 |
| Pure PureScript (no FFI) | ~1 |

The JS backend achieves this through an 8× unrolled compression loop with
optimized `ch` and `maj` formulas (`g^(e&(f^g))` and `(a&b)|((a^b)&c)`),
pre-allocated `Int32Array` message schedule reused across calls,
`Buffer`-native I/O with zero-copy block processing for large inputs,
and `Buffer.allocUnsafe` where contents are immediately overwritten.



### Architecture

```
src/
  Crypto/
    SHA256.purs        -- Public API (Hashable, Digest, SHA2 variants, HMAC)
    SHA256.js          -- JS FFI: SHA-256/224 compression, HMAC, hex utilities
test/
  Test/
    Crypto/
      SHA256.purs      -- 20 test vectors (FIPS 180-4 + RFC 4231)
      SHA256/
        Bench.purs     -- Benchmark suite
        Bench.js       -- FFI: performanceNow, defer
    Main.purs          -- Test runner (--bench flag)
    Main.js            -- FFI: argv
```



### References

- [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) — Secure Hash Standard (SHA-256, SHA-224)
- [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) — HMAC: Keyed-Hashing for Message Authentication
- [RFC 4231](https://datatracker.ietf.org/doc/html/rfc4231) — HMAC-SHA256 Test Vectors