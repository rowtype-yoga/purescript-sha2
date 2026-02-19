module Test.SHA256 where

import Prelude

import Crypto.SHA256 (SHA2(..), hash, toString, fromHex, hmacSha256, hmacSha256Bytes)
import Data.Array as A
import Data.Foldable (for_)
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Effect.Console (log)

type TestCase =
  { name     :: String
  , result   :: String
  , expected :: String
  }

runTests :: Array TestCase -> Effect Unit
runTests tests = do
  let
    results = map
      ( \t ->
          { name: t.name
          , passed: t.result == t.expected
          , result: t.result
          , expected: t.expected
          }
      )
      tests
    passed = A.length (A.filter _.passed results)
    failed = A.length (A.filter (not <<< _.passed) results)

  for_ results \r ->
    if r.passed then log ("  ✓ " <> r.name)
    else do
      log ("  ✗ " <> r.name)
      log ("    expected: " <> r.expected)
      log ("    got:      " <> r.result)

  log ""
  log (show passed <> " passed, " <> show failed <> " failed")

-- | Hash a string, return hex.
hashStr :: SHA2 -> String -> String
hashStr variant = toString <<< hash variant

main :: Effect Unit
main = do
  log "SHA-2 (FIPS 180-4) Test Suite — purescm / Chez Scheme backend\n"
  runTests
    -- SHA-256: NIST FIPS 180-4 §B.1 — empty
    [ { name: "SHA-256(\"\")"
      , result: hashStr SHA2_256 ""
      , expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }

    -- SHA-256: NIST FIPS 180-4 §B.1 — "abc"
    , { name: "SHA-256(\"abc\")"
      , result: hashStr SHA2_256 "abc"
      , expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      }

    -- SHA-256: NIST FIPS 180-4 §B.2 — two-block (56 bytes)
    , { name: "SHA-256(\"abcdbcde...nopq\")"
      , result: hashStr SHA2_256 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      , expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
      }

    -- SHA-256: NIST FIPS 180-4 §B.3 — 112 bytes
    , { name: "SHA-256(\"abcdefgh...nopqrstu\")"
      , result: hashStr SHA2_256 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
      , expected: "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
      }

    -- SHA-256: 1 million 'a's
    , { name: "SHA-256(1M × 0x61)"
      , result: toString (hash SHA2_256 (A.replicate 1000000 0x61))
      , expected: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
      }

    -- SHA-256: single byte
    , { name: "SHA-256(\"a\")"
      , result: hashStr SHA2_256 "a"
      , expected: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
      }

    -- SHA-256: 55 bytes — exactly one block after padding (55+1+8=64)
    , { name: "SHA-256(55 × 0x61, 1 block)"
      , result: toString (hash SHA2_256 (A.replicate 55 0x61))
      , expected: "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
      }

    -- SHA-256: 56 bytes — boundary, needs second block for length
    , { name: "SHA-256(56 × 0x61, 2 blocks)"
      , result: toString (hash SHA2_256 (A.replicate 56 0x61))
      , expected: "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
      }

    -- SHA-256: raw byte array input
    , { name: "SHA-256([0xde,0xad,0xbe,0xef])"
      , result: toString (hash SHA2_256 [0xde, 0xad, 0xbe, 0xef])
      , expected: "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953"
      }

    -- SHA-224: NIST FIPS 180-4 — empty
    , { name: "SHA-224(\"\")"
      , result: hashStr SHA2_224 ""
      , expected: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
      }

    -- SHA-224: NIST FIPS 180-4 — "abc"
    , { name: "SHA-224(\"abc\")"
      , result: hashStr SHA2_224 "abc"
      , expected: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
      }

    -- SHA-224: two-block
    , { name: "SHA-224(\"abcdbcde...nopq\")"
      , result: hashStr SHA2_224 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      , expected: "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
      }

    -- Digest Eq instance
    , { name: "Digest Eq (same input)"
      , result: show (hash SHA2_256 "abc" == hash SHA2_256 "abc")
      , expected: "true"
      }
    , { name: "Digest Eq (different input)"
      , result: show (hash SHA2_256 "abc" == hash SHA2_256 "def")
      , expected: "false"
      }

    -- fromHex roundtrip
    , { name: "fromHex roundtrip"
      , result: show (map toString (fromHex (toString (hash SHA2_256 "abc"))))
      , expected: show (Just (toString (hash SHA2_256 "abc")))
      }

    -- HMAC-SHA256: RFC 4231 Test Case 1 — key=20×0x0b, data="Hi There"
    , { name: "HMAC-SHA256 (RFC4231 TC1)"
      , result: toString (hmacSha256Bytes (A.replicate 20 0x0b) [0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65])
      , expected: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
      }

    -- HMAC-SHA256: RFC 4231 Test Case 2 — key="Jefe", data="what do ya want for nothing?"
    , { name: "HMAC-SHA256 (RFC4231 TC2)"
      , result: toString (hmacSha256 "Jefe" "what do ya want for nothing?")
      , expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
      }

    -- HMAC-SHA256: RFC 4231 Test Case 3 — key=20×0xaa, data=50×0xdd
    , { name: "HMAC-SHA256 (RFC4231 TC3)"
      , result: toString (hmacSha256Bytes (A.replicate 20 0xaa) (A.replicate 50 0xdd))
      , expected: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
      }

    -- HMAC-SHA256: RFC 4231 Test Case 4 — key=0x01..0x19, data=50×0xcd
    , { name: "HMAC-SHA256 (RFC4231 TC4)"
      , result: toString (hmacSha256Bytes (A.range 1 25) (A.replicate 50 0xcd))
      , expected: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
      }

    -- HMAC-SHA256: RFC 4231 Test Case 6 — key=131×0xaa (key > block size)
    , { name: "HMAC-SHA256 (RFC4231 TC6, long key)"
      , result: toString (hmacSha256Bytes (A.replicate 131 0xaa)
          [0x54,0x65,0x73,0x74,0x20,0x55,0x73,0x69,0x6e,0x67,0x20,0x4c
          ,0x61,0x72,0x67,0x65,0x72,0x20,0x54,0x68,0x61,0x6e,0x20,0x42
          ,0x6c,0x6f,0x63,0x6b,0x2d,0x53,0x69,0x7a,0x65,0x20,0x4b,0x65
          ,0x79,0x20,0x2d,0x20,0x48,0x61,0x73,0x68,0x20,0x4b,0x65,0x79
          ,0x20,0x46,0x69,0x72,0x73,0x74])
      , expected: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
      }
    ]