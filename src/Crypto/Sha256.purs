-- | SHA-2 (FIPS 180-4) cryptographic hash functions: SHA-256 and SHA-224.
-- |
-- | Pure PureScript API with Chez Scheme FFI backend using native 32-bit
-- | fixnum operations for the compression function.
-- |
-- | Usage:
-- | ```purescript
-- | import Crypto.SHA256 (sha256, toString)
-- |
-- | digest = sha256 "hello world"
-- | hex    = toString digest
-- | ```
module Crypto.SHA256
  ( SHA2(..)
  , Digest
  , class Hashable
  , hash
  , sha256
  , sha224
  , hmacSha256
  , hmacSha256Bytes
  , toString
  , fromHex
  , toArray
  , fromArray
  ) where

import Prelude

import Data.Maybe (Maybe(..))

-------------------------------------------------------------------------------
-- FFI (Chez Scheme)
-------------------------------------------------------------------------------

-- | Opaque byte array — on Chez this is a native bytevector.
foreign import data ByteArray :: Type

-- | SHA-256 hash: ByteArray → ByteArray (32 bytes)
foreign import sha256Bv :: ByteArray -> ByteArray

-- | SHA-224 hash: ByteArray → ByteArray (28 bytes)
foreign import sha224Bv :: ByteArray -> ByteArray

-- | HMAC-SHA256: key → message → MAC (32 bytes)
foreign import hmacSha256Bv :: ByteArray -> ByteArray -> ByteArray

-- | Convert a PureScript String to a UTF-8 ByteArray.
foreign import stringToUtf8Bv :: String -> ByteArray

-- | Encode a ByteArray as a lowercase hex string.
foreign import bytesToHex :: ByteArray -> String

-- | Decode a hex string to a ByteArray (empty on invalid input).
foreign import hexToByteArray :: String -> ByteArray

-- | Convert Array Int (flexvector) to ByteArray.
foreign import arrayToByteArray :: Array Int -> ByteArray

-- | Convert ByteArray to Array Int (flexvector).
foreign import byteArrayToArray :: ByteArray -> Array Int

-- | ByteArray equality.
foreign import eqByteArray :: ByteArray -> ByteArray -> Boolean

-- | ByteArray length in bytes.
foreign import byteArrayLength :: ByteArray -> Int

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- | SHA-2 hash function variants.
data SHA2 = SHA2_256 | SHA2_224

-- | The output of a SHA-2 hash function, stored as raw bytes.
newtype Digest = Digest ByteArray

instance eqDigest :: Eq Digest where
  eq (Digest a) (Digest b) = eqByteArray a b

instance showDigest :: Show Digest where
  show d = "(Digest " <> toString d <> ")"

-------------------------------------------------------------------------------
-- Hashable
-------------------------------------------------------------------------------

-- | Types that can be hashed with a SHA-2 function.
class Hashable a where
  hash :: SHA2 -> a -> Digest

instance hashableString :: Hashable String where
  hash variant s = hashBv variant (stringToUtf8Bv s)

instance hashableArray :: Hashable (Array Int) where
  hash variant arr = hashBv variant (arrayToByteArray arr)

hashBv :: SHA2 -> ByteArray -> Digest
hashBv SHA2_256 bv = Digest (sha256Bv bv)
hashBv SHA2_224 bv = Digest (sha224Bv bv)

-------------------------------------------------------------------------------
-- Convenience Hash Functions
-------------------------------------------------------------------------------

-- | SHA-256: 256-bit (32-byte) digest.
sha256 :: forall a. Hashable a => a -> Digest
sha256 = hash SHA2_256

-- | SHA-224: 224-bit (28-byte) digest.
sha224 :: forall a. Hashable a => a -> Digest
sha224 = hash SHA2_224

-------------------------------------------------------------------------------
-- HMAC-SHA256 (RFC 2104 / RFC 4231)
-------------------------------------------------------------------------------

-- | HMAC-SHA256 with String key and String message.
-- | Returns a Digest (32 bytes).
hmacSha256 :: String -> String -> Digest
hmacSha256 key msg =
  Digest (hmacSha256Bv (stringToUtf8Bv key) (stringToUtf8Bv msg))

-- | HMAC-SHA256 with raw byte array key and message.
hmacSha256Bytes :: Array Int -> Array Int -> Digest
hmacSha256Bytes key msg =
  Digest (hmacSha256Bv (arrayToByteArray key) (arrayToByteArray msg))

-------------------------------------------------------------------------------
-- Serialization
-------------------------------------------------------------------------------

-- | Hex-encode a digest.
toString :: Digest -> String
toString (Digest bv) = bytesToHex bv

-- | Decode a hex string to a digest.
fromHex :: String -> Maybe Digest
fromHex hex =
  let bv = hexToByteArray hex
  in if byteArrayLength bv > 0 || hex == ""
     then Just (Digest bv)
     else Nothing

-- | Extract the raw bytes from a digest as Array Int.
toArray :: Digest -> Array Int
toArray (Digest bv) = byteArrayToArray bv

-- | Wrap raw bytes as a digest. No validation is performed on length.
fromArray :: Array Int -> Digest
fromArray arr = Digest (arrayToByteArray arr)