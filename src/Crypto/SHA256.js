// Crypto.SHA256 FFI — Optimized JavaScript implementation
//
// SHA-256, SHA-224, and HMAC-SHA256 (FIPS 180-4, RFC 2104).
// Buffer-native hot path: works directly on Node Buffers / Uint8Arrays
// with zero intermediate Array conversions.

// ── Round constants (FIPS 180-4 §4.2.2) ────────────────────────────────────

var K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

// ── Pre-allocated message schedule (reused — single-threaded) ───────────────

var W = new Int32Array(64);

// ── SHA-256 compression function ────────────────────────────────────────────

function compress(h, data, off) {
  var i, j, w15, w2, s0, s1, S0, S1, t1, t2;
  var a, b, c, d, e, f, g, hh;

  // Load 16 words big-endian
  for (i = 0; i < 16; i++) {
    j = off + (i << 2);
    W[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
  }

  // Extend message schedule to 64 words
  for (i = 16; i < 64; i++) {
    w15 = W[i - 15];
    s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    w2 = W[i - 2];
    s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    W[i] = (s1 + W[i - 7] + s0 + W[i - 16]) | 0;
  }

  // 64 rounds — 8x unrolled with optimized ch/maj
  a = h[0]; b = h[1]; c = h[2]; d = h[3];
  e = h[4]; f = h[5]; g = h[6]; hh = h[7];

  for (i = 0; i < 64; i += 8) {
    S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    t1=(hh+S1+(g^(e&(f^g)))+K[i]+W[i])|0;
    S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    t2=(S0+((a&b)|((a^b)&c)))|0;
    hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;

    S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    t1=(hh+S1+(g^(e&(f^g)))+K[i+1]+W[i+1])|0;
    S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    t2=(S0+((a&b)|((a^b)&c)))|0;
    hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;

    S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    t1=(hh+S1+(g^(e&(f^g)))+K[i+2]+W[i+2])|0;
    S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    t2=(S0+((a&b)|((a^b)&c)))|0;
    hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;

    S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    t1=(hh+S1+(g^(e&(f^g)))+K[i+3]+W[i+3])|0;
    S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    t2=(S0+((a&b)|((a^b)&c)))|0;
    hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;

    S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    t1=(hh+S1+(g^(e&(f^g)))+K[i+4]+W[i+4])|0;
    S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    t2=(S0+((a&b)|((a^b)&c)))|0;
    hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;

    S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    t1=(hh+S1+(g^(e&(f^g)))+K[i+5]+W[i+5])|0;
    S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    t2=(S0+((a&b)|((a^b)&c)))|0;
    hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;

    S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    t1=(hh+S1+(g^(e&(f^g)))+K[i+6]+W[i+6])|0;
    S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    t2=(S0+((a&b)|((a^b)&c)))|0;
    hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;

    S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    t1=(hh+S1+(g^(e&(f^g)))+K[i+7]+W[i+7])|0;
    S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    t2=(S0+((a&b)|((a^b)&c)))|0;
    hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
  }

  h[0] = (h[0] + a) | 0;
  h[1] = (h[1] + b) | 0;
  h[2] = (h[2] + c) | 0;
  h[3] = (h[3] + d) | 0;
  h[4] = (h[4] + e) | 0;
  h[5] = (h[5] + f) | 0;
  h[6] = (h[6] + g) | 0;
  h[7] = (h[7] + hh) | 0;
}

// ── Merkle-Damgård: hash a Buffer with given IV ─────────────────────────────

function sha2impl(data, iv, outWords) {
  var len = data.length;
  var h = new Int32Array(iv);

  // Process full 64-byte blocks directly from input (zero-copy)
  var fullBlocks = len >>> 6;
  for (var b = 0; b < fullBlocks; b++) {
    compress(h, data, b << 6);
  }

  // Build padded tail
  var tailStart = fullBlocks << 6;
  var tailLen = len - tailStart;
  var padBlocks = (tailLen + 9 > 64) ? 2 : 1;
  var padLen = padBlocks << 6;
  var pad = new Uint8Array(padLen); // zeroed

  // Copy remaining bytes
  for (var i = 0; i < tailLen; i++) {
    pad[i] = data[tailStart + i];
  }
  pad[tailLen] = 0x80;

  // 64-bit big-endian bit length
  var bitLenHi = Math.floor(len / 0x20000000);
  var bitLenLo = (len << 3) >>> 0;
  pad[padLen - 8] = (bitLenHi >>> 24) & 0xff;
  pad[padLen - 7] = (bitLenHi >>> 16) & 0xff;
  pad[padLen - 6] = (bitLenHi >>> 8) & 0xff;
  pad[padLen - 5] = bitLenHi & 0xff;
  pad[padLen - 4] = (bitLenLo >>> 24) & 0xff;
  pad[padLen - 3] = (bitLenLo >>> 16) & 0xff;
  pad[padLen - 2] = (bitLenLo >>> 8) & 0xff;
  pad[padLen - 1] = bitLenLo & 0xff;

  // Process padded tail
  for (var b = 0; b < padBlocks; b++) {
    compress(h, pad, b << 6);
  }

  // Extract hash as Buffer (big-endian)
  var out = Buffer.allocUnsafe(outWords << 2);
  for (var i = 0; i < outWords; i++) {
    out.writeInt32BE(h[i], i << 2);
  }
  return out;
}

// ── IVs ─────────────────────────────────────────────────────────────────────

var IV256 = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

var IV224 = new Int32Array([
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
  0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
]);

// ── Public API ──────────────────────────────────────────────────────────────

export function sha256Buf(buf) {
  return sha2impl(buf, IV256, 8);
}

export function sha224Buf(buf) {
  return sha2impl(buf, IV224, 7);
}

// ── HMAC-SHA256 (RFC 2104) ──────────────────────────────────────────────────

export function hmacSha256Impl(key) {
  return function (msg) {
    // Normalize key to 64 bytes
    if (key.length > 64) key = sha2impl(key, IV256, 8);
    var kpad = Buffer.alloc(64, 0);
    key.copy(kpad, 0, 0, key.length);

    // XOR key with ipad/opad
    var ipad = Buffer.allocUnsafe(64);
    var opad = Buffer.allocUnsafe(64);
    for (var i = 0; i < 64; i++) {
      ipad[i] = kpad[i] ^ 0x36;
      opad[i] = kpad[i] ^ 0x5c;
    }

    // Inner hash: SHA256(ipad-key ‖ message)
    var innerInput = Buffer.allocUnsafe(64 + msg.length);
    ipad.copy(innerInput, 0);
    msg.copy(innerInput, 64);
    var innerHash = sha2impl(innerInput, IV256, 8);

    // Outer hash: SHA256(opad-key ‖ inner-hash)
    var outerInput = Buffer.allocUnsafe(96); // 64 + 32
    opad.copy(outerInput, 0);
    innerHash.copy(outerInput, 64);
    return sha2impl(outerInput, IV256, 8);
  };
}

// ── Utility FFI ─────────────────────────────────────────────────────────────

export function bufferToHex(buf) {
  return buf.toString("hex");
}

export function bufferFromHex(success) {
  return function (failure) {
    return function (str) {
      if (str.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(str)) {
        return failure;
      }
      return success(Buffer.from(str, "hex"));
    };
  };
}

export function stringToUtf8Buffer(str) {
  return Buffer.from(str, "utf8");
}

export function eqBuffer(a) {
  return function (b) {
    return a.equals(b);
  };
}