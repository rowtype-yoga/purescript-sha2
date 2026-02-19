(optimize-level 3)

(library (Crypto.SHA256 foreign)
  (export sha256Bv sha224Bv hmacSha256Bv
          stringToUtf8Bv bytesToHex hexToByteArray
          arrayToByteArray byteArrayToArray
          eqByteArray byteArrayLength)
  (import (chezscheme)
          (purescm pstring)
          (srfi :214)
          (purescm bytevector))

  ;; ── 32-bit helpers ─────────────────────────────────────────────────────
  ;; On Chez 10 (61-bit fixnums), all 32-bit values are fixnums.
  ;; sll32 pre-masks to prevent fxsll overflow.

  (define-syntax sll32
    (syntax-rules ()
      [(_ x n) (fxsll (fxlogand x (fxsrl #xFFFFFFFF n)) n)]))

  (define-syntax rotr32
    (syntax-rules ()
      [(_ x n) (fxlogior (fxsrl x n) (sll32 x (fx- 32 n)))]))

  ;; ── SHA-256 round constants (FIPS 180-4 §4.2.2) ───────────────────────

  (define K
    '#(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
       #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
       #xd807aa98 #x12835b01 #x243185be #x550c7dc3
       #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
       #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
       #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
       #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
       #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
       #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
       #x650a7354 #x766a0abb #x81c2c92e #x92722c85
       #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
       #xd192e819 #xd6990624 #xf40e3585 #x106aa070
       #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
       #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
       #x748f82ee #x78a5636f #x84c87814 #x8cc70208
       #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))

  ;; ── SHA-256 compression function ───────────────────────────────────────
  ;; h: mutable vector(8) — running hash state
  ;; w: mutable vector(64) — message schedule (reused across blocks)
  ;; padded: bytevector containing the padded message
  ;; off: byte offset of current 64-byte block

  (define (sha256-compress! h w padded off)
    ;; Load 16 words from block (big-endian)
    (do ([i 0 (fx+ i 1)])
        ((fx= i 16))
      (let ([o (fx+ off (fx* i 4))])
        (vector-set! w i
          (fxlogior (fxsll (bytevector-u8-ref padded o) 24)
            (fxlogior (fxsll (bytevector-u8-ref padded (fx+ o 1)) 16)
              (fxlogior (fxsll (bytevector-u8-ref padded (fx+ o 2)) 8)
                        (bytevector-u8-ref padded (fx+ o 3))))))))

    ;; Extend message schedule to 64 words (§6.2.2 step 1)
    (do ([i 16 (fx+ i 1)])
        ((fx= i 64))
      (let* ([w15 (vector-ref w (fx- i 15))]
             [w2  (vector-ref w (fx- i 2))]
             [s0 (fxlogxor (fxlogxor (rotr32 w15 7) (rotr32 w15 18))
                           (fxsrl w15 3))]
             [s1 (fxlogxor (fxlogxor (rotr32 w2 17) (rotr32 w2 19))
                           (fxsrl w2 10))])
        (vector-set! w i
          (fxlogand (fx+ (fx+ (vector-ref w (fx- i 16)) s0)
                         (fx+ (vector-ref w (fx- i 7)) s1))
                    #xFFFFFFFF))))

    ;; 64 rounds of compression (§6.2.2 steps 2–4)
    ;; Named let keeps working variables in registers — no vector overhead.
    (let loop ([j 0]
               [a (vector-ref h 0)] [b (vector-ref h 1)]
               [c (vector-ref h 2)] [d (vector-ref h 3)]
               [e (vector-ref h 4)] [f (vector-ref h 5)]
               [g (vector-ref h 6)] [hv (vector-ref h 7)])
      (if (fx= j 64)
        ;; Add compressed chunk to hash state
        (begin
          (vector-set! h 0 (fxlogand (fx+ (vector-ref h 0) a) #xFFFFFFFF))
          (vector-set! h 1 (fxlogand (fx+ (vector-ref h 1) b) #xFFFFFFFF))
          (vector-set! h 2 (fxlogand (fx+ (vector-ref h 2) c) #xFFFFFFFF))
          (vector-set! h 3 (fxlogand (fx+ (vector-ref h 3) d) #xFFFFFFFF))
          (vector-set! h 4 (fxlogand (fx+ (vector-ref h 4) e) #xFFFFFFFF))
          (vector-set! h 5 (fxlogand (fx+ (vector-ref h 5) f) #xFFFFFFFF))
          (vector-set! h 6 (fxlogand (fx+ (vector-ref h 6) g) #xFFFFFFFF))
          (vector-set! h 7 (fxlogand (fx+ (vector-ref h 7) hv) #xFFFFFFFF)))
        (let* ([S1  (fxlogxor (fxlogxor (rotr32 e 6) (rotr32 e 11))
                              (rotr32 e 25))]
               [ch  (fxlogxor (fxlogand e f)
                              (fxlogand (fxlogxor e #xFFFFFFFF) g))]
               [t1  (fxlogand (fx+ (fx+ (fx+ hv S1) (fx+ ch (vector-ref K j)))
                                   (vector-ref w j))
                              #xFFFFFFFF)]
               [S0  (fxlogxor (fxlogxor (rotr32 a 2) (rotr32 a 13))
                              (rotr32 a 22))]
               [maj (fxlogxor (fxlogxor (fxlogand a b) (fxlogand a c))
                              (fxlogand b c))]
               [t2  (fxlogand (fx+ S0 maj) #xFFFFFFFF)])
          (loop (fx+ j 1)
                (fxlogand (fx+ t1 t2) #xFFFFFFFF) ; a
                a                                    ; b
                b                                    ; c
                c                                    ; d
                (fxlogand (fx+ d t1) #xFFFFFFFF)   ; e
                e                                    ; f
                f                                    ; g
                g)))))                                ; h

  ;; ── Merkle-Damgård construction ────────────────────────────────────────
  ;; Pads message per FIPS 180-4 §5.1.1, then processes 64-byte blocks.

  (define (sha2-hash! h w msg)
    (let* ([msg-len (bytevector-length msg)]
           [bit-len (* msg-len 8)]
           ;; Padding: msg + 0x80 + zeros + 8-byte length = multiple of 64
           [padded-len (fx* (fxdiv (fx+ (fx+ msg-len 9) 63) 64) 64)]
           [padded (make-bytevector padded-len 0)])
      ;; Copy message
      (bytevector-copy! msg 0 padded 0 msg-len)
      ;; Append bit '1'
      (bytevector-u8-set! padded msg-len #x80)
      ;; Write 64-bit big-endian bit length at end
      (let ([lo (logand bit-len #xFFFFFFFF)]
            [hi (logand (ash bit-len -32) #xFFFFFFFF)])
        (bytevector-u8-set! padded (fx- padded-len 8) (fxlogand (fxsrl hi 24) #xFF))
        (bytevector-u8-set! padded (fx- padded-len 7) (fxlogand (fxsrl hi 16) #xFF))
        (bytevector-u8-set! padded (fx- padded-len 6) (fxlogand (fxsrl hi  8) #xFF))
        (bytevector-u8-set! padded (fx- padded-len 5) (fxlogand hi #xFF))
        (bytevector-u8-set! padded (fx- padded-len 4) (fxlogand (fxsrl lo 24) #xFF))
        (bytevector-u8-set! padded (fx- padded-len 3) (fxlogand (fxsrl lo 16) #xFF))
        (bytevector-u8-set! padded (fx- padded-len 2) (fxlogand (fxsrl lo  8) #xFF))
        (bytevector-u8-set! padded (fx- padded-len 1) (fxlogand lo #xFF)))
      ;; Process 64-byte blocks
      (let ([num-blocks (fxdiv padded-len 64)])
        (do ([blk 0 (fx+ blk 1)])
            ((fx= blk num-blocks))
          (sha256-compress! h w padded (fx* blk 64))))))

  ;; ── Extract hash as bytevector (big-endian) ────────────────────────────

  (define (hash-to-bv h num-words)
    (let ([out (make-bytevector (fx* num-words 4))])
      (do ([i 0 (fx+ i 1)])
          ((fx= i num-words))
        (let* ([val (vector-ref h i)]
               [off (fx* i 4)])
          (bytevector-u8-set! out off       (fxlogand (fxsrl val 24) #xFF))
          (bytevector-u8-set! out (fx+ off 1) (fxlogand (fxsrl val 16) #xFF))
          (bytevector-u8-set! out (fx+ off 2) (fxlogand (fxsrl val  8) #xFF))
          (bytevector-u8-set! out (fx+ off 3) (fxlogand val #xFF))))
      out))

  ;; ── Public API ─────────────────────────────────────────────────────────

  ;; SHA-256: ByteArray → ByteArray (32 bytes)
  (define sha256Bv
    (lambda (msg)
      (let ([h (vector #x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                       #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)]
            [w (make-vector 64 0)])
        (sha2-hash! h w msg)
        (hash-to-bv h 8))))

  ;; SHA-224: ByteArray → ByteArray (28 bytes)
  (define sha224Bv
    (lambda (msg)
      (let ([h (vector #xc1059ed8 #x367cd507 #x3070dd17 #xf70e5939
                       #xffc00b31 #x68581511 #x64f98fa7 #xbefa4fa4)]
            [w (make-vector 64 0)])
        (sha2-hash! h w msg)
        (hash-to-bv h 7))))

  ;; ── HMAC-SHA256 (RFC 2104 / RFC 4231) ───────────────────────────────────
  ;; HMAC(K, m) = SHA256( (K' ⊕ opad) || SHA256( (K' ⊕ ipad) || m ) )
  ;; K' = SHA256(K) if len(K)>64, else K padded with zeros to 64 bytes.

  (define hmacSha256Bv
    (lambda (key)
      (lambda (msg)
        ;; Step 1: normalize key to exactly 64 bytes
        (let* ([k (if (fx> (bytevector-length key) 64)
                      (sha256Bv key)
                      key)]
               [k-len (bytevector-length k)]
               [k-padded (make-bytevector 64 0)]
               [_ (bytevector-copy! k 0 k-padded 0 k-len)]
               ;; Step 2: build ipad-key and opad-key
               [ipad-key (make-bytevector 64)]
               [opad-key (make-bytevector 64)]
               [_ (do ([i 0 (fx+ i 1)])
                      ((fx= i 64))
                    (bytevector-u8-set! ipad-key i
                      (fxlogxor (bytevector-u8-ref k-padded i) #x36))
                    (bytevector-u8-set! opad-key i
                      (fxlogxor (bytevector-u8-ref k-padded i) #x5c)))]
               ;; Step 3: inner hash = SHA256(ipad-key || message)
               [msg-len (bytevector-length msg)]
               [inner-input (make-bytevector (fx+ 64 msg-len))]
               [_ (bytevector-copy! ipad-key 0 inner-input 0 64)]
               [_ (bytevector-copy! msg 0 inner-input 64 msg-len)]
               [inner-hash (sha256Bv inner-input)]
               ;; Step 4: outer hash = SHA256(opad-key || inner-hash)
               [outer-input (make-bytevector 96)] ;; 64 + 32
               [_ (bytevector-copy! opad-key 0 outer-input 0 64)]
               [_ (bytevector-copy! inner-hash 0 outer-input 64 32)])
          (sha256Bv outer-input)))))

  ;; ── Byte-level utilities (parallel to SHA3.ss) ─────────────────────────

  ;; String → ByteArray
  (define stringToUtf8Bv
    (lambda (ps)
      (string->utf8 (pstring->string ps))))

  ;; ByteArray → String (hex)
  (define bytesToHex
    (lambda (bv)
      (string->pstring (bv-to-hex bv))))

  ;; String (hex) → ByteArray
  (define hexToByteArray
    (lambda (ps)
      (bv-from-hex (pstring->string ps))))

  ;; Array Int → ByteArray
  (define arrayToByteArray
    (lambda (fv)
      (bv-from-flexvector fv)))

  ;; ByteArray → Array Int
  (define byteArrayToArray
    (lambda (bv)
      (bv-to-flexvector bv)))

  ;; ByteArray → ByteArray → Boolean
  (define eqByteArray
    (lambda (a)
      (lambda (b)
        (bytevector=? a b))))

  ;; ByteArray → Int
  (define byteArrayLength
    (lambda (bv)
      (bytevector-length bv)))

) ;; end library