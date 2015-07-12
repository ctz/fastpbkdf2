/*
 * fast-pbkdf2 - Optimal PBKDF2-HMAC calculation
 * Written in 2015 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
 
#include "fastpbkdf2.h"

#include <assert.h>
#include <string.h>

#include <openssl/sha.h>

/* --- Common useful things --- */
#define MIN(a, b) ((a) > (b)) ? (b) : (a)

static inline void xor(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t n)
{
  for (size_t i = 0; i < n; i++)
    out[i] = a[i] ^ b[i];
}

static inline void write32_be(uint32_t n, uint8_t out[4])
{
  out[0] = (n >> 24) & 0xff;
  out[1] = (n >> 16) & 0xff;
  out[2] = (n >> 8) & 0xff;
  out[3] = n & 0xff;
}

/* Internal function/type names for hash-specific things. */
#define HMAC_CTX(_name) HMAC_ ## _name ## _ctx
#define HMAC_INIT(_name) HMAC_ ## _name ## _init
#define HMAC_UPDATE(_name) HMAC_ ## _name ## _update
#define HMAC_FINAL(_name) HMAC_ ## _name ## _final

#define PBKDF2_F(_name) pbkdf2_f_ ## _name
#define PBKDF2(_name) pbkdf2_ ## _name

/* This macro expands to decls for the whole implementation for a given
 * hash function.  Arguments are:
 *
 * _name like 'sha1', added to symbol names
 * _blocksz block size, in bytes
 * _hashsz digest output, in bytes
 * _ctx hash context type
 * _init hash context initialisation function, taking args (_ctx *c)
 * _update hash context update function, taking args (_ctx *c, const void *data, size_t ndata)
 * _final hash context finish function, taking args (void *out, _ctx *c)
 *
 * The resulting function is named PBKDF2(_name).
 */
#define DECL_PBKDF2(_name, _blocksz, _hashsz, _ctx, _init, _update, _final)   \
  typedef struct {                                                            \
    _ctx inner;                                                               \
    _ctx outer;                                                               \
  } HMAC_CTX(_name);                                                          \
                                                                              \
  static inline void HMAC_INIT(_name)(HMAC_CTX(_name) *ctx,                   \
                                      const uint8_t *key, size_t nkey)        \
  {                                                                           \
    /* Prepare key: */                                                        \
    uint8_t k[_blocksz];                                                      \
                                                                              \
    /* Shorten long keys. */                                                  \
    if (nkey > _blocksz)                                                      \
    {                                                                         \
      _init(&ctx->inner);                                                     \
      _update(&ctx->inner, key, nkey);                                        \
      _final(k, &ctx->inner);                                                 \
                                                                              \
      key = k;                                                                \
      nkey = _hashsz;                                                         \
    }                                                                         \
                                                                              \
    /* Standard doesn't cover case where blocksz < hashsz. */                 \
    assert(nkey <= _blocksz);                                                 \
                                                                              \
    /* Right zero-pad short keys. */                                          \
    if (k != key)                                                             \
      memcpy(k, key, nkey);                                                   \
    if (_blocksz > nkey)                                                      \
      memset(k + nkey, 0, _blocksz - nkey);                                   \
                                                                              \
    /* Start inner hash computation */                                        \
    uint8_t blk_inner[_blocksz];                                              \
    uint8_t blk_outer[_blocksz];                                              \
                                                                              \
    for (size_t i = 0; i < _blocksz; i++)                                     \
    {                                                                         \
      blk_inner[i] = 0x36 ^ k[i];                                             \
      blk_outer[i] = 0x5c ^ k[i];                                             \
    }                                                                         \
                                                                              \
    _init(&ctx->inner);                                                       \
    _update(&ctx->inner, blk_inner, sizeof blk_inner);                        \
                                                                              \
    /* And outer. */                                                          \
    _init(&ctx->outer);                                                       \
    _update(&ctx->outer, blk_outer, sizeof blk_outer);                        \
  }                                                                           \
                                                                              \
  static inline void HMAC_UPDATE(_name)(HMAC_CTX(_name) *ctx,                 \
                                        const void *data, size_t ndata)       \
  {                                                                           \
    _update(&ctx->inner, data, ndata);                                        \
  }                                                                           \
                                                                              \
  static inline void HMAC_FINAL(_name)(HMAC_CTX(_name) *ctx,                  \
                                       uint8_t out[_hashsz])                  \
  {                                                                           \
    _final(out, &ctx->inner);                                                 \
    _update(&ctx->outer, out, _hashsz);                                       \
    _final(out, &ctx->outer);                                                 \
  }                                                                           \
                                                                              \
                                                                              \
  /* --- PBKDF2 --- */                                                        \
  static inline void PBKDF2_F(_name)(const HMAC_CTX(_name) *startctx,         \
                              uint32_t counter,                               \
                              const uint8_t *salt, size_t nsalt,              \
                              uint32_t iterations,                            \
                              uint8_t *out)                                   \
  {                                                                           \
    uint8_t U[_hashsz];                                                       \
                                                                              \
    uint8_t countbuf[4];                                                      \
    write32_be(counter, countbuf);                                            \
                                                                              \
    /* First iteration:                                                       \
     *   U_1 = PRF(P, S || INT_32_BE(i))                                      \
     */                                                                       \
    HMAC_CTX(_name) ctx = *startctx;                                          \
    HMAC_UPDATE(_name)(&ctx, salt, nsalt);                                    \
    HMAC_UPDATE(_name)(&ctx, countbuf, sizeof countbuf);                      \
    HMAC_FINAL(_name)(&ctx, U);                                               \
    memcpy(out, U, _hashsz);                                                  \
                                                                              \
    /* Subsequent iterations:                                                 \
     *   U_c = PRF(P, U_{c-1})                                                \
     */                                                                       \
    for (uint32_t i = 1; i < iterations; i++)                                 \
    {                                                                         \
      ctx = *startctx;                                                        \
      HMAC_UPDATE(_name)(&ctx, U, _hashsz);                                   \
      HMAC_FINAL(_name)(&ctx, U);                                             \
      xor(out, out, U, _hashsz);                                              \
    }                                                                         \
  }                                                                           \
                                                                              \
  static inline void PBKDF2(_name)(const uint8_t *pw, size_t npw,             \
                     const uint8_t *salt, size_t nsalt,                       \
                     uint32_t iterations,                                     \
                     uint8_t *out, size_t nout)                               \
  {                                                                           \
    uint32_t counter = 1;                                                     \
    uint8_t block[_hashsz];                                                   \
                                                                              \
    assert(iterations);                                                       \
    assert(out && nout);                                                      \
                                                                              \
    /* Starting point for inner loop. */                                      \
    HMAC_CTX(_name) ctx;                                                      \
    HMAC_INIT(_name)(&ctx, pw, npw);                                          \
                                                                              \
    while (nout)                                                              \
    {                                                                         \
      PBKDF2_F(_name)(&ctx, counter, salt, nsalt, iterations, block);         \
                                                                              \
      size_t taken = MIN(nout, _hashsz);                                      \
      memcpy(out, block, taken);                                              \
      out += taken;                                                           \
      nout -= taken;                                                          \
      counter++;                                                              \
    }                                                                         \
  }

DECL_PBKDF2(sha1,
            SHA_CBLOCK, SHA_DIGEST_LENGTH,
            SHA_CTX,
            SHA1_Init, SHA1_Update, SHA1_Final)

DECL_PBKDF2(sha256,
            SHA256_CBLOCK, SHA256_DIGEST_LENGTH,
            SHA256_CTX,
            SHA256_Init, SHA256_Update, SHA256_Final)

DECL_PBKDF2(sha512,
            SHA512_CBLOCK, SHA512_DIGEST_LENGTH,
            SHA512_CTX,
            SHA512_Init, SHA512_Update, SHA512_Final)

void fastpbkdf2_hmac_sha1(const uint8_t *pw, size_t npw,
                          const uint8_t *salt, size_t nsalt,
                          uint32_t iterations,
                          uint8_t *out, size_t nout)
{
  PBKDF2(sha1)(pw, npw, salt, nsalt, iterations, out, nout);
}

void fastpbkdf2_hmac_sha256(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout)
{
  PBKDF2(sha256)(pw, npw, salt, nsalt, iterations, out, nout);
}

void fastpbkdf2_hmac_sha512(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout)
{
  PBKDF2(sha512)(pw, npw, salt, nsalt, iterations, out, nout);
}

