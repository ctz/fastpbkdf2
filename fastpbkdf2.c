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
#define rotl(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t read32_be(const uint8_t x[4])
{
#if __GNUC__ >= 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap32(*(uint32_t *)(x));
#else
  uint32_t r = (uint32_t)(x[0]) << 24 |
               (uint32_t)(x[1]) << 16 |
               (uint32_t)(x[2]) << 8 |
               (uint32_t)(x[3]);
  return r;
#endif
}

static inline void write32_be(uint32_t n, uint8_t out[4])
{
#if __GNUC__ >= 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  *(uint32_t *)(out) = __builtin_bswap32(n);
#else
  out[0] = (n >> 24) & 0xff;
  out[1] = (n >> 16) & 0xff;
  out[2] = (n >> 8) & 0xff;
  out[3] = n & 0xff;
#endif
}

static inline void write64_be(uint64_t n, uint8_t out[8])
{
#if __GNUC__ >= 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  *(uint64_t *)(out) = __builtin_bswap64(n);
#else
  write32_be((n >> 32) & 0xffffffff, out);
  write32_be(n & 0xffffffff, out + 4);
#endif
}

typedef void (*blockfn)(void *ctx, const uint8_t *data);

static void blockwise(void *ctx, blockfn block,
                      uint8_t *partial, uint32_t *npartial, uint32_t nblock,
                      const uint8_t *bufin, size_t nbytes)
{
  /* If we have partial data, copy in to buffer. */
  if (*npartial && nbytes)
  {
    uint32_t space = nblock - *npartial;
    uint32_t taken = MIN(space, nbytes);

    memcpy(partial + *npartial, bufin, taken);

    bufin += taken;
    nbytes -= taken;
    *npartial += taken;

    /* If that gives us a full block, process it. */
    if (*npartial == nblock)
    {
      block(ctx, partial);
      *npartial = 0;
    }
  }

  /* now nbytes < nblock or *npartial == 0. */

  /* If we have a full block of data, process it directly. */
  while (nbytes >= nblock)
  {
    /* Partial buffer must be empty, or we're ignoring extant data */
    assert(*npartial == 0);

    block(ctx, bufin);
    bufin += nblock;
    nbytes -= nblock;
  }

  /* Finally, if we have remaining data, buffer it. */
  while (nbytes)
  {
    uint32_t space = nblock - *npartial;
    uint32_t taken = MIN(space, nbytes);

    memcpy(partial + *npartial, bufin, taken);

    bufin += taken;
    nbytes -= taken;
    *npartial += taken;

    /* If we started with *npartial, we must have copied it
     * in first. */
    assert(*npartial < nblock);
  }
}

/* --- SHA1 --- */
#define SHA1_BLOCK 64
#define SHA1_DIGEST 20

typedef struct
{
  uint32_t h[5];
  uint8_t buf[64];
  uint32_t used;
  uint32_t blocks;
} sha1;

typedef uint32_t sha1_block[16];

static void sha1_init(sha1 *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0xc3d2e1f0;
}

static void sha1_raw_transform(uint32_t state[5], const sha1_block inp)
{
  uint32_t a = state[0],
           b = state[1],
           c = state[2],
           d = state[3],
           e = state[4];

  uint32_t w[80];

  for (int i = 0; i < 16; i++)
    w[i] = inp[i];
  for (int i = 16; i < 80; i++)
    w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

#define R0(v, w, x, y, z, B) z += ((w & (x ^ y)) ^ y) + B + 0x5a827999 + rotl(v, 5); w = rotl(w, 30)
#define R1(v, w, x, y, z, B) z += (w ^ x ^ y) + B + 0x6ed9eba1 + rotl(v, 5); w = rotl(w, 30)
#define R2(v, w, x, y, z, B) z += (((w | x) & y) | (w & x)) + B + 0x8f1bbcdc + rotl(v, 5); w = rotl(w, 30)
#define R3(v, w, x, y, z, B) z += (w ^ x ^ y) + B + 0xca62c1d6 + rotl(v, 5); w = rotl(w, 30)

  R0(a, b, c, d, e, w[0]);
  R0(e, a, b, c, d, w[1]);
  R0(d, e, a, b, c, w[2]);
  R0(c, d, e, a, b, w[3]);
  R0(b, c, d, e, a, w[4]);
  R0(a, b, c, d, e, w[5]);
  R0(e, a, b, c, d, w[6]);
  R0(d, e, a, b, c, w[7]);
  R0(c, d, e, a, b, w[8]);
  R0(b, c, d, e, a, w[9]);
  R0(a, b, c, d, e, w[10]);
  R0(e, a, b, c, d, w[11]);
  R0(d, e, a, b, c, w[12]);
  R0(c, d, e, a, b, w[13]);
  R0(b, c, d, e, a, w[14]);
  R0(a, b, c, d, e, w[15]);
  R0(e, a, b, c, d, w[16]);
  R0(d, e, a, b, c, w[17]);
  R0(c, d, e, a, b, w[18]);
  R0(b, c, d, e, a, w[19]);
  R1(a, b, c, d, e, w[20]);
  R1(e, a, b, c, d, w[21]);
  R1(d, e, a, b, c, w[22]);
  R1(c, d, e, a, b, w[23]);
  R1(b, c, d, e, a, w[24]);
  R1(a, b, c, d, e, w[25]);
  R1(e, a, b, c, d, w[26]);
  R1(d, e, a, b, c, w[27]);
  R1(c, d, e, a, b, w[28]);
  R1(b, c, d, e, a, w[29]);
  R1(a, b, c, d, e, w[30]);
  R1(e, a, b, c, d, w[31]);
  R1(d, e, a, b, c, w[32]);
  R1(c, d, e, a, b, w[33]);
  R1(b, c, d, e, a, w[34]);
  R1(a, b, c, d, e, w[35]);
  R1(e, a, b, c, d, w[36]);
  R1(d, e, a, b, c, w[37]);
  R1(c, d, e, a, b, w[38]);
  R1(b, c, d, e, a, w[39]);
  R2(a, b, c, d, e, w[40]);
  R2(e, a, b, c, d, w[41]);
  R2(d, e, a, b, c, w[42]);
  R2(c, d, e, a, b, w[43]);
  R2(b, c, d, e, a, w[44]);
  R2(a, b, c, d, e, w[45]);
  R2(e, a, b, c, d, w[46]);
  R2(d, e, a, b, c, w[47]);
  R2(c, d, e, a, b, w[48]);
  R2(b, c, d, e, a, w[49]);
  R2(a, b, c, d, e, w[50]);
  R2(e, a, b, c, d, w[51]);
  R2(d, e, a, b, c, w[52]);
  R2(c, d, e, a, b, w[53]);
  R2(b, c, d, e, a, w[54]);
  R2(a, b, c, d, e, w[55]);
  R2(e, a, b, c, d, w[56]);
  R2(d, e, a, b, c, w[57]);
  R2(c, d, e, a, b, w[58]);
  R2(b, c, d, e, a, w[59]);
  R3(a, b, c, d, e, w[60]);
  R3(e, a, b, c, d, w[61]);
  R3(d, e, a, b, c, w[62]);
  R3(c, d, e, a, b, w[63]);
  R3(b, c, d, e, a, w[64]);
  R3(a, b, c, d, e, w[65]);
  R3(e, a, b, c, d, w[66]);
  R3(d, e, a, b, c, w[67]);
  R3(c, d, e, a, b, w[68]);
  R3(b, c, d, e, a, w[69]);
  R3(a, b, c, d, e, w[70]);
  R3(e, a, b, c, d, w[71]);
  R3(d, e, a, b, c, w[72]);
  R3(c, d, e, a, b, w[73]);
  R3(b, c, d, e, a, w[74]);
  R3(a, b, c, d, e, w[75]);
  R3(e, a, b, c, d, w[76]);
  R3(d, e, a, b, c, w[77]);
  R3(c, d, e, a, b, w[78]);
  R3(b, c, d, e, a, w[79]);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;

#undef R0
#undef R1
#undef R2
#undef R3
}

static void sha1_convert(sha1_block inp32, const uint8_t inp[64])
{
  for (int i = 0; i < 64; i += 4)
    inp32[i >> 2] = read32_be(inp + i);
}

static void sha1_transform(void *vctx, const uint8_t inp[64])
{
  sha1 *ctx = vctx;
  uint32_t inp32[16];
  sha1_convert(inp32, inp);
  sha1_raw_transform(ctx->h, inp32);
  ctx->blocks += 1;
}

static inline void sha1_extract(sha1 *restrict ctx, uint8_t *restrict out)
{
  write32_be(ctx->h[0], out);
  write32_be(ctx->h[1], out + 4);
  write32_be(ctx->h[2], out + 8);
  write32_be(ctx->h[3], out + 12);
  write32_be(ctx->h[4], out + 16);
}

static inline void sha1_cpy(sha1 *restrict out, const sha1 *restrict in)
{
  out->h[0] = in->h[0];
  out->h[1] = in->h[1];
  out->h[2] = in->h[2];
  out->h[3] = in->h[3];
  out->h[4] = in->h[4];
}

static inline void sha1_xor(sha1 *restrict out, const sha1 *restrict in)
{
  out->h[0] ^= in->h[0];
  out->h[1] ^= in->h[1];
  out->h[2] ^= in->h[2];
  out->h[3] ^= in->h[3];
  out->h[4] ^= in->h[4];
}

static void sha1_update(sha1 *ctx, const uint8_t *bytes, size_t nbytes)
{
  blockwise(ctx, sha1_transform,
            ctx->buf, &ctx->used, SHA1_BLOCK,
            bytes, nbytes);
}

static void sha1_final(uint8_t out[20], sha1 *ctx)
{
  uint32_t bytes = ctx->blocks * SHA1_BLOCK + ctx->used;
  uint32_t bits = bytes * 8;
  uint32_t zeroes = SHA1_BLOCK - ((bytes + 1 + 4) % SHA1_BLOCK);

  uint8_t buf[4] = { 0x80, 0x00 };

  /* Hash padding and zeroes */
  sha1_update(ctx, &buf[0], 1);
  while (zeroes--)
    sha1_update(ctx, &buf[1], 1);

  /* Hash length */
  write32_be(bits, buf);
  sha1_update(ctx, buf, 4);
  assert(ctx->used == 0);

  sha1_extract(ctx, out);
}

/* --- Optional OpenMP parallelisation of consecutive blocks --- */
#ifdef WITH_OPENMP
# define OPENMP_PARALLEL_FOR _Pragma("omp parallel for")
#else
# define OPENMP_PARALLEL_FOR
#endif

/* Prepare block (of blocksz bytes) to contain md padding denoting a msg-size
 * message (in bytes).  block has a prefix of used bytes.
 *
 * Message length is expressed in 32 bits (so suitable for sha1, sha256, sha512). */
static inline void md_pad(uint8_t *block, size_t blocksz, size_t used, size_t msg)
{
  memset(block + used, 0, blocksz - used - 4);
  block[used] = 0x80;
  block += blocksz - 4;
  write32_be(msg * 8, block);
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
 * _ctx incremental hash context type
 * _blocktype
 * _init hash context initialisation function
 *    args: (_ctx *c)
 * _update hash context update function
 *    args: (_ctx *c, const void *data, size_t ndata)
 * _final hash context finish function
 *    args: (void *out, _ctx *c)
 * _xform hash context raw block update function
 *    args: (_ctx *c, const void *data)
 * _xcpy hash context raw copy function (only need copy hash state)
 *    args: (_ctx * restrict out, const _ctx *restrict in)
 * _xtract hash context state extraction
 *    args: args (_ctx *restrict c, uint8_t *restrict out)
 * _xxor hash context xor function (only need xor hash state)
 *    args: (_ctx *restrict out, const _ctx *restrict in)
 *
 * The resulting function is named PBKDF2(_name).
 */
#define DECL_PBKDF2(_name, _blocksz, _hashsz, _ctx, _blocktype,               \
                    _init, _update, _xform, _final, _xcpy, _xtract, _xxor)    \
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
                                     uint32_t counter,                        \
                                     const uint8_t *salt, size_t nsalt,       \
                                     uint32_t iterations,                     \
                                     uint8_t *out)                            \
  {                                                                           \
    uint8_t countbuf[4];                                                      \
    write32_be(counter, countbuf);                                            \
                                                                              \
    /* Prepare loop-invariant padding block. */                               \
    uint8_t Ubytes[_blocksz];                                                 \
    md_pad(Ubytes, _blocksz, _hashsz, _blocksz + _hashsz);                    \
                                                                              \
    /* First iteration:                                                       \
     *   U_1 = PRF(P, S || INT_32_BE(i))                                      \
     */                                                                       \
    HMAC_CTX(_name) ctx = *startctx;                                          \
    HMAC_UPDATE(_name)(&ctx, salt, nsalt);                                    \
    HMAC_UPDATE(_name)(&ctx, countbuf, sizeof countbuf);                      \
    HMAC_FINAL(_name)(&ctx, Ubytes);                                          \
    _ctx result = ctx.outer;                                                  \
                                                                              \
    _blocktype Ublock;                                                        \
    sha1_convert(Ublock, Ubytes);                                             \
                                                                              \
    /* Subsequent iterations:                                                 \
     *   U_c = PRF(P, U_{c-1})                                                \
     */                                                                       \
    for (uint32_t i = 1; i < iterations; i++)                                 \
    {                                                                         \
      /* Complete inner hash with previous U */                               \
      _xcpy(&ctx.inner, &startctx->inner);                                    \
      _xform(ctx.inner.h, Ublock);                                            \
      /* Complete outer hash with inner output */                             \
      _xcpy(&ctx.outer, &startctx->outer);                                    \
      _xform(ctx.outer.h, Ublock);                                            \
      _xxor(&result, &ctx.outer);                                             \
    }                                                                         \
                                                                              \
    /* Reform result into output buffer. */                                   \
    _xtract(&result, out);                                                    \
  }                                                                           \
                                                                              \
  static inline void PBKDF2(_name)(const uint8_t *pw, size_t npw,             \
                     const uint8_t *salt, size_t nsalt,                       \
                     uint32_t iterations,                                     \
                     uint8_t *out, size_t nout)                               \
  {                                                                           \
    assert(iterations);                                                       \
    assert(out && nout);                                                      \
                                                                              \
    /* Starting point for inner loop. */                                      \
    HMAC_CTX(_name) ctx;                                                      \
    HMAC_INIT(_name)(&ctx, pw, npw);                                          \
                                                                              \
    /* How many blocks do we need? */                                         \
    uint32_t blocks_needed = (nout + _hashsz - 1) / _hashsz;                  \
                                                                              \
    OPENMP_PARALLEL_FOR                                                       \
    for (uint32_t counter = 1; counter <= blocks_needed; counter++)           \
    {                                                                         \
      uint8_t block[_hashsz];                                                 \
      PBKDF2_F(_name)(&ctx, counter, salt, nsalt, iterations, block);         \
                                                                              \
      size_t offset = (counter - 1) * _hashsz;                                \
      size_t taken = MIN(nout - offset, _hashsz);                             \
      memcpy(out + offset, block, taken);                                     \
    }                                                                         \
  }

DECL_PBKDF2(sha1,
            SHA1_BLOCK,
            SHA1_DIGEST,
            sha1,
            sha1_block,
            sha1_init,
            sha1_update,
            sha1_raw_transform,
            sha1_final,
            sha1_cpy,
            sha1_extract,
            sha1_xor)

void fastpbkdf2_hmac_sha1(const uint8_t *pw, size_t npw,
                          const uint8_t *salt, size_t nsalt,
                          uint32_t iterations,
                          uint8_t *out, size_t nout)
{
  PBKDF2(sha1)(pw, npw, salt, nsalt, iterations, out, nout);
}

#if 0
static inline void sha256_extract(SHA256_CTX *restrict ctx, uint8_t *restrict out)
{
  write32_be(ctx->h[0], out);
  write32_be(ctx->h[1], out + 4);
  write32_be(ctx->h[2], out + 8);
  write32_be(ctx->h[3], out + 12);
  write32_be(ctx->h[4], out + 16);
  write32_be(ctx->h[5], out + 20);
  write32_be(ctx->h[6], out + 24);
  write32_be(ctx->h[7], out + 28);
}

static inline void sha256_cpy(SHA256_CTX *restrict out, const SHA256_CTX *restrict in)
{
  out->h[0] = in->h[0];
  out->h[1] = in->h[1];
  out->h[2] = in->h[2];
  out->h[3] = in->h[3];
  out->h[4] = in->h[4];
  out->h[5] = in->h[5];
  out->h[6] = in->h[6];
  out->h[7] = in->h[7];
}

static inline void sha256_xor(SHA256_CTX *restrict out, const SHA256_CTX *restrict in)
{
  out->h[0] ^= in->h[0];
  out->h[1] ^= in->h[1];
  out->h[2] ^= in->h[2];
  out->h[3] ^= in->h[3];
  out->h[4] ^= in->h[4];
  out->h[5] ^= in->h[5];
  out->h[6] ^= in->h[6];
  out->h[7] ^= in->h[7];
}

DECL_PBKDF2(sha256,
            SHA256_CBLOCK,
            SHA256_DIGEST_LENGTH,
            SHA256_CTX,
            SHA256_Init,
            SHA256_Update,
            SHA256_Transform,
            SHA256_Final,
            sha256_cpy,
            sha256_extract,
            sha256_xor)

static inline void sha512_extract(SHA512_CTX *restrict ctx, uint8_t *restrict out)
{
  write64_be(ctx->h[0], out);
  write64_be(ctx->h[1], out + 8);
  write64_be(ctx->h[2], out + 16);
  write64_be(ctx->h[3], out + 24);
  write64_be(ctx->h[4], out + 32);
  write64_be(ctx->h[5], out + 40);
  write64_be(ctx->h[6], out + 48);
  write64_be(ctx->h[7], out + 56);
}

static inline void sha512_cpy(SHA512_CTX *restrict out, const SHA512_CTX *restrict in)
{
  out->h[0] = in->h[0];
  out->h[1] = in->h[1];
  out->h[2] = in->h[2];
  out->h[3] = in->h[3];
  out->h[4] = in->h[4];
  out->h[5] = in->h[5];
  out->h[6] = in->h[6];
  out->h[7] = in->h[7];
}

static inline void sha512_xor(SHA512_CTX *restrict out, const SHA512_CTX *restrict in)
{
  out->h[0] ^= in->h[0];
  out->h[1] ^= in->h[1];
  out->h[2] ^= in->h[2];
  out->h[3] ^= in->h[3];
  out->h[4] ^= in->h[4];
  out->h[5] ^= in->h[5];
  out->h[6] ^= in->h[6];
  out->h[7] ^= in->h[7];
}

DECL_PBKDF2(sha512,
            SHA512_CBLOCK,
            SHA512_DIGEST_LENGTH,
            SHA512_CTX,
            SHA512_Init,
            SHA512_Update,
            SHA512_Transform,
            SHA512_Final,
            sha512_cpy,
            sha512_extract,
            sha512_xor)


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
#endif

