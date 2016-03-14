/*
 * cifra - embedded cryptography library
 * Written in 2014 by Joseph Birr-Pixton <jpixton@gmail.com>
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

#include <string.h>

/* --- SHA256 --- */
#define CF_SHA256_BLOCKSZ 64
#define CF_SHA256_HASHSZ 32

typedef struct
{
  uint32_t H[8];
  uint8_t partial[CF_SHA256_BLOCKSZ];
  uint32_t blocks;
  size_t npartial;
} cf_sha256_context;

typedef uint32_t cf_sha256_block[16];

static const uint32_t K[64] = {
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
};

static void cf_sha256_init(cf_sha256_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = 0x6a09e667;
  ctx->H[1] = 0xbb67ae85;
  ctx->H[2] = 0x3c6ef372;
  ctx->H[3] = 0xa54ff53a;
  ctx->H[4] = 0x510e527f;
  ctx->H[5] = 0x9b05688c;
  ctx->H[6] = 0x1f83d9ab;
  ctx->H[7] = 0x5be0cd19;
}

static void sha256_raw_transform(const uint32_t state_in[8],
                                 uint32_t state_out[8],
                                 const cf_sha256_block inp)
{
  /* This is a 16-word window into the whole W array. */
  uint32_t W[16];

  uint32_t a = state_in[0],
           b = state_in[1],
           c = state_in[2],
           d = state_in[3],
           e = state_in[4],
           f = state_in[5],
           g = state_in[6],
           h = state_in[7],
           Wt;
           
# define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
# define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
# define BSIG0(x) (rotr32((x), 2) ^ rotr32((x), 13) ^ rotr32((x), 22))
# define BSIG1(x) (rotr32((x), 6) ^ rotr32((x), 11) ^ rotr32((x), 25))
# define SSIG0(x) (rotr32((x), 7) ^ rotr32((x), 18) ^ ((x) >> 3))
# define SSIG1(x) (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))

  for (size_t t = 0; t < 64; t++)
  {
    /* For W[0..16] we process the input into W.
     * For W[16..64] we compute the next W value:
     *
     * W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
     *
     * But all W indices are reduced mod 16 into our window.
     */
    if (t < 16)
    {
      W[t] = Wt = inp[t];
    } else {
      Wt = SSIG1(W[(t - 2) % 16]) +
           W[(t - 7) % 16] +
           SSIG0(W[(t - 15) % 16]) +
           W[(t - 16) % 16];
      W[t % 16] = Wt;
    }

    uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K[t] + Wt;
    uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  state_out[0] = state_in[0] + a;
  state_out[1] = state_in[1] + b;
  state_out[2] = state_in[2] + c;
  state_out[3] = state_in[3] + d;
  state_out[4] = state_in[4] + e;
  state_out[5] = state_in[5] + f;
  state_out[6] = state_in[6] + g;
  state_out[7] = state_in[7] + h;
  
#undef CH
#undef MAJ
#undef BSIG0
#undef BSIG1
#undef SSIG0
#undef SSIG1
}

static void sha256_convert_input(cf_sha256_block inp32, const uint8_t inp[CF_SHA256_BLOCKSZ])
{
  for (int i = 0; i < 64; i += 4)
    inp32[i >> 2] = read32_be(inp + i);
}

static void sha256_update_block(void *vctx, const uint8_t *inp)
{
  cf_sha256_context *ctx = vctx;
  cf_sha256_block inp32;
  sha256_convert_input(inp32, inp);
  sha256_raw_transform(ctx->H, ctx->H, inp32);
  ctx->blocks += 1;
}

static void cf_sha256_update(cf_sha256_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          data, nbytes,
                          sha256_update_block, ctx);
}

static void sha256_convert_output(const uint32_t H[8],
                                  uint8_t hash[CF_SHA256_HASHSZ])
{
  write32_be(H[0], hash + 0);
  write32_be(H[1], hash + 4);
  write32_be(H[2], hash + 8);
  write32_be(H[3], hash + 12);
  write32_be(H[4], hash + 16);
  write32_be(H[5], hash + 20);
  write32_be(H[6], hash + 24);
  write32_be(H[7], hash + 28);
}

static void sha256_xor(uint32_t *restrict out, const uint32_t *restrict in)
{
  out[0] ^= in[0];
  out[1] ^= in[1];
  out[2] ^= in[2];
  out[3] ^= in[3];
  out[4] ^= in[4];
  out[5] ^= in[5];
  out[6] ^= in[6];
  out[7] ^= in[7];
}

void cf_sha256_final(cf_sha256_context *ctx, uint8_t hash[CF_SHA256_HASHSZ])
{
  uint32_t digested_bytes = ctx->blocks;
  digested_bytes = digested_bytes * CF_SHA256_BLOCKSZ + ctx->npartial;
  uint32_t digested_bits = digested_bytes * 8;

  size_t padbytes = CF_SHA256_BLOCKSZ - ((digested_bytes + 4) % CF_SHA256_BLOCKSZ);

  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                       0x80, 0x00, 0x00, padbytes,
                       sha256_update_block, ctx);

  /* Now hash length. */
  uint8_t buf[4];
  write32_be(digested_bits, buf);
  cf_sha256_update(ctx, buf, 4);
  assert(ctx->npartial == 0);

  sha256_convert_output(ctx->H, hash);
}

#define _name       sha256
#define _blocksz    CF_SHA256_BLOCKSZ
#define _hashsz     CF_SHA256_HASHSZ
#define _ctx        cf_sha256_context
#define _blocktype  cf_sha256_block
#define _cvt_input  sha256_convert_input
#define _cvt_output sha256_convert_output
#define _init       cf_sha256_init
#define _update     cf_sha256_update
#define _final      cf_sha256_final
#define _transform  sha256_raw_transform
#define _xor        sha256_xor

#include "core.inc.c"

#undef _name
#undef _blocksz
#undef _hashsz
#undef _ctx
#undef _blocktype
#undef _cvt_input
#undef _cvt_output
#undef _init
#undef _update
#undef _final
#undef _transform
#undef _xor

