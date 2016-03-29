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

#if defined(__GNUC__) && defined(__x86_64__)
extern void fastpbkdf2_sha256_sse4(const uint32_t state_in[8],
                                   uint32_t state_out[8],
                                   const cf_sha256_block inp);
extern void fastpbkdf2_sha256_avx1(const uint32_t state_in[8],
                                   uint32_t state_out[8],
                                   const cf_sha256_block inp);
# define sha256_raw_transform fastpbkdf2_sha256_sse4
#else
static void sha256_raw_transform(const uint32_t state_in[8],
                                 uint32_t state_out[8],
                                 const cf_sha256_block inp)
{
  uint32_t W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, Wa,
           Wb, Wc, Wd, We, Wf;

  uint32_t a = state_in[0],
           b = state_in[1],
           c = state_in[2],
           d = state_in[3],
           e = state_in[4],
           f = state_in[5],
           g = state_in[6],
           h = state_in[7];
           
# define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
# define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
# define BSIG0(x) (rotr32((x), 2) ^ rotr32((x), 13) ^ rotr32((x), 22))
# define BSIG1(x) (rotr32((x), 6) ^ rotr32((x), 11) ^ rotr32((x), 25))
# define SSIG0(x) (rotr32((x), 7) ^ rotr32((x), 18) ^ ((x) >> 3))
# define SSIG1(x) (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))

# define W(Wn2, Wn7, Wn15, Wn16) SSIG1(Wn2) + Wn7 + SSIG0(Wn15) + Wn16

# define Winit() \
  W0 = inp[0];  W1 = inp[1];  W2 = inp[2];  W3 = inp[3];  \
  W4 = inp[4];  W5 = inp[5];  W6 = inp[6];  W7 = inp[7];  \
  W8 = inp[8];  W9 = inp[9];  Wa = inp[10]; Wb = inp[11]; \
  Wc = inp[12]; Wd = inp[13]; We = inp[14]; Wf = inp[15]

# define Wstep() \
  W0 = W(We, W9, W1, W0);    W1 = W(Wf, Wa, W2, W1);  \
  W2 = W(W0, Wb, W3, W2);    W3 = W(W1, Wc, W4, W3);  \
  W4 = W(W2, Wd, W5, W4);    W5 = W(W3, We, W6, W5);  \
  W6 = W(W4, Wf, W7, W6);    W7 = W(W5, W0, W8, W7);  \
  W8 = W(W6, W1, W9, W8);    W9 = W(W7, W2, Wa, W9);  \
  Wa = W(W8, W3, Wb, Wa);    Wb = W(W9, W4, Wc, Wb);  \
  Wc = W(Wa, W5, Wd, Wc);    Wd = W(Wb, W6, We, Wd);  \
  We = W(Wc, W7, Wf, We);    Wf = W(Wd, W8, W0, Wf)

# define R(a, b, c, d, e, f, g, h, W, K)                           \
      do {                                                         \
        uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K + W;          \
        uint32_t T2 = BSIG0(a) + MAJ(a, b, c);                     \
        d += T1;                                                   \
        h = T1 + T2;                                               \
      } while (0)
  
  /* For best locality/reg allocation, compute 16 terms
   * of W at once. */
  Winit();
  R(a, b, c, d, e, f, g, h, W0, 0x428a2f98);
  R(h, a, b, c, d, e, f, g, W1, 0x71374491);
  R(g, h, a, b, c, d, e, f, W2, 0xb5c0fbcf);
  R(f, g, h, a, b, c, d, e, W3, 0xe9b5dba5);
  R(e, f, g, h, a, b, c, d, W4, 0x3956c25b);
  R(d, e, f, g, h, a, b, c, W5, 0x59f111f1);
  R(c, d, e, f, g, h, a, b, W6, 0x923f82a4);
  R(b, c, d, e, f, g, h, a, W7, 0xab1c5ed5);
  R(a, b, c, d, e, f, g, h, W8, 0xd807aa98);
  R(h, a, b, c, d, e, f, g, W9, 0x12835b01);
  R(g, h, a, b, c, d, e, f, Wa, 0x243185be);
  R(f, g, h, a, b, c, d, e, Wb, 0x550c7dc3);
  R(e, f, g, h, a, b, c, d, Wc, 0x72be5d74);
  R(d, e, f, g, h, a, b, c, Wd, 0x80deb1fe);
  R(c, d, e, f, g, h, a, b, We, 0x9bdc06a7);
  R(b, c, d, e, f, g, h, a, Wf, 0xc19bf174);
 
  Wstep();
  R(a, b, c, d, e, f, g, h, W0, 0xe49b69c1);
  R(h, a, b, c, d, e, f, g, W1, 0xefbe4786);
  R(g, h, a, b, c, d, e, f, W2, 0x0fc19dc6);
  R(f, g, h, a, b, c, d, e, W3, 0x240ca1cc);
  R(e, f, g, h, a, b, c, d, W4, 0x2de92c6f);
  R(d, e, f, g, h, a, b, c, W5, 0x4a7484aa);
  R(c, d, e, f, g, h, a, b, W6, 0x5cb0a9dc);
  R(b, c, d, e, f, g, h, a, W7, 0x76f988da);
  R(a, b, c, d, e, f, g, h, W8, 0x983e5152);
  R(h, a, b, c, d, e, f, g, W9, 0xa831c66d);
  R(g, h, a, b, c, d, e, f, Wa, 0xb00327c8);
  R(f, g, h, a, b, c, d, e, Wb, 0xbf597fc7);
  R(e, f, g, h, a, b, c, d, Wc, 0xc6e00bf3);
  R(d, e, f, g, h, a, b, c, Wd, 0xd5a79147);
  R(c, d, e, f, g, h, a, b, We, 0x06ca6351);
  R(b, c, d, e, f, g, h, a, Wf, 0x14292967);
  
  Wstep();
  R(a, b, c, d, e, f, g, h, W0, 0x27b70a85);
  R(h, a, b, c, d, e, f, g, W1, 0x2e1b2138);
  R(g, h, a, b, c, d, e, f, W2, 0x4d2c6dfc);
  R(f, g, h, a, b, c, d, e, W3, 0x53380d13);
  R(e, f, g, h, a, b, c, d, W4, 0x650a7354);
  R(d, e, f, g, h, a, b, c, W5, 0x766a0abb);
  R(c, d, e, f, g, h, a, b, W6, 0x81c2c92e);
  R(b, c, d, e, f, g, h, a, W7, 0x92722c85);
  R(a, b, c, d, e, f, g, h, W8, 0xa2bfe8a1);
  R(h, a, b, c, d, e, f, g, W9, 0xa81a664b);
  R(g, h, a, b, c, d, e, f, Wa, 0xc24b8b70);
  R(f, g, h, a, b, c, d, e, Wb, 0xc76c51a3);
  R(e, f, g, h, a, b, c, d, Wc, 0xd192e819);
  R(d, e, f, g, h, a, b, c, Wd, 0xd6990624);
  R(c, d, e, f, g, h, a, b, We, 0xf40e3585);
  R(b, c, d, e, f, g, h, a, Wf, 0x106aa070);
 
  Wstep();
  R(a, b, c, d, e, f, g, h, W0, 0x19a4c116);
  R(h, a, b, c, d, e, f, g, W1, 0x1e376c08);
  R(g, h, a, b, c, d, e, f, W2, 0x2748774c);
  R(f, g, h, a, b, c, d, e, W3, 0x34b0bcb5);
  R(e, f, g, h, a, b, c, d, W4, 0x391c0cb3);
  R(d, e, f, g, h, a, b, c, W5, 0x4ed8aa4a);
  R(c, d, e, f, g, h, a, b, W6, 0x5b9cca4f);
  R(b, c, d, e, f, g, h, a, W7, 0x682e6ff3);
  R(a, b, c, d, e, f, g, h, W8, 0x748f82ee);
  R(h, a, b, c, d, e, f, g, W9, 0x78a5636f);
  R(g, h, a, b, c, d, e, f, Wa, 0x84c87814);
  R(f, g, h, a, b, c, d, e, Wb, 0x8cc70208);
  R(e, f, g, h, a, b, c, d, Wc, 0x90befffa);
  R(d, e, f, g, h, a, b, c, Wd, 0xa4506ceb);
  R(c, d, e, f, g, h, a, b, We, 0xbef9a3f7);
  R(b, c, d, e, f, g, h, a, Wf, 0xc67178f2);

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
#undef W
#undef Wstep
#undef Winit
#undef R
}
#endif

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

