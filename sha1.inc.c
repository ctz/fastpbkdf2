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

/* --- SHA1 --- */
#define SHA1_BLOCK 64
#define SHA1_DIGEST 20

typedef struct
{
  uint32_t h[5];
  uint8_t buf[64];
  size_t used;
  size_t blocks;
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

static void sha1_raw_transform(const uint32_t state_in[5],
                               uint32_t state_out[5],
                               const sha1_block inp)
{
  uint32_t a = state_in[0],
           b = state_in[1],
           c = state_in[2],
           d = state_in[3],
           e = state_in[4];

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

  state_out[0] = a + state_in[0];
  state_out[1] = b + state_in[1];
  state_out[2] = c + state_in[2];
  state_out[3] = d + state_in[3];
  state_out[4] = e + state_in[4];

#undef R0
#undef R1
#undef R2
#undef R3
}

static void sha1_convert_input(sha1_block inp32, const uint8_t inp[64])
{
  for (int i = 0; i < 64; i += 4)
    inp32[i >> 2] = read32_be(inp + i);
}

static void sha1_transform(void *vctx, const uint8_t inp[64])
{
  sha1 *ctx = vctx;
  uint32_t inp32[16];
  sha1_convert_input(inp32, inp);
  sha1_raw_transform(ctx->h, ctx->h, inp32);
  ctx->blocks += 1;
}

static void sha1_convert_output(const uint32_t *restrict h, uint8_t *restrict out)
{
  write32_be(h[0], out);
  write32_be(h[1], out + 4);
  write32_be(h[2], out + 8);
  write32_be(h[3], out + 12);
  write32_be(h[4], out + 16);
}

static inline void sha1_xor(uint32_t *restrict out, const uint32_t *restrict in)
{
  out[0] ^= in[0];
  out[1] ^= in[1];
  out[2] ^= in[2];
  out[3] ^= in[3];
  out[4] ^= in[4];
}

static void sha1_update(sha1 *ctx, const uint8_t *bytes, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->buf, &ctx->used, SHA1_BLOCK,
                          bytes, nbytes,
                          sha1_transform, ctx);
}

static void sha1_final(uint8_t out[20], sha1 *ctx)
{
  uint32_t bytes = ctx->blocks * SHA1_BLOCK + ctx->used;
  uint32_t bits = bytes * 8;
  uint32_t padbytes = SHA1_BLOCK - ((bytes + 4) % SHA1_BLOCK);
  
  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->buf, &ctx->used, sizeof ctx->buf,
                       0x80, 0x00, 0x00, padbytes,
                       sha1_transform, ctx);

  /* Hash length */
  uint8_t buf[4];
  write32_be(bits, buf);
  sha1_update(ctx, buf, 4);
  assert(ctx->used == 0);

  sha1_convert_output(ctx->h, out);
}

#define _name       sha1
#define _blocksz    SHA1_BLOCK
#define _hashsz     SHA1_DIGEST
#define _ctx        sha1
#define _blocktype  sha1_block
#define _cvt_input  sha1_convert_input
#define _cvt_output sha1_convert_output
#define _init       sha1_init
#define _update     sha1_update
#define _final      sha1_final
#define _transform  sha1_raw_transform
#define _xor        sha1_xor

#include "core.inc.c"

#undef _name
#undef _blocksz
#undef _hashsz
#undef _ctx
#undef _blocktype
#undef _convert
#undef _init
#undef _update
#undef _final
#undef _transform
#undef _xtract
#undef _xor

#if 0
void cf_sha1_init(cf_sha1_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = 0x67452301;
  ctx->H[1] = 0xefcdab89;
  ctx->H[2] = 0x98badcfe;
  ctx->H[3] = 0x10325476;
  ctx->H[4] = 0xc3d2e1f0;
}

static void sha1_update_block(void *vctx, const uint8_t *inp)
{
  cf_sha1_context *ctx = vctx;

  /* This is a 16-word window into the whole W array. */
  uint32_t W[16];

  uint32_t a = ctx->H[0],
           b = ctx->H[1],
           c = ctx->H[2],
           d = ctx->H[3],
           e = ctx->H[4],
           Wt;

  for (size_t t = 0; t < 80; t++)
  {
    /* For W[0..16] we process the input into W.
     * For W[16..79] we compute the next W value:
     *
     * W[t] = (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]) <<< 1
     *
     * But all W indices are reduced mod 16 into our window.
     */
    if (t < 16)
    {
      W[t] = Wt = read32_be(inp);
      inp += 4;
    } else {
      Wt = W[(t - 3) % 16] ^ W[(t - 8) % 16] ^ W[(t - 14) % 16] ^ W[(t - 16) % 16];
      Wt = rotl32(Wt, 1);
      W[t % 16] = Wt;
    }

    uint32_t f, k;

    if (t <= 19)
    {
      f = (b & c) | (~b & d);
      k = 0x5a827999;
    } else if (t <= 39) {
      f = b ^ c ^ d;
      k = 0x6ed9eba1;
    } else if (t <= 59) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8f1bbcdc;
    } else {
      f = b ^ c ^ d;
      k = 0xca62c1d6;
    }

    uint32_t temp = rotl32(a, 5) + f + e + k + Wt;
    e = d;
    d = c;
    c = rotl32(b, 30);
    b = a;
    a = temp;
  }

  ctx->H[0] += a;
  ctx->H[1] += b;
  ctx->H[2] += c;
  ctx->H[3] += d;
  ctx->H[4] += e;

  ctx->blocks++;
}

void cf_sha1_update(cf_sha1_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          data, nbytes,
                          sha1_update_block, ctx);
}

void cf_sha1_digest(const cf_sha1_context *ctx, uint8_t hash[CF_SHA1_HASHSZ])
{
  cf_sha1_context ours = *ctx;
  cf_sha1_digest_final(&ours, hash);
}

void cf_sha1_digest_final(cf_sha1_context *ctx, uint8_t hash[CF_SHA1_HASHSZ])
{
  uint64_t digested_bytes = ctx->blocks;
  digested_bytes = digested_bytes * CF_SHA1_BLOCKSZ + ctx->npartial;
  uint64_t digested_bits = digested_bytes * 8;

  size_t padbytes = CF_SHA1_BLOCKSZ - ((digested_bytes + 8) % CF_SHA1_BLOCKSZ);

  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                       0x80, 0x00, 0x00, padbytes,
                       sha1_update_block, ctx);

  /* Now hash length. */
  uint8_t buf[8];
  write64_be(digested_bits, buf);
  cf_sha1_update(ctx, buf, 8);

  /* We ought to have got our padding calculation right! */
  assert(ctx->npartial == 0);

  write32_be(ctx->H[0], hash + 0);
  write32_be(ctx->H[1], hash + 4);
  write32_be(ctx->H[2], hash + 8);
  write32_be(ctx->H[3], hash + 12);
  write32_be(ctx->H[4], hash + 16);
  
  memset(ctx, 0, sizeof *ctx);
}

const cf_chash cf_sha1 = {
  .hashsz = CF_SHA1_HASHSZ,
  .blocksz = CF_SHA1_BLOCKSZ,
  .init = (cf_chash_init) cf_sha1_init,
  .update = (cf_chash_update) cf_sha1_update,
  .digest = (cf_chash_digest) cf_sha1_digest
};

#endif
