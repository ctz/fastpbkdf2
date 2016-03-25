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

#define CF_SHA1_HASHSZ 20
#define CF_SHA1_BLOCKSZ 64

typedef struct
{
  uint32_t H[5];
  uint8_t partial[CF_SHA1_BLOCKSZ];
  size_t blocks;
  size_t npartial;
} cf_sha1_context;

typedef uint32_t cf_sha1_block[16];

static void cf_sha1_init(cf_sha1_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = 0x67452301;
  ctx->H[1] = 0xefcdab89;
  ctx->H[2] = 0x98badcfe;
  ctx->H[3] = 0x10325476;
  ctx->H[4] = 0xc3d2e1f0;
}

static void sha1_raw_transform(const uint32_t state_in[5],
                               uint32_t state_out[5],
                               const cf_sha1_block inp)
{
  uint32_t a = state_in[0],
           b = state_in[1],
           c = state_in[2],
           d = state_in[3],
           e = state_in[4];

  uint32_t W[80];

#define Wi(i) W[i] = inp[i]
#define Wn(n) W[n] = rotl32(W[n - 3] ^ W[n - 8] ^ W[n - 14] ^ W[n - 16], 1)

#define R0(v, w, x, y, z, i) z += ((w & (x ^ y)) ^ y) + W[i] + 0x5a827999 + rotl32(v, 5); w = rotl32(w, 30)
#define R1(v, w, x, y, z, i) z += (w ^ x ^ y) + W[i] + 0x6ed9eba1 + rotl32(v, 5); w = rotl32(w, 30)
#define R2(v, w, x, y, z, i) z += (((w | x) & y) | (w & x)) + W[i] + 0x8f1bbcdc + rotl32(v, 5); w = rotl32(w, 30)
#define R3(v, w, x, y, z, i) z += (w ^ x ^ y) + W[i] + 0xca62c1d6 + rotl32(v, 5); w = rotl32(w, 30)

  Wi(0);  R0(a, b, c, d, e, 0);
  Wi(1);  R0(e, a, b, c, d, 1);
  Wi(2);  R0(d, e, a, b, c, 2);
  Wi(3);  R0(c, d, e, a, b, 3);
  Wi(4);  R0(b, c, d, e, a, 4);
  Wi(5);  R0(a, b, c, d, e, 5);
  Wi(6);  R0(e, a, b, c, d, 6);
  Wi(7);  R0(d, e, a, b, c, 7);
  Wi(8);  R0(c, d, e, a, b, 8);
  Wi(9);  R0(b, c, d, e, a, 9);
  Wi(10); R0(a, b, c, d, e, 10);
  Wi(11); R0(e, a, b, c, d, 11);
  Wi(12); R0(d, e, a, b, c, 12);
  Wi(13); R0(c, d, e, a, b, 13);
  Wi(14); R0(b, c, d, e, a, 14);
  Wi(15); R0(a, b, c, d, e, 15);
  
  Wn(16); R0(e, a, b, c, d, 16);
  Wn(17); R0(d, e, a, b, c, 17);
  Wn(18); R0(c, d, e, a, b, 18);
  Wn(19); R0(b, c, d, e, a, 19);
  Wn(20); R1(a, b, c, d, e, 20);
  Wn(21); R1(e, a, b, c, d, 21);
  Wn(22); R1(d, e, a, b, c, 22);
  Wn(23); R1(c, d, e, a, b, 23);
  Wn(24); R1(b, c, d, e, a, 24);
  Wn(25); R1(a, b, c, d, e, 25);
  Wn(26); R1(e, a, b, c, d, 26);
  Wn(27); R1(d, e, a, b, c, 27);
  Wn(28); R1(c, d, e, a, b, 28);
  Wn(29); R1(b, c, d, e, a, 29);
  Wn(30); R1(a, b, c, d, e, 30);
  Wn(31); R1(e, a, b, c, d, 31);
  Wn(32); R1(d, e, a, b, c, 32);
  Wn(33); R1(c, d, e, a, b, 33);
  Wn(34); R1(b, c, d, e, a, 34);
  Wn(35); R1(a, b, c, d, e, 35);
  Wn(36); R1(e, a, b, c, d, 36);
  Wn(37); R1(d, e, a, b, c, 37);
  Wn(38); R1(c, d, e, a, b, 38);
  Wn(39); R1(b, c, d, e, a, 39);
  Wn(40); R2(a, b, c, d, e, 40);
  Wn(41); R2(e, a, b, c, d, 41);
  Wn(42); R2(d, e, a, b, c, 42);
  Wn(43); R2(c, d, e, a, b, 43);
  Wn(44); R2(b, c, d, e, a, 44);
  Wn(45); R2(a, b, c, d, e, 45);
  Wn(46); R2(e, a, b, c, d, 46);
  Wn(47); R2(d, e, a, b, c, 47);
  Wn(48); R2(c, d, e, a, b, 48);
  Wn(49); R2(b, c, d, e, a, 49);
  Wn(50); R2(a, b, c, d, e, 50);
  Wn(51); R2(e, a, b, c, d, 51);
  Wn(52); R2(d, e, a, b, c, 52);
  Wn(53); R2(c, d, e, a, b, 53);
  Wn(54); R2(b, c, d, e, a, 54);
  Wn(55); R2(a, b, c, d, e, 55);
  Wn(56); R2(e, a, b, c, d, 56);
  Wn(57); R2(d, e, a, b, c, 57);
  Wn(58); R2(c, d, e, a, b, 58);
  Wn(59); R2(b, c, d, e, a, 59);
  Wn(60); R3(a, b, c, d, e, 60);
  Wn(61); R3(e, a, b, c, d, 61);
  Wn(62); R3(d, e, a, b, c, 62);
  Wn(63); R3(c, d, e, a, b, 63);
  Wn(64); R3(b, c, d, e, a, 64);
  Wn(65); R3(a, b, c, d, e, 65);
  Wn(66); R3(e, a, b, c, d, 66);
  Wn(67); R3(d, e, a, b, c, 67);
  Wn(68); R3(c, d, e, a, b, 68);
  Wn(69); R3(b, c, d, e, a, 69);
  Wn(70); R3(a, b, c, d, e, 70);
  Wn(71); R3(e, a, b, c, d, 71);
  Wn(72); R3(d, e, a, b, c, 72);
  Wn(73); R3(c, d, e, a, b, 73);
  Wn(74); R3(b, c, d, e, a, 74);
  Wn(75); R3(a, b, c, d, e, 75);
  Wn(76); R3(e, a, b, c, d, 76);
  Wn(77); R3(d, e, a, b, c, 77);
  Wn(78); R3(c, d, e, a, b, 78);
  Wn(79); R3(b, c, d, e, a, 79);

  state_out[0] = a + state_in[0];
  state_out[1] = b + state_in[1];
  state_out[2] = c + state_in[2];
  state_out[3] = d + state_in[3];
  state_out[4] = e + state_in[4];

#undef R0
#undef R1
#undef R2
#undef R3
#undef Wi
#undef Wn
}

static void sha1_convert_input(cf_sha1_block inp32, const uint8_t inp[64])
{
  for (int i = 0; i < 64; i += 4)
    inp32[i >> 2] = read32_be(inp + i);
}

static void sha1_update_block(void *vctx, const uint8_t inp[64])
{
  cf_sha1_context *ctx = vctx;
  uint32_t inp32[16];
  sha1_convert_input(inp32, inp);
  sha1_raw_transform(ctx->H, ctx->H, inp32);
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

static void cf_sha1_update(cf_sha1_context *ctx, const uint8_t *bytes, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          bytes, nbytes,
                          sha1_update_block, ctx);
}

static void cf_sha1_final(cf_sha1_context *ctx, uint8_t out[CF_SHA1_HASHSZ])
{
  uint32_t bytes = ctx->blocks * CF_SHA1_BLOCKSZ + ctx->npartial;
  uint32_t bits = bytes * 8;
  uint32_t padbytes = CF_SHA1_BLOCKSZ - ((bytes + 4) % CF_SHA1_BLOCKSZ);
  
  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                       0x80, 0x00, 0x00, padbytes,
                       sha1_update_block, ctx);

  /* Hash length */
  uint8_t buf[4];
  write32_be(bits, buf);
  cf_sha1_update(ctx, buf, 4);
  assert(ctx->npartial == 0);

  sha1_convert_output(ctx->H, out);
}

#define _name       sha1
#define _blocksz    CF_SHA1_BLOCKSZ
#define _hashsz     CF_SHA1_HASHSZ
#define _ctx        cf_sha1_context
#define _blocktype  cf_sha1_block
#define _cvt_input  sha1_convert_input
#define _cvt_output sha1_convert_output
#define _init       cf_sha1_init
#define _update     cf_sha1_update
#define _final      cf_sha1_final
#define _transform  sha1_raw_transform
#define _xor        sha1_xor

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

