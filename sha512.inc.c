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

/* --- SHA512 --- */
#define CF_SHA512_BLOCKSZ 128
#define CF_SHA512_HASHSZ 64

typedef struct
{
  uint64_t H[8];
  uint8_t partial[CF_SHA512_BLOCKSZ];
  uint32_t blocks;
  size_t npartial;
} cf_sha512_context;

typedef uint64_t cf_sha512_block[16];

static void cf_sha512_init(cf_sha512_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = UINT64_C(0x6a09e667f3bcc908);
  ctx->H[1] = UINT64_C(0xbb67ae8584caa73b);
  ctx->H[2] = UINT64_C(0x3c6ef372fe94f82b);
  ctx->H[3] = UINT64_C(0xa54ff53a5f1d36f1);
  ctx->H[4] = UINT64_C(0x510e527fade682d1);
  ctx->H[5] = UINT64_C(0x9b05688c2b3e6c1f);
  ctx->H[6] = UINT64_C(0x1f83d9abfb41bd6b);
  ctx->H[7] = UINT64_C(0x5be0cd19137e2179);
}

static void sha512_raw_transform(const uint64_t state_in[8],
                                 uint64_t state_out[8],
                                 const cf_sha512_block inp)
{
  uint64_t W[16];

  uint64_t a = state_in[0],
           b = state_in[1],
           c = state_in[2],
           d = state_in[3],
           e = state_in[4],
           f = state_in[5],
           g = state_in[6],
           h = state_in[7];

# define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
# define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
# define BSIG0(x) (rotr64((x), 28) ^ rotr64((x), 34) ^ rotr64((x), 39))
# define BSIG1(x) (rotr64((x), 14) ^ rotr64((x), 18) ^ rotr64((x), 41))
# define SSIG0(x) (rotr64((x), 1) ^ rotr64((x), 8) ^ ((x) >> 7))
# define SSIG1(x) (rotr64((x), 19) ^ rotr64((x), 61) ^ ((x) >> 6))

# define Wi(i) W[i] = inp[i]
# define Wn(n) W[n] = SSIG1(W[n - 2]) + W[n - 7] + SSIG0(W[n - 15]) + W[n - 16]
# define R(a, b, c, d, e, f, g, h, i, K)                           \
      do {                                                         \
        uint64_t T1 = h + BSIG1(e) + CH(e, f, g) + K + W[i];       \
        uint64_t T2 = BSIG0(a) + MAJ(a, b, c);                     \
        d += T1;                                                   \
        h = T1 + T2;                                               \
      } while (0)
      
  Wi(0);  R(a, b, c, d, e, f, g, h, 0, UINT64_C(0x428a2f98d728ae22));
  Wi(1);  R(h, a, b, c, d, e, f, g, 1, UINT64_C(0x7137449123ef65cd));
  Wi(2);  R(g, h, a, b, c, d, e, f, 2, UINT64_C(0xb5c0fbcfec4d3b2f));
  Wi(3);  R(f, g, h, a, b, c, d, e, 3, UINT64_C(0xe9b5dba58189dbbc));
  Wi(4);  R(e, f, g, h, a, b, c, d, 4, UINT64_C(0x3956c25bf348b538));
  Wi(5);  R(d, e, f, g, h, a, b, c, 5, UINT64_C(0x59f111f1b605d019));
  Wi(6);  R(c, d, e, f, g, h, a, b, 6, UINT64_C(0x923f82a4af194f9b));
  Wi(7);  R(b, c, d, e, f, g, h, a, 7, UINT64_C(0xab1c5ed5da6d8118));
  Wi(8);  R(a, b, c, d, e, f, g, h, 8, UINT64_C(0xd807aa98a3030242));
  Wi(9);  R(h, a, b, c, d, e, f, g, 9, UINT64_C(0x12835b0145706fbe));
  Wi(10); R(g, h, a, b, c, d, e, f, 10, UINT64_C(0x243185be4ee4b28c));
  Wi(11); R(f, g, h, a, b, c, d, e, 11, UINT64_C(0x550c7dc3d5ffb4e2));
  Wi(12); R(e, f, g, h, a, b, c, d, 12, UINT64_C(0x72be5d74f27b896f));
  Wi(13); R(d, e, f, g, h, a, b, c, 13, UINT64_C(0x80deb1fe3b1696b1));
  Wi(14); R(c, d, e, f, g, h, a, b, 14, UINT64_C(0x9bdc06a725c71235));
  Wi(15); R(b, c, d, e, f, g, h, a, 15, UINT64_C(0xc19bf174cf692694));

  Wn(16); R(a, b, c, d, e, f, g, h, 16, UINT64_C(0xe49b69c19ef14ad2));
  Wn(17); R(h, a, b, c, d, e, f, g, 17, UINT64_C(0xefbe4786384f25e3));
  Wn(18); R(g, h, a, b, c, d, e, f, 18, UINT64_C(0x0fc19dc68b8cd5b5));
  Wn(19); R(f, g, h, a, b, c, d, e, 19, UINT64_C(0x240ca1cc77ac9c65));
  Wn(20); R(e, f, g, h, a, b, c, d, 20, UINT64_C(0x2de92c6f592b0275));
  Wn(21); R(d, e, f, g, h, a, b, c, 21, UINT64_C(0x4a7484aa6ea6e483));
  Wn(22); R(c, d, e, f, g, h, a, b, 22, UINT64_C(0x5cb0a9dcbd41fbd4));
  Wn(23); R(b, c, d, e, f, g, h, a, 23, UINT64_C(0x76f988da831153b5));
  Wn(24); R(a, b, c, d, e, f, g, h, 24, UINT64_C(0x983e5152ee66dfab));
  Wn(25); R(h, a, b, c, d, e, f, g, 25, UINT64_C(0xa831c66d2db43210));
  Wn(26); R(g, h, a, b, c, d, e, f, 26, UINT64_C(0xb00327c898fb213f));
  Wn(27); R(f, g, h, a, b, c, d, e, 27, UINT64_C(0xbf597fc7beef0ee4));
  Wn(28); R(e, f, g, h, a, b, c, d, 28, UINT64_C(0xc6e00bf33da88fc2));
  Wn(29); R(d, e, f, g, h, a, b, c, 29, UINT64_C(0xd5a79147930aa725));
  Wn(30); R(c, d, e, f, g, h, a, b, 30, UINT64_C(0x06ca6351e003826f));
  Wn(31); R(b, c, d, e, f, g, h, a, 31, UINT64_C(0x142929670a0e6e70));
  Wn(32); R(a, b, c, d, e, f, g, h, 32, UINT64_C(0x27b70a8546d22ffc));
  Wn(33); R(h, a, b, c, d, e, f, g, 33, UINT64_C(0x2e1b21385c26c926));
  Wn(34); R(g, h, a, b, c, d, e, f, 34, UINT64_C(0x4d2c6dfc5ac42aed));
  Wn(35); R(f, g, h, a, b, c, d, e, 35, UINT64_C(0x53380d139d95b3df));
  Wn(36); R(e, f, g, h, a, b, c, d, 36, UINT64_C(0x650a73548baf63de));
  Wn(37); R(d, e, f, g, h, a, b, c, 37, UINT64_C(0x766a0abb3c77b2a8));
  Wn(38); R(c, d, e, f, g, h, a, b, 38, UINT64_C(0x81c2c92e47edaee6));
  Wn(39); R(b, c, d, e, f, g, h, a, 39, UINT64_C(0x92722c851482353b));
  Wn(40); R(a, b, c, d, e, f, g, h, 40, UINT64_C(0xa2bfe8a14cf10364));
  Wn(41); R(h, a, b, c, d, e, f, g, 41, UINT64_C(0xa81a664bbc423001));
  Wn(42); R(g, h, a, b, c, d, e, f, 42, UINT64_C(0xc24b8b70d0f89791));
  Wn(43); R(f, g, h, a, b, c, d, e, 43, UINT64_C(0xc76c51a30654be30));
  Wn(44); R(e, f, g, h, a, b, c, d, 44, UINT64_C(0xd192e819d6ef5218));
  Wn(45); R(d, e, f, g, h, a, b, c, 45, UINT64_C(0xd69906245565a910));
  Wn(46); R(c, d, e, f, g, h, a, b, 46, UINT64_C(0xf40e35855771202a));
  Wn(47); R(b, c, d, e, f, g, h, a, 47, UINT64_C(0x106aa07032bbd1b8));
  Wn(48); R(a, b, c, d, e, f, g, h, 48, UINT64_C(0x19a4c116b8d2d0c8));
  Wn(49); R(h, a, b, c, d, e, f, g, 49, UINT64_C(0x1e376c085141ab53));
  Wn(50); R(g, h, a, b, c, d, e, f, 50, UINT64_C(0x2748774cdf8eeb99));
  Wn(51); R(f, g, h, a, b, c, d, e, 51, UINT64_C(0x34b0bcb5e19b48a8));
  Wn(52); R(e, f, g, h, a, b, c, d, 52, UINT64_C(0x391c0cb3c5c95a63));
  Wn(53); R(d, e, f, g, h, a, b, c, 53, UINT64_C(0x4ed8aa4ae3418acb));
  Wn(54); R(c, d, e, f, g, h, a, b, 54, UINT64_C(0x5b9cca4f7763e373));
  Wn(55); R(b, c, d, e, f, g, h, a, 55, UINT64_C(0x682e6ff3d6b2b8a3));
  Wn(56); R(a, b, c, d, e, f, g, h, 56, UINT64_C(0x748f82ee5defb2fc));
  Wn(57); R(h, a, b, c, d, e, f, g, 57, UINT64_C(0x78a5636f43172f60));
  Wn(58); R(g, h, a, b, c, d, e, f, 58, UINT64_C(0x84c87814a1f0ab72));
  Wn(59); R(f, g, h, a, b, c, d, e, 59, UINT64_C(0x8cc702081a6439ec));
  Wn(60); R(e, f, g, h, a, b, c, d, 60, UINT64_C(0x90befffa23631e28));
  Wn(61); R(d, e, f, g, h, a, b, c, 61, UINT64_C(0xa4506cebde82bde9));
  Wn(62); R(c, d, e, f, g, h, a, b, 62, UINT64_C(0xbef9a3f7b2c67915));
  Wn(63); R(b, c, d, e, f, g, h, a, 63, UINT64_C(0xc67178f2e372532b));
  Wn(64); R(a, b, c, d, e, f, g, h, 64, UINT64_C(0xca273eceea26619c));
  Wn(65); R(h, a, b, c, d, e, f, g, 65, UINT64_C(0xd186b8c721c0c207));
  Wn(66); R(g, h, a, b, c, d, e, f, 66, UINT64_C(0xeada7dd6cde0eb1e));
  Wn(67); R(f, g, h, a, b, c, d, e, 67, UINT64_C(0xf57d4f7fee6ed178));
  Wn(68); R(e, f, g, h, a, b, c, d, 68, UINT64_C(0x06f067aa72176fba));
  Wn(69); R(d, e, f, g, h, a, b, c, 69, UINT64_C(0x0a637dc5a2c898a6));
  Wn(70); R(c, d, e, f, g, h, a, b, 70, UINT64_C(0x113f9804bef90dae));
  Wn(71); R(b, c, d, e, f, g, h, a, 71, UINT64_C(0x1b710b35131c471b));
  Wn(72); R(a, b, c, d, e, f, g, h, 72, UINT64_C(0x28db77f523047d84));
  Wn(73); R(h, a, b, c, d, e, f, g, 73, UINT64_C(0x32caab7b40c72493));
  Wn(74); R(g, h, a, b, c, d, e, f, 74, UINT64_C(0x3c9ebe0a15c9bebc));
  Wn(75); R(f, g, h, a, b, c, d, e, 75, UINT64_C(0x431d67c49c100d4c));
  Wn(76); R(e, f, g, h, a, b, c, d, 76, UINT64_C(0x4cc5d4becb3e42b6));
  Wn(77); R(d, e, f, g, h, a, b, c, 77, UINT64_C(0x597f299cfc657e2a));
  Wn(78); R(c, d, e, f, g, h, a, b, 78, UINT64_C(0x5fcb6fab3ad6faec));
  Wn(79); R(b, c, d, e, f, g, h, a, 79, UINT64_C(0x6c44198c4a475817));

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
#undef SSIG0
#undef SSIG1
#undef BSIG0
#undef BSIG1
#undef R
#undef Wi
#undef Wn
}

static void sha512_convert_input(cf_sha512_block inp64, const uint8_t inp[CF_SHA512_BLOCKSZ])
{
  for (int i = 0; i < CF_SHA512_BLOCKSZ; i += 8)
    inp64[i >> 3] = read64_be(inp + i);
}

static void sha512_update_block(void *vctx, const uint8_t *inp)
{
  cf_sha512_context *ctx = vctx;
  cf_sha512_block inp64;
  sha512_convert_input(inp64, inp);
  sha512_raw_transform(ctx->H, ctx->H, inp64);
  ctx->blocks += 1;
}

static void cf_sha512_update(cf_sha512_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          data, nbytes,
                          sha512_update_block, ctx);
}

static void sha512_convert_output(const uint64_t H[8],
                                  uint8_t hash[CF_SHA512_HASHSZ])
{
  write64_be(H[0], hash + 0);
  write64_be(H[1], hash + 8);
  write64_be(H[2], hash + 16);
  write64_be(H[3], hash + 24);
  write64_be(H[4], hash + 32);
  write64_be(H[5], hash + 40);
  write64_be(H[6], hash + 48);
  write64_be(H[7], hash + 56);
}

static void sha512_xor(uint64_t *restrict out, const uint64_t *restrict in)
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

static void cf_sha512_final(cf_sha512_context *ctx, uint8_t hash[CF_SHA512_HASHSZ])
{
  uint32_t digested_bytes = ctx->blocks;
  digested_bytes = digested_bytes * CF_SHA512_BLOCKSZ + ctx->npartial;
  uint32_t digested_bits = digested_bytes * 8;

  size_t padbytes = CF_SHA512_BLOCKSZ - ((digested_bytes + 4) % CF_SHA512_BLOCKSZ);

  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                       0x80, 0x00, 0x00, padbytes,
                       sha512_update_block, ctx);

  /* Now hash length (this is 128 bits long). */
  uint8_t buf[4];
  write32_be(digested_bits, buf);
  cf_sha512_update(ctx, buf, 4);

  /* We ought to have got our padding calculation right! */
  assert(ctx->npartial == 0);
  
  sha512_convert_output(ctx->H, hash);
}

#define _name       sha512
#define _blocksz    CF_SHA512_BLOCKSZ
#define _hashsz     CF_SHA512_HASHSZ
#define _ctx        cf_sha512_context
#define _blocktype  cf_sha512_block
#define _cvt_input  sha512_convert_input
#define _cvt_output sha512_convert_output
#define _init       cf_sha512_init
#define _update     cf_sha512_update
#define _final      cf_sha512_final
#define _transform  sha512_raw_transform
#define _xor        sha512_xor

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
