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

#include <assert.h>
#include <string.h>

/* This file is the PBKDF2-HMAC core, and is included with the following
 * macros defined:
 *
 * _name:       like 'sha1', added to symbol names
 * _blocksz:    block size, in bytes
 * _hashsz:     digest output, in bytes
 * _ctx:        incremental hash context type
 *    this must have a member named 'H' of integer array type, the
 *    integer type is called 'W' below
 * _blocktype:  message block type
 *    a W-type array of length _blocksz
 * _cvt_input:  convert from bytes into a message block type
 *    args: (_blocktype block, const uint8_t bytes[_blocksz])
 * _cvt_output: convert from current state words to output
 *    args: (const W *restrict state, uint8_t out[_hashsz])
 * _init:       hash context initialisation function
 *    args: (_ctx *c)
 * _update:     hash context update function
 *    args: (_ctx *c, const void *data, size_t ndata)
 * _final:      hash context finish function
 *    args: (_ctx *c, uint8_t *hash)
 * _transform:  hash context raw block update function
 *    args: (const W *state_in, W *state_out, const _blocktype inp)
 * _xor:        hash state xor function
 *    args: (W *restrict out, const W *restrict in)
 *
 * It (eventually) defines a function named PBKDF2(_name).
 */

/* Internal function/type names for hash-specific things. */
#ifndef HMAC_CTX
# define GLUE3(a, b, c) a ## b ## c
# define HMAC_CTX(_name) GLUE3(HMAC_, _name, _ctx)
# define HMAC_INIT(_name) GLUE3(HMAC_, _name, _init)
# define HMAC_UPDATE(_name) GLUE3(HMAC_, _name, _update)
# define HMAC_FINAL(_name) GLUE3(HMAC_, _name, _final)

# define PBKDF2_F(_name) GLUE3(pbkdf2, _f_, _name)
# define PBKDF2(_name) GLUE3(pbkdf2, _, _name)
#endif

typedef struct {
  _ctx inner;
  _ctx outer;
} HMAC_CTX(_name);

static inline void HMAC_INIT(_name)(HMAC_CTX(_name) *ctx,
                                    const uint8_t *key, size_t nkey)
{
  /* Prepare key: */
  uint8_t k[_blocksz];

  /* Shorten long keys. */
  if (nkey > _blocksz)
  {
    _init(&ctx->inner);
    _update(&ctx->inner, key, nkey);
    _final(&ctx->inner, k);

    key = k;
    nkey = _hashsz;
  }

  /* Standard doesn't cover case where blocksz < hashsz. */
  assert(nkey <= _blocksz);

  /* Right zero-pad short keys. */
  if (k != key)
    memcpy(k, key, nkey);
  if (_blocksz > nkey)
    memset(k + nkey, 0, _blocksz - nkey);

  /* Start inner hash computation */
  uint8_t blk_inner[_blocksz];
  uint8_t blk_outer[_blocksz];

  for (size_t i = 0; i < _blocksz; i++)
  {
    blk_inner[i] = 0x36 ^ k[i];
    blk_outer[i] = 0x5c ^ k[i];
  }

  _init(&ctx->inner);
  _update(&ctx->inner, blk_inner, sizeof blk_inner);

  /* And outer. */
  _init(&ctx->outer);
  _update(&ctx->outer, blk_outer, sizeof blk_outer);
}

static inline void HMAC_UPDATE(_name)(HMAC_CTX(_name) *ctx,
                                      const void *data, size_t ndata)
{
  _update(&ctx->inner, data, ndata);
}

static inline void HMAC_FINAL(_name)(HMAC_CTX(_name) *ctx,
                                     uint8_t out[_hashsz])
{
  _final(&ctx->inner, out);
  _update(&ctx->outer, out, _hashsz);
  _final(&ctx->outer, out);
}


/* --- PBKDF2 --- */
static inline void PBKDF2_F(_name)(const HMAC_CTX(_name) *startctx,
                                   uint32_t counter,
                                   const uint8_t *salt, size_t nsalt,
                                   uint32_t iterations,
                                   uint8_t *out)
{
  uint8_t countbuf[4];
  write32_be(counter, countbuf);

  /* Prepare loop-invariant padding block. */
  uint8_t Ubytes[_blocksz];
  md_pad(Ubytes, _blocksz, _hashsz, _blocksz + _hashsz);

  /* First iteration:
   *   U_1 = PRF(P, S || INT_32_BE(i))
   */
  HMAC_CTX(_name) ctx = *startctx;
  HMAC_UPDATE(_name)(&ctx, salt, nsalt);
  HMAC_UPDATE(_name)(&ctx, countbuf, sizeof countbuf);
  HMAC_FINAL(_name)(&ctx, Ubytes);
  _ctx result = ctx.outer;

  /* Convert the first U_1 term to correct endianness.
   * The inner loop is native-endian. */
  _blocktype Ublock;
  _cvt_input(Ublock, Ubytes);

  /* Subsequent iterations:
   *   U_c = PRF(P, U_{c-1})
   */
  for (uint32_t i = 1; i < iterations; i++)
  {
    /* Complete inner hash with previous U (stored at the start of Ublock)
     *
     * Put the result again at the start of Ublock. */
    _transform(startctx->inner.H, Ublock, Ublock);

    /* Complete outer hash with inner output */
    _transform(startctx->outer.H, Ublock, Ublock);

    /* Collect ultimate result */
    _xor(result.H, Ublock);
  }

  /* Reform result into output buffer. */
  _cvt_output(result.H, out);
}

static inline void PBKDF2(_name)(const uint8_t *pw, size_t npw,
                   const uint8_t *salt, size_t nsalt,
                   uint32_t iterations,
                   uint8_t *out, size_t nout)
{
  assert(iterations);
  assert(out && nout);

  /* Starting point for inner loop. */
  HMAC_CTX(_name) ctx;
  HMAC_INIT(_name)(&ctx, pw, npw);

  /* How many blocks do we need? */
  uint32_t blocks_needed = (nout + _hashsz - 1) / _hashsz;

  OPENMP_PARALLEL_FOR
  for (uint32_t counter = 1; counter <= blocks_needed; counter++)
  {
    uint8_t block[_hashsz];
    PBKDF2_F(_name)(&ctx, counter, salt, nsalt, iterations, block);

    size_t offset = (counter - 1) * _hashsz;
    size_t taken = MIN(nout - offset, _hashsz);
    memcpy(out + offset, block, taken);
  }
}

