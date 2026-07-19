/* blake2.c - BLAKE2b hash function
 * Copyright (C) 2017  Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * BLAKE2b for Rover, reduced to the generic (no-AVX) blake2b core plus
 * the variable-length hash H' (blake2b_vl_hash) that argon2 needs.  The
 * blake2b algorithm code below is spliced verbatim from ref/grub
 * cipher/blake2.c; only the libgcrypt internal-header dependencies are
 * shimmed here (gcry_wrap.h supplies buf_get/put_le64 and u64/byte).
 */

#include <grub/types.h>
#include <grub/crypto.h>
#include <grub/misc.h>
#include "gcry_wrap.h"

#define U64_C(c) (c ## ULL)
#define ASM_EXTRA_STACK 0
#define gcry_assert(x) ((void) 0)
#define memset grub_memset
#define buf_cpy(d, s, n) grub_memcpy ((d), (s), (n))
#define wipememory(ptr, len) grub_memset ((ptr), 0, (len))

/* ==== begin blake2b core spliced from libgcrypt cipher/blake2.c ==== */

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64
#define BLAKE2B_KEYBYTES 64

#define BLAKE2S_BLOCKBYTES 64
#define BLAKE2S_OUTBYTES 32
#define BLAKE2S_KEYBYTES 32

typedef struct
{
  u64 h[8];
  u64 t[2];
  u64 f[2];
} BLAKE2B_STATE;

struct blake2b_param_s
{
  byte digest_length;
  byte key_length;
  byte fanout;
  byte depth;
  byte leaf_length[4];
  byte node_offset[4];
  byte xof_length[4];
  byte node_depth;
  byte inner_length;
  byte reserved[14];
  byte salt[16];
  byte personal[16];
};

typedef struct BLAKE2B_CONTEXT_S
{
  BLAKE2B_STATE state;
  byte buf[BLAKE2B_BLOCKBYTES];
  size_t buflen;
  size_t outlen;
#ifdef USE_AVX2
  unsigned int use_avx2:1;
#endif
#ifdef USE_AVX512
  unsigned int use_avx512:1;
#endif
} BLAKE2B_CONTEXT;

typedef unsigned int (*blake2_transform_t)(void *S, const void *inblk,
					   size_t nblks);


static const u64 blake2b_IV[8] =
{
  U64_C(0x6a09e667f3bcc908), U64_C(0xbb67ae8584caa73b),
  U64_C(0x3c6ef372fe94f82b), U64_C(0xa54ff53a5f1d36f1),
  U64_C(0x510e527fade682d1), U64_C(0x9b05688c2b3e6c1f),
  U64_C(0x1f83d9abfb41bd6b), U64_C(0x5be0cd19137e2179)
};

static byte zero_block[BLAKE2B_BLOCKBYTES] = { 0, };


static void blake2_write(void *S, const void *inbuf, size_t inlen,
			 byte *tmpbuf, size_t *tmpbuflen, size_t blkbytes,
			 blake2_transform_t transform_fn)
{
  const byte* in = inbuf;
  unsigned int burn = 0;

  if (inlen > 0)
    {
      size_t left = *tmpbuflen;
      size_t fill = blkbytes - left;
      size_t nblks;

      if (inlen > fill)
	{
	  if (fill > 0)
	    buf_cpy (tmpbuf + left, in, fill); /* Fill buffer */
	  left = 0;

	  burn = transform_fn (S, tmpbuf, 1); /* Increment counter + Compress */

	  in += fill;
	  inlen -= fill;

	  nblks = inlen / blkbytes - !(inlen % blkbytes);
	  if (nblks)
	    {
	      burn = transform_fn(S, in, nblks);
	      in += blkbytes * nblks;
	      inlen -= blkbytes * nblks;
	    }
	}

      gcry_assert (inlen > 0);

      buf_cpy (tmpbuf + left, in, inlen);
      *tmpbuflen = left + inlen;
    }

  if (burn)
    _gcry_burn_stack (burn);

  return;
}


static inline void blake2b_set_lastblock(BLAKE2B_STATE *S)
{
  S->f[0] = U64_C(0xffffffffffffffff);
}

static inline int blake2b_is_lastblock(const BLAKE2B_STATE *S)
{
  return S->f[0] != 0;
}

static inline void blake2b_increment_counter(BLAKE2B_STATE *S, const int inc)
{
  S->t[0] += (u64)inc;
  S->t[1] += (S->t[0] < (u64)inc) - (inc < 0);
}

static inline u64 rotr64(u64 x, u64 n)
{
  return ((x >> (n & 63)) | (x << ((64 - n) & 63)));
}

static unsigned int blake2b_transform_generic(BLAKE2B_STATE *S,
                                              const void *inblks,
                                              size_t nblks)
{
  static const byte blake2b_sigma[12][16] =
  {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
  };
  const byte* in = inblks;
  u64 m[16];
  u64 v[16];

  while (nblks--)
    {
      /* Increment counter */
      blake2b_increment_counter (S, BLAKE2B_BLOCKBYTES);

      /* Compress */
      m[0] = buf_get_le64 (in + 0 * sizeof(m[0]));
      m[1] = buf_get_le64 (in + 1 * sizeof(m[0]));
      m[2] = buf_get_le64 (in + 2 * sizeof(m[0]));
      m[3] = buf_get_le64 (in + 3 * sizeof(m[0]));
      m[4] = buf_get_le64 (in + 4 * sizeof(m[0]));
      m[5] = buf_get_le64 (in + 5 * sizeof(m[0]));
      m[6] = buf_get_le64 (in + 6 * sizeof(m[0]));
      m[7] = buf_get_le64 (in + 7 * sizeof(m[0]));
      m[8] = buf_get_le64 (in + 8 * sizeof(m[0]));
      m[9] = buf_get_le64 (in + 9 * sizeof(m[0]));
      m[10] = buf_get_le64 (in + 10 * sizeof(m[0]));
      m[11] = buf_get_le64 (in + 11 * sizeof(m[0]));
      m[12] = buf_get_le64 (in + 12 * sizeof(m[0]));
      m[13] = buf_get_le64 (in + 13 * sizeof(m[0]));
      m[14] = buf_get_le64 (in + 14 * sizeof(m[0]));
      m[15] = buf_get_le64 (in + 15 * sizeof(m[0]));

      v[ 0] = S->h[0];
      v[ 1] = S->h[1];
      v[ 2] = S->h[2];
      v[ 3] = S->h[3];
      v[ 4] = S->h[4];
      v[ 5] = S->h[5];
      v[ 6] = S->h[6];
      v[ 7] = S->h[7];
      v[ 8] = blake2b_IV[0];
      v[ 9] = blake2b_IV[1];
      v[10] = blake2b_IV[2];
      v[11] = blake2b_IV[3];
      v[12] = blake2b_IV[4] ^ S->t[0];
      v[13] = blake2b_IV[5] ^ S->t[1];
      v[14] = blake2b_IV[6] ^ S->f[0];
      v[15] = blake2b_IV[7] ^ S->f[1];

#define G(r,i,a,b,c,d)                      \
  do {                                      \
    a = a + b + m[blake2b_sigma[r][2*i+0]]; \
    d = rotr64(d ^ a, 32);                  \
    c = c + d;                              \
    b = rotr64(b ^ c, 24);                  \
    a = a + b + m[blake2b_sigma[r][2*i+1]]; \
    d = rotr64(d ^ a, 16);                  \
    c = c + d;                              \
    b = rotr64(b ^ c, 63);                  \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)

      ROUND(0);
      ROUND(1);
      ROUND(2);
      ROUND(3);
      ROUND(4);
      ROUND(5);
      ROUND(6);
      ROUND(7);
      ROUND(8);
      ROUND(9);
      ROUND(10);
      ROUND(11);

#undef G
#undef ROUND

      S->h[0] = S->h[0] ^ v[0] ^ v[0 + 8];
      S->h[1] = S->h[1] ^ v[1] ^ v[1 + 8];
      S->h[2] = S->h[2] ^ v[2] ^ v[2 + 8];
      S->h[3] = S->h[3] ^ v[3] ^ v[3 + 8];
      S->h[4] = S->h[4] ^ v[4] ^ v[4 + 8];
      S->h[5] = S->h[5] ^ v[5] ^ v[5 + 8];
      S->h[6] = S->h[6] ^ v[6] ^ v[6 + 8];
      S->h[7] = S->h[7] ^ v[7] ^ v[7 + 8];

      in += BLAKE2B_BLOCKBYTES;
    }

  return sizeof(void *) * 4 + sizeof(u64) * 16 * 2;
}

static unsigned int blake2b_transform(void *ctx, const void *inblks,
                                      size_t nblks)
{
  BLAKE2B_CONTEXT *c = ctx;
  unsigned int nburn;

  if (0)
    {}
#ifdef USE_AVX512
  else if (c->use_avx512)
    nburn = _gcry_blake2b_transform_amd64_avx512(&c->state, inblks, nblks);
#endif
#ifdef USE_AVX2
  else if (c->use_avx2)
    nburn = _gcry_blake2b_transform_amd64_avx2(&c->state, inblks, nblks);
#endif
  else
    nburn = blake2b_transform_generic(&c->state, inblks, nblks);

  if (nburn)
    nburn += ASM_EXTRA_STACK;

  return nburn;
}

static void blake2b_final(void *ctx)
{
  BLAKE2B_CONTEXT *c = ctx;
  BLAKE2B_STATE *S = &c->state;
  unsigned int burn;
  size_t i;

  gcry_assert (sizeof(c->buf) >= c->outlen);
  if (blake2b_is_lastblock(S))
    return;

  if (c->buflen < BLAKE2B_BLOCKBYTES)
    memset (c->buf + c->buflen, 0, BLAKE2B_BLOCKBYTES - c->buflen); /* Padding */
  blake2b_set_lastblock (S);
  blake2b_increment_counter (S, (int)c->buflen - BLAKE2B_BLOCKBYTES);
  burn = blake2b_transform (ctx, c->buf, 1);

  /* Output full hash to buffer */
  for (i = 0; i < 8; ++i)
    buf_put_le64 (c->buf + sizeof(S->h[i]) * i, S->h[i]);

  /* Zero out extra buffer bytes. */
  if (c->outlen < sizeof(c->buf))
    memset (c->buf + c->outlen, 0, sizeof(c->buf) - c->outlen);

  if (burn)
    _gcry_burn_stack (burn);
}

static byte *blake2b_read(void *ctx)
{
  BLAKE2B_CONTEXT *c = ctx;
  return c->buf;
}

static void blake2b_write(void *ctx, const void *inbuf, size_t inlen)
{
  BLAKE2B_CONTEXT *c = ctx;
  BLAKE2B_STATE *S = &c->state;
  blake2_write(S, inbuf, inlen, c->buf, &c->buflen, BLAKE2B_BLOCKBYTES,
	       blake2b_transform);
}

static inline void blake2b_init_param(BLAKE2B_STATE *S,
				      const struct blake2b_param_s *P)
{
  const byte *p = (const byte *)P;
  size_t i;

  /* init xors IV with input parameter block */

  /* IV XOR ParamBlock */
  for (i = 0; i < 8; ++i)
    S->h[i] = blake2b_IV[i] ^ buf_get_le64(p + sizeof(S->h[i]) * i);
}

static inline gcry_err_code_t blake2b_init(BLAKE2B_CONTEXT *ctx,
					   const byte *key, size_t keylen)
{
  struct blake2b_param_s P[1] = { { 0, } };
  BLAKE2B_STATE *S = &ctx->state;

  if (!ctx->outlen || ctx->outlen > BLAKE2B_OUTBYTES)
    return GPG_ERR_INV_ARG;
  if (sizeof(P[0]) != sizeof(u64) * 8)
    return GPG_ERR_INTERNAL;
  if (keylen && (!key || keylen > BLAKE2B_KEYBYTES))
    return GPG_ERR_INV_KEYLEN;

  P->digest_length = ctx->outlen;
  P->key_length = keylen;
  P->fanout = 1;
  P->depth = 1;

  blake2b_init_param (S, P);
  wipememory (P, sizeof(P));

  if (key)
    {
      blake2b_write (ctx, key, keylen);
      blake2b_write (ctx, zero_block, BLAKE2B_BLOCKBYTES - keylen);
    }

  return 0;
}

static gcry_err_code_t blake2b_init_ctx(void *ctx, unsigned int flags,
					const byte *key, size_t keylen,
					unsigned int dbits)
{
  BLAKE2B_CONTEXT *c = ctx;
  unsigned int features = _gcry_get_hw_features ();

  (void)features;
  (void)flags;

  memset (c, 0, sizeof (*c));

#ifdef USE_AVX2
  c->use_avx2 = !!(features & HWF_INTEL_AVX2);
#endif
#ifdef USE_AVX512
  c->use_avx512 = !!(features & HWF_INTEL_AVX512);
#endif

  c->outlen = dbits / 8;
  c->buflen = 0;
  return blake2b_init(c, key, keylen);
}

/* Variable-length Hash Function H'.  */
gcry_err_code_t
blake2b_vl_hash (const void *in, size_t inlen, size_t outputlen, void *output)
{
  gcry_err_code_t ec;
  BLAKE2B_CONTEXT ctx;
  unsigned char buf[4];

  ec = blake2b_init_ctx (&ctx, 0, NULL, 0,
                         (outputlen < 64 ? outputlen: 64)*8);
  if (ec)
    return ec;

  buf_put_le32 (buf, outputlen);
  blake2b_write (&ctx, buf, 4);
  blake2b_write (&ctx, in, inlen);
  blake2b_final (&ctx);

  if (outputlen <= 64)
    memcpy (output, ctx.buf, outputlen);
  else
    {
      int r = (outputlen-1)/32 - 1;
      unsigned int remained = outputlen - 32*r;
      int i;
      unsigned char d[64];

      i = 0;
      while (1)
        {
          memcpy (d, ctx.buf, 64);
          memcpy ((unsigned char *)output+i*32, d, 32);

          if (++i >= r)
            break;

          ec = blake2b_init_ctx (&ctx, 0, NULL, 0, 64*8);
          if (ec)
            return ec;

          blake2b_write (&ctx, d, 64);
          blake2b_final (&ctx);
        }

      ec = blake2b_init_ctx (&ctx, 0, NULL, 0, remained*8);
      if (ec)
        return ec;

      blake2b_write (&ctx, d, 64);
      blake2b_final (&ctx);

      memcpy ((unsigned char *)output+r*32, ctx.buf, remained);
    }

  wipememory (buf, sizeof (buf));
  wipememory (&ctx, sizeof (ctx));
  return 0;
}

/* ==== end blake2b core ==== */

/*
 * BLAKE2b-512 over an iov vector.  libgcrypt exposes this through
 * _gcry_digest_spec_blake2b_512.hash_buffers, but grub declares that
 * spec field as a plain void*, so argon2 (gcry_kdf.c) calls this typed
 * helper directly instead.
 */
void
grub_blake2b_512_hash_buffers (void *out, const gcry_buffer_t *iov, int iovcnt)
{
  BLAKE2B_CONTEXT hd;

  blake2b_init_ctx (&hd, 0, NULL, 0, 512);
  for (; iovcnt > 0; iov++, iovcnt--)
    blake2b_write (&hd, (const char *) iov[0].data + iov[0].off, iov[0].len);
  blake2b_final (&hd);
  grub_memcpy (out, blake2b_read (&hd), 512 / 8);
}
