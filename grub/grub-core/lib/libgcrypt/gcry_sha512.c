/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/types.h>
#include <grub/crypto.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include "gcry_wrap.h"
#include "hash-common.h"

GRUB_MOD_LICENSE("GPLv3+");

#define U64_C(c) (c ## ULL)
#define memset grub_memset
#define memcpy grub_memcpy

/* sha512.c - SHA384 and SHA512 hash functions
 * Copyright (C) 2003, 2008, 2009 Free Software Foundation, Inc.
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

static unsigned int
do_transform_generic(void* context, const unsigned char* data, size_t nblks);

/*  Test vectors from FIPS-180-2:
 *
 *  "abc"
 * 384:
 *  CB00753F 45A35E8B B5A03D69 9AC65007 272C32AB 0EDED163
 *  1A8B605A 43FF5BED 8086072B A1E7CC23 58BAECA1 34C825A7
 * 512:
 *  DDAF35A1 93617ABA CC417349 AE204131 12E6FA4E 89A97EA2 0A9EEEE6 4B55D39A
 *  2192992A 274FC1A8 36BA3C23 A3FEEBBD 454D4423 643CE80E 2A9AC94F A54CA49F
 *
 *  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
 * 384:
 *  09330C33 F71147E8 3D192FC7 82CD1B47 53111B17 3B3B05D2
 *  2FA08086 E3B0F712 FCC7C71A 557E2DB9 66C3E9FA 91746039
 * 512:
 *  8E959B75 DAE313DA 8CF4F728 14FC143F 8F7779C6 EB9F7FA1 7299AEAD B6889018
 *  501D289E 4900F7E4 331B99DE C4B5433A C7D329EE B6DD2654 5E96E55B 874BE909
 *
 *  "a" x 1000000
 * 384:
 *  9D0E1809 716474CB 086E834E 310A4A1C ED149E9C 00F24852
 *  7972CEC5 704C2A5B 07B8B3DC 38ECC4EB AE97DDD8 7F3D8985
 * 512:
 *  E718483D 0CE76964 4E2E42C7 BC15B463 8E1F98B1 3B204428 5632A803 AFA973EB
 *  DE0FF244 877EA60A 4CB0432C E577C31B EB009C5C 2C49AA2E 4EADB217 AD8CC09B
 */

/* Helper macro to force alignment to 64 bytes.  */
#define ATTR_ALIGNED_64

typedef struct
{
  u64 h[8];
} SHA512_STATE;

typedef struct
{
  gcry_md_block_ctx_t bctx;
  SHA512_STATE state;
} SHA512_CONTEXT;


static ATTR_ALIGNED_64 const u64 k[] =
  {
    U64_C(0x428a2f98d728ae22), U64_C(0x7137449123ef65cd),
    U64_C(0xb5c0fbcfec4d3b2f), U64_C(0xe9b5dba58189dbbc),
    U64_C(0x3956c25bf348b538), U64_C(0x59f111f1b605d019),
    U64_C(0x923f82a4af194f9b), U64_C(0xab1c5ed5da6d8118),
    U64_C(0xd807aa98a3030242), U64_C(0x12835b0145706fbe),
    U64_C(0x243185be4ee4b28c), U64_C(0x550c7dc3d5ffb4e2),
    U64_C(0x72be5d74f27b896f), U64_C(0x80deb1fe3b1696b1),
    U64_C(0x9bdc06a725c71235), U64_C(0xc19bf174cf692694),
    U64_C(0xe49b69c19ef14ad2), U64_C(0xefbe4786384f25e3),
    U64_C(0x0fc19dc68b8cd5b5), U64_C(0x240ca1cc77ac9c65),
    U64_C(0x2de92c6f592b0275), U64_C(0x4a7484aa6ea6e483),
    U64_C(0x5cb0a9dcbd41fbd4), U64_C(0x76f988da831153b5),
    U64_C(0x983e5152ee66dfab), U64_C(0xa831c66d2db43210),
    U64_C(0xb00327c898fb213f), U64_C(0xbf597fc7beef0ee4),
    U64_C(0xc6e00bf33da88fc2), U64_C(0xd5a79147930aa725),
    U64_C(0x06ca6351e003826f), U64_C(0x142929670a0e6e70),
    U64_C(0x27b70a8546d22ffc), U64_C(0x2e1b21385c26c926),
    U64_C(0x4d2c6dfc5ac42aed), U64_C(0x53380d139d95b3df),
    U64_C(0x650a73548baf63de), U64_C(0x766a0abb3c77b2a8),
    U64_C(0x81c2c92e47edaee6), U64_C(0x92722c851482353b),
    U64_C(0xa2bfe8a14cf10364), U64_C(0xa81a664bbc423001),
    U64_C(0xc24b8b70d0f89791), U64_C(0xc76c51a30654be30),
    U64_C(0xd192e819d6ef5218), U64_C(0xd69906245565a910),
    U64_C(0xf40e35855771202a), U64_C(0x106aa07032bbd1b8),
    U64_C(0x19a4c116b8d2d0c8), U64_C(0x1e376c085141ab53),
    U64_C(0x2748774cdf8eeb99), U64_C(0x34b0bcb5e19b48a8),
    U64_C(0x391c0cb3c5c95a63), U64_C(0x4ed8aa4ae3418acb),
    U64_C(0x5b9cca4f7763e373), U64_C(0x682e6ff3d6b2b8a3),
    U64_C(0x748f82ee5defb2fc), U64_C(0x78a5636f43172f60),
    U64_C(0x84c87814a1f0ab72), U64_C(0x8cc702081a6439ec),
    U64_C(0x90befffa23631e28), U64_C(0xa4506cebde82bde9),
    U64_C(0xbef9a3f7b2c67915), U64_C(0xc67178f2e372532b),
    U64_C(0xca273eceea26619c), U64_C(0xd186b8c721c0c207),
    U64_C(0xeada7dd6cde0eb1e), U64_C(0xf57d4f7fee6ed178),
    U64_C(0x06f067aa72176fba), U64_C(0x0a637dc5a2c898a6),
    U64_C(0x113f9804bef90dae), U64_C(0x1b710b35131c471b),
    U64_C(0x28db77f523047d84), U64_C(0x32caab7b40c72493),
    U64_C(0x3c9ebe0a15c9bebc), U64_C(0x431d67c49c100d4c),
    U64_C(0x4cc5d4becb3e42b6), U64_C(0x597f299cfc657e2a),
    U64_C(0x5fcb6fab3ad6faec), U64_C(0x6c44198c4a475817)
  };

static void
sha512_init_common (SHA512_CONTEXT *ctx, unsigned int flags)
{
  unsigned int features = _gcry_get_hw_features ();

  (void)flags;
  (void)k;

  ctx->bctx.nblocks = 0;
  ctx->bctx.nblocks_high = 0;
  ctx->bctx.count = 0;
  ctx->bctx.blocksize_shift = _gcry_ctz(128);

  /* Order of feature checks is important here; last match will be
   * selected.  Keep slower implementations at the top and faster at
   * the bottom.  */
  ctx->bctx.bwrite = do_transform_generic;

  (void)features;
}


static void
sha512_init (void *context, unsigned int flags)
{
  SHA512_CONTEXT *ctx = context;
  SHA512_STATE *hd = &ctx->state;

  hd->h[0] = U64_C(0x6a09e667f3bcc908);
  hd->h[1] = U64_C(0xbb67ae8584caa73b);
  hd->h[2] = U64_C(0x3c6ef372fe94f82b);
  hd->h[3] = U64_C(0xa54ff53a5f1d36f1);
  hd->h[4] = U64_C(0x510e527fade682d1);
  hd->h[5] = U64_C(0x9b05688c2b3e6c1f);
  hd->h[6] = U64_C(0x1f83d9abfb41bd6b);
  hd->h[7] = U64_C(0x5be0cd19137e2179);

  sha512_init_common (ctx, flags);
}

static void
sha384_init (void *context, unsigned int flags)
{
  SHA512_CONTEXT *ctx = context;
  SHA512_STATE *hd = &ctx->state;

  hd->h[0] = U64_C(0xcbbb9d5dc1059ed8);
  hd->h[1] = U64_C(0x629a292a367cd507);
  hd->h[2] = U64_C(0x9159015a3070dd17);
  hd->h[3] = U64_C(0x152fecd8f70e5939);
  hd->h[4] = U64_C(0x67332667ffc00b31);
  hd->h[5] = U64_C(0x8eb44a8768581511);
  hd->h[6] = U64_C(0xdb0c2e0d64f98fa7);
  hd->h[7] = U64_C(0x47b5481dbefa4fa4);

  sha512_init_common (ctx, flags);
}


static void
sha512_256_init (void *context, unsigned int flags)
{
  SHA512_CONTEXT *ctx = context;
  SHA512_STATE *hd = &ctx->state;

  hd->h[0] = U64_C(0x22312194fc2bf72c);
  hd->h[1] = U64_C(0x9f555fa3c84c64c2);
  hd->h[2] = U64_C(0x2393b86b6f53b151);
  hd->h[3] = U64_C(0x963877195940eabd);
  hd->h[4] = U64_C(0x96283ee2a88effe3);
  hd->h[5] = U64_C(0xbe5e1e2553863992);
  hd->h[6] = U64_C(0x2b0199fc2c85b8aa);
  hd->h[7] = U64_C(0x0eb72ddc81c52ca2);

  sha512_init_common (ctx, flags);
}


static void
sha512_224_init (void *context, unsigned int flags)
{
  SHA512_CONTEXT *ctx = context;
  SHA512_STATE *hd = &ctx->state;

  hd->h[0] = U64_C(0x8c3d37c819544da2);
  hd->h[1] = U64_C(0x73e1996689dcd4d6);
  hd->h[2] = U64_C(0x1dfab7ae32ff9c82);
  hd->h[3] = U64_C(0x679dd514582f9fcf);
  hd->h[4] = U64_C(0x0f6d2b697bd44da8);
  hd->h[5] = U64_C(0x77e36f7304c48942);
  hd->h[6] = U64_C(0x3f9d85a86a1d36c8);
  hd->h[7] = U64_C(0x1112e6ad91d692a1);

  sha512_init_common (ctx, flags);
}



#ifndef USE_ARM_ASM

static inline u64
ROTR (u64 x, u64 n)
{
  return ((x >> n) | (x << (64 - n)));
}

static inline u64
Ch (u64 x, u64 y, u64 z)
{
  return ((x & y) ^ ( ~x & z));
}

static inline u64
Maj (u64 x, u64 y, u64 z)
{
  return ((x & y) ^ (x & z) ^ (y & z));
}

static inline u64
Sum0 (u64 x)
{
  return (ROTR (x, 28) ^ ROTR (x, 34) ^ ROTR (x, 39));
}

static inline u64
Sum1 (u64 x)
{
  return (ROTR (x, 14) ^ ROTR (x, 18) ^ ROTR (x, 41));
}

/****************
 * Transform the message W which consists of 16 64-bit-words
 */
static unsigned int
do_transform_generic (void *context, const unsigned char *data, size_t nblks)
{
  SHA512_CONTEXT *ctx = context;
  SHA512_STATE *hd = &ctx->state;

  do
    {
      u64 a, b, c, d, e, f, g, h;
      u64 w[16];
      int t;

      /* get values from the chaining vars */
      a = hd->h[0];
      b = hd->h[1];
      c = hd->h[2];
      d = hd->h[3];
      e = hd->h[4];
      f = hd->h[5];
      g = hd->h[6];
      h = hd->h[7];

      for ( t = 0; t < 16; t++ )
        w[t] = buf_get_be64(data + t * 8);

#define S0(x) (ROTR((x),1) ^ ROTR((x),8) ^ ((x)>>7))
#define S1(x) (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))

      for (t = 0; t < 80 - 16; )
        {
          u64 t1, t2;

          t1 = h + Sum1 (e) + Ch (e, f, g) + k[t] + w[0];
          w[0] += S1 (w[14]) + w[9] + S0 (w[1]);
          t2 = Sum0 (a) + Maj (a, b, c);
          d += t1;
          h = t1 + t2;

          t1 = g + Sum1 (d) + Ch (d, e, f) + k[t+1] + w[1];
          w[1] += S1 (w[15]) + w[10] + S0 (w[2]);
          t2 = Sum0 (h) + Maj (h, a, b);
          c += t1;
          g  = t1 + t2;

          t1 = f + Sum1 (c) + Ch (c, d, e) + k[t+2] + w[2];
          w[2] += S1 (w[0]) + w[11] + S0 (w[3]);
          t2 = Sum0 (g) + Maj (g, h, a);
          b += t1;
          f  = t1 + t2;

          t1 = e + Sum1 (b) + Ch (b, c, d) + k[t+3] + w[3];
          w[3] += S1 (w[1]) + w[12] + S0 (w[4]);
          t2 = Sum0 (f) + Maj (f, g, h);
          a += t1;
          e  = t1 + t2;

          t1 = d + Sum1 (a) + Ch (a, b, c) + k[t+4] + w[4];
          w[4] += S1 (w[2]) + w[13] + S0 (w[5]);
          t2 = Sum0 (e) + Maj (e, f, g);
          h += t1;
          d  = t1 + t2;

          t1 = c + Sum1 (h) + Ch (h, a, b) + k[t+5] + w[5];
          w[5] += S1 (w[3]) + w[14] + S0 (w[6]);
          t2 = Sum0 (d) + Maj (d, e, f);
          g += t1;
          c  = t1 + t2;

          t1 = b + Sum1 (g) + Ch (g, h, a) + k[t+6] + w[6];
          w[6] += S1 (w[4]) + w[15] + S0 (w[7]);
          t2 = Sum0 (c) + Maj (c, d, e);
          f += t1;
          b  = t1 + t2;

          t1 = a + Sum1 (f) + Ch (f, g, h) + k[t+7] + w[7];
          w[7] += S1 (w[5]) + w[0] + S0 (w[8]);
          t2 = Sum0 (b) + Maj (b, c, d);
          e += t1;
          a  = t1 + t2;

          t1 = h + Sum1 (e) + Ch (e, f, g) + k[t+8] + w[8];
          w[8] += S1 (w[6]) + w[1] + S0 (w[9]);
          t2 = Sum0 (a) + Maj (a, b, c);
          d += t1;
          h  = t1 + t2;

          t1 = g + Sum1 (d) + Ch (d, e, f) + k[t+9] + w[9];
          w[9] += S1 (w[7]) + w[2] + S0 (w[10]);
          t2 = Sum0 (h) + Maj (h, a, b);
          c += t1;
          g  = t1 + t2;

          t1 = f + Sum1 (c) + Ch (c, d, e) + k[t+10] + w[10];
          w[10] += S1 (w[8]) + w[3] + S0 (w[11]);
          t2 = Sum0 (g) + Maj (g, h, a);
          b += t1;
          f  = t1 + t2;

          t1 = e + Sum1 (b) + Ch (b, c, d) + k[t+11] + w[11];
          w[11] += S1 (w[9]) + w[4] + S0 (w[12]);
          t2 = Sum0 (f) + Maj (f, g, h);
          a += t1;
          e  = t1 + t2;

          t1 = d + Sum1 (a) + Ch (a, b, c) + k[t+12] + w[12];
          w[12] += S1 (w[10]) + w[5] + S0 (w[13]);
          t2 = Sum0 (e) + Maj (e, f, g);
          h += t1;
          d  = t1 + t2;

          t1 = c + Sum1 (h) + Ch (h, a, b) + k[t+13] + w[13];
          w[13] += S1 (w[11]) + w[6] + S0 (w[14]);
          t2 = Sum0 (d) + Maj (d, e, f);
          g += t1;
          c  = t1 + t2;

          t1 = b + Sum1 (g) + Ch (g, h, a) + k[t+14] + w[14];
          w[14] += S1 (w[12]) + w[7] + S0 (w[15]);
          t2 = Sum0 (c) + Maj (c, d, e);
          f += t1;
          b  = t1 + t2;

          t1 = a + Sum1 (f) + Ch (f, g, h) + k[t+15] + w[15];
          w[15] += S1 (w[13]) + w[8] + S0 (w[0]);
          t2 = Sum0 (b) + Maj (b, c, d);
          e += t1;
          a  = t1 + t2;

          t += 16;
        }

      for (; t < 80; )
        {
          u64 t1, t2;

          t1 = h + Sum1 (e) + Ch (e, f, g) + k[t] + w[0];
          t2 = Sum0 (a) + Maj (a, b, c);
          d += t1;
          h  = t1 + t2;

          t1 = g + Sum1 (d) + Ch (d, e, f) + k[t+1] + w[1];
          t2 = Sum0 (h) + Maj (h, a, b);
          c += t1;
          g  = t1 + t2;

          t1 = f + Sum1 (c) + Ch (c, d, e) + k[t+2] + w[2];
          t2 = Sum0 (g) + Maj (g, h, a);
          b += t1;
          f  = t1 + t2;

          t1 = e + Sum1 (b) + Ch (b, c, d) + k[t+3] + w[3];
          t2 = Sum0 (f) + Maj (f, g, h);
          a += t1;
          e  = t1 + t2;

          t1 = d + Sum1 (a) + Ch (a, b, c) + k[t+4] + w[4];
          t2 = Sum0 (e) + Maj (e, f, g);
          h += t1;
          d  = t1 + t2;

          t1 = c + Sum1 (h) + Ch (h, a, b) + k[t+5] + w[5];
          t2 = Sum0 (d) + Maj (d, e, f);
          g += t1;
          c  = t1 + t2;

          t1 = b + Sum1 (g) + Ch (g, h, a) + k[t+6] + w[6];
          t2 = Sum0 (c) + Maj (c, d, e);
          f += t1;
          b  = t1 + t2;

          t1 = a + Sum1 (f) + Ch (f, g, h) + k[t+7] + w[7];
          t2 = Sum0 (b) + Maj (b, c, d);
          e += t1;
          a  = t1 + t2;

          t1 = h + Sum1 (e) + Ch (e, f, g) + k[t+8] + w[8];
          t2 = Sum0 (a) + Maj (a, b, c);
          d += t1;
          h  = t1 + t2;

          t1 = g + Sum1 (d) + Ch (d, e, f) + k[t+9] + w[9];
          t2 = Sum0 (h) + Maj (h, a, b);
          c += t1;
          g  = t1 + t2;

          t1 = f + Sum1 (c) + Ch (c, d, e) + k[t+10] + w[10];
          t2 = Sum0 (g) + Maj (g, h, a);
          b += t1;
          f  = t1 + t2;

          t1 = e + Sum1 (b) + Ch (b, c, d) + k[t+11] + w[11];
          t2 = Sum0 (f) + Maj (f, g, h);
          a += t1;
          e  = t1 + t2;

          t1 = d + Sum1 (a) + Ch (a, b, c) + k[t+12] + w[12];
          t2 = Sum0 (e) + Maj (e, f, g);
          h += t1;
          d  = t1 + t2;

          t1 = c + Sum1 (h) + Ch (h, a, b) + k[t+13] + w[13];
          t2 = Sum0 (d) + Maj (d, e, f);
          g += t1;
          c  = t1 + t2;

          t1 = b + Sum1 (g) + Ch (g, h, a) + k[t+14] + w[14];
          t2 = Sum0 (c) + Maj (c, d, e);
          f += t1;
          b  = t1 + t2;

          t1 = a + Sum1 (f) + Ch (f, g, h) + k[t+15] + w[15];
          t2 = Sum0 (b) + Maj (b, c, d);
          e += t1;
          a  = t1 + t2;

          t += 16;
        }

      /* Update chaining vars.  */
      hd->h[0] += a;
      hd->h[1] += b;
      hd->h[2] += c;
      hd->h[3] += d;
      hd->h[4] += e;
      hd->h[5] += f;
      hd->h[6] += g;
      hd->h[7] += h;

      data += 128;
    }
  while (--nblks);

  return (8 + 16) * sizeof(u64) + sizeof(u32) + 3 * sizeof(void*);
}
#endif /*!USE_ARM_ASM*/


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 64 bytes representing the digest.  When used for sha384,
 * we take the leftmost 48 of those bytes.
 */

static void
sha512_final (void *context)
{
  SHA512_CONTEXT *hd = context;
  unsigned int burn;
  u64 t, th, msb, lsb;
  byte *p;

  t = hd->bctx.nblocks;
  /* if (sizeof t == sizeof hd->bctx.nblocks) */
  th = hd->bctx.nblocks_high;
  /* else */
  /*   th = hd->bctx.nblocks >> 64; In case we ever use u128  */

  /* multiply by 128 to make a byte count */
  lsb = t << 7;
  msb = (th << 7) | (t >> 57);
  /* add the count */
  t = lsb;
  if ((lsb += hd->bctx.count) < t)
    msb++;
  /* multiply by 8 to make a bit count */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 61;

  if (0)
    { }
  else
    {
      if (hd->bctx.count < 112)
	{
	  /* enough room */
	  hd->bctx.buf[hd->bctx.count++] = 0x80;  /* pad */
	  if (hd->bctx.count < 112)
	    memset (&hd->bctx.buf[hd->bctx.count], 0, 112 - hd->bctx.count);
	}
      else
	{
	  /* need one extra block */
	  hd->bctx.buf[hd->bctx.count++] = 0x80;  /* pad character */
	  if (hd->bctx.count < 128)
	    memset (&hd->bctx.buf[hd->bctx.count], 0, 128 - hd->bctx.count);
	  hd->bctx.count = 128;
	  _gcry_md_block_write (context, NULL, 0); /* flush */
	  memset (hd->bctx.buf, 0, 112);  /* fill next block with zeroes */
	}
      /* append the 128 bit count */
      buf_put_be64(hd->bctx.buf + 112, msb);
      buf_put_be64(hd->bctx.buf + 120, lsb);
      burn = (*hd->bctx.bwrite) (hd, hd->bctx.buf, 1);
    }

  p = hd->bctx.buf;
#define X(a) do { buf_put_be64(p, hd->state.h[a]); p += 8; } while (0)
  X (0);
  X (1);
  X (2);
  X (3);
  X (4);
  X (5);
  /* Note that these last two chunks are included even for SHA384.
     We just ignore them. */
  X (6);
  X (7);
#undef X

  hd->bctx.count = 0;

  _gcry_burn_stack (burn);
}

static byte *
sha512_read (void *context)
{
  SHA512_CONTEXT *hd = (SHA512_CONTEXT *) context;
  return hd->bctx.buf;
}


/* Shortcut functions which puts the hash value of the supplied buffer iov
 * into outbuf which must have a size of 64 bytes.  */
#define _gcry_sha512_hash_buffers 0


/* Shortcut functions which puts the hash value of the supplied buffer iov
 * into outbuf which must have a size of 48 bytes.  */
#define _gcry_sha384_hash_buffers 0


/* Shortcut functions which puts the hash value of the supplied buffer iov
 * into outbuf which must have a size of 32 bytes.  */
#define _gcry_sha512_256_hash_buffers 0


/* Shortcut functions which puts the hash value of the supplied buffer iov
 * into outbuf which must have a size of 28 bytes.  */
#define _gcry_sha512_224_hash_buffers 0

/* Run a full self-test for ALGO and return 0 on success.  */
#define run_selftests 0

static const byte sha512_asn[] =	/* Object ID is 2.16.840.1.101.3.4.2.3 */
  {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
  };

static const gcry_md_oid_spec_t oid_spec_sha512[] =
  {
    { "2.16.840.1.101.3.4.2.3" },

    /* PKCS#1 sha512WithRSAEncryption */
    { "1.2.840.113549.1.1.13" },
    /* ANSI X9.62  ecdsaWithSHA512 */
    { "1.2.840.10045.4.3.4" },

    { NULL }
  };

gcry_md_spec_t _gcry_digest_spec_sha512 =
  {
    GCRY_MD_SHA512, {0, 1},
    "SHA512", sha512_asn, DIM (sha512_asn), oid_spec_sha512, 64,
    sha512_init, _gcry_md_block_write, sha512_final, sha512_read, NULL,
    _gcry_sha512_hash_buffers,
    sizeof (SHA512_CONTEXT),
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_sha512")
    .blocksize = 128
  };

static const byte sha384_asn[] =	/* Object ID is 2.16.840.1.101.3.4.2.2 */
  {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
  };

static const gcry_md_oid_spec_t oid_spec_sha384[] =
  {
    { "2.16.840.1.101.3.4.2.2" },

    /* PKCS#1 sha384WithRSAEncryption */
    { "1.2.840.113549.1.1.12" },

    /* SHA384WithECDSA: RFC 7427 (A.3.3.) */
    { "1.2.840.10045.4.3.3" },

    /* ANSI X9.62  ecdsaWithSHA384 */
    { "1.2.840.10045.4.3.3" },

    { NULL },
  };

gcry_md_spec_t _gcry_digest_spec_sha384 =
  {
    GCRY_MD_SHA384, {0, 1},
    "SHA384", sha384_asn, DIM (sha384_asn), oid_spec_sha384, 48,
    sha384_init, _gcry_md_block_write, sha512_final, sha512_read, NULL,
    _gcry_sha384_hash_buffers,
    sizeof (SHA512_CONTEXT),
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_sha512")
    .blocksize = 128
  };

static const byte sha512_256_asn[] =
  {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05,
    0x00, 0x04, 0x20
  };

static const gcry_md_oid_spec_t oid_spec_sha512_256[] =
  {
    { "2.16.840.1.101.3.4.2.6" },

    { NULL },
  };

gcry_md_spec_t _gcry_digest_spec_sha512_256 =
  {
    GCRY_MD_SHA512_256, {0, 1},
    "SHA512_256", sha512_256_asn, DIM (sha512_256_asn), oid_spec_sha512_256, 32,
    sha512_256_init, _gcry_md_block_write, sha512_final, sha512_read, NULL,
    _gcry_sha512_256_hash_buffers,
    sizeof (SHA512_CONTEXT),
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_sha512")
    .blocksize = 128
  };

static const byte sha512_224_asn[] =
  {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05,
    0x00, 0x04, 0x1c
  };

static const gcry_md_oid_spec_t oid_spec_sha512_224[] =
  {
    { "2.16.840.1.101.3.4.2.5" },

    { NULL },
  };

gcry_md_spec_t _gcry_digest_spec_sha512_224 =
  {
    GCRY_MD_SHA512_224, {0, 1},
    "SHA512_224", sha512_224_asn, DIM (sha512_224_asn), oid_spec_sha512_224, 28,
    sha512_224_init, _gcry_md_block_write, sha512_final, sha512_read, NULL,
    _gcry_sha512_224_hash_buffers,
    sizeof (SHA512_CONTEXT),
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_sha512")
    .blocksize = 128
  };


GRUB_MOD_INIT(gcry_sha512)
{
  grub_md_register (&_gcry_digest_spec_sha512);
  grub_md_register (&_gcry_digest_spec_sha384);
  grub_md_register (&_gcry_digest_spec_sha512_256);
  grub_md_register (&_gcry_digest_spec_sha512_224);
}

GRUB_MOD_FINI(gcry_sha512)
{
  grub_md_unregister (&_gcry_digest_spec_sha512);
  grub_md_unregister (&_gcry_digest_spec_sha384);
  grub_md_unregister (&_gcry_digest_spec_sha512_256);
  grub_md_unregister (&_gcry_digest_spec_sha512_224);
}
