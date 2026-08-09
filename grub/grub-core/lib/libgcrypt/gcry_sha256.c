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

#define memset grub_memset
#define memcpy grub_memcpy

/* sha256.c - SHA256 hash function
 * Copyright (C) 2003, 2006, 2008, 2009 Free Software Foundation, Inc.
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


/*  Test vectors:

    "abc"
    SHA224: 23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7
    SHA256: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad

    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    SHA224: 75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525
    SHA256: 248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1

    "a" one million times
    SHA224: 20794655 980c91d8 bbb4c1ea 97618a4b f03f4258 1948b2ee 4ee7ad67
    SHA256: cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0

 */

typedef struct {
  gcry_md_block_ctx_t bctx;
  u32  h[8];
} SHA256_CONTEXT;


static unsigned int
do_transform_generic (void *ctx, const unsigned char *data, size_t nblks);


static void
sha256_common_init (SHA256_CONTEXT *hd)
{
  unsigned int features = _gcry_get_hw_features ();

  hd->bctx.nblocks = 0;
  hd->bctx.nblocks_high = 0;
  hd->bctx.count = 0;
  hd->bctx.blocksize_shift = _gcry_ctz(64);

  /* Order of feature checks is important here; last match will be
   * selected.  Keep slower implementations at the top and faster at
   * the bottom.  */
  hd->bctx.bwrite = do_transform_generic;

  (void)features;
}


static void
sha256_init (void *context, unsigned int flags)
{
  SHA256_CONTEXT *hd = context;

  (void)flags;

  hd->h[0] = 0x6a09e667;
  hd->h[1] = 0xbb67ae85;
  hd->h[2] = 0x3c6ef372;
  hd->h[3] = 0xa54ff53a;
  hd->h[4] = 0x510e527f;
  hd->h[5] = 0x9b05688c;
  hd->h[6] = 0x1f83d9ab;
  hd->h[7] = 0x5be0cd19;

  sha256_common_init (hd);
}


static void
sha224_init (void *context, unsigned int flags)
{
  SHA256_CONTEXT *hd = context;

  (void)flags;

  hd->h[0] = 0xc1059ed8;
  hd->h[1] = 0x367cd507;
  hd->h[2] = 0x3070dd17;
  hd->h[3] = 0xf70e5939;
  hd->h[4] = 0xffc00b31;
  hd->h[5] = 0x68581511;
  hd->h[6] = 0x64f98fa7;
  hd->h[7] = 0xbefa4fa4;

  sha256_common_init (hd);
}


/*
  Transform the message X which consists of 16 32-bit-words. See FIPS
  180-2 for details.  */
#define R(a,b,c,d,e,f,g,h,k,w) do                                 \
          {                                                       \
            t1 = (h) + Sum1((e)) + Cho((e),(f),(g)) + (k) + (w);  \
            t2 = Sum0((a)) + Maj((a),(b),(c));                    \
            d += t1;                                              \
            h  = t1 + t2;                                         \
          } while (0)

/* (4.2) same as SHA-1's F1.  */
#define Cho(x, y, z)  (z ^ (x & (y ^ z)))

/* (4.3) same as SHA-1's F3 */
#define Maj(x, y, z)  ((x & y) + (z & (x ^ y)))

/* (4.4) */
#define Sum0(x)       (ror (x, 2) ^ ror (x, 13) ^ ror (x, 22))

/* (4.5) */
#define Sum1(x)       (ror (x, 6) ^ ror (x, 11) ^ ror (x, 25))

/* Message expansion */
#define S0(x) (ror ((x), 7) ^ ror ((x), 18) ^ ((x) >> 3))       /* (4.6) */
#define S1(x) (ror ((x), 17) ^ ror ((x), 19) ^ ((x) >> 10))     /* (4.7) */
#define I(i) ( w[i] = buf_get_be32(data + i * 4) )
#define W(i) ( w[i&0x0f] =    S1(w[(i-2) &0x0f]) \
                            +    w[(i-7) &0x0f]  \
                            + S0(w[(i-15)&0x0f]) \
                            +    w[(i-16)&0x0f] )

static unsigned int
do_transform_generic (void *ctx, const unsigned char *data, size_t nblks)
{
  SHA256_CONTEXT *hd = ctx;
  static const u32 K[64] = {
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

  do
    {

      u32 a,b,c,d,e,f,g,h,t1,t2;
      u32 w[16];

      a = hd->h[0];
      b = hd->h[1];
      c = hd->h[2];
      d = hd->h[3];
      e = hd->h[4];
      f = hd->h[5];
      g = hd->h[6];
      h = hd->h[7];

      R(a, b, c, d, e, f, g, h, K[0], I(0));
      R(h, a, b, c, d, e, f, g, K[1], I(1));
      R(g, h, a, b, c, d, e, f, K[2], I(2));
      R(f, g, h, a, b, c, d, e, K[3], I(3));
      R(e, f, g, h, a, b, c, d, K[4], I(4));
      R(d, e, f, g, h, a, b, c, K[5], I(5));
      R(c, d, e, f, g, h, a, b, K[6], I(6));
      R(b, c, d, e, f, g, h, a, K[7], I(7));
      R(a, b, c, d, e, f, g, h, K[8], I(8));
      R(h, a, b, c, d, e, f, g, K[9], I(9));
      R(g, h, a, b, c, d, e, f, K[10], I(10));
      R(f, g, h, a, b, c, d, e, K[11], I(11));
      R(e, f, g, h, a, b, c, d, K[12], I(12));
      R(d, e, f, g, h, a, b, c, K[13], I(13));
      R(c, d, e, f, g, h, a, b, K[14], I(14));
      R(b, c, d, e, f, g, h, a, K[15], I(15));

      R(a, b, c, d, e, f, g, h, K[16], W(16));
      R(h, a, b, c, d, e, f, g, K[17], W(17));
      R(g, h, a, b, c, d, e, f, K[18], W(18));
      R(f, g, h, a, b, c, d, e, K[19], W(19));
      R(e, f, g, h, a, b, c, d, K[20], W(20));
      R(d, e, f, g, h, a, b, c, K[21], W(21));
      R(c, d, e, f, g, h, a, b, K[22], W(22));
      R(b, c, d, e, f, g, h, a, K[23], W(23));
      R(a, b, c, d, e, f, g, h, K[24], W(24));
      R(h, a, b, c, d, e, f, g, K[25], W(25));
      R(g, h, a, b, c, d, e, f, K[26], W(26));
      R(f, g, h, a, b, c, d, e, K[27], W(27));
      R(e, f, g, h, a, b, c, d, K[28], W(28));
      R(d, e, f, g, h, a, b, c, K[29], W(29));
      R(c, d, e, f, g, h, a, b, K[30], W(30));
      R(b, c, d, e, f, g, h, a, K[31], W(31));

      R(a, b, c, d, e, f, g, h, K[32], W(32));
      R(h, a, b, c, d, e, f, g, K[33], W(33));
      R(g, h, a, b, c, d, e, f, K[34], W(34));
      R(f, g, h, a, b, c, d, e, K[35], W(35));
      R(e, f, g, h, a, b, c, d, K[36], W(36));
      R(d, e, f, g, h, a, b, c, K[37], W(37));
      R(c, d, e, f, g, h, a, b, K[38], W(38));
      R(b, c, d, e, f, g, h, a, K[39], W(39));
      R(a, b, c, d, e, f, g, h, K[40], W(40));
      R(h, a, b, c, d, e, f, g, K[41], W(41));
      R(g, h, a, b, c, d, e, f, K[42], W(42));
      R(f, g, h, a, b, c, d, e, K[43], W(43));
      R(e, f, g, h, a, b, c, d, K[44], W(44));
      R(d, e, f, g, h, a, b, c, K[45], W(45));
      R(c, d, e, f, g, h, a, b, K[46], W(46));
      R(b, c, d, e, f, g, h, a, K[47], W(47));

      R(a, b, c, d, e, f, g, h, K[48], W(48));
      R(h, a, b, c, d, e, f, g, K[49], W(49));
      R(g, h, a, b, c, d, e, f, K[50], W(50));
      R(f, g, h, a, b, c, d, e, K[51], W(51));
      R(e, f, g, h, a, b, c, d, K[52], W(52));
      R(d, e, f, g, h, a, b, c, K[53], W(53));
      R(c, d, e, f, g, h, a, b, K[54], W(54));
      R(b, c, d, e, f, g, h, a, K[55], W(55));
      R(a, b, c, d, e, f, g, h, K[56], W(56));
      R(h, a, b, c, d, e, f, g, K[57], W(57));
      R(g, h, a, b, c, d, e, f, K[58], W(58));
      R(f, g, h, a, b, c, d, e, K[59], W(59));
      R(e, f, g, h, a, b, c, d, K[60], W(60));
      R(d, e, f, g, h, a, b, c, K[61], W(61));
      R(c, d, e, f, g, h, a, b, K[62], W(62));
      R(b, c, d, e, f, g, h, a, K[63], W(63));

      hd->h[0] += a;
      hd->h[1] += b;
      hd->h[2] += c;
      hd->h[3] += d;
      hd->h[4] += e;
      hd->h[5] += f;
      hd->h[6] += g;
      hd->h[7] += h;

      data += 64;
    }
  while (--nblks);

  return 26*4 + 32 + 3 * sizeof(void*);
}

#undef S0
#undef S1
#undef R


/*
   The routine finally terminates the computation and returns the
   digest.  The handle is prepared for a new cycle, but adding bytes
   to the handle will the destroy the returned buffer.  Returns: 32
   bytes with the message the digest.  */
static void
sha256_final(void *context)
{
  SHA256_CONTEXT *hd = context;
  u32 t, th, msb, lsb;
  byte *p;
  unsigned int burn;

  t = hd->bctx.nblocks;
  if (sizeof t == sizeof hd->bctx.nblocks)
    th = hd->bctx.nblocks_high;
  else
    th = hd->bctx.nblocks >> 32;

  /* multiply by 64 to make a byte count */
  lsb = t << 6;
  msb = (th << 6) | (t >> 26);
  /* add the count */
  t = lsb;
  if ((lsb += hd->bctx.count) < t)
    msb++;
  /* multiply by 8 to make a bit count */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 29;

  if (0)
    { }
  else if (hd->bctx.count < 56)  /* enough room */
    {
      hd->bctx.buf[hd->bctx.count++] = 0x80; /* pad */
      if (hd->bctx.count < 56)
	memset (&hd->bctx.buf[hd->bctx.count], 0, 56 - hd->bctx.count);

      /* append the 64 bit count */
      buf_put_be32(hd->bctx.buf + 56, msb);
      buf_put_be32(hd->bctx.buf + 60, lsb);
      burn = (*hd->bctx.bwrite) (hd, hd->bctx.buf, 1);
    }
  else  /* need one extra block */
    {
      hd->bctx.buf[hd->bctx.count++] = 0x80; /* pad character */
      /* fill pad and next block with zeroes */
      memset (&hd->bctx.buf[hd->bctx.count], 0, 64 - hd->bctx.count + 56);

      /* append the 64 bit count */
      buf_put_be32(hd->bctx.buf + 64 + 56, msb);
      buf_put_be32(hd->bctx.buf + 64 + 60, lsb);
      burn = (*hd->bctx.bwrite) (hd, hd->bctx.buf, 2);
    }

  p = hd->bctx.buf;
#define X(a) do { buf_put_be32(p, hd->h[a]); p += 4; } while(0)
  X(0);
  X(1);
  X(2);
  X(3);
  X(4);
  X(5);
  X(6);
  X(7);
#undef X

  hd->bctx.count = 0;

  _gcry_burn_stack (burn);
}

static byte *
sha256_read (void *context)
{
  SHA256_CONTEXT *hd = context;

  return hd->bctx.buf;
}


/* Shortcut functions which puts the hash value of the supplied buffer iov
 * into outbuf which must have a size of 32 bytes.  */
#define _gcry_sha256_hash_buffers 0

/* Shortcut functions which puts the hash value of the supplied buffer iov
 * into outbuf which must have a size of 28 bytes.  */
#define _gcry_sha224_hash_buffers 0


/* Run a full self-test for ALGO and return 0 on success.  */
#define run_selftests 0


static const byte asn224[19] = /* Object ID is 2.16.840.1.101.3.4.2.4 */
  { 0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
    0x1C
  };

static const gcry_md_oid_spec_t oid_spec_sha224[] =
  {
    /* From RFC3874, Section 4 */
    { "2.16.840.1.101.3.4.2.4" },
    /* ANSI X9.62  ecdsaWithSHA224 */
    { "1.2.840.10045.4.3.1" },
    { NULL },
  };

static const byte asn256[19] = /* Object ID is  2.16.840.1.101.3.4.2.1 */
  { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20 };

static const gcry_md_oid_spec_t oid_spec_sha256[] =
  {
    /* According to the OpenPGP draft rfc2440-bis06 */
    { "2.16.840.1.101.3.4.2.1" },
    /* PKCS#1 sha256WithRSAEncryption */
    { "1.2.840.113549.1.1.11" },
    /* ANSI X9.62  ecdsaWithSHA256 */
    { "1.2.840.10045.4.3.2" },

    { NULL },
  };

gcry_md_spec_t _gcry_digest_spec_sha224 =
  {
    GCRY_MD_SHA224, {0, 1},
    "SHA224", asn224, DIM (asn224), oid_spec_sha224, 28,
    sha224_init, _gcry_md_block_write, sha256_final, sha256_read, NULL,
    _gcry_sha224_hash_buffers,
    sizeof (SHA256_CONTEXT),
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_sha256")
    .blocksize = 64
  };

gcry_md_spec_t _gcry_digest_spec_sha256 =
  {
    GCRY_MD_SHA256, {0, 1},
    "SHA256", asn256, DIM (asn256), oid_spec_sha256, 32,
    sha256_init, _gcry_md_block_write, sha256_final, sha256_read, NULL,
    _gcry_sha256_hash_buffers,
    sizeof (SHA256_CONTEXT),
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_sha256")
    .blocksize = 64
  };


GRUB_MOD_INIT(gcry_sha256)
{
  grub_md_register (&_gcry_digest_spec_sha224);
  grub_md_register (&_gcry_digest_spec_sha256);
}

GRUB_MOD_FINI(gcry_sha256)
{
  grub_md_unregister (&_gcry_digest_spec_sha224);
  grub_md_unregister (&_gcry_digest_spec_sha256);
}
