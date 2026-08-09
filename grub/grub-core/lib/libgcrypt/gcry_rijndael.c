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
#include "const-time.h"

GRUB_MOD_LICENSE ("GPLv3+");

#pragma warning(disable:4018)	/* signed/unsigned mismatch (<)  */

#define memset grub_memset
#define memcpy grub_memcpy

#define MAXKC                   (256/32)
#define MAXROUNDS               14
#define BLOCKSIZE               (128/8)

/* Helper macro to force alignment to 16 or 64 bytes.  */
#define ATTR_ALIGNED_16
#define ATTR_ALIGNED_64

struct RIJNDAEL_context_s;

typedef unsigned int (*rijndael_cryptfn_t)(const struct RIJNDAEL_context_s *ctx,
                                           unsigned char *bx,
                                           const unsigned char *ax);
typedef void (*rijndael_prefetchfn_t)(void);
typedef void (*rijndael_prepare_decfn_t)(struct RIJNDAEL_context_s *ctx);

/* Our context object.  */
typedef struct RIJNDAEL_context_s
{
  /* The first fields are the keyschedule arrays.  This is so that
     they are aligned on a 16 byte boundary if using gcc.  This
     alignment is required for the AES-NI code and a good idea in any
     case.  The alignment is guaranteed due to the way cipher.c
     allocates the space for the context.  The PROPERLY_ALIGNED_TYPE
     hack is used to force a minimal alignment if not using gcc of if
     the alignment requirement is higher that 16 bytes.  */
  union
  {
    PROPERLY_ALIGNED_TYPE dummy;
    byte keyschedule[MAXROUNDS+1][4][4];
    u32 keyschedule32[MAXROUNDS+1][4];
    u32 keyschedule32b[(MAXROUNDS+1)*4];
  } u1;
  union
  {
    PROPERLY_ALIGNED_TYPE dummy;
    byte keyschedule[MAXROUNDS+1][4][4];
    u32 keyschedule32[MAXROUNDS+1][4];
  } u2;
  int rounds;                         /* Key-length-dependent number of rounds.  */
  unsigned int decryption_prepared:1; /* The decryption key schedule is available.  */
  rijndael_cryptfn_t encrypt_fn;
  rijndael_cryptfn_t decrypt_fn;
  rijndael_prefetchfn_t prefetch_enc_fn;
  rijndael_prefetchfn_t prefetch_dec_fn;
  rijndael_prepare_decfn_t prepare_decryption;
} RIJNDAEL_context ATTR_ALIGNED_16;

/* Macros defining alias for the keyschedules.  */
#define keyschenc     u1.keyschedule
#define keyschenc32   u1.keyschedule32
#define keyschenc32b  u1.keyschedule32b
#define keyschdec     u2.keyschedule
#define keyschdec32   u2.keyschedule32
#define padlockkey    u1.padlock_key

/* Rijndael (AES) for GnuPG
 * Copyright (C) 2000, 2001, 2002, 2003, 2007,
 *               2008, 2011, 2012 Free Software Foundation, Inc.
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
 *******************************************************************
 * The code here is based on the optimized implementation taken from
 * http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ on Oct 2, 2000,
 * which carries this notice:
 *------------------------------------------
 * rijndael-alg-fst.c   v2.3   April '2000
 *
 * Optimised ANSI C code
 *
 * authors: v1.0: Antoon Bosselaers
 *          v2.0: Vincent Rijmen
 *          v2.3: Paulo Barreto
 *
 * This code is placed in the public domain.
 *------------------------------------------
 *
 * The SP800-38a document is available at:
 *   http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 *
 */

static unsigned int do_encrypt (const RIJNDAEL_context *ctx, unsigned char *bx,
                                const unsigned char *ax);
static unsigned int do_decrypt (const RIJNDAEL_context *ctx, unsigned char *bx,
                                const unsigned char *ax);

/* All the numbers.  */
/* rijndael-tables.h */

static struct
{
  volatile u32 counter_head;
  u32 cacheline_align[64 / 4 - 1];
  u32 T[256];
  volatile u32 counter_tail;
} enc_tables ATTR_ALIGNED_64 =
  {
    0,
    { 0, },
    {
      0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6,
      0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591,
      0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56,
      0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec,
      0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa,
      0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb,
      0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45,
      0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b,
      0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c,
      0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
      0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9,
      0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
      0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d,
      0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f,
      0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
      0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea,
      0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34,
      0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
      0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d,
      0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
      0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1,
      0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6,
      0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972,
      0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
      0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed,
      0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511,
      0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe,
      0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b,
      0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05,
      0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
      0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142,
      0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf,
      0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3,
      0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e,
      0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a,
      0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
      0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3,
      0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b,
      0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428,
      0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
      0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14,
      0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8,
      0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4,
      0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2,
      0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
      0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949,
      0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf,
      0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
      0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c,
      0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
      0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e,
      0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f,
      0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc,
      0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c,
      0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969,
      0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27,
      0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122,
      0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433,
      0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9,
      0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
      0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a,
      0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0,
      0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e,
      0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c
    },
    0
  };

#define encT enc_tables.T

static struct
{
  volatile u32 counter_head;
  u32 cacheline_align[64 / 4 - 1];
  u32 T[256];
  byte inv_sbox[256];
  volatile u32 counter_tail;
} dec_tables ATTR_ALIGNED_64 =
  {
    0,
    { 0, },
    {
      0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a,
      0xcb6bab3b, 0xf1459d1f, 0xab58faac, 0x9303e34b,
      0x55fa3020, 0xf66d76ad, 0x9176cc88, 0x254c02f5,
      0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 0x8fa362b5,
      0x495ab1de, 0x671bba25, 0x980eea45, 0xe1c0fe5d,
      0x02752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b,
      0xe75f8f03, 0x959c9215, 0xeb7a6dbf, 0xda595295,
      0x2d83bed4, 0xd3217458, 0x2969e049, 0x44c8c98e,
      0x6a89c275, 0x78798ef4, 0x6b3e5899, 0xdd71b927,
      0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d,
      0x184adf63, 0x82311ae5, 0x60335197, 0x457f5362,
      0xe07764b1, 0x84ae6bbb, 0x1ca081fe, 0x942b08f9,
      0x58684870, 0x19fd458f, 0x876cde94, 0xb7f87b52,
      0x23d373ab, 0xe2024b72, 0x578f1fe3, 0x2aab5566,
      0x0728ebb2, 0x03c2b52f, 0x9a7bc586, 0xa50837d3,
      0xf2872830, 0xb2a5bf23, 0xba6a0302, 0x5c8216ed,
      0x2b1ccf8a, 0x92b479a7, 0xf0f207f3, 0xa1e2694e,
      0xcdf4da65, 0xd5be0506, 0x1f6234d1, 0x8afea6c4,
      0x9d532e34, 0xa055f3a2, 0x32e18a05, 0x75ebf6a4,
      0x39ec830b, 0xaaef6040, 0x069f715e, 0x51106ebd,
      0xf98a213e, 0x3d06dd96, 0xae053edd, 0x46bde64d,
      0xb58d5491, 0x055dc471, 0x6fd40604, 0xff155060,
      0x24fb9819, 0x97e9bdd6, 0xcc434089, 0x779ed967,
      0xbd42e8b0, 0x888b8907, 0x385b19e7, 0xdbeec879,
      0x470a7ca1, 0xe90f427c, 0xc91e84f8, 0x00000000,
      0x83868009, 0x48ed2b32, 0xac70111e, 0x4e725a6c,
      0xfbff0efd, 0x5638850f, 0x1ed5ae3d, 0x27392d36,
      0x64d90f0a, 0x21a65c68, 0xd1545b9b, 0x3a2e3624,
      0xb1670a0c, 0x0fe75793, 0xd296eeb4, 0x9e919b1b,
      0x4fc5c080, 0xa220dc61, 0x694b775a, 0x161a121c,
      0x0aba93e2, 0xe52aa0c0, 0x43e0223c, 0x1d171b12,
      0x0b0d090e, 0xadc78bf2, 0xb9a8b62d, 0xc8a91e14,
      0x8519f157, 0x4c0775af, 0xbbdd99ee, 0xfd607fa3,
      0x9f2601f7, 0xbcf5725c, 0xc53b6644, 0x347efb5b,
      0x7629438b, 0xdcc623cb, 0x68fcedb6, 0x63f1e4b8,
      0xcadc31d7, 0x10856342, 0x40229713, 0x2011c684,
      0x7d244a85, 0xf83dbbd2, 0x1132f9ae, 0x6da129c7,
      0x4b2f9e1d, 0xf330b2dc, 0xec52860d, 0xd0e3c177,
      0x6c16b32b, 0x99b970a9, 0xfa489411, 0x2264e947,
      0xc48cfca8, 0x1a3ff0a0, 0xd82c7d56, 0xef903322,
      0xc74e4987, 0xc1d138d9, 0xfea2ca8c, 0x360bd498,
      0xcf81f5a6, 0x28de7aa5, 0x268eb7da, 0xa4bfad3f,
      0xe49d3a2c, 0x0d927850, 0x9bcc5f6a, 0x62467e54,
      0xc2138df6, 0xe8b8d890, 0x5ef7392e, 0xf5afc382,
      0xbe805d9f, 0x7c93d069, 0xa92dd56f, 0xb31225cf,
      0x3b99acc8, 0xa77d1810, 0x6e639ce8, 0x7bbb3bdb,
      0x097826cd, 0xf418596e, 0x01b79aec, 0xa89a4f83,
      0x656e95e6, 0x7ee6ffaa, 0x08cfbc21, 0xe6e815ef,
      0xd99be7ba, 0xce366f4a, 0xd4099fea, 0xd67cb029,
      0xafb2a431, 0x31233f2a, 0x3094a5c6, 0xc066a235,
      0x37bc4e74, 0xa6ca82fc, 0xb0d090e0, 0x15d8a733,
      0x4a9804f1, 0xf7daec41, 0x0e50cd7f, 0x2ff69117,
      0x8dd64d76, 0x4db0ef43, 0x544daacc, 0xdf0496e4,
      0xe3b5d19e, 0x1b886a4c, 0xb81f2cc1, 0x7f516546,
      0x04ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb,
      0x5a1d67b3, 0x52d2db92, 0x335610e9, 0x1347d66d,
      0x8c61d79a, 0x7a0ca137, 0x8e14f859, 0x893c13eb,
      0xee27a9ce, 0x35c961b7, 0xede51ce1, 0x3cb1477a,
      0x59dfd29c, 0x3f73f255, 0x79ce1418, 0xbf37c773,
      0xeacdf753, 0x5baafd5f, 0x146f3ddf, 0x86db4478,
      0x81f3afca, 0x3ec468b9, 0x2c342438, 0x5f40a3c2,
      0x72c31d16, 0x0c25e2bc, 0x8b493c28, 0x41950dff,
      0x7101a839, 0xdeb30c08, 0x9ce4b4d8, 0x90c15664,
      0x6184cb7b, 0x70b632d5, 0x745c6c48, 0x4257b8d0
    },
    {
      0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
      0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
      0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
      0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
      0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,
      0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
      0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,
      0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
      0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
      0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
      0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,
      0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
      0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,
      0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
      0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
      0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
      0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,
      0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
      0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,
      0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
      0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
      0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
      0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,
      0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
      0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,
      0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
      0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
      0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
      0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,
      0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
      0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,
      0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    },
    0
  };

#define decT dec_tables.T
#define inv_sbox dec_tables.inv_sbox


/* Function prototypes.  */
static void prepare_decryption(RIJNDAEL_context *ctx);


/* Prefetching for encryption/decryption tables. */
static inline void prefetch_table(const volatile byte *tab, size_t len)
{
  size_t i;

  for (i = 0; len - i >= 8 * 32; i += 8 * 32)
    {
      (void)tab[i + 0 * 32];
      (void)tab[i + 1 * 32];
      (void)tab[i + 2 * 32];
      (void)tab[i + 3 * 32];
      (void)tab[i + 4 * 32];
      (void)tab[i + 5 * 32];
      (void)tab[i + 6 * 32];
      (void)tab[i + 7 * 32];
    }
  for (; i < len; i += 32)
    {
      (void)tab[i];
    }

  (void)tab[len - 1];
}

static void prefetch_enc(void)
{
  /* Modify counters to trigger copy-on-write and unsharing if physical pages
   * of look-up table are shared between processes.  Modifying counters also
   * causes checksums for pages to change and hint same-page merging algorithm
   * that these pages are frequently changing.  */
  enc_tables.counter_head++;
  enc_tables.counter_tail++;

  /* Prefetch look-up tables to cache.  */
  prefetch_table((const void *)&enc_tables, sizeof(enc_tables));
}

static void prefetch_dec(void)
{
  /* Modify counters to trigger copy-on-write and unsharing if physical pages
   * of look-up table are shared between processes.  Modifying counters also
   * causes checksums for pages to change and hint same-page merging algorithm
   * that these pages are frequently changing.  */
  dec_tables.counter_head++;
  dec_tables.counter_tail++;

  /* Prefetch look-up tables to cache.  */
  prefetch_table((const void *)&dec_tables, sizeof(dec_tables));
}


static inline u32
sbox4(u32 inb4)
{
  u32 out;
  out =  (encT[(inb4 >> 0) & 0xffU] & 0xff00U) >> 8;
  out |= (encT[(inb4 >> 8) & 0xffU] & 0xff00U) >> 0;
  out |= (encT[(inb4 >> 16) & 0xffU] & 0xff0000U) << 0;
  out |= (encT[(inb4 >> 24) & 0xffU] & 0xff0000U) << 8;
  return out;
}

/* Perform the key setup.  */
static gcry_err_code_t
do_setkey (RIJNDAEL_context *ctx, const byte *key, const unsigned keylen,
           cipher_bulk_ops_t *bulk_ops)
{
  static int initialized = 0;
  static const char *selftest_failed = 0;
  void (*hw_setkey)(RIJNDAEL_context *ctx, const byte *key) = NULL;
  int rounds;
  unsigned int KC;
  unsigned int hwfeatures;

  /* The on-the-fly self tests are only run in non-fips mode. In fips
     mode explicit self-tests are required.  Actually the on-the-fly
     self-tests are not fully thread-safe and it might happen that a
     failed self-test won't get noticed in another thread.

     FIXME: We might want to have a central registry of succeeded
     self-tests. */
  if (!initialized)
    {
      initialized = 1;
    }
  if (selftest_failed)
    return GPG_ERR_SELFTEST_FAILED;

  if( keylen == 128/8 )
    {
      rounds = 10;
      KC = 4;
    }
  else if ( keylen == 192/8 )
    {
      rounds = 12;
      KC = 6;
    }
  else if ( keylen == 256/8 )
    {
      rounds = 14;
      KC = 8;
    }
  else
    return GPG_ERR_INV_KEYLEN;

  ctx->rounds = rounds;
  hwfeatures = _gcry_get_hw_features ();

  ctx->decryption_prepared = 0;

  (void)bulk_ops;

  (void)hwfeatures;

  if (0)
    {
      ;
    }
  else
    {
      ctx->encrypt_fn = do_encrypt;
      ctx->decrypt_fn = do_decrypt;
      ctx->prefetch_enc_fn = prefetch_enc;
      ctx->prefetch_dec_fn = prefetch_dec;
      ctx->prepare_decryption = prepare_decryption;
    }

  /* NB: We don't yet support Padlock hardware key generation.  */

  if (hw_setkey)
    {
      hw_setkey (ctx, key);
    }
  else
    {
      u32 W_prev;
      u32 *W_u32 = ctx->keyschenc32b;
      byte rcon = 1;
      unsigned int i, j;

      prefetch_enc();

      for (i = 0; i < KC; i += 2)
        {
          W_u32[i + 0] = buf_get_le32(key + i * 4 + 0);
          W_u32[i + 1] = buf_get_le32(key + i * 4 + 4);
        }

      for (i = KC, j = KC, W_prev = W_u32[KC - 1];
           i < 4 * (rounds + 1);
           i += 2, j += 2)
        {
          u32 temp0 = W_prev;
          u32 temp1;

          if (j == KC)
            {
              j = 0;
              temp0 = sbox4(rol(temp0, 24)) ^ rcon;
              rcon = ((rcon << 1) ^ (ct_ulong_gen_mask(rcon >> 7) & 0x1b)) & 0xff;
            }
          else if (KC == 8 && j == 4)
            {
              temp0 = sbox4(temp0);
            }

          temp1 = W_u32[i - KC + 0];

          W_u32[i + 0] = temp0 ^ temp1;
          W_u32[i + 1] = W_u32[i - KC + 1] ^ temp0 ^ temp1;
          W_prev = W_u32[i + 1];
        }
    }

  return 0;
}


static gcry_err_code_t
rijndael_setkey (void *context, const byte *key, const unsigned keylen,
                 cipher_bulk_ops_t *bulk_ops)
{
  RIJNDAEL_context *ctx = context;
  return do_setkey (ctx, key, keylen, bulk_ops);
}


/* Make a decryption key from an encryption key. */
static void
prepare_decryption( RIJNDAEL_context *ctx )
{
  const byte *sbox = ((const byte *)encT) + 1;
  int r;

  prefetch_enc();
  prefetch_dec();

  ctx->keyschdec32[0][0] = ctx->keyschenc32[0][0];
  ctx->keyschdec32[0][1] = ctx->keyschenc32[0][1];
  ctx->keyschdec32[0][2] = ctx->keyschenc32[0][2];
  ctx->keyschdec32[0][3] = ctx->keyschenc32[0][3];

  for (r = 1; r < ctx->rounds; r++)
    {
      u32 *wi = ctx->keyschenc32[r];
      u32 *wo = ctx->keyschdec32[r];
      u32 wt;

      wt = wi[0];
      wo[0] = rol(decT[sbox[(byte)(wt >> 0) * 4]], 8 * 0)
	      ^ rol(decT[sbox[(byte)(wt >> 8) * 4]], 8 * 1)
	      ^ rol(decT[sbox[(byte)(wt >> 16) * 4]], 8 * 2)
	      ^ rol(decT[sbox[(byte)(wt >> 24) * 4]], 8 * 3);

      wt = wi[1];
      wo[1] = rol(decT[sbox[(byte)(wt >> 0) * 4]], 8 * 0)
	      ^ rol(decT[sbox[(byte)(wt >> 8) * 4]], 8 * 1)
	      ^ rol(decT[sbox[(byte)(wt >> 16) * 4]], 8 * 2)
	      ^ rol(decT[sbox[(byte)(wt >> 24) * 4]], 8 * 3);

      wt = wi[2];
      wo[2] = rol(decT[sbox[(byte)(wt >> 0) * 4]], 8 * 0)
	      ^ rol(decT[sbox[(byte)(wt >> 8) * 4]], 8 * 1)
	      ^ rol(decT[sbox[(byte)(wt >> 16) * 4]], 8 * 2)
	      ^ rol(decT[sbox[(byte)(wt >> 24) * 4]], 8 * 3);

      wt = wi[3];
      wo[3] = rol(decT[sbox[(byte)(wt >> 0) * 4]], 8 * 0)
	      ^ rol(decT[sbox[(byte)(wt >> 8) * 4]], 8 * 1)
	      ^ rol(decT[sbox[(byte)(wt >> 16) * 4]], 8 * 2)
	      ^ rol(decT[sbox[(byte)(wt >> 24) * 4]], 8 * 3);
    }

  ctx->keyschdec32[r][0] = ctx->keyschenc32[r][0];
  ctx->keyschdec32[r][1] = ctx->keyschenc32[r][1];
  ctx->keyschdec32[r][2] = ctx->keyschenc32[r][2];
  ctx->keyschdec32[r][3] = ctx->keyschenc32[r][3];
}


#if !defined(USE_ARM_ASM) && !defined(USE_AMD64_ASM)
/* Encrypt one block. A and B may be the same. */
static unsigned int
do_encrypt_fn (const RIJNDAEL_context *ctx, unsigned char *b,
               const unsigned char *a)
{
#define rk (ctx->keyschenc32)
  const byte *sbox = ((const byte *)encT) + 1;
  int rounds = ctx->rounds;
  int r;
  u32 sa[4];
  u32 sb[4];

  sb[0] = buf_get_le32(a + 0);
  sb[1] = buf_get_le32(a + 4);
  sb[2] = buf_get_le32(a + 8);
  sb[3] = buf_get_le32(a + 12);

  sa[0] = sb[0] ^ rk[0][0];
  sa[1] = sb[1] ^ rk[0][1];
  sa[2] = sb[2] ^ rk[0][2];
  sa[3] = sb[3] ^ rk[0][3];

  sb[0] = rol(encT[(byte)(sa[0] >> (0 * 8))], (0 * 8));
  sb[3] = rol(encT[(byte)(sa[0] >> (1 * 8))], (1 * 8));
  sb[2] = rol(encT[(byte)(sa[0] >> (2 * 8))], (2 * 8));
  sb[1] = rol(encT[(byte)(sa[0] >> (3 * 8))], (3 * 8));
  sa[0] = rk[1][0] ^ sb[0];

  sb[1] ^= rol(encT[(byte)(sa[1] >> (0 * 8))], (0 * 8));
  sa[0] ^= rol(encT[(byte)(sa[1] >> (1 * 8))], (1 * 8));
  sb[3] ^= rol(encT[(byte)(sa[1] >> (2 * 8))], (2 * 8));
  sb[2] ^= rol(encT[(byte)(sa[1] >> (3 * 8))], (3 * 8));
  sa[1] = rk[1][1] ^ sb[1];

  sb[2] ^= rol(encT[(byte)(sa[2] >> (0 * 8))], (0 * 8));
  sa[1] ^= rol(encT[(byte)(sa[2] >> (1 * 8))], (1 * 8));
  sa[0] ^= rol(encT[(byte)(sa[2] >> (2 * 8))], (2 * 8));
  sb[3] ^= rol(encT[(byte)(sa[2] >> (3 * 8))], (3 * 8));
  sa[2] = rk[1][2] ^ sb[2];

  sb[3] ^= rol(encT[(byte)(sa[3] >> (0 * 8))], (0 * 8));
  sa[2] ^= rol(encT[(byte)(sa[3] >> (1 * 8))], (1 * 8));
  sa[1] ^= rol(encT[(byte)(sa[3] >> (2 * 8))], (2 * 8));
  sa[0] ^= rol(encT[(byte)(sa[3] >> (3 * 8))], (3 * 8));
  sa[3] = rk[1][3] ^ sb[3];

  for (r = 2; r < rounds; r++)
    {
      sb[0] = rol(encT[(byte)(sa[0] >> (0 * 8))], (0 * 8));
      sb[3] = rol(encT[(byte)(sa[0] >> (1 * 8))], (1 * 8));
      sb[2] = rol(encT[(byte)(sa[0] >> (2 * 8))], (2 * 8));
      sb[1] = rol(encT[(byte)(sa[0] >> (3 * 8))], (3 * 8));
      sa[0] = rk[r][0] ^ sb[0];

      sb[1] ^= rol(encT[(byte)(sa[1] >> (0 * 8))], (0 * 8));
      sa[0] ^= rol(encT[(byte)(sa[1] >> (1 * 8))], (1 * 8));
      sb[3] ^= rol(encT[(byte)(sa[1] >> (2 * 8))], (2 * 8));
      sb[2] ^= rol(encT[(byte)(sa[1] >> (3 * 8))], (3 * 8));
      sa[1] = rk[r][1] ^ sb[1];

      sb[2] ^= rol(encT[(byte)(sa[2] >> (0 * 8))], (0 * 8));
      sa[1] ^= rol(encT[(byte)(sa[2] >> (1 * 8))], (1 * 8));
      sa[0] ^= rol(encT[(byte)(sa[2] >> (2 * 8))], (2 * 8));
      sb[3] ^= rol(encT[(byte)(sa[2] >> (3 * 8))], (3 * 8));
      sa[2] = rk[r][2] ^ sb[2];

      sb[3] ^= rol(encT[(byte)(sa[3] >> (0 * 8))], (0 * 8));
      sa[2] ^= rol(encT[(byte)(sa[3] >> (1 * 8))], (1 * 8));
      sa[1] ^= rol(encT[(byte)(sa[3] >> (2 * 8))], (2 * 8));
      sa[0] ^= rol(encT[(byte)(sa[3] >> (3 * 8))], (3 * 8));
      sa[3] = rk[r][3] ^ sb[3];

      r++;

      sb[0] = rol(encT[(byte)(sa[0] >> (0 * 8))], (0 * 8));
      sb[3] = rol(encT[(byte)(sa[0] >> (1 * 8))], (1 * 8));
      sb[2] = rol(encT[(byte)(sa[0] >> (2 * 8))], (2 * 8));
      sb[1] = rol(encT[(byte)(sa[0] >> (3 * 8))], (3 * 8));
      sa[0] = rk[r][0] ^ sb[0];

      sb[1] ^= rol(encT[(byte)(sa[1] >> (0 * 8))], (0 * 8));
      sa[0] ^= rol(encT[(byte)(sa[1] >> (1 * 8))], (1 * 8));
      sb[3] ^= rol(encT[(byte)(sa[1] >> (2 * 8))], (2 * 8));
      sb[2] ^= rol(encT[(byte)(sa[1] >> (3 * 8))], (3 * 8));
      sa[1] = rk[r][1] ^ sb[1];

      sb[2] ^= rol(encT[(byte)(sa[2] >> (0 * 8))], (0 * 8));
      sa[1] ^= rol(encT[(byte)(sa[2] >> (1 * 8))], (1 * 8));
      sa[0] ^= rol(encT[(byte)(sa[2] >> (2 * 8))], (2 * 8));
      sb[3] ^= rol(encT[(byte)(sa[2] >> (3 * 8))], (3 * 8));
      sa[2] = rk[r][2] ^ sb[2];

      sb[3] ^= rol(encT[(byte)(sa[3] >> (0 * 8))], (0 * 8));
      sa[2] ^= rol(encT[(byte)(sa[3] >> (1 * 8))], (1 * 8));
      sa[1] ^= rol(encT[(byte)(sa[3] >> (2 * 8))], (2 * 8));
      sa[0] ^= rol(encT[(byte)(sa[3] >> (3 * 8))], (3 * 8));
      sa[3] = rk[r][3] ^ sb[3];
    }

  /* Last round is special. */

  sb[0] = ((u32)sbox[(byte)(sa[0] >> (0 * 8)) * 4]) << (0 * 8);
  sb[3] = ((u32)sbox[(byte)(sa[0] >> (1 * 8)) * 4]) << (1 * 8);
  sb[2] = ((u32)sbox[(byte)(sa[0] >> (2 * 8)) * 4]) << (2 * 8);
  sb[1] = ((u32)sbox[(byte)(sa[0] >> (3 * 8)) * 4]) << (3 * 8);
  sa[0] = rk[r][0] ^ sb[0];

  sb[1] ^= ((u32)sbox[(byte)(sa[1] >> (0 * 8)) * 4]) << (0 * 8);
  sa[0] ^= ((u32)sbox[(byte)(sa[1] >> (1 * 8)) * 4]) << (1 * 8);
  sb[3] ^= ((u32)sbox[(byte)(sa[1] >> (2 * 8)) * 4]) << (2 * 8);
  sb[2] ^= ((u32)sbox[(byte)(sa[1] >> (3 * 8)) * 4]) << (3 * 8);
  sa[1] = rk[r][1] ^ sb[1];

  sb[2] ^= ((u32)sbox[(byte)(sa[2] >> (0 * 8)) * 4]) << (0 * 8);
  sa[1] ^= ((u32)sbox[(byte)(sa[2] >> (1 * 8)) * 4]) << (1 * 8);
  sa[0] ^= ((u32)sbox[(byte)(sa[2] >> (2 * 8)) * 4]) << (2 * 8);
  sb[3] ^= ((u32)sbox[(byte)(sa[2] >> (3 * 8)) * 4]) << (3 * 8);
  sa[2] = rk[r][2] ^ sb[2];

  sb[3] ^= ((u32)sbox[(byte)(sa[3] >> (0 * 8)) * 4]) << (0 * 8);
  sa[2] ^= ((u32)sbox[(byte)(sa[3] >> (1 * 8)) * 4]) << (1 * 8);
  sa[1] ^= ((u32)sbox[(byte)(sa[3] >> (2 * 8)) * 4]) << (2 * 8);
  sa[0] ^= ((u32)sbox[(byte)(sa[3] >> (3 * 8)) * 4]) << (3 * 8);
  sa[3] = rk[r][3] ^ sb[3];

  buf_put_le32(b + 0, sa[0]);
  buf_put_le32(b + 4, sa[1]);
  buf_put_le32(b + 8, sa[2]);
  buf_put_le32(b + 12, sa[3]);
#undef rk

  return (56 + 2*sizeof(int));
}
#endif /*!USE_ARM_ASM && !USE_AMD64_ASM*/


static unsigned int
do_encrypt (const RIJNDAEL_context *ctx,
            unsigned char *bx, const unsigned char *ax)
{
  return do_encrypt_fn (ctx, bx, ax);
}


static unsigned int
rijndael_encrypt (void *context, byte *b, const byte *a)
{
  RIJNDAEL_context *ctx = context;

  if (ctx->prefetch_enc_fn)
    ctx->prefetch_enc_fn();

  return ctx->encrypt_fn (ctx, b, a);
}


#if !defined(USE_ARM_ASM) && !defined(USE_AMD64_ASM)
/* Decrypt one block.  A and B may be the same. */
static unsigned int
do_decrypt_fn (const RIJNDAEL_context *ctx, unsigned char *b,
               const unsigned char *a)
{
#define rk (ctx->keyschdec32)
  int rounds = ctx->rounds;
  int r;
  u32 sa[4];
  u32 sb[4];

  sb[0] = buf_get_le32(a + 0);
  sb[1] = buf_get_le32(a + 4);
  sb[2] = buf_get_le32(a + 8);
  sb[3] = buf_get_le32(a + 12);

  sa[0] = sb[0] ^ rk[rounds][0];
  sa[1] = sb[1] ^ rk[rounds][1];
  sa[2] = sb[2] ^ rk[rounds][2];
  sa[3] = sb[3] ^ rk[rounds][3];

  for (r = rounds - 1; r > 1; r--)
    {
      sb[0] = rol(decT[(byte)(sa[0] >> (0 * 8))], (0 * 8));
      sb[1] = rol(decT[(byte)(sa[0] >> (1 * 8))], (1 * 8));
      sb[2] = rol(decT[(byte)(sa[0] >> (2 * 8))], (2 * 8));
      sb[3] = rol(decT[(byte)(sa[0] >> (3 * 8))], (3 * 8));
      sa[0] = rk[r][0] ^ sb[0];

      sb[1] ^= rol(decT[(byte)(sa[1] >> (0 * 8))], (0 * 8));
      sb[2] ^= rol(decT[(byte)(sa[1] >> (1 * 8))], (1 * 8));
      sb[3] ^= rol(decT[(byte)(sa[1] >> (2 * 8))], (2 * 8));
      sa[0] ^= rol(decT[(byte)(sa[1] >> (3 * 8))], (3 * 8));
      sa[1] = rk[r][1] ^ sb[1];

      sb[2] ^= rol(decT[(byte)(sa[2] >> (0 * 8))], (0 * 8));
      sb[3] ^= rol(decT[(byte)(sa[2] >> (1 * 8))], (1 * 8));
      sa[0] ^= rol(decT[(byte)(sa[2] >> (2 * 8))], (2 * 8));
      sa[1] ^= rol(decT[(byte)(sa[2] >> (3 * 8))], (3 * 8));
      sa[2] = rk[r][2] ^ sb[2];

      sb[3] ^= rol(decT[(byte)(sa[3] >> (0 * 8))], (0 * 8));
      sa[0] ^= rol(decT[(byte)(sa[3] >> (1 * 8))], (1 * 8));
      sa[1] ^= rol(decT[(byte)(sa[3] >> (2 * 8))], (2 * 8));
      sa[2] ^= rol(decT[(byte)(sa[3] >> (3 * 8))], (3 * 8));
      sa[3] = rk[r][3] ^ sb[3];

      r--;

      sb[0] = rol(decT[(byte)(sa[0] >> (0 * 8))], (0 * 8));
      sb[1] = rol(decT[(byte)(sa[0] >> (1 * 8))], (1 * 8));
      sb[2] = rol(decT[(byte)(sa[0] >> (2 * 8))], (2 * 8));
      sb[3] = rol(decT[(byte)(sa[0] >> (3 * 8))], (3 * 8));
      sa[0] = rk[r][0] ^ sb[0];

      sb[1] ^= rol(decT[(byte)(sa[1] >> (0 * 8))], (0 * 8));
      sb[2] ^= rol(decT[(byte)(sa[1] >> (1 * 8))], (1 * 8));
      sb[3] ^= rol(decT[(byte)(sa[1] >> (2 * 8))], (2 * 8));
      sa[0] ^= rol(decT[(byte)(sa[1] >> (3 * 8))], (3 * 8));
      sa[1] = rk[r][1] ^ sb[1];

      sb[2] ^= rol(decT[(byte)(sa[2] >> (0 * 8))], (0 * 8));
      sb[3] ^= rol(decT[(byte)(sa[2] >> (1 * 8))], (1 * 8));
      sa[0] ^= rol(decT[(byte)(sa[2] >> (2 * 8))], (2 * 8));
      sa[1] ^= rol(decT[(byte)(sa[2] >> (3 * 8))], (3 * 8));
      sa[2] = rk[r][2] ^ sb[2];

      sb[3] ^= rol(decT[(byte)(sa[3] >> (0 * 8))], (0 * 8));
      sa[0] ^= rol(decT[(byte)(sa[3] >> (1 * 8))], (1 * 8));
      sa[1] ^= rol(decT[(byte)(sa[3] >> (2 * 8))], (2 * 8));
      sa[2] ^= rol(decT[(byte)(sa[3] >> (3 * 8))], (3 * 8));
      sa[3] = rk[r][3] ^ sb[3];
    }

  sb[0] = rol(decT[(byte)(sa[0] >> (0 * 8))], (0 * 8));
  sb[1] = rol(decT[(byte)(sa[0] >> (1 * 8))], (1 * 8));
  sb[2] = rol(decT[(byte)(sa[0] >> (2 * 8))], (2 * 8));
  sb[3] = rol(decT[(byte)(sa[0] >> (3 * 8))], (3 * 8));
  sa[0] = rk[1][0] ^ sb[0];

  sb[1] ^= rol(decT[(byte)(sa[1] >> (0 * 8))], (0 * 8));
  sb[2] ^= rol(decT[(byte)(sa[1] >> (1 * 8))], (1 * 8));
  sb[3] ^= rol(decT[(byte)(sa[1] >> (2 * 8))], (2 * 8));
  sa[0] ^= rol(decT[(byte)(sa[1] >> (3 * 8))], (3 * 8));
  sa[1] = rk[1][1] ^ sb[1];

  sb[2] ^= rol(decT[(byte)(sa[2] >> (0 * 8))], (0 * 8));
  sb[3] ^= rol(decT[(byte)(sa[2] >> (1 * 8))], (1 * 8));
  sa[0] ^= rol(decT[(byte)(sa[2] >> (2 * 8))], (2 * 8));
  sa[1] ^= rol(decT[(byte)(sa[2] >> (3 * 8))], (3 * 8));
  sa[2] = rk[1][2] ^ sb[2];

  sb[3] ^= rol(decT[(byte)(sa[3] >> (0 * 8))], (0 * 8));
  sa[0] ^= rol(decT[(byte)(sa[3] >> (1 * 8))], (1 * 8));
  sa[1] ^= rol(decT[(byte)(sa[3] >> (2 * 8))], (2 * 8));
  sa[2] ^= rol(decT[(byte)(sa[3] >> (3 * 8))], (3 * 8));
  sa[3] = rk[1][3] ^ sb[3];

  /* Last round is special. */
  sb[0] = (u32)inv_sbox[(byte)(sa[0] >> (0 * 8))] << (0 * 8);
  sb[1] = (u32)inv_sbox[(byte)(sa[0] >> (1 * 8))] << (1 * 8);
  sb[2] = (u32)inv_sbox[(byte)(sa[0] >> (2 * 8))] << (2 * 8);
  sb[3] = (u32)inv_sbox[(byte)(sa[0] >> (3 * 8))] << (3 * 8);
  sa[0] = sb[0] ^ rk[0][0];

  sb[1] ^= (u32)inv_sbox[(byte)(sa[1] >> (0 * 8))] << (0 * 8);
  sb[2] ^= (u32)inv_sbox[(byte)(sa[1] >> (1 * 8))] << (1 * 8);
  sb[3] ^= (u32)inv_sbox[(byte)(sa[1] >> (2 * 8))] << (2 * 8);
  sa[0] ^= (u32)inv_sbox[(byte)(sa[1] >> (3 * 8))] << (3 * 8);
  sa[1] = sb[1] ^ rk[0][1];

  sb[2] ^= (u32)inv_sbox[(byte)(sa[2] >> (0 * 8))] << (0 * 8);
  sb[3] ^= (u32)inv_sbox[(byte)(sa[2] >> (1 * 8))] << (1 * 8);
  sa[0] ^= (u32)inv_sbox[(byte)(sa[2] >> (2 * 8))] << (2 * 8);
  sa[1] ^= (u32)inv_sbox[(byte)(sa[2] >> (3 * 8))] << (3 * 8);
  sa[2] = sb[2] ^ rk[0][2];

  sb[3] ^= (u32)inv_sbox[(byte)(sa[3] >> (0 * 8))] << (0 * 8);
  sa[0] ^= (u32)inv_sbox[(byte)(sa[3] >> (1 * 8))] << (1 * 8);
  sa[1] ^= (u32)inv_sbox[(byte)(sa[3] >> (2 * 8))] << (2 * 8);
  sa[2] ^= (u32)inv_sbox[(byte)(sa[3] >> (3 * 8))] << (3 * 8);
  sa[3] = sb[3] ^ rk[0][3];

  buf_put_le32(b + 0, sa[0]);
  buf_put_le32(b + 4, sa[1]);
  buf_put_le32(b + 8, sa[2]);
  buf_put_le32(b + 12, sa[3]);
#undef rk

  return (56+2*sizeof(int));
}
#endif /*!USE_ARM_ASM && !USE_AMD64_ASM*/


/* Decrypt one block.  AX and BX may be the same. */
static unsigned int
do_decrypt (const RIJNDAEL_context *ctx, unsigned char *bx,
            const unsigned char *ax)
{
  return do_decrypt_fn (ctx, bx, ax);
}


static inline void
check_decryption_preparation (RIJNDAEL_context *ctx)
{
  if ( !ctx->decryption_prepared )
    {
      ctx->prepare_decryption ( ctx );
      ctx->decryption_prepared = 1;
    }
}


static unsigned int
rijndael_decrypt (void *context, byte *b, const byte *a)
{
  RIJNDAEL_context *ctx = context;

  check_decryption_preparation (ctx);

  if (ctx->prefetch_dec_fn)
    ctx->prefetch_dec_fn();

  return ctx->decrypt_fn (ctx, b, a);
}

/* Run a full self-test for ALGO and return 0 on success.  */
#define run_selftests 0

static const char *rijndael_names[] =
  {
    "RIJNDAEL",
    "AES128",
    "AES-128",
    NULL
  };

static const gcry_cipher_oid_spec_t rijndael_oids[] =
  {
    { "2.16.840.1.101.3.4.1.1", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.2", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.3", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.4", GCRY_CIPHER_MODE_CFB },
    { "2.16.840.1.101.3.4.1.6", GCRY_CIPHER_MODE_GCM },
    { "2.16.840.1.101.3.4.1.7", GCRY_CIPHER_MODE_CCM },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_aes =
  {
    GCRY_CIPHER_AES, {0, 1},
    "AES", rijndael_names, rijndael_oids, 16, 128,
    sizeof (RIJNDAEL_context),
    rijndael_setkey, rijndael_encrypt, rijndael_decrypt,
    NULL, NULL,
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_rijndael")
  };


static const char *rijndael192_names[] =
  {
    "RIJNDAEL192",
    "AES-192",
    NULL
  };

static const gcry_cipher_oid_spec_t rijndael192_oids[] =
  {
    { "2.16.840.1.101.3.4.1.21", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.22", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.23", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.24", GCRY_CIPHER_MODE_CFB },
    { "2.16.840.1.101.3.4.1.26", GCRY_CIPHER_MODE_GCM },
    { "2.16.840.1.101.3.4.1.27", GCRY_CIPHER_MODE_CCM },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_aes192 =
  {
    GCRY_CIPHER_AES192, {0, 1},
    "AES192", rijndael192_names, rijndael192_oids, 16, 192,
    sizeof (RIJNDAEL_context),
    rijndael_setkey, rijndael_encrypt, rijndael_decrypt,
    NULL, NULL,
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_rijndael")
  };


static const char *rijndael256_names[] =
  {
    "RIJNDAEL256",
    "AES-256",
    NULL
  };

static const gcry_cipher_oid_spec_t rijndael256_oids[] =
  {
    { "2.16.840.1.101.3.4.1.41", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.42", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.43", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.44", GCRY_CIPHER_MODE_CFB },
    { "2.16.840.1.101.3.4.1.46", GCRY_CIPHER_MODE_GCM },
    { "2.16.840.1.101.3.4.1.47", GCRY_CIPHER_MODE_CCM },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_aes256 =
  {
    GCRY_CIPHER_AES256, {0, 1},
    "AES256", rijndael256_names, rijndael256_oids, 16, 256,
    sizeof (RIJNDAEL_context),
    rijndael_setkey, rijndael_encrypt, rijndael_decrypt,
    NULL, NULL,
    run_selftests
    ,
    GRUB_UTIL_MODNAME("gcry_rijndael")
  };


GRUB_MOD_INIT(gcry_rijndael)
{
  grub_cipher_register (&_gcry_cipher_spec_aes);
  grub_cipher_register (&_gcry_cipher_spec_aes192);
  grub_cipher_register (&_gcry_cipher_spec_aes256);
}

GRUB_MOD_FINI(gcry_rijndael)
{
  grub_cipher_unregister (&_gcry_cipher_spec_aes);
  grub_cipher_unregister (&_gcry_cipher_spec_aes192);
  grub_cipher_unregister (&_gcry_cipher_spec_aes256);
}
