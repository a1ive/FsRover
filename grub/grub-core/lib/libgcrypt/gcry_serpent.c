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

GRUB_MOD_LICENSE("GPLv3+");

#define memset grub_memset
#define memcpy grub_memcpy

#pragma warning(disable:4018)	/* signed/unsigned mismatch (<)  */

/* serpent.c - Implementation of the Serpent encryption algorithm.
 *	Copyright (C) 2003, 2004, 2005 Free Software Foundation, Inc.
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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* Number of rounds per Serpent encrypt/decrypt operation.  */
#define ROUNDS 32

/* Magic number, used during generating of the subkeys.  */
#define PHI 0x9E3779B9

/* Serpent works on 128 bit blocks.  */
typedef u32 serpent_block_t[4];

/* Serpent key, provided by the user.  If the original key is shorter
   than 256 bits, it is padded.  */
typedef u32 serpent_key_t[8];

/* The key schedule consists of 33 128 bit subkeys.  */
typedef u32 serpent_subkeys_t[ROUNDS + 1][4];

/* A Serpent context.  */
typedef struct serpent_context
{
  serpent_subkeys_t keys;	/* Generated subkeys.  */
} serpent_context_t;

/*
 * These are the S-Boxes of Serpent from following research paper.
 *
 *  D. A. Osvik, "Speeding up Serpent," in Third AES Candidate Conference,
 *   (New York, New York, USA), p. 317-329, National Institute of Standards and
 *   Technology, 2000.
 *
 * Paper is also available at: http://www.ii.uib.no/~osvik/pub/aes3.pdf
 *
 */

#define SBOX0(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r3 ^= r0; r4 =  r1; \
    r1 &= r3; r4 ^= r2; \
    r1 ^= r0; r0 |= r3; \
    r0 ^= r4; r4 ^= r3; \
    r3 ^= r2; r2 |= r1; \
    r2 ^= r4; r4 = ~r4; \
    r4 |= r1; r1 ^= r3; \
    r1 ^= r4; r3 |= r0; \
    r1 ^= r3; r4 ^= r3; \
    \
    w = r1; x = r4; y = r2; z = r0; \
  }

#define SBOX0_INVERSE(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r2 = ~r2; r4 =  r1; \
    r1 |= r0; r4 = ~r4; \
    r1 ^= r2; r2 |= r4; \
    r1 ^= r3; r0 ^= r4; \
    r2 ^= r0; r0 &= r3; \
    r4 ^= r0; r0 |= r1; \
    r0 ^= r2; r3 ^= r4; \
    r2 ^= r1; r3 ^= r0; \
    r3 ^= r1; \
    r2 &= r3; \
    r4 ^= r2; \
    \
    w = r0; x = r4; y = r1; z = r3; \
  }

#define SBOX1(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r0 = ~r0; r2 = ~r2; \
    r4 =  r0; r0 &= r1; \
    r2 ^= r0; r0 |= r3; \
    r3 ^= r2; r1 ^= r0; \
    r0 ^= r4; r4 |= r1; \
    r1 ^= r3; r2 |= r0; \
    r2 &= r4; r0 ^= r1; \
    r1 &= r2; \
    r1 ^= r0; r0 &= r2; \
    r0 ^= r4; \
    \
    w = r2; x = r0; y = r3; z = r1; \
  }

#define SBOX1_INVERSE(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r4 =  r1; r1 ^= r3; \
    r3 &= r1; r4 ^= r2; \
    r3 ^= r0; r0 |= r1; \
    r2 ^= r3; r0 ^= r4; \
    r0 |= r2; r1 ^= r3; \
    r0 ^= r1; r1 |= r3; \
    r1 ^= r0; r4 = ~r4; \
    r4 ^= r1; r1 |= r0; \
    r1 ^= r0; \
    r1 |= r4; \
    r3 ^= r1; \
    \
    w = r4; x = r0; y = r3; z = r2; \
  }

#define SBOX2(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r4 =  r0; r0 &= r2; \
    r0 ^= r3; r2 ^= r1; \
    r2 ^= r0; r3 |= r4; \
    r3 ^= r1; r4 ^= r2; \
    r1 =  r3; r3 |= r4; \
    r3 ^= r0; r0 &= r1; \
    r4 ^= r0; r1 ^= r3; \
    r1 ^= r4; r4 = ~r4; \
    \
    w = r2; x = r3; y = r1; z = r4; \
  }

#define SBOX2_INVERSE(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r2 ^= r3; r3 ^= r0; \
    r4 =  r3; r3 &= r2; \
    r3 ^= r1; r1 |= r2; \
    r1 ^= r4; r4 &= r3; \
    r2 ^= r3; r4 &= r0; \
    r4 ^= r2; r2 &= r1; \
    r2 |= r0; r3 = ~r3; \
    r2 ^= r3; r0 ^= r3; \
    r0 &= r1; r3 ^= r4; \
    r3 ^= r0; \
    \
    w = r1; x = r4; y = r2; z = r3; \
  }

#define SBOX3(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r4 =  r0; r0 |= r3; \
    r3 ^= r1; r1 &= r4; \
    r4 ^= r2; r2 ^= r3; \
    r3 &= r0; r4 |= r1; \
    r3 ^= r4; r0 ^= r1; \
    r4 &= r0; r1 ^= r3; \
    r4 ^= r2; r1 |= r0; \
    r1 ^= r2; r0 ^= r3; \
    r2 =  r1; r1 |= r3; \
    r1 ^= r0; \
    \
    w = r1; x = r2; y = r3; z = r4; \
  }

#define SBOX3_INVERSE(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r4 =  r2; r2 ^= r1; \
    r0 ^= r2; r4 &= r2; \
    r4 ^= r0; r0 &= r1; \
    r1 ^= r3; r3 |= r4; \
    r2 ^= r3; r0 ^= r3; \
    r1 ^= r4; r3 &= r2; \
    r3 ^= r1; r1 ^= r0; \
    r1 |= r2; r0 ^= r3; \
    r1 ^= r4; \
    r0 ^= r1; \
    \
    w = r2; x = r1; y = r3; z = r0; \
  }

#define SBOX4(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r1 ^= r3; r3 = ~r3; \
    r2 ^= r3; r3 ^= r0; \
    r4 =  r1; r1 &= r3; \
    r1 ^= r2; r4 ^= r3; \
    r0 ^= r4; r2 &= r4; \
    r2 ^= r0; r0 &= r1; \
    r3 ^= r0; r4 |= r1; \
    r4 ^= r0; r0 |= r3; \
    r0 ^= r2; r2 &= r3; \
    r0 = ~r0; r4 ^= r2; \
    \
    w = r1; x = r4; y = r0; z = r3; \
  }

#define SBOX4_INVERSE(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r4 =  r2; r2 &= r3; \
    r2 ^= r1; r1 |= r3; \
    r1 &= r0; r4 ^= r2; \
    r4 ^= r1; r1 &= r2; \
    r0 = ~r0; r3 ^= r4; \
    r1 ^= r3; r3 &= r0; \
    r3 ^= r2; r0 ^= r1; \
    r2 &= r0; r3 ^= r0; \
    r2 ^= r4; \
    r2 |= r3; r3 ^= r0; \
    r2 ^= r1; \
    \
    w = r0; x = r3; y = r2; z = r4; \
  }

#define SBOX5(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r0 ^= r1; r1 ^= r3; \
    r3 = ~r3; r4 =  r1; \
    r1 &= r0; r2 ^= r3; \
    r1 ^= r2; r2 |= r4; \
    r4 ^= r3; r3 &= r1; \
    r3 ^= r0; r4 ^= r1; \
    r4 ^= r2; r2 ^= r0; \
    r0 &= r3; r2 = ~r2; \
    r0 ^= r4; r4 |= r3; \
    r2 ^= r4; \
    \
    w = r1; x = r3; y = r0; z = r2; \
  }

#define SBOX5_INVERSE(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r1 = ~r1; r4 =  r3; \
    r2 ^= r1; r3 |= r0; \
    r3 ^= r2; r2 |= r1; \
    r2 &= r0; r4 ^= r3; \
    r2 ^= r4; r4 |= r0; \
    r4 ^= r1; r1 &= r2; \
    r1 ^= r3; r4 ^= r2; \
    r3 &= r4; r4 ^= r1; \
    r3 ^= r4; r4 = ~r4; \
    r3 ^= r0; \
    \
    w = r1; x = r4; y = r3; z = r2; \
  }

#define SBOX6(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r2 = ~r2; r4 =  r3; \
    r3 &= r0; r0 ^= r4; \
    r3 ^= r2; r2 |= r4; \
    r1 ^= r3; r2 ^= r0; \
    r0 |= r1; r2 ^= r1; \
    r4 ^= r0; r0 |= r3; \
    r0 ^= r2; r4 ^= r3; \
    r4 ^= r0; r3 = ~r3; \
    r2 &= r4; \
    r2 ^= r3; \
    \
    w = r0; x = r1; y = r4; z = r2; \
  }

#define SBOX6_INVERSE(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r0 ^= r2; r4 =  r2; \
    r2 &= r0; r4 ^= r3; \
    r2 = ~r2; r3 ^= r1; \
    r2 ^= r3; r4 |= r0; \
    r0 ^= r2; r3 ^= r4; \
    r4 ^= r1; r1 &= r3; \
    r1 ^= r0; r0 ^= r3; \
    r0 |= r2; r3 ^= r1; \
    r4 ^= r0; \
    \
    w = r1; x = r2; y = r4; z = r3; \
  }

#define SBOX7(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r4 =  r1; r1 |= r2; \
    r1 ^= r3; r4 ^= r2; \
    r2 ^= r1; r3 |= r4; \
    r3 &= r0; r4 ^= r2; \
    r3 ^= r1; r1 |= r4; \
    r1 ^= r0; r0 |= r4; \
    r0 ^= r2; r1 ^= r4; \
    r2 ^= r1; r1 &= r0; \
    r1 ^= r4; r2 = ~r2; \
    r2 |= r0; \
    r4 ^= r2; \
    \
    w = r4; x = r3; y = r1; z = r0; \
  }

#define SBOX7_INVERSE(r0, r1, r2, r3, w, x, y, z) \
  { \
    u32 r4; \
    \
    r4 =  r2; r2 ^= r0; \
    r0 &= r3; r4 |= r3; \
    r2 = ~r2; r3 ^= r1; \
    r1 |= r0; r0 ^= r2; \
    r2 &= r4; r3 &= r4; \
    r1 ^= r2; r2 ^= r0; \
    r0 |= r2; r4 ^= r1; \
    r0 ^= r3; r3 ^= r4; \
    r4 |= r0; r3 ^= r2; \
    r4 ^= r2; \
    \
    w = r3; x = r0; y = r1; z = r4; \
  }

/* XOR BLOCK1 into BLOCK0.  */
#define BLOCK_XOR(block0, block1) \
  {                               \
    block0[0] ^= block1[0];       \
    block0[1] ^= block1[1];       \
    block0[2] ^= block1[2];       \
    block0[3] ^= block1[3];       \
  }

/* Copy BLOCK_SRC to BLOCK_DST.  */
#define BLOCK_COPY(block_dst, block_src) \
  {                                      \
    block_dst[0] = block_src[0];         \
    block_dst[1] = block_src[1];         \
    block_dst[2] = block_src[2];         \
    block_dst[3] = block_src[3];         \
  }

/* Apply SBOX number WHICH to to the block found in ARRAY0, writing
   the output to the block found in ARRAY1.  */
#define SBOX(which, array0, array1)                         \
  SBOX##which (array0[0], array0[1], array0[2], array0[3],  \
               array1[0], array1[1], array1[2], array1[3]);

/* Apply inverse SBOX number WHICH to to the block found in ARRAY0, writing
   the output to the block found in ARRAY1.  */
#define SBOX_INVERSE(which, array0, array1)                           \
  SBOX##which##_INVERSE (array0[0], array0[1], array0[2], array0[3],  \
                         array1[0], array1[1], array1[2], array1[3]);

/* Apply the linear transformation to BLOCK.  */
#define LINEAR_TRANSFORMATION(block)                  \
  {                                                   \
    block[0] = rol (block[0], 13);                    \
    block[2] = rol (block[2], 3);                     \
    block[1] = block[1] ^ block[0] ^ block[2];        \
    block[3] = block[3] ^ block[2] ^ (block[0] << 3); \
    block[1] = rol (block[1], 1);                     \
    block[3] = rol (block[3], 7);                     \
    block[0] = block[0] ^ block[1] ^ block[3];        \
    block[2] = block[2] ^ block[3] ^ (block[1] << 7); \
    block[0] = rol (block[0], 5);                     \
    block[2] = rol (block[2], 22);                    \
  }

/* Apply the inverse linear transformation to BLOCK.  */
#define LINEAR_TRANSFORMATION_INVERSE(block)          \
  {                                                   \
    block[2] = ror (block[2], 22);                    \
    block[0] = ror (block[0] , 5);                    \
    block[2] = block[2] ^ block[3] ^ (block[1] << 7); \
    block[0] = block[0] ^ block[1] ^ block[3];        \
    block[3] = ror (block[3], 7);                     \
    block[1] = ror (block[1], 1);                     \
    block[3] = block[3] ^ block[2] ^ (block[0] << 3); \
    block[1] = block[1] ^ block[0] ^ block[2];        \
    block[2] = ror (block[2], 3);                     \
    block[0] = ror (block[0], 13);                    \
  }

/* Apply a Serpent round to BLOCK, using the SBOX number WHICH and the
   subkeys contained in SUBKEYS.  Use BLOCK_TMP as temporary storage.
   This macro increments `round'.  */
#define ROUND(which, subkeys, block, block_tmp) \
  {                                             \
    BLOCK_XOR (block, subkeys[round]);          \
    round++;                                    \
    SBOX (which, block, block_tmp);             \
    LINEAR_TRANSFORMATION (block_tmp);          \
    BLOCK_COPY (block, block_tmp);              \
  }

/* Apply the last Serpent round to BLOCK, using the SBOX number WHICH
   and the subkeys contained in SUBKEYS.  Use BLOCK_TMP as temporary
   storage.  The result will be stored in BLOCK_TMP.  This macro
   increments `round'.  */
#define ROUND_LAST(which, subkeys, block, block_tmp) \
  {                                                  \
    BLOCK_XOR (block, subkeys[round]);               \
    round++;                                         \
    SBOX (which, block, block_tmp);                  \
    BLOCK_XOR (block_tmp, subkeys[round]);           \
    round++;                                         \
  }

/* Apply an inverse Serpent round to BLOCK, using the SBOX number
   WHICH and the subkeys contained in SUBKEYS.  Use BLOCK_TMP as
   temporary storage.  This macro increments `round'.  */
#define ROUND_INVERSE(which, subkey, block, block_tmp) \
  {                                                    \
    LINEAR_TRANSFORMATION_INVERSE (block);             \
    SBOX_INVERSE (which, block, block_tmp);            \
    BLOCK_XOR (block_tmp, subkey[round]);              \
    round--;                                           \
    BLOCK_COPY (block, block_tmp);                     \
  }

/* Apply the first Serpent round to BLOCK, using the SBOX number WHICH
   and the subkeys contained in SUBKEYS.  Use BLOCK_TMP as temporary
   storage.  The result will be stored in BLOCK_TMP.  This macro
   increments `round'.  */
#define ROUND_FIRST_INVERSE(which, subkeys, block, block_tmp) \
  {                                                           \
    BLOCK_XOR (block, subkeys[round]);                        \
    round--;                                                  \
    SBOX_INVERSE (which, block, block_tmp);                   \
    BLOCK_XOR (block_tmp, subkeys[round]);                    \
    round--;                                                  \
  }

/* Convert the user provided key KEY of KEY_LENGTH bytes into the
   internally used format.  */
static void
serpent_key_prepare (const byte *key, unsigned int key_length,
		     serpent_key_t key_prepared)
{
  int i;

  /* Copy key.  */
  key_length /= 4;
  for (i = 0; i < key_length; i++)
    key_prepared[i] = buf_get_le32 (key + i * 4);

  if (i < 8)
    {
      /* Key must be padded according to the Serpent
	 specification.  */
      key_prepared[i] = 0x00000001;

      for (i++; i < 8; i++)
	key_prepared[i] = 0;
    }
}

/* Derive the 33 subkeys from KEY and store them in SUBKEYS.  */
static void
serpent_subkeys_generate (serpent_key_t key, serpent_subkeys_t subkeys)
{
  u32 w[8];		/* The `prekey'.  */
  u32 ws[4];
  u32 wt[4];

  /* Initialize with key values.  */
  w[0] = key[0];
  w[1] = key[1];
  w[2] = key[2];
  w[3] = key[3];
  w[4] = key[4];
  w[5] = key[5];
  w[6] = key[6];
  w[7] = key[7];

  /* Expand to intermediate key using the affine recurrence.  */
#define EXPAND_KEY4(wo, r)                                                     \
  wo[0] = w[(r+0)%8] =                                                         \
    rol (w[(r+0)%8] ^ w[(r+3)%8] ^ w[(r+5)%8] ^ w[(r+7)%8] ^ PHI ^ (r+0), 11); \
  wo[1] = w[(r+1)%8] =                                                         \
    rol (w[(r+1)%8] ^ w[(r+4)%8] ^ w[(r+6)%8] ^ w[(r+0)%8] ^ PHI ^ (r+1), 11); \
  wo[2] = w[(r+2)%8] =                                                         \
    rol (w[(r+2)%8] ^ w[(r+5)%8] ^ w[(r+7)%8] ^ w[(r+1)%8] ^ PHI ^ (r+2), 11); \
  wo[3] = w[(r+3)%8] =                                                         \
    rol (w[(r+3)%8] ^ w[(r+6)%8] ^ w[(r+0)%8] ^ w[(r+2)%8] ^ PHI ^ (r+3), 11);

#define EXPAND_KEY(r)       \
  EXPAND_KEY4(ws, (r));     \
  EXPAND_KEY4(wt, (r + 4));

  /* Calculate subkeys via S-Boxes, in bitslice mode.  */
  EXPAND_KEY (0); SBOX (3, ws, subkeys[0]); SBOX (2, wt, subkeys[1]);
  EXPAND_KEY (8); SBOX (1, ws, subkeys[2]); SBOX (0, wt, subkeys[3]);
  EXPAND_KEY (16); SBOX (7, ws, subkeys[4]); SBOX (6, wt, subkeys[5]);
  EXPAND_KEY (24); SBOX (5, ws, subkeys[6]); SBOX (4, wt, subkeys[7]);
  EXPAND_KEY (32); SBOX (3, ws, subkeys[8]); SBOX (2, wt, subkeys[9]);
  EXPAND_KEY (40); SBOX (1, ws, subkeys[10]); SBOX (0, wt, subkeys[11]);
  EXPAND_KEY (48); SBOX (7, ws, subkeys[12]); SBOX (6, wt, subkeys[13]);
  EXPAND_KEY (56); SBOX (5, ws, subkeys[14]); SBOX (4, wt, subkeys[15]);
  EXPAND_KEY (64); SBOX (3, ws, subkeys[16]); SBOX (2, wt, subkeys[17]);
  EXPAND_KEY (72); SBOX (1, ws, subkeys[18]); SBOX (0, wt, subkeys[19]);
  EXPAND_KEY (80); SBOX (7, ws, subkeys[20]); SBOX (6, wt, subkeys[21]);
  EXPAND_KEY (88); SBOX (5, ws, subkeys[22]); SBOX (4, wt, subkeys[23]);
  EXPAND_KEY (96); SBOX (3, ws, subkeys[24]); SBOX (2, wt, subkeys[25]);
  EXPAND_KEY (104); SBOX (1, ws, subkeys[26]); SBOX (0, wt, subkeys[27]);
  EXPAND_KEY (112); SBOX (7, ws, subkeys[28]); SBOX (6, wt, subkeys[29]);
  EXPAND_KEY (120); SBOX (5, ws, subkeys[30]); SBOX (4, wt, subkeys[31]);
  EXPAND_KEY4 (ws, 128); SBOX (3, ws, subkeys[32]);

  wipememory (ws, sizeof (ws));
  wipememory (wt, sizeof (wt));
  wipememory (w, sizeof (w));
}

/* Initialize CONTEXT with the key KEY of KEY_LENGTH bits.  */
static gcry_err_code_t
serpent_setkey_internal (serpent_context_t *context,
			 const byte *key, unsigned int key_length)
{
  serpent_key_t key_prepared;

  if (key_length > 32)
    return GPG_ERR_INV_KEYLEN;

  serpent_key_prepare (key, key_length, key_prepared);
  serpent_subkeys_generate (key_prepared, context->keys);

  wipememory (key_prepared, sizeof(key_prepared));
  return 0;
}

/* Initialize CTX with the key KEY of KEY_LENGTH bytes.  */
static gcry_err_code_t
serpent_setkey (void *ctx,
		const byte *key, unsigned int key_length,
                cipher_bulk_ops_t *bulk_ops)
{
  serpent_context_t *context = ctx;
  static const char *serpent_test_ret;
  static int serpent_init_done;
  gcry_err_code_t ret = GPG_ERR_NO_ERROR;

  if (! serpent_init_done)
    {
      /* Execute a self-test the first time, Serpent is used.  */
      serpent_init_done = 1;
    }

  (void) bulk_ops;

  if (serpent_test_ret)
    ret = GPG_ERR_SELFTEST_FAILED;
  else
    ret = serpent_setkey_internal (context, key, key_length);

  return ret;
}

static void
serpent_encrypt_internal (serpent_context_t *context,
			  const byte *input, byte *output)
{
  serpent_block_t b, b_next;
  int round = 0;

  b[0] = buf_get_le32 (input + 0);
  b[1] = buf_get_le32 (input + 4);
  b[2] = buf_get_le32 (input + 8);
  b[3] = buf_get_le32 (input + 12);

  ROUND (0, context->keys, b, b_next);
  ROUND (1, context->keys, b, b_next);
  ROUND (2, context->keys, b, b_next);
  ROUND (3, context->keys, b, b_next);
  ROUND (4, context->keys, b, b_next);
  ROUND (5, context->keys, b, b_next);
  ROUND (6, context->keys, b, b_next);
  ROUND (7, context->keys, b, b_next);
  ROUND (0, context->keys, b, b_next);
  ROUND (1, context->keys, b, b_next);
  ROUND (2, context->keys, b, b_next);
  ROUND (3, context->keys, b, b_next);
  ROUND (4, context->keys, b, b_next);
  ROUND (5, context->keys, b, b_next);
  ROUND (6, context->keys, b, b_next);
  ROUND (7, context->keys, b, b_next);
  ROUND (0, context->keys, b, b_next);
  ROUND (1, context->keys, b, b_next);
  ROUND (2, context->keys, b, b_next);
  ROUND (3, context->keys, b, b_next);
  ROUND (4, context->keys, b, b_next);
  ROUND (5, context->keys, b, b_next);
  ROUND (6, context->keys, b, b_next);
  ROUND (7, context->keys, b, b_next);
  ROUND (0, context->keys, b, b_next);
  ROUND (1, context->keys, b, b_next);
  ROUND (2, context->keys, b, b_next);
  ROUND (3, context->keys, b, b_next);
  ROUND (4, context->keys, b, b_next);
  ROUND (5, context->keys, b, b_next);
  ROUND (6, context->keys, b, b_next);

  ROUND_LAST (7, context->keys, b, b_next);

  buf_put_le32 (output + 0, b_next[0]);
  buf_put_le32 (output + 4, b_next[1]);
  buf_put_le32 (output + 8, b_next[2]);
  buf_put_le32 (output + 12, b_next[3]);
}

static void
serpent_decrypt_internal (serpent_context_t *context,
			  const byte *input, byte *output)
{
  serpent_block_t b, b_next;
  int round = ROUNDS;

  b_next[0] = buf_get_le32 (input + 0);
  b_next[1] = buf_get_le32 (input + 4);
  b_next[2] = buf_get_le32 (input + 8);
  b_next[3] = buf_get_le32 (input + 12);

  ROUND_FIRST_INVERSE (7, context->keys, b_next, b);

  ROUND_INVERSE (6, context->keys, b, b_next);
  ROUND_INVERSE (5, context->keys, b, b_next);
  ROUND_INVERSE (4, context->keys, b, b_next);
  ROUND_INVERSE (3, context->keys, b, b_next);
  ROUND_INVERSE (2, context->keys, b, b_next);
  ROUND_INVERSE (1, context->keys, b, b_next);
  ROUND_INVERSE (0, context->keys, b, b_next);
  ROUND_INVERSE (7, context->keys, b, b_next);
  ROUND_INVERSE (6, context->keys, b, b_next);
  ROUND_INVERSE (5, context->keys, b, b_next);
  ROUND_INVERSE (4, context->keys, b, b_next);
  ROUND_INVERSE (3, context->keys, b, b_next);
  ROUND_INVERSE (2, context->keys, b, b_next);
  ROUND_INVERSE (1, context->keys, b, b_next);
  ROUND_INVERSE (0, context->keys, b, b_next);
  ROUND_INVERSE (7, context->keys, b, b_next);
  ROUND_INVERSE (6, context->keys, b, b_next);
  ROUND_INVERSE (5, context->keys, b, b_next);
  ROUND_INVERSE (4, context->keys, b, b_next);
  ROUND_INVERSE (3, context->keys, b, b_next);
  ROUND_INVERSE (2, context->keys, b, b_next);
  ROUND_INVERSE (1, context->keys, b, b_next);
  ROUND_INVERSE (0, context->keys, b, b_next);
  ROUND_INVERSE (7, context->keys, b, b_next);
  ROUND_INVERSE (6, context->keys, b, b_next);
  ROUND_INVERSE (5, context->keys, b, b_next);
  ROUND_INVERSE (4, context->keys, b, b_next);
  ROUND_INVERSE (3, context->keys, b, b_next);
  ROUND_INVERSE (2, context->keys, b, b_next);
  ROUND_INVERSE (1, context->keys, b, b_next);
  ROUND_INVERSE (0, context->keys, b, b_next);

  buf_put_le32 (output + 0, b_next[0]);
  buf_put_le32 (output + 4, b_next[1]);
  buf_put_le32 (output + 8, b_next[2]);
  buf_put_le32 (output + 12, b_next[3]);
}

static unsigned int
serpent_encrypt (void *ctx, byte *buffer_out, const byte *buffer_in)
{
  serpent_context_t *context = ctx;

  serpent_encrypt_internal (context, buffer_in, buffer_out);
  return /*burn_stack*/ (2 * sizeof (serpent_block_t));
}

static unsigned int
serpent_decrypt (void *ctx, byte *buffer_out, const byte *buffer_in)
{
  serpent_context_t *context = ctx;

  serpent_decrypt_internal (context, buffer_in, buffer_out);
  return /*burn_stack*/ (2 * sizeof (serpent_block_t));
}

static const gcry_cipher_oid_spec_t serpent128_oids[] =
  {
    {"1.3.6.1.4.1.11591.13.2.1", GCRY_CIPHER_MODE_ECB },
    {"1.3.6.1.4.1.11591.13.2.2", GCRY_CIPHER_MODE_CBC },
    {"1.3.6.1.4.1.11591.13.2.3", GCRY_CIPHER_MODE_OFB },
    {"1.3.6.1.4.1.11591.13.2.4", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

static const gcry_cipher_oid_spec_t serpent192_oids[] =
  {
    {"1.3.6.1.4.1.11591.13.2.21", GCRY_CIPHER_MODE_ECB },
    {"1.3.6.1.4.1.11591.13.2.22", GCRY_CIPHER_MODE_CBC },
    {"1.3.6.1.4.1.11591.13.2.23", GCRY_CIPHER_MODE_OFB },
    {"1.3.6.1.4.1.11591.13.2.24", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

static const gcry_cipher_oid_spec_t serpent256_oids[] =
  {
    {"1.3.6.1.4.1.11591.13.2.41", GCRY_CIPHER_MODE_ECB },
    {"1.3.6.1.4.1.11591.13.2.42", GCRY_CIPHER_MODE_CBC },
    {"1.3.6.1.4.1.11591.13.2.43", GCRY_CIPHER_MODE_OFB },
    {"1.3.6.1.4.1.11591.13.2.44", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

static const char *serpent128_aliases[] =
  {
    "SERPENT",
    "SERPENT-128",
    NULL
  };
static const char *serpent192_aliases[] =
  {
    "SERPENT-192",
    NULL
  };
static const char *serpent256_aliases[] =
  {
    "SERPENT-256",
    NULL
  };

gcry_cipher_spec_t _gcry_cipher_spec_serpent128 =
  {
    GCRY_CIPHER_SERPENT128, {0, 0},
    "SERPENT128", serpent128_aliases, serpent128_oids, 16, 128,
    sizeof (serpent_context_t),
    serpent_setkey, serpent_encrypt, serpent_decrypt
    ,
    GRUB_UTIL_MODNAME("gcry_serpent")
  };

gcry_cipher_spec_t _gcry_cipher_spec_serpent192 =
  {
    GCRY_CIPHER_SERPENT192, {0, 0},
    "SERPENT192", serpent192_aliases, serpent192_oids, 16, 192,
    sizeof (serpent_context_t),
    serpent_setkey, serpent_encrypt, serpent_decrypt
    ,
    GRUB_UTIL_MODNAME("gcry_serpent")
  };

gcry_cipher_spec_t _gcry_cipher_spec_serpent256 =
  {
    GCRY_CIPHER_SERPENT256, {0, 0},
    "SERPENT256", serpent256_aliases, serpent256_oids, 16, 256,
    sizeof (serpent_context_t),
    serpent_setkey, serpent_encrypt, serpent_decrypt
    ,
    GRUB_UTIL_MODNAME("gcry_serpent")
  };


GRUB_MOD_INIT(gcry_serpent)
{
  grub_cipher_register (&_gcry_cipher_spec_serpent128);
  grub_cipher_register (&_gcry_cipher_spec_serpent192);
  grub_cipher_register (&_gcry_cipher_spec_serpent256);
}

GRUB_MOD_FINI(gcry_serpent)
{
  grub_cipher_unregister (&_gcry_cipher_spec_serpent128);
  grub_cipher_unregister (&_gcry_cipher_spec_serpent192);
  grub_cipher_unregister (&_gcry_cipher_spec_serpent256);
}
