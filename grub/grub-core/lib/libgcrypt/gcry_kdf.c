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

#include <stddef.h>	/* offsetof */

#include <grub/types.h>
#include <grub/crypto.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include "gcry_wrap.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define U64_C(c) (c ## ULL)
#define SIZE_MAX GRUB_SIZE_MAX
#define memset grub_memset
#define memcpy grub_memcpy
#define xtrymalloc(n) grub_malloc (n)
#define xfree(p) grub_free (p)

#pragma warning(disable:4018)	/* signed/unsigned mismatch (<)  */

/* kdf.c  - Key Derivation Functions
 * Copyright (C) 1998, 2008, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
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

/* Transform a passphrase into a suitable key of length KEYSIZE and
   store this key in the caller provided buffer KEYBUFFER.  The caller
   must provide an HASHALGO, a valid ALGO and depending on that algo a
   SALT of 8 bytes and the number of ITERATIONS.  Code taken from
   gnupg/agent/protect.c:hash_passphrase.  */


/* Transform a passphrase into a suitable key of length KEYSIZE and
   store this key in the caller provided buffer KEYBUFFER.  The caller
   must provide PRFALGO which indicates the pseudorandom function to
   use: This shall be the algorithms id of a hash algorithm; it is
   used in HMAC mode.  SALT is a salt of length SALTLEN and ITERATIONS
   gives the number of iterations.  */


/* Derive a key from a passphrase.  KEYSIZE gives the requested size
   of the keys in octets.  KEYBUFFER is a caller provided buffer
   filled on success with the derived key.  The input passphrase is
   taken from (PASSPHRASE,PASSPHRASELEN) which is an arbitrary memory
   buffer.  ALGO specifies the KDF algorithm to use; these are the
   constants GCRY_KDF_*.  SUBALGO specifies an algorithm used
   internally by the KDF algorithms; this is usually a hash algorithm
   but certain KDF algorithm may use it differently.  {SALT,SALTLEN}
   is a salt as needed by most KDF algorithms.  ITERATIONS is a
   positive integer parameter to most KDFs.  0 is returned on success,
   or an error code on failure.  */

typedef struct argon2_context *argon2_ctx_t;

/* Per thread data for Argon2.  */
struct argon2_thread_data {
  argon2_ctx_t a;
  unsigned int pass;
  unsigned int slice;
  unsigned int lane;
};

/* Argon2 context */
struct argon2_context {
  int algo;
  int hash_type;

  unsigned int outlen;

  const unsigned char *password;
  size_t passwordlen;

  const unsigned char *salt;
  size_t saltlen;

  const unsigned char *key;
  size_t keylen;

  const unsigned char *ad;
  size_t adlen;

  unsigned int m_cost;

  unsigned int passes;
  unsigned int memory_blocks;
  unsigned int segment_length;
  unsigned int lane_length;
  unsigned int lanes;

  u64 *block;
  struct argon2_thread_data *thread_data;

  unsigned char out[1];  /* In future, we may use flexible array member.  */
};

#define ARGON2_VERSION 0x13

#define ARGON2_WORDS_IN_BLOCK (1024/8)

static void
xor_block (u64 *dst, const u64 *src)
{
  int i;

  for (i = 0; i < ARGON2_WORDS_IN_BLOCK; i++)
    dst[i] ^= src[i];
}

static void
beswap64_block (u64 *dst)
{
#ifdef WORDS_BIGENDIAN
  int i;

  /* Swap a block in big-endian 64-bit word into one in
     little-endian.  */
  for (i = 0; i < ARGON2_WORDS_IN_BLOCK; i++)
    dst[i] = _gcry_bswap64 (dst[i]);
#else
  /* Nothing to do.  */
  (void)dst;
#endif
}

/* Implementation of _gcry_blake2b_512_hash_buffers */
static gcry_err_code_t
argon2_blake2b_512_hash_buffers (void *outbuf, const gcry_buffer_t *iov, int iovcnt)
{
  void *hd;

  hd = xtrymalloc (_gcry_digest_spec_blake2b_512.contextsize);
  if (!hd)
    return GPG_ERR_OUT_OF_MEMORY;

  _gcry_digest_spec_blake2b_512.init (hd, 0);
  for (;iovcnt > 0; iov++, iovcnt--)
    _gcry_digest_spec_blake2b_512.write (hd, (const char*)iov[0].data + iov[0].off, iov[0].len);
  _gcry_digest_spec_blake2b_512.final (hd);
  grub_memcpy (outbuf, _gcry_digest_spec_blake2b_512.read (hd), 512 / 8);

  xfree (hd);

  return GPG_ERR_NO_ERROR;
}

static gpg_err_code_t
argon2_fill_first_blocks (argon2_ctx_t a)
{
  gpg_err_code_t err;
  unsigned char h0_01_i[72];
  unsigned char buf[10][4];
  gcry_buffer_t iov[8];
  unsigned int iov_count = 0;
  int i;

  /* Generate H0.  */
  buf_put_le32 (buf[0], a->lanes);
  buf_put_le32 (buf[1], a->outlen);
  buf_put_le32 (buf[2], a->m_cost);
  buf_put_le32 (buf[3], a->passes);
  buf_put_le32 (buf[4], ARGON2_VERSION);
  buf_put_le32 (buf[5], a->hash_type);
  buf_put_le32 (buf[6], a->passwordlen);
  iov[iov_count].data = buf[0];
  iov[iov_count].len = 4 * 7;
  iov[iov_count].off = 0;
  iov_count++;
  if (a->passwordlen)
    {
      iov[iov_count].data = (void *)a->password;
      iov[iov_count].len = a->passwordlen;
      iov[iov_count].off = 0;
      iov_count++;
    }

  buf_put_le32 (buf[7], a->saltlen);
  iov[iov_count].data = buf[7];
  iov[iov_count].len = 4;
  iov[iov_count].off = 0;
  iov_count++;
  iov[iov_count].data = (void *)a->salt;
  iov[iov_count].len = a->saltlen;
  iov[iov_count].off = 0;
  iov_count++;

  buf_put_le32 (buf[8], a->keylen);
  iov[iov_count].data = buf[8];
  iov[iov_count].len = 4;
  iov[iov_count].off = 0;
  iov_count++;
  if (a->key)
    {
      iov[iov_count].data = (void *)a->key;
      iov[iov_count].len = a->keylen;
      iov[iov_count].off = 0;
      iov_count++;
    }

  buf_put_le32 (buf[9], a->adlen);
  iov[iov_count].data = buf[9];
  iov[iov_count].len = 4;
  iov[iov_count].off = 0;
  iov_count++;
  if (a->ad)
    {
      iov[iov_count].data = (void *)a->ad;
      iov[iov_count].len = a->adlen;
      iov[iov_count].off = 0;
      iov_count++;
    }

  err = argon2_blake2b_512_hash_buffers (h0_01_i, iov, iov_count);
  if (err != GPG_ERR_NO_ERROR)
    return err;

  for (i = 0; i < a->lanes; i++)
    {
      memset (h0_01_i+64, 0, 4);
      buf_put_le32 (h0_01_i+64+4, i);
      blake2b_vl_hash (h0_01_i, 72, 1024,
                       &a->block[i*a->lane_length*ARGON2_WORDS_IN_BLOCK]);
      beswap64_block (&a->block[i*a->lane_length*ARGON2_WORDS_IN_BLOCK]);

      buf_put_le32 (h0_01_i+64, 1);
      blake2b_vl_hash (h0_01_i, 72, 1024,
                       &a->block[(i*a->lane_length+1)*ARGON2_WORDS_IN_BLOCK]);
      beswap64_block (&a->block[(i*a->lane_length+1)*ARGON2_WORDS_IN_BLOCK]);
    }
  return 0;
}

static gpg_err_code_t
argon2_init (argon2_ctx_t a, unsigned int parallelism,
             unsigned int m_cost, unsigned int t_cost)
{
  gpg_err_code_t ec = 0;
  unsigned int memory_blocks;
  size_t memory_bytes;
  unsigned int segment_length;
  void *block;
  struct argon2_thread_data *thread_data;

  memory_blocks = m_cost;
  if (memory_blocks < 8 * parallelism)
    memory_blocks = 8 * parallelism;

  segment_length = memory_blocks / (parallelism * 4);
  memory_blocks = segment_length * parallelism * 4;

  a->passes = t_cost;
  a->memory_blocks = memory_blocks;
  a->segment_length = segment_length;
  a->lane_length = segment_length * 4;
  a->lanes = parallelism;

  a->block = NULL;
  a->thread_data = NULL;

  if (U64_C(1024) * memory_blocks > SIZE_MAX)
    return GPG_ERR_INV_VALUE;

  memory_bytes = 1024 * (size_t)memory_blocks;
  block = xtrymalloc (memory_bytes);
  if (!block)
    {
      ec = GPG_ERR_OUT_OF_MEMORY;
      return ec;
    }
  memset (block, 0, memory_bytes);

  thread_data = xtrymalloc (a->lanes * sizeof (struct argon2_thread_data));
  if (!thread_data)
    {
      ec = GPG_ERR_OUT_OF_MEMORY;
      xfree (block);
      return ec;
    }

  memset (thread_data, 0, a->lanes * sizeof (struct argon2_thread_data));

  a->block = block;
  a->thread_data = thread_data;
  return 0;
}


static u64 fBlaMka (u64 x, u64 y)
{
  const u64 m = U64_C(0xFFFFFFFF);
  return x + y + 2 * (x & m) * (y & m);
}

static u64 rotr64 (u64 w, unsigned int c)
{
  return (w >> c) | (w << (64 - c));
}

#define G(a, b, c, d)                                                          \
    do {                                                                       \
        a = fBlaMka(a, b);                                                     \
        d = rotr64(d ^ a, 32);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = rotr64(b ^ c, 24);                                                 \
        a = fBlaMka(a, b);                                                     \
        d = rotr64(d ^ a, 16);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = rotr64(b ^ c, 63);                                                 \
    } while ((void)0, 0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,   \
                           v12, v13, v14, v15)                                 \
    do {                                                                       \
        G(v0, v4, v8, v12);                                                    \
        G(v1, v5, v9, v13);                                                    \
        G(v2, v6, v10, v14);                                                   \
        G(v3, v7, v11, v15);                                                   \
        G(v0, v5, v10, v15);                                                   \
        G(v1, v6, v11, v12);                                                   \
        G(v2, v7, v8, v13);                                                    \
        G(v3, v4, v9, v14);                                                    \
    } while ((void)0, 0)

static void
fill_block (const u64 *prev_block, const u64 *ref_block, u64 *curr_block,
            int with_xor)
{
  u64 block_r[ARGON2_WORDS_IN_BLOCK];
  u64 block_tmp[ARGON2_WORDS_IN_BLOCK];
  int i;

  if (prev_block)
    {
      for (i = 0; i < ARGON2_WORDS_IN_BLOCK; i++)
        block_r[i] = ref_block[i] ^ prev_block[i];
    }
  else
    memcpy (block_r, ref_block, 1024);

  memcpy (block_tmp, block_r, 1024);

  if (with_xor)
    xor_block (block_tmp, curr_block);

  for (i = 0; i < 8; ++i)
    BLAKE2_ROUND_NOMSG
      (block_r[16 * i],      block_r[16 * i + 1],  block_r[16 * i + 2],
       block_r[16 * i + 3],  block_r[16 * i + 4],  block_r[16 * i + 5],
       block_r[16 * i + 6],  block_r[16 * i + 7],  block_r[16 * i + 8],
       block_r[16 * i + 9],  block_r[16 * i + 10], block_r[16 * i + 11],
       block_r[16 * i + 12], block_r[16 * i + 13], block_r[16 * i + 14],
       block_r[16 * i + 15]);

  for (i = 0; i < 8; i++)
    BLAKE2_ROUND_NOMSG
      (block_r[2 * i],      block_r[2 * i + 1],  block_r[2 * i + 16],
       block_r[2 * i + 17], block_r[2 * i + 32], block_r[2 * i + 33],
       block_r[2 * i + 48], block_r[2 * i + 49], block_r[2 * i + 64],
       block_r[2 * i + 65], block_r[2 * i + 80], block_r[2 * i + 81],
       block_r[2 * i + 96], block_r[2 * i + 97], block_r[2 * i + 112],
       block_r[2 * i + 113]);

  memcpy (curr_block, block_tmp, 1024);
  xor_block (curr_block, block_r);
}

static void
pseudo_random_generate (u64 *random_block, u64 *input_block)
{
  input_block[6]++;
  fill_block (NULL, input_block, random_block, 0);
  fill_block (NULL, random_block, random_block, 0);
}

static u32
index_alpha (argon2_ctx_t a, const struct argon2_thread_data *t,
             int segment_index, u32 random, int same_lane)
{
  u32 reference_area_size;
  u64 relative_position;
  u32 start_position;

  if (t->pass == 0)
    {
      if (t->slice == 0)
        reference_area_size = segment_index - 1;
      else
        {
          if (same_lane)
            reference_area_size = t->slice * a->segment_length
              + segment_index - 1;
          else
            reference_area_size = t->slice * a->segment_length +
              ((segment_index == 0) ? -1 : 0);
        }
    }
  else
    {
      if (same_lane)
        reference_area_size = a->lane_length
          - a->segment_length + segment_index - 1;
      else
        reference_area_size = a->lane_length
          - a->segment_length + ((segment_index == 0) ? -1 : 0);
    }

  relative_position = (random * (u64)random) >> 32;
  relative_position = reference_area_size - 1 -
    ((reference_area_size * relative_position) >> 32);

  if (t->pass == 0)
    start_position = 0;
  else
    start_position = (t->slice == 4 - 1)
      ? 0
      : (t->slice + 1) * a->segment_length;

  return (start_position + relative_position) % a->lane_length;
}

static void
argon2_compute_segment (void *priv)
{
  const struct argon2_thread_data *t = (const struct argon2_thread_data *)priv;
  argon2_ctx_t a = t->a;
  int i;
  int prev_offset, curr_offset;
  u32 ref_index, ref_lane;
  u64 input_block[1024/sizeof (u64)];
  u64 address_block[1024/sizeof (u64)];
  u64 *random_block = NULL;

  if (a->hash_type == GCRY_KDF_ARGON2I
      || (a->hash_type == GCRY_KDF_ARGON2ID && t->pass == 0 && t->slice < 2))
    {
      memset (input_block, 0, 1024);
      input_block[0] = t->pass;
      input_block[1] = t->lane;
      input_block[2] = t->slice;
      input_block[3] = a->memory_blocks;
      input_block[4] = a->passes;
      input_block[5] = a->hash_type;
      random_block = address_block;
    }

  if (t->pass == 0 && t->slice == 0)
    {
      if (random_block)
        pseudo_random_generate (random_block, input_block);
      i = 2;
    }
  else
    i = 0;

  curr_offset = t->lane * a->lane_length + t->slice * a->segment_length + i;
  if ((curr_offset % a->lane_length))
    prev_offset = curr_offset - 1;
  else
    prev_offset = curr_offset + a->lane_length - 1;

  for (; i < a->segment_length; i++, curr_offset++, prev_offset++)
    {
      u64 *ref_block, *curr_block;
      u64 rand64;

      if ((curr_offset % a->lane_length) == 1)
        prev_offset = curr_offset - 1;

      if (random_block)
        {
          if ((i % (1024/sizeof (u64))) == 0)
            pseudo_random_generate (random_block, input_block);

          rand64 = random_block[(i% (1024/sizeof (u64)))];
        }
      else
        rand64 = a->block[prev_offset*ARGON2_WORDS_IN_BLOCK];

      if (t->pass == 0 && t->slice == 0)
        ref_lane = t->lane;
      else
        ref_lane = (rand64 >> 32) % a->lanes;

      ref_index = index_alpha (a, t, i, (rand64 & 0xffffffff),
                               ref_lane == t->lane);
      ref_block =
        &a->block[(a->lane_length * ref_lane + ref_index)* ARGON2_WORDS_IN_BLOCK];

      curr_block = &a->block[curr_offset * ARGON2_WORDS_IN_BLOCK];
      fill_block (&a->block[prev_offset * ARGON2_WORDS_IN_BLOCK], ref_block,
                  curr_block, t->pass != 0);
    }
}


static gpg_err_code_t
argon2_compute (argon2_ctx_t a, const struct gcry_kdf_thread_ops *ops)
{
  gpg_err_code_t ec;
  unsigned int r;
  unsigned int s;
  unsigned int l;
  int ret;

  ec = argon2_fill_first_blocks (a);
  if (ec)
    return ec;

  for (r = 0; r < a->passes; r++)
    for (s = 0; s < 4; s++)
      {
        for (l = 0; l < a->lanes; l++)
          {
            struct argon2_thread_data *thread_data;

            /* launch a thread.  */
            thread_data = &a->thread_data[l];
            thread_data->a = a;
            thread_data->pass = r;
            thread_data->slice = s;
            thread_data->lane = l;

            if (ops)
	      {
		ret = ops->dispatch_job (ops->jobs_context,
					 argon2_compute_segment, thread_data);
		if (ret < 0)
		  return GPG_ERR_CANCELED;
	      }
            else
              argon2_compute_segment (thread_data);
          }

        if (ops)
	  {
	    ret = ops->wait_all_jobs (ops->jobs_context);
	    if (ret < 0)
	      return GPG_ERR_CANCELED;
	  }

        /* Rover: report unlock progress once per slice (passes * 4 in
	   total); the block filling above is Argon2's dominant cost.  */
        if (grub_cryptodisk_kdf_progress != 0)
          grub_cryptodisk_kdf_progress (r * 4 + s + 1, a->passes * 4,
                                        grub_cryptodisk_kdf_progress_data);
      }

  return 0;
}


static gpg_err_code_t
argon2_final (argon2_ctx_t a, size_t resultlen, void *result)
{
  int i;

  if (resultlen != a->outlen)
    return GPG_ERR_INV_VALUE;

  memset (a->block, 0, 1024);
  for (i = 0; i < a->lanes; i++)
    {
      u64 *last_block;

      last_block = &a->block[(a->lane_length * i + (a->lane_length - 1))
                             * ARGON2_WORDS_IN_BLOCK];
      xor_block (a->block, last_block);
    }

  beswap64_block (a->block);
  blake2b_vl_hash (a->block, 1024, a->outlen, result);
  return 0;
}

static void
argon2_close (argon2_ctx_t a)
{
  size_t n;

  n = offsetof (struct argon2_context, out) + a->outlen;

  if (a->block)
    {
      wipememory (a->block, 1024 * a->memory_blocks);
      xfree (a->block);
    }

  if (a->thread_data)
    xfree (a->thread_data);

  wipememory (a, n);
  xfree (a);
}

static gpg_err_code_t
argon2_open (gcry_kdf_hd_t *hd, int subalgo,
             const unsigned long *param, unsigned int paramlen,
             const void *password, size_t passwordlen,
             const void *salt, size_t saltlen,
             const void *key, size_t keylen,
             const void *ad, size_t adlen)
{
  int hash_type;
  unsigned int taglen;
  unsigned int t_cost;
  unsigned int m_cost;
  unsigned int parallelism = 1;
  argon2_ctx_t a;
  gpg_err_code_t ec;
  size_t n;

  if (subalgo != GCRY_KDF_ARGON2D
      && subalgo != GCRY_KDF_ARGON2I
      && subalgo != GCRY_KDF_ARGON2ID)
    return GPG_ERR_INV_VALUE;
  else
    hash_type = subalgo;

  /* param : [ tag_length, t_cost, m_cost, parallelism ] */
  if (paramlen < 3 || paramlen > 4)
    return GPG_ERR_INV_VALUE;
  else
    {
      taglen = (unsigned int)param[0];
      t_cost = (unsigned int)param[1];
      m_cost = (unsigned int)param[2];
      if (paramlen >= 4)
        parallelism = (unsigned int)param[3];
    }

  if (parallelism == 0)
    return GPG_ERR_INV_VALUE;

  if (U64_C(1024) * m_cost > SIZE_MAX)
    return GPG_ERR_INV_VALUE;

  n = offsetof (struct argon2_context, out) + taglen;
  a = xtrymalloc (n);
  if (!a)
    return GPG_ERR_OUT_OF_MEMORY;

  a->algo = GCRY_KDF_ARGON2;
  a->hash_type = hash_type;

  a->outlen = taglen;

  a->password = password;
  a->passwordlen = passwordlen;
  a->salt = salt;
  a->saltlen = saltlen;
  a->key = key;
  a->keylen = keylen;
  a->ad = ad;
  a->adlen = adlen;

  a->m_cost = m_cost;

  a->block = NULL;
  a->thread_data = NULL;

  ec = argon2_init (a, parallelism, m_cost, t_cost);
  if (ec)
    {
      xfree (a);
      return ec;
    }

  *hd = (void *)a;
  return 0;
}

struct gcry_kdf_handle {
  int algo;
  /* And algo specific parts come.  */
};

gpg_err_code_t
_gcry_kdf_open (gcry_kdf_hd_t *hd, int algo, int subalgo,
                const unsigned long *param, unsigned int paramlen,
                const void *input, size_t inputlen,
                const void *salt, size_t saltlen,
                const void *key, size_t keylen,
                const void *ad, size_t adlen)
{
  gpg_err_code_t ec;

  switch (algo)
    {
    case GCRY_KDF_ARGON2:
      if (!saltlen)
        ec = GPG_ERR_INV_VALUE;
      else
        ec = argon2_open (hd, subalgo, param, paramlen,
                          input, inputlen, salt, saltlen,
                          key, keylen, ad, adlen);
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

  return ec;
}

gpg_err_code_t
_gcry_kdf_compute (gcry_kdf_hd_t h, const struct gcry_kdf_thread_ops *ops)
{
  gpg_err_code_t ec;

  switch (h->algo)
    {
    case GCRY_KDF_ARGON2:
      ec = argon2_compute ((argon2_ctx_t)(void *)h, ops);
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

  return ec;
}


gpg_err_code_t
_gcry_kdf_final (gcry_kdf_hd_t h, size_t resultlen, void *result)
{
  gpg_err_code_t ec;

  switch (h->algo)
    {
    case GCRY_KDF_ARGON2:
      ec = argon2_final ((argon2_ctx_t)(void *)h, resultlen, result);
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

  return ec;
}

void
_gcry_kdf_close (gcry_kdf_hd_t h)
{
  switch (h->algo)
    {
    case GCRY_KDF_ARGON2:
      argon2_close ((argon2_ctx_t)(void *)h);
      break;

    default:
      break;
    }
}
