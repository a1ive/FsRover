/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2026  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Read-only BitLocker (FVE) cryptodisk backend.
 *
 * Ported from dislocker (https://github.com/Aorimn/dislocker); the on-disk
 * format, the VMK/FVEK unwrapping and the sector layout follow its analysis.
 * Only the pieces needed to *read* a volume are implemented: the volume is
 * unlocked with either a user password or a 48-digit recovery password, the
 * VMK is decrypted (AES-CCM) with the stretched key, the FVEK is decrypted
 * with the VMK, and sectors are decrypted with AES-XTS, AES-CBC, or AES-CBC
 * plus the Elephant diffuser.
 *
 * Because BitLocker relocates the first NTFS sectors, presents its in-place
 * metadata as zeroes, and uses a non-generic bulk cipher, this backend takes
 * over the whole read path via grub_cryptodisk's ->read_sectors hook rather
 * than going through grub_cryptodisk_endecrypt().
 */

#include <grub/cryptodisk.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/disk.h>
#include <grub/crypto.h>
#include <grub/charset.h>
#include <grub/partition.h>
#include <grub/procfs.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv2+");

/* BitLocker volume signatures, at offset 3 of the first sector.  */
#define BL_SIGNATURE       "-FVE-FS-"
#define BL_TOGO_SIGNATURE  "MSWIN4.1"
#define BL_SIGNATURE_LEN   8

/* Metadata (information) header signature.  */
#define BL_INFO_SIGNATURE  "-FVE-FS-"

/* BitLocker version stored in the information header.  */
#define BL_VERSION_VISTA   1
#define BL_VERSION_SEVEN   2

/* Metadata encryption state.  */
#define BL_STATE_SWITCHING_ENCRYPTION  2

/* Datum entry types (2nd header field).  */
#define BL_ET_VMK    2
#define BL_ET_FVEK   3
#define BL_ET_ANY    0xffff

/* Datum value types (3rd header field).  */
#define BL_VT_KEY             1
#define BL_VT_STRETCH_KEY     3
#define BL_VT_AES_CCM         5
#define BL_VT_VMK             8
#define BL_VT_VIRTUALIZATION  15
#define BL_VT_MAX             20

/* FVEK / disk cipher identifiers.  */
#define BL_AES_128_DIFFUSER     0x8000
#define BL_AES_256_DIFFUSER     0x8001
#define BL_AES_128_NO_DIFFUSER  0x8002
#define BL_AES_256_NO_DIFFUSER  0x8003
#define BL_AES_XTS_128          0x8004
#define BL_AES_XTS_256          0x8005

/* Bulk cipher families used by this backend.  */
enum
{
  BL_MODE_CBC = 0,
  BL_MODE_CBC_DIFFUSER,
  BL_MODE_XTS
};

/* AES-CCM authenticator (MAC) length used throughout BitLocker.  */
#define BL_CCM_MAC_LEN    16
#define BL_CCM_NONCE_LEN  12

/*
 * The size (in bytes) of the fixed part of each datum, indexed by value type.
 * Datum payloads (and nested datums) begin after this many bytes.  Mirrors
 * dislocker's datum_value_types_prop[].size_header.
 */
static const grub_uint16_t bl_datum_header_size[BL_VT_MAX] =
{
  8, 0xc, 8, 0x1c, 0xc, 0x24, 0xc, 8, 0x24, 0x20,
  0x2c, 0x34, 8, 8, 8, 0x18, 0xc, 0xc, 0x1c, 0xc
};

struct grub_bitlocker
{
  /* AES contexts derived from the FVEK.  */
  grub_crypto_cipher_handle_t data;   /* FVEK data key (encrypt + decrypt).  */
  grub_crypto_cipher_handle_t tweak;  /* Second key: XTS tweak / diffuser.  */
  int mode;

  grub_uint32_t sector_size;
  int log_sector_size;

  /* All byte offsets/sizes below are relative to the volume (partition).  */
  grub_uint64_t encrypted_volume_size;
  grub_uint64_t backup_sectors_addr;
  grub_uint32_t nb_backup_sectors;
  grub_uint16_t dataset_algo;

  /* The credential the volume was unlocked with (password or recovery
     password), copied verbatim for the (proc)/fve_keys dump.  */
  grub_uint8_t *saved_key;
  grub_size_t saved_key_len;

  /* The validated on-disk FVE metadata block and its datum region.  */
  grub_uint8_t *metadata;
  grub_size_t meta_len;
  const grub_uint8_t *datums_start;
  const grub_uint8_t *datums_end;

  /* Regions presented to the reader as zeroes (in-place metadata).  */
  grub_size_t nb_regions;
  struct
  {
    grub_uint64_t addr;
    grub_uint64_t size;
  } region[5];
};

/* Little-endian field readers (metadata is stored little-endian).  */
static grub_uint16_t
bl_le16 (const void *p)
{
  return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
bl_le32 (const void *p)
{
  return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
bl_le64 (const void *p)
{
  return grub_le_to_cpu64 (grub_get_unaligned64 (p));
}

static grub_err_t
bl_read_raw (grub_disk_t disk, grub_uint64_t byte_off, grub_size_t len, void *dst)
{
  return grub_disk_read (disk, byte_off >> GRUB_DISK_SECTOR_BITS,
			 byte_off & (GRUB_DISK_SECTOR_SIZE - 1), len, dst);
}

static grub_crypto_cipher_handle_t
bl_aes_open (const grub_uint8_t *key, grub_size_t keylen)
{
  grub_crypto_cipher_handle_t c = grub_crypto_cipher_open (GRUB_CIPHER_AES);

  if (c == NULL)
    return NULL;
  if (grub_crypto_cipher_set_key (c, key, keylen) != GPG_ERR_NO_ERROR)
    {
      grub_crypto_cipher_close (c);
      return NULL;
    }
  return c;
}

/* Rotate a 32-bit word left, tolerating a zero (and thus safe) shift count.  */
static grub_uint32_t
bl_rotl32 (grub_uint32_t a, unsigned int n)
{
  n &= 31;
  return n ? ((a << n) | (a >> (32 - n))) : a;
}

/* Multiply by the primitive element in GF(2^128), little-endian (x^128 = ... + 1).  */
static void
bl_gf_mul_x (grub_uint8_t *a)
{
  int i;
  grub_uint8_t carry = 0;

  for (i = 0; i < 16; i++)
    {
      grub_uint8_t next = (grub_uint8_t) (a[i] >> 7);
      a[i] = (grub_uint8_t) ((a[i] << 1) | carry);
      carry = next;
    }
  if (carry)
    a[0] ^= 0x87;
}

/*
 * Elephant diffuser (decryption direction), as described by Niels Ferguson.
 * Both stages operate in place on the sector as an array of little-endian
 * 32-bit words.
 */
static void
bl_diffuser_a_decrypt (grub_uint8_t *sector, grub_uint32_t sector_size)
{
  grub_uint32_t *d = (grub_uint32_t *) sector;
  static const unsigned int ra[4] = { 9, 0, 13, 0 };
  int int_size = (int) (sector_size / 4);
  int cycles, i;

  for (cycles = 0; cycles < 5; cycles++)
    for (i = 0; i < int_size; i++)
      d[i] = d[i] + (d[(i - 2 + int_size) % int_size]
		     ^ bl_rotl32 (d[(i - 5 + int_size) % int_size], ra[i % 4]));
}

static void
bl_diffuser_b_decrypt (grub_uint8_t *sector, grub_uint32_t sector_size)
{
  grub_uint32_t *d = (grub_uint32_t *) sector;
  static const unsigned int rb[4] = { 0, 10, 0, 25 };
  int int_size = (int) (sector_size / 4);
  int cycles, i;

  for (cycles = 0; cycles < 3; cycles++)
    for (i = 0; i < int_size; i++)
      d[i] = d[i] + (d[(i + 2) % int_size]
		     ^ bl_rotl32 (d[(i + 5) % int_size], rb[i % 4]));
}

/* AES-XTS sector decryption (in != out).  */
static void
bl_xts_decrypt (struct grub_bitlocker *ctx, grub_uint8_t *out,
		const grub_uint8_t *in, grub_uint64_t sector_number)
{
  grub_uint8_t tweak[16], t[16];
  grub_uint64_t s = sector_number;
  grub_uint32_t i;
  int k;

  grub_memset (tweak, 0, sizeof (tweak));
  for (k = 0; k < 8; k++)
    {
      tweak[k] = (grub_uint8_t) (s & 0xff);
      s >>= 8;
    }
  grub_crypto_ecb_encrypt (ctx->tweak, tweak, tweak, 16);

  for (i = 0; i < ctx->sector_size; i += 16)
    {
      for (k = 0; k < 16; k++)
	t[k] = (grub_uint8_t) (in[i + k] ^ tweak[k]);
      grub_crypto_ecb_decrypt (ctx->data, out + i, t, 16);
      for (k = 0; k < 16; k++)
	out[i + k] ^= tweak[k];
      bl_gf_mul_x (tweak);
    }
}

/* AES-CBC sector decryption, optionally with the Elephant diffuser (in != out).  */
static void
bl_cbc_decrypt (struct grub_bitlocker *ctx, grub_uint8_t *out,
		const grub_uint8_t *in, grub_uint64_t byte_off, int diffuser)
{
  grub_uint8_t iv[16];
  grub_uint8_t sector_key[32];
  grub_uint64_t s = byte_off;
  grub_uint32_t i;
  int k;

  grub_memset (iv, 0, sizeof (iv));
  for (k = 0; k < 8; k++)
    {
      iv[k] = (grub_uint8_t) (s & 0xff);
      s >>= 8;
    }

  if (diffuser)
    {
      grub_uint8_t sk_iv[16];

      grub_memcpy (sk_iv, iv, sizeof (sk_iv));
      grub_crypto_ecb_encrypt (ctx->tweak, sector_key, sk_iv, 16);
      sk_iv[15] = 0x80;
      grub_crypto_ecb_encrypt (ctx->tweak, sector_key + 16, sk_iv, 16);
    }

  /* CBC IV = E_fvek(byte offset).  */
  grub_crypto_ecb_encrypt (ctx->data, iv, iv, 16);
  grub_crypto_cbc_decrypt (ctx->data, out, in, ctx->sector_size, iv);

  if (diffuser)
    {
      bl_diffuser_b_decrypt (out, ctx->sector_size);
      bl_diffuser_a_decrypt (out, ctx->sector_size);
      for (i = 0; i < ctx->sector_size; i++)
	out[i] ^= sector_key[i % 32];
    }
}

static void
bl_decrypt_sector (struct grub_bitlocker *ctx, grub_uint8_t *out,
		   const grub_uint8_t *in, grub_uint64_t byte_off)
{
  switch (ctx->mode)
    {
    case BL_MODE_XTS:
      bl_xts_decrypt (ctx, out, in, byte_off / ctx->sector_size);
      break;
    case BL_MODE_CBC_DIFFUSER:
      bl_cbc_decrypt (ctx, out, in, byte_off, 1);
      break;
    default:
      bl_cbc_decrypt (ctx, out, in, byte_off, 0);
      break;
    }
}

/*
 * AES-CCM key unwrap (VMK and FVEK).  Decrypts INPUT with KEY, verifies the
 * stored MAC and, on success, returns the plaintext in *OUTPUT (caller frees).
 * Returns 1 on a matching MAC, 0 otherwise.
 */
static void
bl_ctr_inc (grub_uint8_t *iv)
{
  int p;

  for (p = 15; p >= 0; p--)
    {
      iv[p]++;
      if (iv[p] != 0)
	break;
    }
}

static int
bl_decrypt_key (const grub_uint8_t *input, grub_size_t input_size,
		const grub_uint8_t *mac, const grub_uint8_t *nonce,
		const grub_uint8_t *key, grub_size_t keylen,
		grub_uint8_t **output)
{
  grub_crypto_cipher_handle_t c;
  grub_uint8_t iv[16], block[16], mac_dec[16], mac_calc[16];
  grub_uint8_t *out;
  grub_size_t pos;
  grub_uint32_t sz;
  int i, loop;

  *output = NULL;

  c = bl_aes_open (key, keylen);
  if (c == NULL)
    return 0;

  out = grub_malloc (input_size);
  if (out == NULL)
    {
      grub_crypto_cipher_close (c);
      return 0;
    }

  /* CTR keystream: counter block S0 authenticates the MAC, S1.. the data.  */
  grub_memset (iv, 0, sizeof (iv));
  grub_memcpy (iv + 1, nonce, BL_CCM_NONCE_LEN);
  iv[0] = 15 - BL_CCM_NONCE_LEN - 1;

  grub_crypto_ecb_encrypt (c, block, iv, 16);
  for (i = 0; i < BL_CCM_MAC_LEN; i++)
    mac_dec[i] = (grub_uint8_t) (mac[i] ^ block[i]);

  iv[15] = 1;
  for (pos = 0; pos + 16 <= input_size; pos += 16)
    {
      grub_crypto_ecb_encrypt (c, block, iv, 16);
      for (i = 0; i < 16; i++)
	out[pos + i] = (grub_uint8_t) (input[pos + i] ^ block[i]);
      bl_ctr_inc (iv);
    }
  if (pos < input_size)
    {
      grub_crypto_ecb_encrypt (c, block, iv, 16);
      for (i = 0; pos + (grub_size_t) i < input_size; i++)
	out[pos + i] = (grub_uint8_t) (input[pos + i] ^ block[i]);
    }

  /* CBC-MAC over the recovered plaintext, starting from block B0.  */
  grub_memset (iv, 0, sizeof (iv));
  iv[0] = (grub_uint8_t) ((0xe - BL_CCM_NONCE_LEN)
			  | (((BL_CCM_MAC_LEN - 2) & 0xfe) << 2));
  grub_memcpy (iv + 1, nonce, BL_CCM_NONCE_LEN);
  sz = (grub_uint32_t) input_size;
  for (loop = 15; loop > BL_CCM_NONCE_LEN; loop--)
    {
      iv[loop] = (grub_uint8_t) (sz & 0xff);
      sz >>= 8;
    }
  grub_crypto_ecb_encrypt (c, iv, iv, 16);

  for (pos = 0; pos + 16 <= input_size; pos += 16)
    {
      for (i = 0; i < 16; i++)
	iv[i] ^= out[pos + i];
      grub_crypto_ecb_encrypt (c, iv, iv, 16);
    }
  if (pos < input_size)
    {
      for (i = 0; pos + (grub_size_t) i < input_size; i++)
	iv[i] ^= out[pos + i];
      grub_crypto_ecb_encrypt (c, iv, iv, 16);
    }
  grub_memcpy (mac_calc, iv, BL_CCM_MAC_LEN);

  grub_crypto_cipher_close (c);

  if (grub_memcmp (mac_calc, mac_dec, BL_CCM_MAC_LEN) != 0)
    {
      grub_free (out);
      return 0;
    }

  *output = out;
  return 1;
}

/* -- Key stretching / password derivation ------------------------------- */

PRAGMA_BEGIN_PACKED
struct bl_chain_hash
{
  grub_uint8_t updated_hash[32];
  grub_uint8_t password_hash[32];
  grub_uint8_t salt[16];
  grub_uint64_t hash_count;
} GRUB_PACKED;
PRAGMA_END_PACKED

/*
 * The BitLocker "stretch" chain hash: SHA-256 the 88-byte structure 2^20
 * times, feeding the previous digest and an incrementing counter back in.
 * (Windows stores hash_count little-endian; the host is always little-endian
 * here, so a native increment produces the right bytes.)
 */
static void
bl_stretch (const grub_uint8_t *pw_hash, const grub_uint8_t *salt,
	    grub_uint8_t *out)
{
  struct bl_chain_hash ch;
  grub_uint64_t i;

  grub_memset (&ch, 0, sizeof (ch));
  grub_memcpy (ch.password_hash, pw_hash, 32);
  grub_memcpy (ch.salt, salt, 16);

  for (i = 0; i < 0x100000; i++)
    {
      grub_crypto_hash (GRUB_MD_SHA256, ch.updated_hash, &ch, sizeof (ch));
      ch.hash_count++;
    }

  grub_memcpy (out, ch.updated_hash, 32);
  grub_memset (&ch, 0, sizeof (ch));
}

/* Derive the 32-byte intermediate key from a user password + salt.  */
static int
bl_user_key (const grub_uint8_t *password, grub_size_t pwlen,
	     const grub_uint8_t *salt, grub_uint8_t *out)
{
  grub_uint16_t *utf16;
  grub_size_t units;
  grub_uint8_t h[32];

  utf16 = grub_malloc ((pwlen + 1) * sizeof (grub_uint16_t));
  if (utf16 == NULL)
    return 0;

  units = grub_utf8_to_utf16 (utf16, pwlen + 1, password, pwlen, NULL);

  /* SHA-256(SHA-256(UTF-16LE(password))) over the string without the NUL.  */
  grub_crypto_hash (GRUB_MD_SHA256, h, utf16, units * 2);
  grub_crypto_hash (GRUB_MD_SHA256, h, h, 32);
  bl_stretch (h, salt, out);

  grub_memset (utf16, 0, (pwlen + 1) * sizeof (grub_uint16_t));
  grub_free (utf16);
  return 1;
}

/*
 * Parse and validate a 48-digit recovery password of the canonical form
 * "dddddd-dddddd-dddddd-dddddd-dddddd-dddddd-dddddd-dddddd" into 8 blocks,
 * each block/11.  Returns 1 if the string is a valid recovery password.
 */
static int
bl_parse_recovery (const grub_uint8_t *rp, grub_size_t len, grub_uint16_t *out)
{
  int b, d;

  if (len != 55)
    return 0;

  for (b = 0; b < 8; b++)
    {
      const grub_uint8_t *blk = rp + b * 7;
      long v = 0;
      int chk;

      for (d = 0; d < 6; d++)
	{
	  if (blk[d] < '0' || blk[d] > '9')
	    return 0;
	  v = v * 10 + (blk[d] - '0');
	}
      if (b < 7 && blk[6] != '-')
	return 0;
      if ((v % 11) != 0 || v >= 720896)
	return 0;

      chk = ((blk[0] - '0') - (blk[1] - '0') + (blk[2] - '0')
	     - (blk[3] - '0') + (blk[4] - '0')) % 11;
      while (chk < 0)
	chk += 11;
      if (chk != (blk[5] - '0'))
	return 0;

      out[b] = (grub_uint16_t) (v / 11);
    }
  return 1;
}

/* Derive the 32-byte intermediate key from parsed recovery blocks + salt.  */
static void
bl_recovery_key (const grub_uint16_t *blocks, const grub_uint8_t *salt,
		 grub_uint8_t *out)
{
  grub_uint8_t distilled[16];
  grub_uint8_t pw_hash[32];
  int i;

  for (i = 0; i < 8; i++)
    {
      distilled[2 * i] = (grub_uint8_t) (blocks[i] & 0xff);
      distilled[2 * i + 1] = (grub_uint8_t) ((blocks[i] >> 8) & 0xff);
    }

  grub_crypto_hash (GRUB_MD_SHA256, pw_hash, distilled, sizeof (distilled));
  bl_stretch (pw_hash, salt, out);
  grub_memset (distilled, 0, sizeof (distilled));
}

/* -- Datum navigation --------------------------------------------------- */

/*
 * Iterate top-level datums, returning the next one after PREV (or the first
 * if PREV is NULL) that matches ENTRY/VALUE (BL_ET_ANY / 0xffff = wildcard).
 */
static int
bl_iter_datum (struct grub_bitlocker *ctx, grub_uint16_t entry,
	       grub_uint16_t value, const grub_uint8_t *prev,
	       const grub_uint8_t **out)
{
  const grub_uint8_t *p, *end = ctx->datums_end;

  if (prev != NULL)
    p = prev + bl_le16 (prev);
  else
    p = ctx->datums_start;

  while (p + 8 <= end)
    {
      grub_uint16_t dsize = bl_le16 (p);
      grub_uint16_t et = bl_le16 (p + 2);
      grub_uint16_t vt = bl_le16 (p + 4);

      if (dsize < 8 || p + dsize > end)
	break;
      if ((entry == BL_ET_ANY || entry == et)
	  && (value == 0xffff || value == vt))
	{
	  *out = p;
	  return 1;
	}
      p += dsize;
    }
  return 0;
}

/*
 * Find the nested datum of a given value type inside DATUM.  DATUM has already
 * been bounds-checked against the metadata buffer by bl_iter_datum().
 */
static int
bl_get_nested (const grub_uint8_t *datum, grub_uint16_t value_type,
	       const grub_uint8_t **out)
{
  grub_uint16_t dsize = bl_le16 (datum);
  grub_uint16_t vtype = bl_le16 (datum + 4);
  const grub_uint8_t *end = datum + dsize;
  const grub_uint8_t *p;

  if (vtype >= BL_VT_MAX)
    return 0;
  p = datum + bl_datum_header_size[vtype];

  while (p + 8 <= end)
    {
      grub_uint16_t nsize = bl_le16 (p);
      grub_uint16_t nvtype = bl_le16 (p + 4);

      if (nsize < 8 || p + nsize > end)
	break;
      if (nvtype == value_type)
	{
	  *out = p;
	  return 1;
	}
      p += nsize;
    }
  return 0;
}

/* Return the next VMK datum whose nonce priority range is within [mn, mx].  */
static int
bl_next_vmk_in_range (struct grub_bitlocker *ctx, grub_uint16_t mn,
		      grub_uint16_t mx, const grub_uint8_t *prev,
		      const grub_uint8_t **out)
{
  const grub_uint8_t *d = prev;

  while (bl_iter_datum (ctx, BL_ET_VMK, BL_VT_VMK, d, &d))
    {
      grub_uint16_t r = bl_le16 (d + 0x22);   /* nonce[10..11] */

      if (mn <= r && r <= mx)
	{
	  *out = d;
	  return 1;
	}
    }
  return 0;
}

/*
 * Decrypt an AES-CCM datum (VMK or FVEK) with KEY.  The datum layout is
 * header(8) | nonce(12) | mac(16) | payload.  On success *OUT holds the
 * decrypted plaintext datum (caller frees) and *OUTLEN its length.
 */
static int
bl_ccm_datum_decrypt (const grub_uint8_t *ccm, const grub_uint8_t *key,
		      grub_size_t keylen, grub_uint8_t **out,
		      grub_size_t *outlen)
{
  grub_uint16_t dsize = bl_le16 (ccm);
  grub_size_t input_size;

  if (dsize <= 0x24)
    return 0;
  input_size = (grub_size_t) dsize - 0x24;

  if (!bl_decrypt_key (ccm + 0x24, input_size, ccm + 0x14, ccm + 8,
		       key, keylen, out))
    return 0;

  *outlen = input_size;
  return 1;
}

/* -- FVEK key schedule -------------------------------------------------- */

/* Configure the disk cipher from the decrypted FVEK bytes.  */
static int
bl_init_keys (struct grub_bitlocker *ctx, grub_uint16_t algo,
	      const grub_uint8_t *key, grub_size_t keylen)
{
  grub_crypto_cipher_handle_t data = NULL, tweak = NULL;
  int mode;

  switch (algo)
    {
    case BL_AES_128_NO_DIFFUSER:
      if (keylen < 16)
	return 0;
      data = bl_aes_open (key, 16);
      mode = BL_MODE_CBC;
      break;
    case BL_AES_256_NO_DIFFUSER:
      if (keylen < 32)
	return 0;
      data = bl_aes_open (key, 32);
      mode = BL_MODE_CBC;
      break;
    case BL_AES_128_DIFFUSER:
      if (keylen < 0x30)
	return 0;
      data = bl_aes_open (key, 16);
      tweak = bl_aes_open (key + 0x20, 16);
      mode = BL_MODE_CBC_DIFFUSER;
      break;
    case BL_AES_256_DIFFUSER:
      if (keylen < 0x40)
	return 0;
      data = bl_aes_open (key, 32);
      tweak = bl_aes_open (key + 0x20, 32);
      mode = BL_MODE_CBC_DIFFUSER;
      break;
    case BL_AES_XTS_128:
      if (keylen < 0x20)
	return 0;
      data = bl_aes_open (key, 16);
      tweak = bl_aes_open (key + 0x10, 16);
      mode = BL_MODE_XTS;
      break;
    case BL_AES_XTS_256:
      if (keylen < 0x40)
	return 0;
      data = bl_aes_open (key, 32);
      tweak = bl_aes_open (key + 0x20, 32);
      mode = BL_MODE_XTS;
      break;
    default:
      return 0;
    }

  if (data == NULL
      || (mode != BL_MODE_CBC && tweak == NULL))
    {
      grub_crypto_cipher_close (data);
      grub_crypto_cipher_close (tweak);
      return 0;
    }

  grub_crypto_cipher_close (ctx->data);
  grub_crypto_cipher_close (ctx->tweak);
  ctx->data = data;
  ctx->tweak = tweak;
  ctx->mode = mode;
  return 1;
}

/* -- Read path ---------------------------------------------------------- */

static int
bl_is_overwritten (struct grub_bitlocker *ctx, grub_uint64_t off,
		   grub_uint32_t size)
{
  grub_size_t k;

  for (k = 0; k < ctx->nb_regions; k++)
    {
      grub_uint64_t a = ctx->region[k].addr;
      grub_uint64_t s = ctx->region[k].size;

      if (s == 0)
	continue;
      if (off >= a && off < a + s)
	return 1;
      if (off < a && off + size > a)
	return 1;
    }
  return 0;
}

static grub_err_t
bl_read (grub_cryptodisk_t dev, grub_disk_addr_t sector, grub_size_t size,
	 char *buf)
{
  struct grub_bitlocker *ctx = dev->dev_data;
  grub_uint32_t ss = ctx->sector_size;
  grub_uint8_t *tmp;
  grub_size_t i;
  grub_err_t err = GRUB_ERR_NONE;

  tmp = grub_malloc (ss);
  if (tmp == NULL)
    return grub_errno;

  for (i = 0; i < size; i++)
    {
      grub_disk_addr_t psec = sector + i;
      grub_uint64_t off = (grub_uint64_t) psec << ctx->log_sector_size;
      grub_uint8_t *out = (grub_uint8_t *) buf + i * ss;

      if (bl_is_overwritten (ctx, off, ss))
	{
	  grub_memset (out, 0, ss);
	  continue;
	}

      if (psec < ctx->nb_backup_sectors)
	{
	  /* The first NTFS sectors live encrypted at the backup location.  */
	  grub_uint64_t to = off + ctx->backup_sectors_addr;

	  err = bl_read_raw (dev->source_disk, to, ss, tmp);
	  if (err)
	    break;
	  if (to >= ctx->encrypted_volume_size)
	    grub_memcpy (out, tmp, ss);
	  else
	    bl_decrypt_sector (ctx, out, tmp, to);
	}
      else if (off >= ctx->encrypted_volume_size)
	{
	  /* Past the encrypted area (conversion in progress): plaintext.  */
	  err = bl_read_raw (dev->source_disk, off, ss, out);
	  if (err)
	    break;
	}
      else
	{
	  err = bl_read_raw (dev->source_disk, off, ss, tmp);
	  if (err)
	    break;
	  bl_decrypt_sector (ctx, out, tmp, off);
	}
    }

  grub_free (tmp);
  return err;
}

static void
bl_close (grub_cryptodisk_t dev)
{
  struct grub_bitlocker *ctx = dev->dev_data;

  if (ctx == NULL)
    return;
  grub_crypto_cipher_close (ctx->data);
  grub_crypto_cipher_close (ctx->tweak);
  if (ctx->saved_key != NULL)
    {
      grub_memset (ctx->saved_key, 0, ctx->saved_key_len);
      grub_free (ctx->saved_key);
    }
  grub_free (ctx->metadata);
  grub_free (ctx);
  dev->dev_data = NULL;
}

/* -- Metadata loading / scan -------------------------------------------- */

/*
 * Read and lightly validate one FVE metadata copy at REGION_ADDR.  On success
 * *OUT holds the freshly allocated metadata block and *OUT_LEN its length.
 */
static grub_err_t
bl_load_metadata (grub_disk_t disk, grub_uint64_t region_addr,
		  grub_uint8_t **out, grub_size_t *out_len)
{
  grub_uint8_t hdr[0x70];
  grub_err_t err;
  grub_uint16_t version;
  grub_uint32_t size, ds_size, ds_hdr, ds_copy;
  grub_uint8_t *buf;

  err = bl_read_raw (disk, region_addr, sizeof (hdr), hdr);
  if (err)
    return err;

  if (grub_memcmp (hdr, BL_INFO_SIGNATURE, 8) != 0)
    return grub_error (GRUB_ERR_BAD_FS, "bad BitLocker metadata signature");

  version = bl_le16 (hdr + 0xa);
  if (version != BL_VERSION_SEVEN)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "unsupported BitLocker metadata version %u",
		       (unsigned) version);

  size = (grub_uint32_t) bl_le16 (hdr + 8) << 4;
  if (size <= 0x70 || size > (1U << 20))
    return grub_error (GRUB_ERR_BAD_FS, "bad BitLocker metadata size");

  buf = grub_malloc (size);
  if (buf == NULL)
    return grub_errno;

  err = bl_read_raw (disk, region_addr, size, buf);
  if (err)
    {
      grub_free (buf);
      return err;
    }

  /* Sanity-check the embedded dataset (at offset 0x40).  */
  ds_size = bl_le32 (buf + 0x40);
  ds_hdr = bl_le32 (buf + 0x48);
  ds_copy = bl_le32 (buf + 0x4c);
  if (ds_copy < ds_hdr || ds_size > ds_copy || (ds_copy - ds_hdr) < 8
      || ds_hdr < 0x30 || (grub_size_t) 0x40 + ds_size > size)
    {
      grub_free (buf);
      return grub_error (GRUB_ERR_BAD_FS, "bad BitLocker dataset");
    }

  *out = buf;
  *out_len = size;
  return GRUB_ERR_NONE;
}

static void
bl_format_guid (const grub_uint8_t *g, char *out)
{
  /* Microsoft GUID string: first three groups little-endian.  */
  static const char order[] = { 3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1,
				8, 9, -1, 10, 11, 12, 13, 14, 15 };
  const char *hex = "0123456789abcdef";
  grub_size_t i;
  char *p = out;

  for (i = 0; i < sizeof (order); i++)
    {
      if (order[i] < 0)
	{
	  *p++ = '-';
	  continue;
	}
      *p++ = hex[g[(int) order[i]] >> 4];
      *p++ = hex[g[(int) order[i]] & 0xf];
    }
  *p = '\0';
}

static grub_cryptodisk_t
bl_scan (grub_disk_t disk, grub_cryptomount_args_t cargs)
{
  grub_uint8_t vbr[512];
  grub_err_t err;
  int is_togo;
  grub_uint32_t sector_size;
  int log_ss;
  const grub_uint8_t *guid_ptr;
  grub_uint64_t info_off[3];
  grub_uint8_t *meta = NULL;
  grub_size_t meta_len = 0;
  struct grub_bitlocker *ctx;
  grub_cryptodisk_t newdev;
  grub_uint16_t curr_state;
  grub_uint32_t metafiles_size;
  const grub_uint8_t *virt;
  char uuid[40];
  unsigned int off_base, guid_base;
  int i;

  if (cargs->check_boot)
    return NULL;

  err = grub_disk_read (disk, 0, 0, sizeof (vbr), vbr);
  if (err)
    {
      if (err == GRUB_ERR_OUT_OF_RANGE)
	grub_errno = GRUB_ERR_NONE;
      return NULL;
    }

  if (grub_memcmp (vbr + 3, BL_SIGNATURE, BL_SIGNATURE_LEN) == 0)
    is_togo = 0;
  else if (grub_memcmp (vbr + 3, BL_TOGO_SIGNATURE, BL_SIGNATURE_LEN) == 0)
    is_togo = 1;
  else
    return NULL;   /* Not a BitLocker volume.  */

  sector_size = bl_le16 (vbr + 0xb);
  if (sector_size == 0)
    sector_size = 512;
  if ((sector_size & (sector_size - 1)) != 0
      || sector_size < 512 || sector_size > 4096)
    {
      grub_error (GRUB_ERR_BAD_FS, "unsupported BitLocker sector size %u",
		  (unsigned) sector_size);
      return NULL;
    }

  log_ss = 0;
  {
    grub_uint32_t s = sector_size;
    while (s > 1)
      {
	s >>= 1;
	log_ss++;
      }
  }

  /* Vista laid its metadata out differently (metadata_lcn != 0); unsupported.  */
  if (!is_togo && bl_le64 (vbr + 0x38) != 0)
    {
      grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		  "BitLocker Vista volumes are not supported");
      return NULL;
    }

  if (is_togo)
    {
      guid_base = 0x1a8;
      off_base = 0x1b8;
    }
  else
    {
      guid_base = 0xa0;
      off_base = 0xb0;
    }
  guid_ptr = vbr + guid_base;
  for (i = 0; i < 3; i++)
    info_off[i] = bl_le64 (vbr + off_base + i * 8);

  /* Load the first metadata copy that validates.  */
  for (i = 0; i < 3; i++)
    {
      if (info_off[i] == 0)
	continue;
      err = bl_load_metadata (disk, info_off[i], &meta, &meta_len);
      if (err == GRUB_ERR_NONE)
	break;
      grub_errno = GRUB_ERR_NONE;
      meta = NULL;
    }
  if (meta == NULL)
    {
      grub_error (GRUB_ERR_BAD_FS, "no valid BitLocker metadata found");
      return NULL;
    }

  if (cargs->search_uuid != NULL)
    {
      bl_format_guid (guid_ptr, uuid);
      if (grub_uuidcasecmp (cargs->search_uuid, uuid, sizeof (uuid)) != 0)
	{
	  grub_free (meta);
	  return NULL;
	}
    }

  ctx = grub_zalloc (sizeof (*ctx));
  newdev = grub_zalloc (sizeof (*newdev));
  if (ctx == NULL || newdev == NULL)
    {
      grub_free (ctx);
      grub_free (newdev);
      grub_free (meta);
      return NULL;
    }

  ctx->metadata = meta;
  ctx->meta_len = meta_len;
  ctx->sector_size = sector_size;
  ctx->log_sector_size = log_ss;
  ctx->encrypted_volume_size = bl_le64 (meta + 0x10);
  ctx->backup_sectors_addr = bl_le64 (meta + 0x38);
  ctx->nb_backup_sectors = bl_le32 (meta + 0x1c);
  ctx->dataset_algo = bl_le16 (meta + 0x64);
  curr_state = bl_le16 (meta + 0xc);

  ctx->datums_start = meta + 0x40 + bl_le32 (meta + 0x48);
  ctx->datums_end = meta + 0x40 + bl_le32 (meta + 0x40);
  if (ctx->datums_end > meta + meta_len)
    ctx->datums_end = meta + meta_len;

  if (ctx->encrypted_volume_size == 0
      || ctx->datums_start >= ctx->datums_end)
    {
      grub_free (ctx);
      grub_free (newdev);
      grub_free (meta);
      grub_error (GRUB_ERR_BAD_FS, "empty or malformed BitLocker volume");
      return NULL;
    }

  /* Regions reported to the reader as zeroes.  */
  metafiles_size = (~(sector_size - 1)) & (sector_size + 0xffff);
  for (i = 0; i < 3; i++)
    {
      ctx->region[i].addr = info_off[i];
      ctx->region[i].size = metafiles_size;
    }
  ctx->nb_regions = 3;

  if (bl_iter_datum (ctx, BL_ET_ANY, BL_VT_VIRTUALIZATION, NULL, &virt)
      && bl_le16 (virt) >= 0x18)
    {
      ctx->region[3].addr = ctx->backup_sectors_addr;
      ctx->region[3].size = bl_le64 (virt + 0x10);
      ctx->nb_regions = 4;
    }
  if (curr_state == BL_STATE_SWITCHING_ENCRYPTION)
    {
      ctx->region[ctx->nb_regions].addr = ctx->encrypted_volume_size;
      ctx->region[ctx->nb_regions].size = bl_le32 (meta + 0x18);
      ctx->nb_regions++;
    }

  newdev->modname = "bitlocker";
  newdev->offset_sectors = 0;
  newdev->log_sector_size = log_ss;
  newdev->total_sectors = ctx->encrypted_volume_size >> log_ss;
  newdev->source_disk = NULL;
  newdev->dev_data = ctx;
  newdev->read_sectors = bl_read;
  newdev->dev_close = bl_close;
  bl_format_guid (guid_ptr, newdev->uuid);

  return newdev;
}

static grub_err_t
bl_recover_key (grub_disk_t source, grub_cryptodisk_t dev,
		grub_cryptomount_args_t cargs)
{
  struct grub_bitlocker *ctx = dev->dev_data;
  grub_uint16_t rp_blocks[8];
  int is_rp;
  grub_uint16_t range_min, range_max;
  const grub_uint8_t *vmk_datum, *prev = NULL;
  grub_uint8_t *vmk_plain = NULL, *fvek_plain = NULL;
  grub_size_t vmk_plain_len = 0, fvek_plain_len = 0;
  const grub_uint8_t *vmk_key, *fvek_key;
  grub_size_t vmk_key_len, fvek_key_len;
  const grub_uint8_t *fvek_ccm = NULL;
  grub_uint16_t vmk_dsize, fvek_dsize, fvek_algo;
  grub_err_t ret;
  int got = 0;

  (void) source;

  if (cargs->key_data == NULL || cargs->key_len == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "no key data");

  is_rp = bl_parse_recovery (cargs->key_data, cargs->key_len, rp_blocks);
  if (is_rp)
    {
      range_min = 0x800;
      range_max = 0xfff;
    }
  else
    {
      range_min = 0x2000;
      range_max = 0x2000;
    }

  /* Try each matching VMK protector until one unwraps and authenticates.  */
  while (!got
	 && bl_next_vmk_in_range (ctx, range_min, range_max, prev, &vmk_datum))
    {
      const grub_uint8_t *stretch, *ccm;
      grub_uint8_t ik[32];

      prev = vmk_datum;

      if (!bl_get_nested (vmk_datum, BL_VT_STRETCH_KEY, &stretch)
	  || !bl_get_nested (vmk_datum, BL_VT_AES_CCM, &ccm))
	continue;

      if (is_rp)
	bl_recovery_key (rp_blocks, stretch + 0xc, ik);
      else if (!bl_user_key (cargs->key_data, cargs->key_len, stretch + 0xc, ik))
	continue;

      got = bl_ccm_datum_decrypt (ccm, ik, 32, &vmk_plain, &vmk_plain_len);
      grub_memset (ik, 0, sizeof (ik));
    }

  if (!got)
    return GRUB_ACCESS_DENIED;

  /* The decrypted VMK is itself a KEY datum: header(8) | algo(2) | pad(2) | key.  */
  vmk_dsize = bl_le16 (vmk_plain);
  if (vmk_dsize <= 0xc || (grub_size_t) vmk_dsize > vmk_plain_len)
    {
      ret = grub_error (GRUB_ERR_BAD_FS, "malformed VMK");
      goto out;
    }
  vmk_key = vmk_plain + 0xc;
  vmk_key_len = (grub_size_t) vmk_dsize - 0xc;

  if (!bl_iter_datum (ctx, BL_ET_FVEK, BL_VT_AES_CCM, NULL, &fvek_ccm)
      || !bl_ccm_datum_decrypt (fvek_ccm, vmk_key, vmk_key_len,
				&fvek_plain, &fvek_plain_len))
    {
      ret = GRUB_ACCESS_DENIED;
      goto out;
    }

  fvek_dsize = bl_le16 (fvek_plain);
  if (fvek_dsize <= 0xc || (grub_size_t) fvek_dsize > fvek_plain_len)
    {
      ret = grub_error (GRUB_ERR_BAD_FS, "malformed FVEK");
      goto out;
    }
  fvek_algo = bl_le16 (fvek_plain + 8);
  fvek_key = fvek_plain + 0xc;
  fvek_key_len = (grub_size_t) fvek_dsize - 0xc;

  if (!bl_init_keys (ctx, fvek_algo, fvek_key, fvek_key_len)
      && !bl_init_keys (ctx, ctx->dataset_algo, fvek_key, fvek_key_len))
    {
      ret = grub_error (GRUB_ERR_BAD_FS,
			"unsupported BitLocker cipher %#x", (unsigned) fvek_algo);
      goto out;
    }

  /* Keep the entered credential for the (proc)/fve_keys dump.  */
  ctx->saved_key = grub_malloc (cargs->key_len);
  if (ctx->saved_key != NULL)
    {
      grub_memcpy (ctx->saved_key, cargs->key_data, cargs->key_len);
      ctx->saved_key_len = cargs->key_len;
    }

  ret = GRUB_ERR_NONE;

out:
  if (vmk_plain != NULL)
    {
      grub_memset (vmk_plain, 0, vmk_plain_len);
      grub_free (vmk_plain);
    }
  if (fvek_plain != NULL)
    {
      grub_memset (fvek_plain, 0, fvek_plain_len);
      grub_free (fvek_plain);
    }
  return ret;
}

struct grub_cryptodisk_dev bitlocker_crypto = {
  .scan = bl_scan,
  .recover_key = bl_recover_key
};

/*
 * (proc)/fve_keys - the BitLocker analogue of (proc)/luks_script.  One line
 * per unlocked BitLocker volume: "<volume-uuid> <credential>", where the
 * credential is the password or recovery password the user unlocked it with.
 */
static char *
fve_keys_get (grub_size_t *sz)
{
  grub_cryptodisk_t dev;
  grub_size_t total = 0;
  char *ret, *ptr;

  *sz = 0;

  for (dev = grub_cryptodisk_list_head (); dev != NULL; dev = dev->next)
    {
      struct grub_bitlocker *ctx = dev->dev_data;

      if (grub_strcmp (dev->modname, "bitlocker") != 0
	  || ctx == NULL || ctx->saved_key == NULL)
	continue;
      total += grub_strlen (dev->uuid) + 1 + ctx->saved_key_len + 1;
    }

  ret = grub_malloc (total + 1);
  if (ret == NULL)
    return NULL;

  ptr = ret;
  for (dev = grub_cryptodisk_list_head (); dev != NULL; dev = dev->next)
    {
      struct grub_bitlocker *ctx = dev->dev_data;

      if (grub_strcmp (dev->modname, "bitlocker") != 0
	  || ctx == NULL || ctx->saved_key == NULL)
	continue;
      ptr = grub_stpcpy (ptr, dev->uuid);
      *ptr++ = ' ';
      grub_memcpy (ptr, ctx->saved_key, ctx->saved_key_len);
      ptr += ctx->saved_key_len;
      *ptr++ = '\n';
    }
  *ptr = '\0';
  *sz = (grub_size_t) (ptr - ret);
  return ret;
}

static struct grub_procfs_entry fve_keys =
{
  .name = "fve_keys",
  .get_contents = fve_keys_get
};

GRUB_MOD_INIT (bitlocker)
{
  grub_cryptodisk_dev_register (&bitlocker_crypto);
  grub_procfs_register ("fve_keys", &fve_keys);
}

GRUB_MOD_FINI (bitlocker)
{
  grub_procfs_unregister (&fve_keys);
  grub_cryptodisk_dev_unregister (&bitlocker_crypto);
}
