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

/*
 * A VeraCrypt volume has no plaintext signature: everything past the 64 byte
 * salt of the header is ciphertext, so the volume can only be recognised by
 * decrypting its header with a key derived from the passphrase and checking
 * the 'VERA' / 'TRUE' magic plus two CRC-32s.
 */

#include <grub/cryptodisk.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/disk.h>
#include <grub/crypto.h>
#include <grub/partition.h>
#include <grub/veracrypt.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv3+");

/* Volume header layout.  All fields are big-endian.  */
#define VC_SALT_SIZE		64
#define VC_HEADER_SIZE		512
#define VC_ENC_OFFSET		VC_SALT_SIZE
#define VC_ENC_SIZE		(VC_HEADER_SIZE - VC_ENC_OFFSET)
#define VC_KEYDATA_OFFSET	256
#define VC_KEYDATA_SIZE		256

#define VC_OFF_MAGIC		64
#define VC_OFF_VERSION		68
#define VC_OFF_REQ_VERSION	70
#define VC_OFF_KEY_CRC		72
#define VC_OFF_HIDDEN_SIZE	92
#define VC_OFF_VOLUME_SIZE	100
#define VC_OFF_AREA_START	108
#define VC_OFF_AREA_LENGTH	116
#define VC_OFF_FLAGS		124
#define VC_OFF_SECTOR_SIZE	128
#define VC_OFF_HEADER_CRC	252

#define VC_MAGIC_VERA		0x56455241U	/* 'VERA' */
#define VC_MAGIC_TRUE		0x54525545U	/* 'TRUE' */

#define VC_HEADER_VERSION_MAX	5

/*
 * Header slots.  Each is 64 KiB but only its first 512 bytes are used; the
 * rest is random data.  A volume reserves 128 KiB at each end of the host.
 */
#define VC_SLOT_SIZE		65536
#define VC_HIDDEN_SLOT_OFFSET	65536
#define VC_HEADER_GROUP_SIZE	131072

/* Legacy (VeraCrypt before 1.0b) volumes carry a bare 512 byte header.  */
#define VC_LEGACY_HEADER_SIZE	512
#define VC_LEGACY_REQ_VERSION	0x10b

/* XTS data units are always 512 bytes, whatever the volume's sector size.  */
#define VC_DATA_UNIT_SIZE	512
#define VC_BLOCK_SIZE		16

/* Every VeraCrypt cipher uses a 256 bit key; cascades chain at most three.  */
#define VC_KEY_SIZE		32
#define VC_MAX_CASCADE		3
#define VC_MAX_KEY		(VC_KEY_SIZE * VC_MAX_CASCADE)
/* PBKDF2 always produces primary + secondary keys for the largest cascade.  */
#define VC_DK_SIZE		(2 * VC_MAX_KEY)

/* Matches VeraCrypt's MAX_PASSWORD; keyfile pools are exactly 64 or 128.  */
#define VC_MAX_PASSPHRASE	128

/* Volume header flags.  */
#define VC_FLAG_SYSTEM		0x1
#define VC_FLAG_INPLACE		0x2

/* Sector size bounds from the header.  */
#define VC_MIN_SECTOR_SIZE	512
#define VC_MAX_SECTOR_SIZE	4096

/* Ciphers, in VeraCrypt's Ciphers[] order.  */
enum vc_cipher_id
{
	VC_AES,
	VC_SERPENT,
	VC_TWOFISH,
	VC_CAMELLIA,
	VC_KUZNYECHIK,
	VC_NCIPHER
};

/*
 * Names to look up in the crypto registry.  A cipher that is not registered
 * simply makes the encryption algorithms using it unavailable.  GOST89 is
 * absent on purpose: VeraCrypt has not compiled it since 1.19, so no volume
 * that can still be mounted by VeraCrypt itself uses it.
 */
static const char *const vc_cipher_names[VC_NCIPHER] =
{
	"AES", "SERPENT256", "TWOFISH", "CAMELLIA256", "KUZNYECHIK"
};

static const signed char vc_ea[][VC_MAX_CASCADE] =
{
	{ VC_AES,		-1,		-1 },
	{ VC_SERPENT,	-1,		-1 },
	{ VC_TWOFISH,	-1,		-1 },
	{ VC_CAMELLIA,	-1,		-1 },
	{ VC_KUZNYECHIK,	-1,		-1 },
	{ VC_TWOFISH,	VC_AES,		-1 },
	{ VC_SERPENT,	VC_TWOFISH,	VC_AES },
	{ VC_AES,		VC_SERPENT,	-1 },
	{ VC_AES,		VC_TWOFISH,	VC_SERPENT },
	{ VC_SERPENT,	VC_TWOFISH,	-1 },
	{ VC_KUZNYECHIK,	VC_CAMELLIA,	-1 },
	{ VC_TWOFISH,	VC_KUZNYECHIK,	-1 },
	{ VC_SERPENT,	VC_CAMELLIA,	-1 },
	{ VC_AES,		VC_KUZNYECHIK,	-1 },
	{ VC_CAMELLIA,	VC_SERPENT,	VC_KUZNYECHIK }
};

#define VC_NEA	(sizeof (vc_ea) / sizeof (vc_ea[0]))

/* PRFs, in VeraCrypt's hash enum order (the order they are tried in).  */
static const struct
{
	const char *md_name;
	int truecrypt;
} vc_prf[] =
{
	{ "SHA512",		1 },	/* GRUB_VERACRYPT_PRF_SHA512    */
	{ "WHIRLPOOL",	1 },	/* GRUB_VERACRYPT_PRF_WHIRLPOOL */
	{ "SHA256",		0 },	/* GRUB_VERACRYPT_PRF_SHA256    */
	{ "RIPEMD160",	1 },	/* GRUB_VERACRYPT_PRF_RIPEMD160 */
	{ "STRIBOG512",	0 }	/* GRUB_VERACRYPT_PRF_STREEBOG  */
};

#define VC_NPRF	(sizeof (vc_prf) / sizeof (vc_prf[0]))

/* A cascade of XTS passes, innermost first.  */
struct vc_xts
{
	int n;
	grub_crypto_cipher_handle_t cipher[VC_MAX_CASCADE];
	grub_crypto_cipher_handle_t tweak[VC_MAX_CASCADE];
};

/* Private state of a cascaded volume; single-cipher volumes have none.  */
struct grub_veracrypt
{
	struct vc_xts xts;
};

/* The fields of a decrypted volume header this backend cares about.  */
struct vc_header
{
	grub_uint16_t version;
	grub_uint16_t req_version;
	grub_uint64_t hidden_size;
	grub_uint64_t volume_size;
	grub_uint64_t area_start;
	grub_uint64_t area_length;
	grub_uint32_t flags;
	grub_uint32_t sector_size;
	grub_uint8_t keydata[VC_KEYDATA_SIZE];
};

static grub_uint16_t
vc_be16 (const grub_uint8_t *p)
{
	return grub_be_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
vc_be32 (const grub_uint8_t *p)
{
	return grub_be_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
vc_be64 (const grub_uint8_t *p)
{
	return grub_be_to_cpu64 (grub_get_unaligned64 (p));
}

/*
 * CRC-32 as used by the volume header: the ordinary reflected CRC-32
 * (polynomial 0xedb88320, preset and final inversion), i.e. what the crypto
 * registry calls "CRC32".
 */
static grub_uint32_t
vc_crc32 (const void *data, grub_size_t len)
{
	grub_uint32_t crc = 0;

	grub_crypto_hash (GRUB_MD_CRC32, &crc, data, len);
	return grub_be_to_cpu32 (crc);
}

/* Multiply by x in GF(2^128), the XTS tweak step (x^128+x^7+x^2+x+1).  */
static void
vc_gf_mul_x (grub_uint8_t *g)
{
	int over = 0, over2 = 0;
	unsigned j;

	for (j = 0; j < VC_BLOCK_SIZE; j++)
	{
		over2 = !!(g[j] & 0x80);
		g[j] = (grub_uint8_t) ((g[j] << 1) | over);
		over = over2;
	}
	if (over)
		g[0] ^= 0x87;
}

/*
 * One XTS decryption pass over BUF.  LEN must be a multiple of the cipher
 * block size but need not be a multiple of the data unit size: the volume
 * header is 448 bytes and lives entirely inside data unit 0.
 */
static gcry_err_code_t
vc_xts_pass (grub_crypto_cipher_handle_t cipher,
	grub_crypto_cipher_handle_t tweak, grub_uint8_t *buf, grub_size_t len, grub_uint64_t unit)
{
	gcry_err_code_t err;

	while (len > 0)
	{
		grub_uint8_t tw[VC_BLOCK_SIZE];
		grub_size_t n = len < VC_DATA_UNIT_SIZE ? len : VC_DATA_UNIT_SIZE;
		grub_size_t j;

		grub_memset(tw, 0, sizeof(tw));
		grub_set_unaligned64(tw, grub_cpu_to_le64(unit));
		err = grub_crypto_ecb_encrypt(tweak, tw, tw, VC_BLOCK_SIZE);
		if (err != GPG_ERR_NO_ERROR)
			return err;

		for (j = 0; j < n; j += VC_BLOCK_SIZE)
		{
			grub_crypto_xor(buf + j, buf + j, tw, VC_BLOCK_SIZE);
			err = grub_crypto_ecb_decrypt(cipher, buf + j, buf + j, VC_BLOCK_SIZE);
			if (err != GPG_ERR_NO_ERROR)
				return err;
			grub_crypto_xor(buf + j, buf + j, tw, VC_BLOCK_SIZE);
			vc_gf_mul_x(tw);
		}

		buf += n;
		len -= n;
		unit++;
	}

	return GPG_ERR_NO_ERROR;
}

/* Undo a cascade: the outermost cipher was applied last, so it goes first.  */
static gcry_err_code_t
vc_xts_decrypt (const struct vc_xts *x, grub_uint8_t *buf, grub_size_t len, grub_uint64_t unit)
{
	gcry_err_code_t err;
	int i;

	for (i = x->n - 1; i >= 0; i--)
	{
		err = vc_xts_pass(x->cipher[i], x->tweak[i], buf, len, unit);
		if (err != GPG_ERR_NO_ERROR)
			return err;
	}

	return GPG_ERR_NO_ERROR;
}

static void
vc_xts_close (struct vc_xts *x)
{
	int i;

	for (i = 0; i < VC_MAX_CASCADE; i++)
	{
		grub_crypto_cipher_close (x->cipher[i]);
		grub_crypto_cipher_close (x->tweak[i]);
		x->cipher[i] = NULL;
		x->tweak[i] = NULL;
	}
	x->n = 0;
}

/*
 * Open the cascade of encryption algorithm EA and key it from KEY, which
 * holds the primary keys of every cipher followed by the secondary keys in
 * the same order.  Returns 0 when a cipher of the cascade is not registered,
 * which is not an error: that algorithm is simply not available.
 */
static int
vc_xts_open (struct vc_xts *x, unsigned ea, const grub_uint8_t *key)
{
	grub_size_t keysize;
	int i;

	grub_memset(x, 0, sizeof(*x));

	for (i = 0; i < VC_MAX_CASCADE && vc_ea[ea][i] >= 0; i++)
		;
	x->n = i;
	keysize = (grub_size_t)x->n * VC_KEY_SIZE;

	for (i = 0; i < x->n; i++)
	{
		const struct gcry_cipher_spec* spec;

		spec = grub_crypto_lookup_cipher_by_name(vc_cipher_names[vc_ea[ea][i]]);
		if (spec == NULL || spec->blocksize != VC_BLOCK_SIZE)
			goto fail;

		x->cipher[i] = grub_crypto_cipher_open(spec);
		x->tweak[i] = grub_crypto_cipher_open(spec);
		if (x->cipher[i] == NULL || x->tweak[i] == NULL)
			goto fail;

		if (grub_crypto_cipher_set_key(x->cipher[i], key + i * VC_KEY_SIZE, VC_KEY_SIZE) != GPG_ERR_NO_ERROR)
			goto fail;
		if (grub_crypto_cipher_set_key(x->tweak[i], key + keysize + i * VC_KEY_SIZE, VC_KEY_SIZE) != GPG_ERR_NO_ERROR)
			goto fail;
	}

	return 1;

fail:
	vc_xts_close(x);
	return 0;
}



/*
 * PBKDF2 iteration count.  Straight from VeraCrypt's
 * get_pkcs5_iteration_count(); BOOT is for volumes inside the scope of
 * system encryption, whose headers are the 512 byte ones written by the
 * bootloader.
 */
static unsigned
vc_iterations (int prf, grub_uint32_t pim, int truecrypt, int boot)
{
	switch (prf)
	{
	case GRUB_VERACRYPT_PRF_RIPEMD160:
		if (truecrypt)
			return boot ? 1000 : 2000;
		if (pim == 0)
			return boot ? 327661 : 655331;
		return boot ? pim * 2048 : 15000 + pim * 1000;

	case GRUB_VERACRYPT_PRF_SHA512:
	case GRUB_VERACRYPT_PRF_WHIRLPOOL:
		if (truecrypt)
			return 1000;
		return pim == 0 ? 500000 : 15000 + pim * 1000;

	case GRUB_VERACRYPT_PRF_SHA256:
	case GRUB_VERACRYPT_PRF_STREEBOG:
		if (truecrypt)
			return 0;
		if (pim == 0)
			return boot ? 200000 : 500000;
		return boot ? pim * 2048 : 15000 + pim * 1000;
	}

	return 0;
}

/*
 * Parse an already decrypted header.  Returns 1 when it is a valid header
 * for this mode, which -- magic plus two CRC-32s over 444 of the 448
 * decrypted bytes -- also means the key was right.
 */
static int
vc_parse_header (const grub_uint8_t *h, int truecrypt, struct vc_header *out)
{
	grub_uint32_t magic = truecrypt ? VC_MAGIC_TRUE : VC_MAGIC_VERA;

	if (vc_be32(h + VC_OFF_MAGIC) != magic)
		return 0;

	out->version = vc_be16(h + VC_OFF_VERSION);
	if (out->version == 0 || out->version > VC_HEADER_VERSION_MAX)
		return 0;

	/* The header CRC only exists from version 4 on.  */
	if (out->version >= 4
		&& vc_be32(h + VC_OFF_HEADER_CRC) != vc_crc32(h + VC_OFF_MAGIC, VC_OFF_HEADER_CRC - VC_OFF_MAGIC))
		return 0;

	if (vc_be32(h + VC_OFF_KEY_CRC) != vc_crc32(h + VC_KEYDATA_OFFSET,
		VC_KEYDATA_SIZE))
		return 0;

	out->req_version = vc_be16(h + VC_OFF_REQ_VERSION);
	/*
	 * VeraCrypt's TrueCrypt mode only claims TrueCrypt 6.0 through 7.1a.
	 * Older volumes use the pre-6.0 layout with LRW or CBC, which VeraCrypt
	 * itself dropped along with those modes.
	 */
	if (truecrypt && (out->req_version < 0x600 || out->req_version > 0x71a))
		return 0;

	out->hidden_size = vc_be64(h + VC_OFF_HIDDEN_SIZE);
	out->volume_size = vc_be64(h + VC_OFF_VOLUME_SIZE);
	out->area_start = vc_be64(h + VC_OFF_AREA_START);
	out->area_length = vc_be64(h + VC_OFF_AREA_LENGTH);
	out->flags = vc_be32(h + VC_OFF_FLAGS);

	out->sector_size = out->version >= 5 ? vc_be32(h + VC_OFF_SECTOR_SIZE) : VC_MIN_SECTOR_SIZE;
	if (out->sector_size < VC_MIN_SECTOR_SIZE
		|| out->sector_size > VC_MAX_SECTOR_SIZE
		|| out->sector_size % VC_DATA_UNIT_SIZE != 0)
		return 0;

	grub_memcpy(out->keydata, h + VC_KEYDATA_OFFSET, VC_KEYDATA_SIZE);
	return 1;
}

/*
 * Try one derived header key against every encryption algorithm.  RAW is the
 * untouched 512 byte header; on success EA receives the algorithm that
 * matched and OUT the parsed header.
 */
static int
vc_try_algorithms (const grub_uint8_t *raw, const grub_uint8_t *dk, int truecrypt, unsigned *ea, struct vc_header *out)
{
	unsigned i;

	for (i = 0; i < VC_NEA; i++)
	{
		grub_uint8_t plain[VC_ENC_SIZE];
		struct vc_xts xts;
		int ok;

		if (!vc_xts_open(&xts, i, dk))
			continue;

		grub_memcpy(plain, raw + VC_ENC_OFFSET, VC_ENC_SIZE);
		ok = vc_xts_decrypt(&xts, plain, VC_ENC_SIZE, 0) == GPG_ERR_NO_ERROR;
		vc_xts_close(&xts);

		/*
		 * vc_parse_header() indexes from the start of the header, so hand it a
		 * buffer whose first VC_ENC_OFFSET bytes are the (unencrypted) salt.
		 */
		if (ok)
		{
			grub_uint8_t full[VC_HEADER_SIZE];

			grub_memcpy(full, raw, VC_ENC_OFFSET);
			grub_memcpy(full + VC_ENC_OFFSET, plain, VC_ENC_SIZE);
			ok = vc_parse_header(full, truecrypt, out);
			grub_memset(full, 0, sizeof(full));
		}

		grub_memset(plain, 0, sizeof(plain));
		if (ok)
		{
			*ea = i;
			return 1;
		}
	}

	return 0;
}

/*
 * Try to unlock the header in RAW.  Runs the key derivation for every
 * candidate PRF and, for each, every encryption algorithm.  DK_OUT keeps the
 * derived key of the PRF that matched (unused by the caller but zeroed here
 * for hygiene); EA, PRF and OUT describe the volume on success.
 */
static int
vc_try_header (const grub_uint8_t *raw, const grub_uint8_t *pass, grub_size_t pass_len,
	grub_uint32_t pim, int want_prf, int truecrypt, int boot, unsigned *ea, int *prf, struct vc_header *out)
{
	unsigned i;

	for (i = 0; i < VC_NPRF; i++)
	{
		int id = (int)i + GRUB_VERACRYPT_PRF_SHA512;
		const gcry_md_spec_t* md;
		grub_uint8_t dk[VC_DK_SIZE];
		unsigned iter;
		int found;

		if (want_prf != GRUB_VERACRYPT_PRF_AUTO && want_prf != id)
			continue;
		if (truecrypt && !vc_prf[i].truecrypt)
			continue;

		iter = vc_iterations(id, pim, truecrypt, boot);
		if (iter == 0)
			continue;

		md = grub_crypto_lookup_md_by_name(vc_prf[i].md_name);
		if (md == NULL)
			continue;

		grub_dprintf("veracrypt", "trying PRF %s, %u iterations\n",
			vc_prf[i].md_name, iter);

		if (grub_crypto_pbkdf2(md, pass, pass_len, raw, VC_SALT_SIZE, iter, dk, sizeof(dk)) != GPG_ERR_NO_ERROR)
		{
			grub_memset(dk, 0, sizeof(dk));
			continue;
		}

		found = vc_try_algorithms(raw, dk, truecrypt, ea, out);
		grub_memset(dk, 0, sizeof(dk));
		if (found)
		{
			*prf = id;
			return 1;
		}
	}

	return 0;
}



static grub_err_t
vc_read_sectors (grub_cryptodisk_t dev, grub_disk_addr_t sector, grub_size_t size, char *buf)
{
	struct grub_veracrypt* ctx = dev->dev_data;
	grub_disk_addr_t start = sector + dev->offset_sectors;
	grub_err_t err;
	gcry_err_code_t gerr;

	/* log_sector_size is pinned to 9, so sectors and data units coincide.  */
	err = grub_disk_read(dev->source_disk, start, 0, size << GRUB_DISK_SECTOR_BITS, buf);
	if (err != GRUB_ERR_NONE)
		return err;

	gerr = vc_xts_decrypt(&ctx->xts, (grub_uint8_t*)buf, size << GRUB_DISK_SECTOR_BITS, start);
	return grub_crypto_gcry_error(gerr);
}

static void
vc_close (grub_cryptodisk_t dev)
{
	struct grub_veracrypt* ctx = dev->dev_data;

	if (ctx == NULL)
		return;
	vc_xts_close(&ctx->xts);
	grub_free(ctx);
	dev->dev_data = NULL;
}

/*
 * VeraCrypt volumes carry no UUID.  Derive a stable one from the salt of the
 * header that unlocked the volume: it is unique per volume, survives
 * remounts, and does not leak key material.
 */
static void
vc_set_uuid (grub_cryptodisk_t dev, const grub_uint8_t *salt)
{
	grub_snprintf (dev->uuid, sizeof (dev->uuid),
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		salt[0], salt[1], salt[2], salt[3], salt[4], salt[5],
		salt[6], salt[7], salt[8], salt[9], salt[10], salt[11],
		salt[12], salt[13], salt[14], salt[15]);
}

/* Configure the bulk cipher of DEV from the decrypted key material.  */
static grub_err_t
vc_setup_cipher (grub_cryptodisk_t dev, unsigned ea, const grub_uint8_t *keydata)
{
	struct grub_veracrypt* ctx;
	int n;

	for (n = 0; n < VC_MAX_CASCADE && vc_ea[ea][n] >= 0; n++)
		;

	if (n == 1)
	{
		grub_err_t err;

		/*
		 * A single cipher fits the generic path: grub_cryptodisk_setkey()
		 * splits an XTS key exactly the way VeraCrypt lays out the primary and
		 * secondary master keys.
		 */
		err = grub_cryptodisk_setcipher(dev, vc_cipher_names[vc_ea[ea][0]], "xts-plain64");
		if (err != GRUB_ERR_NONE)
			return err;

		if (grub_cryptodisk_setkey(dev, (grub_uint8_t*)keydata, 2 * VC_KEY_SIZE) != GPG_ERR_NO_ERROR)
			return grub_error(GRUB_ERR_BAD_ARGUMENT, "cannot set volume key");

		return GRUB_ERR_NONE;
	}

	ctx = grub_zalloc(sizeof(*ctx));
	if (ctx == NULL)
		return grub_errno;

	if (!vc_xts_open(&ctx->xts, ea, keydata))
	{
		grub_free(ctx);
		return grub_error(GRUB_ERR_BAD_ARGUMENT, "cannot set volume key");
	}

	dev->dev_data = ctx;
	dev->read_sectors = vc_read_sectors;
	dev->dev_close = vc_close;
	return GRUB_ERR_NONE;
}

/*
 * Unlock the VeraCrypt or TrueCrypt volume hosted on SOURCE_NAME and, on
 * success, return the name of the resulting cryptodisk ("cryptoN") in
 * OUT_NAME.
 *
 * PASS is the passphrase as typed, or the 64/128 byte pool a keyfile list
 * was folded into.  PIM is the personal iterations multiplier (0 for the
 * default), PRF one of GRUB_VERACRYPT_PRF_* with GRUB_VERACRYPT_PRF_AUTO
 * meaning "try them all", and FLAGS a combination of GRUB_VERACRYPT_*.
 */
grub_err_t
grub_veracrypt_mount (const char *source_name, const void *pass, grub_size_t pass_len,
	grub_uint32_t pim, int prf, grub_uint32_t flags, char *out_name, grub_size_t out_size)
{
	grub_disk_t disk = NULL;
	grub_cryptodisk_t dev = NULL;
	grub_uint8_t raw[VC_HEADER_SIZE];
	struct vc_header hdr;
	grub_uint64_t host_size, slots[2], data_start, data_size;
	unsigned nslots = 0, i, ea = 0;
	int truecrypt = !!(flags & GRUB_VERACRYPT_TRUECRYPT);
	int hidden = 0, found_prf = 0, legacy;
	grub_err_t err;

	if (pass == NULL || pass_len == 0)
		return grub_error(GRUB_ERR_BAD_ARGUMENT, "no passphrase provided");
	if (pass_len > VC_MAX_PASSPHRASE)
		return grub_error(GRUB_ERR_BAD_ARGUMENT, "passphrase too long");
	if (truecrypt && pim != 0)
		return grub_error(GRUB_ERR_BAD_ARGUMENT, "TrueCrypt volumes do not support a PIM");
	if (prf != GRUB_VERACRYPT_PRF_AUTO && (prf < GRUB_VERACRYPT_PRF_SHA512 || prf > GRUB_VERACRYPT_PRF_STREEBOG))
		return grub_error(GRUB_ERR_BAD_ARGUMENT, "unknown PRF");

	disk = grub_disk_open(source_name);
	if (disk == NULL)
		return grub_errno;

	/* Already unlocked?  Report the existing mapping.  */
	dev = grub_cryptodisk_get_by_source_disk(disk);
	if (dev != NULL)
	{
		grub_disk_close(disk);
		if (out_name != NULL && out_size != 0)
			grub_snprintf(out_name, out_size, "crypto%lu", dev->id);
		return GRUB_ERR_NONE;
	}

	if (grub_disk_native_sectors(disk) == GRUB_DISK_SIZE_UNKNOWN)
	{
		err = grub_error(GRUB_ERR_BAD_DEVICE, N_("cannot determine disk %s size"), source_name);
		goto fail;
	}
	host_size = grub_disk_native_sectors(disk) << GRUB_DISK_SECTOR_BITS;

	/*
	 * Header slots to try, in VeraCrypt's own order: the normal header first
	 * (it shares its position with the legacy 512 byte one), then the hidden
	 * header.  Both have a backup copy in the last 128 KiB of the host.
	 */
	if (flags & GRUB_VERACRYPT_BACKUP)
	{
		if (host_size < VC_HEADER_GROUP_SIZE)
		{
			err = grub_error(GRUB_ERR_BAD_DEVICE, "volume too small");
			goto fail;
		}
		if (!(flags & GRUB_VERACRYPT_HIDDEN))
			slots[nslots++] = host_size - VC_HEADER_GROUP_SIZE;
		slots[nslots++] = host_size - VC_SLOT_SIZE;
	}
	else
	{
		if (host_size < VC_SLOT_SIZE + VC_HEADER_SIZE)
		{
			err = grub_error(GRUB_ERR_BAD_DEVICE, "volume too small");
			goto fail;
		}
		if (!(flags & GRUB_VERACRYPT_HIDDEN))
			slots[nslots++] = 0;
		slots[nslots++] = VC_HIDDEN_SLOT_OFFSET;
	}

	for (i = 0; i < nslots; i++)
	{
		err = grub_disk_read(disk, slots[i] >> GRUB_DISK_SECTOR_BITS, 0,
			VC_HEADER_SIZE, raw);
		if (err != GRUB_ERR_NONE)
			goto fail;

		if (vc_try_header(raw, pass, pass_len, pim, prf, truecrypt, 0,
			&ea, &found_prf, &hdr))
			break;
	}

	if (i == nslots)
	{
		err = grub_error(GRUB_ERR_ACCESS_DENIED, "no matching volume header");
		goto fail;
	}

	/*
	 * Which volume was unlocked follows from the slot: the hidden header is
	 * the second one of each pair, and it is the only one that records a
	 * nonzero hidden volume size.
	 */
	hidden = (flags & GRUB_VERACRYPT_HIDDEN) || i > 0;
	if (hidden != (hdr.hidden_size != 0))
	{
		err = grub_error(GRUB_ERR_BAD_DEVICE, "inconsistent volume header");
		goto fail;
	}

	legacy = !truecrypt && !hidden && hdr.req_version < VC_LEGACY_REQ_VERSION;

	if (legacy)
	{
		/*
		 * Legacy layout: a bare 512 byte header with the data straight after
		 * it.  The size and offset fields of such a header are not filled in
		 * (they only became valid at required version 0x600), so the geometry
		 * comes from the host instead.
		 */
		data_start = VC_LEGACY_HEADER_SIZE;
		data_size = host_size - VC_LEGACY_HEADER_SIZE;
	}
	else
	{
		data_start = hdr.area_start;
		data_size = hdr.volume_size;
	}

	if (data_start % VC_DATA_UNIT_SIZE != 0
		|| data_size % VC_DATA_UNIT_SIZE != 0
		|| data_size == 0
		|| data_start > host_size
		|| data_size > host_size - data_start)
	{
		err = grub_error(GRUB_ERR_BAD_DEVICE, "bad volume geometry");
		goto fail;
	}

	/*
	 * In-place encryption that never finished leaves a plaintext tail this
	 * backend would hand out as garbage, so refuse the volume instead.
	 */
	if (!legacy && hdr.area_length != data_size)
	{
		err = grub_error(GRUB_ERR_BAD_DEVICE, "volume is not completely encrypted");
		goto fail;
	}

	dev = grub_zalloc(sizeof(*dev));
	if (dev == NULL)
	{
		err = grub_errno;
		goto fail;
	}

	/*
	 * Pin the mapped sector size to 512.  VeraCrypt's XTS data unit is 512
	 * bytes whatever the volume's sector size, so this keeps offset_sectors,
	 * iv_offset and the data unit number the same number, and the file system
	 * drivers take their sector size from the file system itself anyway.
	 */
	dev->log_sector_size = GRUB_DISK_SECTOR_BITS;
	dev->offset_sectors = data_start >> GRUB_DISK_SECTOR_BITS;
	dev->iv_offset = dev->offset_sectors;
	dev->total_sectors = data_size >> GRUB_DISK_SECTOR_BITS;
	dev->modname = truecrypt ? "truecrypt" : "veracrypt";

	err = vc_setup_cipher(dev, ea, hdr.keydata);
	if (err != GRUB_ERR_NONE)
		goto fail;

	err = grub_cryptodisk_insert(dev, source_name, disk);
	if (err != GRUB_ERR_NONE)
		goto fail;

	vc_set_uuid(dev, raw);

	grub_dprintf("veracrypt",
		"unlocked %s: %s volume, PRF %s, data at %" PRIuGRUB_UINT64_T ", %" PRIuGRUB_UINT64_T " bytes\n",
		source_name,
		hidden ? "hidden" : "normal",
		vc_prf[found_prf - GRUB_VERACRYPT_PRF_SHA512].md_name,
		data_start,
		data_size);

	grub_memset(raw, 0, sizeof(raw));
	grub_memset(&hdr, 0, sizeof(hdr));
	grub_disk_close(disk);

	if (out_name != NULL && out_size != 0)
		grub_snprintf(out_name, out_size, "crypto%lu", dev->id);
	return GRUB_ERR_NONE;

fail:
	grub_memset(raw, 0, sizeof(raw));
	grub_memset(&hdr, 0, sizeof(hdr));
	if (dev != NULL)
	{
		vc_close(dev);
		grub_crypto_cipher_close(dev->cipher);
		grub_crypto_cipher_close(dev->secondary_cipher);
		grub_free(dev);
	}
	grub_disk_close(disk);
	return err;
}

GRUB_MOD_INIT (veracrypt)
{
}

GRUB_MOD_FINI (veracrypt)
{
}
