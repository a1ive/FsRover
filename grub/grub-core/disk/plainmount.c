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
 * Plain mode (cryptsetup's "plainOpen") volumes.
 * There is no header at all:
 * the whole device is ciphertext and every parameter -- cipher, mode, IV
 * generator, key size, sector size and how the passphrase becomes the key --
 * lives outside the volume and has to be supplied by the caller.
 * Nothing can be detected and nothing can be checked, so a wrong parameter
 * simply yields plausible garbage.
 */

#include <grub/cryptodisk.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/disk.h>
#include <grub/crypto.h>
#include <grub/plainmount.h>
#include <grub/safemath.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv3+");

/*
 * Plain volumes have no UUID.  grub gives them this one with the device
 * number in its last digits, and Rover keeps that so a device named in a
 * grub script means the same thing here.
 */
#define PLAINMOUNT_DEFAULT_UUID	"109fea84-a6b7-34a8-4bd1-1c506305a400"

/* Cryptodisk setkey() wrapper.  */
static grub_err_t
plainmount_setkey (grub_cryptodisk_t dev, grub_uint8_t *key, grub_size_t size)
{
	gcry_err_code_t code = grub_cryptodisk_setkey (dev, key, size);

	if (code != GPG_ERR_NO_ERROR)
	{
		grub_dprintf ("plainmount", "failed to set cipher key with code: %d\n", code);
		return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("cannot set specified key"));
	}
	return GRUB_ERR_NONE;
}

/*
 * Configure the device UUID.  Without one from the caller the default above
 * is used with the device number in hex at its end, so successive plain
 * devices get distinct UUIDs.
 */
static void
plainmount_set_uuid (grub_cryptodisk_t dev, const char *user_uuid)
{
	char tail[17];
	grub_size_t len;

	COMPILE_TIME_ASSERT (sizeof (dev->uuid) >= sizeof (PLAINMOUNT_DEFAULT_UUID));

	if (user_uuid != NULL && user_uuid[0] != '\0')
	{
		grub_strncpy (dev->uuid, user_uuid, sizeof (dev->uuid) - 1);
		dev->uuid[sizeof (dev->uuid) - 1] = '\0';
		return;
	}

	grub_strcpy (dev->uuid, PLAINMOUNT_DEFAULT_UUID);
	grub_snprintf (tail, sizeof (tail), "%lx", dev->id + 1);
	len = grub_strlen (tail);
	if (len < sizeof (PLAINMOUNT_DEFAULT_UUID) - 1)
		grub_memcpy (dev->uuid + sizeof (PLAINMOUNT_DEFAULT_UUID) - 1 - len,
			     tail, len);
}

/*
 * Configure the mapped sector size, where the data starts and how far the
 * mapping reaches.  OFFSET and SKIP are cryptsetup's --offset and --skip,
 * both counted in 512 byte sectors however large the mapped sector is: they
 * become the dm-crypt table's data offset and iv_offset, so the data at
 * OFFSET is what the mapped device shows at 0 while the IV keeps counting
 * from SKIP.
 */
static grub_err_t
plainmount_configure_sectors (grub_cryptodisk_t dev, grub_disk_t disk,
			      grub_size_t sector_size, grub_uint64_t offset,
			      grub_uint64_t skip)
{
	grub_uint64_t total = grub_disk_native_sectors (disk);
	grub_uint64_t per_sector;

	if (total == GRUB_DISK_SIZE_UNKNOWN)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   N_("cannot determine disk %s size"), disk->name);

	dev->log_sector_size = grub_log2ull (sector_size);
	per_sector = 1ULL << (dev->log_sector_size - GRUB_DISK_SECTOR_BITS);

	if (offset >= total)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				   N_("offset %" PRIuGRUB_UINT64_T
				      " is past the end of disk %s"),
				   offset, disk->name);
	/* Anything else would put the mapped sectors out of alignment.  */
	if ((offset & (per_sector - 1)) != 0)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				   N_("offset must be a multiple of %"
				      PRIuGRUB_UINT64_T " sectors"), per_sector);

	dev->offset_sectors = offset / per_sector;
	dev->iv_offset = skip;
	dev->total_sectors = (total - offset) / per_sector;
	if (dev->total_sectors == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   N_("cannot set specified sector size on disk %s"),
				   disk->name);

	grub_dprintf ("plainmount", "log_sector_size=%d, offset_sectors=%"
		      PRIuGRUB_UINT64_T ", iv_offset=%" PRIuGRUB_UINT64_T
		      ", total_sectors=%" PRIuGRUB_UINT64_T "\n",
		      dev->log_sector_size, dev->offset_sectors, dev->iv_offset,
		      dev->total_sectors);
	return GRUB_ERR_NONE;
}

/*
 * Turn the passphrase into a key of KEY_SIZE bytes, the way cryptsetup's
 * lib/crypt_plain.c does: block r of the key is hash('A' * r || passphrase),
 * and the blocks are concatenated until the key is full.  Hashing into MD
 * rather than straight into KEY matters on the last block, which is usually
 * a partial one; grub's version writes a whole digest there and overruns its
 * buffer when the key size is not a multiple of the digest length.
 */
static grub_err_t
plainmount_hash_password (const gcry_md_spec_t *hash,
			  const grub_uint8_t *pass, grub_size_t pass_size,
			  grub_uint8_t *key, grub_size_t key_size)
{
	grub_uint8_t md[GRUB_CRYPTO_MAX_MDLEN];
	grub_size_t len = hash->mdlen;
	grub_size_t done, round, sz;
	char *p;

	if (len == 0 || len > sizeof (md))
		return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unusable hash %s"),
				   hash->name);

	/* Room for the passphrase plus one 'A' per round.  */
	if (grub_add (pass_size, key_size / len + 2, &sz))
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
				   N_("overflow detected while allocating size of password buffer"));

	p = grub_zalloc (sz);
	if (p == NULL)
		return grub_errno;

	for (done = 0, round = 0; done < key_size; done += len, round++)
	{
		grub_size_t n = key_size - done;

		grub_memset (p, 'A', round);
		grub_memcpy (p + round, pass, pass_size);
		grub_crypto_hash (hash, md, p, pass_size + round);
		grub_memcpy (key + done, md, n < len ? n : len);
	}

	grub_memset (md, 0, sizeof (md));
	grub_memset (p, 0, sz);
	grub_free (p);
	return GRUB_ERR_NONE;
}

/*
 * Unlock the plain-mode volume on SOURCE_NAME and, on success, return the
 * name of the resulting cryptodisk ("cryptoN") in OUT_NAME.
 *
 * CIPHER is cryptsetup's specification, "cipher-mode-iv" ("aes-xts-plain64");
 * HASH names the digest the passphrase is stretched with, or
 * GRUB_PLAINMOUNT_HASH_NONE to use it verbatim.  KEY_BITS is the volume key
 * size in bits and SECTOR_SIZE the size the mapped device reports.  OFFSET
 * and SKIP are cryptsetup's --offset and --skip in 512 byte sectors.  KEY is
 * a passphrase, or raw key material when GRUB_PLAINMOUNT_KEYFILE is set.
 * UUID may be NULL to have one generated.
 */
grub_err_t
grub_plainmount_mount (const char *source_name,
		       const char *cipher, const char *hash,
		       grub_size_t key_bits, grub_size_t sector_size,
		       grub_uint64_t offset, grub_uint64_t skip,
		       const void *key, grub_size_t key_len, grub_uint32_t flags,
		       const char *uuid, char *out_name, grub_size_t out_size)
{
	grub_disk_t disk = NULL;
	grub_cryptodisk_t dev = NULL;
	const gcry_md_spec_t *md = NULL;
	grub_uint8_t *volume_key = NULL;
	char *ciphername = NULL, *mode;
	grub_size_t key_size;
	grub_err_t err;

	if (cipher == NULL || key == NULL || key_len == 0)
		return grub_error (GRUB_ERR_BAD_ARGUMENT, "missing plainmount parameter");

	if ((key_bits % GRUB_CHAR_BIT) != 0)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				   N_("key size is not multiple of %d bits"), GRUB_CHAR_BIT);
	key_size = key_bits / GRUB_CHAR_BIT;
	if (key_size == 0 || key_size > GRUB_CRYPTODISK_MAX_KEYLEN)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				   N_("key size %" PRIuGRUB_SIZE " exceeds maximum %d bits"),
				   key_bits, GRUB_CRYPTODISK_MAX_KEYLEN * GRUB_CHAR_BIT);

	if (sector_size < GRUB_DISK_SECTOR_SIZE)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				   N_("sector size must be at least %d"),
				   GRUB_DISK_SECTOR_SIZE);
	if ((sector_size & (sector_size - 1)) != 0)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				   N_("sector size %" PRIuGRUB_SIZE " is not power of 2"),
				   sector_size);

	/* A key file supplies the volume key itself, so it must be long enough.  */
	if ((flags & GRUB_PLAINMOUNT_KEYFILE) && key_len < key_size)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				   N_("key file is too short for a %" PRIuGRUB_SIZE
				      " bit key"), key_bits);

	if (!(flags & GRUB_PLAINMOUNT_KEYFILE)
	    && grub_strcmp (hash, GRUB_PLAINMOUNT_HASH_NONE) != 0)
	{
		md = grub_crypto_lookup_md_by_name (hash);
		if (md == NULL)
			return grub_error (GRUB_ERR_FILE_NOT_FOUND,
					   N_("couldn't load %s hash"), hash);
	}

	/* Split cryptsetup's "cipher-mode-iv" at the first hyphen.  */
	ciphername = grub_strdup (cipher);
	if (ciphername == NULL)
		return grub_errno;
	mode = grub_strchr (ciphername, '-');
	if (mode == NULL)
	{
		err = grub_error (GRUB_ERR_BAD_ARGUMENT,
				  N_("invalid cipher mode, must be of format cipher-mode"));
		goto fail;
	}
	*mode++ = '\0';

	disk = grub_disk_open (source_name);
	if (disk == NULL)
	{
		err = grub_errno;
		goto fail;
	}

	/*
	 * Plain volumes carry nothing to recognise them by, so a second mount
	 * of the same device would just be a second guess at its parameters;
	 * report the one already there instead.
	 */
	dev = grub_cryptodisk_get_by_source_disk (disk);
	if (dev != NULL)
	{
		if (out_name != NULL && out_size != 0)
			grub_snprintf (out_name, out_size, "crypto%lu", dev->id);
		grub_disk_close (disk);
		grub_free (ciphername);
		return GRUB_ERR_NONE;
	}

	dev = grub_zalloc (sizeof (*dev));
	volume_key = grub_zalloc (key_size);
	if (dev == NULL || volume_key == NULL)
	{
		err = grub_errno;
		goto fail;
	}

	err = grub_cryptodisk_setcipher (dev, ciphername, mode);
	if (err != GRUB_ERR_NONE)
	{
		if (err == GRUB_ERR_FILE_NOT_FOUND)
			err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid cipher %s"),
					  ciphername);
		else if (err == GRUB_ERR_BAD_ARGUMENT)
			err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid mode %s"), mode);
		goto fail;
	}

	err = plainmount_configure_sectors (dev, disk, sector_size, offset, skip);
	if (err != GRUB_ERR_NONE)
		goto fail;

	if (md != NULL)
	{
		err = plainmount_hash_password (md, key, key_len, volume_key, key_size);
		if (err != GRUB_ERR_NONE)
			goto fail;
		dev->hash = md;
	}
	else
	{
		/*
		 * Raw key material, or the "plain" hash: the key is the first
		 * key_size bytes of what the caller gave, zero padded.
		 */
		grub_memcpy (volume_key, key, key_len < key_size ? key_len : key_size);
	}

	err = plainmount_setkey (dev, volume_key, key_size);
	if (err != GRUB_ERR_NONE)
		goto fail;

	err = grub_cryptodisk_insert (dev, source_name, disk);
	if (err != GRUB_ERR_NONE)
		goto fail;

	dev->modname = "plainmount";
	plainmount_set_uuid (dev, uuid);

	grub_dprintf ("plainmount", "mounted %s: %s-%s, %" PRIuGRUB_SIZE
		      " bit key, %" PRIuGRUB_SIZE " byte sectors, offset %"
		      PRIuGRUB_UINT64_T ", skip %" PRIuGRUB_UINT64_T "\n",
		      source_name, ciphername, mode, key_bits, sector_size,
		      offset, skip);

	grub_memset (volume_key, 0, key_size);
	grub_free (volume_key);
	grub_free (ciphername);
	grub_disk_close (disk);

	if (out_name != NULL && out_size != 0)
		grub_snprintf (out_name, out_size, "crypto%lu", dev->id);
	return GRUB_ERR_NONE;

fail:
	if (volume_key != NULL)
	{
		grub_memset (volume_key, 0, key_size);
		grub_free (volume_key);
	}
	if (dev != NULL)
	{
		grub_crypto_cipher_close (dev->cipher);
		grub_crypto_cipher_close (dev->secondary_cipher);
		grub_crypto_cipher_close (dev->essiv_cipher);
		grub_free (dev);
	}
	grub_free (ciphername);
	grub_disk_close (disk);
	return err;
}

/*
 * Nothing to register: like veracrypt.c this backend is not probed, it is
 * driven from grub_plainmount_mount().
 */
GRUB_MOD_INIT (plainmount)
{
}

GRUB_MOD_FINI (plainmount)
{
}
