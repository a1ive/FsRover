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

#ifndef GRUB_PLAINMOUNT_HEADER
#define GRUB_PLAINMOUNT_HEADER	1

#include <grub/types.h>
#include <grub/err.h>

/*
 * KEY holds raw key material rather than a passphrase: it is used as the
 * volume key verbatim, and HASH is ignored.  This is cryptsetup's key file,
 * which the caller has already read (including any --keyfile-offset).
 */
#define GRUB_PLAINMOUNT_KEYFILE		0x1

/* Passed as HASH to use the passphrase verbatim (cryptsetup's "plain").  */
#define GRUB_PLAINMOUNT_HASH_NONE	"plain"

/* Sector size assumed by cryptsetup when --sector-size is not given.  */
#define GRUB_PLAINMOUNT_DEFAULT_SECTOR_SIZE	512

grub_err_t
grub_plainmount_mount (const char *source_name,
	const char *cipher, const char *hash,
	grub_size_t key_bits, grub_size_t sector_size,
	grub_uint64_t offset, grub_uint64_t skip,
	const void *key, grub_size_t key_len, grub_uint32_t flags,
	const char *uuid, char *out_name, grub_size_t out_size);

#endif /* ! GRUB_PLAINMOUNT_HEADER */
