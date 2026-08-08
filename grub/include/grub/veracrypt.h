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

#ifndef GRUB_VERACRYPT_HEADER
#define GRUB_VERACRYPT_HEADER	1

#include <grub/types.h>
#include <grub/err.h>

/*
 * Key derivation function, numbered like VeraCrypt's own hash IDs.  AUTO
 * tries every one of them, which is what VeraCrypt does when the user does
 * not pick a PRF -- and is correspondingly slow.
 */
#define GRUB_VERACRYPT_PRF_AUTO		0
#define GRUB_VERACRYPT_PRF_SHA512	1
#define GRUB_VERACRYPT_PRF_WHIRLPOOL	2
#define GRUB_VERACRYPT_PRF_SHA256	3
#define GRUB_VERACRYPT_PRF_RIPEMD160	4
#define GRUB_VERACRYPT_PRF_STREEBOG	5

/* Read the volume as a TrueCrypt one ('TRUE' magic, TrueCrypt iterations).  */
#define GRUB_VERACRYPT_TRUECRYPT	0x1
/* Unlock the hidden volume only, instead of trying the normal header first.  */
#define GRUB_VERACRYPT_HIDDEN		0x2
/* Use the backup headers in the last 128 KiB of the host.  */
#define GRUB_VERACRYPT_BACKUP		0x4

grub_err_t
grub_veracrypt_mount (const char *source_name,
	const void *pass, grub_size_t pass_len,
	grub_uint32_t pim, int prf, grub_uint32_t flags,
	char *out_name, grub_size_t out_size);

#endif /* ! GRUB_VERACRYPT_HEADER */
