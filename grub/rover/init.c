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
 * Static replacement for the grub module loader: every module built
 * into grub.lib exposes grub_<name>_init/_fini via GRUB_MOD_INIT
 * (GRUB_KERNEL flavour, see rover\config.h), called here in dependency order.
 */

#include <grub/crypto.h>

#include "rover.h"

extern gcry_md_spec_t _gcry_digest_spec_crc32;
extern gcry_md_spec_t _gcry_digest_spec_md5;
extern gcry_md_spec_t _gcry_digest_spec_sha1;
extern gcry_md_spec_t _gcry_digest_spec_sha256;
extern gcry_md_spec_t _gcry_digest_spec_sha512;
extern gcry_md_spec_t _gcry_digest_spec_sha384;
extern gcry_cipher_spec_t _gcry_cipher_spec_aes;
extern gcry_cipher_spec_t _gcry_cipher_spec_aes192;
extern gcry_cipher_spec_t _gcry_cipher_spec_aes256;

#define ROVER_MODULE_LIST(mod)	\
	/* message digests (io modules look them up at open time) */	\
	mod (adler32)	\
	mod (crc64)	\
	/* disks: physical first, then volume managers / RAID */	\
	mod (windisk)	\
	mod (loopdisk)	\
	mod (diskfilter)	\
	mod (ldm)	\
	mod (lvm)	\
	mod (dm_nv)	\
	mod (mdraid09)	\
	mod (mdraid09_be)	\
	mod (mdraid1x)	\
	mod (raid5rec)	\
	mod (raid6rec)	\
	/* encrypted volumes (LUKS1/LUKS2/BitLocker/GELI) + procfs for luks_script */	\
	mod (cryptodisk)	\
	mod (luks)	\
	mod (luks2)	\
	mod (bitlocker)	\
	mod (geli)	\
	mod (procfs)	\
	/* partition maps */	\
	mod (part_acorn)	\
	mod (part_amiga)	\
	mod (part_apple)	\
	mod (part_bsd)	\
	mod (part_dfly)	\
	mod (part_dvh)	\
	mod (part_gpt)	\
	mod (part_msdos)	\
	mod (part_plan)	\
	mod (part_sun)	\
	mod (part_sunpc)	\
	/* filesystems */	\
	mod (affs)	\
	mod (afs)	\
	mod (apfs)	\
	mod (bfs)	\
	mod (btrfs)	\
	mod (cpio)	\
	mod (cpio_be)	\
	mod (cramfs)	\
	mod (erofs)	\
	mod (exfat)	\
	mod (ext2)	\
	mod (f2fs)	\
	mod (fat)	\
	mod (fbfs)	\
	mod (hfs)	\
	mod (hfsplus)	\
	mod (hfspluscomp)	\
	mod (iso9660)	\
	mod (jffs2)	\
	mod (jfs)	\
	mod (lynxfs)	\
	mod (minix)	\
	mod (minix_be)	\
	mod (minix2)	\
	mod (minix2_be)	\
	mod (minix3)	\
	mod (minix3_be)	\
	mod (newc)	\
	mod (ntfs)	\
	mod (ntfscomp)	\
	mod (odc)	\
	mod (qnx4)	\
	mod (qnx6)	\
	mod (redoxfs)	\
	mod (refs)	\
	mod (reiserfs)	\
	mod (romfs)	\
	mod (sfs)	\
	mod (squash4)	\
	mod (tar)	\
	mod (ubifs)	\
	mod (udf)	\
	mod (ufs1)	\
	mod (ufs1_be)	\
	mod (ufs2)	\
	mod (wim)	\
	mod (xfs)	\
	mod (zfs)	\
	mod (zip)	\
	/* transparent decompression filters */	\
	mod (gzio)	\
	mod (lzopio)	\
	mod (lz4io)	\
	mod (xzio)	\
	mod (zstdio)	\
	/* virtual disk image filters (loopdisk mounts) */	\
	mod (vhd)	\
	mod (vhdx)	\
	mod (vdi)	\
	mod (qcow)	\
	mod (vmdk)	\
	mod (dmg)	\
	mod (isz)

#define ROVER_MOD_DECLARE(name)	\
	void grub_##name##_init (void);	\
	void grub_##name##_fini (void);

ROVER_MODULE_LIST (ROVER_MOD_DECLARE)

#define ROVER_MOD_INIT(name)	grub_##name##_init ();
#define ROVER_MOD_FINI(name)	grub_##name##_fini ();

void
rover_init (void)
{
	grub_md_register (&_gcry_digest_spec_crc32);
	grub_md_register (&_gcry_digest_spec_md5);
	grub_md_register (&_gcry_digest_spec_sha1);
	grub_md_register (&_gcry_digest_spec_sha256);
	grub_md_register (&_gcry_digest_spec_sha512);
	grub_md_register (&_gcry_digest_spec_sha384);

	/* Block ciphers for cryptodisk (LUKS is almost always AES).  */
	grub_cipher_register (&_gcry_cipher_spec_aes);
	grub_cipher_register (&_gcry_cipher_spec_aes192);
	grub_cipher_register (&_gcry_cipher_spec_aes256);

	ROVER_MODULE_LIST (ROVER_MOD_INIT)
}

void
rover_fini (void)
{
	ROVER_MODULE_LIST (ROVER_MOD_FINI)

	grub_cipher_unregister (&_gcry_cipher_spec_aes256);
	grub_cipher_unregister (&_gcry_cipher_spec_aes192);
	grub_cipher_unregister (&_gcry_cipher_spec_aes);
	grub_md_unregister (&_gcry_digest_spec_sha384);
	grub_md_unregister (&_gcry_digest_spec_sha512);
	grub_md_unregister (&_gcry_digest_spec_sha256);
	grub_md_unregister (&_gcry_digest_spec_sha1);
	grub_md_unregister (&_gcry_digest_spec_md5);
	grub_md_unregister (&_gcry_digest_spec_crc32);
}
