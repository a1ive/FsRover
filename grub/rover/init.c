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

#define ROVER_MODULE_LIST(mod)	\
	/* message digests (io modules look them up at open time) */	\
	mod (adler32)	\
	mod (crc64)	\
	/* libgcrypt */	\
	mod (gcry_blake2)	\
	mod (gcry_blowfish)	\
	mod (gcry_camellia)	\
	mod (gcry_cast5)	\
	mod (gcry_crc)	\
	mod (gcry_des)	\
	mod (gcry_kuznyechik)	\
	mod (gcry_md5)	\
	mod (gcry_rijndael)	\
	mod (gcry_rmd160)	\
	mod (gcry_serpent)	\
	mod (gcry_sha1)	\
	mod (gcry_sha256)	\
	mod (gcry_sha512)	\
	mod (gcry_stribog)	\
	mod (gcry_twofish)	\
	mod (gcry_whirlpool)	\
	/* disks: physical (windisk) is optional and rover_init calls it */	\
	/* itself; here come the rest, then volume managers / RAID */	\
	mod (loopdisk)	\
	mod (winfile)	\
	mod (diskfilter)	\
	mod (ldm)	\
	mod (lvm)	\
	mod (dm_nv)	\
	mod (mdraid09)	\
	mod (mdraid09_be)	\
	mod (mdraid1x)	\
	mod (raid5rec)	\
	mod (raid6rec)	\
	/* encrypted volumes (LUKS/BitLocker/VeraCrypt/GELI) + procfs for luks_script */	\
	mod (cryptodisk)	\
	mod (luks)	\
	mod (luks2)	\
	mod (bitlocker)	\
	mod (veracrypt)	\
	mod (plainmount)	\
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
	mod (part_unixware)	\
	/* filesystems */	\
	mod (affs)	\
	mod (afs)	\
	mod (apfs)	\
	mod (arj)	\
	mod (bfs)	\
	mod (bootfs)	\
	mod (btrfs)	\
	mod (cab)	\
	mod (cbfs)	\
	mod (cpio)	\
	mod (cpio_be)	\
	mod (cramfs)	\
	mod (deb)	\
	mod (erofs)	\
	mod (exfat)	\
	mod (ext2)	\
	mod (f2fs)	\
	mod (fat)	\
	mod (fbfs)	\
	mod (hfs)	\
	mod (hfsplus)	\
	mod (hfspluscomp)	\
	mod (hpfs)	\
	mod (iso9660)	\
	mod (jffs2)	\
	mod (jfs)	\
	mod (littlefs)	\
	mod (lynxfs)	\
	mod (lzh)	\
	mod (minix)	\
	mod (minix_be)	\
	mod (minix2)	\
	mod (minix2_be)	\
	mod (minix3)	\
	mod (minix3_be)	\
	mod (newc)	\
	mod (nilfs2)	\
	mod (ntfs)	\
	mod (ntfscomp)	\
	mod (odc)	\
	mod (pmffs)	\
	mod (qnx4)	\
	mod (qnx6)	\
	mod (rar)	\
	mod (redoxfs)	\
	mod (refs)	\
	mod (regfs)	\
	mod (reiserfs)	\
	mod (romfs)	\
	mod (rpm)	\
	mod (sevenzip)	\
	mod (sfs)	\
	mod (sqlitefs)	\
	mod (squash4)	\
	mod (tar)	\
	mod (tibfs)	\
	mod (ubifs)	\
	mod (udf)	\
	mod (uefi)	\
	mod (ufs1)	\
	mod (ufs1_be)	\
	mod (ufs2)	\
	mod (vmfs)	\
	mod (vxfs)	\
	mod (wim)	\
	mod (xar)	\
	mod (xfs)	\
	mod (zfs)	\
	mod (zip)	\
	/* transparent decompression filters */	\
	mod (gzio)	\
	mod (lzopio)	\
	mod (lz4io)	\
	mod (xzio)	\
	mod (zstdio)	\
	mod (bz2io)	\
	mod (brio)	\
	mod (lzmaio)	\
	/* virtual disk image filters (loopdisk mounts) */	\
	mod (vhd)	\
	mod (vhdx)	\
	mod (vdi)	\
	mod (qcow)	\
	mod (vmdk)	\
	mod (dmg)	\
	mod (isz)	\
	mod (sparse)	\
	mod (parallels)	\
	mod (ffu)	\
	mod (tib)	\
	mod (tibx)	\
	mod (pmf)	\
	mod (pmfx)	\
	mod (ntfsclone)	\
	mod (sna)	\
	mod (cdimage)

#define ROVER_MOD_DECLARE(name)	\
	void grub_##name##_init (void);	\
	void grub_##name##_fini (void);

ROVER_MODULE_LIST (ROVER_MOD_DECLARE)

/* The one module outside the list: see ROVER_INIT_NO_WINDISK.  Its
   _fini is unconditional -- the module remembers whether it registered
   (it also declines without an elevated token) and does nothing here
   when it did not.  */
ROVER_MOD_DECLARE (windisk)

#define ROVER_MOD_INIT(name)	grub_##name##_init ();
#define ROVER_MOD_FINI(name)	grub_##name##_fini ();

void
rover_init (int flags)
{
	if (!(flags & ROVER_INIT_NO_WINDISK))
		grub_windisk_init ();
	ROVER_MODULE_LIST (ROVER_MOD_INIT)
}

void
rover_fini (void)
{
	grub_windisk_fini ();
	ROVER_MODULE_LIST (ROVER_MOD_FINI)
}
