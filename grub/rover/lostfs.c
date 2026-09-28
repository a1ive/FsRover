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
 * Boot sector and superblock tests of the lost partition search, on byte
 * buffers only.
 *
 * Deviations from TestDisk: the NTFS test also accepts the negative
 * cluster size encoding (up to 2 MiB clusters) and checks the sector
 * size; the exFAT test checks the boot sector fields the exFAT
 * specification requires and sizes the volume in its own sector size;
 * XFS, Btrfs, APFS, ReFS, F2FS, UFS, JFS and HFS get the additional field
 * checks noted at each; only single-device Btrfs is accepted; ReFS is
 * sized from its boot sector; UDF, which TestDisk does not search, is
 * recognised by its volume recognition sequence (ECMA-167); ReiserFS 4,
 * which GRUB does not read, is left out; extended boot records accept
 * any logical partition type.
 */

#include <grub/types.h>
#include <grub/lib/crc.h>
#include <grub/misc.h>

#include "lostint.h"

/* CRC-32 of the GPT header and entries.  */
grub_uint32_t
lost_crc32 (const grub_uint8_t *p, grub_size_t len)
{
	grub_uint32_t crc = 0xffffffff;
	unsigned int k;

	while (len--)
	{
		crc ^= *p++;
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
	}
	return ~crc;
}

/* ntfs.c test_NTFS/recover_NTFS: the size is the volume plus the backup
   boot sector that follows it.  */
int
lost_ntfs (const grub_uint8_t *bs, grub_uint64_t *size, unsigned int *bps)
{
	grub_uint64_t sectors;
	unsigned int spc;

	if (lost_le16 (bs + 0x1fe) != 0xaa55
		|| grub_memcmp (bs + 3, "NTFS", 4) != 0
		|| lost_le16 (bs + 0x0e) != 0	/* reserved sectors */
		|| bs[0x10] != 0	/* FATs */
		|| lost_le16 (bs + 0x11) != 0	/* root entries */
		|| lost_le16 (bs + 0x13) != 0	/* 16-bit sectors */
		|| lost_le16 (bs + 0x16) != 0	/* FAT length */
		|| lost_le32 (bs + 0x20) != 0)	/* 32-bit sectors */
		return 0;
	*bps = lost_le16 (bs + 0x0b);
	if (*bps < 256 || *bps > 4096 || !lost_is_pow2 (*bps))
		return 0;
	/* 1..128 sectors, or 2^-n for clusters of 128 KiB to 2 MiB.  */
	spc = bs[0x0d];
	if (!(spc <= 0x80 && lost_is_pow2 (spc)) && !(spc >= 0xf4 && spc <= 0xf8))
		return 0;
	sectors = lost_le64 (bs + 0x28);
	if (sectors == 0 || sectors >= (1ULL << 52))
		return 0;
	*size = (sectors + 1) * *bps;
	return 1;
}

/* fat.c test_FAT/recover_FAT.  SECTOR_SIZE is the device's: like TestDisk,
   a FAT whose sector size differs is rejected.  */
const char *
lost_fat (const grub_uint8_t *bs, unsigned int sector_size, grub_uint64_t *size)
{
	grub_uint32_t fat_length, total, reserved, clusters, calc;
	grub_uint64_t start_data;
	unsigned int spc, fats, dir_entries;
	const char *type;

	if (lost_le16 (bs + 0x1fe) != 0xaa55
		|| !((bs[0] == 0xeb && bs[2] == 0x90) || bs[0] == 0xe9))
		return NULL;
	spc = bs[0x0d];
	fats = bs[0x10];
	if (spc > 128 || !lost_is_pow2 (spc) || (fats != 1 && fats != 2)
		|| lost_le16 (bs + 0x0b) != sector_size
		|| (bs[0x15] != 0xf0 && bs[0x15] < 0xf8))
		return NULL;

	fat_length = lost_le16 (bs + 0x16) ? lost_le16 (bs + 0x16) : lost_le32 (bs + 0x24);
	total = lost_le16 (bs + 0x13) ? lost_le16 (bs + 0x13) : lost_le32 (bs + 0x20);
	reserved = lost_le16 (bs + 0x0e);
	dir_entries = lost_le16 (bs + 0x11);
	if (reserved == 0 || fat_length == 0)
		return NULL;
	start_data = reserved + (grub_uint64_t) fats * fat_length
		+ (dir_entries * 32 + sector_size - 1) / sector_size;
	if (start_data >= total)
		return NULL;
	clusters = (grub_uint32_t) ((total - start_data) / spc);

	if (clusters < 4085)
	{
		if (dir_entries == 0 || dir_entries % 16 || lost_le16 (bs + 0x16) > 256)
			return NULL;
		calc = (clusters + 2 + sector_size * 2 / 3 - 1) * 3 / 2 / sector_size;
		type = "fat12";
	}
	else if (clusters < 65525)
	{
		if (lost_le16 (bs + 0x16) == 0 || dir_entries == 0 || dir_entries % 16)
			return NULL;
		calc = (clusters + 2 + sector_size / 2 - 1) * 2 / sector_size;
		type = "fat16";
	}
	else
	{
		grub_uint32_t root = lost_le32 (bs + 0x2c);

		if (lost_le16 (bs + 0x13) != 0 || dir_entries != 0
			|| root < 2 || root >= 2 + clusters)
			return NULL;
		calc = (grub_uint32_t) (((grub_uint64_t) clusters + 2 + sector_size / 4 - 1) * 4 / sector_size);
		type = "fat32";
	}
	if (fat_length < calc)
		return NULL;
	*size = (grub_uint64_t) total * sector_size;
	return type;
}

/* exfat.c test_exFAT/recover_exFAT, with the boot sector checks of the
   exFAT specification (MustBeZero, shifts, number of FATs).  */
int
lost_exfat (const grub_uint8_t *bs, unsigned int *shift, grub_uint64_t *size)
{
	grub_uint64_t sectors;
	unsigned int i;

	if (lost_le16 (bs + 0x1fe) != 0xaa55 || grub_memcmp (bs + 3, "EXFAT   ", 8) != 0)
		return 0;
	for (i = 0x0b; i < 0x40; i++)
		if (bs[i])
			return 0;
	*shift = bs[0x6c];
	if (*shift < 9 || *shift > 12 || bs[0x6d] > 25 - *shift
		|| (bs[0x6e] != 1 && bs[0x6e] != 2))
		return 0;
	sectors = lost_le64 (bs + 0x48);
	if (sectors == 0 || sectors >= (1ULL << (64 - *shift)))
		return 0;
	*size = sectors << *shift;
	return 1;
}

/* ext2_common.c test_EXT2 and ext2.c recover_EXT2/set_EXT2_info.
   *SB_OFFSET is where this superblock copy lies from the start of the
   filesystem.  */
const char *
lost_ext (const grub_uint8_t *sb, grub_uint64_t *size, grub_uint64_t *sb_offset)
{
	grub_uint32_t compat, incompat, ro_compat, log_bs, bpg;
	grub_uint64_t blocks, free_blocks, block_nr;
	unsigned int errors, group;

	if (lost_le16 (sb + 0x38) != 0xef53)
		return NULL;
	compat = lost_le32 (sb + 0x5c);
	incompat = lost_le32 (sb + 0x60);
	ro_compat = lost_le32 (sb + 0x64);
	blocks = lost_le32 (sb + 0x04);
	free_blocks = lost_le32 (sb + 0x0c);
	if (incompat & 0x80)	/* 64BIT */
	{
		blocks |= (grub_uint64_t) lost_le32 (sb + 0x150) << 32;
		free_blocks |= (grub_uint64_t) lost_le32 (sb + 0x158) << 32;
	}
	errors = lost_le16 (sb + 0x3c);
	log_bs = lost_le32 (sb + 0x18);
	bpg = lost_le32 (sb + 0x20);
	if (free_blocks > blocks
		|| lost_le32 (sb + 0x10) > lost_le32 (sb + 0x00)	/* free inodes */
		|| errors > 3
		|| (lost_le16 (sb + 0x3a) & ~3U) != 0	/* state */
		|| blocks == 0 || log_bs > 6 || bpg == 0
		|| blocks >= (1ULL << (54 - log_bs)))
		return NULL;
	*size = blocks << (10 + log_bs);

	group = lost_le16 (sb + 0x5a);
	if (group)
	{
		block_nr = lost_le32 (sb + 0x14) + (grub_uint64_t) group * bpg;
		*sb_offset = block_nr << (10 + log_bs);
	}
	else
		*sb_offset = LOST_SB_1K;

	if ((ro_compat & (0x08 | 0x10 | 0x20 | 0x40)) || (incompat & (0x80 | 0x100)))
		return "ext4";
	if (compat & 0x04)
		return "ext3";
	return "ext2";
}

/* xfs.c test_xfs/recover_xfs, plus range checks of the logarithms,
   allocation groups and version.  *AG_SIZE is the byte size of an
   allocation group, *SECTOR_SIZE the filesystem's sector size.  */
int
lost_xfs (const grub_uint8_t *sb, grub_uint64_t *size, grub_uint64_t *ag_size,
	unsigned int *sector_size)
{
	grub_uint64_t dblocks = lost_be64 (sb + 8);
	grub_uint32_t agblocks = lost_be32 (sb + 84);
	grub_uint32_t agcount = lost_be32 (sb + 88);
	unsigned int version = lost_be16 (sb + 100) & 0xf;
	unsigned int blocklog = sb[120], sectlog = sb[121], inodelog = sb[122];

	if (lost_be32 (sb) != 0x58465342	/* "XFSB" */
		|| blocklog < 9 || blocklog > 16 || sectlog < 9 || sectlog > blocklog
		|| inodelog < 8 || inodelog > 11
		|| lost_be32 (sb + 4) != 1U << blocklog
		|| lost_be16 (sb + 102) != 1U << sectlog
		|| lost_be16 (sb + 104) != 1U << inodelog
		|| version < 1 || version > 5
		|| dblocks == 0 || agblocks == 0 || agcount == 0
		|| dblocks > (grub_uint64_t) agcount * agblocks)
		return 0;
	*size = dblocks << blocklog;
	*ag_size = (grub_uint64_t) agblocks << blocklog;
	*sector_size = 1U << sectlog;
	return 1;
}

/* btrfs.c test_btrfs/recover_btrfs, for single-device filesystems, with
   the superblock checksum when it is CRC32C.  *BYTENR is where this copy
   lies from the start of the device (64 KiB, 64 MiB or 256 GiB).  */
int
lost_btrfs (const grub_uint8_t *sb, grub_uint64_t *size, grub_uint64_t *bytenr)
{
	grub_uint32_t sectorsize = lost_le32 (sb + 144);
	grub_uint32_t nodesize = lost_le32 (sb + 148);

	if (grub_memcmp (sb + 64, "_BHRfS_M", 8) != 0)
		return 0;
	*bytenr = lost_le64 (sb + 48);
	if ((*bytenr != LOST_BTRFS_SB && *bytenr != 64ULL << 20 && *bytenr != 256ULL << 30)
		|| lost_le64 (sb + 136) != 1	/* num_devices */
		|| sectorsize < 4096 || sectorsize > 65536 || !lost_is_pow2 (sectorsize)
		|| nodesize < sectorsize || nodesize > 65536 || !lost_is_pow2 (nodesize)
		|| lost_le32 (sb + 201 + 32) == 0)	/* dev_item.sector_size */
		return 0;
	if (lost_le16 (sb + 196) == 0	/* csum_type CRC32C */
		&& lost_le32 (sb) != grub_getcrc32c (0, sb + 32, LOST_BTRFS_SB_SIZE - 32))
		return 0;
	*size = lost_le64 (sb + 201 + 8);	/* dev_item.total_bytes */
	return *size != 0;
}

/* hfs.c test_HFS/recover_HFS and hfsp.c test_HFSP/recover_HFSP on a
   master directory block or volume header.  */
const char *
lost_hfs (const grub_uint8_t *b, grub_uint64_t *size)
{
	grub_uint32_t block_size, total;
	grub_uint16_t sig = lost_be16 (b);

	if (sig == 0x4244)	/* "BD" */
	{
		grub_uint16_t blocks = lost_be16 (b + 0x12);

		block_size = lost_be32 (b + 0x14);
		/* Beyond TestDisk: the volume bitmap starts at sector 3 and the
		   allocation blocks after it, the name has at most 27 bytes and
		   the clump size is whole allocation blocks.  */
		if (block_size < 512 || !lost_is_pow2 (block_size) || blocks == 0
			|| lost_be16 (b + 0x22) > blocks
			|| lost_be16 (b + 0x0e) != 3 || lost_be16 (b + 0x1c) <= 3 || b[0x24] > 27
			|| lost_be32 (b + 0x18) % block_size)
			return NULL;
		/* The last 1 KiB holds the alternate MDB.  */
		*size = (grub_uint64_t) blocks * block_size + lost_be16 (b + 0x1c) * 512ULL + 0x400;
		if (*size > 2049ULL << 30)
			return NULL;
		return "hfs";
	}
	if (!(sig == 0x482b && lost_be16 (b + 2) == 4) && !(sig == 0x4858 && lost_be16 (b + 2) == 5))
		return NULL;
	block_size = lost_be32 (b + 0x28);
	total = lost_be32 (b + 0x2c);
	if (lost_be32 (b + 0x30) > total || total == 0
		|| block_size < 512 || !lost_is_pow2 (block_size))
		return NULL;
	*size = (grub_uint64_t) total * block_size;
	return sig == 0x482b ? "hfsplus" : "hfsx";
}

/* apfs.c recover_APFS and apfs_common.c test_APFS/VerifyBlock, with the
   object type and the checksum over the whole container block.  */
int
lost_apfs (const grub_uint8_t *b, grub_size_t avail, grub_uint64_t *size)
{
	grub_uint32_t block_size = lost_le32 (b + 36);
	grub_uint64_t blocks = lost_le64 (b + 40);
	grub_uint64_t sum1 = 0, sum2 = 0;
	grub_size_t i;

	if (lost_le32 (b + 32) != 0x4253584e	/* "NXSB" */
		|| (lost_le32 (b + 24) & 0xffff) != 1	/* OBJECT_TYPE_NX_SUPERBLOCK */
		|| block_size < 4096 || block_size > 65536 || !lost_is_pow2 (block_size)
		|| block_size > avail || blocks == 0 || blocks >= (1ULL << 48)
		|| (grub_uint64_t) lost_le32 (b + 104) + lost_le32 (b + 108) > blocks)
		return 0;
	/* Fletcher-64 over the block after the checksum, then over the
	   checksum itself, comes out zero.  */
	for (i = 8; i < block_size + 8; i += 4)
	{
		sum1 = (sum1 + lost_le32 (b + (i < block_size ? i : i - block_size))) % 0xffffffff;
		sum2 = (sum2 + sum1) % 0xffffffff;
	}
	if (sum1 || sum2)
		return 0;
	*size = blocks * block_size;
	return 1;
}

/* refs.c test_ReFS, sized from the boot sector's sector count (TestDisk
   reports one sector) with the checks the GRUB ReFS driver applies.  */
int
lost_refs (const grub_uint8_t *bs, grub_uint64_t *size)
{
	grub_uint64_t sectors = lost_le64 (bs + 0x18);
	grub_uint32_t bps = lost_le32 (bs + 0x20);
	grub_uint64_t cluster = (grub_uint64_t) bps * lost_le32 (bs + 0x24);

	if (grub_memcmp (bs + 3, "ReFS", 4) != 0 || grub_memcmp (bs + 0x10, "FSRS", 4) != 0
		|| bps < 512 || bps > 4096 || !lost_is_pow2 (bps)
		|| cluster < 4096 || cluster > 65536 || !lost_is_pow2 (cluster)
		|| (bs[0x28] != 1 && bs[0x28] != 3)
		|| sectors == 0 || sectors >= (1ULL << 52))
		return 0;
	*size = sectors * bps;
	return 1;
}

/* f2fs.c test_f2fs/recover_f2fs, with the block size fields checked
   against each other.  */
int
lost_f2fs (const grub_uint8_t *sb, grub_uint64_t *size)
{
	grub_uint32_t log_sector = lost_le32 (sb + 8);
	grub_uint64_t blocks = lost_le64 (sb + 36);

	if (lost_le32 (sb) != 0xf2f52010
		|| lost_le32 (sb + 16) != 12	/* log_blocksize */
		|| log_sector < 9 || log_sector > 12
		|| log_sector + lost_le32 (sb + 12) != 12	/* log_sectors_per_block */
		|| blocks == 0 || blocks >= (1ULL << 52))
		return 0;
	*size = blocks << 12;
	return 1;
}

/* ufs.c test_ufs/recover_ufs: a UFS1 or UFS2 superblock in either byte
   order, found AT bytes into the filesystem (8 or 64 KiB, where either
   may be), with the block and fragment sizes checked against each other.
   fs_sblockloc, when set, must name AT, so that the same superblock is
   not also taken for one at the other offset; without it UFS1 is at
   8 KiB and UFS2 at 64 KiB.  */
const char *
lost_ufs (const grub_uint8_t *sb, grub_uint64_t at, grub_uint64_t *size)
{
	grub_uint64_t location;
	grub_uint32_t magic_le = lost_le32 (sb + 1372);
	grub_uint32_t magic_be = lost_be32 (sb + 1372);
	grub_uint32_t fsize, bsize;
	grub_uint64_t blocks;
	int be, ufs2;

	if (magic_le == 0x00011954 || magic_le == 0x19540119)
	{
		be = 0;
		ufs2 = magic_le == 0x19540119;
	}
	else if (magic_be == 0x00011954 || magic_be == 0x19540119)
	{
		be = 1;
		ufs2 = magic_be == 0x19540119;
	}
	else
		return NULL;
	fsize = be ? lost_be32 (sb + 52) : lost_le32 (sb + 52);
	bsize = be ? lost_be32 (sb + 48) : lost_le32 (sb + 48);
	if (ufs2)
		blocks = be ? lost_be64 (sb + 1080) : lost_le64 (sb + 1080);
	else
		blocks = be ? lost_be32 (sb + 36) : lost_le32 (sb + 36);
	location = be ? lost_be64 (sb + 1000) : lost_le64 (sb + 1000);
	if (location == LOST_UFS1_SB || location == LOST_UFS2_SB
		? location != at : at != (ufs2 ? LOST_UFS2_SB : LOST_UFS1_SB))
		return NULL;
	if (fsize < 512 || fsize > 4096 || !lost_is_pow2 (fsize)
		|| bsize < fsize || bsize > 65536 || !lost_is_pow2 (bsize) || bsize / fsize > 8
		|| (be ? lost_be32 (sb + 44) : lost_le32 (sb + 44)) == 0	/* cylinder groups */
		|| blocks == 0 || blocks >= (1ULL << 52))
		return NULL;
	*size = blocks * fsize;
	return ufs2 ? "ufs2" : "ufs";
}

/* jfs.c test_JFS/recover_JFS, with the physical block size checked: the
   size adds the inline log and fsck work areas to the aggregate.  */
int
lost_jfs (const grub_uint8_t *sb, grub_uint64_t *size)
{
	grub_uint32_t bsize = lost_le32 (sb + 16);
	grub_uint32_t pbsize = lost_le32 (sb + 24);
	grub_uint64_t blocks = lost_le64 (sb + 8);

	if (grub_memcmp (sb, "JFS1", 4) != 0
		|| bsize < 512 || bsize > 4096 || !lost_is_pow2 (bsize)
		|| pbsize < 512 || pbsize > 4096 || !lost_is_pow2 (pbsize)
		|| blocks == 0 || blocks >= (1ULL << 50))
		return 0;
	/* s_logpxd and s_fsckpxd: 24-bit lengths in aggregate blocks.  */
	*size = blocks * pbsize + (grub_uint64_t) bsize
		* ((lost_le32 (sb + 72) & 0xffffff) + (lost_le32 (sb + 80) & 0xffffff));
	return 1;
}

/* rfs.c test_rfs/recover_rfs, ReiserFS 3.x only.  */
int
lost_reiserfs (const grub_uint8_t *sb, grub_uint64_t *size)
{
	grub_uint32_t blocks = lost_le32 (sb);
	grub_uint16_t block_size = lost_le16 (sb + 0x2c);
	grub_uint16_t oid_max = lost_le16 (sb + 0x2e);
	grub_uint16_t state = lost_le16 (sb + 0x32);

	if ((grub_memcmp (sb + 0x34, "ReIsErFs", 9) != 0
			&& grub_memcmp (sb + 0x34, "ReIsEr2Fs", 10) != 0
			&& grub_memcmp (sb + 0x34, "ReIsEr3Fs", 10) != 0)
		|| blocks < lost_le32 (sb + 4) || blocks < 100
		|| (state != 1 && state != 2)
		|| oid_max % 2 || oid_max < lost_le16 (sb + 0x30)
		|| (block_size != 4096 && block_size != 8192))
		return 0;
	*size = (grub_uint64_t) blocks * block_size;
	return 1;
}

/* iso.c test_ISO/set_ISO_info: the primary volume descriptor, sized by
   its volume space and block size, whose two byte orders must agree.  */
int
lost_iso (const grub_uint8_t *pvd, grub_uint64_t *size)
{
	static const grub_uint8_t id[] = { 1, 'C', 'D', '0', '0', '1', 1 };
	grub_uint32_t blocks = lost_le32 (pvd + 80);
	grub_uint16_t block_size = lost_le16 (pvd + 128);

	if (grub_memcmp (pvd, id, sizeof (id)) != 0
		|| blocks != lost_be32 (pvd + 84) || block_size != lost_be16 (pvd + 130)
		|| block_size < 512 || block_size > 2048 || !lost_is_pow2 (block_size)
		|| blocks <= 16)
		return 0;
	*size = (grub_uint64_t) blocks * block_size;
	return 1;
}

/* ECMA-167 2/9: a volume recognition sequence at 32 KiB with BEA01
   followed by NSR02 or NSR03, after any ISO9660 descriptors.  */
int
lost_udf_vrs (const grub_uint8_t *buf, unsigned int sector_size)
{
	grub_size_t step = sector_size > 2048 ? sector_size : 2048;
	grub_size_t at;
	int extended = 0;

	for (at = LOST_VRS; at + 6 <= LOST_WINDOW; at += step)
	{
		const grub_uint8_t *id = buf + at + 1;

		if (grub_memcmp (id, "BEA01", 5) == 0)
			extended = 1;
		else if (extended && (grub_memcmp (id, "NSR02", 5) == 0 || grub_memcmp (id, "NSR03", 5) == 0))
			return 1;
		else if (grub_memcmp (id, "CD001", 5) != 0 && grub_memcmp (id, "BOOT2", 5) != 0)
			return 0;
	}
	return 0;
}

/* An ECMA-167 descriptor tag with identifier IDENT, located at LOCATION,
   whose checksum is right.  */
int
lost_udf_tag (const grub_uint8_t *tag, grub_uint16_t ident, grub_uint32_t location)
{
	grub_uint8_t sum = 0;
	unsigned int i;

	for (i = 0; i < 16; i++)
		if (i != 4)
			sum = (grub_uint8_t) (sum + tag[i]);
	return sum == tag[4] && lost_le16 (tag) == ident && lost_le32 (tag + 12) == location;
}

/* parti386.c recover_i386_logical: an extended boot record, entry 0 a
   logical partition relative to it and entry 1 empty or a link.  */
int
lost_ebr (const grub_uint8_t *b, grub_uint32_t *start, grub_uint32_t *count)
{
	const grub_uint8_t *e0 = b + 0x1be;
	const grub_uint8_t *e1 = e0 + 16;
	unsigned int i;

	if (lost_le16 (b + 0x1fe) != 0xaa55 || (e0[0] & 0x7f) || (e1[0] & 0x7f))
		return 0;
	for (i = 32; i < 64; i++)
		if (e0[i])
			return 0;
	/* 0xee: the protective MBR of a GPT disk.  */
	if (e0[4] == 0 || e0[4] == 0x05 || e0[4] == 0x0f || e0[4] == 0x85 || e0[4] == 0xee
		|| (e1[4] && e1[4] != 0x05 && e1[4] != 0x0f && e1[4] != 0x85))
		return 0;
	*start = lost_le32 (e0 + 8);
	*count = lost_le32 (e0 + 12);
	return *start && *count;
}
