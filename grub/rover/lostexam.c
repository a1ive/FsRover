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
 * What lies at one offset of the lost partition search: a filesystem
 * starting there, or one found there through a backup boot sector or
 * superblock copy.
 *
 * Deviations from TestDisk: backups are looked for next to every
 * candidate offset, including the XFS allocation group copies (told
 * apart by the AGF sequence number), the Btrfs mirrors (by their
 * bytenr) and the JFS secondary superblock; a result found through a
 * backup carries the remaps that open it with the backup in place of its
 * primary (lostdisk), where TestDisk only reports it; a backup met before
 * its volume's start is checked against the primary, and reported as a
 * plain find when the primary is intact; UDF is sized from the anchor's
 * partition descriptor.
 */

#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>

#include "lostint.h"

/* UDF at S: the anchor volume descriptor pointer at block 256 (blocks
   of the device's sector size up to 4 KiB), then the partition
   descriptor in the main volume descriptor sequence.  The size reaches
   the end of the partition.  */
static int
lost_udf (struct rover_lost_scan *scan, grub_uint64_t s, grub_uint64_t *size)
{
	grub_uint8_t *aux = scan->aux;
	grub_uint64_t bs;

	for (bs = scan->sector_size; bs <= 4096; bs <<= 1)
	{
		grub_uint32_t length, location, i;
		grub_uint64_t end = 257;

		if (s + 257 * bs > scan->size || lost_read (scan, s + 256 * bs, 512, aux)
			|| !lost_udf_tag (aux, 2, 256))
			continue;
		length = lost_le32 (aux + 16);
		location = lost_le32 (aux + 20);
		if (length > LOST_AUX)
			length = LOST_AUX;
		length -= length % (grub_uint32_t) bs;
		if (!length || s + (location + 1ULL) * bs + length > scan->size
			|| lost_read (scan, s + location * bs, length, aux))
			continue;
		for (i = 0; i * bs < length; i++)
		{
			const grub_uint8_t *desc = aux + i * bs;

			if (lost_udf_tag (desc, 8, location + i))	/* terminating */
				break;
			if (lost_udf_tag (desc, 5, location + i))	/* partition */
			{
				grub_uint64_t pend = (grub_uint64_t) lost_le32 (desc + 188) + lost_le32 (desc + 192);

				if (pend > end)
					end = pend;
			}
		}
		*size = end * bs;
		return 1;
	}
	return 0;
}

/* Is the primary boot sector or superblock of HIT, a filesystem found
   through a backup, intact after all and the same filesystem?  A
   backup at the end of a volume or in a later group can be met before
   the volume's start is.  */
int
lost_primary_ok (struct rover_lost_scan *scan, const struct lost_hit *hit)
{
	grub_uint8_t *buf = scan->buf;
	grub_uint64_t size, sb_offset, ag_size;
	unsigned int bps, shift, sector;
	const char *type;
	grub_size_t len;

	len = (grub_size_t) (scan->size - hit->start < LOST_WINDOW ? scan->size - hit->start : LOST_WINDOW);
	if (lost_read (scan, hit->start, len, buf))
		return 0;
	if (len < LOST_WINDOW)
		grub_memset (buf + len, 0, LOST_WINDOW - len);
	if (grub_strcmp (hit->type, "ntfs") == 0)
		return lost_ntfs (buf, &size, &bps) && size == hit->size;
	if (grub_strcmp (hit->type, "exfat") == 0)
		return lost_exfat (buf, &shift, &size) && size == hit->size;
	if (grub_strcmp (hit->type, "xfs") == 0)
		return lost_xfs (buf, &size, &ag_size, &sector) && size == hit->size
			&& (lost_be32 (buf + sector) != 0x58414746 || lost_be32 (buf + sector + 8) == 0);
	if (grub_strcmp (hit->type, "btrfs") == 0)
		return lost_btrfs (buf + LOST_BTRFS_SB, &size, &sb_offset)
			&& sb_offset == LOST_BTRFS_SB && size == hit->size;
	if (grub_strcmp (hit->type, "jfs") == 0)
		return lost_jfs (buf + LOST_JFS_SB, &size) && size == hit->size;
	if ((type = lost_ext (buf + LOST_SB_1K, &size, &sb_offset)) != NULL)
		return sb_offset == LOST_SB_1K && size == hit->size && grub_strcmp (type, hit->type) == 0;
	if ((type = lost_hfs (buf + LOST_SB_1K, &size)) != NULL)
		return size == hit->size && grub_strcmp (type, hit->type) == 0;
	type = lost_fat (buf, scan->sector_size, &size);
	return type && size == hit->size && grub_strcmp (type, hit->type) == 0;
}

int
lost_set_hit (struct lost_hit *hit, grub_uint64_t start, grub_uint64_t size,
	const char *type, int backup)
{
	hit->start = start;
	hit->size = size;
	hit->type = type;
	hit->backup = backup;
	hit->remap_count = 0;
	return 1;
}

/* Read LENGTH bytes at TARGET of HIT's window from SOURCE.  */
static int
lost_remap (struct lost_hit *hit, grub_uint64_t target, grub_uint64_t source,
	grub_uint64_t length)
{
	if (hit->remap_count < ROVER_LOST_REMAP_MAX)
	{
		hit->remap[hit->remap_count].target = target;
		hit->remap[hit->remap_count].source = source;
		hit->remap[hit->remap_count].length = length;
		hit->remap_count++;
	}
	return 1;
}

/* An ext superblock copy SB_OFFSET into the filesystem stands in for
   the primary at 1 KiB, and the group descriptor table after it for the
   primary one -- unless META_BG spreads the descriptors over the groups.  */
static int
lost_ext_remap (struct lost_hit *hit, const grub_uint8_t *sb, grub_uint64_t sb_offset)
{
	grub_uint32_t incompat = lost_le32 (sb + 0x60);
	grub_uint64_t bs = 1024ULL << lost_le32 (sb + 0x18);
	grub_uint64_t first = lost_le32 (sb + 0x14);
	grub_uint64_t per_group = lost_le32 (sb + 0x20);
	grub_uint64_t blocks = lost_le32 (sb + 0x04);
	grub_uint64_t desc = 32, table;

	lost_remap (hit, LOST_SB_1K, sb_offset, LOST_EXT_SB_SIZE);
	if (incompat & 0x10)	/* META_BG */
		return 1;
	if (incompat & 0x80)	/* 64BIT */
	{
		blocks |= (grub_uint64_t) lost_le32 (sb + 0x150) << 32;
		desc = lost_le16 (sb + 0xfe);
	}
	if (desc < 32 || desc > bs || !lost_is_pow2 (desc) || blocks <= first)
		return 1;
	table = lost_round_up ((blocks - first + per_group - 1) / per_group * desc, bs);
	if (table < per_group * bs)
		lost_remap (hit, (first + 1) * bs, (sb_offset / bs + 1) * bs, table);
	return 1;
}

/* Filesystems whose volume ends at S: the NTFS backup boot sector in
   the last device sector, the HFS/HFS+ alternate header 1 KiB before.  */
unsigned int
lost_tail_len (const struct rover_lost_scan *scan)
{
	return scan->sector_size > LOST_SB_1K ? scan->sector_size : LOST_SB_1K;
}

/* END points just past the lost_tail_len() bytes before S.  */
int
lost_examine_end (struct rover_lost_scan *scan, grub_uint64_t s, const grub_uint8_t *end,
	struct lost_hit *hits)
{
	unsigned int ss = scan->sector_size;
	unsigned int len = lost_tail_len (scan);
	const grub_uint8_t *tail = end - len;
	grub_uint64_t size;
	const char *type;
	unsigned int bps;
	int n = 0;

	/* ntfs.c search_NTFS_backup, for NTFS sectors of the device's size.  */
	if (lost_ntfs (tail + len - ss, &size, &bps) && bps == ss && size <= s)
	{
		lost_set_hit (&hits[n], s - size, size, "ntfs", 1);
		n += lost_remap (&hits[n], 0, size - bps, bps);
	}
	/* analyse.c search_HFS_backup.  */
	type = lost_hfs (tail + len - LOST_SB_1K, &size);
	if (type && size <= s && (s - size) % ss == 0)
	{
		lost_set_hit (&hits[n], s - size, size, type, 1);
		n += lost_remap (&hits[n], LOST_SB_1K, size - LOST_SB_1K, 512);
	}
	return n;
}

/* Filesystems starting at S, or found at S through a superblock copy.
   BUF holds the LOST_WINDOW bytes from S, of which LEN are on the device
   and the rest zeros.  POSITIONAL also looks for the backups found by
   their distance from the start.  */
int
lost_examine (struct rover_lost_scan *scan, grub_uint64_t s, const grub_uint8_t *buf,
	grub_size_t len, int positional, struct lost_hit *hit)
{
	unsigned int ss = scan->sector_size;
	grub_uint64_t size, sb_offset, ag_size;
	const char *type;
	unsigned int shift, bps, xfs_sector;
	grub_uint32_t ebr_start, ebr_count;

	/* analyse.c search_type_2: superblocks at 1 KiB.  */
	type = lost_ext (buf + LOST_SB_1K, &size, &sb_offset);
	if (type && sb_offset == LOST_SB_1K)
		return lost_set_hit (hit, s, size, type, 0);
	/* A superblock copy of a later block group where a primary would
	   be: 1 KiB blocks keep it 1 KiB into the group, larger blocks at
	   the group start.  Both lie in the window, unlike the group 3
	   copy of ROVER_LOST_SCAN_EXT_BACKUP.  */
	if (type && sb_offset <= s + LOST_SB_1K && (s + LOST_SB_1K - sb_offset) % ss == 0)
	{
		lost_set_hit (hit, s + LOST_SB_1K - sb_offset, size, type, 1);
		return lost_ext_remap (hit, buf + LOST_SB_1K, sb_offset);
	}
	type = lost_ext (buf, &size, &sb_offset);
	if (type && lost_le32 (buf + 0x18) > 0 && lost_le16 (buf + 0x5a) != 0
		&& sb_offset <= s && (s - sb_offset) % ss == 0)
	{
		lost_set_hit (hit, s - sb_offset, size, type, 1);
		return lost_ext_remap (hit, buf, sb_offset);
	}
	if ((type = lost_hfs (buf + LOST_SB_1K, &size)) != NULL)
		return lost_set_hit (hit, s, size, type, 0);
	if (lost_f2fs (buf + LOST_SB_1K, &size))
		return lost_set_hit (hit, s, size, "f2fs", 0);

	/* analyse.c search_type_0: boot sectors and superblocks at 0.  */
	if (lost_apfs (buf, len, &size))
		return lost_set_hit (hit, s, size, "apfs", 0);
	if ((type = lost_fat (buf, ss, &size)) != NULL)
		return lost_set_hit (hit, s, size, type, 0);
	if (lost_exfat (buf, &shift, &size))
		return lost_set_hit (hit, s, size, "exfat", 0);
	if (lost_ntfs (buf, &size, &bps))
		return lost_set_hit (hit, s, size, "ntfs", 0);
	if (lost_refs (buf, &size))
		return lost_set_hit (hit, s, size, "refs", 0);
	if (lost_xfs (buf, &size, &ag_size, &xfs_sector))
	{
		/* Every allocation group starts with a superblock copy; the
		   AGF that follows it numbers the group.  */
		grub_uint64_t group = 0;

		if (lost_be32 (buf + xfs_sector) == 0x58414746)	/* "XAGF" */
			group = lost_be32 (buf + xfs_sector + 8);
		if (group <= s / ag_size && (s - group * ag_size) % ss == 0)
		{
			lost_set_hit (hit, s - group * ag_size, size, "xfs", group != 0);
			if (group)
				lost_remap (hit, 0, group * ag_size, xfs_sector);
			return 1;
		}
	}

	/* analyse.c search_type_128: Btrfs at 64 KiB, or one of its mirrors
	   at the candidate itself.  */
	if (lost_btrfs (buf + LOST_BTRFS_SB, &size, &sb_offset))
	{
		if (sb_offset == LOST_BTRFS_SB)
			return lost_set_hit (hit, s, size, "btrfs", 0);
	}
	else if (lost_btrfs (buf, &size, &sb_offset) && sb_offset <= s && (s - sb_offset) % ss == 0)
	{
		lost_set_hit (hit, s - sb_offset, size, "btrfs", sb_offset != LOST_BTRFS_SB);
		if (sb_offset != LOST_BTRFS_SB)
			lost_remap (hit, LOST_BTRFS_SB, sb_offset, LOST_BTRFS_SB_SIZE);
		return 1;
	}

	/* analyse.c search_type_16/64/128: UFS at 8 KiB, JFS at 32 KiB,
	   ReiserFS and UFS2 at 64 KiB.  */
	if ((type = lost_ufs (buf + LOST_UFS1_SB, LOST_UFS1_SB, &size)) != NULL
		|| (type = lost_ufs (buf + LOST_UFS2_SB, LOST_UFS2_SB, &size)) != NULL)
		return lost_set_hit (hit, s, size, type, 0);
	if (lost_jfs (buf + LOST_JFS_SB, &size))
		return lost_set_hit (hit, s, size, "jfs", 0);
	if (lost_reiserfs (buf + LOST_REISERFS_SB, &size))
		return lost_set_hit (hit, s, size, "reiserfs", 0);

	/* Volume descriptors at 32 KiB: UDF (also on an ISO9660/UDF bridge
	   disc), else ISO9660.  */
	if (lost_udf_vrs (buf, ss) && lost_udf (scan, s, &size))
		return lost_set_hit (hit, s, size, "udf", 0);
	if (lost_iso (buf + LOST_VRS, &size))
		return lost_set_hit (hit, s, size, "iso9660", 0);

	/* parti386.c: an extended boot record; its logical partition joins
	   the table entries.  */
	if (lost_ebr (buf, &ebr_start, &ebr_count))
	{
		if (lost_add_table (scan, s + (grub_uint64_t) ebr_start * ss, (grub_uint64_t) ebr_count * ss))
			return -1;
		return 0;
	}

	if (!positional)
		return 0;

	/* analyse.c search_FAT_backup / search_exFAT_backup, and the second
	   F2FS superblock in block 1.  */
	type = lost_fat (buf + 6 * ss, ss, &size);
	if (type && grub_strcmp (type, "fat32") == 0 && lost_le16 (buf + 6 * ss + 0x32) == 6)
	{
		/* Boot sector, FSInfo and the third boot sector.  */
		lost_set_hit (hit, s, size, type, 1);
		return lost_remap (hit, 0, 6 * ss, 3 * ss);
	}
	for (shift = 9; shift <= 12; shift++)
	{
		unsigned int got;

		if ((1U << shift) >= ss && lost_exfat (buf + (12U << shift), &got, &size) && got == shift)
		{
			/* The whole 12-sector boot region, checksum included.  */
			lost_set_hit (hit, s, size, "exfat", 1);
			return lost_remap (hit, 0, 12U << shift, 12U << shift);
		}
	}
	if (lost_f2fs (buf + 4096 + LOST_SB_1K, &size))
		return lost_set_hit (hit, s, size, "f2fs", 1);
	/* The secondary JFS superblock.  */
	if (lost_jfs (buf + LOST_JFS_SB2, &size))
	{
		lost_set_hit (hit, s, size, "jfs", 1);
		return lost_remap (hit, LOST_JFS_SB, LOST_JFS_SB2, LOST_JFS_SB_SIZE);
	}

	/* godmode.c test_nbr 5: the ext superblock copy in block group 3,
	   for 1, 2 and 4 KiB blocks with the default blocks per group.  */
	if ((scan->flags & ROVER_LOST_SCAN_EXT_BACKUP) && !(scan->flags & ROVER_LOST_SCAN_DEEP))
	{
		grub_uint8_t *aux = scan->aux;
		unsigned int log_bs;

		for (log_bs = 0; log_bs <= 2; log_bs++)
		{
			grub_uint64_t bs = 1024ULL << log_bs;
			grub_uint64_t at = s + 3 * bs * 8 * bs + (log_bs ? 0 : LOST_SB_1K);

			if (at + LOST_EXT_SB_SIZE > scan->size || lost_read (scan, at, LOST_EXT_SB_SIZE, aux))
				continue;
			type = lost_ext (aux, &size, &sb_offset);
			if (type && lost_le16 (aux + 0x5a) != 0 && sb_offset <= at
				&& (at - sb_offset) % ss == 0)
			{
				lost_set_hit (hit, at - sb_offset, size, type, 1);
				return lost_ext_remap (hit, aux, sb_offset);
			}
		}
	}
	return 0;
}
