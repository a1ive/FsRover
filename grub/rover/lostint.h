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
 * Internal interface of the lost partition search, shared by lostpart.c
 * (scan engine and API), lostexam.c (what lies at one offset),
 * losttable.c (partition table entries) and lostfs.c (boot sector and
 * superblock tests).  The public interface is in rover.h.
 */

#ifndef ROVER_LOSTINT_H
#define ROVER_LOSTINT_H	1

#include <grub/disk.h>
#include <grub/types.h>

#include "rover.h"

#define LOST_MIB	(1ULL << 20)
/* CHS layout of the partitioning tools TestDisk accounts for: 63
   sectors per track, 255 heads.  */
#define LOST_TRACK	(63ULL * 512)
#define LOST_CYLINDER	(255ULL * LOST_TRACK)
/* Bytes read at a candidate: the boot sectors and superblocks up to
   the Btrfs one at 64 KiB, and the FAT32 / exFAT / F2FS backups for
   sector sizes up to 4096.  */
#define LOST_WINDOW	(65536 + 4096)
/* Bytes read before a candidate: NTFS backup boot sector (one device
   sector) and HFS/HFS+ alternate header (1 KiB before the end).  */
#define LOST_TAIL	4096
#define LOST_SB_1K	1024
#define LOST_EXT_SB_SIZE	1024
#define LOST_BTRFS_SB	65536
#define LOST_BTRFS_SB_SIZE	4096
#define LOST_GPT_MAX_ENTRIES	4096
#define LOST_UFS1_SB	8192
#define LOST_UFS2_SB	65536
#define LOST_JFS_SB	0x8000
#define LOST_JFS_SB2	0xf000
#define LOST_JFS_SB_SIZE	4096
#define LOST_REISERFS_SB	65536
#define LOST_VRS	32768	/* ISO9660 / UDF volume descriptors */
/* Scratch for reads beyond the window (UDF anchor and descriptors, ext
   group 3 superblock).  */
#define LOST_AUX	65536
/* Bytes read at a time by the deep search.  */
#define LOST_DEEP_CHUNK	(4ULL << 20)

struct lost_range
{
	grub_uint64_t start;
	grub_uint64_t end;
	int readable;
};

struct lost_found
{
	grub_uint64_t start;
	grub_uint64_t size;
	const char *type;
};

/* A partition table entry GRUB does not use.  */
struct lost_table
{
	grub_uint64_t start;
	grub_uint64_t size;
	int claimed;
};

/* A range the quick search stepped over, and whether to search it
   after all.  */
enum lost_skip_state
{
	LOST_SKIP_PASSED,
	LOST_SKIP_QUEUED,
	LOST_SKIP_DONE,
};

struct lost_skip
{
	grub_uint64_t from;
	grub_uint64_t to;
	enum lost_skip_state state;
};

struct lost_hit
{
	grub_uint64_t start;
	grub_uint64_t size;
	const char *type;
	int backup;
	struct rover_lost_remap remap[ROVER_LOST_REMAP_MAX];
	unsigned int remap_count;
};

struct rover_lost_scan
{
	grub_disk_t disk;
	grub_uint64_t size;
	unsigned int sector_size;
	unsigned int flags;
	grub_uint64_t pos;
	grub_uint64_t limit;	/* end of the current pass */
	int done;
	int rescanning;
	int finishing;
	int base_readable;
	struct lost_range *ranges;
	grub_size_t nranges;
	grub_uint64_t *hints;
	grub_size_t nhints;
	grub_size_t hints_alloc;
	struct lost_found *found;
	grub_size_t nfound;
	grub_size_t found_alloc;
	struct lost_table *tables;
	grub_size_t ntables;
	grub_size_t tables_alloc;
	grub_size_t next_table;
	struct lost_skip *skips;
	grub_size_t nskips;
	grub_size_t skips_alloc;
	/* Deep search: hits kept until the end.  */
	struct lost_hit *pending;
	grub_size_t npending;
	grub_size_t pending_alloc;
	grub_size_t next_pending;
	int pending_ready;
	grub_uint8_t *deep;
	grub_uint8_t *aux;
	grub_uint8_t *buf;
	grub_uint8_t *tail;
};

static inline grub_uint16_t
lost_le16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) (p[0] | (p[1] << 8));
}

static inline grub_uint32_t
lost_le32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8)
		| ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

static inline grub_uint64_t
lost_le64 (const grub_uint8_t *p)
{
	return (grub_uint64_t) lost_le32 (p) | ((grub_uint64_t) lost_le32 (p + 4) << 32);
}

static inline grub_uint16_t
lost_be16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) ((p[0] << 8) | p[1]);
}

static inline grub_uint32_t
lost_be32 (const grub_uint8_t *p)
{
	return ((grub_uint32_t) p[0] << 24) | ((grub_uint32_t) p[1] << 16)
		| ((grub_uint32_t) p[2] << 8) | (grub_uint32_t) p[3];
}

static inline grub_uint64_t
lost_be64 (const grub_uint8_t *p)
{
	return ((grub_uint64_t) lost_be32 (p) << 32) | lost_be32 (p + 4);
}

static inline int
lost_is_pow2 (grub_uint64_t v)
{
	return v && !(v & (v - 1));
}

static inline grub_uint64_t
lost_round_up (grub_uint64_t v, grub_uint64_t align)
{
	return (v + align - 1) / align * align;
}

/* lostfs.c: boot sector and superblock tests on byte buffers.  */
grub_uint32_t lost_crc32 (const grub_uint8_t *p, grub_size_t len);
int lost_ntfs (const grub_uint8_t *bs, grub_uint64_t *size, unsigned int *bps);
const char *lost_fat (const grub_uint8_t *bs, unsigned int sector_size, grub_uint64_t *size);
int lost_exfat (const grub_uint8_t *bs, unsigned int *shift, grub_uint64_t *size);
const char *lost_ext (const grub_uint8_t *sb, grub_uint64_t *size, grub_uint64_t *sb_offset);
int lost_xfs (const grub_uint8_t *sb, grub_uint64_t *size, grub_uint64_t *ag_size,
	unsigned int *sector_size);
int lost_btrfs (const grub_uint8_t *sb, grub_uint64_t *size, grub_uint64_t *bytenr);
const char *lost_hfs (const grub_uint8_t *b, grub_uint64_t *size);
int lost_apfs (const grub_uint8_t *b, grub_size_t avail, grub_uint64_t *size);
int lost_refs (const grub_uint8_t *bs, grub_uint64_t *size);
int lost_f2fs (const grub_uint8_t *sb, grub_uint64_t *size);
const char *lost_ufs (const grub_uint8_t *sb, grub_uint64_t at, grub_uint64_t *size);
int lost_jfs (const grub_uint8_t *sb, grub_uint64_t *size);
int lost_reiserfs (const grub_uint8_t *sb, grub_uint64_t *size);
int lost_iso (const grub_uint8_t *pvd, grub_uint64_t *size);
int lost_udf_vrs (const grub_uint8_t *buf, unsigned int sector_size);
int lost_udf_tag (const grub_uint8_t *tag, grub_uint16_t ident, grub_uint32_t location);
int lost_ebr (const grub_uint8_t *b, grub_uint32_t *start, grub_uint32_t *count);

/* lostexam.c: what lies at one offset.  */
int lost_primary_ok (struct rover_lost_scan *scan, const struct lost_hit *hit);
int lost_set_hit (struct lost_hit *hit, grub_uint64_t start, grub_uint64_t size,
	const char *type, int backup);
unsigned int lost_tail_len (const struct rover_lost_scan *scan);
int lost_examine_end (struct rover_lost_scan *scan, grub_uint64_t s, const grub_uint8_t *end,
	struct lost_hit *hits);
int lost_examine (struct rover_lost_scan *scan, grub_uint64_t s, const grub_uint8_t *buf,
	grub_size_t len, int positional, struct lost_hit *hit);

/* losttable.c: partition table entries GRUB does not use.  */
int lost_add_table (struct rover_lost_scan *scan, grub_uint64_t start, grub_uint64_t size);
int lost_gpt (struct rover_lost_scan *scan, grub_uint64_t lba_size, grub_uint64_t lba);

/* lostpart.c: device reads, search hints, stepped-over ranges.  */
int lost_read (struct rover_lost_scan *scan, grub_uint64_t offset, grub_size_t len, void *buf);
int lost_add_hint (struct rover_lost_scan *scan, grub_uint64_t offset);
int lost_add_end_hints (struct rover_lost_scan *scan, grub_uint64_t end);
void lost_conflict (struct rover_lost_scan *scan, grub_uint64_t start);

#endif
