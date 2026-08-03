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
 * DiskGenius partition backup images (.pmf) taken in one of the two
 * sector modes, presented as the partition they hold.  The same
 * container in its third, file-by-file mode is a filesystem of its own
 * and is left to grub-core\fs\pmf.c.
 *
 * A .pmf opens with a "VIMG" header; the backup mode is a u32 at +0x27f,
 * 4 for every sector and 1 for the used ones only.  The stored bytes are
 * one flat stream, cut into blocks of at most 64 MiB, each headed by
 *
 *	u32 plaintext length, u32 stored length, then the payload
 *
 * deflated, stored verbatim when the two lengths match, or written with
 * the LZ77 codec of grub-core\lib\dgcomp.c.  The chain starts at 0x600
 * and runs to the end of the file.
 *
 * In "all sectors" mode the stream simply is the partition.
 *
 * In "used sectors" mode the stream holds only the clusters the source
 * filesystem had in use, in ascending cluster order, so rebuilding the
 * partition means knowing which those were.  How the stream says so
 * depends on the filesystem it came from:
 *
 *	FAT12/16/32	a u32 at 0x600 counts the sectors stored verbatim
 *			at the front -- the reserved area and the first FAT
 *			-- and the chain starts at 0x604.  The FAT is the
 *			map; the further FATs are not stored, being copies
 *			of the first.
 *	exFAT		the same u32 and the same verbatim head, covering
 *			the boot region and the FAT.  A thirteen byte
 *			record then sits between two chain blocks, naming
 *			the length of the allocation bitmap that follows;
 *			the bitmap, padded to a sector, is the map.
 *	NTFS		no verbatim head and no leading u32: the chain
 *			starts at 0x600 and opens with the cluster bitmap.
 *	ext4		the same u32, the head covering the boot block and
 *			the superblock.  The group descriptors follow --
 *			as they are, not padded to a block -- and then the
 *			block bitmap of every group that has one.  A group
 *			flagged BLOCK_UNINIT keeps none, since ext4 keeps
 *			none either; what it has in use is the metadata at
 *			its front, as long as its free count says.
 *
 * Unallocated clusters, and anything the head does not reach, read back
 * as zeros.  A backup of any other filesystem is left alone rather than
 * presented wrongly.
 *
 * A backup written with compression turned off has no block chain at
 * all: the stream simply is the rest of the file.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/fat.h>
#include <grub/dgcomp.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define PMF_MAGIC		"VIMG"
#define PMF_HDR_MODE		0x27f	/* u32 */

#define PMF_MODE_DATA		1	/* used sectors only */
#define PMF_MODE_FILE		2	/* file by file, see fs\pmf.c */
#define PMF_MODE_ALL		4	/* every sector */

/* Where the block chain starts, and the u32 in front of it that the
   "used sectors" mode adds.  */
#define PMF_STREAM_OFF		0x600
#define PMF_META_SECTORS	0x600	/* u32, "used sectors" mode only */
#define PMF_BLOCK_HDR		8

/* The filesystem the backup came from, as its name at 0x0c spells it.  */
#define PMF_HDR_FS		0x0c
#define PMF_HDR_SECTORS		0x5b	/* u32, sectors in the partition */
#define PMF_HDR_BPS		0x6b	/* u32, bytes per sector */
#define PMF_HDR_SPC		0x6f	/* u32, sectors per cluster */

/* ext4, as its superblock and group descriptors spell it.  */
#define PMF_E4_SB		1024	/* where the superblock sits */
#define PMF_E4_MAGIC		0xef53
#define PMF_E4_BLOCKS		0x04	/* u32 */
#define PMF_E4_FIRST		0x14	/* u32 first data block */
#define PMF_E4_LOG_BS		0x18	/* u32, block size is 1024 << this */
#define PMF_E4_BPG		0x20	/* u32 blocks per group */
#define PMF_E4_MAGIC_OFF	0x38	/* u16 */
#define PMF_E4_DESC_SIZE	0xfe	/* u16, 32 when the field is zero */
#define PMF_E4_GD_FREE		0x0c	/* u16 free blocks in the group */
#define PMF_E4_GD_FLAGS		0x12	/* u16 */
#define PMF_E4_BG_BLOCK_UNINIT	0x0002
#define PMF_E4_GROUPS_MAX	(1u << 20)

/* The record exFAT puts in front of its allocation bitmap: a zero byte,
   a kind, the bitmap's length and a zero.  */
#define PMF_BITMAP_REC		13
#define PMF_BITMAP_KIND		2

/* Sanity caps against a corrupt or hostile image.  */
#define PMF_BLOCK_MAX		(64u << 20)
#define PMF_BLOCKS_MAX		(1u << 20)
#define PMF_PART_MAX		((grub_uint64_t) 1 << 46)
#define PMF_CLUSTERS_MAX	(1u << 28)

/* Clusters per entry of the running allocated-cluster count.  A lookup
   scans at most this many bits of the allocation bitmap.  */
#define PMF_RANK_SHIFT		12
#define PMF_RANK_GROUP		(1u << PMF_RANK_SHIFT)

struct pmf_block
{
	grub_uint64_t soff;	/* where the block starts in the stream */
	grub_uint64_t foff;	/* where its payload sits in the image */
	grub_uint32_t dlen;
	grub_uint32_t clen;
};

struct pmf_image
{
	grub_file_t file;
	grub_uint64_t size;	/* bytes of the partition this exposes */
	grub_uint64_t stream;	/* bytes the stream holds */

	struct pmf_block *blk;
	grub_uint32_t nblocks;

	grub_uint8_t *cache;	/* the block the previous read landed in */
	grub_uint32_t cache_len;
	grub_uint32_t cached;
	int have_cache;

	/* A backup with compression off keeps no chain: the stream is the
	   rest of the image, from here.  */
	grub_uint64_t raw_off;

	/* "used sectors" mode.  */
	int sparse;
	grub_uint32_t bps;
	grub_uint32_t spc;		/* sectors per cluster */
	grub_uint32_t meta_sectors;	/* stored verbatim at the front */
	grub_uint32_t first_lba;	/* sector the first cluster lands on */
	grub_uint64_t data_off;		/* where its bytes start in the stream */
	grub_uint32_t nclusters;
	grub_uint8_t *alloc;		/* one bit per cluster */
	grub_uint64_t *rank;		/* allocated clusters below each group */
	grub_uint32_t nranks;
	/* FAT only: the further FATs mirror the stored one.  */
	grub_uint32_t reserved;		/* sectors before the first FAT */
	grub_uint32_t fat_size;		/* sectors in one FAT */
	grub_uint32_t fat_end;		/* first sector past the last FAT */
};

static grub_err_t
pmf_pread (struct pmf_image *img, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;
	grub_uint64_t size = grub_file_size (img->file);

	if (off > size || len > size - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "pmf image truncated");
	if (grub_file_seek (img->file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (img->file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "pmf image truncated");
	return GRUB_ERR_NONE;
}

static void
pmf_free_image (struct pmf_image *img)
{
	grub_free (img->blk);
	grub_free (img->cache);
	grub_free (img->alloc);
	grub_free (img->rank);
	img->blk = NULL;
	img->cache = NULL;
	img->alloc = NULL;
	img->rank = NULL;
	img->have_cache = 0;
}

/* ---------------- the block stream ---------------- */

/* Walk the chain from START, noting where every block lands.  Stops
   once the stream holds UNTIL bytes, or at the end of the image when
   UNTIL is zero; *NEXT comes back with where it stopped reading.  */
static grub_err_t
pmf_scan_blocks (struct pmf_image *img, grub_uint64_t start,
		 grub_uint64_t until, grub_uint64_t *next)
{
	grub_uint64_t end = grub_file_size (img->file);
	grub_uint64_t off = start;
	grub_uint64_t soff = img->stream;
	grub_uint32_t cap = img->nblocks, biggest = img->cache_len;
	grub_err_t err;

	while (off + PMF_BLOCK_HDR <= end && (!until || soff < until))
	{
		grub_uint8_t hdr[PMF_BLOCK_HDR];
		grub_uint32_t dlen, clen;

		err = pmf_pread (img, off, hdr, sizeof (hdr));
		if (err)
			return err;
		dlen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr));
		clen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 4));
		if (dlen == 0 || dlen > PMF_BLOCK_MAX || clen == 0 || clen > dlen
			|| clen > end - off - PMF_BLOCK_HDR)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmf block at 0x%llx",
					   (unsigned long long) off);

		if (img->nblocks == cap)
		{
			struct pmf_block *bigger;

			cap = cap ? cap * 2 : 64;
			if (cap > PMF_BLOCKS_MAX)
				return grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many pmf blocks");
			bigger = grub_realloc (img->blk, (grub_size_t) cap * sizeof (*bigger));
			if (!bigger)
				return grub_errno;
			img->blk = bigger;
		}
		img->blk[img->nblocks].soff = soff;
		img->blk[img->nblocks].foff = off + PMF_BLOCK_HDR;
		img->blk[img->nblocks].dlen = dlen;
		img->blk[img->nblocks].clen = clen;
		img->nblocks++;

		if (dlen > biggest)
			biggest = dlen;
		soff += dlen;
		off += PMF_BLOCK_HDR + clen;
	}

	if (img->nblocks == 0 || soff == 0 || (until && soff != until))
		return grub_error (GRUB_ERR_BAD_DEVICE, "truncated pmf image");
	img->stream = soff;
	if (biggest > img->cache_len)
	{
		grub_uint8_t *bigger = grub_realloc (img->cache, biggest);

		if (!bigger)
			return grub_errno;
		img->cache = bigger;
		img->cache_len = biggest;
		img->have_cache = 0;
	}
	*next = off;
	return GRUB_ERR_NONE;
}

/* Take the stream from START: a chain of blocks, or, when a backup was
   written with compression off, the rest of the image as it lies.  */
static grub_err_t
pmf_open_stream (struct pmf_image *img, grub_uint64_t start)
{
	grub_uint64_t next;
	grub_err_t err = pmf_scan_blocks (img, start, 0, &next);

	if (!err)
		return GRUB_ERR_NONE;
	grub_errno = GRUB_ERR_NONE;
	img->nblocks = 0;
	img->have_cache = 0;
	if (grub_file_size (img->file) <= start)
		return grub_error (GRUB_ERR_BAD_DEVICE, "empty pmf image");
	img->raw_off = start;
	img->stream = grub_file_size (img->file) - start;
	return GRUB_ERR_NONE;
}

/* Index of the block holding stream offset OFF, or -1.  */
static grub_uint32_t
pmf_find_block (struct pmf_image *img, grub_uint64_t off)
{
	grub_uint32_t lo = 0, hi = img->nblocks;

	if (img->have_cache && img->blk[img->cached].soff <= off
		&& off - img->blk[img->cached].soff < img->blk[img->cached].dlen)
		return img->cached;
	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (img->blk[mid].soff <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0)
		return (grub_uint32_t) -1;
	return lo - 1;
}

/* Copy up to LEN bytes of the stream from OFF, stopping at the end of
   whichever block they start in.  */
static grub_err_t
pmf_stream_read (struct pmf_image *img, grub_uint64_t off, void *buf,
		 grub_size_t len, grub_size_t *got)
{
	struct pmf_block *b;
	grub_uint32_t nr;
	grub_uint64_t in;
	grub_size_t n;

	*got = 0;
	if (off >= img->stream)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past the end of the pmf stream");
	if (img->raw_off)
	{
		grub_err_t err;

		if (len > img->stream - off)
			len = (grub_size_t) (img->stream - off);
		err = pmf_pread (img, img->raw_off + off, buf, len);
		if (err)
			return err;
		*got = len;
		return GRUB_ERR_NONE;
	}
	nr = pmf_find_block (img, off);
	if (nr == (grub_uint32_t) -1)
		return grub_error (GRUB_ERR_BAD_DEVICE, "unmapped pmf stream offset");
	b = &img->blk[nr];
	in = off - b->soff;
	n = (grub_size_t) (b->dlen - in);
	if (n > len)
		n = len;

	if (!img->have_cache || img->cached != nr)
	{
		grub_uint8_t *raw;
		grub_err_t err;

		img->have_cache = 0;
		raw = grub_malloc (b->clen);
		if (!raw)
			return grub_errno;
		err = pmf_pread (img, b->foff, raw, b->clen);
		if (!err)
			err = grub_dgcomp_block (raw, b->clen, img->cache, b->dlen);
		grub_free (raw);
		if (err)
			return err;
		img->cached = nr;
		img->have_cache = 1;
	}

	grub_memcpy (buf, img->cache + in, n);
	*got = n;
	return GRUB_ERR_NONE;
}

/* Read exactly LEN bytes of the stream, crossing blocks as needed.  */
static grub_err_t
pmf_stream_pread (struct pmf_image *img, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_uint8_t *p = buf;

	while (len)
	{
		grub_size_t n;
		grub_err_t err = pmf_stream_read (img, off, p, len, &n);

		if (err)
			return err;
		if (n == 0)
			return grub_error (GRUB_ERR_BAD_DEVICE, "short pmf stream read");
		off += n;
		p += n;
		len -= n;
	}
	return GRUB_ERR_NONE;
}

/* ---------------- rebuilding a "used sectors" backup ---------------- */

static grub_uint32_t
pmf_popcount (grub_uint8_t v)
{
	v = (grub_uint8_t) (v - ((v >> 1) & 0x55));
	v = (grub_uint8_t) ((v & 0x33) + ((v >> 2) & 0x33));
	return (grub_uint32_t) ((v + (v >> 4)) & 0x0f);
}

/* Allocated clusters strictly below cluster index C.  */
static grub_uint64_t
pmf_rank (struct pmf_image *img, grub_uint32_t c)
{
	grub_uint32_t g = c >> PMF_RANK_SHIFT;
	grub_uint32_t from = g << PMF_RANK_SHIFT;
	grub_uint64_t n = img->rank[g];
	grub_uint32_t i;

	for (i = from; i + 8 <= c; i += 8)
		n += pmf_popcount (img->alloc[i >> 3]);
	for (; i < c; i++)
		n += (img->alloc[i >> 3] >> (i & 7)) & 1;
	return n;
}

/* Allocate the allocation bitmap and the running count over it.  */
static grub_err_t
pmf_alloc_map (struct pmf_image *img)
{
	if (img->nclusters == 0 || img->nclusters > PMF_CLUSTERS_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmf cluster count");
	img->nranks = (img->nclusters >> PMF_RANK_SHIFT) + 1;
	img->alloc = grub_zalloc ((img->nclusters + 7) / 8 + 1);
	img->rank = grub_calloc (img->nranks, sizeof (*img->rank));
	if (!img->alloc || !img->rank)
		return grub_errno;
	return GRUB_ERR_NONE;
}

/* Fill in the running count, and check that the clusters the map hands
   out are exactly the ones the stream carries.  */
static grub_err_t
pmf_finish_map (struct pmf_image *img)
{
	grub_uint64_t seen = 0;
	grub_uint32_t i;

	for (i = 0; i < img->nclusters; i++)
	{
		if ((i & (PMF_RANK_GROUP - 1)) == 0)
			img->rank[i >> PMF_RANK_SHIFT] = seen;
		seen += (img->alloc[i >> 3] >> (i & 7)) & 1;
	}
	if (seen * img->spc * (grub_uint64_t) img->bps
		!= img->stream - img->data_off)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "pmf used-cluster map does not fit the stream");
	return GRUB_ERR_NONE;
}

/* Read the bitmap the stream carries at OFF into the allocation map.  */
static grub_err_t
pmf_read_bitmap (struct pmf_image *img, grub_uint64_t off, grub_uint32_t len)
{
	grub_uint32_t want = (img->nclusters + 7) / 8;
	grub_err_t err;

	if (len < want || len > (img->nclusters + 7) / 8 + img->bps)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmf bitmap length %u", len);
	err = pmf_stream_pread (img, off, img->alloc, want);
	if (err)
		return err;
	/* The bits past the last cluster are set; they are not clusters.  */
	if (img->nclusters & 7)
		img->alloc[want - 1] &= (grub_uint8_t) ((1 << (img->nclusters & 7)) - 1);
	return GRUB_ERR_NONE;
}

/* Read the first FAT out of the stream and note which clusters it hands
   out.  The FAT is what a FAT backup keeps instead of a bitmap.  */
static grub_err_t
pmf_build_fat_map (struct pmf_image *img)
{
	grub_uint8_t *fat;
	grub_uint64_t off = (grub_uint64_t) img->reserved * img->bps;
	grub_uint64_t left = (grub_uint64_t) img->fat_size * img->bps;
	grub_uint32_t chunk = 64 * 1024;
	grub_uint32_t c = 0;	/* the FAT's first two entries are reserved */
	grub_err_t err;

	fat = grub_malloc (chunk);
	if (!fat)
		return grub_errno;

	while (left && c < img->nclusters + 2)
	{
		grub_uint32_t n = left > chunk ? chunk : (grub_uint32_t) left;
		grub_uint32_t i;

		err = pmf_stream_pread (img, off, fat, n);
		if (err)
		{
			grub_free (fat);
			return err;
		}
		for (i = 0; i + 4 <= n && c < img->nclusters + 2; i += 4, c++)
		{
			grub_uint32_t idx;

			if (c < 2)
				continue;
			idx = c - 2;
			if ((grub_le_to_cpu32 (grub_get_unaligned32 (fat + i)) & 0x0fffffff) == 0)
				continue;
			img->alloc[idx >> 3] |= (grub_uint8_t) (1 << (idx & 7));
		}
		off += n;
		left -= n;
	}
	grub_free (fat);
	return GRUB_ERR_NONE;
}

/* A FAT32 backup: the boot sector the stream opens with says where the
   FAT and the data area are, and the FAT is the map.  */
static grub_err_t
pmf_setup_fat (struct pmf_image *img)
{
	struct grub_fat_bpb bpb;
	grub_uint32_t nfat, root_entries, total, fat_size;
	grub_err_t err;

	err = pmf_stream_pread (img, 0, &bpb, sizeof (bpb));
	if (err)
		return err;

	img->bps = grub_le_to_cpu16 (bpb.bytes_per_sector);
	img->spc = bpb.sectors_per_cluster;
	img->reserved = grub_le_to_cpu16 (bpb.num_reserved_sectors);
	nfat = bpb.num_fats;
	root_entries = grub_le_to_cpu16 (bpb.num_root_entries);
	fat_size = grub_le_to_cpu16 (bpb.sectors_per_fat_16);
	total = grub_le_to_cpu16 (bpb.num_total_sectors_16);
	if (!total)
		total = grub_le_to_cpu32 (bpb.num_total_sectors_32);
	if (!fat_size)
		fat_size = grub_le_to_cpu32 (bpb.version_specific.fat32.sectors_per_fat_32);
	img->fat_size = fat_size;

	if (img->bps < 512 || img->bps > 4096 || (img->bps & (img->bps - 1)) != 0
		|| img->spc == 0 || (img->spc & (img->spc - 1)) != 0
		|| img->reserved == 0 || nfat == 0 || nfat > 4 || fat_size == 0
		|| total == 0)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "no FAT boot sector in the pmf stream");

	/* Only FAT32 keeps its root directory in the data area, and only
	   FAT32 is known to lay its stream out this way.  */
	if (root_entries != 0)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "only FAT32 used-sector pmf images are supported");
	if (img->meta_sectors != img->reserved + fat_size)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "unexpected pmf metadata region");

	img->fat_end = img->reserved + nfat * fat_size;
	img->first_lba = img->fat_end;
	img->data_off = (grub_uint64_t) img->meta_sectors * img->bps;
	if (total <= img->first_lba)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad FAT geometry in the pmf stream");
	img->nclusters = (total - img->first_lba) / img->spc;
	if (img->nclusters < 65525)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "only FAT32 used-sector pmf images are supported");
	img->size = (grub_uint64_t) total * img->bps;

	err = pmf_alloc_map (img);
	if (!err)
		err = pmf_build_fat_map (img);
	return err;
}

/* An exFAT backup: the verbatim head runs to the end of the FAT, the
   bitmap follows it, and the boot sector says where the clusters are.  */
static grub_err_t
pmf_setup_exfat (struct pmf_image *img, grub_uint64_t next)
{
	grub_uint8_t boot[512];
	grub_uint8_t rec[PMF_BITMAP_REC];
	grub_uint32_t fat_off, fat_len, heap_off, clusters;
	grub_uint32_t bm_len, bm_pad;
	grub_uint64_t after;
	grub_err_t err;

	err = pmf_stream_pread (img, 0, boot, sizeof (boot));
	if (err)
		return err;
	if (grub_memcmp (boot + 3, "EXFAT   ", 8) != 0)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "no exFAT boot sector in the pmf stream");
	fat_off = grub_le_to_cpu32 (grub_get_unaligned32 (boot + 80));
	fat_len = grub_le_to_cpu32 (grub_get_unaligned32 (boot + 84));
	heap_off = grub_le_to_cpu32 (grub_get_unaligned32 (boot + 88));
	clusters = grub_le_to_cpu32 (grub_get_unaligned32 (boot + 92));
	if (boot[108] > 12 || boot[109] > 25)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad exFAT geometry");
	img->bps = 1U << boot[108];
	img->spc = 1U << boot[109];
	if (fat_off == 0 || fat_len == 0 || heap_off < fat_off + fat_len
		|| img->meta_sectors != fat_off + fat_len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "unexpected pmf metadata region");

	/* The record between the head and the bitmap names the bitmap's
	   length, which is the check that the head really ended here.  */
	err = pmf_pread (img, next, rec, sizeof (rec));
	if (err)
		return err;
	bm_len = (clusters + 7) / 8;
	if (rec[0] != 0
		|| grub_le_to_cpu32 (grub_get_unaligned32 (rec + 1)) != PMF_BITMAP_KIND
		|| grub_le_to_cpu32 (grub_get_unaligned32 (rec + 5)) != bm_len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "no pmf bitmap record");
	err = pmf_scan_blocks (img, next + sizeof (rec), 0, &after);
	if (err)
		return err;

	bm_pad = (bm_len + img->bps - 1) / img->bps * img->bps;
	img->nclusters = clusters;
	img->first_lba = heap_off;
	img->data_off = (grub_uint64_t) img->meta_sectors * img->bps + bm_pad;
	img->size = (grub_uint64_t) heap_off * img->bps
		+ (grub_uint64_t) clusters * img->spc * img->bps;

	err = pmf_alloc_map (img);
	if (err)
		return err;
	return pmf_read_bitmap (img, (grub_uint64_t) img->meta_sectors * img->bps, bm_pad);
}

/* An NTFS backup: no verbatim head, the stream opens with the cluster
   bitmap and the geometry comes from the image header.  */
static grub_err_t
pmf_setup_ntfs (struct pmf_image *img, grub_uint32_t sectors)
{
	grub_uint32_t bm_len;
	grub_err_t err;

	if (img->spc == 0 || (img->spc & (img->spc - 1)) != 0 || sectors < img->spc)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad NTFS geometry in the pmf header");
	img->nclusters = sectors / img->spc;
	img->first_lba = 0;
	/* The writer rounds the bitmap up to a multiple of eight bytes.  */
	bm_len = (img->nclusters + 63) / 64 * 8;
	img->data_off = bm_len;
	img->size = (grub_uint64_t) sectors * img->bps;

	err = pmf_alloc_map (img);
	if (err)
		return err;
	return pmf_read_bitmap (img, 0, bm_len);
}

/* An ext4 backup: the head covers the boot block and the superblock,
   the group descriptors come next, and then one block bitmap per group
   that keeps one.  A group flagged BLOCK_UNINIT has no bitmap anywhere;
   what it has in use is the run of metadata at its front, whose length
   its free-block count gives.  */
static grub_err_t
pmf_setup_ext4 (struct pmf_image *img)
{
	grub_uint8_t sb[1024];
	grub_uint8_t *gd = NULL;
	grub_uint8_t *bm = NULL;
	grub_uint64_t blocks, sec;
	grub_uint32_t bs, bpg, first, groups, dsize, g, stored = 0, kept = 0;
	grub_err_t err;

	err = pmf_stream_pread (img, PMF_E4_SB, sb, sizeof (sb));
	if (err)
		return err;
	if (grub_le_to_cpu16 (grub_get_unaligned16 (sb + PMF_E4_MAGIC_OFF)) != PMF_E4_MAGIC)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "no ext4 superblock in the pmf stream");
	if (grub_le_to_cpu32 (grub_get_unaligned32 (sb + PMF_E4_LOG_BS)) > 6)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ext4 block size");
	bs = 1024U << grub_le_to_cpu32 (grub_get_unaligned32 (sb + PMF_E4_LOG_BS));
	blocks = grub_le_to_cpu32 (grub_get_unaligned32 (sb + PMF_E4_BLOCKS));
	bpg = grub_le_to_cpu32 (grub_get_unaligned32 (sb + PMF_E4_BPG));
	first = grub_le_to_cpu32 (grub_get_unaligned32 (sb + PMF_E4_FIRST));
	dsize = grub_le_to_cpu16 (grub_get_unaligned16 (sb + PMF_E4_DESC_SIZE));
	if (!dsize)
		dsize = 32;
	if (bs % img->bps != 0 || bpg == 0 || blocks <= first
		|| dsize < 32 || dsize > bs)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ext4 geometry");
	groups = (grub_uint32_t) ((blocks - first + bpg - 1) / bpg);
	if (groups == 0 || groups > PMF_E4_GROUPS_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ext4 group count");
	if (img->meta_sectors * (grub_uint64_t) img->bps < PMF_E4_SB + sizeof (sb))
		return grub_error (GRUB_ERR_BAD_DEVICE, "unexpected pmf metadata region");

	img->spc = bs / img->bps;
	img->first_lba = 0;
	img->nclusters = (grub_uint32_t) blocks;
	img->size = blocks * bs;

	err = pmf_alloc_map (img);
	if (err)
		return err;

	/* The descriptors are stored as they are, not padded to a block.  */
	gd = grub_malloc ((grub_size_t) groups * dsize);
	bm = grub_malloc (bs);
	if (!gd || !bm)
	{
		err = grub_errno;
		goto out;
	}
	sec = (grub_uint64_t) img->meta_sectors * img->bps;
	err = pmf_stream_pread (img, sec, gd, (grub_size_t) groups * dsize);
	if (err)
		goto out;
	sec += (grub_uint64_t) groups * dsize;
	for (g = 0; g < groups; g++)
		if (!(grub_le_to_cpu16 (grub_get_unaligned16 (gd + (grub_size_t) g * dsize
							      + PMF_E4_GD_FLAGS))
		      & PMF_E4_BG_BLOCK_UNINIT))
			stored++;
	img->data_off = sec + (grub_uint64_t) stored * bs;

	/* Blocks below the first group belong to no bitmap and are kept.  */
	for (g = 0; g < first; g++)
		img->alloc[g >> 3] |= (grub_uint8_t) (1 << (g & 7));

	for (g = 0; g < groups; g++)
	{
		const grub_uint8_t *desc = gd + (grub_size_t) g * dsize;
		grub_uint64_t base = (grub_uint64_t) first + (grub_uint64_t) g * bpg;
		grub_uint32_t n = bpg;
		grub_uint32_t i;

		if (blocks - base < n)
			n = (grub_uint32_t) (blocks - base);
		if (grub_le_to_cpu16 (grub_get_unaligned16 (desc + PMF_E4_GD_FLAGS))
			& PMF_E4_BG_BLOCK_UNINIT)
		{
			/* Nothing but the metadata at the front is in use.  */
			grub_uint32_t used = bpg
				- grub_le_to_cpu16 (grub_get_unaligned16 (desc + PMF_E4_GD_FREE));

			if (used > n)
				used = n;
			for (i = 0; i < used; i++)
				img->alloc[(base + i) >> 3] |= (grub_uint8_t) (1 << ((base + i) & 7));
			continue;
		}
		err = pmf_stream_pread (img, sec + (grub_uint64_t) kept * bs, bm, bs);
		if (err)
			goto out;
		kept++;
		for (i = 0; i < n; i++)
			if ((bm[i >> 3] >> (i & 7)) & 1)
				img->alloc[(base + i) >> 3] |= (grub_uint8_t) (1 << ((base + i) & 7));
	}

out:
	grub_free (gd);
	grub_free (bm);
	return err;
}

/* Byte offset in the stream of the partition's sector LBA, or -1 when
   it was never stored and reads back as zeros.  RUN comes back with how
   many sectors from LBA on keep following it.  A bitmap need not be a
   whole number of sectors long, so this counts in bytes.  */
static grub_uint64_t
pmf_map_sector (struct pmf_image *img, grub_uint64_t lba, grub_uint32_t *run)
{
	grub_uint32_t c, in_cluster;

	if (lba < img->meta_sectors)
	{
		*run = (grub_uint32_t) (img->meta_sectors - lba);
		return lba * img->bps;
	}
	if (lba < img->fat_end)
	{
		/* A further copy of the FAT, mirroring the stored one.  */
		grub_uint32_t s = (grub_uint32_t) (lba - img->reserved) % img->fat_size;

		*run = img->fat_size - s;
		return (grub_uint64_t) (img->reserved + s) * img->bps;
	}
	if (lba < img->first_lba)
	{
		*run = (grub_uint32_t) (img->first_lba - lba);
		return (grub_uint64_t) -1;
	}
	c = (grub_uint32_t) ((lba - img->first_lba) / img->spc);
	in_cluster = (grub_uint32_t) ((lba - img->first_lba) % img->spc);
	*run = img->spc - in_cluster;
	if (c >= img->nclusters)
		return (grub_uint64_t) -1;
	if (!((img->alloc[c >> 3] >> (c & 7)) & 1))
		return (grub_uint64_t) -1;
	return img->data_off
		+ (pmf_rank (img, c) * img->spc + in_cluster) * (grub_uint64_t) img->bps;
}

/* ---------------- reads ---------------- */

static grub_err_t
pmf_read (struct pmf_image *img, grub_uint64_t off, void *buf,
	  grub_size_t len, grub_size_t *actually_read)
{
	grub_uint64_t lba, sec, in;
	grub_uint32_t run = 0;
	grub_size_t n;

	*actually_read = 0;
	if (off >= img->size)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past the end of the pmf image");
	if (len > img->size - off)
		len = (grub_size_t) (img->size - off);
	if (len == 0)
		return GRUB_ERR_NONE;

	if (!img->sparse)
		return pmf_stream_read (img, off, buf, len, actually_read);

	lba = off / img->bps;
	in = off % img->bps;
	sec = pmf_map_sector (img, lba, &run);
	n = (grub_size_t) ((grub_uint64_t) run * img->bps - in);
	if (n > len)
		n = len;
	if (sec == (grub_uint64_t) -1)
	{
		grub_memset (buf, 0, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}
	return pmf_stream_read (img, sec + in, buf, n, actually_read);
}

/* ---------------- io filter ---------------- */

struct grub_pmf
{
	grub_file_t file;
	struct pmf_image *image;
};
typedef struct grub_pmf *grub_pmf_t;

static struct grub_fs grub_pmf_fs;

static grub_err_t
grub_pmf_close (grub_file_t file)
{
	grub_pmf_t pmfio = file->data;

	pmf_free_image (pmfio->image);
	grub_free (pmfio->image);
	grub_file_close (pmfio->file);
	grub_free (pmfio);
	file->device = 0;
	return grub_errno;
}

static grub_err_t
pmf_open_image (struct pmf_image *img, grub_uint32_t mode, const char *fs)
{
	grub_uint8_t buf[4];
	grub_uint64_t next;
	grub_uint32_t sectors;
	int is_ntfs, is_exfat, is_ext;
	grub_err_t err;

	if (mode != PMF_MODE_DATA)
	{
		err = pmf_open_stream (img, PMF_STREAM_OFF);
		if (err)
			return err;
		img->size = img->stream;
		if (img->size > PMF_PART_MAX)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmf partition size");
		return GRUB_ERR_NONE;
	}

	is_ntfs = grub_strcmp (fs, "NTFS") == 0;
	is_exfat = grub_strcmp (fs, "exFAT") == 0;
	is_ext = grub_memcmp (fs, "EXT", 3) == 0;
	if (!is_ntfs && !is_exfat && !is_ext && grub_memcmp (fs, "FAT", 3) != 0)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "used-sector pmf images of %s are not supported", fs);
	img->sparse = 1;
	img->bps = 512;

	if (is_ntfs)
	{
		/* No verbatim head: the chain opens with the bitmap.  */
		err = pmf_pread (img, PMF_HDR_SECTORS, buf, sizeof (buf));
		if (err)
			return err;
		sectors = grub_le_to_cpu32 (grub_get_unaligned32 (buf));
		err = pmf_pread (img, PMF_HDR_BPS, buf, sizeof (buf));
		if (!err)
			img->bps = grub_le_to_cpu32 (grub_get_unaligned32 (buf));
		if (!err)
			err = pmf_pread (img, PMF_HDR_SPC, buf, sizeof (buf));
		if (err)
			return err;
		img->spc = grub_le_to_cpu32 (grub_get_unaligned32 (buf));
		if (img->bps < 512 || img->bps > 4096 || (img->bps & (img->bps - 1)) != 0)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmf sector size");
		err = pmf_open_stream (img, PMF_STREAM_OFF);
		if (err)
			return err;
		err = pmf_setup_ntfs (img, sectors);
	}
	else
	{
		err = pmf_pread (img, PMF_META_SECTORS, buf, sizeof (buf));
		if (err)
			return err;
		img->meta_sectors = grub_le_to_cpu32 (grub_get_unaligned32 (buf));
		if (img->meta_sectors == 0 || img->meta_sectors > PMF_BLOCKS_MAX * 64)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmf metadata region");
		if (is_exfat)
		{
			/* The head is stored first; its length is known in
			   sectors, so read it before anything says how long a
			   sector is.  */
			err = pmf_scan_blocks (img, PMF_STREAM_OFF + 4,
					       (grub_uint64_t) img->meta_sectors * 512, &next);
			if (!err)
				err = pmf_setup_exfat (img, next);
		}
		else
		{
			err = pmf_open_stream (img, PMF_STREAM_OFF + 4);
			if (!err)
				err = is_ext ? pmf_setup_ext4 (img) : pmf_setup_fat (img);
		}
	}

	if (err)
		return err;
	if (img->size > PMF_PART_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmf partition size");
	return pmf_finish_map (img);
}

static grub_file_t
grub_pmf_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_pmf_t pmfio;
	struct pmf_image *image;
	grub_uint8_t probe[PMF_HDR_MODE + 4];
	char fs[6];
	grub_uint32_t mode;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < PMF_STREAM_OFF + PMF_BLOCK_HDR || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;
	if (grub_file_seek (io, 0) == (grub_off_t) -1
		|| grub_file_read (io, probe, sizeof (probe)) != (grub_ssize_t) sizeof (probe)
		|| grub_memcmp (probe, PMF_MAGIC, 4) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}
	mode = grub_le_to_cpu32 (grub_get_unaligned32 (probe + PMF_HDR_MODE));
	if (mode != PMF_MODE_ALL && mode != PMF_MODE_DATA)
	{
		/* A file-by-file backup: grub-core\fs\pmf.c reads those.  */
		grub_file_seek (io, 0);
		return io;
	}

	grub_memcpy (fs, probe + PMF_HDR_FS, sizeof (fs) - 1);
	fs[sizeof (fs) - 1] = '\0';

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (pmf_open_image (image, mode, fs) != GRUB_ERR_NONE)
	{
		pmf_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	pmfio = grub_zalloc (sizeof (*pmfio));
	if (!file || !pmfio)
	{
		pmf_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (pmfio);
		return 0;
	}
	pmfio->file = io;
	pmfio->image = image;

	file->device = io->device;
	file->data = pmfio;
	file->fs = &grub_pmf_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->size;

	return file;
}

static grub_ssize_t
grub_pmf_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_pmf_t pmfio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = pmf_read (pmfio->image, read_offset, buf, len, &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR, "pmf read made no progress");
			break;
		}
		read_offset += real_size;
		buf += real_size;
		size += real_size;
		if (real_size >= len)
			break;
		len -= real_size;
	}

	if (err != GRUB_ERR_NONE)
	{
		if (!grub_errno)
			grub_error (err, "pmf image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_pmf_fs =
{
	.name = "pmf",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_pmf_read,
	.fs_close = grub_pmf_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (pmf)
{
	grub_file_filter_register (GRUB_FILE_FILTER_PMF, grub_pmf_open);
}

GRUB_MOD_FINI (pmf)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_PMF);
}
