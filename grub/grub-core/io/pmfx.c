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
 * DiskGenius whole-disk backup images (.pmfx), presented as the disk
 * they hold.
 *
 * Layout:
 *
 *	0x0000	header
 *		  +0x00	"PMFX"
 *		  +0x10	u32 bytes per sector
 *		  +0x14	u64 sectors on the source disk
 *		  +0x1c	u32 sectors per block
 *		  +0x20	u32 block table capacity
 *		  +0x58	UTF-16 image name
 *		  +0x100 "CLDK", then the date and a u32 backup mode at
 *		         +0x10c: 4 all sectors, 1 used sectors, 2 files
 *	0x1000	block table, one 16 byte entry per block:
 *		  +0x00 u64 offset of the stored block in the image
 *		  +0x08 u32 length of its slot, comp rounded up to 4 KiB
 *		  +0x0c u32 stored length
 *	        the data area follows the table's full capacity.
 *
 * Block N holds the disk's bytes [N * blocksize, (N + 1) * blocksize).
 * An all-zero table entry means the block was never written: the
 * "used sectors" and "files" modes only store the blocks the source
 * filesystems had in use, and everything else reads back as zeros.  The
 * "files" mode is still a sector image -- DiskGenius lays the files it
 * saved into a freshly built filesystem and stores the result -- so all
 * three modes are the same container and are presented the same way.
 *
 * Blocks are deflated, stored verbatim, or written with the LZ77 codec
 * of grub-core\lib\dgcomp.c, whichever the backup's compression setting
 * chose.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/dgcomp.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define PMFX_MAGIC		"PMFX"
#define PMFX_DISK_MAGIC		"CLDK"

#define PMFX_HDR_SECTOR_SIZE	0x10	/* u32 */
#define PMFX_HDR_SECTORS	0x14	/* u64 */
#define PMFX_HDR_BLOCK_SECTORS	0x1c	/* u32 */
#define PMFX_HDR_TABLE_CAP	0x20	/* u32 */
#define PMFX_HDR_DISK		0x100	/* "CLDK" */
#define PMFX_HDR_MODE		0x10c	/* u32 */
#define PMFX_HDR_SIZE		0x110

#define PMFX_TABLE_OFF		0x1000
#define PMFX_ENTRY_SIZE		16

/* Sanity caps against a corrupt or hostile image.  */
#define PMFX_TABLE_CAP_MAX	(1u << 22)
#define PMFX_BLOCK_MAX		(64u << 20)
#define PMFX_DISK_MAX		((grub_uint64_t) 1 << 48)

struct pmfx_block
{
	grub_uint64_t off;	/* where the stored block lives, 0 if absent */
	grub_uint32_t comp;	/* its stored length */
};

struct pmfx_image
{
	grub_file_t file;
	grub_uint64_t size;	/* bytes of the disk this exposes */
	grub_uint32_t bsize;	/* plaintext bytes per block */
	grub_uint32_t nblocks;
	struct pmfx_block *blk;

	/* The block the previous read landed in, kept expanded.  */
	grub_uint8_t *cache;
	grub_uint32_t cached;
	int have_cache;
};

static grub_err_t
pmfx_pread (struct pmfx_image *img, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;
	grub_uint64_t size = grub_file_size (img->file);

	if (off > size || len > size - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "pmfx image truncated");
	if (grub_file_seek (img->file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (img->file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "pmfx image truncated");
	return GRUB_ERR_NONE;
}

static void
pmfx_free_image (struct pmfx_image *img)
{
	grub_free (img->blk);
	grub_free (img->cache);
	img->blk = NULL;
	img->cache = NULL;
	img->have_cache = 0;
}

/* Read the header and the block table.  */
static grub_err_t
pmfx_open_image (struct pmfx_image *img)
{
	grub_uint8_t hdr[PMFX_HDR_SIZE];
	grub_uint8_t *raw = NULL;
	grub_uint64_t sectors, table_bytes;
	grub_uint32_t bps, spb, cap, i;
	grub_err_t err;

	err = pmfx_pread (img, 0, hdr, sizeof (hdr));
	if (err)
		return err;
	if (grub_memcmp (hdr, PMFX_MAGIC, 4) != 0
		|| grub_memcmp (hdr + PMFX_HDR_DISK, PMFX_DISK_MAGIC, 4) != 0)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a pmfx image");

	bps = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + PMFX_HDR_SECTOR_SIZE));
	sectors = grub_le_to_cpu64 (grub_get_unaligned64 (hdr + PMFX_HDR_SECTORS));
	spb = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + PMFX_HDR_BLOCK_SECTORS));
	cap = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + PMFX_HDR_TABLE_CAP));

	if (bps < 512 || bps > 4096 || (bps & (bps - 1)) != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmfx sector size %u", bps);
	if (spb == 0 || cap == 0 || cap > PMFX_TABLE_CAP_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmfx block table");
	if ((grub_uint64_t) spb * bps > PMFX_BLOCK_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmfx block size");
	if (sectors == 0 || sectors > PMFX_DISK_MAX / bps)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad pmfx disk size");

	img->bsize = spb * bps;
	img->size = sectors * bps;
	img->nblocks = (grub_uint32_t) ((sectors + spb - 1) / spb);
	if (img->nblocks > cap)
		return grub_error (GRUB_ERR_BAD_DEVICE, "pmfx block table too small");

	table_bytes = (grub_uint64_t) img->nblocks * PMFX_ENTRY_SIZE;
	raw = grub_malloc ((grub_size_t) table_bytes);
	img->blk = grub_calloc (img->nblocks, sizeof (*img->blk));
	img->cache = grub_malloc (img->bsize);
	if (!raw || !img->blk || !img->cache)
	{
		err = grub_errno;
		goto fail;
	}
	err = pmfx_pread (img, PMFX_TABLE_OFF, raw, (grub_size_t) table_bytes);
	if (err)
		goto fail;

	for (i = 0; i < img->nblocks; i++)
	{
		const grub_uint8_t *e = raw + (grub_size_t) i * PMFX_ENTRY_SIZE;
		grub_uint64_t off = grub_le_to_cpu64 (grub_get_unaligned64 (e));
		grub_uint32_t comp = grub_le_to_cpu32 (grub_get_unaligned32 (e + 12));

		if (off == 0 || comp == 0)
			continue;	/* the block was never written */
		if (off < PMFX_TABLE_OFF || off > grub_file_size (img->file)
			|| comp > grub_file_size (img->file) - off
			|| comp > img->bsize)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE, "bad pmfx block %u", i);
			goto fail;
		}
		img->blk[i].off = off;
		img->blk[i].comp = comp;
	}

	grub_free (raw);
	return GRUB_ERR_NONE;

fail:
	grub_free (raw);
	pmfx_free_image (img);
	return err;
}

/* Expand block NR into the cache.  */
static grub_err_t
pmfx_load_block (struct pmfx_image *img, grub_uint32_t nr)
{
	grub_uint8_t *raw;
	grub_uint32_t want;
	grub_err_t err;

	if (img->have_cache && img->cached == nr)
		return GRUB_ERR_NONE;
	img->have_cache = 0;

	raw = grub_malloc (img->blk[nr].comp);
	if (!raw)
		return grub_errno;
	err = pmfx_pread (img, img->blk[nr].off, raw, img->blk[nr].comp);
	if (err)
	{
		grub_free (raw);
		return err;
	}

	/* Blocks hold a full blocksize even where the disk ends inside
	   one, but do not insist on it: expand what the last one carries.  */
	want = img->bsize;
	err = grub_dgcomp_block (raw, img->blk[nr].comp, img->cache, want);
	if (err != GRUB_ERR_NONE && nr + 1 == img->nblocks
		&& img->size % img->bsize != 0)
	{
		grub_errno = GRUB_ERR_NONE;
		want = (grub_uint32_t) (img->size % img->bsize);
		grub_memset (img->cache, 0, img->bsize);
		err = grub_dgcomp_block (raw, img->blk[nr].comp, img->cache, want);
	}
	grub_free (raw);
	if (err)
		return err;

	img->cached = nr;
	img->have_cache = 1;
	return GRUB_ERR_NONE;
}

static grub_err_t
pmfx_read (struct pmfx_image *img, grub_uint64_t off, void *buf,
	   grub_size_t len, grub_size_t *actually_read)
{
	grub_uint32_t nr = (grub_uint32_t) (off / img->bsize);
	grub_uint32_t in = (grub_uint32_t) (off % img->bsize);
	grub_size_t n;
	grub_err_t err;

	*actually_read = 0;
	if (off >= img->size)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past the end of the pmfx image");
	if (len > img->size - off)
		len = (grub_size_t) (img->size - off);
	if (len == 0)
		return GRUB_ERR_NONE;

	n = img->bsize - in;
	if (n > len)
		n = len;

	if (nr >= img->nblocks || img->blk[nr].comp == 0)
	{
		grub_memset (buf, 0, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}

	err = pmfx_load_block (img, nr);
	if (err)
		return err;
	grub_memcpy (buf, img->cache + in, n);
	*actually_read = n;
	return GRUB_ERR_NONE;
}

/* ---------------- io filter ---------------- */

struct grub_pmfx
{
	grub_file_t file;
	struct pmfx_image *image;
};
typedef struct grub_pmfx *grub_pmfx_t;

static struct grub_fs grub_pmfx_fs;

static grub_err_t
grub_pmfx_close (grub_file_t file)
{
	grub_pmfx_t pmfxio = file->data;

	pmfx_free_image (pmfxio->image);
	grub_free (pmfxio->image);
	grub_file_close (pmfxio->file);
	grub_free (pmfxio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_pmfx_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_pmfx_t pmfxio;
	struct pmfx_image *image;
	grub_uint8_t probe[4];

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < PMFX_TABLE_OFF || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;
	if (grub_file_seek (io, 0) == (grub_off_t) -1
		|| grub_file_read (io, probe, sizeof (probe)) != (grub_ssize_t) sizeof (probe)
		|| grub_memcmp (probe, PMFX_MAGIC, sizeof (probe)) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (pmfx_open_image (image) != GRUB_ERR_NONE)
	{
		pmfx_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	pmfxio = grub_zalloc (sizeof (*pmfxio));
	if (!file || !pmfxio)
	{
		pmfx_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (pmfxio);
		return 0;
	}
	pmfxio->file = io;
	pmfxio->image = image;

	file->device = io->device;
	file->data = pmfxio;
	file->fs = &grub_pmfx_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->size;

	return file;
}

static grub_ssize_t
grub_pmfx_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_pmfx_t pmfxio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = pmfx_read (pmfxio->image, read_offset, buf, len, &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR, "pmfx read made no progress");
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
			grub_error (err, "pmfx image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_pmfx_fs =
{
	.name = "pmfx",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_pmfx_read,
	.fs_close = grub_pmfx_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (pmfx)
{
	grub_file_filter_register (GRUB_FILE_FILTER_PMFX, grub_pmfx_open);
}

GRUB_MOD_FINI (pmfx)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_PMFX);
}
