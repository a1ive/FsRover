/* gho.c - Symantec (Norton) Ghost disk image io filter */
/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  Block layout and the Fast LZ token stream follow ref\gho
 *  (github.com/nyarime/gho, MIT); the container walk was re-derived
 *  from Ghost 11/12 images because the reference only ever looks for
 *  four record types and misses the ones these images use.
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
 * A Ghost image starts with a 512 byte file header, followed by an
 * opaque descriptor area and a 512 byte partition header carrying the
 * same image id.  Sector images ("image all", ghost -ia) store the
 * partition contents right behind that partition header as a chain of
 *
 *	[2 byte stored_len (counts itself)][stored_len - 2 bytes]
 *
 * blocks, each holding 32 KiB of the image.  A ten byte record header
 * (magic 0x012f18d8) closes the chain.  Images split over several files
 * continue the very same chain in name00001.ghs, name00002.ghs, ...,
 * each of which repeats the 512 byte file header and nothing else.
 *
 * This filter decodes single-partition sector images into the raw
 * partition image, so mounting one lands straight on its filesystem.
 * File based images (Ghost's default backup mode) hold a directory tree
 * instead of sectors and are handed to fs\gho.c; all this filter does
 * for them is splice the span files back into one stream so that the
 * browser sees the whole catalogue.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/ghost.h>
#include <grub/safemath.h>
#include <grub/winfile.h>

GRUB_MOD_LICENSE ("GPLv3+");

/* Record type (low 16 bits) that resumes the block chain.  */
#define GHO_REC_CONTINUE	0x0703

/* Sanity caps against corrupt images.  The block index is the only
   per-image allocation that grows with the image size: 4M blocks is a
   128 GiB image and a 32 MiB index.  */
#define GHO_MAX_BLOCKS		(4u << 20)
#define GHO_MAX_EXTENTS		(4u << 20)
#define GHO_MAX_SPANS		1024
#define GHO_HEADER_SCAN_MAX	(16u << 20)
#define GHO_SCAN_BUF		(256u << 10)
#define GHO_NTFS_FRAGMENT	(32u << 10)
#define GHO_NTFS_RECORD_MAX	(64u << 10)

#define GHO_CACHE_NONE		0xffffffffu

/* One file of the image set: the primary .gho plus its .ghs spans,
   concatenated into a single stream with the file headers dropped.  */
struct gho_span
{
	grub_file_t file;
	grub_uint64_t start;		/* stream offset of its first payload byte */
	grub_uint64_t size;		/* payload bytes it contributes */
	grub_uint32_t skip;		/* file header bytes in front of the payload */
};

struct gho_ntfs_block
{
	grub_uint64_t phys;
	grub_uint64_t logical;
	grub_uint32_t len;
};

struct gho_ntfs_extent
{
	grub_uint64_t disk;
	grub_uint64_t stream;
	grub_uint64_t len;
};

struct gho_image
{
	struct gho_span *spans;
	unsigned nspans;
	grub_uint64_t stream_size;

	grub_uint32_t id;		/* image id, shared by every file */
	grub_uint8_t comp;
	int raw;			/* 1: hand the spliced stream straight out */
	int ntfs;			/* 1: expose the reconstructed NTFS volume */
	grub_uint64_t data_start;	/* stream offset of the first block */

	grub_uint64_t *blocks;		/* stream offset of every block */
	grub_uint32_t nblocks;
	grub_uint32_t block_size;	/* uncompressed bytes per block */
	grub_uint64_t total_bytes;
	struct gho_ntfs_block *ntfs_blocks;
	grub_uint32_t nntfs_blocks;
	grub_uint64_t ntfs_stream_size;
	struct gho_ntfs_extent *extents;
	grub_uint32_t nextents;
	grub_uint32_t cluster_size;

	grub_uint32_t cached_nr;
	grub_uint8_t *blk_buf;		/* GRUB_GHOST_BLOCK_MAX bytes */
	grub_uint8_t *cmp_buf;		/* GRUB_GHOST_STORED_MAX bytes */
	grub_int32_t *hash_tbl;		/* GRUB_GHOST_FASTLZ_HASH_SIZE entries */
};

/* ------------------------------------------------------------------ */
/* the concatenated stream                                             */

static grub_err_t
gho_pread (struct gho_image *image, grub_uint64_t off, void *buf,
	   grub_size_t len)
{
	grub_uint8_t *out = buf;
	unsigned i = 0;

	if (off > image->stream_size || len > image->stream_size - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "Ghost image truncated");

	while (len > 0)
	{
		struct gho_span *sp;
		grub_uint64_t in;
		grub_size_t n;
		grub_ssize_t got;

		while (i < image->nspans
		       && off >= image->spans[i].start + image->spans[i].size)
			i++;
		if (i >= image->nspans)
			return grub_error (GRUB_ERR_BAD_DEVICE, "Ghost image truncated");

		sp = &image->spans[i];
		in = off - sp->start;
		n = len;
		if (n > sp->size - in)
			n = (grub_size_t) (sp->size - in);

		if (grub_file_seek (sp->file, sp->skip + in) == (grub_off_t) -1)
			return grub_errno;
		got = grub_file_read (sp->file, out, n);
		if (got < 0)
			return grub_errno;
		if ((grub_size_t) got != n)
			return grub_error (GRUB_ERR_BAD_DEVICE, "Ghost image truncated");

		off += n;
		out += n;
		len -= n;
	}
	return GRUB_ERR_NONE;
}

/* ------------------------------------------------------------------ */
/* blocks                                                              */

/* Decode the block starting at stream offset POS.  */
static grub_err_t
gho_decode_block (struct gho_image *image, grub_uint64_t pos,
		  grub_uint8_t *dst, grub_size_t dstcap, grub_size_t *outlen)
{
	grub_uint8_t len_buf[2];
	grub_uint32_t stored;
	grub_uint32_t clen;
	grub_err_t err;

	err = gho_pread (image, pos, len_buf, sizeof (len_buf));
	if (err)
		return err;
	stored = grub_ghost_get16 (len_buf);
	if (stored < GRUB_GHOST_STORED_MIN)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "empty Ghost block");
	clen = stored - 2;

	err = gho_pread (image, pos + 2, image->cmp_buf, clen);
	if (err)
		return err;

	return grub_ghost_decode (image->comp, image->hash_tbl, image->cmp_buf,
				  clen, dst, dstcap, outlen);
}

static grub_err_t
gho_load_block (struct gho_image *image, grub_uint32_t nr)
{
	grub_size_t n;
	grub_err_t err;

	if (image->cached_nr == nr)
		return GRUB_ERR_NONE;
	image->cached_nr = GHO_CACHE_NONE;

	err = gho_decode_block (image, image->blocks[nr], image->blk_buf,
				GRUB_GHOST_BLOCK_MAX, &n);
	if (err)
		return err;
	if (n > image->block_size)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "oversized block in Ghost image");
	if (n < image->block_size)
		grub_memset (image->blk_buf + n, 0, image->block_size - n);

	image->cached_nr = nr;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_load_ntfs_block (struct gho_image *image, grub_uint32_t nr)
{
	grub_size_t n;
	grub_err_t err;

	if (image->cached_nr == nr)
		return GRUB_ERR_NONE;
	image->cached_nr = GHO_CACHE_NONE;
	err = gho_decode_block (image, image->ntfs_blocks[nr].phys,
				image->blk_buf, GRUB_GHOST_BLOCK_MAX, &n);
	if (err)
		return err;
	if (n != image->ntfs_blocks[nr].len)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "Ghost NTFS block size changed");
	image->cached_nr = nr;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_ntfs_pread (struct gho_image *image, grub_uint64_t off, void *buf,
		grub_size_t len)
{
	grub_uint8_t *out = buf;
	grub_uint32_t lo = 0;
	grub_uint32_t hi = image->nntfs_blocks;

	if (off > image->ntfs_stream_size || len > image->ntfs_stream_size - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "Ghost NTFS stream truncated");
	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (image->ntfs_blocks[mid].logical <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0 && len != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad Ghost NTFS stream offset");
	if (lo != 0)
		lo--;

	while (len > 0)
	{
		struct gho_ntfs_block *block;
		grub_uint32_t in;
		grub_size_t n;
		grub_err_t err;

		if (lo >= image->nntfs_blocks)
			return grub_error (GRUB_ERR_BAD_DEVICE, "Ghost NTFS stream truncated");
		block = &image->ntfs_blocks[lo];
		if (off < block->logical || off >= block->logical + block->len)
			return grub_error (GRUB_ERR_BAD_DEVICE, "gap in Ghost NTFS stream");
		err = gho_load_ntfs_block (image, lo);
		if (err)
			return err;
		in = (grub_uint32_t) (off - block->logical);
		n = len;
		if (n > block->len - in)
			n = block->len - in;
		grub_memcpy (out, image->blk_buf + in, n);
		off += n;
		out += n;
		len -= n;
		lo++;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_read_ntfs (struct gho_image *image, grub_uint64_t off, void *buf,
	       grub_size_t len, grub_size_t *actually_read)
{
	grub_uint32_t lo = 0;
	grub_uint32_t hi = image->nextents;
	struct gho_ntfs_extent *extent = NULL;
	grub_size_t n;

	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (image->extents[mid].disk <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo != 0 && off < image->extents[lo - 1].disk + image->extents[lo - 1].len)
		extent = &image->extents[lo - 1];

	n = len;
	if (extent)
	{
		grub_uint64_t in = off - extent->disk;
		grub_err_t err;

		if (n > extent->len - in)
			n = (grub_size_t) (extent->len - in);
		err = gho_ntfs_pread (image, extent->stream + in, buf, n);
		if (err)
			return err;
	}
	else
	{
		if (lo < image->nextents && n > image->extents[lo].disk - off)
			n = (grub_size_t) (image->extents[lo].disk - off);
		grub_memset (buf, 0, n);
	}
	*actually_read = n;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_read (struct gho_image *image, grub_uint64_t off, void *buf,
	  grub_size_t len, grub_size_t *actually_read)
{
	grub_uint32_t nr;
	grub_uint32_t in;
	grub_err_t err;

	*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of Ghost image");
	if (len == 0)
		return GRUB_ERR_NONE;

	if (image->raw)
	{
		err = gho_pread (image, off, buf, len);
		if (err)
			return err;
		*actually_read = len;
		return GRUB_ERR_NONE;
	}
	if (image->ntfs)
		return gho_read_ntfs (image, off, buf, len, actually_read);

	nr = (grub_uint32_t) (off / image->block_size);
	in = (grub_uint32_t) (off % image->block_size);

	/* Clip to the block; never grow the request.  */
	if (len > image->block_size - in)
		len = image->block_size - in;

	err = gho_load_block (image, nr);
	if (err)
		return err;
	grub_memcpy (buf, image->blk_buf + in, len);

	*actually_read = len;
	return GRUB_ERR_NONE;
}

/* ------------------------------------------------------------------ */
/* opening                                                             */

static void
gho_free_image (struct gho_image *image)
{
	unsigned i;

	/* spans[0] is the caller's file and is closed by the outer close.  */
	for (i = 1; i < image->nspans; i++)
		grub_file_close (image->spans[i].file);
	grub_free (image->spans);
	image->spans = NULL;
	image->nspans = 0;
	grub_free (image->blocks);
	image->blocks = NULL;
	grub_free (image->ntfs_blocks);
	image->ntfs_blocks = NULL;
	grub_free (image->extents);
	image->extents = NULL;
	grub_free (image->blk_buf);
	image->blk_buf = NULL;
	grub_free (image->cmp_buf);
	image->cmp_buf = NULL;
	grub_free (image->hash_tbl);
	image->hash_tbl = NULL;
}

static grub_err_t
gho_add_span (struct gho_image *image, grub_file_t file, grub_uint32_t skip)
{
	struct gho_span *spans;
	grub_size_t sz;

	if (grub_mul ((grub_size_t) image->nspans + 1, sizeof (*spans), &sz))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many Ghost span files");
	spans = grub_realloc (image->spans, sz);
	if (!spans)
		return grub_errno;
	image->spans = spans;

	spans[image->nspans].file = file;
	spans[image->nspans].skip = skip;
	spans[image->nspans].start = image->stream_size;
	spans[image->nspans].size = grub_file_size (file) - skip;
	image->stream_size += spans[image->nspans].size;
	image->nspans++;
	return GRUB_ERR_NONE;
}

/* Build "<stem><nnnnn><ext>" from the primary image name.  */
static char *
gho_span_name (const char *name, unsigned nr, const char *ext)
{
	const char *slash;
	const char *dot;
	grub_size_t stem;
	char *out;

	slash = grub_strrchr (name, '/');
	dot = grub_strrchr (slash ? slash : name, '.');
	stem = dot ? (grub_size_t) (dot - name) : grub_strlen (name);

	out = grub_malloc (stem + 16);
	if (!out)
		return NULL;
	grub_memcpy (out, name, stem);
	grub_snprintf (out + stem, 16, "%05u%s", nr, ext);
	return out;
}

/* A span repeats the file header with type 0x09 and the image id
   bumped by its ordinal, which is enough to reject a stray sibling.  */
static grub_file_t
gho_open_span (struct gho_image *image, const char *name, unsigned nr)
{
	static const char *exts[] = { ".ghs", ".GHS" };
	unsigned i;

	for (i = 0; i < ARRAY_SIZE (exts); i++)
	{
		grub_uint8_t hdr[GRUB_GHOST_HEADER_SIZE];
		grub_file_t file;
		char *path;

		path = gho_span_name (name, nr, exts[i]);
		if (!path)
			return NULL;
		if (image->spans[0].file->fs
		    && grub_strcmp (image->spans[0].file->fs->name, "winfile") == 0)
			file = grub_winfile_open (path, GRUB_FILE_TYPE_LOOPBACK
						     | GRUB_FILE_TYPE_NO_DECOMPRESS);
		else
			file = grub_file_open (path, GRUB_FILE_TYPE_LOOPBACK
						 | GRUB_FILE_TYPE_NO_DECOMPRESS);
		grub_free (path);
		grub_errno = GRUB_ERR_NONE;
		if (!file)
			continue;

		if (grub_file_size (file) > GRUB_GHOST_HEADER_SIZE
		    && grub_file_size (file) != GRUB_FILE_SIZE_UNKNOWN
		    && grub_file_read (file, hdr, sizeof (hdr)) == (grub_ssize_t) sizeof (hdr)
		    && hdr[0] == 0xfe && hdr[1] == 0xef
		    && hdr[2] == GRUB_GHOST_FILE_SPAN && hdr[3] == image->comp
		    && grub_ghost_get32 (hdr + 4) == image->id + nr)
			return file;

		grub_file_close (file);
		grub_errno = GRUB_ERR_NONE;
	}
	return NULL;
}

static grub_err_t
gho_open_spans (struct gho_image *image, const char *name)
{
	unsigned nr;

	if (!name)
		return GRUB_ERR_NONE;

	for (nr = 1; nr <= GHO_MAX_SPANS; nr++)
	{
		grub_file_t file;
		grub_err_t err;

		file = gho_open_span (image, name, nr);
		if (!file)
			break;
		err = gho_add_span (image, file, GRUB_GHOST_HEADER_SIZE);
		if (err)
		{
			grub_file_close (file);
			return err;
		}
	}
	/* Running out of spans is the normal way out of the loop.  */
	grub_errno = GRUB_ERR_NONE;
	return GRUB_ERR_NONE;
}

/* Find the partition header that introduces the block chain.  The area
   between it and the file header is an opaque descriptor blob whose
   length is not recorded anywhere, so it is scanned over.  */
static grub_err_t
gho_find_data_start (struct gho_image *image, grub_uint8_t *scan,
		     grub_uint8_t *subtype)
{
	grub_uint64_t limit = image->spans[0].size;
	grub_uint64_t pos = GRUB_GHOST_HEADER_SIZE;

	if (limit > GHO_HEADER_SCAN_MAX)
		limit = GHO_HEADER_SCAN_MAX;

	while (pos + GRUB_GHOST_HEADER_SIZE <= limit)
	{
		grub_size_t len;
		grub_size_t i;
		grub_err_t err;

		len = GHO_SCAN_BUF;
		if (len > limit - pos)
			len = (grub_size_t) (limit - pos);
		err = gho_pread (image, pos, scan, len);
		if (err)
			return err;

		for (i = 0; i + 8 <= len; i++)
			if (scan[i] == 0xfe && scan[i + 1] == 0xef
			    && scan[i + 3] == image->comp
			    && grub_ghost_get32 (scan + i + 4) == image->id)
			{
				*subtype = scan[i + 2];
				image->data_start = pos + i + GRUB_GHOST_HEADER_SIZE;
				return GRUB_ERR_NONE;
			}

		if (len < 8)
			break;
		pos += len - 7;
	}
	return grub_error (GRUB_ERR_BAD_SIGNATURE, "no Ghost partition header");
}

static int
gho_ntfs_id_packet (const grub_uint8_t *p, grub_uint16_t *id,
		    grub_uint64_t *value)
{
	unsigned i;

	if (p[0] != 0x0e || p[15] != 0x0f)
		return 0;
	for (i = 3; i < 7; i++)
		if (p[i] != 0)
			return 0;
	*id = grub_ghost_get16 (p + 1);
	*value = grub_get_unaligned64 (p + 7);
	return 1;
}

/* GHPR metadata has no length field.  Its final checksum packet is
   immediately followed by the first compressed NTFS packet, so use
   that pair as the stream delimiter.  */
static grub_err_t
gho_find_ntfs_data_start (struct gho_image *image, grub_uint8_t *scan)
{
	grub_uint64_t limit = image->stream_size;
	grub_uint64_t pos = image->data_start;

	if (limit > image->data_start + GHO_HEADER_SCAN_MAX)
		limit = image->data_start + GHO_HEADER_SCAN_MAX;
	while (pos + 12 <= limit)
	{
		grub_size_t len = GHO_SCAN_BUF;
		grub_size_t i;
		grub_err_t err;

		if (len > limit - pos)
			len = (grub_size_t) (limit - pos);
		err = gho_pread (image, pos, scan, len);
		if (err)
			return err;
		for (i = 0; i + 12 <= len; i++)
		{
			grub_size_t outlen;
			grub_uint16_t id;
			grub_uint64_t value;
			grub_uint64_t candidate;

			if (scan[i] != 0x0a || scan[i + 9] != 0x0b)
				continue;
			candidate = pos + i + 10;
			if (grub_ghost_get16 (scan + i + 10) < GRUB_GHOST_STORED_MIN)
				continue;
			err = gho_decode_block (image, candidate, image->blk_buf,
						GRUB_GHOST_BLOCK_MAX, &outlen);
			if (!err && outlen == 16
			    && gho_ntfs_id_packet (image->blk_buf, &id, &value)
			    && (id & 0x8000) != 0)
			{
				image->data_start = candidate;
				return GRUB_ERR_NONE;
			}
			grub_errno = GRUB_ERR_NONE;
		}
		if (len < 11)
			break;
		pos += len - 11;
	}
	return grub_error (GRUB_ERR_BAD_SIGNATURE, "no Ghost NTFS data stream");
}

static grub_err_t
gho_add_ntfs_block (struct gho_image *image, grub_uint32_t *capacity,
		    grub_uint64_t phys, grub_uint64_t logical,
		    grub_uint32_t len)
{
	if (image->nntfs_blocks == *capacity)
	{
		struct gho_ntfs_block *blocks;
		grub_uint32_t want = *capacity ? *capacity * 2 : 1024;
		grub_size_t sz;

		if (want > GHO_MAX_BLOCKS)
			want = GHO_MAX_BLOCKS;
		if (want == *capacity
		    || grub_mul ((grub_size_t) want, sizeof (*blocks), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost NTFS stream too large");
		blocks = grub_realloc (image->ntfs_blocks, sz);
		if (!blocks)
			return grub_errno;
		image->ntfs_blocks = blocks;
		*capacity = want;
	}
	image->ntfs_blocks[image->nntfs_blocks].phys = phys;
	image->ntfs_blocks[image->nntfs_blocks].logical = logical;
	image->ntfs_blocks[image->nntfs_blocks].len = len;
	image->nntfs_blocks++;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_build_ntfs_block_index (struct gho_image *image)
{
	grub_uint64_t pos = image->data_start;
	grub_uint64_t logical = 0;
	grub_uint32_t capacity = 0;

	while (pos + 2 <= image->stream_size)
	{
		grub_uint8_t prefix[2];
		grub_uint32_t stored;
		grub_size_t outlen;
		grub_err_t err;

		err = gho_pread (image, pos, prefix, sizeof (prefix));
		if (err)
			return err;
		stored = grub_ghost_get16 (prefix);
		if (stored < GRUB_GHOST_STORED_MIN || stored > image->stream_size - pos)
			break;
		err = gho_decode_block (image, pos, image->blk_buf,
					GRUB_GHOST_BLOCK_MAX, &outlen);
		if (err)
			return err;
		if (outlen == 0 || outlen > GRUB_GHOST_BLOCK_MAX
		    || logical > ~((grub_uint64_t) 0) - outlen)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					   "bad Ghost NTFS block");
		err = gho_add_ntfs_block (image, &capacity, pos, logical,
					  (grub_uint32_t) outlen);
		if (err)
			return err;
		logical += outlen;
		pos += stored;
	}
	if (image->nntfs_blocks == 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "empty Ghost NTFS stream");
	image->ntfs_stream_size = logical;
	image->cached_nr = GHO_CACHE_NONE;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_ntfs_read_id (struct gho_image *image, grub_uint64_t *pos,
		  grub_uint16_t *id, grub_uint64_t *value)
{
	grub_uint8_t packet[16];
	grub_err_t err;

	err = gho_ntfs_pread (image, *pos, packet, sizeof (packet));
	if (err)
		return err;
	if (!gho_ntfs_id_packet (packet, id, value))
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "bad Ghost NTFS id packet");
	*pos += sizeof (packet);
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_ntfs_read_data_packet (struct gho_image *image, grub_uint64_t *pos,
			   grub_uint32_t *value)
{
	grub_uint8_t packet[10];
	grub_err_t err;
	unsigned i;

	err = gho_ntfs_pread (image, *pos, packet, sizeof (packet));
	if (err)
		return err;
	if (packet[0] != 0x0f || packet[9] != 0x0e)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "bad Ghost NTFS data packet");
	for (i = 5; i < 9; i++)
		if (packet[i] != 0)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					   "bad Ghost NTFS data packet");
	*value = grub_ghost_get32 (packet + 1);
	*pos += sizeof (packet);
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_ntfs_skip_crc (struct gho_image *image, grub_uint64_t *pos)
{
	grub_uint8_t packet[10];
	grub_err_t err;

	if (*pos >= image->ntfs_stream_size)
		return GRUB_ERR_NONE;
	err = gho_ntfs_pread (image, *pos, packet, 1);
	if (err)
		return err;
	if (packet[0] != 0x0a)
		return GRUB_ERR_NONE;
	if (image->ntfs_stream_size - *pos < sizeof (packet))
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "truncated Ghost NTFS checksum");
	err = gho_ntfs_pread (image, *pos, packet, sizeof (packet));
	if (err)
		return err;
	if (packet[9] != 0x0b)
		return GRUB_ERR_NONE;
	*pos += sizeof (packet);
	return GRUB_ERR_NONE;
}

static int
gho_ntfs_boundary (struct gho_image *image, grub_uint64_t pos)
{
	grub_uint8_t packet[16];
	grub_uint16_t id;
	grub_uint64_t value;

	if (pos == image->ntfs_stream_size)
		return 1;
	if (image->ntfs_stream_size - pos >= 10
	    && gho_ntfs_pread (image, pos, packet, 10) == GRUB_ERR_NONE
	    && packet[0] == 0x0a && packet[9] == 0x0b)
		pos += 10;
	grub_errno = GRUB_ERR_NONE;
	if (image->ntfs_stream_size - pos < sizeof (packet)
	    || gho_ntfs_pread (image, pos, packet, sizeof (packet)) != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	return gho_ntfs_id_packet (packet, &id, &value);
}

static grub_err_t
gho_ntfs_infer_cluster_size (struct gho_image *image, grub_uint64_t pos,
			     grub_uint64_t clusters)
{
	grub_uint32_t candidate;
	grub_uint32_t found = 0;

	for (candidate = 512; candidate <= 65536; candidate <<= 1)
	{
		grub_uint64_t bytes;

		if (clusters > (~((grub_uint64_t) 0) / candidate))
			continue;
		bytes = clusters * candidate;
		if (bytes <= image->ntfs_stream_size - pos
		    && gho_ntfs_boundary (image, pos + bytes))
		{
			if (found != 0)
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
						   "ambiguous Ghost NTFS cluster size");
			found = candidate;
		}
	}
	if (found == 0)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "cannot determine Ghost NTFS cluster size");
	image->cluster_size = found;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_add_ntfs_extent (struct gho_image *image, grub_uint32_t *capacity,
		     grub_uint64_t disk, grub_uint64_t stream,
		     grub_uint64_t len)
{
	if (image->nextents == *capacity)
	{
		struct gho_ntfs_extent *extents;
		grub_uint32_t want = *capacity ? *capacity * 2 : 4096;
		grub_size_t sz;

		if (want > GHO_MAX_EXTENTS)
			want = GHO_MAX_EXTENTS;
		if (want == *capacity
		    || grub_mul ((grub_size_t) want, sizeof (*extents), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many Ghost NTFS extents");
		extents = grub_realloc (image->extents, sz);
		if (!extents)
			return grub_errno;
		image->extents = extents;
		*capacity = want;
	}
	image->extents[image->nextents].disk = disk;
	image->extents[image->nextents].stream = stream;
	image->extents[image->nextents].len = len;
	image->nextents++;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_ntfs_fixup (grub_uint8_t *record, grub_uint32_t size)
{
	grub_uint16_t usa;
	grub_uint16_t count;
	grub_uint32_t sector_size;
	grub_uint16_t marker;
	unsigned i;

	if (size < 0x30 || grub_memcmp (record, "FILE", 4) != 0)
		return GRUB_ERR_NONE;
	usa = grub_ghost_get16 (record + 4);
	count = grub_ghost_get16 (record + 6);
	if (count < 2 || usa > size || (grub_uint32_t) count * 2 > size - usa
	    || size % (count - 1) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "bad NTFS fixup in Ghost image");
	sector_size = size / (count - 1);
	marker = grub_ghost_get16 (record + usa);
	for (i = 1; i < count; i++)
	{
		grub_uint32_t at = i * sector_size - 2;
		grub_uint16_t replacement = grub_ghost_get16 (record + usa + i * 2);

		if (grub_ghost_get16 (record + at) == replacement)
			continue;
		if (grub_ghost_get16 (record + at) != marker)
			return grub_error (GRUB_ERR_BAD_FS, "bad NTFS fixup in Ghost image");
		record[at] = record[usa + i * 2];
		record[at + 1] = record[usa + i * 2 + 1];
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_ntfs_check_boot (struct gho_image *image, grub_uint64_t stream)
{
	grub_uint8_t boot[512];
	grub_uint32_t bytes_per_sector;
	grub_uint32_t cluster_size;
	grub_uint64_t sectors;
	grub_err_t err;

	err = gho_ntfs_pread (image, stream, boot, sizeof (boot));
	if (err)
		return err;
	if (grub_memcmp (boot + 3, "NTFS    ", 8) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "bad NTFS boot sector in Ghost image");
	bytes_per_sector = grub_ghost_get16 (boot + 0x0b);
	if (bytes_per_sector < 512 || bytes_per_sector > 4096
	    || (bytes_per_sector & (bytes_per_sector - 1)) != 0 || boot[0x0d] == 0)
		return grub_error (GRUB_ERR_BAD_FS, "bad NTFS geometry in Ghost image");
	cluster_size = bytes_per_sector * boot[0x0d];
	if (cluster_size != image->cluster_size)
		return grub_error (GRUB_ERR_BAD_FS, "Ghost NTFS cluster size mismatch");
	sectors = grub_get_unaligned64 (boot + 0x28);
	if (sectors == 0 || sectors > ~((grub_uint64_t) 0) / bytes_per_sector)
		return grub_error (GRUB_ERR_BAD_FS, "bad NTFS size in Ghost image");
	image->total_bytes = sectors * bytes_per_sector;
	return GRUB_ERR_NONE;
}

static grub_int64_t
gho_ntfs_signed (const grub_uint8_t *p, unsigned size)
{
	grub_uint64_t value = 0;
	unsigned i;

	for (i = 0; i < size; i++)
		value |= (grub_uint64_t) p[i] << (i * 8);
	if (size < 8 && (p[size - 1] & 0x80) != 0)
		value |= ~((grub_uint64_t) 0) << (size * 8);
	return (grub_int64_t) value;
}

static grub_err_t
gho_ntfs_map_attribute (struct gho_image *image, grub_uint8_t *record,
			grub_uint32_t attr, grub_uint64_t *pos,
			grub_uint32_t *capacity)
{
	grub_uint32_t attr_len = grub_ghost_get32 (record + attr + 4);
	grub_uint32_t run = attr + grub_ghost_get16 (record + attr + 0x20);
	grub_uint32_t end = attr + attr_len;
	grub_int64_t lcn = 0;
	grub_uint16_t id;
	grub_uint64_t value;
	grub_uint64_t run_index = 0;
	grub_err_t err;

	err = gho_ntfs_read_id (image, pos, &id, &value);
	if (err)
		return err;
	if (id == 0x8040)
		return gho_ntfs_skip_crc (image, pos);
	if (id != 0x8020 || run >= end)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "bad Ghost NTFS attribute packet");

	while (run < end && record[run] != 0)
	{
		grub_uint8_t head = record[run++];
		unsigned len_size = head & 0x0f;
		unsigned off_size = head >> 4;
		grub_uint64_t clusters = 0;
		grub_uint64_t bytes;
		grub_uint64_t disk_base;
		grub_uint64_t done = 0;
		unsigned i;

		if (len_size == 0 || len_size > 8 || off_size > 8
		    || run + len_size + off_size > end)
			return grub_error (GRUB_ERR_BAD_FS, "bad NTFS runlist in Ghost image");
		for (i = 0; i < len_size; i++)
			clusters |= (grub_uint64_t) record[run + i] << (i * 8);
		run += len_size;
		if (off_size != 0)
		{
			grub_int64_t delta = gho_ntfs_signed (record + run, off_size);

			if ((delta > 0
			     && lcn > (grub_int64_t) 0x7fffffffffffffffULL - delta)
			    || (delta < 0
				&& lcn < (grub_int64_t) 0x8000000000000000ULL - delta))
				return grub_error (GRUB_ERR_OUT_OF_RANGE, "NTFS run overflow");
			lcn += delta;
		}
		run += off_size;

		err = gho_ntfs_read_id (image, pos, &id, &value);
		if (err)
			return err;
		if (id != 0x0002 || value != run_index++)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					   "bad Ghost NTFS run packet");
		if (off_size == 0)
			continue;
		if (lcn < 0 || clusters == 0)
			return grub_error (GRUB_ERR_BAD_FS, "bad NTFS run in Ghost image");
		{
			grub_uint32_t stored_clusters;

			err = gho_ntfs_read_data_packet (image, pos, &stored_clusters);
			if (err)
				return err;
			if (stored_clusters != clusters)
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
						   "Ghost NTFS run length mismatch");
		}
		if (image->cluster_size == 0)
		{
			err = gho_ntfs_infer_cluster_size (image, *pos, clusters);
			if (err)
				return err;
		}
		if (clusters > ~((grub_uint64_t) 0) / image->cluster_size)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost NTFS run too large");
		bytes = clusters * image->cluster_size;
		if (bytes > image->ntfs_stream_size - *pos
		    || (grub_uint64_t) lcn > ~((grub_uint64_t) 0) / image->cluster_size)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					   "truncated Ghost NTFS run");
		disk_base = (grub_uint64_t) lcn * image->cluster_size;
		if (disk_base > ~((grub_uint64_t) 0) - bytes)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost NTFS run too large");
		while (done < bytes)
		{
			grub_uint64_t take = bytes - done;
			grub_uint64_t disk = disk_base + done;

			if (take > GHO_NTFS_FRAGMENT)
				take = GHO_NTFS_FRAGMENT;
			err = gho_add_ntfs_extent (image, capacity, disk, *pos, take);
			if (err)
				return err;
			if (disk == 0 && image->total_bytes == 0)
			{
				err = gho_ntfs_check_boot (image, *pos);
				if (err)
					return err;
			}
			*pos += take;
			done += take;
			err = gho_ntfs_skip_crc (image, pos);
			if (err)
				return err;
		}
	}
	return GRUB_ERR_NONE;
}

static int
gho_ntfs_extent_before (const struct gho_ntfs_extent *a,
			const struct gho_ntfs_extent *b)
{
	if (a->disk != b->disk)
		return a->disk < b->disk;
	return a->stream > b->stream;
}

static void
gho_ntfs_extent_sift (struct gho_ntfs_extent *ext, grub_size_t root,
		      grub_size_t n)
{
	while (1)
	{
		struct gho_ntfs_extent tmp;
		grub_size_t child = 2 * root + 1;

		if (child >= n)
			return;
		if (child + 1 < n
		    && gho_ntfs_extent_before (&ext[child], &ext[child + 1]))
			child++;
		if (!gho_ntfs_extent_before (&ext[root], &ext[child]))
			return;
		tmp = ext[root];
		ext[root] = ext[child];
		ext[child] = tmp;
		root = child;
	}
}

static void
gho_ntfs_sort_extents (struct gho_image *image)
{
	grub_size_t i;

	for (i = image->nextents / 2; i > 0; i--)
		gho_ntfs_extent_sift (image->extents, i - 1, image->nextents);
	for (i = image->nextents; i > 1; i--)
	{
		struct gho_ntfs_extent tmp = image->extents[0];

		image->extents[0] = image->extents[i - 1];
		image->extents[i - 1] = tmp;
		gho_ntfs_extent_sift (image->extents, 0, i - 1);
	}
}

static void
gho_ntfs_drop_overlaps (struct gho_image *image)
{
	grub_uint64_t covered = 0;
	grub_size_t i;
	grub_size_t out = 0;

	for (i = 0; i < image->nextents; i++)
	{
		struct gho_ntfs_extent extent = image->extents[i];

		if (extent.disk < covered)
		{
			grub_uint64_t skip = covered - extent.disk;

			if (skip >= extent.len)
				continue;
			extent.disk += skip;
			extent.stream += skip;
			extent.len -= skip;
		}
		covered = extent.disk + extent.len;
		image->extents[out++] = extent;
	}
	image->nextents = (grub_uint32_t) out;
}

static grub_err_t
gho_build_ntfs_extents (struct gho_image *image)
{
	grub_uint8_t *record;
	grub_uint64_t pos = 0;
	grub_uint32_t capacity = 0;
	grub_uint32_t records = 0;
	grub_err_t err = GRUB_ERR_NONE;

	record = grub_malloc (GHO_NTFS_RECORD_MAX);
	if (!record)
		return grub_errno;
	while (image->ntfs_stream_size - pos >= 16)
	{
		grub_uint8_t packet[16];
		grub_uint16_t id;
		grub_uint64_t mft;
		grub_uint32_t record_size;
		grub_uint32_t attr;
		grub_uint32_t used;

		err = gho_ntfs_pread (image, pos, packet, sizeof (packet));
		if (err)
			goto fail;
		if (!gho_ntfs_id_packet (packet, &id, &mft))
			break;
		if (id != 0x8004 && id != 0x8008 && id != 0x8010)
			break;
		pos += sizeof (packet);
		err = gho_ntfs_read_data_packet (image, &pos, &record_size);
		if (err)
			goto fail;
		if (record_size < 0x30 || record_size > GHO_NTFS_RECORD_MAX
		    || record_size > image->ntfs_stream_size - pos)
		{
			err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					  "bad Ghost NTFS record size");
			goto fail;
		}
		err = gho_ntfs_pread (image, pos, record, record_size);
		if (err)
			goto fail;
		pos += record_size;
		records++;
		if (id == 0x8004 && grub_memcmp (record, "FILE", 4) == 0)
		{
			err = gho_ntfs_fixup (record, record_size);
			if (err)
				goto fail;
			attr = grub_ghost_get16 (record + 0x14);
			used = grub_ghost_get32 (record + 0x18);
			if (used > record_size)
				used = record_size;
			while (attr + 16 <= used)
			{
				grub_uint32_t type = grub_ghost_get32 (record + attr);
				grub_uint32_t attr_len = grub_ghost_get32 (record + attr + 4);

				if (type == 0xffffffff)
					break;
				if (attr_len < 16 || attr_len > used - attr)
				{
					err = grub_error (GRUB_ERR_BAD_FS,
							  "bad NTFS attribute in Ghost image");
					goto fail;
				}
				if (record[attr + 8] != 0)
				{
					if (attr_len < 0x40)
					{
						err = grub_error (GRUB_ERR_BAD_FS,
								  "short NTFS runlist in Ghost image");
						goto fail;
					}
					err = gho_ntfs_map_attribute (image, record, attr,
							      &pos, &capacity);
					if (err)
						goto fail;
				}
				attr += attr_len;
			}
		}
		err = gho_ntfs_skip_crc (image, &pos);
		if (err)
			goto fail;
	}
	if (records == 0 || image->nextents == 0 || image->total_bytes == 0)
	{
		err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				  "incomplete Ghost NTFS stream");
		goto fail;
	}
	gho_ntfs_sort_extents (image);
	gho_ntfs_drop_overlaps (image);
	grub_free (record);
	return GRUB_ERR_NONE;

fail:
	grub_free (record);
	return err;
}

static grub_err_t
gho_add_block (struct gho_image *image, grub_uint32_t *capacity,
	       grub_uint64_t pos)
{
	if (image->nblocks == *capacity)
	{
		grub_uint64_t *blocks;
		grub_uint32_t want;
		grub_size_t sz;

		want = *capacity ? *capacity * 2 : 1024;
		if (want > GHO_MAX_BLOCKS)
			want = GHO_MAX_BLOCKS;
		if (want == *capacity)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost image too large");
		if (grub_mul ((grub_size_t) want, sizeof (*blocks), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost image too large");
		blocks = grub_realloc (image->blocks, sz);
		if (!blocks)
			return grub_errno;
		image->blocks = blocks;
		*capacity = want;
	}
	image->blocks[image->nblocks++] = pos;
	return GRUB_ERR_NONE;
}

/*
 * Walk the chain once and remember where every block starts.  Only two
 * bytes per block matter, but they sit one block apart, so this ends up
 * streaming the whole image past the reader - there is no index in the
 * format to shortcut it.
 */
static grub_err_t
gho_build_index (struct gho_image *image, grub_uint8_t *scan)
{
	grub_uint64_t pos = image->data_start;
	grub_uint64_t buf_at = 0;
	grub_size_t buf_len = 0;
	grub_uint32_t capacity = 0;
	grub_err_t err;

	while (pos + 2 <= image->stream_size)
	{
		const grub_uint8_t *p;
		grub_size_t avail;
		grub_uint32_t stored;

		if (buf_len == 0 || pos < buf_at
		    || pos + GRUB_GHOST_REC_HDR_SIZE > buf_at + buf_len)
		{
			buf_len = GHO_SCAN_BUF;
			if (buf_len > image->stream_size - pos)
				buf_len = (grub_size_t) (image->stream_size - pos);
			err = gho_pread (image, pos, scan, buf_len);
			if (err)
				return err;
			buf_at = pos;
		}
		p = scan + (pos - buf_at);
		avail = buf_len - (grub_size_t) (pos - buf_at);

		if (avail >= 8 && grub_ghost_get32 (p + 4) == GRUB_GHOST_REC_MAGIC)
		{
			grub_uint8_t next[8];

			/* Any other record ends the image.  */
			if (avail < GRUB_GHOST_REC_HDR_SIZE
			    || (grub_ghost_get16 (p) != GHO_REC_CONTINUE))
				break;
			pos += GRUB_GHOST_REC_HDR_SIZE + grub_ghost_get16 (p + 8);

			/* The resumed chain may be re-introduced by a
			   fresh partition header.  */
			if (pos + GRUB_GHOST_HEADER_SIZE <= image->stream_size
			    && gho_pread (image, pos, next, sizeof (next)) == GRUB_ERR_NONE
			    && next[0] == 0xfe && next[1] == 0xef
			    && grub_ghost_get32 (next + 4) == image->id)
				pos += GRUB_GHOST_HEADER_SIZE;
			grub_errno = GRUB_ERR_NONE;
			buf_len = 0;
			continue;
		}

		stored = grub_ghost_get16 (p);
		if (stored < GRUB_GHOST_STORED_MIN || stored > image->stream_size - pos)
			break;
		err = gho_add_block (image, &capacity, pos);
		if (err)
			return err;
		pos += stored;
	}

	if (image->nblocks == 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "no Ghost sector data");
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_open_image (struct gho_image *image, grub_file_t io, const char *name)
{
	grub_uint8_t hdr[GRUB_GHOST_HEADER_SIZE];
	grub_uint8_t *scan = NULL;
	grub_uint8_t subtype = 0;
	grub_size_t n;
	grub_err_t err;

	err = gho_add_span (image, io, 0);
	if (err)
		return err;

	err = gho_pread (image, 0, hdr, sizeof (hdr));
	if (err)
		return err;
	if (hdr[0] != 0xfe || hdr[1] != 0xef)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "not a Ghost image");
	if (hdr[2] != GRUB_GHOST_FILE_PRIMARY)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "not the first file of a Ghost image");
	if (!grub_ghost_comp_supported (hdr[3]))
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "unsupported Ghost compression type %u", hdr[3]);
	image->comp = hdr[3];
	image->id = grub_ghost_get32 (hdr + 4);

	err = gho_open_spans (image, name);
	if (err)
		return err;

	image->blk_buf = grub_malloc (GRUB_GHOST_BLOCK_MAX);
	image->cmp_buf = grub_malloc (GRUB_GHOST_STORED_MAX);
	image->hash_tbl = grub_calloc (GRUB_GHOST_FASTLZ_HASH_SIZE,
				       sizeof (*image->hash_tbl));
	scan = grub_malloc (GHO_SCAN_BUF);
	if (!image->blk_buf || !image->cmp_buf || !image->hash_tbl || !scan)
	{
		err = grub_errno;
		goto fail;
	}

	err = gho_find_data_start (image, scan, &subtype);
	if (err)
		goto fail;
	if (image->comp == GRUB_GHOST_COMP_NTFS
	    && subtype == GRUB_GHOST_PART_NTFS)
	{
		err = gho_find_ntfs_data_start (image, scan);
		if (err)
			goto fail;
		err = gho_build_ntfs_block_index (image);
		if (err)
			goto fail;
		err = gho_build_ntfs_extents (image);
		if (err)
			goto fail;
		image->ntfs = 1;
		image->cached_nr = GHO_CACHE_NONE;
		grub_free (scan);
		return GRUB_ERR_NONE;
	}

	/* File based images put a record where a sector image puts its
	   first block.  They hold a directory tree rather than sectors,
	   so leave them to fs\gho.c - but if the catalogue continues into
	   span files, hand the browser the spliced stream.  */
	err = gho_pread (image, image->data_start, hdr, 8);
	if (err)
		goto fail;
	if (grub_ghost_get32 (hdr + 4) == GRUB_GHOST_REC_MAGIC
	    || subtype != GRUB_GHOST_PART_SECTOR)
	{
		if (image->nspans < 2)
		{
			err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
					  "file based Ghost image, nothing to decode");
			goto fail;
		}
		image->raw = 1;
		image->total_bytes = image->stream_size;
		grub_free (scan);
		return GRUB_ERR_NONE;
	}

	/* The first block fixes the block size.  */
	err = gho_decode_block (image, image->data_start, image->blk_buf,
				GRUB_GHOST_BLOCK_MAX, &n);
	if (err)
		goto fail;
	if (n < GRUB_DISK_SECTOR_SIZE || n > GRUB_GHOST_BLOCK_MAX
	    || (n & (GRUB_DISK_SECTOR_SIZE - 1)) != 0)
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE, "bad Ghost block size %" PRIuGRUB_SIZE, n);
		goto fail;
	}
	image->block_size = (grub_uint32_t) n;

	err = gho_build_index (image, scan);
	if (err)
		goto fail;

	/* Only the final block may be short.  */
	err = gho_decode_block (image, image->blocks[image->nblocks - 1],
				image->blk_buf, GRUB_GHOST_BLOCK_MAX, &n);
	if (err)
		goto fail;
	if (n == 0 || n > image->block_size)
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE, "bad final Ghost block");
		goto fail;
	}
	image->total_bytes = (grub_uint64_t) (image->nblocks - 1) * image->block_size + n;
	image->cached_nr = GHO_CACHE_NONE;

	grub_free (scan);
	return GRUB_ERR_NONE;

fail:
	grub_free (scan);
	return err;
}

/* ------------------------------------------------------------------ */
/* io filter wrapper                                                   */

struct grub_gho
{
	grub_file_t file;
	struct gho_image *gho;
};
typedef struct grub_gho *grub_gho_t;

static struct grub_fs grub_gho_fs;

static grub_err_t
grub_gho_close (grub_file_t file)
{
	grub_gho_t ghoio = file->data;

	gho_free_image (ghoio->gho);
	grub_free (ghoio->gho);
	grub_file_close (ghoio->file);
	grub_free (ghoio);
	/* The inner close released the shared device; the outer name is
	   freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_gho_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_gho_t ghoio;
	struct gho_image *image;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size <= GRUB_GHOST_HEADER_SIZE || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;

	/* gho_open_image makes IO the first span; gho_free_image leaves
	   it alone because the outer close owns it.  */
	if (gho_open_image (image, io, io->name) != GRUB_ERR_NONE)
	{
		gho_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	ghoio = grub_zalloc (sizeof (*ghoio));
	if (!file || !ghoio)
	{
		gho_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (ghoio);
		return 0;
	}
	ghoio->file = io;
	ghoio->gho = image;

	file->device = io->device;
	file->data = ghoio;
	file->fs = &grub_gho_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;

	return file;
}

static grub_ssize_t
grub_gho_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_gho_t ghoio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = gho_read (ghoio->gho, read_offset, buf, len, &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR, "Ghost read made no progress");
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
			grub_error (err, "Ghost image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_gho_fs =
{
	.name = "gho",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_gho_read,
	.fs_close = grub_gho_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (gho)
{
	grub_file_filter_register (GRUB_FILE_FILTER_GHO, grub_gho_open);
}

GRUB_MOD_FINI (gho)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_GHO);
}
