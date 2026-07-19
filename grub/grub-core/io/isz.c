/* isz.c - UltraISO ISZ compressed ISO image io filter */
/*
 *  Rover -- GRUB 2 filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  Implemented from the ISZ File Format Specification 1.00
 *  (EZB Systems, 2006), see ref\iszspec.txt.
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
 * Supported: single-file images with zero / raw / zlib / bzip2 chunks,
 * with or without a chunk definition table (no table = raw contiguous
 * data).  Not supported: segmented images (.i01 sibling files) and
 * AES encryption (the spec does not define the password key
 * derivation, so it cannot be implemented from it).
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/deflate.h>
#include <grub/safemath.h>

#include <bzlib.h>

GRUB_MOD_LICENSE ("GPLv3+");

/* has_password */
#define ISZ_ENC_PLAIN		0

/* chunk_flag: top two bits of a chunk table entry
   (0x00 / 0x40 / 0x80 / 0xc0 in the most significant byte) */
#define ISZ_CHUNK_ZERO		0	/* all zeros, no stored data */
#define ISZ_CHUNK_DATA		1	/* raw data */
#define ISZ_CHUNK_ZLIB		2	/* zlib stream */
#define ISZ_CHUNK_BZ2		3	/* bzip2 stream */

/* Sanity caps against corrupt images.  */
#define ISZ_BLOCK_SIZE_MAX	(16u << 20)
#define ISZ_NCHUNKS_MAX		(4u << 20)

#define ISZ_CACHE_NONE		0xffffffffu

/* UltraISO obfuscates the SDT and CDT with this repeating XOR key.
   The public specification omits this on-disk detail.  */
static const grub_uint8_t isz_table_key[] = { 0xb6, 0x8c, 0xa5, 0xde };

PRAGMA_BEGIN_PACKED
struct isz_header
{
	grub_uint8_t signature[4];	/* "IsZ!" */
	grub_uint8_t header_size;
	grub_uint8_t ver;
	grub_uint32_t vsn;		/* volume serial number */
	grub_uint16_t sect_size;	/* bytes per sector, 2048 for ISO */
	grub_uint32_t total_sectors;
	grub_uint8_t has_password;
	grub_uint64_t segment_size;
	grub_uint32_t nblocks;		/* chunks in the whole image */
	grub_uint32_t block_size;	/* uncompressed chunk size */
	grub_uint8_t ptr_len;		/* bytes per chunk table entry */
	grub_uint8_t seg_no;
	grub_uint32_t ptr_offs;		/* chunk table offset, 0 = none */
	grub_uint32_t seg_offs;		/* segment table offset, 0 = single file */
	grub_uint32_t data_offs;	/* chunk data offset */
	grub_uint8_t reserved;
};
PRAGMA_END_PACKED

struct isz_chunk
{
	grub_uint64_t file_off;		/* stored data offset in the .isz */
	grub_uint32_t stored_len;	/* stored (possibly compressed) bytes */
	grub_uint8_t flag;		/* ISZ_CHUNK_* */
};

struct isz_image
{
	grub_file_t file;
	grub_uint64_t total_bytes;
	grub_uint64_t data_offs;
	grub_uint32_t block_size;
	grub_uint32_t nchunks;
	struct isz_chunk *chunks;	/* NULL: raw contiguous data */

	/* last decoded chunk (sequential reads revisit chunks) */
	grub_uint32_t cached_nr;
	grub_uint8_t *chunk_buf;	/* block_size bytes */
	grub_uint8_t *comp_buf;		/* block_size bytes */
};

static grub_err_t
isz_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (file)
	    || len > grub_file_size (file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "isz file truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "isz file truncated");
	return GRUB_ERR_NONE;
}

static void
isz_free_image (struct isz_image *image)
{
	grub_free (image->chunks);
	image->chunks = NULL;
	grub_free (image->chunk_buf);
	image->chunk_buf = NULL;
	grub_free (image->comp_buf);
	image->comp_buf = NULL;
}

static grub_err_t
isz_open_image (struct isz_image *image)
{
	struct isz_header hdr;
	grub_uint64_t file_size = grub_file_size (image->file);
	grub_uint64_t total;
	grub_uint64_t nchunks;
	grub_uint64_t table_bytes;
	grub_uint64_t cur;
	grub_uint64_t len_mask;
	grub_uint32_t sect_size, block_size, ptr_offs;
	grub_uint32_t i;
	grub_size_t table_pos;
	unsigned ptr_len, bits;
	grub_uint8_t *raw = NULL;
	grub_err_t err;

	err = isz_pread (image->file, 0, &hdr, sizeof (hdr));
	if (err)
		return err;
	if (grub_memcmp (hdr.signature, "IsZ!", 4) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "not an ISZ image");
	if (hdr.header_size < sizeof (hdr))
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ISZ header size");

	sect_size = grub_le_to_cpu16 (hdr.sect_size);
	block_size = grub_le_to_cpu32 (hdr.block_size);
	ptr_offs = grub_le_to_cpu32 (hdr.ptr_offs);
	total = (grub_uint64_t) grub_le_to_cpu32 (hdr.total_sectors) * sect_size;

	if (sect_size == 0 || total == 0
	    || block_size == 0 || block_size > ISZ_BLOCK_SIZE_MAX
	    || block_size % sect_size != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ISZ geometry");
	if (hdr.has_password != ISZ_ENC_PLAIN)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "password protected ISZ images are not supported");
	if (grub_le_to_cpu32 (hdr.seg_offs) != 0)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "segmented ISZ images are not supported");

	image->data_offs = grub_le_to_cpu32 (hdr.data_offs);
	if (image->data_offs >= file_size)
		return grub_error (GRUB_ERR_BAD_DEVICE, "ISZ image truncated");

	nchunks = (total + block_size - 1) / block_size;
	if (nchunks > ISZ_NCHUNKS_MAX
	    || grub_le_to_cpu32 (hdr.nblocks) < nchunks)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ISZ chunk count");

	image->total_bytes = total;
	image->block_size = block_size;
	image->nchunks = (grub_uint32_t) nchunks;

	if (ptr_offs == 0)
	{
		/* No chunk table: the ISO is stored raw and contiguous.  */
		if (total > file_size - image->data_offs)
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "ISZ image truncated");
		return GRUB_ERR_NONE;
	}

	ptr_len = hdr.ptr_len;
	if (ptr_len < 1 || ptr_len > 8)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ISZ pointer length");
	bits = ptr_len * 8;
	len_mask = (1ULL << (bits - 2)) - 1;

	table_bytes = (grub_uint64_t) image->nchunks * ptr_len;
	if (ptr_offs >= file_size || table_bytes > file_size - ptr_offs)
		return grub_error (GRUB_ERR_BAD_DEVICE, "ISZ image truncated");

	raw = grub_malloc ((grub_size_t) table_bytes);
	if (!raw)
		return grub_errno;
	err = isz_pread (image->file, ptr_offs, raw, (grub_size_t) table_bytes);
	if (err)
		goto fail;
	for (table_pos = 0; table_pos < (grub_size_t) table_bytes;
	     table_pos++)
		raw[table_pos] ^= isz_table_key[table_pos
						  % ARRAY_SIZE (isz_table_key)];

	image->chunks = grub_calloc (image->nchunks, sizeof (*image->chunks));
	if (!image->chunks)
	{
		err = grub_errno;
		goto fail;
	}

	/* Chunk data is stored back to back starting at data_offs; zero
	   chunks store nothing.  */
	cur = image->data_offs;
	for (i = 0; i < image->nchunks; i++)
	{
		const grub_uint8_t *p = raw + (grub_size_t) i * ptr_len;
		grub_uint64_t val = 0;
		grub_uint64_t blk_len;
		grub_uint8_t flag;
		unsigned j;

		for (j = 0; j < ptr_len; j++)
			val |= (grub_uint64_t) p[j] << (8 * j);
		flag = (grub_uint8_t) (val >> (bits - 2));
		blk_len = val & len_mask;

		if (blk_len > block_size)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "oversized ISZ chunk");
			goto fail;
		}
		if (blk_len == 0
		    && (flag == ISZ_CHUNK_ZLIB || flag == ISZ_CHUNK_BZ2))
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "empty compressed ISZ chunk");
			goto fail;
		}

		image->chunks[i].file_off = cur;
		image->chunks[i].flag = flag;
		if (flag != ISZ_CHUNK_ZERO)
		{
			image->chunks[i].stored_len = (grub_uint32_t) blk_len;
			if (grub_add (cur, blk_len, &cur))
			{
				err = grub_error (GRUB_ERR_OUT_OF_RANGE,
						  "ISZ chunk layout overflow");
				goto fail;
			}
		}
	}
	if (cur > file_size)
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE, "ISZ image truncated");
		goto fail;
	}

	image->chunk_buf = grub_malloc (block_size);
	image->comp_buf = grub_malloc (block_size);
	if (!image->chunk_buf || !image->comp_buf)
	{
		err = grub_errno;
		goto fail;
	}
	image->cached_nr = ISZ_CACHE_NONE;

	grub_free (raw);
	return GRUB_ERR_NONE;

fail:
	grub_free (raw);
	return err;
}

/* Decode chunk CHUNK_NR (USIZE uncompressed bytes) into chunk_buf.  */
static grub_err_t
isz_load_chunk (struct isz_image *image, grub_uint32_t chunk_nr,
		grub_uint32_t usize)
{
	struct isz_chunk *chunk = &image->chunks[chunk_nr];
	grub_err_t err;

	if (image->cached_nr == chunk_nr)
		return GRUB_ERR_NONE;
	image->cached_nr = ISZ_CACHE_NONE;

	switch (chunk->flag)
	{
	case ISZ_CHUNK_DATA:
	{
		grub_uint32_t n = chunk->stored_len;

		if (n > usize)
			n = usize;
		err = isz_pread (image->file, chunk->file_off,
				 image->chunk_buf, n);
		if (err)
			return err;
		if (n < usize)
			grub_memset (image->chunk_buf + n, 0, usize - n);
		break;
	}
	case ISZ_CHUNK_ZLIB:
	{
		grub_ssize_t n;

		err = isz_pread (image->file, chunk->file_off,
				 image->comp_buf, chunk->stored_len);
		if (err)
			return err;
		n = grub_zlib_decompress ((char *) image->comp_buf,
					  chunk->stored_len, 0,
					  (char *) image->chunk_buf, usize);
		if (n != (grub_ssize_t) usize)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					   "corrupt zlib chunk in ISZ image");
		break;
	}
	case ISZ_CHUNK_BZ2:
	{
		bz_stream bz = { 0 };
		int ret;

		if (chunk->stored_len < 4)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					   "short bzip2 chunk in ISZ image");
		err = isz_pread (image->file, chunk->file_off,
				 image->comp_buf, chunk->stored_len);
		if (err)
			return err;
		/* UltraISO replaces the standard bzip2 stream prefix.  */
		image->comp_buf[0] = 'B';
		image->comp_buf[1] = 'Z';
		image->comp_buf[2] = 'h';
		if (BZ2_bzDecompressInit (&bz, 0, 0) != BZ_OK)
			return grub_error (GRUB_ERR_OUT_OF_MEMORY,
					   "bzip2 decompressor init failed");
		bz.next_in = (char *) image->comp_buf;
		bz.avail_in = chunk->stored_len;
		bz.next_out = (char *) image->chunk_buf;
		bz.avail_out = usize;
		ret = BZ2_bzDecompress (&bz);
		BZ2_bzDecompressEnd (&bz);
		if (ret != BZ_STREAM_END || bz.avail_out != 0)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					   "corrupt bzip2 chunk in ISZ image");
		break;
	}
	default:
		return grub_error (GRUB_ERR_BUG, "bad ISZ chunk type");
	}

	image->cached_nr = chunk_nr;
	return GRUB_ERR_NONE;
}

static grub_err_t
isz_read (struct isz_image *image, grub_uint64_t off, void *buf,
	  grub_size_t len, grub_size_t *actually_read)
{
	struct isz_chunk *chunk;
	grub_uint32_t chunk_nr;
	grub_uint32_t off_in_chunk;
	grub_uint32_t usize;
	grub_err_t err;

	*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
				   "read past end of ISZ image");

	if (!image->chunks)
	{
		err = isz_pread (image->file, image->data_offs + off,
				 buf, len);
		if (err)
			return err;
		*actually_read = len;
		return GRUB_ERR_NONE;
	}

	chunk_nr = (grub_uint32_t) (off / image->block_size);
	off_in_chunk = (grub_uint32_t) (off % image->block_size);
	usize = image->block_size;
	if ((grub_uint64_t) chunk_nr * image->block_size + usize
	    > image->total_bytes)
		usize = (grub_uint32_t) (image->total_bytes
					 - (grub_uint64_t) chunk_nr
					 * image->block_size);

	/* Clip to the chunk; never grow the request.  */
	if (len > usize - off_in_chunk)
		len = usize - off_in_chunk;

	chunk = &image->chunks[chunk_nr];
	if (chunk->flag == ISZ_CHUNK_ZERO || chunk->stored_len == 0)
		grub_memset (buf, 0, len);
	else
	{
		err = isz_load_chunk (image, chunk_nr, usize);
		if (err)
			return err;
		grub_memcpy (buf, image->chunk_buf + off_in_chunk, len);
	}

	*actually_read = len;
	return GRUB_ERR_NONE;
}

/* ------------------------------------------------------------------ */
/* io filter wrapper                                                   */

struct grub_isz
{
	grub_file_t file;
	struct isz_image *isz;
};
typedef struct grub_isz *grub_isz_t;

static struct grub_fs grub_isz_fs;

static grub_err_t
grub_isz_close (grub_file_t file)
{
	grub_isz_t iszio = file->data;

	isz_free_image (iszio->isz);
	grub_free (iszio->isz);
	grub_file_close (iszio->file);
	grub_free (iszio);
	/* The inner close released the shared device; the outer name is
	   freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_isz_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_isz_t iszio;
	struct isz_image *image;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < sizeof (struct isz_header)
	    || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (isz_open_image (image) != GRUB_ERR_NONE)
	{
		isz_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	iszio = grub_zalloc (sizeof (*iszio));
	if (!file || !iszio)
	{
		isz_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (iszio);
		return 0;
	}
	iszio->file = io;
	iszio->isz = image;

	file->device = io->device;
	file->data = iszio;
	file->fs = &grub_isz_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;

	return file;
}

static grub_ssize_t
grub_isz_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_isz_t iszio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = isz_read (iszio->isz, read_offset, buf, len,
				&real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR,
					  "isz read made no progress");
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
			grub_error (err, "ISZ image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_isz_fs =
{
	.name = "isz",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_isz_read,
	.fs_close = grub_isz_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (isz)
{
	grub_file_filter_register (GRUB_FILE_FILTER_ISZ, grub_isz_open);
}

GRUB_MOD_FINI (isz)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_ISZ);
}
