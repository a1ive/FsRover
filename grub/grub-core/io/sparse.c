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
 * Android sparse image io filter
 * Implemented from the AOSP libsparse on-disk format
 * (libsparse/sparse_format.h)
 * https://2net.co.uk/tutorial/android-sparse-image-format
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define SPARSE_MAGIC		0xed26ff3a
#define SPARSE_MAJOR_VERSION	1

/* Sizes of the first (and so far only) revision of the format.  Both
   headers may grow, so they are read from the file and used as strides.  */
#define SPARSE_HEADER_SIZE	28
#define SPARSE_CHUNK_HEADER_SIZE 12

#define SPARSE_CHUNK_RAW	0xcac1
#define SPARSE_CHUNK_FILL	0xcac2
#define SPARSE_CHUNK_DONT_CARE	0xcac3
#define SPARSE_CHUNK_CRC32	0xcac4

#define SPARSE_FILL_SIZE	4

/* Sanity caps against corrupt images.  */
#define SPARSE_BLOCK_SIZE_MAX	(16u << 20)
#define SPARSE_NCHUNKS_MAX	(4u << 20)

PRAGMA_BEGIN_PACKED
struct sparse_header
{
	grub_uint32_t magic;		/* SPARSE_MAGIC */
	grub_uint16_t major_version;	/* reject anything but 1 */
	grub_uint16_t minor_version;	/* higher minor versions are fine */
	grub_uint16_t file_hdr_sz;	/* 28 */
	grub_uint16_t chunk_hdr_sz;	/* 12 */
	grub_uint32_t blk_sz;		/* output block size, multiple of 4 */
	grub_uint32_t total_blks;	/* blocks in the expanded image */
	grub_uint32_t total_chunks;	/* chunks in the sparse image */
	grub_uint32_t image_checksum;	/* CRC32 of the expanded image */
};

struct sparse_chunk_header
{
	grub_uint16_t chunk_type;	/* SPARSE_CHUNK_* */
	grub_uint16_t reserved;
	grub_uint32_t chunk_sz;		/* output blocks covered */
	grub_uint32_t total_sz;		/* stored bytes, chunk header included */
};
PRAGMA_END_PACKED

/* phy_off holds the file offset of the stored data of a raw chunk.  Chunk
   data never starts before the file header, so these two markers cannot
   collide with a real offset.  */
#define SPARSE_PHY_DONT_CARE	0
#define SPARSE_PHY_FILL		1

struct sparse_chunk
{
	grub_uint64_t phy_off;		/* SPARSE_PHY_* or a file offset */
	grub_uint32_t virt_blk;		/* first output block of the chunk */
	grub_uint8_t fill[SPARSE_FILL_SIZE];
};

struct sparse_image
{
	grub_file_t file;
	grub_uint64_t total_bytes;
	grub_uint32_t block_size;
	/* chunks[] is sorted by virt_blk and ends with a sentinel entry whose
	   virt_blk is the block count of the whole image, so a chunk covers
	   [chunks[i].virt_blk, chunks[i + 1].virt_blk).  */
	grub_uint32_t nchunks;
	struct sparse_chunk *chunks;
	grub_uint32_t cached_nr;	/* chunk hit by the previous read */
};

static grub_err_t
sparse_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (file)
	    || len > grub_file_size (file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sparse image truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sparse image truncated");
	return GRUB_ERR_NONE;
}

static void
sparse_free_image (struct sparse_image *image)
{
	grub_free (image->chunks);
	image->chunks = NULL;
}

static grub_err_t
sparse_open_image (struct sparse_image *image)
{
	struct sparse_header hdr;
	grub_uint64_t file_size = grub_file_size (image->file);
	grub_uint64_t off;
	grub_uint32_t blk_sz, total_blks, total_chunks;
	grub_uint32_t hdr_sz, chunk_hdr_sz;
	grub_uint32_t virt_blk = 0;
	grub_uint32_t i, n = 0;
	grub_err_t err;

	err = sparse_pread (image->file, 0, &hdr, sizeof (hdr));
	if (err)
		return err;
	if (grub_le_to_cpu32 (hdr.magic) != SPARSE_MAGIC)
		return grub_error (GRUB_ERR_BAD_SIGNATURE,
				   "not an Android sparse image");
	if (grub_le_to_cpu16 (hdr.major_version) != SPARSE_MAJOR_VERSION)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "unsupported sparse image version %u",
				   grub_le_to_cpu16 (hdr.major_version));

	hdr_sz = grub_le_to_cpu16 (hdr.file_hdr_sz);
	chunk_hdr_sz = grub_le_to_cpu16 (hdr.chunk_hdr_sz);
	blk_sz = grub_le_to_cpu32 (hdr.blk_sz);
	total_blks = grub_le_to_cpu32 (hdr.total_blks);
	total_chunks = grub_le_to_cpu32 (hdr.total_chunks);

	if (hdr_sz < SPARSE_HEADER_SIZE
	    || chunk_hdr_sz < SPARSE_CHUNK_HEADER_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad sparse header size");
	if (blk_sz == 0 || blk_sz % 4 != 0 || blk_sz > SPARSE_BLOCK_SIZE_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad sparse block size");
	if (total_blks == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "empty sparse image");
	if (total_chunks > SPARSE_NCHUNKS_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad sparse chunk count");

	image->block_size = blk_sz;
	image->total_bytes = (grub_uint64_t) total_blks * blk_sz;

	/* Every chunk yields at most one entry, plus the tail hole and the
	   sentinel.  */
	image->chunks = grub_calloc (total_chunks + 2, sizeof (*image->chunks));
	if (!image->chunks)
		return grub_errno;

	off = hdr_sz;
	for (i = 0; i < total_chunks; i++)
	{
		struct sparse_chunk_header chdr;
		struct sparse_chunk *chunk = &image->chunks[n];
		grub_uint64_t data_off;
		grub_uint32_t type, nblocks, stored;

		err = sparse_pread (image->file, off, &chdr, sizeof (chdr));
		if (err)
			goto fail;
		type = grub_le_to_cpu16 (chdr.chunk_type);
		nblocks = grub_le_to_cpu32 (chdr.chunk_sz);
		stored = grub_le_to_cpu32 (chdr.total_sz);

		if (stored < chunk_hdr_sz)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "short sparse chunk");
			goto fail;
		}
		data_off = off + chunk_hdr_sz;
		stored -= chunk_hdr_sz;
		if (grub_add (off, grub_le_to_cpu32 (chdr.total_sz), &off)
		    || off > file_size)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "sparse image truncated");
			goto fail;
		}
		if (nblocks > total_blks - virt_blk)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "oversized sparse chunk");
			goto fail;
		}

		if (type == SPARSE_CHUNK_CRC32)
		{
			/* Checksum of the expanded image; carries no data.  */
			if (nblocks != 0 || stored != SPARSE_FILL_SIZE)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "bad sparse CRC32 chunk");
				goto fail;
			}
			continue;
		}

		if (nblocks == 0)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "empty sparse chunk");
			goto fail;
		}

		switch (type)
		{
		case SPARSE_CHUNK_RAW:
			if ((grub_uint64_t) nblocks * blk_sz != stored)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "bad sparse raw chunk size");
				goto fail;
			}
			chunk->phy_off = data_off;
			break;
		case SPARSE_CHUNK_FILL:
			if (stored != SPARSE_FILL_SIZE)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "bad sparse fill chunk size");
				goto fail;
			}
			err = sparse_pread (image->file, data_off, chunk->fill,
					    SPARSE_FILL_SIZE);
			if (err)
				goto fail;
			chunk->phy_off = SPARSE_PHY_FILL;
			break;
		case SPARSE_CHUNK_DONT_CARE:
			if (stored != 0)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "bad sparse hole chunk size");
				goto fail;
			}
			chunk->phy_off = SPARSE_PHY_DONT_CARE;
			break;
		default:
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "unknown sparse chunk type 0x%x", type);
			goto fail;
		}

		chunk->virt_blk = virt_blk;
		virt_blk += nblocks;
		n++;
	}

	/* Tolerate chunks that stop short of the declared image size; the
	   tail reads back as a hole.  */
	if (virt_blk < total_blks)
	{
		image->chunks[n].phy_off = SPARSE_PHY_DONT_CARE;
		image->chunks[n].virt_blk = virt_blk;
		n++;
	}
	image->chunks[n].phy_off = SPARSE_PHY_DONT_CARE;
	image->chunks[n].virt_blk = total_blks;
	image->nchunks = n + 1;

	return GRUB_ERR_NONE;

fail:
	sparse_free_image (image);
	return err;
}

/* Write LEN bytes of the 4 byte PATTERN into BUF, starting the pattern at
   byte PHASE so that fill chunks stay aligned across partial reads.  */
static void
sparse_fill (void *buf, grub_size_t len, const grub_uint8_t *pattern,
	     unsigned phase)
{
	grub_uint8_t *dest = buf;
	grub_uint8_t seed[SPARSE_FILL_SIZE];
	grub_size_t done;
	unsigned i;

	for (i = 0; i < SPARSE_FILL_SIZE; i++)
		seed[i] = pattern[(phase + i) % SPARSE_FILL_SIZE];

	done = len < SPARSE_FILL_SIZE ? len : SPARSE_FILL_SIZE;
	grub_memcpy (dest, seed, done);
	/* Double what is already there until the buffer is covered.  */
	while (done < len)
	{
		grub_size_t todo = len - done;

		if (todo > done)
			todo = done;
		grub_memcpy (dest + done, dest, todo);
		done += todo;
	}
}

static grub_err_t
sparse_read (struct sparse_image *image, grub_uint64_t off, void *buf,
	     grub_size_t len, grub_size_t *actually_read)
{
	const struct sparse_chunk *chunk;
	grub_uint64_t blk, chunk_end, off_in_chunk;
	grub_uint32_t nr;
	grub_err_t err;

	*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
				   "read past end of sparse image");
	if (len == 0)
		return GRUB_ERR_NONE;

	blk = off / image->block_size;
	nr = image->cached_nr;
	if (blk < image->chunks[nr].virt_blk
	    || blk >= image->chunks[nr + 1].virt_blk)
	{
		/* Invariant: chunks[lo].virt_blk <= blk < chunks[hi].virt_blk.  */
		grub_uint32_t lo = 0, hi = image->nchunks - 1;

		while (hi - lo > 1)
		{
			grub_uint32_t mid = lo + (hi - lo) / 2;

			if (blk < image->chunks[mid].virt_blk)
				hi = mid;
			else
				lo = mid;
		}
		nr = lo;
		image->cached_nr = nr;
	}

	chunk = &image->chunks[nr];
	off_in_chunk = off - (grub_uint64_t) chunk->virt_blk * image->block_size;
	chunk_end = (grub_uint64_t) chunk[1].virt_blk * image->block_size;

	/* Clip to the chunk; never grow the request.  */
	if (len > chunk_end - off)
		len = (grub_size_t) (chunk_end - off);

	if (chunk->phy_off == SPARSE_PHY_DONT_CARE)
		grub_memset (buf, 0, len);
	else if (chunk->phy_off == SPARSE_PHY_FILL)
		sparse_fill (buf, len, chunk->fill,
			     (unsigned) (off_in_chunk % SPARSE_FILL_SIZE));
	else
	{
		err = sparse_pread (image->file, chunk->phy_off + off_in_chunk,
				    buf, len);
		if (err)
			return err;
	}

	*actually_read = len;
	return GRUB_ERR_NONE;
}

struct grub_sparse
{
	grub_file_t file;
	struct sparse_image *sparse;
};
typedef struct grub_sparse *grub_sparse_t;

static struct grub_fs grub_sparse_fs;

static grub_err_t
grub_sparse_close (grub_file_t file)
{
	grub_sparse_t sparseio = file->data;

	sparse_free_image (sparseio->sparse);
	grub_free (sparseio->sparse);
	grub_file_close (sparseio->file);
	grub_free (sparseio);
	/* The inner close released the shared device; the outer name is
	   freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_sparse_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_sparse_t sparseio;
	struct sparse_image *image;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < sizeof (struct sparse_header)
	    || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (sparse_open_image (image) != GRUB_ERR_NONE)
	{
		sparse_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	sparseio = grub_zalloc (sizeof (*sparseio));
	if (!file || !sparseio)
	{
		sparse_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (sparseio);
		return 0;
	}
	sparseio->file = io;
	sparseio->sparse = image;

	file->device = io->device;
	file->data = sparseio;
	file->fs = &grub_sparse_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;

	return file;
}

static grub_ssize_t
grub_sparse_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_sparse_t sparseio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = sparse_read (sparseio->sparse, read_offset, buf, len,
				   &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR,
					  "sparse read made no progress");
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
			grub_error (err, "sparse image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_sparse_fs =
{
	.name = "sparse",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_sparse_read,
	.fs_close = grub_sparse_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (sparse)
{
	grub_file_filter_register (GRUB_FILE_FILTER_SPARSE, grub_sparse_open);
}

GRUB_MOD_FINI (sparse)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_SPARSE);
}
