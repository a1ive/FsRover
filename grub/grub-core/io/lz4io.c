/* lz4io.c - decompression support for LZ4 frames */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2011  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/dl.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/mm.h>

#include <lz4.h>
#define XXH_STATIC_LINKING_ONLY
#include <xxhash.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define LZ4_MAGIC		0x184d2204U
#define LZ4_MAX_HEADER_SIZE	19
#define LZ4_DICT_SIZE		(64 * 1024)

#define LZ4_FLG_BLOCK_INDEPENDENT	0x20
#define LZ4_FLG_BLOCK_CHECKSUM		0x10
#define LZ4_FLG_CONTENT_SIZE		0x08
#define LZ4_FLG_CONTENT_CHECKSUM		0x04
#define LZ4_FLG_DICTIONARY_ID		0x01

struct grub_lz4io
{
	grub_file_t file;
	int has_b_indep;
	int has_b_checksum;
	int has_c_size;
	int has_c_checksum;
	grub_size_t header_size;
	grub_uint64_t content_size;
	grub_size_t max_block_size;
	grub_off_t saved_off;
	char *ubuf;
	grub_size_t u_size;
	char *cbuf;
	char *dict_buf;
	grub_size_t dict_size;
	XXH32_state_t content_hash;
	int frame_finished;
	int failed;
	grub_err_t failure_error;
	char failure_message[GRUB_MAX_ERRMSG];
};

typedef struct grub_lz4io *grub_lz4io_t;
static struct grub_fs grub_lz4io_fs;

static grub_uint32_t
read_le32 (const void *buf)
{
	grub_uint32_t value;

	grub_memcpy (&value, buf, sizeof (value));
	return grub_le_to_cpu32 (value);
}

static grub_uint64_t
read_le64 (const void *buf)
{
	grub_uint64_t value;

	grub_memcpy (&value, buf, sizeof (value));
	return grub_le_to_cpu64 (value);
}

static int
read_exact (grub_file_t file, void *buf, grub_size_t size)
{
	grub_ssize_t result;

	result = grub_file_read (file, buf, size);
	if (result == (grub_ssize_t) size)
		return 1;
	if (result >= 0)
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
			    N_("truncated LZ4 frame"));
	return 0;
}

static int
read_u32 (grub_file_t file, grub_uint32_t *value)
{
	grub_uint32_t stored;

	if (!read_exact (file, &stored, sizeof (stored)))
		return 0;
	*value = grub_le_to_cpu32 (stored);
	return 1;
}

static int
bad_data (const char *message)
{
	grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "%s", message);
	return -1;
}

static int
parse_header (grub_lz4io_t lz4io, grub_uint32_t magic)
{
	grub_uint8_t header[LZ4_MAX_HEADER_SIZE];
	grub_uint8_t flg;
	grub_uint8_t bd;
	grub_uint8_t checksum;
	grub_size_t optional_size;
	unsigned int block_size_id;

	grub_memcpy (header, &magic, sizeof (magic));
	if (!read_exact (lz4io->file, header + sizeof (magic), 2))
		return 0;

	flg = header[4];
	bd = header[5];
	if ((flg & 0xc0) != 0x40 || (flg & 0x02) != 0)
	{
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
			    N_("invalid LZ4 frame flags"));
		return 0;
	}

	block_size_id = (bd >> 4) & 7;
	if ((bd & 0x8f) != 0 || block_size_id < 4)
	{
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
			    N_("invalid LZ4 maximum block size"));
		return 0;
	}
	lz4io->max_block_size = (grub_size_t) 1 << (2 * block_size_id + 8);

	lz4io->has_b_indep = !!(flg & LZ4_FLG_BLOCK_INDEPENDENT);
	lz4io->has_b_checksum = !!(flg & LZ4_FLG_BLOCK_CHECKSUM);
	lz4io->has_c_size = !!(flg & LZ4_FLG_CONTENT_SIZE);
	lz4io->has_c_checksum = !!(flg & LZ4_FLG_CONTENT_CHECKSUM);
	optional_size = (lz4io->has_c_size ? 8 : 0)
			+ ((flg & LZ4_FLG_DICTIONARY_ID) ? 4 : 0);
	lz4io->header_size = 7 + optional_size;
	if (!read_exact (lz4io->file, header + 6, optional_size + 1))
		return 0;

	checksum = (grub_uint8_t) (XXH32 (header + 4,
					     lz4io->header_size - 5, 0) >> 8);
	if (checksum != header[lz4io->header_size - 1])
	{
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
			    N_("invalid LZ4 frame header checksum"));
		return 0;
	}

	if (lz4io->has_c_size)
		lz4io->content_size = read_le64 (header + 6);
	if (flg & LZ4_FLG_DICTIONARY_ID)
	{
		grub_uint32_t dictionary_id;
		grub_size_t dictionary_offset = 6 + (lz4io->has_c_size ? 8 : 0);

		dictionary_id = read_le32 (header + dictionary_offset);
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			    N_("LZ4 dictionary 0x%x is not available"),
			    dictionary_id);
		return 0;
	}

	return 1;
}

static void
update_dictionary (grub_lz4io_t lz4io)
{
	grub_size_t keep;

	if (lz4io->has_b_indep)
		return;
	if (lz4io->u_size >= LZ4_DICT_SIZE)
	{
		grub_memcpy (lz4io->dict_buf,
			     lz4io->ubuf + lz4io->u_size - LZ4_DICT_SIZE,
			     LZ4_DICT_SIZE);
		lz4io->dict_size = LZ4_DICT_SIZE;
		return;
	}

	keep = LZ4_DICT_SIZE - lz4io->u_size;
	if (keep > lz4io->dict_size)
		keep = lz4io->dict_size;
	if (keep != 0)
		grub_memmove (lz4io->dict_buf,
			      lz4io->dict_buf + lz4io->dict_size - keep,
			      keep);
	grub_memcpy (lz4io->dict_buf + keep, lz4io->ubuf, lz4io->u_size);
	lz4io->dict_size = keep + lz4io->u_size;
}

static int
finish_frame (grub_lz4io_t lz4io)
{
	grub_uint32_t stored_checksum;

	if (lz4io->has_c_size && lz4io->saved_off != lz4io->content_size)
		return bad_data (N_("LZ4 content size mismatch"));
	if (lz4io->has_c_checksum)
	{
		if (!read_u32 (lz4io->file, &stored_checksum))
			return -1;
		if (stored_checksum != XXH32_digest (&lz4io->content_hash))
			return bad_data (N_("invalid LZ4 content checksum"));
	}
	lz4io->frame_finished = 1;
	return 0;
}

static int
read_block (grub_lz4io_t lz4io)
{
	grub_ssize_t result;
	grub_uint32_t block_header;
	grub_uint32_t block_size;
	grub_uint32_t stored_checksum;
	int uncompressed;

	if (lz4io->frame_finished)
		return 0;
	if (!read_u32 (lz4io->file, &block_header))
		return -1;
	if (block_header == 0)
		return finish_frame (lz4io) < 0 ? -1 : 0;

	uncompressed = !!(block_header & 0x80000000U);
	block_size = block_header & 0x7fffffffU;
	if (block_size == 0 || block_size > lz4io->max_block_size)
		return bad_data (N_("invalid LZ4 block size"));
	if (!read_exact (lz4io->file, lz4io->cbuf, block_size))
		return -1;
	if (lz4io->has_b_checksum)
	{
		if (!read_u32 (lz4io->file, &stored_checksum))
			return -1;
		if (stored_checksum != XXH32 (lz4io->cbuf, block_size, 0))
			return bad_data (N_("invalid LZ4 block checksum"));
	}

	if (uncompressed)
	{
		grub_memcpy (lz4io->ubuf, lz4io->cbuf, block_size);
		lz4io->u_size = block_size;
	}
	else if (lz4io->has_b_indep)
	{
		result = LZ4_decompress_safe (lz4io->cbuf, lz4io->ubuf,
					      (int) block_size,
					      (int) lz4io->max_block_size);
		if (result <= 0)
			return bad_data (N_("invalid LZ4 compressed block"));
		lz4io->u_size = (grub_size_t) result;
	}
	else
	{
		result = LZ4_decompress_safe_usingDict (lz4io->cbuf, lz4io->ubuf,
							(int) block_size,
							(int) lz4io->max_block_size,
							lz4io->dict_buf,
							(int) lz4io->dict_size);
		if (result <= 0)
			return bad_data (N_("invalid linked LZ4 block"));
		lz4io->u_size = (grub_size_t) result;
	}

	if (lz4io->has_c_size
	    && lz4io->u_size > lz4io->content_size - lz4io->saved_off)
		return bad_data (N_("LZ4 content exceeds its declared size"));
	if (lz4io->has_c_checksum)
		XXH32_update (&lz4io->content_hash, lz4io->ubuf, lz4io->u_size);
	update_dictionary (lz4io);
	lz4io->saved_off += lz4io->u_size;

	/* When a content size is present, validate the frame trailer before
	   exposing the final block.  grub_file_read() does not call fs_read at
	   offset == file->size, so waiting for the next read would skip it.  */
	if (lz4io->has_c_size && lz4io->saved_off == lz4io->content_size)
	{
		if (!read_u32 (lz4io->file, &block_header))
			return -1;
		if (block_header != 0)
			return bad_data (N_("missing LZ4 end mark"));
		if (finish_frame (lz4io) < 0)
			return -1;
	}

	return 1;
}

static int
reset_dctx (grub_lz4io_t lz4io)
{
	if (grub_file_seek (lz4io->file, lz4io->header_size)
	    == (grub_off_t) -1)
		return 0;
	lz4io->saved_off = 0;
	lz4io->u_size = 0;
	lz4io->dict_size = 0;
	lz4io->frame_finished = 0;
	XXH32_reset (&lz4io->content_hash, 0);
	return 1;
}

static grub_ssize_t
remember_failure (grub_lz4io_t lz4io)
{
	if (!lz4io->failed)
	{
		lz4io->failure_error = grub_errno != GRUB_ERR_NONE
					? grub_errno : GRUB_ERR_BAD_COMPRESSED_DATA;
		grub_strncpy (lz4io->failure_message,
			      grub_errno != GRUB_ERR_NONE
				      ? grub_errmsg : N_("invalid LZ4 frame"),
			      sizeof (lz4io->failure_message) - 1);
		lz4io->failure_message[sizeof (lz4io->failure_message) - 1] = 0;
		lz4io->failed = 1;
	}
	grub_error (lz4io->failure_error, "%s", lz4io->failure_message);
	return -1;
}

static void
free_context (grub_lz4io_t lz4io)
{
	grub_free (lz4io->dict_buf);
	grub_free (lz4io->cbuf);
	grub_free (lz4io->ubuf);
	grub_free (lz4io);
}

static grub_file_t
grub_lz4io_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file = 0;
	grub_lz4io_t lz4io = 0;
	grub_uint32_t magic;
	grub_ssize_t result;
	int block_result;

	if (type & GRUB_FILE_TYPE_NO_DECOMPRESS)
		return io;
	if (grub_file_tell (io) != 0
	    && grub_file_seek (io, 0) == (grub_off_t) -1)
		return 0;

	result = grub_file_read (io, &magic, sizeof (magic));
	if (result < 0)
		return 0;
	if (result != sizeof (magic) || grub_le_to_cpu32 (magic) != LZ4_MAGIC)
	{
		grub_errno = GRUB_ERR_NONE;
		if (grub_file_seek (io, 0) == (grub_off_t) -1)
			return 0;
		return io;
	}

	file = grub_zalloc (sizeof (*file));
	if (!file)
		goto fail;
	lz4io = grub_zalloc (sizeof (*lz4io));
	if (!lz4io)
		goto fail;
	lz4io->file = io;
	if (!parse_header (lz4io, magic))
		goto fail;

	lz4io->ubuf = grub_malloc (lz4io->max_block_size);
	if (!lz4io->ubuf)
		goto fail;
	lz4io->cbuf = grub_malloc (lz4io->max_block_size);
	if (!lz4io->cbuf)
		goto fail;
	if (!lz4io->has_b_indep)
	{
		lz4io->dict_buf = grub_malloc (LZ4_DICT_SIZE);
		if (!lz4io->dict_buf)
			goto fail;
	}
	if (!reset_dctx (lz4io))
		goto fail;

	file->device = io->device;
	file->data = lz4io;
	file->fs = &grub_lz4io_fs;
	file->size = lz4io->has_c_size
			? lz4io->content_size : GRUB_FILE_SIZE_UNKNOWN;
	file->not_easily_seekable = 1;

	/* A zero-size file is never passed to fs_read, so validate its complete
	   frame here instead.  */
	if (lz4io->has_c_size && lz4io->content_size == 0)
	{
		block_result = read_block (lz4io);
		if (block_result != 0)
			goto fail;
	}
	return file;

fail:
	if (lz4io)
		free_context (lz4io);
	grub_free (file);
	return 0;
}

static grub_ssize_t
grub_lz4io_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_lz4io_t lz4io = file->data;
	grub_ssize_t ret = 0;
	grub_off_t off;
	int result;

	if (lz4io->failed)
		return remember_failure (lz4io);
	if (lz4io->saved_off - lz4io->u_size > grub_file_tell (file))
	{
		if (!reset_dctx (lz4io))
			return remember_failure (lz4io);
	}

	while (lz4io->saved_off <= grub_file_tell (file))
	{
		result = read_block (lz4io);
		if (result == 0)
			return 0;
		if (result < 0)
			return remember_failure (lz4io);
	}

	off = grub_file_tell (file) - (lz4io->saved_off - lz4io->u_size);
	while (len != 0)
	{
		grub_size_t to_copy;

		to_copy = lz4io->u_size - (grub_size_t) off;
		if (to_copy > len)
			to_copy = len;
		grub_memcpy (buf, lz4io->ubuf + off, to_copy);
		len -= to_copy;
		buf += to_copy;
		ret += (grub_ssize_t) to_copy;
		off = 0;

		if (len > 0)
		{
			result = read_block (lz4io);
			if (result == 0)
				break;
			if (result < 0)
				return remember_failure (lz4io);
		}
	}
	return ret;
}

/* Release everything, including the underlying file object.  */
static grub_err_t
grub_lz4io_close (grub_file_t file)
{
	grub_lz4io_t lz4io = file->data;

	grub_file_close (lz4io->file);
	free_context (lz4io);

	/* Device must not be closed twice.  */
	file->device = 0;
	return grub_errno;
}

static struct grub_fs grub_lz4io_fs =
{
	.name = "lz4io",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_lz4io_read,
	.fs_close = grub_lz4io_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (lz4io)
{
	grub_file_filter_register (GRUB_FILE_FILTER_LZ4IO, grub_lz4io_open);
}

GRUB_MOD_FINI (lz4io)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_LZ4IO);
}
