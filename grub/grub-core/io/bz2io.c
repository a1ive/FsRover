/*
 *  Rover -- GRUB 2 filesystem browser for Windows
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
 * A bzip2 stream carries no uncompressed length, so the size stays
 * GRUB_FILE_SIZE_UNKNOWN until the stream has been decoded to its end;
 * seeking backwards restarts the decoder at offset 0.  Concatenated
 * streams (bzip2 -c a b, pbzip2) read as one continuous file; trailing
 * bytes that do not start a further stream end the file.
 */

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/dl.h>

#include <bzlib.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define BZ2IO_BUFSIZ		0x2000

/* "BZh" plus the block size digit.  */
#define BZ2IO_MAGIC_SIZE	4
/* The stream header plus the block or end-of-stream magic that follows
   it; four bytes alone are too weak to probe every file open with.  */
#define BZ2IO_HEADER_SIZE	10

struct grub_bz2io
{
	grub_file_t file;
	bz_stream bz;
	/* Decompressed offset the decoder currently sits at.  */
	grub_off_t saved_offset;
	/* No further stream data; file->size is final.  */
	bool eof;
	grub_uint8_t inbuf[BZ2IO_BUFSIZ];
	grub_uint8_t outbuf[BZ2IO_BUFSIZ];
};
typedef struct grub_bz2io *grub_bz2io_t;

static struct grub_fs grub_bz2io_fs;

static bool
test_magic (const grub_uint8_t *buf)
{
	return (buf[0] == 'B' && buf[1] == 'Z' && buf[2] == 'h' && buf[3] >= '1' && buf[3] <= '9');
}

/* A bzip2 file may hold several streams back to back (bzip2 -c a b,
   pbzip2).  Restart the decoder when one follows the stream that just
   ended.  Returns 1 for a new stream, 0 at end of data, -1 on error.  */
static int
next_stream (grub_bz2io_t bz2io)
{
	grub_size_t rest = bz2io->bz.avail_in;
	grub_ssize_t readret;

	if (rest != 0)
		grub_memmove (bz2io->inbuf, bz2io->bz.next_in, rest);
	if (rest < BZ2IO_MAGIC_SIZE)
	{
		readret = grub_file_read (bz2io->file, bz2io->inbuf + rest, BZ2IO_BUFSIZ - rest);
		if (readret < 0)
			return -1;
		rest += (grub_size_t) readret;
	}
	if (rest < BZ2IO_MAGIC_SIZE || !test_magic (bz2io->inbuf))
		return 0;

	BZ2_bzDecompressEnd (&bz2io->bz);
	if (BZ2_bzDecompressInit (&bz2io->bz, 0, 0) != BZ_OK)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "bzip2 decompressor init failed");
		return -1;
	}
	bz2io->bz.next_in = (char *) bz2io->inbuf;
	bz2io->bz.avail_in = (unsigned int) rest;
	return 1;
}

/* Throw the decoder away and start over from the head of the file.  */
static bool
reset_stream (grub_bz2io_t bz2io)
{
	BZ2_bzDecompressEnd (&bz2io->bz);
	bz2io->bz.next_in = NULL;
	bz2io->bz.avail_in = 0;
	bz2io->saved_offset = 0;
	bz2io->eof = false;

	if (grub_file_seek (bz2io->file, 0) == (grub_off_t) -1)
		return false;
	if (BZ2_bzDecompressInit (&bz2io->bz, 0, 0) != BZ_OK)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "bzip2 decompressor init failed");
		return false;
	}
	return true;
}

static grub_file_t
grub_bz2io_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file = NULL;
	grub_bz2io_t bz2io = NULL;
	grub_uint8_t header[BZ2IO_HEADER_SIZE];

	if (type & GRUB_FILE_TYPE_NO_DECOMPRESS)
		return io;

	if (grub_file_tell (io) != 0 && grub_file_seek (io, 0) == (grub_off_t) -1)
		goto pass;
	if (grub_file_read (io, header, sizeof (header)) != (grub_ssize_t) sizeof (header) || !test_magic (header))
		goto pass;

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	bz2io = grub_zalloc (sizeof (*bz2io));
	if (!file || !bz2io)
		goto fail;

	bz2io->file = io;

	file->device = io->device;
	file->data = bz2io;
	file->fs = &grub_bz2io_fs;
	file->size = GRUB_FILE_SIZE_UNKNOWN;
	file->not_easily_seekable = 1;

	if (BZ2_bzDecompressInit (&bz2io->bz, 0, 0) != BZ_OK)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "bzip2 decompressor init failed");
		goto fail;
	}

	/* Let the decoder consume the header it will need anyway; it only
	   asks for more input (BZ_OK) when the stream really is bzip2.  */
	grub_memcpy (bz2io->inbuf, header, sizeof (header));
	bz2io->bz.next_in = (char *) bz2io->inbuf;
	bz2io->bz.avail_in = (unsigned int) sizeof (header);
	bz2io->bz.next_out = (char *) bz2io->outbuf;
	bz2io->bz.avail_out = BZ2IO_BUFSIZ;
	if (BZ2_bzDecompress (&bz2io->bz) != BZ_OK)
	{
		BZ2_bzDecompressEnd (&bz2io->bz);
		goto pass;
	}

	return file;

pass:
	grub_free (bz2io);
	grub_free (file);
	grub_file_seek (io, 0);
	grub_errno = GRUB_ERR_NONE;
	return io;

fail:
	grub_free (bz2io);
	grub_free (file);
	return NULL;
}

static grub_ssize_t
grub_bz2io_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_bz2io_t bz2io = file->data;
	grub_ssize_t ret = 0;
	grub_off_t current_offset;

	/* Seeking backwards means decoding from the start again.
	   TODO Possible improvement by remembering block boundaries.  */
	if (file->offset < bz2io->saved_offset && !reset_stream (bz2io))
		return -1;

	current_offset = bz2io->saved_offset;

	while (len > 0 && !bz2io->eof)
	{
		grub_off_t want = file->offset + ret + len - current_offset;
		grub_off_t new_offset;
		unsigned int outsize;
		unsigned int outpos;
		int bzret;

		outsize = (want > BZ2IO_BUFSIZ) ? BZ2IO_BUFSIZ : (unsigned int) want;

		/* Feed input.  */
		if (bz2io->bz.avail_in == 0)
		{
			grub_ssize_t readret;

			readret = grub_file_read (bz2io->file, bz2io->inbuf, BZ2IO_BUFSIZ);
			if (readret < 0)
				return -1;
			if (readret == 0)
			{
				/* Truncated stream: keep what was decoded.  */
				bz2io->eof = true;
				file->size = current_offset;
				break;
			}
			bz2io->bz.next_in = (char *) bz2io->inbuf;
			bz2io->bz.avail_in = (unsigned int) readret;
		}

		bz2io->bz.next_out = (char *) bz2io->outbuf;
		bz2io->bz.avail_out = outsize;
		bzret = BZ2_bzDecompress (&bz2io->bz);
		if (bzret != BZ_OK && bzret != BZ_STREAM_END)
		{
			grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bzip2 file corrupted");
			return -1;
		}

		outpos = outsize - bz2io->bz.avail_out;
		new_offset = current_offset + outpos;

		/* Everything before file->offset is decoded and dropped.  */
		if (file->offset <= new_offset)
		{
			grub_size_t delta;

			delta = (grub_size_t) (new_offset - (file->offset + ret));
			grub_memmove (buf, bz2io->outbuf + (outpos - delta), delta);
			len -= delta;
			buf += delta;
			ret += delta;
		}
		current_offset = new_offset;

		if (bzret == BZ_STREAM_END)
		{
			int nret = next_stream (bz2io);

			if (nret < 0)
				return -1;
			if (nret == 0)
			{
				/* Whole file seen, its length is now known.  */
				bz2io->eof = true;
				file->size = current_offset;
			}
		}
	}

	bz2io->saved_offset = current_offset;
	return ret;
}

/* Release everything, including the underlying file object.  */
static grub_err_t
grub_bz2io_close (grub_file_t file)
{
	grub_bz2io_t bz2io = file->data;

	BZ2_bzDecompressEnd (&bz2io->bz);
	grub_file_close (bz2io->file);
	grub_free (bz2io);

	/* Device must not be closed twice.  */
	file->device = 0;
	return grub_errno;
}

static struct grub_fs grub_bz2io_fs =
{
	.name = "bz2io",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_bz2io_read,
	.fs_close = grub_bz2io_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (bz2io)
{
	grub_file_filter_register (GRUB_FILE_FILTER_BZ2IO, grub_bz2io_open);
}

GRUB_MOD_FINI (bz2io)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_BZ2IO);
}
