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
 * Brotli (RFC 7932) is a bare bit stream: no magic, no header, no stored
 * length.  A stream opens with the window-size bits, so every byte string
 * is a syntactically plausible start and content sniffing alone cannot
 * decide.
 * A filter that guessed from content alone would therefore corrupt unrelated files
 * every few tens of thousands of opens, so detection is driven by the
 * customary ".br" suffix and the stream head only has to decode.
 *
 * No length is stored either, so the size stays GRUB_FILE_SIZE_UNKNOWN
 * until the stream has been decoded to its end; seeking backwards
 * restarts the decoder at offset 0.  Unlike gzip or bzip2, concatenated
 * brotli streams are not a defined format and are not read as one file:
 * the first stream ends the file.
 */

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/dl.h>

#include <brotli/decode.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define BRIO_BUFSIZ		0x2000

/* Head of the stream handed to the decoder to confirm the suffix.  */
#define BRIO_PROBE_SIZE		0x1000
/* Output buffers the probe is allowed to fill before it gives up and
   calls a stream that keeps expanding good enough.  */
#define BRIO_PROBE_ROUNDS	8

struct grub_brio
{
	grub_file_t file;
	BrotliDecoderState *dec;
	/* Compressed bytes the decoder has not taken yet.  */
	const grub_uint8_t *next_in;
	grub_size_t avail_in;
	/* Decompressed offset the decoder currently sits at.  */
	grub_off_t saved_offset;
	/* No further stream data; file->size is final.  */
	bool eof;
	grub_uint8_t inbuf[BRIO_BUFSIZ];
	grub_uint8_t outbuf[BRIO_BUFSIZ];
};
typedef struct grub_brio *grub_brio_t;

static struct grub_fs grub_brio_fs;

static void *
brio_alloc (void *opaque, grub_size_t size)
{
	(void) opaque;
	return grub_malloc (size);
}

static void
brio_free (void *opaque, void *addr)
{
	(void) opaque;
	grub_free (addr);
}

/* Throw the decoder away and start over from the head of the file.  */
static bool
reset_stream (grub_brio_t brio)
{
	BrotliDecoderDestroyInstance (brio->dec);
	brio->dec = NULL;
	brio->next_in = NULL;
	brio->avail_in = 0;
	brio->saved_offset = 0;
	brio->eof = false;

	if (grub_file_seek (brio->file, 0) == (grub_off_t) -1)
		return false;
	brio->dec = BrotliDecoderCreateInstance (brio_alloc, brio_free, NULL);
	if (!brio->dec)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "brotli decompressor init failed");
		return false;
	}
	return true;
}

/* Decode the head of the stream.  All a headerless format allows us to
   check is that it decodes at all; the suffix has to carry the rest.  */
static bool
probe_stream (grub_brio_t brio)
{
	BrotliDecoderResult res;
	grub_ssize_t readret;
	int round = 0;

	readret = grub_file_read (brio->file, brio->inbuf, BRIO_PROBE_SIZE);
	if (readret <= 0)
		return false;
	brio->next_in = brio->inbuf;
	brio->avail_in = (grub_size_t) readret;

	do
	{
		grub_uint8_t *next_out = brio->outbuf;
		grub_size_t avail_out = BRIO_BUFSIZ;

		res = BrotliDecoderDecompressStream (brio->dec, &brio->avail_in, &brio->next_in, &avail_out, &next_out, NULL);
	}
	while (res == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT && ++round < BRIO_PROBE_ROUNDS);

	/* A file that fits inside the probe has to finish inside it: with no
	   more input to blame, an unfinished stream is not one of ours.  This
	   is what keeps a short misnamed file from decoding to nothing.  */
	if ((grub_size_t) readret < BRIO_PROBE_SIZE && res == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT)
		return false;

	return res != BROTLI_DECODER_RESULT_ERROR;
}

static grub_file_t
grub_brio_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file = NULL;
	grub_brio_t brio = NULL;
	const char *suffix;

	if (type & GRUB_FILE_TYPE_NO_DECOMPRESS)
		return io;
	suffix = grub_file_get_suffix (io->name);
	if (!suffix || (grub_strcasecmp (suffix, ".br") != 0 && grub_strcasecmp (suffix, ".brotli") != 0))
		return io;

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	brio = grub_zalloc (sizeof (*brio));
	if (!file || !brio)
		goto fail;

	brio->file = io;
	if (!reset_stream (brio))
		goto fail;
	if (!probe_stream (brio))
		goto pass;
	/* The probe ate part of the stream; hand the reader a fresh one.  */
	if (!reset_stream (brio))
		goto fail;

	file->device = io->device;
	file->data = brio;
	file->fs = &grub_brio_fs;
	file->size = GRUB_FILE_SIZE_UNKNOWN;
	file->not_easily_seekable = 1;

	return file;

pass:
	BrotliDecoderDestroyInstance (brio->dec);
	grub_free (brio);
	grub_free (file);
	grub_file_seek (io, 0);
	grub_errno = GRUB_ERR_NONE;
	return io;

fail:
	if (brio)
		BrotliDecoderDestroyInstance (brio->dec);
	grub_free (brio);
	grub_free (file);
	return NULL;
}

static grub_ssize_t
grub_brio_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_brio_t brio = file->data;
	grub_ssize_t ret = 0;
	grub_off_t current_offset;

	/* Seeking backwards means decoding from the start again.
	   TODO Possible improvement by remembering meta-block boundaries.  */
	if (file->offset < brio->saved_offset && !reset_stream (brio))
		return -1;

	current_offset = brio->saved_offset;

	while (len > 0 && !brio->eof)
	{
		grub_off_t want = file->offset + ret + len - current_offset;
		grub_off_t new_offset;
		grub_uint8_t *next_out;
		grub_size_t outsize;
		grub_size_t avail_out;
		grub_size_t outpos;
		BrotliDecoderResult res;

		outsize = (want > BRIO_BUFSIZ) ? BRIO_BUFSIZ : (grub_size_t) want;

		next_out = brio->outbuf;
		avail_out = outsize;
		res = BrotliDecoderDecompressStream (brio->dec, &brio->avail_in, &brio->next_in, &avail_out, &next_out, NULL);
		if (res == BROTLI_DECODER_RESULT_ERROR)
		{
			grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "brotli file corrupted");
			return -1;
		}

		outpos = outsize - avail_out;
		new_offset = current_offset + outpos;

		/* Everything before file->offset is decoded and dropped.  */
		if (file->offset <= new_offset)
		{
			grub_size_t delta;

			delta = (grub_size_t) (new_offset - (file->offset + ret));
			grub_memmove (buf, brio->outbuf + (outpos - delta), delta);
			len -= delta;
			buf += delta;
			ret += delta;
		}
		current_offset = new_offset;

		if (res == BROTLI_DECODER_RESULT_SUCCESS)
		{
			/* Whole stream seen, its length is now known.  */
			brio->eof = true;
			file->size = current_offset;
		}
		else if (res == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT)
		{
			grub_ssize_t readret;

			readret = grub_file_read (brio->file, brio->inbuf, BRIO_BUFSIZ);
			if (readret < 0)
				return -1;
			if (readret == 0)
			{
				/* Truncated stream: keep what was decoded.  */
				brio->eof = true;
				file->size = current_offset;
				break;
			}
			brio->next_in = brio->inbuf;
			brio->avail_in = (grub_size_t) readret;
		}
	}

	brio->saved_offset = current_offset;
	return ret;
}

/* Release everything, including the underlying file object.  */
static grub_err_t
grub_brio_close (grub_file_t file)
{
	grub_brio_t brio = file->data;

	BrotliDecoderDestroyInstance (brio->dec);
	grub_file_close (brio->file);
	grub_free (brio);

	/* Device must not be closed twice.  */
	file->device = 0;
	return grub_errno;
}

static struct grub_fs grub_brio_fs =
{
	.name = "brio",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_brio_read,
	.fs_close = grub_brio_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (brio)
{
	grub_file_filter_register (GRUB_FILE_FILTER_BROTLI, grub_brio_open);
}

GRUB_MOD_FINI (brio)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_BROTLI);
}
