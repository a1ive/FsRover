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
 * The "LZMA alone" container that lzma(1) and 7-Zip's -tlzma write: a 13
 * byte header -- one properties byte holding lc/lp/pb, a 32 bit
 * dictionary size and a 64 bit uncompressed size -- followed by the raw
 * LZMA stream.  That is a weak signature: no magic, and the range coder
 * behind it decodes almost any bit string without complaining, so unlike
 * xz or bzip2 there is nothing to fall back on when the header passes.
 * Detection is therefore driven by the ".lzma" suffix, and the header is
 * checked the way 7-Zip's LzmaHandler checks it: properties below
 * 9*5*5, a stored size below 1<<56, and a dictionary size out of the set
 * encoders round to.  That last test is the one that earns its keep: a
 * 4 KiB run of zeros -- which disk images and tar padding are full of --
 * parses as a valid header and decodes without complaint until it is
 * applied.  Measured with the probe below over 4 KiB chunks, acceptances
 * of non-lzma data go from 1020/1020 to 0 on a zero-filled file and from
 * 48 to 0 over 8836 chunks of tar / ELF / rpm; random data the header
 * and the range coder already reject on their own.
 *
 * The uncompressed size is all ones when the encoder did not know it --
 * lzma(1) always writes that and ends the stream with an end marker
 * instead -- and the size then stays GRUB_FILE_SIZE_UNKNOWN until the
 * stream has been decoded to its end.  Seeking backwards restarts the
 * decoder at the first stream byte, which only costs an LzmaDec_Init:
 * the dictionary stays allocated for the life of the file.
 */

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/dl.h>

#include <7zTypes.h>
#include <LzmaDec.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define LZMAIO_BUFSIZ		0x2000

/* Properties byte, dictionary size, uncompressed size.  */
#define LZMAIO_HEADER_SIZE	13
/* The uncompressed size the encoder writes when it does not know it.  */
#define LZMAIO_SIZE_UNKNOWN	0xffffffffffffffffULL

/* Head of the stream handed to the decoder to confirm the suffix.  */
#define LZMAIO_PROBE_SIZE	0x1000
/* A dictionary is allocated up front, so cap what a header may ask for;
   nothing in the wild goes past 64 MiB.  */
#define LZMAIO_MAX_DICT		0x40000000UL
/* Stored sizes past this are nonsense, and loopdisk would believe them.  */
#define LZMAIO_MAX_SIZE		0x0100000000000000ULL

struct grub_lzmaio
{
	grub_file_t file;
	CLzmaDec dec;
	/* Compressed bytes the decoder has not taken yet.  */
	const grub_uint8_t *next_in;
	grub_size_t avail_in;
	/* Decompressed offset the decoder currently sits at.  */
	grub_off_t saved_offset;
	/* No further stream data; file->size is final.  */
	bool eof;
	grub_uint8_t inbuf[LZMAIO_BUFSIZ];
	grub_uint8_t outbuf[LZMAIO_BUFSIZ];
};
typedef struct grub_lzmaio *grub_lzmaio_t;

static struct grub_fs grub_lzmaio_fs;

static void *
lzmaio_alloc (ISzAllocPtr p, size_t size)
{
	(void) p;
	return grub_malloc (size);
}

static void
lzmaio_free (ISzAllocPtr p, void *address)
{
	(void) p;
	grub_free (address);
}

static const ISzAlloc lzmaio_allocator = { lzmaio_alloc, lzmaio_free };

/* The dictionary sizes encoders round to: 2^n and 3*2^n, plus the 1 that
   the SDK writes for an empty dictionary.  Taken from 7-Zip's
   LzmaHandler.cpp (CheckDicSize), which recognises the container the
   same way; 0xffffffff is accepted there but we would have to allocate
   it, so LZMAIO_MAX_DICT throws it out.  */
static bool
dict_ok (grub_uint32_t dict)
{
	unsigned i;

	if (dict == 1)
		return true;
	for (i = 0; i <= 30; i++)
		if (dict == (2UL << i) || dict == (3UL << i))
			return true;
	return false;
}

/* Reads the header into HEADER and hands back the stored uncompressed
   size, LZMAIO_SIZE_UNKNOWN when the encoder left it out.  */
static bool
read_header (grub_file_t io, grub_uint8_t *header, grub_uint64_t *size)
{
	grub_uint32_t dict;

	if (grub_file_tell (io) != 0 && grub_file_seek (io, 0) == (grub_off_t) -1)
		return false;
	if (grub_file_read (io, header, LZMAIO_HEADER_SIZE) != (grub_ssize_t) LZMAIO_HEADER_SIZE)
		return false;

	dict = grub_le_to_cpu32 (grub_get_unaligned32 (header + 1));
	*size = grub_le_to_cpu64 (grub_get_unaligned64 (header + 5));

	if (header[0] >= 9 * 5 * 5 || dict > LZMAIO_MAX_DICT || !dict_ok (dict))
		return false;
	if (*size != LZMAIO_SIZE_UNKNOWN && *size > LZMAIO_MAX_SIZE)
		return false;
	return true;
}

/* Rewind to the first stream byte.  The dictionary is kept.  */
static bool
reset_stream (grub_lzmaio_t lzio)
{
	lzio->next_in = NULL;
	lzio->avail_in = 0;
	lzio->saved_offset = 0;
	lzio->eof = false;

	if (grub_file_seek (lzio->file, LZMAIO_HEADER_SIZE) == (grub_off_t) -1)
		return false;
	LzmaDec_Init (&lzio->dec);
	return true;
}

/* Decode the head of the stream.  The header has been checked already;
   this only rejects what the range coder itself chokes on.  */
static bool
probe_stream (grub_lzmaio_t lzio)
{
	ELzmaStatus status;
	grub_ssize_t readret;
	SizeT destlen, srclen;

	readret = grub_file_read (lzio->file, lzio->inbuf, LZMAIO_PROBE_SIZE);
	if (readret <= 0)
		return false;

	destlen = LZMAIO_BUFSIZ;
	srclen = (SizeT) readret;
	return LzmaDec_DecodeToBuf (&lzio->dec, lzio->outbuf, &destlen, lzio->inbuf, &srclen, LZMA_FINISH_ANY, &status) == SZ_OK;
}

/* No more data will come out; publish the length we ended up with.  */
static void
end_of_stream (grub_file_t file, grub_off_t offset)
{
	grub_lzmaio_t lzio = file->data;

	lzio->eof = true;
	if (file->size == GRUB_FILE_SIZE_UNKNOWN || offset < file->size)
		file->size = offset;
}

static grub_file_t
grub_lzmaio_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file = NULL;
	grub_lzmaio_t lzio = NULL;
	grub_uint8_t header[LZMAIO_HEADER_SIZE];
	grub_uint64_t size;
	const char *suffix;
	SRes res;

	if (type & GRUB_FILE_TYPE_NO_DECOMPRESS)
		return io;
	suffix = grub_file_get_suffix (io->name);
	if (!suffix || (grub_strcasecmp (suffix, ".lzma") != 0 && grub_strcasecmp (suffix, ".tlz") != 0))
		return io;
	if (!read_header (io, header, &size))
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	lzio = grub_zalloc (sizeof (*lzio));
	if (!file || !lzio)
		goto fail;

	lzio->file = io;
	LzmaDec_Construct (&lzio->dec);

	/* The first five header bytes are the properties LzmaDec wants.  */
	res = LzmaDec_Allocate (&lzio->dec, header, LZMA_PROPS_SIZE, &lzmaio_allocator);
	if (res == SZ_ERROR_MEM)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "lzma decompressor init failed");
		goto fail;
	}
	if (res != SZ_OK)
		goto pass;
	if (!reset_stream (lzio))
		goto fail;
	if (!probe_stream (lzio))
		goto pass;
	/* The probe ate part of the stream; hand the reader a fresh one.  */
	if (!reset_stream (lzio))
		goto fail;

	file->device = io->device;
	file->data = lzio;
	file->fs = &grub_lzmaio_fs;
	file->size = (size == LZMAIO_SIZE_UNKNOWN) ? GRUB_FILE_SIZE_UNKNOWN : (grub_off_t) size;
	file->not_easily_seekable = 1;

	return file;

pass:
	LzmaDec_Free (&lzio->dec, &lzmaio_allocator);
	grub_free (lzio);
	grub_free (file);
	grub_file_seek (io, 0);
	grub_errno = GRUB_ERR_NONE;
	return io;

fail:
	if (lzio)
		LzmaDec_Free (&lzio->dec, &lzmaio_allocator);
	grub_free (lzio);
	grub_free (file);
	return NULL;
}

static grub_ssize_t
grub_lzmaio_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_lzmaio_t lzio = file->data;
	grub_ssize_t ret = 0;
	grub_off_t current_offset;

	/* Seeking backwards means decoding from the start again.
	   TODO Possible improvement by remembering decoder snapshots.  */
	if (file->offset < lzio->saved_offset && !reset_stream (lzio))
		return -1;

	current_offset = lzio->saved_offset;

	while (len > 0 && !lzio->eof)
	{
		grub_off_t want = file->offset + ret + len - current_offset;
		grub_off_t new_offset;
		grub_size_t outsize;
		grub_size_t outpos;
		SizeT destlen, srclen;
		ELzmaStatus status;

		outsize = (want > LZMAIO_BUFSIZ) ? LZMAIO_BUFSIZ : (grub_size_t) want;

		/* Feed input.  */
		if (lzio->avail_in == 0)
		{
			grub_ssize_t readret;

			readret = grub_file_read (lzio->file, lzio->inbuf, LZMAIO_BUFSIZ);
			if (readret < 0)
				return -1;
			if (readret == 0)
			{
				/* Truncated stream: keep what was decoded.  */
				end_of_stream (file, current_offset);
				break;
			}
			lzio->next_in = lzio->inbuf;
			lzio->avail_in = (grub_size_t) readret;
		}

		destlen = outsize;
		srclen = lzio->avail_in;
		if (LzmaDec_DecodeToBuf (&lzio->dec, lzio->outbuf, &destlen, lzio->next_in, &srclen, LZMA_FINISH_ANY, &status) != SZ_OK)
		{
			grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "lzma file corrupted");
			return -1;
		}
		lzio->next_in += srclen;
		lzio->avail_in -= srclen;

		outpos = (grub_size_t) destlen;
		new_offset = current_offset + outpos;

		/* Everything before file->offset is decoded and dropped.  */
		if (file->offset <= new_offset)
		{
			grub_size_t delta;

			delta = (grub_size_t) (new_offset - (file->offset + ret));
			grub_memmove (buf, lzio->outbuf + (outpos - delta), delta);
			len -= delta;
			buf += delta;
			ret += delta;
		}
		current_offset = new_offset;

		/* The end marker is the only in-band end of stream.  A decoder
		   that took no input and produced no output has nothing left to
		   do either, which is where a size-terminated stream (and a tail
		   of trailing junk) comes to rest.  */
		if (status == LZMA_STATUS_FINISHED_WITH_MARK || (destlen == 0 && srclen == 0))
			end_of_stream (file, current_offset);
	}

	lzio->saved_offset = current_offset;
	return ret;
}

/* Release everything, including the underlying file object.  */
static grub_err_t
grub_lzmaio_close (grub_file_t file)
{
	grub_lzmaio_t lzio = file->data;

	LzmaDec_Free (&lzio->dec, &lzmaio_allocator);
	grub_file_close (lzio->file);
	grub_free (lzio);

	/* Device must not be closed twice.  */
	file->device = 0;
	return grub_errno;
}

static struct grub_fs grub_lzmaio_fs =
{
	.name = "lzmaio",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_lzmaio_read,
	.fs_close = grub_lzmaio_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (lzmaio)
{
	grub_file_filter_register (GRUB_FILE_FILTER_LZMAIO, grub_lzmaio_open);
}

GRUB_MOD_FINI (lzmaio)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_LZMAIO);
}
