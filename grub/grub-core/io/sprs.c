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
 * Apple sparseimage io filter
 */

#include <grub/dl.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define APPLE_SPARSE_HEADER_SIZE	4096U
#define APPLE_SPARSE_TABLE_OFFSET	64U
#define APPLE_SPARSE_SECTOR_SIZE	512U
#define APPLE_SPARSE_SLOT_NONE	0xffffffffU

struct apple_sparse
{
	grub_file_t carrier;
	grub_uint64_t media_size;
	grub_uint64_t band_size;
	grub_uint32_t number_of_bands;
	grub_uint32_t *band_slots;
};

struct grub_apple_sparse
{
	grub_file_t file;
	struct apple_sparse *image;
};
typedef struct grub_apple_sparse *grub_apple_sparse_t;

static grub_err_t
apple_sparse_pread (grub_file_t file, grub_uint64_t offset, void *buffer, grub_size_t size)
{
	grub_ssize_t got;

	if (grub_file_seek (file, offset) == (grub_off_t) -1)
		return grub_errno;
	got = grub_file_read (file, buffer, size);
	if (got < 0)
		return grub_errno ? grub_errno : GRUB_ERR_FILE_READ_ERROR;
	if ((grub_size_t) got != size)
		return grub_error (GRUB_ERR_FILE_READ_ERROR, "short read in Apple sparse image");
	return GRUB_ERR_NONE;
}

static grub_uint32_t
apple_sparse_get_be32 (const grub_uint8_t *data)
{
	return grub_be_to_cpu32 (grub_get_unaligned32 (data));
}

static void
apple_sparse_free (struct apple_sparse *image)
{
	if (!image)
		return;
	grub_free (image->band_slots);
	grub_free (image);
}

static grub_err_t
apple_sparseimage_open (struct apple_sparse *image)
{
	grub_uint8_t header[APPLE_SPARSE_HEADER_SIZE];
	grub_uint32_t sectors_per_band;
	grub_uint32_t number_of_sectors;
	grub_uint32_t physical;
	grub_uint32_t logical;
	grub_uint64_t data_offset;
	grub_uint64_t logical_offset;
	grub_uint64_t required;
	grub_err_t err;

	err = apple_sparse_pread (image->carrier, 0, header, sizeof (header));
	if (err)
		return err;
	if (grub_memcmp (header, "sprs", 4) != 0)
		return GRUB_ERR_BAD_DEVICE;

	sectors_per_band = apple_sparse_get_be32 (header + 8);
	number_of_sectors = apple_sparse_get_be32 (header + 16);
	if (!sectors_per_band || !number_of_sectors)
		return grub_error (GRUB_ERR_BAD_DEVICE, "invalid Apple sparseimage geometry");

	image->band_size = (grub_uint64_t) sectors_per_band * APPLE_SPARSE_SECTOR_SIZE;
	image->media_size = (grub_uint64_t) number_of_sectors * APPLE_SPARSE_SECTOR_SIZE;
	image->number_of_bands = number_of_sectors / sectors_per_band;
	if (number_of_sectors % sectors_per_band)
		image->number_of_bands++;
	if (!image->number_of_bands
		|| image->number_of_bands > (APPLE_SPARSE_HEADER_SIZE - APPLE_SPARSE_TABLE_OFFSET) / sizeof (grub_uint32_t))
		return grub_error (GRUB_ERR_BAD_DEVICE, "Apple sparseimage band table does not fit the header");

	image->band_slots = grub_malloc ((grub_size_t) image->number_of_bands * sizeof (image->band_slots[0]));
	if (!image->band_slots)
		return grub_errno;
	grub_memset (image->band_slots, 0xff,
		(grub_size_t) image->number_of_bands * sizeof (image->band_slots[0]));

	for (physical = 0; physical < image->number_of_bands; physical++)
	{
		grub_uint32_t reference = apple_sparse_get_be32
			(header + APPLE_SPARSE_TABLE_OFFSET + (grub_size_t) physical * sizeof (reference));

		if (!reference)
			continue;
		if (reference > image->number_of_bands)
			return grub_error (GRUB_ERR_BAD_DEVICE, "Apple sparseimage band reference is out of range");
		logical = reference - 1;
		if (image->band_slots[logical] != APPLE_SPARSE_SLOT_NONE)
			return grub_error (GRUB_ERR_BAD_DEVICE, "duplicate Apple sparseimage band reference");
		image->band_slots[logical] = physical;
	}

	for (logical = 0; logical < image->number_of_bands; logical++)
	{
		physical = image->band_slots[logical];
		if (physical == APPLE_SPARSE_SLOT_NONE)
			continue;
		data_offset = APPLE_SPARSE_HEADER_SIZE
			+ (grub_uint64_t) physical * image->band_size;
		logical_offset = (grub_uint64_t) logical * image->band_size;
		required = image->band_size;
		if (required > image->media_size - logical_offset)
			required = image->media_size - logical_offset;
		if (data_offset > grub_file_size (image->carrier)
			|| required > grub_file_size (image->carrier) - data_offset)
			return grub_error (GRUB_ERR_BAD_DEVICE, "Apple sparseimage band data is truncated");
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
apple_sparse_read_chunk (struct apple_sparse *image, grub_uint64_t offset,
	void *buffer, grub_size_t size)
{
	grub_uint64_t band_index = offset / image->band_size;
	grub_uint64_t in_band = offset % image->band_size;
	grub_uint64_t physical = image->band_slots[band_index];

	if (physical == APPLE_SPARSE_SLOT_NONE)
	{
		grub_memset (buffer, 0, size);
		return GRUB_ERR_NONE;
	}
	return apple_sparse_pread (image->carrier,
		APPLE_SPARSE_HEADER_SIZE + physical * image->band_size + in_band,
		buffer, size);
}

static grub_ssize_t
grub_apple_sparse_read (grub_file_t file, char *buffer, grub_size_t size)
{
	grub_apple_sparse_t sparse = file->data;
	grub_uint64_t offset = file->offset;
	grub_ssize_t total = 0;

	while (size)
	{
		grub_uint64_t in_band = offset % sparse->image->band_size;
		grub_size_t chunk = (grub_size_t)
			(sparse->image->band_size - in_band);
		grub_err_t err;

		if (chunk > size)
			chunk = size;
		if (chunk > sparse->image->media_size - offset)
			chunk = (grub_size_t)
				(sparse->image->media_size - offset);
		if (!chunk)
			break;
		err = apple_sparse_read_chunk (sparse->image, offset, buffer, chunk);
		if (err)
			return -1;
		offset += chunk;
		buffer += chunk;
		size -= chunk;
		total += (grub_ssize_t) chunk;
	}
	return total;
}

static grub_err_t
grub_apple_sparse_close (grub_file_t file)
{
	grub_apple_sparse_t sparse = file->data;
	grub_file_t carrier = sparse->file;

	apple_sparse_free (sparse->image);
	grub_file_close (carrier);
	grub_free (sparse);
	file->device = NULL;
	return grub_errno;
}

static struct grub_fs grub_apple_sparse_fs =
{
	.name = "sprs",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_apple_sparse_read,
	.fs_close = grub_apple_sparse_close,
	.fs_label = 0,
	.next = 0
};

static grub_file_t
grub_apple_sparse_open (grub_file_t io, enum grub_file_type type)
{
	struct apple_sparse *image = NULL;
	grub_apple_sparse_t sparse = NULL;
	grub_file_t file = NULL;
	grub_uint8_t signature[4];
	grub_err_t err;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK)
		|| io->size == GRUB_FILE_SIZE_UNKNOWN || io->size < sizeof (signature))
		return io;
	if (apple_sparse_pread (io, 0, signature, sizeof (signature)))
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}
	if (grub_memcmp (signature, "sprs", sizeof (signature)) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return NULL;
	image->carrier = io;
	err = apple_sparseimage_open (image);
	if (err)
	{
		apple_sparse_free (image);
		return NULL;
	}

	file = grub_zalloc (sizeof (*file));
	sparse = grub_zalloc (sizeof (*sparse));
	if (!file || !sparse)
	{
		apple_sparse_free (image);
		grub_free (file);
		grub_free (sparse);
		return NULL;
	}
	sparse->file = io;
	sparse->image = image;
	file->device = io->device;
	file->data = sparse;
	file->fs = &grub_apple_sparse_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->media_size;
	return file;
}

GRUB_MOD_INIT (sprs)
{
	grub_file_filter_register (GRUB_FILE_FILTER_SPRS, grub_apple_sparse_open);
}

GRUB_MOD_FINI (sprs)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_SPRS);
}
