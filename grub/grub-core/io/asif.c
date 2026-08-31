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

#include <grub/dl.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define ASIF_MAGIC			0x73686477U /* shdw */
#define ASIF_VERSION			1U
#define ASIF_HEADER_READ_SIZE		0x50U
#define ASIF_ENTRY_CHUNK_MASK		0x007fffffffffffffULL
#define ASIF_ENTRY_RESERVED_MASK	0x3f80000000000000ULL
#define ASIF_CACHE_NONE			(~0ULL)

struct asif_image
{
	grub_file_t carrier;
	grub_uint64_t file_size;
	grub_uint64_t media_size;
	grub_uint64_t maximum_size;
	grub_uint64_t chunk_size;
	grub_uint64_t block_size;
	grub_uint64_t chunks_per_group;
	grub_uint64_t group_size;
	grub_uint64_t groups_per_table;
	grub_uint64_t data_per_group;
	grub_uint64_t data_per_table;
	grub_uint64_t table_count;
	grub_uint64_t directory_offset;

	grub_uint8_t *group_cache;
	grub_uint64_t cached_table;
	grub_uint64_t cached_group;
	int cached_sparse_table;

	grub_uint8_t *bitmap_cache;
	grub_uint64_t cached_bitmap_chunk;
	grub_uint64_t cached_bitmap_block;
};

struct grub_asif
{
	grub_file_t file;
	struct asif_image *image;
};
typedef struct grub_asif *grub_asif_t;

static grub_uint16_t
asif_get_be16 (const grub_uint8_t *data)
{
	return grub_be_to_cpu16 (grub_get_unaligned16 (data));
}

static grub_uint32_t
asif_get_be32 (const grub_uint8_t *data)
{
	return grub_be_to_cpu32 (grub_get_unaligned32 (data));
}

static grub_uint64_t
asif_get_be64 (const grub_uint8_t *data)
{
	return grub_be_to_cpu64 (grub_get_unaligned64 (data));
}

static int
asif_add_overflow (grub_uint64_t left, grub_uint64_t right, grub_uint64_t *result)
{
	if (left > ~0ULL - right)
		return 1;
	*result = left + right;
	return 0;
}

static int
asif_mul_overflow (grub_uint64_t left, grub_uint64_t right, grub_uint64_t *result)
{
	if (right && left > ~0ULL / right)
		return 1;
	*result = left * right;
	return 0;
}

static int
asif_range_valid (grub_uint64_t offset, grub_uint64_t size, grub_uint64_t limit)
{
	return offset <= limit && size <= limit - offset;
}

static grub_err_t
asif_pread (struct asif_image *image, grub_uint64_t offset, void *buffer, grub_size_t size, const char *what)
{
	grub_ssize_t got;

	if (!asif_range_valid (offset, size, image->file_size))
		return grub_error (GRUB_ERR_BAD_DEVICE, "ASIF %s is outside the backing file", what);
	if (grub_file_seek (image->carrier, offset) == (grub_off_t) -1)
		return grub_errno;
	got = grub_file_read (image->carrier, buffer, size);
	if (got < 0)
		return grub_errno ? grub_errno : GRUB_ERR_FILE_READ_ERROR;
	if ((grub_size_t) got != size)
		return grub_error (GRUB_ERR_FILE_READ_ERROR, "short read in ASIF %s", what);
	return GRUB_ERR_NONE;
}

static grub_err_t
asif_chunk_offset (struct asif_image *image, grub_uint64_t chunk, grub_uint64_t *offset)
{
	if (asif_mul_overflow (chunk, image->chunk_size, offset))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF physical chunk offset overflows");
	return GRUB_ERR_NONE;
}

static void
asif_free_image (struct asif_image *image)
{
	if (!image)
		return;
	grub_free (image->bitmap_cache);
	grub_free (image->group_cache);
	grub_free (image);
}

static grub_err_t
asif_open_image (struct asif_image *image)
{
	grub_uint8_t header[ASIF_HEADER_READ_SIZE];
	grub_uint8_t sequence_data[8];
	grub_uint64_t directory_offsets[2];
	grub_uint64_t directory_size;
	grub_uint64_t sequence[2];
	grub_uint64_t metadata_chunk;
	grub_uint64_t value;
	grub_uint32_t header_size;
	grub_uint32_t chunk_size;
	grub_uint16_t block_size;
	grub_uint16_t total_segments;
	grub_err_t err;
	int index;

	err = asif_pread (image, 0, header, sizeof (header), "header");
	if (err)
		return err;
	if (asif_get_be32 (header) != ASIF_MAGIC)
		return GRUB_ERR_BAD_DEVICE;
	if (asif_get_be32 (header + 4) != ASIF_VERSION)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported ASIF header version");

	header_size = asif_get_be32 (header + 8);
	directory_offsets[0] = asif_get_be64 (header + 0x10);
	directory_offsets[1] = asif_get_be64 (header + 0x18);
	chunk_size = asif_get_be32 (header + 0x40);
	block_size = asif_get_be16 (header + 0x44);
	total_segments = asif_get_be16 (header + 0x46);
	metadata_chunk = asif_get_be64 (header + 0x48);

	if (!chunk_size || !block_size || block_size % 512
		|| chunk_size % block_size || total_segments != 0
		|| header_size < ASIF_HEADER_READ_SIZE
		|| header_size > chunk_size || header_size > image->file_size)
		return grub_error (GRUB_ERR_BAD_DEVICE, "invalid ASIF header geometry");

	image->chunk_size = chunk_size;
	image->block_size = block_size;
	if (asif_mul_overflow (asif_get_be64 (header + 0x30), block_size,
		&image->media_size)
		|| asif_mul_overflow (asif_get_be64 (header + 0x38), block_size,
			&image->maximum_size)
		|| image->media_size > image->maximum_size
		|| image->maximum_size == 0
		|| image->media_size == GRUB_FILE_SIZE_UNKNOWN
		|| image->maximum_size == GRUB_FILE_SIZE_UNKNOWN)
		return grub_error (GRUB_ERR_BAD_DEVICE, "invalid ASIF logical size");

	image->chunks_per_group = 4ULL * block_size;
	if (asif_add_overflow (image->chunks_per_group, 1, &value)
		|| asif_mul_overflow (value, 8, &image->group_size))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF chunk-group geometry overflows");
	image->groups_per_table = image->chunk_size / image->group_size;
	if (!image->groups_per_table
		|| asif_mul_overflow (image->chunks_per_group, image->chunk_size, &image->data_per_group)
		|| asif_mul_overflow (image->groups_per_table, image->data_per_group, &image->data_per_table)
		|| !image->data_per_table)
		return grub_error (GRUB_ERR_BAD_DEVICE, "invalid ASIF table geometry");

	image->table_count = image->maximum_size / image->data_per_table;
	if (image->maximum_size % image->data_per_table)
		image->table_count++;
	if (!image->table_count
		|| asif_mul_overflow (image->table_count, 8, &directory_size)
		|| asif_add_overflow (directory_size, 8, &directory_size))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF directory geometry overflows");

	for (index = 0; index < 2; index++)
	{
		if (directory_offsets[index] < header_size
			|| !asif_range_valid (directory_offsets[index], directory_size, image->file_size))
			return grub_error (GRUB_ERR_BAD_DEVICE, "ASIF directory is outside the backing file");
		err = asif_pread (image, directory_offsets[index], sequence_data, sizeof (sequence_data), "directory sequence");
		if (err)
			return err;
		sequence[index] = asif_get_be64 (sequence_data);
	}
	image->directory_offset = sequence[1] > sequence[0]
		? directory_offsets[1] : directory_offsets[0];

	if (metadata_chunk
		&& (asif_mul_overflow (metadata_chunk, image->chunk_size, &value)
			|| value >= image->maximum_size))
		return grub_error (GRUB_ERR_BAD_DEVICE, "ASIF metadata offset is outside the maximum disk size");

	image->group_cache = grub_malloc ((grub_size_t) image->group_size);
	image->bitmap_cache = grub_malloc ((grub_size_t) image->block_size);
	if (!image->group_cache || !image->bitmap_cache)
		return grub_errno;
	image->cached_table = ASIF_CACHE_NONE;
	image->cached_group = ASIF_CACHE_NONE;
	image->cached_bitmap_chunk = ASIF_CACHE_NONE;
	image->cached_bitmap_block = ASIF_CACHE_NONE;
	return GRUB_ERR_NONE;
}

static grub_err_t
asif_load_group (struct asif_image *image, grub_uint64_t table_index, grub_uint64_t group_index)
{
	grub_uint8_t entry_data[8];
	grub_uint64_t entry_offset;
	grub_uint64_t table_chunk;
	grub_uint64_t table_offset;
	grub_uint64_t group_offset;
	grub_uint64_t delta;
	grub_err_t err;

	if (image->cached_table == table_index
		&& image->cached_group == group_index)
		return GRUB_ERR_NONE;
	if (table_index >= image->table_count
		|| group_index >= image->groups_per_table)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF table index is out of range");

	if (asif_mul_overflow (table_index, 8, &delta)
		|| asif_add_overflow (image->directory_offset, 8, &entry_offset)
		|| asif_add_overflow (entry_offset, delta, &entry_offset))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF directory entry offset overflows");
	err = asif_pread (image, entry_offset, entry_data, sizeof (entry_data), "directory entry");
	if (err)
		return err;
	table_chunk = asif_get_be64 (entry_data);
	image->cached_table = table_index;
	image->cached_group = group_index;
	image->cached_sparse_table = table_chunk == 0;
	if (!table_chunk)
		return GRUB_ERR_NONE;

	err = asif_chunk_offset (image, table_chunk, &table_offset);
	if (err)
		goto fail;
	if (asif_mul_overflow (group_index, image->group_size, &delta)
		|| asif_add_overflow (table_offset, delta, &group_offset))
	{
		err = grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF chunk-group offset overflows");
		goto fail;
	}
	err = asif_pread (image, group_offset, image->group_cache, (grub_size_t) image->group_size, "chunk group");
	if (err)
		goto fail;
	return GRUB_ERR_NONE;

fail:
	image->cached_table = ASIF_CACHE_NONE;
	image->cached_group = ASIF_CACHE_NONE;
	return err;
}

static grub_err_t
asif_load_bitmap_block (struct asif_image *image, grub_uint64_t bitmap_chunk, grub_uint64_t bitmap_byte)
{
	grub_uint64_t block_index = bitmap_byte / image->block_size;
	grub_uint64_t bitmap_offset;
	grub_uint64_t delta;
	grub_err_t err;

	if (image->cached_bitmap_chunk == bitmap_chunk
		&& image->cached_bitmap_block == block_index)
		return GRUB_ERR_NONE;
	if (bitmap_byte >= image->chunk_size)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF bitmap index is out of range");
	err = asif_chunk_offset (image, bitmap_chunk, &bitmap_offset);
	if (err)
		return err;
	if (asif_mul_overflow (block_index, image->block_size, &delta)
		|| asif_add_overflow (bitmap_offset, delta, &bitmap_offset))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF bitmap offset overflows");
	err = asif_pread (image, bitmap_offset, image->bitmap_cache, (grub_size_t) image->block_size, "bitmap chunk");
	if (err)
		return err;
	image->cached_bitmap_chunk = bitmap_chunk;
	image->cached_bitmap_block = block_index;
	return GRUB_ERR_NONE;
}

static grub_err_t
asif_map (struct asif_image *image, grub_uint64_t offset,
	grub_uint64_t *physical_offset, grub_size_t *available, int *sparse)
{
	grub_uint64_t table_index = offset / image->data_per_table;
	grub_uint64_t table_relative = offset % image->data_per_table;
	grub_uint64_t group_index = table_relative / image->data_per_group;
	grub_uint64_t group_relative = table_relative % image->data_per_group;
	grub_uint64_t data_index = group_relative / image->chunk_size;
	grub_uint64_t in_chunk = group_relative % image->chunk_size;
	grub_uint64_t entry;
	grub_uint64_t chunk;
	grub_uint64_t bitmap_entry;
	grub_uint64_t bitmap_chunk;
	grub_uint64_t sector_index;
	grub_uint64_t bitmap_byte;
	grub_uint64_t chunk_offset;
	grub_uint64_t remain;
	grub_uint32_t status;
	grub_uint8_t bitmap_state;
	grub_err_t err;

	remain = image->chunk_size - in_chunk;
	if (remain > image->media_size - offset)
		remain = image->media_size - offset;
	*available = remain > (grub_uint64_t) GRUB_SIZE_MAX ? GRUB_SIZE_MAX : (grub_size_t) remain;
	*sparse = 1;

	err = asif_load_group (image, table_index, group_index);
	if (err || image->cached_sparse_table)
		return err;
	entry = asif_get_be64 (image->group_cache + data_index * 8);
	status = (grub_uint32_t) (entry >> 62);
	chunk = entry & ASIF_ENTRY_CHUNK_MASK;
	if (entry & ASIF_ENTRY_RESERVED_MASK)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported ASIF data-entry flags");

	if (status == 0 || status == 2)
	{
		if (chunk)
			return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported ASIF sparse data-entry state");
		return GRUB_ERR_NONE;
	}
	if (!chunk)
		return grub_error (GRUB_ERR_BAD_DEVICE, "ASIF allocated data entry has no physical chunk");

	if (status == 3)
	{
		bitmap_entry = asif_get_be64 (image->group_cache + image->chunks_per_group * 8);
		bitmap_chunk = bitmap_entry & ASIF_ENTRY_CHUNK_MASK;
		if ((bitmap_entry & ~ASIF_ENTRY_CHUNK_MASK) || !bitmap_chunk)
			return grub_error (GRUB_ERR_BAD_DEVICE, "invalid ASIF bitmap chunk entry");
		sector_index = data_index * (image->chunk_size / image->block_size) + in_chunk / image->block_size;
		bitmap_byte = sector_index / 4;
		err = asif_load_bitmap_block (image, bitmap_chunk, bitmap_byte);
		if (err)
			return err;
		bitmap_state = (image->bitmap_cache[bitmap_byte % image->block_size] >> ((sector_index % 4) * 2)) & 3;
		if (bitmap_state == 3)
			return grub_error (GRUB_ERR_BAD_DEVICE, "invalid ASIF bitmap sector state");
		remain = image->block_size - (offset % image->block_size);
		if (remain < *available)
			*available = (grub_size_t) remain;
		if (bitmap_state == 0 || bitmap_state == 2)
			return GRUB_ERR_NONE;
	}

	err = asif_chunk_offset (image, chunk, &chunk_offset);
	if (err)
		return err;
	if (asif_add_overflow (chunk_offset, in_chunk, physical_offset))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "ASIF data offset overflows");
	*sparse = 0;
	return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_asif_read (grub_file_t file, char *buffer, grub_size_t size)
{
	grub_asif_t asif = file->data;
	grub_uint64_t offset = file->offset;
	grub_ssize_t total = 0;

	while (size && offset < asif->image->media_size)
	{
		grub_uint64_t physical_offset = 0;
		grub_size_t available;
		grub_size_t chunk;
		grub_err_t err;
		int sparse;

		err = asif_map (asif->image, offset, &physical_offset,
			&available, &sparse);
		if (err)
			return -1;
		chunk = available < size ? available : size;
		if (!chunk)
			break;
		if (sparse)
			grub_memset (buffer, 0, chunk);
		else
		{
			err = asif_pread (asif->image, physical_offset, buffer, chunk, "data chunk");
			if (err)
				return -1;
		}
		offset += chunk;
		buffer += chunk;
		size -= chunk;
		total += (grub_ssize_t) chunk;
	}
	return total;
}

static grub_err_t
grub_asif_close (grub_file_t file)
{
	grub_asif_t asif = file->data;
	grub_file_t carrier = asif->file;

	asif_free_image (asif->image);
	grub_file_close (carrier);
	grub_free (asif);
	file->device = NULL;
	return grub_errno;
}

static struct grub_fs grub_asif_fs =
{
	.name = "asif",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_asif_read,
	.fs_close = grub_asif_close,
	.fs_label = 0,
	.next = 0
};

static grub_file_t
grub_asif_open (grub_file_t io, enum grub_file_type type)
{
	struct asif_image *image = NULL;
	grub_asif_t asif = NULL;
	grub_file_t file = NULL;
	grub_uint8_t signature[4];
	grub_err_t err;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK)
		|| io->size == GRUB_FILE_SIZE_UNKNOWN || io->size < sizeof (signature))
		return io;
	if (grub_file_seek (io, 0) == (grub_off_t) -1
		|| grub_file_read (io, signature, sizeof (signature))
			!= (grub_ssize_t) sizeof (signature))
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}
	if (asif_get_be32 (signature) != ASIF_MAGIC)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return NULL;
	image->carrier = io;
	image->file_size = grub_file_size (io);
	err = asif_open_image (image);
	if (err)
	{
		asif_free_image (image);
		return NULL;
	}

	file = grub_zalloc (sizeof (*file));
	asif = grub_zalloc (sizeof (*asif));
	if (!file || !asif)
	{
		asif_free_image (image);
		grub_free (file);
		grub_free (asif);
		return NULL;
	}
	asif->file = io;
	asif->image = image;
	file->device = io->device;
	file->data = asif;
	file->fs = &grub_asif_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->media_size;
	return file;
}

GRUB_MOD_INIT (asif)
{
	grub_file_filter_register (GRUB_FILE_FILTER_ASIF, grub_asif_open);
}

GRUB_MOD_FINI (asif)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_ASIF);
}
