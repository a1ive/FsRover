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

#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/fshelp.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/safemath.h>
#include <grub/types.h>

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define YAFFS_OBJECTID_ROOT		1U
#define YAFFS_OBJECTID_LOSTNFOUND	2U
#define YAFFS_OBJECTID_UNLINKED		3U
#define YAFFS_OBJECTID_DELETED		4U
#define YAFFS_OBJECTID_SUMMARY		0x10U
#define YAFFS_OBJECTID_CHECKPOINT	0x20U
#define YAFFS_SEQUENCE_CHECKPOINT	0x21U
#define YAFFS_SEQUENCE_LOWEST		0x00001000U
#define YAFFS_SEQUENCE_HIGHEST		0xefffff00U
#define YAFFS_SEQUENCE_BAD_BLOCK	0xffff0000U
#define YAFFS_OBJECT_MAX		0x0003ffffU
#define YAFFS_CHUNK_MAX			0x0fffffffU
#define YAFFS_NAME_MAX			255U
#define YAFFS_ALIAS_MAX			159U
#define YAFFS_OBJECT_BUCKETS		257U
#define YAFFS_DETECT_PAGES		4096U

#define YAFFS_TYPE_UNKNOWN	0U
#define YAFFS_TYPE_FILE		1U
#define YAFFS_TYPE_SYMLINK	2U
#define YAFFS_TYPE_DIRECTORY	3U
#define YAFFS_TYPE_HARDLINK	4U
#define YAFFS_TYPE_SPECIAL	5U

#define YAFFS_EXTRA_HEADER	0x80000000U
#define YAFFS_EXTRA_SHRINK	0x40000000U
#define YAFFS_EXTRA_SHADOWS	0x20000000U
#define YAFFS_EXTRA_FLAGS	0xf0000000U
#define YAFFS_EXTRA_TYPE_SHIFT	28U
#define YAFFS_EXTRA_TYPE_MASK	0xf0000000U

#define YAFFS_OH_TYPE		0U
#define YAFFS_OH_PARENT		4U
#define YAFFS_OH_NAME		10U
#define YAFFS_OH_MODE		268U
#define YAFFS_OH_ATIME		280U
#define YAFFS_OH_MTIME		284U
#define YAFFS_OH_CTIME		288U
#define YAFFS_OH_SIZE_LOW	292U
#define YAFFS_OH_EQUIV		296U
#define YAFFS_OH_ALIAS		300U
#define YAFFS_OH_INBAND_SHADOW	488U
#define YAFFS_OH_INBAND_SHRINK	492U
#define YAFFS_OH_SIZE_HIGH	496U
#define YAFFS_OH_SHADOWS	504U
#define YAFFS_OH_IS_SHRINK	508U
#define YAFFS_OH_SIZE		512U

struct grub_yaffs_geometry
{
	grub_uint32_t data_size;
	grub_uint32_t record_size;
	grub_uint32_t tags_offset;
	grub_uint16_t tags_size;
	grub_uint8_t version;
	grub_uint8_t big_endian;
	grub_uint8_t inband;
	grub_uint8_t tags_big_endian;
};

struct grub_yaffs_tags
{
	grub_uint32_t sequence;
	grub_uint32_t object;
	grub_uint32_t chunk;
	grub_uint32_t bytes;
	grub_uint32_t extra_parent;
	grub_uint32_t extra_type;
	grub_uint32_t extra_equiv;
	grub_uint8_t serial;
	grub_uint8_t used;
	grub_uint8_t deleted;
	grub_uint8_t extra;
	grub_uint8_t shrink;
	grub_uint8_t shadows;
};

struct grub_yaffs_chunk
{
	struct grub_yaffs_chunk *next;
	grub_uint64_t page;
	grub_uint32_t logical;
	grub_uint32_t bytes;
	grub_uint32_t sequence;
	grub_uint8_t serial;
};

struct grub_yaffs_object
{
	struct grub_yaffs_object *next;
	struct grub_yaffs_chunk *chunks;
	char *name;
	char *alias;
	grub_uint64_t header_page;
	grub_uint64_t size;
	grub_uint32_t id;
	grub_uint32_t parent;
	grub_uint32_t type;
	grub_uint32_t mode;
	grub_uint32_t mtime;
	grub_uint32_t equivalent;
	grub_uint32_t shadows;
	grub_uint32_t header_sequence;
	grub_uint8_t header_serial;
	grub_uint8_t valid;
	grub_uint8_t shadowed;
	grub_uint8_t synthetic;
};

struct grub_yaffs_data;

struct grub_fshelp_node
{
	struct grub_yaffs_data *data;
	struct grub_yaffs_object *object;
};

struct grub_yaffs_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	grub_uint64_t pages;
	struct grub_yaffs_geometry geometry;
	struct grub_yaffs_object *objects[YAFFS_OBJECT_BUCKETS];
	struct grub_fshelp_node root;
	struct grub_fshelp_node open_node;
	struct grub_yaffs_chunk *read_chunk;
	grub_uint32_t read_logical;
	grub_uint32_t object_count;
	grub_uint32_t header_count;
};

struct grub_yaffs_header
{
	grub_uint32_t type;
	grub_uint32_t parent;
	grub_uint32_t mode;
	grub_uint32_t mtime;
	grub_uint32_t equivalent;
	grub_uint32_t shadows;
	grub_uint32_t is_shrink;
	grub_uint64_t size;
	grub_size_t name_length;
	grub_size_t alias_length;
	grub_uint8_t name[YAFFS_NAME_MAX + 1];
	grub_uint8_t alias[YAFFS_ALIAS_MAX + 1];
};

static const struct grub_yaffs_geometry yaffs_geometries[] =
{
	/* Layout written by ref/yaffs2/utils/mkyaffs2image. */
	{ 2048, 2112, 2048, 28, 2, 0, 0 },
	/* Compact images written by yaffs2_image_maker, with and without tag ECC. */
	{ 2048, 2076, 2048, 28, 2, 0, 0 },
	{ 2048, 2064, 2048, 16, 2, 0, 0 },
	/* In-band tags occupy the final 16 bytes of the NAND data area. */
	{ 2032, 2048, 2032, 16, 2, 0, 1 },
	/* Other page sizes accepted by the reference flexible image tools. */
	{ 1024, 1056, 1024, 28, 2, 0, 0 },
	{ 1024, 1052, 1024, 28, 2, 0, 0 },
	{ 1024, 1040, 1024, 16, 2, 0, 0 },
	{ 1008, 1024, 1008, 16, 2, 0, 1 },
	{ 4096, 4224, 4096, 28, 2, 0, 0 },
	{ 4096, 4124, 4096, 28, 2, 0, 0 },
	{ 4096, 4112, 4096, 16, 2, 0, 0 },
	{ 4080, 4096, 4080, 16, 2, 0, 1 },
	{ 8192, 8448, 8192, 28, 2, 0, 0 },
	{ 8192, 8220, 8192, 28, 2, 0, 0 },
	{ 8192, 8208, 8192, 16, 2, 0, 0 },
	{ 8176, 8192, 8176, 16, 2, 0, 1 },
	/* YAFFS1 small-page NAND layout. */
	{ 512, 528, 512, 16, 1, 0, 0 }
};

static grub_uint32_t
yaffs_get_u32 (const grub_uint8_t *p, int big_endian)
{
	grub_uint32_t value = grub_get_unaligned32 (p);

	return big_endian ? grub_be_to_cpu32 (value) : grub_le_to_cpu32 (value);
}

static grub_err_t
yaffs_disk_read (grub_disk_t disk, grub_uint64_t disk_size,
	grub_uint64_t offset, grub_size_t length, void *buffer)
{
	if (offset > disk_size || length > disk_size - offset)
		return grub_error (GRUB_ERR_BAD_FS, "YAFFS read outside device");
	return grub_disk_read (disk, offset >> GRUB_DISK_SECTOR_BITS,
		(grub_off_t) (offset & (GRUB_DISK_SECTOR_SIZE - 1)), length, buffer);
}

static int
yaffs_all_ff (const grub_uint8_t *p, grub_size_t length)
{
	while (length-- > 0)
		if (*p++ != 0xff)
			return 0;
	return 1;
}

static int
yaffs_parse_tags2 (const struct grub_yaffs_geometry *geometry,
	const grub_uint8_t *raw, struct grub_yaffs_tags *tags)
{
	grub_uint32_t raw_object;
	grub_uint32_t raw_chunk;

	grub_memset (tags, 0, sizeof (*tags));
	if (yaffs_all_ff (raw, 16))
		return 1;
	tags->sequence = yaffs_get_u32 (raw, geometry->tags_big_endian);
	raw_object = yaffs_get_u32 (raw + 4, geometry->tags_big_endian);
	raw_chunk = yaffs_get_u32 (raw + 8, geometry->tags_big_endian);
	tags->bytes = yaffs_get_u32 (raw + 12, geometry->tags_big_endian);
	tags->used = 1;
	if (raw_chunk & YAFFS_EXTRA_HEADER)
	{
		tags->extra = 1;
		tags->chunk = 0;
		tags->extra_parent = raw_chunk & ~YAFFS_EXTRA_FLAGS;
		tags->shrink = (raw_chunk & YAFFS_EXTRA_SHRINK) != 0;
		tags->shadows = (raw_chunk & YAFFS_EXTRA_SHADOWS) != 0;
		tags->extra_type = raw_object >> YAFFS_EXTRA_TYPE_SHIFT;
		tags->object = raw_object & ~YAFFS_EXTRA_TYPE_MASK;
		if (tags->extra_type == YAFFS_TYPE_HARDLINK)
			tags->extra_equiv = tags->bytes;
		tags->bytes = 0;
	}
	else
	{
		tags->object = raw_object;
		tags->chunk = raw_chunk;
	}
	if (tags->sequence == YAFFS_SEQUENCE_CHECKPOINT
		|| tags->sequence == YAFFS_SEQUENCE_BAD_BLOCK)
		return 1;
	if (tags->sequence < YAFFS_SEQUENCE_LOWEST
		|| tags->sequence >= YAFFS_SEQUENCE_HIGHEST
		|| tags->object == 0 || tags->object > YAFFS_OBJECT_MAX
		|| tags->chunk > YAFFS_CHUNK_MAX
		|| (tags->chunk != 0 && tags->bytes > geometry->data_size)
		|| (tags->extra && (tags->extra_parent > YAFFS_OBJECT_MAX
			|| tags->extra_type == YAFFS_TYPE_UNKNOWN
			|| tags->extra_type > YAFFS_TYPE_SPECIAL)))
		return 0;
	return 1;
}

static int
yaffs_parse_tags1 (const grub_uint8_t *spare, struct grub_yaffs_tags *tags)
{
	grub_uint8_t packed[8];
	grub_uint32_t word0;
	grub_uint32_t word1;

	grub_memset (tags, 0, sizeof (*tags));
	if (yaffs_all_ff (spare, 16))
		return 1;
	if (spare[4] != 0xff)
	{
		tags->deleted = 1;
		return 1;
	}
	packed[0] = spare[0];
	packed[1] = spare[1];
	packed[2] = spare[2];
	packed[3] = spare[3];
	packed[4] = spare[6];
	packed[5] = spare[7];
	packed[6] = spare[11];
	packed[7] = spare[12];
	word0 = grub_le_to_cpu32 (grub_get_unaligned32 (packed));
	word1 = grub_le_to_cpu32 (grub_get_unaligned32 (packed + 4));
	tags->chunk = word0 & 0x000fffffU;
	tags->serial = (grub_uint8_t) ((word0 >> 20) & 3U);
	tags->bytes = (word0 >> 22) & 0x3ffU;
	tags->object = word1 & 0x0003ffffU;
	tags->used = 1;
	if (tags->object == 0 || tags->object > YAFFS_OBJECT_MAX
		|| tags->chunk > YAFFS_CHUNK_MAX
		|| (tags->chunk != 0 && tags->bytes > 512U))
		return 0;
	return 1;
}

static int
yaffs_parse_tags (const struct grub_yaffs_geometry *geometry,
	const grub_uint8_t *raw, struct grub_yaffs_tags *tags)
{
	if (geometry->version == 1)
		return yaffs_parse_tags1 (raw, tags);
	return yaffs_parse_tags2 (geometry, raw, tags);
}

static int
yaffs_name_valid (const grub_uint8_t *name, grub_size_t length)
{
	grub_size_t i;

	if (length == 0)
		return 0;
	for (i = 0; i < length; i++)
		if (name[i] == '/' || name[i] < 0x20 || name[i] == 0x7f)
			return 0;
	return 1;
}

static int
yaffs_parse_header (const struct grub_yaffs_geometry *geometry,
	const grub_uint8_t *raw, grub_uint32_t object,
	struct grub_yaffs_header *header)
{
	grub_uint32_t high;

	grub_memset (header, 0, sizeof (*header));
	header->type = yaffs_get_u32 (raw + YAFFS_OH_TYPE, geometry->big_endian);
	header->parent = yaffs_get_u32 (raw + YAFFS_OH_PARENT, geometry->big_endian);
	header->mode = yaffs_get_u32 (raw + YAFFS_OH_MODE, geometry->big_endian);
	header->mtime = yaffs_get_u32 (raw + YAFFS_OH_MTIME, geometry->big_endian);
	header->equivalent = yaffs_get_u32 (raw + YAFFS_OH_EQUIV, geometry->big_endian);
	header->shadows = yaffs_get_u32 (raw + YAFFS_OH_SHADOWS, geometry->big_endian);
	header->is_shrink = yaffs_get_u32 (raw + YAFFS_OH_IS_SHRINK, geometry->big_endian);
	if (geometry->inband)
	{
		header->shadows = yaffs_get_u32 (raw + YAFFS_OH_INBAND_SHADOW,
			geometry->big_endian);
		header->is_shrink = yaffs_get_u32 (raw + YAFFS_OH_INBAND_SHRINK,
			geometry->big_endian);
	}
	high = yaffs_get_u32 (raw + YAFFS_OH_SIZE_HIGH, geometry->big_endian);
	header->size = yaffs_get_u32 (raw + YAFFS_OH_SIZE_LOW, geometry->big_endian);
	if (high != 0xffffffffU)
		header->size |= (grub_uint64_t) high << 32;
	while (header->name_length <= YAFFS_NAME_MAX
		&& raw[YAFFS_OH_NAME + header->name_length] != 0)
		header->name_length++;
	if (header->name_length > YAFFS_NAME_MAX)
		return 0;
	grub_memcpy (header->name, raw + YAFFS_OH_NAME, header->name_length);
	if (header->type == YAFFS_TYPE_SYMLINK)
	{
		while (header->alias_length <= YAFFS_ALIAS_MAX
			&& raw[YAFFS_OH_ALIAS + header->alias_length] != 0)
			header->alias_length++;
		if (header->alias_length > YAFFS_ALIAS_MAX)
			return 0;
		grub_memcpy (header->alias, raw + YAFFS_OH_ALIAS,
			header->alias_length);
	}
	if (header->type == YAFFS_TYPE_UNKNOWN || header->type > YAFFS_TYPE_SPECIAL
		|| header->parent > YAFFS_OBJECT_MAX
		|| (object != YAFFS_OBJECTID_ROOT
			&& (!yaffs_name_valid (header->name, header->name_length)
				|| header->parent == 0))
		|| (header->type == YAFFS_TYPE_SYMLINK
			&& header->alias_length == 0)
		|| (header->type == YAFFS_TYPE_HARDLINK
			&& (header->equivalent == 0
				|| header->equivalent > YAFFS_OBJECT_MAX)))
		return 0;
	return 1;
}

static int
yaffs_header_matches_tags (const struct grub_yaffs_tags *tags,
	const struct grub_yaffs_header *header)
{
	if (!tags->extra)
		return 1;
	if (tags->extra_type != header->type || tags->extra_parent != header->parent)
		return 0;
	if (header->type == YAFFS_TYPE_HARDLINK
		&& tags->extra_equiv != header->equivalent)
		return 0;
	return 1;
}

static int
yaffs_try_geometry (grub_disk_t disk, grub_uint64_t disk_size,
	const struct grub_yaffs_geometry *geometry)
{
	grub_uint64_t pages;
	grub_uint64_t page;
	grub_uint64_t limit;
	grub_uint64_t offset;
	grub_uint8_t tags_raw[28];
	grub_uint8_t header_raw[YAFFS_OH_SIZE];
	struct grub_yaffs_header header;
	struct grub_yaffs_tags tags;
	int score = 0;
	unsigned valid_tags = 0;
	unsigned valid_headers = 0;
	unsigned invalid = 0;

	if (disk_size < geometry->record_size
		|| disk_size % geometry->record_size >= GRUB_DISK_SECTOR_SIZE)
		return -1;
	pages = disk_size / geometry->record_size;
	limit = pages < YAFFS_DETECT_PAGES ? pages : YAFFS_DETECT_PAGES;
	for (page = 0; page < limit; page++)
	{
		offset = page * geometry->record_size + geometry->tags_offset;
		if (yaffs_disk_read (disk, disk_size, offset,
			geometry->tags_size, tags_raw))
			return -1;
		if (!yaffs_parse_tags (geometry, tags_raw, &tags))
		{
			invalid++;
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		if (!tags.used || tags.deleted
			|| tags.sequence == YAFFS_SEQUENCE_CHECKPOINT
			|| tags.sequence == YAFFS_SEQUENCE_BAD_BLOCK
			|| tags.object == YAFFS_OBJECTID_SUMMARY
			|| tags.object == YAFFS_OBJECTID_CHECKPOINT)
			continue;
		valid_tags++;
		if (tags.chunk != 0)
			continue;
		if (yaffs_disk_read (disk, disk_size,
			page * geometry->record_size, sizeof (header_raw), header_raw))
			return -1;
		if (!yaffs_parse_header (geometry, header_raw, tags.object, &header)
			|| !yaffs_header_matches_tags (&tags, &header))
		{
			invalid++;
			continue;
		}
		valid_headers++;
	}
	if (valid_headers == 0 || valid_tags == 0)
		return -1;
	score = (int) valid_headers * 32 + (int) valid_tags - (int) invalid * 4;
	return score;
}

static int
yaffs_detect_geometry (grub_disk_t disk, grub_uint64_t disk_size,
	struct grub_yaffs_geometry *selected)
{
	grub_size_t i;
	int endian;
	int score;
	int best_score = -1;
	struct grub_yaffs_geometry candidate;

	for (i = 0; i < ARRAY_SIZE (yaffs_geometries); i++)
	{
		candidate = yaffs_geometries[i];
		for (endian = 0; endian < (candidate.version == 2 ? 4 : 1); endian++)
		{
			candidate.big_endian = (grub_uint8_t) (endian & 1);
			candidate.tags_big_endian = (grub_uint8_t) ((endian >> 1) & 1);
			score = yaffs_try_geometry (disk, disk_size, &candidate);
			grub_errno = GRUB_ERR_NONE;
			if (score > best_score)
			{
				best_score = score;
				*selected = candidate;
			}
		}
	}
	return best_score >= 0;
}

static struct grub_yaffs_object *
yaffs_find_object (struct grub_yaffs_data *data, grub_uint32_t id)
{
	struct grub_yaffs_object *object;

	for (object = data->objects[id % YAFFS_OBJECT_BUCKETS]; object;
		object = object->next)
		if (object->id == id)
			return object;
	return NULL;
}

static struct grub_yaffs_object *
yaffs_get_object (struct grub_yaffs_data *data, grub_uint32_t id)
{
	struct grub_yaffs_object *object;
	grub_uint32_t bucket = id % YAFFS_OBJECT_BUCKETS;

	object = yaffs_find_object (data, id);
	if (object)
		return object;
	object = grub_zalloc (sizeof (*object));
	if (!object)
		return NULL;
	object->id = id;
	object->next = data->objects[bucket];
	data->objects[bucket] = object;
	data->object_count++;
	return object;
}

static void
yaffs_free_object (struct grub_yaffs_object *object)
{
	struct grub_yaffs_chunk *chunk;
	struct grub_yaffs_chunk *next;

	for (chunk = object->chunks; chunk; chunk = next)
	{
		next = chunk->next;
		grub_free (chunk);
	}
	grub_free (object->name);
	grub_free (object->alias);
	grub_free (object);
}

static void
yaffs_free_data (struct grub_yaffs_data *data)
{
	struct grub_yaffs_object *object;
	struct grub_yaffs_object *next;
	grub_uint32_t i;

	if (!data)
		return;
	for (i = 0; i < YAFFS_OBJECT_BUCKETS; i++)
		for (object = data->objects[i]; object; object = next)
		{
			next = object->next;
			yaffs_free_object (object);
		}
	grub_free (data);
}

static int
yaffs_newer (const struct grub_yaffs_geometry *geometry,
	grub_uint32_t old_sequence, grub_uint64_t old_page, grub_uint8_t old_serial,
	grub_uint32_t sequence, grub_uint64_t page, grub_uint8_t serial)
{
	if (geometry->version == 1)
		return (((old_serial + 1U) & 3U) == serial);
	if (sequence != old_sequence)
		return sequence > old_sequence;
	return page > old_page;
}

static grub_err_t
yaffs_set_header (struct grub_yaffs_data *data,
	struct grub_yaffs_object *object, const struct grub_yaffs_tags *tags,
	const struct grub_yaffs_header *header, grub_uint64_t page)
{
	char *name = NULL;
	char *alias = NULL;

	if (object->valid && !yaffs_newer (&data->geometry,
		object->header_sequence, object->header_page, object->header_serial,
		tags->sequence, page, tags->serial))
		return GRUB_ERR_NONE;
	if (object->id == YAFFS_OBJECTID_ROOT)
		name = grub_strdup ("");
	else
		name = grub_fs_bytes_to_utf8 (header->name, header->name_length,
			grub_fs_char_encoding);
	if (!name)
		return grub_errno;
	if (header->type == YAFFS_TYPE_SYMLINK)
	{
		alias = grub_fs_bytes_to_utf8 (header->alias, header->alias_length,
			grub_fs_char_encoding);
		if (!alias)
		{
			grub_free (name);
			return grub_errno;
		}
	}
	grub_free (object->name);
	grub_free (object->alias);
	object->name = name;
	object->alias = alias;
	object->parent = header->parent;
	object->type = header->type;
	object->mode = header->mode;
	object->mtime = header->mtime;
	object->size = header->size;
	object->equivalent = header->equivalent;
	object->shadows = header->shadows;
	object->header_sequence = tags->sequence;
	object->header_page = page;
	object->header_serial = tags->serial;
	if (!object->valid)
		data->header_count++;
	object->valid = 1;
	object->synthetic = 0;
	return GRUB_ERR_NONE;
}

static grub_err_t
yaffs_add_chunk (struct grub_yaffs_data *data,
	struct grub_yaffs_object *object, const struct grub_yaffs_tags *tags,
	grub_uint64_t page)
{
	struct grub_yaffs_chunk **link = &object->chunks;
	struct grub_yaffs_chunk *chunk;

	while (*link && (*link)->logical < tags->chunk)
		link = &(*link)->next;
	if (*link && (*link)->logical == tags->chunk)
	{
		chunk = *link;
		if (!yaffs_newer (&data->geometry, chunk->sequence, chunk->page,
			chunk->serial, tags->sequence, page, tags->serial))
			return GRUB_ERR_NONE;
		chunk->page = page;
		chunk->bytes = tags->bytes;
		chunk->sequence = tags->sequence;
		chunk->serial = tags->serial;
		return GRUB_ERR_NONE;
	}
	chunk = grub_malloc (sizeof (*chunk));
	if (!chunk)
		return grub_errno;
	chunk->next = *link;
	chunk->page = page;
	chunk->logical = tags->chunk;
	chunk->bytes = tags->bytes;
	chunk->sequence = tags->sequence;
	chunk->serial = tags->serial;
	*link = chunk;
	return GRUB_ERR_NONE;
}

static grub_err_t
yaffs_scan (struct grub_yaffs_data *data)
{
	grub_uint8_t tags_raw[28];
	grub_uint8_t header_raw[YAFFS_OH_SIZE];
	struct grub_yaffs_header header;
	struct grub_yaffs_object *object;
	struct grub_yaffs_tags tags;
	grub_uint64_t page;
	grub_uint64_t base;

	for (page = 0; page < data->pages; page++)
	{
		base = page * data->geometry.record_size;
		if (yaffs_disk_read (data->disk, data->disk_size,
			base + data->geometry.tags_offset, data->geometry.tags_size,
			tags_raw))
			return grub_errno;
		if (!yaffs_parse_tags (&data->geometry, tags_raw, &tags))
			continue;
		if (!tags.used || tags.deleted
			|| tags.sequence == YAFFS_SEQUENCE_CHECKPOINT
			|| tags.sequence == YAFFS_SEQUENCE_BAD_BLOCK
			|| tags.object == YAFFS_OBJECTID_SUMMARY
			|| tags.object == YAFFS_OBJECTID_CHECKPOINT)
			continue;
		object = yaffs_get_object (data, tags.object);
		if (!object)
			return grub_errno;
		if (tags.chunk != 0)
		{
			if (yaffs_add_chunk (data, object, &tags, page))
				return grub_errno;
			continue;
		}
		if (yaffs_disk_read (data->disk, data->disk_size, base,
			sizeof (header_raw), header_raw))
			return grub_errno;
		if (!yaffs_parse_header (&data->geometry, header_raw,
			tags.object, &header) || !yaffs_header_matches_tags (&tags, &header))
			continue;
		if (yaffs_set_header (data, object, &tags, &header, page))
			return grub_errno;
	}
	return GRUB_ERR_NONE;
}

static int
yaffs_object_visible (const struct grub_yaffs_object *object)
{
	return object && object->valid && !object->shadowed
		&& object->parent != YAFFS_OBJECTID_UNLINKED
		&& object->parent != YAFFS_OBJECTID_DELETED;
}

static grub_err_t
yaffs_make_synthetic (struct grub_yaffs_data *data, grub_uint32_t id,
	grub_uint32_t parent, grub_uint32_t type, const char *name)
{
	struct grub_yaffs_object *object = yaffs_get_object (data, id);

	if (!object)
		return grub_errno;
	if (object->valid)
		return GRUB_ERR_NONE;
	object->name = grub_strdup (name);
	if (!object->name)
		return grub_errno;
	object->parent = parent;
	object->type = type;
	object->mode = type == YAFFS_TYPE_DIRECTORY ? 0040755U : 0100644U;
	object->valid = 1;
	object->synthetic = 1;
	return GRUB_ERR_NONE;
}

static grub_err_t
yaffs_validate_tree (struct grub_yaffs_data *data)
{
	struct grub_yaffs_object *object;
	struct grub_yaffs_object *parent;
	grub_uint32_t i;
	grub_uint32_t depth;
	grub_uint32_t pass;
	int changed;
	int need_lost_found = 0;

	if (yaffs_make_synthetic (data, YAFFS_OBJECTID_ROOT,
		YAFFS_OBJECTID_ROOT, YAFFS_TYPE_DIRECTORY, ""))
		return grub_errno;
	parent = yaffs_find_object (data, YAFFS_OBJECTID_ROOT);
	if (!parent || parent->type != YAFFS_TYPE_DIRECTORY)
		return grub_error (GRUB_ERR_BAD_FS, "invalid YAFFS root object");
	for (i = 0; i < YAFFS_OBJECT_BUCKETS; i++)
		for (object = data->objects[i]; object; object = object->next)
		{
			if (object->valid && object->shadows != 0
				&& object->shadows <= YAFFS_OBJECT_MAX)
			{
				parent = yaffs_find_object (data, object->shadows);
				if (parent)
					parent->shadowed = 1;
			}
			if (object->valid && object->parent == YAFFS_OBJECTID_LOSTNFOUND)
				need_lost_found = 1;
		}
	if (need_lost_found && yaffs_make_synthetic (data,
		YAFFS_OBJECTID_LOSTNFOUND, YAFFS_OBJECTID_ROOT,
		YAFFS_TYPE_DIRECTORY, "lost+found"))
		return grub_errno;
	/* Objects below an unlinked, deleted, or shadowed directory are hidden too. */
	for (pass = 0; pass < data->object_count; pass++)
	{
		changed = 0;
		for (i = 0; i < YAFFS_OBJECT_BUCKETS; i++)
			for (object = data->objects[i]; object; object = object->next)
			{
				if (!yaffs_object_visible (object)
					|| object->id == YAFFS_OBJECTID_ROOT)
					continue;
				parent = yaffs_find_object (data, object->parent);
				if (parent && parent->valid
					&& (parent->shadowed
						|| parent->parent == YAFFS_OBJECTID_UNLINKED
						|| parent->parent == YAFFS_OBJECTID_DELETED))
				{
					object->shadowed = 1;
					changed = 1;
				}
			}
		if (!changed)
			break;
	}
	for (i = 0; i < YAFFS_OBJECT_BUCKETS; i++)
		for (object = data->objects[i]; object; object = object->next)
		{
			if (!yaffs_object_visible (object)
				|| object->id == YAFFS_OBJECTID_ROOT)
				continue;
			parent = object;
			for (depth = 0; depth <= data->object_count; depth++)
			{
				if (parent->id == YAFFS_OBJECTID_ROOT)
					break;
				parent = yaffs_find_object (data, parent->parent);
				if (!yaffs_object_visible (parent)
					|| parent->type != YAFFS_TYPE_DIRECTORY)
					return grub_error (GRUB_ERR_BAD_FS,
						"invalid YAFFS parent object");
			}
			if (depth > data->object_count)
				return grub_error (GRUB_ERR_BAD_FS,
					"cyclic YAFFS parent objects");
		}
	return GRUB_ERR_NONE;
}

static struct grub_yaffs_data *
yaffs_mount (grub_disk_t disk)
{
	struct grub_yaffs_data *data;
	grub_disk_addr_t sectors;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	sectors = grub_disk_native_sectors (disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN
		|| sectors > (~(grub_uint64_t) 0 >> GRUB_DISK_SECTOR_BITS))
	{
		grub_error (GRUB_ERR_BAD_FS, "YAFFS requires a bounded device");
		goto fail;
	}
	data->disk_size = (grub_uint64_t) sectors << GRUB_DISK_SECTOR_BITS;
	if (!yaffs_detect_geometry (disk, data->disk_size, &data->geometry))
	{
		grub_error (GRUB_ERR_BAD_FS, "not a supported YAFFS filesystem");
		goto fail;
	}
	data->pages = data->disk_size / data->geometry.record_size;
	if (data->pages == 0 || data->pages > 0xffffffffU)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid YAFFS page count");
		goto fail;
	}
	if (yaffs_scan (data) || data->header_count == 0
		|| yaffs_validate_tree (data))
		goto fail;
	data->root.data = data;
	data->root.object = yaffs_find_object (data, YAFFS_OBJECTID_ROOT);
	return data;

fail:
	yaffs_free_data (data);
	return NULL;
}

static struct grub_yaffs_object *
yaffs_resolve_hardlink (struct grub_yaffs_data *data,
	struct grub_yaffs_object *object)
{
	grub_uint32_t depth;

	for (depth = 0; object && object->type == YAFFS_TYPE_HARDLINK
		&& depth <= data->object_count; depth++)
		object = yaffs_find_object (data, object->equivalent);
	if (!yaffs_object_visible (object) || depth > data->object_count)
		return NULL;
	return object;
}

static enum grub_fshelp_filetype
yaffs_filetype (struct grub_yaffs_data *data, struct grub_yaffs_object *object)
{
	struct grub_yaffs_object *target;

	if (object->type == YAFFS_TYPE_SYMLINK)
		return GRUB_FSHELP_SYMLINK;
	target = yaffs_resolve_hardlink (data, object);
	if (target && target->type == YAFFS_TYPE_DIRECTORY)
		return GRUB_FSHELP_DIR;
	return GRUB_FSHELP_REG;
}

static int
yaffs_iterate_directory (grub_fshelp_node_t directory,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_yaffs_data *data = directory->data;
	struct grub_yaffs_object *object;
	struct grub_fshelp_node *node;
	grub_uint32_t i;

	if (directory->object->type != YAFFS_TYPE_DIRECTORY)
		return 0;
	for (i = 0; i < YAFFS_OBJECT_BUCKETS; i++)
		for (object = data->objects[i]; object; object = object->next)
		{
			if (!yaffs_object_visible (object)
				|| object->id == YAFFS_OBJECTID_ROOT
				|| object->parent != directory->object->id)
				continue;
			node = grub_malloc (sizeof (*node));
			if (!node)
				return 1;
			node->data = data;
			node->object = object;
			if (hook (object->name, yaffs_filetype (data, object),
				node, hook_data))
				return 1;
		}
	return 0;
}

static char *
yaffs_read_symlink (grub_fshelp_node_t node)
{
	if (node->object->type != YAFFS_TYPE_SYMLINK || !node->object->alias)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a YAFFS symbolic link");
		return NULL;
	}
	return grub_strdup (node->object->alias);
}

static grub_err_t
grub_yaffs_open (struct grub_file *file, const char *name)
{
	struct grub_yaffs_data *data;
	struct grub_fshelp_node *node = NULL;
	struct grub_yaffs_object *target;

	data = yaffs_mount (file->device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (name, &data->root, &node,
		yaffs_iterate_directory, yaffs_read_symlink, GRUB_FSHELP_REG))
		goto fail;
	target = yaffs_resolve_hardlink (data, node->object);
	if (!target || (target->type != YAFFS_TYPE_FILE
		&& target->type != YAFFS_TYPE_SPECIAL))
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a regular YAFFS file");
		goto fail;
	}
	data->open_node.data = data;
	data->open_node.object = target;
	data->read_chunk = target->chunks;
	data->read_logical = data->read_chunk ? data->read_chunk->logical : 0;
	file->data = data;
	file->size = target->size;
	file->offset = 0;
	if (node != &data->root)
		grub_free (node);
	return GRUB_ERR_NONE;

fail:
	if (node && node != &data->root)
		grub_free (node);
	yaffs_free_data (data);
	return grub_errno;
}

static struct grub_yaffs_chunk *
yaffs_find_chunk (struct grub_yaffs_data *data, grub_uint32_t logical)
{
	struct grub_yaffs_chunk *chunk;

	chunk = data->read_chunk;
	if (!chunk || logical < data->read_logical)
		chunk = data->open_node.object->chunks;
	while (chunk && chunk->logical < logical)
		chunk = chunk->next;
	data->read_chunk = chunk;
	data->read_logical = chunk ? chunk->logical : 0xffffffffU;
	return chunk && chunk->logical == logical ? chunk : NULL;
}

static grub_ssize_t
grub_yaffs_read (grub_file_t file, char *buffer, grub_size_t length)
{
	struct grub_yaffs_data *data = file->data;
	struct grub_yaffs_object *object = data->open_node.object;
	struct grub_yaffs_chunk *chunk;
	grub_uint64_t offset = file->offset;
	grub_uint64_t physical;
	grub_uint32_t logical;
	grub_uint32_t in_chunk;
	grub_size_t part;
	grub_size_t total = 0;

	if (offset > object->size)
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of YAFFS file");
		return -1;
	}
	if (length > object->size - offset)
		length = (grub_size_t) (object->size - offset);
	while (total < length)
	{
		logical = (grub_uint32_t) (offset / data->geometry.data_size) + 1;
		in_chunk = (grub_uint32_t) (offset % data->geometry.data_size);
		part = length - total;
		if (part > data->geometry.data_size - in_chunk)
			part = data->geometry.data_size - in_chunk;
		chunk = yaffs_find_chunk (data, logical);
		if (!chunk || in_chunk >= chunk->bytes)
			grub_memset (buffer + total, 0, part);
		else
		{
			if (part > chunk->bytes - in_chunk)
			{
				grub_size_t present = chunk->bytes - in_chunk;

				physical = chunk->page * data->geometry.record_size + in_chunk;
				data->disk->read_hook = file->read_hook;
				data->disk->read_hook_data = file->read_hook_data;
				if (yaffs_disk_read (data->disk, data->disk_size,
					physical, present, buffer + total))
				{
					data->disk->read_hook = NULL;
					return -1;
				}
				data->disk->read_hook = NULL;
				grub_memset (buffer + total + present, 0, part - present);
			}
			else
			{
				physical = chunk->page * data->geometry.record_size + in_chunk;
				data->disk->read_hook = file->read_hook;
				data->disk->read_hook_data = file->read_hook_data;
				if (yaffs_disk_read (data->disk, data->disk_size,
					physical, part, buffer + total))
				{
					data->disk->read_hook = NULL;
					return -1;
				}
				data->disk->read_hook = NULL;
			}
		}
		total += part;
		offset += part;
	}
	return (grub_ssize_t) total;
}

static grub_err_t
grub_yaffs_close (grub_file_t file)
{
	yaffs_free_data (file->data);
	file->data = NULL;
	return GRUB_ERR_NONE;
}

struct grub_yaffs_dir_context
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_yaffs_dir_hook (const char *name, enum grub_fshelp_filetype type,
	grub_fshelp_node_t node, void *hook_data)
{
	struct grub_yaffs_dir_context *context = hook_data;
	struct grub_yaffs_object *target;
	struct grub_dirhook_info info;
	int stop;

	grub_memset (&info, 0, sizeof (info));
	info.dir = ((type & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink = ((type & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK);
	target = yaffs_resolve_hardlink (node->data, node->object);
	if (!target)
		target = node->object;
	info.mtime = target->mtime;
	info.mtimeset = 1;
	info.inode = node->object->id;
	info.inodeset = 1;
	if (!info.dir && !info.symlink)
	{
		info.sizeset = 1;
		info.size = target->size;
	}
	stop = context->hook (name, &info, context->hook_data);
	grub_free (node);
	return stop;
}

static grub_err_t
grub_yaffs_dir (grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_yaffs_dir_context context = { hook, hook_data };
	struct grub_yaffs_data *data;
	struct grub_fshelp_node *directory = NULL;

	data = yaffs_mount (device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (path, &data->root, &directory,
		yaffs_iterate_directory, yaffs_read_symlink, GRUB_FSHELP_DIR))
		goto out;
	yaffs_iterate_directory (directory, grub_yaffs_dir_hook, &context);

out:
	if (directory && directory != &data->root)
		grub_free (directory);
	yaffs_free_data (data);
	return grub_errno;
}

static struct grub_fs grub_yaffs_fs =
{
	.name = "yaffs",
	.fs_dir = grub_yaffs_dir,
	.fs_open = grub_yaffs_open,
	.fs_read = grub_yaffs_read,
	.fs_close = grub_yaffs_close,
	.next = NULL
};

GRUB_MOD_INIT (yaffs)
{
	grub_yaffs_fs.mod = mod;
	grub_fs_register (&grub_yaffs_fs);
}

GRUB_MOD_FINI (yaffs)
{
	grub_fs_unregister (&grub_yaffs_fs);
}
