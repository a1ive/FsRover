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
 * DwarFS 2.x driver.
 *
 * DwarFS metadata is not described by a fixed on-disk structure.  Every
 * image carries a Compact Thrift encoded Frozen2 schema which gives the bit
 * width and position of every field.
 */

#include <grub/types.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/safemath.h>
#include <grub/crypto.h>

#include <zstd.h>
#include <lz4.h>
#include <brotli/decode.h>
#include <xz.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define DWARFS_MAGIC		"DWARFS"
#define DWARFS_MAGIC_SIZE	6
#define DWARFS_MAJOR		2
#define DWARFS_MINOR_MAX	6
#define DWARFS_V1_HEADER_SIZE	8
#define DWARFS_V2_HEADER_SIZE	64
#define DWARFS_SECTOR_BITS	9
#define DWARFS_SECTION_BLOCK	0
#define DWARFS_SECTION_SCHEMA	7
#define DWARFS_SECTION_METADATA	8
#define DWARFS_SECTION_INDEX	9
#define DWARFS_SECTION_HISTORY	10
#define DWARFS_COMP_NONE	0
#define DWARFS_COMP_LZMA	1
#define DWARFS_COMP_ZSTD	2
#define DWARFS_COMP_LZ4		3
#define DWARFS_COMP_LZ4HC	4
#define DWARFS_COMP_BROTLI	5
#define DWARFS_COMP_FLAC	6
#define DWARFS_COMP_RICEPP	7
#define DWARFS_METADATA_LIMIT	(512U << 20)
#define DWARFS_SECTION_LIMIT	((grub_uint64_t) 1 << 40)
#define DWARFS_PATH_DEPTH_MAX	64
#define DWARFS_FROZEN_FILE_VERSION	1
#define DWARFS_FROZEN_LAYOUT_MAX	4096
#define DWARFS_FROZEN_FIELD_MAX	16384
#define DWARFS_FSST_VERSION	20190218ULL
#define DWARFS_FSST_ESC		255
#define DWARFS_MODE_TYPE_MASK	0170000U
#define DWARFS_MODE_DIRECTORY	0040000U
#define DWARFS_MODE_REGULAR	0100000U
#define DWARFS_MODE_SYMLINK	0120000U
#define DWARFS_LARGE_HOLE_OFFSET	0xffffffffU
#define DWARFS_UINT64_MAX	(~(grub_uint64_t) 0)
#define DWARFS_INT64_MAX	((grub_int64_t) (DWARFS_UINT64_MAX >> 1))

enum dwarfs_compact_type
{
	DWARFS_CT_STOP = 0,
	DWARFS_CT_TRUE = 1,
	DWARFS_CT_FALSE = 2,
	DWARFS_CT_BYTE = 3,
	DWARFS_CT_I16 = 4,
	DWARFS_CT_I32 = 5,
	DWARFS_CT_I64 = 6,
	DWARFS_CT_DOUBLE = 7,
	DWARFS_CT_BINARY = 8,
	DWARFS_CT_LIST = 9,
	DWARFS_CT_SET = 10,
	DWARFS_CT_MAP = 11,
	DWARFS_CT_STRUCT = 12,
	DWARFS_CT_FLOAT = 13
};

struct dwarfs_section
{
	grub_uint64_t offset;
	grub_uint64_t length;
	grub_uint16_t compression;
	grub_uint8_t checksummed;
	grub_uint8_t sha2_512_256[32];
	grub_uint8_t integrity_header[24];
};

struct dwarfs_field
{
	grub_int16_t id;
	grub_int16_t layout_id;
	grub_int16_t offset;
};

struct dwarfs_layout
{
	grub_int16_t id;
	grub_uint32_t size;
	grub_uint16_t bits;
	struct dwarfs_field *fields;
	grub_size_t field_count;
};

struct dwarfs_schema
{
	struct dwarfs_layout *layouts;
	grub_size_t layout_count;
	grub_size_t field_count;
	grub_int16_t root_id;
	grub_int32_t file_version;
};

struct dwarfs_view
{
	const struct dwarfs_layout *layout;
	const grub_uint8_t *base;
	grub_size_t bit;
};

struct dwarfs_array
{
	struct dwarfs_view view;
	const struct dwarfs_layout *item_layout;
	const grub_uint8_t *data;
	grub_uint64_t count;
};

struct dwarfs_fsst_decoder
{
	grub_uint8_t zero_terminated;
	grub_uint8_t len[255];
	grub_uint64_t symbol[255];
};

struct dwarfs_string_table
{
	int compact;
	struct dwarfs_array legacy;
	const grub_uint8_t *buffer;
	grub_size_t buffer_size;
	grub_uint32_t *index;
	grub_size_t count;
	int fsst;
	struct dwarfs_fsst_decoder decoder;
};

struct dwarfs_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	grub_uint64_t image_offset;
	grub_uint8_t minor;
	int header_version;
	struct dwarfs_section schema_section;
	struct dwarfs_section metadata_section;
	struct dwarfs_section *blocks;
	grub_size_t block_count;
	grub_size_t block_capacity;
	grub_uint8_t *schema_buf;
	grub_size_t schema_size;
	grub_uint8_t *metadata_buf;
	grub_size_t metadata_size;
	struct dwarfs_schema schema;
	struct dwarfs_view root;
	struct dwarfs_array chunks;
	struct dwarfs_array directories;
	struct dwarfs_array inodes;
	struct dwarfs_array chunk_table;
	struct dwarfs_array entry_table;
	struct dwarfs_array symlink_table;
	struct dwarfs_array modes;
	struct dwarfs_array dir_entries;
	struct dwarfs_array shared_files;
	struct dwarfs_array large_holes;
	struct dwarfs_string_table names;
	struct dwarfs_string_table symlinks;
	grub_uint32_t *directory_first;
	grub_uint32_t *chunk_first;
	grub_uint32_t *shared_map;
	grub_size_t shared_count;
	grub_uint32_t block_size;
	grub_uint32_t hole_block;
	int has_hole_block;
	int modern;
	int packed_directories;
	int packed_chunk_table;
	int packed_shared_files;
	grub_uint32_t symlink_inode_offset;
	grub_uint32_t file_inode_offset;
	grub_uint32_t dev_inode_offset;
	grub_uint32_t unique_files;
	grub_uint64_t timestamp_base;
	grub_uint32_t time_resolution;
};

struct dwarfs_file
{
	struct dwarfs_data *data;
	grub_uint32_t inode;
	grub_uint32_t chunk_begin;
	grub_uint32_t chunk_end;
	grub_uint8_t *block_buf;
	grub_size_t block_size;
	grub_uint32_t cached_block;
};

struct dwarfs_compact
{
	const grub_uint8_t *p;
	const grub_uint8_t *end;
};

static const struct dwarfs_layout dwarfs_empty_layout;

static grub_uint16_t
dwarfs_le16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
dwarfs_le32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
dwarfs_le64 (const grub_uint8_t *p)
{
	return grub_le_to_cpu64 (grub_get_unaligned64 (p));
}

static int
dwarfs_read_at (struct dwarfs_data *data, grub_uint64_t offset,
	grub_size_t size, void *buf)
{
	grub_uint64_t end;

	if (grub_add (offset, (grub_uint64_t) size, &end)
		|| end > data->disk_size)
	{
		grub_error (GRUB_ERR_BAD_FS, "DwarFS read outside image");
		return -1;
	}
	if (grub_disk_read (data->disk, offset >> DWARFS_SECTOR_BITS,
		(unsigned) (offset & ((1U << DWARFS_SECTOR_BITS) - 1)), size, buf))
		return -1;
	return 0;
}

static int
dwarfs_compact_varint (struct dwarfs_compact *cp, grub_uint64_t *value)
{
	grub_uint64_t result = 0;
	unsigned shift = 0;

	while (cp->p < cp->end && shift < 64)
	{
		grub_uint8_t byte = *cp->p++;

		result |= (grub_uint64_t) (byte & 0x7f) << shift;
		if (!(byte & 0x80))
		{
			*value = result;
			return 0;
		}
		shift += 7;
	}
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS Thrift varint");
	return -1;
}

static int
dwarfs_compact_integer (struct dwarfs_compact *cp, grub_int64_t *value)
{
	grub_uint64_t encoded;

	if (dwarfs_compact_varint (cp, &encoded) != 0)
		return -1;
	*value = (grub_int64_t) (encoded >> 1) ^ -(grub_int64_t) (encoded & 1);
	return 0;
}

static int
dwarfs_compact_field (struct dwarfs_compact *cp, grub_int16_t *last,
	grub_int16_t *id, grub_uint8_t *type)
{
	grub_uint8_t header;
	grub_uint8_t delta;
	grub_int64_t explicit_id;

	if (cp->p >= cp->end)
		goto truncated;
	header = *cp->p++;
	*type = header & 0x0f;
	if (*type == DWARFS_CT_STOP)
		return 0;
	delta = header >> 4;
	if (delta)
		*id = (grub_int16_t) (*last + delta);
	else
	{
		if (dwarfs_compact_integer (cp, &explicit_id) != 0)
			return -1;
		if (explicit_id < GRUB_SHRT_MIN || explicit_id > GRUB_SHRT_MAX)
			goto invalid;
		*id = (grub_int16_t) explicit_id;
	}
	*last = *id;
	return 1;

truncated:
	grub_error (GRUB_ERR_BAD_FS, "truncated DwarFS Thrift field");
	return -1;
invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS Thrift field id");
	return -1;
}

static int dwarfs_compact_skip (struct dwarfs_compact *cp,
	grub_uint8_t type);

static int
dwarfs_compact_collection (struct dwarfs_compact *cp, grub_uint64_t *count,
	grub_uint8_t *type)
{
	grub_uint8_t header;

	if (cp->p >= cp->end)
		goto truncated;
	header = *cp->p++;
	*count = header >> 4;
	*type = header & 0x0f;
	if (*count == 15 && dwarfs_compact_varint (cp, count) != 0)
		return -1;
	return 0;

truncated:
	grub_error (GRUB_ERR_BAD_FS, "truncated DwarFS Thrift collection");
	return -1;
}

static int
dwarfs_compact_map (struct dwarfs_compact *cp, grub_uint64_t *count,
	grub_uint8_t *key_type, grub_uint8_t *value_type)
{
	grub_uint8_t types;

	if (dwarfs_compact_varint (cp, count) != 0)
		return -1;
	if (!*count)
	{
		*key_type = DWARFS_CT_STOP;
		*value_type = DWARFS_CT_STOP;
		return 0;
	}
	if (cp->p >= cp->end)
		goto truncated;
	types = *cp->p++;
	*key_type = types >> 4;
	*value_type = types & 0x0f;
	return 0;

truncated:
	grub_error (GRUB_ERR_BAD_FS, "truncated DwarFS Thrift map");
	return -1;
}

static int
dwarfs_compact_skip_struct (struct dwarfs_compact *cp)
{
	grub_int16_t last = 0;
	grub_int16_t id;
	grub_uint8_t type;
	int result;

	while ((result = dwarfs_compact_field (cp, &last, &id, &type)) > 0)
		if (dwarfs_compact_skip (cp, type) != 0)
			return -1;
	return result < 0 ? -1 : 0;
}

static int
dwarfs_compact_skip (struct dwarfs_compact *cp, grub_uint8_t type)
{
	grub_uint64_t count;
	grub_uint64_t length;
	grub_uint64_t i;
	grub_uint8_t key_type;
	grub_uint8_t value_type;
	grub_int64_t integer;

	switch (type)
	{
	case DWARFS_CT_TRUE:
	case DWARFS_CT_FALSE:
		return 0;
	case DWARFS_CT_BYTE:
		if (cp->p >= cp->end)
			break;
		cp->p++;
		return 0;
	case DWARFS_CT_I16:
	case DWARFS_CT_I32:
	case DWARFS_CT_I64:
		return dwarfs_compact_integer (cp, &integer);
	case DWARFS_CT_DOUBLE:
		length = 8;
		goto fixed;
	case DWARFS_CT_FLOAT:
		length = 4;
		goto fixed;
	case DWARFS_CT_BINARY:
		if (dwarfs_compact_varint (cp, &length) != 0)
			return -1;
	fixed:
		if (length > (grub_uint64_t) (cp->end - cp->p))
			break;
		cp->p += (grub_size_t) length;
		return 0;
	case DWARFS_CT_LIST:
	case DWARFS_CT_SET:
		if (dwarfs_compact_collection (cp, &count, &value_type) != 0)
			return -1;
		for (i = 0; i < count; i++)
			if (dwarfs_compact_skip (cp, value_type) != 0)
				return -1;
		return 0;
	case DWARFS_CT_MAP:
		if (dwarfs_compact_map (cp, &count, &key_type, &value_type) != 0)
			return -1;
		for (i = 0; i < count; i++)
			if (dwarfs_compact_skip (cp, key_type) != 0
				|| dwarfs_compact_skip (cp, value_type) != 0)
				return -1;
		return 0;
	case DWARFS_CT_STRUCT:
		return dwarfs_compact_skip_struct (cp);
	default:
		grub_error (GRUB_ERR_BAD_FS, "unknown DwarFS Thrift type");
		return -1;
	}
	grub_error (GRUB_ERR_BAD_FS, "truncated DwarFS Thrift value");
	return -1;
}

static int
dwarfs_schema_field_value (struct dwarfs_compact *cp, grub_uint8_t type,
	grub_int16_t *value)
{
	grub_int64_t number;

	if (type != DWARFS_CT_I16 || dwarfs_compact_integer (cp, &number) != 0)
		return -1;
	if (number < GRUB_SHRT_MIN || number > GRUB_SHRT_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS schema integer");
		return -1;
	}
	*value = (grub_int16_t) number;
	return 0;
}

static int
dwarfs_schema_parse_field (struct dwarfs_compact *cp,
	struct dwarfs_field *field)
{
	grub_int16_t last = 0;
	grub_int16_t id;
	grub_uint8_t type;
	int result;

	grub_memset (field, 0, sizeof (*field));
	field->layout_id = -1;
	while ((result = dwarfs_compact_field (cp, &last, &id, &type)) > 0)
	{
		if (id == 1)
		{
			if (dwarfs_schema_field_value (cp, type, &field->layout_id) != 0)
				return -1;
		}
		else if (id == 2)
		{
			if (dwarfs_schema_field_value (cp, type, &field->offset) != 0)
				return -1;
		}
		else if (dwarfs_compact_skip (cp, type) != 0)
			return -1;
	}
	if (result < 0)
		return -1;
	if (field->layout_id < 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "DwarFS schema field has no layout");
		return -1;
	}
	return 0;
}

static int
dwarfs_schema_add_field (struct dwarfs_schema *schema,
	struct dwarfs_layout *layout, struct dwarfs_field field)
{
	struct dwarfs_field *fields;

	if (schema->field_count >= DWARFS_FROZEN_FIELD_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "too many DwarFS schema fields");
		return -1;
	}
	fields = grub_realloc (layout->fields,
		(layout->field_count + 1) * sizeof (*fields));
	if (!fields)
		return -1;
	layout->fields = fields;
	layout->fields[layout->field_count++] = field;
	schema->field_count++;
	return 0;
}

static int
dwarfs_schema_parse_layout (struct dwarfs_compact *cp,
	struct dwarfs_schema *schema, struct dwarfs_layout *layout)
{
	grub_int16_t last = 0;
	grub_int16_t id;
	grub_uint8_t type;
	grub_uint8_t key_type;
	grub_uint8_t value_type;
	grub_uint64_t count;
	grub_uint64_t i;
	grub_int64_t value;
	int result;

	while ((result = dwarfs_compact_field (cp, &last, &id, &type)) > 0)
	{
		if (id == 1 || id == 2)
		{
			if ((id == 1 && type != DWARFS_CT_I32)
				|| (id == 2 && type != DWARFS_CT_I16)
				|| dwarfs_compact_integer (cp, &value) != 0)
			{
				grub_error (GRUB_ERR_BAD_FS,
					"invalid DwarFS layout property %d type %u", id, type);
				return -1;
			}
			if (value < 0
				|| (id == 1 && (grub_uint64_t) value > GRUB_UINT_MAX)
				|| (id == 2 && (grub_uint64_t) value > GRUB_USHRT_MAX))
			{
				grub_error (GRUB_ERR_BAD_FS,
					"invalid DwarFS layout property %d value %lld", id, value);
				return -1;
			}
			if (id == 1)
				layout->size = (grub_uint32_t) value;
			else
				layout->bits = (grub_uint16_t) value;
		}
		else if (id == 3)
		{
			if (type != DWARFS_CT_MAP
				|| dwarfs_compact_map (cp, &count, &key_type, &value_type) != 0)
				return -1;
			if (count && (key_type != DWARFS_CT_I16
				|| value_type != DWARFS_CT_STRUCT))
			{
				grub_error (GRUB_ERR_BAD_FS,
					"invalid DwarFS field map types %u/%u",
					key_type, value_type);
				return -1;
			}
			for (i = 0; i < count; i++)
			{
				struct dwarfs_field field;

				if (dwarfs_compact_integer (cp, &value) != 0
					|| value < GRUB_SHRT_MIN || value > GRUB_SHRT_MAX)
				{
					grub_error (GRUB_ERR_BAD_FS,
						"invalid DwarFS field id");
					return -1;
				}
				if (dwarfs_schema_parse_field (cp, &field) != 0)
					return -1;
				field.id = (grub_int16_t) value;
				if (dwarfs_schema_add_field (schema, layout, field) != 0)
					return -1;
			}
		}
		else if (dwarfs_compact_skip (cp, type) != 0)
			return -1;
	}
	if (result < 0)
		return -1;
	return 0;
}

static int
dwarfs_schema_add_layout (struct dwarfs_schema *schema,
	struct dwarfs_layout layout)
{
	struct dwarfs_layout *layouts;

	if (schema->layout_count >= DWARFS_FROZEN_LAYOUT_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "too many DwarFS schema layouts");
		return -1;
	}
	layouts = grub_realloc (schema->layouts,
		(schema->layout_count + 1) * sizeof (*layouts));
	if (!layouts)
		return -1;
	schema->layouts = layouts;
	schema->layouts[schema->layout_count++] = layout;
	return 0;
}

static int
dwarfs_schema_parse (struct dwarfs_schema *schema,
	const grub_uint8_t *buf, grub_size_t size)
{
	struct dwarfs_compact cp = { buf, buf + size };
	grub_int16_t last = 0;
	grub_int16_t id;
	grub_uint8_t type;
	grub_uint8_t key_type;
	grub_uint8_t value_type;
	grub_uint64_t count;
	grub_uint64_t i;
	grub_int64_t value;
	int result;

	grub_memset (schema, 0, sizeof (*schema));
	schema->root_id = -1;
	while ((result = dwarfs_compact_field (&cp, &last, &id, &type)) > 0)
	{
		if (id == 2)
		{
			if (type != DWARFS_CT_MAP
				|| dwarfs_compact_map (&cp, &count, &key_type, &value_type) != 0)
				goto fail;
			if (key_type != DWARFS_CT_I16 || value_type != DWARFS_CT_STRUCT)
				goto invalid;
			for (i = 0; i < count; i++)
			{
				struct dwarfs_layout layout;

				grub_memset (&layout, 0, sizeof (layout));
				if (dwarfs_compact_integer (&cp, &value) != 0
					|| value < 0 || value > GRUB_SHRT_MAX)
					goto invalid;
				layout.id = (grub_int16_t) value;
				if (dwarfs_schema_parse_layout (&cp, schema, &layout) != 0)
				{
					grub_free (layout.fields);
					goto fail;
				}
				if (dwarfs_schema_add_layout (schema, layout) != 0)
				{
					grub_free (layout.fields);
					goto fail;
				}
			}
		}
		else if (id == 3)
		{
			if (dwarfs_schema_field_value (&cp, type, &schema->root_id) != 0)
				goto fail;
		}
		else if (id == 4)
		{
			if (type != DWARFS_CT_I32
				|| dwarfs_compact_integer (&cp, &value) != 0
				|| value < 0 || value > GRUB_INT32_MAX)
				goto invalid;
			schema->file_version = (grub_int32_t) value;
		}
		else if (dwarfs_compact_skip (&cp, type) != 0)
			goto fail;
	}
	if (result < 0)
		goto fail;
	if (schema->root_id < 0 || !schema->layout_count
		|| schema->file_version > DWARFS_FROZEN_FILE_VERSION)
		goto invalid;
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid or unsupported DwarFS Frozen schema");
fail:
	return -1;
}

static const struct dwarfs_layout *
dwarfs_layout_find (const struct dwarfs_schema *schema, grub_int16_t id)
{
	grub_size_t i;

	for (i = 0; i < schema->layout_count; i++)
		if (schema->layouts[i].id == id)
			return &schema->layouts[i];
	return NULL;
}

static const struct dwarfs_field *
dwarfs_field_find (const struct dwarfs_layout *layout, grub_int16_t id)
{
	grub_size_t i;

	if (!layout)
		return NULL;
	for (i = 0; i < layout->field_count; i++)
		if (layout->fields[i].id == id)
			return &layout->fields[i];
	return NULL;
}

static int
dwarfs_view_field (const struct dwarfs_data *data, struct dwarfs_view parent,
	grub_int16_t id, struct dwarfs_view *view)
{
	const struct dwarfs_field *field = dwarfs_field_find (parent.layout, id);
	const struct dwarfs_layout *layout;

	if (!field)
		return 0;
	layout = dwarfs_layout_find (&data->schema, field->layout_id);
	if (!layout)
	{
		grub_error (GRUB_ERR_BAD_FS, "DwarFS field references missing layout");
		return -1;
	}
	view->layout = layout;
	view->base = parent.base;
	view->bit = parent.bit;
	if (field->offset < 0)
	{
		grub_size_t add = (grub_size_t) -(int) field->offset;

		if (view->bit > GRUB_SIZE_MAX - add)
			goto invalid;
		view->bit += add;
	}
	else
	{
		if (view->base < data->metadata_buf
			|| view->base > data->metadata_buf + data->metadata_size
			|| (grub_size_t) field->offset
				> (grub_size_t) (data->metadata_buf + data->metadata_size
					- view->base))
			goto invalid;
		view->base += field->offset;
	}
	return 1;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "DwarFS field position overflow");
	return -1;
}

static int
dwarfs_view_check (const struct dwarfs_data *data, struct dwarfs_view view)
{
	grub_uint64_t offset;
	grub_uint64_t bytes;

	if (!view.layout || view.base < data->metadata_buf
		|| view.base > data->metadata_buf + data->metadata_size)
		goto invalid;
	offset = (grub_uint64_t) (view.base - data->metadata_buf);
	bytes = view.layout->size;
	if (!bytes && view.layout->bits)
	{
		if (view.bit > GRUB_SIZE_MAX - view.layout->bits - 7)
			goto invalid;
		bytes = (view.bit + view.layout->bits + 7) / 8;
	}
	if (offset > data->metadata_size || bytes > data->metadata_size - offset)
		goto invalid;
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "DwarFS Frozen view outside metadata");
	return -1;
}

static int
dwarfs_view_uint (const struct dwarfs_data *data, struct dwarfs_view view,
	grub_uint64_t *value)
{
	grub_uint64_t result = 0;
	grub_size_t i;
	grub_size_t bits;
	grub_size_t bit;

	if (dwarfs_view_check (data, view) != 0)
		return -1;
	bits = view.layout->bits;
	if (bits > 64)
	{
		grub_error (GRUB_ERR_BAD_FS, "oversized DwarFS Frozen integer");
		return -1;
	}
	for (i = 0; i < bits; i++)
	{
		bit = view.bit + i;
		if (view.base[bit >> 3] & (1U << (bit & 7)))
			result |= (grub_uint64_t) 1 << i;
	}
	*value = result;
	return 0;
}

static int
dwarfs_field_uint (const struct dwarfs_data *data, struct dwarfs_view parent,
	grub_int16_t id, grub_uint64_t *value)
{
	struct dwarfs_view view;
	int result = dwarfs_view_field (data, parent, id, &view);

	if (result <= 0)
	{
		*value = 0;
		return result;
	}
	if (dwarfs_view_uint (data, view, value) != 0)
		return -1;
	return 1;
}

static int
dwarfs_optional (const struct dwarfs_data *data, struct dwarfs_view optional,
	struct dwarfs_view *value)
{
	grub_uint64_t isset;
	int result;

	result = dwarfs_field_uint (data, optional, 1, &isset);
	if (result < 0)
		return -1;
	if (!isset)
		return 0;
	result = dwarfs_view_field (data, optional, 2, value);
	if (result <= 0)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_FS, "DwarFS optional has no value layout");
		return -1;
	}
	return 1;
}

static int
dwarfs_optional_field (const struct dwarfs_data *data,
	struct dwarfs_view parent, grub_int16_t id, struct dwarfs_view *value)
{
	struct dwarfs_view optional;
	int result = dwarfs_view_field (data, parent, id, &optional);

	if (result <= 0)
		return result;
	result = dwarfs_optional (data, optional, value);
	if (result < 0)
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS optional field %d", id);
	return result;
}

static int
dwarfs_array_open (const struct dwarfs_data *data, struct dwarfs_view view,
	struct dwarfs_array *array)
{
	struct dwarfs_view item;
	grub_uint64_t distance = 0;
	grub_uint64_t bytes;
	int result;

	grub_memset (array, 0, sizeof (*array));
	array->view = view;
	if (dwarfs_view_check (data, view) != 0)
		return -1;
	result = dwarfs_field_uint (data, view, 2, &array->count);
	if (result < 0)
		return -1;
	if (!array->count)
		return 0;
	if (result == 0 || dwarfs_field_uint (data, view, 1, &distance) < 0)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_FS, "incomplete DwarFS Frozen array layout");
		return -1;
	}
	result = dwarfs_view_field (data, view, 3, &item);
	if (result < 0)
		return -1;
	array->item_layout = result ? item.layout : &dwarfs_empty_layout;
	if (distance > (grub_uint64_t) (data->metadata_buf + data->metadata_size - view.base))
		goto invalid;
	array->data = view.base + (grub_size_t) distance;
	if (array->item_layout->size)
	{
		if (grub_mul (array->count, (grub_uint64_t) array->item_layout->size,
			&bytes))
			goto invalid;
	}
	else
	{
		if (grub_mul (array->count, (grub_uint64_t) array->item_layout->bits,
			&bytes))
			goto invalid;
		bytes = (bytes + 7) / 8;
	}
	if (bytes > (grub_uint64_t) (data->metadata_buf + data->metadata_size - array->data))
		goto invalid;
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "DwarFS Frozen array outside metadata");
	return -1;
}

static int
dwarfs_array_field (const struct dwarfs_data *data, struct dwarfs_view parent,
	grub_int16_t id, struct dwarfs_array *array)
{
	struct dwarfs_view view;
	int result = dwarfs_view_field (data, parent, id, &view);

	if (result <= 0)
		return result;
	if (dwarfs_array_open (data, view, array) != 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS array field %d", id);
		return -1;
	}
	return 1;
}

static int
dwarfs_optional_array_field (const struct dwarfs_data *data,
	struct dwarfs_view parent, grub_int16_t id, struct dwarfs_array *array)
{
	struct dwarfs_view optional;
	struct dwarfs_view view;
	grub_uint64_t isset;
	int result = dwarfs_view_field (data, parent, id, &optional);

	if (result <= 0)
		return result;
	if (dwarfs_field_uint (data, optional, 1, &isset) < 0)
		return -1;
	if (!isset)
		return 0;
	result = dwarfs_view_field (data, optional, 2, &view);
	if (result < 0)
		return -1;
	if (!result)
	{
		grub_memset (array, 0, sizeof (*array));
		return 1;
	}
	return dwarfs_array_open (data, view, array) == 0 ? 1 : -1;
}

static int
dwarfs_array_item (const struct dwarfs_data *data,
	const struct dwarfs_array *array, grub_uint64_t index,
	struct dwarfs_view *item)
{
	grub_uint64_t offset;

	if (index >= array->count || !array->item_layout)
	{
		grub_error (GRUB_ERR_BAD_FS, "DwarFS array index out of range");
		return -1;
	}
	item->layout = array->item_layout;
	if (array->item_layout->size)
	{
		if (grub_mul (index, (grub_uint64_t) array->item_layout->size,
			&offset))
			goto invalid;
		item->base = array->data + (grub_size_t) offset;
		item->bit = 0;
	}
	else
	{
		if (grub_mul (index, (grub_uint64_t) array->item_layout->bits,
			&offset) || offset > GRUB_SIZE_MAX)
			goto invalid;
		item->base = array->data;
		item->bit = (grub_size_t) offset;
	}
	return dwarfs_view_check (data, *item);

invalid:
	grub_error (GRUB_ERR_BAD_FS, "DwarFS array item overflow");
	return -1;
}

static int
dwarfs_array_uint (const struct dwarfs_data *data,
	const struct dwarfs_array *array, grub_uint64_t index,
	grub_uint64_t *value)
{
	struct dwarfs_view item;

	if (dwarfs_array_item (data, array, index, &item) != 0)
		return -1;
	return dwarfs_view_uint (data, item, value);
}

static int
dwarfs_string_view (const struct dwarfs_data *data, struct dwarfs_view view,
	const grub_uint8_t **string, grub_size_t *size)
{
	grub_uint64_t count = 0;
	grub_uint64_t distance = 0;

	if (dwarfs_view_check (data, view) != 0)
		return -1;
	if (dwarfs_field_uint (data, view, 2, &count) < 0)
		return -1;
	if (count > GRUB_SIZE_MAX)
		goto invalid;
	if (count && dwarfs_field_uint (data, view, 1, &distance) < 0)
		goto invalid;
	if (distance > (grub_uint64_t) (data->metadata_buf + data->metadata_size - view.base)
		|| count > (grub_uint64_t) (data->metadata_buf + data->metadata_size
			- (view.base + (grub_size_t) distance)))
		goto invalid;
	*string = view.base + (grub_size_t) distance;
	*size = (grub_size_t) count;
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "DwarFS Frozen string outside metadata");
	return -1;
}

static int
dwarfs_fsst_import (struct dwarfs_fsst_decoder *decoder,
	const grub_uint8_t *buf, grub_size_t size)
{
	grub_uint64_t version;
	grub_uint8_t histogram[8];
	grub_uint32_t code;
	grub_size_t pos = 17;
	grub_uint32_t length;
	grub_uint32_t i;
	grub_uint32_t j;

	if (size < 17)
		return -1;
	version = dwarfs_le64 (buf);
	if ((version >> 32) != DWARFS_FSST_VERSION)
		return -1;
	decoder->zero_terminated = buf[8] & 1;
	grub_memcpy (histogram, buf + 9, sizeof (histogram));
	decoder->len[0] = 1;
	decoder->symbol[0] = 0;
	code = decoder->zero_terminated;
	if (decoder->zero_terminated)
	{
		if (!histogram[0])
			return -1;
		histogram[0]--;
	}
	for (length = 1; length <= 8; length++)
		for (i = 0; i < histogram[length & 7]; i++, code++)
		{
			grub_uint32_t actual = (length & 7) + 1;

			if (code >= 255 || actual > size - pos)
				return -1;
			decoder->len[code] = (grub_uint8_t) actual;
			decoder->symbol[code] = 0;
			for (j = 0; j < actual; j++)
				((grub_uint8_t *) &decoder->symbol[code])[j] = buf[pos++];
		}
	while (code < 255)
	{
		decoder->symbol[code] = 0x0074707572726f63ULL;
		decoder->len[code++] = 8;
	}
	return pos == size ? 0 : -1;
}

static grub_size_t
dwarfs_fsst_size (const struct dwarfs_fsst_decoder *decoder,
	const grub_uint8_t *input, grub_size_t size)
{
	grub_size_t in = 0;
	grub_size_t out = 0;

	while (in < size)
	{
		grub_uint8_t code = input[in++];

		if (code == DWARFS_FSST_ESC)
		{
			if (in >= size)
				return GRUB_SIZE_MAX;
			in++;
			out++;
		}
		else
		{
			if (out > GRUB_SIZE_MAX - decoder->len[code])
				return GRUB_SIZE_MAX;
			out += decoder->len[code];
		}
	}
	return out;
}

static int
dwarfs_fsst_decode (const struct dwarfs_fsst_decoder *decoder,
	const grub_uint8_t *input, grub_size_t size, char *output,
	grub_size_t output_size)
{
	grub_size_t in = 0;
	grub_size_t out = 0;

	while (in < size)
	{
		grub_uint8_t code = input[in++];

		if (code == DWARFS_FSST_ESC)
		{
			if (in >= size || out >= output_size)
				return -1;
			output[out++] = (char) input[in++];
		}
		else
		{
			grub_size_t length = decoder->len[code];

			if (length > output_size - out)
				return -1;
			grub_memcpy (output + out, &decoder->symbol[code], length);
			out += length;
		}
	}
	return out == output_size ? 0 : -1;
}

static void
dwarfs_string_table_free (struct dwarfs_string_table *table)
{
	grub_free (table->index);
	grub_memset (table, 0, sizeof (*table));
}

static int
dwarfs_string_table_compact (struct dwarfs_data *data,
	struct dwarfs_view table_view, struct dwarfs_string_table *table)
{
	struct dwarfs_view view;
	struct dwarfs_array index;
	const grub_uint8_t *symtab;
	grub_size_t symtab_size;
	grub_uint64_t packed = 0;
	grub_uint64_t value;
	grub_uint64_t total = 0;
	grub_size_t i;
	int result;

	grub_memset (table, 0, sizeof (*table));
	table->compact = 1;
	result = dwarfs_view_field (data, table_view, 1, &view);
	if (result < 0)
		return -1;
	if (result > 0)
	{
		if (dwarfs_string_view (data, view, &table->buffer,
			&table->buffer_size) != 0)
			return -1;
	}
	else
		table->buffer = data->metadata_buf;
	result = dwarfs_array_field (data, table_view, 3, &index);
	if (result < 0)
		return -1;
	if (!result)
		grub_memset (&index, 0, sizeof (index));
	if (dwarfs_field_uint (data, table_view, 4, &packed) < 0)
		return -1;
	if (index.count > GRUB_SIZE_MAX)
		goto invalid_index;
	table->count = packed ? (grub_size_t) index.count
		: index.count ? (grub_size_t) index.count - 1 : 0;
	if (table->count >= GRUB_SIZE_MAX / sizeof (*table->index))
		goto invalid_index;
	table->index = grub_malloc ((table->count + 1) * sizeof (*table->index));
	if (!table->index)
		return -1;
	table->index[0] = 0;
	if (packed)
	{
		for (i = 0; i < table->count; i++)
		{
			if (dwarfs_array_uint (data, &index, i, &value) != 0
				|| value > GRUB_UINT_MAX - total)
				goto invalid;
			total += value;
			table->index[i + 1] = (grub_uint32_t) total;
		}
	}
	else
	{
		for (i = 0; i <= table->count; i++)
		{
			if (dwarfs_array_uint (data, &index, i, &value) != 0
				|| value > GRUB_UINT_MAX)
				goto invalid;
			table->index[i] = (grub_uint32_t) value;
		}
	}
	if (table->index[table->count] > table->buffer_size)
		goto invalid_index;
	result = dwarfs_optional_field (data, table_view, 2, &view);
	if (result < 0)
		return -1;
	if (result > 0)
	{
		if (dwarfs_string_view (data, view, &symtab, &symtab_size) != 0
			|| dwarfs_fsst_import (&table->decoder, symtab, symtab_size) != 0)
			goto invalid_symtab;
		table->fsst = 1;
	}
	return 0;

invalid:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS compact string table");
	return -1;
invalid_index:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS compact string index");
	return -1;
invalid_symtab:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS FSST symbol table");
	return -1;
}

static int
dwarfs_string_table_legacy (struct dwarfs_data *data,
	struct dwarfs_view root, grub_int16_t id,
	struct dwarfs_string_table *table)
{
	grub_memset (table, 0, sizeof (*table));
	if (dwarfs_array_field (data, root, id, &table->legacy) < 0)
	{
		return -1;
	}
	table->count = (grub_size_t) table->legacy.count;
	return 0;
}

static char *
dwarfs_string_lookup (struct dwarfs_data *data,
	const struct dwarfs_string_table *table, grub_uint32_t index)
{
	const grub_uint8_t *source;
	grub_size_t source_size;
	grub_size_t output_size;
	struct dwarfs_view view;
	char *output;

	if (index >= table->count)
		goto invalid;
	if (table->compact)
	{
		source = table->buffer + table->index[index];
		source_size = table->index[index + 1] - table->index[index];
	}
	else
	{
		if (dwarfs_array_item (data, &table->legacy, index, &view) != 0
			|| dwarfs_string_view (data, view, &source, &source_size) != 0)
			return NULL;
	}
	output_size = table->fsst
		? dwarfs_fsst_size (&table->decoder, source, source_size) : source_size;
	if (output_size == GRUB_SIZE_MAX)
		goto invalid;
	output = grub_malloc (output_size + 1);
	if (!output)
		return NULL;
	if (table->fsst)
	{
		if (dwarfs_fsst_decode (&table->decoder, source, source_size,
			output, output_size) != 0)
		{
			grub_free (output);
			goto invalid;
		}
	}
	else
		grub_memcpy (output, source, output_size);
	output[output_size] = '\0';
	return output;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS string index");
	return NULL;
}

static int
dwarfs_section_add_block (struct dwarfs_data *data,
	struct dwarfs_section section)
{
	struct dwarfs_section *blocks;
	grub_size_t capacity;

	if (data->block_count == data->block_capacity)
	{
		capacity = data->block_capacity ? data->block_capacity * 2 : 32;
		if (capacity < data->block_capacity
			|| capacity > GRUB_SIZE_MAX / sizeof (*blocks))
			goto overflow;
		blocks = grub_realloc (data->blocks, capacity * sizeof (*blocks));
		if (!blocks)
			return -1;
		data->blocks = blocks;
		data->block_capacity = capacity;
	}
	data->blocks[data->block_count++] = section;
	return 0;

overflow:
	grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many DwarFS blocks");
	return -1;
}

static int
dwarfs_section_record (struct dwarfs_data *data, grub_uint16_t type,
	struct dwarfs_section section)
{
	switch (type)
	{
	case DWARFS_SECTION_BLOCK:
		return dwarfs_section_add_block (data, section);
	case DWARFS_SECTION_SCHEMA:
		if (data->schema_section.length)
			goto duplicate;
		data->schema_section = section;
		return 0;
	case DWARFS_SECTION_METADATA:
		if (data->metadata_section.length)
			goto duplicate;
		data->metadata_section = section;
		return 0;
	case DWARFS_SECTION_INDEX:
	case DWARFS_SECTION_HISTORY:
		return 0;
	default:
		/* Minor-version compatibility permits unknown optional sections.  */
		return 0;
	}

duplicate:
	grub_error (GRUB_ERR_BAD_FS, "duplicate DwarFS metadata section");
	return -1;
}

static int
dwarfs_parse_sections_v2 (struct dwarfs_data *data)
{
	grub_uint8_t header[DWARFS_V2_HEADER_SIZE];
	grub_uint64_t offset = data->image_offset;
	grub_uint64_t next;
	grub_uint64_t length;
	grub_uint32_t expected_number = 0;
	grub_uint16_t type;
	struct dwarfs_section section;

	while (offset < data->disk_size)
	{
		if (data->disk_size - offset < sizeof (header))
		{
			if (data->metadata_section.length
				&& data->disk_size - offset < (1U << DWARFS_SECTOR_BITS))
				break;
			goto truncated;
		}
		if (dwarfs_read_at (data, offset, sizeof (header), header) != 0)
			return -1;
		if (grub_memcmp (header, DWARFS_MAGIC, DWARFS_MAGIC_SIZE) != 0)
		{
			if (data->metadata_section.length
				&& data->disk_size - offset < (1U << DWARFS_SECTOR_BITS))
				break;
			goto invalid;
		}
		if (header[6] != DWARFS_MAJOR || header[7] > DWARFS_MINOR_MAX
			|| dwarfs_le32 (header + 48) != expected_number)
			goto invalid;
		type = dwarfs_le16 (header + 52);
		section.compression = dwarfs_le16 (header + 54);
		section.checksummed = 1;
		grub_memcpy (section.sha2_512_256, header + 8,
			sizeof (section.sha2_512_256));
		grub_memcpy (section.integrity_header, header + 40,
			sizeof (section.integrity_header));
		length = dwarfs_le64 (header + 56);
		if (!length || length > DWARFS_SECTION_LIMIT
			|| section.compression > DWARFS_COMP_RICEPP)
			goto invalid;
		if (grub_add (offset, (grub_uint64_t) sizeof (header), &section.offset)
			|| grub_add (section.offset, length, &next)
			|| next > data->disk_size)
			goto truncated;
		section.length = length;
		if (dwarfs_section_record (data, type, section) != 0)
			return -1;
		offset = next;
		expected_number++;
		if (type == DWARFS_SECTION_INDEX)
			break;
	}
	if (!data->schema_section.length || !data->metadata_section.length)
		goto invalid;
	return 0;

truncated:
	grub_error (GRUB_ERR_BAD_FS, "truncated DwarFS section");
	return -1;
invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS section header");
	return -1;
}

static int
dwarfs_parse_sections_v1 (struct dwarfs_data *data)
{
	grub_uint8_t header[8];
	grub_uint64_t offset;
	grub_uint64_t next;
	grub_uint16_t type;
	struct dwarfs_section section;

	if (grub_add (data->image_offset, (grub_uint64_t) DWARFS_V1_HEADER_SIZE,
		&offset))
		goto invalid;
	while (offset < data->disk_size)
	{
		if (data->disk_size - offset < sizeof (header)
			|| dwarfs_read_at (data, offset, sizeof (header), header) != 0)
		{
			if (data->metadata_section.length
				&& data->disk_size - offset < (1U << DWARFS_SECTOR_BITS))
				break;
			goto truncated;
		}
		type = dwarfs_le16 (header);
		section.compression = header[2];
		section.checksummed = 0;
		section.length = dwarfs_le32 (header + 4);
		if (!section.length || section.compression > DWARFS_COMP_LZ4HC)
		{
			if (data->metadata_section.length
				&& data->disk_size - offset < (1U << DWARFS_SECTOR_BITS))
				break;
			goto invalid;
		}
		if (grub_add (offset, (grub_uint64_t) sizeof (header), &section.offset)
			|| grub_add (section.offset, section.length, &next)
			|| next > data->disk_size)
			goto truncated;
		if (dwarfs_section_record (data, type, section) != 0)
			return -1;
		offset = next;
	}
	if (!data->schema_section.length || !data->metadata_section.length)
		goto invalid;
	return 0;

truncated:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "truncated DwarFS section");
	return -1;
invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS section header");
	return -1;
}

static int
dwarfs_brotli_varint (const grub_uint8_t *buf, grub_size_t size,
	grub_uint64_t *value, grub_size_t *used)
{
	grub_uint64_t result = 0;
	unsigned shift = 0;
	grub_size_t i;

	for (i = 0; i < size && shift < 64; i++, shift += 7)
	{
		result |= (grub_uint64_t) (buf[i] & 0x7f) << shift;
		if (!(buf[i] & 0x80))
		{
			*value = result;
			*used = i + 1;
			return 0;
		}
	}
	return -1;
}

static int
dwarfs_decompress_lzma (const grub_uint8_t *compressed,
	grub_size_t compressed_size, grub_uint8_t **output,
	grub_size_t *output_size, grub_size_t limit)
{
	struct xz_dec *decoder = NULL;
	struct xz_buf buffer;
	grub_uint8_t *plain = NULL;
	grub_uint8_t *grown;
	grub_size_t capacity;
	grub_size_t old_in;
	grub_size_t old_out;
	enum xz_ret result;

	capacity = compressed_size > 0x10000 ? compressed_size : 0x10000;
	if (capacity > limit)
		capacity = limit;
	if (!capacity)
		capacity = 1;
	plain = grub_malloc (capacity);
	if (!plain)
		return -1;
	decoder = xz_dec_init (1U << 16);
	if (!decoder)
		goto fail;
	buffer.in = compressed;
	buffer.in_pos = 0;
	buffer.in_size = compressed_size;
	buffer.out = plain;
	buffer.out_pos = 0;
	buffer.out_size = capacity;
	for (;;)
	{
		old_in = buffer.in_pos;
		old_out = buffer.out_pos;
		result = xz_dec_run (decoder, &buffer);
		if (result == XZ_STREAM_END)
		{
			if (buffer.in_pos != compressed_size)
				goto bad_data;
			xz_dec_end (decoder);
			*output = plain;
			*output_size = buffer.out_pos;
			return 0;
		}
		if (result != XZ_OK || (old_in == buffer.in_pos
			&& old_out == buffer.out_pos))
			goto bad_data;
		if (buffer.out_pos == buffer.out_size)
		{
			if (capacity == limit)
				goto too_large;
			capacity = capacity > limit - capacity ? limit : capacity * 2;
			grown = grub_realloc (plain, capacity);
			if (!grown)
				goto fail;
			plain = grown;
			buffer.out = plain;
			buffer.out_size = capacity;
		}
	}

bad_data:
	grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt DwarFS LZMA section");
	goto fail;
too_large:
	grub_error (GRUB_ERR_OUT_OF_RANGE, "DwarFS LZMA section is too large");
fail:
	xz_dec_end (decoder);
	grub_free (plain);
	return -1;
}

static int
dwarfs_verify_section (const struct dwarfs_section *section,
	const grub_uint8_t *contents)
{
	const gcry_md_spec_t *hash;
	void *context;
	const grub_uint8_t *digest;

	if (!section->checksummed)
		return 0;
	hash = grub_crypto_lookup_md_by_name ("SHA512_256");
	if (!hash || hash->mdlen != sizeof (section->sha2_512_256))
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			"SHA512/256 is unavailable for DwarFS verification");
		return -1;
	}
	context = grub_malloc (hash->contextsize);
	if (!context)
		return -1;
	hash->init (context, 0);
	hash->write (context, section->integrity_header,
		sizeof (section->integrity_header));
	hash->write (context, contents, (grub_size_t) section->length);
	hash->final (context);
	digest = hash->read (context);
	if (grub_memcmp (digest, section->sha2_512_256,
		sizeof (section->sha2_512_256)) != 0)
	{
		grub_free (context);
		grub_error (GRUB_ERR_BAD_FS, "DwarFS section checksum mismatch");
		return -1;
	}
	grub_free (context);
	return 0;
}

static int
dwarfs_decompress (struct dwarfs_data *data,
	const struct dwarfs_section *section, grub_uint8_t **output,
	grub_size_t *output_size, grub_size_t limit)
{
	grub_uint8_t *compressed = NULL;
	grub_uint8_t *plain = NULL;
	grub_uint64_t expected64;
	grub_size_t expected;
	grub_size_t used;
	grub_size_t got;
	int lz4_result;
	BrotliDecoderResult brotli_result;

	*output = NULL;
	*output_size = 0;
	if (section->length > GRUB_SIZE_MAX)
		goto too_large;
	compressed = grub_malloc ((grub_size_t) section->length);
	if (!compressed)
		return -1;
	if (dwarfs_read_at (data, section->offset, (grub_size_t) section->length,
		compressed) != 0)
		goto fail;
	if (dwarfs_verify_section (section, compressed) != 0)
		goto fail;
	if (section->compression == DWARFS_COMP_LZMA)
	{
		int result = dwarfs_decompress_lzma (compressed,
			(grub_size_t) section->length, output, output_size, limit);

		grub_free (compressed);
		return result;
	}
	switch (section->compression)
	{
	case DWARFS_COMP_NONE:
		if (section->length > limit)
			goto too_large;
		*output = compressed;
		*output_size = (grub_size_t) section->length;
		return 0;

	case DWARFS_COMP_ZSTD:
		expected64 = ZSTD_getFrameContentSize (compressed,
			(grub_size_t) section->length);
		if (expected64 == ZSTD_CONTENTSIZE_ERROR
			|| expected64 == ZSTD_CONTENTSIZE_UNKNOWN)
			goto bad_data;
		break;

	case DWARFS_COMP_LZ4:
	case DWARFS_COMP_LZ4HC:
		if (section->length < 4)
			goto bad_data;
		expected64 = dwarfs_le32 (compressed);
		break;

	case DWARFS_COMP_BROTLI:
		if (dwarfs_brotli_varint (compressed, (grub_size_t) section->length,
			&expected64, &used) != 0)
			goto bad_data;
		break;

	case DWARFS_COMP_FLAC:
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			"DwarFS FLAC sections are not supported");
		goto fail;
	case DWARFS_COMP_RICEPP:
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			"DwarFS ricepp sections are not supported");
		goto fail;
	default:
		goto bad_data;
	}
	if (expected64 > limit || expected64 > GRUB_SIZE_MAX)
		goto too_large;
	expected = (grub_size_t) expected64;
	plain = grub_malloc (expected ? expected : 1);
	if (!plain)
		goto fail;
	switch (section->compression)
	{
	case DWARFS_COMP_ZSTD:
		got = ZSTD_decompress (plain, expected, compressed,
			(grub_size_t) section->length);
		if (ZSTD_isError (got) || got != expected)
			goto bad_data;
		break;
	case DWARFS_COMP_LZ4:
	case DWARFS_COMP_LZ4HC:
		if (section->length - 4 > GRUB_INT_MAX || expected > GRUB_INT_MAX)
			goto too_large;
		lz4_result = LZ4_decompress_safe ((const char *) compressed + 4,
			(char *) plain, (int) section->length - 4, (int) expected);
		if (lz4_result < 0 || (grub_size_t) lz4_result != expected)
			goto bad_data;
		break;
	case DWARFS_COMP_BROTLI:
		got = expected;
		brotli_result = BrotliDecoderDecompress ((grub_size_t) section->length - used,
			compressed + used, &got, plain);
		if (brotli_result != BROTLI_DECODER_RESULT_SUCCESS || got != expected)
			goto bad_data;
		break;
	default:
		goto bad_data;
	}
	grub_free (compressed);
	*output = plain;
	*output_size = expected;
	return 0;

bad_data:
	grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt DwarFS section");
	goto fail;
too_large:
	grub_error (GRUB_ERR_OUT_OF_RANGE, "DwarFS section is too large");
fail:
	grub_free (plain);
	grub_free (compressed);
	return -1;
}

static void
dwarfs_free (struct dwarfs_data *data)
{
	grub_size_t i;

	if (!data)
		return;
	for (i = 0; i < data->schema.layout_count; i++)
		grub_free (data->schema.layouts[i].fields);
	grub_free (data->schema.layouts);
	dwarfs_string_table_free (&data->names);
	dwarfs_string_table_free (&data->symlinks);
	grub_free (data->directory_first);
	grub_free (data->chunk_first);
	grub_free (data->shared_map);
	grub_free (data->metadata_buf);
	grub_free (data->schema_buf);
	grub_free (data->blocks);
	grub_free (data);
}

static int
dwarfs_root_uint (struct dwarfs_data *data, grub_int16_t id,
	grub_uint64_t *value)
{
	if (dwarfs_field_uint (data, data->root, id, value) < 0)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_FS, "missing DwarFS metadata field");
		return -1;
	}
	return 0;
}

static int
dwarfs_metadata_arrays (struct dwarfs_data *data)
{
	struct dwarfs_view view;
	grub_uint64_t value;
	int result;

	if (dwarfs_array_field (data, data->root, 1, &data->chunks) < 0
		|| dwarfs_array_field (data, data->root, 2, &data->directories) < 0
		|| dwarfs_array_field (data, data->root, 3, &data->inodes) < 0
		|| dwarfs_array_field (data, data->root, 4, &data->chunk_table) < 0
		|| dwarfs_array_field (data, data->root, 9, &data->modes) < 0)
		goto missing;
	result = dwarfs_array_field (data, data->root, 6, &data->symlink_table);
	if (result < 0)
		return -1;
	result = dwarfs_optional_array_field (data, data->root, 19,
		&data->dir_entries);
	if (result < 0)
		return -1;
	data->modern = result > 0;
	if (!data->modern
		&& dwarfs_array_field (data, data->root, 5, &data->entry_table) < 0)
		goto missing;
	result = dwarfs_optional_array_field (data, data->root, 20,
		&data->shared_files);
	if (result < 0)
		return -1;
	result = dwarfs_optional_array_field (data, data->root, 35,
		&data->large_holes);
	if (result < 0)
		return -1;
	if (dwarfs_root_uint (data, 12, &data->timestamp_base) != 0
		|| dwarfs_root_uint (data, 15, &value) != 0
		|| value > GRUB_UINT_MAX)
		return -1;
	data->block_size = (grub_uint32_t) value;
	if (!data->block_size)
		goto invalid;
	result = dwarfs_optional_field (data, data->root, 34, &view);
	if (result < 0)
		return -1;
	if (result > 0)
	{
		if (dwarfs_view_uint (data, view, &value) != 0
			|| value > GRUB_UINT_MAX)
			return -1;
		data->has_hole_block = 1;
		data->hole_block = (grub_uint32_t) value;
	}
	return 0;

missing:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "missing DwarFS metadata table");
	return -1;
invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS metadata");
	return -1;
}

static int
dwarfs_metadata_options (struct dwarfs_data *data)
{
	struct dwarfs_view options;
	struct dwarfs_view value_view;
	grub_uint64_t value;
	int result;

	data->time_resolution = 1;
	result = dwarfs_optional_field (data, data->root, 18, &options);
	if (result <= 0)
		return result < 0 ? -1 : 0;
	if (dwarfs_field_uint (data, options, 3, &value) < 0)
		return -1;
	data->packed_chunk_table = !!value;
	if (dwarfs_field_uint (data, options, 4, &value) < 0)
		return -1;
	data->packed_directories = !!value;
	if (dwarfs_field_uint (data, options, 5, &value) < 0)
		return -1;
	data->packed_shared_files = !!value;
	result = dwarfs_optional_field (data, options, 2, &value_view);
	if (result < 0)
		return -1;
	if (result > 0)
	{
		if (dwarfs_view_uint (data, value_view, &value) != 0
			|| !value || value > GRUB_UINT_MAX)
			goto invalid;
		data->time_resolution = (grub_uint32_t) value;
	}
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS metadata options");
	return -1;
}

static int
dwarfs_metadata_features (struct dwarfs_data *data)
{
	struct dwarfs_array features;
	struct dwarfs_view view;
	const grub_uint8_t *name;
	grub_size_t name_size;
	grub_size_t i;
	int result;

	result = dwarfs_optional_array_field (data, data->root, 27, &features);
	if (result <= 0)
		return result < 0 ? -1 : 0;
	if (features.count > GRUB_SIZE_MAX)
		goto invalid;
	for (i = 0; i < (grub_size_t) features.count; i++)
	{
		if (dwarfs_array_item (data, &features, i, &view) != 0
			|| dwarfs_string_view (data, view, &name, &name_size) != 0)
			return -1;
		if (name_size != sizeof ("sparsefiles") - 1
			|| grub_memcmp (name, "sparsefiles", name_size) != 0)
		{
			grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				"DwarFS image uses an unsupported feature");
			return -1;
		}
	}
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS feature table");
	return -1;
}

static int
dwarfs_metadata_strings (struct dwarfs_data *data)
{
	struct dwarfs_view view;
	int result;

	result = dwarfs_optional_field (data, data->root, 24, &view);
	if (result < 0)
		return -1;
	if (result > 0)
	{
		if (dwarfs_string_table_compact (data, view, &data->names) != 0)
			return -1;
	}
	else if (dwarfs_string_table_legacy (data, data->root, 10,
		&data->names) != 0)
		return -1;
	result = dwarfs_optional_field (data, data->root, 25, &view);
	if (result < 0)
		return -1;
	if (result > 0)
	{
		if (dwarfs_string_table_compact (data, view, &data->symlinks) != 0)
			return -1;
	}
	else if (dwarfs_string_table_legacy (data, data->root, 11,
		&data->symlinks) != 0)
		return -1;
	return 0;
}

static int
dwarfs_inode_view (struct dwarfs_data *data, grub_uint32_t inode,
	struct dwarfs_view *view)
{
	grub_uint64_t index = inode;

	if (!data->modern)
	{
		if (inode >= data->entry_table.count
			|| dwarfs_array_uint (data, &data->entry_table, inode, &index) != 0)
			return -1;
	}
	return dwarfs_array_item (data, &data->inodes, index, view);
}

static int
dwarfs_inode_mode (struct dwarfs_data *data, grub_uint32_t inode,
	grub_uint32_t *mode)
{
	struct dwarfs_view view;
	grub_uint64_t index;
	grub_uint64_t value;

	if (dwarfs_inode_view (data, inode, &view) != 0
		|| dwarfs_field_uint (data, view, 2, &index) < 0
		|| dwarfs_array_uint (data, &data->modes, index, &value) != 0
		|| value > GRUB_UINT_MAX)
		goto invalid;
	*mode = (grub_uint32_t) value;
	return 0;

invalid:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS inode mode");
	return -1;
}

static int
dwarfs_dir_entry (struct dwarfs_data *data, grub_uint32_t entry,
	grub_uint32_t *name_index, grub_uint32_t *inode)
{
	const struct dwarfs_array *array = data->modern
		? &data->dir_entries : &data->inodes;
	struct dwarfs_view view;
	grub_uint64_t name;
	grub_uint64_t ino;

	if (dwarfs_array_item (data, array, entry, &view) != 0
		|| dwarfs_field_uint (data, view, 1, &name) < 0
		|| dwarfs_field_uint (data, view, data->modern ? 2 : 3, &ino) < 0
		|| name > GRUB_UINT_MAX || ino > GRUB_UINT_MAX)
		goto invalid;
	*name_index = (grub_uint32_t) name;
	*inode = (grub_uint32_t) ino;
	return 0;

invalid:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS directory entry");
	return -1;
}

static int
dwarfs_build_directories (struct dwarfs_data *data)
{
	grub_uint64_t value;
	grub_uint64_t total = 0;
	grub_size_t i;

	if (data->directories.count < 2
		|| data->directories.count > GRUB_SIZE_MAX / sizeof (*data->directory_first))
		goto invalid;
	data->directory_first = grub_malloc ((grub_size_t) data->directories.count
		* sizeof (*data->directory_first));
	if (!data->directory_first)
		return -1;
	for (i = 0; i < (grub_size_t) data->directories.count; i++)
	{
		struct dwarfs_view view;

		if (dwarfs_array_item (data, &data->directories, i, &view) != 0
			|| dwarfs_field_uint (data, view, 2, &value) < 0)
			goto invalid;
		if (data->packed_directories)
		{
			if (value > GRUB_UINT_MAX - total)
				goto invalid;
			total += value;
		}
		else
			total = value;
		if (total > GRUB_UINT_MAX)
			goto invalid;
		data->directory_first[i] = (grub_uint32_t) total;
		if (i && data->directory_first[i] < data->directory_first[i - 1])
			goto invalid;
	}
	if (data->directory_first[data->directories.count - 1]
		> (data->modern ? data->dir_entries.count : data->inodes.count))
		goto invalid;
	return 0;

invalid:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS directory table");
	return -1;
}

static int
dwarfs_build_chunk_table (struct dwarfs_data *data)
{
	grub_uint64_t value;
	grub_uint64_t total = 0;
	grub_size_t i;

	if (!data->chunk_table.count
		|| data->chunk_table.count > GRUB_SIZE_MAX / sizeof (*data->chunk_first))
		goto invalid;
	data->chunk_first = grub_malloc ((grub_size_t) data->chunk_table.count
		* sizeof (*data->chunk_first));
	if (!data->chunk_first)
		return -1;
	for (i = 0; i < (grub_size_t) data->chunk_table.count; i++)
	{
		if (dwarfs_array_uint (data, &data->chunk_table, i, &value) != 0)
			return -1;
		if (data->packed_chunk_table)
		{
			if (value > GRUB_UINT_MAX - total)
				goto invalid;
			total += value;
		}
		else
			total = value;
		if (total > data->chunks.count)
			goto invalid;
		data->chunk_first[i] = (grub_uint32_t) total;
		if (i && data->chunk_first[i] < data->chunk_first[i - 1])
			goto invalid;
	}
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS chunk table");
	return -1;
}

static int
dwarfs_build_shared_table (struct dwarfs_data *data)
{
	grub_uint64_t value;
	grub_uint64_t total;
	grub_size_t i;
	grub_size_t j;
	grub_size_t target = 0;

	if (!data->shared_files.count)
		return 0;
	if (data->packed_shared_files)
	{
		if (data->shared_files.count > DWARFS_UINT64_MAX / 2)
			goto invalid;
		total = data->shared_files.count * 2;
		for (i = 0; i < (grub_size_t) data->shared_files.count; i++)
		{
			if (dwarfs_array_uint (data, &data->shared_files, i, &value) != 0
				|| value > GRUB_SIZE_MAX - total)
				goto invalid;
			total += value;
		}
	}
	else
		total = data->shared_files.count;
	if (total > GRUB_SIZE_MAX / sizeof (*data->shared_map))
		goto invalid;
	data->shared_map = grub_malloc ((grub_size_t) total
		* sizeof (*data->shared_map));
	if (!data->shared_map)
		return -1;
	if (data->packed_shared_files)
	{
		for (i = 0; i < (grub_size_t) data->shared_files.count; i++)
		{
			if (dwarfs_array_uint (data, &data->shared_files, i, &value) != 0)
				return -1;
			for (j = 0; j < (grub_size_t) value + 2; j++)
				data->shared_map[target++] = (grub_uint32_t) i;
		}
	}
	else
	{
		for (i = 0; i < (grub_size_t) total; i++)
		{
			if (dwarfs_array_uint (data, &data->shared_files, i, &value) != 0
				|| value > GRUB_UINT_MAX)
				goto invalid;
			data->shared_map[i] = (grub_uint32_t) value;
		}
	}
	data->shared_count = (grub_size_t) total;
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS shared files table");
	return -1;
}

static int
dwarfs_find_inode_offsets (struct dwarfs_data *data)
{
	grub_uint64_t inode_count64 = data->modern
		? data->inodes.count : data->entry_table.count;
	grub_uint32_t inode_count;
	grub_uint32_t mode;
	grub_uint32_t inode;

	if (!inode_count64 || inode_count64 > GRUB_UINT_MAX)
		goto invalid;
	inode_count = (grub_uint32_t) inode_count64;
	data->symlink_inode_offset = inode_count;
	data->file_inode_offset = inode_count;
	data->dev_inode_offset = inode_count;
	for (inode = 0; inode < inode_count; inode++)
	{
		if (dwarfs_inode_mode (data, inode, &mode) != 0)
			return -1;
		if (data->symlink_inode_offset == inode_count
			&& (mode & DWARFS_MODE_TYPE_MASK) != DWARFS_MODE_DIRECTORY)
			data->symlink_inode_offset = inode;
		if (data->file_inode_offset == inode_count
			&& (mode & DWARFS_MODE_TYPE_MASK) == DWARFS_MODE_REGULAR)
			data->file_inode_offset = inode;
		if (data->file_inode_offset != inode_count
			&& data->dev_inode_offset == inode_count
			&& (mode & DWARFS_MODE_TYPE_MASK) != DWARFS_MODE_REGULAR)
			data->dev_inode_offset = inode;
	}
	if (data->symlink_inode_offset == inode_count)
		data->symlink_inode_offset = data->file_inode_offset;
	if (data->file_inode_offset == inode_count)
		data->file_inode_offset = data->dev_inode_offset = inode_count;
	if (data->dev_inode_offset == inode_count)
		data->dev_inode_offset = inode_count;
	if (data->directories.count - 1 != data->symlink_inode_offset
		|| data->dev_inode_offset < data->file_inode_offset
		|| data->shared_count > data->dev_inode_offset - data->file_inode_offset)
		goto invalid;
	data->unique_files = data->dev_inode_offset - data->file_inode_offset
		- (grub_uint32_t) data->shared_count;
	if (data->chunk_table.count != (grub_uint64_t) data->unique_files + 1
		&& !data->shared_count)
	{
		/* Without a shared table every regular inode owns one chunk range.  */
		if (data->chunk_table.count
			!= (grub_uint64_t) (data->dev_inode_offset - data->file_inode_offset) + 1)
			goto invalid;
	}
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS inode partitioning");
	return -1;
}

static int
dwarfs_metadata_init (struct dwarfs_data *data)
{
	const struct dwarfs_layout *root;

	if (dwarfs_decompress (data, &data->schema_section, &data->schema_buf,
		&data->schema_size, DWARFS_METADATA_LIMIT) != 0
		|| dwarfs_decompress (data, &data->metadata_section, &data->metadata_buf,
			&data->metadata_size, DWARFS_METADATA_LIMIT) != 0
		|| dwarfs_schema_parse (&data->schema, data->schema_buf,
			data->schema_size) != 0)
		return -1;
	root = dwarfs_layout_find (&data->schema, data->schema.root_id);
	if (!root)
	{
		grub_error (GRUB_ERR_BAD_FS, "missing DwarFS root layout");
		return -1;
	}
	data->root.layout = root;
	data->root.base = data->metadata_buf;
	data->root.bit = 0;
	if (dwarfs_view_check (data, data->root) != 0
		|| dwarfs_metadata_arrays (data) != 0
		|| dwarfs_metadata_options (data) != 0
		|| dwarfs_metadata_features (data) != 0
		|| dwarfs_metadata_strings (data) != 0
		|| dwarfs_build_directories (data) != 0
		|| dwarfs_build_chunk_table (data) != 0
		|| dwarfs_build_shared_table (data) != 0
		|| dwarfs_find_inode_offsets (data) != 0)
		return -1;
	return 0;
}

static struct dwarfs_data *
dwarfs_mount (grub_disk_t disk)
{
	struct dwarfs_data *data;
	grub_uint8_t header[DWARFS_V1_HEADER_SIZE];
	grub_disk_addr_t sectors;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	sectors = grub_disk_native_sectors (disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN
		|| sectors > (DWARFS_UINT64_MAX >> DWARFS_SECTOR_BITS))
		data->disk_size = DWARFS_UINT64_MAX;
	else
		data->disk_size = (grub_uint64_t) sectors << DWARFS_SECTOR_BITS;
	if (dwarfs_read_at (data, 0, sizeof (header), header) != 0)
		goto fail;
	if (grub_memcmp (header, DWARFS_MAGIC, DWARFS_MAGIC_SIZE) != 0
		|| header[6] != DWARFS_MAJOR || header[7] > DWARFS_MINOR_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "not a DwarFS filesystem");
		goto fail;
	}
	data->minor = header[7];
	data->header_version = data->minor >= 2 ? 2 : 1;
	if ((data->header_version == 2 ? dwarfs_parse_sections_v2 (data)
		: dwarfs_parse_sections_v1 (data)) != 0
		|| dwarfs_metadata_init (data) != 0)
		goto fail;
	return data;

fail:
	dwarfs_free (data);
	return NULL;
}

static int
dwarfs_chunk_info (struct dwarfs_data *data, grub_uint32_t index,
	grub_uint32_t *block, grub_uint32_t *offset, grub_uint64_t *size,
	int *hole)
{
	struct dwarfs_view view;
	grub_uint64_t b;
	grub_uint64_t o;
	grub_uint64_t s;

	if (dwarfs_array_item (data, &data->chunks, index, &view) != 0
		|| dwarfs_field_uint (data, view, 1, &b) < 0
		|| dwarfs_field_uint (data, view, 2, &o) < 0
		|| dwarfs_field_uint (data, view, 3, &s) < 0
		|| b > GRUB_UINT_MAX || o > GRUB_UINT_MAX
		|| s > GRUB_UINT_MAX)
		goto invalid;
	*block = (grub_uint32_t) b;
	*offset = (grub_uint32_t) o;
	*hole = data->has_hole_block && *block == data->hole_block;
	if (*hole)
	{
		if (*offset == DWARFS_LARGE_HOLE_OFFSET)
		{
			if (s >= data->large_holes.count
				|| dwarfs_array_uint (data, &data->large_holes, s, size) != 0)
				goto invalid;
		}
		else
		{
			if (grub_mul (s, (grub_uint64_t) data->block_size, size)
				|| grub_add (*size, (grub_uint64_t) *offset, size))
				goto invalid;
		}
	}
	else
		*size = s;
	return 0;

invalid:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS chunk");
	return -1;
}

static int
dwarfs_file_chunks (struct dwarfs_data *data, grub_uint32_t inode,
	grub_uint32_t *begin, grub_uint32_t *end)
{
	grub_uint32_t index;
	grub_uint32_t shared;

	if (inode < data->file_inode_offset || inode >= data->dev_inode_offset)
		goto invalid;
	index = inode - data->file_inode_offset;
	if (index >= data->unique_files)
	{
		shared = index - data->unique_files;
		if (shared >= data->shared_count)
			goto invalid;
		index = data->unique_files + data->shared_map[shared];
	}
	if ((grub_uint64_t) index + 1 >= data->chunk_table.count)
		goto invalid;
	*begin = data->chunk_first[index];
	*end = data->chunk_first[index + 1];
	if (*begin > *end || *end > data->chunks.count)
		goto invalid;
	return 0;

invalid:
	grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS file chunk range");
	return -1;
}

static int
dwarfs_file_size (struct dwarfs_data *data, grub_uint32_t begin,
	grub_uint32_t end, grub_uint64_t *size)
{
	grub_uint64_t total = 0;
	grub_uint64_t chunk_size;
	grub_uint32_t block;
	grub_uint32_t offset;
	grub_uint32_t i;
	int hole;

	for (i = begin; i < end; i++)
	{
		if (dwarfs_chunk_info (data, i, &block, &offset, &chunk_size,
			&hole) != 0 || grub_add (total, chunk_size, &total))
			goto invalid;
	}
	*size = total;
	return 0;

invalid:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "DwarFS file size overflow");
	return -1;
}

static int
dwarfs_entry_name (struct dwarfs_data *data, grub_uint32_t entry,
	char **name, grub_uint32_t *inode)
{
	grub_uint32_t name_index;

	if (dwarfs_dir_entry (data, entry, &name_index, inode) != 0)
		return -1;
	*name = dwarfs_string_lookup (data, &data->names, name_index);
	return *name ? 0 : -1;
}

static int
dwarfs_lookup (struct dwarfs_data *data, const char *path,
	grub_uint32_t *inode)
{
	const char *p = path;
	const char *start;
	grub_size_t length;
	grub_uint32_t current = 0;
	grub_uint32_t entry;
	grub_uint32_t child;
	grub_uint32_t mode;
	char *name;
	int found;
	unsigned depth = 0;

	while (*p == '/')
		p++;
	while (*p)
	{
		if (++depth > DWARFS_PATH_DEPTH_MAX)
		{
			grub_error (GRUB_ERR_BAD_FILENAME, "DwarFS path is too deep");
			return -1;
		}
		start = p;
		while (*p && *p != '/')
			p++;
		length = (grub_size_t) (p - start);
		while (*p == '/')
			p++;
		if (length == 1 && start[0] == '.')
			continue;
		if (length == 2 && start[0] == '.' && start[1] == '.')
		{
			grub_error (GRUB_ERR_BAD_FILENAME,
				"DwarFS parent path components are unsupported");
			return -1;
		}
		if (dwarfs_inode_mode (data, current, &mode) != 0)
			return -1;
		if ((mode & DWARFS_MODE_TYPE_MASK) != DWARFS_MODE_DIRECTORY
			|| (grub_uint64_t) current + 1 >= data->directories.count)
			goto not_found;
		found = 0;
		for (entry = data->directory_first[current];
			entry < data->directory_first[current + 1]; entry++)
		{
			if (dwarfs_entry_name (data, entry, &name, &child) != 0)
				return -1;
			if (grub_strlen (name) == length
				&& grub_memcmp (name, start, length) == 0)
			{
				current = child;
				found = 1;
				grub_free (name);
				break;
			}
			grub_free (name);
		}
		if (!found)
			goto not_found;
	}
	*inode = current;
	return 0;

not_found:
	grub_error (GRUB_ERR_FILE_NOT_FOUND, "DwarFS file not found");
	return -1;
}

static int
dwarfs_inode_mtime (struct dwarfs_data *data, grub_uint32_t inode,
	grub_int64_t *mtime)
{
	struct dwarfs_view view;
	grub_uint64_t offset = 0;
	grub_uint64_t scaled;
	grub_uint64_t result;

	if (dwarfs_inode_view (data, inode, &view) != 0
		|| dwarfs_field_uint (data, view, 7, &offset) < 0)
		return -1;
	if (grub_mul (offset, (grub_uint64_t) data->time_resolution, &scaled)
		|| grub_add (data->timestamp_base, scaled, &result)
		|| result > DWARFS_INT64_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS modification time");
		return -1;
	}
	*mtime = (grub_int64_t) result;
	return 0;
}

static grub_err_t
dwarfs_dir (grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct dwarfs_data *data = NULL;
	struct grub_dirhook_info info;
	grub_uint32_t inode;
	grub_uint32_t child;
	grub_uint32_t entry;
	grub_uint32_t mode;
	char *name = NULL;
	grub_err_t err = GRUB_ERR_NONE;

	data = dwarfs_mount (device->disk);
	if (!data)
		return grub_errno;
	if (dwarfs_lookup (data, path, &inode) != 0
		|| dwarfs_inode_mode (data, inode, &mode) != 0)
		goto fail;
	if ((mode & DWARFS_MODE_TYPE_MASK) != DWARFS_MODE_DIRECTORY
		|| (grub_uint64_t) inode + 1 >= data->directories.count)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a DwarFS directory");
		goto fail;
	}
	for (entry = data->directory_first[inode];
		entry < data->directory_first[inode + 1]; entry++)
	{
		if (dwarfs_entry_name (data, entry, &name, &child) != 0
			|| dwarfs_inode_mode (data, child, &mode) != 0)
			goto fail;
		grub_memset (&info, 0, sizeof (info));
		info.dir = (mode & DWARFS_MODE_TYPE_MASK) == DWARFS_MODE_DIRECTORY;
		info.symlink = (mode & DWARFS_MODE_TYPE_MASK) == DWARFS_MODE_SYMLINK;
		info.inodeset = 1;
		info.inode = child;
		if (!info.dir && !info.symlink)
		{
			grub_uint32_t begin, end;

			if (dwarfs_file_chunks (data, child, &begin, &end) == 0
				&& dwarfs_file_size (data, begin, end, &info.size) == 0)
				info.sizeset = 1;
			else
				grub_errno = GRUB_ERR_NONE;
		}
		if (dwarfs_inode_mtime (data, child, &info.mtime) == 0)
			info.mtimeset = 1;
		else
			goto fail;
		if (hook (name, &info, hook_data))
		{
			grub_free (name);
			name = NULL;
			break;
		}
		grub_free (name);
		name = NULL;
	}
	goto out;

fail:
	err = grub_errno;
out:
	grub_free (name);
	dwarfs_free (data);
	return err;
}

static grub_err_t
dwarfs_open (grub_file_t file, const char *name)
{
	struct dwarfs_data *data = NULL;
	struct dwarfs_file *opened = NULL;
	grub_uint32_t inode;
	grub_uint32_t mode;
	grub_uint64_t size;
	grub_err_t err = GRUB_ERR_NONE;

	data = dwarfs_mount (file->device->disk);
	if (!data)
		return grub_errno;
	if (dwarfs_lookup (data, name, &inode) != 0
		|| dwarfs_inode_mode (data, inode, &mode) != 0)
		goto fail;
	if ((mode & DWARFS_MODE_TYPE_MASK) != DWARFS_MODE_REGULAR)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a regular DwarFS file");
		goto fail;
	}
	opened = grub_zalloc (sizeof (*opened));
	if (!opened)
		goto fail;
	opened->cached_block = GRUB_UINT_MAX;
	opened->data = data;
	opened->inode = inode;
	if (dwarfs_file_chunks (data, inode, &opened->chunk_begin,
		&opened->chunk_end) != 0
		|| dwarfs_file_size (data, opened->chunk_begin, opened->chunk_end,
			&size) != 0)
		goto fail;
	file->data = opened;
	file->size = size;
	return GRUB_ERR_NONE;

fail:
	err = grub_errno;
	if (opened)
	{
		grub_free (opened->block_buf);
		grub_free (opened);
	}
	dwarfs_free (data);
	return err;
}

static int
dwarfs_load_block (struct dwarfs_file *file, grub_uint32_t block)
{
	grub_uint8_t *buf;
	grub_size_t size;

	if (block == file->cached_block)
		return 0;
	if (block >= file->data->block_count)
	{
		grub_error (GRUB_ERR_BAD_FS, "DwarFS block index out of range");
		return -1;
	}
	if (dwarfs_decompress (file->data, &file->data->blocks[block],
		&buf, &size, file->data->block_size) != 0)
		return -1;
	grub_free (file->block_buf);
	file->block_buf = buf;
	file->block_size = size;
	file->cached_block = block;
	return 0;
}

static grub_ssize_t
dwarfs_read (grub_file_t grub_file, char *buf, grub_size_t len)
{
	struct dwarfs_file *file = grub_file->data;
	grub_uint64_t file_pos = 0;
	grub_uint64_t chunk_size;
	grub_uint64_t chunk_end;
	grub_uint64_t wanted_end;
	grub_uint64_t start;
	grub_uint64_t take;
	grub_uint32_t block;
	grub_uint32_t block_offset;
	grub_uint32_t chunk;
	grub_size_t done = 0;
	int hole;

	if (grub_add ((grub_uint64_t) grub_file->offset, (grub_uint64_t) len,
		&wanted_end))
		goto invalid;
	for (chunk = file->chunk_begin; chunk < file->chunk_end && done < len;
		chunk++)
	{
		if (dwarfs_chunk_info (file->data, chunk, &block, &block_offset,
			&chunk_size, &hole) != 0
			|| grub_add (file_pos, chunk_size, &chunk_end))
			goto invalid;
		if (chunk_end <= grub_file->offset)
		{
			file_pos = chunk_end;
			continue;
		}
		if (file_pos >= wanted_end)
			break;
		start = grub_file->offset > file_pos ? grub_file->offset - file_pos : 0;
		take = chunk_size - start;
		if (take > len - done)
			take = len - done;
		if (take > GRUB_SIZE_MAX)
			goto invalid;
		if (hole)
			grub_memset (buf + done, 0, (grub_size_t) take);
		else
		{
			grub_uint64_t source;

			if (dwarfs_load_block (file, block) != 0
				|| grub_add ((grub_uint64_t) block_offset, start, &source)
				|| source > file->block_size
				|| take > file->block_size - source)
				goto invalid;
			grub_memcpy (buf + done, file->block_buf + (grub_size_t) source,
				(grub_size_t) take);
		}
		done += (grub_size_t) take;
		file_pos = chunk_end;
	}
	return (grub_ssize_t) done;

invalid:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "invalid DwarFS file data");
	return -1;
}

static grub_err_t
dwarfs_close (grub_file_t grub_file)
{
	struct dwarfs_file *file = grub_file->data;

	grub_free (file->block_buf);
	dwarfs_free (file->data);
	grub_free (file);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_dwarfs_fs =
{
	.name = "dwarfs",
	.fs_dir = dwarfs_dir,
	.fs_open = dwarfs_open,
	.fs_read = dwarfs_read,
	.fs_close = dwarfs_close,
	.next = 0
};

GRUB_MOD_INIT (dwarfs)
{
	grub_dwarfs_fs.mod = mod;
	grub_fs_register (&grub_dwarfs_fs);
}

GRUB_MOD_FINI (dwarfs)
{
	grub_fs_unregister (&grub_dwarfs_fs);
}
