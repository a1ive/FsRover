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
 * ReFS (Resilient File System) 1.x / 3.x read-only driver.
 *
 * Limitations: alternate data streams, reparse point targets and the
 * rare short-form file records are not supported.
 */

#include <grub/types.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/fshelp.h>
#include <grub/dl.h>
#include <grub/lib/crc.h>
#include <lz4.h>
#include <zstd.h>

GRUB_MOD_LICENSE("GPLv2+");

/* well-known object ids */
#define REFS_OID_OBJECT_TABLE	0x2ULL
#define REFS_OID_CONTAINERS	0xBULL
#define REFS_OID_CONTAINER_INDEX	0xEULL
#define REFS_OID_VOLUME_INFO	0x500ULL
#define REFS_OID_ROOT_DIR	0x600ULL

/* container compression policy formats */
#define REFS_COMPRESSION_LZ4	1
#define REFS_COMPRESSION_ZSTD	2
#define REFS_COMPRESSION_LZ4QAT	3

/* per-container index row and compression-header flags */
#define REFS_CONTAINER_INDEX_COMPRESSION	7
#define REFS_CONTAINER_INDEX_COMPACT_MAP	3
#define REFS_COMPRESSION_LAST_RAW	0x1
#define REFS_COMPRESSION_CHECKSUMS	0x2

/* directory tree key types */
#define REFS_KEY_DIRENT		0x0030
#define REFS_KEY_HARDLINK	0x0040
#define REFS_KEY_LABEL		0x0510

#define REFS_DIRENT_LONG	0x0001
#define REFS_DIRENT_SHORT	0x0002

/* attribute type (in attribute keys) */
#define REFS_ATTR_DATA		0x0080

/* file flags */
#define REFS_FLAG_DIRECTORY	0x10000000UL
#define REFS_FLAG_REPARSE	0x00000400UL
#define REFS_FLAG_SPARSE	0x00000200UL

/* reparse tags that carry a filesystem link target */
#define REFS_REPARSE_MOUNT_POINT	0xA0000003UL
#define REFS_REPARSE_SYMLINK	0xA000000CUL
#define REFS_REPARSE_LX_SYMLINK	0xA000001DUL

#define REFS_SUPERBLOCK_BLOCK	30

/* v3 metadata block header */
#define REFS_NODE_HEADER_SIZE	0x50
#define REFS_NODE_SELF_BLOCKS	0x20	/* le64[4] */
#define REFS_NODE_OBJECT_ID	0x48

/* v1 metadata block header: block number, then the object id */
#define REFS_V1_NODE_HEADER_SIZE	0x30
#define REFS_V1_NODE_OBJECT_ID		0x18

/* v1 addresses metadata and file data in fixed 16 KiB blocks */
#define REFS_V1_BLOCK_SHIFT	14

/* seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01 */
#define REFS_EPOCH_BIAS		11644473600ULL

/* guards against reference loops / absurd allocations */
#define REFS_MAX_WALK_NODES	(1UL << 20)
#define REFS_MAX_EXTENTS	(1UL << 22)

static grub_uint16_t
refs_get16(const grub_uint8_t *p)
{
	return grub_le_to_cpu16(grub_get_unaligned16(p));
}

static grub_uint32_t
refs_get32(const grub_uint8_t *p)
{
	return grub_le_to_cpu32(grub_get_unaligned32(p));
}

static grub_uint64_t
refs_get64(const grub_uint8_t *p)
{
	return grub_le_to_cpu64(grub_get_unaligned64(p));
}

/* one range of the virtual -> physical container mapping */
struct grub_refs_map_entry
{
	grub_uint64_t id;
	grub_uint64_t start;
	grub_uint64_t count;
	grub_uint32_t flags;
	grub_uint8_t *compact_bitmap;
	grub_uint16_t *compact_rank;
};

struct grub_refs_compression_range
{
	grub_uint64_t container_id;
	grub_uint64_t plain_start;
	grub_uint64_t plain_size;
	grub_uint64_t stored_start;
	grub_uint64_t stored_size;
	grub_uint32_t flags;
	grub_uint32_t unit_count;
	grub_uint32_t *ends;
	grub_uint32_t *checksums;
};

struct grub_refs_data
{
	grub_disk_t disk;
	grub_uint8_t version_major;
	grub_uint8_t version_minor;
	grub_uint8_t v1;		/* 1.x on-disk layout */
	grub_uint32_t header_size;	/* metadata block header */
	grub_uint32_t table_min;	/* minimum node allocation entry */
	grub_uint16_t ref_size;		/* node reference */
	grub_uint16_t extent_size;	/* raw extent record */
	grub_uint32_t cluster_size;	/* allocation unit (v1: 16 KiB) */
	int cluster_shift;
	grub_uint32_t block_size;	/* metadata node size */
	grub_uint32_t chunk_count;	/* clusters per node (1..4) */
	grub_uint64_t serial;
	/* container mapping (from the 0xB tree) */
	grub_uint64_t linear_limit;	/* blocks below this are identity */
	int bpc_shift;			/* log2(blocks per container chunk) */
	grub_uint64_t bpc_mask;
	struct grub_refs_map_entry *map;
	grub_uint32_t map_len;
	grub_uint16_t compression_format;
	grub_uint32_t compression_unit_size;
	struct grub_refs_compression_range *compression;
	grub_uint32_t compression_len;
	grub_uint8_t *compressed_buf;
	grub_uint8_t *plain_buf;
	grub_uint32_t cache_range;
	grub_uint32_t cache_unit;
	int cache_valid;
	grub_uint64_t obj_table[4];	/* object table root node */
};

/* fshelp node types */
enum
{
	REFS_NODE_DIR,
	REFS_NODE_REG,		/* long entry; record[] holds the value */
	REFS_NODE_HARDLINK,	/* short entry pointing at a 0x40 record */
	REFS_NODE_SHORT		/* short-form file without a record */
};

struct grub_fshelp_node
{
	struct grub_refs_data *data;
	grub_uint8_t type;
	grub_uint8_t reparse;
	grub_uint8_t sparse;
	grub_uint64_t oid;	/* DIR: directory object id;
				   HARDLINK: parent directory object id */
	grub_uint64_t hardlink_id;
	grub_uint64_t size;
	grub_int64_t mtime;	/* unix time */
	grub_uint32_t record_size;
	grub_uint8_t record[];	/* REFS_NODE_REG: dirent value copy */
};

struct grub_refs_extent
{
	grub_uint64_t vcn;	/* first file cluster */
	grub_uint64_t count;	/* cluster count */
	grub_uint64_t block;	/* first virtual disk cluster */
};

/* an open file: resident data or collected extents */
struct grub_refs_stream
{
	struct grub_refs_data *data;
	struct grub_fshelp_node *node;
	grub_uint8_t *hl_record;	/* resolved hard link record */
	grub_uint32_t hl_record_size;
	int is_resident;
	const grub_uint8_t *resident;	/* into node->record / hl_record */
	grub_uint32_t resident_size;
	struct grub_refs_extent *ext;
	grub_uint32_t ext_len;
	grub_uint32_t ext_cap;
	grub_uint32_t hint;		/* last extent hit (read locality) */
};

static grub_int64_t
grub_refs_filetime_to_unix(grub_uint64_t ft)
{
	return (grub_int64_t) grub_divmod64(ft, 10000000, 0) - (grub_int64_t) REFS_EPOCH_BIAS;
}

/* convert an UTF-16LE name (LEN 16-bit units, not NUL-terminated) to
   a freshly allocated UTF-8 string */
static char *
grub_refs_get_utf8(const grub_uint8_t *in, grub_size_t len)
{
	grub_uint8_t *buf;
	grub_uint16_t *tmp;
	grub_size_t i;

	buf = grub_calloc(len + 1, GRUB_MAX_UTF8_PER_UTF16);
	tmp = grub_calloc(len + 1, sizeof(tmp[0]));
	if (!buf || !tmp)
		goto fail;
	for (i = 0; i < len; i++)
		tmp[i] = grub_le_to_cpu16(grub_get_unaligned16(in + 2 * i));
	*grub_utf16_to_utf8(buf, tmp, len) = '\0';
	grub_free(tmp);
	return (char *) buf;

fail:
	grub_free(buf);
	grub_free(tmp);
	return NULL;
}

/* locate and translate a virtual cluster through the container table */
static int
grub_refs_lookup_map(struct grub_refs_data *data, grub_uint64_t block,
	struct grub_refs_map_entry **entry, grub_uint64_t *physical)
{
	grub_uint64_t id;
	grub_uint32_t i;

	*entry = NULL;
	if (block < data->linear_limit)
	{
		*physical = block;
		return 1;
	}

	/* One boundary bit separates the encoded container id from the
	   in-container cluster offset.  The key in the 0xB table is the
	   container id; compressed rows use COUNT for stored clusters, so
	   it must not be accumulated to locate later rows. */
	if (block & ((grub_uint64_t) 1 << data->bpc_shift))
		return 0;
	id = block >> (data->bpc_shift + 1);
	for (i = 0; i < data->map_len; i++)
	{
		if (id == data->map[i].id)
		{
			*entry = &data->map[i];
			*physical = data->map[i].start | (block & data->bpc_mask);
			return 1;
		}
	}
	return 0;
}

/* translate a virtual cluster number through the container table */
static grub_uint64_t
grub_refs_map_block(struct grub_refs_data *data, grub_uint64_t block)
{
	struct grub_refs_map_entry *entry;
	grub_uint64_t physical;

	if (grub_refs_lookup_map(data, block, &entry, &physical))
		return physical;
	return 0;
}

static grub_uint8_t grub_refs_popcount8(grub_uint8_t value);

static struct grub_refs_compression_range *
grub_refs_find_compression(struct grub_refs_data *data,
	grub_uint64_t container_id, grub_uint64_t offset,
	grub_uint32_t *range_index)
{
	grub_uint32_t i;

	for (i = 0; i < data->compression_len; i++)
	{
		struct grub_refs_compression_range *range = &data->compression[i];

		if (range->container_id == container_id
			&& offset >= range->plain_start
			&& offset - range->plain_start < range->plain_size)
		{
			*range_index = i;
			return range;
		}
	}
	return NULL;
}

static int
grub_refs_container_is_compressed(struct grub_refs_data *data,
	grub_uint64_t container_id)
{
	grub_uint32_t i;

	for (i = 0; i < data->compression_len; i++)
		if (data->compression[i].container_id == container_id)
			return 1;
	return 0;
}

/* Read the compressed backing range through its ordinary second-level
   virtual container mapping.  Compression backing containers must not
   themselves be compressed. */
static grub_err_t
grub_refs_read_compressed_backing(struct grub_refs_data *data,
	grub_uint64_t byte, grub_size_t len, grub_uint8_t *buf)
{
	grub_uint64_t cluster_mask = data->cluster_size - 1;

	while (len)
	{
		struct grub_refs_map_entry *entry;
		grub_uint64_t block = byte >> data->cluster_shift;
		grub_uint64_t physical;
		grub_uint64_t offset = byte & cluster_mask;
		grub_uint64_t container_left;
		grub_size_t step;

		if (!grub_refs_lookup_map(data, block, &entry, &physical))
			return grub_error(GRUB_ERR_BAD_FS, "refs: unmapped compressed backing");
		if (entry && grub_refs_container_is_compressed(data, entry->id))
			return grub_error(GRUB_ERR_BAD_FS, "refs: recursive compressed backing");
		container_left = ((data->bpc_mask + 1 - (block & data->bpc_mask)) << data->cluster_shift) - offset;
		step = len;
		if (container_left < step)
			step = (grub_size_t) container_left;
		if (grub_disk_read(data->disk, 0,
			(physical << data->cluster_shift) + offset, step, buf))
			return grub_errno;
		byte += step;
		buf += step;
		len -= step;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_refs_load_compression_unit(struct grub_refs_data *data,
	struct grub_refs_map_entry *entry,
	struct grub_refs_compression_range *range,
	grub_uint32_t range_index, grub_uint32_t unit)
{
	grub_uint32_t stored_start = unit ? range->ends[unit - 1] : 0;
	grub_uint32_t stored_end = range->ends[unit];
	grub_uint32_t stored_size = stored_end - stored_start;
	grub_uint64_t plain_done = (grub_uint64_t) unit * data->compression_unit_size;
	grub_uint32_t plain_size;
	size_t got;

	if (range->plain_size - plain_done < data->compression_unit_size)
		plain_size = (grub_uint32_t) (range->plain_size - plain_done);
	else
		plain_size = data->compression_unit_size;
	if (!stored_size || stored_size > data->compression_unit_size)
		return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA, "refs: invalid compressed unit size");
	if (grub_refs_read_compressed_backing(data,
		(entry->start << data->cluster_shift) + range->stored_start + stored_start,
		stored_size, data->compressed_buf))
		return grub_errno;
	if ((range->flags & REFS_COMPRESSION_CHECKSUMS)
		&& grub_getcrc32c(0, data->compressed_buf, (int) stored_size) != range->checksums[unit])
		return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA, "refs: compressed unit checksum mismatch");

	if (unit + 1 == range->unit_count
		&& (range->flags & REFS_COMPRESSION_LAST_RAW))
	{
		if (stored_size != plain_size)
			return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA, "refs: invalid raw compression unit");
		grub_memcpy(data->plain_buf, data->compressed_buf, plain_size);
	}
	else if (data->compression_format == REFS_COMPRESSION_LZ4
		|| data->compression_format == REFS_COMPRESSION_LZ4QAT)
	{
		if (LZ4_decompress_safe((const char *) data->compressed_buf,
			(char *) data->plain_buf, (int) stored_size,
			(int) plain_size) != (int) plain_size)
			return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA, "refs: invalid LZ4 compressed unit");
	}
	else if (data->compression_format == REFS_COMPRESSION_ZSTD)
	{
		got = ZSTD_decompress(data->plain_buf, plain_size, data->compressed_buf, stored_size);
		if (got != plain_size)
			return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA, "refs: invalid ZSTD compressed unit");
	}
	else
		return grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET, "refs: unsupported compression format %u", data->compression_format);

	data->cache_range = range_index;
	data->cache_unit = unit;
	data->cache_valid = 1;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_refs_read_data(struct grub_refs_data *data, grub_uint64_t block,
	grub_uint64_t offset, grub_size_t len, char *buf)
{
	while (len)
	{
		struct grub_refs_map_entry *entry;
		struct grub_refs_compression_range *range;
		grub_uint64_t physical;
		grub_uint64_t container_offset;
		grub_uint64_t compacted_offset;
		grub_uint64_t container_left;
		grub_uint32_t range_index = 0;
		grub_size_t step;

		block += offset >> data->cluster_shift;
		offset &= data->cluster_size - 1;
		if (!grub_refs_lookup_map(data, block, &entry, &physical))
			return grub_error(GRUB_ERR_BAD_FS, "refs: unmapped file extent");
		container_offset = ((block & data->bpc_mask) << data->cluster_shift) + offset;
		compacted_offset = container_offset;
		if (entry && grub_refs_container_is_compressed(data, entry->id))
		{
			grub_uint32_t cluster = (grub_uint32_t) (block & data->bpc_mask);
			grub_uint32_t byte_index = cluster >> 3;
			grub_uint32_t bit = cluster & 7;
			grub_uint8_t byte;
			grub_uint32_t rank;

			if (!entry->compact_bitmap || !entry->compact_rank)
				return grub_error(GRUB_ERR_BAD_FS, "refs: missing compacted cluster map");
			byte = entry->compact_bitmap[byte_index];
			if (!(byte & (1U << bit)))
				return grub_error(GRUB_ERR_BAD_FS, "refs: unallocated compressed cluster");
			rank = entry->compact_rank[byte_index]
				+ grub_refs_popcount8((grub_uint8_t) (byte & ((1U << bit) - 1)));
			compacted_offset = ((grub_uint64_t) rank << data->cluster_shift) + offset;
		}
		range = entry ? grub_refs_find_compression(data, entry->id,
			compacted_offset, &range_index) : NULL;
		if (range)
		{
			grub_uint64_t in_range =
				compacted_offset - range->plain_start;
			grub_uint32_t unit = (grub_uint32_t)
				(in_range / data->compression_unit_size);
			grub_uint32_t in_unit = (grub_uint32_t)
				(in_range % data->compression_unit_size);

			if (!data->cache_valid || data->cache_range != range_index
				|| data->cache_unit != unit)
				if (grub_refs_load_compression_unit(data, entry, range, range_index, unit))
					return grub_errno;
			step = data->compression_unit_size - in_unit;
			if (range->plain_size - in_range < step)
				step = (grub_size_t) (range->plain_size - in_range);
			if (step > len)
				step = len;
			grub_memcpy(buf, data->plain_buf + in_unit, step);
		}
		else
		{
			if (entry && grub_refs_container_is_compressed(data, entry->id))
				return grub_error(GRUB_ERR_BAD_FS, "refs: missing compressed range");
			container_left = ((data->bpc_mask + 1
				- (block & data->bpc_mask)) << data->cluster_shift)
				- offset;
			step = len;
			if (container_left < step)
				step = (grub_size_t) container_left;
			if (grub_disk_read(data->disk, 0,
				(physical << data->cluster_shift) + offset, step, buf))
				return grub_errno;
		}
		buf += step;
		len -= step;
		offset += step;
	}
	return GRUB_ERR_NONE;
}

/*
 * Read one metadata node into BUF (block_size bytes).  BLOCKS holds up
 * to four virtual cluster numbers; continuation clusters that are zero
 * are fetched from the header of the first cluster.  With IDENTITY set
 * the container mapping is bypassed (superblock / checkpoint).
 */
static grub_err_t
grub_refs_read_node(struct grub_refs_data *data, const grub_uint64_t *blocks,
	int identity, const char *sig, grub_uint8_t *buf)
{
	grub_uint64_t b[4];
	grub_uint32_t i;

	b[0] = blocks[0];
	b[1] = blocks[1];
	b[2] = blocks[2];
	b[3] = blocks[3];
	if (!b[0])
		return grub_error(GRUB_ERR_BAD_FS, "refs: null node reference");

	for (i = 0; i < data->chunk_count; i++)
	{
		grub_uint64_t phys;

		if (i && !b[i])
			b[i] = refs_get64(buf + REFS_NODE_SELF_BLOCKS + 8 * i);
		phys = identity ? b[i] : grub_refs_map_block(data, b[i]);
		if (!phys)
			return grub_error(GRUB_ERR_BAD_FS, "refs: unmapped metadata block");
		if (grub_disk_read(data->disk, 0,
			phys << data->cluster_shift, data->cluster_size,
			buf + (grub_size_t) i * data->cluster_size))
			return grub_errno;
	}

	/* v1 headers carry no signature, only the self block number */
	if (data->v1 ? (refs_get64(buf) != blocks[0])
		: (grub_memcmp(buf, sig, 4) != 0 || refs_get64(buf + REFS_NODE_SELF_BLOCKS) != blocks[0]))
		return grub_error(GRUB_ERR_BAD_FS, "refs: bad metadata node");
	return GRUB_ERR_NONE;
}

/*
 * Decode a node reference (index entry value, object table value, ...):
 * four block numbers in v3, a single one in v1.  Returns 0 when the
 * reference is too short or null.
 */
static int
grub_refs_get_ref(struct grub_refs_data *data, const grub_uint8_t *value,
	grub_uint16_t value_size, grub_uint64_t *b)
{
	if (value_size < data->ref_size)
		return 0;
	b[0] = refs_get64(value);
	if (data->v1)
		b[1] = b[2] = b[3] = 0;
	else
	{
		b[1] = refs_get64(value + 8);
		b[2] = refs_get64(value + 16);
		b[3] = refs_get64(value + 24);
	}
	return b[0] != 0;
}

/*
 * Generic node table iteration.  TABLE points at the allocation entry
 * of a node body (or of an embedded attribute / extent list); entries
 * are located through the value offsets array.  Leaf entries either
 * follow the generic key/value layout or, with RAW_LEAF_SIZE nonzero,
 * are raw fixed-size records (extent subtree leaves).
 *
 * Hooks return 0 to continue, a positive value to stop (propagated
 * as-is) or -1 on error with grub_errno set.
 */
typedef int (*grub_refs_entry_hook_t)(struct grub_refs_data *data,
	int is_index, const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx);

static int
grub_refs_iter_table(struct grub_refs_data *data, const grub_uint8_t *table,
	grub_uint32_t avail, grub_uint16_t raw_leaf_size,
	grub_refs_entry_hook_t hook, void *ctx)
{
	grub_uint32_t asize, vo_start, vo_end, count;
	grub_uint32_t i;
	int is_index;

	if (avail < data->table_min + 4)
		goto corrupt;
	asize = refs_get32(table);
	is_index = (table[0xD] & 0x1) != 0;
	vo_start = refs_get32(table + 0x10);
	count = refs_get32(table + 0x14);
	/* the value offsets array end trails the entry in v1 */
	vo_end = refs_get32(table + (data->v1 ? 0x18 : 0x20));
	if (asize < data->table_min || asize > avail || vo_start < asize
		|| vo_start > vo_end || vo_end > avail
		|| count > (vo_end - vo_start) / 4)
		goto corrupt;

	for (i = 0; i < count; i++)
	{
		grub_uint32_t off = refs_get16(table + vo_start + 4 * i);
		const grub_uint8_t *entry = table + off;
		const grub_uint8_t *key = NULL;
		const grub_uint8_t *value = NULL;
		grub_uint32_t esize;
		grub_uint16_t key_off, key_size, val_off, val_size;
		int ret;

		if (off < asize)
			continue;

		if (!is_index && raw_leaf_size)
		{
			if (off + raw_leaf_size > vo_start)
				continue;
			ret = hook(data, 0, NULL, 0, entry, raw_leaf_size,
				ctx);
			if (ret)
				return ret;
			continue;
		}

		if (off + 0x10 > vo_start)
			continue;
		esize = refs_get32(entry);
		if (esize < 0x10 || esize > vo_start - off)
			continue;
		key_off = refs_get16(entry + 0x4);
		key_size = refs_get16(entry + 0x6);
		val_off = refs_get16(entry + 0xA);
		val_size = refs_get16(entry + 0xC);
		if (key_size)
		{
			if (key_off < 0x10 || (grub_uint32_t) key_off + key_size > esize)
				continue;
			key = entry + key_off;
		}
		if (val_size)
		{
			if (val_off < 0x10
				|| (grub_uint32_t) val_off + val_size > esize)
				continue;
			value = entry + val_off;
		}
		ret = hook(data, is_index, key, key ? key_size : 0, value, value ? val_size : 0, ctx);
		if (ret)
			return ret;
	}

	return 0;

corrupt:
	grub_error(GRUB_ERR_BAD_FS, "refs: corrupt node table");
	return -1;
}

/*
 * Breadth-first walk over a B-tree given its root node reference.
 * Index entries push their child node onto the queue; leaf entries are
 * handed to the hook.  Return convention as grub_refs_iter_table.
 */
struct grub_refs_walk_ctx
{
	grub_uint64_t (*queue)[4];
	grub_uint32_t len;
	grub_uint32_t cap;
	grub_refs_entry_hook_t hook;
	void *hook_ctx;
};

static int
grub_refs_walk_push(struct grub_refs_walk_ctx *w, const grub_uint64_t *b)
{
	if (w->len == w->cap)
	{
		grub_uint32_t ncap = w->cap ? w->cap * 2 : 16;
		grub_uint64_t (*n)[4];

		n = grub_realloc(w->queue, (grub_size_t) ncap * sizeof(w->queue[0]));
		if (!n)
			return -1;
		w->queue = n;
		w->cap = ncap;
	}
	grub_memcpy(w->queue[w->len], b, 4 * sizeof(grub_uint64_t));
	w->len++;
	return 0;
}

static int
grub_refs_walk_entry(struct grub_refs_data *data, int is_index,
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	struct grub_refs_walk_ctx *w = ctx;

	if (is_index)
	{
		grub_uint64_t b[4];

		if (!grub_refs_get_ref(data, value, value_size, b))
			return 0;
		return grub_refs_walk_push(w, b) ? -1 : 0;
	}

	return w->hook(data, 0, key, key_size, value, value_size, w->hook_ctx);
}

static int
grub_refs_walk_tree(struct grub_refs_data *data, const grub_uint64_t *root,
	grub_uint16_t raw_leaf_size, grub_refs_entry_hook_t hook, void *ctx)
{
	struct grub_refs_walk_ctx w;
	grub_uint8_t *buf;
	grub_uint32_t head;
	int ret = -1;

	grub_memset(&w, 0, sizeof(w));
	w.hook = hook;
	w.hook_ctx = ctx;

	buf = grub_malloc(data->block_size);
	if (!buf)
		return -1;
	if (grub_refs_walk_push(&w, root))
		goto out;

	for (head = 0; head < w.len; head++)
	{
		grub_uint32_t hsize;
		int r;

		if (head >= REFS_MAX_WALK_NODES)
		{
			grub_error(GRUB_ERR_BAD_FS, "refs: tree loop");
			goto out;
		}
		if (grub_refs_read_node(data, w.queue[head], 0, "MSB+", buf))
			goto out;
		hsize = refs_get32(buf + data->header_size);
		if (hsize < 4 || hsize > data->block_size - data->header_size - data->table_min - 4)
		{
			grub_error(GRUB_ERR_BAD_FS, "refs: corrupt node");
			goto out;
		}
		r = grub_refs_iter_table(data,
			buf + data->header_size + hsize,
			data->block_size - data->header_size - hsize,
			raw_leaf_size, grub_refs_walk_entry, &w);
		if (r)
		{
			ret = r;
			goto out;
		}
	}
	ret = 0;

out:
	grub_free(w.queue);
	grub_free(buf);
	return ret;
}

/* look up an object id in the object table (0x2 tree) */
struct grub_refs_oid_ctx
{
	grub_uint64_t oid;
	grub_uint64_t root[4];
	int found;
};

static int
grub_refs_oid_hook(struct grub_refs_data *data,
	int is_index __attribute__((unused)),
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	struct grub_refs_oid_ctx *c = ctx;
	/* v3 prefixes the node reference with a 0x20-byte value header */
	grub_uint16_t off = data->v1 ? 0 : 0x20;

	if (key_size < 0x10 || value_size < off)
		return 0;
	if (refs_get16(key) != 0 || refs_get64(key + 8) != c->oid)
		return 0;
	if (!grub_refs_get_ref(data, value + off, (grub_uint16_t) (value_size - off), c->root))
		return 0;
	c->found = 1;
	return 1;
}

static grub_err_t
grub_refs_find_tree(struct grub_refs_data *data, grub_uint64_t oid, grub_uint64_t *root)
{
	struct grub_refs_oid_ctx c;

	grub_memset(&c, 0, sizeof(c));
	c.oid = oid;
	if (grub_refs_walk_tree(data, data->obj_table, 0, grub_refs_oid_hook, &c) < 0)
		return grub_errno;
	if (!c.found || !c.root[0])
		return grub_error(GRUB_ERR_BAD_FS, "refs: object 0x%" PRIxGRUB_UINT64_T " not found", oid);
	grub_memcpy(root, c.root, sizeof(c.root));
	return GRUB_ERR_NONE;
}

/* container table (0xB tree) leaf: append one mapping range */
static int
grub_refs_map_hook(struct grub_refs_data *data,
	int is_index __attribute__((unused)),
	const grub_uint8_t *key,
	grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size,
	void *ctx __attribute__((unused)))
{
	grub_uint64_t start, count;
	struct grub_refs_map_entry *n;

	/* v3.x: block range start / length trail the value */
	if (value_size <= 0x60)
		return 0;
	start = refs_get64(value + value_size - 0x10);
	count = refs_get64(value + value_size - 0x8);
	if (!count)
		return 0;

	n = grub_realloc(data->map, ((grub_size_t) data->map_len + 1) * sizeof(data->map[0]));
	if (!n)
		return -1;
	data->map = n;
	data->map[data->map_len].id = (key_size >= 8) ? refs_get64(key) : data->map_len;
	data->map[data->map_len].start = start;
	data->map[data->map_len].count = count;
	data->map[data->map_len].flags = (value_size >= 0x18) ? refs_get32(value + 0x14) : 0;
	data->map[data->map_len].compact_bitmap = NULL;
	data->map[data->map_len].compact_rank = NULL;
	data->map_len++;
	return 0;
}

static grub_uint8_t
grub_refs_popcount8(grub_uint8_t value)
{
	value = (grub_uint8_t) (value - ((value >> 1) & 0x55));
	value = (grub_uint8_t) ((value & 0x33) + ((value >> 2) & 0x33));
	return (grub_uint8_t) ((value + (value >> 4)) & 0x0F);
}

/* Container Index (0xE): type 3 is the original-cluster to compacted
   stream bitmap; type 7 describes a compressed range in that stream. */
static int
grub_refs_compression_hook(struct grub_refs_data *data,
	int is_index __attribute__((unused)),
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size,
	void *ctx __attribute__((unused)))
{
	struct grub_refs_compression_range range;
	struct grub_refs_compression_range *n;
	struct grub_refs_map_entry *entry = NULL;
	grub_uint64_t container_size;
	grub_uint64_t stored_capacity;
	grub_uint32_t array_offset;
	grub_uint32_t checksum_type;
	grub_uint32_t kind;
	grub_uint32_t i;

	if (key_size < 0x10)
		return 0;
	kind = refs_get32(key + 0x0C);
	if (kind != REFS_CONTAINER_INDEX_COMPACT_MAP
		&& kind != REFS_CONTAINER_INDEX_COMPRESSION)
		return 0;
	if (value_size < 0x30 || refs_get64(value) != refs_get64(key)
		|| refs_get32(value + 0x0C) != kind)
		goto corrupt;
	for (i = 0; i < data->map_len; i++)
		if (data->map[i].id == refs_get64(value))
		{
			entry = &data->map[i];
			break;
		}
	if (!entry)
		goto corrupt;
	if (kind == REFS_CONTAINER_INDEX_COMPACT_MAP)
	{
		grub_uint32_t bitmap_bytes =
			(grub_uint32_t) ((data->bpc_mask + 1) >> 3);

		if (entry->compact_bitmap || entry->compact_rank
			|| value_size < 0x30 + bitmap_bytes
			|| refs_get64(value + 0x18) != (entry->id << (data->bpc_shift + 1))
			|| refs_get64(value + 0x20) != data->bpc_mask + 1)
			goto corrupt;
		entry->compact_bitmap = grub_malloc(bitmap_bytes);
		entry->compact_rank = grub_malloc(((grub_size_t) bitmap_bytes + 1) * sizeof(entry->compact_rank[0]));
		if (!entry->compact_bitmap || !entry->compact_rank)
			return -1;
		grub_memcpy(entry->compact_bitmap, value + 0x30, bitmap_bytes);
		entry->compact_rank[0] = 0;
		for (i = 0; i < bitmap_bytes; i++)
			entry->compact_rank[i + 1] = (grub_uint16_t) (entry->compact_rank[i] + grub_refs_popcount8(entry->compact_bitmap[i]));
		return 0;
	}
	if (value_size < 0x40)
		goto corrupt;

	grub_memset(&range, 0, sizeof(range));
	range.container_id = refs_get64(value);
	range.plain_start = refs_get64(value + 0x10);
	range.plain_size = refs_get64(value + 0x18);
	range.stored_start = refs_get64(value + 0x20);
	range.stored_size = refs_get64(value + 0x28);
	range.flags = refs_get32(value + 0x30);
	range.unit_count = refs_get32(value + 0x34);
	array_offset = refs_get32(value + 0x38);
	checksum_type = refs_get16(value + 0x3C);

	container_size = (data->bpc_mask + 1) << data->cluster_shift;
	if (!data->compression_unit_size
		|| !range.plain_size || !range.stored_size
		|| range.flags & ~(REFS_COMPRESSION_LAST_RAW | REFS_COMPRESSION_CHECKSUMS)
		|| !range.unit_count || range.unit_count > 0x10000
		|| range.plain_start > container_size
		|| range.plain_size > container_size - range.plain_start
		|| range.plain_start % data->compression_unit_size
		|| range.unit_count != (range.plain_size + data->compression_unit_size - 1) / data->compression_unit_size
		|| array_offset < 0x40 || array_offset > value_size
		|| range.unit_count > (value_size - array_offset) / 4)
		goto corrupt;
	stored_capacity = entry->count << data->cluster_shift;
	if (range.stored_start > stored_capacity
		|| range.stored_size > stored_capacity - range.stored_start)
		goto corrupt;
	if (range.flags & REFS_COMPRESSION_CHECKSUMS)
	{
		if (checksum_type != 1
			|| range.unit_count > (value_size - array_offset) / 8)
			goto corrupt;
	}
	else if (checksum_type != 0)
		goto corrupt;

	range.ends = grub_malloc((grub_size_t) range.unit_count
		* sizeof(range.ends[0]));
	if (!range.ends)
		return -1;
	if (range.flags & REFS_COMPRESSION_CHECKSUMS)
	{
		range.checksums = grub_malloc((grub_size_t) range.unit_count * sizeof(range.checksums[0]));
		if (!range.checksums)
			goto fail;
	}
	for (i = 0; i < range.unit_count; i++)
	{
		range.ends[i] = refs_get32(value + array_offset + 4 * i);
		if (!range.ends[i] || range.ends[i] > range.stored_size
			|| (i && range.ends[i] <= range.ends[i - 1]))
			goto corrupt_range;
		if (range.checksums)
			range.checksums[i] = refs_get32(value + array_offset + 4 * range.unit_count + 4 * i);
	}
	if (range.ends[range.unit_count - 1] != range.stored_size)
		goto corrupt_range;

	n = grub_realloc(data->compression,
		((grub_size_t) data->compression_len + 1) * sizeof(data->compression[0]));
	if (!n)
		goto fail;
	data->compression = n;
	data->compression[data->compression_len++] = range;
	return 0;

corrupt_range:
	grub_error(GRUB_ERR_BAD_FS, "refs: corrupt compression header");
fail:
	grub_free(range.checksums);
	grub_free(range.ends);
	return -1;
corrupt:
	grub_error(GRUB_ERR_BAD_FS, "refs: corrupt compression header");
	return -1;
}

static void
grub_refs_unmount(struct grub_refs_data *data)
{
	grub_uint32_t i;

	for (i = 0; i < data->compression_len; i++)
	{
		grub_free(data->compression[i].checksums);
		grub_free(data->compression[i].ends);
	}
	for (i = 0; i < data->map_len; i++)
	{
		grub_free(data->map[i].compact_rank);
		grub_free(data->map[i].compact_bitmap);
	}
	grub_free(data->plain_buf);
	grub_free(data->compressed_buf);
	grub_free(data->compression);
	grub_free(data->map);
	grub_free(data);
}

static struct grub_refs_data *
grub_refs_mount(grub_disk_t disk)
{
	grub_uint8_t bs[512];
	struct grub_refs_data *data = NULL;
	grub_uint8_t *node = NULL;
	grub_uint8_t *tmp = NULL;
	grub_uint32_t bps, spc;
	grub_uint64_t cs64;
	grub_uint32_t cs;
	grub_uint64_t sb_blocks[4];
	grub_uint64_t l1[2];
	grub_uint64_t containers[4];
	grub_uint64_t container_index[4];
	grub_uint32_t l1_off, l1_count;
	grub_uint32_t ref_count, ref_base;
	int have_chkp = 0;
	int v314;
	int pass;
	grub_uint32_t i;

	if (grub_disk_read(disk, 0, 0, sizeof(bs), bs))
		goto fail;
	if (grub_memcmp(bs + 0x3, "ReFS", 4) != 0
		|| grub_memcmp(bs + 0x10, "FSRS", 4) != 0)
		goto fail;

	bps = refs_get32(bs + 0x20);
	spc = refs_get32(bs + 0x24);
	if (bps < 512 || bps > 65536 || (bps & (bps - 1)) || !spc)
		goto fail;
	cs64 = (grub_uint64_t) bps * spc;
	if (cs64 < 4096 || cs64 > 65536 || (cs64 & (cs64 - 1)))
		goto fail;
	cs = (grub_uint32_t) cs64;

	if (bs[0x28] != 1 && bs[0x28] != 3)
	{
		grub_error(GRUB_ERR_BAD_FS, "unsupported ReFS version %u.%u", bs[0x28], bs[0x29]);
		goto fail;
	}

	data = grub_zalloc(sizeof(*data));
	if (!data)
		goto fail;
	data->disk = disk;
	data->version_major = bs[0x28];
	data->version_minor = bs[0x29];
	data->v1 = (bs[0x28] == 1);
	data->header_size = data->v1 ? REFS_V1_NODE_HEADER_SIZE : REFS_NODE_HEADER_SIZE;
	data->table_min = data->v1 ? 0x1C : 0x24;
	data->ref_size = data->v1 ? 0x18 : 0x20;
	data->extent_size = data->v1 ? 48 : 24;
	data->serial = refs_get64(bs + 0x38);

	if (data->v1)
	{
		/* v1 ignores the cluster size: metadata nodes and file
		   extents alike are counted in 16 KiB blocks, and block
		   numbers are physical (no container table). */
		data->cluster_shift = REFS_V1_BLOCK_SHIFT;
		data->cluster_size = 1U << REFS_V1_BLOCK_SHIFT;
		data->block_size = data->cluster_size;
		data->chunk_count = 1;
		data->linear_limit = ~(grub_uint64_t) 0;
	}
	else
	{
		data->cluster_size = cs;
		while (((grub_uint32_t) 1 << data->cluster_shift) < cs)
			data->cluster_shift++;
		data->block_size = (cs > 16384) ? cs : 16384;
		data->chunk_count = data->block_size / cs;
		data->linear_limit = (cs == 4096) ? 0x10000 : 0x1000;
		data->bpc_shift = (cs == 4096) ? 14 : 10;
		data->bpc_mask = ((grub_uint64_t) 1 << data->bpc_shift) - 1;
	}

	v314 = (data->version_major > 3
		|| (data->version_major == 3 && data->version_minor >= 14));

	node = grub_malloc(data->block_size);
	if (!node)
		goto fail;

	/* superblock at block 30 */
	for (i = 0; i < 4; i++)
		sb_blocks[i] = REFS_SUPERBLOCK_BLOCK + i;
	if (grub_refs_read_node(data, sb_blocks, 1, "SUPB", node))
		goto fail;
	/* the checkpoint list trails the volume guid and two reserved
	   fields at the start of the superblock body */
	l1_off = refs_get32(node + data->header_size + 0x20);
	l1_count = refs_get32(node + data->header_size + 0x24);
	if (!l1_count || l1_off > data->block_size
		|| l1_count > (data->block_size - l1_off) / 8)
	{
		grub_error(GRUB_ERR_BAD_FS, "refs: corrupt superblock");
		goto fail;
	}
	l1[0] = refs_get64(node + l1_off);
	l1[1] = (l1_count >= 2) ? refs_get64(node + l1_off + 8) : 0;

	/* checkpoint: try the primary copy, then the secondary */
	for (i = 0; i < 2; i++)
	{
		grub_uint64_t cb[4];
		grub_uint32_t j;

		if (!l1[i])
			continue;
		for (j = 0; j < 4; j++)
			cb[j] = l1[i] + j;
		if (grub_refs_read_node(data, cb, 1, "CHKP", node) == GRUB_ERR_NONE)
		{
			have_chkp = 1;
			break;
		}
		grub_errno = GRUB_ERR_NONE;
	}
	if (!have_chkp)
	{
		grub_error(GRUB_ERR_BAD_FS, "refs: no valid checkpoint");
		goto fail;
	}

	/* level 2 tree root references */
	ref_count = refs_get32(node + (data->v1 ? 0x58 : 0x90));
	ref_base = data->v1 ? 0x5C : 0x94;
	if (v314)
	{
		grub_uint32_t ref_start = refs_get32(node + ref_base);

		/* ReFS 3.14 stores the absolute list offset in its first slot. */
		if (ref_start)
			ref_base = ref_start;
	}
	if (ref_count > 64 || ref_base > data->block_size
		|| ref_count > (data->block_size - ref_base) / 4)
	{
		grub_error(GRUB_ERR_BAD_FS, "refs: corrupt checkpoint");
		goto fail;
	}

	/*
	 * Two passes over the level 2 roots: the container table (0xB)
	 * lives in the identity-mapped region and must be found first so
	 * that the second pass can reach trees in mapped space (the
	 * object table root moves anywhere on copy-on-write).  v1 has no
	 * container table, so its first pass is skipped.
	 */
	tmp = grub_malloc(data->block_size);
	if (!tmp)
		goto fail;
	grub_memset(containers, 0, sizeof(containers));
	grub_memset(container_index, 0, sizeof(container_index));
	for (pass = data->v1 ? 1 : 0; pass < 2; pass++)
	{
		for (i = 0; i < ref_count; i++)
		{
			grub_uint32_t roff = refs_get32(node + ref_base + 4 * i);
			grub_uint64_t b[4];
			grub_uint64_t oid;

			if (roff > data->block_size
				|| data->block_size - roff < data->ref_size)
				continue;
			if (!grub_refs_get_ref(data, node + roff, data->ref_size, b))
				continue;
			if (grub_refs_read_node(data, b, 0, "MSB+", tmp))
			{
				grub_errno = GRUB_ERR_NONE;
				continue;
			}
			oid = refs_get64(tmp + (data->v1 ? REFS_V1_NODE_OBJECT_ID : REFS_NODE_OBJECT_ID));
			if (pass == 0 && oid == REFS_OID_CONTAINERS)
			{
				grub_memcpy(containers, b, sizeof(containers));
				if (data->block_size >= 0xAC && refs_get32(tmp + 0xA0) == 0x0F)
				{
					data->compression_format = refs_get16(tmp + 0xA4);
					data->compression_unit_size = refs_get32(tmp + 0xA8);
				}
				break;
			}
			if (pass == 1 && oid == REFS_OID_OBJECT_TABLE)
				grub_memcpy(data->obj_table, b, sizeof(data->obj_table));
			else if (pass == 1 && oid == REFS_OID_CONTAINER_INDEX)
				grub_memcpy(container_index, b, sizeof(container_index));
		}
		if (pass == 0 && containers[0]
			&& grub_refs_walk_tree(data, containers, 0,
				grub_refs_map_hook, NULL) < 0)
			goto fail;
	}
	if (container_index[0]
		&& grub_refs_walk_tree(data, container_index, 0,
			grub_refs_compression_hook, NULL) < 0)
		goto fail;
	if (data->compression_len)
	{
		grub_uint64_t container_size =
			(data->bpc_mask + 1) << data->cluster_shift;
		grub_uint32_t bitmap_bytes =
			(grub_uint32_t) ((data->bpc_mask + 1) >> 3);

		if ((data->compression_format != REFS_COMPRESSION_LZ4
				&& data->compression_format != REFS_COMPRESSION_ZSTD
				&& data->compression_format != REFS_COMPRESSION_LZ4QAT)
			|| data->compression_unit_size < data->cluster_size
			|| data->compression_unit_size > container_size
			|| (data->compression_unit_size
				& (data->compression_unit_size - 1)))
		{
			grub_error(GRUB_ERR_BAD_FS, "refs: invalid compression policy");
			goto fail;
		}
		for (i = 0; i < data->map_len; i++)
			if (grub_refs_container_is_compressed(data, data->map[i].id))
			{
				grub_uint64_t packed_size;
				grub_uint64_t range_size = 0;
				grub_uint32_t j;
				grub_uint32_t k;

				if (!data->map[i].compact_bitmap || !data->map[i].compact_rank)
					goto bad_compression_map;
				packed_size = (grub_uint64_t)
					data->map[i].compact_rank[bitmap_bytes] << data->cluster_shift;
				for (j = 0; j < data->compression_len; j++)
				{
					struct grub_refs_compression_range *a = &data->compression[j];

					if (a->container_id != data->map[i].id)
						continue;
					if (a->plain_start > packed_size
						|| a->plain_size > packed_size - a->plain_start)
						goto bad_compression_map;
					for (k = j + 1; k < data->compression_len; k++)
					{
						struct grub_refs_compression_range *b = &data->compression[k];

						if (b->container_id == a->container_id
							&& a->plain_start < b->plain_start + b->plain_size
							&& b->plain_start < a->plain_start + a->plain_size)
							goto bad_compression_map;
					}
					range_size += a->plain_size;
				}
				if (range_size != packed_size)
					goto bad_compression_map;
			}
		data->compressed_buf = grub_malloc(data->compression_unit_size);
		data->plain_buf = grub_malloc(data->compression_unit_size);
		if (!data->compressed_buf || !data->plain_buf)
			goto fail;
	}
	grub_free(tmp);
	tmp = NULL;

	if (!data->obj_table[0])
	{
		grub_error(GRUB_ERR_BAD_FS, "refs: object table not found");
		goto fail;
	}

	grub_free(node);
	grub_errno = GRUB_ERR_NONE;
	return data;

bad_compression_map:
	grub_error(GRUB_ERR_BAD_FS, "refs: corrupt compacted cluster map");

fail:
	grub_free(tmp);
	grub_free(node);
	if (data)
		grub_refs_unmount(data);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "not a ReFS filesystem");
	return NULL;
}

/*
 * $DATA attribute parsing: resident data or extent collection.
 */

/* append one 24-byte extent record (or descend into a subtree) */
static int
grub_refs_extent_hook(struct grub_refs_data *data, int is_index,
	const grub_uint8_t *key __attribute__((unused)),
	grub_uint16_t key_size __attribute__((unused)),
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	struct grub_refs_stream *st = ctx;
	grub_uint64_t disk_block, vcn, mapped, count;

	if (is_index)
	{
		/* embedded index entry -> extent subtree node */
		grub_uint64_t b[4];

		if (!grub_refs_get_ref(data, value, value_size, b))
			return 0;
		return grub_refs_walk_tree(data, b, data->extent_size,
			grub_refs_extent_hook, st);
	}

	if (value_size < data->extent_size)
		return 0;
	if (data->v1)
	{
		/* the record header is part of the raw v1 extent */
		vcn = refs_get64(value + 0x10);
		count = refs_get64(value + 0x18);
		disk_block = refs_get64(value + 0x20);
	}
	else
	{
		disk_block = refs_get64(value);
		vcn = refs_get64(value + 12);
		count = refs_get32(value + 20);
	}
	/* keep the byte arithmetic in grub_refs_read from wrapping */
	if (!disk_block || !count
		|| count > (~(grub_uint64_t) 0 >> data->cluster_shift)
		|| vcn > (~(grub_uint64_t) 0 >> data->cluster_shift) - count)
		return 0;
	mapped = grub_refs_map_block(data, disk_block);
	if (!mapped)
	{
		grub_error(GRUB_ERR_BAD_FS, "refs: unmapped file extent");
		return -1;
	}

	if (st->ext_len == st->ext_cap)
	{
		grub_uint32_t ncap = st->ext_cap ? st->ext_cap * 2 : 8;
		struct grub_refs_extent *n;

		if (st->ext_len >= REFS_MAX_EXTENTS)
		{
			grub_error(GRUB_ERR_BAD_FS, "refs: too many extents");
			return -1;
		}
		n = grub_realloc(st->ext, (grub_size_t) ncap * sizeof(st->ext[0]));
		if (!n)
			return -1;
		st->ext = n;
		st->ext_cap = ncap;
	}
	st->ext[st->ext_len].vcn = vcn;
	st->ext[st->ext_len].count = count;
	st->ext[st->ext_len].block = disk_block;
	st->ext_len++;
	return 0;
}

struct grub_refs_attr_ctx
{
	struct grub_refs_stream *st;
	int depth;	/* 1 when inside a non-resident attribute list */
};

static int
grub_refs_attr_hook(struct grub_refs_data *data, int is_index,
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	struct grub_refs_attr_ctx *c = ctx;
	grub_uint16_t tyoff = (!data->v1 && (data->version_major > 3
		|| data->version_minor >= 5)) ? 0x0C : 0x08;

	if (!value)
		return 0;

	if (is_index)
	{
		/*
		 * A record whose attribute table is an index table keeps its
		 * attributes in a separate tree; v1 uses this in place of the
		 * keyless entry below.
		 */
		struct grub_refs_attr_ctx sub;
		grub_uint64_t b[4];

		if (c->depth || !grub_refs_get_ref(data, value, value_size, b))
			return 0;
		sub.st = c->st;
		sub.depth = 1;
		return grub_refs_walk_tree(data, b, 0, grub_refs_attr_hook,
			&sub);
	}

	if (key && key_size >= (grub_uint16_t) (tyoff + 2)
		&& refs_get16(key + tyoff) == REFS_ATTR_DATA)
	{
		/* v1 has no resident data and reuses key+0x08 for the type */
		grub_uint16_t stype = (!data->v1 && key_size >= 0x0A) ?
			refs_get16(key + 0x08) : 0;

		if (stype == 0x1)
		{
			/* resident data; only valid inside the record copy */
			grub_uint64_t lsize;

			if (c->depth || value_size < 0x3C)
				return 0;
			lsize = refs_get64(value + 0x20);
			c->st->is_resident = 1;
			c->st->resident = value + 0x3C;
			c->st->resident_size =
				(grub_uint32_t) value_size - 0x3C;
			if (lsize < c->st->resident_size)
				c->st->resident_size = (grub_uint32_t) lsize;
			return 0;
		}
		else
		{
			/* non-resident: embedded extent list */
			grub_uint32_t payload = refs_get32(value);

			if (payload < 4 || payload >= value_size
				|| value_size - payload < data->table_min + 4)
				return 0;
			return grub_refs_iter_table(data, value + payload,
				(grub_uint32_t) value_size - payload,
				data->extent_size, grub_refs_extent_hook,
				c->st);
		}
	}

	if (!key_size && value_size >= 0x30 && c->depth == 0)
	{
		/* non-resident attribute list: value is a node reference */
		struct grub_refs_attr_ctx sub;
		grub_uint64_t b[4];

		if (!grub_refs_get_ref(data, value, value_size, b))
			return 0;
		sub.st = c->st;
		sub.depth = 1;
		return grub_refs_walk_tree(data, b, 0, grub_refs_attr_hook, &sub);
	}

	return 0;
}

/* collect resident data / extents from a long-entry record */
static grub_err_t
grub_refs_stream_setup(struct grub_refs_stream *st,
	const grub_uint8_t *record, grub_uint32_t record_size)
{
	struct grub_refs_attr_ctx ctx;
	grub_uint32_t basic;

	if (record_size < 2)
		return GRUB_ERR_NONE;
	basic = refs_get16(record);
	if (!basic)
		basic = 0xA8;	/* size field unset: fixed basic info size */
	if (basic < 0x10 || basic >= record_size
		|| record_size - basic < st->data->table_min + 4)
		return GRUB_ERR_NONE;	/* no attribute table: empty file */

	ctx.st = st;
	ctx.depth = 0;
	if (grub_refs_iter_table(st->data, record + basic,
		record_size - basic, 0, grub_refs_attr_hook, &ctx) < 0)
		return grub_errno;
	return GRUB_ERR_NONE;
}

struct grub_refs_reparse_ctx
{
	int depth;
	int is_link;
};

static int
grub_refs_reparse_hook(struct grub_refs_data *data, int is_index,
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	struct grub_refs_reparse_ctx *c = ctx;
	grub_uint16_t tyoff = (!data->v1 && (data->version_major > 3
		|| data->version_minor >= 5)) ? 0x0C : 0x08;

	if (is_index)
	{
		/* attributes kept in a separate tree (see the attribute hook) */
		struct grub_refs_reparse_ctx sub = { 1, 0 };
		grub_uint64_t b[4];
		int ret;

		if (c->depth || !value
			|| !grub_refs_get_ref(data, value, value_size, b))
			return 0;
		ret = grub_refs_walk_tree(data, b, 0, grub_refs_reparse_hook,
			&sub);
		if (ret < 0)
			return ret;
		if (!sub.is_link)
			return 0;
		c->is_link = 1;
		return 1;
	}
	/* refsprogs treats a generic attribute with type 0xc0 as reparse
	   data.  Its tag is at entry +0x2c; the generic value starts at
	   entry +0x20 in observed v3 records. */
	if (key && key_size >= (grub_uint16_t) (tyoff + 2)
		&& refs_get16(key + tyoff) == 0x00C0 && value_size >= 0x10)
	{
		grub_uint32_t tag = refs_get32(value + 0x0C);

		if (tag == REFS_REPARSE_MOUNT_POINT
			|| tag == REFS_REPARSE_SYMLINK
			|| tag == REFS_REPARSE_LX_SYMLINK)
		{
			c->is_link = 1;
			return 1;
		}
	}
	else if (!key_size && value && value_size >= 0x30 && c->depth == 0)
	{
		struct grub_refs_reparse_ctx sub = { 1, 0 };
		grub_uint64_t b[4];
		int ret;

		if (!grub_refs_get_ref(data, value, value_size, b))
			return 0;
		ret = grub_refs_walk_tree(data, b, 0, grub_refs_reparse_hook, &sub);
		if (ret < 0)
			return ret;
		if (sub.is_link)
		{
			c->is_link = 1;
			return 1;
		}
	}

	return 0;
}

/* A reparse-point file attribute alone does not imply a link: cloud
   placeholders, sockets and other objects use it too.  Inspect the reparse
   tag and expose only junctions and Windows/WSL symbolic links as links. */
static int
grub_refs_record_is_link(struct grub_refs_data *data,
	const grub_uint8_t *record, grub_uint32_t record_size)
{
	struct grub_refs_reparse_ctx ctx = { 0, 0 };
	grub_uint32_t basic;
	int ret;

	if (record_size < 2)
		return 0;
	basic = refs_get16(record);
	if (!basic)
		basic = 0xA8;
	if (basic < 0x10 || basic >= record_size
		|| record_size - basic < data->table_min + 4)
		return 0;
	ret = grub_refs_iter_table(data, record + basic,
		record_size - basic, 0, grub_refs_reparse_hook, &ctx);
	return ret < 0 ? -1 : ctx.is_link;
}

/* resolve a hard link (0x40 key in the parent directory tree) */
struct grub_refs_hl_ctx
{
	grub_uint64_t id;
	grub_uint64_t parent;
	grub_uint8_t *record;
	grub_uint32_t record_size;
};

static int
grub_refs_hl_hook(struct grub_refs_data *data __attribute__((unused)),
	int is_index __attribute__((unused)),
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	struct grub_refs_hl_ctx *c = ctx;

	if (key_size < 24 || !value)
		return 0;
	if (refs_get16(key) != REFS_KEY_HARDLINK
		|| refs_get64(key + 8) != c->id
		|| refs_get64(key + 16) != c->parent)
		return 0;
	c->record = grub_malloc(value_size);
	if (!c->record)
		return -1;
	grub_memcpy(c->record, value, value_size);
	c->record_size = value_size;
	return 1;
}

static grub_err_t
grub_refs_resolve_hardlink(struct grub_refs_stream *st)
{
	struct grub_refs_hl_ctx ctx;
	grub_uint64_t root[4];

	grub_memset(&ctx, 0, sizeof(ctx));
	ctx.id = st->node->hardlink_id;
	ctx.parent = st->node->oid;

	if (grub_refs_find_tree(st->data, st->node->oid, root))
		return grub_errno;
	if (grub_refs_walk_tree(st->data, root, 0, grub_refs_hl_hook, &ctx) < 0)
		return grub_errno;
	if (!ctx.record)
		return grub_error(GRUB_ERR_BAD_FS, "refs: hard link target not found");
	st->hl_record = ctx.record;
	st->hl_record_size = ctx.record_size;
	return GRUB_ERR_NONE;
}

/*
 * Directory iteration (fshelp).
 */

static char *
grub_refs_read_symlink(grub_fshelp_node_t node __attribute__((unused)))
{
	/* reparse points are exposed as regular entries */
	return NULL;
}

struct grub_refs_dirent_ctx
{
	grub_fshelp_iterate_dir_hook_t hook;
	void *hook_data;
};

static int
grub_refs_dirent_hook(struct grub_refs_data *data,
	int is_index __attribute__((unused)),
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	struct grub_refs_dirent_ctx *c = ctx;
	struct grub_fshelp_node *node;
	char *name;
	enum grub_fshelp_filetype ftype = GRUB_FSHELP_REG;
	grub_uint16_t dtype;
	grub_uint32_t name_len;
	grub_uint32_t flags;
	grub_uint64_t ft;
	int ret;

	if (key_size < 6 || !value || refs_get16(key) != REFS_KEY_DIRENT)
		return 0;
	dtype = refs_get16(key + 2);
	name_len = ((grub_uint32_t) key_size - 4) / 2;
	if (!name_len)
		return 0;

	if (dtype == REFS_DIRENT_LONG)
	{
		/* v1 keeps two extra 64-bit fields before the sizes */
		grub_uint16_t szoff = data->v1 ? 104 : 88;
		int is_link;

		/* file record with embedded attributes */
		if (value_size < szoff + 8)
			return 0;
		node = grub_zalloc(sizeof(*node) + value_size);
		if (!node)
			return -1;
		flags = refs_get32(value + 72);
		/* the timestamps are in the Write/Change/Access order. */
		ft = refs_get64(value + 48);
		node->type = REFS_NODE_REG;
		node->size = refs_get64(value + szoff);
		node->record_size = value_size;
		grub_memcpy(node->record, value, value_size);
		if (flags & REFS_FLAG_REPARSE)
		{
			is_link = grub_refs_record_is_link(data, value, value_size);
			if (is_link < 0)
			{
				grub_free(node);
				return -1;
			}
			node->reparse = is_link;
		}
	}
	else if (dtype == REFS_DIRENT_SHORT)
	{
		/* v1 has no hard link id and starts with the object id */
		grub_uint16_t oidoff = data->v1 ? 0 : 8;

		/* directory, hard link or short-form file */
		if (value_size < 72)
			return 0;
		node = grub_zalloc(sizeof(*node));
		if (!node)
			return -1;
		flags = refs_get32(value + 64);
		ft = refs_get64(value + 24);
		node->oid = refs_get64(value + oidoff);
		if (flags & REFS_FLAG_DIRECTORY)
		{
			node->type = REFS_NODE_DIR;
			ftype = GRUB_FSHELP_DIR;
		}
		else
		{
			node->hardlink_id = data->v1 ? 0 : refs_get64(value);
			node->size = refs_get64(value + 56);
			node->type = node->hardlink_id ? REFS_NODE_HARDLINK : REFS_NODE_SHORT;
		}
	}
	else
		return 0;

	node->data = data;
	node->sparse = (flags & REFS_FLAG_SPARSE) ? 1 : 0;
	node->mtime = grub_refs_filetime_to_unix(ft);

	name = grub_refs_get_utf8(key + 4, name_len);
	if (!name)
	{
		grub_free(node);
		return -1;
	}

	ret = c->hook(name, ftype | GRUB_FSHELP_CASE_INSENSITIVE, node, c->hook_data);
	grub_free(name);
	return ret;
}

static int
grub_refs_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_refs_dirent_ctx ctx = { hook, hook_data };
	grub_uint64_t root[4];

	if (dir->type != REFS_NODE_DIR)
		return 0;
	if (grub_refs_find_tree(dir->data, dir->oid, root))
		return 0;
	return grub_refs_walk_tree(dir->data, root, 0, grub_refs_dirent_hook, &ctx) > 0;
}

/* context + hook adapter for directory listing */
struct grub_refs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_refs_dir_iter(const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *data)
{
	struct grub_refs_dir_ctx *ctx = data;
	struct grub_dirhook_info info;

	grub_memset(&info, 0, sizeof(info));
	info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink = node->reparse;
	info.case_insensitive = 1;
	info.mtimeset = 1;
	info.mtime = node->mtime;
	/* Only directories carry an object id; a regular file's oid field
	   is its parent's, which would alias every file in one directory
	   into a single identity.  */
	if (info.dir)
	{
		info.inodeset = 1;
		info.inode = node->oid;
	}
	if (!info.dir && !info.symlink)
	{
		info.sizeset = 1;
		info.size = node->size;
	}
	grub_free(node);
	return ctx->hook(filename, &info, ctx->hook_data);
}

static grub_err_t
grub_refs_dir(grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_refs_dir_ctx ctx = { hook, hook_data };
	struct grub_refs_data *data;
	struct grub_fshelp_node root;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_refs_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_memset(&root, 0, sizeof(root));
	root.data = data;
	root.type = REFS_NODE_DIR;
	root.oid = REFS_OID_ROOT_DIR;

	grub_fshelp_find_file(path, &root, &fdiro, grub_refs_iterate_dir,
		grub_refs_read_symlink, GRUB_FSHELP_DIR);
	if (grub_errno)
		goto out;

	grub_refs_iterate_dir(fdiro, grub_refs_dir_iter, &ctx);

out:
	if (fdiro && fdiro != &root)
		grub_free(fdiro);
	grub_refs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_refs_open(struct grub_file *file, const char *name)
{
	struct grub_refs_data *data;
	struct grub_fshelp_node root;
	struct grub_fshelp_node *fdiro = NULL;
	struct grub_refs_stream *st = NULL;

	data = grub_refs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_memset(&root, 0, sizeof(root));
	root.data = data;
	root.type = REFS_NODE_DIR;
	root.oid = REFS_OID_ROOT_DIR;

	grub_fshelp_find_file(name, &root, &fdiro, grub_refs_iterate_dir,
		grub_refs_read_symlink, GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	st = grub_zalloc(sizeof(*st));
	if (!st)
		goto fail;
	st->data = data;
	st->node = fdiro;

	if (fdiro->type == REFS_NODE_REG)
	{
		if (grub_refs_stream_setup(st, fdiro->record, fdiro->record_size))
			goto fail;
	}
	else if (fdiro->type == REFS_NODE_HARDLINK)
	{
		grub_uint32_t flags;
		int is_link;

		if (grub_refs_resolve_hardlink(st))
			goto fail;
		if (st->hl_record_size >= 96)
		{
			fdiro->size = refs_get64(st->hl_record + 88);
			flags = refs_get32(st->hl_record + 72);
			fdiro->sparse = (flags & REFS_FLAG_SPARSE) ? 1 : 0;
			if (flags & REFS_FLAG_REPARSE)
			{
				is_link = grub_refs_record_is_link(data, st->hl_record, st->hl_record_size);
				if (is_link < 0)
					goto fail;
				fdiro->reparse = is_link;
			}
		}
		if (grub_refs_stream_setup(st, st->hl_record, st->hl_record_size))
			goto fail;
	}
	else if (fdiro->type == REFS_NODE_SHORT)
	{
		if (fdiro->size)
		{
			grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET, "refs: short-form file record not supported");
			goto fail;
		}
	}
	else
	{
		grub_error(GRUB_ERR_BAD_FILE_TYPE, "not a regular file");
		goto fail;
	}

	file->data = st;
	file->size = fdiro->size;
	return GRUB_ERR_NONE;

fail:
	if (st)
	{
		grub_free(st->ext);
		grub_free(st->hl_record);
		grub_free(st);
	}
	if (fdiro && fdiro != &root)
		grub_free(fdiro);
	grub_refs_unmount(data);
	return grub_errno;
}

static grub_ssize_t
grub_refs_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_refs_stream *st = file->data;
	struct grub_refs_data *data = st->data;
	grub_uint64_t pos = file->offset;
	grub_size_t remaining = len;
	char *p = buf;

	if (st->is_resident)
	{
		grub_size_t have = 0;

		if (pos < st->resident_size)
		{
			have = (grub_size_t) (st->resident_size - pos);
			if (have > remaining)
				have = remaining;
			grub_memcpy(p, st->resident + pos, have);
			p += have;
			remaining -= have;
		}
		if (remaining && !st->node->sparse)
		{
			grub_error(GRUB_ERR_BAD_FS, "refs: resident data shorter than file");
			return -1;
		}
		grub_memset(p, 0, remaining);
		return (grub_ssize_t) len;
	}

	while (remaining)
	{
		const struct grub_refs_extent *hit = NULL;
		grub_uint64_t next_start = ~(grub_uint64_t) 0;
		grub_uint64_t chunk;
		grub_size_t step;
		grub_uint32_t i;

		/* sequential reads usually hit the last extent or the
		   following one; fall back to a full scan (which also
		   finds the next extent past a sparse hole) */
		for (i = 0; i < 2 && st->hint + i < st->ext_len; i++)
		{
			const struct grub_refs_extent *e = &st->ext[st->hint + i];
			grub_uint64_t start = e->vcn << data->cluster_shift;
			grub_uint64_t end = start + (e->count << data->cluster_shift);

			if (pos >= start && pos < end)
			{
				hit = e;
				st->hint += i;
				break;
			}
		}
		if (!hit)
			for (i = 0; i < st->ext_len; i++)
			{
				const struct grub_refs_extent *e = &st->ext[i];
				grub_uint64_t start = e->vcn << data->cluster_shift;
				grub_uint64_t end = start + (e->count << data->cluster_shift);

				if (pos >= start && pos < end)
				{
					hit = e;
					st->hint = i;
					break;
				}
				if (start > pos && start < next_start)
					next_start = start;
			}

		if (hit)
		{
			grub_uint64_t start = hit->vcn << data->cluster_shift;
			grub_uint64_t end = start + (hit->count << data->cluster_shift);

			chunk = end - pos;
			if (chunk > remaining)
				chunk = remaining;
			step = (grub_size_t) chunk;
			if (grub_refs_read_data(data, hit->block, pos - start, step, p))
				return -1;
		}
		else
		{
			/* sparse hole (or allocation shorter than the file
			   size): zero-fill up to the next extent */
			if (!st->node->sparse)
			{
				grub_error(GRUB_ERR_BAD_FS, "refs: missing file extent");
				return -1;
			}
			chunk = remaining;
			if (next_start != ~(grub_uint64_t) 0 && next_start - pos < chunk)
				chunk = next_start - pos;
			step = (grub_size_t) chunk;
			grub_memset(p, 0, step);
		}

		p += step;
		pos += step;
		remaining -= step;
	}

	return (grub_ssize_t) len;
}

static grub_err_t
grub_refs_close(grub_file_t file)
{
	struct grub_refs_stream *st = file->data;
	struct grub_refs_data *data = st->data;

	grub_free(st->ext);
	grub_free(st->hl_record);
	grub_free(st->node);
	grub_free(st);
	grub_refs_unmount(data);
	return GRUB_ERR_NONE;
}

/* volume label: key type 0x510 in the 0x500 tree */
static int
grub_refs_label_hook(struct grub_refs_data *data __attribute__((unused)),
	int is_index __attribute__((unused)),
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	char **label = ctx;

	if (key_size < 2 || refs_get16(key) != REFS_KEY_LABEL || !value || value_size < 2)
		return 0;
	*label = grub_refs_get_utf8(value, value_size / 2);
	return 1;
}

static grub_err_t
grub_refs_label(grub_device_t device, char **label)
{
	struct grub_refs_data *data;
	grub_uint64_t root[4];

	*label = 0;
	data = grub_refs_mount(device->disk);
	if (!data)
		return grub_errno;

	if (grub_refs_find_tree(data, REFS_OID_VOLUME_INFO, root) == GRUB_ERR_NONE)
		grub_refs_walk_tree(data, root, 0, grub_refs_label_hook, label);

	/* a missing label is not an error */
	grub_errno = GRUB_ERR_NONE;
	grub_refs_unmount(data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_refs_uuid(grub_device_t device, char **uuid)
{
	grub_uint8_t bs[512];

	*uuid = 0;
	if (grub_disk_read(device->disk, 0, 0, sizeof(bs), bs))
		return grub_errno;
	if (grub_memcmp(bs + 0x3, "ReFS", 4) != 0
		|| grub_memcmp(bs + 0x10, "FSRS", 4) != 0)
		return grub_error(GRUB_ERR_BAD_FS, "not a ReFS filesystem");

	*uuid = grub_xasprintf("%016llx", (unsigned long long) refs_get64(bs + 0x38));
	return grub_errno;
}

static struct grub_fs grub_refs_fs =
{
	.name = "refs",
	.fs_dir = grub_refs_dir,
	.fs_open = grub_refs_open,
	.fs_read = grub_refs_read,
	.fs_close = grub_refs_close,
	.fs_label = grub_refs_label,
	.fs_uuid = grub_refs_uuid,
	.next = 0
};

GRUB_MOD_INIT(refs)
{
	grub_refs_fs.mod = mod;
	grub_fs_register(&grub_refs_fs);
}

GRUB_MOD_FINI(refs)
{
	grub_fs_unregister(&grub_refs_fs);
}
