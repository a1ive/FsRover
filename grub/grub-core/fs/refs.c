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
 * ReFS (Resilient File System) 3.x read-only driver.
 *
 * On-disk layout follows refsprogs (librefs\node.c):
 * boot sector -> superblock ("SUPB", block 30) -> checkpoint ("CHKP",
 * primary/secondary copy) -> level 2 tree roots.  The container table
 * (object id 0xB) maps virtual cluster numbers to physical ones (all
 * metadata below a version-dependent limit is identity mapped); the
 * object table (object id 0x2) maps directory object ids to the roots
 * of their B-trees.  Directory trees are "MSB+" nodes holding dirents
 * (key type 0x30; type 1 = file record with embedded attributes,
 * type 2 = directory / hard link), hard link target records (key type
 * 0x40) and the volume label (key type 0x510, in the 0x500 tree).
 * File data comes from the $DATA attribute: resident bytes or an
 * extent list that may overflow into subtree nodes or a separate
 * non-resident attribute list node.
 *
 * Limitations: ReFS 1.x volumes are rejected; alternate data streams,
 * reparse point targets and the rare short-form file records are not
 * supported.
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

GRUB_MOD_LICENSE("GPLv2+");

/* well-known object ids */
#define REFS_OID_OBJECT_TABLE	0x2ULL
#define REFS_OID_CONTAINERS	0xBULL
#define REFS_OID_VOLUME_INFO	0x500ULL
#define REFS_OID_ROOT_DIR	0x600ULL

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

#define REFS_SUPERBLOCK_BLOCK	30

/* v3 metadata block header */
#define REFS_NODE_HEADER_SIZE	0x50
#define REFS_NODE_SELF_BLOCKS	0x20	/* le64[4] */
#define REFS_NODE_OBJECT_ID	0x48

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
	grub_uint64_t start;
	grub_uint64_t count;
};

struct grub_refs_data
{
	grub_disk_t disk;
	grub_uint8_t version_major;
	grub_uint8_t version_minor;
	grub_uint32_t cluster_size;
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
	grub_uint64_t phys;	/* first physical cluster (mapped) */
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
	return (grub_int64_t) grub_divmod64(ft, 10000000, 0)
		- (grub_int64_t) REFS_EPOCH_BIAS;
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

/* translate a virtual cluster number through the container table */
static grub_uint64_t
grub_refs_map_block(struct grub_refs_data *data, grub_uint64_t block)
{
	grub_uint64_t want;
	grub_uint64_t base = 0;
	grub_uint32_t i;

	if (block < data->linear_limit)
		return block;

	/* index derivation as reverse engineered by refsprogs */
	want = (((block >> data->bpc_shift) >> 1) - 2) << data->bpc_shift;
	for (i = 0; i < data->map_len; i++)
	{
		if (want < base + data->map[i].count)
			return data->map[i].start | (block & data->bpc_mask);
		base += data->map[i].count;
	}
	return 0;
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
			return grub_error(GRUB_ERR_BAD_FS,
				"refs: unmapped metadata block");
		if (grub_disk_read(data->disk, 0,
			phys << data->cluster_shift, data->cluster_size,
			buf + (grub_size_t) i * data->cluster_size))
			return grub_errno;
	}

	if (grub_memcmp(buf, sig, 4) != 0
		|| refs_get64(buf + REFS_NODE_SELF_BLOCKS) != blocks[0])
		return grub_error(GRUB_ERR_BAD_FS, "refs: bad metadata node");
	return GRUB_ERR_NONE;
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

	if (avail < 0x28)
		goto corrupt;
	asize = refs_get32(table);
	is_index = (table[0xD] & 0x1) != 0;
	vo_start = refs_get32(table + 0x10);
	count = refs_get32(table + 0x14);
	vo_end = refs_get32(table + 0x20);
	if (asize < 0x24 || asize > avail || vo_start < asize
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
			if (key_off < 0x10
				|| (grub_uint32_t) key_off + key_size > esize)
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
		ret = hook(data, is_index, key, key ? key_size : 0,
			value, value ? val_size : 0, ctx);
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

		n = grub_realloc(w->queue, (grub_size_t) ncap
			* sizeof(w->queue[0]));
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

		if (value_size < 0x20)
			return 0;
		b[0] = refs_get64(value);
		b[1] = refs_get64(value + 8);
		b[2] = refs_get64(value + 16);
		b[3] = refs_get64(value + 24);
		if (!b[0])
			return 0;
		return grub_refs_walk_push(w, b) ? -1 : 0;
	}

	return w->hook(data, 0, key, key_size, value, value_size,
		w->hook_ctx);
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
		hsize = refs_get32(buf + REFS_NODE_HEADER_SIZE);
		if (hsize < 4 || hsize > data->block_size
			- REFS_NODE_HEADER_SIZE - 0x28)
		{
			grub_error(GRUB_ERR_BAD_FS, "refs: corrupt node");
			goto out;
		}
		r = grub_refs_iter_table(data,
			buf + REFS_NODE_HEADER_SIZE + hsize,
			data->block_size - REFS_NODE_HEADER_SIZE - hsize,
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
grub_refs_oid_hook(struct grub_refs_data *data __attribute__((unused)),
	int is_index __attribute__((unused)),
	const grub_uint8_t *key, grub_uint16_t key_size,
	const grub_uint8_t *value, grub_uint16_t value_size, void *ctx)
{
	struct grub_refs_oid_ctx *c = ctx;

	if (key_size < 0x10 || value_size < 0x50)
		return 0;
	if (refs_get16(key) != 0 || refs_get64(key + 8) != c->oid)
		return 0;
	/* skip the 0x20-byte value header; then a node reference */
	c->root[0] = refs_get64(value + 0x20);
	c->root[1] = refs_get64(value + 0x28);
	c->root[2] = refs_get64(value + 0x30);
	c->root[3] = refs_get64(value + 0x38);
	c->found = 1;
	return 1;
}

static grub_err_t
grub_refs_find_tree(struct grub_refs_data *data, grub_uint64_t oid,
	grub_uint64_t *root)
{
	struct grub_refs_oid_ctx c;

	grub_memset(&c, 0, sizeof(c));
	c.oid = oid;
	if (grub_refs_walk_tree(data, data->obj_table, 0, grub_refs_oid_hook,
		&c) < 0)
		return grub_errno;
	if (!c.found || !c.root[0])
		return grub_error(GRUB_ERR_BAD_FS,
			"refs: object 0x%" PRIxGRUB_UINT64_T " not found",
			oid);
	grub_memcpy(root, c.root, sizeof(c.root));
	return GRUB_ERR_NONE;
}

/* container table (0xB tree) leaf: append one mapping range */
static int
grub_refs_map_hook(struct grub_refs_data *data,
	int is_index __attribute__((unused)),
	const grub_uint8_t *key __attribute__((unused)),
	grub_uint16_t key_size __attribute__((unused)),
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

	n = grub_realloc(data->map, ((grub_size_t) data->map_len + 1)
		* sizeof(data->map[0]));
	if (!n)
		return -1;
	data->map = n;
	data->map[data->map_len].start = start;
	data->map[data->map_len].count = count;
	data->map_len++;
	return 0;
}

static void
grub_refs_unmount(struct grub_refs_data *data)
{
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

	if (bs[0x28] < 3)
	{
		grub_error(GRUB_ERR_BAD_FS, "unsupported ReFS version %u.%u",
			bs[0x28], bs[0x29]);
		goto fail;
	}

	data = grub_zalloc(sizeof(*data));
	if (!data)
		goto fail;
	data->disk = disk;
	data->version_major = bs[0x28];
	data->version_minor = bs[0x29];
	data->cluster_size = cs;
	while (((grub_uint32_t) 1 << data->cluster_shift) < cs)
		data->cluster_shift++;
	data->block_size = (cs > 16384) ? cs : 16384;
	data->chunk_count = data->block_size / cs;
	data->serial = refs_get64(bs + 0x38);
	data->linear_limit = (cs == 4096) ? 0x10000 : 0x1000;
	data->bpc_shift = (cs == 4096) ? 14 : 10;
	data->bpc_mask = ((grub_uint64_t) 1 << data->bpc_shift) - 1;

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
	l1_off = refs_get32(node + 0x70);
	l1_count = refs_get32(node + 0x74);
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
		if (grub_refs_read_node(data, cb, 1, "CHKP", node)
			== GRUB_ERR_NONE)
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
	ref_count = refs_get32(node + 0x90);
	ref_base = 0x94 + (v314 ? 5 * 4 : 0);
	if (ref_count > 64 || ref_base + ref_count * 4 > data->block_size)
	{
		grub_error(GRUB_ERR_BAD_FS, "refs: corrupt checkpoint");
		goto fail;
	}

	/*
	 * Two passes over the level 2 roots: the container table (0xB)
	 * lives in the identity-mapped region and must be found first so
	 * that the second pass can reach trees in mapped space (the
	 * object table root moves anywhere on copy-on-write).
	 */
	tmp = grub_malloc(data->block_size);
	if (!tmp)
		goto fail;
	grub_memset(containers, 0, sizeof(containers));
	for (pass = 0; pass < 2; pass++)
	{
		for (i = 0; i < ref_count; i++)
		{
			grub_uint32_t roff =
				refs_get32(node + ref_base + 4 * i);
			grub_uint64_t b[4];
			grub_uint64_t oid;
			grub_uint32_t j;

			if (roff > data->block_size
				|| data->block_size - roff < 0x30)
				continue;
			for (j = 0; j < 4; j++)
				b[j] = refs_get64(node + roff + 8 * j);
			if (!b[0])
				continue;
			if (grub_refs_read_node(data, b, 0, "MSB+", tmp))
			{
				grub_errno = GRUB_ERR_NONE;
				continue;
			}
			oid = refs_get64(tmp + REFS_NODE_OBJECT_ID);
			if (pass == 0 && oid == REFS_OID_CONTAINERS)
			{
				grub_memcpy(containers, b,
					sizeof(containers));
				break;
			}
			if (pass == 1 && oid == REFS_OID_OBJECT_TABLE)
			{
				grub_memcpy(data->obj_table, b,
					sizeof(data->obj_table));
				break;
			}
		}
		if (pass == 0 && containers[0]
			&& grub_refs_walk_tree(data, containers, 0,
				grub_refs_map_hook, NULL) < 0)
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
	grub_uint64_t disk_block, vcn, phys;
	grub_uint32_t count;

	if (is_index)
	{
		/* embedded index entry -> extent subtree node */
		grub_uint64_t b[4];

		if (value_size < 0x20)
			return 0;
		b[0] = refs_get64(value);
		b[1] = refs_get64(value + 8);
		b[2] = refs_get64(value + 16);
		b[3] = refs_get64(value + 24);
		if (!b[0])
			return 0;
		return grub_refs_walk_tree(data, b, 24,
			grub_refs_extent_hook, st);
	}

	if (value_size < 24)
		return 0;
	disk_block = refs_get64(value);
	vcn = refs_get64(value + 12);
	count = refs_get32(value + 20);
	if (!disk_block || !count)
		return 0;
	phys = grub_refs_map_block(data, disk_block);
	if (!phys)
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
		n = grub_realloc(st->ext, (grub_size_t) ncap
			* sizeof(st->ext[0]));
		if (!n)
			return -1;
		st->ext = n;
		st->ext_cap = ncap;
	}
	st->ext[st->ext_len].vcn = vcn;
	st->ext[st->ext_len].count = count;
	st->ext[st->ext_len].phys = phys;
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
	grub_uint16_t tyoff = (data->version_major > 3
		|| data->version_minor >= 5) ? 0x0C : 0x08;

	if (is_index || !value)
		return 0;

	if (key && key_size >= (grub_uint16_t) (tyoff + 2)
		&& refs_get16(key + tyoff) == REFS_ATTR_DATA)
	{
		grub_uint16_t stype = (key_size >= 0x0A) ?
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
				|| value_size - payload < 0x28)
				return 0;
			return grub_refs_iter_table(data, value + payload,
				(grub_uint32_t) value_size - payload, 24,
				grub_refs_extent_hook, c->st);
		}
	}

	if (!key_size && value_size >= 0x30 && c->depth == 0)
	{
		/* non-resident attribute list: value is a node reference */
		struct grub_refs_attr_ctx sub;
		grub_uint64_t b[4];

		b[0] = refs_get64(value);
		b[1] = refs_get64(value + 8);
		b[2] = refs_get64(value + 16);
		b[3] = refs_get64(value + 24);
		if (!b[0])
			return 0;
		sub.st = c->st;
		sub.depth = 1;
		return grub_refs_walk_tree(data, b, 0, grub_refs_attr_hook,
			&sub);
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
		|| record_size - basic < 0x28)
		return GRUB_ERR_NONE;	/* no attribute table: empty file */

	ctx.st = st;
	ctx.depth = 0;
	if (grub_refs_iter_table(st->data, record + basic,
		record_size - basic, 0, grub_refs_attr_hook, &ctx) < 0)
		return grub_errno;
	return GRUB_ERR_NONE;
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
	if (grub_refs_walk_tree(st->data, root, 0, grub_refs_hl_hook,
		&ctx) < 0)
		return grub_errno;
	if (!ctx.record)
		return grub_error(GRUB_ERR_BAD_FS,
			"refs: hard link target not found");
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
		/* file record with embedded attributes */
		if (value_size < 96)
			return 0;
		node = grub_zalloc(sizeof(*node) + value_size);
		if (!node)
			return -1;
		flags = refs_get32(value + 72);
		ft = refs_get64(value + 48);
		node->type = REFS_NODE_REG;
		node->size = refs_get64(value + 88);
		node->record_size = value_size;
		grub_memcpy(node->record, value, value_size);
	}
	else if (dtype == REFS_DIRENT_SHORT)
	{
		/* directory, hard link or short-form file */
		if (value_size < 72)
			return 0;
		node = grub_zalloc(sizeof(*node));
		if (!node)
			return -1;
		flags = refs_get32(value + 64);
		ft = refs_get64(value + 24);
		if (flags & REFS_FLAG_DIRECTORY)
		{
			node->type = REFS_NODE_DIR;
			node->oid = refs_get64(value + 8);
			ftype = GRUB_FSHELP_DIR;
		}
		else
		{
			node->hardlink_id = refs_get64(value);
			node->oid = refs_get64(value + 8);
			node->size = refs_get64(value + 56);
			node->type = node->hardlink_id ?
				REFS_NODE_HARDLINK : REFS_NODE_SHORT;
		}
	}
	else
		return 0;

	node->data = data;
	node->reparse = (flags & REFS_FLAG_REPARSE) ? 1 : 0;
	node->mtime = grub_refs_filetime_to_unix(ft);

	name = grub_refs_get_utf8(key + 4, name_len);
	if (!name)
	{
		grub_free(node);
		return -1;
	}

	ret = c->hook(name, ftype | GRUB_FSHELP_CASE_INSENSITIVE, node,
		c->hook_data);
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
	return grub_refs_walk_tree(dir->data, root, 0,
		grub_refs_dirent_hook, &ctx) > 0;
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
		if (grub_refs_stream_setup(st, fdiro->record,
			fdiro->record_size))
			goto fail;
	}
	else if (fdiro->type == REFS_NODE_HARDLINK)
	{
		if (grub_refs_resolve_hardlink(st))
			goto fail;
		if (st->hl_record_size >= 96)
			fdiro->size = refs_get64(st->hl_record + 88);
		if (grub_refs_stream_setup(st, st->hl_record,
			st->hl_record_size))
			goto fail;
	}
	else if (fdiro->type == REFS_NODE_SHORT)
	{
		if (fdiro->size)
		{
			grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
				"refs: short-form file record not supported");
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
		/* pad a size mismatch with zeroes */
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
			const struct grub_refs_extent *e =
				&st->ext[st->hint + i];
			grub_uint64_t start = e->vcn << data->cluster_shift;
			grub_uint64_t end = start
				+ (e->count << data->cluster_shift);

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
				grub_uint64_t start =
					e->vcn << data->cluster_shift;
				grub_uint64_t end = start
					+ (e->count << data->cluster_shift);

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
			grub_uint64_t end = start
				+ (hit->count << data->cluster_shift);

			chunk = end - pos;
			if (chunk > remaining)
				chunk = remaining;
			step = (grub_size_t) chunk;
			if (grub_disk_read(data->disk, 0,
				(hit->phys << data->cluster_shift)
				+ (pos - start), step, p))
				return -1;
		}
		else
		{
			/* sparse hole (or allocation shorter than the file
			   size): zero-fill up to the next extent */
			chunk = remaining;
			if (next_start != ~(grub_uint64_t) 0
				&& next_start - pos < chunk)
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

	if (key_size < 2 || refs_get16(key) != REFS_KEY_LABEL
		|| !value || value_size < 2)
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

	if (grub_refs_find_tree(data, REFS_OID_VOLUME_INFO, root)
		== GRUB_ERR_NONE)
		grub_refs_walk_tree(data, root, 0, grub_refs_label_hook,
			label);

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

	*uuid = grub_xasprintf("%016llx",
		(unsigned long long) refs_get64(bs + 0x38));
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
