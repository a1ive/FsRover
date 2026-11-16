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
 * Read-only bcachefs.  The btree walk started from Meridian's fsw_bcachefs
 * (GPL-3.0-or-later, Abdelkader Boudih); layouts were checked against
 * bcachefs-tools' format definitions.
 *
 * Only cleanly unmounted, unencrypted filesystems are read: the btree roots
 * come from the superblock's clean section and the journal is not replayed.
 * Replicas on other visible member devices can supply metadata and data.
 *
 * Btree nodes are logs of sorted bsets; a node is read whole, its bsets
 * merged (a later bset wins at the same position) and cached.  Keys of the
 * snapshotted btrees are resolved for one snapshot at a time: at each
 * position the visible key is the one of the nearest ancestor snapshot, and
 * a whiteout there hides the position.
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/filemap.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/device.h>
#include <grub/fshelp.h>
#include <grub/deflate.h>
#include <grub/safemath.h>

#include <lz4.h>
#include <zstd.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define BCH_SECTOR_BITS		9
#define BCH_SECTOR_SIZE		512
#define BCH_SB_SECTOR		8
#define BCH_SB_LAYOUT_SECTOR	7
#define BCH_SB_HEAD_SIZE	752
#define BCH_SB_MAX_SIZE		(1U << 20)
#define BCH_SB_LAYOUT_MAX	61
/* 0.14, btree_ptr_sectors_written: the oldest version bcachefs reads */
#define BCH_VERSION_MIN		14

#define BCH_SB_FIELD_CLEAN	6
#define BCH_SB_FIELD_EXTENT_TYPE_U64S	16
#define BCH_JSET_ENTRY_BTREE_ROOT	1

#define BCH_BTREE_EXTENTS	0
#define BCH_BTREE_INODES	1
#define BCH_BTREE_DIRENTS	2
#define BCH_BTREE_XATTRS	3
#define BCH_BTREE_REFLINK	7
#define BCH_BTREE_SUBVOLUMES	8
#define BCH_BTREE_SNAPSHOTS	9
#define BCH_BTREE_NR		10
#define BCH_BTREE_MAX_DEPTH	4

#define BCH_KEY_DELETED		0
#define BCH_KEY_WHITEOUT	1
#define BCH_KEY_ERROR		2
#define BCH_KEY_COOKIE		3
#define BCH_KEY_HASH_WHITEOUT	4
#define BCH_KEY_BTREE_PTR	5
#define BCH_KEY_EXTENT		6
#define BCH_KEY_RESERVATION	7
#define BCH_KEY_INODE		8
#define BCH_KEY_DIRENT		10
#define BCH_KEY_REFLINK_P	15
#define BCH_KEY_REFLINK_V	16
#define BCH_KEY_INLINE_DATA	17
#define BCH_KEY_BTREE_PTR_V2	18
#define BCH_KEY_INDIRECT_INLINE	19
#define BCH_KEY_SUBVOLUME	21
#define BCH_KEY_SNAPSHOT	22
#define BCH_KEY_INODE_V2	23
#define BCH_KEY_INODE_V3	29
#define BCH_KEY_EXTENT_WHITEOUT	36
#define BCH_KEY_INLINE_DATA_V2	40
#define BCH_KEY_INDIRECT_INLINE_V2	41

#define BCH_KEY_FORMAT_LOCAL	0
#define BCH_KEY_FORMAT_CURRENT	1
#define BCH_BKEY_BYTES		40
#define BCH_BKEY_FIELDS		6
#define BCH_VAL_MAX		2048

#define BCH_EXTENT_PTR		0
#define BCH_EXTENT_CRC32	1
#define BCH_EXTENT_CRC64	2
#define BCH_EXTENT_CRC128	3
#define BCH_EXTENT_FLAGS		6
#define BCH_EXTENT_POISONED	(1ULL << 7)
#define BCH_INLINE_POISONED	1
#define BCH_EXTENT_TYPES_KNOWN	9
#define BCH_EXTENT_TYPES_MAX	31

#define BCH_COMPRESSION_NONE	0
#define BCH_COMPRESSION_LZ4_OLD	1
#define BCH_COMPRESSION_GZIP	2
#define BCH_COMPRESSION_LZ4	3
#define BCH_COMPRESSION_ZSTD	4
#define BCH_COMPRESSION_INCOMPRESSIBLE	5
#define BCH_CSUM_CHACHA20_POLY1305_80	3
#define BCH_CSUM_CHACHA20_POLY1305_128	4

#define BCH_ROOT_SUBVOL		1
#define BCH_ROOT_INO		4096
#define BCH_SNAPSHOT_MAX	0xffffffffU
#define BCH_DT_DIR		4
#define BCH_DT_REG		8
#define BCH_DT_LNK		10
#define BCH_DT_SUBVOL		16
#define BCH_NAME_MAX		512

/* BCH_SB_MEMBER_INVALID: a placeholder pointer's device */
#define BCH_DEV_INVALID		255

#define BCH_NODE_CACHE		16
#define BCH_NODE_SECTORS_MAX	4096
#define BCH_EXTENT_SECTORS_MAX	8192
#define BCH_SNAPSHOTS_MAX	(1U << 20)
#define BCH_SYMLINK_MAX		65536

#define BCH_S_IFMT		0170000
#define BCH_S_IFDIR		0040000
#define BCH_S_IFLNK		0120000

static const grub_uint8_t bch_magic[16] = {
	0xc6, 0x85, 0x73, 0xf6, 0x66, 0xce, 0x90, 0xa9,
	0xd9, 0x6a, 0x60, 0xcf, 0x80, 0x3d, 0xf7, 0xef
};

/* bcache's magic, which old bcachefs superblocks still carry */
static const grub_uint8_t bch_magic_old[16] = {
	0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca,
	0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81
};

#define BCH_BSET_MAGIC		0x90135c78b99e07f5ULL

/* Sizes of the extent entry types this driver knows, in bytes. */
static const grub_uint8_t bch_entry_bytes[BCH_EXTENT_TYPES_KNOWN] = {
	8, 8, 16, 24, 8, 8, 8, 8, 8
};

struct bch_pos
{
	grub_uint64_t inode;
	grub_uint64_t offset;
	grub_uint32_t snapshot;
};

/* A key and a copy of its value. */
struct bch_kv
{
	struct bch_pos p;
	grub_uint32_t size;
	grub_uint32_t len;
	grub_uint8_t type;
	grub_uint8_t val[BCH_VAL_MAX];
};

/* A key of a cached node, its value left in the node buffer. */
struct bch_nkey
{
	struct bch_pos p;
	grub_uint32_t size;
	grub_uint32_t val;
	grub_uint16_t len;
	grub_uint8_t type;
};

struct bch_format
{
	grub_uint8_t key_u64s;
	grub_uint8_t bits[BCH_BKEY_FIELDS];
	grub_uint64_t offset[BCH_BKEY_FIELDS];
};

struct bch_bptr
{
	grub_uint64_t sector;
	grub_uint64_t seq;
	grub_uint32_t sectors;
	grub_uint8_t dev;
	int v2;
	int range_updated;
	struct bch_pos min;
	struct bch_pos max;
};

struct bch_node
{
	struct bch_bptr ptr;
	unsigned btree;
	unsigned level;
	grub_uint64_t used;
	grub_uint8_t *buf;
	struct bch_nkey *keys;
	grub_size_t nkeys;
	int valid;
};

struct bch_root
{
	int alive;
	unsigned level;
	struct bch_bptr ptr;
};

struct bch_snap
{
	grub_uint32_t id;
	grub_uint32_t parent;
};

/* The pointer an extent is read through, and the crc entry before it. */
struct bch_dptr
{
	grub_uint64_t offset;
	grub_uint8_t dev;
	int poisoned;
	int unwritten;
	int has_crc;
	grub_uint32_t csize;
	grub_uint32_t usize;
	grub_uint32_t coffset;
	grub_uint8_t csum_type;
	grub_uint8_t ctype;
};

enum bch_seg_kind
{
	BCH_SEG_HOLE,
	BCH_SEG_ZERO,
	BCH_SEG_UNWRITTEN,
	BCH_SEG_DISK,
	BCH_SEG_COMP,
	BCH_SEG_INLINE,
	BCH_SEG_ERROR
};

/* File sectors [start, end) and where their data is. */
struct bch_seg
{
	grub_uint64_t start;
	grub_uint64_t end;
	enum bch_seg_kind kind;
	int shared;
	/* DISK, UNWRITTEN: byte address of START */
	grub_uint64_t disk;
	/* COMP: decoded byte offset of START; INLINE: data byte offset of START */
	grub_uint64_t dec;
	struct bch_dptr dp;
	/* INLINE: the data, in kv.val */
	grub_uint32_t inl_off;
	grub_uint32_t inl_len;
	struct bch_kv kv;
};

struct bch_inode
{
	grub_uint16_t mode;
	grub_uint64_t size;
	grub_uint64_t mtime;
};

struct grub_bcachefs_data;

struct grub_fshelp_node
{
	struct grub_bcachefs_data *data;
	grub_uint64_t inum;
	grub_uint32_t subvol;
	grub_uint32_t snapshot;
	int inode_read;
	struct bch_inode inode;
};

struct grub_bcachefs_data
{
	grub_disk_t disk;
	/* the other member devices, found on first use */
	grub_device_t members[BCH_DEV_INVALID];
	int scanned;
	grub_uint8_t uuid[16];
	grub_uint8_t user_uuid[16];
	char label[33];
	grub_uint8_t dev_idx;
	grub_uint32_t block_bytes;
	grub_uint32_t node_sectors;
	grub_uint64_t bset_magic;
	grub_uint64_t time_base;
	grub_uint32_t time_precision;
	grub_uint64_t write_time;
	grub_uint8_t entry_bytes[BCH_EXTENT_TYPES_MAX];
	struct bch_root roots[BCH_BTREE_NR];
	struct bch_snap *snaps;
	grub_size_t nsnaps;
	struct bch_node cache[BCH_NODE_CACHE];
	grub_uint64_t clock;
	/* the last extent decompressed */
	grub_uint8_t *dc_buf;
	grub_uint64_t dc_sector;
	grub_uint8_t dc_dev;
	grub_uint32_t dc_csize;
	grub_uint32_t dc_usize;
	grub_uint8_t dc_type;
	int dc_valid;
	struct grub_fshelp_node root;
	struct grub_fshelp_node file;
};

static inline grub_uint16_t
bch_le16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) (p[0] | (p[1] << 8));
}

static inline grub_uint32_t
bch_le32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8) |
		((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

static inline grub_uint64_t
bch_le64 (const grub_uint8_t *p)
{
	return bch_le32 (p) | ((grub_uint64_t) bch_le32 (p + 4) << 32);
}

static unsigned
bch_ctz64 (grub_uint64_t v)
{
	unsigned n = 0;

	while (n < 64 && !(v & 1))
	{
		v >>= 1;
		n++;
	}
	return n;
}

static int
bch_pos_cmp (const struct bch_pos *a, const struct bch_pos *b)
{
	if (a->inode != b->inode)
		return a->inode < b->inode ? -1 : 1;
	if (a->offset != b->offset)
		return a->offset < b->offset ? -1 : 1;
	if (a->snapshot != b->snapshot)
		return a->snapshot < b->snapshot ? -1 : 1;
	return 0;
}

static struct bch_pos
bch_pos_make (grub_uint64_t inode, grub_uint64_t offset, grub_uint32_t snapshot)
{
	struct bch_pos p;

	p.inode = inode;
	p.offset = offset;
	p.snapshot = snapshot;
	return p;
}

static struct bch_pos
bch_pos_read (const grub_uint8_t *p)
{
	return bch_pos_make (bch_le64 (p + 12), bch_le64 (p + 4), bch_le32 (p));
}

/* The position after P; 0 if P is the last one. */
static int
bch_pos_next (const struct bch_pos *p, struct bch_pos *out)
{
	*out = *p;
	if (out->snapshot != BCH_SNAPSHOT_MAX)
	{
		out->snapshot++;
		return 1;
	}
	out->snapshot = 0;
	if (out->offset != ~(grub_uint64_t) 0)
	{
		out->offset++;
		return 1;
	}
	out->offset = 0;
	if (out->inode != ~(grub_uint64_t) 0)
	{
		out->inode++;
		return 1;
	}
	return 0;
}

/* The first position of the offset after P's, whatever its snapshot. */
static int
bch_pos_next_offset (const struct bch_pos *p, struct bch_pos *out)
{
	struct bch_pos last = *p;

	last.snapshot = BCH_SNAPSHOT_MAX;
	return bch_pos_next (&last, out);
}

static int
bch_is_whiteout (grub_uint8_t type)
{
	return type == BCH_KEY_DELETED || type == BCH_KEY_WHITEOUT ||
		type == BCH_KEY_HASH_WHITEOUT || type == BCH_KEY_EXTENT_WHITEOUT;
}

static int
bch_btree_has_snapshots (unsigned btree)
{
	return btree == BCH_BTREE_EXTENTS || btree == BCH_BTREE_INODES ||
		btree == BCH_BTREE_DIRENTS || btree == BCH_BTREE_XATTRS;
}

static grub_err_t
bch_corrupt (const char *what)
{
	return grub_error (GRUB_ERR_BAD_FS, "bcachefs: corrupted %s", what);
}

/* Finds a superblock's fixed part: at its default sector, else where the
   layout sector says the copies are. */
static grub_err_t
bch_find_sb (grub_disk_t disk, grub_uint8_t *head, grub_uint64_t *sector)
{
	grub_uint8_t layout[BCH_SECTOR_SIZE];
	unsigned i = 0, nr = 0;

	*sector = BCH_SB_SECTOR;
	for (;;)
	{
		if (grub_disk_read (disk, *sector, 0, BCH_SB_HEAD_SIZE, head) == GRUB_ERR_NONE &&
			(!grub_memcmp (head + 24, bch_magic, 16) || !grub_memcmp (head + 24, bch_magic_old, 16)) &&
			/* bcache has a 64-bit version and shares the old magic. */
			(grub_memcmp (head + 24, bch_magic_old, 16) || bch_le64 (head + 16) > 6) &&
			bch_le64 (head + 104) == *sector)
			return GRUB_ERR_NONE;
		grub_errno = GRUB_ERR_NONE;
		if (!i)
		{
			if (grub_disk_read (disk, BCH_SB_LAYOUT_SECTOR, 0, sizeof (layout), layout))
				break;
			if (grub_memcmp (layout, bch_magic, 16) && grub_memcmp (layout, bch_magic_old, 16))
				break;
			nr = grub_min (layout[18], BCH_SB_LAYOUT_MAX);
		}
		if (i >= nr)
			break;
		*sector = bch_le64 (layout + 24 + i * 8);
		i++;
	}
	return grub_error (GRUB_ERR_BAD_FS, "not a bcachefs filesystem");
}

/* Keeps open each device holding another member of this filesystem. */
static int
bch_scan_iter (const char *name, void *ctx)
{
	struct grub_bcachefs_data *data = ctx;
	grub_uint8_t head[BCH_SB_HEAD_SIZE];
	grub_uint64_t sector;
	grub_device_t dev;
	unsigned idx;

	dev = grub_device_open (name);
	if (!dev)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	if (!dev->disk || bch_find_sb (dev->disk, head, &sector) ||
		grub_memcmp (head + 40, data->uuid, 16))
		goto skip;
	idx = head[122];
	if (idx == data->dev_idx || idx >= BCH_DEV_INVALID || data->members[idx])
		goto skip;
	data->members[idx] = dev;
	return 0;

skip:
	grub_errno = GRUB_ERR_NONE;
	grub_device_close (dev);
	return 0;
}

/* The local replica can be selected without enumerating host devices. */
static int
bch_member_available (struct grub_bcachefs_data *data, grub_uint8_t dev)
{
	if (dev == BCH_DEV_INVALID)
		return 0;
	if (dev == data->dev_idx)
		return 1;
	if (!data->members[dev] && !data->scanned)
	{
		data->scanned = 1;
		grub_device_iterate (bch_scan_iter, data);
		grub_errno = GRUB_ERR_NONE;
	}
	return data->members[dev] != NULL;
}

/* The disk of member device DEV. */
static grub_disk_t
bch_member_disk (struct grub_bcachefs_data *data, grub_uint8_t dev)
{
	if (bch_member_available (data, dev))
		return dev == data->dev_idx ? data->disk : data->members[dev]->disk;
	grub_error (GRUB_ERR_BAD_FS, "bcachefs: member device %u is not available", dev);
	return NULL;
}

/*
 * Packed keys: the fields, each its node format's width and less its
 * offset, run from the top of the key's last word downward.
 */
static int
bch_unpack_key (const struct bch_format *f, const grub_uint8_t *k,
	grub_uint32_t u64s, struct bch_nkey *out, grub_uint32_t *key_bytes)
{
	grub_uint64_t v[BCH_BKEY_FIELDS];
	grub_uint64_t w;
	unsigned left = 64;
	unsigned i;
	int word;

	switch (k[1] & 0x7f)
	{
	case BCH_KEY_FORMAT_CURRENT:
		if (u64s * 8 < BCH_BKEY_BYTES)
			return 0;
		out->size = bch_le32 (k + 16);
		out->p.snapshot = bch_le32 (k + 20);
		out->p.offset = bch_le64 (k + 24);
		out->p.inode = bch_le64 (k + 32);
		*key_bytes = BCH_BKEY_BYTES;
		return 1;
	case BCH_KEY_FORMAT_LOCAL:
		break;
	default:
		return 0;
	}

	if (u64s < f->key_u64s)
		return 0;
	word = f->key_u64s - 1;
	w = bch_le64 (k + word * 8);
	for (i = 0; i < BCH_BKEY_FIELDS; i++)
	{
		unsigned bits = f->bits[i];
		grub_uint64_t x = 0;

		if (bits >= left)
		{
			x = w >> (64 - bits);
			bits -= left;
			word--;
			w = word >= 0 ? bch_le64 (k + word * 8) : 0;
			left = 64;
		}
		x |= (w >> 1) >> (63 - bits);
		w <<= bits;
		left -= bits;
		v[i] = x + f->offset[i];
	}
	out->p.inode = v[0];
	out->p.offset = v[1];
	out->p.snapshot = (grub_uint32_t) v[2];
	out->size = (grub_uint32_t) v[3];
	*key_bytes = (grub_uint32_t) f->key_u64s * 8;
	return 1;
}

/* A btree pointer's range and an available replica, preferring this device. */
static grub_err_t
bch_btree_ptr (struct grub_bcachefs_data *data, grub_uint8_t type,
	const grub_uint8_t *val, grub_uint32_t len, const struct bch_pos *max,
	struct bch_bptr *out)
{
	grub_uint32_t start, pos;
	grub_uint32_t written = 0;
	unsigned pass;
	int have = 0, fallback = 0;

	grub_memset (out, 0, sizeof (*out));
	out->max = *max;
	if (type == BCH_KEY_BTREE_PTR_V2)
	{
		if (len < 40)
			return bch_corrupt ("btree pointer");
		written = bch_le16 (val + 16);
		out->v2 = 1;
		out->seq = bch_le64 (val + 8);
		out->range_updated = bch_le16 (val + 18) & 1;
		out->min = bch_pos_read (val + 20);
		if (bch_pos_cmp (&out->min, &out->max) > 0)
			return bch_corrupt ("btree pointer range");
		start = 40;
	}
	else if (type == BCH_KEY_BTREE_PTR)
		start = 0;
	else
		return bch_corrupt ("btree pointer");

	/* Scan remote members only when the key has no local replica. */
	for (pass = 0; pass < 2 && !have; pass++)
	{
		pos = start;
		while (pos + 8 <= len)
		{
			grub_uint64_t w = bch_le64 (val + pos);
			unsigned t = bch_ctz64 (w);

			if (t >= BCH_EXTENT_TYPES_MAX || !data->entry_bytes[t] ||
				pos + data->entry_bytes[t] > len)
				return bch_corrupt ("btree pointer entry");
			if (t == BCH_EXTENT_FLAGS && (w & BCH_EXTENT_POISONED))
				return grub_error (GRUB_ERR_READ_ERROR, "bcachefs: btree pointer is marked poisoned");
			if (t == BCH_EXTENT_PTR && !have)
			{
				grub_uint8_t dev = (grub_uint8_t) (w >> 48);

				if (dev != BCH_DEV_INVALID && !(w & 2))
				{
					have = pass ? bch_member_available (data, dev) : dev == data->dev_idx;
					if (!fallback || have)
					{
						out->sector = (w >> 4) & ((1ULL << 44) - 1);
						out->dev = dev;
						fallback = 1;
					}
				}
			}
			pos += data->entry_bytes[t];
		}
		if (pos != len)
			return bch_corrupt ("btree pointer entry");
	}
	/* An unavailable root need not be read; defer its error until traversal. */
	if (!fallback)
		return grub_error (GRUB_ERR_BAD_FS, "bcachefs: no usable btree replica");
	out->sectors = written ? written : data->node_sectors;
	if (out->sectors > data->node_sectors)
		return bch_corrupt ("btree pointer");
	return GRUB_ERR_NONE;
}

static void
bch_node_free (struct bch_node *node)
{
	grub_free (node->buf);
	grub_free (node->keys);
	node->buf = NULL;
	node->keys = NULL;
	node->nkeys = 0;
	node->valid = 0;
}

/* Sorts KEYS by position, stable: a bset is sorted unless its whiteouts
   were kept apart, as old versions did. */
static void
bch_sort_keys (struct bch_nkey *keys, grub_size_t n)
{
	grub_size_t i, j;

	for (i = 1; i < n; i++)
	{
		struct bch_nkey k = keys[i];

		for (j = i; j > 0 && bch_pos_cmp (&keys[j - 1].p, &k.p) > 0; j--)
			keys[j] = keys[j - 1];
		keys[j] = k;
	}
}

/* Merges the sorted bset B into the node's keys A: B is newer and wins at
   the same position. */
static struct bch_nkey *
bch_merge_keys (struct bch_nkey *a, grub_size_t na, struct bch_nkey *b,
	grub_size_t nb, grub_size_t *nout)
{
	struct bch_nkey *out;
	grub_size_t i = 0, j = 0, n = 0;

	out = grub_calloc (na + nb ? na + nb : 1, sizeof (*out));
	if (!out)
		return NULL;
	while (i < na && j < nb)
	{
		int c = bch_pos_cmp (&a[i].p, &b[j].p);

		if (c < 0)
			out[n++] = a[i++];
		else
		{
			if (!c)
				i++;
			out[n++] = b[j++];
		}
	}
	while (i < na)
		out[n++] = a[i++];
	while (j < nb)
		out[n++] = b[j++];
	*nout = n;
	return out;
}

static grub_err_t
bch_parse_node (struct grub_bcachefs_data *data, struct bch_node *node,
	const struct bch_bptr *ptr, unsigned btree, unsigned level)
{
	const grub_uint8_t *b = node->buf;
	grub_uint32_t sectors = ptr->sectors;
	grub_uint32_t bytes = sectors << BCH_SECTOR_BITS;
	struct bch_pos min, max;
	struct bch_format f;
	struct bch_nkey *keys = NULL;
	struct bch_nkey *set = NULL;
	grub_size_t nkeys = 0;
	grub_uint64_t seq, node_flags;
	grub_uint32_t off = 0;
	grub_size_t i, n;

	if (bytes < 160 || bch_le64 (b + 16) != data->bset_magic)
	{
		bch_corrupt ("btree node header");
		goto fail;
	}
	node_flags = bch_le64 (b + 24);
	if (((node_flags >> 4) & 0xf) != level ||
		((node_flags & 0xf) | (((node_flags >> 9) & 0xffff) << 4)) != btree)
	{
		bch_corrupt ("btree node identity");
		goto fail;
	}
	min = bch_pos_read (b + 32);
	max = bch_pos_read (b + 52);
	seq = bch_le64 (b + 136);
	if ((ptr->v2 && seq != ptr->seq) ||
		(!ptr->range_updated && (bch_pos_cmp (&max, &ptr->max) ||
			(ptr->v2 && bch_pos_cmp (&min, &ptr->min)))))
	{
		bch_corrupt ("btree node pointer");
		goto fail;
	}
	if (ptr->range_updated)
	{
		min = ptr->min;
		max = ptr->max;
	}
	if (bch_pos_cmp (&min, &max) > 0)
	{
		bch_corrupt ("btree node range");
		goto fail;
	}
	f.key_u64s = b[80];
	if (!f.key_u64s || f.key_u64s * 8 > BCH_BKEY_BYTES || b[81] != BCH_BKEY_FIELDS)
	{
		bch_corrupt ("btree node key format");
		goto fail;
	}
	for (i = 0; i < BCH_BKEY_FIELDS; i++)
	{
		f.bits[i] = b[82 + i];
		f.offset[i] = bch_le64 (b + 88 + i * 8);
		if (f.bits[i] > 64)
		{
			bch_corrupt ("btree node key format");
			goto fail;
		}
	}
	while (off < sectors)
	{
		grub_uint32_t hdr = off << BCH_SECTOR_BITS;
		grub_uint32_t bset, start, end, p, flags;
		grub_uint32_t step;
		int sorted = 1;
		struct bch_nkey *merged;

		if (!off)
		{
			bset = 136;
			start = 160;
		}
		else
		{
			if (hdr + 40 > bytes)
				break;
			bset = hdr + 16;
			start = hdr + 40;
			if (bch_le64 (b + bset) != seq)
				break;
		}
		flags = bch_le32 (b + bset + 16);
		if ((flags >> 4) & 1)
		{
			grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: big-endian btree nodes are not supported");
			goto fail;
		}
		if ((flags & 0xf) == BCH_CSUM_CHACHA20_POLY1305_80 || (flags & 0xf) == BCH_CSUM_CHACHA20_POLY1305_128)
		{
			grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: encrypted btree nodes are not supported");
			goto fail;
		}
		end = start + ((grub_uint32_t) bch_le16 (b + bset + 22) << 3);
		if (end > bytes)
		{
			if (!off)
			{
				bch_corrupt ("btree node");
				goto fail;
			}
			break;
		}

		set = grub_calloc ((end - start) / 8 + 1, sizeof (*set));
		if (!set)
			goto fail;
		n = 0;
		for (p = start; p < end;)
		{
			grub_uint32_t u64s = b[p];
			grub_uint32_t kbytes;
			struct bch_nkey *k = &set[n];

			/* a key that doesn't fit ends the bset, as bcachefs truncates it */
			if (!u64s || p + u64s * 8 > end)
				break;
			if (!bch_unpack_key (&f, b + p, u64s, k, &kbytes))
			{
				bch_corrupt ("btree key");
				goto fail;
			}
			k->type = b[p + 2];
			k->val = p + kbytes;
			k->len = (grub_uint16_t) (u64s * 8 - kbytes);
			if (n && bch_pos_cmp (&set[n - 1].p, &k->p) >= 0)
				sorted = 0;
			n++;
			p += u64s * 8;
		}
		if (!sorted)
		{
			grub_size_t d = 0;

			bch_sort_keys (set, n);
			for (i = 0; i < n; i++)
			{
				if (d && !bch_pos_cmp (&set[d - 1].p, &set[i].p))
					d--;
				set[d++] = set[i];
			}
			n = d;
		}
		merged = bch_merge_keys (keys, nkeys, set, n, &nkeys);
		if (!merged)
			goto fail;
		grub_free (keys);
		grub_free (set);
		keys = merged;
		set = NULL;

		step = ALIGN_UP (end - hdr, data->block_bytes) >> BCH_SECTOR_BITS;
		if (!step)
			break;
		off += step;
	}

	/* Keys outside the node's range are dropped, as bcachefs does: topology
	   repair can shrink a node without rewriting its bsets. */
	for (i = 0, n = 0; i < nkeys; i++)
		if (bch_pos_cmp (&keys[i].p, &min) >= 0 && bch_pos_cmp (&keys[i].p, &max) <= 0 &&
			keys[i].type != BCH_KEY_DELETED)
			keys[n++] = keys[i];
	node->keys = keys;
	node->nkeys = n;
	return GRUB_ERR_NONE;

fail:
	grub_free (set);
	grub_free (keys);
	return grub_errno;
}

static struct bch_node *
bch_get_node (struct grub_bcachefs_data *data, const struct bch_bptr *ptr,
	unsigned btree, unsigned level)
{
	struct bch_node *node = NULL;
	grub_disk_t disk;
	unsigned i;

	for (i = 0; i < BCH_NODE_CACHE; i++)
	{
		struct bch_node *c = &data->cache[i];

		if (c->valid && c->ptr.sector == ptr->sector && c->ptr.dev == ptr->dev &&
			c->ptr.sectors == ptr->sectors && c->ptr.seq == ptr->seq &&
			c->ptr.v2 == ptr->v2 && c->ptr.range_updated == ptr->range_updated &&
			!bch_pos_cmp (&c->ptr.min, &ptr->min) && !bch_pos_cmp (&c->ptr.max, &ptr->max) &&
			c->btree == btree && c->level == level)
		{
			c->used = ++data->clock;
			return c;
		}
		if (!node || !c->valid || (node->valid && c->used < node->used))
			node = c;
	}

	bch_node_free (node);
	disk = bch_member_disk (data, ptr->dev);
	if (!disk)
		return NULL;
	node->buf = grub_malloc ((grub_size_t) ptr->sectors << BCH_SECTOR_BITS);
	if (!node->buf)
		return NULL;
	if (grub_disk_read (disk, ptr->sector, 0,
			(grub_size_t) ptr->sectors << BCH_SECTOR_BITS, node->buf) ||
		bch_parse_node (data, node, ptr, btree, level))
	{
		bch_node_free (node);
		return NULL;
	}
	node->ptr = *ptr;
	node->btree = btree;
	node->level = level;
	node->used = ++data->clock;
	node->valid = 1;
	return node;
}

static grub_size_t
bch_lower_bound (const struct bch_node *node, const struct bch_pos *search)
{
	grub_size_t lo = 0, hi = node->nkeys;

	while (lo < hi)
	{
		grub_size_t mid = lo + (hi - lo) / 2;

		if (bch_pos_cmp (&node->keys[mid].p, search) < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

/* The first key at or after SEARCH, whatever its snapshot: 1 if found,
   0 if not, -1 on error. */
static int
bch_peek (struct grub_bcachefs_data *data, unsigned btree,
	struct bch_pos search, struct bch_kv *kv)
{
	const struct bch_root *root = &data->roots[btree];

	if (!root->alive)
		return 0;
	for (;;)
	{
		struct bch_bptr ptr = root->ptr;
		unsigned level = root->level;
		struct bch_pos bound = bch_pos_make (~(grub_uint64_t) 0, ~(grub_uint64_t) 0, BCH_SNAPSHOT_MAX);
		struct bch_node *node;
		const struct bch_nkey *k;
		grub_size_t i;

		for (;;)
		{
			node = bch_get_node (data, &ptr, btree, level);
			if (!node)
				return -1;
			i = bch_lower_bound (node, &search);
			if (!level)
				break;
			if (i == node->nkeys)
				return 0;
			k = &node->keys[i];
			bound = k->p;
			if (bch_btree_ptr (data, k->type, node->buf + k->val, k->len, &bound, &ptr))
				return -1;
			level--;
		}

		if (i < node->nkeys)
		{
			k = &node->keys[i];
			if (k->len > BCH_VAL_MAX)
			{
				bch_corrupt ("btree key");
				return -1;
			}
			kv->p = k->p;
			kv->size = k->size;
			kv->type = k->type;
			kv->len = k->len;
			grub_memcpy (kv->val, node->buf + k->val, k->len);
			return 1;
		}
		/* past this leaf's keys: the next key is in the next leaf */
		if (!bch_pos_next (&bound, &search))
			return 0;
	}
}

static int
bch_is_ancestor (struct grub_bcachefs_data *data, grub_uint32_t id,
	grub_uint32_t ancestor)
{
	grub_size_t steps = 0;

	while (id && id < ancestor && steps++ <= data->nsnaps)
	{
		grub_size_t lo = 0, hi = data->nsnaps;

		while (lo < hi)
		{
			grub_size_t mid = lo + (hi - lo) / 2;

			if (data->snaps[mid].id < id)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (lo == data->nsnaps || data->snaps[lo].id != id)
			return 0;
		id = data->snaps[lo].parent;
	}
	return id == ancestor;
}

/* The first key at or after POS visible in SNAPSHOT (ignored for the
   btrees without snapshots), skipping hidden positions. */
static int
bch_peek_visible (struct grub_bcachefs_data *data, unsigned btree,
	struct bch_pos pos, grub_uint32_t snapshot, struct bch_kv *kv)
{
	int snapshots = bch_btree_has_snapshots (btree);

	for (;;)
	{
		int r;

		if (snapshots && pos.snapshot < snapshot)
			pos.snapshot = snapshot;
		r = bch_peek (data, btree, pos, kv);
		if (r <= 0)
			return r;
		if (snapshots && !bch_is_ancestor (data, snapshot, kv->p.snapshot))
		{
			if (!bch_pos_next (&kv->p, &pos))
				return 0;
			continue;
		}
		if (bch_is_whiteout (kv->type))
		{
			if (!bch_pos_next_offset (&kv->p, &pos))
				return 0;
			continue;
		}
		return 1;
	}
}

static grub_err_t
bch_load_snapshots (struct grub_bcachefs_data *data)
{
	struct bch_kv *kv;
	struct bch_pos pos = bch_pos_make (0, 0, 0);
	grub_size_t cap = 0;

	kv = grub_malloc (sizeof (*kv));
	if (!kv)
		return grub_errno;
	for (;;)
	{
		int r = bch_peek (data, BCH_BTREE_SNAPSHOTS, pos, kv);

		if (r < 0)
			goto fail;
		if (!r)
			break;
		if (kv->type == BCH_KEY_SNAPSHOT && kv->len >= 8 && !kv->p.inode &&
			kv->p.offset <= BCH_SNAPSHOT_MAX)
		{
			if (data->nsnaps == cap)
			{
				struct bch_snap *s;

				if (cap >= BCH_SNAPSHOTS_MAX)
				{
					bch_corrupt ("snapshot table");
					goto fail;
				}
				cap = cap ? cap * 2 : 64;
				s = grub_realloc (data->snaps, cap * sizeof (*s));
				if (!s)
					goto fail;
				data->snaps = s;
			}
			data->snaps[data->nsnaps].id = (grub_uint32_t) kv->p.offset;
			data->snaps[data->nsnaps].parent = bch_le32 (kv->val + 4);
			data->nsnaps++;
		}
		if (!bch_pos_next_offset (&kv->p, &pos))
			break;
	}
	grub_free (kv);
	return GRUB_ERR_NONE;

fail:
	grub_free (kv);
	return grub_errno;
}

/* Subvolume ID's root inode and snapshot. */
static grub_err_t
bch_lookup_subvol (struct grub_bcachefs_data *data, grub_uint32_t id,
	grub_uint64_t *inum, grub_uint32_t *snapshot)
{
	struct bch_kv *kv;
	int r;

	kv = grub_malloc (sizeof (*kv));
	if (!kv)
		return grub_errno;
	r = bch_peek_visible (data, BCH_BTREE_SUBVOLUMES, bch_pos_make (0, id, 0), 0, kv);
	if (r < 0)
		goto fail;
	if (!r || kv->p.inode || kv->p.offset != id || kv->type != BCH_KEY_SUBVOLUME || kv->len < 16)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "bcachefs: subvolume %u not found", id);
		goto fail;
	}
	*snapshot = bch_le32 (kv->val + 4);
	*inum = bch_le64 (kv->val + 8);
	grub_free (kv);
	return GRUB_ERR_NONE;

fail:
	grub_free (kv);
	return grub_errno;
}

/* Reads a superblock: at its default sector, else where the layout sector
   says the copies are. */
static grub_uint8_t *
bch_read_sb (grub_disk_t disk)
{
	grub_uint8_t head[BCH_SB_HEAD_SIZE];
	grub_uint64_t sector;
	grub_uint8_t *sb;
	grub_uint32_t size;

	if (bch_find_sb (disk, head, &sector))
		return NULL;
	size = bch_le32 (head + 124);
	if (size > (BCH_SB_MAX_SIZE - BCH_SB_HEAD_SIZE) / 8)
	{
		bch_corrupt ("superblock");
		return NULL;
	}
	size = BCH_SB_HEAD_SIZE + size * 8;
	sb = grub_malloc (size);
	if (!sb)
		return NULL;
	if (grub_disk_read (disk, sector, 0, size, sb))
		goto fail;
	if (grub_memcmp (sb, head, sizeof (head)))
	{
		bch_corrupt ("superblock changed during read");
		goto fail;
	}
	return sb;

fail:
	grub_free (sb);
	return NULL;
}

/* The btree roots a clean shutdown left in the superblock. */
static grub_err_t
bch_parse_clean (struct grub_bcachefs_data *data, const grub_uint8_t *f,
	grub_uint32_t len)
{
	grub_uint32_t e = 24;

	if (len < e)
		return bch_corrupt ("clean section");
	while (e + 8 <= len)
	{
		grub_uint32_t u64s = bch_le16 (f + e);
		unsigned btree = f[e + 2];
		unsigned level = f[e + 3];
		grub_uint32_t next = e + 8 + u64s * 8;
		const grub_uint8_t *k = f + e + 8;

		if (next > len)
			return bch_corrupt ("clean section");
		if (f[e + 4] == BCH_JSET_ENTRY_BTREE_ROOT && btree < BCH_BTREE_NR &&
			u64s * 8 >= BCH_BKEY_BYTES)
		{
			struct bch_root *root = &data->roots[btree];
			struct bch_pos max = bch_pos_read (k + 20);

			if ((k[1] & 0x7f) != BCH_KEY_FORMAT_CURRENT || k[0] > u64s ||
				k[0] * 8 < BCH_BKEY_BYTES || level >= BCH_BTREE_MAX_DEPTH)
				return bch_corrupt ("btree root");
			if (bch_btree_ptr (data, k[2], k + BCH_BKEY_BYTES,
					k[0] * 8 - BCH_BKEY_BYTES, &max, &root->ptr))
				return grub_errno;
			root->level = level;
			root->alive = 1;
		}
		e = next;
	}
	return GRUB_ERR_NONE;
}

static void
grub_bcachefs_unmount (struct grub_bcachefs_data *data)
{
	unsigned i;

	if (!data)
		return;
	for (i = 0; i < BCH_NODE_CACHE; i++)
		bch_node_free (&data->cache[i]);
	for (i = 0; i < BCH_DEV_INVALID; i++)
		if (data->members[i])
			grub_device_close (data->members[i]);
	grub_free (data->snaps);
	grub_free (data->dc_buf);
	grub_free (data);
}

static grub_err_t bch_read_inode (struct grub_fshelp_node *node);

static struct grub_bcachefs_data *
grub_bcachefs_mount (grub_disk_t disk)
{
	struct grub_bcachefs_data *data;
	grub_uint8_t *sb = NULL;
	grub_uint64_t flags0, flags1;
	grub_uint32_t end, pos;
	grub_uint16_t block;
	unsigned i;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	sb = bch_read_sb (disk);
	if (!sb)
		goto fail;

	if (bch_le16 (sb + 16) < BCH_VERSION_MIN)
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: metadata version %u.%u is too old",
			bch_le16 (sb + 16) >> 10, bch_le16 (sb + 16) & 0x3ff);
		goto fail;
	}
	flags0 = bch_le64 (sb + 144);
	flags1 = bch_le64 (sb + 152);
	if ((flags0 >> 62) & 1)
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: big-endian filesystems are not supported");
		goto fail;
	}
	if ((flags1 >> 10) & 0xf)
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: encrypted filesystems are not supported");
		goto fail;
	}
	if (!((flags0 >> 1) & 1))
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			"bcachefs: filesystem was not cleanly unmounted (journal replay is not supported)");
		goto fail;
	}

	block = bch_le16 (sb + 120);
	data->dev_idx = sb[122];
	data->node_sectors = (grub_uint32_t) ((flags0 >> 12) & 0xffff);
	if (data->dev_idx == BCH_DEV_INVALID ||
		!block || (block & (block - 1)) || block > BCH_NODE_SECTORS_MAX ||
		!data->node_sectors || data->node_sectors > BCH_NODE_SECTORS_MAX)
	{
		bch_corrupt ("superblock");
		goto fail;
	}
	data->block_bytes = (grub_uint32_t) block << BCH_SECTOR_BITS;
	grub_memcpy (data->uuid, sb + 40, 16);
	data->bset_magic = bch_le64 (sb + 40) ^ BCH_BSET_MAGIC;
	data->time_base = bch_le64 (sb + 128);
	data->time_precision = bch_le32 (sb + 140);
	data->write_time = bch_le64 (sb + 200);
	grub_memcpy (data->user_uuid, sb + 56, 16);
	grub_memcpy (data->label, sb + 72, 32);
	data->label[32] = 0;
	grub_memcpy (data->entry_bytes, bch_entry_bytes, sizeof (bch_entry_bytes));

	/* entry sizes first: btree roots in the clean section are parsed with them */
	end = BCH_SB_HEAD_SIZE + bch_le32 (sb + 124) * 8;
	for (pos = BCH_SB_HEAD_SIZE; pos + 8 <= end;)
	{
		grub_uint32_t u64s = bch_le32 (sb + pos);
		grub_uint32_t len;

		if (!u64s || u64s > (end - pos) / 8)
		{
			bch_corrupt ("superblock field");
			goto fail;
		}
		len = u64s * 8;
		if (bch_le32 (sb + pos + 4) == BCH_SB_FIELD_EXTENT_TYPE_U64S)
		{
			/* Zero terminates the table; known layouts have fixed lengths. */
			for (i = 0; i < BCH_EXTENT_TYPES_MAX && 8 + i < len && sb[pos + 8 + i]; i++)
			{
				unsigned entry_u64s = sb[pos + 8 + i];

				if (entry_u64s >= 32 ||
					(i < BCH_EXTENT_TYPES_KNOWN && entry_u64s * 8 != bch_entry_bytes[i]))
				{
					bch_corrupt ("extent entry sizes");
					goto fail;
				}
				data->entry_bytes[i] = (grub_uint8_t) (entry_u64s * 8);
			}
		}
		pos += len;
	}
	for (pos = BCH_SB_HEAD_SIZE; pos + 8 <= end; pos += bch_le32 (sb + pos) * 8)
		if (bch_le32 (sb + pos + 4) == BCH_SB_FIELD_CLEAN &&
			bch_parse_clean (data, sb + pos, bch_le32 (sb + pos) * 8))
			goto fail;
	grub_free (sb);
	sb = NULL;

	/* a btree never written has no root: it is empty */
	if (!data->roots[BCH_BTREE_INODES].alive)
	{
		grub_error (GRUB_ERR_BAD_FS, "bcachefs: no inodes btree root in the clean section");
		goto fail;
	}
	if (bch_load_snapshots (data))
		goto fail;

	data->root.data = data;
	data->root.subvol = BCH_ROOT_SUBVOL;
	if (data->roots[BCH_BTREE_SUBVOLUMES].alive)
	{
		if (bch_lookup_subvol (data, BCH_ROOT_SUBVOL, &data->root.inum, &data->root.snapshot))
			goto fail;
	}
	else
	{
		data->root.inum = BCH_ROOT_INO;
		data->root.snapshot = BCH_SNAPSHOT_MAX;
	}
	if (bch_read_inode (&data->root))
		goto fail;
	if ((data->root.inode.mode & BCH_S_IFMT) != BCH_S_IFDIR)
	{
		bch_corrupt ("root directory inode");
		goto fail;
	}
	return data;

fail:
	grub_free (sb);
	grub_bcachefs_unmount (data);
	if (grub_errno == GRUB_ERR_FILE_NOT_FOUND)
		bch_corrupt ("root subvolume or inode");
	else if (grub_errno == GRUB_ERR_OUT_OF_RANGE)
		grub_error (GRUB_ERR_BAD_FS, "not a bcachefs filesystem");
	return NULL;
}

/* A new-style varint: its length is the count of the first byte's low
   one bits, plus one. */
static int
bch_varint (const grub_uint8_t *in, const grub_uint8_t *end, grub_uint64_t *out)
{
	unsigned bytes = 1, i;
	grub_uint64_t v = 0;

	if (in >= end)
		return -1;
	while (bytes < 9 && (in[0] >> (bytes - 1)) & 1)
		bytes++;
	if (bytes > (grub_size_t) (end - in))
		return -1;
	if (bytes == 9)
	{
		*out = bch_le64 (in + 1);
		return 9;
	}
	for (i = 0; i < bytes; i++)
		v |= (grub_uint64_t) in[i] << (i * 8);
	*out = v >> bytes;
	return (int) bytes;
}

/* An original-packing field: big endian, its length marked by the first
   byte's highest set bit. */
static int
bch_v1_field (const grub_uint8_t *in, const grub_uint8_t *end, grub_uint64_t *out)
{
	static const grub_uint8_t lens[8] = { 1, 2, 3, 4, 6, 8, 10, 13 };
	unsigned lz = 0, len, i;
	grub_uint64_t v = 0;

	if (in >= end || !in[0])
		return -1;
	while (!(in[0] & (0x80 >> lz)))
		lz++;
	len = lens[lz];
	if (len > (grub_size_t) (end - in))
		return -1;
	/* only the low 64 bits are kept: the wider fields are times */
	for (i = 0; i < len; i++)
		v = (v << 8) | (i ? in[i] : (grub_uint8_t) (in[0] ^ (0x80 >> lz)));
	*out = v;
	return (int) len;
}

/* The first WANT packed fields, the first four 96 bits wide. */
static grub_err_t
bch_inode_fields (const grub_uint8_t *in, const grub_uint8_t *end,
	unsigned nr_fields, int v1, unsigned want, grub_uint64_t *vals)
{
	unsigned i;

	for (i = 0; i < want; i++)
	{
		grub_uint64_t hi;
		int n;

		vals[i] = 0;
		if (i >= nr_fields)
			continue;
		if (v1)
			n = bch_v1_field (in, end, &vals[i]);
		else
			n = bch_varint (in, end, &vals[i]);
		if (n < 0)
			return bch_corrupt ("inode");
		in += n;
		if (!v1 && i < 4)
		{
			n = bch_varint (in, end, &hi);
			if (n < 0)
				return bch_corrupt ("inode");
			in += n;
		}
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
bch_read_inode (struct grub_fshelp_node *node)
{
	struct grub_bcachefs_data *data = node->data;
	struct bch_inode *ino = &node->inode;
	struct bch_kv *kv;
	const grub_uint8_t *v, *end;
	grub_uint64_t f[6];
	int r;

	if (node->inode_read)
		return GRUB_ERR_NONE;
	kv = grub_malloc (sizeof (*kv));
	if (!kv)
		return grub_errno;
	r = bch_peek_visible (data, BCH_BTREE_INODES,
		bch_pos_make (0, node->inum, node->snapshot), node->snapshot, kv);
	if (r < 0)
		goto fail;
	if (!r || kv->p.inode || kv->p.offset != node->inum)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "bcachefs: inode %llu not found",
			(unsigned long long) node->inum);
		goto fail;
	}
	v = kv->val;
	end = v + kv->len;
	switch (kv->type)
	{
	case BCH_KEY_INODE_V3:
	{
		grub_uint64_t flags;
		grub_uint32_t fields_start;

		if (kv->len < 48)
			goto corrupt;
		flags = bch_le64 (v + 16);
		fields_start = (grub_uint32_t) ((flags >> 31) & 0x1f) * 8;
		if (fields_start < 48 || fields_start > kv->len)
			goto corrupt;
		ino->mode = (grub_uint16_t) (flags >> 36);
		ino->size = bch_le64 (v + 32);
		if (bch_inode_fields (v + fields_start, end, (unsigned) (flags >> 24) & 0x7f, 0, 3, f))
			goto fail;
		break;
	}
	case BCH_KEY_INODE_V2:
		if (kv->len < 26)
			goto corrupt;
		ino->mode = bch_le16 (v + 24);
		if (bch_inode_fields (v + 26, end, (unsigned) (bch_le64 (v + 16) >> 24) & 0x7f, 0, 5, f))
			goto fail;
		ino->size = f[4];
		break;
	case BCH_KEY_INODE:
	{
		grub_uint32_t flags;

		if (kv->len < 14)
			goto corrupt;
		flags = bch_le32 (v + 8);
		ino->mode = bch_le16 (v + 12);
		if (bch_inode_fields (v + 14, end, (flags >> 24) & 0x7f, !(flags >> 31), 5, f))
			goto fail;
		ino->size = f[4];
		break;
	}
	default:
		goto corrupt;
	}
	ino->mtime = f[2];
	node->inode_read = 1;
	grub_free (kv);
	return GRUB_ERR_NONE;

corrupt:
	bch_corrupt ("inode");
fail:
	grub_free (kv);
	return grub_errno;
}

static grub_int64_t
bch_unix_time (struct grub_bcachefs_data *data, grub_uint64_t t)
{
	grub_uint64_t per_sec = 1000000000;
	grub_uint64_t v, q, r;

	if (data->time_precision)
		per_sec = grub_divmod64 (per_sec, data->time_precision, NULL);
	if (!per_sec)
		per_sec = 1;
	v = t + data->time_base;
	if (!(v >> 63))
		return (grub_int64_t) grub_divmod64 (v, per_sec, NULL);
	q = grub_divmod64 (-v, per_sec, &r);
	return -(grub_int64_t) q - (r ? 1 : 0);
}

/*
 * Picks an available dirty replica, preferring this device. Each crc entry
 * applies to the pointers after it. Cached copies require bucket generation
 * validation, so a key with only cached copies is refused.
 */
static grub_err_t
bch_pick_ptr (struct grub_bcachefs_data *data, const grub_uint8_t *val,
	grub_uint32_t len, struct bch_dptr *out)
{
	struct bch_dptr crc;
	grub_uint32_t pos;
	unsigned pass;
	int have = 0, cached = 0, dirty = 0, poisoned = 0;

	grub_memset (out, 0, sizeof (*out));
	for (pass = 0; pass < 2 && !have && !poisoned; pass++)
	{
		grub_memset (&crc, 0, sizeof (crc));
		pos = 0;
		while (pos + 8 <= len)
		{
			grub_uint64_t w = bch_le64 (val + pos);
			unsigned t = bch_ctz64 (w);

			if (t >= BCH_EXTENT_TYPES_MAX || !data->entry_bytes[t] ||
				pos + data->entry_bytes[t] > len)
				return bch_corrupt ("extent entry");
			switch (t)
			{
			case BCH_EXTENT_PTR:
			{
				grub_uint8_t dev = (grub_uint8_t) (w >> 48);

				/* Unwritten ranges read as zeroes even with a missing member. */
				if (w & 8)
				{
					*out = crc;
					out->offset = (w >> 4) & ((1ULL << 44) - 1);
					out->dev = dev;
					out->unwritten = 1;
					have = 1;
					break;
				}
				if (w & 2)
				{
					cached = 1;
					break;
				}
				dirty = 1;
				if (dev == BCH_DEV_INVALID || have ||
					!(pass ? bch_member_available (data, dev) : dev == data->dev_idx))
					break;
				*out = crc;
				out->offset = (w >> 4) & ((1ULL << 44) - 1);
				out->dev = dev;
				out->unwritten = (int) ((w >> 3) & 1);
				have = 1;
				break;
			}
			case BCH_EXTENT_CRC32:
				crc.has_crc = 1;
				crc.csize = (grub_uint32_t) ((w >> 2) & 0x7f) + 1;
				crc.usize = (grub_uint32_t) ((w >> 9) & 0x7f) + 1;
				crc.coffset = (grub_uint32_t) ((w >> 16) & 0x7f);
				crc.csum_type = (grub_uint8_t) ((w >> 24) & 0xf);
				crc.ctype = (grub_uint8_t) ((w >> 28) & 0xf);
				break;
			case BCH_EXTENT_CRC64:
				crc.has_crc = 1;
				crc.csize = (grub_uint32_t) ((w >> 3) & 0x1ff) + 1;
				crc.usize = (grub_uint32_t) ((w >> 12) & 0x1ff) + 1;
				crc.coffset = (grub_uint32_t) ((w >> 21) & 0x1ff);
				crc.csum_type = (grub_uint8_t) ((w >> 40) & 0xf);
				crc.ctype = (grub_uint8_t) ((w >> 44) & 0xf);
				break;
			case BCH_EXTENT_CRC128:
				crc.has_crc = 1;
				crc.csize = (grub_uint32_t) ((w >> 4) & 0x1fff) + 1;
				crc.usize = (grub_uint32_t) ((w >> 17) & 0x1fff) + 1;
				crc.coffset = (grub_uint32_t) ((w >> 30) & 0x1fff);
				crc.csum_type = (grub_uint8_t) ((w >> 56) & 0xf);
				crc.ctype = (grub_uint8_t) ((w >> 60) & 0xf);
				break;
			case BCH_EXTENT_FLAGS:
				poisoned |= (w & BCH_EXTENT_POISONED) != 0;
				break;
			default:
				break;
			}
			pos += data->entry_bytes[t];
		}
		if (pos != len)
			return bch_corrupt ("extent entry");
	}
	out->poisoned = poisoned;
	if (poisoned)
		return GRUB_ERR_NONE;
	if (!have)
	{
		if (cached && !dirty)
			return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				"bcachefs: cached-only extent requires bucket generation validation");
		return grub_error (GRUB_ERR_READ_ERROR, "bcachefs: no available dirty data replica");
	}
	return GRUB_ERR_NONE;
}

/* Fills SEG, whose START and END are set, from the extent value VAL; REL is
   START's sector offset from the extent's start. */
static grub_err_t
bch_seg_ptrs (struct grub_bcachefs_data *data, const grub_uint8_t *val,
	grub_uint32_t len, grub_uint64_t rel, struct bch_seg *seg)
{
	struct bch_dptr *dp = &seg->dp;
	grub_uint64_t span = seg->end - seg->start;

	if (bch_pick_ptr (data, val, len, dp))
		return grub_errno;
	if (dp->poisoned)
	{
		seg->kind = BCH_SEG_ERROR;
		return GRUB_ERR_NONE;
	}
	if (dp->csum_type == BCH_CSUM_CHACHA20_POLY1305_80 ||
		dp->csum_type == BCH_CSUM_CHACHA20_POLY1305_128)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: encrypted extents are not supported");
	if (dp->has_crc && (dp->usize < dp->coffset || rel > dp->usize - dp->coffset ||
			span > dp->usize - dp->coffset - rel))
		return bch_corrupt ("extent");
	if (dp->ctype == BCH_COMPRESSION_NONE || dp->ctype == BCH_COMPRESSION_INCOMPRESSIBLE)
	{
		seg->kind = dp->unwritten ? BCH_SEG_UNWRITTEN : BCH_SEG_DISK;
		seg->disk = (dp->offset + dp->coffset + rel) << BCH_SECTOR_BITS;
		return GRUB_ERR_NONE;
	}
	if (dp->unwritten)
	{
		seg->kind = BCH_SEG_ZERO;
		return GRUB_ERR_NONE;
	}
	if (dp->ctype > BCH_COMPRESSION_ZSTD)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: unknown compression type %u", dp->ctype);
	seg->kind = BCH_SEG_COMP;
	seg->dec = (dp->coffset + rel) << BCH_SECTOR_BITS;
	return GRUB_ERR_NONE;
}

static void
bch_seg_inline (struct bch_seg *seg, grub_uint32_t off, grub_uint64_t dec)
{
	seg->kind = BCH_SEG_INLINE;
	seg->inl_off = off;
	seg->inl_len = seg->kv.len - off;
	seg->dec = dec << BCH_SECTOR_BITS;
}

/* What is at file sector SECTOR of NODE, and how far it goes. */
static grub_err_t
bch_file_seg (struct grub_fshelp_node *node, grub_uint64_t sector, struct bch_seg *seg)
{
	struct grub_bcachefs_data *data = node->data;
	struct bch_kv *kv = &seg->kv;
	grub_uint64_t start, rel, idx, ridx;
	int r;

	grub_memset (seg, 0, offsetof (struct bch_seg, kv));
	seg->start = sector;
	seg->end = ~(grub_uint64_t) 0;
	seg->kind = BCH_SEG_HOLE;
	if (sector == ~(grub_uint64_t) 0)
		return GRUB_ERR_NONE;

	r = bch_peek_visible (data, BCH_BTREE_EXTENTS,
		bch_pos_make (node->inum, sector + 1, node->snapshot), node->snapshot, kv);
	if (r < 0)
		return grub_errno;
	if (!r || kv->p.inode != node->inum)
		return GRUB_ERR_NONE;
	if (kv->size > kv->p.offset)
		return bch_corrupt ("extent");
	start = kv->p.offset - kv->size;
	if (start > sector)
	{
		seg->end = start;
		return GRUB_ERR_NONE;
	}
	seg->end = kv->p.offset;
	rel = sector - start;

	switch (kv->type)
	{
	case BCH_KEY_EXTENT:
		return bch_seg_ptrs (data, kv->val, kv->len, rel, seg);
	case BCH_KEY_RESERVATION:
		seg->kind = BCH_SEG_ZERO;
		return GRUB_ERR_NONE;
	case BCH_KEY_INLINE_DATA:
		bch_seg_inline (seg, 0, rel);
		return GRUB_ERR_NONE;
	case BCH_KEY_INLINE_DATA_V2:
		if (kv->len < 24)
			return bch_corrupt ("inline extent");
		if (kv->val[1] & BCH_INLINE_POISONED)
		{
			seg->kind = BCH_SEG_ERROR;
			return GRUB_ERR_NONE;
		}
		bch_seg_inline (seg, 24, bch_le32 (kv->val + 4) + rel);
		return GRUB_ERR_NONE;
	case BCH_KEY_ERROR:
		seg->kind = BCH_SEG_ERROR;
		return GRUB_ERR_NONE;
	case BCH_KEY_COOKIE:
		return GRUB_ERR_NONE;
	case BCH_KEY_REFLINK_P:
		break;
	default:
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: unsupported extent type %u", kv->type);
	}

	/* reflink_p: the indirect extent at its index, offset as this key is */
	if (kv->len < 8)
		return bch_corrupt ("reflink pointer");
	idx = bch_le64 (kv->val);
	if ((idx >> 56) & 1)
	{
		seg->kind = BCH_SEG_ERROR;
		return GRUB_ERR_NONE;
	}
	if (grub_add (idx & ((1ULL << 56) - 1), rel, &ridx) || ridx == ~(grub_uint64_t) 0)
		return bch_corrupt ("reflink pointer");
	r = bch_peek_visible (data, BCH_BTREE_REFLINK, bch_pos_make (0, ridx + 1, 0), 0, kv);
	if (r < 0)
		return grub_errno;
	if (!r || kv->p.inode || kv->size > kv->p.offset || kv->p.offset - kv->size > ridx)
		return grub_error (GRUB_ERR_BAD_FS, "bcachefs: missing indirect extent %llu",
			(unsigned long long) ridx);
	if (kv->p.offset - ridx < seg->end - seg->start)
		seg->end = seg->start + (kv->p.offset - ridx);
	seg->shared = 1;
	rel = ridx - (kv->p.offset - kv->size);

	switch (kv->type)
	{
	case BCH_KEY_REFLINK_V:
		if (kv->len < 8)
			return bch_corrupt ("indirect extent");
		return bch_seg_ptrs (data, kv->val + 8, kv->len - 8, rel, seg);
	case BCH_KEY_INDIRECT_INLINE:
		if (kv->len < 8)
			return bch_corrupt ("indirect extent");
		bch_seg_inline (seg, 8, rel);
		return GRUB_ERR_NONE;
	case BCH_KEY_INDIRECT_INLINE_V2:
		if (kv->len < 32)
			return bch_corrupt ("indirect extent");
		if (kv->val[9] & BCH_INLINE_POISONED)
		{
			seg->kind = BCH_SEG_ERROR;
			return GRUB_ERR_NONE;
		}
		bch_seg_inline (seg, 32, bch_le32 (kv->val + 12) + rel);
		return GRUB_ERR_NONE;
	case BCH_KEY_ERROR:
		seg->kind = BCH_SEG_ERROR;
		return GRUB_ERR_NONE;
	default:
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "bcachefs: unsupported indirect extent type %u", kv->type);
	}
}

/* DP's whole extent, decompressed; the last one is kept. */
static const grub_uint8_t *
bch_decompress (struct grub_bcachefs_data *data, const struct bch_dptr *dp)
{
	grub_size_t clen = (grub_size_t) dp->csize << BCH_SECTOR_BITS;
	grub_size_t ulen = (grub_size_t) dp->usize << BCH_SECTOR_BITS;
	grub_uint8_t *src = NULL, *dst;
	grub_disk_t disk;
	int ok = 0;

	if (data->dc_valid && data->dc_sector == dp->offset && data->dc_dev == dp->dev &&
		data->dc_csize == dp->csize && data->dc_usize == dp->usize && data->dc_type == dp->ctype)
		return data->dc_buf;
	data->dc_valid = 0;
	if (dp->csize > BCH_EXTENT_SECTORS_MAX || dp->usize > BCH_EXTENT_SECTORS_MAX)
	{
		bch_corrupt ("compressed extent");
		return NULL;
	}
	disk = bch_member_disk (data, dp->dev);
	if (!disk)
		return NULL;
	dst = grub_realloc (data->dc_buf, ulen);
	if (!dst)
		return NULL;
	data->dc_buf = dst;
	src = grub_malloc (clen);
	if (!src)
		return NULL;
	if (grub_disk_read (disk, dp->offset, 0, clen, src))
		goto fail;

	switch (dp->ctype)
	{
	case BCH_COMPRESSION_LZ4_OLD:
	case BCH_COMPRESSION_LZ4:
		ok = LZ4_decompress_safe_partial ((const char *) src, (char *) dst,
			(int) clen, (int) ulen, (int) ulen) == (int) ulen;
		break;
	case BCH_COMPRESSION_GZIP:
		ok = grub_deflate_decompress ((char *) src, clen, 0, (char *) dst, ulen) == (grub_ssize_t) ulen;
		grub_errno = GRUB_ERR_NONE;
		break;
	case BCH_COMPRESSION_ZSTD:
	{
		grub_size_t real = bch_le32 (src);
		grub_size_t r;

		if (real > clen - 4)
			break;
		r = ZSTD_decompress (dst, ulen, src + 4, real);
		ok = !ZSTD_isError (r) && r == ulen;
		break;
	}
	default:
		break;
	}
	if (!ok)
	{
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bcachefs: corrupted compressed extent at sector %llu",
			(unsigned long long) dp->offset);
		goto fail;
	}
	grub_free (src);
	data->dc_sector = dp->offset;
	data->dc_dev = dp->dev;
	data->dc_csize = dp->csize;
	data->dc_usize = dp->usize;
	data->dc_type = dp->ctype;
	data->dc_valid = 1;
	return dst;

fail:
	grub_free (src);
	return NULL;
}

/* The bytes of SEG from file byte POS on: no more than WANT. */
static grub_uint64_t
bch_seg_bytes (const struct bch_seg *seg, grub_uint64_t pos, grub_uint64_t want)
{
	grub_uint64_t off = pos - (seg->start << BCH_SECTOR_BITS);

	if (seg->end - seg->start > ((want + off) >> BCH_SECTOR_BITS))
		return want;
	return ((seg->end - seg->start) << BCH_SECTOR_BITS) - off;
}

static grub_ssize_t
bch_read_data (struct grub_fshelp_node *node, grub_uint64_t pos, grub_size_t len,
	char *buf, grub_disk_read_hook_t hook, void *hook_data)
{
	struct grub_bcachefs_data *data = node->data;
	struct bch_seg *seg;
	grub_size_t done = 0;

	seg = grub_malloc (sizeof (*seg));
	if (!seg)
		return -1;
	while (done < len)
	{
		grub_size_t off, n, i;
		const grub_uint8_t *d;
		grub_disk_t disk;
		grub_err_t err;

		if (bch_file_seg (node, pos >> BCH_SECTOR_BITS, seg))
			goto fail;
		off = (grub_size_t) (pos - (seg->start << BCH_SECTOR_BITS));
		n = (grub_size_t) bch_seg_bytes (seg, pos, len - done);
		switch (seg->kind)
		{
		case BCH_SEG_HOLE:
		case BCH_SEG_ZERO:
		case BCH_SEG_UNWRITTEN:
			grub_memset (buf + done, 0, n);
			break;
		case BCH_SEG_DISK:
			disk = bch_member_disk (data, seg->dp.dev);
			if (!disk)
				goto fail;
			/* the hook reports sectors of the file's own device only */
			if (disk == data->disk)
			{
				disk->read_hook = hook;
				disk->read_hook_data = hook_data;
			}
			err = grub_disk_read (disk, (seg->disk + off) >> BCH_SECTOR_BITS,
				(seg->disk + off) & (BCH_SECTOR_SIZE - 1), n, buf + done);
			data->disk->read_hook = NULL;
			data->disk->read_hook_data = NULL;
			if (err)
				goto fail;
			break;
		case BCH_SEG_COMP:
			d = bch_decompress (data, &seg->dp);
			if (!d)
				goto fail;
			grub_memcpy (buf + done, d + (grub_size_t) seg->dec + off, n);
			break;
		case BCH_SEG_INLINE:
			for (i = 0; i < n; i++)
			{
				grub_uint64_t at = seg->dec + off + i;

				buf[done + i] = (char) (at < seg->inl_len ? seg->kv.val[seg->inl_off + (grub_size_t) at] : 0);
			}
			break;
		case BCH_SEG_ERROR:
			grub_error (GRUB_ERR_READ_ERROR, "bcachefs: extent data was lost or marked poisoned");
			goto fail;
		}
		done += n;
		pos += n;
	}
	grub_free (seg);
	return (grub_ssize_t) done;

fail:
	grub_free (seg);
	return -1;
}

static char *
grub_bcachefs_read_symlink (grub_fshelp_node_t node)
{
	char *buf;

	if (bch_read_inode (node))
		return NULL;
	if (node->inode.size >= BCH_SYMLINK_MAX)
	{
		bch_corrupt ("symlink");
		return NULL;
	}
	buf = grub_malloc (node->inode.size + 1);
	if (!buf)
		return NULL;
	if (bch_read_data (node, 0, node->inode.size, buf, NULL, NULL) < 0)
	{
		grub_free (buf);
		return NULL;
	}
	/* the target is stored with its NUL */
	buf[node->inode.size] = 0;
	return buf;
}

static int
grub_bcachefs_iterate_dir (grub_fshelp_node_t dir, grub_fshelp_iterate_dir_hook_t hook,
	void *hook_data)
{
	struct grub_bcachefs_data *data = dir->data;
	struct bch_kv *kv;
	struct bch_pos pos = bch_pos_make (dir->inum, 0, dir->snapshot);
	char *name;
	int ret = 0;

	if (bch_read_inode (dir))
		return 0;
	if ((dir->inode.mode & BCH_S_IFMT) != BCH_S_IFDIR)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "bcachefs: not a directory");
		return 0;
	}
	kv = grub_malloc (sizeof (*kv) + BCH_NAME_MAX + 1);
	if (!kv)
		return 0;
	name = (char *) (kv + 1);
	for (;;)
	{
		struct grub_fshelp_node *child;
		enum grub_fshelp_filetype type;
		grub_uint32_t nlen, at, pad;
		unsigned dtype;
		int r;

		r = bch_peek_visible (data, BCH_BTREE_DIRENTS, pos, dir->snapshot, kv);
		if (r <= 0 || kv->p.inode != dir->inum)
			break;
		if (!bch_pos_next_offset (&kv->p, &pos))
			pos.inode = ~(grub_uint64_t) 0;
		if (kv->type != BCH_KEY_DIRENT || kv->len < 16)
			continue;

		dtype = kv->val[8] & 0x1f;
		if (kv->val[8] & 0x80)
		{
			/* casefolded: the name, then its folded form */
			at = 15;
			nlen = bch_le16 (kv->val + 11);
			if (at + nlen > kv->len)
				continue;
		}
		else
		{
			at = 9;
			for (pad = 0; pad < 8 && !kv->val[kv->len - 1 - pad]; pad++)
				;
			nlen = kv->len - at > pad ? kv->len - at - pad : 0;
		}
		if (!nlen || nlen > BCH_NAME_MAX)
			continue;
		grub_memcpy (name, kv->val + at, nlen);
		name[nlen] = 0;

		child = grub_zalloc (sizeof (*child));
		if (!child)
			break;
		child->data = data;
		if (dtype == BCH_DT_SUBVOL)
		{
			/* a snapshot of this subvolume keeps the dirents of its children */
			if (bch_le32 (kv->val + 4) != dir->subvol)
			{
				grub_free (child);
				continue;
			}
			child->subvol = bch_le32 (kv->val);
			if (bch_lookup_subvol (data, child->subvol, &child->inum, &child->snapshot))
			{
				grub_free (child);
				break;
			}
		}
		else
		{
			child->inum = bch_le64 (kv->val);
			child->subvol = dir->subvol;
			child->snapshot = dir->snapshot;
		}
		switch (dtype)
		{
		case BCH_DT_DIR:
		case BCH_DT_SUBVOL:
			type = GRUB_FSHELP_DIR;
			break;
		case BCH_DT_REG:
			type = GRUB_FSHELP_REG;
			break;
		case BCH_DT_LNK:
			type = GRUB_FSHELP_SYMLINK;
			break;
		default:
			type = GRUB_FSHELP_UNKNOWN;
			break;
		}
		if ((kv->val[8] & 0x80) && type != GRUB_FSHELP_UNKNOWN)
			type |= GRUB_FSHELP_CASE_INSENSITIVE;
		if (hook (name, type, child, hook_data))
		{
			ret = 1;
			break;
		}
	}
	grub_free (kv);
	return ret;
}

struct grub_bcachefs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_bcachefs_dir_iter (const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *data)
{
	struct grub_bcachefs_dir_ctx *ctx = data;
	struct grub_dirhook_info info;
	int ret;

	grub_memset (&info, 0, sizeof (info));
	info.dir = (filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR;
	info.symlink = (filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK;
	info.case_insensitive = !!(filetype & GRUB_FSHELP_CASE_INSENSITIVE);
	info.inodeset = 1;
	info.inode = node->inum;
	if (bch_read_inode (node) == GRUB_ERR_NONE)
	{
		grub_uint32_t fmt = node->inode.mode & BCH_S_IFMT;

		info.dir = fmt == BCH_S_IFDIR;
		info.symlink = fmt == BCH_S_IFLNK;
		info.mtimeset = 1;
		info.mtime = bch_unix_time (node->data, node->inode.mtime);
		if (!info.dir)
		{
			info.sizeset = 1;
			info.size = node->inode.size;
		}
	}
	else
		grub_errno = GRUB_ERR_NONE;
	ret = ctx->hook (filename, &info, ctx->hook_data);
	grub_free (node);
	return ret;
}

static grub_err_t
grub_bcachefs_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook,
	void *hook_data)
{
	struct grub_bcachefs_dir_ctx ctx = { hook, hook_data };
	struct grub_bcachefs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_bcachefs_mount (device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (path, &data->root, &fdiro, grub_bcachefs_iterate_dir,
			grub_bcachefs_read_symlink, GRUB_FSHELP_DIR))
		goto fail;
	grub_bcachefs_iterate_dir (fdiro, grub_bcachefs_dir_iter, &ctx);

fail:
	if (fdiro != &data->root)
		grub_free (fdiro);
	grub_bcachefs_unmount (data);
	return grub_errno;
}

static grub_err_t
grub_bcachefs_open (struct grub_file *file, const char *name)
{
	struct grub_bcachefs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_bcachefs_mount (file->device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (name, &data->root, &fdiro, grub_bcachefs_iterate_dir,
			grub_bcachefs_read_symlink, GRUB_FSHELP_REG) ||
		bch_read_inode (fdiro))
		goto fail;
	data->file = *fdiro;
	if (fdiro != &data->root)
		grub_free (fdiro);
	file->data = data;
	file->size = data->file.inode.size;
	file->offset = 0;
	return GRUB_ERR_NONE;

fail:
	if (fdiro != &data->root)
		grub_free (fdiro);
	grub_bcachefs_unmount (data);
	return grub_errno;
}

static grub_ssize_t
grub_bcachefs_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_bcachefs_data *data = file->data;

	return bch_read_data (&data->file, file->offset, len, buf,
		file->read_hook, file->read_hook_data);
}

static const char *
bch_compression_name (grub_uint8_t type)
{
	switch (type)
	{
	case BCH_COMPRESSION_LZ4_OLD:
	case BCH_COMPRESSION_LZ4:
		return "LZ4";
	case BCH_COMPRESSION_GZIP:
		return "deflate";
	case BCH_COMPRESSION_ZSTD:
		return "ZSTD";
	default:
		return "unknown";
	}
}

static grub_err_t
grub_bcachefs_map (grub_file_t file, struct grub_file_map_context *ctx)
{
	struct grub_bcachefs_data *data = file->data;
	struct bch_seg *seg;
	grub_uint64_t pos = ctx->start;

	seg = grub_malloc (sizeof (*seg));
	if (!seg)
		return grub_errno;
	while (pos < ctx->end && !grub_file_map_cancelled (ctx))
	{
		grub_uint64_t off, n;
		unsigned shared;
		grub_err_t err = GRUB_ERR_NONE;

		if (bch_file_seg (&data->file, pos >> BCH_SECTOR_BITS, seg))
			break;
		off = pos - (seg->start << BCH_SECTOR_BITS);
		n = bch_seg_bytes (seg, pos, ctx->end - pos);
		shared = seg->shared ? GRUB_FILE_MAP_SHARED : 0;
		/* another member's addresses are not this device's */
		if ((seg->kind == BCH_SEG_DISK || seg->kind == BCH_SEG_UNWRITTEN || seg->kind == BCH_SEG_COMP) &&
			seg->dp.dev != data->dev_idx)
			seg->kind = BCH_SEG_ERROR;
		switch (seg->kind)
		{
		case BCH_SEG_HOLE:
			err = grub_file_map_simple (ctx, pos, n, GRUB_FILE_MAP_ZERO | GRUB_FILE_MAP_HOLE, 0);
			break;
		case BCH_SEG_ZERO:
			err = grub_file_map_simple (ctx, pos, n, GRUB_FILE_MAP_ZERO, 0);
			break;
		case BCH_SEG_UNWRITTEN:
			err = grub_file_map_simple (ctx, pos, n, GRUB_FILE_MAP_ZERO | GRUB_FILE_MAP_UNWRITTEN | shared,
				seg->disk + off);
			break;
		case BCH_SEG_DISK:
			err = grub_file_map_simple (ctx, pos, n, GRUB_FILE_MAP_DIRECT | shared, seg->disk + off);
			break;
		case BCH_SEG_INLINE:
			err = grub_file_map_simple (ctx, pos, n, GRUB_FILE_MAP_INLINE | shared, 0);
			break;
		case BCH_SEG_ERROR:
			err = grub_file_map_simple (ctx, pos, n, GRUB_FILE_MAP_UNKNOWN, 0);
			break;
		case BCH_SEG_COMP:
		{
			struct grub_file_map_storage storage;
			struct grub_file_map_extent e;

			grub_memset (&e, 0, sizeof (e));
			storage.offset = seg->dp.offset << BCH_SECTOR_BITS;
			storage.length = (grub_uint64_t) seg->dp.csize << BCH_SECTOR_BITS;
			storage.address_space = GRUB_FILE_MAP_VOLUME;
			e.logical_offset = pos;
			e.logical_length = n;
			e.decoded_offset = seg->dec + off;
			e.decoded_length = (grub_uint64_t) seg->dp.usize << BCH_SECTOR_BITS;
			e.flags = GRUB_FILE_MAP_COMPRESSED | GRUB_FILE_MAP_TRANSFORMED | shared;
			e.encoding = bch_compression_name (seg->dp.ctype);
			e.storage = &storage;
			e.storage_count = 1;
			err = grub_file_map_emit (ctx, &e);
			break;
		}
		}
		if (err)
			break;
		pos += n;
	}
	grub_free (seg);
	return grub_errno;
}

static grub_err_t
grub_bcachefs_close (grub_file_t file)
{
	grub_bcachefs_unmount (file->data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_bcachefs_readlink (grub_device_t device, const char *path, char **target)
{
	struct grub_bcachefs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	*target = NULL;
	data = grub_bcachefs_mount (device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (path, &data->root, &fdiro, grub_bcachefs_iterate_dir,
			grub_bcachefs_read_symlink, GRUB_FSHELP_SYMLINK))
		goto fail;
	if (bch_read_inode (fdiro))
		goto fail;
	if ((fdiro->inode.mode & BCH_S_IFMT) != BCH_S_IFLNK)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a symbolic link");
		goto fail;
	}
	*target = grub_bcachefs_read_symlink (fdiro);

fail:
	if (fdiro != &data->root)
		grub_free (fdiro);
	grub_bcachefs_unmount (data);
	return grub_errno;
}

static grub_err_t
grub_bcachefs_label (grub_device_t device, char **label)
{
	struct grub_bcachefs_data *data;

	*label = NULL;
	data = grub_bcachefs_mount (device->disk);
	if (!data)
		return grub_errno;
	*label = grub_strdup (data->label);
	grub_bcachefs_unmount (data);
	return grub_errno;
}

static grub_err_t
grub_bcachefs_uuid (grub_device_t device, char **uuid)
{
	struct grub_bcachefs_data *data;
	const grub_uint8_t *u;

	*uuid = NULL;
	data = grub_bcachefs_mount (device->disk);
	if (!data)
		return grub_errno;
	u = data->user_uuid;
	*uuid = grub_xasprintf ("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
		u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
	grub_bcachefs_unmount (data);
	return grub_errno;
}

static grub_err_t
grub_bcachefs_mtime (grub_device_t device, grub_int64_t *tm)
{
	struct grub_bcachefs_data *data;

	*tm = 0;
	data = grub_bcachefs_mount (device->disk);
	if (!data)
		return grub_errno;
	*tm = (grub_int64_t) data->write_time;
	grub_bcachefs_unmount (data);
	return grub_errno;
}

static struct grub_fs grub_bcachefs_fs = {
	.name = "bcachefs",
	.fs_dir = grub_bcachefs_dir,
	.fs_open = grub_bcachefs_open,
	.fs_read = grub_bcachefs_read,
	.fs_map_range = grub_bcachefs_map,
	.fs_close = grub_bcachefs_close,
	.fs_label = grub_bcachefs_label,
	.fs_uuid = grub_bcachefs_uuid,
	.fs_mtime = grub_bcachefs_mtime,
	.fs_readlink = grub_bcachefs_readlink,
#ifdef GRUB_UTIL
	.reserved_first_sector = 0,
	.blocklist_install = 0,
#endif
};

GRUB_MOD_INIT (bcachefs)
{
	grub_bcachefs_fs.mod = mod;
	grub_fs_register (&grub_bcachefs_fs);
}

GRUB_MOD_FINI (bcachefs)
{
	grub_fs_unregister (&grub_bcachefs_fs);
}
