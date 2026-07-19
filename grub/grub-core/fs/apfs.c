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
 * APFS (Apple File System) read-only driver.
 *
 * On-disk structures follow Apple's reference documentation and
 * ref\linux-apfs-rw (apfs_raw.h); the overall approach -- checkpoint
 * selection, object map lookups, sealed-volume fext trees, decmpfs
 * compressed files -- matches ref\7z2602 ApfsHandler.cpp, but the
 * B-trees are walked on demand instead of being slurped into memory.
 *
 * Each volume of the container is exposed as a top-level directory
 * named after the volume.  Encrypted (FileVault) volumes are skipped
 * at mount time; snapshots and fusion containers are not supported.
 *
 * decmpfs compressed files support the zlib, lzvn, lzfse, lzbitmap
 * and uncompressed flavours: zlib decoding reuses grub's gzio, the
 * other decoders live in grub-core\lib\lzfse and
 * grub-core\lib\libzbitmap.c (both ported from ref\linux-apfs-rw).
 */

#include <grub/types.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/fshelp.h>
#include <grub/deflate.h>
#include <grub/dl.h>

#include <lzfse.h>
#include <lzvn_decode_base.h>
#include <libzbitmap.h>

GRUB_MOD_LICENSE("GPLv3+");

#define GRUB_APFS_NX_MAGIC	0x4253584EU	/* "NXSB" */
#define GRUB_APFS_APSB_MAGIC	0x42535041U	/* "APSB" */
#define GRUB_APFS_CMP_MAGIC	0x636D7066U	/* "fpmc" */

#define GRUB_APFS_MAX_FILE_SYSTEMS	100
#define GRUB_APFS_MAX_XP_DESC_BLOCKS	8192
#define GRUB_APFS_TREE_MAX_DEPTH	16
#define GRUB_APFS_MAX_META_SIZE		0x1000000	/* xattr/decmpfs blobs */
#define GRUB_APFS_MAX_CDATA_SIZE	0x20000	/* one compressed 64 KiB block */
#define GRUB_APFS_CMP_BLOCK		0x10000

/* object types (obj_phys::type & 0xffff) */
#define GRUB_APFS_OBJECT_TYPE_NX_SUPERBLOCK	0x01
#define GRUB_APFS_OBJECT_TYPE_BTREE		0x02
#define GRUB_APFS_OBJECT_TYPE_BTREE_NODE	0x03
#define GRUB_APFS_OBJECT_TYPE_OMAP		0x0B
#define GRUB_APFS_OBJECT_TYPE_FS		0x0D
#define GRUB_APFS_OBJECT_TYPE_FSTREE		0x0E
#define GRUB_APFS_OBJECT_TYPE_FEXT_TREE		0x1F
#define GRUB_APFS_OBJECT_TYPE_MASK		0xFFFF
#define GRUB_APFS_OBJ_PHYSICAL			0x40000000U

/* B-tree node flags */
#define GRUB_APFS_BTNODE_ROOT		0x0001
#define GRUB_APFS_BTNODE_LEAF		0x0002
#define GRUB_APFS_BTNODE_FIXED_KV_SIZE	0x0004
#define GRUB_APFS_BTNODE_HASHED		0x0008
#define GRUB_APFS_BTNODE_NOHEADER	0x0010

#define GRUB_APFS_BTOFF_INVALID	0xFFFF

/* object map value flags */
#define GRUB_APFS_OMAP_VAL_DELETED	0x01
#define GRUB_APFS_OMAP_VAL_NOHEADER	0x08

/* file-system record types (key >> 60) */
#define GRUB_APFS_TYPE_INODE		3
#define GRUB_APFS_TYPE_XATTR		4
#define GRUB_APFS_TYPE_FILE_EXTENT	8
#define GRUB_APFS_TYPE_DIR_REC		9

#define GRUB_APFS_OBJ_ID_MASK		0x0FFFFFFFFFFFFFFFULL
#define GRUB_APFS_OBJ_TYPE_SHIFT	60

#define GRUB_APFS_ROOT_DIR_INO	2

#define GRUB_APFS_DREC_LEN_MASK	0x3FF

/* directory record file types (drec value flags & 0xF, DT_* values) */
#define GRUB_APFS_DT_DIR	4
#define GRUB_APFS_DT_REG	8
#define GRUB_APFS_DT_LNK	10

/* volume incompatible features */
#define GRUB_APFS_INCOMPAT_CASE_INSENSITIVE	0x01
#define GRUB_APFS_INCOMPAT_NORM_INSENSITIVE	0x08

/* volume flags */
#define GRUB_APFS_FS_UNENCRYPTED	0x01

/* inode bsd_flags */
#define GRUB_APFS_INOBSD_COMPRESSED	0x20

/* inode mode */
#define GRUB_APFS_MODE_IFMT	0xF000
#define GRUB_APFS_MODE_IFDIR	0x4000
#define GRUB_APFS_MODE_IFLNK	0xA000

/* xattr value flags */
#define GRUB_APFS_XATTR_DATA_STREAM	0x01
#define GRUB_APFS_XATTR_DATA_EMBEDDED	0x02

/* inode extended field types */
#define GRUB_APFS_INO_EXT_TYPE_DSTREAM	8

#define GRUB_APFS_FILE_EXTENT_LEN_MASK	0x00FFFFFFFFFFFFFFULL

/* decmpfs algorithms */
#define GRUB_APFS_COMPRESS_ZLIB_ATTR	3
#define GRUB_APFS_COMPRESS_ZLIB_RSRC	4
#define GRUB_APFS_COMPRESS_LZVN_ATTR	7
#define GRUB_APFS_COMPRESS_LZVN_RSRC	8
#define GRUB_APFS_COMPRESS_PLAIN_ATTR	9
#define GRUB_APFS_COMPRESS_PLAIN_RSRC	10
#define GRUB_APFS_COMPRESS_LZFSE_ATTR	11
#define GRUB_APFS_COMPRESS_LZFSE_RSRC	12
#define GRUB_APFS_COMPRESS_LZBITMAP_ATTR	13
#define GRUB_APFS_COMPRESS_LZBITMAP_RSRC	14

#define GRUB_APFS_XATTR_SYMLINK	"com.apple.fs.symlink"
#define GRUB_APFS_XATTR_DECMPFS	"com.apple.decmpfs"
#define GRUB_APFS_XATTR_RSRC	"com.apple.ResourceFork"

PRAGMA_BEGIN_PACKED
struct grub_apfs_obj_phys
{
	grub_uint64_t cksum;
	grub_uint64_t oid;
	grub_uint64_t xid;
	grub_uint32_t type;
	grub_uint32_t subtype;
} GRUB_PACKED;

struct grub_apfs_nx_super
{
	struct grub_apfs_obj_phys o;		/* 0x00 */
	grub_uint32_t magic;			/* 0x20 */
	grub_uint32_t block_size;
	grub_uint64_t block_count;		/* 0x28 */
	grub_uint64_t features;			/* 0x30 */
	grub_uint64_t ro_compat_features;
	grub_uint64_t incompat_features;	/* 0x40 */
	grub_uint8_t uuid[16];			/* 0x48 */
	grub_uint64_t next_oid;			/* 0x58 */
	grub_uint64_t next_xid;
	grub_uint32_t xp_desc_blocks;		/* 0x68 */
	grub_uint32_t xp_data_blocks;
	grub_uint64_t xp_desc_base;		/* 0x70 */
	grub_uint64_t xp_data_base;
	grub_uint32_t xp_desc_next;		/* 0x80 */
	grub_uint32_t xp_data_next;
	grub_uint32_t xp_desc_index;		/* 0x88 */
	grub_uint32_t xp_desc_len;
	grub_uint32_t xp_data_index;		/* 0x90 */
	grub_uint32_t xp_data_len;
	grub_uint64_t spaceman_oid;		/* 0x98 */
	grub_uint64_t omap_oid;			/* 0xA0 */
	grub_uint64_t reaper_oid;
	grub_uint32_t test_type;		/* 0xB0 */
	grub_uint32_t max_file_systems;
	grub_uint64_t fs_oid[GRUB_APFS_MAX_FILE_SYSTEMS];	/* 0xB8 */
} GRUB_PACKED;

struct grub_apfs_omap_phys
{
	struct grub_apfs_obj_phys o;		/* 0x00 */
	grub_uint32_t flags;			/* 0x20 */
	grub_uint32_t snap_count;
	grub_uint32_t tree_type;
	grub_uint32_t snapshot_tree_type;
	grub_uint64_t tree_oid;			/* 0x30 */
} GRUB_PACKED;

struct grub_apfs_nloc
{
	grub_uint16_t off;
	grub_uint16_t len;
} GRUB_PACKED;

struct grub_apfs_kvloc
{
	struct grub_apfs_nloc k;
	struct grub_apfs_nloc v;
} GRUB_PACKED;

struct grub_apfs_kvoff
{
	grub_uint16_t k;
	grub_uint16_t v;
} GRUB_PACKED;

struct grub_apfs_btnode
{
	struct grub_apfs_obj_phys o;		/* 0x00 */
	grub_uint16_t flags;			/* 0x20 */
	grub_uint16_t level;
	grub_uint32_t nkeys;
	struct grub_apfs_nloc table_space;	/* 0x28 */
	struct grub_apfs_nloc free_space;
	struct grub_apfs_nloc key_free_list;
	struct grub_apfs_nloc val_free_list;	/* header ends at 0x38 */
} GRUB_PACKED;

struct grub_apfs_btinfo
{
	grub_uint32_t flags;
	grub_uint32_t node_size;
	grub_uint32_t key_size;
	grub_uint32_t val_size;
	grub_uint32_t longest_key;
	grub_uint32_t longest_val;
	grub_uint64_t key_count;
	grub_uint64_t node_count;
} GRUB_PACKED;			/* 0x28 bytes at the end of a root node */

struct grub_apfs_omap_val
{
	grub_uint32_t flags;
	grub_uint32_t size;
	grub_uint64_t paddr;
} GRUB_PACKED;

struct grub_apfs_modified_by
{
	grub_uint8_t id[32];
	grub_uint64_t timestamp;
	grub_uint64_t last_xid;
} GRUB_PACKED;

struct grub_apfs_vol_super
{
	struct grub_apfs_obj_phys o;		/* 0x00 */
	grub_uint32_t magic;			/* 0x20 */
	grub_uint32_t fs_index;
	grub_uint64_t features;			/* 0x28 */
	grub_uint64_t ro_compat_features;
	grub_uint64_t incompat_features;	/* 0x38 */
	grub_uint64_t unmount_time;		/* 0x40 */
	grub_uint64_t fs_reserve_block_count;
	grub_uint64_t fs_quota_block_count;
	grub_uint64_t fs_alloc_count;		/* 0x58 */
	grub_uint8_t meta_crypto[20];		/* 0x60 */
	grub_uint32_t root_tree_type;		/* 0x74 */
	grub_uint32_t extentref_tree_type;
	grub_uint32_t snap_meta_tree_type;
	grub_uint64_t omap_oid;			/* 0x80 */
	grub_uint64_t root_tree_oid;		/* 0x88 */
	grub_uint64_t extentref_tree_oid;
	grub_uint64_t snap_meta_tree_oid;
	grub_uint64_t revert_to_xid;		/* 0xA0 */
	grub_uint64_t revert_to_sblock_oid;
	grub_uint64_t next_obj_id;		/* 0xB0 */
	grub_uint64_t num_files;		/* 0xB8 */
	grub_uint64_t num_directories;
	grub_uint64_t num_symlinks;
	grub_uint64_t num_other_fsobjects;
	grub_uint64_t num_snapshots;
	grub_uint64_t total_blocks_alloced;	/* 0xE0 */
	grub_uint64_t total_blocks_freed;
	grub_uint8_t vol_uuid[16];		/* 0xF0 */
	grub_uint64_t last_mod_time;		/* 0x100 */
	grub_uint64_t fs_flags;			/* 0x108 */
	struct grub_apfs_modified_by formatted_by;	/* 0x110 */
	struct grub_apfs_modified_by modified_by[8];	/* 0x140 */
	grub_uint8_t volname[256];		/* 0x2C0 */
	grub_uint32_t next_doc_id;		/* 0x3C0 */
	grub_uint16_t role;
	grub_uint16_t reserved;
	grub_uint64_t root_to_xid;		/* 0x3C8 */
	grub_uint64_t er_state_oid;
	grub_uint64_t cloneinfo_id_epoch;	/* 0x3D8 */
	grub_uint64_t cloneinfo_xid;
	grub_uint64_t snap_meta_ext_oid;	/* 0x3E8 */
	grub_uint8_t volume_group_id[16];	/* 0x3F0 */
	grub_uint64_t integrity_meta_oid;	/* 0x400 */
	grub_uint64_t fext_tree_oid;		/* 0x408 */
	grub_uint32_t fext_tree_type;		/* 0x410 */
} GRUB_PACKED;

struct grub_apfs_dstream
{
	grub_uint64_t size;
	grub_uint64_t alloced_size;
	grub_uint64_t default_crypto_id;
	grub_uint64_t total_bytes_written;
	grub_uint64_t total_bytes_read;
} GRUB_PACKED;

struct grub_apfs_inode_val
{
	grub_uint64_t parent_id;		/* 0x00 */
	grub_uint64_t private_id;
	grub_uint64_t create_time;		/* 0x10 */
	grub_uint64_t mod_time;
	grub_uint64_t change_time;		/* 0x20 */
	grub_uint64_t access_time;
	grub_uint64_t internal_flags;		/* 0x30 */
	grub_uint32_t nchildren_or_nlink;	/* 0x38 */
	grub_uint32_t default_protection_class;
	grub_uint32_t write_generation_counter;	/* 0x40 */
	grub_uint32_t bsd_flags;
	grub_uint32_t owner;			/* 0x48 */
	grub_uint32_t group;
	grub_uint16_t mode;			/* 0x50 */
	grub_uint16_t pad1;
	grub_uint64_t uncompressed_size;	/* 0x54 */
} GRUB_PACKED;			/* 0x5C bytes, then extended fields */

struct grub_apfs_xf_blob
{
	grub_uint16_t num_exts;
	grub_uint16_t used_data;
} GRUB_PACKED;

struct grub_apfs_x_field
{
	grub_uint8_t type;
	grub_uint8_t flags;
	grub_uint16_t size;
} GRUB_PACKED;

struct grub_apfs_drec_val
{
	grub_uint64_t file_id;
	grub_uint64_t date_added;
	grub_uint16_t flags;
} GRUB_PACKED;			/* 0x12 bytes, then extended fields */

struct grub_apfs_xattr_val
{
	grub_uint16_t flags;
	grub_uint16_t xdata_len;
} GRUB_PACKED;			/* followed by xdata */

struct grub_apfs_xattr_dstream
{
	grub_uint64_t xattr_obj_id;
	struct grub_apfs_dstream dstream;
} GRUB_PACKED;

struct grub_apfs_file_extent_val
{
	grub_uint64_t len_and_flags;
	grub_uint64_t phys_block_num;
	grub_uint64_t crypto_id;
} GRUB_PACKED;

struct grub_apfs_cmp_hdr
{
	grub_uint32_t signature;
	grub_uint32_t algo;
	grub_uint64_t size;
} GRUB_PACKED;

/* HFS-style resource fork header used by the zlib/plain flavours
   (big-endian fields) */
struct grub_apfs_rsrc_hdr
{
	grub_uint32_t data_offs;
	grub_uint32_t mgmt_offs;
	grub_uint32_t data_size;
	grub_uint32_t mgmt_size;
} GRUB_PACKED;
PRAGMA_END_PACKED

struct grub_apfs_data;

struct grub_apfs_volume
{
	struct grub_apfs_data *data;
	char *name;			/* UTF-8, unique within the container */
	grub_uint64_t omap_root;	/* paddr of the volume omap tree root */
	grub_uint64_t root_paddr;	/* paddr of the fs tree root node */
	int root_noheader;
	grub_uint64_t root_tree_oid;	/* virtual oid; base for hashed child ids */
	grub_uint64_t fext_root;	/* paddr of the fext tree root, 0 if none */
	grub_int64_t mtime;		/* seconds since the epoch */
	int hashed_names;		/* directory records carry name hashes */
	int case_insensitive;
};

struct grub_fshelp_node
{
	struct grub_apfs_data *data;
	struct grub_apfs_volume *vol;	/* NULL = container root (volume list) */
	grub_uint64_t ino;
	/* filled by grub_apfs_load_inode */
	int have_inode;
	grub_uint64_t private_id;
	grub_uint64_t size;		/* data stream size */
	grub_uint64_t mtime_ns;
	grub_uint64_t internal_flags;
	grub_uint32_t bsd_flags;
	grub_uint16_t mode;
};

struct grub_apfs_data
{
	grub_disk_t disk;
	grub_uint32_t blksz;
	int blklog;			/* log2(blksz) */
	grub_uint64_t blocks;		/* container block count */
	grub_uint8_t uuid[16];
	grub_uint64_t omap_root;	/* container omap tree root paddr */
	grub_uint32_t nvols;
	struct grub_apfs_volume *vols;
	struct grub_fshelp_node rootnode;
};

/* one B-tree to walk: root location plus how to resolve child pointers */
struct grub_apfs_tree
{
	struct grub_apfs_data *data;
	grub_uint64_t root;
	int root_noheader;
	grub_uint32_t subtype;
	grub_uint64_t omap_root;	/* resolve virtual child oids; 0 = physical */
	grub_uint64_t oid_base;		/* added to child oids of hashed nodes */
	/* fixed key/value sizes, captured from the root node's btree_info */
	grub_uint32_t kfix;
	grub_uint32_t vfix;
};

enum
{
	GRUB_APFS_CMP_KIND_OMAP,
	GRUB_APFS_CMP_KIND_FS,
	GRUB_APFS_CMP_KIND_FEXT
};

enum
{
	GRUB_APFS_MATCH_PREFIX,	/* every record with the same id (and type) */
	GRUB_APFS_MATCH_FLOOR,	/* order by the extra field (xid / offset) */
	GRUB_APFS_MATCH_GE	/* match once the extra field reaches a bound */
};

struct grub_apfs_key_target
{
	int kind;
	int mode;
	grub_uint64_t id;
	grub_uint8_t type;	/* fs record type, unused for omap/fext */
	grub_uint64_t extra;
};

/* return nonzero to stop the iteration */
typedef int (*grub_apfs_rec_hook_t)(const grub_uint8_t *key, grub_uint32_t klen,
	const grub_uint8_t *val, grub_uint32_t vlen, void *ctx);

static grub_err_t grub_apfs_dstream_read(struct grub_apfs_volume *vol,
	grub_uint64_t ext_id, grub_uint64_t pos, grub_uint64_t len,
	grub_uint8_t *buf, grub_file_t file);

/* Fletcher-64 as used by APFS: sums the block starting after the
   8-byte checksum field */
static int
grub_apfs_checksum_ok(const grub_uint8_t *buf, grub_size_t size)
{
	const grub_uint32_t *w = (const grub_uint32_t *) buf;
	grub_size_t i, n = size / 4;
	grub_uint64_t a = 0, b = 0, ck_lo, ck_hi;

	for (i = 2; i < n; i++)
	{
		a += grub_le_to_cpu32(w[i]);
		b += a;
	}
	a %= 0xFFFFFFFFULL;
	b %= 0xFFFFFFFFULL;
	ck_lo = 0xFFFFFFFFULL - ((a + b) % 0xFFFFFFFFULL);
	ck_hi = 0xFFFFFFFFULL - ((a + ck_lo) % 0xFFFFFFFFULL);
	return grub_le_to_cpu64(*(const grub_uint64_t *) buf)
		== ((ck_hi << 32) | ck_lo);
}

static grub_err_t
grub_apfs_read_block(struct grub_apfs_data *data, grub_uint64_t paddr, void *buf)
{
	if (paddr >= data->blocks)
		return grub_error(GRUB_ERR_BAD_FS, "APFS block out of range");
	return grub_disk_read(data->disk,
		(grub_disk_addr_t) (paddr << (data->blklog - GRUB_DISK_SECTOR_BITS)),
		0, data->blksz, buf);
}

static int
grub_apfs_key_cmp(const struct grub_apfs_key_target *t,
	const grub_uint8_t *key, grub_uint32_t klen)
{
	grub_uint64_t id, extra;

	if (klen < 8)
		return -1;
	id = grub_le_to_cpu64(grub_get_unaligned64(key));

	if (t->kind == GRUB_APFS_CMP_KIND_FS)
	{
		grub_uint8_t type = (grub_uint8_t) (id >> GRUB_APFS_OBJ_TYPE_SHIFT);

		id &= GRUB_APFS_OBJ_ID_MASK;
		if (id != t->id)
			return id < t->id ? -1 : 1;
		if (type != t->type)
			return type < t->type ? -1 : 1;
	}
	else if (id != t->id)
		return id < t->id ? -1 : 1;

	if (t->mode == GRUB_APFS_MATCH_PREFIX)
		return 0;
	if (klen < 16)
		return -1;
	extra = grub_le_to_cpu64(grub_get_unaligned64(key + 8));
	if (t->mode == GRUB_APFS_MATCH_GE)
		return extra >= t->extra ? 0 : -1;
	if (extra != t->extra)
		return extra < t->extra ? -1 : 1;
	return 0;
}

/* per-node view: table of contents, key area and value area bounds */
struct grub_apfs_nview
{
	const grub_uint8_t *buf;
	grub_uint32_t nkeys;
	grub_uint32_t toc;
	grub_uint32_t keys;
	grub_uint32_t end;
	int leaf;
	int fixed;
	int hashed;
};

static grub_err_t
grub_apfs_node_setup(struct grub_apfs_tree *tree, const grub_uint8_t *buf,
	int noheader, int depth, struct grub_apfs_nview *v)
{
	const struct grub_apfs_btnode *n = (const struct grub_apfs_btnode *) buf;
	grub_uint32_t blksz = tree->data->blksz;
	grub_uint32_t flags, entsz;

	if (noheader)
	{
		grub_uint32_t i;

		for (i = 0; i < sizeof(struct grub_apfs_obj_phys); i++)
			if (buf[i])
				return grub_error(GRUB_ERR_BAD_FS, "bad headerless APFS node");
	}
	else
	{
		grub_uint32_t type = grub_le_to_cpu32(n->o.type)
			& GRUB_APFS_OBJECT_TYPE_MASK;

		if (!grub_apfs_checksum_ok(buf, blksz))
			return grub_error(GRUB_ERR_BAD_FS, "APFS node checksum mismatch");
		if (type != GRUB_APFS_OBJECT_TYPE_BTREE
			&& type != GRUB_APFS_OBJECT_TYPE_BTREE_NODE)
			return grub_error(GRUB_ERR_BAD_FS, "not an APFS B-tree node");
		if (grub_le_to_cpu32(n->o.subtype) != tree->subtype)
			return grub_error(GRUB_ERR_BAD_FS, "unexpected APFS B-tree subtype");
	}

	flags = grub_le_to_cpu16(n->flags);
	if (((flags & GRUB_APFS_BTNODE_NOHEADER) != 0) != (noheader != 0))
		return grub_error(GRUB_ERR_BAD_FS, "APFS node header flag mismatch");
	if (((flags & GRUB_APFS_BTNODE_ROOT) != 0) != (depth == 0))
		return grub_error(GRUB_ERR_BAD_FS, "APFS node root flag mismatch");

	v->buf = buf;
	v->leaf = (flags & GRUB_APFS_BTNODE_LEAF) != 0;
	v->fixed = (flags & GRUB_APFS_BTNODE_FIXED_KV_SIZE) != 0;
	v->hashed = (flags & GRUB_APFS_BTNODE_HASHED) != 0;
	v->nkeys = grub_le_to_cpu32(n->nkeys);
	v->toc = sizeof(struct grub_apfs_btnode)
		+ grub_le_to_cpu16(n->table_space.off);
	v->keys = v->toc + grub_le_to_cpu16(n->table_space.len);
	v->end = blksz - ((flags & GRUB_APFS_BTNODE_ROOT)
		? (grub_uint32_t) sizeof(struct grub_apfs_btinfo) : 0);

	entsz = v->fixed ? 4 : 8;
	if (v->toc > v->end || v->keys > v->end || v->keys < v->toc
		|| v->nkeys > (v->keys - v->toc) / entsz)
		return grub_error(GRUB_ERR_BAD_FS, "malformed APFS B-tree node");

	if (flags & GRUB_APFS_BTNODE_ROOT)
	{
		const struct grub_apfs_btinfo *info =
			(const struct grub_apfs_btinfo *) (buf + v->end);

		tree->kfix = grub_le_to_cpu32(info->key_size);
		tree->vfix = grub_le_to_cpu32(info->val_size);
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_apfs_node_key(struct grub_apfs_tree *tree, const struct grub_apfs_nview *v,
	grub_uint32_t i, const grub_uint8_t **key, grub_uint32_t *klen)
{
	grub_uint32_t off, len;

	if (v->fixed)
	{
		const struct grub_apfs_kvoff *e =
			(const struct grub_apfs_kvoff *) (v->buf + v->toc) + i;

		off = v->keys + grub_le_to_cpu16(e->k);
		len = tree->kfix;
		if (!len)
			return grub_error(GRUB_ERR_BAD_FS, "APFS fixed key size missing");
	}
	else
	{
		const struct grub_apfs_kvloc *e =
			(const struct grub_apfs_kvloc *) (v->buf + v->toc) + i;

		off = v->keys + grub_le_to_cpu16(e->k.off);
		len = grub_le_to_cpu16(e->k.len);
	}
	if (off < v->keys || off > v->end || len > v->end - off)
		return grub_error(GRUB_ERR_BAD_FS, "APFS key out of bounds");
	*key = v->buf + off;
	*klen = len;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_apfs_node_val(struct grub_apfs_tree *tree, const struct grub_apfs_nview *v,
	grub_uint32_t i, const grub_uint8_t **val, grub_uint32_t *vlen)
{
	grub_uint32_t voff, len;

	if (v->fixed)
	{
		const struct grub_apfs_kvoff *e =
			(const struct grub_apfs_kvoff *) (v->buf + v->toc) + i;

		voff = grub_le_to_cpu16(e->v);
		len = v->leaf ? tree->vfix : 8;
	}
	else
	{
		const struct grub_apfs_kvloc *e =
			(const struct grub_apfs_kvloc *) (v->buf + v->toc) + i;

		voff = grub_le_to_cpu16(e->v.off);
		len = grub_le_to_cpu16(e->v.len);
	}
	if (voff == GRUB_APFS_BTOFF_INVALID)
	{
		*val = NULL;
		*vlen = 0;
		return GRUB_ERR_NONE;
	}
	if (voff > v->end || len > voff
		|| v->end - voff < sizeof(struct grub_apfs_btnode))
		return grub_error(GRUB_ERR_BAD_FS, "APFS value out of bounds");
	*val = v->buf + (v->end - voff);
	*vlen = len;
	return GRUB_ERR_NONE;
}

static grub_err_t grub_apfs_omap_lookup(struct grub_apfs_data *data,
	grub_uint64_t omap_root, grub_uint64_t oid, grub_uint64_t *paddr,
	int *noheader, int *found);

/* map a child pointer (right after an internal node entry) to a block */
static grub_err_t
grub_apfs_resolve_child(struct grub_apfs_tree *tree,
	const struct grub_apfs_nview *v, const grub_uint8_t *val,
	grub_uint32_t vlen, grub_uint64_t *paddr, int *noheader)
{
	grub_uint64_t oid;

	if (vlen < 8)
		return grub_error(GRUB_ERR_BAD_FS, "APFS child pointer too short");
	oid = grub_le_to_cpu64(grub_get_unaligned64(val));
	if (v->hashed)
		oid += tree->oid_base;
	if (tree->omap_root)
	{
		int found = 0;
		grub_err_t err;

		err = grub_apfs_omap_lookup(tree->data, tree->omap_root, oid,
			paddr, noheader, &found);
		if (err)
			return err;
		if (!found)
			return grub_error(GRUB_ERR_BAD_FS, "APFS virtual object %llu not mapped",
				(unsigned long long) oid);
		return GRUB_ERR_NONE;
	}
	*paddr = oid;
	*noheader = 0;
	return GRUB_ERR_NONE;
}

/*
 * Find the last record whose key sorts <= the target ("floor" search).
 * Key and value are returned as malloc'ed copies.  *FOUND is cleared
 * when every key in the tree sorts above the target; the caller still
 * has to check that the returned key really matches what it wants.
 */
static grub_err_t
grub_apfs_btree_find(struct grub_apfs_tree *tree,
	const struct grub_apfs_key_target *target,
	grub_uint8_t **key_out, grub_uint32_t *klen_out,
	grub_uint8_t **val_out, grub_uint32_t *vlen_out, int *found)
{
	grub_uint8_t *buf;
	grub_uint64_t paddr = tree->root;
	int noheader = tree->root_noheader;
	int depth;
	grub_err_t err = GRUB_ERR_NONE;

	*found = 0;
	buf = grub_malloc(tree->data->blksz);
	if (!buf)
		return grub_errno;

	for (depth = 0; depth < GRUB_APFS_TREE_MAX_DEPTH; depth++)
	{
		struct grub_apfs_nview v;
		const grub_uint8_t *key, *val;
		grub_uint32_t klen, vlen, lo, hi;

		err = grub_apfs_read_block(tree->data, paddr, buf);
		if (err)
			goto fail;
		err = grub_apfs_node_setup(tree, buf, noheader, depth, &v);
		if (err)
			goto fail;

		/* binary search for the last entry <= target */
		lo = 0;
		hi = v.nkeys;
		while (lo < hi)
		{
			grub_uint32_t mid = lo + (hi - lo) / 2;

			err = grub_apfs_node_key(tree, &v, mid, &key, &klen);
			if (err)
				goto fail;
			if (grub_apfs_key_cmp(target, key, klen) <= 0)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (lo == 0)
			goto fail;	/* target below the leftmost key */

		err = grub_apfs_node_val(tree, &v, lo - 1, &val, &vlen);
		if (err)
			goto fail;

		if (v.leaf)
		{
			err = grub_apfs_node_key(tree, &v, lo - 1, &key, &klen);
			if (err)
				goto fail;
			*key_out = grub_malloc(klen ? klen : 1);
			*val_out = grub_malloc(vlen ? vlen : 1);
			if (!*key_out || !*val_out)
			{
				grub_free(*key_out);
				grub_free(*val_out);
				err = grub_errno;
				goto fail;
			}
			grub_memcpy(*key_out, key, klen);
			grub_memcpy(*val_out, val, vlen);
			*klen_out = klen;
			*vlen_out = vlen;
			*found = 1;
			goto fail;	/* success: common cleanup */
		}

		err = grub_apfs_resolve_child(tree, &v, val, vlen, &paddr, &noheader);
		if (err)
			goto fail;
	}
	err = grub_error(GRUB_ERR_BAD_FS, "APFS B-tree too deep");

fail:
	grub_free(buf);
	return err;
}

/* call HOOK for every leaf record matching TARGET, in key order */
static grub_err_t
grub_apfs_btree_iterate_node(struct grub_apfs_tree *tree, grub_uint64_t paddr,
	int noheader, int depth, const struct grub_apfs_key_target *target,
	grub_apfs_rec_hook_t hook, void *ctx, int *stop)
{
	grub_uint8_t *buf;
	struct grub_apfs_nview v;
	grub_uint32_t i;
	grub_err_t err;

	if (depth >= GRUB_APFS_TREE_MAX_DEPTH)
		return grub_error(GRUB_ERR_BAD_FS, "APFS B-tree too deep");

	buf = grub_malloc(tree->data->blksz);
	if (!buf)
		return grub_errno;

	err = grub_apfs_read_block(tree->data, paddr, buf);
	if (err)
		goto fail;
	err = grub_apfs_node_setup(tree, buf, noheader, depth, &v);
	if (err)
		goto fail;

	for (i = 0; i < v.nkeys && !*stop; i++)
	{
		const grub_uint8_t *key, *val;
		grub_uint32_t klen, vlen;
		int c;

		err = grub_apfs_node_key(tree, &v, i, &key, &klen);
		if (err)
			goto fail;
		c = grub_apfs_key_cmp(target, key, klen);

		if (v.leaf)
		{
			if (c < 0)
				continue;
			if (c > 0)
				break;
			err = grub_apfs_node_val(tree, &v, i, &val, &vlen);
			if (err)
				goto fail;
			if (hook(key, klen, val, vlen, ctx))
				*stop = 1;
			continue;
		}

		/* child i spans [key_i, key_i+1): skip subtrees entirely
		   below or above the target range */
		if (c > 0)
			break;
		if (i + 1 < v.nkeys)
		{
			err = grub_apfs_node_key(tree, &v, i + 1, &key, &klen);
			if (err)
				goto fail;
			if (grub_apfs_key_cmp(target, key, klen) < 0)
				continue;
		}
		{
			grub_uint64_t child;
			int child_noheader;

			err = grub_apfs_node_val(tree, &v, i, &val, &vlen);
			if (err)
				goto fail;
			err = grub_apfs_resolve_child(tree, &v, val, vlen,
				&child, &child_noheader);
			if (err)
				goto fail;
			err = grub_apfs_btree_iterate_node(tree, child, child_noheader,
				depth + 1, target, hook, ctx, stop);
			if (err)
				goto fail;
		}
	}

fail:
	grub_free(buf);
	return err;
}

static grub_err_t
grub_apfs_btree_iterate(struct grub_apfs_tree *tree,
	const struct grub_apfs_key_target *target,
	grub_apfs_rec_hook_t hook, void *ctx)
{
	int stop = 0;

	return grub_apfs_btree_iterate_node(tree, tree->root, tree->root_noheader,
		0, target, hook, ctx, &stop);
}

/* look up the newest mapping of a (virtual) object id in an object map */
static grub_err_t
grub_apfs_omap_lookup(struct grub_apfs_data *data, grub_uint64_t omap_root,
	grub_uint64_t oid, grub_uint64_t *paddr, int *noheader, int *found)
{
	struct grub_apfs_tree tree;
	struct grub_apfs_key_target target;
	grub_uint8_t *key = NULL, *val = NULL;
	grub_uint32_t klen, vlen, flags;
	grub_err_t err;

	grub_memset(&tree, 0, sizeof(tree));
	tree.data = data;
	tree.root = omap_root;
	tree.subtype = GRUB_APFS_OBJECT_TYPE_OMAP;

	grub_memset(&target, 0, sizeof(target));
	target.kind = GRUB_APFS_CMP_KIND_OMAP;
	target.mode = GRUB_APFS_MATCH_FLOOR;
	target.id = oid;
	target.extra = ~0ULL;	/* newest transaction */

	*found = 0;
	err = grub_apfs_btree_find(&tree, &target, &key, &klen, &val, &vlen, found);
	if (err || !*found)
		return err;

	*found = 0;
	if (klen >= 16 && vlen >= sizeof(struct grub_apfs_omap_val)
		&& grub_le_to_cpu64(grub_get_unaligned64(key)) == oid)
	{
		const struct grub_apfs_omap_val *ov =
			(const struct grub_apfs_omap_val *) val;

		flags = grub_le_to_cpu32(ov->flags);
		if (!(flags & GRUB_APFS_OMAP_VAL_DELETED))
		{
			*paddr = grub_le_to_cpu64(ov->paddr);
			*noheader = (flags & GRUB_APFS_OMAP_VAL_NOHEADER) != 0;
			*found = 1;
		}
	}
	grub_free(key);
	grub_free(val);
	return GRUB_ERR_NONE;
}

static void
grub_apfs_fs_tree(struct grub_apfs_volume *vol, struct grub_apfs_tree *tree)
{
	grub_memset(tree, 0, sizeof(*tree));
	tree->data = vol->data;
	tree->root = vol->root_paddr;
	tree->root_noheader = vol->root_noheader;
	tree->subtype = GRUB_APFS_OBJECT_TYPE_FSTREE;
	tree->omap_root = vol->omap_root;
	tree->oid_base = vol->root_tree_oid;
}

static void
grub_apfs_extent_tree(struct grub_apfs_volume *vol, struct grub_apfs_tree *tree,
	struct grub_apfs_key_target *target, grub_uint64_t ext_id)
{
	grub_memset(target, 0, sizeof(*target));
	target->id = ext_id;
	if (vol->fext_root)
	{
		grub_memset(tree, 0, sizeof(*tree));
		tree->data = vol->data;
		tree->root = vol->fext_root;
		tree->subtype = GRUB_APFS_OBJECT_TYPE_FEXT_TREE;
		target->kind = GRUB_APFS_CMP_KIND_FEXT;
	}
	else
	{
		grub_apfs_fs_tree(vol, tree);
		target->kind = GRUB_APFS_CMP_KIND_FS;
		target->type = GRUB_APFS_TYPE_FILE_EXTENT;
	}
}

static int
grub_apfs_extent_key_ok(struct grub_apfs_volume *vol, const grub_uint8_t *key,
	grub_uint32_t klen, grub_uint64_t ext_id, grub_uint64_t *laddr)
{
	grub_uint64_t v;

	if (klen < 16)
		return 0;
	v = grub_le_to_cpu64(grub_get_unaligned64(key));
	if (vol->fext_root)
	{
		if (v != ext_id)
			return 0;
	}
	else if ((v & GRUB_APFS_OBJ_ID_MASK) != ext_id
		|| (v >> GRUB_APFS_OBJ_TYPE_SHIFT) != GRUB_APFS_TYPE_FILE_EXTENT)
		return 0;
	*laddr = grub_le_to_cpu64(grub_get_unaligned64(key + 8));
	return 1;
}

struct grub_apfs_next_extent_ctx
{
	grub_uint64_t next;
	int found;
};

static int
grub_apfs_next_extent_hook(const grub_uint8_t *key, grub_uint32_t klen,
	const grub_uint8_t *val __attribute__((unused)),
	grub_uint32_t vlen __attribute__((unused)), void *c)
{
	struct grub_apfs_next_extent_ctx *ctx = c;

	if (klen < 16)
		return 0;
	ctx->next = grub_le_to_cpu64(grub_get_unaligned64(key + 8));
	ctx->found = 1;
	return 1;
}

/*
 * Read POS..POS+LEN of the data stream identified by EXT_ID.  Ranges
 * not covered by an extent (sparse holes) read as zeros.  FILE, when
 * non-NULL, receives read progress.
 */
static grub_err_t
grub_apfs_dstream_read(struct grub_apfs_volume *vol, grub_uint64_t ext_id,
	grub_uint64_t pos, grub_uint64_t len, grub_uint8_t *buf, grub_file_t file)
{
	struct grub_apfs_data *data = vol->data;
	grub_err_t err = GRUB_ERR_NONE;

	while (len)
	{
		struct grub_apfs_tree tree;
		struct grub_apfs_key_target target;
		grub_uint8_t *key = NULL, *val = NULL;
		grub_uint32_t klen, vlen;
		grub_uint64_t estart = 0, elen = 0, phys = 0, chunk;
		int found = 0, have = 0;

		grub_apfs_extent_tree(vol, &tree, &target, ext_id);
		target.mode = GRUB_APFS_MATCH_FLOOR;
		target.extra = pos;
		err = grub_apfs_btree_find(&tree, &target, &key, &klen, &val, &vlen,
			&found);
		if (err)
			return err;
		if (found)
		{
			if (grub_apfs_extent_key_ok(vol, key, klen, ext_id, &estart)
				&& vlen >= 16)
			{
				elen = grub_le_to_cpu64(grub_get_unaligned64(val))
					& GRUB_APFS_FILE_EXTENT_LEN_MASK;
				phys = grub_le_to_cpu64(grub_get_unaligned64(val + 8));
				if (pos >= estart && pos < estart + elen)
					have = 1;
			}
			grub_free(key);
			grub_free(val);
		}

		if (have)
		{
			chunk = estart + elen - pos;
			if (chunk > len)
				chunk = len;
			if (phys)
			{
				if (phys >= data->blocks)
					return grub_error(GRUB_ERR_BAD_FS,
						"APFS extent out of range");
				err = grub_disk_read(data->disk,
					(grub_disk_addr_t) (phys << (data->blklog
						- GRUB_DISK_SECTOR_BITS)),
					pos - estart, (grub_size_t) chunk, buf);
				if (err)
					return err;
			}
			else
				grub_memset(buf, 0, (grub_size_t) chunk);
		}
		else
		{
			/* hole: zero-fill up to the next extent */
			struct grub_apfs_next_extent_ctx nctx;

			grub_memset(&nctx, 0, sizeof(nctx));
			grub_apfs_extent_tree(vol, &tree, &target, ext_id);
			target.mode = GRUB_APFS_MATCH_GE;
			target.extra = pos + 1;
			err = grub_apfs_btree_iterate(&tree, &target,
				grub_apfs_next_extent_hook, &nctx);
			if (err)
				return err;
			chunk = len;
			if (nctx.found && nctx.next - pos < chunk)
				chunk = nctx.next - pos;
			grub_memset(buf, 0, (grub_size_t) chunk);
		}

		if (file && grub_file_progress_hook)
			grub_file_progress_hook(0, 0, (unsigned) chunk, NULL, file);
		pos += chunk;
		buf += chunk;
		len -= chunk;
	}
	return GRUB_ERR_NONE;
}

/* parse the inode record of NODE->ino */
static grub_err_t
grub_apfs_load_inode(struct grub_fshelp_node *node)
{
	struct grub_apfs_tree tree;
	struct grub_apfs_key_target target;
	grub_uint8_t *key = NULL, *val = NULL;
	grub_uint32_t klen, vlen;
	int found = 0;
	grub_err_t err;

	if (node->have_inode)
		return GRUB_ERR_NONE;

	grub_apfs_fs_tree(node->vol, &tree);
	grub_memset(&target, 0, sizeof(target));
	target.kind = GRUB_APFS_CMP_KIND_FS;
	target.mode = GRUB_APFS_MATCH_PREFIX;
	target.id = node->ino;
	target.type = GRUB_APFS_TYPE_INODE;

	err = grub_apfs_btree_find(&tree, &target, &key, &klen, &val, &vlen, &found);
	if (err)
		return err;
	if (found)
	{
		grub_uint64_t v = klen >= 8
			? grub_le_to_cpu64(grub_get_unaligned64(key)) : 0;

		if ((v & GRUB_APFS_OBJ_ID_MASK) != node->ino
			|| (v >> GRUB_APFS_OBJ_TYPE_SHIFT) != GRUB_APFS_TYPE_INODE)
			found = 0;
	}
	if (!found || vlen < sizeof(struct grub_apfs_inode_val))
	{
		grub_free(key);
		grub_free(val);
		return grub_error(GRUB_ERR_FILE_NOT_FOUND, "APFS inode %llu not found",
			(unsigned long long) node->ino);
	}

	{
		const struct grub_apfs_inode_val *ino =
			(const struct grub_apfs_inode_val *) val;

		node->private_id = grub_le_to_cpu64(ino->private_id);
		node->mtime_ns = grub_le_to_cpu64(ino->mod_time);
		node->internal_flags = grub_le_to_cpu64(ino->internal_flags);
		node->bsd_flags = grub_le_to_cpu32(ino->bsd_flags);
		node->mode = grub_le_to_cpu16(ino->mode);
		node->size = 0;
	}

	/* extended fields: pick up the data stream size */
	if (vlen >= sizeof(struct grub_apfs_inode_val) + sizeof(struct grub_apfs_xf_blob))
	{
		const grub_uint8_t *xf = val + sizeof(struct grub_apfs_inode_val);
		grub_uint32_t xflen = vlen - (grub_uint32_t) sizeof(struct grub_apfs_inode_val);
		grub_uint32_t num = grub_le_to_cpu16(
			((const struct grub_apfs_xf_blob *) xf)->num_exts);
		grub_uint32_t doff = (grub_uint32_t) sizeof(struct grub_apfs_xf_blob)
			+ num * (grub_uint32_t) sizeof(struct grub_apfs_x_field);
		grub_uint32_t i;

		for (i = 0; i < num && doff <= xflen; i++)
		{
			const struct grub_apfs_x_field *f =
				(const struct grub_apfs_x_field *) (xf
					+ sizeof(struct grub_apfs_xf_blob)) + i;
			grub_uint32_t fsize = grub_le_to_cpu16(f->size);

			if ((const grub_uint8_t *) (f + 1) > xf + xflen
				|| fsize > xflen - doff)
				break;
			if (f->type == GRUB_APFS_INO_EXT_TYPE_DSTREAM
				&& fsize >= sizeof(struct grub_apfs_dstream))
			{
				const struct grub_apfs_dstream *ds =
					(const struct grub_apfs_dstream *) (xf + doff);

				node->size = grub_le_to_cpu64(ds->size);
				break;
			}
			doff += (fsize + 7) & ~7U;
		}
	}

	node->have_inode = 1;
	grub_free(key);
	grub_free(val);
	return GRUB_ERR_NONE;
}

/* result of an extended-attribute lookup */
struct grub_apfs_xattr_res
{
	grub_uint8_t *data;		/* embedded payload (malloc'ed) */
	grub_uint32_t len;
	int is_stream;
	grub_uint64_t stream_id;
	grub_uint64_t stream_size;
};

struct grub_apfs_xattr_ctx
{
	const char *name;
	grub_size_t name_len;		/* strlen + 1 */
	struct grub_apfs_xattr_res *res;
	int found;
	grub_err_t err;
};

static int
grub_apfs_xattr_hook(const grub_uint8_t *key, grub_uint32_t klen,
	const grub_uint8_t *val, grub_uint32_t vlen, void *c)
{
	struct grub_apfs_xattr_ctx *ctx = c;
	grub_uint32_t nlen, flags, xlen;

	if (klen < 10)
		return 0;
	nlen = grub_le_to_cpu16(grub_get_unaligned16(key + 8));
	if (nlen != ctx->name_len || klen < 10 + nlen
		|| grub_memcmp(key + 10, ctx->name, nlen) != 0)
		return 0;

	if (vlen < sizeof(struct grub_apfs_xattr_val))
		return 0;
	flags = grub_le_to_cpu16(((const struct grub_apfs_xattr_val *) val)->flags);
	xlen = grub_le_to_cpu16(((const struct grub_apfs_xattr_val *) val)->xdata_len);
	val += sizeof(struct grub_apfs_xattr_val);
	vlen -= (grub_uint32_t) sizeof(struct grub_apfs_xattr_val);
	if (xlen > vlen)
		return 0;

	if (flags & GRUB_APFS_XATTR_DATA_EMBEDDED)
	{
		ctx->res->data = grub_malloc(xlen ? xlen : 1);
		if (!ctx->res->data)
		{
			ctx->err = grub_errno;
			return 1;
		}
		grub_memcpy(ctx->res->data, val, xlen);
		ctx->res->len = xlen;
		ctx->found = 1;
		return 1;
	}
	if (flags & GRUB_APFS_XATTR_DATA_STREAM)
	{
		const struct grub_apfs_xattr_dstream *xs =
			(const struct grub_apfs_xattr_dstream *) val;

		if (xlen < sizeof(*xs))
			return 0;
		ctx->res->is_stream = 1;
		ctx->res->stream_id = grub_le_to_cpu64(xs->xattr_obj_id);
		ctx->res->stream_size = grub_le_to_cpu64(xs->dstream.size);
		ctx->found = 1;
		return 1;
	}
	return 0;
}

static grub_err_t
grub_apfs_xattr_get(struct grub_apfs_volume *vol, grub_uint64_t ino,
	const char *name, struct grub_apfs_xattr_res *res, int *found)
{
	struct grub_apfs_tree tree;
	struct grub_apfs_key_target target;
	struct grub_apfs_xattr_ctx ctx;
	grub_err_t err;

	grub_memset(res, 0, sizeof(*res));
	grub_memset(&ctx, 0, sizeof(ctx));
	ctx.name = name;
	ctx.name_len = grub_strlen(name) + 1;
	ctx.res = res;

	grub_apfs_fs_tree(vol, &tree);
	grub_memset(&target, 0, sizeof(target));
	target.kind = GRUB_APFS_CMP_KIND_FS;
	target.mode = GRUB_APFS_MATCH_PREFIX;
	target.id = ino;
	target.type = GRUB_APFS_TYPE_XATTR;

	err = grub_apfs_btree_iterate(&tree, &target, grub_apfs_xattr_hook, &ctx);
	if (!err && ctx.err)
		err = ctx.err;
	*found = ctx.found;
	return err;
}

/* read a whole xattr (embedded or streamed) into a malloc'ed buffer */
static grub_err_t
grub_apfs_xattr_read_all(struct grub_apfs_volume *vol,
	struct grub_apfs_xattr_res *res, grub_uint8_t **buf, grub_uint32_t *len)
{
	grub_err_t err;

	if (!res->is_stream)
	{
		*buf = res->data;
		*len = res->len;
		res->data = NULL;	/* ownership transferred */
		return GRUB_ERR_NONE;
	}
	if (res->stream_size > GRUB_APFS_MAX_META_SIZE)
		return grub_error(GRUB_ERR_BAD_FS, "APFS xattr stream too large");
	*len = (grub_uint32_t) res->stream_size;
	*buf = grub_malloc(*len ? *len : 1);
	if (!*buf)
		return grub_errno;
	err = grub_apfs_dstream_read(vol, res->stream_id, 0, *len, *buf, NULL);
	if (err)
		grub_free(*buf);
	return err;
}

/* decmpfs (compressed file) state, hanging off an open file */
struct grub_apfs_cmp
{
	grub_uint32_t algo;
	grub_uint64_t size;		/* uncompressed size */
	grub_uint8_t *attr;		/* whole com.apple.decmpfs xattr */
	grub_uint32_t attr_len;
	struct grub_apfs_xattr_res rsrc;	/* resource fork, if used */
	int have_rsrc;
	grub_uint8_t *cbuf;		/* one decompressed 64 KiB block */
	grub_uint64_t cbuf_block;
	grub_uint32_t cbuf_len;
	void *scratch;			/* lzfse decoder scratch */
};

struct grub_apfs_file
{
	struct grub_apfs_data *data;
	struct grub_apfs_volume *vol;
	grub_uint64_t ino;
	grub_uint64_t private_id;
	struct grub_apfs_cmp *cmp;	/* NULL = plain data stream */
};

/* read from the resource fork xattr (stream or embedded) */
static grub_err_t
grub_apfs_rsrc_read(struct grub_apfs_file *f, grub_uint64_t off,
	grub_uint64_t len, grub_uint8_t *buf)
{
	struct grub_apfs_cmp *cmp = f->cmp;

	if (cmp->rsrc.is_stream)
	{
		if (off > cmp->rsrc.stream_size
			|| len > cmp->rsrc.stream_size - off)
			return grub_error(GRUB_ERR_BAD_FS, "APFS resource fork overrun");
		return grub_apfs_dstream_read(f->vol, cmp->rsrc.stream_id, off, len,
			buf, NULL);
	}
	if (off > cmp->rsrc.len || len > cmp->rsrc.len - off)
		return grub_error(GRUB_ERR_BAD_FS, "APFS resource fork overrun");
	grub_memcpy(buf, cmp->rsrc.data + off, (grub_size_t) len);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_apfs_cmp_decompress(struct grub_apfs_cmp *cmp, const grub_uint8_t *cdata,
	grub_uint32_t csize, grub_uint32_t bsize)
{
	if (!csize)
		return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA, "empty decmpfs block");

	switch (cmp->algo)
	{
	case GRUB_APFS_COMPRESS_ZLIB_ATTR:
	case GRUB_APFS_COMPRESS_ZLIB_RSRC:
		if ((cdata[0] & 0x0F) == 0x0F)
			goto stored;
		{
			grub_ssize_t n = grub_zlib_decompress((char *) cdata, csize, 0,
				(char *) cmp->cbuf, bsize);

			if (n < 0)
				return grub_errno;
			cmp->cbuf_len = (grub_uint32_t) n;
		}
		break;

	case GRUB_APFS_COMPRESS_LZVN_ATTR:
	case GRUB_APFS_COMPRESS_LZVN_RSRC:
		if (cdata[0] == 0x06)
			goto stored;
		{
			lzvn_decoder_state st;

			grub_memset(&st, 0, sizeof(st));
			st.src = cdata;
			st.src_end = cdata + csize;
			st.dst = st.dst_begin = cmp->cbuf;
			st.dst_end = cmp->cbuf + bsize;
			lzvn_decode(&st);
			cmp->cbuf_len = (grub_uint32_t) (st.dst - cmp->cbuf);
		}
		break;

	case GRUB_APFS_COMPRESS_LZFSE_ATTR:
	case GRUB_APFS_COMPRESS_LZFSE_RSRC:
		if (cdata[0] != 0x62)	/* not "bvx?" -- stored with escape byte */
			goto stored;
		{
			grub_size_t n;

			if (!cmp->scratch)
			{
				cmp->scratch = grub_malloc(lzfse_decode_scratch_size());
				if (!cmp->scratch)
					return grub_errno;
			}
			n = lzfse_decode_buffer(cmp->cbuf, bsize, cdata, csize,
				cmp->scratch);
			if (!n)
				return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA,
					"lzfse decompression failed");
			cmp->cbuf_len = (grub_uint32_t) n;
		}
		break;

	case GRUB_APFS_COMPRESS_LZBITMAP_ATTR:
	case GRUB_APFS_COMPRESS_LZBITMAP_RSRC:
		if (cdata[0] == 0x5A)	/* "ZBM" */
		{
			grub_size_t out = 0;

			if (zbm_decompress(cmp->cbuf, bsize, cdata, csize, &out) < 0)
				return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA,
					"lzbitmap decompression failed");
			cmp->cbuf_len = (grub_uint32_t) out;
			break;
		}
		if ((cdata[0] & 0x0F) == 0x0F)
			goto stored;
		return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA,
			"bad lzbitmap escape byte");

	case GRUB_APFS_COMPRESS_PLAIN_ATTR:
	case GRUB_APFS_COMPRESS_PLAIN_RSRC:
		goto stored;

	default:
		return grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
			"decmpfs algorithm %u not supported", cmp->algo);
	}
	return GRUB_ERR_NONE;

stored:
	{
		grub_uint32_t n = csize - 1;

		if (n > bsize)
			n = bsize;
		grub_memcpy(cmp->cbuf, cdata + 1, n);
		cmp->cbuf_len = n;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_apfs_cmp_load_block(struct grub_apfs_file *f, grub_uint64_t blk)
{
	struct grub_apfs_cmp *cmp = f->cmp;
	grub_uint32_t bsize;
	grub_err_t err;

	if (cmp->cbuf_block == blk)
		return GRUB_ERR_NONE;

	bsize = GRUB_APFS_CMP_BLOCK;
	if (cmp->size - (blk << 16) < bsize)
		bsize = (grub_uint32_t) (cmp->size - (blk << 16));

	if (cmp->algo & 1)
	{
		/* *_ATTR: the whole file lives in the decmpfs xattr */
		if (blk != 0 || cmp->size > GRUB_APFS_CMP_BLOCK)
			return grub_error(GRUB_ERR_BAD_FS,
				"decmpfs inline data too large");
		err = grub_apfs_cmp_decompress(cmp,
			cmp->attr + sizeof(struct grub_apfs_cmp_hdr),
			cmp->attr_len - (grub_uint32_t) sizeof(struct grub_apfs_cmp_hdr),
			bsize);
		if (err)
			return err;
	}
	else
	{
		grub_uint32_t coffs, csize;
		grub_uint8_t *cdata;

		if (cmp->algo == GRUB_APFS_COMPRESS_ZLIB_RSRC
			|| cmp->algo == GRUB_APFS_COMPRESS_PLAIN_RSRC)
		{
			/* HFS-style resource layout */
			struct grub_apfs_rsrc_hdr hdr;
			grub_uint32_t doffs, cnt[2], desc[2];

			err = grub_apfs_rsrc_read(f, 0, sizeof(hdr),
				(grub_uint8_t *) &hdr);
			if (err)
				return err;
			doffs = grub_be_to_cpu32(hdr.data_offs);
			err = grub_apfs_rsrc_read(f, doffs, sizeof(cnt),
				(grub_uint8_t *) cnt);
			if (err)
				return err;
			if (blk >= grub_le_to_cpu32(cnt[1]))
				return grub_error(GRUB_ERR_BAD_FS,
					"decmpfs block out of range");
			err = grub_apfs_rsrc_read(f, doffs + 8 + 8 * blk, sizeof(desc),
				(grub_uint8_t *) desc);
			if (err)
				return err;
			coffs = doffs + grub_le_to_cpu32(desc[0]) + 4;
			csize = grub_le_to_cpu32(desc[1]);
		}
		else
		{
			/* flat table of little-endian block offsets */
			grub_uint32_t offs[2];

			err = grub_apfs_rsrc_read(f, 4 * blk, sizeof(offs),
				(grub_uint8_t *) offs);
			if (err)
				return err;
			coffs = grub_le_to_cpu32(offs[0]);
			if (grub_le_to_cpu32(offs[1]) <= coffs)
				return grub_error(GRUB_ERR_BAD_FS,
					"bad decmpfs block table");
			csize = grub_le_to_cpu32(offs[1]) - coffs;
		}

		if (!csize || csize > GRUB_APFS_MAX_CDATA_SIZE)
			return grub_error(GRUB_ERR_BAD_FS, "bad decmpfs block size");
		cdata = grub_malloc(csize);
		if (!cdata)
			return grub_errno;
		err = grub_apfs_rsrc_read(f, coffs, csize, cdata);
		if (!err)
			err = grub_apfs_cmp_decompress(cmp, cdata, csize, bsize);
		grub_free(cdata);
		if (err)
			return err;
	}

	if (cmp->cbuf_len < bsize)
		return grub_error(GRUB_ERR_BAD_COMPRESSED_DATA,
			"decmpfs block decompressed short");
	cmp->cbuf_block = blk;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_apfs_cmp_read(grub_file_t file, struct grub_apfs_file *f,
	grub_uint8_t *buf, grub_uint64_t pos, grub_uint64_t len)
{
	struct grub_apfs_cmp *cmp = f->cmp;
	grub_err_t err;

	while (len)
	{
		grub_uint64_t blk = pos >> 16;
		grub_uint32_t boff = (grub_uint32_t) (pos & (GRUB_APFS_CMP_BLOCK - 1));
		grub_uint64_t chunk = GRUB_APFS_CMP_BLOCK - boff;

		if (chunk > len)
			chunk = len;
		err = grub_apfs_cmp_load_block(f, blk);
		if (err)
			return err;
		grub_memcpy(buf, cmp->cbuf + boff, (grub_size_t) chunk);
		if (grub_file_progress_hook)
			grub_file_progress_hook(0, 0, (unsigned) chunk, NULL, file);
		pos += chunk;
		buf += chunk;
		len -= chunk;
	}
	return GRUB_ERR_NONE;
}

/* set up decmpfs state for an open file; FILE->size gets the real size */
static grub_err_t
grub_apfs_cmp_setup(grub_file_t file, struct grub_apfs_file *f)
{
	struct grub_apfs_xattr_res dec;
	struct grub_apfs_cmp *cmp = NULL;
	grub_uint8_t *attr = NULL;
	grub_uint32_t attr_len = 0;
	const struct grub_apfs_cmp_hdr *hdr;
	int found = 0;
	grub_err_t err;

	err = grub_apfs_xattr_get(f->vol, f->ino, GRUB_APFS_XATTR_DECMPFS, &dec,
		&found);
	if (err)
		return err;
	if (!found)
		return GRUB_ERR_NONE;	/* fall back to the plain data stream */

	err = grub_apfs_xattr_read_all(f->vol, &dec, &attr, &attr_len);
	grub_free(dec.data);
	if (err)
		return err;
	if (attr_len < sizeof(*hdr))
	{
		err = grub_error(GRUB_ERR_BAD_FS, "short decmpfs header");
		goto fail;
	}
	hdr = (const struct grub_apfs_cmp_hdr *) attr;
	if (grub_le_to_cpu32(hdr->signature) != GRUB_APFS_CMP_MAGIC)
	{
		err = grub_error(GRUB_ERR_BAD_FS, "bad decmpfs signature");
		goto fail;
	}

	cmp = grub_zalloc(sizeof(*cmp));
	if (!cmp)
	{
		err = grub_errno;
		goto fail;
	}
	cmp->algo = grub_le_to_cpu32(hdr->algo);
	cmp->size = grub_le_to_cpu64(hdr->size);
	cmp->attr = attr;
	cmp->attr_len = attr_len;
	cmp->cbuf_block = ~0ULL;

	switch (cmp->algo)
	{
	case GRUB_APFS_COMPRESS_ZLIB_ATTR:
	case GRUB_APFS_COMPRESS_ZLIB_RSRC:
	case GRUB_APFS_COMPRESS_LZVN_ATTR:
	case GRUB_APFS_COMPRESS_LZVN_RSRC:
	case GRUB_APFS_COMPRESS_PLAIN_ATTR:
	case GRUB_APFS_COMPRESS_PLAIN_RSRC:
	case GRUB_APFS_COMPRESS_LZFSE_ATTR:
	case GRUB_APFS_COMPRESS_LZFSE_RSRC:
	case GRUB_APFS_COMPRESS_LZBITMAP_ATTR:
	case GRUB_APFS_COMPRESS_LZBITMAP_RSRC:
		break;
	default:
		err = grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
			"decmpfs algorithm %u not supported", cmp->algo);
		goto fail;
	}

	if (!(cmp->algo & 1))
	{
		/* *_RSRC: compressed data lives in the resource fork */
		err = grub_apfs_xattr_get(f->vol, f->ino, GRUB_APFS_XATTR_RSRC,
			&cmp->rsrc, &found);
		if (err)
			goto fail;
		if (!found)
		{
			err = grub_error(GRUB_ERR_BAD_FS,
				"compressed file has no resource fork");
			goto fail;
		}
		cmp->have_rsrc = 1;
	}

	cmp->cbuf = grub_malloc(GRUB_APFS_CMP_BLOCK);
	if (!cmp->cbuf)
	{
		err = grub_errno;
		goto fail;
	}

	f->cmp = cmp;
	file->size = cmp->size;
	return GRUB_ERR_NONE;

fail:
	if (cmp)
	{
		grub_free(cmp->rsrc.data);
		grub_free(cmp->cbuf);
		grub_free(cmp);
	}
	grub_free(attr);
	return err;
}

/* --- directory iteration ------------------------------------------- */

struct grub_apfs_dir_rec_ctx
{
	struct grub_fshelp_node *dir;
	grub_fshelp_iterate_dir_hook_t hook;
	void *hook_data;
	int called;
	grub_err_t err;
};

static int
grub_apfs_dir_rec(const grub_uint8_t *key, grub_uint32_t klen,
	const grub_uint8_t *val, grub_uint32_t vlen, void *c)
{
	struct grub_apfs_dir_rec_ctx *ctx = c;
	struct grub_apfs_volume *vol = ctx->dir->vol;
	const struct grub_apfs_drec_val *drec;
	struct grub_fshelp_node *node;
	const grub_uint8_t *name;
	grub_uint32_t noff, nlen;
	int ftype;

	noff = vol->hashed_names ? 12 : 10;
	if (klen < noff)
		return 0;
	if (vol->hashed_names)
		nlen = grub_le_to_cpu32(grub_get_unaligned32(key + 8))
			& GRUB_APFS_DREC_LEN_MASK;
	else
		nlen = grub_le_to_cpu16(grub_get_unaligned16(key + 8));
	if (!nlen || nlen > klen - noff)
		return 0;
	name = key + noff;
	if (name[nlen - 1] != '\0')
		return 0;

	if (vlen < sizeof(*drec))
		return 0;
	drec = (const struct grub_apfs_drec_val *) val;

	switch (grub_le_to_cpu16(drec->flags) & 0xF)
	{
	case GRUB_APFS_DT_DIR:
		ftype = GRUB_FSHELP_DIR;
		break;
	case GRUB_APFS_DT_LNK:
		ftype = GRUB_FSHELP_SYMLINK;
		break;
	case GRUB_APFS_DT_REG:
		ftype = GRUB_FSHELP_REG;
		break;
	default:
		ftype = GRUB_FSHELP_UNKNOWN;
		break;
	}
	if (vol->case_insensitive)
		ftype |= GRUB_FSHELP_CASE_INSENSITIVE;

	node = grub_zalloc(sizeof(*node));
	if (!node)
	{
		ctx->err = grub_errno;
		return 1;
	}
	node->data = ctx->dir->data;
	node->vol = vol;
	node->ino = grub_le_to_cpu64(drec->file_id);

	if (ctx->hook((const char *) name, (enum grub_fshelp_filetype) ftype,
		node, ctx->hook_data))
	{
		ctx->called = 1;
		return 1;
	}
	return 0;
}

static int
grub_apfs_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_apfs_tree tree;
	struct grub_apfs_key_target target;
	struct grub_apfs_dir_rec_ctx ctx;

	if (!dir->vol)
	{
		/* container root: one directory per volume */
		grub_uint32_t i;

		for (i = 0; i < dir->data->nvols; i++)
		{
			struct grub_fshelp_node *node = grub_zalloc(sizeof(*node));

			if (!node)
				return 0;
			node->data = dir->data;
			node->vol = &dir->data->vols[i];
			node->ino = GRUB_APFS_ROOT_DIR_INO;
			if (hook(node->vol->name, GRUB_FSHELP_DIR, node, hook_data))
				return 1;
		}
		return 0;
	}

	grub_memset(&ctx, 0, sizeof(ctx));
	ctx.dir = dir;
	ctx.hook = hook;
	ctx.hook_data = hook_data;

	grub_apfs_fs_tree(dir->vol, &tree);
	grub_memset(&target, 0, sizeof(target));
	target.kind = GRUB_APFS_CMP_KIND_FS;
	target.mode = GRUB_APFS_MATCH_PREFIX;
	target.id = dir->ino;
	target.type = GRUB_APFS_TYPE_DIR_REC;

	grub_apfs_btree_iterate(&tree, &target, grub_apfs_dir_rec, &ctx);
	if (ctx.err && !grub_errno)
		grub_errno = ctx.err;
	return ctx.called;
}

static char *
grub_apfs_read_symlink(grub_fshelp_node_t node)
{
	struct grub_apfs_xattr_res res;
	char *target = NULL;
	int found = 0;

	if (grub_apfs_xattr_get(node->vol, node->ino, GRUB_APFS_XATTR_SYMLINK,
		&res, &found) || !found)
	{
		grub_free(res.data);
		if (!grub_errno)
			grub_error(GRUB_ERR_SYMLINK_LOOP, "APFS symlink target missing");
		return NULL;
	}

	if (!res.is_stream)
	{
		target = grub_malloc(res.len + 1);
		if (target)
		{
			grub_memcpy(target, res.data, res.len);
			target[res.len] = '\0';
		}
		grub_free(res.data);
		return target;
	}

	if (res.stream_size > 0x10000)
	{
		grub_error(GRUB_ERR_BAD_FS, "APFS symlink target too long");
		return NULL;
	}
	target = grub_malloc((grub_size_t) res.stream_size + 1);
	if (!target)
		return NULL;
	if (grub_apfs_dstream_read(node->vol, res.stream_id, 0, res.stream_size,
		(grub_uint8_t *) target, NULL))
	{
		grub_free(target);
		return NULL;
	}
	target[res.stream_size] = '\0';
	return target;
}

/* --- mount / unmount ------------------------------------------------ */

static void
grub_apfs_unmount(struct grub_apfs_data *data)
{
	grub_uint32_t i;

	if (!data)
		return;
	for (i = 0; i < data->nvols; i++)
		grub_free(data->vols[i].name);
	grub_free(data->vols);
	grub_free(data);
}

/* read and validate an object-map object, returning its tree root */
static grub_err_t
grub_apfs_read_omap(struct grub_apfs_data *data, grub_uint64_t paddr,
	grub_uint8_t *blkbuf, grub_uint64_t *tree_root)
{
	const struct grub_apfs_omap_phys *om;
	grub_err_t err;

	err = grub_apfs_read_block(data, paddr, blkbuf);
	if (err)
		return err;
	om = (const struct grub_apfs_omap_phys *) blkbuf;
	if (!grub_apfs_checksum_ok(blkbuf, data->blksz)
		|| (grub_le_to_cpu32(om->o.type) & GRUB_APFS_OBJECT_TYPE_MASK)
			!= GRUB_APFS_OBJECT_TYPE_OMAP)
		return grub_error(GRUB_ERR_BAD_FS, "bad APFS object map");
	*tree_root = grub_le_to_cpu64(om->tree_oid);
	if (*tree_root >= data->blocks)
		return grub_error(GRUB_ERR_BAD_FS, "APFS object map root out of range");
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_apfs_add_volume(struct grub_apfs_data *data, grub_uint64_t fs_oid,
	grub_uint8_t *blkbuf)
{
	const struct grub_apfs_vol_super *vsb;
	struct grub_apfs_volume *vol;
	grub_uint64_t paddr, omap_root, root_paddr;
	grub_uint32_t i, fext_type;
	int noheader, found = 0, root_noheader = 0;
	char *name;
	grub_err_t err;

	err = grub_apfs_omap_lookup(data, data->omap_root, fs_oid, &paddr,
		&noheader, &found);
	if (err || !found)
		return err ? err : grub_error(GRUB_ERR_BAD_FS, "volume not in object map");

	err = grub_apfs_read_block(data, paddr, blkbuf);
	if (err)
		return err;
	vsb = (const struct grub_apfs_vol_super *) blkbuf;
	if (!grub_apfs_checksum_ok(blkbuf, data->blksz)
		|| grub_le_to_cpu32(vsb->magic) != GRUB_APFS_APSB_MAGIC
		|| (grub_le_to_cpu32(vsb->o.type) & GRUB_APFS_OBJECT_TYPE_MASK)
			!= GRUB_APFS_OBJECT_TYPE_FS)
		return grub_error(GRUB_ERR_BAD_FS, "bad APFS volume superblock");

	if (!(grub_le_to_cpu64(vsb->fs_flags) & GRUB_APFS_FS_UNENCRYPTED))
		return grub_error(GRUB_ERR_BAD_FS, "encrypted APFS volume");

	vol = &data->vols[data->nvols];
	grub_memset(vol, 0, sizeof(*vol));
	vol->data = data;
	vol->root_tree_oid = grub_le_to_cpu64(vsb->root_tree_oid);
	{
		grub_uint64_t incompat = grub_le_to_cpu64(vsb->incompat_features);

		vol->case_insensitive =
			(incompat & GRUB_APFS_INCOMPAT_CASE_INSENSITIVE) != 0;
		vol->hashed_names = (incompat
			& (GRUB_APFS_INCOMPAT_CASE_INSENSITIVE
				| GRUB_APFS_INCOMPAT_NORM_INSENSITIVE)) != 0;
	}
	vol->mtime = (grub_int64_t) (grub_le_to_cpu64(vsb->last_mod_time)
		/ 1000000000ULL);

	fext_type = grub_le_to_cpu32(vsb->fext_tree_type);
	if (vsb->fext_tree_oid && (fext_type & GRUB_APFS_OBJ_PHYSICAL))
	{
		vol->fext_root = grub_le_to_cpu64(vsb->fext_tree_oid);
		if (vol->fext_root >= data->blocks)
			return grub_error(GRUB_ERR_BAD_FS, "APFS fext tree out of range");
	}

	/* the volume name is used as a path component: make it usable */
	name = grub_malloc(sizeof(vsb->volname) + 16);
	if (!name)
		return grub_errno;
	grub_memcpy(name, vsb->volname, sizeof(vsb->volname));
	name[sizeof(vsb->volname) - 1] = '\0';
	if (!name[0])
		grub_snprintf(name, sizeof(vsb->volname), "Volume%u",
			grub_le_to_cpu32(vsb->fs_index));
	for (i = 0; name[i]; i++)
		if (name[i] == '/')
			name[i] = '_';
	for (i = 0; i < data->nvols; i++)
		if (grub_strcmp(data->vols[i].name, name) == 0)
		{
			grub_size_t l = grub_strlen(name);

			grub_snprintf(name + l, 16, " (%u)",
				grub_le_to_cpu32(vsb->fs_index));
			break;
		}
	vol->name = name;

	/* volume object map, then the fs tree root through it (blkbuf is
	   reused, so pull everything needed from vsb first) */
	err = grub_apfs_read_omap(data, grub_le_to_cpu64(vsb->omap_oid), blkbuf,
		&omap_root);
	if (err)
		goto fail;
	vol->omap_root = omap_root;

	found = 0;
	err = grub_apfs_omap_lookup(data, vol->omap_root, vol->root_tree_oid,
		&root_paddr, &root_noheader, &found);
	if (err)
		goto fail;
	if (!found)
	{
		err = grub_error(GRUB_ERR_BAD_FS, "APFS root tree not in object map");
		goto fail;
	}
	vol->root_paddr = root_paddr;
	vol->root_noheader = root_noheader;

	data->nvols++;
	return GRUB_ERR_NONE;

fail:
	grub_free(vol->name);
	vol->name = NULL;
	return err;
}

static struct grub_apfs_data *
grub_apfs_mount(grub_disk_t disk)
{
	struct grub_apfs_data *data = NULL;
	struct grub_apfs_nx_super hdr;
	grub_uint8_t *sb = NULL, *scan = NULL;
	const struct grub_apfs_nx_super *nxsb;
	grub_uint32_t blksz, desc_blocks, maxfs, i;
	grub_uint64_t best_xid;

	/* the superblock header fits in the smallest legal block */
	if (grub_disk_read(disk, 0, 0, sizeof(hdr), &hdr))
		goto fail;
	if (grub_le_to_cpu32(hdr.magic) != GRUB_APFS_NX_MAGIC)
	{
		grub_error(GRUB_ERR_BAD_FS, "not an APFS filesystem");
		goto fail;
	}
	blksz = grub_le_to_cpu32(hdr.block_size);
	if (blksz < 4096 || blksz > 65536 || (blksz & (blksz - 1)))
	{
		grub_error(GRUB_ERR_BAD_FS, "invalid APFS block size");
		goto fail;
	}

	data = grub_zalloc(sizeof(*data));
	if (!data)
		goto fail;
	data->disk = disk;
	data->blksz = blksz;
	for (data->blklog = 12; (1U << data->blklog) != blksz; data->blklog++)
		;
	data->blocks = grub_le_to_cpu64(hdr.block_count);

	sb = grub_malloc(blksz);
	scan = grub_malloc(blksz);
	if (!sb || !scan)
		goto fail;

	if (grub_disk_read(disk, 0, 0, blksz, sb))
		goto fail;
	nxsb = (const struct grub_apfs_nx_super *) sb;
	if (!grub_apfs_checksum_ok(sb, blksz)
		|| (grub_le_to_cpu32(nxsb->o.type) & GRUB_APFS_OBJECT_TYPE_MASK)
			!= GRUB_APFS_OBJECT_TYPE_NX_SUPERBLOCK)
	{
		grub_error(GRUB_ERR_BAD_FS, "bad APFS container superblock");
		goto fail;
	}
	best_xid = grub_le_to_cpu64(nxsb->o.xid);

	/* block 0 may be stale: scan the checkpoint descriptor area for
	   the newest valid container superblock */
	desc_blocks = grub_le_to_cpu32(nxsb->xp_desc_blocks);
	if (!(desc_blocks & 0x80000000U)
		&& desc_blocks <= GRUB_APFS_MAX_XP_DESC_BLOCKS)
	{
		grub_uint64_t base = grub_le_to_cpu64(nxsb->xp_desc_base);

		for (i = 0; i < desc_blocks; i++)
		{
			const struct grub_apfs_nx_super *cand =
				(const struct grub_apfs_nx_super *) scan;

			if (base + i >= data->blocks
				|| grub_apfs_read_block(data, base + i, scan))
				break;
			if ((grub_le_to_cpu32(cand->o.type)
					& GRUB_APFS_OBJECT_TYPE_MASK)
					!= GRUB_APFS_OBJECT_TYPE_NX_SUPERBLOCK
				|| grub_le_to_cpu32(cand->magic) != GRUB_APFS_NX_MAGIC
				|| grub_le_to_cpu32(cand->block_size) != blksz
				|| grub_le_to_cpu64(cand->o.xid) <= best_xid
				|| !grub_apfs_checksum_ok(scan, blksz))
				continue;
			grub_memcpy(sb, scan, blksz);
			best_xid = grub_le_to_cpu64(cand->o.xid);
		}
		grub_errno = GRUB_ERR_NONE;
	}

	grub_memcpy(data->uuid, nxsb->uuid, sizeof(data->uuid));

	/* container object map */
	if (grub_apfs_read_omap(data, grub_le_to_cpu64(nxsb->omap_oid), scan,
		&data->omap_root))
		goto fail;

	maxfs = grub_le_to_cpu32(nxsb->max_file_systems);
	if (maxfs > GRUB_APFS_MAX_FILE_SYSTEMS)
		maxfs = GRUB_APFS_MAX_FILE_SYSTEMS;
	data->vols = grub_calloc(maxfs ? maxfs : 1, sizeof(*data->vols));
	if (!data->vols)
		goto fail;

	for (i = 0; i < maxfs; i++)
	{
		grub_uint64_t fs_oid = grub_le_to_cpu64(nxsb->fs_oid[i]);

		if (!fs_oid)
			continue;
		/* skip volumes we cannot read (e.g. FileVault) */
		if (grub_apfs_add_volume(data, fs_oid, scan))
			grub_errno = GRUB_ERR_NONE;
	}
	if (!data->nvols)
	{
		grub_error(GRUB_ERR_BAD_FS, "no readable APFS volume");
		goto fail;
	}

	data->rootnode.data = data;
	grub_free(sb);
	grub_free(scan);
	return data;

fail:
	if (!grub_errno)
		grub_error(GRUB_ERR_BAD_FS, "not an APFS filesystem");
	grub_free(sb);
	grub_free(scan);
	grub_apfs_unmount(data);
	return NULL;
}

/* --- grub_fs interface ---------------------------------------------- */

struct grub_apfs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_apfs_dir_iter(const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *data)
{
	struct grub_apfs_dir_ctx *ctx = data;
	struct grub_dirhook_info info;

	grub_memset(&info, 0, sizeof(info));
	if (grub_apfs_load_inode(node) == GRUB_ERR_NONE)
	{
		info.mtimeset = 1;
		info.mtime = (grub_int64_t) (node->mtime_ns / 1000000000ULL);
	}
	else
		grub_errno = GRUB_ERR_NONE;
	info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK);
	info.case_insensitive = node->vol->case_insensitive ? 1 : 0;
	info.inodeset = 1;
	info.inode = node->ino;
	grub_free(node);
	return ctx->hook(filename, &info, ctx->hook_data);
}

static grub_err_t
grub_apfs_dir(grub_device_t device, const char *path, grub_fs_dir_hook_t hook,
	void *hook_data)
{
	struct grub_apfs_dir_ctx ctx =
	{
		.hook = hook,
		.hook_data = hook_data
	};
	struct grub_apfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_apfs_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(path, &data->rootnode, &fdiro,
		grub_apfs_iterate_dir, grub_apfs_read_symlink, GRUB_FSHELP_DIR);
	if (grub_errno)
		goto fail;

	grub_apfs_iterate_dir(fdiro, grub_apfs_dir_iter, &ctx);

fail:
	if (fdiro != &data->rootnode)
		grub_free(fdiro);
	grub_apfs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_apfs_open(struct grub_file *file, const char *name)
{
	struct grub_apfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;
	struct grub_apfs_file *f = NULL;
	grub_err_t err;

	data = grub_apfs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(name, &data->rootnode, &fdiro,
		grub_apfs_iterate_dir, grub_apfs_read_symlink, GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	err = grub_apfs_load_inode(fdiro);
	if (err)
		goto fail;

	f = grub_zalloc(sizeof(*f));
	if (!f)
		goto fail;
	f->data = data;
	f->vol = fdiro->vol;
	f->ino = fdiro->ino;
	f->private_id = fdiro->private_id;
	file->size = fdiro->size;

	if (fdiro->bsd_flags & GRUB_APFS_INOBSD_COMPRESSED)
	{
		err = grub_apfs_cmp_setup(file, f);
		if (err)
			goto fail;
	}

	file->data = f;
	if (fdiro != &data->rootnode)
		grub_free(fdiro);
	return GRUB_ERR_NONE;

fail:
	grub_free(f);
	if (fdiro && fdiro != &data->rootnode)
		grub_free(fdiro);
	grub_apfs_unmount(data);
	return grub_errno;
}

static grub_ssize_t
grub_apfs_read(struct grub_file *file, char *buf, grub_size_t len)
{
	struct grub_apfs_file *f = file->data;
	grub_err_t err;

	if (file->offset >= file->size)
		return 0;
	if (len > file->size - file->offset)
		len = (grub_size_t) (file->size - file->offset);
	if (!len)
		return 0;

	if (f->cmp)
		err = grub_apfs_cmp_read(file, f, (grub_uint8_t *) buf,
			file->offset, len);
	else
		err = grub_apfs_dstream_read(f->vol, f->private_id, file->offset,
			len, (grub_uint8_t *) buf, file);
	return err ? -1 : (grub_ssize_t) len;
}

static grub_err_t
grub_apfs_close(struct grub_file *file)
{
	struct grub_apfs_file *f = file->data;

	if (f->cmp)
	{
		grub_free(f->cmp->attr);
		grub_free(f->cmp->rsrc.data);
		grub_free(f->cmp->cbuf);
		grub_free(f->cmp->scratch);
		grub_free(f->cmp);
	}
	grub_apfs_unmount(f->data);
	grub_free(f);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_apfs_label(grub_device_t device, char **label)
{
	struct grub_apfs_data *data;

	*label = NULL;
	data = grub_apfs_mount(device->disk);
	if (!data)
		return grub_errno;
	*label = grub_strdup(data->vols[0].name);
	grub_apfs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_apfs_uuid(grub_device_t device, char **uuid)
{
	struct grub_apfs_data *data;

	*uuid = NULL;
	data = grub_apfs_mount(device->disk);
	if (!data)
		return grub_errno;
	*uuid = grub_xasprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		data->uuid[0], data->uuid[1], data->uuid[2], data->uuid[3],
		data->uuid[4], data->uuid[5], data->uuid[6], data->uuid[7],
		data->uuid[8], data->uuid[9], data->uuid[10], data->uuid[11],
		data->uuid[12], data->uuid[13], data->uuid[14], data->uuid[15]);
	grub_apfs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_apfs_mtime(grub_device_t device, grub_int64_t *tm)
{
	struct grub_apfs_data *data;
	grub_uint32_t i;

	*tm = 0;
	data = grub_apfs_mount(device->disk);
	if (!data)
		return grub_errno;
	for (i = 0; i < data->nvols; i++)
		if (data->vols[i].mtime > *tm)
			*tm = data->vols[i].mtime;
	grub_apfs_unmount(data);
	return grub_errno;
}

static struct grub_fs grub_apfs_fs =
{
	.name = "apfs",
	.fs_dir = grub_apfs_dir,
	.fs_open = grub_apfs_open,
	.fs_read = grub_apfs_read,
	.fs_close = grub_apfs_close,
	.fs_label = grub_apfs_label,
	.fs_uuid = grub_apfs_uuid,
	.fs_mtime = grub_apfs_mtime,
	.next = 0
};

GRUB_MOD_INIT(apfs)
{
	grub_apfs_fs.mod = mod;
	grub_fs_register(&grub_apfs_fs);
}

GRUB_MOD_FINI(apfs)
{
	grub_fs_unregister(&grub_apfs_fs);
}
