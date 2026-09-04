/* gho.c - Symantec (Norton) Ghost file based image browser */
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
 * Ghost's default backup mode stores a directory tree instead of
 * sectors, so there is no image for io\gho.c to hand back.  What
 * follows the partition header is a depth first walk of the volume,
 * emitted as a chain of ten byte records:
 *
 *	kind 0x17  the 512 byte boot sector
 *	kind 0x04  one 32 byte FAT directory entry (padded to 56)
 *	kind 0x02  32 KiB of the current file's contents, compressed
 *	kind 0x03  end of the current file's data
 *	kind 0x06  pre-partition sectors, ahead of the first partition
 *	kind 0x18  the reserved sector area, at the very end
 *
 * A directory entry for a subdirectory is immediately followed by that
 * subdirectory's own entries, and an all-zero entry pops back out - the
 * same end-of-list convention FAT itself uses.  A file's data records
 * follow its entry directly.
 *
 * Ghost's Linux-aware format (partition subtype 0x05) is a second
 * catalogue form.  Kind 0x1d expands to an inode number, parent inode,
 * the 128-byte ext inode and an absolute path.  The following kind 0x1e
 * records expand to the regular file's contents.  Their decoded sizes
 * vary with the source ext block runs, so they are indexed lazily as a
 * file is read rather than assuming fixed 32 KiB blocks.
 *
 * The image is presented as one directory per partition, numbered from
 * one.  A partition Ghost imaged sector by sector holds a single
 * disk.img instead of a tree; that one is indexed only when it is
 * opened, because indexing means walking its whole block chain.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/fs.h>
#include <grub/charset.h>
#include <grub/datetime.h>
#include <grub/ghost.h>
#include <grub/safemath.h>

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define GHO_SCAN_BUF		(256u << 10)
#define GHO_HEADER_SCAN_MAX	(16u << 20)
#define GHO_BOOT_TAIL_MAX	512

/* Sanity caps against corrupt images.  */
#define GHO_MAX_DEPTH		128
#define GHO_MAX_NODES		(4u << 20)
#define GHO_MAX_BLOCKS		(4u << 20)
#define GHO_MAX_PARTS		128

/* FAT directory entry layout.  */
#define GHO_DIRENT_SIZE		32
#define GHO_ATTR_VOLID		0x08
#define GHO_ATTR_DIR		0x10
#define GHO_ATTR_LFN		0x0f
#define GHO_NT_LOWER_BASE	0x08
#define GHO_NT_LOWER_EXT	0x10
#define GHO_LFN_CHARS		13
#define GHO_LFN_MAX_SEQ		20

/* ext2/ext3 catalogue metadata: two leading inode numbers followed by
   the original 128-byte ext inode and the absolute path.  */
#define GHO_EXT_META_SIZE	136
#define GHO_EXT_INODE_DATA	48
#define GHO_EXT_INLINE_MAX	60
#define GHO_EXT_MODE_MASK	0170000
#define GHO_EXT_MODE_DIR	0040000
#define GHO_EXT_MODE_REG	0100000
#define GHO_EXT_MODE_SYMLINK	0120000
#define GHO_EXT_INODE_BUCKETS	16384

#define GHO_CACHE_NONE		0xffffffffu
#define GHO_INDEX_STRIDE		64u

enum gho_node_kind
{
	GHO_NODE_DIR,
	/* consecutive kind 0x02 records; payload at record + 10 */
	GHO_NODE_FILE,
	GHO_NODE_SYMLINK,
	/* an explicit list of block payloads */
	GHO_NODE_BLOBS
};

struct gho_blob
{
	grub_uint64_t off;		/* payload offset */
	grub_uint32_t len;		/* payload length */
};

struct gho_node
{
	struct gho_node *next;
	struct gho_node *child;
	struct gho_node *last_child;
	char *name;
	grub_uint64_t size;
	grub_int64_t mtime;
	grub_uint64_t inode;
	int kind;
	int mtimeset;
	int case_insensitive;
	int variable;			/* ext records have variable decoded sizes */
	grub_uint8_t *inline_data;	/* short ext symlink */
	struct gho_node *hardlink;	/* shared content; owned by the target node */
	struct gho_node *inode_next;	/* per-partition lookup while scanning */

	/* GHO_NODE_FILE: records run back to back from FIRST, so only
	   their body lengths need keeping.  */
	grub_uint64_t first;
	grub_uint16_t *lens;
	grub_uint32_t *outs;		/* decoded sizes, learned lazily */
	grub_uint64_t *offsets;		/* ext payloads; metadata can interrupt a run */
	grub_uint32_t nblk;
	grub_uint32_t cap;
	/* One checkpoint per STRIDE blocks: FAT record offsets or ext logical
	   offsets.  Ext checkpoints cover only the validated prefix. */
	grub_uint64_t *checkpoints;
	grub_uint32_t indexed_blocks;
	grub_uint64_t indexed_bytes;

	/* GHO_NODE_BLOBS */
	struct gho_blob *blobs;
	grub_uint32_t nblobs;
	grub_uint32_t bs;		/* uncompressed bytes per block */
	grub_uint64_t chain_at;		/* sector chain to index on first use */
};

struct gho_data
{
	grub_uint32_t devid;
	grub_uint32_t diskid;
	grub_uint64_t size;
	grub_uint8_t comp;
	grub_uint32_t id;
	grub_uint32_t encoding;
	char *label;
	struct gho_node *root;
	grub_uint32_t nnodes;
	grub_uint32_t refs;		/* open files still holding this tree */
	int detached;			/* evicted from the cache, free on last close */
};

/* A mount walks the whole record chain, so the result is kept for the
   next call instead of being rebuilt per open.  Loopback disk ids are
   handed out from a counter that never repeats, so a hit really is the
   same image.  */
static struct gho_data *gho_cached;

struct gho_file
{
	struct gho_data *data;
	struct gho_node *node;
	grub_uint8_t *blk;		/* GRUB_GHOST_BLOCK_MAX bytes */
	grub_uint8_t *cmp;		/* GRUB_GHOST_STORED_MAX bytes */
	grub_int32_t *hash;
	grub_uint32_t cached_nr;
	grub_uint32_t cached_len;
	grub_uint32_t walk_idx;		/* memo for the GHO_NODE_FILE offset walk */
	grub_uint64_t walk_off;
	grub_uint32_t data_idx;		/* memo for variable-size ext records */
	grub_uint64_t data_off;
};

/* ------------------------------------------------------------------ */
/* reading                                                             */

static grub_err_t
gho_dread (grub_disk_t disk, grub_uint64_t off, void *buf, grub_size_t len)
{
	return grub_disk_read (disk, off >> GRUB_DISK_SECTOR_BITS,
			       off & (GRUB_DISK_SECTOR_SIZE - 1), len, buf);
}

/* A sliding window over the image, so walking the record chain reads
   sequentially instead of one scattered header at a time.  */
struct gho_cur
{
	grub_disk_t disk;
	grub_uint64_t size;
	grub_uint8_t *buf;
	grub_uint64_t at;
	grub_size_t len;
};

static const grub_uint8_t *
gho_peek (struct gho_cur *c, grub_uint64_t pos, grub_size_t want,
	  grub_size_t *avail)
{
	if (pos >= c->size || want > c->size - pos)
		return NULL;
	if (c->len == 0 || pos < c->at || pos + want > c->at + c->len)
	{
		c->len = GHO_SCAN_BUF;
		if (c->len > c->size - pos)
			c->len = (grub_size_t) (c->size - pos);
		if (gho_dread (c->disk, pos, c->buf, c->len) != GRUB_ERR_NONE)
		{
			c->len = 0;
			return NULL;
		}
		c->at = pos;
	}
	*avail = c->len - (grub_size_t) (pos - c->at);
	return c->buf + (pos - c->at);
}

/* ------------------------------------------------------------------ */
/* tree                                                                */

static void
gho_free_node (struct gho_node *n)
{
	while (n)
	{
		struct gho_node *next = n->next;

		gho_free_node (n->child);
		grub_free (n->name);
		grub_free (n->lens);
		grub_free (n->outs);
		grub_free (n->offsets);
		grub_free (n->checkpoints);
		grub_free (n->inline_data);
		grub_free (n->blobs);
		grub_free (n);
		n = next;
	}
}

static void
gho_free_data (struct gho_data *data)
{
	if (!data)
		return;
	gho_free_node (data->root);
	grub_free (data->label);
	grub_free (data);
}

/* Drop an open file's hold; the tree outlives the cache slot when a
   different image was mounted while the file was open.  */
static void
gho_release (struct gho_data *data)
{
	if (!data)
		return;
	if (data->refs > 0)
		data->refs--;
	if (data->refs == 0 && data->detached)
		gho_free_data (data);
}

static struct gho_node *
gho_new_node (struct gho_data *data, struct gho_node *parent, const char *name,
	      int kind)
{
	struct gho_node *n;

	if (data->nnodes >= GHO_MAX_NODES)
		return NULL;
	n = grub_zalloc (sizeof (*n));
	if (!n)
		return NULL;
	n->name = grub_strdup (name);
	if (!n->name)
	{
		grub_free (n);
		return NULL;
	}
	n->kind = kind;
	n->case_insensitive = parent->case_insensitive;
	data->nnodes++;

	if (parent->last_child)
		parent->last_child->next = n;
	else
		parent->child = n;
	parent->last_child = n;
	return n;
}

static grub_err_t
gho_add_len (struct gho_node *n, grub_uint16_t len)
{
	if (n->nblk == n->cap)
	{
		grub_uint16_t *lens;
		grub_uint32_t want = n->cap ? n->cap * 2 : 16;
		grub_size_t sz;

		if (want > GHO_MAX_BLOCKS)
			want = GHO_MAX_BLOCKS;
		if (want == n->cap)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost file too large");
		if (grub_mul ((grub_size_t) want, sizeof (*lens), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost file too large");
		lens = grub_realloc (n->lens, sz);
		if (!lens)
			return grub_errno;
		n->lens = lens;
		n->cap = want;
	}
	n->lens[n->nblk++] = len;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_add_ext_len (struct gho_node *n, grub_uint16_t len, grub_uint64_t off,
	grub_uint32_t hole)
{
	grub_uint32_t oldcap = n->cap;
	grub_uint32_t *outs;
	grub_uint64_t *offsets;
	grub_size_t sz;
	grub_err_t err;

	err = gho_add_len (n, len);
	if (err)
		return err;
	if (n->cap != oldcap)
	{
		if (grub_mul ((grub_size_t) n->cap, sizeof (*outs), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost file too large");
		outs = grub_realloc (n->outs, sz);
		if (!outs)
			return grub_errno;
		n->outs = outs;
		if (grub_mul ((grub_size_t) n->cap, sizeof (*offsets), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost file too large");
		offsets = grub_realloc (n->offsets, sz);
		if (!offsets)
			return grub_errno;
		n->offsets = offsets;
	}
	n->outs[n->nblk - 1] = hole;
	n->offsets[n->nblk - 1] = off;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_add_blob (struct gho_node *n, grub_uint32_t *capacity, grub_uint64_t off,
	      grub_uint32_t len)
{
	if (n->nblobs == *capacity)
	{
		struct gho_blob *blobs;
		grub_uint32_t want = *capacity ? *capacity * 2 : 16;
		grub_size_t sz;

		if (want > GHO_MAX_BLOCKS)
			want = GHO_MAX_BLOCKS;
		if (want == *capacity)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost image too large");
		if (grub_mul ((grub_size_t) want, sizeof (*blobs), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost image too large");
		blobs = grub_realloc (n->blobs, sz);
		if (!blobs)
			return grub_errno;
		n->blobs = blobs;
		*capacity = want;
	}
	n->blobs[n->nblobs].off = off;
	n->blobs[n->nblobs].len = len;
	n->nblobs++;
	return GRUB_ERR_NONE;
}

static struct gho_node *
gho_lookup_node (struct gho_node *n, const char *path)
{
	while (*path)
	{
		const char *end;
		grub_size_t len;
		struct gho_node *c;

		while (*path == '/')
			path++;
		if (!*path)
			break;
		end = grub_strchr (path, '/');
		len = end ? (grub_size_t) (end - path) : grub_strlen (path);

		for (c = n->child; c; c = c->next)
			if (grub_strlen (c->name) == len
			    && (n->case_insensitive
				? grub_strncasecmp (c->name, path, len)
				: grub_strncmp (c->name, path, len)) == 0)
				break;
		if (!c)
			return NULL;
		n = c;
		path += len;
	}
	return n;
}

/* ------------------------------------------------------------------ */
/* directory entries                                                   */

struct gho_lfn
{
	grub_uint16_t buf[GHO_LFN_MAX_SEQ * GHO_LFN_CHARS + 1];
	unsigned seen;			/* highest sequence number stored */
	int broken;
};

static void
gho_lfn_reset (struct gho_lfn *l)
{
	l->seen = 0;
	l->broken = 0;
}

static void
gho_lfn_add (struct gho_lfn *l, const grub_uint8_t *e)
{
	static const unsigned slot[GHO_LFN_CHARS] =
		{ 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
	unsigned seq = e[0] & 0x3f;
	unsigned i;

	if (seq < 1 || seq > GHO_LFN_MAX_SEQ)
	{
		l->broken = 1;
		return;
	}
	for (i = 0; i < GHO_LFN_CHARS; i++)
		l->buf[(seq - 1) * GHO_LFN_CHARS + i] = grub_ghost_get16 (e + slot[i]);
	if (seq > l->seen)
		l->seen = seq;
}

/* Render the accumulated long name, or NULL when there is none.  */
static char *
gho_lfn_name (struct gho_lfn *l)
{
	grub_uint8_t *out;
	grub_uint8_t *end;
	unsigned n;

	if (l->broken || l->seen == 0)
		return NULL;
	for (n = 0; n < l->seen * GHO_LFN_CHARS; n++)
		if (l->buf[n] == 0 || l->buf[n] == 0xffff)
			break;
	if (n == 0)
		return NULL;

	/* Worst case three bytes of UTF-8 per UTF-16 unit.  */
	out = grub_malloc (n * 3 + 1);
	if (!out)
		return NULL;
	end = grub_utf16_to_utf8 (out, l->buf, n);
	*end = '\0';
	return (char *) out;
}

/* Render the 8.3 name, honouring the two lower-case hint bits Windows
   sets when a name needs no long entry.  */
static char *
gho_short_name (const grub_uint8_t *e)
{
	char raw[13];
	char *out;
	char *p;
	int i;
	int n = 0;
	int lower_base = (e[12] & GHO_NT_LOWER_BASE) != 0;
	int lower_ext = (e[12] & GHO_NT_LOWER_EXT) != 0;

	for (i = 0; i < 8 && e[i] != ' '; i++)
		raw[n++] = (char) e[i];
	if (e[8] != ' ')
	{
		raw[n++] = '.';
		for (i = 8; i < 11 && e[i] != ' '; i++)
			raw[n++] = (char) e[i];
	}
	raw[n] = '\0';
	out = grub_fs_bytes_to_utf8 (raw, n, grub_fs_char_encoding);
	if (!out)
		return NULL;
	for (p = out; *p && *p != '.'; p++)
		if (lower_base)
			*p = grub_tolower (*p);
	if (*p == '.')
		for (p++; *p; p++)
			if (lower_ext)
				*p = grub_tolower (*p);
	return out;
}

/* A volume label is eleven contiguous bytes, not an 8.3 pair.  */
static void
gho_volume_label (const grub_uint8_t *e, char *out)
{
	int i;
	int n = 0;

	for (i = 0; i < 11; i++)
		out[n++] = (char) e[i];
	while (n > 0 && out[n - 1] == ' ')
		n--;
	out[n] = '\0';
}

/* ECMA-107 11.3.5/11.3.6, as in fs\fat.c.  */
static int
gho_timestamp (grub_uint16_t time, grub_uint16_t date, grub_int64_t *nix)
{
	struct grub_datetime datetime =
	{
		.year   = (grub_uint16_t) ((date >> 9) + 1980),
		.month  = (grub_uint8_t) ((date & 0x01e0) >> 5),
		.day    = (grub_uint8_t) (date & 0x001f),
		.hour   = (grub_uint8_t) (time >> 11),
		.minute = (grub_uint8_t) ((time & 0x07e0) >> 5),
		.second = (grub_uint8_t) ((time & 0x001f) * 2),
	};

	if ((time & 0x1f) > 29)
		return 0;
	return grub_datetime2unixtime (&datetime, nix);
}

/* ------------------------------------------------------------------ */
/* mounting                                                            */

static int
gho_known_kind (grub_uint8_t kind)
{
	switch (kind)
	{
	case GRUB_GHOST_REC_DATA:
	case GRUB_GHOST_REC_END:
	case GRUB_GHOST_REC_DIRENT:
	case GRUB_GHOST_REC_TRACK0:
	case GRUB_GHOST_REC_BOOT:
	case GRUB_GHOST_REC_RESERVED:
	case GRUB_GHOST_REC_DIRENT_OLD:
		return 1;
	}
	return 0;
}

/* Older Ghost writers put a 66 byte metadata tail after the boot sector
   record and use kind 0x19 directory records whose middle dword is not the
   usual magic.  Keep the relaxed test confined to that one record kind.  */
static int
gho_record_header (const grub_uint8_t *p, grub_size_t avail)
{
	grub_uint8_t kind;
	grub_uint16_t len;

	if (avail < GRUB_GHOST_REC_HDR_SIZE)
		return 0;
	kind = p[0];
	len = grub_ghost_get16 (p + 8);
	if (kind == GRUB_GHOST_REC_DIRENT_OLD)
		return len >= GHO_DIRENT_SIZE;
	return gho_known_kind (kind)
	       && grub_ghost_get32 (p + 4) == GRUB_GHOST_REC_MAGIC;
}

static grub_uint64_t
gho_skip_boot_tail (struct gho_cur *cur, grub_uint64_t pos)
{
	grub_size_t avail;
	grub_size_t i;
	const grub_uint8_t *p;

	p = gho_peek (cur, pos, GRUB_GHOST_REC_HDR_SIZE, &avail);
	if (!p || gho_record_header (p, avail))
		return pos;
	if (avail > GHO_BOOT_TAIL_MAX + GRUB_GHOST_REC_HDR_SIZE)
		avail = GHO_BOOT_TAIL_MAX + GRUB_GHOST_REC_HDR_SIZE;
	for (i = 1; i + GRUB_GHOST_REC_HDR_SIZE <= avail; i++)
		if (gho_record_header (p + i, avail - i))
			return pos + i;
	return pos;
}

/*
 * The descriptor area between the file header and the first record has
 * no recorded length, so find where the chain starts: either a
 * partition header carrying our image id, or the first record of a
 * recognised kind - a disk backup opens with its track 0 records, ahead
 * of any partition header.
 */
static grub_err_t
gho_find_start (struct gho_data *data, struct gho_cur *cur, grub_uint64_t *start)
{
	grub_uint64_t pos = GRUB_GHOST_HEADER_SIZE;
	grub_uint64_t limit = data->size;

	if (limit > GHO_HEADER_SCAN_MAX)
		limit = GHO_HEADER_SCAN_MAX;

	while (pos + 8 <= limit)
	{
		grub_size_t avail;
		grub_size_t i;
		const grub_uint8_t *p = gho_peek (cur, pos, 8, &avail);

		if (!p)
			break;
		for (i = 0; i + 8 <= avail; i++)
		{
			if (p[i] == 0xfe && p[i + 1] == 0xef && p[i + 3] == data->comp
			    && grub_ghost_get32 (p + i + 4) == data->id)
			{
				*start = pos + i;
				return GRUB_ERR_NONE;
			}
			if (grub_ghost_get32 (p + i + 4) == GRUB_GHOST_REC_MAGIC
			    && gho_known_kind (p[i]))
			{
				*start = pos + i;
				return GRUB_ERR_NONE;
			}
		}
		if (avail < 8)
			break;
		pos += avail - 7;
	}
	return grub_error (GRUB_ERR_BAD_FS, "no Ghost partition header");
}

static grub_err_t
gho_ext_add_inode (struct gho_data *data, struct gho_node *part,
			   const grub_uint8_t *meta, grub_size_t metalen,
			   struct gho_node **inodes, int hardlink, struct gho_node **file)
{
	grub_uint32_t ino;
	grub_uint32_t parent_ino;
	grub_uint16_t mode;
	grub_uint64_t size;
	grub_size_t pathlen;
	grub_size_t i;
	char *path;
	char *base;
	struct gho_node *parent;
	struct gho_node *n;
	struct gho_node *owner;
	unsigned bucket;
	int kind;

	*file = NULL;
	if (metalen <= GHO_EXT_META_SIZE)
		return grub_error (GRUB_ERR_BAD_FS, "short Ghost ext inode record");
	ino = grub_ghost_get32 (meta);
	parent_ino = grub_ghost_get32 (meta + 4);
	mode = grub_ghost_get16 (meta + 8);
	pathlen = metalen - GHO_EXT_META_SIZE;
	/* Writers use both counted paths and counted, NUL-terminated paths.
	   Accept a single terminator, never an embedded NUL or an empty name. */
	if (meta[GHO_EXT_META_SIZE + pathlen - 1] == 0)
		pathlen--;
	if (pathlen == 0)
		return grub_error (GRUB_ERR_BAD_FS, "empty Ghost ext path");
	for (i = 0; i < pathlen; i++)
		if (meta[GHO_EXT_META_SIZE + i] == 0)
			return grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext path");

	/* Inode 8 is the private ext3 journal.  Ghost names it '.', but it
	   is not a directory entry and must not be exposed in the tree.  */
	if (parent_ino == 0 && pathlen == 1
	    && meta[GHO_EXT_META_SIZE] == '.')
		return GRUB_ERR_NONE;

	path = grub_fs_bytes_to_utf8 ((const char *) meta + GHO_EXT_META_SIZE,
				     pathlen, data->encoding);
	if (!path)
		return grub_errno;
	if (ino == 2 && grub_strcmp (path, "/") == 0)
	{
		part->inode = ino;
		part->mtime = (grub_int64_t) grub_ghost_get32 (meta + 24);
		part->mtimeset = 1;
		grub_free (path);
		return GRUB_ERR_NONE;
	}
	if (path[0] != '/')
	{
		grub_free (path);
		return grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext path");
	}

	base = grub_strrchr (path, '/');
	if (!base || base[1] == 0)
	{
		grub_free (path);
		return grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext path");
	}
	*base = 0;
	parent = gho_lookup_node (part, path);
	*base++ = '/';
	if (!parent || parent->kind != GHO_NODE_DIR
	    || (parent_ino != 0 && parent->inode != parent_ino))
	{
		grub_free (path);
		return grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext parent inode");
	}

	switch (mode & GHO_EXT_MODE_MASK)
	{
	case GHO_EXT_MODE_DIR:
		kind = GHO_NODE_DIR;
		break;
	case GHO_EXT_MODE_SYMLINK:
		kind = GHO_NODE_SYMLINK;
		break;
	default:
		kind = GHO_NODE_FILE;
		break;
	}
	n = gho_new_node (data, parent, base, kind);
	grub_free (path);
	if (!n)
		return grub_errno ? grub_errno : GRUB_ERR_OUT_OF_MEMORY;
	n->inode = ino;
	n->mtime = (grub_int64_t) grub_ghost_get32 (meta + 24);
	n->mtimeset = 1;
	size = grub_ghost_get32 (meta + 12);
	if ((mode & GHO_EXT_MODE_MASK) == GHO_EXT_MODE_REG)
		size |= (grub_uint64_t) grub_ghost_get32 (meta + 116) << 32;
	n->size = size;
	bucket = ino % GHO_EXT_INODE_BUCKETS;
	for (owner = inodes[bucket]; owner; owner = owner->inode_next)
		if (owner->inode == ino)
			break;
	if (hardlink)
	{
		if (!owner || (mode & GHO_EXT_MODE_MASK) != GHO_EXT_MODE_REG
		    || owner->kind != GHO_NODE_FILE || !owner->variable || owner->size != size)
			return grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext hard link");
		n->hardlink = owner;
		return GRUB_ERR_NONE;
	}
	if (owner)
		return grub_error (GRUB_ERR_BAD_FS, "duplicate Ghost ext inode");
	n->inode_next = inodes[bucket];
	inodes[bucket] = n;

	if (kind == GHO_NODE_SYMLINK && size < GHO_EXT_INLINE_MAX)
	{
		if (size != 0)
		{
			n->inline_data = grub_malloc ((grub_size_t) size);
			if (!n->inline_data)
				return grub_errno;
			grub_memcpy (n->inline_data, meta + GHO_EXT_INODE_DATA,
				     (grub_size_t) size);
		}
	}
	else if ((mode & GHO_EXT_MODE_MASK) == GHO_EXT_MODE_REG
		 || kind == GHO_NODE_SYMLINK)
	{
		n->variable = 1;
		*file = n;
	}
	else
		n->size = 0;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_scan_ext (struct gho_data *data, struct gho_cur *cur,
	      struct gho_node *part, grub_uint64_t *position)
{
	struct gho_node *file = NULL;
	struct gho_node **inodes;
	grub_uint64_t pos = *position;
	grub_uint32_t block_size = 0;
	grub_uint8_t *meta;
	grub_int32_t *hash = NULL;
	grub_err_t err = GRUB_ERR_NONE;

	meta = grub_malloc (GRUB_GHOST_BLOCK_MAX);
	if (data->comp == GRUB_GHOST_COMP_FAST)
		hash = grub_malloc (GRUB_GHOST_FASTLZ_HASH_SIZE * sizeof (*hash));
	inodes = grub_calloc (GHO_EXT_INODE_BUCKETS, sizeof (*inodes));
	if (!meta || !inodes || (data->comp == GRUB_GHOST_COMP_FAST && !hash))
	{
		err = grub_errno;
		goto out;
	}
	part->case_insensitive = 0;

	while (pos + GRUB_GHOST_REC_HDR_SIZE <= cur->size)
	{
		const grub_uint8_t *p;
		grub_size_t avail;
		grub_size_t outlen;
		grub_uint16_t type;
		grub_uint16_t len;

		p = gho_peek (cur, pos, GRUB_GHOST_REC_HDR_SIZE, &avail);
		if (!p || grub_ghost_get32 (p + 4) != GRUB_GHOST_REC_MAGIC)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext record");
			goto out;
		}
		type = grub_ghost_get16 (p);
		len = grub_ghost_get16 (p + 8);
		if (len > cur->size - pos - GRUB_GHOST_REC_HDR_SIZE)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "truncated Ghost ext record");
			goto out;
		}
		p = gho_peek (cur, pos, GRUB_GHOST_REC_HDR_SIZE + len, &avail);
		if (!p)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "truncated Ghost ext record");
			goto out;
		}

		switch (type & 0xff)
		{
		case GRUB_GHOST_EXT_INFO_FIRST:
			file = NULL;
			break;

		case GRUB_GHOST_EXT_INFO_LAST:
			err = grub_ghost_decode (data->comp, hash,
				p + GRUB_GHOST_REC_HDR_SIZE, len, meta, GRUB_GHOST_BLOCK_MAX, &outlen);
			if (err)
				goto out;
			if (outlen < 104 || grub_ghost_get16 (meta + 56) != 0xef53
			    || grub_ghost_get32 (meta + 24) > 6)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext superblock");
				goto out;
			}
			block_size = 1024u << grub_ghost_get32 (meta + 24);
			file = NULL;
			break;

		case GRUB_GHOST_EXT_INODE:
			err = grub_ghost_decode (data->comp, hash,
					 p + GRUB_GHOST_REC_HDR_SIZE, len,
					 meta, GRUB_GHOST_BLOCK_MAX, &outlen);
			if (err)
				goto out;
			err = gho_ext_add_inode (data, part, meta, outlen, inodes, (type & 0x100) != 0, &file);
			if (err)
				goto out;
			break;

		case GRUB_GHOST_EXT_DATA:
			if (file)
			{
				if (file->nblk == 0)
					file->first = pos;
				err = gho_add_ext_len (file, len, pos + GRUB_GHOST_REC_HDR_SIZE, 0);
				if (err)
					goto out;
			}
			break;

		case GRUB_GHOST_EXT_HOLE:
		{
			grub_uint32_t blocks = ((grub_uint32_t) p[1] << 16)
				| ((grub_uint32_t) p[2] << 8) | p[3];
			grub_uint32_t bytes;

			if (len != 0 || !blocks || !block_size || grub_mul (blocks, block_size, &bytes)
			    || (file && bytes > file->size))
			{
				err = grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext sparse run");
				goto out;
			}
			if (file)
			{
				err = gho_add_ext_len (file, 0, 0, bytes);
				if (err)
					goto out;
			}
			break;
		}

		case GRUB_GHOST_EXT_XATTR:
			/* External ext attribute blocks (including SELinux labels) do
			   not contribute bytes to the current file's content. */
			break;

		case GRUB_GHOST_EXT_CHECKSUM:
			file = NULL;
			break;

		case GRUB_GHOST_EXT_END:
			if (part->inode != 2 || !block_size || len != 0)
				err = grub_error (GRUB_ERR_BAD_FS,
						  "Ghost ext root inode missing");
			else
				*position = pos + GRUB_GHOST_REC_HDR_SIZE;
			goto out;

		case GRUB_GHOST_EXT_SWAP:
			/* Ghost saves no filesystem catalogue for swap.  Keep its
			   numbered partition entry and continue with the next header. */
			if (part->inode || part->child || len != 16)
				err = grub_error (GRUB_ERR_BAD_FS, "bad Ghost swap descriptor");
			else
				*position = pos + GRUB_GHOST_REC_HDR_SIZE + len;
			goto out;

		default:
			err = grub_error (GRUB_ERR_BAD_FS,
					  "unsupported Ghost ext record 0x%x", type);
			goto out;
		}
		pos += GRUB_GHOST_REC_HDR_SIZE + len;
	}
	err = grub_error (GRUB_ERR_BAD_FS, "unterminated Ghost ext catalogue");

out:
	grub_free (inodes);
	grub_free (meta);
	grub_free (hash);
	return err;
}

static grub_err_t
gho_scan (struct gho_data *data, struct gho_cur *cur)
{
	struct gho_node *stack[GHO_MAX_DEPTH];
	struct gho_node *part = NULL;
	struct gho_node *file = NULL;
	struct gho_lfn lfn;
	struct gho_node *track0 = NULL;
	grub_uint32_t t0cap = 0;
	grub_uint64_t pos;
	unsigned depth = 0;
	unsigned nparts = 0;
	grub_err_t err;

	err = gho_find_start (data, cur, &pos);
	if (err)
		return err;
	gho_lfn_reset (&lfn);

	while (pos + 8 <= data->size)
	{
		const grub_uint8_t *p;
		grub_size_t avail;
		grub_uint8_t kind;
		grub_uint32_t len;

		p = gho_peek (cur, pos, 8, &avail);
		if (!p)
			break;

		/* A partition header opens a new partition.  */
		if (p[0] == 0xfe && p[1] == 0xef
		    && grub_ghost_get32 (p + 4) == data->id)
		{
			char name[16];
			grub_uint8_t subtype = p[2];

			if (nparts >= GHO_MAX_PARTS)
				break;
			grub_snprintf (name, sizeof (name), "%u", nparts + 1);
			part = gho_new_node (data, data->root, name, GHO_NODE_DIR);
			if (!part)
				return grub_errno ? grub_errno : GRUB_ERR_OUT_OF_MEMORY;
			nparts++;
			depth = 0;
			stack[depth] = part;
			file = NULL;
			gho_lfn_reset (&lfn);
			pos += GRUB_GHOST_HEADER_SIZE;
			if (subtype == GRUB_GHOST_PART_EXT2)
			{
				err = gho_scan_ext (data, cur, part, &pos);
				if (err)
					return err;
				continue;
			}

			/* Anything Ghost could not walk as files is stored as
			   a raw block chain, which is indexed only when the
			   image is opened.  Stepping over it here to look for
			   a further partition would mean streaming the whole
			   chain past the reader during the mount, so the walk
			   stops instead: a partition behind a sector imaged
			   one stays hidden.  */
			if (subtype != GRUB_GHOST_PART_FAT)
			{
				struct gho_node *img;

				img = gho_new_node (data, part, "disk.img", GHO_NODE_BLOBS);
				if (!img)
					return grub_errno ? grub_errno : GRUB_ERR_OUT_OF_MEMORY;
				img->chain_at = pos;
				break;
			}
			continue;
		}

		if (!gho_record_header (p, avail))
			break;

		kind = p[0];
		len = grub_ghost_get16 (p + 8);

		if (kind == GRUB_GHOST_REC_TRACK0)
		{
			/* Sector data, framed the way a sector image frames
			   it: a stored length then the payload.  */
			grub_uint32_t stored;

			p = gho_peek (cur, pos + GRUB_GHOST_REC_HDR_SIZE, 2, &avail);
			if (!p)
				break;
			stored = grub_ghost_get16 (p);
			if (stored < GRUB_GHOST_STORED_MIN || len == 0)
				break;
			if (!track0)
			{
				track0 = gho_new_node (data, data->root, "track0.bin",
						       GHO_NODE_BLOBS);
				if (!track0)
					return grub_errno ? grub_errno : GRUB_ERR_OUT_OF_MEMORY;
				track0->bs = len;
			}
			if (track0->bs == len)
			{
				err = gho_add_blob (track0, &t0cap,
						    pos + GRUB_GHOST_REC_HDR_SIZE + 2,
						    stored - 2);
				if (err)
					return err;
			}
			pos += GRUB_GHOST_REC_HDR_SIZE + stored;
			continue;
		}

		switch (kind)
		{
		case GRUB_GHOST_REC_DIRENT:
		case GRUB_GHOST_REC_DIRENT_OLD:
		{
			const grub_uint8_t *e;
			char *name;
			struct gho_node *n;
			grub_uint8_t attr;

			if (!part || len < GHO_DIRENT_SIZE)
				break;
			e = gho_peek (cur, pos + GRUB_GHOST_REC_HDR_SIZE,
				      GHO_DIRENT_SIZE, &avail);
			if (!e)
				return grub_error (GRUB_ERR_BAD_FS, "truncated Ghost catalogue");

			if (e[0] == 0x00)
			{
				/* End of this directory's entries.  */
				if (depth > 0)
					depth--;
				file = NULL;
				gho_lfn_reset (&lfn);
				break;
			}
			if (e[0] == 0xe5)
			{
				gho_lfn_reset (&lfn);
				break;
			}
			attr = e[11];
			if ((attr & GHO_ATTR_LFN) == GHO_ATTR_LFN)
			{
				gho_lfn_add (&lfn, e);
				break;
			}
			if (attr & GHO_ATTR_VOLID)
			{
				if (!data->label)
				{
					char lbl[12];

					gho_volume_label (e, lbl);
					data->label = grub_fs_bytes_to_utf8 (lbl,
						grub_strlen (lbl), grub_fs_char_encoding);
					if (!data->label)
						return grub_errno;
				}
				gho_lfn_reset (&lfn);
				break;
			}

			name = gho_lfn_name (&lfn);
			gho_lfn_reset (&lfn);
			if (!name)
			{
				name = gho_short_name (e);
				if (!name)
					return grub_errno;
				if (grub_strcmp (name, ".") == 0
				    || grub_strcmp (name, "..") == 0)
				{
					grub_free (name);
					file = NULL;
					break;
				}
			}

			n = gho_new_node (data, stack[depth], name,
					  (attr & GHO_ATTR_DIR) ? GHO_NODE_DIR : GHO_NODE_FILE);
			grub_free (name);
			if (!n)
				return grub_errno ? grub_errno : GRUB_ERR_OUT_OF_MEMORY;
			n->mtimeset = gho_timestamp (grub_ghost_get16 (e + 22),
						     grub_ghost_get16 (e + 24), &n->mtime);
			if (attr & GHO_ATTR_DIR)
			{
				/* Its entries follow straight away.  */
				file = NULL;
				if (depth + 1 >= GHO_MAX_DEPTH)
					return grub_error (GRUB_ERR_BAD_FS,
							   "Ghost catalogue nested too deeply");
				stack[++depth] = n;
			}
			else
			{
				n->size = grub_ghost_get32 (e + 28);
				n->bs = GRUB_GHOST_BLOCK_SIZE;
				file = n;
			}
			break;
		}

		case GRUB_GHOST_REC_DATA:
			if (file)
			{
				if (file->nblk == 0)
					file->first = pos;
				err = gho_add_len (file, (grub_uint16_t) len);
				if (err)
					return err;
			}
			break;

		case GRUB_GHOST_REC_END:
			file = NULL;
			break;

		default:
			break;
		}

		pos += GRUB_GHOST_REC_HDR_SIZE + len;
		if (kind == GRUB_GHOST_REC_BOOT)
			pos = gho_skip_boot_tail (cur, pos);
	}

	if (nparts == 0)
		return grub_error (GRUB_ERR_BAD_FS, "no Ghost partition found");
	if (track0 && track0->nblobs)
		track0->size = (grub_uint64_t) track0->nblobs * track0->bs;
	return GRUB_ERR_NONE;
}

static struct gho_data *
gho_mount (grub_disk_t disk)
{
	struct gho_data *data;
	struct gho_cur cur;
	grub_uint8_t hdr[GRUB_GHOST_HEADER_SIZE];
	grub_uint64_t sectors;

	if (gho_cached && gho_cached->devid == disk->dev->id
	    && gho_cached->diskid == disk->id
	    && gho_cached->encoding == grub_fs_char_encoding)
		return gho_cached;

	sectors = grub_disk_native_sectors (disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN)
	{
		grub_error (GRUB_ERR_BAD_FS, "not a Ghost image");
		return NULL;
	}

	if (gho_dread (disk, 0, hdr, sizeof (hdr)) != GRUB_ERR_NONE)
		return NULL;
	if (hdr[0] != 0xfe || hdr[1] != 0xef
	    || hdr[2] != GRUB_GHOST_FILE_PRIMARY
	    || !grub_ghost_comp_supported (hdr[3]))
	{
		grub_error (GRUB_ERR_BAD_FS, "not a Ghost image");
		return NULL;
	}

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->devid = disk->dev->id;
	data->diskid = disk->id;
	data->size = sectors << disk->log_sector_size;
	data->comp = hdr[3];
	data->id = grub_ghost_get32 (hdr + 4);
	data->encoding = grub_fs_char_encoding;
	data->root = grub_zalloc (sizeof (*data->root));
	if (!data->root)
		goto fail;
	data->root->kind = GHO_NODE_DIR;
	data->root->case_insensitive = 1;

	cur.disk = disk;
	cur.size = data->size;
	cur.at = 0;
	cur.len = 0;
	cur.buf = grub_malloc (GHO_SCAN_BUF);
	if (!cur.buf)
		goto fail;

	if (gho_scan (data, &cur) != GRUB_ERR_NONE)
	{
		grub_free (cur.buf);
		goto fail;
	}
	grub_free (cur.buf);

	if (gho_cached)
	{
		if (gho_cached->refs == 0)
			gho_free_data (gho_cached);
		else
			gho_cached->detached = 1;
	}
	gho_cached = data;
	return data;

fail:
	gho_free_data (data);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* lookup                                                              */

static struct gho_node *
gho_lookup (struct gho_data *data, const char *path)
{
	return gho_lookup_node (data->root, path);
}

/* ------------------------------------------------------------------ */
/* file data                                                           */

/* GET_SIZE, empty files and inline symlinks need no decoding workspace.
   Commit all buffers together so a failed allocation can be retried. */
static grub_err_t
gho_alloc_buffers (struct gho_file *f)
{
	grub_uint8_t *blk;
	grub_uint8_t *cmp;
	grub_int32_t *hash = NULL;

	if (f->blk)
		return GRUB_ERR_NONE;
	blk = grub_malloc (GRUB_GHOST_BLOCK_MAX);
	cmp = grub_malloc (GRUB_GHOST_STORED_MAX);
	if (f->data->comp == GRUB_GHOST_COMP_FAST)
		hash = grub_malloc (GRUB_GHOST_FASTLZ_HASH_SIZE * sizeof (*hash));
	if (!blk || !cmp || (f->data->comp == GRUB_GHOST_COMP_FAST && !hash))
		goto fail;
	f->blk = blk;
	f->cmp = cmp;
	f->hash = hash;
	return GRUB_ERR_NONE;

fail:
	grub_free (blk);
	grub_free (cmp);
	grub_free (hash);
	return grub_errno;
}

static grub_err_t
gho_alloc_index (struct gho_node *n)
{
	grub_size_t count;
	grub_size_t sz;

	if (n->checkpoints || n->nblk <= GHO_INDEX_STRIDE)
		return GRUB_ERR_NONE;
	count = (n->nblk - 1) / GHO_INDEX_STRIDE + 1;
	if (grub_mul (count, sizeof (*n->checkpoints), &sz))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "Ghost file too large");
	n->checkpoints = grub_malloc (sz);
	if (!n->checkpoints)
		return grub_errno;
	if (!n->variable)
	{
		grub_uint64_t off = n->first;
		grub_uint32_t i;

		for (i = 0; i < n->nblk; i++)
		{
			if (i % GHO_INDEX_STRIDE == 0)
				n->checkpoints[i / GHO_INDEX_STRIDE] = off;
			off += GRUB_GHOST_REC_HDR_SIZE + n->lens[i];
		}
	}
	return GRUB_ERR_NONE;
}

/* Build the block list of a sector-imaged partition.  Deferred until
   the image is opened, because it walks the whole chain.  */
static grub_err_t
gho_build_chain (struct gho_file *f, grub_disk_t disk)
{
	struct gho_node *n = f->node;
	struct gho_cur cur;
	grub_uint64_t pos = n->chain_at;
	grub_uint32_t cap = 0;
	grub_size_t out = 0;
	grub_err_t err;

	cur.disk = disk;
	cur.size = f->data->size;
	cur.at = 0;
	cur.len = 0;
	cur.buf = grub_malloc (GHO_SCAN_BUF);
	if (!cur.buf)
		return grub_errno;

	while (pos + 2 <= cur.size)
	{
		grub_size_t avail;
		const grub_uint8_t *p = gho_peek (&cur, pos, 2, &avail);
		grub_uint32_t stored;

		if (!p)
			break;
		if (avail >= 8 && grub_ghost_get32 (p + 4) == GRUB_GHOST_REC_MAGIC)
			break;
		if (p[0] == 0xfe && p[1] == 0xef && avail >= 8
		    && grub_ghost_get32 (p + 4) == f->data->id)
			break;
		stored = grub_ghost_get16 (p);
		if (stored < GRUB_GHOST_STORED_MIN || stored > cur.size - pos)
			break;
		err = gho_add_blob (n, &cap, pos + 2, stored - 2);
		if (err)
			goto fail;
		pos += stored;
	}
	grub_free (cur.buf);
	cur.buf = NULL;

	if (n->nblobs == 0)
		return grub_error (GRUB_ERR_BAD_FS, "empty Ghost sector image");

	/* The first block fixes the block size, the last one may be short.  */
	err = gho_alloc_buffers (f);
	if (err)
		return err;
	if (n->blobs[0].len > GRUB_GHOST_STORED_MAX)
		return grub_error (GRUB_ERR_BAD_FS, "bad Ghost block");
	err = gho_dread (disk, n->blobs[0].off, f->cmp, n->blobs[0].len);
	if (err)
		return err;
	err = grub_ghost_decode (f->data->comp, f->hash, f->cmp, n->blobs[0].len,
				 f->blk, GRUB_GHOST_BLOCK_MAX, &out);
	if (err)
		return err;
	if (out < GRUB_DISK_SECTOR_SIZE || (out & (GRUB_DISK_SECTOR_SIZE - 1)) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "bad Ghost block size");
	n->bs = (grub_uint32_t) out;

	err = gho_dread (disk, n->blobs[n->nblobs - 1].off, f->cmp,
			 n->blobs[n->nblobs - 1].len);
	if (err)
		return err;
	err = grub_ghost_decode (f->data->comp, f->hash, f->cmp,
				 n->blobs[n->nblobs - 1].len, f->blk,
				 GRUB_GHOST_BLOCK_MAX, &out);
	if (err)
		return err;
	if (out == 0 || out > n->bs)
		return grub_error (GRUB_ERR_BAD_FS, "bad final Ghost block");

	n->size = (grub_uint64_t) (n->nblobs - 1) * n->bs + out;
	n->chain_at = 0;
	f->cached_nr = GHO_CACHE_NONE;
	return GRUB_ERR_NONE;

fail:
	grub_free (cur.buf);
	return err;
}

/* Offset of block NR of a GHO_NODE_FILE, walking the record run.  */
static grub_uint64_t
gho_file_block (struct gho_file *f, grub_uint32_t nr)
{
	struct gho_node *n = f->node;
	grub_uint32_t i = 0;
	grub_uint64_t off = n->first;

	if (n->checkpoints)
	{
		i = (nr / GHO_INDEX_STRIDE) * GHO_INDEX_STRIDE;
		off = n->checkpoints[nr / GHO_INDEX_STRIDE];
	}
	if (f->walk_idx <= nr && f->walk_idx > i)
	{
		i = f->walk_idx;
		off = f->walk_off;
	}
	for (; i < nr; i++)
		off += GRUB_GHOST_REC_HDR_SIZE + n->lens[i];
	f->walk_idx = nr;
	f->walk_off = off;
	return off;
}

static grub_err_t
gho_load (struct gho_file *f, grub_disk_t disk, grub_uint32_t nr)
{
	struct gho_node *n = f->node;
	grub_uint64_t off;
	grub_uint32_t clen;
	grub_size_t out;
	grub_err_t err;

	if (f->cached_nr == nr)
		return GRUB_ERR_NONE;
	f->cached_nr = GHO_CACHE_NONE;

	err = gho_alloc_buffers (f);
	if (err)
		return err;
	if (n->kind == GHO_NODE_FILE && !n->variable)
	{
		err = gho_alloc_index (n);
		if (err)
			return err;
	}

	if (n->kind == GHO_NODE_FILE || n->variable)
	{
		off = n->variable ? n->offsets[nr]
			: gho_file_block (f, nr) + GRUB_GHOST_REC_HDR_SIZE;
		clen = n->lens[nr];
	}
	else
	{
		off = n->blobs[nr].off;
		clen = n->blobs[nr].len;
	}
	if (clen == 0 || clen > GRUB_GHOST_STORED_MAX)
		return grub_error (GRUB_ERR_BAD_FS, "bad Ghost block");

	err = gho_dread (disk, off, f->cmp, clen);
	if (err)
		return err;
	err = grub_ghost_decode (f->data->comp, f->hash, f->cmp, clen, f->blk,
				 GRUB_GHOST_BLOCK_MAX, &out);
	if (err)
		return err;
	if (n->variable)
	{
		if (out == 0 || out > GRUB_GHOST_BLOCK_MAX)
			return grub_error (GRUB_ERR_BAD_FS, "bad Ghost ext data block");
		if (n->outs[nr] != 0 && n->outs[nr] != out)
			return grub_error (GRUB_ERR_BAD_FS, "Ghost ext block size changed");
		n->outs[nr] = (grub_uint32_t) out;
		f->cached_len = (grub_uint32_t) out;
	}
	else
	{
		if (out > n->bs)
			return grub_error (GRUB_ERR_BAD_FS, "oversized Ghost block");
		if (out < n->bs)
			grub_memset (f->blk + out, 0, n->bs - out);
		f->cached_len = n->bs;
	}

	f->cached_nr = nr;
	return GRUB_ERR_NONE;
}

static grub_err_t
gho_ext_locate (struct gho_file *f, grub_disk_t disk, grub_uint64_t off,
		grub_uint32_t *nr, grub_uint32_t *in)
{
	struct gho_node *n = f->node;
	grub_uint32_t i = 0;
	grub_uint64_t base = 0;
	grub_err_t err;

	err = gho_alloc_index (n);
	if (err)
		return err;
	if (off >= n->indexed_bytes)
	{
		i = n->indexed_blocks;
		base = n->indexed_bytes;
	}
	else if (n->checkpoints)
	{
		grub_uint32_t lo = 0;
		grub_uint32_t hi = (n->indexed_blocks - 1) / GHO_INDEX_STRIDE + 1;

		while (lo < hi)
		{
			grub_uint32_t mid = lo + (hi - lo) / 2;

			if (n->checkpoints[mid] <= off)
				lo = mid + 1;
			else
				hi = mid;
		}
		i = (lo - 1) * GHO_INDEX_STRIDE;
		base = n->checkpoints[lo - 1];
	}
	if (f->data_idx >= i && f->data_idx < n->indexed_blocks && f->data_off <= off)
	{
		i = f->data_idx;
		base = f->data_off;
	}
	while (i < n->nblk)
	{
		grub_uint32_t len = n->outs[i];
		grub_uint64_t end;

		if (len == 0)
		{
			err = gho_load (f, disk, i);

			if (err)
				return err;
			len = f->cached_len;
		}
		if (base > ~((grub_uint64_t) 0) - len)
			return grub_error (GRUB_ERR_BAD_FS, "oversized Ghost ext file");
		end = base + len;
		if (end > n->size || (i + 1 == n->nblk && end != n->size)
		    || (i + 1 < n->nblk && end == n->size))
			return grub_error (GRUB_ERR_BAD_FS, "Ghost ext data length mismatch");
		if (i == n->indexed_blocks)
		{
			if (n->checkpoints && i % GHO_INDEX_STRIDE == 0)
				n->checkpoints[i / GHO_INDEX_STRIDE] = base;
			n->indexed_blocks++;
			n->indexed_bytes = end;
		}
		if (off < end)
		{
			f->data_idx = i;
			f->data_off = base;
			*nr = i;
			*in = (grub_uint32_t) (off - base);
			return GRUB_ERR_NONE;
		}
		base = end;
		i++;
	}
	return grub_error (GRUB_ERR_BAD_FS, "Ghost ext file truncated");
}

/* ------------------------------------------------------------------ */
/* filesystem entry points                                             */

static grub_err_t
grub_gho_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct gho_data *data;
	struct gho_node *dir;
	struct gho_node *c;

	data = gho_mount (device->disk);
	if (!data)
		return grub_errno;
	dir = gho_lookup (data, path);
	if (!dir)
		return grub_error (GRUB_ERR_FILE_NOT_FOUND, "directory not found");
	if (dir->kind != GHO_NODE_DIR)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");

	for (c = dir->child; c; c = c->next)
	{
		struct grub_dirhook_info info;

		grub_memset (&info, 0, sizeof (info));
		info.dir = (c->kind == GHO_NODE_DIR);
		info.symlink = (c->kind == GHO_NODE_SYMLINK);
		info.mtimeset = c->mtimeset;
		info.mtime = c->mtime;
		info.case_insensitive = dir->case_insensitive;
		info.inodeset = c->inode != 0;
		info.inode = c->inode;
		if (!info.dir && !info.symlink)
		{
			info.sizeset = 1;
			info.size = c->size;
		}
		if (hook (c->name, &info, hook_data))
			break;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_gho_open (grub_file_t file, const char *name)
{
	struct gho_data *data;
	struct gho_node *node;
	struct gho_file *f;
	grub_err_t err;

	data = gho_mount (file->device->disk);
	if (!data)
		return grub_errno;
	node = gho_lookup (data, name);
	if (!node)
		return grub_error (GRUB_ERR_FILE_NOT_FOUND, "file not found");
	if (node->kind == GHO_NODE_DIR)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a regular file");
	if (node->hardlink)
		node = node->hardlink;

	f = grub_zalloc (sizeof (*f));
	if (!f)
		return grub_errno;
	f->data = data;
	f->node = node;
	f->cached_nr = GHO_CACHE_NONE;
	if (node->kind == GHO_NODE_BLOBS && node->chain_at)
	{
		err = gho_build_chain (f, file->device->disk);
		if (err)
		{
			/* Leave nothing half-indexed for the next attempt.  */
			grub_free (node->blobs);
			node->blobs = NULL;
			node->nblobs = 0;
			goto fail;
		}
	}

	/* A catalogue file is stored as whole blocks; trust whichever of
	   the directory entry and the block run is smaller.  */
	if (node->kind == GHO_NODE_FILE && !node->variable)
	{
		grub_uint64_t held = (grub_uint64_t) node->nblk * node->bs;

		if (node->size > held)
			node->size = held;
	}

	data->refs++;
	file->data = f;
	file->size = node->size;
	return GRUB_ERR_NONE;

fail:
	grub_free (f->blk);
	grub_free (f->cmp);
	grub_free (f->hash);
	grub_free (f);
	return err;
}

static grub_ssize_t
grub_gho_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct gho_file *f = file->data;
	struct gho_node *n = f->node;
	grub_uint64_t off = file->offset;
	grub_ssize_t done = 0;

	if (off > n->size || len > n->size - off)
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of Ghost file");
		return -1;
	}
	if (n->inline_data)
	{
		grub_memcpy (buf, n->inline_data + off, len);
		return (grub_ssize_t) len;
	}
	while (len > 0)
	{
		grub_uint32_t nr;
		grub_uint32_t in;
		grub_size_t take = len;

		if (n->variable)
		{
			if (gho_ext_locate (f, file->device->disk, off, &nr, &in)
			    != GRUB_ERR_NONE)
				return -1;
			if (take > n->outs[nr] - in)
				take = n->outs[nr] - in;
		}
		else
		{
			grub_uint32_t have = (n->kind == GHO_NODE_FILE)
				? n->nblk : n->nblobs;

			nr = (grub_uint32_t) (off / n->bs);
			in = (grub_uint32_t) (off % n->bs);
			if (nr >= have)
			{
				grub_error (GRUB_ERR_BAD_FS, "Ghost file truncated");
				return -1;
			}
			if (take > n->bs - in)
				take = n->bs - in;
		}
		if (n->variable && n->lens[nr] == 0)
			grub_memset (buf, 0, take);
		else
		{
			if (gho_load (f, file->device->disk, nr) != GRUB_ERR_NONE)
				return -1;
			grub_memcpy (buf, f->blk + in, take);
		}
		buf += take;
		off += take;
		done += take;
		len -= take;
	}
	return done;
}

static grub_err_t
grub_gho_close (grub_file_t file)
{
	struct gho_file *f = file->data;

	if (f)
	{
		gho_release (f->data);
		grub_free (f->blk);
		grub_free (f->cmp);
		grub_free (f->hash);
		grub_free (f);
	}
	file->data = NULL;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_gho_label (grub_device_t device, char **label)
{
	struct gho_data *data;

	*label = NULL;
	data = gho_mount (device->disk);
	if (!data)
		return grub_errno;
	if (data->label)
		*label = grub_strdup (data->label);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_gho_fs =
{
	.name = "gho",
	.fs_dir = grub_gho_dir,
	.fs_open = grub_gho_open,
	.fs_read = grub_gho_read,
	.fs_close = grub_gho_close,
	.fs_label = grub_gho_label,
	.next = 0
};

GRUB_MOD_INIT (ghofs)
{
	grub_gho_fs.mod = mod;
	grub_fs_register (&grub_gho_fs);
}

GRUB_MOD_FINI (ghofs)
{
	grub_fs_unregister (&grub_gho_fs);
	gho_free_data (gho_cached);
	gho_cached = NULL;
}
