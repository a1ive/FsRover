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
 * UBIFS read-only driver, with an optional UBI container layer.
 *
 * On-flash format follows u-boot\fs\ubifs\ubifs-media.h.  Two
 * image shapes are accepted: a bare UBIFS image (mkfs.ubifs output,
 * LEB n at byte n * leb_size) and a UBI image / flash dump ("UBI#"
 * erase counter headers; the physical eraseblock size is detected
 * from the header spacing, volumes are mapped through the big-endian
 * EC/VID headers and the first volume carrying a UBIFS superblock is
 * mounted, labeled with its volume table name).
 *
 * Unlike u-boot this driver does not replay the journal: it walks the
 * committed on-flash index (superblock -> newest master node -> B-tree
 * range walks), so changes written after the last commit of an
 * uncleanly detached image are not visible.  Compression: none, LZO,
 * zlib (raw deflate) and zstd.  Encrypted or authenticated
 * filesystems are rejected.
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>
#include <grub/deflate.h>
#include <minilzo.h>
#include <zstd.h>

GRUB_MOD_LICENSE("GPLv2+");

/* UBI container (all header fields big-endian) */
#define UBI_EC_MAGIC		0x55424923	/* "UBI#" */
#define UBI_VID_MAGIC		0x55424921	/* "UBI!" */
#define UBI_HDR_LEN		64
#define UBI_CRC_LEN		60	/* hdr_crc covers this much */
#define UBI_MAX_PEB_SIZE	0x1000000
#define UBI_INTERNAL_VOL	0x7fff0000	/* internal volumes from here */
#define UBI_LAYOUT_VOL		0x7fffefff	/* volume table volume */
#define UBI_VTBL_REC_LEN	172
#define UBI_VTBL_NAME_MAX	127

/* UBIFS on-flash format */
#define UBIFS_MAGIC		0x06101831
#define UBIFS_CRC32_INIT	0xffffffffu
#define UBIFS_BLOCK_SIZE	4096
#define UBIFS_ROOT_INO		1
#define UBIFS_SB_LNUM		0
#define UBIFS_MST_LNUM		1
#define UBIFS_KEY_LEN		8	/* simple key format */

/* node types */
#define UBIFS_INO_NODE		0
#define UBIFS_DATA_NODE		1
#define UBIFS_DENT_NODE		2
#define UBIFS_XENT_NODE		3
#define UBIFS_PAD_NODE		5
#define UBIFS_SB_NODE		6
#define UBIFS_MST_NODE		7
#define UBIFS_IDX_NODE		9

/* key types (high 3 bits of the second key word) */
#define UBIFS_INO_KEY		0
#define UBIFS_DATA_KEY		1
#define UBIFS_DENT_KEY		2
#define UBIFS_S_KEY_BLOCK_MASK	0x1fffffff

/* inode types (dent->type) */
#define UBIFS_ITYPE_REG		0
#define UBIFS_ITYPE_DIR		1
#define UBIFS_ITYPE_LNK		2

/* compression types */
#define UBIFS_COMPR_NONE	0
#define UBIFS_COMPR_LZO		1
#define UBIFS_COMPR_ZLIB	2
#define UBIFS_COMPR_ZSTD	3

/* superblock flags */
#define UBIFS_FLG_BIGLPT	0x02
#define UBIFS_FLG_SPACE_FIXUP	0x04
#define UBIFS_FLG_DOUBLE_HASH	0x08
#define UBIFS_FLG_ENCRYPTION	0x10
#define UBIFS_FLG_AUTHENTICATION	0x20

/* common header (24 bytes): magic @0, crc @4 (over [8,len)), sqnum @8,
   len @16, node_type @20 */
#define UBIFS_CH_LEN		24
/* superblock node: key_hash @26, key_fmt @27, flags @28,
   min_io_size @32, leb_size @36, leb_cnt @40, fanout @72,
   fmt_version @80, uuid @108, ro_compat_version @124; 4096 total */
#define UBIFS_SB_LEN		4096
/* master node: root_lnum @48, root_offs @52, root_len @56; 512 total */
#define UBIFS_MST_LEN		512
/* inode node: key @24, size @48, mtime_sec @72, nlink @92, mode @104,
   data_len @112, data @160 */
#define UBIFS_INO_LEN		160
/* directory entry node: key @24, inum @40, type @49, nlen @50, name @56 */
#define UBIFS_DENT_LEN		56
/* data node: key @24, size @40, compr_type @44, data @48 */
#define UBIFS_DATA_LEN		48
/* index node: child_cnt @24, level @26, branches @28;
   branch: lnum @0, offs @4, len @8, key @12 */
#define UBIFS_IDX_LEN		28
#define UBIFS_BRANCH_LEN	(12 + UBIFS_KEY_LEN)

#define UBIFS_MAX_NODE_LEN	(UBIFS_INO_LEN + UBIFS_BLOCK_SIZE)
#define UBIFS_MAX_DEPTH		64
#define UBIFS_MAX_FANOUT	1024

struct grub_ubifs_key
{
	grub_uint32_t lo;		/* inode number */
	grub_uint32_t hi;		/* type << 29 | hash / block */
};

struct grub_ubifs_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	/* UBI mapping: lnum -> byte offset, ~0 = unmapped; NULL when the
	   image is a bare UBIFS (LEB n at n * leb_size) */
	grub_uint64_t *leb_off;
	grub_uint32_t leb_map_cnt;
	char *vol_name;			/* UBI volume name, may be NULL */
	/* superblock */
	grub_uint32_t leb_size;
	grub_uint32_t leb_cnt;
	grub_uint8_t uuid[16];
	/* newest master node */
	grub_uint32_t root_lnum;
	grub_uint32_t root_offs;
	grub_uint32_t root_len;
	struct grub_fshelp_node *root;
};

struct grub_fshelp_node
{
	struct grub_ubifs_data *data;
	grub_uint64_t ino;
	grub_uint8_t type;		/* UBIFS_ITYPE_* */
	grub_uint64_t size;		/* valid for opened files */
};

/* CRC-32 (poly 0xEDB88320, seed passed in, no inversion); UBIFS node
   CRCs seed with 0xFFFFFFFF, UBI header CRCs likewise */
static grub_uint32_t grub_ubifs_crc_table[256];
static int grub_ubifs_crc_ready;

static grub_uint32_t
grub_ubifs_crc(grub_uint32_t crc, const grub_uint8_t *buf, grub_size_t len)
{
	if (!grub_ubifs_crc_ready)
	{
		grub_uint32_t i, j, c;

		for (i = 0; i < 256; i++)
		{
			c = i;
			for (j = 0; j < 8; j++)
				c = (c >> 1) ^ ((c & 1) ? 0xedb88320 : 0);
			grub_ubifs_crc_table[i] = c;
		}
		grub_ubifs_crc_ready = 1;
	}
	while (len--)
		crc = grub_ubifs_crc_table[(crc ^ *buf++) & 0xff]
			^ (crc >> 8);
	return crc;
}

static grub_uint16_t
ub_get16(const grub_uint8_t *p)
{
	return grub_le_to_cpu16(grub_get_unaligned16(p));
}

static grub_uint32_t
ub_get32(const grub_uint8_t *p)
{
	return grub_le_to_cpu32(grub_get_unaligned32(p));
}

static grub_uint64_t
ub_get64(const grub_uint8_t *p)
{
	return grub_le_to_cpu64(grub_get_unaligned64(p));
}

static grub_uint16_t
ub_be16(const grub_uint8_t *p)
{
	return grub_be_to_cpu16(grub_get_unaligned16(p));
}

static grub_uint32_t
ub_be32(const grub_uint8_t *p)
{
	return grub_be_to_cpu32(grub_get_unaligned32(p));
}

static grub_uint64_t
ub_be64(const grub_uint8_t *p)
{
	return grub_be_to_cpu64(grub_get_unaligned64(p));
}

static int
grub_ubifs_key_cmp(const struct grub_ubifs_key *a,
	const struct grub_ubifs_key *b)
{
	if (a->lo != b->lo)
		return a->lo < b->lo ? -1 : 1;
	if (a->hi != b->hi)
		return a->hi < b->hi ? -1 : 1;
	return 0;
}

static grub_err_t
grub_ubifs_leb_read(struct grub_ubifs_data *data, grub_uint32_t lnum,
	grub_uint32_t offs, grub_size_t len, void *buf)
{
	grub_uint64_t base;

	if (lnum >= data->leb_cnt
		|| (grub_uint64_t) offs + len > data->leb_size)
		return grub_error(GRUB_ERR_BAD_FS,
			"ubifs: LEB reference out of range");
	if (data->leb_off)
	{
		if (lnum >= data->leb_map_cnt
			|| data->leb_off[lnum] == ~(grub_uint64_t) 0)
			return grub_error(GRUB_ERR_BAD_FS,
				"ubifs: unmapped LEB %u", lnum);
		base = data->leb_off[lnum];
	}
	else
		base = (grub_uint64_t) lnum * data->leb_size;
	if (base + offs + len > data->disk_size)
		return grub_error(GRUB_ERR_BAD_FS,
			"ubifs: LEB %u beyond end of image", lnum);
	return grub_disk_read(data->disk, 0, base + offs, len, buf);
}

/* validate a node's common header and CRC in place */
static grub_err_t
grub_ubifs_check_node(const grub_uint8_t *node, grub_uint32_t len,
	int node_type)
{
	grub_uint32_t nlen;

	if (len < UBIFS_CH_LEN
		|| ub_get32(node) != UBIFS_MAGIC
		|| node[20] != node_type)
		goto bad;
	nlen = ub_get32(node + 16);
	if (nlen < UBIFS_CH_LEN || nlen > len)
		goto bad;
	if (ub_get32(node + 4)
		!= grub_ubifs_crc(UBIFS_CRC32_INIT, node + 8, nlen - 8))
		goto bad;
	return GRUB_ERR_NONE;

bad:
	return grub_error(GRUB_ERR_BAD_FS, "ubifs: corrupt node");
}

/*
 * Index walk: visit every leaf node whose key falls into [lo, hi],
 * reading index nodes straight from the media (the on-flash index is
 * complete for committed data; there is no in-memory TNC).
 */

typedef int (*grub_ubifs_walk_cb)(const grub_uint8_t *node,
	grub_uint32_t len, void *ctx);

static grub_err_t
grub_ubifs_walk(struct grub_ubifs_data *data, grub_uint32_t lnum,
	grub_uint32_t offs, grub_uint32_t len,
	const struct grub_ubifs_key *lo, const struct grub_ubifs_key *hi,
	grub_ubifs_walk_cb cb, void *ctx, unsigned depth, int *stopped)
{
	grub_uint8_t *idx = NULL;
	grub_uint32_t child_cnt, i;

	if (depth > UBIFS_MAX_DEPTH)
		return grub_error(GRUB_ERR_BAD_FS, "ubifs: index too deep");
	if (len < UBIFS_IDX_LEN || len > UBIFS_IDX_LEN
		+ (grub_uint32_t) UBIFS_MAX_FANOUT * UBIFS_BRANCH_LEN)
		return grub_error(GRUB_ERR_BAD_FS,
			"ubifs: bad index node size");

	idx = grub_malloc(len);
	if (!idx)
		return grub_errno;
	if (grub_ubifs_leb_read(data, lnum, offs, len, idx)
		|| grub_ubifs_check_node(idx, len, UBIFS_IDX_NODE))
		goto fail;
	child_cnt = ub_get16(idx + 24);
	if (child_cnt > UBIFS_MAX_FANOUT
		|| UBIFS_IDX_LEN + child_cnt * UBIFS_BRANCH_LEN
			> ub_get32(idx + 16))
	{
		grub_error(GRUB_ERR_BAD_FS, "ubifs: corrupt index node");
		goto fail;
	}

	for (i = 0; i < child_cnt && !*stopped; i++)
	{
		const grub_uint8_t *br = idx + UBIFS_IDX_LEN
			+ i * UBIFS_BRANCH_LEN;
		struct grub_ubifs_key key, next;
		grub_uint32_t blnum, boffs, blen;

		key.lo = ub_get32(br + 12);
		key.hi = ub_get32(br + 16);
		if (grub_ubifs_key_cmp(&key, hi) > 0)
			break;
		if (i + 1 < child_cnt)
		{
			/* subtree i spans up to the first key of subtree
			   i+1; skip it when that still falls below LO */
			next.lo = ub_get32(br + UBIFS_BRANCH_LEN + 12);
			next.hi = ub_get32(br + UBIFS_BRANCH_LEN + 16);
			if (grub_ubifs_key_cmp(&next, lo) < 0)
				continue;
		}
		blnum = ub_get32(br);
		boffs = ub_get32(br + 4);
		blen = ub_get32(br + 8);

		if (ub_get16(idx + 26) != 0)	/* level */
		{
			if (grub_ubifs_walk(data, blnum, boffs, blen, lo,
				hi, cb, ctx, depth + 1, stopped))
				goto fail;
		}
		else if (grub_ubifs_key_cmp(&key, lo) >= 0)
		{
			grub_uint8_t *leaf;

			if (blen < UBIFS_CH_LEN
				|| blen > UBIFS_MAX_NODE_LEN)
			{
				grub_error(GRUB_ERR_BAD_FS,
					"ubifs: bad leaf node size");
				goto fail;
			}
			leaf = grub_malloc(blen);
			if (!leaf)
				goto fail;
			if (grub_ubifs_leb_read(data, blnum, boffs, blen,
				leaf)
				|| grub_ubifs_check_node(leaf, blen,
					leaf[20]))
			{
				grub_free(leaf);
				goto fail;
			}
			if (cb(leaf, blen, ctx))
				*stopped = 1;
			grub_free(leaf);
			if (grub_errno)
				goto fail;
		}
	}

	grub_free(idx);
	return GRUB_ERR_NONE;

fail:
	grub_free(idx);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "ubifs: index walk failed");
	return grub_errno;
}

static grub_err_t
grub_ubifs_walk_range(struct grub_ubifs_data *data,
	const struct grub_ubifs_key *lo, const struct grub_ubifs_key *hi,
	grub_ubifs_walk_cb cb, void *ctx, int *stopped_out)
{
	int stopped = 0;
	grub_err_t err;

	err = grub_ubifs_walk(data, data->root_lnum, data->root_offs,
		data->root_len, lo, hi, cb, ctx, 0, &stopped);
	if (stopped_out)
		*stopped_out = stopped;
	return err;
}

/* exact inode node lookup */
struct grub_ubifs_ino_info
{
	grub_uint64_t ino;
	int found;
	grub_uint64_t size;
	grub_int64_t mtime;
	grub_uint32_t nlink;
	grub_uint32_t data_len;
	char *sdata;			/* malloc'ed inode data if wanted */
	int want_data;
};

static int
grub_ubifs_ino_cb(const grub_uint8_t *node, grub_uint32_t len, void *ctx_in)
{
	struct grub_ubifs_ino_info *info = ctx_in;

	if (node[20] != UBIFS_INO_NODE || len < UBIFS_INO_LEN
		|| ub_get32(node + 24) != (grub_uint32_t) info->ino)
		return 0;
	info->found = 1;
	info->size = ub_get64(node + 48);
	info->mtime = (grub_int64_t) ub_get64(node + 72);
	info->nlink = ub_get32(node + 92);
	info->data_len = ub_get32(node + 112);
	if (info->want_data)
	{
		grub_uint32_t dlen = info->data_len;

		if ((grub_uint64_t) UBIFS_INO_LEN + dlen > len)
			dlen = len - UBIFS_INO_LEN;
		info->sdata = grub_malloc((grub_size_t) dlen + 1);
		if (!info->sdata)
			return 1;
		grub_memcpy(info->sdata, node + UBIFS_INO_LEN, dlen);
		info->sdata[dlen] = '\0';
	}
	return 1;
}

static grub_err_t
grub_ubifs_lookup_ino(struct grub_ubifs_data *data, grub_uint64_t ino,
	int want_data, struct grub_ubifs_ino_info *info)
{
	struct grub_ubifs_key key;

	grub_memset(info, 0, sizeof(*info));
	info->ino = ino;
	info->want_data = want_data;
	key.lo = (grub_uint32_t) ino;
	key.hi = (grub_uint32_t) UBIFS_INO_KEY << 29;
	if (grub_ubifs_walk_range(data, &key, &key, grub_ubifs_ino_cb,
		info, NULL))
		return grub_errno;
	if (!info->found)
		return grub_error(GRUB_ERR_BAD_FS,
			"ubifs: inode %llu not found",
			(unsigned long long) ino);
	return GRUB_ERR_NONE;
}

/* directory entry iteration */
struct grub_ubifs_dent_ctx
{
	grub_uint64_t dir_ino;
	int (*hook) (const char *name, grub_uint8_t type,
		grub_uint64_t inum, void *hook_data);
	void *hook_data;
};

static int
grub_ubifs_dent_cb(const grub_uint8_t *node, grub_uint32_t len, void *ctx_in)
{
	struct grub_ubifs_dent_ctx *ctx = ctx_in;
	grub_uint64_t inum;
	grub_uint32_t nlen;
	char name[256];

	if (node[20] != UBIFS_DENT_NODE || len < UBIFS_DENT_LEN
		|| ub_get32(node + 24) != (grub_uint32_t) ctx->dir_ino)
		return 0;
	nlen = ub_get16(node + 50);
	if (nlen == 0 || nlen > 255
		|| (grub_uint64_t) UBIFS_DENT_LEN + nlen > len)
		return 0;
	inum = ub_get64(node + 40);
	if (inum == 0)
		return 0;
	grub_memcpy(name, node + UBIFS_DENT_LEN, nlen);
	name[nlen] = '\0';
	return ctx->hook(name, node[49], inum, ctx->hook_data);
}

static int
grub_ubifs_iterate_entries(struct grub_ubifs_data *data,
	grub_uint64_t dir_ino, struct grub_ubifs_dent_ctx *ctx)
{
	struct grub_ubifs_key lo, hi;
	int stopped = 0;

	lo.lo = (grub_uint32_t) dir_ino;
	lo.hi = (grub_uint32_t) UBIFS_DENT_KEY << 29;
	hi.lo = (grub_uint32_t) dir_ino;
	hi.hi = ((grub_uint32_t) UBIFS_DENT_KEY << 29)
		| UBIFS_S_KEY_BLOCK_MASK;
	ctx->dir_ino = dir_ino;
	/* on error return 0 with grub_errno set so callers propagate it */
	if (grub_ubifs_walk_range(data, &lo, &hi, grub_ubifs_dent_cb,
		ctx, &stopped))
		return 0;
	return stopped;
}

/* file data */
struct grub_ubifs_read_ctx
{
	grub_uint64_t ino;
	grub_uint64_t pos;		/* file offset of buf[0] */
	grub_size_t len;
	char *buf;
	grub_uint8_t *block;		/* UBIFS_BLOCK_SIZE scratch */
};

static int
grub_ubifs_data_cb(const grub_uint8_t *node, grub_uint32_t len, void *ctx_in)
{
	struct grub_ubifs_read_ctx *ctx = ctx_in;
	grub_uint64_t bstart, bend, cs, ce;
	grub_uint32_t block, dsize, csize;
	grub_uint16_t compr;
	const grub_uint8_t *src;

	if (node[20] != UBIFS_DATA_NODE || len < UBIFS_DATA_LEN
		|| ub_get32(node + 24) != (grub_uint32_t) ctx->ino
		|| (ub_get32(node + 28) >> 29) != UBIFS_DATA_KEY)
		return 0;
	block = ub_get32(node + 28) & UBIFS_S_KEY_BLOCK_MASK;
	dsize = ub_get32(node + 40);
	compr = ub_get16(node + 44);
	csize = ub_get32(node + 16) - UBIFS_DATA_LEN;
	if (dsize == 0 || dsize > UBIFS_BLOCK_SIZE || csize > len - UBIFS_DATA_LEN)
	{
		grub_error(GRUB_ERR_BAD_FS, "ubifs: corrupt data node");
		return 1;
	}

	bstart = (grub_uint64_t) block * UBIFS_BLOCK_SIZE;
	bend = bstart + dsize;
	cs = bstart > ctx->pos ? bstart : ctx->pos;
	ce = bend < ctx->pos + ctx->len ? bend : ctx->pos + ctx->len;
	if (cs >= ce)
		return 0;

	src = node + UBIFS_DATA_LEN;
	switch (compr)
	{
	case UBIFS_COMPR_NONE:
		if (csize < dsize)
			goto corrupt;
		grub_memcpy(ctx->block, src, dsize);
		break;
	case UBIFS_COMPR_LZO:
	{
		lzo_uint dst_len = dsize;

		if (lzo1x_decompress_safe(src, csize, ctx->block, &dst_len,
			NULL) != LZO_E_OK || dst_len != dsize)
			goto corrupt;
		break;
	}
	case UBIFS_COMPR_ZLIB:
	{
		/* UBIFS zlib streams are raw deflate (no zlib header) */
		grub_ssize_t n = grub_deflate_decompress((char *) src,
			csize, 0, (char *) ctx->block, dsize);

		if (n < 0)
			return 1;
		if ((grub_uint32_t) n < dsize)
			goto corrupt;
		break;
	}
	case UBIFS_COMPR_ZSTD:
	{
		grub_size_t n = ZSTD_decompress(ctx->block,
			UBIFS_BLOCK_SIZE, src, csize);

		if (ZSTD_isError(n) || n != dsize)
			goto corrupt;
		break;
	}
	default:
		grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
			"ubifs: compression type %u not supported",
			(unsigned) compr);
		return 1;
	}

	grub_memcpy(ctx->buf + (grub_size_t) (cs - ctx->pos),
		ctx->block + (grub_size_t) (cs - bstart),
		(grub_size_t) (ce - cs));
	return 0;

corrupt:
	grub_error(GRUB_ERR_BAD_FS, "ubifs: bad compressed data");
	return 1;
}

static grub_err_t
grub_ubifs_read_file(struct grub_ubifs_data *data, grub_uint64_t ino,
	grub_off_t pos, grub_size_t len, char *buf)
{
	struct grub_ubifs_read_ctx ctx;
	struct grub_ubifs_key lo, hi;
	grub_uint64_t b0, b1;

	if (len == 0)
		return GRUB_ERR_NONE;
	b0 = pos / UBIFS_BLOCK_SIZE;
	b1 = (pos + len - 1) / UBIFS_BLOCK_SIZE;
	if (b1 > UBIFS_S_KEY_BLOCK_MASK)
		return grub_error(GRUB_ERR_OUT_OF_RANGE, "ubifs: file too big");

	ctx.ino = ino;
	ctx.pos = pos;
	ctx.len = len;
	ctx.buf = buf;
	ctx.block = grub_malloc(UBIFS_BLOCK_SIZE);
	if (!ctx.block)
		return grub_errno;

	/* missing blocks are holes */
	grub_memset(buf, 0, len);

	lo.lo = (grub_uint32_t) ino;
	lo.hi = ((grub_uint32_t) UBIFS_DATA_KEY << 29)
		| (grub_uint32_t) b0;
	hi.lo = (grub_uint32_t) ino;
	hi.hi = ((grub_uint32_t) UBIFS_DATA_KEY << 29)
		| (grub_uint32_t) b1;
	grub_ubifs_walk_range(data, &lo, &hi, grub_ubifs_data_cb, &ctx,
		NULL);
	grub_free(ctx.block);
	return grub_errno;
}

/*
 * Mount: optional UBI mapping, superblock, newest master node.
 */

static grub_err_t
grub_ubifs_read_sb(struct grub_ubifs_data *data)
{
	grub_uint8_t *sb;
	grub_uint32_t flags, leb_size;

	sb = grub_malloc(UBIFS_SB_LEN);
	if (!sb)
		return grub_errno;
	/* leb_size is not known yet: read the superblock node directly
	   (LEB 0 always starts at the mapped/bare offset 0) */
	if (data->leb_off)
	{
		if (data->leb_map_cnt == 0
			|| data->leb_off[0] == ~(grub_uint64_t) 0
			|| data->leb_off[0] + UBIFS_SB_LEN > data->disk_size
			|| grub_disk_read(data->disk, 0, data->leb_off[0],
				UBIFS_SB_LEN, sb))
			goto bad;
	}
	else if (UBIFS_SB_LEN > data->disk_size
		|| grub_disk_read(data->disk, 0, 0, UBIFS_SB_LEN, sb))
		goto bad;
	if (grub_ubifs_check_node(sb, UBIFS_SB_LEN, UBIFS_SB_NODE))
		goto fail;

	if (sb[27] != 0)	/* key_fmt: simple keys only */
		goto bad;
	flags = ub_get32(sb + 28);
	if (flags & (UBIFS_FLG_ENCRYPTION | UBIFS_FLG_AUTHENTICATION))
	{
		grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
			"ubifs: encrypted or authenticated filesystem");
		goto fail;
	}
	leb_size = ub_get32(sb + 36);
	if (leb_size < UBIFS_SB_LEN || leb_size > 0x8000000)
		goto bad;
	if (data->leb_off && leb_size != data->leb_size)
		goto bad;
	data->leb_size = leb_size;
	data->leb_cnt = ub_get32(sb + 40);
	if (data->leb_cnt < 5)
		goto bad;
	grub_memcpy(data->uuid, sb + 108, 16);
	grub_free(sb);
	return GRUB_ERR_NONE;

bad:
	grub_error(GRUB_ERR_BAD_FS, "not a ubifs filesystem");
fail:
	grub_free(sb);
	return grub_errno;
}

/* scan one master-area LEB for its newest valid master node */
static void
grub_ubifs_scan_master_leb(struct grub_ubifs_data *data, grub_uint32_t lnum,
	grub_uint64_t *best_sqnum, int *found)
{
	grub_uint8_t node[UBIFS_MST_LEN];
	grub_uint32_t offs = 0;

	while (offs + UBIFS_MST_LEN <= data->leb_size)
	{
		grub_uint32_t nlen;

		if (grub_ubifs_leb_read(data, lnum, offs, UBIFS_CH_LEN,
			node))
			break;
		if (ub_get32(node) != UBIFS_MAGIC)
			break;
		nlen = ub_get32(node + 16);
		if (nlen < UBIFS_CH_LEN || offs + nlen > data->leb_size)
			break;
		if (node[20] == UBIFS_PAD_NODE)
		{
			grub_uint32_t pad_len;

			if (nlen < 28 || nlen > sizeof(node)
				|| grub_ubifs_leb_read(data, lnum, offs,
					nlen, node)
				|| grub_ubifs_check_node(node, nlen,
					UBIFS_PAD_NODE))
				break;
			pad_len = ub_get32(node + 24);
			if (pad_len > data->leb_size - offs)
				break;
			offs += ((nlen + 7) & ~(grub_uint32_t) 7) + pad_len;
			continue;
		}
		if (node[20] != UBIFS_MST_NODE || nlen > UBIFS_MST_LEN
			|| grub_ubifs_leb_read(data, lnum, offs, nlen, node)
			|| grub_ubifs_check_node(node, nlen,
				UBIFS_MST_NODE))
			break;
		if (nlen >= 60)
		{
			grub_uint64_t sqnum = ub_get64(node + 8);

			if (!*found || sqnum >= *best_sqnum)
			{
				*best_sqnum = sqnum;
				*found = 1;
				data->root_lnum = ub_get32(node + 48);
				data->root_offs = ub_get32(node + 52);
				data->root_len = ub_get32(node + 56);
			}
		}
		offs += (nlen + 7) & ~(grub_uint32_t) 7;
	}
	grub_errno = GRUB_ERR_NONE;
}

static grub_err_t
grub_ubifs_read_master(struct grub_ubifs_data *data)
{
	grub_uint64_t best_sqnum = 0;
	int found = 0;

	grub_ubifs_scan_master_leb(data, UBIFS_MST_LNUM, &best_sqnum,
		&found);
	grub_ubifs_scan_master_leb(data, UBIFS_MST_LNUM + 1, &best_sqnum,
		&found);
	if (!found)
		return grub_error(GRUB_ERR_BAD_FS,
			"ubifs: no valid master node");
	if (data->root_len < UBIFS_IDX_LEN
		|| data->root_lnum >= data->leb_cnt
		|| (grub_uint64_t) data->root_offs + data->root_len
			> data->leb_size)
		return grub_error(GRUB_ERR_BAD_FS,
			"ubifs: bad index root reference");
	return GRUB_ERR_NONE;
}

/* map a UBI container: detect the PEB size from the EC header spacing,
   then map the first volume whose LEB 0 holds a UBIFS superblock */
static grub_err_t
grub_ubifs_map_ubi(struct grub_ubifs_data *data)
{
	grub_uint8_t hdr[UBI_HDR_LEN];
	grub_uint64_t peb_size = 0, npebs, peb, *sqnums = NULL;
	grub_uint32_t vid_hdr_offset, data_offset, data_pad = 0;
	grub_uint64_t vtbl_off = ~(grub_uint64_t) 0, vtbl_sq = 0;
	grub_uint32_t vol_id = 0;
	grub_uint64_t off;
	int have_vol = 0;

	if (grub_disk_read(data->disk, 0, 0, sizeof(hdr), hdr))
		return grub_errno;
	if (ub_be32(hdr) != UBI_EC_MAGIC
		|| ub_be32(hdr + 60)
			!= grub_ubifs_crc(UBIFS_CRC32_INIT, hdr,
				UBI_CRC_LEN))
		return grub_error(GRUB_ERR_BAD_FS, "not a ubi image");
	vid_hdr_offset = ub_be32(hdr + 16);
	data_offset = ub_be32(hdr + 20);
	if (vid_hdr_offset < UBI_HDR_LEN || data_offset
		< vid_hdr_offset + UBI_HDR_LEN
		|| data_offset >= UBI_MAX_PEB_SIZE)
		return grub_error(GRUB_ERR_BAD_FS, "ubifs: bad ubi headers");

	/* PEB size = distance to the next EC header */
	for (off = 512; off < data->disk_size && off <= UBI_MAX_PEB_SIZE;
		off += 512)
	{
		if (grub_disk_read(data->disk, 0, off, sizeof(hdr), hdr))
			return grub_errno;
		if (ub_be32(hdr) == UBI_EC_MAGIC
			&& ub_be32(hdr + 60)
				== grub_ubifs_crc(UBIFS_CRC32_INIT, hdr,
					UBI_CRC_LEN))
		{
			peb_size = off;
			break;
		}
	}
	if (peb_size <= data_offset)
		return grub_error(GRUB_ERR_BAD_FS,
			"ubifs: cannot detect ubi eraseblock size");
	data->leb_size = (grub_uint32_t) (peb_size - data_offset);

	npebs = data->disk_size / peb_size;
	data->leb_off = grub_malloc((grub_size_t) npebs
		* sizeof(*data->leb_off));
	sqnums = grub_malloc((grub_size_t) npebs * sizeof(*sqnums));
	if (!data->leb_off || !sqnums)
		goto fail;
	data->leb_map_cnt = (grub_uint32_t) npebs;

	/* two passes: find the volume to mount, then map its LEBs */
	for (peb = 0; peb < npebs; peb++)
	{
		grub_uint8_t vid[UBI_HDR_LEN];
		grub_uint32_t vol, lnum;
		grub_uint64_t sqnum;

		if (grub_disk_read(data->disk, 0, peb * peb_size,
			sizeof(hdr), hdr))
			goto ignore;
		if (ub_be32(hdr) != UBI_EC_MAGIC
			|| ub_be32(hdr + 60)
				!= grub_ubifs_crc(UBIFS_CRC32_INIT, hdr,
					UBI_CRC_LEN))
			goto ignore;
		if (grub_disk_read(data->disk, 0,
			peb * peb_size + ub_be32(hdr + 16), sizeof(vid),
			vid))
			goto ignore;
		if (ub_be32(vid) != UBI_VID_MAGIC
			|| ub_be32(vid + 60)
				!= grub_ubifs_crc(UBIFS_CRC32_INIT, vid,
					UBI_CRC_LEN))
			goto ignore;
		vol = ub_be32(vid + 8);
		lnum = ub_be32(vid + 12);
		sqnum = ub_be64(vid + 40);
		if (vol == UBI_LAYOUT_VOL && lnum <= 1)
		{
			if (vtbl_off == ~(grub_uint64_t) 0
				|| (lnum == 0 && sqnum > vtbl_sq))
			{
				vtbl_off = peb * peb_size + data_offset;
				vtbl_sq = sqnum;
			}
			continue;
		}
		if (vol >= UBI_INTERNAL_VOL || lnum >= npebs)
			continue;
		if (lnum == 0)
		{
			grub_uint8_t probe[UBIFS_CH_LEN];

			/* candidate volume: UBIFS superblock at LEB 0? */
			if ((!have_vol || vol < vol_id)
				&& grub_disk_read(data->disk, 0,
					peb * peb_size + data_offset,
					sizeof(probe), probe)
					== GRUB_ERR_NONE
				&& ub_get32(probe) == UBIFS_MAGIC
				&& probe[20] == UBIFS_SB_NODE)
			{
				data_pad = ub_be32(vid + 28);
				vol_id = vol;
				have_vol = 1;
			}
		}
		continue;

ignore:
		grub_errno = GRUB_ERR_NONE;
	}
	if (!have_vol)
	{
		grub_error(GRUB_ERR_BAD_FS,
			"ubifs: no ubifs volume in ubi image");
		goto fail;
	}
	if (data_pad >= data->leb_size)
	{
		grub_error(GRUB_ERR_BAD_FS, "ubifs: bad ubi data_pad");
		goto fail;
	}
	data->leb_size -= data_pad;

	for (peb = 0; peb < npebs; peb++)
		data->leb_off[peb] = ~(grub_uint64_t) 0;
	for (peb = 0; peb < npebs; peb++)
	{
		grub_uint8_t vid[UBI_HDR_LEN];
		grub_uint32_t lnum;
		grub_uint64_t sqnum;

		if (grub_disk_read(data->disk, 0, peb * peb_size,
			sizeof(hdr), hdr)
			|| ub_be32(hdr) != UBI_EC_MAGIC
			|| grub_disk_read(data->disk, 0,
				peb * peb_size + ub_be32(hdr + 16),
				sizeof(vid), vid)
			|| ub_be32(vid) != UBI_VID_MAGIC
			|| ub_be32(vid + 60)
				!= grub_ubifs_crc(UBIFS_CRC32_INIT, vid,
					UBI_CRC_LEN)
			|| ub_be32(vid + 8) != vol_id)
		{
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		lnum = ub_be32(vid + 12);
		sqnum = ub_be64(vid + 40);
		if (lnum >= npebs)
			continue;
		/* a leftover wear-leveling copy: newest wins */
		if (data->leb_off[lnum] != ~(grub_uint64_t) 0
			&& sqnums[lnum] >= sqnum)
			continue;
		data->leb_off[lnum] = peb * peb_size + data_offset;
		sqnums[lnum] = sqnum;
	}
	grub_free(sqnums);
	sqnums = NULL;

	/* volume name from the layout volume, for the label */
	if (vtbl_off != ~(grub_uint64_t) 0)
	{
		grub_uint8_t rec[UBI_VTBL_REC_LEN];
		grub_uint64_t rec_off = vtbl_off
			+ (grub_uint64_t) vol_id * UBI_VTBL_REC_LEN;

		if ((grub_uint64_t) vol_id * UBI_VTBL_REC_LEN
			+ UBI_VTBL_REC_LEN <= data->leb_size
			&& grub_disk_read(data->disk, 0, rec_off,
				sizeof(rec), rec) == GRUB_ERR_NONE
			&& ub_be32(rec + 168)
				== grub_ubifs_crc(UBIFS_CRC32_INIT, rec,
					UBI_VTBL_REC_LEN - 4))
		{
			grub_uint32_t name_len = ub_be16(rec + 14);

			if (name_len <= UBI_VTBL_NAME_MAX)
				data->vol_name = grub_strndup(
					(char *) rec + 16, name_len);
		}
		grub_errno = GRUB_ERR_NONE;
	}
	return GRUB_ERR_NONE;

fail:
	grub_free(sqnums);
	grub_free(data->leb_off);
	data->leb_off = NULL;
	return grub_errno;
}

static void
grub_ubifs_unmount(struct grub_ubifs_data *data)
{
	if (!data)
		return;
	grub_free(data->leb_off);
	grub_free(data->vol_name);
	grub_free(data);
}

static struct grub_ubifs_data *
grub_ubifs_mount(grub_disk_t disk)
{
	struct grub_ubifs_data *data;
	grub_uint8_t probe[UBIFS_CH_LEN];

	if (disk->total_sectors == GRUB_DISK_SIZE_UNKNOWN)
	{
		grub_error(GRUB_ERR_BAD_FS, "not a ubifs filesystem");
		return NULL;
	}

	data = grub_zalloc(sizeof(*data) + sizeof(*data->root));
	if (!data)
		return NULL;
	data->disk = disk;
	data->disk_size = disk->total_sectors << GRUB_DISK_SECTOR_BITS;
	data->root = (struct grub_fshelp_node *) (data + 1);
	data->root->data = data;
	data->root->ino = UBIFS_ROOT_INO;
	data->root->type = UBIFS_ITYPE_DIR;

	if (grub_disk_read(disk, 0, 0, sizeof(probe), probe))
		goto fail;
	if (ub_be32(probe) == UBI_EC_MAGIC)
	{
		if (grub_ubifs_map_ubi(data))
			goto fail;
	}
	else if (ub_get32(probe) != UBIFS_MAGIC
		|| probe[20] != UBIFS_SB_NODE)
	{
		grub_error(GRUB_ERR_BAD_FS, "not a ubifs filesystem");
		goto fail;
	}

	if (grub_ubifs_read_sb(data) || grub_ubifs_read_master(data))
		goto fail;
	return data;

fail:
	grub_ubifs_unmount(data);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "not a ubifs filesystem");
	return NULL;
}

/* fshelp bindings */
struct grub_ubifs_fshelp_ctx
{
	struct grub_ubifs_data *data;
	grub_fshelp_iterate_dir_hook_t hook;
	void *hook_data;
};

static int
grub_ubifs_fshelp_iter(const char *name, grub_uint8_t type,
	grub_uint64_t inum, void *ctx_in)
{
	struct grub_ubifs_fshelp_ctx *ctx = ctx_in;
	struct grub_fshelp_node *node;
	enum grub_fshelp_filetype ftype;

	node = grub_zalloc(sizeof(*node));
	if (!node)
		return 1;
	node->data = ctx->data;
	node->ino = inum;
	node->type = type;
	switch (type)
	{
	case UBIFS_ITYPE_DIR:
		ftype = GRUB_FSHELP_DIR;
		break;
	case UBIFS_ITYPE_LNK:
		ftype = GRUB_FSHELP_SYMLINK;
		break;
	case UBIFS_ITYPE_REG:
		ftype = GRUB_FSHELP_REG;
		break;
	default:
		ftype = GRUB_FSHELP_UNKNOWN;
		break;
	}
	return ctx->hook(name, ftype, node, ctx->hook_data);
}

static int
grub_ubifs_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_ubifs_fshelp_ctx fctx = { dir->data, hook, hook_data };
	struct grub_ubifs_dent_ctx ctx;

	ctx.hook = grub_ubifs_fshelp_iter;
	ctx.hook_data = &fctx;
	return grub_ubifs_iterate_entries(dir->data, dir->ino, &ctx);
}

static char *
grub_ubifs_read_symlink(grub_fshelp_node_t node)
{
	struct grub_ubifs_ino_info info;

	if (grub_ubifs_lookup_ino(node->data, node->ino, 1, &info))
		return NULL;
	return info.sdata;
}

/* grub_fs dir: emit entries with mtime from each inode node */
struct grub_ubifs_dir_ctx
{
	struct grub_ubifs_data *data;
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_ubifs_dir_iter(const char *name, grub_uint8_t type,
	grub_uint64_t inum, void *ctx_in)
{
	struct grub_ubifs_dir_ctx *ctx = ctx_in;
	struct grub_dirhook_info info;
	struct grub_ubifs_ino_info ii;

	grub_memset(&info, 0, sizeof(info));
	info.dir = (type == UBIFS_ITYPE_DIR);
	info.symlink = (type == UBIFS_ITYPE_LNK);
	info.inodeset = 1;
	info.inode = inum;
	if (grub_ubifs_lookup_ino(ctx->data, inum, 0, &ii) == GRUB_ERR_NONE)
	{
		info.mtimeset = 1;
		info.mtime = ii.mtime;
	}
	else
		grub_errno = GRUB_ERR_NONE;
	return ctx->hook(name, &info, ctx->hook_data);
}

static grub_err_t
grub_ubifs_dir(grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_ubifs_data *data;
	struct grub_ubifs_dir_ctx dctx;
	struct grub_ubifs_dent_ctx ctx;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_ubifs_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(path, data->root, &fdiro,
		grub_ubifs_iterate_dir, grub_ubifs_read_symlink,
		GRUB_FSHELP_DIR);
	if (grub_errno)
		goto fail;

	dctx.data = data;
	dctx.hook = hook;
	dctx.hook_data = hook_data;
	ctx.hook = grub_ubifs_dir_iter;
	ctx.hook_data = &dctx;
	grub_ubifs_iterate_entries(data, fdiro->ino, &ctx);

fail:
	if (fdiro != data->root)
		grub_free(fdiro);
	grub_ubifs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_ubifs_open(struct grub_file *file, const char *name)
{
	struct grub_ubifs_data *data;
	struct grub_fshelp_node *fdiro = NULL;
	struct grub_ubifs_ino_info info;

	data = grub_ubifs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(name, data->root, &fdiro,
		grub_ubifs_iterate_dir, grub_ubifs_read_symlink,
		GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	if (grub_ubifs_lookup_ino(data, fdiro->ino, 0, &info))
		goto fail;

	fdiro->size = info.size;
	file->size = info.size;
	file->data = fdiro;
	return GRUB_ERR_NONE;

fail:
	if (fdiro && fdiro != data->root)
		grub_free(fdiro);
	grub_ubifs_unmount(data);
	return grub_errno;
}

static grub_ssize_t
grub_ubifs_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fshelp_node *node = file->data;

	if (len == 0)
		return 0;
	if (grub_ubifs_read_file(node->data, node->ino, file->offset, len,
		buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_ubifs_close(grub_file_t file)
{
	struct grub_fshelp_node *node = file->data;
	struct grub_ubifs_data *data = node->data;

	if (node != data->root)
		grub_free(node);
	grub_ubifs_unmount(data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_ubifs_label(grub_device_t device, char **label)
{
	struct grub_ubifs_data *data;

	*label = NULL;
	data = grub_ubifs_mount(device->disk);
	if (!data)
		return grub_errno;
	if (data->vol_name)
		*label = grub_strdup(data->vol_name);
	grub_ubifs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_ubifs_uuid(grub_device_t device, char **uuid)
{
	struct grub_ubifs_data *data;

	*uuid = NULL;
	data = grub_ubifs_mount(device->disk);
	if (!data)
		return grub_errno;
	*uuid = grub_xasprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x%02x%02x%02x%02x",
		data->uuid[0], data->uuid[1], data->uuid[2], data->uuid[3],
		data->uuid[4], data->uuid[5], data->uuid[6], data->uuid[7],
		data->uuid[8], data->uuid[9], data->uuid[10],
		data->uuid[11], data->uuid[12], data->uuid[13],
		data->uuid[14], data->uuid[15]);
	grub_ubifs_unmount(data);
	return grub_errno;
}

static struct grub_fs grub_ubifs_fs =
{
	.name = "ubifs",
	.fs_dir = grub_ubifs_dir,
	.fs_open = grub_ubifs_open,
	.fs_read = grub_ubifs_read,
	.fs_close = grub_ubifs_close,
	.fs_label = grub_ubifs_label,
	.fs_uuid = grub_ubifs_uuid,
	.next = 0
};

GRUB_MOD_INIT(ubifs)
{
	grub_ubifs_fs.mod = mod;
	grub_fs_register(&grub_ubifs_fs);
}

GRUB_MOD_FINI(ubifs)
{
	grub_fs_unregister(&grub_ubifs_fs);
}
