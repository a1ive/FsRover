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
 * cramfs (compressed ROM filesystem) read-only driver.
 *
 * On-disk layout follows Linux
 * include/uapi/linux/cramfs_fs.h: a 76-byte superblock at offset 0
 * (or 512 for images prepended with boot code), 12-byte packed
 * inodes, per-file arrays of u32 block end-pointers followed by the
 * zlib-compressed 4 KiB blocks themselves.  Zero-length block
 * regions are holes.  Both little- and big-endian images are
 * accepted (the inode bit fields flip with the byte order); the
 * Linux 4.15 CRAMFS_BLK_FLAG_UNCOMPRESSED extension is honoured,
 * direct block pointers (XIP images) are rejected.
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

GRUB_MOD_LICENSE("GPLv2+");

#define CRAMFS_MAGIC		0x28cd3d45
#define CRAMFS_SIGNATURE	"Compressed ROMFS"
#define CRAMFS_BLOCK_SIZE	4096

/* superblock byte offsets */
#define CRAMFS_SB_MAGIC		0
#define CRAMFS_SB_SIZE		4
#define CRAMFS_SB_FLAGS		8
#define CRAMFS_SB_SIGNATURE	16
#define CRAMFS_SB_NAME		48
#define CRAMFS_SB_ROOT		64
#define CRAMFS_SB_LEN		76

#define CRAMFS_INODE_LEN	12

/* superblock flags */
#define CRAMFS_FLAG_HOLES		0x00000100
#define CRAMFS_FLAG_WRONG_SIGNATURE	0x00000200
#define CRAMFS_FLAG_SHIFTED_ROOT_OFFSET	0x00000400
#define CRAMFS_SUPPORTED_FLAGS	(0x000000ff \
				| CRAMFS_FLAG_HOLES \
				| CRAMFS_FLAG_WRONG_SIGNATURE \
				| CRAMFS_FLAG_SHIFTED_ROOT_OFFSET)

/* block pointer flags (Linux 4.15+ extension) */
#define CRAMFS_BLK_FLAG_UNCOMPRESSED	0x80000000u
#define CRAMFS_BLK_FLAG_DIRECT_PTR	0x40000000u
#define CRAMFS_BLK_FLAGS	(CRAMFS_BLK_FLAG_UNCOMPRESSED \
				| CRAMFS_BLK_FLAG_DIRECT_PTR)

/* mode bits (POSIX) */
#define CRAMFS_S_IFMT	0xF000
#define CRAMFS_S_IFDIR	0x4000
#define CRAMFS_S_IFREG	0x8000
#define CRAMFS_S_IFLNK	0xA000

struct grub_cramfs_data
{
	grub_disk_t disk;
	int be;				/* big-endian image */
	grub_uint32_t size;		/* filesystem length in bytes */
	grub_uint32_t flags;
	char name[17];			/* user-defined image name */
	struct grub_fshelp_node *root;
};

struct grub_fshelp_node
{
	struct grub_cramfs_data *data;
	grub_uint32_t mode;
	grub_uint32_t size;
	grub_uint32_t offset;		/* data offset in bytes */
};

static grub_uint32_t
grub_cramfs_u32(struct grub_cramfs_data *data, const grub_uint8_t *p)
{
	grub_uint32_t v = grub_get_unaligned32(p);

	return data->be ? grub_be_to_cpu32(v) : grub_le_to_cpu32(v);
}

/* decode a 12-byte packed inode; the bit fields flip with the image
   byte order (mode:16,uid:16 | size:24,gid:8 | namelen:6,offset:26) */
static void
grub_cramfs_parse_inode(struct grub_cramfs_data *data,
	const grub_uint8_t *raw, struct grub_fshelp_node *node,
	grub_uint32_t *namelen)
{
	grub_uint32_t w0 = grub_cramfs_u32(data, raw);
	grub_uint32_t w1 = grub_cramfs_u32(data, raw + 4);
	grub_uint32_t w2 = grub_cramfs_u32(data, raw + 8);

	node->data = data;
	if (data->be)
	{
		node->mode = w0 >> 16;
		node->size = w1 >> 8;
		node->offset = (w2 & 0x03ffffff) << 2;
		if (namelen)
			*namelen = (w2 >> 26) << 2;
	}
	else
	{
		node->mode = w0 & 0xffff;
		node->size = w1 & 0xffffff;
		node->offset = (w2 >> 6) << 2;
		if (namelen)
			*namelen = (w2 & 0x3f) << 2;
	}
}

static grub_err_t
grub_cramfs_read_data(struct grub_cramfs_data *data, grub_uint64_t offset,
	grub_size_t len, void *buf)
{
	return grub_disk_read(data->disk, 0, offset, len, buf);
}

static struct grub_cramfs_data *
grub_cramfs_mount(grub_disk_t disk)
{
	struct grub_cramfs_data *data = NULL;
	grub_uint8_t sb[CRAMFS_SB_LEN];
	grub_uint64_t sb_off = 0;
	grub_uint32_t magic;
	int be;

	if (grub_disk_read(disk, 0, 0, sizeof(sb), sb))
		goto fail;
	magic = grub_get_unaligned32(sb + CRAMFS_SB_MAGIC);
	if (magic != grub_cpu_to_le32_compile_time(CRAMFS_MAGIC)
		&& magic != grub_cpu_to_be32_compile_time(CRAMFS_MAGIC))
	{
		/* boot-block images carry the superblock at offset 512 */
		sb_off = 512;
		if (grub_disk_read(disk, 0, sb_off, sizeof(sb), sb))
			goto fail;
		magic = grub_get_unaligned32(sb + CRAMFS_SB_MAGIC);
		if (magic != grub_cpu_to_le32_compile_time(CRAMFS_MAGIC)
			&& magic != grub_cpu_to_be32_compile_time(CRAMFS_MAGIC))
			goto fail;
	}
	be = (magic == grub_cpu_to_be32_compile_time(CRAMFS_MAGIC));

	data = grub_zalloc(sizeof(*data) + sizeof(*data->root));
	if (!data)
		return NULL;
	data->disk = disk;
	data->be = be;
	data->root = (struct grub_fshelp_node *) (data + 1);
	data->size = grub_cramfs_u32(data, sb + CRAMFS_SB_SIZE);
	data->flags = grub_cramfs_u32(data, sb + CRAMFS_SB_FLAGS);

	if (data->flags & ~CRAMFS_SUPPORTED_FLAGS)
	{
		grub_error(GRUB_ERR_BAD_FS, "cramfs: unsupported features");
		goto fail;
	}
	if (grub_memcmp(sb + CRAMFS_SB_SIGNATURE, CRAMFS_SIGNATURE, 16) != 0
		&& !(data->flags & CRAMFS_FLAG_WRONG_SIGNATURE))
	{
		grub_error(GRUB_ERR_BAD_FS, "cramfs: bad signature");
		goto fail;
	}

	grub_memcpy(data->name, sb + CRAMFS_SB_NAME, 16);
	grub_cramfs_parse_inode(data, sb + CRAMFS_SB_ROOT, data->root, NULL);
	if ((data->root->mode & CRAMFS_S_IFMT) != CRAMFS_S_IFDIR)
	{
		grub_error(GRUB_ERR_BAD_FS, "cramfs: root is not a directory");
		goto fail;
	}
	return data;

fail:
	grub_free(data);
	if (grub_errno == GRUB_ERR_NONE || grub_errno == GRUB_ERR_OUT_OF_RANGE)
		grub_error(GRUB_ERR_BAD_FS, "not a cramfs filesystem");
	return NULL;
}

/* read LEN bytes of a file's uncompressed contents starting at POS */
static grub_err_t
grub_cramfs_read_file(struct grub_fshelp_node *node, grub_off_t pos,
	grub_size_t len, char *buf)
{
	struct grub_cramfs_data *data = node->data;
	grub_uint8_t *cbuf = NULL;
	char *ubuf = NULL;
	grub_uint32_t nblocks, bi;
	grub_uint64_t table_end;

	if (pos >= node->size || len > node->size - pos)
	{
		grub_error(GRUB_ERR_OUT_OF_RANGE, "read past end of file");
		goto fail;
	}
	if (len == 0)
		return GRUB_ERR_NONE;

	nblocks = (node->size + CRAMFS_BLOCK_SIZE - 1) / CRAMFS_BLOCK_SIZE;
	table_end = (grub_uint64_t) node->offset + (grub_uint64_t) nblocks * 4;

	cbuf = grub_malloc(2 * CRAMFS_BLOCK_SIZE);
	ubuf = grub_malloc(CRAMFS_BLOCK_SIZE);
	if (!cbuf || !ubuf)
		goto fail;

	for (bi = (grub_uint32_t) (pos / CRAMFS_BLOCK_SIZE); len > 0; bi++)
	{
		grub_uint8_t ptr_raw[8];
		grub_uint32_t ptr, blk_off, blk_dsize;
		grub_uint64_t start, end;
		grub_size_t take;

		/* this block's data region: [previous end pointer, ours) */
		if (bi == 0)
		{
			start = table_end;
			if (grub_cramfs_read_data(data, node->offset, 4,
				ptr_raw + 4))
				goto fail;
		}
		else if (grub_cramfs_read_data(data,
			node->offset + (grub_uint64_t) (bi - 1) * 4, 8,
			ptr_raw))
			goto fail;
		ptr = grub_cramfs_u32(data, ptr_raw + 4);
		if (ptr & CRAMFS_BLK_FLAG_DIRECT_PTR)
		{
			grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
				"cramfs: direct block pointers not supported");
			goto fail;
		}
		if (bi != 0)
			start = grub_cramfs_u32(data, ptr_raw)
				& ~CRAMFS_BLK_FLAGS;
		end = ptr & ~CRAMFS_BLK_FLAGS;

		blk_dsize = node->size - bi * CRAMFS_BLOCK_SIZE;
		if (blk_dsize > CRAMFS_BLOCK_SIZE)
			blk_dsize = CRAMFS_BLOCK_SIZE;

		if (end < start || end - start > 2 * CRAMFS_BLOCK_SIZE)
		{
			grub_error(GRUB_ERR_BAD_FS,
				"cramfs: bad block pointer");
			goto fail;
		}

		if (end == start)
			/* hole: implicit zero block */
			grub_memset(ubuf, 0, blk_dsize);
		else if (ptr & CRAMFS_BLK_FLAG_UNCOMPRESSED)
		{
			if (end - start > blk_dsize)
			{
				grub_error(GRUB_ERR_BAD_FS,
					"cramfs: bad block size");
				goto fail;
			}
			grub_memset(ubuf, 0, blk_dsize);
			if (grub_cramfs_read_data(data, start,
				(grub_size_t) (end - start), ubuf))
				goto fail;
		}
		else
		{
			grub_ssize_t dsize;

			if (grub_cramfs_read_data(data, start,
				(grub_size_t) (end - start), cbuf))
				goto fail;
			dsize = grub_zlib_decompress((char *) cbuf,
				(grub_size_t) (end - start), 0,
				ubuf, blk_dsize);
			if (dsize < 0)
				goto fail;
			if ((grub_uint32_t) dsize < blk_dsize)
				grub_memset(ubuf + dsize, 0,
					blk_dsize - (grub_uint32_t) dsize);
		}

		blk_off = (grub_uint32_t) (pos % CRAMFS_BLOCK_SIZE);
		take = blk_dsize - blk_off;
		if (take > len)
			take = len;
		grub_memcpy(buf, ubuf + blk_off, take);
		buf += take;
		pos += take;
		len -= take;
	}

	grub_free(cbuf);
	grub_free(ubuf);
	return GRUB_ERR_NONE;

fail:
	grub_free(cbuf);
	grub_free(ubuf);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "cramfs: read error");
	return grub_errno;
}

static int
grub_cramfs_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_cramfs_data *data = dir->data;
	grub_uint64_t off = dir->offset;
	grub_uint64_t end = off + dir->size;

	while (off < end)
	{
		grub_uint8_t raw[CRAMFS_INODE_LEN];
		char name[64 * 4 + 1];
		struct grub_fshelp_node *node;
		grub_uint32_t namelen;
		enum grub_fshelp_filetype type;

		if (end - off < CRAMFS_INODE_LEN)
			break;
		node = grub_malloc(sizeof(*node));
		if (!node)
			return 1;
		if (grub_cramfs_read_data(data, off, sizeof(raw), raw))
		{
			grub_free(node);
			return 1;
		}
		grub_cramfs_parse_inode(data, raw, node, &namelen);
		if (namelen == 0 || namelen > end - off - CRAMFS_INODE_LEN)
		{
			grub_free(node);
			break;
		}
		if (grub_cramfs_read_data(data, off + CRAMFS_INODE_LEN,
			namelen, name))
		{
			grub_free(node);
			return 1;
		}
		/* names are zero-padded to a 4-byte boundary */
		name[namelen] = '\0';

		switch (node->mode & CRAMFS_S_IFMT)
		{
		case CRAMFS_S_IFDIR:
			type = GRUB_FSHELP_DIR;
			break;
		case CRAMFS_S_IFLNK:
			type = GRUB_FSHELP_SYMLINK;
			break;
		case CRAMFS_S_IFREG:
			type = GRUB_FSHELP_REG;
			break;
		default:
			type = GRUB_FSHELP_UNKNOWN;
			break;
		}

		if (hook(name, type, node, hook_data))
			return 1;

		off += CRAMFS_INODE_LEN + namelen;
	}
	return 0;
}

static char *
grub_cramfs_read_symlink(grub_fshelp_node_t node)
{
	char *target;

	target = grub_malloc((grub_size_t) node->size + 1);
	if (!target)
		return NULL;
	if (node->size != 0
		&& grub_cramfs_read_file(node, 0, node->size, target))
	{
		grub_free(target);
		return NULL;
	}
	target[node->size] = '\0';
	return target;
}

/* context for grub_cramfs_dir */
struct grub_cramfs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_cramfs_dir_iter(const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *ctx_in)
{
	struct grub_cramfs_dir_ctx *ctx = ctx_in;
	struct grub_dirhook_info info;

	grub_memset(&info, 0, sizeof(info));
	info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink =
		((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK);
	grub_free(node);
	return ctx->hook(filename, &info, ctx->hook_data);
}

static grub_err_t
grub_cramfs_dir(grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_cramfs_dir_ctx ctx = { hook, hook_data };
	struct grub_cramfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_cramfs_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(path, data->root, &fdiro,
		grub_cramfs_iterate_dir, grub_cramfs_read_symlink,
		GRUB_FSHELP_DIR);
	if (grub_errno)
		goto fail;

	grub_cramfs_iterate_dir(fdiro, grub_cramfs_dir_iter, &ctx);

fail:
	if (fdiro != data->root)
		grub_free(fdiro);
	grub_free(data);
	return grub_errno;
}

static grub_err_t
grub_cramfs_open(struct grub_file *file, const char *name)
{
	struct grub_cramfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_cramfs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(name, data->root, &fdiro,
		grub_cramfs_iterate_dir, grub_cramfs_read_symlink,
		GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	file->size = fdiro->size;
	file->data = fdiro;
	fdiro->data = data;
	return GRUB_ERR_NONE;

fail:
	if (fdiro != data->root)
		grub_free(fdiro);
	grub_free(data);
	return grub_errno;
}

static grub_ssize_t
grub_cramfs_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fshelp_node *node = file->data;

	if (len == 0)
		return 0;
	if (grub_cramfs_read_file(node, file->offset, len, buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_cramfs_close(grub_file_t file)
{
	struct grub_fshelp_node *node = file->data;
	struct grub_cramfs_data *data = node->data;

	if (node != data->root)
		grub_free(node);
	grub_free(data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cramfs_label(grub_device_t device, char **label)
{
	struct grub_cramfs_data *data;

	*label = NULL;
	data = grub_cramfs_mount(device->disk);
	if (!data)
		return grub_errno;

	*label = grub_strdup(data->name);
	grub_free(data);
	return grub_errno;
}

static struct grub_fs grub_cramfs_fs =
{
	.name = "cramfs",
	.fs_dir = grub_cramfs_dir,
	.fs_open = grub_cramfs_open,
	.fs_read = grub_cramfs_read,
	.fs_close = grub_cramfs_close,
	.fs_label = grub_cramfs_label,
	.next = 0
};

GRUB_MOD_INIT(cramfs)
{
	grub_cramfs_fs.mod = mod;
	grub_fs_register(&grub_cramfs_fs);
}

GRUB_MOD_FINI(cramfs)
{
	grub_fs_unregister(&grub_cramfs_fs);
}
