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
 * SCO UnixWare Boot File System (BFS) read-only driver.
 *
 * BFS is the tiny filesystem UnixWare puts on /stand: blocks are always
 * 512 bytes, block 0 holds the super block, the inode list follows right
 * behind it and ends at the byte offset s_start where the data area
 * begins.  Inodes are 64 bytes and numbered from 2 (the root directory)
 * on; every file occupies one contiguous run of blocks i_sblock..i_eblock
 * whose length in bytes is derived from i_eoffset.  The root directory is
 * a plain file holding 16 byte records of an inode number and a name of
 * up to 14 characters, and it is the only directory the format can hold.
 * There are no symbolic links.  The driver is called "bootfs" because the
 * GRUB name "bfs" is taken by the Be File System.
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>

GRUB_MOD_LICENSE("GPLv3+");

#define BOOTFS_BSIZE		512U
#define BOOTFS_BSHIFT		9
#define BOOTFS_BMASK		(BOOTFS_BSIZE - 1)

#define BOOTFS_MAGIC		0x1badfaceU
#define BOOTFS_ROOT_INO		2
#define BOOTFS_INODE_SIZE	64U
#define BOOTFS_DIRENT_SIZE	16U
#define BOOTFS_NAMELEN		14

/* mkfs.bfs(8) accepts -N 512, which makes the last inode number 513 */
#define BOOTFS_MAX_LASTI	513

/* super block byte offsets */
#define BOOTFS_SB_MAGIC		0x00
#define BOOTFS_SB_START		0x04
#define BOOTFS_SB_END		0x08
#define BOOTFS_SB_FROM		0x0c
#define BOOTFS_SB_TO		0x10
#define BOOTFS_SB_FSNAME	0x1c
#define BOOTFS_SB_VOLUME	0x22
#define BOOTFS_SB_NAMELEN	6

/* inode byte offsets */
#define BOOTFS_INO_INO		0x00
#define BOOTFS_INO_SBLOCK	0x04
#define BOOTFS_INO_EBLOCK	0x08
#define BOOTFS_INO_EOFFSET	0x0c
#define BOOTFS_INO_VTYPE	0x10
#define BOOTFS_INO_MODE		0x14
#define BOOTFS_INO_NLINK	0x20
#define BOOTFS_INO_MTIME	0x28

/* SVR4 vnode types stored in i_vtype */
#define BOOTFS_VREG		1
#define BOOTFS_VDIR		2

struct grub_bootfs_data;

struct grub_fshelp_node
{
	struct grub_bootfs_data *data;
	grub_uint32_t ino;
	grub_uint32_t sblock;		/* first data block, 0 if the file is empty */
	grub_uint32_t eblock;		/* last block allocated to the file */
	grub_uint32_t size;
	grub_uint32_t mtime;
};

struct grub_bootfs_data
{
	grub_disk_t disk;
	grub_uint32_t blocks;		/* filesystem length in 512 byte blocks */
	grub_uint32_t end;		/* offset of the last byte of the filesystem */
	grub_uint32_t lasti;		/* highest inode number the inode list holds */
	char label[BOOTFS_SB_NAMELEN + 1];
	struct grub_fshelp_node root;
};

/* context for grub_bootfs_dir */
struct grub_bootfs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static grub_uint32_t
bootfs_get32(const grub_uint8_t *p)
{
	return grub_le_to_cpu32(grub_get_unaligned32(p));
}

static grub_uint16_t
bootfs_get16(const grub_uint8_t *p)
{
	return grub_le_to_cpu16(grub_get_unaligned16(p));
}

/* Copy a fixed size, space or NUL padded name field out of the super
   block.  Fields left uninitialized by the formatter carry binary junk,
   which has no business showing up as a volume label.  */
static void
grub_bootfs_get_name(const grub_uint8_t *p, char *out)
{
	int i, len = 0;

	for (i = 0; i < BOOTFS_SB_NAMELEN && p[i]; i++)
	{
		if (p[i] < 0x20 || p[i] > 0x7e)
			return;
		if (p[i] != ' ')
			len = i + 1;
	}
	grub_memcpy(out, p, len);
	out[len] = '\0';
}

static grub_disk_addr_t
grub_bootfs_get_block(grub_fshelp_node_t node, grub_disk_addr_t block)
{
	grub_disk_addr_t blk = node->sblock + block;

	if (!node->sblock || blk > node->eblock)
	{
		grub_error(GRUB_ERR_BAD_FS,
			"bootfs: block %llu is outside of inode %u",
			(unsigned long long) block, (unsigned) node->ino);
		return 0;
	}
	return blk;
}

/* Load inode INO into NODE.  The inode list starts right behind the super
   block and ends where the data area begins.  */
static grub_err_t
grub_bootfs_read_inode(struct grub_bootfs_data *data, grub_uint32_t ino,
	struct grub_fshelp_node *node, grub_uint32_t *vtype)
{
	grub_uint8_t raw[BOOTFS_INODE_SIZE];
	grub_uint32_t off, sblock, eblock, eoffset;
	grub_uint64_t size = 0;

	if (ino < BOOTFS_ROOT_INO || ino > data->lasti)
		return grub_error(GRUB_ERR_BAD_FS, "bootfs: bad inode number %u",
			(unsigned) ino);

	off = BOOTFS_BSIZE + (ino - BOOTFS_ROOT_INO) * BOOTFS_INODE_SIZE;
	if (grub_disk_read(data->disk, off >> BOOTFS_BSHIFT, off & BOOTFS_BMASK,
		sizeof(raw), raw))
		return grub_errno;

	sblock = bootfs_get32(raw + BOOTFS_INO_SBLOCK);
	eblock = bootfs_get32(raw + BOOTFS_INO_EBLOCK);
	eoffset = bootfs_get32(raw + BOOTFS_INO_EOFFSET);

	/* the same consistency checks the Linux driver runs at mount time */
	if (sblock > data->blocks || eblock > data->blocks || sblock > eblock
		|| (eoffset != 0xffffffffU && eoffset > data->end))
		return grub_error(GRUB_ERR_BAD_FS, "bootfs: inode %u is corrupted",
			(unsigned) ino);
	if (sblock)
	{
		grub_uint64_t start = (grub_uint64_t) sblock * BOOTFS_BSIZE;

		if (start > eoffset)
			return grub_error(GRUB_ERR_BAD_FS,
				"bootfs: inode %u is corrupted", (unsigned) ino);
		size = (grub_uint64_t) eoffset + 1 - start;
		if (size > ((grub_uint64_t) (eblock - sblock) + 1) * BOOTFS_BSIZE)
			return grub_error(GRUB_ERR_BAD_FS,
				"bootfs: inode %u is corrupted", (unsigned) ino);
	}

	node->data = data;
	node->ino = ino;
	node->sblock = sblock;
	node->eblock = eblock;
	node->size = (grub_uint32_t) size;
	node->mtime = bootfs_get32(raw + BOOTFS_INO_MTIME);
	*vtype = bootfs_get32(raw + BOOTFS_INO_VTYPE);
	return GRUB_ERR_NONE;
}

/* The root is the only directory the format can hold -- neither mkfs.bfs
   nor any driver can create a second one -- so an inode other than the
   root claiming to be a directory comes from a corrupted image and is
   reported as an unknown entry instead.  */
static enum grub_fshelp_filetype
grub_bootfs_filetype(grub_uint32_t vtype, grub_uint32_t ino)
{
	if (vtype == BOOTFS_VDIR && ino == BOOTFS_ROOT_INO)
		return GRUB_FSHELP_DIR;
	if (vtype == BOOTFS_VREG)
		return GRUB_FSHELP_REG;
	return GRUB_FSHELP_UNKNOWN;
}

static struct grub_bootfs_data *
grub_bootfs_mount(grub_disk_t disk)
{
	struct grub_bootfs_data *data = NULL;
	grub_uint8_t sb[BOOTFS_BSIZE];
	grub_uint64_t total;
	grub_uint32_t start, end, vtype;

	if (grub_disk_read(disk, 0, 0, sizeof(sb), sb))
		goto fail;
	if (bootfs_get32(sb + BOOTFS_SB_MAGIC) != BOOTFS_MAGIC)
		goto fail;

	start = bootfs_get32(sb + BOOTFS_SB_START);
	end = bootfs_get32(sb + BOOTFS_SB_END);
	/* the data area starts behind the super block and at least one
	   directory entry of the root directory has to fit in front of it */
	if (start < BOOTFS_BSIZE + BOOTFS_DIRENT_SIZE || start > end
		|| end == 0xffffffffU)
	{
		grub_error(GRUB_ERR_BAD_FS, "bootfs: super block is corrupted");
		goto fail;
	}

	data = grub_zalloc(sizeof(*data));
	if (!data)
		return NULL;
	data->disk = disk;
	data->end = end;
	data->blocks = (end + 1) >> BOOTFS_BSHIFT;
	data->lasti = (start - BOOTFS_BSIZE) / BOOTFS_INODE_SIZE
		+ BOOTFS_ROOT_INO - 1;
	if (data->lasti > BOOTFS_MAX_LASTI)
	{
		grub_error(GRUB_ERR_BAD_FS, "bootfs: impossible last inode %u",
			(unsigned) data->lasti);
		goto fail;
	}

	total = grub_disk_native_sectors(disk);
	if (total != GRUB_DISK_SIZE_UNKNOWN && data->blocks > total)
	{
		grub_error(GRUB_ERR_BAD_FS, "bootfs: filesystem is larger than "
			"the device");
		goto fail;
	}

	if (grub_bootfs_read_inode(data, BOOTFS_ROOT_INO, &data->root, &vtype))
		goto fail;
	if (vtype != BOOTFS_VDIR)
	{
		grub_error(GRUB_ERR_BAD_FS, "bootfs: root inode is not a directory");
		goto fail;
	}

	grub_bootfs_get_name(sb + BOOTFS_SB_VOLUME, data->label);
	return data;

fail:
	grub_free(data);
	if (grub_errno == GRUB_ERR_NONE || grub_errno == GRUB_ERR_OUT_OF_RANGE)
		grub_error(GRUB_ERR_BAD_FS, "not a bootfs filesystem");
	return NULL;
}

static grub_err_t
grub_bootfs_read_file(struct grub_fshelp_node *node, grub_off_t pos,
	grub_size_t len, char *buf)
{
	if (grub_fshelp_read_file(node->data->disk, node, NULL, NULL, pos, len,
		buf, grub_bootfs_get_block, node->size, 0, 0) < 0)
	{
		if (grub_errno == GRUB_ERR_NONE)
			grub_error(GRUB_ERR_BAD_FS, "bootfs: read error");
		return grub_errno;
	}
	return GRUB_ERR_NONE;
}

static int
grub_bootfs_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_bootfs_data *data = dir->data;
	grub_uint8_t buf[BOOTFS_BSIZE];
	grub_uint32_t pos;
	int ret = 0;

	for (pos = 0; pos < dir->size && !ret; pos += BOOTFS_BSIZE)
	{
		grub_uint32_t len = dir->size - pos, p;

		if (len > BOOTFS_BSIZE)
			len = BOOTFS_BSIZE;
		if (grub_bootfs_read_file(dir, pos, len, (char *) buf))
			return 1;

		for (p = 0; p + BOOTFS_DIRENT_SIZE <= len;
			p += BOOTFS_DIRENT_SIZE)
		{
			struct grub_fshelp_node *node;
			char name[BOOTFS_NAMELEN + 1];
			grub_uint32_t ino = bootfs_get16(buf + p), vtype;

			if (!ino)
				continue;
			grub_memcpy(name, buf + p + 2, BOOTFS_NAMELEN);
			name[BOOTFS_NAMELEN] = '\0';

			node = grub_zalloc(sizeof(*node));
			if (!node)
				return 1;
			if (grub_bootfs_read_inode(data, ino, node, &vtype))
			{
				/* a single broken entry must not abort the listing */
				grub_errno = GRUB_ERR_NONE;
				grub_free(node);
				continue;
			}
			ret = hook(name, grub_bootfs_filetype(vtype, ino), node,
				hook_data);
			if (ret)
				break;
		}
	}
	return ret;
}

static int
grub_bootfs_dir_iter(const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *ctx_in)
{
	struct grub_bootfs_dir_ctx *ctx = ctx_in;
	struct grub_dirhook_info info;

	grub_memset(&info, 0, sizeof(info));
	info.dir = (filetype == GRUB_FSHELP_DIR);
	info.mtimeset = 1;
	info.mtime = node->mtime;
	info.inodeset = 1;
	info.inode = node->ino;
	if (!info.dir)
	{
		info.sizeset = 1;
		info.size = node->size;
	}
	grub_free(node);
	return ctx->hook(filename, &info, ctx->hook_data);
}

static grub_err_t
grub_bootfs_dir(grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_bootfs_dir_ctx ctx = { hook, hook_data };
	struct grub_bootfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_bootfs_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(path, &data->root, &fdiro, grub_bootfs_iterate_dir,
		NULL, GRUB_FSHELP_DIR);
	if (grub_errno)
		goto fail;

	grub_bootfs_iterate_dir(fdiro, grub_bootfs_dir_iter, &ctx);

fail:
	if (fdiro != &data->root)
		grub_free(fdiro);
	grub_free(data);
	return grub_errno;
}

static grub_err_t
grub_bootfs_open(struct grub_file *file, const char *name)
{
	struct grub_bootfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_bootfs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(name, &data->root, &fdiro, grub_bootfs_iterate_dir,
		NULL, GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	file->size = fdiro->size;
	file->data = fdiro;
	return GRUB_ERR_NONE;

fail:
	if (fdiro != &data->root)
		grub_free(fdiro);
	grub_free(data);
	return grub_errno;
}

static grub_ssize_t
grub_bootfs_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fshelp_node *node = file->data;

	if (len == 0)
		return 0;
	if (grub_bootfs_read_file(node, file->offset, len, buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_bootfs_close(grub_file_t file)
{
	struct grub_fshelp_node *node = file->data;
	struct grub_bootfs_data *data = node->data;

	if (node != &data->root)
		grub_free(node);
	grub_free(data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_bootfs_label(grub_device_t device, char **label)
{
	struct grub_bootfs_data *data;

	*label = NULL;
	data = grub_bootfs_mount(device->disk);
	if (!data)
		return grub_errno;

	if (data->label[0])
		*label = grub_strdup(data->label);
	grub_free(data);
	return grub_errno;
}

static struct grub_fs grub_bootfs_fs =
{
	.name = "bootfs",
	.fs_dir = grub_bootfs_dir,
	.fs_open = grub_bootfs_open,
	.fs_read = grub_bootfs_read,
	.fs_close = grub_bootfs_close,
	.fs_label = grub_bootfs_label,
	.next = 0
};

GRUB_MOD_INIT(bootfs)
{
	grub_bootfs_fs.mod = mod;
	grub_fs_register(&grub_bootfs_fs);
}

GRUB_MOD_FINI(bootfs)
{
	grub_fs_unregister(&grub_bootfs_fs);
}
