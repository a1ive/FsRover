/* efs.c - SGI Extent File System. */
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
#include <grub/types.h>

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define EFS_BLOCK_SIZE		512U
#define EFS_SUPER_BLOCK		1U
#define EFS_ROOT_INODE		2U
#define EFS_MAGIC		0x072959U
#define EFS_NEW_MAGIC		0x07295aU
#define EFS_DIRECT_EXTENTS	12U
#define EFS_EXTENT_SIZE		8U
#define EFS_EXTENTS_PER_BLOCK	(EFS_BLOCK_SIZE / EFS_EXTENT_SIZE)
#define EFS_DIR_MAGIC		0xbeefU
#define EFS_DIR_HEADER_SIZE	4U
#define EFS_DIR_ENTRY_BASE_SIZE	5U
#define EFS_SYMLINK_MAX		4096U

#define EFS_MODE_MASK		0170000U
#define EFS_MODE_REG		0100000U
#define EFS_MODE_DIR		0040000U
#define EFS_MODE_SYMLINK		0120000U

PRAGMA_BEGIN_PACKED
struct grub_efs_super
{
	grub_uint32_t size;
	grub_uint32_t first_cg;
	grub_uint32_t cg_size;
	grub_uint16_t cg_inode_blocks;
	grub_uint16_t sectors;
	grub_uint16_t heads;
	grub_uint16_t cg_count;
	grub_uint16_t dirty;
	grub_uint16_t padding;
	grub_uint32_t time;
	grub_uint32_t magic;
	char name[6];
	char pack_name[6];
	grub_uint32_t bitmap_size;
	grub_uint32_t free_blocks;
	grub_uint32_t free_inodes;
	grub_uint32_t bitmap_block;
	grub_uint32_t replica_block;
	grub_uint32_t last_inode;
	grub_uint8_t spare[20];
	grub_uint32_t checksum;
} GRUB_PACKED;

struct grub_efs_inode
{
	grub_uint16_t mode;
	grub_uint16_t links;
	grub_uint16_t uid;
	grub_uint16_t gid;
	grub_uint32_t size;
	grub_uint32_t atime;
	grub_uint32_t mtime;
	grub_uint32_t ctime;
	grub_uint32_t generation;
	grub_uint16_t extent_count;
	grub_uint8_t version;
	grub_uint8_t spare;
	grub_uint8_t extents[EFS_DIRECT_EXTENTS][EFS_EXTENT_SIZE];
} GRUB_PACKED;
PRAGMA_END_PACKED

struct grub_efs_extent
{
	grub_uint32_t block;
	grub_uint32_t offset;
	grub_uint32_t length;
};

struct grub_efs_data;

struct grub_fshelp_node
{
	struct grub_efs_data *data;
	struct grub_efs_inode inode;
	grub_uint32_t number;
	grub_uint32_t last_extent;
};

struct grub_efs_data
{
	grub_disk_t disk;
	struct grub_efs_super super;
	grub_uint32_t size;
	grub_uint32_t first_cg;
	grub_uint32_t cg_size;
	grub_uint32_t cg_inode_blocks;
	grub_uint32_t cg_count;
	grub_uint32_t inode_count;
	struct grub_fshelp_node root;
	struct grub_fshelp_node open_node;
};

static grub_uint32_t
grub_efs_be24 (const grub_uint8_t *p)
{
	return ((grub_uint32_t) p[0] << 16) | ((grub_uint32_t) p[1] << 8) | p[2];
}

static grub_err_t
grub_efs_decode_extent (const grub_uint8_t raw[EFS_EXTENT_SIZE],
	struct grub_efs_extent *extent)
{
	if (raw[0] != 0 || raw[4] == 0)
		return grub_error (GRUB_ERR_BAD_FS, "invalid EFS extent");

	extent->block = grub_efs_be24 (raw + 1);
	extent->length = raw[4];
	extent->offset = grub_efs_be24 (raw + 5);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_efs_check_blocks (struct grub_efs_data *data, grub_uint32_t block,
	grub_uint32_t count)
{
	if (count == 0 || block >= data->size || count > data->size - block)
		return grub_error (GRUB_ERR_BAD_FS, "EFS extent outside filesystem");
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_efs_read_inode (struct grub_efs_data *data, grub_uint32_t number,
	struct grub_fshelp_node *node)
{
	grub_uint32_t inode_index;
	grub_uint32_t group;
	grub_uint32_t block;
	grub_uint32_t offset;
	grub_uint32_t count;
	grub_uint32_t i;

	if (number >= data->inode_count)
		return grub_error (GRUB_ERR_BAD_FS, "EFS inode outside inode table");

	inode_index = number / (EFS_BLOCK_SIZE / sizeof (node->inode));
	group = inode_index / data->cg_inode_blocks;
	if (group >= data->cg_count)
		return grub_error (GRUB_ERR_BAD_FS, "EFS inode group outside filesystem");
	block = data->first_cg + group * data->cg_size + inode_index % data->cg_inode_blocks;
	offset = (number % (EFS_BLOCK_SIZE / sizeof (node->inode))) * sizeof (node->inode);
	if (grub_efs_check_blocks (data, block, 1))
		return grub_errno;
	if (grub_disk_read (data->disk, block, offset, sizeof (node->inode),
		&node->inode))
		return grub_errno;

	node->data = data;
	node->number = number;
	node->last_extent = 0;
	count = grub_be_to_cpu16 (node->inode.extent_count);
	if (count == 0 && grub_be_to_cpu32 (node->inode.size) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "non-empty EFS inode has no extents");
	if (count <= EFS_DIRECT_EXTENTS)
	{
		for (i = 0; i < count; i++)
		{
			struct grub_efs_extent extent;

			if (grub_efs_decode_extent (node->inode.extents[i], &extent)
				|| grub_efs_check_blocks (data, extent.block, extent.length))
				return grub_errno;
		}
	}
	else
	{
		struct grub_efs_extent extent;
		grub_uint32_t indirect_count;
		grub_uint32_t capacity = 0;

		if (grub_efs_decode_extent (node->inode.extents[0], &extent))
			return grub_errno;
		indirect_count = extent.offset;
		if (indirect_count == 0 || indirect_count > EFS_DIRECT_EXTENTS)
			return grub_error (GRUB_ERR_BAD_FS, "invalid EFS indirect extent count");
		for (i = 0; i < indirect_count; i++)
		{
			if (grub_efs_decode_extent (node->inode.extents[i], &extent)
				|| grub_efs_check_blocks (data, extent.block, extent.length))
				return grub_errno;
			capacity += extent.length * EFS_EXTENTS_PER_BLOCK;
		}
		if (capacity < count)
			return grub_error (GRUB_ERR_BAD_FS, "truncated EFS indirect extent table");
	}

	return GRUB_ERR_NONE;
}

static grub_err_t
grub_efs_get_extent (grub_fshelp_node_t node, grub_uint32_t index,
	struct grub_efs_extent *extent)
{
	grub_uint32_t count = grub_be_to_cpu16 (node->inode.extent_count);

	if (index >= count)
		return grub_error (GRUB_ERR_BAD_FS, "EFS extent index out of range");
	if (count <= EFS_DIRECT_EXTENTS)
		return grub_efs_decode_extent (node->inode.extents[index], extent);
	else
	{
		struct grub_efs_extent indirect;
		grub_uint32_t indirect_count;
		grub_uint32_t base = 0;
		grub_uint32_t i;

		if (grub_efs_decode_extent (node->inode.extents[0], &indirect))
			return grub_errno;
		indirect_count = indirect.offset;
		for (i = 0; i < indirect_count; i++)
		{
			grub_uint32_t capacity;
			grub_uint32_t local;
			grub_uint8_t raw[EFS_EXTENT_SIZE];

			if (grub_efs_decode_extent (node->inode.extents[i], &indirect))
				return grub_errno;
			capacity = indirect.length * EFS_EXTENTS_PER_BLOCK;
			if (index >= base && index - base < capacity)
			{
				local = index - base;
				if (grub_disk_read (node->data->disk,
					indirect.block + local / EFS_EXTENTS_PER_BLOCK,
					(local % EFS_EXTENTS_PER_BLOCK) * EFS_EXTENT_SIZE,
					sizeof (raw), raw))
					return grub_errno;
				if (grub_efs_decode_extent (raw, extent)
					|| grub_efs_check_blocks (node->data, extent->block, extent->length))
					return grub_errno;
				return GRUB_ERR_NONE;
			}
			base += capacity;
		}
	}

	return grub_error (GRUB_ERR_BAD_FS, "missing EFS indirect extent");
}

static grub_disk_addr_t
grub_efs_read_block (grub_fshelp_node_t node, grub_disk_addr_t file_block)
{
	grub_uint32_t count = grub_be_to_cpu16 (node->inode.extent_count);
	grub_uint32_t i;

	for (i = 0; i < count; i++)
	{
		struct grub_efs_extent extent;
		grub_uint32_t index = (node->last_extent + i) % count;

		if (grub_efs_get_extent (node, index, &extent))
			return 0;
		if (file_block >= extent.offset
			&& file_block - extent.offset < extent.length)
		{
			grub_uint32_t block = extent.block + (grub_uint32_t) file_block - extent.offset;

			if (grub_efs_check_blocks (node->data, block, 1))
				return 0;
			node->last_extent = index;
			return block;
		}
	}

	grub_error (GRUB_ERR_BAD_FS, "missing EFS file block");
	return 0;
}

static grub_ssize_t
grub_efs_read_file (grub_fshelp_node_t node,
	grub_disk_read_hook_t read_hook, void *read_hook_data,
	grub_off_t pos, grub_size_t len, char *buf)
{
	return grub_fshelp_read_file (node->data->disk, node, read_hook,
		read_hook_data, pos, len, buf, grub_efs_read_block,
		grub_be_to_cpu32 (node->inode.size), 0, 0);
}

static enum grub_fshelp_filetype
grub_efs_inode_type (const struct grub_efs_inode *inode)
{
	switch (grub_be_to_cpu16 (inode->mode) & EFS_MODE_MASK)
	{
	case EFS_MODE_REG:
		return GRUB_FSHELP_REG;
	case EFS_MODE_DIR:
		return GRUB_FSHELP_DIR;
	case EFS_MODE_SYMLINK:
		return GRUB_FSHELP_SYMLINK;
	default:
		return GRUB_FSHELP_UNKNOWN;
	}
}

static char *
grub_efs_read_symlink (grub_fshelp_node_t node)
{
	grub_uint32_t size = grub_be_to_cpu32 (node->inode.size);
	char *target;

	if (size > EFS_SYMLINK_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "EFS symlink is too long");
		return NULL;
	}
	target = grub_malloc ((grub_size_t) size + 1);
	if (!target)
		return NULL;
	if (grub_efs_read_file (node, NULL, NULL, 0, size, target) != size)
	{
		grub_free (target);
		return NULL;
	}
	target[size] = '\0';
	return target;
}

static int
grub_efs_name_valid (const grub_uint8_t *name, grub_uint32_t length)
{
	grub_uint32_t i;

	for (i = 0; i < length; i++)
		if (name[i] == 0 || name[i] == '/')
			return 0;
	return 1;
}

static int
grub_efs_iterate_dir (grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	grub_uint32_t size = grub_be_to_cpu32 (dir->inode.size);
	grub_uint32_t block_count;
	grub_uint32_t block;

	if (grub_efs_inode_type (&dir->inode) != GRUB_FSHELP_DIR)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "not an EFS directory");
		return 0;
	}
	if (size % EFS_BLOCK_SIZE != 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid EFS directory size");
		return 0;
	}
	block_count = size / EFS_BLOCK_SIZE;
	for (block = 0; block < block_count; block++)
	{
		grub_uint8_t buf[EFS_BLOCK_SIZE];
		grub_uint32_t slots;
		grub_uint32_t slot;

		if (grub_efs_read_file (dir, NULL, NULL,
			(grub_off_t) block * EFS_BLOCK_SIZE, sizeof (buf),
			(char *) buf) != sizeof (buf))
			return 0;
		if (grub_be_to_cpu16 (grub_get_unaligned16 (buf)) != EFS_DIR_MAGIC)
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid EFS directory block");
			return 0;
		}
		slots = buf[3];
		for (slot = 0; slot < slots; slot++)
		{
			grub_uint32_t entry_offset;
			grub_uint32_t name_length;
			grub_uint32_t inode_number;
			struct grub_fshelp_node *node;
			char *name;
			int stop;

			if (buf[EFS_DIR_HEADER_SIZE + slot] == 0)
				continue;
			entry_offset = (grub_uint32_t) buf[EFS_DIR_HEADER_SIZE + slot] << 1;
			if (entry_offset < EFS_DIR_HEADER_SIZE + slots
				|| entry_offset + EFS_DIR_ENTRY_BASE_SIZE > EFS_BLOCK_SIZE)
			{
				grub_error (GRUB_ERR_BAD_FS,
					"invalid EFS directory entry offset");
				return 0;
			}
			name_length = buf[entry_offset + 4];
			if (name_length == 0
				|| name_length > EFS_BLOCK_SIZE - entry_offset - EFS_DIR_ENTRY_BASE_SIZE
				|| !grub_efs_name_valid (buf + entry_offset + 5, name_length))
			{
				grub_error (GRUB_ERR_BAD_FS, "invalid EFS directory entry name");
				return 0;
			}
			inode_number = grub_be_to_cpu32(grub_get_unaligned32 (buf + entry_offset));
			node = grub_malloc (sizeof (*node));
			if (!node)
				return 0;
			if (grub_efs_read_inode (dir->data, inode_number, node))
			{
				grub_free (node);
				return 0;
			}
			name = grub_fs_bytes_to_utf8((const char *) buf + entry_offset + 5, name_length, grub_fs_char_encoding);
			if (!name)
			{
				grub_free (node);
				return 0;
			}
			stop = hook (name, grub_efs_inode_type (&node->inode), node, hook_data);
			grub_free (name);
			if (stop)
				return 1;
		}
	}

	return 0;
}

static struct grub_efs_data *
grub_efs_mount (grub_disk_t disk)
{
	struct grub_efs_data *data;
	grub_uint32_t magic;
	grub_uint64_t group_end;
	grub_uint64_t inode_count;
	grub_uint64_t disk_size;

	COMPILE_TIME_ASSERT (sizeof (struct grub_efs_super) == 92);
	COMPILE_TIME_ASSERT (sizeof (struct grub_efs_inode) == 128);

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	if (grub_disk_read (disk, EFS_SUPER_BLOCK, 0, sizeof (data->super), &data->super))
		goto fail;

	magic = grub_be_to_cpu32 (data->super.magic);
	if (magic != EFS_MAGIC && magic != EFS_NEW_MAGIC)
	{
		grub_error (GRUB_ERR_BAD_FS, "not an EFS filesystem");
		goto fail;
	}
	data->size = grub_be_to_cpu32 (data->super.size);
	data->first_cg = grub_be_to_cpu32 (data->super.first_cg);
	data->cg_size = grub_be_to_cpu32 (data->super.cg_size);
	data->cg_inode_blocks = grub_be_to_cpu16 (data->super.cg_inode_blocks);
	data->cg_count = grub_be_to_cpu16 (data->super.cg_count);
	if (data->size <= EFS_SUPER_BLOCK || data->first_cg >= data->size
		|| data->cg_size == 0 || data->cg_inode_blocks == 0
		|| data->cg_inode_blocks >= data->cg_size || data->cg_count == 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid EFS superblock geometry");
		goto fail;
	}
	group_end = (grub_uint64_t) data->first_cg + (grub_uint64_t) data->cg_size * data->cg_count;
	if (group_end > data->size)
	{
		grub_error (GRUB_ERR_BAD_FS, "EFS cylinder groups outside filesystem");
		goto fail;
	}
	disk_size = grub_disk_native_sectors (disk);
	if (disk_size != GRUB_DISK_SIZE_UNKNOWN && data->size > disk_size)
	{
		grub_error (GRUB_ERR_BAD_FS, "EFS size exceeds device");
		goto fail;
	}
	inode_count = (grub_uint64_t) data->cg_count * data->cg_inode_blocks * (EFS_BLOCK_SIZE / sizeof (struct grub_efs_inode));
	if (inode_count <= EFS_ROOT_INODE || inode_count > 0xffffffffU)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid EFS inode count");
		goto fail;
	}
	data->inode_count = (grub_uint32_t) inode_count;
	if (grub_efs_read_inode (data, EFS_ROOT_INODE, &data->root))
		goto fail;
	if (grub_efs_inode_type (&data->root.inode) != GRUB_FSHELP_DIR)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid EFS root inode");
		goto fail;
	}
	return data;

fail:
	if (grub_errno == GRUB_ERR_OUT_OF_RANGE)
		grub_error (GRUB_ERR_BAD_FS, "not an EFS filesystem");
	grub_free (data);
	return NULL;
}

static grub_err_t
grub_efs_open (struct grub_file *file, const char *name)
{
	struct grub_efs_data *data;
	struct grub_fshelp_node *node = NULL;

	data = grub_efs_mount (file->device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (name, &data->root, &node,
		grub_efs_iterate_dir, grub_efs_read_symlink, GRUB_FSHELP_REG))
		goto fail;
	data->open_node = *node;
	if (node != &data->root)
		grub_free (node);
	file->data = data;
	file->size = grub_be_to_cpu32 (data->open_node.inode.size);
	file->offset = 0;
	return GRUB_ERR_NONE;

fail:
	if (node && node != &data->root)
		grub_free (node);
	grub_free (data);
	return grub_errno;
}

static grub_ssize_t
grub_efs_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_efs_data *data = file->data;

	return grub_efs_read_file (&data->open_node, file->read_hook,
		file->read_hook_data, file->offset, len, buf);
}

static grub_err_t
grub_efs_close (grub_file_t file)
{
	grub_free (file->data);
	return GRUB_ERR_NONE;
}

struct grub_efs_dir_context
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_efs_dir_hook (const char *name, enum grub_fshelp_filetype type,
	grub_fshelp_node_t node, void *hook_data)
{
	struct grub_efs_dir_context *context = hook_data;
	struct grub_dirhook_info info;
	int stop;

	grub_memset (&info, 0, sizeof (info));
	info.dir = ((type & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink = ((type & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK);
	info.mtime = grub_be_to_cpu32 (node->inode.mtime);
	info.mtimeset = 1;
	info.inode = node->number;
	info.inodeset = 1;
	stop = context->hook (name, &info, context->hook_data);
	grub_free (node);
	return stop;
}

static grub_err_t
grub_efs_dir (grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_efs_dir_context context = { hook, hook_data };
	struct grub_efs_data *data;
	struct grub_fshelp_node *dir = NULL;

	data = grub_efs_mount (device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (path, &data->root, &dir,
		grub_efs_iterate_dir, grub_efs_read_symlink, GRUB_FSHELP_DIR))
		goto out;
	grub_efs_iterate_dir (dir, grub_efs_dir_hook, &context);

out:
	if (dir && dir != &data->root)
		grub_free (dir);
	grub_free (data);
	return grub_errno;
}

static grub_err_t
grub_efs_label (grub_device_t device, char **label)
{
	struct grub_efs_data *data;
	grub_size_t length = sizeof (data->super.name);

	*label = NULL;
	data = grub_efs_mount (device->disk);
	if (!data)
		return grub_errno;
	while (length > 0 && (data->super.name[length - 1] == '\0' || data->super.name[length - 1] == ' '))
		length--;
	if (length > 0)
		*label = grub_fs_bytes_to_utf8 (data->super.name, length, grub_fs_char_encoding);
	grub_free (data);
	return grub_errno;
}

static grub_err_t
grub_efs_mtime (grub_device_t device, grub_int64_t *time)
{
	struct grub_efs_data *data;

	data = grub_efs_mount (device->disk);
	if (!data)
		return grub_errno;
	*time = grub_be_to_cpu32 (data->super.time);
	grub_free (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_efs_fs =
{
	.name = "efs",
	.fs_dir = grub_efs_dir,
	.fs_open = grub_efs_open,
	.fs_read = grub_efs_read,
	.fs_close = grub_efs_close,
	.fs_label = grub_efs_label,
	.fs_mtime = grub_efs_mtime,
#ifdef GRUB_UTIL
	.reserved_first_sector = 1,
	.blocklist_install = 0,
#endif
	.next = NULL
};

GRUB_MOD_INIT(efs)
{
	grub_efs_fs.mod = mod;
	grub_fs_register (&grub_efs_fs);
}

GRUB_MOD_FINI(efs)
{
	grub_fs_unregister (&grub_efs_fs);
}
