/* xdvdfs.c - Xbox DVD File System. */
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
#include <grub/safemath.h>
#include <grub/types.h>

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define XDVDFS_SECTOR_SIZE		2048U
#define XDVDFS_VOLUME_SECTOR		32U
#define XDVDFS_VOLUME_SIZE		2048U
#define XDVDFS_MAGIC_SIZE		20U
#define XDVDFS_ROOT_SECTOR_OFFSET	20U
#define XDVDFS_ROOT_SIZE_OFFSET		24U
#define XDVDFS_TIMESTAMP_OFFSET		28U
#define XDVDFS_TRAILING_MAGIC_OFFSET	2028U
#define XDVDFS_DIRECTORY_MAX		(4U * 1024U * 1024U)
#define XDVDFS_ENTRY_HEADER_SIZE		14U
#define XDVDFS_ATTR_DIRECTORY		0x10U
#define XDVDFS_NO_SUBTREE		0xffffU
#define XDVDFS_TREE_DEPTH_MAX		64U
#define XDVDFS_FILETIME_EPOCH		116444736000000000ULL
#define XDVDFS_FILETIME_TICKS		10000000ULL

static const grub_uint8_t xdvdfs_magic[XDVDFS_MAGIC_SIZE] = "MICROSOFT*XBOX*MEDIA";

static const grub_uint64_t xdvdfs_candidates[] =
{
	0,
	32ULL * XDVDFS_SECTOR_SIZE,
	64ULL * XDVDFS_SECTOR_SIZE,
	0x30600ULL * XDVDFS_SECTOR_SIZE,
	0x02080000ULL,
	0x0fd90000ULL
};

struct grub_xdvdfs_data;

struct grub_fshelp_node
{
	struct grub_xdvdfs_data *data;
	grub_uint64_t inode;
	grub_uint32_t sector;
	grub_uint32_t size;
	grub_uint8_t directory;
};

struct grub_xdvdfs_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	grub_uint64_t fs_start;
	grub_uint64_t timestamp;
	struct grub_fshelp_node root;
	struct grub_fshelp_node open_node;
};

struct grub_xdvdfs_walk_context
{
	grub_fshelp_iterate_dir_hook_t hook;
	void *hook_data;
	struct grub_xdvdfs_data *data;
	const grub_uint8_t *table;
	grub_uint8_t *seen;
	grub_uint32_t table_size;
	grub_uint64_t table_offset;
};

static grub_uint16_t
xdvdfs_get_u16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
xdvdfs_get_u32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
xdvdfs_get_u64 (const grub_uint8_t *p)
{
	return grub_le_to_cpu64 (grub_get_unaligned64 (p));
}

static grub_err_t
xdvdfs_disk_read (struct grub_xdvdfs_data *data, grub_uint64_t offset,
	grub_size_t length, void *buffer)
{
	if (offset > data->disk_size || length > data->disk_size - offset)
		return grub_error (GRUB_ERR_BAD_FS, "XDVDFS read outside device");
	return grub_disk_read (data->disk, offset >> GRUB_DISK_SECTOR_BITS,
		(grub_off_t) (offset & (GRUB_DISK_SECTOR_SIZE - 1)), length, buffer);
}

static grub_err_t
xdvdfs_extent_offset (struct grub_xdvdfs_data *data, grub_uint32_t sector,
	grub_uint32_t size, grub_uint64_t *offset)
{
	grub_uint64_t relative;

	if (grub_mul ((grub_uint64_t) sector, (grub_uint64_t) XDVDFS_SECTOR_SIZE, &relative)
		|| grub_add (data->fs_start, relative, offset)
		|| *offset > data->disk_size
		|| size > data->disk_size - *offset)
		return grub_error (GRUB_ERR_BAD_FS, "XDVDFS extent outside device");
	return GRUB_ERR_NONE;
}

static int
xdvdfs_name_valid (const grub_uint8_t *name, grub_uint32_t length)
{
	grub_uint32_t i;

	for (i = 0; i < length; i++)
		if (name[i] == 0 || name[i] == '/')
			return 0;
	return 1;
}

static int
xdvdfs_filler_entry (const grub_uint8_t *entry)
{
	grub_uint32_t i;

	for (i = 0; i < XDVDFS_ENTRY_HEADER_SIZE; i++)
		if (entry[i] != 0xff)
			return 0;
	return 1;
}

static int
xdvdfs_has_subtree (grub_uint32_t pointer)
{
	return pointer != 0 && pointer != XDVDFS_NO_SUBTREE;
}

static int
xdvdfs_walk_tree (struct grub_xdvdfs_walk_context *context,
	grub_uint32_t offset, grub_uint32_t depth)
{
	const grub_uint8_t *entry;
	struct grub_fshelp_node *node;
	grub_uint32_t left;
	grub_uint32_t right;
	grub_uint32_t name_length;
	grub_uint64_t extent_offset;
	char *name;
	enum grub_fshelp_filetype type;
	int stop;

	if (depth > XDVDFS_TREE_DEPTH_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "XDVDFS directory tree is too deep");
		return 0;
	}
	if ((offset & 3) != 0 || offset > context->table_size
		|| XDVDFS_ENTRY_HEADER_SIZE > context->table_size - offset)
	{
		grub_error (GRUB_ERR_BAD_FS, "XDVDFS directory pointer is invalid");
		return 0;
	}
	if (context->seen[offset >> 2])
	{
		grub_error (GRUB_ERR_BAD_FS, "cyclic XDVDFS directory tree");
		return 0;
	}
	context->seen[offset >> 2] = 1;
	entry = context->table + offset;
	if (xdvdfs_filler_entry (entry))
		return 0;

	left = xdvdfs_get_u16 (entry);
	right = xdvdfs_get_u16 (entry + 2);
	if (xdvdfs_has_subtree (left))
	{
		left *= 4;
		if (xdvdfs_walk_tree (context, left, depth + 1) || grub_errno)
			return grub_errno == GRUB_ERR_NONE;
	}

	name_length = entry[13];
	if (name_length == 0 || name_length > context->table_size - offset
		|| XDVDFS_ENTRY_HEADER_SIZE > context->table_size - offset - name_length
		|| !xdvdfs_name_valid (entry + XDVDFS_ENTRY_HEADER_SIZE, name_length))
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid XDVDFS directory entry name");
		return 0;
	}
	node = grub_zalloc (sizeof (*node));
	if (!node)
		return 0;
	node->data = context->data;
	node->sector = xdvdfs_get_u32 (entry + 4);
	node->size = xdvdfs_get_u32 (entry + 8);
	node->directory = !!(entry[12] & XDVDFS_ATTR_DIRECTORY);
	if (node->directory && node->size > XDVDFS_DIRECTORY_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "XDVDFS directory table is too large");
		grub_free (node);
		return 0;
	}
	if (xdvdfs_extent_offset (context->data, node->sector, node->size,
		&extent_offset))
	{
		grub_free (node);
		return 0;
	}
	if (node->directory)
		node->inode = extent_offset;
	else
		node->inode = context->table_offset + offset;
	name = grub_fs_bytes_to_utf8 ((const char *) entry + XDVDFS_ENTRY_HEADER_SIZE, name_length, grub_fs_char_encoding);
	if (!name)
	{
		grub_free (node);
		return 0;
	}
	type = node->directory ? GRUB_FSHELP_DIR : GRUB_FSHELP_REG;
	stop = context->hook (name, type | GRUB_FSHELP_CASE_INSENSITIVE, node, context->hook_data);
	grub_free (name);
	if (stop)
		return 1;

	if (xdvdfs_has_subtree (right))
	{
		right *= 4;
		if (xdvdfs_walk_tree (context, right, depth + 1) || grub_errno)
			return grub_errno == GRUB_ERR_NONE;
	}
	return 0;
}

static int
xdvdfs_iterate_directory (grub_fshelp_node_t directory,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_xdvdfs_walk_context context;
	grub_uint64_t table_offset;
	grub_uint8_t *table = NULL;
	grub_uint8_t *seen = NULL;
	grub_size_t seen_size;
	int stop = 0;

	if (!directory->directory)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "not an XDVDFS directory");
		return 0;
	}
	if (directory->size == 0)
		return 0;
	if (directory->size > XDVDFS_DIRECTORY_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "XDVDFS directory table is too large");
		return 0;
	}
	if (xdvdfs_extent_offset (directory->data, directory->sector, directory->size, &table_offset))
		return 0;
	table = grub_malloc (directory->size);
	if (!table)
		return 0;
	if (xdvdfs_disk_read (directory->data, table_offset, directory->size, table))
		goto out;
	if (directory->size < XDVDFS_ENTRY_HEADER_SIZE)
	{
		grub_error (GRUB_ERR_BAD_FS, "truncated XDVDFS directory table");
		goto out;
	}
	seen_size = ((grub_size_t) directory->size + 3) / 4;
	seen = grub_zalloc (seen_size);
	if (!seen)
		goto out;
	context.hook = hook;
	context.hook_data = hook_data;
	context.data = directory->data;
	context.table = table;
	context.seen = seen;
	context.table_size = directory->size;
	context.table_offset = table_offset;
	stop = xdvdfs_walk_tree (&context, 0, 0);

out:
	grub_free (seen);
	grub_free (table);
	return stop;
}

static struct grub_xdvdfs_data *
xdvdfs_mount (grub_disk_t disk)
{
	struct grub_xdvdfs_data *data;
	grub_uint64_t sectors;
	grub_uint8_t volume[XDVDFS_VOLUME_SIZE];
	grub_uint64_t volume_offset;
	grub_uint64_t root_offset;
	grub_uint32_t root_sector;
	grub_uint32_t root_size;
	grub_uint32_t i;
	int found = 0;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	sectors = grub_disk_native_sectors (disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN
		|| sectors > (~(grub_uint64_t) 0 >> GRUB_DISK_SECTOR_BITS))
	{
		grub_error (GRUB_ERR_BAD_FS, "XDVDFS device size is unknown");
		goto fail;
	}
	data->disk_size = sectors << GRUB_DISK_SECTOR_BITS;
	for (i = 0; i < ARRAY_SIZE (xdvdfs_candidates); i++)
	{
		if (grub_add (xdvdfs_candidates[i], (grub_uint64_t) XDVDFS_VOLUME_SECTOR * XDVDFS_SECTOR_SIZE, &volume_offset)
			|| volume_offset > data->disk_size
			|| XDVDFS_VOLUME_SIZE > data->disk_size - volume_offset)
			continue;
		if (xdvdfs_disk_read (data, volume_offset, sizeof (volume), volume))
		{
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		if (grub_memcmp (volume, xdvdfs_magic, XDVDFS_MAGIC_SIZE) == 0
			&& grub_memcmp (volume + XDVDFS_TRAILING_MAGIC_OFFSET, xdvdfs_magic, XDVDFS_MAGIC_SIZE) == 0)
		{
			data->fs_start = xdvdfs_candidates[i];
			found = 1;
			break;
		}
	}
	if (!found)
	{
		grub_error (GRUB_ERR_BAD_FS, "not an XDVDFS filesystem");
		goto fail;
	}
	root_sector = xdvdfs_get_u32 (volume + XDVDFS_ROOT_SECTOR_OFFSET);
	root_size = xdvdfs_get_u32 (volume + XDVDFS_ROOT_SIZE_OFFSET);
	if (root_size > XDVDFS_DIRECTORY_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "XDVDFS root directory is too large");
		goto fail;
	}
	if (xdvdfs_extent_offset (data, root_sector, root_size, &root_offset))
		goto fail;
	data->timestamp = xdvdfs_get_u64 (volume + XDVDFS_TIMESTAMP_OFFSET);
	data->root.data = data;
	data->root.inode = root_offset;
	data->root.sector = root_sector;
	data->root.size = root_size;
	data->root.directory = 1;
	return data;

fail:
	grub_free (data);
	return NULL;
}

static grub_err_t
grub_xdvdfs_open (struct grub_file *file, const char *name)
{
	struct grub_xdvdfs_data *data;
	struct grub_fshelp_node *node = NULL;

	data = xdvdfs_mount (file->device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (name, &data->root, &node, xdvdfs_iterate_directory, NULL, GRUB_FSHELP_REG))
		goto fail;
	data->open_node = *node;
	if (node != &data->root)
		grub_free (node);
	file->data = data;
	file->size = data->open_node.size;
	file->offset = 0;
	return GRUB_ERR_NONE;

fail:
	if (node && node != &data->root)
		grub_free (node);
	grub_free (data);
	return grub_errno;
}

static grub_ssize_t
grub_xdvdfs_read (grub_file_t file, char *buffer, grub_size_t length)
{
	struct grub_xdvdfs_data *data = file->data;
	grub_uint64_t extent_offset;
	grub_uint64_t offset;

	if (file->offset > data->open_node.size)
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "attempt to read past end of XDVDFS file");
		return -1;
	}
	if (length > data->open_node.size - file->offset)
		length = (grub_size_t) (data->open_node.size - file->offset);
	if (length == 0)
		return 0;
	if (xdvdfs_extent_offset (data, data->open_node.sector, data->open_node.size, &extent_offset)
		|| grub_add (extent_offset, (grub_uint64_t) file->offset, &offset))
		return -1;
	data->disk->read_hook = file->read_hook;
	data->disk->read_hook_data = file->read_hook_data;
	if (xdvdfs_disk_read (data, offset, length, buffer))
	{
		data->disk->read_hook = NULL;
		return -1;
	}
	data->disk->read_hook = NULL;
	return (grub_ssize_t) length;
}

static grub_err_t
grub_xdvdfs_close (grub_file_t file)
{
	grub_free (file->data);
	file->data = NULL;
	return GRUB_ERR_NONE;
}

struct grub_xdvdfs_dir_context
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_xdvdfs_dir_hook (const char *name, enum grub_fshelp_filetype type,
	grub_fshelp_node_t node, void *hook_data)
{
	struct grub_xdvdfs_dir_context *context = hook_data;
	struct grub_dirhook_info info;
	int stop;

	grub_memset (&info, 0, sizeof (info));
	info.dir = ((type & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.case_insensitive = 1;
	info.inodeset = 1;
	info.inode = node->inode;
	if (!info.dir)
	{
		info.sizeset = 1;
		info.size = node->size;
	}
	stop = context->hook (name, &info, context->hook_data);
	grub_free (node);
	return stop;
}

static grub_err_t
grub_xdvdfs_dir (grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_xdvdfs_dir_context context = { hook, hook_data };
	struct grub_xdvdfs_data *data;
	struct grub_fshelp_node *directory = NULL;

	data = xdvdfs_mount (device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (path, &data->root, &directory, xdvdfs_iterate_directory, NULL, GRUB_FSHELP_DIR))
		goto out;
	xdvdfs_iterate_directory (directory, grub_xdvdfs_dir_hook, &context);

out:
	if (directory && directory != &data->root)
		grub_free (directory);
	grub_free (data);
	return grub_errno;
}

static grub_err_t
grub_xdvdfs_mtime (grub_device_t device, grub_int64_t *time)
{
	struct grub_xdvdfs_data *data;

	data = xdvdfs_mount (device->disk);
	if (!data)
		return grub_errno;
	if (data->timestamp > 0x7fffffffffffffffULL)
	{
		grub_free (data);
		return grub_error (GRUB_ERR_BAD_FS, "invalid XDVDFS volume timestamp");
	}
	*time = ((grub_int64_t) data->timestamp - (grub_int64_t) XDVDFS_FILETIME_EPOCH) / (grub_int64_t) XDVDFS_FILETIME_TICKS;
	grub_free (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_xdvdfs_fs =
{
	.name = "xdvdfs",
	.fs_dir = grub_xdvdfs_dir,
	.fs_open = grub_xdvdfs_open,
	.fs_read = grub_xdvdfs_read,
	.fs_close = grub_xdvdfs_close,
	.fs_mtime = grub_xdvdfs_mtime,
	.next = NULL
};

GRUB_MOD_INIT(xdvdfs)
{
	grub_xdvdfs_fs.mod = mod;
	grub_fs_register (&grub_xdvdfs_fs);
}

GRUB_MOD_FINI(xdvdfs)
{
	grub_fs_unregister (&grub_xdvdfs_fs);
}
