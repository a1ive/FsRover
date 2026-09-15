/* sysv.c - System V, SCO EAFS, Xenix, V7 and Coherent filesystems. */
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

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define SYSV_ROOT_INO	2U
#define SYSV_MODE_MASK	0170000U
#define SYSV_MODE_REG	0100000U
#define SYSV_MODE_DIR	0040000U
#define SYSV_MODE_LINK	0120000U
#define SYSV_SYMLINK_MAX	4096U
#define SYSV_NAME_MAX	255U
#define SYSV_PARTIAL_NAME	0xffffU

enum sysv_byte_order
{
	SYSV_LE,
	SYSV_BE,
	SYSV_PDP
};

struct grub_sysv_data;

struct grub_fshelp_node
{
	struct grub_sysv_data *data;
	grub_uint32_t number;
	grub_uint32_t size;
	grub_uint32_t mtime;
	grub_uint32_t blocks[13];
	grub_uint16_t mode;
};

struct grub_sysv_data
{
	grub_disk_t disk;
	enum sysv_byte_order order;
	unsigned int block_bits;
	int extended_names;
	grub_uint32_t first_data;
	grub_uint32_t block_count;
	grub_uint32_t inode_count;
	grub_uint32_t mtime;
	char label[6];
	struct grub_fshelp_node root;
	struct grub_fshelp_node open_node;
};

static grub_uint16_t
sysv_u16 (const struct grub_sysv_data *data, const grub_uint8_t *p)
{
	if (data->order == SYSV_BE)
		return ((grub_uint16_t) p[0] << 8) | p[1];
	return ((grub_uint16_t) p[1] << 8) | p[0];
}

static grub_uint32_t
sysv_u32 (const struct grub_sysv_data *data, const grub_uint8_t *p)
{
	if (data->order == SYSV_BE)
		return ((grub_uint32_t) p[0] << 24) | ((grub_uint32_t) p[1] << 16)
			| ((grub_uint32_t) p[2] << 8) | p[3];
	if (data->order == SYSV_PDP)
		return ((grub_uint32_t) p[1] << 24) | ((grub_uint32_t) p[0] << 16)
			| ((grub_uint32_t) p[3] << 8) | p[2];
	return ((grub_uint32_t) p[3] << 24) | ((grub_uint32_t) p[2] << 16)
		| ((grub_uint32_t) p[1] << 8) | p[0];
}

static grub_uint32_t
sysv_u24 (const struct grub_sysv_data *data, const grub_uint8_t *p)
{
	if (data->order == SYSV_BE)
		return ((grub_uint32_t) p[0] << 16) | ((grub_uint32_t) p[1] << 8) | p[2];
	if (data->order == SYSV_PDP)
		return ((grub_uint32_t) p[0] << 16) | ((grub_uint32_t) p[2] << 8) | p[1];
	return ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[1] << 8) | p[0];
}

static enum grub_fshelp_filetype
sysv_inode_type (const struct grub_fshelp_node *node)
{
	switch (node->mode & SYSV_MODE_MASK)
	{
	case SYSV_MODE_REG:
		return GRUB_FSHELP_REG;
	case SYSV_MODE_DIR:
		return GRUB_FSHELP_DIR;
	case SYSV_MODE_LINK:
		return GRUB_FSHELP_SYMLINK;
	default:
		return GRUB_FSHELP_UNKNOWN;
	}
}

static grub_err_t
sysv_read_inode (struct grub_sysv_data *data, grub_uint32_t number,
	struct grub_fshelp_node *node)
{
	grub_uint8_t raw[64];
	grub_uint64_t offset;
	grub_uint64_t ptrs = 1U << (data->block_bits - 2);
	grub_uint64_t max_size = (10 + ptrs + ptrs * ptrs + ptrs * ptrs * ptrs)
		<< data->block_bits;
	unsigned int i;

	if (number == 0 || number > data->inode_count || number > 0xffff)
	{
		grub_error (GRUB_ERR_BAD_FS, "System V inode outside inode table");
		goto fail;
	}
	offset = (2ULL << data->block_bits) + (grub_uint64_t) (number - 1) * 64;
	if (grub_disk_read (data->disk, offset >> 9, offset & 511, sizeof (raw), raw))
		goto fail;
	node->data = data;
	node->number = number;
	node->mode = sysv_u16 (data, raw);
	node->size = sysv_u32 (data, raw + 8);
	node->mtime = sysv_u32 (data, raw + 56);
	if (sysv_u16 (data, raw + 2) == 0 || node->mode == 0 || node->size > max_size)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid System V inode");
		goto fail;
	}
	if (sysv_inode_type (node) == GRUB_FSHELP_DIR && (node->size & 15))
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid System V directory size");
		goto fail;
	}
	for (i = 0; i < ARRAY_SIZE (node->blocks); i++)
		node->blocks[i] = sysv_u24 (data, raw + 12 + 3 * i);
	return GRUB_ERR_NONE;

fail:
	return grub_errno;
}

static grub_err_t
sysv_check_block (struct grub_sysv_data *data, grub_uint32_t block)
{
	/* Zero denotes a hole, including missing indirect subtrees. */
	if (block && (block < data->first_data || block >= data->block_count))
		return grub_error (GRUB_ERR_BAD_FS, "System V block outside data area");
	return GRUB_ERR_NONE;
}

static grub_disk_addr_t
sysv_get_block (grub_fshelp_node_t node, grub_disk_addr_t logical)
{
	struct grub_sysv_data *data = node->data;
	grub_uint64_t ptrs = 1U << (data->block_bits - 2);
	grub_uint64_t span = ptrs;
	grub_uint32_t block;
	unsigned int depth;

	if (logical < 10)
	{
		block = node->blocks[logical];
		if (sysv_check_block (data, block))
			goto fail;
		return block;
	}
	logical -= 10;
	for (depth = 1; depth <= 3; depth++)
	{
		if (logical < span)
			break;
		logical -= span;
		span *= ptrs;
	}
	if (depth > 3)
	{
		grub_error (GRUB_ERR_BAD_FS, "System V logical block outside inode capacity");
		goto fail;
	}
	block = node->blocks[9 + depth];
	while (depth--)
	{
		grub_uint8_t raw[4];
		grub_uint32_t index;

		if (sysv_check_block (data, block))
			goto fail;
		if (!block)
			return 0;
		span /= ptrs;
		index = (grub_uint32_t) (logical / span);
		logical %= span;
		if (grub_disk_read (data->disk,
			(grub_disk_addr_t) block << (data->block_bits - 9),
			index * 4, sizeof (raw), raw))
			goto fail;
		block = sysv_u32 (data, raw);
	}
	if (sysv_check_block (data, block))
		goto fail;
	return block;

fail:
	return 0;
}

static grub_ssize_t
sysv_read_file (grub_fshelp_node_t node, grub_disk_read_hook_t hook,
	void *hook_data, grub_off_t offset, grub_size_t len, char *buf)
{
	return grub_fshelp_read_file (node->data->disk, node, hook, hook_data,
		offset, len, buf, sysv_get_block, node->size, node->data->block_bits - 9, 0);
}

static char *
sysv_read_symlink (grub_fshelp_node_t node)
{
	char *raw = NULL;
	char *target;

	if (node->size == 0 || node->size > SYSV_SYMLINK_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid System V symbolic link size");
		goto fail;
	}
	raw = grub_malloc (node->size);
	if (!raw)
		goto fail;
	if (sysv_read_file (node, NULL, NULL, 0, node->size, raw) != node->size)
		goto fail;
	if (grub_memchr (raw, 0, node->size))
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid System V symbolic link target");
		goto fail;
	}
	target = grub_fs_bytes_to_utf8 (raw, node->size, grub_fs_char_encoding);
	grub_free (raw);
	return target;

fail:
	grub_free (raw);
	return NULL;
}

static int
sysv_iterate_dir (grub_fshelp_node_t dir, grub_fshelp_iterate_dir_hook_t hook,
	void *hook_data)
{
	grub_uint64_t offset;
	struct grub_fshelp_node *node = NULL;
	char *name = NULL;
	grub_uint8_t raw_name[SYSV_NAME_MAX];
	grub_size_t name_length = 0;

	/* SCO EAFS/ES51K use 0xffff inode entries for 14-byte prefixes,
	 * followed by an entry carrying the actual inode and final suffix.
	 * See ref/sco_fs/sco_fs-2.1.30.patch. Assemble bytes before charset
	 * conversion, since a multibyte character can span two fragments.
	 */
	for (offset = 0; offset < dir->size; offset += 16)
	{
		grub_uint8_t entry[16];
		grub_uint32_t number;
		grub_size_t length;
		int stop;

		if (sysv_read_file (dir, NULL, NULL, offset, sizeof (entry),
			(char *) entry) != sizeof (entry))
			goto fail;
		number = sysv_u16 (dir->data, entry);
		if (!number)
		{
			/* Deleted slots also discard any preceding orphan prefixes. */
			name_length = 0;
			continue;
		}
		for (length = 0; length < 14 && entry[2 + length]; length++)
		{
			if (entry[2 + length] == '/')
			{
				grub_error (GRUB_ERR_BAD_FS, "invalid System V directory name");
				goto fail;
			}
		}
		if (!length)
		{
			grub_error (GRUB_ERR_BAD_FS, "empty System V directory name");
			goto fail;
		}
		if (length > SYSV_NAME_MAX - name_length)
		{
			grub_error (GRUB_ERR_BAD_FS, "System V directory name too long");
			goto fail;
		}
		grub_memcpy (raw_name + name_length, entry + 2, length);
		name_length += length;
		if (dir->data->extended_names && number == SYSV_PARTIAL_NAME)
		{
			if (length != 14)
			{
				grub_error (GRUB_ERR_BAD_FS, "short SCO directory name prefix");
				goto fail;
			}
			continue;
		}
		node = grub_malloc (sizeof (*node));
		if (!node || sysv_read_inode (dir->data, number, node))
			goto fail;
		name = grub_fs_bytes_to_utf8 ((const char *) raw_name, name_length,
			grub_fs_char_encoding);
		name_length = 0;
		if (!name)
			goto fail;
		stop = hook (name, sysv_inode_type (node), node, hook_data);
		node = NULL; /* The hook owns the node, also when it stops iteration. */
		grub_free (name);
		name = NULL;
		if (stop)
			return 1;
	}
	if (name_length)
	{
		grub_error (GRUB_ERR_BAD_FS, "unterminated SCO directory name");
		goto fail;
	}
	return 0;

fail:
	grub_free (name);
	grub_free (node);
	return 0;
}

static grub_err_t
sysv_check_root (struct grub_sysv_data *data, int v7)
{
	grub_uint8_t entries[32];
	grub_uint64_t sectors = grub_disk_native_sectors (data->disk);

	if (data->first_data <= 2 || data->first_data >= data->block_count
		|| data->block_count > 0xffffff
		|| (sectors != GRUB_DISK_SIZE_UNKNOWN
			&& ((grub_uint64_t) data->block_count << (data->block_bits - 9)) > sectors))
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid System V volume geometry");
		goto fail;
	}
	data->inode_count = (data->first_data - 2) << (data->block_bits - 6);
	if (sysv_read_inode (data, SYSV_ROOT_INO, &data->root))
		goto fail;
	if (sysv_inode_type (&data->root) != GRUB_FSHELP_DIR || data->root.size < 32
		|| (v7 && data->root.size > 1024 * 16))
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid System V root directory");
		goto fail;
	}
	/* V7 has no magic. Check real directory contents as well as its inode. */
	if (sysv_read_file (&data->root, NULL, NULL, 0, sizeof (entries),
		(char *) entries) != sizeof (entries))
		goto fail;
	if (sysv_u16 (data, entries) != SYSV_ROOT_INO
		|| entries[2] != '.' || entries[3] != 0
		|| sysv_u16 (data, entries + 16) != SYSV_ROOT_INO
		|| entries[18] != '.' || entries[19] != '.' || entries[20] != 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid System V root dot entries");
		goto fail;
	}
	return GRUB_ERR_NONE;

fail:
	return grub_errno;
}

static int
sysv_magic (struct grub_sysv_data *data, const grub_uint8_t *p, grub_uint32_t magic)
{
	data->order = SYSV_LE;
	if (sysv_u32 (data, p) == magic)
		return 1;
	data->order = SYSV_BE;
	return sysv_u32 (data, p) == magic;
}

static struct grub_sysv_data *
sysv_mount (grub_disk_t disk)
{
	/* Linux probes 1 KiB blocks 0, 9, 15 and 18 for System V. Addresses
	 * within inodes stay relative to the volume, not to the superblock. */
	static const unsigned int sysv_sectors[] = { 1, 19, 31, 37 };
	grub_uint8_t super[1024];
	struct grub_sysv_data *data;
	grub_uint32_t type;
	unsigned int i;
	unsigned int time_offset;
	unsigned int label_offset;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	if (!grub_disk_read (disk, 2, 0, sizeof (super), super)
		&& sysv_magic (data, super + 1016, 0x002b5544))
	{
		type = sysv_u32 (data, super + 1020);
		if (type < 1 || type > 2)
			goto bad_format;
		data->block_bits = type + 8;
		data->first_data = sysv_u16 (data, super);
		data->block_count = sysv_u32 (data, super + 2);
		time_offset = 614;
		label_offset = 632;
		goto found;
	}
	grub_errno = GRUB_ERR_NONE;
	for (i = 0; i < ARRAY_SIZE (sysv_sectors); i++)
	{
		if (grub_disk_read (disk, sysv_sectors[i], 0, 512, super))
		{
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		data->extended_names = 0;
		if (!sysv_magic (data, super + 504, 0xfd187e20))
		{
			if (!sysv_magic (data, super + 504, 0xfd187e21))
				continue;
			data->extended_names = 1;
		}
		type = sysv_u32 (data, super + 508);
		/* ISC long-name encodings are not the classic 16-byte directory
		 * format. Do not silently present truncated names for those volumes. */
		if (type < 1 || type > 3 || ((i == 1 || i == 2) && type == 3))
			goto bad_format;
		data->block_bits = type + 8;
		data->first_data = sysv_u16 (data, super);
		/* Extended SCO superblocks use the R4 layout, including ES51K
		 * without the AFS free-space bitmap marker. Reads never modify
		 * either free-space representation.
		 */
		if (!data->extended_names && sysv_u16 (data, super + 8) != 0xffff
			&& sysv_u32 (data, super + 420) < 315532800U)
		{
			data->block_count = sysv_u32 (data, super + 2);
			time_offset = 414;
			label_offset = 432;
		}
		else
		{
			data->block_count = sysv_u32 (data, super + 4);
			time_offset = 420;
			label_offset = 440;
		}
		goto found;
	}
	if (grub_disk_read (disk, 1, 0, 512, super))
		goto fail;
	data->block_bits = 9;
	data->order = SYSV_PDP;
	if ((!grub_memcmp (super + 484, "noname", 6) || !grub_memcmp (super + 484, "xxxxx ", 6))
		&& (!grub_memcmp (super + 490, "nopack", 6) || !grub_memcmp (super + 490, "xxxxx\n", 6)))
	{
		data->first_data = sysv_u16 (data, super);
		data->block_count = sysv_u32 (data, super + 2);
		time_offset = 470;
		label_offset = 484;
		goto found;
	}
	/* V7 PDP-11, then PC/IX (little endian), as in Linux v7_fill_super. */
	for (i = 0; i < 2; i++)
	{
		data->order = i == 0 ? SYSV_PDP : SYSV_LE;
		data->first_data = sysv_u16 (data, super);
		data->block_count = sysv_u32 (data, super + 2);
		if (sysv_u16 (data, super + 6) > 50 || sysv_u16 (data, super + 208) > 100)
			continue;
		if (!sysv_check_root (data, 1))
		{
			data->mtime = sysv_u32 (data, super + 414);
			grub_memcpy (data->label, super + 428, 6);
			return data;
		}
		grub_errno = GRUB_ERR_NONE;
	}
	goto bad_format;

found:
	data->mtime = sysv_u32 (data, super + time_offset);
	grub_memcpy (data->label, super + label_offset, 6);
	if (sysv_check_root (data, 0))
		goto fail;
	return data;

bad_format:
	grub_error (GRUB_ERR_BAD_FS, "not a supported System V filesystem");
fail:
	if (grub_errno == GRUB_ERR_OUT_OF_RANGE)
		grub_error (GRUB_ERR_BAD_FS, "System V filesystem outside device");
	grub_free (data);
	return NULL;
}

static grub_err_t
sysv_open (grub_file_t file, const char *name)
{
	struct grub_sysv_data *data;
	struct grub_fshelp_node *node = NULL;

	data = sysv_mount (file->device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (name, &data->root, &node,
		sysv_iterate_dir, sysv_read_symlink, GRUB_FSHELP_REG))
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
sysv_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_sysv_data *data = file->data;

	return sysv_read_file (&data->open_node, file->read_hook,
		file->read_hook_data, file->offset, len, buf);
}

static grub_err_t
sysv_close (grub_file_t file)
{
	grub_free (file->data);
	return GRUB_ERR_NONE;
}

struct sysv_dir_context
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
sysv_dir_hook (const char *name, enum grub_fshelp_filetype type,
	grub_fshelp_node_t node, void *hook_data)
{
	struct sysv_dir_context *context = hook_data;
	struct grub_dirhook_info info;
	int stop;

	grub_memset (&info, 0, sizeof (info));
	info.dir = (type == GRUB_FSHELP_DIR);
	info.symlink = (type == GRUB_FSHELP_SYMLINK);
	info.mtime = node->mtime;
	info.mtimeset = 1;
	info.inode = node->number;
	info.inodeset = 1;
	if (type == GRUB_FSHELP_REG)
	{
		info.sizeset = 1;
		info.size = node->size;
	}
	stop = context->hook (name, &info, context->hook_data);
	grub_free (node);
	return stop;
}

static grub_err_t
sysv_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook,
	void *hook_data)
{
	struct sysv_dir_context context = { hook, hook_data };
	struct grub_sysv_data *data;
	struct grub_fshelp_node *dir = NULL;

	data = sysv_mount (device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (path, &data->root, &dir,
		sysv_iterate_dir, sysv_read_symlink, GRUB_FSHELP_DIR))
		goto fail;
	sysv_iterate_dir (dir, sysv_dir_hook, &context);

fail:
	if (dir && dir != &data->root)
		grub_free (dir);
	grub_free (data);
	return grub_errno;
}

static grub_err_t
sysv_label (grub_device_t device, char **label)
{
	struct grub_sysv_data *data;
	grub_size_t length;

	*label = NULL;
	data = sysv_mount (device->disk);
	if (!data)
		return grub_errno;
	for (length = 0; length < sizeof (data->label) && data->label[length]; length++)
		;
	while (length && data->label[length - 1] == ' ')
		length--;
	if (length)
		*label = grub_fs_bytes_to_utf8 (data->label, length, grub_fs_char_encoding);
	grub_free (data);
	return grub_errno;
}

static grub_err_t
sysv_mtime (grub_device_t device, grub_int64_t *time)
{
	struct grub_sysv_data *data = sysv_mount (device->disk);

	if (!data)
		return grub_errno;
	*time = data->mtime;
	grub_free (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_sysv_fs =
{
	.name = "sysv",
	.fs_dir = sysv_dir,
	.fs_open = sysv_open,
	.fs_read = sysv_read,
	.fs_close = sysv_close,
	.fs_label = sysv_label,
	.fs_mtime = sysv_mtime,
	.next = NULL
};

GRUB_MOD_INIT(sysv)
{
	grub_sysv_fs.mod = mod;
	grub_fs_register (&grub_sysv_fs);
}

GRUB_MOD_FINI(sysv)
{
	grub_fs_unregister (&grub_sysv_fs);
}
