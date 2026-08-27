/* fatx.c - Xbox FATX / XTAF filesystem. */
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

#include <grub/datetime.h>
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

#define FATX_SECTOR_SIZE		512U
#define FATX_PAGE_SIZE		4096U
#define FATX_RESERVED_BYTES	FATX_PAGE_SIZE
#define FATX_DIRENT_SIZE		0x40U
#define FATX_NAME_MAX		42U
#define FATX_PARTITION_MAX	6U

#define FATX_DIRENT_END_A	0x00U
#define FATX_DIRENT_END_B	0xffU
#define FATX_DIRENT_DELETED	0xe5U
#define FATX_ATTR_DIRECTORY	0x10U

#define FATX_FAT16_RESERVED	0xfff0U
#define FATX_FAT32_RESERVED	0xfffffff0U

struct grub_fatx_partition
{
	const char *name;
	grub_uint64_t offset;
	grub_uint64_t length;
	grub_uint64_t bytes_per_cluster;
	grub_uint64_t file_area_offset;
	grub_uint32_t serial;
	grub_uint32_t root_cluster;
	grub_uint32_t fat_entries;
	grub_uint32_t cluster_count;
	grub_uint8_t log2_sectors_per_cluster;
	grub_uint8_t fat_entry_size;
	grub_uint8_t big_endian;
};

struct grub_fatx_data;

struct grub_fshelp_node
{
	struct grub_fatx_data *data;
	grub_uint64_t inode;
	grub_uint32_t first_cluster;
	grub_uint32_t size;
	grub_uint32_t write_time;
	grub_uint32_t map_cluster;
	grub_uint32_t map_index;
	grub_uint8_t partition;
	grub_uint8_t directory;
	grub_uint8_t synthetic_root;
	grub_uint8_t map_valid;
};

struct grub_fatx_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	grub_uint32_t partition_count;
	struct grub_fatx_partition partitions[FATX_PARTITION_MAX];
	struct grub_fshelp_node root;
	struct grub_fshelp_node open_node;
};

struct grub_fatx_candidate
{
	const char *name;
	grub_uint64_t offset;
	grub_uint64_t length;
};

static const struct grub_fatx_candidate fatx_candidates[] =
{
	{ "Partition", 0, 0 },
	{ "Partition3 (Cache X)", 0x00080000ULL, 0x2ee00000ULL },
	{ "Partition4 (Cache Y)", 0x2ee80000ULL, 0x2ee00000ULL },
	{ "Partition5 (Cache Z)", 0x5dc80000ULL, 0x2ee00000ULL },
	{ "Partition2 (System C)", 0x8ca80000ULL, 0x1f400000ULL },
	{ "Partition1 (Data E)", 0xabe80000ULL, 0 }
};

static grub_uint32_t
fatx_get_u32 (const grub_uint8_t *p, int big_endian)
{
	grub_uint32_t value = grub_get_unaligned32 (p);

	return big_endian ? grub_be_to_cpu32 (value) : grub_le_to_cpu32 (value);
}

static grub_uint16_t
fatx_get_u16 (const grub_uint8_t *p, int big_endian)
{
	grub_uint16_t value = grub_get_unaligned16 (p);

	return big_endian ? grub_be_to_cpu16 (value) : grub_le_to_cpu16 (value);
}

static grub_err_t
fatx_disk_read (struct grub_fatx_data *data, grub_uint64_t offset,
	grub_size_t length, void *buffer)
{
	if (offset > data->disk_size || length > data->disk_size - offset)
		return grub_error (GRUB_ERR_BAD_FS, "FATX read outside device");
	return grub_disk_read (data->disk, offset >> GRUB_DISK_SECTOR_BITS,
		(grub_off_t) (offset & (GRUB_DISK_SECTOR_SIZE - 1)), length, buffer);
}

static grub_err_t
fatx_partition_read (struct grub_fatx_data *data,
	const struct grub_fatx_partition *partition, grub_uint64_t offset,
	grub_size_t length, void *buffer)
{
	grub_uint64_t absolute;

	if (offset > partition->length || length > partition->length - offset
		|| grub_add (partition->offset, offset, &absolute))
		return grub_error (GRUB_ERR_BAD_FS, "FATX read outside partition");
	return fatx_disk_read (data, absolute, length, buffer);
}

static int
fatx_is_power_of_two (grub_uint32_t value)
{
	return value != 0 && (value & (value - 1)) == 0;
}

static int
fatx_parse_partition (struct grub_fatx_data *data, const char *name,
	grub_uint64_t offset, grub_uint64_t length,
	struct grub_fatx_partition *partition)
{
	grub_uint8_t header[16];
	grub_uint64_t bytes_per_cluster;
	grub_uint64_t fat_entries;
	grub_uint64_t raw_fat_bytes;
	grub_uint64_t fat_bytes;
	grub_uint64_t file_area_offset;
	grub_uint64_t cluster_count;
	grub_uint32_t sectors_per_cluster;
	grub_uint32_t root_cluster;
	grub_uint32_t serial;
	grub_uint32_t entry_size;
	grub_uint8_t log2_sectors = 0;
	int big_endian;

	if (length < FATX_PAGE_SIZE || offset > data->disk_size
		|| length > data->disk_size - offset)
		return 0;
	if (fatx_disk_read (data, offset, sizeof (header), header))
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	if (grub_memcmp (header, "FATX", 4) == 0)
		big_endian = 0;
	else if (grub_memcmp (header, "XTAF", 4) == 0)
		big_endian = 1;
	else
		return 0;

	serial = fatx_get_u32 (header + 4, big_endian);
	sectors_per_cluster = fatx_get_u32 (header + 8, big_endian);
	root_cluster = fatx_get_u32 (header + 12, big_endian);
	if (!fatx_is_power_of_two (sectors_per_cluster)
		|| sectors_per_cluster > 0x400U || root_cluster == 0)
		return 0;
	while (((grub_uint32_t) 1 << log2_sectors) < sectors_per_cluster)
		log2_sectors++;
	bytes_per_cluster = (grub_uint64_t) sectors_per_cluster * FATX_SECTOR_SIZE;
	fat_entries = length / bytes_per_cluster + 1;
	if (fat_entries > 0xffffffffU)
		return 0;
	entry_size = fat_entries < FATX_FAT16_RESERVED ? 2U : 4U;
	if (grub_mul (fat_entries, (grub_uint64_t) entry_size, &raw_fat_bytes)
		|| grub_add (raw_fat_bytes, (grub_uint64_t) FATX_PAGE_SIZE - 1, &fat_bytes))
		return 0;
	fat_bytes &= ~((grub_uint64_t) FATX_PAGE_SIZE - 1);
	if (grub_add ((grub_uint64_t) FATX_RESERVED_BYTES, fat_bytes,
		&file_area_offset) || file_area_offset >= length)
		return 0;
	cluster_count = (length - file_area_offset) / bytes_per_cluster;
	if (cluster_count == 0 || cluster_count > 0xffffffffU
		|| root_cluster > cluster_count)
		return 0;

	grub_memset (partition, 0, sizeof (*partition));
	partition->name = name;
	partition->offset = offset;
	partition->length = length;
	partition->bytes_per_cluster = bytes_per_cluster;
	partition->file_area_offset = file_area_offset;
	partition->serial = serial;
	partition->root_cluster = root_cluster;
	partition->fat_entries = (grub_uint32_t) fat_entries;
	partition->cluster_count = (grub_uint32_t) cluster_count;
	partition->log2_sectors_per_cluster = log2_sectors;
	partition->fat_entry_size = (grub_uint8_t) entry_size;
	partition->big_endian = (grub_uint8_t) big_endian;
	return 1;
}

static grub_err_t
fatx_read_fat (struct grub_fatx_data *data,
	const struct grub_fatx_partition *partition, grub_uint32_t cluster,
	grub_uint32_t *value)
{
	grub_uint8_t raw[4];
	grub_uint64_t offset;

	if (cluster == 0 || cluster >= partition->fat_entries)
		return grub_error (GRUB_ERR_BAD_FS, "FATX cluster outside FAT");
	offset = FATX_RESERVED_BYTES
		+ (grub_uint64_t) cluster * partition->fat_entry_size;
	if (fatx_partition_read (data, partition, offset,
		partition->fat_entry_size, raw))
		return grub_errno;
	if (partition->fat_entry_size == 2)
		*value = fatx_get_u16 (raw, partition->big_endian);
	else
		*value = fatx_get_u32 (raw, partition->big_endian);
	return GRUB_ERR_NONE;
}

static grub_err_t
fatx_advance_cluster (struct grub_fatx_data *data,
	const struct grub_fatx_partition *partition, grub_uint32_t cluster,
	grub_uint32_t *next, int *ended)
{
	grub_uint32_t value;
	grub_uint32_t reserved = partition->fat_entry_size == 2
		? FATX_FAT16_RESERVED : FATX_FAT32_RESERVED;

	*ended = 0;
	if (cluster == 0 || cluster > partition->cluster_count)
		return grub_error (GRUB_ERR_BAD_FS, "FATX cluster outside file area");
	if (fatx_read_fat (data, partition, cluster, &value))
		return grub_errno;
	if (value >= reserved)
	{
		*ended = 1;
		return GRUB_ERR_NONE;
	}
	if (value == 0)
		return grub_error (GRUB_ERR_BAD_FS, "FATX chain reaches a free cluster");
	if (value > partition->cluster_count)
		return grub_error (GRUB_ERR_BAD_FS, "FATX chain leaves file area");
	*next = value;
	return GRUB_ERR_NONE;
}

static grub_err_t
fatx_validate_chain (struct grub_fatx_data *data,
	const struct grub_fatx_partition *partition, grub_uint32_t first)
{
	grub_uint32_t slow = first;
	grub_uint32_t fast = first;
	grub_uint32_t next;
	grub_uint32_t steps;
	int ended;

	if (first == 0 || first > partition->cluster_count)
		return grub_error (GRUB_ERR_BAD_FS, "invalid FATX first cluster");
	for (steps = 0; steps < partition->cluster_count; steps++)
	{
		if (fatx_advance_cluster (data, partition, slow, &next, &ended))
			return grub_errno;
		if (ended)
			return GRUB_ERR_NONE;
		slow = next;
		if (fatx_advance_cluster (data, partition, fast, &next, &ended))
			return grub_errno;
		if (ended)
			return GRUB_ERR_NONE;
		fast = next;
		if (fatx_advance_cluster (data, partition, fast, &next, &ended))
			return grub_errno;
		if (ended)
			return GRUB_ERR_NONE;
		fast = next;
		if (slow == fast)
			return grub_error (GRUB_ERR_BAD_FS, "cyclic FATX cluster chain");
	}
	return grub_error (GRUB_ERR_BAD_FS, "FATX cluster chain is too long");
}

static grub_err_t
fatx_require_clusters (struct grub_fatx_data *data,
	const struct grub_fatx_partition *partition, grub_uint32_t first,
	grub_uint64_t required)
{
	grub_uint32_t current = first;
	grub_uint32_t next;
	grub_uint64_t index;
	int ended;

	if (required == 0)
		return GRUB_ERR_NONE;
	if (required > partition->cluster_count)
		return grub_error (GRUB_ERR_BAD_FS, "FATX file exceeds file area");
	for (index = 1; index < required; index++)
	{
		if (fatx_advance_cluster (data, partition, current, &next, &ended))
			return grub_errno;
		if (ended)
			return grub_error (GRUB_ERR_BAD_FS, "truncated FATX file chain");
		current = next;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
fatx_cluster_offset (const struct grub_fatx_partition *partition,
	grub_uint32_t cluster, grub_uint64_t *offset)
{
	grub_uint64_t relative;

	if (cluster == 0 || cluster > partition->cluster_count
		|| grub_mul ((grub_uint64_t) cluster - 1, partition->bytes_per_cluster, &relative)
		|| grub_add (partition->file_area_offset, relative, &relative)
		|| grub_add (partition->offset, relative, offset)
		|| partition->bytes_per_cluster > partition->length - relative)
		return grub_error (GRUB_ERR_BAD_FS, "FATX cluster outside partition");
	return GRUB_ERR_NONE;
}

static int
fatx_name_valid (const grub_uint8_t *name, grub_uint32_t length)
{
	grub_uint32_t i;

	if (length == 0 || length > FATX_NAME_MAX)
		return 0;
	for (i = 0; i < length; i++)
		if (name[i] == 0 || name[i] == '/')
			return 0;
	return 1;
}

static int
fatx_timestamp (grub_uint32_t value, int xbox_360, grub_int64_t *time)
{
	struct grub_datetime datetime;

	if (value == 0 || (value & 0x1fU) > 29)
		return 0;
	datetime.year = (grub_uint16_t) ((value >> 25) + (xbox_360 ? 1980 : 2000));
	datetime.month = (grub_uint8_t) ((value >> 21) & 0x0fU);
	datetime.day = (grub_uint8_t) ((value >> 16) & 0x1fU);
	datetime.hour = (grub_uint8_t) ((value >> 11) & 0x1fU);
	datetime.minute = (grub_uint8_t) ((value >> 5) & 0x3fU);
	datetime.second = (grub_uint8_t) ((value & 0x1fU) * 2);
	return grub_datetime2unixtime (&datetime, time);
}

static int
fatx_iterate_directory (grub_fshelp_node_t directory,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_fatx_data *data = directory->data;
	const struct grub_fatx_partition *partition;
	grub_uint32_t cluster;
	grub_uint32_t next;
	grub_uint32_t chain_count = 0;
	grub_uint8_t *buffer = NULL;
	int ended;
	int stop = 0;

	if (!directory->directory)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a FATX directory");
		return 0;
	}
	if (directory->synthetic_root)
	{
		grub_uint32_t i;

		for (i = 0; i < data->partition_count; i++)
		{
			struct grub_fshelp_node *node = grub_zalloc (sizeof (*node));

			if (!node)
				return 0;
			node->data = data;
			node->inode = data->partitions[i].offset;
			node->first_cluster = data->partitions[i].root_cluster;
			node->partition = (grub_uint8_t) i;
			node->directory = 1;
			stop = hook (data->partitions[i].name,
				GRUB_FSHELP_DIR | GRUB_FSHELP_CASE_INSENSITIVE,
				node, hook_data);
			if (stop)
				return 1;
		}
		return 0;
	}

	partition = &data->partitions[directory->partition];
	if (fatx_validate_chain (data, partition, directory->first_cluster))
		return 0;
	buffer = grub_malloc ((grub_size_t) partition->bytes_per_cluster);
	if (!buffer)
		return 0;
	cluster = directory->first_cluster;
	while (chain_count++ < partition->cluster_count)
	{
		grub_uint64_t physical;
		grub_uint64_t entry_offset;

		if (fatx_cluster_offset (partition, cluster, &physical)
			|| fatx_disk_read (data, physical,
				(grub_size_t) partition->bytes_per_cluster, buffer))
			goto out;
		for (entry_offset = 0;
			entry_offset + FATX_DIRENT_SIZE <= partition->bytes_per_cluster;
			entry_offset += FATX_DIRENT_SIZE)
		{
			const grub_uint8_t *raw = buffer + (grub_size_t) entry_offset;
			grub_uint32_t name_length = raw[0];
			grub_uint32_t first_cluster;
			grub_uint32_t size;
			struct grub_fshelp_node *node;
			char *name;
			enum grub_fshelp_filetype type;

			if (name_length == FATX_DIRENT_END_A
				|| name_length == FATX_DIRENT_END_B)
				goto out;
			if (name_length == FATX_DIRENT_DELETED)
				continue;
			if (!fatx_name_valid (raw + 2, name_length))
			{
				grub_error (GRUB_ERR_BAD_FS, "invalid FATX directory entry name");
				goto out;
			}
			first_cluster = fatx_get_u32 (raw + 0x2c,
				partition->big_endian);
			size = fatx_get_u32 (raw + 0x30, partition->big_endian);
			if ((raw[1] & FATX_ATTR_DIRECTORY)
				? (first_cluster == 0 || first_cluster > partition->cluster_count)
				: (size != 0 && (first_cluster == 0
					|| first_cluster > partition->cluster_count)))
			{
				grub_error (GRUB_ERR_BAD_FS, "invalid FATX directory entry cluster");
				goto out;
			}
			name = grub_fs_bytes_to_utf8 ((const char *) raw + 2,
				name_length, grub_fs_char_encoding);
			if (!name)
				goto out;
			node = grub_zalloc (sizeof (*node));
			if (!node)
			{
				grub_free (name);
				goto out;
			}
			node->data = data;
			node->inode = physical + entry_offset;
			node->first_cluster = first_cluster;
			node->size = size;
			node->write_time = fatx_get_u32 (raw + 0x38, partition->big_endian);
			node->partition = directory->partition;
			node->directory = !!(raw[1] & FATX_ATTR_DIRECTORY);
			type = node->directory ? GRUB_FSHELP_DIR : GRUB_FSHELP_REG;
			stop = hook (name, type | GRUB_FSHELP_CASE_INSENSITIVE, node, hook_data);
			grub_free (name);
			if (stop)
				goto out;
		}
		if (fatx_advance_cluster (data, partition, cluster, &next, &ended))
			goto out;
		if (ended)
			break;
		cluster = next;
	}

out:
	grub_free (buffer);
	return stop;
}

static struct grub_fatx_data *
fatx_mount (grub_disk_t disk)
{
	struct grub_fatx_data *data;
	grub_uint64_t sectors;
	grub_uint32_t i;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	sectors = grub_disk_native_sectors (disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN
		|| sectors > (~(grub_uint64_t) 0 >> GRUB_DISK_SECTOR_BITS))
	{
		grub_error (GRUB_ERR_BAD_FS, "FATX device size is unknown");
		goto fail;
	}
	data->disk_size = sectors << GRUB_DISK_SECTOR_BITS;
	for (i = 0; i < ARRAY_SIZE (fatx_candidates); i++)
	{
		grub_uint64_t length;

		if (fatx_candidates[i].offset >= data->disk_size)
			continue;
		length = data->disk_size - fatx_candidates[i].offset;
		if (fatx_candidates[i].length != 0 && fatx_candidates[i].length < length)
			length = fatx_candidates[i].length;
		if (fatx_parse_partition (data, fatx_candidates[i].name,
			fatx_candidates[i].offset, length,
			&data->partitions[data->partition_count]))
			data->partition_count++;
	}
	if (data->partition_count == 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "not a FATX/XTAF filesystem");
		goto fail;
	}

	data->root.data = data;
	data->root.directory = 1;
	if (data->partition_count > 1)
		data->root.synthetic_root = 1;
	else
	{
		data->root.first_cluster = data->partitions[0].root_cluster;
		data->root.partition = 0;
		data->root.inode = data->partitions[0].offset + data->partitions[0].file_area_offset;
	}
	return data;

fail:
	grub_free (data);
	return NULL;
}

static grub_err_t
fatx_prepare_file (struct grub_fatx_data *data, struct grub_fshelp_node *node)
{
	const struct grub_fatx_partition *partition =
		&data->partitions[node->partition];
	grub_uint64_t required;

	if (node->size == 0)
		return GRUB_ERR_NONE;
	required = ((grub_uint64_t) node->size + partition->bytes_per_cluster - 1) / partition->bytes_per_cluster;
	if (fatx_validate_chain (data, partition, node->first_cluster)
		|| fatx_require_clusters (data, partition, node->first_cluster, required))
		return grub_errno;
	node->map_cluster = node->first_cluster;
	node->map_index = 0;
	node->map_valid = 1;
	return GRUB_ERR_NONE;
}

static grub_err_t
fatx_map_file_cluster (struct grub_fshelp_node *node, grub_uint32_t index,
	grub_uint32_t *cluster)
{
	const struct grub_fatx_partition *partition =
		&node->data->partitions[node->partition];
	grub_uint32_t next;
	int ended;

	if (!node->map_valid || index < node->map_index)
	{
		node->map_cluster = node->first_cluster;
		node->map_index = 0;
		node->map_valid = 1;
	}
	while (node->map_index < index)
	{
		if (fatx_advance_cluster (node->data, partition,
			node->map_cluster, &next, &ended))
			return grub_errno;
		if (ended)
			return grub_error (GRUB_ERR_BAD_FS, "truncated FATX file chain");
		node->map_cluster = next;
		node->map_index++;
	}
	*cluster = node->map_cluster;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_fatx_open (struct grub_file *file, const char *name)
{
	struct grub_fatx_data *data;
	struct grub_fshelp_node *node = NULL;

	data = fatx_mount (file->device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (name, &data->root, &node,
		fatx_iterate_directory, NULL, GRUB_FSHELP_REG))
		goto fail;
	data->open_node = *node;
	if (node != &data->root)
	{
		grub_free (node);
		node = NULL;
	}
	if (fatx_prepare_file (data, &data->open_node))
		goto fail;
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
grub_fatx_read (grub_file_t file, char *buffer, grub_size_t length)
{
	struct grub_fatx_data *data = file->data;
	struct grub_fshelp_node *node = &data->open_node;
	const struct grub_fatx_partition *partition = &data->partitions[node->partition];
	grub_uint64_t offset = file->offset;
	grub_size_t total = 0;

	if (offset > node->size)
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "attempt to read past end of FATX file");
		return -1;
	}
	if (length > node->size - offset)
		length = (grub_size_t) (node->size - offset);
	while (total < length)
	{
		grub_uint32_t index = (grub_uint32_t) (offset / partition->bytes_per_cluster);
		grub_uint64_t in_cluster = offset % partition->bytes_per_cluster;
		grub_uint64_t physical;
		grub_uint32_t cluster;
		grub_size_t chunk = length - total;

		if (chunk > partition->bytes_per_cluster - in_cluster)
			chunk = (grub_size_t) (partition->bytes_per_cluster - in_cluster);
		if (fatx_map_file_cluster (node, index, &cluster)
			|| fatx_cluster_offset (partition, cluster, &physical))
			return -1;
		data->disk->read_hook = file->read_hook;
		data->disk->read_hook_data = file->read_hook_data;
		if (fatx_disk_read (data, physical + in_cluster, chunk,
			buffer + total))
		{
			data->disk->read_hook = NULL;
			return -1;
		}
		data->disk->read_hook = NULL;
		total += chunk;
		offset += chunk;
	}
	return (grub_ssize_t) total;
}

static grub_err_t
grub_fatx_close (grub_file_t file)
{
	grub_free (file->data);
	file->data = NULL;
	return GRUB_ERR_NONE;
}

struct grub_fatx_dir_context
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_fatx_dir_hook (const char *name, enum grub_fshelp_filetype type,
	grub_fshelp_node_t node, void *hook_data)
{
	struct grub_fatx_dir_context *context = hook_data;
	const struct grub_fatx_partition *partition = &node->data->partitions[node->partition];
	struct grub_dirhook_info info;
	int stop;

	grub_memset (&info, 0, sizeof (info));
	info.dir = ((type & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.case_insensitive = 1;
	info.inodeset = 1;
	info.inode = node->inode;
	info.mtimeset = fatx_timestamp (node->write_time,
		partition->big_endian, &info.mtime);
	stop = context->hook (name, &info, context->hook_data);
	grub_free (node);
	return stop;
}

static grub_err_t
grub_fatx_dir (grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_fatx_dir_context context = { hook, hook_data };
	struct grub_fatx_data *data;
	struct grub_fshelp_node *directory = NULL;

	data = fatx_mount (device->disk);
	if (!data)
		return grub_errno;
	if (grub_fshelp_find_file (path, &data->root, &directory,
		fatx_iterate_directory, NULL, GRUB_FSHELP_DIR))
		goto out;
	fatx_iterate_directory (directory, grub_fatx_dir_hook, &context);

out:
	if (directory && directory != &data->root)
		grub_free (directory);
	grub_free (data);
	return grub_errno;
}

static grub_err_t
grub_fatx_uuid (grub_device_t device, char **uuid)
{
	struct grub_fatx_data *data;

	*uuid = NULL;
	data = fatx_mount (device->disk);
	if (!data)
		return grub_errno;
	if (data->partition_count == 1)
	{
		*uuid = grub_malloc (9);
		if (*uuid)
			grub_snprintf (*uuid, 9, "%08x", data->partitions[0].serial);
	}
	grub_free (data);
	return grub_errno;
}

static struct grub_fs grub_fatx_fs =
{
	.name = "fatx",
	.fs_dir = grub_fatx_dir,
	.fs_open = grub_fatx_open,
	.fs_read = grub_fatx_read,
	.fs_close = grub_fatx_close,
	.fs_uuid = grub_fatx_uuid,
	.next = NULL
};

GRUB_MOD_INIT (fatx)
{
	grub_fatx_fs.mod = mod;
	grub_fs_register (&grub_fatx_fs);
}

GRUB_MOD_FINI (fatx)
{
	grub_fs_unregister (&grub_fatx_fs);
}
