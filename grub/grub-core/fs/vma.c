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

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/crypto.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define VMA_MAGIC		"VMA\0"
#define VMA_EXTENT_MAGIC	"VMAE"
#define VMA_VERSION		1U
#define VMA_HEADER_MIN_SIZE	(3U * 4096U)
#define VMA_HEADER_MAX_SIZE	(1024U * 4096U)
#define VMA_EXTENT_HEADER_SIZE	512U
#define VMA_BLOCK_SIZE		4096U
#define VMA_CLUSTER_SIZE	65536U
#define VMA_BLOCKS_PER_CLUSTER	16U
#define VMA_CLUSTERS_PER_EXTENT	59U
#define VMA_MAX_BLOCK_COUNT	(VMA_BLOCKS_PER_CLUSTER * VMA_CLUSTERS_PER_EXTENT)
#define VMA_MAX_CONFIGS		256U
#define VMA_NAME_MAX		4096U

#define VMA_HEAD_VERSION_OFF	4U
#define VMA_HEAD_UUID_OFF	8U
#define VMA_HEAD_CTIME_OFF	24U
#define VMA_HEAD_MD5_OFF	32U
#define VMA_HEAD_BLOB_OFF	48U
#define VMA_HEAD_BLOB_SIZE_OFF	52U
#define VMA_HEAD_SIZE_OFF	56U
#define VMA_HEAD_CONFIG_NAME_OFF 2044U
#define VMA_HEAD_CONFIG_DATA_OFF 3068U
#define VMA_HEAD_DEVINFO_OFF	4096U
#define VMA_DEVINFO_SIZE	32U

#define VMA_EXTENT_BLOCK_COUNT_OFF 6U
#define VMA_EXTENT_UUID_OFF	8U
#define VMA_EXTENT_MD5_OFF	24U
#define VMA_EXTENT_BLOCKINFO_OFF 40U

enum vma_item_type
{
	VMA_ITEM_CONFIG,
	VMA_ITEM_DEVICE
};

struct vma_cluster
{
	grub_uint64_t data_pos;
	grub_uint32_t number;
	grub_uint16_t mask;
};

struct vma_stream
{
	char *name;
	grub_uint64_t size;
	grub_uint64_t expected_clusters;
	struct vma_cluster *clusters;
	grub_size_t num_clusters;
	grub_size_t cap_clusters;
};

struct vma_item
{
	char *name;
	grub_uint64_t size;
	grub_uint32_t data_offset;
	grub_uint8_t dev_id;
	grub_uint8_t type;
};

struct grub_vma_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	grub_int64_t ctime;
	grub_uint8_t uuid[16];
	grub_uint8_t *header;
	grub_uint32_t header_size;
	struct vma_stream streams[256];
	struct vma_item *items;
	unsigned num_items;
	unsigned cap_items;
};

struct grub_vma_file
{
	struct grub_vma_data *data;
	unsigned item_index;
};

static grub_uint16_t
vma_get_be16 (const void *p)
{
	return grub_be_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
vma_get_be32 (const void *p)
{
	return grub_be_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
vma_get_be64 (const void *p)
{
	return grub_be_to_cpu64 (grub_get_unaligned64 (p));
}

static unsigned
vma_popcount16 (grub_uint16_t value)
{
	unsigned count = 0;

	while (value)
	{
		value &= (grub_uint16_t) (value - 1);
		count++;
	}
	return count;
}

static void
vma_free_data (struct grub_vma_data *data)
{
	unsigned i;

	if (!data)
		return;
	for (i = 0; i < ARRAY_SIZE (data->streams); i++)
	{
		grub_free (data->streams[i].name);
		grub_free (data->streams[i].clusters);
	}
	for (i = 0; i < data->num_items; i++)
		grub_free (data->items[i].name);
	grub_free (data->items);
	grub_free (data->header);
	grub_free (data);
}

static char *
vma_copy_name (const grub_uint8_t *raw, grub_uint16_t size)
{
	char *name;
	unsigned i;

	if (size && raw[size - 1] == 0)
		size--;
	if (size == 0 || size > VMA_NAME_MAX)
		return 0;
	if ((size == 1 && raw[0] == '.')
	    || (size == 2 && raw[0] == '.' && raw[1] == '.'))
		return 0;
	for (i = 0; i < size; i++)
		if (raw[i] == 0 || raw[i] == '/' || raw[i] == '\\')
			return 0;
	name = grub_malloc ((grub_size_t) size + 1);
	if (!name)
		return 0;
	grub_memcpy (name, raw, size);
	name[size] = 0;
	return name;
}

static int
vma_blob (const struct grub_vma_data *data, grub_uint32_t blob_offset,
	grub_uint32_t blob_size, grub_uint32_t pointer, const grub_uint8_t **blob, grub_uint16_t *size)
{
	grub_uint32_t absolute;

	if (pointer == 0 || pointer > blob_size
		|| blob_size - pointer < sizeof (grub_uint16_t))
		return 0;
	absolute = blob_offset + pointer;
	*size = grub_le_to_cpu16 (grub_get_unaligned16 (data->header + absolute));
	if ((grub_uint32_t) *size > blob_size - pointer - sizeof (grub_uint16_t))
		return 0;
	*blob = data->header + absolute + sizeof (grub_uint16_t);
	return 1;
}

static int
vma_add_item (struct grub_vma_data *data, char *name, grub_uint64_t size,
	enum vma_item_type type, grub_uint8_t dev_id, grub_uint32_t data_offset)
{
	struct vma_item *items;
	unsigned i;
	unsigned cap;

	for (i = 0; i < data->num_items; i++)
		if (grub_strcmp (data->items[i].name, name) == 0)
			return 0;
	if (data->num_items == data->cap_items)
	{
		cap = data->cap_items ? data->cap_items * 2 : 16;
		if (cap < data->cap_items || cap > GRUB_SIZE_MAX / sizeof (*items))
			return 0;
		items = grub_realloc (data->items, cap * sizeof (*items));
		if (!items)
			return 0;
		data->items = items;
		data->cap_items = cap;
	}
	data->items[data->num_items].name = name;
	data->items[data->num_items].size = size;
	data->items[data->num_items].type = (grub_uint8_t) type;
	data->items[data->num_items].dev_id = dev_id;
	data->items[data->num_items].data_offset = data_offset;
	data->num_items++;
	return 1;
}

static int
vma_add_cluster (struct vma_stream *stream, grub_uint32_t number,
	grub_uint16_t mask, grub_uint64_t data_pos)
{
	struct vma_cluster *clusters;
	grub_size_t cap;

	if (stream->num_clusters == stream->cap_clusters)
	{
		cap = stream->cap_clusters ? stream->cap_clusters * 2 : 256;
		if (cap < stream->cap_clusters || cap > GRUB_SIZE_MAX / sizeof (*clusters))
			return 0;
		clusters = grub_realloc (stream->clusters, cap * sizeof (*clusters));
		if (!clusters)
			return 0;
		stream->clusters = clusters;
		stream->cap_clusters = cap;
	}
	stream->clusters[stream->num_clusters].number = number;
	stream->clusters[stream->num_clusters].mask = mask;
	stream->clusters[stream->num_clusters].data_pos = data_pos;
	stream->num_clusters++;
	return 1;
}

static void
vma_swap_cluster (struct vma_cluster *a, struct vma_cluster *b)
{
	struct vma_cluster tmp = *a;

	*a = *b;
	*b = tmp;
}

static void
vma_sift_clusters (struct vma_cluster *clusters, grub_size_t root, grub_size_t end)
{
	if (root >= end)
		return;
	while (root <= (end - 1) / 2)
	{
		grub_size_t child = root * 2 + 1;

		if (child < end
			&& clusters[child].number < clusters[child + 1].number)
			child++;
		if (clusters[root].number >= clusters[child].number)
			return;
		vma_swap_cluster (&clusters[root], &clusters[child]);
		root = child;
	}
}

static void
vma_sort_clusters (struct vma_cluster *clusters, grub_size_t count)
{
	grub_size_t start;
	grub_size_t end;

	if (count < 2)
		return;
	start = (count - 2) / 2;
	for (;;)
	{
		vma_sift_clusters (clusters, start, count - 1);
		if (start == 0)
			break;
		start--;
	}
	for (end = count - 1; end; end--)
	{
		vma_swap_cluster (&clusters[0], &clusters[end]);
		vma_sift_clusters (clusters, 0, end - 1);
	}
}

static int
vma_parse_header (struct grub_vma_data *data)
{
	grub_uint8_t stored_md5[16];
	grub_uint8_t actual_md5[16];
	grub_uint32_t blob_offset;
	grub_uint32_t blob_size;
	unsigned i;

	if (grub_memcmp (data->header, VMA_MAGIC, 4) != 0)
		return 0;
	if (vma_get_be32 (data->header + VMA_HEAD_VERSION_OFF) != VMA_VERSION)
	{
		grub_error (GRUB_ERR_BAD_FS, "unsupported vma version");
		return 0;
	}
	blob_offset = vma_get_be32 (data->header + VMA_HEAD_BLOB_OFF);
	blob_size = vma_get_be32 (data->header + VMA_HEAD_BLOB_SIZE_OFF);
	if (blob_offset < VMA_HEADER_MIN_SIZE || blob_offset > data->header_size
		|| blob_size > data->header_size - blob_offset)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid vma blob buffer");
		return 0;
	}
	grub_memcpy (stored_md5, data->header + VMA_HEAD_MD5_OFF, sizeof (stored_md5));
	grub_memset (data->header + VMA_HEAD_MD5_OFF, 0, sizeof (stored_md5));
	grub_crypto_hash (GRUB_MD_MD5, actual_md5, data->header, data->header_size);
	grub_memcpy (data->header + VMA_HEAD_MD5_OFF, stored_md5, sizeof (stored_md5));
	if (grub_memcmp (stored_md5, actual_md5, sizeof (stored_md5)) != 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "vma header checksum mismatch");
		return 0;
	}
	grub_memcpy (data->uuid, data->header + VMA_HEAD_UUID_OFF, sizeof (data->uuid));
	data->ctime = (grub_int64_t) vma_get_be64 (data->header + VMA_HEAD_CTIME_OFF);

	for (i = 0; i < VMA_MAX_CONFIGS; i++)
	{
		grub_uint32_t name_ptr;
		grub_uint32_t value_ptr;
		grub_uint16_t name_size;
		grub_uint16_t value_size;
		const grub_uint8_t *name_blob;
		const grub_uint8_t *value_blob;
		char *name;

		name_ptr = vma_get_be32 (data->header + VMA_HEAD_CONFIG_NAME_OFF + i * sizeof (grub_uint32_t));
		value_ptr = vma_get_be32 (data->header + VMA_HEAD_CONFIG_DATA_OFF + i * sizeof (grub_uint32_t));
		if (!name_ptr && !value_ptr)
			continue;
		if (!name_ptr || !value_ptr
			|| !vma_blob (data, blob_offset, blob_size, name_ptr, &name_blob, &name_size)
			|| !vma_blob (data, blob_offset, blob_size, value_ptr, &value_blob, &value_size))
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid vma config blob");
			return 0;
		}
		name = vma_copy_name (name_blob, name_size);
		if (!name
			|| !vma_add_item (data, name, value_size, VMA_ITEM_CONFIG, 0, (grub_uint32_t) (value_blob - data->header)))
		{
			grub_free (name);
			grub_error (GRUB_ERR_BAD_FS, "invalid or duplicate vma file name");
			return 0;
		}
	}

	for (i = 1; i < 255; i++)
	{
		const grub_uint8_t *entry = data->header + VMA_HEAD_DEVINFO_OFF + i * VMA_DEVINFO_SIZE;
		grub_uint32_t name_ptr = vma_get_be32 (entry);
		grub_uint64_t size = vma_get_be64 (entry + 8);
		grub_uint16_t name_size;
		const grub_uint8_t *name_blob;
		char *name;
		char *path;
		grub_size_t name_len;

		if (!name_ptr && !size)
			continue;
		if (!name_ptr || !size
			|| !vma_blob (data, blob_offset, blob_size, name_ptr, &name_blob, &name_size))
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid vma device entry");
			return 0;
		}
		name = vma_copy_name (name_blob, name_size);
		if (!name)
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid vma device name");
			return 0;
		}
		data->streams[i].name = name;
		data->streams[i].size = size;
		data->streams[i].expected_clusters = (size >> 16) + ((size & (VMA_CLUSTER_SIZE - 1)) != 0);
		name_len = grub_strlen (name);
		if (grub_strcmp (name, "vmstate") == 0)
			path = grub_strdup ("vmstate.bin");
		else
		{
			if (name_len > GRUB_SIZE_MAX - 10)
				return 0;
			path = grub_malloc (name_len + 10);
			if (path)
			{
				grub_memcpy (path, "disk-", 5);
				grub_memcpy (path + 5, name, name_len);
				grub_memcpy (path + 5 + name_len, ".raw", 5);
			}
		}
		if (!path
			|| !vma_add_item (data, path, size, VMA_ITEM_DEVICE, (grub_uint8_t) i, 0))
		{
			grub_free (path);
			grub_error (GRUB_ERR_BAD_FS, "invalid or duplicate vma file name");
			return 0;
		}
	}
	return 1;
}

static int
vma_scan_extents (struct grub_vma_data *data)
{
	grub_uint64_t pos = data->header_size;
	grub_uint8_t head[VMA_EXTENT_HEADER_SIZE];
	unsigned extent_count = 0;
	unsigned i;

	while (pos < data->disk_size)
	{
		grub_uint8_t stored_md5[16];
		grub_uint8_t actual_md5[16];
		grub_uint16_t block_count;
		grub_uint64_t extent_size;
		grub_uint64_t payload_pos;
		unsigned actual_blocks = 0;

		if (data->disk_size - pos < sizeof (head))
		{
			grub_error (GRUB_ERR_BAD_FS, "truncated vma extent header");
			return 0;
		}
		if (grub_disk_read (data->disk, 0, pos, sizeof (head), head))
			return 0;
		if (grub_memcmp (head, VMA_EXTENT_MAGIC, 4) != 0 || vma_get_be16 (head + 4) != 0)
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid vma extent header");
			return 0;
		}
		if (grub_memcmp (head + VMA_EXTENT_UUID_OFF, data->uuid, sizeof (data->uuid)) != 0)
		{
			grub_error (GRUB_ERR_BAD_FS, "vma extent uuid mismatch");
			return 0;
		}
		grub_memcpy (stored_md5, head + VMA_EXTENT_MD5_OFF, sizeof (stored_md5));
		grub_memset (head + VMA_EXTENT_MD5_OFF, 0, sizeof (stored_md5));
		grub_crypto_hash (GRUB_MD_MD5, actual_md5, head, sizeof (head));
		if (grub_memcmp (stored_md5, actual_md5, sizeof (stored_md5)) != 0)
		{
			grub_error (GRUB_ERR_BAD_FS, "vma extent header checksum mismatch");
			return 0;
		}
		block_count = vma_get_be16 (head + VMA_EXTENT_BLOCK_COUNT_OFF);
		if (block_count > VMA_MAX_BLOCK_COUNT)
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid vma extent block count");
			return 0;
		}
		extent_size = VMA_EXTENT_HEADER_SIZE + (grub_uint64_t) block_count * VMA_BLOCK_SIZE;
		if (extent_size > data->disk_size - pos)
		{
			grub_error (GRUB_ERR_BAD_FS, "truncated vma extent data");
			return 0;
		}
		payload_pos = pos + VMA_EXTENT_HEADER_SIZE;
		for (i = 0; i < VMA_CLUSTERS_PER_EXTENT; i++)
		{
			grub_uint64_t info = vma_get_be64 (head + VMA_EXTENT_BLOCKINFO_OFF + i * sizeof (grub_uint64_t));
			grub_uint16_t mask = (grub_uint16_t) (info >> 48);
			grub_uint8_t reserved = (grub_uint8_t) (info >> 40);
			grub_uint8_t dev_id = (grub_uint8_t) (info >> 32);
			grub_uint32_t cluster_num = (grub_uint32_t) info;
			unsigned blocks = vma_popcount16 (mask);

			if (!dev_id)
			{
				if (info != 0)
				{
					grub_error (GRUB_ERR_BAD_FS, "invalid unused vma block descriptor");
					return 0;
				}
				continue;
			}
			if (reserved || !data->streams[dev_id].name
				|| cluster_num >= data->streams[dev_id].expected_clusters)
			{
				grub_error (GRUB_ERR_BAD_FS, "invalid vma block descriptor");
				return 0;
			}
			if (!vma_add_cluster (&data->streams[dev_id], cluster_num, mask, payload_pos))
				return 0;
			actual_blocks += blocks;
			payload_pos += (grub_uint64_t) blocks * VMA_BLOCK_SIZE;
		}
		if (actual_blocks != block_count || payload_pos != pos + extent_size)
		{
			grub_error (GRUB_ERR_BAD_FS, "vma extent payload size mismatch");
			return 0;
		}
		pos += extent_size;
		extent_count++;
	}

	for (i = 1; i < 255; i++)
	{
		struct vma_stream *stream = &data->streams[i];
		grub_size_t cluster;

		if (!stream->name)
			continue;
		if (stream->expected_clusters != stream->num_clusters)
		{
			grub_error (GRUB_ERR_BAD_FS, "incomplete vma device stream");
			return 0;
		}
		vma_sort_clusters (stream->clusters, stream->num_clusters);
		for (cluster = 0; cluster < stream->num_clusters; cluster++)
			if (stream->clusters[cluster].number != cluster)
			{
				grub_error (GRUB_ERR_BAD_FS, "duplicate or missing vma device cluster");
				return 0;
			}
	}
	(void) extent_count;
	return 1;
}

static struct grub_vma_data *
grub_vma_mount (grub_disk_t disk)
{
	struct grub_vma_data *data = 0;
	grub_uint8_t probe[60];
	grub_uint64_t sectors;
	grub_uint32_t header_size;

	if (grub_disk_read (disk, 0, 0, sizeof (probe), probe))
		goto fail;
	if (grub_memcmp (probe, VMA_MAGIC, 4) != 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "not a vma archive");
		return 0;
	}
	header_size = vma_get_be32 (probe + VMA_HEAD_SIZE_OFF);
	if (header_size < VMA_HEADER_MIN_SIZE || header_size > VMA_HEADER_MAX_SIZE || (header_size & 511) != 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid vma header size");
		return 0;
	}
	sectors = grub_disk_native_sectors (disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN
		|| sectors > (~(grub_uint64_t) 0 >> GRUB_DISK_SECTOR_BITS))
	{
		grub_error (GRUB_ERR_BAD_FS, "unknown vma archive size");
		return 0;
	}
	data = grub_zalloc (sizeof (*data));
	if (!data)
		return 0;
	data->disk = disk;
	data->disk_size = sectors << GRUB_DISK_SECTOR_BITS;
	data->header_size = header_size;
	if (header_size > data->disk_size)
	{
		grub_error (GRUB_ERR_BAD_FS, "truncated vma header");
		goto fail;
	}
	data->header = grub_malloc (header_size);
	if (!data->header)
		goto fail;
	if (grub_disk_read (disk, 0, 0, header_size, data->header))
		goto fail;
	if (!vma_parse_header (data) || !vma_scan_extents (data))
		goto fail;
	return data;

fail:
	vma_free_data (data);
	return 0;
}

static const char *
vma_norm_path (const char *path)
{
	while (*path == '/')
		path++;
	return path;
}

static grub_err_t
grub_vma_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_vma_data *data = grub_vma_mount (device->disk);
	struct grub_dirhook_info info;
	unsigned i;

	if (!data)
		return grub_errno;
	path = vma_norm_path (path);
	if (*path)
	{
		vma_free_data (data);
		return grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);
	}
	for (i = 0; i < data->num_items; i++)
	{
		grub_memset (&info, 0, sizeof (info));
		info.inodeset = 1;
		info.inode = i;
		info.sizeset = 1;
		info.size = data->items[i].size;
		if (data->ctime)
		{
			info.mtimeset = 1;
			info.mtime = data->ctime;
		}
		if (hook (data->items[i].name, &info, hook_data))
			break;
	}
	vma_free_data (data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_vma_open (grub_file_t file, const char *name)
{
	struct grub_vma_data *data = grub_vma_mount (file->device->disk);
	struct grub_vma_file *ctx;
	unsigned i;

	if (!data)
		return grub_errno;
	name = vma_norm_path (name);
	for (i = 0; i < data->num_items; i++)
		if (grub_strcmp (data->items[i].name, name) == 0)
			break;
	if (i == data->num_items)
	{
		vma_free_data (data);
		return grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", name);
	}
	ctx = grub_malloc (sizeof (*ctx));
	if (!ctx)
	{
		vma_free_data (data);
		return grub_errno;
	}
	ctx->data = data;
	ctx->item_index = i;
	file->data = ctx;
	file->size = data->items[i].size;
	return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_vma_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_vma_file *ctx = file->data;
	const struct vma_item *item = &ctx->data->items[ctx->item_index];
	grub_uint64_t pos = file->offset;
	grub_size_t left = len;

	if (pos > item->size || len > item->size - pos)
		return -1;
	if (item->type == VMA_ITEM_CONFIG)
	{
		grub_memcpy (buf, ctx->data->header + item->data_offset + (grub_size_t) pos, len);
		return (grub_ssize_t) len;
	}
	grub_memset (buf, 0, len);
	ctx->data->disk->read_hook = file->read_hook;
	ctx->data->disk->read_hook_data = file->read_hook_data;
	while (left)
	{
		const struct vma_stream *stream = &ctx->data->streams[item->dev_id];
		grub_uint64_t cluster_num = pos >> 16;
		unsigned block_num = (unsigned) ((pos >> 12) & 15);
		grub_size_t in_block = (grub_size_t) (pos & (VMA_BLOCK_SIZE - 1));
		grub_size_t count = VMA_BLOCK_SIZE - in_block;
		const struct vma_cluster *cluster;

		if (count > left)
			count = left;
		cluster = &stream->clusters[(grub_size_t) cluster_num];
		if (cluster->mask & (1U << block_num))
		{
			grub_uint16_t before = (grub_uint16_t) (cluster->mask & ((1U << block_num) - 1));
			grub_uint64_t data_pos = cluster->data_pos
				+ (grub_uint64_t) vma_popcount16 (before) * VMA_BLOCK_SIZE
				+ in_block;

			if (grub_disk_read (ctx->data->disk, 0, data_pos, count, buf))
			{
				ctx->data->disk->read_hook = 0;
				return -1;
			}
		}
		pos += count;
		buf += count;
		left -= count;
	}
	ctx->data->disk->read_hook = 0;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_vma_close (grub_file_t file)
{
	struct grub_vma_file *ctx = file->data;

	if (ctx)
	{
		vma_free_data (ctx->data);
		grub_free (ctx);
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_vma_uuid (grub_device_t device, char **uuid)
{
	struct grub_vma_data *data = grub_vma_mount (device->disk);
	char *text;
	int size;

	if (!data)
		return grub_errno;
	text = grub_malloc (37);
	if (!text)
	{
		vma_free_data (data);
		return grub_errno;
	}
	size = grub_snprintf (text, 37,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x%02x%02x%02x%02x",
		data->uuid[0], data->uuid[1], data->uuid[2], data->uuid[3],
		data->uuid[4], data->uuid[5], data->uuid[6], data->uuid[7],
		data->uuid[8], data->uuid[9], data->uuid[10], data->uuid[11],
		data->uuid[12], data->uuid[13], data->uuid[14], data->uuid[15]);
	if (size != 36)
	{
		grub_free (text);
		vma_free_data (data);
		return grub_error (GRUB_ERR_BAD_FS, "invalid vma uuid");
	}
	*uuid = text;
	vma_free_data (data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_vma_mtime (grub_device_t device, grub_int64_t *timebuf)
{
	struct grub_vma_data *data = grub_vma_mount (device->disk);

	if (!data)
		return grub_errno;
	*timebuf = data->ctime;
	vma_free_data (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_vma_fs =
{
	.name = "vma",
	.fs_dir = grub_vma_dir,
	.fs_open = grub_vma_open,
	.fs_read = grub_vma_read,
	.fs_close = grub_vma_close,
	.fs_uuid = grub_vma_uuid,
	.fs_mtime = grub_vma_mtime,
};

GRUB_MOD_INIT (vma)
{
	grub_fs_register (&grub_vma_fs);
}

GRUB_MOD_FINI (vma)
{
	grub_fs_unregister (&grub_vma_fs);
}
