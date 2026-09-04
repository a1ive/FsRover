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
#include <grub/datetime.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define HIK_MASTER_OFFSET	0x200
#define HIK_MASTER_SIZE		0x100
#define HIK_MASTER_SIGNATURE_OFFSET	0x10
#define HIK_MASTER_VERSION_OFFSET	0x30
#define HIK_MASTER_CAPACITY_OFFSET	0x48
#define HIK_MASTER_LOG_OFFSET		0x60
#define HIK_MASTER_LOG_SIZE_OFFSET	0x68
#define HIK_MASTER_VIDEO_OFFSET		0x78
#define HIK_MASTER_BLOCK_SIZE_OFFSET	0x88
#define HIK_MASTER_BLOCK_COUNT_OFFSET	0x90
#define HIK_MASTER_TREE1_OFFSET		0x98
#define HIK_MASTER_TREE1_SIZE_OFFSET	0xA0
#define HIK_MASTER_TREE2_OFFSET		0xA8
#define HIK_MASTER_TREE2_SIZE_OFFSET	0xB0
#define HIK_MASTER_INIT_TIME_OFFSET	0xF0

#define HIK_TREE_SIGNATURE_OFFSET	0x10
#define HIK_TREE_FOOTER_OFFSET		0x40
#define HIK_TREE_PAGE_LIST_OFFSET	0x50
#define HIK_TREE_FIRST_PAGE_OFFSET	0x58
#define HIK_TREE_HEADER_READ		0x60

#define HIK_PAGE_SIZE		0x1000
#define HIK_PAGE_COUNT_OFFSET	0x10
#define HIK_PAGE_NEXT_OFFSET	0x20
#define HIK_PAGE_ENTRIES_OFFSET	0x60
#define HIK_ENTRY_SIZE		0x30
#define HIK_PAGE_ENTRIES_MAX	((HIK_PAGE_SIZE - HIK_PAGE_ENTRIES_OFFSET) / HIK_ENTRY_SIZE)

#define HIK_ENTRY_STATUS_OFFSET	0x08
#define HIK_ENTRY_CHANNEL_OFFSET	0x10
#define HIK_ENTRY_START_OFFSET	0x18
#define HIK_ENTRY_END_OFFSET	0x1C
#define HIK_ENTRY_DATA_OFFSET	0x20

#define HIK_FOOTER_MARKER_OFFSET	0x10
#define HIK_FOOTER_LAST_PAGE_OFFSET	0x18
#define HIK_FOOTER_READ		0x20

#define HIK_TIMESTAMP_RECORDING	0x7FFFFFFFU
#define HIK_MEDIA_PROBE_SIZE	4096
#define HIK_NAME_MAX		192

enum hik_media_kind
{
	HIK_MEDIA_BIN,
	HIK_MEDIA_PS,
	HIK_MEDIA_H264
};

struct hik_master
{
	grub_uint64_t capacity;
	grub_uint64_t log_offset;
	grub_uint64_t log_size;
	grub_uint64_t video_offset;
	grub_uint64_t block_size;
	grub_uint32_t block_count;
	grub_uint64_t tree_offset[2];
	grub_uint32_t tree_size[2];
	grub_uint32_t init_time;
};

struct hik_entry
{
	grub_uint64_t data_offset;
	grub_uint64_t size;
	grub_uint64_t block_index;
	grub_uint32_t start_time;
	grub_uint32_t end_time;
	grub_uint32_t ordinal;
	grub_uint16_t channel;
	grub_uint8_t media_kind;
};

struct hik_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct hik_master master;
	struct hik_entry *entries;
	grub_uint32_t num_entries;
	grub_uint32_t cap_entries;
};

struct hik_file
{
	struct hik_data *data;
	grub_uint32_t index;
};

static const grub_uint8_t hik_signature[] = "HIKVISION@HANGZHOU";
static const grub_uint8_t hik_version[] = "HIK.2011.03.08";
static const grub_uint8_t hik_tree_signature[] = "HIKBTREE";

static grub_uint16_t
hik_get_be16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) (((grub_uint16_t) p[0] << 8) | p[1]);
}

static grub_uint32_t
hik_get_le32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
hik_get_le64 (const grub_uint8_t *p)
{
	return grub_le_to_cpu64 (grub_get_unaligned64 (p));
}

static int
hik_range (grub_uint64_t offset, grub_uint64_t size, grub_uint64_t limit)
{
	return offset <= limit && size <= limit - offset;
}

static int
hik_tree_range (grub_uint64_t base, grub_uint32_t size,
		grub_uint64_t offset, grub_uint64_t length)
{
	return offset >= base && offset - base <= size
		&& length <= size - (offset - base);
}

static int
hik_all_byte (const grub_uint8_t *p, grub_size_t size, grub_uint8_t value)
{
	grub_size_t i;

	for (i = 0; i < size; i++)
		if (p[i] != value)
			return 0;
	return 1;
}

static void
hik_free_data (struct hik_data *data)
{
	if (!data)
		return;
	grub_free (data->entries);
	grub_free (data);
}

static grub_err_t
hik_read (struct hik_data *data, grub_uint64_t offset, grub_size_t size,
	  void *buf)
{
	if (!hik_range (offset, size, data->disk_size))
		return grub_error (GRUB_ERR_BAD_FS, "Hikvision structure is outside the disk");
	return grub_disk_read (data->disk, 0, offset, size, buf);
}

static int
hik_valid_timestamp (grub_uint32_t value)
{
	return value != 0 && value < HIK_TIMESTAMP_RECORDING;
}

static const char *
hik_media_extension (grub_uint8_t kind)
{
	switch (kind)
	{
	case HIK_MEDIA_PS:
		return "ps";
	case HIK_MEDIA_H264:
		return "h264";
	default:
		return "bin";
	}
}

static grub_err_t
hik_probe_media (struct hik_data *data, struct hik_entry *entry)
{
	grub_uint8_t probe[HIK_MEDIA_PROBE_SIZE];
	grub_size_t size, i;
	grub_size_t h264 = HIK_MEDIA_PROBE_SIZE;

	size = entry->size < sizeof (probe) ? (grub_size_t) entry->size : sizeof (probe);
	if (hik_read (data, entry->data_offset, size, probe))
		return grub_errno;

	for (i = 0; i + 4 <= size; i++)
	{
		if (probe[i] == 0 && probe[i + 1] == 0
			&& probe[i + 2] == 1 && probe[i + 3] == 0xBA)
		{
			entry->data_offset += i;
			entry->size -= i;
			entry->media_kind = HIK_MEDIA_PS;
			return GRUB_ERR_NONE;
		}
		if (h264 == sizeof (probe))
		{
			if (i + 5 <= size && probe[i] == 0 && probe[i + 1] == 0
				&& probe[i + 2] == 0 && probe[i + 3] == 1 && (probe[i + 4] & 0x1F) == 7)
				h264 = i;
			else if (probe[i] == 0 && probe[i + 1] == 0 && probe[i + 2] == 1 && (probe[i + 3] & 0x1F) == 7)
				h264 = i;
		}
	}
	if (h264 != sizeof (probe))
	{
		entry->data_offset += h264;
		entry->size -= h264;
		entry->media_kind = HIK_MEDIA_H264;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
hik_add_entry (struct hik_data *data, const grub_uint8_t *raw, grub_uint32_t ordinal)
{
	struct hik_entry entry;
	grub_uint64_t status, offset, index;
	grub_uint16_t channel;
	grub_uint32_t start, end;

	if (!hik_all_byte (raw, 8, 0xFF))
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE entry marker");

	status = hik_get_le64 (raw + HIK_ENTRY_STATUS_OFFSET);
	if (status != 0)
		return GRUB_ERR_NONE;

	channel = hik_get_be16 (raw + HIK_ENTRY_CHANNEL_OFFSET);
	start = hik_get_le32 (raw + HIK_ENTRY_START_OFFSET);
	end = hik_get_le32 (raw + HIK_ENTRY_END_OFFSET);
	offset = hik_get_le64 (raw + HIK_ENTRY_DATA_OFFSET);

	if (offset < data->master.video_offset)
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision data block offset");
	if ((offset - data->master.video_offset) % data->master.block_size != 0)
		return grub_error (GRUB_ERR_BAD_FS, "unaligned Hikvision data block offset");
	index = (offset - data->master.video_offset) / data->master.block_size;
	if (index >= data->master.block_count
		|| !hik_range (offset, data->master.block_size, data->master.capacity))
		return grub_error (GRUB_ERR_BAD_FS, "Hikvision data block is out of range");

	/* Channel 0 and 255 entries describe unassigned or initialization
	   blocks.  Other malformed time records remain recoverable only through
	   those reserved records, so do not invent a camera file for them.  */
	if (channel == 0 || channel >= 255)
		return GRUB_ERR_NONE;
	if (start != HIK_TIMESTAMP_RECORDING
		&& (!hik_valid_timestamp (start) || !hik_valid_timestamp (end)))
		return GRUB_ERR_NONE;

	grub_memset (&entry, 0, sizeof (entry));
	entry.data_offset = offset;
	entry.size = data->master.block_size;
	entry.block_index = index;
	entry.start_time = start;
	entry.end_time = end;
	entry.ordinal = ordinal;
	entry.channel = channel;
	if (hik_probe_media (data, &entry))
		return grub_errno;

	if (data->num_entries == data->cap_entries)
	{
		grub_uint32_t cap = data->cap_entries ? data->cap_entries * 2 : 64;
		struct hik_entry *entries;

		entries = grub_realloc (data->entries, (grub_size_t) cap * sizeof (*entries));
		if (!entries)
			return grub_errno;
		data->entries = entries;
		data->cap_entries = cap;
	}
	data->entries[data->num_entries++] = entry;
	return GRUB_ERR_NONE;
}

static int
hik_find_page (const grub_uint64_t *pages, grub_uint32_t count, grub_uint64_t offset)
{
	grub_uint32_t i;

	for (i = 0; i < count; i++)
		if (pages[i] == offset)
			return (int) i;
	return -1;
}

static grub_err_t
hik_validate_chain (const grub_uint64_t *pages, const grub_uint64_t *next, grub_uint32_t count, grub_uint64_t footer_last)
{
	grub_uint8_t *incoming = NULL;
	grub_uint8_t *seen = NULL;
	grub_uint32_t i, head = count, terminal = count;
	grub_uint32_t terminal_count = 0, head_count = 0;
	grub_err_t err = GRUB_ERR_NONE;

	incoming = grub_calloc (count, sizeof (*incoming));
	seen = grub_calloc (count, sizeof (*seen));
	if (!incoming || !seen)
	{
		err = grub_errno;
		goto out;
	}

	for (i = 0; i < count; i++)
	{
		int target;

		if (next[i] == ~(grub_uint64_t) 0)
		{
			terminal = i;
			terminal_count++;
			continue;
		}
		target = hik_find_page (pages, count, next[i]);
		if (target < 0 || incoming[target])
		{
			err = grub_error (GRUB_ERR_BAD_FS, "broken Hikvision HIKBTREE page chain");
			goto out;
		}
		incoming[target] = 1;
	}
	for (i = 0; i < count; i++)
		if (!incoming[i])
		{
			head = i;
			head_count++;
		}
	if (terminal_count != 1 || head_count != 1 || pages[terminal] != footer_last)
	{
		err = grub_error (GRUB_ERR_BAD_FS, "inconsistent Hikvision HIKBTREE page chain");
		goto out;
	}

	for (i = 0; i < count; i++)
	{
		int target;

		if (head >= count || seen[head])
		{
			err = grub_error (GRUB_ERR_BAD_FS, "cyclic Hikvision HIKBTREE page chain");
			goto out;
		}
		seen[head] = 1;
		if (next[head] == ~(grub_uint64_t) 0)
		{
			head = count;
			continue;
		}
		target = hik_find_page (pages, count, next[head]);
		if (target < 0)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "broken Hikvision HIKBTREE page chain");
			goto out;
		}
		head = (grub_uint32_t) target;
	}
	if (head != count)
		err = grub_error (GRUB_ERR_BAD_FS, "incomplete Hikvision HIKBTREE page chain");

out:
	grub_free (incoming);
	grub_free (seen);
	return err;
}

static grub_err_t
hik_parse_tree (struct hik_data *data, grub_uint64_t base, grub_uint32_t size)
{
	grub_uint8_t header[HIK_TREE_HEADER_READ];
	grub_uint8_t footer[HIK_FOOTER_READ];
	grub_uint8_t page_header[HIK_PAGE_ENTRIES_OFFSET];
	grub_uint8_t raw[HIK_ENTRY_SIZE];
	grub_uint64_t footer_offset, page_list, first_page, footer_last;
	grub_uint64_t *pages = NULL, *next = NULL;
	grub_uint32_t page_count, i, j, ordinal = 0;
	grub_err_t err = GRUB_ERR_NONE;

	if (size < HIK_PAGE_SIZE * 3 || !hik_range (base, size, data->master.capacity))
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE range");
	if (hik_read (data, base, sizeof (header), header))
		return grub_errno;
	if (grub_memcmp (header + HIK_TREE_SIGNATURE_OFFSET, hik_tree_signature,
			sizeof (hik_tree_signature) - 1) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE signature");

	footer_offset = hik_get_le64 (header + HIK_TREE_FOOTER_OFFSET);
	page_list = hik_get_le64 (header + HIK_TREE_PAGE_LIST_OFFSET);
	first_page = hik_get_le64 (header + HIK_TREE_FIRST_PAGE_OFFSET);
	if (!hik_tree_range (base, size, footer_offset, sizeof (footer))
		|| !hik_tree_range (base, size, page_list, HIK_PAGE_SIZE)
		|| !hik_tree_range (base, size, first_page, HIK_PAGE_SIZE)
		|| (footer_offset - base) % HIK_PAGE_SIZE != 0
		|| (page_list - base) % HIK_PAGE_SIZE != 0
		|| (first_page - base) % HIK_PAGE_SIZE != 0)
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE pointers");

	if (hik_read (data, page_list + HIK_PAGE_COUNT_OFFSET, sizeof (page_count), &page_count))
		return grub_errno;
	page_count = grub_le_to_cpu32 (page_count);
	if (page_count == 0 || page_count > HIK_PAGE_ENTRIES_MAX || page_count > size / HIK_PAGE_SIZE)
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE page count");

	pages = grub_calloc (page_count, sizeof (*pages));
	next = grub_calloc (page_count, sizeof (*next));
	if (!pages || !next)
	{
		err = grub_errno;
		goto out;
	}
	for (i = 0; i < page_count; i++)
	{
		grub_uint64_t entry_offset = page_list + HIK_PAGE_ENTRIES_OFFSET
			+ (grub_uint64_t) i * HIK_ENTRY_SIZE;

		if (hik_read (data, entry_offset, sizeof (raw), raw))
		{
			err = grub_errno;
			goto out;
		}
		pages[i] = hik_get_le64 (raw);
		if (!hik_tree_range (base, size, pages[i], HIK_PAGE_SIZE)
			|| (pages[i] - base) % HIK_PAGE_SIZE != 0
			|| hik_find_page (pages, i, pages[i]) >= 0)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE page list");
			goto out;
		}
	}

	for (i = 0; i < page_count; i++)
	{
		grub_uint32_t entry_count;

		if (hik_read (data, pages[i], sizeof (page_header), page_header))
		{
			err = grub_errno;
			goto out;
		}
		entry_count = hik_get_le32 (page_header + HIK_PAGE_COUNT_OFFSET);
		next[i] = hik_get_le64 (page_header + HIK_PAGE_NEXT_OFFSET);
		if (entry_count > HIK_PAGE_ENTRIES_MAX)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE entry count");
			goto out;
		}
		for (j = 0; j < entry_count; j++)
		{
			grub_uint64_t entry_offset = pages[i] + HIK_PAGE_ENTRIES_OFFSET + (grub_uint64_t) j * HIK_ENTRY_SIZE;

			if (hik_read (data, entry_offset, sizeof (raw), raw))
			{
				err = grub_errno;
				goto out;
			}
			ordinal++;
			err = hik_add_entry (data, raw, ordinal);
			if (err)
				goto out;
		}
	}

	if (hik_read (data, footer_offset, sizeof (footer), footer))
	{
		err = grub_errno;
		goto out;
	}
	if (!hik_all_byte (footer + HIK_FOOTER_MARKER_OFFSET, 8, 0xFF))
	{
		err = grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE footer");
		goto out;
	}
	footer_last = hik_get_le64 (footer + HIK_FOOTER_LAST_PAGE_OFFSET);
	err = hik_validate_chain (pages, next, page_count, footer_last);

out:
	grub_free (pages);
	grub_free (next);
	return err;
}

static grub_err_t
hik_parse_master (struct hik_data *data)
{
	grub_uint8_t raw[HIK_MASTER_SIZE];
	struct hik_master *m = &data->master;
	grub_uint64_t blocks_end;
	unsigned i;

	if (data->disk->log_sector_size >= 64
		|| data->disk->total_sectors > (~(grub_uint64_t) 0 >> data->disk->log_sector_size))
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision disk size");
	data->disk_size = data->disk->total_sectors << data->disk->log_sector_size;
	if (!hik_range (HIK_MASTER_OFFSET, sizeof (raw), data->disk_size))
		return grub_error (GRUB_ERR_BAD_FS, "not a Hikvision HDD filesystem");
	if (hik_read (data, HIK_MASTER_OFFSET, sizeof (raw), raw))
		return grub_errno;
	if (grub_memcmp (raw + HIK_MASTER_SIGNATURE_OFFSET, hik_signature, sizeof (hik_signature) - 1) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "not a Hikvision HDD filesystem");
	if (grub_memcmp (raw + HIK_MASTER_VERSION_OFFSET, hik_version, sizeof (hik_version) - 1) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "unsupported Hikvision HDD version");

	m->capacity = hik_get_le64 (raw + HIK_MASTER_CAPACITY_OFFSET);
	m->log_offset = hik_get_le64 (raw + HIK_MASTER_LOG_OFFSET);
	m->log_size = hik_get_le64 (raw + HIK_MASTER_LOG_SIZE_OFFSET);
	m->video_offset = hik_get_le64 (raw + HIK_MASTER_VIDEO_OFFSET);
	m->block_size = hik_get_le64 (raw + HIK_MASTER_BLOCK_SIZE_OFFSET);
	m->block_count = hik_get_le32 (raw + HIK_MASTER_BLOCK_COUNT_OFFSET);
	m->tree_offset[0] = hik_get_le64 (raw + HIK_MASTER_TREE1_OFFSET);
	m->tree_size[0] = hik_get_le32 (raw + HIK_MASTER_TREE1_SIZE_OFFSET);
	m->tree_offset[1] = hik_get_le64 (raw + HIK_MASTER_TREE2_OFFSET);
	m->tree_size[1] = hik_get_le32 (raw + HIK_MASTER_TREE2_SIZE_OFFSET);
	m->init_time = hik_get_le32 (raw + HIK_MASTER_INIT_TIME_OFFSET);

	if (m->capacity < HIK_MASTER_OFFSET + HIK_MASTER_SIZE
		|| m->capacity > data->disk_size || m->block_size == 0
		|| m->block_size % ((grub_uint64_t) 1 << data->disk->log_sector_size) != 0
		|| m->block_count == 0 || m->video_offset >= m->capacity
		|| m->block_count > (m->capacity - m->video_offset) / m->block_size)
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision master sector");
	blocks_end = m->video_offset + (grub_uint64_t) m->block_count * m->block_size;
	if (blocks_end > m->capacity
		|| (m->log_size && !hik_range (m->log_offset, m->log_size, m->capacity)))
		return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision master ranges");

	for (i = 0; i < 2; i++)
		if (m->tree_size[i]
			&& (!hik_range (m->tree_offset[i], m->tree_size[i], m->capacity) || m->tree_offset[i] < blocks_end))
			return grub_error (GRUB_ERR_BAD_FS, "invalid Hikvision HIKBTREE range");
	if (!m->tree_size[0] && !m->tree_size[1])
		return grub_error (GRUB_ERR_BAD_FS, "Hikvision HIKBTREE is missing");
	return GRUB_ERR_NONE;
}

static struct hik_data *
hik_mount (grub_disk_t disk)
{
	struct hik_data *data;
	grub_err_t err;
	unsigned tree;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	if (hik_parse_master (data))
		goto fail;

	for (tree = 0; tree < 2; tree++)
	{
		if (!data->master.tree_size[tree])
			continue;
		data->num_entries = 0;
		err = hik_parse_tree (data, data->master.tree_offset[tree], data->master.tree_size[tree]);
		if (!err)
		{
			grub_errno = GRUB_ERR_NONE;
			return data;
		}
		if (err == GRUB_ERR_OUT_OF_MEMORY)
			goto fail;
		grub_errno = GRUB_ERR_NONE;
	}
	grub_error (GRUB_ERR_BAD_FS, "both Hikvision HIKBTREE copies are invalid");

fail:
	hik_free_data (data);
	return NULL;
}

static const char *
hik_normalize (const char *path, grub_size_t *length)
{
	const char *end;

	while (*path == '/')
		path++;
	end = path + grub_strlen (path);
	while (end > path && end[-1] == '/')
		end--;
	*length = (grub_size_t) (end - path);
	return path;
}

static int
hik_parse_channel (const char *path, grub_size_t length,
	grub_uint16_t *channel, const char **child, grub_size_t *child_length)
{
	unsigned value;

	if (length < 5 || grub_strncasecmp (path, "CH", 2) != 0
		|| path[2] < '0' || path[2] > '9'
		|| path[3] < '0' || path[3] > '9'
		|| path[4] < '0' || path[4] > '9')
		return 0;
	value = (unsigned) (path[2] - '0') * 100 + (unsigned) (path[3] - '0') * 10 + (unsigned) (path[4] - '0');
	if (value == 0 || value >= 255)
		return 0;
	if (length == 5)
	{
		*child = path + 5;
		*child_length = 0;
	}
	else
	{
		if (path[5] != '/' || length == 6
			|| grub_memchr (path + 6, '/', length - 6))
			return 0;
		*child = path + 6;
		*child_length = length - 6;
	}
	*channel = (grub_uint16_t) value;
	return 1;
}

static void
hik_format_name (const struct hik_entry *entry, char *name, grub_size_t size)
{
	const char *ext = hik_media_extension (entry->media_kind);

	if (entry->start_time == HIK_TIMESTAMP_RECORDING)
	{
		grub_snprintf (name, size, "RECORDING--block-%06llu--entry-%06u.%s",
			(unsigned long long) entry->block_index, (unsigned) entry->ordinal, ext);
	}
	else
	{
		struct grub_datetime start, end;

		grub_unixtime2datetime (entry->start_time, &start);
		grub_unixtime2datetime (entry->end_time, &end);
		grub_snprintf (name, size,
			"%04u-%02u-%02u_%02u-%02u-%02u--%04u-%02u-%02u_%02u-%02u-%02u--block-%06llu--entry-%06u.%s",
			(unsigned) start.year, (unsigned) start.month,
			(unsigned) start.day, (unsigned) start.hour,
			(unsigned) start.minute, (unsigned) start.second,
			(unsigned) end.year, (unsigned) end.month,
			(unsigned) end.day, (unsigned) end.hour,
			(unsigned) end.minute, (unsigned) end.second,
			(unsigned long long) entry->block_index,
			(unsigned) entry->ordinal, ext);
	}
}

static grub_err_t
grub_hikvision_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook, void *hook_data)
{
	struct hik_data *data;
	const char *normalized, *child;
	grub_size_t length, child_length;
	grub_uint16_t channel;
	grub_uint8_t listed[255];
	grub_uint32_t i;
	int found = 0;
	grub_err_t err = GRUB_ERR_NONE;

	data = hik_mount (device->disk);
	if (!data)
		return grub_errno;
	normalized = hik_normalize (path, &length);
	grub_memset (listed, 0, sizeof (listed));

	if (length == 0)
	{
		for (i = 0; i < data->num_entries; i++)
		{
			struct grub_dirhook_info info;
			char name[8];

			channel = data->entries[i].channel;
			if (listed[channel])
				continue;
			listed[channel] = 1;
			grub_snprintf (name, sizeof (name), "CH%03u", (unsigned) channel);
			grub_memset (&info, 0, sizeof (info));
			info.dir = 1;
			info.case_insensitive = 1;
			info.inodeset = 1;
			info.inode = channel;
			if (hook (name, &info, hook_data))
				break;
		}
		goto out;
	}

	if (!hik_parse_channel (normalized, length, &channel, &child, &child_length) || child_length != 0)
	{
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND, "directory `%s' not found", path);
		goto out;
	}
	for (i = 0; i < data->num_entries; i++)
	{
		struct grub_dirhook_info info;
		char name[HIK_NAME_MAX];

		if (data->entries[i].channel != channel)
			continue;
		found = 1;
		hik_format_name (&data->entries[i], name, sizeof (name));
		grub_memset (&info, 0, sizeof (info));
		info.case_insensitive = 1;
		info.inodeset = 1;
		info.inode = (grub_uint64_t) i + 256;
		info.sizeset = 1;
		info.size = data->entries[i].size;
		if (hik_valid_timestamp (data->entries[i].end_time))
		{
			info.mtimeset = 1;
			info.mtime = data->entries[i].end_time;
		}
		if (hook (name, &info, hook_data))
			break;
	}
	if (!found)
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND, "directory `%s' not found", path);

out:
	hik_free_data (data);
	return err;
}

static grub_err_t
grub_hikvision_open (struct grub_file *file, const char *name)
{
	struct hik_data *data;
	struct hik_file *ctx = NULL;
	const char *normalized, *child;
	grub_size_t length, child_length;
	grub_uint16_t channel;
	grub_uint32_t i;
	char generated[HIK_NAME_MAX];

	data = hik_mount (file->device->disk);
	if (!data)
		return grub_errno;
	normalized = hik_normalize (name, &length);
	if (!hik_parse_channel (normalized, length, &channel, &child, &child_length) || child_length == 0)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", name);
		goto fail;
	}

	for (i = 0; i < data->num_entries; i++)
	{
		if (data->entries[i].channel != channel)
			continue;
		hik_format_name (&data->entries[i], generated, sizeof (generated));
		if (grub_strlen (generated) == child_length
			&& grub_strncasecmp (generated, child, child_length) == 0)
			break;
	}
	if (i == data->num_entries)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", name);
		goto fail;
	}

	ctx = grub_malloc (sizeof (*ctx));
	if (!ctx)
		goto fail;
	ctx->data = data;
	ctx->index = i;
	file->data = ctx;
	file->size = data->entries[i].size;
	grub_errno = GRUB_ERR_NONE;
	return GRUB_ERR_NONE;

fail:
	grub_free (ctx);
	hik_free_data (data);
	return grub_errno;
}

static grub_ssize_t
grub_hikvision_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct hik_file *ctx = file->data;
	const struct hik_entry *entry = &ctx->data->entries[ctx->index];
	grub_uint64_t available;

	ctx->data->disk = file->device->disk;
	if (file->offset >= entry->size)
		return 0;
	available = entry->size - file->offset;
	if (len > available)
		len = (grub_size_t) available;
	if (len && hik_read (ctx->data, entry->data_offset + file->offset, len, buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_hikvision_close (grub_file_t file)
{
	struct hik_file *ctx = file->data;

	if (ctx)
	{
		hik_free_data (ctx->data);
		grub_free (ctx);
		file->data = NULL;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_hikvision_label (grub_device_t device, char **label)
{
	struct hik_data *data;

	*label = NULL;
	data = hik_mount (device->disk);
	if (!data)
		return grub_errno;
	*label = grub_strdup ("HIKVISION DVR");
	hik_free_data (data);
	return grub_errno;
}

static grub_err_t
grub_hikvision_mtime (grub_device_t device, grub_int64_t *timebuf)
{
	struct hik_data *data;

	*timebuf = 0;
	data = hik_mount (device->disk);
	if (!data)
		return grub_errno;
	if (hik_valid_timestamp (data->master.init_time))
		*timebuf = data->master.init_time;
	hik_free_data (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_hikvision_fs =
{
	.name = "hikvision",
	.fs_dir = grub_hikvision_dir,
	.fs_open = grub_hikvision_open,
	.fs_read = grub_hikvision_read,
	.fs_close = grub_hikvision_close,
	.fs_label = grub_hikvision_label,
	.fs_mtime = grub_hikvision_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (hikvision)
{
	grub_hikvision_fs.mod = mod;
	grub_fs_register (&grub_hikvision_fs);
}

GRUB_MOD_FINI (hikvision)
{
	grub_fs_unregister (&grub_hikvision_fs);
}
