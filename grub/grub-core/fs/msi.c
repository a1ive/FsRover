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
#include <grub/charset.h>
#include <grub/dl.h>
#include <grub/cab.h>

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define CFB_FREE		0xFFFFFFFFU
#define CFB_END			0xFFFFFFFEU
#define CFB_FAT			0xFFFFFFFDU
#define CFB_DIFAT		0xFFFFFFFCU
#define CFB_NOSTREAM		0xFFFFFFFFU

#define CFB_TYPE_EMPTY		0
#define CFB_TYPE_STORAGE	1
#define CFB_TYPE_STREAM		2
#define CFB_TYPE_ROOT		5

#define CFB_MINI_SHIFT		6
#define CFB_MINI_CUTOFF		4096
#define CFB_MAX_DIRENTS		(1U << 20)
#define CFB_MAX_CHAIN		(1U << 24)
#define MSI_MAX_TABLE_SIZE	(64U << 20)
#define MSI_SEEN_BUCKETS	256

static const grub_uint8_t cfb_signature[8] =
{
	0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
};

static const grub_uint8_t msi_database_clsid[16] =
{
	0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

static const char msi_name_chars[] =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

struct cfb_dirent
{
	char *name;
	grub_uint32_t left;
	grub_uint32_t right;
	grub_uint32_t child;
	grub_uint32_t start;
	grub_uint64_t size;
	grub_uint64_t mtime;
	grub_uint8_t type;
};

struct grub_msi_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	grub_uint32_t num_sectors;
	unsigned sector_shift;
	grub_uint32_t *fat;
	grub_uint32_t fat_count;
	grub_uint32_t *mini_fat;
	grub_uint32_t mini_fat_count;
	grub_uint32_t *root_chain;
	grub_uint32_t root_chain_count;
	struct cfb_dirent *dirents;
	grub_uint32_t dirent_count;

	char **strings;
	grub_uint32_t string_count;
	unsigned string_ref_size;

	struct msi_directory *directories;
	unsigned num_directories;
	struct msi_component *components;
	unsigned num_components;
	struct msi_file_ent *files;
	unsigned num_files;
	struct msi_media *media;
	unsigned num_media;
};

struct cfb_stream
{
	struct grub_msi_data *data;
	grub_uint32_t *chain;
	grub_uint32_t chain_count;
	grub_uint64_t size;
	unsigned unit_shift;
	unsigned mini:1;
};

struct msi_directory
{
	char *id;
	char *parent;
	char *name;
	char *path;
	unsigned resolving:1;
};

struct msi_component
{
	char *id;
	char *directory;
	char *path;
};

struct msi_file_ent
{
	char *id;
	char *path;
	grub_uint32_t size;
	grub_uint32_t sequence;
};

struct msi_media
{
	char *cabinet;
	grub_uint32_t last_sequence;
	int stream_index;
};

struct msi_open_file
{
	struct grub_msi_data *data;
	struct cfb_stream cabinet_stream;
	struct grub_cab_file *cabinet_file;
};

struct msi_table
{
	grub_uint8_t *data;
	grub_uint32_t size;
	grub_uint32_t rows;
	unsigned columns;
	unsigned widths[8];
	grub_uint32_t offsets[8];
};

static grub_uint16_t
msi_get16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) (p[0] | ((grub_uint16_t) p[1] << 8));
}

static grub_uint32_t
msi_get24 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8) | ((grub_uint32_t) p[2] << 16);
}

static grub_uint32_t
msi_get32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8) | ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

static grub_uint64_t
msi_get64 (const grub_uint8_t *p)
{
	return (grub_uint64_t) msi_get32 (p) | ((grub_uint64_t) msi_get32 (p + 4) << 32);
}

static void
cfb_stream_close (struct cfb_stream *stream)
{
	grub_free (stream->chain);
	grub_memset (stream, 0, sizeof (*stream));
}

static void
msi_table_free (struct msi_table *table)
{
	grub_free (table->data);
	grub_memset (table, 0, sizeof (*table));
}

static void
grub_msi_free (struct grub_msi_data *data)
{
	unsigned i;

	if (!data)
		return;
	if (data->dirents)
		for (i = 0; i < data->dirent_count; i++)
			grub_free (data->dirents[i].name);
	if (data->strings)
		for (i = 0; i < data->string_count; i++)
			grub_free (data->strings[i]);
	if (data->directories)
		for (i = 0; i < data->num_directories; i++)
		{
			grub_free (data->directories[i].id);
			grub_free (data->directories[i].parent);
			grub_free (data->directories[i].name);
			grub_free (data->directories[i].path);
		}
	if (data->components)
		for (i = 0; i < data->num_components; i++)
		{
			grub_free (data->components[i].id);
			grub_free (data->components[i].directory);
			grub_free (data->components[i].path);
		}
	if (data->files)
		for (i = 0; i < data->num_files; i++)
		{
			grub_free (data->files[i].id);
			grub_free (data->files[i].path);
		}
	if (data->media)
		for (i = 0; i < data->num_media; i++)
			grub_free (data->media[i].cabinet);
	grub_free (data->fat);
	grub_free (data->mini_fat);
	grub_free (data->root_chain);
	grub_free (data->dirents);
	grub_free (data->strings);
	grub_free (data->directories);
	grub_free (data->components);
	grub_free (data->files);
	grub_free (data->media);
	grub_free (data);
}

static grub_err_t
cfb_read_sector (struct grub_msi_data *data, grub_uint32_t sid, void *buffer)
{
	grub_uint64_t offset;
	grub_size_t size = (grub_size_t) 1 << data->sector_shift;

	if (sid >= data->num_sectors)
		return grub_error (GRUB_ERR_BAD_FS, "CFB sector out of range");
	offset = ((grub_uint64_t) sid + 1) << data->sector_shift;
	if (offset > data->disk_size || size > data->disk_size - offset)
		return grub_error (GRUB_ERR_BAD_FS, "truncated CFB sector");
	return grub_disk_read (data->disk, 0, offset, size, buffer);
}

static grub_err_t
cfb_build_chain (const grub_uint32_t *table, grub_uint32_t table_count,
	grub_uint32_t sid_limit, grub_uint32_t start,
	grub_uint32_t expected, grub_uint32_t **chain_out,
	grub_uint32_t *count_out)
{
	grub_uint8_t *seen = 0;
	grub_uint32_t *chain = 0;
	grub_uint32_t count = 0, capacity = expected;
	grub_uint32_t sid = start;

	*chain_out = 0;
	*count_out = 0;
	if (expected > CFB_MAX_CHAIN || table_count > CFB_MAX_CHAIN)
		return grub_error (GRUB_ERR_BAD_FS, "CFB chain is too large");
	if (expected == 0 && start == CFB_END)
		return GRUB_ERR_NONE;
	if (!table || table_count == 0)
		return grub_error (GRUB_ERR_BAD_FS, "CFB allocation table is missing");
	if (capacity == 0)
		capacity = 16;
	chain = grub_malloc ((grub_size_t) capacity * sizeof (*chain));
	seen = grub_zalloc (table_count);
	if (!chain || !seen)
		goto fail;

	while (sid != CFB_END)
	{
		grub_uint32_t *grown;

		if (sid >= table_count || sid >= sid_limit || seen[sid])
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid CFB sector chain");
			goto fail;
		}
		if (expected != 0 && count >= expected)
		{
			grub_error (GRUB_ERR_BAD_FS, "overlong CFB sector chain");
			goto fail;
		}
		if (count == capacity)
		{
			if (capacity >= CFB_MAX_CHAIN / 2)
			{
				grub_error (GRUB_ERR_BAD_FS, "CFB chain is too large");
				goto fail;
			}
			capacity *= 2;
			grown = grub_realloc (chain,
				(grub_size_t) capacity * sizeof (*chain));
			if (!grown)
				goto fail;
			chain = grown;
		}
		seen[sid] = 1;
		chain[count++] = sid;
		sid = table[sid];
	}
	if (expected != 0 && count != expected)
	{
		grub_error (GRUB_ERR_BAD_FS, "short CFB sector chain");
		goto fail;
	}

	grub_free (seen);
	*chain_out = chain;
	*count_out = count;
	return GRUB_ERR_NONE;

fail:
	grub_free (seen);
	grub_free (chain);
	return grub_errno;
}

static char *
cfb_decode_name (const grub_uint8_t *raw, unsigned units)
{
	grub_uint16_t expanded[64];
	grub_uint8_t utf8[64 * GRUB_MAX_UTF8_PER_UTF16 + 1];
	grub_uint8_t *end;
	unsigned i, n = 0;

	for (i = 0; i < units; i++)
	{
		grub_uint16_t c = msi_get16 (raw + i * 2);

		if (c == 0x4840)
			expanded[n++] = '!';
		else if (c >= 0x3800 && c < 0x4800)
		{
			unsigned v = c - 0x3800;

			expanded[n++] = (grub_uint8_t) msi_name_chars[v & 0x3F];
			expanded[n++] = (grub_uint8_t) msi_name_chars[v >> 6];
		}
		else if (c >= 0x4800 && c < 0x4840)
			expanded[n++] = (grub_uint8_t) msi_name_chars[c - 0x4800];
		else
			expanded[n++] = c;
	}
	end = grub_utf16_to_utf8 (utf8, expanded, n);
	*end = '\0';
	return grub_strdup ((char *) utf8);
}

static grub_err_t
cfb_walk_tree (struct grub_msi_data *data, grub_uint32_t index, grub_uint8_t *state, unsigned depth)
{
	struct cfb_dirent *ent;

	if (index == CFB_NOSTREAM)
		return GRUB_ERR_NONE;
	if (depth > 256 || index >= data->dirent_count
		|| data->dirents[index].type == CFB_TYPE_EMPTY || state[index])
		return grub_error (GRUB_ERR_BAD_FS, "invalid CFB directory tree");
	ent = &data->dirents[index];
	state[index] = 1;
	if (cfb_walk_tree (data, ent->left, state, depth + 1))
		return grub_errno;
	if (ent->type == CFB_TYPE_STORAGE)
	{
		if (cfb_walk_tree (data, ent->child, state, depth + 1))
			return grub_errno;
	}
	else if (ent->child != CFB_NOSTREAM)
		return grub_error (GRUB_ERR_BAD_FS, "invalid CFB stream child");
	if (cfb_walk_tree (data, ent->right, state, depth + 1))
		return grub_errno;
	state[index] = 2;
	return GRUB_ERR_NONE;
}

static int
cfb_find_stream (const struct grub_msi_data *data, const char *name)
{
	grub_uint32_t i;

	for (i = 1; i < data->dirent_count; i++)
		if (data->dirents[i].type == CFB_TYPE_STREAM
			&& data->dirents[i].name
			&& grub_strcasecmp (data->dirents[i].name, name) == 0)
			return (int) i;
	return -1;
}

static grub_err_t
cfb_stream_open (struct grub_msi_data *data, unsigned index,
		 struct cfb_stream *stream)
{
	struct cfb_dirent *ent;
	grub_uint64_t count64;
	grub_uint32_t count;

	grub_memset (stream, 0, sizeof (*stream));
	if (index >= data->dirent_count
		|| data->dirents[index].type != CFB_TYPE_STREAM)
		return grub_error (GRUB_ERR_BAD_FS, "invalid CFB stream");
	ent = &data->dirents[index];
	stream->data = data;
	stream->size = ent->size;
	stream->mini = ent->size < CFB_MINI_CUTOFF;
	stream->unit_shift = stream->mini ? CFB_MINI_SHIFT : data->sector_shift;
	if (ent->size > (grub_uint64_t) -1 - (((grub_uint64_t) 1 << stream->unit_shift) - 1))
		return grub_error (GRUB_ERR_BAD_FS, "CFB stream is too large");
	count64 = (ent->size + (((grub_uint64_t) 1 << stream->unit_shift) - 1)) >> stream->unit_shift;
	if (count64 > CFB_MAX_CHAIN)
		return grub_error (GRUB_ERR_BAD_FS, "CFB stream is too large");
	count = (grub_uint32_t) count64;
	return cfb_build_chain (stream->mini ? data->mini_fat : data->fat,
		stream->mini ? data->mini_fat_count : data->fat_count,
		stream->mini ? data->mini_fat_count : data->num_sectors,
		ent->start, count, &stream->chain, &stream->chain_count);
}

static grub_err_t
cfb_stream_read (struct cfb_stream *stream, grub_uint64_t offset, grub_size_t size, void *buffer)
{
	struct grub_msi_data *data = stream->data;
	grub_uint8_t *out = buffer;
	grub_uint64_t unit_size = (grub_uint64_t) 1 << stream->unit_shift;

	if (offset > stream->size || size > stream->size - offset)
		return grub_error (GRUB_ERR_BAD_FS, "CFB stream read out of range");
	while (size != 0)
	{
		grub_uint64_t logical_unit = offset >> stream->unit_shift;
		grub_size_t in_unit = (grub_size_t) (offset & (unit_size - 1));
		grub_size_t chunk = (grub_size_t) unit_size - in_unit;
		grub_uint32_t sid;
		grub_uint64_t physical;

		if (logical_unit >= stream->chain_count)
			return grub_error (GRUB_ERR_BAD_FS, "short CFB stream chain");
		if (chunk > size)
			chunk = size;
		if (!stream->mini)
		{
			sid = stream->chain[logical_unit];
			physical = ((grub_uint64_t) sid + 1) << data->sector_shift;
			physical += in_unit;
		}
		else
		{
			grub_uint64_t mini_offset;
			grub_uint64_t root_unit;

			mini_offset = (grub_uint64_t) stream->chain[logical_unit]
				      << CFB_MINI_SHIFT;
			root_unit = mini_offset >> data->sector_shift;
			if (root_unit >= data->root_chain_count)
				return grub_error (GRUB_ERR_BAD_FS, "CFB mini stream out of range");
			sid = data->root_chain[root_unit];
			physical = ((grub_uint64_t) sid + 1) << data->sector_shift;
			physical += mini_offset & (((grub_uint64_t) 1 << data->sector_shift) - 1);
			physical += in_unit;
		}
		if (physical > data->disk_size || chunk > data->disk_size - physical)
			return grub_error (GRUB_ERR_BAD_FS, "truncated CFB stream");
		if (grub_disk_read (data->disk, 0, physical, chunk, out))
			return grub_errno;
		offset += chunk;
		out += chunk;
		size -= chunk;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
cfb_load_stream (struct grub_msi_data *data, unsigned index, grub_uint8_t **buffer, grub_uint32_t *size)
{
	struct cfb_stream stream;
	grub_uint8_t *out = 0;

	*buffer = 0;
	*size = 0;
	if (data->dirents[index].size > MSI_MAX_TABLE_SIZE)
		return grub_error (GRUB_ERR_BAD_FS, "MSI table stream is too large");
	if (cfb_stream_open (data, index, &stream))
		return grub_errno;
	if (stream.size != 0)
	{
		out = grub_malloc ((grub_size_t) stream.size);
		if (!out)
			goto fail;
		if (cfb_stream_read (&stream, 0, (grub_size_t) stream.size, out))
			goto fail;
	}
	*buffer = out;
	*size = (grub_uint32_t) stream.size;
	cfb_stream_close (&stream);
	return GRUB_ERR_NONE;

fail:
	grub_free (out);
	cfb_stream_close (&stream);
	return grub_errno;
}

static grub_err_t
cfb_parse (struct grub_msi_data *data)
{
	grub_uint8_t hdr[512];
	grub_uint8_t *sector = 0, *state = 0;
	grub_uint32_t *difat = 0, *dir_chain = 0, *mini_chain = 0;
	grub_uint32_t fat_sectors, difat_sectors, dir_sectors, mini_sectors;
	grub_uint32_t entries_per_sector, dir_chain_count = 0;
	grub_uint32_t mini_chain_count = 0, difat_count = 0;
	grub_uint32_t i, j, version;
	grub_uint64_t native_sectors;
	grub_size_t sector_size;

	if (grub_disk_read (data->disk, 0, 0, sizeof (hdr), hdr))
		goto fail;
	if (grub_memcmp (hdr, cfb_signature, sizeof (cfb_signature)) != 0)
		goto not_msi;
	version = msi_get16 (hdr + 0x1A);
	data->sector_shift = msi_get16 (hdr + 0x1E);
	if (msi_get16 (hdr + 0x18) != 0x3E
		|| (version != 3 && version != 4)
		|| msi_get16 (hdr + 0x1C) != 0xFFFE
		|| data->sector_shift != version * 3
		|| msi_get16 (hdr + 0x20) != CFB_MINI_SHIFT
		|| msi_get16 (hdr + 0x22) != 0 || msi_get32 (hdr + 0x24) != 0
		|| msi_get32 (hdr + 0x38) != CFB_MINI_CUTOFF)
		goto bad_cfb;
	dir_sectors = msi_get32 (hdr + 0x28);
	if ((version == 3 && dir_sectors != 0) || (version == 4 && dir_sectors == 0))
		goto bad_cfb;

	native_sectors = grub_disk_native_sectors (data->disk);
	if (native_sectors == GRUB_DISK_SIZE_UNKNOWN
		|| native_sectors > (GRUB_DISK_SIZE_UNKNOWN >> GRUB_DISK_SECTOR_BITS))
		goto bad_cfb;
	data->disk_size = native_sectors << GRUB_DISK_SECTOR_BITS;
	sector_size = (grub_size_t) 1 << data->sector_shift;
	if (data->disk_size < sector_size)
		goto bad_cfb;
	if ((data->disk_size >> data->sector_shift) - 1 > 0xFFFFFFFAU)
		goto bad_cfb;
	data->num_sectors = (grub_uint32_t)
		((data->disk_size >> data->sector_shift) - 1);
	entries_per_sector = (grub_uint32_t) sector_size / 4;
	fat_sectors = msi_get32 (hdr + 0x2C);
	difat_sectors = msi_get32 (hdr + 0x48);
	mini_sectors = msi_get32 (hdr + 0x40);
	if (fat_sectors == 0 || fat_sectors > data->num_sectors
		|| difat_sectors > data->num_sectors
		|| mini_sectors > data->num_sectors
		|| fat_sectors > CFB_MAX_CHAIN / entries_per_sector)
		goto bad_cfb;

	sector = grub_malloc (sector_size);
	difat = grub_malloc ((grub_size_t) fat_sectors * sizeof (*difat));
	if (!sector || !difat)
		goto fail;
	for (i = 0; i < 109 && difat_count < fat_sectors; i++)
	{
		grub_uint32_t sid = msi_get32 (hdr + 0x4C + i * 4);

		if (sid == CFB_FREE)
			break;
		if (sid >= data->num_sectors)
			goto bad_cfb;
		difat[difat_count++] = sid;
	}
	if (difat_count < fat_sectors)
	{
		grub_uint8_t *seen = grub_zalloc (data->num_sectors);
		grub_uint32_t sid = msi_get32 (hdr + 0x44);

		if (!seen)
			goto fail;
		for (i = 0; i < difat_sectors; i++)
		{
			if (sid >= data->num_sectors || seen[sid] || cfb_read_sector (data, sid, sector))
			{
				grub_free (seen);
				goto bad_cfb;
			}
			seen[sid] = 1;
			for (j = 0; j + 1 < entries_per_sector && difat_count < fat_sectors; j++)
			{
				grub_uint32_t fat_sid = msi_get32 (sector + j * 4);

				if (fat_sid >= data->num_sectors)
				{
					grub_free (seen);
					goto bad_cfb;
				}
				difat[difat_count++] = fat_sid;
			}
			sid = msi_get32 (sector + (entries_per_sector - 1) * 4);
		}
		grub_free (seen);
		if (sid != CFB_END || difat_count != fat_sectors)
			goto bad_cfb;
	}
	else if (difat_sectors != 0)
		goto bad_cfb;

	data->fat_count = fat_sectors * entries_per_sector;
	data->fat = grub_malloc ((grub_size_t) data->fat_count * sizeof (*data->fat));
	if (!data->fat)
		goto fail;
	for (i = 0; i < fat_sectors; i++)
	{
		if (cfb_read_sector (data, difat[i], sector))
			goto fail;
		for (j = 0; j < entries_per_sector; j++)
			data->fat[i * entries_per_sector + j]
				= msi_get32 (sector + j * 4);
	}
	for (i = 0; i < fat_sectors; i++)
		if (data->fat[difat[i]] != CFB_FAT)
			goto bad_cfb;

	if (mini_sectors != 0)
	{
		if (cfb_build_chain (data->fat, data->fat_count,
			data->num_sectors, msi_get32 (hdr + 0x3C), mini_sectors,
			&mini_chain, &mini_chain_count))
			goto fail;
		data->mini_fat_count = mini_sectors * entries_per_sector;
		data->mini_fat = grub_malloc ((grub_size_t) data->mini_fat_count * sizeof (*data->mini_fat));
		if (!data->mini_fat)
			goto fail;
		for (i = 0; i < mini_chain_count; i++)
		{
			if (cfb_read_sector (data, mini_chain[i], sector))
				goto fail;
			for (j = 0; j < entries_per_sector; j++)
				data->mini_fat[i * entries_per_sector + j] = msi_get32 (sector + j * 4);
		}
	}
	else if (msi_get32 (hdr + 0x3C) != CFB_END
		 && msi_get32 (hdr + 0x3C) != CFB_FREE)
		goto bad_cfb;

	if (cfb_build_chain (data->fat, data->fat_count, data->num_sectors,
		msi_get32 (hdr + 0x30), version == 4 ? dir_sectors : 0,
		&dir_chain, &dir_chain_count))
		goto fail;
	if (dir_chain_count == 0 || dir_chain_count > CFB_MAX_DIRENTS / (sector_size / 128))
		goto bad_cfb;
	data->dirent_count = dir_chain_count * ((grub_uint32_t) sector_size / 128);
	data->dirents = grub_zalloc ((grub_size_t) data->dirent_count * sizeof (*data->dirents));
	if (!data->dirents)
		goto fail;
	for (i = 0; i < dir_chain_count; i++)
	{
		if (cfb_read_sector (data, dir_chain[i], sector))
			goto fail;
		for (j = 0; j < sector_size / 128; j++)
		{
			const grub_uint8_t *raw = sector + j * 128;
			struct cfb_dirent *ent = &data->dirents[
				i * (sector_size / 128) + j];
			grub_uint16_t name_size = msi_get16 (raw + 64);

			ent->type = raw[66];
			if (ent->type == CFB_TYPE_EMPTY)
				continue;
			if ((ent->type != CFB_TYPE_STORAGE && ent->type != CFB_TYPE_STREAM && ent->type != CFB_TYPE_ROOT)
				|| name_size < 2 || name_size > 64 || (name_size & 1)
				|| msi_get16 (raw + name_size - 2) != 0)
				goto bad_cfb;
			ent->name = cfb_decode_name (raw, name_size / 2 - 1);
			if (!ent->name)
				goto fail;
			ent->left = msi_get32 (raw + 68);
			ent->right = msi_get32 (raw + 72);
			ent->child = msi_get32 (raw + 76);
			ent->mtime = msi_get64 (raw + 108);
			ent->start = msi_get32 (raw + 116);
			ent->size = msi_get32 (raw + 120);
			if (version == 4)
				ent->size |= (grub_uint64_t) msi_get32 (raw + 124) << 32;
			else if (msi_get32 (raw + 124) != 0)
				goto bad_cfb;
		}
	}
	if (data->dirents[0].type != CFB_TYPE_ROOT
		|| grub_strcmp (data->dirents[0].name, "Root Entry") != 0
		|| data->dirents[0].left != CFB_NOSTREAM
		|| data->dirents[0].right != CFB_NOSTREAM)
		goto bad_cfb;
	/* The root entry CLSID identifies an MSI database, not an MSP/MST. */
	{
		grub_uint32_t root_sid = dir_chain[0];

		if (cfb_read_sector (data, root_sid, sector)
			|| grub_memcmp (sector + 80, msi_database_clsid, sizeof (msi_database_clsid)) != 0)
			goto not_msi;
	}
	state = grub_zalloc (data->dirent_count);
	if (!state)
		goto fail;
	state[0] = 2;
	if (cfb_walk_tree (data, data->dirents[0].child, state, 1))
		goto fail;
	for (i = 1; i < data->dirent_count; i++)
		if (data->dirents[i].type != CFB_TYPE_EMPTY && state[i] != 2)
			goto bad_cfb;

	{
		grub_uint64_t count64;

		if (data->dirents[0].size > (grub_uint64_t) -1 - (sector_size - 1))
			goto bad_cfb;
		count64 = (data->dirents[0].size + sector_size - 1) >> data->sector_shift;
		if (count64 > CFB_MAX_CHAIN)
			goto bad_cfb;
		if (cfb_build_chain (data->fat, data->fat_count,
			data->num_sectors, data->dirents[0].start,
			(grub_uint32_t) count64, &data->root_chain,
			&data->root_chain_count))
			goto fail;
	}

	grub_free (sector);
	grub_free (state);
	grub_free (difat);
	grub_free (dir_chain);
	grub_free (mini_chain);
	return GRUB_ERR_NONE;

not_msi:
	grub_error (GRUB_ERR_BAD_FS, "not an MSI database");
	goto fail;
bad_cfb:
	grub_error (GRUB_ERR_BAD_FS, "corrupt MSI compound file");
fail:
	grub_free (sector);
	grub_free (state);
	grub_free (difat);
	grub_free (dir_chain);
	grub_free (mini_chain);
	return grub_errno;
}

static const char *
msi_string (const struct grub_msi_data *data, grub_uint32_t id)
{
	if (id == 0)
		return "";
	if (id >= data->string_count)
		return 0;
	return data->strings[id];
}

static grub_err_t
msi_load_strings (struct grub_msi_data *data)
{
	grub_uint8_t *pool = 0, *bytes = 0;
	grub_uint32_t pool_size = 0, bytes_size = 0;
	grub_uint32_t count, i, n, offset = 0, codepage;
	int pool_index, data_index;

	pool_index = cfb_find_stream (data, "!_StringPool");
	data_index = cfb_find_stream (data, "!_StringData");
	if (pool_index < 0 || data_index < 0)
		return grub_error (GRUB_ERR_BAD_FS, "MSI string table is missing");
	if (cfb_load_stream (data, (unsigned) pool_index, &pool, &pool_size)
		|| cfb_load_stream (data, (unsigned) data_index, &bytes, &bytes_size))
		goto fail;
	if (pool_size < 4 || (pool_size & 3))
	{
		grub_error (GRUB_ERR_BAD_FS, "corrupt MSI string pool");
		goto fail;
	}
	codepage = msi_get32 (pool);
	data->string_ref_size = (codepage & 0x80000000U) ? 3 : 2;
	codepage &= 0x7FFFFFFFU;
	if (codepage == 0)
		codepage = 1252;
	count = pool_size / 4;
	data->strings = grub_zalloc ((grub_size_t) count * sizeof (*data->strings));
	if (!data->strings)
		goto fail;
	data->string_count = count;
	data->strings[0] = grub_strdup ("");
	if (!data->strings[0])
		goto fail;

	for (i = 1, n = 1; i < count; n++)
	{
		grub_uint32_t length = msi_get16 (pool + i * 4);
		grub_uint16_t refs = msi_get16 (pool + i * 4 + 2);
		grub_uint32_t k;

		if (n >= count)
		{
			grub_error (GRUB_ERR_BAD_FS, "corrupt MSI string pool");
			goto fail;
		}
		if (length == 0 && refs == 0)
		{
			i++;
			continue;
		}
		if (length == 0)
		{
			if (i + 1 >= count)
			{
				grub_error (GRUB_ERR_BAD_FS, "corrupt MSI long string");
				goto fail;
			}
			length = msi_get16 (pool + (i + 1) * 4) | ((grub_uint32_t) msi_get16 (pool + (i + 1) * 4 + 2) << 16);
			i += 2;
		}
		else
			i++;
		if (length > bytes_size - offset)
		{
			grub_error (GRUB_ERR_BAD_FS, "corrupt MSI string data");
			goto fail;
		}
		for (k = 0; k < length; k++)
			if (bytes[offset + k] == 0)
			{
				grub_error (GRUB_ERR_BAD_FS, "invalid MSI string");
				goto fail;
			}
		data->strings[n] = grub_fs_bytes_to_utf8 ((const char *) bytes + offset, length, codepage);
		if (!data->strings[n])
			goto fail;
		offset += length;
	}
	if (offset != bytes_size)
	{
		grub_error (GRUB_ERR_BAD_FS, "unused MSI string data");
		goto fail;
	}
	grub_free (pool);
	grub_free (bytes);
	return GRUB_ERR_NONE;

fail:
	grub_free (pool);
	grub_free (bytes);
	return grub_errno;
}

static grub_uint32_t
msi_table_value (const struct msi_table *table, grub_uint32_t row, unsigned column)
{
	const grub_uint8_t *p = table->data + table->offsets[column] + row * table->widths[column];

	switch (table->widths[column])
	{
	case 2:
		return msi_get16 (p);
	case 3:
		return msi_get24 (p);
	default:
		return msi_get32 (p);
	}
}

static grub_err_t
msi_table_load (struct grub_msi_data *data, const char *name,
	const int *types, unsigned columns, struct msi_table *table)
{
	char stream_name[64];
	grub_uint32_t row_size = 0, offset = 0;
	unsigned i;
	int index;

	grub_memset (table, 0, sizeof (*table));
	if (columns > 8 || grub_strlen (name) + 2 > sizeof (stream_name))
		return grub_error (GRUB_ERR_BAD_FS, "invalid MSI table schema");
	stream_name[0] = '!';
	grub_strcpy (stream_name + 1, name);
	index = cfb_find_stream (data, stream_name);
	if (index < 0)
		return GRUB_ERR_NONE;
	table->columns = columns;
	for (i = 0; i < columns; i++)
	{
		table->widths[i] = types[i] == 0 ? data->string_ref_size : (unsigned) types[i];
		row_size += table->widths[i];
	}
	if (cfb_load_stream (data, (unsigned) index, &table->data, &table->size))
		return grub_errno;
	if (row_size == 0 || table->size % row_size != 0)
	{
		msi_table_free (table);
		return grub_error (GRUB_ERR_BAD_FS, "corrupt MSI table `%s'", name);
	}
	table->rows = table->size / row_size;
	for (i = 0; i < columns; i++)
	{
		table->offsets[i] = offset;
		offset += table->rows * table->widths[i];
	}
	return GRUB_ERR_NONE;
}

static char *
msi_dup_field (const struct grub_msi_data *data,
	const struct msi_table *table, grub_uint32_t row, unsigned column)
{
	const char *value = msi_string (data, msi_table_value (table, row, column));

	if (!value)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid MSI string reference");
		return 0;
	}
	return grub_strdup (value);
}

static char *
msi_target_name (const char *value)
{
	const char *colon = grub_strchr (value, ':');
	const char *bar;
	grub_size_t length = colon ? (grub_size_t) (colon - value) : grub_strlen (value);
	char *target = grub_strndup (value, length);
	char *long_name;

	if (!target)
		return 0;
	bar = grub_strchr (target, '|');
	if (!bar)
		return target;
	long_name = grub_strdup (bar + 1);
	grub_free (target);
	return long_name;
}

static int
msi_safe_component (const char *name)
{
	return *name != '\0' && grub_strcmp (name, ".") != 0
		&& grub_strcmp (name, "..") != 0
		&& !grub_strchr (name, '/') && !grub_strchr (name, '\\');
}

static char *
msi_join_path (const char *parent, const char *name)
{
	grub_size_t parent_len = grub_strlen (parent);
	grub_size_t name_len = grub_strlen (name);
	char *path;

	if (name_len == 0)
		return grub_strdup (parent);
	if (!msi_safe_component (name))
	{
		grub_error (GRUB_ERR_BAD_FS, "unsafe MSI path component");
		return 0;
	}
	if (parent_len == 0)
		return grub_strdup (name);
	if (parent_len > (grub_size_t) -1 - name_len - 2)
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "MSI path is too long");
		return 0;
	}
	path = grub_malloc (parent_len + name_len + 2);
	if (!path)
		return 0;
	grub_memcpy (path, parent, parent_len);
	path[parent_len] = '/';
	grub_memcpy (path + parent_len + 1, name, name_len + 1);
	return path;
}

static int
msi_find_directory (const struct grub_msi_data *data, const char *id)
{
	unsigned i;

	for (i = 0; i < data->num_directories; i++)
		if (grub_strcmp (data->directories[i].id, id) == 0)
			return (int) i;
	return -1;
}

static char *
msi_resolve_directory (struct grub_msi_data *data, unsigned index, unsigned depth)
{
	struct msi_directory *dir = &data->directories[index];
	char *name = 0;
	const char *parent_path = "";

	if (dir->path)
		return dir->path;
	if (depth > 128 || dir->resolving)
	{
		grub_error (GRUB_ERR_BAD_FS, "cyclic MSI directory table");
		return 0;
	}
	dir->resolving = 1;
	if (dir->parent[0] != '\0')
	{
		int parent = msi_find_directory (data, dir->parent);

		if (parent < 0)
		{
			grub_error (GRUB_ERR_BAD_FS, "missing MSI parent directory");
			goto fail;
		}
		parent_path = msi_resolve_directory (data, (unsigned) parent,
			depth + 1);
		if (!parent_path)
			goto fail;
	}
	if (grub_strcmp (dir->id, "ProgramFilesFolder") == 0)
		name = grub_strdup ("Program Files");
	else
		name = msi_target_name (dir->name);
	if (!name)
		goto fail;
	if (grub_strcmp (name, ".") == 0
		|| grub_strcmp (name, "SourceDir") == 0)
		name[0] = '\0';
	dir->path = msi_join_path (parent_path, name);
	grub_free (name);
	dir->resolving = 0;
	return dir->path;

fail:
	grub_free (name);
	dir->resolving = 0;
	return 0;
}

static int
msi_find_component (const struct grub_msi_data *data, const char *id)
{
	unsigned i;

	for (i = 0; i < data->num_components; i++)
		if (grub_strcmp (data->components[i].id, id) == 0)
			return (int) i;
	return -1;
}

static grub_err_t
msi_load_tables (struct grub_msi_data *data)
{
	static const int directory_types[] = { 0, 0, 0 };
	static const int component_types[] = { 0, 0, 0, 2, 0, 0 };
	static const int file_types[] = { 0, 0, 0, 4, 0, 0, 2, 4 };
	static const int media_types[] = { 2, 4, 0, 0, 0, 0 };
	struct msi_table directories, components, files, media;
	grub_uint32_t i;

	grub_memset (&directories, 0, sizeof (directories));
	grub_memset (&components, 0, sizeof (components));
	grub_memset (&files, 0, sizeof (files));
	grub_memset (&media, 0, sizeof (media));
	if (msi_table_load (data, "Directory", directory_types, 3, &directories)
		|| msi_table_load (data, "Component", component_types, 6, &components)
		|| msi_table_load (data, "File", file_types, 8, &files)
		|| msi_table_load (data, "Media", media_types, 6, &media))
		goto fail;

	data->num_directories = directories.rows;
	data->directories = grub_zalloc ((grub_size_t) directories.rows * sizeof (*data->directories));
	data->num_components = components.rows;
	data->components = grub_zalloc ((grub_size_t) components.rows * sizeof (*data->components));
	data->num_files = files.rows;
	data->files = grub_zalloc ((grub_size_t) files.rows * sizeof (*data->files));
	data->num_media = media.rows;
	data->media = grub_zalloc ((grub_size_t) media.rows * sizeof (*data->media));
	if ((directories.rows && !data->directories)
		|| (components.rows && !data->components)
		|| (files.rows && !data->files) || (media.rows && !data->media))
		goto fail;

	for (i = 0; i < directories.rows; i++)
	{
		data->directories[i].id = msi_dup_field (data, &directories, i, 0);
		data->directories[i].parent = msi_dup_field (data, &directories, i, 1);
		data->directories[i].name = msi_dup_field (data, &directories, i, 2);
		if (!data->directories[i].id || !data->directories[i].parent
			|| !data->directories[i].name
			|| data->directories[i].id[0] == '\0')
			goto corrupt;
	}
	for (i = 0; i < directories.rows; i++)
		if (!msi_resolve_directory (data, i, 0))
			goto fail;

	for (i = 0; i < components.rows; i++)
	{
		int dir_index;

		data->components[i].id = msi_dup_field (data, &components, i, 0);
		data->components[i].directory = msi_dup_field (data, &components, i, 2);
		if (!data->components[i].id || !data->components[i].directory
			|| data->components[i].id[0] == '\0')
			goto corrupt;
		dir_index = msi_find_directory (data, data->components[i].directory);
		if (dir_index < 0)
			goto corrupt;
		data->components[i].path = grub_strdup (data->directories[dir_index].path);
		if (!data->components[i].path)
			goto fail;
	}

	for (i = 0; i < files.rows; i++)
	{
		char *component = 0, *stored_name = 0, *name = 0;
		int component_index;
		grub_uint32_t raw_size, raw_sequence;

		data->files[i].id = msi_dup_field (data, &files, i, 0);
		component = msi_dup_field (data, &files, i, 1);
		stored_name = msi_dup_field (data, &files, i, 2);
		if (!data->files[i].id || !component || !stored_name || data->files[i].id[0] == '\0')
		{
			grub_free (component);
			grub_free (stored_name);
			goto corrupt;
		}
		component_index = msi_find_component (data, component);
		name = msi_target_name (stored_name);
		grub_free (component);
		grub_free (stored_name);
		if (component_index < 0 || !name)
		{
			grub_free (name);
			goto corrupt;
		}
		data->files[i].path = msi_join_path (data->components[component_index].path, name);
		grub_free (name);
		if (!data->files[i].path)
			goto fail;
		raw_size = msi_table_value (&files, i, 3);
		raw_sequence = msi_table_value (&files, i, 7);
		data->files[i].size = raw_size ^ 0x80000000U;
		data->files[i].sequence = raw_sequence ^ 0x80000000U;
		if ((data->files[i].size & 0x80000000U)
			|| (data->files[i].sequence & 0x80000000U)
			|| data->files[i].sequence == 0)
			goto corrupt;
	}

	for (i = 0; i < media.rows; i++)
	{
		grub_uint32_t raw_last = msi_table_value (&media, i, 1);

		data->media[i].cabinet = msi_dup_field (data, &media, i, 3);
		if (!data->media[i].cabinet)
			goto fail;
		data->media[i].last_sequence = raw_last ^ 0x80000000U;
		if (data->media[i].last_sequence & 0x80000000U)
			goto corrupt;
		data->media[i].stream_index = -1;
		if (data->media[i].cabinet[0] == '#' && data->media[i].cabinet[1] != '\0')
			data->media[i].stream_index = cfb_find_stream (data,data->media[i].cabinet + 1);
	}

	msi_table_free (&directories);
	msi_table_free (&components);
	msi_table_free (&files);
	msi_table_free (&media);
	return GRUB_ERR_NONE;

corrupt:
	grub_error (GRUB_ERR_BAD_FS, "corrupt MSI database tables");
fail:
	msi_table_free (&directories);
	msi_table_free (&components);
	msi_table_free (&files);
	msi_table_free (&media);
	return grub_errno;
}

static struct grub_msi_data *
grub_msi_mount (grub_disk_t disk)
{
	struct grub_msi_data *data = grub_zalloc (sizeof (*data));

	if (!data)
		return 0;
	data->disk = disk;
	if (cfb_parse (data) || msi_load_strings (data) || msi_load_tables (data))
	{
		grub_msi_free (data);
		return 0;
	}
	return data;
}

static const char *
msi_norm_path (const char *path, grub_size_t *length)
{
	grub_size_t n;

	while (*path == '/')
		path++;
	n = grub_strlen (path);
	while (n != 0 && path[n - 1] == '/')
		n--;
	*length = n;
	return path;
}

static int
msi_name_in_dir (const char *name, const char *dir, grub_size_t dir_length,
		 const char **child, grub_size_t *child_length, int *is_dir)
{
	const char *rest, *slash;

	if (dir_length != 0)
	{
		if (grub_strncmp (name, dir, dir_length) != 0 || name[dir_length] != '/')
			return 0;
		rest = name + dir_length + 1;
	}
	else
		rest = name;
	if (*rest == '\0')
		return 0;
	slash = grub_strchr (rest, '/');
	if (slash)
	{
		*child = rest;
		*child_length = (grub_size_t) (slash - rest);
		*is_dir = 1;
	}
	else
	{
		*child = rest;
		*child_length = grub_strlen (rest);
		*is_dir = 0;
	}
	return *child_length != 0;
}

struct msi_seen
{
	struct msi_seen *next;
	char *name;
};

static grub_uint32_t
msi_hash_name (const char *name)
{
	grub_uint32_t hash = 5381;

	while (*name)
		hash = hash * 33 + (grub_uint8_t) *name++;
	return hash & (MSI_SEEN_BUCKETS - 1);
}

static int
msi_seen_add (struct msi_seen **buckets, char *name)
{
	grub_uint32_t hash = msi_hash_name (name);
	struct msi_seen *entry;

	for (entry = buckets[hash]; entry; entry = entry->next)
		if (grub_strcmp (entry->name, name) == 0)
			return 1;
	entry = grub_malloc (sizeof (*entry));
	if (!entry)
		return -1;
	entry->name = name;
	entry->next = buckets[hash];
	buckets[hash] = entry;
	return 0;
}

static grub_err_t
grub_msi_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_msi_data *data;
	struct msi_seen **buckets = 0;
	const char *dir;
	grub_size_t dir_length;
	grub_err_t error = GRUB_ERR_NONE;
	unsigned i;
	int found;

	data = grub_msi_mount (device->disk);
	if (!data)
		return grub_errno;
	dir = msi_norm_path (path, &dir_length);
	found = dir_length == 0;
	buckets = grub_calloc (MSI_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		grub_msi_free (data);
		return grub_errno;
	}
	for (i = 0; i < data->num_files; i++)
	{
		const char *child;
		grub_size_t child_length;
		struct grub_dirhook_info info;
		char *name;
		int child_is_dir, duplicate;

		if (!msi_name_in_dir (data->files[i].path, dir, dir_length, &child, &child_length, &child_is_dir))
		{
			if (dir_length != 0 && grub_strcmp (data->files[i].path, dir) == 0)
				found = 1;
			continue;
		}
		found = 1;
		name = grub_strndup (child, child_length);
		if (!name)
		{
			error = grub_errno;
			goto out;
		}
		duplicate = msi_seen_add (buckets, name);
		if (duplicate)
		{
			grub_free (name);
			if (duplicate < 0)
			{
				error = grub_errno;
				goto out;
			}
			continue;
		}
		grub_memset (&info, 0, sizeof (info));
		info.dir = child_is_dir;
		info.inodeset = 1;
		info.inode = i;
		if (hook (name, &info, hook_data))
			goto out;
	}
	if (!found)
		error = grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);

out:
	for (i = 0; i < MSI_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct msi_seen *entry = buckets[i];

			buckets[i] = entry->next;
			grub_free (entry->name);
			grub_free (entry);
		}
	grub_free (buckets);
	grub_msi_free (data);
	return error;
}

static int
msi_find_file (const struct grub_msi_data *data, const char *name)
{
	const char *path;
	grub_size_t length;
	unsigned i;

	path = msi_norm_path (name, &length);
	for (i = 0; i < data->num_files; i++)
		if (grub_strlen (data->files[i].path) == length && grub_strncmp (data->files[i].path, path, length) == 0)
			return (int) i;
	return -1;
}

static int
msi_find_media (const struct grub_msi_data *data, grub_uint32_t sequence)
{
	grub_uint32_t best = 0xFFFFFFFFU;
	int index = -1;
	unsigned i;

	for (i = 0; i < data->num_media; i++)
		if (sequence <= data->media[i].last_sequence && data->media[i].last_sequence < best)
		{
			best = data->media[i].last_sequence;
			index = (int) i;
		}
	return index;
}

static grub_err_t
msi_cabinet_read (void *context, grub_uint64_t offset, grub_size_t size,
		  void *buffer)
{
	return cfb_stream_read ((struct cfb_stream *) context, offset, size, buffer);
}

static grub_err_t
grub_msi_open (struct grub_file *file, const char *name)
{
	struct grub_msi_data *data;
	struct msi_open_file *context = 0;
	struct grub_cab_data *cabinet = 0;
	struct msi_file_ent *entry;
	struct msi_media *media;
	unsigned i;
	int file_index, media_index, cab_index = -1;

	data = grub_msi_mount (file->device->disk);
	if (!data)
		return grub_errno;
	file_index = msi_find_file (data, name);
	if (file_index < 0)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", name);
		goto fail;
	}
	entry = &data->files[file_index];
	media_index = msi_find_media (data, entry->sequence);
	if (media_index < 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "MSI file has no media record");
		goto fail;
	}
	media = &data->media[media_index];
	if (media->cabinet[0] == '\0')
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "MSI file is not stored in a cabinet");
		goto fail;
	}
	if (media->cabinet[0] != '#')
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "MSI file uses an external cabinet");
		goto fail;
	}
	if (media->stream_index < 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "embedded MSI cabinet is missing");
		goto fail;
	}
	context = grub_zalloc (sizeof (*context));
	if (!context)
		goto fail;
	context->data = data;
	if (cfb_stream_open (data, (unsigned) media->stream_index,
		&context->cabinet_stream))
		goto fail;
	cabinet = grub_cab_mount_source (msi_cabinet_read,
		&context->cabinet_stream, context->cabinet_stream.size);
	if (!cabinet)
		goto fail;
	for (i = 0; i < grub_cab_item_count (cabinet); i++)
		if (!grub_cab_item_is_dir (cabinet, i)
			&& grub_cab_item_name (cabinet, i)
			&& grub_strcmp (grub_cab_item_name (cabinet, i), entry->id) == 0)
		{
			cab_index = (int) i;
			break;
		}
	if (cab_index < 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "MSI cabinet entry is missing");
		goto fail;
	}
	if (grub_cab_item_size (cabinet, (unsigned) cab_index) != entry->size)
	{
		grub_error (GRUB_ERR_BAD_FS, "MSI file size does not match cabinet");
		goto fail;
	}
	if (grub_cab_item_is_unsupported (cabinet, (unsigned) cab_index))
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "MSI cabinet spans multiple volumes");
		goto fail;
	}
	context->cabinet_file = grub_cab_file_open (cabinet, (unsigned) cab_index);
	cabinet = 0;
	if (!context->cabinet_file)
		goto fail;
	file->data = context;
	file->size = entry->size;
	file->not_easily_seekable = 1;
	return GRUB_ERR_NONE;

fail:
	grub_cab_free (cabinet);
	if (context)
	{
		grub_cab_file_close (context->cabinet_file);
		cfb_stream_close (&context->cabinet_stream);
		grub_free (context);
	}
	grub_msi_free (data);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

static grub_ssize_t
grub_msi_read (grub_file_t file, char *buffer, grub_size_t size)
{
	struct msi_open_file *context = file->data;

	return grub_cab_file_read (context->cabinet_file, file->offset, buffer, size);
}

static grub_err_t
grub_msi_close (grub_file_t file)
{
	struct msi_open_file *context = file->data;

	grub_cab_file_close (context->cabinet_file);
	cfb_stream_close (&context->cabinet_stream);
	grub_msi_free (context->data);
	grub_free (context);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_msi_fs =
{
	.name = "msi",
	.fs_dir = grub_msi_dir,
	.fs_open = grub_msi_open,
	.fs_read = grub_msi_read,
	.fs_close = grub_msi_close,
	.fs_label = 0,
	.fs_mtime = 0,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (msi)
{
	grub_msi_fs.mod = mod;
	grub_fs_register (&grub_msi_fs);
}

GRUB_MOD_FINI (msi)
{
	grub_fs_unregister (&grub_msi_fs);
}
