/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Read-only fsarchiver archive filesystem.  This implements the
 *  FsArCh_002 stream described by ref/fsarchiver and exposes archived
 *  objects as a directory tree.  Data blocks are decompressed independently
 *  and their Fletcher-32 checksums are verified before use.  Blowfish
 *  encryption and split volumes are deliberately rejected.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/crypto.h>
#include <grub/deflate.h>

#include <minilzo.h>
#include <lz4.h>
#include <zstd.h>
#include <bzlib.h>
#include <xz.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define FSA_FORMAT		"FsArCh_002"
#define FSA_MAGIC_VOLH		"FsA0"
#define FSA_MAGIC_VOLF		"FsAE"
#define FSA_MAGIC_MAIN		"ArCh"
#define FSA_MAGIC_FSIN		"FsIn"
#define FSA_MAGIC_FSYB		"FsYs"
#define FSA_MAGIC_DIRS		"DiRs"
#define FSA_MAGIC_OBJT		"ObJt"
#define FSA_MAGIC_BLKH		"BlKh"
#define FSA_MAGIC_FILF		"FiLf"
#define FSA_MAGIC_DATF		"DaEn"

#define FSA_FSID_NULL		0xffff
#define FSA_HEADER_MAX		(16U << 20)
#define FSA_BLOCK_MAX		921600U
#define FSA_STORED_MAX		(16U << 20)
#define FSA_ITEMS_MAX		(1U << 20)
#define FSA_BLOCKS_MAX		(1U << 20)
#define FSA_PATH_MAX		32768U
#define FSA_MULTI_MAX		512U
#define FSA_SEEN_BUCKETS	512U

enum fsa_dico_type
{
	FSA_DICO_NULL = 0,
	FSA_DICO_U8,
	FSA_DICO_U16,
	FSA_DICO_U32,
	FSA_DICO_U64,
	FSA_DICO_DATA,
	FSA_DICO_STRING
};

enum fsa_archive_type
{
	FSA_ARCH_NULL = 0,
	FSA_ARCH_FILESYSTEMS,
	FSA_ARCH_DIRECTORIES
};

enum fsa_object_type
{
	FSA_OBJ_NULL = 0,
	FSA_OBJ_DIR,
	FSA_OBJ_SYMLINK,
	FSA_OBJ_HARDLINK,
	FSA_OBJ_CHARDEV,
	FSA_OBJ_BLOCKDEV,
	FSA_OBJ_FIFO,
	FSA_OBJ_SOCKET,
	FSA_OBJ_REGFILE,
	FSA_OBJ_REGFILE_MULTI
};

enum fsa_compression
{
	FSA_COMP_NULL = 0,
	FSA_COMP_NONE,
	FSA_COMP_LZO,
	FSA_COMP_GZIP,
	FSA_COMP_BZIP2,
	FSA_COMP_LZMA,
	FSA_COMP_LZ4,
	FSA_COMP_ZSTD
};

enum
{
	FSA_VOLUME_VOLNUM = 0,
	FSA_VOLUME_ARCHID,
	FSA_VOLUME_FORMAT,
	FSA_VOLUME_VERSION
};

enum
{
	FSA_VOLUME_FOOT_VOLNUM = 0,
	FSA_VOLUME_FOOT_ARCHID,
	FSA_VOLUME_FOOT_LAST
};

enum
{
	FSA_MAIN_NULL = 0,
	FSA_MAIN_FORMAT,
	FSA_MAIN_VERSION,
	FSA_MAIN_ARCHID,
	FSA_MAIN_CTIME,
	FSA_MAIN_LABEL,
	FSA_MAIN_TYPE,
	FSA_MAIN_FSCOUNT,
	FSA_MAIN_COMP,
	FSA_MAIN_LEVEL,
	FSA_MAIN_ENCRYPT
};

enum
{
	FSA_ITEM_NULL = 0,
	FSA_ITEM_ID,
	FSA_ITEM_PATH,
	FSA_ITEM_TYPE,
	FSA_ITEM_SYMLINK,
	FSA_ITEM_HARDLINK,
	FSA_ITEM_RDEV,
	FSA_ITEM_MODE,
	FSA_ITEM_SIZE,
	FSA_ITEM_UID,
	FSA_ITEM_GID,
	FSA_ITEM_ATIME,
	FSA_ITEM_MTIME,
	FSA_ITEM_MD5,
	FSA_ITEM_MULTI_COUNT,
	FSA_ITEM_MULTI_OFFSET
};

enum
{
	FSA_BLOCK_NULL = 0,
	FSA_BLOCK_REALSIZE,
	FSA_BLOCK_OFFSET,
	FSA_BLOCK_COMP,
	FSA_BLOCK_ENCRYPT,
	FSA_BLOCK_ARSIZE,
	FSA_BLOCK_COMPSIZE,
	FSA_BLOCK_CHECKSUM
};

enum
{
	FSA_FILE_FOOT_NULL = 0,
	FSA_FILE_FOOT_MD5
};

struct fsa_dico
{
	grub_uint8_t *data;
	grub_uint32_t size;
	grub_uint16_t count;
};

struct fsa_header
{
	char magic[5];
	grub_uint32_t archid;
	grub_uint16_t fsid;
	struct fsa_dico dico;
};

struct fsa_reader
{
	grub_disk_t disk;
	grub_uint64_t size;
	grub_uint64_t pos;
};

struct fsa_block
{
	grub_uint64_t data_pos;
	grub_uint64_t offset;
	grub_uint32_t real_size;
	grub_uint32_t ar_size;
	grub_uint32_t comp_size;
	grub_uint32_t checksum;
	grub_uint16_t comp;
	grub_uint16_t encrypt;
};

struct fsa_item
{
	char *name;
	char *link;
	grub_uint64_t size;
	grub_int64_t mtime;
	grub_uint32_t mode;
	grub_uint32_t type;
	grub_uint16_t fsid;
	grub_uint32_t multi_offset;
	grub_uint8_t md5[16];
	int has_md5;
	struct fsa_block *blocks;
	unsigned num_blocks;
	unsigned cap_blocks;
};

struct grub_fsa_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	grub_uint32_t archid;
	grub_uint32_t archive_type;
	grub_uint64_t fs_count;
	grub_int64_t ctime;
	char *label;
	struct fsa_item *items;
	unsigned num_items;
	unsigned cap_items;
};

struct grub_fsa_file
{
	struct grub_fsa_data *data;
	unsigned index;
	unsigned cache_index;
	grub_uint8_t *cache;
	grub_size_t cache_size;
	const gcry_md_spec_t *md5_desc;
	void *md5_ctx;
	grub_uint64_t md5_pos;
	int md5_active;
};

static grub_uint16_t
fsa_get16 (const void *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
fsa_get32 (const void *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
fsa_get64 (const void *p)
{
	return grub_le_to_cpu64 (grub_get_unaligned64 (p));
}

static grub_uint32_t
fsa_fletcher32 (const grub_uint8_t *data, grub_uint32_t len)
{
	grub_uint32_t sum1 = 0xffff;
	grub_uint32_t sum2 = 0xffff;

	while (len)
	{
		unsigned count = len > 360 ? 360 : len;
		unsigned left = count;

		len -= count;
		while (left--)
		{
			sum1 += *data++;
			sum2 += sum1;
		}
		sum1 = (sum1 & 0xffff) + (sum1 >> 16);
		sum2 = (sum2 & 0xffff) + (sum2 >> 16);
	}
	sum1 = (sum1 & 0xffff) + (sum1 >> 16);
	sum2 = (sum2 & 0xffff) + (sum2 >> 16);
	return (sum2 << 16) | sum1;
}

static int
fsa_read (struct fsa_reader *r, void *buf, grub_size_t len)
{
	if (r->pos > r->size || len > r->size - r->pos)
		return 0;
	if (len && grub_disk_read (r->disk, 0, r->pos, len, buf))
		return 0;
	r->pos += len;
	return 1;
}

static int
fsa_magic_valid (const char *magic)
{
	static const char *const magics[] =
	{
		FSA_MAGIC_VOLH, FSA_MAGIC_VOLF, FSA_MAGIC_MAIN,
		FSA_MAGIC_FSIN, FSA_MAGIC_FSYB, FSA_MAGIC_DIRS,
		FSA_MAGIC_OBJT, FSA_MAGIC_BLKH, FSA_MAGIC_FILF,
		FSA_MAGIC_DATF
	};
	unsigned i;

	for (i = 0; i < ARRAY_SIZE (magics); i++)
		if (grub_memcmp (magic, magics[i], 4) == 0)
			return 1;
	return 0;
}

static void
fsa_header_free (struct fsa_header *h)
{
	grub_free (h->dico.data);
	grub_memset (h, 0, sizeof (*h));
}

static int
fsa_read_header (struct fsa_reader *r, struct fsa_header *h)
{
	grub_uint8_t fixed[14];
	grub_uint32_t header_size;
	grub_uint32_t checksum;
	grub_uint32_t pos;
	unsigned i;

	grub_memset (h, 0, sizeof (*h));
	if (!fsa_read (r, fixed, sizeof (fixed)))
		return 0;
	grub_memcpy (h->magic, fixed, 4);
	if (!fsa_magic_valid (h->magic))
		return 0;
	h->archid = fsa_get32 (fixed + 4);
	h->fsid = fsa_get16 (fixed + 8);
	header_size = fsa_get32 (fixed + 10);
	if (header_size < 2 || header_size > FSA_HEADER_MAX
	    || header_size > r->size - r->pos)
		return 0;
	h->dico.data = grub_malloc (header_size);
	if (!h->dico.data)
		return 0;
	h->dico.size = header_size;
	if (!fsa_read (r, h->dico.data, header_size)
	    || !fsa_read (r, &checksum, sizeof (checksum)))
		goto fail;
	checksum = grub_le_to_cpu32 (checksum);
	if (fsa_fletcher32 (h->dico.data, header_size) != checksum)
		goto fail;
	h->dico.count = fsa_get16 (h->dico.data);
	pos = 2;
	for (i = 0; i < h->dico.count; i++)
	{
		grub_uint16_t size;

		if (pos > header_size || 6 > header_size - pos)
			goto fail;
		size = fsa_get16 (h->dico.data + pos + 4);
		pos += 6;
		if (size > header_size - pos)
			goto fail;
		pos += size;
	}
	if (pos != header_size)
		goto fail;
	return 1;

fail:
	fsa_header_free (h);
	return 0;
}

static const grub_uint8_t *
fsa_dico_get (const struct fsa_dico *d, grub_uint8_t section,
	     grub_uint16_t key, grub_uint8_t type, grub_uint16_t *size)
{
	grub_uint32_t pos = 2;
	unsigned i;

	for (i = 0; i < d->count; i++)
	{
		const grub_uint8_t item_type = d->data[pos];
		const grub_uint8_t item_section = d->data[pos + 1];
		const grub_uint16_t item_key = fsa_get16 (d->data + pos + 2);
		const grub_uint16_t item_size = fsa_get16 (d->data + pos + 4);

		pos += 6;
		if (item_section == section && item_key == key)
		{
			if (item_type != type)
				return 0;
			*size = item_size;
			return d->data + pos;
		}
		pos += item_size;
	}
	return 0;
}

static int
fsa_dico_u16 (const struct fsa_dico *d, grub_uint16_t key,
	      grub_uint16_t *value)
{
	grub_uint16_t size;
	const grub_uint8_t *p = fsa_dico_get (d, 0, key, FSA_DICO_U16, &size);

	if (!p || size != 2)
		return 0;
	*value = fsa_get16 (p);
	return 1;
}

static int
fsa_dico_u32 (const struct fsa_dico *d, grub_uint16_t key,
	      grub_uint32_t *value)
{
	grub_uint16_t size;
	const grub_uint8_t *p = fsa_dico_get (d, 0, key, FSA_DICO_U32, &size);

	if (!p || size != 4)
		return 0;
	*value = fsa_get32 (p);
	return 1;
}

static int
fsa_dico_u64 (const struct fsa_dico *d, grub_uint16_t key,
	      grub_uint64_t *value)
{
	grub_uint16_t size;
	const grub_uint8_t *p = fsa_dico_get (d, 0, key, FSA_DICO_U64, &size);

	if (!p || size != 8)
		return 0;
	*value = fsa_get64 (p);
	return 1;
}

static const char *
fsa_dico_string (const struct fsa_dico *d, grub_uint16_t key,
		 grub_uint16_t *size)
{
	const grub_uint8_t *p = fsa_dico_get (d, 0, key, FSA_DICO_STRING, size);

	if (!p || *size == 0 || p[*size - 1] != 0)
		return 0;
	return (const char *) p;
}

static const grub_uint8_t *
fsa_dico_data (const struct fsa_dico *d, grub_uint16_t key,
	       grub_uint16_t *size)
{
	return fsa_dico_get (d, 0, key, FSA_DICO_DATA, size);
}

static void
fsa_free_data (struct grub_fsa_data *data)
{
	unsigned i;

	if (!data)
		return;
	for (i = 0; i < data->num_items; i++)
	{
		grub_free (data->items[i].name);
		grub_free (data->items[i].link);
		grub_free (data->items[i].blocks);
	}
	grub_free (data->items);
	grub_free (data->label);
	grub_free (data);
}

static int
fsa_add_item (struct grub_fsa_data *data, struct fsa_item *item,
	      unsigned *index)
{
	if (data->num_items >= FSA_ITEMS_MAX)
		return 0;
	if (data->num_items == data->cap_items)
	{
		unsigned cap = data->cap_items ? data->cap_items * 2 : 64;
		struct fsa_item *items;

		if (cap > FSA_ITEMS_MAX)
			cap = FSA_ITEMS_MAX;
		items = grub_realloc (data->items, cap * sizeof (*items));
		if (!items)
			return 0;
		data->items = items;
		data->cap_items = cap;
	}
	*index = data->num_items;
	data->items[data->num_items++] = *item;
	grub_memset (item, 0, sizeof (*item));
	return 1;
}

static int
fsa_add_block (struct fsa_item *item, const struct fsa_block *block)
{
	if (item->num_blocks >= FSA_BLOCKS_MAX)
		return 0;
	if (item->num_blocks == item->cap_blocks)
	{
		unsigned cap = item->cap_blocks ? item->cap_blocks * 2 : 4;
		struct fsa_block *blocks;

		if (cap > FSA_BLOCKS_MAX)
			cap = FSA_BLOCKS_MAX;
		blocks = grub_realloc (item->blocks, cap * sizeof (*blocks));
		if (!blocks)
			return 0;
		item->blocks = blocks;
		item->cap_blocks = cap;
	}
	item->blocks[item->num_blocks++] = *block;
	return 1;
}

/* Strip the leading slash and reject path traversal in archive metadata. */
static int
fsa_normalize_archive_name (char *name)
{
	char *read = name;
	char *write = name;

	while (*read == '/')
		read++;
	while (*read)
	{
		char *component;
		grub_size_t len;

		while (*read == '/')
			read++;
		component = read;
		while (*read && *read != '/')
			read++;
		len = (grub_size_t) (read - component);
		if (len == 0 || (len == 1 && component[0] == '.'))
			continue;
		if (len == 2 && component[0] == '.' && component[1] == '.')
			return 0;
		if (write != name)
			*write++ = '/';
		grub_memmove (write, component, len);
		write += len;
	}
	*write = 0;
	return 1;
}

static char *
fsa_item_name (const struct grub_fsa_data *data, grub_uint16_t fsid,
	       const char *raw, grub_uint16_t raw_size)
{
	char prefix[32];
	grub_size_t prefix_len = 0;
	char *name;

	if (raw_size == 0 || raw_size > FSA_PATH_MAX)
		return 0;
	if (data->archive_type == FSA_ARCH_FILESYSTEMS && data->fs_count > 1)
	{
		int len = grub_snprintf (prefix, sizeof (prefix), "fs%u/",
					 (unsigned) fsid);

		if (len < 0 || (grub_size_t) len >= sizeof (prefix))
			return 0;
		prefix_len = (grub_size_t) len;
	}
	name = grub_malloc (prefix_len + raw_size);
	if (!name)
		return 0;
	grub_memcpy (name, prefix, prefix_len);
	grub_memcpy (name + prefix_len, raw, raw_size);
	if (!fsa_normalize_archive_name (name + prefix_len))
	{
		grub_free (name);
		return 0;
	}
	if (prefix_len && name[prefix_len] == 0)
		name[prefix_len - 1] = 0;
	return name;
}

static int
fsa_parse_item (const struct grub_fsa_data *data, const struct fsa_header *h,
		struct fsa_item *item, grub_uint32_t *multi_count)
{
	grub_uint16_t size;
	const char *path;
	const char *link;
	grub_uint64_t value64;
	grub_uint32_t value32;
	const grub_uint8_t *md5;

	grub_memset (item, 0, sizeof (*item));
	path = fsa_dico_string (&h->dico, FSA_ITEM_PATH, &size);
	if (!path)
		return 0;
	item->name = fsa_item_name (data, h->fsid, path, size);
	if (!item->name)
		return 0;
	if (!fsa_dico_u32 (&h->dico, FSA_ITEM_TYPE, &item->type)
	    || item->type < FSA_OBJ_DIR || item->type > FSA_OBJ_REGFILE_MULTI
	    || !fsa_dico_u64 (&h->dico, FSA_ITEM_SIZE, &item->size))
		goto fail;
	item->fsid = h->fsid;
	if (fsa_dico_u64 (&h->dico, FSA_ITEM_MTIME, &value64))
		item->mtime = (grub_int64_t) value64;
	if (fsa_dico_u32 (&h->dico, FSA_ITEM_MODE, &value32))
		item->mode = value32;
	if (item->type == FSA_OBJ_SYMLINK)
	{
		link = fsa_dico_string (&h->dico, FSA_ITEM_SYMLINK, &size);
		if (!link || size > FSA_PATH_MAX)
			goto fail;
		item->link = grub_strdup (link);
		if (!item->link)
			goto fail;
	}
	else if (item->type == FSA_OBJ_HARDLINK)
	{
		link = fsa_dico_string (&h->dico, FSA_ITEM_HARDLINK, &size);
		if (!link || size > FSA_PATH_MAX)
			goto fail;
		item->link = grub_strdup (link);
		if (!item->link)
			goto fail;
	}
	if (item->type == FSA_OBJ_REGFILE_MULTI)
	{
		if (!fsa_dico_u32 (&h->dico, FSA_ITEM_MULTI_COUNT, multi_count)
		    || *multi_count == 0 || *multi_count > FSA_MULTI_MAX
		    || !fsa_dico_u32 (&h->dico, FSA_ITEM_MULTI_OFFSET,
				       &item->multi_offset))
			goto fail;
		md5 = fsa_dico_data (&h->dico, FSA_ITEM_MD5, &size);
		if (!md5 || size != sizeof (item->md5))
			goto fail;
		grub_memcpy (item->md5, md5, sizeof (item->md5));
		item->has_md5 = 1;
	}
	return 1;

fail:
	grub_free (item->name);
	grub_free (item->link);
	grub_memset (item, 0, sizeof (*item));
	return 0;
}

static int
fsa_parse_block (const struct fsa_header *h, struct fsa_reader *r,
		 struct fsa_block *block)
{
	grub_uint64_t end;

	grub_memset (block, 0, sizeof (*block));
	if (!fsa_dico_u32 (&h->dico, FSA_BLOCK_REALSIZE, &block->real_size)
	    || !fsa_dico_u64 (&h->dico, FSA_BLOCK_OFFSET, &block->offset)
	    || !fsa_dico_u16 (&h->dico, FSA_BLOCK_COMP, &block->comp)
	    || !fsa_dico_u16 (&h->dico, FSA_BLOCK_ENCRYPT, &block->encrypt)
	    || !fsa_dico_u32 (&h->dico, FSA_BLOCK_ARSIZE, &block->ar_size)
	    || !fsa_dico_u32 (&h->dico, FSA_BLOCK_COMPSIZE, &block->comp_size)
	    || !fsa_dico_u32 (&h->dico, FSA_BLOCK_CHECKSUM, &block->checksum))
		return 0;
	if (block->real_size == 0 || block->real_size > FSA_BLOCK_MAX
	    || block->ar_size == 0 || block->ar_size > FSA_STORED_MAX
	    || block->comp_size != block->ar_size
	    || block->comp < FSA_COMP_NONE || block->comp > FSA_COMP_ZSTD
	    || block->encrypt != 1)
		return 0;
	block->data_pos = r->pos;
	end = r->pos + block->ar_size;
	if (end < r->pos || end > r->size)
		return 0;
	r->pos = end;
	return 1;
}

static int
fsa_parse_multi (struct grub_fsa_data *data, struct fsa_reader *r,
		 struct fsa_header *first)
{
	unsigned indices[FSA_MULTI_MAX];
	struct fsa_item item;
	struct fsa_header h;
	struct fsa_block block;
	grub_uint32_t count;
	grub_uint32_t item_count;
	unsigned i;

	if (!fsa_parse_item (data, first, &item, &count)
	    || !fsa_add_item (data, &item, &indices[0]))
		return 0;
	for (i = 1; i < count; i++)
	{
		if (!fsa_read_header (r, &h))
			return 0;
		if (grub_memcmp (h.magic, FSA_MAGIC_OBJT, 4) != 0
		    || h.archid != data->archid || h.fsid != first->fsid
		    || !fsa_parse_item (data, &h, &item, &item_count)
		    || item.type != FSA_OBJ_REGFILE_MULTI || item_count != count
		    || !fsa_add_item (data, &item, &indices[i]))
		{
			fsa_header_free (&h);
			return 0;
		}
		fsa_header_free (&h);
	}
	if (!fsa_read_header (r, &h))
		return 0;
	if (grub_memcmp (h.magic, FSA_MAGIC_BLKH, 4) != 0
	    || h.archid != data->archid || h.fsid != first->fsid
	    || !fsa_parse_block (&h, r, &block))
	{
		fsa_header_free (&h);
		return 0;
	}
	for (i = 0; i < count; i++)
	{
		struct fsa_item *cur = &data->items[indices[i]];

		if (cur->multi_offset > block.real_size
		    || cur->size > block.real_size - cur->multi_offset
		    || !fsa_add_block (cur, &block))
		{
			fsa_header_free (&h);
			return 0;
		}
	}
	fsa_header_free (&h);
	return 1;
}

static int
fsa_parse_unique (struct grub_fsa_data *data, struct fsa_reader *r,
		  unsigned index)
{
	struct fsa_item *item = &data->items[index];
	grub_uint64_t total = 0;

	while (total < item->size)
	{
		struct fsa_header h;
		struct fsa_block block;

		if (!fsa_read_header (r, &h))
			return 0;
		if (grub_memcmp (h.magic, FSA_MAGIC_BLKH, 4) != 0
		    || h.archid != data->archid || h.fsid != item->fsid
		    || !fsa_parse_block (&h, r, &block)
		    || block.offset != total || block.real_size > item->size - total
		    || !fsa_add_block (item, &block))
		{
			fsa_header_free (&h);
			return 0;
		}
		total += block.real_size;
		fsa_header_free (&h);
	}
	if (item->size)
	{
		struct fsa_header h;
		grub_uint16_t size;
		const grub_uint8_t *md5;

		if (!fsa_read_header (r, &h))
			return 0;
		md5 = fsa_dico_data (&h.dico, FSA_FILE_FOOT_MD5, &size);
		if (grub_memcmp (h.magic, FSA_MAGIC_FILF, 4) != 0
		    || h.archid != data->archid || h.fsid != item->fsid
		    || !md5 || size != sizeof (item->md5))
		{
			fsa_header_free (&h);
			return 0;
		}
		grub_memcpy (item->md5, md5, sizeof (item->md5));
		item->has_md5 = 1;
		fsa_header_free (&h);
	}
	return 1;
}

static struct grub_fsa_data *
grub_fsa_mount (grub_disk_t disk)
{
	struct grub_fsa_data *data = 0;
	struct fsa_reader r;
	struct fsa_header h;
	grub_uint8_t probe[4];
	grub_uint32_t value32;
	grub_uint64_t value64;
	grub_uint16_t size;
	const char *string;
	int got_footer = 0;

	if (grub_disk_read (disk, 0, 0, sizeof (probe), probe))
		goto fail;
	if (grub_memcmp (probe, FSA_MAGIC_VOLH, 4) != 0)
		goto not_fsa;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return 0;
	data->disk = disk;
	data->disk_size = grub_disk_native_sectors (disk)
			  << GRUB_DISK_SECTOR_BITS;
	r.disk = disk;
	r.size = data->disk_size;
	r.pos = 0;

	if (!fsa_read_header (&r, &h)
	    || grub_memcmp (h.magic, FSA_MAGIC_VOLH, 4) != 0
	    || h.fsid != FSA_FSID_NULL
	    || !fsa_dico_u32 (&h.dico, FSA_VOLUME_VOLNUM, &value32)
	    || value32 != 0
	    || !fsa_dico_u32 (&h.dico, FSA_VOLUME_ARCHID, &data->archid)
	    || data->archid == 0 || data->archid != h.archid)
		goto corrupt_header;
	string = fsa_dico_string (&h.dico, FSA_VOLUME_FORMAT, &size);
	if (!string || grub_strcmp (string, FSA_FORMAT) != 0)
		goto corrupt_header;
	fsa_header_free (&h);

	if (!fsa_read_header (&r, &h)
	    || grub_memcmp (h.magic, FSA_MAGIC_MAIN, 4) != 0
	    || h.archid != data->archid || h.fsid != FSA_FSID_NULL
	    || !fsa_dico_u32 (&h.dico, FSA_MAIN_ARCHID, &value32)
	    || value32 != data->archid
	    || !fsa_dico_u32 (&h.dico, FSA_MAIN_TYPE, &data->archive_type)
	    || (data->archive_type != FSA_ARCH_FILESYSTEMS
		&& data->archive_type != FSA_ARCH_DIRECTORIES)
	    || !fsa_dico_u32 (&h.dico, FSA_MAIN_ENCRYPT, &value32)
	    || value32 != 1)
		goto corrupt_header;
	string = fsa_dico_string (&h.dico, FSA_MAIN_FORMAT, &size);
	if (!string || grub_strcmp (string, FSA_FORMAT) != 0)
		goto corrupt_header;
	if (data->archive_type == FSA_ARCH_FILESYSTEMS)
	{
		if (!fsa_dico_u64 (&h.dico, FSA_MAIN_FSCOUNT, &data->fs_count)
		    || data->fs_count == 0 || data->fs_count > 128)
			goto corrupt_header;
	}
	else
		data->fs_count = 1;
	if (fsa_dico_u64 (&h.dico, FSA_MAIN_CTIME, &value64))
		data->ctime = (grub_int64_t) value64;
	string = fsa_dico_string (&h.dico, FSA_MAIN_LABEL, &size);
	if (string && string[0] && grub_strcmp (string, "<none>") != 0)
	{
		data->label = grub_strdup (string);
		if (!data->label)
			goto corrupt_header;
	}
	fsa_header_free (&h);

	while (r.pos < r.size)
	{
		struct fsa_item item;
		grub_uint32_t multi_count = 0;
		unsigned index;

		if (!fsa_read_header (&r, &h))
			goto corrupt;
		if (h.archid != data->archid)
			goto corrupt_header;
		if (grub_memcmp (h.magic, FSA_MAGIC_VOLF, 4) == 0)
		{
			if (h.fsid != FSA_FSID_NULL
			    || !fsa_dico_u32 (&h.dico, FSA_VOLUME_FOOT_VOLNUM,
					       &value32) || value32 != 0
			    || !fsa_dico_u32 (&h.dico, FSA_VOLUME_FOOT_ARCHID,
					       &value32) || value32 != data->archid
			    || !fsa_dico_u32 (&h.dico, FSA_VOLUME_FOOT_LAST,
					       &value32) || value32 != 1)
				goto corrupt_header;
			got_footer = 1;
			fsa_header_free (&h);
			break;
		}
		if (grub_memcmp (h.magic, FSA_MAGIC_OBJT, 4) != 0)
		{
			if (grub_memcmp (h.magic, FSA_MAGIC_FSIN, 4) != 0
			    && grub_memcmp (h.magic, FSA_MAGIC_FSYB, 4) != 0
			    && grub_memcmp (h.magic, FSA_MAGIC_DIRS, 4) != 0
			    && grub_memcmp (h.magic, FSA_MAGIC_DATF, 4) != 0)
				goto corrupt_header;
			fsa_header_free (&h);
			continue;
		}
		if (h.fsid == FSA_FSID_NULL || h.fsid >= data->fs_count)
			goto corrupt_header;
		if (!fsa_parse_item (data, &h, &item, &multi_count))
			goto corrupt_header;
		if (item.type == FSA_OBJ_REGFILE_MULTI)
		{
			grub_free (item.name);
			grub_free (item.link);
			if (!fsa_parse_multi (data, &r, &h))
				goto corrupt_header;
		}
		else
		{
			if (!fsa_add_item (data, &item, &index))
				goto corrupt_header;
			if (data->items[index].type == FSA_OBJ_REGFILE
			    && !fsa_parse_unique (data, &r, index))
				goto corrupt_header;
		}
		fsa_header_free (&h);
	}
	/* Host files are exposed through a sector-sized disk and may therefore
	   have zero padding after the exact end of the final volume footer. */
	if (!got_footer)
		goto corrupt;
	return data;

corrupt_header:
	fsa_header_free (&h);
corrupt:
	fsa_free_data (data);
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "corrupt or unsupported fsa archive");
	return 0;

not_fsa:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "not an fsa archive");
	return 0;

fail:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "cannot read fsa archive");
	return 0;
}

static const char *
fsa_norm_path (const char *path, grub_size_t *len)
{
	grub_size_t size;

	while (*path == '/')
		path++;
	size = grub_strlen (path);
	while (size && path[size - 1] == '/')
		size--;
	*len = size;
	return path;
}

static int
fsa_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
		 const char **child, grub_size_t *child_len, int *is_dir)
{
	const char *rest;
	const char *slash;

	if (dir_len)
	{
		if (grub_strncmp (name, dir, dir_len) != 0 || name[dir_len] != '/')
			return 0;
		rest = name + dir_len + 1;
	}
	else
		rest = name;
	if (!*rest)
		return 0;
	slash = grub_strchr (rest, '/');
	*child = rest;
	*child_len = slash ? (grub_size_t) (slash - rest) : grub_strlen (rest);
	*is_dir = slash != 0;
	return *child_len != 0;
}

struct fsa_seen
{
	struct fsa_seen *next;
	char *name;
};

static grub_uint32_t
fsa_hash_name (const char *name)
{
	grub_uint32_t hash = 5381;

	while (*name)
		hash = hash * 33 + (grub_uint8_t) *name++;
	return hash & (FSA_SEEN_BUCKETS - 1);
}

static int
fsa_seen_add (struct fsa_seen **buckets, char *name)
{
	const grub_uint32_t hash = fsa_hash_name (name);
	struct fsa_seen *entry;

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
grub_fsa_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_fsa_data *data;
	struct fsa_seen **buckets;
	const char *dir;
	grub_size_t dir_len;
	grub_err_t err = GRUB_ERR_NONE;
	unsigned i;
	int found;

	data = grub_fsa_mount (device->disk);
	if (!data)
		return grub_errno;
	dir = fsa_norm_path (path, &dir_len);
	found = (dir_len == 0);
	buckets = grub_calloc (FSA_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		fsa_free_data (data);
		return grub_errno;
	}
	for (i = 0; i < data->num_items; i++)
	{
		struct grub_dirhook_info info;
		const char *child;
		grub_size_t child_len;
		int child_is_dir;
		char *name;
		int duplicate;

		if (!fsa_name_in_dir (data->items[i].name, dir, dir_len,
				      &child, &child_len, &child_is_dir))
		{
			if (dir_len && grub_strncmp (data->items[i].name, dir,
						     dir_len) == 0
			    && data->items[i].name[dir_len] == 0)
				found = 1;
			continue;
		}
		found = 1;
		name = grub_malloc (child_len + 1);
		if (!name)
		{
			err = grub_errno;
			goto out;
		}
		grub_memcpy (name, child, child_len);
		name[child_len] = 0;
		duplicate = fsa_seen_add (buckets, name);
		if (duplicate)
		{
			grub_free (name);
			if (duplicate < 0)
			{
				err = grub_errno;
				goto out;
			}
			continue;
		}
		grub_memset (&info, 0, sizeof (info));
		info.dir = child_is_dir || data->items[i].type == FSA_OBJ_DIR;
		info.symlink = !child_is_dir && data->items[i].type == FSA_OBJ_SYMLINK;
		info.inodeset = 1;
		info.inode = i;
		if (!info.dir && !info.symlink)
		{
			info.sizeset = 1;
			info.size = data->items[i].size;
		}
		if (!child_is_dir && data->items[i].mtime)
		{
			info.mtimeset = 1;
			info.mtime = data->items[i].mtime;
		}
		if (hook (name, &info, hook_data))
			goto out;
	}
	if (!found)
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);

out:
	for (i = 0; i < FSA_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct fsa_seen *entry = buckets[i];

			buckets[i] = entry->next;
			grub_free (entry->name);
			grub_free (entry);
		}
	grub_free (buckets);
	fsa_free_data (data);
	return err;
}

static int
fsa_find_item (const struct grub_fsa_data *data, const char *name)
{
	grub_size_t len;
	const char *path = fsa_norm_path (name, &len);
	unsigned i;

	for (i = 0; i < data->num_items; i++)
		if (grub_strncmp (data->items[i].name, path, len) == 0
		    && data->items[i].name[len] == 0)
			return (int) i;
	return -1;
}

static char *
fsa_link_path (const struct grub_fsa_data *data, const struct fsa_item *item)
{
	char *path;
	char *slash;
	grub_size_t parent_len = 0;
	grub_size_t fs_prefix_len = 0;
	grub_size_t link_len;
	char fs_prefix[32];

	if (!item->link)
		return 0;
	link_len = grub_strlen (item->link);
	if (link_len >= FSA_PATH_MAX)
		return 0;
	if (item->link[0] != '/')
	{
		slash = grub_strrchr (item->name, '/');
		if (slash)
			parent_len = (grub_size_t) (slash - item->name) + 1;
	}
	else if (data->archive_type == FSA_ARCH_FILESYSTEMS
		 && data->fs_count > 1)
	{
		int len = grub_snprintf (fs_prefix, sizeof (fs_prefix), "fs%u/",
					 (unsigned) item->fsid);

		if (len < 0 || (grub_size_t) len >= sizeof (fs_prefix))
			return 0;
		fs_prefix_len = (grub_size_t) len;
	}
	path = grub_malloc (fs_prefix_len + parent_len + link_len + 1);
	if (!path)
		return 0;
	if (fs_prefix_len)
		grub_memcpy (path, fs_prefix, fs_prefix_len);
	if (parent_len)
		grub_memcpy (path + fs_prefix_len, item->name, parent_len);
	grub_memcpy (path + fs_prefix_len + parent_len, item->link, link_len + 1);

	/* Canonicalize link targets, allowing .. without escaping the archive. */
	{
		char *read = path;
		char *write = path;

		while (*read == '/')
			read++;
		while (*read)
		{
			char *component;
			grub_size_t len;

			while (*read == '/')
				read++;
			component = read;
			while (*read && *read != '/')
				read++;
			len = (grub_size_t) (read - component);
			if (len == 0 || (len == 1 && component[0] == '.'))
				continue;
			if (len == 2 && component[0] == '.' && component[1] == '.')
			{
				if (write == path)
				{
					grub_free (path);
					return 0;
				}
				while (write > path && write[-1] != '/')
					write--;
				if (write > path)
					write--;
				continue;
			}
			if (write != path)
				*write++ = '/';
			grub_memmove (write, component, len);
			write += len;
		}
		*write = 0;
	}
	return path;
}

static grub_err_t
grub_fsa_open (struct grub_file *file, const char *name)
{
	struct grub_fsa_data *data;
	struct grub_fsa_file *ctx;
	int index;
	unsigned depth;

	data = grub_fsa_mount (file->device->disk);
	if (!data)
		return grub_errno;
	index = fsa_find_item (data, name);
	if (index < 0)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", name);
		goto fail;
	}
	for (depth = 0; depth < 8
	     && (data->items[index].type == FSA_OBJ_SYMLINK
		 || data->items[index].type == FSA_OBJ_HARDLINK); depth++)
	{
		char *target = fsa_link_path (data, &data->items[index]);

		if (!target)
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid fsa link target");
			goto fail;
		}
		index = fsa_find_item (data, target);
		grub_free (target);
		if (index < 0)
		{
			grub_error (GRUB_ERR_FILE_NOT_FOUND, "fsa link target not found");
			goto fail;
		}
	}
	if (depth == 8)
	{
		grub_error (GRUB_ERR_SYMLINK_LOOP, "too deep nesting of fsa links");
		goto fail;
	}
	if (data->items[index].type == FSA_OBJ_DIR)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "is a directory");
		goto fail;
	}
	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
		goto fail;
	ctx->data = data;
	ctx->index = (unsigned) index;
	ctx->cache_index = (unsigned) -1;
	if (data->items[index].has_md5)
	{
		ctx->md5_desc = GRUB_MD_MD5;
		ctx->md5_ctx = grub_malloc (ctx->md5_desc->contextsize);
		if (!ctx->md5_ctx)
		{
			grub_free (ctx);
			goto fail;
		}
		ctx->md5_desc->init (ctx->md5_ctx, 0);
		ctx->md5_active = 1;
	}
	file->data = ctx;
	file->size = data->items[index].size;
	return GRUB_ERR_NONE;

fail:
	fsa_free_data (data);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

static int
fsa_unpack_block (struct grub_fsa_file *ctx, unsigned block_index)
{
	const struct fsa_item *item = &ctx->data->items[ctx->index];
	const struct fsa_block *block = &item->blocks[block_index];
	grub_uint8_t *stored = 0;
	grub_uint8_t *plain = 0;
	int ok = 0;

	if (ctx->cache_index == block_index)
		return 1;
	stored = grub_malloc (block->ar_size);
	plain = grub_malloc (block->real_size);
	if (!stored || !plain)
		goto out;
	if (grub_disk_read (ctx->data->disk, 0, block->data_pos,
			    block->ar_size, stored))
		goto out;
	if (fsa_fletcher32 (stored, block->ar_size) != block->checksum)
	{
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
			    "fsa data block checksum mismatch");
		goto out;
	}
	switch (block->comp)
	{
	case FSA_COMP_NONE:
		if (block->ar_size != block->real_size)
			goto bad_stream;
		grub_memcpy (plain, stored, block->real_size);
		break;
	case FSA_COMP_LZO:
		{
			lzo_uint size = block->real_size;

			if (lzo1x_decompress_safe (stored, block->comp_size, plain,
						  &size, 0) != LZO_E_OK
			    || size != block->real_size)
				goto bad_stream;
		}
		break;
	case FSA_COMP_GZIP:
		if (grub_zlib_decompress ((char *) stored, block->comp_size, 0,
					 (char *) plain, block->real_size)
		    != (grub_ssize_t) block->real_size)
			goto bad_stream;
		break;
	case FSA_COMP_BZIP2:
		{
			unsigned int size = block->real_size;

			if (BZ2_bzBuffToBuffDecompress ((char *) plain, &size,
						(char *) stored, block->comp_size,
						0, 0) != BZ_OK
			    || size != block->real_size)
				goto bad_stream;
		}
		break;
	case FSA_COMP_LZMA:
		{
			struct xz_dec *decoder = xz_dec_init (0);
			struct xz_buf buffer;
			enum xz_ret result;

			if (!decoder)
				goto out;
			buffer.in = stored;
			buffer.in_pos = 0;
			buffer.in_size = block->comp_size;
			buffer.out = plain;
			buffer.out_pos = 0;
			buffer.out_size = block->real_size;
			result = xz_dec_run (decoder, &buffer);
			xz_dec_end (decoder);
			if (result != XZ_STREAM_END
			    || buffer.in_pos != block->comp_size
			    || buffer.out_pos != block->real_size)
				goto bad_stream;
		}
		break;
	case FSA_COMP_LZ4:
		if (LZ4_decompress_safe ((const char *) stored, (char *) plain,
					 block->comp_size, block->real_size)
		    != (int) block->real_size)
			goto bad_stream;
		break;
	case FSA_COMP_ZSTD:
		{
			size_t size = ZSTD_decompress (plain, block->real_size,
						 stored, block->comp_size);

			if (ZSTD_isError (size) || size != block->real_size)
				goto bad_stream;
		}
		break;
	default:
		goto bad_stream;
	}
	grub_free (ctx->cache);
	ctx->cache = plain;
	ctx->cache_size = block->real_size;
	ctx->cache_index = block_index;
	plain = 0;
	ok = 1;
	goto out;

bad_stream:
	grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt fsa compressed block");
out:
	grub_free (plain);
	grub_free (stored);
	return ok;
}

static grub_ssize_t
grub_fsa_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fsa_file *ctx = file->data;
	const struct fsa_item *item = &ctx->data->items[ctx->index];
	grub_uint64_t start = file->offset;
	grub_uint64_t end = start + len;
	unsigned i;

	if (end < start || end > item->size)
		return -1;
	grub_memset (buf, 0, len);
	if (item->type == FSA_OBJ_REGFILE_MULTI)
	{
		if (item->num_blocks != 1 || !fsa_unpack_block (ctx, 0))
			return -1;
		if (item->multi_offset > ctx->cache_size
		    || end > ctx->cache_size - item->multi_offset)
			return -1;
		grub_memcpy (buf, ctx->cache + item->multi_offset + start, len);
	}
	else if (item->type == FSA_OBJ_REGFILE)
	{
		for (i = 0; i < item->num_blocks; i++)
		{
			const struct fsa_block *block = &item->blocks[i];
			grub_uint64_t block_end = block->offset + block->real_size;
			grub_uint64_t copy_start;
			grub_uint64_t copy_end;

			if (block_end <= start || block->offset >= end)
				continue;
			if (!fsa_unpack_block (ctx, i))
				return -1;
			copy_start = block->offset > start ? block->offset : start;
			copy_end = block_end < end ? block_end : end;
			grub_memcpy (buf + (copy_start - start),
				     ctx->cache + (copy_start - block->offset),
				     (grub_size_t) (copy_end - copy_start));
		}
	}
	if (ctx->md5_active)
	{
		if (start != ctx->md5_pos)
			ctx->md5_active = 0;
		else
		{
			ctx->md5_desc->write (ctx->md5_ctx, buf, len);
			ctx->md5_pos += len;
			if (ctx->md5_pos == item->size)
			{
				ctx->md5_desc->final (ctx->md5_ctx);
				if (grub_memcmp (ctx->md5_desc->read (ctx->md5_ctx),
						 item->md5, sizeof (item->md5)) != 0)
				{
					grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
						    "fsa file md5 mismatch");
					return -1;
				}
			}
		}
	}
	return (grub_ssize_t) len;
}

static grub_err_t
grub_fsa_close (grub_file_t file)
{
	struct grub_fsa_file *ctx = file->data;

	if (ctx)
	{
		grub_free (ctx->cache);
		grub_free (ctx->md5_ctx);
		fsa_free_data (ctx->data);
		grub_free (ctx);
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_fsa_label (grub_device_t device, char **label)
{
	struct grub_fsa_data *data = grub_fsa_mount (device->disk);

	if (!data)
		return grub_errno;
	*label = data->label ? grub_strdup (data->label) : 0;
	fsa_free_data (data);
	return grub_errno;
}

static grub_err_t
grub_fsa_mtime (grub_device_t device, grub_int64_t *timebuf)
{
	struct grub_fsa_data *data = grub_fsa_mount (device->disk);

	if (!data)
		return grub_errno;
	*timebuf = data->ctime;
	fsa_free_data (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_fsa_fs =
{
	.name = "fsa",
	.fs_dir = grub_fsa_dir,
	.fs_open = grub_fsa_open,
	.fs_read = grub_fsa_read,
	.fs_close = grub_fsa_close,
	.fs_label = grub_fsa_label,
	.fs_mtime = grub_fsa_mtime,
};

GRUB_MOD_INIT (fsa)
{
	grub_fs_register (&grub_fsa_fs);
}

GRUB_MOD_FINI (fsa)
{
	grub_fs_unregister (&grub_fsa_fs);
}
