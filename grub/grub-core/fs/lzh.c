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

/*  Read-only LHA / LZH archive filesystem driver.
 *
 *  Header semantics follow 7-Zip 26.02 CPP\7zip\Archive\LzhHandler.cpp:
 *  a flat chain of level 0 / 1 / 2 headers, each followed by its packed
 *  data, with the level 1 and 2 extension headers carrying the long file
 *  and directory names.  Decompression uses grub-core\lib\7z\LzhDecoder.c.
 *
 *  Methods: -lhd- (directory), -lh0- and -lz4- (stored), -lh4- .. -lh7-
 *  (LZH, 4 KiB .. 64 KiB dictionary).  The older -lh1- / -lh2- / -lh3- and
 *  -lzs- / -lz5- streams use different coders and are rejected at open
 *  time, as they are in the 7-Zip handler.  Names are stored in an OEM
 *  code page and decoded with the selected filesystem source encoding.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/datetime.h>
#include <grub/dl.h>

#include <LzhDecoder.h>

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define LZH_METHOD_SIZE		5
#define LZH_BASIC_PART_SIZE	22
#define LZH_HEADER_MAX		256

#define LZH_EXT_FILENAME	0x01
#define LZH_EXT_DIRNAME		0x02
#define LZH_EXT_UNIXTIME	0x54

/* item->method */
#define LZH_M_UNSUPPORTED	0
#define LZH_M_DIR		1
#define LZH_M_COPY		2
#define LZH_M_LH		3

/* an entry we are willing to unpack into memory in one go */
#define LZH_UNPACK_MAX		((grub_uint64_t) 256 << 20)
#define LZH_ITEMS_MAX		(1u << 20)
#define LZH_SEEN_BUCKETS	512

struct lzh_item
{
	char *name;		/* full path, '/' separated, no trailing '/' */
	grub_uint64_t data_pos;
	grub_uint32_t pack_size;
	grub_uint32_t size;
	grub_uint16_t crc;
	grub_uint8_t method;
	grub_uint8_t dict_bits;
	grub_uint8_t is_dir;
	char method_id[LZH_METHOD_SIZE + 1];
	grub_int64_t mtime;
};

struct grub_lzh_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct lzh_item *items;
	unsigned num_items;
	unsigned cap_items;
};

struct grub_lzh_file
{
	struct grub_lzh_data *data;
	unsigned index;
	grub_uint8_t *buf;	/* unpacked content, 0 until first read */
};

/* CRC-16/ARC, the checksum LHA stores per entry */
static grub_uint16_t lzh_crc16_table[256];

static void
lzh_crc16_init (void)
{
	grub_uint32_t i;

	for (i = 0; i < 256; i++)
	{
		grub_uint32_t r = i;
		unsigned j;

		for (j = 0; j < 8; j++)
			r = (r >> 1) ^ (0xA001 & (grub_uint32_t) (0 - (r & 1)));
		lzh_crc16_table[i] = (grub_uint16_t) r;
	}
}

static grub_uint16_t
lzh_crc16 (const grub_uint8_t *p, grub_size_t size)
{
	grub_uint16_t crc = 0;

	while (size--)
		crc = (grub_uint16_t) (lzh_crc16_table[(crc ^ *p++) & 0xFF]
				       ^ (crc >> 8));
	return crc;
}

static grub_uint16_t
lzh_get16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
lzh_get32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_int64_t
lzh_dos_time (grub_uint32_t dos)
{
	struct grub_datetime dt;
	grub_int64_t nix = 0;

	grub_memset (&dt, 0, sizeof (dt));
	dt.year = (grub_int16_t) (((dos >> 25) & 0x7f) + 1980);
	dt.month = (grub_uint8_t) ((dos >> 21) & 0x0f);
	dt.day = (grub_uint8_t) ((dos >> 16) & 0x1f);
	dt.hour = (grub_uint8_t) ((dos >> 11) & 0x1f);
	dt.minute = (grub_uint8_t) ((dos >> 5) & 0x3f);
	dt.second = (grub_uint8_t) ((dos & 0x1f) * 2);
	if (dt.month < 1 || dt.month > 12 || dt.day < 1 || dt.day > 31)
		return 0;
	if (grub_datetime2unixtime (&dt, &nix))
		return nix;
	return 0;
}

/* ---------------- sequential reader ---------------- */

struct lzh_reader
{
	grub_disk_t disk;
	grub_uint64_t size;
	grub_uint64_t pos;
};

/* reads up to `want` bytes, reports how many were there */
static int
lzh_read (struct lzh_reader *r, void *buf, grub_size_t want,
	  grub_size_t *got)
{
	grub_size_t n = want;

	if (r->pos >= r->size)
		n = 0;
	else if ((grub_uint64_t) n > r->size - r->pos)
		n = (grub_size_t) (r->size - r->pos);
	if (n != 0 && grub_disk_read (r->disk, 0, r->pos, n, buf))
		return 0;
	r->pos += n;
	*got = n;
	return 1;
}

static int
lzh_read_full (struct lzh_reader *r, void *buf, grub_size_t want)
{
	grub_size_t got;

	if (!lzh_read (r, buf, want, &got))
		return 0;
	return got == want;
}

/* ---------------- header parsing ---------------- */

struct lzh_header
{
	grub_uint8_t method[LZH_METHOD_SIZE];
	grub_uint32_t pack_size;
	grub_uint32_t size;
	grub_uint32_t mtime;
	grub_uint8_t level;
	grub_uint16_t crc;
	char *base_name;	/* level 0 / 1 name field */
	char *ext_name;		/* extension 0x01 */
	char *ext_dir;		/* extension 0x02 */
	grub_uint32_t unix_time;
	int has_unix_time;
};

static void
lzh_header_free (struct lzh_header *h)
{
	grub_free (h->base_name);
	grub_free (h->ext_name);
	grub_free (h->ext_dir);
	h->base_name = 0;
	h->ext_name = 0;
	h->ext_dir = 0;
}

static int
lzh_method_valid (const grub_uint8_t *m)
{
	return m[0] == '-' && m[1] == 'l' && m[4] == '-';
}

static char *
lzh_dup_string (const grub_uint8_t *p, grub_size_t size)
{
	grub_size_t n = 0;
	char *s;

	while (n < size && p[n] != 0)
		n++;
	s = grub_malloc (n + 1);
	if (!s)
		return 0;
	grub_memcpy (s, p, n);
	s[n] = '\0';
	return s;
}

static grub_uint8_t
lzh_calc_sum (const grub_uint8_t *p, grub_size_t size)
{
	grub_uint8_t sum = 0;

	while (size--)
		sum = (grub_uint8_t) (sum + *p++);
	return sum;
}

/*
 * GetNextItem(): 1 = header parsed, 0 = end of archive, -1 = corrupt.
 * On success the reader is positioned at the entry's packed data.
 */
static int
lzh_next_header (struct lzh_reader *r, struct lzh_header *h)
{
	grub_uint8_t start[2];
	grub_uint8_t header[LZH_HEADER_MAX];
	const grub_uint8_t *p;
	grub_size_t got;
	grub_uint32_t header_size;
	grub_uint16_t next_size;

	grub_memset (h, 0, sizeof (*h));

	if (!lzh_read (r, start, 2, &got))
		return -1;
	if (got == 0)
		return 0;
	if (got == 1)
		return start[0] == 0 ? 0 : -1;
	if (start[0] == 0 && start[1] == 0)
		return 0;

	if (!lzh_read (r, header, LZH_BASIC_PART_SIZE, &got))
		return -1;
	if (got != LZH_BASIC_PART_SIZE)
		return start[0] == 0 ? 0 : -1;

	p = header;
	grub_memcpy (h->method, p, LZH_METHOD_SIZE);
	if (!lzh_method_valid (h->method))
		return 0;
	p += LZH_METHOD_SIZE;
	h->pack_size = lzh_get32 (p);
	h->size = lzh_get32 (p + 4);
	h->mtime = lzh_get32 (p + 8);
	h->level = p[13];
	p += 14;
	if (h->level > 2)
		return -1;

	if (h->level < 2)
	{
		grub_size_t name_len;

		header_size = start[0];
		if (header_size < LZH_BASIC_PART_SIZE)
			return -1;
		if (!lzh_read_full (r, header + LZH_BASIC_PART_SIZE,
				    header_size - LZH_BASIC_PART_SIZE))
			return -1;
		if (start[1] != lzh_calc_sum (header, header_size))
			return -1;
		name_len = *p++;
		if ((grub_size_t) (p - header) + name_len + 2 > header_size)
			return -1;
		h->base_name = lzh_dup_string (p, name_len);
		if (!h->base_name)
			return -1;
		p += name_len;
	}
	else
		header_size = start[0] | ((grub_uint32_t) start[1] << 8);

	h->crc = lzh_get16 (p);
	p += 2;

	if (h->level == 0)
		return 1;

	if (h->level == 2
	    && !lzh_read_full (r, header + LZH_BASIC_PART_SIZE, 2))
		return -1;
	if ((grub_size_t) (p - header) + 3 > header_size)
		return -1;
	p++;			/* OS id */
	next_size = lzh_get16 (p);

	while (next_size != 0)
	{
		grub_uint8_t type;
		grub_uint8_t *data;
		grub_uint8_t tail[2];

		if (next_size < 3)
			return -1;
		if (h->level == 1)
		{
			if (h->pack_size < next_size)
				return -1;
			h->pack_size -= next_size;
		}
		if (!lzh_read_full (r, &type, 1))
			return -1;
		next_size = (grub_uint16_t) (next_size - 3);

		data = grub_malloc (next_size ? next_size : 1);
		if (!data)
			return -1;
		if (!lzh_read_full (r, data, next_size)
		    || !lzh_read_full (r, tail, 2))
		{
			grub_free (data);
			return -1;
		}

		switch (type)
		{
		case LZH_EXT_FILENAME:
			if (!h->ext_name)
				h->ext_name = lzh_dup_string (data, next_size);
			break;
		case LZH_EXT_DIRNAME:
			if (!h->ext_dir)
				h->ext_dir = lzh_dup_string (data, next_size);
			break;
		case LZH_EXT_UNIXTIME:
			if (next_size >= 4)
			{
				h->unix_time = lzh_get32 (data);
				h->has_unix_time = 1;
			}
			break;
		default:
			break;
		}
		grub_free (data);
		next_size = lzh_get16 (tail);
	}
	return 1;
}

/*
 * '\' and 0xFF both act as separators; empty, "." and ".." components are
 * dropped so that every entry names exactly one place in the tree ("." is
 * what LHA stores for the archived directory itself).
 */
static void
lzh_normalize_name (char *s)
{
	char *rd;
	char *wr = s;

	for (rd = s; *rd; rd++)
		if (*rd == '\\' || *rd == (char) 0xFF)
			*rd = '/';

	rd = s;
	while (*rd)
	{
		const char *comp;
		grub_size_t len;

		while (*rd == '/')
			rd++;
		comp = rd;
		while (*rd && *rd != '/')
			rd++;
		len = (grub_size_t) (rd - comp);
		if (len == 0)
			continue;
		if (len == 1 && comp[0] == '.')
			continue;
		if (len == 2 && comp[0] == '.' && comp[1] == '.')
			continue;
		if (wr != s)
			*wr++ = '/';
		grub_memmove (wr, comp, len);
		wr += len;
	}
	*wr = '\0';
}

/*
 * GetName(): the directory extension holds the path, the file name comes
 * from its own extension or from the level 0 / 1 name field.
 */
static char *
lzh_build_name (const struct lzh_header *h)
{
	const char *dir = h->ext_dir ? h->ext_dir : "";
	const char *file = h->ext_name ? h->ext_name
				       : (h->base_name ? h->base_name : "");
	const grub_size_t dl = grub_strlen (dir);
	const grub_size_t fl = grub_strlen (file);
	char *raw_dir = 0;
	char *dir_u8 = 0;
	char *file_u8 = 0;
	char *s = 0;
	char *p;

	raw_dir = grub_strndup (dir, dl);
	if (!raw_dir)
		goto fail;
	/* LHA uses 0xFF as the directory separator.  Replace it before
	   decoding, but leave 0x5C alone because it can be a DBCS trail byte. */
	for (p = raw_dir; *p; p++)
		if ((grub_uint8_t) *p == 0xFF)
			*p = '/';
	dir_u8 = grub_fs_bytes_to_utf8 (raw_dir, dl, grub_fs_char_encoding);
	file_u8 = grub_fs_bytes_to_utf8 (file, fl, grub_fs_char_encoding);
	if (!dir_u8 || !file_u8)
		goto fail;
	s = grub_malloc (grub_strlen (dir_u8) + grub_strlen (file_u8) + 2);
	if (!s)
		goto fail;
	p = grub_stpcpy (s, dir_u8);
	*p++ = '/';
	grub_strcpy (p, file_u8);
	lzh_normalize_name (s);
	grub_free (raw_dir);
	grub_free (dir_u8);
	grub_free (file_u8);
	return s;

fail:
	grub_free (raw_dir);
	grub_free (dir_u8);
	grub_free (file_u8);
	grub_free (s);
	return 0;
}

static void
lzh_classify (struct lzh_item *item, const grub_uint8_t *method)
{
	item->method = LZH_M_UNSUPPORTED;
	item->dict_bits = 0;
	item->is_dir = 0;

	if (method[2] == 'h')
	{
		switch (method[3])
		{
		case 'd':
			item->method = LZH_M_DIR;
			item->is_dir = 1;
			return;
		case '0':
			item->method = LZH_M_COPY;
			return;
		case '4':
			item->dict_bits = 12;
			break;
		case '5':
			item->dict_bits = 13;
			break;
		case '6':
			item->dict_bits = 15;
			break;
		case '7':
			item->dict_bits = 16;
			break;
		default:
			return;
		}
		item->method = LZH_M_LH;
	}
	else if (method[2] == 'z' && method[3] == '4')
		item->method = LZH_M_COPY;
}

/* ---------------- mount ---------------- */

static void
lzh_free_data (struct grub_lzh_data *data)
{
	unsigned i;

	if (!data)
		return;
	for (i = 0; i < data->num_items; i++)
		grub_free (data->items[i].name);
	grub_free (data->items);
	grub_free (data);
}

static int
lzh_add_item (struct grub_lzh_data *data, const struct lzh_item *item)
{
	if (data->num_items >= LZH_ITEMS_MAX)
		return 0;
	if (data->num_items == data->cap_items)
	{
		const unsigned cap = data->cap_items ? data->cap_items * 2 : 64;
		struct lzh_item *n = grub_realloc (data->items,
						   cap * sizeof (*n));

		if (!n)
			return 0;
		data->items = n;
		data->cap_items = cap;
	}
	data->items[data->num_items++] = *item;
	return 1;
}

static struct grub_lzh_data *
grub_lzh_mount (grub_disk_t disk)
{
	struct grub_lzh_data *data;
	struct lzh_reader r;
	grub_uint8_t magic[2 + LZH_BASIC_PART_SIZE];

	if (grub_disk_read (disk, 0, 0, sizeof (magic), magic))
		goto fail;
	if (magic[2] != '-' || magic[3] != 'l' || magic[4] != 'h'
	    || magic[6] != '-')
		goto fail;
	if (magic[5] != 'd' && (magic[5] < '0' || magic[5] > '7'))
		goto fail;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return 0;
	data->disk = disk;
	data->disk_size = grub_disk_native_sectors (disk)
			  << GRUB_DISK_SECTOR_BITS;

	r.disk = disk;
	r.size = data->disk_size;
	r.pos = 0;

	for (;;)
	{
		struct lzh_header h;
		struct lzh_item item;
		int res = lzh_next_header (&r, &h);

		if (res <= 0)
		{
			lzh_header_free (&h);
			if (res < 0 && data->num_items == 0)
			{
				grub_error (GRUB_ERR_BAD_FS,
					    "corrupt lzh archive");
				lzh_free_data (data);
				return 0;
			}
			break;
		}

		grub_memset (&item, 0, sizeof (item));
		item.name = lzh_build_name (&h);
		grub_memcpy (item.method_id, h.method, LZH_METHOD_SIZE);
		item.method_id[LZH_METHOD_SIZE] = '\0';
		lzh_classify (&item, h.method);
		item.data_pos = r.pos;
		item.pack_size = h.pack_size;
		item.size = item.is_dir ? 0 : h.size;
		item.crc = h.crc;
		if (h.has_unix_time)
			item.mtime = (grub_int64_t) (grub_int32_t) h.unix_time;
		else if (h.level == 2)
			item.mtime = (grub_int64_t) (grub_int32_t) h.mtime;
		else
			item.mtime = lzh_dos_time (h.mtime);
		lzh_header_free (&h);

		if (!item.name)
		{
			lzh_free_data (data);
			return 0;
		}
		if (item.name[0] == '\0')
			grub_free (item.name);	/* nameless entry, skip it */
		else if (!lzh_add_item (data, &item))
		{
			grub_free (item.name);
			lzh_free_data (data);
			if (!grub_errno)
				grub_error (GRUB_ERR_OUT_OF_MEMORY,
					    "out of memory");
			return 0;
		}

		if (r.pos + item.pack_size > r.size)
			break;
		r.pos += item.pack_size;
	}

	if (data->num_items == 0)
	{
		lzh_free_data (data);
		goto fail;
	}
	return data;

fail:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "not an lzh archive");
	return 0;
}

/* ---------------- directory listing ---------------- */

static const char *
lzh_norm_path (const char *path, grub_size_t *len)
{
	grub_size_t n;

	while (*path == '/')
		path++;
	n = grub_strlen (path);
	while (n > 0 && path[n - 1] == '/')
		n--;
	*len = n;
	return path;
}

static int
lzh_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
		 const char **child, grub_size_t *child_len, int *is_dir)
{
	const char *rest;
	const char *slash;

	if (dir_len != 0)
	{
		if (grub_strncmp (name, dir, dir_len) != 0)
			return 0;
		if (name[dir_len] != '/')
			return 0;
		rest = name + dir_len + 1;
	}
	else
		rest = name;

	if (*rest == '\0')
		return 0;
	slash = grub_strchr (rest, '/');
	*child = rest;
	*child_len = slash ? (grub_size_t) (slash - rest) : grub_strlen (rest);
	*is_dir = slash != 0;
	return *child_len != 0;
}

struct lzh_seen
{
	struct lzh_seen *next;
	char *name;
};

static grub_uint32_t
lzh_hash_name (const char *s)
{
	grub_uint32_t h = 5381;

	while (*s)
		h = h * 33 + (grub_uint8_t) *s++;
	return h & (LZH_SEEN_BUCKETS - 1);
}

/* returns 1 when the name was seen before, -1 on allocation failure */
static int
lzh_seen_add (struct lzh_seen **buckets, char *name)
{
	const grub_uint32_t h = lzh_hash_name (name);
	struct lzh_seen *ent;

	for (ent = buckets[h]; ent; ent = ent->next)
		if (grub_strcmp (ent->name, name) == 0)
			return 1;
	ent = grub_malloc (sizeof (*ent));
	if (!ent)
		return -1;
	ent->name = name;
	ent->next = buckets[h];
	buckets[h] = ent;
	return 0;
}

static grub_err_t
grub_lzh_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_lzh_data *data;
	const char *dir;
	grub_size_t dir_len;
	struct lzh_seen **buckets;
	unsigned i;
	int found;
	grub_err_t err = GRUB_ERR_NONE;

	data = grub_lzh_mount (device->disk);
	if (!data)
		return grub_errno;

	dir = lzh_norm_path (path, &dir_len);
	found = (dir_len == 0);

	buckets = grub_calloc (LZH_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		lzh_free_data (data);
		return grub_errno;
	}

	for (i = 0; i < data->num_items; i++)
	{
		struct grub_dirhook_info info;
		const char *child;
		grub_size_t child_len;
		int child_is_dir;
		char *name;
		int dup;

		if (!lzh_name_in_dir (data->items[i].name, dir, dir_len,
				      &child, &child_len, &child_is_dir))
		{
			if (dir_len != 0
			    && grub_strcmp (data->items[i].name, dir) == 0)
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
		name[child_len] = '\0';

		dup = lzh_seen_add (buckets, name);
		if (dup)
		{
			grub_free (name);
			if (dup < 0)
			{
				err = grub_errno;
				goto out;
			}
			continue;
		}

		grub_memset (&info, 0, sizeof (info));
		info.dir = child_is_dir || data->items[i].is_dir;
		info.inodeset = 1;
		info.inode = i;
		if (!child_is_dir && data->items[i].mtime != 0)
		{
			info.mtimeset = 1;
			info.mtime = data->items[i].mtime;
		}

		if (hook (name, &info, hook_data))
			goto out;
	}

	if (!found)
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
				  "file `%s' not found", path);

out:
	for (i = 0; i < LZH_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct lzh_seen *ent = buckets[i];

			buckets[i] = ent->next;
			grub_free (ent->name);
			grub_free (ent);
		}
	grub_free (buckets);
	lzh_free_data (data);
	return err;
}

/* ---------------- file access ---------------- */

static int
lzh_find_item (struct grub_lzh_data *data, const char *name)
{
	grub_size_t len;
	const char *path = lzh_norm_path (name, &len);
	unsigned i;

	for (i = 0; i < data->num_items; i++)
	{
		const char *n = data->items[i].name;

		if (grub_strncmp (n, path, len) == 0 && n[len] == '\0')
			return (int) i;
	}
	return -1;
}

static grub_err_t
grub_lzh_open (struct grub_file *file, const char *name)
{
	struct grub_lzh_data *data;
	struct grub_lzh_file *ctx;
	const struct lzh_item *item;
	int index;

	data = grub_lzh_mount (file->device->disk);
	if (!data)
		return grub_errno;

	index = lzh_find_item (data, name);
	if (index < 0)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found",
			    name);
		goto fail;
	}
	item = &data->items[index];
	if (item->is_dir)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "is a directory");
		goto fail;
	}
	if (item->method == LZH_M_UNSUPPORTED)
	{
		grub_error (GRUB_ERR_BAD_FS, "unsupported lzh method `%s'",
			    item->method_id);
		goto fail;
	}
	if (item->method == LZH_M_COPY && item->pack_size != item->size)
	{
		grub_error (GRUB_ERR_BAD_FS, "corrupt stored lzh entry");
		goto fail;
	}
	if (item->method != LZH_M_COPY && item->size > LZH_UNPACK_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "lzh entry too large to unpack");
		goto fail;
	}
	if (item->data_pos > data->disk_size
	    || item->pack_size > data->disk_size - item->data_pos)
	{
		grub_error (GRUB_ERR_BAD_FS, "truncated lzh archive");
		goto fail;
	}

	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
		goto fail;
	ctx->data = data;
	ctx->index = (unsigned) index;

	file->data = ctx;
	file->size = item->size;
	return GRUB_ERR_NONE;

fail:
	lzh_free_data (data);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

/* unpacks the whole entry once, verifying its CRC-16 */
static int
lzh_unpack (struct grub_lzh_file *ctx)
{
	const struct lzh_item *item = &ctx->data->items[ctx->index];
	grub_uint8_t *packed;
	SizeT processed = 0;
	int res;

	ctx->buf = grub_malloc (item->size ? item->size : 1);
	if (!ctx->buf)
		return 0;
	if (item->size == 0)
		return 1;

	packed = grub_malloc (item->pack_size ? item->pack_size : 1);
	if (!packed)
		goto fail;
	if (item->pack_size != 0
	    && grub_disk_read (ctx->data->disk, 0, item->data_pos,
			       item->pack_size, packed))
		goto fail;

	res = LzhDecode (packed, item->pack_size, ctx->buf, item->size,
			 (UInt32) 1 << item->dict_bits, &processed);
	grub_free (packed);
	if (res != LZH_OK || processed != item->pack_size)
	{
		grub_error (GRUB_ERR_BAD_FS, "corrupt lzh stream");
		goto fail;
	}
	if (lzh_crc16 (ctx->buf, item->size) != item->crc)
	{
		grub_error (GRUB_ERR_BAD_FS, "lzh crc mismatch");
		goto fail;
	}
	return 1;

fail:
	grub_free (ctx->buf);
	ctx->buf = 0;
	return 0;
}

static grub_ssize_t
grub_lzh_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_lzh_file *ctx = file->data;
	const struct lzh_item *item = &ctx->data->items[ctx->index];
	grub_uint64_t avail;

	if (item->size == 0 || (grub_uint64_t) file->offset >= item->size)
		return 0;
	avail = item->size - file->offset;
	if (len > avail)
		len = (grub_size_t) avail;
	if (len == 0)
		return 0;

	if (item->method == LZH_M_COPY)
	{
		if (grub_disk_read (ctx->data->disk, 0,
				    item->data_pos + file->offset, len, buf))
			return -1;
		return (grub_ssize_t) len;
	}

	if (!ctx->buf && !lzh_unpack (ctx))
		return -1;
	grub_memcpy (buf, ctx->buf + file->offset, len);
	return (grub_ssize_t) len;
}

static grub_err_t
grub_lzh_close (grub_file_t file)
{
	struct grub_lzh_file *ctx = file->data;

	if (ctx)
	{
		lzh_free_data (ctx->data);
		grub_free (ctx->buf);
		grub_free (ctx);
		file->data = 0;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_lzh_mtime (grub_device_t device, grub_int64_t *tm)
{
	struct grub_lzh_data *data;
	unsigned i;

	*tm = 0;
	data = grub_lzh_mount (device->disk);
	if (!data)
		return grub_errno;
	for (i = 0; i < data->num_items; i++)
		if (data->items[i].mtime > *tm)
			*tm = data->items[i].mtime;
	lzh_free_data (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_lzh_fs =
{
	.name = "lzh",
	.fs_dir = grub_lzh_dir,
	.fs_open = grub_lzh_open,
	.fs_read = grub_lzh_read,
	.fs_close = grub_lzh_close,
	.fs_label = 0,
	.fs_mtime = grub_lzh_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (lzh)
{
	lzh_crc16_init ();
	grub_lzh_fs.mod = mod;
	grub_fs_register (&grub_lzh_fs);
}

GRUB_MOD_FINI (lzh)
{
	grub_fs_unregister (&grub_lzh_fs);
}
