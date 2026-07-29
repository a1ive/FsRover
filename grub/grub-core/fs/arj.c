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

/*  Read-only ARJ archive filesystem driver.
 *
 *  Container semantics follow 7-Zip 26.02 CPP\7zip\Archive\ArjHandler.cpp:
 *  a main header block followed by one block per entry, every block CRC32
 *  protected and optionally trailed by extended header blocks, with the
 *  packed data sitting right behind each entry's block chain.
 *
 *  Methods: 0 (stored), 1..3 (LZH with a 26624 byte dictionary) and 4
 *  (ARJ's own coder); both decoders live in grub-core\lib\7z\LzhDecoder.c.
 *  Methods 8 and 9 carry no data.  Garbled (password protected) entries,
 *  and entries continued in another volume, are rejected at open time.
 *  Names are stored in an OEM code page which is not translated here.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/datetime.h>
#include <grub/dl.h>

#include <7zCrc.h>
#include <LzhDecoder.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define ARJ_SIG0		0x60
#define ARJ_SIG1		0xEA
#define ARJ_BLOCK_MIN		30
#define ARJ_BLOCK_MAX		2600
#define ARJ_EXT_BLOCK_MAX	((1u << 16) - 1)

/* compression methods */
#define ARJ_M_STORED		0
#define ARJ_M_COMPRESSED1A	1
#define ARJ_M_COMPRESSED1B	2
#define ARJ_M_COMPRESSED1C	3
#define ARJ_M_COMPRESSED2	4
#define ARJ_M_NO_DATA_NO_CRC	8
#define ARJ_M_NO_DATA		9

/* file types */
#define ARJ_T_ARCHIVE_HEADER	2
#define ARJ_T_DIRECTORY		3

/* flags */
#define ARJ_F_GARBLED		0x01
#define ARJ_F_VOLUME		0x04
#define ARJ_F_EXTFILE		0x08

#define ARJ_UNPACK_MAX		((grub_uint64_t) 256 << 20)
#define ARJ_ITEMS_MAX		(1u << 20)
#define ARJ_SEEN_BUCKETS	512

struct arj_item
{
	char *name;		/* full path, '/' separated, no trailing '/' */
	grub_uint64_t data_pos;
	grub_uint32_t pack_size;
	grub_uint32_t size;
	grub_uint32_t crc;
	grub_uint8_t method;
	grub_uint8_t is_dir;
	grub_uint8_t unsupported;	/* garbled or split entry */
	grub_int64_t mtime;
};

struct grub_arj_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct arj_item *items;
	unsigned num_items;
	unsigned cap_items;
};

struct grub_arj_file
{
	struct grub_arj_data *data;
	unsigned index;
	grub_uint8_t *buf;	/* unpacked content, 0 until first read */
};

static grub_uint16_t
arj_get16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
arj_get32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_int64_t
arj_dos_time (grub_uint32_t dos)
{
	struct grub_datetime dt;
	grub_int64_t nix = 0;

	if (dos == 0)
		return 0;
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

/* ---------------- block reader ---------------- */

struct arj_reader
{
	grub_disk_t disk;
	grub_uint64_t size;
	grub_uint64_t pos;
	grub_uint8_t *block;
	grub_uint32_t block_size;
	grub_size_t block_cap;
};

static int
arj_read_at (struct arj_reader *r, void *buf, grub_size_t want)
{
	if (r->pos > r->size || want > r->size - r->pos)
		return 0;
	if (want != 0 && grub_disk_read (r->disk, 0, r->pos, want, buf))
		return 0;
	r->pos += want;
	return 1;
}

/*
 * CArc::ReadBlock(): 1 = block read, 0 = terminating zero size block,
 * -1 = corrupt or truncated.  `ext` marks an extended header block, which
 * carries no signature and may be up to 64 KiB.
 */
static int
arj_read_block (struct arj_reader *r, int ext)
{
	grub_uint8_t buf[4];
	const unsigned sig_size = ext ? 0 : 2;
	grub_size_t need;

	if (!arj_read_at (r, buf, sig_size + 2))
		return -1;
	if (!ext && (buf[0] != ARJ_SIG0 || buf[1] != ARJ_SIG1))
		return -1;
	r->block_size = arj_get16 (buf + sig_size);
	if (r->block_size == 0)
		return 0;
	if (!ext && (r->block_size < ARJ_BLOCK_MIN
		     || r->block_size > ARJ_BLOCK_MAX))
		return -1;
	if (ext && r->block_size > ARJ_EXT_BLOCK_MAX)
		return -1;

	need = (grub_size_t) r->block_size + 4;
	if (need > r->block_cap)
	{
		grub_uint8_t *n = grub_realloc (r->block, need);

		if (!n)
			return -1;
		r->block = n;
		r->block_cap = need;
	}
	if (!arj_read_at (r, r->block, need))
		return -1;
	if (arj_get32 (r->block + r->block_size)
	    != CrcCalc (r->block, r->block_size))
		return -1;
	return 1;
}

/* CArc::SkipExtendedHeaders() */
static int
arj_skip_ext (struct arj_reader *r)
{
	for (;;)
	{
		const int res = arj_read_block (r, 1);

		if (res < 0)
			return 0;
		if (res == 0)
			return 1;
	}
}

/* reads a NUL terminated string out of the block, advancing *pos */
static char *
arj_read_string (const grub_uint8_t *p, grub_uint32_t size, unsigned *pos)
{
	unsigned i = *pos;
	unsigned start = i;
	char *s;

	while (i < size && p[i] != 0)
		i++;
	if (i >= size)
		return 0;
	s = grub_malloc (i - start + 1);
	if (!s)
		return 0;
	grub_memcpy (s, p + start, i - start);
	s[i - start] = '\0';
	*pos = i + 1;
	return s;
}

/* ---------------- mount ---------------- */

static void
arj_free_data (struct grub_arj_data *data)
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
arj_add_item (struct grub_arj_data *data, const struct arj_item *item)
{
	if (data->num_items >= ARJ_ITEMS_MAX)
		return 0;
	if (data->num_items == data->cap_items)
	{
		const unsigned cap = data->cap_items ? data->cap_items * 2 : 64;
		struct arj_item *n = grub_realloc (data->items,
						   cap * sizeof (*n));

		if (!n)
			return 0;
		data->items = n;
		data->cap_items = cap;
	}
	data->items[data->num_items++] = *item;
	return 1;
}

/*
 * '\' and '/' both act as separators; empty, "." and ".." components are
 * dropped so that every entry names exactly one place in the tree.
 */
static void
arj_normalize_name (char *s)
{
	char *rd;
	char *wr = s;

	for (rd = s; *rd; rd++)
		if (*rd == '\\')
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

static struct grub_arj_data *
grub_arj_mount (grub_disk_t disk)
{
	struct grub_arj_data *data = 0;
	struct arj_reader r;
	grub_uint8_t magic[4];

	r.block = 0;
	r.block_cap = 0;

	if (grub_disk_read (disk, 0, 0, sizeof (magic), magic))
		goto fail;
	if (magic[0] != ARJ_SIG0 || magic[1] != ARJ_SIG1)
		goto fail;
	{
		const grub_uint32_t bs = arj_get16 (magic + 2);

		if (bs < ARJ_BLOCK_MIN || bs > ARJ_BLOCK_MAX)
			goto fail;
	}

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return 0;
	data->disk = disk;
	data->disk_size = grub_disk_native_sectors (disk)
			  << GRUB_DISK_SECTOR_BITS;

	r.disk = disk;
	r.size = data->disk_size;
	r.pos = 0;

	/* main header */
	if (arj_read_block (&r, 0) != 1)
		goto fail_data;
	if (r.block[0] < ARJ_BLOCK_MIN || r.block[0] > r.block_size
	    || r.block[6] != ARJ_T_ARCHIVE_HEADER)
		goto fail_data;
	if (!arj_skip_ext (&r))
		goto fail_data;

	for (;;)
	{
		struct arj_item item;
		const grub_uint8_t *p;
		unsigned pos;
		char *comment;
		int res = arj_read_block (&r, 0);

		if (res <= 0)
			break;

		p = r.block;
		if (p[0] < ARJ_BLOCK_MIN || p[0] > r.block_size)
			break;

		grub_memset (&item, 0, sizeof (item));
		item.method = p[5];
		item.is_dir = (p[6] == ARJ_T_DIRECTORY);
		item.mtime = arj_dos_time (arj_get32 (p + 8));
		item.pack_size = arj_get32 (p + 12);
		item.size = arj_get32 (p + 16);
		item.crc = arj_get32 (p + 20);
		item.unsupported = (p[4] & (ARJ_F_GARBLED | ARJ_F_VOLUME
					    | ARJ_F_EXTFILE)) != 0;

		pos = p[0];
		item.name = arj_read_string (p, r.block_size, &pos);
		if (!item.name)
			break;
		comment = arj_read_string (p, r.block_size, &pos);
		grub_free (comment);

		if (!arj_skip_ext (&r))
		{
			grub_free (item.name);
			break;
		}

		arj_normalize_name (item.name);
		item.data_pos = r.pos;
		if (item.is_dir)
			item.size = 0;

		if (item.name[0] == '\0')
			grub_free (item.name);
		else if (!arj_add_item (data, &item))
		{
			grub_free (item.name);
			goto fail_data;
		}

		if (r.pos + item.pack_size > r.size)
			break;
		r.pos += item.pack_size;
	}

	grub_free (r.block);
	r.block = 0;
	if (data->num_items == 0)
	{
		arj_free_data (data);
		data = 0;
		goto fail;
	}
	return data;

fail_data:
	grub_free (r.block);
	arj_free_data (data);
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "corrupt arj archive");
	return 0;

fail:
	grub_free (r.block);
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "not an arj archive");
	return 0;
}

/* ---------------- directory listing ---------------- */

static const char *
arj_norm_path (const char *path, grub_size_t *len)
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
arj_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
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

struct arj_seen
{
	struct arj_seen *next;
	char *name;
};

static grub_uint32_t
arj_hash_name (const char *s)
{
	grub_uint32_t h = 5381;

	while (*s)
		h = h * 33 + (grub_uint8_t) *s++;
	return h & (ARJ_SEEN_BUCKETS - 1);
}

/* returns 1 when the name was seen before, -1 on allocation failure */
static int
arj_seen_add (struct arj_seen **buckets, char *name)
{
	const grub_uint32_t h = arj_hash_name (name);
	struct arj_seen *ent;

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
grub_arj_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_arj_data *data;
	const char *dir;
	grub_size_t dir_len;
	struct arj_seen **buckets;
	unsigned i;
	int found;
	grub_err_t err = GRUB_ERR_NONE;

	data = grub_arj_mount (device->disk);
	if (!data)
		return grub_errno;

	dir = arj_norm_path (path, &dir_len);
	found = (dir_len == 0);

	buckets = grub_calloc (ARJ_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		arj_free_data (data);
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

		if (!arj_name_in_dir (data->items[i].name, dir, dir_len,
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

		dup = arj_seen_add (buckets, name);
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
	for (i = 0; i < ARJ_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct arj_seen *ent = buckets[i];

			buckets[i] = ent->next;
			grub_free (ent->name);
			grub_free (ent);
		}
	grub_free (buckets);
	arj_free_data (data);
	return err;
}

/* ---------------- file access ---------------- */

static int
arj_find_item (struct grub_arj_data *data, const char *name)
{
	grub_size_t len;
	const char *path = arj_norm_path (name, &len);
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
grub_arj_open (struct grub_file *file, const char *name)
{
	struct grub_arj_data *data;
	struct grub_arj_file *ctx;
	const struct arj_item *item;
	int index;

	data = grub_arj_mount (file->device->disk);
	if (!data)
		return grub_errno;

	index = arj_find_item (data, name);
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
	if (item->unsupported)
	{
		grub_error (GRUB_ERR_BAD_FS,
			    "encrypted or multi-volume arj entries are not"
			    " supported");
		goto fail;
	}
	switch (item->method)
	{
	case ARJ_M_STORED:
		if (item->pack_size != item->size)
		{
			grub_error (GRUB_ERR_BAD_FS,
				    "corrupt stored arj entry");
			goto fail;
		}
		break;
	case ARJ_M_COMPRESSED1A:
	case ARJ_M_COMPRESSED1B:
	case ARJ_M_COMPRESSED1C:
	case ARJ_M_COMPRESSED2:
		if (item->size > ARJ_UNPACK_MAX)
		{
			grub_error (GRUB_ERR_BAD_FS,
				    "arj entry too large to unpack");
			goto fail;
		}
		break;
	default:
		grub_error (GRUB_ERR_BAD_FS, "unsupported arj method %u",
			    (unsigned) item->method);
		goto fail;
	}
	if (item->data_pos > data->disk_size
	    || item->pack_size > data->disk_size - item->data_pos)
	{
		grub_error (GRUB_ERR_BAD_FS, "truncated arj archive");
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
	arj_free_data (data);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

/* unpacks the whole entry once, verifying its CRC-32 */
static int
arj_unpack (struct grub_arj_file *ctx)
{
	const struct arj_item *item = &ctx->data->items[ctx->index];
	grub_uint8_t *packed = 0;
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

	if (item->method == ARJ_M_COMPRESSED2)
		res = ArjDecode (packed, item->pack_size, ctx->buf,
				 item->size, &processed);
	else
		res = LzhDecode (packed, item->pack_size, ctx->buf,
				 item->size, LZH_DICT_ARJ, &processed);
	grub_free (packed);
	packed = 0;
	if (res != LZH_OK || processed != item->pack_size)
	{
		grub_error (GRUB_ERR_BAD_FS, "corrupt arj stream");
		goto fail;
	}
	if (CrcCalc (ctx->buf, item->size) != item->crc)
	{
		grub_error (GRUB_ERR_BAD_FS, "arj crc mismatch");
		goto fail;
	}
	return 1;

fail:
	grub_free (packed);
	grub_free (ctx->buf);
	ctx->buf = 0;
	return 0;
}

static grub_ssize_t
grub_arj_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_arj_file *ctx = file->data;
	const struct arj_item *item = &ctx->data->items[ctx->index];
	grub_uint64_t avail;

	if (item->size == 0 || (grub_uint64_t) file->offset >= item->size)
		return 0;
	avail = item->size - file->offset;
	if (len > avail)
		len = (grub_size_t) avail;
	if (len == 0)
		return 0;

	if (item->method == ARJ_M_STORED)
	{
		if (grub_disk_read (ctx->data->disk, 0,
				    item->data_pos + file->offset, len, buf))
			return -1;
		return (grub_ssize_t) len;
	}

	if (!ctx->buf && !arj_unpack (ctx))
		return -1;
	grub_memcpy (buf, ctx->buf + file->offset, len);
	return (grub_ssize_t) len;
}

static grub_err_t
grub_arj_close (grub_file_t file)
{
	struct grub_arj_file *ctx = file->data;

	if (ctx)
	{
		arj_free_data (ctx->data);
		grub_free (ctx->buf);
		grub_free (ctx);
		file->data = 0;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_arj_mtime (grub_device_t device, grub_int64_t *tm)
{
	struct grub_arj_data *data;
	unsigned i;

	*tm = 0;
	data = grub_arj_mount (device->disk);
	if (!data)
		return grub_errno;
	for (i = 0; i < data->num_items; i++)
		if (data->items[i].mtime > *tm)
			*tm = data->items[i].mtime;
	arj_free_data (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_arj_fs =
{
	.name = "arj",
	.fs_dir = grub_arj_dir,
	.fs_open = grub_arj_open,
	.fs_read = grub_arj_read,
	.fs_close = grub_arj_close,
	.fs_label = 0,
	.fs_mtime = grub_arj_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (arj)
{
	CrcGenerateTable ();
	grub_arj_fs.mod = mod;
	grub_fs_register (&grub_arj_fs);
}

GRUB_MOD_FINI (arj)
{
	grub_fs_unregister (&grub_arj_fs);
}
