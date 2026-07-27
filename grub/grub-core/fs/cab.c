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

/*
 *  Read-only Microsoft Cabinet (.cab) archive filesystem driver.
 *
 *  Container parsing and folder decoding follow 7-Zip 26.02
 *  (CPP\7zip\Archive\Cab\CabIn.cpp / CabHandler.cpp /
 *  CabBlockInStream.cpp).  MSZIP blocks are inflated with the miniz
 *  tinfl core over a shared 32 KiB history window; LZX and Quantum
 *  live in grub-core\lib\mscab.  Cabinets spanning several volumes
 *  are rejected per entry with a clear error.

 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/datetime.h>
#include <grub/dl.h>

#include <miniz.h>

#include <mscab.h>

GRUB_MOD_LICENSE ("GPLv3+");

/* CFHEADER flags */
#define CAB_FLAG_PREV		1
#define CAB_FLAG_NEXT		2
#define CAB_FLAG_RESERVE	4

/* folder compression methods */
#define CAB_METHOD_NONE		0
#define CAB_METHOD_MSZIP	1
#define CAB_METHOD_QUANTUM	2
#define CAB_METHOD_LZX		3

/* special CFFILE folder indices (multi-volume continuation) */
#define CAB_IFOLDER_FROM_PREV	0xFFFD
#define CAB_IFOLDER_TO_NEXT	0xFFFE
#define CAB_IFOLDER_PREV_NEXT	0xFFFF

#define CAB_ATTR_DIRECTORY	0x10
#define CAB_ATTR_NAME_IS_UTF	0x80

#define CAB_MAX_NAME		(1u << 13)
#define CAB_MAX_ITEMS		(1u << 16)

/* packed data of one logical block (may span continuation records) */
#define CAB_PACK_MAX		(1u << 16)

#define CAB_SEEN_BUCKETS	256

struct cab_folder_ent
{
	grub_uint32_t data_start;
	grub_uint16_t num_blocks;
	grub_uint8_t method;	/* CAB_METHOD_* */
	grub_uint8_t minor;	/* dictionary bits for LZX/Quantum */
};

struct cab_item
{
	char *name;
	grub_uint32_t size;
	grub_uint32_t offset;	/* uncompressed offset inside the folder */
	grub_uint16_t folder;	/* raw iFolder value */
	grub_int64_t mtime;
	unsigned is_dir:1;
	unsigned unsupported:1;	/* spans cabinet volumes */
};

struct grub_cab_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct cab_folder_ent *folders;
	struct cab_item *items;
	unsigned num_folders;
	unsigned num_items;
	grub_uint8_t res_data;	/* per-datablock reserved bytes */
};

static grub_uint16_t
cab_get16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) (p[0] | ((grub_uint16_t) p[1] << 8));
}

static grub_uint32_t
cab_get32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8)
	       | ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

static grub_int64_t
cab_dos_time (grub_uint32_t dos)
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

/* CFDATA checksum (CabBlockInStream.cpp): XOR folded 32-bit words */
static grub_uint32_t
cab_checksum (const grub_uint8_t *p, grub_uint32_t size)
{
	grub_uint32_t sum = 0;

	for (; size >= 4; size -= 4, p += 4)
		sum ^= cab_get32 (p);
	if (size != 0)
	{
		if (size >= 2)
		{
			if (size > 2)
				sum ^= (grub_uint32_t) (*p++) << 16;
			sum ^= (grub_uint32_t) (*p++) << 8;
		}
		sum ^= (grub_uint32_t) (*p);
	}
	return sum;
}

/* reads a NUL terminated string, only to skip it */
static grub_err_t
cab_skip_string (struct grub_cab_data *data, grub_uint64_t *pos)
{
	grub_uint32_t i;

	for (i = 0; i < CAB_MAX_NAME; i++)
	{
		grub_uint8_t b;

		if (grub_disk_read (data->disk, 0, *pos + i, 1, &b))
			return grub_errno;
		if (b == 0)
		{
			*pos += i + 1;
			return GRUB_ERR_NONE;
		}
	}
	return grub_error (GRUB_ERR_BAD_FS, "bad cab string");
}

static void
cab_free_data (struct grub_cab_data *data)
{
	unsigned i;

	if (!data)
		return;
	if (data->items)
		for (i = 0; i < data->num_items; i++)
			grub_free (data->items[i].name);
	grub_free (data->items);
	grub_free (data->folders);
	grub_free (data);
}

static struct grub_cab_data *
grub_cab_mount (grub_disk_t disk)
{
	struct grub_cab_data *data = 0;
	grub_uint8_t hdr[0x28];
	grub_uint8_t *name_buf = 0;
	grub_uint32_t cab_size, coff_files, flags, num_folders, num_files;
	grub_uint8_t res_folder = 0;
	grub_uint64_t pos;
	unsigned i;

	if (grub_disk_read (disk, 0, 0, sizeof (hdr), hdr))
		goto fail;
	if (grub_memcmp (hdr, "MSCF", 4) != 0 || cab_get32 (hdr + 4) != 0
	    || cab_get32 (hdr + 0x0C) != 0 || cab_get32 (hdr + 0x14) != 0)
		goto fail;
	cab_size = cab_get32 (hdr + 8);
	flags = cab_get16 (hdr + 0x1E);
	coff_files = cab_get32 (hdr + 0x10);
	if (cab_size < 36 || flags > 7
	    || (coff_files != 0 && coff_files > cab_size))
		goto fail;
	num_folders = cab_get16 (hdr + 0x1A);
	num_files = cab_get16 (hdr + 0x1C);

	data = grub_zalloc (sizeof (*data));
	if (!data)
		goto fail_data;
	data->disk = disk;
	data->disk_size = grub_disk_native_sectors (disk)
			  << GRUB_DISK_SECTOR_BITS;
	data->num_folders = num_folders;

	pos = 0x24;	/* fixed part + setID + iCabinet */
	if (flags & CAB_FLAG_RESERVE)
	{
		grub_uint8_t res[4];

		if (grub_disk_read (disk, 0, pos, sizeof (res), res))
			goto fail_data;
		res_folder = res[2];
		data->res_data = res[3];
		pos += 4 + cab_get16 (res);
	}
	if (flags & CAB_FLAG_PREV)
	{
		if (cab_skip_string (data, &pos)
		    || cab_skip_string (data, &pos))
			goto fail_data;
	}
	if (flags & CAB_FLAG_NEXT)
	{
		if (cab_skip_string (data, &pos)
		    || cab_skip_string (data, &pos))
			goto fail_data;
	}

	if (num_folders)
	{
		data->folders = grub_calloc (num_folders,
					     sizeof (*data->folders));
		if (!data->folders)
			goto fail_data;
	}
	for (i = 0; i < num_folders; i++)
	{
		grub_uint8_t f[8];

		if (grub_disk_read (disk, 0, pos, sizeof (f), f))
			goto fail_data;
		data->folders[i].data_start = cab_get32 (f);
		data->folders[i].num_blocks = cab_get16 (f + 4);
		data->folders[i].method = f[6] & 0xF;
		data->folders[i].minor = f[7];
		pos += 8 + res_folder;
	}

	if (num_files > CAB_MAX_ITEMS)
		goto fail_data_bad;
	if (num_files)
	{
		data->items = grub_calloc (num_files, sizeof (*data->items));
		if (!data->items)
			goto fail_data;
		name_buf = grub_malloc (CAB_MAX_NAME);
		if (!name_buf)
			goto fail_data;
	}

	pos = coff_files;
	for (i = 0; i < num_files; i++)
	{
		struct cab_item *item = &data->items[i];
		grub_uint8_t fh[16];
		grub_size_t got, j, k;

		if (grub_disk_read (disk, 0, pos, sizeof (fh), fh))
			goto fail_data;
		item->size = cab_get32 (fh);
		item->offset = cab_get32 (fh + 4);
		item->folder = cab_get16 (fh + 8);
		item->mtime = cab_dos_time (((grub_uint32_t)
					     cab_get16 (fh + 10) << 16)
					    | cab_get16 (fh + 12));
		item->is_dir = (cab_get16 (fh + 14) & CAB_ATTR_DIRECTORY)
			       != 0;
		data->num_items = i + 1;
		pos += 16;

		got = CAB_MAX_NAME;
		if (pos + got > data->disk_size)
			got = (grub_size_t) (data->disk_size - pos);
		if (got == 0
		    || grub_disk_read (disk, 0, pos, got, name_buf))
			goto fail_data;
		for (j = 0; j < got && name_buf[j] != 0; j++)
			;
		if (j == got)
			goto fail_data_bad;
		pos += j + 1;

		item->name = grub_malloc (j + 1);
		if (!item->name)
			goto fail_data;
		grub_memcpy (item->name, name_buf, j);
		item->name[j] = '\0';
		for (k = 0; k < j; k++)
			if (item->name[k] == '\\')
				item->name[k] = '/';

		if (item->folder == CAB_IFOLDER_FROM_PREV
		    || item->folder == CAB_IFOLDER_TO_NEXT
		    || item->folder == CAB_IFOLDER_PREV_NEXT)
			item->unsupported = 1;
		else if (item->folder >= num_folders && !item->is_dir
			 && item->size != 0)
			goto fail_data_bad;
	}

	/*
	 * A folder continued from the previous cabinet misses its start;
	 * nothing referencing it can be decoded from this volume alone.
	 */
	for (i = 0; i < data->num_items; i++)
		if (data->items[i].folder == CAB_IFOLDER_FROM_PREV
		    || data->items[i].folder == CAB_IFOLDER_PREV_NEXT)
		{
			unsigned j2;

			for (j2 = 0; j2 < data->num_items; j2++)
				if (data->items[j2].folder == 0)
					data->items[j2].unsupported = 1;
			break;
		}

	grub_free (name_buf);
	return data;

fail_data_bad:
	grub_error (GRUB_ERR_BAD_FS, "corrupt cab header");
fail_data:
	grub_free (name_buf);
	cab_free_data (data);
	return 0;

fail:
	grub_error (GRUB_ERR_BAD_FS, "not a cab filesystem");
	return 0;
}

struct grub_cab_file
{
	struct grub_cab_data *data;
	unsigned target;	/* item index */
	const struct cab_folder_ent *fo;

	/* CFDATA cursor */
	grub_uint64_t block_pos;
	int last_short;
	grub_uint8_t *pack;
	grub_uint32_t pack_size;

	/* decoders (only the folder's one is created) */
	cab_lzx *lzx;
	cab_qtm *qtm;
	tinfl_decompressor *infl;
	grub_uint8_t *dict;	/* 32 KiB MSZIP history ring */
	grub_size_t dict_ofs;
	grub_uint8_t *lin;	/* linear view of the current MSZIP block */

	int started;
	grub_uint64_t stream_pos;	/* folder output consumed so far */
	const grub_uint8_t *cur;	/* current unpacked block */
	grub_uint32_t cur_len;
	grub_uint32_t cur_pos;
};

/* positions the folder stream at its first block, dropping history */
static void
cab_stream_rewind (struct grub_cab_file *ctx)
{
	ctx->block_pos = ctx->fo->data_start;
	ctx->last_short = 0;
	ctx->pack_size = 0;
	ctx->started = 1;
	ctx->stream_pos = 0;
	ctx->cur = 0;
	ctx->cur_len = 0;
	ctx->cur_pos = 0;
	if (ctx->lzx)
		cab_lzx_reset (ctx->lzx);
	if (ctx->qtm)
		cab_qtm_reset (ctx->qtm);
	if (ctx->dict)
	{
		grub_memset (ctx->dict, 0, TINFL_LZ_DICT_SIZE);
		ctx->dict_ofs = 0;
	}
}

/*
 * Reads the next logical CFDATA block into ctx->pack; records with a
 * zero unpacked size only carry packed continuation data and are
 * accumulated (CabHandler keepInputBuffer).
 */
static grub_err_t
cab_read_block (struct grub_cab_file *ctx, grub_uint32_t *unpack_size)
{
	struct grub_cab_data *data = ctx->data;
	grub_uint8_t hdr[8 + 255];
	const grub_uint32_t hdr_size = 8u + data->res_data;

	ctx->pack_size = 0;
	for (;;)
	{
		grub_uint32_t pack, unpack, csum;

		if (grub_disk_read (data->disk, 0, ctx->block_pos, hdr_size,
				    hdr))
			return grub_errno;
		csum = cab_get32 (hdr);
		pack = cab_get16 (hdr + 4);
		unpack = cab_get16 (hdr + 6);
		if (pack > CAB_PACK_MAX - ctx->pack_size)
			return grub_error (GRUB_ERR_BAD_FS,
					   "corrupt cab data");
		if (pack != 0
		    && grub_disk_read (data->disk, 0,
				       ctx->block_pos + hdr_size, pack,
				       ctx->pack + ctx->pack_size))
			return grub_errno;
		if (csum != 0
		    && (cab_checksum (hdr + 4, hdr_size - 4)
			^ cab_checksum (ctx->pack + ctx->pack_size, pack))
		       != csum)
			return grub_error (GRUB_ERR_BAD_FS,
					   "cab block checksum mismatch");
		ctx->pack_size += pack;
		ctx->block_pos += hdr_size + pack;

		if (unpack != 0)
		{
			if (unpack > CAB_BLOCK_MAX || ctx->last_short)
				return grub_error (GRUB_ERR_BAD_FS,
						   "corrupt cab data");
			if (unpack != CAB_BLOCK_MAX)
				ctx->last_short = 1;
			*unpack_size = unpack;
			return GRUB_ERR_NONE;
		}
	}
}

/* inflates one MSZIP block; the 32 KiB ring persists across blocks */
static grub_err_t
cab_mszip_block (struct grub_cab_file *ctx, grub_uint32_t unpack)
{
	grub_size_t in_pos = 2;
	grub_uint32_t produced = 0;

	if (ctx->pack_size < 2 || ctx->pack[0] != 'C' || ctx->pack[1] != 'K')
		return grub_error (GRUB_ERR_BAD_FS, "bad mszip block");

	tinfl_init (ctx->infl);
	for (;;)
	{
		size_t in_bytes = ctx->pack_size - in_pos;
		size_t out_bytes = TINFL_LZ_DICT_SIZE - ctx->dict_ofs;
		tinfl_status st;

		st = tinfl_decompress (ctx->infl, ctx->pack + in_pos,
				       &in_bytes, ctx->dict,
				       ctx->dict + ctx->dict_ofs, &out_bytes,
				       0);
		in_pos += in_bytes;
		if (produced + out_bytes > unpack)
			return grub_error (GRUB_ERR_BAD_FS,
					   "bad mszip block");
		grub_memcpy (ctx->lin + produced, ctx->dict + ctx->dict_ofs,
			     out_bytes);
		ctx->dict_ofs = (ctx->dict_ofs + out_bytes)
				& (TINFL_LZ_DICT_SIZE - 1);
		produced += (grub_uint32_t) out_bytes;

		if (st == TINFL_STATUS_DONE)
			break;
		if (st < TINFL_STATUS_DONE
		    || st == TINFL_STATUS_NEEDS_MORE_INPUT)
			return grub_error (GRUB_ERR_BAD_FS,
					   "bad mszip block");
	}
	if (produced != unpack || in_pos != ctx->pack_size)
		return grub_error (GRUB_ERR_BAD_FS, "bad mszip block");
	ctx->cur = ctx->lin;
	return GRUB_ERR_NONE;
}

/* decodes the next block and exposes it via cur/cur_len */
static grub_err_t
cab_next_block (struct grub_cab_file *ctx)
{
	grub_uint32_t unpack;
	grub_err_t err;
	int r;

	err = cab_read_block (ctx, &unpack);
	if (err)
		return err;

	switch (ctx->fo->method)
	{
	case CAB_METHOD_NONE:
		if (ctx->pack_size != unpack)
			return grub_error (GRUB_ERR_BAD_FS,
					   "corrupt cab data");
		ctx->cur = ctx->pack;
		break;
	case CAB_METHOD_MSZIP:
		err = cab_mszip_block (ctx, unpack);
		if (err)
			return err;
		break;
	case CAB_METHOD_QUANTUM:
		r = cab_qtm_block (ctx->qtm, ctx->pack, ctx->pack_size,
				   unpack, &ctx->cur);
		if (r != CAB_OK)
			return grub_error (r == CAB_ERR_MEM
					   ? GRUB_ERR_OUT_OF_MEMORY
					   : GRUB_ERR_BAD_FS,
					   "bad quantum block");
		break;
	default:	/* CAB_METHOD_LZX */
		r = cab_lzx_block (ctx->lzx, ctx->pack, ctx->pack_size,
				   unpack, &ctx->cur);
		if (r != CAB_OK)
			return grub_error (r == CAB_ERR_MEM
					   ? GRUB_ERR_OUT_OF_MEMORY
					   : GRUB_ERR_BAD_FS,
					   "bad lzx block");
		break;
	}

	ctx->cur_len = unpack;
	ctx->cur_pos = 0;
	return GRUB_ERR_NONE;
}

/* reads decoded folder bytes at the current stream position */
static grub_ssize_t
cab_stream_read (struct grub_cab_file *ctx, grub_uint8_t *buf,
		 grub_size_t len)
{
	grub_size_t done = 0;

	while (done < len)
	{
		grub_size_t n;

		if (ctx->cur_pos == ctx->cur_len)
		{
			if (cab_next_block (ctx))
				return -1;
		}
		n = ctx->cur_len - ctx->cur_pos;
		if (n > len - done)
			n = len - done;
		grub_memcpy (buf + done, ctx->cur + ctx->cur_pos, n);
		ctx->cur_pos += (grub_uint32_t) n;
		done += n;
	}
	ctx->stream_pos += done;
	return (grub_ssize_t) done;
}

static void
cab_file_free (struct grub_cab_file *ctx)
{
	if (!ctx)
		return;
	cab_lzx_free (ctx->lzx);
	cab_qtm_free (ctx->qtm);
	grub_free (ctx->infl);
	grub_free (ctx->dict);
	grub_free (ctx->lin);
	grub_free (ctx->pack);
	cab_free_data (ctx->data);
	grub_free (ctx);
}

/* skips leading slashes and returns the normalized path length */
static const char *
cab_norm_path (const char *path, grub_size_t *len)
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
cab_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
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
	if (slash)
	{
		*child = rest;
		*child_len = (grub_size_t) (slash - rest);
		*is_dir = 1;
	}
	else
	{
		*child = rest;
		*child_len = grub_strlen (rest);
		*is_dir = 0;
	}
	return *child_len != 0;
}

struct cab_seen
{
	struct cab_seen *next;
	char *name;
};

static grub_uint32_t
cab_hash_name (const char *s)
{
	grub_uint32_t h = 5381;

	while (*s)
		h = h * 33 + (grub_uint8_t) *s++;
	return h & (CAB_SEEN_BUCKETS - 1);
}

/* returns 1 when the name was seen before, -1 on allocation failure */
static int
cab_seen_add (struct cab_seen **buckets, char *name)
{
	const grub_uint32_t h = cab_hash_name (name);
	struct cab_seen *ent;

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
grub_cab_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_cab_data *data;
	const char *dir;
	grub_size_t dir_len;
	struct cab_seen **buckets;
	unsigned i;
	int found;
	grub_err_t err = GRUB_ERR_NONE;

	data = grub_cab_mount (device->disk);
	if (!data)
		return grub_errno;

	dir = cab_norm_path (path, &dir_len);
	found = (dir_len == 0);

	buckets = grub_calloc (CAB_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		cab_free_data (data);
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

		if (!data->items[i].name)
			continue;
		if (!cab_name_in_dir (data->items[i].name, dir, dir_len,
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

		dup = cab_seen_add (buckets, name);
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
	for (i = 0; i < CAB_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct cab_seen *ent = buckets[i];

			buckets[i] = ent->next;
			grub_free (ent->name);
			grub_free (ent);
		}
	grub_free (buckets);
	cab_free_data (data);
	return err;
}

static int
cab_find_item (struct grub_cab_data *data, const char *name)
{
	grub_size_t len;
	const char *path = cab_norm_path (name, &len);
	unsigned i;

	for (i = 0; i < data->num_items; i++)
	{
		const char *n = data->items[i].name;

		if (!n)
			continue;
		if (grub_strncmp (n, path, len) == 0 && n[len] == '\0')
			return (int) i;
	}
	return -1;
}

static grub_err_t
grub_cab_open (struct grub_file *file, const char *name)
{
	struct grub_cab_data *data;
	struct grub_cab_file *ctx = 0;
	struct cab_item *item;
	int index;

	data = grub_cab_mount (file->device->disk);
	if (!data)
		return grub_errno;

	index = cab_find_item (data, name);
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
			    "cab entry spans multiple cabinets");
		goto fail;
	}

	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
		goto fail;
	ctx->data = data;
	ctx->target = (unsigned) index;

	if (item->size != 0)
	{
		const struct cab_folder_ent *fo;

		if (item->folder >= data->num_folders)
		{
			grub_error (GRUB_ERR_BAD_FS, "corrupt cab header");
			goto fail;
		}
		fo = &data->folders[item->folder];
		ctx->fo = fo;
		ctx->pack = grub_malloc (CAB_PACK_MAX);
		if (!ctx->pack)
			goto fail;

		switch (fo->method)
		{
		case CAB_METHOD_NONE:
			break;
		case CAB_METHOD_MSZIP:
			ctx->infl = grub_malloc (sizeof (*ctx->infl));
			ctx->dict = grub_malloc (TINFL_LZ_DICT_SIZE);
			ctx->lin = grub_malloc (CAB_BLOCK_MAX);
			if (!ctx->infl || !ctx->dict || !ctx->lin)
				goto fail;
			break;
		case CAB_METHOD_QUANTUM:
			ctx->qtm = cab_qtm_create (fo->minor);
			if (!ctx->qtm)
			{
				if (!grub_errno)
					grub_error (GRUB_ERR_BAD_FS,
						"bad quantum dictionary size");
				goto fail;
			}
			break;
		case CAB_METHOD_LZX:
			ctx->lzx = cab_lzx_create (fo->minor);
			if (!ctx->lzx)
			{
				if (!grub_errno)
					grub_error (GRUB_ERR_BAD_FS,
						"bad lzx dictionary size");
				goto fail;
			}
			break;
		default:
			grub_error (GRUB_ERR_BAD_FS,
				    "unsupported cab method %u",
				    (unsigned) fo->method);
			goto fail;
		}
	}

	file->data = ctx;
	file->size = item->size;
	file->not_easily_seekable = 1;
	return GRUB_ERR_NONE;

fail:
	if (ctx)
	{
		ctx->data = 0;
		cab_file_free (ctx);
	}
	cab_free_data (data);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

static grub_ssize_t
grub_cab_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_cab_file *ctx = file->data;
	const struct cab_item *item = &ctx->data->items[ctx->target];
	grub_uint64_t want;

	if (len == 0 || item->size == 0)
		return 0;

	want = (grub_uint64_t) item->offset + file->offset;

	if (ctx->started && want < ctx->stream_pos)
		ctx->started = 0;
	if (!ctx->started)
		cab_stream_rewind (ctx);

	/* discard folder output up to the requested position */
	while (ctx->stream_pos < want)
	{
		grub_size_t n;

		if (ctx->cur_pos == ctx->cur_len)
		{
			if (cab_next_block (ctx))
				return -1;
		}
		n = ctx->cur_len - ctx->cur_pos;
		if ((grub_uint64_t) n > want - ctx->stream_pos)
			n = (grub_size_t) (want - ctx->stream_pos);
		ctx->cur_pos += (grub_uint32_t) n;
		ctx->stream_pos += n;
	}

	return cab_stream_read (ctx, (grub_uint8_t *) buf, len);
}

static grub_err_t
grub_cab_close (grub_file_t file)
{
	cab_file_free (file->data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cab_mtime (grub_device_t device, grub_int64_t *tm)
{
	struct grub_cab_data *data;
	unsigned i;

	*tm = 0;
	data = grub_cab_mount (device->disk);
	if (!data)
		return grub_errno;
	for (i = 0; i < data->num_items; i++)
		if (data->items[i].mtime > *tm)
			*tm = data->items[i].mtime;
	cab_free_data (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_cab_fs =
{
	.name = "cab",
	.fs_dir = grub_cab_dir,
	.fs_open = grub_cab_open,
	.fs_read = grub_cab_read,
	.fs_close = grub_cab_close,
	.fs_label = 0,
	.fs_mtime = grub_cab_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (cab)
{
	grub_cab_fs.mod = mod;
	grub_fs_register (&grub_cab_fs);
}

GRUB_MOD_FINI (cab)
{
	grub_fs_unregister (&grub_cab_fs);
}
