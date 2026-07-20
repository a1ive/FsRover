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
 * Convention:
 * grub_errno is reset on entry and cleared again on success,
 * so rover_last_error() reflects the most recent rover call only.
 */

#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/device.h>
#include <grub/disk.h>
#include <grub/fs.h>
#include <grub/file.h>
#include <grub/partition.h>
#include <grub/diskfilter.h>
#include <grub/cryptodisk.h>

#include "rover.h"

/*
 * Detect a locked LUKS1/LUKS2 container by its on-disk magic, without
 * unlocking it.  Both formats begin with "LUKS\xBA\xBE" and a big-endian
 * u16 version (1 or 2) and store a NUL-terminated UUID at offset 168.
 * Returns 1 and fills *type ("luks"/"luks2") and UUID_BUF on a match.
 */
static int
rover_detect_luks (grub_disk_t disk, const char **type, char *uuid_buf, grub_size_t uuid_size)
{
	static const grub_uint8_t magic[6] = { 'L', 'U', 'K', 'S', 0xBA, 0xBE };
	grub_uint8_t hdr[256];
	grub_uint16_t version;
	grub_size_t i;

	/* grub_fs_probe() leaves GRUB_ERR_UNKNOWN_FS behind on an encrypted
	   volume.  Do not let that expected probe result poison this read.  */
	grub_errno = GRUB_ERR_NONE;
	if (grub_disk_read (disk, 0, 0, sizeof (hdr), hdr) != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}

	if (grub_memcmp (hdr, magic, sizeof (magic)) != 0)
		return 0;

	version = grub_be_to_cpu16 (grub_get_unaligned16 (hdr + 6));
	if (version == 1)
		*type = "luks";
	else if (version == 2)
		*type = "luks2";
	else
		return 0;

	/* UUID field: 40 bytes at offset 168, NUL-terminated ASCII.  */
	for (i = 0; i + 1 < uuid_size && i < 40 && hdr[168 + i]; i++)
		uuid_buf[i] = (char) hdr[168 + i];
	uuid_buf[i] = '\0';
	return 1;
}

/*
 * Detect a locked BitLocker (FVE) volume by its on-disk signature, without
 * unlocking it.  Fixed drives carry "-FVE-FS-" at offset 3 (volume GUID at
 * 0xa0); BitLocker-To-Go volumes carry "MSWIN4.1" (volume GUID at 0x1a8).
 * Returns 1 and fills *type ("bitlocker") and the formatted volume GUID.
 */
static int
rover_detect_bitlocker (grub_disk_t disk, const char **type,
			char *uuid_buf, grub_size_t uuid_size)
{
	static const char hex[] = "0123456789abcdef";
	/* Microsoft GUID string order: first three groups little-endian.  */
	static const signed char order[] =
	{
		3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1,
		8, 9, -1, 10, 11, 12, 13, 14, 15
	};
	grub_uint8_t hdr[512];
	const grub_uint8_t *guid;
	grub_size_t i, n = 0;

	grub_errno = GRUB_ERR_NONE;
	if (grub_disk_read (disk, 0, 0, sizeof (hdr), hdr) != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}

	if (grub_memcmp (hdr + 3, "-FVE-FS-", 8) == 0)
		guid = hdr + 0xa0;
	else if (grub_memcmp (hdr + 3, "MSWIN4.1", 8) == 0)
		guid = hdr + 0x1a8;
	else
		return 0;

	*type = "bitlocker";

	for (i = 0; i < ARRAY_SIZE (order) && n + 2 < uuid_size; i++)
	{
		int idx = order[i];

		if (idx < 0)
		{
			uuid_buf[n++] = '-';
			continue;
		}
		uuid_buf[n++] = hex[guid[idx] >> 4];
		uuid_buf[n++] = hex[guid[idx] & 0xf];
	}
	uuid_buf[n] = '\0';
	return 1;
}

/*
 * Detect a locked FreeBSD GELI container, without unlocking it.  Unlike
 * LUKS/BitLocker, the GELI metadata lives in the *last* sector of the
 * volume ("GEOM::ELI" magic + a little-endian version 1..7) and the UUID
 * is not stored but derived: it is the hex of HMAC-SHA256(salt, "uuid"),
 * matching make_uuid() in disk\geli.c.  Fields are read by offset from
 * the packed on-disk header (magic[16], version@16, salt[64]@47).
 * Returns 1 and fills *type ("geli") and UUID_BUF on a match.
 */
static int
rover_detect_geli (grub_disk_t disk, const char **type, char *uuid_buf, grub_size_t uuid_size)
{
	static const char hex[] = "0123456789abcdef";
	grub_uint8_t hdr[512];
	grub_uint8_t uuidbin[GRUB_CRYPTODISK_MAX_UUID_LENGTH];
	grub_disk_addr_t sectors;
	grub_uint32_t version;
	grub_size_t i, n, mdlen;

	sectors = grub_disk_native_sectors (disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN || sectors == 0)
		return 0;

	grub_errno = GRUB_ERR_NONE;
	if (grub_disk_read (disk, sectors - 1, 0, sizeof (hdr), hdr)
	    != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}

	if (grub_memcmp (hdr, "GEOM::ELI", sizeof ("GEOM::ELI")) != 0)
		return 0;

	version = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 16));
	if (version < 1 || version > 7)
		return 0;

	*type = "geli";

	/* UUID = hex(HMAC-SHA256(salt[64]@47, "uuid")); salt is the key.  */
	mdlen = GRUB_MD_SHA256->mdlen;
	if (2 * mdlen + 1 > uuid_size
		|| grub_crypto_hmac_buffer (GRUB_MD_SHA256, hdr + 47, 64, "uuid", sizeof ("uuid") - 1, uuidbin))
	{
		grub_errno = GRUB_ERR_NONE;
		uuid_buf[0] = '\0';
		return 1;
	}
	for (i = 0, n = 0; i < mdlen; i++)
	{
		uuid_buf[n++] = hex[uuidbin[i] >> 4];
		uuid_buf[n++] = hex[uuidbin[i] & 0xf];
	}
	uuid_buf[n] = '\0';
	return 1;
}

/*
 * grub_error() prepends "file:function:line:" to every message (see
 * grub_error() in kern/err.c).  That location tag is developer noise in
 * a user-facing status bar, so skip it: scan for the first
 * ":<identifier>:<digits>:" run -- the function/line separators -- and
 * return whatever follows.  A Windows __FILE__ ("C:\...\fs.c") has only
 * the drive-letter colon, which is followed by a backslash and never
 * matches; a message without the tag (grub_user_error) falls through
 * unchanged.
 */
static const char *
rover_strip_location (const char *msg)
{
	const char *p;

	for (p = msg; *p != '\0'; p++)
	{
		const char *q = p;

		if (*q != ':')
			continue;
		q++;
		/* function name: a C identifier */
		if (!grub_isalpha ((grub_uint8_t) *q) && *q != '_')
			continue;
		do
			q++;
		while (grub_isalnum ((grub_uint8_t) *q) || *q == '_');
		if (*q != ':')
			continue;
		q++;
		/* line number: one or more digits */
		if (!grub_isdigit ((grub_uint8_t) *q))
			continue;
		do
			q++;
		while (grub_isdigit ((grub_uint8_t) *q));
		if (*q != ':')
			continue;
		return q + 1;
	}
	return msg;
}

const char *
rover_last_error (void)
{
	if (grub_errno == GRUB_ERR_NONE)
		return NULL;
	return rover_strip_location (grub_errmsg);
}

/* Disk/volume enumeration */

struct enum_ctx
{
	rover_disk_hook cb;
	void *data;
};

/*
 * Member devices of a diskfilter volume (LVM/LDM/mdraid/dmraid): its
 * physical volumes, one grub device name per line.  disk->data is the
 * logical volume; each PV points at the disk it lives on (or, when that
 * disk is missing, carries only its own recorded name).  Returns a
 * grub_malloc'd string the caller frees, or NULL if there is nothing to
 * report.
 */
static char *
rover_diskfilter_parents (grub_disk_t disk)
{
	struct grub_diskfilter_lv *lv = disk->data;
	struct grub_diskfilter_pv *pv;
	grub_size_t total = 0;
	char *out;
	char *p;

	if (!lv || !lv->vg)
		return NULL;

	for (pv = lv->vg->pvs; pv; pv = pv->next)
	{
		const char *n = pv->disk ? pv->disk->name : pv->name;
		if (n)
			total += grub_strlen (n) + 1;	/* separator or NUL */
	}
	if (!total)
		return NULL;

	out = grub_malloc (total);
	if (!out)
		return NULL;

	p = out;
	for (pv = lv->vg->pvs; pv; pv = pv->next)
	{
		const char *n = pv->disk ? pv->disk->name : pv->name;
		grub_size_t len;

		if (!n)
			continue;
		if (p != out)
			*p++ = '\n';
		len = grub_strlen (n);
		grub_memcpy (p, n, len);
		p += len;
	}
	*p = '\0';
	return out;
}

static int
enum_disk_shim (const char *name, void *data)
{
	struct enum_ctx *ctx = data;
	struct rover_disk_info info;
	grub_device_t dev;
	grub_fs_t fs;
	grub_uint64_t sectors;
	char *label = NULL;
	char *uuid = NULL;
	char *parents = NULL;
	char crypto_uuid[GRUB_CRYPTODISK_MAX_UUID_LENGTH + 1];
	int ret;

	grub_memset (&info, 0, sizeof (info));
	info.name = name;
	info.size = ROVER_SIZE_UNKNOWN;

	dev = grub_device_open (name);
	if (!dev)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}

	if (dev->disk)
	{
		info.is_partition = dev->disk->partition != NULL;
		sectors = grub_disk_native_sectors (dev->disk);
		if (sectors != GRUB_DISK_SIZE_UNKNOWN)
			info.size = sectors << GRUB_DISK_SECTOR_BITS;
		info.sector_size = 1U << dev->disk->log_sector_size;
		/* Partition start, in the disk's own sector units (the value in
		   the partition table); grub_partition_get_start() is normalised
		   to 512-byte sectors.  */
		if (dev->disk->partition)
			info.start_lba = grub_disk_to_native_sector (dev->disk,
				grub_partition_get_start (dev->disk->partition));
		switch (dev->disk->dev->id)
		{
		case GRUB_DISK_DEVICE_HOSTDISK_ID:
			info.dev_id = ROVER_DEV_WINDISK;
			break;
		case GRUB_DISK_DEVICE_LOOPBACK_ID:
			info.dev_id = ROVER_DEV_LOOPBACK;
			info.parent_file = rover_loopback_get_file (name);
			break;
		case GRUB_DISK_DEVICE_DISKFILTER_ID:
			info.dev_id = ROVER_DEV_DISKFILTER;
			parents = rover_diskfilter_parents (dev->disk);
			info.parents = parents;
			break;
		case GRUB_DISK_DEVICE_CRYPTODISK_ID:
			info.dev_id = ROVER_DEV_CRYPTODISK;
			break;
		case GRUB_DISK_DEVICE_PROCFS_ID:
			info.dev_id = ROVER_DEV_PROCFS;
			break;
		default:
			break;
		}
	}

	fs = grub_fs_probe (dev);
	if (fs)
	{
		info.fs = fs->name;
		if (fs->fs_label && (fs->fs_label) (dev, &label) == GRUB_ERR_NONE)
			info.label = label;
		if (fs->fs_uuid && (fs->fs_uuid) (dev, &uuid) == GRUB_ERR_NONE)
			info.fs_uuid = uuid;
	}
	else if (dev->disk != NULL && grub_cryptodisk_get_by_source_disk (dev->disk) == NULL)
	{
		/* No readable fs and not already unlocked: flag a locked
		   LUKS/LUKS2/BitLocker/GELI container so the GUI can prompt
		   for a key.  */
		const char *ctype = NULL;

		if (rover_detect_luks (dev->disk, &ctype, crypto_uuid, sizeof (crypto_uuid))
			|| rover_detect_bitlocker (dev->disk, &ctype, crypto_uuid, sizeof (crypto_uuid))
			|| rover_detect_geli (dev->disk, &ctype, crypto_uuid, sizeof (crypto_uuid)))
		{
			info.encrypted = 1;
			info.crypto_type = ctype;
			info.crypto_uuid = crypto_uuid;
		}
	}
	grub_errno = GRUB_ERR_NONE;

	ret = ctx->cb (&info, ctx->data);

	grub_free (label);
	grub_free (uuid);
	grub_free (parents);
	grub_device_close (dev);
	grub_errno = GRUB_ERR_NONE;
	return ret;
}

int
rover_enum_disks (rover_disk_hook cb, void *data)
{
	struct enum_ctx ctx = { cb, data };
	int ret;

	grub_errno = GRUB_ERR_NONE;
	ret = grub_device_iterate (enum_disk_shim, &ctx);
	grub_errno = GRUB_ERR_NONE;
	return ret;
}

/* Directory enumeration */

struct dir_ctx
{
	rover_dir_hook cb;
	void *data;
};

static int
dir_hook_shim (const char *filename, const struct grub_dirhook_info *info, void *data)
{
	struct dir_ctx *ctx = data;
	struct rover_dirent ent;

	if (grub_strcmp (filename, ".") == 0
		|| grub_strcmp (filename, "..") == 0)
		return 0;

	ent.name = filename;
	ent.is_dir = info->dir ? 1 : 0;
	ent.is_symlink = info->symlink ? 1 : 0;
	ent.mtime_set = info->mtimeset ? 1 : 0;
	ent.mtime = info->mtimeset ? info->mtime : 0;
	return ctx->cb (&ent, ctx->data);
}

int
rover_dir_list (const char *path, rover_dir_hook cb, void *data)
{
	struct dir_ctx ctx = { cb, data };
	grub_device_t dev = NULL;
	grub_fs_t fs;
	char *device_name = NULL;
	const char *fs_path;
	int err;

	grub_errno = GRUB_ERR_NONE;
	if (path[0] != '(')
		return grub_error (GRUB_ERR_BAD_FILENAME, "no device in path `%s'", path);

	device_name = grub_file_get_device_name (path);
	if (grub_errno)
		goto fail;

	dev = grub_device_open (device_name);
	if (!dev)
		goto fail;

	fs = grub_fs_probe (dev);
	if (!fs)
		goto fail;

	fs_path = grub_strchr (path, ')') + 1;
	if (*fs_path == '\0')
		fs_path = "/";

	(fs->fs_dir) (dev, fs_path, dir_hook_shim, &ctx);
	if (grub_errno)
		goto fail;

	grub_free (device_name);
	grub_device_close (dev);
	grub_errno = GRUB_ERR_NONE;
	return 0;

fail:
	err = grub_errno;
	grub_free (device_name);
	if (dev)
		grub_device_close (dev);
	grub_errno = err;
	return err;
}

/* File access */

struct rover_file
{
	grub_file_t file;
};

rover_file *
rover_file_open (const char *path)
{
	rover_file *f;
	grub_file_t file;

	grub_errno = GRUB_ERR_NONE;
	file = grub_file_open (path, GRUB_FILE_TYPE_CAT | GRUB_FILE_TYPE_NO_DECOMPRESS);
	if (!file)
		return NULL;

	f = grub_malloc (sizeof (*f));
	if (!f)
	{
		int err = grub_errno;
		grub_file_close (file);
		grub_errno = err;
		return NULL;
	}
	f->file = file;
	return f;
}

long long
rover_file_read (rover_file *f, void *buf, unsigned long long len)
{
	unsigned long long max = (grub_size_t) -1;

	grub_errno = GRUB_ERR_NONE;
	if (len > max)
		len = max;
	return grub_file_read (f->file, buf, (grub_size_t) len);
}

int
rover_file_seek (rover_file *f, unsigned long long offset)
{
	grub_errno = GRUB_ERR_NONE;
	grub_file_seek (f->file, offset);
	return grub_errno;
}

unsigned long long
rover_file_size (rover_file *f)
{
	return grub_file_size (f->file);
}

void
rover_file_close (rover_file *f)
{
	grub_file_close (f->file);
	grub_free (f);
	grub_errno = GRUB_ERR_NONE;
}

/* Read progress */

static rover_progress_hook progress_cb;
static void *progress_data;

static grub_err_t
progress_shim (grub_disk_addr_t sector, unsigned offset, unsigned length, char *buf, void *data)
{
	grub_file_t file = data;

	(void) sector;
	(void) offset;
	(void) buf;
	/* DATA is the file being read and progress_offset accumulates across nested reads.  */
	file->progress_offset += length;
	progress_cb (file->progress_offset, file->size, progress_data);
	return GRUB_ERR_NONE;
}

void
rover_set_progress (rover_progress_hook cb, void *data)
{
	progress_cb = cb;
	progress_data = data;
	grub_file_progress_hook = cb ? progress_shim : NULL;
}

/* Metadata */

struct stat_ctx
{
	const char *name;
	int found;
	rover_stat_t *st;
};

static int
stat_dir_hook (const char *filename, const struct grub_dirhook_info *info, void *data)
{
	struct stat_ctx *ctx = data;
	int match;

	if (info->case_insensitive)
		match = grub_strcasecmp (filename, ctx->name) == 0;
	else
		match = grub_strcmp (filename, ctx->name) == 0;
	if (!match)
		return 0;

	ctx->found = 1;
	ctx->st->is_dir = info->dir ? 1 : 0;
	ctx->st->mtime_set = info->mtimeset ? 1 : 0;
	ctx->st->mtime = info->mtimeset ? info->mtime : 0;
	return 1;
}

int
rover_stat (const char *path, rover_stat_t *st)
{
	struct stat_ctx ctx;
	grub_device_t dev = NULL;
	grub_fs_t fs;
	grub_file_t file;
	char *dup = NULL;
	char *fs_path;
	char *sep;
	char *p;
	int err;

	grub_memset (st, 0, sizeof (*st));
	grub_errno = GRUB_ERR_NONE;

	if (path[0] != '(')
		return grub_error (GRUB_ERR_BAD_FILENAME, "no device in path `%s'", path);

	dup = grub_strdup (path);
	if (!dup)
		goto fail;

	fs_path = grub_strchr (dup, ')');
	if (!fs_path)
	{
		grub_error (GRUB_ERR_BAD_FILENAME, "missing `)' in `%s'", path);
		goto fail;
	}
	*fs_path++ = '\0';

	dev = grub_device_open (dup + 1);
	if (!dev)
		goto fail;

	fs = grub_fs_probe (dev);
	if (!fs)
		goto fail;

	p = fs_path + grub_strlen (fs_path);
	while (p > fs_path && p[-1] == '/')
		*--p = '\0';

	if (*fs_path == '\0')
	{
		/* Device root.  */
		st->is_dir = 1;
		goto done;
	}

	sep = grub_strrchr (fs_path, '/');
	if (!sep)
	{
		grub_error (GRUB_ERR_BAD_FILENAME, "invalid path `%s'", path);
		goto fail;
	}

	ctx.name = sep + 1;
	ctx.found = 0;
	ctx.st = st;
	if (sep == fs_path)
		(fs->fs_dir) (dev, "/", stat_dir_hook, &ctx);
	else
	{
		*sep = '\0';
		(fs->fs_dir) (dev, fs_path, stat_dir_hook, &ctx);
	}
	grub_errno = GRUB_ERR_NONE;

	if (!ctx.found)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);
		goto fail;
	}

	if (!st->is_dir)
	{
		file = grub_file_open (path, GRUB_FILE_TYPE_GET_SIZE | GRUB_FILE_TYPE_NO_DECOMPRESS);
		if (file)
		{
			st->size = grub_file_size (file);
			grub_file_close (file);
		}
		else
			st->size = ROVER_SIZE_UNKNOWN;
	}

done:
	grub_free (dup);
	grub_device_close (dev);
	grub_errno = GRUB_ERR_NONE;
	return 0;

fail:
	err = grub_errno;
	grub_free (dup);
	if (dev)
		grub_device_close (dev);
	grub_errno = err;
	return err;
}

const char *
rover_fs_name (const char *device)
{
	grub_device_t dev;
	grub_fs_t fs;

	grub_errno = GRUB_ERR_NONE;
	dev = grub_device_open (device);
	if (!dev)
		return NULL;

	fs = grub_fs_probe (dev);
	grub_device_close (dev);
	grub_errno = GRUB_ERR_NONE;
	return fs ? fs->name : NULL;
}

int
rover_enum_support (int category, rover_support_hook cb, void *data)
{
	switch (category)
	{
	case ROVER_SUPPORT_FS:
	{
		grub_fs_t fs;
		FOR_FILESYSTEMS (fs)
			if (cb (fs->name, data))
				return 1;
		break;
	}
	case ROVER_SUPPORT_PARTMAP:
	{
		grub_partition_map_t partmap;
		FOR_PARTITION_MAPS (partmap)
			if (cb (partmap->name, data))
				return 1;
		break;
	}
	case ROVER_SUPPORT_DISKFILTER:
	{
		grub_diskfilter_t df;
		FOR_LIST_ELEMENTS (df, grub_diskfilter_list)
			if (cb (df->name, data))
				return 1;
		break;
	}
	case ROVER_SUPPORT_IOFILTER:
	{
		/* grub_file_filters[] holds bare function pointers; these
		   names mirror the grub_file_filter_id_t slot order.  */
		static const char *const names[] =
		{
			"gzio", "xzio", "lzopio", "lz4io", "zstdio",
			"vhd", "vhdx", "vdi", "qcow", "vmdk", "dmg", "isz",
		};
		int id;
		for (id = GRUB_FILE_FILTER_COMPRESSION_FIRST; id <= GRUB_FILE_FILTER_VDISK_LAST; id++)
			if (grub_file_filters[id] && cb (names[id - GRUB_FILE_FILTER_COMPRESSION_FIRST], data))
				return 1;
		break;
	}
	}
	return 0;
}

/* Cryptodisk (LUKS/LUKS2) unlock */

int
rover_crypto_unlock (const char *device, const void *key,
		     unsigned long long key_len,
		     char *out_dev, unsigned long long out_size)
{
	grub_err_t err;

	grub_errno = GRUB_ERR_NONE;
	err = grub_cryptodisk_mount_by_name (device, key, (grub_size_t) key_len, out_dev, (grub_size_t) out_size);
	if (err == GRUB_ERR_NONE)
		grub_errno = GRUB_ERR_NONE;
	return (int) err;
}

static rover_progress_hook crypto_progress_cb;
static void *crypto_progress_data;

static void
crypto_progress_shim (unsigned int done, unsigned int total, void *data)
{
	(void) data;
	if (crypto_progress_cb)
		crypto_progress_cb (done, total, crypto_progress_data);
}

void
rover_set_crypto_progress (rover_progress_hook cb, void *data)
{
	crypto_progress_cb = cb;
	crypto_progress_data = data;
	grub_cryptodisk_kdf_progress = cb ? crypto_progress_shim : 0;
	grub_cryptodisk_kdf_progress_data = 0;
}
