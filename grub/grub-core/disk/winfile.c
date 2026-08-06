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
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/safemath.h>
#include <grub/types.h>
#include <grub/winfile.h>

#include <windows.h>

#include "rover.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Largest ReadFile() in one go; a disk read is bounded well below this
   by max_agglomerate, the loop is only here so that no length can
   overflow the DWORD count.  */
#define WINFILE_READ_MAX	0x4000000

/* Backing store of the synthetic grub file: the open Windows file.  */
struct winfile_host
{
	HANDLE handle;
};

struct winfile
{
	struct winfile *next;
	char *devname;
	char *path;	/* Windows path, UTF-8, for the GUI */
	grub_file_t file;	/* io filter chain over the host file */
	unsigned long id;
	grub_uint64_t refcnt;
};

static struct winfile *winfile_list;
static unsigned long winfile_last_id;

static grub_ssize_t
host_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct winfile_host *host = file->data;
	LARGE_INTEGER pos;
	grub_size_t left = len;

	pos.QuadPart = (LONGLONG) file->offset;
	if (!SetFilePointerEx (host->handle, pos, NULL, FILE_BEGIN))
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "cannot seek to 0x%llx in `%s'",
			(unsigned long long) file->offset, file->name);
		return -1;
	}

	while (left)
	{
		DWORD want = (DWORD) (left > WINFILE_READ_MAX ? WINFILE_READ_MAX : left);
		DWORD got = 0;

		if (!ReadFile (host->handle, buf, want, &got, NULL))
		{
			grub_error (GRUB_ERR_READ_ERROR, "cannot read `%s' (Windows error %lu)",
				file->name, (unsigned long) GetLastError ());
			return -1;
		}
		if (!got)
			break;	/* end of file */
		buf += got;
		left -= got;
	}
	return (grub_ssize_t) (len - left);
}

static grub_err_t
host_close (grub_file_t file)
{
	struct winfile_host *host = file->data;

	CloseHandle (host->handle);
	grub_free (host);
	file->data = NULL;
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_winfile_fs =
{
	.name = "winfile",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = host_read,
	.fs_close = host_close,
	.fs_label = 0,
	.next = 0
};

/* PATH is a Windows path in UTF-8.  Returns the unfiltered grub file, or NULL with grub_errno set.  */
static grub_file_t
host_open_raw (const char *path)
{
	struct winfile_host *host = NULL;
	grub_file_t file = NULL;
	HANDLE handle = INVALID_HANDLE_VALUE;
	LARGE_INTEGER size;
	WCHAR *wpath;
	int wlen;

	wlen = MultiByteToWideChar (CP_UTF8, 0, path, -1, NULL, 0);
	if (wlen <= 0)
	{
		grub_error (GRUB_ERR_BAD_FILENAME, "invalid file name `%s'", path);
		goto fail;
	}
	wpath = grub_calloc ((grub_size_t) wlen, sizeof (*wpath));
	if (!wpath)
		goto fail;
	MultiByteToWideChar (CP_UTF8, 0, path, -1, wpath, wlen);
	handle = CreateFileW (wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL);
	grub_free (wpath);
	if (handle == INVALID_HANDLE_VALUE)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "cannot open `%s' (%lu)", path, (unsigned long) GetLastError ());
		goto fail;
	}
	if (!GetFileSizeEx (handle, &size))
	{
		grub_error (GRUB_ERR_FILE_READ_ERROR, "cannot size `%s' (%lu)", path, (unsigned long) GetLastError ());
		goto fail;
	}

	host = grub_malloc (sizeof (*host));
	if (!host)
		goto fail;
	host->handle = handle;

	file = grub_zalloc (sizeof (*file));
	if (!file)
		goto fail;
	file->fs = &grub_winfile_fs;
	file->data = host;
	file->size = (grub_off_t) size.QuadPart;
	/* The file owns both from here on.  */
	host = NULL;
	handle = INVALID_HANDLE_VALUE;

	/* Carried by every layer for the filters that go by extension.  */
	file->name = grub_strdup (path);
	if (!file->name)
	{
		grub_file_close (file);
		file = NULL;
		goto fail;
	}
	return file;

fail:
	if (handle != INVALID_HANDLE_VALUE)
		CloseHandle (handle);
	grub_free (host);
	return NULL;
}

/* The same, decoded through the io filter chain.  */
grub_file_t
grub_winfile_open (const char *path, enum grub_file_type type)
{
	grub_file_t file;
	grub_file_t last = NULL;
	grub_file_filter_id_t filter;

	file = host_open_raw (path);
	if (!file)
		return NULL;

	/* The chain kern\file.c runs after fs_open.  */
	for (filter = 0; file && filter < ARRAY_SIZE (grub_file_filters); filter++)
		if (grub_file_filters[filter])
		{
			last = file;
			file = grub_file_filters[filter] (file, type);
			if (file && file != last)
			{
				file->name = grub_strdup (path);
				grub_errno = GRUB_ERR_NONE;
			}
		}
	if (!file)
	{
		grub_file_close (last);
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_DEVICE, "cannot decode image `%s'", path);
	}
	return file;
}

/* Compressed images stay raw unless transparent decompression was asked
   for; virtual disk images are always decoded.  */
static grub_file_t
host_open (const char *path, int decompress)
{
	enum grub_file_type type = GRUB_FILE_TYPE_LOOPBACK | GRUB_FILE_TYPE_FILTER_VDISK;

	if (!decompress)
		type |= GRUB_FILE_TYPE_NO_DECOMPRESS;
	return grub_winfile_open (path, type);
}

int
rover_winfile_add (const char *devname, const char *path, int decompress)
{
	struct winfile *dev;
	grub_file_t file = NULL;
	int err;

	grub_errno = GRUB_ERR_NONE;

	for (dev = winfile_list; dev; dev = dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			return grub_error (GRUB_ERR_BAD_ARGUMENT, "device `%s' already exists", devname);

	file = host_open (path, decompress);
	if (!file)
		goto fail;

	dev = grub_malloc (sizeof (*dev));
	if (!dev)
		goto fail;
	dev->devname = grub_strdup (devname);
	dev->path = grub_strdup (path);
	if (!dev->devname || !dev->path)
	{
		grub_free (dev->devname);
		grub_free (dev->path);
		grub_free (dev);
		goto fail;
	}

	dev->file = file;
	dev->id = winfile_last_id++;
	dev->refcnt = 0;
	dev->next = winfile_list;
	winfile_list = dev;
	return GRUB_ERR_NONE;

fail:
	err = grub_errno;
	if (file)
		grub_file_close (file);
	grub_errno = err;
	return err;
}

int
rover_winfile_del (const char *devname)
{
	struct winfile **prev;
	struct winfile *dev;

	grub_errno = GRUB_ERR_NONE;

	for (prev = &winfile_list; (dev = *prev); prev = &dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			break;
	if (!dev)
		return grub_error (GRUB_ERR_BAD_DEVICE, "device `%s' not found", devname);
	if (dev->refcnt > 0)
		return grub_error (GRUB_ERR_STILL_REFERENCED, "device `%s' still in use", devname);

	*prev = dev->next;
	grub_free (dev->devname);
	grub_free (dev->path);
	grub_file_close (dev->file);
	grub_free (dev);
	grub_errno = GRUB_ERR_NONE;
	return GRUB_ERR_NONE;
}

const char *
rover_winfile_get_path (const char *devname)
{
	struct winfile *dev;

	for (dev = winfile_list; dev; dev = dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			return dev->path;
	return NULL;
}

static int
winfile_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data, grub_disk_pull_t pull)
{
	struct winfile *dev;

	if (pull != GRUB_DISK_PULL_NONE)
		return 0;
	for (dev = winfile_list; dev; dev = dev->next)
		if (hook (dev->devname, hook_data))
			return 1;
	return 0;
}

static grub_err_t
winfile_open (const char *name, grub_disk_t disk)
{
	struct winfile *dev;

	for (dev = winfile_list; dev; dev = dev->next)
		if (grub_strcmp (dev->devname, name) == 0)
			break;
	if (!dev)
		return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "can't open device");

	if (grub_add (dev->refcnt, 1, &dev->refcnt))
		grub_fatal ("Reference count overflow");

	/* File size rounded up to a whole sector.  */
	if (dev->file->size != GRUB_FILE_SIZE_UNKNOWN)
		disk->total_sectors = ((dev->file->size + GRUB_DISK_SECTOR_SIZE - 1) >> GRUB_DISK_SECTOR_BITS);
	else
		disk->total_sectors = GRUB_DISK_SIZE_UNKNOWN;
	/* Avoid reading more than 512MiB at once.  */
	disk->max_agglomerate = 1 << (29 - GRUB_DISK_SECTOR_BITS - GRUB_DISK_CACHE_BITS);
	disk->id = dev->id;
	disk->data = dev;
	return GRUB_ERR_NONE;
}

static void
winfile_close (grub_disk_t disk)
{
	struct winfile *dev = disk->data;

	if (grub_sub (dev->refcnt, 1, &dev->refcnt))
		grub_fatal ("Reference count underflow");
}

static grub_err_t
winfile_read (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, char *buf)
{
	grub_file_t file = ((struct winfile *) disk->data)->file;
	grub_size_t len = size << GRUB_DISK_SECTOR_BITS;
	grub_ssize_t got;

	if (grub_file_seek (file, sector << GRUB_DISK_SECTOR_BITS) == (grub_off_t) -1)
		return grub_errno;
	got = grub_file_read (file, buf, len);
	if (got < 0)
		return grub_errno;

	/* Zero-fill whatever the image does not cover; see loopdisk.c for
	   why the gap is derived from the length actually read.  */
	if ((grub_size_t) got < len)
		grub_memset (buf + got, 0, len - got);
	return GRUB_ERR_NONE;
}

static grub_err_t
winfile_write (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, const char *buf)
{
	(void) disk;
	(void) sector;
	(void) size;
	(void) buf;
	return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "winfile writes are not supported");
}

static struct grub_disk_dev grub_winfile_dev =
{
	.name = "winfile",
	.id = GRUB_DISK_DEVICE_HOST_ID,
	.disk_iterate = winfile_iterate,
	.disk_open = winfile_open,
	.disk_close = winfile_close,
	.disk_read = winfile_read,
	.disk_write = winfile_write,
	.next = 0
};

GRUB_MOD_INIT (winfile)
{
	grub_disk_dev_register (&grub_winfile_dev);
}

GRUB_MOD_FINI (winfile)
{
	/* Drop any devices still attached; grub state is going away.  */
	while (winfile_list)
	{
		struct winfile *dev = winfile_list;
		winfile_list = dev->next;
		grub_free (dev->devname);
		grub_free (dev->path);
		grub_file_close (dev->file);
		grub_free (dev);
	}
	grub_disk_dev_unregister (&grub_winfile_dev);
}
