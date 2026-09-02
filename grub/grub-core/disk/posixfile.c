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

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/hostfile.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/safemath.h>
#include <grub/types.h>

#include "rover.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define POSIXFILE_READ_MAX	0x4000000

struct posixfile_host
{
	int fd;
};

struct posixfile
{
	struct posixfile *next;
	char *devname;
	char *path;
	grub_file_t file;
	unsigned long id;
	grub_uint64_t refcnt;
};

static struct posixfile *posixfile_list;
static unsigned long posixfile_last_id;

static grub_ssize_t
host_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct posixfile_host *host = file->data;
	grub_size_t left = len;
	grub_off_t offset = file->offset;

	while (left)
	{
		size_t want = left > POSIXFILE_READ_MAX ? POSIXFILE_READ_MAX : left;
		ssize_t got = pread (host->fd, buf, want, (off_t) offset);

		if (got < 0)
		{
			if (errno == EINTR)
				continue;
			grub_error (GRUB_ERR_READ_ERROR, "cannot read `%s' (%s)",
				file->name, strerror (errno));
			return -1;
		}
		if (got == 0)
			break;
		buf += got;
		left -= (grub_size_t) got;
		offset += got;
	}
	return (grub_ssize_t) (len - left);
}

static grub_err_t
host_close (grub_file_t file)
{
	struct posixfile_host *host = file->data;

	close (host->fd);
	grub_free (host);
	file->data = NULL;
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_posixfile_fs =
{
	.name = "posixfile",
	.fs_read = host_read,
	.fs_close = host_close
};

static grub_file_t
host_open_raw (const char *path)
{
	struct posixfile_host *host = NULL;
	grub_file_t file = NULL;
	struct stat st;
	int fd = -1;

	fd = open (path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "cannot open `%s' (%s)",
			path, strerror (errno));
		goto fail;
	}
	if (fstat (fd, &st) != 0 || st.st_size < 0)
	{
		grub_error (GRUB_ERR_FILE_READ_ERROR, "cannot size `%s' (%s)",
			path, strerror (errno));
		goto fail;
	}
	host = grub_malloc (sizeof (*host));
	if (!host)
		goto fail;
	host->fd = fd;
	file = grub_zalloc (sizeof (*file));
	if (!file)
		goto fail;
	file->fs = &grub_posixfile_fs;
	file->data = host;
	file->size = (grub_off_t) st.st_size;
	host = NULL;
	fd = -1;
	file->name = grub_strdup (path);
	if (!file->name)
	{
		grub_file_close (file);
		return NULL;
	}
	return file;

fail:
	if (fd >= 0)
		close (fd);
	grub_free (host);
	return NULL;
}

grub_file_t
grub_hostfile_open (const char *path, enum grub_file_type type)
{
	grub_file_t file;
	grub_file_t last = NULL;
	grub_file_filter_id_t filter;

	file = host_open_raw (path);
	if (!file)
		return NULL;
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

static grub_file_t
host_open (const char *path, int decompress)
{
	enum grub_file_type type = GRUB_FILE_TYPE_LOOPBACK | GRUB_FILE_TYPE_FILTER_VDISK;

	if (!decompress)
		type |= GRUB_FILE_TYPE_NO_DECOMPRESS;
	return grub_hostfile_open (path, type);
}

int
rover_posixfile_add (const char *devname, const char *path, int decompress)
{
	struct posixfile *dev;
	grub_file_t file = NULL;
	int err;

	grub_errno = GRUB_ERR_NONE;
	for (dev = posixfile_list; dev; dev = dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			return grub_error (GRUB_ERR_BAD_ARGUMENT,
				"device `%s' already exists", devname);
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
	dev->id = posixfile_last_id++;
	dev->refcnt = 0;
	dev->next = posixfile_list;
	posixfile_list = dev;
	return GRUB_ERR_NONE;

fail:
	err = grub_errno;
	if (file)
		grub_file_close (file);
	grub_errno = err;
	return err;
}

int
rover_posixfile_del (const char *devname)
{
	struct posixfile **prev;
	struct posixfile *dev;

	grub_errno = GRUB_ERR_NONE;
	for (prev = &posixfile_list; (dev = *prev); prev = &dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			break;
	if (!dev)
		return grub_error (GRUB_ERR_BAD_DEVICE, "device `%s' not found", devname);
	if (dev->refcnt > 0)
		return grub_error (GRUB_ERR_STILL_REFERENCED,
			"device `%s' still in use", devname);
	*prev = dev->next;
	grub_free (dev->devname);
	grub_free (dev->path);
	grub_file_close (dev->file);
	grub_free (dev);
	grub_errno = GRUB_ERR_NONE;
	return GRUB_ERR_NONE;
}

const char *
rover_posixfile_get_path (const char *devname)
{
	struct posixfile *dev;

	for (dev = posixfile_list; dev; dev = dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			return dev->path;
	return NULL;
}

static int
posixfile_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
	grub_disk_pull_t pull)
{
	struct posixfile *dev;

	if (pull != GRUB_DISK_PULL_NONE)
		return 0;
	for (dev = posixfile_list; dev; dev = dev->next)
		if (hook (dev->devname, hook_data))
			return 1;
	return 0;
}

static grub_err_t
posixfile_open (const char *name, grub_disk_t disk)
{
	struct posixfile *dev;

	for (dev = posixfile_list; dev; dev = dev->next)
		if (grub_strcmp (dev->devname, name) == 0)
			break;
	if (!dev)
		return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "can't open device");
	if (grub_add (dev->refcnt, 1, &dev->refcnt))
		grub_fatal ("reference count overflow");
	if (dev->file->size != GRUB_FILE_SIZE_UNKNOWN)
		disk->total_sectors = (dev->file->size + GRUB_DISK_SECTOR_SIZE - 1)
			>> GRUB_DISK_SECTOR_BITS;
	else
		disk->total_sectors = GRUB_DISK_SIZE_UNKNOWN;
	disk->max_agglomerate = 1 << (29 - GRUB_DISK_SECTOR_BITS
		- GRUB_DISK_CACHE_BITS);
	disk->id = dev->id;
	disk->data = dev;
	return GRUB_ERR_NONE;
}

static void
posixfile_close (grub_disk_t disk)
{
	struct posixfile *dev = disk->data;

	if (grub_sub (dev->refcnt, 1, &dev->refcnt))
		grub_fatal ("reference count underflow");
}

static grub_err_t
posixfile_read (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size,
	char *buf)
{
	grub_file_t file = ((struct posixfile *) disk->data)->file;
	grub_size_t len = size << GRUB_DISK_SECTOR_BITS;
	grub_ssize_t got;

	if (grub_file_seek (file, sector << GRUB_DISK_SECTOR_BITS)
		== (grub_off_t) -1)
		return grub_errno;
	got = grub_file_read (file, buf, len);
	if (got < 0)
		return grub_errno;
	if ((grub_size_t) got < len)
		grub_memset (buf + got, 0, len - got);
	return GRUB_ERR_NONE;
}

static grub_err_t
posixfile_write (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size,
	const char *buf)
{
	(void) disk;
	(void) sector;
	(void) size;
	(void) buf;
	return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		"posixfile writes are not supported");
}

static struct grub_disk_dev grub_posixfile_dev =
{
	.name = "posixfile",
	.id = GRUB_DISK_DEVICE_HOST_ID,
	.disk_iterate = posixfile_iterate,
	.disk_open = posixfile_open,
	.disk_close = posixfile_close,
	.disk_read = posixfile_read,
	.disk_write = posixfile_write
};

GRUB_MOD_INIT (posixfile)
{
	grub_disk_dev_register (&grub_posixfile_dev);
}

GRUB_MOD_FINI (posixfile)
{
	while (posixfile_list)
	{
		struct posixfile *dev = posixfile_list;

		posixfile_list = dev->next;
		grub_free (dev->devname);
		grub_free (dev->path);
		grub_file_close (dev->file);
		grub_free (dev);
	}
	grub_disk_dev_unregister (&grub_posixfile_dev);
}
