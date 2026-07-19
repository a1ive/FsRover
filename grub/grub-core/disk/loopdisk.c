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
 * File-backed virtual disks ("loopN" over any grub file path).
 * The disk device logic follows grub-core\disk\loopback.c; the grub
 * shell command interface is replaced by rover_loopback_add/del so
 * that no extcmd machinery is needed.
 */

#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/safemath.h>
#include <grub/types.h>

#include "rover.h"

GRUB_MOD_LICENSE ("GPLv3+");

struct loopdisk
{
	struct loopdisk *next;
	char *devname;
	grub_file_t file;
	unsigned long id;
	grub_uint64_t refcnt;
};

static struct loopdisk *loopdisk_list;
static unsigned long loopdisk_last_id;

int
rover_loopback_add (const char *devname, const char *path, int decompress)
{
	struct loopdisk *dev;
	grub_file_t file = NULL;
	enum grub_file_type type = GRUB_FILE_TYPE_LOOPBACK
				   | GRUB_FILE_TYPE_FILTER_VDISK;
	int err;

	grub_errno = GRUB_ERR_NONE;

	for (dev = loopdisk_list; dev; dev = dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			return grub_error (GRUB_ERR_BAD_ARGUMENT, "device `%s' already exists", devname);

	/* FILTER_VDISK lets the vhd/vhdx/vdi/qcow/vmdk/dmg/isz io filters decode
	   virtual disk images transparently; raw images pass through.
	   Compressed images stay raw unless the caller asks for
	   transparent decompression through the gzip/xz/... filters.  */
	if (!decompress)
		type |= GRUB_FILE_TYPE_NO_DECOMPRESS;
	file = grub_file_open (path, type);
	if (!file)
		goto fail;

	dev = grub_malloc (sizeof (*dev));
	if (!dev)
		goto fail;
	dev->devname = grub_strdup (devname);
	if (!dev->devname)
	{
		grub_free (dev);
		goto fail;
	}

	dev->file = file;
	dev->id = loopdisk_last_id++;
	dev->refcnt = 0;
	dev->next = loopdisk_list;
	loopdisk_list = dev;
	return GRUB_ERR_NONE;

fail:
	err = grub_errno;
	if (file)
		grub_file_close (file);
	grub_errno = err;
	return err;
}

int
rover_loopback_del (const char *devname)
{
	struct loopdisk **prev;
	struct loopdisk *dev;

	grub_errno = GRUB_ERR_NONE;

	for (prev = &loopdisk_list; (dev = *prev); prev = &dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			break;
	if (!dev)
		return grub_error (GRUB_ERR_BAD_DEVICE, "device `%s' not found", devname);
	if (dev->refcnt > 0)
		return grub_error (GRUB_ERR_STILL_REFERENCED, "device `%s' still in use", devname);

	*prev = dev->next;
	grub_free (dev->devname);
	grub_file_close (dev->file);
	grub_free (dev);
	grub_errno = GRUB_ERR_NONE;
	return GRUB_ERR_NONE;
}

static int
loopdisk_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data, grub_disk_pull_t pull)
{
	struct loopdisk *dev;

	if (pull != GRUB_DISK_PULL_NONE)
		return 0;
	for (dev = loopdisk_list; dev; dev = dev->next)
		if (hook (dev->devname, hook_data))
			return 1;
	return 0;
}

static grub_err_t
loopdisk_open (const char *name, grub_disk_t disk)
{
	struct loopdisk *dev;

	for (dev = loopdisk_list; dev; dev = dev->next)
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
loopdisk_close (grub_disk_t disk)
{
	struct loopdisk *dev = disk->data;

	if (grub_sub (dev->refcnt, 1, &dev->refcnt))
		grub_fatal ("Reference count underflow");
}

static grub_err_t
loopdisk_read (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, char *buf)
{
	grub_file_t file = ((struct loopdisk *) disk->data)->file;
	grub_off_t pos;

	grub_file_seek (file, sector << GRUB_DISK_SECTOR_BITS);
	grub_file_read (file, buf, size << GRUB_DISK_SECTOR_BITS);
	if (grub_errno)
		return grub_errno;

	/* Zero-fill the tail when the file is not a whole number of sectors long.  */
	pos = (sector + size) << GRUB_DISK_SECTOR_BITS;
	if (pos > file->size)
	{
		grub_size_t amount = (grub_size_t) (pos - file->size);
		grub_memset (buf + (size << GRUB_DISK_SECTOR_BITS) - amount, 0, amount);
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
loopdisk_write (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, const char *buf)
{
	(void) disk;
	(void) sector;
	(void) size;
	(void) buf;
	return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "loopdisk writes are not supported");
}

static struct grub_disk_dev grub_loopdisk_dev =
{
	.name = "loopdisk",
	.id = GRUB_DISK_DEVICE_LOOPBACK_ID,
	.disk_iterate = loopdisk_iterate,
	.disk_open = loopdisk_open,
	.disk_close = loopdisk_close,
	.disk_read = loopdisk_read,
	.disk_write = loopdisk_write,
	.next = 0
};

GRUB_MOD_INIT (loopdisk)
{
	grub_disk_dev_register (&grub_loopdisk_dev);
}

GRUB_MOD_FINI (loopdisk)
{
	/* Drop any devices still attached; grub state is going away.  */
	while (loopdisk_list)
	{
		struct loopdisk *dev = loopdisk_list;
		loopdisk_list = dev->next;
		grub_free (dev->devname);
		grub_file_close (dev->file);
		grub_free (dev);
	}
	grub_disk_dev_unregister (&grub_loopdisk_dev);
}
