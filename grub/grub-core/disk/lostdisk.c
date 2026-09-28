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
 * Lost partitions ("lostN"): a read-only window of another grub disk,
 * given by a byte offset and length, so that a filesystem found by the
 * lost partition search (rover\lostpart.c) can be browsed and mounted
 * without a partition table entry.  The device keeps its parent open
 * and inherits the parent's logical sector size.  Remaps substitute
 * byte ranges of the window with other ranges of it on every read, so
 * a volume whose primary boot sector or superblock is damaged opens
 * through its backup.
 */

#include <grub/device.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/fs.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/safemath.h>
#include <grub/types.h>

#include "rover.h"
#include "lost.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Name of the transient device grub_lostdisk_probe() opens.  It is not
   listed by the iterator, and rover_lost_add refuses it.  */
#define LOSTDISK_PROBE_NAME	"lostprobe"

struct lostdisk
{
	struct lostdisk *next;
	char *devname;
	char *parent_name;	/* NULL for the probe device */
	grub_disk_t parent;	/* owned unless this is the probe device */
	grub_disk_addr_t start;	/* in 512-byte sectors on the parent */
	grub_uint64_t sectors;	/* in 512-byte sectors */
	struct rover_lost_remap remap[ROVER_LOST_REMAP_MAX];
	unsigned int remap_count;
	unsigned long id;
	grub_uint64_t refcnt;
};

static struct lostdisk *lostdisk_list;
static unsigned long lostdisk_last_id;

static struct lostdisk *
lostdisk_find (const char *devname)
{
	struct lostdisk *dev;

	for (dev = lostdisk_list; dev; dev = dev->next)
		if (grub_strcmp (dev->devname, devname) == 0)
			return dev;
	return NULL;
}

static void
lostdisk_free (struct lostdisk *dev)
{
	grub_free (dev->devname);
	if (dev->parent_name)
	{
		grub_free (dev->parent_name);
		grub_disk_close (dev->parent);
	}
	grub_free (dev);
}

/* Each remap lies inside a SIZE-byte window.  */
static grub_err_t
lostdisk_check_remap (grub_uint64_t size, const struct rover_lost_remap *remap,
	unsigned int remap_count)
{
	unsigned int i;

	if (remap_count > ROVER_LOST_REMAP_MAX)
		return grub_error (GRUB_ERR_BAD_ARGUMENT, "too many remaps");
	for (i = 0; i < remap_count; i++)
		if (remap[i].length == 0 || remap[i].length > size
			|| remap[i].target > size - remap[i].length
			|| remap[i].source > size - remap[i].length)
			return grub_error (GRUB_ERR_BAD_ARGUMENT, "remap is outside the range");
	return GRUB_ERR_NONE;
}

int
rover_lost_add (const char *devname, const char *parent,
	unsigned long long offset, unsigned long long size)
{
	return rover_lost_add_ex (devname, parent, offset, size, NULL, 0);
}

int
rover_lost_add_ex (const char *devname, const char *parent,
	unsigned long long offset, unsigned long long size,
	const struct rover_lost_remap *remap, unsigned int remap_count)
{
	struct lostdisk *dev = NULL;
	grub_disk_t disk = NULL;
	grub_uint64_t total;
	unsigned int sector_size;
	int err;

	grub_errno = GRUB_ERR_NONE;

	if (grub_strcmp (devname, LOSTDISK_PROBE_NAME) == 0 || lostdisk_find (devname))
		return grub_error (GRUB_ERR_BAD_ARGUMENT, "device `%s' already exists", devname);
	if (lostdisk_check_remap (size, remap, remap_count))
		return grub_errno;

	disk = grub_disk_open (parent);
	if (!disk)
		goto fail;

	/* Whole logical sectors of the parent only, inside the parent.  */
	sector_size = 1U << disk->log_sector_size;
	if (size == 0 || (offset & (sector_size - 1)) || (size & (sector_size - 1)))
	{
		grub_error (GRUB_ERR_BAD_ARGUMENT, "range is not a multiple of %u-byte sectors", sector_size);
		goto fail;
	}
	total = grub_disk_native_sectors (disk);
	if (total != GRUB_DISK_SIZE_UNKNOWN
		&& (offset >> GRUB_DISK_SECTOR_BITS > total
			|| size >> GRUB_DISK_SECTOR_BITS > total - (offset >> GRUB_DISK_SECTOR_BITS)))
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "range is beyond the end of `%s'", parent);
		goto fail;
	}

	dev = grub_zalloc (sizeof (*dev));
	if (!dev)
		goto fail;
	dev->devname = grub_strdup (devname);
	dev->parent_name = grub_strdup (parent);
	if (!dev->devname || !dev->parent_name)
		goto fail;

	dev->parent = disk;
	dev->start = offset >> GRUB_DISK_SECTOR_BITS;
	dev->sectors = size >> GRUB_DISK_SECTOR_BITS;
	if (remap_count)
		grub_memcpy (dev->remap, remap, remap_count * sizeof (*remap));
	dev->remap_count = remap_count;
	dev->id = lostdisk_last_id++;
	dev->next = lostdisk_list;
	lostdisk_list = dev;
	return GRUB_ERR_NONE;

fail:
	err = grub_errno;
	if (dev)
	{
		grub_free (dev->devname);
		grub_free (dev->parent_name);
		grub_free (dev);
	}
	if (disk)
		grub_disk_close (disk);
	grub_errno = err;
	return err;
}

int
rover_lost_del (const char *devname)
{
	struct lostdisk **prev;
	struct lostdisk *dev;

	grub_errno = GRUB_ERR_NONE;

	for (prev = &lostdisk_list; (dev = *prev); prev = &dev->next)
		if (dev->parent_name && grub_strcmp (dev->devname, devname) == 0)
			break;
	if (!dev)
		return grub_error (GRUB_ERR_BAD_DEVICE, "device `%s' not found", devname);
	if (dev->refcnt > 0)
		return grub_error (GRUB_ERR_STILL_REFERENCED, "device `%s' still in use", devname);

	*prev = dev->next;
	lostdisk_free (dev);
	grub_errno = GRUB_ERR_NONE;
	return GRUB_ERR_NONE;
}

const char *
rover_lost_get_parent (const char *devname)
{
	struct lostdisk *dev = lostdisk_find (devname);

	return dev ? dev->parent_name : NULL;
}

grub_err_t
grub_lostdisk_probe (grub_disk_t parent, grub_disk_addr_t start, grub_uint64_t sectors,
	const struct rover_lost_remap *remap, unsigned int remap_count,
	const char **fs_name, char **label, char **uuid)
{
	struct lostdisk dev;
	struct lostdisk **prev;
	grub_device_t device;
	grub_fs_t fs;
	grub_err_t err;

	*fs_name = NULL;
	*label = NULL;
	*uuid = NULL;

	if (lostdisk_check_remap (sectors << GRUB_DISK_SECTOR_BITS, remap, remap_count))
		return grub_errno;
	grub_memset (&dev, 0, sizeof (dev));
	dev.devname = (char *) LOSTDISK_PROBE_NAME;
	dev.parent = parent;
	dev.start = start;
	dev.sectors = sectors;
	if (remap_count)
		grub_memcpy (dev.remap, remap, remap_count * sizeof (*remap));
	dev.remap_count = remap_count;
	dev.id = lostdisk_last_id++;
	dev.next = lostdisk_list;
	lostdisk_list = &dev;

	device = grub_device_open (LOSTDISK_PROBE_NAME);
	if (!device)
		goto out;
	fs = grub_fs_probe (device);
	if (fs)
	{
		*fs_name = fs->name;
		if (fs->fs_label && (fs->fs_label) (device, label) != GRUB_ERR_NONE)
			*label = NULL;
		grub_errno = GRUB_ERR_NONE;
		if (fs->fs_uuid && (fs->fs_uuid) (device, uuid) != GRUB_ERR_NONE)
			*uuid = NULL;
	}
	grub_device_close (device);

out:
	err = *fs_name ? GRUB_ERR_NONE : GRUB_ERR_UNKNOWN_FS;
	grub_errno = GRUB_ERR_NONE;
	for (prev = &lostdisk_list; *prev != &dev; prev = &(*prev)->next)
		;
	*prev = dev.next;
	return err;
}

grub_disk_addr_t
grub_lostdisk_start (grub_disk_t disk)
{
	return ((struct lostdisk *) disk->data)->start;
}

static int
lostdisk_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data, grub_disk_pull_t pull)
{
	struct lostdisk *dev;

	if (pull != GRUB_DISK_PULL_NONE)
		return 0;
	for (dev = lostdisk_list; dev; dev = dev->next)
		if (dev->parent_name && hook (dev->devname, hook_data))
			return 1;
	return 0;
}

static grub_err_t
lostdisk_open (const char *name, grub_disk_t disk)
{
	struct lostdisk *dev = lostdisk_find (name);

	if (!dev)
		return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "can't open device");

	if (grub_add (dev->refcnt, 1, &dev->refcnt))
		grub_fatal ("Reference count overflow");

	disk->log_sector_size = dev->parent->log_sector_size;
	disk->total_sectors = dev->sectors >> (disk->log_sector_size - GRUB_DISK_SECTOR_BITS);
	disk->max_agglomerate = dev->parent->max_agglomerate;
	disk->id = dev->id;
	disk->data = dev;
	return GRUB_ERR_NONE;
}

static void
lostdisk_close (grub_disk_t disk)
{
	struct lostdisk *dev = disk->data;

	if (grub_sub (dev->refcnt, 1, &dev->refcnt))
		grub_fatal ("Reference count underflow");
}

static grub_err_t
lostdisk_read (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, char *buf)
{
	struct lostdisk *dev = disk->data;
	unsigned int shift = disk->log_sector_size - GRUB_DISK_SECTOR_BITS;
	grub_uint64_t first = (grub_uint64_t) sector << disk->log_sector_size;
	grub_uint64_t last = first + ((grub_uint64_t) size << disk->log_sector_size);
	grub_uint64_t base = dev->start << GRUB_DISK_SECTOR_BITS;
	unsigned int i;

	if (grub_disk_read (dev->parent, dev->start + (sector << shift), 0,
		size << disk->log_sector_size, buf))
		return grub_errno;
	/* Overlay the part of each remap this read covers.  */
	for (i = 0; i < dev->remap_count; i++)
	{
		const struct rover_lost_remap *r = &dev->remap[i];
		grub_uint64_t from = first > r->target ? first : r->target;
		grub_uint64_t to = last < r->target + r->length ? last : r->target + r->length;
		grub_uint64_t source;

		if (from >= to)
			continue;
		source = base + r->source + (from - r->target);
		if (grub_disk_read (dev->parent, source >> GRUB_DISK_SECTOR_BITS,
			source & (GRUB_DISK_SECTOR_SIZE - 1), (grub_size_t) (to - from),
			buf + (from - first)))
			return grub_errno;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
lostdisk_write (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, const char *buf)
{
	(void) disk;
	(void) sector;
	(void) size;
	(void) buf;
	return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "lostdisk writes are not supported");
}

static struct grub_disk_dev grub_lostdisk_dev =
{
	.name = "lostdisk",
	.id = GRUB_DISK_DEVICE_LOST_ID,
	.disk_iterate = lostdisk_iterate,
	.disk_open = lostdisk_open,
	.disk_close = lostdisk_close,
	.disk_read = lostdisk_read,
	.disk_write = lostdisk_write,
	.next = 0
};

GRUB_MOD_INIT (lostdisk)
{
	grub_disk_dev_register (&grub_lostdisk_dev);
}

GRUB_MOD_FINI (lostdisk)
{
	while (lostdisk_list)
	{
		struct lostdisk *dev = lostdisk_list;
		lostdisk_list = dev->next;
		lostdisk_free (dev);
	}
	grub_disk_dev_unregister (&grub_lostdisk_dev);
}
