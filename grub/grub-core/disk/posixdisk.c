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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define POSIXDISK_CDROM_ID	0x80000000UL

struct posixdisk_device
{
	struct posixdisk_device *next;
	char *name;
	char *path;
	unsigned long id;
};

struct posixdisk_data
{
	int fd;
};

static struct posixdisk_device *posixdisk_devices;

static int
skip_device (const char *name)
{
	return grub_strncmp (name, "loop", 4) == 0
		|| grub_strncmp (name, "ram", 3) == 0
		|| grub_strncmp (name, "zram", 4) == 0
		|| grub_strncmp (name, "fd", 2) == 0;
}

static int
is_partition (const char *name)
{
	char path[512];

	if (snprintf (path, sizeof (path), "/sys/class/block/%s/partition", name)
		< 0)
		return 1;
	return access (path, F_OK) == 0;
}

static int
append_device (const char *sysname, unsigned long sequence, int optical,
	struct posixdisk_device ***tail)
{
	struct posixdisk_device *dev;
	char name[32];
	char path[512];
	int name_len;
	int path_len;

	name_len = snprintf (name, sizeof (name), "%s%lu",
		optical ? "cd" : "hd", sequence);
	path_len = snprintf (path, sizeof (path), "/dev/%s", sysname);
	if (name_len < 0 || (grub_size_t) name_len >= sizeof (name)
		|| path_len < 0 || (grub_size_t) path_len >= sizeof (path))
		return 0;
	dev = grub_zalloc (sizeof (*dev));
	if (!dev)
		return 0;
	dev->name = grub_strdup (name);
	dev->path = grub_strdup (path);
	if (!dev->name || !dev->path)
	{
		grub_free (dev->name);
		grub_free (dev->path);
		grub_free (dev);
		return 0;
	}
	dev->id = optical ? sequence | POSIXDISK_CDROM_ID : sequence;
	**tail = dev;
	*tail = &dev->next;
	return 1;
}

static void
free_devices (void)
{
	while (posixdisk_devices)
	{
		struct posixdisk_device *dev = posixdisk_devices;

		posixdisk_devices = dev->next;
		grub_free (dev->name);
		grub_free (dev->path);
		grub_free (dev);
	}
}

static void
scan_devices (void)
{
	struct dirent **entries = NULL;
	struct posixdisk_device **tail = &posixdisk_devices;
	unsigned long disk_sequence = 0;
	unsigned long optical_sequence = 0;
	int count;
	int i;

	free_devices ();
	count = scandir ("/sys/class/block", &entries, NULL, alphasort);
	if (count < 0)
		return;
	for (i = 0; i < count; i++)
	{
		const char *name = entries[i]->d_name;
		int optical = grub_strncmp (name, "sr", 2) == 0;

		if (name[0] != '.' && !skip_device (name) && !is_partition (name))
		{
			unsigned long sequence = optical ? optical_sequence : disk_sequence;

			if (append_device (name, sequence, optical, &tail))
			{
				if (optical)
					optical_sequence++;
				else
					disk_sequence++;
			}
		}
		free (entries[i]);
	}
	free (entries);
}

static struct posixdisk_device *
find_device (const char *name)
{
	struct posixdisk_device *dev;

	for (dev = posixdisk_devices; dev; dev = dev->next)
		if (grub_strcmp (dev->name, name) == 0)
			return dev;
	return NULL;
}

static int
posixdisk_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
	grub_disk_pull_t pull)
{
	struct posixdisk_device *dev;

	if (pull != GRUB_DISK_PULL_NONE)
		return 0;
	for (dev = posixdisk_devices; dev; dev = dev->next)
		if (hook (dev->name, hook_data))
			return 1;
	return 0;
}

static grub_err_t
posixdisk_open (const char *name, grub_disk_t disk)
{
	struct posixdisk_device *dev = find_device (name);
	struct posixdisk_data *data;
	unsigned long long bytes = 0;
	unsigned int sector_size = GRUB_DISK_SECTOR_SIZE;
	struct stat st;
	int fd;

	if (!dev)
		return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not a posixdisk");
	fd = open (dev->path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "cannot open %s (%s)",
			dev->path, strerror (errno));
	if (ioctl (fd, BLKSSZGET, &sector_size) != 0
		|| sector_size < GRUB_DISK_SECTOR_SIZE
		|| (sector_size & (sector_size - 1)) != 0)
		sector_size = GRUB_DISK_SECTOR_SIZE;
	if (ioctl (fd, BLKGETSIZE64, &bytes) != 0)
	{
		if (fstat (fd, &st) != 0 || st.st_size < 0)
		{
			close (fd);
			return grub_error (GRUB_ERR_BAD_DEVICE, "cannot size %s (%s)",
				dev->path, strerror (errno));
		}
		bytes = (unsigned long long) st.st_size;
	}
	data = grub_malloc (sizeof (*data));
	if (!data)
	{
		close (fd);
		return grub_errno;
	}
	data->fd = fd;
	disk->id = dev->id;
	for (disk->log_sector_size = 0;
		(1U << disk->log_sector_size) < sector_size;
		disk->log_sector_size++)
		;
	disk->total_sectors = bytes >> disk->log_sector_size;
	disk->max_agglomerate = 1048576
		>> (GRUB_DISK_SECTOR_BITS + GRUB_DISK_CACHE_BITS);
	disk->data = data;
	return GRUB_ERR_NONE;
}

static void
posixdisk_close (grub_disk_t disk)
{
	struct posixdisk_data *data = disk->data;

	if (!data)
		return;
	close (data->fd);
	grub_free (data);
	disk->data = NULL;
}

static grub_err_t
posixdisk_read (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size,
	char *buf)
{
	struct posixdisk_data *data = disk->data;
	grub_uint64_t byte_offset = sector << disk->log_sector_size;
	grub_uint64_t byte_count = (grub_uint64_t) size << disk->log_sector_size;
	grub_uint64_t done = 0;

	while (done < byte_count)
	{
		ssize_t got = pread (data->fd, buf + done,
			(size_t) (byte_count - done), (off_t) (byte_offset + done));

		if (got < 0)
		{
			if (errno == EINTR)
				continue;
			return grub_error (GRUB_ERR_READ_ERROR,
				"failure reading %llu sectors at 0x%llx from %s (%s)",
				(unsigned long long) size, (unsigned long long) sector,
				disk->name, strerror (errno));
		}
		if (got == 0)
			return grub_error (GRUB_ERR_READ_ERROR,
				"short read at sector 0x%llx from %s",
				(unsigned long long) sector, disk->name);
		done += (grub_uint64_t) got;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
posixdisk_write (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size,
	const char *buf)
{
	(void) disk;
	(void) sector;
	(void) size;
	(void) buf;
	return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		"posixdisk writes are not supported");
}

static struct grub_disk_dev grub_posixdisk_dev =
{
	.name = "posixdisk",
	.id = GRUB_DISK_DEVICE_HOSTDISK_ID,
	.disk_iterate = posixdisk_iterate,
	.disk_open = posixdisk_open,
	.disk_close = posixdisk_close,
	.disk_read = posixdisk_read,
	.disk_write = posixdisk_write
};

GRUB_MOD_INIT (posixdisk)
{
	scan_devices ();
	grub_disk_dev_register (&grub_posixdisk_dev);
}

GRUB_MOD_FINI (posixdisk)
{
	grub_disk_dev_unregister (&grub_posixdisk_dev);
	free_devices ();
}
