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

#include <grub/device.h>
#include <grub/disk.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/misc.h>
#include <grub/partition.h>
#include <grub/procfs.h>

#include "proc.h"
#include "rover.h"
#include "version.h"

#define ROVER_PROC_STATS_MAX	256
#define ROVER_PROC_ERRORS_MAX	32
#define ROVER_PROC_NAME_MAX	128

struct rover_proc_diskstat
{
	char name[ROVER_PROC_NAME_MAX];
	grub_uint64_t reads;
	grub_uint64_t bytes;
	grub_uint64_t cache_hits;
	grub_uint64_t cache_misses;
	grub_uint64_t errors;
};

struct rover_proc_error
{
	grub_uint64_t sequence;
	grub_err_t error;
	char message[GRUB_MAX_ERRMSG];
};

static struct rover_proc_diskstat diskstats[ROVER_PROC_STATS_MAX];
static grub_size_t diskstats_count;
static struct rover_proc_error errors[ROVER_PROC_ERRORS_MAX];
static grub_size_t errors_next;
static grub_size_t errors_count;
static grub_uint64_t error_sequence;
static int proc_enabled;
static int proc_observing;

static struct rover_proc_diskstat *
proc_find_diskstat (grub_disk_t disk)
{
	grub_size_t i;
	const char *name = disk->name;

	for (i = 0; i < diskstats_count; i++)
		if (grub_strcmp (diskstats[i].name, name) == 0)
			return &diskstats[i];

	if (diskstats_count == ROVER_PROC_STATS_MAX)
		return NULL;

	i = diskstats_count++;
	grub_memset (&diskstats[i], 0, sizeof (diskstats[i]));
	grub_snprintf (diskstats[i].name, sizeof (diskstats[i].name), "%s", name);
	return &diskstats[i];
}

void
grub_procfs_record_disk_read (grub_disk_t disk, grub_size_t bytes, grub_err_t error)
{
	struct rover_proc_diskstat *stat;

	if (!proc_enabled || proc_observing || disk->dev->id == GRUB_DISK_DEVICE_PROCFS_ID)
		return;
	stat = proc_find_diskstat (disk);
	if (!stat)
		return;
	stat->reads++;
	if (error == GRUB_ERR_NONE)
		stat->bytes += bytes;
	if (error == GRUB_ERR_READ_ERROR || error == GRUB_ERR_FILE_READ_ERROR || error == GRUB_ERR_IO)
		stat->errors++;
}

void
grub_procfs_record_cache (grub_disk_t disk, int hit)
{
	struct rover_proc_diskstat *stat;

	if (!proc_enabled || proc_observing || disk->dev->id == GRUB_DISK_DEVICE_PROCFS_ID)
		return;
	stat = proc_find_diskstat (disk);
	if (!stat)
		return;
	if (hit)
		stat->cache_hits++;
	else
		stat->cache_misses++;
}

void
grub_procfs_record_error (grub_err_t error, const char *message)
{
	struct rover_proc_error *entry;

	if (!proc_enabled || proc_observing || error == GRUB_ERR_NONE)
		return;
	entry = &errors[errors_next];
	entry->sequence = ++error_sequence;
	entry->error = error;
	grub_snprintf (entry->message, sizeof (entry->message), "%s", message);
	errors_next = (errors_next + 1) % ROVER_PROC_ERRORS_MAX;
	if (errors_count < ROVER_PROC_ERRORS_MAX)
		errors_count++;
}

static grub_err_t
proc_version (struct grub_procfs_entry *entry, struct grub_procfs_writer *writer)
{
	(void) entry;
	grub_procfs_printf (writer, "FsRover\t%s\r\n", ROVER_VERSION_STR);
	grub_procfs_printf (writer, "GRUB\t%s\r\n", PACKAGE_VERSION);
	grub_procfs_printf (writer, "architecture\t%s\r\n", GRUB_TARGET_CPU);
	grub_procfs_printf (writer, "platform\t%s\r\n", GRUB_PLATFORM);
#if defined (_MSC_VER)
	grub_procfs_printf (writer, "compiler\tMSVC %d\r\n", _MSC_VER);
#endif
	return grub_procfs_writer_error (writer);
}

struct proc_support_context
{
	struct grub_procfs_writer *writer;
	const char *class_name;
};

static int
proc_support_hook (const char *name, void *data)
{
	struct proc_support_context *context = data;

	grub_procfs_printf (context->writer, "%s\t%s\r\n", context->class_name, name);
	return grub_procfs_writer_error (context->writer) != GRUB_ERR_NONE;
}

static grub_err_t
proc_devices (struct grub_procfs_entry *entry, struct grub_procfs_writer *writer)
{
	struct proc_support_context context;
	grub_disk_dev_t diskdev;

	grub_procfs_puts (writer, entry->data);
	for (diskdev = grub_disk_dev_list; diskdev; diskdev = diskdev->next)
		grub_procfs_printf (writer, "disk\t%s\r\n", diskdev->name);

	context.writer = writer;
	context.class_name = "volume";
	rover_enum_support (ROVER_SUPPORT_DISKFILTER, proc_support_hook, &context);
	context.class_name = "crypto";
	rover_enum_support (ROVER_SUPPORT_CRYPTODISK, proc_support_hook, &context);
	context.class_name = "io";
	rover_enum_support (ROVER_SUPPORT_IOFILTER, proc_support_hook, &context);
	return grub_procfs_writer_error (writer);
}

struct proc_enum_context
{
	struct grub_procfs_writer *writer;
};

static int
proc_partition_hook (const char *name, void *data)
{
	struct proc_enum_context *context = data;
	grub_device_t device;
	grub_err_t error;
	grub_uint64_t sectors;
	grub_uint64_t start = 0;

	device = grub_device_open (name);
	if (!device)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	if (!device->disk || device->disk->dev->id == GRUB_DISK_DEVICE_PROCFS_ID)
		goto out;

	sectors = grub_disk_native_sectors (device->disk);
	if (device->disk->partition)
		start = grub_disk_to_native_sector (device->disk, grub_partition_get_start (device->disk->partition));
	if (sectors == GRUB_DISK_SIZE_UNKNOWN)
		grub_procfs_printf (context->writer, "%s\t%llu\t-\t%u\r\n",
			name, (unsigned long long) start,
			1U << device->disk->log_sector_size);
	else
		grub_procfs_printf (context->writer, "%s\t%llu\t%llu\t%u\r\n",
			name, (unsigned long long) start,
			(unsigned long long) sectors,
			1U << device->disk->log_sector_size);

out:
	error = grub_procfs_writer_error (context->writer);
	grub_device_close (device);
	grub_errno = error;
	return error != GRUB_ERR_NONE;
}

static grub_err_t
proc_partitions (struct grub_procfs_entry *entry, struct grub_procfs_writer *writer)
{
	struct proc_enum_context context;

	context.writer = writer;
	grub_procfs_puts (writer, entry->data);
	if (grub_procfs_writer_error (writer) == GRUB_ERR_NONE)
	{
		proc_observing++;
		grub_device_iterate (proc_partition_hook, &context);
		proc_observing--;
	}
	if (grub_procfs_writer_error (writer) == GRUB_ERR_NONE)
		grub_errno = GRUB_ERR_NONE;
	return grub_procfs_writer_error (writer);
}

static int
proc_mount_hook (const char *name, void *data)
{
	struct proc_enum_context *context = data;
	grub_device_t device;
	grub_err_t error;
	grub_fs_t fs;

	device = grub_device_open (name);
	if (!device)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	fs = grub_fs_probe (device);
	if (fs)
		grub_procfs_printf (context->writer, "%s\t%s\r\n", name, fs->name);
	error = grub_procfs_writer_error (context->writer);
	grub_device_close (device);
	grub_errno = error;
	return error != GRUB_ERR_NONE;
}

static grub_err_t
proc_mounts (struct grub_procfs_entry *entry, struct grub_procfs_writer *writer)
{
	struct proc_enum_context context;

	context.writer = writer;
	grub_procfs_puts (writer, entry->data);
	if (grub_procfs_writer_error (writer) == GRUB_ERR_NONE)
	{
		proc_observing++;
		grub_device_iterate (proc_mount_hook, &context);
		proc_observing--;
	}
	if (grub_procfs_writer_error (writer) == GRUB_ERR_NONE)
		grub_errno = GRUB_ERR_NONE;
	return grub_procfs_writer_error (writer);
}

static grub_err_t
proc_diskstats (struct grub_procfs_entry *entry, struct grub_procfs_writer *writer)
{
	grub_size_t i;

	grub_procfs_puts (writer, entry->data);
	for (i = 0; i < diskstats_count; i++)
		grub_procfs_printf (writer, "%s\t%llu\t%llu\t%llu\t%llu\t%llu\r\n",
			diskstats[i].name,
			(unsigned long long) diskstats[i].reads,
			(unsigned long long) diskstats[i].bytes,
			(unsigned long long) diskstats[i].cache_hits,
			(unsigned long long) diskstats[i].cache_misses,
			(unsigned long long) diskstats[i].errors);
	return grub_procfs_writer_error (writer);
}

static void
proc_append_error_message (struct grub_procfs_writer *writer, const char *message)
{
	char clean[GRUB_MAX_ERRMSG];
	grub_size_t i;

	for (i = 0; i + 1 < sizeof (clean) && message[i]; i++)
		clean[i] = (message[i] == '\r' || message[i] == '\n' || message[i] == '\t') ? ' ' : message[i];
	clean[i] = '\0';
	grub_procfs_puts (writer, clean);
}

static const char *
proc_error_name (grub_err_t error)
{
#define ROVER_ERROR_NAME(value) case value: return #value
	switch (error)
	{
	ROVER_ERROR_NAME (GRUB_ERR_NONE);
	ROVER_ERROR_NAME (GRUB_ERR_TEST_FAILURE);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_MODULE);
	ROVER_ERROR_NAME (GRUB_ERR_OUT_OF_MEMORY);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_FILE_TYPE);
	ROVER_ERROR_NAME (GRUB_ERR_FILE_NOT_FOUND);
	ROVER_ERROR_NAME (GRUB_ERR_FILE_READ_ERROR);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_FILENAME);
	ROVER_ERROR_NAME (GRUB_ERR_UNKNOWN_FS);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_FS);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_NUMBER);
	ROVER_ERROR_NAME (GRUB_ERR_OUT_OF_RANGE);
	ROVER_ERROR_NAME (GRUB_ERR_UNKNOWN_DEVICE);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_DEVICE);
	ROVER_ERROR_NAME (GRUB_ERR_READ_ERROR);
	ROVER_ERROR_NAME (GRUB_ERR_WRITE_ERROR);
	ROVER_ERROR_NAME (GRUB_ERR_UNKNOWN_COMMAND);
	ROVER_ERROR_NAME (GRUB_ERR_INVALID_COMMAND);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_ARGUMENT);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_PART_TABLE);
	ROVER_ERROR_NAME (GRUB_ERR_UNKNOWN_OS);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_OS);
	ROVER_ERROR_NAME (GRUB_ERR_NO_KERNEL);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_FONT);
	ROVER_ERROR_NAME (GRUB_ERR_NOT_IMPLEMENTED_YET);
	ROVER_ERROR_NAME (GRUB_ERR_SYMLINK_LOOP);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_COMPRESSED_DATA);
	ROVER_ERROR_NAME (GRUB_ERR_MENU);
	ROVER_ERROR_NAME (GRUB_ERR_TIMEOUT);
	ROVER_ERROR_NAME (GRUB_ERR_IO);
	ROVER_ERROR_NAME (GRUB_ERR_ACCESS_DENIED);
	ROVER_ERROR_NAME (GRUB_ERR_EXTRACTOR);
	ROVER_ERROR_NAME (GRUB_ERR_NET_BAD_ADDRESS);
	ROVER_ERROR_NAME (GRUB_ERR_NET_ROUTE_LOOP);
	ROVER_ERROR_NAME (GRUB_ERR_NET_NO_ROUTE);
	ROVER_ERROR_NAME (GRUB_ERR_NET_NO_ANSWER);
	ROVER_ERROR_NAME (GRUB_ERR_NET_NO_CARD);
	ROVER_ERROR_NAME (GRUB_ERR_WAIT);
	ROVER_ERROR_NAME (GRUB_ERR_BUG);
	ROVER_ERROR_NAME (GRUB_ERR_NET_PORT_CLOSED);
	ROVER_ERROR_NAME (GRUB_ERR_NET_INVALID_RESPONSE);
	ROVER_ERROR_NAME (GRUB_ERR_NET_UNKNOWN_ERROR);
	ROVER_ERROR_NAME (GRUB_ERR_NET_PACKET_TOO_BIG);
	ROVER_ERROR_NAME (GRUB_ERR_NET_NO_DOMAIN);
	ROVER_ERROR_NAME (GRUB_ERR_EOF);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_SIGNATURE);
	ROVER_ERROR_NAME (GRUB_ERR_BAD_FIRMWARE);
	ROVER_ERROR_NAME (GRUB_ERR_STILL_REFERENCED);
	ROVER_ERROR_NAME (GRUB_ERR_RECURSION_DEPTH);
	ROVER_ERROR_NAME (GRUB_ERR_EXISTS);
	default:
		return "GRUB_ERR_UNKNOWN";
	}
#undef ROVER_ERROR_NAME
}

static grub_err_t
proc_errors (struct grub_procfs_entry *proc_entry, struct grub_procfs_writer *writer)
{
	grub_size_t first;
	grub_size_t i;

	grub_procfs_puts (writer, proc_entry->data);
	first = (errors_next + ROVER_PROC_ERRORS_MAX - errors_count) % ROVER_PROC_ERRORS_MAX;
	for (i = 0; i < errors_count; i++)
	{
		const struct rover_proc_error *entry = &errors[(first + i) % ROVER_PROC_ERRORS_MAX];

		grub_procfs_printf (writer, "%llu\t%d\t%s\t",
			(unsigned long long) entry->sequence, (int) entry->error,
			proc_error_name (entry->error));
		proc_append_error_message (writer, entry->message);
		grub_procfs_puts (writer, "\r\n");
	}
	return grub_procfs_writer_error (writer);
}

static struct grub_procfs_entry version_entry =
{
	.name = "version",
	.data = NULL,
	.generate = proc_version
};

static struct grub_procfs_entry devices_entry =
{
	.name = "devices",
	.data = "class\tname\r\n",
	.generate = proc_devices
};

static struct grub_procfs_entry partitions_entry =
{
	.name = "partitions",
	.data = "device\tstart_lba\tsectors\tsector_size\r\n",
	.generate = proc_partitions
};

static struct grub_procfs_entry mounts_entry =
{
	.name = "mounts",
	.data = "device\tfilesystem\r\n",
	.generate = proc_mounts
};

static struct grub_procfs_entry diskstats_entry =
{
	.name = "diskstats",
	.data = "device\treads\tbytes_read\tcache_hits\tcache_misses\terrors\r\n",
	.generate = proc_diskstats
};

static struct grub_procfs_entry errors_entry =
{
	.name = "errors",
	.data = "sequence\terrno\tname\tmessage\r\n",
	.generate = proc_errors
};

void
rover_proc_init (void)
{
	grub_memset (diskstats, 0, sizeof (diskstats));
	grub_memset (errors, 0, sizeof (errors));
	diskstats_count = 0;
	errors_next = 0;
	errors_count = 0;
	error_sequence = 0;
	proc_observing = 0;
	grub_procfs_register (&version_entry);
	grub_procfs_register (&devices_entry);
	grub_procfs_register (&partitions_entry);
	grub_procfs_register (&mounts_entry);
	grub_procfs_register (&diskstats_entry);
	grub_procfs_register (&errors_entry);
	proc_enabled = 1;
}

void
rover_proc_fini (void)
{
	proc_enabled = 0;
	grub_procfs_unregister (&errors_entry);
	grub_procfs_unregister (&diskstats_entry);
	grub_procfs_unregister (&mounts_entry);
	grub_procfs_unregister (&partitions_entry);
	grub_procfs_unregister (&devices_entry);
	grub_procfs_unregister (&version_entry);
}
