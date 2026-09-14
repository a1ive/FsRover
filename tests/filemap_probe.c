/* Native metadata mapping and read-path probe. GPL-3.0-or-later. */
#include <stdio.h>
#include <stdlib.h>
#include <grub/fs.h>
#include <grub/filemap.h>
#include <grub/disk.h>
#include <grub/device.h>
#include <grub/partition.h>
#include "rover.h"

static unsigned long long calls, sectors, records, stop_after;
static grub_err_t (*saved_read) (grub_disk_t, grub_disk_addr_t, grub_size_t, char *);

static grub_err_t
trace_read (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, char *buf)
{
	calls++;
	sectors += size;
	fprintf (stderr, "{\"read_sector\":%llu,\"sectors\":%llu}\n",
		(unsigned long long) sector, (unsigned long long) size);
	return saved_read (disk, sector, size, buf);
}

static int
record (const struct grub_file_map_extent *extent, void *data)
{
	unsigned i;
	(void) data;
	printf ("{\"offset\":%llu,\"length\":%llu,\"flags\":%u,"
		"\"decoded_offset\":%llu,\"decoded_length\":%llu,\"encoding\":\"%s\",\"storage\":[",
		(unsigned long long) extent->logical_offset,
		(unsigned long long) extent->logical_length, extent->flags,
		(unsigned long long) extent->decoded_offset,
		(unsigned long long) extent->decoded_length,
		extent->encoding ? extent->encoding : "");
	for (i = 0; i < extent->storage_count; i++)
		printf ("%s[%llu,%llu,%u]", i ? "," : "",
			(unsigned long long) extent->storage[i].offset,
			(unsigned long long) extent->storage[i].length,
			extent->storage[i].address_space);
	puts ("]}");
	records++;
	return stop_after && records >= stop_after;
}

/* Exercise the real core with synthetic metadata, without host I/O. */
static struct grub_file_map_storage core_storage[2];
static unsigned core_merge;
static unsigned core_flags, core_count, core_steps, core_callbacks, core_polls, core_cancel_at;

static int
core_cancel (void *data)
{
	(void) data;
	core_polls++;
	return core_cancel_at && core_polls >= core_cancel_at;
}

static int
core_record (const struct grub_file_map_extent *extent, void *data)
{
	(void) extent;
	(void) data;
	core_callbacks++;
	return 0;
}

static grub_err_t
core_map (grub_file_t file, struct grub_file_map_context *ctx)
{
	unsigned i;
	struct grub_file_map_extent e = { 0 };

	(void) file;
	for (i = 0; i < core_steps; i++)
	{
		if (grub_file_map_cancelled (ctx))
			return GRUB_ERR_NONE;
	}
	if (core_merge)
	{
		for (i = 0; i < 8; i++)
		{
			if (grub_file_map_simple (ctx, i * 64, 64, GRUB_FILE_MAP_DIRECT, i * 64))
				return grub_errno;
		}
		return GRUB_ERR_NONE;
	}
	e.logical_length = 512;
	e.flags = core_flags;
	e.storage = core_storage;
	e.storage_count = core_count;
	return grub_file_map_emit (ctx, &e);
}

static int
core_case (const char *name, grub_file_t file, int error, int stopped, unsigned callbacks)
{
	int actual_stop = 0;
	grub_err_t err;

	core_callbacks = core_polls = 0;
	grub_errno = GRUB_ERR_NONE;
	err = grub_file_map_range_ex (file, 0, 512, core_record, NULL,
		core_cancel, NULL, &actual_stop);
	if ((err != 0) != error || actual_stop != stopped || core_callbacks != callbacks || file->offset != 17)
	{
		fprintf (stderr, "%s: error=%u stopped=%d callbacks=%u\n",
			name, (unsigned) err, actual_stop, core_callbacks);
		return 1;
	}
	return 0;
}

static int
core_tests (void)
{
	struct grub_disk disk = { 0 };
	struct grub_partition part = { 0 }, parent = { 0 };
	struct grub_device device = { 0 };
	struct grub_fs fs = { 0 };
	struct grub_file file = { 0 };
	int failed = 0;

	disk.total_sectors = 8;
	disk.log_sector_size = 9;
	device.disk = &disk;
	fs.fs_map_range = core_map;
	file.device = &device;
	file.fs = &fs;
	file.size = 512;
	file.offset = 17;
	core_flags = GRUB_FILE_MAP_DIRECT;
	core_count = 1;
	core_storage[0].offset = 3584;
	core_storage[0].length = 512;
	failed |= core_case ("disk exact end", &file, 0, 0, 1);
	core_storage[0].offset++;
	failed |= core_case ("disk one byte past end", &file, 1, 0, 0);
	core_storage[0].offset = 1ULL << 32;
	failed |= core_case ("disk far outside", &file, 1, 0, 0);
	core_storage[0].offset = 3584;
	disk.partition = &part;
	part.len = 7;
	failed |= core_case ("partition boundary", &file, 1, 0, 0);
	part.len = 8;
	part.start = 1;
	failed |= core_case ("partition exceeds backing disk", &file, 1, 0, 0);
	disk.total_sectors = 32;
	part.parent = &parent;
	parent.len = 8;
	failed |= core_case ("parent boundary", &file, 1, 0, 0);
	parent.len = 9;
	failed |= core_case ("nested exact end", &file, 0, 0, 1);
	parent.start = ~0ULL;
	failed |= core_case ("partition translation overflow", &file, 1, 0, 0);
	disk.partition = NULL;
	disk.total_sectors = 1;
	disk.log_sector_size = 12;
	failed |= core_case ("4Kn exact end", &file, 0, 0, 1);
	core_storage[0].offset++;
	failed |= core_case ("4Kn one byte past end", &file, 1, 0, 0);
	disk.total_sectors = GRUB_DISK_SIZE_UNKNOWN;
	failed |= core_case ("unknown capacity", &file, 0, 0, 1);
	disk.total_sectors = 1;
	core_storage[0].address_space = GRUB_FILE_MAP_FS_LOGICAL;
	core_storage[0].offset = 1ULL << 32;
	failed |= core_case ("FS logical is not a volume offset", &file, 0, 0, 1);
	core_storage[0].address_space = GRUB_FILE_MAP_VOLUME;
	core_storage[0].offset = 0;
	core_storage[1] = core_storage[0];
	core_storage[1].offset = 4096;
	core_flags = GRUB_FILE_MAP_COMPRESSED | GRUB_FILE_MAP_TRANSFORMED;
	core_count = 2;
	failed |= core_case ("compressed second fragment outside", &file, 1, 0, 0);
	core_count = 1;
	core_flags = GRUB_FILE_MAP_DIRECT;
	core_cancel_at = 1;
	failed |= core_case ("cancel before driver", &file, 0, 1, 0);
	core_steps = 100;
	core_cancel_at = 30;
	failed |= core_case ("cancel metadata before first extent", &file, 0, 1, 0);
	core_steps = 0;
	core_cancel_at = 4;
	failed |= core_case ("cancel pending extent before flush", &file, 0, 1, 0);
	core_merge = 1;
	core_cancel_at = 12;
	failed |= core_case ("cancel coalescing contiguous extents", &file, 0, 1, 0);
	core_merge = 0;
	core_cancel_at = 0;
	failed |= core_case ("fresh query after cancellation", &file, 0, 0, 1);
	return failed;
}

static int
public_record (const struct rover_map_extent *extent, void *data)
{
	(void) extent;
	(void) data;
	core_callbacks++;
	return 0;
}

/* Arguments: IMAGE PATH OFFSET LENGTH STOP [OUTPUT], or
 * IMAGE PATH read OFFSET LENGTH OUTPUT for an exact normal-read slice. */
int
product_filemap_probe (int argc, const char **argv)
{
	grub_file_t file = NULL;
	grub_err_t err;
	grub_off_t saved_offset;
	unsigned long long offset, length;
	int stopped = 0, status = 1, read_only;
	char *buffer = NULL;
	FILE *out = NULL;

	if (argc == 1 && !grub_strcmp (argv[0], "core"))
		return core_tests ();
	if (argc < 5)
		return 2;
	read_only = !grub_strcmp (argv[2], "read");
	if (read_only && argc != 6)
		return 2;
	rover_init (ROVER_INIT_NO_HOSTDISK);
#ifdef _WIN32
	err = (grub_err_t) rover_winfile_add ("img0", argv[0], 0);
#else
	err = (grub_err_t) rover_posixfile_add ("img0", argv[0], 0);
#endif
	if (err)
		goto fail;
	file = grub_file_open (argv[1], GRUB_FILE_TYPE_CAT | GRUB_FILE_TYPE_NO_DECOMPRESS);
	if (!file)
		goto fail;
	offset = strtoull (argv[read_only ? 3 : 2], NULL, 0);
	length = strtoull (argv[read_only ? 4 : 3], NULL, 0);
	if (!read_only)
	{
		if (!grub_strncmp (argv[4], "cancel:", 7))
			core_cancel_at = (unsigned) strtoul (argv[4] + 7, NULL, 0);
		else
			stop_after = strtoull (argv[4], NULL, 0);
		file->offset = file->size > 17 ? 17 : 0;
		saved_offset = file->offset;
		grub_disk_cache_invalidate_all ();
		saved_read = file->device->disk->dev->disk_read;
		file->device->disk->dev->disk_read = trace_read;
		err = grub_file_map_range_ex (file, offset, length, record, NULL,
			core_cancel_at ? core_cancel : NULL, NULL, &stopped);
		file->device->disk->dev->disk_read = saved_read;
		fprintf (stderr, "{\"fs\":\"%s\",\"error\":%u,\"stopped\":%d,"
			"\"records\":%llu,\"host_reads\":%llu,\"host_sectors\":%llu,"
			"\"offset_preserved\":%d}\n", file->fs->name, (unsigned) err, stopped,
			records, calls, sectors, saved_offset == file->offset);
		if (err || saved_offset != file->offset)
			goto fail;
		if (core_cancel_at)
		{
			rover_file *public_file = rover_file_open (argv[1]);
			int public_stopped = 0;
			int public_error;

			if (!public_file)
				goto fail;
			core_polls = core_callbacks = 0;
			public_error = rover_file_map_range_ex (public_file, offset, length,
				public_record, NULL, core_cancel, NULL, &public_stopped);
			rover_file_close (public_file);
			if (public_error || public_stopped != stopped || core_callbacks != records)
				goto fail;
		}
		offset = 0;
		length = file->size;
	}
	if (argc == 6)
	{
		buffer = malloc (65536);
#ifdef _WIN32
		if (fopen_s (&out, argv[5], "wb"))
			goto fail;
#else
		out = fopen (argv[5], "wb");
#endif
		if (!buffer || !out)
			goto fail;
		grub_file_seek (file, offset);
		while (length)
		{
			grub_size_t step = length > 65536 ? 65536 : (grub_size_t) length;
			grub_ssize_t n = grub_file_read (file, buffer, step);
			if (n <= 0 || fwrite (buffer, 1, (size_t) n, out) != (size_t) n)
				goto fail;
			length -= n;
		}
		if (fclose (out))
		{
			out = NULL;
			goto fail;
		}
		out = NULL;
	}
	status = 0;
fail:
	if (status)
		fprintf (stderr, "mapping/read probe failed: %s\n",
			rover_last_error () ? rover_last_error () : "host I/O or cursor failure");
	if (out)
		fclose (out);
	free (buffer);
	if (file)
		grub_file_close (file);
	rover_fini ();
	return status;
}
