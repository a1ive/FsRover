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
 * libFuzzer target: the input is a raw volume image.  It is placed in a
 * memfd, attached through posixfile as "(fuzz)", and walked with the
 * public rover API (probe, directory listing, stat, readlink, read,
 * seek and block mapping).  The walk is bounded so a large but valid
 * tree does not starve the parsers of executions.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "rover.h"

#define FUZZ_DEVNAME	"fuzz"
#define FUZZ_DEPTH_MAX	4
#define FUZZ_DIR_MAX	64
#define FUZZ_PATH_MAX	1024
#define FUZZ_READ_MAX	0x10000

struct fuzz_entry
{
	char *name;
	int is_dir;
	int is_symlink;
};

struct fuzz_dir
{
	struct fuzz_entry ent[FUZZ_DIR_MAX];
	unsigned count;
};

static int image_fd = -1;
static char image_path[64];
static unsigned char read_buf[FUZZ_READ_MAX];

static int
collect_entry (const struct rover_dirent *ent, void *data)
{
	struct fuzz_dir *dir = data;
	struct fuzz_entry *e;

	if (dir->count >= FUZZ_DIR_MAX)
		return 1;
	e = &dir->ent[dir->count];
	e->name = strdup (ent->name);
	if (!e->name)
		return 1;
	e->is_dir = ent->is_dir;
	e->is_symlink = ent->is_symlink;
	dir->count++;
	return 0;
}

static int
map_extent (const struct rover_map_extent *ext, void *data)
{
	unsigned long long *total = data;
	unsigned int i;

	*total += ext->logical_length;
	for (i = 0; i < ext->storage_count; i++)
		*total += ext->storage[i].length;
	return 0;
}

static void
walk_file (const char *path)
{
	unsigned long long size;
	unsigned long long mapped = 0;
	rover_file *file;
	int stopped = 0;

	file = rover_file_open (path);
	if (!file)
		return;
	size = rover_file_size (file);
	if (rover_file_read (file, read_buf, sizeof (read_buf)) < 0)
		goto done;
	if (size != ROVER_SIZE_UNKNOWN && size > sizeof (read_buf)
		&& !rover_file_seek (file, size / 2))
		rover_file_read (file, read_buf, 4096);
	rover_file_map_range (file, 0, sizeof (read_buf), map_extent, &mapped,
		&stopped);
done:
	rover_file_close (file);
}

static void
walk_dir (char *path, size_t len, int depth)
{
	struct fuzz_dir *dir;
	unsigned i;

	dir = calloc (1, sizeof (*dir));
	if (!dir)
		return;
	if (rover_dir_list (path, collect_entry, dir))
		goto done;
	for (i = 0; i < dir->count; i++)
	{
		struct fuzz_entry *e = &dir->ent[i];
		size_t name_len = strlen (e->name);
		rover_stat_t st;
		char target[256];
		unsigned long long target_len;

		if (len + name_len + 2 > FUZZ_PATH_MAX)
			continue;
		memcpy (path + len, e->name, name_len + 1);
		rover_stat (path, &st);
		if (e->is_symlink)
			rover_readlink (path, target, sizeof (target), &target_len);
		else if (e->is_dir)
		{
			if (depth < FUZZ_DEPTH_MAX)
			{
				path[len + name_len] = '/';
				path[len + name_len + 1] = '\0';
				walk_dir (path, len + name_len + 1, depth + 1);
			}
		}
		else
			walk_file (path);
		path[len] = '\0';
	}
done:
	for (i = 0; i < dir->count; i++)
		free (dir->ent[i].name);
	free (dir);
}

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
	(void) argc;
	(void) argv;
	image_fd = memfd_create ("rover-fuzz", MFD_CLOEXEC);
	if (image_fd < 0)
	{
		perror ("memfd_create");
		abort ();
	}
	snprintf (image_path, sizeof (image_path), "/proc/self/fd/%d", image_fd);
	rover_init (ROVER_INIT_NO_HOSTDISK);
	return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	static char path[FUZZ_PATH_MAX];
	size_t done = 0;

	if (ftruncate (image_fd, 0))
		abort ();
	while (done < size)
	{
		ssize_t n = pwrite (image_fd, data + done, size - done, (off_t) done);

		if (n <= 0)
			abort ();
		done += (size_t) n;
	}
	if (rover_posixfile_add (FUZZ_DEVNAME, image_path, 0))
		return 0;
	rover_fs_name (FUZZ_DEVNAME);
	strcpy (path, "(" FUZZ_DEVNAME ")/");
	walk_dir (path, strlen (path), 0);
	/* Every handle is closed by now; a failure here is a leaked reference. */
	if (rover_posixfile_del (FUZZ_DEVNAME))
	{
		fprintf (stderr, "rover_posixfile_del: %s\n", rover_last_error ());
		abort ();
	}
	return 0;
}
