/*
 *  Rover -- Filesystem browser
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

#ifndef FSROVER_FUSEFS_H
#define FSROVER_FUSEFS_H	1

#include <stddef.h>
#include <stdint.h>

#include <functional>
#include <memory>
#include <string>

/* Host-neutral, FUSE-shaped view of a mounted Rover filesystem.  Platform
   adapters translate these small structures to libfuse, WinFsp-FUSE or
   Dokany ABI structures. */

struct fusefs_cache;

/* Roughly 250 bytes per entry: at most ~16 MiB per mount. */
constexpr size_t FUSEFS_CACHE_MAX = 65536;

struct fusefs
{
	std::string device;
	std::string root;
	std::string fs_name;
	unsigned long long size;
	/* Volume sector size reported to the host, a power of two in
	   512..4096; also the allocation unit (grub does not expose cluster
	   sizes).  */
	uint32_t sector_size;
	uint32_t serial;
	std::function<bool (const std::function<void ()> &)> dispatch;
	/* Path -> metadata LRU.  The volume is read-only, so entries stay valid
	   until the name decoding changes (see fusefs_invalidate). */
	std::shared_ptr<fusefs_cache> cache;
};

struct fusefs_stat
{
	uint32_t mode;
	uint64_t inode;
	uint64_t size;
	long long mtime;
};

struct fusefs_statvfs
{
	uint64_t blocks;
	uint64_t block_size;
	uint64_t name_max;
};

typedef int (*fusefs_fill_dir) (void *data, const char *name,
	const fusefs_stat *st);

/* SECTOR_SIZE is the device's logical sector size (rover_disk_info),
   0 if unknown. */
void fusefs_init (fusefs *fs, const std::string &device,
	const std::string &fs_name, unsigned long long size,
	unsigned int sector_size,
	std::function<bool (const std::function<void ()> &)> dispatch,
	size_t cache_max = FUSEFS_CACHE_MAX);

int fusefs_getattr (fusefs *fs, const char *path, fusefs_stat *st);
int fusefs_open (fusefs *fs, const char *path, int flags, uint64_t *handle);
int fusefs_read (fusefs *fs, const char *path, void *buf, size_t size,
	long long offset, uint64_t *handle);
int fusefs_release (fusefs *fs, uint64_t *handle);
int fusefs_readdir (fusefs *fs, const char *path, fusefs_fill_dir fill,
	void *data);
int fusefs_statfs (fusefs *fs, fusefs_statvfs *st);

/* Drop cached metadata.  Call after rover_set_fs_char_encoding() returns:
   names decoded with the old setting no longer resolve the same way. */
void fusefs_invalidate (fusefs *fs);

#endif
