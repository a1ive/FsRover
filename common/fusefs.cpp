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

/*
 * FUSE-shaped read-only filesystem core shared by the Linux, Dokan, and
 * WinFsp adapters.  The injected dispatcher keeps Rover calls serialized.
 */

#include <errno.h>
#include <fcntl.h>

#include <algorithm>
#include <utility>
#include <vector>

#include <rover.h>

#include "fusefs.h"

namespace
{

constexpr uint32_t MODE_DIR = 0040000;
constexpr uint32_t MODE_FILE = 0100000;
constexpr uint32_t MODE_READ = 00444;
constexpr uint32_t MODE_EXEC = 00111;

std::string
rover_path (const fusefs *fs, const char *path)
{
	if (!path || !*path || (path[0] == '/' && path[1] == 0))
		return fs->root;
	return path[0] == '/' ? fs->root + path : fs->root + "/" + path;
}

void
fill_stat (const rover_stat_t &in, fusefs_stat *out)
{
	out->mode = (in.is_dir ? MODE_DIR | MODE_EXEC : MODE_FILE) | MODE_READ;
	out->inode = in.inode_set ? in.inode : 0;
	out->size = in.is_dir || in.size == ROVER_SIZE_UNKNOWN ? 0 : in.size;
	out->mtime = in.mtime_set ? in.mtime : 0;
}

struct dir_entry
{
	std::string name;
	fusefs_stat st;
	bool size_set;
};

} // namespace

void
fusefs_init (fusefs *fs, const std::string &device,
	const std::string &fs_name, unsigned long long size,
	std::function<bool (const std::function<void ()> &)> dispatch)
{
	fs->device = device;
	fs->root = "(" + device + ")";
	fs->fs_name = fs_name;
	fs->size = size;
	fs->dispatch = std::move (dispatch);
	uint32_t hash = 2166136261u;
	for (char c : device)
		hash = (hash ^ (unsigned char) c) * 16777619u;
	fs->serial = hash ? hash : 1;
}

int
fusefs_getattr (fusefs *fs, const char *path, fusefs_stat *st)
{
	rover_stat_t rover_st = {};
	int err = 0;
	std::string full = rover_path (fs, path);

	if (!fs->dispatch ([&] { err = rover_stat (full.c_str (), &rover_st); }))
		return -EIO;
	if (err)
		return -ENOENT;
	fill_stat (rover_st, st);
	return 0;
}

int
fusefs_open (fusefs *fs, const char *path, int flags, uint64_t *handle)
{
	/* POSIX and WinFsp use the low two bits for O_ACCMODE. */
	if ((flags & 3) != O_RDONLY)
		return -EROFS;

	std::string full = rover_path (fs, path);
	rover_file *file = nullptr;
	if (!fs->dispatch ([&] { file = rover_file_open (full.c_str ()); }))
		return -EIO;
	if (!file)
		return -ENOENT;
	*handle = (uint64_t) (uintptr_t) file;
	return 0;
}

int
fusefs_read (fusefs *fs, const char *path, void *buf, size_t size,
	long long offset, uint64_t *handle)
{
	if (offset < 0)
		return -EINVAL;
	if (size > 0x7fffffffU)
		size = 0x7fffffffU;

	std::string full = rover_path (fs, path);
	int result = 0;
	if (!fs->dispatch ([&]
	{
		rover_file *file = (rover_file *) (uintptr_t) *handle;
		if (!file)
		{
			file = rover_file_open (full.c_str ());
			if (!file)
			{
				result = -ENOENT;
				return;
			}
			*handle = (uint64_t) (uintptr_t) file;
		}
		unsigned long long file_size = rover_file_size (file);
		if ((unsigned long long) offset >= file_size)
			return;
		unsigned long long want = std::min<unsigned long long> (size,
			file_size - (unsigned long long) offset);
		if (rover_file_seek (file, (unsigned long long) offset))
		{
			result = -EIO;
			return;
		}
		long long got = rover_file_read (file, buf, want);
		result = got < 0 ? -EIO : (int) got;
	}))
		return -EIO;
	return result;
}

int
fusefs_release (fusefs *fs, uint64_t *handle)
{
	rover_file *file = (rover_file *) (uintptr_t) *handle;
	if (!file)
		return 0;
	*handle = 0;
	return fs->dispatch ([&] { rover_file_close (file); }) ? 0 : -EIO;
}

int
fusefs_readdir (fusefs *fs, const char *path, fusefs_fill_dir fill,
	void *data)
{
	std::string full = rover_path (fs, path);
	std::vector<dir_entry> entries;
	int err = 0;

	if (!fs->dispatch ([&]
	{
		err = rover_dir_list (full.c_str (),
			[] (const rover_dirent *ent, void *opaque) -> int
			{
				auto *out = (std::vector<dir_entry> *) opaque;
				dir_entry item = {};
				item.name = ent->name;
				item.st.mode = (ent->is_dir ? MODE_DIR | MODE_EXEC : MODE_FILE) | MODE_READ;
				item.st.inode = ent->inode_set ? ent->inode : 0;
				item.st.size = ent->size_set ? ent->size : 0;
				item.st.mtime = ent->mtime_set ? ent->mtime : 0;
				item.size_set = ent->size_set != 0;
				out->push_back (std::move (item));
				return 0;
			}, &entries);
		if (err)
			return;

		/* Directory consumers cache the first metadata snapshot.  Most
		   drivers report sizes from metadata already read while enumerating;
		   obtain exact sizes separately only when a driver cannot do so. */
		std::string prefix = full;
		if (prefix.empty () || prefix.back () != '/')
			prefix += '/';
		for (dir_entry &item : entries)
		{
			if ((item.st.mode & MODE_DIR) == MODE_DIR || item.size_set)
				continue;
			rover_file *file = rover_file_open ((prefix + item.name).c_str ());
			if (file)
			{
				item.st.size = rover_file_size (file);
				rover_file_close (file);
			}
		}
	}))
		return -EIO;
	if (err)
		return -ENOENT;

	fusefs_stat dot = {};
	dot.mode = MODE_DIR | MODE_READ | MODE_EXEC;
	if (fill (data, ".", &dot) || fill (data, "..", &dot))
		return 0;
	for (const dir_entry &item : entries)
		if (fill (data, item.name.c_str (), &item.st))
			break;
	return 0;
}

int
fusefs_statfs (fusefs *fs, fusefs_statvfs *st)
{
	st->block_size = 512;
	st->blocks = fs->size == ~0ULL ? 0 : (fs->size + 511) / 512;
	st->name_max = 255;
	return 0;
}
