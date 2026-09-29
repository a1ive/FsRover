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
#include <list>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <rover.h>

#include "fusefs.h"

/* Adapter threads read the cache directly so hits skip the dispatcher; only
   the dispatched (serialized) side inserts, which orders every insert with
   respect to rover_set_fs_char_encoding(). */
struct fusefs_cache
{
	struct entry
	{
		int err;	/* mount_stat() result for exactly this path */
		rover_stat_t st;
	};
	typedef std::list<std::pair<std::string, entry>> lru_list;

	std::mutex lock;
	size_t max;	/* entries kept, at least 1 */
	lru_list lru;	/* most recently used first */
	/* Keys borrow the strings of list nodes, which never move. */
	std::unordered_map<std::string_view, lru_list::iterator> map;
};

namespace
{

constexpr uint32_t MODE_DIR = 0040000;
constexpr uint32_t MODE_FILE = 0100000;
constexpr uint32_t MODE_READ = 00444;
constexpr uint32_t MODE_EXEC = 00111;

bool
cache_get (fusefs_cache *cache, std::string_view path, fusefs_cache::entry *out)
{
	std::lock_guard<std::mutex> hold (cache->lock);
	auto it = cache->map.find (path);
	if (it == cache->map.end ())
		return false;
	cache->lru.splice (cache->lru.begin (), cache->lru, it->second);
	*out = it->second->second;
	return true;
}

/* Only outcomes fixed by on-disk metadata are kept; I/O and allocation
   failures may succeed on a later attempt. */
void
cache_put (fusefs_cache *cache, std::string_view path,
	const fusefs_cache::entry &ent)
{
	if (ent.err && ent.err != -ENOENT && ent.err != -ENOTDIR
		&& ent.err != -ENOTSUP)
		return;

	std::lock_guard<std::mutex> hold (cache->lock);
	auto it = cache->map.find (path);
	if (it != cache->map.end ())
	{
		it->second->second = ent;
		cache->lru.splice (cache->lru.begin (), cache->lru, it->second);
		return;
	}
	if (cache->lru.size () >= cache->max)
	{
		cache->map.erase (cache->lru.back ().first);
		cache->lru.pop_back ();
	}
	cache->lru.emplace_front (std::string (path), ent);
	cache->map.emplace (cache->lru.front ().first, cache->lru.begin ());
}

std::string
rover_path (const fusefs *fs, const char *path)
{
	if (!path || !*path || (path[0] == '/' && path[1] == 0))
		return fs->root;
	return path[0] == '/' ? fs->root + path : fs->root + "/" + path;
}

fusefs_cache::entry
lookup (const char *path)
{
	fusefs_cache::entry ent = {};
	if (rover_stat (path, &ent.st))
		ent.err = -rover_last_errno ();
	else if (ent.st.is_symlink)
		ent.err = -ENOTSUP;
	return ent;
}

/* GRUB exposes link identity but has no common readlink interface.  Do not
   synthesize regular files from links or follow a directory link indirectly.
   Reject every link component, including direct calls with /link/child.

   rover_stat() resolves from the root and scans the whole parent directory,
   so each component goes through the cache.  A cached success for FULL
   implies its ancestors were checked when it was stored. */
fusefs_cache::entry
resolve (fusefs_cache *cache, const std::string &full)
{
	fusefs_cache::entry ent;
	size_t close = full.find (')');
	for (size_t slash = full.find ('/', close == std::string::npos ? 0 : close + 1);
		slash != std::string::npos; slash = full.find ('/', slash + 1))
	{
		if (slash == close + 1)
			continue;
		std::string_view parent (full.data (), slash);
		if (!cache_get (cache, parent, &ent))
		{
			ent = lookup (std::string (parent).c_str ());
			cache_put (cache, parent, ent);
		}
		if (!ent.err && !ent.st.is_dir)
			ent.err = -ENOTDIR;
		if (ent.err)
			return { ent.err, {} };
	}
	return lookup (full.c_str ());
}

int
mount_stat (fusefs_cache *cache, const std::string &full, rover_stat_t *st)
{
	fusefs_cache::entry ent;
	if (!cache_get (cache, full, &ent))
	{
		ent = resolve (cache, full);
		cache_put (cache, full, ent);
	}
	*st = ent.st;
	return ent.err;
}

rover_file *
open_file (fusefs_cache *cache, const std::string &full, int *error)
{
	rover_stat_t st = {};
	*error = mount_stat (cache, full, &st);
	if (*error)
		return nullptr;
	if (st.is_dir)
	{
		*error = -EISDIR;
		return nullptr;
	}
	rover_file *file = rover_file_open (full.c_str ());
	if (!file)
		*error = -rover_last_errno ();
	return file;
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
	fusefs_cache::entry ent;	/* what lookup() would return */
};

} // namespace

void
fusefs_init (fusefs *fs, const std::string &device,
	const std::string &fs_name, unsigned long long size,
	unsigned int sector_size,
	std::function<bool (const std::function<void ()> &)> dispatch,
	size_t cache_max)
{
	fs->device = device;
	fs->root = "(" + device + ")";
	fs->fs_name = fs_name;
	fs->size = size;
	/* WinFsp caps sectors at 4096; Dokan wants a power of two.  */
	if (sector_size < 512 || sector_size > 4096 || (sector_size & (sector_size - 1)))
		sector_size = 512;
	fs->sector_size = sector_size;
	fs->dispatch = std::move (dispatch);
	fs->cache = std::make_shared<fusefs_cache> ();
	fs->cache->max = cache_max ? cache_max : 1;
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
	fusefs_cache::entry ent;

	if (cache_get (fs->cache.get (), full, &ent))
	{
		if (ent.err)
			return ent.err;
		fill_stat (ent.st, st);
		return 0;
	}
	if (!fs->dispatch ([&] { err = mount_stat (fs->cache.get (), full, &rover_st); }))
		return -EIO;
	if (err)
		return err;
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
	int err = 0;
	if (!fs->dispatch ([&] { file = open_file (fs->cache.get (), full, &err); }))
		return -EIO;
	if (!file)
		return err;
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
			file = open_file (fs->cache.get (), full, &result);
			if (!file)
				return;
			*handle = (uint64_t) (uintptr_t) file;
		}
		unsigned long long file_size = rover_file_size (file);
		if ((unsigned long long) offset >= file_size)
			return;
		unsigned long long want = std::min<unsigned long long> (size,
			file_size - (unsigned long long) offset);
		if (rover_file_seek (file, (unsigned long long) offset))
		{
			result = -rover_last_errno ();
			return;
		}
		long long got = rover_file_read (file, buf, want);
		result = got < 0 ? -rover_last_errno () : (int) got;
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
		fusefs_cache *cache = fs->cache.get ();
		rover_stat_t st = {};
		err = mount_stat (cache, full, &st);
		if (err)
			return;
		if (!st.is_dir)
		{
			err = -ENOTDIR;
			return;
		}
		err = rover_dir_list (full.c_str (),
			[] (const rover_dirent *ent, void *opaque) -> int
			{
				auto *out = (std::vector<dir_entry> *) opaque;
				dir_entry item = {};
				item.name = ent->name;
				item.ent.err = ent->is_symlink ? -ENOTSUP : 0;
				item.ent.st.is_dir = ent->is_dir;
				item.ent.st.is_symlink = ent->is_symlink;
				item.ent.st.mtime_set = ent->mtime_set;
				item.ent.st.mtime = ent->mtime;
				item.ent.st.size = ent->size_set ? ent->size : ROVER_SIZE_UNKNOWN;
				item.ent.st.inode_set = ent->inode_set;
				item.ent.st.inode = ent->inode;
				out->push_back (std::move (item));
				return 0;
			}, &entries);
		if (err)
		{
			err = -rover_last_errno ();
			return;
		}

		/* Directory consumers cache the first metadata snapshot.  Most
		   drivers report sizes from metadata already read while enumerating;
		   obtain exact sizes separately only when a driver cannot do so,
		   and only once per file. */
		std::string prefix = full;
		if (prefix.empty () || prefix.back () != '/')
			prefix += '/';
		for (dir_entry &item : entries)
		{
			rover_stat_t &ist = item.ent.st;
			if (ist.is_dir || ist.is_symlink || ist.size != ROVER_SIZE_UNKNOWN)
				continue;
			std::string child = prefix + item.name;
			fusefs_cache::entry cached;
			if (cache_get (cache, child, &cached) && !cached.err)
			{
				ist.size = cached.st.size;
				continue;
			}
			rover_file *file = rover_file_open (child.c_str ());
			if (file)
			{
				ist.size = rover_file_size (file);
				rover_file_close (file);
			}
		}

		/* Seed the per-entry lookups that follow a listing.  Reverse order
		   leaves the first of duplicate names, the one rover_stat() finds. */
		for (auto it = entries.rbegin (); it != entries.rend (); ++it)
			cache_put (cache, prefix + it->name, it->ent);
	}))
		return -EIO;
	if (err)
		return err;

	fusefs_stat dot = {};
	dot.mode = MODE_DIR | MODE_READ | MODE_EXEC;
	if (fill (data, ".", &dot) || fill (data, "..", &dot))
		return 0;
	for (const dir_entry &item : entries)
	{
		/* Unsupported links must not appear as ordinary files. */
		if (item.ent.st.is_symlink)
			continue;
		fusefs_stat st = {};
		fill_stat (item.ent.st, &st);
		if (fill (data, item.name.c_str (), &st))
			break;
	}
	return 0;
}

int
fusefs_statfs (fusefs *fs, fusefs_statvfs *st)
{
	st->block_size = fs->sector_size;
	st->blocks = fs->size == ~0ULL ? 0 : (fs->size + fs->sector_size - 1) / fs->sector_size;
	st->name_max = 255;
	return 0;
}

void
fusefs_invalidate (fusefs *fs)
{
	std::lock_guard<std::mutex> hold (fs->cache->lock);
	fs->cache->map.clear ();
	fs->cache->lru.clear ();
}
