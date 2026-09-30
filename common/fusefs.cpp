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
#include <string.h>

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
   respect to rover_set_fs_char_encoding().

   Two kinds of key share the LRU: a mount path ("(dev)/a/b") maps to what
   the mount presents there, and "#" plus a physical path maps to what
   rover_stat() reports for it.  A physical path contains no link
   component, so GRUB never has to follow one; the core resolves links
   itself, which also covers drivers whose lookup does not follow them. */
struct fusefs_cache
{
	struct entry
	{
		int err;	/* result for exactly this key */
		rover_stat_t st;
		std::string phys;	/* physical path of the object */
		std::string link;	/* target when st.is_symlink */
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

typedef fusefs_cache::entry entry;

constexpr uint32_t MODE_DIR = 0040000;
constexpr uint32_t MODE_FILE = 0100000;
constexpr uint32_t MODE_LINK = 0120000;
constexpr uint32_t MODE_READ = 00444;
constexpr uint32_t MODE_EXEC = 00111;

/* Links replaced while resolving one path (Linux MAXSYMLINKS). */
constexpr unsigned LINK_DEPTH_MAX = 40;
/* Longest link target accepted from a driver. */
constexpr unsigned long long LINK_TARGET_MAX = 65536;

bool
cache_get (fusefs_cache *cache, std::string_view key, entry *out)
{
	std::lock_guard<std::mutex> hold (cache->lock);
	auto it = cache->map.find (key);
	if (it == cache->map.end ())
		return false;
	cache->lru.splice (cache->lru.begin (), cache->lru, it->second);
	*out = it->second->second;
	return true;
}

/* Only outcomes fixed by on-disk metadata are kept; I/O and allocation
   failures may succeed on a later attempt. */
void
cache_put (fusefs_cache *cache, std::string_view key, const entry &ent)
{
	if (ent.err && ent.err != -ENOENT && ent.err != -ENOTDIR
		&& ent.err != -ELOOP && ent.err != -ENAMETOOLONG)
		return;

	std::lock_guard<std::mutex> hold (cache->lock);
	auto it = cache->map.find (key);
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
	cache->lru.emplace_front (std::string (key), ent);
	cache->map.emplace (cache->lru.front ().first, cache->lru.begin ());
}

entry
failure (int err)
{
	entry ent = {};
	ent.err = err;
	return ent;
}

std::string
rover_path (const fusefs *fs, const char *path)
{
	if (!path || !*path || (path[0] == '/' && path[1] == 0))
		return fs->root;
	return path[0] == '/' ? fs->root + path : fs->root + "/" + path;
}

std::string
raw_key (const std::string &phys)
{
	return "#" + phys;
}

/* Read the target of a link entry.  A driver that flags links but cannot
   report targets (registry link keys, ReFS/WIM reparse points) gets its
   entry shown as the ordinary object GRUB exposes. */
void
settle_link (entry *ent)
{
	if (!ent->st.is_symlink)
		return;
	std::string target (256, '\0');
	unsigned long long length = 0;
	for (;;)
	{
		if (rover_readlink (ent->phys.c_str (), target.data (), target.size (), &length))
		{
			int err = -rover_last_errno ();
			if (err == -ENOTSUP)
				ent->st.is_symlink = 0;
			else
				ent->err = err;
			return;
		}
		if (length < target.size ())
			break;
		if (length >= LINK_TARGET_MAX)
		{
			ent->err = -ENAMETOOLONG;
			return;
		}
		target.resize ((size_t) length + 1);
	}
	target.resize ((size_t) length);
	ent->link = std::move (target);
}

entry
raw_stat (fusefs_cache *cache, const std::string &phys)
{
	entry ent;
	std::string key = raw_key (phys);
	if (cache_get (cache, key, &ent))
		return ent;
	ent = {};
	ent.phys = phys;
	if (rover_stat (phys.c_str (), &ent.st))
		ent.err = -rover_last_errno ();
	else
		settle_link (&ent);
	cache_put (cache, key, ent);
	return ent;
}

/* Push the components of PATH so that the first one is popped first. */
void
push_components (std::vector<std::string> *todo, std::string_view path)
{
	size_t end = path.size ();
	while (end > 0)
	{
		size_t start = path.rfind ('/', end - 1);
		start = start == std::string_view::npos ? 0 : start + 1;
		if (start < end)
			todo->emplace_back (path.substr (start, end - start));
		end = start ? start - 1 : 0;
	}
}

/* Resolve the mount path FULL the way POSIX does: links in leading
   components are replaced by their targets, FOLLOW decides the final one.
   Absolute targets start at the device root.  The result's phys names the
   object itself, free of links. */
entry
walk (fusefs *fs, const std::string &full, bool follow)
{
	fusefs_cache *cache = fs->cache.get ();
	std::vector<std::string> todo;
	push_components (&todo, std::string_view (full).substr (fs->root.size ()));
	entry cur = raw_stat (cache, fs->root);
	unsigned links = 0;

	while (!cur.err && !todo.empty ())
	{
		std::string name = std::move (todo.back ());
		todo.pop_back ();
		if (!cur.st.is_dir)
			return failure (-ENOTDIR);
		if (name == ".")
			continue;
		if (name == "..")
		{
			/* Device names may contain '/', so stay right of the root. */
			size_t slash = cur.phys.rfind ('/');
			if (cur.phys.size () > fs->root.size () && slash >= fs->root.size ())
				cur = raw_stat (cache, cur.phys.substr (0, slash));
			continue;
		}
		entry next = raw_stat (cache, cur.phys + "/" + name);
		if (next.err)
			return failure (next.err);
		if (next.st.is_symlink && (follow || !todo.empty ()))
		{
			if (++links > LINK_DEPTH_MAX)
				return failure (-ELOOP);
			if (next.link.empty ())
				return failure (-ENOENT);
			push_components (&todo, next.link);
			if (next.link[0] == '/')
				cur = raw_stat (cache, fs->root);
			continue;
		}
		cur = std::move (next);
	}
	return cur.err ? failure (cur.err) : cur;
}

entry
mount_stat (fusefs *fs, const std::string &full)
{
	entry ent;
	if (!cache_get (fs->cache.get (), full, &ent))
	{
		ent = walk (fs, full, fs->links == fusefs_links::follow);
		cache_put (fs->cache.get (), full, ent);
	}
	return ent;
}

/* Data and directory operations always act on what a link points to. */
entry
mount_target (fusefs *fs, const std::string &full)
{
	entry ent = mount_stat (fs, full);
	if (!ent.err && ent.st.is_symlink)
		ent = walk (fs, full, true);
	return ent;
}

rover_file *
open_file (fusefs *fs, const std::string &full, int *error)
{
	entry ent = mount_target (fs, full);
	*error = ent.err;
	if (*error)
		return nullptr;
	if (ent.st.is_dir)
	{
		*error = -EISDIR;
		return nullptr;
	}
	rover_file *file = rover_file_open (ent.phys.c_str ());
	if (!file)
		*error = -rover_last_errno ();
	return file;
}

void
fill_stat (const entry &in, fusefs_stat *out)
{
	if (in.st.is_symlink)
	{
		out->mode = MODE_LINK | 00777;
		out->size = in.link.size ();
	}
	else
	{
		out->mode = (in.st.is_dir ? MODE_DIR | MODE_EXEC : MODE_FILE) | MODE_READ;
		out->size = in.st.is_dir || in.st.size == ROVER_SIZE_UNKNOWN ? 0 : in.st.size;
	}
	out->inode = in.st.inode_set ? in.st.inode : 0;
	out->mtime = in.st.mtime_set ? in.st.mtime : 0;
}

/* Physical directories on the way to the mount path FULL, root first. */
std::vector<std::string>
ancestry (fusefs *fs, const std::string &full)
{
	std::vector<std::string> chain;
	size_t close = fs->root.size ();
	for (size_t slash = full.find ('/', close); slash != std::string::npos;
		slash = full.find ('/', slash + 1))
	{
		entry ent = mount_target (fs, full.substr (0, slash));
		if (!ent.err)
			chain.push_back (ent.phys);
	}
	entry ent = mount_target (fs, full);
	if (!ent.err)
		chain.push_back (ent.phys);
	return chain;
}

/* A directory link that leads back to a directory on the current path
   repeats forever under a recursive walker; keep it out of listings. */
bool
loops_back (const std::vector<std::string> &chain, const std::string &target)
{
	for (const std::string &dir : chain)
		if (dir == target || (dir.size () > target.size ()
			&& dir.compare (0, target.size (), target) == 0
			&& dir[target.size ()] == '/'))
			return true;
	return false;
}

struct dir_entry
{
	std::string name;
	entry ent;	/* physical entry of the child */
	bool shown;
	entry presented;	/* what the mount shows for the child */
};

} // namespace

void
fusefs_init (fusefs *fs, const std::string &device,
	const std::string &fs_name, unsigned long long size,
	unsigned int sector_size,
	std::function<bool (const std::function<void ()> &)> dispatch,
	size_t cache_max, fusefs_links links)
{
	fs->device = device;
	fs->root = "(" + device + ")";
	fs->fs_name = fs_name;
	fs->size = size;
	/* WinFsp caps sectors at 4096; Dokan wants a power of two.  */
	if (sector_size < 512 || sector_size > 4096 || (sector_size & (sector_size - 1)))
		sector_size = 512;
	fs->sector_size = sector_size;
	fs->links = links;
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
	std::string full = rover_path (fs, path);
	entry ent;

	if (!cache_get (fs->cache.get (), full, &ent)
		&& !fs->dispatch ([&] { ent = mount_stat (fs, full); }))
		return -EIO;
	if (ent.err)
		return ent.err;
	fill_stat (ent, st);
	return 0;
}

int
fusefs_readlink (fusefs *fs, const char *path, char *buf, size_t size)
{
	std::string full = rover_path (fs, path);
	entry ent;

	if (!size)
		return -EINVAL;
	if (!cache_get (fs->cache.get (), full, &ent)
		&& !fs->dispatch ([&] { ent = mount_stat (fs, full); }))
		return -EIO;
	if (ent.err)
		return ent.err;
	if (!ent.st.is_symlink)
		return -EINVAL;
	size_t length = std::min (ent.link.size (), size - 1);
	memcpy (buf, ent.link.data (), length);
	buf[length] = '\0';
	return 0;
}

int
fusefs_realpath (fusefs *fs, const char *path, std::string *out)
{
	std::string full = rover_path (fs, path);
	entry ent;

	if (!fs->dispatch ([&] { ent = walk (fs, full, true); }))
		return -EIO;
	if (ent.err)
		return ent.err;
	*out = ent.phys.size () > fs->root.size () ? ent.phys.substr (fs->root.size ()) : "/";
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
	if (!fs->dispatch ([&] { file = open_file (fs, full, &err); }))
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
			file = open_file (fs, full, &result);
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
		entry dir = mount_target (fs, full);
		err = dir.err;
		if (err)
			return;
		if (!dir.st.is_dir)
		{
			err = -ENOTDIR;
			return;
		}
		err = rover_dir_list (dir.phys.c_str (),
			[] (const rover_dirent *ent, void *opaque) -> int
			{
				auto *out = (std::vector<dir_entry> *) opaque;
				dir_entry item = {};
				item.name = ent->name;
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
		std::string prefix = dir.phys + "/";
		for (dir_entry &item : entries)
		{
			item.ent.phys = prefix + item.name;
			settle_link (&item.ent);
			rover_stat_t &ist = item.ent.st;
			if (item.ent.err || ist.is_dir || ist.is_symlink
				|| ist.size != ROVER_SIZE_UNKNOWN)
				continue;
			entry cached;
			if (cache_get (cache, raw_key (item.ent.phys), &cached) && !cached.err)
			{
				ist.size = cached.st.size;
				continue;
			}
			rover_file *file = rover_file_open (item.ent.phys.c_str ());
			if (file)
			{
				ist.size = rover_file_size (file);
				rover_file_close (file);
			}
		}

		/* Seed the per-entry lookups that follow a listing.  Reverse order
		   leaves the first of duplicate names, the one rover_stat() finds. */
		for (auto it = entries.rbegin (); it != entries.rend (); ++it)
			cache_put (cache, raw_key (it->ent.phys), it->ent);

		std::string mount_prefix = full;
		if (mount_prefix.back () != '/')
			mount_prefix += '/';
		std::vector<std::string> chain;
		for (auto it = entries.rbegin (); it != entries.rend (); ++it)
		{
			dir_entry &item = *it;
			std::string child = mount_prefix + item.name;
			item.presented = item.ent;
			if (!item.ent.err && item.ent.st.is_symlink
				&& fs->links == fusefs_links::follow)
				item.presented = walk (fs, child, true);
			cache_put (cache, child, item.presented);
			item.shown = !item.presented.err;
			if (item.shown && item.ent.st.is_symlink
				&& item.presented.st.is_dir && !item.presented.st.is_symlink)
			{
				if (chain.empty ())
					chain = ancestry (fs, full);
				item.shown = !loops_back (chain, item.presented.phys);
			}
		}
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
		if (!item.shown)
			continue;
		fusefs_stat st = {};
		fill_stat (item.presented, &st);
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
