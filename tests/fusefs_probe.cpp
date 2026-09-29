/* Shared mount core metadata cache regression. GPL-3.0-or-later. */
#include <errno.h>
#include <fcntl.h>
#include <rover.h>
#include "../common/fusefs.h"
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace
{

/* Small bound for the eviction check: every insert costs a real lookup. */
constexpr unsigned EVICT_MAX = 256;

void require (bool value, const std::string &message)
{
	if (!value)
		throw std::runtime_error (message);
}

void attach (const char *name, const std::filesystem::path &path)
{
#ifdef _WIN32
	const auto utf8 = path.u8string ();
	int error = rover_winfile_add (name, reinterpret_cast<const char *> (utf8.c_str ()), 0);
#else
	int error = rover_posixfile_add (name, path.c_str (), 0);
#endif
	require (!error, std::string ("attach failed: ") + name);
}

struct result
{
	int err = 0;
	fusefs_stat st = {};
	bool operator== (const result &o) const
	{
		return err == o.err && (err || (st.mode == o.st.mode
			&& st.inode == o.st.inode && st.size == o.st.size
			&& st.mtime == o.st.mtime));
	}
};

std::string describe (const std::string &path, const result &r)
{
	char text[160];
	snprintf (text, sizeof (text), "%s: err=%d mode=%o inode=%llu size=%llu mtime=%lld",
		path.c_str (), r.err, (unsigned) r.st.mode, (unsigned long long) r.st.inode,
		(unsigned long long) r.st.size, r.st.mtime);
	return text;
}

/* Uncached reference: the per-request walk the cache replaces. */
result oracle (const std::string &device, const std::string &path)
{
	std::string full = "(" + device + ")";
	if (!(path.empty () || path == "/"))
		full += path;
	result r;
	rover_stat_t st = {};
	size_t close = full.find (')');
	for (size_t slash = full.find ('/', close + 1); slash != std::string::npos;
		slash = full.find ('/', slash + 1))
	{
		if (slash == close + 1)
			continue;
		if (rover_stat (full.substr (0, slash).c_str (), &st))
			r.err = -rover_last_errno ();
		else if (st.is_symlink)
			r.err = -ENOTSUP;
		else if (!st.is_dir)
			r.err = -ENOTDIR;
		if (r.err)
			return r;
	}
	if (rover_stat (full.c_str (), &st))
		r.err = -rover_last_errno ();
	else if (st.is_symlink)
		r.err = -ENOTSUP;
	else
	{
		r.st.mode = st.is_dir ? 0040555 : 0100444;
		r.st.inode = st.inode_set ? st.inode : 0;
		r.st.size = st.is_dir || st.size == ROVER_SIZE_UNKNOWN ? 0 : st.size;
		r.st.mtime = st.mtime_set ? st.mtime : 0;
	}
	return r;
}

struct mount
{
	fusefs fs;
	std::mutex backend;	/* stands in for the single Rover thread */
	std::atomic<unsigned> dispatches { 0 };

	explicit mount (const std::string &device, size_t cache_max = FUSEFS_CACHE_MAX)
	{
		fusefs_init (&fs, device, "probe", ~0ULL, 0,
			[this] (const std::function<void ()> &fn)
			{
				std::lock_guard<std::mutex> hold (backend);
				dispatches++;
				fn ();
				return true;
			}, cache_max);
	}

	result getattr (const std::string &path)
	{
		result r;
		r.err = fusefs_getattr (&fs, path.c_str (), &r.st);
		return r;
	}
};

typedef std::vector<std::pair<std::string, fusefs_stat>> listing;

int collect (void *data, const char *name, const fusefs_stat *st)
{
	static_cast<listing *> (data)->emplace_back (name, *st);
	return 0;
}

int list (mount &m, const std::string &path, listing *out)
{
	out->clear ();
	return fusefs_readdir (&m.fs, path.c_str (), collect, out);
}

void check_same (mount &m, const std::string &path, const result &expect)
{
	result got = m.getattr (path);
	require (got == expect, "cache mismatch: " + describe (path, got)
		+ " expected " + describe (path, expect));
}

/* Raw driver listing: name and whether it is a symlink. */
std::vector<std::pair<std::string, bool>> oracle_names (const std::string &device,
	const std::string &dir)
{
	std::vector<std::pair<std::string, bool>> out;
	std::string full = "(" + device + ")" + dir;
	require (!rover_dir_list (full.c_str (),
		[] (const rover_dirent *ent, void *data) -> int
		{
			static_cast<std::vector<std::pair<std::string, bool>> *> (data)
				->emplace_back (ent->name, ent->is_symlink != 0);
			return 0;
		}, &out), "oracle listing failed: " + dir);
	return out;
}

std::string child_path (const std::string &dir, const std::string &name)
{
	return (dir == "/" ? "/" : dir + "/") + name;
}

/* Returns the listed children, symlinks included. */
std::vector<std::string> check_listing (mount &m, const std::string &device,
	const std::string &dir)
{
	listing entries;
	require (list (m, dir, &entries) == 0, "readdir failed: " + dir);
	require (entries.size () >= 2 && entries[0].first == "." && entries[1].first == "..",
		"readdir dot entries missing: " + dir);
	std::vector<std::string> children;
	size_t next = 2;
	for (const auto &raw : oracle_names (device, dir))
	{
		std::string path = child_path (dir, raw.first);
		children.push_back (path);
		if (raw.second)
			continue;
		require (next < entries.size () && entries[next].first == raw.first,
			"readdir names changed: " + path);
		result listed;
		listed.st = entries[next++].second;
		result want = oracle (device, path);
		require (listed == want, "readdir entry mismatch: " + describe (path, listed)
			+ " expected " + describe (path, want));
	}
	require (next == entries.size (), "readdir listed a symlink or extra entry: " + dir);
	return children;
}

void run_device (const std::string &device, const std::vector<std::string> &paths,
	const std::vector<std::string> &dirs)
{
	std::map<std::string, result> expect;
	for (const std::string &path : paths)
		expect[path] = oracle (device, path);

	/* Cold misses resolve once, then repeat without the backend. */
	{
		mount m (device);
		for (const std::string &path : paths)
			check_same (m, path, expect[path]);
		unsigned cold = m.dispatches;
		require (cold > 0, "cold lookups did not reach the backend");
		for (int round = 0; round < 3; round++)
			for (const std::string &path : paths)
				check_same (m, path, expect[path]);
		require (m.dispatches == cold, device + ": warm getattr dispatched");

		fusefs_invalidate (&m.fs);
		check_same (m, paths[1], expect[paths[1]]);
		require (m.dispatches == cold + 1, device + ": invalidate kept entries");
	}

	/* A listing seeds its children, symlinks included. */
	{
		mount m (device);
		std::vector<std::string> children;
		for (const std::string &dir : dirs)
			for (const std::string &path : check_listing (m, device, dir))
				children.push_back (path);
		unsigned seeded = m.dispatches;
		require (seeded == dirs.size (), device + ": one dispatch per listing");
		for (const std::string &path : children)
			check_same (m, path, oracle (device, path));
		require (m.dispatches == seeded, device + ": seeded entry dispatched");
		for (const std::string &dir : dirs)
			check_listing (m, device, dir);
		require (m.dispatches == seeded + dirs.size (), device + ": relisting dispatch count");
		/* Names absent from the listings (case variants, missing) resolve too. */
		for (const std::string &path : paths)
			check_same (m, path, expect[path]);
	}

	/* Uncached error paths through readdir and open. */
	{
		mount m (device);
		for (const auto &item : expect)
		{
			listing entries;
			int rc = list (m, item.first, &entries);
			int want = item.second.err ? item.second.err
				: (item.second.st.mode & 0040000) ? 0 : -ENOTDIR;
			require (rc == want, "readdir status: " + describe (item.first, item.second)
				+ " got " + std::to_string (rc));
			uint64_t handle = 0;
			rc = fusefs_open (&m.fs, item.first.c_str (), O_RDONLY, &handle);
			want = item.second.err ? item.second.err
				: (item.second.st.mode & 0040000) ? -EISDIR : 0;
			require (rc == want, "open status: " + describe (item.first, item.second)
				+ " got " + std::to_string (rc));
			if (!rc)
			{
				std::vector<char> data (static_cast<size_t> (item.second.st.size) + 16);
				int got = fusefs_read (&m.fs, item.first.c_str (), data.data (),
					data.size (), 0, &handle);
				require (got == (int) item.second.st.size, "short read: " + item.first);
				require (fusefs_release (&m.fs, &handle) == 0, "release failed");
			}
		}
	}

	/* Concurrent hits, misses, listings and invalidations. */
	{
		mount m (device);
		std::atomic<bool> failed { false };
		std::string failure;
		std::mutex failure_lock;
		std::vector<std::thread> workers;
		for (unsigned t = 0; t < 4; t++)
			workers.emplace_back ([&, t]
			{
				unsigned seed = 2166136261u ^ t;
				for (unsigned i = 0; i < 3000 && !failed; i++)
				{
					seed = seed * 1103515245u + 12345u;
					unsigned pick = (seed >> 8) % (unsigned) (paths.size () + dirs.size () + 1);
					try
					{
						if (pick < paths.size ())
							check_same (m, paths[pick], expect[paths[pick]]);
						else if (pick < paths.size () + dirs.size ())
						{
							listing entries;
							require (list (m, dirs[pick - paths.size ()], &entries) == 0,
								"concurrent readdir failed");
						}
						else if (t == 0)
							fusefs_invalidate (&m.fs);
					}
					catch (const std::exception &error)
					{
						std::lock_guard<std::mutex> hold (failure_lock);
						failure = error.what ();
						failed = true;
					}
				}
			});
		for (std::thread &worker : workers)
			worker.join ();
		require (!failed, "concurrent: " + failure);
	}
	printf ("PASS fusefs cache %s (%zu paths)\n", device.c_str (), paths.size ());
}

void run_eviction (const std::string &device)
{
	mount m (device, EVICT_MAX);
	unsigned total = EVICT_MAX + 64;
	for (unsigned i = 0; i < total; i++)
	{
		std::string path = "/absent-" + std::to_string (i);
		require (m.getattr (path).err == -ENOENT, "absent name resolved: " + path);
	}
	unsigned before = m.dispatches;
	require (m.getattr ("/absent-" + std::to_string (total - 1)).err == -ENOENT
		&& m.dispatches == before, "newest entry was evicted");
	require (m.getattr ("/absent-0").err == -ENOENT && m.dispatches == before + 1,
		"oldest entry was not evicted");
	/* The reinserted entry is the newest again; the next oldest is gone. */
	require (m.getattr ("/absent-0").err == -ENOENT && m.dispatches == before + 1,
		"reinserted entry missing");
	require (m.getattr ("/absent-64").err == -ENOENT && m.dispatches == before + 2,
		"eviction order changed");
	printf ("PASS fusefs cache LRU bound (%u entries)\n", total);
}

} // namespace

int product_fusefs_probe (const std::filesystem::path &fixtures)
{
	rover_init (ROVER_INIT_NO_HOSTDISK);
	int status = 0;
	try
	{
		attach ("ext", fixtures / "basic.ext2");
		attach ("fat", fixtures / "basic.img");
		run_device ("ext", {
			"/", "/hello.txt", "/empty.bin", "/nested", "/nested/data.bin",
			"/empty-dir", "/unicode-\xe6\xb5\x8b\xe8\xaf\x95.txt", "/link.txt",
			"/dirlink", "/dirlink/data.bin", "/missing", "/missing/child",
			"/hello.txt/child", "/nested/", "/nested//data.bin",
			"/nested/missing", "/link.txt/child" }, { "/", "/nested", "/empty-dir" });
		run_device ("fat", {
			"/", "/hello.txt", "/HELLO.TXT", "/empty.bin", "/dir", "/dir/child.txt",
			"/DIR/CHILD.TXT", "/missing", "/dir/missing", "/hello.txt/child" },
			{ "/", "/dir" });
		run_eviction ("ext");
	}
	catch (const std::exception &error)
	{
		fprintf (stderr, "FAIL: %s\n", error.what ());
		status = 1;
	}
	rover_fini ();
	return status;
}
