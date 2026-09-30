/* Shared mount core metadata cache and link semantics regression.
   GPL-3.0-or-later. */
#include <errno.h>
#include <fcntl.h>
#include <rover.h>
#include "../common/fusefs.h"
#include <atomic>
#include <cstdio>
#include <cstring>
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

const char *mode_name (fusefs_links links)
{
	return links == fusefs_links::native ? "native" : "follow";
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
	char text[200];
	snprintf (text, sizeof (text), "%s: err=%d mode=%o inode=%llu size=%llu mtime=%lld",
		path.c_str (), r.err, (unsigned) r.st.mode, (unsigned long long) r.st.inode,
		(unsigned long long) r.st.size, r.st.mtime);
	return text;
}

/* Uncached reference walk: plain POSIX resolution over rover_stat() on
   link-free paths and rover_readlink(). */
struct resolved
{
	result r;
	std::string phys;
	bool link = false;	/* the result is a link itself */
	bool linked = false;	/* the final component was a link */
};

std::string raw_target (const std::string &phys)
{
	char buffer[4096];
	unsigned long long length = 0;
	require (!rover_readlink (phys.c_str (), buffer, sizeof (buffer), &length)
		&& length < sizeof (buffer), "oracle readlink failed: " + phys);
	return buffer;
}

resolved oracle_walk (const std::string &device, const std::string &path, bool follow)
{
	const std::string root = "(" + device + ")";
	std::vector<std::string> todo;
	auto push = [&todo] (const std::string &text)
	{
		std::vector<std::string> parts;
		size_t start = 0;
		while (start <= text.size ())
		{
			size_t end = text.find ('/', start);
			if (end == std::string::npos)
				end = text.size ();
			if (end > start)
				parts.push_back (text.substr (start, end - start));
			start = end + 1;
		}
		todo.insert (todo.end (), parts.rbegin (), parts.rend ());
	};
	push (path);
	resolved out;
	out.phys = root;
	rover_stat_t st = {};
	st.is_dir = 1;
	unsigned links = 0;
	while (!todo.empty ())
	{
		std::string name = todo.back ();
		todo.pop_back ();
		out.linked = false;
		if (!st.is_dir)
		{
			out.r.err = -ENOTDIR;
			return out;
		}
		if (name == ".")
			continue;
		if (name == "..")
		{
			if (out.phys != root)
			{
				out.phys.erase (out.phys.rfind ('/'));
				require (!rover_stat (out.phys.c_str (), &st), "oracle parent");
			}
			continue;
		}
		std::string next = out.phys + "/" + name;
		if (rover_stat (next.c_str (), &st))
		{
			out.r.err = -rover_last_errno ();
			return out;
		}
		if (st.is_symlink && (follow || !todo.empty ()))
		{
			std::string target = raw_target (next);
			if (++links > 40)
			{
				out.r.err = -ELOOP;
				return out;
			}
			if (target.empty ())
			{
				out.r.err = -ENOENT;
				return out;
			}
			push (target);
			if (target[0] == '/')
				out.phys = root;
			rover_stat (out.phys.c_str (), &st);
			if (out.phys == root)
				st.is_dir = 1;
			out.linked = true;
			continue;
		}
		out.phys = next;
		out.linked = false;
	}
	if (out.phys == root)
	{
		st = {};
		st.is_dir = 1;
		rover_stat (root.c_str (), &st);
	}
	else
		require (!rover_stat (out.phys.c_str (), &st), "oracle final stat");
	if (st.is_symlink)
	{
		out.link = true;
		out.r.st.mode = 0120777;
		out.r.st.size = raw_target (out.phys).size ();
	}
	else
	{
		out.r.st.mode = st.is_dir ? 0040555 : 0100444;
		out.r.st.size = st.is_dir || st.size == ROVER_SIZE_UNKNOWN ? 0 : st.size;
	}
	out.r.st.inode = st.inode_set ? st.inode : 0;
	out.r.st.mtime = st.mtime_set ? st.mtime : 0;
	return out;
}

resolved oracle (const std::string &device, const std::string &path, fusefs_links links)
{
	return oracle_walk (device, path, links == fusefs_links::follow);
}

struct mount
{
	fusefs fs;
	std::mutex backend;	/* stands in for the single Rover thread */
	std::atomic<unsigned> dispatches { 0 };

	mount (const std::string &device, fusefs_links links,
		size_t cache_max = FUSEFS_CACHE_MAX)
	{
		fusefs_init (&fs, device, "probe", ~0ULL, 0,
			[this] (const std::function<void ()> &fn)
			{
				std::lock_guard<std::mutex> hold (backend);
				dispatches++;
				fn ();
				return true;
			}, cache_max, links);
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
	require (got == expect, std::string (mode_name (m.fs.links)) + " cache mismatch: "
		+ describe (path, got) + " expected " + describe (path, expect));
}

/* Raw driver listing: name and whether it is a symlink. */
std::vector<std::pair<std::string, bool>> oracle_names (const std::string &phys)
{
	std::vector<std::pair<std::string, bool>> out;
	require (!rover_dir_list (phys.c_str (),
		[] (const rover_dirent *ent, void *data) -> int
		{
			static_cast<std::vector<std::pair<std::string, bool>> *> (data)
				->emplace_back (ent->name, ent->is_symlink != 0);
			return 0;
		}, &out), "oracle listing failed: " + phys);
	return out;
}

std::string child_path (const std::string &dir, const std::string &name)
{
	return (dir == "/" ? "/" : dir + "/") + name;
}

/* A directory link back onto the current path is left out of follow-mode
   listings: its target is an ancestor of, or equal to, a directory on the
   way to DIR. */
bool cyclic (const std::string &device, const std::string &dir, const std::string &target)
{
	std::vector<std::string> chain = { "(" + device + ")" };
	for (size_t slash = dir.find ('/', 1); ; slash = dir.find ('/', slash + 1))
	{
		resolved step = oracle_walk (device, dir.substr (0, slash), true);
		if (!step.r.err)
			chain.push_back (step.phys);
		if (slash == std::string::npos)
			break;
	}
	for (const std::string &p : chain)
		if (p == target || (p.size () > target.size ()
			&& p.compare (0, target.size (), target) == 0 && p[target.size ()] == '/'))
			return true;
	return false;
}

/* Returns every child name of DIR, shown or not. */
std::vector<std::string> check_listing (mount &m, const std::string &device,
	const std::string &dir)
{
	listing entries;
	require (list (m, dir, &entries) == 0, "readdir failed: " + dir);
	require (entries.size () >= 2 && entries[0].first == "." && entries[1].first == "..",
		"readdir dot entries missing: " + dir);
	resolved where = oracle_walk (device, dir, true);
	require (!where.r.err, "oracle cannot resolve listed directory: " + dir);
	std::vector<std::string> children;
	size_t next = 2;
	for (const auto &raw : oracle_names (where.phys))
	{
		std::string path = child_path (dir, raw.first);
		children.push_back (path);
		resolved want = oracle (device, path, m.fs.links);
		bool shown = !want.r.err;
		if (shown && raw.second && m.fs.links == fusefs_links::follow
			&& (want.r.st.mode & 0170000) == 0040000)
			shown = !cyclic (device, dir, want.phys);
		if (!shown)
			continue;
		require (next < entries.size () && entries[next].first == raw.first,
			std::string (mode_name (m.fs.links)) + " readdir names changed: " + path);
		result listed;
		listed.st = entries[next++].second;
		require (listed == want.r, std::string (mode_name (m.fs.links))
			+ " readdir entry mismatch: " + describe (path, listed)
			+ " expected " + describe (path, want.r));
	}
	require (next == entries.size (), std::string (mode_name (m.fs.links))
		+ " readdir listed an extra entry: " + dir);
	return children;
}

void check_readlink (mount &m, const std::string &device, const std::string &path,
	const resolved &want)
{
	char buffer[4096];
	int rc = fusefs_readlink (&m.fs, path.c_str (), buffer, sizeof (buffer));
	if (want.r.err)
		require (rc == want.r.err, "readlink status: " + describe (path, want.r)
			+ " got " + std::to_string (rc));
	else if (!want.link)
		require (rc == -EINVAL, "readlink of a non-link: " + path
			+ " got " + std::to_string (rc));
	else
	{
		std::string target = raw_target (want.phys);
		require (rc == 0 && target == buffer, "readlink target: " + path);
		char small[4];
		require (fusefs_readlink (&m.fs, path.c_str (), small, sizeof (small)) == 0
			&& std::string (small) == target.substr (0, 3), "readlink truncation: " + path);
	}
	(void) device;
}

void run_device (const std::string &device, fusefs_links links,
	const std::vector<std::string> &paths, const std::vector<std::string> &dirs)
{
	std::map<std::string, resolved> expect, target;
	for (const std::string &path : paths)
	{
		expect[path] = oracle (device, path, links);
		target[path] = oracle_walk (device, path, true);
	}

	/* Cold misses resolve once, then repeat without the backend. */
	{
		mount m (device, links);
		for (const std::string &path : paths)
			check_same (m, path, expect[path].r);
		unsigned cold = m.dispatches;
		require (cold > 0, "cold lookups did not reach the backend");
		for (int round = 0; round < 3; round++)
			for (const std::string &path : paths)
				check_same (m, path, expect[path].r);
		require (m.dispatches == cold, device + ": warm getattr dispatched");
		for (const std::string &path : paths)
			check_readlink (m, device, path, expect[path]);
		require (m.dispatches == cold, device + ": warm readlink dispatched");

		fusefs_invalidate (&m.fs);
		check_same (m, paths[1], expect[paths[1]].r);
		require (m.dispatches == cold + 1, device + ": invalidate kept entries");
	}

	/* A listing seeds its children, links and hidden entries included. */
	{
		mount m (device, links);
		std::vector<std::string> children;
		for (const std::string &dir : dirs)
			for (const std::string &path : check_listing (m, device, dir))
				children.push_back (path);
		unsigned seeded = m.dispatches;
		require (seeded == dirs.size (), device + ": one dispatch per listing");
		for (const std::string &path : children)
			check_same (m, path, oracle (device, path, links).r);
		require (m.dispatches == seeded, device + ": seeded entry dispatched");
		for (const std::string &dir : dirs)
			check_listing (m, device, dir);
		require (m.dispatches == seeded + dirs.size (), device + ": relisting dispatch count");
		/* Names absent from the listings (case variants, missing) resolve too. */
		for (const std::string &path : paths)
			check_same (m, path, expect[path].r);
	}

	/* Uncached error paths through readdir and open, which act on what a
	   link points to in both modes. */
	{
		mount m (device, links);
		for (const auto &item : target)
		{
			const result &want_target = item.second.r;
			bool is_dir = (want_target.st.mode & 0170000) == 0040000;
			listing entries;
			int rc = list (m, item.first, &entries);
			int want = want_target.err ? want_target.err : is_dir ? 0 : -ENOTDIR;
			require (rc == want, "readdir status: " + describe (item.first, want_target)
				+ " got " + std::to_string (rc));
			uint64_t handle = 0;
			rc = fusefs_open (&m.fs, item.first.c_str (), O_RDONLY, &handle);
			want = want_target.err ? want_target.err : is_dir ? -EISDIR : 0;
			require (rc == want, "open status: " + describe (item.first, want_target)
				+ " got " + std::to_string (rc));
			if (!rc)
			{
				std::vector<char> data (static_cast<size_t> (want_target.st.size) + 16);
				int got = fusefs_read (&m.fs, item.first.c_str (), data.data (),
					data.size (), 0, &handle);
				require (got == (int) want_target.st.size, "short read: " + item.first);
				require (fusefs_release (&m.fs, &handle) == 0, "release failed");
			}
		}
	}

	/* Concurrent hits, misses, listings and invalidations. */
	{
		mount m (device, links);
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
							check_same (m, paths[pick], expect[paths[pick]].r);
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
	printf ("PASS fusefs %s %s (%zu paths)\n", device.c_str (), mode_name (links),
		paths.size ());
}

void run_eviction (const std::string &device)
{
	mount m (device, fusefs_links::native, EVICT_MAX);
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

/* Spot checks of the presentation itself, independent of the oracle. */
void run_links_spot ()
{
	mount native ("lnk", fusefs_links::native);
	mount follow ("lnk", fusefs_links::follow);
	result r = native.getattr ("/dirlink");
	require (!r.err && r.st.mode == 0120777 && r.st.size == 6, "native directory link");
	r = follow.getattr ("/dirlink");
	require (!r.err && (r.st.mode & 0170000) == 0040000, "followed directory link");
	r = follow.getattr ("/abs");
	require (!r.err && (r.st.mode & 0170000) == 0100000, "followed absolute link");
	require (follow.getattr ("/dangling").err == -ENOENT, "dangling link");
	require (follow.getattr ("/loop").err == -ELOOP, "self loop");
	require (native.getattr ("/chain/sib/.").err == -ENOTDIR, "file link as directory");
	r = native.getattr ("/chain/.");
	require (!r.err && (r.st.mode & 0170000) == 0040000, "slash-dot through links");

	char buffer[64];
	require (fusefs_readlink (&native.fs, "/", buffer, sizeof (buffer)) == -EINVAL,
		"readlink of the root");
	require (fusefs_readlink (&native.fs, "/nested/up", buffer, sizeof (buffer)) == 0
		&& !strcmp (buffer, ".."), "readlink through a directory");
	require (fusefs_readlink (&follow.fs, "/link.txt", buffer, sizeof (buffer)) == -EINVAL,
		"follow mode has no links");

	/* The link back to the root is reachable but not listed. */
	r = follow.getattr ("/nested/up");
	require (!r.err && (r.st.mode & 0170000) == 0040000, "cyclic link resolves");
	listing entries;
	require (list (follow, "/dirlink", &entries) == 0, "list through link");
	bool up = false, sib = false;
	for (const auto &e : entries)
	{
		up |= e.first == "up";
		sib |= e.first == "sib";
	}
	require (!up && sib, "cyclic directory link listed");
	require (list (native, "/nested", &entries) == 0, "native list");
	up = false;
	for (const auto &e : entries)
		up |= e.first == "up" && e.second.mode == 0120777;
	require (up, "native listing lost the link");
	printf ("PASS fusefs link presentation\n");
}

} // namespace

int product_fusefs_probe (const std::filesystem::path &fixtures)
{
	rover_init (ROVER_INIT_NO_HOSTDISK);
	int status = 0;
	try
	{
		attach ("ext", fixtures / "basic.ext2");
		attach ("lnk", fixtures / "links.ext2");
		attach ("fat", fixtures / "basic.img");
		for (fusefs_links links : { fusefs_links::native, fusefs_links::follow })
		{
			run_device ("ext", links, {
				"/", "/hello.txt", "/empty.bin", "/nested", "/nested/data.bin",
				"/empty-dir", "/unicode-\xe6\xb5\x8b\xe8\xaf\x95.txt", "/link.txt",
				"/dirlink", "/dirlink/data.bin", "/missing", "/missing/child",
				"/hello.txt/child", "/nested/", "/nested//data.bin",
				"/nested/missing", "/link.txt/child", "/.", "/dirlink/." },
				{ "/", "/nested", "/empty-dir", "/dirlink" });
			run_device ("lnk", links, {
				"/", "/hello.txt", "/link.txt", "/dirlink", "/chain", "/abs",
				"/dangling", "/loop", "/loop/x", "/nested/up", "/nested/sib",
				"/chain/up/chain/sib", "/dirlink/../link.txt", "/nested/up/abs",
				"/dangling/x", "/chain/data.bin", "/abs/x", "/." },
				{ "/", "/nested", "/dirlink", "/chain", "/nested/up" });
			run_device ("fat", links, {
				"/", "/hello.txt", "/HELLO.TXT", "/empty.bin", "/dir", "/dir/child.txt",
				"/DIR/CHILD.TXT", "/missing", "/dir/missing", "/hello.txt/child" },
				{ "/", "/dir" });
		}
		run_links_spot ();
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
