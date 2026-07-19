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
 * grub backend thread: a task queue drained by the only thread that
 * may touch grub.  See backend.h for the message protocol.
 */

#include "backend.h"

#include <bcrypt.h>
#include <process.h>
#include <string.h>
#include <wchar.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>

#include <rover.h>

#include <filetype.h>

#include "strconv.h"

#pragma comment (lib, "bcrypt.lib")

namespace
{

struct queued_task
{
	backend_task task;
	UINT seq;
};

struct sync_request
{
	const std::function<void ()> *fn;
	HANDLE done;
};

HWND g_notify;
HANDLE g_thread;
std::mutex g_lock;
std::condition_variable g_wake;
std::deque<queued_task> g_queue;	/* guarded by g_lock */
std::deque<sync_request> g_requests;	/* guarded by g_lock */
bool g_stop;	/* guarded by g_lock */
UINT g_seq;	/* guarded by g_lock */
std::atomic<bool> g_cancel;
UINT g_loop_seq;	/* backend thread only: next "loopN" suffix */

/* Backend thread: run every pending backend_call().  Called between
   tasks and at chunk boundaries inside long ones, so dokan requests
   are not starved by a long extract or listing.  */
void
service_requests (void)
{
	for (;;)
	{
		sync_request req;
		{
			std::lock_guard<std::mutex> hold (g_lock);
			if (g_requests.empty ())
				return;
			req = g_requests.front ();
			g_requests.pop_front ();
		}
		(*req.fn) ();
		SetEvent (req.done);
	}
}

/* Task handlers */

void
set_error (backend_result *res, const char *fallback)
{
	const char *msg = rover_last_error ();

	res->error = msg ? msg : fallback;
}

std::string
join_path (const std::string &dir, const std::string &name)
{
	std::string p = dir;

	if (p.empty () || p.back () != '/')
		p += '/';
	return p + name;
}

static_assert (BACKEND_DEV_OTHER == ROVER_DEV_OTHER
	       && BACKEND_DEV_WINDISK == ROVER_DEV_WINDISK
	       && BACKEND_DEV_LOOPBACK == ROVER_DEV_LOOPBACK
	       && BACKEND_DEV_DISKFILTER == ROVER_DEV_DISKFILTER
	       && BACKEND_DEV_CRYPTODISK == ROVER_DEV_CRYPTODISK
	       && BACKEND_DEV_PROCFS == ROVER_DEV_PROCFS,
	       "BACKEND_DEV_* must match ROVER_DEV_*");

int
enum_disk_hook (const struct rover_disk_info *info, void *data)
{
	auto *disks = static_cast<std::vector<backend_diskent> *> (data);
	backend_diskent d;

	d.name = info->name;
	d.is_partition = info->is_partition != 0;
	d.dev_id = info->dev_id;
	d.size = info->size;
	d.fs = info->fs ? info->fs : "";
	d.label = info->label ? info->label : "";
	d.encrypted = info->encrypted != 0;
	d.crypto_type = info->crypto_type ? info->crypto_type : "";
	d.crypto_uuid = info->crypto_uuid ? info->crypto_uuid : "";
	disks->push_back (std::move (d));
	return 0;
}

int
support_hook (const char *name, void *data)
{
	static_cast<std::vector<std::string> *> (data)->push_back (name);
	return 0;
}

int
list_dir_hook (const struct rover_dirent *ent, void *data)
{
	auto *entries = static_cast<std::vector<backend_dirent> *> (data);
	backend_dirent e;

	e.name = ent->name;
	e.is_dir = ent->is_dir != 0;
	e.is_symlink = ent->is_symlink != 0;
	e.size = 0;
	e.mtime = ent->mtime_set ? ent->mtime : 0;
	entries->push_back (std::move (e));
	return 0;
}

void
run_list_dir (const std::string &path, backend_result *res)
{
	res->path = path;
	if (rover_dir_list (path.c_str (), list_dir_hook, &res->entries))
	{
		set_error (res, "cannot list directory");
		res->entries.clear ();
		return;
	}

	std::sort (res->entries.begin (), res->entries.end (),
		[] (const backend_dirent &a, const backend_dirent &b)
		{
			if (a.is_dir != b.is_dir)
				return a.is_dir;
			return _stricmp (a.name.c_str (), b.name.c_str ()) < 0;
		});

	/* File sizes: grub dir hooks do not report them, so open each
	   file once the iteration is over (never from inside the dir
	   callback -- that would re-enter the filesystem driver).  */
	std::string prefix = path;
	if (prefix.empty () || prefix.back () != '/')
		prefix += '/';
	for (auto &e : res->entries)
	{
		/* Directories have no size;
		   a symlink's own size is meaningless.  */
		if (e.is_dir || e.is_symlink)
			continue;
		if (g_cancel.load (std::memory_order_relaxed))
			break;
		service_requests ();
		rover_file *f = rover_file_open ((prefix + e.name).c_str ());
		if (f)
		{
			e.size = rover_file_size (f);
			rover_file_close (f);
		}
		else
			e.size = BACKEND_SIZE_UNKNOWN;
	}
}

/*
 * Extraction.  Phase 1 resolves every source into a flat work list
 * (directories are walked by collecting each level first and only
 * then recursing -- never from inside the dir callback, which would
 * re-enter the filesystem driver).  Phase 2 creates directories and
 * copies files in list order, so parents always precede children.
 */

struct walk_item
{
	std::string src;	/* grub path */
	std::wstring rel;	/* Win32 path relative to the destination */
	bool is_dir;
};

struct extract_ctx
{
	UINT seq;
	UINT64 files_total = 0;
	UINT64 files_done = 0;
	UINT64 bytes_done = 0;
	ULONGLONG last_tick = 0;
	std::string cur;	/* source path of the file being copied */
};

void
post_progress (extract_ctx &ctx, int percent)
{
	backend_progress *p = new backend_progress;

	p->seq = ctx.seq;
	p->percent = percent;
	p->file_index = ctx.files_done;
	p->file_total = ctx.files_total;
	p->name = ctx.cur;
	if (!PostMessageW (g_notify, WM_APP_TASK_PROGRESS, ctx.seq, (LPARAM) p))
		delete p;
}

void
extract_progress_hook (unsigned long long done, unsigned long long total, void *data)
{
	extract_ctx *ctx = static_cast<extract_ctx *> (data);
	ULONGLONG now = GetTickCount64 ();

	if (now - ctx->last_tick < 100)
		return;
	ctx->last_tick = now;
	post_progress (*ctx, total ? (int) (done * 100 / total) : 0);
}

std::wstring
sanitize_component (const std::string &name)
{
	std::wstring out = widen (name);

	for (wchar_t &c : out)
		if (c < 32 || wcschr (L"<>:\"/\\|?*", c))
			c = L'_';
	return out;
}

/* Destination name for a top-level source: last path component, or
   the device name for a device root ("(hd0,gpt2)/" -> "hd0,gpt2").  */
std::wstring
top_rel_name (const std::string &src)
{
	std::string s = src;

	while (!s.empty () && s.back () == '/')
		s.pop_back ();
	size_t close = s.find (')');
	std::string base;
	if (close == std::string::npos)
		base = s;
	else if (close + 1 >= s.size ())
		base = s.substr (1, close - 1);
	else
		base = s.substr (s.find_last_of ('/') + 1);
	return sanitize_component (base);
}

/* Returns false on error (error set) or cancellation (error empty).  */
bool
walk_dir (const std::string &src, const std::wstring &rel, std::vector<walk_item> &out, std::string &error)
{
	std::vector<backend_dirent> children;

	if (rover_dir_list (src.c_str (), list_dir_hook, &children))
	{
		const char *msg = rover_last_error ();
		error = src + ": " + (msg ? msg : "cannot list directory");
		return false;
	}
	for (const backend_dirent &e : children)
	{
		if (g_cancel.load (std::memory_order_relaxed))
			return false;
		walk_item item;
		item.src = join_path (src, e.name);
		item.rel = rel + L'\\' + sanitize_component (e.name);
		item.is_dir = e.is_dir;
		out.push_back (item);
		if (e.is_dir && !walk_dir (item.src, item.rel, out, error))
			return false;
	}
	return true;
}

/* Returns false on error (error set) or cancellation (error empty);
   the partial destination file is deleted either way.  */
bool
extract_file (const std::string &src, const std::wstring &dst, extract_ctx &ctx, std::vector<char> &buf, std::string &error)
{
	rover_file *f;
	HANDLE h;
	bool ok = false;

	f = rover_file_open (src.c_str ());
	if (!f)
	{
		const char *msg = rover_last_error ();
		error = src + ": " + (msg ? msg : "cannot open");
		return false;
	}
	h = CreateFileW (dst.c_str (), GENERIC_WRITE, 0, nullptr,
			 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE)
	{
		rover_file_close (f);
		error = src + ": cannot create destination file";
		return false;
	}

	for (;;)
	{
		if (g_cancel.load (std::memory_order_relaxed))
			break;
		service_requests ();
		long long r = rover_file_read (f, buf.data (), buf.size ());
		if (r < 0)
		{
			const char *msg = rover_last_error ();
			error = src + ": " + (msg ? msg : "read error");
			break;
		}
		if (r == 0)
		{
			ok = true;
			break;
		}
		DWORD w = 0;
		if (!WriteFile (h, buf.data (), (DWORD) r, &w, nullptr)
		    || w != (DWORD) r)
		{
			error = src + ": write failed";
			break;
		}
		ctx.bytes_done += (UINT64) r;
	}

	CloseHandle (h);
	rover_file_close (f);
	if (!ok)
		DeleteFileW (dst.c_str ());
	return ok;
}

void
run_extract (const backend_task &task, UINT seq, backend_result *res)
{
	extract_ctx ctx;
	std::vector<walk_item> work;
	std::vector<char> buf ((size_t) 1 << 20);
	std::wstring root;

	ctx.seq = seq;
	if (task.paths.empty () || task.dest.empty ())
	{
		res->error = "nothing to extract";
		return;
	}

	root = task.dest;
	while (!root.empty () && root.back () == L'\\')
		root.pop_back ();
	/* Long-path prefix so deep trees do not hit MAX_PATH.  */
	if (root.rfind (L"\\\\", 0) != 0)
		root = L"\\\\?\\" + root;

	for (const std::string &src : task.paths)
	{
		rover_stat_t st;
		if (rover_stat (src.c_str (), &st))
		{
			set_error (res, "cannot stat source");
			return;
		}
		walk_item item;
		item.src = src;
		item.rel = top_rel_name (src);
		item.is_dir = st.is_dir != 0;
		work.push_back (item);
		if (item.is_dir && !walk_dir (item.src, item.rel, work, res->error))
			goto fail;
	}
	for (const walk_item &item : work)
		if (!item.is_dir)
			ctx.files_total++;

	rover_set_progress (extract_progress_hook, &ctx);
	for (const walk_item &item : work)
	{
		if (g_cancel.load (std::memory_order_relaxed))
			break;
		std::wstring dst = root + L'\\' + item.rel;
		if (item.is_dir)
		{
			if (!CreateDirectoryW (dst.c_str (), nullptr)
			    && GetLastError () != ERROR_ALREADY_EXISTS)
			{
				res->error = "cannot create directory";
				break;
			}
			continue;
		}
		ctx.files_done++;
		ctx.cur = item.src;
		ctx.last_tick = GetTickCount64 ();
		post_progress (ctx, 0);
		if (!extract_file (item.src, dst, ctx, buf, res->error))
			break;
	}
	rover_set_progress (nullptr, nullptr);

	res->stat_files = ctx.files_done;
	res->stat_bytes = ctx.bytes_done;
	if (res->error.empty () && g_cancel.load (std::memory_order_relaxed))
		res->error = "extraction cancelled";
	return;

fail:
	if (res->error.empty ())
		res->error = "extraction cancelled";
}

/*
 * File properties (dialog): libmagic description and hashes.  Both
 * read through rover, so they live on this thread like everything
 * else; hashing itself (CNG + CRC tables) has no grub dependency.
 */

/* libmagic looks at a prefix of the file; 1 MiB is the classic file(1)
   sniff size and keeps the dialog snappy on slow filesystems.  */
constexpr size_t SNIFF_MAX = 1 << 20;

void
run_file_props (const std::string &path, backend_result *res)
{
	rover_file *f = rover_file_open (path.c_str ());

	if (!f)
	{
		set_error (res, "cannot open file");
		return;
	}
	UINT64 size = rover_file_size (f);
	size_t want = size < SNIFF_MAX ? (size_t) size : SNIFF_MAX;
	std::vector<char> buf (want ? want : 1);
	size_t got = 0;
	while (got < want)
	{
		long long r = rover_file_read (f, buf.data () + got,
					       want - got);
		if (r < 0)
		{
			set_error (res, "read error");
			rover_file_close (f);
			return;
		}
		if (r == 0)
			break;
		got += (size_t) r;
	}
	rover_file_close (f);

	const char *desc = filetype_describe (buf.data (), got);
	if (!desc)
	{
		res->error = "cannot identify file type";
		return;
	}
	res->text = desc;
}

/* One CNG hash (MD5/SHA1/SHA256/SHA512).  NTSTATUS < 0 = failure.  */
struct cng_hash
{
	BCRYPT_ALG_HANDLE alg = nullptr;
	BCRYPT_HASH_HANDLE hash = nullptr;
	std::vector<UCHAR> object;
	DWORD digest_len = 0;

	~cng_hash ()
	{
		if (hash)
			BCryptDestroyHash (hash);
		if (alg)
			BCryptCloseAlgorithmProvider (alg, 0);
	}
};

bool
cng_open (cng_hash &h, const wchar_t *alg_id)
{
	DWORD object_len = 0;
	DWORD got = 0;

	if (BCryptOpenAlgorithmProvider (&h.alg, alg_id, nullptr, 0) < 0)
		return false;
	if (BCryptGetProperty (h.alg, BCRYPT_OBJECT_LENGTH,
			(PUCHAR) &object_len, sizeof (object_len), &got, 0) < 0)
		return false;
	if (BCryptGetProperty (h.alg, BCRYPT_HASH_LENGTH,
			(PUCHAR) &h.digest_len, sizeof (h.digest_len), &got, 0) < 0)
		return false;
	h.object.resize (object_len);
	if (BCryptCreateHash (h.alg, &h.hash, h.object.data (), object_len, nullptr, 0, 0) < 0)
		return false;
	return true;
}

std::string
hex_bytes (const UCHAR *data, DWORD len)
{
	static const char digits[] = "0123456789abcdef";
	std::string out;

	out.reserve ((size_t) len * 2);
	for (DWORD i = 0; i < len; i++)
	{
		out += digits[data[i] >> 4];
		out += digits[data[i] & 0x0f];
	}
	return out;
}

/* Reflected CRC-32 (zip) and CRC-64/XZ (ECMA-182).  */

void
crc32_fill (DWORD table[256])
{
	for (DWORD i = 0; i < 256; i++)
	{
		DWORD crc = i;
		for (int bit = 0; bit < 8; bit++)
			crc = (crc & 1) ? ((crc >> 1) ^ 0xedb88320UL)
					: (crc >> 1);
		table[i] = crc;
	}
}

void
crc64_fill (UINT64 table[256])
{
	for (DWORD i = 0; i < 256; i++)
	{
		UINT64 crc = i;
		for (int bit = 0; bit < 8; bit++)
			crc = (crc & 1) ? ((crc >> 1) ^ 0xc96c5795d7870f42ULL)
					: (crc >> 1);
		table[i] = crc;
	}
}

void
post_hash_progress (UINT seq, const std::string &path, int percent)
{
	backend_progress *p = new backend_progress;

	p->seq = seq;
	p->percent = percent;
	p->file_index = 1;
	p->file_total = 1;
	p->name = path;
	if (!PostMessageW (g_notify, WM_APP_TASK_PROGRESS, seq, (LPARAM) p))
		delete p;
}

void
run_hash_file (const backend_task &task, UINT seq, backend_result *res)
{
	/* Indexed by BACKEND_HASH_* bit number; CRCs have no CNG id.  */
	static const wchar_t *alg_ids[BACKEND_HASH_COUNT] =
	{
		BCRYPT_MD5_ALGORITHM, BCRYPT_SHA1_ALGORITHM, nullptr,
		nullptr, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA512_ALGORITHM,
	};
	cng_hash cng[BACKEND_HASH_COUNT];
	DWORD crc32_table[256];
	UINT64 crc64_table[256];
	DWORD crc32 = 0xffffffffUL;
	UINT64 crc64 = ~0ULL;
	UINT mask = task.hash_mask;

	if (!mask)
	{
		res->error = "no hash algorithm selected";
		return;
	}
	for (int i = 0; i < BACKEND_HASH_COUNT; i++)
		if ((mask & (1u << i)) && alg_ids[i] && !cng_open (cng[i], alg_ids[i]))
		{
			res->error = "hash provider error";
			return;
		}
	if (mask & BACKEND_HASH_CRC32)
		crc32_fill (crc32_table);
	if (mask & BACKEND_HASH_CRC64)
		crc64_fill (crc64_table);

	rover_file *f = rover_file_open (task.path.c_str ());
	if (!f)
	{
		set_error (res, "cannot open file");
		return;
	}
	UINT64 total = rover_file_size (f);
	UINT64 done = 0;
	std::vector<char> buf ((size_t) 1 << 20);
	ULONGLONG last_tick = GetTickCount64 ();
	for (;;)
	{
		if (g_cancel.load (std::memory_order_relaxed))
		{
			rover_file_close (f);
			res->error = "hash cancelled";
			return;
		}
		service_requests ();
		long long r = rover_file_read (f, buf.data (), buf.size ());
		if (r < 0)
		{
			set_error (res, "read error");
			rover_file_close (f);
			return;
		}
		if (r == 0)
			break;
		for (int i = 0; i < BACKEND_HASH_COUNT; i++)
			if ((mask & (1u << i)) && alg_ids[i]
				&& BCryptHashData (cng[i].hash, (PUCHAR) buf.data (), (ULONG) r, 0) < 0)
			{
				rover_file_close (f);
				res->error = "hash provider error";
				return;
			}
		if (mask & BACKEND_HASH_CRC32)
			for (long long i = 0; i < r; i++)
				crc32 = crc32_table[(crc32 ^ (UCHAR) buf[(size_t) i]) & 0xff] ^ (crc32 >> 8);
		if (mask & BACKEND_HASH_CRC64)
			for (long long i = 0; i < r; i++)
				crc64 = crc64_table[(crc64 ^ (UCHAR) buf[(size_t) i]) & 0xff] ^ (crc64 >> 8);

		done += (UINT64) r;
		ULONGLONG now = GetTickCount64 ();
		if (now - last_tick >= 100)
		{
			last_tick = now;
			post_hash_progress (seq, task.path, total ? (int) (done * 100 / total) : 0);
		}
	}
	rover_file_close (f);

	for (int i = 0; i < BACKEND_HASH_COUNT; i++)
	{
		if (!(mask & (1u << i)) || !alg_ids[i])
			continue;
		UCHAR digest[64];
		if (BCryptFinishHash (cng[i].hash, digest, cng[i].digest_len, 0) < 0)
		{
			res->error = "hash provider error";
			return;
		}
		res->hash[i] = hex_bytes (digest, cng[i].digest_len);
	}
	if (mask & BACKEND_HASH_CRC32)
	{
		char text[16];
		snprintf (text, sizeof (text), "%08lx", (unsigned long) (crc32 ^ 0xffffffffUL));
		res->hash[2] = text;
	}
	if (mask & BACKEND_HASH_CRC64)
	{
		char text[24];
		snprintf (text, sizeof (text), "%016llx", (unsigned long long) (crc64 ^ ~0ULL));
		res->hash[3] = text;
	}
	post_hash_progress (seq, task.path, 100);
}

/* Hex/text viewers: read LENGTH bytes at OFFSET.  A request past EOF
   is not an error -- the viewer sizes itself from file_size and a
   short or empty read simply ends the listing.  */
void
run_read_chunk (const backend_task &task, backend_result *res)
{
	rover_file *f = rover_file_open (task.path.c_str ());

	if (!f)
	{
		set_error (res, "cannot open file");
		return;
	}
	res->file_size = rover_file_size (f);
	if (task.limit != BACKEND_SIZE_UNKNOWN && task.limit < res->file_size)
		res->file_size = task.limit;
	UINT64 remain = task.offset < res->file_size ? res->file_size - task.offset : 0;
	size_t want = (size_t) (remain < task.length ? remain : task.length);
	if (want && rover_file_seek (f, task.offset))
	{
		set_error (res, "seek error");
		rover_file_close (f);
		return;
	}
	res->data.resize (want);
	size_t got = 0;
	while (got < want)
	{
		/* The text viewer asks for megabytes; keep dokan served
		   and shutdown responsive between fs reads.  */
		if (g_cancel.load (std::memory_order_relaxed))
			break;
		service_requests ();
		long long r = rover_file_read (f, res->data.data () + got, want - got);
		if (r < 0)
		{
			set_error (res, "read error");
			res->data.clear ();
			rover_file_close (f);
			return;
		}
		if (r == 0)
			break;
		got += (size_t) r;
	}
	res->data.resize (got);
	rover_file_close (f);
}

/* Progress for the unlock KDF (Argon2/PBKDF2).  A non-capturing callback
   so it fits rover_set_crypto_progress; the seq + throttle live in the
   ctx passed as data.  */
struct crypto_prog_ctx
{
	UINT seq;
	ULONGLONG last_tick;
};

void
crypto_progress (unsigned long long done, unsigned long long total, void *data)
{
	auto *ctx = static_cast<crypto_prog_ctx *> (data);
	ULONGLONG now = GetTickCount64 ();

	if (now - ctx->last_tick < 100)
		return;
	ctx->last_tick = now;

	backend_progress *p = new backend_progress;
	p->seq = ctx->seq;
	p->percent = total ? (int) (done * 100 / total) : 0;
	p->file_index = 1;
	p->file_total = 1;
	if (!PostMessageW (g_notify, WM_APP_TASK_PROGRESS, ctx->seq, (LPARAM) p))
		delete p;
}

/* Cryptodisk unlock: hand the passphrase/keyfile bytes to grub and, on
   success, report the resulting "cryptoN" device so the GUI can refresh
   and browse into it.  The key derivation can be slow (Argon2), so drive
   a progress bar through the crypto progress hook while it runs.  */
void
run_crypto_unlock (const backend_task &task, backend_result *res)
{
	char dev[64] = { 0 };
	crypto_prog_ctx ctx = { res->seq, 0 };

	rover_set_crypto_progress (crypto_progress, &ctx);
	if (rover_crypto_unlock (task.path.c_str (), task.key.data (),
				 task.key.size (), dev, sizeof (dev)))
		set_error (res, "cannot unlock volume");
	else
		res->path = dev;
	rover_set_crypto_progress (nullptr, nullptr);
}

backend_result *
run_task (queued_task &item)
{
	backend_result *res = new backend_result;

	res->type = item.task.type;
	res->seq = item.seq;

	switch (item.task.type)
	{
	case backend_task_type::enum_disks:
		rover_enum_disks (enum_disk_hook, &res->disks);
		std::sort (res->disks.begin (), res->disks.end (),
			[] (const backend_diskent &a, const backend_diskent &b)
			{
				return a.name < b.name;
			});
		break;
	case backend_task_type::list_dir:
		run_list_dir (item.task.path, res);
		break;
	case backend_task_type::extract:
		run_extract (item.task, item.seq, res);
		break;
	case backend_task_type::loopback_add:
	{
		std::string dev = "loop" + std::to_string (g_loop_seq);
		if (rover_loopback_add (dev.c_str (), item.task.path.c_str (), item.task.decompress ? 1 : 0))
			set_error (res, "cannot mount image");
		else
		{
			g_loop_seq++;
			res->path = dev;
		}
		break;
	}
	case backend_task_type::loopback_del:
		res->path = item.task.path;
		if (rover_loopback_del (item.task.path.c_str ()))
			set_error (res, "cannot unmount device");
		break;
	case backend_task_type::file_props:
		res->path = item.task.path;
		run_file_props (item.task.path, res);
		break;
	case backend_task_type::hash_file:
		res->path = item.task.path;
		run_hash_file (item.task, item.seq, res);
		break;
	case backend_task_type::read_chunk:
		res->path = item.task.path;
		run_read_chunk (item.task, res);
		break;
	case backend_task_type::crypto_unlock:
		run_crypto_unlock (item.task, res);
		break;
	}
	return res;
}

unsigned __stdcall
backend_main (void *)
{
	rover_init ();
	PostMessageW (g_notify, WM_APP_BACKEND_READY, 0, 0);

	for (;;)
	{
		queued_task item;
		bool have_task = false;
		{
			std::unique_lock<std::mutex> hold (g_lock);
			g_wake.wait (hold,
				[]
				{
					return g_stop || !g_queue.empty () || !g_requests.empty ();
				});
			if (g_stop)
				break;
			if (!g_queue.empty ())
			{
				item = std::move (g_queue.front ());
				g_queue.pop_front ();
				have_task = true;
			}
		}

		service_requests ();
		if (!have_task)
			continue;
		g_cancel.store (false, std::memory_order_relaxed);
		backend_result *res = run_task (item);
		if (!PostMessageW (g_notify, WM_APP_TASK_DONE, res->seq, (LPARAM) res))
			delete res;
	}

	/* Unblock any straggler before grub state goes away.  */
	service_requests ();
	rover_fini ();
	filetype_shutdown ();
	return 0;
}

} // namespace

backend_support
backend_get_support (void)
{
	backend_support s;

	backend_call ([&s] ()
	{
		rover_enum_support (ROVER_SUPPORT_FS, support_hook, &s.fs);
		rover_enum_support (ROVER_SUPPORT_PARTMAP, support_hook,
			&s.partmap);
		rover_enum_support (ROVER_SUPPORT_DISKFILTER, support_hook,
			&s.diskfilter);
		rover_enum_support (ROVER_SUPPORT_IOFILTER, support_hook,
			&s.iofilter);
	});
	for (auto *v : { &s.fs, &s.partmap, &s.diskfilter, &s.iofilter })
		std::sort (v->begin (), v->end (),
			[] (const std::string &a, const std::string &b)
			{
				return _stricmp (a.c_str (), b.c_str ()) < 0;
			});
	return s;
}

void
backend_start (HWND notify)
{
	g_notify = notify;
	g_thread = (HANDLE) _beginthreadex (nullptr, 0, backend_main, nullptr, 0, nullptr);
}

void
backend_stop (void)
{
	if (!g_thread)
		return;
	{
		std::lock_guard<std::mutex> hold (g_lock);
		g_stop = true;
		g_queue.clear ();
	}
	g_cancel.store (true, std::memory_order_relaxed);
	g_wake.notify_one ();
	WaitForSingleObject (g_thread, INFINITE);
	CloseHandle (g_thread);
	g_thread = nullptr;
}

UINT
backend_post (backend_task &&task)
{
	UINT seq;
	{
		std::lock_guard<std::mutex> hold (g_lock);
		seq = ++g_seq;
		g_queue.push_back ({ std::move (task), seq });
	}
	g_wake.notify_one ();
	return seq;
}

void
backend_cancel (void)
{
	g_cancel.store (true, std::memory_order_relaxed);
}

void
backend_call (const std::function<void ()> &fn)
{
	HANDLE done = CreateEventW (nullptr, TRUE, FALSE, nullptr);
	{
		std::lock_guard<std::mutex> hold (g_lock);
		g_requests.push_back ({ &fn, done });
	}
	g_wake.notify_one ();
	WaitForSingleObject (done, INFINITE);
	CloseHandle (done);
}
