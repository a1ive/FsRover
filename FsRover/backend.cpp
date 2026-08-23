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
#include <memory>
#include <mutex>

#include <rover.h>

#include <filetype.h>

#include "../common/extract_core.h"
#include "../common/natural_sort.h"
#include "dokanfs.h"
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
	sync_request (const std::function<void ()> &request_fn, HANDLE event) :
		fn (request_fn), done (event)
	{
	}

	~sync_request ()
	{
		CloseHandle (done);
	}

	std::function<void ()> fn;
	HANDLE done;
};

enum class backend_state
{
	stopped,
	starting,
	running,
	stopping,
};

HWND g_notify;
HANDLE g_thread;
std::mutex g_lock;
std::condition_variable g_wake;
std::deque<queued_task> g_queue;	/* guarded by g_lock */
std::deque<std::shared_ptr<sync_request>> g_requests;	/* guarded by g_lock */
backend_state g_state = backend_state::stopped;	/* guarded by g_lock */
bool g_stop;	/* guarded by g_lock */
UINT g_seq;	/* guarded by g_lock */
std::atomic<bool> g_cancel;
std::atomic<UINT> g_latest_list_seq;	/* newest GUI directory generation */
UINT g_loop_seq;	/* backend thread only: next "loopN" suffix */
UINT g_img_seq;	/* backend thread only: next "imgN" suffix */
int g_init_flags;	/* ROVER_INIT_*, set before the thread starts */

/* Backend thread: run every pending backend_call().  Called between
   tasks and at chunk boundaries inside long ones, so dokan requests
   are not starved by a long extract or listing.  */
void
service_requests (void)
{
	for (;;)
	{
		std::shared_ptr<sync_request> req;
		{
			std::lock_guard<std::mutex> hold (g_lock);
			if (g_requests.empty ())
				return;
			req = g_requests.front ();
			g_requests.pop_front ();
		}
		req->fn ();
		SetEvent (req->done);
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
	&& BACKEND_DEV_PROCFS == ROVER_DEV_PROCFS
	&& BACKEND_DEV_WINFILE == ROVER_DEV_WINFILE,
	"BACKEND_DEV_* must match ROVER_DEV_*");

static_assert (BACKEND_VC_PRF_AUTO == ROVER_VC_PRF_AUTO
	&& BACKEND_VC_PRF_SHA512 == ROVER_VC_PRF_SHA512
	&& BACKEND_VC_PRF_WHIRLPOOL == ROVER_VC_PRF_WHIRLPOOL
	&& BACKEND_VC_PRF_SHA256 == ROVER_VC_PRF_SHA256
	&& BACKEND_VC_PRF_RIPEMD160 == ROVER_VC_PRF_RIPEMD160
	&& BACKEND_VC_PRF_STREEBOG == ROVER_VC_PRF_STREEBOG
	&& BACKEND_VC_TRUECRYPT == ROVER_VC_TRUECRYPT
	&& BACKEND_VC_HIDDEN == ROVER_VC_HIDDEN
	&& BACKEND_VC_BACKUP == ROVER_VC_BACKUP,
	"BACKEND_VC_* must match ROVER_VC_*");

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
	d.fs_uuid = info->fs_uuid ? info->fs_uuid : "";
	d.start_lba = info->start_lba;
	d.sector_size = info->sector_size;
	d.parent_file = info->parent_file ? info->parent_file : "";
	d.parent_device = info->parent_device ? info->parent_device : "";
	d.parents = info->parents ? info->parents : "";
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
	e.size = e.is_dir || e.is_symlink ? 0 : BACKEND_SIZE_UNKNOWN;
	e.size_set = e.is_dir || e.is_symlink;
	e.mtime = ent->mtime_set ? ent->mtime : 0;
	e.inode_set = ent->inode_set != 0;
	e.inode = ent->inode;
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
			return rover_sort::natural_less (a.name, b.name);
		});

	/* grub dir hooks do not report file sizes.  The GUI asks for
	   bounded visible ranges later instead of turning this cheap
	   enumeration into one file open per entry.  */
}

void
run_list_sizes (const list_sizes_task &task, backend_result *res)
{
	std::string prefix = task.path;
	if (prefix.empty () || prefix.back () != '/')
		prefix += '/';

	res->path = task.path;
	res->owner_seq = task.owner_seq;
	res->sizes.reserve (task.paths.size ());
	for (const std::string &name : task.paths)
	{
		/* A navigation posted while this batch is running makes the
		   remaining random reads useless.  This is separate from the
		   extraction cancellation flag.  */
		if (task.owner_seq != g_latest_list_seq.load (std::memory_order_relaxed))
			break;
		service_requests ();
		rover_file *f = rover_file_open ((prefix + name).c_str ());
		if (f)
		{
			res->sizes.push_back (rover_file_size (f));
			rover_file_close (f);
		}
		else
			res->sizes.push_back (BACKEND_SIZE_UNKNOWN);
	}
}

/*
 * Extraction is implemented once in common/extract.cpp.  The GUI
 * adapter below only supplies backend cancellation, request servicing,
 * and progress-message delivery.
 */

void
post_extract_progress (UINT seq, ULONGLONG &last_tick,
	const rover_extract::progress &progress)
{
	if (progress.kind == rover_extract::progress_kind::failed)
		return;

	ULONGLONG now = GetTickCount64 ();
	if (progress.kind == rover_extract::progress_kind::advanced
	    && now - last_tick < 100)
		return;
	last_tick = now;

	backend_progress *posted = new backend_progress;
	posted->seq = seq;
	posted->percent = progress.percent;
	posted->file_index = progress.file_index;
	posted->file_total = progress.file_total;
	posted->name = progress.source;
	if (!PostMessageW (g_notify, WM_APP_TASK_PROGRESS, seq, (LPARAM) posted))
		delete posted;
}

/* Progress for the tasks that work on a single item (image export,
   hashing): one "file" of one, so only the percentage moves.  */
void
post_item_progress (UINT seq, const std::string &name, int percent)
{
	backend_progress *p = new backend_progress;

	p->seq = seq;
	p->percent = percent;
	p->file_index = 1;
	p->file_total = 1;
	p->name = name;
	if (!PostMessageW (g_notify, WM_APP_TASK_PROGRESS, seq, (LPARAM) p))
		delete p;
}

void
run_extract (const extract_task &task, UINT seq, backend_result *res)
{
	rover_extract::options options;
	rover_extract::result stats;
	std::string error;
	ULONGLONG last_tick = 0;

	options.preserve_times = task.preserve_times;
	options.cancelled = [] ()
	{
		return g_cancel.load (std::memory_order_relaxed);
	};
	options.service = [] ()
	{
		service_requests ();
	};
	options.report_progress = [seq, &last_tick] (
		const rover_extract::progress &progress)
	{
		post_extract_progress (seq, last_tick, progress);
	};

	rover_extract::extract (task.paths, task.dest, options, &stats, &error);
	res->stat_files = stats.files;
	res->stat_bytes = stats.bytes;
	res->stat_links = stats.links;
	res->stat_errors = stats.errors.size ();
	if (!stats.errors.empty ())
		res->extract_error = std::move (stats.errors.front ());
	res->error = std::move (error);
}

/*
 * Raw image export: the device read through grub's "(dev)0+" blocklist
 * -- the whole span of the device, byte for byte -- into one .img file.
 *
 * The blocklist sizes itself from the parent disk, so on a partition
 * its size covers the entire disk while reads past the partition end
 * fail; task.limit carries the device size the GUI already knows and
 * is what actually bounds the copy (same arrangement as read_chunk).
 */
void
run_export_image (const export_image_task &task, UINT seq, backend_result *res)
{
	std::string src = "(" + task.path + ")0+";
	std::vector<char> buf ((size_t) 1 << 20);
	rover_file *f;
	HANDLE h;
	UINT64 total;
	ULONGLONG last_tick;

	f = rover_file_open (src.c_str ());
	if (!f)
	{
		set_error (res, "cannot open device");
		return;
	}
	total = rover_file_size (f);
	if (task.limit < total)
		total = task.limit;

	h = CreateFileW (task.dest.c_str (), GENERIC_WRITE, 0, nullptr,
			 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE)
	{
		rover_file_close (f);
		res->error = "cannot create image file";
		return;
	}

	last_tick = GetTickCount64 ();
	post_item_progress (seq, task.path, 0);
	while (res->stat_bytes < total)
	{
		if (g_cancel.load (std::memory_order_relaxed))
			break;
		service_requests ();
		UINT64 remain = total - res->stat_bytes;
		size_t want = buf.size () < remain ? buf.size () : (size_t) remain;
		long long r = rover_file_read (f, buf.data (), want);
		if (r < 0)
		{
			set_error (res, "read error");
			break;
		}
		/* Short of the announced size: the device shrank or lied,
		   so the image would be truncated -- say so.  */
		if (r == 0)
		{
			res->error = "device ended before the expected size";
			break;
		}
		DWORD w = 0;
		if (!WriteFile (h, buf.data (), (DWORD) r, &w, nullptr)
		    || w != (DWORD) r)
		{
			res->error = "write failed";
			break;
		}
		res->stat_bytes += (UINT64) r;

		ULONGLONG now = GetTickCount64 ();
		if (now - last_tick >= 100)
		{
			last_tick = now;
			post_item_progress (seq, task.path,
				total ? (int) (res->stat_bytes * 100 / total) : 100);
		}
	}

	CloseHandle (h);
	rover_file_close (f);
	if (res->error.empty () && g_cancel.load (std::memory_order_relaxed))
		res->error = "export cancelled";
	/* A partial raw image is indistinguishable from a complete one
	   once the app is gone, and there is no resume; drop it.  */
	if (!res->error.empty ())
	{
		DeleteFileW (task.dest.c_str ());
		res->stat_bytes = 0;
	}
	else
		res->stat_files = 1;
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
	rover_stat_t st;
	rover_file *f;

	/* Identity first, and on its own: it comes from the directory
	   entry rather than the file, so it is still worth showing for a
	   file whose contents cannot be read.  */
	if (!rover_stat (path.c_str (), &st) && st.inode_set)
	{
		res->inode_set = true;
		res->inode = st.inode;
	}

	f = rover_file_open (path.c_str ());
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
			crc = (crc & 1) ? ((crc >> 1) ^ 0xedb88320UL) : (crc >> 1);
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
			crc = (crc & 1) ? ((crc >> 1) ^ 0xc96c5795d7870f42ULL) : (crc >> 1);
		table[i] = crc;
	}
}

void
run_hash_file (const hash_file_task &task, UINT seq, backend_result *res)
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
			if ((mask & (1u << i)) && alg_ids[i] && BCryptHashData (cng[i].hash, (PUCHAR) buf.data (), (ULONG) r, 0) < 0)
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
			post_item_progress (seq, task.path, total ? (int) (done * 100 / total) : 0);
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
	post_item_progress (seq, task.path, 100);
}

/* Hex/text viewers: read LENGTH bytes at OFFSET.  A request past EOF
   is not an error -- the viewer sizes itself from file_size and a
   short or empty read simply ends the listing.  */
void
run_read_chunk (const read_chunk_task &task, backend_result *res)
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
run_crypto_unlock (const crypto_unlock_task &task, backend_result *res)
{
	char dev[64] = { 0 };
	crypto_prog_ctx ctx = { res->seq, 0 };

	rover_set_crypto_progress (crypto_progress, &ctx);
	if (rover_crypto_unlock (task.path.c_str (), task.key.data (), task.key.size (), dev, sizeof (dev)))
		set_error (res, "cannot unlock volume");
	else
		res->path = dev;
	rover_set_crypto_progress (nullptr, nullptr);
}

/* For VeraCrypt/TrueCrypt volumes, which additionally need the
   parameters that are not stored in the volume.
   Key files were already folded into task.key by the dialog.  */
void
run_veracrypt_unlock (const veracrypt_unlock_task &task, backend_result *res)
{
	char dev[64] = { 0 };
	crypto_prog_ctx ctx = { res->seq, 0 };

	rover_set_crypto_progress (crypto_progress, &ctx);
	if (rover_veracrypt_unlock (task.path.c_str (), task.key.data (), task.key.size (),
		task.pim, task.prf, task.vc_flags, dev, sizeof (dev)))
		set_error (res, "cannot unlock volume");
	else
		res->path = dev;
	rover_set_crypto_progress (nullptr, nullptr);
}

/* Plain dm-crypt volumes: no header, so every parameter comes from the
   dialog and a wrong one yields garbage rather than an error.  */
void
run_plainmount_unlock (const plainmount_unlock_task &task, backend_result *res)
{
	char dev[64] = { 0 };

	if (rover_plainmount_unlock (task.path.c_str (), task.cipher.c_str (),
				     task.hash.c_str (), task.key_bits,
				     task.sector_size, task.offset, task.skip,
				     task.key.data (), task.key.size (),
				     task.keyfile ? ROVER_PM_KEYFILE : 0u, nullptr,
				     dev, sizeof (dev)))
		set_error (res, "cannot mount volume");
	else
		res->path = dev;
}

void
run_payload (const enum_disks_task &, UINT, backend_result *res)
{
	res->type = backend_task_type::enum_disks;
	rover_enum_disks (enum_disk_hook, &res->disks);
	std::sort (res->disks.begin (), res->disks.end (),
		[] (const backend_diskent &a, const backend_diskent &b)
		{
			return rover_sort::natural_less (a.name, b.name);
		});
}

void
run_payload (const list_dir_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::list_dir;
	run_list_dir (task.path, res);
}

void
run_payload (const list_sizes_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::list_sizes;
	run_list_sizes (task, res);
}

void
run_payload (const extract_task &task, UINT seq, backend_result *res)
{
	res->type = backend_task_type::extract;
	run_extract (task, seq, res);
}

void
run_payload (const export_image_task &task, UINT seq, backend_result *res)
{
	res->type = backend_task_type::export_image;
	res->path = task.path;
	run_export_image (task, seq, res);
}

void
run_payload (const loopback_add_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::loopback_add;
	std::string dev = "loop" + std::to_string (g_loop_seq);
	if (rover_loopback_add (dev.c_str (), task.path.c_str (), task.decompress ? 1 : 0))
		set_error (res, "cannot mount image");
	else
	{
		g_loop_seq++;
		res->path = dev;
	}
}

void
run_payload (const loopback_del_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::loopback_del;
	res->path = task.path;
	if (rover_loopback_del (task.path.c_str ()))
		set_error (res, "cannot unmount device");
}

void
run_payload (const winfile_add_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::winfile_add;
	/* The image lives on the Windows filesystem, which has no grub
	   device.  Do not enter one of our own Dokan mounts here: its
	   worker waits for this backend thread, which would deadlock.  */
	std::string dev = "img" + std::to_string (g_img_seq);
	if (dokanfs_owns_path (task.path))
		set_error (res, "cannot mount an image through FsRover's own Dokan drive; use Mount as disk instead");
	else if (rover_winfile_add (dev.c_str (), narrow (task.path).c_str (),
		task.decompress ? 1 : 0))
		set_error (res, "cannot mount image");
	else
	{
		g_img_seq++;
		res->path = dev;
	}
}

void
run_payload (const winfile_del_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::winfile_del;
	res->path = task.path;
	if (rover_winfile_del (task.path.c_str ()))
		set_error (res, "cannot unmount device");
}

void
run_payload (const file_props_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::file_props;
	res->path = task.path;
	run_file_props (task.path, res);
}

void
run_payload (const hash_file_task &task, UINT seq, backend_result *res)
{
	res->type = backend_task_type::hash_file;
	res->path = task.path;
	run_hash_file (task, seq, res);
}

void
run_payload (const read_chunk_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::read_chunk;
	res->path = task.path;
	run_read_chunk (task, res);
}

void
run_payload (const crypto_unlock_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::crypto_unlock;
	run_crypto_unlock (task, res);
}

void
run_payload (const veracrypt_unlock_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::veracrypt_unlock;
	run_veracrypt_unlock (task, res);
}

void
run_payload (const plainmount_unlock_task &task, UINT, backend_result *res)
{
	res->type = backend_task_type::plainmount_unlock;
	run_plainmount_unlock (task, res);
}

backend_result *
run_task (queued_task &item)
{
	backend_result *res = new backend_result;

	res->seq = item.seq;
	std::visit ([&] (const auto &task)
	{
		run_payload (task, item.seq, res);
	}, item.task);
	return res;
}

unsigned __stdcall
backend_main (void *)
{
	bool notify = false;

	rover_init (g_init_flags);
	{
		std::lock_guard<std::mutex> hold (g_lock);
		if (g_state == backend_state::starting)
		{
			g_state = backend_state::running;
			notify = true;
		}
	}
	if (notify)
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
	{
		std::lock_guard<std::mutex> hold (g_lock);
		g_state = backend_state::stopped;
	}
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
		rover_enum_support (ROVER_SUPPORT_CRYPTODISK, support_hook,
			&s.cryptodisk);
		rover_enum_support (ROVER_SUPPORT_IOFILTER, support_hook,
			&s.iofilter);
	});
	for (auto *v : { &s.fs, &s.partmap, &s.diskfilter, &s.cryptodisk, &s.iofilter })
		std::sort (v->begin (), v->end (),
			[] (const std::string &a, const std::string &b)
			{
				return rover_sort::natural_less (a, b);
			});
	return s;
}

void
backend_set_fs_char_encoding (UINT encoding)
{
	backend_call ([encoding] ()
	{
		rover_set_fs_char_encoding (encoding);
	});
}

bool
backend_start (HWND notify, bool no_windisk)
{
	std::lock_guard<std::mutex> hold (g_lock);

	if (g_state != backend_state::stopped || g_thread)
		return false;
	g_notify = notify;
	g_init_flags = no_windisk ? ROVER_INIT_NO_WINDISK : 0;
	g_stop = false;
	g_cancel.store (false, std::memory_order_relaxed);
	g_state = backend_state::starting;
	g_thread = (HANDLE) _beginthreadex (nullptr, 0, backend_main, nullptr, 0, nullptr);
	if (!g_thread)
	{
		g_state = backend_state::stopped;
		return false;
	}
	return true;
}

bool
backend_stop (void)
{
	HANDLE thread;
	{
		std::lock_guard<std::mutex> hold (g_lock);
		thread = g_thread;
		if (!thread)
			return true;
		if (g_state != backend_state::stopped)
		{
			g_state = backend_state::stopping;
			g_stop = true;
			g_queue.clear ();
		}
	}
	g_cancel.store (true, std::memory_order_relaxed);
	g_wake.notify_one ();
	if (WaitForSingleObject (thread, INFINITE) != WAIT_OBJECT_0)
		return false;
	{
		std::lock_guard<std::mutex> hold (g_lock);
		if (g_thread == thread)
		{
			CloseHandle (g_thread);
			g_thread = nullptr;
		}
		g_state = backend_state::stopped;
		g_stop = false;
		g_requests.clear ();
	}
	return true;
}

UINT
backend_post (backend_task &&task)
{
	UINT seq;
	{
		std::lock_guard<std::mutex> hold (g_lock);
		if (g_state != backend_state::running)
			return 0;
		seq = ++g_seq;
		if (std::holds_alternative<list_dir_task> (task))
			g_latest_list_seq.store (seq, std::memory_order_relaxed);
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

bool
backend_call (const std::function<void ()> &fn)
{
	HANDLE done = CreateEventW (nullptr, TRUE, FALSE, nullptr);
	if (!done)
		return false;
	auto req = std::make_shared<sync_request> (fn, done);
	HANDLE thread_wait = nullptr;
	{
		std::lock_guard<std::mutex> hold (g_lock);
		if (g_state != backend_state::running
		    || !DuplicateHandle (GetCurrentProcess (), g_thread,
			GetCurrentProcess (), &thread_wait, SYNCHRONIZE, FALSE, 0))
			return false;
		g_requests.push_back (req);
	}
	g_wake.notify_one ();
	HANDLE waits[] = { done, thread_wait };
	DWORD wait = WaitForMultipleObjects (2, waits, FALSE, INFINITE);
	CloseHandle (thread_wait);
	if (wait == WAIT_OBJECT_0)
		return true;

	/* The backend exited, or the wait itself failed.  Remove a request
	   that had not been claimed so its captured references cannot run
	   after this call returns.  A claimed request is always completed
	   before the backend thread handle becomes signalled.  */
	{
		std::lock_guard<std::mutex> hold (g_lock);
		auto it = std::find (g_requests.begin (), g_requests.end (), req);
		if (it != g_requests.end ())
			g_requests.erase (it);
	}
	return false;
}
