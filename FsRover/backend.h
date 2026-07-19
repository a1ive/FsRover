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
 * GUI <-> grub backend thread protocol.
 *
 * grub keeps global state (grub_errno, device list, disk cache), so
 * every grub call runs on the single thread owned by this module.
 * The GUI queues work with backend_post() and never blocks: results
 * come back to the window given to backend_start() as WM_APP messages.
 * Strings crossing the boundary are UTF-8 (grub's encoding); the GUI
 * converts to UTF-16 at its edge.
 */

#ifndef FSROVER_BACKEND_H
#define FSROVER_BACKEND_H	1

#include <windows.h>

#include <functional>
#include <string>
#include <vector>

/* backend -> GUI: rover_init() finished, tasks will be served now.  */
constexpr UINT WM_APP_BACKEND_READY = WM_APP + 1;

/* backend -> GUI: a task finished.  lParam = backend_result*
   allocated with new; the GUI takes ownership and deletes it.  */
constexpr UINT WM_APP_TASK_DONE = WM_APP + 2;

/* backend -> GUI: extract progress, throttled.  wParam = task seq,
   lParam = backend_progress* allocated with new; the GUI takes
   ownership and deletes it.  */
constexpr UINT WM_APP_TASK_PROGRESS = WM_APP + 3;

enum class backend_task_type
{
	enum_disks,	/* grub devices -> result.disks */
	list_dir,	/* path -> result.entries */
	extract,	/* paths -> dest, recursive for directories */
	loopback_add,	/* path (image file) -> result.path = "loopN" */
	loopback_del,	/* path = device name */
	file_props,	/* path -> result.text (libmagic description) */
	hash_file,	/* path + hash_mask -> result.hash[] */
	read_chunk,	/* path + offset/length -> result.data, file_size */
	crypto_unlock,	/* path (source device) + key -> result.path = "cryptoN" */
};

/* hash_file algorithms; result.hash[] is indexed by the bit number.  */
constexpr UINT BACKEND_HASH_MD5 = 1u << 0;
constexpr UINT BACKEND_HASH_SHA1 = 1u << 1;
constexpr UINT BACKEND_HASH_CRC32 = 1u << 2;
constexpr UINT BACKEND_HASH_CRC64 = 1u << 3;
constexpr UINT BACKEND_HASH_SHA256 = 1u << 4;
constexpr UINT BACKEND_HASH_SHA512 = 1u << 5;
constexpr int BACKEND_HASH_COUNT = 6;

struct backend_task
{
	backend_task_type type;
	std::string path;	/* list_dir: "(hd0,gpt2)/dir" */
	std::vector<std::string> paths;	/* extract: sources */
	std::wstring dest;	/* extract: destination directory */
	UINT hash_mask = 0;	/* hash_file: BACKEND_HASH_* bits */
	UINT64 offset = 0;	/* read_chunk: file position */
	UINT length = 0;	/* read_chunk: bytes wanted */
	UINT64 limit = ~0ULL;	/* read_chunk: optional logical EOF */
	std::vector<char> key;	/* crypto_unlock: passphrase or keyfile bytes */
	bool decompress = false;	/* loopback_add: decode gzip/xz/... transparently */
};

struct backend_progress
{
	UINT seq;
	int percent;	/* 0..100 of the current file */
	UINT64 file_index;	/* 1-based */
	UINT64 file_total;
	std::string name;	/* current source path, UTF-8 */
};

constexpr UINT64 BACKEND_SIZE_UNKNOWN = ~0ULL;

/* Driver class of a device, from grub_disk_dev_id; values match the
   ROVER_DEV_* constants in rover.h (static_assert'd in backend.cpp).  */
constexpr int BACKEND_DEV_OTHER = 0;
constexpr int BACKEND_DEV_WINDISK = 1;	/* physical disk/volume */
constexpr int BACKEND_DEV_LOOPBACK = 2;	/* loopdisk image mount */
constexpr int BACKEND_DEV_DISKFILTER = 3;	/* lvm/ldm/mdraid/dmraid volume */
constexpr int BACKEND_DEV_CRYPTODISK = 4;	/* unlocked crypto volume */
constexpr int BACKEND_DEV_PROCFS = 5;	/* (proc) pseudo-device */

struct backend_diskent
{
	std::string name;	/* grub device name, no parens */
	bool is_partition;
	int dev_id = BACKEND_DEV_OTHER;	/* BACKEND_DEV_* driver class */
	UINT64 size;	/* bytes, BACKEND_SIZE_UNKNOWN if unknown */
	std::string fs;	/* empty if unrecognized */
	std::string label;	/* empty if none */
	bool encrypted = false;	/* locked LUKS/LUKS2 or BitLocker container */
	std::string crypto_type;	/* "luks", "luks2" or "bitlocker" */
	std::string crypto_uuid;	/* container UUID when encrypted */
};

struct backend_dirent
{
	std::string name;
	bool is_dir;
	bool is_symlink;
	UINT64 size;	/* BACKEND_SIZE_UNKNOWN if not determined */
	INT64 mtime;	/* seconds since Unix epoch, 0 = unknown */
};

struct backend_result
{
	backend_task_type type;
	UINT seq;	/* matches the backend_post() return value */
	std::string error;	/* empty = success */
	std::string path;	/* list_dir: the path that was listed */
	std::vector<backend_diskent> disks;	/* enum_disks */
	std::vector<backend_dirent> entries;	/* list_dir, dirs first */
	UINT64 stat_files = 0;	/* extract: files written */
	UINT64 stat_bytes = 0;	/* extract: bytes written */
	std::string text;	/* file_props: libmagic description */
	std::string hash[BACKEND_HASH_COUNT];	/* hash_file: lowercase hex */
	std::vector<char> data;	/* read_chunk: short read = EOF */
	UINT64 file_size = 0;	/* read_chunk */
};

/* Registered feature names for the Help "supported features" list,
   each vector sorted case-insensitively.  Fetched synchronously on the
   backend thread via backend_call(); the grub registration lists are
   fixed once rover_init() has run, so any time after backend_start()
   is fine.  */
struct backend_support
{
	std::vector<std::string> fs;
	std::vector<std::string> partmap;
	std::vector<std::string> diskfilter;
	std::vector<std::string> iofilter;
};

backend_support backend_get_support (void);

/* Start the backend thread; results are posted to NOTIFY.  */
void backend_start (HWND notify);

/* Discard queued tasks, join the thread, release grub state.  */
void backend_stop (void);

/* Queue a task; returns its seq for matching the result.  */
UINT backend_post (backend_task &&task);

/* Ask the currently running task to stop at the next checkpoint.  */
void backend_cancel (void);

/* Run FN on the backend thread and wait for it to finish.  This is
   how dokan worker threads reach rover: requests jump ahead of queued
   tasks and are also serviced inside long tasks between read chunks.
   Never call from the backend thread itself.  */
void backend_call (const std::function<void ()> &fn);

#endif /* ! FSROVER_BACKEND_H */
