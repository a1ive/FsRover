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

#include <windows.h>

#include <atomic>
#include <cstdlib>
#include <string>
#include <thread>

#include "fusefs.h"
#include "gui.h"
#include "winfsp_fuse.h"
#include "winfspfs.h"

namespace
{

typedef int (*fn_version) (fsp_fuse_env *);
typedef fuse_chan *(*fn_mount) (fsp_fuse_env *, const char *, fuse_args *);
typedef void (*fn_unmount) (fsp_fuse_env *, const char *, fuse_chan *);
typedef fuse *(*fn_new) (fsp_fuse_env *, fuse_chan *, fuse_args *,
	const fuse_operations *, size_t, void *);
typedef void (*fn_destroy) (fsp_fuse_env *, fuse *);
typedef int (*fn_loop_mt) (fsp_fuse_env *, fuse *);
typedef void (*fn_exit) (fsp_fuse_env *, fuse *);
typedef fuse_context *(*fn_get_context) (fsp_fuse_env *);
typedef void (*fn_free_args) (fsp_fuse_env *, fuse_args *);

HMODULE g_dll;
HWND g_notify;
UINT g_gone_message;
UINT g_mounted_message;
fsp_fuse_env g_env;
fn_version p_version;
fn_mount p_mount;
fn_unmount p_unmount;
fn_new p_new;
fn_destroy p_destroy;
fn_loop_mt p_loop_mt;
fn_exit p_exit;
fn_get_context p_get_context;
fn_free_args p_free_args;

int
env_daemonize (int)
{
	return 0;
}

int
env_signals (void *)
{
	return 0;
}

std::wstring
runtime_path (void)
{
	HKEY key = nullptr;
	if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"SOFTWARE\\WinFsp", 0,
		KEY_QUERY_VALUE | KEY_WOW64_32KEY, &key) != ERROR_SUCCESS)
		return {};

	wchar_t dir[MAX_PATH];
	DWORD bytes = sizeof (dir);
	LONG rc = RegQueryValueExW (key, L"SxsDir", nullptr, nullptr,
		(BYTE *) dir, &bytes);
	if (rc != ERROR_SUCCESS)
	{
		bytes = sizeof (dir);
		rc = RegQueryValueExW (key, L"InstallDir", nullptr, nullptr,
			(BYTE *) dir, &bytes);
	}
	RegCloseKey (key);
	if (rc != ERROR_SUCCESS || bytes < sizeof (wchar_t))
		return {};

	std::wstring path = dir;
	if (!path.empty () && path.back () != L'\\')
		path += L'\\';
	path += L"bin\\";
#if defined(_M_ARM64)
	path += L"winfsp-a64.dll";
#elif defined(_WIN64)
	path += L"winfsp-x64.dll";
#else
	path += L"winfsp-x86.dll";
#endif
	return path;
}

template<typename T>
bool
load_proc (T *out, const char *name)
{
	*out = (T) GetProcAddress (g_dll, name);
	return *out != nullptr;
}

fusefs *
current_fs (void)
{
	fuse_context *context = p_get_context (&g_env);
	return context ? (fusefs *) context->private_data : nullptr;
}

void
copy_stat (const fusefs_stat &in, fuse_stat *out)
{
	ZeroMemory (out, sizeof (*out));
	out->st_mode = in.mode;
	out->st_nlink = 1;
	out->st_ino = in.inode;
	out->st_size = (fuse_off_t) in.size;
	out->st_mtim.tv_sec = (decltype (out->st_mtim.tv_sec)) in.mtime;
	out->st_atim = out->st_mtim;
	out->st_ctim = out->st_mtim;
	out->st_blksize = 512;
	out->st_blocks = (fuse_blkcnt_t) ((in.size + 511) / 512);
}

int
fs_getattr (const char *path, fuse_stat *out)
{
	fusefs_stat st = {};
	fusefs *fs = current_fs ();
	int rc = fs ? fusefs_getattr (fs, path, &st) : -EIO;
	if (!rc)
		copy_stat (st, out);
	return rc;
}

int
fs_open (const char *path, fuse_file_info *info)
{
	fusefs *fs = current_fs ();
	return fs ? fusefs_open (fs, path, info->flags, &info->fh) : -EIO;
}

int
fs_read (const char *path, char *buf, size_t size, fuse_off_t offset,
	fuse_file_info *info)
{
	fusefs *fs = current_fs ();
	return fs ? fusefs_read (fs, path, buf, size, offset, &info->fh) : -EIO;
}

int
fs_release (const char *, fuse_file_info *info)
{
	return fusefs_release (&info->fh);
}

struct fill_context
{
	void *buf;
	fuse_fill_dir_t fill;
};

int
fill_dir (void *opaque, const char *name, const fusefs_stat *st)
{
	auto *context = (fill_context *) opaque;
	fuse_stat out;
	copy_stat (*st, &out);
	return context->fill (context->buf, name, &out, 0);
}

int
fs_readdir (const char *path, void *buf, fuse_fill_dir_t fill,
	fuse_off_t, fuse_file_info *)
{
	fusefs *fs = current_fs ();
	fill_context context = { buf, fill };
	return fs ? fusefs_readdir (fs, path, fill_dir, &context) : -EIO;
}

int
fs_statfs (const char *, fuse_statvfs *out)
{
	fusefs *fs = current_fs ();
	fusefs_statvfs st = {};
	int rc = fs ? fusefs_statfs (fs, &st) : -EIO;
	if (rc)
		return rc;
	ZeroMemory (out, sizeof (*out));
	out->f_bsize = (decltype (out->f_bsize)) st.block_size;
	out->f_frsize = (decltype (out->f_frsize)) st.block_size;
	out->f_blocks = (fuse_fsblkcnt_t) st.blocks;
	out->f_namemax = (decltype (out->f_namemax)) st.name_max;
	return 0;
}

void *
fs_init (fuse_conn_info *conn)
{
	conn->want |= FSP_FUSE_CAP_READ_ONLY;
	fuse_context *context = p_get_context (&g_env);
	return context ? context->private_data : nullptr;
}

fuse_operations g_ops =
{
	.getattr = fs_getattr,
	.open = fs_open,
	.read = fs_read,
	.statfs = fs_statfs,
	.release = fs_release,
	.readdir = fs_readdir,
	.init = fs_init,
};

} // namespace

struct winfsp_mount
{
	fusefs *fs;
	std::string mountpoint;
	void *notify_context;
	bool open_explorer;
	fuse_chan *channel;
	fuse *instance;
	std::thread worker;
	HANDLE finished;
	std::atomic<bool> published;
};

bool
winfspfs_init (HWND notify, UINT gone_message, UINT mounted_message)
{
	g_notify = notify;
	g_gone_message = gone_message;
	g_mounted_message = mounted_message;
	std::wstring path = runtime_path ();
	if (path.empty ())
		return false;
	g_dll = LoadLibraryW (path.c_str ());
	if (!g_dll)
		return false;

	bool ok = load_proc (&p_version, "fsp_fuse_version")
		&& load_proc (&p_mount, "fsp_fuse_mount")
		&& load_proc (&p_unmount, "fsp_fuse_unmount")
		&& load_proc (&p_new, "fsp_fuse_new")
		&& load_proc (&p_destroy, "fsp_fuse_destroy")
		&& load_proc (&p_loop_mt, "fsp_fuse_loop_mt")
		&& load_proc (&p_exit, "fsp_fuse_exit")
		&& load_proc (&p_get_context, "fsp_fuse_get_context")
		&& load_proc (&p_free_args, "fsp_fuse_opt_free_args");
	if (!ok)
	{
		FreeLibrary (g_dll);
		g_dll = nullptr;
		return false;
	}

	g_env = { 'W', malloc, free, env_daemonize, env_signals,
		nullptr, nullptr, { nullptr, nullptr } };
	if (p_version (&g_env) < 28)
	{
		FreeLibrary (g_dll);
		g_dll = nullptr;
		return false;
	}
	return true;
}

bool
winfspfs_available (void)
{
	return g_dll != nullptr;
}

void
winfspfs_shutdown (void)
{
	if (g_dll)
		FreeLibrary (g_dll);
	g_dll = nullptr;
}

winfsp_mount *
winfspfs_mount (fusefs *fs, wchar_t letter, bool open_explorer,
	void *notify_context, std::wstring *error)
{
	if (!g_dll)
	{
		*error = L"WinFsp is not available";
		return nullptr;
	}

	auto *mount = new winfsp_mount;
	mount->fs = fs;
	/* A plain X: mount uses the caller's local DOS-device namespace.  Under
	   UAC an elevated FsRover and the desktop Explorer have different
	   authentication IDs, so Explorer cannot resolve that drive.  WinFsp
	   treats \\?\X: as a Mount Manager request, which publishes the drive
	   across both token namespaces; that path requires elevation. */
	mount->mountpoint = std::string (is_elevated () ? "\\\\?\\" : "")
		+ (char) letter + ":";
	mount->notify_context = notify_context;
	mount->open_explorer = open_explorer;
	mount->channel = nullptr;
	mount->instance = nullptr;
	mount->published = false;
	char arg0[] = "FsRover";
	char arg1[] = "-o";
	std::string label = fs->device;
	for (char &c : label)
		if (c == ',')
			c = '_';
	std::string options = "ro,volname=" + label + ",ExactFileSystemName=FsRover";
	char *argv[] = { arg0, arg1, options.data () };
	fuse_args args = { 3, argv, 0 };
	wchar_t drive[3] = { letter, L':', 0 };
	wchar_t target[512];
	mount->finished = CreateEventW (nullptr, TRUE, FALSE, nullptr);
	if (!mount->finished)
		goto fail;
	mount->channel = p_mount (&g_env, mount->mountpoint.c_str (), &args);
	if (!mount->channel)
	{
		p_free_args (&g_env, &args);
		goto fail;
	}
	mount->instance = p_new (&g_env, mount->channel, &args, &g_ops,
		sizeof (g_ops), fs);
	p_free_args (&g_env, &args);
	if (!mount->instance)
		goto fail;

	mount->worker = std::thread ([mount]
	{
		p_loop_mt (&g_env, mount->instance);
		SetEvent (mount->finished);
		if (mount->published.load (std::memory_order_acquire))
			PostMessageW (g_notify, g_gone_message, 0,
				(LPARAM) mount->notify_context);
	});

	/* Preflight has succeeded.  Wait briefly for the dispatcher to publish
	   the DOS device so Explorer is never launched against a missing drive. */
	for (int i = 0; i < 300; i++)
	{
		if (QueryDosDeviceW (drive, target, (DWORD) std::size (target)))
			break;
		if (WaitForSingleObject (mount->finished, 10) == WAIT_OBJECT_0)
			goto fail_thread;
	}
	if (!QueryDosDeviceW (drive, target, (DWORD) std::size (target)))
		goto fail_thread;

	mount->published.store (true, std::memory_order_release);
	if (WaitForSingleObject (mount->finished, 0) == WAIT_OBJECT_0)
	{
		mount->published.store (false, std::memory_order_release);
		goto fail_thread;
	}
	if (open_explorer)
		PostMessageW (g_notify, g_mounted_message, 0, (LPARAM) notify_context);
	return mount;

fail_thread:
	p_exit (&g_env, mount->instance);
	if (mount->worker.joinable ())
		mount->worker.join ();
fail:
	if (mount->instance)
		p_destroy (&g_env, mount->instance);
	if (mount->channel)
		p_unmount (&g_env, mount->mountpoint.c_str (), mount->channel);
	if (mount->finished)
		CloseHandle (mount->finished);
	delete mount;
	*error = L"WinFsp mount failed";
	return nullptr;
}

void
winfspfs_unmount (winfsp_mount *mount)
{
	mount->published.store (false, std::memory_order_release);
	p_exit (&g_env, mount->instance);
	if (mount->worker.joinable ())
		mount->worker.join ();
	p_destroy (&g_env, mount->instance);
	p_unmount (&g_env, mount->mountpoint.c_str (), mount->channel);
	CloseHandle (mount->finished);
	delete mount;
}
