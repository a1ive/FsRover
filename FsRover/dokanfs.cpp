/*
 *  Rover -- GRUB 2 filesystem browser for Windows
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
 * Drive-mount manager and Dokan adapter.
 * Filesystem semantics live in the FUSE-shaped fusefs core.
 */

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winsvc.h>

#include <stdio.h>
#include <wchar.h>
#include <errno.h>

#include <atomic>
#include <string>
#include <vector>

#include "dokan/dokan.h"

#include <rover.h>

#include "backend.h"
#include "dokanfs.h"
#include "../common/fusefs.h"
#include "gui.h"
#include "resource.h"
#include "strconv.h"
#include "winfspfs.h"

/* Service control for the in-app Install Dokan feature.  */
#pragma comment (lib, "advapi32.lib")

namespace
{

typedef VOID (__stdcall *fn_DokanInit) (void);
typedef VOID (__stdcall *fn_DokanShutdown) (void);
typedef int (__stdcall *fn_DokanCreateFileSystem) (PDOKAN_OPTIONS, PDOKAN_OPERATIONS, PDOKAN_HANDLE);
typedef VOID (__stdcall *fn_DokanCloseHandle) (DOKAN_HANDLE);
typedef ULONG (__stdcall *fn_DokanDriverVersion) (void);

HMODULE g_dll;
fn_DokanInit p_DokanInit;
fn_DokanShutdown p_DokanShutdown;
fn_DokanCreateFileSystem p_DokanCreateFileSystem;
fn_DokanCloseHandle p_DokanCloseHandle;
fn_DokanDriverVersion p_DokanDriverVersion;

bool g_dokan_ok;
dokanfs_backend g_backend = dokanfs_backend::winfsp;
HWND g_notify;
std::vector<dokan_mount *> g_table;	/* GUI thread only */
std::atomic<DWORD> g_mount_mask { 0 };	/* drive letters, read by backend */

} // namespace

struct dokan_mount
{
	fusefs core;
	std::wstring mountpoint;	/* L"Z:\\" */
	bool open_explorer;	/* post WM_APP_DOKAN_MOUNTED when live */
	bool winfsp;
	winfsp_mount *winfsp_handle;
	DOKAN_HANDLE handle;
	DOKAN_OPTIONS opts;	/* must outlive the mount */
};

namespace
{

dokan_mount *
mount_of (PDOKAN_FILE_INFO info)
{
	return (dokan_mount *) (UINT_PTR) info->DokanOptions->GlobalContext;
}

/* "\dir\file" (UTF-16) -> FUSE path "/dir/file" (UTF-8). */
std::string
fuse_path (LPCWSTR name)
{
	std::string p = narrow (name);

	for (char &c : p)
		if (c == '\\')
			c = '/';
	return p;
}

FILETIME
unix_to_filetime (long long t)
{
	FILETIME ft = {};

	if (t > 0)
	{
		ULONGLONG v = (ULONGLONG) t * 10000000ULL + 116444736000000000ULL;
		ft.dwLowDateTime = (DWORD) v;
		ft.dwHighDateTime = (DWORD) (v >> 32);
	}
	return ft;
}

NTSTATUS DOKAN_CALLBACK
fs_create (LPCWSTR name, PDOKAN_IO_SECURITY_CONTEXT, ACCESS_MASK, ULONG, ULONG,
	ULONG disposition, ULONG options, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);

	if (disposition != FILE_OPEN && disposition != FILE_OPEN_IF)
		return STATUS_MEDIA_WRITE_PROTECTED;

	std::string path = fuse_path (name);
	fusefs_stat st = {};
	int err = fusefs_getattr (&m->core, path.c_str (), &st);
	if (err)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	if ((st.mode & 0170000) == 0040000)
	{
		if (options & FILE_NON_DIRECTORY_FILE)
			return STATUS_FILE_IS_A_DIRECTORY;
		info->IsDirectory = TRUE;
	}
	else if (info->IsDirectory || (options & FILE_DIRECTORY_FILE))
		return STATUS_NOT_A_DIRECTORY;

	info->Context = 0;
	return STATUS_SUCCESS;
}

void DOKAN_CALLBACK
fs_cleanup (LPCWSTR, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	uint64_t handle = info->Context;
	fusefs_release (&m->core, &handle);
	info->Context = handle;
}

void DOKAN_CALLBACK
fs_close (LPCWSTR name, PDOKAN_FILE_INFO info)
{
	fs_cleanup (name, info);
}

NTSTATUS DOKAN_CALLBACK
fs_read (LPCWSTR name, LPVOID buf, DWORD len, LPDWORD got, LONGLONG off, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	std::string path = fuse_path (name);
	uint64_t handle = info->Context;
	int rc = fusefs_read (&m->core, path.c_str (), buf, len, off, &handle);
	info->Context = handle;
	if (rc == -ENOENT)
		return STATUS_OBJECT_NAME_NOT_FOUND;
	if (rc < 0)
		return STATUS_UNSUCCESSFUL;
	*got = (DWORD) rc;
	return rc == 0 && len && off >= 0 ? STATUS_END_OF_FILE : STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_getinfo (LPCWSTR name, LPBY_HANDLE_FILE_INFORMATION out, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	std::string path = fuse_path (name);
	fusefs_stat st = {};
	if (fusefs_getattr (&m->core, path.c_str (), &st))
		return STATUS_OBJECT_NAME_NOT_FOUND;

	ZeroMemory (out, sizeof (*out));
	out->dwFileAttributes = FILE_ATTRIBUTE_READONLY;
	if ((st.mode & 0170000) == 0040000)
		out->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
	FILETIME ft = unix_to_filetime (st.mtime);
	out->ftCreationTime = ft;
	out->ftLastAccessTime = ft;
	out->ftLastWriteTime = ft;
	if ((st.mode & 0170000) != 0040000)
	{
		out->nFileSizeHigh = (DWORD) (st.size >> 32);
		out->nFileSizeLow = (DWORD) st.size;
	}
	out->dwVolumeSerialNumber = m->core.serial;
	out->nNumberOfLinks = 1;
	return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_findfiles (LPCWSTR name, PFillFindData fill, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	std::string path = fuse_path (name);
	struct fill_context
	{
		PFillFindData fill;
		PDOKAN_FILE_INFO info;
	} context = { fill, info };
	int rc = fusefs_readdir (&m->core, path.c_str (),
		[] (void *opaque, const char *entry_name, const fusefs_stat *st) -> int
		{
			if (!strcmp (entry_name, ".") || !strcmp (entry_name, ".."))
				return 0;
			auto *context = (fill_context *) opaque;
			WIN32_FIND_DATAW fd = {};
			fd.dwFileAttributes = FILE_ATTRIBUTE_READONLY;
			if ((st->mode & 0170000) == 0040000)
				fd.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
			FILETIME ft = unix_to_filetime (st->mtime);
			fd.ftCreationTime = ft;
			fd.ftLastAccessTime = ft;
			fd.ftLastWriteTime = ft;
			fd.nFileSizeHigh = (DWORD) (st->size >> 32);
			fd.nFileSizeLow = (DWORD) st->size;
			wcsncpy_s (fd.cFileName, widen (entry_name).c_str (), _TRUNCATE);
			return context->fill (&fd, context->info);
		}, &context);
	return rc ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_freespace (PULONGLONG avail, PULONGLONG total, PULONGLONG free_total, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	fusefs_statvfs st = {};
	fusefs_statfs (&m->core, &st);
	*avail = 0;
	*total = st.blocks * st.block_size;
	*free_total = 0;
	return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_volinfo (LPWSTR vol_name, DWORD vol_size, LPDWORD serial,
	LPDWORD max_component, LPDWORD flags, LPWSTR fs_name, DWORD fs_size, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);

	wcsncpy_s (vol_name, vol_size, widen (m->core.device).c_str (), _TRUNCATE);
	*serial = m->core.serial;
	*max_component = 255;
	*flags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_READ_ONLY_VOLUME;
	wcsncpy_s (fs_name, fs_size, widen (m->core.fs_name).c_str (), _TRUNCATE);
	return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_mounted (LPCWSTR, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);

	if (m->open_explorer)
		PostMessageW (g_notify, WM_APP_DOKAN_MOUNTED, 0, (LPARAM) m);
	return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_unmounted (PDOKAN_FILE_INFO info)
{
	PostMessageW (g_notify, WM_APP_DOKAN_GONE, 0, (LPARAM) mount_of (info));
	return STATUS_SUCCESS;
}

/* Write-side callbacks stay null: DOKAN_OPTION_WRITE_PROTECT makes
   the volume read-only at the driver level.  */
DOKAN_OPERATIONS g_ops =
{
	.ZwCreateFile = fs_create,
	.Cleanup = fs_cleanup,
	.CloseFile = fs_close,
	.ReadFile = fs_read,
	.GetFileInformation = fs_getinfo,
	.FindFiles = fs_findfiles,
	.GetDiskFreeSpace = fs_freespace,
	.GetVolumeInformation = fs_volinfo,
	.Mounted = fs_mounted,
	.Unmounted = fs_unmounted,
};

DWORD
drive_mask (wchar_t letter)
{
	if (letter >= L'a' && letter <= L'z')
		letter -= L'a' - L'A';
	return letter >= L'A' && letter <= L'Z'
		? 1u << (letter - L'A') : 0;
}

/* Load dokan2.dll, resolve the entry points and confirm the driver is
   live; on any failure the library is unloaded again.  Shared by
   dokanfs_init() (startup probe) and dokanfs_install() (re-probe once
   the driver has been installed).  */
bool
dokan_load (void)
{
	/* The driver only accepts an elevated caller.  */
	if (!is_elevated ())
		return false;

	wchar_t sysdir[MAX_PATH];
	UINT n = GetSystemDirectoryW (sysdir, ARRAYSIZE (sysdir));
	if (n == 0 || n >= ARRAYSIZE (sysdir))
		return false;
	std::wstring dll_path = sysdir;
	dll_path += L"\\dokan2.dll";

	g_dll = LoadLibraryW (dll_path.c_str ());
	if (!g_dll)
		return false;

	p_DokanInit = (fn_DokanInit)
		GetProcAddress (g_dll, "DokanInit");
	p_DokanShutdown = (fn_DokanShutdown)
		GetProcAddress (g_dll, "DokanShutdown");
	p_DokanCreateFileSystem = (fn_DokanCreateFileSystem)
		GetProcAddress (g_dll, "DokanCreateFileSystem");
	p_DokanCloseHandle = (fn_DokanCloseHandle)
		GetProcAddress (g_dll, "DokanCloseHandle");
	p_DokanDriverVersion = (fn_DokanDriverVersion)
		GetProcAddress (g_dll, "DokanDriverVersion");
	if (!p_DokanInit || !p_DokanShutdown || !p_DokanCreateFileSystem || !p_DokanCloseHandle || !p_DokanDriverVersion)
		goto fail;

	p_DokanInit ();
	if (p_DokanDriverVersion () == 0)
	{
		p_DokanShutdown ();
		goto fail;
	}
	g_dokan_ok = true;
	return true;

fail:
	FreeLibrary (g_dll);
	g_dll = nullptr;
	return false;
}

/* Write an embedded RT_RCDATA resource verbatim to PATH (overwriting).  */
bool
write_resource (int id, const wchar_t *path, std::wstring *error)
{
	HRSRC res = FindResourceW (nullptr, MAKEINTRESOURCEW (id), RT_RCDATA);
	HGLOBAL blob = res ? LoadResource (nullptr, res) : nullptr;
	const void *data = blob ? LockResource (blob) : nullptr;
	DWORD size = res ? SizeofResource (nullptr, res) : 0;

	if (!data || !size)
	{
		*error = L"a bundled Dokan resource is missing";
		return false;
	}
	HANDLE f = CreateFileW (path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (f == INVALID_HANDLE_VALUE)
	{
		*error = L"cannot write " + std::wstring (path);
		return false;
	}
	DWORD wrote = 0;
	bool ok = WriteFile (f, data, size, &wrote, nullptr) && wrote == size;
	CloseHandle (f);
	if (!ok)
	{
		*error = L"cannot write " + std::wstring (path);
		return false;
	}
	return true;
}

/* Create (or reuse) the Dokan2 file-system driver service pointing at
   SYS_PATH and start it.  */
bool
install_service (const wchar_t *sys_path, std::wstring *error)
{
	SC_HANDLE scm = OpenSCManagerW (nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (!scm)
	{
		*error = L"cannot open the service control manager";
		return false;
	}
	SC_HANDLE svc = CreateServiceW (scm, L"Dokan2", L"Dokan2",
					SERVICE_ALL_ACCESS,
					SERVICE_FILE_SYSTEM_DRIVER,
					SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
					sys_path, nullptr, nullptr, nullptr,
					nullptr, nullptr);
	if (!svc && GetLastError () == ERROR_SERVICE_EXISTS)
		svc = OpenServiceW (scm, L"Dokan2", SERVICE_ALL_ACCESS);
	if (!svc)
	{
		CloseServiceHandle (scm);
		*error = L"cannot create the Dokan driver service";
		return false;
	}

	bool ok = StartServiceW (svc, 0, nullptr) || GetLastError () == ERROR_SERVICE_ALREADY_RUNNING;
	CloseServiceHandle (svc);
	CloseServiceHandle (scm);
	if (!ok)
	{
		*error = L"the Dokan driver failed to start";
		return false;
	}
	return true;
}

} // namespace

bool
dokanfs_init (HWND notify)
{
	g_notify = notify;
	bool winfsp = winfspfs_init (notify, WM_APP_DOKAN_GONE,
		WM_APP_DOKAN_MOUNTED);
	dokan_load ();
	g_backend = winfsp ? dokanfs_backend::winfsp : dokanfs_backend::dokan;
	return winfsp || g_dokan_ok;
}

bool
dokanfs_available (void)
{
	return winfspfs_available () || g_dokan_ok;
}

const wchar_t *
dokanfs_backend_name (void)
{
	return g_backend == dokanfs_backend::winfsp ? L"WinFsp" : L"Dokan";
}

bool
dokanfs_backend_available (dokanfs_backend backend)
{
	return backend == dokanfs_backend::winfsp
		? winfspfs_available () : g_dokan_ok;
}

dokanfs_backend
dokanfs_current_backend (void)
{
	return g_backend;
}

bool
dokanfs_select_backend (dokanfs_backend backend)
{
	if (!dokanfs_backend_available (backend))
		return false;
	g_backend = backend;
	return true;
}

bool
dokanfs_install (std::wstring *error)
{
	if (g_dokan_ok)
		return true;

	/* The bundled runtime matches this executable's architecture, so a
	   WoW64 process would install a driver the kernel cannot load --
	   and its System32 writes would land in SysWOW64 to begin with.
	   The menu does not offer the install there; refuse it outright
	   too, rather than leaving stray files behind.  */
	if (is_wow64 ())
	{
		*error = res_str (IDS_DOKAN_WOW64);
		return false;
	}

	wchar_t sysdir[MAX_PATH];
	UINT n = GetSystemDirectoryW (sysdir, MAX_PATH);
	if (n == 0 || n >= MAX_PATH)
	{
		*error = L"cannot locate the system directory";
		return false;
	}
	std::wstring base = sysdir;	/* ...\System32 */
	std::wstring dll_path = base + L"\\dokan2.dll";
	std::wstring sys_path = base + L"\\drivers\\dokan2.sys";

	/* The official Dokan release driver carries an embedded Microsoft
	   kernel signature, so install it like dokanctl: copy the runtime,
	   create the file-system service and start it.  */
	bool ok = write_resource (IDR_DOKAN_SYS, sys_path.c_str (), error)
		&& write_resource (IDR_DOKAN_DLL, dll_path.c_str (), error)
		&& install_service (sys_path.c_str (), error);
	if (!ok)
		return false;

	if (!dokan_load ())
	{
		*error = L"Dokan was installed but its driver did not respond";
		return false;
	}
	if (!winfspfs_available ())
		g_backend = dokanfs_backend::dokan;
	return true;
}

void
dokanfs_shutdown (void)
{
	dokanfs_unmount_all ();
	winfspfs_shutdown ();
	if (g_dokan_ok)
	{
		p_DokanShutdown ();
		FreeLibrary (g_dll);
		g_dll = nullptr;
		g_dokan_ok = false;
	}
}

dokan_mount *
dokanfs_mount (const std::string &device, const std::string &fs,
	unsigned long long size, wchar_t letter, bool open_explorer, std::wstring *error)
{
	if (!dokanfs_backend_available (g_backend))
	{
		*error = std::wstring (dokanfs_backend_name ()) + L" is not available";
		return nullptr;
	}

	dokan_mount *m = new dokan_mount;
	fusefs_init (&m->core, device, fs, size,
		[] (const std::function<void ()> &fn) { return backend_call (fn); });
	m->mountpoint = std::wstring (1, letter) + L":\\";
	m->open_explorer = open_explorer;
	m->winfsp = false;
	m->winfsp_handle = nullptr;
	m->handle = nullptr;

	/* The selected backend is authoritative: do not silently retry the other
	   host, so backend-specific tests have deterministic results. */
	if (g_backend == dokanfs_backend::winfsp)
	{
		m->winfsp_handle = winfspfs_mount (&m->core, letter,
			open_explorer, m, error);
		if (m->winfsp_handle)
			m->winfsp = true;
		else
		{
			delete m;
			return nullptr;
		}
	}

	if (!m->winfsp)
	{
		ZeroMemory (&m->opts, sizeof (m->opts));
		m->opts.Version = DOKAN_VERSION;
		m->opts.Options = DOKAN_OPTION_WRITE_PROTECT;
		m->opts.GlobalContext = (ULONG64) (UINT_PTR) m;
		m->opts.MountPoint = m->mountpoint.c_str ();
		m->opts.SectorSize = 512;
		m->opts.AllocationUnitSize = 512;

		int rc = p_DokanCreateFileSystem (&m->opts, &g_ops, &m->handle);
		if (rc != DOKAN_SUCCESS)
		{
			wchar_t buf[64];
			swprintf (buf, 64, L"dokan mount failed (%d)", rc);
			*error = buf;
			delete m;
			return nullptr;
		}
	}
	g_mount_mask.fetch_or (drive_mask (letter), std::memory_order_relaxed);
	g_table.push_back (m);
	return m;
}

void
dokanfs_unmount (dokan_mount *m)
{
	if (m->winfsp)
		winfspfs_unmount (m->winfsp_handle);
	else
		p_DokanCloseHandle (m->handle);
	g_mount_mask.fetch_and (~drive_mask (m->mountpoint[0]),
		std::memory_order_relaxed);
	for (size_t i = 0; i < g_table.size (); i++)
		if (g_table[i] == m)
		{
			g_table.erase (g_table.begin () + (ptrdiff_t) i);
			break;
		}
	delete m;
}

void
dokanfs_unmount_all (void)
{
	while (!g_table.empty ())
		dokanfs_unmount (g_table.back ());
}

size_t
dokanfs_count (void)
{
	return g_table.size ();
}

dokan_mount *
dokanfs_get (size_t i)
{
	return i < g_table.size () ? g_table[i] : nullptr;
}

dokan_mount *
dokanfs_find_device (const std::string &device)
{
	for (dokan_mount *m : g_table)
		if (m->core.device == device)
			return m;
	return nullptr;
}

dokan_mount *
dokanfs_find_ptr (void *raw)
{
	for (dokan_mount *m : g_table)
		if (m == raw)
			return m;
	return nullptr;
}

bool
dokanfs_owns_path (const std::wstring &path)
{
	/* GetFullPathName does no filesystem I/O; besides ordinary relative
	   paths, keep the explicit Win32 device spellings recognizable.  */
	DWORD len = GetFullPathNameW (path.c_str (), 0, nullptr, nullptr);
	std::wstring full = path;
	if (len)
	{
		full.resize (len);
		DWORD got = GetFullPathNameW (path.c_str (), len, full.data (), nullptr);
		if (got && got < len)
			full.resize (got);
		else
			full = path;
	}

	size_t pos = 0;
	if (full.size () >= 4 && full[0] == L'\\' && full[1] == L'\\'
		&& (full[2] == L'?' || full[2] == L'.') && full[3] == L'\\')
		pos = 4;
	if (full.size () < pos + 2 || full[pos + 1] != L':')
		return false;
	DWORD mask = drive_mask (full[pos]);
	return mask && (g_mount_mask.load (std::memory_order_relaxed) & mask);
}

const std::string &
dokanfs_device (const dokan_mount *m)
{
	return m->core.device;
}

std::wstring
dokanfs_letter (const dokan_mount *m)
{
	return m->mountpoint.substr (0, 2);
}
