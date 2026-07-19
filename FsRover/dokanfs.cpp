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
 * Read-only dokan filesystem over the rover API (see dokanfs.h).
 * Callbacks arrive on dokan worker threads; every rover call is
 * wrapped in backend_call() so grub still runs on one thread only.
 */

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winsvc.h>
#include <wintrust.h>
#include <mscat.h>

#include <stdio.h>
#include <wchar.h>

#include <string>
#include <vector>

#include "dokan/dokan.h"

#include <rover.h>

#include "backend.h"
#include "dokanfs.h"
#include "resource.h"
#include "strconv.h"

/* Service control (Dokan2 driver service) and driver-catalog
   registration (dokan2.cat) for the in-app Install Dokan feature.  */
#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "wintrust.lib")

namespace
{

typedef VOID (__stdcall *fn_DokanInit) (void);
typedef VOID (__stdcall *fn_DokanShutdown) (void);
typedef int (__stdcall *fn_DokanCreateFileSystem) (PDOKAN_OPTIONS,
						   PDOKAN_OPERATIONS,
						   PDOKAN_HANDLE);
typedef VOID (__stdcall *fn_DokanCloseHandle) (DOKAN_HANDLE);
typedef ULONG (__stdcall *fn_DokanDriverVersion) (void);

HMODULE g_dll;
fn_DokanInit p_DokanInit;
fn_DokanShutdown p_DokanShutdown;
fn_DokanCreateFileSystem p_DokanCreateFileSystem;
fn_DokanCloseHandle p_DokanCloseHandle;
fn_DokanDriverVersion p_DokanDriverVersion;

bool g_ok;
HWND g_notify;
std::vector<dokan_mount *> g_table;	/* GUI thread only */

} // namespace

struct dokan_mount
{
	std::string device;	/* grub device, no parens */
	std::string root;	/* "(device)" */
	std::wstring fs_name;
	std::wstring mountpoint;	/* L"Z:\\" */
	unsigned long long size;
	DWORD serial;
	bool open_explorer;	/* post WM_APP_DOKAN_MOUNTED when live */
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

/* "\dir\file" (UTF-16) -> "(device)/dir/file" (UTF-8).  */
std::string
grub_path (dokan_mount *m, LPCWSTR name)
{
	std::string p = narrow (name);

	for (char &c : p)
		if (c == '\\')
			c = '/';
	return m->root + p;
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
fs_create (LPCWSTR name, PDOKAN_IO_SECURITY_CONTEXT,
	   ACCESS_MASK, ULONG, ULONG, ULONG disposition, ULONG options,
	   PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);

	if (disposition != FILE_OPEN && disposition != FILE_OPEN_IF)
		return STATUS_MEDIA_WRITE_PROTECTED;

	std::string path = grub_path (m, name);
	rover_stat_t st = {};
	int err = 0;
	backend_call ([&] { err = rover_stat (path.c_str (), &st); });
	if (err)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	if (st.is_dir)
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
	rover_file *f = (rover_file *) (UINT_PTR) info->Context;

	if (!f)
		return;
	info->Context = 0;
	backend_call ([&] { rover_file_close (f); });
}

void DOKAN_CALLBACK
fs_close (LPCWSTR name, PDOKAN_FILE_INFO info)
{
	fs_cleanup (name, info);
}

NTSTATUS DOKAN_CALLBACK
fs_read (LPCWSTR name, LPVOID buf, DWORD len, LPDWORD got,
	 LONGLONG off, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	std::string path = grub_path (m, name);
	NTSTATUS ret = STATUS_SUCCESS;

	*got = 0;
	backend_call ([&]
	{
		/* Lazily opened on first read, reused afterwards; both
		   Context accesses run on the backend thread, so
		   concurrent reads on one handle stay race-free.  */
		rover_file *f = (rover_file *) (UINT_PTR) info->Context;
		if (!f)
		{
			f = rover_file_open (path.c_str ());
			if (!f)
			{
				ret = STATUS_OBJECT_NAME_NOT_FOUND;
				return;
			}
			info->Context = (ULONG64) (UINT_PTR) f;
		}

		unsigned long long size = rover_file_size (f);
		if ((unsigned long long) off >= size)
		{
			ret = STATUS_END_OF_FILE;
			return;
		}
		unsigned long long want = len;
		if (want > size - (unsigned long long) off)
			want = size - (unsigned long long) off;
		if (rover_file_seek (f, (unsigned long long) off))
		{
			ret = STATUS_UNSUCCESSFUL;
			return;
		}
		long long r = rover_file_read (f, buf, want);
		if (r < 0)
			ret = STATUS_UNSUCCESSFUL;
		else
			*got = (DWORD) r;
	});
	return ret;
}

NTSTATUS DOKAN_CALLBACK
fs_getinfo (LPCWSTR name, LPBY_HANDLE_FILE_INFORMATION out,
	    PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	std::string path = grub_path (m, name);
	rover_stat_t st = {};
	int err = 0;

	backend_call ([&] { err = rover_stat (path.c_str (), &st); });
	if (err)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	ZeroMemory (out, sizeof (*out));
	out->dwFileAttributes = FILE_ATTRIBUTE_READONLY;
	if (st.is_dir)
		out->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
	FILETIME ft = unix_to_filetime (st.mtime_set ? st.mtime : 0);
	out->ftCreationTime = ft;
	out->ftLastAccessTime = ft;
	out->ftLastWriteTime = ft;
	if (!st.is_dir && st.size != ROVER_SIZE_UNKNOWN)
	{
		out->nFileSizeHigh = (DWORD) (st.size >> 32);
		out->nFileSizeLow = (DWORD) st.size;
	}
	out->dwVolumeSerialNumber = m->serial;
	out->nNumberOfLinks = 1;
	return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_findfiles (LPCWSTR name, PFillFindData fill, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	std::string path = grub_path (m, name);
	struct entry
	{
		std::string name;
		bool is_dir;
		unsigned long long size;
		long long mtime;
	};
	std::vector<entry> entries;
	int err = 0;

	backend_call ([&]
	{
		err = rover_dir_list (path.c_str (),
			[] (const struct rover_dirent *ent, void *data) -> int
			{
				auto *out = (std::vector<entry> *) data;
				entry e;
				e.name = ent->name;
				e.is_dir = ent->is_dir != 0;
				e.size = 0;
				e.mtime = ent->mtime_set ? ent->mtime : 0;
				out->push_back (std::move (e));
				return 0;
			}, &entries);
		if (err)
			return;
		std::string prefix = path;
		if (prefix.empty () || prefix.back () != '/')
			prefix += '/';
		for (entry &e : entries)
		{
			if (e.is_dir)
				continue;
			rover_file *f =
				rover_file_open ((prefix + e.name).c_str ());
			if (f)
			{
				e.size = rover_file_size (f);
				rover_file_close (f);
			}
		}
	});
	if (err)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	for (const entry &e : entries)
	{
		WIN32_FIND_DATAW fd = {};
		fd.dwFileAttributes = FILE_ATTRIBUTE_READONLY;
		if (e.is_dir)
			fd.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
		FILETIME ft = unix_to_filetime (e.mtime);
		fd.ftCreationTime = ft;
		fd.ftLastAccessTime = ft;
		fd.ftLastWriteTime = ft;
		if (!e.is_dir && e.size != ROVER_SIZE_UNKNOWN)
		{
			fd.nFileSizeHigh = (DWORD) (e.size >> 32);
			fd.nFileSizeLow = (DWORD) e.size;
		}
		wcsncpy_s (fd.cFileName, widen (e.name).c_str (), _TRUNCATE);
		fill (&fd, info);
	}
	return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_freespace (PULONGLONG avail, PULONGLONG total, PULONGLONG free_total,
	      PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);
	unsigned long long size = m->size;

	if (size == ~0ULL)
		size = 0;
	*avail = 0;
	*total = size;
	*free_total = 0;
	return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
fs_volinfo (LPWSTR vol_name, DWORD vol_size, LPDWORD serial,
	    LPDWORD max_component, LPDWORD flags,
	    LPWSTR fs_name, DWORD fs_size, PDOKAN_FILE_INFO info)
{
	dokan_mount *m = mount_of (info);

	wcsncpy_s (vol_name, vol_size, widen (m->device).c_str (), _TRUNCATE);
	*serial = m->serial;
	*max_component = 255;
	*flags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES
		 | FILE_UNICODE_ON_DISK | FILE_READ_ONLY_VOLUME;
	wcsncpy_s (fs_name, fs_size, m->fs_name.c_str (), _TRUNCATE);
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
device_serial (const std::string &device)
{
	DWORD h = 2166136261u;

	for (char c : device)
		h = (h ^ (unsigned char) c) * 16777619u;
	return h ? h : 1;
}

/* Load dokan2.dll, resolve the entry points and confirm the driver is
   live; on any failure the library is unloaded again.  Shared by
   dokanfs_init() (startup probe) and dokanfs_install() (re-probe once
   the driver has been installed).  */
bool
dokan_load (void)
{
	g_dll = LoadLibraryW (L"dokan2.dll");
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
	if (!p_DokanInit || !p_DokanShutdown || !p_DokanCreateFileSystem
		|| !p_DokanCloseHandle || !p_DokanDriverVersion)
		goto fail;

	p_DokanInit ();
	if (p_DokanDriverVersion () == 0)
	{
		p_DokanShutdown ();
		goto fail;
	}
	g_ok = true;
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

/* Register dokan2.cat in the driver catalog store so the catalog-signed
   dokan2.sys passes kernel signature enforcement.  Without this the
   driver would fail to load on a machine that never had Dokan.  */
bool
register_catalog (const wchar_t *cat_path, std::wstring *error)
{
	/* DRIVER_ACTION_VERIFY -- the driver catalog subsystem, spelled
	   out to avoid pulling <softpub.h>.  */
	static const GUID driver_verify =
		{ 0xf750e6c3, 0x38ee, 0x11d1,
		  { 0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };
	HCATADMIN admin = nullptr;
	HCATINFO info;

	if (!CryptCATAdminAcquireContext (&admin, &driver_verify, 0))
	{
		*error = L"cannot open the driver catalog store";
		return false;
	}
	info = CryptCATAdminAddCatalog (admin, (PWSTR) cat_path, (PWSTR) L"dokan2.cat", 0);
	if (info)
		CryptCATAdminReleaseCatalogContext (admin, info, 0);
	CryptCATAdminReleaseContext (admin, 0);
	if (!info)
	{
		*error = L"cannot register the Dokan driver catalog";
		return false;
	}
	return true;
}

/* Create (or reuse) the Dokan2 file-system driver service pointing at
   SYS_PATH and start it.  */
bool
install_service (const wchar_t *sys_path, std::wstring *error)
{
	SC_HANDLE scm = OpenSCManagerW (nullptr, nullptr,
					SC_MANAGER_CONNECT
					| SC_MANAGER_CREATE_SERVICE);
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
	return dokan_load ();
}

bool
dokanfs_available (void)
{
	return g_ok;
}

bool
dokanfs_install (std::wstring *error)
{
	if (g_ok)
		return true;

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

	wchar_t tmpdir[MAX_PATH];
	n = GetTempPathW (MAX_PATH, tmpdir);
	if (n == 0 || n >= MAX_PATH)
	{
		*error = L"cannot locate the temporary directory";
		return false;
	}
	std::wstring cat_path = std::wstring (tmpdir) + L"dokan2.cat";

	/* Driver + catalog first, then the library; the catalog must be
	   registered before the service starts (which triggers the kernel
	   signature check).  The catalog file is only needed during
	   registration, so it goes to a scratch path and is removed after.  */
	bool ok = write_resource (IDR_DOKAN_SYS, sys_path.c_str (), error)
		&& write_resource (IDR_DOKAN_DLL, dll_path.c_str (), error)
		&& write_resource (IDR_DOKAN_CAT, cat_path.c_str (), error)
		&& register_catalog (cat_path.c_str (), error)
		&& install_service (sys_path.c_str (), error);
	DeleteFileW (cat_path.c_str ());
	if (!ok)
		return false;

	if (!dokan_load ())
	{
		*error = L"Dokan was installed but its driver did not respond";
		return false;
	}
	return true;
}

void
dokanfs_shutdown (void)
{
	if (!g_ok)
		return;
	dokanfs_unmount_all ();
	p_DokanShutdown ();
	FreeLibrary (g_dll);
	g_dll = nullptr;
	g_ok = false;
}

dokan_mount *
dokanfs_mount (const std::string &device, const std::string &fs,
	unsigned long long size, wchar_t letter, bool open_explorer, std::wstring *error)
{
	if (!g_ok)
	{
		*error = L"dokan is not available";
		return nullptr;
	}

	dokan_mount *m = new dokan_mount;
	m->device = device;
	m->root = "(" + device + ")";
	m->fs_name = widen (fs);
	m->mountpoint = std::wstring (1, letter) + L":\\";
	m->size = size;
	m->serial = device_serial (device);
	m->open_explorer = open_explorer;
	m->handle = nullptr;
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
	g_table.push_back (m);
	return m;
}

void
dokanfs_unmount (dokan_mount *m)
{
	p_DokanCloseHandle (m->handle);
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
		if (m->device == device)
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

const std::string &
dokanfs_device (const dokan_mount *m)
{
	return m->device;
}

std::wstring
dokanfs_letter (const dokan_mount *m)
{
	return m->mountpoint.substr (0, 2);
}
