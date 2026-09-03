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
 * Drive-letter mounts of grub devices.
 * All functions are GUI-thread only; the filesystem callbacks marshal
 * their rover calls onto the backend thread via backend_call().
 */

#ifndef FSROVER_DOKANFS_H
#define FSROVER_DOKANFS_H	1

#include "build_config.h"

#include <windows.h>

#include <string>

/* dokan -> GUI: a mount disappeared behind our back (driver-side
   unmount).  lParam = dokan_mount*; validate with dokanfs_find_ptr()
   and finish with dokanfs_unmount().  */
constexpr UINT WM_APP_DOKAN_GONE = WM_APP + 4;

/* dokan -> GUI: a mount with the open-Explorer option went live
   (WM_APP + 5 is the tray message in main.cpp).  lParam = dokan_mount*;
   validate with dokanfs_find_ptr() and open the drive.  */
constexpr UINT WM_APP_DOKAN_MOUNTED = WM_APP + 6;

struct dokan_mount;

enum class dokanfs_backend
{
	winfsp,
	dokan,
};

/* Probe WinFsp first, then Dokan; false = feature disabled.
   NOTIFY receives WM_APP_DOKAN_GONE.  */
bool dokanfs_init (HWND notify);

/* True when the library and driver are usable.  */
bool dokanfs_available (void);

/* Name of the backend selected for new mounts. */
const wchar_t *dokanfs_backend_name (void);

/* Backend selection is process-local.  Startup prefers WinFsp, then Dokan;
   selecting an unavailable backend fails without changing the selection. */
bool dokanfs_backend_available (dokanfs_backend backend);
dokanfs_backend dokanfs_current_backend (void);
bool dokanfs_select_backend (dokanfs_backend backend);

#if FSROVER_EMBED_DOKAN
/* Install the app-embedded Dokan runtime (library + kernel driver) to
   the system, start the driver service and
   re-probe.  On success dokanfs_available() becomes true and true is
   returned; otherwise false with *ERROR set.  Writing System32 and
   creating a kernel service needs an elevated token: the app runs
   asInvoker, so the GUI only offers this while is_elevated().  */
bool dokanfs_install (std::wstring *error);
#endif

/* Unmount everything and unload the library.  */
void dokanfs_shutdown (void);

/* Mount DEVICE ("hd0,gpt2") read-only on drive letter LETTER (e.g.
   L'Z').  FS/SIZE feed the volume information; when OPEN_EXPLORER is
   set, WM_APP_DOKAN_MOUNTED is posted once the volume is live.
   Returns NULL and sets ERROR on failure.  */
dokan_mount *dokanfs_mount (const std::string &device,
	const std::string &fs,
	unsigned long long size, wchar_t letter,
	bool open_explorer, std::wstring *error);

/* Blocks until the filesystem is closed, then frees the mount.  */
void dokanfs_unmount (dokan_mount *m);

void dokanfs_unmount_all (void);

size_t dokanfs_count (void);
dokan_mount *dokanfs_get (size_t i);
dokan_mount *dokanfs_find_device (const std::string &device);
dokan_mount *dokanfs_find_ptr (void *raw);

/* True when PATH resolves syntactically to one of our mounted drive letters.
   Thread-safe: the backend uses this before starting Windows file I/O.  */
bool dokanfs_owns_path (const std::wstring &path);

const std::string &dokanfs_device (const dokan_mount *m);
/* Drive letter for display, e.g. L"Z:".  */
std::wstring dokanfs_letter (const dokan_mount *m);

#endif /* ! FSROVER_DOKANFS_H */
