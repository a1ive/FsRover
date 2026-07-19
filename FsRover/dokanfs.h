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
 * Dokan drive-letter mounts of grub devices.  dokan2.dll is loaded
 * dynamically: when the library or its driver is absent everything
 * degrades to dokanfs_available() == false and the GUI offers Install
 * Dokan instead.  The runtime (dll + driver) is embedded in
 * our resources for the build architecture; dokanfs_install() writes it
 * to the system and starts the driver (the process runs elevated).  All
 * functions are GUI-thread only; the filesystem callbacks marshal their
 * rover calls onto the backend thread via backend_call().
 */

#ifndef FSROVER_DOKANFS_H
#define FSROVER_DOKANFS_H	1

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

/* Load dokan2.dll and check the driver; false = feature disabled.
   NOTIFY receives WM_APP_DOKAN_GONE.  */
bool dokanfs_init (HWND notify);

/* True when the library and driver are usable.  */
bool dokanfs_available (void);

/* Install the app-embedded Dokan runtime (library + kernel driver) to
   the system, start the driver service and
   re-probe.  On success dokanfs_available() becomes true and true is
   returned; otherwise false with *ERROR set.  The process already runs
   elevated (RequireAdministrator), so no re-launch is needed.  */
bool dokanfs_install (std::wstring *error);

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

const std::string &dokanfs_device (const dokan_mount *m);
/* Drive letter for display, e.g. L"Z:".  */
std::wstring dokanfs_letter (const dokan_mount *m);

#endif /* ! FSROVER_DOKANFS_H */
