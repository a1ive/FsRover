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

#ifndef FSROVER_MOUNTDLG_H
#define FSROVER_MOUNTDLG_H	1

#include "build_config.h"
#include <windows.h>
#include <string>

struct backend_diskent;
struct dokan_mount;

/* Return the status text for main's status bar; cancellation returns empty. */
std::wstring show_mount_dialog (HWND owner, const backend_diskent &disk);
std::wstring unmount_drive (dokan_mount *mount);
#if FSROVER_EMBED_DOKAN
void show_dokan_install (HWND owner, HWND status);
#endif

#endif
