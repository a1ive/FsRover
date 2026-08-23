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

#ifndef FSROVER_WINFSPFS_H
#define FSROVER_WINFSPFS_H	1

#include <windows.h>

#include <string>

#include "fusefs.h"

struct winfsp_mount;

bool winfspfs_init (HWND notify, UINT gone_message, UINT mounted_message);
bool winfspfs_available (void);
void winfspfs_shutdown (void);

winfsp_mount *winfspfs_mount (fusefs *fs, wchar_t letter,
	bool open_explorer, void *notify_context, std::wstring *error);
void winfspfs_unmount (winfsp_mount *mount);

#endif
