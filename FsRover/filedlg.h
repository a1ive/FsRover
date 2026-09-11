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

#ifndef FSROVER_FILEDLG_H
#define FSROVER_FILEDLG_H	1

#include <windows.h>
#include <string>

/* Native host-path pickers. An empty result means cancelled or unavailable. */
std::wstring pick_folder (HWND owner);
std::wstring pick_image_file (HWND owner, const std::wstring &defname);
std::wstring pick_open_image (HWND owner);

#endif
