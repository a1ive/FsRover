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

#ifndef FSROVER_TRAY_H
#define FSROVER_TRAY_H	1

#include <windows.h>
#include <shellapi.h>

struct dokan_mount;

/* GUI-thread notification icon. Remove before destroying the mount backend. */
class tray_icon
{
public:
	tray_icon () = default;
	tray_icon (const tray_icon &) = delete;
	tray_icon &operator= (const tray_icon &) = delete;
	void add (HWND owner, void (*unmount) (dokan_mount *));
	void remove (void);
	bool handle_message (UINT message, LPARAM data);

private:
	void show_window (void);
	void show_menu (void);
	NOTIFYICONDATAW data_ = {};
	UINT taskbar_message_ = 0;
	void (*unmount_) (dokan_mount *) = nullptr;
};

#endif
