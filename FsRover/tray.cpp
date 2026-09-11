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

#include "tray.h"
#include "dokanfs.h"
#include "gui.h"
#include "resource.h"
#include "strconv.h"

#pragma comment (lib, "shell32.lib")

namespace
{
constexpr int IDM_TRAY_OPEN = 900;
constexpr int IDM_TRAY_EXIT = 901;
constexpr int IDM_TRAY_UNMOUNT_BASE = 1000;
constexpr UINT WM_APP_TRAY = WM_APP + 5;
} // namespace

/* Tray icon: resident for quick unmounting; the app only exits
   through WM_CLOSE, which warns while dokan mounts are alive.  It is
   also the only way back to a minimized window, which leaves the
   taskbar entirely (WM_SIZE).  */

void
tray_icon::add (HWND wnd, void (*unmount) (dokan_mount *))
{
	/* Explorer drops every notification icon when it restarts and
	   broadcasts this to ask for them back.  Without it a restart
	   would stand the icon down for good, and a window that is
	   hidden rather than merely minimized could never be reached
	   again.  Registering twice is harmless: the atom is the same.  */
	taskbar_message_ = RegisterWindowMessageW (L"TaskbarCreated");

	unmount_ = unmount;
	data_.cbSize = sizeof (data_);
	data_.hWnd = wnd;
	data_.uID = 1;
	data_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	data_.uCallbackMessage = WM_APP_TRAY;
	data_.hIcon = (HICON) LoadImageW (GetModuleHandleW (nullptr),
		MAKEINTRESOURCEW (IDI_APP),
		IMAGE_ICON,
		GetSystemMetrics (SM_CXSMICON),
		GetSystemMetrics (SM_CYSMICON), 0);
	wcscpy_s (data_.szTip, res_str (IDS_APP_TITLE).c_str ());
	Shell_NotifyIconW (NIM_ADD, &data_);
}

void
tray_icon::show_window (void)
{
	/* Minimizing hides the window, so it can be hidden and iconic at
	   once (from the minimize box) or hidden and normal (from
	   --minimize, which never showed it).  SW_RESTORE covers the
	   first, SW_SHOW the second; using SW_SHOW on an iconic window
	   would only put the minimized frame back on screen.  */
	ShowWindow (data_.hWnd, IsIconic (data_.hWnd) ? SW_RESTORE : SW_SHOW);
	SetForegroundWindow (data_.hWnd);
}

void
tray_icon::show_menu (void)
{
	POINT pt;
	GetCursorPos (&pt);

	HMENU menu = CreatePopupMenu ();
	for (size_t i = 0; i < dokanfs_count (); i++)
	{
		dokan_mount *m = dokanfs_get (i);
		wchar_t text[160];
		_snwprintf_s (text, 160, _TRUNCATE, res_str (IDS_FMT_TRAY_UNMOUNT).c_str (),
			dokanfs_letter (m).c_str (), widen (dokanfs_device (m)).c_str ());
		AppendMenuW (menu, MF_STRING, IDM_TRAY_UNMOUNT_BASE + (int) i, text);
	}
	if (dokanfs_count ())
		AppendMenuW (menu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (menu, MF_STRING, IDM_TRAY_OPEN, res_str (IDS_TRAY_OPEN).c_str ());
	AppendMenuW (menu, MF_STRING, IDM_TRAY_EXIT, res_str (IDS_TRAY_EXIT).c_str ());

	/* Required for the menu to close on an outside click.  */
	SetForegroundWindow (data_.hWnd);
	int cmd = TrackPopupMenu (menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, data_.hWnd, nullptr);
	DestroyMenu (menu);

	if (cmd == IDM_TRAY_OPEN)
		show_window ();
	else if (cmd == IDM_TRAY_EXIT)
		SendMessageW (data_.hWnd, WM_CLOSE, 0, 0);
	else if (cmd >= IDM_TRAY_UNMOUNT_BASE)
	{
		dokan_mount *m = dokanfs_get ((size_t) (cmd - IDM_TRAY_UNMOUNT_BASE));
		if (m)
			unmount_ (m);
	}
}

void
tray_icon::remove (void)
{
	Shell_NotifyIconW (NIM_DELETE, &data_);
	if (data_.hIcon)
		DestroyIcon (data_.hIcon);
	data_ = {};
	taskbar_message_ = 0;
	unmount_ = nullptr;
}

bool
tray_icon::handle_message (UINT message, LPARAM data)
{
	/* Explorer requests re-registration after its taskbar restarts. */
	if (taskbar_message_ && message == taskbar_message_)
	{
		Shell_NotifyIconW (NIM_ADD, &data_);
		return true;
	}
	if (message != WM_APP_TRAY)
		return false;
	if (data == WM_LBUTTONDBLCLK)
		show_window ();
	else if (data == WM_RBUTTONUP)
		show_menu ();
	return true;
}
