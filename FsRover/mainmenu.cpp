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
 * The menu bar and its commands, plus the ways a disk gets mounted from
 * outside the tree: host image files (menu, command line, drag and
 * drop) and the drive letter mounts through WinFsp/Dokan.
 */

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>

#include <string>

#include "../common/fs_encoding.h"
#include "dokanfs.h"
#include "filedlg.h"
#include "mainwnd.h"
#include "mountdlg.h"
#include "resource.h"
#include "strconv.h"

/* The message the drag payload itself travels in; the SDK headers
   name every other one but not this.  See enable_file_drop().  */
#ifndef WM_COPYGLOBALDATA
#define WM_COPYGLOBALDATA 0x0049
#endif

namespace mainwnd
{

namespace
{

HMENU g_menu_file;	/* File popup: Refresh grays while extracting */
HMENU g_menu_settings;	/* Settings popup: toggles refreshed on open */
HMENU g_menu_encoding;	/* File name encoding radio submenu */
HMENU g_menu_dokan;	/* Dokan popup, rebuilt on every open */

void
open_host_image (bool decompress)
{
	std::wstring file = pick_open_image (g_main);

	if (file.empty ())
		return;
	mount_host_image (std::move (file), decompress);
}

#if FSROVER_ENABLE_ADMIN_FEATURES
/* Restart elevated (File menu, shown only while this process is not).
   A running process cannot gain privileges, so this instance hands
   over as soon as the elevated one has been started.  */
void
run_as_admin (void)
{
	wchar_t exe[MAX_PATH];
	SHELLEXECUTEINFOW info = { sizeof (info) };

	if (!GetModuleFileNameW (nullptr, exe, ARRAYSIZE (exe)))
		return;

	/* NOASYNC: the shell must be done with the request before this
	   process leaves.  */
	info.fMask = SEE_MASK_NOASYNC;
	info.hwnd = g_main;
	info.lpVerb = L"runas";
	info.lpFile = exe;
	info.nShow = SW_SHOWNORMAL;
	if (!ShellExecuteExW (&info))
	{
		/* Dismissing the UAC prompt is a decision, not a failure.  */
		if (GetLastError () != ERROR_CANCELLED)
			set_status (IDS_ELEVATE_FAILED);
		return;
	}
	DestroyWindow (g_main);
}
#endif

} // namespace

/* Take dropped files.  The main window is the only drop target, which
   is enough for the panes as well: a drop lands on the first ancestor
   that is registered.  An elevated window also has to let the drag
   through UIPI -- these three messages carry it, and without them a
   drag from the unelevated Explorer is refused with no sign of why.
   The hole is opened only where the integrity boundary exists.  */
void
enable_file_drop (HWND wnd)
{
	DragAcceptFiles (wnd, TRUE);
	if (!is_elevated ())
		return;
	ChangeWindowMessageFilterEx (wnd, WM_DROPFILES, MSGFLT_ALLOW, nullptr);
	ChangeWindowMessageFilterEx (wnd, WM_COPYDATA, MSGFLT_ALLOW, nullptr);
	ChangeWindowMessageFilterEx (wnd, WM_COPYGLOBALDATA, MSGFLT_ALLOW, nullptr);
}

/* Every dropped file is mounted as a virtual disk of its own, exactly
   as --file does: a drop carries no way to ask for anything else, and
   the decompressing variant stays a menu item away.  */
void
on_drop_files (HDROP drop)
{
	UINT count = DragQueryFileW (drop, 0xFFFFFFFF, nullptr, 0);

	/* The mount menu items gray out while an extraction runs, for the
	   same reason: the mount would queue behind the job and overwrite
	   the progress line it is holding.  */
	if (g_extracting)
		count = 0;
	for (UINT i = 0; i < count; i++)
	{
		std::wstring path (DragQueryFileW (drop, i, nullptr, 0), L'\0');
		DWORD attr;

		if (path.empty ())
			continue;
		DragQueryFileW (drop, i, path.data (), (UINT) path.size () + 1);
		/* A directory cannot back a disk, and the Win32 error for
		   opening one as a file (access denied) would only mislead.  */
		attr = GetFileAttributesW (path.c_str ());
		if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
			continue;
		mount_host_image (std::move (path), false);
	}
	DragFinish (drop);
}

/* The main window owns the status bar; mount dialogs return its text. */
void
do_dokan_mount (const backend_diskent &disk)
{
	std::wstring text = show_mount_dialog (g_main, disk);
	if (!text.empty ())
		set_status (text.c_str ());
}

void
do_dokan_unmount (dokan_mount *mount)
{
	set_status (unmount_drive (mount).c_str ());
}

/* The menu bar and its submenus are owned by the window and destroyed
   with it.  The drive-mount popup starts empty; on_menu_popup fills it. */
void
create_menu_bar (HWND wnd)
{
	HMENU bar = CreateMenu ();

	g_menu_file = CreatePopupMenu ();
	AppendMenuW (g_menu_file, MF_STRING, IDM_FILE_OPEN_IMAGE, res_str (IDS_MENU_OPEN_IMAGE).c_str ());
	AppendMenuW (g_menu_file, MF_STRING, IDM_FILE_OPEN_IMAGE_DECOMP, res_str (IDS_MENU_OPEN_IMAGE_DECOMP).c_str ());
	AppendMenuW (g_menu_file, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (g_menu_file, MF_STRING, IDM_FILE_REFRESH, res_str (IDS_BTN_REFRESH).c_str ());
	AppendMenuW (g_menu_file, MF_SEPARATOR, 0, nullptr);
#if FSROVER_ENABLE_ADMIN_FEATURES
	/* Elevation cannot change while the process runs, so the re-launch
	   is either offered for good or never.  Under --file it is never:
	   the new instance would start on an empty command line, dropping
	   the image this one was asked to open for physical disks this one
	   was asked to leave alone.  */
	if (!is_elevated () && !g_cmdline.no_windisk)
		AppendMenuW (g_menu_file, MF_STRING, IDM_FILE_RUNAS, res_str (IDS_MENU_RUNAS).c_str ());
#endif

	AppendMenuW (g_menu_file, MF_STRING, IDM_FILE_EXIT, res_str (IDS_TRAY_EXIT).c_str ());

	HMENU sel = CreatePopupMenu ();
	AppendMenuW (sel, MF_STRING, IDM_SEL_ALL, res_str (IDS_MENU_SEL_ALL).c_str ());
	AppendMenuW (sel, MF_STRING, IDM_SEL_INVERT, res_str (IDS_MENU_SEL_INVERT).c_str ());

	g_menu_settings = CreatePopupMenu ();
	g_menu_encoding = CreatePopupMenu ();
	for (int i = 0; i < (int) ARRAYSIZE (rover_fs_encoding::OPTIONS); i++)
		AppendMenuW (g_menu_encoding, MF_STRING, IDM_FS_ENCODING_BASE + i,
			rover_fs_encoding::OPTIONS[i].name);
	AppendMenuW (g_menu_settings, MF_POPUP, (UINT_PTR) g_menu_encoding,
		res_str (IDS_MENU_FS_ENCODING).c_str ());
	AppendMenuW (g_menu_settings, MF_SEPARATOR, 0, nullptr);
	/* Check mark set by on_menu_popup from g_preserve_times.  */
	AppendMenuW (g_menu_settings, MF_STRING, IDM_FILE_TIMESTAMPS, res_str (IDS_MENU_TIMESTAMPS).c_str ());

	g_menu_dokan = CreatePopupMenu ();

	HMENU help = CreatePopupMenu ();
	AppendMenuW (help, MF_STRING, IDM_HELP_DOC, res_str (IDS_MENU_HELPDOC).c_str ());
	AppendMenuW (help, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (help, MF_STRING, IDM_HELP_SHORTCUTS, res_str (IDS_MENU_SHORTCUTS).c_str ());
	AppendMenuW (help, MF_STRING, IDM_HELP_SUPPORT, res_str (IDS_MENU_SUPPORT).c_str ());
	AppendMenuW (help, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (help, MF_STRING, IDM_HELP_ABOUT, res_str (IDS_MENU_ABOUT).c_str ());

	AppendMenuW (bar, MF_POPUP, (UINT_PTR) g_menu_file, res_str (IDS_MENU_FILE).c_str ());
	AppendMenuW (bar, MF_POPUP, (UINT_PTR) sel, res_str (IDS_MENU_SELECTION).c_str ());
	AppendMenuW (bar, MF_POPUP, (UINT_PTR) g_menu_settings, res_str (IDS_MENU_SETTINGS).c_str ());
	AppendMenuW (bar, MF_POPUP, (UINT_PTR) g_menu_dokan, res_str (IDS_MENU_DOKAN).c_str ());
	AppendMenuW (bar, MF_POPUP, (UINT_PTR) help, res_str (IDS_MENU_HELP).c_str ());
	SetMenu (wnd, bar);
}

void
on_menu_popup (HMENU menu)
{
	if (menu == g_menu_file)
	{
		/* Same rule as the old toolbar button: a refresh would
		   queue behind a running extraction and overwrite the
		   progress line.  Mounting an image ends in a refresh, so
		   it waits for the same moment.  */
		EnableMenuItem (menu, IDM_FILE_REFRESH, g_extracting ? MF_GRAYED : MF_ENABLED);
		EnableMenuItem (menu, IDM_FILE_OPEN_IMAGE, g_extracting ? MF_GRAYED : MF_ENABLED);
		EnableMenuItem (menu, IDM_FILE_OPEN_IMAGE_DECOMP, g_extracting ? MF_GRAYED : MF_ENABLED);
		return;
	}
	if (menu == g_menu_settings)
	{
		CheckMenuItem (menu, IDM_FILE_TIMESTAMPS, g_preserve_times ? MF_CHECKED : MF_UNCHECKED);
		EnableMenuItem (menu, 0, MF_BYPOSITION | (g_extracting ? MF_GRAYED : MF_ENABLED));
		return;
	}
	if (menu == g_menu_encoding)
	{
		int selected = IDM_FS_ENCODING_BASE;
		for (int i = 0; i < (int) ARRAYSIZE (rover_fs_encoding::OPTIONS); i++)
			if (rover_fs_encoding::OPTIONS[i].code_page == g_fs_encoding)
				selected += i;
		CheckMenuRadioItem (menu, IDM_FS_ENCODING_BASE,
			IDM_FS_ENCODING_BASE + (int) ARRAYSIZE (rover_fs_encoding::OPTIONS) - 1,
			selected, MF_BYCOMMAND);
		return;
	}
	if (menu != g_menu_dokan)
		return;

	/* Rebuilt on every open, like the tray menu: one unmount entry
	   per live mount, or a grayed line saying why there is none.  */
	while (GetMenuItemCount (menu) > 0)
		DeleteMenu (menu, 0, MF_BYPOSITION);
	if (!dokanfs_available ())
	{
		AppendMenuW (menu, MF_STRING | MF_GRAYED, 0,
			res_str (IDS_MOUNT_UNAVAILABLE).c_str ());
#if FSROVER_EMBED_DOKAN
		AppendMenuW (menu, MF_SEPARATOR, 0, nullptr);
		/* With the driver absent and nothing in the way, offer to
		   install the bundled runtime instead of just greying the
		   feature out.  What can be in the way is named in the order
		   the user can act on it: a 32-bit build on 64-bit Windows
		   bundles a runtime the system cannot use and elevating
		   would not change that. Otherwise an elevated token is needed.  */
		if (is_wow64 ())
			AppendMenuW (menu, MF_STRING | MF_GRAYED, 0, res_str (IDS_DOKAN_WOW64).c_str ());
		else if (!is_elevated ())
			AppendMenuW (menu, MF_STRING | MF_GRAYED, 0, res_str (IDS_DOKAN_NEED_ADMIN).c_str ());
		else
			AppendMenuW (menu, MF_STRING, IDM_DOKAN_INSTALL, res_str (IDS_DOKAN_INSTALL).c_str ());
#endif
		return;
	}
	wchar_t backend[96];
	_snwprintf_s (backend, ARRAYSIZE (backend), _TRUNCATE,
		res_str (IDS_FMT_MOUNT_BACKEND).c_str (), dokanfs_backend_name ());
	HMENU hosts = CreatePopupMenu ();
	dokanfs_backend selected = dokanfs_current_backend ();
	AppendMenuW (hosts, MF_STRING
		| (dokanfs_backend_available (dokanfs_backend::winfsp) ? 0u : MF_GRAYED)
		| (selected == dokanfs_backend::winfsp ? MF_CHECKED : 0u),
		IDM_BACKEND_WINFSP, L"WinFsp");
	AppendMenuW (hosts, MF_STRING
		| (dokanfs_backend_available (dokanfs_backend::dokan) ? 0u : MF_GRAYED)
		| (selected == dokanfs_backend::dokan ? MF_CHECKED : 0u),
		IDM_BACKEND_DOKAN, L"Dokan");
#if FSROVER_EMBED_DOKAN
	if (!dokanfs_backend_available (dokanfs_backend::dokan))
	{
		AppendMenuW (hosts, MF_SEPARATOR, 0, nullptr);
		if (is_wow64 ())
			AppendMenuW (hosts, MF_STRING | MF_GRAYED, 0, res_str (IDS_DOKAN_WOW64).c_str ());
		else if (!is_elevated ())
			AppendMenuW (hosts, MF_STRING | MF_GRAYED, 0, res_str (IDS_DOKAN_NEED_ADMIN).c_str ());
		else
			AppendMenuW (hosts, MF_STRING, IDM_DOKAN_INSTALL, res_str (IDS_DOKAN_INSTALL).c_str ());
	}
#endif

	AppendMenuW (menu, MF_POPUP, (UINT_PTR) hosts, backend);
	AppendMenuW (menu, MF_SEPARATOR, 0, nullptr);
	if (!dokanfs_count ())
	{
		AppendMenuW (menu, MF_STRING | MF_GRAYED, 0, res_str (IDS_DOKAN_NONE).c_str ());
		return;
	}
	for (size_t i = 0; i < dokanfs_count (); i++)
	{
		dokan_mount *m = dokanfs_get (i);
		wchar_t text[160];
		_snwprintf_s (text, 160, _TRUNCATE, res_str (IDS_FMT_TRAY_UNMOUNT).c_str (),
			dokanfs_letter (m).c_str (), widen (dokanfs_device (m)).c_str ());
		AppendMenuW (menu, MF_STRING, IDM_DOKAN_UNMOUNT_BASE + (int) i, text);
	}
}

void
on_command (int id)
{
	if (id >= IDM_FS_ENCODING_BASE
		&& id < IDM_FS_ENCODING_BASE + (int) ARRAYSIZE (rover_fs_encoding::OPTIONS))
	{
		if (!g_extracting)
			set_fs_encoding (rover_fs_encoding::OPTIONS[id - IDM_FS_ENCODING_BASE].code_page);
		return;
	}
	if (id >= IDM_DOKAN_UNMOUNT_BASE)
	{
		dokan_mount *m = dokanfs_get (
			(size_t) (id - IDM_DOKAN_UNMOUNT_BASE));
		if (m)
			do_dokan_unmount (m);
		return;
	}
	switch (id)
	{
	case IDM_BACKEND_WINFSP:
		dokanfs_select_backend (dokanfs_backend::winfsp);
		break;
	case IDM_BACKEND_DOKAN:
		dokanfs_select_backend (dokanfs_backend::dokan);
		break;
#if FSROVER_EMBED_DOKAN
	case IDM_DOKAN_INSTALL:
		show_dokan_install (g_main, g_status);
		break;
#endif

	case IDM_FILE_REFRESH:
		if (!g_extracting)
			refresh ();
		break;
	case IDM_FILE_OPEN_IMAGE:
	case IDM_FILE_OPEN_IMAGE_DECOMP:
		if (!g_extracting)
			open_host_image (id == IDM_FILE_OPEN_IMAGE_DECOMP);
		break;
	case IDM_FILE_TIMESTAMPS:
		/* A running extraction keeps the setting it started with.  */
		g_preserve_times = !g_preserve_times;
		break;
#if FSROVER_ENABLE_ADMIN_FEATURES
	case IDM_FILE_RUNAS:
		run_as_admin ();
		break;
#endif

	case IDM_FILE_EXIT:
		SendMessageW (g_main, WM_CLOSE, 0, 0);
		break;
	case IDM_SEL_ALL:
		ListView_SetItemState (g_list, -1, LVIS_SELECTED, LVIS_SELECTED);
		break;
	case IDM_SEL_INVERT:
		for (int i = 0, n = ListView_GetItemCount (g_list); i < n; i++)
			ListView_SetItemState (g_list, i, ListView_GetItemState (g_list, i, LVIS_SELECTED) ^ LVIS_SELECTED, LVIS_SELECTED);
		break;
	case IDM_HELP_DOC:
		show_help_doc ();
		break;
	case IDM_HELP_SHORTCUTS:
		show_shortcuts ();
		break;
	case IDM_HELP_SUPPORT:
		show_support ();
		break;
	case IDM_HELP_ABOUT:
		show_about ();
		break;
	/* The buttons are disabled while extracting, but their accelerators
	   fire regardless of the button state.  */
	case IDC_BACK:
		if (!g_extracting)
			go_back ();
		break;
	case IDC_FWD:
		if (!g_extracting)
			go_forward ();
		break;
	case IDC_UP:
		if (!g_extracting)
			go_up ();
		break;
	case IDC_EXTRACT:
		on_extract_button ();
		break;
	}
}

} // namespace mainwnd

using namespace mainwnd;

/* Mount a file from the Windows filesystem as a virtual disk
   (winfile.c); the result arrives like a loopback mount.  Also the
   --file startup path, which is why it lives outside the picker.  */
void
mount_host_image (std::wstring file, bool decompress)
{
	backend_post (winfile_add_task { std::move (file), decompress });
	set_status (IDS_STATUS_MOUNTING);
}
