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

#include "mountdlg.h"
#include "dokanfs.h"
#include "gui.h"
#include "resource.h"
#include "strconv.h"

namespace
{

/* Windows drive-letter mounts (WinFsp default, selectable Dokan host). */

/* Mount options collected by the dialog; the device entry is a
   snapshot because a disk refresh arriving during the modal loop
   reallocates g_disks, and the Explorer checkbox keeps its last
   state for the session.  */
backend_diskent g_dokan_disk;
wchar_t g_dokan_letter;
bool g_dokan_explorer = true;

INT_PTR CALLBACK
dokan_mount_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		SetWindowTextW (dlg, res_str (IDS_MENU_DOKAN_MOUNT).c_str ());
		std::wstring info = widen (g_dokan_disk.name) + L" (" + widen (g_dokan_disk.fs) + L")";
		SetDlgItemTextW (dlg, IDC_DOKAN_INFO, info.c_str ());
		SetDlgItemTextW (dlg, IDC_DOKAN_LETTER_LABEL, res_str (IDS_DOKAN_LETTER).c_str ());
		SetDlgItemTextW (dlg, IDC_DOKAN_EXPLORER, res_str (IDS_DOKAN_OPEN_EXPLORER).c_str ());
		SetDlgItemTextW (dlg, IDCANCEL, res_str (IDS_BTN_CANCEL).c_str ());

		HWND combo = GetDlgItem (dlg, IDC_DOKAN_LETTER);
		DWORD mask = GetLogicalDrives ();
		for (int i = 3; i < 26; i++)	/* D: through Z: */
			if (!(mask & (1u << i)))
			{
				wchar_t item[3] = { (wchar_t) (L'A' + i), L':', 0 };
				SendMessageW (combo, CB_ADDSTRING, 0, (LPARAM) item);
			}
		/* Default to the highest free letter.  */
		int count = (int) SendMessageW (combo, CB_GETCOUNT, 0, 0);
		SendMessageW (combo, CB_SETCURSEL, (WPARAM) (count - 1), 0);
		CheckDlgButton (dlg, IDC_DOKAN_EXPLORER, g_dokan_explorer ? BST_CHECKED : BST_UNCHECKED);
		return TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDOK:
		{
			HWND combo = GetDlgItem (dlg, IDC_DOKAN_LETTER);
			int sel = (int) SendMessageW (combo, CB_GETCURSEL, 0, 0);
			if (sel < 0)
				return TRUE;	/* no free drive letter */
			wchar_t item[8] = {};
			SendMessageW (combo, CB_GETLBTEXT, (WPARAM) sel, (LPARAM) item);
			g_dokan_letter = item[0];
			g_dokan_explorer = IsDlgButtonChecked (dlg, IDC_DOKAN_EXPLORER) == BST_CHECKED;
			EndDialog (dlg, 1);
			return TRUE;
		}
		case IDCANCEL:
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

} // namespace

std::wstring
show_mount_dialog (HWND owner, const backend_diskent &d)
{
	g_dokan_disk = d;
	{
		modal_scope hold;
		if (DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_DOKANMOUNT), owner, dokan_mount_dlg_proc, 0) != 1)
			return {};
	}

	std::wstring err;
	dokan_mount *m = dokanfs_mount (g_dokan_disk.name, g_dokan_disk.fs, g_dokan_disk.size, g_dokan_letter, g_dokan_explorer, &err);
	if (!m)
		return err;
	wchar_t text[160];
	// Mounted %s to %s
	_snwprintf_s (text, 160, _TRUNCATE, res_str (IDS_FMT_DOKAN_MOUNTED).c_str (),
		widen (g_dokan_disk.name).c_str (), dokanfs_letter (m).c_str ());
	return text;
}

std::wstring
unmount_drive (dokan_mount *m)
{
	std::string dev = dokanfs_device (m);

	dokanfs_unmount (m);
	wchar_t text[160];
	// Unmount %s (%s)
	_snwprintf_s (text, 160, _TRUNCATE, res_str (IDS_FMT_UNMOUNTED).c_str (), widen (dev).c_str ());
	return text;
}

#if FSROVER_EMBED_DOKAN
/* Install the app-embedded Dokan runtime (Dokan menu, shown only while
   the driver is absent and this process is elevated).  Runs in-process,
   writing to System32 and starting a kernel service directly; a wait
   cursor covers the brief pause and the outcome is reported explicitly,
   since installing a driver is worth confirming.  */
void
show_dokan_install (HWND owner, HWND status)
{
	auto set_status = [status] (const wchar_t *text)
	{
		SendMessageW (status, SB_SETTEXTW, 0, (LPARAM) text);
	};
	set_status (res_str (IDS_DOKAN_INSTALLING).c_str ());
	UpdateWindow (status);
	HCURSOR prev = SetCursor (LoadCursorW (nullptr, IDC_WAIT));

	std::wstring err;
	bool ok = dokanfs_install (&err);

	SetCursor (prev);

	modal_scope hold;
	if (ok)
	{
		set_status (res_str (IDS_DOKAN_INSTALL_OK).c_str ());
		MessageBoxW (owner, res_str (IDS_DOKAN_INSTALL_OK).c_str (), res_str (IDS_APP_TITLE).c_str (), MB_ICONINFORMATION | MB_OK);
	}
	else
	{
		wchar_t text[320];
		// Could not install Dokan: %s
		_snwprintf_s (text, 320, _TRUNCATE, res_str (IDS_FMT_DOKAN_INSTALL_FAIL).c_str (), err.c_str ());
		set_status (text);
		MessageBoxW (owner, text, res_str (IDS_APP_TITLE).c_str (), MB_ICONERROR | MB_OK);
	}
}
#endif
