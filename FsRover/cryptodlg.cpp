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

/* Cryptodisk unlock dialog (LUKS/LUKS2): collect a passphrase or key
   file and hand the bytes to grub via rover_crypto_unlock().  */

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>

#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

HWND g_crypto;	/* modal unlock dialog, null when closed */

namespace
{

/* Source device being unlocked, its UUID, and (on success) the
   resulting "cryptoN" device to navigate into.  */
UINT g_seq_crypto;	/* in-flight crypto_unlock task */
std::string g_crypto_dev;
std::string g_crypto_uuid;
std::string g_crypto_newdev;

std::vector<char>
crypto_gather_key (HWND dlg)
{
	if (IsDlgButtonChecked (dlg, IDC_CRYPTO_USEKEYFILE) == BST_CHECKED)
	{
		wchar_t path[MAX_PATH] = {};
		GetDlgItemTextW (dlg, IDC_CRYPTO_KEYFILE, path, MAX_PATH);
		if (!path[0])
			return {};

		HANDLE h = CreateFileW (path, GENERIC_READ, FILE_SHARE_READ,
					nullptr, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE)
			return {};

		/* A key file is used verbatim as the secret; cap the read so
		   an accidental huge file cannot exhaust memory.  */
		std::vector<char> key;
		std::vector<char> buf (65536);
		DWORD got = 0;
		while (key.size () < (8u << 20)
			&& ReadFile (h, buf.data (), (DWORD) buf.size (), &got, nullptr) && got)
			key.insert (key.end (), buf.data (), buf.data () + got);
		CloseHandle (h);
		return key;
	}

	wchar_t pass[512] = {};
	GetDlgItemTextW (dlg, IDC_CRYPTO_PASS, pass, 512);
	std::string u = narrow (pass);
	return std::vector<char> (u.begin (), u.end ());
}

/* Enable/disable the inputs while an unlock is in flight (the keyfile vs
   passphrase controls follow the checkbox).  */
void
crypto_enable_inputs (HWND dlg, BOOL on)
{
	BOOL kf = IsDlgButtonChecked (dlg, IDC_CRYPTO_USEKEYFILE) == BST_CHECKED;

	EnableWindow (GetDlgItem (dlg, IDOK), on);
	EnableWindow (GetDlgItem (dlg, IDC_CRYPTO_USEKEYFILE), on);
	EnableWindow (GetDlgItem (dlg, IDC_CRYPTO_PASS), on && !kf);
	EnableWindow (GetDlgItem (dlg, IDC_CRYPTO_KEYFILE), on && kf);
	EnableWindow (GetDlgItem (dlg, IDC_CRYPTO_BROWSE), on && kf);
}

INT_PTR CALLBACK
crypto_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		wchar_t title[128];

		g_crypto = dlg;
		swprintf (title, 128, res_str (IDS_FMT_CRYPTO_TITLE).c_str (), widen (g_crypto_dev).c_str ());
		SetWindowTextW (dlg, title);

		std::wstring info = widen (g_crypto_dev);
		if (!g_crypto_uuid.empty ())
			info += L" (" + widen (g_crypto_uuid) + L")";
		SetDlgItemTextW (dlg, IDC_CRYPTO_INFO, info.c_str ());

		SendDlgItemMessageW (dlg, IDC_CRYPTO_PROGRESS, PBM_SETRANGE32, 0, 100);
		SetFocus (GetDlgItem (dlg, IDC_CRYPTO_PASS));
		return FALSE;	/* focus was set explicitly */
	}
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDC_CRYPTO_USEKEYFILE:
		{
			BOOL kf = IsDlgButtonChecked (dlg, IDC_CRYPTO_USEKEYFILE)
				  == BST_CHECKED;
			EnableWindow (GetDlgItem (dlg, IDC_CRYPTO_PASS), !kf);
			EnableWindow (GetDlgItem (dlg, IDC_CRYPTO_KEYFILE), kf);
			EnableWindow (GetDlgItem (dlg, IDC_CRYPTO_BROWSE), kf);
			return TRUE;
		}
		case IDC_CRYPTO_BROWSE:
		{
			wchar_t path[MAX_PATH] = {};
			OPENFILENAMEW ofn = { sizeof (ofn) };
			std::wstring t = res_str (IDS_CRYPTO_KEYFILE);

			ofn.hwndOwner = dlg;
			ofn.lpstrFile = path;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrTitle = t.c_str ();
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			if (GetOpenFileNameW (&ofn))
				SetDlgItemTextW (dlg, IDC_CRYPTO_KEYFILE, path);
			return TRUE;
		}
		case IDOK:
		{
			backend_task task;
			task.key = crypto_gather_key (dlg);
			if (task.key.empty ())
				return TRUE;	/* nothing entered; keep waiting */

			/* Unlock on the grub thread; the dialog stays up and the
			   result comes back through WM_APP_TASK_DONE.  Disable
			   the inputs so it cannot be submitted twice and the KDF
			   (Argon2 can be slow) does not look ignored.  */
			task.type = backend_task_type::crypto_unlock;
			task.path = g_crypto_dev;
			crypto_enable_inputs (dlg, FALSE);
			SendDlgItemMessageW (dlg, IDC_CRYPTO_PROGRESS, PBM_SETPOS, 0, 0);
			ShowWindow (GetDlgItem (dlg, IDC_CRYPTO_PROGRESS), SW_SHOW);
			g_seq_crypto = backend_post (std::move (task));
			return TRUE;
		}
		case IDCANCEL:
			/* A late unlock result is dropped once g_crypto is null.  */
			g_crypto = nullptr;
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

} // namespace

/* Called from WM_APP_TASK_DONE when a crypto_unlock finishes.  */
void
crypto_unlock_done (backend_result *res)
{
	if (!g_crypto || res->seq != g_seq_crypto)
		return;
	if (!res->error.empty ())
	{
		crypto_enable_inputs (g_crypto, TRUE);
		ShowWindow (GetDlgItem (g_crypto, IDC_CRYPTO_PROGRESS), SW_HIDE);
		MessageBoxW (g_crypto, res_str (IDS_CRYPTO_BADKEY).c_str (), nullptr, MB_ICONWARNING | MB_OK);
		SetDlgItemTextW (g_crypto, IDC_CRYPTO_PASS, L"");
		SetFocus (GetDlgItem (g_crypto, IDC_CRYPTO_PASS));
		return;
	}
	g_crypto_newdev = res->path;
	HWND dlg = g_crypto;
	g_crypto = nullptr;
	EndDialog (dlg, 1);
}

void
prompt_unlock (const std::string &devname, const std::string &uuid)
{
	g_crypto_dev = devname;
	g_crypto_uuid = uuid;
	g_crypto_newdev.clear ();

	INT_PTR r = DialogBoxParamW (GetModuleHandleW (nullptr),
		MAKEINTRESOURCEW (IDD_CRYPTO), g_main, crypto_dlg_proc, 0);
	if (r == 1 && !g_crypto_newdev.empty ())
	{
		/* "cryptoN" now exists: rebuild the tree and browse into it.  */
		refresh ();
		navigate ("(" + g_crypto_newdev + ")/");
	}
}

/* WM_APP_TASK_PROGRESS routing; true = the update was this dialog's.  */
bool
crypto_on_progress (backend_progress *p)
{
	if (!g_crypto || p->seq != g_seq_crypto)
		return false;
	SendDlgItemMessageW (g_crypto, IDC_CRYPTO_PROGRESS, PBM_SETPOS, (WPARAM) p->percent, 0);
	return true;
}
