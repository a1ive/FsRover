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

/* Cryptodisk unlock dialogs.
 *
 * Two of them.  LUKS/LUKS2 volumes are detected while enumerating devices,
 * so that dialog only has to collect a passphrase or key file and hand the
 * bytes to rover_crypto_unlock().
 *
 * VeraCrypt/TrueCrypt volumes carry nothing in plaintext, so they cannot be
 * detected at all: the second dialog is reached from the tree's context menu
 * on any device and additionally collects everything the volume does not
 * store -- the PIM, which key derivation function to try, whether to read
 * the volume as TrueCrypt, and whether to look at the hidden volume or the
 * backup headers.  Key files are folded into the passphrase here rather than
 * in grub, following VeraCrypt's own algorithm.  */

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>

#include <algorithm>
#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

namespace
{

HWND g_crypto;	/* unlock dialog, null when closed */

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
			BOOL kf = IsDlgButtonChecked (dlg, IDC_CRYPTO_USEKEYFILE) == BST_CHECKED;
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
			crypto_unlock_task task;
			task.key = crypto_gather_key (dlg);
			if (task.key.empty ())
				return TRUE;	/* nothing entered; keep waiting */

			/* Unlock on the grub thread; the dialog stays up and the
			   result comes back through WM_APP_TASK_DONE.  Disable
			   the inputs so it cannot be submitted twice and the KDF
			   (Argon2 can be slow) does not look ignored.  */
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

/* VeraCrypt / TrueCrypt */

namespace
{

HWND g_vc;	/* unlock dialog, null when closed */
UINT g_seq_vc;	/* in-flight veracrypt_unlock task */
std::string g_vc_dev;
std::string g_vc_newdev;
std::vector<std::wstring> g_vc_keyfiles;

/* The PRF combo, in the order VeraCrypt lists them; index 0 is "auto".  */
const int VC_PRF_ORDER[] =
{
	BACKEND_VC_PRF_AUTO,
	BACKEND_VC_PRF_SHA512,
	BACKEND_VC_PRF_WHIRLPOOL,
	BACKEND_VC_PRF_SHA256,
	BACKEND_VC_PRF_RIPEMD160,
	BACKEND_VC_PRF_STREEBOG,
};
const wchar_t *const VC_PRF_NAMES[] =
{
	nullptr,	/* filled from IDS_VC_PRF_AUTO */
	L"SHA-512", L"Whirlpool", L"SHA-256", L"RIPEMD-160", L"Streebog",
};

/*
 * Fold a key file into the pool:
 * run a CRC-32 over the first megabyte and add the four bytes of
 * the running register (not the finished checksum) into successive pool bytes,
 * wrapping at the end of the pool.
 */
bool
vc_apply_keyfile (const std::wstring &path, std::vector<unsigned char> &pool)
{
	static UINT32 tab[256];
	static bool tab_ready;

	if (!tab_ready)
	{
		for (UINT32 i = 0; i < 256; i++)
		{
			UINT32 c = i;
			for (int k = 0; k < 8; k++)
				c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
			tab[i] = c;
		}
		tab_ready = true;
	}

	HANDLE h = CreateFileW (path.c_str (), GENERIC_READ, FILE_SHARE_READ,
				nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE)
		return false;

	UINT32 crc = 0xffffffffu;
	size_t pos = 0, total = 0;
	std::vector<char> buf (65536);
	DWORD got = 0;
	bool ok = true;

	while (total < (1u << 20) && ReadFile (h, buf.data (), (DWORD) buf.size (), &got, nullptr) && got)
	{
		for (DWORD i = 0; i < got; i++)
		{
			crc = tab[(crc ^ (unsigned char) buf[i]) & 0xff] ^ (crc >> 8);
			pool[pos++] += (unsigned char) (crc >> 24);
			pool[pos++] += (unsigned char) (crc >> 16);
			pool[pos++] += (unsigned char) (crc >> 8);
			pool[pos++] += (unsigned char) crc;
			if (pos >= pool.size ())
				pos = 0;
			if (++total >= (1u << 20))
				break;
		}
	}
	CloseHandle (h);

	/* VeraCrypt rejects an empty key file rather than ignoring it.  */
	if (total == 0)
		ok = false;
	return ok;
}

/*
 * Build the secret the volume header is unlocked with.  Without key files
 * that is the passphrase as typed; with them it is the 64 or 128 byte pool
 * the passphrase was mixed into, which is what VeraCrypt hands to PBKDF2.
 */
std::vector<char>
vc_gather_key (HWND dlg)
{
	wchar_t pass[256] = {};
	GetDlgItemTextW (dlg, IDC_VC_PASS, pass, 256);
	std::string u = narrow (pass);
	SecureZeroMemory (pass, sizeof (pass));

	/* VeraCrypt's own limit; longer passphrases cannot open any volume.  */
	if (u.size () > 128)
		u.resize (128);

	if (g_vc_keyfiles.empty ())
		return std::vector<char> (u.begin (), u.end ());

	std::vector<unsigned char> pool (u.size () <= 64 ? 64 : 128, 0);
	std::copy (u.begin (), u.end (), pool.begin ());
	for (const std::wstring &kf : g_vc_keyfiles)
		if (!vc_apply_keyfile (kf, pool))
			return {};

	return std::vector<char> (pool.begin (), pool.end ());
}

void
vc_show_keyfiles (HWND dlg)
{
	std::wstring s;

	for (const std::wstring &kf : g_vc_keyfiles)
	{
		size_t slash = kf.find_last_of (L'\\');
		if (!s.empty ())
			s += L"; ";
		s += slash == std::wstring::npos ? kf : kf.substr (slash + 1);
	}
	SetDlgItemTextW (dlg, IDC_VC_KEYFILES, s.c_str ());
	EnableWindow (GetDlgItem (dlg, IDC_VC_CLEARKEYS), !g_vc_keyfiles.empty ());
}

void
vc_enable_inputs (HWND dlg, BOOL on)
{
	const int ids[] =
	{
		IDOK, IDC_VC_PASS, IDC_VC_BROWSE, IDC_VC_CLEARKEYS, IDC_VC_PIM,
		IDC_VC_PRF, IDC_VC_TRUECRYPT, IDC_VC_HIDDEN, IDC_VC_BACKUP,
	};

	for (int id : ids)
		EnableWindow (GetDlgItem (dlg, id), on);
	if (on)
		EnableWindow (GetDlgItem (dlg, IDC_VC_CLEARKEYS), !g_vc_keyfiles.empty ());
	/* TrueCrypt volumes have no PIM, so that field follows the checkbox.  */
	if (on && IsDlgButtonChecked (dlg, IDC_VC_TRUECRYPT) == BST_CHECKED)
		EnableWindow (GetDlgItem (dlg, IDC_VC_PIM), FALSE);
}

/* Read the PIM box.
   Returns false (and leaves *pim alone) if it holds
   something that is not a number in range.  */
bool
vc_read_pim (HWND dlg, UINT *pim)
{
	wchar_t buf[16] = {};
	GetDlgItemTextW (dlg, IDC_VC_PIM, buf, 16);
	if (!buf[0])
	{
		*pim = 0;
		return true;
	}

	unsigned long v = 0;
	for (const wchar_t *p = buf; *p; p++)
	{
		if (*p < L'0' || *p > L'9')
			return false;
		v = v * 10 + (unsigned long) (*p - L'0');
		if (v > 2147468ul)	/* VeraCrypt's MAX_PIM_VALUE */
			return false;
	}
	*pim = (UINT) v;
	return true;
}

INT_PTR CALLBACK
vc_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		wchar_t title[128];
		std::wstring autos = res_str (IDS_VC_PRF_AUTO);

		g_vc = dlg;
		swprintf (title, 128, res_str (IDS_FMT_VC_TITLE).c_str (), widen (g_vc_dev).c_str ());
		SetWindowTextW (dlg, title);
		SetDlgItemTextW (dlg, IDC_VC_INFO, widen (g_vc_dev).c_str ());

		for (size_t i = 0; i < ARRAYSIZE (VC_PRF_ORDER); i++)
			SendDlgItemMessageW (dlg, IDC_VC_PRF, CB_ADDSTRING, 0,
				(LPARAM) (i == 0 ? autos.c_str () : VC_PRF_NAMES[i]));
		SendDlgItemMessageW (dlg, IDC_VC_PRF, CB_SETCURSEL, 0, 0);

		vc_show_keyfiles (dlg);
		SendDlgItemMessageW (dlg, IDC_VC_PROGRESS, PBM_SETRANGE32, 0, 100);
		SetFocus (GetDlgItem (dlg, IDC_VC_PASS));
		return FALSE;	/* focus was set explicitly */
	}
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDC_VC_TRUECRYPT:
			/* TrueCrypt volumes predate the PIM.  */
			EnableWindow (GetDlgItem (dlg, IDC_VC_PIM),
				IsDlgButtonChecked (dlg, IDC_VC_TRUECRYPT) != BST_CHECKED);
			return TRUE;
		case IDC_VC_BROWSE:
		{
			/* Several key files may be combined, so allow a multi
			   selection; the buffer holds the directory then the
			   names, each NUL terminated.  */
			std::vector<wchar_t> path (32768, 0);
			OPENFILENAMEW ofn = { sizeof (ofn) };
			std::wstring t = res_str (IDS_VC_KEYFILES);

			ofn.hwndOwner = dlg;
			ofn.lpstrFile = path.data ();
			ofn.nMaxFile = (DWORD) path.size ();
			ofn.lpstrTitle = t.c_str ();
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST
				| OFN_ALLOWMULTISELECT | OFN_EXPLORER;
			if (!GetOpenFileNameW (&ofn))
				return TRUE;

			const wchar_t *p = path.data ();
			std::wstring dir = p;
			p += dir.size () + 1;
			if (!*p)
			{
				g_vc_keyfiles.push_back (dir);	/* single selection */
			}
			else
			{
				if (!dir.empty () && dir.back () != L'\\')
					dir += L'\\';
				for (; *p; p += wcslen (p) + 1)
					g_vc_keyfiles.push_back (dir + p);
			}
			vc_show_keyfiles (dlg);
			return TRUE;
		}
		case IDC_VC_CLEARKEYS:
			g_vc_keyfiles.clear ();
			vc_show_keyfiles (dlg);
			return TRUE;
		case IDOK:
		{
			veracrypt_unlock_task task;
			UINT pim = 0;

			if (!vc_read_pim (dlg, &pim))
			{
				MessageBoxW (dlg, res_str (IDS_VC_BADPIM).c_str (),
					nullptr, MB_ICONWARNING | MB_OK);
				SetFocus (GetDlgItem (dlg, IDC_VC_PIM));
				return TRUE;
			}

			task.key = vc_gather_key (dlg);
			if (task.key.empty ())
				return TRUE;	/* nothing entered; keep waiting */

			task.path = g_vc_dev;
			task.pim = pim;
			task.prf = VC_PRF_ORDER[SendDlgItemMessageW (dlg, IDC_VC_PRF,
								    CB_GETCURSEL, 0, 0)];
			if (IsDlgButtonChecked (dlg, IDC_VC_TRUECRYPT) == BST_CHECKED)
			{
				task.vc_flags |= BACKEND_VC_TRUECRYPT;
				task.pim = 0;
			}
			if (IsDlgButtonChecked (dlg, IDC_VC_HIDDEN) == BST_CHECKED)
				task.vc_flags |= BACKEND_VC_HIDDEN;
			if (IsDlgButtonChecked (dlg, IDC_VC_BACKUP) == BST_CHECKED)
				task.vc_flags |= BACKEND_VC_BACKUP;

			/* Trying every PRF runs five key derivations of up to
			   half a million iterations each, so this can take tens
			   of seconds; the progress bar is driven by the KDF.  */
			vc_enable_inputs (dlg, FALSE);
			SendDlgItemMessageW (dlg, IDC_VC_PROGRESS, PBM_SETPOS, 0, 0);
			ShowWindow (GetDlgItem (dlg, IDC_VC_PROGRESS), SW_SHOW);
			g_seq_vc = backend_post (std::move (task));
			return TRUE;
		}
		case IDCANCEL:
			g_vc = nullptr;
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

} // namespace

/* Called from WM_APP_TASK_DONE when a veracrypt_unlock finishes.  */
void
veracrypt_unlock_done (backend_result *res)
{
	if (!g_vc || res->seq != g_seq_vc)
		return;
	if (!res->error.empty ())
	{
		vc_enable_inputs (g_vc, TRUE);
		ShowWindow (GetDlgItem (g_vc, IDC_VC_PROGRESS), SW_HIDE);
		MessageBoxW (g_vc, res_str (IDS_VC_BADKEY).c_str (), nullptr, MB_ICONWARNING | MB_OK);
		SetFocus (GetDlgItem (g_vc, IDC_VC_PASS));
		return;
	}
	g_vc_newdev = res->path;
	HWND dlg = g_vc;
	g_vc = nullptr;
	EndDialog (dlg, 1);
}

void
prompt_unlock_veracrypt (const std::string &devname)
{
	g_vc_dev = devname;
	g_vc_newdev.clear ();
	g_vc_keyfiles.clear ();

	INT_PTR r;
	{
		modal_scope hold;
		r = DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_VERACRYPT), g_main, vc_dlg_proc, 0);
	}
	if (r == 1 && !g_vc_newdev.empty ())
	{
		refresh ();
		navigate ("(" + g_vc_newdev + ")/");
	}
}

/* WM_APP_TASK_PROGRESS routing; true = the update was this dialog's.  */
bool
veracrypt_on_progress (backend_progress *p)
{
	if (!g_vc || p->seq != g_seq_vc)
		return false;
	SendDlgItemMessageW (g_vc, IDC_VC_PROGRESS, PBM_SETPOS, (WPARAM) p->percent, 0);
	return true;
}

/* Plain dm-crypt */

namespace
{

HWND g_pm;	/* mount dialog, null when closed */
UINT g_seq_pm;	/* in-flight plainmount_unlock task */
std::string g_pm_dev;
std::string g_pm_newdev;

/* cryptsetup's own default is aes-xts-plain64 with a 512 bit key.  */
const wchar_t *const PM_CIPHERS[] =
{
	L"aes-xts-plain64", L"aes-cbc-essiv:sha256", L"aes-cbc-plain64",
	L"aes-cbc-plain", L"serpent-xts-plain64", L"twofish-xts-plain64",
	L"camellia-xts-plain64", L"kuznyechik-xts-plain64", L"aes-lrw-benbi",
	L"aes-ecb",
};

/* Index 0 means "no hashing", which the backend spells "plain".  */
const wchar_t *const PM_HASHES[] =
{
	nullptr,	/* filled from IDS_PM_HASH_NONE */
	L"ripemd160", L"sha1", L"sha256", L"sha512", L"whirlpool", L"stribog512",
};

const wchar_t *const PM_KEYBITS[] = { L"512", L"256", L"128", L"192", L"1024" };
const wchar_t *const PM_SECTORS[] = { L"512", L"1024", L"2048", L"4096" };

/* Read a decimal control, returning false when it is empty or malformed.  */
bool
pm_read_number (HWND dlg, int id, UINT64 max, UINT64 *out)
{
	wchar_t buf[24] = {};
	UINT64 v = 0;

	GetDlgItemTextW (dlg, id, buf, 24);
	if (!buf[0])
		return false;
	for (const wchar_t *p = buf; *p; p++)
	{
		if (*p < L'0' || *p > L'9')
			return false;
		v = v * 10 + (UINT64) (*p - L'0');
		if (v > max)
			return false;
	}
	*out = v;
	return true;
}

/*
 * The secret.  A passphrase goes to the backend as typed; a key file is read
 * here, because the caller is the one that knows the key file offset, and
 * exactly key_bits/8 bytes of it become the volume key.
 */
std::vector<char>
pm_gather_key (HWND dlg, UINT key_bits, bool *is_keyfile)
{
	*is_keyfile = IsDlgButtonChecked (dlg, IDC_PM_USEKEYFILE) == BST_CHECKED;
	if (!*is_keyfile)
	{
		wchar_t pass[512] = {};
		GetDlgItemTextW (dlg, IDC_PM_PASS, pass, 512);
		std::string u = narrow (pass);
		SecureZeroMemory (pass, sizeof (pass));
		return std::vector<char> (u.begin (), u.end ());
	}

	wchar_t path[MAX_PATH] = {};
	GetDlgItemTextW (dlg, IDC_PM_KEYFILE, path, MAX_PATH);
	if (!path[0])
		return {};

	UINT64 off = 0;
	wchar_t offbuf[24] = {};
	GetDlgItemTextW (dlg, IDC_PM_KEYOFFSET, offbuf, 24);
	if (offbuf[0] && !pm_read_number (dlg, IDC_PM_KEYOFFSET, ~0ULL / 2, &off))
		return {};

	HANDLE h = CreateFileW (path, GENERIC_READ, FILE_SHARE_READ, nullptr,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE)
		return {};

	LARGE_INTEGER li;
	li.QuadPart = (LONGLONG) off;
	std::vector<char> key (key_bits / 8);
	DWORD got = 0;
	bool ok = SetFilePointerEx (h, li, nullptr, FILE_BEGIN)
		&& ReadFile (h, key.data (), (DWORD) key.size (), &got, nullptr)
		&& got == key.size ();
	CloseHandle (h);
	return ok ? key : std::vector<char> ();
}

void
pm_enable_inputs (HWND dlg, BOOL on)
{
	BOOL kf = IsDlgButtonChecked (dlg, IDC_PM_USEKEYFILE) == BST_CHECKED;
	const int ids[] =
	{
		IDOK, IDC_PM_CIPHER, IDC_PM_HASH, IDC_PM_KEYBITS, IDC_PM_SECTOR,
		IDC_PM_OFFSET, IDC_PM_SKIP, IDC_PM_USEKEYFILE,
	};

	for (int id : ids)
		EnableWindow (GetDlgItem (dlg, id), on);
	EnableWindow (GetDlgItem (dlg, IDC_PM_PASS), on && !kf);
	EnableWindow (GetDlgItem (dlg, IDC_PM_KEYFILE), on && kf);
	EnableWindow (GetDlgItem (dlg, IDC_PM_BROWSE), on && kf);
	EnableWindow (GetDlgItem (dlg, IDC_PM_KEYOFFSET), on && kf);
	/* Hashing applies to a passphrase only; a key file is the key.  */
	EnableWindow (GetDlgItem (dlg, IDC_PM_HASH), on && !kf);
}

INT_PTR CALLBACK
pm_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		wchar_t title[128];
		std::wstring none = res_str (IDS_PM_HASH_NONE);

		g_pm = dlg;
		swprintf (title, 128, res_str (IDS_FMT_PM_TITLE).c_str (), widen (g_pm_dev).c_str ());
		SetWindowTextW (dlg, title);
		SetDlgItemTextW (dlg, IDC_PM_INFO, widen (g_pm_dev).c_str ());

		for (const wchar_t *c : PM_CIPHERS)
			SendDlgItemMessageW (dlg, IDC_PM_CIPHER, CB_ADDSTRING, 0, (LPARAM) c);
		SetDlgItemTextW (dlg, IDC_PM_CIPHER, PM_CIPHERS[0]);

		for (size_t i = 0; i < ARRAYSIZE (PM_HASHES); i++)
			SendDlgItemMessageW (dlg, IDC_PM_HASH, CB_ADDSTRING, 0,
				(LPARAM) (i == 0 ? none.c_str () : PM_HASHES[i]));
		SendDlgItemMessageW (dlg, IDC_PM_HASH, CB_SETCURSEL, 1, 0);	/* ripemd160 */

		for (const wchar_t *k : PM_KEYBITS)
			SendDlgItemMessageW (dlg, IDC_PM_KEYBITS, CB_ADDSTRING, 0, (LPARAM) k);
		SetDlgItemTextW (dlg, IDC_PM_KEYBITS, PM_KEYBITS[0]);

		for (const wchar_t *s : PM_SECTORS)
			SendDlgItemMessageW (dlg, IDC_PM_SECTOR, CB_ADDSTRING, 0, (LPARAM) s);
		SendDlgItemMessageW (dlg, IDC_PM_SECTOR, CB_SETCURSEL, 0, 0);

		pm_enable_inputs (dlg, TRUE);
		SetFocus (GetDlgItem (dlg, IDC_PM_PASS));
		return FALSE;	/* focus was set explicitly */
	}
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDC_PM_USEKEYFILE:
			pm_enable_inputs (dlg, TRUE);
			return TRUE;
		case IDC_PM_BROWSE:
		{
			wchar_t path[MAX_PATH] = {};
			OPENFILENAMEW ofn = { sizeof (ofn) };
			std::wstring t = res_str (IDS_PM_KEYFILE);

			ofn.hwndOwner = dlg;
			ofn.lpstrFile = path;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrTitle = t.c_str ();
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			if (GetOpenFileNameW (&ofn))
				SetDlgItemTextW (dlg, IDC_PM_KEYFILE, path);
			return TRUE;
		}
		case IDOK:
		{
			plainmount_unlock_task task;
			wchar_t cipher[128] = {}, sector[24] = {};
			UINT64 key_bits = 0;
			bool is_keyfile = false;
			int hash_idx;

			UINT64 offset = 0, skip = 0;

			GetDlgItemTextW (dlg, IDC_PM_CIPHER, cipher, 128);
			GetDlgItemTextW (dlg, IDC_PM_SECTOR, sector, 24);
			/* Both offsets are optional and default to 0.  */
			if (GetWindowTextLengthW (GetDlgItem (dlg, IDC_PM_OFFSET)) > 0
				&& !pm_read_number (dlg, IDC_PM_OFFSET, ~0ULL / 512, &offset))
				offset = ~0ULL;
			if (GetWindowTextLengthW (GetDlgItem (dlg, IDC_PM_SKIP)) > 0
				&& !pm_read_number (dlg, IDC_PM_SKIP, ~0ULL / 512, &skip))
				skip = ~0ULL;
			/* A key size that is not a whole number of bytes, or a
			   cipher without a mode, cannot be mounted at all.  */
			if (!cipher[0] || !wcschr (cipher, L'-')
				|| !pm_read_number (dlg, IDC_PM_KEYBITS, 1024, &key_bits)
				|| key_bits == 0 || (key_bits % 8) != 0
				|| offset == ~0ULL || skip == ~0ULL)
			{
				MessageBoxW (dlg, res_str (IDS_PM_BADPARAM).c_str (),
					nullptr, MB_ICONWARNING | MB_OK);
				return TRUE;
			}

			task.key = pm_gather_key (dlg, (UINT) key_bits, &is_keyfile);
			if (task.key.empty ())
				return TRUE;	/* nothing usable entered */

			hash_idx = (int) SendDlgItemMessageW (dlg, IDC_PM_HASH, CB_GETCURSEL, 0, 0);
			task.path = g_pm_dev;
			task.cipher = narrow (cipher);
			task.hash = hash_idx <= 0 ? "plain" : narrow (PM_HASHES[hash_idx]);
			task.key_bits = (UINT) key_bits;
			task.sector_size = (UINT) _wtoi (sector);
			task.offset = offset;
			task.skip = skip;
			task.keyfile = is_keyfile;

			pm_enable_inputs (dlg, FALSE);
			g_seq_pm = backend_post (std::move (task));
			return TRUE;
		}
		case IDCANCEL:
			g_pm = nullptr;
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

} // namespace

/* Called from WM_APP_TASK_DONE when a plainmount_unlock finishes.  */
void
plainmount_done (backend_result *res)
{
	if (!g_pm || res->seq != g_seq_pm)
		return;
	if (!res->error.empty ())
	{
		pm_enable_inputs (g_pm, TRUE);
		MessageBoxW (g_pm, res_str (IDS_PM_FAILED).c_str (), nullptr, MB_ICONWARNING | MB_OK);
		return;
	}
	g_pm_newdev = res->path;
	HWND dlg = g_pm;
	g_pm = nullptr;
	EndDialog (dlg, 1);
}

void
prompt_plainmount (const std::string &devname)
{
	g_pm_dev = devname;
	g_pm_newdev.clear ();

	INT_PTR r;
	{
		modal_scope hold;
		r = DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_PLAINMOUNT), g_main, pm_dlg_proc, 0);
	}
	if (r == 1 && !g_pm_newdev.empty ())
	{
		refresh ();
		navigate ("(" + g_pm_newdev + ")/");
	}
}

void
prompt_unlock (const std::string &devname, const std::string &uuid)
{
	g_crypto_dev = devname;
	g_crypto_uuid = uuid;
	g_crypto_newdev.clear ();

	INT_PTR r;
	{
		modal_scope hold;
		r = DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_CRYPTO), g_main, crypto_dlg_proc, 0);
	}
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
