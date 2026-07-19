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

/* Help menu dialogs: the About box (logo, version, third-party
   credits) and the supported-features list.  The feature names are
   fetched synchronously from the backend thread; the grub
   registration lists are fixed after init, so the wait is only ever
   one task-queue checkpoint.  */

#include <windows.h>

#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"
#include "version.h"

HWND g_about;	/* modal About dialog, null when closed */
HWND g_support;	/* modal supported-features dialog */

namespace
{

#if defined(_M_X64)
#define ROVER_ARCH_W	L"x64"
#elif defined(_M_IX86)
#define ROVER_ARCH_W	L"x86"
#elif defined(_M_ARM64)
#define ROVER_ARCH_W	L"ARM64"
#endif

/* Shipped third-party code and the references the ports follow; the
   list is ASCII and identical in every UI language.  */
const wchar_t k_credits[] =
	L"GNU GRUB - <https://www.gnu.org/software/grub> \r\n"
	L"Dokany - <https://github.com/dokan-dev/dokany>\r\n"
	L"file - <http://www.darwinsys.com/file>\r\n"
	L"stb_image - <https://github.com/nothings/stb>\r\n"
	L"lz4 - <http://www.lz4.org/>\r\n"
	L"Zstandard - <http://www.zstd.net/>\r\n"
	L"bzip2 - <https://www.sourceware.org/bzip2>\r\n"
	L"lzfse - <https://github.com/lzfse/lzfse>\r\n"
	L"wimboot - <https://ipxe.org/wimboot>\r\n"
	L"VirtualBox - <https://www.virtualbox.org/>\r\n";

/* Menu label -> window caption: drop the mnemonic.  CJK labels carry
   it as a "(&A)" suffix, which goes away whole; otherwise only the
   ampersand is removed.  */
std::wstring
menu_caption (UINT id)
{
	std::wstring s = res_str (id);
	size_t amp = s.find (L'&');

	if (amp == std::wstring::npos)
		return s;
	if (amp > 0 && s[amp - 1] == L'(' && amp + 2 < s.size ()
	    && s[amp + 2] == L')')
		s.erase (amp - 1, 4);
	else
		s.erase (amp, 1);
	return s;
}

INT_PTR CALLBACK
about_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		g_about = dlg;
		SetWindowTextW (dlg, menu_caption (IDS_MENU_ABOUT).c_str ());

		int size = dpi_scale (32);
		HICON icon = (HICON) LoadImageW (GetModuleHandleW (nullptr),
						 MAKEINTRESOURCEW (IDI_APP),
						 IMAGE_ICON, size, size, 0);
		SendDlgItemMessageW (dlg, IDC_ABOUT_ICON, STM_SETICON, (WPARAM) icon, 0);

		std::wstring name = L"FsRover " + widen (ROVER_VERSION_STR) + L" (" ROVER_ARCH_W L")";
		SetDlgItemTextW (dlg, IDC_ABOUT_NAME, name.c_str ());
		SetDlgItemTextW (dlg, IDC_ABOUT_CREDITS_LABEL,
				 res_str (IDS_ABOUT_CREDITS).c_str ());
		SetDlgItemTextW (dlg, IDC_ABOUT_CREDITS, k_credits);
		/* Keep focus off the edit: the dialog manager select-alls
		   an edit it focuses (DLGC_HASSETSEL).  */
		SetFocus (GetDlgItem (dlg, IDOK));
		return FALSE;	/* focus was set explicitly */
	}
	case WM_COMMAND:
		if (LOWORD (wp) == IDOK || LOWORD (wp) == IDCANCEL)
		{
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	case WM_DESTROY:
	{
		/* The icon set with STM_SETICON is ours to free.  */
		HICON icon = (HICON) SendDlgItemMessageW (dlg, IDC_ABOUT_ICON,
							  STM_GETICON, 0, 0);
		if (icon)
			DestroyIcon (icon);
		g_about = nullptr;
		break;
	}
	}
	return FALSE;
}

INT_PTR CALLBACK
support_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		g_support = dlg;
		SetWindowTextW (dlg, menu_caption (IDS_MENU_SUPPORT).c_str ());
		SetDlgItemTextW (dlg, IDC_SUPPORT_TEXT,
				 (const wchar_t *) lp);
		/* Keep focus off the edit: the dialog manager select-alls
		   an edit it focuses (DLGC_HASSETSEL).  */
		SetFocus (GetDlgItem (dlg, IDOK));
		return FALSE;	/* focus was set explicitly */
	case WM_COMMAND:
		if (LOWORD (wp) == IDOK || LOWORD (wp) == IDCANCEL)
		{
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	case WM_DESTROY:
		g_support = nullptr;
		break;
	}
	return FALSE;
}

/* "Header (N):" line followed by the comma-separated names.  */
std::wstring
support_section (UINT title_id, const std::vector<std::string> &names)
{
	std::wstring out = res_str (title_id);
	wchar_t count[16];

	swprintf (count, 16, L" (%d):\r\n", (int) names.size ());
	out += count;
	for (size_t i = 0; i < names.size (); i++)
	{
		if (i)
			out += L", ";
		out += widen (names[i]);
	}
	out += L"\r\n\r\n";
	return out;
}

} // namespace

void
show_about (void)
{
	DialogBoxParamW (GetModuleHandleW (nullptr),
			 MAKEINTRESOURCEW (IDD_ABOUT), g_main,
			 about_dlg_proc, 0);
}

void
show_support (void)
{
	backend_support s = backend_get_support ();
	std::wstring text = support_section (IDS_SUPPORT_FS, s.fs)
		+ support_section (IDS_SUPPORT_PARTMAP, s.partmap)
		+ support_section (IDS_SUPPORT_DISKFILTER, s.diskfilter)
		+ support_section (IDS_SUPPORT_IOFILTER, s.iofilter);

	DialogBoxParamW (GetModuleHandleW (nullptr),
		MAKEINTRESOURCEW (IDD_SUPPORT), g_main, support_dlg_proc, (LPARAM) text.c_str ());
}
