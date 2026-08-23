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
#include <shellapi.h>

#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"
#include "version.h"

namespace
{

HWND g_about;	/* About dialog, null when closed */
HWND g_support;	/* supported-features dialog */

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
	L"WinFsp - <https://github.com/winfsp/winfsp>\r\n"
	L"file - <http://www.darwinsys.com/file>\r\n"
	L"stb_image - <https://github.com/nothings/stb>\r\n"
	L"NanoSVG - <https://github.com/memononen/nanosvg>\r\n"
	L"tiny-webp - <https://github.com/justus2510/tiny-webp>\r\n"
	L"MD4C - <https://github.com/mity/md4c>\r\n"
	L"lz4 - <http://www.lz4.org/>\r\n"
	L"Zstandard - <http://www.zstd.net/>\r\n"
	L"bzip2 - <https://www.sourceware.org/bzip2>\r\n"
	L"lzfse - <https://github.com/lzfse/lzfse>\r\n"
	L"wimboot - <https://ipxe.org/wimboot>\r\n"
	L"VirtualBox - <https://www.virtualbox.org/>\r\n"
	L"7-Zip - <https://www.7-zip.org/>\r\n"
	L"Yxml - <https://dev.yorhel.nl/yxml>\r\n";

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
	if (amp > 0 && s[amp - 1] == L'(' && amp + 2 < s.size () && s[amp + 2] == L')')
		s.erase (amp - 1, 4);
	else
		s.erase (amp, 1);
	return s;
}

/* The app icon at 32 px for this dialog's own DPI.  The only metric the
   About box scales, so the DPI is read from the window each time rather
   than kept beside it; STM_SETICON hands back the icon it replaces, and
   that one is ours to free.  */
void
about_apply_dpi (HWND dlg)
{
	int size = dpi_scale (dpi_for_window (dlg), 32);
	HICON icon = (HICON) LoadImageW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDI_APP), IMAGE_ICON, size, size, 0);
	HICON prev = (HICON) SendDlgItemMessageW (dlg, IDC_ABOUT_ICON, STM_SETICON, (WPARAM) icon, 0);

	if (prev)
		DestroyIcon (prev);
}

INT_PTR CALLBACK
about_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		g_about = dlg;
		SetWindowTextW (dlg, menu_caption (IDS_MENU_ABOUT).c_str ());
		about_apply_dpi (dlg);

		std::wstring name = L"FsRover " + widen (ROVER_VERSION_STR) + L" (" ROVER_ARCH_W L")";
		SetDlgItemTextW (dlg, IDC_ABOUT_NAME, name.c_str ());
		SetDlgItemTextW (dlg, IDC_ABOUT_CREDITS_LABEL, res_str (IDS_ABOUT_CREDITS).c_str ());
		SetDlgItemTextW (dlg, IDC_ABOUT_CREDITS, k_credits);
		/* Keep focus off the edit: the dialog manager select-alls
		   an edit it focuses (DLGC_HASSETSEL).  */
		SetFocus (GetDlgItem (dlg, IDOK));
		return FALSE;	/* focus was set explicitly */
	}
	case WM_APP_DPI_CHANGED:
		about_apply_dpi (dlg);
		return TRUE;
	case WM_DPICHANGED:
		dpi_take_suggested (dlg, lp);
		PostMessageW (dlg, WM_APP_DPI_CHANGED, 0, 0);
		return FALSE;	/* the dialog manager still rescales the control fonts */
	case WM_NOTIFY:
	{
		/* The project link.  Its target is the href baked into the
		   dialog template, so there is nothing to confirm the way the
		   markdown viewer does for document links.  */
		const NMHDR *nm = (const NMHDR *) lp;

		if (nm->idFrom == IDC_ABOUT_URL && (nm->code == NM_CLICK || nm->code == NM_RETURN))
		{
			ShellExecuteW (dlg, L"open", ((const NMLINK *) lp)->item.szUrl,
				       nullptr, nullptr, SW_SHOWNORMAL);
			return TRUE;
		}
		break;
	}
	case WM_COMMAND:
		if (LOWORD (wp) == IDC_ABOUT_ICON && HIWORD (wp) == STN_CLICKED)
		{
			show_rover_game (dlg);
			return TRUE;
		}
		if (LOWORD (wp) == IDOK || LOWORD (wp) == IDCANCEL)
		{
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	case WM_DESTROY:
	{
		/* The icon set with STM_SETICON is ours to free.  */
		HICON icon = (HICON) SendDlgItemMessageW (dlg, IDC_ABOUT_ICON, STM_GETICON, 0, 0);
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
		SetDlgItemTextW (dlg, IDC_SUPPORT_TEXT, (const wchar_t *) lp);
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
	modal_scope hold;

	DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_ABOUT), g_main, about_dlg_proc, 0);
}

/* The bundled help page, shown by the markdown viewer (which holds the
   modal scope itself).  It is an RCDATA resource, so the load only
   fails on a corrupt executable; a help.md sitting next to the
   executable wins over it, which is how a release can carry a
   corrected page without a rebuild.  */
void
show_help_doc (void)
{
	md_document doc;

	if (!md_load_help (L"help.md", IDR_HELP_MD, &doc))
		return;
	doc.title = menu_caption (IDS_MENU_HELPDOC);
	show_markdown_doc (doc);
}

/* The whole list is one string resource: the key names are not
   translated, only the actions after them.  */
void
show_shortcuts (void)
{
	modal_scope hold;

	MessageBoxW (g_main, res_str (IDS_KEY_LIST).c_str (), menu_caption (IDS_MENU_SHORTCUTS).c_str (), MB_ICONINFORMATION | MB_OK);
}

void
show_support (void)
{
	backend_support s = backend_get_support ();
	std::wstring text = support_section (IDS_SUPPORT_FS, s.fs)
		+ support_section (IDS_SUPPORT_PARTMAP, s.partmap)
		+ support_section (IDS_SUPPORT_DISKFILTER, s.diskfilter)
		+ support_section (IDS_SUPPORT_CRYPTODISK, s.cryptodisk)
		+ support_section (IDS_SUPPORT_IOFILTER, s.iofilter);

	modal_scope hold;
	DialogBoxParamW (GetModuleHandleW (nullptr),
		MAKEINTRESOURCEW (IDD_SUPPORT), g_main, support_dlg_proc, (LPARAM) text.c_str ());
}
