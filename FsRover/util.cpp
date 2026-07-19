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

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <time.h>

#include <string>

#include "gui.h"

std::wstring
window_text (HWND wnd)
{
	std::wstring text ((size_t) GetWindowTextLengthW (wnd), L'\0');
	GetWindowTextW (wnd, text.data (), (int) text.size () + 1);
	return text;
}

/* Localized string from the resource stringtable; the language block
   is selected once by init_language().  */
std::wstring
res_str (UINT id)
{
	const wchar_t *p = nullptr;
	int len = LoadStringW (GetModuleHandleW (nullptr), id, (LPWSTR) &p, 0);

	if (len <= 0)
		return {};
	return std::wstring (p, (size_t) len);
}

/* Pin the thread UI language to one of the shipped stringtables so
   LoadStringW resolves deterministically (en-US fallback).  */
void
init_language (void)
{
	LANGID lang = GetUserDefaultUILanguage ();

	switch (PRIMARYLANGID (lang))
	{
	case LANG_CHINESE:
		switch (SUBLANGID (lang))
		{
		case SUBLANG_CHINESE_TRADITIONAL:
		case SUBLANG_CHINESE_HONGKONG:
		case SUBLANG_CHINESE_MACAU:
			lang = MAKELANGID (LANG_CHINESE, SUBLANG_CHINESE_TRADITIONAL);
			break;
		default:
			lang = MAKELANGID (LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED);
			break;
		}
		break;
	case LANG_JAPANESE:
		lang = MAKELANGID (LANG_JAPANESE, SUBLANG_DEFAULT);
		break;
	default:
		lang = MAKELANGID (LANG_ENGLISH, SUBLANG_ENGLISH_US);
		break;
	}
	SetThreadUILanguage (lang);
}

HICON
load_system_icon (const wchar_t* dll, int id, int size)
{
	wchar_t path[MAX_PATH];
	HICON icon = nullptr;

	GetSystemDirectoryW (path, MAX_PATH);
	wcscat_s (path, dll);
	if (SHDefExtractIconW (path, -id, 0, &icon, nullptr, (UINT) size) != S_OK)
		return nullptr;
	return icon;
}

HIMAGELIST
icon_list (const wchar_t* dll, const int *ids, int count, int size)
{
	HIMAGELIST himl = ImageList_Create (size, size, ILC_COLOR32 | ILC_MASK, count, 0);

	for (int i = 0; i < count; i++)
	{
		HICON icon = load_system_icon (dll, ids[i], size);

		ImageList_AddIcon (himl, icon);
		if (icon)
			DestroyIcon (icon);
	}
	return himl;
}

/* One-icon image list for a button, or null if the icon does not
   exist in this shell32 (the button keeps its text).  */
HIMAGELIST
button_icons (const wchar_t* dll, int id, int size)
{
	HICON icon = load_system_icon (dll, id, size);

	if (!icon)
		return nullptr;
	HIMAGELIST himl = ImageList_Create (size, size, ILC_COLOR32 | ILC_MASK, 1, 0);
	ImageList_AddIcon (himl, icon);
	DestroyIcon (icon);
	return himl;
}

void
set_button_icon (HWND btn, HIMAGELIST himl)
{
	BUTTON_IMAGELIST bil = {};

	if (!himl)
		return;
	bil.himl = himl;
	bil.margin.left = 6;
	bil.margin.right = 2;
	bil.uAlign = BUTTON_IMAGELIST_ALIGN_LEFT;
	SendMessageW (btn, BCM_SETIMAGELIST, 0, (LPARAM) &bil);
}

/*
 * Per-monitor DPI.  The window is PerMonitorV2 aware,
 * so every pixel metric is authored at 96 DPI and scaled through dpi_scale()
 * for the monitor the window currently lives on; moving to a differently
 * scaled monitor arrives as WM_DPICHANGED, which refreshes g_dpi and rebuilds
 * the DPI-dependent GDI objects.  The scaling helpers (GetDpiForWindow,
 * GetSystemMetricsForDpi, SystemParametersInfoForDpi) are Windows 10 1607+,
 * so they are resolved at runtime and degrade to the system-DPI equivalents
 * on the older Windows the app still supports.
 */

UINT g_dpi = 96;	/* main-window DPI; drives all layout scaling */

namespace
{

using GetDpiForWindow_t = UINT (WINAPI *) (HWND);
using GetSystemMetricsForDpi_t = int (WINAPI *) (int, UINT);
using SystemParametersInfoForDpi_t = BOOL (WINAPI *) (UINT, UINT, PVOID, UINT, UINT);

GetDpiForWindow_t p_GetDpiForWindow;
GetSystemMetricsForDpi_t p_GetSystemMetricsForDpi;
SystemParametersInfoForDpi_t p_SystemParametersInfoForDpi;

} // namespace

void
load_dpi_api (void)
{
	HMODULE u = GetModuleHandleW (L"user32.dll");

	if (!u)
		return;
	p_GetDpiForWindow = reinterpret_cast<GetDpiForWindow_t> (GetProcAddress (u, "GetDpiForWindow"));
	p_GetSystemMetricsForDpi = reinterpret_cast<GetSystemMetricsForDpi_t> (GetProcAddress (u, "GetSystemMetricsForDpi"));
	p_SystemParametersInfoForDpi = reinterpret_cast<SystemParametersInfoForDpi_t> (GetProcAddress (u, "SystemParametersInfoForDpi"));
}

int
dpi_scale (int value)
{
	return MulDiv (value, (int) g_dpi, 96);
}

UINT
dpi_for_window (HWND wnd)
{
	if (p_GetDpiForWindow)
	{
		UINT d = p_GetDpiForWindow (wnd);
		if (d)
			return d;
	}
	HDC dc = GetDC (wnd);
	int d = GetDeviceCaps (dc, LOGPIXELSX);
	ReleaseDC (wnd, dc);
	return d > 0 ? (UINT) d : 96;
}

int
system_metric_dpi (int index)
{
	if (p_GetSystemMetricsForDpi)
		return p_GetSystemMetricsForDpi (index, g_dpi);
	return GetSystemMetrics (index);
}

/* Message font sized for the current DPI.  SystemParametersInfoForDpi
   returns metrics already scaled to g_dpi; the down-level fallback returns
   them at the system DPI, which is correct on the single-DPI systems that
   lack the per-DPI variant.  */
HFONT
create_message_font (void)
{
	NONCLIENTMETRICSW ncm = { sizeof (ncm) };

	if (p_SystemParametersInfoForDpi)
		p_SystemParametersInfoForDpi (SPI_GETNONCLIENTMETRICS, sizeof (ncm), &ncm, 0, g_dpi);
	else
		SystemParametersInfoW (SPI_GETNONCLIENTMETRICS, sizeof (ncm), &ncm, 0);
	return CreateFontIndirectW (&ncm.lfMessageFont);
}

std::wstring
format_size (UINT64 size)
{
	static const wchar_t *units[] = { L"KB", L"MB", L"GB", L"TB", L"PB" };
	wchar_t buf[32];

	if (size == BACKEND_SIZE_UNKNOWN)
		return L"?";
	if (size < 1024)
	{
		swprintf (buf, 32, L"%llu B", size);
		return buf;
	}
	double v = (double) size;
	int u = -1;
	while (v >= 1024.0 && u < 4)
	{
		v /= 1024.0;
		u++;
	}
	swprintf (buf, 32, L"%.1f %s", v, units[u]);
	return buf;
}

std::wstring
format_mtime (INT64 mtime)
{
	__time64_t t = mtime;
	struct tm tmv;
	wchar_t buf[32];

	if (!mtime || _localtime64_s (&tmv, &t))
		return {};
	swprintf (buf, 32, L"%04d-%02d-%02d %02d:%02d",
		tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min);
	return buf;
}

std::string
join_path (const std::string &dir, const std::string &name)
{
	std::string p = dir;

	if (p.empty () || p.back () != '/')
		p += '/';
	return p + name;
}

/* Put UTF-16 TEXT on the clipboard; OWNER opens/closes it.  */
void
clipboard_set_text (HWND owner, const std::wstring &text)
{
	size_t bytes = (text.size () + 1) * sizeof (wchar_t);
	HGLOBAL mem = GlobalAlloc (GMEM_MOVEABLE, bytes);

	if (!mem)
		return;
	memcpy (GlobalLock (mem), text.c_str (), bytes);
	GlobalUnlock (mem);
	if (!OpenClipboard (owner))
	{
		GlobalFree (mem);
		return;
	}
	EmptyClipboard ();
	if (!SetClipboardData (CF_UNICODETEXT, mem))
		GlobalFree (mem);
	CloseClipboard ();
}
