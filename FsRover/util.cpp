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
#include <richedit.h>
#include <shlobj.h>
#include <time.h>

#include <string>

#include "gui.h"

/* Modal-loop registry; see gui.h.  Everything modal runs on the GUI
   thread, so a plain counter is enough -- the scopes nest (a viewer
   putting up its own error box) and unwind in order.  */

namespace
{

int g_modal_depth;

} // namespace

modal_scope::modal_scope ()
{
	g_modal_depth++;
}

modal_scope::~modal_scope ()
{
	g_modal_depth--;
}

bool
modal_open (void)
{
	return g_modal_depth > 0;
}

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

namespace
{

bool g_rtl;	/* see ui_rtl() */

bool
lang_is_rtl (LANGID lang)
{
	wchar_t name[LOCALE_NAME_MAX_LENGTH];
	DWORD layout = 0;

	if (!LCIDToLocaleName (MAKELCID (lang, SORT_DEFAULT), name, LOCALE_NAME_MAX_LENGTH, 0))
		return false;
	if (!GetLocaleInfoEx (name, LOCALE_IREADINGLAYOUT | LOCALE_RETURN_NUMBER,
		(LPWSTR) &layout, sizeof (layout) / sizeof (wchar_t)))
		return false;
	return layout == 1;	/* 0 LTR, 1 RTL, 2/3 vertical */
}

} // namespace

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
	case LANG_KOREAN:
		lang = MAKELANGID (LANG_KOREAN, SUBLANG_KOREAN);
		break;
	default:
		lang = MAKELANGID (LANG_ENGLISH, SUBLANG_ENGLISH_US);
		break;
	}
	SetThreadUILanguage (lang);

	/* Mirror the UI for the stringtable actually selected, not for the
	   Windows display language: an Arabic system without an Arabic
	   table gets the English UI, laid out left to right.  Must run
	   before the first window exists; see ui_rtl().  */
	g_rtl = lang_is_rtl (lang);
	if (g_rtl)
		SetProcessDefaultLayout (LAYOUT_RTL);
}

/* Right-to-left UI.  SetProcessDefaultLayout() mirrors the main window
   and everything parented to it, but dialogs, message boxes and popup
   menus do not inherit layout and need the helpers below.  Views whose
   content is inherently left to right (hex dump, line-numbered text,
   the Direct2D image canvas, the pixel game) are opened with plain
   DialogBoxParamW and stay unmirrored.  */
bool
ui_rtl (void)
{
	return g_rtl;
}

INT_PTR
dialog_box (UINT id, HWND owner, DLGPROC proc, LPARAM param)
{
	HINSTANCE inst = GetModuleHandleW (nullptr);
	HRSRC res;
	HGLOBAL mem;
	const BYTE *src;
	DWORD size;
	std::vector<BYTE> copy;

	if (!g_rtl)
		goto plain;
	res = FindResourceW (inst, MAKEINTRESOURCEW (id), RT_DIALOG);
	if (!res || !(mem = LoadResource (inst, res)) || !(src = (const BYTE *) LockResource (mem)))
		goto plain;
	size = SizeofResource (inst, res);
	if (size < sizeof (DLGTEMPLATE))
		goto plain;
	copy.assign (src, src + size);
	dialog_template_rtl ((DLGTEMPLATE *) copy.data ());
	return DialogBoxIndirectParamW (inst, (const DLGTEMPLATE *) copy.data (), owner, proc, param);

plain:
	return DialogBoxParamW (inst, MAKEINTRESOURCEW (id), owner, proc, param);
}

/* Set WS_EX_LAYOUTRTL in a DLGTEMPLATE or DLGTEMPLATEEX (told apart by
   the 0xFFFF signature in its second WORD).  */
void
dialog_template_rtl (DLGTEMPLATE *templ)
{
	WORD *w = (WORD *) templ;
	DWORD *ex = w[0] == 1 && w[1] == 0xFFFF ? (DWORD *) (w + 4) : &templ->dwExtendedStyle;

	if (g_rtl)
		*ex |= WS_EX_LAYOUTRTL;
}

int
msg_box (HWND owner, const wchar_t *text, const wchar_t *caption, UINT type)
{
	return MessageBoxW (owner, text, caption, g_rtl ? type | MB_RTLREADING | MB_RIGHT : type);
}

int
track_popup_menu (HMENU menu, UINT flags, int x, int y, HWND owner)
{
	return (int) TrackPopupMenu (menu, g_rtl ? flags | TPM_LAYOUTRTL : flags, x, y, 0, owner, nullptr);
}

/* Keep one control left to right inside a mirrored window: paths,
   URLs and the credits list are ASCII and garble under RTL reading
   (the trailing '/' or '>' of a line jumps to its other end).  Edit
   controls are not mirrored but given RTL reading, right alignment
   and a leading scroll bar instead, so those go as well.  */
void
set_ltr_layout (HWND wnd)
{
	const LONG_PTR rtl = WS_EX_LAYOUTRTL | WS_EX_RTLREADING | WS_EX_RIGHT | WS_EX_LEFTSCROLLBAR;
	LONG_PTR ex = GetWindowLongPtrW (wnd, GWL_EXSTYLE);
	LONG_PTR style = GetWindowLongPtrW (wnd, GWL_STYLE);

	if (!g_rtl)
		return;
	SetWindowLongPtrW (wnd, GWL_EXSTYLE, ex & ~rtl);
	SetWindowLongPtrW (wnd, GWL_STYLE, style & ~(LONG_PTR) ES_RIGHT);
	SetWindowPos (wnd, nullptr, 0, 0, 0, 0,
		SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
	InvalidateRect (wnd, nullptr, TRUE);
}

/* Wrap a left-to-right run (a size, a date, a version) in LRE..PDF so
   an RTL paragraph keeps "6 B" and "2026-11-19 04:20" in order instead
   of reordering the digit groups around the spaces.  Embedding rather
   than isolate marks: Uniscribe on Windows 7 knows only the former.  */
std::wstring
ltr_run (const std::wstring &s)
{
	if (!g_rtl || s.empty ())
		return s;
	return L"\x202A" + s + L"\x202C";
}

/* ILC_MIRROR for image lists shown in mirrored controls: the icons
   (drives, files, shell glyphs) depict objects, not directions, so they
   are pre-flipped to come out of the mirrored DC the right way round.  */
UINT
il_mirror (void)
{
	return g_rtl ? ILC_MIRROR : 0;
}

/* DT_RTLREADING for DrawText into a (mirrored) dialog DC: mirroring
   flips the coordinates, the reading order has to be asked for.  */
UINT
dt_reading (void)
{
	return g_rtl ? DT_RTLREADING : 0;
}

/* Whether this process holds an elevated token.  Physical drives
   (windisk, which does not even register without one) and the Dokan
   driver install need it; the File menu offers a re-launch when it is
   missing.  A process cannot gain or lose elevation while it runs, so
   the answer is resolved once.  */
bool
is_elevated (void)
{
	static int cached = -1;

	if (cached < 0)
	{
		HANDLE token = nullptr;
		TOKEN_ELEVATION elevation = {};
		DWORD len = 0;

		cached = 0;
		if (OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
		{
			if (GetTokenInformation (token, TokenElevation, &elevation, sizeof (elevation), &len))
				cached = elevation.TokenIsElevated ? 1 : 0;
			CloseHandle (token);
		}
	}
	return cached > 0;
}

/* Whether this is a 32-bit process on 64-bit Windows.  The bundled
   Dokan runtime is built for this executable's architecture and a
   WoW64 process cannot install one the system could use: its System32
   writes are redirected to SysWOW64, and the kernel would not load an
   x86 driver anyway.  A 64-bit build is never under WoW64.  */
bool
is_wow64 (void)
{
#ifdef _WIN64
	return false;
#else
	using IsWow64Process_t = BOOL (WINAPI *) (HANDLE, PBOOL);
	HMODULE k32 = GetModuleHandleW (L"kernel32.dll");
	IsWow64Process_t fn = k32 ? reinterpret_cast<IsWow64Process_t>
		(GetProcAddress (k32, "IsWow64Process")) : nullptr;
	BOOL wow = FALSE;

	if (fn)
		fn (GetCurrentProcess (), &wow);
	return wow != FALSE;
#endif
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
	HIMAGELIST himl = ImageList_Create (size, size, ILC_COLOR32 | ILC_MASK | il_mirror (), count, 0);

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
	HIMAGELIST himl = ImageList_Create (size, size, ILC_COLOR32 | ILC_MASK | il_mirror (), 1, 0);
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

/* Put WND at W x H device pixels over the middle of the main window,
   kept inside the work area of the monitor the main window is on.
   SPI_GETWORKAREA answers for the primary monitor no matter where the
   program sits, which parked the viewers on the wrong screen -- and,
   since the layout metrics are scaled for the main window's DPI, at
   the wrong scale too.  */
void
center_on_owner (HWND wnd, int w, int h)
{
	MONITORINFO mi = { sizeof (mi) };
	RECT owner;
	bool work = GetMonitorInfoW (MonitorFromWindow (g_main, MONITOR_DEFAULTTONEAREST), &mi) != FALSE;

	if (work)
	{
		if (w > mi.rcWork.right - mi.rcWork.left)
			w = mi.rcWork.right - mi.rcWork.left;
		if (h > mi.rcWork.bottom - mi.rcWork.top)
			h = mi.rcWork.bottom - mi.rcWork.top;
	}
	GetWindowRect (g_main, &owner);
	int x = owner.left + ((owner.right - owner.left) - w) / 2;
	int y = owner.top + ((owner.bottom - owner.top) - h) / 2;
	if (work)
	{
		if (x + w > mi.rcWork.right)
			x = mi.rcWork.right - w;
		if (y + h > mi.rcWork.bottom)
			y = mi.rcWork.bottom - h;
		if (x < mi.rcWork.left)
			x = mi.rcWork.left;
		if (y < mi.rcWork.top)
			y = mi.rcWork.top;
	}
	SetWindowPos (wnd, nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
}

/*
 * Per-monitor DPI.  The process is PerMonitorV2 aware, so DPI is a
 * property of a window and not of the program: two top-level windows on
 * two differently scaled monitors are both live at the same time, and
 * dragging one across changes only that one.
 *
 * Every pixel metric is therefore authored at 96 DPI and scaled through
 * the DPI of the window it belongs to.  Each top-level window keeps that
 * DPI next to its other state (g_main_dpi, g_hex_dpi, ...), reads it from
 * dpi_for_window() when the window comes up, and refreshes it -- together
 * with whatever GDI objects were built at the old one -- on WM_DPICHANGED;
 * the file-local scale() helpers below each of those variables are what
 * the layout code calls.  Nothing here holds a program-wide DPI: a value
 * that is right for one window is wrong for the next.
 *
 * The scaling helpers (GetDpiForWindow, GetDpiForSystem,
 * GetSystemMetricsForDpi, SystemParametersInfoForDpi) are Windows 10
 * 1607+, so they are resolved at runtime and degrade to the system-DPI
 * equivalents on the older Windows the app still supports.
 */

namespace
{

using GetDpiForWindow_t = UINT (WINAPI *) (HWND);
using GetDpiForSystem_t = UINT (WINAPI *) (void);
using GetSystemMetricsForDpi_t = int (WINAPI *) (int, UINT);
using SystemParametersInfoForDpi_t = BOOL (WINAPI *) (UINT, UINT, PVOID, UINT, UINT);

GetDpiForWindow_t p_GetDpiForWindow;
GetDpiForSystem_t p_GetDpiForSystem;
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
	p_GetDpiForSystem = reinterpret_cast<GetDpiForSystem_t> (GetProcAddress (u, "GetDpiForSystem"));
	p_GetSystemMetricsForDpi = reinterpret_cast<GetSystemMetricsForDpi_t> (GetProcAddress (u, "GetSystemMetricsForDpi"));
	p_SystemParametersInfoForDpi = reinterpret_cast<SystemParametersInfoForDpi_t> (GetProcAddress (u, "SystemParametersInfoForDpi"));
}

/* An authored 96-DPI metric in device pixels on a DPI monitor.  */
int
dpi_scale (UINT dpi, int value)
{
	return MulDiv (value, (int) dpi, 96);
}

/* Device pixels back to a 96-DPI metric, for the few sizes the user
   sets with the mouse and the app then stores like an authored one.  */
int
dpi_unscale (UINT dpi, int value)
{
	return MulDiv (value, 96, (int) dpi);
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

/* The DPI everything that goes through GDI is measured in.  A screen DC
   reports the system DPI whatever monitor the window is on -- GDI has
   no per-monitor notion -- so anything that converts points to pixels
   outside our own layout code (RichEdit, the ChooseFont dialog) works
   at this DPI rather than at the window's.  */
UINT
dpi_system (void)
{
	if (p_GetDpiForSystem)
	{
		UINT d = p_GetDpiForSystem ();
		if (d)
			return d;
	}
	HDC dc = GetDC (nullptr);
	int d = GetDeviceCaps (dc, LOGPIXELSY);
	ReleaseDC (nullptr, dc);
	return d > 0 ? (UINT) d : 96;
}

/* Match the document to the window.  A RichEdit lays out for the
   resolution it believes the screen has, and that is not the window's:
   a control that has just been created asks GDI, which answers with the
   system DPI whatever monitor the window is on, while one that Windows
   has since told about a monitor change follows the window from then
   on.  DEVICE is whichever of the two the control is working in and the
   zoom makes up the difference -- so a viewer that opens on a monitor
   scaled differently from the primary one zooms, and goes back to 1:1
   once the control has been through a DPI change of its own.  Client
   coordinates (EM_POSFROMCHAR, EM_CHARFROMPOS) follow the zoom; pixel
   metrics such as EM_SETMARGINS do not.  */
void
richedit_dpi_zoom (HWND edit, UINT dpi, UINT device)
{
	SendMessageW (edit, EM_SETZOOM, (WPARAM) dpi, (LPARAM) device);
}

/* Take the frame Windows suggests for the new DPI.  A top-level window
   has to resize itself on WM_DPICHANGED -- neither the system nor the
   dialog manager does it -- and leaving it out is what strands a window
   at its old pixel size with freshly rescaled contents inside.  The
   dialogs that size themselves to their content put their own height
   back once they have re-measured.  */
void
dpi_take_suggested (HWND wnd, LPARAM lp)
{
	const RECT *r = (const RECT *) lp;

	SetWindowPos (wnd, nullptr, r->left, r->top,
		r->right - r->left, r->bottom - r->top,
		SWP_NOZORDER | SWP_NOACTIVATE);
}

int
system_metric_dpi (UINT dpi, int index)
{
	if (p_GetSystemMetricsForDpi)
		return p_GetSystemMetricsForDpi (index, dpi);
	return GetSystemMetrics (index);
}

/* Message font sized for one window's DPI.  SystemParametersInfoForDpi
   returns metrics already scaled to DPI; the down-level fallback returns
   them at the system DPI, which is correct on the single-DPI systems that
   lack the per-DPI variant.  */
HFONT
create_message_font (UINT dpi)
{
	NONCLIENTMETRICSW ncm = { sizeof (ncm) };

	if (p_SystemParametersInfoForDpi)
		p_SystemParametersInfoForDpi (SPI_GETNONCLIENTMETRICS, sizeof (ncm), &ncm, 0, dpi);
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
		return ltr_run (buf);
	}
	double v = (double) size;
	int u = -1;
	while (v >= 1024.0 && u < 4)
	{
		v /= 1024.0;
		u++;
	}
	swprintf (buf, 32, L"%.1f %s", v, units[u]);
	return ltr_run (buf);
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
	return ltr_run (buf);
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
