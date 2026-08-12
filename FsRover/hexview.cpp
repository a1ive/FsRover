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

/* A virtual ListView is limited to 100,000,000 items,
   so exposing one row per 16 bytes cannot represent
   a normal disk directly.  The control instead contains at most 1M rows
   (16 MiB); the offset bar and previous/next buttons move that window over
   the full 64-bit address space.  Rows render from a small FIFO cache of
   64 KiB chunks fetched on demand with read_chunk tasks.  */

#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <wctype.h>

#include <deque>
#include <map>
#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

namespace
{

HWND g_hex;	/* hex viewer, null when closed */

/* Hex viewer state; see the block comment at the top of the file.  */
constexpr UINT64 HEX_CHUNK = 1u << 16;
constexpr int HEX_ROW_BYTES = 16;
constexpr UINT64 HEX_WINDOW_ROWS = 1u << 20;	/* 16 MiB per view */
constexpr UINT64 HEX_WINDOW_BYTES = HEX_WINDOW_ROWS * HEX_ROW_BYTES;
constexpr size_t HEX_CACHE_MAX = 64;	/* chunks kept: 4 MiB */
constexpr size_t HEX_PENDING_MAX = 4;	/* in-flight read_chunk tasks */

static_assert (HEX_WINDOW_ROWS <= 100000000, "LVS_OWNERDATA supports at most 100 million rows");

const wchar_t HEX_RULER[] = L"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F";

std::string g_hex_path;	/* file/device being viewed, UTF-8 */
std::wstring g_hex_title;	/* caption override; empty = path basename */
UINT64 g_hex_size;	/* ~0 until the first chunk reports it */
UINT64 g_hex_view_base;	/* byte offset represented by list row zero */
HFONT g_hex_font;	/* fixed-pitch, owned by the viewer */
UINT g_hex_dpi = 96;	/* this window's DPI, refreshed on WM_DPICHANGED */
std::map<UINT64, std::vector<char>> g_hex_cache;	/* by chunk base */
std::deque<UINT64> g_hex_fifo;	/* cache eviction order */
std::map<UINT, UINT64> g_hex_pending;	/* task seq -> chunk base */

int
hex_scale (int value)
{
	return dpi_scale (g_hex_dpi, value);
}

int
hex_text_width (HWND list, const wchar_t *text)
{
	HDC dc = GetDC (list);
	HFONT old = (HFONT) SelectObject (dc, g_hex_font);
	SIZE size = {};

	GetTextExtentPoint32W (dc, text, lstrlenW (text), &size);
	SelectObject (dc, old);
	ReleaseDC (list, dc);
	return size.cx;
}

void
hex_request (UINT64 base)
{
	if (g_hex_cache.count (base) || g_hex_pending.size () >= HEX_PENDING_MAX)
		return;
	for (const auto &p : g_hex_pending)
		if (p.second == base)
			return;

	backend_task task;
	task.type = backend_task_type::read_chunk;
	task.path = g_hex_path;
	task.offset = base;
	task.length = (UINT) HEX_CHUNK;
	task.limit = g_hex_size;
	g_hex_pending[backend_post (std::move (task))] = base;
}

void
hex_set_view (HWND dlg, UINT64 offset)
{
	if (g_hex_size == BACKEND_SIZE_UNKNOWN)
		return;

	if (!g_hex_size)
		offset = 0;
	else if (offset >= g_hex_size)
		offset = (g_hex_size - 1) & ~(UINT64) (HEX_ROW_BYTES - 1);
	else
		offset &= ~(UINT64) (HEX_ROW_BYTES - 1);
	g_hex_view_base = offset;

	UINT64 rows = g_hex_size > offset ? (g_hex_size - offset + HEX_ROW_BYTES - 1) / HEX_ROW_BYTES : 0;
	if (rows > HEX_WINDOW_ROWS)
		rows = HEX_WINDOW_ROWS;

	HWND list = GetDlgItem (dlg, IDC_HEX_LIST);
	ListView_SetItemCountEx (list, (int) rows, 0);
	if (rows)
		ListView_EnsureVisible (list, 0, FALSE);

	wchar_t text[32];
	swprintf (text, 32, L"%llX", g_hex_view_base);
	SetDlgItemTextW (dlg, IDC_HEX_OFFSET_EDIT, text);
	EnableWindow (GetDlgItem (dlg, IDC_HEX_PREV), g_hex_view_base != 0);
	EnableWindow (GetDlgItem (dlg, IDC_HEX_NEXT), rows && g_hex_view_base + rows * HEX_ROW_BYTES < g_hex_size);

	if (g_hex_size > 0xffffffffULL)
		ListView_SetColumnWidth (list, 0, hex_text_width (list, L"0000000000000000") + 24);
	InvalidateRect (list, nullptr, FALSE);
	if (rows)
		hex_request (g_hex_view_base & ~(HEX_CHUNK - 1));
}

void
hex_go (HWND dlg)
{
	std::wstring text = window_text (GetDlgItem (dlg, IDC_HEX_OFFSET_EDIT));
	wchar_t *end = nullptr;
	UINT64 offset = _wcstoui64 (text.c_str (), &end, 16);

	while (end && iswspace (*end))
		end++;
	if (text.empty () || end == text.c_str () || (end && *end))
	{
		MessageBeep (MB_ICONWARNING);
		return;
	}
	hex_set_view (dlg, offset);
	SetFocus (GetDlgItem (dlg, IDC_HEX_LIST));
}

void
hex_getdispinfo (NMLVDISPINFOW *di)
{
	if (!(di->item.mask & LVIF_TEXT) || di->item.cchTextMax < 1)
		return;
	di->item.pszText[0] = L'\0';

	UINT64 off = g_hex_view_base + (UINT64) di->item.iItem * HEX_ROW_BYTES;
	wchar_t buf[64];
	if (di->item.iSubItem == 0)
	{
		swprintf (buf, 64, L"%08llX", off);
		lstrcpynW (di->item.pszText, buf, di->item.cchTextMax);
		return;
	}

	UINT64 base = off & ~(HEX_CHUNK - 1);
	auto it = g_hex_cache.find (base);
	if (it == g_hex_cache.end ())
	{
		hex_request (base);
		return;
	}
	const std::vector<char> &data = it->second;
	size_t start = (size_t) (off - base);
	size_t n = start < data.size () ? data.size () - start : 0;
	if (n > HEX_ROW_BYTES)
		n = HEX_ROW_BYTES;
	if (!n)
		return;

	if (di->item.iSubItem == 1)
	{
		for (size_t i = 0; i < n; i++)
			swprintf (buf + i * 3, 4, L"%02X ", (unsigned char) data[start + i]);
		buf[n * 3 - 1] = L'\0';
	}
	else if (di->item.iSubItem == 2)
	{
		for (size_t i = 0; i < n; i++)
		{
			unsigned char c = (unsigned char) data[start + i];
			buf[i] = (c >= 0x20 && c < 0x7f) ? (wchar_t) c : L'.';
		}
		buf[n] = L'\0';
	}
	else
		return;
	lstrcpynW (di->item.pszText, buf, di->item.cchTextMax);
}

void
hex_layout (HWND dlg)
{
	RECT rc;

	GetClientRect (dlg, &rc);
	int margin = hex_scale (6);
	int gap = hex_scale (4);
	int bar_h = hex_scale (30);
	int label_w = hex_scale (66);
	int go_w = hex_scale (44);
	int step_w = hex_scale (32);
	int edit_w = rc.right - 2 * margin - label_w - go_w - 2 * step_w - 4 * gap;
	if (edit_w < hex_scale (80))
		edit_w = hex_scale (80);
	int x = margin;
	MoveWindow (GetDlgItem (dlg, IDC_HEX_OFFSET_LABEL), x, hex_scale (8), label_w, hex_scale (18), TRUE);
	x += label_w + gap;
	MoveWindow (GetDlgItem (dlg, IDC_HEX_OFFSET_EDIT), x, hex_scale (4), edit_w, hex_scale (22), TRUE);
	x += edit_w + gap;
	MoveWindow (GetDlgItem (dlg, IDC_HEX_GO), x, hex_scale (4), go_w, hex_scale (22), TRUE);
	x += go_w + gap;
	MoveWindow (GetDlgItem (dlg, IDC_HEX_PREV), x, hex_scale (4), step_w, hex_scale (22), TRUE);
	x += step_w + gap;
	MoveWindow (GetDlgItem (dlg, IDC_HEX_NEXT), x, hex_scale (4), step_w, hex_scale (22), TRUE);
	MoveWindow (GetDlgItem (dlg, IDC_HEX_LIST), 0, bar_h, rc.right, rc.bottom - bar_h, TRUE);
}

/* On a monitor change the dialog manager hands every control the
   rescaled dialog font.  The dump only lines up in the fixed-pitch one
   the viewer builds for itself, so that is the only font let through
   (the list passes its font on to the header, which is covered too).  */
LRESULT CALLBACK
hex_list_proc (HWND wnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR)
{
	if (msg == WM_SETFONT && (HFONT) wp != g_hex_font)
		return 0;
	if (msg == WM_NCDESTROY)
		RemoveWindowSubclass (wnd, hex_list_proc, 0);
	return DefSubclassProc (wnd, msg, wp, lp);
}

/* The dump font, at 10 pt for this window's DPI: a screen DC would
   answer for the primary monitor and leave the bytes unreadable on any
   other.  Rebuilt from scratch on a DPI change, which is also when the
   list drops the old font, so the replacement is installed before the
   previous one goes away.  */
void
hex_apply_dpi (HWND dlg)
{
	HWND list = GetDlgItem (dlg, IDC_HEX_LIST);
	HFONT prev = g_hex_font;

	g_hex_font = CreateFontW (-MulDiv (10, (int) g_hex_dpi, 72), 0, 0, 0,
		FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
		OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		FIXED_PITCH | FF_MODERN, L"Consolas");
	SendMessageW (list, WM_SETFONT, (WPARAM) g_hex_font, TRUE);
	/* Same font on the header so the 00..0F ruler lines up with the
	   byte columns underneath it.  */
	SendMessageW (ListView_GetHeader (list), WM_SETFONT, (WPARAM) g_hex_font, TRUE);
	if (prev)
		DeleteObject (prev);
}

/* Column widths follow the font, so they are measured again whenever it
   changes.  */
void
hex_size_columns (HWND list)
{
	ListView_SetColumnWidth (list, 0, hex_text_width (list, L"00000000") + hex_scale (24));
	ListView_SetColumnWidth (list, 1, hex_text_width (list, HEX_RULER) + hex_scale (24));
	ListView_SetColumnWidth (list, 2, hex_text_width (list, L"0123456789ABCDEF") + hex_scale (24));
}

void
hex_init_dialog (HWND dlg)
{
	g_hex = dlg;
	g_hex_dpi = dpi_for_window (dlg);
	g_hex_view_base = 0;

	std::wstring name;
	if (!g_hex_title.empty ())
		name = g_hex_title;
	else
	{
		size_t cut = g_hex_path.find_last_of ('/');
		name = widen (cut == std::string::npos ? g_hex_path : g_hex_path.substr (cut + 1));
	}
	SetWindowTextW (dlg, (name + L" - " + res_str (IDS_HEX_TITLE)).c_str ());

	HWND list = GetDlgItem (dlg, IDC_HEX_LIST);
	SetDlgItemTextW (dlg, IDC_HEX_OFFSET_LABEL, res_str (IDS_HEX_OFFSET).c_str ());
	SetDlgItemTextW (dlg, IDC_HEX_GO, res_str (IDS_HEX_GO).c_str ());
	SetWindowTheme (list, L"Explorer", nullptr);
	ListView_SetExtendedListViewStyle (list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
	SetWindowSubclass (list, hex_list_proc, 0, 0);

	hex_apply_dpi (dlg);

	LVCOLUMNW col = {};
	std::wstring col_off = res_str (IDS_HEX_OFFSET);
	std::wstring col_text = res_str (IDS_HEX_TEXT);
	col.mask = LVCF_TEXT | LVCF_FMT;
	col.fmt = LVCFMT_LEFT;
	col.pszText = const_cast<wchar_t *> (col_off.c_str ());
	ListView_InsertColumn (list, 0, &col);
	col.pszText = const_cast<wchar_t *> (HEX_RULER);
	ListView_InsertColumn (list, 1, &col);
	col.pszText = const_cast<wchar_t *> (col_text.c_str ());
	ListView_InsertColumn (list, 2, &col);
	hex_size_columns (list);

	/* Widen the frame so all three columns fit, then center it on
	   the owner (the template size is just a fallback).  */
	int want = ListView_GetColumnWidth (list, 0)
		+ ListView_GetColumnWidth (list, 1)
		+ ListView_GetColumnWidth (list, 2)
		+ system_metric_dpi (g_hex_dpi, SM_CXVSCROLL) + hex_scale (8);
	RECT wrc, crc;
	GetWindowRect (dlg, &wrc);
	GetClientRect (dlg, &crc);
	center_on_owner (dlg, want + (wrc.right - wrc.left) - crc.right,
		wrc.bottom - wrc.top);

	if (g_hex_size == BACKEND_SIZE_UNKNOWN)
	{
		EnableWindow (GetDlgItem (dlg, IDC_HEX_PREV), FALSE);
		EnableWindow (GetDlgItem (dlg, IDC_HEX_NEXT), FALSE);
		hex_request (0);	/* first chunk also reports the size */
	}
	else
		hex_set_view (dlg, 0);
}

INT_PTR CALLBACK
hex_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		hex_init_dialog (dlg);
		hex_layout (dlg);
		return TRUE;
	case WM_SIZE:
		hex_layout (dlg);
		return TRUE;
	case WM_DPICHANGED:
		g_hex_dpi = HIWORD (wp);
		dpi_take_suggested (dlg, lp);
		PostMessageW (dlg, WM_APP_DPI_CHANGED, 0, 0);
		return FALSE;	/* the dialog manager still rescales the control fonts */
	case WM_APP_DPI_CHANGED:
		hex_apply_dpi (dlg);
		hex_size_columns (GetDlgItem (dlg, IDC_HEX_LIST));
		hex_layout (dlg);
		return TRUE;
	case WM_GETMINMAXINFO:
		((MINMAXINFO *) lp)->ptMinTrackSize = { hex_scale (420), hex_scale (240) };
		return TRUE;
	case WM_NOTIFY:
	{
		NMHDR *hdr = (NMHDR *) lp;
		if (hdr->idFrom == IDC_HEX_LIST && hdr->code == LVN_GETDISPINFOW)
		{
			hex_getdispinfo ((NMLVDISPINFOW *) hdr);
			return TRUE;
		}
		break;
	}
	case WM_COMMAND:
		if (LOWORD (wp) == IDC_HEX_GO)
		{
			hex_go (dlg);
			return TRUE;
		}
		if (LOWORD (wp) == IDC_HEX_PREV)
		{
			hex_set_view (dlg, g_hex_view_base > HEX_WINDOW_BYTES ? g_hex_view_base - HEX_WINDOW_BYTES : 0);
			return TRUE;
		}
		if (LOWORD (wp) == IDC_HEX_NEXT)
		{
			hex_set_view (dlg, g_hex_view_base + HEX_WINDOW_BYTES);
			return TRUE;
		}
		if (LOWORD (wp) == IDCANCEL)
		{
			g_hex = nullptr;
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

} // namespace

void
hex_on_chunk (backend_result *res)
{
	auto it = g_hex_pending.find (res->seq);

	if (!g_hex || it == g_hex_pending.end ())
		return;
	UINT64 base = it->second;
	g_hex_pending.erase (it);
	if (!res->error.empty ())
	{
		HWND dlg = g_hex;
		g_hex = nullptr;	/* drop the other in-flight chunks */
		MessageBoxW (dlg, widen (res->error).c_str (), res_str (IDS_HEX_TITLE).c_str (), MB_ICONERROR);
		EndDialog (dlg, 0);
		return;
	}

	HWND list = GetDlgItem (g_hex, IDC_HEX_LIST);
	bool got_size = g_hex_size == BACKEND_SIZE_UNKNOWN;
	if (got_size)
		g_hex_size = res->file_size;
	g_hex_cache[base] = std::move (res->data);
	g_hex_fifo.push_back (base);
	if (g_hex_fifo.size () > HEX_CACHE_MAX)
	{
		g_hex_cache.erase (g_hex_fifo.front ());
		g_hex_fifo.pop_front ();
	}
	if (got_size)
		hex_set_view (g_hex, 0);
	/* Repainting also re-requests any still-missing visible rows.  */
	InvalidateRect (list, nullptr, FALSE);
}

void
show_hex (const std::string &path, const std::wstring &title,
	  UINT64 known_size)
{
	g_hex_path = path;
	g_hex_title = title;
	g_hex_size = known_size;
	{
		modal_scope hold;
		DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_HEX), g_main, hex_dlg_proc, 0);
	}
	g_hex = nullptr;
	g_hex_cache.clear ();
	g_hex_fifo.clear ();
	g_hex_pending.clear ();
	if (g_hex_font)
	{
		DeleteObject (g_hex_font);
		g_hex_font = nullptr;
	}
}
