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
 * Lost partition search dialog.  The search runs as a chain of
 * lost_scan slices (see backend.h); each finished slice adds its results
 * and, unless the search was stopped, queues the next one.  Results are
 * opened as read-only lostN devices through lost_add tasks, which the
 * main window finishes like an image mount.
 */

#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>

#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

namespace
{

constexpr int ID_LIST = 100;
constexpr int ID_OPEN = 101;
constexpr int ID_COPY = 102;
constexpr int ID_SEARCH = 103;
constexpr int ID_EXT_BACKUP = 104;
constexpr int ID_DEEP = 105;
constexpr size_t COLUMN_COUNT = 7;

HWND dialog;
HWND list;
HWND status;
HWND note;
HWND progress;
HWND ext_backup;
HWND deep;
HWND open_button;
HWND copy_button;
HWND search_button;
HFONT font;
UINT dpi;

backend_diskent device;	/* the searched device, copied at open */
std::shared_ptr<backend_lost_scan> state;
UINT sequence;	/* the slice in flight */
bool running;
UINT64 done_bytes;
UINT64 total_bytes;
std::vector<backend_lost_part> parts;
std::vector<std::array<std::wstring, COLUMN_COUNT>> rows;

const UINT columns[COLUMN_COUNT] = { IDS_LOST_COL_OFFSET, IDS_LOST_COL_SIZE,
	IDS_LOST_COL_TYPE, IDS_LOST_COL_FS, IDS_LOST_COL_LABEL, IDS_LOST_COL_FLAGS,
	IDS_LOST_COL_UUID };
const int widths[COLUMN_COUNT] = { 130, 90, 80, 80, 120, 230, 260 };

std::wstring
flags_text (UINT flags)
{
	static const struct { UINT flag; UINT id; } names[] = {
		{ BACKEND_LOST_VERIFIED, IDS_LOST_F_VERIFIED },
		{ BACKEND_LOST_BACKUP, IDS_LOST_F_BACKUP },
		{ BACKEND_LOST_TABLE, IDS_LOST_F_TABLE },
		{ BACKEND_LOST_EXISTING, IDS_LOST_F_EXISTING },
		{ BACKEND_LOST_OVERLAP, IDS_LOST_F_OVERLAP },
		{ BACKEND_LOST_TRUNCATED, IDS_LOST_F_TRUNCATED },
	};
	std::wstring text;

	for (const auto &name : names)
		if (flags & name.flag)
		{
			if (!text.empty ())
				text += L", ";
			text += res_str (name.id);
		}
	return text;
}

std::array<std::wstring, COLUMN_COUNT>
make_row (const backend_lost_part &p)
{
	std::array<std::wstring, COLUMN_COUNT> row;

	row[0] = std::to_wstring (p.offset);
	row[1] = format_size (p.size);
	row[2] = widen (p.type);
	row[3] = widen (p.fs);
	row[4] = widen (p.label);
	row[5] = flags_text (p.flags);
	row[6] = widen (p.fs_uuid);
	return row;
}

/* Results arrive as the search finds them, so one that turns out to
   overlap a later one learns about it here.  */
void
add_part (backend_lost_part &&p)
{
	for (size_t i = 0; i < parts.size (); i++)
	{
		backend_lost_part &q = parts[i];

		if (p.offset < q.offset + q.size && q.offset < p.offset + p.size)
		{
			p.flags |= BACKEND_LOST_OVERLAP;
			if (!(q.flags & BACKEND_LOST_OVERLAP))
			{
				q.flags |= BACKEND_LOST_OVERLAP;
				rows[i][5] = flags_text (q.flags);
			}
		}
	}
	rows.push_back (make_row (p));
	parts.push_back (std::move (p));
}

/* Once the search is over, list the results by offset; ranges searched
   a second time report theirs out of order.  */
void
sort_parts (void)
{
	std::stable_sort (parts.begin (), parts.end (),
		[] (const backend_lost_part &a, const backend_lost_part &b)
		{
			return a.offset < b.offset;
		});
	rows.clear ();
	for (const backend_lost_part &p : parts)
		rows.push_back (make_row (p));
	ListView_SetItemState (list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
	InvalidateRect (list, nullptr, TRUE);
}

void
update_status (void)
{
	wchar_t text[160];
	int found = (int) parts.size ();

	if (running)
	{
		int percent = total_bytes ? (int) (done_bytes * 100 / total_bytes) : 0;
		swprintf (text, 160, res_str (IDS_LOST_FMT_SCANNING).c_str (), percent, found);
	}
	else
		swprintf (text, 160, res_str (state && state->cancelled.load ()
			? IDS_LOST_FMT_STOPPED : IDS_LOST_FMT_DONE).c_str (), found);
	SetWindowTextW (status, text);
	SendMessageW (progress, PBM_SETPOS,
		total_bytes ? (WPARAM) (done_bytes * 1000 / total_bytes) : 0, 0);
	SetWindowTextW (search_button, res_str (running ? IDS_LOST_STOP : IDS_LOST_SEARCH).c_str ());
	EnableWindow (deep, !running);
	EnableWindow (ext_backup, !running && SendMessageW (deep, BM_GETCHECK, 0, 0) != BST_CHECKED);
}

void
start_search (void)
{
	lost_scan_task task;

	parts.clear ();
	rows.clear ();
	ListView_SetItemCountEx (list, 0, 0);
	done_bytes = 0;
	total_bytes = device.size;
	state = std::make_shared<backend_lost_scan> ();
	task.device = device.name;
	task.flags = 0;
	if (SendMessageW (ext_backup, BM_GETCHECK, 0, 0) == BST_CHECKED)
		task.flags |= BACKEND_LOST_SCAN_EXT_BACKUP;
	if (SendMessageW (deep, BM_GETCHECK, 0, 0) == BST_CHECKED)
		task.flags |= BACKEND_LOST_SCAN_DEEP;
	task.state = state;
	sequence = backend_post (std::move (task));
	running = sequence != 0;
	update_status ();
	if (!sequence)
		SetWindowTextW (status, L"Backend unavailable");
}

/* Stop at the next slice; one more slice releases the scan handle,
   and its result reports the stop.  */
void
stop_search (void)
{
	if (!running)
		return;
	state->cancelled.store (true);
	lost_scan_task task;
	task.device = device.name;
	task.state = state;
	sequence = backend_post (std::move (task));
	if (!sequence)
		running = false;
}

void
open_selected (void)
{
	int opened = 0;

	for (int i = -1; (i = ListView_GetNextItem (list, i, LVNI_SELECTED)) >= 0;)
	{
		const backend_lost_part &p = parts[(size_t) i];

		if (!p.window)
			continue;
		if (backend_post (lost_add_task { device.name, p.offset, p.window, p.remap }))
			opened++;
	}
	if (!opened)
		MessageBeep (MB_ICONWARNING);
}

void
copy_rows (void)
{
	std::wstring text;

	for (size_t j = 0; j < COLUMN_COUNT; j++)
	{
		if (j)
			text += L'\t';
		text += res_str (columns[j]);
	}
	text += L"\r\n";
	for (int i = -1; (i = ListView_GetNextItem (list, i, LVNI_SELECTED)) >= 0;)
	{
		for (size_t j = 0; j < COLUMN_COUNT; j++)
		{
			if (j)
				text += L'\t';
			text += rows[(size_t) i][j];
		}
		text += L"\r\n";
	}
	clipboard_set_text (dialog, text);
}

void
layout (HWND dlg)
{
	RECT rc;
	GetClientRect (dlg, &rc);
	int pad = dpi_scale (dpi, 10);
	int line = dpi_scale (dpi, 26);
	int button = dpi_scale (dpi, 150);
	int width = rc.right - 2 * pad;
	int y = pad;

	MoveWindow (note, pad, y, width, line * 2, TRUE);
	y += line * 2;
	MoveWindow (ext_backup, pad, y, width - button - pad, line, TRUE);
	MoveWindow (search_button, rc.right - pad - button, y, button, line, TRUE);
	y += line;
	MoveWindow (deep, pad, y, width - button - pad, line, TRUE);
	y += line + pad / 2;
	MoveWindow (status, pad, y, width, line, TRUE);
	y += line;
	MoveWindow (progress, pad, y, width, dpi_scale (dpi, 14), TRUE);
	y += dpi_scale (dpi, 14) + pad;
	MoveWindow (list, pad, y, width, rc.bottom - y - pad * 2 - line, TRUE);
	MoveWindow (open_button, pad, rc.bottom - pad - line, button, line, TRUE);
	MoveWindow (copy_button, pad * 2 + button, rc.bottom - pad - line, button, line, TRUE);
	MoveWindow (GetDlgItem (dlg, IDCANCEL), rc.right - pad - dpi_scale (dpi, 100),
		rc.bottom - pad - line, dpi_scale (dpi, 100), line, TRUE);
}

void
set_font (void)
{
	HFONT previous = font;

	font = create_message_font (dpi);
	for (HWND h : { list, status, note, ext_backup, deep, search_button, open_button,
		copy_button, GetDlgItem (dialog, IDCANCEL) })
		SendMessageW (h, WM_SETFONT, (WPARAM) font, TRUE);
	if (previous)
		DeleteObject (previous);
}

HWND
add_control (HWND dlg, const wchar_t *cls, UINT text, DWORD style, int id)
{
	return CreateWindowW (cls, text ? res_str (text).c_str () : L"",
		WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, dlg, (HMENU) (INT_PTR) id,
		nullptr, nullptr);
}

void
close_dialog (HWND dlg)
{
	stop_search ();
	dialog = nullptr;
	EndDialog (dlg, 0);
}

INT_PTR CALLBACK
proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		dialog = dlg;
		dpi = dpi_for_window (dlg);
		std::wstring title = res_str (IDS_LOST_TITLE) + L" - (" + widen (device.name) + L")";
		SetWindowTextW (dlg, title.c_str ());
		note = add_control (dlg, L"STATIC", IDS_LOST_NOTE, 0, 0);
		ext_backup = add_control (dlg, L"BUTTON", IDS_LOST_EXT_BACKUP,
			WS_TABSTOP | BS_AUTOCHECKBOX, ID_EXT_BACKUP);
		deep = add_control (dlg, L"BUTTON", IDS_LOST_DEEP,
			WS_TABSTOP | BS_AUTOCHECKBOX, ID_DEEP);
		search_button = add_control (dlg, L"BUTTON", IDS_LOST_STOP, WS_TABSTOP, ID_SEARCH);
		status = add_control (dlg, L"STATIC", 0, SS_ENDELLIPSIS, 0);
		progress = add_control (dlg, PROGRESS_CLASSW, 0, 0, 0);
		SendMessageW (progress, PBM_SETRANGE32, 0, 1000);
		list = CreateWindowExW (WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE
			| WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS,
			0, 0, 0, 0, dlg, (HMENU) (INT_PTR) ID_LIST, nullptr, nullptr);
		ListView_SetExtendedListViewStyle (list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER
			| LVS_EX_GRIDLINES);
		SetWindowTheme (list, L"Explorer", nullptr);
		for (int i = 0; i < (int) COLUMN_COUNT; i++)
		{
			std::wstring text = res_str (columns[i]);
			LVCOLUMNW col = {};
			col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
			col.fmt = i < 2 ? LVCFMT_RIGHT : LVCFMT_LEFT;
			col.pszText = text.data ();
			col.cx = dpi_scale (dpi, widths[i]);
			ListView_InsertColumn (list, i, &col);
		}
		open_button = add_control (dlg, L"BUTTON", IDS_LOST_OPEN, WS_TABSTOP, ID_OPEN);
		copy_button = add_control (dlg, L"BUTTON", IDS_MAP_COPY, WS_TABSTOP, ID_COPY);
		add_control (dlg, L"BUTTON", IDS_LOST_CLOSE, WS_TABSTOP, IDCANCEL);
		set_font ();
		center_on_owner (dlg, dpi_scale (dpi, 980), dpi_scale (dpi, 560));
		layout (dlg);
		start_search ();
		return TRUE;
	}
	case WM_SIZE:
		layout (dlg);
		return TRUE;
	case WM_DPICHANGED:
		dpi = HIWORD (wp);
		dpi_take_suggested (dlg, lp);
		set_font ();
		layout (dlg);
		return TRUE;
	case WM_GETMINMAXINFO:
		((MINMAXINFO *) lp)->ptMinTrackSize = { dpi_scale (dpi, 620), dpi_scale (dpi, 360) };
		return TRUE;
	case WM_NOTIFY:
	{
		auto *hdr = (NMHDR *) lp;
		if (hdr->hwndFrom != list)
			break;
		if (hdr->code == LVN_GETDISPINFOW)
		{
			auto *info = (NMLVDISPINFOW *) lp;
			if ((info->item.mask & LVIF_TEXT) && info->item.iItem >= 0
				&& (size_t) info->item.iItem < rows.size ()
				&& info->item.iSubItem >= 0 && info->item.iSubItem < (int) COLUMN_COUNT)
				info->item.pszText = rows[(size_t) info->item.iItem][info->item.iSubItem].data ();
			return TRUE;
		}
		if (hdr->code == NM_DBLCLK)
		{
			open_selected ();
			return TRUE;
		}
		if (hdr->code == LVN_KEYDOWN)
		{
			auto *key = (NMLVKEYDOWN *) lp;
			if (GetKeyState (VK_CONTROL) < 0 && key->wVKey == 'C')
				copy_rows ();
			if (GetKeyState (VK_CONTROL) < 0 && key->wVKey == 'A')
				ListView_SetItemState (list, -1, LVIS_SELECTED, LVIS_SELECTED);
			if (key->wVKey == VK_RETURN)
				open_selected ();
		}
		break;
	}
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case ID_OPEN:
			open_selected ();
			return TRUE;
		case ID_COPY:
			copy_rows ();
			return TRUE;
		case ID_DEEP:
			/* The deep search checks every ext superblock copy anyway.  */
			update_status ();
			return TRUE;
		case ID_SEARCH:
			if (running)
				stop_search ();
			else
				start_search ();
			update_status ();
			return TRUE;
		case IDCANCEL:
			close_dialog (dlg);
			return TRUE;
		}
		break;
	case WM_CLOSE:
		close_dialog (dlg);
		return TRUE;
	}
	return FALSE;
}

} // namespace

void
lost_scan_done (backend_result *res)
{
	if (!dialog || res->seq != sequence)
		return;
	for (backend_lost_part &p : res->lost_parts)
		add_part (std::move (p));
	ListView_SetItemCountEx (list, (int) rows.size (), LVSICF_NOSCROLL);
	InvalidateRect (list, nullptr, TRUE);
	if (res->lost_total)
	{
		done_bytes = res->lost_done;
		total_bytes = res->lost_total;
	}
	if (!res->error.empty ())
	{
		running = false;
		update_status ();
		SetWindowTextW (status, widen (res->error).c_str ());
		return;
	}
	if (res->lost_finished || state->cancelled.load ())
	{
		if (res->lost_finished)
		{
			running = false;
			sort_parts ();
		}
		if (!state->cancelled.load ())
			done_bytes = total_bytes;
		update_status ();
		return;
	}
	lost_scan_task task;
	task.device = device.name;
	task.state = state;
	sequence = backend_post (std::move (task));
	if (!sequence)
		running = false;
	update_status ();
}

void
lost_add_done (backend_result *res)
{
	if (!dialog)
		return;
	if (!res->error.empty ())
	{
		SetWindowTextW (status, widen (res->error).c_str ());
		return;
	}
	wchar_t text[128];
	swprintf (text, 128, res_str (IDS_LOST_FMT_OPENED).c_str (), widen (res->path).c_str ());
	SetWindowTextW (status, text);
}

void
show_lost_scan (const backend_diskent &d)
{
	device = d;
	parts.clear ();
	rows.clear ();
	sequence = 0;
	running = false;
	state.reset ();
	/* Zero-terminated menu/class/title follow this aligned dialog template.  */
	struct { DLGTEMPLATE dlg; WORD menu, cls, title; } templ = {};
	templ.dlg.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | DS_MODALFRAME;
	templ.dlg.cx = 650;
	templ.dlg.cy = 360;
	{
		modal_scope hold;
		DialogBoxIndirectParamW (GetModuleHandleW (nullptr), &templ.dlg, g_main, proc, 0);
	}
	dialog = nullptr;
	parts.clear ();
	rows.clear ();
	if (font)
	{
		DeleteObject (font);
		font = nullptr;
	}
}
