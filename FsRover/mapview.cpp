/* Metadata map viewer. GPL-3.0-or-later. */
#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <array>
#include <memory>
#include <string>
#include <vector>
#include "gui.h"
#include "resource.h"
#include "strconv.h"

namespace
{
HWND viewer;
HWND list;
HWND status;
HWND note;
HWND copy_button;
HFONT font;
UINT dpi;
UINT sequence;
std::string path;
std::shared_ptr<std::atomic<bool>> cancelled;
std::vector<std::array<std::wstring, 11>> rows;
const UINT columns[] = { IDS_MAP_GROUP, IDS_MAP_LOGICAL, IDS_MAP_LENGTH,
	IDS_MAP_TYPE, IDS_MAP_DEVICE, IDS_MAP_SPACE, IDS_MAP_OFFSET, IDS_MAP_STORED,
	IDS_MAP_ENCODING, IDS_MAP_DECODED_OFFSET, IDS_MAP_DECODED_LENGTH };
const int widths[] = { 65, 135, 135, 240, 120, 110, 145, 135, 90, 135, 135 };

void layout (HWND dlg)
{
	RECT rc;
	GetClientRect (dlg, &rc);
	int pad = dpi_scale (dpi, 10), line = dpi_scale (dpi, 26);
	MoveWindow (status, pad, pad, rc.right - 2 * pad, line, TRUE);
	MoveWindow (note, pad, pad + line, rc.right - 2 * pad, line * 2, TRUE);
	MoveWindow (list, pad, pad + line * 3, rc.right - 2 * pad,
		rc.bottom - pad * 3 - line * 4, TRUE);
	MoveWindow (copy_button, pad, rc.bottom - pad - line, dpi_scale (dpi, 160), line, TRUE);
	MoveWindow (GetDlgItem (dlg, IDCANCEL), rc.right - pad - dpi_scale (dpi, 100),
		rc.bottom - pad - line, dpi_scale (dpi, 100), line, TRUE);
}

void set_font ()
{
	HFONT previous = font;
	font = create_message_font (dpi);
	for (HWND h : { list, status, note, copy_button, GetDlgItem (viewer, IDCANCEL) })
		SendMessageW (h, WM_SETFONT, (WPARAM) font, TRUE);
	if (previous) DeleteObject (previous);
}

void copy_rows ()
{
	std::wstring text;
	for (size_t j = 0; j < std::size (columns); j++)
	{
		if (j) text += L'\t';
		text += res_str (columns[j]);
	}
	text += L"\r\n";
	for (int i = -1; (i = ListView_GetNextItem (list, i, LVNI_SELECTED)) >= 0;)
	{
		for (size_t j = 0; j < std::size (columns); j++)
		{
			if (j) text += L'\t';
			text += rows[(size_t) i][j];
		}
		text += L"\r\n";
	}
	clipboard_set_text (viewer, text);
}

INT_PTR CALLBACK proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		viewer = dlg; dpi = dpi_for_window (dlg);
		std::wstring title = res_str (IDS_MAP_TITLE) + L" - " + widen (path);
		SetWindowTextW (dlg, title.c_str ());
		status = CreateWindowW (L"STATIC", res_str (IDS_MAP_LOADING).c_str (), WS_CHILD | WS_VISIBLE,
			0, 0, 0, 0, dlg, nullptr, nullptr, nullptr);
		note = CreateWindowW (L"STATIC", res_str (IDS_MAP_NOTE).c_str (), WS_CHILD | WS_VISIBLE,
			0, 0, 0, 0, dlg, nullptr, nullptr, nullptr);
		list = CreateWindowExW (WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP |
			LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS, 0, 0, 0, 0, dlg, (HMENU) 100, nullptr, nullptr);
		ListView_SetExtendedListViewStyle (list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
		SetWindowTheme (list, L"Explorer", nullptr);
		for (int i = 0; i < (int) std::size (columns); i++)
		{
			std::wstring title_text = res_str (columns[i]);
			LVCOLUMNW col = {}; col.mask = LVCF_TEXT | LVCF_WIDTH;
			col.pszText = title_text.data (); col.cx = dpi_scale (dpi, widths[i]);
			ListView_InsertColumn (list, i, &col);
		}
		copy_button = CreateWindowW (L"BUTTON", res_str (IDS_MAP_COPY).c_str (), WS_CHILD | WS_VISIBLE | WS_TABSTOP,
			0, 0, 0, 0, dlg, (HMENU) 101, nullptr, nullptr);
		CreateWindowW (L"BUTTON", res_str (IDS_BTN_CANCEL).c_str (), WS_CHILD | WS_VISIBLE | WS_TABSTOP,
			0, 0, 0, 0, dlg, (HMENU) IDCANCEL, nullptr, nullptr);
		set_font (); center_on_owner (dlg, dpi_scale (dpi, 1050), dpi_scale (dpi, 620)); layout (dlg);
		file_map_task task { path, cancelled };
		sequence = backend_post (std::move (task));
		if (!sequence) SetWindowTextW (status, L"Backend unavailable");
		return TRUE;
	}
	case WM_SIZE: layout (dlg); return TRUE;
	case WM_DPICHANGED:
		dpi = HIWORD (wp); dpi_take_suggested (dlg, lp); set_font (); layout (dlg); return TRUE;
	case WM_GETMINMAXINFO:
		((MINMAXINFO *) lp)->ptMinTrackSize = { dpi_scale (dpi, 620), dpi_scale (dpi, 340) }; return TRUE;
	case WM_NOTIFY:
	{
		auto *hdr = (NMHDR *) lp;
		if (hdr->hwndFrom != list) break;
		if (hdr->code == LVN_GETDISPINFOW)
		{
			auto *info = (NMLVDISPINFOW *) lp;
			if ((info->item.mask & LVIF_TEXT) && info->item.iItem >= 0 && (size_t) info->item.iItem < rows.size () &&
				info->item.iSubItem >= 0 && info->item.iSubItem < 11)
				info->item.pszText = rows[(size_t) info->item.iItem][info->item.iSubItem].data ();
			return TRUE;
		}
		if (hdr->code == LVN_KEYDOWN)
		{
			auto *key = (NMLVKEYDOWN *) lp;
			if (GetKeyState (VK_CONTROL) < 0 && key->wVKey == 'C') copy_rows ();
			if (GetKeyState (VK_CONTROL) < 0 && key->wVKey == 'A') ListView_SetItemState (list, -1, LVIS_SELECTED, LVIS_SELECTED);
		}
		break;
	}
	case WM_COMMAND:
		if (LOWORD (wp) == 101) { copy_rows (); return TRUE; }
		if (LOWORD (wp) == IDCANCEL) { cancelled->store (true); viewer = nullptr; EndDialog (dlg, 0); return TRUE; }
		break;
	case WM_CLOSE:
		cancelled->store (true); viewer = nullptr; EndDialog (dlg, 0); return TRUE;
	}
	return FALSE;
}
}

void file_map_done (backend_result *res)
{
	if (!viewer || res->seq != sequence) return;
	rows.reserve (res->map_rows.size ());
	for (const auto &source : res->map_rows)
	{
		std::array<std::wstring, 11> row;
		for (size_t i = 0; i < row.size (); i++) row[i] = widen (source[i]);
		rows.push_back (std::move (row));
	}
	ListView_SetItemCountEx (list, (int) rows.size (), LVSICF_NOSCROLL);
	std::wstring text = !res->error.empty () ? widen (res->error) : res_str (res->map_stopped ? IDS_MAP_PARTIAL : IDS_MAP_COMPLETE);
	text += L" - " + std::to_wstring (rows.size ());
	SetWindowTextW (status, text.c_str ());
}

void show_file_map (const std::string &name)
{
	path = name; rows.clear (); sequence = 0;
	cancelled = std::make_shared<std::atomic<bool>> (false);
	/* Zero-terminated menu/class/title follow this aligned dialog template. */
	struct { DLGTEMPLATE dlg; WORD menu, cls, title; } templ = {};
	templ.dlg.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | DS_MODALFRAME;
	templ.dlg.cx = 700; templ.dlg.cy = 400;
	{
		modal_scope hold;
		DialogBoxIndirectParamW (GetModuleHandleW (nullptr), &templ.dlg, g_main, proc, 0);
	}
	cancelled->store (true); viewer = nullptr; rows.clear ();
	if (font) { DeleteObject (font); font = nullptr; }
}
