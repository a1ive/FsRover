/* Metadata map viewer. GPL-3.0-or-later. */
#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <array>
#include <cwchar>
#include <memory>
#include <string>
#include <vector>
#include "gui.h"
#include "resource.h"
#include "strconv.h"

namespace
{
/* What a user cares about in an extent; one per row, picked from the
   BACKEND_MAP_* flags by category ().  */
enum { CAT_DATA, CAT_UNWRITTEN, CAT_HOLE, CAT_ZERO, CAT_INLINE, CAT_ENCODED, CAT_UNKNOWN, CAT_COUNT };
const UINT cat_names[CAT_COUNT] = { IDS_MAP_CAT_DATA, IDS_MAP_CAT_UNWRITTEN, IDS_MAP_CAT_HOLE,
	IDS_MAP_CAT_ZERO, IDS_MAP_CAT_INLINE, IDS_MAP_CAT_ENCODED, IDS_MAP_CAT_UNKNOWN };
/* Strip colour, and the light tint of the list rows.  */
const COLORREF cat_bar[CAT_COUNT] = { RGB (59, 130, 246), RGB (148, 163, 184), RGB (209, 213, 219),
	RGB (203, 213, 225), RGB (139, 92, 246), RGB (16, 185, 129), RGB (239, 68, 68) };
const COLORREF cat_row[CAT_COUNT] = { RGB (232, 241, 253), RGB (238, 241, 245), RGB (247, 247, 247),
	RGB (244, 246, 249), RGB (243, 238, 254), RGB (231, 248, 241), RGB (253, 236, 236) };

HWND viewer;
HWND list;
HWND status;
HWND bar;
HWND details;
HWND copy_button;
HWND close_button;
HFONT font;
UINT dpi;
UINT sequence;
std::string path;
std::shared_ptr<std::atomic<bool>> cancelled;
std::vector<std::array<std::wstring, 11>> rows;	/* raw columns: details view and copy */
std::vector<std::array<std::wstring, 5>> simple;
std::vector<backend_map_info> info;	/* parallel to rows */
std::vector<int> shown;	/* list column -> rows/simple column */
UINT64 file_size;
UINT64 totals[CAT_COUNT];	/* file bytes per category */
const UINT columns[] = { IDS_MAP_GROUP, IDS_MAP_LOGICAL, IDS_MAP_LENGTH,
	IDS_MAP_TYPE, IDS_MAP_DEVICE, IDS_MAP_SPACE, IDS_MAP_OFFSET, IDS_MAP_STORED,
	IDS_MAP_ENCODING, IDS_MAP_DECODED_OFFSET, IDS_MAP_DECODED_LENGTH };
const int widths[] = { 65, 135, 135, 240, 120, 110, 145, 135, 90, 135, 135 };
const UINT simple_columns[] = { 0, IDS_MAP_COL_RANGE, IDS_MAP_COL_SIZE,
	IDS_MAP_COL_STATUS, IDS_MAP_COL_LOCATION };
const int simple_widths[] = { 50, 230, 100, 250, 260 };
const wchar_t sep[] = { L' ', L' ', 0x00B7, L' ', L' ', 0 };	/* middle dot */
const wchar_t dash[] = { L' ', 0x2013, L' ', 0 };	/* en dash */

UINT category (UINT flags)
{
	if (flags & BACKEND_MAP_UNKNOWN) return CAT_UNKNOWN;
	if (flags & (BACKEND_MAP_COMPRESSED | BACKEND_MAP_TRANSFORMED)) return CAT_ENCODED;
	if (flags & BACKEND_MAP_INLINE) return CAT_INLINE;
	if (flags & BACKEND_MAP_UNWRITTEN) return CAT_UNWRITTEN;
	if (flags & BACKEND_MAP_HOLE) return CAT_HOLE;
	if (flags & BACKEND_MAP_ZERO) return CAT_ZERO;
	return (flags & BACKEND_MAP_DIRECT) ? CAT_DATA : CAT_UNKNOWN;
}

std::wstring format (UINT id, const std::wstring &arg)
{
	std::wstring text = res_str (id);
	size_t at = text.find (L"%s");
	if (at != std::wstring::npos) text.replace (at, 2, arg);
	return text;
}

std::wstring location (const backend_map_info &m)
{
	if (!m.storage) return L"-";
	wchar_t hex[32];
	swprintf (hex, 32, L" (0x%llX)", m.storage_offset);
	std::wstring text = format_size (m.storage_offset) + hex;
	return m.fs_logical ? format (IDS_MAP_FS_LOGICAL, text) : text;
}

int strip_height ()
{
	return dpi_scale (dpi, 16);
}

/* Pixel span of an extent on a strip WIDTH pixels wide; never empty.  */
void extent_span (const backend_map_info &m, int width, int *x0, int *x1)
{
	*x0 = (int) ((double) m.offset * width / (double) file_size);
	*x1 = (int) ((double) (m.offset + m.length) * width / (double) file_size);
	if (*x0 >= width) *x0 = width - 1;
	if (*x1 > width) *x1 = width;
	if (*x1 <= *x0) *x1 = *x0 + 1;
}

void draw_bar (const DRAWITEMSTRUCT *di)
{
	RECT rc = di->rcItem;
	int w = rc.right - rc.left, h = rc.bottom - rc.top;
	HDC dc = CreateCompatibleDC (di->hDC);
	HBITMAP bmp = CreateCompatibleBitmap (di->hDC, w, h);
	HGDIOBJ old_bmp = SelectObject (dc, bmp);
	HGDIOBJ old_font = SelectObject (dc, font);
	HGDIOBJ old_brush = SelectObject (dc, GetStockObject (DC_BRUSH));
	RECT all = { 0, 0, w, h }, strip = { 0, 0, w, strip_height () };
	FillRect (dc, &all, GetSysColorBrush (COLOR_BTNFACE));
	FillRect (dc, &strip, GetSysColorBrush (COLOR_WINDOW));
	if (file_size)
		for (const auto &m : info)
		{
			if (!m.first) continue;
			int x0, x1;
			extent_span (m, w, &x0, &x1);
			RECT seg = { x0, strip.top, x1, strip.bottom };
			SetDCBrushColor (dc, cat_bar[category (m.flags)]);
			FillRect (dc, &seg, (HBRUSH) GetStockObject (DC_BRUSH));
		}
	FrameRect (dc, &strip, GetSysColorBrush (COLOR_BTNSHADOW));
	TEXTMETRICW tm;
	GetTextMetricsW (dc, &tm);
	int y = strip.bottom + dpi_scale (dpi, 6), box = tm.tmHeight * 2 / 3, x = 0;
	SetBkMode (dc, TRANSPARENT);
	SetTextColor (dc, GetSysColor (COLOR_BTNTEXT));
	for (int c = 0; c < CAT_COUNT; c++)
	{
		if (!totals[c]) continue;
		RECT swatch = { x, y + (tm.tmHeight - box) / 2, x + box, y + (tm.tmHeight - box) / 2 + box };
		SetDCBrushColor (dc, cat_bar[c]);
		FillRect (dc, &swatch, (HBRUSH) GetStockObject (DC_BRUSH));
		FrameRect (dc, &swatch, GetSysColorBrush (COLOR_BTNSHADOW));
		x += box + dpi_scale (dpi, 5);
		std::wstring label = res_str (cat_names[c]);
		SIZE size;
		TextOutW (dc, x, y, label.c_str (), (int) label.size ());
		GetTextExtentPoint32W (dc, label.c_str (), (int) label.size (), &size);
		x += size.cx + dpi_scale (dpi, 18);
	}
	BitBlt (di->hDC, rc.left, rc.top, w, h, dc, 0, 0, SRCCOPY);
	SelectObject (dc, old_brush);
	SelectObject (dc, old_font);
	SelectObject (dc, old_bmp);
	DeleteObject (bmp);
	DeleteDC (dc);
}

/* A click on the strip selects the rows of the extent under it.  */
void bar_click ()
{
	DWORD pos = GetMessagePos ();
	POINT pt = { (short) LOWORD (pos), (short) HIWORD (pos) };
	RECT rc;
	ScreenToClient (bar, &pt);
	GetClientRect (bar, &rc);
	if (!file_size || pt.y >= strip_height () || pt.x < 0 || pt.x >= rc.right) return;
	size_t hit = info.size ();
	for (size_t i = 0; i < info.size () && hit == info.size (); i++)
	{
		int x0, x1;
		if (!info[i].first) continue;
		extent_span (info[i], rc.right, &x0, &x1);
		if (pt.x >= x0 && pt.x < x1) hit = i;
	}
	if (hit == info.size ()) return;
	ListView_SetItemState (list, -1, 0, LVIS_SELECTED);
	for (size_t i = hit; i < info.size () && info[i].group == info[hit].group; i++)
		ListView_SetItemState (list, (int) i, LVIS_SELECTED, LVIS_SELECTED);
	ListView_SetItemState (list, (int) hit, LVIS_FOCUSED, LVIS_FOCUSED);
	ListView_EnsureVisible (list, (int) hit, FALSE);
	SetFocus (list);
}

LRESULT row_color (NMLVCUSTOMDRAW *cd)
{
	size_t item = (size_t) cd->nmcd.dwItemSpec;
	switch (cd->nmcd.dwDrawStage)
	{
	case CDDS_PREPAINT:
		return CDRF_NOTIFYITEMDRAW;
	case CDDS_ITEMPREPAINT:
		if (item < info.size () && !ListView_GetItemState (list, (int) item, LVIS_SELECTED))
			cd->clrTextBk = cat_row[category (info[item].flags)];
		return CDRF_NEWFONT;
	}
	return CDRF_DODEFAULT;
}

/* Simple view: five readable columns.  Details: the raw byte columns,
   minus the volume (it is in the title) and whatever says nothing for
   this file.  */
void set_columns ()
{
	bool detail = SendMessageW (details, BM_GETCHECK, 0, 0) == BST_CHECKED;
	while (ListView_DeleteColumn (list, 0)) {}
	shown.clear ();
	if (detail)
	{
		bool fs_logical = false, encoded = false;
		for (const auto &m : info) fs_logical |= m.fs_logical;
		for (const auto &r : rows) encoded |= r[8] != L"-";
		for (int i = 0; i < (int) std::size (columns); i++)
			if (i != 4 && (i != 5 || fs_logical) && (i < 8 || encoded)) shown.push_back (i);
	}
	else
		for (int i = 0; i < (int) std::size (simple_columns); i++) shown.push_back (i);
	for (int i = 0; i < (int) shown.size (); i++)
	{
		int src = shown[(size_t) i];
		std::wstring title_text = detail ? res_str (columns[src]) : src ? res_str (simple_columns[src]) : L"#";
		LVCOLUMNW col = {}; col.mask = LVCF_TEXT | LVCF_WIDTH;
		col.pszText = title_text.data (); col.cx = dpi_scale (dpi, detail ? widths[src] : simple_widths[src]);
		ListView_InsertColumn (list, i, &col);
	}
	InvalidateRect (list, nullptr, TRUE);
}

void layout (HWND dlg)
{
	RECT rc;
	GetClientRect (dlg, &rc);
	int pad = dpi_scale (dpi, 10), line = dpi_scale (dpi, 26);
	MoveWindow (status, pad, pad, rc.right - 2 * pad, line, TRUE);
	MoveWindow (bar, pad, pad + line, rc.right - 2 * pad, line * 2, TRUE);
	MoveWindow (list, pad, pad + line * 3, rc.right - 2 * pad,
		rc.bottom - pad * 3 - line * 4, TRUE);
	MoveWindow (copy_button, pad, rc.bottom - pad - line, dpi_scale (dpi, 160), line, TRUE);
	MoveWindow (details, pad * 2 + dpi_scale (dpi, 160), rc.bottom - pad - line, dpi_scale (dpi, 280), line, TRUE);
	MoveWindow (close_button, rc.right - pad - dpi_scale (dpi, 100),
		rc.bottom - pad - line, dpi_scale (dpi, 100), line, TRUE);
}

void set_font ()
{
	HFONT previous = font;
	font = create_message_font (dpi);
	for (HWND h : { list, status, bar, details, copy_button, close_button })
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
		status = CreateWindowW (L"STATIC", res_str (IDS_MAP_LOADING).c_str (), WS_CHILD | WS_VISIBLE |
			SS_NOPREFIX | SS_ENDELLIPSIS, 0, 0, 0, 0, dlg, nullptr, nullptr, nullptr);
		bar = CreateWindowW (L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW | SS_NOTIFY,
			0, 0, 0, 0, dlg, (HMENU) 102, nullptr, nullptr);
		list = CreateWindowExW (WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP |
			LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS, 0, 0, 0, 0, dlg, (HMENU) 100, nullptr, nullptr);
		ListView_SetExtendedListViewStyle (list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
		SetWindowTheme (list, L"Explorer", nullptr);
		copy_button = CreateWindowW (L"BUTTON", res_str (IDS_MAP_COPY).c_str (), WS_CHILD | WS_VISIBLE | WS_TABSTOP,
			0, 0, 0, 0, dlg, (HMENU) 101, nullptr, nullptr);
		details = CreateWindowW (L"BUTTON", res_str (IDS_MAP_DETAILS).c_str (), WS_CHILD | WS_VISIBLE | WS_TABSTOP |
			BS_AUTOCHECKBOX, 0, 0, 0, 0, dlg, (HMENU) 103, nullptr, nullptr);
		close_button = CreateWindowW (L"BUTTON", res_str (IDS_BTN_CANCEL).c_str (), WS_CHILD | WS_VISIBLE | WS_TABSTOP,
			0, 0, 0, 0, dlg, (HMENU) IDCANCEL, nullptr, nullptr);
		set_font (); set_columns (); center_on_owner (dlg, dpi_scale (dpi, 1050), dpi_scale (dpi, 620)); layout (dlg);
		file_map_task task { path, cancelled };
		sequence = backend_post (std::move (task));
		if (!sequence)
		{
			SetWindowTextW (status, L"Backend unavailable");
			SetWindowTextW (close_button, res_str (IDS_MAP_CLOSE).c_str ());
		}
		return TRUE;
	}
	case WM_SIZE: layout (dlg); return TRUE;
	case WM_DPICHANGED:
		dpi = HIWORD (wp); dpi_take_suggested (dlg, lp); set_font (); set_columns (); layout (dlg); return TRUE;
	case WM_GETMINMAXINFO:
		((MINMAXINFO *) lp)->ptMinTrackSize = { dpi_scale (dpi, 620), dpi_scale (dpi, 340) }; return TRUE;
	case WM_DRAWITEM:
		if (((DRAWITEMSTRUCT *) lp)->hwndItem != bar) break;
		draw_bar ((DRAWITEMSTRUCT *) lp);
		return TRUE;
	case WM_NOTIFY:
	{
		auto *hdr = (NMHDR *) lp;
		if (hdr->hwndFrom != list) break;
		if (hdr->code == LVN_GETDISPINFOW)
		{
			auto *item = &((NMLVDISPINFOW *) lp)->item;
			bool detail = SendMessageW (details, BM_GETCHECK, 0, 0) == BST_CHECKED;
			if ((item->mask & LVIF_TEXT) && item->iItem >= 0 && (size_t) item->iItem < rows.size () &&
				item->iSubItem >= 0 && (size_t) item->iSubItem < shown.size ())
			{
				int src = shown[(size_t) item->iSubItem];
				item->pszText = detail ? rows[(size_t) item->iItem][src].data () : simple[(size_t) item->iItem][src].data ();
			}
			return TRUE;
		}
		if (hdr->code == NM_CUSTOMDRAW)
		{
			SetWindowLongPtrW (dlg, DWLP_MSGRESULT, row_color ((NMLVCUSTOMDRAW *) lp));
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
		if (LOWORD (wp) == 102 && HIWORD (wp) == STN_CLICKED) { bar_click (); return TRUE; }
		if (LOWORD (wp) == 103 && HIWORD (wp) == BN_CLICKED) { set_columns (); return TRUE; }
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
	file_size = res->file_size;
	info = std::move (res->map_info);
	rows.reserve (res->map_rows.size ());
	for (const auto &source : res->map_rows)
	{
		std::array<std::wstring, 11> row;
		for (size_t i = 0; i < row.size (); i++) row[i] = widen (source[i]);
		rows.push_back (std::move (row));
	}
	UINT64 extents = 0, fragments = 0, next = 0;
	bool placed = false;
	simple.reserve (info.size ());
	for (const auto &m : info)
	{
		std::array<std::wstring, 5> row;
		UINT c = category (m.flags);
		if (m.first)
		{
			extents++;
			totals[c] += m.length;
			row[0] = std::to_wstring (m.group);
			row[1] = format_size (m.offset) + dash + format_size (m.offset + m.length);
			row[2] = format_size (m.length);
			row[3] = res_str (cat_names[c]);
			if (m.flags & BACKEND_MAP_SHARED) row[3] += res_str (IDS_MAP_SHARED);
			/* Fragments: breaks in the on-disk run of the file's data.  */
			if (m.storage && !m.fs_logical && (c == CAT_DATA || c == CAT_ENCODED))
			{
				if (!placed || m.storage_offset != next) fragments++;
				placed = true;
				next = m.storage_offset + m.storage_length;
			}
		}
		row[4] = location (m);
		simple.push_back (std::move (row));
	}
	ListView_SetItemCountEx (list, (int) rows.size (), LVSICF_NOSCROLL);
	set_columns ();
	std::wstring text = format (IDS_MAP_SUM_SIZE, format_size (file_size)) + sep +
		format (IDS_MAP_SUM_EXTENTS, std::to_wstring (extents));
	if (fragments) text += sep + format (IDS_MAP_SUM_FRAGMENTS, std::to_wstring (fragments));
	for (int c = 0; c < CAT_COUNT; c++)
		if (totals[c]) text += sep + res_str (cat_names[c]) + L" " + format_size (totals[c]);
	if (res->map_stopped) text += sep + res_str (IDS_MAP_PARTIAL);
	if (!res->error.empty ()) text = widen (res->error) + sep + text;
	SetWindowTextW (status, text.c_str ());
	SetWindowTextW (close_button, res_str (IDS_MAP_CLOSE).c_str ());
	InvalidateRect (bar, nullptr, FALSE);
}

void show_file_map (const std::string &name)
{
	path = name; rows.clear (); simple.clear (); info.clear (); sequence = 0;
	file_size = 0;
	for (auto &t : totals) t = 0;
	cancelled = std::make_shared<std::atomic<bool>> (false);
	/* Zero-terminated menu/class/title follow this aligned dialog template. */
	struct { DLGTEMPLATE dlg; WORD menu, cls, title; } templ = {};
	templ.dlg.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | DS_MODALFRAME;
	templ.dlg.cx = 700; templ.dlg.cy = 400;
	{
		modal_scope hold;
		DialogBoxIndirectParamW (GetModuleHandleW (nullptr), &templ.dlg, g_main, proc, 0);
	}
	cancelled->store (true); viewer = nullptr; rows.clear (); simple.clear (); info.clear ();
	if (font) { DeleteObject (font); font = nullptr; }
}
