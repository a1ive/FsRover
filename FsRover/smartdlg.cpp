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
 * S.M.A.R.T. of a physical drive "hdN".
 *
 * cdi_init_smart() walks every drive in the machine and takes seconds,
 * so the CDI_SMART handle is created and scanned on the first view and
 * then kept for the session; Refresh re-reads only that one drive
 * (cdi_update_smart) and the HEX box re-formats what is already cached.
 *
 * The sheet above the attribute list is painted like the disk
 * properties one.  Everything here runs on the GUI thread and touches no
 * grub state.
 */

#include "build_config.h"

#if FSROVER_ENABLE_ADMIN_FEATURES

#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

#include "libcdi/libcdi.h"

namespace
{

/* libcdi ships one DLL per architecture, each under its own name.  */
#if defined (_M_ARM64)
const wchar_t CDI_DLL[] = L"libcdiaa64.dll";
#elif defined (_M_X64)
const wchar_t CDI_DLL[] = L"libcdi.dll";
#else
const wchar_t CDI_DLL[] = L"libcdix86.dll";
#endif

/* Only the entry points this viewer uses; the DLL is rejected unless it
   exports every one of them.  */
struct cdi_api
{
	HMODULE dll;
	CDI_SMART *(WINAPI *create) (VOID);
	VOID (WINAPI *destroy) (CDI_SMART *ptr);
	VOID (WINAPI *init) (CDI_SMART *ptr, UINT64 flags);
	DWORD (WINAPI *update) (CDI_SMART *ptr, INT index);
	INT (WINAPI *count) (CDI_SMART *ptr);
	BOOL (WINAPI *get_bool) (CDI_SMART *ptr, INT index, enum CDI_ATA_BOOL attr);
	INT (WINAPI *get_int) (CDI_SMART *ptr, INT index, enum CDI_ATA_INT attr);
	DWORD (WINAPI *get_dword) (CDI_SMART *ptr, INT index, enum CDI_ATA_DWORD attr);
	WCHAR *(WINAPI *get_string) (CDI_SMART *ptr, INT index, enum CDI_ATA_STRING attr);
	VOID (WINAPI *free_string) (WCHAR *ptr);
	WCHAR *(WINAPI *attr_format) (CDI_SMART *ptr, INT index);
	BYTE (WINAPI *attr_id) (CDI_SMART *ptr, INT index, INT attr);
	WCHAR *(WINAPI *attr_value) (CDI_SMART *ptr, INT index, INT attr, BOOL hex);
	INT (WINAPI *attr_status) (CDI_SMART *ptr, INT index, INT attr);
	WCHAR *(WINAPI *attr_name) (CDI_SMART *ptr, INT index, BYTE id);
};

cdi_api g_cdi;
CDI_SMART *g_cdi_smart;	/* created and scanned once, kept for the session */

#define CDI_BIND(field, name)	\
	(g_cdi.field = reinterpret_cast<decltype (g_cdi.field)> (GetProcAddress (g_cdi.dll, name)))

/* Load libcdi from the executable's own directory, once.  A missing or
   incomplete DLL is not an error: the feature is simply not there.  */
bool
cdi_load (void)
{
	static int state = -1;	/* -1 = not tried yet */
	wchar_t path[MAX_PATH];
	DWORD len;
	wchar_t *sep;
	size_t dir;

	if (state >= 0)
		return state > 0;
	state = 0;

	len = GetModuleFileNameW (nullptr, path, MAX_PATH);
	if (!len || len >= MAX_PATH)
		return false;
	sep = wcsrchr (path, L'\\');
	if (!sep)
		return false;
	dir = (size_t) (sep + 1 - path);
	if (dir + wcslen (CDI_DLL) >= MAX_PATH)
		return false;
	wcscpy_s (path + dir, MAX_PATH - dir, CDI_DLL);

	/* An absolute path with ALTERED_SEARCH_PATH: whatever libcdi
	   imports is resolved from its own directory, never from the
	   current one.  */
	g_cdi.dll = LoadLibraryExW (path, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
	if (!g_cdi.dll)
		return false;
	if (!CDI_BIND (create, "cdi_create_smart")
		|| !CDI_BIND (destroy, "cdi_destroy_smart")
		|| !CDI_BIND (init, "cdi_init_smart")
		|| !CDI_BIND (update, "cdi_update_smart")
		|| !CDI_BIND (count, "cdi_get_disk_count")
		|| !CDI_BIND (get_bool, "cdi_get_bool")
		|| !CDI_BIND (get_int, "cdi_get_int")
		|| !CDI_BIND (get_dword, "cdi_get_dword")
		|| !CDI_BIND (get_string, "cdi_get_string")
		|| !CDI_BIND (free_string, "cdi_free_string")
		|| !CDI_BIND (attr_format, "cdi_get_smart_format")
		|| !CDI_BIND (attr_id, "cdi_get_smart_id")
		|| !CDI_BIND (attr_value, "cdi_get_smart_value")
		|| !CDI_BIND (attr_status, "cdi_get_smart_status")
		|| !CDI_BIND (attr_name, "cdi_get_smart_name"))
		goto fail;
	state = 1;
	return true;
fail:
	FreeLibrary (g_cdi.dll);
	g_cdi = {};
	return false;
}

/* Layout metrics authored at 96 DPI; scaled through dpi_scale().  */
constexpr int SM_MARGIN = 12;
constexpr int SM_GAP = 8;
constexpr int SM_BOX_W = 92;	/* health and temperature boxes */
constexpr int SM_BOX_H = 38;
constexpr int SM_BTN_W = 64;
constexpr int SM_BTN_H = 23;
constexpr int SM_HEX_W = 50;
constexpr int SM_VAL_MIN = 44;	/* narrowest right-hand value column */
constexpr int SM_NAME_MIN = 120;	/* narrowest attribute-name column */
constexpr int SM_LIST_ROWS = 9;	/* attribute rows the initial size shows */

struct sm_field
{
	std::wstring label;
	std::wstring value;
};

struct sm_attr
{
	std::wstring id;
	std::wstring name;
	std::wstring value;	/* the whole "Cur Wor Thr RawValues" line */
	int status;
};

HWND g_smart;	/* the viewer, null when closed */
INT g_sm_disk = -1;	/* libcdi disk index the sheet is about */
bool g_sm_hex;	/* HEX: raw values in hexadecimal, kept across views */

/* Snapshot of the drive, formatted from libcdi before each paint pass.
   The grub device name and the capacity come from the tree, everything
   else from libcdi.  */
std::wstring g_sm_dev;	/* "hd0", the caption and the model's fallback */
std::wstring g_sm_caption;
std::wstring g_sm_model;	/* header line */
std::wstring g_sm_size;
std::wstring g_sm_health;	/* "Good 100%" */
std::wstring g_sm_temp;
int g_sm_health_status;
int g_sm_temp_status;
std::vector<sm_field> g_sm_left;	/* identity rows */
std::vector<sm_field> g_sm_right;	/* counters */
sm_field g_sm_features;	/* spans both columns */
std::wstring g_sm_format;	/* value column header, from libcdi */
std::vector<sm_attr> g_sm_attrs;

/* Owned by the dialog, released in WM_DESTROY.  */
HFONT g_sm_head_font;	/* model and box text: a step up and semibold */
HFONT g_sm_small_font;	/* box captions */
HFONT g_sm_list_font;	/* fixed pitch, so the value columns line up */

UINT g_sm_dpi = 96;	/* this window's DPI, refreshed on WM_DPICHANGED */

int
sm_scale (int value)
{
	return dpi_scale (g_sm_dpi, value);
}

/* Painted layout, measured from the snapshot and the client width.  */
struct sm_layout
{
	int head_h;	/* header row: model, size, buttons */
	int y_rule1;
	int y_body;
	int body_h;
	int y_rule2;
	int y_list;
	int row_h;	/* one field row */
	int small_h;	/* line height of g_sm_small_font */
	int lw_left;	/* label column widths */
	int lw_right;
	int vw_right;	/* right-hand value column */
	int x_size;	/* right edge of the header's size text */
};

sm_layout g_sm_lay;

/* PCT percent of A over B, for tinting a colour towards the window
   background without assuming a light or a dark theme.  */
COLORREF
mix (COLORREF a, COLORREF b, int pct)
{
	int r = (GetRValue (a) * pct + GetRValue (b) * (100 - pct)) / 100;
	int g = (GetGValue (a) * pct + GetGValue (b) * (100 - pct)) / 100;
	int bl = (GetBValue (a) * pct + GetBValue (b) * (100 - pct)) / 100;

	return RGB (r, g, bl);
}

UINT
sm_status_name (int status)
{
	switch (status)
	{
	case CDI_DISK_STATUS_GOOD:
		return IDS_SM_GOOD;
	case CDI_DISK_STATUS_CAUTION:
		return IDS_SM_CAUTION;
	case CDI_DISK_STATUS_BAD:
		return IDS_SM_BAD;
	}
	return IDS_SM_UNKNOWN;
}

/* Fixed hues rather than system colours: green/amber/red is what a
   health readout means everywhere, and each one is only ever painted
   mixed into COLOR_WINDOW.  */
COLORREF
sm_status_color (int status)
{
	switch (status)
	{
	case CDI_DISK_STATUS_GOOD:
		return RGB (0x2e, 0xa0, 0x43);
	case CDI_DISK_STATUS_CAUTION:
		return RGB (0xd8, 0x8f, 0x00);
	case CDI_DISK_STATUS_BAD:
		return RGB (0xd0, 0x3a, 0x2f);
	}
	return GetSysColor (COLOR_BTNSHADOW);
}

/* The drive's own alarm threshold when it has one, CrystalDiskInfo's
   default otherwise; 90 C is where every drive is out of spec.  */
int
sm_temp_status (int temp, int alarm)
{
	if (temp < 0)
		return CDI_DISK_STATUS_UNKNOWN;
	if (alarm <= 0)
		alarm = 60;
	if (temp >= 90)
		return CDI_DISK_STATUS_BAD;
	if (temp >= alarm)
		return CDI_DISK_STATUS_CAUTION;
	return CDI_DISK_STATUS_GOOD;
}

std::wstring
sm_string (enum CDI_ATA_STRING attr)
{
	WCHAR *str = g_cdi.get_string (g_cdi_smart, g_sm_disk, attr);
	std::wstring out;

	if (str)
	{
		out = str;
		g_cdi.free_string (str);
	}
	return out;
}

/* A negative count is libcdi for "the drive does not report this".  */
std::wstring
sm_count (int value, const wchar_t *unit)
{
	wchar_t buf[64];

	if (value < 0)
		return {};
	swprintf (buf, 64, L"%d%s", value, unit);
	return buf;
}

void
sm_add (std::vector<sm_field> &rows, UINT label, const std::wstring &value)
{
	sm_field f;

	f.label = res_str (label) + res_str (IDS_DP_COLON);
	f.value = value.empty () ? L"-" : value;
	rows.push_back (std::move (f));
}

/* The attributes, and the header of the one column their values live
   in.  libcdi prints format and values from the same branch and pads
   both to the same fields ("Cur Wor Thr RawValues(6)" over
   "100 100  10 0"), so a fixed-pitch list needs no columns of its own to
   line them up.  */
void
sm_build_attrs (void)
{
	WCHAR *str = g_cdi.attr_format (g_cdi_smart, g_sm_disk);
	DWORD count = g_cdi.get_dword (g_cdi_smart, g_sm_disk, CDI_DWORD_ATTR_COUNT);

	g_sm_format.clear ();
	if (str)
	{
		g_sm_format = str;
		g_cdi.free_string (str);
	}

	g_sm_attrs.clear ();
	for (DWORD i = 0; i < count; i++)
	{
		BYTE id = g_cdi.attr_id (g_cdi_smart, g_sm_disk, (INT) i);
		wchar_t buf[8];
		sm_attr a;

		if (!id)
			continue;
		swprintf (buf, 8, L"%02X", id);
		a.id = buf;
		str = g_cdi.attr_name (g_cdi_smart, g_sm_disk, id);
		if (str)
		{
			a.name = str;
			g_cdi.free_string (str);
		}
		str = g_cdi.attr_value (g_cdi_smart, g_sm_disk, (INT) i, g_sm_hex);
		if (str)
		{
			a.value = str;
			g_cdi.free_string (str);
		}
		a.status = g_cdi.attr_status (g_cdi_smart, g_sm_disk, (INT) i);
		g_sm_attrs.push_back (std::move (a));
	}
}

void
sm_feature (std::wstring &text, bool on, const wchar_t *name)
{
	if (!on)
		return;
	if (!text.empty ())
		text += L' ';
	text += name;
}

/* Format everything the sheet shows out of libcdi's cached data.  Run
   again after a refresh and after the HEX box is toggled.  */
void
sm_build (void)
{
	BOOL ssd = g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_SSD);
	int life = g_cdi.get_int (g_cdi_smart, g_sm_disk, CDI_INT_LIFE);
	int temp = g_cdi.get_int (g_cdi_smart, g_sm_disk, CDI_INT_TEMPERATURE);
	int nand = g_cdi.get_int (g_cdi_smart, g_sm_disk, CDI_INT_NAND_WRITES);
	std::wstring cur = sm_string (CDI_STRING_TRANSFER_MODE_CUR);
	std::wstring best = sm_string (CDI_STRING_TRANSFER_MODE_MAX);
	std::wstring features;
	DWORD buffer, rpm;

	g_sm_left.clear ();
	g_sm_right.clear ();

	g_sm_model = sm_string (CDI_STRING_MODEL);
	if (g_sm_model.empty ())
		g_sm_model = g_sm_dev;
	g_sm_health_status = g_cdi.get_int (g_cdi_smart, g_sm_disk, CDI_INT_DISK_STATUS);
	g_sm_health = res_str (sm_status_name (g_sm_health_status));
	if (life >= 0)
		g_sm_health += L" " + std::to_wstring (life) + L"%";
	g_sm_temp_status = sm_temp_status (temp,
		g_cdi.get_int (g_cdi_smart, g_sm_disk, CDI_INT_TEMPERATURE_ALARM));
	g_sm_temp = temp < 0 ? L"-" : std::to_wstring (temp) + L" \u00b0C";

	sm_add (g_sm_left, IDS_SM_FIRMWARE, sm_string (CDI_STRING_FIRMWARE));
	sm_add (g_sm_left, IDS_SM_SERIAL, sm_string (CDI_STRING_SN));
	sm_add (g_sm_left, IDS_SM_INTERFACE, sm_string (CDI_STRING_INTERFACE));
	/* Negotiated mode first, then what the link could do at best.  */
	if (!cur.empty () && !best.empty ())
		cur += L" | " + best;
	else
		cur += best;
	sm_add (g_sm_left, IDS_SM_MODE, cur);
	sm_add (g_sm_left, IDS_SM_DRIVE, sm_string (CDI_STRING_DRIVE_MAP));
	sm_add (g_sm_left, IDS_SM_STANDARD, sm_string (CDI_STRING_VERSION_MAJOR));

	/* What a drive counts depends on what it is made of: a solid state
	   drive reports how much has gone through it (and, when the
	   controller tells, how much of that reached the flash), a
	   spinning one its cache and its speed.  */
	if (ssd)
	{
		sm_add (g_sm_right, IDS_SM_READS,
			sm_count (g_cdi.get_int (g_cdi_smart, g_sm_disk, CDI_INT_HOST_READS), L" GB"));
		sm_add (g_sm_right, IDS_SM_WRITES,
			sm_count (g_cdi.get_int (g_cdi_smart, g_sm_disk, CDI_INT_HOST_WRITES), L" GB"));
		if (nand >= 0)
			sm_add (g_sm_right, IDS_SM_NAND, sm_count (nand, L" GB"));
		sm_add (g_sm_right, IDS_SM_RPM, L"(SSD)");
	}
	else
	{
		buffer = g_cdi.get_dword (g_cdi_smart, g_sm_disk, CDI_DWORD_BUFFER_SIZE);
		rpm = g_cdi.get_dword (g_cdi_smart, g_sm_disk, CDI_DWORD_ROTATION_RATE);
		sm_add (g_sm_right, IDS_SM_BUFFER, buffer ? format_size (buffer) : L"");
		sm_add (g_sm_right, IDS_SM_RPM, rpm ? std::to_wstring (rpm) + L" RPM" : L"");
	}
	sm_add (g_sm_right, IDS_SM_POWER_COUNT,
		std::to_wstring (g_cdi.get_dword (g_cdi_smart, g_sm_disk, CDI_DWORD_POWER_ON_COUNT)));
	sm_add (g_sm_right, IDS_SM_POWER_HOURS,
		sm_count (g_cdi.get_int (g_cdi_smart, g_sm_disk, CDI_INT_POWER_ON_HOURS), L""));

	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_SMART) != FALSE, L"SMART");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_AAM) != FALSE, L"AAM");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_APM) != FALSE, L"APM");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_NCQ) != FALSE, L"NCQ");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_NV_CACHE) != FALSE, L"NVCache");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_DEVSLP) != FALSE, L"DEVSLP");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_STREAMING) != FALSE, L"Streaming");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_GPL) != FALSE, L"GPL");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_TRIM) != FALSE, L"TRIM");
	sm_feature (features, g_cdi.get_bool (g_cdi_smart, g_sm_disk, CDI_BOOL_VOLATILE_WRITE_CACHE) != FALSE,
		L"VolatileWriteCache");
	g_sm_features.label = res_str (IDS_SM_FEATURES) + res_str (IDS_DP_COLON);
	g_sm_features.value = features.empty () ? L"-" : features;

	sm_build_attrs ();
}

int
sm_text_w (HDC dc, const std::wstring &text)
{
	SIZE size = {};

	GetTextExtentPoint32W (dc, text.c_str (), (int) text.size (), &size);
	return size.cx;
}

int
sm_widest (HDC dc, const std::vector<sm_field> &rows, bool value)
{
	int w = 0;

	for (const sm_field &f : rows)
	{
		int cx = sm_text_w (dc, value ? f.value : f.label);

		if (cx > w)
			w = cx;
	}
	return w;
}

/* Rows in the field grid: the two columns are filled independently and
   the longer one decides.  */
size_t
sm_rows (void)
{
	return g_sm_left.size () > g_sm_right.size () ? g_sm_left.size () : g_sm_right.size ();
}

void
sm_measure (HWND dlg)
{
	HDC dc = GetDC (dlg);
	HFONT body = (HFONT) SendMessageW (dlg, WM_GETFONT, 0, 0);
	HFONT old = (HFONT) SelectObject (dc, g_sm_head_font);
	TEXTMETRICW tm;
	int m = sm_scale (SM_MARGIN);
	int label_w, grid_h, boxes_h;

	GetTextMetricsW (dc, &tm);
	g_sm_lay.head_h = tm.tmHeight;
	if (g_sm_lay.head_h < sm_scale (SM_BTN_H))
		g_sm_lay.head_h = sm_scale (SM_BTN_H);

	SelectObject (dc, body);
	GetTextMetricsW (dc, &tm);
	g_sm_lay.row_h = tm.tmHeight + sm_scale (6);
	label_w = sm_text_w (dc, g_sm_features.label);
	g_sm_lay.lw_left = sm_widest (dc, g_sm_left, false);
	if (g_sm_lay.lw_left < label_w)
		g_sm_lay.lw_left = label_w;
	g_sm_lay.lw_right = sm_widest (dc, g_sm_right, false);
	g_sm_lay.vw_right = sm_widest (dc, g_sm_right, true);
	if (g_sm_lay.vw_right < sm_scale (SM_VAL_MIN))
		g_sm_lay.vw_right = sm_scale (SM_VAL_MIN);

	SelectObject (dc, g_sm_small_font);
	GetTextMetricsW (dc, &tm);
	g_sm_lay.small_h = tm.tmHeight;

	g_sm_lay.y_rule1 = m + g_sm_lay.head_h + m;
	g_sm_lay.y_body = g_sm_lay.y_rule1 + m;
	/* One row per pair plus the features row, which spans both.  */
	grid_h = ((int) sm_rows () + 1) * g_sm_lay.row_h;
	boxes_h = 2 * (g_sm_lay.small_h + sm_scale (2) + sm_scale (SM_BOX_H)) + sm_scale (SM_GAP);
	g_sm_lay.body_h = grid_h > boxes_h ? grid_h : boxes_h;
	g_sm_lay.y_rule2 = g_sm_lay.y_body + g_sm_lay.body_h + m;
	g_sm_lay.y_list = g_sm_lay.y_rule2 + m;

	SelectObject (dc, old);
	ReleaseDC (dlg, dc);
}

/* Content width for the ID and value columns; the attribute name takes
   whatever is left over, being the only one holding prose.  */
void
sm_fit_columns (HWND list)
{
	HDC dc = GetDC (list);
	HFONT old = (HFONT) SelectObject (dc, (HFONT) SendMessageW (list, WM_GETFONT, 0, 0));
	int pad = sm_scale (18);
	int id_w = sm_text_w (dc, L"ID");
	int val_w = sm_text_w (dc, g_sm_format);
	int name_w;
	RECT rc;

	for (const sm_attr &a : g_sm_attrs)
	{
		int cx = sm_text_w (dc, a.id);

		if (cx > id_w)
			id_w = cx;
		cx = sm_text_w (dc, a.value);
		if (cx > val_w)
			val_w = cx;
	}
	SelectObject (dc, old);
	ReleaseDC (list, dc);

	ListView_SetColumnWidth (list, 0, id_w + pad);
	ListView_SetColumnWidth (list, 2, val_w + pad);
	GetClientRect (list, &rc);
	name_w = rc.right - (id_w + pad) - (val_w + pad) - system_metric_dpi (g_sm_dpi, SM_CXVSCROLL);
	if (name_w < sm_scale (SM_NAME_MIN))
		name_w = sm_scale (SM_NAME_MIN);
	ListView_SetColumnWidth (list, 1, name_w);
}

void
sm_fill (HWND list)
{
	LVCOLUMNW col = {};

	/* The format only changes with the drive, but it is the value
	   column's header and both come out of the same snapshot.  */
	col.mask = LVCF_TEXT;
	col.pszText = g_sm_format.data ();
	ListView_SetColumn (list, 2, &col);

	ListView_DeleteAllItems (list);
	for (size_t i = 0; i < g_sm_attrs.size (); i++)
	{
		LVITEMW item = {};

		item.mask = LVIF_TEXT;
		item.iItem = (int) i;
		item.pszText = g_sm_attrs[i].id.data ();
		ListView_InsertItem (list, &item);
		ListView_SetItemText (list, (int) i, 1, g_sm_attrs[i].name.data ());
		ListView_SetItemText (list, (int) i, 2, g_sm_attrs[i].value.data ());
	}
	sm_fit_columns (list);
}

void
sm_columns (HWND list)
{
	std::wstring name = res_str (IDS_SM_ATTR);
	LVCOLUMNW col = {};
	std::wstring id = L"ID";

	col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
	col.fmt = LVCFMT_LEFT;
	col.cx = sm_scale (40);
	col.pszText = id.data ();
	ListView_InsertColumn (list, 0, &col);
	col.cx = sm_scale (SM_NAME_MIN);
	col.pszText = name.data ();
	ListView_InsertColumn (list, 1, &col);
	col.cx = sm_scale (SM_VAL_MIN);
	col.pszText = g_sm_format.data ();
	ListView_InsertColumn (list, 2, &col);
}

void
sm_place (HWND dlg)
{
	HWND list = GetDlgItem (dlg, IDC_SMART_LIST);
	int m = sm_scale (SM_MARGIN);
	int gap = sm_scale (SM_GAP);
	int bw = sm_scale (SM_BTN_W);
	int bh = sm_scale (SM_BTN_H);
	int hex_w = sm_scale (SM_HEX_W);
	int y = m + (g_sm_lay.head_h - bh) / 2;
	int h;
	RECT rc;

	GetClientRect (dlg, &rc);
	MoveWindow (GetDlgItem (dlg, IDC_SMART_HEX), rc.right - m - hex_w, y, hex_w, bh, TRUE);
	MoveWindow (GetDlgItem (dlg, IDC_SMART_REFRESH),
		rc.right - m - hex_w - gap - bw, y, bw, bh, TRUE);
	g_sm_lay.x_size = rc.right - m - hex_w - gap - bw - gap;

	h = rc.bottom - m - g_sm_lay.y_list;
	if (h < sm_scale (40))
		h = sm_scale (40);
	MoveWindow (list, m, g_sm_lay.y_list, rc.right - 2 * m, h, TRUE);
	sm_fit_columns (list);
}

void
sm_rule (HDC dc, int x1, int x2, int y)
{
	RECT r = { x1, y, x2, y + 1 };
	HBRUSH brush = CreateSolidBrush (mix (GetSysColor (COLOR_BTNSHADOW), GetSysColor (COLOR_BTNFACE), 45));

	FillRect (dc, &r, brush);
	DeleteObject (brush);
}

/* One readout box: a tinted body in the status colour with the value
   centred in it, under a small caption.  */
void
sm_draw_box (HDC dc, int x, int y, const std::wstring &caption, const std::wstring &value, int status)
{
	COLORREF face = GetSysColor (COLOR_WINDOW);
	COLORREF accent = sm_status_color (status);
	int w = sm_scale (SM_BOX_W);
	int h = sm_scale (SM_BOX_H);
	RECT tr = { x, y, x + w, y + g_sm_lay.small_h };
	RECT box = { x, tr.bottom + sm_scale (2), x + w, tr.bottom + sm_scale (2) + h };
	UINT fmt = DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX;
	HBRUSH brush;

	SelectObject (dc, g_sm_small_font);
	SetTextColor (dc, GetSysColor (COLOR_GRAYTEXT));
	DrawTextW (dc, caption.c_str (), -1, &tr, fmt);

	brush = CreateSolidBrush (mix (accent, face, 20));
	FillRect (dc, &box, brush);
	DeleteObject (brush);
	brush = CreateSolidBrush (mix (accent, face, 65));
	FrameRect (dc, &box, brush);
	DeleteObject (brush);

	InflateRect (&box, -sm_scale (2), 0);
	SelectObject (dc, g_sm_head_font);
	SetTextColor (dc, GetSysColor (COLOR_WINDOWTEXT));
	DrawTextW (dc, value.c_str (), -1, &box,
		DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
}

void
sm_draw_row (HDC dc, const std::wstring &label, const std::wstring &value,
	     int x, int label_w, int value_x, int value_w, int y, UINT fmt)
{
	RECT tr = { x, y, x + label_w, y + g_sm_lay.row_h };

	SetTextColor (dc, GetSysColor (COLOR_GRAYTEXT));
	DrawTextW (dc, label.c_str (), -1, &tr, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
	tr = { value_x, y, value_x + value_w, y + g_sm_lay.row_h };
	SetTextColor (dc, GetSysColor (COLOR_WINDOWTEXT));
	DrawTextW (dc, value.c_str (), -1, &tr, fmt);
}

void
sm_paint (HWND dlg, HDC dc)
{
	HFONT body = (HFONT) SendMessageW (dlg, WM_GETFONT, 0, 0);
	HFONT old = (HFONT) SelectObject (dc, g_sm_head_font);
	UINT left = DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX;
	UINT right = DT_RIGHT | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX;
	int m = sm_scale (SM_MARGIN);
	int gap = sm_scale (SM_GAP);
	int x0, x_lv, x_rv, x_rl, w_lv, y;
	RECT rc, tr;

	GetClientRect (dlg, &rc);
	SetBkMode (dc, TRANSPARENT);

	/* Header: the model on the left, the capacity in front of the
	   buttons.  The two use different fonts, so both are centred
	   against the header row rather than sharing a baseline.  */
	tr = { m, m, g_sm_lay.x_size, m + g_sm_lay.head_h };
	SetTextColor (dc, GetSysColor (COLOR_WINDOWTEXT));
	DrawTextW (dc, g_sm_model.c_str (), -1, &tr, left | DT_VCENTER);
	SelectObject (dc, body);
	SetTextColor (dc, GetSysColor (COLOR_GRAYTEXT));
	DrawTextW (dc, g_sm_size.c_str (), -1, &tr, right | DT_VCENTER);
	sm_rule (dc, m, rc.right - m, g_sm_lay.y_rule1);

	sm_draw_box (dc, m, g_sm_lay.y_body, res_str (IDS_SM_HEALTH), g_sm_health, g_sm_health_status);
	sm_draw_box (dc, m, g_sm_lay.y_body + g_sm_lay.small_h + sm_scale (2)
		+ sm_scale (SM_BOX_H) + sm_scale (SM_GAP),
		res_str (IDS_SM_TEMPERATURE), g_sm_temp, g_sm_temp_status);

	/* Two label/value pairs per row, the right-hand values flush with
	   the right margin; the features row spans the whole width.  */
	SelectObject (dc, body);
	x0 = m + sm_scale (SM_BOX_W) + m;
	x_lv = x0 + g_sm_lay.lw_left + gap;
	x_rv = rc.right - m - g_sm_lay.vw_right;
	x_rl = x_rv - gap - g_sm_lay.lw_right;
	w_lv = x_rl - gap - x_lv;
	if (w_lv < 0)
		w_lv = 0;
	y = g_sm_lay.y_body;
	for (size_t i = 0; i < sm_rows (); i++)
	{
		if (i < g_sm_left.size ())
			sm_draw_row (dc, g_sm_left[i].label, g_sm_left[i].value,
				x0, g_sm_lay.lw_left, x_lv, w_lv, y, left);
		if (i < g_sm_right.size ())
			sm_draw_row (dc, g_sm_right[i].label, g_sm_right[i].value,
				x_rl, g_sm_lay.lw_right, x_rv, g_sm_lay.vw_right, y, right);
		y += g_sm_lay.row_h;
	}
	sm_draw_row (dc, g_sm_features.label, g_sm_features.value,
		x0, g_sm_lay.lw_left, x_lv, rc.right - m - x_lv, y, left);

	sm_rule (dc, m, rc.right - m, g_sm_lay.y_rule2);
	SelectObject (dc, old);
}

/* The attribute's own health, as the colour of its ID cell.  */
LRESULT
sm_customdraw (NMLVCUSTOMDRAW *cd)
{
	size_t item = (size_t) cd->nmcd.dwItemSpec;

	switch (cd->nmcd.dwDrawStage)
	{
	case CDDS_PREPAINT:
		return CDRF_NOTIFYITEMDRAW;
	case CDDS_ITEMPREPAINT:
		return CDRF_NOTIFYSUBITEMDRAW;
	case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
		if (!cd->iSubItem && item < g_sm_attrs.size ())
			cd->clrTextBk = mix (sm_status_color (g_sm_attrs[item].status),
				GetSysColor (COLOR_WINDOW), 35);
		return CDRF_NEWFONT;
	}
	return CDRF_DODEFAULT;
}

void
sm_reload (HWND dlg)
{
	sm_build ();
	sm_measure (dlg);
	sm_place (dlg);
	sm_fill (GetDlgItem (dlg, IDC_SMART_LIST));
	InvalidateRect (dlg, nullptr, TRUE);
}

/* On a monitor change the dialog manager hands every control the
   rescaled dialog font.  The attribute list only lines up in the
   fixed-pitch one built below, so that is the only font let through.  */
LRESULT CALLBACK
sm_list_proc (HWND wnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR)
{
	if (msg == WM_SETFONT && (HFONT) wp != g_sm_list_font)
		return 0;
	if (msg == WM_NCDESTROY)
		RemoveWindowSubclass (wnd, sm_list_proc, 0);
	return DefSubclassProc (wnd, msg, wp, lp);
}

/* The three fonts, all derived from the dialog font, which the dialog
   manager has already sized for this monitor (lfHeight is negative, so
   a bigger factor is a bigger font).  On a DPI change this runs again,
   after the manager has resized that font.  */
void
sm_apply_dpi (HWND dlg)
{
	HFONT body = (HFONT) SendMessageW (dlg, WM_GETFONT, 0, 0);
	HWND list = GetDlgItem (dlg, IDC_SMART_LIST);
	LOGFONTW lf = {};
	LONG height;

	GetObjectW (body, (int) sizeof (lf), &lf);
	height = lf.lfHeight;
	lf.lfHeight = height * 6 / 5;
	lf.lfWeight = FW_SEMIBOLD;
	if (g_sm_head_font)
		DeleteObject (g_sm_head_font);
	g_sm_head_font = CreateFontIndirectW (&lf);
	lf.lfHeight = height * 6 / 7;
	lf.lfWeight = FW_NORMAL;
	if (g_sm_small_font)
		DeleteObject (g_sm_small_font);
	g_sm_small_font = CreateFontIndirectW (&lf);
	/* libcdi pads the format string and the values into the same
	   fields, so the list only lines up in a fixed-pitch font.
	   FIXED_PITCH is what makes the fallback one too.  */
	lf.lfHeight = height;
	lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
	wcscpy_s (lf.lfFaceName, L"Consolas");
	HFONT prev_list = g_sm_list_font;
	g_sm_list_font = CreateFontIndirectW (&lf);

	SendMessageW (list, WM_SETFONT, (WPARAM) g_sm_list_font, TRUE);
	/* The header carries the format string over the values it
	   describes, so it has to be the same font.  */
	SendMessageW (ListView_GetHeader (list), WM_SETFONT, (WPARAM) g_sm_list_font, TRUE);
	if (prev_list)
		DeleteObject (prev_list);
}

void
sm_init (HWND dlg)
{
	HWND list = GetDlgItem (dlg, IDC_SMART_LIST);
	RECT wr, cr;
	int rows;

	g_smart = dlg;
	g_sm_dpi = dpi_for_window (dlg);
	SetWindowTextW (dlg, g_sm_caption.c_str ());
	SetDlgItemTextW (dlg, IDC_SMART_REFRESH, res_str (IDS_BTN_REFRESH).c_str ());
	SetDlgItemTextW (dlg, IDC_SMART_HEX, res_str (IDS_SM_HEX).c_str ());
	CheckDlgButton (dlg, IDC_SMART_HEX, g_sm_hex ? BST_CHECKED : BST_UNCHECKED);

	SetWindowTheme (list, L"Explorer", nullptr);
	ListView_SetExtendedListViewStyle (list, LVS_EX_DOUBLEBUFFER);
	SetWindowSubclass (list, sm_list_proc, 0, 0);
	sm_apply_dpi (dlg);
	sm_columns (list);

	sm_measure (dlg);

	/* Grow the template to the measured sheet plus a few attribute
	   rows, then centre what came out on the owner.  */
	rows = g_sm_lay.row_h * SM_LIST_ROWS + sm_scale (28);
	GetWindowRect (dlg, &wr);
	GetClientRect (dlg, &cr);
	center_on_owner (dlg, wr.right - wr.left,
		g_sm_lay.y_list + rows + sm_scale (SM_MARGIN) + (wr.bottom - wr.top) - cr.bottom);

	sm_place (dlg);
	sm_fill (list);
}

INT_PTR CALLBACK
smart_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		sm_init (dlg);
		return TRUE;
	case WM_SIZE:
	{
		RECT rc;

		/* Creating the frame sizes it once before WM_INITDIALOG, when
		   there are no controls and no fonts to lay out yet.  */
		if (!g_smart)
			return TRUE;
		sm_measure (dlg);
		sm_place (dlg);
		/* Only the painted sheet has to follow the width; the list
		   redraws itself and must not flicker along with it.  */
		GetClientRect (dlg, &rc);
		rc.bottom = g_sm_lay.y_list;
		InvalidateRect (dlg, &rc, TRUE);
		return TRUE;
	}
	case WM_DPICHANGED:
		g_sm_dpi = HIWORD (wp);
		dpi_take_suggested (dlg, lp);
		PostMessageW (dlg, WM_APP_DPI_CHANGED, 0, 0);
		return FALSE;	/* the dialog manager still rescales the control fonts */
	case WM_APP_DPI_CHANGED:
		/* The sheet is re-measured against the new fonts and the list
		   re-fitted by sm_place(); the frame is where the dialog
		   manager (or the user) left it.  */
		sm_apply_dpi (dlg);
		sm_measure (dlg);
		sm_place (dlg);
		InvalidateRect (dlg, nullptr, TRUE);
		return TRUE;
	case WM_GETMINMAXINFO:
		((MINMAXINFO *) lp)->ptMinTrackSize = { sm_scale (520), sm_scale (360) };
		return TRUE;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC dc;

		if (!g_smart)
			break;
		dc = BeginPaint (dlg, &ps);
		sm_paint (dlg, dc);
		EndPaint (dlg, &ps);
		return TRUE;
	}
	case WM_NOTIFY:
	{
		NMHDR *hdr = (NMHDR *) lp;

		if (hdr->idFrom == IDC_SMART_LIST && hdr->code == NM_CUSTOMDRAW)
		{
			SetWindowLongPtrW (dlg, DWLP_MSGRESULT, sm_customdraw ((NMLVCUSTOMDRAW *) hdr));
			return TRUE;
		}
		break;
	}
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDC_SMART_REFRESH:
		{
			HCURSOR prev = SetCursor (LoadCursorW (nullptr, IDC_WAIT));

			g_cdi.update (g_cdi_smart, g_sm_disk);
			SetCursor (prev);
			sm_reload (dlg);
			return TRUE;
		}
		case IDC_SMART_HEX:
			g_sm_hex = IsDlgButtonChecked (dlg, IDC_SMART_HEX) == BST_CHECKED;
			sm_build_attrs ();
			sm_fill (GetDlgItem (dlg, IDC_SMART_LIST));
			return TRUE;
		case IDOK:
		case IDCANCEL:
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	case WM_DESTROY:
		if (g_sm_head_font)
			DeleteObject (g_sm_head_font);
		if (g_sm_small_font)
			DeleteObject (g_sm_small_font);
		if (g_sm_list_font)
			DeleteObject (g_sm_list_font);
		g_sm_head_font = nullptr;
		g_sm_small_font = nullptr;
		g_sm_list_font = nullptr;
		g_smart = nullptr;
		break;
	}
	return FALSE;
}

/* Bring libcdi up if it is not already, and find the drive D stands
   for.  The scan is what takes the seconds, so it happens once.  */
bool
sm_open (const backend_diskent &d)
{
	INT drive, count;

	if (!cdi_load ())
		return false;
	if (!g_cdi_smart)
	{
		HCURSOR prev = SetCursor (LoadCursorW (nullptr, IDC_WAIT));

		g_cdi_smart = g_cdi.create ();
		if (g_cdi_smart)
			g_cdi.init (g_cdi_smart, CDI_FLAG_DEFAULT);
		SetCursor (prev);
	}
	if (!g_cdi_smart)
		return false;

	/* "hdN" is \\.\PhysicalDriveN, which is what libcdi reports as the
	   disk id -- its own indexes are in scan order.  */
	drive = (INT) strtoul (d.name.c_str () + 2, nullptr, 10);
	count = g_cdi.count (g_cdi_smart);
	for (INT i = 0; i < count; i++)
		if (g_cdi.get_int (g_cdi_smart, i, CDI_INT_DISK_ID) == drive)
		{
			g_sm_disk = i;
			return true;
		}
	return false;
}

} // namespace

/* Whether the S.M.A.R.T. item can be offered at all.  Loading the DLL
   is the only way to know, so the first windisk right-click pays for
   it and every later one is answered from the cached result.  */
bool
smart_available (void)
{
	return cdi_load ();
}

/* S.M.A.R.T. of the physical drive behind D (tree right-click).  D is a
   windisk "hdN"; the caller has already checked that much.  */
void
show_smart (const backend_diskent &d)
{
	if (!sm_open (d))
	{
		modal_scope hold;

		MessageBoxW (g_main, res_str (IDS_SM_NO_DATA).c_str (),
			res_str (IDS_SM_TITLE).c_str (), MB_ICONWARNING | MB_OK);
		return;
	}

	g_sm_dev = widen (d.name);
	g_sm_size = format_size (d.size);
	g_sm_caption = g_sm_dev + L" - " + res_str (IDS_SM_TITLE);
	sm_build ();
	{
		modal_scope hold;
		DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_SMART),
			g_main, smart_dlg_proc, 0);
	}
	g_smart = nullptr;
	g_sm_left.clear ();
	g_sm_right.clear ();
	g_sm_format.clear ();
	g_sm_attrs.clear ();
}

/* Release the scan before COM goes down with the main window.  */
void
smart_shutdown (void)
{
	if (!g_cdi_smart)
		return;
	g_cdi.destroy (g_cdi_smart);
	g_cdi_smart = nullptr;
}

#endif
