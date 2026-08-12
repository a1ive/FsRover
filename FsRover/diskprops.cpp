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

#include <algorithm>
#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

namespace
{

HWND g_diskprops;	/* disk properties dialog, null when closed */
UINT g_dp_dpi = 96;	/* this window's DPI, refreshed on WM_DPICHANGED */

int
dp_scale (int value)
{
	return dpi_scale (g_dp_dpi, value);
}

/* Layout metrics authored at 96 DPI; scaled through dp_scale().  */
constexpr int DP_MARGIN = 12;
constexpr int DP_GAP = 8;	/* icon to text, button to button */
constexpr int DP_ICON = 32;
constexpr int DP_BTN_W = 76;
constexpr int DP_BTN_H = 23;
constexpr int DP_BAR_H = 52;	/* the map itself, without its header row */
constexpr int DP_STRIPE_H = 5;	/* coloured band on top of a box */
constexpr int DP_PAD = 5;	/* text inset inside a box */
constexpr int DP_BOX_MIN = 16;	/* no box is ever drawn thinner */
constexpr int DP_BOX_TEXT = 30;	/* under this width a box stays blank */
constexpr int DP_BOX_TWOLINE = 60;	/* under this only the size fits */

/* A hole gets a box of its own only once it is this big, absolutely and
   relative to the device: the 1 MiB in front of the first partition and
   the alignment padding between them is not free space, and something
   negligible would still take up a labelled box.  */
constexpr UINT64 DP_HOLE_MIN = 8ull << 20;
constexpr UINT64 DP_HOLE_FRAC = 1000;

struct dp_field
{
	std::wstring label;	/* empty = continuation of the row above */
	std::wstring value;
};

/* One box of the map: a partition of the mapped device, or a hole
   between two of them.  */
struct dp_box
{
	std::wstring name;	/* partition, or the free-space label */
	std::wstring info;	/* size and filesystem */
	std::wstring brief;	/* size alone, all a narrow box has room for */
	UINT64 size = 0;
	bool self = false;	/* the device the dialog is about */
	bool free = false;
	int x = 0;	/* set by dp_place_boxes */
	int w = 0;
};

/* Snapshot of the device, formatted before the modal loop starts.  */
std::wstring g_dp_caption;	/* window title */
std::wstring g_dp_spec;	/* "(hd0,msdos1)", the header line */
int g_dp_icon;	/* imageres.dll icon id for the header */
std::vector<dp_field> g_dp_fields;
std::vector<dp_box> g_dp_boxes;	/* empty = this device gets no map */
std::wstring g_dp_map_name;	/* spec of the device the map covers */
UINT64 g_dp_map_size;	/* bytes the map spans */
std::wstring g_dp_text;	/* what the Copy button hands out */

/* Owned by the dialog, released in WM_DESTROY.  */
HICON g_dp_hicon;
HFONT g_dp_head_font;	/* device spec: a step up and semibold */
HFONT g_dp_small_font;	/* map labels */

/* Painted layout, measured once from the snapshot.  */
struct dp_layout
{
	int y_spec;	/* the header line, centred against the icon */
	int y_rule1;	/* rule under the header */
	int y_fields;	/* first field row */
	int row_h;	/* one field row */
	int label_w;	/* widest field label */
	int y_rule2;	/* rule above the map */
	int y_map;	/* map header row */
	int small_h;	/* line height of g_dp_small_font */
	int y_btn;
	int height;	/* client height the dialog is resized to */
};

dp_layout g_dp_lay;

/* PCT percent of A over B, for tinting a system colour without
   assuming a light or a dark theme.  */
COLORREF
mix (COLORREF a, COLORREF b, int pct)
{
	int r = (GetRValue (a) * pct + GetRValue (b) * (100 - pct)) / 100;
	int g = (GetGValue (a) * pct + GetGValue (b) * (100 - pct)) / 100;
	int bl = (GetBValue (a) * pct + GetBValue (b) * (100 - pct)) / 100;

	return RGB (r, g, bl);
}

std::wstring
group_digits (UINT64 v)
{
	std::wstring s = std::to_wstring (v);

	for (int i = (int) s.size () - 3; i > 0; i -= 3)
		s.insert ((size_t) i, L",");
	return s;
}

/* What kind of device this is, for the Type row.  A locked container is
   usually a partition and stays one here -- that it is encrypted shows up
   in the padlock icon and on the filesystem row.  */
UINT
dp_type_label (const backend_diskent &d)
{
	if (d.is_partition)
		return IDS_DP_T_PART;
	if (d.encrypted || d.dev_id == BACKEND_DEV_CRYPTODISK)
		return IDS_DP_T_CRYPTO;
	switch (d.dev_id)
	{
	case BACKEND_DEV_LOOPBACK:
	case BACKEND_DEV_WINFILE:
		return IDS_DP_T_IMAGE;
	case BACKEND_DEV_DISKFILTER:
		return IDS_DP_T_VOLUME;
	case BACKEND_DEV_PROCFS:
		return IDS_DP_T_PSEUDO;
	}
	return IDS_DP_T_DISK;
}

/* Filesystem name, the container type when the volume is locked, or the
   placeholder when nothing recognised it.  */
std::wstring
dp_fs_name (const backend_diskent &d)
{
	if (!d.fs.empty ())
		return widen (d.fs);
	if (d.encrypted)
		return widen (d.crypto_type);
	return res_str (IDS_DP_UNKNOWN);
}

void
dp_field_add (UINT label, const std::wstring &value)
{
	dp_field f;

	f.label = res_str (label) + res_str (IDS_DP_COLON);
	f.value = value;
	g_dp_fields.push_back (std::move (f));
}

void
dp_field_cont (const std::wstring &value)
{
	dp_field f;

	f.value = value;
	g_dp_fields.push_back (std::move (f));
}

/* Byte offset of D on its disk; 0 for anything that is not a partition.
   start_lba counts the disk's own sectors and is absolute, so nested
   partitions are measured from the same origin as their parent.  */
UINT64
dp_offset (const backend_diskent &d)
{
	return d.is_partition ? d.start_lba * d.sector_size : 0;
}

/* Is NAME a direct partition of PARENT?  "hd0,gpt2" is, and shows up on
   the map of "hd0"; "hd0,gpt2,bsd1" is not, it belongs to "hd0,gpt2".  */
bool
dp_is_child (const std::string &name, const std::string &parent)
{
	if (name.size () <= parent.size () + 1
		|| name.compare (0, parent.size (), parent) != 0
		|| name[parent.size ()] != ',')
		return false;
	return name.find (',', parent.size () + 1) == std::string::npos;
}

dp_box
dp_make_box (const backend_diskent &d, UINT64 size, bool self)
{
	size_t comma = d.name.find_last_of (',');
	dp_box b;

	/* Just the partition component: "gpt2", not "hd0,gpt2", so the
	   label has a chance of fitting into a narrow box.  */
	b.name = widen (comma == std::string::npos ? d.name : d.name.substr (comma + 1));
	if (!d.label.empty ())
		b.name += L" (" + widen (d.label) + L")";
	b.brief = format_size (size);
	b.info = b.brief;
	if (!d.fs.empty () || d.encrypted)
		b.info += L" " + dp_fs_name (d);
	b.size = size;
	b.self = self;
	return b;
}

bool
dp_hole_shown (UINT64 hole, UINT64 total)
{
	return hole >= DP_HOLE_MIN && hole >= total / DP_HOLE_FRAC;
}

dp_box
dp_make_hole (UINT64 size)
{
	dp_box b;

	b.name = res_str (IDS_DP_FREE);
	b.brief = format_size (size);
	b.info = b.brief;
	b.size = size;
	b.free = true;
	return b;
}

/* One box per direct partition of MAPPED plus one per hole between them,
   in disk order, with SELF (which may be a partition of MAPPED) marked.
   Stays empty -- no map is drawn -- when the mapped size is unknown, or
   when nothing partitions the device: one box spanning a whole volume
   would say nothing the fields above it do not.  */
void
dp_build_map (const backend_diskent &mapped, const std::string &self, const std::vector<backend_diskent> &disks)
{
	std::vector<const backend_diskent *> parts;
	UINT64 total = mapped.size;
	UINT64 base = dp_offset (mapped);
	UINT64 pos = 0;

	if (total == BACKEND_SIZE_UNKNOWN || !total)
		return;

	for (const backend_diskent &e : disks)
		if (dp_is_child (e.name, mapped.name)
			&& e.size != BACKEND_SIZE_UNKNOWN && e.sector_size
			&& dp_offset (e) >= base && dp_offset (e) - base < total)
			parts.push_back (&e);
	if (parts.empty ())
		return;
	std::sort (parts.begin (), parts.end (),
		[] (const backend_diskent *a, const backend_diskent *b)
		{
			return a->start_lba < b->start_lba;
		});

	g_dp_map_name = L"(" + widen (mapped.name) + L")";
	g_dp_map_size = total;

	/* Boxes are laid out side by side in table order, so a skipped hole
	   only widens its neighbours a little -- no absolute positions to
	   keep in step.  */
	for (const backend_diskent *p : parts)
	{
		UINT64 off = dp_offset (*p) - base;
		UINT64 len = p->size;

		if (off < pos)	/* overlaps the box before it */
			continue;
		if (len > total - off)
			len = total - off;
		if (dp_hole_shown (off - pos, total))
			g_dp_boxes.push_back (dp_make_hole (off - pos));
		g_dp_boxes.push_back (dp_make_box (*p, len, p->name == self));
		pos = off + len;
	}
	if (dp_hole_shown (total - pos, total))
		g_dp_boxes.push_back (dp_make_hole (total - pos));
}

/* The Copy button hands out the same rows as plain text, with the device
   spec the header shows in front of them.  */
void
dp_build_text (void)
{
	g_dp_text = res_str (IDS_DP_DEVICE) + res_str (IDS_DP_COLON) + L" " + g_dp_spec + L"\r\n";
	for (const dp_field &f : g_dp_fields)
	{
		if (f.label.empty ())
			g_dp_text += L"    " + f.value + L"\r\n";
		else
			g_dp_text += f.label + L" " + f.value + L"\r\n";
	}
}

void
dp_build (const backend_diskent &d, const std::vector<backend_diskent> &disks)
{
	g_dp_caption = widen (d.name) + L" - " + res_str (IDS_MENU_PROPS);
	g_dp_spec = L"(" + widen (d.name) + L")";
	g_dp_icon = device_icon_id (d);

	dp_field_add (IDS_DP_TYPE, res_str (dp_type_label (d)));
	if (d.size != BACKEND_SIZE_UNKNOWN)
		dp_field_add (IDS_DP_SIZE,
			format_size (d.size) + L" (" + group_digits (d.size) + L" B)");
	dp_field_add (IDS_DP_FS, dp_fs_name (d));
	if (!d.label.empty ())
		dp_field_add (IDS_DP_LABEL, widen (d.label));

	/* UUID: the filesystem's, or the container's while it is locked.  */
	if (!d.fs_uuid.empty ())
		dp_field_add (IDS_DP_UUID, widen (d.fs_uuid));
	else if (d.encrypted && !d.crypto_uuid.empty ())
		dp_field_add (IDS_DP_UUID, widen (d.crypto_uuid));

	/* Start LBA is only meaningful for an actual partition.  */
	if (d.is_partition)
		dp_field_add (IDS_DP_LBA, group_digits (d.start_lba));
	if (d.sector_size)
		dp_field_add (IDS_DP_SECTOR, std::to_wstring (d.sector_size) + L" B");
	if (!d.parent_file.empty ())
		dp_field_add (IDS_DP_PARENT_FILE, widen (d.parent_file));
	if (!d.parent_device.empty ())
		dp_field_add (IDS_DP_PARENT_DEV, widen (d.parent_device));

	/* Diskfilter members arrive one grub device name per line; the first
	   takes the label, the rest are continuation rows.  */
	for (size_t pos = 0; pos < d.parents.size (); )
	{
		size_t nl = d.parents.find ('\n', pos);

		if (nl == std::string::npos)
			nl = d.parents.size ();
		if (pos)
			dp_field_cont (widen (d.parents.substr (pos, nl - pos)));
		else
			dp_field_add (IDS_DP_PARENTS, widen (d.parents.substr (pos, nl - pos)));
		pos = nl + 1;
	}

	/* A partition is drawn on its disk's map, a disk on its own.  */
	if (!d.is_partition)
		dp_build_map (d, d.name, disks);
	else
	{
		size_t comma = d.name.find_last_of (',');
		if (comma != std::string::npos)
			for (const backend_diskent &e : disks)
				if (e.name == d.name.substr (0, comma))
				{
					dp_build_map (e, d.name, disks);
					break;
				}
	}

	dp_build_text ();
}

/* Widths for the map.  A partition table is nothing like proportional --
   a 100 MB ESP next to a 1 TB volume would be a hairline -- so every box
   starts from a share large enough to label and only what is left over is
   handed out by size, the way Disk Management draws it.  */
void
dp_place_boxes (int width)
{
	int n = (int) g_dp_boxes.size ();
	int min_w = width / 10;	/* enough for a size on one line */
	UINT64 total = 0;
	int extra;
	int x = 0;

	for (const dp_box &b : g_dp_boxes)
		total += b.size;
	if (min_w < dp_scale (DP_BOX_MIN))
		min_w = dp_scale (DP_BOX_MIN);
	if (n * min_w > width * 3 / 4)
		min_w = width * 3 / 4 / n;
	extra = width - n * min_w;

	for (dp_box &b : g_dp_boxes)
	{
		b.x = x;
		b.w = min_w + (total ? (int) ((UINT64) extra * b.size / total) : extra / n);
		x += b.w;
	}
	/* Rounding leftovers go to the last box so the map ends flush.  */
	g_dp_boxes.back ().w += width - x;
}

void
dp_measure (HWND dlg)
{
	HDC dc = GetDC (dlg);
	HFONT body = (HFONT) SendMessageW (dlg, WM_GETFONT, 0, 0);
	HFONT old = (HFONT) SelectObject (dc, g_dp_head_font);
	TEXTMETRICW tm;
	RECT rc;
	int m = dp_scale (DP_MARGIN);
	int icon = dp_scale (DP_ICON);
	int y;

	GetClientRect (dlg, &rc);

	/* Header: one line of text centred against the icon.  */
	GetTextMetricsW (dc, &tm);
	g_dp_lay.y_spec = m + (icon > tm.tmHeight ? (icon - tm.tmHeight) / 2 : 0);
	y = m + (icon > tm.tmHeight ? icon : tm.tmHeight);

	/* Field rows: a label column as wide as the widest label.  */
	SelectObject (dc, body);
	GetTextMetricsW (dc, &tm);
	g_dp_lay.row_h = tm.tmHeight + dp_scale (6);
	g_dp_lay.label_w = 0;
	for (const dp_field &f : g_dp_fields)
	{
		SIZE sz = {};

		GetTextExtentPoint32W (dc, f.label.c_str (), (int) f.label.size (), &sz);
		if (sz.cx > g_dp_lay.label_w)
			g_dp_lay.label_w = sz.cx;
	}
	g_dp_lay.y_rule1 = y + m;
	g_dp_lay.y_fields = g_dp_lay.y_rule1 + m;
	y = g_dp_lay.y_fields + (int) g_dp_fields.size () * g_dp_lay.row_h;

	SelectObject (dc, g_dp_small_font);
	GetTextMetricsW (dc, &tm);
	g_dp_lay.small_h = tm.tmHeight;
	g_dp_lay.y_rule2 = 0;
	g_dp_lay.y_map = 0;
	if (!g_dp_boxes.empty ())
	{
		g_dp_lay.y_rule2 = y + m - dp_scale (2);
		g_dp_lay.y_map = g_dp_lay.y_rule2 + m;
		y = g_dp_lay.y_map + g_dp_lay.small_h + dp_scale (4) + dp_scale (DP_BAR_H);
		dp_place_boxes (rc.right - 2 * m);
	}

	g_dp_lay.y_btn = y + m;
	g_dp_lay.height = g_dp_lay.y_btn + dp_scale (DP_BTN_H) + m;

	SelectObject (dc, old);
	ReleaseDC (dlg, dc);
}

/* Grow the template to the measured content and put the buttons back in
   its bottom-right corner.  CENTRE puts the result on the owner, which
   is what the template's DS_CENTER did for its placeholder size; a
   dialog that is only being re-measured for a new DPI stays where the
   user dragged it.  */
void
dp_resize (HWND dlg, bool centre)
{
	RECT wr, cr;
	int m = dp_scale (DP_MARGIN);
	int bw = dp_scale (DP_BTN_W);
	int bh = dp_scale (DP_BTN_H);

	GetWindowRect (dlg, &wr);
	GetClientRect (dlg, &cr);
	int w = wr.right - wr.left;	/* the template's width is kept */
	int h = g_dp_lay.height + (wr.bottom - wr.top) - cr.bottom;

	if (centre)
		center_on_owner (dlg, w, h);
	else
		SetWindowPos (dlg, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);

	GetClientRect (dlg, &cr);
	MoveWindow (GetDlgItem (dlg, IDOK), cr.right - m - bw, g_dp_lay.y_btn, bw, bh, TRUE);
	MoveWindow (GetDlgItem (dlg, IDC_DISKPROPS_COPY), cr.right - m - 2 * bw - dp_scale (DP_GAP), g_dp_lay.y_btn, bw, bh, TRUE);
}

void
dp_rule (HDC dc, int x1, int x2, int y)
{
	RECT r = { x1, y, x2, y + 1 };
	HBRUSH brush = CreateSolidBrush (mix (GetSysColor (COLOR_BTNSHADOW), GetSysColor (COLOR_BTNFACE), 45));

	FillRect (dc, &r, brush);
	DeleteObject (brush);
}

/* One box of the map: a tinted body under a coloured band, the device
   the dialog is about in the full accent colour.  */
void
dp_draw_box (HDC dc, const dp_box &b, int x, int y, int h)
{
	COLORREF face = GetSysColor (COLOR_WINDOW);
	COLORREF accent = b.free ? GetSysColor (COLOR_BTNSHADOW) : GetSysColor (COLOR_HIGHLIGHT);
	RECT box = { x, y, x + b.w, y + h };
	RECT stripe = { x, y, x + b.w, y + dp_scale (DP_STRIPE_H) };
	int pad = dp_scale (DP_PAD);
	HBRUSH brush;

	brush = CreateSolidBrush (mix (accent, face, b.self ? 22 : 8));
	FillRect (dc, &box, brush);
	DeleteObject (brush);
	brush = CreateSolidBrush (b.self ? accent : mix (accent, face, 55));
	FillRect (dc, &stripe, brush);
	DeleteObject (brush);
	brush = CreateSolidBrush (mix (accent, face, b.self ? 70 : 35));
	FrameRect (dc, &box, brush);
	if (b.self)
	{
		/* Two pixels of frame, so which box the sheet is about reads
		   even where the accent colour is faint.  */
		InflateRect (&box, -1, -1);
		FrameRect (dc, &box, brush);
	}
	DeleteObject (brush);

	if (b.w - 2 * pad < dp_scale (DP_BOX_TEXT))
		return;

	RECT tr = { x + pad, y + dp_scale (DP_STRIPE_H) + pad, x + b.w - pad, y + h - pad };
	UINT fmt = DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX;

	SelectObject (dc, g_dp_small_font);
	if (b.w < dp_scale (DP_BOX_TWOLINE))
	{
		/* Only room for the number, like Disk Management's slivers.  */
		SetTextColor (dc, GetSysColor (COLOR_WINDOWTEXT));
		DrawTextW (dc, b.brief.c_str (), -1, &tr, fmt);
		return;
	}
	SetTextColor (dc, GetSysColor (COLOR_WINDOWTEXT));
	DrawTextW (dc, b.name.c_str (), -1, &tr, fmt);
	tr.top += g_dp_lay.small_h + dp_scale (2);
	SetTextColor (dc, GetSysColor (COLOR_GRAYTEXT));
	DrawTextW (dc, b.info.c_str (), -1, &tr, fmt);
}

void
dp_paint (HWND dlg, HDC dc)
{
	HFONT body = (HFONT) SendMessageW (dlg, WM_GETFONT, 0, 0);
	HFONT old = (HFONT) SelectObject (dc, g_dp_head_font);
	UINT fmt = DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX;
	int m = dp_scale (DP_MARGIN);
	int icon = dp_scale (DP_ICON);
	RECT rc, tr;

	GetClientRect (dlg, &rc);
	SetBkMode (dc, TRANSPARENT);

	if (g_dp_hicon)
		DrawIconEx (dc, m, m, g_dp_hicon, icon, icon, 0, nullptr, DI_NORMAL);
	tr = { m + icon + dp_scale (DP_GAP), g_dp_lay.y_spec, rc.right - m, g_dp_lay.height };
	SetTextColor (dc, GetSysColor (COLOR_WINDOWTEXT));
	DrawTextW (dc, g_dp_spec.c_str (), -1, &tr, fmt);
	dp_rule (dc, m, rc.right - m, g_dp_lay.y_rule1);

	SelectObject (dc, body);
	int y = g_dp_lay.y_fields;
	for (const dp_field &f : g_dp_fields)
	{
		tr = { m, y, m + g_dp_lay.label_w, y + g_dp_lay.row_h };
		SetTextColor (dc, GetSysColor (COLOR_GRAYTEXT));
		DrawTextW (dc, f.label.c_str (), -1, &tr, fmt);
		tr = { m + g_dp_lay.label_w + dp_scale (DP_GAP), y, rc.right - m, y + g_dp_lay.row_h };
		SetTextColor (dc, GetSysColor (COLOR_WINDOWTEXT));
		DrawTextW (dc, f.value.c_str (), -1, &tr, fmt);
		y += g_dp_lay.row_h;
	}

	if (!g_dp_boxes.empty ())
	{
		int bar_y = g_dp_lay.y_map + g_dp_lay.small_h + dp_scale (4);
		int bar_h = dp_scale (DP_BAR_H);

		dp_rule (dc, m, rc.right - m, g_dp_lay.y_rule2);

		/* Which device the map covers, and how big it is.  */
		SelectObject (dc, g_dp_small_font);
		SetTextColor (dc, GetSysColor (COLOR_GRAYTEXT));
		tr = { m, g_dp_lay.y_map, rc.right - m, bar_y };
		DrawTextW (dc, g_dp_map_name.c_str (), -1, &tr, fmt);
		DrawTextW (dc, format_size (g_dp_map_size).c_str (), -1, &tr, fmt | DT_RIGHT);

		for (const dp_box &b : g_dp_boxes)
			dp_draw_box (dc, b, m + b.x, bar_y, bar_h);
	}

	SelectObject (dc, old);
}

/* The GDI objects that depend on the dialog's DPI.  The two fonts are
   derived from the dialog font, which the dialog manager has already
   sized for this monitor (lfHeight is negative, so a bigger factor is a
   bigger font); the icon is asked for in pixels outright.  On a DPI
   change this runs again, after the manager has resized that font.  */
void
dp_apply_dpi (HWND dlg)
{
	HFONT body = (HFONT) SendMessageW (dlg, WM_GETFONT, 0, 0);
	LOGFONTW lf = {};
	LONG height;

	GetObjectW (body, (int) sizeof (lf), &lf);
	height = lf.lfHeight;
	lf.lfHeight = height * 6 / 5;
	lf.lfWeight = FW_SEMIBOLD;
	if (g_dp_head_font)
		DeleteObject (g_dp_head_font);
	g_dp_head_font = CreateFontIndirectW (&lf);
	lf.lfHeight = height * 6 / 7;
	lf.lfWeight = FW_NORMAL;
	if (g_dp_small_font)
		DeleteObject (g_dp_small_font);
	g_dp_small_font = CreateFontIndirectW (&lf);
	if (g_dp_hicon)
		DestroyIcon (g_dp_hicon);
	g_dp_hicon = load_system_icon (L"\\imageres.dll", g_dp_icon, dp_scale (DP_ICON));
}

void
dp_init (HWND dlg)
{
	g_diskprops = dlg;
	g_dp_dpi = dpi_for_window (dlg);
	SetWindowTextW (dlg, g_dp_caption.c_str ());
	SetDlgItemTextW (dlg, IDC_DISKPROPS_COPY, res_str (IDS_DP_COPY).c_str ());

	dp_apply_dpi (dlg);
	dp_measure (dlg);
	dp_resize (dlg, true);
}

INT_PTR CALLBACK
disk_props_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		dp_init (dlg);
		/* Focus the default button; nothing else here takes input.  */
		SetFocus (GetDlgItem (dlg, IDOK));
		return FALSE;	/* focus was set explicitly */
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC dc = BeginPaint (dlg, &ps);

		dp_paint (dlg, dc);
		EndPaint (dlg, &ps);
		return TRUE;
	}
	case WM_DPICHANGED:
		/* The suggested frame carries the width the sheet is measured
		   against; dp_resize() puts the height back afterwards.  */
		g_dp_dpi = HIWORD (wp);
		dpi_take_suggested (dlg, lp);
		PostMessageW (dlg, WM_APP_DPI_CHANGED, 0, 0);
		return FALSE;	/* the dialog manager still rescales the control fonts */
	case WM_APP_DPI_CHANGED:
		dp_apply_dpi (dlg);
		dp_measure (dlg);
		dp_resize (dlg, false);
		InvalidateRect (dlg, nullptr, TRUE);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDC_DISKPROPS_COPY:
			clipboard_set_text (dlg, g_dp_text);
			return TRUE;
		case IDOK:
		case IDCANCEL:
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	case WM_DESTROY:
		if (g_dp_hicon)
			DestroyIcon (g_dp_hicon);
		if (g_dp_head_font)
			DeleteObject (g_dp_head_font);
		if (g_dp_small_font)
			DeleteObject (g_dp_small_font);
		g_dp_hicon = nullptr;
		g_dp_head_font = nullptr;
		g_dp_small_font = nullptr;
		g_diskprops = nullptr;
		break;
	}
	return FALSE;
}

} // namespace

/* Disk / partition properties (tree right-click).  Both the device and
   the disk list are snapshots: a refresh arriving during the modal loop
   reallocates g_disks, so everything the dialog paints is formatted here,
   before the modal loop starts.  */
void
show_disk_props (const backend_diskent &d, const std::vector<backend_diskent> &disks)
{
	g_dp_fields.clear ();
	g_dp_boxes.clear ();
	g_dp_map_name.clear ();
	g_dp_map_size = 0;
	dp_build (d, disks);
	{
		modal_scope hold;
		DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_DISKPROPS), g_main, disk_props_dlg_proc, 0);
	}
	g_diskprops = nullptr;
}
