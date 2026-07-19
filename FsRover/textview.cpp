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

/* Text viewer: one read_chunk task loads the first TEXT_MAX bytes on the
 * backend thread (larger files are shown truncated, so no size ever
 * stalls the GUI), the bytes are decoded with the encoding picked in the
 * combo (or detected: BOM, BOM-less UTF-16 NUL pattern, UTF-8 validity,
 * else ANSI) and shown in a read-only RichEdit.  Word wrap toggles via
 * EM_SETTARGETDEVICE, the optional line numbers are painted on a gutter
 * strip left of the control, and font/size/colour come from ChooseFont
 * (CF_EFFECTS) applied with EM_SETCHARFORMAT.  */

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>

#include <algorithm>
#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

HWND g_text;	/* modal text viewer, null when closed */

namespace
{

/* Text viewer state; see the block comment at the top of the file.  */
constexpr UINT TEXT_MAX = 16u << 20;	/* bytes loaded; the rest is cut */
constexpr UINT TEXT_PROBE = 64u << 10;	/* first-stage sniff read */
constexpr UINT64 TEXT_WARN = 4u << 20;	/* ask before opening above this */

/* Encoding combo entries after "Auto"; TEXT_CP_* mark UTF-16.  */
constexpr int TEXT_CP_U16LE = -1;
constexpr int TEXT_CP_U16BE = -2;

struct text_encoding
{
	const wchar_t *name;
	int cp;	/* Windows codepage, or TEXT_CP_* */
};

const text_encoding TEXT_ENCODINGS[] =
{
	{ L"ANSI", CP_ACP },
	{ L"UTF-8", CP_UTF8 },
	{ L"UTF-16 LE", TEXT_CP_U16LE },
	{ L"UTF-16 BE", TEXT_CP_U16BE },
	{ L"GBK", 936 },
	{ L"Big5", 950 },
	{ L"Shift-JIS", 932 },
	{ L"EUC-KR", 949 },
};

constexpr int TEXT_ENC_ANSI = 0;
constexpr int TEXT_ENC_UTF8 = 1;
constexpr int TEXT_ENC_U16LE = 2;
constexpr int TEXT_ENC_U16BE = 3;

std::string g_text_path;	/* file being viewed, UTF-8 */
UINT g_seq_text;	/* in-flight read_chunk task */
std::vector<char> g_text_raw;	/* loaded prefix of the file */
UINT64 g_text_full;	/* real file size (raw may be a prefix) */
bool g_text_loaded;	/* raw/full are valid */
bool g_text_probing;	/* the in-flight read is the sniff stage */
std::vector<UINT> g_text_starts;	/* control char index per line */
HFONT g_text_font;	/* gutter font, matches the RichEdit format */
LOGFONTW g_text_lf;	/* user font; kept across viewer sessions */
bool g_text_lf_init;
int g_text_ptsize = 100;	/* font size, 1/10 pt */
COLORREF g_text_color;
bool g_text_wrap = true;
bool g_text_linenum;
int g_text_gutter;	/* line-number strip width, pixels */

int
text_detect (const std::vector<char> &raw)
{
	const unsigned char *p = (const unsigned char *) raw.data ();
	size_t n = raw.size ();

	if (n >= 3 && p[0] == 0xef && p[1] == 0xbb && p[2] == 0xbf)
		return TEXT_ENC_UTF8;
	if (n >= 2 && p[0] == 0xff && p[1] == 0xfe)
		return TEXT_ENC_U16LE;
	if (n >= 2 && p[0] == 0xfe && p[1] == 0xff)
		return TEXT_ENC_U16BE;

	/* BOM-less UTF-16: mostly-ASCII text shows up as NUL bytes in
	   every other position.  Checked before UTF-8, whose validation
	   would accept those NULs as U+0000.  */
	size_t probe = n < 4096 ? n : 4096;
	size_t zero_even = 0;
	size_t zero_odd = 0;
	for (size_t i = 0; i < probe; i++)
		if (!p[i])
			(i & 1 ? zero_odd : zero_even)++;
	if (probe >= 16)
	{
		if (zero_odd > probe / 8 && zero_odd > 4 * zero_even)
			return TEXT_ENC_U16LE;
		if (zero_even > probe / 8 && zero_even > 4 * zero_odd)
			return TEXT_ENC_U16BE;
	}

	/* Valid UTF-8 (pure ASCII included); a multi-byte sequence cut
	   at the load limit still counts.  */
	size_t i = 0;
	while (i < n)
	{
		unsigned char c = p[i];
		size_t len = c < 0x80 ? 1
			: (c & 0xe0) == 0xc0 ? 2
			: (c & 0xf0) == 0xe0 ? 3
			: (c & 0xf8) == 0xf0 ? 4 : 0;
		if (!len)
			return TEXT_ENC_ANSI;
		if (i + len > n)
			break;
		for (size_t k = 1; k < len; k++)
			if ((p[i + k] & 0xc0) != 0x80)
				return TEXT_ENC_ANSI;
		i += len;
	}
	return TEXT_ENC_UTF8;
}

std::wstring
text_decode (int enc)
{
	const char *p = g_text_raw.data ();
	size_t n = g_text_raw.size ();
	const unsigned char *u = (const unsigned char *) p;
	std::wstring out;

	/* Skip the BOM when it matches the chosen encoding.  */
	if (enc == TEXT_ENC_UTF8 && n >= 3 && u[0] == 0xef && u[1] == 0xbb && u[2] == 0xbf)
	{
		p += 3;
		n -= 3;
	}
	else if (enc == TEXT_ENC_U16LE && n >= 2 && u[0] == 0xff && u[1] == 0xfe)
	{
		p += 2;
		n -= 2;
	}
	else if (enc == TEXT_ENC_U16BE && n >= 2 && u[0] == 0xfe && u[1] == 0xff)
	{
		p += 2;
		n -= 2;
	}

	if (enc == TEXT_ENC_U16LE || enc == TEXT_ENC_U16BE)
	{
		out.resize (n / 2);
		for (size_t i = 0; i < out.size (); i++)
		{
			unsigned char a = (unsigned char) p[i * 2];
			unsigned char b = (unsigned char) p[i * 2 + 1];
			out[i] = enc == TEXT_ENC_U16LE ? (wchar_t) (a | (b << 8)) : (wchar_t) ((a << 8) | b);
		}
		return out;
	}

	if (!n)
		return out;
	UINT cp = (UINT) TEXT_ENCODINGS[enc].cp;
	int len = MultiByteToWideChar (cp, 0, p, (int) n, nullptr, 0);
	if (len <= 0)
		return out;
	out.resize ((size_t) len);
	MultiByteToWideChar (cp, 0, p, (int) n, out.data (), len);
	return out;
}

/* Normalize CRLF/CR/LF to the single '\r' RichEdit stores internally,
   recording each line's character index in the control's coordinate
   space, and blank out NULs (SetWindowText would stop there).  */
std::wstring
text_reflow (const std::wstring &in)
{
	std::wstring out;

	out.reserve (in.size ());
	g_text_starts.clear ();
	g_text_starts.push_back (0);
	for (size_t i = 0; i < in.size (); i++)
	{
		wchar_t c = in[i];
		if (c == L'\r' || c == L'\n')
		{
			if (c == L'\r' && i + 1 < in.size () && in[i + 1] == L'\n')
				i++;
			out += L'\r';
			g_text_starts.push_back ((UINT) out.size ());
			continue;
		}
		out += c ? c : L'\xfffd';
	}
	return out;
}

/* Gutter font at the RichEdit's point size for the current DPI, so the
   painted numbers line up with the control's rendering.  */
void
text_make_font (void)
{
	LOGFONTW lf = g_text_lf;

	lf.lfHeight = -MulDiv (g_text_ptsize, (int) g_dpi, 720);
	lf.lfWidth = 0;
	if (g_text_font)
		DeleteObject (g_text_font);
	g_text_font = CreateFontIndirectW (&lf);
}

void
text_apply_format (HWND dlg)
{
	CHARFORMATW cf = {};

	cf.cbSize = sizeof (cf);
	cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR | CFM_BOLD | CFM_ITALIC | CFM_CHARSET;
	cf.yHeight = g_text_ptsize * 2;	/* 1/10 pt -> twips */
	cf.crTextColor = g_text_color;
	cf.bCharSet = g_text_lf.lfCharSet;
	cf.bPitchAndFamily = g_text_lf.lfPitchAndFamily;
	wcscpy_s (cf.szFaceName, g_text_lf.lfFaceName);
	if (g_text_lf.lfWeight >= FW_BOLD)
		cf.dwEffects |= CFE_BOLD;
	if (g_text_lf.lfItalic)
		cf.dwEffects |= CFE_ITALIC;
	SendDlgItemMessageW (dlg, IDC_TEXT_EDIT, EM_SETCHARFORMAT, SCF_ALL, (LPARAM) &cf);
}

void
text_update_info (HWND dlg, int enc)
{
	wchar_t buf[160];

	swprintf (buf, 160, res_str (IDS_FMT_TEXT_INFO).c_str (), TEXT_ENCODINGS[enc].name, (int) g_text_starts.size ());
	std::wstring text = buf;
	if (g_text_full > g_text_raw.size ())
	{
		swprintf (buf, 160, res_str (IDS_FMT_TEXT_TRUNC).c_str (),
			format_size (g_text_raw.size ()).c_str (),
			format_size (g_text_full).c_str ());
		text += buf;
	}
	SetDlgItemTextW (dlg, IDC_TEXT_INFO, text.c_str ());
}

void
text_update_gutter (HWND dlg)
{
	int digits = 1;
	for (size_t v = g_text_starts.size (); v >= 10; v /= 10)
		digits++;
	if (digits < 3)
		digits = 3;

	HDC dc = GetDC (dlg);
	HFONT old = (HFONT) SelectObject (dc, g_text_font);
	SIZE size = {};
	GetTextExtentPoint32W (dc, L"0", 1, &size);
	SelectObject (dc, old);
	ReleaseDC (dlg, dc);
	g_text_gutter = size.cx * digits + dpi_scale (10);
}

/* With the gutter off the strip is covered by the RichEdit, and the
   dialog (no WS_CLIPCHILDREN) would erase right through it -- each
   erase makes the control repaint, whose EN_UPDATE would invalidate
   again, flickering forever.  Only invalidate when numbers are shown,
   and without erasing: text_paint_gutter() fills the background
   itself, so scrolling does not blink.  */
void
text_invalidate_gutter (HWND dlg)
{
	RECT rc;

	if (!g_text_linenum)
		return;
	GetClientRect (dlg, &rc);
	rc.right = g_text_gutter;
	rc.top = dpi_scale (30);
	InvalidateRect (dlg, &rc, FALSE);
}

void
text_layout (HWND dlg)
{
	RECT rc;

	GetClientRect (dlg, &rc);
	int margin = dpi_scale (6);
	int gap = dpi_scale (4);
	int bar_h = dpi_scale (30);
	int label_w = dpi_scale (70);
	int combo_w = dpi_scale (110);
	int wrap_w = dpi_scale (100);
	int num_w = dpi_scale (110);
	int font_w = dpi_scale (64);
	int x = margin;

	MoveWindow (GetDlgItem (dlg, IDC_TEXT_ENC_LABEL), x, dpi_scale (8), label_w, dpi_scale (18), TRUE);
	x += label_w + gap;
	MoveWindow (GetDlgItem (dlg, IDC_TEXT_ENCODING), x, dpi_scale (4), combo_w, dpi_scale (160), TRUE);
	x += combo_w + gap;
	MoveWindow (GetDlgItem (dlg, IDC_TEXT_WRAP), x, dpi_scale (6), wrap_w, dpi_scale (18), TRUE);
	x += wrap_w + gap;
	MoveWindow (GetDlgItem (dlg, IDC_TEXT_LINENUM), x, dpi_scale (6), num_w, dpi_scale (18), TRUE);
	x += num_w + gap;
	MoveWindow (GetDlgItem (dlg, IDC_TEXT_FONT), x, dpi_scale (4), font_w, dpi_scale (22), TRUE);
	x += font_w + gap;
	int info_w = rc.right - margin - x;
	if (info_w < dpi_scale (40))
		info_w = dpi_scale (40);
	MoveWindow (GetDlgItem (dlg, IDC_TEXT_INFO), x, dpi_scale (8), info_w, dpi_scale (18), TRUE);

	int gutter = g_text_linenum ? g_text_gutter : 0;
	MoveWindow (GetDlgItem (dlg, IDC_TEXT_EDIT), gutter, bar_h, rc.right - gutter, rc.bottom - bar_h, TRUE);
	text_invalidate_gutter (dlg);
}

void
text_paint_gutter (HWND dlg)
{
	PAINTSTRUCT ps;
	HDC dc = BeginPaint (dlg, &ps);

	if (g_text_linenum && g_text_font && !g_text_starts.empty ())
	{
		HWND edit = GetDlgItem (dlg, IDC_TEXT_EDIT);
		RECT erc;
		GetWindowRect (edit, &erc);
		MapWindowPoints (nullptr, dlg, (POINT *) &erc, 2);

		/* Own background fill (the invalidations skip the erase
		   pass); BeginPaint clipped this to the update region.  */
		RECT grc = { 0, erc.top, g_text_gutter, erc.bottom };
		FillRect (dc, &grc, GetSysColorBrush (COLOR_BTNFACE));

		HFONT old = (HFONT) SelectObject (dc, g_text_font);
		UINT align = SetTextAlign (dc, TA_RIGHT | TA_TOP);
		int bkmode = SetBkMode (dc, TRANSPARENT);
		SetTextColor (dc, GetSysColor (COLOR_GRAYTEXT));

		int first = (int) SendMessageW (edit, EM_GETFIRSTVISIBLELINE, 0, 0);
		for (int i = first;; i++)
		{
			LRESULT idx = SendMessageW (edit, EM_LINEINDEX, (WPARAM) i, 0);
			if (idx < 0)
				break;
			/* RichEdit 2.0+: wParam = POINTL out, lParam = character index.  */
			POINTL pos = {};
			SendMessageW (edit, EM_POSFROMCHAR, (WPARAM) &pos, idx);
			POINT pt = { 0, pos.y };
			MapWindowPoints (edit, dlg, &pt, 1);
			if (pt.y >= erc.bottom)
				break;
			auto it = std::upper_bound (g_text_starts.begin (), g_text_starts.end (), (UINT) idx);
			size_t line = (size_t) (it - g_text_starts.begin ());
			if (g_text_starts[line - 1] != (UINT) idx)
				continue;	/* wrapped continuation */
			wchar_t buf[24];
			swprintf (buf, 24, L"%u", (UINT) line);
			ExtTextOutW (dc, g_text_gutter - dpi_scale (6), pt.y, 0, nullptr, buf, (UINT) lstrlenW (buf), nullptr);
		}
		SetBkMode (dc, bkmode);
		SetTextAlign (dc, align);
		SelectObject (dc, old);
	}
	EndPaint (dlg, &ps);
}

LRESULT CALLBACK
text_edit_proc (HWND wnd, UINT msg, WPARAM wp, LPARAM lp,
		UINT_PTR, DWORD_PTR)
{
	LRESULT r = DefSubclassProc (wnd, msg, wp, lp);

	switch (msg)
	{
	case WM_VSCROLL:
	case WM_MOUSEWHEEL:
	case WM_KEYDOWN:
		/* The gutter tracks the visible lines.  */
		text_invalidate_gutter (GetParent (wnd));
		break;
	case WM_NCDESTROY:
		RemoveWindowSubclass (wnd, text_edit_proc, 0);
		break;
	}
	return r;
}

void
text_reload (HWND dlg)
{
	if (!g_text_loaded)
		return;
	/* Reverts on the next WM_SETCURSOR; a many-MiB RichEdit insert
	   can take a moment.  */
	SetCursor (LoadCursorW (nullptr, IDC_WAIT));
	int sel = (int) SendDlgItemMessageW (dlg, IDC_TEXT_ENCODING, CB_GETCURSEL, 0, 0);
	int enc = sel > 0 ? sel - 1 : text_detect (g_text_raw);
	std::wstring body = text_reflow (text_decode (enc));
	SetDlgItemTextW (dlg, IDC_TEXT_EDIT, body.c_str ());
	text_apply_format (dlg);
	text_update_info (dlg, enc);
	text_update_gutter (dlg);
	text_layout (dlg);
}

void
text_choose_font (HWND dlg)
{
	CHOOSEFONTW cf = { sizeof (cf) };
	LOGFONTW lf = g_text_lf;

	lf.lfHeight = -MulDiv (g_text_ptsize, (int) g_dpi, 720);
	cf.hwndOwner = dlg;
	cf.lpLogFont = &lf;
	cf.rgbColors = g_text_color;
	cf.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT | CF_EFFECTS;
	if (!ChooseFontW (&cf))
		return;
	g_text_lf = lf;
	g_text_ptsize = cf.iPointSize;
	g_text_color = cf.rgbColors;
	text_make_font ();
	text_apply_format (dlg);
	text_update_gutter (dlg);
	text_layout (dlg);
}

void
text_init_dialog (HWND dlg)
{
	g_text = dlg;
	g_text_loaded = false;

	size_t cut = g_text_path.find_last_of ('/');
	std::wstring name = widen (cut == std::string::npos ? g_text_path : g_text_path.substr (cut + 1));
	SetWindowTextW (dlg, (name + L" - " + res_str (IDS_TEXT_TITLE)).c_str ());

	SetDlgItemTextW (dlg, IDC_TEXT_ENC_LABEL, res_str (IDS_TEXT_ENCODING).c_str ());
	SetDlgItemTextW (dlg, IDC_TEXT_WRAP, res_str (IDS_TEXT_WRAP).c_str ());
	SetDlgItemTextW (dlg, IDC_TEXT_LINENUM, res_str (IDS_TEXT_LINENUM).c_str ());
	SetDlgItemTextW (dlg, IDC_TEXT_FONT, res_str (IDS_TEXT_FONT).c_str ());
	SetDlgItemTextW (dlg, IDC_TEXT_INFO, res_str (IDS_TEXT_LOADING).c_str ());
	CheckDlgButton (dlg, IDC_TEXT_WRAP, g_text_wrap ? BST_CHECKED : BST_UNCHECKED);
	CheckDlgButton (dlg, IDC_TEXT_LINENUM, g_text_linenum ? BST_CHECKED : BST_UNCHECKED);

	HWND combo = GetDlgItem (dlg, IDC_TEXT_ENCODING);
	SendMessageW (combo, CB_ADDSTRING, 0, (LPARAM) res_str (IDS_TEXT_AUTO).c_str ());
	for (const text_encoding &e : TEXT_ENCODINGS)
		SendMessageW (combo, CB_ADDSTRING, 0, (LPARAM) e.name);
	SendMessageW (combo, CB_SETCURSEL, 0, 0);

	if (!g_text_lf_init)
	{
		g_text_lf_init = true;
		g_text_lf.lfCharSet = DEFAULT_CHARSET;
		g_text_lf.lfQuality = CLEARTYPE_QUALITY;
		g_text_lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
		wcscpy_s (g_text_lf.lfFaceName, L"Consolas");
		g_text_color = GetSysColor (COLOR_WINDOWTEXT);
	}
	text_make_font ();
	text_update_gutter (dlg);

	HWND edit = GetDlgItem (dlg, IDC_TEXT_EDIT);
	SendMessageW (edit, EM_EXLIMITTEXT, 0, 0x7ffffffe);
	SendMessageW (edit, EM_SETEVENTMASK, 0, ENM_UPDATE);
	SendMessageW (edit, EM_SETTARGETDEVICE, 0, g_text_wrap ? 0 : 1);
	SendMessageW (edit, EM_SETMARGINS, EC_LEFTMARGIN, (LPARAM) dpi_scale (4));
	SetWindowSubclass (edit, text_edit_proc, 0, 0);
	text_apply_format (dlg);

	/* Default frame centered on the work area (the template size is just a fallback).  */
	RECT wa;
	SystemParametersInfoW (SPI_GETWORKAREA, 0, &wa, 0);
	int width = dpi_scale (760);
	int height = dpi_scale (540);
	if (width > wa.right - wa.left)
		width = wa.right - wa.left;
	if (height > wa.bottom - wa.top)
		height = wa.bottom - wa.top;
	SetWindowPos (dlg, nullptr,
		wa.left + ((wa.right - wa.left) - width) / 2,
		wa.top + ((wa.bottom - wa.top) - height) / 2,
		width, height, SWP_NOZORDER);

	backend_task task;
	task.type = backend_task_type::read_chunk;
	task.path = g_text_path;
	task.offset = 0;
	task.length = TEXT_PROBE;
	g_text_probing = true;
	g_seq_text = backend_post (std::move (task));
}

INT_PTR CALLBACK
text_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		text_init_dialog (dlg);
		text_layout (dlg);
		SetFocus (GetDlgItem (dlg, IDC_TEXT_EDIT));
		return FALSE;	/* focus was set explicitly */
	case WM_SIZE:
		text_layout (dlg);
		return TRUE;
	case WM_GETMINMAXINFO:
		((MINMAXINFO *) lp)->ptMinTrackSize =
			{ dpi_scale (560), dpi_scale (240) };
		return TRUE;
	case WM_PAINT:
		text_paint_gutter (dlg);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDC_TEXT_ENCODING:
			if (HIWORD (wp) == CBN_SELCHANGE)
				text_reload (dlg);
			return TRUE;
		case IDC_TEXT_WRAP:
			g_text_wrap = IsDlgButtonChecked (dlg, IDC_TEXT_WRAP) == BST_CHECKED;
			SendDlgItemMessageW (dlg, IDC_TEXT_EDIT, EM_SETTARGETDEVICE, 0, g_text_wrap ? 0 : 1);
			text_invalidate_gutter (dlg);
			return TRUE;
		case IDC_TEXT_LINENUM:
			g_text_linenum = IsDlgButtonChecked (dlg, IDC_TEXT_LINENUM) == BST_CHECKED;
			text_layout (dlg);
			return TRUE;
		case IDC_TEXT_FONT:
			text_choose_font (dlg);
			return TRUE;
		case IDC_TEXT_EDIT:
			/* Any view change repaints the gutter.  */
			if (HIWORD (wp) == EN_UPDATE)
				text_invalidate_gutter (dlg);
			return TRUE;
		case IDCANCEL:
			/* A late read result is dropped once g_text is null.  */
			g_text = nullptr;
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

} // namespace

void
text_on_chunk (backend_result *res)
{
	if (!g_text || res->seq != g_seq_text)
		return;
	if (!res->error.empty ())
	{
		HWND dlg = g_text;
		g_text = nullptr;
		MessageBoxW (dlg, widen (res->error).c_str (), res_str (IDS_TEXT_TITLE).c_str (), MB_ICONERROR);
		EndDialog (dlg, 0);
		return;
	}

	/* Stage one: the sniff read supplies the size and enough bytes
	   to ask about binary/large files before the expensive load.  */
	if (g_text_probing)
	{
		g_text_probing = false;

		int enc = text_detect (res->data);
		bool binary = enc != TEXT_ENC_U16LE && enc != TEXT_ENC_U16BE
			&& !res->data.empty ()
			&& memchr (res->data.data (), 0, res->data.size ());
		std::wstring ask;
		if (binary)
			ask = res_str (IDS_ASK_TEXT_BIN);
		else if (res->file_size > TEXT_WARN)
		{
			wchar_t buf[256];
			swprintf (buf, 256, res_str (IDS_ASK_TEXT_BIG).c_str (), format_size (res->file_size).c_str ());
			ask = buf;
		}
		if (!ask.empty ()
			&& MessageBoxW (g_text, ask.c_str (), res_str (IDS_TEXT_TITLE).c_str (),
				MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES)
		{
			HWND dlg = g_text;
			g_text = nullptr;
			EndDialog (dlg, 0);
			return;
		}
		if (res->file_size > res->data.size ())
		{
			backend_task task;
			task.type = backend_task_type::read_chunk;
			task.path = g_text_path;
			task.offset = 0;
			task.length = TEXT_MAX;
			g_seq_text = backend_post (std::move (task));
			return;
		}
		/* The probe already covered the whole file.  */
	}

	g_text_raw = std::move (res->data);
	g_text_full = res->file_size;
	g_text_loaded = true;
	text_reload (g_text);
}

void
show_text (const std::string &path)
{
	/* RICHEDIT50W lives in Msftedit.dll; load once, keep loaded.  */
	static HMODULE msftedit;
	if (!msftedit)
	{
		msftedit = LoadLibraryW (L"Msftedit.dll");
		if (!msftedit)
			return;
	}
	g_text_path = path;
	DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_TEXT), g_main, text_dlg_proc, 0);
	g_text = nullptr;
	g_text_loaded = false;
	std::vector<char> ().swap (g_text_raw);
	std::vector<UINT> ().swap (g_text_starts);
	if (g_text_font)
	{
		DeleteObject (g_text_font);
		g_text_font = nullptr;
	}
}
