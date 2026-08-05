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
#include <shellapi.h>

#include <string>
#include <vector>

#include "gui.h"
#include "mdrtf.h"
#include "resource.h"
#include "strconv.h"

namespace
{

HWND g_md;	/* markdown viewer, null when closed */

constexpr UINT MD_MAX = 4u << 20;	/* bytes rendered; the rest is cut */
constexpr UINT MD_PROBE = 64u << 10;	/* first-stage sniff read */
constexpr UINT64 MD_WARN = 1u << 20;	/* ask before rendering above this */

md_document g_md_doc;	/* what the window shows */
std::string g_md_path;	/* backend path, empty for an in-memory document */
UINT g_seq_md;	/* in-flight read_chunk task */
bool g_md_probing;	/* the in-flight read is the sniff stage */
std::vector<md_rtf_link> g_md_links;	/* clickable ranges, document order */
std::vector<md_rtf_anchor> g_md_anchors;	/* heading slug -> position */

/* Feeds the converted RTF to EM_STREAMIN.  */
struct md_stream
{
	const std::string *rtf;
	size_t at;
};

DWORD CALLBACK
md_stream_read (DWORD_PTR cookie, LPBYTE buf, LONG cb, LONG *done)
{
	md_stream *s = (md_stream *) cookie;
	size_t left = s->rtf->size () - s->at;
	size_t take = (size_t) cb < left ? (size_t) cb : left;

	memcpy (buf, s->rtf->data () + s->at, take);
	s->at += take;
	*done = (LONG) take;
	return 0;
}

void
md_strip_bom (std::string &text)
{
	if (text.size () >= 3 && (unsigned char) text[0] == 0xef
		&& (unsigned char) text[1] == 0xbb && (unsigned char) text[2] == 0xbf)
		text.erase (0, 3);
}

void
md_layout (HWND dlg)
{
	RECT rc;

	GetClientRect (dlg, &rc);
	MoveWindow (GetDlgItem (dlg, IDC_MD_EDIT), 0, 0, rc.right, rc.bottom, TRUE);
}

/* Convert and show.  The link ranges are only applied when the control
   ends up holding exactly as many characters as the converter counted:
   a mismatch would put them on the wrong words, and inert links are the
   better failure.  */
void
md_render (HWND dlg)
{
	HWND edit = GetDlgItem (dlg, IDC_MD_EDIT);
	md_rtf_doc doc = md_to_rtf (g_md_doc.text.data (), g_md_doc.text.size (), md_rtf_default_style ());
	md_stream src = { &doc.rtf, 0 };
	EDITSTREAM es = {};

	SetCursor (LoadCursorW (nullptr, IDC_WAIT));
	es.dwCookie = (DWORD_PTR) &src;
	es.pfnCallback = md_stream_read;
	SendMessageW (edit, EM_STREAMIN, SF_RTF, (LPARAM) &es);

	GETTEXTLENGTHEX gtl = { GTL_NUMCHARS | GTL_PRECISE, 1200 };
	LONG len = (LONG) SendMessageW (edit, EM_GETTEXTLENGTHEX, (WPARAM) &gtl, 0);
	if (len == doc.chars)
	{
		CHARFORMAT2W cf = {};
		cf.cbSize = sizeof (cf);
		cf.dwMask = CFM_LINK;
		cf.dwEffects = CFE_LINK;
		for (const md_rtf_link &l : doc.links)
		{
			CHARRANGE cr = { l.start, l.end };
			SendMessageW (edit, EM_EXSETSEL, 0, (LPARAM) &cr);
			SendMessageW (edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &cf);
		}
		g_md_links = std::move (doc.links);
		g_md_anchors = std::move (doc.anchors);
	}
	else
	{
		g_md_links.clear ();
		g_md_anchors.clear ();
	}

	CHARRANGE home = { 0, 0 };
	SendMessageW (edit, EM_EXSETSEL, 0, (LPARAM) &home);
	SendMessageW (edit, WM_VSCROLL, SB_TOP, 0);
}

/* Put the heading a "#slug" link names at the top of the view.  */
void
md_goto_anchor (HWND dlg, const std::wstring &slug)
{
	HWND edit = GetDlgItem (dlg, IDC_MD_EDIT);

	for (const md_rtf_anchor &a : g_md_anchors)
	{
		if (_wcsicmp (a.slug.c_str (), slug.c_str ()) != 0)
			continue;
		CHARRANGE cr = { a.at, a.at };
		SendMessageW (edit, EM_EXSETSEL, 0, (LPARAM) &cr);
		LONG line = (LONG) SendMessageW (edit, EM_EXLINEFROMCHAR, 0, a.at);
		LONG first = (LONG) SendMessageW (edit, EM_GETFIRSTVISIBLELINE, 0, 0);
		SendMessageW (edit, EM_LINESCROLL, 0, (LPARAM) (line - first));
		return;
	}
}

/* A link the user clicked.  A "#section" link jumps within the
   document; only web and mail targets leave the program, and only after
   the whole target has been shown and confirmed.  Anything else -- a
   relative path to a neighbouring file -- has nothing to resolve
   against here and stays inert.  */
void
md_open_link (HWND dlg, CHARRANGE cr)
{
	for (const md_rtf_link &l : g_md_links)
	{
		if (cr.cpMin < l.start || cr.cpMax > l.end)
			continue;
		const wchar_t *t = l.target.c_str ();
		if (t[0] == L'#')
		{
			md_goto_anchor (dlg, l.target.substr (1));
			return;
		}
		if (_wcsnicmp (t, L"http://", 7) != 0 && _wcsnicmp (t, L"https://", 8) != 0 && _wcsnicmp (t, L"mailto:", 7) != 0)
			return;
		std::wstring ask = res_str (IDS_MD_ASK_LINK) + L"\r\n\r\n" + l.target;
		if (MessageBoxW (dlg, ask.c_str (), res_str (IDS_MD_TITLE).c_str (),
				 MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) == IDYES)
			ShellExecuteW (dlg, L"open", t, nullptr, nullptr, SW_SHOWNORMAL);
		return;
	}
}

void
md_init_dialog (HWND dlg)
{
	g_md = dlg;
	g_md_links.clear ();
	g_md_anchors.clear ();
	SetWindowTextW (dlg, g_md_doc.title.c_str ());

	HWND edit = GetDlgItem (dlg, IDC_MD_EDIT);
	SendMessageW (edit, EM_EXLIMITTEXT, 0, 0x7ffffffe);
	SendMessageW (edit, EM_SETEVENTMASK, 0, ENM_LINK);
	SendMessageW (edit, EM_SETTARGETDEVICE, 0, 0);	/* wrap to the window */
	SendMessageW (edit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM (dpi_scale (12), dpi_scale (12)));

	/* Default frame centered on the work area (the template size is just a fallback).  */
	RECT wa;
	SystemParametersInfoW (SPI_GETWORKAREA, 0, &wa, 0);
	int width = dpi_scale (820);
	int height = dpi_scale (620);
	if (width > wa.right - wa.left)
		width = wa.right - wa.left;
	if (height > wa.bottom - wa.top)
		height = wa.bottom - wa.top;
	SetWindowPos (dlg, nullptr,
		wa.left + ((wa.right - wa.left) - width) / 2,
		wa.top + ((wa.bottom - wa.top) - height) / 2,
		width, height, SWP_NOZORDER);

	if (g_md_path.empty ())
	{
		md_render (dlg);
		return;
	}
	/* Replaced wholesale by the first EM_STREAMIN, so a slow device
	   does not leave an empty window with nothing to say.  */
	SetDlgItemTextW (dlg, IDC_MD_EDIT, res_str (IDS_TEXT_LOADING).c_str ());

	backend_task task;
	task.type = backend_task_type::read_chunk;
	task.path = g_md_path;
	task.offset = 0;
	task.length = MD_PROBE;
	g_md_probing = true;
	g_seq_md = backend_post (std::move (task));
}

INT_PTR CALLBACK
md_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		md_init_dialog (dlg);
		md_layout (dlg);
		SetFocus (GetDlgItem (dlg, IDC_MD_EDIT));
		return FALSE;	/* focus was set explicitly */
	case WM_SIZE:
		md_layout (dlg);
		return TRUE;
	case WM_GETMINMAXINFO:
		((MINMAXINFO *) lp)->ptMinTrackSize = { dpi_scale (400), dpi_scale (240) };
		return TRUE;
	case WM_NOTIFY:
	{
		NMHDR *nm = (NMHDR *) lp;
		if (nm->idFrom == IDC_MD_EDIT && nm->code == EN_LINK)
		{
			ENLINK *el = (ENLINK *) lp;
			if (el->msg == WM_LBUTTONUP)
				md_open_link (dlg, el->chrg);
			SetWindowLongPtrW (dlg, DWLP_MSGRESULT, 0);
			return TRUE;
		}
		break;
	}
	case WM_COMMAND:
		if (LOWORD (wp) == IDCANCEL)
		{
			/* A late read result is dropped once g_md is null.  */
			g_md = nullptr;
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

void
md_show_dialog (void)
{
	/* RICHEDIT50W lives in Msftedit.dll; load once, keep loaded.  */
	static HMODULE msftedit;

	if (!msftedit)
	{
		msftedit = LoadLibraryW (L"Msftedit.dll");
		if (!msftedit)
			return;
	}
	{
		modal_scope hold;
		DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_MD), g_main, md_dlg_proc, 0);
	}
	g_md = nullptr;
	g_md_doc = md_document ();
	g_md_path.clear ();
	std::vector<md_rtf_link> ().swap (g_md_links);
	std::vector<md_rtf_anchor> ().swap (g_md_anchors);
}

} // namespace

/* Extensions that get the preview entry in the file context menu.  */
bool
is_markdown_name (const std::string &name)
{
	static const char *exts[] = { "md", "markdown" };
	size_t dot = name.find_last_of ('.');

	if (dot == std::string::npos)
		return false;
	std::string ext = name.substr (dot + 1);
	for (const char *e : exts)
		if (_stricmp (ext.c_str (), e) == 0)
			return true;
	return false;
}

void
md_on_chunk (backend_result *res)
{
	if (!g_md || res->seq != g_seq_md)
		return;
	if (!res->error.empty ())
	{
		HWND dlg = g_md;
		g_md = nullptr;
		MessageBoxW (dlg, widen (res->error).c_str (), res_str (IDS_MD_TITLE).c_str (), MB_ICONERROR);
		EndDialog (dlg, 0);
		return;
	}

	/* Stage one: the sniff read supplies the size, so a huge document
	   can be refused before the load and the conversion.  */
	if (g_md_probing)
	{
		g_md_probing = false;
		if (res->file_size > MD_WARN)
		{
			wchar_t buf[256];
			swprintf (buf, 256, res_str (IDS_ASK_TEXT_BIG).c_str (), format_size (res->file_size).c_str ());
			if (MessageBoxW (g_md, buf, res_str (IDS_MD_TITLE).c_str (),
					 MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES)
			{
				HWND dlg = g_md;
				g_md = nullptr;
				EndDialog (dlg, 0);
				return;
			}
		}
		if (res->file_size > res->data.size ())
		{
			backend_task task;
			task.type = backend_task_type::read_chunk;
			task.path = g_md_path;
			task.offset = 0;
			task.length = MD_MAX;
			g_seq_md = backend_post (std::move (task));
			return;
		}
		/* The probe already covered the whole file.  */
	}

	g_md_doc.text.assign (res->data.begin (), res->data.end ());
	md_strip_bom (g_md_doc.text);
	if (res->file_size > res->data.size ())
	{
		/* The cut is reported in the document itself, so it survives
		   scrolling and cannot be missed in a caption.  */
		wchar_t buf[256];
		swprintf (buf, 256, res_str (IDS_FMT_MD_TRUNC).c_str (),
			format_size (res->data.size ()).c_str (),
			format_size (res->file_size).c_str ());
		g_md_doc.text += "\n\n---\n\n*";
		g_md_doc.text += narrow (buf);
		g_md_doc.text += "*\n";
	}
	md_render (g_md);
}

void
show_markdown_doc (const md_document &doc)
{
	g_md_doc = doc;
	g_md_path.clear ();
	md_show_dialog ();
}

void
show_markdown (const std::string &path)
{
	size_t cut = path.find_last_of ('/');
	std::wstring name = widen (cut == std::string::npos ? path : path.substr (cut + 1));

	g_md_doc = md_document ();
	g_md_doc.title = name + L" - " + res_str (IDS_MD_TITLE);
	g_md_path = path;
	md_show_dialog ();
}

bool
md_load_resource (UINT id, md_document *doc)
{
	HMODULE self = GetModuleHandleW (nullptr);
	HRSRC found = FindResourceW (self, MAKEINTRESOURCEW (id), RT_RCDATA);

	if (!found)
		return false;
	HGLOBAL block = LoadResource (self, found);
	DWORD size = SizeofResource (self, found);
	const char *data = block ? (const char *) LockResource (block) : nullptr;
	if (!data || !size)
		return false;
	doc->text.assign (data, size);
	md_strip_bom (doc->text);
	return true;
}

bool
md_load_file (const std::wstring &path, md_document *doc)
{
	HANDLE file = CreateFileW (path.c_str (), GENERIC_READ, FILE_SHARE_READ, nullptr,
				   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	LARGE_INTEGER size = {};
	DWORD got = 0;
	bool ok = false;

	if (file == INVALID_HANDLE_VALUE)
		return false;
	if (!GetFileSizeEx (file, &size) || size.QuadPart <= 0)
		goto out;
	if (size.QuadPart > MD_MAX)
		size.QuadPart = MD_MAX;
	doc->text.resize ((size_t) size.QuadPart);
	if (!ReadFile (file, doc->text.data (), (DWORD) size.QuadPart, &got, nullptr))
		goto out;
	doc->text.resize (got);
	md_strip_bom (doc->text);
	ok = true;
out:
	CloseHandle (file);
	if (!ok)
		doc->text.clear ();
	return ok;
}

/* A page shipped with the program.  A file next to the executable wins
   over the resource copy, so a page can be corrected or translated in a
   release without rebuilding; pass res_id 0 for a file-only page, or an
   empty name for a resource-only one.  */
bool
md_load_help (const wchar_t *name, UINT res_id, md_document *doc)
{
	wchar_t exe[MAX_PATH];
	DWORD len = name ? GetModuleFileNameW (nullptr, exe, MAX_PATH) : 0;

	if (len && len < MAX_PATH)
	{
		std::wstring path (exe, len);
		size_t cut = path.find_last_of (L'\\');
		path.erase (cut == std::wstring::npos ? 0 : cut + 1);
		path += name;
		if (md_load_file (path, doc))
			return true;
	}
	return res_id != 0 && md_load_resource (res_id, doc);
}
