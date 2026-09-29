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
 * This thread never calls grub; work is queued to
 * the backend thread (backend.h) and results arrive as WM_APP messages.
 * This file owns the main window itself: its controls and layout, the
 * window procedure and the dispatch of backend results.  The list,
 * tree, navigation, job and menu code are split out by function and
 * share mainwnd.h.
 */

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>
#include <wchar.h>

#include <memory>
#include <string>

#include "dokanfs.h"
#include "mainwnd.h"
#include "tray.h"
#include "resource.h"
#include "strconv.h"

#pragma comment (lib, "comctl32.lib")
#pragma comment (lib, "shell32.lib")
#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "uxtheme.lib")
#pragma comment (lib, "comdlg32.lib")

/* Common controls v6: themed controls and buttons that can show an
   icon next to their text (BCM_SETIMAGELIST).  */
#pragma comment (linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' \
language='*'\"")

/* Shared with the dialog and viewer files through gui.h.  */
HWND g_main;

namespace mainwnd
{

HWND g_address;
HWND g_btn_extract;
HWND g_btn_up;
HWND g_btn_back;
HWND g_btn_fwd;
HWND g_tree;
HWND g_list;
HWND g_status;
HWND g_progress;

namespace
{

/* This window's DPI, and the layout metrics it scales.  Read from the
   creation monitor in WM_CREATE and refreshed on WM_DPICHANGED; every
   other top-level window keeps one of its own.  */
UINT g_main_dpi = 96;

int
main_scale (int value)
{
	return dpi_scale (g_main_dpi, value);
}

/* Layout metrics authored at 96 DPI; scaled through main_scale().  */
constexpr int TOP_BAR_H = 28;
constexpr int TREE_W = 280;	/* initial splitter position */
constexpr int TREE_MIN_W = 120;	/* neither pane can be dragged away */
constexpr int LIST_MIN_W = 200;
constexpr int SPLIT_W = 5;	/* draggable gap between the two panes */
constexpr int MARGIN = 2;
constexpr int BTN_W = 90;
constexpr int NAV_W = 30;	/* Back/Forward/Up: glyph only, no label */
constexpr int PROGRESS_W = 260;
constexpr int DEF_W = 1000;	/* default window size */
constexpr int DEF_H = 700;

HFONT g_font;	/* message font, shared by all controls */
tray_icon g_tray;	/* notification icon and its shell-restart handling */

/* Splitter state.  The width is kept in 96-DPI units like every other
   layout metric, so a move to another monitor rescales it for free.  */
int g_tree_w = TREE_W;
bool g_split_drag;
int g_split_grab;	/* cursor offset inside the bar when the drag began */

} // namespace

void
set_status (const wchar_t *text)
{
	SendMessageW (g_status, SB_SETTEXTW, 0, (LPARAM) text);
}

void
set_status (UINT id)
{
	set_status (res_str (id).c_str ());
}

namespace
{

/* (Re)create every DPI-dependent GDI object at g_main_dpi and hand it to the
   controls that use it, freeing the previous generation.  Called once when
   the controls are built and again on each WM_DPICHANGED.  */
void
apply_dpi_resources (void)
{
	int sm = system_metric_dpi (g_main_dpi, SM_CXSMICON);

	/* Shared message font.  */
	HFONT font = create_message_font (g_main_dpi);
	for (HWND ctl : { g_address, g_btn_extract, g_btn_up, g_btn_back, g_btn_fwd, g_tree, g_list })
		SendMessageW (ctl, WM_SETFONT, (WPARAM) font, TRUE);
	if (g_font)
		DeleteObject (g_font);
	g_font = font;

	list_apply_dpi (sm);
	tree_apply_dpi (sm);
	job_apply_dpi (sm);
}

void
on_task_done (backend_result *raw)
{
	std::unique_ptr<backend_result> res (raw);

	switch (res->type)
	{
	case backend_task_type::enum_disks:
		if (res->seq != g_seq_disks)
			return;
		break;
	case backend_task_type::list_dir:
		if (res->seq != g_seq_list)
			return;
		break;
	case backend_task_type::list_sizes:
		if (res->seq != g_seq_sizes || res->owner_seq != g_seq_list)
			return;
		break;
	case backend_task_type::extract:
	case backend_task_type::export_image:
		if (!job_finish (res.get ()))
			return;
		break;
	case backend_task_type::loopback_add:
	case backend_task_type::loopback_del:
	case backend_task_type::winfile_add:
	case backend_task_type::winfile_del:
	case backend_task_type::lost_del:
		break;
	case backend_task_type::lost_add:
		lost_add_done (res.get ());
		break;
	case backend_task_type::lost_scan:
		lost_scan_done (res.get ());
		return;
	case backend_task_type::file_map:
		file_map_done (res.get ());
		return;
	case backend_task_type::file_props:
		props_on_type (res.get ());
		return;
	case backend_task_type::hash_file:
		props_on_hash (res.get ());
		return;
	case backend_task_type::read_chunk:
		/* Each viewer drops results that are not its own.  */
		hex_on_chunk (res.get ());
		text_on_chunk (res.get ());
		img_on_chunk (res.get ());
		md_on_chunk (res.get ());
		return;
	case backend_task_type::crypto_unlock:
		crypto_unlock_done (res.get ());
		return;
	case backend_task_type::veracrypt_unlock:
		veracrypt_unlock_done (res.get ());
		return;
	case backend_task_type::plainmount_unlock:
		plainmount_done (res.get ());
		return;
	}

	if (!res->error.empty ())
	{
		if (res->type == backend_task_type::list_dir)
		{
			/* A failed navigation must not keep showing the
			   previous directory's entries.  */
			list_clear ();
			SetWindowTextW (g_address, widen (res->path).c_str ());
		}
		set_status (widen (res->error).c_str ());
		return;
	}

	switch (res->type)
	{
	case backend_task_type::enum_disks:
		fill_tree (res.get ());
		break;
	case backend_task_type::list_dir:
		fill_list (res.get ());
		nav_on_listed (res->seq);
		break;
	case backend_task_type::list_sizes:
		fill_list_sizes (res.get ());
		break;
	case backend_task_type::extract:
	case backend_task_type::export_image:
		job_report (res.get ());
		break;
	case backend_task_type::loopback_add:
	case backend_task_type::winfile_add:
	case backend_task_type::lost_add:
		tree_on_mounted (res.get ());
		break;
	case backend_task_type::loopback_del:
	case backend_task_type::winfile_del:
	case backend_task_type::lost_del:
		tree_on_unmounted (res.get ());
		break;
	}
}

void
on_task_progress (backend_progress *raw)
{
	std::unique_ptr<backend_progress> p (raw);

	/* The properties hash and the crypto unlock own their bars.  */
	if (props_on_progress (p.get ()) || crypto_on_progress (p.get ())
		|| veracrypt_on_progress (p.get ()))
		return;
	job_on_progress (p.get ());
}

LRESULT
on_notify (NMHDR *hdr)
{
	if (hdr->hwndFrom == g_list)
		return list_on_notify (hdr);
	if (hdr->hwndFrom == g_tree)
		return tree_on_notify (hdr);
	return 0;
}

/* Window plumbing */

void
create_children (HWND wnd)
{
	const DWORD child = WS_CHILD | WS_VISIBLE;

	g_address = CreateWindowExW (WS_EX_CLIENTEDGE, L"EDIT", L"",
		child | ES_AUTOHSCROLL, 0, 0, 0, 0, wnd, nullptr, nullptr, nullptr);
	g_btn_extract = CreateWindowExW (0, L"BUTTON", res_str (IDS_BTN_EXTRACT).c_str (),
		child | BS_PUSHBUTTON, 0, 0, 0, 0, wnd, (HMENU) (INT_PTR) IDC_EXTRACT, nullptr, nullptr);
	g_btn_up = CreateWindowExW (0, L"BUTTON", res_str (IDS_BTN_UP).c_str (),
		child | BS_PUSHBUTTON, 0, 0, 0, 0, wnd, (HMENU) (INT_PTR) IDC_UP, nullptr, nullptr);
	g_btn_back = CreateWindowExW (0, L"BUTTON", res_str (IDS_BTN_BACK).c_str (),
		child | BS_PUSHBUTTON, 0, 0, 0, 0, wnd, (HMENU) (INT_PTR) IDC_BACK, nullptr, nullptr);
	g_btn_fwd = CreateWindowExW (0, L"BUTTON", res_str (IDS_BTN_FWD).c_str (),
		child | BS_PUSHBUTTON, 0, 0, 0, 0, wnd, (HMENU) (INT_PTR) IDC_FWD, nullptr, nullptr);
	g_tree = CreateWindowExW (WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
		child | TVS_HASBUTTONS | TVS_SHOWSELALWAYS | TVS_FULLROWSELECT, 0, 0, 0, 0, wnd, nullptr, nullptr, nullptr);
	g_list = CreateWindowExW (WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
		child | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA | LVS_SHAREIMAGELISTS, 0, 0, 0, 0, wnd, nullptr, nullptr, nullptr);
	g_status = CreateWindowExW (0, STATUSCLASSNAMEW, L"",
		child | SBARS_SIZEGRIP, 0, 0, 0, 0, wnd, nullptr, nullptr, nullptr);
	g_progress = CreateWindowExW (0, PROGRESS_CLASSW, L"",
		WS_CHILD, 0, 0, 0, 0, g_status, nullptr, nullptr, nullptr);
	SendMessageW (g_progress, PBM_SETRANGE32, 0, 100);

	ListView_SetExtendedListViewStyle (g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

	/* Explorer-style hover/selection rendering.  */
	SetWindowTheme (g_tree, L"Explorer", nullptr);
	SetWindowTheme (g_list, L"Explorer", nullptr);
	TreeView_SetExtendedStyle (g_tree,
		TVS_EX_DOUBLEBUFFER | TVS_EX_FADEINOUTEXPANDOS,
		TVS_EX_DOUBLEBUFFER | TVS_EX_FADEINOUTEXPANDOS);

	/* Font, file/tree icons and button icons, all sized for the current
	   monitor DPI (rebuilt on WM_DPICHANGED).  */
	apply_dpi_resources ();
	nav_init ();

	LVCOLUMNW col = {};
	std::wstring col_name = res_str (IDS_COL_NAME);
	std::wstring col_size = res_str (IDS_COL_SIZE);
	std::wstring col_mtime = res_str (IDS_COL_MODIFIED);
	col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
	col.fmt = LVCFMT_LEFT;
	col.pszText = const_cast<wchar_t *> (col_name.c_str ());
	col.cx = main_scale (260);
	ListView_InsertColumn (g_list, 0, &col);
	col.fmt = LVCFMT_RIGHT;
	col.pszText = const_cast<wchar_t *> (col_size.c_str ());
	col.cx = main_scale (100);
	ListView_InsertColumn (g_list, 1, &col);
	col.fmt = LVCFMT_LEFT;
	col.pszText = const_cast<wchar_t *> (col_mtime.c_str ());
	col.cx = main_scale (140);
	ListView_InsertColumn (g_list, 2, &col);

	set_status (IDS_STATUS_STARTING);
}

/* Range where both panes stay usable, in device pixels.  */
int
clamp_split_x (int x, int client_w)
{
	const int min_w = main_scale (TREE_MIN_W);
	const int max_w = client_w - main_scale (SPLIT_W + LIST_MIN_W);

	if (x > max_w)
		x = max_w;
	if (x < min_w)
		x = min_w;
	return x;
}

/* Where the bar sits right now.  A window too narrow for the stored
   width is clamped here and not in g_tree_w, so widening it again
   gives the user's chosen width back.  */
int
splitter_x (int client_w)
{
	return clamp_split_x (main_scale (g_tree_w), client_w);
}

/* The bar itself: the gap between the two panes, below the top row.
   Everything under it is covered by a child window, so a client hit
   this far down is either the gap or one of the panes.  */
bool
in_splitter (HWND wnd, POINT pt)
{
	RECT rc;
	int x;

	if (pt.y < main_scale (TOP_BAR_H + MARGIN))
		return false;
	GetClientRect (wnd, &rc);
	x = splitter_x (rc.right);
	return pt.x >= x && pt.x < x + main_scale (SPLIT_W);
}

void
layout (HWND wnd)
{
	RECT rc;
	const int margin = main_scale (MARGIN);
	const int top_bar_h = main_scale (TOP_BAR_H);
	const int split_w = main_scale (SPLIT_W);
	const int btn_w = main_scale (BTN_W);
	const int nav_w = main_scale (NAV_W);
	const int progress_w = main_scale (PROGRESS_W);

	GetClientRect (wnd, &rc);
	const int tree_w = splitter_x (rc.right);
	SendMessageW (g_status, WM_SIZE, 0, 0);

	int parts[2] = { rc.right - progress_w - main_scale (20), -1 };
	SendMessageW (g_status, SB_SETPARTS, 2, (LPARAM) parts);
	RECT prc;
	SendMessageW (g_status, SB_GETRECT, 1, (LPARAM) &prc);
	MoveWindow (g_progress,
		prc.left + main_scale (2), prc.top + main_scale (2),
		prc.right - prc.left - main_scale (22),
		prc.bottom - prc.top - main_scale (4), TRUE);

	RECT src;
	GetWindowRect (g_status, &src);
	const int status_h = src.bottom - src.top;
	const int body_top = top_bar_h + margin;
	const int body_h = rc.bottom - body_top - status_h;
	const int btn_h = top_bar_h - 2 * margin;

	int x = margin;
	MoveWindow (g_btn_back, x, margin, nav_w, btn_h, TRUE);
	x += nav_w + margin;
	MoveWindow (g_btn_fwd, x, margin, nav_w, btn_h, TRUE);
	x += nav_w + margin;
	MoveWindow (g_btn_up, x, margin, nav_w, btn_h, TRUE);
	x += nav_w + margin;
	MoveWindow (g_address, x, margin, rc.right - x - btn_w - 2 * margin, btn_h, TRUE);
	MoveWindow (g_btn_extract, rc.right - btn_w - margin, margin, btn_w, btn_h, TRUE);
	MoveWindow (g_tree, 0, body_top, tree_w, body_h, TRUE);
	MoveWindow (g_list, tree_w + split_w, body_top, rc.right - tree_w - split_w, body_h, TRUE);
}

LRESULT CALLBACK
main_wnd_proc (HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
	if (g_tray.handle_message (msg, lp))
		return 0;

	switch (msg)
	{
	case WM_CREATE:
		g_main = wnd;
		g_main_dpi = dpi_for_window (wnd);
		create_children (wnd);
		create_menu_bar (wnd);
		if (!backend_start (wnd, g_cmdline.no_windisk))
		{
			MessageBoxW (wnd, res_str (IDS_BACKEND_START_FAILED).c_str (),
				res_str (IDS_APP_TITLE).c_str (), MB_ICONERROR | MB_OK);
			return -1;
		}
		dokanfs_init (wnd);
		g_tray.add (wnd, do_dokan_unmount);
		enable_file_drop (wnd);
		/* Grow the default frame for a high-DPI creation monitor
		   (WM_DPICHANGED takes over once it is on screen).  */
		if (g_main_dpi != 96)
			SetWindowPos (wnd, nullptr, 0, 0, main_scale (DEF_W), main_scale (DEF_H), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
		return 0;
	case WM_SIZE:
		/* The tray icon is already the app's resident presence, so a
		   minimized window would just be a second, redundant entry
		   in the taskbar: leave it altogether and come back through
		   the tray.  Nothing to lay out at zero client size either.  */
		if (wp == SIZE_MINIMIZED)
		{
			ShowWindow (wnd, SW_HIDE);
			return 0;
		}
		layout (wnd);
		return 0;
	case WM_DPICHANGED:
	{
		/* Moved to a monitor with a different scale: rebuild the
		   DPI-sized fonts/icons, carry the columns over, and take the
		   suggested frame (which re-lays-out through WM_SIZE).  */
		UINT prev = g_main_dpi;

		g_main_dpi = HIWORD (wp);
		apply_dpi_resources ();
		for (int c = 0; c < 3; c++)
		{
			int w = ListView_GetColumnWidth (g_list, c);
			ListView_SetColumnWidth (g_list, c, MulDiv (w, (int) g_main_dpi, (int) prev));
		}
		dpi_take_suggested (wnd, lp);
		return 0;
	}
	case WM_SETCURSOR:
	{
		/* WM_SETCURSOR carries no position, and during a drag the
		   cursor has usually left the bar already.  */
		POINT pt;
		if (LOWORD (lp) != HTCLIENT)
			break;
		GetCursorPos (&pt);
		ScreenToClient (wnd, &pt);
		if (!g_split_drag && !in_splitter (wnd, pt))
			break;
		SetCursor (LoadCursorW (nullptr, IDC_SIZEWE));
		return TRUE;
	}
	case WM_LBUTTONDOWN:
	{
		POINT pt = { (short) LOWORD (lp), (short) HIWORD (lp) };
		RECT rc;
		if (!in_splitter (wnd, pt))
			break;
		GetClientRect (wnd, &rc);
		/* Grab offset, so the bar does not jump under the cursor.  */
		g_split_grab = pt.x - splitter_x (rc.right);
		g_split_drag = true;
		SetCapture (wnd);
		return 0;
	}
	case WM_MOUSEMOVE:
	{
		RECT rc;
		if (!g_split_drag)
			break;
		/* Clamped here too: the bar stops at the limit and follows
		   again the moment the cursor comes back, instead of
		   trailing however far it was dragged past it.  */
		GetClientRect (wnd, &rc);
		g_tree_w = dpi_unscale (g_main_dpi, clamp_split_x ((short) LOWORD (lp) - g_split_grab, rc.right));
		layout (wnd);
		return 0;
	}
	case WM_LBUTTONUP:
		if (g_split_drag)
			ReleaseCapture ();	/* clears the flag below */
		break;
	case WM_CAPTURECHANGED:
		g_split_drag = false;
		return 0;
	case WM_COMMAND:
		on_command (LOWORD (wp));
		return 0;
	case WM_INITMENUPOPUP:
		on_menu_popup ((HMENU) wp);
		return 0;
	case WM_NOTIFY:
		return on_notify ((NMHDR *) lp);
	case WM_DROPFILES:
		on_drop_files ((HDROP) wp);
		return 0;
	case WM_APP_BACKEND_READY:
		/* Apply command-line settings before any startup mount or enumeration. */
		backend_set_fs_char_encoding (g_fs_encoding);
		/* --file/--file-dec stand in for the first refresh: each mount
		   ends in one of its own (on_task_done), and doing both would
		   leave two enumerations racing for the tree.  */
		if (!g_cmdline.mounts.empty ())
		{
			for (const auto &mount : g_cmdline.mounts)
				mount_host_image (mount.file, mount.decompress);
		}
		else
			refresh ();
		return 0;
	case WM_APP_TASK_DONE:
		on_task_done ((backend_result *) lp);
		return 0;
	case WM_APP_TASK_PROGRESS:
		on_task_progress ((backend_progress *) lp);
		return 0;
	case WM_APP_DOKAN_GONE:
	{
		/* Driver-side unmount; the pointer may already be gone
		   if we unmounted it ourselves.  */
		dokan_mount *m = dokanfs_find_ptr ((void *) lp);
		if (m)
			do_dokan_unmount (m);
		return 0;
	}
	case WM_APP_DOKAN_MOUNTED:
	{
		/* A mount with the open-Explorer option went live; it
		   may already be gone again.  */
		dokan_mount *m = dokanfs_find_ptr ((void *) lp);
		if (m)
			ShellExecuteW (nullptr, L"open", (dokanfs_letter (m) + L"\\").c_str (), nullptr, nullptr, SW_SHOWNORMAL);
		return 0;
	}
	case WM_CLOSE:
		/* The tray Exit can arrive while a modal dialog holds
		   the main window disabled; destroying the owner under
		   a modal loop is not survivable.  Every modal call site
		   registers itself (gui.h), so this stays right without
		   anyone having to remember to extend it.  */
		if (modal_open ())
			return 0;
		if (dokanfs_count () > 0)
		{
			modal_scope hold;
			if (MessageBoxW (wnd, res_str (IDS_ASK_UNMOUNT_ALL).c_str (), res_str (IDS_APP_TITLE).c_str (),
				MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
				return 0;
			dokanfs_unmount_all ();
		}
		DestroyWindow (wnd);
		return 0;
	case WM_DESTROY:
		g_tray.remove ();
		dokanfs_shutdown ();
#if FSROVER_ENABLE_ADMIN_FEATURES
		smart_shutdown ();
#endif
		if (!backend_stop ())
			MessageBoxW (nullptr, res_str (IDS_BACKEND_STOP_FAILED).c_str (),
				res_str (IDS_APP_TITLE).c_str (), MB_ICONERROR | MB_OK);
		PostQuitMessage (0);
		return 0;
	}
	return DefWindowProcW (wnd, msg, wp, lp);
}

} // namespace

} // namespace mainwnd

int WINAPI
wWinMain (HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
	using namespace mainwnd;

	CoInitializeEx (nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	init_language ();
	/* After init_language(), because the usage box is localized.  */
	if (!cmdline_parse ())
	{
		CoUninitialize ();
		return 0;
	}
	g_preserve_times = g_cmdline.preserve_times;
	g_fs_encoding = g_cmdline.fs_encoding;
	load_dpi_api ();

	INITCOMMONCONTROLSEX icc = { sizeof (icc),
		ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES
		| ICC_PROGRESS_CLASS | ICC_LINK_CLASS | ICC_STANDARD_CLASSES };
	InitCommonControlsEx (&icc);

	WNDCLASSEXW wc = { sizeof (wc) };
	wc.lpfnWndProc = main_wnd_proc;
	wc.hInstance = instance;
	wc.hIcon = (HICON) LoadImageW (instance, MAKEINTRESOURCEW (IDI_APP), IMAGE_ICON,
		GetSystemMetrics (SM_CXICON), GetSystemMetrics (SM_CYICON), 0);
	wc.hIconSm = (HICON) LoadImageW (instance, MAKEINTRESOURCEW (IDI_APP), IMAGE_ICON,
		GetSystemMetrics (SM_CXSMICON), GetSystemMetrics (SM_CYSMICON), 0);
	wc.hCursor = LoadCursorW (nullptr, IDC_ARROW);
	wc.hbrBackground = (HBRUSH) (COLOR_BTNFACE + 1);
	wc.lpszClassName = L"FsRoverMain";
	RegisterClassExW (&wc);

	HWND wnd = CreateWindowExW (0, wc.lpszClassName, res_str (IDS_APP_TITLE).c_str (),
		WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, DEF_W, DEF_H, nullptr, nullptr, instance, nullptr);
	if (!wnd)
		return 1;
	/* --minimize overrides the shell's suggestion and starts in the
	   tray.  The window has simply never been shown, so there is no
	   taskbar button to put up and take away again -- which is what
	   showing it minimized would do, now that minimizing hides.  */
	ShowWindow (wnd, g_cmdline.minimize ? SW_HIDE : show);
	UpdateWindow (wnd);

	/* Explorer's navigation bindings plus Ctrl+A.  Built here rather than
	   loaded from an ACCELERATORS resource because the command ids live in
	   mainwnd.h, not resource.h, and the table needs no translation.  */
	ACCEL accels[] =
	{
		{ FVIRTKEY | FALT, VK_LEFT, IDC_BACK },
		{ FVIRTKEY | FALT, VK_RIGHT, IDC_FWD },
		{ FVIRTKEY | FALT, VK_UP, IDC_UP },
		{ FVIRTKEY | FCONTROL, 'A', IDM_SEL_ALL },
	};
	HACCEL accel = CreateAcceleratorTableW (accels, ARRAYSIZE (accels));

	MSG msg;
	while (GetMessageW (&msg, nullptr, 0, 0) > 0)
	{
		/* Editing the address bar keeps its own keys, Ctrl+A included.
		   Every other window is a modal dialog running its own loop, so
		   nothing else reaches this one.  */
		if (GetFocus () != g_address && TranslateAcceleratorW (wnd, accel, &msg))
			continue;
		TranslateMessage (&msg);
		DispatchMessageW (&msg);
	}
	DestroyAcceleratorTable (accel);
	CoUninitialize ();
	return (int) msg.wParam;
}
