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
 */

#include <windows.h>
#include <commctrl.h>
#include <commoncontrols.h>
#include <shlobj.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <wctype.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "backend.h"
#include "dokanfs.h"
#include "gui.h"
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
bool g_extracting;

namespace
{

constexpr int IDC_EXTRACT = 101;
constexpr int IDC_UP = 102;

/* Menu bar commands.  IDM_DOKAN_UNMOUNT_BASE + i unmounts
   dokanfs_get(i); the Dokan popup is rebuilt on every open, and a
   menu is modal, so the index is still valid when the command
   arrives.  */
constexpr int IDM_FILE_REFRESH = 200;
constexpr int IDM_FILE_EXIT = 201;
constexpr int IDM_SEL_ALL = 210;
constexpr int IDM_SEL_INVERT = 211;
constexpr int IDM_HELP_SUPPORT = 220;
constexpr int IDM_HELP_ABOUT = 221;
constexpr int IDM_DOKAN_INSTALL = 222;
constexpr int IDM_DOKAN_UNMOUNT_BASE = 2000;

constexpr int IDM_EXTRACT = 1;
constexpr int IDM_MOUNT = 2;
constexpr int IDM_UNMOUNT = 3;
constexpr int IDM_DOKAN_MOUNT = 4;
constexpr int IDM_DOKAN_UNMOUNT = 5;
constexpr int IDM_PROPS = 6;
constexpr int IDM_HEX = 7;
constexpr int IDM_COPY_NAME = 8;
constexpr int IDM_COPY_PATH = 9;
constexpr int IDM_MOUNT_DECOMP = 10;
constexpr int IDM_TEXT = 11;
constexpr int IDM_IMAGE = 12;
constexpr int IDM_TRAY_OPEN = 900;
constexpr int IDM_TRAY_EXIT = 901;
constexpr int IDM_TRAY_UNMOUNT_BASE = 1000;

/* tray -> window: mouse events on the notification icon.  */
constexpr UINT WM_APP_TRAY = WM_APP + 5;

/* Layout metrics authored at 96 DPI; scaled through dpi_scale().  */
constexpr int TOP_BAR_H = 28;
constexpr int TREE_W = 280;
constexpr int MARGIN = 2;
constexpr int BTN_W = 90;
constexpr int PROGRESS_W = 260;
constexpr int DEF_W = 1000;	/* default window size */
constexpr int DEF_H = 700;

/* imageres.dll */
constexpr int IR_ICON_FLOPPY = 28;
constexpr int IR_ICON_CD = 30;
constexpr int IR_ICON_DISK = 32;
constexpr int IR_ICON_CHIP = 34;
constexpr int IR_ICON_BACK = 148;
constexpr int IR_ICON_ZIP = 174;
constexpr int IR_ICON_LOCK = 1031;
constexpr int IR_ICON_UNLOCK = 1030;

/* SHELL32.dll */
constexpr int SH_ICON_CANCEL = 240;
constexpr int SH_ICON_EXTRACT = 241;
constexpr int SH_ICON_UP = 255;

/* Tree image list order.  */
constexpr int IMG_DISK = 0;
constexpr int IMG_FLOPPY = 1;
constexpr int IMG_CD = 2;
constexpr int IMG_LOOP = 3;
constexpr int IMG_LVM = 4;
constexpr int IMG_FW = 5;
constexpr int IMG_LOCK = 6;
constexpr int IMG_UNLOCK = 7;

/* The file list uses per-extension shell icons copied into a DPI-sized
   image list; indexes come from list_icon() below, not a fixed order.  */

HWND g_address;
HWND g_btn_extract;
HWND g_btn_up;
HWND g_tree;
HWND g_list;
HWND g_status;
HWND g_progress;
HMENU g_menu_file;	/* File popup: Refresh grays while extracting */
HMENU g_menu_dokan;	/* Dokan popup, rebuilt on every open */

/* Current view; owned by the GUI thread, replaced from task results.  */
struct list_row
{
	std::wstring name;
	std::wstring size;
	std::wstring mtime;
	int image = -1;	/* DPI-sized list image index, -1 if none */
};

std::vector<backend_diskent> g_disks;
std::vector<backend_dirent> g_entries;
std::vector<list_row> g_rows;	/* display strings for the virtual list */
std::map<std::wstring, int> g_icon_cache;	/* list_icon() memo, by key */
std::string g_path;	/* listed path, UTF-8, empty = nothing shown */
UINT g_seq_disks;	/* pending seq per task type; older results */
UINT g_seq_list;	/* are stale and dropped */
UINT g_seq_extract;

std::set<std::string> g_mounted;	/* loopback devices we created */
HFONT g_font;	/* message font, shared by all controls */
HIMAGELIST g_himl_extract;	/* Extract button icon */
HIMAGELIST g_himl_cancel;	/* same button while extracting */
HIMAGELIST g_himl_up;	/* Up button icon */
HIMAGELIST g_tree_iml;	/* tree device-icon image list */
HIMAGELIST g_list_iml;	/* DPI-sized file/folder icons */
IImageList *g_shell_iml;	/* source shell icons at the nearest larger size */
NOTIFYICONDATAW g_tray;	/* resident notification icon */

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

int list_icon (const std::string &name, bool is_dir);

/* (Re)create every DPI-dependent GDI object at g_dpi and hand it to the
   controls that use it, freeing the previous generation.  Called once when
   the controls are built and again on each WM_DPICHANGED.  */
void
apply_dpi_resources (void)
{
	static const int tree_ids[] =
		{ IR_ICON_DISK, IR_ICON_FLOPPY, IR_ICON_CD, IR_ICON_ZIP,
		  IR_ICON_BACK, IR_ICON_CHIP, IR_ICON_LOCK, IR_ICON_UNLOCK };
	int sm = system_metric_dpi (SM_CXSMICON);

	/* Shared message font.  */
	HFONT font = create_message_font ();
	for (HWND ctl : { g_address, g_btn_extract, g_btn_up, g_tree, g_list })
		SendMessageW (ctl, WM_SETFONT, (WPARAM) font, TRUE);
	if (g_font)
		DeleteObject (g_font);
	g_font = font;

	/* File/folder icons.  SHGFI_SMALLICON is fixed at 16 physical pixels
	   in a per-monitor-aware process, so copy the same shell indexes from
	   the nearest larger system list into an image list sized for this
	   monitor.  Rebuilding also updates the ListView row height.  */
	int shell_size = sm > 48 ? SHIL_JUMBO : sm > 32 ? SHIL_EXTRALARGE : sm > 16 ? SHIL_LARGE : SHIL_SMALL;
	IImageList *shell_iml = nullptr;
	SHGetImageList (shell_size, IID_IImageList, reinterpret_cast<void **> (&shell_iml));
	HIMAGELIST list_iml = ImageList_Create (sm, sm, ILC_COLOR32 | ILC_MASK, 16, 8);
	if (list_iml)
	{
		ImageList_SetBkColor (list_iml, CLR_NONE);
		ListView_SetImageList (g_list, list_iml, LVSIL_SMALL);
		if (g_list_iml)
			ImageList_Destroy (g_list_iml);
		if (g_shell_iml)
			g_shell_iml->Release ();
		g_list_iml = list_iml;
		g_shell_iml = shell_iml;
		g_icon_cache.clear ();
		for (size_t i = 0; i < g_entries.size () && i < g_rows.size (); i++)
			g_rows[i].image = list_icon (g_entries[i].name, g_entries[i].is_dir);
		InvalidateRect (g_list, nullptr, TRUE);
	}
	else if (shell_iml)
		shell_iml->Release ();

	/* Tree device icons.  */
	HIMAGELIST tree_iml = icon_list (L"\\imageres.dll", tree_ids, 8, sm);
	TreeView_SetImageList (g_tree, tree_iml, TVSIL_NORMAL);
	if (g_tree_iml)
		ImageList_Destroy (g_tree_iml);
	g_tree_iml = tree_iml;

	/* Toolbar button icons; a button keeps its current icon if the shell
	   has no replacement at this size rather than being blanked.  */
	HIMAGELIST up = button_icons (L"\\SHELL32.dll", SH_ICON_UP, sm);
	if (up)
	{
		set_button_icon (g_btn_up, up);
		if (g_himl_up)
			ImageList_Destroy (g_himl_up);
		g_himl_up = up;
	}
	HIMAGELIST extract = button_icons (L"\\SHELL32.dll", SH_ICON_EXTRACT, sm);
	HIMAGELIST cancel = button_icons (L"\\SHELL32.dll", SH_ICON_CANCEL, sm);
	if (extract && cancel)
	{
		set_button_icon (g_btn_extract, g_extracting ? cancel : extract);
		if (g_himl_extract)
			ImageList_Destroy (g_himl_extract);
		if (g_himl_cancel)
			ImageList_Destroy (g_himl_cancel);
		g_himl_extract = extract;
		g_himl_cancel = cancel;
	}
	else
	{
		if (extract)
			ImageList_Destroy (extract);
		if (cancel)
			ImageList_Destroy (cancel);
	}
}

int
device_icon (const backend_diskent &d)
{
	if (d.encrypted)
		return IMG_LOCK;
	switch (d.dev_id)
	{
	case BACKEND_DEV_LOOPBACK:
		return IMG_LOOP;
	case BACKEND_DEV_DISKFILTER:
		return IMG_LVM;
	case BACKEND_DEV_PROCFS:
		return IMG_FW;
	case BACKEND_DEV_CRYPTODISK:
		return IMG_UNLOCK;
	}
	if (d.name.rfind ("cd", 0) == 0)
		return IMG_CD;
	if (d.name.rfind ("fd", 0) == 0)
		return IMG_FLOPPY;
	return IMG_DISK;
}

/* DPI-sized image-list index for a directory entry, chosen by the shell
   from the file extension (folders get the generic folder icon).
   SHGFI_USEFILEATTRIBUTES keeps the shell off the disk -- these paths
   live inside a grub image, not the local filesystem.  Results are
   memoised by extension so a directory full of like-typed files costs
   one shell call.  (No link overlay: SHGFI_LINKOVERLAY only works with
   SHGFI_ICON, not the SHGFI_SYSICONINDEX index we return here, and the
   "SYMLINK" size-column label marks symlinks anyway.)  */
int
list_icon (const std::string &name, bool is_dir)
{
	std::wstring wname = widen (name);
	std::wstring key;

	if (is_dir)
		key = L"\x01" L"dir";
	else
	{
		size_t dot = wname.rfind (L'.');
		key = (dot == std::wstring::npos) ? std::wstring (L"\x01" L"file") : wname.substr (dot);
		for (wchar_t &c : key)
			c = (wchar_t) towlower (c);
	}

	auto it = g_icon_cache.find (key);
	if (it != g_icon_cache.end ())
		return it->second;

	SHFILEINFOW sfi = {};
	DWORD attr = is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
	int idx = -1;
	int icon_w = 16;
	int icon_h = 16;
	ImageList_GetIconSize (g_list_iml, &icon_w, &icon_h);
	if (SHGetFileInfoW (wname.c_str (), attr, &sfi, sizeof (sfi), SHGFI_SYSICONINDEX | SHGFI_USEFILEATTRIBUTES))
	{
		HICON icon = nullptr;
		if (g_shell_iml)
			g_shell_iml->GetIcon (sfi.iIcon, ILD_TRANSPARENT, &icon);
		if (!icon && SHGetFileInfoW (wname.c_str (), attr, &sfi, sizeof (sfi),
				SHGFI_ICON | (icon_w <= 16 ? SHGFI_SMALLICON : SHGFI_LARGEICON) | SHGFI_USEFILEATTRIBUTES))
			icon = sfi.hIcon;
		if (icon)
		{
			HICON sized = (HICON) CopyImage (icon, IMAGE_ICON, icon_w, icon_h, 0);
			if (sized)
			{
				DestroyIcon (icon);
				icon = sized;
			}
			idx = ImageList_AddIcon (g_list_iml, icon);
			DestroyIcon (icon);
		}
	}
	g_icon_cache[key] = idx;
	return idx;
}

} // namespace

/* Navigation: every view change goes through a list_dir task; the
   address bar and g_path are updated from the result, so the UI
   always reflects what was actually listed.  */

void
navigate (const std::string &path)
{
	backend_task task;

	task.type = backend_task_type::list_dir;
	task.path = path;
	g_seq_list = backend_post (std::move (task));
	set_status (IDS_STATUS_LISTING);
}

void
refresh (void)
{
	backend_task task;

	task.type = backend_task_type::enum_disks;
	g_seq_disks = backend_post (std::move (task));
	set_status (IDS_STATUS_ENUM);
	if (!g_path.empty ())
		navigate (g_path);
}

namespace
{

void
go_up (void)
{
	size_t close = g_path.find (')');

	if (close == std::string::npos)
		return;
	size_t root_len = close + 2;	/* "(dev)" + "/" */
	if (g_path.size () <= root_len)
		return;
	size_t cut = g_path.find_last_of ('/');
	if (cut < root_len)
		navigate (g_path.substr (0, root_len));
	else
		navigate (g_path.substr (0, cut));
}

LRESULT CALLBACK
address_proc (HWND wnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR)
{
	switch (msg)
	{
	case WM_KEYDOWN:
		if (wp == VK_RETURN)
		{
			navigate (narrow (window_text (wnd)));
			return 0;
		}
		break;
	case WM_CHAR:
		if (wp == L'\r')
			return 0;
		break;
	case WM_NCDESTROY:
		RemoveWindowSubclass (wnd, address_proc, 0);
		break;
	}
	return DefSubclassProc (wnd, msg, wp, lp);
}

/* Extraction */

std::wstring
pick_folder (void)
{
	wchar_t buf[MAX_PATH] = {};
	BROWSEINFOW bi = {};
	std::wstring out;
	std::wstring title = res_str (IDS_PICK_FOLDER);

	bi.hwndOwner = g_main;
	bi.lpszTitle = title.c_str ();
	bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
	PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW (&bi);
	if (!pidl)
		return {};
	if (SHGetPathFromIDListW (pidl, buf))
		out = buf;
	CoTaskMemFree (pidl);
	return out;
}

std::vector<std::string>
selected_paths (void)
{
	std::vector<std::string> out;
	int i = -1;

	while ((i = ListView_GetNextItem (g_list, i, LVNI_SELECTED)) != -1)
		if ((size_t) i < g_entries.size ())
			out.push_back (join_path (g_path, g_entries[(size_t) i].name));
	return out;
}

void
start_extract (std::vector<std::string> &&paths)
{
	if (g_extracting || paths.empty ())
		return;
	std::wstring dest = pick_folder ();
	if (dest.empty ())
		return;

	backend_task task;
	task.type = backend_task_type::extract;
	task.paths = std::move (paths);
	task.dest = std::move (dest);
	g_seq_extract = backend_post (std::move (task));
	g_extracting = true;
	SetWindowTextW (g_btn_extract, res_str (IDS_BTN_CANCEL).c_str ());
	set_button_icon (g_btn_extract, g_himl_cancel);
	/* Refresh (File menu, grayed in on_menu_popup) and Up would only
	   queue list tasks behind the running extraction and overwrite the
	   progress line; the context menus gray their backend items for
	   the same reason.  */
	EnableWindow (g_btn_up, FALSE);
	SendMessageW (g_progress, PBM_SETPOS, 0, 0);
	ShowWindow (g_progress, SW_SHOW);
	set_status (IDS_STATUS_EXTRACTING);
}

void
on_extract_button (void)
{
	if (g_extracting)
	{
		backend_cancel ();
		set_status (IDS_STATUS_CANCELLING);
		return;
	}
	std::vector<std::string> paths = selected_paths ();
	if (paths.empty () && !g_path.empty ())
		paths.push_back (g_path);
	if (paths.empty ())
	{
		set_status (IDS_STATUS_NOTHING);
		return;
	}
	start_extract (std::move (paths));
}

/* Index of the selected entry if the selection is exactly one file
   (not a directory), else -1.  Mounting only makes sense for files.  */
int
selected_single_file (void)
{
	int i = ListView_GetNextItem (g_list, -1, LVNI_SELECTED);

	if (i < 0 || (size_t) i >= g_entries.size ())
		return -1;
	if (ListView_GetNextItem (g_list, i, LVNI_SELECTED) != -1)
		return -1;
	return g_entries[(size_t) i].is_dir ? -1 : i;
}

void
on_list_rclick (NMITEMACTIVATE *ia)
{
	int hit = ia->iItem;

	if (hit < 0 || (size_t) hit >= g_entries.size ())
		return;
	/* The menu acts on the item under the cursor: a right click
	   outside the current selection replaces it, so a stale
	   selection can never be mounted/extracted by accident.  */
	if (!(ListView_GetItemState (g_list, hit, LVIS_SELECTED) & LVIS_SELECTED))
	{
		ListView_SetItemState (g_list, -1, 0, LVIS_SELECTED);
		ListView_SetItemState (g_list, hit, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	}

	std::vector<std::string> paths = selected_paths ();
	if (paths.empty ())
		return;
	int file_item = selected_single_file ();
	/* While an extraction runs, everything that would touch the
	   backend is grayed: a second extract would silently no-op, and
	   mounts/viewers/properties would queue behind the running task
	   with their dialogs sitting dead until it finishes.  The copy
	   items are pure GUI and stay enabled.  */
	UINT busy = g_extracting ? MF_GRAYED : 0u;
	POINT pt;
	GetCursorPos (&pt);
	HMENU menu = CreatePopupMenu ();
	AppendMenuW (menu, MF_STRING | busy, IDM_EXTRACT, res_str (IDS_MENU_EXTRACT).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (file_item >= 0 ? 0u : MF_GRAYED), IDM_MOUNT, res_str (IDS_MENU_MOUNT).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (file_item >= 0 ? 0u : MF_GRAYED), IDM_MOUNT_DECOMP, res_str (IDS_MENU_MOUNT_DECOMP).c_str ());
	if (file_item >= 0 && is_image_name (g_entries[(size_t) file_item].name))
		AppendMenuW (menu, MF_STRING | busy, IDM_IMAGE, res_str (IDS_MENU_IMAGE).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (file_item >= 0 ? 0u : MF_GRAYED), IDM_TEXT, res_str (IDS_MENU_TEXT).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (file_item >= 0 ? 0u : MF_GRAYED), IDM_HEX, res_str (IDS_MENU_HEX).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (file_item >= 0 ? 0u : MF_GRAYED), IDM_PROPS, res_str (IDS_MENU_PROPS).c_str ());
	AppendMenuW (menu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (menu, MF_STRING, IDM_COPY_NAME, res_str (IDS_MENU_COPY_NAME).c_str ());
	AppendMenuW (menu, MF_STRING, IDM_COPY_PATH, res_str (IDS_MENU_COPY_PATH).c_str ());
	int cmd = TrackPopupMenu (menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_main, nullptr);
	DestroyMenu (menu);
	if (cmd == IDM_EXTRACT)
		start_extract (std::move (paths));
	else if ((cmd == IDM_MOUNT || cmd == IDM_MOUNT_DECOMP) && file_item >= 0)
	{
		backend_task task;
		task.type = backend_task_type::loopback_add;
		task.path = join_path (g_path, g_entries[(size_t) file_item].name);
		task.decompress = (cmd == IDM_MOUNT_DECOMP);
		backend_post (std::move (task));
		set_status (IDS_STATUS_MOUNTING);
	}
	else if (cmd == IDM_IMAGE && file_item >= 0)
		show_image (join_path (g_path, g_entries[(size_t) file_item].name));
	else if (cmd == IDM_TEXT && file_item >= 0)
		show_text (join_path (g_path, g_entries[(size_t) file_item].name));
	else if (cmd == IDM_HEX && file_item >= 0)
		show_hex (join_path (g_path, g_entries[(size_t) file_item].name));
	else if (cmd == IDM_PROPS && file_item >= 0)
		show_props (join_path (g_path, g_entries[(size_t) file_item].name));
	else if (cmd == IDM_COPY_NAME || cmd == IDM_COPY_PATH)
	{
		/* One line per selected item: the full grub path, or just
		   the name component after the last '/'.  */
		std::wstring text;
		for (const std::string &p : paths)
		{
			std::string s = p;
			if (cmd == IDM_COPY_NAME)
			{
				size_t slash = p.find_last_of ('/');
				if (slash != std::string::npos)
					s = p.substr (slash + 1);
			}
			if (!text.empty ())
				text += L"\r\n";
			text += widen (s);
		}
		clipboard_set_text (g_main, text);
	}
}

/* Dokan drive-letter mounts */

/* Mount options collected by the dialog; the device entry is a
   snapshot because a disk refresh arriving during the modal loop
   reallocates g_disks, and the Explorer checkbox keeps its last
   state for the session.  */
backend_diskent g_dokan_disk;
wchar_t g_dokan_letter;
bool g_dokan_explorer = true;

INT_PTR CALLBACK
dokan_mount_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		SetWindowTextW (dlg, res_str (IDS_MENU_DOKAN_MOUNT).c_str ());
		std::wstring info = widen (g_dokan_disk.name) + L" (" + widen (g_dokan_disk.fs) + L")";
		SetDlgItemTextW (dlg, IDC_DOKAN_INFO, info.c_str ());
		SetDlgItemTextW (dlg, IDC_DOKAN_LETTER_LABEL, res_str (IDS_DOKAN_LETTER).c_str ());
		SetDlgItemTextW (dlg, IDC_DOKAN_EXPLORER, res_str (IDS_DOKAN_OPEN_EXPLORER).c_str ());
		SetDlgItemTextW (dlg, IDCANCEL, res_str (IDS_BTN_CANCEL).c_str ());

		HWND combo = GetDlgItem (dlg, IDC_DOKAN_LETTER);
		DWORD mask = GetLogicalDrives ();
		for (int i = 3; i < 26; i++)	/* D: through Z: */
			if (!(mask & (1u << i)))
			{
				wchar_t item[3] = { (wchar_t) (L'A' + i), L':', 0 };
				SendMessageW (combo, CB_ADDSTRING, 0, (LPARAM) item);
			}
		/* Default to the highest free letter.  */
		int count = (int) SendMessageW (combo, CB_GETCOUNT, 0, 0);
		SendMessageW (combo, CB_SETCURSEL, (WPARAM) (count - 1), 0);
		CheckDlgButton (dlg, IDC_DOKAN_EXPLORER, g_dokan_explorer ? BST_CHECKED : BST_UNCHECKED);
		return TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDOK:
		{
			HWND combo = GetDlgItem (dlg, IDC_DOKAN_LETTER);
			int sel = (int) SendMessageW (combo, CB_GETCURSEL, 0, 0);
			if (sel < 0)
				return TRUE;	/* no free drive letter */
			wchar_t item[8] = {};
			SendMessageW (combo, CB_GETLBTEXT, (WPARAM) sel, (LPARAM) item);
			g_dokan_letter = item[0];
			g_dokan_explorer = IsDlgButtonChecked (dlg, IDC_DOKAN_EXPLORER) == BST_CHECKED;
			EndDialog (dlg, 1);
			return TRUE;
		}
		case IDCANCEL:
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

void
do_dokan_mount (const backend_diskent &d)
{
	g_dokan_disk = d;
	if (DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_DOKANMOUNT), g_main, dokan_mount_dlg_proc, 0) != 1)
		return;

	std::wstring err;
	dokan_mount *m = dokanfs_mount (g_dokan_disk.name, g_dokan_disk.fs, g_dokan_disk.size, g_dokan_letter, g_dokan_explorer, &err);
	if (!m)
	{
		set_status (err.c_str ());
		return;
	}
	wchar_t text[160];
	// Mounted %s to %s
	_snwprintf_s (text, 160, _TRUNCATE, res_str (IDS_FMT_DOKAN_MOUNTED).c_str (),
		widen (g_dokan_disk.name).c_str (), dokanfs_letter (m).c_str ());
	set_status (text);
}

void
do_dokan_unmount (dokan_mount *m)
{
	std::string dev = dokanfs_device (m);

	dokanfs_unmount (m);
	wchar_t text[160];
	// Unmount %s (%s)
	_snwprintf_s (text, 160, _TRUNCATE, res_str (IDS_FMT_UNMOUNTED).c_str (), widen (dev).c_str ());
	set_status (text);
}

/* Install the app-embedded Dokan runtime (Dokan menu, shown only while
   the driver is absent).  Runs in-process -- the app is elevated -- so
   it writes to System32 and starts a kernel service directly; a wait
   cursor covers the brief pause and the outcome is reported explicitly,
   since installing a driver is worth confirming.  */
void
do_dokan_install (void)
{
	set_status (IDS_DOKAN_INSTALLING);
	UpdateWindow (g_status);
	HCURSOR prev = SetCursor (LoadCursorW (nullptr, IDC_WAIT));

	std::wstring err;
	bool ok = dokanfs_install (&err);

	SetCursor (prev);
	if (ok)
	{
		set_status (IDS_DOKAN_INSTALL_OK);
		MessageBoxW (g_main, res_str (IDS_DOKAN_INSTALL_OK).c_str (), res_str (IDS_APP_TITLE).c_str (), MB_ICONINFORMATION | MB_OK);
	}
	else
	{
		wchar_t text[320];
		// Could not install Dokan: %s
		_snwprintf_s (text, 320, _TRUNCATE, res_str (IDS_FMT_DOKAN_INSTALL_FAIL).c_str (), err.c_str ());
		set_status (text);
		MessageBoxW (g_main, text, res_str (IDS_APP_TITLE).c_str (), MB_ICONERROR | MB_OK);
	}
}

void
on_tree_rclick (void)
{
	POINT pt;
	GetCursorPos (&pt);
	TVHITTESTINFO ht = {};
	ht.pt = pt;
	ScreenToClient (g_tree, &ht.pt);
	HTREEITEM item = TreeView_HitTest (g_tree, &ht);
	if (!item)
		return;

	TVITEMW tvi = {};
	tvi.mask = TVIF_PARAM | TVIF_HANDLE;
	tvi.hItem = item;
	TreeView_GetItem (g_tree, &tvi);
	size_t i = (size_t) tvi.lParam;
	if (i >= g_disks.size ())
		return;
	const backend_diskent &d = g_disks[i];

	/* Dokan mounting needs a recognized filesystem on the device
	   and an installed dokan driver; otherwise the item is grey.
	   Dokan stays usable during an extraction (backend_call jumps
	   the task queue), but loopback unmount and the hex viewer
	   would queue behind it -- and the unmount could even pull the
	   device the extraction is reading from -- so they gray.  */
	dokan_mount *dm = dokanfs_find_device (d.name);
	bool can_dokan = dokanfs_available () && !d.fs.empty () && !dm;
	bool is_loop = g_mounted.count (d.name) != 0;
	/* Raw hex view needs a known device size (the "0+" blocklist spans
	   the whole device); pseudo-devices report an unknown size.  */
	bool can_hex = d.size != BACKEND_SIZE_UNKNOWN;
	UINT busy = g_extracting ? MF_GRAYED : 0u;

	HMENU menu = CreatePopupMenu ();
	AppendMenuW (menu, MF_STRING | (can_dokan ? 0u : MF_GRAYED), IDM_DOKAN_MOUNT, res_str (IDS_MENU_DOKAN_MOUNT).c_str ());
	if (dm)
		AppendMenuW (menu, MF_STRING, IDM_DOKAN_UNMOUNT, res_str (IDS_MENU_DOKAN_UNMOUNT).c_str ());
	if (is_loop)
		AppendMenuW (menu, MF_STRING | busy, IDM_UNMOUNT, res_str (IDS_MENU_UNMOUNT).c_str ());
	AppendMenuW (menu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (menu, MF_STRING | busy | (can_hex ? 0u : MF_GRAYED), IDM_HEX, res_str (IDS_MENU_HEX).c_str ());
	/* Properties reads only the cached diskent, so it stays available
	   during an extraction (unlike the backend-touching items above).  */
	AppendMenuW (menu, MF_STRING, IDM_PROPS, res_str (IDS_MENU_PROPS).c_str ());
	int cmd = TrackPopupMenu (menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_main, nullptr);
	DestroyMenu (menu);
	if (cmd == IDM_DOKAN_MOUNT && can_dokan)
		do_dokan_mount (d);
	else if (cmd == IDM_HEX && can_hex)
		show_hex ("(" + d.name + ")0+", widen ("(" + d.name + ")"), d.size);
	else if (cmd == IDM_PROPS)
		show_disk_props (d);
	else if (cmd == IDM_DOKAN_UNMOUNT && dm)
		do_dokan_unmount (dm);
	else if (cmd == IDM_UNMOUNT && is_loop)
	{
		backend_task task;
		task.type = backend_task_type::loopback_del;
		task.path = d.name;
		backend_post (std::move (task));
		set_status (IDS_STATUS_UNMOUNTING);
	}
}

/* Tray icon: resident for quick unmounting; the app only exits
   through WM_CLOSE, which warns while dokan mounts are alive.  */

void
tray_add (HWND wnd)
{
	g_tray.cbSize = sizeof (g_tray);
	g_tray.hWnd = wnd;
	g_tray.uID = 1;
	g_tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	g_tray.uCallbackMessage = WM_APP_TRAY;
	g_tray.hIcon = (HICON) LoadImageW (GetModuleHandleW (nullptr),
		MAKEINTRESOURCEW (IDI_APP),
		IMAGE_ICON,
		GetSystemMetrics (SM_CXSMICON),
		GetSystemMetrics (SM_CYSMICON), 0);
	wcscpy_s (g_tray.szTip, res_str (IDS_APP_TITLE).c_str ());
	Shell_NotifyIconW (NIM_ADD, &g_tray);
}

void
show_main_window (void)
{
	ShowWindow (g_main, SW_SHOW);
	if (IsIconic (g_main))
		ShowWindow (g_main, SW_RESTORE);
	SetForegroundWindow (g_main);
}

void
tray_menu (void)
{
	POINT pt;
	GetCursorPos (&pt);

	HMENU menu = CreatePopupMenu ();
	for (size_t i = 0; i < dokanfs_count (); i++)
	{
		dokan_mount *m = dokanfs_get (i);
		wchar_t text[160];
		_snwprintf_s (text, 160, _TRUNCATE, res_str (IDS_FMT_TRAY_UNMOUNT).c_str (),
			dokanfs_letter (m).c_str (), widen (dokanfs_device (m)).c_str ());
		AppendMenuW (menu, MF_STRING, IDM_TRAY_UNMOUNT_BASE + (int) i, text);
	}
	if (dokanfs_count ())
		AppendMenuW (menu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (menu, MF_STRING, IDM_TRAY_OPEN, res_str (IDS_TRAY_OPEN).c_str ());
	AppendMenuW (menu, MF_STRING, IDM_TRAY_EXIT, res_str (IDS_TRAY_EXIT).c_str ());

	/* Required for the menu to close on an outside click.  */
	SetForegroundWindow (g_main);
	int cmd = TrackPopupMenu (menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_main, nullptr);
	DestroyMenu (menu);

	if (cmd == IDM_TRAY_OPEN)
		show_main_window ();
	else if (cmd == IDM_TRAY_EXIT)
		SendMessageW (g_main, WM_CLOSE, 0, 0);
	else if (cmd >= IDM_TRAY_UNMOUNT_BASE)
	{
		dokan_mount *m = dokanfs_get (
			(size_t) (cmd - IDM_TRAY_UNMOUNT_BASE));
		if (m)
			do_dokan_unmount (m);
	}
}

/* Result handling */

void
fill_tree (backend_result *res)
{
	std::map<std::string, HTREEITEM> items;

	g_disks = std::move (res->disks);
	TreeView_DeleteAllItems (g_tree);

	for (size_t i = 0; i < g_disks.size (); i++)
	{
		const backend_diskent &d = g_disks[i];

		std::wstring text = widen (d.name);
		std::wstring extra;
		if (!d.fs.empty ())
			extra = widen (d.fs);
		else if (d.encrypted)
			extra = widen (d.crypto_type);
		if (!d.label.empty ())
		{
			if (!extra.empty ())
				extra += L", ";
			extra += widen (d.label);
		}
		if (d.size != BACKEND_SIZE_UNKNOWN)
		{
			if (!extra.empty ())
				extra += L", ";
			extra += format_size (d.size);
		}
		if (!extra.empty ())
			text += L" [" + extra + L"]";

		/* Partitions hang under their disk: "hd0,gpt2" under
		   "hd0", "hd0,msdos1,bsd1" under "hd0,msdos1".  */
		HTREEITEM parent = TVI_ROOT;
		size_t comma = d.name.find_last_of (',');
		if (comma != std::string::npos)
		{
			auto it = items.find (d.name.substr (0, comma));
			if (it != items.end ())
				parent = it->second;
		}

		TVINSERTSTRUCTW ins = {};
		ins.hParent = parent;
		ins.hInsertAfter = TVI_LAST;
		ins.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE
				| TVIF_SELECTEDIMAGE;
		ins.item.pszText = const_cast<wchar_t *> (text.c_str ());
		ins.item.lParam = (LPARAM) i;
		ins.item.iImage = device_icon (d);
		ins.item.iSelectedImage = ins.item.iImage;
		items[d.name] = TreeView_InsertItem (g_tree, &ins);
	}

	for (const auto &it : items)
		TreeView_Expand (g_tree, it.second, TVE_EXPAND);

	wchar_t text[64];
	swprintf (text, 64, res_str (IDS_FMT_DEVICES).c_str (), (int) g_disks.size ());
	set_status (text);
}

void
fill_list (backend_result *res)
{
	g_path = res->path;
	g_entries = std::move (res->entries);

	g_rows.clear ();
	g_rows.reserve (g_entries.size ());
	for (const backend_dirent &e : g_entries)
	{
		list_row row;
		row.name = widen (e.name);
		if (e.is_symlink)
			row.size = res_str (IDS_SIZE_SYMLINK);
		else if (!e.is_dir)
			row.size = format_size (e.size);
		row.mtime = format_mtime (e.mtime);
		row.image = list_icon (e.name, e.is_dir);
		g_rows.push_back (std::move (row));
	}

	ListView_SetItemCountEx (g_list, (int) g_rows.size (), 0);
	SetWindowTextW (g_address, widen (g_path).c_str ());

	wchar_t text[64];
	swprintf (text, 64, res_str (IDS_FMT_ITEMS).c_str (), (int) g_rows.size ());
	set_status (text);
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
	case backend_task_type::extract:
		if (res->seq != g_seq_extract)
			return;
		g_extracting = false;
		SetWindowTextW (g_btn_extract, res_str (IDS_BTN_EXTRACT).c_str ());
		set_button_icon (g_btn_extract, g_himl_extract);
		EnableWindow (g_btn_up, TRUE);
		ShowWindow (g_progress, SW_HIDE);
		break;
	case backend_task_type::loopback_add:
	case backend_task_type::loopback_del:
		break;
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
		return;
	case backend_task_type::crypto_unlock:
		crypto_unlock_done (res.get ());
		return;
	}

	if (!res->error.empty ())
	{
		if (res->type == backend_task_type::list_dir)
		{
			/* A failed navigation must not keep showing the
			   previous directory's entries.  */
			g_path.clear ();
			g_entries.clear ();
			g_rows.clear ();
			ListView_SetItemCountEx (g_list, 0, 0);
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
		break;
	case backend_task_type::extract:
	{
		wchar_t text[128];
		swprintf (text, 128, res_str (IDS_FMT_EXTRACT_DONE).c_str (),
			res->stat_files, format_size (res->stat_bytes).c_str ());
		set_status (text);
		break;
	}
	case backend_task_type::loopback_add:
	{
		g_mounted.insert (res->path);
		refresh ();
		wchar_t text[128];
		swprintf (text, 128, res_str (IDS_FMT_MOUNTED).c_str (), widen (res->path).c_str ());
		set_status (text);
		break;
	}
	case backend_task_type::loopback_del:
	{
		g_mounted.erase (res->path);
		/* Leave the view if it was on the departed device.  */
		if (g_path.rfind ("(" + res->path + ")", 0) == 0 || g_path.rfind ("(" + res->path + ",", 0) == 0)
		{
			g_path.clear ();
			g_entries.clear ();
			g_rows.clear ();
			ListView_SetItemCountEx (g_list, 0, 0);
			SetWindowTextW (g_address, L"");
		}
		refresh ();
		wchar_t text[128];
		swprintf (text, 128, res_str (IDS_FMT_UNMOUNTED).c_str (), widen (res->path).c_str ());
		set_status (text);
		break;
	}
	}
}

void
on_task_progress (backend_progress *raw)
{
	std::unique_ptr<backend_progress> p (raw);

	/* The properties hash and the crypto unlock own their bars.  */
	if (props_on_progress (p.get ()) || crypto_on_progress (p.get ()))
		return;
	if (!g_extracting || p->seq != g_seq_extract)
		return;
	SendMessageW (g_progress, PBM_SETPOS, (WPARAM) p->percent, 0);

	wchar_t text[512];
	_snwprintf_s (text, 512, _TRUNCATE, res_str (IDS_FMT_EXTRACT_PROG).c_str (),
		p->file_index, p->file_total, widen (p->name).c_str (), p->percent);
	set_status (text);
}

/* Control notifications */

void
on_list_getdispinfo (NMLVDISPINFOW *di)
{
	int item = di->item.iItem;

	if (item < 0 || item >= (int) g_rows.size ())
		return;

	if (di->item.mask & LVIF_IMAGE)
		di->item.iImage = g_rows[(size_t) item].image;
	if (!(di->item.mask & LVIF_TEXT))
		return;

	const list_row &row = g_rows[(size_t) item];
	const std::wstring *text = &row.name;
	if (di->item.iSubItem == 1)
		text = &row.size;
	else if (di->item.iSubItem == 2)
		text = &row.mtime;
	lstrcpynW (di->item.pszText, text->c_str (), di->item.cchTextMax);
}

void
on_list_dblclk (int item)
{
	if (item < 0 || item >= (int) g_entries.size ())
		return;
	const backend_dirent &e = g_entries[(size_t) item];
	if (e.is_dir)
		navigate (join_path (g_path, e.name));
}

void
on_tree_selchanged (NMTREEVIEWW *tv)
{
	/* TVC_UNKNOWN = programmatic (tree rebuild), not the user.  */
	if (tv->action == TVC_UNKNOWN)
		return;
	size_t i = (size_t) tv->itemNew.lParam;
	if (i >= g_disks.size ())
		return;
	/* A locked LUKS/LUKS2 volume has no browsable filesystem yet:
	   prompt for the passphrase/key file instead of listing it.  */
	if (g_disks[i].encrypted)
	{
		prompt_unlock (g_disks[i].name, g_disks[i].crypto_uuid);
		return;
	}
	navigate ("(" + g_disks[i].name + ")/");
}

LRESULT
on_notify (NMHDR *hdr)
{
	if (hdr->hwndFrom == g_list && hdr->code == LVN_GETDISPINFOW)
		on_list_getdispinfo ((NMLVDISPINFOW *) hdr);
	else if (hdr->hwndFrom == g_list && hdr->code == NM_DBLCLK)
		on_list_dblclk (((NMITEMACTIVATE *) hdr)->iItem);
	else if (hdr->hwndFrom == g_list && hdr->code == NM_RCLICK)
		on_list_rclick ((NMITEMACTIVATE *) hdr);
	else if (hdr->hwndFrom == g_tree && hdr->code == NM_RCLICK)
		on_tree_rclick ();
	else if (hdr->hwndFrom == g_tree && hdr->code == TVN_SELCHANGEDW)
		on_tree_selchanged ((NMTREEVIEWW *) hdr);
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
	g_tree = CreateWindowExW (WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
		child | TVS_HASBUTTONS | TVS_SHOWSELALWAYS | TVS_FULLROWSELECT, 0, 0, 0, 0, wnd, nullptr, nullptr, nullptr);
	g_list = CreateWindowExW (WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
		child | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA | LVS_SHAREIMAGELISTS, 0, 0, 0, 0, wnd, nullptr, nullptr, nullptr);
	g_status = CreateWindowExW (0, STATUSCLASSNAMEW, L"",
		child | SBARS_SIZEGRIP, 0, 0, 0, 0, wnd, nullptr, nullptr, nullptr);
	g_progress = CreateWindowExW (0, PROGRESS_CLASSW, L"",
		WS_CHILD, 0, 0, 0, 0, g_status, nullptr, nullptr, nullptr);
	SendMessageW (g_progress, PBM_SETRANGE32, 0, 100);

	SetWindowSubclass (g_address, address_proc, 0, 0);
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

	LVCOLUMNW col = {};
	std::wstring col_name = res_str (IDS_COL_NAME);
	std::wstring col_size = res_str (IDS_COL_SIZE);
	std::wstring col_mtime = res_str (IDS_COL_MODIFIED);
	col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
	col.fmt = LVCFMT_LEFT;
	col.pszText = const_cast<wchar_t *> (col_name.c_str ());
	col.cx = dpi_scale (260);
	ListView_InsertColumn (g_list, 0, &col);
	col.fmt = LVCFMT_RIGHT;
	col.pszText = const_cast<wchar_t *> (col_size.c_str ());
	col.cx = dpi_scale (100);
	ListView_InsertColumn (g_list, 1, &col);
	col.fmt = LVCFMT_LEFT;
	col.pszText = const_cast<wchar_t *> (col_mtime.c_str ());
	col.cx = dpi_scale (140);
	ListView_InsertColumn (g_list, 2, &col);

	set_status (IDS_STATUS_STARTING);
}

/* The menu bar and its submenus are owned by the window and destroyed
   with it.  The Dokan popup starts empty; on_menu_popup fills it.  */
void
create_menu_bar (HWND wnd)
{
	HMENU bar = CreateMenu ();

	g_menu_file = CreatePopupMenu ();
	AppendMenuW (g_menu_file, MF_STRING, IDM_FILE_REFRESH, res_str (IDS_BTN_REFRESH).c_str ());
	AppendMenuW (g_menu_file, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (g_menu_file, MF_STRING, IDM_FILE_EXIT, res_str (IDS_TRAY_EXIT).c_str ());

	HMENU sel = CreatePopupMenu ();
	AppendMenuW (sel, MF_STRING, IDM_SEL_ALL, res_str (IDS_MENU_SEL_ALL).c_str ());
	AppendMenuW (sel, MF_STRING, IDM_SEL_INVERT, res_str (IDS_MENU_SEL_INVERT).c_str ());

	g_menu_dokan = CreatePopupMenu ();

	HMENU help = CreatePopupMenu ();
	AppendMenuW (help, MF_STRING, IDM_HELP_SUPPORT, res_str (IDS_MENU_SUPPORT).c_str ());
	AppendMenuW (help, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (help, MF_STRING, IDM_HELP_ABOUT, res_str (IDS_MENU_ABOUT).c_str ());

	AppendMenuW (bar, MF_POPUP, (UINT_PTR) g_menu_file, res_str (IDS_MENU_FILE).c_str ());
	AppendMenuW (bar, MF_POPUP, (UINT_PTR) sel, res_str (IDS_MENU_SELECTION).c_str ());
	AppendMenuW (bar, MF_POPUP, (UINT_PTR) g_menu_dokan, res_str (IDS_MENU_DOKAN).c_str ());
	AppendMenuW (bar, MF_POPUP, (UINT_PTR) help, res_str (IDS_MENU_HELP).c_str ());
	SetMenu (wnd, bar);
}

void
on_menu_popup (HMENU menu)
{
	if (menu == g_menu_file)
	{
		/* Same rule as the old toolbar button: a refresh would
		   queue behind a running extraction and overwrite the
		   progress line.  */
		EnableMenuItem (menu, IDM_FILE_REFRESH, g_extracting ? MF_GRAYED : MF_ENABLED);
		return;
	}
	if (menu != g_menu_dokan)
		return;

	/* Rebuilt on every open, like the tray menu: one unmount entry
	   per live mount, or a grayed line saying why there is none.  */
	while (GetMenuItemCount (menu) > 0)
		DeleteMenu (menu, 0, MF_BYPOSITION);
	if (!dokanfs_available ())
	{
		/* No driver yet: offer to install the bundled runtime
		   instead of just greying the feature out.  */
		AppendMenuW (menu, MF_STRING, IDM_DOKAN_INSTALL, res_str (IDS_DOKAN_INSTALL).c_str ());
		return;
	}
	if (!dokanfs_count ())
	{
		AppendMenuW (menu, MF_STRING | MF_GRAYED, 0, res_str (IDS_DOKAN_NONE).c_str ());
		return;
	}
	for (size_t i = 0; i < dokanfs_count (); i++)
	{
		dokan_mount *m = dokanfs_get (i);
		wchar_t text[160];
		_snwprintf_s (text, 160, _TRUNCATE, res_str (IDS_FMT_TRAY_UNMOUNT).c_str (),
			dokanfs_letter (m).c_str (), widen (dokanfs_device (m)).c_str ());
		AppendMenuW (menu, MF_STRING, IDM_DOKAN_UNMOUNT_BASE + (int) i, text);
	}
}

void
layout (HWND wnd)
{
	RECT rc;
	const int margin = dpi_scale (MARGIN);
	const int top_bar_h = dpi_scale (TOP_BAR_H);
	const int tree_w = dpi_scale (TREE_W);
	const int btn_w = dpi_scale (BTN_W);
	const int progress_w = dpi_scale (PROGRESS_W);

	GetClientRect (wnd, &rc);
	SendMessageW (g_status, WM_SIZE, 0, 0);

	int parts[2] = { rc.right - progress_w - dpi_scale (20), -1 };
	SendMessageW (g_status, SB_SETPARTS, 2, (LPARAM) parts);
	RECT prc;
	SendMessageW (g_status, SB_GETRECT, 1, (LPARAM) &prc);
	MoveWindow (g_progress,
		prc.left + dpi_scale (2), prc.top + dpi_scale (2),
		prc.right - prc.left - dpi_scale (22),
		prc.bottom - prc.top - dpi_scale (4), TRUE);

	RECT src;
	GetWindowRect (g_status, &src);
	const int status_h = src.bottom - src.top;
	const int body_top = top_bar_h + margin;
	const int body_h = rc.bottom - body_top - status_h;
	const int btn_h = top_bar_h - 2 * margin;

	MoveWindow (g_btn_up, margin, margin, btn_w, btn_h, TRUE);
	MoveWindow (g_address, btn_w + 2 * margin, margin, rc.right - 2 * btn_w - 4 * margin, btn_h, TRUE);
	MoveWindow (g_btn_extract, rc.right - btn_w - margin, margin, btn_w, btn_h, TRUE);
	MoveWindow (g_tree, 0, body_top, tree_w, body_h, TRUE);
	MoveWindow (g_list, tree_w + margin, body_top, rc.right - tree_w - margin, body_h, TRUE);
}

void
on_command (int id)
{
	if (id >= IDM_DOKAN_UNMOUNT_BASE)
	{
		dokan_mount *m = dokanfs_get (
			(size_t) (id - IDM_DOKAN_UNMOUNT_BASE));
		if (m)
			do_dokan_unmount (m);
		return;
	}
	switch (id)
	{
	case IDM_DOKAN_INSTALL:
		do_dokan_install ();
		break;
	case IDM_FILE_REFRESH:
		if (!g_extracting)
			refresh ();
		break;
	case IDM_FILE_EXIT:
		SendMessageW (g_main, WM_CLOSE, 0, 0);
		break;
	case IDM_SEL_ALL:
		ListView_SetItemState (g_list, -1, LVIS_SELECTED, LVIS_SELECTED);
		break;
	case IDM_SEL_INVERT:
		for (int i = 0, n = ListView_GetItemCount (g_list); i < n; i++)
			ListView_SetItemState (g_list, i, ListView_GetItemState (g_list, i, LVIS_SELECTED) ^ LVIS_SELECTED, LVIS_SELECTED);
		break;
	case IDM_HELP_SUPPORT:
		show_support ();
		break;
	case IDM_HELP_ABOUT:
		show_about ();
		break;
	case IDC_UP:
		go_up ();
		break;
	case IDC_EXTRACT:
		on_extract_button ();
		break;
	}
}

LRESULT CALLBACK
main_wnd_proc (HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_CREATE:
		g_main = wnd;
		g_dpi = dpi_for_window (wnd);
		create_children (wnd);
		create_menu_bar (wnd);
		backend_start (wnd);
		dokanfs_init (wnd);
		tray_add (wnd);
		/* Grow the default frame for a high-DPI creation monitor
		   (WM_DPICHANGED takes over once it is on screen).  */
		if (g_dpi != 96)
			SetWindowPos (wnd, nullptr, 0, 0, dpi_scale (DEF_W), dpi_scale (DEF_H), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
		return 0;
	case WM_SIZE:
		layout (wnd);
		return 0;
	case WM_DPICHANGED:
	{
		/* Moved to a monitor with a different scale: rebuild the
		   DPI-sized fonts/icons, carry the columns over, and take the
		   suggested frame (which re-lays-out through WM_SIZE).  */
		UINT prev = g_dpi;
		RECT *sug = (RECT *) lp;

		g_dpi = HIWORD (wp);
		apply_dpi_resources ();
		for (int c = 0; c < 3; c++)
		{
			int w = ListView_GetColumnWidth (g_list, c);
			ListView_SetColumnWidth (g_list, c, MulDiv (w, (int) g_dpi, (int) prev));
		}
		SetWindowPos (wnd, nullptr,
			sug->left, sug->top, sug->right - sug->left, sug->bottom - sug->top,
			SWP_NOZORDER | SWP_NOACTIVATE);
		return 0;
	}
	case WM_COMMAND:
		on_command (LOWORD (wp));
		return 0;
	case WM_INITMENUPOPUP:
		on_menu_popup ((HMENU) wp);
		return 0;
	case WM_NOTIFY:
		return on_notify ((NMHDR *) lp);
	case WM_APP_BACKEND_READY:
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
	case WM_APP_TRAY:
		if (lp == WM_LBUTTONDBLCLK)
			show_main_window ();
		else if (lp == WM_RBUTTONUP)
			tray_menu ();
		return 0;
	case WM_CLOSE:
		/* The tray Exit can arrive while a modal dialog holds
		   the main window disabled; destroying the owner under
		   a modal loop is not survivable.  */
		if (g_props || g_diskprops || g_hex || g_text || g_img || g_crypto
		    || g_about || g_support)
			return 0;
		if (dokanfs_count () > 0)
		{
			if (MessageBoxW (wnd, res_str (IDS_ASK_UNMOUNT_ALL).c_str (), res_str (IDS_APP_TITLE).c_str (),
				MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
				return 0;
			dokanfs_unmount_all ();
		}
		DestroyWindow (wnd);
		return 0;
	case WM_DESTROY:
		Shell_NotifyIconW (NIM_DELETE, &g_tray);
		dokanfs_shutdown ();
		backend_stop ();
		PostQuitMessage (0);
		return 0;
	}
	return DefWindowProcW (wnd, msg, wp, lp);
}

} // namespace

int WINAPI
wWinMain (HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
	CoInitializeEx (nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	init_language ();
	load_dpi_api ();

	INITCOMMONCONTROLSEX icc = { sizeof (icc),
		ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES
		| ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
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
	ShowWindow (wnd, show);
	UpdateWindow (wnd);

	MSG msg;
	while (GetMessageW (&msg, nullptr, 0, 0) > 0)
	{
		TranslateMessage (&msg);
		DispatchMessageW (&msg);
	}
	CoUninitialize ();
	return (int) msg.wParam;
}
