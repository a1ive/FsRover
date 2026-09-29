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
 * The file list: a virtual ListView over the last successful listing,
 * sizes filled in lazily around the visible rows, and its context menu.
 */

#include <windows.h>
#include <commctrl.h>
#include <commoncontrols.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wchar.h>
#include <wctype.h>

#include <map>
#include <string>
#include <vector>

#include "mainwnd.h"
#include "resource.h"
#include "strconv.h"

namespace mainwnd
{

std::string g_path;
UINT g_seq_sizes;

namespace
{

/* Current view; owned by the GUI thread, replaced from task results.  */
struct list_row
{
	std::wstring name;
	std::wstring size;
	std::wstring mtime;
	int image = -1;	/* DPI-sized list image index, -1 if none */
};

std::vector<backend_dirent> g_entries;
std::vector<list_row> g_rows;	/* display strings for the virtual list */
std::map<std::wstring, int> g_icon_cache;	/* list_icon() memo, by key */
UINT g_view_seq;	/* list_dir seq currently represented by g_entries */

constexpr size_t LIST_SIZE_BATCH = 64;
constexpr int LIST_SIZE_WINDOW = 192;
std::vector<bool> g_size_pending;	/* parallel to g_entries */
std::vector<size_t> g_size_rows;	/* rows owned by g_seq_sizes */
int g_size_want_first;
int g_size_want_last = -1;

/* The file list uses per-extension shell icons copied into a DPI-sized
   image list; indexes come from list_icon() below, not a fixed order.  */
HIMAGELIST g_list_iml;	/* DPI-sized file/folder icons */
IImageList *g_shell_iml;	/* source shell icons at the nearest larger size */

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
	std::wstring key = is_dir ? L"\x01" L"dir" : L"\x01" L"file";
	std::wstring lookup_name = is_dir ? L"folder" : L"file";

	if (!is_dir)
	{
		size_t dot = name.rfind ('.');
		if (dot != std::string::npos)
		{
			key = widen (name.substr (dot));
			for (wchar_t &c : key)
				c = (wchar_t) towlower (c);
			lookup_name += key;
		}
	}

	auto it = g_icon_cache.find (key);
	if (it != g_icon_cache.end ())
		return it->second;

	SHFILEINFOW sfi = {};
	DWORD attr = is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
	/* Never pass the image entry name to the shell: names such as "M:"
	   retain drive-path semantics even with SHGFI_USEFILEATTRIBUTES and can
	   poison the shared directory icon cache with a disk icon.  The cache key
	   contains all the type information needed for a synthetic lookup name.  */
	int idx = -1;
	int icon_w = 16;
	int icon_h = 16;
	ImageList_GetIconSize (g_list_iml, &icon_w, &icon_h);
	if (SHGetFileInfoW (lookup_name.c_str (), attr, &sfi, sizeof (sfi), SHGFI_SYSICONINDEX | SHGFI_USEFILEATTRIBUTES))
	{
		HICON icon = nullptr;
		if (g_shell_iml)
			g_shell_iml->GetIcon (sfi.iIcon, ILD_TRANSPARENT, &icon);
		if (!icon && SHGetFileInfoW (lookup_name.c_str (), attr, &sfi, sizeof (sfi),
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
	if (file_item >= 0 && is_markdown_name (g_entries[(size_t) file_item].name))
		AppendMenuW (menu, MF_STRING | busy, IDM_MARKDOWN, res_str (IDS_MENU_MARKDOWN).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (file_item >= 0 ? 0u : MF_GRAYED), IDM_TEXT, res_str (IDS_MENU_TEXT).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (file_item >= 0 ? 0u : MF_GRAYED), IDM_HEX, res_str (IDS_MENU_HEX).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (file_item >= 0 ? 0u : MF_GRAYED), IDM_FILE_MAP, res_str (IDS_MAP_TITLE).c_str ());
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
		loopback_add_task task;
		task.path = join_path (g_path, g_entries[(size_t) file_item].name);
		task.decompress = (cmd == IDM_MOUNT_DECOMP);
		backend_post (std::move (task));
		set_status (IDS_STATUS_MOUNTING);
	}
	else if (cmd == IDM_IMAGE && file_item >= 0)
		show_image (join_path (g_path, g_entries[(size_t) file_item].name));
	else if (cmd == IDM_MARKDOWN && file_item >= 0)
		show_markdown (join_path (g_path, g_entries[(size_t) file_item].name));
	else if (cmd == IDM_TEXT && file_item >= 0)
		show_text (join_path (g_path, g_entries[(size_t) file_item].name));
	else if (cmd == IDM_HEX && file_item >= 0)
		show_hex (join_path (g_path, g_entries[(size_t) file_item].name));
	else if (cmd == IDM_FILE_MAP && file_item >= 0)
		show_file_map (join_path (g_path, g_entries[(size_t) file_item].name));
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

void
queue_list_sizes (int first, int last)
{
	if (g_view_seq != g_seq_list || g_entries.empty ())
		return;
	if (first < 0)
		first = 0;
	if (last >= (int) g_entries.size ())
		last = (int) g_entries.size () - 1;
	if (first > last)
		return;

	/* A newer cache hint replaces the desired neighborhood.  The
	   in-flight batch is deliberately small; when it finishes we fill
	   the newest neighborhood rather than queueing scroll history.  */
	g_size_want_first = first;
	g_size_want_last = last;
	if (g_seq_sizes)
		return;

	list_sizes_task task;
	std::vector<size_t> rows;
	task.path = g_path;
	task.owner_seq = g_view_seq;
	task.paths.reserve (LIST_SIZE_BATCH);
	rows.reserve (LIST_SIZE_BATCH);
	for (int i = first; i <= last && rows.size () < LIST_SIZE_BATCH; i++)
	{
		const backend_dirent &e = g_entries[(size_t) i];
		if (e.is_dir || e.is_symlink || e.size_set || g_size_pending[(size_t) i])
			continue;
		g_size_pending[(size_t) i] = true;
		task.paths.push_back (e.name);
		rows.push_back ((size_t) i);
	}
	if (rows.empty ())
		return;

	g_size_rows = std::move (rows);
	g_seq_sizes = backend_post (std::move (task));
}

void
hint_list_sizes (int from, int to)
{
	if (from < 0 || to < from || g_entries.empty ())
		return;
	int page = ListView_GetCountPerPage (g_list);
	if (page < 1)
		page = 32;
	int span = to - from + 1;
	int first = from - page;
	int last = to + page;
	if (span >= LIST_SIZE_WINDOW)
	{
		first = from;
		last = from + LIST_SIZE_WINDOW - 1;
	}
	else if (last - first + 1 > LIST_SIZE_WINDOW)
	{
		int extra = LIST_SIZE_WINDOW - span;
		first = from - extra / 2;
		last = to + extra - extra / 2;
	}
	if (first < 0)
	{
		last -= first;
		first = 0;
	}
	if (last >= (int) g_entries.size ())
	{
		int over = last - (int) g_entries.size () + 1;
		last = (int) g_entries.size () - 1;
		first = first > over ? first - over : 0;
	}
	queue_list_sizes (first, last);
}

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
on_list_cache_hint (NMLVCACHEHINT *hint)
{
	hint_list_sizes (hint->iFrom, hint->iTo);
}

int
on_list_finditem (NMLVFINDITEMW *find)
{
	const LVFINDINFOW &fi = find->lvfi;
	if ((fi.flags & (LVFI_PARAM | LVFI_NEARESTXY))
		|| !(fi.flags & (LVFI_STRING | LVFI_PARTIAL | LVFI_SUBSTRING | LVFI_WRAP))
		|| !fi.psz || !*fi.psz || g_rows.empty ())
		return -1;

	const int count = (int) g_rows.size ();
	const bool wrap = (fi.flags & LVFI_WRAP) != 0;
	const bool partial = (fi.flags & (LVFI_PARTIAL | LVFI_SUBSTRING)) != 0;
	const int length = lstrlenW (fi.psz);
	/* The notification's iStart is inclusive (unlike LVM_FINDITEM). */
	int item = find->iStart < 0 ? 0 : find->iStart;
	if (item >= count)
	{
		if (!wrap)
			return -1;
		item = 0;
	}
	const int limit = wrap ? count : count - item;
	for (int n = 0; n < limit; n++)
	{
		const std::wstring &name = g_rows[(size_t) item].name;
		if (name.size () >= (size_t) length
			&& (partial || name.size () == (size_t) length)
			&& CompareStringOrdinal (name.c_str (), length, fi.psz, length, TRUE) == CSTR_EQUAL)
			return item;
		if (++item == count)
			item = 0;
	}
	return -1;
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

} // namespace

/* File/folder icons.  SHGFI_SMALLICON is fixed at 16 physical pixels
   in a per-monitor-aware process, so copy the same shell indexes from
   the nearest larger system list into an image list sized for this
   monitor.  Rebuilding also updates the ListView row height.  */
void
list_apply_dpi (int sm)
{
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
}

LRESULT
list_on_notify (NMHDR *hdr)
{
	switch (hdr->code)
	{
	case LVN_GETDISPINFOW:
		on_list_getdispinfo ((NMLVDISPINFOW *) hdr);
		break;
	case LVN_ODCACHEHINT:
		on_list_cache_hint ((NMLVCACHEHINT *) hdr);
		break;
	case LVN_ODFINDITEMW:
		return on_list_finditem ((NMLVFINDITEMW *) hdr);
	case NM_DBLCLK:
		on_list_dblclk (((NMITEMACTIVATE *) hdr)->iItem);
		break;
	case NM_RCLICK:
		on_list_rclick ((NMITEMACTIVATE *) hdr);
		break;
	}
	return 0;
}

/* Show nothing.  A failed listing, a departed device or a new file
   name encoding must not keep the previous entries on screen.  */
void
list_clear (void)
{
	g_path.clear ();
	g_view_seq = 0;
	g_entries.clear ();
	g_rows.clear ();
	ListView_SetItemCountEx (g_list, 0, 0);
}

/* A navigation is under way: sizes still coming for the old view
   belong to nobody.  */
void
list_drop_sizes (void)
{
	g_seq_sizes = 0;
	g_size_pending.clear ();
	g_size_rows.clear ();
	g_size_want_last = -1;
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
fill_list_sizes (backend_result *res)
{
	int redraw_first = (int) g_entries.size ();
	int redraw_last = -1;
	size_t got = res->sizes.size () < g_size_rows.size ()
		? res->sizes.size () : g_size_rows.size ();

	for (size_t row : g_size_rows)
		if (row < g_size_pending.size ())
			g_size_pending[row] = false;
	for (size_t i = 0; i < got; i++)
	{
		size_t row = g_size_rows[i];
		if (row >= g_entries.size () || row >= g_rows.size ())
			continue;
		g_entries[row].size = res->sizes[i];
		g_entries[row].size_set = true;
		g_rows[row].size = format_size (res->sizes[i]);
		if ((int) row < redraw_first)
			redraw_first = (int) row;
		if ((int) row > redraw_last)
			redraw_last = (int) row;
	}

	g_size_rows.clear ();
	g_seq_sizes = 0;
	if (redraw_last >= redraw_first)
		ListView_RedrawItems (g_list, redraw_first, redraw_last);
	if (g_size_want_last >= g_size_want_first)
		queue_list_sizes (g_size_want_first, g_size_want_last);
}

void
fill_list (backend_result *res)
{
	g_path = res->path;
	g_entries = std::move (res->entries);
	g_view_seq = res->seq;
	g_seq_sizes = 0;
	g_size_pending.assign (g_entries.size (), false);
	g_size_rows.clear ();
	g_size_want_first = 0;
	g_size_want_last = -1;

	g_rows.clear ();
	g_rows.reserve (g_entries.size ());
	for (const backend_dirent &e : g_entries)
	{
		list_row row;
		row.name = widen (e.name);
		if (e.is_symlink)
			row.size = res_str (IDS_SIZE_SYMLINK);
		else if (!e.is_dir && e.size_set)
			row.size = format_size (e.size);
		row.mtime = format_mtime (e.mtime);
		row.image = list_icon (e.name, e.is_dir);
		g_rows.push_back (std::move (row));
	}

	ListView_SetItemCountEx (g_list, (int) g_rows.size (), 0);
	int top = ListView_GetTopIndex (g_list);
	int per_page = ListView_GetCountPerPage (g_list);
	hint_list_sizes (top, top + (per_page > 0 ? per_page : 1) - 1);
	SetWindowTextW (g_address, widen (g_path).c_str ());

	wchar_t text[64];
	swprintf (text, 64, res_str (IDS_FMT_ITEMS).c_str (), (int) g_rows.size ());
	set_status (text);
}

} // namespace mainwnd
