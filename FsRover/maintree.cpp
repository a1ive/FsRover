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
 * The device tree: every disk, partition and virtual device the backend
 * enumerated, its context menu, and the loopback devices we created.
 */

#include <windows.h>
#include <commctrl.h>
#include <wchar.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "dokanfs.h"
#include "mainwnd.h"
#include "resource.h"
#include "strconv.h"

namespace mainwnd
{

namespace
{

/* imageres.dll */
constexpr int IR_ICON_FLOPPY = 28;
constexpr int IR_ICON_CD = 30;
constexpr int IR_ICON_DISK = 32;
constexpr int IR_ICON_CHIP = 34;
constexpr int IR_ICON_WINFILE = 67;
constexpr int IR_ICON_BACK = 148;
constexpr int IR_ICON_ZIP = 174;
constexpr int IR_ICON_LOCK = 1031;
constexpr int IR_ICON_UNLOCK = 1030;

/* Tree image list order, and the imageres.dll icon each index holds.  */
constexpr int IMG_DISK = 0;
constexpr int IMG_FLOPPY = 1;
constexpr int IMG_CD = 2;
constexpr int IMG_LOOP = 3;
constexpr int IMG_LVM = 4;
constexpr int IMG_FW = 5;
constexpr int IMG_LOCK = 6;
constexpr int IMG_UNLOCK = 7;
constexpr int IMG_WINFILE = 8;
constexpr int TREE_ICON_IDS[] =
	{ IR_ICON_DISK, IR_ICON_FLOPPY, IR_ICON_CD, IR_ICON_ZIP,
	  IR_ICON_BACK, IR_ICON_CHIP, IR_ICON_LOCK, IR_ICON_UNLOCK,
	  IR_ICON_WINFILE };

std::vector<backend_diskent> g_disks;
std::set<std::string> g_mounted;	/* loopback devices we created */
HIMAGELIST g_tree_iml;	/* tree device-icon image list */

int
device_icon (const backend_diskent &d)
{
	if (d.encrypted)
		return IMG_LOCK;
	switch (d.dev_id)
	{
	case BACKEND_DEV_LOOPBACK:
	case BACKEND_DEV_LOST:
		return IMG_LOOP;
	case BACKEND_DEV_DISKFILTER:
		return IMG_LVM;
	case BACKEND_DEV_PROCFS:
		return IMG_FW;
	case BACKEND_DEV_CRYPTODISK:
		return IMG_UNLOCK;
	case BACKEND_DEV_WINFILE:
		return IMG_WINFILE;
	}
	if (d.name.rfind ("cd", 0) == 0)
		return IMG_CD;
	if (d.name.rfind ("fd", 0) == 0)
		return IMG_FLOPPY;
	return IMG_DISK;
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

	/* Drive mounting needs a recognized filesystem on the device and
	   either WinFsp or Dokan; otherwise the item is grey.  It stays
	   usable during an extraction (backend_call jumps
	   the task queue), but loopback unmount and the hex viewer
	   would queue behind it -- and the unmount could even pull the
	   device the extraction is reading from -- so they gray.  */
	dokan_mount *dm = dokanfs_find_device (d.name);
	bool can_dokan = dokanfs_available () && !d.fs.empty () && !dm;
	bool is_loop = g_mounted.count (d.name) != 0;
	/* Both raw reads (hex view, image export) go through the "0+"
	   blocklist, which spans the whole device, so they need a known
	   device size; pseudo-devices report none.  */
	bool can_raw = d.size != BACKEND_SIZE_UNKNOWN;
	/* A VeraCrypt volume needs at least its two header slots plus some
	   data, and unlocking one that is itself an unlocked volume is not
	   something the backend supports.  */
	bool can_vc = can_raw && d.size >= 256 * 1024
		&& d.dev_id != BACKEND_DEV_CRYPTODISK;
	bool can_pm = can_raw && d.dev_id != BACKEND_DEV_CRYPTODISK;
	/* The lost partition search reads raw sectors as well.  */
	bool can_lost = can_raw && d.dev_id != BACKEND_DEV_PROCFS;
#if FSROVER_ENABLE_ADMIN_FEATURES
	/* S.M.A.R.T. belongs to a drive, not to a volume: only a whole
	   windisk "hdN" has a \\.\PhysicalDriveN behind it to ask.  The
	   optical drives ("cdN") and everything mapped or imaged are out,
	   and the item is left off their menus entirely.  */
	bool is_drive = d.dev_id == BACKEND_DEV_WINDISK && !d.is_partition
		&& d.name.compare (0, 2, "hd") == 0;
#endif

	UINT busy = g_extracting ? MF_GRAYED : 0u;

	HMENU menu = CreatePopupMenu ();
	AppendMenuW (menu, MF_STRING | (can_dokan ? 0u : MF_GRAYED), IDM_DOKAN_MOUNT, res_str (IDS_MENU_DOKAN_MOUNT).c_str ());
	if (dm)
		AppendMenuW (menu, MF_STRING, IDM_DOKAN_UNMOUNT, res_str (IDS_MENU_DOKAN_UNMOUNT).c_str ());
	if (is_loop)
		AppendMenuW (menu, MF_STRING | busy, IDM_UNMOUNT, res_str (IDS_MENU_UNMOUNT).c_str ());
	AppendMenuW (menu, MF_SEPARATOR, 0, nullptr);
	/* VeraCrypt volumes are not detectable, so the item is offered on any
	   device with a known size that is not already an unlocked one.  */
	AppendMenuW (menu, MF_STRING | busy | (can_vc ? 0u : MF_GRAYED), IDM_VERACRYPT, res_str (IDS_MENU_VERACRYPT).c_str ());
	/* Plain dm-crypt has no header at all, so the same applies -- except
	   that it needs no room for headers, only a device.  */
	AppendMenuW (menu, MF_STRING | busy | (can_pm ? 0u : MF_GRAYED), IDM_PLAINMOUNT, res_str (IDS_MENU_PLAINMOUNT).c_str ());
	AppendMenuW (menu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW (menu, MF_STRING | busy | (can_raw ? 0u : MF_GRAYED), IDM_HEX, res_str (IDS_MENU_HEX).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (can_raw ? 0u : MF_GRAYED), IDM_EXPORT, res_str (IDS_MENU_EXPORT).c_str ());
	AppendMenuW (menu, MF_STRING | busy | (can_lost ? 0u : MF_GRAYED), IDM_LOST_SCAN, res_str (IDS_LOST_MENU).c_str ());
#if FSROVER_ENABLE_ADMIN_FEATURES
	/* Neither S.M.A.R.T. nor Properties goes through the backend --
	   one is libcdi's own I/O, the other reads the cached diskent --
	   so both stay available during an extraction.  */
	if (is_drive)
		AppendMenuW (menu, MF_STRING | (smart_available () ? 0u : MF_GRAYED), IDM_SMART, res_str (IDS_MENU_SMART).c_str ());
#endif

	AppendMenuW (menu, MF_STRING, IDM_PROPS, res_str (IDS_MENU_PROPS).c_str ());
	int cmd = TrackPopupMenu (menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_main, nullptr);
	DestroyMenu (menu);
	/* TrackPopupMenu never returns a grayed or absent item, so the
	   guards below only restate what the menu already enforces.  */
	switch (cmd)
	{
	case IDM_DOKAN_MOUNT:
		if (can_dokan)
			do_dokan_mount (d);
		break;
	case IDM_DOKAN_UNMOUNT:
		if (dm)
			do_dokan_unmount (dm);
		break;
	case IDM_UNMOUNT:
		if (is_loop)
		{
			if (d.dev_id == BACKEND_DEV_WINFILE)
				backend_post (winfile_del_task { d.name });
			else if (d.dev_id == BACKEND_DEV_LOST)
				backend_post (lost_del_task { d.name });
			else
				backend_post (loopback_del_task { d.name });
			set_status (IDS_STATUS_UNMOUNTING);
		}
		break;
	case IDM_VERACRYPT:
		if (can_vc)
			prompt_unlock_veracrypt (d.name);
		break;
	case IDM_PLAINMOUNT:
		if (can_pm)
			prompt_plainmount (d.name);
		break;
	case IDM_HEX:
		if (can_raw)
			show_hex ("(" + d.name + ")0+", widen ("(" + d.name + ")"), d.size);
		break;
	case IDM_EXPORT:
		if (can_raw)
			start_export (d);
		break;
	case IDM_LOST_SCAN:
		if (can_lost)
			show_lost_scan (d);
		break;
#if FSROVER_ENABLE_ADMIN_FEATURES
	case IDM_SMART:
		if (is_drive)
			show_smart (d);
		break;
#endif

	case IDM_PROPS:
		show_disk_props (d, g_disks);
		break;
	}
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

} // namespace

/* Tree device icons.  */
void
tree_apply_dpi (int sm)
{
	HIMAGELIST tree_iml = icon_list (L"\\imageres.dll", TREE_ICON_IDS,
					 ARRAYSIZE (TREE_ICON_IDS), sm);
	TreeView_SetImageList (g_tree, tree_iml, TVSIL_NORMAL);
	if (g_tree_iml)
		ImageList_Destroy (g_tree_iml);
	g_tree_iml = tree_iml;
}

LRESULT
tree_on_notify (NMHDR *hdr)
{
	if (hdr->code == NM_RCLICK)
		on_tree_rclick ();
	else if (hdr->code == TVN_SELCHANGEDW)
		on_tree_selchanged ((NMTREEVIEWW *) hdr);
	return 0;
}

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
		ins.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
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
tree_on_mounted (backend_result *res)
{
	g_mounted.insert (res->path);
	refresh ();
	wchar_t text[128];
	swprintf (text, 128, res_str (IDS_FMT_MOUNTED).c_str (), widen (res->path).c_str ());
	set_status (text);
}

void
tree_on_unmounted (backend_result *res)
{
	g_mounted.erase (res->path);
	/* Leave the view if it was on the departed device.  */
	if (g_path.rfind ("(" + res->path + ")", 0) == 0 || g_path.rfind ("(" + res->path + ",", 0) == 0)
	{
		list_clear ();
		SetWindowTextW (g_address, L"");
	}
	refresh ();
	wchar_t text[128];
	swprintf (text, 128, res_str (IDS_FMT_UNMOUNTED).c_str (), widen (res->path).c_str ());
	set_status (text);
}

} // namespace mainwnd

/* Same icon the tree shows for a device, as an imageres.dll id, for the
   dialogs that want one icon instead of the tree image list.  */
int
device_icon_id (const backend_diskent &d)
{
	return mainwnd::TREE_ICON_IDS[mainwnd::device_icon (d)];
}
