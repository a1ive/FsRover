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

/* File properties dialog: libmagic file type (filled by a file_props
   task as soon as the dialog opens) and a hash calculator (hash_file
   task with progress).  Modal over the main window; results are still
   posted there and routed here while the dialog exists.  */

#include <windows.h>
#include <commctrl.h>

#include <string>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

HWND g_props;	/* modal file properties dialog, null when closed */
HWND g_diskprops;	/* modal disk properties dialog, null when closed */

namespace
{

UINT g_seq_props;	/* pending seq per task; older results */
UINT g_seq_hash;	/* are stale and dropped */
bool g_hashing;	/* hash task posted from the properties dialog */
std::string g_props_path;	/* file the dialog is about, UTF-8 */

/* Snapshot for the disk properties dialog (see show_disk_props).  */
std::string g_dp_name;	/* device name, for the caption */
std::wstring g_dp_text;	/* preformatted "field: value" body */

void
props_enable_hash_controls (HWND dlg, BOOL enabled)
{
	static const int ids[] =
	{
		IDC_PROPS_MD5, IDC_PROPS_SHA1, IDC_PROPS_CRC32,
		IDC_PROPS_CRC64, IDC_PROPS_SHA256, IDC_PROPS_SHA512,
		IDC_PROPS_CALC,
	};

	for (int id : ids)
		EnableWindow (GetDlgItem (dlg, id), enabled);
}

void
props_start_hash (HWND dlg)
{
	/* Checkbox per BACKEND_HASH_* bit, same order.  */
	static const int boxes[BACKEND_HASH_COUNT] =
	{
		IDC_PROPS_MD5, IDC_PROPS_SHA1, IDC_PROPS_CRC32,
		IDC_PROPS_CRC64, IDC_PROPS_SHA256, IDC_PROPS_SHA512,
	};
	UINT mask = 0;

	for (int i = 0; i < BACKEND_HASH_COUNT; i++)
		if (IsDlgButtonChecked (dlg, boxes[i]) == BST_CHECKED)
			mask |= 1u << i;
	if (!mask)
	{
		MessageBoxW (dlg, res_str (IDS_PROPS_SELECT_ONE).c_str (), res_str (IDS_APP_TITLE).c_str (), MB_ICONINFORMATION);
		return;
	}
	if (g_hashing)
		return;

	backend_task task;
	task.type = backend_task_type::hash_file;
	task.path = g_props_path;
	task.hash_mask = mask;
	g_seq_hash = backend_post (std::move (task));
	g_hashing = true;
	SendDlgItemMessageW (dlg, IDC_PROPS_PROGRESS, PBM_SETPOS, 0, 0);
	SetDlgItemTextW (dlg, IDC_PROPS_RESULT, L"");
	SetDlgItemTextW (dlg, IDC_PROPS_STATUS, res_str (IDS_PROPS_CALCULATING).c_str ());
	EnableWindow (GetDlgItem (dlg, IDC_PROPS_COPY), FALSE);
	props_enable_hash_controls (dlg, FALSE);
}

void
props_copy (HWND dlg)
{
	std::wstring text = window_text (GetDlgItem (dlg, IDC_PROPS_RESULT));

	if (!text.empty ())
		clipboard_set_text (dlg, text);
}

INT_PTR CALLBACK
props_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		g_props = dlg;
		/* "name - Properties" so it is clear which file this is.  */
		size_t cut = g_props_path.find_last_of ('/');
		std::wstring name = widen (cut == std::string::npos ? g_props_path : g_props_path.substr (cut + 1));
		SetWindowTextW (dlg, (name + L" - " + window_text (dlg)).c_str ());
		CheckDlgButton (dlg, IDC_PROPS_SHA256, BST_CHECKED);
		SendDlgItemMessageW (dlg, IDC_PROPS_PROGRESS, PBM_SETRANGE32, 0, 100);
		EnableWindow (GetDlgItem (dlg, IDC_PROPS_COPY), FALSE);

		backend_task task;
		task.type = backend_task_type::file_props;
		task.path = g_props_path;
		g_seq_props = backend_post (std::move (task));
		return TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDC_PROPS_CALC:
			props_start_hash (dlg);
			return TRUE;
		case IDC_PROPS_COPY:
			props_copy (dlg);
			return TRUE;
		case IDCANCEL:
			/* Late results are dropped once g_props is null.
			   Only cancel when the hash is actually the running
			   task; never yank a live extraction.  */
			if (g_hashing && !g_extracting)
				backend_cancel ();
			g_hashing = false;
			g_props = nullptr;
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

/* Disk / partition properties: everything is already in the diskent from
   the last enumeration, so the dialog is a plain formatter -- no backend
   task, hence safe to open even while an extraction runs.  */

std::wstring
group_digits (UINT64 v)
{
	std::wstring s = std::to_wstring (v);

	for (int i = (int) s.size () - 3; i > 0; i -= 3)
		s.insert ((size_t) i, L",");
	return s;
}

void
append_field (std::wstring &out, UINT label, const std::wstring &value)
{
	out += res_str (label);
	out += L": ";
	out += value;
	out += L"\r\n";
}

std::wstring
disk_props_text (const backend_diskent &d)
{
	std::wstring out;

	append_field (out, IDS_DP_DEVICE, widen (d.name));

	/* Filesystem: its name, the crypto container type when locked, or a
	   placeholder when nothing recognised the volume.  */
	std::wstring fs;
	if (!d.fs.empty ())
		fs = widen (d.fs);
	else if (d.encrypted)
		fs = widen (d.crypto_type);
	else
		fs = res_str (IDS_DP_UNKNOWN);
	append_field (out, IDS_DP_FS, fs);

	/* UUID: the filesystem's, or the crypto container's when locked.  */
	std::wstring uuid;
	if (!d.fs_uuid.empty ())
		uuid = widen (d.fs_uuid);
	else if (d.encrypted && !d.crypto_uuid.empty ())
		uuid = widen (d.crypto_uuid);
	if (!uuid.empty ())
		append_field (out, IDS_DP_UUID, uuid);

	if (!d.label.empty ())
		append_field (out, IDS_DP_LABEL, widen (d.label));

	if (d.size != BACKEND_SIZE_UNKNOWN)
		append_field (out, IDS_DP_SIZE,
			format_size (d.size) + L" (" + group_digits (d.size) + L" B)");

	/* Start LBA is only meaningful for an actual partition.  */
	if (d.is_partition)
		append_field (out, IDS_DP_LBA, group_digits (d.start_lba));

	if (d.sector_size)
		append_field (out, IDS_DP_SECTOR, std::to_wstring (d.sector_size) + L" B");

	if (!d.parent_file.empty ())
		append_field (out, IDS_DP_PARENT_FILE, widen (d.parent_file));

	/* Diskfilter members arrive one grub device name per line; list each
	   under its own indented row.  */
	if (!d.parents.empty ())
	{
		out += res_str (IDS_DP_PARENTS);
		out += L":\r\n";
		for (size_t pos = 0; pos < d.parents.size (); )
		{
			size_t nl = d.parents.find ('\n', pos);
			if (nl == std::string::npos)
				nl = d.parents.size ();
			out += L"    " + widen (d.parents.substr (pos, nl - pos)) + L"\r\n";
			pos = nl + 1;
		}
	}

	return out;
}

INT_PTR CALLBACK
disk_props_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		g_diskprops = dlg;
		SetWindowTextW (dlg, (widen (g_dp_name) + L" - " + res_str (IDS_MENU_PROPS)).c_str ());
		SetDlgItemTextW (dlg, IDC_DISKPROPS_COPY, res_str (IDS_DP_COPY).c_str ());
		SetDlgItemTextW (dlg, IDC_DISKPROPS_TEXT, g_dp_text.c_str ());
		/* Focus the OK button, not the edit: giving the edit focus would
		   select all its text.  Returning FALSE keeps this focus.  */
		SetFocus (GetDlgItem (dlg, IDOK));
		return FALSE;
	case WM_COMMAND:
		switch (LOWORD (wp))
		{
		case IDC_DISKPROPS_COPY:
			clipboard_set_text (dlg, g_dp_text);
			return TRUE;
		case IDOK:
		case IDCANCEL:
			g_diskprops = nullptr;
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

} // namespace

void
show_props (const std::string &path)
{
	g_props_path = path;
	g_hashing = false;
	DialogBoxParamW (GetModuleHandleW (nullptr),
			 MAKEINTRESOURCEW (IDD_PROPS), g_main,
			 props_dlg_proc, 0);
	g_props = nullptr;
}

/* Disk / partition properties (tree right-click).  The diskent is a
   snapshot: a disk refresh arriving during the modal loop reallocates
   g_disks, so the caller passes a copy, formatted up front here.  */
void
show_disk_props (const backend_diskent &d)
{
	g_dp_name = d.name;
	g_dp_text = disk_props_text (d);
	DialogBoxParamW (GetModuleHandleW (nullptr),
			 MAKEINTRESOURCEW (IDD_DISKPROPS), g_main,
			 disk_props_dlg_proc, 0);
	g_diskprops = nullptr;
}

/* Task results for the dialog; stale or orphaned ones are dropped.  */

void
props_on_type (backend_result *res)
{
	if (!g_props || res->seq != g_seq_props)
		return;
	SetDlgItemTextW (g_props, IDC_PROPS_TYPE, widen (res->error.empty () ? res->text : res->error).c_str ());
}

void
props_on_hash (backend_result *res)
{
	static const wchar_t *names[BACKEND_HASH_COUNT] =
	{
		L"MD5", L"SHA1", L"CRC32", L"CRC64", L"SHA256", L"SHA512",
	};

	if (!g_props || res->seq != g_seq_hash)
		return;
	g_hashing = false;
	props_enable_hash_controls (g_props, TRUE);
	if (!res->error.empty ())
	{
		SetDlgItemTextW (g_props, IDC_PROPS_RESULT, L"");
		SetDlgItemTextW (g_props, IDC_PROPS_STATUS, widen (res->error).c_str ());
		return;
	}

	std::wstring text;
	for (int i = 0; i < BACKEND_HASH_COUNT; i++)
		if (!res->hash[i].empty ())
			text += std::wstring (names[i]) + L"\t" + widen (res->hash[i]) + L"\r\n";
	SetDlgItemTextW (g_props, IDC_PROPS_RESULT, text.c_str ());
	SetDlgItemTextW (g_props, IDC_PROPS_STATUS, res_str (IDS_PROPS_COMPLETE).c_str ());
	SendDlgItemMessageW (g_props, IDC_PROPS_PROGRESS, PBM_SETPOS, 100, 0);
	EnableWindow (GetDlgItem (g_props, IDC_PROPS_COPY), TRUE);
}

/* WM_APP_TASK_PROGRESS routing; true = the update was this dialog's.  */
bool
props_on_progress (backend_progress *p)
{
	if (!g_hashing || !g_props || p->seq != g_seq_hash)
		return false;
	SendDlgItemMessageW (g_props, IDC_PROPS_PROGRESS, PBM_SETPOS, (WPARAM) p->percent, 0);
	return true;
}
