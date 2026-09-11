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

#include <shlobj.h>

#include "filedlg.h"
#include "gui.h"
#include "resource.h"

#pragma comment (lib, "ole32.lib")

std::wstring
pick_folder (HWND owner)
{
	IFileDialog *dlg = nullptr;
	IShellItem *item = nullptr;
	wchar_t *path = nullptr;
	FILEOPENDIALOGOPTIONS opts = 0;
	std::wstring out;
	std::wstring title = res_str (IDS_PICK_FOLDER);

	if (FAILED (CoCreateInstance (CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS (&dlg))))
		return {};
	if (FAILED (dlg->GetOptions (&opts))
		|| FAILED (dlg->SetOptions (opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST))
		|| FAILED (dlg->SetTitle (title.c_str ()))
		|| FAILED (dlg->Show (owner))
		|| FAILED (dlg->GetResult (&item))
		|| FAILED (item->GetDisplayName (SIGDN_FILESYSPATH, &path)))
		goto fail;

	out = path;
	CoTaskMemFree (path);
fail:
	if (item)
		item->Release ();
	dlg->Release ();
	return out;
}

/* Save dialog for the raw image export.  DEFNAME seeds the name; the
   ".img" extension is appended when the user types none.  */
std::wstring
pick_image_file (HWND owner, const std::wstring &defname)
{
	IFileSaveDialog *dlg = nullptr;
	IShellItem *item = nullptr;
	wchar_t *path = nullptr;
	FILEOPENDIALOGOPTIONS opts = 0;
	std::wstring out;
	std::wstring title = res_str (IDS_PICK_IMAGE);
	std::wstring filter = res_str (IDS_FILTER_IMAGE);
	COMDLG_FILTERSPEC types[] = { { filter.c_str (), L"*.img" } };

	if (FAILED (CoCreateInstance (CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS (&dlg))))
		return {};
	if (FAILED (dlg->GetOptions (&opts))
		|| FAILED (dlg->SetOptions (opts | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT | FOS_PATHMUSTEXIST))
		|| FAILED (dlg->SetTitle (title.c_str ()))
		|| FAILED (dlg->SetFileTypes (ARRAYSIZE (types), types))
		|| FAILED (dlg->SetDefaultExtension (L"img"))
		|| FAILED (dlg->SetFileName (defname.c_str ()))
		|| FAILED (dlg->Show (owner))
		|| FAILED (dlg->GetResult (&item))
		|| FAILED (item->GetDisplayName (SIGDN_FILESYSPATH, &path)))
		goto fail;

	out = path;
	CoTaskMemFree (path);
fail:
	if (item)
		item->Release ();
	dlg->Release ();
	return out;
}

/* Open dialog for the File menu's "open image": any Windows file can be mounted.  */
std::wstring
pick_open_image (HWND owner)
{
	IFileOpenDialog *dlg = nullptr;
	IShellItem *item = nullptr;
	wchar_t *path = nullptr;
	FILEOPENDIALOGOPTIONS opts = 0;
	std::wstring out;
	std::wstring title = res_str (IDS_PICK_OPEN_IMAGE);
	std::wstring filter = res_str (IDS_FILTER_OPEN_IMAGE);
	std::wstring filter_all = res_str (IDS_FILTER_ALL);
	COMDLG_FILTERSPEC types[] =
	{
		{ filter.c_str (), L"*.img;*.ima;*.iso;*.vhd;*.vhdx;*.vdi;*.qcow;*.qcow2;*.vmdk;*.dmg;"
				   L"*.cue;*.toc;*.nrg;*.ccd;*.mds;*.cdr" },
		{ filter_all.c_str (), L"*.*" },
	};

	if (FAILED (CoCreateInstance (CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS (&dlg))))
		return {};
	if (FAILED (dlg->GetOptions (&opts))
		|| FAILED (dlg->SetOptions (opts | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST))
		|| FAILED (dlg->SetTitle (title.c_str ()))
		|| FAILED (dlg->SetFileTypes (ARRAYSIZE (types), types))
		|| FAILED (dlg->Show (owner))
		|| FAILED (dlg->GetResult (&item))
		|| FAILED (item->GetDisplayName (SIGDN_FILESYSPATH, &path)))
		goto fail;

	out = path;
	CoTaskMemFree (path);
fail:
	if (item)
		item->Release ();
	dlg->Release ();
	return out;
}

