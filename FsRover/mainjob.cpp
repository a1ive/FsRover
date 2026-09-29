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
 * The one long backend job at a time: extracting files or exporting a
 * raw device image.  While it runs the Extract button turns into
 * Cancel and the status bar shows a progress bar.
 */

#include <windows.h>
#include <commctrl.h>
#include <wchar.h>

#include <string>
#include <vector>

#include "filedlg.h"
#include "mainwnd.h"
#include "resource.h"
#include "strconv.h"

/* Shared with the dialog and viewer files through gui.h.  */
bool g_extracting;

namespace mainwnd
{

bool g_preserve_times = true;

namespace
{

/* SHELL32.dll */
constexpr int SH_ICON_CANCEL = 240;
constexpr int SH_ICON_EXTRACT = 241;

UINT g_seq_extract;	/* also the raw image export: one long job at a time */
bool g_export_job;	/* the running job is an export, not an extraction */
HIMAGELIST g_himl_extract;	/* Extract button icon */
HIMAGELIST g_himl_cancel;	/* same button while extracting */

/* Claim the long-job slot for the task just posted: the Extract button
   turns into Cancel and the status bar grows a progress bar.  */
void
begin_job (UINT seq, bool is_export, UINT status_id)
{
	g_seq_extract = seq;
	g_extracting = true;
	g_export_job = is_export;
	SetWindowTextW (g_btn_extract, res_str (IDS_BTN_CANCEL).c_str ());
	set_button_icon (g_btn_extract, g_himl_cancel);
	/* Refresh (File menu, grayed in on_menu_popup) and the navigation
	   buttons would only queue list tasks behind the running job
	   and overwrite the progress line; the context menus gray their
	   backend items for the same reason.  */
	update_nav_buttons ();
	SendMessageW (g_progress, PBM_SETPOS, 0, 0);
	ShowWindow (g_progress, SW_SHOW);
	set_status (status_id);
}

/* "lvm/vg-root" -> "lvm_vg-root.img": a device name goes straight into
   a file name, so the path separators and the other characters Win32
   reserves cannot survive.  */
std::wstring
image_default_name (const std::string &device)
{
	std::wstring out = widen (device);

	for (wchar_t &c : out)
		if (c < 32 || wcschr (L"<>:\"/\\|?*", c))
			c = L'_';
	return out + L".img";
}

} // namespace

/* Button icons; the button keeps its current icon if the shell has no
   replacement at this size rather than being blanked.  The
   Back/Forward/Up buttons carry a glyph from the string table instead.  */
void
job_apply_dpi (int sm)
{
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

void
start_extract (std::vector<std::string> &&paths)
{
	if (g_extracting || paths.empty ())
		return;
	std::wstring dest = pick_folder (g_main);
	if (dest.empty ())
		return;

	extract_task task { std::move (paths), std::move (dest), g_preserve_times };
	begin_job (backend_post (std::move (task)), false, IDS_STATUS_EXTRACTING);
}

/* Raw image export.  It shares the extract job slot (progress bar and
   Cancel button); only one long backend job runs at a time.  */
void
start_export (const backend_diskent &d)
{
	if (g_extracting)
		return;
	std::wstring dest = pick_image_file (g_main, image_default_name (d.name));
	if (dest.empty ())
		return;

	export_image_task task { d.name, std::move (dest) };
	/* The device size the tree already knows: on a partition it is
	   what bounds the copy, the blocklist alone would not.  */
	task.limit = d.size;
	begin_job (backend_post (std::move (task)), true, IDS_STATUS_EXPORTING);
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

bool
job_finish (backend_result *res)
{
	if (res->seq != g_seq_extract)
		return false;
	g_extracting = false;
	g_export_job = false;
	SetWindowTextW (g_btn_extract, res_str (IDS_BTN_EXTRACT).c_str ());
	set_button_icon (g_btn_extract, g_himl_extract);
	update_nav_buttons ();
	ShowWindow (g_progress, SW_HIDE);
	return true;
}

/* Status line for a job that completed without an error.  */
void
job_report (backend_result *res)
{
	if (res->type == backend_task_type::export_image)
	{
		wchar_t text[192];
		swprintf (text, 192, res_str (IDS_FMT_EXPORT_DONE).c_str (),
			widen (res->path).c_str (), format_size (res->stat_bytes).c_str ());
		set_status (text);
		return;
	}

	wchar_t text[512];
	int n = swprintf (text, 512, res_str (IDS_FMT_EXTRACT_DONE).c_str (),
		res->stat_files, format_size (res->stat_bytes).c_str ());
	/* Symlinks are never extracted; say so instead of letting
	   the file count silently come up short.  */
	if (res->stat_links && n > 0 && n < 512)
	{
		int added = swprintf (text + n, (size_t) (512 - n),
			res_str (IDS_FMT_EXTRACT_LINKS).c_str (), res->stat_links);
		if (added > 0)
			n += added;
	}
	if (res->stat_errors && n > 0 && n < 512)
		swprintf (text + n, (size_t) (512 - n),
			res_str (IDS_FMT_EXTRACT_ERRORS).c_str (), res->stat_errors,
			widen (res->extract_error).c_str ());
	set_status (text);
}

void
job_on_progress (backend_progress *p)
{
	if (!g_extracting || p->seq != g_seq_extract)
		return;
	SendMessageW (g_progress, PBM_SETPOS, (WPARAM) p->percent, 0);

	wchar_t text[512];
	if (g_export_job)
		_snwprintf_s (text, 512, _TRUNCATE, res_str (IDS_FMT_EXPORT_PROG).c_str (),
			widen (p->name).c_str (), p->percent);
	else
		_snwprintf_s (text, 512, _TRUNCATE, res_str (IDS_FMT_EXTRACT_PROG).c_str (),
			p->file_index, p->file_total, widen (p->name).c_str (), p->percent);
	set_status (text);
}

} // namespace mainwnd
