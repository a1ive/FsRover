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
 * Navigation: every view change goes through a list_dir task; the
 * address bar and g_path are updated from the result, so the UI
 * always reflects what was actually listed.  Also Back/Forward/Up and
 * the file name encoding the listed paths were decoded with.
 */

#include <windows.h>
#include <commctrl.h>

#include <string>
#include <vector>

#include "dokanfs.h"
#include "mainwnd.h"
#include "resource.h"
#include "strconv.h"

namespace mainwnd
{

UINT g_seq_disks;
UINT g_seq_list;
UINT g_fs_encoding = BACKEND_FS_ENCODING_UTF8;

namespace
{

/* Back/Forward, Explorer style: the visited paths in order with a
   cursor on the current one.  Only a listing that succeeded is
   recorded (fill_list), so the history never points at a path that
   could not be read.  */
constexpr size_t HIST_MAX = 10;
std::vector<std::string> g_hist;	/* oldest first */
int g_hist_pos = -1;	/* index of the current path, -1 = empty */
UINT g_hist_seq;	/* list_dir seq posted by Back/Forward, 0 = none */

/* Called for every listing that came back without an error.  A Back or
   Forward only moves the cursor (it already did); anything else drops
   whatever was ahead of the cursor and appends.  */
void
hist_record (UINT seq)
{
	if (seq == g_hist_seq)
	{
		g_hist_seq = 0;
		return;
	}
	/* Refresh, or navigating to where we already are.  */
	if (g_hist_pos >= 0 && g_hist[(size_t) g_hist_pos] == g_path)
		return;
	g_hist.erase (g_hist.begin () + (g_hist_pos + 1), g_hist.end ());
	g_hist.push_back (g_path);
	if (g_hist.size () > HIST_MAX)
		g_hist.erase (g_hist.begin ());
	g_hist_pos = (int) g_hist.size () - 1;
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

} // namespace

/* Back, Forward and Up all post a list_dir, which would queue behind a
   running extraction and overwrite its progress line, so they follow
   the same rule as the File menu's Refresh.  */
void
update_nav_buttons (void)
{
	EnableWindow (g_btn_back, !g_extracting && g_hist_pos > 0);
	EnableWindow (g_btn_fwd, !g_extracting && g_hist_pos >= 0 && (size_t) (g_hist_pos + 1) < g_hist.size ());
	EnableWindow (g_btn_up, !g_extracting);
}

void
nav_init (void)
{
	SetWindowSubclass (g_address, address_proc, 0, 0);
	update_nav_buttons ();	/* nothing visited yet: both grayed */
}

void
nav_on_listed (UINT seq)
{
	hist_record (seq);
	update_nav_buttons ();
}

/* Both moves walk the cursor first and remember the seq they posted:
   should the user navigate somewhere else before the listing lands,
   that result carries a different seq and is recorded normally.  */
void
go_back (void)
{
	if (g_hist_pos <= 0)
		return;
	g_hist_pos--;
	navigate (g_hist[(size_t) g_hist_pos]);
	g_hist_seq = g_seq_list;
}

void
go_forward (void)
{
	if (g_hist_pos < 0 || (size_t) (g_hist_pos + 1) >= g_hist.size ())
		return;
	g_hist_pos++;
	navigate (g_hist[(size_t) g_hist_pos]);
	g_hist_seq = g_seq_list;
}

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

void
set_fs_encoding (UINT encoding)
{
	std::string root;

	if (g_extracting || encoding == g_fs_encoding)
		return;
	backend_set_fs_char_encoding (encoding);
	dokanfs_invalidate_all ();
	g_fs_encoding = encoding;

	/* Paths below the device root may themselves have been decoded with the
	   old setting.  Restart at the stable device root and discard history
	   entries that can no longer be resolved. */
	if (!g_path.empty ())
	{
		size_t close = g_path.find (')');
		if (close != std::string::npos)
			root = g_path.substr (0, close + 1);
	}
	g_hist.clear ();
	g_hist_pos = -1;
	g_hist_seq = 0;
	list_clear ();
	g_path = std::move (root);
	SetWindowTextW (g_address, widen (g_path).c_str ());
	refresh ();
}

} // namespace mainwnd

using namespace mainwnd;

void
navigate (const std::string &path)
{
	g_seq_list = backend_post (list_dir_task { path });
	/* A result from the old view must not populate the new one, even
	   when both paths happen to contain the same names.  */
	list_drop_sizes ();
	set_status (IDS_STATUS_LISTING);
}

void
refresh (void)
{
	g_seq_disks = backend_post (enum_disks_task {});
	set_status (IDS_STATUS_ENUM);
	if (!g_path.empty ())
		navigate (g_path);
}
