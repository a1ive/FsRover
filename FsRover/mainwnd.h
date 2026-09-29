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
 * Private surface shared by the main window's source files: main.cpp
 * (the window itself and result dispatch), mainlist.cpp (file list),
 * maintree.cpp (device tree), mainnav.cpp (navigation and history),
 * mainjob.cpp (extract/export job) and mainmenu.cpp (menu bar, mounts,
 * file drop).  Everything here runs on the GUI thread.  The dialogs
 * and viewers do not include this header; what they need of the main
 * window is in gui.h.
 */

#ifndef FSROVER_MAINWND_H
#define FSROVER_MAINWND_H	1

#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>

#include "gui.h"

struct dokan_mount;

namespace mainwnd
{

/* Toolbar buttons; also the accelerator targets in wWinMain.  */
constexpr int IDC_EXTRACT = 101;
constexpr int IDC_UP = 102;
constexpr int IDC_BACK = 103;
constexpr int IDC_FWD = 104;

/* Menu bar commands.  IDM_DOKAN_UNMOUNT_BASE + i unmounts
   dokanfs_get(i); the Dokan popup is rebuilt on every open, and a
   menu is modal, so the index is still valid when the command
   arrives.  */
constexpr int IDM_FILE_REFRESH = 200;
constexpr int IDM_FILE_EXIT = 201;
constexpr int IDM_FILE_TIMESTAMPS = 202;
constexpr int IDM_FILE_OPEN_IMAGE = 203;
constexpr int IDM_FILE_OPEN_IMAGE_DECOMP = 204;
#if FSROVER_ENABLE_ADMIN_FEATURES
constexpr int IDM_FILE_RUNAS = 205;
#endif
constexpr int IDM_SEL_ALL = 210;
constexpr int IDM_SEL_INVERT = 211;
constexpr int IDM_HELP_SUPPORT = 220;
constexpr int IDM_HELP_ABOUT = 221;
#if FSROVER_EMBED_DOKAN
constexpr int IDM_DOKAN_INSTALL = 222;
#endif
constexpr int IDM_HELP_SHORTCUTS = 223;
constexpr int IDM_HELP_DOC = 224;
constexpr int IDM_BACKEND_WINFSP = 225;
constexpr int IDM_BACKEND_DOKAN = 226;
constexpr int IDM_FS_ENCODING_BASE = 230;
constexpr int IDM_DOKAN_UNMOUNT_BASE = 2000;

/* Context menu commands.  Both popups are tracked with TPM_RETURNCMD,
   so these never reach WM_COMMAND and may overlap the menu bar's.  */
constexpr int IDM_EXTRACT = 1;
constexpr int IDM_MOUNT = 2;
constexpr int IDM_UNMOUNT = 3;
constexpr int IDM_DOKAN_MOUNT = 4;
constexpr int IDM_DOKAN_UNMOUNT = 5;
constexpr int IDM_PROPS = 6;
constexpr int IDM_FILE_MAP = 30;
constexpr int IDM_HEX = 7;
constexpr int IDM_COPY_NAME = 8;
constexpr int IDM_COPY_PATH = 9;
constexpr int IDM_MOUNT_DECOMP = 10;
constexpr int IDM_TEXT = 11;
constexpr int IDM_IMAGE = 12;
constexpr int IDM_EXPORT = 13;
constexpr int IDM_MARKDOWN = 14;
constexpr int IDM_VERACRYPT = 15;
constexpr int IDM_PLAINMOUNT = 16;
#if FSROVER_ENABLE_ADMIN_FEATURES
constexpr int IDM_SMART = 17;
#endif
constexpr int IDM_LOST_SCAN = 18;

/* Child controls, created by main.cpp.  */
extern HWND g_address;
extern HWND g_btn_extract;
extern HWND g_btn_up;
extern HWND g_btn_back;
extern HWND g_btn_fwd;
extern HWND g_tree;
extern HWND g_list;
extern HWND g_status;
extern HWND g_progress;

/* main.cpp */
void set_status (const wchar_t *text);
void set_status (UINT id);

/* mainnav.cpp */
extern UINT g_seq_disks;	/* pending seq per task type; older results */
extern UINT g_seq_list;	/* are stale and dropped */
extern UINT g_fs_encoding;
void nav_init (void);	/* once the controls exist */
void nav_on_listed (UINT seq);	/* a listing succeeded */
void update_nav_buttons (void);
void go_back (void);
void go_forward (void);
void go_up (void);
void set_fs_encoding (UINT encoding);

/* mainlist.cpp */
extern std::string g_path;	/* listed path, UTF-8, empty = nothing shown */
extern UINT g_seq_sizes;	/* one bounded lazy-size batch at a time */
void list_apply_dpi (int icon_size);
LRESULT list_on_notify (NMHDR *hdr);
void list_clear (void);
void list_drop_sizes (void);
void fill_list (backend_result *res);
void fill_list_sizes (backend_result *res);
std::vector<std::string> selected_paths (void);

/* maintree.cpp */
void tree_apply_dpi (int icon_size);
LRESULT tree_on_notify (NMHDR *hdr);
void fill_tree (backend_result *res);
void tree_on_mounted (backend_result *res);
void tree_on_unmounted (backend_result *res);

/* mainjob.cpp */
extern bool g_preserve_times;	/* Settings toggle, copied into each extract task */
void job_apply_dpi (int icon_size);
void start_extract (std::vector<std::string> &&paths);
void start_export (const backend_diskent &d);
void on_extract_button (void);
bool job_finish (backend_result *res);	/* false = not the running job */
void job_report (backend_result *res);
void job_on_progress (backend_progress *p);

/* mainmenu.cpp */
void create_menu_bar (HWND wnd);
void on_menu_popup (HMENU menu);
void on_command (int id);
void enable_file_drop (HWND wnd);
void on_drop_files (HDROP drop);
void do_dokan_mount (const backend_diskent &disk);
void do_dokan_unmount (dokan_mount *mount);

} // namespace mainwnd

#endif /* ! FSROVER_MAINWND_H */
