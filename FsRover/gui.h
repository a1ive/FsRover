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
 * Shared surface of the GUI thread.  main.cpp owns the main window and
 * dispatches backend results; the modal dialogs and viewers live in
 * their own files (propsdlg/cryptodlg/hexview/textview/imageview) and
 * are reached only through the functions below.  Everything here runs
 * on the GUI thread; grub work still goes through backend.h.
 */

#ifndef FSROVER_GUI_H
#define FSROVER_GUI_H	1

#include "build_config.h"

#include <windows.h>
#include <commctrl.h>

#include <string>
#include <vector>

#include "backend.h"

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

/* Posted by a dialog to itself from WM_DPICHANGED: everything that has
   to run after the dialog manager has rescaled the frame, the dialog
   font and the controls.  (WM_APP + 1..6 are taken by backend.h and
   dokanfs.h, + 5 by the tray icon in main.cpp.)  */
constexpr UINT WM_APP_DPI_CHANGED = WM_APP + 7;

/*
 * Modal loops.  A dialog or message box owned by the main window
 * disables it and runs a message loop of its own; the tray menu keeps
 * working through that loop, so an Exit can arrive at any moment, and
 * destroying the owner from under a modal loop is not survivable.
 *
 * Every modal call site holds a modal_scope for as long as its loop
 * runs and WM_CLOSE refuses while any is up.  The viewers' own window
 * handles cannot answer this question -- several are cleared early,
 * while the dialog is still on screen, to drop read results that
 * arrived too late -- which is why the registry is separate from them.
 */

class modal_scope
{
public:
	modal_scope ();
	~modal_scope ();
	modal_scope (const modal_scope &) = delete;
	modal_scope &operator= (const modal_scope &) = delete;
};

bool modal_open (void);

/* main.cpp */
extern HWND g_main;	/* owner window for every modal dialog */
extern bool g_extracting;	/* an extract task is in flight */
void navigate (const std::string &path);
void refresh (void);
int device_icon_id (const backend_diskent &d);	/* imageres.dll icon id */
void mount_host_image (std::wstring file, bool decompress);	/* winfile */

/* cmdline.cpp */

/* What the command line asked for; filled once by cmdline_parse() and
   read back while the session starts.  */
struct cmdline_options
{
	bool minimize = false;	/* -m: come up in the tray, no window */
	bool preserve_times = true;	/* -n: extracted items keep no source times */
	UINT fs_encoding = BACKEND_FS_ENCODING_UTF8;	/* -c: byte-oriented names */
	/* -f/-d: the physical disks are the one thing an unprivileged
	   process cannot read, and a session about someone's own image
	   file has no use for them.  */
	bool no_windisk = false;
	struct mount
	{
		std::wstring file;
		bool decompress;	/* -d rather than -f */
	};
	std::vector<mount> mounts;	/* -f/-d, in command-line order */
};

extern cmdline_options g_cmdline;

/* False = the line was answered with a message box (a bad switch, or
   --help) and the program should not start.  */
bool cmdline_parse (void);

/* util.cpp */
std::wstring window_text (HWND wnd);
std::wstring res_str (UINT id);
void init_language (void);
bool is_elevated (void);	/* elevated token: physical disks, driver install */
bool is_wow64 (void);	/* 32-bit process on 64-bit Windows */
HICON load_system_icon (const wchar_t *dll, int id, int size);
HIMAGELIST icon_list (const wchar_t *dll, const int *ids, int count, int size);
HIMAGELIST button_icons (const wchar_t *dll, int id, int size);
void set_button_icon (HWND btn, HIMAGELIST himl);
void center_on_owner (HWND wnd, int w, int h);	/* on g_main's monitor */

/* Per-monitor DPI; see the block comment in util.cpp.  Every top-level
   window keeps its own DPI and passes it in -- there is deliberately no
   program-wide one.  */
void load_dpi_api (void);
int dpi_scale (UINT dpi, int value);
int dpi_unscale (UINT dpi, int value);
UINT dpi_for_window (HWND wnd);
UINT dpi_system (void);	/* the DPI GDI measures in */
void richedit_dpi_zoom (HWND edit, UINT dpi, UINT device);
void dpi_take_suggested (HWND wnd, LPARAM lp);	/* WM_DPICHANGED frame */
int system_metric_dpi (UINT dpi, int index);
HFONT create_message_font (UINT dpi);

std::wstring format_size (UINT64 size);
std::wstring format_mtime (INT64 mtime);
std::string join_path (const std::string &dir, const std::string &name);
void clipboard_set_text (HWND owner, const std::wstring &text);

/* propsdlg.cpp */
void show_props (const std::string &path);
void props_on_type (backend_result *res);
void props_on_hash (backend_result *res);
bool props_on_progress (backend_progress *p);

/* diskprops.cpp */
void show_disk_props (const backend_diskent &d,
		      const std::vector<backend_diskent> &disks);

#if FSROVER_ENABLE_ADMIN_FEATURES
/* smartdlg.cpp */

/* False = libcdi is not next to the executable, so nothing can be read
   and the menu item stays grayed.  */
bool smart_available (void);
void show_smart (const backend_diskent &d);	/* windisk "hdN" only */
void smart_shutdown (void);	/* before COM goes down */
#endif

/* cryptodlg.cpp */
void prompt_unlock (const std::string &devname, const std::string &uuid);
void crypto_unlock_done (backend_result *res);
bool crypto_on_progress (backend_progress *p);
void prompt_unlock_veracrypt (const std::string &devname);
void veracrypt_unlock_done (backend_result *res);
bool veracrypt_on_progress (backend_progress *p);
void prompt_plainmount (const std::string &devname);
void plainmount_done (backend_result *res);

/* hexview.cpp */
void show_hex (const std::string &path, const std::wstring &title = {}, UINT64 known_size = BACKEND_SIZE_UNKNOWN);
void hex_on_chunk (backend_result *res);

/* textview.cpp */
void show_text (const std::string &path);
void text_on_chunk (backend_result *res);

/* imageview.cpp */
bool is_image_name (const std::string &name);
void show_image (const std::string &path);
void img_on_chunk (backend_result *res);

/* mdview.cpp */

/* A page the markdown viewer can show: window caption plus the UTF-8
   markdown itself.  Keeping the two apart from where they were read
   lets one viewer serve both browsed files and the pages shipped with
   the program.  */
struct md_document
{
	std::wstring title;
	std::string text;
};

bool is_markdown_name (const std::string &name);
void show_markdown (const std::string &path);	/* file in the browsed fs */
void show_markdown_doc (const md_document &doc);	/* already in memory */
void md_on_chunk (backend_result *res);
/* Sources for pages shipped with the program; see mdview.cpp.  */
bool md_load_resource (UINT id, md_document *doc);
bool md_load_file (const std::wstring &path, md_document *doc);
bool md_load_help (const wchar_t *name, UINT res_id, md_document *doc);

/* helpdlg.cpp */
void show_about (void);
void show_support (void);
void show_shortcuts (void);
void show_help_doc (void);	/* the bundled help page, IDR_HELP_MD */

/* game.cpp: About-box icon easter egg.  */
void show_rover_game (HWND owner);

#endif /* ! FSROVER_GUI_H */
