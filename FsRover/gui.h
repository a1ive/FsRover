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

#include <windows.h>
#include <commctrl.h>

#include <string>

#include "backend.h"

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

/* main.cpp */
extern HWND g_main;	/* owner window for every modal dialog */
extern bool g_extracting;	/* an extract task is in flight */
void navigate (const std::string &path);
void refresh (void);

/* util.cpp */
extern UINT g_dpi;	/* main-window DPI; drives all layout scaling */
std::wstring window_text (HWND wnd);
std::wstring res_str (UINT id);
void init_language (void);
HICON load_system_icon (const wchar_t *dll, int id, int size);
HIMAGELIST icon_list (const wchar_t *dll, const int *ids, int count, int size);
HIMAGELIST button_icons (const wchar_t *dll, int id, int size);
void set_button_icon (HWND btn, HIMAGELIST himl);
void load_dpi_api (void);
int dpi_scale (int value);
UINT dpi_for_window (HWND wnd);
int system_metric_dpi (int index);
HFONT create_message_font (void);
std::wstring format_size (UINT64 size);
std::wstring format_mtime (INT64 mtime);
std::string join_path (const std::string &dir, const std::string &name);
void clipboard_set_text (HWND owner, const std::wstring &text);

/* propsdlg.cpp */
extern HWND g_props;	/* modal file properties dialog, null when closed */
extern HWND g_diskprops;	/* modal disk properties dialog, null when closed */
void show_props (const std::string &path);
void show_disk_props (const backend_diskent &d);
void props_on_type (backend_result *res);
void props_on_hash (backend_result *res);
bool props_on_progress (backend_progress *p);

/* cryptodlg.cpp */
extern HWND g_crypto;	/* modal unlock dialog, null when closed */
void prompt_unlock (const std::string &devname, const std::string &uuid);
void crypto_unlock_done (backend_result *res);
bool crypto_on_progress (backend_progress *p);

/* hexview.cpp */
extern HWND g_hex;	/* modal hex viewer, null when closed */
void show_hex (const std::string &path, const std::wstring &title = {}, UINT64 known_size = BACKEND_SIZE_UNKNOWN);
void hex_on_chunk (backend_result *res);

/* textview.cpp */
extern HWND g_text;	/* modal text viewer, null when closed */
void show_text (const std::string &path);
void text_on_chunk (backend_result *res);

/* imageview.cpp */
extern HWND g_img;	/* modal image viewer, null when closed */
bool is_image_name (const std::string &name);
void show_image (const std::string &path);
void img_on_chunk (backend_result *res);

/* helpdlg.cpp */
extern HWND g_about;	/* modal About dialog, null when closed */
extern HWND g_support;	/* modal supported-features dialog */
void show_about (void);
void show_support (void);

#endif /* ! FSROVER_GUI_H */
