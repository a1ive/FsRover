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
 * State and helpers shared by the GtkRover modules.  Everything declared
 * here belongs to the GTK thread unless a comment says otherwise; grub
 * work goes through run_job() (or backend::post) and comes back as a
 * closure on the main loop.
 */

#ifndef GTKROVER_APP_H
#define GTKROVER_APP_H	1

#include <gtk/gtk.h>
#include <glib/gi18n.h>

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "backend.h"
#include "row.h"

struct app_state
{
	GtkApplication *app = nullptr;
	GtkWindow *window = nullptr;
	GtkEntry *path_entry = nullptr;
	GListStore *disks = nullptr;
	GtkSingleSelection *disk_sel = nullptr;
	GtkListView *disk_view = nullptr;
	GListStore *entries = nullptr;
	GtkMultiSelection *entry_sel = nullptr;
	GtkColumnView *entry_view = nullptr;
	GtkStack *stack = nullptr;
	GtkWidget *entry_menu = nullptr;
	GtkWidget *disk_menu = nullptr;
	GtkLabel *status = nullptr;
	GtkProgressBar *progress = nullptr;
	GtkWidget *cancel_button = nullptr;
	GtkWidget *access_button = nullptr;

	std::string cur_path;	/* "(dev)/dir", empty when no device is open */
	std::vector<std::string> history;
	std::vector<std::string> forward;
	std::atomic<unsigned> list_gen { 0 };
	std::atomic<bool> cancel { false };
	bool ready = false;
	bool busy = false;
	bool closing = false;
	bool syncing_disks = false;
	bool preserve_times = true;
	unsigned fs_encoding = 65001;	/* ROVER_FS_ENCODING_* */
	unsigned next_image = 0;
	unsigned next_loop = 0;
	unsigned next_lost = 0;
	std::vector<std::string> pending_images;
};

extern app_state S;

/* ---- window.cpp ---------------------------------------------------- */

/* rover_last_error() as a string.  Grub thread only.  */
std::string last_error ();
std::string fmt (const char *format, ...) G_GNUC_PRINTF (1, 2);
std::string join_path (const std::string &dir, const std::string &name);
std::string parent_path (const std::string &path);
std::string device_of (const std::string &path);
std::string basename_of (const std::string &path);
std::string format_size (unsigned long long size);
std::string format_exact (unsigned long long size);
std::string format_time (long long seconds);

void set_status (const std::string &text);
void show_error (const std::string &title, const std::string &detail);
void copy_text (const std::string &text);

/* Long jobs own the status bar's progress bar and Cancel button (which
   sets S.cancel); one at a time.  */
bool begin_job (const std::string &text, bool cancellable = true);
void end_job (const std::string &text);
/* Throttled; callable from the grub thread.  */
void post_progress (double fraction, const std::string &text);

void update_actions ();
void refresh_disks (std::function<void ()> then);
void navigate (const std::string &path, bool push, bool open_fallback = false);
void auto_enter (const std::string &dev);
bool find_disk (const std::string &name, row_data *out);
void select_disk (const std::string &name);

/* A transient window for S.window, destroyed with it.  */
GtkWindow *new_dialog (const std::string &title, int width, int height);
GtkWidget *dialog_box (GtkWindow *dialog);
GtkWidget *button_row (std::initializer_list<GtkWidget *> buttons);
/* Bold text label, left aligned.  */
GtkWidget *heading_label (const std::string &text);

/* Run WORK () on the grub thread, then DONE (result) on the GTK thread
   unless the main window is closing.  Both must be copyable.  */
template <typename Work, typename Done>
void
run_job (Work work, Done done)
{
	backend::post ([work, done] () mutable
	{
		auto result = std::make_shared<decltype (work ())> (work ());
		backend::ui ([done, result] () mutable
		{
			if (!S.closing)
				done (std::move (*result));
		});
	});
}

/* Grub-thread helper for the viewers: up to LENGTH bytes at OFFSET of the
   rover path PATH ("(hd0)0+" reads a raw device).  */
struct chunk
{
	std::string error;
	unsigned long long size = 0;	/* file or device size */
	std::vector<unsigned char> data;
};
chunk read_chunk (const std::string &path, unsigned long long offset, size_t length);

/* ---- cryptodlg.cpp ------------------------------------------------- */
void show_unlock (const std::string &device, const std::string &type);
void show_veracrypt (const std::string &device);
void show_plain_unlock (const std::string &device);

/* ---- propsdlg.cpp -------------------------------------------------- */
void show_file_props (const std::string &path);
void show_disk_props (const row_data &disk);

/* ---- viewers ------------------------------------------------------- */
void show_hex (const std::string &path, const std::string &title);
void show_text (const std::string &path);
void show_image (const std::string &path);
void show_markdown_file (const std::string &path);
void show_help ();
void show_file_map (const std::string &path);

/* ---- lostdlg.cpp --------------------------------------------------- */
void show_lost_scan (const std::string &device);

/* ---- mount.cpp ----------------------------------------------------- */
void show_mount (const row_data &disk);
bool mount_active (const std::string &device, std::string *mountpoint);
/* PATH lies inside one of our FUSE mounts.  Reading it through the kernel
   would make the grub thread wait on itself.  */
bool mount_contains (const std::string &path);
void mount_stop (const std::string &device);
void mount_invalidate_all ();
void mount_shutdown ();

/* ---- hostdisk.cpp -------------------------------------------------- */
void hostdisk_install_hook ();
bool hostdisk_needed ();
void hostdisk_request_access ();
int hostdisk_helper_main (int argc, char **argv);

#endif /* ! GTKROVER_APP_H */
