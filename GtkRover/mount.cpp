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
 * Read-only FUSE mounts.  Each mount has its own libfuse instance and a
 * single-threaded loop thread; the shared fusefs core (common/fusefs.cpp)
 * hands every grub call to its dispatch function, which queues it on the
 * grub thread and waits.  So grub still runs on one thread only, and a
 * mount stalls while a long job (an extraction) holds that thread.
 *
 * Shutdown unmounts before the grub thread stops: a FUSE request waiting
 * on a dropped job would never return.
 */

#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include "app.h"

#include <glib/gstdio.h>

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include <condition_variable>
#include <mutex>
#include <thread>

#include "../common/fusefs.h"

namespace
{

struct mount_entry
{
	unsigned id = 0;
	std::string device;
	std::string mountpoint;
	bool created_dir = false;
	fusefs core;
	struct fuse *fuse = nullptr;
	std::thread thread;
	bool stopping = false;
};

/* GTK thread only.  */
std::vector<std::unique_ptr<mount_entry>> mounts;
unsigned next_id = 1;

/* Run FN on the grub thread and wait for it (FUSE loop threads).  */
bool
dispatch (const std::function<void ()> &fn)
{
	struct waiter
	{
		std::mutex lock;
		std::condition_variable cv;
		bool done = false;
	};
	auto w = std::make_shared<waiter> ();

	backend::post ([fn, w]
	{
		fn ();
		std::lock_guard<std::mutex> guard (w->lock);
		w->done = true;
		w->cv.notify_one ();
	});
	std::unique_lock<std::mutex> guard (w->lock);
	w->cv.wait (guard, [&w] { return w->done; });
	return true;
}

fusefs *
current_fs ()
{
	fuse_context *context = fuse_get_context ();

	return context ? static_cast<fusefs *> (context->private_data) : nullptr;
}

void
copy_stat (const fusefs_stat &in, struct stat *out)
{
	memset (out, 0, sizeof (*out));
	out->st_mode = in.mode;
	out->st_nlink = (in.mode & S_IFMT) == S_IFDIR ? 2 : 1;
	out->st_ino = in.inode;
	out->st_size = static_cast<off_t> (in.size);
	out->st_mtime = static_cast<time_t> (in.mtime);
	out->st_uid = getuid ();
	out->st_gid = getgid ();
}

int
fs_getattr (const char *path, struct stat *st, fuse_file_info *)
{
	fusefs_stat status = {};
	fusefs *fs = current_fs ();
	int rc = fs ? fusefs_getattr (fs, path, &status) : -EIO;

	if (!rc)
		copy_stat (status, st);
	return rc;
}

int
fs_readlink (const char *path, char *buf, size_t size)
{
	fusefs *fs = current_fs ();

	return fs ? fusefs_readlink (fs, path, buf, size) : -EIO;
}

int
fs_open (const char *path, fuse_file_info *info)
{
	fusefs *fs = current_fs ();

	return fs ? fusefs_open (fs, path, info->flags, &info->fh) : -EIO;
}

int
fs_read (const char *path, char *buf, size_t size, off_t offset, fuse_file_info *info)
{
	fusefs *fs = current_fs ();

	return fs ? fusefs_read (fs, path, buf, size, offset, &info->fh) : -EIO;
}

int
fs_release (const char *, fuse_file_info *info)
{
	fusefs *fs = current_fs ();

	return fs ? fusefs_release (fs, &info->fh) : -EIO;
}

struct fill_context
{
	void *buffer;
	fuse_fill_dir_t fill;
};

int
fill_directory (void *opaque, const char *name, const fusefs_stat *status)
{
	auto *context = static_cast<fill_context *> (opaque);
	struct stat st;

	copy_stat (*status, &st);
	return context->fill (context->buffer, name, &st, 0, static_cast<fuse_fill_dir_flags> (0));
}

int
fs_readdir (const char *path, void *buffer, fuse_fill_dir_t fill, off_t, fuse_file_info *,
	fuse_readdir_flags)
{
	fusefs *fs = current_fs ();
	fill_context context = { buffer, fill };

	return fs ? fusefs_readdir (fs, path, fill_directory, &context) : -EIO;
}

int
fs_statfs (const char *, struct statvfs *st)
{
	fusefs *fs = current_fs ();
	fusefs_statvfs status = {};
	int rc = fs ? fusefs_statfs (fs, &status) : -EIO;

	if (rc)
		return rc;
	memset (st, 0, sizeof (*st));
	st->f_bsize = status.block_size;
	st->f_frsize = status.block_size;
	st->f_blocks = status.blocks;
	st->f_namemax = status.name_max;
	st->f_flag = ST_RDONLY;
	return 0;
}

const fuse_operations *
operations ()
{
	static fuse_operations ops;
	static bool ready;

	if (!ready)
	{
		ops.getattr = fs_getattr;
		ops.readlink = fs_readlink;
		ops.open = fs_open;
		ops.read = fs_read;
		ops.release = fs_release;
		ops.readdir = fs_readdir;
		ops.statfs = fs_statfs;
		ready = true;
	}
	return &ops;
}

void
finish (mount_entry *m)
{
	if (!m->stopping)
	{
		m->stopping = true;
		fuse_exit (m->fuse);
		/* Unmounting aborts the connection, which ends the loop.  */
		fuse_unmount (m->fuse);
	}
	if (m->thread.joinable ())
		m->thread.join ();
	fuse_destroy (m->fuse);
	if (m->created_dir)
		g_rmdir (m->mountpoint.c_str ());
}

void
remove_mount (mount_entry *m)
{
	for (auto it = mounts.begin (); it != mounts.end (); ++it)
		if (it->get () == m)
		{
			mounts.erase (it);
			return;
		}
}

/* The loop of mount ID ended.  Unless we stopped it, someone ran
   fusermount -u.  */
void
loop_ended (unsigned id)
{
	for (const auto &entry : mounts)
		if (entry->id == id && !entry->stopping)
		{
			mount_entry *m = entry.get ();
			std::string device = m->device;
			finish (m);
			remove_mount (m);
			set_status (fmt (_("(%s) was unmounted"), device.c_str ()));
			refresh_disks (nullptr);
			return;
		}
}

std::string
default_mountpoint (const std::string &device)
{
	std::string name = device;

	for (char &c : name)
		if (c == ',' || c == '/')
			c = '_';
	return std::string (g_get_user_runtime_dir ()) + "/fsrover/" + name;
}

bool
dir_is_empty (const std::string &path)
{
	GDir *dir = g_dir_open (path.c_str (), 0, nullptr);
	bool empty = dir && !g_dir_read_name (dir);

	if (dir)
		g_dir_close (dir);
	return empty;
}

void
on_launch_done (GObject *source, GAsyncResult *result, gpointer)
{
	gtk_file_launcher_launch_finish (GTK_FILE_LAUNCHER (source), result, nullptr);
}

bool
start_mount (const row_data &disk, const std::string &mountpoint, bool open_after,
	std::string *error)
{
	auto m = std::make_unique<mount_entry> ();
	std::string options = "ro,default_permissions,fsname=fsrover:(" + disk.name + "),subtype=fsrover";
	const char *argv[] = { "fsrover", "-o", options.c_str () };
	fuse_args args = FUSE_ARGS_INIT (3, const_cast<char **> (argv));

	if (!g_file_test (mountpoint.c_str (), G_FILE_TEST_EXISTS))
	{
		if (g_mkdir_with_parents (mountpoint.c_str (), 0700) != 0)
		{
			*error = fmt (_("Cannot create %s: %s"), mountpoint.c_str (), g_strerror (errno));
			return false;
		}
		m->created_dir = true;
	}
	else if (!g_file_test (mountpoint.c_str (), G_FILE_TEST_IS_DIR))
	{
		*error = fmt (_("%s is not a folder"), mountpoint.c_str ());
		return false;
	}
	else if (!dir_is_empty (mountpoint))
	{
		*error = fmt (_("%s is not empty"), mountpoint.c_str ());
		return false;
	}
	m->device = disk.name;
	m->mountpoint = mountpoint;
	fusefs_init (&m->core, disk.name, disk.fs, disk.size, disk.sector_size, dispatch);
	m->fuse = fuse_new (&args, operations (), sizeof (fuse_operations), &m->core);
	fuse_opt_free_args (&args);
	if (!m->fuse || fuse_mount (m->fuse, mountpoint.c_str ()) != 0)
	{
		*error = fmt (_("FUSE could not mount %s. Is fusermount3 installed and /dev/fuse usable?"),
			mountpoint.c_str ());
		if (m->fuse)
			fuse_destroy (m->fuse);
		if (m->created_dir)
			g_rmdir (mountpoint.c_str ());
		return false;
	}
	m->id = next_id++;
	m->thread = std::thread ([fuse = m->fuse, id = m->id]
	{
		fuse_loop (fuse);
		backend::ui ([id] { loop_ended (id); });
	});
	mounts.push_back (std::move (m));
	if (open_after)
	{
		GFile *folder = g_file_new_for_path (mountpoint.c_str ());
		GtkFileLauncher *launcher = gtk_file_launcher_new (folder);
		gtk_file_launcher_launch (launcher, S.window, nullptr, on_launch_done, nullptr);
		g_object_unref (launcher);
		g_object_unref (folder);
	}
	return true;
}

/* ---- dialog --------------------------------------------------------- */

struct mount_widgets
{
	row_data disk;
	GtkWidget *entry;
	GtkWidget *open_after;
	GtkLabel *message;
};

void
on_folder_chosen (GObject *source, GAsyncResult *result, gpointer entry)
{
	GFile *folder = gtk_file_dialog_select_folder_finish (GTK_FILE_DIALOG (source), result, nullptr);

	if (folder)
	{
		char *path = g_file_get_path (folder);
		if (path)
			gtk_editable_set_text (GTK_EDITABLE (entry), path);
		g_free (path);
		g_object_unref (folder);
	}
	g_object_unref (entry);
}

void
on_choose_folder (GtkButton *button, gpointer entry)
{
	GtkFileDialog *dialog = gtk_file_dialog_new ();

	gtk_file_dialog_set_title (dialog, _("Choose an Empty Folder"));
	gtk_file_dialog_select_folder (dialog, GTK_WINDOW (gtk_widget_get_root (GTK_WIDGET (button))),
		nullptr, on_folder_chosen, g_object_ref (entry));
	g_object_unref (dialog);
}

void
on_mount_clicked (GtkButton *, gpointer dialog)
{
	auto *w = static_cast<mount_widgets *> (g_object_get_data (G_OBJECT (dialog), "rover-mount"));
	std::string error;
	std::string mountpoint = gtk_editable_get_text (GTK_EDITABLE (w->entry));

	if (mountpoint.empty () || mountpoint[0] != '/')
	{
		gtk_label_set_text (w->message, _("Enter an absolute folder path."));
		return;
	}
	if (!start_mount (w->disk, mountpoint,
		gtk_check_button_get_active (GTK_CHECK_BUTTON (w->open_after)), &error))
	{
		gtk_label_set_text (w->message, error.c_str ());
		return;
	}
	set_status (fmt (_("Mounted (%s) at %s"), w->disk.name.c_str (), mountpoint.c_str ()));
	gtk_window_destroy (GTK_WINDOW (dialog));
	refresh_disks (nullptr);
}

void
on_mount_cancel (GtkButton *, gpointer dialog)
{
	gtk_window_close (GTK_WINDOW (dialog));
}

} /* namespace */

void
show_mount (const row_data &disk)
{
	GtkWindow *dialog = new_dialog (fmt (_("Mount (%s)"), disk.name.c_str ()), 480, -1);
	GtkWidget *box = dialog_box (dialog);
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *browse = gtk_button_new_with_label (_("Browse…"));
	GtkWidget *cancel = gtk_button_new_with_mnemonic (_("_Cancel"));
	GtkWidget *mount = gtk_button_new_with_mnemonic (_("_Mount"));
	auto *w = new mount_widgets;

	w->disk = disk;
	gtk_window_set_modal (dialog, TRUE);
	gtk_window_set_resizable (dialog, FALSE);
	gtk_box_append (GTK_BOX (box), heading_label (fmt (_("Mount (%s) read-only"), disk.name.c_str ())));
	GtkWidget *hint = gtk_label_new (_("The volume appears as a folder that every program can read. "
		"It stays mounted until you unmount it or quit FsRover."));
	gtk_label_set_xalign (GTK_LABEL (hint), 0);
	gtk_label_set_wrap (GTK_LABEL (hint), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (hint), 50);
	gtk_box_append (GTK_BOX (box), hint);
	w->entry = gtk_entry_new ();
	gtk_editable_set_text (GTK_EDITABLE (w->entry), default_mountpoint (disk.name).c_str ());
	gtk_widget_set_hexpand (w->entry, TRUE);
	g_object_set (w->entry, "activates-default", TRUE, nullptr);
	gtk_box_append (GTK_BOX (row), w->entry);
	gtk_box_append (GTK_BOX (row), browse);
	gtk_box_append (GTK_BOX (box), row);
	w->open_after = gtk_check_button_new_with_mnemonic (_("_Open the folder after mounting"));
	gtk_check_button_set_active (GTK_CHECK_BUTTON (w->open_after), TRUE);
	gtk_box_append (GTK_BOX (box), w->open_after);
	w->message = GTK_LABEL (gtk_label_new (nullptr));
	gtk_label_set_xalign (w->message, 0);
	gtk_label_set_wrap (w->message, TRUE);
	gtk_label_set_max_width_chars (w->message, 50);
	gtk_widget_add_css_class (GTK_WIDGET (w->message), "error");
	gtk_box_append (GTK_BOX (box), GTK_WIDGET (w->message));
	gtk_widget_add_css_class (mount, "suggested-action");
	gtk_box_append (GTK_BOX (box), button_row ({ cancel, mount }));
	gtk_window_set_default_widget (dialog, mount);

	g_object_set_data_full (G_OBJECT (dialog), "rover-mount", w,
		[] (gpointer p) { delete static_cast<mount_widgets *> (p); });
	g_signal_connect (browse, "clicked", G_CALLBACK (on_choose_folder), w->entry);
	g_signal_connect (mount, "clicked", G_CALLBACK (on_mount_clicked), dialog);
	g_signal_connect (cancel, "clicked", G_CALLBACK (on_mount_cancel), dialog);
	gtk_window_present (dialog);
}

bool
mount_active (const std::string &device, std::string *mountpoint)
{
	for (const auto &m : mounts)
		if (m->device == device)
		{
			if (mountpoint)
				*mountpoint = m->mountpoint;
			return true;
		}
	return false;
}

bool
mount_contains (const std::string &path)
{
	for (const auto &m : mounts)
		if (path == m->mountpoint || g_str_has_prefix (path.c_str (), (m->mountpoint + "/").c_str ()))
			return true;
	return false;
}

void
mount_stop (const std::string &device)
{
	for (const auto &entry : mounts)
		if (entry->device == device)
		{
			mount_entry *m = entry.get ();
			finish (m);
			remove_mount (m);
			set_status (fmt (_("Unmounted (%s)"), device.c_str ()));
			refresh_disks (nullptr);
			return;
		}
}

void
mount_invalidate_all ()
{
	for (const auto &m : mounts)
		fusefs_invalidate (&m->core);
}

void
mount_shutdown ()
{
	for (const auto &m : mounts)
		finish (m.get ());
	mounts.clear ();
}
