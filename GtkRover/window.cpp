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
 * Main window: device sidebar, directory view, status bar, and the
 * actions behind the menus.  Everything here runs on the GTK thread;
 * rover_* calls are wrapped in jobs whose results come back through
 * backend::ui().  A listing that arrives after the user navigated
 * elsewhere is dropped by comparing the list generation it was started
 * with.
 */

#include "window.h"
#include "app.h"

#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>

#include <rover.h>

#include "../common/extract_core.h"
#include "../common/natural_sort.h"

app_state S;

/* ---- helpers -------------------------------------------------------- */

std::string
last_error ()
{
	const char *message = rover_last_error ();

	return message ? message : _("unknown error");
}

std::string
fmt (const char *format, ...)
{
	va_list args;
	char *text;

	va_start (args, format);
	text = g_strdup_vprintf (format, args);
	va_end (args);
	std::string out = text;
	g_free (text);
	return out;
}

std::string
join_path (const std::string &dir, const std::string &name)
{
	return dir.back () == '/' ? dir + name : dir + '/' + name;
}

/* "(d)/a/b" -> "(d)/a" -> "(d)/" -> "" */
std::string
parent_path (const std::string &path)
{
	size_t close = path.find (')');

	if (close == std::string::npos)
		return "";
	std::string rest = path.substr (close + 1);
	while (rest.size () > 1 && rest.back () == '/')
		rest.pop_back ();
	if (rest.empty () || rest == "/")
		return "";
	size_t slash = rest.rfind ('/');
	if (slash == 0 || slash == std::string::npos)
		return path.substr (0, close + 1) + '/';
	return path.substr (0, close + 1) + rest.substr (0, slash);
}

std::string
device_of (const std::string &path)
{
	size_t close = path.find (')');

	if (path.empty () || path[0] != '(' || close == std::string::npos)
		return "";
	return path.substr (1, close - 1);
}

std::string
basename_of (const std::string &path)
{
	size_t slash = path.rfind ('/');

	return slash == std::string::npos ? path : path.substr (slash + 1);
}

std::string
format_size (unsigned long long size)
{
	char *text = g_format_size_full (size, G_FORMAT_SIZE_IEC_UNITS);
	std::string out = text;

	g_free (text);
	return out;
}

/* "1,234,567 bytes" */
std::string
format_exact (unsigned long long size)
{
	std::string digits = std::to_string (size);

	for (size_t i = digits.size (); i > 3; i -= 3)
		digits.insert (i - 3, ",");
	return fmt (g_dngettext (nullptr, "%s byte", "%s bytes", size), digits.c_str ());
}

std::string
format_time (long long seconds)
{
	GDateTime *dt = g_date_time_new_from_unix_local (seconds);

	if (!dt)
		return "";
	char *text = g_date_time_format (dt, "%Y-%m-%d %H:%M:%S");
	std::string out = text ? text : "";
	g_free (text);
	g_date_time_unref (dt);
	return out;
}

void
set_status (const std::string &text)
{
	gtk_label_set_text (S.status, text.c_str ());
}

void
show_error (const std::string &title, const std::string &detail)
{
	GtkAlertDialog *dialog = gtk_alert_dialog_new ("%s", title.c_str ());

	gtk_alert_dialog_set_detail (dialog, detail.c_str ());
	gtk_alert_dialog_show (dialog, S.window);
	g_object_unref (dialog);
}

void
copy_text (const std::string &text)
{
	gdk_clipboard_set_text (gtk_widget_get_clipboard (GTK_WIDGET (S.window)), text.c_str ());
}

GtkWindow *
new_dialog (const std::string &title, int width, int height)
{
	GtkWindow *dialog = GTK_WINDOW (gtk_window_new ());
	GtkEventController *keys = gtk_shortcut_controller_new ();

	gtk_window_set_title (dialog, title.c_str ());
	gtk_window_set_transient_for (dialog, S.window);
	gtk_window_set_destroy_with_parent (dialog, TRUE);
	gtk_window_set_default_size (dialog, width, height);
	gtk_shortcut_controller_add_shortcut (GTK_SHORTCUT_CONTROLLER (keys),
		gtk_shortcut_new (gtk_shortcut_trigger_parse_string ("Escape"),
			gtk_named_action_new ("window.close")));
	gtk_widget_add_controller (GTK_WIDGET (dialog), keys);
	return dialog;
}

GtkWidget *
dialog_box (GtkWindow *dialog)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);

	gtk_widget_set_margin_top (box, 16);
	gtk_widget_set_margin_bottom (box, 16);
	gtk_widget_set_margin_start (box, 16);
	gtk_widget_set_margin_end (box, 16);
	gtk_window_set_child (dialog, box);
	return box;
}

GtkWidget *
button_row (std::initializer_list<GtkWidget *> buttons)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);

	gtk_widget_set_halign (row, GTK_ALIGN_END);
	for (GtkWidget *button : buttons)
		gtk_box_append (GTK_BOX (row), button);
	return row;
}

GtkWidget *
heading_label (const std::string &text)
{
	GtkWidget *label = gtk_label_new (nullptr);
	char *markup = g_markup_printf_escaped ("<b>%s</b>", text.c_str ());

	gtk_label_set_markup (GTK_LABEL (label), markup);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_label_set_wrap (GTK_LABEL (label), TRUE);
	g_free (markup);
	return label;
}

namespace
{

void
enable_action (const char *name, bool enabled)
{
	GAction *action = g_action_map_lookup_action (G_ACTION_MAP (S.window), name);

	g_simple_action_set_enabled (G_SIMPLE_ACTION (action), enabled);
}

std::vector<row_data>
selected_rows ()
{
	GtkSelectionModel *model = GTK_SELECTION_MODEL (S.entry_sel);
	GtkBitset *set = gtk_selection_model_get_selection (model);
	std::vector<row_data> rows;
	GtkBitsetIter iter;
	guint pos;

	for (bool ok = gtk_bitset_iter_init_first (&iter, set, &pos); ok;
		ok = gtk_bitset_iter_next (&iter, &pos))
	{
		RoverRow *row = ROVER_ROW (g_list_model_get_item (G_LIST_MODEL (model), pos));
		rows.push_back (rover_row_get (row));
		g_object_unref (row);
	}
	gtk_bitset_unref (set);
	return rows;
}

std::vector<std::string>
selected_paths ()
{
	std::vector<std::string> paths;

	for (const row_data &d : selected_rows ())
		paths.push_back (join_path (S.cur_path, d.name));
	return paths;
}

/* The one selected entry that is not a folder, if that is the selection.  */
bool
selected_file (std::string *path)
{
	std::vector<row_data> rows = selected_rows ();

	if (S.cur_path.empty () || rows.size () != 1 || rows[0].is_dir)
		return false;
	*path = join_path (S.cur_path, rows[0].name);
	return true;
}

bool
selected_disk (row_data *out)
{
	gpointer item = gtk_single_selection_get_selected_item (S.disk_sel);

	if (!item)
		return false;
	*out = rover_row_get (ROVER_ROW (item));
	return true;
}

bool
is_detachable (const row_data &d)
{
	return !d.is_partition && (d.dev_id == ROVER_DEV_POSIXFILE
		|| d.dev_id == ROVER_DEV_LOOPBACK || d.dev_id == ROVER_DEV_LOST);
}

} /* namespace */

void
update_actions ()
{
	std::vector<row_data> rows = S.cur_path.empty () ? std::vector<row_data> ()
		: selected_rows ();
	std::string file;
	bool one_file = selected_file (&file);
	row_data disk;
	bool have_disk = selected_disk (&disk);

	enable_action ("back", !S.history.empty ());
	enable_action ("forward", !S.forward.empty ());
	enable_action ("up", !S.cur_path.empty ());
	enable_action ("extract", !rows.empty () && !S.busy);
	enable_action ("open", rows.size () == 1 && !S.busy);
	enable_action ("open-as-image", one_file);
	enable_action ("open-as-image-dec", one_file);
	enable_action ("view-text", one_file);
	enable_action ("view-hex", one_file);
	enable_action ("view-image", one_file);
	enable_action ("view-markdown", one_file);
	enable_action ("file-map", one_file);
	enable_action ("file-props", rows.size () == 1);
	enable_action ("copy-name", !rows.empty ());
	enable_action ("copy-path", !rows.empty ());
	enable_action ("select-all", !S.cur_path.empty ());
	enable_action ("select-invert", !S.cur_path.empty ());
	enable_action ("disk-browse", have_disk);
	enable_action ("disk-mount", have_disk && !disk.fs.empty () && disk.mountpoint.empty ());
	enable_action ("disk-unmount", have_disk && !disk.mountpoint.empty ());
	enable_action ("unlock", have_disk && disk.encrypted && !S.busy);
	enable_action ("veracrypt", have_disk && disk.fs.empty () && !S.busy);
	enable_action ("plain-unlock", have_disk && disk.fs.empty () && !S.busy);
	enable_action ("disk-hex", have_disk);
	enable_action ("export-image", have_disk && !S.busy);
	enable_action ("lost-scan", have_disk && disk.dev_id != ROVER_DEV_LOST);
	enable_action ("detach", have_disk && is_detachable (disk));
	enable_action ("disk-props", have_disk);
	enable_action ("host-access", hostdisk_needed ());
	if (S.access_button)
		gtk_widget_set_visible (S.access_button, hostdisk_needed ());
}

/* Long jobs (extract, export, unlock) own the progress bar; one at a time.  */
bool
begin_job (const std::string &text, bool cancellable)
{
	if (S.busy)
	{
		set_status (_("Another operation is still running"));
		return false;
	}
	S.busy = true;
	S.cancel = false;
	gtk_progress_bar_set_fraction (S.progress, 0);
	gtk_widget_set_visible (GTK_WIDGET (S.progress), TRUE);
	gtk_widget_set_visible (S.cancel_button, cancellable);
	set_status (text);
	update_actions ();
	return true;
}

void
end_job (const std::string &text)
{
	S.busy = false;
	gtk_widget_set_visible (GTK_WIDGET (S.progress), FALSE);
	gtk_widget_set_visible (S.cancel_button, FALSE);
	set_status (text);
	update_actions ();
}

void
post_progress (double fraction, const std::string &text)
{
	static gint64 last;
	gint64 now = g_get_monotonic_time ();

	if (now - last < 100000)
		return;
	last = now;
	backend::ui ([fraction, text]
	{
		if (S.closing || !S.busy)
			return;
		gtk_progress_bar_set_fraction (S.progress, CLAMP (fraction, 0.0, 1.0));
		if (!text.empty ())
			set_status (text);
	});
}

chunk
read_chunk (const std::string &path, unsigned long long offset, size_t length)
{
	chunk out;
	rover_file *f = rover_file_open (path.c_str ());

	if (!f)
	{
		out.error = last_error ();
		return out;
	}
	out.size = rover_file_size (f);
	unsigned long long remain = offset < out.size ? out.size - offset : 0;
	size_t want = remain < length ? (size_t) remain : length;
	if (want && rover_file_seek (f, offset))
	{
		out.error = last_error ();
		rover_file_close (f);
		return out;
	}
	out.data.resize (want);
	size_t got = 0;
	while (got < want)
	{
		long long r = rover_file_read (f, out.data.data () + got, want - got);
		if (r < 0)
		{
			out.error = last_error ();
			break;
		}
		if (r == 0)
			break;
		got += (size_t) r;
	}
	out.data.resize (got);
	rover_file_close (f);
	return out;
}

/* ---- device list ---------------------------------------------------- */

namespace
{

int
collect_disk (const rover_disk_info *info, void *data)
{
	auto *rows = static_cast<std::vector<row_data> *> (data);
	row_data d;

	if (info->dev_id == ROVER_DEV_PROCFS)
		return 0;
	d.kind = row_kind::disk;
	d.name = info->name;
	d.is_partition = info->is_partition != 0;
	d.dev_id = info->dev_id;
	d.size = info->size;
	d.fs = info->fs ? info->fs : "";
	d.label = info->label ? info->label : "";
	d.fs_uuid = info->fs_uuid ? info->fs_uuid : "";
	d.start_lba = info->start_lba;
	d.sector_size = info->sector_size;
	d.encrypted = info->encrypted != 0;
	d.crypto_type = info->crypto_type ? info->crypto_type : "";
	d.crypto_uuid = info->crypto_uuid ? info->crypto_uuid : "";
	d.parent_file = info->parent_file ? info->parent_file : "";
	d.parents = info->parents ? info->parents : "";
	if (info->parent_device)
		d.parent = info->parent_device;
	else if (info->parent_file)
		d.parent = device_of (info->parent_file);
	if (d.dev_id == ROVER_DEV_POSIXFILE && !d.is_partition)
	{
		const char *host = rover_posixfile_get_path (info->name);
		if (host)
			d.parent_file = host;
	}
	rows->push_back (std::move (d));
	return 0;
}

/* Device a sidebar row nests under: a partition under its disk, an
   unlocked/lost/loop volume under the device it reads from.  */
std::string
owner_of (const row_data &d)
{
	if (d.is_partition)
	{
		size_t comma = d.name.rfind (',');
		if (comma != std::string::npos)
			return d.name.substr (0, comma);
	}
	return d.parent;
}

bool
natural_before (const row_data &a, const row_data &b)
{
	if (a.is_partition != b.is_partition)
		return a.is_partition;
	return rover_sort::natural_compare (a.name.c_str (), b.name.c_str ()) < 0;
}

void
emit_disk (std::vector<row_data> &rows, const std::vector<std::string> &owners,
	std::vector<bool> &used, size_t index, int depth, std::vector<row_data> &out)
{
	std::vector<size_t> children;

	used[index] = true;
	rows[index].depth = depth;
	out.push_back (rows[index]);
	for (size_t i = 0; i < rows.size (); i++)
		if (!used[i] && owners[i] == rows[index].name)
			children.push_back (i);
	std::sort (children.begin (), children.end (), [&rows] (size_t a, size_t b)
	{
		return natural_before (rows[a], rows[b]);
	});
	for (size_t i : children)
		if (!used[i])
			emit_disk (rows, owners, used, i, depth + 1, out);
}

/* rover_enum_disks() order, rearranged into a tree.  */
std::vector<row_data>
order_disks (std::vector<row_data> rows)
{
	std::vector<std::string> owners;
	std::vector<bool> used (rows.size (), false);
	std::vector<size_t> roots;
	std::vector<row_data> out;

	/* An unlocked source no longer reports its container type.  */
	for (const row_data &d : rows)
		if (d.dev_id == ROVER_DEV_CRYPTODISK && !d.parent.empty ())
			for (row_data &source : rows)
				if (source.name == d.parent && source.fs.empty () && source.crypto_type.empty ())
					source.crypto_type = _("encrypted");
	for (row_data &d : rows)
	{
		owners.push_back (owner_of (d));
		mount_active (d.name, &d.mountpoint);
	}
	for (size_t i = 0; i < rows.size (); i++)
	{
		bool orphan = true;
		for (const row_data &d : rows)
			if (d.name == owners[i])
				orphan = false;
		if (orphan)
			roots.push_back (i);
	}
	std::sort (roots.begin (), roots.end (), [&rows] (size_t a, size_t b)
	{
		return natural_before (rows[a], rows[b]);
	});
	for (size_t i : roots)
		if (!used[i])
			emit_disk (rows, owners, used, i, 0, out);
	for (size_t i = 0; i < rows.size (); i++)
		if (!used[i])
			emit_disk (rows, owners, used, i, 0, out);
	return out;
}

void
sync_disk_selection ()
{
	std::string device = device_of (S.cur_path);
	GListModel *model = G_LIST_MODEL (S.disks);
	guint n = g_list_model_get_n_items (model);
	guint found = GTK_INVALID_LIST_POSITION;

	for (guint i = 0; i < n && found == GTK_INVALID_LIST_POSITION; i++)
	{
		RoverRow *row = ROVER_ROW (g_list_model_get_item (model, i));
		if (rover_row_get (row).name == device)
			found = i;
		g_object_unref (row);
	}
	S.syncing_disks = true;
	gtk_single_selection_set_selected (S.disk_sel, found);
	S.syncing_disks = false;
}

} /* namespace */

void
select_disk (const std::string &name)
{
	GListModel *model = G_LIST_MODEL (S.disks);
	guint n = g_list_model_get_n_items (model);

	for (guint i = 0; i < n; i++)
	{
		RoverRow *row = ROVER_ROW (g_list_model_get_item (model, i));
		bool match = rover_row_get (row).name == name;
		g_object_unref (row);
		if (match)
		{
			S.syncing_disks = true;
			gtk_single_selection_set_selected (S.disk_sel, i);
			S.syncing_disks = false;
			return;
		}
	}
}

bool
find_disk (const std::string &name, row_data *out)
{
	GListModel *model = G_LIST_MODEL (S.disks);
	guint n = g_list_model_get_n_items (model);

	for (guint i = 0; i < n; i++)
	{
		RoverRow *row = ROVER_ROW (g_list_model_get_item (model, i));
		bool match = rover_row_get (row).name == name;
		if (match)
			*out = rover_row_get (row);
		g_object_unref (row);
		if (match)
			return true;
	}
	return false;
}

void
refresh_disks (std::function<void ()> then)
{
	run_job ([]
	{
		std::vector<row_data> rows;
		rover_enum_disks (collect_disk, &rows);
		return rows;
	},
	[then] (std::vector<row_data> rows)
	{
		std::vector<gpointer> items;
		for (const row_data &d : order_disks (std::move (rows)))
			items.push_back (rover_row_new (d));
		S.syncing_disks = true;
		g_list_store_splice (S.disks, 0, g_list_model_get_n_items (G_LIST_MODEL (S.disks)),
			items.data (), items.size ());
		S.syncing_disks = false;
		for (gpointer item : items)
			g_object_unref (item);
		sync_disk_selection ();
		update_actions ();
		if (then)
			then ();
	});
}

namespace
{

/* Open the readable volume decrypted (or otherwise derived) from NAME.  */
bool
enter_child (const std::string &name)
{
	GListModel *model = G_LIST_MODEL (S.disks);
	guint n = g_list_model_get_n_items (model);

	for (guint i = 0; i < n; i++)
	{
		RoverRow *row = ROVER_ROW (g_list_model_get_item (model, i));
		row_data d = rover_row_get (row);
		g_object_unref (row);
		if (d.parent == name && !d.fs.empty ())
		{
			navigate ("(" + d.name + ")/", true);
			return true;
		}
	}
	return false;
}

void
enter_disk (const row_data &d, bool force)
{
	if (!d.fs.empty ())
	{
		if (force || device_of (S.cur_path) != d.name)
			navigate ("(" + d.name + ")/", true);
	}
	else if (d.encrypted)
		show_unlock (d.name, d.crypto_type);
	else if (!enter_child (d.name))
		set_status (fmt (_("(%s) has no filesystem GRUB can read"), d.name.c_str ()));
}

} /* namespace */

/* After attaching or unlocking DEV, open the first readable volume on it.  */
void
auto_enter (const std::string &dev)
{
	GListModel *model = G_LIST_MODEL (S.disks);
	guint n = g_list_model_get_n_items (model);
	std::string prefix = dev + ",";

	for (int pass = 0; pass < 2; pass++)
		for (guint i = 0; i < n; i++)
		{
			RoverRow *row = ROVER_ROW (g_list_model_get_item (model, i));
			row_data d = rover_row_get (row);
			g_object_unref (row);
			if (d.name != dev && d.name.rfind (prefix, 0) != 0)
				continue;
			if (pass == 0 ? !d.fs.empty () : d.encrypted)
			{
				enter_disk (d, true);
				return;
			}
		}
	select_disk (dev);
	set_status (fmt (_("(%s) has no filesystem GRUB can read"), dev.c_str ()));
}

namespace
{

struct rc_result
{
	int rc;
	std::string error;
};

void
attach_image (const std::string &path, bool decompress)
{
	if (mount_contains (path))
	{
		show_error (fmt (_("Cannot open %s"), path.c_str ()),
			_("This file is inside a volume FsRover itself has mounted. Browse to it in "
			"FsRover and use \"Open as Disk Image\" instead."));
		return;
	}
	std::string name = "img" + std::to_string (S.next_image++);

	set_status (fmt (_("Opening %s…"), path.c_str ()));
	run_job ([name, path, decompress]
	{
		int rc = rover_posixfile_add (name.c_str (), path.c_str (), decompress);
		return rc_result { rc, rc ? last_error () : "" };
	},
	[name, path] (rc_result r)
	{
		if (r.rc)
		{
			set_status (fmt (_("Cannot open %s"), path.c_str ()));
			show_error (fmt (_("Cannot open %s"), path.c_str ()), r.error);
			return;
		}
		refresh_disks ([name] { auto_enter (name); });
	});
}

/* ---- directory view ------------------------------------------------- */

int
collect_entry (const rover_dirent *ent, void *data)
{
	auto *rows = static_cast<std::vector<row_data> *> (data);
	row_data d;

	d.name = ent->name;
	d.is_dir = ent->is_dir != 0;
	d.is_symlink = ent->is_symlink != 0;
	d.size_set = ent->size_set != 0;
	d.size = ent->size;
	d.mtime_set = ent->mtime_set != 0;
	d.mtime = ent->mtime;
	rows->push_back (std::move (d));
	return 0;
}

void
remember (const std::string &path, bool push)
{
	if (push && path != S.cur_path)
	{
		S.history.push_back (S.cur_path);
		S.forward.clear ();
	}
}

void
show_home (bool push)
{
	remember ("", push && !S.cur_path.empty ());
	S.cur_path.clear ();
	S.list_gen++;
	g_list_store_remove_all (S.entries);
	gtk_stack_set_visible_child_name (S.stack, "home");
	gtk_editable_set_text (GTK_EDITABLE (S.path_entry), "");
	sync_disk_selection ();
	set_status (_("Ready"));
	update_actions ();
}

/* Entries whose driver did not report a size get one from rover_stat(),
   in batches, so a large directory shows up before its sizes do.  */
void
start_size_pass (const std::string &dir, unsigned gen, const std::vector<row_data> &rows)
{
	auto todo = std::make_shared<std::vector<std::pair<guint, std::string>>> ();

	for (guint i = 0; i < rows.size (); i++)
		if (!rows[i].is_dir && !rows[i].is_symlink && !rows[i].size_set)
			todo->push_back ({ i, join_path (dir, rows[i].name) });
	if (todo->empty ())
		return;
	backend::post ([todo, gen]
	{
		std::vector<std::pair<guint, unsigned long long>> batch;
		auto flush = [&batch, gen]
		{
			if (batch.empty ())
				return;
			backend::ui ([batch, gen]
			{
				if (S.closing || gen != S.list_gen)
					return;
				for (const auto &[index, size] : batch)
				{
					gpointer item = g_list_model_get_item (G_LIST_MODEL (S.entries), index);
					if (!item)
						continue;
					rover_row_set_size (ROVER_ROW (item), size);
					g_object_unref (item);
				}
			});
			batch.clear ();
		};
		for (const auto &[index, path] : *todo)
		{
			if (gen != S.list_gen)
				return;
			rover_stat_t st = {};
			if (rover_stat (path.c_str (), &st) == 0 && !st.is_dir)
				batch.push_back ({ index, st.size });
			if (batch.size () >= 128)
				flush ();
		}
		flush ();
	});
}

void
show_listing (const std::string &path, bool push, const std::vector<row_data> &rows)
{
	std::vector<gpointer> items;
	size_t dirs = 0;

	remember (path, push);
	S.cur_path = path;
	for (const row_data &d : rows)
	{
		dirs += d.is_dir;
		items.push_back (rover_row_new (d));
	}
	g_list_store_splice (S.entries, 0, g_list_model_get_n_items (G_LIST_MODEL (S.entries)),
		items.data (), items.size ());
	for (gpointer item : items)
		g_object_unref (item);
	if (!items.empty ())
		gtk_column_view_scroll_to (S.entry_view, 0, nullptr, GTK_LIST_SCROLL_NONE, nullptr);
	gtk_stack_set_visible_child_name (S.stack, "entries");
	gtk_editable_set_text (GTK_EDITABLE (S.path_entry), path.c_str ());
	sync_disk_selection ();
	if (rows.empty ())
		set_status (_("Empty folder"));
	else
		set_status (fmt (_("%zu folders, %zu files"), dirs, rows.size () - dirs));
	update_actions ();
}

void open_file (const std::string &path);

struct listing
{
	std::string error;
	std::vector<row_data> rows;
};

} /* namespace */

void
navigate (const std::string &path, bool push, bool open_fallback)
{
	if (path.empty ())
	{
		show_home (push);
		return;
	}
	unsigned gen = ++S.list_gen;
	set_status (fmt (_("Loading %s…"), path.c_str ()));
	run_job ([path]
	{
		listing out;
		if (rover_dir_list (path.c_str (), collect_entry, &out.rows))
			out.error = last_error ();
		return out;
	},
	[path, gen, push, open_fallback] (listing out)
	{
		if (gen != S.list_gen)
			return;
		if (!out.error.empty ())
		{
			if (open_fallback)
			{
				open_file (path);
				return;
			}
			gtk_editable_set_text (GTK_EDITABLE (S.path_entry), S.cur_path.c_str ());
			set_status (path + ": " + out.error);
			return;
		}
		show_listing (path, push, out.rows);
		start_size_pass (path, gen, out.rows);
	});
}

namespace
{

/* ---- extraction and export ------------------------------------------ */

using extract_done = std::function<void (bool ok, const std::string &summary)>;

void
run_extract (const std::vector<std::string> &sources, const std::string &dest,
	extract_done done)
{
	bool preserve = S.preserve_times;

	backend::post ([sources, dest, done, preserve]
	{
		rover_extract::options opts;
		rover_extract::result stats;
		std::string error;

		opts.preserve_times = preserve;
		opts.cancelled = [] { return S.cancel.load (); };
		opts.report_progress = [] (const rover_extract::progress &p)
		{
			double fraction = p.file_total
				? (p.file_index + p.percent / 100.0) / p.file_total
				: p.percent / 100.0;
			post_progress (fraction, fmt (_("Extracting %s"), p.source.c_str ()));
		};
		bool ok = rover_extract::extract (sources, dest, opts, &stats, &error);
		std::string summary;
		if (S.cancel)
			summary = _("Cancelled");
		else if (!ok)
			summary = fmt (_("Failed: %s"), error.c_str ());
		else
			summary = fmt (g_dngettext (nullptr, "%llu file, %s", "%llu files, %s", stats.files),
				stats.files, format_size (stats.bytes).c_str ());
		if (!stats.errors.empty ())
			summary += " " + fmt (g_dngettext (nullptr, "(%zu error)", "(%zu errors)",
				stats.errors.size ()), stats.errors.size ());
		ok = ok && !S.cancel;
		backend::ui ([done, ok, summary]
		{
			if (!S.closing)
				done (ok, summary);
		});
	});
}

/* A file dialog returned nothing: report it unless the user just closed it.  */
void
report_dialog_error (GError *error)
{
	if (!error)
		return;
	if (!S.closing && !g_error_matches (error, GTK_DIALOG_ERROR, GTK_DIALOG_ERROR_DISMISSED)
		&& !g_error_matches (error, GTK_DIALOG_ERROR, GTK_DIALOG_ERROR_CANCELLED))
		set_status (fmt (_("File dialog failed: %s"), error->message));
	g_error_free (error);
}

/* Local path of a dialog result, or empty (and an error shown).  */
std::string
local_path (GFile *file)
{
	char *path = g_file_get_path (file);
	std::string out = path ? path : "";

	g_free (path);
	g_object_unref (file);
	if (out.empty ())
		show_error (_("Not a local path"), _("Choose a file or folder on this computer."));
	return out;
}

void
on_extract_folder (GObject *source, GAsyncResult *result, gpointer data)
{
	std::unique_ptr<std::vector<std::string>> sources (
		static_cast<std::vector<std::string> *> (data));
	GError *error = nullptr;
	GFile *folder = gtk_file_dialog_select_folder_finish (GTK_FILE_DIALOG (source),
		result, &error);

	if (!folder)
	{
		report_dialog_error (error);
		return;
	}
	std::string dest = local_path (folder);
	if (dest.empty () || !begin_job (fmt (_("Extracting to %s…"), dest.c_str ())))
		return;
	run_extract (*sources, dest, [dest] (bool, const std::string &summary)
	{
		end_job (fmt (_("Extract to %s: %s"), dest.c_str (), summary.c_str ()));
	});
}

void
on_launched (GObject *source, GAsyncResult *result, gpointer)
{
	GError *error = nullptr;

	if (!gtk_file_launcher_launch_finish (GTK_FILE_LAUNCHER (source), result, &error))
	{
		if (!S.closing && !g_error_matches (error, GTK_DIALOG_ERROR, GTK_DIALOG_ERROR_DISMISSED))
			set_status (fmt (_("Cannot open: %s"), error->message));
		g_error_free (error);
	}
}

/* Extract one file into a private cache directory and hand it to the
   desktop's default application.  */
void
open_file (const std::string &path)
{
	std::string base = std::string (g_get_user_cache_dir ()) + "/fsrover/open";
	std::string dir = base + "/XXXXXX";

	if (g_mkdir_with_parents (base.c_str (), 0700) != 0
		|| !g_mkdtemp_full (dir.data (), 0700))
	{
		set_status (fmt (_("Cannot create a temporary directory in %s"), base.c_str ()));
		return;
	}
	if (!begin_job (fmt (_("Opening %s…"), path.c_str ())))
		return;
	run_extract ({ path }, dir, [dir, path] (bool ok, const std::string &summary)
	{
		end_job (ok ? fmt (_("Opened %s"), basename_of (path).c_str ())
			: fmt (_("Open %s: %s"), path.c_str (), summary.c_str ()));
		if (!ok)
			return;
		GDir *handle = g_dir_open (dir.c_str (), 0, nullptr);
		const char *name = handle ? g_dir_read_name (handle) : nullptr;
		if (name)
		{
			std::string target = dir + "/" + name;
			GFile *file = g_file_new_for_path (target.c_str ());
			GtkFileLauncher *launcher = gtk_file_launcher_new (file);
			gtk_file_launcher_launch (launcher, S.window, nullptr, on_launched, nullptr);
			g_object_unref (launcher);
			g_object_unref (file);
		}
		if (handle)
			g_dir_close (handle);
	});
}

struct export_result
{
	std::string error;
	unsigned long long bytes = 0;
};

/* Copy the raw device into a sibling temporary file and rename it over
   DEST only once complete: a failed or cancelled export never truncates
   an existing destination.  */
export_result
export_device (const std::string &device, const std::string &dest)
{
	export_result out;
	std::string src = "(" + device + ")0+";
	std::string temp = dest.substr (0, dest.rfind ('/') + 1) + ".fsrover-XXXXXX.tmp";
	std::vector<char> buf ((size_t) 1 << 20);
	unsigned long long total;
	rover_file *f;
	int fd;

	f = rover_file_open (src.c_str ());
	if (!f)
	{
		out.error = last_error ();
		return out;
	}
	total = rover_file_size (f);
	fd = g_mkstemp_full (temp.data (), O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0)
	{
		out.error = fmt (_("Cannot create %s: %s"), temp.c_str (), g_strerror (errno));
		goto fail;
	}
	while (out.bytes < total && !S.cancel)
	{
		size_t want = (size_t) std::min<unsigned long long> (buf.size (), total - out.bytes);
		long long r = rover_file_read (f, buf.data (), want);
		if (r < 0)
		{
			out.error = last_error ();
			break;
		}
		if (r == 0)
		{
			out.error = _("The device ended before its reported size");
			break;
		}
		for (long long done = 0; done < r;)
		{
			ssize_t w = write (fd, buf.data () + done, (size_t) (r - done));
			if (w < 0 && errno == EINTR)
				continue;
			if (w <= 0)
			{
				out.error = fmt (_("Write failed: %s"), g_strerror (errno));
				break;
			}
			done += w;
		}
		if (!out.error.empty ())
			break;
		out.bytes += (unsigned long long) r;
		post_progress (total ? (double) out.bytes / total : 1.0,
			fmt (_("Exporting (%s): %s of %s"), device.c_str (),
				format_size (out.bytes).c_str (), format_size (total).c_str ()));
	}
	if (out.error.empty () && S.cancel)
		out.error = _("Cancelled");
	if (out.error.empty () && fsync (fd) != 0)
		out.error = fmt (_("Cannot flush %s: %s"), temp.c_str (), g_strerror (errno));
	if (close (fd) != 0 && out.error.empty ())
		out.error = fmt (_("Cannot close %s: %s"), temp.c_str (), g_strerror (errno));
	if (out.error.empty () && rename (temp.c_str (), dest.c_str ()) != 0)
		out.error = fmt (_("Cannot replace %s: %s"), dest.c_str (), g_strerror (errno));
	if (!out.error.empty ())
		unlink (temp.c_str ());
fail:
	rover_file_close (f);
	return out;
}

void
on_export_chosen (GObject *source, GAsyncResult *result, gpointer data)
{
	std::unique_ptr<std::string> device (static_cast<std::string *> (data));
	GError *error = nullptr;
	GFile *file = gtk_file_dialog_save_finish (GTK_FILE_DIALOG (source), result, &error);

	if (!file)
	{
		report_dialog_error (error);
		return;
	}
	std::string dest = local_path (file);
	std::string dev = *device;
	if (dest.empty () || !begin_job (fmt (_("Exporting (%s)…"), dev.c_str ())))
		return;
	run_job ([dev, dest] { return export_device (dev, dest); },
		[dev, dest] (export_result r)
	{
		if (r.error.empty ())
			end_job (fmt (_("Exported (%s) to %s, %s"), dev.c_str (), dest.c_str (),
				format_exact (r.bytes).c_str ()));
		else
		{
			end_job (fmt (_("Export of (%s) failed"), dev.c_str ()));
			if (r.error != _("Cancelled"))
				show_error (fmt (_("Cannot export (%s)"), dev.c_str ()), r.error);
		}
	});
}

/* ---- actions -------------------------------------------------------- */

void
on_open_image_chosen (GObject *source, GAsyncResult *result, gpointer decompress)
{
	GError *error = nullptr;
	GFile *file = gtk_file_dialog_open_finish (GTK_FILE_DIALOG (source), result, &error);

	if (!file)
	{
		report_dialog_error (error);
		return;
	}
	std::string path = local_path (file);
	if (!path.empty ())
		attach_image (path, GPOINTER_TO_INT (decompress) != 0);
}

void
choose_image (bool decompress)
{
	GtkFileDialog *dialog = gtk_file_dialog_new ();

	gtk_file_dialog_set_title (dialog, decompress ? _("Open Compressed Disk Image")
		: _("Open Disk Image"));
	gtk_file_dialog_open (dialog, S.window, nullptr, on_open_image_chosen,
		GINT_TO_POINTER (decompress));
	g_object_unref (dialog);
}

void
act_open_image (GSimpleAction *, GVariant *, gpointer)
{
	choose_image (false);
}

void
act_open_image_dec (GSimpleAction *, GVariant *, gpointer)
{
	choose_image (true);
}

void
act_refresh (GSimpleAction *, GVariant *, gpointer)
{
	refresh_disks (nullptr);
	if (!S.cur_path.empty ())
		navigate (S.cur_path, false);
}

void
act_back (GSimpleAction *, GVariant *, gpointer)
{
	if (S.history.empty ())
		return;
	std::string path = S.history.back ();
	S.history.pop_back ();
	S.forward.push_back (S.cur_path);
	navigate (path, false);
}

void
act_forward (GSimpleAction *, GVariant *, gpointer)
{
	if (S.forward.empty ())
		return;
	std::string path = S.forward.back ();
	S.forward.pop_back ();
	S.history.push_back (S.cur_path);
	navigate (path, false);
}

void
act_up (GSimpleAction *, GVariant *, gpointer)
{
	if (!S.cur_path.empty ())
		navigate (parent_path (S.cur_path), true);
}

void
act_focus_path (GSimpleAction *, GVariant *, gpointer)
{
	gtk_widget_grab_focus (GTK_WIDGET (S.path_entry));
}

void
act_extract (GSimpleAction *, GVariant *, gpointer)
{
	std::vector<std::string> paths = selected_paths ();

	if (paths.empty ())
		return;
	GtkFileDialog *dialog = gtk_file_dialog_new ();
	gtk_file_dialog_set_title (dialog, _("Extract To"));
	gtk_file_dialog_select_folder (dialog, S.window, nullptr, on_extract_folder,
		new std::vector<std::string> (std::move (paths)));
	g_object_unref (dialog);
}

void
act_open (GSimpleAction *, GVariant *, gpointer)
{
	std::vector<row_data> rows = selected_rows ();

	if (rows.size () != 1)
		return;
	std::string path = join_path (S.cur_path, rows[0].name);
	if (rows[0].is_dir || rows[0].is_symlink)
		navigate (path, true, rows[0].is_symlink);
	else
		open_file (path);
}

void
open_as_image (bool decompress)
{
	std::string path;

	if (!selected_file (&path))
		return;
	std::string name = "loop" + std::to_string (S.next_loop++);
	run_job ([name, path, decompress]
	{
		int rc = rover_loopback_add (name.c_str (), path.c_str (), decompress);
		return rc_result { rc, rc ? last_error () : "" };
	},
	[name, path] (rc_result r)
	{
		if (r.rc)
		{
			show_error (fmt (_("Cannot open %s as a disk image"), basename_of (path).c_str ()),
				r.error);
			return;
		}
		refresh_disks ([name] { auto_enter (name); });
	});
}

void
act_open_as_image (GSimpleAction *, GVariant *, gpointer)
{
	open_as_image (false);
}

void
act_open_as_image_dec (GSimpleAction *, GVariant *, gpointer)
{
	open_as_image (true);
}

void
act_view_text (GSimpleAction *, GVariant *, gpointer)
{
	std::string path;

	if (selected_file (&path))
		show_text (path);
}

void
act_view_hex (GSimpleAction *, GVariant *, gpointer)
{
	std::string path;

	if (selected_file (&path))
		show_hex (path, basename_of (path));
}

void
act_view_image (GSimpleAction *, GVariant *, gpointer)
{
	std::string path;

	if (selected_file (&path))
		show_image (path);
}

void
act_view_markdown (GSimpleAction *, GVariant *, gpointer)
{
	std::string path;

	if (selected_file (&path))
		show_markdown_file (path);
}

void
act_file_map (GSimpleAction *, GVariant *, gpointer)
{
	std::string path;

	if (selected_file (&path))
		show_file_map (path);
}

void
act_file_props (GSimpleAction *, GVariant *, gpointer)
{
	std::vector<std::string> paths = selected_paths ();

	if (paths.size () == 1)
		show_file_props (paths[0]);
}

void
act_copy_name (GSimpleAction *, GVariant *, gpointer)
{
	std::string text;

	for (const row_data &d : selected_rows ())
		text += (text.empty () ? "" : "\n") + d.name;
	copy_text (text);
}

void
act_copy_path (GSimpleAction *, GVariant *, gpointer)
{
	std::string text;

	for (const std::string &path : selected_paths ())
		text += (text.empty () ? "" : "\n") + path;
	copy_text (text);
}

void
act_select_all (GSimpleAction *, GVariant *, gpointer)
{
	gtk_selection_model_select_all (GTK_SELECTION_MODEL (S.entry_sel));
}

void
act_select_invert (GSimpleAction *, GVariant *, gpointer)
{
	GtkSelectionModel *model = GTK_SELECTION_MODEL (S.entry_sel);
	guint n = g_list_model_get_n_items (G_LIST_MODEL (model));
	GtkBitset *selected = gtk_selection_model_get_selection (model);
	GtkBitset *mask = gtk_bitset_new_range (0, n);
	GtkBitset *inverted = gtk_bitset_copy (mask);

	gtk_bitset_subtract (inverted, selected);
	gtk_selection_model_set_selection (model, inverted, mask);
	gtk_bitset_unref (inverted);
	gtk_bitset_unref (mask);
	gtk_bitset_unref (selected);
}

void
act_preserve_times (GSimpleAction *action, GVariant *value, gpointer)
{
	g_simple_action_set_state (action, value);
	S.preserve_times = g_variant_get_boolean (value);
}

void
act_disk_browse (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		enter_disk (d, true);
}

void
act_disk_mount (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		show_mount (d);
}

void
act_disk_unmount (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		mount_stop (d.name);
}

void
act_unlock (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		show_unlock (d.name, d.crypto_type);
}

void
act_veracrypt (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		show_veracrypt (d.name);
}

void
act_plain_unlock (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		show_plain_unlock (d.name);
}

void
act_disk_hex (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		show_hex ("(" + d.name + ")0+", "(" + d.name + ")");
}

void
act_export_image (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (!selected_disk (&d))
		return;
	std::string name = d.name;
	std::replace (name.begin (), name.end (), ',', '_');
	std::replace (name.begin (), name.end (), '/', '_');
	GtkFileDialog *dialog = gtk_file_dialog_new ();
	gtk_file_dialog_set_title (dialog, fmt (_("Export (%s) as Raw Image"), d.name.c_str ()).c_str ());
	gtk_file_dialog_set_initial_name (dialog, (name + ".img").c_str ());
	gtk_file_dialog_save (dialog, S.window, nullptr, on_export_chosen, new std::string (d.name));
	g_object_unref (dialog);
}

void
act_lost_scan (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		show_lost_scan (d.name);
}

void
act_disk_props (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (selected_disk (&d))
		show_disk_props (d);
}

void
act_detach (GSimpleAction *, GVariant *, gpointer)
{
	row_data d;

	if (!selected_disk (&d))
		return;
	if (!is_detachable (d))
	{
		set_status (_("Only attached images and lost partitions can be detached"));
		return;
	}
	std::string name = d.name;
	int dev_id = d.dev_id;
	std::string cur = device_of (S.cur_path);
	if (mount_active (name, nullptr))
	{
		show_error (fmt (_("Cannot detach (%s)"), name.c_str ()), _("Unmount it first."));
		return;
	}
	if (cur == name || cur.rfind (name + ",", 0) == 0)
	{
		S.history.clear ();
		S.forward.clear ();
		show_home (false);
	}
	run_job ([name, dev_id]
	{
		int rc = dev_id == ROVER_DEV_POSIXFILE ? rover_posixfile_del (name.c_str ())
			: dev_id == ROVER_DEV_LOOPBACK ? rover_loopback_del (name.c_str ())
			: rover_lost_del (name.c_str ());
		return rc_result { rc, rc ? last_error () : "" };
	},
	[name] (rc_result r)
	{
		if (r.rc)
			show_error (fmt (_("Cannot detach (%s)"), name.c_str ()), r.error);
		else
			set_status (fmt (_("Detached (%s)"), name.c_str ()));
		refresh_disks (nullptr);
	});
}

void
act_host_access (GSimpleAction *, GVariant *, gpointer)
{
	hostdisk_request_access ();
}

void
act_encoding (GSimpleAction *action, GVariant *value, gpointer)
{
	unsigned encoding = static_cast<unsigned> (
		g_ascii_strtoull (g_variant_get_string (value, nullptr), nullptr, 10));

	g_simple_action_set_state (action, value);
	S.fs_encoding = encoding;
	backend::post ([encoding]
	{
		rover_set_fs_char_encoding (encoding);
	});
	mount_invalidate_all ();
	act_refresh (nullptr, nullptr, nullptr);
}

void
act_help (GSimpleAction *, GVariant *, gpointer)
{
	show_help ();
}

void
act_shortcuts (GSimpleAction *, GVariant *, gpointer)
{
	static const char *const ui =
		"<interface>"
		"<object class='GtkShortcutsWindow' id='w'><property name='modal'>1</property>"
		"<child><object class='GtkShortcutsSection'>"
		"<child><object class='GtkShortcutsGroup'><property name='title' translatable='yes'>Navigation</property>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Alt&gt;Left</property><property name='title' translatable='yes'>Back</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Alt&gt;Right</property><property name='title' translatable='yes'>Forward</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Alt&gt;Up</property><property name='title' translatable='yes'>Up one level</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Control&gt;l</property><property name='title' translatable='yes'>Edit the path</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>F5</property><property name='title' translatable='yes'>Refresh</property></object></child>"
		"</object></child>"
		"<child><object class='GtkShortcutsGroup'><property name='title' translatable='yes'>Files</property>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Control&gt;o</property><property name='title' translatable='yes'>Open a disk image</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Control&gt;e</property><property name='title' translatable='yes'>Extract the selection</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Control&gt;a</property><property name='title' translatable='yes'>Select all</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Alt&gt;Return</property><property name='title' translatable='yes'>Properties</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>F3</property><property name='title' translatable='yes'>View as text</property></object></child>"
		"<child><object class='GtkShortcutsShortcut'><property name='accelerator'>&lt;Control&gt;h</property><property name='title' translatable='yes'>View as hex</property></object></child>"
		"</object></child>"
		"</object></child></object></interface>";
	/* The titles above, for xgettext, which does not look inside the XML.  */
	static const char *const titles[] G_GNUC_UNUSED =
	{
		N_("Navigation"), N_("Back"), N_("Forward"), N_("Up one level"), N_("Edit the path"),
		N_("Refresh"), N_("Files"), N_("Open a disk image"), N_("Extract the selection"),
		N_("Select all"), N_("Properties"), N_("View as text"), N_("View as hex")
	};
	GtkBuilder *builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);
	gtk_builder_add_from_string (builder, ui, -1, nullptr);
	GtkWindow *window = GTK_WINDOW (gtk_builder_get_object (builder, "w"));
	gtk_window_set_transient_for (window, S.window);
	gtk_window_present (window);
	g_object_unref (builder);
}

void
act_about (GSimpleAction *, GVariant *, gpointer)
{
	gtk_show_about_dialog (S.window,
		"program-name", "FsRover",
		"comments", _("Read-only filesystem browser built on GRUB drivers."),
		"license-type", GTK_LICENSE_GPL_3_0,
		"logo-icon-name", "drive-harddisk",
		"copyright", "Copyright © 2026 A1ive",
		"translator-credits", _("translator-credits"),
		nullptr);
}

const GActionEntry window_actions[] =
{
	{ "open-image", act_open_image, nullptr, nullptr, nullptr, { 0 } },
	{ "open-image-dec", act_open_image_dec, nullptr, nullptr, nullptr, { 0 } },
	{ "refresh", act_refresh, nullptr, nullptr, nullptr, { 0 } },
	{ "back", act_back, nullptr, nullptr, nullptr, { 0 } },
	{ "forward", act_forward, nullptr, nullptr, nullptr, { 0 } },
	{ "up", act_up, nullptr, nullptr, nullptr, { 0 } },
	{ "focus-path", act_focus_path, nullptr, nullptr, nullptr, { 0 } },
	{ "extract", act_extract, nullptr, nullptr, nullptr, { 0 } },
	{ "open", act_open, nullptr, nullptr, nullptr, { 0 } },
	{ "open-as-image", act_open_as_image, nullptr, nullptr, nullptr, { 0 } },
	{ "open-as-image-dec", act_open_as_image_dec, nullptr, nullptr, nullptr, { 0 } },
	{ "view-text", act_view_text, nullptr, nullptr, nullptr, { 0 } },
	{ "view-hex", act_view_hex, nullptr, nullptr, nullptr, { 0 } },
	{ "view-image", act_view_image, nullptr, nullptr, nullptr, { 0 } },
	{ "view-markdown", act_view_markdown, nullptr, nullptr, nullptr, { 0 } },
	{ "file-map", act_file_map, nullptr, nullptr, nullptr, { 0 } },
	{ "file-props", act_file_props, nullptr, nullptr, nullptr, { 0 } },
	{ "copy-name", act_copy_name, nullptr, nullptr, nullptr, { 0 } },
	{ "copy-path", act_copy_path, nullptr, nullptr, nullptr, { 0 } },
	{ "select-all", act_select_all, nullptr, nullptr, nullptr, { 0 } },
	{ "select-invert", act_select_invert, nullptr, nullptr, nullptr, { 0 } },
	{ "preserve-times", nullptr, nullptr, "true", act_preserve_times, { 0 } },
	{ "disk-browse", act_disk_browse, nullptr, nullptr, nullptr, { 0 } },
	{ "disk-mount", act_disk_mount, nullptr, nullptr, nullptr, { 0 } },
	{ "disk-unmount", act_disk_unmount, nullptr, nullptr, nullptr, { 0 } },
	{ "unlock", act_unlock, nullptr, nullptr, nullptr, { 0 } },
	{ "veracrypt", act_veracrypt, nullptr, nullptr, nullptr, { 0 } },
	{ "plain-unlock", act_plain_unlock, nullptr, nullptr, nullptr, { 0 } },
	{ "disk-hex", act_disk_hex, nullptr, nullptr, nullptr, { 0 } },
	{ "export-image", act_export_image, nullptr, nullptr, nullptr, { 0 } },
	{ "lost-scan", act_lost_scan, nullptr, nullptr, nullptr, { 0 } },
	{ "disk-props", act_disk_props, nullptr, nullptr, nullptr, { 0 } },
	{ "detach", act_detach, nullptr, nullptr, nullptr, { 0 } },
	{ "host-access", act_host_access, nullptr, nullptr, nullptr, { 0 } },
	{ "encoding", nullptr, "s", "'65001'", act_encoding, { 0 } },
	{ "help", act_help, nullptr, nullptr, nullptr, { 0 } },
	{ "shortcuts", act_shortcuts, nullptr, nullptr, nullptr, { 0 } },
	{ "about", act_about, nullptr, nullptr, nullptr, { 0 } },
};

/* ---- list widgets --------------------------------------------------- */

/* Bind TARGET of WIDGET to property SOURCE of the row shown by ITEM.  */
void
bind_row (GtkListItem *item, GtkWidget *widget, const char *target, const char *source)
{
	GtkExpression *expr = gtk_property_expression_new (GTK_TYPE_LIST_ITEM, nullptr, "item");

	expr = gtk_property_expression_new (ROVER_TYPE_ROW, expr, source);
	gtk_expression_bind (expr, widget, target, item);
}

void
on_cell_pressed (GtkGestureClick *gesture, int, double x, double y, gpointer data)
{
	bool disks = GPOINTER_TO_INT (data) != 0;
	GtkListItem *item = GTK_LIST_ITEM (g_object_get_data (G_OBJECT (gesture), "rover-item"));
	guint pos = gtk_list_item_get_position (item);
	GtkSelectionModel *model = disks ? GTK_SELECTION_MODEL (S.disk_sel)
		: GTK_SELECTION_MODEL (S.entry_sel);
	GtkWidget *anchor = disks ? GTK_WIDGET (S.disk_view) : GTK_WIDGET (S.entry_view);
	GtkWidget *menu = disks ? S.disk_menu : S.entry_menu;
	GtkWidget *cell = gtk_event_controller_get_widget (GTK_EVENT_CONTROLLER (gesture));
	graphene_point_t in = GRAPHENE_POINT_INIT ((float) x, (float) y);
	graphene_point_t out;

	if (pos == GTK_INVALID_LIST_POSITION)
		return;
	if (!gtk_selection_model_is_selected (model, pos))
	{
		S.syncing_disks = disks;
		gtk_selection_model_select_item (model, pos, TRUE);
		S.syncing_disks = false;
		update_actions ();
	}
	if (!gtk_widget_compute_point (cell, anchor, &in, &out))
		return;
	GdkRectangle rect = { (int) out.x, (int) out.y, 1, 1 };
	gtk_popover_set_pointing_to (GTK_POPOVER (menu), &rect);
	gtk_popover_popup (GTK_POPOVER (menu));
}

void
add_context_gesture (GtkWidget *cell, GtkListItem *item, bool disks)
{
	GtkGesture *gesture = gtk_gesture_click_new ();

	gtk_gesture_single_set_button (GTK_GESTURE_SINGLE (gesture), GDK_BUTTON_SECONDARY);
	g_object_set_data (G_OBJECT (gesture), "rover-item", item);
	g_signal_connect (gesture, "pressed", G_CALLBACK (on_cell_pressed), GINT_TO_POINTER (disks));
	gtk_widget_add_controller (cell, GTK_EVENT_CONTROLLER (gesture));
}

void
setup_disk_cell (GtkSignalListItemFactory *, GObject *object, gpointer)
{
	GtkListItem *item = GTK_LIST_ITEM (object);
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *image = gtk_image_new ();
	GtkWidget *title = gtk_label_new (nullptr);
	GtkWidget *subtitle = gtk_label_new (nullptr);

	gtk_image_set_icon_size (GTK_IMAGE (image), GTK_ICON_SIZE_LARGE);
	gtk_widget_set_valign (text, GTK_ALIGN_CENTER);
	gtk_label_set_xalign (GTK_LABEL (title), 0);
	gtk_label_set_ellipsize (GTK_LABEL (title), PANGO_ELLIPSIZE_END);
	gtk_label_set_xalign (GTK_LABEL (subtitle), 0);
	gtk_label_set_ellipsize (GTK_LABEL (subtitle), PANGO_ELLIPSIZE_END);
	gtk_widget_add_css_class (subtitle, "dim-label");
	gtk_widget_add_css_class (subtitle, "caption");
	gtk_widget_set_margin_top (box, 3);
	gtk_widget_set_margin_bottom (box, 3);
	gtk_box_append (GTK_BOX (text), title);
	gtk_box_append (GTK_BOX (text), subtitle);
	gtk_box_append (GTK_BOX (box), image);
	gtk_box_append (GTK_BOX (box), text);
	bind_row (item, image, "gicon", "icon");
	bind_row (item, title, "label", "title");
	bind_row (item, subtitle, "label", "subtitle");
	bind_row (item, box, "margin-start", "indent");
	add_context_gesture (box, item, true);
	gtk_list_item_set_child (item, box);
}

void
setup_name_cell (GtkSignalListItemFactory *, GObject *object, gpointer)
{
	GtkListItem *item = GTK_LIST_ITEM (object);
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *image = gtk_image_new ();
	GtkWidget *label = gtk_label_new (nullptr);

	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_MIDDLE);
	gtk_widget_set_hexpand (label, TRUE);
	gtk_box_append (GTK_BOX (box), image);
	gtk_box_append (GTK_BOX (box), label);
	bind_row (item, image, "gicon", "icon");
	bind_row (item, label, "label", "title");
	add_context_gesture (box, item, false);
	gtk_list_item_set_child (item, box);
}

struct text_column
{
	const char *property;
	float xalign;
};

const text_column size_spec = { "size-text", 1.0f };
const text_column mtime_spec = { "mtime-text", 0.0f };
const text_column type_spec = { "type-text", 0.0f };

void
setup_text_cell (GtkSignalListItemFactory *, GObject *object, gpointer data)
{
	const text_column *spec = static_cast<const text_column *> (data);
	GtkListItem *item = GTK_LIST_ITEM (object);
	GtkWidget *label = gtk_label_new (nullptr);

	gtk_label_set_xalign (GTK_LABEL (label), spec->xalign);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	if (spec->xalign > 0.5f)
		gtk_widget_add_css_class (label, "numeric");
	bind_row (item, label, "label", spec->property);
	add_context_gesture (label, item, false);
	gtk_list_item_set_child (item, label);
}

const row_data &
row_of (gconstpointer item)
{
	return rover_row_get (ROVER_ROW (const_cast<gpointer> (item)));
}

template <typename T>
int
order (const T &a, const T &b)
{
	return a < b ? -1 : b < a ? 1 : 0;
}

int
compare_dirs_first (gconstpointer a, gconstpointer b, gpointer)
{
	return order (!row_of (a).is_dir, !row_of (b).is_dir);
}

int
compare_name (gconstpointer a, gconstpointer b, gpointer)
{
	return rover_sort::natural_compare (row_of (a).name.c_str (), row_of (b).name.c_str ());
}

int
compare_size (gconstpointer a, gconstpointer b, gpointer)
{
	const row_data &x = row_of (a);
	const row_data &y = row_of (b);
	int rc = order (x.size_set ? x.size : 0, y.size_set ? y.size : 0);

	return rc ? rc : compare_name (a, b, nullptr);
}

int
compare_mtime (gconstpointer a, gconstpointer b, gpointer)
{
	const row_data &x = row_of (a);
	const row_data &y = row_of (b);
	int rc = order (x.mtime_set ? x.mtime : 0LL, y.mtime_set ? y.mtime : 0LL);

	return rc ? rc : compare_name (a, b, nullptr);
}

int
compare_type (gconstpointer a, gconstpointer b, gpointer)
{
	const std::string &x = row_of (a).name;
	const std::string &y = row_of (b).name;
	size_t xdot = x.rfind ('.');
	size_t ydot = y.rfind ('.');
	int rc = g_ascii_strcasecmp (xdot == std::string::npos ? "" : x.c_str () + xdot,
		ydot == std::string::npos ? "" : y.c_str () + ydot);

	return rc ? rc : compare_name (a, b, nullptr);
}

GtkColumnViewColumn *
add_column (const char *title, GCallback setup, gconstpointer data,
	GCompareDataFunc compare, bool expand, int width)
{
	GtkListItemFactory *factory = gtk_signal_list_item_factory_new ();
	GtkSorter *sorter = GTK_SORTER (gtk_custom_sorter_new (compare, nullptr, nullptr));
	GtkColumnViewColumn *column;

	g_signal_connect (factory, "setup", setup, const_cast<gpointer> (data));
	column = gtk_column_view_column_new (title, factory);
	gtk_column_view_column_set_sorter (column, sorter);
	g_object_unref (sorter);
	gtk_column_view_column_set_resizable (column, TRUE);
	gtk_column_view_column_set_expand (column, expand);
	if (width > 0)
		gtk_column_view_column_set_fixed_width (column, width);
	gtk_column_view_append_column (S.entry_view, column);
	g_object_unref (column);
	return column;
}

void
on_entry_activate (GtkColumnView *, guint pos, gpointer)
{
	RoverRow *row = ROVER_ROW (g_list_model_get_item (G_LIST_MODEL (S.entry_sel), pos));
	row_data d = rover_row_get (row);
	std::string path = join_path (S.cur_path, d.name);

	g_object_unref (row);
	if (d.is_dir || d.is_symlink)
		navigate (path, true, d.is_symlink);
	else
		open_file (path);
}

/* Runs from idle, not from the click: entering a locked volume opens a modal
   dialog, which must not grab the pointer in the middle of the list view's
   press/release sequence.  */
gboolean
enter_selected_disk (gpointer force)
{
	row_data d;

	if (!S.closing && selected_disk (&d))
		enter_disk (d, GPOINTER_TO_INT (force) != 0);
	return G_SOURCE_REMOVE;
}

void
on_disk_selected (GtkSelectionModel *, guint, guint, gpointer)
{
	update_actions ();
	if (!S.syncing_disks)
		g_idle_add (enter_selected_disk, GINT_TO_POINTER (FALSE));
}

void
on_disk_activate (GtkListView *, guint, gpointer)
{
	g_idle_add (enter_selected_disk, GINT_TO_POINTER (TRUE));
}

void
on_entry_selection (GtkSelectionModel *, guint, guint, gpointer)
{
	update_actions ();
}

void
on_path_activate (GtkEntry *entry, gpointer)
{
	std::string path = gtk_editable_get_text (GTK_EDITABLE (entry));

	if (!path.empty () && path[0] != '(')
		path = "(" + path + ")/";
	navigate (path, true);
}

void
on_cancel (GtkButton *, gpointer)
{
	S.cancel = true;
	set_status (_("Cancelling…"));
}

void
on_view_destroy (GtkWidget *, gpointer menu)
{
	gtk_widget_unparent (GTK_WIDGET (menu));
}

GtkWidget *
make_popover (GMenuModel *model, GtkWidget *parent)
{
	GtkWidget *menu = gtk_popover_menu_new_from_model (model);

	gtk_popover_set_has_arrow (GTK_POPOVER (menu), FALSE);
	gtk_widget_set_halign (menu, GTK_ALIGN_START);
	gtk_widget_set_parent (menu, parent);
	g_signal_connect (parent, "destroy", G_CALLBACK (on_view_destroy), menu);
	return menu;
}

/* Sections given as { label, action } lists; a null label ends a section.  */
struct menu_item
{
	const char *label;
	const char *action;
};

GMenu *
build_sections (std::initializer_list<std::initializer_list<menu_item>> sections)
{
	GMenu *menu = g_menu_new ();

	for (const auto &items : sections)
	{
		GMenu *section = g_menu_new ();
		for (const menu_item &item : items)
			g_menu_append (section, _(item.label), item.action);
		g_menu_append_section (menu, nullptr, G_MENU_MODEL (section));
		g_object_unref (section);
	}
	return menu;
}

GMenuModel *
build_main_menu ()
{
	GMenu *menu = build_sections ({
		{ { N_("Open Disk Image…"), "win.open-image" },
		  { N_("Open Compressed Disk Image…"), "win.open-image-dec" },
		  { N_("Access Physical Disks…"), "win.host-access" },
		  { N_("Refresh"), "win.refresh" } },
		{ { N_("Select All"), "win.select-all" },
		  { N_("Invert Selection"), "win.select-invert" } },
	});
	GMenu *settings = g_menu_new ();
	GMenu *encoding = g_menu_new ();
	GMenu *help = build_sections ({
		{ { N_("Help"), "win.help" },
		  { N_("Keyboard Shortcuts"), "win.shortcuts" },
		  { N_("About FsRover"), "win.about" } },
	});

	g_menu_append (encoding, "UTF-8", "win.encoding::65001");
	g_menu_append (encoding, "GBK", "win.encoding::936");
	g_menu_append (encoding, "Big5", "win.encoding::950");
	g_menu_append (encoding, "Shift-JIS", "win.encoding::932");
	g_menu_append (encoding, "EUC-KR", "win.encoding::51949");
	g_menu_append_submenu (settings, _("Filename Encoding"), G_MENU_MODEL (encoding));
	g_menu_append (settings, _("Preserve Timestamps When Extracting"), "win.preserve-times");
	g_menu_append_section (menu, nullptr, G_MENU_MODEL (settings));
	g_menu_append_section (menu, nullptr, G_MENU_MODEL (help));
	g_object_unref (settings);
	g_object_unref (encoding);
	g_object_unref (help);
	return G_MENU_MODEL (menu);
}

GMenuModel *
build_entry_menu ()
{
	return G_MENU_MODEL (build_sections ({
		{ { N_("Open"), "win.open" },
		  { N_("Extract To…"), "win.extract" } },
		{ { N_("View as Text"), "win.view-text" },
		  { N_("View as Hex"), "win.view-hex" },
		  { N_("View as Image"), "win.view-image" },
		  { N_("View as Markdown"), "win.view-markdown" } },
		{ { N_("Open as Disk Image"), "win.open-as-image" },
		  { N_("Open as Compressed Disk Image"), "win.open-as-image-dec" } },
		{ { N_("File Map"), "win.file-map" },
		  { N_("Properties"), "win.file-props" } },
		{ { N_("Copy Name"), "win.copy-name" },
		  { N_("Copy Path"), "win.copy-path" } },
	}));
}

GMenuModel *
build_disk_menu ()
{
	return G_MENU_MODEL (build_sections ({
		{ { N_("Browse"), "win.disk-browse" },
		  { N_("Mount…"), "win.disk-mount" },
		  { N_("Unmount"), "win.disk-unmount" } },
		{ { N_("Unlock…"), "win.unlock" },
		  { N_("Unlock VeraCrypt / TrueCrypt…"), "win.veracrypt" },
		  { N_("Open Plain dm-crypt…"), "win.plain-unlock" } },
		{ { N_("View as Hex"), "win.disk-hex" },
		  { N_("Export Raw Image…"), "win.export-image" },
		  { N_("Search for Lost Partitions…"), "win.lost-scan" } },
		{ { N_("Detach"), "win.detach" },
		  { N_("Properties"), "win.disk-props" } },
	}));
}

GtkWidget *
build_sidebar ()
{
	GtkListItemFactory *factory = gtk_signal_list_item_factory_new ();
	GtkWidget *scroll = gtk_scrolled_window_new ();
	GMenuModel *menu = build_disk_menu ();

	S.disks = g_list_store_new (ROVER_TYPE_ROW);
	S.disk_sel = gtk_single_selection_new (G_LIST_MODEL (g_object_ref (S.disks)));
	gtk_single_selection_set_autoselect (S.disk_sel, FALSE);
	gtk_single_selection_set_can_unselect (S.disk_sel, TRUE);
	g_signal_connect (factory, "setup", G_CALLBACK (setup_disk_cell), nullptr);
	S.disk_view = GTK_LIST_VIEW (gtk_list_view_new (GTK_SELECTION_MODEL (S.disk_sel), factory));
	gtk_widget_add_css_class (GTK_WIDGET (S.disk_view), "navigation-sidebar");
	g_signal_connect (S.disk_sel, "selection-changed", G_CALLBACK (on_disk_selected), nullptr);
	g_signal_connect (S.disk_view, "activate", G_CALLBACK (on_disk_activate), nullptr);
	S.disk_menu = make_popover (menu, GTK_WIDGET (S.disk_view));
	g_object_unref (menu);

	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_NEVER,
		GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), GTK_WIDGET (S.disk_view));
	gtk_widget_set_size_request (scroll, 220, -1);
	return scroll;
}

GtkWidget *
build_entry_view ()
{
	GtkWidget *scroll = gtk_scrolled_window_new ();
	GtkMultiSorter *sorter = gtk_multi_sorter_new ();
	GtkSortListModel *sorted;
	GtkColumnViewColumn *name;
	GMenuModel *menu = build_entry_menu ();

	S.entries = g_list_store_new (ROVER_TYPE_ROW);
	S.entry_view = GTK_COLUMN_VIEW (gtk_column_view_new (nullptr));
	gtk_column_view_set_enable_rubberband (S.entry_view, TRUE);
	name = add_column (_("Name"), G_CALLBACK (setup_name_cell), nullptr, compare_name, true, 0);
	add_column (_("Size"), G_CALLBACK (setup_text_cell), &size_spec, compare_size, false, 110);
	add_column (_("Modified"), G_CALLBACK (setup_text_cell), &mtime_spec, compare_mtime, false, 150);
	add_column (_("Type"), G_CALLBACK (setup_text_cell), &type_spec, compare_type, false, 180);

	/* Folders stay on top whichever way the user sorts.  */
	gtk_multi_sorter_append (sorter, GTK_SORTER (gtk_custom_sorter_new (compare_dirs_first,
		nullptr, nullptr)));
	gtk_multi_sorter_append (sorter, GTK_SORTER (g_object_ref (
		gtk_column_view_get_sorter (S.entry_view))));
	sorted = gtk_sort_list_model_new (G_LIST_MODEL (g_object_ref (S.entries)),
		GTK_SORTER (sorter));
	S.entry_sel = gtk_multi_selection_new (G_LIST_MODEL (sorted));
	gtk_column_view_set_model (S.entry_view, GTK_SELECTION_MODEL (S.entry_sel));
	gtk_column_view_sort_by_column (S.entry_view, name, GTK_SORT_ASCENDING);
	g_signal_connect (S.entry_view, "activate", G_CALLBACK (on_entry_activate), nullptr);
	g_signal_connect (S.entry_sel, "selection-changed", G_CALLBACK (on_entry_selection), nullptr);
	S.entry_menu = make_popover (menu, GTK_WIDGET (S.entry_view));
	g_object_unref (menu);

	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), GTK_WIDGET (S.entry_view));
	return scroll;
}

GtkWidget *
build_home_page ()
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	GtkWidget *image = gtk_image_new_from_icon_name ("drive-harddisk");
	GtkWidget *label = gtk_label_new (
		_("Pick a volume on the left, or open a disk image (Ctrl+O)."));

	gtk_image_set_pixel_size (GTK_IMAGE (image), 96);
	gtk_widget_add_css_class (image, "dim-label");
	gtk_widget_add_css_class (label, "dim-label");
	gtk_widget_set_valign (box, GTK_ALIGN_CENTER);
	S.access_button = gtk_button_new_with_mnemonic (_("_Access Physical Disks…"));
	gtk_actionable_set_action_name (GTK_ACTIONABLE (S.access_button), "win.host-access");
	gtk_widget_set_tooltip_text (S.access_button,
		_("Some disks need administrator permission to be read. FsRover asks for it "
		"without running as root."));
	gtk_widget_set_halign (S.access_button, GTK_ALIGN_CENTER);
	gtk_widget_add_css_class (S.access_button, "pill");
	gtk_box_append (GTK_BOX (box), image);
	gtk_box_append (GTK_BOX (box), label);
	gtk_box_append (GTK_BOX (box), S.access_button);
	return box;
}

GtkWidget *
icon_button (const char *icon, const char *action, const char *tooltip)
{
	GtkWidget *button = gtk_button_new_from_icon_name (icon);

	gtk_actionable_set_action_name (GTK_ACTIONABLE (button), action);
	gtk_widget_set_tooltip_text (button, tooltip);
	return button;
}

GtkWidget *
build_header ()
{
	GtkWidget *header = gtk_header_bar_new ();
	GtkWidget *extract = gtk_button_new_with_mnemonic (_("_Extract…"));
	GtkWidget *menu_button = gtk_menu_button_new ();
	GMenuModel *menu = build_main_menu ();

	gtk_actionable_set_action_name (GTK_ACTIONABLE (extract), "win.extract");
	gtk_widget_set_tooltip_text (extract, _("Extract the selection (Ctrl+E)"));
	gtk_menu_button_set_icon_name (GTK_MENU_BUTTON (menu_button), "open-menu-symbolic");
	gtk_menu_button_set_menu_model (GTK_MENU_BUTTON (menu_button), menu);
	gtk_menu_button_set_primary (GTK_MENU_BUTTON (menu_button), TRUE);
	g_object_unref (menu);

	S.path_entry = GTK_ENTRY (gtk_entry_new ());
	gtk_entry_set_placeholder_text (S.path_entry, _("(device)/path"));
	gtk_widget_set_hexpand (GTK_WIDGET (S.path_entry), TRUE);
	gtk_editable_set_width_chars (GTK_EDITABLE (S.path_entry), 48);
	g_signal_connect (S.path_entry, "activate", G_CALLBACK (on_path_activate), nullptr);

	gtk_header_bar_pack_start (GTK_HEADER_BAR (header),
		icon_button ("go-previous-symbolic", "win.back", _("Back (Alt+Left)")));
	gtk_header_bar_pack_start (GTK_HEADER_BAR (header),
		icon_button ("go-next-symbolic", "win.forward", _("Forward (Alt+Right)")));
	gtk_header_bar_pack_start (GTK_HEADER_BAR (header),
		icon_button ("go-up-symbolic", "win.up", _("Up (Alt+Up)")));
	gtk_header_bar_pack_start (GTK_HEADER_BAR (header),
		icon_button ("document-open-symbolic", "win.open-image", _("Open Disk Image (Ctrl+O)")));
	gtk_header_bar_set_title_widget (GTK_HEADER_BAR (header), GTK_WIDGET (S.path_entry));
	gtk_header_bar_pack_end (GTK_HEADER_BAR (header), menu_button);
	gtk_header_bar_pack_end (GTK_HEADER_BAR (header), extract);
	return header;
}

GtkWidget *
build_status_bar ()
{
	GtkWidget *bar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);

	S.status = GTK_LABEL (gtk_label_new (_("Starting…")));
	gtk_label_set_xalign (S.status, 0);
	gtk_label_set_ellipsize (S.status, PANGO_ELLIPSIZE_MIDDLE);
	gtk_widget_set_hexpand (GTK_WIDGET (S.status), TRUE);
	S.progress = GTK_PROGRESS_BAR (gtk_progress_bar_new ());
	gtk_widget_set_size_request (GTK_WIDGET (S.progress), 200, -1);
	gtk_widget_set_valign (GTK_WIDGET (S.progress), GTK_ALIGN_CENTER);
	gtk_widget_set_visible (GTK_WIDGET (S.progress), FALSE);
	S.cancel_button = gtk_button_new_with_label (_("Cancel"));
	gtk_widget_add_css_class (S.cancel_button, "flat");
	gtk_widget_set_visible (S.cancel_button, FALSE);
	g_signal_connect (S.cancel_button, "clicked", G_CALLBACK (on_cancel), nullptr);
	gtk_widget_set_margin_start (bar, 10);
	gtk_widget_set_margin_end (bar, 6);
	gtk_widget_set_margin_top (bar, 3);
	gtk_widget_set_margin_bottom (bar, 3);
	gtk_box_append (GTK_BOX (bar), GTK_WIDGET (S.status));
	gtk_box_append (GTK_BOX (bar), GTK_WIDGET (S.progress));
	gtk_box_append (GTK_BOX (bar), S.cancel_button);
	return bar;
}

gboolean
on_close_request (GtkWindow *, gpointer)
{
	S.closing = true;
	S.cancel = true;
	return FALSE;
}

void
set_accels (GtkApplication *app)
{
	struct accel { const char *action; const char *keys[3]; };
	static const accel accels[] =
	{
		{ "win.open-image", { "<Control>o", nullptr, nullptr } },
		{ "win.refresh", { "F5", "<Control>r", nullptr } },
		{ "win.back", { "<Alt>Left", nullptr, nullptr } },
		{ "win.forward", { "<Alt>Right", nullptr, nullptr } },
		{ "win.up", { "<Alt>Up", nullptr, nullptr } },
		{ "win.focus-path", { "<Control>l", nullptr, nullptr } },
		{ "win.extract", { "<Control>e", nullptr, nullptr } },
		{ "win.file-props", { "<Alt>Return", nullptr, nullptr } },
		{ "win.view-text", { "F3", nullptr, nullptr } },
		{ "win.view-hex", { "<Control>h", nullptr, nullptr } },
		{ "win.help", { "F1", nullptr, nullptr } },
		{ "win.shortcuts", { "<Control>question", nullptr, nullptr } },
	};

	for (const accel &a : accels)
		gtk_application_set_accels_for_action (app, a.action, a.keys);
}

void
build_window (GtkApplication *app)
{
	GtkWidget *window = gtk_application_window_new (app);
	GtkWidget *content = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *paned = gtk_paned_new (GTK_ORIENTATION_HORIZONTAL);
	GtkWidget *stack = gtk_stack_new ();

	S.app = app;
	S.window = GTK_WINDOW (window);
	gtk_window_set_title (S.window, "FsRover");
	gtk_window_set_icon_name (S.window, "drive-harddisk");
	gtk_window_set_default_size (S.window, 1100, 700);
	g_action_map_add_action_entries (G_ACTION_MAP (window), window_actions,
		G_N_ELEMENTS (window_actions), nullptr);
	set_accels (app);
	gtk_window_set_titlebar (S.window, build_header ());

	S.stack = GTK_STACK (stack);
	gtk_stack_add_named (S.stack, build_home_page (), "home");
	gtk_stack_add_named (S.stack, build_entry_view (), "entries");
	gtk_stack_set_visible_child_name (S.stack, "home");

	gtk_paned_set_start_child (GTK_PANED (paned), build_sidebar ());
	gtk_paned_set_end_child (GTK_PANED (paned), stack);
	gtk_paned_set_resize_start_child (GTK_PANED (paned), FALSE);
	gtk_paned_set_shrink_start_child (GTK_PANED (paned), FALSE);
	gtk_paned_set_position (GTK_PANED (paned), 280);
	gtk_widget_set_vexpand (paned, TRUE);

	gtk_box_append (GTK_BOX (content), paned);
	gtk_box_append (GTK_BOX (content), gtk_separator_new (GTK_ORIENTATION_HORIZONTAL));
	gtk_box_append (GTK_BOX (content), build_status_bar ());
	gtk_window_set_child (S.window, content);
	g_signal_connect (window, "close-request", G_CALLBACK (on_close_request), nullptr);
	update_actions ();
}

void
attach_pending ()
{
	std::vector<std::string> images = std::move (S.pending_images);

	S.pending_images.clear ();
	for (const std::string &path : images)
		attach_image (path, false);
}

} /* namespace */

void
rover_window_open (GtkApplication *app, const std::vector<std::string> &images)
{
	S.pending_images.insert (S.pending_images.end (), images.begin (), images.end ());
	if (!S.window)
	{
		build_window (app);
		hostdisk_install_hook ();
		backend::start (0, []
		{
			if (S.closing)
				return;
			S.ready = true;
			set_status (_("Ready"));
			refresh_disks (attach_pending);
		});
	}
	else if (S.ready)
		attach_pending ();
	gtk_window_present (S.window);
}

void
rover_window_shutdown ()
{
	S.closing = true;
	S.cancel = true;
	mount_shutdown ();
	backend::stop ();
}
