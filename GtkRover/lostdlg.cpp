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
 * Lost partition search.  The scan runs one 64 MiB slice per grub job, so
 * listings and viewers keep working while it goes on; each slice reports
 * its results and the next is queued from the GTK thread.  A result opens
 * as a lostN window (with its backup remaps), which then browses like any
 * device.
 */

#include "app.h"

#include <rover.h>

#include "../common/lostpart.h"

namespace
{

constexpr unsigned long long SLICE = 64ULL << 20;

/* Touched only on the grub thread, except CANCEL.  */
struct scan_state
{
	rover_lost_scan *scan = nullptr;
	bool started = false;
	std::atomic<bool> cancel { false };
};

struct lost_ui
{
	GtkWindow *dialog = nullptr;
	GtkWidget *ext_backup = nullptr;
	GtkWidget *deep = nullptr;
	GtkWidget *start = nullptr;
	GtkWidget *open = nullptr;
	GtkProgressBar *progress = nullptr;
	GtkLabel *info = nullptr;
	GtkStringList *rows = nullptr;
	GtkSingleSelection *selection = nullptr;
	std::string device;
	std::vector<rover_lostpart::result> results;
	std::shared_ptr<scan_state> state;
	bool closed = false;
	bool opening = false;	/* an add is in flight */
};

using lost_ptr = std::shared_ptr<lost_ui>;

lost_ptr
lost_of (gpointer dialog)
{
	return *static_cast<lost_ptr *> (g_object_get_data (G_OBJECT (dialog), "rover-lost"));
}

struct step_result
{
	int more = 0;	/* rover_lost_scan_step(): 1 more, 0 done, -1 error */
	std::string error;
	unsigned long long done = 0;
	unsigned long long total = 0;
	std::vector<rover_lostpart::result> found;
};

/* Grub thread: one slice; the first opens the scan, the last closes it.  */
step_result
scan_step (const std::shared_ptr<scan_state> &state, const std::string &device, unsigned flags)
{
	step_result out;

	if (!state->started)
	{
		state->started = true;
		state->scan = rover_lost_scan_begin (device.c_str (), flags);
		if (!state->scan)
		{
			out.more = -1;
			out.error = last_error ();
			return out;
		}
	}
	if (!state->scan)
		return out;
	if (state->cancel || S.closing)
		out.more = 0;
	else
	{
		out.more = rover_lost_scan_step (state->scan, SLICE, rover_lostpart::collect, &out.found);
		if (out.more < 0)
			out.error = last_error ();
	}
	rover_lost_scan_progress (state->scan, &out.done, &out.total);
	if (out.more <= 0)
	{
		rover_lost_scan_end (state->scan);
		state->scan = nullptr;
	}
	return out;
}

std::string
row_label (const rover_lostpart::result &r, int column)
{
	switch (column)
	{
	case 0: return format_exact (r.offset);
	case 1: return format_size (r.size);
	case 2: return r.type;
	case 3: return r.fs.empty () ? "-" : r.fs;
	case 4: return r.label.empty () ? "-" : r.label;
	default: return rover_lostpart::flags_text (r.flags);
	}
}

void
show_rows (const lost_ptr &u)
{
	std::vector<std::string> keys;
	std::vector<const char *> ptrs;

	for (size_t i = 0; i < u->results.size (); i++)
		keys.push_back (std::to_string (i));
	for (const std::string &key : keys)
		ptrs.push_back (key.c_str ());
	ptrs.push_back (nullptr);
	gtk_string_list_splice (u->rows, 0, g_list_model_get_n_items (G_LIST_MODEL (u->rows)),
		ptrs.data ());
}

void scan_next (const lost_ptr &u, unsigned flags);

void
scan_done (const lost_ptr &u, const step_result &r, unsigned flags)
{
	if (u->closed)
	{
		if (r.more > 0)
			scan_next (u, flags);	/* lets the grub thread close the scan */
		return;
	}
	u->results.insert (u->results.end (), r.found.begin (), r.found.end ());
	if (r.total)
		gtk_progress_bar_set_fraction (u->progress, (double) r.done / r.total);
	gtk_progress_bar_set_text (u->progress, fmt (_("%s of %s"), format_size (r.done).c_str (),
		format_size (r.total).c_str ()).c_str ());
	if (r.more > 0)
	{
		if (!r.found.empty ())
			show_rows (u);
		gtk_label_set_text (u->info, fmt (g_dngettext (nullptr, "Searching… %zu found",
			"Searching… %zu found", u->results.size ()), u->results.size ()).c_str ());
		scan_next (u, flags);
		return;
	}
	rover_lostpart::finish (u->results);
	show_rows (u);
	std::string info = u->state->cancel ? std::string (_("Stopped."))
		: !r.error.empty () ? r.error : std::string (_("Search complete."));
	info += " " + fmt (g_dngettext (nullptr, "%zu partition found.", "%zu partitions found.",
		u->results.size ()), u->results.size ());
	gtk_label_set_text (u->info, info.c_str ());
	gtk_button_set_label (GTK_BUTTON (u->start), _("_Search"));
	gtk_widget_set_sensitive (u->ext_backup, TRUE);
	gtk_widget_set_sensitive (u->deep, TRUE);
	u->state.reset ();
}

void
scan_next (const lost_ptr &u, unsigned flags)
{
	std::shared_ptr<scan_state> state = u->state;
	std::string device = u->device;

	run_job ([state, device, flags] { return scan_step (state, device, flags); },
		[u, flags] (step_result r) { scan_done (u, r, flags); });
}

void
on_start_clicked (GtkButton *, gpointer dialog)
{
	lost_ptr u = lost_of (dialog);

	if (u->state)
	{
		u->state->cancel = true;
		gtk_label_set_text (u->info, _("Stopping…"));
		return;
	}
	unsigned flags = (gtk_check_button_get_active (GTK_CHECK_BUTTON (u->ext_backup))
			? ROVER_LOST_SCAN_EXT_BACKUP : 0)
		| (gtk_check_button_get_active (GTK_CHECK_BUTTON (u->deep)) ? ROVER_LOST_SCAN_DEEP : 0);
	u->results.clear ();
	show_rows (u);
	u->state = std::make_shared<scan_state> ();
	gtk_button_set_label (GTK_BUTTON (u->start), _("_Stop"));
	gtk_widget_set_sensitive (u->ext_backup, FALSE);
	gtk_widget_set_sensitive (u->deep, FALSE);
	gtk_progress_bar_set_fraction (u->progress, 0);
	gtk_label_set_text (u->info, _("Searching…"));
	scan_next (u, flags);
}

struct add_result
{
	int rc;
	std::string error;
};

void
on_open_clicked (GtkButton *, gpointer dialog)
{
	lost_ptr u = lost_of (dialog);
	guint pos = gtk_single_selection_get_selected (u->selection);

	if (pos == GTK_INVALID_LIST_POSITION || pos >= u->results.size () || u->opening)
		return;
	const rover_lostpart::result &r = u->results[pos];
	/* Already open: show that window instead of adding a second.  */
	GListModel *disks = G_LIST_MODEL (S.disks);
	for (guint i = 0; i < g_list_model_get_n_items (disks); i++)
	{
		RoverRow *row = ROVER_ROW (g_list_model_get_item (disks, i));
		row_data d = rover_row_get (row);
		g_object_unref (row);
		if (d.dev_id == ROVER_DEV_LOST && d.parent == u->device
			&& d.start_lba * (d.sector_size ? d.sector_size : 512) == r.offset)
		{
			auto_enter (d.name);
			return;
		}
	}
	rover_lostpart::window w = { u->device, r.offset, r.window, r.remap };
	std::string name = "lost" + std::to_string (S.next_lost++);
	u->opening = true;
	run_job ([name, w]
	{
		int rc = rover_lostpart::add_window (name, w);
		return add_result { rc, rc ? last_error () : "" };
	},
	[name, u] (add_result a)
	{
		u->opening = false;
		if (a.rc)
		{
			show_error (_("Cannot open the lost partition"), a.error);
			return;
		}
		refresh_disks ([name] { auto_enter (name); });
	});
}

void
on_selection (GtkSelectionModel *, guint, guint, gpointer dialog)
{
	lost_ptr u = lost_of (dialog);

	gtk_widget_set_sensitive (u->open,
		gtk_single_selection_get_selected (u->selection) != GTK_INVALID_LIST_POSITION);
}

void
on_lost_activate (GtkColumnView *, guint, gpointer dialog)
{
	on_open_clicked (nullptr, dialog);
}

void
setup_cell (GtkSignalListItemFactory *, GObject *object, gpointer column)
{
	GtkWidget *label = gtk_label_new (nullptr);

	gtk_label_set_xalign (GTK_LABEL (label), GPOINTER_TO_INT (column) <= 1 ? 1.0f : 0.0f);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	gtk_list_item_set_child (GTK_LIST_ITEM (object), label);
}

void
bind_cell (GtkSignalListItemFactory *factory, GObject *object, gpointer column)
{
	GtkListItem *item = GTK_LIST_ITEM (object);
	auto *u = static_cast<lost_ui *> (g_object_get_data (G_OBJECT (factory), "rover-lost"));
	const char *key = gtk_string_object_get_string (GTK_STRING_OBJECT (gtk_list_item_get_item (item)));
	size_t index = (size_t) g_ascii_strtoull (key, nullptr, 10);

	if (index < u->results.size ())
		gtk_label_set_text (GTK_LABEL (gtk_list_item_get_child (item)),
			row_label (u->results[index], GPOINTER_TO_INT (column)).c_str ());
}

void
on_lost_close (GtkButton *, gpointer dialog)
{
	gtk_window_close (GTK_WINDOW (dialog));
}

void
on_lost_destroy (GtkWidget *dialog, gpointer)
{
	lost_ptr u = lost_of (dialog);

	u->closed = true;
	if (u->state)
		u->state->cancel = true;
}

} /* namespace */

void
show_lost_scan (const std::string &device)
{
	static const char *const columns[] =
		{ N_("Offset"), N_("Size"), N_("Type"), N_("Filesystem"), N_("Label"), N_("Flags") };
	auto u = std::make_shared<lost_ui> ();
	GtkWindow *dialog = new_dialog (fmt (_("Lost Partitions on (%s)"), device.c_str ()), 860, 520);
	GtkWidget *box = dialog_box (dialog);
	GtkWidget *options = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *scroll = gtk_scrolled_window_new ();
	GtkWidget *close = gtk_button_new_with_mnemonic (_("_Close"));
	GtkColumnView *view;

	u->dialog = dialog;
	u->device = device;
	u->rows = gtk_string_list_new (nullptr);
	u->selection = gtk_single_selection_new (G_LIST_MODEL (u->rows));
	gtk_single_selection_set_autoselect (u->selection, FALSE);
	u->ext_backup = gtk_check_button_new_with_mnemonic (_("Also look for _ext backup superblocks"));
	u->deep = gtk_check_button_new_with_mnemonic (_("_Deep search (every sector, much slower)"));
	u->start = gtk_button_new_with_mnemonic (_("_Search"));
	gtk_widget_add_css_class (u->start, "suggested-action");
	u->open = gtk_button_new_with_mnemonic (_("_Open"));
	gtk_widget_set_sensitive (u->open, FALSE);
	u->progress = GTK_PROGRESS_BAR (gtk_progress_bar_new ());
	gtk_progress_bar_set_show_text (u->progress, TRUE);
	gtk_progress_bar_set_text (u->progress, "");
	u->info = GTK_LABEL (gtk_label_new (_("Searches the device for filesystems that no "
		"partition table entry points at.")));
	gtk_label_set_xalign (u->info, 0);
	gtk_label_set_wrap (u->info, TRUE);

	view = GTK_COLUMN_VIEW (gtk_column_view_new (GTK_SELECTION_MODEL (u->selection)));
	for (int i = 0; i < (int) G_N_ELEMENTS (columns); i++)
	{
		GtkListItemFactory *factory = gtk_signal_list_item_factory_new ();
		g_object_set_data (G_OBJECT (factory), "rover-lost", u.get ());
		g_signal_connect (factory, "setup", G_CALLBACK (setup_cell), GINT_TO_POINTER (i));
		g_signal_connect (factory, "bind", G_CALLBACK (bind_cell), GINT_TO_POINTER (i));
		GtkColumnViewColumn *column = gtk_column_view_column_new (_(columns[i]), factory);
		gtk_column_view_column_set_resizable (column, TRUE);
		gtk_column_view_column_set_expand (column, i == 4 || i == 5);
		gtk_column_view_append_column (view, column);
		g_object_unref (column);
	}
	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), GTK_WIDGET (view));
	gtk_widget_set_vexpand (scroll, TRUE);

	gtk_box_append (GTK_BOX (options), u->ext_backup);
	gtk_box_append (GTK_BOX (options), u->deep);
	gtk_box_append (GTK_BOX (box), options);
	gtk_box_append (GTK_BOX (box), GTK_WIDGET (u->info));
	gtk_box_append (GTK_BOX (box), GTK_WIDGET (u->progress));
	gtk_box_append (GTK_BOX (box), scroll);
	gtk_box_append (GTK_BOX (box), button_row ({ u->start, u->open, close }));

	g_object_set_data_full (G_OBJECT (dialog), "rover-lost", new lost_ptr (u),
		[] (gpointer p) { delete static_cast<lost_ptr *> (p); });
	g_signal_connect (u->start, "clicked", G_CALLBACK (on_start_clicked), dialog);
	g_signal_connect (u->open, "clicked", G_CALLBACK (on_open_clicked), dialog);
	g_signal_connect (close, "clicked", G_CALLBACK (on_lost_close), dialog);
	g_signal_connect (u->selection, "selection-changed", G_CALLBACK (on_selection), dialog);
	g_signal_connect (view, "activate", G_CALLBACK (on_lost_activate), dialog);
	g_signal_connect (dialog, "destroy", G_CALLBACK (on_lost_destroy), nullptr);
	gtk_window_present (dialog);
}
