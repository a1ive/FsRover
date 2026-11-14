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
 * File map: where a file's bytes live, as the filesystem driver reports it
 * through rover_file_map_range_ex().  Rows use the shared column layout of
 * the CLI blocklist (common/filemap_format.h) and can be copied or saved
 * as TSV.  The query runs on the grub thread and stops when the dialog
 * closes or the row cap is reached.
 */

#include "app.h"

#include <rover.h>

#include "../common/filemap_format.h"

namespace
{

constexpr size_t MAP_ROWS_MAX = 200000;

const char *const COLUMNS[11] =
{
	N_("Extent"), N_("Logical offset"), N_("Length"), N_("Type"), N_("Device"),
	N_("Address space"), N_("Storage offset"), N_("Storage length"), N_("Encoding"),
	N_("Decoded offset"), N_("Decoded length")
};

struct map_ui
{
	GtkWindow *dialog = nullptr;
	GtkLabel *info = nullptr;
	GtkStringList *rows = nullptr;
	std::string tsv;
	std::atomic<bool> cancel { false };
};

using map_ptr = std::shared_ptr<map_ui>;

struct map_result
{
	std::string error;
	std::vector<std::string> rows;	/* TSV lines */
	unsigned extents = 0;
	bool truncated = false;
	bool cancelled = false;
};

struct map_context
{
	map_result *out;
	std::string device;
	std::atomic<bool> *cancel;
};

std::string
tsv_line (const std::array<std::string, 11> &columns)
{
	std::string line;

	for (size_t i = 0; i < columns.size (); i++)
		line += (i ? "\t" : "") + columns[i];
	return line;
}

int
collect_extent (const rover_map_extent *e, void *data)
{
	auto *ctx = static_cast<map_context *> (data);
	/* Numbered from 1, as the CLI blocklist does.  */
	std::string group = std::to_string (++ctx->out->extents);
	unsigned count = e->storage_count ? e->storage_count : 1;

	for (unsigned i = 0; i < count; i++)
		ctx->out->rows.push_back (tsv_line (file_map_columns (*e, i, ctx->device, group)));
	if (ctx->out->rows.size () >= MAP_ROWS_MAX)
	{
		ctx->out->truncated = true;
		return 1;
	}
	return 0;
}

int
map_cancelled (void *data)
{
	return static_cast<map_context *> (data)->cancel->load () || S.closing;
}

/* Grub thread.  */
map_result
map_file (const std::string &path, std::atomic<bool> *cancel)
{
	map_result out;
	map_context ctx = { &out, "(" + device_of (path) + ")", cancel };
	rover_file *f = rover_file_open (path.c_str ());
	int stopped = 0;

	if (!f)
	{
		out.error = last_error ();
		return out;
	}
	if (rover_file_map_range_ex (f, 0, rover_file_size (f), collect_extent, &ctx,
		map_cancelled, &ctx, &stopped))
		out.error = last_error ();
	out.cancelled = stopped && !out.truncated;
	rover_file_close (f);
	return out;
}

void
bind_cell (GtkSignalListItemFactory *, GObject *object, gpointer column)
{
	GtkListItem *item = GTK_LIST_ITEM (object);
	const char *line = gtk_string_object_get_string (GTK_STRING_OBJECT (gtk_list_item_get_item (item)));
	char **fields = g_strsplit (line, "\t", -1);
	guint index = GPOINTER_TO_UINT (column);

	gtk_label_set_text (GTK_LABEL (gtk_list_item_get_child (item)),
		index < g_strv_length (fields) ? fields[index] : "");
	g_strfreev (fields);
}

void
setup_cell (GtkSignalListItemFactory *, GObject *object, gpointer column)
{
	GtkWidget *label = gtk_label_new (nullptr);
	guint index = GPOINTER_TO_UINT (column);

	/* The numeric columns read better right aligned.  */
	bool numeric = index == 0 || index == 1 || index == 2 || index >= 6;
	gtk_label_set_xalign (GTK_LABEL (label), numeric && index != 8 ? 1.0f : 0.0f);
	if (numeric)
		gtk_widget_add_css_class (label, "numeric");
	gtk_list_item_set_child (GTK_LIST_ITEM (object), label);
}

map_ptr
map_of (gpointer dialog)
{
	return *static_cast<map_ptr *> (g_object_get_data (G_OBJECT (dialog), "rover-map"));
}

void
on_map_copy (GtkButton *, gpointer dialog)
{
	copy_text (map_of (dialog)->tsv);
	set_status (_("Copied to the clipboard"));
}

void
on_map_saved (GObject *source, GAsyncResult *result, gpointer data)
{
	std::unique_ptr<std::string> tsv (static_cast<std::string *> (data));
	GFile *file = gtk_file_dialog_save_finish (GTK_FILE_DIALOG (source), result, nullptr);
	GError *error = nullptr;

	if (!file)
		return;
	if (!g_file_replace_contents (file, tsv->data (), tsv->size (), nullptr, FALSE,
		G_FILE_CREATE_NONE, nullptr, nullptr, &error))
	{
		show_error (_("Cannot save the file map"), error->message);
		g_error_free (error);
	}
	g_object_unref (file);
}

void
on_map_save (GtkButton *, gpointer dialog)
{
	GtkFileDialog *save = gtk_file_dialog_new ();

	gtk_file_dialog_set_title (save, _("Save File Map"));
	gtk_file_dialog_set_initial_name (save, "filemap.tsv");
	gtk_file_dialog_save (save, GTK_WINDOW (dialog), nullptr, on_map_saved,
		new std::string (map_of (dialog)->tsv));
	g_object_unref (save);
}

void
on_map_close (GtkButton *, gpointer dialog)
{
	gtk_window_close (GTK_WINDOW (dialog));
}

void
on_map_destroy (GtkWidget *dialog, gpointer)
{
	map_of (dialog)->cancel = true;
}

} /* namespace */

void
show_file_map (const std::string &path)
{
	auto u = std::make_shared<map_ui> ();
	GtkWindow *dialog = new_dialog (fmt (_("%s — File Map"), basename_of (path).c_str ()), 1000, 520);
	GtkWidget *box = dialog_box (dialog);
	GtkWidget *scroll = gtk_scrolled_window_new ();
	GtkColumnView *view;
	GtkWidget *copy = gtk_button_new_with_mnemonic (_("_Copy as TSV"));
	GtkWidget *save = gtk_button_new_with_mnemonic (_("_Save as TSV…"));
	GtkWidget *close = gtk_button_new_with_mnemonic (_("_Close"));

	u->dialog = dialog;
	u->rows = gtk_string_list_new (nullptr);
	u->info = GTK_LABEL (gtk_label_new (_("Mapping…")));
	gtk_label_set_xalign (u->info, 0);
	gtk_label_set_wrap (u->info, TRUE);
	view = GTK_COLUMN_VIEW (gtk_column_view_new (GTK_SELECTION_MODEL (
		gtk_no_selection_new (G_LIST_MODEL (g_object_ref (u->rows))))));
	gtk_column_view_set_show_column_separators (view, TRUE);
	for (guint i = 0; i < G_N_ELEMENTS (COLUMNS); i++)
	{
		GtkListItemFactory *factory = gtk_signal_list_item_factory_new ();
		g_signal_connect (factory, "setup", G_CALLBACK (setup_cell), GUINT_TO_POINTER (i));
		g_signal_connect (factory, "bind", G_CALLBACK (bind_cell), GUINT_TO_POINTER (i));
		GtkColumnViewColumn *column = gtk_column_view_column_new (_(COLUMNS[i]), factory);
		gtk_column_view_column_set_resizable (column, TRUE);
		gtk_column_view_append_column (view, column);
		g_object_unref (column);
	}
	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), GTK_WIDGET (view));
	gtk_widget_set_vexpand (scroll, TRUE);
	gtk_widget_set_sensitive (copy, FALSE);
	gtk_widget_set_sensitive (save, FALSE);
	gtk_box_append (GTK_BOX (box), GTK_WIDGET (u->info));
	gtk_box_append (GTK_BOX (box), scroll);
	gtk_box_append (GTK_BOX (box), button_row ({ copy, save, close }));

	g_object_set_data_full (G_OBJECT (dialog), "rover-map", new map_ptr (u),
		[] (gpointer p)
		{
			map_ptr *m = static_cast<map_ptr *> (p);
			g_object_unref ((*m)->rows);
			delete m;
		});
	g_signal_connect (copy, "clicked", G_CALLBACK (on_map_copy), dialog);
	g_signal_connect (save, "clicked", G_CALLBACK (on_map_save), dialog);
	g_signal_connect (close, "clicked", G_CALLBACK (on_map_close), dialog);
	g_signal_connect (dialog, "destroy", G_CALLBACK (on_map_destroy), nullptr);
	gtk_window_present (dialog);

	/* The rows list is kept alive by the job too, in case the dialog goes.  */
	GtkStringList *rows = GTK_STRING_LIST (g_object_ref (u->rows));
	run_job ([path, u] { return map_file (path, &u->cancel); },
		[u, rows, copy, save] (map_result r)
	{
		if (!u->cancel)
		{
			std::string header;
			for (size_t i = 0; i < G_N_ELEMENTS (COLUMNS); i++)
				header += (i ? "\t" : "") + std::string (COLUMNS[i]);
			u->tsv = header + "\n";
			std::vector<const char *> lines;
			for (const std::string &line : r.rows)
			{
				u->tsv += line + "\n";
				lines.push_back (line.c_str ());
			}
			lines.push_back (nullptr);
			gtk_string_list_splice (rows, 0, 0, lines.data ());
			std::string info = fmt (g_dngettext (nullptr, "%u extent", "%u extents", r.extents),
				r.extents);
			if (r.truncated)
				info += " — " + fmt (_("stopped after %zu rows"), r.rows.size ());
			if (!r.error.empty ())
				info += " — " + r.error;
			gtk_label_set_text (u->info, info.c_str ());
			gtk_widget_set_sensitive (copy, !r.rows.empty ());
			gtk_widget_set_sensitive (save, !r.rows.empty ());
		}
		g_object_unref (rows);
	});
}
