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
 * Hex viewer for a file or a raw device.  The scrollbar counts rows, not
 * pixels, so a multi-terabyte disk scrolls like a small file; the bytes on
 * screen come from 64 KiB blocks fetched on the grub thread as they are
 * first drawn, and the oldest blocks are dropped beyond a small cache.
 */

#include "app.h"

#include <algorithm>
#include <map>
#include <set>

namespace
{

constexpr unsigned ROW_BYTES = 16;
constexpr unsigned long long BLOCK = 64 * 1024;
constexpr size_t CACHE_BLOCKS = 64;

struct hex_ui
{
	GtkWindow *dialog = nullptr;
	GtkWidget *area = nullptr;
	GtkAdjustment *adj = nullptr;
	GtkLabel *info = nullptr;
	GtkEntry *goto_entry = nullptr;
	std::string path;
	unsigned long long size = 0;
	bool size_known = false;
	std::string error;
	std::map<unsigned long long, std::vector<unsigned char>> blocks;
	std::vector<unsigned long long> order;	/* insertion order, for eviction */
	std::set<unsigned long long> pending;
	int row_height = 16;
	int char_width = 8;
	bool closed = false;
};

using hex_ptr = std::shared_ptr<hex_ui>;

hex_ptr
hex_of (gpointer widget)
{
	return *static_cast<hex_ptr *> (g_object_get_data (G_OBJECT (widget), "rover-hex"));
}

unsigned long long
total_rows (const hex_ui &u)
{
	return (u.size + ROW_BYTES - 1) / ROW_BYTES;
}

void
update_info (hex_ui &u)
{
	unsigned long long top = (unsigned long long) gtk_adjustment_get_value (u.adj) * ROW_BYTES;

	if (!u.error.empty () && !u.size_known)
		gtk_label_set_text (u.info, u.error.c_str ());
	else
		gtk_label_set_text (u.info, fmt (_("Offset 0x%llX of %s"), top,
			format_exact (u.size).c_str ()).c_str ());
}

void
set_size (const hex_ptr &u, unsigned long long size)
{
	if (u->size_known)
		return;
	u->size_known = true;
	u->size = size;
	gtk_adjustment_set_upper (u->adj, (double) total_rows (*u));
	update_info (*u);
}

void
request_block (const hex_ptr &u, unsigned long long block)
{
	if (u->pending.count (block) || u->blocks.count (block))
		return;
	u->pending.insert (block);
	std::string path = u->path;
	run_job ([path, block] { return read_chunk (path, block * BLOCK, BLOCK); },
		[u, block] (chunk c)
	{
		u->pending.erase (block);
		if (u->closed)
			return;
		if (!c.error.empty ())
		{
			u->error = c.error;
			update_info (*u);
			gtk_widget_queue_draw (u->area);
			return;
		}
		set_size (u, c.size);
		u->blocks[block] = std::move (c.data);
		u->order.push_back (block);
		while (u->order.size () > CACHE_BLOCKS)
		{
			u->blocks.erase (u->order.front ());
			u->order.erase (u->order.begin ());
		}
		gtk_widget_queue_draw (u->area);
	});
}

/* Byte at OFFSET, or -1 if its block is not here yet.  */
int
byte_at (hex_ui &u, unsigned long long offset)
{
	auto it = u.blocks.find (offset / BLOCK);

	if (it == u.blocks.end () || offset % BLOCK >= it->second.size ())
		return -1;
	return it->second[offset % BLOCK];
}

void
measure (hex_ui &u, GtkWidget *widget)
{
	PangoLayout *layout = gtk_widget_create_pango_layout (widget, "0");
	PangoFontDescription *font = pango_font_description_from_string ("Monospace");
	int width, height;

	pango_layout_set_font_description (layout, font);
	pango_layout_get_pixel_size (layout, &width, &height);
	u.char_width = width > 0 ? width : 8;
	u.row_height = height > 0 ? height + 2 : 16;
	pango_font_description_free (font);
	g_object_unref (layout);
}

void
draw_hex (GtkDrawingArea *area, cairo_t *cr, int width, int height, gpointer data)
{
	hex_ptr u = hex_of (data);
	GtkWidget *widget = GTK_WIDGET (area);
	PangoLayout *layout = gtk_widget_create_pango_layout (widget, nullptr);
	PangoFontDescription *font = pango_font_description_from_string ("Monospace");
	GdkRGBA color;
	unsigned long long first = (unsigned long long) gtk_adjustment_get_value (u->adj);
	int visible = height / u->row_height + 1;
	bool wide = u->size > 0xffffffffULL;

	(void) width;
	pango_layout_set_font_description (layout, font);
	gtk_widget_get_color (widget, &color);
	gdk_cairo_set_source_rgba (cr, &color);
	gtk_adjustment_set_page_size (u->adj, height / u->row_height);
	gtk_adjustment_set_page_increment (u->adj, std::max (1, height / u->row_height - 1));
	for (int r = 0; r < visible; r++)
	{
		unsigned long long row = first + (unsigned long long) r;
		unsigned long long offset = row * ROW_BYTES;
		if (u->size_known && offset >= u->size)
			break;
		std::string hex;
		std::string text;
		bool missing = false;
		for (unsigned i = 0; i < ROW_BYTES; i++)
		{
			int b = u->size_known && offset + i >= u->size ? -2 : byte_at (*u, offset + i);
			if (b == -2)
				hex += "   ";
			else if (b < 0)
			{
				missing = true;
				hex += "?? ";
				text += ' ';
			}
			else
			{
				hex += fmt ("%02X ", b);
				text += b >= 0x20 && b < 0x7f ? (char) b : '.';
			}
			if (i == 7)
				hex += ' ';
		}
		if (missing && u->error.empty ())
		{
			request_block (u, offset / BLOCK);
			request_block (u, (offset + ROW_BYTES - 1) / BLOCK);
		}
		std::string line = (wide ? fmt ("%016llX", offset) : fmt ("%08llX", offset))
			+ "  " + hex + " " + text;
		pango_layout_set_text (layout, line.c_str (), -1);
		cairo_move_to (cr, 6, r * u->row_height);
		pango_cairo_show_layout (cr, layout);
	}
	if (!u->size_known && u->blocks.empty () && u->error.empty ())
		request_block (u, first * ROW_BYTES / BLOCK);
	pango_font_description_free (font);
	g_object_unref (layout);
}

void
on_scrolled (GtkAdjustment *, gpointer area)
{
	hex_ptr u = hex_of (area);

	update_info (*u);
	gtk_widget_queue_draw (GTK_WIDGET (area));
}

gboolean
on_wheel (GtkEventControllerScroll *, double, double dy, gpointer area)
{
	hex_ptr u = hex_of (area);

	gtk_adjustment_set_value (u->adj, gtk_adjustment_get_value (u->adj) + dy * 3);
	return TRUE;
}

gboolean
on_key (GtkEventControllerKey *, guint key, guint, GdkModifierType, gpointer area)
{
	hex_ptr u = hex_of (area);
	double value = gtk_adjustment_get_value (u->adj);
	double page = std::max (1.0, gtk_adjustment_get_page_size (u->adj) - 1);

	switch (key)
	{
	case GDK_KEY_Up: value -= 1; break;
	case GDK_KEY_Down: value += 1; break;
	case GDK_KEY_Page_Up: value -= page; break;
	case GDK_KEY_Page_Down: value += page; break;
	case GDK_KEY_Home: value = 0; break;
	case GDK_KEY_End: value = gtk_adjustment_get_upper (u->adj); break;
	default: return FALSE;
	}
	gtk_adjustment_set_value (u->adj, value);
	return TRUE;
}

void
on_goto (GtkEntry *entry, gpointer area)
{
	hex_ptr u = hex_of (area);
	std::string text = gtk_editable_get_text (GTK_EDITABLE (entry));
	char *end = nullptr;
	unsigned long long offset;

	/* "0x1F0" or "1f0h" is hex, plain digits are decimal.  */
	if (text.size () > 1 && (text.back () == 'h' || text.back () == 'H'))
		offset = g_ascii_strtoull (text.substr (0, text.size () - 1).c_str (), &end, 16);
	else
		offset = g_ascii_strtoull (text.c_str (), &end, 0);
	if (text.empty () || (end && *end && *end != 'h' && *end != 'H'))
	{
		gtk_widget_error_bell (GTK_WIDGET (entry));
		return;
	}
	gtk_adjustment_set_value (u->adj, (double) (offset / ROW_BYTES));
	gtk_widget_grab_focus (GTK_WIDGET (area));
}

void
on_hex_destroy (GtkWidget *dialog, gpointer)
{
	hex_of (dialog)->closed = true;
}

} /* namespace */

void
show_hex (const std::string &path, const std::string &title)
{
	auto u = std::make_shared<hex_ui> ();
	GtkWindow *dialog = new_dialog (fmt (_("%s — Hex"), title.c_str ()), 760, 560);
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *bar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	GtkWidget *view = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkWidget *scrollbar;
	GtkEventController *wheel;
	GtkEventController *keys;

	u->dialog = dialog;
	u->path = path;
	u->area = gtk_drawing_area_new ();
	u->adj = gtk_adjustment_new (0, 0, 1, 1, 16, 16);
	u->info = GTK_LABEL (gtk_label_new (_("Reading…")));
	u->goto_entry = GTK_ENTRY (gtk_entry_new ());
	gtk_entry_set_placeholder_text (u->goto_entry, _("Go to offset (0x… or decimal)"));
	gtk_editable_set_width_chars (GTK_EDITABLE (u->goto_entry), 24);
	gtk_label_set_xalign (u->info, 0);
	gtk_widget_set_hexpand (GTK_WIDGET (u->info), TRUE);
	gtk_widget_set_margin_start (bar, 8);
	gtk_widget_set_margin_end (bar, 8);
	gtk_widget_set_margin_top (bar, 6);
	gtk_widget_set_margin_bottom (bar, 6);
	gtk_box_append (GTK_BOX (bar), GTK_WIDGET (u->info));
	gtk_box_append (GTK_BOX (bar), GTK_WIDGET (u->goto_entry));

	measure (*u, u->area);
	gtk_widget_set_hexpand (u->area, TRUE);
	gtk_widget_set_vexpand (u->area, TRUE);
	gtk_widget_set_focusable (u->area, TRUE);
	gtk_drawing_area_set_content_width (GTK_DRAWING_AREA (u->area), u->char_width * 80);
	gtk_drawing_area_set_draw_func (GTK_DRAWING_AREA (u->area), draw_hex, u->area, nullptr);
	scrollbar = gtk_scrollbar_new (GTK_ORIENTATION_VERTICAL, u->adj);
	gtk_box_append (GTK_BOX (view), u->area);
	gtk_box_append (GTK_BOX (view), scrollbar);
	gtk_box_append (GTK_BOX (box), bar);
	gtk_box_append (GTK_BOX (box), gtk_separator_new (GTK_ORIENTATION_HORIZONTAL));
	gtk_box_append (GTK_BOX (box), view);
	gtk_window_set_child (dialog, box);

	/* The dialog and the drawing area both lead back to the state.  */
	g_object_set_data_full (G_OBJECT (u->area), "rover-hex", new hex_ptr (u),
		[] (gpointer p) { delete static_cast<hex_ptr *> (p); });
	g_object_set_data_full (G_OBJECT (dialog), "rover-hex", new hex_ptr (u),
		[] (gpointer p) { delete static_cast<hex_ptr *> (p); });
	wheel = gtk_event_controller_scroll_new (GTK_EVENT_CONTROLLER_SCROLL_VERTICAL);
	g_signal_connect (wheel, "scroll", G_CALLBACK (on_wheel), u->area);
	gtk_widget_add_controller (u->area, wheel);
	keys = gtk_event_controller_key_new ();
	g_signal_connect (keys, "key-pressed", G_CALLBACK (on_key), u->area);
	gtk_widget_add_controller (u->area, keys);
	g_signal_connect (u->adj, "value-changed", G_CALLBACK (on_scrolled), u->area);
	g_signal_connect (u->goto_entry, "activate", G_CALLBACK (on_goto), u->area);
	g_signal_connect (dialog, "destroy", G_CALLBACK (on_hex_destroy), nullptr);
	gtk_window_present (dialog);
	gtk_widget_grab_focus (u->area);
}
