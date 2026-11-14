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
 * Image viewer.  The file is read whole (up to IMAGE_MAX) on the grub
 * thread and decoded here: GDK's own loaders first (PNG, JPEG, TIFF), then
 * whatever gdk-pixbuf loaders are installed (GIF, BMP, ICO, WebP, SVG, ...).
 */

#include "app.h"

#include <gdk-pixbuf/gdk-pixbuf.h>

#include <algorithm>

namespace
{

constexpr size_t IMAGE_MAX = 256 << 20;

struct image_ui
{
	GtkWindow *dialog = nullptr;
	GtkPicture *picture = nullptr;
	GtkWidget *scroll = nullptr;
	GtkWidget *fit = nullptr;
	GtkLabel *info = nullptr;
	GdkTexture *texture = nullptr;
	double zoom = 1.0;
	bool closed = false;

	~image_ui ()
	{
		g_clear_object (&texture);
	}
};

using image_ptr = std::shared_ptr<image_ui>;

image_ptr
image_of (gpointer widget)
{
	return *static_cast<image_ptr *> (g_object_get_data (G_OBJECT (widget), "rover-image"));
}

GdkTexture *
decode_image (const std::vector<unsigned char> &data, std::string *format, std::string *error)
{
	GBytes *bytes = g_bytes_new (data.data (), data.size ());
	GdkTexture *texture = gdk_texture_new_from_bytes (bytes, nullptr);

	g_bytes_unref (bytes);
	if (texture)
		return texture;

	GdkPixbufLoader *loader = gdk_pixbuf_loader_new ();
	GError *err = nullptr;
	if (gdk_pixbuf_loader_write (loader, data.data (), data.size (), &err)
		&& gdk_pixbuf_loader_close (loader, &err))
	{
		GdkPixbuf *pixbuf = gdk_pixbuf_loader_get_pixbuf (loader);
		GdkPixbufFormat *info = gdk_pixbuf_loader_get_format (loader);
		if (info)
		{
			char *name = gdk_pixbuf_format_get_name (info);
			*format = name;
			g_free (name);
		}
		if (pixbuf)
			texture = gdk_texture_new_for_pixbuf (pixbuf);
	}
	else
	{
		gdk_pixbuf_loader_close (loader, nullptr);
		*error = err ? err->message : _("Unrecognized image format");
	}
	g_clear_error (&err);
	g_object_unref (loader);
	if (!texture && error->empty ())
		*error = _("Unrecognized image format");
	return texture;
}

void
apply_zoom (const image_ptr &u)
{
	bool fit = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (u->fit));

	if (!u->texture)
		return;
	/* A picture scales to whatever it is given: centre it at its own size
	   unless fitting.  */
	gtk_widget_set_halign (GTK_WIDGET (u->picture), fit ? GTK_ALIGN_FILL : GTK_ALIGN_CENTER);
	gtk_widget_set_valign (GTK_WIDGET (u->picture), fit ? GTK_ALIGN_FILL : GTK_ALIGN_CENTER);
	if (fit)
	{
		gtk_widget_set_size_request (GTK_WIDGET (u->picture), -1, -1);
		gtk_picture_set_can_shrink (u->picture, TRUE);
		gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (u->scroll),
			GTK_POLICY_NEVER, GTK_POLICY_NEVER);
	}
	else
	{
		int w = gdk_texture_get_width (u->texture);
		int h = gdk_texture_get_height (u->texture);
		gtk_widget_set_size_request (GTK_WIDGET (u->picture),
			std::max (1, (int) (w * u->zoom)), std::max (1, (int) (h * u->zoom)));
		gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (u->scroll),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	}
}

void
on_fit_toggled (GtkToggleButton *, gpointer dialog)
{
	apply_zoom (image_of (dialog));
}

void
zoom_by (gpointer dialog, double factor)
{
	image_ptr u = image_of (dialog);

	u->zoom = factor == 0 ? 1.0 : CLAMP (u->zoom * factor, 0.05, 32.0);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (u->fit), FALSE);
	apply_zoom (u);
}

void
on_zoom_in (GtkButton *, gpointer dialog)
{
	zoom_by (dialog, 1.25);
}

void
on_zoom_out (GtkButton *, gpointer dialog)
{
	zoom_by (dialog, 0.8);
}

void
on_zoom_reset (GtkButton *, gpointer dialog)
{
	zoom_by (dialog, 0);
}

void
on_image_destroy (GtkWidget *dialog, gpointer)
{
	image_of (dialog)->closed = true;
}

GtkWidget *
tool_button (const char *icon, const char *tooltip, GCallback callback, gpointer data)
{
	GtkWidget *button = gtk_button_new_from_icon_name (icon);

	gtk_widget_set_tooltip_text (button, tooltip);
	g_signal_connect (button, "clicked", callback, data);
	return button;
}

} /* namespace */

void
show_image (const std::string &path)
{
	auto u = std::make_shared<image_ui> ();
	GtkWindow *dialog = new_dialog (fmt (_("%s — Image"), basename_of (path).c_str ()), 800, 600);
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *bar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

	u->dialog = dialog;
	u->picture = GTK_PICTURE (gtk_picture_new ());
	gtk_picture_set_content_fit (u->picture, GTK_CONTENT_FIT_CONTAIN);
	u->scroll = gtk_scrolled_window_new ();
	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (u->scroll), GTK_WIDGET (u->picture));
	gtk_widget_set_vexpand (u->scroll, TRUE);
	u->info = GTK_LABEL (gtk_label_new (_("Reading…")));
	gtk_label_set_xalign (u->info, 0);
	gtk_widget_set_hexpand (GTK_WIDGET (u->info), TRUE);
	u->fit = gtk_toggle_button_new_with_mnemonic (_("_Fit"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (u->fit), TRUE);

	gtk_widget_set_margin_start (bar, 8);
	gtk_widget_set_margin_end (bar, 8);
	gtk_widget_set_margin_top (bar, 6);
	gtk_widget_set_margin_bottom (bar, 6);
	gtk_box_append (GTK_BOX (bar), GTK_WIDGET (u->info));
	gtk_box_append (GTK_BOX (bar), u->fit);
	gtk_box_append (GTK_BOX (bar), tool_button ("zoom-out-symbolic", _("Zoom out"),
		G_CALLBACK (on_zoom_out), dialog));
	gtk_box_append (GTK_BOX (bar), tool_button ("zoom-original-symbolic", _("Actual size"),
		G_CALLBACK (on_zoom_reset), dialog));
	gtk_box_append (GTK_BOX (bar), tool_button ("zoom-in-symbolic", _("Zoom in"),
		G_CALLBACK (on_zoom_in), dialog));
	gtk_box_append (GTK_BOX (box), bar);
	gtk_box_append (GTK_BOX (box), gtk_separator_new (GTK_ORIENTATION_HORIZONTAL));
	gtk_box_append (GTK_BOX (box), u->scroll);
	gtk_window_set_child (dialog, box);

	g_object_set_data_full (G_OBJECT (dialog), "rover-image", new image_ptr (u),
		[] (gpointer p) { delete static_cast<image_ptr *> (p); });
	g_signal_connect (u->fit, "toggled", G_CALLBACK (on_fit_toggled), dialog);
	g_signal_connect (dialog, "destroy", G_CALLBACK (on_image_destroy), nullptr);
	gtk_window_present (dialog);

	run_job ([path] { return read_chunk (path, 0, IMAGE_MAX); }, [u] (chunk c)
	{
		std::string format;
		std::string error = c.error;

		if (u->closed)
			return;
		if (error.empty () && c.size > c.data.size ())
			error = fmt (_("The image is larger than %s"), format_size (IMAGE_MAX).c_str ());
		if (error.empty ())
			u->texture = decode_image (c.data, &format, &error);
		if (!u->texture)
		{
			gtk_label_set_text (u->info, error.c_str ());
			return;
		}
		gtk_picture_set_paintable (u->picture, GDK_PAINTABLE (u->texture));
		std::string info = fmt ("%d × %d", gdk_texture_get_width (u->texture),
			gdk_texture_get_height (u->texture));
		if (!format.empty ())
			info += ", " + format;
		info += ", " + format_size (c.size);
		gtk_label_set_text (u->info, info.c_str ());
		apply_zoom (u);
	});
}
