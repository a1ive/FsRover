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
 * The About-box easter egg: a window hosting the toolkit-free game in
 * common/rover_game.cpp.  Each frame is copied into a cairo RGB24 surface
 * (the same 0x00RRGGBB words) and scaled up with a nearest-neighbour
 * filter; the frame clock drives the game.  It runs on the GTK thread
 * only and never touches grub.
 */

#include "app.h"
#include "rover_game.h"

#include <cstring>

namespace
{

constexpr int GAME_W = rover_game::WIDTH;
constexpr int GAME_H = rover_game::HEIGHT;

struct game_ui
{
	rover_game::state *game = nullptr;
	gint64 last_frame = 0;	/* frame clock time in us; 0 before the first tick */
};

void
free_game (gpointer data)
{
	game_ui *u = (game_ui *) data;

	rover_game::destroy (u->game);
	delete u;
}

/* A fresh surface per frame: GTK's render node keeps the one it was
   drawn with, so the game's own buffer cannot be wrapped and rewritten
   in place.  */
cairo_surface_t *
frame_surface (const game_ui *u)
{
	cairo_surface_t *surface = cairo_image_surface_create (CAIRO_FORMAT_RGB24, GAME_W, GAME_H);
	unsigned char *dst = cairo_image_surface_get_data (surface);
	int stride = cairo_image_surface_get_stride (surface);
	const std::uint32_t *src = rover_game::pixels (u->game);

	cairo_surface_flush (surface);
	for (int y = 0; y < GAME_H; y++)
		memcpy (dst + (size_t) y * stride, src + (size_t) y * GAME_W, GAME_W * sizeof (std::uint32_t));
	cairo_surface_mark_dirty (surface);
	return surface;
}

void
draw_game (GtkDrawingArea *, cairo_t *cr, int width, int height, gpointer data)
{
	game_ui *u = (game_ui *) data;
	double draw_w;
	double draw_h;
	int scale = rover_game::integer_scale (width, height);

	cairo_set_source_rgb (cr, 0.0, 0.0, 0.0);
	cairo_paint (cr);
	if (scale >= 1)
	{
		draw_w = GAME_W * scale;
		draw_h = GAME_H * scale;
	}
	else
	{
		/* Below 1:1 only a fractional fit is possible.  */
		draw_w = width;
		draw_h = draw_w * GAME_H / GAME_W;
		if (draw_h > height)
		{
			draw_h = height;
			draw_w = draw_h * GAME_W / GAME_H;
		}
	}

	cairo_surface_t *surface = frame_surface (u);
	cairo_translate (cr, (int) ((width - draw_w) / 2), (int) ((height - draw_h) / 2));
	cairo_scale (cr, draw_w / GAME_W, draw_h / GAME_H);
	cairo_set_source_surface (cr, surface, 0.0, 0.0);
	cairo_pattern_set_filter (cairo_get_source (cr), CAIRO_FILTER_NEAREST);
	cairo_rectangle (cr, 0.0, 0.0, GAME_W, GAME_H);
	cairo_fill (cr);
	cairo_surface_destroy (surface);
}

gboolean
on_tick (GtkWidget *area, GdkFrameClock *clock, gpointer data)
{
	game_ui *u = (game_ui *) data;
	gint64 now = gdk_frame_clock_get_frame_time (clock);
	double dt = u->last_frame ? (double) (now - u->last_frame) / G_USEC_PER_SEC : 0.0;

	u->last_frame = now;
	if (rover_game::tick (u->game, dt))
		gtk_widget_queue_draw (area);
	return G_SOURCE_CONTINUE;
}

rover_game::key
game_key (guint keyval)
{
	switch (keyval)
	{
	case GDK_KEY_space:
	case GDK_KEY_KP_Space:
	case GDK_KEY_Up:
	case GDK_KEY_KP_Up:
		return rover_game::key::jump;
	case GDK_KEY_Down:
	case GDK_KEY_KP_Down:
		return rover_game::key::duck;
	default:
		return rover_game::key::other;
	}
}

/* Held keys auto-repeat as further presses; the game ignores the
   repeats of a held jump key.  */
gboolean
on_key_pressed (GtkEventControllerKey *keys, guint keyval, guint, GdkModifierType, gpointer data)
{
	game_ui *u = (game_ui *) data;

	if (keyval == GDK_KEY_Escape)
	{
		gtk_window_close (GTK_WINDOW (gtk_event_controller_get_widget (GTK_EVENT_CONTROLLER (keys))));
		return TRUE;
	}
	rover_game::key k = game_key (keyval);
	rover_game::key_down (u->game, k);
	return k != rover_game::key::other;
}

void
on_key_released (GtkEventControllerKey *, guint keyval, guint, GdkModifierType, gpointer data)
{
	game_ui *u = (game_ui *) data;

	rover_game::key_up (u->game, game_key (keyval));
}

void
on_active (GObject *window, GParamSpec *, gpointer data)
{
	game_ui *u = (game_ui *) data;

	rover_game::set_active (u->game, gtk_window_is_active (GTK_WINDOW (window)));
}

} // namespace

void
show_rover_game (GtkWindow *parent)
{
	game_ui *u = new game_ui;
	u->game = rover_game::create ((guint32) g_get_monotonic_time () ^ g_random_int ());

	GtkWindow *window = GTK_WINDOW (gtk_window_new ());
	gtk_window_set_title (window, "FSROVER : MARS RUNNER");
	gtk_window_set_transient_for (window, parent);
	gtk_window_set_modal (window, TRUE);
	gtk_window_set_destroy_with_parent (window, TRUE);
	g_object_set_data_full (G_OBJECT (window), "rover-game", u, free_game);

	/* The window opens at its natural size, a 2x game under the title
	   bar, and can shrink to 1:1.  */
	GtkWidget *area = gtk_drawing_area_new ();
	gtk_widget_set_size_request (area, GAME_W, GAME_H);
	gtk_drawing_area_set_content_width (GTK_DRAWING_AREA (area), GAME_W * 2);
	gtk_drawing_area_set_content_height (GTK_DRAWING_AREA (area), GAME_H * 2);
	gtk_drawing_area_set_draw_func (GTK_DRAWING_AREA (area), draw_game, u, nullptr);
	gtk_widget_add_tick_callback (area, on_tick, u, nullptr);
	gtk_window_set_child (window, area);

	GtkEventController *keys = gtk_event_controller_key_new ();
	g_signal_connect (keys, "key-pressed", G_CALLBACK (on_key_pressed), u);
	g_signal_connect (keys, "key-released", G_CALLBACK (on_key_released), u);
	gtk_widget_add_controller (GTK_WIDGET (window), keys);
	g_signal_connect (window, "notify::is-active", G_CALLBACK (on_active), u);

	gtk_window_present (window);
}
