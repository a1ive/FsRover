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
 * Markdown viewer, also used for the built-in help.  md4c's push parser
 * (FsRover/md4c, the same copy the Windows viewer uses) drives a
 * GtkTextBuffer: blocks and spans become text tags, headings get marks
 * named after their GitHub-style slugs so "#anchor" links scroll to them,
 * and web links open in the desktop's browser.
 */

#include "app.h"

#include <stdlib.h>
#include <string.h>

#include "../FsRover/md4c/md4c.h"
extern "C" {
#include "../FsRover/md4c/entity.h"
}

namespace
{

constexpr size_t MARKDOWN_MAX = 16 << 20;
constexpr int INDENT_STEP = 26;
constexpr int VIEW_MARGIN = 18;

struct md_list
{
	bool ordered;
	unsigned next;
};

struct md_render
{
	GtkTextBuffer *buf;
	std::vector<std::string> spans;	/* active span tag names */
	std::vector<md_list> lists;
	std::vector<GtkTextTag *> links;
	int quote = 0;
	int code = 0;
	int image = 0;
	int heading = 0;	/* level of the open heading, 0 if none */
	int block_start = 0;
	int heading_start = 0;
	bool after_bullet = false;
	bool first_cell = false;
	std::string heading_text;
	std::vector<std::string> slugs;
};

void
create_tags (GtkTextBuffer *buf)
{
	static const double scales[] = { 2.0, 1.6, 1.3, 1.15, 1.05, 1.0 };

	for (int level = 1; level <= 6; level++)
		gtk_text_buffer_create_tag (buf, fmt ("h%d", level).c_str (),
			"weight", PANGO_WEIGHT_BOLD, "scale", scales[level - 1],
			"pixels-above-lines", level <= 2 ? 14 : 8, "pixels-below-lines", 4, nullptr);
	gtk_text_buffer_create_tag (buf, "p", "pixels-below-lines", 8, nullptr);
	gtk_text_buffer_create_tag (buf, "em", "style", PANGO_STYLE_ITALIC, nullptr);
	gtk_text_buffer_create_tag (buf, "strong", "weight", PANGO_WEIGHT_BOLD, nullptr);
	gtk_text_buffer_create_tag (buf, "del", "strikethrough", TRUE, nullptr);
	gtk_text_buffer_create_tag (buf, "u", "underline", PANGO_UNDERLINE_SINGLE, nullptr);
	gtk_text_buffer_create_tag (buf, "code", "family", "Monospace",
		"background", "rgba(127,127,127,0.18)", nullptr);
	gtk_text_buffer_create_tag (buf, "pre", "family", "Monospace",
		"paragraph-background", "rgba(127,127,127,0.12)", "pixels-below-lines", 0, nullptr);
	gtk_text_buffer_create_tag (buf, "quote", "style", PANGO_STYLE_ITALIC,
		"foreground", "rgba(127,127,127,1)", nullptr);
	gtk_text_buffer_create_tag (buf, "link", "foreground", "#3584e4",
		"underline", PANGO_UNDERLINE_SINGLE, nullptr);
	gtk_text_buffer_create_tag (buf, "dim", "foreground", "rgba(127,127,127,1)", nullptr);
	gtk_text_buffer_create_tag (buf, "th", "weight", PANGO_WEIGHT_BOLD, nullptr);
}

GtkTextTag *
indent_tag (GtkTextBuffer *buf, int level)
{
	std::string name = fmt ("indent-%d", level);
	GtkTextTagTable *table = gtk_text_buffer_get_tag_table (buf);
	GtkTextTag *tag = gtk_text_tag_table_lookup (table, name.c_str ());

	/* A tag's margin replaces the view's (VIEW_MARGIN) instead of adding.  */
	if (!tag)
		tag = gtk_text_buffer_create_tag (buf, name.c_str (), "left-margin",
			VIEW_MARGIN + level * INDENT_STEP, nullptr);
	return tag;
}

int
end_offset (md_render &r)
{
	GtkTextIter end;

	gtk_text_buffer_get_end_iter (r.buf, &end);
	return gtk_text_iter_get_offset (&end);
}

void
apply (md_render &r, const char *tag, int start)
{
	GtkTextIter a, b;

	gtk_text_buffer_get_iter_at_offset (r.buf, &a, start);
	gtk_text_buffer_get_end_iter (r.buf, &b);
	gtk_text_buffer_apply_tag_by_name (r.buf, tag, &a, &b);
}

void
insert (md_render &r, const std::string &text)
{
	GtkTextIter a, b;
	int start = end_offset (r);

	if (text.empty ())
		return;
	gtk_text_buffer_get_end_iter (r.buf, &b);
	gtk_text_buffer_insert (r.buf, &b, text.c_str (), (int) text.size ());
	gtk_text_buffer_get_iter_at_offset (r.buf, &a, start);
	gtk_text_buffer_get_end_iter (r.buf, &b);
	for (const std::string &tag : r.spans)
		gtk_text_buffer_apply_tag_by_name (r.buf, tag.c_str (), &a, &b);
	if (!r.links.empty ())
		gtk_text_buffer_apply_tag (r.buf, r.links.back (), &a, &b);
	if (r.quote)
		gtk_text_buffer_apply_tag_by_name (r.buf, "quote", &a, &b);
	if (r.code)
		gtk_text_buffer_apply_tag_by_name (r.buf, "pre", &a, &b);
	int level = r.quote + (int) r.lists.size ();
	if (level)
		gtk_text_buffer_apply_tag (r.buf, indent_tag (r.buf, level), &a, &b);
	if (r.heading)
		r.heading_text += text;
	r.after_bullet = false;
}

/* Start a block on a fresh line (unless a list bullet is waiting for it).  */
void
begin_block (md_render &r)
{
	GtkTextIter end;

	gtk_text_buffer_get_end_iter (r.buf, &end);
	if (!r.after_bullet && gtk_text_iter_get_offset (&end) > 0
		&& gtk_text_iter_backward_char (&end) && gtk_text_iter_get_char (&end) != '\n')
		insert (r, "\n");
	r.block_start = end_offset (r);
}

void
end_block (md_render &r, const char *spacing)
{
	insert (r, "\n");
	if (spacing)
		apply (r, spacing, r.block_start);
}

/* GitHub's anchor for a heading: lower case, punctuation dropped, spaces
   turned into hyphens.  */
std::string
slugify (const std::string &text)
{
	std::string out;

	for (const char *p = text.c_str (); *p; p = g_utf8_next_char (p))
	{
		gunichar c = g_utf8_get_char (p);
		if (g_unichar_isalnum (c) || c == '-' || c == '_')
		{
			char buf[8];
			buf[g_unichar_to_utf8 (g_unichar_tolower (c), buf)] = '\0';
			out += buf;
		}
		else if (c == ' ')
			out += '-';
	}
	return out;
}

std::string
codepoint (unsigned cp)
{
	char buf[8];

	if (cp == 0 || cp > 0x10ffff || (cp >= 0xd800 && cp < 0xe000))
		cp = 0xfffd;
	buf[g_unichar_to_utf8 (cp, buf)] = '\0';
	return buf;
}

/* "&amp;", "&#65;" or "&#x41;"; anything unknown stays verbatim.  */
std::string
entity (const char *p, size_t n)
{
	if (n > 3 && p[1] == '#')
	{
		bool hex = p[2] == 'x' || p[2] == 'X';
		return codepoint ((unsigned) strtoul (p + (hex ? 3 : 2), nullptr, hex ? 16 : 10));
	}
	const ENTITY *ent = entity_lookup (p, n);
	if (!ent)
		return std::string (p, n);
	std::string out = codepoint (ent->codepoints[0]);
	if (ent->codepoints[1])
		out += codepoint (ent->codepoints[1]);
	return out;
}

std::string
attribute (const MD_ATTRIBUTE *a)
{
	std::string out;

	for (int i = 0; a->substr_offsets[i] < a->size; i++)
	{
		const char *p = a->text + a->substr_offsets[i];
		size_t n = a->substr_offsets[i + 1] - a->substr_offsets[i];
		if (a->substr_types[i] == MD_TEXT_ENTITY)
			out += entity (p, n);
		else
			out.append (p, n);
	}
	return out;
}

int
enter_block (MD_BLOCKTYPE type, void *detail, void *data)
{
	md_render &r = *static_cast<md_render *> (data);

	switch (type)
	{
	case MD_BLOCK_QUOTE:
		r.quote++;
		break;
	case MD_BLOCK_UL:
		r.lists.push_back ({ false, 0 });
		break;
	case MD_BLOCK_OL:
		r.lists.push_back ({ true, static_cast<MD_BLOCK_OL_DETAIL *> (detail)->start });
		break;
	case MD_BLOCK_LI:
	{
		auto *li = static_cast<MD_BLOCK_LI_DETAIL *> (detail);
		begin_block (r);
		std::string bullet = r.lists.back ().ordered
			? fmt ("%u. ", r.lists.back ().next++) : "• ";
		if (li->is_task)
			bullet += li->task_mark == ' ' ? "☐ " : "☑ ";
		/* The bullet sits one level out from the item's text.  */
		md_list list = r.lists.back ();
		r.lists.pop_back ();
		r.spans.push_back ("dim");
		insert (r, std::string (r.lists.empty () && !r.quote ? "  " : "") + bullet);
		r.spans.pop_back ();
		r.lists.push_back (list);
		r.after_bullet = true;
		break;
	}
	case MD_BLOCK_HR:
		begin_block (r);
		r.spans.push_back ("dim");
		insert (r, "────────────────────────────────────────");
		r.spans.pop_back ();
		break;
	case MD_BLOCK_H:
		begin_block (r);
		r.heading = (int) static_cast<MD_BLOCK_H_DETAIL *> (detail)->level;
		r.heading_start = end_offset (r);
		r.heading_text.clear ();
		r.spans.push_back (fmt ("h%d", r.heading));
		break;
	case MD_BLOCK_CODE:
		begin_block (r);
		r.code++;
		break;
	case MD_BLOCK_P:
	case MD_BLOCK_TABLE:
		begin_block (r);
		break;
	case MD_BLOCK_TR:
		begin_block (r);
		r.first_cell = true;
		break;
	case MD_BLOCK_TH:
	case MD_BLOCK_TD:
		if (!r.first_cell)
		{
			r.spans.push_back ("dim");
			insert (r, "  │  ");
			r.spans.pop_back ();
		}
		r.first_cell = false;
		if (type == MD_BLOCK_TH)
			r.spans.push_back ("th");
		break;
	default:
		break;
	}
	return 0;
}

int
leave_block (MD_BLOCKTYPE type, void *, void *data)
{
	md_render &r = *static_cast<md_render *> (data);

	switch (type)
	{
	case MD_BLOCK_QUOTE:
		r.quote--;
		break;
	case MD_BLOCK_UL:
	case MD_BLOCK_OL:
		r.lists.pop_back ();
		break;
	case MD_BLOCK_HR:
		end_block (r, "p");
		break;
	case MD_BLOCK_H:
	{
		GtkTextIter at;
		std::string slug = slugify (r.heading_text);
		std::string name = "#" + slug;
		/* Repeated headings get -1, -2, ... like on GitHub.  */
		int n = 0;
		for (const std::string &seen : r.slugs)
			n += seen == slug;
		if (n)
			name += fmt ("-%d", n);
		r.slugs.push_back (slug);
		gtk_text_buffer_get_iter_at_offset (r.buf, &at, r.heading_start);
		if (!gtk_text_buffer_get_mark (r.buf, name.c_str ()))
			gtk_text_buffer_create_mark (r.buf, name.c_str (), &at, TRUE);
		r.spans.pop_back ();
		r.heading = 0;
		end_block (r, nullptr);
		break;
	}
	case MD_BLOCK_CODE:
		r.code--;
		end_block (r, "p");
		break;
	case MD_BLOCK_P:
		end_block (r, r.lists.empty () ? "p" : nullptr);
		break;
	case MD_BLOCK_TH:
		r.spans.pop_back ();
		break;
	case MD_BLOCK_TABLE:
		apply (r, "p", r.block_start);
		break;
	case MD_BLOCK_TR:
		insert (r, "\n");
		break;
	default:
		break;
	}
	return 0;
}

int
enter_span (MD_SPANTYPE type, void *detail, void *data)
{
	md_render &r = *static_cast<md_render *> (data);

	switch (type)
	{
	case MD_SPAN_EM: r.spans.push_back ("em"); break;
	case MD_SPAN_STRONG: r.spans.push_back ("strong"); break;
	case MD_SPAN_DEL: r.spans.push_back ("del"); break;
	case MD_SPAN_U: r.spans.push_back ("u"); break;
	case MD_SPAN_CODE: r.spans.push_back ("code"); break;
	case MD_SPAN_A:
	{
		GtkTextTag *tag = gtk_text_buffer_create_tag (r.buf, nullptr, nullptr);
		std::string href = attribute (&static_cast<MD_SPAN_A_DETAIL *> (detail)->href);
		g_object_set_data_full (G_OBJECT (tag), "href", g_strdup (href.c_str ()), g_free);
		r.links.push_back (tag);
		r.spans.push_back ("link");
		break;
	}
	case MD_SPAN_IMG:
		r.image++;
		r.spans.push_back ("dim");
		insert (r, "[");
		break;
	default:
		r.spans.push_back ("dim");
		break;
	}
	return 0;
}

int
leave_span (MD_SPANTYPE type, void *, void *data)
{
	md_render &r = *static_cast<md_render *> (data);

	if (type == MD_SPAN_A)
		r.links.pop_back ();
	if (type == MD_SPAN_IMG)
	{
		insert (r, "]");
		r.image--;
	}
	r.spans.pop_back ();
	return 0;
}

int
text (MD_TEXTTYPE type, const MD_CHAR *p, MD_SIZE size, void *data)
{
	md_render &r = *static_cast<md_render *> (data);

	switch (type)
	{
	case MD_TEXT_NULLCHAR:
		insert (r, "\xef\xbf\xbd");
		break;
	case MD_TEXT_BR:
		insert (r, r.image ? " " : "\n");
		break;
	case MD_TEXT_SOFTBR:
		insert (r, " ");
		break;
	case MD_TEXT_ENTITY:
		insert (r, entity (p, size));
		break;
	default:
	{
		/* A text buffer cannot hold invalid UTF-8.  */
		char *valid = g_utf8_make_valid (p, (gssize) size);
		insert (r, valid);
		g_free (valid);
		break;
	}
	}
	return 0;
}

void
render_markdown (GtkTextBuffer *buf, const std::string &source)
{
	md_render r;
	MD_PARSER parser = {};

	r.buf = buf;
	create_tags (buf);
	parser.flags = MD_DIALECT_GITHUB | MD_FLAG_COLLAPSEWHITESPACE;
	parser.enter_block = enter_block;
	parser.leave_block = leave_block;
	parser.enter_span = enter_span;
	parser.leave_span = leave_span;
	parser.text = text;
	md_parse (source.c_str (), (MD_SIZE) source.size (), &parser, &r);
}

/* The link under the pointer, or null.  */
const char *
link_at (GtkTextView *view, double x, double y)
{
	GtkTextIter iter;
	int bx, by;
	const char *href = nullptr;

	gtk_text_view_window_to_buffer_coords (view, GTK_TEXT_WINDOW_WIDGET, (int) x, (int) y, &bx, &by);
	if (!gtk_text_view_get_iter_at_location (view, &iter, bx, by))
		return nullptr;
	GSList *tags = gtk_text_iter_get_tags (&iter);
	for (GSList *t = tags; t && !href; t = t->next)
		href = static_cast<const char *> (g_object_get_data (G_OBJECT (t->data), "href"));
	g_slist_free (tags);
	return href;
}

void
on_link_released (GtkGestureClick *gesture, int, double x, double y, gpointer)
{
	GtkTextView *view = GTK_TEXT_VIEW (gtk_event_controller_get_widget (GTK_EVENT_CONTROLLER (gesture)));
	GtkTextBuffer *buf = gtk_text_view_get_buffer (view);
	GtkTextIter start, end;

	/* A drag that selected text is not a click.  */
	if (gtk_text_buffer_get_selection_bounds (buf, &start, &end))
		return;
	const char *href = link_at (view, x, y);
	if (!href)
		return;
	if (href[0] == '#')
	{
		GtkTextMark *mark = gtk_text_buffer_get_mark (buf, href);
		if (mark)
			gtk_text_view_scroll_to_mark (view, mark, 0, TRUE, 0, 0);
		return;
	}
	if (g_str_has_prefix (href, "http://") || g_str_has_prefix (href, "https://")
		|| g_str_has_prefix (href, "mailto:"))
	{
		GtkUriLauncher *launcher = gtk_uri_launcher_new (href);
		gtk_uri_launcher_launch (launcher, GTK_WINDOW (gtk_widget_get_root (GTK_WIDGET (view))),
			nullptr, nullptr, nullptr);
		g_object_unref (launcher);
	}
}

void
on_motion (GtkEventControllerMotion *motion, double x, double y, gpointer)
{
	GtkWidget *view = gtk_event_controller_get_widget (GTK_EVENT_CONTROLLER (motion));

	gtk_widget_set_cursor_from_name (view, link_at (GTK_TEXT_VIEW (view), x, y) ? "pointer" : nullptr);
}

/* A window with an empty markdown view; returns its buffer.  */
GtkTextView *
markdown_window (const std::string &title, GtkLabel **info)
{
	GtkWindow *dialog = new_dialog (title, 820, 640);
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *scroll = gtk_scrolled_window_new ();
	GtkTextView *view = GTK_TEXT_VIEW (gtk_text_view_new ());
	GtkGesture *click = gtk_gesture_click_new ();
	GtkEventController *motion = gtk_event_controller_motion_new ();

	gtk_text_view_set_editable (view, FALSE);
	gtk_text_view_set_cursor_visible (view, FALSE);
	gtk_text_view_set_wrap_mode (view, GTK_WRAP_WORD_CHAR);
	gtk_text_view_set_left_margin (view, VIEW_MARGIN);
	gtk_text_view_set_right_margin (view, 18);
	gtk_text_view_set_top_margin (view, 12);
	gtk_text_view_set_bottom_margin (view, 12);
	g_signal_connect (click, "released", G_CALLBACK (on_link_released), nullptr);
	gtk_widget_add_controller (GTK_WIDGET (view), GTK_EVENT_CONTROLLER (click));
	g_signal_connect (motion, "motion", G_CALLBACK (on_motion), nullptr);
	gtk_widget_add_controller (GTK_WIDGET (view), motion);
	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), GTK_WIDGET (view));
	gtk_widget_set_vexpand (scroll, TRUE);
	if (info)
	{
		*info = GTK_LABEL (gtk_label_new (_("Reading…")));
		gtk_label_set_xalign (*info, 0);
		gtk_widget_set_margin_start (GTK_WIDGET (*info), 8);
		gtk_widget_set_margin_top (GTK_WIDGET (*info), 4);
		gtk_widget_set_margin_bottom (GTK_WIDGET (*info), 4);
		gtk_box_append (GTK_BOX (box), GTK_WIDGET (*info));
		gtk_box_append (GTK_BOX (box), gtk_separator_new (GTK_ORIENTATION_HORIZONTAL));
	}
	gtk_box_append (GTK_BOX (box), scroll);
	gtk_window_set_child (dialog, box);
	gtk_window_present (dialog);
	return view;
}

} /* namespace */

void
show_markdown_file (const std::string &path)
{
	GtkLabel *info = nullptr;
	GtkTextView *view = markdown_window (fmt (_("%s — Markdown"), basename_of (path).c_str ()), &info);
	GtkTextBuffer *buf = gtk_text_view_get_buffer (view);
	/* The job holds references so a closed window is simply discarded.  */
	g_object_ref (buf);
	g_object_ref (info);

	run_job ([path] { return read_chunk (path, 0, MARKDOWN_MAX); }, [buf, info] (chunk c)
	{
		if (!c.error.empty ())
			gtk_label_set_text (info, c.error.c_str ());
		else
		{
			render_markdown (buf, std::string (c.data.begin (), c.data.end ()));
			gtk_label_set_text (info, c.size > c.data.size ()
				? fmt (_("%s, showing the first %s"), format_size (c.size).c_str (),
					format_size (c.data.size ()).c_str ()).c_str ()
				: format_size (c.size).c_str ());
		}
		g_object_unref (buf);
		g_object_unref (info);
	});
}

void
show_help ()
{
	GBytes *bytes = g_resources_lookup_data ("/io/github/a1ive/FsRover/help.md",
		G_RESOURCE_LOOKUP_FLAGS_NONE, nullptr);
	GtkTextView *view = markdown_window (_("FsRover Help"), nullptr);
	gsize size = 0;

	if (!bytes)
	{
		gtk_text_buffer_set_text (gtk_text_view_get_buffer (view), _("The help text is missing."), -1);
		return;
	}
	const char *data = static_cast<const char *> (g_bytes_get_data (bytes, &size));
	render_markdown (gtk_text_view_get_buffer (view), std::string (data, size));
	g_bytes_unref (bytes);
}
