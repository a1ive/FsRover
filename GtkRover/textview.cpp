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
 * Text viewer.  The first TEXT_MAX bytes are read once; switching the
 * encoding re-decodes them.  Decoding never fails: bytes the charset
 * cannot map become U+FFFD, so a binary or mislabelled file still opens.
 */

#include "app.h"

#include <errno.h>
#include <string.h>

#include <algorithm>

namespace
{

constexpr size_t TEXT_MAX = 16 << 20;

/* Index 0 is "Automatic"; the rest are iconv names.  */
const char *const CHARSETS[] =
{
	N_("Automatic"), "UTF-8", "UTF-16LE", "UTF-16BE", "GB18030", "BIG5", "SHIFT_JIS",
	"EUC-JP", "EUC-KR", "WINDOWS-1252", "ISO-8859-1", "KOI8-R", "WINDOWS-1251", nullptr
};

struct text_ui
{
	GtkWindow *dialog = nullptr;
	GtkTextView *view = nullptr;
	GtkTextBuffer *buffer = nullptr;
	GtkWidget *charset = nullptr;
	GtkLabel *info = nullptr;
	GtkWidget *search_bar = nullptr;
	GtkWidget *search_entry = nullptr;
	std::string path;
	std::vector<unsigned char> data;
	unsigned long long size = 0;
	bool closed = false;
};

using text_ptr = std::shared_ptr<text_ui>;

text_ptr
text_of (gpointer widget)
{
	return *static_cast<text_ptr *> (g_object_get_data (G_OBJECT (widget), "rover-text"));
}

/* The 8-bit charset a non-UTF-8 file most likely uses: the filename
   encoding chosen for the volume, else the one of the UI language.  */
const char *
legacy_charset ()
{
	switch (S.fs_encoding)
	{
	case 936: return "GB18030";
	case 950: return "BIG5";
	case 932: return "SHIFT_JIS";
	case 51949: return "EUC-KR";
	}
	for (const char *const *lang = g_get_language_names (); *lang; lang++)
	{
		if (g_str_has_prefix (*lang, "zh_TW") || g_str_has_prefix (*lang, "zh_HK"))
			return "BIG5";
		if (g_str_has_prefix (*lang, "zh"))
			return "GB18030";
		if (g_str_has_prefix (*lang, "ja"))
			return "SHIFT_JIS";
		if (g_str_has_prefix (*lang, "ko"))
			return "EUC-KR";
		if (g_str_has_prefix (*lang, "ru") || g_str_has_prefix (*lang, "uk")
			|| g_str_has_prefix (*lang, "bg"))
			return "WINDOWS-1251";
	}
	return "WINDOWS-1252";
}

/* Charset for DATA when the user left it to us; *SKIP is the BOM length.  */
const char *
detect_charset (const std::vector<unsigned char> &data, size_t *skip)
{
	size_t n = data.size ();
	size_t zero_even = 0;
	size_t zero_odd = 0;

	*skip = 0;
	if (n >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf)
	{
		*skip = 3;
		return "UTF-8";
	}
	if (n >= 2 && data[0] == 0xff && data[1] == 0xfe)
	{
		*skip = 2;
		return "UTF-16LE";
	}
	if (n >= 2 && data[0] == 0xfe && data[1] == 0xff)
	{
		*skip = 2;
		return "UTF-16BE";
	}
	/* BOM-less UTF-16 text has a NUL in every other byte.  */
	for (size_t i = 0; i < n && i < 4096; i++)
		if (!data[i])
			(i & 1 ? zero_odd : zero_even)++;
	size_t sample = std::min (n, (size_t) 4096) / 2;
	if (sample && zero_odd > sample * 3 / 4 && zero_even < sample / 8)
		return "UTF-16LE";
	if (sample && zero_even > sample * 3 / 4 && zero_odd < sample / 8)
		return "UTF-16BE";
	/* A truncated read may end in the middle of a sequence.  */
	const char *end = nullptr;
	if (g_utf8_validate ((const char *) data.data (), (gssize) n, &end)
		|| (n == TEXT_MAX && (const unsigned char *) end + 4 > data.data () + n))
		return "UTF-8";
	return legacy_charset ();
}

/* DATA in CHARSET as UTF-8, with U+FFFD for whatever does not convert.  */
std::string
decode (const unsigned char *data, size_t size, const char *charset)
{
	GIConv cd = g_iconv_open ("UTF-8", charset);
	std::string out;
	size_t unit = g_str_has_prefix (charset, "UTF-16") ? 2 : 1;

	if (cd == (GIConv) -1)
	{
		char *valid = g_utf8_make_valid ((const char *) data, (gssize) size);
		out = valid;
		g_free (valid);
		return out;
	}
	std::vector<char> buf (65536);
	char *in = (char *) data;
	gsize in_left = size;
	while (in_left)
	{
		char *o = buf.data ();
		gsize o_left = buf.size ();
		gsize r = g_iconv (cd, &in, &in_left, &o, &o_left);
		out.append (buf.data (), buf.size () - o_left);
		if (r == (gsize) -1)
		{
			if (errno == E2BIG)
				continue;
			/* EILSEQ, or EINVAL for a sequence cut off by the read cap.  */
			out += "\xef\xbf\xbd";
			gsize step = std::min (in_left, unit);
			in += step;
			in_left -= step;
			g_iconv (cd, nullptr, nullptr, nullptr, nullptr);
		}
	}
	g_iconv_close (cd);
	return out;
}

void
render (const text_ptr &u)
{
	guint index = gtk_drop_down_get_selected (GTK_DROP_DOWN (u->charset));
	size_t skip = 0;
	const char *charset = index == 0 ? detect_charset (u->data, &skip) : CHARSETS[index];
	std::string text = decode (u->data.data () + skip, u->data.size () - skip, charset);

	/* A text buffer cannot hold NUL; show it as the control picture.  */
	for (size_t at = text.find ('\0'); at != std::string::npos; at = text.find ('\0', at))
		text.replace (at, 1, "\xe2\x90\x80");
	gtk_text_buffer_set_text (u->buffer, text.c_str (), (int) text.size ());
	std::string info = fmt (_("%s, %s"), format_size (u->size).c_str (), charset);
	if (u->size > u->data.size ())
		info += " — " + fmt (_("showing the first %s"), format_size (u->data.size ()).c_str ());
	gtk_label_set_text (u->info, info.c_str ());
}

void
on_charset_changed (GtkDropDown *, GParamSpec *, gpointer dialog)
{
	text_ptr u = text_of (dialog);

	if (!u->data.empty () || u->size == 0)
		render (u);
}

void
on_wrap_toggled (GtkCheckButton *check, gpointer dialog)
{
	gtk_text_view_set_wrap_mode (text_of (dialog)->view,
		gtk_check_button_get_active (check) ? GTK_WRAP_WORD_CHAR : GTK_WRAP_NONE);
}

/* Find the next match after the selection, wrapping around once.  */
void
find_next (const text_ptr &u, bool from_start)
{
	std::string needle = gtk_editable_get_text (GTK_EDITABLE (u->search_entry));
	GtkTextIter start, match_start, match_end;

	if (needle.empty ())
		return;
	if (from_start)
		gtk_text_buffer_get_start_iter (u->buffer, &start);
	else
	{
		GtkTextIter sel_start;
		gtk_text_buffer_get_selection_bounds (u->buffer, &sel_start, &start);
	}
	GtkTextSearchFlags flags = (GtkTextSearchFlags) (GTK_TEXT_SEARCH_CASE_INSENSITIVE
		| GTK_TEXT_SEARCH_TEXT_ONLY);
	bool found = gtk_text_iter_forward_search (&start, needle.c_str (), flags,
		&match_start, &match_end, nullptr);
	if (!found && !from_start)
	{
		gtk_text_buffer_get_start_iter (u->buffer, &start);
		found = gtk_text_iter_forward_search (&start, needle.c_str (), flags,
			&match_start, &match_end, nullptr);
	}
	if (!found)
	{
		gtk_widget_error_bell (u->search_entry);
		return;
	}
	gtk_text_buffer_select_range (u->buffer, &match_start, &match_end);
	gtk_text_view_scroll_to_iter (u->view, &match_start, 0.1, FALSE, 0, 0);
}

void
on_search_changed (GtkSearchEntry *, gpointer dialog)
{
	find_next (text_of (dialog), true);
}

void
on_search_next (GtkSearchEntry *, gpointer dialog)
{
	find_next (text_of (dialog), false);
}

void
on_text_destroy (GtkWidget *dialog, gpointer)
{
	text_of (dialog)->closed = true;
}

} /* namespace */

void
show_text (const std::string &path)
{
	auto u = std::make_shared<text_ptr::element_type> ();
	GtkWindow *dialog = new_dialog (fmt (_("%s — Text"), basename_of (path).c_str ()), 820, 600);
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *bar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	GtkWidget *scroll = gtk_scrolled_window_new ();
	GtkWidget *wrap = gtk_check_button_new_with_mnemonic (_("_Wrap lines"));
	GtkWidget *search_button = gtk_toggle_button_new ();
	const char *names[G_N_ELEMENTS (CHARSETS)];

	for (size_t i = 0; i < G_N_ELEMENTS (CHARSETS); i++)
		names[i] = i == 0 ? _(CHARSETS[0]) : CHARSETS[i];
	u->dialog = dialog;
	u->path = path;
	u->view = GTK_TEXT_VIEW (gtk_text_view_new ());
	u->buffer = gtk_text_view_get_buffer (u->view);
	gtk_text_view_set_editable (u->view, FALSE);
	gtk_text_view_set_monospace (u->view, TRUE);
	gtk_text_view_set_left_margin (u->view, 6);
	gtk_text_view_set_right_margin (u->view, 6);
	u->charset = gtk_drop_down_new_from_strings (names);
	u->info = GTK_LABEL (gtk_label_new (_("Reading…")));
	gtk_label_set_xalign (u->info, 0);
	gtk_label_set_ellipsize (u->info, PANGO_ELLIPSIZE_END);
	gtk_widget_set_hexpand (GTK_WIDGET (u->info), TRUE);
	gtk_button_set_icon_name (GTK_BUTTON (search_button), "edit-find-symbolic");
	gtk_widget_set_tooltip_text (search_button, _("Find (Ctrl+F)"));

	gtk_widget_set_margin_start (bar, 8);
	gtk_widget_set_margin_end (bar, 8);
	gtk_widget_set_margin_top (bar, 6);
	gtk_widget_set_margin_bottom (bar, 6);
	gtk_box_append (GTK_BOX (bar), GTK_WIDGET (u->info));
	gtk_box_append (GTK_BOX (bar), wrap);
	gtk_box_append (GTK_BOX (bar), u->charset);
	gtk_box_append (GTK_BOX (bar), search_button);

	u->search_entry = gtk_search_entry_new ();
	u->search_bar = gtk_search_bar_new ();
	gtk_search_bar_set_child (GTK_SEARCH_BAR (u->search_bar), u->search_entry);
	gtk_search_bar_connect_entry (GTK_SEARCH_BAR (u->search_bar), GTK_EDITABLE (u->search_entry));
	gtk_search_bar_set_show_close_button (GTK_SEARCH_BAR (u->search_bar), TRUE);
	gtk_search_bar_set_key_capture_widget (GTK_SEARCH_BAR (u->search_bar), GTK_WIDGET (dialog));
	g_object_bind_property (search_button, "active", u->search_bar, "search-mode-enabled",
		(GBindingFlags) (G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE));

	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), GTK_WIDGET (u->view));
	gtk_widget_set_vexpand (scroll, TRUE);
	gtk_box_append (GTK_BOX (box), bar);
	gtk_box_append (GTK_BOX (box), u->search_bar);
	gtk_box_append (GTK_BOX (box), gtk_separator_new (GTK_ORIENTATION_HORIZONTAL));
	gtk_box_append (GTK_BOX (box), scroll);
	gtk_window_set_child (dialog, box);

	g_object_set_data_full (G_OBJECT (dialog), "rover-text", new text_ptr (u),
		[] (gpointer p) { delete static_cast<text_ptr *> (p); });
	g_signal_connect (u->charset, "notify::selected", G_CALLBACK (on_charset_changed), dialog);
	g_signal_connect (wrap, "toggled", G_CALLBACK (on_wrap_toggled), dialog);
	g_signal_connect (u->search_entry, "search-changed", G_CALLBACK (on_search_changed), dialog);
	g_signal_connect (u->search_entry, "activate", G_CALLBACK (on_search_next), dialog);
	g_signal_connect (u->search_entry, "next-match", G_CALLBACK (on_search_next), dialog);
	g_signal_connect (dialog, "destroy", G_CALLBACK (on_text_destroy), nullptr);
	gtk_window_present (dialog);

	run_job ([path] { return read_chunk (path, 0, TEXT_MAX); }, [u] (chunk c)
	{
		if (u->closed)
			return;
		if (!c.error.empty ())
		{
			gtk_label_set_text (u->info, c.error.c_str ());
			return;
		}
		u->size = c.size;
		u->data = std::move (c.data);
		render (u);
	});
}
