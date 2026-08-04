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

/* Markdown -> RTF, driven by md4c's push parser (FsRover\md4c, taken
 * from upstream unchanged).  RTF is the output format because the
 * viewer is a plain RichEdit: no browser control, no extra runtime, and
 * selection/copy come for free.
 *
 * The renderer keeps no block stack of its own.  Paragraphs open
 * lazily -- the first text or span inside a block starts one with the
 * properties the current state implies (indent from the quote/list
 * nesting, hanging indent for a list marker, tab stops for a table
 * row) and each one begins with \pard\plain, so no formatting can leak
 * from the paragraph before it.  The closing \par is emitted by the
 * *next* open, which keeps the document from ending in a stray empty
 * paragraph and makes the character count below exact.
 *
 * That count is the second job of the renderer: every control word it
 * writes produces either zero characters or exactly one, so the
 * running total is the character position the RichEdit will report.
 * Link spans are recorded with those positions and the caller turns
 * them into CFE_LINK ranges after streaming; mdview.cpp checks the
 * total against the control before trusting them.
 *
 * Two constructs work around what RichEdit does not read.  Tables are
 * laid out with tab stops instead of \trowd rows, so a cell wider than
 * its column pushes the rest of the row right rather than colliding
 * with it; a thematic break is an underlined tab to a stop past the
 * right edge, because paragraph borders (\brdrb) are parsed and then
 * ignored -- measured, not assumed.
 *
 * Deliberate limitations: raw HTML is dropped (inline markup keeps its
 * text, an HTML block disappears) and images render as their alt text.
 */

#include <windows.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include "mdrtf.h"

extern "C"
{
#include "md4c/md4c.h"
#include "md4c/entity.h"
}

namespace
{

/* Colour table slots; index 0 is RTF's "auto" and stays unused.  The
   order here is the order md_rtf_style fields are written out.  */
constexpr int COL_TEXT = 1;
constexpr int COL_QUOTE = 2;
constexpr int COL_LINK = 3;
constexpr int COL_CODE = 4;
constexpr int COL_CODEBG = 5;
constexpr int COL_RULE = 6;

constexpr int INDENT_STEP = 300;	/* twips per quote/list level */
constexpr int LIST_HANG = 260;	/* marker overhang of a list item */
constexpr int TABLE_W = 8400;	/* total width tab stops spread over */
constexpr int RULE_W = 14400;	/* thematic break width, twips */

/* Heading size as a percentage of the body size, h1 first.  */
const int HEADING_PCT[6] = { 175, 145, 125, 112, 100, 92 };

/* Bullet per unordered nesting level: * o - (U+2022/25E6/25AA).  */
const wchar_t BULLETS[3] = { 0x2022, 0x25e6, 0x25aa };

void
utf8_append (std::wstring &out, const char *p, size_t n)
{
	if (!n)
		return;
	int len = MultiByteToWideChar (CP_UTF8, 0, p, (int) n, nullptr, 0);
	if (len <= 0)
		return;
	size_t at = out.size ();
	out.resize (at + (size_t) len);
	MultiByteToWideChar (CP_UTF8, 0, p, (int) n, out.data () + at, len);
}

void
cp_append (std::wstring &out, unsigned cp)
{
	if (!cp || cp > 0x10ffff || (cp >= 0xd800 && cp < 0xe000))
		cp = 0xfffd;
	if (cp >= 0x10000)
	{
		cp -= 0x10000;
		out += (wchar_t) (0xd800 + (cp >> 10));
		out += (wchar_t) (0xdc00 + (cp & 0x3ff));
		return;
	}
	out += (wchar_t) cp;
}

/* One MD_TEXT_ENTITY run, e.g. "&amp;", "&#65;" or "&#x41;".  The text
   is not terminated, but it always ends in ';', which stops strtoul as
   reliably as a NUL would.  Anything unknown is kept verbatim, which is
   also what a browser shows.  */
void
entity_append (std::wstring &out, const char *p, size_t n)
{
	if (n > 3 && p[1] == '#')
	{
		unsigned base = (p[2] == 'x' || p[2] == 'X') ? 16u : 10u;
		cp_append (out, (unsigned) strtoul (p + (base == 16 ? 3 : 2), nullptr, (int) base));
		return;
	}

	const ENTITY *ent = entity_lookup (p, n);
	if (!ent)
	{
		utf8_append (out, p, n);
		return;
	}
	cp_append (out, ent->codepoints[0]);
	if (ent->codepoints[1])
		cp_append (out, ent->codepoints[1]);
}

/* Link targets and the like arrive split into normal/entity pieces.  */
std::wstring
attr_text (const MD_ATTRIBUTE *a)
{
	std::wstring out;

	if (!a->text)
		return out;
	for (int i = 0; a->substr_offsets[i] < a->size; i++)
	{
		const char *p = a->text + a->substr_offsets[i];
		size_t n = a->substr_offsets[i + 1] - a->substr_offsets[i];
		if (a->substr_types[i] == MD_TEXT_ENTITY)
			entity_append (out, p, n);
		else if (a->substr_types[i] == MD_TEXT_NULLCHAR)
			out += L'\xfffd';
		else
			utf8_append (out, p, n);
	}
	return out;
}

/* Append text as RTF body, one control character per wchar_t: the
   caller's character accounting depends on that ratio holding.  */
void
rtf_escape (std::string &out, const std::wstring &text)
{
	char buf[16];

	for (wchar_t c : text)
	{
		if (c == L'\\' || c == L'{' || c == L'}')
		{
			out += '\\';
			out += (char) c;
		}
		else if (c >= 0x20 && c < 0x7f)
			out += (char) c;
		else if (c == L'\t')
			out += "\\tab ";
		else if (c == L'\r' || c == L'\n')
			out += ' ';	/* line breaks are the block layer's job */
		else
		{
			snprintf (buf, sizeof (buf), "\\u%d?", (int) (short) c);
			out += buf;
		}
	}
}

class renderer
{
public:
	explicit renderer (const md_rtf_style &style) : m_st (style)
	{
	}

	void prologue (void);
	void epilogue (void);
	md_rtf_doc take (void) { return { std::move (m_out), std::move (m_links), m_chars }; }

	int enter_block (MD_BLOCKTYPE type, void *detail);
	int leave_block (MD_BLOCKTYPE type, void *detail);
	int enter_span (MD_SPANTYPE type, void *detail);
	int leave_span (MD_SPANTYPE type, void *detail);
	int text (MD_TEXTTYPE type, const char *p, MD_SIZE n);

private:
	struct list_level
	{
		bool ordered;
		unsigned next;	/* item number of an ordered list */
	};

	int base_cf (void) const { return m_quote ? COL_QUOTE : COL_TEXT; }
	int base_halfpt (void) const { return (m_st.body_pt10 + 2) / 5; }

	void put (const char *rtf) { m_out += rtf; }
	void putf (const char *fmt, ...);
	void put_text (const std::wstring &text);
	void put_utf8 (const char *p, size_t n);
	void put_char (wchar_t c) { put_text (std::wstring (1, c)); }

	void open_para (void);
	void close_para (void);
	void emit_rule (void);
	void emit_code_text (const char *p, MD_SIZE n);
	std::wstring list_marker (const MD_BLOCK_LI_DETAIL *det);
	void begin_link (std::wstring target);
	void end_link (void);

	std::string m_out;
	LONG m_chars = 0;	/* characters the control will hold so far */
	const md_rtf_style &m_st;
	std::vector<md_rtf_link> m_links;

	bool m_para = false;	/* a paragraph is open */
	bool m_need_par = false;	/* the previous one still owes its \par */
	int m_indent = 0;	/* left indent, twips */
	int m_quote = 0;	/* block quote nesting */
	std::vector<list_level> m_lists;
	std::wstring m_marker;	/* list marker waiting for a paragraph */
	int m_heading = 0;	/* heading level, 0 outside one */
	bool m_code = false;	/* inside a code block */
	int m_code_nl = 0;	/* newlines owed inside that block */
	bool m_rule = false;	/* the paragraph being opened is a rule */
	unsigned m_cols = 0;	/* table columns, 0 outside a table */
	unsigned m_cell = 0;	/* cells emitted in the current row */
	bool m_head_row = false;	/* the row is a table header */
	std::string m_stops;	/* tab stops shared by the table's rows */
	bool m_in_link = false;
	LONG m_link_at = 0;
	std::wstring m_link_target;
};

void
renderer::putf (const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf), fmt, ap);
	va_end (ap);
	m_out += buf;
}

void
renderer::put_text (const std::wstring &text)
{
	rtf_escape (m_out, text);
	m_chars += (LONG) text.size ();
}

void
renderer::put_utf8 (const char *p, size_t n)
{
	std::wstring w;

	utf8_append (w, p, n);
	put_text (w);
}

/* Paragraph properties and the character defaults that go with them.
   Both are rebuilt from scratch (\pard\plain) for every paragraph.  */
void
renderer::open_para (void)
{
	if (m_para)
		return;
	if (m_need_par)
	{
		put ("\\par\n");
		m_chars++;
		m_need_par = false;
	}
	m_para = true;

	put ("\\pard\\plain");
	if (m_cols)
	{
		putf ("\\sa40\\li%d", m_indent);
		put (m_stops.c_str ());
	}
	else if (!m_marker.empty ())
		putf ("\\sa60\\li%d\\fi-%d", m_indent, LIST_HANG);
	else if (m_rule)
		putf ("\\sb120\\sa120\\li%d\\tx%d", m_indent, m_indent + RULE_W);
	else if (m_heading)
		putf ("\\sb200\\sa80\\keepn\\li%d", m_indent);
	else if (m_code)
		putf ("\\sb60\\sa120\\li%d", m_indent + INDENT_STEP);
	else
		putf ("\\sa120\\li%d", m_indent);

	int halfpt = base_halfpt ();
	if (m_heading)
		halfpt = halfpt * HEADING_PCT[m_heading - 1] / 100;
	else if (m_code)
		halfpt = halfpt * 92 / 100;
	putf ("\\f%d\\fs%d", m_code ? 1 : 0, halfpt);
	if (m_heading || m_head_row)
		put ("\\b");
	if (m_code)
		putf ("\\cf%d\\highlight%d", COL_CODE, COL_CODEBG);
	else
		putf ("\\cf%d", m_rule ? COL_RULE : base_cf ());
	put (" ");

	if (!m_marker.empty ())
	{
		std::wstring marker = std::move (m_marker);
		m_marker.clear ();
		put_text (marker);
		put ("\\tab ");
		m_chars++;
	}
}

void
renderer::close_para (void)
{
	if (!m_para)
		return;
	m_para = false;
	m_need_par = true;
}

/* One underlined tab reaching a stop well past the right edge: the
   underline draws the line and the tab never wraps, so the break fills
   whatever width the window has.  */
void
renderer::emit_rule (void)
{
	close_para ();
	m_rule = true;
	open_para ();
	put ("\\ul\\tab\\ulnone ");
	m_chars++;
	close_para ();
	m_rule = false;
}

/* Code block text arrives with its newlines embedded.  They become
   \line so the whole block stays one paragraph (and one continuous
   background); the newline that closes the last line is dropped by
   only flushing what is owed once more text shows up.  */
void
renderer::emit_code_text (const char *p, MD_SIZE n)
{
	MD_SIZE i = 0;

	if (!m_code)
	{
		open_para ();
		put_utf8 (p, n);
		return;
	}
	while (i < n)
	{
		MD_SIZE end = i;
		while (end < n && p[end] != '\n')
			end++;
		if (end > i)
		{
			open_para ();
			for (; m_code_nl > 0; m_code_nl--)
			{
				put ("\\line ");
				m_chars++;
			}
			put_utf8 (p + i, end - i);
		}
		if (end < n)
		{
			m_code_nl++;
			end++;
		}
		i = end;
	}
}

std::wstring
renderer::list_marker (const MD_BLOCK_LI_DETAIL *det)
{
	wchar_t buf[24];

	if (det->is_task)
		return std::wstring (1, det->task_mark == ' ' ? L'\x2610' : L'\x2611');
	if (m_lists.empty ())
		return std::wstring (1, BULLETS[0]);
	if (m_lists.back ().ordered)
	{
		swprintf (buf, 24, L"%u.", m_lists.back ().next++);
		return buf;
	}
	return std::wstring (1, BULLETS[(m_lists.size () - 1) % 3]);
}

void
renderer::begin_link (std::wstring target)
{
	putf ("\\cf%d\\ul ", COL_LINK);
	m_in_link = true;
	m_link_at = m_chars;
	m_link_target = std::move (target);
}

void
renderer::end_link (void)
{
	putf ("\\ulnone\\cf%d ", base_cf ());
	if (!m_in_link)
		return;
	m_in_link = false;
	if (m_chars > m_link_at && !m_link_target.empty ())
		m_links.push_back ({ m_link_at, m_chars, std::move (m_link_target) });
	m_link_target.clear ();
}

void
renderer::prologue (void)
{
	const COLORREF colors[] =
	{
		m_st.text, m_st.quote, m_st.link,
		m_st.code, m_st.code_bg, m_st.rule,
	};

	m_out = "{\\rtf1\\ansi\\ansicpg1252\\deff0\\uc1\n{\\fonttbl{\\f0\\fswiss\\fcharset0 ";
	rtf_escape (m_out, m_st.body_face);
	m_out += ";}{\\f1\\fmodern\\fcharset0 ";
	rtf_escape (m_out, m_st.mono_face);
	m_out += ";}}\n{\\colortbl;";
	for (COLORREF c : colors)
		putf ("\\red%d\\green%d\\blue%d;", GetRValue (c), GetGValue (c), GetBValue (c));
	m_out += "}\n\\viewkind4\n";
}

void
renderer::epilogue (void)
{
	/* No closing \par: the last paragraph mark would be a character
	   the caller did not count.  */
	m_out += "}\n";
}

int
renderer::enter_block (MD_BLOCKTYPE type, void *detail)
{
	switch (type)
	{
	case MD_BLOCK_QUOTE:
		close_para ();
		m_quote++;
		m_indent += INDENT_STEP;
		break;
	case MD_BLOCK_UL:
		close_para ();
		m_lists.push_back ({ false, 0 });
		m_indent += INDENT_STEP;
		break;
	case MD_BLOCK_OL:
		close_para ();
		m_lists.push_back ({ true, ((MD_BLOCK_OL_DETAIL *) detail)->start });
		m_indent += INDENT_STEP;
		break;
	case MD_BLOCK_LI:
		close_para ();
		m_marker = list_marker ((MD_BLOCK_LI_DETAIL *) detail);
		break;
	case MD_BLOCK_HR:
		emit_rule ();
		break;
	case MD_BLOCK_H:
		close_para ();
		m_heading = (int) ((MD_BLOCK_H_DETAIL *) detail)->level;
		if (m_heading < 1 || m_heading > 6)
			m_heading = 6;
		break;
	case MD_BLOCK_CODE:
		close_para ();
		m_code = true;
		m_code_nl = 0;
		break;
	case MD_BLOCK_TABLE:
	{
		unsigned cols = ((MD_BLOCK_TABLE_DETAIL *) detail)->col_count;
		close_para ();
		m_cols = cols ? cols : 1;
		m_stops.clear ();
		for (unsigned i = 1; i <= m_cols; i++)
		{
			char buf[32];
			snprintf (buf, sizeof (buf), "\\tx%d", m_indent + (int) i * (TABLE_W / (int) m_cols));
			m_stops += buf;
		}
		break;
	}
	case MD_BLOCK_THEAD:
		m_head_row = true;
		break;
	case MD_BLOCK_TR:
		close_para ();
		m_cell = 0;
		break;
	case MD_BLOCK_TH:
	case MD_BLOCK_TD:
		open_para ();
		if (m_cell)
		{
			put ("\\tab ");
			m_chars++;
		}
		m_cell++;
		break;
	case MD_BLOCK_DOC:
	case MD_BLOCK_HTML:
	case MD_BLOCK_P:
	case MD_BLOCK_TBODY:
		close_para ();
		break;
	}
	return 0;
}

int
renderer::leave_block (MD_BLOCKTYPE type, void *)
{
	switch (type)
	{
	case MD_BLOCK_QUOTE:
		close_para ();
		m_quote--;
		m_indent -= INDENT_STEP;
		break;
	case MD_BLOCK_UL:
	case MD_BLOCK_OL:
		close_para ();
		if (!m_lists.empty ())
			m_lists.pop_back ();
		m_indent -= INDENT_STEP;
		break;
	case MD_BLOCK_LI:
		/* An item with no content still shows its marker.  */
		if (!m_marker.empty ())
			open_para ();
		close_para ();
		break;
	case MD_BLOCK_H:
		close_para ();
		m_heading = 0;
		break;
	case MD_BLOCK_CODE:
		close_para ();
		m_code = false;
		m_code_nl = 0;
		break;
	case MD_BLOCK_TABLE:
		close_para ();
		m_cols = 0;
		m_stops.clear ();
		break;
	case MD_BLOCK_THEAD:
		m_head_row = false;
		break;
	case MD_BLOCK_TH:
	case MD_BLOCK_TD:
		break;	/* the row paragraph runs on */
	case MD_BLOCK_DOC:
	case MD_BLOCK_HR:
	case MD_BLOCK_HTML:
	case MD_BLOCK_P:
	case MD_BLOCK_TBODY:
	case MD_BLOCK_TR:
		close_para ();
		break;
	}
	return 0;
}

int
renderer::enter_span (MD_SPANTYPE type, void *detail)
{
	open_para ();
	switch (type)
	{
	case MD_SPAN_EM:
		put ("\\i ");
		break;
	case MD_SPAN_STRONG:
		put ("\\b ");
		break;
	case MD_SPAN_U:
		put ("\\ul ");
		break;
	case MD_SPAN_DEL:
		put ("\\strike ");
		break;
	case MD_SPAN_CODE:
		if (!m_code)
			putf ("\\f1\\cf%d\\highlight%d ", COL_CODE, COL_CODEBG);
		break;
	case MD_SPAN_A:
		begin_link (attr_text (&((MD_SPAN_A_DETAIL *) detail)->href));
		break;
	case MD_SPAN_WIKILINK:
		begin_link (attr_text (&((MD_SPAN_WIKILINK_DETAIL *) detail)->target));
		break;
	case MD_SPAN_IMG:
		/* No image loading here: the alt text stands in for it.  */
		putf ("\\i\\cf%d ", COL_LINK);
		put_char (L'[');
		break;
	case MD_SPAN_LATEXMATH:
	case MD_SPAN_LATEXMATH_DISPLAY:
		break;
	}
	return 0;
}

int
renderer::leave_span (MD_SPANTYPE type, void *)
{
	switch (type)
	{
	case MD_SPAN_EM:
		put ("\\i0 ");
		break;
	case MD_SPAN_STRONG:
		put ("\\b0 ");
		break;
	case MD_SPAN_U:
		put ("\\ulnone ");
		break;
	case MD_SPAN_DEL:
		put ("\\strike0 ");
		break;
	case MD_SPAN_CODE:
		if (!m_code)
			putf ("\\f0\\highlight0\\cf%d ", base_cf ());
		break;
	case MD_SPAN_A:
	case MD_SPAN_WIKILINK:
		end_link ();
		break;
	case MD_SPAN_IMG:
		put_char (L']');
		putf ("\\i0\\cf%d ", base_cf ());
		break;
	case MD_SPAN_LATEXMATH:
	case MD_SPAN_LATEXMATH_DISPLAY:
		break;
	}
	return 0;
}

int
renderer::text (MD_TEXTTYPE type, const char *p, MD_SIZE n)
{
	std::wstring w;

	switch (type)
	{
	case MD_TEXT_NULLCHAR:
		open_para ();
		put_char (L'\xfffd');
		break;
	case MD_TEXT_BR:
		if (m_para)
		{
			put ("\\line ");
			m_chars++;
		}
		break;
	case MD_TEXT_SOFTBR:
		if (m_para)
			put_char (L' ');
		break;
	case MD_TEXT_ENTITY:
		open_para ();
		entity_append (w, p, n);
		put_text (w);
		break;
	case MD_TEXT_HTML:
		break;	/* dropped; see the file comment */
	case MD_TEXT_CODE:
		emit_code_text (p, n);
		break;
	case MD_TEXT_NORMAL:
	case MD_TEXT_LATEXMATH:
		open_para ();
		put_utf8 (p, n);
		break;
	}
	return 0;
}

int
cb_enter_block (MD_BLOCKTYPE type, void *detail, void *userdata)
{
	return ((renderer *) userdata)->enter_block (type, detail);
}

int
cb_leave_block (MD_BLOCKTYPE type, void *detail, void *userdata)
{
	return ((renderer *) userdata)->leave_block (type, detail);
}

int
cb_enter_span (MD_SPANTYPE type, void *detail, void *userdata)
{
	return ((renderer *) userdata)->enter_span (type, detail);
}

int
cb_leave_span (MD_SPANTYPE type, void *detail, void *userdata)
{
	return ((renderer *) userdata)->leave_span (type, detail);
}

int
cb_text (MD_TEXTTYPE type, const MD_CHAR *p, MD_SIZE n, void *userdata)
{
	return ((renderer *) userdata)->text (type, p, n);
}

} // namespace

md_rtf_style
md_rtf_default_style (void)
{
	NONCLIENTMETRICSW ncm = { sizeof (ncm) };
	md_rtf_style st;

	st.body_face = L"Segoe UI";
	st.mono_face = L"Consolas";
	st.body_pt10 = 100;
	if (SystemParametersInfoW (SPI_GETNONCLIENTMETRICS, sizeof (ncm), &ncm, 0))
	{
		HDC dc = GetDC (nullptr);
		int height = ncm.lfMessageFont.lfHeight;
		int dpi = GetDeviceCaps (dc, LOGPIXELSY);
		ReleaseDC (nullptr, dc);
		if (height < 0)
			height = -height;
		if (height > 0 && dpi > 0)
			st.body_pt10 = MulDiv (height, 720, dpi);
		if (ncm.lfMessageFont.lfFaceName[0])
			st.body_face = ncm.lfMessageFont.lfFaceName;
	}
	if (st.body_pt10 < 60 || st.body_pt10 > 300)
		st.body_pt10 = 100;

	st.text = GetSysColor (COLOR_WINDOWTEXT);
	st.quote = GetSysColor (COLOR_GRAYTEXT);
	st.link = GetSysColor (COLOR_HOTLIGHT);
	st.code = st.text;
	st.code_bg = GetSysColor (COLOR_BTNFACE);
	st.rule = GetSysColor (COLOR_GRAYTEXT);
	return st;
}

md_rtf_doc
md_to_rtf (const char *text, size_t size, const md_rtf_style &style)
{
	MD_PARSER parser = {};
	renderer render (style);

	if (size > 0xffffffffu)
		size = 0xffffffffu;
	parser.flags = MD_DIALECT_GITHUB | MD_FLAG_COLLAPSEWHITESPACE;
	parser.enter_block = cb_enter_block;
	parser.leave_block = cb_leave_block;
	parser.enter_span = cb_enter_span;
	parser.leave_span = cb_leave_span;
	parser.text = cb_text;

	render.prologue ();
	md_parse (text, (MD_SIZE) size, &parser, &render);
	render.epilogue ();
	return render.take ();
}
