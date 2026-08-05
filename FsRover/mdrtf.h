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
 * Markdown -> RTF.  The only interface between md4c and the GUI: it
 * takes a UTF-8 CommonMark (GitHub dialect) document and returns an RTF
 * document ready for EM_STREAMIN, plus the character ranges of every
 * link so the caller can mark them CFE_LINK and act on EN_LINK.
 *
 * Nothing here touches a window, so the conversion can serve any
 * markdown source: a file read out of the browsed filesystem, a help
 * page compiled into the executable, or one shipped next to it.
 */

#ifndef FSROVER_MDRTF_H
#define FSROVER_MDRTF_H	1

#include <windows.h>

#include <string>
#include <vector>

/* One link in the rendered document: the half-open character range it
   occupies in the RichEdit ([start, end)) and what it points at.  */
struct md_rtf_link
{
	LONG start;
	LONG end;
	std::wstring target;
};

/* A heading, under the slug a "#..." link would name it by.  The slug
   is built the way GitHub builds one -- lowercased, punctuation
   dropped, spaces turned into hyphens -- so a table of contents
   written for GitHub resolves here too.  */
struct md_rtf_anchor
{
	std::wstring slug;
	LONG at;	/* character position of the heading text */
};

/* Look of the rendered document.  md_rtf_default_style() fills this
   from the system message font and the system colours; a caller that
   wants a different body font or size only has to override fields.  */
struct md_rtf_style
{
	std::wstring body_face;	/* proportional face, for prose */
	std::wstring mono_face;	/* fixed face, for code */
	int body_pt10;	/* body size, 1/10 pt */
	COLORREF text;
	COLORREF quote;	/* block quotes */
	COLORREF link;
	COLORREF code;	/* code text */
	COLORREF code_bg;
	COLORREF rule;	/* thematic breaks, table head underline */
};

md_rtf_style md_rtf_default_style (void);

/* A converted document.  The link positions assume `rtf` was streamed
   into a fresh control; `chars` is what the control should then report,
   so a caller can check it against EM_GETTEXTLENGTHEX and only trust
   the ranges if the two agree.  */
struct md_rtf_doc
{
	std::string rtf;	/* ready for EM_STREAMIN with SF_RTF */
	std::vector<md_rtf_link> links;	/* in document order */
	std::vector<md_rtf_anchor> anchors;	/* one per heading */
	LONG chars;
};

/* Render `size` bytes of UTF-8 markdown (CommonMark, GitHub dialect).  */
md_rtf_doc md_to_rtf (const char *text, size_t size, const md_rtf_style &style);

#endif /* ! FSROVER_MDRTF_H */
