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

#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

#include <string>

#include "gui.h"
#include "../common/optparse.h"
#include "resource.h"

cmdline_options g_cmdline;

namespace
{

/* Index into OPTS below; optparse() returns the same number for a
   short name and its long spelling.  */
enum
{
	OPT_MINIMIZE,
	OPT_FILE,
	OPT_FILE_DEC,
	OPT_HELP,
};

const struct optparse_option OPTS[] =
{
	{ L"minimize", L'm', OPTPARSE_NONE },
	{ L"file", L'f', OPTPARSE_REQUIRED },
	{ L"file-dec", L'd', OPTPARSE_REQUIRED },
	{ L"help", L'h', OPTPARSE_NONE },
	{ nullptr, 0, OPTPARSE_NONE },
};

/* The usage box, with PROBLEM above it when the line was wrong.
   optparse writes its errmsg in English only, which is why the
   localized part is the usage text below it.  */
void
show_usage (const wchar_t *problem)
{
	std::wstring text;

	if (problem)
		text = std::wstring (problem) + L"\n\n";
	text += res_str (IDS_CMDLINE_USAGE);
	MessageBoxW (nullptr, text.c_str (), res_str (IDS_APP_TITLE).c_str (),
		MB_OK | (problem ? MB_ICONERROR : MB_ICONINFORMATION));
}

/* The image is opened much later, on the backend thread, and its path
   is shown in the disk properties: resolve it against the current
   directory while that still means what the user meant.  */
std::wstring
full_path (const wchar_t *arg)
{
	DWORD len = GetFullPathNameW (arg, 0, nullptr, nullptr);
	std::wstring out;

	if (!len)
		return arg;
	out.resize (len);
	len = GetFullPathNameW (arg, len, out.data (), nullptr);
	if (!len || len >= out.size ())
		return arg;
	out.resize (len);
	return out;
}

} // namespace

bool
cmdline_parse (void)
{
	int argc = 0;
	wchar_t **argv = CommandLineToArgvW (GetCommandLineW (), &argc);
	struct optparse parser;
	bool ok = true;
	int opt;

	/* No line to read is not a reason to refuse to start.  */
	if (!argv)
		return true;

	optparse_init (&parser, argv);
	while ((opt = optparse (&parser, OPTS, nullptr)) != OPTPARSE_DONE)
	{
		if (opt == OPTPARSE_ERR)
		{
			show_usage (parser.errmsg);
			ok = false;
			goto out;
		}
		switch (opt)
		{
		case OPT_MINIMIZE:
			g_cmdline.minimize = true;
			break;
		case OPT_FILE:
		case OPT_FILE_DEC:
			/* Browsing a file of one's own needs no privileges, so
			   the physical disks (the only thing that does) stay
			   out of this session entirely.  */
			g_cmdline.mounts.push_back ({ full_path (parser.optarg),
				opt == OPT_FILE_DEC });
			g_cmdline.no_windisk = true;
			break;
		case OPT_HELP:
			show_usage (nullptr);
			ok = false;
			goto out;
		}
	}

	/* Options are permuted to the front, so anything left here is a
	   bare argument.  There is no positional syntax to fall back on:
	   say so rather than start with it silently dropped.  */
	if (parser.argv[parser.optind])
	{
		wchar_t text[320];
		// Unexpected argument -- '%s'
		_snwprintf_s (text, ARRAYSIZE (text), _TRUNCATE,
			res_str (IDS_FMT_CMDLINE_ARG).c_str (), parser.argv[parser.optind]);
		show_usage (text);
		ok = false;
	}
out:
	LocalFree (argv);
	return ok;
}
