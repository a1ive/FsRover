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

#include <algorithm>
#include <atomic>
#include <climits>
#include <string>
#include <utility>

#include "../common/extract.h"
#include "extract.h"

namespace
{

struct console_context
{
	ULONGLONG last_tick = 0;
	bool console_progress = false;
};

std::atomic<bool> g_cancel = false;

std::wstring
widen (const std::string &text)
{
	if (text.empty () || text.size () > INT_MAX)
		return {};
	int len = MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS,
		text.data (), static_cast<int> (text.size ()), nullptr, 0);
	if (!len)
		return {};
	std::wstring wide (static_cast<size_t> (len), L'\0');
	MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS, text.data (),
		static_cast<int> (text.size ()), wide.data (), len);
	return wide;
}

void
write_stderr (const std::string &text)
{
	HANDLE out = GetStdHandle (STD_ERROR_HANDLE);
	DWORD mode;

	if (!out || out == INVALID_HANDLE_VALUE || text.empty ())
		return;
	if (GetConsoleMode (out, &mode))
	{
		std::wstring wide = widen (text);
		size_t offset = 0;
		while (offset < wide.size ())
		{
			DWORD chunk = static_cast<DWORD> (
				std::min<size_t> (wide.size () - offset, 32767));
			DWORD written = 0;
			if (!WriteConsoleW (out, wide.data () + offset, chunk,
				&written, nullptr) || !written)
				break;
			offset += written;
		}
		return;
	}

	size_t offset = 0;
	while (offset < text.size ())
	{
		DWORD chunk = static_cast<DWORD> (
			std::min<size_t> (text.size () - offset, MAXDWORD));
		DWORD written = 0;
		if (!WriteFile (out, text.data () + offset, chunk, &written, nullptr)
			|| !written)
			break;
		offset += written;
	}
}

bool
stderr_is_console ()
{
	HANDLE out = GetStdHandle (STD_ERROR_HANDLE);
	DWORD mode;

	return out && out != INVALID_HANDLE_VALUE && GetConsoleMode (out, &mode);
}

BOOL WINAPI
ctrl_handler (DWORD type)
{
	if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT)
		return FALSE;
	g_cancel.store (true, std::memory_order_relaxed);
	return TRUE;
}

std::string
display_path (const std::string &path)
{
	std::string clean = path;
	for (char &c : clean)
		if (static_cast<unsigned char> (c) < 32)
			c = '?';
	return clean;
}

void
show_progress (console_context &context,
	const rover_extract::progress &progress)
{
	if (progress.kind == rover_extract::progress_kind::failed)
	{
		if (context.console_progress)
			write_stderr ("\r\n");
		return;
	}
	if (progress.kind == rover_extract::progress_kind::completed)
	{
		if (context.console_progress)
		{
			write_stderr ("\rExtracting [" + std::to_string (progress.file_index)
				+ '/' + std::to_string (progress.file_total) + "] 100% "
				+ display_path (progress.source) + "\r\n");
		}
		else
			write_stderr ("Extracted [" + std::to_string (progress.file_index)
				+ '/' + std::to_string (progress.file_total) + "] "
				+ display_path (progress.source) + "\r\n");
		return;
	}
	if (!context.console_progress)
		return;

	ULONGLONG now = GetTickCount64 ();
	if (progress.kind == rover_extract::progress_kind::advanced
		&& now - context.last_tick < 100)
		return;
	context.last_tick = now;
	write_stderr ("\rExtracting [" + std::to_string (progress.file_index)
		+ '/' + std::to_string (progress.file_total) + "] "
		+ std::to_string (progress.percent) + "% "
		+ display_path (progress.source));
}

} /* namespace */

bool
extract_paths (const std::vector<std::string> &sources,
	const std::wstring &destination, extract_result *result, std::string *error)
{
	console_context context;
	rover_extract::options options;
	rover_extract::result stats;
	bool handler_set;

	*result = {};
	g_cancel.store (false, std::memory_order_relaxed);
	handler_set = SetConsoleCtrlHandler (ctrl_handler, TRUE) != FALSE;
	context.console_progress = stderr_is_console ();
	options.cancelled = [] ()
	{
		return g_cancel.load (std::memory_order_relaxed);
	};
	options.report_progress = [&context] (const rover_extract::progress &progress)
	{
		show_progress (context, progress);
	};
	bool ok = rover_extract::extract (sources, destination, options, &stats, error);
	if (handler_set)
		SetConsoleCtrlHandler (ctrl_handler, FALSE);
	result->files = stats.files;
	result->bytes = stats.bytes;
	result->links = stats.links;
	result->errors = std::move (stats.errors);
	return ok;
}
