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
#include <climits>
#include <cstring>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include <rover.h>

#include "../common/natural_sort.h"
#include "../FsRover/optparse.h"
#include "extract.h"

namespace
{

struct mount_options
{
	bool loopback;
	std::wstring file;
	bool decompress;
};

struct command_options
{
	std::vector<mount_options> mounts;
	bool list = false;
	std::wstring list_path;
	std::vector<std::wstring> extracts;
	std::wstring output;
};

struct dir_entry
{
	std::string name;
	bool is_dir;
};

enum
{
	OPT_FILE,
	OPT_FILE_DEC,
	OPT_LOOP,
	OPT_LOOP_DEC,
	OPT_EXTRACT,
	OPT_OUTPUT,
	OPT_LIST,
	OPT_HELP,
};

const struct optparse_option OPTIONS[] =
{
	{ L"file", L'f', OPTPARSE_REQUIRED },
	{ L"file-dec", L'd', OPTPARSE_REQUIRED },
	{ L"loop", L'p', OPTPARSE_REQUIRED },
	{ L"loop-dec", 0, OPTPARSE_REQUIRED },
	{ L"extract", L'e', OPTPARSE_REQUIRED },
	{ L"output", L'o', OPTPARSE_REQUIRED },
	{ L"list", L'l', OPTPARSE_OPTIONAL },
	{ L"help", L'h', OPTPARSE_NONE },
	{ nullptr, 0, OPTPARSE_NONE },
};

const char USAGE[] =
	"Usage: CliRover [OPTIONS]\r\n"
	"\r\n"
	"  -f, --file=FILE       Mount a host image as (imgN).\r\n"
	"  -d, --file-dec=FILE   Mount an image after decompression.\r\n"
	"  -p, --loop=PATH       Mount a GRUB file as (loopN).\r\n"
	"      --loop-dec=PATH   Mount a GRUB file after decompression.\r\n"
	"  -l, --list[=PATH]     List devices, a directory, or a file.\r\n"
	"  -e, --extract=PATH    Extract a GRUB file or directory.\r\n"
	"  -o, --output=DIR      Destination directory for --extract.\r\n"
	"  -h, --help            Show this help.\r\n"
	"\r\n"
	"Mount options may be repeated and are processed in command-line order.\r\n";

std::string
narrow (const std::wstring &wide)
{
	if (wide.empty ())
		return {};
	if (wide.size () > INT_MAX)
		return {};
	int len = WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS,
		wide.data (), static_cast<int> (wide.size ()), nullptr, 0, nullptr, nullptr);
	if (!len)
		return {};
	std::string text (static_cast<size_t> (len), '\0');
	WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS,
		wide.data (), static_cast<int> (wide.size ()), text.data (), len, nullptr, nullptr);
	return text;
}

std::wstring
widen (const std::string &text)
{
	if (text.empty ())
		return {};
	if (text.size () > INT_MAX)
		return {};
	int len = MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS,
		text.data (), static_cast<int> (text.size ()), nullptr, 0);
	if (!len)
		return {};
	std::wstring wide (static_cast<size_t> (len), L'\0');
	MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS,
		text.data (), static_cast<int> (text.size ()), wide.data (), len);
	return wide;
}

void
write_stream (DWORD stream, const std::string &text)
{
	HANDLE out = GetStdHandle (stream);
	DWORD mode;

	if (!out || out == INVALID_HANDLE_VALUE || text.empty ())
		return;
	if (GetConsoleMode (out, &mode))
	{
		std::wstring wide = widen (text);
		size_t offset = 0;
		while (offset < wide.size ())
		{
			DWORD chunk = static_cast<DWORD> (std::min<size_t> (wide.size () - offset, 32767));
			DWORD written = 0;
			if (!WriteConsoleW (out, wide.data () + offset, chunk, &written, nullptr)
				|| !written)
				break;
			offset += written;
		}
		return;
	}

	size_t offset = 0;
	while (offset < text.size ())
	{
		DWORD chunk = static_cast<DWORD> (std::min<size_t> (text.size () - offset, MAXDWORD));
		DWORD written = 0;
		if (!WriteFile (out, text.data () + offset, chunk, &written, nullptr) || !written)
			break;
		offset += written;
	}
}

int
report_error (const std::string &error)
{
	write_stream (STD_ERROR_HANDLE, "CliRover: " + error + "\r\n");
	return 1;
}

std::wstring
full_path (const wchar_t *arg)
{
	DWORD len = GetFullPathNameW (arg, 0, nullptr, nullptr);
	std::wstring path;

	if (!len)
		return arg;
	path.resize (len);
	len = GetFullPathNameW (arg, len, path.data (), nullptr);
	if (!len || len >= path.size ())
		return arg;
	path.resize (len);
	return path;
}

bool
parse_options (int argc, wchar_t **argv, command_options *options,
	bool *show_help, std::string *error)
{
	struct optparse parser;
	bool list_seen = false;
	bool output_seen = false;
	int opt;

	*show_help = false;
	optparse_init (&parser, argv);
	while ((opt = optparse (&parser, OPTIONS, nullptr)) != OPTPARSE_DONE)
	{
		if (opt == OPTPARSE_ERR)
		{
			*error = narrow (parser.errmsg);
			return false;
		}
		switch (opt)
		{
		case OPT_FILE:
		case OPT_FILE_DEC:
			options->mounts.push_back ({ false, full_path (parser.optarg),
				opt == OPT_FILE_DEC });
			break;
		case OPT_LOOP:
		case OPT_LOOP_DEC:
			options->mounts.push_back ({ true, parser.optarg, opt == OPT_LOOP_DEC });
			break;
		case OPT_EXTRACT:
			options->extracts.push_back (parser.optarg);
			break;
		case OPT_OUTPUT:
			if (output_seen)
			{
				*error = "--output may only be specified once";
				return false;
			}
			output_seen = true;
			options->output = full_path (parser.optarg);
			break;
		case OPT_LIST:
			if (list_seen)
			{
				*error = "--list may only be specified once";
				return false;
			}
			list_seen = true;
			options->list = true;
			if (parser.optarg)
				options->list_path = parser.optarg;
			break;
		case OPT_HELP:
			*show_help = true;
			return true;
		}
	}

	/* An optional optparse argument is attached with '=' or to its short
	   option.  Accept the familiar separated form, "-l (hd0)/dir", as
	   the one remaining positional argument too.  */
	wchar_t *arg = optparse_arg (&parser);
	if (arg && options->list && options->list_path.empty ())
	{
		options->list_path = arg;
		arg = optparse_arg (&parser);
	}
	if (arg)
	{
		*error = "unexpected argument '" + narrow (arg) + "'";
		return false;
	}
	if (argc == 1)
	{
		*show_help = true;
		return true;
	}
	if (options->list && !options->extracts.empty ())
	{
		*error = "--list and --extract are mutually exclusive";
		return false;
	}
	if (!options->extracts.empty () && options->output.empty ())
	{
		*error = "--output is required with --extract";
		return false;
	}
	if (options->extracts.empty () && !options->output.empty ())
	{
		*error = "--output requires --extract";
		return false;
	}
	if (!options->list && options->extracts.empty ())
	{
		*error = "no operation specified; use --list or --extract";
		return false;
	}
	return true;
}

int
collect_device (const struct rover_disk_info *info, void *data)
{
	auto *devices = static_cast<std::vector<std::string> *> (data);

	devices->push_back ("(" + std::string (info->name) + ")");
	return 0;
}

std::vector<std::string>
enumerate_devices ()
{
	std::vector<std::string> devices;

	rover_enum_disks (collect_device, &devices);
	std::sort (devices.begin (), devices.end (), rover_sort::natural_less);
	return devices;
}

int
collect_dir_entry (const struct rover_dirent *entry, void *data)
{
	auto *entries = static_cast<std::vector<dir_entry> *> (data);

	entries->push_back ({ entry->name, entry->is_dir != 0 });
	return 0;
}

bool
list_directory (const std::string &path, std::vector<dir_entry> *entries,
	std::string *error)
{
	if (rover_dir_list (path.c_str (), collect_dir_entry, entries))
	{
		const char *message = rover_last_error ();
		*error = message ? message : "cannot list directory";
		entries->clear ();
		return false;
	}
	std::sort (entries->begin (), entries->end (),
		[] (const dir_entry &left, const dir_entry &right)
		{
			if (left.is_dir != right.is_dir)
				return left.is_dir;
			return rover_sort::natural_less (left.name, right.name);
		});
	return true;
}

bool
has_wildcard (const std::string &text)
{
	return text.find_first_of ("*?") != std::string::npos;
}

std::regex
wildcard_regex (const std::string &pattern)
{
	std::string expression = "^";

	for (char ch : pattern)
	{
		if (ch == '*')
			expression += ".*";
		else if (ch == '?')
			expression += '.';
		else
		{
			if (std::strchr ("\\.^$|()[]{}+", ch))
				expression += '\\';
			expression += ch;
		}
	}
	expression += '$';
	return std::regex (expression, std::regex::ECMAScript);
}

std::string
join_path (const std::string &directory, const std::string &name)
{
	if (!directory.empty () && directory.back () == '/')
		return directory + name;
	return directory + '/' + name;
}

bool
expand_wildcard (const std::string &pattern, std::vector<std::string> *matches,
	std::string *error)
{
	if (pattern.empty () || pattern.front () != '(')
	{
		*error = "no device in path '" + pattern + "'";
		return false;
	}
	size_t close = pattern.find (')');
	if (close == std::string::npos)
	{
		*error = "missing ')' in '" + pattern + "'";
		return false;
	}
	std::string device_pattern = pattern.substr (0, close + 1);
	std::string tail = pattern.substr (close + 1);
	if (!tail.empty () && tail.front () != '/')
	{
		*error = "invalid path '" + pattern + "'";
		return false;
	}
	bool directory_only = !tail.empty () && tail.back () == '/';

	std::vector<std::string> devices = enumerate_devices ();
	if (has_wildcard (device_pattern))
	{
		std::regex matcher = wildcard_regex (device_pattern);
		for (const std::string &device : devices)
			if (std::regex_match (device, matcher))
				matches->push_back (device);
	}
	else
		/* GRUB accepts partition shorthand such as (img0,3), while
		   enumeration includes the map name, e.g. (img0,gpt3).
		   Leave exact device parsing to rover_dir_list/rover_stat.  */
		matches->push_back (device_pattern);

	size_t start = 0;
	while (start < tail.size ())
	{
		while (start < tail.size () && tail[start] == '/')
			start++;
		if (start == tail.size ())
			break;
		size_t end = tail.find ('/', start);
		if (end == std::string::npos)
			end = tail.size ();
		std::string component = tail.substr (start, end - start);
		std::vector<std::string> next;

		if (!has_wildcard (component))
		{
			for (const std::string &path : *matches)
				next.push_back (join_path (path, component));
		}
		else
		{
			std::regex matcher = wildcard_regex (component);
			for (const std::string &path : *matches)
			{
				std::vector<dir_entry> entries;
				std::string ignored;

				if (!list_directory (path, &entries, &ignored))
					continue;
				for (const dir_entry &entry : entries)
					if (std::regex_match (entry.name, matcher))
						next.push_back (join_path (path, entry.name));
			}
		}
		*matches = std::move (next);
		if (matches->empty ())
			break;
		start = end;
	}

	std::vector<std::string> valid;
	for (std::string &path : *matches)
	{
		/* A wildcard device with no filesystem path names the device
		   itself.  Otherwise stat determines existence and output type.  */
		if (!tail.empty ())
		{
			rover_stat_t status;
			if (rover_stat (path.c_str (), &status))
				continue;
			if (directory_only && !status.is_dir)
				continue;
			if (status.is_dir && (path.empty () || path.back () != '/'))
				path += '/';
		}
		valid.push_back (std::move (path));
	}
	std::sort (valid.begin (), valid.end (), rover_sort::natural_less);
	valid.erase (std::unique (valid.begin (), valid.end ()), valid.end ());
	*matches = std::move (valid);
	if (matches->empty ())
	{
		*error = "no matches for '" + pattern + "'";
		return false;
	}
	return true;
}

bool
run_list (const std::string &path, std::string *error)
{
	if (path.empty ())
	{
		std::vector<std::string> devices = enumerate_devices ();
		std::string output;
		for (size_t i = 0; i < devices.size (); i++)
		{
			if (i)
				output += ' ';
			output += devices[i];
		}
		output += "\r\n";
		write_stream (STD_OUTPUT_HANDLE, output);
		return true;
	}

	if (has_wildcard (path))
	{
		std::vector<std::string> matches;
		if (!expand_wildcard (path, &matches, error))
			return false;
		for (const std::string &match : matches)
			write_stream (STD_OUTPUT_HANDLE, match + "\r\n");
		return true;
	}

	rover_stat_t status;
	if (rover_stat (path.c_str (), &status))
	{
		const char *message = rover_last_error ();
		*error = message ? message : "cannot stat path";
		return false;
	}
	if (!status.is_dir)
	{
		write_stream (STD_OUTPUT_HANDLE, path + "\r\n");
		return true;
	}

	std::vector<dir_entry> entries;
	if (!list_directory (path, &entries, error))
		return false;
	for (const dir_entry &entry : entries)
		write_stream (STD_OUTPUT_HANDLE,
			entry.name + (entry.is_dir ? "/\r\n" : "\r\n"));
	return true;
}

} // namespace

int
wmain (int argc, wchar_t **argv)
{
	command_options options;
	bool show_help;
	std::string error;

	if (!parse_options (argc, argv, &options, &show_help, &error))
	{
		report_error (error);
		write_stream (STD_ERROR_HANDLE, "\r\n" + std::string (USAGE));
		return 2;
	}
	if (show_help)
	{
		write_stream (STD_OUTPUT_HANDLE, USAGE);
		return 0;
	}

	bool has_host_mount = std::any_of (options.mounts.begin (), options.mounts.end (),
		[] (const mount_options &mount) { return !mount.loopback; });
	rover_init (has_host_mount ? ROVER_INIT_NO_WINDISK : 0);
	int result = 0;
	size_t img_seq = 0;
	size_t loop_seq = 0;
	for (size_t i = 0; i < options.mounts.size (); i++)
	{
		const mount_options &mount = options.mounts[i];
		std::string name = mount.loopback
			? "loop" + std::to_string (loop_seq)
			: "img" + std::to_string (img_seq);
		std::string file = narrow (mount.file);
		int error_code = file.empty () ? 1
			: mount.loopback
				? rover_loopback_add (name.c_str (), file.c_str (), mount.decompress ? 1 : 0)
				: rover_winfile_add (name.c_str (), file.c_str (), mount.decompress ? 1 : 0);
		if (error_code)
		{
			const char *message = rover_last_error ();
			error = "cannot mount '" + file + "' as (" + name + "): "
				+ (message ? message : "unknown error");
			result = report_error (error);
			goto out;
		}
		if (mount.loopback)
			loop_seq++;
		else
			img_seq++;
	}

	if (options.list)
	{
		if (!run_list (narrow (options.list_path), &error))
			result = report_error (error);
	}
	else
	{
		std::vector<std::string> sources;
		for (const std::wstring &source : options.extracts)
			sources.push_back (narrow (source));
		extract_result stats;
		bool extracted = extract_paths (sources, options.output, &stats, &error);
		for (const std::string &item_error : stats.errors)
			result = report_error (item_error);
		if (!extracted && !error.empty ())
			result = report_error (error);
		if (extracted || stats.files || stats.links || !stats.errors.empty ())
		{
			std::string summary = "Extracted " + std::to_string (stats.files)
				+ " file(s), " + std::to_string (stats.bytes) + " bytes";
			if (stats.links)
				summary += "; skipped " + std::to_string (stats.links) + " symlink(s)";
			if (!stats.errors.empty ())
				summary += "; failed " + std::to_string (stats.errors.size ()) + " file(s)";
			write_stream (STD_ERROR_HANDLE, summary + ".\r\n");
		}
	}
out:
	rover_fini ();
	return result;
}
