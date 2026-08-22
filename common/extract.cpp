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

#include "extract.h"

#include <windows.h>

#include <algorithm>
#include <climits>
#include <cwchar>
#include <utility>

#include <rover.h>

namespace rover_extract
{
namespace
{

/* Build a flat work list before copying: directory callbacks only collect
   one level, so no filesystem driver is re-entered.  Symlinks are skipped;
   inode ancestry catches cycles, with a 64-level fallback for drivers that
   do not expose inode identity.  Parents precede children in the work list,
   and directory timestamps are restored deepest-first after copying.  */

struct dir_entry
{
	std::string name;
	bool is_dir;
	bool is_symlink;
	long long mtime;
	bool inode_set;
	unsigned long long inode;
};

struct walk_item
{
	std::string src;
	std::wstring rel;
	bool is_dir;
	long long mtime;
};

struct walk_level
{
	bool inode_set;
	unsigned long long inode;
};

using walk_chain = std::vector<walk_level>;

struct extract_context
{
	const options *opts;
	unsigned long long files_total = 0;
	unsigned long long files_done = 0;
	unsigned long long files_processed = 0;
	unsigned long long bytes_done = 0;
	unsigned long long links_skipped = 0;
	std::string current;
};

constexpr size_t WALK_MAX_DEPTH = 64;

bool
cancelled (const options &opts)
{
	return opts.cancelled && opts.cancelled ();
}

void
service (const options &opts)
{
	if (opts.service)
		opts.service ();
}

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

int
collect_dir_entry (const struct rover_dirent *entry, void *data)
{
	auto *entries = static_cast<std::vector<dir_entry> *> (data);
	entries->push_back ({ entry->name, entry->is_dir != 0,
		entry->is_symlink != 0, entry->mtime_set ? entry->mtime : 0,
		entry->inode_set != 0, entry->inode });
	return 0;
}

std::string
join_path (const std::string &parent, const std::string &name)
{
	if (!parent.empty () && parent.back () == '/')
		return parent + name;
	return parent + '/' + name;
}

std::wstring
sanitize_component (const std::string &name)
{
	std::wstring out = widen (name);

	for (wchar_t &c : out)
		if (c < 32 || wcschr (L"<>:\"/\\|?*", c))
			c = L'_';
	return out;
}

std::wstring
top_rel_name (const std::string &src)
{
	std::string path = src;

	while (!path.empty () && path.back () == '/')
		path.pop_back ();
	size_t close = path.find (')');
	std::string base;
	if (close == std::string::npos)
		base = path;
	else if (close + 1 >= path.size ())
		base = path.substr (1, close - 1);
	else
		base = path.substr (path.find_last_of ('/') + 1);
	return sanitize_component (base);
}

bool
chain_has (const walk_chain &chain, unsigned long long inode)
{
	return std::find_if (chain.begin (), chain.end (),
		[inode] (const walk_level &level)
		{
			return level.inode_set && level.inode == inode;
		}) != chain.end ();
}

bool
walk_dir (const std::string &src, const std::wstring &rel,
	walk_chain &chain, std::vector<walk_item> &out,
	unsigned long long &links, const options &opts, std::string &error)
{
	std::vector<dir_entry> children;

	if (chain.size () >= WALK_MAX_DEPTH)
	{
		error = src + ": directory nesting too deep";
		return false;
	}
	if (rover_dir_list (src.c_str (), collect_dir_entry, &children))
	{
		const char *message = rover_last_error ();
		error = src + ": " + (message ? message : "cannot list directory");
		return false;
	}
	for (const dir_entry &entry : children)
	{
		if (cancelled (opts))
			return false;
		if (entry.is_symlink)
		{
			links++;
			continue;
		}
		walk_item item;
		item.src = join_path (src, entry.name);
		item.rel = rel + L'\\' + sanitize_component (entry.name);
		item.is_dir = entry.is_dir;
		item.mtime = entry.mtime;
		if (entry.is_dir && entry.inode_set && chain_has (chain, entry.inode))
		{
			error = item.src + ": directory loops back on itself";
			return false;
		}
		out.push_back (item);
		if (!entry.is_dir)
			continue;
		chain.push_back ({ entry.inode_set, entry.inode });
		bool ok = walk_dir (item.src, item.rel, chain, out, links, opts, error);
		chain.pop_back ();
		if (!ok)
			return false;
	}
	return true;
}

bool
unix_to_filetime (long long seconds, FILETIME *filetime)
{
	if (seconds < -11644473600LL || seconds > 1833029933770LL)
		return false;
	unsigned long long ticks = static_cast<unsigned long long> (
		(seconds + 11644473600LL) * 10000000LL);
	filetime->dwLowDateTime = static_cast<DWORD> (ticks);
	filetime->dwHighDateTime = static_cast<DWORD> (ticks >> 32);
	return true;
}

void
set_mtime (HANDLE handle, long long mtime)
{
	FILETIME filetime;

	if (mtime && unix_to_filetime (mtime, &filetime))
		SetFileTime (handle, nullptr, nullptr, &filetime);
}

std::wstring
long_path (std::wstring path)
{
	while (path.size () > 3 && (path.back () == L'\\' || path.back () == L'/'))
		path.pop_back ();
	if (path.rfind (L"\\\\?\\", 0) == 0)
		return path;
	if (path.rfind (L"\\\\", 0) == 0)
		return L"\\\\?\\UNC\\" + path.substr (2);
	return L"\\\\?\\" + path;
}

bool
create_one_directory (const std::wstring &path)
{
	if (CreateDirectoryW (path.c_str (), nullptr))
		return true;
	if (GetLastError () != ERROR_ALREADY_EXISTS)
		return false;
	DWORD attributes = GetFileAttributesW (path.c_str ());
	return attributes != INVALID_FILE_ATTRIBUTES
		&& (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool
create_directory_tree (const std::wstring &path)
{
	size_t start;

	if (path.rfind (L"\\\\?\\UNC\\", 0) == 0)
	{
		size_t server = path.find (L'\\', 8);
		if (server == std::wstring::npos)
			return false;
		size_t share = path.find (L'\\', server + 1);
		if (share == std::wstring::npos)
			return true;
		start = share + 1;
	}
	else if (path.rfind (L"\\\\?\\", 0) == 0)
		start = 7;
	else
		start = 3;

	for (size_t slash = path.find (L'\\', start);
		slash != std::wstring::npos; slash = path.find (L'\\', slash + 1))
		if (!create_one_directory (path.substr (0, slash)))
			return false;
	return create_one_directory (path);
}

void
report_progress (extract_context &context, progress_kind kind, int percent)
{
	if (!context.opts->report_progress)
		return;
	context.opts->report_progress ({ kind, context.files_processed,
		context.files_total, percent, context.current });
}

void
progress_hook (unsigned long long done, unsigned long long total, void *data)
{
	auto *context = static_cast<extract_context *> (data);
	int percent = total ? static_cast<int> (done * 100 / total) : 0;
	report_progress (*context, progress_kind::advanced, percent);
}

bool
extract_file (const walk_item &item, const std::wstring &destination,
	extract_context &context, std::vector<char> &buffer, std::string &error)
{
	unsigned long long bytes_before = context.bytes_done;
	rover_file *source = rover_file_open (item.src.c_str ());
	if (!source)
	{
		const char *message = rover_last_error ();
		error = item.src + ": " + (message ? message : "cannot open");
		return false;
	}
	HANDLE output = CreateFileW (destination.c_str (), GENERIC_WRITE, 0,
		nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (output == INVALID_HANDLE_VALUE)
	{
		rover_file_close (source);
		error = item.src + ": cannot create destination file";
		return false;
	}

	bool ok = false;
	for (;;)
	{
		if (cancelled (*context.opts))
			break;
		service (*context.opts);
		long long size = rover_file_read (source, buffer.data (), buffer.size ());
		if (size < 0)
		{
			const char *message = rover_last_error ();
			error = item.src + ": " + (message ? message : "read error");
			break;
		}
		if (!size)
		{
			ok = true;
			break;
		}
		DWORD written = 0;
		DWORD chunk = static_cast<DWORD> (size);
		if (!WriteFile (output, buffer.data (), chunk, &written, nullptr)
			|| written != chunk)
		{
			error = item.src + ": write failed";
			break;
		}
		context.bytes_done += static_cast<unsigned long long> (size);
	}

	if (ok && context.opts->preserve_times)
		set_mtime (output, item.mtime);
	CloseHandle (output);
	rover_file_close (source);
	if (!ok)
	{
		context.bytes_done = bytes_before;
		DeleteFileW (destination.c_str ());
	}
	return ok;
}

void
stamp_directories (const std::vector<walk_item> &work,
	const std::wstring &root)
{
	for (size_t index = work.size (); index-- > 0;)
	{
		const walk_item &item = work[index];
		if (!item.is_dir || !item.mtime)
			continue;
		std::wstring destination = root + L'\\' + item.rel;
		HANDLE handle = CreateFileW (destination.c_str (), FILE_WRITE_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
		if (handle == INVALID_HANDLE_VALUE)
			continue;
		set_mtime (handle, item.mtime);
		CloseHandle (handle);
	}
}

} /* namespace */

bool
extract (const std::vector<std::string> &sources,
	const std::wstring &destination, const options &opts,
	result *stats, std::string *error)
{
	extract_context context = { &opts };
	std::vector<walk_item> work;
	std::vector<char> buffer ((size_t) 1 << 20);
	std::wstring root = long_path (destination);
	bool progress_set = false;
	bool ok = false;

	*stats = {};
	error->clear ();
	if (sources.empty () || destination.empty ())
	{
		*error = "nothing to extract";
		return false;
	}
	if (!create_directory_tree (root))
	{
		*error = "cannot create output directory";
		goto out;
	}

	for (const std::string &source : sources)
	{
		if (cancelled (opts))
			goto out;
		rover_stat_t stat;
		if (rover_stat (source.c_str (), &stat))
		{
			const char *message = rover_last_error ();
			*error = source + ": " + (message ? message : "cannot stat source");
			goto out;
		}
		if (stat.is_symlink)
		{
			context.links_skipped++;
			continue;
		}
		walk_item item = { source, top_rel_name (source), stat.is_dir != 0,
			stat.mtime_set ? stat.mtime : 0 };
		work.push_back (item);
		walk_chain chain = { { stat.inode_set != 0, stat.inode } };
		if (item.is_dir && !walk_dir (item.src, item.rel, chain, work,
			context.links_skipped, opts, *error))
			goto out;
	}
	for (const walk_item &item : work)
		if (!item.is_dir)
			context.files_total++;

	rover_set_progress (progress_hook, &context);
	progress_set = true;
	for (const walk_item &item : work)
	{
		if (cancelled (opts))
			goto out;
		std::wstring target = root + L'\\' + item.rel;
		if (item.is_dir)
		{
			if (!create_one_directory (target))
			{
				*error = item.src + ": cannot create destination directory";
				goto out;
			}
			continue;
		}
		context.files_processed++;
		context.current = item.src;
		report_progress (context, progress_kind::started, 0);
		std::string item_error;
		if (!extract_file (item, target, context, buffer, item_error))
		{
			report_progress (context, progress_kind::failed, 0);
			if (cancelled (opts))
				goto out;
			stats->errors.push_back (std::move (item_error));
			continue;
		}
		context.files_done++;
		report_progress (context, progress_kind::completed, 100);
	}
	ok = true;

out:
	if (progress_set)
		rover_set_progress (nullptr, nullptr);
	if (opts.preserve_times)
		stamp_directories (work, root);
	stats->files = context.files_done;
	stats->bytes = context.bytes_done;
	stats->links = context.links_skipped;
	if (!ok && error->empty ())
		*error = cancelled (opts) ? "extraction cancelled" : "extraction failed";
	return ok && stats->errors.empty ();
}

} /* namespace rover_extract */
