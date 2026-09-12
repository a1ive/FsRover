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

#include "extract_core.h"

#include "extract_host.h"

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
	host_path component;
	size_t parent;
	host_path target;
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
constexpr size_t NO_PARENT = static_cast<size_t> (-1);

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

struct collect_context
{
	std::vector<dir_entry> *entries;
	const options *opts;
};

int
collect_dir_entry (const struct rover_dirent *entry, void *data)
{
	auto *context = static_cast<collect_context *> (data);
	if (cancelled (*context->opts))
		return 1;
	context->entries->push_back ({ entry->name, entry->is_dir != 0,
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

host_path
top_component (const std::string &src)
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
walk_dir (const std::string &src, size_t parent,
	walk_chain &chain, std::vector<walk_item> &out,
	unsigned long long &links, const options &opts, std::string &error)
{
	std::vector<dir_entry> children;
	collect_context collect = { &children, &opts };

	if (cancelled (opts))
		return false;
	if (chain.size () >= WALK_MAX_DEPTH)
	{
		error = src + ": directory nesting too deep";
		return false;
	}
	if (rover_dir_list (src.c_str (), collect_dir_entry, &collect))
	{
		const char *message = rover_last_error ();
		error = src + ": " + (message ? message : "cannot list directory");
		return false;
	}
	/* The driver has returned: synchronous mount requests are now safe. */
	service (opts);
	if (cancelled (opts))
		return false;
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
		item.component = sanitize_component (entry.name);
		item.parent = parent;
		item.is_dir = entry.is_dir;
		item.mtime = entry.mtime;
		if (entry.is_dir && entry.inode_set && chain_has (chain, entry.inode))
		{
			error = item.src + ": directory loops back on itself";
			return false;
		}
		std::string child_src = item.src;
		size_t index = out.size ();
		out.push_back (std::move (item));
		if (!entry.is_dir)
			continue;
		chain.push_back ({ entry.inode_set, entry.inode });
		bool ok = walk_dir (child_src, index, chain, out, links, opts, error);
		chain.pop_back ();
		if (!ok)
			return false;
	}
	return true;
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
extract_file (const walk_item &item, const host_path &parent,
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
	host_path destination;
	host_handle output = create_unique_file (parent, item.component, destination);
	if (output == invalid_host_handle)
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
		if (!write_output (output, buffer.data (), static_cast<size_t> (size)))
		{
			error = item.src + ": write failed";
			break;
		}
		context.bytes_done += static_cast<unsigned long long> (size);
	}

	if (ok && context.opts->preserve_times)
		set_mtime (output, item.mtime);
	if (!close_output (output) && ok)
	{
		ok = false;
		error = item.src + ": close failed";
	}
	rover_file_close (source);
	if (!ok)
	{
		context.bytes_done = bytes_before;
		remove_output (destination);
	}
	return ok;
}

void
stamp_directories (const std::vector<walk_item> &work)
{
	for (size_t index = work.size (); index-- > 0;)
	{
		const walk_item &item = work[index];
		if (!item.is_dir || !item.mtime)
			continue;
		stamp_directory (item.target, item.mtime);
	}
}

} /* namespace */

bool
extract (const std::vector<std::string> &sources,
	const host_path &destination, const options &opts,
	result *stats, std::string *error)
{
	extract_context context = {};
	context.opts = &opts;
	std::vector<walk_item> work;
	std::vector<char> buffer ((size_t) 1 << 20);
	host_path root = long_path (destination);
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
		service (opts);
		if (cancelled (opts))
			goto out;
		if (stat.is_symlink)
		{
			context.links_skipped++;
			continue;
		}
		walk_item item = { source, top_component (source), NO_PARENT, {},
			stat.is_dir != 0, stat.mtime_set ? stat.mtime : 0 };
		work.push_back (item);
		walk_chain chain = { { stat.inode_set != 0, stat.inode } };
		if (item.is_dir && !walk_dir (item.src, work.size () - 1, chain, work,
			context.links_skipped, opts, *error))
			goto out;
	}
	for (const walk_item &item : work)
		if (!item.is_dir)
			context.files_total++;

	rover_set_progress (progress_hook, &context);
	progress_set = true;
	for (walk_item &item : work)
	{
		if (cancelled (opts))
			goto out;
		const host_path &parent = item.parent == NO_PARENT ? root
			: work[item.parent].target;
		if (item.is_dir)
		{
			if (!create_unique_directory (parent, item.component, item.target))
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
		if (!extract_file (item, parent, context, buffer, item_error))
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
		stamp_directories (work);
	stats->files = context.files_done;
	stats->bytes = context.bytes_done;
	stats->links = context.links_skipped;
	if (!ok && error->empty ())
		*error = cancelled (opts) ? "extraction cancelled" : "extraction failed";
	return ok && stats->errors.empty ();
}

} /* namespace rover_extract */
