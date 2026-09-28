/* Shared lost partition search output and window specifications. GPL-3.0-or-later. */
#ifndef ROVER_LOSTPART_H
#define ROVER_LOSTPART_H
#include <algorithm>
#include <climits>
#include <functional>
#include <string>
#include <utility>
#include <vector>
#include <rover.h>
#include "blocklist.h"

namespace rover_lostpart
{
/* A lost partition window, "DEVICE:OFFSET:SIZE" in bytes, optionally
   followed by ":TARGET=SOURCE+LENGTH[,...]" remaps relative to the window,
   as the window column of the scan output prints it.  */
struct window
{
	std::string parent;
	unsigned long long offset = 0;
	unsigned long long size = 0;
	std::vector<rover_lost_remap> remap;
};

inline std::string strip_device (const std::string &device)
{
	if (device.size () >= 2 && device.front () == '(' && device.back () == ')')
		return device.substr (1, device.size () - 2);
	return device;
}

inline bool parse_number (const std::string &text, unsigned long long *value)
{
	unsigned long long result = 0;

	if (text.empty ())
		return false;
	for (char c : text)
	{
		if (c < '0' || c > '9' || result > (ULLONG_MAX - (c - '0')) / 10)
			return false;
		result = result * 10 + (c - '0');
	}
	*value = result;
	return true;
}

/* "TARGET=SOURCE+LENGTH".  */
inline bool parse_remap (const std::string &text, rover_lost_remap *out)
{
	size_t equal = text.find ('=');
	size_t plus = text.find ('+');
	return equal != std::string::npos && plus != std::string::npos && equal < plus
		&& parse_number (text.substr (0, equal), &out->target)
		&& parse_number (text.substr (equal + 1, plus - equal - 1), &out->source)
		&& parse_number (text.substr (plus + 1), &out->length);
}

inline bool parse_window (const std::string &text, window *out)
{
	std::vector<std::string> fields;
	size_t start = 0;

	for (;;)
	{
		size_t colon = text.find (':', start);
		fields.push_back (text.substr (start, colon - start));
		if (colon == std::string::npos)
			break;
		start = colon + 1;
	}
	if (fields.size () != 3 && fields.size () != 4)
		return false;
	out->parent = strip_device (fields[0]);
	out->remap.clear ();
	if (out->parent.empty () || !parse_number (fields[1], &out->offset)
		|| !parse_number (fields[2], &out->size))
		return false;
	if (fields.size () == 3)
		return true;
	start = 0;
	for (;;)
	{
		size_t comma = fields[3].find (',', start);
		rover_lost_remap remap;
		if (!parse_remap (fields[3].substr (start, comma - start), &remap))
			return false;
		out->remap.push_back (remap);
		if (comma == std::string::npos)
			return out->remap.size () <= ROVER_LOST_REMAP_MAX;
		start = comma + 1;
	}
}

inline std::string window_text (const std::string &device, unsigned long long offset,
	unsigned long long size, const rover_lost_remap *remap, unsigned int count)
{
	std::string text = device + ":" + std::to_string (offset) + ":" + std::to_string (size);
	for (unsigned int i = 0; i < count; i++)
		text += (i ? "," : ":") + std::to_string (remap[i].target) + "="
			+ std::to_string (remap[i].source) + "+" + std::to_string (remap[i].length);
	return text;
}

/* Add WINDOW as lost device NAME.  */
inline int add_window (const std::string &name, const window &w)
{
	return rover_lost_add_ex (name.c_str (), w.parent.c_str (), w.offset, w.size,
		w.remap.data (), (unsigned int) w.remap.size ());
}

inline std::string flags_text (unsigned int flags)
{
	const std::pair<unsigned int, const char *> names[] = {
		{ ROVER_LOST_VERIFIED, "VERIFIED" }, { ROVER_LOST_BACKUP, "BACKUP" },
		{ ROVER_LOST_EXISTING, "EXISTING" }, { ROVER_LOST_OVERLAP, "OVERLAP" },
		{ ROVER_LOST_TRUNCATED, "TRUNCATED" }, { ROVER_LOST_TABLE, "TABLE" }
	};
	std::string text;
	for (const auto &item : names)
		if (flags & item.first)
		{
			if (!text.empty ())
				text += " | ";
			text += item.second;
		}
	return text.empty () ? "-" : text;
}

/* A result kept until the search is over (struct rover_lost_part owns
   none of its strings).  */
struct result
{
	unsigned long long offset;
	unsigned long long size;
	std::string type;
	std::string fs;
	std::string label;
	std::string fs_uuid;
	unsigned int flags;
	unsigned long long window;
	std::vector<rover_lost_remap> remap;
};

inline int collect (const rover_lost_part *part, void *data)
{
	static_cast<std::vector<result> *> (data)->push_back ({ part->offset, part->size,
		part->type, part->fs ? part->fs : "", part->label ? part->label : "",
		part->fs_uuid ? part->fs_uuid : "", part->flags, part->window,
		std::vector<rover_lost_remap> (part->remap, part->remap + part->remap_count) });
	return 0;
}

/* The search reports a result as soon as it finds it, so one that a
   later result overlaps only learns about it here; results from ranges
   searched twice also come out of order.  */
inline void finish (std::vector<result> &results)
{
	for (size_t i = 0; i < results.size (); i++)
		for (size_t j = i + 1; j < results.size (); j++)
			if (results[i].offset < results[j].offset + results[j].size
				&& results[j].offset < results[i].offset + results[i].size)
			{
				results[i].flags |= ROVER_LOST_OVERLAP;
				results[j].flags |= ROVER_LOST_OVERLAP;
			}
	std::stable_sort (results.begin (), results.end (),
		[] (const result &a, const result &b) { return a.offset < b.offset; });
}

inline std::string row_text (const std::string &device, const result &r)
{
	const std::string columns[] = {
		std::to_string (r.offset), std::to_string (r.size), r.type, flags_text (r.flags),
		r.fs.empty () ? "-" : r.fs, r.label.empty () ? "-" : r.label,
		r.fs_uuid.empty () ? "-" : r.fs_uuid,
		window_text (device, r.offset, r.window, r.remap.data (), (unsigned int) r.remap.size ())
	};
	std::string line;
	for (const std::string &column : columns)
	{
		if (!line.empty ())
			line += '\t';
		line += rover_blocklist::escape (column);
	}
	return line + "\n";
}

/* Scan DEVICE and write one TSV row per result, by offset, once the
   search is over (or has failed: then the rows found so far).  PROGRESS,
   if set, is called with the bytes covered and the device size between
   slices.  */
inline bool run (const std::string &device, unsigned int flags,
	const std::function<bool (const std::string &)> &write,
	const std::function<void (unsigned long long, unsigned long long)> &progress,
	std::string *error)
{
	std::string name = strip_device (device);
	unsigned long long done = 0, total = 0;
	int more = 1;

	rover_lost_scan *scan = rover_lost_scan_begin (name.c_str (), flags);
	if (!scan)
	{
		*error = rover_last_error () ? rover_last_error () : "cannot scan device";
		return false;
	}
	std::vector<result> results;
	bool ok;

	while (more > 0)
	{
		more = rover_lost_scan_step (scan, 256ULL << 20, collect, &results);
		rover_lost_scan_progress (scan, &done, &total);
		if (progress)
			progress (done, total);
	}
	if (more < 0)
		*error = rover_last_error () ? rover_last_error () : "lost partition search failed";
	rover_lost_scan_end (scan);

	finish (results);
	ok = write ("offset\tsize\ttype\tflags\tfs\tlabel\tuuid\twindow\n");
	for (size_t i = 0; ok && i < results.size (); i++)
		ok = write (row_text (name, results[i]));
	if (!ok && more == 0)
		*error = "lost partition output incomplete";
	return ok && more == 0;
}
}
#endif
