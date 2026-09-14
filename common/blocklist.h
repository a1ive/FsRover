/* Shared streaming CLI blocklist output. GPL-3.0-or-later. */
#ifndef ROVER_BLOCKLIST_H
#define ROVER_BLOCKLIST_H
#include <algorithm>
#include <functional>
#include <rover.h>
#include "filemap_format.h"

namespace rover_blocklist
{
inline std::string escape (const std::string &s)
{
	std::string out;
	for (char c : s)
		switch (c)
		{
		case '\\': out += "\\\\"; break;
		case '\t': out += "\\t"; break;
		case '\r': out += "\\r"; break;
		case '\n': out += "\\n"; break;
		default: out += c; break;
		}
	return out;
}
struct context
{
	const std::function<bool (const std::string &)> &write;
	std::string device;
	unsigned long long group = 0;
};
inline int emit (const rover_map_extent *extent, void *data)
{
	auto &ctx = *static_cast<context *> (data);
	std::string group = std::to_string (++ctx.group);
	for (unsigned i = 0; i < (std::max) (1U, extent->storage_count); ++i)
	{
		auto columns = file_map_columns (*extent, i, ctx.device, group);
		std::string line;
		for (const auto &column : columns)
		{
			if (!line.empty ()) line += '\t';
			line += escape (column);
		}
		if (!ctx.write (line + "\n")) return 1;
	}
	return 0;
}
inline bool run (const std::string &path,
	const std::function<bool (const std::string &)> &write, std::string *error)
{
	rover_file *file = rover_file_open (path.c_str ());
	if (!file)
	{
		*error = rover_last_error () ? rover_last_error () : "cannot open file";
		return false;
	}
	context ctx { write, path.substr (0, path.find (')') + 1), 0 };
	int stopped = 0;
	bool ok = write ("group\tfile_offset\tfile_length\ttype\tdevice\taddress_space\tstorage_offset\tstorage_length\tencoding\tdecoded_offset\tdecoded_length\n");
	if (ok)
		ok = rover_file_map_range (file, 0, rover_file_size (file), emit, &ctx, &stopped) == 0;
	if (!ok || stopped)
		*error = stopped || !rover_last_error () ? "blocklist output incomplete" : rover_last_error ();
	rover_file_close (file);
	return ok && !stopped;
}
}
#endif
