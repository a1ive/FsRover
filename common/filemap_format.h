/* Shared metadata mapping text columns. GPL-3.0-or-later. */
#ifndef ROVER_FILEMAP_FORMAT_H
#define ROVER_FILEMAP_FORMAT_H
#include <array>
#include <string>
#include <utility>
#include "../grub/rover/rover.h"

inline std::array<std::string, 11>
file_map_columns (const rover_map_extent &extent, unsigned i,
	const std::string &device, const std::string &group)
{
	const auto *e = &extent;
	std::string type;
	const std::pair<unsigned, const char *> names[] = {
		{ ROVER_MAP_DIRECT, "DIRECT" }, { ROVER_MAP_ZERO, "ZERO" },
		{ ROVER_MAP_HOLE, "HOLE" }, { ROVER_MAP_INLINE, "INLINE" },
		{ ROVER_MAP_COMPRESSED, "COMPRESSED" }, { ROVER_MAP_UNWRITTEN, "UNWRITTEN" },
		{ ROVER_MAP_UNKNOWN, "UNMAPPABLE" }, { ROVER_MAP_TRANSFORMED, "TRANSFORMED" },
		{ ROVER_MAP_SHARED, "SHARED" }
	};
	for (const auto &item : names)
		if (e->flags & item.first) { if (!type.empty ()) type += " | "; type += item.second; }
	std::array<std::string, 11> row;
	row[0] = group; row[1] = std::to_string (e->logical_offset);
	row[2] = std::to_string (e->logical_length); row[3] = type;
	row[4] = device;
	row[5] = e->storage_count ? (e->storage[i].address_space == ROVER_MAP_FS_LOGICAL ? "FS logical" : "Volume") : "-";
	row[6] = e->storage_count ? std::to_string (e->storage[i].offset) : "-";
	row[7] = e->storage_count ? std::to_string (e->storage[i].length) : "-";
	row[8] = e->encoding ? e->encoding : "-";
	row[9] = std::to_string (e->decoded_offset); row[10] = std::to_string (e->decoded_length);
	return row;
}
#endif
