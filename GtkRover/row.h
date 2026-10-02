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
 * List item for both the device sidebar and the directory view.  The
 * widgets bind to its read-only string/icon properties through
 * GtkExpressions, so rover_row_set_size() repaints a row in place.
 */

#ifndef GTKROVER_ROW_H
#define GTKROVER_ROW_H	1

#include <gio/gio.h>

#include <string>

G_BEGIN_DECLS

#define ROVER_TYPE_ROW (rover_row_get_type ())
G_DECLARE_FINAL_TYPE (RoverRow, rover_row, ROVER, ROW, GObject)

G_END_DECLS

enum class row_kind
{
	disk,
	entry
};

struct row_data
{
	row_kind kind = row_kind::entry;
	std::string name;	/* entry name, or device name without parens */

	/* row_kind::entry */
	bool is_dir = false;
	bool is_symlink = false;
	bool size_set = false;
	unsigned long long size = 0;
	bool mtime_set = false;
	long long mtime = 0;

	/* row_kind::disk; size is shared with entries */
	bool is_partition = false;
	int dev_id = 0;
	std::string fs;
	std::string label;
	bool encrypted = false;
	std::string crypto_type;
	std::string crypto_uuid;
	std::string fs_uuid;
	unsigned long long start_lba = 0;
	unsigned int sector_size = 0;
	std::string parent_file;	/* loopback backing file (rover path) */
	std::string parents;	/* diskfilter members, '\n'-separated */
	std::string parent;	/* device a crypto/lost/loop volume is read from */
	std::string mountpoint;	/* FUSE mount, empty if none */
	int depth = 0;	/* sidebar nesting level */
};

RoverRow *rover_row_new (row_data data);
const row_data &rover_row_get (RoverRow *row);
void rover_row_set_size (RoverRow *row, unsigned long long size);

#endif /* ! GTKROVER_ROW_H */
