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

#ifndef GRUB_CAB_HEADER
#define GRUB_CAB_HEADER 1

#include <grub/types.h>
#include <grub/err.h>

typedef grub_err_t (*grub_cab_read_at_t) (void *context,
	grub_uint64_t offset, grub_size_t size, void *buffer);

struct grub_cab_data;
struct grub_cab_file;

struct grub_cab_data *grub_cab_mount_source (grub_cab_read_at_t read_at,
	void *context, grub_uint64_t size);
void grub_cab_free (struct grub_cab_data *data);

unsigned grub_cab_item_count (const struct grub_cab_data *data);
const char *grub_cab_item_name (const struct grub_cab_data *data,
	unsigned index);
grub_uint32_t grub_cab_item_size (const struct grub_cab_data *data,
	unsigned index);
grub_int64_t grub_cab_item_mtime (const struct grub_cab_data *data,
	unsigned index);
int grub_cab_item_is_dir (const struct grub_cab_data *data, unsigned index);
int grub_cab_item_is_unsupported (const struct grub_cab_data *data,
	unsigned index);

/* Takes ownership of DATA, whether opening succeeds or fails. */
struct grub_cab_file *grub_cab_file_open (struct grub_cab_data *data,
	unsigned index);
grub_ssize_t grub_cab_file_read (struct grub_cab_file *file,
	grub_uint64_t offset, char *buffer, grub_size_t size);
void grub_cab_file_close (struct grub_cab_file *file);

#endif
