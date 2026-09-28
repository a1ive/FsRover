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

#ifndef ROVER_LOST_H
#define ROVER_LOST_H	1

#include <grub/disk.h>

struct rover_lost_remap;

/* Probe START/SECTORS (512-byte sectors on PARENT) with the GRUB
   filesystem drivers through a transient, unlisted lostdisk window
   with REMAP_COUNT remaps.  On success *FS_NAME is the driver name and
   *LABEL / *UUID are allocated (or NULL); the caller frees them.  */
grub_err_t grub_lostdisk_probe (grub_disk_t parent, grub_disk_addr_t start,
	grub_uint64_t sectors, const struct rover_lost_remap *remap,
	unsigned int remap_count, const char **fs_name, char **label, char **uuid);

/* First 512-byte sector on its parent of open lostdisk DISK.  */
grub_disk_addr_t grub_lostdisk_start (grub_disk_t disk);

#endif
