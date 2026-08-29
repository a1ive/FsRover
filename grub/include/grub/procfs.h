/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_PROCFS_HEADER
#define GRUB_PROCFS_HEADER	1

#include <grub/err.h>
#include <grub/list.h>
#include <grub/types.h>

struct grub_disk;
struct grub_procfs_writer;

struct grub_procfs_entry
{
  struct grub_procfs_entry *next;
  struct grub_procfs_entry **prev;

  const char *name;
  void *data;
  grub_err_t (*generate) (struct grub_procfs_entry *entry,
			  struct grub_procfs_writer *writer);
};

extern struct grub_procfs_entry *grub_procfs_entries;

/* Rover diagnostic accounting.  These hooks never change grub_errno.  */
void grub_procfs_record_disk_read (struct grub_disk *disk, grub_size_t bytes,
				   grub_err_t error);
void grub_procfs_record_cache (struct grub_disk *disk, int hit);
void grub_procfs_record_error (grub_err_t error, const char *message);

grub_err_t grub_procfs_write (struct grub_procfs_writer *writer,
			      const void *data, grub_size_t size);
grub_err_t grub_procfs_puts (struct grub_procfs_writer *writer,
			     const char *text);
grub_err_t grub_procfs_printf (struct grub_procfs_writer *writer,
			       const char *format, ...)
  __attribute__ ((format (printf, 2, 3)));
grub_err_t grub_procfs_writer_error (const struct grub_procfs_writer *writer);

static inline void
grub_procfs_register (struct grub_procfs_entry *entry)
{
  grub_list_push (GRUB_AS_LIST_P (&grub_procfs_entries),
		  GRUB_AS_LIST (entry));
}

static inline void
grub_procfs_unregister (struct grub_procfs_entry *entry)
{
  grub_list_remove (GRUB_AS_LIST (entry));
}


#endif
