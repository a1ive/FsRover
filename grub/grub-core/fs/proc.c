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

#include <stdarg.h>

#include <grub/procfs.h>
#include <grub/disk.h>
#include <grub/fs.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/archelp.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

struct grub_procfs_entry *grub_procfs_entries;

struct grub_procfs_writer
{
  char *data;
  grub_size_t size;
  grub_size_t capacity;
  grub_err_t error;
};

static grub_err_t
grub_procfs_writer_reserve (struct grub_procfs_writer *writer,
			    grub_size_t size)
{
  grub_size_t needed, capacity;
  char *data;

  if (writer->error != GRUB_ERR_NONE)
    return writer->error;
  if (grub_add (writer->size, size, &needed)
      || grub_add (needed, 1, &needed))
    {
      writer->error = grub_error (GRUB_ERR_OUT_OF_RANGE,
				  "procfs file is too large");
      return writer->error;
    }
  if (needed <= writer->capacity)
    return GRUB_ERR_NONE;

  capacity = writer->capacity ? writer->capacity : 256;
  while (capacity < needed)
    {
      if (capacity > GRUB_SIZE_MAX / 2)
	{
	  capacity = needed;
	  break;
	}
      capacity *= 2;
    }
  data = grub_realloc (writer->data, capacity);
  if (!data)
    {
      writer->error = grub_errno;
      if (writer->error == GRUB_ERR_NONE)
	writer->error = grub_error (GRUB_ERR_OUT_OF_MEMORY,
				    "cannot allocate procfs file");
      return writer->error;
    }
  writer->data = data;
  writer->capacity = capacity;
  return GRUB_ERR_NONE;
}

grub_err_t
grub_procfs_write (struct grub_procfs_writer *writer, const void *data,
		   grub_size_t size)
{
  if (grub_procfs_writer_reserve (writer, size) != GRUB_ERR_NONE)
    return writer->error;
  if (size)
    grub_memcpy (writer->data + writer->size, data, size);
  writer->size += size;
  writer->data[writer->size] = '\0';
  return GRUB_ERR_NONE;
}

grub_err_t
grub_procfs_puts (struct grub_procfs_writer *writer, const char *text)
{
  return grub_procfs_write (writer, text, grub_strlen (text));
}

grub_err_t
grub_procfs_printf (struct grub_procfs_writer *writer, const char *format, ...)
{
  va_list args;
  char *text;

  if (writer->error != GRUB_ERR_NONE)
    return writer->error;
  va_start (args, format);
  text = grub_xvasprintf (format, args);
  va_end (args);
  if (!text)
    {
      writer->error = grub_errno;
      if (writer->error == GRUB_ERR_NONE)
	writer->error = grub_error (GRUB_ERR_OUT_OF_MEMORY,
				    "cannot format procfs file");
      return writer->error;
    }
  grub_procfs_puts (writer, text);
  grub_free (text);
  return writer->error;
}

grub_err_t
grub_procfs_writer_error (const struct grub_procfs_writer *writer)
{
  return writer->error;
}

static int
grub_procdev_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
			 grub_disk_pull_t pull)
{
  if (pull != GRUB_DISK_PULL_NONE)
    return 0;

  return hook ("proc", hook_data);
}

static grub_err_t
grub_procdev_open (const char *name, grub_disk_t disk)
{
  if (grub_strcmp (name, "proc"))
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not a procfs disk");

  disk->total_sectors = 0;
  disk->id = 0;

  disk->data = 0;

  return GRUB_ERR_NONE;
}

static void
grub_procdev_close (grub_disk_t disk __attribute((unused)))
{
}

static grub_err_t
grub_procdev_read (grub_disk_t disk __attribute((unused)),
		grub_disk_addr_t sector __attribute((unused)),
		grub_size_t size __attribute((unused)),
		char *buf __attribute((unused)))
{
  return GRUB_ERR_OUT_OF_RANGE;
}

static grub_err_t
grub_procdev_write (grub_disk_t disk __attribute ((unused)),
		       grub_disk_addr_t sector __attribute ((unused)),
		       grub_size_t size __attribute ((unused)),
		       const char *buf __attribute ((unused)))
{
  return GRUB_ERR_OUT_OF_RANGE;
}

struct grub_archelp_data
{
  struct grub_procfs_entry *entry, *next_entry;
};

static void
grub_procfs_rewind (struct grub_archelp_data *data)
{
  data->entry = NULL;
  data->next_entry = grub_procfs_entries;
}

static grub_err_t
grub_procfs_find_file (struct grub_archelp_data *data, char **name,
		     grub_int32_t *mtime,
		     grub_archelp_mode_t *mode)
{
  data->entry = data->next_entry;
  if (!data->entry)
    {
      *mode = GRUB_ARCHELP_ATTR_END;
      return GRUB_ERR_NONE;
    }
  data->next_entry = data->entry->next;
  *mode = GRUB_ARCHELP_ATTR_FILE | GRUB_ARCHELP_ATTR_NOTIME;
  *name = grub_strdup (data->entry->name);
  *mtime = 0;
  if (!*name)
    return grub_errno;
  return GRUB_ERR_NONE;
}

static struct grub_archelp_ops arcops =
  {
    .find_file = grub_procfs_find_file,
    .rewind = grub_procfs_rewind
  };

static grub_ssize_t
grub_procfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  char *data = file->data;

  grub_memcpy (buf, data + file->offset, len);

  return len;
}

static grub_err_t
grub_procfs_close (grub_file_t file)
{
  char *data;

  data = file->data;
  grub_free (data);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_procfs_dir (grub_device_t device, const char *path,
		 grub_fs_dir_hook_t hook, void *hook_data)
{
  struct grub_archelp_data data;

  /* Check if the disk is our dummy disk.  */
  if (grub_strcmp (device->disk->name, "proc"))
    return grub_error (GRUB_ERR_BAD_FS, "not a procfs");

  grub_procfs_rewind (&data);

  return grub_archelp_dir (&data, &arcops,
			   path, hook, hook_data);
}

static grub_err_t
grub_procfs_open (struct grub_file *file, const char *path)
{
  grub_err_t err;
  struct grub_archelp_data data;
  struct grub_procfs_writer writer = { 0 };

  grub_procfs_rewind (&data);

  err = grub_archelp_open (&data, &arcops, path);
  if (err)
    return err;
  err = data.entry->generate (data.entry, &writer);
  if (err == GRUB_ERR_NONE)
    err = writer.error;
  if (err == GRUB_ERR_NONE)
    err = grub_procfs_write (&writer, "", 0);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (writer.data);
      if (grub_errno == GRUB_ERR_NONE)
	grub_error (err, "cannot generate procfs file `%s'", path);
      return err;
    }
  file->data = writer.data;
  file->size = writer.size;
  return GRUB_ERR_NONE;
}

static struct grub_disk_dev grub_procfs_dev = {
  .name = "proc",
  .id = GRUB_DISK_DEVICE_PROCFS_ID,
  .disk_iterate = grub_procdev_iterate,
  .disk_open = grub_procdev_open,
  .disk_close = grub_procdev_close,
  .disk_read = grub_procdev_read,
  .disk_write = grub_procdev_write,
  .next = 0
};

static struct grub_fs grub_procfs_fs =
  {
    .name = "procfs",
    .fs_dir = grub_procfs_dir,
    .fs_open = grub_procfs_open,
    .fs_read = grub_procfs_read,
    .fs_close = grub_procfs_close,
    .next = 0
  };

GRUB_MOD_INIT (procfs)
{
  grub_procfs_fs.mod = mod;
  grub_disk_dev_register (&grub_procfs_dev);
  grub_fs_register (&grub_procfs_fs);
}

GRUB_MOD_FINI (procfs)
{
  grub_disk_dev_unregister (&grub_procfs_dev);
  grub_fs_unregister (&grub_procfs_fs);
}
