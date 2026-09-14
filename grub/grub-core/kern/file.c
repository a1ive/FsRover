/* file.c - file I/O functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2006,2007,2009  Free Software Foundation, Inc.
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

#include <grub/misc.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/filemap.h>
#include <grub/net.h>
#include <grub/mm.h>
#include <grub/fs.h>
#include <grub/device.h>
#include <grub/partition.h>
#include <grub/i18n.h>
#include <grub/dl.h>

void (*EXPORT_VAR (grub_grubnet_fini)) (void);

grub_file_filter_t grub_file_filters[GRUB_FILE_FILTER_MAX];

/* Get the device part of the filename NAME. It is enclosed by parentheses.  */
char *
grub_file_get_device_name (const char *name)
{
  if (name[0] == '(')
    {
      char *p = grub_strchr (name, ')');
      char *ret;

      if (! p)
	{
	  grub_error (GRUB_ERR_BAD_FILENAME, N_("missing `%c' symbol"), ')');
	  return 0;
	}

      ret = (char *) grub_malloc (p - name);
      if (! ret)
	return 0;

      grub_memcpy (ret, name + 1, p - name - 1);
      ret[p - name - 1] = '\0';
      return ret;
    }

  return 0;
}

grub_file_t
grub_file_open (const char *name, enum grub_file_type type)
{
  grub_device_t device = 0;
  grub_file_t file = 0, last_file = 0;
  char *device_name;
  const char *file_name;
  grub_file_filter_id_t filter;

  /* Reset grub_errno before we start. */
  grub_errno = GRUB_ERR_NONE;

  device_name = grub_file_get_device_name (name);
  if (grub_errno)
    goto fail;

  /* Get the file part of NAME.  */
  file_name = (name[0] == '(') ? grub_strchr (name, ')') : NULL;
  if (file_name)
    file_name++;
  else
    file_name = name;

  device = grub_device_open (device_name);
  grub_free (device_name);
  device_name = NULL;
  if (! device)
    goto fail;

  file = (grub_file_t) grub_zalloc (sizeof (*file));
  if (! file)
    goto fail;

  file->device = device;

  /* In case of relative pathnames and non-Unix systems (like Windows)
   * name of host files may not start with `/'. Blocklists for host files
   * are meaningless as well (for a start, host disk does not allow any direct
   * access - it is just a marker). So skip host disk in this case.
   */
  if (device->disk && file_name[0] != '/'
#if defined(GRUB_UTIL) || defined(GRUB_MACHINE_EMU)
      && grub_strcmp (device->disk->name, "host")
#endif
     )
    /* This is a block list.  */
    file->fs = &grub_fs_blocklist;
  else
    {
      file->fs = grub_fs_probe (device);
      if (! file->fs)
	goto fail;
    }

  if ((file->fs->fs_open) (file, file_name) != GRUB_ERR_NONE)
    goto fail;

  if (file->data == NULL)
    goto fail;

  if (file->fs->mod)
    grub_dl_ref (file->fs->mod);

  file->name = grub_strdup (name);
  grub_errno = GRUB_ERR_NONE;

  for (filter = 0; file && filter < ARRAY_SIZE (grub_file_filters);
       filter++)
    if (grub_file_filters[filter])
      {
	last_file = file;
	file = grub_file_filters[filter] (file, type);
	if (file && file != last_file)
	  {
	    file->name = grub_strdup (name);
	    grub_errno = GRUB_ERR_NONE;
	  }
      }
  if (!file)
    grub_file_close (last_file);

  return file;

 fail:
  grub_free (device_name);
  if (device)
    grub_device_close (device);

  /* if (net) grub_net_close (net);  */

  grub_free (file);

  return 0;
}

grub_disk_read_hook_t grub_file_progress_hook;

grub_ssize_t
grub_file_read (grub_file_t file, void *buf, grub_size_t len)
{
  grub_ssize_t res;
  grub_disk_read_hook_t read_hook;
  void *read_hook_data;

  if (file->offset > file->size)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE,
		  N_("attempt to read past the end of file"));
      return -1;
    }

  if (len == 0)
    return 0;

  if (len > file->size - file->offset)
    len = file->size - file->offset;

  /* Prevent an overflow.  */
  if ((grub_ssize_t) len < 0)
    len >>= 1;

  if (len == 0)
    return 0;
  read_hook = file->read_hook;
  read_hook_data = file->read_hook_data;
  if (!file->read_hook)
    {
      file->read_hook = grub_file_progress_hook;
      file->read_hook_data = file;
      file->progress_offset = file->offset;
    }
  res = (file->fs->fs_read) (file, buf, len);
  file->read_hook = read_hook;
  file->read_hook_data = read_hook_data;
  if (res > 0)
    file->offset += res;

  return res;
}

grub_err_t
grub_file_close (grub_file_t file)
{
  if (file->fs->fs_close)
    (file->fs->fs_close) (file);

  if (file->fs->mod)
    grub_dl_unref (file->fs->mod);

  if (file->device)
    grub_device_close (file->device);
  grub_free (file->name);
  grub_free (file);
  return grub_errno;
}

grub_off_t
grub_file_seek (grub_file_t file, grub_off_t offset)
{
  grub_off_t old;

  if (offset > file->size)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE,
		  N_("attempt to seek outside of the file"));
      return -1;
    }

  old = file->offset;
  file->offset = offset;

  return old;
}

int
grub_file_map_cancelled (struct grub_file_map_context *ctx)
{
	if (!ctx->stopped && ctx->cancelled)
		ctx->stopped = ctx->cancelled (ctx->cancel_data) != 0;
	return ctx->stopped;
}

/* Compare inclusive 512-byte sector endpoints to avoid capacity byte overflow.
 * Partition starts and lengths are always in 512-byte sectors. */
static grub_err_t
grub_file_map_check_storage (grub_disk_t disk,
	const struct grub_file_map_storage *storage, grub_uint64_t end)
{
	grub_partition_t part;
	grub_uint64_t first = storage->offset >> GRUB_DISK_SECTOR_BITS;
	grub_uint64_t last = (end - 1) >> GRUB_DISK_SECTOR_BITS;
	grub_uint64_t limit = GRUB_DISK_MAX_SECTORS;
	unsigned shift;

	if (storage->address_space == GRUB_FILE_MAP_FS_LOGICAL)
		return GRUB_ERR_NONE;
	if (storage->address_space != GRUB_FILE_MAP_VOLUME || !disk)
		return grub_error (GRUB_ERR_BAD_FS, "invalid mapping address space");
	for (part = disk->partition; part; part = part->parent)
	{
		if (last >= part->len || grub_add (first, part->start, &first) ||
			grub_add (last, part->start, &last))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "storage mapping outside partition");
	}
	if (disk->log_sector_size < GRUB_DISK_SECTOR_BITS || disk->log_sector_size > 12)
		return grub_error (GRUB_ERR_BAD_FS, "invalid mapping sector size");
	shift = disk->log_sector_size - GRUB_DISK_SECTOR_BITS;
	if (disk->total_sectors != GRUB_DISK_SIZE_UNKNOWN &&
		disk->total_sectors < (limit >> shift))
		limit = disk->total_sectors << shift;
	if (last >= limit)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "storage mapping outside disk");
	return GRUB_ERR_NONE;
}

/* Metadata mapping: clip/validate driver records and coalesce plain runs. */
static void
grub_file_map_flush (struct grub_file_map_context *ctx)
{
	if (ctx->pending.logical_length && !grub_file_map_cancelled (ctx))
		ctx->stopped = ctx->hook (&ctx->pending, ctx->data) != 0;
	ctx->pending.logical_length = 0;
}

grub_err_t
grub_file_map_emit (struct grub_file_map_context *ctx,
	const struct grub_file_map_extent *input)
{
	struct grub_file_map_extent e = *input;
	struct grub_file_map_storage storage;
	grub_uint64_t end, left, delta;
	unsigned i;
	if (grub_file_map_cancelled (ctx))
		return GRUB_ERR_NONE;
	if (!e.logical_length || grub_add (e.logical_offset, e.logical_length, &end))
		return grub_error (GRUB_ERR_BAD_FS, "invalid mapping range");
	if (end <= ctx->start || e.logical_offset >= ctx->end)
		return GRUB_ERR_NONE;
	if (e.storage_count && !e.storage)
		return grub_error (GRUB_ERR_BAD_FS, "missing mapping storage");
	for (i = 0; i < e.storage_count; i++)
	{
		grub_uint64_t storage_end;
		if (grub_file_map_cancelled (ctx))
			return GRUB_ERR_NONE;
		if (!e.storage[i].length || grub_add (e.storage[i].offset, e.storage[i].length, &storage_end))
			return grub_error (GRUB_ERR_BAD_FS, "invalid storage mapping range");
		if (grub_file_map_check_storage (ctx->disk, &e.storage[i], storage_end))
			return grub_errno;
	}
	if ((e.flags & GRUB_FILE_MAP_TRANSFORMED) && e.storage_count && e.decoded_length &&
		(e.decoded_offset > e.decoded_length || e.logical_length > e.decoded_length - e.decoded_offset))
		return grub_error (GRUB_ERR_BAD_FS, "invalid decoded mapping range");
	left = grub_max (e.logical_offset, ctx->start);
	if (left != ctx->next)
		return grub_error (GRUB_ERR_BAD_FS, "incomplete or overlapping mapping");
	delta = left - e.logical_offset;
	e.logical_offset = left;
	e.logical_length = grub_min (end, ctx->end) - left;
	if ((e.flags & GRUB_FILE_MAP_DIRECT) || ((e.flags & GRUB_FILE_MAP_UNWRITTEN) && !(e.flags & GRUB_FILE_MAP_TRANSFORMED)))
	{
		if (e.storage_count != 1 || !e.storage ||
			e.storage[0].length < input->logical_length)
			return grub_error (GRUB_ERR_BAD_FS, "invalid direct mapping");
		storage = e.storage[0];
		if (grub_add (storage.offset, delta, &storage.offset) ||
			grub_add (storage.offset, e.logical_length, &end))
			return grub_error (GRUB_ERR_BAD_FS, "mapping address overflow");
		storage.length = e.logical_length;
		e.storage = &storage;
	}
	else if (e.flags & GRUB_FILE_MAP_TRANSFORMED)
	{
		if (grub_add (e.decoded_offset, delta, &e.decoded_offset))
			return grub_error (GRUB_ERR_BAD_FS, "decoded offset overflow");
	}
	ctx->next = left + e.logical_length;
	/* Only simple direct and unallocated zero runs can be coalesced. */
	if (e.flags == GRUB_FILE_MAP_DIRECT || e.flags == (GRUB_FILE_MAP_ZERO | GRUB_FILE_MAP_HOLE))
	{
		if (ctx->pending.logical_length && ctx->pending.flags == e.flags &&
			ctx->pending.logical_offset + ctx->pending.logical_length == left &&
			(!e.storage_count || (ctx->pending_storage.address_space == storage.address_space &&
			ctx->pending_storage.offset + ctx->pending_storage.length == storage.offset)))
		{
			ctx->pending.logical_length += e.logical_length;
			ctx->pending_storage.length += e.logical_length;
			return GRUB_ERR_NONE;
		}
		grub_file_map_flush (ctx);
		ctx->pending = e;
		if (e.storage_count)
		{
			ctx->pending_storage = storage;
			ctx->pending.storage = &ctx->pending_storage;
		}
	}
	else
	{
		grub_file_map_flush (ctx);
		if (!grub_file_map_cancelled (ctx))
			ctx->stopped = ctx->hook (&e, ctx->data) != 0;
	}
	return GRUB_ERR_NONE;
}

grub_err_t
grub_file_map_simple (struct grub_file_map_context *ctx,
	grub_uint64_t offset, grub_uint64_t length, unsigned flags,
	grub_uint64_t physical)
{
	struct grub_file_map_storage storage = { physical, length, GRUB_FILE_MAP_VOLUME };
	struct grub_file_map_extent e = { 0 };
	e.logical_offset = offset;
	e.logical_length = length;
	e.flags = flags;
	if (flags & (GRUB_FILE_MAP_DIRECT | GRUB_FILE_MAP_UNWRITTEN))
	{
		e.storage = &storage;
		e.storage_count = 1;
	}
	return grub_file_map_emit (ctx, &e);
}

grub_err_t
grub_file_map_range_ex (grub_file_t file, grub_uint64_t offset,
	grub_uint64_t length, grub_file_map_hook hook, void *data,
	grub_file_map_cancel_hook cancelled, void *cancel_data, int *stopped)
{
	struct grub_file_map_context ctx = { 0 };
	grub_err_t err;
	*stopped = 0;
	if (!hook || grub_add (offset, length, &ctx.end))
		return grub_error (GRUB_ERR_BAD_ARGUMENT, "invalid mapping query");
	if (file->size == GRUB_FILE_SIZE_UNKNOWN)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "mapping requires known file size");
	ctx.start = ctx.next = offset;
	ctx.end = grub_min (ctx.end, file->size);
	ctx.hook = hook;
	ctx.data = data;
	ctx.disk = file->device ? file->device->disk : NULL;
	ctx.cancelled = cancelled;
	ctx.cancel_data = cancel_data;
	if (grub_file_map_cancelled (&ctx))
	{
		*stopped = 1;
		return GRUB_ERR_NONE;
	}
	if (offset >= ctx.end)
		return GRUB_ERR_NONE;
	if (!file->fs->fs_map_range)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "filesystem has no metadata mapping");
	err = file->fs->fs_map_range (file, &ctx);
	if (!err && !grub_file_map_cancelled (&ctx) && ctx.next != ctx.end)
		err = grub_error (GRUB_ERR_BAD_FS, "incomplete file mapping");
	if (!err)
		grub_file_map_flush (&ctx);
	*stopped = ctx.stopped;
	return err;
}

grub_err_t
grub_file_map_range (grub_file_t file, grub_uint64_t offset,
	grub_uint64_t length, grub_file_map_hook hook, void *data, int *stopped)
{
	return grub_file_map_range_ex (file, offset, length, hook, data, NULL, NULL, stopped);
}
