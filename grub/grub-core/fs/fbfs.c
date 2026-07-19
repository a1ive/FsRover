/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2023,2026 A1ive
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

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/fbfs.h>
#include <grub/archelp.h>

GRUB_MOD_LICENSE("GPLv3+");

struct grub_archelp_data
{
	grub_disk_t disk;
	grub_size_t name_offset;
	grub_uint32_t ofs;
	grub_uint32_t pri_size;
	struct fbm_file* p;
	char fb_list[0];
};

static grub_err_t
grub_fbfs_find_file(struct grub_archelp_data* data, char** name,
	grub_int32_t* mtime, grub_archelp_mode_t* mode)
{
	if (!data->p)
		data->p = (struct fbm_file*)data->fb_list;
	else
		data->p = (struct fbm_file*)((char*)data->p + data->p->size + 2);

	if (!data->p->size)
	{
		*mode = GRUB_ARCHELP_ATTR_END;
		return GRUB_ERR_NONE;
	}

	*mtime = grub_le_to_cpu32(data->p->data_time);

	*name = grub_strdup(data->p->name + data->name_offset);
	if (*name == NULL)
		return grub_errno;
	return GRUB_ERR_NONE;
}

static char*
grub_fbfs_get_link_target(struct grub_archelp_data* data __attribute__((unused)))
{
	return NULL;
}

static void
grub_fbfs_rewind(struct grub_archelp_data* data)
{
	data->p = NULL;
}

static struct grub_archelp_ops arcops =
{
	.find_file = grub_fbfs_find_file,
	.get_link_target = grub_fbfs_get_link_target,
	.rewind = grub_fbfs_rewind
};

static struct grub_archelp_data*
grub_fbfs_mount(grub_disk_t disk)
{
	struct fb_mbr* m;
	struct fb_data* d;
	char buf[GRUB_DISK_SECTOR_SIZE];
	struct grub_archelp_data* data;
	unsigned boot_base, boot_size, list_used, pri_size, ofs, i;
	char* fb_list, * p1, * p2;

	if (grub_disk_read(disk, 0, 0, sizeof(buf), buf))
		goto fail;

	m = (struct fb_mbr*)buf;
	d = (struct fb_data*)buf;
	grub_uint32_t* fb_pt = (grub_uint32_t*)&buf[0];
	if (*fb_pt == FB_AR_MAGIC_LONG)
	{
		ofs = 0;
		boot_base = 0;
		boot_size = 0;
		pri_size = 0;
	}
	else
	{
		if ((m->fb_magic != FB_MAGIC_LONG) || (m->end_magic != 0xaa55))
			goto fail;

		ofs = m->lba;
		boot_base = m->boot_base;

		if (grub_disk_read(disk, boot_base + 1 - ofs, 0, sizeof(buf), buf))
			goto fail;

		boot_size = d->boot_size;
		pri_size = d->pri_size;
	}

	if ((d->ver_major != 1) || (d->ver_minor != 6 && d->ver_minor != 7))
		goto fail;

	list_used = d->list_used;
	data = grub_zalloc(sizeof(*data) + (list_used << 9));
	if (!data)
		goto fail;

	data->disk = disk;
	if (d->ver_minor == 6)
		data->name_offset = 0;
	else
		data->name_offset = 4;

	fb_list = data->fb_list;
	if (grub_disk_read(disk, boot_base + 1 + boot_size - ofs, 0,
		(list_used << 9), fb_list))
	{
		grub_free(data);
		goto fail;
	}

	p1 = p2 = fb_list;
	for (i = 0; i < list_used - 1; i++)
	{
		p1 += 510;
		p2 += 512;
		grub_memcpy(p1, p2, 510);
	}
	data->p = NULL;
	data->ofs = ofs;
	data->pri_size = pri_size;

	return data;

fail:
	grub_error(GRUB_ERR_BAD_FS, "not a fb filesystem");
	return 0;
}

static grub_err_t
grub_fbfs_dir(grub_device_t device, const char* path_in,
	grub_fs_dir_hook_t hook, void* hook_data)
{
	struct grub_archelp_data* data;
	grub_err_t err;

	data = grub_fbfs_mount(device->disk);
	if (!data)
		return grub_errno;

	err = grub_archelp_dir(data, &arcops,
		path_in, hook, hook_data);

	grub_free(data);

	return err;
}

static grub_err_t
grub_fbfs_open(struct grub_file* file, const char* name_in)
{
	struct grub_archelp_data* data;
	grub_err_t err;

	data = grub_fbfs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	err = grub_archelp_open(data, &arcops, name_in);
	if (err)
	{
		grub_free(data);
	}
	else
	{
		file->data = data;
		file->size = data->p->data_size;
	}
	return err;
}

static grub_ssize_t
grub_fbfs_read(grub_file_t file, char* buf, grub_size_t len)
{
	struct fbm_file* p;
	grub_uint32_t sector;
	grub_size_t saved_len, ofs;
	struct grub_archelp_data* data;

	data = file->data;
	data->disk->read_hook = file->read_hook;
	data->disk->read_hook_data = file->read_hook_data;

	p = data->p;
	if (p->data_start >= data->pri_size)
	{
		grub_err_t err;
		err = grub_disk_read(data->disk, p->data_start - data->ofs, file->offset, len, buf);
		data->disk->read_hook = 0;
		return (err) ? -1 : (grub_ssize_t)len;
	}

	sector = p->data_start + ((grub_uint32_t)file->offset / 510) - data->ofs;
	ofs = ((grub_uint32_t)file->offset % 510);
	saved_len = len;
	while (len)
	{
		int n;

		n = len;
		if (ofs + n > 510)
			n = 510 - ofs;
		if (grub_disk_read(data->disk, sector, ofs, n, buf))
		{
			saved_len = -1;
			break;
		}
		sector++;
		if (buf)
			buf += n;
		len -= n;
		ofs = 0;
	}

	data->disk->read_hook = 0;
	return saved_len;
}

static grub_err_t
grub_fbfs_close(grub_file_t file)
{
	grub_free(file->data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_fb_fs =
{
	.name = "ud",
	.fs_dir = grub_fbfs_dir,
	.fs_open = grub_fbfs_open,
	.fs_read = grub_fbfs_read,
	.fs_close = grub_fbfs_close,
	.next = 0
};

GRUB_MOD_INIT(fbfs)
{
	grub_fb_fs.mod = mod;
	grub_fs_register(&grub_fb_fs);
}

GRUB_MOD_FINI(fbfs)
{
	grub_fs_unregister(&grub_fb_fs);
}
