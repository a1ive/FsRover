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

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>

#include <miniz.h>

GRUB_MOD_LICENSE("GPLv3+");

PRAGMA_BEGIN_PACKED
struct grub_zip_header
{
	char magic[4];
	grub_uint16_t version;
	grub_uint16_t flag;
	grub_uint16_t compression_method;
	grub_uint32_t mtime;
	grub_uint32_t crc32;
	grub_uint32_t csize;
	grub_uint32_t usize;
	grub_uint16_t name_len;
	grub_uint16_t field_len;
};
PRAGMA_END_PACKED

struct grub_zip_data
{
	grub_disk_t disk;
	grub_off_t size;
	grub_off_t saved_offset;
	mz_zip_reader_extract_iter_state* iter;
	mz_zip_archive zip;
	mz_uint index;
	mz_zip_archive_file_stat stat;
	struct grub_zip_header header;
};

static size_t
mz_grub_file_read(void* pOpaque, mz_uint64 file_ofs, void* pBuf, size_t n)
{
	grub_disk_t disk = pOpaque;
	if (grub_disk_read(disk, 0, file_ofs, n, pBuf))
		return 0;
	return n;
}

static char* path_convert(const char* path)
{
	grub_size_t i;
	char* path_copy = grub_zalloc(MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE);
	if (!path_copy)
		return NULL;
	while (*path == '/')
		path++;
	for (i = 0; i < MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE - 2; path++)
	{
		if (path[0] == '/' && path[1] == '/')
			continue;
		path_copy[i] = *path;
		i++;
		if (*path == '\0')
			break;
	}
	return path_copy;
}

static struct grub_zip_data*
grub_zip_mount(grub_disk_t disk)
{
	struct grub_zip_data* data = NULL;
	struct grub_zip_header header;
	mz_bool bret;

	if (grub_disk_read(disk, 0, 0, sizeof(header), &header))
		goto fail;

	if (grub_memcmp(header.magic, "PK\3\4", 4) != 0)
		goto fail;

	data = grub_zalloc(sizeof(struct grub_zip_data));
	if (!data)
		goto fail;

	grub_memcpy(&data->header, &header, sizeof(header));
	data->disk = disk;
	data->size = grub_disk_native_sectors(disk) << GRUB_DISK_SECTOR_BITS;
	data->zip.m_pRead = mz_grub_file_read;
	data->zip.m_pIO_opaque = disk;

	bret = mz_zip_reader_init(&data->zip, data->size, MZ_ZIP_FLAG_COMPRESSED_DATA);
	if (bret == MZ_FALSE)
		goto fail;

	return data;
fail:
	if (data)
		grub_free(data);
	grub_error(GRUB_ERR_BAD_FS, "not a zip filesystem");
	return 0;
}

static grub_err_t
grub_zip_open(struct grub_file* file, const char* name)
{
	struct grub_zip_data* data;
	mz_bool bret;
	char* new_path;

	data = grub_zip_mount(file->device->disk);
	if (!data)
		return grub_errno;

	new_path = path_convert(name);
	if (!new_path)
	{
		grub_error(GRUB_ERR_OUT_OF_MEMORY, "out of memory");
		goto fail;
	}

	bret = mz_zip_reader_locate_file_v2(&data->zip, new_path, NULL, 0, &data->index);
	if (bret == MZ_FALSE)
	{
		grub_error(GRUB_ERR_FILE_NOT_FOUND, "file not found");
		goto fail;
	}
	bret = mz_zip_reader_file_stat(&data->zip, data->index, &data->stat);
	if (bret == MZ_FALSE)
	{
		grub_error(GRUB_ERR_FILE_NOT_FOUND, "file not found");
		goto fail;
	}
	if (data->stat.m_is_directory == MZ_TRUE)
	{
		grub_error(GRUB_ERR_FILE_NOT_FOUND, "is a directory");
		goto fail;
	}
	data->iter = mz_zip_reader_extract_iter_new(&data->zip, data->index, 0);
	if (!data->iter)
	{
		grub_error(GRUB_ERR_OUT_OF_MEMORY, "out of memory");
		goto fail;
	}

	grub_errno = GRUB_ERR_NONE;
	file->data = data;
	file->size = data->stat.m_uncomp_size;
	file->not_easily_seekable = 1;

fail:
	if (new_path)
		grub_free(new_path);
	if (grub_errno)
	{
		if (data->iter)
			mz_zip_reader_extract_iter_free(data->iter);
		mz_zip_reader_end(&data->zip);
		grub_free(data);
	}
	return grub_errno;
}

static grub_err_t
grub_zip_close(grub_file_t file)
{
	struct grub_zip_data* data = file->data;
	if (data->iter)
		mz_zip_reader_extract_iter_free(data->iter);
	mz_zip_reader_end(&data->zip);
	grub_free(data);
	return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_zip_read(grub_file_t file, char* buf, grub_size_t len)
{
	struct grub_zip_data* data = file->data;
	grub_disk_t disk = data->disk;
	grub_ssize_t ret = -1;
	char* tmp = NULL;
	grub_size_t tmp_size = 1024 * 1024; // 1MB
	grub_off_t tmp_offset = 0;

	if (data->iter && data->saved_offset > file->offset)
	{
		mz_zip_reader_extract_iter_free(data->iter);
		data->iter = mz_zip_reader_extract_iter_new(&data->zip, data->index, 0);
		data->saved_offset = 0;
	}
	else
		tmp_offset = data->saved_offset;
	if (!data->iter)
	{
		grub_error(GRUB_ERR_OUT_OF_MEMORY, "out of memory");
		goto fail;
	}

	disk->read_hook = 0;
	tmp = grub_malloc(tmp_size);
	if (!tmp)
		goto fail;
	while (tmp_offset < file->offset)
	{
		grub_size_t s;
		if (file->offset - tmp_offset < tmp_size)
			tmp_size = file->offset - tmp_offset;
		s = mz_zip_reader_extract_iter_read(data->iter, tmp, tmp_size);
		if (s != tmp_size)
			goto fail;
		tmp_offset += s;
	}

	ret = mz_zip_reader_extract_iter_read(data->iter, buf, len);
	data->saved_offset = file->offset + ret;

fail:
	if (tmp)
		grub_free(tmp);
	return ret;
}

static grub_err_t
grub_zip_dir(grub_device_t device, const char* path,
	grub_fs_dir_hook_t hook, void* hook_data)
{
	char* new_path;
	grub_size_t new_path_len;
	struct grub_zip_data* data;
	mz_uint max_file;
	struct grub_dirhook_info info;
	mz_bool bret;

	data = grub_zip_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_memset(&info, 0, sizeof(info));
	info.inodeset = 1;
	info.inode = (mz_uint)-1;

	new_path = path_convert(path);
	if (!new_path)
		goto fail;
	new_path_len = grub_strlen(new_path);

	grub_errno = GRUB_ERR_NONE;
	if (new_path_len > 0 && new_path[new_path_len - 1] != '/')
	{
		int id = mz_zip_reader_locate_file(&data->zip, new_path, NULL, 0);
		if (id < 0)
		{
			new_path[new_path_len] = '/';
			new_path_len++;
			new_path[new_path_len] = '\0';
		}
		else
		{
			char* p = grub_strrchr(new_path, '/');
			if (p)
				p++;
			else
				p = new_path;
			info.dir = 0;
			info.inode = id;
			hook(p, &info, hook_data);
			goto fail;
		}
	}

	max_file = mz_zip_reader_get_num_files(&data->zip);
	for (data->index = 0; data->index < max_file; data->index++)
	{
		bret = mz_zip_reader_file_stat(&data->zip, data->index, &data->stat);
		if (bret == MZ_FALSE)
			continue;
		if (grub_strncasecmp(new_path, data->stat.m_filename, new_path_len) == 0)
		{
			grub_size_t p_len;
			char* p = &data->stat.m_filename[new_path_len];
			char* q;
			info.dir = data->stat.m_is_directory ? 1 : 0;
			info.mtimeset = 1;
			info.mtime = data->stat.m_time;
			info.inode = data->index;
			if (*p == '/')
				p++;
			if (*p == '\0')
				continue;
			q = grub_strchr(p, '/');
			if (q && q[1] != '\0')
				continue;
			p_len = grub_strlen(p);
			if (p_len == 0)
				continue;
			if (p[p_len - 1] == '/')
				p[p_len - 1] = '\0';
			if (hook(p, &info, hook_data) == 1)
				goto fail;
		}
	}

fail:
	if (info.inode == (mz_uint)-1)
		grub_error(GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);
	if (new_path)
		grub_free(new_path);
	mz_zip_reader_end(&data->zip);
	grub_free(data);
	return grub_errno;
}

static grub_err_t grub_zip_label(grub_device_t device, char** label)
{
	struct grub_zip_header header;

	*label = 0;
	if (grub_disk_read(device->disk, 0, 0, sizeof(header), &header))
		return grub_errno;
	*label = grub_zalloc(header.name_len + 1);
	if (!*label)
		return grub_errno;
	grub_disk_read(device->disk, 0, sizeof(header), header.name_len, *label);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_zip_mtime(grub_device_t device, grub_int64_t* tm)
{
	struct grub_zip_header header;

	*tm = 0;
	if (grub_disk_read(device->disk, 0, 0, sizeof(header), &header))
		return grub_errno;
	*tm = grub_le_to_cpu32(header.mtime);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_zip_fs =
{
	.name = "zip",
	.fs_dir = grub_zip_dir,
	.fs_open = grub_zip_open,
	.fs_read = grub_zip_read,
	.fs_close = grub_zip_close,
	.fs_label = grub_zip_label,
	.fs_mtime = grub_zip_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT(zip)
{
	grub_zip_fs.mod = mod;
	grub_fs_register(&grub_zip_fs);
}

GRUB_MOD_FINI(zip)
{
	grub_fs_unregister(&grub_zip_fs);
}
