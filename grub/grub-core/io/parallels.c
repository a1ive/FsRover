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
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define PARALLELS_MAGIC		"WithoutFreeSpace"
#define PARALLELS_MAGIC_EXT	"WithouFreSpacExt"
#define PARALLELS_MAGIC_SIZE	16
#define PARALLELS_VERSION	2

#define PARALLELS_SECTOR_SIZE	512
#define PARALLELS_SECTOR_SHIFT	9

/* Sanity caps against corrupt images.  A cluster stays below 2 GiB (the
   cap QEMU uses) and the BAT below 4 GiB; the BAT is also bounded by the
   file having to hold it.  */
#define PARALLELS_CLUSTER_MAX	(0x7fffffffu / 513)
#define PARALLELS_BAT_MAX	(1u << 30)

PRAGMA_BEGIN_PACKED
struct parallels_header
{
	char magic[PARALLELS_MAGIC_SIZE];	/* PARALLELS_MAGIC[_EXT] */
	grub_uint32_t version;			/* PARALLELS_VERSION */
	grub_uint32_t heads;
	grub_uint32_t cylinders;
	grub_uint32_t tracks;			/* cluster size, in sectors */
	grub_uint32_t bat_entries;		/* clusters mapped by the BAT */
	grub_uint64_t nb_sectors;		/* 32 bit without the ext magic */
	grub_uint32_t inuse;			/* left open by a writer */
	grub_uint32_t data_off;			/* first data sector, may be 0 */
	grub_uint32_t flags;
	grub_uint64_t ext_off;			/* format extension, ignored */
};
PRAGMA_END_PACKED

struct parallels_image
{
	grub_file_t file;
	grub_uint64_t total_bytes;	/* size of the guest disk */
	grub_uint64_t cluster_bytes;	/* bytes mapped by one BAT entry */
	grub_uint32_t off_multiplier;	/* BAT entry unit, in sectors */
	grub_uint32_t nentries;
	grub_uint32_t *bat;		/* cluster start, in BAT entry units */
};

static grub_err_t
parallels_pread (grub_file_t file, grub_uint64_t off, void *buf,
		 grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (file) || len > grub_file_size (file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "Parallels image truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "Parallels image truncated");
	return GRUB_ERR_NONE;
}

static void
parallels_free_image (struct parallels_image *image)
{
	grub_free (image->bat);
	image->bat = NULL;
}

static grub_err_t
parallels_open_image (struct parallels_image *image)
{
	struct parallels_header hdr;
	grub_uint64_t file_size = grub_file_size (image->file);
	grub_uint64_t file_sectors, bat_bytes, data_first;
	grub_uint64_t nb_sectors;
	grub_uint32_t cluster, nentries, i;
	int ext;
	grub_err_t err;

	COMPILE_TIME_ASSERT (sizeof (struct parallels_header) == 64);

	err = parallels_pread (image->file, 0, &hdr, sizeof (hdr));
	if (err)
		return err;

	ext = grub_memcmp (hdr.magic, PARALLELS_MAGIC_EXT, PARALLELS_MAGIC_SIZE) == 0;
	if (!ext && grub_memcmp (hdr.magic, PARALLELS_MAGIC, PARALLELS_MAGIC_SIZE) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "not a Parallels disk image");
	if (grub_le_to_cpu32 (hdr.version) != PARALLELS_VERSION)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported image version %u", grub_le_to_cpu32 (hdr.version));

	cluster = grub_le_to_cpu32 (hdr.tracks);
	nentries = grub_le_to_cpu32 (hdr.bat_entries);
	nb_sectors = grub_le_to_cpu64 (hdr.nb_sectors);
	/* Without the extended magic the upper half of the field is part of
	   the padding of older images and carries no size.  */
	if (!ext)
		nb_sectors &= 0xffffffffULL;

	if (cluster == 0 || cluster > PARALLELS_CLUSTER_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad Parallels cluster size");
	if (nentries == 0 || nentries > PARALLELS_BAT_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad Parallels BAT size");
	if (nb_sectors == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "empty Parallels image");

	bat_bytes = (grub_uint64_t) nentries * sizeof (grub_uint32_t);
	if (bat_bytes > file_size - sizeof (hdr))
		return grub_error (GRUB_ERR_BAD_DEVICE, "Parallels BAT out of range");

	image->off_multiplier = ext ? cluster : 1;
	image->cluster_bytes = (grub_uint64_t) cluster << PARALLELS_SECTOR_SHIFT;
	if (grub_mul (nb_sectors, (grub_uint64_t) PARALLELS_SECTOR_SIZE, &image->total_bytes))
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad Parallels image size");
	image->nentries = nentries;

	image->bat = grub_calloc (nentries, sizeof (grub_uint32_t));
	if (!image->bat)
		return grub_errno;
	err = parallels_pread (image->file, sizeof (hdr), image->bat, (grub_size_t) bat_bytes);
	if (err)
		goto fail;

	/* Data can only start past the BAT; the header's data_off says where
	   exactly, but it is optional and only ever larger than this.  */
	data_first = (sizeof (hdr) + bat_bytes + PARALLELS_SECTOR_SIZE - 1) / PARALLELS_SECTOR_SIZE;
	file_sectors = file_size / PARALLELS_SECTOR_SIZE;

	for (i = 0; i < nentries; i++)
	{
		grub_uint64_t start;

		image->bat[i] = grub_le_to_cpu32 (image->bat[i]);
		if (image->bat[i] == 0)
			continue;
		start = (grub_uint64_t) image->bat[i] * image->off_multiplier;
		if (start < data_first || start > file_sectors || cluster > file_sectors - start)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE, "Parallels cluster %u out of range", i);
			goto fail;
		}
	}

	return GRUB_ERR_NONE;

fail:
	parallels_free_image (image);
	return err;
}

static grub_err_t
parallels_read (struct parallels_image *image, grub_uint64_t off, void *buf,
		grub_size_t len, grub_size_t *actually_read)
{
	grub_uint64_t idx, off_in_cluster;

	*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of Parallels image");
	if (len == 0)
		return GRUB_ERR_NONE;

	idx = off / image->cluster_bytes;
	off_in_cluster = off % image->cluster_bytes;

	/* Clip to the cluster; never grow the request.  */
	if (len > image->cluster_bytes - off_in_cluster)
		len = (grub_size_t) (image->cluster_bytes - off_in_cluster);

	/* A disk larger than the BAT maps reads back as zeros, as does any
	   cluster that was never allocated.  */
	if (idx >= image->nentries || image->bat[idx] == 0)
		grub_memset (buf, 0, len);
	else
	{
		grub_uint64_t start;
		grub_err_t err;

		start = (grub_uint64_t) image->bat[idx] * image->off_multiplier;
		err = parallels_pread (image->file, (start << PARALLELS_SECTOR_SHIFT) + off_in_cluster, buf, len);
		if (err)
			return err;
	}

	*actually_read = len;
	return GRUB_ERR_NONE;
}

struct grub_parallels
{
	grub_file_t file;
	struct parallels_image *parallels;
};
typedef struct grub_parallels *grub_parallels_t;

static struct grub_fs grub_parallels_fs;

static grub_err_t
grub_parallels_close (grub_file_t file)
{
	grub_parallels_t pio = file->data;

	parallels_free_image (pio->parallels);
	grub_free (pio->parallels);
	grub_file_close (pio->file);
	grub_free (pio);
	/* The inner close released the shared device;
	   the outer name is freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_parallels_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_parallels_t pio;
	struct parallels_image *image;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < sizeof (struct parallels_header)
	    || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (parallels_open_image (image) != GRUB_ERR_NONE)
	{
		parallels_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	pio = grub_zalloc (sizeof (*pio));
	if (!file || !pio)
	{
		parallels_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (pio);
		return 0;
	}
	pio->file = io;
	pio->parallels = image;

	file->device = io->device;
	file->data = pio;
	file->fs = &grub_parallels_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;

	return file;
}

static grub_ssize_t
grub_parallels_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_parallels_t pio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = parallels_read (pio->parallels, read_offset, buf, len, &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR, "Parallels read made no progress");
			break;
		}
		read_offset += real_size;
		buf += real_size;
		size += real_size;
		if (real_size >= len)
			break;
		len -= real_size;
	}

	if (err != GRUB_ERR_NONE)
	{
		if (!grub_errno)
			grub_error (err, "Parallels image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_parallels_fs =
{
	.name = "parallels",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_parallels_read,
	.fs_close = grub_parallels_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (parallels)
{
	grub_file_filter_register (GRUB_FILE_FILTER_PARALLELS, grub_parallels_open);
}

GRUB_MOD_FINI (parallels)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_PARALLELS);
}
