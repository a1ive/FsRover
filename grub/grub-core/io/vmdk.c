/* vmdk.c - VMware VMDK disk image io filter */
/*
 *  Rover -- GRUB 2 filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  Read logic modeled on qemu block/vmdk.c
 *  (Copyright (c) 2004 Fabrice Bellard, 2005 Filip Navara, MIT license)
 *  and the VMware Virtual Disk Format 5.0 specification.
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
 * Supported: monolithicSparse (VMDK4 "KDMV" hosted sparse),
 * streamOptimized (footer, zlib compressed grains with markers), text
 * descriptor files with FLAT / VMFS / SPARSE / ZERO extents, and
 * differencing images via parentFileNameHint.  Not supported: VMDK3
 * ("COWD" / vmfsSparse), seSparse, encrypted images.  parentCID
 * validation is skipped (the parent is only visible here as a decoded
 * disk, its descriptor text is out of reach).
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/deflate.h>
#include <grub/safemath.h>

#include <vbox.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define VMDK_SECTOR_SIZE	512

#define VMDK4_FLAG_RGD		(1u << 1)
#define VMDK4_FLAG_ZERO_GRAIN	(1u << 2)
#define VMDK4_FLAG_COMPRESS	(1u << 16)
#define VMDK4_FLAG_MARKER	(1u << 17)
#define VMDK4_GD_AT_END		0xffffffffffffffffULL
#define VMDK4_COMPRESSION_DEFLATE 1

#define VMDK_MARKER_FOOTER	3

/* Sanity caps against corrupt images.  */
#define VMDK_GTES_PER_GT_MAX	512	/* same limit as qemu */
#define VMDK_GRAIN_BYTES_MAX	(32u * _1M)
#define VMDK_GD_ENTRIES_MAX	(_4K * _1K)	/* 16 MiB table */
#define VMDK_DESC_SIZE_MAX	_1M
#define VMDK_EXTENTS_MAX	1024

PRAGMA_BEGIN_PACKED
struct vmdk4_header
{
	grub_uint32_t version;
	grub_uint32_t flags;
	grub_uint64_t capacity;		/* sectors */
	grub_uint64_t granularity;	/* sectors per grain */
	grub_uint64_t desc_offset;	/* sectors */
	grub_uint64_t desc_size;	/* sectors */
	grub_uint32_t num_gtes_per_gt;
	grub_uint64_t rgd_offset;	/* sectors */
	grub_uint64_t gd_offset;	/* sectors */
	grub_uint64_t grain_offset;	/* sectors */
	grub_uint8_t filler[1];
	grub_uint8_t check_bytes[4];
	grub_uint16_t compress_algorithm;
};

struct vmdk_grain_marker
{
	grub_uint64_t lba;
	grub_uint32_t size;
};

struct vmdk_footer
{
	/* footer marker sector */
	grub_uint64_t marker_val;
	grub_uint32_t marker_size;
	grub_uint32_t marker_type;
	grub_uint8_t marker_pad[VMDK_SECTOR_SIZE - 16];
	/* footer sector: header copy with the real gd_offset */
	grub_uint8_t magic[4];
	struct vmdk4_header header;
};
PRAGMA_END_PACKED

enum vmdk_extent_type
{
	VMDK_EXTENT_SPARSE,
	VMDK_EXTENT_FLAT,
	VMDK_EXTENT_ZERO
};

struct vmdk_extent
{
	grub_file_t file;	/* NULL for ZERO extents */
	int own_file;		/* close file when freeing */
	int type;
	int compressed;
	int has_marker;
	int has_zero_grain;

	grub_uint64_t sector_first;	/* first virtual sector */
	grub_uint64_t sectors;		/* virtual sectors covered */

	grub_uint64_t flat_start;	/* FLAT: byte offset in file */

	/* SPARSE only.  */
	grub_uint64_t grain_bytes;
	grub_uint32_t gtes_per_gt;
	grub_uint32_t gd_entries;
	grub_uint32_t *gd;
	grub_uint32_t *gt_cache;	/* one grain table */
	grub_uint32_t gt_cached;	/* GD entry cached, 0 = none */
};

struct vmdk_image
{
	grub_file_t file;	/* the file the filter was opened on */
	grub_uint64_t total_bytes;

	struct vmdk_extent *extents;
	unsigned n_extents;
	unsigned last_extent;	/* search hint */

	char *parent_hint;
	grub_file_t parent;

	/* last decompressed grain (streamOptimized reads repeat grains) */
	struct vmdk_extent *grain_extent;
	grub_uint64_t grain_nr;
	grub_uint8_t *grain_buf;
	grub_size_t grain_buf_size;
	grub_uint8_t *comp_buf;
	grub_size_t comp_buf_size;
};

static grub_err_t
vmdk_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (file)
	    || len > grub_file_size (file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "vmdk file truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "vmdk file truncated");
	return GRUB_ERR_NONE;
}

/* ------------------------------------------------------------------ */
/* image assembly                                                      */

static struct vmdk_extent *
vmdk_add_extent (struct vmdk_image *image)
{
	struct vmdk_extent *ext;
	grub_uint64_t sector_first = 0;

	if (image->n_extents >= VMDK_EXTENTS_MAX)
	{
		grub_error (GRUB_ERR_BAD_DEVICE, "too many vmdk extents");
		return NULL;
	}
	if (image->n_extents
	    && grub_add (image->extents[image->n_extents - 1].sector_first,
			 image->extents[image->n_extents - 1].sectors,
			 &sector_first))
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "vmdk extent layout overflow");
		return NULL;
	}
	ext = grub_realloc (image->extents,
			    (image->n_extents + 1) * sizeof (*ext));
	if (!ext)
		return NULL;
	image->extents = ext;
	ext = &image->extents[image->n_extents++];
	grub_memset (ext, 0, sizeof (*ext));
	ext->sector_first = sector_first;
	return ext;
}

static void
vmdk_free_image (struct vmdk_image *image)
{
	unsigned i;

	for (i = 0; i < image->n_extents; i++)
	{
		struct vmdk_extent *ext = &image->extents[i];

		if (ext->file && ext->own_file)
			grub_file_close (ext->file);
		grub_free (ext->gd);
		grub_free (ext->gt_cache);
	}
	grub_free (image->extents);
	image->extents = NULL;
	image->n_extents = 0;
	if (image->parent)
	{
		grub_file_close (image->parent);
		image->parent = NULL;
	}
	grub_free (image->parent_hint);
	image->parent_hint = NULL;
	grub_free (image->grain_buf);
	image->grain_buf = NULL;
	grub_free (image->comp_buf);
	image->comp_buf = NULL;
}

/*
 * Open one VMDK4 hosted sparse extent from FILE and append it.
 * SECTORS_OVERRIDE (from a descriptor extent line) limits the virtual
 * size; pass 0 to use the header capacity.
 */
static grub_err_t
vmdk_open_sparse_extent (struct vmdk_image *image, grub_file_t file,
			 int own_file, grub_uint64_t sectors_override)
{
	struct vmdk4_header header;
	struct vmdk_extent *ext;
	grub_uint8_t magic[4];
	grub_uint64_t gd_offset;
	grub_uint64_t gd_byte_offset;
	grub_uint64_t l1_entry_sectors;
	grub_uint64_t gd_entries;
	grub_uint64_t rounded_capacity;
	grub_uint64_t granularity;
	grub_uint32_t gtes_per_gt;
	grub_uint64_t sectors;
	grub_err_t err;

	err = vmdk_pread (file, 0, magic, sizeof (magic));
	if (err)
		return err;
	if (grub_memcmp (magic, "COWD", 4) == 0)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "VMDK3/vmfsSparse extents are not supported");
	if (grub_memcmp (magic, "KDMV", 4) != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "not a VMDK sparse extent");

	err = vmdk_pread (file, sizeof (magic), &header, sizeof (header));
	if (err)
		return err;

	/*
	 * streamOptimized: the header is a placeholder, the real one
	 * lives in the footer, two sectors before the end of the file.
	 */
	if (grub_le_to_cpu64 (header.gd_offset) == VMDK4_GD_AT_END)
	{
		struct vmdk_footer footer;

		if (grub_file_size (file) < 3 * VMDK_SECTOR_SIZE)
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "vmdk file too short for a footer");
		err = vmdk_pread (file,
				  grub_file_size (file) - 3 * VMDK_SECTOR_SIZE,
				  &footer, sizeof (footer));
		if (err)
			return err;
		if (grub_memcmp (footer.magic, "KDMV", 4) != 0
		    || footer.marker_size != 0
		    || grub_le_to_cpu32 (footer.marker_type) != VMDK_MARKER_FOOTER
		    || grub_le_to_cpu64 (footer.header.gd_offset) == VMDK4_GD_AT_END)
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "invalid vmdk footer");
		header = footer.header;
	}

	if (grub_le_to_cpu32 (header.version) > 3)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "unsupported VMDK version");
	if (grub_le_to_cpu16 (header.compress_algorithm) != 0
	    && grub_le_to_cpu16 (header.compress_algorithm) != VMDK4_COMPRESSION_DEFLATE)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "unsupported VMDK compression algorithm");

	granularity = grub_le_to_cpu64 (header.granularity);
	gtes_per_gt = grub_le_to_cpu32 (header.num_gtes_per_gt);
	if (gtes_per_gt == 0 || gtes_per_gt > VMDK_GTES_PER_GT_MAX
	    || granularity == 0
	    || granularity > VMDK_GRAIN_BYTES_MAX / VMDK_SECTOR_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "invalid vmdk grain geometry");

	sectors = grub_le_to_cpu64 (header.capacity);
	if (sectors_override && sectors_override < sectors)
		sectors = sectors_override;
	if (sectors == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "empty vmdk extent");
	if (sectors > ~0ULL / VMDK_SECTOR_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "vmdk extent size overflow");

	if (grub_mul ((grub_uint64_t) gtes_per_gt, granularity,
		      &l1_entry_sectors)
	    || grub_add (grub_le_to_cpu64 (header.capacity),
			 l1_entry_sectors - 1, &rounded_capacity))
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "invalid vmdk grain directory size");
	gd_entries = grub_divmod64 (rounded_capacity,
				    l1_entry_sectors, NULL);
	if (gd_entries == 0 || gd_entries > VMDK_GD_ENTRIES_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "invalid vmdk grain directory size");

	gd_offset = grub_le_to_cpu64 (header.gd_offset);
	if (grub_mul (gd_offset, (grub_uint64_t) VMDK_SECTOR_SIZE,
		      &gd_byte_offset))
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "invalid vmdk grain directory offset");

	ext = vmdk_add_extent (image);
	if (!ext)
		return grub_errno;
	ext->file = file;
	ext->own_file = own_file;
	ext->type = VMDK_EXTENT_SPARSE;
	ext->sectors = sectors;
	ext->compressed = grub_le_to_cpu16 (header.compress_algorithm)
		== VMDK4_COMPRESSION_DEFLATE;
	ext->has_marker = !!(grub_le_to_cpu32 (header.flags) & VMDK4_FLAG_MARKER);
	ext->has_zero_grain = !!(grub_le_to_cpu32 (header.flags) & VMDK4_FLAG_ZERO_GRAIN);
	ext->grain_bytes = granularity * VMDK_SECTOR_SIZE;
	ext->gtes_per_gt = gtes_per_gt;
	ext->gd_entries = (grub_uint32_t) gd_entries;
	ext->gt_cached = 0;

	ext->gd = grub_malloc (gd_entries * sizeof (grub_uint32_t));
	ext->gt_cache = grub_malloc ((grub_size_t) gtes_per_gt
				     * sizeof (grub_uint32_t));
	if (!ext->gd || !ext->gt_cache)
		return grub_errno;
	err = vmdk_pread (file, gd_byte_offset, ext->gd,
			  gd_entries * sizeof (grub_uint32_t));
	if (err)
		return err;
	return GRUB_ERR_NONE;
}

/* ------------------------------------------------------------------ */
/* descriptor parsing                                                  */

static const char *
vmdk_next_line (const char *p)
{
	while (*p && *p != '\n')
		p++;
	if (*p)
		p++;
	return p;
}

/* Extract a quoted value following `KEY="' anywhere in DESC.  */
static char *
vmdk_desc_get_str (const char *desc, const char *key)
{
	const char *p = grub_strstr (desc, key);
	const char *end;

	if (!p)
		return NULL;
	p += grub_strlen (key);
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != '=')
		return NULL;
	p++;
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != '"')
		return NULL;
	p++;
	end = p;
	while (*end && *end != '"' && *end != '\n' && *end != '\r')
		end++;
	if (*end != '"')
		return NULL;
	return grub_strndup (p, end - p);
}

/* Parse one token of at most LEN-1 chars; returns NULL on overflow.  */
static const char *
vmdk_get_token (const char *p, char *out, grub_size_t len)
{
	grub_size_t i = 0;

	while (*p == ' ' || *p == '\t')
		p++;
	while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
	{
		if (i + 1 >= len)
			return NULL;
		out[i++] = *p++;
	}
	out[i] = '\0';
	return i ? p : NULL;
}

/*
 * Parse the extent lines of a descriptor and open the referenced
 * files.  Lines look like:
 *   RW 4192256 SPARSE "disk-s001.vmdk"
 *   RW 4192256 FLAT "disk-flat.vmdk" 0
 *   RW 8388608 VMFS "disk-flat.vmdk"
 *   RW 123 ZERO
 */
static grub_err_t
vmdk_parse_extents (struct vmdk_image *image, const char *desc)
{
	const char *p;
	grub_err_t err;

	for (p = desc; *p; p = vmdk_next_line (p))
	{
		char access[11], type[11];
		char fname[512];
		const char *q;
		grub_uint64_t sectors;
		grub_uint64_t flat_offset = 0;
		grub_uint64_t flat_start;
		grub_uint64_t extent_bytes;
		grub_file_t file;
		struct vmdk_extent *ext;

		q = vmdk_get_token (p, access, sizeof (access));
		if (!q || grub_strcmp (access, "RW") != 0)
			continue;

		sectors = grub_strtoull (q, &q, 10);
		if (grub_errno)
		{
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		q = vmdk_get_token (q, type, sizeof (type));
		if (!q || sectors == 0)
			continue;
		if (sectors > ~0ULL / VMDK_SECTOR_SIZE)
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "vmdk extent size overflow");

		if (grub_strcmp (type, "ZERO") == 0)
		{
			ext = vmdk_add_extent (image);
			if (!ext)
				return grub_errno;
			ext->type = VMDK_EXTENT_ZERO;
			ext->sectors = sectors;
			continue;
		}

		if (grub_strcmp (type, "FLAT") != 0
		    && grub_strcmp (type, "VMFS") != 0
		    && grub_strcmp (type, "SPARSE") != 0)
		{
			if (grub_strcmp (type, "VMFSSPARSE") == 0
			    || grub_strcmp (type, "SESPARSE") == 0)
				return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
						   "unsupported vmdk extent type `%s'",
						   type);
			continue;
		}

		/* Quoted file name.  */
		while (*q == ' ' || *q == '\t')
			q++;
		if (*q != '"')
			continue;
		q++;
		{
			grub_size_t i = 0;
			while (*q && *q != '"' && *q != '\n' && *q != '\r')
			{
				if (i + 1 >= sizeof (fname))
					break;
				fname[i++] = *q++;
			}
			fname[i] = '\0';
			if (*q != '"' || i == 0)
				continue;
			q++;
		}

		if (grub_strcmp (type, "FLAT") == 0)
		{
			flat_offset = grub_strtoull (q, &q, 10);
			if (grub_errno)
			{
				grub_errno = GRUB_ERR_NONE;
				continue;
			}
		}

		file = grub_vdisk_open_member (image->file->name, fname);
		if (!file)
			return grub_errno;

		if (grub_strcmp (type, "SPARSE") == 0)
		{
			err = vmdk_open_sparse_extent (image, file, 1, sectors);
			if (err)
			{
				/* Not yet owned by the extent array on failure
				   before vmdk_add_extent; afterwards the array
				   owns it.  Close only if not appended.  */
				if (image->n_extents == 0
				    || image->extents[image->n_extents - 1].file != file)
					grub_file_close (file);
				return err;
			}
		}
		else
		{
			if (grub_mul (flat_offset,
				      (grub_uint64_t) VMDK_SECTOR_SIZE,
				      &flat_start)
			    || grub_mul (sectors,
					 (grub_uint64_t) VMDK_SECTOR_SIZE,
					 &extent_bytes)
			    || flat_start > grub_file_size (file)
			    || extent_bytes > grub_file_size (file) - flat_start)
			{
				grub_file_close (file);
				return grub_error (GRUB_ERR_BAD_DEVICE,
						   "vmdk flat extent truncated");
			}
			ext = vmdk_add_extent (image);
			if (!ext)
			{
				grub_file_close (file);
				return grub_errno;
			}
			ext->file = file;
			ext->own_file = 1;
			ext->type = VMDK_EXTENT_FLAT;
			ext->sectors = sectors;
			ext->flat_start = flat_start;
		}
	}

	if (image->n_extents == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "vmdk descriptor has no usable extents");
	return GRUB_ERR_NONE;
}

/* Pick up parent linkage from a descriptor.  */
static void
vmdk_parse_parent (struct vmdk_image *image, const char *desc)
{
	const char *p;

	if (image->parent_hint)
		return;

	/* parentCID=ffffffff means no parent.  */
	p = grub_strstr (desc, "parentCID");
	if (p)
	{
		p += sizeof ("parentCID") - 1;
		while (*p == ' ' || *p == '\t' || *p == '=')
			p++;
		if (grub_strtoul (p, NULL, 16) == 0xffffffffUL)
		{
			grub_errno = GRUB_ERR_NONE;
			return;
		}
		grub_errno = GRUB_ERR_NONE;
	}

	image->parent_hint = vmdk_desc_get_str (desc, "parentFileNameHint");
}

/* ------------------------------------------------------------------ */
/* open                                                                */

static grub_err_t
vmdk_open_image (struct vmdk_image *image)
{
	grub_uint8_t magic[4];
	char *desc = NULL;
	grub_err_t err;

	err = vmdk_pread (image->file, 0, magic, sizeof (magic));
	if (err)
		return err;

	if (grub_memcmp (magic, "COWD", 4) == 0)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "VMDK3 images are not supported");

	if (grub_memcmp (magic, "KDMV", 4) == 0)
	{
		struct vmdk4_header header;

		err = vmdk_pread (image->file, sizeof (magic), &header,
				  sizeof (header));
		if (err)
			return err;

		/* Read the embedded descriptor (parent linkage; also the
		   extent list when the header carries no data).  */
		if (grub_le_to_cpu64 (header.desc_offset)
		    && grub_le_to_cpu64 (header.desc_size))
		{
			grub_uint64_t off;
			grub_uint64_t len;

			if (grub_mul (grub_le_to_cpu64 (header.desc_offset),
				      (grub_uint64_t) VMDK_SECTOR_SIZE, &off)
			    || grub_mul (grub_le_to_cpu64 (header.desc_size),
					 (grub_uint64_t) VMDK_SECTOR_SIZE, &len)
			    || len > VMDK_DESC_SIZE_MAX)
				return grub_error (GRUB_ERR_BAD_DEVICE,
						   "invalid vmdk descriptor size");
			desc = grub_zalloc ((grub_size_t) len + 1);
			if (!desc)
				return grub_errno;
			err = vmdk_pread (image->file, off, desc,
					  (grub_size_t) len);
			if (err)
				goto fail;
			vmdk_parse_parent (image, desc);
		}

		if (grub_le_to_cpu64 (header.capacity) == 0)
		{
			/* Descriptor-only KDMV file.  */
			if (!desc)
				return grub_error (GRUB_ERR_BAD_DEVICE,
						   "empty vmdk image");
			err = vmdk_parse_extents (image, desc);
			if (err)
				goto fail;
		}
		else
		{
			err = vmdk_open_sparse_extent (image, image->file, 0, 0);
			if (err)
				goto fail;
		}
	}
	else
	{
		/* Text descriptor file; the first line is fixed, check it
		   before pulling in the whole file.  */
		static const char sig[] = "# Disk DescriptorFile";
		char head[sizeof (sig) - 1];
		grub_uint64_t len = grub_file_size (image->file);

		if (len < sizeof (head))
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "not a vmdk descriptor");
		err = vmdk_pread (image->file, 0, head, sizeof (head));
		if (err)
			return err;
		if (grub_memcmp (head, sig, sizeof (head)) != 0)
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "not a vmdk descriptor");

		if (len > VMDK_DESC_SIZE_MAX)
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "vmdk descriptor too large");
		desc = grub_zalloc ((grub_size_t) len + 1);
		if (!desc)
			return grub_errno;
		err = vmdk_pread (image->file, 0, desc, (grub_size_t) len);
		if (err)
			goto fail;
		vmdk_parse_parent (image, desc);
		err = vmdk_parse_extents (image, desc);
		if (err)
			goto fail;
	}

	if (grub_add (image->extents[image->n_extents - 1].sector_first,
		      image->extents[image->n_extents - 1].sectors,
		      &image->total_bytes)
	    || grub_mul (image->total_bytes,
			 (grub_uint64_t) VMDK_SECTOR_SIZE,
			 &image->total_bytes))
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE,
				  "vmdk virtual size overflow");
		goto fail;
	}

	if (image->parent_hint)
	{
		image->parent = grub_vdisk_open_parent (image->file->name,
							image->parent_hint);
		if (!image->parent)
		{
			err = grub_errno;
			goto fail;
		}
	}

	grub_free (desc);
	return GRUB_ERR_NONE;

fail:
	grub_free (desc);
	return err;
}

/* ------------------------------------------------------------------ */
/* read                                                                */

static struct vmdk_extent *
vmdk_find_extent (struct vmdk_image *image, grub_uint64_t sector)
{
	unsigned i = image->last_extent;

	if (i >= image->n_extents
	    || sector < image->extents[i].sector_first
	    || sector >= image->extents[i].sector_first + image->extents[i].sectors)
	{
		for (i = 0; i < image->n_extents; i++)
			if (sector >= image->extents[i].sector_first
			    && sector < image->extents[i].sector_first
				       + image->extents[i].sectors)
				break;
		if (i >= image->n_extents)
			return NULL;
		image->last_extent = i;
	}
	return &image->extents[i];
}

/* Read from an unallocated range: parent chain or zeros.  */
static grub_err_t
vmdk_read_unalloc (struct vmdk_image *image, grub_uint64_t off,
		   void *buf, grub_size_t len)
{
	if (image->parent)
		return grub_vdisk_read_parent (image->parent, off, buf, len);
	grub_memset (buf, 0, len);
	return GRUB_ERR_NONE;
}

/* Decompress the grain at GRAIN_SECTOR into the image's grain cache.  */
static grub_err_t
vmdk_load_compressed_grain (struct vmdk_image *image,
			    struct vmdk_extent *ext,
			    grub_uint64_t grain_nr,
			    grub_uint64_t grain_sector)
{
	grub_uint64_t off;
	grub_uint64_t extent_bytes;
	grub_uint64_t grain_start;
	grub_uint64_t expected;
	grub_size_t max_read = 2 * (grub_size_t) ext->grain_bytes;
	grub_size_t comp_len;
	const grub_uint8_t *data;
	grub_ssize_t n;
	grub_ssize_t out_len;

	if (image->grain_extent == ext && image->grain_nr == grain_nr)
		return GRUB_ERR_NONE;
	image->grain_extent = NULL;
	if (grub_mul (grain_sector, (grub_uint64_t) VMDK_SECTOR_SIZE,
		      &off)
	    || grub_mul (ext->sectors, (grub_uint64_t) VMDK_SECTOR_SIZE,
			 &extent_bytes)
	    || grub_mul (grain_nr, ext->grain_bytes, &grain_start)
	    || grain_start >= extent_bytes)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "invalid vmdk compressed grain");
	expected = extent_bytes - grain_start;
	if (expected > ext->grain_bytes)
		expected = ext->grain_bytes;

	if (image->grain_buf_size < ext->grain_bytes)
	{
		grub_free (image->grain_buf);
		image->grain_buf = grub_malloc ((grub_size_t) ext->grain_bytes);
		if (!image->grain_buf)
			return grub_errno;
		image->grain_buf_size = (grub_size_t) ext->grain_bytes;
	}
	if (image->comp_buf_size < max_read)
	{
		grub_free (image->comp_buf);
		image->comp_buf = grub_malloc (max_read);
		if (!image->comp_buf)
			return grub_errno;
		image->comp_buf_size = max_read;
	}

	if (off >= grub_file_size (ext->file))
		return grub_error (GRUB_ERR_BAD_DEVICE, "vmdk grain out of file");
	if (max_read > grub_file_size (ext->file) - off)
		max_read = (grub_size_t) (grub_file_size (ext->file) - off);

	grub_file_seek (ext->file, off);
	n = grub_file_read (ext->file, image->comp_buf, max_read);
	if (n < 0)
		return grub_errno;

	data = image->comp_buf;
	comp_len = (grub_size_t) n;
	if (ext->has_marker)
	{
		struct vmdk_grain_marker marker;

		if (comp_len < sizeof (marker))
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "truncated vmdk grain marker");
		grub_memcpy (&marker, data, sizeof (marker));
		if (grub_le_to_cpu32 (marker.size) == 0
		    || grub_le_to_cpu32 (marker.size) > comp_len - sizeof (marker))
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "invalid vmdk grain marker");
		data += sizeof (marker);
		comp_len = grub_le_to_cpu32 (marker.size);
	}

	/* Grains are zlib streams; a short last grain decompresses to
	   less than grain_bytes, the tail stays zero.  */
	grub_memset (image->grain_buf, 0, (grub_size_t) ext->grain_bytes);
	out_len = grub_zlib_decompress ((char *) data, comp_len, 0,
					(char *) image->grain_buf,
					(grub_size_t) ext->grain_bytes);
	if (out_len < 0)
	{
		if (grub_errno)
			return grub_errno;
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "vmdk grain decompression failed");
	}
	if ((grub_uint64_t) out_len < expected)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "vmdk grain decompressed short");

	image->grain_extent = ext;
	image->grain_nr = grain_nr;
	return GRUB_ERR_NONE;
}

static grub_err_t
vmdk_read (struct vmdk_image *image, grub_uint64_t off, void *buf,
	   grub_size_t len, grub_size_t *actually_read)
{
	struct vmdk_extent *ext;
	grub_uint64_t ext_start;
	grub_uint64_t off_in_extent;
	grub_uint64_t ext_bytes;
	grub_err_t err = GRUB_ERR_NONE;

	if (actually_read)
		*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return GRUB_ERR_BAD_ARGUMENT;

	ext = vmdk_find_extent (image, off / VMDK_SECTOR_SIZE);
	if (!ext)
		return GRUB_ERR_BAD_ARGUMENT;
	ext_start = ext->sector_first * VMDK_SECTOR_SIZE;
	off_in_extent = off - ext_start;
	ext_bytes = ext->sectors * VMDK_SECTOR_SIZE;

	/* Clip to the extent; never grow a request.  */
	if (len > ext_bytes - off_in_extent)
		len = (grub_size_t) (ext_bytes - off_in_extent);

	switch (ext->type)
	{
	case VMDK_EXTENT_ZERO:
		grub_memset (buf, 0, len);
		break;

	case VMDK_EXTENT_FLAT:
	{
		grub_uint64_t file_off;

		if (grub_add (ext->flat_start, off_in_extent, &file_off))
			err = grub_error (GRUB_ERR_OUT_OF_RANGE,
					  "vmdk flat extent offset overflow");
		else
			err = vmdk_pread (ext->file, file_off, buf, len);
		break;
	}

	case VMDK_EXTENT_SPARSE:
	{
		grub_uint64_t grain_nr = off_in_extent / ext->grain_bytes;
		grub_uint64_t off_in_grain = off_in_extent % ext->grain_bytes;
		grub_uint32_t gd_index = (grub_uint32_t) (grain_nr / ext->gtes_per_gt);
		grub_uint32_t gt_index = (grub_uint32_t) (grain_nr % ext->gtes_per_gt);
		grub_uint32_t gt_sector;
		grub_uint32_t grain_sector;

		/* Clip to the grain; never grow.  */
		if (len > ext->grain_bytes - off_in_grain)
			len = (grub_size_t) (ext->grain_bytes - off_in_grain);

		if (gd_index >= ext->gd_entries)
			return GRUB_ERR_OUT_OF_RANGE;
		gt_sector = grub_le_to_cpu32 (ext->gd[gd_index]);
		if (gt_sector == 0)
		{
			err = vmdk_read_unalloc (image, off, buf, len);
			break;
		}

		if (ext->gt_cached != gt_sector)
		{
			ext->gt_cached = 0;
			err = vmdk_pread (ext->file,
					  (grub_uint64_t) gt_sector * VMDK_SECTOR_SIZE,
					  ext->gt_cache,
					  (grub_size_t) ext->gtes_per_gt
					  * sizeof (grub_uint32_t));
			if (err)
				break;
			ext->gt_cached = gt_sector;
		}

		grain_sector = grub_le_to_cpu32 (ext->gt_cache[gt_index]);
		if (grain_sector == 0)
		{
			err = vmdk_read_unalloc (image, off, buf, len);
			break;
		}
		if (grain_sector == 1 && ext->has_zero_grain)
		{
			grub_memset (buf, 0, len);
			break;
		}

		if (!ext->compressed)
		{
			err = vmdk_pread (ext->file,
					  (grub_uint64_t) grain_sector * VMDK_SECTOR_SIZE
					  + off_in_grain,
					  buf, len);
			break;
		}

		err = vmdk_load_compressed_grain (image, ext, grain_nr,
						  grain_sector);
		if (err)
			break;
		grub_memcpy (buf, image->grain_buf + off_in_grain, len);
		break;
	}
	}

	if (!err && actually_read)
		*actually_read = len;
	return err;
}

/* ------------------------------------------------------------------ */
/* io filter wrapper                                                   */

struct grub_vmdk
{
	grub_file_t file;
	struct vmdk_image *vmdk;
};
typedef struct grub_vmdk *grub_vmdk_t;

static struct grub_fs grub_vmdk_fs;

static grub_err_t
grub_vmdk_close (grub_file_t file)
{
	grub_vmdk_t vmdkio = file->data;

	vmdk_free_image (vmdkio->vmdk);
	grub_free (vmdkio->vmdk);
	grub_file_close (vmdkio->file);
	grub_free (vmdkio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_vmdk_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_vmdk_t vmdkio;
	struct vmdk_image *image;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	/* Text descriptor files are routinely smaller than a sector; the
	   fixed first line is the practical minimum.  */
	if (io->size < sizeof ("# Disk DescriptorFile") - 1
	    || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (vmdk_open_image (image) != GRUB_ERR_NONE)
	{
		vmdk_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	vmdkio = grub_zalloc (sizeof (*vmdkio));
	if (!file || !vmdkio)
	{
		vmdk_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (vmdkio);
		return 0;
	}
	vmdkio->file = io;
	vmdkio->vmdk = image;

	file->device = io->device;
	file->data = vmdkio;
	file->fs = &grub_vmdk_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;

	return file;
}

static grub_ssize_t
grub_vmdk_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_vmdk_t vmdkio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = vmdk_read (vmdkio->vmdk, read_offset, buf, len,
				 &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR,
					  "vmdk read made no progress");
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
			grub_error (err, "vmdk image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_vmdk_fs =
{
	.name = "vmdk",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_vmdk_read,
	.fs_close = grub_vmdk_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (vmdk)
{
	grub_file_filter_register (GRUB_FILE_FILTER_VMDK, grub_vmdk_open);
}

GRUB_MOD_FINI (vmdk)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_VMDK);
}
