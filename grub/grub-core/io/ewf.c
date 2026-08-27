/* ewf.c - Expert Witness Compression Format disk image filter */
/*
 *  Rover -- GRUB 2 filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  The on-disk layout and compatibility rules are based on ref\libewf,
 *  in particular its EWF specification and version 1 segment/table reader.
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
#include <grub/deflate.h>
#include <grub/safemath.h>
#include <grub/winfile.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define EWF_FILE_HEADER_SIZE	13
#define EWF_SECTION_DESC_SIZE	76
#define EWF_TABLE_HEADER_SIZE	24
#define EWF_TABLE_FOOTER_SIZE	4
#define EWF_VOLUME_SIZE		1052
#define EWF_SMART_VOLUME_SIZE	94

#define EWF_MAX_SEGMENTS	4096
#define EWF_MAX_GROUPS		(1u << 20)
#define EWF_MAX_CHUNKS		(16u << 20)
#define EWF_MAX_SECTIONS	(1u << 20)
#define EWF_MAX_CHUNK_SIZE	(64u << 20)
#define EWF_CACHE_NONE		0xffffffffu

#define EWF_COMPRESSED		0x80000000u
#define EWF_OFFSET_MASK		0x7fffffffu

static const grub_uint8_t ewf_signature[8] =
{
	'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00
};

static const grub_uint8_t ewf_logical_signature[8] =
{
	'L', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00
};

static const grub_uint8_t ewf2_signature[8] =
{
	'E', 'V', 'F', '2', 0x0d, 0x0a, 0x81, 0x00
};

struct ewf_segment
{
	grub_file_t file;
};

struct ewf_group
{
	grub_uint32_t first_chunk;
	grub_uint32_t count;
	grub_uint32_t overflow_at;
	grub_uint32_t segment;
	grub_uint64_t base_offset;
	grub_uint64_t data_end;
	grub_uint32_t *entries;
};

struct ewf_image
{
	struct ewf_segment *segments;
	grub_uint32_t nsegments;
	struct ewf_group *groups;
	grub_uint32_t ngroups;
	grub_uint32_t nchunks;
	grub_uint32_t indexed_chunks;
	grub_uint32_t chunk_size;
	grub_uint32_t sector_size;
	grub_uint64_t total_bytes;
	grub_uint8_t set_id[16];
	int has_set_id;
	int volume_seen;
	int smart;

	grub_uint32_t cached_chunk;
	grub_uint32_t cached_group;
	grub_uint8_t *chunk_buf;
	grub_uint8_t *comp_buf;
	grub_size_t comp_capacity;
};

struct grub_ewf
{
	grub_file_t file;
	struct ewf_image *image;
};
typedef struct grub_ewf *grub_ewf_t;

static struct grub_fs grub_ewf_fs;

static grub_uint16_t
ewf_get16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) p[0] | ((grub_uint16_t) p[1] << 8);
}

static grub_uint32_t
ewf_get32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0]
		| ((grub_uint32_t) p[1] << 8)
		| ((grub_uint32_t) p[2] << 16)
		| ((grub_uint32_t) p[3] << 24);
}

static grub_uint64_t
ewf_get64 (const grub_uint8_t *p)
{
	return (grub_uint64_t) ewf_get32 (p)
		| ((grub_uint64_t) ewf_get32 (p + 4) << 32);
}

static grub_uint32_t
ewf_adler32 (const void *data, grub_size_t len)
{
	const grub_uint8_t *p = data;
	grub_uint32_t s1 = 1;
	grub_uint32_t s2 = 0;

	while (len > 0)
	{
		grub_size_t n = len > 5552 ? 5552 : len;

		len -= n;
		while (n--)
		{
			s1 += *p++;
			s2 += s1;
		}
		s1 %= 65521;
		s2 %= 65521;
	}
	return (s2 << 16) | s1;
}

static int
ewf_power_of_two (grub_uint32_t value)
{
	return value && !(value & (value - 1));
}

static grub_err_t
ewf_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_uint64_t size = grub_file_size (file);
	grub_ssize_t got;

	if (size == GRUB_FILE_SIZE_UNKNOWN || off > size || len > size - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "EWF segment truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	got = grub_file_read (file, buf, len);
	if (got < 0)
		return grub_errno;
	if ((grub_size_t) got != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "EWF segment truncated");
	return GRUB_ERR_NONE;
}

static int
ewf_nonzero (const grub_uint8_t *data, grub_size_t len)
{
	while (len--)
		if (*data++)
			return 1;
	return 0;
}

static void
ewf_free_image (struct ewf_image *image)
{
	grub_uint32_t i;

	for (i = 1; i < image->nsegments; i++)
		grub_file_close (image->segments[i].file);
	for (i = 0; i < image->ngroups; i++)
		grub_free (image->groups[i].entries);
	grub_free (image->segments);
	grub_free (image->groups);
	grub_free (image->chunk_buf);
	grub_free (image->comp_buf);
	grub_free (image);
}

static grub_err_t
ewf_add_segment (struct ewf_image *image, grub_file_t file)
{
	struct ewf_segment *segments;
	grub_size_t size;

	if (image->nsegments >= EWF_MAX_SEGMENTS
		|| grub_mul ((grub_size_t) image->nsegments + 1, sizeof (*segments), &size))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many EWF segment files");
	segments = grub_realloc (image->segments, size);
	if (!segments)
		return grub_errno;
	image->segments = segments;
	segments[image->nsegments++].file = file;
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf_add_group (struct ewf_image *image, struct ewf_group *group)
{
	struct ewf_group *groups;
	grub_size_t size;

	if (image->ngroups >= EWF_MAX_GROUPS
		|| grub_mul ((grub_size_t) image->ngroups + 1, sizeof (*groups), &size))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many EWF chunk tables");
	groups = grub_realloc (image->groups, size);
	if (!groups)
		return grub_errno;
	image->groups = groups;
	groups[image->ngroups++] = *group;
	group->entries = NULL;
	return GRUB_ERR_NONE;
}

static char *
ewf_segment_name (const char *name, grub_uint32_t number, int alternate_case)
{
	const char *slash;
	const char *dot;
	grub_size_t stem;
	char first;
	char alpha;
	char ext[4];
	char *out;
	grub_uint32_t n;

	if (!name || number == 0)
		return NULL;
	slash = grub_strrchr (name, '/');
	dot = grub_strrchr (slash ? slash : name, '.');
	if (!dot || grub_strlen (dot + 1) != 3)
		return NULL;

	first = dot[1];
	if (first >= 'A' && first <= 'Z')
	{
		if (alternate_case)
			first = (char) (first - 'A' + 'a');
		alpha = (first >= 'a' && first <= 'z') ? 'a' : 'A';
	}
	else if (first >= 'a' && first <= 'z')
	{
		if (alternate_case)
			first = (char) (first - 'a' + 'A');
		alpha = (first >= 'a' && first <= 'z') ? 'a' : 'A';
	}
	else
		return NULL;

	ext[0] = first;
	if (number <= 99)
	{
		ext[1] = (char) ('0' + number / 10);
		ext[2] = (char) ('0' + number % 10);
	}
	else
	{
		n = number - 100;
		if (n / (26 * 26) > (grub_uint32_t) ('z' - first) && first >= 'a')
			return NULL;
		if (n / (26 * 26) > (grub_uint32_t) ('Z' - first) && first <= 'Z')
			return NULL;
		ext[0] = (char) (first + n / (26 * 26));
		ext[1] = (char) (alpha + (n / 26) % 26);
		ext[2] = (char) (alpha + n % 26);
	}
	ext[3] = 0;

	stem = (grub_size_t) (dot - name + 1);
	out = grub_malloc (stem + sizeof (ext));
	if (!out)
		return NULL;
	grub_memcpy (out, name, stem);
	grub_memcpy (out + stem, ext, sizeof (ext));
	return out;
}

static grub_file_t
ewf_open_segment (struct ewf_image *image, const char *name, grub_uint32_t number)
{
	grub_file_t first = image->segments[0].file;
	grub_file_t file;
	unsigned attempt;

	for (attempt = 0; attempt < 2; attempt++)
	{
		char *path = ewf_segment_name (name, number, attempt != 0);

		if (!path)
			return NULL;
		if (first->fs && grub_strcmp (first->fs->name, "winfile") == 0)
			file = grub_winfile_open (path, GRUB_FILE_TYPE_LOOPBACK | GRUB_FILE_TYPE_NO_DECOMPRESS);
		else
			file = grub_file_open (path, GRUB_FILE_TYPE_LOOPBACK | GRUB_FILE_TYPE_NO_DECOMPRESS);
		grub_free (path);
		if (file)
			return file;
		grub_errno = GRUB_ERR_NONE;
	}
	return NULL;
}

static grub_err_t
ewf_check_file_header (grub_file_t file, grub_uint32_t expected_segment)
{
	grub_uint8_t header[EWF_FILE_HEADER_SIZE];
	grub_err_t err;

	err = ewf_pread (file, 0, header, sizeof (header));
	if (err)
		return err;
	if (grub_memcmp (header, ewf_signature, sizeof (ewf_signature)) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad EWF segment signature");
	if (header[8] != 1 || header[11] != 0 || header[12] != 0
		|| ewf_get16 (header + 9) != expected_segment)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF segment header");
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf_parse_volume (struct ewf_image *image, grub_file_t file,
		  grub_uint64_t off, grub_uint64_t size)
{
	grub_uint8_t data[EWF_VOLUME_SIZE];
	grub_uint64_t sectors;
	grub_uint64_t total;
	grub_uint64_t expected_chunks;
	grub_uint32_t chunks;
	grub_uint32_t sectors_per_chunk;
	grub_uint32_t sector_size;
	grub_uint32_t stored_sum;
	grub_size_t volume_size;
	int smart;
	grub_err_t err;

	if (image->volume_seen)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "duplicate EWF volume section");
	if (size >= EWF_VOLUME_SIZE)
	{
		volume_size = EWF_VOLUME_SIZE;
		smart = 0;
	}
	else if (size >= EWF_SMART_VOLUME_SIZE)
	{
		volume_size = EWF_SMART_VOLUME_SIZE;
		smart = 1;
	}
	else
		return grub_error (GRUB_ERR_BAD_DEVICE, "short EWF volume section");

	err = ewf_pread (file, off, data, volume_size);
	if (err)
		return err;
	stored_sum = ewf_get32 (data + volume_size - 4);
	if (stored_sum != ewf_adler32 (data, volume_size - 4))
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF volume checksum");
	if (!smart && data[0] == 0x0e)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "logical EWF-L01 images are not disk images");

	chunks = ewf_get32 (data + 4);
	sectors_per_chunk = ewf_get32 (data + 8);
	sector_size = ewf_get32 (data + 12);
	sectors = smart ? ewf_get32 (data + 16) : ewf_get64 (data + 16);
	if (!chunks || chunks > EWF_MAX_CHUNKS
		|| !sectors_per_chunk || !sector_size
		|| !ewf_power_of_two (sector_size)
		|| sector_size < 128 || sector_size > 65536
		|| sectors_per_chunk > EWF_MAX_CHUNK_SIZE / sector_size)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF media geometry");
	image->chunk_size = sectors_per_chunk * sector_size;
	if (!image->chunk_size || image->chunk_size > EWF_MAX_CHUNK_SIZE
		|| grub_mul (sectors, sector_size, &total) || !total)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "bad EWF media size");
	expected_chunks = (total + image->chunk_size - 1) / image->chunk_size;
	if (expected_chunks != chunks)
		return grub_error (GRUB_ERR_BAD_DEVICE, "inconsistent EWF chunk count");

	image->nchunks = chunks;
	image->sector_size = sector_size;
	image->total_bytes = total;
	image->smart = smart;
	if (!smart)
	{
		grub_memcpy (image->set_id, data + 64, sizeof (image->set_id));
		image->has_set_id = ewf_nonzero (image->set_id, sizeof (image->set_id));
	}
	image->volume_seen = 1;
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf_check_data_section (struct ewf_image *image, grub_file_t file,
	grub_uint64_t off, grub_uint64_t size)
{
	grub_uint8_t data[EWF_VOLUME_SIZE];
	grub_uint32_t stored_sum;
	grub_err_t err;

	if (!image->volume_seen || image->smart || size < sizeof (data))
		return GRUB_ERR_NONE;
	err = ewf_pread (file, off, data, sizeof (data));
	if (err)
		return err;
	stored_sum = ewf_get32 (data + sizeof (data) - 4);
	/* Some Logicube writers leave this checksum unset.  */
	if (stored_sum && stored_sum != ewf_adler32 (data, sizeof (data) - 4))
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF data checksum");
	if (ewf_get32 (data + 4) != image->nchunks
		|| ewf_get32 (data + 8) != image->chunk_size / image->sector_size
		|| ewf_get32 (data + 12) != image->sector_size
		|| ewf_get64 (data + 16) != image->total_bytes / image->sector_size)
		return grub_error (GRUB_ERR_BAD_DEVICE, "inconsistent EWF segment geometry");
	if (image->has_set_id
		&& grub_memcmp (data + 64, image->set_id, sizeof (image->set_id)) != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "EWF segment belongs to another set");
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf_parse_table (struct ewf_image *image, grub_file_t file,
	grub_uint32_t segment, grub_uint64_t section_off, grub_uint64_t section_size)
{
	grub_uint8_t header[EWF_TABLE_HEADER_SIZE];
	grub_uint8_t checksum[4];
	struct ewf_group group = { 0 };
	grub_uint64_t file_size = grub_file_size (file);
	grub_uint64_t section_end;
	grub_uint64_t entries_bytes;
	grub_uint64_t max_stored;
	grub_uint64_t last_phys;
	grub_uint64_t phys;
	grub_uint64_t stored_size;
	grub_uint32_t raw;
	grub_uint32_t next_raw;
	grub_uint32_t current;
	grub_uint32_t next;
	grub_uint32_t i;
	int overflow = 0;
	grub_err_t err;

	if (!image->volume_seen)
		return grub_error (GRUB_ERR_BAD_DEVICE, "EWF table precedes volume metadata");
	if (section_size < EWF_SECTION_DESC_SIZE + EWF_TABLE_HEADER_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "short EWF table section");
	section_end = section_off + section_size;

	err = ewf_pread (file, section_off + EWF_SECTION_DESC_SIZE, header, sizeof (header));
	if (err)
		return err;
	if (ewf_get32 (header + 20) != ewf_adler32 (header, 20))
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF table header checksum");
	group.count = ewf_get32 (header);
	group.base_offset = ewf_get64 (header + 8);
	if (!group.count || group.count > EWF_MAX_CHUNKS
		|| group.count > image->nchunks - image->indexed_chunks)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF table entry count");
	entries_bytes = (grub_uint64_t) group.count * sizeof (*group.entries);
	if (entries_bytes > section_size - EWF_SECTION_DESC_SIZE - EWF_TABLE_HEADER_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "truncated EWF table");
	group.entries = grub_malloc ((grub_size_t) entries_bytes);
	if (!group.entries)
		return grub_errno;
	err = ewf_pread (file, section_off + EWF_SECTION_DESC_SIZE + EWF_TABLE_HEADER_SIZE, group.entries, (grub_size_t) entries_bytes);
	if (err)
		goto fail;
	for (i = 0; i < group.count; i++)
		group.entries[i] = grub_le_to_cpu32 (group.entries[i]);

	if (!image->smart)
	{
		grub_uint64_t footer_off = section_off + EWF_SECTION_DESC_SIZE + EWF_TABLE_HEADER_SIZE + entries_bytes;

		if (footer_off > file_size || sizeof (checksum) > file_size - footer_off)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE, "truncated EWF table footer");
			goto fail;
		}
		err = ewf_pread (file, footer_off, checksum, sizeof (checksum));
		if (err)
			goto fail;
		if (ewf_get32 (checksum) != ewf_adler32 (group.entries, (grub_size_t) entries_bytes))
		{
			/* The checksum covers the little-endian bytes.  On the supported
			   Windows targets the converted array is byte-identical.  */
			err = grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF table checksum");
			goto fail;
		}
	}

	group.first_chunk = image->indexed_chunks;
	group.segment = segment;
	group.overflow_at = group.count;
	max_stored = (grub_uint64_t) image->chunk_size
		+ image->chunk_size / 100 + 65536;

	for (i = 0; i < group.count; i++)
	{
		raw = group.entries[i];
		current = overflow ? raw : raw & EWF_OFFSET_MASK;
		if (i + 1 < group.count)
		{
			next_raw = group.entries[i + 1];
			next = overflow ? next_raw : next_raw & EWF_OFFSET_MASK;
			if (!overflow && next < current && next_raw >= current)
				next = next_raw;
			if (next <= current)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE, "invalid EWF chunk offsets");
				goto fail;
			}
			stored_size = next - current;
		}
		else
			stored_size = 0;
		if (grub_add (group.base_offset, current, &phys) || phys >= file_size)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE, "EWF chunk offset outside segment");
			goto fail;
		}
		if (i + 1 == group.count)
		{
			last_phys = phys;
			if (last_phys < section_off)
				group.data_end = section_off;
			else if (last_phys < section_end)
				group.data_end = section_end;
			else
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE, "last EWF chunk outside data section");
				goto fail;
			}
			stored_size = group.data_end - last_phys;
		}
		if (!stored_size || stored_size > max_stored
			|| phys > file_size || stored_size > file_size - phys)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE, "invalid EWF chunk size");
			goto fail;
		}
		if (!(raw & EWF_COMPRESSED) && !overflow
			&& (stored_size < 4 || stored_size > image->chunk_size + 4))
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE, "invalid uncompressed EWF chunk size");
			goto fail;
		}
		if (stored_size > image->comp_capacity)
			image->comp_capacity = (grub_size_t) stored_size;
		if (!overflow && current + stored_size > 0x7fffffffu)
		{
			overflow = 1;
			group.overflow_at = i + 1;
		}
	}

	err = ewf_add_group (image, &group);
	if (err)
		goto fail;
	image->indexed_chunks += group.count;
	return GRUB_ERR_NONE;

fail:
	grub_free (group.entries);
	return err;
}

static int
ewf_type_is (const grub_uint8_t *type, const char *name)
{
	grub_size_t len = grub_strlen (name);

	return len <= 16 && grub_memcmp (type, name, len) == 0
		&& (len == 16 || type[len] == 0);
}

static grub_err_t
ewf_scan_segment (struct ewf_image *image, grub_uint32_t segment, int *has_next)
{
	grub_file_t file = image->segments[segment].file;
	grub_uint64_t file_size = grub_file_size (file);
	grub_uint64_t off = EWF_FILE_HEADER_SIZE;
	grub_uint32_t sections;
	grub_uint8_t desc[EWF_SECTION_DESC_SIZE];
	grub_err_t err;

	*has_next = 0;
	err = ewf_check_file_header (file, segment + 1);
	if (err)
		return err;

	for (sections = 0; sections < EWF_MAX_SECTIONS; sections++)
	{
		grub_uint64_t next;
		grub_uint64_t size;

		if (off > file_size || sizeof (desc) > file_size - off)
			return grub_error (GRUB_ERR_BAD_DEVICE, "missing EWF end section");
		err = ewf_pread (file, off, desc, sizeof (desc));
		if (err)
			return err;
		if (ewf_get32 (desc + 72) != ewf_adler32 (desc, 72))
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF section checksum");
		next = ewf_get64 (desc + 16);
		size = ewf_get64 (desc + 24);

		if (ewf_type_is (desc, "next") || ewf_type_is (desc, "done"))
		{
			*has_next = ewf_type_is (desc, "next");
			return GRUB_ERR_NONE;
		}
		if (size < EWF_SECTION_DESC_SIZE || size > file_size - off
			|| next <= off || next > file_size)
			return grub_error (GRUB_ERR_BAD_DEVICE, "invalid EWF section layout");

		if (ewf_type_is (desc, "volume"))
		{
			if (segment != 0)
				return grub_error (GRUB_ERR_BAD_DEVICE, "EWF volume in later segment");
			err = ewf_parse_volume (image, file, off + EWF_SECTION_DESC_SIZE, size - EWF_SECTION_DESC_SIZE);
			if (err)
				return err;
		}
		else if (ewf_type_is (desc, "data"))
		{
			err = ewf_check_data_section (image, file, off + EWF_SECTION_DESC_SIZE, size - EWF_SECTION_DESC_SIZE);
			if (err)
				return err;
		}
		else if (ewf_type_is (desc, "table"))
		{
			err = ewf_parse_table (image, file, segment, off, size);
			if (err)
				return err;
		}
		off = next;
	}
	return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many EWF sections");
}

static grub_err_t
ewf_open_image (struct ewf_image *image, grub_file_t first)
{
	grub_file_t file;
	grub_uint32_t segment;
	int has_next = 0;
	grub_err_t err;

	err = ewf_add_segment (image, first);
	if (err)
		return err;
	for (segment = 0; segment < EWF_MAX_SEGMENTS; segment++)
	{
		err = ewf_scan_segment (image, segment, &has_next);
		if (err)
			return err;
		if (!has_next)
			break;
		file = ewf_open_segment (image, first->name, segment + 2);
		if (!file)
			return grub_error (GRUB_ERR_FILE_NOT_FOUND, "missing EWF segment %u", segment + 2);
		err = ewf_add_segment (image, file);
		if (err)
		{
			grub_file_close (file);
			return err;
		}
	}
	if (has_next)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many EWF segment files");
	if (!image->volume_seen || image->indexed_chunks != image->nchunks)
		return grub_error (GRUB_ERR_BAD_DEVICE, "incomplete EWF chunk index");
	image->chunk_buf = grub_malloc (image->chunk_size);
	image->comp_buf = grub_malloc (image->comp_capacity);
	if (!image->chunk_buf || !image->comp_buf)
		return grub_errno;
	image->cached_chunk = EWF_CACHE_NONE;
	image->cached_group = EWF_CACHE_NONE;
	return GRUB_ERR_NONE;
}

static struct ewf_group *
ewf_find_group (struct ewf_image *image, grub_uint32_t chunk)
{
	grub_uint32_t low = 0;
	grub_uint32_t high = image->ngroups;

	if (image->cached_group < image->ngroups)
	{
		struct ewf_group *group = &image->groups[image->cached_group];

		if (chunk >= group->first_chunk && chunk - group->first_chunk < group->count)
			return group;
	}
	while (low < high)
	{
		grub_uint32_t mid = low + (high - low) / 2;
		struct ewf_group *group = &image->groups[mid];

		if (chunk < group->first_chunk)
			high = mid;
		else if (chunk - group->first_chunk >= group->count)
			low = mid + 1;
		else
		{
			image->cached_group = mid;
			return group;
		}
	}
	return NULL;
}

static grub_err_t
ewf_chunk_location (struct ewf_image *image, grub_uint32_t chunk,
	grub_file_t *file, grub_uint64_t *off, grub_uint32_t *stored_size, int *compressed)
{
	struct ewf_group *group = ewf_find_group (image, chunk);
	grub_uint32_t index;
	grub_uint32_t current;
	grub_uint32_t next;
	grub_uint64_t phys;
	grub_uint64_t size;

	if (!group)
		return grub_error (GRUB_ERR_BAD_DEVICE, "missing EWF chunk table");
	index = chunk - group->first_chunk;
	current = group->entries[index];
	*compressed = index < group->overflow_at
		&& (current & EWF_COMPRESSED) != 0;
	if (index < group->overflow_at)
		current &= EWF_OFFSET_MASK;
	if (grub_add (group->base_offset, current, &phys))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "EWF chunk offset overflow");
	if (index + 1 < group->count)
	{
		next = group->entries[index + 1];
		if (index + 1 < group->overflow_at)
			next &= EWF_OFFSET_MASK;
		if (next <= current)
			return grub_error (GRUB_ERR_BAD_DEVICE, "invalid EWF chunk offsets");
		size = next - current;
	}
	else
		size = group->data_end - phys;
	if (!size || size > image->comp_capacity)
		return grub_error (GRUB_ERR_BAD_DEVICE, "invalid EWF chunk size");

	*file = image->segments[group->segment].file;
	*off = phys;
	*stored_size = (grub_uint32_t) size;
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf_load_chunk (struct ewf_image *image, grub_uint32_t chunk)
{
	grub_file_t file;
	grub_uint64_t off;
	grub_uint64_t logical;
	grub_uint32_t stored_size;
	grub_uint32_t plain_size;
	grub_uint32_t expected;
	grub_uint8_t checksum[4];
	grub_ssize_t out_size;
	int compressed;
	grub_err_t err;

	if (image->cached_chunk == chunk)
		return GRUB_ERR_NONE;
	image->cached_chunk = EWF_CACHE_NONE;
	err = ewf_chunk_location (image, chunk, &file, &off, &stored_size, &compressed);
	if (err)
		return err;
	logical = (grub_uint64_t) chunk * image->chunk_size;
	expected = image->chunk_size;
	if (expected > image->total_bytes - logical)
		expected = (grub_uint32_t) (image->total_bytes - logical);

	if (compressed)
	{
		err = ewf_pread (file, off, image->comp_buf, stored_size);
		if (err)
			return err;
		out_size = grub_zlib_decompress ((char *) image->comp_buf, stored_size, 0, (char *) image->chunk_buf, image->chunk_size);
		if (out_size < 0 || (grub_uint32_t) out_size < expected || (grub_uint32_t) out_size > image->chunk_size)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt zlib chunk in EWF image");
	}
	else
	{
		if (stored_size < 4)
			return grub_error (GRUB_ERR_BAD_DEVICE, "short EWF data chunk");
		plain_size = stored_size - 4;
		if (plain_size < expected || plain_size > image->chunk_size)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF data chunk size");
		err = ewf_pread (file, off, image->chunk_buf, plain_size);
		if (err)
			return err;
		err = ewf_pread (file, off + plain_size, checksum, sizeof (checksum));
		if (err)
			return err;
		if (ewf_get32 (checksum) != ewf_adler32 (image->chunk_buf, plain_size))
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF chunk checksum");
	}
	image->cached_chunk = chunk;
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf_read (struct ewf_image *image, grub_uint64_t off, void *buf,
	grub_size_t len, grub_size_t *actually_read)
{
	grub_uint32_t chunk;
	grub_uint32_t in_chunk;
	grub_size_t n;
	grub_err_t err;

	*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of EWF image");
	chunk = (grub_uint32_t) (off / image->chunk_size);
	in_chunk = (grub_uint32_t) (off % image->chunk_size);
	n = image->chunk_size - in_chunk;
	if (n > len)
		n = len;
	if (n > image->total_bytes - off)
		n = (grub_size_t) (image->total_bytes - off);
	err = ewf_load_chunk (image, chunk);
	if (err)
		return err;
	grub_memcpy (buf, image->chunk_buf + in_chunk, n);
	*actually_read = n;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_ewf_close (grub_file_t file)
{
	grub_ewf_t ewfio = file->data;
	grub_file_t inner = ewfio->file;

	ewf_free_image (ewfio->image);
	grub_file_close (inner);
	grub_free (ewfio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_ewf_open (grub_file_t io, enum grub_file_type type)
{
	grub_uint8_t signature[8];
	struct ewf_image *image;
	grub_ewf_t ewfio;
	grub_file_t file;
	grub_err_t err;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK)
		|| io->size == GRUB_FILE_SIZE_UNKNOWN || io->size < sizeof (signature))
		return io;
	if (ewf_pread (io, 0, signature, sizeof (signature)) != GRUB_ERR_NONE)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}
	if (grub_memcmp (signature, "ADCRYPT", sizeof (signature)) == 0)
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "encrypted ADCRYPT images are not supported");
		return NULL;
	}
	if (grub_memcmp (signature, ewf2_signature, sizeof (signature)) == 0)
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "EWF2-Ex01 images are not supported");
		return NULL;
	}
	if (grub_memcmp (signature, ewf_logical_signature,
			 sizeof (signature)) == 0)
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "logical EWF-L01 images are not disk images");
		return NULL;
	}
	if (grub_memcmp (signature, ewf_signature, sizeof (signature)) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return NULL;
	err = ewf_open_image (image, io);
	if (err)
	{
		ewf_free_image (image);
		return NULL;
	}

	file = grub_zalloc (sizeof (*file));
	ewfio = grub_zalloc (sizeof (*ewfio));
	if (!file || !ewfio)
	{
		ewf_free_image (image);
		grub_free (file);
		grub_free (ewfio);
		return NULL;
	}
	ewfio->file = io;
	ewfio->image = image;
	file->device = io->device;
	file->data = ewfio;
	file->fs = &grub_ewf_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;
	return file;
}

static grub_ssize_t
grub_ewf_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_ewf_t ewfio = file->data;
	grub_uint64_t read_offset = file->offset;
	grub_ssize_t total = 0;

	while (len > 0)
	{
		grub_size_t got = 0;
		grub_err_t err = ewf_read (ewfio->image, read_offset, buf, len, &got);

		if (err)
			return -1;
		if (!got)
		{
			grub_error (GRUB_ERR_FILE_READ_ERROR, "EWF read made no progress");
			return -1;
		}
		read_offset += got;
		buf += got;
		total += got;
		len -= got;
	}
	return total;
}

static struct grub_fs grub_ewf_fs =
{
	.name = "ewf",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_ewf_read,
	.fs_close = grub_ewf_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (ewf)
{
	grub_file_filter_register (GRUB_FILE_FILTER_EWF, grub_ewf_open);
}

GRUB_MOD_FINI (ewf)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_EWF);
}
