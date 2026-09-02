/* ewf.c - Expert Witness Compression Format disk image filter */
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
#include <grub/deflate.h>
#include <grub/crypto.h>
#include <grub/safemath.h>
#include <grub/hostfile.h>

#include <bzlib.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define EWF_FILE_HEADER_SIZE	13
#define EWF_SECTION_DESC_SIZE	76
#define EWF_TABLE_HEADER_SIZE	24
#define EWF_TABLE_FOOTER_SIZE	4
#define EWF_VOLUME_SIZE		1052
#define EWF_SMART_VOLUME_SIZE	94

#define EWF2_FILE_HEADER_SIZE	32
#define EWF2_SECTION_DESC_SIZE	64
#define EWF2_TABLE_HEADER_SIZE	32
#define EWF2_TABLE_ENTRY_SIZE	16
#define EWF2_TABLE_FOOTER_SIZE	16
#define EWF2_MAX_METADATA_SIZE	(1u << 20)

#define EWF_MAX_SEGMENTS	4096
#define EWF_MAX_GROUPS		(1u << 20)
#define EWF_MAX_CHUNKS		(16u << 20)
#define EWF_MAX_SECTIONS	(1u << 20)
#define EWF_MAX_CHUNK_SIZE	(64u << 20)
#define EWF_CACHE_NONE		0xffffffffu

#define EWF_COMPRESSED		0x80000000u
#define EWF_OFFSET_MASK		0x7fffffffu

#define EWF2_SECTION_DEVICE	1
#define EWF2_SECTION_CASE	2
#define EWF2_SECTION_SECTOR_DATA	3
#define EWF2_SECTION_SECTOR_TABLE 4
#define EWF2_SECTION_KEYS	11
#define EWF2_SECTION_NEXT	13
#define EWF2_SECTION_DONE	15

#define EWF2_DATA_MD5		0x00000001u
#define EWF2_DATA_ENCRYPTED	0x00000002u

#define EWF2_CHUNK_COMPRESSED	0x00000001u
#define EWF2_CHUNK_CHECKSUMED	0x00000002u
#define EWF2_CHUNK_PATTERN_FILL	0x00000004u

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

static const grub_uint8_t ewf2_logical_signature[8] =
{
	'L', 'E', 'F', '2', 0x0d, 0x0a, 0x81, 0x00
};

struct ewf_segment
{
	grub_file_t file;
};

struct ewf2_entry
{
	grub_uint64_t offset;
	grub_uint32_t size;
	grub_uint32_t flags;
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
	struct ewf2_entry *entries2;
};

struct ewf2_section
{
	grub_uint32_t type;
	grub_uint32_t flags;
	grub_uint64_t data_offset;
	grub_uint64_t data_size;
	grub_uint32_t padding_size;
	grub_uint8_t integrity_hash[16];
};

struct ewf2_metadata
{
	grub_uint64_t sectors;
	grub_uint64_t chunks;
	grub_uint32_t sector_size;
	grub_uint32_t sectors_per_chunk;
	int device_seen;
	int case_seen;
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
	int version2;
	grub_uint16_t compression_method;

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
	{
		grub_free (image->groups[i].entries);
		grub_free (image->groups[i].entries2);
	}
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
	group->entries2 = NULL;
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

static char *
ewf2_segment_name (const char *name, grub_uint32_t number, int alternate_case)
{
	const char *slash;
	const char *dot;
	grub_size_t stem;
	char first;
	char second;
	char alpha;
	char ext[5];
	char *out;
	grub_uint32_t n;

	if (!name || number == 0)
		return NULL;
	slash = grub_strrchr (name, '/');
	dot = grub_strrchr (slash ? slash : name, '.');
	if (!dot || grub_strlen (dot + 1) != 4)
		return NULL;

	first = dot[1];
	second = dot[2];
	if ((first != 'E' && first != 'e')
		|| (second != 'X' && second != 'x'))
		return NULL;
	if (alternate_case)
	{
		first = (first >= 'A' && first <= 'Z')
			? (char) (first - 'A' + 'a') : (char) (first - 'a' + 'A');
		second = (second >= 'A' && second <= 'Z')
			? (char) (second - 'A' + 'a') : (char) (second - 'a' + 'A');
	}
	alpha = (first >= 'A' && first <= 'Z') ? 'A' : 'a';
	ext[0] = first;
	ext[1] = second;
	if (number <= 99)
	{
		ext[2] = (char) ('0' + number / 10);
		ext[3] = (char) ('0' + number % 10);
	}
	else
	{
		n = number - 100;
		if (n / (26 * 26) > 2)
			return NULL;
		ext[1] = (char) (second + n / (26 * 26));
		ext[2] = (char) (alpha + (n / 26) % 26);
		ext[3] = (char) (alpha + n % 26);
	}
	ext[4] = 0;

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
		char *path = image->version2
			? ewf2_segment_name (name, number, attempt != 0)
			: ewf_segment_name (name, number, attempt != 0);

		if (!path)
			return NULL;
		if (first->fs && grub_strcmp (first->fs->name, "winfile") == 0)
			file = grub_hostfile_open (path, GRUB_FILE_TYPE_LOOPBACK | GRUB_FILE_TYPE_NO_DECOMPRESS);
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
ewf2_check_file_header (struct ewf_image *image, grub_file_t file,
			grub_uint32_t expected_segment)
{
	grub_uint8_t header[EWF2_FILE_HEADER_SIZE];
	grub_uint16_t compression_method;
	grub_err_t err;

	err = ewf_pread (file, 0, header, sizeof (header));
	if (err)
		return err;
	if (grub_memcmp (header, ewf2_signature, sizeof (ewf2_signature)) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad EWF2 segment signature");
	compression_method = ewf_get16 (header + 10);
	if (header[8] != 2 || header[9] != 1
		|| ewf_get32 (header + 12) != expected_segment)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF2 segment header");
	if (compression_method != 1 && compression_method != 2)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
				   "unsupported EWF2 compression method %u",
				   compression_method);
	if (expected_segment == 1)
	{
		image->compression_method = compression_method;
		grub_memcpy (image->set_id, header + 16, sizeof (image->set_id));
		image->has_set_id = 1;
	}
	else if (compression_method != image->compression_method
		|| grub_memcmp (image->set_id, header + 16, sizeof (image->set_id)) != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "EWF2 segment belongs to another set");
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf2_add_section (struct ewf2_section **sections, grub_uint32_t *count,
		  const struct ewf2_section *section)
{
	struct ewf2_section *new_sections;
	grub_size_t size;

	if (*count >= EWF_MAX_SECTIONS
		|| grub_mul ((grub_size_t) *count + 1, sizeof (*new_sections), &size))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many EWF2 sections");
	new_sections = grub_realloc (*sections, size);
	if (!new_sections)
		return grub_errno;
	*sections = new_sections;
	new_sections[(*count)++] = *section;
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf2_check_section_md5 (grub_file_t file, const struct ewf2_section *section)
{
	const gcry_md_spec_t *md5 = GRUB_MD_MD5;
	grub_uint8_t *buffer = NULL;
	void *context = NULL;
	grub_uint64_t offset;
	grub_uint64_t remaining;
	grub_size_t size;
	grub_err_t err = GRUB_ERR_NONE;

	if (!(section->flags & EWF2_DATA_MD5))
		return GRUB_ERR_NONE;
	buffer = grub_malloc (65536);
	context = grub_malloc (md5->contextsize);
	if (!buffer || !context)
	{
		err = grub_errno;
		goto fail;
	}
	md5->init (context, 0);
	offset = section->data_offset;
	remaining = section->data_size;
	while (remaining > 0)
	{
		size = remaining > 65536 ? 65536 : (grub_size_t) remaining;
		err = ewf_pread (file, offset, buffer, size);
		if (err)
			goto fail;
		md5->write (context, buffer, size);
		offset += size;
		remaining -= size;
	}
	md5->final (context);
	if (grub_memcmp (md5->read (context), section->integrity_hash,
			 sizeof (section->integrity_hash)) != 0)
		err = grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF2 section integrity hash");

fail:
	grub_free (context);
	grub_free (buffer);
	return err;
}

static grub_err_t
ewf2_read_metadata (struct ewf_image *image, grub_file_t file,
		    const struct ewf2_section *section, char **text,
		    grub_size_t *text_size)
{
	grub_uint8_t *compressed = NULL;
	grub_uint8_t *plain = NULL;
	char *ascii = NULL;
	grub_size_t ascii_size;
	grub_ssize_t zlib_size;
	unsigned int bzip2_size;
	grub_size_t i;
	grub_size_t j;
	int result;
	grub_err_t err;

	*text = NULL;
	*text_size = 0;
	if (!section->data_size || section->data_size > EWF2_MAX_METADATA_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF2 metadata section size");
	err = ewf2_check_section_md5 (file, section);
	if (err)
		return err;
	compressed = grub_malloc ((grub_size_t) section->data_size);
	plain = grub_malloc (EWF2_MAX_METADATA_SIZE);
	if (!compressed || !plain)
	{
		err = grub_errno;
		goto fail;
	}
	err = ewf_pread (file, section->data_offset, compressed,
			 (grub_size_t) section->data_size);
	if (err)
		goto fail;
	if (image->compression_method == 1)
	{
		zlib_size = grub_zlib_decompress ((char *) compressed,
						 (grub_size_t) section->data_size, 0,
						 (char *) plain, EWF2_MAX_METADATA_SIZE);
		if (zlib_size <= 0)
		{
			err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					 "corrupt EWF2 metadata");
			goto fail;
		}
		ascii_size = (grub_size_t) zlib_size;
	}
	else
	{
		bzip2_size = EWF2_MAX_METADATA_SIZE;
		result = BZ2_bzBuffToBuffDecompress ((char *) plain, &bzip2_size,
						     (char *) compressed,
						     (unsigned int) section->data_size,
						     0, 0);
		if (result != BZ_OK || bzip2_size == 0)
		{
			err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					 "corrupt bzip2 metadata in EWF2 image");
			goto fail;
		}
		ascii_size = bzip2_size;
	}

	if (ascii_size >= 2 && plain[0] == 0xff && plain[1] == 0xfe)
	{
		ascii = grub_malloc ((ascii_size - 2) / 2 + 1);
		if (!ascii)
		{
			err = grub_errno;
			goto fail;
		}
		for (i = 2, j = 0; i + 1 < ascii_size; i += 2)
		{
			grub_uint16_t character = ewf_get16 (plain + i);

			if (character == 0)
				break;
			ascii[j++] = character <= 0x7f ? (char) character : '?';
		}
		ascii[j] = 0;
		ascii_size = j;
	}
	else
	{
		ascii = grub_malloc (ascii_size + 1);
		if (!ascii)
		{
			err = grub_errno;
			goto fail;
		}
		grub_memcpy (ascii, plain, ascii_size);
		ascii[ascii_size] = 0;
	}
	*text = ascii;
	*text_size = ascii_size;
	grub_free (plain);
	grub_free (compressed);
	return GRUB_ERR_NONE;

fail:
	grub_free (ascii);
	grub_free (plain);
	grub_free (compressed);
	return err;
}

static int
ewf2_get_line (const char *text, grub_size_t text_size, unsigned number,
	       const char **line, grub_size_t *line_size)
{
	grub_size_t start = 0;
	grub_size_t end;
	unsigned current = 0;

	while (start <= text_size)
	{
		end = start;
		while (end < text_size && text[end] != '\n')
			end++;
		if (current == number)
		{
			if (end > start && text[end - 1] == '\r')
				end--;
			*line = text + start;
			*line_size = end - start;
			return 1;
		}
		if (end == text_size)
			break;
		start = end + 1;
		current++;
	}
	return 0;
}

static int
ewf2_find_field (const char *text, grub_size_t text_size, const char *name,
		 const char **value, grub_size_t *value_size)
{
	const char *tags;
	const char *values;
	grub_size_t tags_size;
	grub_size_t values_size;
	grub_size_t name_size = grub_strlen (name);
	grub_size_t start;
	grub_size_t end;
	grub_size_t value_start;
	grub_size_t value_end;
	unsigned column = 0;
	unsigned value_column;

	if (!ewf2_get_line (text, text_size, 2, &tags, &tags_size)
		|| !ewf2_get_line (text, text_size, 3, &values, &values_size))
		return 0;
	for (start = 0; start <= tags_size; start = end + 1, column++)
	{
		end = start;
		while (end < tags_size && tags[end] != '\t')
			end++;
		if (end - start == name_size
			&& grub_memcmp (tags + start, name, name_size) == 0)
		{
			value_start = 0;
			for (value_column = 0; value_column < column; value_column++)
			{
				while (value_start < values_size && values[value_start] != '\t')
					value_start++;
				if (value_start == values_size)
					return 0;
				value_start++;
			}
			value_end = value_start;
			while (value_end < values_size && values[value_end] != '\t')
				value_end++;
			*value = values + value_start;
			*value_size = value_end - value_start;
			return 1;
		}
		if (end == tags_size)
			break;
	}
	return 0;
}

static int
ewf2_parse_uint64 (const char *text, grub_size_t size, grub_uint64_t *value)
{
	grub_uint64_t result = 0;
	grub_size_t i;

	if (!size)
		return 0;
	for (i = 0; i < size; i++)
	{
		grub_uint64_t digit;

		if (text[i] < '0' || text[i] > '9')
			return 0;
		digit = (grub_uint64_t) (text[i] - '0');
		if (result > (~(grub_uint64_t) 0 - digit) / 10)
			return 0;
		result = result * 10 + digit;
	}
	*value = result;
	return 1;
}

static grub_err_t
ewf2_parse_device_metadata (struct ewf2_metadata *metadata, const char *text,
			    grub_size_t text_size)
{
	const char *value;
	grub_size_t value_size;
	grub_uint64_t number;

	if (!ewf2_find_field (text, text_size, "ts", &value, &value_size)
		|| !ewf2_parse_uint64 (value, value_size, &metadata->sectors)
		|| !ewf2_find_field (text, text_size, "bp", &value, &value_size)
		|| !ewf2_parse_uint64 (value, value_size, &number)
		|| number > 0xffffffffu)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF2 device metadata");
	metadata->sector_size = (grub_uint32_t) number;
	metadata->device_seen = 1;
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf2_parse_case_metadata (struct ewf_image *image,
			  struct ewf2_metadata *metadata, const char *text,
			  grub_size_t text_size)
{
	const char *value;
	grub_size_t value_size;
	grub_uint64_t number;

	if (!ewf2_find_field (text, text_size, "tb", &value, &value_size)
		|| !ewf2_parse_uint64 (value, value_size, &metadata->chunks)
		|| !ewf2_find_field (text, text_size, "sb", &value, &value_size)
		|| !ewf2_parse_uint64 (value, value_size, &number)
		|| number > 0xffffffffu)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF2 case metadata");
	metadata->sectors_per_chunk = (grub_uint32_t) number;
	if (ewf2_find_field (text, text_size, "cp", &value, &value_size)
		&& value_size != 0)
	{
		if (!ewf2_parse_uint64 (value, value_size, &number)
			|| number != image->compression_method)
			return grub_error (GRUB_ERR_BAD_DEVICE,
					   "inconsistent EWF2 compression metadata");
	}
	metadata->case_seen = 1;
	return GRUB_ERR_NONE;
}

static grub_err_t
ewf2_apply_metadata (struct ewf_image *image,
		     const struct ewf2_metadata *metadata)
{
	grub_uint64_t chunk_size;
	grub_uint64_t total;
	grub_uint64_t expected_chunks;

	if (!metadata->device_seen || !metadata->case_seen)
		return grub_error (GRUB_ERR_BAD_DEVICE, "missing EWF2 media metadata");
	if (!metadata->chunks || metadata->chunks > EWF_MAX_CHUNKS
		|| !metadata->sectors || !metadata->sector_size
		|| !metadata->sectors_per_chunk
		|| !ewf_power_of_two (metadata->sector_size)
		|| metadata->sector_size < 128 || metadata->sector_size > 65536
		|| grub_mul ((grub_uint64_t) metadata->sectors_per_chunk,
			     metadata->sector_size, &chunk_size)
		|| !chunk_size || chunk_size > EWF_MAX_CHUNK_SIZE
		|| grub_mul (metadata->sectors, metadata->sector_size, &total)
		|| !total)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad EWF2 media geometry");
	expected_chunks = total / chunk_size + (total % chunk_size != 0);
	if (expected_chunks != metadata->chunks)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "inconsistent EWF2 chunk count");
	if (!image->volume_seen)
	{
		image->nchunks = (grub_uint32_t) metadata->chunks;
		image->sector_size = metadata->sector_size;
		image->chunk_size = (grub_uint32_t) chunk_size;
		image->total_bytes = total;
		image->volume_seen = 1;
	}
	else if (image->nchunks != metadata->chunks
		|| image->sector_size != metadata->sector_size
		|| image->chunk_size != chunk_size || image->total_bytes != total)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "inconsistent EWF2 segment geometry");
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

static grub_err_t
ewf2_parse_table (struct ewf_image *image, grub_file_t file,
		  grub_uint32_t segment, const struct ewf2_section *section,
		  grub_uint64_t data_start, grub_uint64_t data_end)
{
	grub_uint8_t header[EWF2_TABLE_HEADER_SIZE];
	grub_uint8_t footer[EWF2_TABLE_FOOTER_SIZE];
	struct ewf_group group = { 0 };
	grub_uint64_t first_chunk;
	grub_uint64_t entries_bytes;
	grub_uint64_t expected_size;
	grub_uint64_t entries_offset;
	grub_uint64_t footer_offset;
	grub_uint64_t max_stored;
	grub_size_t allocation_size;
	grub_uint32_t count;
	grub_uint32_t i;
	grub_err_t err;

	if (!image->volume_seen)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "EWF2 table precedes media metadata");
	if (section->data_size < EWF2_TABLE_HEADER_SIZE + EWF2_TABLE_FOOTER_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "short EWF2 sector table");
	err = ewf2_check_section_md5 (file, section);
	if (err)
		return err;
	err = ewf_pread (file, section->data_offset, header, sizeof (header));
	if (err)
		return err;
	if (ewf_get32 (header + 16) != ewf_adler32 (header, 16))
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "bad EWF2 table header checksum");
	first_chunk = ewf_get64 (header);
	count = ewf_get32 (header + 8);
	if (!count || count > EWF_MAX_CHUNKS
		|| first_chunk != image->indexed_chunks
		|| count > image->nchunks - image->indexed_chunks)
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "bad EWF2 table chunk range");
	entries_bytes = (grub_uint64_t) count * EWF2_TABLE_ENTRY_SIZE;
	expected_size = EWF2_TABLE_HEADER_SIZE + entries_bytes
		+ EWF2_TABLE_FOOTER_SIZE;
	if (section->data_size != expected_size
		|| grub_mul ((grub_size_t) count, sizeof (*group.entries2),
			     &allocation_size))
		return grub_error (GRUB_ERR_BAD_DEVICE,
				   "invalid EWF2 sector table size");
	group.entries2 = grub_malloc (allocation_size);
	if (!group.entries2)
		return grub_errno;
	if (grub_add (section->data_offset, EWF2_TABLE_HEADER_SIZE,
		      &entries_offset)
		|| grub_add (entries_offset, entries_bytes, &footer_offset))
	{
		err = grub_error (GRUB_ERR_OUT_OF_RANGE,
				  "EWF2 table offset overflow");
		goto fail;
	}
	err = ewf_pread (file, entries_offset, group.entries2, allocation_size);
	if (err)
		goto fail;
	err = ewf_pread (file, footer_offset, footer, sizeof (footer));
	if (err)
		goto fail;
	if (ewf_get32 (footer) != ewf_adler32 (group.entries2, allocation_size))
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE,
				  "bad EWF2 table entries checksum");
		goto fail;
	}

	group.first_chunk = (grub_uint32_t) first_chunk;
	group.count = count;
	group.segment = segment;
	max_stored = (grub_uint64_t) image->chunk_size
		+ image->chunk_size / 100 + 65536;
	for (i = 0; i < count; i++)
	{
		struct ewf2_entry *entry = &group.entries2[i];

		entry->offset = grub_le_to_cpu64 (entry->offset);
		entry->size = grub_le_to_cpu32 (entry->size);
		entry->flags = grub_le_to_cpu32 (entry->flags);
		if (entry->flags & ~(EWF2_CHUNK_COMPRESSED
				     | EWF2_CHUNK_CHECKSUMED
				     | EWF2_CHUNK_PATTERN_FILL))
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "unsupported EWF2 chunk flags");
			goto fail;
		}
		if (entry->flags & EWF2_CHUNK_PATTERN_FILL)
		{
			if ((entry->flags & (EWF2_CHUNK_COMPRESSED
					 | EWF2_CHUNK_CHECKSUMED))
				!= EWF2_CHUNK_COMPRESSED
				|| (entry->size != 0 && entry->size != 8))
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "invalid EWF2 pattern-fill chunk");
				goto fail;
			}
			continue;
		}
		if (entry->flags & EWF2_CHUNK_COMPRESSED)
		{
			if ((entry->flags & EWF2_CHUNK_CHECKSUMED)
				|| !entry->size || entry->size > max_stored)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "invalid compressed EWF2 chunk");
				goto fail;
			}
			if (entry->size > image->comp_capacity)
				image->comp_capacity = entry->size;
		}
		else if (!(entry->flags & EWF2_CHUNK_CHECKSUMED)
			|| entry->size < 4 || entry->size > image->chunk_size + 4)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "invalid uncompressed EWF2 chunk");
			goto fail;
		}
		if (entry->offset < data_start || entry->offset > data_end
			|| entry->size > data_end - entry->offset)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "EWF2 chunk outside sector data section");
			goto fail;
		}
	}
	err = ewf_add_group (image, &group);
	if (err)
		goto fail;
	image->indexed_chunks += count;
	return GRUB_ERR_NONE;

fail:
	grub_free (group.entries2);
	return err;
}

static grub_err_t
ewf2_scan_segment (struct ewf_image *image, grub_uint32_t segment,
		   int *has_next)
{
	grub_file_t file = image->segments[segment].file;
	grub_uint64_t file_size = grub_file_size (file);
	struct ewf2_section *sections = NULL;
	struct ewf2_metadata metadata = { 0 };
	grub_uint32_t nsections = 0;
	grub_uint32_t i;
	grub_uint64_t descriptor_offset;
	grub_uint64_t previous_offset;
	grub_uint64_t data_offset;
	grub_uint64_t sector_data_start = 0;
	grub_uint64_t sector_data_end = 0;
	grub_uint8_t descriptor[EWF2_SECTION_DESC_SIZE];
	char *text = NULL;
	grub_size_t text_size;
	int chain_complete = 0;
	int geometry_applied = 0;
	grub_err_t err;

	*has_next = 0;
	err = ewf2_check_file_header (image, file, segment + 1);
	if (err)
		return err;
	if (file_size == GRUB_FILE_SIZE_UNKNOWN
		|| file_size < EWF2_FILE_HEADER_SIZE + EWF2_SECTION_DESC_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "short EWF2 segment");
	descriptor_offset = file_size - EWF2_SECTION_DESC_SIZE;
	for (i = 0; i < EWF_MAX_SECTIONS; i++)
	{
		struct ewf2_section section = { 0 };

		err = ewf_pread (file, descriptor_offset, descriptor,
				 sizeof (descriptor));
		if (err)
			goto fail;
		if (ewf_get32 (descriptor + 60) != ewf_adler32 (descriptor, 60))
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "bad EWF2 section descriptor checksum");
			goto fail;
		}
		section.type = ewf_get32 (descriptor);
		section.flags = ewf_get32 (descriptor + 4);
		previous_offset = ewf_get64 (descriptor + 8);
		section.data_size = ewf_get64 (descriptor + 16);
		section.padding_size = ewf_get32 (descriptor + 28);
		grub_memcpy (section.integrity_hash, descriptor + 32,
			     sizeof (section.integrity_hash));
		if (ewf_get32 (descriptor + 24) != EWF2_SECTION_DESC_SIZE
			|| (section.flags & ~(EWF2_DATA_MD5 | EWF2_DATA_ENCRYPTED)))
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "invalid EWF2 section descriptor");
			goto fail;
		}
		if ((section.flags & EWF2_DATA_ENCRYPTED)
			|| section.type == EWF2_SECTION_KEYS)
		{
			err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
					  "encrypted EWF2 images are not supported");
			goto fail;
		}
		if (previous_offset == 0)
			data_offset = EWF2_FILE_HEADER_SIZE;
		else
		{
			if (previous_offset < EWF2_FILE_HEADER_SIZE
				|| previous_offset >= descriptor_offset
				|| grub_add (previous_offset, EWF2_SECTION_DESC_SIZE,
					     &data_offset)
				|| data_offset > descriptor_offset)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "invalid EWF2 section chain");
				goto fail;
			}
		}
		if (section.data_size > descriptor_offset - data_offset
			|| section.padding_size > section.data_size)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "invalid EWF2 section layout");
			goto fail;
		}
		section.data_offset = data_offset;
		err = ewf2_add_section (&sections, &nsections, &section);
		if (err)
			goto fail;
		if (nsections == 1
			&& section.type != EWF2_SECTION_NEXT
			&& section.type != EWF2_SECTION_DONE)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE,
					  "missing EWF2 end section");
			goto fail;
		}
		if (previous_offset == 0)
		{
			chain_complete = 1;
			break;
		}
		descriptor_offset = previous_offset;
	}
	if (!chain_complete)
	{
		err = grub_error (GRUB_ERR_OUT_OF_RANGE, "too many EWF2 sections");
		goto fail;
	}
	*has_next = sections[0].type == EWF2_SECTION_NEXT;
	if (sections[0].data_size != 0)
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE, "invalid EWF2 end section");
		goto fail;
	}

	for (i = nsections; i > 0; i--)
	{
		struct ewf2_section *section = &sections[i - 1];

		switch (section->type)
		{
		case EWF2_SECTION_DEVICE:
			if (metadata.device_seen)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "duplicate EWF2 device metadata");
				goto fail;
			}
			err = ewf2_read_metadata (image, file, section, &text,
						  &text_size);
			if (err)
				goto fail;
			err = ewf2_parse_device_metadata (&metadata, text, text_size);
			grub_free (text);
			text = NULL;
			if (err)
				goto fail;
			break;

		case EWF2_SECTION_CASE:
			if (metadata.case_seen)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "duplicate EWF2 case metadata");
				goto fail;
			}
			err = ewf2_read_metadata (image, file, section, &text,
						  &text_size);
			if (err)
				goto fail;
			err = ewf2_parse_case_metadata (image, &metadata, text,
						       text_size);
			grub_free (text);
			text = NULL;
			if (err)
				goto fail;
			break;

		case EWF2_SECTION_SECTOR_DATA:
			if (!geometry_applied)
			{
				err = ewf2_apply_metadata (image, &metadata);
				if (err)
					goto fail;
				geometry_applied = 1;
			}
			if (sector_data_start || !section->data_size
				|| grub_add (section->data_offset, section->data_size,
					     &sector_data_end))
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "invalid EWF2 sector data section");
				goto fail;
			}
			sector_data_start = section->data_offset;
			break;

		case EWF2_SECTION_SECTOR_TABLE:
			if (!geometry_applied)
			{
				err = ewf2_apply_metadata (image, &metadata);
				if (err)
					goto fail;
				geometry_applied = 1;
			}
			if (!sector_data_start)
			{
				err = grub_error (GRUB_ERR_BAD_DEVICE,
						  "EWF2 table without sector data");
				goto fail;
			}
			err = ewf2_parse_table (image, file, segment, section,
						sector_data_start, sector_data_end);
			if (err)
				goto fail;
			sector_data_start = 0;
			sector_data_end = 0;
			break;
		}
	}
	if (!geometry_applied)
	{
		err = ewf2_apply_metadata (image, &metadata);
		if (err)
			goto fail;
	}
	if (sector_data_start)
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE,
				  "EWF2 sector data without a table");
		goto fail;
	}
	grub_free (sections);
	return GRUB_ERR_NONE;

fail:
	grub_free (text);
	grub_free (sections);
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
		err = image->version2
			? ewf2_scan_segment (image, segment, &has_next)
			: ewf_scan_segment (image, segment, &has_next);
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
	if (image->comp_capacity)
		image->comp_buf = grub_malloc (image->comp_capacity);
	if (!image->chunk_buf || (image->comp_capacity && !image->comp_buf))
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
	grub_file_t *file, grub_uint64_t *off, grub_uint32_t *stored_size,
	int *compressed, int *checksummed, int *pattern_fill,
	grub_uint64_t *pattern)
{
	struct ewf_group *group = ewf_find_group (image, chunk);
	struct ewf2_entry *entry;
	grub_uint32_t index;
	grub_uint32_t current;
	grub_uint32_t next;
	grub_uint64_t phys;
	grub_uint64_t size;

	if (!group)
		return grub_error (GRUB_ERR_BAD_DEVICE, "missing EWF chunk table");
	index = chunk - group->first_chunk;
	if (group->entries2)
	{
		entry = &group->entries2[index];
		*compressed = (entry->flags & EWF2_CHUNK_COMPRESSED) != 0;
		*checksummed = (entry->flags & EWF2_CHUNK_CHECKSUMED) != 0;
		*pattern_fill = (entry->flags & EWF2_CHUNK_PATTERN_FILL) != 0;
		*pattern = entry->offset;
		*file = image->segments[group->segment].file;
		*off = entry->offset;
		*stored_size = entry->size;
		return GRUB_ERR_NONE;
	}
	current = group->entries[index];
	*compressed = index < group->overflow_at
		&& (current & EWF_COMPRESSED) != 0;
	*checksummed = !*compressed;
	*pattern_fill = 0;
	*pattern = 0;
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
	grub_uint64_t pattern;
	grub_uint32_t i;
	unsigned int bzip2_size;
	int bzip2_result;
	int compressed;
	int checksummed;
	int pattern_fill;
	grub_err_t err;

	if (image->cached_chunk == chunk)
		return GRUB_ERR_NONE;
	image->cached_chunk = EWF_CACHE_NONE;
	err = ewf_chunk_location (image, chunk, &file, &off, &stored_size,
				  &compressed, &checksummed, &pattern_fill,
				  &pattern);
	if (err)
		return err;
	logical = (grub_uint64_t) chunk * image->chunk_size;
	expected = image->chunk_size;
	if (expected > image->total_bytes - logical)
		expected = (grub_uint32_t) (image->total_bytes - logical);

	if (pattern_fill)
	{
		for (i = 0; i < image->chunk_size; i++)
			image->chunk_buf[i] = (grub_uint8_t)
				(pattern >> ((i & 7) * 8));
	}
	else if (compressed)
	{
		err = ewf_pread (file, off, image->comp_buf, stored_size);
		if (err)
			return err;
		if (!image->version2 || image->compression_method == 1)
		{
			out_size = grub_zlib_decompress ((char *) image->comp_buf,
						 stored_size, 0,
						 (char *) image->chunk_buf,
						 image->chunk_size);
			if (out_size < 0 || (grub_uint32_t) out_size < expected
				|| (grub_uint32_t) out_size > image->chunk_size)
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
						   "corrupt zlib chunk in EWF image");
		}
		else
		{
			bzip2_size = image->chunk_size;
			bzip2_result = BZ2_bzBuffToBuffDecompress (
				(char *) image->chunk_buf, &bzip2_size,
				(char *) image->comp_buf, stored_size, 0, 0);
			if (bzip2_result != BZ_OK || bzip2_size < expected
				|| bzip2_size > image->chunk_size)
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
						   "corrupt bzip2 chunk in EWF2 image");
		}
	}
	else
	{
		if (!checksummed || stored_size < 4)
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
	if (grub_memcmp (signature, ewf_logical_signature,
			 sizeof (signature)) == 0
		|| grub_memcmp (signature, ewf2_logical_signature,
			       sizeof (signature)) == 0)
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			    "logical EWF-L01/Lx01 images are not disk images");
		return NULL;
	}
	if (grub_memcmp (signature, ewf_signature, sizeof (signature)) != 0
		&& grub_memcmp (signature, ewf2_signature, sizeof (signature)) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return NULL;
	image->version2 = grub_memcmp (signature, ewf2_signature,
				       sizeof (signature)) == 0;
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
