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

/*
 * Present an SQLite 3 database as a small read-only virtual filesystem.
 * Schema objects are grouped by kind and table records are JSON files.
 * This intentionally parses the documented file format directly: linking
 * the SQLite execution engine into grub.lib would add a large writable SQL
 * runtime where only deterministic, read-only browsing is required.
 */

#include <grub/types.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/safemath.h>

#include <stdio.h> /* snprintf: GRUB's formatter has no floating-point support. */

GRUB_MOD_LICENSE ("GPLv3+");

#define SQLITEFS_HEADER_SIZE	100
#define SQLITEFS_HEADER_MAGIC_SIZE	16
#define SQLITEFS_HEADER_PAGE_SIZE	16
#define SQLITEFS_HEADER_WRITE_VERSION	18
#define SQLITEFS_HEADER_READ_VERSION	19
#define SQLITEFS_HEADER_RESERVED_BYTES	20
#define SQLITEFS_HEADER_MAX_PAYLOAD	21
#define SQLITEFS_HEADER_MIN_PAYLOAD	22
#define SQLITEFS_HEADER_LEAF_PAYLOAD	23
#define SQLITEFS_HEADER_CHANGE_COUNTER	24
#define SQLITEFS_HEADER_DATABASE_PAGES	28
#define SQLITEFS_HEADER_SCHEMA_FORMAT	44
#define SQLITEFS_HEADER_ENCODING	56
#define SQLITEFS_HEADER_USER_VERSION	60
#define SQLITEFS_HEADER_APPLICATION_ID	68
#define SQLITEFS_HEADER_VERSION_VALID_FOR	92
#define SQLITEFS_HEADER_SQLITE_VERSION	96

#define SQLITEFS_PAGE_SIZE_ENCODED_64K	1
#define SQLITEFS_PAGE_SIZE_MIN	512
#define SQLITEFS_PAGE_SIZE_MAX	65536
#define SQLITEFS_USABLE_SIZE_MIN	480
#define SQLITEFS_FILE_FORMAT_LEGACY	1
#define SQLITEFS_FILE_FORMAT_WAL	2
#define SQLITEFS_PAYLOAD_FRACTION_MAX	64
#define SQLITEFS_PAYLOAD_FRACTION_MIN	32
#define SQLITEFS_PAYLOAD_FRACTION_LEAF	32
#define SQLITEFS_PAYLOAD_FRACTION_DENOMINATOR	255
#define SQLITEFS_SCHEMA_FORMAT_MIN	1
#define SQLITEFS_SCHEMA_FORMAT_MAX	4
#define SQLITEFS_ENCODING_UTF8	1
#define SQLITEFS_ENCODING_UTF16BE	3
#define SQLITEFS_DATABASE_PAGE_MAX	0xfffffffeULL

#define SQLITEFS_PAYLOAD_FRACTION_BASE	12
#define SQLITEFS_PAYLOAD_FRACTION_ADJUSTMENT	23
#define SQLITEFS_TABLE_LEAF_PAYLOAD_ADJUSTMENT	35
#define SQLITEFS_OVERFLOW_NEXT_SIZE	4
#define SQLITEFS_BTREE_DEPTH_MAX	64
#define SQLITEFS_PATH_PARTS_MAX	4

#define SQLITEFS_PAGE_INDEX_INTERIOR	0x02
#define SQLITEFS_PAGE_TABLE_INTERIOR	0x05
#define SQLITEFS_PAGE_INDEX_LEAF		0x0a
#define SQLITEFS_PAGE_TABLE_LEAF		0x0d

enum sqlitefs_object_type
{
	SQLITEFS_OBJECT_TABLE,
	SQLITEFS_OBJECT_INDEX,
	SQLITEFS_OBJECT_VIEW,
	SQLITEFS_OBJECT_TRIGGER
};

struct sqlitefs_data
{
	grub_disk_t disk;
	grub_uint32_t page_size;
	grub_uint32_t usable_size;
	grub_uint32_t pages;
	grub_uint32_t encoding;
	grub_uint32_t schema_format;
	grub_uint32_t user_version;
	grub_uint32_t application_id;
	grub_uint32_t sqlite_version;
};

struct sqlitefs_object
{
	enum sqlitefs_object_type type;
	char *name;
	char *path_name;
	char *table_name;
	char *sql;
	grub_uint32_t root_page;
};

struct sqlitefs_schema
{
	struct sqlitefs_object *objects;
	grub_size_t count;
	grub_size_t capacity;
};

struct sqlitefs_buf
{
	char *data;
	grub_size_t len;
	grub_size_t capacity;
};

struct sqlitefs_path
{
	const char *part[SQLITEFS_PATH_PARTS_MAX];
	grub_size_t len[SQLITEFS_PATH_PARTS_MAX];
	grub_size_t count;
};

struct sqlitefs_value
{
	grub_uint64_t serial;
	const grub_uint8_t *data;
	grub_size_t size;
};

struct sqlitefs_cell
{
	grub_uint8_t page_type;
	grub_uint32_t page;
	grub_uint16_t cell;
	grub_int64_t rowid;
	grub_uint8_t *payload;
	grub_size_t payload_size;
};

typedef int (*sqlitefs_cell_hook_t) (const struct sqlitefs_cell *cell,
	void *hook_data);

struct sqlitefs_walk
{
	struct sqlitefs_data *data;
	sqlitefs_cell_hook_t hook;
	void *hook_data;
	grub_uint32_t pages_seen;
	int family;	/* 1 = table b-tree, 2 = index b-tree */
	int stopped;
};

struct sqlitefs_file
{
	char *data;
};

static grub_uint16_t
sqlitefs_be16 (const grub_uint8_t *p)
{
	return grub_be_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
sqlitefs_be32 (const grub_uint8_t *p)
{
	return grub_be_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
sqlitefs_be64 (const grub_uint8_t *p)
{
	return grub_be_to_cpu64 (grub_get_unaligned64 (p));
}

static void
sqlitefs_i64_string (char *out, grub_size_t size, grub_int64_t value)
{
	char reversed[24];
	grub_uint64_t magnitude;
	grub_size_t i = 0;
	grub_size_t n = 0;

	if (!size)
		return;
	if (value < 0)
	{
		out[n++] = '-';
		magnitude = (grub_uint64_t) (-(value + 1)) + 1;
	}
	else
		magnitude = (grub_uint64_t) value;
	do
	{
		reversed[i++] = (char) ('0' + magnitude % 10);
		magnitude /= 10;
	}
	while (magnitude);
	while (i && n + 1 < size)
		out[n++] = reversed[--i];
	out[n] = '\0';
}

static int
sqlitefs_buf_reserve (struct sqlitefs_buf *buf, grub_size_t extra)
{
	grub_size_t need;
	grub_size_t capacity;
	char *p;

	if (grub_add (buf->len, extra, &need) || grub_add (need, 1, &need))
		goto overflow;
	if (need <= buf->capacity)
		return 0;

	capacity = buf->capacity ? buf->capacity : 256;
	while (capacity < need)
	{
		grub_size_t grown;

		if (grub_add (capacity, capacity / 2 + 64, &grown))
		{
			capacity = need;
			break;
		}
		capacity = grown;
	}
	p = grub_realloc (buf->data, capacity);
	if (!p)
		return -1;
	buf->data = p;
	buf->capacity = capacity;
	return 0;

overflow:
	grub_error (GRUB_ERR_OUT_OF_MEMORY, "SQLite output is too large");
	return -1;
}

static int
sqlitefs_buf_append (struct sqlitefs_buf *buf, const void *data,
	grub_size_t size)
{
	if (sqlitefs_buf_reserve (buf, size) != 0)
		return -1;
	if (size)
		grub_memcpy (buf->data + buf->len, data, size);
	buf->len += size;
	buf->data[buf->len] = '\0';
	return 0;
}

static int
sqlitefs_buf_string (struct sqlitefs_buf *buf, const char *s)
{
	return sqlitefs_buf_append (buf, s, grub_strlen (s));
}

static int
sqlitefs_buf_char (struct sqlitefs_buf *buf, char c)
{
	return sqlitefs_buf_append (buf, &c, 1);
}

static char *
sqlitefs_buf_finish (struct sqlitefs_buf *buf, grub_size_t *size)
{
	if (!buf->data)
	{
		buf->data = grub_zalloc (1);
		if (!buf->data)
			return NULL;
		buf->capacity = 1;
	}
	*size = buf->len;
	return buf->data;
}

static grub_err_t
sqlitefs_bad (const char *message)
{
	return grub_error (GRUB_ERR_BAD_FS, "%s", message);
}

static int
sqlitefs_read_varint (const grub_uint8_t *p, grub_size_t available,
	grub_uint64_t *value, grub_size_t *used)
{
	grub_uint64_t v = 0;
	grub_size_t i;

	for (i = 0; i < 8 && i < available; i++)
	{
		v = (v << 7) | (p[i] & 0x7f);
		if (!(p[i] & 0x80))
		{
			*value = v;
			*used = i + 1;
			return 0;
		}
	}
	if (available >= 9)
	{
		*value = (v << 8) | p[8];
		*used = 9;
		return 0;
	}
	return -1;
}

static int
sqlitefs_utf8_char (struct sqlitefs_buf *buf, grub_uint32_t c)
{
	grub_uint8_t out[4];
	grub_size_t size;

	if (c <= 0x7f)
	{
		out[0] = (grub_uint8_t) c;
		size = 1;
	}
	else if (c <= 0x7ff)
	{
		out[0] = 0xc0 | (c >> 6);
		out[1] = 0x80 | (c & 0x3f);
		size = 2;
	}
	else if (c <= 0xffff)
	{
		out[0] = 0xe0 | (c >> 12);
		out[1] = 0x80 | ((c >> 6) & 0x3f);
		out[2] = 0x80 | (c & 0x3f);
		size = 3;
	}
	else
	{
		out[0] = 0xf0 | (c >> 18);
		out[1] = 0x80 | ((c >> 12) & 0x3f);
		out[2] = 0x80 | ((c >> 6) & 0x3f);
		out[3] = 0x80 | (c & 0x3f);
		size = 4;
	}
	return sqlitefs_buf_append (buf, out, size);
}

static char *
sqlitefs_text (struct sqlitefs_data *data, const grub_uint8_t *raw,
	grub_size_t size, grub_size_t *out_size)
{
	struct sqlitefs_buf out = { 0 };
	grub_size_t i;

	if (data->encoding == 1)
	{
		if (sqlitefs_buf_append (&out, raw, size) != 0)
			goto fail;
	}
	else
	{
		for (i = 0; i + 1 < size; i += 2)
		{
			grub_uint32_t c;

			if (data->encoding == 2)
				c = raw[i] | ((grub_uint32_t) raw[i + 1] << 8);
			else
				c = ((grub_uint32_t) raw[i] << 8) | raw[i + 1];
			if (c >= 0xd800 && c <= 0xdbff && i + 3 < size)
			{
				grub_uint32_t low;

				if (data->encoding == 2)
					low = raw[i + 2] | ((grub_uint32_t) raw[i + 3] << 8);
				else
					low = ((grub_uint32_t) raw[i + 2] << 8) | raw[i + 3];
				if (low >= 0xdc00 && low <= 0xdfff)
				{
					c = 0x10000 + ((c - 0xd800) << 10) + low - 0xdc00;
					i += 2;
				}
				else
					c = 0xfffd;
			}
			else if (c >= 0xd800 && c <= 0xdfff)
				c = 0xfffd;
			if (sqlitefs_utf8_char (&out, c) != 0)
				goto fail;
		}
		if (i != size && sqlitefs_utf8_char (&out, 0xfffd) != 0)
			goto fail;
	}
	return sqlitefs_buf_finish (&out, out_size);

fail:
	grub_free (out.data);
	return NULL;
}

static int
sqlitefs_reserved_name (const grub_uint8_t *name, grub_size_t size)
{
	char stem[5];
	grub_size_t i = 0;

	while (i < size && i < sizeof (stem) - 1 && name[i] != '.')
	{
		char c = (char) name[i++];

		if (c >= 'a' && c <= 'z')
			c -= 'a' - 'A';
		stem[i - 1] = c;
	}
	stem[i] = '\0';
	return grub_strcmp (stem, "CON") == 0 || grub_strcmp (stem, "PRN") == 0
		|| grub_strcmp (stem, "AUX") == 0 || grub_strcmp (stem, "NUL") == 0
		|| (i == 4 && stem[0] == 'C' && stem[1] == 'O'
			&& stem[2] == 'M' && stem[3] >= '1' && stem[3] <= '9')
		|| (i == 4 && stem[0] == 'L' && stem[1] == 'P'
			&& stem[2] == 'T' && stem[3] >= '1' && stem[3] <= '9');
}

static char *
sqlitefs_path_name (const char *name)
{
	static const char hex[] = "0123456789ABCDEF";
	const grub_uint8_t *raw = (const grub_uint8_t *) name;
	grub_size_t size = grub_strlen (name);
	struct sqlitefs_buf out = { 0 };
	grub_size_t i;
	int reserved = sqlitefs_reserved_name (raw, size);

	for (i = 0; i < size; i++)
	{
		grub_uint8_t c = raw[i];
		int escape = c < 0x20 || c == 0x7f || c == '%' || c == '/'
			|| c == '\\' || c == ':' || c == '*' || c == '?'
			|| c == '"' || c == '<' || c == '>' || c == '|'
			|| (i + 1 == size && (c == '.' || c == ' '))
			|| (i == 0 && reserved)
			|| (i == 0 && (grub_strcmp (name, ".") == 0
				|| grub_strcmp (name, "..") == 0));

		if (escape)
		{
			char escaped[3] = { '%', hex[c >> 4], hex[c & 0xf] };

			if (sqlitefs_buf_append (&out, escaped, sizeof (escaped)) != 0)
				goto fail;
		}
		else if (sqlitefs_buf_char (&out, (char) c) != 0)
			goto fail;
	}
	if (!size && sqlitefs_buf_string (&out, "%00") != 0)
		goto fail;
	return sqlitefs_buf_finish (&out, &size);

fail:
	grub_free (out.data);
	return NULL;
}

static struct sqlitefs_data *
sqlitefs_mount (grub_disk_t disk)
{
	static const char magic[SQLITEFS_HEADER_MAGIC_SIZE] = "SQLite format 3";
	grub_uint8_t header[SQLITEFS_HEADER_SIZE];
	grub_uint64_t sectors;
	grub_uint64_t bytes;
	grub_uint64_t actual_pages;
	grub_uint32_t header_pages;
	struct sqlitefs_data *data = NULL;

	if (grub_disk_read (disk, 0, 0, sizeof (header), header))
		goto fail;
	if (grub_memcmp (header, magic, sizeof (magic)) != 0)
		goto bad;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		goto fail;
	data->disk = disk;
	data->page_size = sqlitefs_be16 (header + SQLITEFS_HEADER_PAGE_SIZE);
	if (data->page_size == SQLITEFS_PAGE_SIZE_ENCODED_64K)
		data->page_size = SQLITEFS_PAGE_SIZE_MAX;
	if (data->page_size < SQLITEFS_PAGE_SIZE_MIN
		|| data->page_size > SQLITEFS_PAGE_SIZE_MAX
		|| (data->page_size & (data->page_size - 1)) != 0)
		goto bad;
	if ((header[SQLITEFS_HEADER_WRITE_VERSION] != SQLITEFS_FILE_FORMAT_LEGACY
			&& header[SQLITEFS_HEADER_WRITE_VERSION] != SQLITEFS_FILE_FORMAT_WAL)
		|| (header[SQLITEFS_HEADER_READ_VERSION] != SQLITEFS_FILE_FORMAT_LEGACY
			&& header[SQLITEFS_HEADER_READ_VERSION] != SQLITEFS_FILE_FORMAT_WAL)
		|| header[SQLITEFS_HEADER_MAX_PAYLOAD] != SQLITEFS_PAYLOAD_FRACTION_MAX
		|| header[SQLITEFS_HEADER_MIN_PAYLOAD] != SQLITEFS_PAYLOAD_FRACTION_MIN
		|| header[SQLITEFS_HEADER_LEAF_PAYLOAD] != SQLITEFS_PAYLOAD_FRACTION_LEAF)
		goto bad;
	data->usable_size = data->page_size - header[SQLITEFS_HEADER_RESERVED_BYTES];
	if (data->usable_size < SQLITEFS_USABLE_SIZE_MIN)
		goto bad;

	data->schema_format = sqlitefs_be32 (header + SQLITEFS_HEADER_SCHEMA_FORMAT);
	data->encoding = sqlitefs_be32 (header + SQLITEFS_HEADER_ENCODING);
	data->user_version = sqlitefs_be32 (header + SQLITEFS_HEADER_USER_VERSION);
	data->application_id = sqlitefs_be32 (header + SQLITEFS_HEADER_APPLICATION_ID);
	data->sqlite_version = sqlitefs_be32 (header + SQLITEFS_HEADER_SQLITE_VERSION);
	if (data->schema_format < SQLITEFS_SCHEMA_FORMAT_MIN
		|| data->schema_format > SQLITEFS_SCHEMA_FORMAT_MAX
		|| data->encoding < SQLITEFS_ENCODING_UTF8
		|| data->encoding > SQLITEFS_ENCODING_UTF16BE)
		goto bad;

	sectors = grub_disk_native_sectors (disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN || sectors > (~0ULL >> 9))
		goto bad;
	bytes = sectors << GRUB_DISK_SECTOR_BITS;
	actual_pages = bytes / data->page_size;
	if (!actual_pages || actual_pages > SQLITEFS_DATABASE_PAGE_MAX)
		goto bad;
	header_pages = sqlitefs_be32 (header + SQLITEFS_HEADER_DATABASE_PAGES);
	/* The header count is authoritative only when its validity marker
	   matches the change counter.  Older databases may leave it zero. */
	if (header_pages
		&& sqlitefs_be32 (header + SQLITEFS_HEADER_CHANGE_COUNTER)
		== sqlitefs_be32 (header + SQLITEFS_HEADER_VERSION_VALID_FOR))
	{
		if (header_pages > actual_pages)
			goto bad;
		data->pages = header_pages;
	}
	else
		data->pages = (grub_uint32_t) actual_pages;
	return data;

bad:
	grub_free (data);
	sqlitefs_bad ("not a valid SQLite 3 database");
fail:
	return NULL;
}

static grub_uint8_t *
sqlitefs_read_page (struct sqlitefs_data *data, grub_uint32_t page)
{
	grub_uint8_t *buf;
	grub_uint64_t offset;

	if (!page || page > data->pages)
	{
		sqlitefs_bad ("SQLite b-tree page is out of range");
		return NULL;
	}
	offset = (grub_uint64_t) (page - 1) * data->page_size;
	buf = grub_malloc (data->page_size);
	if (!buf)
		return NULL;
	if (grub_disk_read (data->disk, 0, offset, data->page_size, buf))
	{
		grub_free (buf);
		return NULL;
	}
	return buf;
}

static int
sqlitefs_local_payload (struct sqlitefs_data *data, grub_uint8_t page_type,
	grub_uint64_t payload, grub_size_t *local)
{
	grub_uint64_t maximum;
	grub_uint64_t minimum;
	grub_uint64_t candidate;

	maximum = (page_type == SQLITEFS_PAGE_TABLE_LEAF)
		? data->usable_size - SQLITEFS_TABLE_LEAF_PAYLOAD_ADJUSTMENT
		: ((grub_uint64_t) (data->usable_size - SQLITEFS_PAYLOAD_FRACTION_BASE)
			* SQLITEFS_PAYLOAD_FRACTION_MAX
			/ SQLITEFS_PAYLOAD_FRACTION_DENOMINATOR)
			- SQLITEFS_PAYLOAD_FRACTION_ADJUSTMENT;
	minimum = ((grub_uint64_t) (data->usable_size - SQLITEFS_PAYLOAD_FRACTION_BASE)
		* SQLITEFS_PAYLOAD_FRACTION_MIN
		/ SQLITEFS_PAYLOAD_FRACTION_DENOMINATOR)
		- SQLITEFS_PAYLOAD_FRACTION_ADJUSTMENT;
	if (payload <= maximum)
		candidate = payload;
	else
	{
		candidate = minimum + (payload - minimum)
			% (data->usable_size - SQLITEFS_OVERFLOW_NEXT_SIZE);
		if (candidate > maximum)
			candidate = minimum;
	}
	if (candidate > (grub_uint64_t) (grub_size_t) -1)
		return -1;
	*local = (grub_size_t) candidate;
	return 0;
}

static grub_uint8_t *
sqlitefs_payload (struct sqlitefs_data *data, const grub_uint8_t *page,
	grub_size_t cell_offset, grub_uint8_t page_type, grub_uint64_t payload_size,
	grub_size_t payload_offset, grub_size_t *out_size)
{
	grub_size_t local;
	grub_size_t size;
	grub_uint8_t *payload;
	grub_uint32_t overflow = 0;
	grub_size_t copied;
	grub_uint32_t links = 0;

	if (payload_size > (grub_uint64_t) (grub_size_t) -1
		|| sqlitefs_local_payload (data, page_type, payload_size, &local) != 0)
		goto bad;
	size = (grub_size_t) payload_size;
	if (cell_offset > data->usable_size || payload_offset > data->usable_size - cell_offset
		|| local > data->usable_size - cell_offset - payload_offset)
		goto bad;
	if (local != size)
	{
		grub_size_t next_offset = cell_offset + payload_offset + local;

		if (next_offset > data->usable_size
			|| data->usable_size - next_offset < sizeof (grub_uint32_t))
			goto bad;
		overflow = sqlitefs_be32 (page + next_offset);
	}
	payload = grub_malloc (size ? size : 1);
	if (!payload)
		return NULL;
	if (local)
		grub_memcpy (payload, page + cell_offset + payload_offset, local);
	copied = local;
	while (copied < size)
	{
		grub_size_t chunk = size - copied;
		grub_uint8_t next[4];
		grub_uint64_t page_offset;

		if (!overflow || overflow > data->pages || ++links > data->pages)
			goto bad_free;
		if (chunk > data->usable_size - SQLITEFS_OVERFLOW_NEXT_SIZE)
			chunk = data->usable_size - SQLITEFS_OVERFLOW_NEXT_SIZE;
		page_offset = (grub_uint64_t) (overflow - 1) * data->page_size;
		if (grub_disk_read (data->disk, 0, page_offset, sizeof (next), next)
			|| grub_disk_read (data->disk, 0, page_offset + 4,
				chunk, payload + copied))
			goto fail_free;
		overflow = sqlitefs_be32 (next);
		copied += chunk;
	}
	if (overflow)
		goto bad_free;
	*out_size = size;
	return payload;

bad_free:
	sqlitefs_bad ("invalid SQLite overflow chain");
fail_free:
	grub_free (payload);
	return NULL;
bad:
	sqlitefs_bad ("invalid SQLite cell payload");
	return NULL;
}

static int sqlitefs_walk_page (struct sqlitefs_walk *walk,
	grub_uint32_t page_number, unsigned depth);

static int
sqlitefs_visit_cell (struct sqlitefs_walk *walk, const grub_uint8_t *page,
	grub_uint32_t page_number, grub_uint8_t page_type, grub_uint16_t cell_number,
	grub_size_t cell_offset)
{
	struct sqlitefs_cell cell = { 0 };
	grub_uint64_t payload_size;
	grub_uint64_t rowid;
	grub_size_t used;
	grub_size_t offset = 0;

	if (page_type == SQLITEFS_PAGE_INDEX_INTERIOR)
		offset = 4;
	if (cell_offset > walk->data->usable_size
		|| offset > walk->data->usable_size - cell_offset
		|| sqlitefs_read_varint (page + cell_offset + offset,
			walk->data->usable_size - cell_offset - offset,
			&payload_size, &used) != 0)
		goto bad;
	offset += used;
	if (page_type == SQLITEFS_PAGE_TABLE_LEAF)
	{
		if (sqlitefs_read_varint (page + cell_offset + offset,
			walk->data->usable_size - cell_offset - offset,
			&rowid, &used) != 0)
			goto bad;
		offset += used;
		cell.rowid = (grub_int64_t) rowid;
	}

	cell.payload = sqlitefs_payload (walk->data, page, cell_offset,
		page_type, payload_size, offset, &cell.payload_size);
	if (!cell.payload)
		return -1;
	cell.page_type = page_type;
	cell.page = page_number;
	cell.cell = cell_number;
	if (walk->hook (&cell, walk->hook_data))
		walk->stopped = 1;
	grub_free (cell.payload);
	return 0;

bad:
	sqlitefs_bad ("invalid SQLite b-tree cell");
	return -1;
}

static int
sqlitefs_walk_page (struct sqlitefs_walk *walk, grub_uint32_t page_number,
	unsigned depth)
{
	grub_uint8_t *page = NULL;
	grub_size_t header_offset = page_number == 1 ? SQLITEFS_HEADER_SIZE : 0;
	grub_size_t header_size;
	grub_uint16_t cells;
	grub_uint16_t i;
	grub_uint8_t page_type;
	int interior;

	if (walk->stopped)
		return 0;
	if (depth > SQLITEFS_BTREE_DEPTH_MAX || ++walk->pages_seen > walk->data->pages)
		goto bad;
	page = sqlitefs_read_page (walk->data, page_number);
	if (!page)
		return -1;
	page_type = page[header_offset];
	interior = page_type == SQLITEFS_PAGE_INDEX_INTERIOR
		|| page_type == SQLITEFS_PAGE_TABLE_INTERIOR;
	if (!interior && page_type != SQLITEFS_PAGE_INDEX_LEAF
		&& page_type != SQLITEFS_PAGE_TABLE_LEAF)
		goto bad;
	{
		int family = (page_type == SQLITEFS_PAGE_TABLE_INTERIOR
			|| page_type == SQLITEFS_PAGE_TABLE_LEAF) ? 1 : 2;

		if (!walk->family)
			walk->family = family;
		else if (walk->family != family)
			goto bad;
	}
	header_size = interior ? 12 : 8;
	if (header_offset + header_size > walk->data->usable_size)
		goto bad;
	cells = sqlitefs_be16 (page + header_offset + 3);
	if ((grub_size_t) cells > (walk->data->usable_size
		- header_offset - header_size) / 2)
		goto bad;

	for (i = 0; i < cells && !walk->stopped; i++)
	{
		grub_size_t pointer_offset = header_offset + header_size + 2 * i;
		grub_size_t cell_offset = sqlitefs_be16 (page + pointer_offset);
		grub_uint32_t child;

		if (cell_offset < header_offset + header_size + 2 * cells
			|| cell_offset >= walk->data->usable_size)
			goto bad;
		if (interior)
		{
			if (walk->data->usable_size - cell_offset < 4)
				goto bad;
			child = sqlitefs_be32 (page + cell_offset);
			if (sqlitefs_walk_page (walk, child, depth + 1) != 0)
				goto fail;
		}
		if (!walk->stopped && page_type != SQLITEFS_PAGE_TABLE_INTERIOR
			&& sqlitefs_visit_cell (walk, page, page_number, page_type,
				i, cell_offset) != 0)
			goto fail;
	}
	if (interior && !walk->stopped)
	{
		grub_uint32_t right = sqlitefs_be32 (page + header_offset + 8);

		if (sqlitefs_walk_page (walk, right, depth + 1) != 0)
			goto fail;
	}
	grub_free (page);
	return 0;

bad:
	sqlitefs_bad ("invalid SQLite b-tree page");
fail:
	grub_free (page);
	return -1;
}

static int
sqlitefs_walk_btree (struct sqlitefs_data *data, grub_uint32_t root,
	sqlitefs_cell_hook_t hook, void *hook_data)
{
	struct sqlitefs_walk walk = { 0 };

	walk.data = data;
	walk.hook = hook;
	walk.hook_data = hook_data;
	if (sqlitefs_walk_page (&walk, root, 1) != 0)
		return -1;
	return walk.stopped;
}

static int
sqlitefs_serial_size (grub_uint64_t serial, grub_size_t *size)
{
	grub_uint64_t value;

	switch (serial)
	{
	case 0: case 8: case 9:
		value = 0;
		break;
	case 1: value = 1; break;
	case 2: value = 2; break;
	case 3: value = 3; break;
	case 4: value = 4; break;
	case 5: value = 6; break;
	case 6: case 7: value = 8; break;
	case 10: case 11:
		return -1;
	default:
		value = (serial - (serial & 1 ? 13 : 12)) / 2;
		break;
	}
	if (value > (grub_uint64_t) (grub_size_t) -1)
		return -1;
	*size = (grub_size_t) value;
	return 0;
}

static int
sqlitefs_record_values (const grub_uint8_t *record, grub_size_t size,
	struct sqlitefs_value *values, grub_size_t maximum, grub_size_t *count)
{
	grub_uint64_t header_value;
	grub_size_t header_used;
	grub_size_t header_size;
	grub_size_t header_offset;
	grub_size_t body_offset;
	grub_size_t n = 0;

	if (sqlitefs_read_varint (record, size, &header_value, &header_used) != 0
		|| header_value > size || header_value < header_used)
		goto bad;
	header_size = (grub_size_t) header_value;
	header_offset = header_used;
	body_offset = header_size;
	while (header_offset < header_size)
	{
		grub_uint64_t serial;
		grub_size_t used;
		grub_size_t value_size;

		if (n == maximum || sqlitefs_read_varint (record + header_offset,
			header_size - header_offset, &serial, &used) != 0
			|| sqlitefs_serial_size (serial, &value_size) != 0
			|| value_size > size - body_offset)
			goto bad;
		values[n].serial = serial;
		values[n].data = record + body_offset;
		values[n].size = value_size;
		n++;
		header_offset += used;
		body_offset += value_size;
	}
	if (body_offset != size)
		goto bad;
	*count = n;
	return 0;

bad:
	sqlitefs_bad ("invalid SQLite record");
	return -1;
}

static grub_int64_t
sqlitefs_integer (const struct sqlitefs_value *value)
{
	grub_uint64_t number = 0;
	grub_size_t i;

	if (value->serial == 8)
		return 0;
	if (value->serial == 9)
		return 1;
	for (i = 0; i < value->size; i++)
		number = (number << 8) | value->data[i];
	if (value->size && value->size < 8 && (value->data[0] & 0x80))
		number |= (~0ULL) << (value->size * 8);
	return (grub_int64_t) number;
}

static int
sqlitefs_value_text (struct sqlitefs_data *data,
	const struct sqlitefs_value *value, char **text)
{
	grub_size_t size;

	if (value->serial < 13 || !(value->serial & 1))
		return -1;
	*text = sqlitefs_text (data, value->data, value->size, &size);
	if (!*text)
		return -1;
	/* Schema identifiers and SQL cannot contain an embedded NUL. */
	if (grub_strlen (*text) != size)
	{
		grub_free (*text);
		*text = NULL;
		return -1;
	}
	return 0;
}

static enum sqlitefs_object_type
sqlitefs_object_type (const char *type, int *valid)
{
	*valid = 1;
	if (grub_strcmp (type, "table") == 0)
		return SQLITEFS_OBJECT_TABLE;
	if (grub_strcmp (type, "index") == 0)
		return SQLITEFS_OBJECT_INDEX;
	if (grub_strcmp (type, "view") == 0)
		return SQLITEFS_OBJECT_VIEW;
	if (grub_strcmp (type, "trigger") == 0)
		return SQLITEFS_OBJECT_TRIGGER;
	*valid = 0;
	return SQLITEFS_OBJECT_TABLE;
}

struct sqlitefs_schema_ctx
{
	struct sqlitefs_data *data;
	struct sqlitefs_schema *schema;
};

static int
sqlitefs_schema_cell (const struct sqlitefs_cell *cell, void *hook_data)
{
	struct sqlitefs_schema_ctx *ctx = hook_data;
	struct sqlitefs_value values[5];
	struct sqlitefs_object object = { 0 };
	grub_size_t count;
	char *type = NULL;
	int valid;

	if (cell->page_type != SQLITEFS_PAGE_TABLE_LEAF
		|| sqlitefs_record_values (cell->payload, cell->payload_size,
			values, ARRAY_SIZE (values), &count) != 0 || count != 5
		|| sqlitefs_value_text (ctx->data, &values[0], &type) != 0
		|| sqlitefs_value_text (ctx->data, &values[1], &object.name) != 0
		|| sqlitefs_value_text (ctx->data, &values[2], &object.table_name) != 0)
		goto bad;
	object.type = sqlitefs_object_type (type, &valid);
	if (!valid || values[3].serial == 7 || values[3].serial > 9)
		goto bad;
	{
		grub_int64_t root = values[3].serial == 0 ? 0
			: sqlitefs_integer (&values[3]);

		if (root < 0 || (grub_uint64_t) root > ctx->data->pages)
			goto bad;
		object.root_page = (grub_uint32_t) root;
	}
	if (values[4].serial != 0
		&& sqlitefs_value_text (ctx->data, &values[4], &object.sql) != 0)
		goto bad;
	object.path_name = sqlitefs_path_name (object.name);
	if (!object.path_name)
		goto fail;

	if (ctx->schema->count == ctx->schema->capacity)
	{
		grub_size_t capacity;
		grub_size_t bytes;
		struct sqlitefs_object *objects;

		if (!ctx->schema->capacity)
			capacity = 16;
		else if (grub_add (ctx->schema->capacity,
			ctx->schema->capacity / 2 + 8, &capacity))
			goto overflow;
		if (grub_mul (capacity, sizeof (*objects), &bytes))
			goto overflow;
		objects = grub_realloc (ctx->schema->objects, bytes);
		if (!objects)
			goto fail;
		ctx->schema->objects = objects;
		ctx->schema->capacity = capacity;
	}
	ctx->schema->objects[ctx->schema->count++] = object;
	grub_free (type);
	return 0;

overflow:
	grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many SQLite schema objects");

bad:
	if (!grub_errno)
		sqlitefs_bad ("invalid sqlite_schema record");
fail:
	grub_free (type);
	grub_free (object.name);
	grub_free (object.path_name);
	grub_free (object.table_name);
	grub_free (object.sql);
	return 1;
}

static void
sqlitefs_free_schema (struct sqlitefs_schema *schema)
{
	grub_size_t i;

	for (i = 0; i < schema->count; i++)
	{
		grub_free (schema->objects[i].name);
		grub_free (schema->objects[i].path_name);
		grub_free (schema->objects[i].table_name);
		grub_free (schema->objects[i].sql);
	}
	grub_free (schema->objects);
	grub_memset (schema, 0, sizeof (*schema));
}

static int
sqlitefs_load_schema (struct sqlitefs_data *data,
	struct sqlitefs_schema *schema)
{
	struct sqlitefs_schema_ctx ctx = { data, schema };

	if (sqlitefs_walk_btree (data, 1, sqlitefs_schema_cell, &ctx) < 0
		|| grub_errno != GRUB_ERR_NONE)
	{
		sqlitefs_free_schema (schema);
		return -1;
	}
	return 0;
}

static void
sqlitefs_parse_path (const char *path, struct sqlitefs_path *parsed)
{
	const char *p = path;

	grub_memset (parsed, 0, sizeof (*parsed));
	while (*p == '/')
		p++;
	while (*p && parsed->count < SQLITEFS_PATH_PARTS_MAX)
	{
		const char *start = p;

		while (*p && *p != '/')
			p++;
		parsed->part[parsed->count] = start;
		parsed->len[parsed->count] = p - start;
		parsed->count++;
		while (*p == '/')
			p++;
	}
	if (*p)
		parsed->count = SQLITEFS_PATH_PARTS_MAX + 1;
}

static int
sqlitefs_part (const struct sqlitefs_path *path, grub_size_t index,
	const char *name)
{
	grub_size_t size = grub_strlen (name);

	return index < path->count && path->len[index] == size
		&& grub_memcmp (path->part[index], name, size) == 0;
}

static int
sqlitefs_part_suffix (const struct sqlitefs_path *path, grub_size_t index,
	const char *name, const char *suffix)
{
	grub_size_t name_size = grub_strlen (name);
	grub_size_t suffix_size = grub_strlen (suffix);

	return index < path->count && path->len[index] == name_size + suffix_size
		&& grub_memcmp (path->part[index], name, name_size) == 0
		&& grub_memcmp (path->part[index] + name_size, suffix, suffix_size) == 0;
}

static struct sqlitefs_object *
sqlitefs_find_object (struct sqlitefs_schema *schema,
	enum sqlitefs_object_type type, const struct sqlitefs_path *path,
	grub_size_t part, const char *suffix)
{
	grub_size_t i;

	for (i = 0; i < schema->count; i++)
		if (schema->objects[i].type == type
			&& sqlitefs_part_suffix (path, part,
				schema->objects[i].path_name, suffix))
			return &schema->objects[i];
	return NULL;
}

static int
sqlitefs_emit (grub_fs_dir_hook_t hook, void *hook_data, const char *name,
	int directory, grub_uint64_t inode)
{
	struct grub_dirhook_info info = { 0 };

	info.dir = directory;
	info.inodeset = 1;
	info.inode = inode;
	return hook (name, &info, hook_data);
}

struct sqlitefs_dir_rows_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static void
sqlitefs_cell_name (const struct sqlitefs_cell *cell, char *name,
	grub_size_t size)
{
	if (cell->page_type == SQLITEFS_PAGE_TABLE_LEAF)
	{
		grub_size_t len;

		sqlitefs_i64_string (name, size, cell->rowid);
		len = grub_strlen (name);
		grub_snprintf (name + len, size - len, ".json");
	}
	else
		grub_snprintf (name, size, "%08x-%05u.json", cell->page,
			(unsigned) cell->cell);
}

static int
sqlitefs_dir_row (const struct sqlitefs_cell *cell, void *hook_data)
{
	struct sqlitefs_dir_rows_ctx *ctx = hook_data;
	char name[48];
	grub_uint64_t inode;

	sqlitefs_cell_name (cell, name, sizeof (name));
	inode = ((grub_uint64_t) cell->page << 16) | cell->cell;
	return sqlitefs_emit (ctx->hook, ctx->hook_data, name, 0, inode);
}

static grub_err_t
sqlitefs_dir (grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct sqlitefs_data *data = NULL;
	struct sqlitefs_schema schema = { 0 };
	struct sqlitefs_path parsed;
	struct sqlitefs_object *object;
	grub_size_t i;
	grub_err_t err = GRUB_ERR_NONE;

	data = sqlitefs_mount (device->disk);
	if (!data)
		return grub_errno;
	sqlitefs_parse_path (path, &parsed);
	/* Probe through the schema root too.  A valid 100-byte header alone is
	   not sufficient to claim the device as sqlitefs. */
	if (sqlitefs_load_schema (data, &schema) != 0)
		goto fail;
	if (parsed.count == 0)
	{
		if (sqlitefs_emit (hook, hook_data, "tables", 1, 1)
			|| sqlitefs_emit (hook, hook_data, "indexes", 1, 2)
			|| sqlitefs_emit (hook, hook_data, "views", 1, 3)
			|| sqlitefs_emit (hook, hook_data, "triggers", 1, 4)
			|| sqlitefs_emit (hook, hook_data, "schema.sql", 0, 5)
			|| sqlitefs_emit (hook, hook_data, "database.json", 0, 6))
			goto out;
		goto out;
	}
	if (parsed.count == 1)
	{
		enum sqlitefs_object_type type;
		int matched = 1;

		if (sqlitefs_part (&parsed, 0, "tables"))
			type = SQLITEFS_OBJECT_TABLE;
		else if (sqlitefs_part (&parsed, 0, "indexes"))
			type = SQLITEFS_OBJECT_INDEX;
		else if (sqlitefs_part (&parsed, 0, "views"))
			type = SQLITEFS_OBJECT_VIEW;
		else if (sqlitefs_part (&parsed, 0, "triggers"))
			type = SQLITEFS_OBJECT_TRIGGER;
		else
			matched = 0;
		if (matched)
		{
			for (i = 0; i < schema.count; i++)
			{
				char *name;
				struct sqlitefs_buf filename = { 0 };
				grub_size_t ignored;

				if (schema.objects[i].type != type)
					continue;
				if (type == SQLITEFS_OBJECT_TABLE)
					name = schema.objects[i].path_name;
				else
				{
					if (sqlitefs_buf_string (&filename,
						schema.objects[i].path_name) != 0
						|| sqlitefs_buf_string (&filename, ".sql") != 0)
					{
						grub_free (filename.data);
						goto fail;
					}
					name = sqlitefs_buf_finish (&filename, &ignored);
				}
				if (sqlitefs_emit (hook, hook_data, name,
					type == SQLITEFS_OBJECT_TABLE, 0x100 + i))
				{
					grub_free (filename.data);
					goto out;
				}
				grub_free (filename.data);
			}
			goto out;
		}
	}

	if (parsed.count >= 2 && sqlitefs_part (&parsed, 0, "tables"))
	{
		object = sqlitefs_find_object (&schema, SQLITEFS_OBJECT_TABLE,
			&parsed, 1, "");
		if (!object)
			goto not_found;
		if (parsed.count == 2)
		{
			grub_uint64_t object_inode = 0x100000000ULL
				+ 2 * (grub_uint64_t) (object - schema.objects);

			if (sqlitefs_emit (hook, hook_data, "schema.sql", 0,
				object_inode))
				goto out;
			if (object->root_page
				&& sqlitefs_emit (hook, hook_data, "rows", 1,
					object_inode + 1))
				goto out;
			goto out;
		}
		if (parsed.count == 3 && sqlitefs_part (&parsed, 2, "rows")
			&& object->root_page)
		{
			struct sqlitefs_dir_rows_ctx ctx = { hook, hook_data };

			if (sqlitefs_walk_btree (data, object->root_page,
				sqlitefs_dir_row, &ctx) < 0)
				goto fail;
			goto out;
		}
	}

not_found:
	err = grub_error (GRUB_ERR_FILE_NOT_FOUND, "SQLite directory not found");
	goto out;
fail:
	err = grub_errno;
out:
	sqlitefs_free_schema (&schema);
	grub_free (data);
	return err;
}

static int
sqlitefs_json_string (struct sqlitefs_buf *buf, const grub_uint8_t *text,
	grub_size_t size)
{
	static const char hex[] = "0123456789ABCDEF";
	grub_size_t i;

	if (sqlitefs_buf_char (buf, '"') != 0)
		return -1;
	for (i = 0; i < size; i++)
	{
		grub_uint8_t c = text[i];

		if (c == '"' || c == '\\')
		{
			char escaped[2] = { '\\', (char) c };

			if (sqlitefs_buf_append (buf, escaped, sizeof (escaped)) != 0)
				return -1;
		}
		else if (c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t')
		{
			char escaped[2] = { '\\', c == '\b' ? 'b' : c == '\f' ? 'f'
				: c == '\n' ? 'n' : c == '\r' ? 'r' : 't' };

			if (sqlitefs_buf_append (buf, escaped, sizeof (escaped)) != 0)
				return -1;
		}
		else if (c < 0x20)
		{
			char escaped[6] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0xf] };

			if (sqlitefs_buf_append (buf, escaped, sizeof (escaped)) != 0)
				return -1;
		}
		else if (sqlitefs_buf_char (buf, (char) c) != 0)
			return -1;
	}
	return sqlitefs_buf_char (buf, '"');
}

static int
sqlitefs_json_value (struct sqlitefs_data *data, struct sqlitefs_buf *buf,
	const struct sqlitefs_value *value)
{
	char number[64];
	grub_size_t i;

	if (value->serial == 0)
		return sqlitefs_buf_string (buf, "null");
	if ((value->serial >= 1 && value->serial <= 6)
		|| value->serial == 8 || value->serial == 9)
	{
		sqlitefs_i64_string (number, sizeof (number),
			sqlitefs_integer (value));
		return sqlitefs_buf_string (buf, number);
	}
	if (value->serial == 7)
	{
		grub_uint64_t bits = sqlitefs_be64 (value->data);
		double real;
		int written;

		if ((bits & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL)
			return sqlitefs_json_string (buf,
				(const grub_uint8_t *) "non-finite", 10);
		grub_memcpy (&real, &bits, sizeof (real));
		written = snprintf (number, sizeof (number), "%.17g", real);
		if (written < 0 || (grub_size_t) written >= sizeof (number))
		{
			grub_error (GRUB_ERR_BAD_FS, "cannot format SQLite real value");
			return -1;
		}
		return sqlitefs_buf_append (buf, number, (grub_size_t) written);
	}
	if (value->serial >= 13 && (value->serial & 1))
	{
		grub_size_t size;
		char *text = sqlitefs_text (data, value->data, value->size, &size);
		int result;

		if (!text)
			return -1;
		result = sqlitefs_json_string (buf, (grub_uint8_t *) text, size);
		grub_free (text);
		return result;
	}

	if (sqlitefs_buf_string (buf, "{\"blob\":\"") != 0)
		return -1;
	for (i = 0; i < value->size; i++)
	{
		static const char hex[] = "0123456789ABCDEF";
		char pair[2] = { hex[value->data[i] >> 4], hex[value->data[i] & 0xf] };

		if (sqlitefs_buf_append (buf, pair, sizeof (pair)) != 0)
			return -1;
	}
	return sqlitefs_buf_string (buf, "\"}");
}

static char *
sqlitefs_row_json (struct sqlitefs_data *data,
	const struct sqlitefs_cell *cell, grub_size_t *size)
{
	struct sqlitefs_buf out = { 0 };
	struct sqlitefs_value *values = NULL;
	grub_size_t maximum;
	grub_size_t count;
	grub_size_t i;
	grub_uint64_t header_size;
	grub_size_t used;
	char number[64];

	if (sqlitefs_read_varint (cell->payload, cell->payload_size,
		&header_size, &used) != 0 || header_size < used
		|| header_size > cell->payload_size)
		goto bad;
	maximum = (grub_size_t) header_size - used;
	values = grub_calloc (maximum ? maximum : 1, sizeof (*values));
	if (!values)
		goto fail;
	if (sqlitefs_record_values (cell->payload, cell->payload_size,
		values, maximum, &count) != 0)
		goto fail;
	if (sqlitefs_buf_string (&out, "{\r\n") != 0)
		goto fail;
	if (cell->page_type == SQLITEFS_PAGE_TABLE_LEAF)
	{
		if (sqlitefs_buf_string (&out, "  \"rowid\": ") != 0)
			goto fail;
		sqlitefs_i64_string (number, sizeof (number), cell->rowid);
		if (sqlitefs_buf_string (&out, number) != 0
			|| sqlitefs_buf_string (&out, ",\r\n") != 0)
			goto fail;
	}
	if (sqlitefs_buf_string (&out, "  \"values\": [") != 0)
		goto fail;
	for (i = 0; i < count; i++)
	{
		if (i && sqlitefs_buf_string (&out, ", ") != 0)
			goto fail;
		if (sqlitefs_json_value (data, &out, &values[i]) != 0)
			goto fail;
	}
	if (sqlitefs_buf_string (&out, "]\r\n}\r\n") != 0)
		goto fail;
	grub_free (values);
	return sqlitefs_buf_finish (&out, size);

bad:
	sqlitefs_bad ("invalid SQLite record");
fail:
	grub_free (values);
	grub_free (out.data);
	return NULL;
}

struct sqlitefs_open_row_ctx
{
	struct sqlitefs_data *data;
	const struct sqlitefs_path *path;
	char *contents;
	grub_size_t size;
};

static int
sqlitefs_open_row (const struct sqlitefs_cell *cell, void *hook_data)
{
	struct sqlitefs_open_row_ctx *ctx = hook_data;
	char name[48];

	sqlitefs_cell_name (cell, name, sizeof (name));
	if (!sqlitefs_part (ctx->path, 3, name))
		return 0;
	ctx->contents = sqlitefs_row_json (ctx->data, cell, &ctx->size);
	return 1;
}

static char *
sqlitefs_schema_sql (struct sqlitefs_schema *schema, grub_size_t *size)
{
	struct sqlitefs_buf out = { 0 };
	grub_size_t i;

	for (i = 0; i < schema->count; i++)
	{
		grub_size_t sql_size;

		if (!schema->objects[i].sql)
			continue;
		sql_size = grub_strlen (schema->objects[i].sql);
		if (sqlitefs_buf_append (&out, schema->objects[i].sql, sql_size) != 0
			|| (!sql_size || schema->objects[i].sql[sql_size - 1] != ';')
				&& sqlitefs_buf_char (&out, ';') != 0
			|| sqlitefs_buf_string (&out, "\r\n\r\n") != 0)
			goto fail;
	}
	return sqlitefs_buf_finish (&out, size);

fail:
	grub_free (out.data);
	return NULL;
}

static char *
sqlitefs_database_json (struct sqlitefs_data *data, grub_size_t *size)
{
	char text[512];
	int written;

	written = grub_snprintf (text, sizeof (text),
		"{\r\n"
		"  \"format\": \"SQLite 3\",\r\n"
		"  \"page_size\": %u,\r\n"
		"  \"usable_page_size\": %u,\r\n"
		"  \"page_count\": %u,\r\n"
		"  \"text_encoding\": \"%s\",\r\n"
		"  \"schema_format\": %u,\r\n"
		"  \"user_version\": %u,\r\n"
		"  \"application_id\": %u,\r\n"
		"  \"sqlite_version_number\": %u\r\n"
		"}\r\n",
		data->page_size, data->usable_size, data->pages,
		data->encoding == 1 ? "UTF-8" : data->encoding == 2 ? "UTF-16le" : "UTF-16be",
		data->schema_format, data->user_version, data->application_id,
		data->sqlite_version);
	if (written < 0 || (grub_size_t) written >= sizeof (text))
		return NULL;
	*size = (grub_size_t) written;
	return grub_strdup (text);
}

static grub_err_t
sqlitefs_open (struct grub_file *file, const char *name)
{
	struct sqlitefs_data *data = NULL;
	struct sqlitefs_schema schema = { 0 };
	struct sqlitefs_path path;
	struct sqlitefs_object *object = NULL;
	struct sqlitefs_file *opened = NULL;
	char *contents = NULL;
	grub_size_t size = 0;
	grub_err_t err = GRUB_ERR_NONE;

	data = sqlitefs_mount (file->device->disk);
	if (!data)
		return grub_errno;
	sqlitefs_parse_path (name, &path);
	if (path.count == 1 && sqlitefs_part (&path, 0, "database.json"))
		contents = sqlitefs_database_json (data, &size);
	else
	{
		if (sqlitefs_load_schema (data, &schema) != 0)
			goto fail;
		if (path.count == 1 && sqlitefs_part (&path, 0, "schema.sql"))
			contents = sqlitefs_schema_sql (&schema, &size);
		else if (path.count == 2 && sqlitefs_part (&path, 0, "indexes"))
			object = sqlitefs_find_object (&schema, SQLITEFS_OBJECT_INDEX,
				&path, 1, ".sql");
		else if (path.count == 2 && sqlitefs_part (&path, 0, "views"))
			object = sqlitefs_find_object (&schema, SQLITEFS_OBJECT_VIEW,
				&path, 1, ".sql");
		else if (path.count == 2 && sqlitefs_part (&path, 0, "triggers"))
			object = sqlitefs_find_object (&schema, SQLITEFS_OBJECT_TRIGGER,
				&path, 1, ".sql");
		else if (path.count >= 3 && sqlitefs_part (&path, 0, "tables"))
		{
			object = sqlitefs_find_object (&schema, SQLITEFS_OBJECT_TABLE,
				&path, 1, "");
			if (object && path.count == 4 && sqlitefs_part (&path, 2, "rows")
				&& object->root_page)
			{
				struct sqlitefs_open_row_ctx ctx = { data, &path, NULL, 0 };

				if (sqlitefs_walk_btree (data, object->root_page,
					sqlitefs_open_row, &ctx) < 0)
					goto fail;
				contents = ctx.contents;
				size = ctx.size;
				object = NULL;
			}
			else if (!object || path.count != 3
				|| !sqlitefs_part (&path, 2, "schema.sql"))
				object = NULL;
		}
		if (!contents && object && object->sql)
		{
			size = grub_strlen (object->sql);
			contents = grub_malloc (size + 3);
			if (contents)
			{
				grub_memcpy (contents, object->sql, size);
				contents[size++] = '\r';
				contents[size++] = '\n';
				contents[size] = '\0';
			}
		}
		else if (!contents && object)
		{
			struct sqlitefs_buf note = { 0 };

			if (sqlitefs_buf_string (&note, "-- Implicit SQLite index: ") != 0
				|| sqlitefs_buf_string (&note, object->name) != 0
				|| sqlitefs_buf_string (&note, "\r\n") != 0)
			{
				grub_free (note.data);
				goto fail;
			}
			contents = sqlitefs_buf_finish (&note, &size);
		}
	}
	if (!contents)
	{
		if (grub_errno != GRUB_ERR_NONE)
			goto fail;
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND, "SQLite file not found");
		goto out;
	}
	opened = grub_malloc (sizeof (*opened));
	if (!opened)
		goto fail;
	opened->data = contents;
	file->data = opened;
	file->size = size;
	contents = NULL;
	goto out;

fail:
	err = grub_errno;
out:
	grub_free (contents);
	sqlitefs_free_schema (&schema);
	grub_free (data);
	return err;
}

static grub_ssize_t
sqlitefs_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct sqlitefs_file *opened = file->data;

	grub_memcpy (buf, opened->data + file->offset, len);
	return (grub_ssize_t) len;
}

static grub_err_t
sqlitefs_close (grub_file_t file)
{
	struct sqlitefs_file *opened = file->data;

	grub_free (opened->data);
	grub_free (opened);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_sqlitefs_fs =
{
	.name = "sqlitefs",
	.fs_dir = sqlitefs_dir,
	.fs_open = sqlitefs_open,
	.fs_read = sqlitefs_read,
	.fs_close = sqlitefs_close,
	.next = 0
};

GRUB_MOD_INIT (sqlitefs)
{
	grub_sqlitefs_fs.mod = mod;
	grub_fs_register (&grub_sqlitefs_fs);
}

GRUB_MOD_FINI (sqlitefs)
{
	grub_fs_unregister (&grub_sqlitefs_fs);
}
