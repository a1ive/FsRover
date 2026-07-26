/*
 *  Rover -- Filesystem browser for Windows
 *  Read-only RAR (RAR 1.5 .. RAR 7) archive filesystem driver.
 *
 *  Container parsing follows 7-Zip 26.02
 *  (CPP\7zip\Archive\Rar\RarHandler.cpp / Rar5Handler.cpp);
 *  decompression lives in grub-core\lib\unrar.
 *
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
#include <grub/charset.h>
#include <grub/datetime.h>
#include <grub/dl.h>

#include <unrar.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define RAR_MAX_ITEMS		(1u << 20)
#define RAR_MAX_NAME		(1u << 16)
#define RAR_MAX_HEADER		(1u << 21)

/* RAR4 block types */
#define RAR4_TYPE_MARKER	0x72
#define RAR4_TYPE_ARCHIVE	0x73
#define RAR4_TYPE_FILE		0x74
#define RAR4_TYPE_ENDARC	0x7b

/* RAR4 archive flags */
#define RAR4_ARC_VOLUME		0x0001
#define RAR4_ARC_SOLID		0x0008
#define RAR4_ARC_ENC_HEADERS	0x0080

/* RAR4 file flags */
#define RAR4_FILE_SPLIT_BEFORE	0x0001
#define RAR4_FILE_SPLIT_AFTER	0x0002
#define RAR4_FILE_ENCRYPTED	0x0004
#define RAR4_FILE_SOLID		0x0010
#define RAR4_FILE_DICT_MASK	0x00e0
#define RAR4_FILE_DICT_DIR	0x00e0
#define RAR4_FILE_SIZE64	0x0100
#define RAR4_FILE_UNICODE_NAME	0x0200
#define RAR4_FILE_SALT		0x0400
#define RAR4_FILE_EXT_TIME	0x1000
#define RAR4_FILE_LONG_BLOCK	0x8000

/* RAR4 host OS */
#define RAR4_HOST_MSDOS		0
#define RAR4_HOST_OS2		1
#define RAR4_HOST_WIN32		2
#define RAR4_HOST_UNIX		3
#define RAR4_HOST_MACOS		4
#define RAR4_HOST_BEOS		5

/* RAR5 header types */
#define RAR5_TYPE_ARC		1
#define RAR5_TYPE_FILE		2
#define RAR5_TYPE_SERVICE	3
#define RAR5_TYPE_ARC_ENCRYPT	4
#define RAR5_TYPE_ENDARC	5

/* RAR5 common header flags */
#define RAR5_HFLAG_EXTRA	(1 << 0)
#define RAR5_HFLAG_DATA		(1 << 1)
#define RAR5_HFLAG_PREV_VOL	(1 << 3)
#define RAR5_HFLAG_NEXT_VOL	(1 << 4)

/* RAR5 archive flags */
#define RAR5_AFLAG_VOL		(1 << 0)
#define RAR5_AFLAG_SOLID	(1 << 2)

/* RAR5 file flags */
#define RAR5_FFLAG_DIR		(1 << 0)
#define RAR5_FFLAG_UTIME	(1 << 1)
#define RAR5_FFLAG_CRC32	(1 << 2)
#define RAR5_FFLAG_UNKNOWN_SIZE	(1 << 3)

/* RAR5 extra record ids */
#define RAR5_EXTRA_CRYPTO	1
#define RAR5_EXTRA_LINK		5

#define RAR5_LINK_UNIX_SYMLINK	1
#define RAR5_LINK_WIN_SYMLINK	2

#define FILE_ATTRIBUTE_DIRECTORY_	0x10

struct grub_rar_item
{
	char *name;
	grub_uint64_t data_pos;
	grub_uint64_t pack_size;
	grub_uint64_t unp_size;
	grub_int64_t mtime;
	grub_uint8_t algo;	/* RAR_ALGO_* */
	grub_uint8_t dict_main;
	grub_uint8_t dict_frac;
	unsigned store:1;	/* stored, no compression */
	unsigned is_v7:1;
	unsigned is_dir:1;
	unsigned is_solid:1;
	unsigned is_link:1;
	unsigned mtime_set:1;
	unsigned unsupported:1;	/* encrypted or unknown method */
};

struct grub_rar_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct grub_rar_item *items;
	unsigned num_items;
	unsigned alloc_items;
	int is_rar5;
	int arc_solid;
	int split;		/* archive continues in another volume */
};

struct grub_rar_file
{
	struct grub_rar_data *data;
	rar_decoder *dec;
	unsigned target;	/* index of the item being read */
	unsigned cur;		/* item currently fed to the decoder */
	int started;		/* an item has been handed to the decoder */
	int solid_start;	/* next item must reset the LZ window */
	int collecting;		/* cur == target: keep the output */
	int finished;		/* target item fully decoded */

	/* packed input for the current item */
	grub_uint64_t in_pos;
	grub_uint64_t in_left;

	/* decoded output bookkeeping (positions inside the target item) */
	grub_uint64_t stream_pos;
	grub_uint64_t skip_to;
	grub_uint8_t *pend;
	grub_size_t pend_alloc;
	grub_size_t pend_len;
	grub_uint64_t pend_pos;
	grub_size_t want;
	int io_err;
};

static const grub_uint8_t rar4_marker[7] =
	{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 };
static const grub_uint8_t rar5_marker[8] =
	{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00 };

/* ---------------- helpers ---------------- */

static grub_uint16_t
rar_get16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) (p[0] | ((grub_uint16_t) p[1] << 8));
}

static grub_uint32_t
rar_get32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8)
	       | ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

/* reads a RAR5 variable length integer; returns consumed bytes, 0 on error */
static unsigned
rar_read_vint (const grub_uint8_t *p, grub_size_t max, grub_uint64_t *val)
{
	grub_uint64_t v = 0;
	unsigned i;

	if (max > 10)
		max = 10;
	for (i = 0; i < max;)
	{
		const unsigned b = p[i];
		v |= (grub_uint64_t) (b & 0x7F) << (7 * i);
		i++;
		if ((b & 0x80) == 0)
		{
			*val = v;
			return i;
		}
	}
	*val = 0;
	return 0;
}

static grub_int64_t
rar_dos_time (grub_uint32_t dos)
{
	struct grub_datetime dt;
	grub_int64_t nix = 0;

	grub_memset (&dt, 0, sizeof (dt));
	dt.year = (grub_int16_t) (((dos >> 25) & 0x7f) + 1980);
	dt.month = (grub_uint8_t) ((dos >> 21) & 0x0f);
	dt.day = (grub_uint8_t) ((dos >> 16) & 0x1f);
	dt.hour = (grub_uint8_t) ((dos >> 11) & 0x1f);
	dt.minute = (grub_uint8_t) ((dos >> 5) & 0x3f);
	dt.second = (grub_uint8_t) ((dos & 0x1f) * 2);
	if (dt.month < 1 || dt.month > 12 || dt.day < 1 || dt.day > 31)
		return 0;
	if (grub_datetime2unixtime (&dt, &nix))
		return nix;
	return 0;
}

/* normalizes separators and strips leading slashes / "." components */
static void
rar_fix_name (char *name)
{
	char *p;

	for (p = name; *p; p++)
		if (*p == '\\')
			*p = '/';
}

static struct grub_rar_item *
rar_add_item (struct grub_rar_data *data)
{
	struct grub_rar_item *item;

	if (data->num_items >= RAR_MAX_ITEMS)
		return 0;
	if (data->num_items == data->alloc_items)
	{
		unsigned n = data->alloc_items ? data->alloc_items * 2 : 64;
		struct grub_rar_item *tmp;
		tmp = grub_calloc (n, sizeof (*tmp));
		if (!tmp)
			return 0;
		if (data->items)
		{
			grub_memcpy (tmp, data->items,
				     data->num_items * sizeof (*tmp));
			grub_free (data->items);
		}
		data->items = tmp;
		data->alloc_items = n;
	}
	item = &data->items[data->num_items++];
	grub_memset (item, 0, sizeof (*item));
	return item;
}

static void
rar_free_data (struct grub_rar_data *data)
{
	unsigned i;

	if (!data)
		return;
	for (i = 0; i < data->num_items; i++)
		grub_free (data->items[i].name);
	grub_free (data->items);
	grub_free (data);
}

/* ---------------- RAR4 name decoding ---------------- */

/*
 * RAR 3 stores non-ASCII names as an ASCII fallback, a NUL and a
 * compressed UTF-16 encoding of the real name.  Decodes into utf16[],
 * returning the number of code units.
 */
static unsigned
rar4_decode_unicode_name (const grub_uint8_t *name, const grub_uint8_t *enc,
			  unsigned enc_size, grub_uint16_t *out,
			  unsigned max_out)
{
	unsigned enc_pos = 0;
	unsigned dec_pos = 0;
	unsigned flag_bits = 0;
	unsigned high_bits;
	grub_uint8_t flags = 0;

	if (enc_pos >= enc_size)
		return 0;
	high_bits = ((unsigned) enc[enc_pos++]) << 8;

	while (enc_pos < enc_size && dec_pos < max_out)
	{
		unsigned len, mode;

		if (flag_bits == 0)
		{
			flags = enc[enc_pos++];
			flag_bits = 8;
			if (enc_pos >= enc_size)
				break;
		}

		len = enc[enc_pos++];

		flag_bits -= 2;
		mode = (flags >> flag_bits) & 3;

		if (mode != 3)
		{
			if (mode == 1)
				len += high_bits;
			else if (mode == 2)
			{
				if (enc_pos >= enc_size)
					break;
				len += ((unsigned) enc[enc_pos++] << 8);
			}
			out[dec_pos++] = (grub_uint16_t) len;
		}
		else
		{
			if (len & 0x80)
			{
				grub_uint8_t correction;
				if (enc_pos >= enc_size)
					break;
				correction = enc[enc_pos++];
				for (len = (len & 0x7f) + 2;
				     len > 0 && dec_pos < max_out;
				     len--, dec_pos++)
					out[dec_pos] = (grub_uint16_t)
						(((name[dec_pos] + correction)
						  & 0xff) + high_bits);
			}
			else
				for (len += 2; len > 0 && dec_pos < max_out;
				     len--, dec_pos++)
					out[dec_pos] = name[dec_pos];
		}
	}

	return dec_pos < max_out ? dec_pos : max_out - 1;
}

static char *
rar4_read_name (const grub_uint8_t *p, unsigned name_size, int unicode)
{
	unsigned i;
	char *name;

	for (i = 0; i < name_size && p[i] != 0; i++)
		;

	if (unicode && i < name_size)
	{
		grub_uint16_t *utf16;
		unsigned max_out = name_size < 0x400 ? name_size : 0x400;
		unsigned len;

		utf16 = grub_calloc (max_out + 1, sizeof (*utf16));
		if (!utf16)
			return 0;
		len = rar4_decode_unicode_name (p, p + i + 1,
						name_size - i - 1, utf16,
						max_out);
		name = grub_calloc (len + 1, GRUB_MAX_UTF8_PER_UTF16);
		if (name)
			*grub_utf16_to_utf8 ((grub_uint8_t *) name, utf16, len)
				= '\0';
		grub_free (utf16);
		return name;
	}

	/*
	 * Plain name: either pure ASCII, or UTF-8 when the unicode flag is
	 * set without a NUL separator.  Non-ASCII OEM names are kept
	 * verbatim; there is no code page table here to convert them.
	 */
	name = grub_malloc (i + 1);
	if (!name)
		return 0;
	grub_memcpy (name, p, i);
	name[i] = '\0';
	return name;
}

/* ---------------- RAR4 container parsing ---------------- */

static grub_err_t
rar4_parse (struct grub_rar_data *data)
{
	grub_uint64_t pos = sizeof (rar4_marker);
	grub_uint8_t head[7];
	grub_uint8_t *body = 0;
	grub_uint16_t arc_flags;
	grub_err_t err = GRUB_ERR_NONE;

	/* archive header */
	if (grub_disk_read (data->disk, 0, pos, sizeof (head), head))
		return grub_errno;
	if (head[2] != RAR4_TYPE_ARCHIVE)
		return grub_error (GRUB_ERR_BAD_FS, "not a rar archive");
	arc_flags = rar_get16 (head + 3);
	if (arc_flags & RAR4_ARC_ENC_HEADERS)
		return grub_error (GRUB_ERR_BAD_FS,
				   "encrypted rar headers are not supported");
	if (arc_flags & RAR4_ARC_VOLUME)
		data->split = 1;
	data->arc_solid = (arc_flags & RAR4_ARC_SOLID) != 0;
	pos += rar_get16 (head + 5);

	body = grub_malloc (RAR_MAX_HEADER);
	if (!body)
		return grub_errno;

	while (pos + sizeof (head) <= data->disk_size)
	{
		unsigned head_size, name_size, rest;
		grub_uint16_t flags;
		grub_uint64_t pack_size, unp_size;
		struct grub_rar_item *item;
		grub_uint8_t host_os, unp_ver, method;
		grub_uint32_t attrib;
		const grub_uint8_t *p;

		if (grub_disk_read (data->disk, 0, pos, sizeof (head), head))
		{
			grub_errno = GRUB_ERR_NONE;
			break;
		}
		head_size = rar_get16 (head + 5);
		flags = rar_get16 (head + 3);
		if (head_size < 7 || head_size > RAR_MAX_HEADER)
			break;
		if (head[2] == RAR4_TYPE_ENDARC)
			break;
		if (head[2] < RAR4_TYPE_FILE || head[2] > RAR4_TYPE_ENDARC)
			break;

		if (head[2] != RAR4_TYPE_FILE)
		{
			grub_uint64_t next = pos + head_size;
			if (flags & RAR4_FILE_LONG_BLOCK)
			{
				grub_uint8_t sz[4];
				if (grub_disk_read (data->disk, 0, pos + 7,
						    sizeof (sz), sz))
				{
					grub_errno = GRUB_ERR_NONE;
					break;
				}
				next += rar_get32 (sz);
			}
			if (next <= pos)
				break;
			pos = next;
			continue;
		}

		if (head_size < 7 + 25)
			break;
		if (grub_disk_read (data->disk, 0, pos + 7, head_size - 7,
				    body))
		{
			grub_errno = GRUB_ERR_NONE;
			break;
		}

		p = body;
		rest = head_size - 7;
		pack_size = rar_get32 (p);
		unp_size = rar_get32 (p + 4);
		host_os = p[8];
		unp_ver = p[17];
		method = p[18];
		name_size = rar_get16 (p + 19);
		attrib = rar_get32 (p + 21);
		p += 25;
		rest -= 25;

		if (flags & RAR4_FILE_SIZE64)
		{
			if (rest < 8)
				break;
			pack_size |= (grub_uint64_t) rar_get32 (p) << 32;
			unp_size |= (grub_uint64_t) rar_get32 (p + 4) << 32;
			p += 8;
			rest -= 8;
		}
		if (name_size > rest || name_size > RAR_MAX_NAME)
			break;

		item = rar_add_item (data);
		if (!item)
		{
			err = grub_errno ? grub_errno : GRUB_ERR_OUT_OF_MEMORY;
			goto out;
		}

		item->name = rar4_read_name (p, name_size,
			(flags & RAR4_FILE_UNICODE_NAME) != 0);
		if (!item->name)
		{
			err = GRUB_ERR_OUT_OF_MEMORY;
			goto out;
		}
		rar_fix_name (item->name);

		item->data_pos = pos + head_size;
		item->pack_size = pack_size;
		item->unp_size = unp_size;
		item->mtime = rar_dos_time (rar_get32 (body + 13));
		item->mtime_set = 1;

		if ((flags & RAR4_FILE_DICT_MASK) == RAR4_FILE_DICT_DIR)
			item->is_dir = 1;
		else if (host_os == RAR4_HOST_MSDOS || host_os == RAR4_HOST_OS2
			 || host_os == RAR4_HOST_WIN32)
			item->is_dir = (attrib
					& FILE_ATTRIBUTE_DIRECTORY_) != 0;
		else if (host_os == RAR4_HOST_UNIX || host_os == RAR4_HOST_BEOS)
			item->is_dir = ((attrib & 0xF000) == 0x4000);

		if (!item->is_dir
		    && (host_os == RAR4_HOST_UNIX || host_os == RAR4_HOST_BEOS)
		    && (attrib & 0xF000) == 0xA000)
			item->is_link = 1;

		item->store = (method == '0');
		if (unp_ver < 20)
		{
			item->algo = RAR_ALGO_15;
			item->is_solid = data->arc_solid
					 && data->num_items > 1;
		}
		else
		{
			item->algo = (unp_ver < 29) ? RAR_ALGO_20
						    : RAR_ALGO_29;
			item->is_solid = (flags & RAR4_FILE_SOLID) != 0;
		}
		if (flags & RAR4_FILE_SPLIT_BEFORE)
			item->is_solid = 1;

		if (unp_ver > 40 || (method != '0'
				     && (method < '1' || method > '5')))
			item->unsupported = 1;
		if (flags & RAR4_FILE_ENCRYPTED)
			item->unsupported = 1;
		if (flags & (RAR4_FILE_SPLIT_BEFORE | RAR4_FILE_SPLIT_AFTER))
		{
			item->unsupported = 1;
			data->split = 1;
		}

		pos = item->data_pos + pack_size;
		if (pos <= item->data_pos && pack_size != 0)
			break;
	}

out:
	grub_free (body);
	return err;
}

/* ---------------- RAR5 container parsing ---------------- */

struct rar5_extra_info
{
	int encrypted;
	int is_link;
};

static void
rar5_parse_extra (const grub_uint8_t *p, grub_size_t size,
		  struct rar5_extra_info *info)
{
	while (size != 0)
	{
		grub_uint64_t rec_size64, id;
		grub_size_t rec_size;
		unsigned num;

		num = rar_read_vint (p, size, &rec_size64);
		if (num == 0)
			return;
		p += num;
		size -= num;
		if (rec_size64 > size)
			return;
		rec_size = (grub_size_t) rec_size64;
		size -= rec_size;

		num = rar_read_vint (p, rec_size, &id);
		if (num == 0)
			return;

		if (id == RAR5_EXTRA_CRYPTO)
			info->encrypted = 1;
		else if (id == RAR5_EXTRA_LINK)
		{
			grub_uint64_t type;
			if (rar_read_vint (p + num, rec_size - num, &type)
			    && (type == RAR5_LINK_UNIX_SYMLINK
				|| type == RAR5_LINK_WIN_SYMLINK))
				info->is_link = 1;
		}

		p += rec_size;
	}
}

static grub_err_t
rar5_parse (struct grub_rar_data *data)
{
	grub_uint64_t pos = sizeof (rar5_marker);
	grub_uint8_t *buf;
	grub_err_t err = GRUB_ERR_NONE;
	int seen_arc = 0;

	buf = grub_malloc (RAR_MAX_HEADER);
	if (!buf)
		return grub_errno;

	while (pos + 8 <= data->disk_size)
	{
		grub_uint8_t start[8];
		grub_uint64_t head_size64, type, flags, extra_size = 0;
		grub_uint64_t data_size = 0;
		grub_size_t head_size, off, avail;
		unsigned num;
		const grub_uint8_t *p;

		if (grub_disk_read (data->disk, 0, pos, sizeof (start), start))
		{
			grub_errno = GRUB_ERR_NONE;
			break;
		}
		num = rar_read_vint (start + 4, 3, &head_size64);
		if (num == 0 || head_size64 < 2
		    || head_size64 > RAR_MAX_HEADER)
			break;
		off = 4 + num;
		head_size = (grub_size_t) head_size64 + off;
		if (head_size > RAR_MAX_HEADER)
			break;
		if (grub_disk_read (data->disk, 0, pos, head_size, buf))
		{
			grub_errno = GRUB_ERR_NONE;
			break;
		}

		p = buf + off;
		avail = head_size - off;

		num = rar_read_vint (p, avail, &type);
		if (num == 0)
			break;
		p += num;
		avail -= num;
		num = rar_read_vint (p, avail, &flags);
		if (num == 0)
			break;
		p += num;
		avail -= num;

		if (flags & RAR5_HFLAG_EXTRA)
		{
			num = rar_read_vint (p, avail, &extra_size);
			if (num == 0 || extra_size > avail)
				break;
			p += num;
			avail -= num;
		}
		if (flags & RAR5_HFLAG_DATA)
		{
			num = rar_read_vint (p, avail, &data_size);
			if (num == 0)
				break;
			p += num;
			avail -= num;
		}
		if (extra_size > avail)
			break;

		if (type == RAR5_TYPE_ARC_ENCRYPT)
		{
			err = grub_error (GRUB_ERR_BAD_FS,
				"encrypted rar headers are not supported");
			goto out;
		}
		if (type == RAR5_TYPE_ENDARC)
			break;

		if (type == RAR5_TYPE_ARC)
		{
			grub_uint64_t arc_flags = 0;
			if (!rar_read_vint (p, avail, &arc_flags))
				break;
			if (arc_flags & RAR5_AFLAG_VOL)
				data->split = 1;
			data->arc_solid = (arc_flags & RAR5_AFLAG_SOLID) != 0;
			seen_arc = 1;
		}
		else if (type == RAR5_TYPE_FILE)
		{
			grub_uint64_t fflags, unp_size, attrib, comp, host_os;
			grub_uint64_t name_len;
			struct grub_rar_item *item;
			struct rar5_extra_info extra;
			unsigned algo_bits, method;
			grub_uint32_t mtime = 0;

			if (!seen_arc)
				break;

			num = rar_read_vint (p, avail, &fflags);
			if (num == 0)
				break;
			p += num;
			avail -= num;
			num = rar_read_vint (p, avail, &unp_size);
			if (num == 0)
				break;
			p += num;
			avail -= num;
			num = rar_read_vint (p, avail, &attrib);
			if (num == 0)
				break;
			p += num;
			avail -= num;
			if (fflags & RAR5_FFLAG_UTIME)
			{
				if (avail < 4)
					break;
				mtime = rar_get32 (p);
				p += 4;
				avail -= 4;
			}
			if (fflags & RAR5_FFLAG_CRC32)
			{
				if (avail < 4)
					break;
				p += 4;
				avail -= 4;
			}
			num = rar_read_vint (p, avail, &comp);
			if (num == 0)
				break;
			p += num;
			avail -= num;
			num = rar_read_vint (p, avail, &host_os);
			if (num == 0)
				break;
			p += num;
			avail -= num;
			num = rar_read_vint (p, avail, &name_len);
			if (num == 0 || name_len > avail
			    || name_len > RAR_MAX_NAME)
				break;
			p += num;
			avail -= num;

			item = rar_add_item (data);
			if (!item)
			{
				err = grub_errno ? grub_errno
						 : GRUB_ERR_OUT_OF_MEMORY;
				goto out;
			}
			item->name = grub_malloc ((grub_size_t) name_len + 1);
			if (!item->name)
			{
				err = GRUB_ERR_OUT_OF_MEMORY;
				goto out;
			}
			grub_memcpy (item->name, p, (grub_size_t) name_len);
			item->name[name_len] = '\0';
			rar_fix_name (item->name);

			p += name_len;
			avail -= name_len;

			grub_memset (&extra, 0, sizeof (extra));
			if (extra_size != 0 && extra_size <= avail)
				rar5_parse_extra (p, (grub_size_t) extra_size,
						  &extra);

			item->data_pos = pos + head_size;
			item->pack_size = data_size;
			item->unp_size = unp_size;
			item->is_dir = (fflags & RAR5_FFLAG_DIR) != 0;
			item->is_link = extra.is_link;
			if (fflags & RAR5_FFLAG_UTIME)
			{
				item->mtime = mtime;
				item->mtime_set = 1;
			}

			algo_bits = (unsigned) comp & 0x3F;
			method = ((unsigned) comp >> 7) & 7;
			item->algo = RAR_ALGO_50;
			item->store = (method == 0);
			item->is_solid = ((unsigned) comp & (1u << 6)) != 0;
			item->is_v7 = (algo_bits == 1
				       && !((unsigned) comp & (1u << 20)));
			item->dict_main = (grub_uint8_t)
				(((unsigned) comp >> 10)
				 & (algo_bits == 0 ? 0xf : 0x1f));
			item->dict_frac = (grub_uint8_t)
				(algo_bits == 0 ? 0
						: (((unsigned) comp >> 15)
						   & 0x1f));

			if (algo_bits > 1 || method > 5)
				item->unsupported = 1;
			if (extra.encrypted)
				item->unsupported = 1;
			if (fflags & RAR5_FFLAG_UNKNOWN_SIZE)
				item->unsupported = 1;
			if (flags & (RAR5_HFLAG_PREV_VOL | RAR5_HFLAG_NEXT_VOL))
			{
				item->unsupported = 1;
				data->split = 1;
			}
			if (flags & RAR5_HFLAG_PREV_VOL)
				item->is_solid = 1;
		}

		{
			const grub_uint64_t next = pos + head_size + data_size;
			if (next <= pos)
				break;
			pos = next;
		}
	}

out:
	grub_free (buf);
	return err;
}

/* ---------------- mount ---------------- */

static struct grub_rar_data *
grub_rar_mount (grub_disk_t disk)
{
	struct grub_rar_data *data;
	grub_uint8_t magic[8];

	if (grub_disk_read (disk, 0, 0, sizeof (magic), magic))
		goto fail;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		goto fail;
	data->disk = disk;
	data->disk_size = grub_disk_native_sectors (disk)
			  << GRUB_DISK_SECTOR_BITS;

	if (grub_memcmp (magic, rar5_marker, sizeof (rar5_marker)) == 0)
	{
		data->is_rar5 = 1;
		if (rar5_parse (data))
			goto fail_data;
	}
	else if (grub_memcmp (magic, rar4_marker, sizeof (rar4_marker)) == 0)
	{
		if (rar4_parse (data))
			goto fail_data;
	}
	else
	{
		grub_free (data);
		goto fail;
	}

	return data;

fail_data:
	rar_free_data (data);
	return 0;
fail:
	grub_error (GRUB_ERR_BAD_FS, "not a rar filesystem");
	return 0;
}

/* ---------------- directory listing ---------------- */

/* skips leading slashes and returns the normalized path length */
static const char *
rar_norm_path (const char *path, grub_size_t *len)
{
	grub_size_t n;

	while (*path == '/')
		path++;
	n = grub_strlen (path);
	while (n > 0 && path[n - 1] == '/')
		n--;
	*len = n;
	return path;
}

static int
rar_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
		 const char **child, grub_size_t *child_len, int *is_dir)
{
	const char *rest;
	const char *slash;

	if (dir_len != 0)
	{
		if (grub_strncmp (name, dir, dir_len) != 0)
			return 0;
		if (name[dir_len] != '/')
			return 0;
		rest = name + dir_len + 1;
	}
	else
		rest = name;

	if (*rest == '\0')
		return 0;
	slash = grub_strchr (rest, '/');
	if (slash)
	{
		*child = rest;
		*child_len = (grub_size_t) (slash - rest);
		*is_dir = 1;
	}
	else
	{
		*child = rest;
		*child_len = grub_strlen (rest);
		*is_dir = 0;
	}
	return *child_len != 0;
}

static grub_err_t
grub_rar_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_rar_data *data;
	const char *dir;
	grub_size_t dir_len;
	char **seen = 0;
	unsigned num_seen = 0;
	unsigned i, j;
	int found;
	grub_err_t err = GRUB_ERR_NONE;

	data = grub_rar_mount (device->disk);
	if (!data)
		return grub_errno;

	dir = rar_norm_path (path, &dir_len);
	found = (dir_len == 0);

	if (data->num_items)
	{
		seen = grub_calloc (data->num_items, sizeof (*seen));
		if (!seen)
		{
			rar_free_data (data);
			return grub_errno;
		}
	}

	for (i = 0; i < data->num_items; i++)
	{
		struct grub_dirhook_info info;
		const char *child;
		grub_size_t child_len;
		int child_is_dir;
		char *name;
		int dup = 0;

		if (!data->items[i].name)
			continue;
		if (!rar_name_in_dir (data->items[i].name, dir, dir_len,
				      &child, &child_len, &child_is_dir))
		{
			/* the path itself may be a stored directory entry */
			if (dir_len != 0
			    && grub_strcmp (data->items[i].name, dir) == 0)
				found = 1;
			continue;
		}
		found = 1;

		name = grub_malloc (child_len + 1);
		if (!name)
		{
			err = grub_errno;
			goto out;
		}
		grub_memcpy (name, child, child_len);
		name[child_len] = '\0';

		for (j = 0; j < num_seen; j++)
			if (grub_strcmp (seen[j], name) == 0)
			{
				dup = 1;
				break;
			}
		if (dup)
		{
			grub_free (name);
			continue;
		}
		seen[num_seen++] = name;

		grub_memset (&info, 0, sizeof (info));
		info.dir = child_is_dir || data->items[i].is_dir;
		info.inodeset = 1;
		info.inode = i;
		if (!child_is_dir)
		{
			info.symlink = data->items[i].is_link;
			info.mtimeset = data->items[i].mtime_set;
			info.mtime = data->items[i].mtime;
		}

		if (hook (name, &info, hook_data))
			goto out;
	}

	if (!found)
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
				  "file `%s' not found", path);

out:
	for (j = 0; j < num_seen; j++)
		grub_free (seen[j]);
	grub_free (seen);
	rar_free_data (data);
	return err;
}

/* ---------------- file reading ---------------- */

static grub_ssize_t
rar_input_read (void *opaque, void *buf, grub_size_t size)
{
	struct grub_rar_file *ctx = opaque;

	if (size > ctx->in_left)
		size = (grub_size_t) ctx->in_left;
	if (size == 0)
		return 0;
	if (grub_disk_read (ctx->data->disk, 0, ctx->in_pos, size, buf))
	{
		grub_errno = GRUB_ERR_NONE;
		ctx->io_err = 1;
		return -1;
	}
	ctx->in_pos += size;
	ctx->in_left -= size;
	return (grub_ssize_t) size;
}

static int
rar_output_sink (void *opaque, const grub_uint8_t *data, grub_size_t size)
{
	struct grub_rar_file *ctx = opaque;
	grub_size_t need;

	if (!ctx->collecting)
		return 0;

	/* drop everything below the requested start position */
	if (ctx->stream_pos + size <= ctx->skip_to)
	{
		ctx->stream_pos += size;
		return 0;
	}
	if (ctx->stream_pos < ctx->skip_to)
	{
		const grub_size_t drop = (grub_size_t) (ctx->skip_to
							- ctx->stream_pos);
		data += drop;
		size -= drop;
		ctx->stream_pos = ctx->skip_to;
		ctx->pend_pos = ctx->skip_to;
		ctx->pend_len = 0;
	}

	need = ctx->pend_len + size;
	if (need > ctx->pend_alloc)
	{
		grub_size_t n = ctx->pend_alloc ? ctx->pend_alloc : 65536;
		grub_uint8_t *tmp;
		while (n < need)
			n *= 2;
		tmp = grub_malloc (n);
		if (!tmp)
			return -1;
		if (ctx->pend_len)
			grub_memcpy (tmp, ctx->pend, ctx->pend_len);
		grub_free (ctx->pend);
		ctx->pend = tmp;
		ctx->pend_alloc = n;
	}
	grub_memcpy (ctx->pend + ctx->pend_len, data, size);
	ctx->pend_len += size;
	ctx->stream_pos += size;

	return (ctx->pend_len >= ctx->want) ? 1 : 0;
}

/*
 * Finds the first item of the solid chain that ends at index.  Stored
 * entries never feed the LZ window (7-Zip runs them through a plain copy
 * coder), so a stored target needs no replay at all.
 */
static unsigned
rar_chain_start (struct grub_rar_data *data, unsigned index)
{
	unsigned i = index;

	if (data->items[index].store)
		return index;
	while (i > 0 && data->items[i].is_solid)
		i--;
	return i;
}

/*
 * Starts decoding item `index`.  Directories and other zero-data entries
 * inside a solid chain are skipped by the caller.
 */
static int
rar_begin_item (struct grub_rar_file *ctx, unsigned index)
{
	struct grub_rar_item *item = &ctx->data->items[index];
	struct rar_dec_props props;
	int r;

	ctx->cur = index;
	ctx->collecting = (index == ctx->target);
	ctx->in_pos = item->data_pos;
	ctx->in_left = item->pack_size;

	if (item->store)
	{
		ctx->started = 1;
		return 0;
	}

	grub_memset (&props, 0, sizeof (props));
	/*
	 * Matches 7-Zip: the first item of a chain always decodes with a
	 * fresh window, even when its own solid flag is set.
	 */
	props.solid = item->is_solid && !ctx->solid_start;
	ctx->solid_start = 0;
	props.dict_main = item->dict_main;
	props.dict_frac = item->dict_frac;
	props.is_v7 = item->is_v7;
	props.unp_size = item->unp_size;
	props.pack_size = item->pack_size;

	r = ctx->dec->start_item (ctx->dec, &props);
	if (r)
		return r;
	ctx->started = 1;
	return 0;
}

/*
 * Moves to the next item that carries data, honouring 7-Zip's solidStart
 * rule.  Three kinds of entry never reach the decoder and so must not
 * disturb the solid stream: directories, entries with neither packed nor
 * unpacked data (7-Zip skips the coder for those), and stored entries
 * encountered while replaying a chain for a compressed target (stored
 * data goes through a copy coder and never enters the LZ window).
 * Sets *done when no such item remains up to and including the target.
 */
static int
rar_advance_item (struct grub_rar_file *ctx, unsigned from, int *done)
{
	struct grub_rar_data *data = ctx->data;
	const int target_store = data->items[ctx->target].store;
	unsigned i;

	*done = 0;
	for (i = from; i <= ctx->target; i++)
	{
		if (!data->items[i].is_solid)
			ctx->solid_start = 1;
		if (data->items[i].is_dir)
			continue;
		if (data->items[i].pack_size == 0
		    && data->items[i].unp_size == 0)
			continue;
		if (!target_store && data->items[i].store)
			continue;
		return rar_begin_item (ctx, i);
	}
	*done = 1;
	return 0;
}

/* copies stored data straight from the archive */
static int
rar_run_stored (struct grub_rar_file *ctx)
{
	grub_uint8_t buf[4096];
	int r;

	while (ctx->in_left != 0)
	{
		grub_ssize_t got = rar_input_read (ctx, buf, sizeof (buf));
		if (got < 0)
			return RAR_ERR_READ;
		if (got == 0)
			break;
		r = rar_output_sink (ctx, buf, (grub_size_t) got);
		if (r < 0)
			return RAR_ERR_WRITE;
		if (r > 0)
			return RAR_PAUSED;
	}
	return RAR_DONE;
}

static void
rar_reset_stream (struct grub_rar_file *ctx)
{
	rar_decoder_free (ctx->dec);
	ctx->dec = 0;
	ctx->started = 0;
	ctx->solid_start = 1;
	ctx->collecting = 0;
	ctx->finished = 0;
	ctx->stream_pos = 0;
	ctx->skip_to = 0;
	ctx->pend_len = 0;
	ctx->pend_pos = 0;
	ctx->io_err = 0;
}

static grub_err_t
rar_start_stream (struct grub_rar_file *ctx)
{
	struct grub_rar_data *data = ctx->data;
	struct grub_rar_item *item = &data->items[ctx->target];
	unsigned start, i;
	int done, r;

	rar_reset_stream (ctx);

	start = rar_chain_start (data, ctx->target);

	/*
	 * A solid chain shares one LZ window, so every compressed member of
	 * it must use the same compression family and be decodable.  7-Zip
	 * keeps one decoder per RAR version; that is not reproduced here.
	 */
	for (i = start; i < ctx->target; i++)
	{
		if (data->items[i].is_dir || data->items[i].store)
			continue;
		if (data->items[i].unsupported)
			return grub_error (GRUB_ERR_BAD_FS,
				"solid block contains an unreadable entry");
		if (data->items[i].algo != item->algo)
			return grub_error (GRUB_ERR_BAD_FS,
				"solid block mixes compression versions");
	}

	if (!item->store)
	{
		ctx->dec = rar_decoder_create (item->algo);
		if (!ctx->dec)
			return grub_error (GRUB_ERR_OUT_OF_MEMORY,
					   "out of memory");
		ctx->dec->read_cb = rar_input_read;
		ctx->dec->read_opaque = ctx;
		ctx->dec->sink_cb = rar_output_sink;
		ctx->dec->sink_opaque = ctx;
	}

	r = rar_advance_item (ctx, start, &done);
	if (r)
		return grub_error (GRUB_ERR_BAD_FS,
				   "cannot start rar decoder");
	if (done)
		ctx->finished = 1;	/* the entry carries no data */
	return GRUB_ERR_NONE;
}

/* runs the decoder until it pauses, finishes the target item, or fails */
static grub_err_t
rar_pump (struct grub_rar_file *ctx)
{
	struct grub_rar_data *data = ctx->data;
	int r;

	while (!ctx->finished)
	{
		struct grub_rar_item *item = &data->items[ctx->cur];

		if (item->store)
			r = rar_run_stored (ctx);
		else
			r = ctx->dec->run (ctx->dec);

		if (r == RAR_PAUSED)
			return GRUB_ERR_NONE;
		if (r == RAR_ERR_MEM || r == RAR_ERR_WRITE)
			return grub_error (GRUB_ERR_OUT_OF_MEMORY,
					   "out of memory");
		if (r == RAR_ERR_READ || ctx->io_err)
			return grub_error (GRUB_ERR_READ_ERROR,
					   "rar read error");
		if (r == RAR_ERR_UNSUP)
			return grub_error (GRUB_ERR_BAD_FS,
					   "unsupported rar filter");
		if (r != RAR_DONE)
			return grub_error (GRUB_ERR_BAD_FS,
					   "corrupt rar data");

		if (ctx->cur == ctx->target)
		{
			ctx->finished = 1;
			return GRUB_ERR_NONE;
		}
		{
			int done;
			r = rar_advance_item (ctx, ctx->cur + 1, &done);
			if (r)
				return grub_error (GRUB_ERR_BAD_FS,
					"cannot continue solid rar stream");
			if (done)
				ctx->finished = 1;
		}
	}
	return GRUB_ERR_NONE;
}

static int
rar_find_item (struct grub_rar_data *data, const char *name)
{
	grub_size_t len;
	const char *path = rar_norm_path (name, &len);
	unsigned i;

	for (i = 0; i < data->num_items; i++)
	{
		const char *n = data->items[i].name;
		if (!n)
			continue;
		if (grub_strlen (n) == len
		    && grub_strncmp (n, path, len) == 0)
			return (int) i;
	}
	return -1;
}

static grub_err_t
grub_rar_open (struct grub_file *file, const char *name)
{
	struct grub_rar_data *data;
	struct grub_rar_file *ctx = 0;
	int index;

	data = grub_rar_mount (file->device->disk);
	if (!data)
		return grub_errno;

	index = rar_find_item (data, name);
	if (index < 0)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found",
			    name);
		goto fail;
	}
	if (data->items[index].is_dir)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "is a directory");
		goto fail;
	}
	if (data->items[index].unsupported)
	{
		grub_error (GRUB_ERR_BAD_FS,
			    "encrypted, split or unsupported rar entry");
		goto fail;
	}

	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
		goto fail;
	ctx->data = data;
	ctx->target = (unsigned) index;

	if (rar_start_stream (ctx))
		goto fail;

	file->data = ctx;
	file->size = data->items[index].unp_size;
	file->not_easily_seekable = 1;
	return GRUB_ERR_NONE;

fail:
	if (ctx)
	{
		rar_decoder_free (ctx->dec);
		grub_free (ctx->pend);
		grub_free (ctx);
	}
	rar_free_data (data);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

static grub_ssize_t
grub_rar_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_rar_file *ctx = file->data;
	grub_uint64_t off = file->offset;
	grub_size_t done = 0;

	if (len == 0)
		return 0;

	if (off < ctx->pend_pos)
	{
		if (rar_start_stream (ctx))
			return -1;
	}

	while (done < len)
	{
		const grub_uint64_t want_pos = off + done;

		if (want_pos >= ctx->pend_pos
		    && want_pos < ctx->pend_pos + ctx->pend_len)
		{
			const grub_size_t skip = (grub_size_t)
				(want_pos - ctx->pend_pos);
			grub_size_t n = ctx->pend_len - skip;
			if (n > len - done)
				n = len - done;
			grub_memcpy (buf + done, ctx->pend + skip, n);
			done += n;
			continue;
		}

		if (ctx->finished)
			break;

		/* the pending window is consumed; ask for more output */
		ctx->pend_pos = ctx->stream_pos;
		ctx->pend_len = 0;
		ctx->skip_to = want_pos;
		ctx->want = len - done;

		if (rar_pump (ctx))
			return -1;

		if (ctx->pend_len == 0 && ctx->finished)
			break;
		if (ctx->pend_len == 0 && ctx->stream_pos <= want_pos)
			break;
	}

	return (grub_ssize_t) done;
}

static grub_err_t
grub_rar_close (grub_file_t file)
{
	struct grub_rar_file *ctx = file->data;

	if (ctx)
	{
		rar_decoder_free (ctx->dec);
		grub_free (ctx->pend);
		rar_free_data (ctx->data);
		grub_free (ctx);
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_rar_label (grub_device_t device, char **label)
{
	struct grub_rar_data *data;

	*label = 0;
	data = grub_rar_mount (device->disk);
	if (!data)
		return grub_errno;
	*label = grub_strdup (data->is_rar5 ? "RAR5" : "RAR");
	rar_free_data (data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_rar_mtime (grub_device_t device, grub_int64_t *tm)
{
	struct grub_rar_data *data;
	unsigned i;

	*tm = 0;
	data = grub_rar_mount (device->disk);
	if (!data)
		return grub_errno;
	for (i = 0; i < data->num_items; i++)
		if (data->items[i].mtime > *tm)
			*tm = data->items[i].mtime;
	rar_free_data (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_rar_fs =
{
	.name = "rar",
	.fs_dir = grub_rar_dir,
	.fs_open = grub_rar_open,
	.fs_read = grub_rar_read,
	.fs_close = grub_rar_close,
	.fs_label = grub_rar_label,
	.fs_mtime = grub_rar_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (rar)
{
	grub_rar_fs.mod = mod;
	grub_fs_register (&grub_rar_fs);
}

GRUB_MOD_FINI (rar)
{
	grub_fs_unregister (&grub_rar_fs);
}
