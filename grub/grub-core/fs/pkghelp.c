/* pkghelp.c -- Linux software package helper functions */
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

#include <grub/pkghelp.h>
#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/deflate.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define PKG_MAX_ENTRIES		(1u << 20)
#define PKG_MAX_NAME		(1u << 14)
#define PKG_MAX_PAX		(1u << 16)
#define PKG_SEEN_BUCKETS	256
#define PKG_SIG_SIZE		512

/* Entry list */

void
grub_pkg_truncate_entries (struct grub_pkg_data *data, unsigned num)
{
	while (data->num_entries > num)
	{
		struct grub_pkg_entry *ent = &data->entries[--data->num_entries];

		grub_free (ent->name);
		grub_free (ent->target);
	}
}

static void
pkg_free_data (struct grub_pkg_data *data)
{
	grub_pkg_truncate_entries (data, 0);
	grub_free (data->entries);
	grub_free (data->label);
	grub_free (data);
}

struct grub_pkg_entry *
grub_pkg_new_entry (struct grub_pkg_data *data, char *name)
{
	struct grub_pkg_entry *ent;

	if (data->num_entries == data->max_entries)
	{
		unsigned num = data->max_entries ? data->max_entries * 2 : 64;
		struct grub_pkg_entry *grown;

		if (num > PKG_MAX_ENTRIES)
		{
			grub_free (name);
			grub_error (GRUB_ERR_BAD_FS, "too many files in package");
			return 0;
		}
		grown = grub_realloc (data->entries, num * sizeof (*grown));
		if (!grown)
		{
			grub_free (name);
			return 0;
		}
		data->entries = grown;
		data->max_entries = num;
	}

	ent = &data->entries[data->num_entries++];
	grub_memset (ent, 0, sizeof (*ent));
	ent->name = name;
	ent->stream = GRUB_PKG_STREAM_RAW;
	return ent;
}

int
grub_pkg_add_stream (struct grub_pkg_data *data, grub_off_t off, grub_off_t len)
{
	if (data->num_streams >= GRUB_PKG_MAX_STREAMS)
		return -1;
	data->streams[data->num_streams].off = off;
	data->streams[data->num_streams].len = len;
	return (int) data->num_streams++;
}

void
grub_pkg_drop_stream (struct grub_pkg_data *data)
{
	if (data->num_streams)
		data->num_streams--;
}

grub_err_t
grub_pkg_norm_name (const char *prefix, const char *raw, char **out)
{
	grub_size_t plen = prefix ? grub_strlen (prefix) : 0;
	grub_size_t rlen = grub_strlen (raw);
	const char *src;
	char *buf, *dst;

	*out = NULL;
	if (rlen > PKG_MAX_NAME)
		return grub_error (GRUB_ERR_BAD_FS, "file name too long");

	buf = grub_malloc (plen + rlen + 2);
	if (!buf)
		return grub_errno;

	dst = buf;
	if (plen)
	{
		grub_memcpy (dst, prefix, plen);
		dst += plen;
	}

	for (src = raw; *src; )
	{
		const char *comp = src;
		grub_size_t clen;

		while (*src && *src != '/')
			src++;
		clen = (grub_size_t) (src - comp);
		while (*src == '/')
			src++;
		if (clen == 0 || (clen == 1 && comp[0] == '.'))
			continue;
		if (dst != buf)
			*dst++ = '/';
		grub_memcpy (dst, comp, clen);
		dst += clen;
	}
	*dst = '\0';

	if (dst == buf)
	{
		grub_free (buf);
		return GRUB_ERR_NONE;
	}
	*out = buf;
	return GRUB_ERR_NONE;
}

/*
 * Entry list cache.  One slot for all package filesystems: the GUI sizes a
 * directory listing by opening every entry in turn, which all hits the same
 * disk, so the slot stays warm through the access pattern that matters.
 * Alternating between a deb and an rpm device only costs a re-parse.
 */

struct pkg_cache
{
	struct grub_pkg_ops *ops;
	char *name;
	unsigned long id;
	grub_uint64_t size;
	grub_size_t siglen;
	grub_uint8_t sig[PKG_SIG_SIZE];
	struct grub_pkg_data *data;
};

static struct pkg_cache pkg_cache;

static void
pkg_cache_clear (void)
{
	if (pkg_cache.data)
		pkg_free_data (pkg_cache.data);
	grub_free (pkg_cache.name);
	grub_memset (&pkg_cache, 0, sizeof (pkg_cache));
}

void
grub_pkg_cache_release (struct grub_pkg_ops *ops)
{
	if (pkg_cache.ops == ops)
		pkg_cache_clear ();
}

static void
pkg_cache_store (grub_disk_t disk, struct grub_pkg_ops *ops,
		 const grub_uint8_t *sig, grub_size_t siglen,
		 grub_uint64_t size, struct grub_pkg_data *data)
{
	char *name = grub_strdup (disk->name);

	/* caching is an optimisation: carry on uncached when out of memory */
	if (!name)
	{
		grub_errno = GRUB_ERR_NONE;
		return;
	}
	pkg_cache_clear ();
	pkg_cache.ops = ops;
	pkg_cache.name = name;
	pkg_cache.id = disk->id;
	pkg_cache.size = size;
	pkg_cache.siglen = siglen;
	grub_memcpy (pkg_cache.sig, sig, siglen);
	pkg_cache.data = data;
}

static struct grub_pkg_data *
pkg_mount (grub_disk_t disk, struct grub_pkg_ops *ops)
{
	struct grub_pkg_data *data;
	grub_uint8_t sig[PKG_SIG_SIZE];
	grub_uint64_t sectors, size;
	grub_size_t siglen;
	grub_err_t err;

	sectors = grub_disk_native_sectors (disk);
	size = (sectors == GRUB_DISK_SIZE_UNKNOWN)
	       ? GRUB_DISK_SIZE_UNKNOWN : sectors << GRUB_DISK_SECTOR_BITS;
	siglen = (size < PKG_SIG_SIZE) ? (grub_size_t) size : PKG_SIG_SIZE;
	if (siglen == 0 || grub_disk_read (disk, 0, 0, siglen, sig))
	{
		grub_error (GRUB_ERR_BAD_FS, "not a %s archive", ops->name);
		return 0;
	}

	if (pkg_cache.data && pkg_cache.ops == ops && pkg_cache.id == disk->id
	    && pkg_cache.size == size && pkg_cache.siglen == siglen
	    && grub_memcmp (pkg_cache.sig, sig, siglen) == 0
	    && grub_strcmp (pkg_cache.name, disk->name) == 0)
	{
		pkg_cache.data->disk = disk;
		grub_errno = GRUB_ERR_NONE;
		return pkg_cache.data;
	}

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return 0;
	data->disk = disk;
	data->disk_size = size;

	if (ops->parse (data))
	{
		err = grub_errno;
		pkg_free_data (data);
		grub_errno = err ? err : GRUB_ERR_BAD_FS;
		return 0;
	}

	pkg_cache_store (disk, ops, sig, siglen, size, data);
	grub_errno = GRUB_ERR_NONE;
	return data;
}

static void
pkg_unmount (struct grub_pkg_data *data)
{
	if (data != pkg_cache.data)
		pkg_free_data (data);
}

/* Payload streams */

struct pkg_diskfile
{
	grub_disk_t disk;
};

static grub_ssize_t
pkg_disk_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct pkg_diskfile *df = file->data;

	if (grub_disk_read (df->disk, 0, file->offset, len, buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
pkg_disk_close (grub_file_t file)
{
	grub_free (file->data);
	/* the disk belongs to the caller, never to this file */
	file->device = 0;
	return GRUB_ERR_NONE;
}

static struct grub_fs pkg_disk_fs =
{
	.name = "pkgdisk",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = pkg_disk_read,
	.fs_close = pkg_disk_close,
	.fs_label = 0,
	.next = 0
};

/* wraps the raw byte range RAW in the decoder CODEC names */
static grub_file_t
pkg_codec_open (grub_file_t raw, int codec, grub_off_t size)
{
	grub_file_filter_id_t id;
	grub_file_t file;

	switch (codec)
	{
	case GRUB_PKG_CODEC_ZLIB:
		return grub_zlibio_open (raw, size);
	case GRUB_PKG_CODEC_BZIP2:
		id = GRUB_FILE_FILTER_BZ2IO;
		break;
	case GRUB_PKG_CODEC_XZ:
		id = GRUB_FILE_FILTER_XZIO;
		break;
	default:
		return 0;
	}

	if (!grub_file_filters[id])
		return 0;
	file = grub_file_filters[id] (raw, GRUB_FILE_TYPE_NONE);
	/* a filter hands its argument back when the stream is not its own */
	if (file == raw)
		return 0;
	if (file)
		file->size = size;	/* the index knows better than the stream */
	return file;
}

/*
 * Opens the byte range [OFF, OFF + LEN) of DISK as a decompressed file.
 * CODEC < 0 leaves the choice to the whole compression filter chain, which
 * is what a deb or rpm payload needs; otherwise exactly one decoder runs
 * and SIZE is the length it has to produce.
 */
static grub_file_t
pkg_range_open (grub_disk_t disk, grub_uint64_t disk_size,
		grub_off_t off, grub_off_t len, int codec, grub_off_t size)
{
	struct pkg_diskfile *df;
	grub_file_t base, raw, file;
	enum grub_file_type type;

	df = grub_zalloc (sizeof (*df));
	if (!df)
		return 0;
	base = grub_zalloc (sizeof (*base));
	if (!base)
	{
		grub_free (df);
		return 0;
	}

	df->disk = disk;
	base->fs = &pkg_disk_fs;
	base->data = df;
	base->size = disk_size;

	type = (codec < 0) ? GRUB_FILE_TYPE_NONE : GRUB_FILE_TYPE_NO_DECOMPRESS;
	raw = grub_file_offset_open (base, type, off, len);
	if (!raw)
	{
		grub_file_close (base);
		return 0;
	}
	if (codec < 0 || codec == GRUB_PKG_CODEC_NONE)
		return raw;

	file = pkg_codec_open (raw, codec, size);
	if (!file)
	{
		grub_file_close (raw);
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
			    "cannot decode the package payload");
		return 0;
	}
	return file;
}

grub_file_t
grub_pkg_stream_open (struct grub_pkg_data *data, int stream)
{
	return pkg_range_open (data->disk, data->disk_size,
			       data->streams[stream].off,
			       data->streams[stream].len, -1, 0);
}

/* replaces *OUT with SIZE bytes read at OFF, NUL terminated */
static grub_err_t
pkg_read_string (grub_file_t file, grub_off_t off, grub_off_t size, char **out)
{
	char *str;

	grub_free (*out);
	*out = NULL;
	if (size > PKG_MAX_NAME)
		return grub_error (GRUB_ERR_BAD_FS, "file name too long");

	str = grub_malloc ((grub_size_t) size + 1);
	if (!str)
		return grub_errno;
	if (grub_file_seek (file, off) == (grub_off_t) -1
	    || grub_file_read (file, str, (grub_size_t) size)
	       != (grub_ssize_t) size)
	{
		grub_free (str);
		return grub_error (GRUB_ERR_BAD_FS, "truncated package payload");
	}
	str[size] = '\0';
	*out = str;
	return GRUB_ERR_NONE;
}

/* tar payload */

#define PKG_TAR_BLOCK		512
/* prefix[155] + '/' + name[100] + NUL */
#define PKG_TAR_NAME_MAX	258

PRAGMA_BEGIN_PACKED
struct pkg_tar_head
{
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
	char pad[12];
} GRUB_PACKED;
PRAGMA_END_PACKED

/* octal, or GNU base 256 when the top bit of the first byte is set */
static grub_uint64_t
pkg_tar_number (const char *str, grub_size_t size)
{
	grub_uint64_t ret = 0;
	grub_size_t i;

	if ((grub_uint8_t) str[0] & 0x80)
	{
		for (i = (size > 8) ? size - 8 : 0; i < size; i++)
			ret = (ret << 8) | (grub_uint8_t) str[i];
		return ret;
	}

	for (i = 0; i < size && (str[i] == ' ' || str[i] == '\0'); i++)
		;
	for (; i < size && str[i] >= '0' && str[i] <= '7'; i++)
		ret = (ret << 3) | (grub_uint64_t) (str[i] - '0');
	return ret;
}

static int
pkg_tar_is_zero (const struct pkg_tar_head *hd)
{
	const grub_uint8_t *ptr = (const grub_uint8_t *) hd;
	grub_size_t i;

	for (i = 0; i < sizeof (*hd); i++)
		if (ptr[i])
			return 0;
	return 1;
}

/* length of a header field that is only NUL terminated when it is short */
static grub_size_t
pkg_field_len (const char *field, grub_size_t size)
{
	grub_size_t len = 0;

	while (len < size && field[len])
		len++;
	return len;
}

/* pulls the "path" record out of a pax extended header */
static grub_err_t
pkg_read_pax (grub_file_t file, grub_off_t off, grub_off_t size, char **out)
{
	char *buf, *pos, *end;

	grub_free (*out);
	*out = NULL;
	if (size == 0)
		return GRUB_ERR_NONE;
	if (size > PKG_MAX_PAX)
		return grub_error (GRUB_ERR_BAD_FS, "pax header too long");

	buf = grub_malloc ((grub_size_t) size + 1);
	if (!buf)
		return grub_errno;
	if (grub_file_seek (file, off) == (grub_off_t) -1
	    || grub_file_read (file, buf, (grub_size_t) size)
	       != (grub_ssize_t) size)
	{
		grub_free (buf);
		return grub_error (GRUB_ERR_BAD_FS, "truncated pax header");
	}
	buf[size] = '\0';

	/* records are "<decimal length> <key>=<value>\n" */
	pos = buf;
	end = buf + size;
	while (pos < end)
	{
		char *rec = pos;
		char *eq;
		grub_size_t len = 0;

		while (pos < end && *pos >= '0' && *pos <= '9')
			len = len * 10 + (grub_size_t) (*pos++ - '0');
		if (pos == rec || pos >= end || *pos != ' ')
			break;
		if (len < (grub_size_t) (pos - rec) + 2
		    || len > (grub_size_t) (end - rec))
			break;
		pos++;
		rec[len - 1] = '\0';	/* the trailing newline */

		eq = grub_strchr (pos, '=');
		if (eq)
		{
			*eq = '\0';
			if (grub_strcmp (pos, "path") == 0)
			{
				grub_free (*out);
				*out = grub_strdup (eq + 1);
				if (!*out)
				{
					grub_free (buf);
					return grub_errno;
				}
			}
		}
		pos = rec + len;
	}

	grub_free (buf);
	return GRUB_ERR_NONE;
}

grub_err_t
grub_pkg_scan_tar (struct grub_pkg_data *data, int stream, const char *prefix)
{
	char namebuf[PKG_TAR_NAME_MAX];
	char *longname = NULL, *longlink = NULL, *paxname = NULL, *name;
	grub_file_t file;
	grub_off_t pos = 0;
	grub_err_t err = GRUB_ERR_NONE;
	int first = 1;

	file = grub_pkg_stream_open (data, stream);
	if (!file)
		return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;

	for (;;)
	{
		struct pkg_tar_head hd;
		struct grub_pkg_entry *ent;
		const char *raw, *link;
		grub_off_t size, dofs;

		if (grub_file_seek (file, pos) == (grub_off_t) -1
		    || grub_file_read (file, &hd, sizeof (hd))
		       != (grub_ssize_t) sizeof (hd))
		{
			grub_errno = GRUB_ERR_NONE;
			if (first)
				err = grub_error (GRUB_ERR_BAD_FS,
						  "not a tar payload");
			break;
		}

		if (grub_memcmp (hd.magic, "ustar", 5) != 0)
		{
			/* the archive ends with zero filled blocks */
			if (!first && pkg_tar_is_zero (&hd))
				break;
			err = grub_error (GRUB_ERR_BAD_FS, "not a tar payload");
			break;
		}
		first = 0;

		size = pkg_tar_number (hd.size, sizeof (hd.size));
		if (size > GRUB_PKG_MAX_SIZE)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "tar size overflow");
			break;
		}
		dofs = pos + PKG_TAR_BLOCK;

		if (hd.typeflag == 'L')		/* GNU long name */
		{
			err = pkg_read_string (file, dofs, size, &longname);
			if (err)
				break;
			goto next;
		}
		if (hd.typeflag == 'K')		/* GNU long link target */
		{
			err = pkg_read_string (file, dofs, size, &longlink);
			if (err)
				break;
			goto next;
		}
		if (hd.typeflag == 'x')		/* pax header for this entry */
		{
			err = pkg_read_pax (file, dofs, size, &paxname);
			if (err)
				break;
			goto next;
		}
		if (hd.typeflag == 'g')		/* global pax header */
			goto next;

		raw = paxname ? paxname : longname;
		if (!raw)
		{
			char *dst = namebuf;

			/*
			 * Only POSIX ustar splits long names into
			 * prefix + name; GNU tar (magic "ustar  ") keeps
			 * unrelated data in that area.
			 */
			if (hd.magic[5] == '\0' && hd.prefix[0])
			{
				grub_size_t plen;

				plen = pkg_field_len (hd.prefix,
						      sizeof (hd.prefix));
				grub_memcpy (dst, hd.prefix, plen);
				dst += plen;
				*dst++ = '/';
			}
			grub_memcpy (dst, hd.name, sizeof (hd.name));
			dst[sizeof (hd.name)] = '\0';
			raw = namebuf;
		}

		err = grub_pkg_norm_name (prefix, raw, &name);
		if (err)
			break;
		if (!name)
			goto next;

		ent = grub_pkg_new_entry (data, name);
		if (!ent)
		{
			err = grub_errno;
			break;
		}
		ent->mtime = (grub_int64_t) pkg_tar_number (hd.mtime,
							    sizeof (hd.mtime));

		if (hd.typeflag == '5')
		{
			ent->is_dir = 1;
			ent->stream = GRUB_PKG_STREAM_MEM;
		}
		else if (hd.typeflag == '1' || hd.typeflag == '2')
		{
			link = longlink;
			if (!link)
			{
				grub_memcpy (namebuf, hd.linkname,
					     sizeof (hd.linkname));
				namebuf[sizeof (hd.linkname)] = '\0';
				link = namebuf;
			}
			ent->target = grub_strdup (link);
			if (!ent->target)
			{
				err = grub_errno;
				break;
			}
			ent->is_lnk = 1;
			ent->stream = GRUB_PKG_STREAM_MEM;
			ent->size = grub_strlen (ent->target);
		}
		else
		{
			ent->stream = stream;
			ent->off = dofs;
			ent->size = size;
		}

	next:
		pos = dofs + ((size + PKG_TAR_BLOCK - 1)
			      & ~(grub_off_t) (PKG_TAR_BLOCK - 1));
		if (hd.typeflag != 'L' && hd.typeflag != 'K'
		    && hd.typeflag != 'x')
		{
			grub_free (longname);
			grub_free (longlink);
			grub_free (paxname);
			longname = longlink = paxname = NULL;
		}
	}

	grub_free (longname);
	grub_free (longlink);
	grub_free (paxname);
	grub_file_close (file);
	return err;
}

/* cpio payload */

#define PKG_CPIO_NEWC_HEAD	110	/* "new ASCII", hex fields */
#define PKG_CPIO_ODC_HEAD	76	/* "portable ASCII", octal fields */
#define PKG_CPIO_NAME_MAX	4096

#define PKG_S_IFMT		0170000
#define PKG_S_IFDIR		0040000
#define PKG_S_IFLNK		0120000

static grub_uint64_t
pkg_cpio_hex (const grub_uint8_t *str, grub_size_t size)
{
	grub_uint64_t ret = 0;
	grub_size_t i;

	for (i = 0; i < size && grub_isxdigit (str[i]); i++)
	{
		grub_uint8_t dig = str[i];

		if (dig >= '0' && dig <= '9')
			dig = (grub_uint8_t) (dig - '0');
		else if (dig >= 'a' && dig <= 'f')
			dig = (grub_uint8_t) (dig - 'a' + 10);
		else
			dig = (grub_uint8_t) (dig - 'A' + 10);
		ret = (ret << 4) | dig;
	}
	return ret;
}

static grub_uint64_t
pkg_cpio_oct (const grub_uint8_t *str, grub_size_t size)
{
	grub_uint64_t ret = 0;
	grub_size_t i;

	for (i = 0; i < size && str[i] >= '0' && str[i] <= '7'; i++)
		ret = (ret << 3) | (grub_uint64_t) (str[i] - '0');
	return ret;
}

grub_err_t
grub_pkg_scan_cpio (struct grub_pkg_data *data, int stream, const char *prefix)
{
	grub_uint8_t hd[PKG_CPIO_NEWC_HEAD];
	char *raw = NULL, *name;
	grub_file_t file;
	grub_off_t pos = 0;
	grub_err_t err = GRUB_ERR_NONE;
	int first = 1;

	file = grub_pkg_stream_open (data, stream);
	if (!file)
		return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;

	for (;;)
	{
		struct grub_pkg_entry *ent;
		grub_off_t size, nsize, dofs, align;
		grub_uint64_t mode, mtime;
		grub_size_t hlen;

		/*
		 * The magic is read on its own so that the rest of the
		 * header can be sized to the format: reading more than
		 * that would put the name behind the stream position, and
		 * seeking back re-runs the decompressor from the start.
		 */
		if (grub_file_seek (file, pos) == (grub_off_t) -1
		    || grub_file_read (file, hd, 6) != 6)
			goto eof;

		if (grub_memcmp (hd, "070701", 6) == 0
		    || grub_memcmp (hd, "070702", 6) == 0)
		{
			hlen = PKG_CPIO_NEWC_HEAD;
			align = 4;
		}
		else if (grub_memcmp (hd, "070707", 6) == 0)
		{
			hlen = PKG_CPIO_ODC_HEAD;
			align = 1;
		}
		else
			goto eof;

		if (grub_file_read (file, hd + 6, hlen - 6)
		    != (grub_ssize_t) (hlen - 6))
			goto eof;
		first = 0;

		if (align == 4)
		{
			mode = pkg_cpio_hex (hd + 14, 8);
			mtime = pkg_cpio_hex (hd + 46, 8);
			size = pkg_cpio_hex (hd + 54, 8);
			nsize = pkg_cpio_hex (hd + 94, 8);
		}
		else
		{
			mode = pkg_cpio_oct (hd + 18, 6);
			mtime = pkg_cpio_oct (hd + 48, 11);
			nsize = pkg_cpio_oct (hd + 59, 6);
			size = pkg_cpio_oct (hd + 65, 11);
		}

		if (nsize == 0 || nsize > PKG_CPIO_NAME_MAX
		    || size > GRUB_PKG_MAX_SIZE)
		{
			err = grub_error (GRUB_ERR_BAD_FS,
					  "corrupt cpio payload");
			break;
		}

		err = pkg_read_string (file, pos + hlen, nsize - 1, &raw);
		if (err)
			break;
		dofs = (pos + hlen + nsize + align - 1) & ~(align - 1);

		if (grub_strcmp (raw, "TRAILER!!!") == 0)
			break;

		err = grub_pkg_norm_name (prefix, raw, &name);
		if (err)
			break;
		if (!name)
			goto next;

		ent = grub_pkg_new_entry (data, name);
		if (!ent)
		{
			err = grub_errno;
			break;
		}
		ent->mtime = (grub_int64_t) mtime;

		if ((mode & PKG_S_IFMT) == PKG_S_IFDIR)
		{
			ent->is_dir = 1;
			ent->stream = GRUB_PKG_STREAM_MEM;
		}
		else if ((mode & PKG_S_IFMT) == PKG_S_IFLNK)
		{
			/* a cpio symlink keeps its target in the file data */
			err = pkg_read_string (file, dofs, size, &ent->target);
			if (err)
				break;
			ent->is_lnk = 1;
			ent->stream = GRUB_PKG_STREAM_MEM;
			ent->size = grub_strlen (ent->target);
		}
		else
		{
			ent->stream = stream;
			ent->off = dofs;
			ent->size = size;
		}

	next:
		pos = (dofs + size + align - 1) & ~(align - 1);
		continue;

	eof:
		/* a payload that never held a header is not a cpio at all */
		grub_errno = GRUB_ERR_NONE;
		if (first)
			err = grub_error (GRUB_ERR_BAD_FS, "not a cpio payload");
		break;
	}

	grub_free (raw);
	grub_file_close (file);
	return err;
}

/* Directory tree over the flat entry list */

/* skips leading slashes and returns the normalized path length */
static const char *
pkg_norm_path (const char *path, grub_size_t *len)
{
	grub_size_t num;

	while (*path == '/')
		path++;
	num = grub_strlen (path);
	while (num > 0 && path[num - 1] == '/')
		num--;
	*len = num;
	return path;
}

static int
pkg_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
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

struct pkg_seen
{
	struct pkg_seen *next;
	char *name;
};

static grub_uint32_t
pkg_hash_name (const char *str)
{
	grub_uint32_t hash = 5381;

	while (*str)
		hash = hash * 33 + (grub_uint8_t) *str++;
	return hash & (PKG_SEEN_BUCKETS - 1);
}

/* returns 1 when the name was seen before, -1 on allocation failure */
static int
pkg_seen_add (struct pkg_seen **buckets, char *name)
{
	const grub_uint32_t hash = pkg_hash_name (name);
	struct pkg_seen *ent;

	for (ent = buckets[hash]; ent; ent = ent->next)
		if (grub_strcmp (ent->name, name) == 0)
			return 1;
	ent = grub_malloc (sizeof (*ent));
	if (!ent)
		return -1;
	ent->name = name;
	ent->next = buckets[hash];
	buckets[hash] = ent;
	return 0;
}

grub_err_t
grub_pkg_dir (grub_device_t device, struct grub_pkg_ops *ops,
	      const char *path, grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_pkg_data *data;
	struct pkg_seen **buckets;
	const char *dir;
	grub_size_t dir_len;
	unsigned i;
	int found;
	grub_err_t err = GRUB_ERR_NONE;

	data = pkg_mount (device->disk, ops);
	if (!data)
		return grub_errno;

	dir = pkg_norm_path (path, &dir_len);
	found = (dir_len == 0);

	buckets = grub_calloc (PKG_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		pkg_unmount (data);
		return grub_errno;
	}

	for (i = 0; i < data->num_entries; i++)
	{
		const struct grub_pkg_entry *entry = &data->entries[i];
		struct grub_dirhook_info info;
		const char *child;
		grub_size_t child_len;
		int child_is_dir;
		char *name;
		int dup;

		if (!pkg_name_in_dir (entry->name, dir, dir_len,
				      &child, &child_len, &child_is_dir))
		{
			if (dir_len != 0 && grub_strcmp (entry->name, dir) == 0)
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

		dup = pkg_seen_add (buckets, name);
		if (dup)
		{
			grub_free (name);
			if (dup < 0)
			{
				err = grub_errno;
				goto out;
			}
			continue;
		}

		grub_memset (&info, 0, sizeof (info));
		info.dir = child_is_dir || entry->is_dir;
		info.inodeset = 1;
		info.inode = i;
		if (!child_is_dir)
		{
			info.symlink = entry->is_lnk;
			if (!info.dir && !info.symlink)
			{
				info.sizeset = 1;
				info.size = entry->size;
			}
			if (entry->mtime != 0)
			{
				info.mtimeset = 1;
				info.mtime = entry->mtime;
			}
		}

		if (hook (name, &info, hook_data))
			goto out;
	}

	if (!found)
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
				  "file `%s' not found", path);

out:
	for (i = 0; i < PKG_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct pkg_seen *ent = buckets[i];

			buckets[i] = ent->next;
			grub_free (ent->name);
			grub_free (ent);
		}
	grub_free (buckets);
	pkg_unmount (data);
	return err;
}

int
grub_pkg_find_entry (struct grub_pkg_data *data, const char *name)
{
	grub_size_t len;
	const char *path = pkg_norm_path (name, &len);
	unsigned i;

	for (i = 0; i < data->num_entries; i++)
	{
		const char *cur = data->entries[i].name;

		if (grub_strncmp (cur, path, len) == 0 && cur[len] == '\0')
			return (int) i;
	}
	return -1;
}

/* File access */

struct pkg_file
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct grub_pkg_stream range;
	grub_off_t data_off;
	grub_off_t size;
	grub_file_t stream;	/* opened on the first read */
	char *mem;
	int kind;
	int codec;		/* -1 = whatever the filter chain detects */
};

grub_err_t
grub_pkg_open (grub_file_t file, struct grub_pkg_ops *ops, const char *name)
{
	struct grub_pkg_data *data;
	struct grub_pkg_entry *ent;
	struct pkg_file *ctx;
	int index;

	data = pkg_mount (file->device->disk, ops);
	if (!data)
		return grub_errno;

	index = grub_pkg_find_entry (data, name);
	if (index < 0)
	{
		pkg_unmount (data);
		return grub_error (GRUB_ERR_FILE_NOT_FOUND,
				   "file `%s' not found", name);
	}

	ent = &data->entries[index];
	if (ent->is_dir)
	{
		pkg_unmount (data);
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "is a directory");
	}

	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
	{
		pkg_unmount (data);
		return grub_errno;
	}

	/*
	 * Everything the read path needs is copied out: an open file must
	 * not point into the entry list, which the cache may drop.
	 */
	ctx->disk = data->disk;
	ctx->disk_size = data->disk_size;
	ctx->data_off = ent->off;
	ctx->size = ent->size;
	ctx->kind = ent->stream;
	ctx->codec = -1;
	if (ent->stream == GRUB_PKG_STREAM_MEM)
	{
		ctx->mem = grub_strdup (ent->target ? ent->target : "");
		if (!ctx->mem)
		{
			grub_free (ctx);
			pkg_unmount (data);
			return grub_errno;
		}
	}
	else if (ent->stream == GRUB_PKG_STREAM_SUB)
	{
		/* the whole range is this one file, so it starts at zero */
		ctx->range.off = ent->off;
		ctx->range.len = ent->plen;
		ctx->data_off = 0;
		ctx->codec = ent->codec;
	}
	else if (ent->stream >= 0)
		ctx->range = data->streams[ent->stream];

	file->data = ctx;
	file->size = ent->size;
	file->not_easily_seekable = (ent->stream >= 0
				     || ent->stream == GRUB_PKG_STREAM_SUB);
	pkg_unmount (data);
	return GRUB_ERR_NONE;
}

grub_ssize_t
grub_pkg_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct pkg_file *ctx = file->data;
	grub_ssize_t ret;

	if (len == 0)
		return 0;

	if (ctx->kind == GRUB_PKG_STREAM_MEM)
	{
		grub_memcpy (buf, ctx->mem + file->offset, len);
		ret = (grub_ssize_t) len;
	}
	else if (ctx->kind == GRUB_PKG_STREAM_RAW)
	{
		if (grub_disk_read (ctx->disk, 0, ctx->data_off + file->offset,
				    len, buf))
			return -1;
		ret = (grub_ssize_t) len;
	}
	else
	{
		if (!ctx->stream)
		{
			ctx->stream = pkg_range_open (ctx->disk, ctx->disk_size,
						      ctx->range.off,
						      ctx->range.len,
						      ctx->codec, ctx->size);
			if (!ctx->stream)
				return -1;
		}
		if (grub_file_seek (ctx->stream, ctx->data_off + file->offset)
		    == (grub_off_t) -1)
			return -1;
		ret = grub_file_read (ctx->stream, buf, len);
		if (ret < 0)
			return -1;
	}

	/*
	 * Nothing above reaches the disk read hook, so report the bytes
	 * handed out here to keep grub_file_progress_hook working.
	 */
	if (ret > 0 && file->read_hook)
		file->read_hook (0, 0, (unsigned) ret, buf,
				 file->read_hook_data);
	return ret;
}

grub_err_t
grub_pkg_close (grub_file_t file)
{
	struct pkg_file *ctx = file->data;

	if (ctx->stream)
		grub_file_close (ctx->stream);
	grub_free (ctx->mem);
	grub_free (ctx);
	return GRUB_ERR_NONE;
}

grub_err_t
grub_pkg_label (grub_device_t device, struct grub_pkg_ops *ops, char **label)
{
	struct grub_pkg_data *data;

	*label = NULL;
	data = pkg_mount (device->disk, ops);
	if (!data)
		return grub_errno;
	if (data->label)
		*label = grub_strdup (data->label);
	pkg_unmount (data);
	return GRUB_ERR_NONE;
}

grub_err_t
grub_pkg_mtime (grub_device_t device, struct grub_pkg_ops *ops,
		grub_int64_t *tm)
{
	struct grub_pkg_data *data;

	*tm = 0;
	data = pkg_mount (device->disk, ops);
	if (!data)
		return grub_errno;
	*tm = data->mtime;
	pkg_unmount (data);
	return GRUB_ERR_NONE;
}
