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
 *  Read-only RPM package (.rpm / .srpm) filesystem driver.
 *
 *  An rpm is a 96 byte lead, an optional signature header, the main
 *  header and finally the payload: a cpio archive compressed with gzip,
 *  xz, zstd, lzo, lz4 or nothing at all.  Header parsing follows 7-Zip
 *  26.02 (CPP\7zip\Archive\RpmHandler.cpp); the payload is expanded in
 *  place by grub-core\fs\pkghelp.c, so a package browses straight as the
 *  file tree it installs (/usr/bin/..., /etc/...).
 *
 *  Only the few header tags that name the package are read, so the
 *  (frequently large) rest of the header costs nothing.  The volume
 *  label is the usual name-version-release.arch.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/pkghelp.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define RPM_LEAD_SIZE		96
#define RPM_LEAD_NAME		66
#define RPM_LEAD_MAGIC		0xedabeedbU
#define RPM_HEAD_MAGIC		0x8eade801U
#define RPM_HEAD_INTRO		16
#define RPM_ENTRY_SIZE		16
#define RPM_MAX_ENTRIES		(1u << 16)
#define RPM_MAX_HEADER		(1u << 28)
#define RPM_MAX_STRING		1024
#define RPM_PGP262_SIZE		256

/* lead signature types */
#define RPM_SIG_NONE		0
#define RPM_SIG_PGP262		1
#define RPM_SIG_HEADER		5

/* signature header tags: size of the main header plus the payload */
#define RPM_SIGTAG_LONGSIZE	270
#define RPM_SIGTAG_SIZE		1000

/* main header tags */
#define RPM_TAG_NAME		1000
#define RPM_TAG_VERSION		1001
#define RPM_TAG_RELEASE		1002
#define RPM_TAG_BUILDTIME	1006
#define RPM_TAG_ARCH		1022
#define RPM_TAG_PAYLOADFORMAT	1124
#define RPM_TAG_PAYLOADCOMP	1125

/* header entry types */
#define RPM_TYPE_INT32		4
#define RPM_TYPE_INT64		5
#define RPM_TYPE_STRING		6

struct rpm_header
{
	grub_off_t index;	/* first index entry */
	grub_off_t data;	/* first data byte */
	grub_off_t end;		/* first byte past the header */
	grub_uint32_t count;	/* index entries */
	grub_uint32_t len;	/* data bytes */
};

struct rpm_info
{
	char *name;
	char *version;
	char *release;
	char *arch;
	char *format;
	char *compressor;
};

static grub_uint16_t
rpm_get16 (const grub_uint8_t *ptr)
{
	return (grub_uint16_t) (((grub_uint16_t) ptr[0] << 8) | ptr[1]);
}

static grub_uint32_t
rpm_get32 (const grub_uint8_t *ptr)
{
	return ((grub_uint32_t) ptr[0] << 24) | ((grub_uint32_t) ptr[1] << 16)
	       | ((grub_uint32_t) ptr[2] << 8) | (grub_uint32_t) ptr[3];
}

static void
rpm_free_info (struct rpm_info *info)
{
	grub_free (info->name);
	grub_free (info->version);
	grub_free (info->release);
	grub_free (info->arch);
	grub_free (info->format);
	grub_free (info->compressor);
}

static grub_err_t
rpm_read_header (struct grub_pkg_data *data, grub_off_t pos,
		 struct rpm_header *hdr)
{
	grub_uint8_t intro[RPM_HEAD_INTRO];

	if (pos > data->disk_size
	    || data->disk_size - pos < RPM_HEAD_INTRO
	    || grub_disk_read (data->disk, 0, pos, sizeof (intro), intro))
		return grub_error (GRUB_ERR_BAD_FS, "truncated rpm header");
	if (rpm_get32 (intro) != RPM_HEAD_MAGIC)
		return grub_error (GRUB_ERR_BAD_FS, "bad rpm header magic");

	hdr->count = rpm_get32 (intro + 8);
	hdr->len = rpm_get32 (intro + 12);
	if (hdr->count > RPM_MAX_ENTRIES || hdr->len > RPM_MAX_HEADER)
		return grub_error (GRUB_ERR_BAD_FS, "oversized rpm header");

	hdr->index = pos + RPM_HEAD_INTRO;
	hdr->data = hdr->index + (grub_off_t) hdr->count * RPM_ENTRY_SIZE;
	hdr->end = hdr->data + hdr->len;
	if (hdr->end > data->disk_size)
		return grub_error (GRUB_ERR_BAD_FS, "truncated rpm header");
	return GRUB_ERR_NONE;
}

static grub_err_t
rpm_read_string (struct grub_pkg_data *data, const struct rpm_header *hdr,
		 grub_uint32_t off, char **out)
{
	char buf[RPM_MAX_STRING + 1];
	grub_size_t len = hdr->len - off;

	grub_free (*out);
	*out = NULL;
	if (len > RPM_MAX_STRING)
		len = RPM_MAX_STRING;
	if (grub_disk_read (data->disk, 0, hdr->data + off, len, buf))
		return grub_errno;
	buf[len] = '\0';

	*out = grub_strdup (buf);
	return *out ? GRUB_ERR_NONE : grub_errno;
}

/*
 * RPMSIGTAG_SIZE covers the main header plus the payload and is the only
 * exact payload length an rpm carries.  It matters: a disk holding the
 * package is padded out to a whole sector, and the trailing zeros throw
 * off the end of stream checks the gzip and xz filters make.
 * *SET becomes 1 for the 32 bit tag and 2 for the 64 bit one.
 */
static grub_err_t
rpm_read_sig_size (struct grub_pkg_data *data, const struct rpm_header *hdr,
		   grub_uint64_t *size, int *set)
{
	grub_uint32_t i;

	*size = 0;
	*set = 0;
	for (i = 0; i < hdr->count; i++)
	{
		grub_uint8_t ent[RPM_ENTRY_SIZE];
		grub_uint8_t val[8];
		grub_uint32_t tag, type, off, num;
		grub_uint32_t need;

		if (grub_disk_read (data->disk, 0,
				    hdr->index + (grub_off_t) i * RPM_ENTRY_SIZE,
				    sizeof (ent), ent))
			return grub_errno;
		tag = rpm_get32 (ent);
		type = rpm_get32 (ent + 4);
		off = rpm_get32 (ent + 8);
		num = rpm_get32 (ent + 12);
		if (num != 1 || off >= hdr->len)
			continue;

		if (tag == RPM_SIGTAG_LONGSIZE && type == RPM_TYPE_INT64)
			need = 8;
		else if (tag == RPM_SIGTAG_SIZE && type == RPM_TYPE_INT32
			 && *set != 2)
			need = 4;
		else
			continue;
		if (hdr->len - off < need)
			continue;
		if (grub_disk_read (data->disk, 0, hdr->data + off, need, val))
			return grub_errno;

		*size = (need == 4)
			? rpm_get32 (val)
			: (((grub_uint64_t) rpm_get32 (val) << 32)
			   | rpm_get32 (val + 4));
		*set = (need == 8) ? 2 : 1;
	}
	return GRUB_ERR_NONE;
}

/* picks the handful of tags that name the package out of the index */
static grub_err_t
rpm_read_tags (struct grub_pkg_data *data, const struct rpm_header *hdr,
	       struct rpm_info *info)
{
	grub_uint32_t i;

	for (i = 0; i < hdr->count; i++)
	{
		grub_uint8_t ent[RPM_ENTRY_SIZE];
		grub_uint32_t tag, type, off, num;
		char **dst;
		grub_err_t err;

		if (grub_disk_read (data->disk, 0,
				    hdr->index + (grub_off_t) i * RPM_ENTRY_SIZE,
				    sizeof (ent), ent))
			return grub_errno;
		tag = rpm_get32 (ent);
		type = rpm_get32 (ent + 4);
		off = rpm_get32 (ent + 8);
		num = rpm_get32 (ent + 12);
		if (off >= hdr->len || num != 1)
			continue;

		if (type == RPM_TYPE_INT32)
		{
			grub_uint8_t val[4];

			if (tag != RPM_TAG_BUILDTIME || hdr->len - off < 4)
				continue;
			if (grub_disk_read (data->disk, 0, hdr->data + off,
					    sizeof (val), val))
				return grub_errno;
			data->mtime = (grub_int64_t) rpm_get32 (val);
			continue;
		}
		if (type != RPM_TYPE_STRING)
			continue;

		switch (tag)
		{
		case RPM_TAG_NAME:
			dst = &info->name;
			break;
		case RPM_TAG_VERSION:
			dst = &info->version;
			break;
		case RPM_TAG_RELEASE:
			dst = &info->release;
			break;
		case RPM_TAG_ARCH:
			dst = &info->arch;
			break;
		case RPM_TAG_PAYLOADFORMAT:
			dst = &info->format;
			break;
		case RPM_TAG_PAYLOADCOMP:
			dst = &info->compressor;
			break;
		default:
			continue;
		}

		err = rpm_read_string (data, hdr, off, dst);
		if (err)
			return err;
	}
	return GRUB_ERR_NONE;
}

/* true when a compression filter for NAME is built into grub.lib */
static int
rpm_known_compressor (const char *name)
{
	return grub_strcmp (name, "gzip") == 0
	       || grub_strcmp (name, "xz") == 0
	       || grub_strcmp (name, "zstd") == 0
	       || grub_strcmp (name, "lzo") == 0
	       || grub_strcmp (name, "lz4") == 0
	       || grub_strcmp (name, "none") == 0;
}

static grub_err_t
rpm_set_label (struct grub_pkg_data *data, const struct rpm_info *info,
	       const grub_uint8_t *lead)
{
	char leadname[RPM_LEAD_NAME + 1];
	const char *name = info->name;

	if (!name)
	{
		grub_memcpy (leadname, lead + 10, RPM_LEAD_NAME);
		leadname[RPM_LEAD_NAME] = '\0';
		name = leadname;
	}
	if (!*name)
		return GRUB_ERR_NONE;

	if (info->version && info->release && info->arch)
		data->label = grub_xasprintf ("%s-%s-%s.%s", name,
					      info->version, info->release,
					      info->arch);
	else
		data->label = grub_strdup (name);
	return data->label ? GRUB_ERR_NONE : grub_errno;
}

static grub_err_t
rpm_parse (struct grub_pkg_data *data)
{
	grub_uint8_t lead[RPM_LEAD_SIZE];
	struct rpm_header hdr;
	struct rpm_info info;
	grub_off_t pos, hdr_start, payload_len;
	grub_uint64_t sigsize = 0;
	grub_uint16_t sigtype;
	int sigsize_set = 0;
	int stream;
	grub_err_t err;

	grub_memset (&info, 0, sizeof (info));

	if (data->disk_size < RPM_LEAD_SIZE + RPM_HEAD_INTRO
	    || grub_disk_read (data->disk, 0, 0, sizeof (lead), lead)
	    || rpm_get32 (lead) != RPM_LEAD_MAGIC)
		return grub_error (GRUB_ERR_BAD_FS, "not an rpm package");
	if (lead[4] < 3 || rpm_get16 (lead + 6) > 1)
		return grub_error (GRUB_ERR_BAD_FS, "unsupported rpm version");

	sigtype = rpm_get16 (lead + 78);
	pos = RPM_LEAD_SIZE;
	if (sigtype == RPM_SIG_PGP262)
		pos += RPM_PGP262_SIZE;
	else if (sigtype == RPM_SIG_HEADER)
	{
		err = rpm_read_header (data, pos, &hdr);
		if (err)
			return err;
		err = rpm_read_sig_size (data, &hdr, &sigsize, &sigsize_set);
		if (err)
			return err;
		/* the main header starts on an eight byte boundary */
		pos = (hdr.end + 7) & ~(grub_off_t) 7;
	}
	else if (sigtype != RPM_SIG_NONE)
		return grub_error (GRUB_ERR_BAD_FS,
				   "unsupported rpm signature type %u",
				   (unsigned) sigtype);

	hdr_start = pos;
	err = rpm_read_header (data, pos, &hdr);
	if (err)
		return err;
	err = rpm_read_tags (data, &hdr, &info);
	if (err)
		goto fail;

	if (info.format && grub_strcmp (info.format, "cpio") != 0)
	{
		err = grub_error (GRUB_ERR_BAD_FS,
				  "unsupported rpm payload format `%s'",
				  info.format);
		goto fail;
	}
	if (info.compressor && !rpm_known_compressor (info.compressor))
	{
		err = grub_error (GRUB_ERR_BAD_FS,
				  "unsupported rpm payload compressor `%s'",
				  info.compressor);
		goto fail;
	}
	if (hdr.end >= data->disk_size)
	{
		err = grub_error (GRUB_ERR_BAD_FS, "empty rpm payload");
		goto fail;
	}

	err = rpm_set_label (data, &info, lead);
	if (err)
		goto fail;

	payload_len = data->disk_size - hdr.end;
	if (sigsize_set)
	{
		grub_uint64_t hdr_len = hdr.end - hdr_start;

		if (sigsize > hdr_len && sigsize - hdr_len <= payload_len)
			payload_len = sigsize - hdr_len;
	}

	stream = grub_pkg_add_stream (data, hdr.end, payload_len);
	if (stream < 0)
	{
		err = grub_error (GRUB_ERR_BAD_FS, "too many rpm payloads");
		goto fail;
	}
	err = grub_pkg_scan_cpio (data, stream, NULL);

fail:
	rpm_free_info (&info);
	return err;
}

static struct grub_pkg_ops rpm_ops =
{
	.name = "rpm",
	.parse = rpm_parse
};

static grub_err_t
grub_rpm_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	return grub_pkg_dir (device, &rpm_ops, path, hook, hook_data);
}

static grub_err_t
grub_rpm_open (grub_file_t file, const char *name)
{
	return grub_pkg_open (file, &rpm_ops, name);
}

static grub_err_t
grub_rpm_label (grub_device_t device, char **label)
{
	return grub_pkg_label (device, &rpm_ops, label);
}

static grub_err_t
grub_rpm_mtime (grub_device_t device, grub_int64_t *tm)
{
	return grub_pkg_mtime (device, &rpm_ops, tm);
}

static struct grub_fs grub_rpm_fs =
{
	.name = "rpm",
	.fs_dir = grub_rpm_dir,
	.fs_open = grub_rpm_open,
	.fs_read = grub_pkg_read,
	.fs_close = grub_pkg_close,
	.fs_label = grub_rpm_label,
	.fs_mtime = grub_rpm_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (rpm)
{
	grub_rpm_fs.mod = mod;
	grub_fs_register (&grub_rpm_fs);
}

GRUB_MOD_FINI (rpm)
{
	grub_fs_unregister (&grub_rpm_fs);
	grub_pkg_cache_release (&rpm_ops);
}
