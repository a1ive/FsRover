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
 *  Read-only Debian package (.deb / .udeb) filesystem driver.
 *
 *  A deb is an "!<arch>" (ar) archive whose first member is
 *  "debian-binary", followed by the compressed control and data
 *  tarballs.  Container parsing follows 7-Zip 26.02
 *  (CPP\7zip\Archive\ArHandler.cpp); both tarballs are expanded in place
 *  by grub-core\fs\pkghelp.c, so a package browses as
 *
 *      /debian-binary
 *      /control/...    maintainer scripts, md5sums, conffiles, ...
 *      /data/...       the files the package installs
 *
 *  Members that are not a tarball this build can decode -- a bzip2 or
 *  plain lzma control/data tarball, signatures such as _gpgorigin --
 *  stay visible as plain files at the root.
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

#define DEB_MAGIC	"!<arch>\n"
#define DEB_MAGIC_LEN	8
#define DEB_HEAD_LEN	60
#define DEB_NAME_LEN	16

/* how much of control/control is inspected for the volume label */
#define DEB_CONTROL_MAX	4096

struct deb_member
{
	char name[DEB_NAME_LEN + 1];
	grub_off_t off;
	grub_off_t size;
	grub_int64_t mtime;
};

static grub_uint64_t
deb_number (const char *str, grub_size_t size)
{
	grub_uint64_t ret = 0;
	grub_size_t i;

	for (i = 0; i < size && str[i] == ' '; i++)
		;
	for (; i < size && str[i] >= '0' && str[i] <= '9'; i++)
		ret = ret * 10 + (grub_uint64_t) (str[i] - '0');
	return ret;
}

/* returns 0 when POS does not hold a well formed ar member header */
static int
deb_read_member (struct grub_pkg_data *data, grub_off_t pos,
		 struct deb_member *mem)
{
	char hd[DEB_HEAD_LEN];
	grub_size_t len;
	unsigned i;

	if (pos > data->disk_size || data->disk_size - pos < DEB_HEAD_LEN)
		return 0;
	if (grub_disk_read (data->disk, 0, pos, sizeof (hd), hd))
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	if (hd[DEB_HEAD_LEN - 2] != 0x60 || hd[DEB_HEAD_LEN - 1] != '\n')
		return 0;
	for (i = 0; i < DEB_HEAD_LEN - 2; i++)
		if (hd[i] == '\0')
			return 0;

	grub_memcpy (mem->name, hd, DEB_NAME_LEN);
	mem->name[DEB_NAME_LEN] = '\0';
	len = DEB_NAME_LEN;
	while (len > 0 && mem->name[len - 1] == ' ')
		mem->name[--len] = '\0';
	/* the GNU variant terminates short names with a slash */
	if (len > 1 && mem->name[len - 1] == '/')
		mem->name[--len] = '\0';
	if (len == 0)
		return 0;

	mem->mtime = (grub_int64_t) deb_number (hd + 16, 12);
	mem->size = deb_number (hd + 48, 10);
	mem->off = pos + DEB_HEAD_LEN;
	if (mem->size > GRUB_PKG_MAX_SIZE
	    || mem->size > data->disk_size - mem->off)
		return 0;
	return 1;
}

/* keeps an ar member as a plain file at the root */
static grub_err_t
deb_add_member (struct grub_pkg_data *data, const struct deb_member *mem)
{
	struct grub_pkg_entry *ent;
	char *name;
	grub_err_t err;

	err = grub_pkg_norm_name (NULL, mem->name, &name);
	if (err)
		return err;
	if (!name)	/* the "/" and "//" bookkeeping members */
		return GRUB_ERR_NONE;

	ent = grub_pkg_new_entry (data, name);
	if (!ent)
		return grub_errno;
	ent->stream = GRUB_PKG_STREAM_RAW;
	ent->off = mem->off;
	ent->size = mem->size;
	ent->mtime = mem->mtime;
	return GRUB_ERR_NONE;
}

/* expands a control/data tarball under PREFIX */
static grub_err_t
deb_add_payload (struct grub_pkg_data *data, const struct deb_member *mem,
		 const char *prefix)
{
	unsigned saved = data->num_entries;
	int stream;
	grub_err_t err;

	stream = grub_pkg_add_stream (data, mem->off, mem->size);
	if (stream < 0)
		return grub_error (GRUB_ERR_BAD_FS, "too many deb payloads");

	err = grub_pkg_scan_tar (data, stream, prefix);
	if (err)
	{
		/* not a tarball this build decodes: undo and fall back */
		grub_pkg_truncate_entries (data, saved);
		grub_pkg_drop_stream (data);
		grub_errno = GRUB_ERR_NONE;
	}
	return err;
}

static char *
deb_trim (char *str)
{
	grub_size_t len;

	while (*str == ' ' || *str == '\t')
		str++;
	len = grub_strlen (str);
	while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t'
			   || str[len - 1] == '\r'))
		str[--len] = '\0';
	return str;
}

/* the Package and Version fields of control/control make the label */
static void
deb_read_label (struct grub_pkg_data *data)
{
	char buf[DEB_CONTROL_MAX + 1];
	const struct grub_pkg_entry *ent;
	grub_file_t file;
	char *line, *next, *name = NULL, *version = NULL;
	grub_ssize_t got = 0;
	int index;

	index = grub_pkg_find_entry (data, "control/control");
	if (index < 0)
		return;
	ent = &data->entries[index];
	if (ent->stream < 0 || ent->size == 0)
		return;

	file = grub_pkg_stream_open (data, ent->stream);
	if (!file)
	{
		grub_errno = GRUB_ERR_NONE;
		return;
	}
	if (grub_file_seek (file, ent->off) != (grub_off_t) -1)
	{
		grub_size_t want = (ent->size < DEB_CONTROL_MAX)
				   ? (grub_size_t) ent->size : DEB_CONTROL_MAX;

		got = grub_file_read (file, buf, want);
	}
	grub_file_close (file);
	grub_errno = GRUB_ERR_NONE;
	if (got <= 0)
		return;
	buf[got] = '\0';

	for (line = buf; *line; line = next)
	{
		char *eol = grub_strchr (line, '\n');

		if (eol)
		{
			*eol = '\0';
			next = eol + 1;
		}
		else
			next = line + grub_strlen (line);

		if (grub_strncmp (line, "Package:", 8) == 0)
			name = deb_trim (line + 8);
		else if (grub_strncmp (line, "Version:", 8) == 0)
			version = deb_trim (line + 8);
	}

	if (!name || !*name)
		return;
	if (version && *version)
		data->label = grub_xasprintf ("%s-%s", name, version);
	else
		data->label = grub_strdup (name);
	grub_errno = GRUB_ERR_NONE;
}

static grub_err_t
deb_parse (struct grub_pkg_data *data)
{
	char magic[DEB_MAGIC_LEN];
	grub_off_t pos = DEB_MAGIC_LEN;
	unsigned count = 0;
	grub_err_t err;

	if (data->disk_size < DEB_MAGIC_LEN + DEB_HEAD_LEN
	    || grub_disk_read (data->disk, 0, 0, sizeof (magic), magic)
	    || grub_memcmp (magic, DEB_MAGIC, DEB_MAGIC_LEN) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "not a deb archive");

	for (;;)
	{
		struct deb_member mem;
		const char *prefix;

		if (!deb_read_member (data, pos, &mem))
			break;
		/*
		 * Plain ar archives (.a, .lib) are not packages; requiring
		 * the dpkg format marker keeps them off this driver.
		 */
		if (count == 0 && grub_strcmp (mem.name, "debian-binary") != 0)
			return grub_error (GRUB_ERR_BAD_FS, "not a deb archive");
		count++;
		if (mem.mtime > data->mtime)
			data->mtime = mem.mtime;

		prefix = NULL;
		if (grub_strncmp (mem.name, "control.tar", 11) == 0)
			prefix = "control";
		else if (grub_strncmp (mem.name, "data.tar", 8) == 0)
			prefix = "data";

		if (prefix && deb_add_payload (data, &mem, prefix))
			prefix = NULL;
		if (!prefix)
		{
			err = deb_add_member (data, &mem);
			if (err)
				return err;
		}

		pos = mem.off + mem.size + (mem.size & 1);
	}

	if (count == 0)
		return grub_error (GRUB_ERR_BAD_FS, "not a deb archive");

	deb_read_label (data);
	return GRUB_ERR_NONE;
}

static struct grub_pkg_ops deb_ops =
{
	.name = "deb",
	.parse = deb_parse
};

static grub_err_t
grub_deb_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	return grub_pkg_dir (device, &deb_ops, path, hook, hook_data);
}

static grub_err_t
grub_deb_open (grub_file_t file, const char *name)
{
	return grub_pkg_open (file, &deb_ops, name);
}

static grub_err_t
grub_deb_label (grub_device_t device, char **label)
{
	return grub_pkg_label (device, &deb_ops, label);
}

static grub_err_t
grub_deb_mtime (grub_device_t device, grub_int64_t *tm)
{
	return grub_pkg_mtime (device, &deb_ops, tm);
}

static struct grub_fs grub_deb_fs =
{
	.name = "deb",
	.fs_dir = grub_deb_dir,
	.fs_open = grub_deb_open,
	.fs_read = grub_pkg_read,
	.fs_close = grub_pkg_close,
	.fs_label = grub_deb_label,
	.fs_mtime = grub_deb_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (deb)
{
	grub_deb_fs.mod = mod;
	grub_fs_register (&grub_deb_fs);
}

GRUB_MOD_FINI (deb)
{
	grub_fs_unregister (&grub_deb_fs);
	grub_pkg_cache_release (&deb_ops);
}
