/*
 *  Rover -- GRUB 2 filesystem browser for Windows
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
 * Parent / backing file resolution shared by the vhd, vhdx and qcow io
 * filters.  A differencing child stores the parent location as a Windows
 * (VHD/VHDX) or POSIX (QCOW) path; we resolve it relative to the child's
 * own grub path and reopen it through the vdisk filter chain, so parent
 * chains of arbitrary format nest naturally.
 */

#include <grub/charset.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>

#include "vbox.h"

/* All grub calls happen on the single backend thread, so a static
   recursion counter is a safe guard against parent chain loops.  */
#define VDISK_PARENT_MAX_DEPTH	8
static int vdisk_parent_depth;

char *
grub_vdisk_utf16_to_utf8_dup (const void *src, grub_size_t nunits,
			      int big_endian)
{
	grub_uint16_t *tmp = NULL;
	grub_uint8_t *utf8 = NULL;
	grub_uint8_t *end;
	grub_size_t i;

	tmp = grub_calloc (nunits + 1, sizeof (tmp[0]));
	if (!tmp)
		goto fail;
	for (i = 0; i < nunits; i++)
	{
		grub_uint16_t c;

		/* The source may be unaligned (vhdx locator key/value blobs).  */
		grub_memcpy (&c, (const grub_uint8_t *) src + 2 * i, 2);
		c = big_endian ? grub_be_to_cpu16 (c) : grub_le_to_cpu16 (c);
		if (c == 0)
			break;
		tmp[i] = c;
	}
	nunits = i;

	utf8 = grub_malloc (nunits * GRUB_MAX_UTF8_PER_UTF16 + 1);
	if (!utf8)
		goto fail;
	end = grub_utf16_to_utf8 (utf8, tmp, nunits);
	*end = '\0';
	grub_free (tmp);
	return (char *) utf8;

fail:
	grub_free (tmp);
	grub_free (utf8);
	return NULL;
}

/* Strip the last path component in place ("(hd0)/a/b" -> "(hd0)/a").
   Never strips the device prefix.  */
static void
vdisk_dirname (char *path, const char *root)
{
	char *p = path + grub_strlen (path);

	while (p > root + 1 && p[-1] != '/')
		p--;
	while (p > root + 1 && p[-1] == '/')
		p--;
	*p = '\0';
}

char *
grub_vdisk_parent_path (const char *image, const char *parent)
{
	char *norm = NULL;
	char *result = NULL;
	char *root;
	const char *comp;
	grub_size_t len;

	/* Already a full grub path (as produced by ourselves).  */
	if (parent[0] == '(')
		return grub_strdup (parent);

	norm = grub_strdup (parent);
	if (!norm)
		goto fail;
	for (char *p = norm; *p; p++)
		if (*p == '\\')
			*p = '/';

	/* Foreign absolute paths (drive letter, UNC share) cannot be
	   resolved inside the grub namespace; fall back to looking for
	   the basename next to the child image.  */
	if ((grub_isalpha (norm[0]) && norm[1] == ':')
	    || (norm[0] == '/' && norm[1] == '/'))
	{
		char *base = grub_strrchr (norm, '/');
		char *dup = grub_strdup (base ? base + 1 : norm);
		grub_free (norm);
		if (!dup)
			return NULL;
		norm = dup;
	}

	/* Work buffer: image directory + '/' + parent.  */
	len = grub_strlen (image) + grub_strlen (norm) + 2;
	result = grub_malloc (len);
	if (!result)
		goto fail;
	grub_strcpy (result, image);

	/* The device prefix "(...)" is the resolution root.  */
	root = result;
	if (result[0] == '(')
	{
		root = grub_strchr (result, ')');
		if (!root)
			goto fail;
	}

	if (norm[0] == '/')
		root[1] = '\0';	/* absolute within the same device */
	else
		vdisk_dirname (result, root);

	/* Append components, folding "." and "..".  */
	comp = norm;
	while (*comp)
	{
		const char *next;
		grub_size_t clen;

		while (*comp == '/')
			comp++;
		if (!*comp)
			break;
		next = grub_strchr (comp, '/');
		clen = next ? (grub_size_t) (next - comp) : grub_strlen (comp);

		if (clen == 1 && comp[0] == '.')
			;
		else if (clen == 2 && comp[0] == '.' && comp[1] == '.')
			vdisk_dirname (result, root);
		else
		{
			grub_size_t rlen = grub_strlen (result);
			if (rlen == 0 || result[rlen - 1] != '/')
				result[rlen++] = '/';
			grub_memcpy (result + rlen, comp, clen);
			result[rlen + clen] = '\0';
		}
		comp = next ? next : comp + clen;
	}

	grub_free (norm);
	return result;

fail:
	grub_free (norm);
	grub_free (result);
	return NULL;
}

struct grub_file *
grub_vdisk_open_parent (const char *image, const char *parent)
{
	char *path;
	grub_file_t file;

	if (vdisk_parent_depth >= VDISK_PARENT_MAX_DEPTH)
	{
		grub_error (GRUB_ERR_BAD_DEVICE,
			    "virtual disk parent chain too deep");
		return NULL;
	}
	if (!image || !parent || !parent[0])
	{
		grub_error (GRUB_ERR_BAD_DEVICE,
			    "virtual disk parent image not found");
		return NULL;
	}

	path = grub_vdisk_parent_path (image, parent);
	if (!path)
		return NULL;

	vdisk_parent_depth++;
	file = grub_file_open (path, GRUB_FILE_TYPE_LOOPBACK
				     | GRUB_FILE_TYPE_NO_DECOMPRESS
				     | GRUB_FILE_TYPE_FILTER_VDISK);
	vdisk_parent_depth--;
	if (!file)
		grub_error (GRUB_ERR_BAD_DEVICE,
			    "cannot open virtual disk parent `%s'", path);
	grub_free (path);
	return file;
}

struct grub_file *
grub_vdisk_open_member (const char *image, const char *member)
{
	char *path;
	grub_file_t file;

	if (!image || !member || !member[0])
	{
		grub_error (GRUB_ERR_BAD_DEVICE,
			    "virtual disk extent file not found");
		return NULL;
	}

	path = grub_vdisk_parent_path (image, member);
	if (!path)
		return NULL;

	/* Raw open: an extent must not be decoded by the vdisk filters
	   (a SPARSE extent carries the same magic as a full image).  */
	file = grub_file_open (path, GRUB_FILE_TYPE_LOOPBACK
				     | GRUB_FILE_TYPE_NO_DECOMPRESS);
	if (!file)
		grub_error (GRUB_ERR_BAD_DEVICE,
			    "cannot open virtual disk extent `%s'", path);
	grub_free (path);
	return file;
}

int
grub_vdisk_read_parent (struct grub_file *parent, grub_uint64_t off,
			void *buf, grub_size_t len)
{
	grub_memset (buf, 0, len);
	if (off < grub_file_size (parent))
	{
		grub_size_t n = len;
		grub_ssize_t cb_read;
		if (n > grub_file_size (parent) - off)
			n = (grub_size_t) (grub_file_size (parent) - off);
		if (grub_file_seek (parent, off) == (grub_off_t) -1)
			return GRUB_ERR_OUT_OF_RANGE;
		cb_read = grub_file_read (parent, buf, n);
		if (cb_read < 0)
			return GRUB_ERR_FILE_READ_ERROR;
		if ((grub_size_t) cb_read != n)
			return grub_error (GRUB_ERR_FILE_READ_ERROR,
					   "short read in virtual disk parent");
	}
	return GRUB_ERR_NONE;
}
