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
 * Parent / backing / extent file resolution shared by the vhd, vhdx,
 * qcow, vmdk and cdimage io filters.  A child stores the location of
 * the file it needs as a Windows (VHD/VHDX/VMDK), POSIX (QCOW) or bare
 * name (cue/ccd/mds) path, which is resolved relative to the child's
 * own location and reopened, so chains of arbitrary format nest
 * naturally.
 *
 * "Its own location" means one of two namespaces, told apart by whether
 * the child has a grub device:
 *
 *   - a grub path like "(loop0)/dir/child.vhd", when the image was
 *     mounted off a browsed volume.  Resolution is textual and the
 *     result goes back through grub_file_open.
 *   - a Windows path like "F:\images\child.vhd", when the GUI opened
 *     the image straight off the host filesystem (File > Open Image, or
 *     --file).  grub_file_open has no device to resolve against there,
 *     so the join is done in Windows terms and the result opened with
 *     the Win32 API through grub_winfile_open.
 *
 * An absolute path recorded by whoever made the image usually names a
 * directory that only existed on that machine; both namespaces fall
 * back to looking for its last component next to the child.
 */

#include <grub/charset.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/winfile.h>

#include "vbox.h"

/* All grub calls happen on the single backend thread, so a static
   recursion counter is a safe guard against parent chain loops.  */
#define VDISK_PARENT_MAX_DEPTH	8
static int vdisk_parent_depth;

/* A parent may itself be a differencing image, so it goes back through
   the vdisk filters.  An extent must not: a VMDK SPARSE extent carries
   the same magic as a full image.  */
#define VDISK_PARENT_TYPE	(GRUB_FILE_TYPE_LOOPBACK	\
				 | GRUB_FILE_TYPE_NO_DECOMPRESS	\
				 | GRUB_FILE_TYPE_FILTER_VDISK)
#define VDISK_MEMBER_TYPE	(GRUB_FILE_TYPE_LOOPBACK	\
				 | GRUB_FILE_TYPE_NO_DECOMPRESS)

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

/* Last component of a path, in either namespace.  */
static const char *
vdisk_basename (const char *path)
{
	const char *p, *base = path;

	for (p = path; *p; p++)
		if (*p == '/' || *p == '\\')
			base = p + 1;
	return base;
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

/* Resolution inside the grub namespace.  */
static char *
vdisk_grub_path (const char *image, const char *member)
{
	char *norm = NULL;
	char *result = NULL;
	char *root;
	const char *comp;
	grub_size_t len;

	/* Already a full grub path (as produced by ourselves).  */
	if (member[0] == '(')
		return grub_strdup (member);

	norm = grub_strdup (member);
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
		char *dup = grub_strdup (vdisk_basename (norm));

		grub_free (norm);
		if (!dup)
			return NULL;
		norm = dup;
	}

	/* Work buffer: image directory + '/' + member.  */
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

/* Drive letter, UNC share, \\?\ device path or a root relative path;
   Win32 resolves "." and ".." itself, so nothing has to be folded.  */
static int
vdisk_host_absolute (const char *path)
{
	return (grub_isalpha (path[0]) && path[1] == ':')
	       || path[0] == '/' || path[0] == '\\';
}

/* Resolution next to a host image: its directory plus MEMBER.  */
static char *
vdisk_host_path (const char *image, const char *member)
{
	const char *base = vdisk_basename (image);
	grub_size_t dirlen = (grub_size_t) (base - image);
	char *path;

	path = grub_malloc (dirlen + grub_strlen (member) + 1);
	if (!path)
		return NULL;
	grub_memcpy (path, image, dirlen);
	grub_strcpy (path + dirlen, member);
	return path;
}

static struct grub_file *
vdisk_open_host (const char *image, const char *member,
		 enum grub_file_type type)
{
	char *path;
	struct grub_file *file;

	if (vdisk_host_absolute (member))
	{
		file = grub_winfile_open (member, type);
		if (file)
			return file;
		grub_errno = GRUB_ERR_NONE;
		member = vdisk_basename (member);
	}

	path = vdisk_host_path (image, member);
	if (!path)
		return NULL;
	file = grub_winfile_open (path, type);
	grub_free (path);
	return file;
}

static struct grub_file *
vdisk_open_grub (const char *image, const char *member,
		 enum grub_file_type type)
{
	char *path;
	struct grub_file *file;

	path = vdisk_grub_path (image, member);
	if (!path)
		return NULL;
	file = grub_file_open (path, type);
	grub_free (path);
	return file;
}

static struct grub_file *
vdisk_open_relative (struct grub_file *image, const char *member,
		     enum grub_file_type type)
{
	if (!image || !image->name || !member || !member[0])
	{
		grub_error (GRUB_ERR_BAD_DEVICE, "virtual disk file not named");
		return NULL;
	}
	if (image->device)
		return vdisk_open_grub (image->name, member, type);
	return vdisk_open_host (image->name, member, type);
}

struct grub_file *
grub_vdisk_open_parent (struct grub_file *image, const char *parent)
{
	struct grub_file *file;

	if (vdisk_parent_depth >= VDISK_PARENT_MAX_DEPTH)
	{
		grub_error (GRUB_ERR_BAD_DEVICE,
			    "virtual disk parent chain too deep");
		return NULL;
	}

	vdisk_parent_depth++;
	file = vdisk_open_relative (image, parent, VDISK_PARENT_TYPE);
	vdisk_parent_depth--;
	if (!file)
		grub_error (GRUB_ERR_BAD_DEVICE,
			    "cannot open virtual disk parent `%s'", parent);
	return file;
}

struct grub_file *
grub_vdisk_open_member (struct grub_file *image, const char *member)
{
	struct grub_file *file;

	file = vdisk_open_relative (image, member, VDISK_MEMBER_TYPE);
	if (!file)
		grub_error (GRUB_ERR_BAD_DEVICE,
			    "cannot open virtual disk extent `%s'", member);
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
