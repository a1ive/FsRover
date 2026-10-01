/* cpio.c - cpio and tar filesystem.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2007,2008,2009,2013 Free Software Foundation, Inc.
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

#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/archelp.h>

#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/i18n.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

/* tar support */
#define MAGIC	"ustar"
PRAGMA_BEGIN_PACKED
struct head
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
} GRUB_PACKED;
PRAGMA_END_PACKED

static inline unsigned long long
read_number (const char *str, grub_size_t size)
{
  unsigned long long ret = 0;

  /* GNU base-256: a set high bit in the first byte means the rest of the
     field is a big-endian binary number (used for sizes >= 8 GiB and the
     like).  0xff starts a negative value, which only makes sense for
     pre-1970 mtimes; report those as 0.  Values that do not fit return
     all ones so the callers' range checks reject them.  */
  if (size && (*str & 0x80))
    {
      const grub_uint8_t *p = (const grub_uint8_t *) str;

      if (*p == 0xff)
	return 0;
      ret = *p++ & 0x7f;
      while (--size)
	{
	  if (ret >> 56)
	    return ~0ULL;
	  ret = (ret << 8) | *p++;
	}
      return ret;
    }

  /* Pre-POSIX tars pad the numeric fields with leading spaces rather than
     zeroes; POSIX allows either.  Without this every field of such a
     header, the entry size included, reads back as zero.  */
  while (size && *str == ' ')
    {
      str++;
      size--;
    }
  while (size-- && *str >= '0' && *str <= '7')
    ret = (ret << 3) | (*str++ & 0xf);
  return ret;
}

/* Pre-POSIX ("v7") tars carry no magic, so fall back to the header
   checksum: it covers the whole 512 byte block with the chksum field
   taken as eight spaces.  Some old writers summed signed chars, so
   accept that reading as well.  */
static int
checksum_ok (grub_disk_t disk, grub_off_t hofs)
{
  grub_uint8_t blk[GRUB_DISK_SECTOR_SIZE];
  unsigned long long stored;
  unsigned long long sum = 0;
  long long ssum = 0;
  grub_size_t i;

  if (grub_disk_read (disk, 0, hofs, sizeof (blk), blk))
    {
      grub_errno = GRUB_ERR_NONE;
      return 0;
    }

  stored = read_number ((char *) blk + 148, 8);
  for (i = 0; i < sizeof (blk); i++)
    {
      grub_uint8_t c = (i >= 148 && i < 156) ? ' ' : blk[i];

      sum += c;
      ssum += (signed char) c;
    }

  return (stored == sum || (ssum >= 0 && stored == (unsigned long long) ssum));
}

static int
head_ok (grub_disk_t disk, grub_off_t hofs, const struct head *hd)
{
  if (grub_memcmp (hd->magic, MAGIC, sizeof (MAGIC) - 1) == 0)
    return 1;
  return checksum_ok (disk, hofs);
}

struct grub_archelp_data
{
  grub_disk_t disk;
  grub_off_t hofs, next_hofs;
  grub_off_t dofs;
  grub_off_t size;
  char *linkname;
  grub_size_t linkname_alloc;
};

static grub_err_t
set_linkname (struct grub_archelp_data *data, const char *str, grub_size_t len)
{
  if (data->linkname_alloc < len + 1)
    {
      char *n;
      n = grub_malloc (len + 1);
      if (!n)
	return grub_errno;
      grub_free (data->linkname);
      data->linkname = n;
      data->linkname_alloc = len + 1;
    }
  grub_memcpy (data->linkname, str, len);
  data->linkname[len] = 0;
  return GRUB_ERR_NONE;
}

/* POSIX.1-2001 (pax) extended header overrides for the next entry.  */
#define PAX_MAX_SIZE	(1024 * 1024)

struct pax_info
{
  int have_size, have_mtime;
  unsigned long long size;
  grub_int32_t mtime;
};

static unsigned long long
read_decimal (const char *str, const char *end, int *neg)
{
  unsigned long long ret = 0;

  *neg = 0;
  if (str < end && *str == '-')
    {
      *neg = 1;
      str++;
    }
  while (str < end && *str >= '0' && *str <= '9')
    ret = ret * 10 + (*str++ - '0');
  return ret;
}

/* Parse the "<len> <key>=<value>\n" records of a pax extended header ('x';
   Solaris 'X' uses the same layout).  Only the keys that matter for
   browsing are honoured: path, linkpath, size and mtime.  An empty value
   cancels the keyword, i.e. the ustar header field stays in effect.  */
static grub_err_t
read_pax (struct grub_archelp_data *data, grub_size_t len, char **name,
	  int *have_longname, int *have_longlink, struct pax_info *pax)
{
  grub_err_t err = GRUB_ERR_NONE;
  char *buf, *p, *end;

  if (len > PAX_MAX_SIZE)
    return grub_error (GRUB_ERR_BAD_FS, N_("pax header too large"));

  buf = grub_malloc (len + 1);
  if (!buf)
    return grub_errno;
  err = grub_disk_read (data->disk, 0, data->hofs + GRUB_DISK_SECTOR_SIZE,
			len, buf);
  if (err)
    goto out;
  buf[len] = 0;

  p = buf;
  end = buf + len;
  while (p < end && *p)
    {
      char *rec = p, *rend, *key, *val;
      grub_size_t reclen = 0, vlen;
      int neg;

      while (p < end && *p >= '0' && *p <= '9' && reclen <= len)
	reclen = reclen * 10 + (*p++ - '0');
      if (p == rec || p >= end || *p != ' ' || reclen > (grub_size_t) (end - rec)
	  || reclen <= (grub_size_t) (p + 1 - rec) || rec[reclen - 1] != '\n')
	{
	  err = grub_error (GRUB_ERR_BAD_FS, N_("invalid pax header"));
	  goto out;
	}
      rend = rec + reclen - 1;
      key = p + 1;
      for (val = key; val < rend && *val != '='; val++)
	;
      if (val == rend)
	{
	  err = grub_error (GRUB_ERR_BAD_FS, N_("invalid pax header"));
	  goto out;
	}
      *val++ = 0;
      *rend = 0;
      vlen = rend - val;
      p = rend + 1;

      if (vlen == 0)
	continue;

      if (grub_strcmp (key, "path") == 0)
	{
	  grub_free (*name);
	  *name = grub_malloc (vlen + 1);
	  if (!*name)
	    {
	      err = grub_errno;
	      goto out;
	    }
	  grub_memcpy (*name, val, vlen + 1);
	  *have_longname = 1;
	}
      else if (grub_strcmp (key, "linkpath") == 0)
	{
	  err = set_linkname (data, val, vlen);
	  if (err)
	    goto out;
	  *have_longlink = 1;
	}
      else if (grub_strcmp (key, "size") == 0)
	{
	  pax->size = read_decimal (val, rend, &neg);
	  pax->have_size = !neg;
	}
      else if (grub_strcmp (key, "mtime") == 0)
	{
	  unsigned long long t = read_decimal (val, rend, &neg);

	  /* Fractional seconds are dropped; out-of-range stamps keep the
	     header value.  */
	  if (t <= 0x7fffffffULL)
	    {
	      pax->mtime = neg ? -(grub_int32_t) t : (grub_int32_t) t;
	      pax->have_mtime = 1;
	    }
	}
    }

 out:
  grub_free (buf);
  return err;
}

static grub_err_t
grub_cpio_find_file (struct grub_archelp_data *data, char **name,
		     grub_int32_t *mtime,
		     grub_archelp_mode_t *mode)
{
  struct head hd;
  int reread = 0, have_longname = 0, have_longlink = 0;
  grub_size_t sz;
  struct pax_info pax = { 0 };

  data->hofs = data->next_hofs;
  *name = NULL;

  /* Metadata entries (GNU 'L'/'K', pax 'x'/'g'/'X') precede the real one.  */
  for (reread = 0; reread < 8; reread++)
    {
      if (grub_disk_read (data->disk, 0, data->hofs, sizeof (hd), &hd))
	return grub_errno;

      if (!hd.name[0] && !hd.prefix[0])
	{
	  *mode = GRUB_ARCHELP_ATTR_END;
	  return GRUB_ERR_NONE;
	}

      if (!head_ok (data->disk, data->hofs, &hd))
	return grub_error (GRUB_ERR_BAD_FS, "invalid tar archive");

      if (hd.typeflag == 'x' || hd.typeflag == 'X' || hd.typeflag == 'g')
	{
	  grub_size_t paxsize;

	  if (grub_cast (read_number (hd.size, sizeof (hd.size)), &paxsize))
	    return grub_error (GRUB_ERR_BAD_FS, N_("pax header size overflow"));

	  /* Global headers ('g') only carry archive-wide defaults such as
	     git-archive's commit id; skip them.  */
	  if (hd.typeflag != 'g')
	    {
	      grub_err_t err;

	      err = read_pax (data, paxsize, name, &have_longname,
			      &have_longlink, &pax);
	      if (err)
		return err;
	    }
	  data->hofs += GRUB_DISK_SECTOR_SIZE
	    + ((paxsize + GRUB_DISK_SECTOR_SIZE - 1) &
	       ~(GRUB_DISK_SECTOR_SIZE - 1));
	  continue;
	}

      if (hd.typeflag == 'L')
	{
	  grub_err_t err;
	  grub_size_t namesize;

	  if (grub_cast (read_number (hd.size, sizeof (hd.size)), &namesize) ||
	      grub_add (namesize, 1, &sz))
	    return grub_error (GRUB_ERR_BAD_FS, N_("name size overflow"));

	  grub_free (*name);
	  *name = grub_malloc (sz);
	  if (*name == NULL)
	    return grub_errno;
	  err = grub_disk_read (data->disk, 0,
				data->hofs + GRUB_DISK_SECTOR_SIZE, namesize,
				*name);
	  (*name)[namesize] = 0;
	  if (err)
	    return err;
	  data->hofs += GRUB_DISK_SECTOR_SIZE
	    + ((namesize + GRUB_DISK_SECTOR_SIZE - 1) &
	       ~(GRUB_DISK_SECTOR_SIZE - 1));
	  have_longname = 1;
	  continue;
	}

      if (hd.typeflag == 'K')
	{
	  grub_err_t err;
	  grub_size_t linksize;

	  if (grub_cast (read_number (hd.size, sizeof (hd.size)), &linksize) ||
	      grub_add (linksize, 1, &sz))
	    return grub_error (GRUB_ERR_BAD_FS, N_("link size overflow"));

	  if (data->linkname_alloc < sz)
	    {
	      char *n;
	      n = grub_calloc (2, sz);
	      if (!n)
		return grub_errno;
	      grub_free (data->linkname);
	      data->linkname = n;
	      data->linkname_alloc = 2 * (sz);
	    }

	  err = grub_disk_read (data->disk, 0,
				data->hofs + GRUB_DISK_SECTOR_SIZE, linksize,
				data->linkname);
	  if (err)
	    return err;
	  data->linkname[linksize] = 0;
	  data->hofs += GRUB_DISK_SECTOR_SIZE
	    + ((linksize + GRUB_DISK_SECTOR_SIZE - 1) &
	       ~(GRUB_DISK_SECTOR_SIZE - 1));
	  have_longlink = 1;
	  continue;
	}

      if (!have_longname)
	{
	  grub_size_t extra_size = 0;

	  while (extra_size < sizeof (hd.prefix)
		 && hd.prefix[extra_size])
	    extra_size++;

	  if (grub_add (sizeof (hd.name) + 2, extra_size, &sz))
	    return grub_error (GRUB_ERR_BAD_FS, N_("long name size overflow"));
	  *name = grub_malloc (sz);
	  if (*name == NULL)
	    return grub_errno;
	  if (hd.prefix[0])
	    {
	      grub_memcpy (*name, hd.prefix, extra_size);
	      (*name)[extra_size++] = '/';
	    }
	  grub_memcpy (*name + extra_size, hd.name, sizeof (hd.name));
	  (*name)[extra_size + sizeof (hd.name)] = 0;
	}

      if (grub_cast (read_number (hd.size, sizeof (hd.size)), &data->size))
	return grub_error (GRUB_ERR_BAD_FS, N_("data size overflow"));
      if (pax.have_size)
	data->size = pax.size;

      data->dofs = data->hofs + GRUB_DISK_SECTOR_SIZE;
      /* pax and base-256 sizes can come close to 2^64.  */
      if (ALIGN_UP_OVF (data->size, GRUB_DISK_SECTOR_SIZE, &data->next_hofs) ||
	  grub_add (data->dofs, data->next_hofs, &data->next_hofs))
	return grub_error (GRUB_ERR_BAD_FS, N_("data size overflow"));
      if (mtime)
	{
	  if (grub_cast (read_number (hd.mtime, sizeof (hd.mtime)), mtime))
	    return grub_error (GRUB_ERR_BAD_FS, N_("mtime overflow"));
	  if (pax.have_mtime)
	    *mtime = pax.mtime;
	}
      if (mode)
	{
	  grub_uint32_t modeval;
	  if (grub_cast (read_number (hd.mode, sizeof (hd.mode)), &modeval))
	    return grub_error (GRUB_ERR_BAD_FS, N_("mode overflow"));

	  *mode = modeval;

	  switch (hd.typeflag)
	    {
	      /* Hardlink.  */
	    case '1':
	      /* Symlink.  */
	    case '2':
	      *mode |= GRUB_ARCHELP_ATTR_LNK;
	      break;
	    case '0':
	      *mode |= GRUB_ARCHELP_ATTR_FILE;
	      break;
	    case '5':
	      *mode |= GRUB_ARCHELP_ATTR_DIR;
	      break;
	      /* Pre-POSIX tars have no type byte and mark a directory by a
		 trailing slash in its name; POSIX also lets a plain file
		 use NUL in place of '0'.  */
	    case '\0':
	      {
		grub_size_t len = *name ? grub_strlen (*name) : 0;

		*mode |= (len != 0 && (*name)[len - 1] == '/')
			 ? GRUB_ARCHELP_ATTR_DIR : GRUB_ARCHELP_ATTR_FILE;
	      }
	      break;
	    }
	}
      if (!have_longlink)
	{
	  if (data->linkname_alloc < 101)
	    {
	      char *n;
	      n = grub_malloc (101);
	      if (!n)
		return grub_errno;
	      grub_free (data->linkname);
	      data->linkname = n;
	      data->linkname_alloc = 101;
	    }
	  grub_memcpy (data->linkname, hd.linkname, sizeof (hd.linkname));
	  data->linkname[100] = 0;
	}
      return GRUB_ERR_NONE;
    }

  /* Too many metadata entries in a row: nothing was filled in for the
     caller, so this cannot be reported as an entry.  */
  grub_free (*name);
  *name = NULL;
  return grub_error (GRUB_ERR_BAD_FS, "invalid tar archive");
}

static char *
grub_cpio_get_link_target (struct grub_archelp_data *data)
{
  return grub_strdup (data->linkname);
}

static grub_uint64_t
grub_cpio_get_size (struct grub_archelp_data *data)
{
  return data->size;
}

static void
grub_cpio_rewind (struct grub_archelp_data *data)
{
  data->next_hofs = 0;
}

static struct grub_archelp_ops arcops =
  {
    .find_file = grub_cpio_find_file,
    .get_link_target = grub_cpio_get_link_target,
    .get_size = grub_cpio_get_size,
    .rewind = grub_cpio_rewind
  };

static struct grub_archelp_data *
grub_cpio_mount (grub_disk_t disk)
{
  struct head hd;
  struct grub_archelp_data *data;

  if (grub_disk_read (disk, 0, 0, sizeof (hd), &hd))
    goto fail;

  if (!head_ok (disk, 0, &hd))
    goto fail;

  data = (struct grub_archelp_data *) grub_zalloc (sizeof (*data));
  if (!data)
    goto fail;

  data->disk = disk;

  return data;

fail:
  grub_error (GRUB_ERR_BAD_FS, "not a tarfs filesystem");
  return 0;
}

static grub_err_t
grub_cpio_dir (grub_device_t device, const char *path_in,
	       grub_fs_dir_hook_t hook, void *hook_data)
{
  struct grub_archelp_data *data;
  grub_err_t err;

  data = grub_cpio_mount (device->disk);
  if (!data)
    return grub_errno;

  err = grub_archelp_dir (data, &arcops,
			  path_in, hook, hook_data);

  grub_free (data->linkname);
  grub_free (data);

  return err;
}

static grub_err_t
grub_cpio_readlink (grub_device_t device, const char *path_in, char **target)
{
  struct grub_archelp_data *data;
  grub_err_t err;

  data = grub_cpio_mount (device->disk);
  if (!data)
    return grub_errno;

  err = grub_archelp_readlink (data, &arcops, path_in, target);

  grub_free (data->linkname);
  grub_free (data);

  return err;
}

static grub_err_t
grub_cpio_open (grub_file_t file, const char *name_in)
{
  struct grub_archelp_data *data;
  grub_err_t err;

  data = grub_cpio_mount (file->device->disk);
  if (!data)
    return grub_errno;

  err = grub_archelp_open (data, &arcops, name_in);
  if (err)
    {
      grub_free (data->linkname);
      grub_free (data);
    }
  else
    {
      file->data = data;
      file->size = data->size;
    }
  return err;
}

static grub_ssize_t
grub_cpio_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_archelp_data *data;
  grub_ssize_t ret;

  data = file->data;

  data->disk->read_hook = file->read_hook;
  data->disk->read_hook_data = file->read_hook_data;
  ret = (grub_disk_read (data->disk, 0, data->dofs + file->offset,
			 len, buf)) ? -1 : (grub_ssize_t) len;
  data->disk->read_hook = 0;

  return ret;
}

static grub_err_t
grub_cpio_close (grub_file_t file)
{
  struct grub_archelp_data *data;

  data = file->data;
  grub_free (data->linkname);
  grub_free (data);

  return grub_errno;
}

static struct grub_fs grub_cpio_fs = {
  .name = "tarfs",
  .fs_dir = grub_cpio_dir,
  .fs_readlink = grub_cpio_readlink,
  .fs_open = grub_cpio_open,
  .fs_read = grub_cpio_read,
  .fs_close = grub_cpio_close,
#ifdef GRUB_UTIL
  .reserved_first_sector = 0,
  .blocklist_install = 0,
#endif
};

GRUB_MOD_INIT (tar)
{
  grub_cpio_fs.mod = mod;
  grub_fs_register (&grub_cpio_fs);
}

GRUB_MOD_FINI (tar)
{
  grub_fs_unregister (&grub_cpio_fs);
}
