/* cbfs.c - cbfs and tar filesystem.  */
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
#include <grub/cbfs_core.h>
#include <grub/lockdown.h>

GRUB_MOD_LICENSE ("GPLv3+");


struct grub_archelp_data
{
  grub_disk_t disk;
  grub_off_t hofs, next_hofs;
  grub_off_t dofs;
  grub_off_t size;
  grub_off_t cbfs_start;
  grub_off_t cbfs_end;
  grub_off_t cbfs_align;
};

static grub_err_t
grub_cbfs_find_file (struct grub_archelp_data *data, char **name,
		     grub_int32_t *mtime,
		     grub_archelp_mode_t *mode)
{
  grub_size_t offset;
  for (;;
       data->dofs = data->hofs + offset,
	 data->next_hofs = ALIGN_UP (data->dofs + data->size, data->cbfs_align))
    {
      struct cbfs_file hd;
      grub_size_t namesize;

      data->hofs = data->next_hofs;

      if (data->hofs >= data->cbfs_end)
	{
	  *mode = GRUB_ARCHELP_ATTR_END;
	  return GRUB_ERR_NONE;
	}

      if (grub_disk_read (data->disk, 0, data->hofs, sizeof (hd), &hd))
	return grub_errno;

      if (grub_memcmp (hd.magic, CBFS_FILE_MAGIC, sizeof (hd.magic)) != 0)
	{
	  *mode = GRUB_ARCHELP_ATTR_END;
	  return GRUB_ERR_NONE;
	}
      data->size = grub_be_to_cpu32 (hd.len);
      (void) mtime;
      offset = grub_be_to_cpu32 (hd.offset);

      *mode = GRUB_ARCHELP_ATTR_FILE | GRUB_ARCHELP_ATTR_NOTIME;

      namesize = offset;
      if (namesize >= sizeof (hd))
	namesize -= sizeof (hd);
      if (namesize == 0)
	continue;
      *name = grub_malloc (namesize + 1);
      if (*name == NULL)
	return grub_errno;

      if (grub_disk_read (data->disk, 0, data->hofs + sizeof (hd),
			  namesize, *name))
	{
	  grub_free (*name);
	  return grub_errno;
	}

      if ((*name)[0] == '\0')
	{
	  grub_free (*name);
	  *name = NULL;
	  continue;
	}

      (*name)[namesize] = 0;

      data->dofs = data->hofs + offset;
      data->next_hofs = ALIGN_UP (data->dofs + data->size, data->cbfs_align);
      return GRUB_ERR_NONE;
    }
}

static void
grub_cbfs_rewind (struct grub_archelp_data *data)
{
  data->next_hofs = data->cbfs_start;
}

static struct grub_archelp_ops arcops =
  {
    .find_file = grub_cbfs_find_file,
    .rewind = grub_cbfs_rewind
  };

static int
validate_head (struct cbfs_header *head)
{
  return (head->magic == grub_cpu_to_be32_compile_time (CBFS_HEADER_MAGIC)
	  && (head->version
	      == grub_cpu_to_be32_compile_time (CBFS_HEADER_VERSION1)
	      || head->version
	      == grub_cpu_to_be32_compile_time (CBFS_HEADER_VERSION2))
	  && (grub_be_to_cpu32 (head->bootblocksize)
	      < grub_be_to_cpu32 (head->romsize))
	  && (grub_be_to_cpu32 (head->offset)
	      < grub_be_to_cpu32 (head->romsize))
	  && (grub_be_to_cpu32 (head->offset)
	      + grub_be_to_cpu32 (head->bootblocksize)
	      < grub_be_to_cpu32 (head->romsize))
	  && head->align != 0
	  && (head->align & (head->align - 1)) == 0
	  && head->romsize != 0);
}

/*
 * Modern coreboot images carry no master header: the flash is carved up by
 * an FMAP (flash map) and the CBFS lives inside one of its areas -- what
 * "cbfstool FILE create -M layout.fmap" produces.  The on-disk layout below
 * is coreboot's src/commonlib/include/commonlib/fmap_serialized.h (all
 * little-endian, unlike the big-endian master header above); coreboot has no
 * header for it in grub, so it is spelled out here.
 */
#define CBFS_FMAP_SIGNATURE	"__FMAP__"
#define CBFS_FMAP_VER_MAJOR	1
#define CBFS_FMAP_STRLEN	32

/* The region cbfstool calls the primary CBFS.  */
#define CBFS_FMAP_REGION	"COREBOOT"

/* CBFS_ALIGNMENT: an FMAP CBFS has no master header to state its alignment,
   every producer uses 64.  */
#define CBFS_FMAP_ALIGN		64

/* Bounds on the search below.  Nothing but a flash image can be a cbfs, so
   refuse to sweep something that is too big to be one (the largest SPI part
   in circulation is 64 MiB).  The stride is the floor of the binary search
   in coreboot's own util/cbfstool/flashmap/fmap.c; a byte-granular FMAP
   would not be found, no layout tool emits one.  */
#define CBFS_FMAP_MAX_IMAGE	(64ULL << 20)
#define CBFS_FMAP_MIN_IMAGE	(64ULL << 10)
#define CBFS_FMAP_STRIDE	16
#define CBFS_FMAP_CHUNK		65536

PRAGMA_BEGIN_PACKED
struct cbfs_fmap
{
  char signature[8];
  grub_uint8_t ver_major;
  grub_uint8_t ver_minor;
  grub_uint64_t base;
  grub_uint32_t size;
  char name[CBFS_FMAP_STRLEN];
  grub_uint16_t nareas;
} GRUB_PACKED;

struct cbfs_fmap_area
{
  grub_uint32_t offset;
  grub_uint32_t size;
  char name[CBFS_FMAP_STRLEN];
  grub_uint16_t flags;
} GRUB_PACKED;
PRAGMA_END_PACKED

/* Does OFF start a cbfs, i.e. is there a file header there?  This is the
   only thing that tells a CBFS area apart from any other FMAP area -- the
   flags word has no bit for it and cbfstool goes by the magic too.  */
static int
cbfs_area_is_cbfs (grub_disk_t disk, grub_off_t off)
{
  struct cbfs_file hd;

  if (grub_disk_read (disk, 0, off, sizeof (hd), &hd))
    {
      grub_errno = GRUB_ERR_NONE;
      return 0;
    }

  return grub_memcmp (hd.magic, CBFS_FILE_MAGIC,
		      sizeof (CBFS_FILE_MAGIC) - 1) == 0;
}

/* Pick the area holding the CBFS out of an FMAP whose header sits at
   FMAP_OFF.  CBFS_FMAP_REGION wins when it is present, so that a ChromeOS
   style image with several CBFSes (FW_MAIN_A/B beside COREBOOT) opens on
   the read-only one; otherwise the first area that starts with a file
   header does.  */
static int
cbfs_fmap_area (grub_disk_t disk, grub_off_t fmap_off, grub_uint16_t nareas,
		grub_off_t total, grub_off_t *start, grub_off_t *end)
{
  grub_off_t off = fmap_off + sizeof (struct cbfs_fmap);
  grub_uint16_t i;
  int found = 0;

  for (i = 0; i < nareas; i++, off += sizeof (struct cbfs_fmap_area))
    {
      struct cbfs_fmap_area area;
      grub_uint32_t abeg, asize;
      int is_region;

      if (grub_disk_read (disk, 0, off, sizeof (area), &area))
	{
	  grub_errno = GRUB_ERR_NONE;
	  return found;
	}

      abeg = grub_le_to_cpu32 (area.offset);
      asize = grub_le_to_cpu32 (area.size);

      /* Areas nest (RO_SECTION contains both FMAP and COREBOOT), so an
         out-of-range one is a reason to skip it, not to give up.  */
      if (asize <= sizeof (struct cbfs_file) || abeg >= total
	  || asize > total - abeg)
	continue;

      is_region = grub_memcmp (area.name, CBFS_FMAP_REGION,
			       sizeof (CBFS_FMAP_REGION)) == 0;
      if (!is_region && found)
	continue;

      if (!cbfs_area_is_cbfs (disk, abeg))
	continue;

      *start = abeg;
      *end = (grub_off_t) abeg + asize;
      found = 1;

      if (is_region)
	break;
    }

  return found;
}

/* Sweep the image for an FMAP header.  */
static int
cbfs_fmap_find (grub_disk_t disk, grub_off_t total,
		grub_off_t *start, grub_off_t *end)
{
  grub_uint8_t *buf;
  grub_off_t pos;
  int found = 0;

  if (total < CBFS_FMAP_MIN_IMAGE || total > CBFS_FMAP_MAX_IMAGE)
    return 0;

  buf = grub_malloc (CBFS_FMAP_CHUNK);
  if (!buf)
    return 0;

  /* CBFS_FMAP_CHUNK is a multiple of the stride and so is every chunk
     boundary, hence no candidate offset ever straddles two chunks.  */
  for (pos = 0; pos + sizeof (struct cbfs_fmap) <= total; pos += CBFS_FMAP_CHUNK)
    {
      grub_size_t len = CBFS_FMAP_CHUNK;
      grub_size_t i;

      if (len > total - pos)
	len = (grub_size_t) (total - pos);

      if (grub_disk_read (disk, 0, pos, len, buf))
	{
	  grub_errno = GRUB_ERR_NONE;
	  break;
	}

      for (i = 0; i + sizeof (CBFS_FMAP_SIGNATURE) - 1 <= len;
	   i += CBFS_FMAP_STRIDE)
	{
	  struct cbfs_fmap fmap;
	  grub_uint32_t fsize;
	  grub_uint16_t nareas;
	  grub_off_t need;

	  if (grub_memcmp (buf + i, CBFS_FMAP_SIGNATURE,
			   sizeof (CBFS_FMAP_SIGNATURE) - 1) != 0)
	    continue;

	  if (grub_disk_read (disk, 0, pos + i, sizeof (fmap), &fmap))
	    {
	      grub_errno = GRUB_ERR_NONE;
	      continue;
	    }

	  if (fmap.ver_major != CBFS_FMAP_VER_MAJOR)
	    continue;

	  /* The map covers the whole flash part, which is this image (or a
	     window into a bigger one, hence <= rather than ==).  */
	  fsize = grub_le_to_cpu32 (fmap.size);
	  nareas = grub_le_to_cpu16 (fmap.nareas);
	  if (fsize < CBFS_FMAP_MIN_IMAGE || fsize > total || nareas == 0)
	    continue;

	  /* The area table follows the header in the same image.  */
	  need = sizeof (struct cbfs_fmap)
	    + (grub_off_t) nareas * sizeof (struct cbfs_fmap_area);
	  if (need > total - (pos + i))
	    continue;

	  if (cbfs_fmap_area (disk, pos + i, nareas, total, start, end))
	    {
	      found = 1;
	      break;
	    }
	}

      if (found)
	break;
    }

  grub_free (buf);
  return found;
}

static struct grub_archelp_data *
grub_cbfs_mount (grub_disk_t disk)
{
  struct cbfs_file hd;
  struct grub_archelp_data *data = NULL;
  grub_uint32_t ptr;
  grub_off_t header_off;
  grub_off_t total;
  struct cbfs_header head;

  if (grub_disk_native_sectors (disk) == GRUB_DISK_SIZE_UNKNOWN)
    goto fail;

  total = grub_disk_native_sectors (disk) << GRUB_DISK_SECTOR_BITS;

  data = (struct grub_archelp_data *) grub_zalloc (sizeof (*data));
  if (!data)
    goto fail;

  if (grub_disk_read (disk, grub_disk_native_sectors (disk) - 1,
		      GRUB_DISK_SECTOR_SIZE - sizeof (ptr),
		      sizeof (ptr), &ptr))
    goto fail;

  ptr = grub_cpu_to_le32 (ptr);
  header_off = total + (grub_int32_t) ptr;

  if (grub_disk_read (disk, 0, header_off, sizeof (head), &head)
      || !validate_head (&head))
    {
      /* No master header: the modern, FMAP-partitioned layout.  The area
         search already checked for a file header at cbfs_start.  */
      grub_errno = GRUB_ERR_NONE;

      if (!cbfs_fmap_find (disk, total, &data->cbfs_start, &data->cbfs_end))
	goto fail;

      data->cbfs_align = CBFS_FMAP_ALIGN;
    }
  else
    {
      data->cbfs_start = total
	- (grub_be_to_cpu32 (head.romsize) - grub_be_to_cpu32 (head.offset));
      data->cbfs_end = total - grub_be_to_cpu32 (head.bootblocksize);
      data->cbfs_align = grub_be_to_cpu32 (head.align);

      if (data->cbfs_start >= total)
	goto fail;
      if (data->cbfs_end > total)
	data->cbfs_end = total;

      if (grub_disk_read (disk, 0, data->cbfs_start, sizeof (hd), &hd))
	goto fail;

      if (grub_memcmp (hd.magic, CBFS_FILE_MAGIC,
		       sizeof (CBFS_FILE_MAGIC) - 1))
	goto fail;
    }

  data->next_hofs = data->cbfs_start;
  data->disk = disk;

  return data;

fail:
  grub_free (data);
  grub_error (GRUB_ERR_BAD_FS, "not a cbfs filesystem");
  return 0;
}

static grub_err_t
grub_cbfs_dir (grub_device_t device, const char *path_in,
	       grub_fs_dir_hook_t hook, void *hook_data)
{
  struct grub_archelp_data *data;
  grub_err_t err;

  data = grub_cbfs_mount (device->disk);
  if (!data)
    return grub_errno;

  err = grub_archelp_dir (data, &arcops,
			  path_in, hook, hook_data);

  grub_free (data);

  return err;
}

static grub_err_t
grub_cbfs_open (grub_file_t file, const char *name_in)
{
  struct grub_archelp_data *data;
  grub_err_t err;

  data = grub_cbfs_mount (file->device->disk);
  if (!data)
    return grub_errno;

  err = grub_archelp_open (data, &arcops, name_in);
  if (err)
    {
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
grub_cbfs_read (grub_file_t file, char *buf, grub_size_t len)
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
grub_cbfs_close (grub_file_t file)
{
  struct grub_archelp_data *data;

  data = file->data;
  grub_free (data);

  return grub_errno;
}

#if (defined (__i386__) || defined (__x86_64__)) && !defined (GRUB_UTIL) \
  && !defined (GRUB_MACHINE_EMU) && !defined (GRUB_MACHINE_XEN)

static char *cbfsdisk_addr;
static grub_off_t cbfsdisk_size = 0;

static int
grub_cbfsdisk_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
		       grub_disk_pull_t pull)
{
  if (pull != GRUB_DISK_PULL_NONE)
    return 0;

  return hook ("cbfsdisk", hook_data);
}

static grub_err_t
grub_cbfsdisk_open (const char *name, grub_disk_t disk)
{
  if (grub_strcmp (name, "cbfsdisk"))
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not a cbfsdisk");

  disk->total_sectors = cbfsdisk_size / GRUB_DISK_SECTOR_SIZE;
  disk->max_agglomerate = GRUB_DISK_MAX_MAX_AGGLOMERATE;
  disk->id = 0;

  return GRUB_ERR_NONE;
}

static void
grub_cbfsdisk_close (grub_disk_t disk __attribute((unused)))
{
}

static grub_err_t
grub_cbfsdisk_read (grub_disk_t disk __attribute((unused)),
		    grub_disk_addr_t sector,
		    grub_size_t size, char *buf)
{
  grub_memcpy (buf, cbfsdisk_addr + (sector << GRUB_DISK_SECTOR_BITS),
	       size << GRUB_DISK_SECTOR_BITS);
  return 0;
}

static grub_err_t
grub_cbfsdisk_write (grub_disk_t disk __attribute__ ((unused)),
		     grub_disk_addr_t sector __attribute__ ((unused)),
		     grub_size_t size __attribute__ ((unused)),
		     const char *buf __attribute__ ((unused)))
{
  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		     "rom flashing isn't implemented yet");
}

static struct grub_disk_dev grub_cbfsdisk_dev =
  {
    .name = "cbfsdisk",
    .id = GRUB_DISK_DEVICE_CBFSDISK_ID,
    .disk_iterate = grub_cbfsdisk_iterate,
    .disk_open = grub_cbfsdisk_open,
    .disk_close = grub_cbfsdisk_close,
    .disk_read = grub_cbfsdisk_read,
    .disk_write = grub_cbfsdisk_write,
    .next = 0
  };

static void
init_cbfsdisk (void)
{
  grub_uint32_t ptr;
  struct cbfs_header *head;

  ptr = *((grub_uint32_t *) grub_absolute_pointer (0xfffffffc));
  head = (struct cbfs_header *) (grub_addr_t) ptr;
  grub_dprintf ("cbfs", "head=%p\n", head);

  /* coreboot current supports only ROMs <= 16 MiB. Bigger ROMs will
     have problems as RCBA is 18 MiB below end of 32-bit typically,
     so either memory map would have to be rearranged or we'd need to support
     reading ROMs through controller directly.
   */
  if (ptr < 0xff000000
      || 0xffffffff - ptr < (grub_uint32_t) sizeof (*head) + 0xf
      || !validate_head (head))
    return;

  cbfsdisk_size = ALIGN_UP (grub_be_to_cpu32 (head->romsize),
			    GRUB_DISK_SECTOR_SIZE);
  cbfsdisk_addr = (void *) (grub_addr_t) (0x100000000ULL - cbfsdisk_size);

  grub_disk_dev_register (&grub_cbfsdisk_dev);
}

static void
fini_cbfsdisk (void)
{
  if (! cbfsdisk_size)
    return;
  grub_disk_dev_unregister (&grub_cbfsdisk_dev);
}

#endif

static struct grub_fs grub_cbfs_fs = {
  .name = "cbfs",
  .fs_dir = grub_cbfs_dir,
  .fs_open = grub_cbfs_open,
  .fs_read = grub_cbfs_read,
  .fs_close = grub_cbfs_close,
#ifdef GRUB_UTIL
  .reserved_first_sector = 0,
  .blocklist_install = 0,
#endif
};

GRUB_MOD_INIT (cbfs)
{
#if (defined (__i386__) || defined (__x86_64__)) && !defined (GRUB_UTIL) && !defined (GRUB_MACHINE_EMU) && !defined (GRUB_MACHINE_XEN)
  init_cbfsdisk ();
#endif
  if (!grub_is_lockdown ())
    {
      grub_cbfs_fs.mod = mod;
      grub_fs_register (&grub_cbfs_fs);
    }
}

GRUB_MOD_FINI (cbfs)
{
  if (!grub_is_lockdown ())
    grub_fs_unregister (&grub_cbfs_fs);
#if (defined (__i386__) || defined (__x86_64__)) && !defined (GRUB_UTIL) && !defined (GRUB_MACHINE_EMU) && !defined (GRUB_MACHINE_XEN)
  fini_cbfsdisk ();
#endif
}
