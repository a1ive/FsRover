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
 * Read-only littlefs driver (on-disk versions lfs2.0 and lfs2.1).
 * See <https://github.com/littlefs-project/littlefs/blob/master/SPEC.md>.
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define LITTLEFS_BLOCK_NULL	0xffffffffU

/* A tag with the valid bit set can never appear in a commit.  */
#define LITTLEFS_TAG_INVALID	0xffffffffU

/* Abstract tag types (type1).  */
#define LITTLEFS_TYPE_NAME		0x000
#define LITTLEFS_TYPE_STRUCT		0x200
#define LITTLEFS_TYPE_SPLICE		0x400
#define LITTLEFS_TYPE_TAIL		0x600

/* Concrete tag types (type3).  */
#define LITTLEFS_TYPE_REG		0x001
#define LITTLEFS_TYPE_DIR		0x002
#define LITTLEFS_TYPE_SUPERBLOCK	0x0ff
#define LITTLEFS_TYPE_DIRSTRUCT		0x200
#define LITTLEFS_TYPE_INLINESTRUCT	0x201
#define LITTLEFS_TYPE_CTZSTRUCT		0x202
#define LITTLEFS_TYPE_CREATE		0x401
#define LITTLEFS_TYPE_DELETE		0x4ff
#define LITTLEFS_TYPE_MOVESTATE		0x7ff

/* Commit terminator, matched on type2 because the low chunk bit is a flag.  */
#define LITTLEFS_TYPE_CCRC		0x500

#define LITTLEFS_MKTAG(type, id, size)		\
  (((grub_uint32_t) (type) << 20)		\
   | ((grub_uint32_t) (id) << 10)		\
   | (grub_uint32_t) (size))

/* 0x3ff in the length field means "deleted", so 0x3fe bytes is the most a
   tag can carry -- and therefore the longest possible file name.  */
#define LITTLEFS_NAME_MAX	0x3fe

/* A CTZ skip-list block must hold two pointers plus the largest file offset,
   which bottoms out at 104 bytes; round up to the smallest plausible erase
   block.  The upper bound only guards the per-mount block buffer.  */
#define LITTLEFS_MIN_BLOCK_SIZE	128
#define LITTLEFS_MAX_BLOCK_SIZE	(8 << 20)

/* On-disk file sizes are capped at 2 GiB - 1 by the format.  */
#define LITTLEFS_FILE_MAX	0x7fffffffU

/* Bytes of block 0 needed to recover the geometry: revision count, the
   superblock name tag with "littlefs", then the inline struct tag with
   version / block size / block count / name max / file max / attr max.  */
#define LITTLEFS_SB_PROBE_SIZE	44

/* Results of the entry comparison callback, as in lfs_bd_cmp.  */
#define LITTLEFS_CMP_EQ		0
#define LITTLEFS_CMP_LT		1
#define LITTLEFS_CMP_GT		2

/* littlefs reports "no such entry" all over its lookup paths; going through
   grub_error for that would leave a bogus message behind on every miss.  */
enum littlefs_status
{
  LITTLEFS_OK,
  LITTLEFS_NOENT,
  LITTLEFS_ERR			/* grub_errno is set */
};

/* The live state of one metadata pair: which of the two blocks is current,
   and what the newest complete commit in it left behind.  */
struct littlefs_mdir
{
  grub_uint32_t pair[2];
  grub_uint32_t rev;
  grub_uint32_t off;		/* end of the newest complete commit */
  grub_uint32_t etag;		/* the tag that closed it */
  grub_uint32_t tail[2];
  grub_uint16_t count;		/* ids in use */
  int split;			/* tail is a hard tail: same directory */
};

/* Brent's algorithm, used on every metadata-pair list we follow.  */
struct littlefs_tortoise
{
  grub_uint32_t pair[2];
  grub_uint32_t i;
  grub_uint32_t period;
};

struct grub_littlefs_data
{
  grub_disk_t disk;
  grub_uint32_t block_size;
  grub_uint32_t block_count;
  grub_uint32_t version;
  grub_uint32_t root[2];
  /* Readable bytes of the device, 0 when it will not say.  */
  grub_uint64_t disk_bytes;
  /* On-disk global state, the XOR sum of the deltas in every metadata pair.
     Only the move state lives here, and it hides the source of a move that
     lost power halfway through.  */
  grub_uint32_t gtag;
  grub_uint32_t gpair[2];
  /* The one metadata block kept decoded in memory.  */
  grub_uint8_t *cbuf;
  grub_uint32_t cblock;
};

struct grub_fshelp_node
{
  struct grub_littlefs_data *data;
  struct littlefs_mdir mdir;	/* the pair the entry lives in */
  grub_uint32_t pair[2];	/* directories: first pair of the directory */
  grub_uint32_t head;		/* files: head of the CTZ skip-list */
  grub_uint32_t size;
  grub_uint16_t id;		/* entry id inside MDIR */
  int isdir;
  int isinline;			/* payload sits in MDIR, not in a CTZ list */
};

/* Entry comparison hook for littlefs_dir_fetchmatch.  ENTRY points at the
   tag's payload inside the cached block.  */
typedef int (*littlefs_match_hook_t) (void *ctx, grub_uint32_t tag,
				      const grub_uint8_t *entry);

struct littlefs_name_match
{
  const char *name;
  grub_uint32_t size;
};

/* CRC-32 with polynomial 0x04c11db7, no final inversion: a running checksum,
   not the usual one-shot digest, so grub's md_crc32 cannot stand in.  */
static grub_uint32_t
littlefs_crc (grub_uint32_t crc, const void *buffer, grub_size_t size)
{
  static const grub_uint32_t rtable[16] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
  };
  const grub_uint8_t *data = buffer;
  grub_size_t i;

  for (i = 0; i < size; i++)
    {
      crc = (crc >> 4) ^ rtable[(crc ^ (data[i] >> 0)) & 0xf];
      crc = (crc >> 4) ^ rtable[(crc ^ (data[i] >> 4)) & 0xf];
    }

  return crc;
}

static grub_uint32_t
littlefs_popc (grub_uint32_t a)
{
  a = a - ((a >> 1) & 0x55555555);
  a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
  return (((a + (a >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
}

/* Smallest power of two greater than or equal to A.  */
static grub_uint32_t
littlefs_npw2 (grub_uint32_t a)
{
  grub_uint32_t r = 0;
  grub_uint32_t s;

  a -= 1;
  s = (a > 0xffff) ? 16U : 0U; a >>= s; r |= s;
  s = (a > 0xff) ? 8U : 0U;    a >>= s; r |= s;
  s = (a > 0xf) ? 4U : 0U;     a >>= s; r |= s;
  s = (a > 0x3) ? 2U : 0U;     a >>= s; r |= s;
  return (r | (a >> 1)) + 1;
}

static grub_uint32_t
littlefs_ctz (grub_uint32_t a)
{
  return littlefs_npw2 ((a & (~a + 1)) + 1) - 1;
}

/* Revision counts wrap, so they are compared as a sequence distance.  */
static int
littlefs_rev_newer (grub_uint32_t a, grub_uint32_t b)
{
  return (grub_int32_t) (a - b) > 0;
}

static int
littlefs_tag_isvalid (grub_uint32_t tag)
{
  return !(tag & 0x80000000);
}

static int
littlefs_tag_isdelete (grub_uint32_t tag)
{
  return (tag & 0x3ff) == 0x3ff;
}

static grub_uint16_t
littlefs_tag_type1 (grub_uint32_t tag)
{
  return (grub_uint16_t) ((tag & 0x70000000) >> 20);
}

static grub_uint16_t
littlefs_tag_type2 (grub_uint32_t tag)
{
  return (grub_uint16_t) ((tag & 0x78000000) >> 20);
}

static grub_uint16_t
littlefs_tag_type3 (grub_uint32_t tag)
{
  return (grub_uint16_t) ((tag & 0x7ff00000) >> 20);
}

static grub_uint8_t
littlefs_tag_chunk (grub_uint32_t tag)
{
  return (grub_uint8_t) ((tag & 0x0ff00000) >> 20);
}

/* The chunk field of a splice tag is a signed count of created/deleted ids;
   sign-extend it so that adding it to a tag shifts the id field the way
   LFS_MKTAG(0, lfs_tag_splice(tag), 0) does.  */
static grub_uint32_t
littlefs_tag_splice (grub_uint32_t tag)
{
  return (grub_uint32_t) (grub_int32_t) (grub_int8_t) littlefs_tag_chunk (tag);
}

static grub_uint16_t
littlefs_tag_id (grub_uint32_t tag)
{
  return (grub_uint16_t) ((tag & 0x000ffc00) >> 10);
}

static grub_uint32_t
littlefs_tag_size (grub_uint32_t tag)
{
  return tag & 0x3ff;
}

/* Tag plus payload.  A deleted tag carries nothing, and the +1 turns its
   0x3ff length field into 0 without a branch.  */
static grub_uint32_t
littlefs_tag_dsize (grub_uint32_t tag)
{
  return 4 + littlefs_tag_size (tag + (grub_uint32_t) littlefs_tag_isdelete (tag));
}

static int
littlefs_pair_isnull (const grub_uint32_t pair[2])
{
  return pair[0] == LITTLEFS_BLOCK_NULL || pair[1] == LITTLEFS_BLOCK_NULL;
}

/* Zero when the two pairs name the same metadata pair; the blocks may have
   been swapped, and a half-relocated pair still counts as the same one.  */
static int
littlefs_pair_cmp (const grub_uint32_t a[2], const grub_uint32_t b[2])
{
  return !(a[0] == b[0] || a[1] == b[1] || a[0] == b[1] || a[1] == b[0]);
}

static int
littlefs_pair_issync (const grub_uint32_t a[2], const grub_uint32_t b[2])
{
  return (a[0] == b[0] && a[1] == b[1]) || (a[0] == b[1] && a[1] == b[0]);
}

static void
littlefs_tortoise_init (struct littlefs_tortoise *t)
{
  t->pair[0] = LITTLEFS_BLOCK_NULL;
  t->pair[1] = LITTLEFS_BLOCK_NULL;
  t->i = 1;
  t->period = 1;
}

static grub_err_t
littlefs_tortoise_step (struct littlefs_tortoise *t, const grub_uint32_t pair[2])
{
  if (littlefs_pair_issync (pair, t->pair))
    return grub_error (GRUB_ERR_BAD_FS, "littlefs: cycle in metadata pair list");

  if (t->i == t->period)
    {
      t->pair[0] = pair[0];
      t->pair[1] = pair[1];
      t->i = 0;
      t->period *= 2;
    }
  t->i++;

  return GRUB_ERR_NONE;
}

static grub_err_t
littlefs_disk_read (struct grub_littlefs_data *data, grub_uint32_t block,
		    grub_uint32_t off, void *buf, grub_uint32_t size)
{
  grub_disk_addr_t pos;

  if (block >= data->block_count || off > data->block_size
      || size > data->block_size - off)
    return grub_error (GRUB_ERR_BAD_FS, "littlefs: read outside block %u", block);

  pos = (grub_disk_addr_t) block * data->block_size + off;
  return grub_disk_read (data->disk, pos >> GRUB_DISK_SECTOR_BITS,
			 pos & (GRUB_DISK_SECTOR_SIZE - 1), size, buf);
}

/* Metadata is walked tag by tag in both directions, so the whole block is
   pulled in once and every later access is a memcpy.  */
static grub_err_t
littlefs_mread (struct grub_littlefs_data *data, grub_uint32_t block,
		grub_uint32_t off, void *buf, grub_uint32_t size)
{
  if (data->cblock != block)
    {
      grub_uint32_t avail = data->block_size;
      grub_disk_addr_t base;

      if (block >= data->block_count)
	return grub_error (GRUB_ERR_BAD_FS, "littlefs: block %u out of range",
			   block);

      base = (grub_disk_addr_t) block * data->block_size;

      /* An image that stops part way into a block still has the bytes before
	 the cut.  Flash reads as 0xff wherever nothing was programmed, and so
	 does the missing tail here, which makes the commit replay stop at the
	 cut instead of writing the entire pair off as unreadable.  Payload
	 reads do not get this treatment -- littlefs_disk_read still fails
	 rather than hand back invented file content.  */
      if (data->disk_bytes != 0)
	{
	  if (base >= data->disk_bytes)
	    avail = 0;
	  else if (data->disk_bytes - base < avail)
	    avail = (grub_uint32_t) (data->disk_bytes - base);
	}

      data->cblock = LITTLEFS_BLOCK_NULL;
      if (avail != 0
	  && grub_disk_read (data->disk, base >> GRUB_DISK_SECTOR_BITS,
			     base & (GRUB_DISK_SECTOR_SIZE - 1),
			     avail, data->cbuf) != GRUB_ERR_NONE)
	return grub_errno;
      if (avail != data->block_size)
	grub_memset (data->cbuf + avail, 0xff, data->block_size - avail);
      data->cblock = block;
    }

  if (off > data->block_size || size > data->block_size - off)
    return grub_error (GRUB_ERR_BAD_FS, "littlefs: read outside block %u", block);

  grub_memcpy (buf, data->cbuf + off, size);
  return GRUB_ERR_NONE;
}

/* Walk MDIR's log backwards and return the newest tag matching GTAG under
   GMASK, copying GSIZE bytes of its payload from offset GOFF into GBUFFER.
   Short payloads are zero padded, as lfs_dir_getslice does.  */
static enum littlefs_status
littlefs_dir_getslice (struct grub_littlefs_data *data,
		       const struct littlefs_mdir *mdir,
		       grub_uint32_t gmask, grub_uint32_t gtag,
		       grub_uint32_t goff, void *gbuffer, grub_uint32_t gsize,
		       grub_uint32_t *outtag)
{
  grub_uint32_t off = mdir->off;
  grub_uint32_t ntag = mdir->etag;
  grub_uint32_t gdiff = 0;

  /* A move that lost power is still recorded twice on disk.  The source copy
     counts as deleted, and the ids above it shift down by one.  */
  if (littlefs_tag_type1 (data->gtag) != 0
      && littlefs_pair_cmp (data->gpair, mdir->pair) == 0
      && littlefs_tag_id (gmask) != 0)
    {
      if (littlefs_tag_id (data->gtag) == littlefs_tag_id (gtag))
	return LITTLEFS_NOENT;
      if (littlefs_tag_id (data->gtag) < littlefs_tag_id (gtag))
	gdiff -= LITTLEFS_MKTAG (0, 1, 0);
    }

  while (off >= 4 + littlefs_tag_dsize (ntag))
    {
      grub_uint32_t tag;
      grub_uint32_t raw;

      off -= littlefs_tag_dsize (ntag);
      tag = ntag;
      if (littlefs_mread (data, mdir->pair[0], off, &raw, 4) != GRUB_ERR_NONE)
	return LITTLEFS_ERR;
      ntag = (grub_be_to_cpu32 (raw) ^ tag) & 0x7fffffff;

      /* Creations and deletions renumber everything above them, so the id we
	 are looking for drifts as we walk further back.  */
      if (littlefs_tag_id (gmask) != 0
	  && littlefs_tag_type1 (tag) == LITTLEFS_TYPE_SPLICE
	  && littlefs_tag_id (tag) <= littlefs_tag_id (gtag - gdiff))
	{
	  if (tag == (LITTLEFS_MKTAG (LITTLEFS_TYPE_CREATE, 0, 0)
		      | (LITTLEFS_MKTAG (0, 0x3ff, 0) & (gtag - gdiff))))
	    return LITTLEFS_NOENT;

	  gdiff += littlefs_tag_splice (tag) << 10;
	}

      if ((gmask & tag) == (gmask & (gtag - gdiff)))
	{
	  grub_uint32_t tsize;
	  grub_uint32_t diff;

	  if (littlefs_tag_isdelete (tag))
	    return LITTLEFS_NOENT;

	  tsize = littlefs_tag_size (tag);
	  diff = goff < tsize ? tsize - goff : 0;
	  if (diff > gsize)
	    diff = gsize;

	  if (diff != 0
	      && littlefs_mread (data, mdir->pair[0], off + 4 + goff,
				 gbuffer, diff) != GRUB_ERR_NONE)
	    return LITTLEFS_ERR;
	  grub_memset ((grub_uint8_t *) gbuffer + diff, 0, gsize - diff);

	  *outtag = tag + gdiff;
	  return LITTLEFS_OK;
	}
    }

  return LITTLEFS_NOENT;
}

static int
littlefs_name_match (void *ctx, grub_uint32_t tag, const grub_uint8_t *entry)
{
  struct littlefs_name_match *m = ctx;
  grub_uint32_t tsize = littlefs_tag_size (tag);
  grub_uint32_t diff = m->size < tsize ? m->size : tsize;
  int res;

  res = grub_memcmp (entry, m->name, diff);
  if (res != 0)
    return res < 0 ? LITTLEFS_CMP_LT : LITTLEFS_CMP_GT;

  if (m->size != tsize)
    return m->size < tsize ? LITTLEFS_CMP_LT : LITTLEFS_CMP_GT;

  return LITTLEFS_CMP_EQ;
}

/* Replay the commit log in MDIR->pair[0].  Every commit that checksums out
   publishes its state into MDIR, so whatever survives is the newest complete
   commit; MDIR->off stays 0 when the block holds none.  A block that cannot
   be read is simply barren -- that is what the second block of the pair is
   for -- so no error escapes here.  */
static void
littlefs_mdir_scan (struct grub_littlefs_data *data, struct littlefs_mdir *mdir,
		    grub_uint32_t fmask, grub_uint32_t ftag,
		    littlefs_match_hook_t cb, void *cbdata,
		    grub_uint32_t *besttag)
{
  grub_uint32_t off = 0;
  grub_uint32_t ptag = LITTLEFS_TAG_INVALID;
  grub_uint32_t tempbesttag = *besttag;
  grub_uint32_t temptail[2] = { LITTLEFS_BLOCK_NULL, LITTLEFS_BLOCK_NULL };
  grub_uint16_t tempcount = 0;
  int tempsplit = 0;
  grub_uint32_t crc;
  grub_uint32_t rev;
  const grub_uint8_t *blk;

  if (littlefs_mread (data, mdir->pair[0], 0, &rev, 4) != GRUB_ERR_NONE)
    {
      grub_errno = GRUB_ERR_NONE;
      return;
    }
  blk = data->cbuf;

  /* The revision count is the first thing the commit checksum covers.  */
  crc = littlefs_crc (0xffffffff, &rev, 4);

  while (1)
    {
      grub_uint32_t tag;
      grub_uint32_t dsize;

      off += littlefs_tag_dsize (ptag);
      if (off + 4 > data->block_size)
	break;

      crc = littlefs_crc (crc, blk + off, 4);
      tag = grub_be_to_cpu32 (grub_get_unaligned32 (blk + off)) ^ ptag;

      /* The valid bit flips at every commit boundary, so a tag that fails it
	 marks the end of what was ever written.  */
      if (!littlefs_tag_isvalid (tag))
	break;

      dsize = littlefs_tag_dsize (tag);
      if (dsize > data->block_size - off)
	break;

      ptag = tag;

      if (littlefs_tag_type2 (tag) == LITTLEFS_TYPE_CCRC)
	{
	  if (dsize < 8
	      || crc != grub_le_to_cpu32 (grub_get_unaligned32 (blk + off + 4)))
	    break;

	  /* The CRC tag dictates the valid bit the next commit must use.  */
	  ptag ^= (grub_uint32_t) (littlefs_tag_chunk (tag) & 1) << 31;

	  *besttag = tempbesttag;
	  mdir->off = off + dsize;
	  mdir->etag = ptag;
	  mdir->count = tempcount;
	  mdir->tail[0] = temptail[0];
	  mdir->tail[1] = temptail[1];
	  mdir->split = tempsplit;

	  crc = 0xffffffff;
	  continue;
	}

      crc = littlefs_crc (crc, blk + off + 4, dsize - 4);

      if (littlefs_tag_type1 (tag) == LITTLEFS_TYPE_NAME)
	{
	  if (littlefs_tag_id (tag) >= tempcount)
	    tempcount = (grub_uint16_t) (littlefs_tag_id (tag) + 1);
	}
      else if (littlefs_tag_type1 (tag) == LITTLEFS_TYPE_SPLICE)
	{
	  tempcount = (grub_uint16_t) (tempcount + littlefs_tag_splice (tag));

	  if (tag == (LITTLEFS_MKTAG (LITTLEFS_TYPE_DELETE, 0, 0)
		      | (LITTLEFS_MKTAG (0, 0x3ff, 0) & tempbesttag)))
	    tempbesttag |= 0x80000000;
	  else if (tempbesttag != LITTLEFS_TAG_INVALID
		   && littlefs_tag_id (tag) <= littlefs_tag_id (tempbesttag))
	    tempbesttag += littlefs_tag_splice (tag) << 10;
	}
      else if (littlefs_tag_type1 (tag) == LITTLEFS_TYPE_TAIL)
	{
	  if (dsize < 12)
	    break;
	  tempsplit = (littlefs_tag_chunk (tag) & 1);
	  temptail[0] = grub_le_to_cpu32 (grub_get_unaligned32 (blk + off + 4));
	  temptail[1] = grub_le_to_cpu32 (grub_get_unaligned32 (blk + off + 8));
	}

      if (cb != 0 && (fmask & tag) == (fmask & ftag))
	{
	  int res = cb (cbdata, tag, blk + off + 4);

	  if (res == LITTLEFS_CMP_EQ)
	    tempbesttag = tag;
	  else if ((LITTLEFS_MKTAG (0x7ff, 0x3ff, 0) & tag)
		   == (LITTLEFS_MKTAG (0x7ff, 0x3ff, 0) & tempbesttag))
	    /* The same tag again with different contents: our match was
	       superseded by this commit.  */
	    tempbesttag = LITTLEFS_TAG_INVALID;
	  else if (res == LITTLEFS_CMP_GT
		   && littlefs_tag_id (tag) <= littlefs_tag_id (tempbesttag))
	    /* Entries are stored sorted, so remember that we already walked
	       past where the wanted name would have been.  */
	    tempbesttag = tag | 0x80000000;
	}
    }
}

/* Load the metadata pair PAIR into MDIR, and while the log is being replayed
   anyway, note the newest tag matching FTAG under FMASK whose payload CB
   accepts.  *BESTTAG_OUT is left 0 when there is no match here.  */
static enum littlefs_status
littlefs_dir_fetchmatch (struct grub_littlefs_data *data,
			 struct littlefs_mdir *mdir, const grub_uint32_t pair[2],
			 grub_uint32_t fmask, grub_uint32_t ftag,
			 littlefs_match_hook_t cb, void *cbdata,
			 grub_uint32_t *besttag_out)
{
  grub_uint32_t besttag = LITTLEFS_TAG_INVALID;
  grub_uint32_t revs[2] = { 0, 0 };
  int corrupt[2] = { 0, 0 };
  int r = 0;
  int i;

  *besttag_out = 0;

  if (pair[0] >= data->block_count || pair[1] >= data->block_count)
    {
      grub_error (GRUB_ERR_BAD_FS, "littlefs: metadata pair out of range");
      return LITTLEFS_ERR;
    }

  for (i = 0; i < 2; i++)
    {
      grub_uint32_t rev;

      if (littlefs_disk_read (data, pair[i], 0, &rev, 4) != GRUB_ERR_NONE)
	{
	  grub_errno = GRUB_ERR_NONE;
	  corrupt[i] = 1;
	  continue;
	}
      revs[i] = grub_le_to_cpu32 (rev);
    }

  if (!corrupt[1] && littlefs_rev_newer (revs[1], revs[0]))
    r = 1;

  mdir->pair[0] = pair[r];
  mdir->pair[1] = pair[(r + 1) % 2];
  mdir->rev = revs[r];
  mdir->off = 0;
  mdir->etag = 0;
  mdir->count = 0;
  mdir->tail[0] = LITTLEFS_BLOCK_NULL;
  mdir->tail[1] = LITTLEFS_BLOCK_NULL;
  mdir->split = 0;

  for (i = 0; i < 2; i++)
    {
      littlefs_mdir_scan (data, mdir, fmask, ftag, cb, cbdata, &besttag);

      if (mdir->off == 0)
	{
	  /* Nothing usable in this block, fall back on its twin.  */
	  grub_uint32_t t = mdir->pair[0];

	  mdir->pair[0] = mdir->pair[1];
	  mdir->pair[1] = t;
	  mdir->rev = revs[(r + 1) % 2];
	  continue;
	}

      /* Same fixup as in littlefs_dir_getslice: an interrupted move deletes
	 its source and shifts the ids above it.  */
      if (littlefs_tag_type1 (data->gtag) != 0
	  && littlefs_pair_cmp (data->gpair, mdir->pair) == 0)
	{
	  if (littlefs_tag_id (data->gtag) == littlefs_tag_id (besttag))
	    besttag |= 0x80000000;
	  else if (besttag != LITTLEFS_TAG_INVALID
		   && littlefs_tag_id (data->gtag) < littlefs_tag_id (besttag))
	    besttag -= LITTLEFS_MKTAG (0, 1, 0);
	}

      if (littlefs_tag_isvalid (besttag))
	{
	  *besttag_out = besttag;
	  return LITTLEFS_OK;
	}

      /* An id below the entry count means we walked past the wanted name in
	 a sorted pair, so no later pair can hold it either.  */
      if (littlefs_tag_id (besttag) < mdir->count)
	return LITTLEFS_NOENT;

      return LITTLEFS_OK;
    }

  grub_error (GRUB_ERR_BAD_FS, "littlefs: corrupted metadata pair {%u, %u}",
	      pair[0], pair[1]);
  return LITTLEFS_ERR;
}

static enum littlefs_status
littlefs_dir_fetch (struct grub_littlefs_data *data, struct littlefs_mdir *mdir,
		    const grub_uint32_t pair[2])
{
  grub_uint32_t tag;

  /* No callback, and a mask/tag pair with the valid bit set that no real tag
     can ever match.  */
  return littlefs_dir_fetchmatch (data, mdir, pair, LITTLEFS_TAG_INVALID,
				  LITTLEFS_TAG_INVALID, 0, 0, &tag);
}

/* XOR this pair's global-state delta into GSTATE.  */
static enum littlefs_status
littlefs_dir_getgstate (struct grub_littlefs_data *data,
			const struct littlefs_mdir *mdir, grub_uint32_t gstate[3])
{
  grub_uint8_t buf[12];
  grub_uint32_t tag;
  enum littlefs_status status;

  status = littlefs_dir_getslice (data, mdir, LITTLEFS_MKTAG (0x7ff, 0, 0),
				  LITTLEFS_MKTAG (LITTLEFS_TYPE_MOVESTATE, 0, 0),
				  0, buf, sizeof (buf), &tag);
  if (status == LITTLEFS_NOENT)
    return LITTLEFS_OK;
  if (status != LITTLEFS_OK)
    return status;

  gstate[0] ^= grub_le_to_cpu32 (grub_get_unaligned32 (buf));
  gstate[1] ^= grub_le_to_cpu32 (grub_get_unaligned32 (buf + 4));
  gstate[2] ^= grub_le_to_cpu32 (grub_get_unaligned32 (buf + 8));
  return LITTLEFS_OK;
}

/* Attach the data structure behind the entry NAMETAG describes to NODE.  */
static enum littlefs_status
littlefs_fill_node (struct grub_littlefs_data *data,
		    const struct littlefs_mdir *mdir, grub_uint32_t nametag,
		    struct grub_fshelp_node *node)
{
  grub_uint8_t st[8];
  grub_uint32_t tag;
  grub_uint16_t id = littlefs_tag_id (nametag);
  enum littlefs_status status;

  status = littlefs_dir_getslice (data, mdir, LITTLEFS_MKTAG (0x700, 0x3ff, 0),
				  LITTLEFS_MKTAG (LITTLEFS_TYPE_STRUCT, id, 0),
				  0, st, sizeof (st), &tag);
  if (status != LITTLEFS_OK)
    return status;

  node->data = data;
  node->mdir = *mdir;
  node->id = id;
  node->isdir = (littlefs_tag_type3 (nametag) == LITTLEFS_TYPE_DIR);

  switch (littlefs_tag_type3 (tag))
    {
    case LITTLEFS_TYPE_DIRSTRUCT:
      node->pair[0] = grub_le_to_cpu32 (grub_get_unaligned32 (st));
      node->pair[1] = grub_le_to_cpu32 (grub_get_unaligned32 (st + 4));
      break;

    case LITTLEFS_TYPE_CTZSTRUCT:
      node->head = grub_le_to_cpu32 (grub_get_unaligned32 (st));
      node->size = grub_le_to_cpu32 (grub_get_unaligned32 (st + 4));
      if (node->size > LITTLEFS_FILE_MAX
	  || (node->size != 0 && node->head >= data->block_count))
	return LITTLEFS_NOENT;
      break;

    case LITTLEFS_TYPE_INLINESTRUCT:
      node->isinline = 1;
      node->size = littlefs_tag_size (tag);
      break;

    default:
      return LITTLEFS_NOENT;
    }

  /* A name tag and a struct tag that disagree about the entry's kind mean a
     damaged pair; treat the entry as absent rather than chasing a bogus
     metadata pair through the directory walk.  */
  if (node->isdir != (littlefs_tag_type3 (tag) == LITTLEFS_TYPE_DIRSTRUCT))
    return LITTLEFS_NOENT;

  return LITTLEFS_OK;
}

/* Resolve id ID of MDIR into NAME (at least LITTLEFS_NAME_MAX + 1 bytes) and
   NODE.  Ids that no longer carry a name tag come back as LITTLEFS_NOENT.  */
static enum littlefs_status
littlefs_dir_getinfo (struct grub_littlefs_data *data,
		      const struct littlefs_mdir *mdir, grub_uint16_t id,
		      char *name, struct grub_fshelp_node *node)
{
  grub_uint32_t tag;
  enum littlefs_status status;

  /* Masking on type2 keeps the superblock entry (type 0x0ff, id 0 of the root
     pair) out of the listing: only 0x00x names are real files.  */
  status = littlefs_dir_getslice (data, mdir, LITTLEFS_MKTAG (0x780, 0x3ff, 0),
				  LITTLEFS_MKTAG (LITTLEFS_TYPE_NAME, id, 0),
				  0, name, LITTLEFS_NAME_MAX + 1, &tag);
  if (status != LITTLEFS_OK)
    return status;

  return littlefs_fill_node (data, mdir, tag, node);
}

/* Index of the CTZ skip-list block holding byte *OFF, with *OFF rewritten to
   the offset inside that block -- past the skip pointers it starts with.  */
static grub_uint32_t
littlefs_ctz_index (grub_uint32_t block_size, grub_uint32_t *off)
{
  grub_uint32_t size = *off;
  grub_uint32_t b = block_size - 2 * 4;
  grub_uint32_t i = size / b;

  if (i == 0)
    return 0;

  i = (size - 4 * (littlefs_popc (i - 1) + 2)) / b;
  *off = size - b * i - 4 * littlefs_popc (i);
  return i;
}

/* Follow the skip-list backwards from HEAD (the last block of the file) to
   the block holding byte POS.  */
static grub_err_t
littlefs_ctz_find (struct grub_littlefs_data *data, grub_uint32_t head,
		   grub_uint32_t size, grub_uint32_t pos,
		   grub_uint32_t *block, grub_uint32_t *off)
{
  grub_uint32_t tpos = pos;
  grub_uint32_t cpos = size - 1;
  grub_uint32_t current;
  grub_uint32_t target;

  current = littlefs_ctz_index (data->block_size, &cpos);
  target = littlefs_ctz_index (data->block_size, &tpos);

  while (current > target)
    {
      grub_uint32_t reach = littlefs_npw2 (current - target + 1) - 1;
      grub_uint32_t have = littlefs_ctz (current);
      grub_uint32_t skip = reach < have ? reach : have;
      grub_uint32_t next;
      grub_err_t err;

      err = littlefs_disk_read (data, head, 4 * skip, &next, 4);
      if (err != GRUB_ERR_NONE)
	return err;

      head = grub_le_to_cpu32 (next);
      current -= 1U << skip;
    }

  if (head >= data->block_count || tpos >= data->block_size)
    return grub_error (GRUB_ERR_BAD_FS, "littlefs: bad CTZ skip-list pointer");

  *block = head;
  *off = tpos;
  return GRUB_ERR_NONE;
}

static grub_ssize_t
littlefs_read_data (struct grub_fshelp_node *node, grub_off_t pos,
		    char *buf, grub_size_t len)
{
  struct grub_littlefs_data *data = node->data;
  grub_size_t total = 0;

  if (pos >= node->size)
    return 0;
  if (len > node->size - pos)
    len = (grub_size_t) (node->size - pos);

  if (node->isinline)
    {
      grub_uint32_t tag;

      if (littlefs_dir_getslice (data, &node->mdir,
				 LITTLEFS_MKTAG (0x7ff, 0x3ff, 0),
				 LITTLEFS_MKTAG (LITTLEFS_TYPE_INLINESTRUCT,
						 node->id, 0),
				 (grub_uint32_t) pos, buf,
				 (grub_uint32_t) len, &tag) != LITTLEFS_OK)
	{
	  if (grub_errno == GRUB_ERR_NONE)
	    grub_error (GRUB_ERR_BAD_FS, "littlefs: inline data disappeared");
	  return -1;
	}

      return (grub_ssize_t) len;
    }

  while (total < len)
    {
      grub_uint32_t block;
      grub_uint32_t boff;
      grub_uint32_t diff;

      if (littlefs_ctz_find (data, node->head, node->size,
			     (grub_uint32_t) (pos + total),
			     &block, &boff) != GRUB_ERR_NONE)
	return -1;

      diff = data->block_size - boff;
      if (diff > len - total)
	diff = (grub_uint32_t) (len - total);

      if (littlefs_disk_read (data, block, boff, buf + total, diff)
	  != GRUB_ERR_NONE)
	return -1;

      total += diff;
    }

  return (grub_ssize_t) total;
}

static grub_err_t
littlefs_lookup_file (grub_fshelp_node_t dir, const char *name,
		      grub_fshelp_node_t *foundnode,
		      enum grub_fshelp_filetype *foundtype)
{
  struct grub_littlefs_data *data = dir->data;
  struct littlefs_mdir mdir;
  struct littlefs_name_match match;
  struct littlefs_tortoise tortoise;
  struct grub_fshelp_node *node;
  grub_uint32_t pair[2];
  grub_uint32_t tag = 0;
  grub_size_t namelen = grub_strlen (name);

  if (namelen > LITTLEFS_NAME_MAX)
    return GRUB_ERR_NONE;

  match.name = name;
  match.size = (grub_uint32_t) namelen;

  pair[0] = dir->pair[0];
  pair[1] = dir->pair[1];
  littlefs_tortoise_init (&tortoise);

  /* A directory is a list of metadata pairs kept in sorted order, so the
     name may live in any pair reachable through the hard tails.  */
  while (1)
    {
      enum littlefs_status status;
      grub_err_t err;

      err = littlefs_tortoise_step (&tortoise, pair);
      if (err != GRUB_ERR_NONE)
	return err;

      status = littlefs_dir_fetchmatch (data, &mdir, pair,
					LITTLEFS_MKTAG (0x780, 0, 0),
					LITTLEFS_MKTAG (LITTLEFS_TYPE_NAME, 0, 0),
					littlefs_name_match, &match, &tag);
      if (status == LITTLEFS_ERR)
	return grub_errno;
      if (status == LITTLEFS_NOENT)
	return GRUB_ERR_NONE;
      if (tag != 0)
	break;
      if (!mdir.split)
	return GRUB_ERR_NONE;

      pair[0] = mdir.tail[0];
      pair[1] = mdir.tail[1];
    }

  node = grub_zalloc (sizeof (*node));
  if (!node)
    return grub_errno;

  if (littlefs_fill_node (data, &mdir, tag, node) != LITTLEFS_OK)
    {
      grub_free (node);
      if (grub_errno != GRUB_ERR_NONE)
	return grub_errno;
      return GRUB_ERR_NONE;
    }

  *foundnode = node;
  *foundtype = node->isdir ? GRUB_FSHELP_DIR : GRUB_FSHELP_REG;
  return GRUB_ERR_NONE;
}

/* Pull the geometry out of the superblock that starts at BASE.  Returns 0 if
   there is no superblock there; grub_errno is left clean either way.  */
static int
littlefs_probe_superblock (grub_disk_t disk, grub_disk_addr_t base,
			   grub_uint32_t *block_size, grub_uint32_t *block_count,
			   grub_uint32_t *version)
{
  grub_uint8_t buf[LITTLEFS_SB_PROBE_SIZE];
  grub_uint32_t nametag;
  grub_uint32_t structtag;
  grub_uint32_t bs;
  grub_uint32_t bc;

  if (grub_disk_read (disk, base >> GRUB_DISK_SECTOR_BITS,
		      base & (GRUB_DISK_SECTOR_SIZE - 1),
		      sizeof (buf), buf) != GRUB_ERR_NONE)
    {
      grub_errno = GRUB_ERR_NONE;
      return 0;
    }

  /* The first tag of the block, un-XORed from the initial 0xffffffff.  */
  nametag = grub_be_to_cpu32 (grub_get_unaligned32 (buf + 4)) ^ 0xffffffff;
  if (nametag != LITTLEFS_MKTAG (LITTLEFS_TYPE_SUPERBLOCK, 0, 8)
      || grub_memcmp (buf + 8, "littlefs", 8) != 0)
    return 0;

  structtag = grub_be_to_cpu32 (grub_get_unaligned32 (buf + 16)) ^ nametag;
  if (littlefs_tag_type3 (structtag) != LITTLEFS_TYPE_INLINESTRUCT
      || littlefs_tag_id (structtag) != 0
      || littlefs_tag_size (structtag) < 12)
    return 0;

  bs = grub_le_to_cpu32 (grub_get_unaligned32 (buf + 24));
  bc = grub_le_to_cpu32 (grub_get_unaligned32 (buf + 28));

  if (bs < LITTLEFS_MIN_BLOCK_SIZE || bs > LITTLEFS_MAX_BLOCK_SIZE || bc < 2)
    return 0;

  *version = grub_le_to_cpu32 (grub_get_unaligned32 (buf + 20));
  *block_size = bs;
  *block_count = bc;
  return 1;
}

static void
grub_littlefs_unmount (struct grub_littlefs_data *data)
{
  grub_free (data->cbuf);
  grub_free (data);
}

static struct grub_littlefs_data *
grub_littlefs_mount (grub_disk_t disk)
{
  struct grub_littlefs_data *data;
  struct littlefs_mdir mdir;
  struct littlefs_tortoise tortoise;
  struct littlefs_name_match match;
  grub_uint32_t gstate[3] = { 0, 0, 0 };
  grub_uint32_t block_size = 0;
  grub_uint32_t block_count = 0;
  grub_uint32_t version = 0;
  grub_uint32_t limit;
  grub_uint64_t sectors;
  int found_root = 0;

  data = grub_zalloc (sizeof (*data));
  if (!data)
    return 0;
  data->disk = disk;
  data->cblock = LITTLEFS_BLOCK_NULL;

  if (!littlefs_probe_superblock (disk, 0, &block_size, &block_count, &version))
    {
      grub_uint32_t bs;

      /* Block 0 is unreadable or was clobbered.  Its twin holds the same
	 superblock, but finding it means guessing the block size; erase
	 blocks are powers of two in practice.  */
      for (bs = LITTLEFS_MIN_BLOCK_SIZE; bs <= LITTLEFS_MAX_BLOCK_SIZE; bs <<= 1)
	{
	  grub_uint32_t probed = 0;

	  if (littlefs_probe_superblock (disk, bs, &probed, &block_count,
					 &version)
	      && probed == bs)
	    {
	      block_size = bs;
	      break;
	    }
	}

      if (block_size == 0)
	{
	  grub_error (GRUB_ERR_BAD_FS, "not a littlefs filesystem");
	  goto fail;
	}
    }

  /* Only the block size is fixed at format time; lfs_fs_grow rewrites the
     block count into a later commit of the root pair, which the bootstrap
     read above cannot see.  So bound the pair pointers by the device for the
     duration of the scan and take the real count from the superblock the scan
     settles on.  An image that stops short of the block count it claims -- a
     truncated dump, or a tool that only wrote up to the last block it
     touched -- keeps its own geometry as the bound and simply fails the reads
     that fall off the end.  */
  sectors = grub_disk_native_sectors (disk);
  if (sectors == GRUB_DISK_SIZE_UNKNOWN)
    {
      data->disk_bytes = 0;
      limit = LITTLEFS_BLOCK_NULL;
    }
  else
    {
      grub_uint64_t devblocks;

      data->disk_bytes = sectors << GRUB_DISK_SECTOR_BITS;
      devblocks = data->disk_bytes / block_size;
      limit = devblocks < LITTLEFS_BLOCK_NULL
	      ? (grub_uint32_t) devblocks : LITTLEFS_BLOCK_NULL;
      if (limit < block_count)
	limit = block_count;
    }

  data->block_size = block_size;
  data->block_count = limit;
  data->version = version;

  data->cbuf = grub_malloc (block_size);
  if (!data->cbuf)
    goto fail;

  /* Walk the whole metadata-pair list: the superblock entries are chained
     from the pair {0, 1} and the last one that carries it doubles as the root
     directory, while every pair may contribute a global-state delta.  */
  grub_memset (&mdir, 0, sizeof (mdir));
  mdir.tail[0] = 0;
  mdir.tail[1] = 1;
  littlefs_tortoise_init (&tortoise);

  match.name = "littlefs";
  match.size = 8;

  while (!littlefs_pair_isnull (mdir.tail))
    {
      grub_uint32_t pair[2];
      grub_uint32_t tag;

      pair[0] = mdir.tail[0];
      pair[1] = mdir.tail[1];

      if (littlefs_tortoise_step (&tortoise, pair) != GRUB_ERR_NONE)
	goto fail;

      if (littlefs_dir_fetchmatch (data, &mdir, pair,
				   LITTLEFS_MKTAG (0x7ff, 0x3ff, 0),
				   LITTLEFS_MKTAG (LITTLEFS_TYPE_SUPERBLOCK, 0, 8),
				   littlefs_name_match, &match, &tag)
	  == LITTLEFS_ERR)
	goto fail;

      if (tag != 0 && !littlefs_tag_isdelete (tag))
	{
	  grub_uint8_t sb[24];
	  grub_uint32_t stag;

	  data->root[0] = mdir.pair[0];
	  data->root[1] = mdir.pair[1];
	  found_root = 1;

	  if (littlefs_dir_getslice (data, &mdir,
				     LITTLEFS_MKTAG (0x7ff, 0x3ff, 0),
				     LITTLEFS_MKTAG (LITTLEFS_TYPE_INLINESTRUCT,
						     0, 0),
				     0, sb, sizeof (sb), &stag) != LITTLEFS_OK)
	    {
	      if (grub_errno == GRUB_ERR_NONE)
		grub_error (GRUB_ERR_BAD_FS, "littlefs: superblock has no struct");
	      goto fail;
	    }

	  version = grub_le_to_cpu32 (grub_get_unaligned32 (sb));
	  if ((version >> 16) != 2 || (version & 0xffff) > 1)
	    {
	      grub_error (GRUB_ERR_BAD_FS, "unsupported littlefs version %u.%u",
			  version >> 16, version & 0xffff);
	      goto fail;
	    }
	  data->version = version;

	  block_count = grub_le_to_cpu32 (grub_get_unaligned32 (sb + 8));
	  if (grub_le_to_cpu32 (grub_get_unaligned32 (sb + 4)) != block_size
	      || block_count < 2 || block_count > limit)
	    {
	      grub_error (GRUB_ERR_BAD_FS, "littlefs: inconsistent geometry");
	      goto fail;
	    }
	}

      if (littlefs_dir_getgstate (data, &mdir, gstate) == LITTLEFS_ERR)
	goto fail;
    }

  if (!found_root)
    {
      grub_error (GRUB_ERR_BAD_FS, "not a littlefs filesystem");
      goto fail;
    }

  /* The scan is over, so the pointers can be held to the real geometry.  */
  data->block_count = block_count;

  /* Publish the move state only now: while the list was being summed, the
     lookups above had to see the disk as it is.  A zero tag would read as a
     valid one, so littlefs nudges it out of the way.  */
  gstate[0] += littlefs_tag_isvalid (gstate[0]) ? 0 : 1;
  data->gtag = gstate[0];
  data->gpair[0] = gstate[1];
  data->gpair[1] = gstate[2];

  return data;

fail:
  if (grub_errno == GRUB_ERR_NONE)
    grub_error (GRUB_ERR_BAD_FS, "not a littlefs filesystem");
  grub_littlefs_unmount (data);
  return 0;
}

static grub_err_t
grub_littlefs_dir (grub_device_t device, const char *path,
		   grub_fs_dir_hook_t hook, void *hook_data)
{
  struct grub_littlefs_data *data;
  struct grub_fshelp_node root;
  struct grub_fshelp_node *found = 0;
  struct littlefs_mdir mdir;
  struct littlefs_tortoise tortoise;
  grub_uint32_t pair[2];
  char *name = 0;
  grub_err_t err;

  data = grub_littlefs_mount (device->disk);
  if (!data)
    return grub_errno;

  grub_memset (&root, 0, sizeof (root));
  root.data = data;
  root.isdir = 1;
  root.pair[0] = data->root[0];
  root.pair[1] = data->root[1];

  err = grub_fshelp_find_file_lookup (path, &root, &found, littlefs_lookup_file,
				      0, GRUB_FSHELP_DIR);
  if (err != GRUB_ERR_NONE)
    goto out;

  name = grub_malloc (LITTLEFS_NAME_MAX + 1);
  if (!name)
    {
      err = grub_errno;
      goto out;
    }

  pair[0] = found->pair[0];
  pair[1] = found->pair[1];
  littlefs_tortoise_init (&tortoise);

  while (1)
    {
      grub_uint16_t id;

      err = littlefs_tortoise_step (&tortoise, pair);
      if (err != GRUB_ERR_NONE)
	goto out;

      if (littlefs_dir_fetch (data, &mdir, pair) != LITTLEFS_OK)
	{
	  err = grub_errno;
	  goto out;
	}

      for (id = 0; id < mdir.count; id++)
	{
	  struct grub_fshelp_node node;
	  struct grub_dirhook_info info;
	  enum littlefs_status status;

	  grub_memset (&node, 0, sizeof (node));
	  status = littlefs_dir_getinfo (data, &mdir, id, name, &node);
	  if (status == LITTLEFS_ERR)
	    {
	      err = grub_errno;
	      goto out;
	    }
	  /* Ids the newest commit no longer names, plus the superblock entry
	     of the root pair, simply are not entries.  */
	  if (status == LITTLEFS_NOENT)
	    continue;

	  grub_memset (&info, 0, sizeof (info));
	  info.dir = node.isdir;
	  if (node.isdir)
	    {
	      /* The first pair of a directory identifies it for as long as it
		 is not compacted, which is all a caller can ask for.  */
	      info.inodeset = 1;
	      info.inode = node.pair[0];
	    }

	  if (hook (name, &info, hook_data))
	    goto out;
	}

      if (!mdir.split)
	break;

      pair[0] = mdir.tail[0];
      pair[1] = mdir.tail[1];
    }

  err = GRUB_ERR_NONE;

out:
  grub_free (name);
  if (found != &root)
    grub_free (found);
  grub_littlefs_unmount (data);
  return err;
}

static grub_err_t
grub_littlefs_open (struct grub_file *file, const char *name)
{
  struct grub_littlefs_data *data;
  struct grub_fshelp_node *root;
  struct grub_fshelp_node *found = 0;
  grub_err_t err;

  data = grub_littlefs_mount (file->device->disk);
  if (!data)
    return grub_errno;

  /* The root has to outlive this call when the path resolves to it.  */
  root = grub_zalloc (sizeof (*root));
  if (!root)
    {
      err = grub_errno;
      goto fail;
    }
  root->data = data;
  root->isdir = 1;
  root->pair[0] = data->root[0];
  root->pair[1] = data->root[1];

  err = grub_fshelp_find_file_lookup (name, root, &found, littlefs_lookup_file,
				      0, GRUB_FSHELP_REG);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (root);
      goto fail;
    }

  if (found != root)
    grub_free (root);

  file->data = found;
  file->size = found->size;
  return GRUB_ERR_NONE;

fail:
  grub_littlefs_unmount (data);
  return err;
}

static grub_ssize_t
grub_littlefs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_fshelp_node *node = file->data;

  return littlefs_read_data (node, file->offset, buf, len);
}

static grub_err_t
grub_littlefs_close (grub_file_t file)
{
  struct grub_fshelp_node *node = file->data;

  grub_littlefs_unmount (node->data);
  grub_free (node);
  return GRUB_ERR_NONE;
}

static struct grub_fs grub_littlefs_fs = {
  .name = "littlefs",
  .fs_dir = grub_littlefs_dir,
  .fs_open = grub_littlefs_open,
  .fs_read = grub_littlefs_read,
  .fs_close = grub_littlefs_close,
  .next = 0
};

GRUB_MOD_INIT(littlefs)
{
  grub_littlefs_fs.mod = mod;
  grub_fs_register (&grub_littlefs_fs);
}

GRUB_MOD_FINI(littlefs)
{
  grub_fs_unregister (&grub_littlefs_fs);
}
