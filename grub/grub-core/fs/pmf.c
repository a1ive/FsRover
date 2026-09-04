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
 * DiskGenius partition backups (.pmf) taken file by file rather than
 * sector by sector -- what "backup all files" writes.  The two sector
 * modes of the same container are volume images and belong to
 * grub-core\io\pmf.c; this reads the third, which has no volume to
 * expose and is a filesystem in its own right.
 *
 * A .pmf opens with a "VIMG" header carrying the source filesystem's
 * name at +0x0c, the image name at +0x254 and the backup mode, 2 here,
 * as a u32 at +0x27f.  How the files are catalogued depends on the
 * volume they came from; both shapes are read here.
 *
 * A backup of a FAT or exFAT volume catalogues them by path:
 *
 *	0x10400	u32 catalog length, the same length again, u32 stored
 *		length, then the deflated catalog:
 *		  u32 count, then for each entry
 *		    u64 FILETIME, u64 size, u16 name length in characters
 *		    (big endian), the UTF-16 name -- a full path from the
 *		    volume root -- and a u16 of padding
 *	        one 9 byte record per entry: u8 spare, u64 image offset
 *	        of the entry's blob
 *	        u32 reserved sector count, then that many sectors of the
 *	        volume's reserved area, verbatim
 *	blobs	u8 (1 for a directory), u32 metadata length, u32 stored
 *		metadata length, the deflated metadata -- the short name,
 *		the long name and the rest of the directory entry -- and
 *		then, for a file, its content as a chain of
 *		  u32 plaintext length, u32 stored length, payload
 *		chunks, deflated or verbatim where the lengths match.
 *
 * The catalog spells out every directory as its own entry, so the tree
 * is just the sorted path list.  Only the blob says whether an entry is
 * a directory, so that byte is read for the entries no other path runs
 * through -- on FAT only for the empty ones, since there a directory
 * holds no bytes of its own, but on exFAT for every leaf, since there a
 * directory holds a cluster like anything else.
 *
 * A backup of an ext4 volume keeps the volume's own inodes: three u32
 * -- zero, a record count, zero -- and then one 32 byte record per
 * inode (mtime, inode, spare, blob offset, size, spare).  Each blob is
 * that inode as ext4 wrote it, followed by the file's content, and the
 * tree is whatever the directory blocks in that content say, starting
 * at inode two.
 *
 * A backup of an NTFS volume catalogues them by MFT record instead:
 *
 *	somewhere past 0x8600, after a volume record of no fixed length,
 *	come 0x44 byte entries, one per MFT record and zero where the
 *	record is not kept:
 *	  +0x08 u64 FILETIME  +0x18 u64 size  +0x20 u64 blob offset
 *	  +0x2c u64 FILETIME  +0x34 u32 MFT record number
 *	The first live entry's blob is where the catalog ends.
 *
 *	blobs	u32 record, u32 zero, u8 spare, u32 metadata length --
 *		and, when the metadata is deflated, that length again and
 *		the stored length.  The metadata holds the UTF-16 name,
 *		the parent's record reference at +0x208, the size at
 *		+0x210, the attributes at +0x230 and the volume's own
 *		FILE record from +0x240, its attributes one per 0x248
 *		byte slot.  A file's content follows: the unnamed $DATA,
 *		behind whatever other non-resident attributes come first,
 *		either verbatim or in the same chunks as above.
 *
 * The tree there is what the parent references say, the root being
 * record five.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/charset.h>
#include <grub/dgcomp.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define PMF_MAGIC		"VIMG"
#define PMF_HDR_FS		0x0c	/* the source filesystem's name */
#define PMF_HDR_NAME		0x254	/* UTF-16 image name */
#define PMF_HDR_NAME_MAX	16	/* characters */
#define PMF_HDR_MODE		0x27f	/* u32 */
#define PMF_MODE_FILE		2

/* The catalog, and the fixed part of one of its entries.  */
#define PMF_CATALOG_OFF		0x10400
#define PMF_CATALOG_HDR		12
#define PMF_ENT_FIXED		18
#define PMF_ENT_PAD		2
#define PMF_LOCATOR_SIZE	9

/* A blob's header, and the header of one of its content chunks.  */
#define PMF_BLOB_HDR		9
#define PMF_CHUNK_HDR		8

/* Sanity caps against a corrupt or hostile image.  */
#define PMF_CATALOG_MAX		(256u << 20)
#define PMF_ENTRIES_MAX		(8u << 20)
#define PMF_NAME_CHARS_MAX	4096
#define PMF_CHUNK_MAX		(16u << 20)
#define PMF_CHUNKS_MAX		(8u << 20)

/* A backup of an NTFS volume is catalogued by MFT record instead: the
   records are a fixed stride apart and each one points at its blob.  */
#define PMF_MFT_SCAN		0x8600	/* where the catalog can start */
#define PMF_MFT_WINDOW		(1u << 20)
#define PMF_MFT_ENT		0x44
#define PMF_MFT_MTIME		0x08	/* u64 FILETIME */
#define PMF_MFT_SIZE		0x18	/* u64 */
#define PMF_MFT_BLOB		0x20	/* u64 */
#define PMF_MFT_CTIME		0x2c	/* u64 FILETIME */
#define PMF_MFT_RECNO		0x34	/* u32 */
#define PMF_MFT_ROOT		5	/* the record the volume root is */
/* Its blob: u32 record, u32 zero, u8 spare, u32 length -- and, when the
   metadata is deflated, that length again and the stored length.  */
#define PMF_MFT_RAW_HDR		13
#define PMF_MFT_BLOB_HDR	21
/* The metadata: the name, then the fields the record is filed by.  */
#define PMF_MFT_NAME_CHARS	260
#define PMF_MFT_PARENT		0x208	/* u64 reference, 48 bits of record */
#define PMF_MFT_FLAGS		0x230	/* u32 FILE_ATTRIBUTE_* */
#define PMF_MFT_FLAG_DIR	0x10000000
#define PMF_MFT_RECORD		0x240	/* the NTFS FILE record itself */
#define PMF_MFT_ATTR_SLOT	0x248	/* one attribute per fixed slot */
#define PMF_MFT_ATTR_DATA	0x80
#define PMF_MFT_ATTRS_MAX	64
#define PMF_MFT_META_MIN	(PMF_MFT_RECORD + 0x30)
#define PMF_MFT_META_MAX	(1u << 20)
#define PMF_MFT_DEPTH_MAX	64

/* A backup of an ext4 volume keeps the volume's own inodes: the
   catalog is three u32 -- zero, a record count, zero -- and then one
   32 byte record per inode, and the tree is whatever the directories
   the records point at say.  */
#define PMF_E4_SCAN_LO		0x8600	/* where the catalog can start */
#define PMF_E4_SCAN_HI		0x12000
#define PMF_E4_HDR		12
#define PMF_E4_ENT		32	/* u32 mtime, u32 inode, u32, u64 blob, u64 size, u32 */
#define PMF_E4_ROOT		2	/* the inode the volume root is */
#define PMF_E4_DIRENT		8	/* u32 inode, u16 length, u8 name, u8 type */
#define PMF_E4_IBLOCK		0x28	/* a short symlink's target */
#define PMF_E4_FAST_LINK	60
#define PMF_E4_FMT		0xf000
#define PMF_E4_FMT_DIR		0x4000
#define PMF_E4_FMT_LNK		0xa000
#define PMF_E4_DIR_MAX		(64u << 20)
#define PMF_E4_DEPTH_MAX	64

/* FILETIME values a real timestamp falls between: 1970 and about 2104.
   The catalog scan tells its records from anything else by them.  */
#define PMF_FT_MIN		116444736000000000ULL
#define PMF_FT_MAX		159000000000000000ULL

/* Seconds between the FILETIME epoch and the Unix one.  */
#define PMF_FILETIME_EPOCH	11644473600LL

struct pmf_ent
{
	char *path;		/* from the volume root, no leading slash */
	grub_uint64_t size;
	grub_uint64_t mtime;	/* FILETIME */
	grub_uint64_t blob;	/* where the entry's blob sits in the image */
	/* An NTFS source states where the content is more precisely: it may
	   sit inside the metadata, or behind the other attributes' bytes.  */
	grub_uint64_t skip;
	int dir;
	int resident;
	int chunked;
};

struct pmf_data
{
	grub_disk_t disk;
	int ntfs;		/* the catalog is the MFT-shaped one */
	int ext4;		/* the catalog is the inode-shaped one */
	int exfat;		/* a directory of its own is not empty */
	grub_uint32_t e4_inode_size;
	struct pmf_ent *ents;
	grub_uint32_t *by_path;	/* entry indices, sorted by path */
	grub_uint32_t nents;
	char *label;
};

/* One chunk of a file's content, as the walk found it.  */
struct pmf_chunk
{
	grub_uint64_t off;	/* its header's place in the image */
	grub_uint64_t poff;	/* the plaintext offset it starts at */
	grub_uint32_t dlen;
	grub_uint32_t clen;
};

struct pmf_file
{
	struct pmf_data *data;
	grub_uint64_t size;
	grub_uint64_t base;	/* plaintext to drop off the front */
	grub_uint8_t *mem;	/* content the metadata kept inline */
	grub_uint64_t raw;	/* content stored as it is, at this offset */
	grub_uint64_t next;	/* where the walk will look for a chunk */
	grub_uint64_t known;	/* plaintext the walk has reached */

	struct pmf_chunk *chunk;
	grub_uint32_t nchunks;
	grub_uint32_t cap;

	grub_uint8_t *buf;	/* the chunk the previous read landed in */
	grub_uint32_t buf_len;
	grub_uint32_t buf_nr;
	int have_buf;
};

static grub_dl_t my_mod;

/* ---------------- catalog ---------------- */

static grub_err_t
pmf_read_blob (grub_disk_t disk, grub_uint64_t off, grub_uint32_t clen,
	       grub_uint32_t dlen, grub_uint8_t **out)
{
	grub_uint8_t *raw, *plain;
	grub_err_t err;

	raw = grub_malloc (clen);
	plain = grub_malloc (dlen ? dlen : 1);
	if (!raw || !plain)
	{
		grub_free (raw);
		grub_free (plain);
		return grub_errno;
	}
	if (grub_disk_read (disk, 0, off, clen, raw))
	{
		grub_free (raw);
		grub_free (plain);
		return grub_errno;
	}
	err = grub_dgcomp_block (raw, clen, plain, dlen);
	grub_free (raw);
	if (err)
	{
		grub_free (plain);
		return err;
	}
	*out = plain;
	return GRUB_ERR_NONE;
}

/* Turn one catalog name into a path with the separators grub expects.  */
static char *
pmf_utf16_path (const grub_uint8_t *src, grub_uint32_t nchars)
{
	grub_uint16_t *utf16;
	grub_uint8_t *out;
	grub_uint8_t *end;
	grub_uint32_t i, n;

	utf16 = grub_calloc (nchars ? nchars : 1, sizeof (*utf16));
	out = grub_malloc ((grub_size_t) nchars * GRUB_MAX_UTF8_PER_UTF16 + 1);
	if (!utf16 || !out)
	{
		grub_free (utf16);
		grub_free (out);
		return NULL;
	}
	for (i = 0; i < nchars; i++)
		utf16[i] = (grub_uint16_t) (src[2 * i] | (src[2 * i + 1] << 8));
	n = nchars;
	while (n && utf16[n - 1] == 0)
		n--;
	end = grub_utf16_to_utf8 (out, utf16, n);
	*end = '\0';
	for (i = 0; out[i]; i++)
		if (out[i] == '\\')
			out[i] = '/';
	/* Catalog paths lead with the volume root.  */
	if (out[0] == '/')
		grub_memmove (out, out + 1, grub_strlen ((char *) out));
	return (char *) out;
}

/* Case-insensitive first so that a lookup can be case-insensitive too,
   with an exact tie-break to keep the order total.  */
static int
pmf_pathcmp (const char *a, const char *b)
{
	int c = grub_strcasecmp (a, b);

	return c ? c : grub_strcmp (a, b);
}

/* Bottom-up merge sort, stable so equal paths keep catalog order.  */
static void
pmf_sort (grub_uint32_t *idx, grub_uint32_t *tmp, grub_uint32_t n,
	  const struct pmf_ent *ents)
{
	grub_uint32_t width;

	for (width = 1; width < n; width *= 2)
	{
		grub_uint32_t i;

		for (i = 0; i < n; i += 2 * width)
		{
			grub_uint32_t l = i, r = i + width, o = i;
			grub_uint32_t lend = r > n ? n : r;
			grub_uint32_t rend = i + 2 * width > n ? n : i + 2 * width;

			if (r > n)
				r = n;
			while (l < lend && r < rend)
			{
				if (pmf_pathcmp (ents[idx[r]].path, ents[idx[l]].path) < 0)
					tmp[o++] = idx[r++];
				else
					tmp[o++] = idx[l++];
			}
			while (l < lend)
				tmp[o++] = idx[l++];
			while (r < rend)
				tmp[o++] = idx[r++];
		}
		grub_memcpy (idx, tmp, (grub_size_t) n * sizeof (*idx));
	}
}

/* Index into by_path of the first entry that does not case-fold below
   KEY, which is where the run of entries KEY matches or prefixes
   starts.  */
static grub_uint32_t
pmf_lower_bound (const struct pmf_data *data, const char *key)
{
	grub_uint32_t lo = 0, hi = data->nents;

	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (grub_strcasecmp (data->ents[data->by_path[mid]].path, key) < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

static struct pmf_ent *
pmf_lookup (const struct pmf_data *data, const char *path)
{
	struct pmf_ent *folded = NULL;
	grub_uint32_t i;

	for (i = pmf_lower_bound (data, path); i < data->nents; i++)
	{
		struct pmf_ent *ent = &data->ents[data->by_path[i]];

		if (grub_strcasecmp (ent->path, path) != 0)
			break;
		if (grub_strcmp (ent->path, path) == 0)
			return ent;
		if (!folded)
			folded = ent;
	}
	return folded;
}

/* Does any other entry sit under ENT?  */
static int
pmf_has_children (struct pmf_data *data, const struct pmf_ent *ent)
{
	grub_size_t plen = grub_strlen (ent->path);
	char *prefix = grub_malloc (plen + 2);
	grub_uint32_t i;
	int found = 0;

	if (!prefix)
		return 0;
	grub_memcpy (prefix, ent->path, plen);
	prefix[plen] = '/';
	prefix[plen + 1] = '\0';
	i = pmf_lower_bound (data, prefix);
	if (i < data->nents
		&& grub_strncasecmp (data->ents[data->by_path[i]].path, prefix, plen + 1) == 0)
		found = 1;
	grub_free (prefix);
	return found;
}

/* Settle which entries are directories.  A directory is empty and holds
   no bytes, so anything with a size is a file and anything other paths
   run through is a directory; only what is left needs its blob read.  */
static grub_err_t
pmf_mark_dirs (struct pmf_data *data)
{
	grub_uint32_t i;

	for (i = 0; i < data->nents; i++)
	{
		struct pmf_ent *ent = &data->ents[i];
		grub_uint8_t flag;

		/* On FAT a directory holds no bytes of its own; on exFAT it
		   holds a cluster, so there the blob has to say.  */
		if (ent->size != 0 && !data->exfat)
			continue;
		if (pmf_has_children (data, ent))
		{
			ent->dir = 1;
			continue;
		}
		if (grub_disk_read (data->disk, 0, ent->blob, 1, &flag))
			return grub_errno;
		ent->dir = flag ? 1 : 0;
	}
	return GRUB_ERR_NONE;
}

static void
pmf_free (struct pmf_data *data)
{
	grub_uint32_t i;

	if (!data)
		return;
	for (i = 0; i < data->nents; i++)
		grub_free (data->ents[i].path);
	grub_free (data->ents);
	grub_free (data->by_path);
	grub_free (data->label);
	grub_free (data);
}

/* Decode the catalog and the locators that follow it.  */
static grub_err_t
pmf_read_catalog (struct pmf_data *data)
{
	grub_uint8_t hdr[PMF_CATALOG_HDR];
	grub_uint8_t *cat = NULL;
	grub_uint8_t *loc = NULL;
	grub_uint32_t *tmp = NULL;
	grub_uint32_t dlen, clen, count, i;
	grub_size_t pos;
	grub_err_t err;

	if (grub_disk_read (data->disk, 0, PMF_CATALOG_OFF, sizeof (hdr), hdr))
		return grub_errno;
	dlen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr));
	clen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 8));
	if (dlen < 4 || dlen > PMF_CATALOG_MAX || clen == 0 || clen > PMF_CATALOG_MAX)
		return grub_error (GRUB_ERR_BAD_FS, "bad pmf catalog");

	err = pmf_read_blob (data->disk, PMF_CATALOG_OFF + PMF_CATALOG_HDR, clen, dlen, &cat);
	if (err)
		return err;

	count = grub_le_to_cpu32 (grub_get_unaligned32 (cat));
	if (count == 0 || count > PMF_ENTRIES_MAX)
	{
		err = grub_error (GRUB_ERR_BAD_FS, "bad pmf catalog entry count");
		goto out;
	}

	data->ents = grub_calloc (count, sizeof (*data->ents));
	data->by_path = grub_calloc (count, sizeof (*data->by_path));
	loc = grub_malloc ((grub_size_t) count * PMF_LOCATOR_SIZE);
	tmp = grub_calloc (count, sizeof (*tmp));
	if (!data->ents || !data->by_path || !loc || !tmp)
	{
		err = grub_errno;
		goto out;
	}
	if (grub_disk_read (data->disk, 0, PMF_CATALOG_OFF + PMF_CATALOG_HDR + clen,
			    (grub_size_t) count * PMF_LOCATOR_SIZE, loc))
	{
		err = grub_errno;
		goto out;
	}

	pos = 4;
	for (i = 0; i < count; i++)
	{
		struct pmf_ent *ent = &data->ents[i];
		grub_uint32_t nchars;

		if (pos + PMF_ENT_FIXED > dlen)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "truncated pmf catalog");
			goto out;
		}
		nchars = ((grub_uint32_t) cat[pos + 16] << 8) | cat[pos + 17];
		if (nchars == 0 || nchars > PMF_NAME_CHARS_MAX
			|| pos + PMF_ENT_FIXED + 2 * (grub_size_t) nchars > dlen)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "bad pmf catalog name");
			goto out;
		}
		ent->mtime = grub_le_to_cpu64 (grub_get_unaligned64 (cat + pos));
		ent->size = grub_le_to_cpu64 (grub_get_unaligned64 (cat + pos + 8));
		ent->path = pmf_utf16_path (cat + pos + PMF_ENT_FIXED, nchars);
		if (!ent->path)
		{
			err = grub_errno;
			goto out;
		}
		ent->blob = grub_le_to_cpu64 (grub_get_unaligned64 (loc + (grub_size_t) i * PMF_LOCATOR_SIZE + 1));
		data->by_path[i] = i;
		data->nents++;
		pos += PMF_ENT_FIXED + 2 * (grub_size_t) nchars + PMF_ENT_PAD;
	}

	pmf_sort (data->by_path, tmp, data->nents, data->ents);
	err = pmf_mark_dirs (data);

out:
	grub_free (cat);
	grub_free (loc);
	grub_free (tmp);
	return err;
}

/* ---------------- an NTFS source: the MFT-shaped catalog ---------------- */

/* Where in the catalog window a plausible record could start.  */
static int
pmf_mft_entry_ok (const grub_uint8_t *w, grub_size_t len, grub_size_t i,
		  grub_uint64_t image_size)
{
	grub_uint64_t ft, crt, blob;
	grub_uint32_t rec;

	if (i + PMF_MFT_ENT > len)
		return 0;
	ft = grub_le_to_cpu64 (grub_get_unaligned64 (w + i + PMF_MFT_MTIME));
	crt = grub_le_to_cpu64 (grub_get_unaligned64 (w + i + PMF_MFT_CTIME));
	blob = grub_le_to_cpu64 (grub_get_unaligned64 (w + i + PMF_MFT_BLOB));
	rec = grub_le_to_cpu32 (grub_get_unaligned32 (w + i + PMF_MFT_RECNO));
	return (ft >= PMF_FT_MIN && ft <= PMF_FT_MAX
		&& (crt == 0 || (crt >= PMF_FT_MIN && crt <= PMF_FT_MAX))
		&& blob > PMF_MFT_SCAN && blob < image_size && rec != 0);
}

static int
pmf_mft_entry_zero (const grub_uint8_t *w, grub_size_t i)
{
	grub_size_t k;

	for (k = 0; k < PMF_MFT_ENT; k++)
		if (w[i + k])
			return 0;
	return 1;
}

/* Find where the catalog starts.  Its records are a fixed stride apart
   and their MFT numbers rise, which the compressed volume record in
   front of them does not manage for long.  */
static grub_err_t
pmf_find_mft_catalog (struct pmf_data *data, grub_uint64_t image_size,
		      grub_uint64_t *start, grub_uint64_t *end)
{
	grub_uint8_t *w;
	grub_size_t len = PMF_MFT_WINDOW;
	grub_size_t i;
	int found;

	if (image_size < PMF_MFT_SCAN + PMF_MFT_ENT)
		return grub_error (GRUB_ERR_BAD_FS, "pmf image too short for a catalog");
	if (len > image_size - PMF_MFT_SCAN)
		len = (grub_size_t) (image_size - PMF_MFT_SCAN);
	w = grub_malloc (len);
	if (!w)
		return grub_errno;
	if (grub_disk_read (data->disk, 0, PMF_MFT_SCAN, len, w))
	{
		grub_free (w);
		return grub_errno;
	}

	found = 0;
	for (i = 0; i + 8 * PMF_MFT_ENT <= len; i++)
	{
		grub_uint32_t last, good = 1;
		grub_size_t k, first = i;
		int ok = 1;

		if (!pmf_mft_entry_ok (w, len, i, image_size))
			continue;
		last = grub_le_to_cpu32 (grub_get_unaligned32 (w + i + PMF_MFT_RECNO));
		for (k = 1; k < 8; k++)
		{
			grub_size_t j = i + k * PMF_MFT_ENT;
			grub_uint32_t rec;

			if (pmf_mft_entry_zero (w, j))
				continue;
			if (!pmf_mft_entry_ok (w, len, j, image_size))
			{
				ok = 0;
				break;
			}
			rec = grub_le_to_cpu32 (grub_get_unaligned32 (w + j + PMF_MFT_RECNO));
			if (rec <= last)
			{
				ok = 0;
				break;
			}
			last = rec;
			good++;
		}
		if (!ok || good < 4)
			continue;
		/* The run may have begun before the first live record.  */
		while (first >= PMF_MFT_ENT
			&& (pmf_mft_entry_ok (w, len, first - PMF_MFT_ENT, image_size)
			    || pmf_mft_entry_zero (w, first - PMF_MFT_ENT)))
			first -= PMF_MFT_ENT;
		*start = PMF_MFT_SCAN + first;
		*end = grub_le_to_cpu64 (grub_get_unaligned64 (w + i + PMF_MFT_BLOB));
		found = 1;
		break;
	}
	grub_free (w);
	if (!found)
		return grub_error (GRUB_ERR_BAD_FS, "no pmf catalog");
	return GRUB_ERR_NONE;
}

/* Read one blob's metadata.  The stream is either deflated, with the
   plaintext length stated twice and then the stored length, or kept as
   it is with just the one length.  */
static grub_err_t
pmf_mft_metadata (grub_disk_t disk, grub_uint64_t blob, grub_uint8_t **out,
		  grub_uint32_t *outlen, grub_uint64_t *after)
{
	grub_uint8_t hdr[PMF_MFT_BLOB_HDR + 1];
	grub_uint32_t dlen, dlen2, clen;
	grub_uint8_t *plain;
	grub_err_t err;

	if (grub_disk_read (disk, 0, blob, sizeof (hdr), hdr))
		return grub_errno;
	dlen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 9));
	dlen2 = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 13));
	clen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 17));
	if (dlen < PMF_MFT_META_MIN || dlen > PMF_MFT_META_MAX)
		return grub_error (GRUB_ERR_BAD_FS, "bad pmf metadata length");

	if (dlen2 == dlen && clen != 0 && clen <= dlen && hdr[PMF_MFT_BLOB_HDR] == 0x78)
	{
		err = pmf_read_blob (disk, blob + PMF_MFT_BLOB_HDR, clen, dlen, &plain);
		if (err)
			return err;
		*after = blob + PMF_MFT_BLOB_HDR + clen;
		*out = plain;
		*outlen = dlen;
		return GRUB_ERR_NONE;
	}

	plain = grub_malloc (dlen);
	if (!plain)
		return grub_errno;
	if (grub_disk_read (disk, 0, blob + PMF_MFT_RAW_HDR, dlen, plain))
	{
		grub_free (plain);
		return grub_errno;
	}
	*after = blob + PMF_MFT_RAW_HDR + dlen;
	*out = plain;
	*outlen = dlen;
	return GRUB_ERR_NONE;
	/* Whether the content that follows is chunked is decided the same
	   way: a deflated blob chunks it, an as-is blob does not.  */
}

/* The unnamed $DATA of a record: where its bytes are and how many.
   RESIDENT points into the metadata; otherwise SKIP counts the bytes
   the non-resident attributes ahead of it take up.  */
static int
pmf_mft_data (const grub_uint8_t *m, grub_uint32_t len, grub_uint32_t *resident,
	      grub_uint64_t *skip, grub_uint64_t *size)
{
	grub_uint32_t pos, count, i;
	grub_uint16_t attrs_off;

	*resident = 0;
	*skip = 0;
	*size = 0;
	if (len < PMF_MFT_RECORD + 0x30
		|| grub_memcmp (m + PMF_MFT_RECORD, "FILE", 4) != 0)
		return 0;
	attrs_off = grub_le_to_cpu16 (grub_get_unaligned16 (m + PMF_MFT_RECORD + 0x14));
	pos = PMF_MFT_RECORD + attrs_off;
	if (pos + 4 > len)
		return 0;
	count = grub_le_to_cpu32 (grub_get_unaligned32 (m + pos));
	if (count > PMF_MFT_ATTRS_MAX)
		return 0;
	pos += 4;
	for (i = 0; i < count; i++)
	{
		grub_uint32_t type, clen;
		int nonres;

		if (pos + 0x40 > len)
			return 0;
		type = grub_le_to_cpu32 (grub_get_unaligned32 (m + pos));
		if (type == 0 || type == 0xffffffffU)
			return 0;
		nonres = m[pos + 8] != 0;
		if (nonres)
		{
			grub_uint64_t real
				= grub_le_to_cpu64 (grub_get_unaligned64 (m + pos + 0x30));

			if (type == PMF_MFT_ATTR_DATA && m[pos + 9] == 0)
			{
				*size = real;
				return 1;
			}
			*skip += real;
			pos += PMF_MFT_ATTR_SLOT + 8;
			continue;
		}
		clen = grub_le_to_cpu32 (grub_get_unaligned32 (m + pos + 0x10));
		if (clen > len || pos + PMF_MFT_ATTR_SLOT + 8 > len - clen)
			return 0;
		if (type == PMF_MFT_ATTR_DATA && m[pos + 9] == 0)
		{
			*resident = pos + PMF_MFT_ATTR_SLOT + 8;
			*size = clen;
			return 1;
		}
		pos += PMF_MFT_ATTR_SLOT + 8 + clen;
	}
	return 0;
}

/* One catalog record, before the paths are built.  */
struct pmf_mft_row
{
	grub_uint32_t recno;
	grub_uint32_t parent;
	char *name;
};

/* Order the rows by MFT record, so a parent can be found.  The catalog
   starts out in record order but does not stay in it.  */
static void
pmf_mft_sort (grub_uint32_t *idx, grub_uint32_t *tmp, grub_uint32_t n,
	      const struct pmf_mft_row *rows)
{
	grub_uint32_t width;

	for (width = 1; width < n; width *= 2)
	{
		grub_uint32_t i;

		for (i = 0; i < n; i += 2 * width)
		{
			grub_uint32_t l = i, r = i + width, o = i;
			grub_uint32_t lend = r > n ? n : r;
			grub_uint32_t rend = i + 2 * width > n ? n : i + 2 * width;

			if (r > n)
				r = n;
			while (l < lend && r < rend)
			{
				if (rows[idx[r]].recno < rows[idx[l]].recno)
					tmp[o++] = idx[r++];
				else
					tmp[o++] = idx[l++];
			}
			while (l < lend)
				tmp[o++] = idx[l++];
			while (r < rend)
				tmp[o++] = idx[r++];
		}
		grub_memcpy (idx, tmp, (grub_size_t) n * sizeof (*idx));
	}
}

/* Build every entry's path from its name and the record its parent
   holds, the root being record five.  */
static grub_err_t
pmf_mft_paths (struct pmf_data *data, struct pmf_mft_row *rows,
	       grub_uint32_t *by_rec, grub_uint32_t *tmp)
{
	grub_uint32_t i;
	grub_err_t err = GRUB_ERR_NONE;

	for (i = 0; i < data->nents; i++)
		by_rec[i] = i;
	pmf_mft_sort (by_rec, tmp, data->nents, rows);

	for (i = 0; i < data->nents; i++)
	{
		grub_uint32_t chain[PMF_MFT_DEPTH_MAX];
		grub_uint32_t depth = 0, cur = i;
		grub_size_t total = 0, at;

		for (;;)
		{
			grub_uint32_t lo = 0, hi = data->nents, want;

			chain[depth++] = cur;
			total += grub_strlen (rows[cur].name) + 1;
			want = rows[cur].parent;
			if (want == PMF_MFT_ROOT || depth == PMF_MFT_DEPTH_MAX)
				break;
			while (lo < hi)
			{
				grub_uint32_t mid = lo + (hi - lo) / 2;

				if (rows[by_rec[mid]].recno < want)
					lo = mid + 1;
				else
					hi = mid;
			}
			if (lo == data->nents || rows[by_rec[lo]].recno != want)
				break;	/* the parent is not in the catalog */
			cur = by_rec[lo];
		}

		data->ents[i].path = grub_malloc (total);
		if (!data->ents[i].path)
		{
			err = grub_errno;
			break;
		}
		at = 0;
		while (depth--)
		{
			grub_size_t n = grub_strlen (rows[chain[depth]].name);

			if (at)
				data->ents[i].path[at++] = '/';
			grub_memcpy (data->ents[i].path + at, rows[chain[depth]].name, n);
			at += n;
		}
		data->ents[i].path[at] = '\0';
	}
	return err;
}

static grub_err_t
pmf_read_mft_catalog (struct pmf_data *data)
{
	grub_uint64_t start, end, image_size;
	struct pmf_mft_row *rows = NULL;
	grub_uint32_t *tmp = NULL;
	grub_uint32_t *order = NULL;
	grub_uint32_t cap = 0;
	grub_uint64_t off;
	grub_err_t err;

	image_size = grub_disk_native_sectors (data->disk) << GRUB_DISK_SECTOR_BITS;
	err = pmf_find_mft_catalog (data, image_size, &start, &end);
	if (err)
		return err;
	if (end <= start || end - start > (grub_uint64_t) PMF_ENTRIES_MAX * PMF_MFT_ENT)
		return grub_error (GRUB_ERR_BAD_FS, "bad pmf catalog range");

	for (off = start; off + PMF_MFT_ENT <= end; off += PMF_MFT_ENT)
	{
		grub_uint8_t e[PMF_MFT_ENT];
		grub_uint8_t *meta = NULL;
		grub_uint32_t mlen, resident;
		grub_uint64_t blob, after, skip, size;
		struct pmf_ent *ent;
		struct pmf_mft_row *row;
		grub_uint32_t nchars;

		if (grub_disk_read (data->disk, 0, off, sizeof (e), e))
		{
			err = grub_errno;
			goto out;
		}
		blob = grub_le_to_cpu64 (grub_get_unaligned64 (e + PMF_MFT_BLOB));
		if (blob == 0 || blob >= image_size)
			continue;

		if (data->nents == cap)
		{
			grub_uint32_t bigger = cap ? cap * 2 : 256;
			struct pmf_ent *a;
			struct pmf_mft_row *b;
			grub_uint32_t *c;

			if (bigger > PMF_ENTRIES_MAX)
			{
				err = grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many pmf entries");
				goto out;
			}
			a = grub_realloc (data->ents, (grub_size_t) bigger * sizeof (*a));
			if (a)
				data->ents = a;
			b = a ? grub_realloc (rows, (grub_size_t) bigger * sizeof (*b)) : NULL;
			if (b)
				rows = b;
			c = b ? grub_realloc (data->by_path, (grub_size_t) bigger * sizeof (*c)) : NULL;
			if (!c)
			{
				err = grub_errno;
				goto out;
			}
			data->by_path = c;
			cap = bigger;
		}

		err = pmf_mft_metadata (data->disk, blob, &meta, &mlen, &after);
		if (err)
		{
			/* A record the writer left half done is not fatal.  */
			grub_errno = GRUB_ERR_NONE;
			err = GRUB_ERR_NONE;
			continue;
		}

		ent = &data->ents[data->nents];
		row = &rows[data->nents];
		grub_memset (ent, 0, sizeof (*ent));
		row->recno = grub_le_to_cpu32 (grub_get_unaligned32 (e + PMF_MFT_RECNO));
		row->parent = (grub_uint32_t)
			(grub_le_to_cpu64 (grub_get_unaligned64 (meta + PMF_MFT_PARENT))
			 & 0xffffffffffffULL);
		for (nchars = 0; nchars < PMF_MFT_NAME_CHARS; nchars++)
			if (grub_get_unaligned16 (meta + 2 * nchars) == 0)
				break;
		row->name = pmf_utf16_path (meta, nchars);
		if (!row->name)
		{
			err = grub_errno;
			grub_free (meta);
			goto out;
		}
		ent->mtime = grub_le_to_cpu64 (grub_get_unaligned64 (e + PMF_MFT_MTIME));
		ent->dir = (grub_le_to_cpu32 (grub_get_unaligned32 (meta + PMF_MFT_FLAGS))
			    & PMF_MFT_FLAG_DIR) != 0;
		ent->blob = after;
		ent->resident = 0;
		if (!ent->dir && pmf_mft_data (meta, mlen, &resident, &skip, &size))
		{
			ent->size = size;
			ent->skip = skip;
			if (resident)
			{
				ent->resident = 1;
				ent->blob = blob;
				ent->skip = resident;
			}
			else
				ent->chunked = after != blob + PMF_MFT_RAW_HDR + mlen;
		}
		grub_free (meta);
		data->by_path[data->nents] = data->nents;
		data->nents++;
	}

	if (data->nents == 0)
	{
		err = grub_error (GRUB_ERR_BAD_FS, "empty pmf catalog");
		goto out;
	}
	tmp = grub_calloc (data->nents, sizeof (*tmp));
	order = grub_calloc (data->nents, sizeof (*order));
	if (!tmp || !order)
	{
		err = grub_errno;
		goto out;
	}
	err = pmf_mft_paths (data, rows, order, tmp);
	if (err)
		goto out;
	pmf_sort (data->by_path, tmp, data->nents, data->ents);

out:
	if (rows)
	{
		grub_uint32_t i;

		for (i = 0; i < data->nents; i++)
			grub_free (rows[i].name);
		grub_free (rows);
	}
	grub_free (tmp);
	grub_free (order);
	return err;
}

/* ---------------- an ext4 source: the inode-shaped catalog ---------------- */

/* Where the catalog is: a header of three u32 -- zero, the number of
   records, zero -- and then the records themselves, the first of which
   is inode one.  It sits behind a preamble of no fixed length.  */
static grub_err_t
pmf_find_e4_catalog (struct pmf_data *data, grub_uint64_t image_size,
		     grub_uint64_t *at, grub_uint32_t *count)
{
	grub_uint8_t *w;
	grub_size_t len = PMF_E4_SCAN_HI - PMF_E4_SCAN_LO;
	grub_size_t i;
	int found = 0;

	if (image_size < PMF_E4_SCAN_LO + PMF_E4_HDR + PMF_E4_ENT)
		return grub_error (GRUB_ERR_BAD_FS, "pmf image too short for a catalog");
	if (len > image_size - PMF_E4_SCAN_LO)
		len = (grub_size_t) (image_size - PMF_E4_SCAN_LO);
	w = grub_malloc (len);
	if (!w)
		return grub_errno;
	if (grub_disk_read (data->disk, 0, PMF_E4_SCAN_LO, len, w))
	{
		grub_free (w);
		return grub_errno;
	}

	for (i = 0; i + PMF_E4_HDR + PMF_E4_ENT <= len; i += 4)
	{
		grub_uint32_t n = grub_le_to_cpu32 (grub_get_unaligned32 (w + i + 4));
		grub_uint64_t blob;

		if (grub_get_unaligned32 (w + i) != 0
			|| grub_get_unaligned32 (w + i + 8) != 0
			|| n == 0 || n > PMF_ENTRIES_MAX)
			continue;
		if (grub_le_to_cpu32 (grub_get_unaligned32 (w + i + PMF_E4_HDR + 4)) != 1)
			continue;	/* the first record is always inode one */
		blob = grub_le_to_cpu64 (grub_get_unaligned64 (w + i + PMF_E4_HDR + 12));
		if (blob <= PMF_E4_SCAN_LO + i || blob >= image_size)
			continue;
		*at = PMF_E4_SCAN_LO + i;
		*count = n;
		found = 1;
		break;
	}
	grub_free (w);
	if (!found)
		return grub_error (GRUB_ERR_BAD_FS, "no pmf catalog");
	return GRUB_ERR_NONE;
}

/* Read the ext4 inode a blob opens with.  A compressed backup frames it
   as [u32 plaintext][u32 stored][payload]; otherwise it lies as it is
   and its length is the gap the catalog leaves for it.  */
static grub_err_t
pmf_e4_inode (struct pmf_data *data, grub_uint64_t blob, grub_uint8_t **out,
	      grub_uint32_t *outlen, grub_uint64_t *after, int *framed)
{
	grub_uint8_t hdr[9];
	grub_uint32_t dlen, clen;
	grub_uint8_t *plain;

	if (grub_disk_read (data->disk, 0, blob, sizeof (hdr), hdr))
		return grub_errno;
	dlen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr));
	clen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 4));
	if ((dlen == 128 || dlen == 256 || dlen == 512 || dlen == 1024)
		&& clen != 0 && clen <= dlen && (clen == dlen || hdr[8] == 0x78))
	{
		grub_err_t err = pmf_read_blob (data->disk, blob + 8, clen, dlen, &plain);

		if (err)
			return err;
		*out = plain;
		*outlen = dlen;
		*after = blob + 8 + clen;
		*framed = 1;
		return GRUB_ERR_NONE;
	}

	dlen = data->e4_inode_size;
	plain = grub_malloc (dlen);
	if (!plain)
		return grub_errno;
	if (grub_disk_read (data->disk, 0, blob, dlen, plain))
	{
		grub_free (plain);
		return grub_errno;
	}
	*out = plain;
	*outlen = dlen;
	*after = blob + dlen;
	*framed = 0;
	return GRUB_ERR_NONE;
}

/* A file's content, for the directory walk.  */
static grub_err_t
pmf_e4_content (struct pmf_data *data, grub_uint64_t off, int framed,
		grub_uint64_t size, grub_uint8_t **out)
{
	grub_uint8_t *buf;
	grub_uint64_t done = 0;

	if (size > PMF_E4_DIR_MAX)
		return grub_error (GRUB_ERR_BAD_FS, "oversized pmf directory");
	buf = grub_malloc ((grub_size_t) size);
	if (!buf)
		return grub_errno;
	if (!framed)
	{
		if (grub_disk_read (data->disk, 0, off, (grub_size_t) size, buf))
		{
			grub_free (buf);
			return grub_errno;
		}
		*out = buf;
		return GRUB_ERR_NONE;
	}
	while (done < size)
	{
		grub_uint8_t hdr[8];
		grub_uint32_t dlen, clen;
		grub_uint8_t *chunk;
		grub_err_t err;

		if (grub_disk_read (data->disk, 0, off, sizeof (hdr), hdr))
		{
			grub_free (buf);
			return grub_errno;
		}
		dlen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr));
		clen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 4));
		if (dlen == 0 || clen == 0 || clen > dlen || dlen > size - done)
		{
			grub_free (buf);
			return grub_error (GRUB_ERR_BAD_FS, "bad pmf content chunk");
		}
		err = pmf_read_blob (data->disk, off + 8, clen, dlen, &chunk);
		if (err)
		{
			grub_free (buf);
			return err;
		}
		grub_memcpy (buf + done, chunk, dlen);
		grub_free (chunk);
		done += dlen;
		off += 8 + clen;
	}
	*out = buf;
	return GRUB_ERR_NONE;
}

/* One catalog record.  */
struct pmf_e4_row
{
	grub_uint32_t inode;
	grub_uint32_t mtime;
	grub_uint64_t blob;
	grub_uint64_t size;
};

/* The record for INODE, or NULL: the catalog is in inode order.  */
static struct pmf_e4_row *
pmf_e4_find (struct pmf_e4_row *rows, grub_uint32_t n, grub_uint32_t inode)
{
	grub_uint32_t lo = 0, hi = n;

	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (rows[mid].inode < inode)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < n && rows[lo].inode == inode)
		return &rows[lo];
	return NULL;
}

static grub_err_t
pmf_e4_add (struct pmf_data *data, grub_uint32_t *cap, char *path,
	    const struct pmf_e4_row *row, int dir, grub_uint64_t off,
	    int framed, grub_uint32_t resident)
{
	struct pmf_ent *ent;

	if (data->nents == *cap)
	{
		grub_uint32_t bigger = *cap ? *cap * 2 : 256;
		struct pmf_ent *a;
		grub_uint32_t *b;

		if (bigger > PMF_ENTRIES_MAX)
			return grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many pmf entries");
		a = grub_realloc (data->ents, (grub_size_t) bigger * sizeof (*a));
		if (a)
			data->ents = a;
		b = a ? grub_realloc (data->by_path, (grub_size_t) bigger * sizeof (*b)) : NULL;
		if (!b)
			return grub_errno;
		data->by_path = b;
		*cap = bigger;
	}
	ent = &data->ents[data->nents];
	grub_memset (ent, 0, sizeof (*ent));
	ent->path = path;
	ent->size = dir ? 0 : row->size;
	/* The catalog keeps Unix time; the rest of the driver keeps FILETIME.  */
	ent->mtime = ((grub_uint64_t) row->mtime + PMF_FILETIME_EPOCH) * 10000000ULL;
	ent->blob = off;
	ent->dir = dir;
	ent->chunked = framed;
	ent->resident = resident != 0;
	if (resident)
		ent->skip = resident;
	data->by_path[data->nents] = data->nents;
	data->nents++;
	return GRUB_ERR_NONE;
}

/* Walk the directory INODE holds, adding an entry for everything in it
   and recursing.  The tree is the one the directory blocks describe;
   nothing else in the backup states it.  */
static grub_err_t
pmf_e4_walk (struct pmf_data *data, struct pmf_e4_row *rows, grub_uint32_t nrows,
	     grub_uint32_t *cap, grub_uint32_t inode, const char *prefix, int depth)
{
	struct pmf_e4_row *row = pmf_e4_find (rows, nrows, inode);
	grub_uint8_t *ino = NULL;
	grub_uint8_t *dir = NULL;
	grub_uint64_t after;
	grub_uint32_t ilen, pos = 0;
	grub_size_t plen = grub_strlen (prefix);
	int framed;
	grub_err_t err;

	if (!row || depth > PMF_E4_DEPTH_MAX || row->size == 0)
		return GRUB_ERR_NONE;
	err = pmf_e4_inode (data, row->blob, &ino, &ilen, &after, &framed);
	if (err)
		return err;
	grub_free (ino);
	err = pmf_e4_content (data, after, framed, row->size, &dir);
	if (err)
		return err;

	while (pos + PMF_E4_DIRENT <= row->size)
	{
		grub_uint32_t child = grub_le_to_cpu32 (grub_get_unaligned32 (dir + pos));
		grub_uint16_t reclen = grub_le_to_cpu16 (grub_get_unaligned16 (dir + pos + 4));
		grub_uint32_t nlen = dir[pos + 6];
		struct pmf_e4_row *crow;
		grub_uint8_t *cino;
		grub_uint32_t clen;
		grub_uint64_t cafter;
		int cframed, isdir;
		char *path;

		if (reclen < PMF_E4_DIRENT || pos + reclen > row->size)
			break;
		pos += reclen;
		if (child == 0 || nlen == 0 || nlen + PMF_E4_DIRENT > reclen)
			continue;
		if (dir[pos - reclen + PMF_E4_DIRENT] == '.'
			&& (nlen == 1 || (nlen == 2 && dir[pos - reclen + PMF_E4_DIRENT + 1] == '.')))
			continue;
		crow = pmf_e4_find (rows, nrows, child);
		if (!crow)
			continue;

		path = grub_malloc (plen + 1 + nlen + 1);
		if (!path)
		{
			err = grub_errno;
			goto out;
		}
		grub_memcpy (path, prefix, plen);
		if (plen)
			path[plen] = '/';
		grub_memcpy (path + plen + (plen ? 1 : 0),
			     dir + pos - reclen + PMF_E4_DIRENT, nlen);
		path[plen + (plen ? 1 : 0) + nlen] = '\0';

		err = pmf_e4_inode (data, crow->blob, &cino, &clen, &cafter, &cframed);
		if (err)
		{
			grub_free (path);
			goto out;
		}
		isdir = (grub_le_to_cpu16 (grub_get_unaligned16 (cino)) & PMF_E4_FMT)
			== PMF_E4_FMT_DIR;
		if ((grub_le_to_cpu16 (grub_get_unaligned16 (cino)) & PMF_E4_FMT)
			== PMF_E4_FMT_LNK && crow->size <= PMF_E4_FAST_LINK)
			/* A short symlink keeps its target in the inode.  */
			err = pmf_e4_add (data, cap, path, crow, 0, crow->blob, cframed,
					  PMF_E4_IBLOCK);
		else
			err = pmf_e4_add (data, cap, path, crow, isdir, cafter, cframed, 0);
		grub_free (cino);
		if (err)
		{
			grub_free (path);
			goto out;
		}
		if (isdir)
		{
			err = pmf_e4_walk (data, rows, nrows, cap, child,
					   data->ents[data->nents - 1].path, depth + 1);
			if (err)
				goto out;
		}
	}

out:
	grub_free (dir);
	return err;
}

static grub_err_t
pmf_read_e4_catalog (struct pmf_data *data)
{
	grub_uint64_t at, image_size;
	grub_uint32_t count, i, cap = 0;
	struct pmf_e4_row *rows = NULL;
	grub_uint8_t *raw = NULL;
	grub_uint32_t *tmp = NULL;
	grub_err_t err;

	image_size = grub_disk_native_sectors (data->disk) << GRUB_DISK_SECTOR_BITS;
	err = pmf_find_e4_catalog (data, image_size, &at, &count);
	if (err)
		return err;

	rows = grub_calloc (count, sizeof (*rows));
	raw = grub_malloc ((grub_size_t) count * PMF_E4_ENT);
	if (!rows || !raw)
	{
		err = grub_errno;
		goto out;
	}
	if (grub_disk_read (data->disk, 0, at + PMF_E4_HDR,
			    (grub_size_t) count * PMF_E4_ENT, raw))
	{
		err = grub_errno;
		goto out;
	}
	for (i = 0; i < count; i++)
	{
		const grub_uint8_t *e = raw + (grub_size_t) i * PMF_E4_ENT;

		rows[i].mtime = grub_le_to_cpu32 (grub_get_unaligned32 (e));
		rows[i].inode = grub_le_to_cpu32 (grub_get_unaligned32 (e + 4));
		rows[i].blob = grub_le_to_cpu64 (grub_get_unaligned64 (e + 12));
		rows[i].size = grub_le_to_cpu64 (grub_get_unaligned64 (e + 20));
		if (rows[i].blob >= image_size)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "bad pmf catalog record");
			goto out;
		}
	}

	/* An uncompressed backup states no length for the inode it stores;
	   the gap the catalog leaves for one that has no content is it.  */
	data->e4_inode_size = 256;
	for (i = 0; i + 1 < count; i++)
		if (rows[i].size == 0 && rows[i + 1].blob > rows[i].blob)
		{
			grub_uint64_t gap = rows[i + 1].blob - rows[i].blob;

			if (gap == 128 || gap == 256 || gap == 512 || gap == 1024)
			{
				data->e4_inode_size = (grub_uint32_t) gap;
				break;
			}
		}

	err = pmf_e4_walk (data, rows, count, &cap, PMF_E4_ROOT, "", 0);
	if (err)
		goto out;
	if (data->nents == 0)
	{
		err = grub_error (GRUB_ERR_BAD_FS, "empty pmf catalog");
		goto out;
	}
	tmp = grub_calloc (data->nents, sizeof (*tmp));
	if (!tmp)
	{
		err = grub_errno;
		goto out;
	}
	pmf_sort (data->by_path, tmp, data->nents, data->ents);

out:
	grub_free (rows);
	grub_free (raw);
	grub_free (tmp);
	return err;
}

static struct pmf_data *
pmf_mount (grub_disk_t disk)
{
	struct pmf_data *data;
	grub_uint8_t hdr[PMF_HDR_MODE + 4];
	grub_uint16_t name[PMF_HDR_NAME_MAX + 1];
	grub_uint8_t *label;
	grub_uint32_t i;

	if (grub_disk_read (disk, 0, 0, sizeof (hdr), hdr))
		goto bad;
	if (grub_memcmp (hdr, PMF_MAGIC, 4) != 0
		|| grub_le_to_cpu32 (grub_get_unaligned32 (hdr + PMF_HDR_MODE)) != PMF_MODE_FILE)
		goto bad;
	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	/* FAT and exFAT are catalogued by path, NTFS by MFT record.  */
	if (grub_memcmp (hdr + PMF_HDR_FS, "NTFS", 4) == 0)
		data->ntfs = 1;
	else if (grub_memcmp (hdr + PMF_HDR_FS, "EXT", 3) == 0)
		data->ext4 = 1;
	else if (grub_memcmp (hdr + PMF_HDR_FS, "exFAT", 5) == 0)
		data->exfat = 1;
	else if (grub_memcmp (hdr + PMF_HDR_FS, "FAT", 3) != 0)
	{
		grub_free (data);
		goto bad;
	}

	if (grub_disk_read (disk, 0, PMF_HDR_NAME, 2 * PMF_HDR_NAME_MAX, name))
	{
		pmf_free (data);
		return NULL;
	}
	for (i = 0; i < PMF_HDR_NAME_MAX; i++)
		name[i] = grub_le_to_cpu16 (name[i]);
	name[PMF_HDR_NAME_MAX] = 0;
	for (i = 0; i < PMF_HDR_NAME_MAX && name[i]; i++)
		;
	label = grub_malloc ((grub_size_t) PMF_HDR_NAME_MAX * GRUB_MAX_UTF8_PER_UTF16 + 1);
	if (label)
	{
		*grub_utf16_to_utf8 (label, name, i) = '\0';
		data->label = (char *) label;
	}

	if ((data->ntfs ? pmf_read_mft_catalog (data)
	     : data->ext4 ? pmf_read_e4_catalog (data)
			  : pmf_read_catalog (data)) != GRUB_ERR_NONE)
	{
		pmf_free (data);
		return NULL;
	}
	return data;

bad:
	grub_error (GRUB_ERR_BAD_FS, "not a pmf file backup");
	return NULL;
}

/* ---------------- file content ---------------- */

static void
pmf_file_free (struct pmf_file *f)
{
	if (!f)
		return;
	pmf_free (f->data);
	grub_free (f->chunk);
	grub_free (f->buf);
	grub_free (f->mem);
	grub_free (f);
}

/* Walk the chunk chain far enough to cover plaintext offset WANT.  */
static grub_err_t
pmf_walk_chunks (struct pmf_file *f, grub_uint64_t want)
{
	grub_uint64_t end = f->base + f->size;

	while (f->known <= want && f->known < end)
	{
		grub_uint8_t hdr[PMF_CHUNK_HDR];
		grub_uint32_t dlen, clen;

		if (grub_disk_read (f->data->disk, 0, f->next, sizeof (hdr), hdr))
			return grub_errno;
		dlen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr));
		clen = grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 4));
		if (dlen == 0 || dlen > PMF_CHUNK_MAX || clen == 0 || clen > dlen)
			return grub_error (GRUB_ERR_BAD_FS, "bad pmf content chunk");
		if (dlen > end - f->known)
			dlen = (grub_uint32_t) (end - f->known);

		if (f->nchunks == f->cap)
		{
			grub_uint32_t cap = f->cap ? f->cap * 2 : 16;
			struct pmf_chunk *bigger;

			if (cap > PMF_CHUNKS_MAX)
				return grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many pmf content chunks");
			bigger = grub_realloc (f->chunk, (grub_size_t) cap * sizeof (*bigger));
			if (!bigger)
				return grub_errno;
			f->chunk = bigger;
			f->cap = cap;
		}
		f->chunk[f->nchunks].off = f->next + PMF_CHUNK_HDR;
		f->chunk[f->nchunks].poff = f->known;
		f->chunk[f->nchunks].dlen = dlen;
		f->chunk[f->nchunks].clen = clen;
		f->nchunks++;

		f->known += dlen;
		f->next += PMF_CHUNK_HDR + clen;
	}
	return GRUB_ERR_NONE;
}

/* Expand the chunk holding plaintext offset OFF.  */
static grub_err_t
pmf_load_chunk (struct pmf_file *f, grub_uint64_t off, grub_uint32_t *nr)
{
	grub_uint32_t lo = 0, hi, hit;
	struct pmf_chunk *c;
	grub_uint8_t *raw;
	grub_err_t err;

	err = pmf_walk_chunks (f, off);
	if (err)
		return err;
	hi = f->nchunks;
	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (f->chunk[mid].poff <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0)
		return grub_error (GRUB_ERR_BAD_FS, "unmapped pmf content offset");
	hit = lo - 1;
	c = &f->chunk[hit];
	*nr = hit;

	if (f->have_buf && f->buf_nr == hit)
		return GRUB_ERR_NONE;
	f->have_buf = 0;
	if (f->buf_len < c->dlen)
	{
		grub_uint8_t *bigger = grub_realloc (f->buf, c->dlen);

		if (!bigger)
			return grub_errno;
		f->buf = bigger;
		f->buf_len = c->dlen;
	}
	raw = grub_malloc (c->clen);
	if (!raw)
		return grub_errno;
	if (grub_disk_read (f->data->disk, 0, c->off, c->clen, raw))
	{
		grub_free (raw);
		return grub_errno;
	}
	err = grub_dgcomp_block (raw, c->clen, f->buf, c->dlen);
	grub_free (raw);
	if (err)
		return err;
	f->buf_nr = hit;
	f->have_buf = 1;
	return GRUB_ERR_NONE;
}

/* ---------------- filesystem hooks ---------------- */

static char *
pmf_normalize (const char *path)
{
	char *out = grub_malloc (grub_strlen (path) + 1);
	grub_size_t n = 0;

	if (!out)
		return NULL;
	while (*path)
	{
		if (*path == '/' && (n == 0 || out[n - 1] == '/'))
		{
			path++;
			continue;
		}
		out[n++] = *path++;
	}
	while (n && out[n - 1] == '/')
		n--;
	out[n] = '\0';
	return out;
}

static grub_err_t
grub_pmf_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct pmf_data *data;
	char *dir = NULL;
	char *prefix = NULL;
	grub_size_t plen;
	grub_uint32_t i;

	grub_dl_ref (my_mod);
	data = pmf_mount (device->disk);
	if (!data)
	{
		grub_dl_unref (my_mod);
		return grub_errno;
	}

	dir = pmf_normalize (path);
	if (!dir)
		goto out;
	plen = grub_strlen (dir);
	prefix = grub_malloc (plen + 2);
	if (!prefix)
		goto out;
	grub_memcpy (prefix, dir, plen);
	if (plen)
		prefix[plen++] = '/';
	prefix[plen] = '\0';

	if (*dir)
	{
		struct pmf_ent *ent = pmf_lookup (data, dir);

		if (!ent || !ent->dir)
		{
			grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);
			goto out;
		}
	}

	for (i = pmf_lower_bound (data, prefix); i < data->nents; i++)
	{
		struct pmf_ent *ent = &data->ents[data->by_path[i]];
		struct grub_dirhook_info info;

		if (grub_strncasecmp (ent->path, prefix, plen) != 0)
			break;
		if (ent->path[plen] == '\0' || grub_strchr (ent->path + plen, '/'))
			continue;
		grub_memset (&info, 0, sizeof (info));
		info.dir = ent->dir;
		info.case_insensitive = 1;
		info.inodeset = 1;
		info.inode = (grub_uint64_t) (ent - data->ents);
		if (!info.dir)
		{
			info.sizeset = 1;
			info.size = ent->size;
		}
		if (ent->mtime)
		{
			info.mtimeset = 1;
			info.mtime = (grub_int64_t) (ent->mtime / 10000000) - PMF_FILETIME_EPOCH;
		}
		if (hook (ent->path + plen, &info, hook_data))
			break;
	}
	grub_errno = GRUB_ERR_NONE;

out:
	grub_free (dir);
	grub_free (prefix);
	pmf_free (data);
	grub_dl_unref (my_mod);
	return grub_errno;
}

static grub_err_t
grub_pmf_open (struct grub_file *file, const char *name)
{
	struct pmf_data *data;
	struct pmf_file *f = NULL;
	struct pmf_ent *ent;
	char *path = NULL;
	grub_uint8_t hdr[PMF_BLOB_HDR];

	grub_dl_ref (my_mod);
	data = pmf_mount (file->device->disk);
	if (!data)
	{
		grub_dl_unref (my_mod);
		return grub_errno;
	}

	path = pmf_normalize (name);
	if (!path)
		goto fail;
	ent = pmf_lookup (data, path);
	if (!ent || ent->dir)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", name);
		goto fail;
	}

	f = grub_zalloc (sizeof (*f));
	if (!f)
		goto fail;
	f->data = data;
	f->size = ent->size;

	if (ent->resident)
	{
		/* The metadata keeps the content itself.  */
		grub_uint8_t *meta;
		grub_uint32_t mlen;
		grub_uint64_t after;
		int framed;

		if (data->ext4
		    ? pmf_e4_inode (data, ent->blob, &meta, &mlen, &after, &framed)
		    : pmf_mft_metadata (data->disk, ent->blob, &meta, &mlen, &after))
			goto fail;
		f->mem = grub_malloc (ent->size ? (grub_size_t) ent->size : 1);
		if (!f->mem || ent->skip > mlen || ent->size > mlen - ent->skip)
		{
			grub_free (meta);
			if (f->mem)
				grub_error (GRUB_ERR_BAD_FS, "bad pmf resident content");
			goto fail;
		}
		grub_memcpy (f->mem, meta + ent->skip, (grub_size_t) ent->size);
		grub_free (meta);
	}
	else if ((data->ntfs || data->ext4) && !ent->chunked)
		f->raw = ent->blob + ent->skip;
	else if (data->ntfs || data->ext4)
	{
		f->next = ent->blob;
		f->base = ent->skip;
	}
	else
	{
		if (grub_disk_read (data->disk, 0, ent->blob, sizeof (hdr), hdr))
			goto fail;
		/* The content follows the blob's metadata.  */
		f->next = ent->blob + PMF_BLOB_HDR
			+ grub_le_to_cpu32 (grub_get_unaligned32 (hdr + 5));
	}

	grub_free (path);
	file->data = f;
	file->size = ent->size;
	return GRUB_ERR_NONE;

fail:
	grub_free (path);
	if (f)
	{
		f->data = NULL;
		pmf_file_free (f);
	}
	pmf_free (data);
	grub_dl_unref (my_mod);
	return grub_errno;
}

static grub_ssize_t
grub_pmf_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct pmf_file *f = file->data;
	grub_uint64_t off = file->offset;
	grub_ssize_t done = 0;

	if (off >= f->size)
		return 0;
	if (len > f->size - off)
		len = (grub_size_t) (f->size - off);

	if (f->mem)
	{
		grub_memcpy (buf, f->mem + off, len);
		return (grub_ssize_t) len;
	}
	if (f->raw)
	{
		if (grub_disk_read (f->data->disk, 0, f->raw + off, len, buf))
			return -1;
		return (grub_ssize_t) len;
	}

	off += f->base;
	while (len)
	{
		struct pmf_chunk *c;
		grub_uint32_t nr;
		grub_size_t n;

		if (pmf_load_chunk (f, off, &nr) != GRUB_ERR_NONE)
			return -1;
		c = &f->chunk[nr];
		n = (grub_size_t) (c->poff + c->dlen - off);
		if (n > len)
			n = len;
		grub_memcpy (buf, f->buf + (off - c->poff), n);
		buf += n;
		off += n;
		done += n;
		len -= n;
	}
	return done;
}

static grub_err_t
grub_pmf_close (grub_file_t file)
{
	pmf_file_free (file->data);
	file->data = NULL;
	grub_dl_unref (my_mod);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_pmf_label (grub_device_t device, char **label)
{
	struct pmf_data *data;

	*label = NULL;
	data = pmf_mount (device->disk);
	if (!data)
		return grub_errno;
	if (data->label)
		*label = grub_strdup (data->label);
	pmf_free (data);
	return grub_errno;
}

static struct grub_fs grub_pmf_fs =
{
	.name = "pmf",
	.fs_dir = grub_pmf_dir,
	.fs_open = grub_pmf_open,
	.fs_read = grub_pmf_read,
	.fs_close = grub_pmf_close,
	.fs_label = grub_pmf_label,
	.next = 0
};

/* The module is "pmffs" so that the sector-mode io filter can keep the
   plain "pmf" name; the filesystem it registers is still "pmf".  */
GRUB_MOD_INIT (pmffs)
{
	grub_pmf_fs.mod = mod;
	grub_fs_register (&grub_pmf_fs);
	my_mod = mod;
}

GRUB_MOD_FINI (pmffs)
{
	grub_fs_unregister (&grub_pmf_fs);
}
