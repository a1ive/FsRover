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
 * Acronis True Image filesystem-mode .tib archives -- what the product
 * writes when it backs up files and folders (or a network share) rather
 * than a block device.  Such an archive wears the sector-mode volume
 * header (magic 0xA2B924CE) but closes with the filesystem-mode trailer
 * magic 0x94E18A2C; the sector-mode io filter leaves it alone.
 *
 * Layout:
 *
 *	+0x00		volume header		32 bytes (36 on Mac)
 *	hdr_len		block stream		[type byte][zlib stream] ...
 *			  'm'  one chunk of the file being written
 *			  'n'  end of that file (zlib stream of nothing)
 *			  'f'  out of band batch of NTFS attribute blobs
 *			'e' record		product metainfo
 *			'g' record		directory tree: paths and sizes
 *			locator			u64 count, u64 'e' record offset
 *			trailer magic		0x94E18A2C
 *	EOF-48		volume footer		byte-reversed header mirror
 *
 * A file is the run of 'm' records up to the next 'n'.  Every record
 * covers 256 KiB of the file, but the writer strips the chunk's trailing
 * zeros before deflating it, so a record inflates to at most that much
 * and the reader pads the remainder back out.  Empty files contribute no
 * record at all, and 'f' records are metadata the reader skips: they are
 * flushed between files, not at file boundaries.
 *
 * Names live only in the trailing directory tree, which carries no
 * pointer into the block stream.  The tree's ts field is the archive
 * offset of that entry's 'f' metadata, which the writer emits in the
 * same order it emits content, so sorting the non-empty content owners
 * by it recovers the block stream order.  A hard-link alias instead
 * carries the path of its content owner in the tree and contributes no
 * block-stream record of its own.  Finding where file N starts still
 * means scanning the stream for the N preceding 'n' records; that scan
 * is incremental (it only ever runs as far as the file being read) and
 * its results, along with the parsed tree, are cached across mounts so
 * that walking a whole archive costs one pass over it.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/charset.h>
#include <grub/safemath.h>

#include <miniz.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define TIB_VOLUME_MAGIC	0xa2b924ceU
#define TIB_TRAILER_FS		0x94e18a2cU

#define TIB_HDR_LEN_MIN		32
#define TIB_HDR_LEN_MAX		36
#define TIB_HDR_ARCHIVE_ID	0x08	/* u64, the backup chain this belongs to */
#define TIB_HDR_VOLUME_ID	0x10	/* u32 */
#define TIB_FOOTER_SIZE		48
/* [u64 record count][u64 body-relative offset of the tree] */
#define TIB_LOCATOR_SIZE	16

/* Body record types.  */
#define TIB_REC_CHUNK		0x6d	/* 'm' */
#define TIB_REC_END		0x6e	/* 'n' */
#define TIB_REC_META		0x66	/* 'f' */
#define TIB_REC_INFO		0x65	/* 'e' */
#define TIB_REC_TREE		0x67	/* 'g' */

/* Plaintext span of one 'm' record.  */
#define TIB_CHUNK_SIZE		(256 * 1024)

/* Fixed part of a directory-tree record, after the three name strings.  */
#define TIB_TREE_TAIL_SIZE	0x4a
#define TIB_TREE_OFF_SIZE	0x0c
#define TIB_TREE_OFF_ORDER	0x1c
#define TIB_TREE_OFF_ATTR	0x24
/* A nonzero cookie at +0x34 followed by a counted UTF-16 path is the
   content owner of a hard-link alias.  Ordinary entries keep both zero.  */
#define TIB_TREE_OFF_LINK_COOKIE	0x34
#define TIB_TREE_OFF_LINK_CHARS	0x38
#define TIB_TREE_OFF_LINK_PATH	0x3c
/* The only attribute bit the writer sets on a container.  */
#define TIB_ATTR_DIR		0x80

/* Records in the trailing region are framed as [type][raw deflate][u32
   checksum]; how far past the checksum to keep looking for the tree
   record if it does not sit where it should.  */
#define TIB_TREE_CKSUM_LEN	4
#define TIB_TREE_SEEK_MAX	16

/* Sanity caps against a corrupt or hostile archive.  */
#define TIB_MAX_ENTRIES		(8u << 20)
#define TIB_MAX_NAME_CHARS	65535
#define TIB_MAX_BLOB		(512u << 20)
/* How far past an 'f' record to look for the file that follows it.  */
#define TIB_RESYNC_MAX		(64u << 20)

#define TIB_IN_WINDOW		65536
#define TIB_SCAN_WINDOW		(256 * 1024)

/* Parsed archives kept alive past their last unmount, so that browsing
   or extracting many files does not rescan the block stream each time.
   Entries still referenced by an open file are never evicted.  */
#define TIB_CACHE_MAX		2

#define TIB_NO_FILE		0xffffffffU

struct tib_ent
{
	char *path;		/* full path, '/' separated, UTF-8 */
	char *link;		/* hard-link content owner while resolving the tree */
	grub_uint32_t base;	/* offset of the basename within path */
	grub_uint32_t source;	/* canonical entry that owns the content */
	grub_uint64_t size;
	grub_uint64_t order;	/* block stream ordering key */
	grub_uint32_t file_no;	/* position in the block stream */
	int dir;
};

struct tib_data
{
	struct tib_data *next;
	grub_uint32_t refcnt;

	/* Identity of the archive this was parsed from.  */
	grub_uint8_t hdr[TIB_HDR_LEN_MAX];
	grub_uint64_t total_sectors;

	grub_disk_t disk;	/* refreshed by every mount */

	grub_uint64_t body_start;
	grub_uint64_t body_end;	/* first byte of the directory tree region */

	struct tib_ent *ents;
	grub_uint32_t nents;
	grub_uint32_t *by_path;	/* entry indices, sorted by path */
	grub_uint32_t *by_file;	/* block stream position -> entry index */
	grub_uint32_t nfiles;

	/* Start of each file's chunk run, discovered on demand.  */
	grub_uint64_t *group;
	grub_uint32_t ngroup;
	grub_uint64_t scan_pos;
	grub_uint8_t zhdr[2];	/* zlib header the writer emits */
};

struct tib_file
{
	struct tib_data *data;
	grub_uint64_t size;
	grub_uint32_t file_no;
	grub_uint32_t nchunks;
	grub_uint64_t *chunk;	/* offset of each chunk record */
	grub_uint32_t known;	/* how many of them are filled in */
	grub_uint8_t *buf;	/* plaintext of chunk CACHED */
	grub_uint32_t cached;
};

static struct grub_fs grub_tib_fs;
static struct tib_data *tib_cache;

static struct tib_ent *tib_lookup (const struct tib_data *data, const char *path);

/* Inflate the stream at byte offset OFF, which may not run past END.
   With *BUFP NULL the output buffer is allocated and grown as needed and
   *CAP is ignored on entry; otherwise the stream must fit in *CAP bytes.
   Reports the input bytes consumed so the caller can find the record
   that follows.  */
static grub_err_t
tib_inflate (grub_disk_t disk, grub_uint64_t off, grub_uint64_t end,
	int raw, grub_uint8_t **bufp, grub_size_t *cap, grub_size_t *outlen, grub_size_t *consumed)
{
	tinfl_decompressor *dec = NULL;
	grub_uint8_t *win = NULL;
	grub_uint8_t *out = *bufp;
	grub_size_t out_cap = out ? *cap : 0;
	grub_size_t out_total = 0, in_total = 0;
	int grow = (out == NULL);
	grub_err_t err;

	dec = grub_malloc (sizeof (*dec));
	win = grub_malloc (TIB_IN_WINDOW);
	if (!dec || !win)
	{
		err = grub_errno;
		goto fail;
	}
	if (grow)
	{
		out_cap = TIB_IN_WINDOW;
		out = grub_malloc (out_cap);
		if (!out)
		{
			err = grub_errno;
			goto fail;
		}
	}

	tinfl_init (dec);
	for (;;)
	{
		mz_uint32 flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
		grub_uint64_t remain;
		grub_size_t in_size, out_size;
		tinfl_status st;

		if (out_total == out_cap)
		{
			grub_uint8_t *bigger;

			if (!grow || out_cap >= TIB_MAX_BLOB)
			{
				err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
						  "oversized tib stream");
				goto fail;
			}
			bigger = grub_realloc (out, out_cap * 2);
			if (!bigger)
			{
				err = grub_errno;
				goto fail;
			}
			out = bigger;
			out_cap *= 2;
		}

		remain = end - (off + in_total);
		in_size = remain > TIB_IN_WINDOW ? TIB_IN_WINDOW : (grub_size_t) remain;
		if (in_size == 0)
		{
			err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
					  "truncated tib stream");
			goto fail;
		}
		if (grub_disk_read (disk, 0, off + in_total, in_size, win))
		{
			err = grub_errno;
			goto fail;
		}
		if (remain > in_size)
			flags |= TINFL_FLAG_HAS_MORE_INPUT;
		if (!raw)
			flags |= TINFL_FLAG_PARSE_ZLIB_HEADER;

		out_size = out_cap - out_total;
		st = tinfl_decompress (dec, win, &in_size, out, out + out_total, &out_size, flags);
		in_total += in_size;
		out_total += out_size;
		if (st == TINFL_STATUS_DONE)
			break;
		if (st < TINFL_STATUS_DONE || (in_size == 0 && out_size == 0))
		{
			err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad tib stream at 0x%llx", (unsigned long long) off);
			goto fail;
		}
	}

	grub_free (dec);
	grub_free (win);
	*bufp = out;
	*cap = out_cap;
	*outlen = out_total;
	*consumed = in_total;
	return GRUB_ERR_NONE;

fail:
	grub_free (dec);
	grub_free (win);
	if (grow)
		grub_free (out);
	return err;
}

/* ---------------- directory tree ---------------- */

/* Turn NCHARS UTF-16LE units into a fresh UTF-8 string, dropping the
   terminating NUL the writer includes in the count and mapping the
   Windows separator onto grub's.  */
static char *
tib_utf16_path (const grub_uint8_t *src, grub_uint32_t nchars)
{
	grub_uint16_t *utf16 = NULL;
	grub_uint8_t *out = NULL;
	grub_uint8_t *end;
	grub_uint32_t i;

	utf16 = grub_calloc (nchars ? nchars : 1, sizeof (*utf16));
	out = grub_malloc ((grub_size_t) nchars * GRUB_MAX_UTF8_PER_UTF16 + 1);
	if (!utf16 || !out)
		goto fail;
	for (i = 0; i < nchars; i++)
		utf16[i] = (grub_uint16_t) (src[2 * i] | (src[2 * i + 1] << 8));
	while (nchars && utf16[nchars - 1] == 0)
		nchars--;
	end = grub_utf16_to_utf8 (out, utf16, nchars);
	*end = '\0';
	for (i = 0; out[i]; i++)
		if (out[i] == '\\')
			out[i] = '/';
	grub_free (utf16);
	return (char *) out;

fail:
	grub_free (utf16);
	grub_free (out);
	return NULL;
}

/* Case-insensitive first so that a lookup can be case-insensitive too,
   with an exact tie-break to keep the order total.  */
static int
tib_pathcmp (const char *a, const char *b)
{
	int c = grub_strcasecmp (a, b);

	return c ? c : grub_strcmp (a, b);
}

static int
tib_cmp_path (const struct tib_ent *a, const struct tib_ent *b)
{
	return tib_pathcmp (a->path, b->path);
}

static int
tib_cmp_order (const struct tib_ent *a, const struct tib_ent *b)
{
	if (a->order != b->order)
		return a->order < b->order ? -1 : 1;
	return 0;
}

typedef int (*tib_cmp_t) (const struct tib_ent *a, const struct tib_ent *b);

/* Bottom-up merge sort: stable, so entries the archive gives the same
   ordering key keep the order the tree listed them in.  */
static void
tib_sort (grub_uint32_t *idx, grub_uint32_t *tmp, grub_uint32_t n,
	  const struct tib_ent *ents, tib_cmp_t cmp)
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
				if (cmp (&ents[idx[r]], &ents[idx[l]]) < 0)
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

/* Decode one tree record at *POS of BLOB into ENT.  */
static grub_err_t
tib_parse_record (const grub_uint8_t *blob, grub_size_t len, grub_size_t *pos,
		  struct tib_ent *ent)
{
	grub_size_t p = *pos;
	grub_uint32_t nchars, tail_words;
	grub_size_t tail, sub;
	grub_uint32_t n;
	char *path;
	char *link = NULL;
	const grub_uint8_t *fixed;

	if (p + 4 > len)
		goto bad;
	nchars = grub_le_to_cpu32 (grub_get_unaligned32 (blob + p));
	p += 4;
	if (nchars > TIB_MAX_NAME_CHARS || p + 2 * (grub_size_t) nchars > len)
		goto bad;
	path = tib_utf16_path (blob + p, nchars);
	if (!path)
		return grub_errno;
	p += 2 * (grub_size_t) nchars;

	if (p + 4 > len)
	{
		grub_free (path);
		goto bad;
	}
	tail_words = grub_le_to_cpu32 (grub_get_unaligned32 (blob + p));
	p += 4;
	tail = 2 * (grub_size_t) tail_words;
	if (tail < TIB_TREE_TAIL_SIZE || p + tail > len)
	{
		grub_free (path);
		goto bad;
	}

	/* Basename and short-name strings precede the fixed fields; their
	   contents duplicate the full path, so only their length matters.  */
	sub = 0;
	for (n = 0; n < 2; n++)
	{
		grub_uint32_t cnt;

		if (sub + 4 > tail)
		{
			grub_free (path);
			goto bad;
		}
		cnt = grub_le_to_cpu32 (grub_get_unaligned32 (blob + p + sub));
		sub += 4;
		if (cnt > TIB_MAX_NAME_CHARS || sub + 2 * (grub_size_t) cnt > tail)
		{
			grub_free (path);
			goto bad;
		}
		sub += 2 * (grub_size_t) cnt;
	}
	if (tail - sub < TIB_TREE_TAIL_SIZE)
	{
		grub_free (path);
		goto bad;
	}

	fixed = blob + p + sub;
	if (tail - sub >= TIB_TREE_OFF_LINK_PATH
	    && grub_le_to_cpu32 (grub_get_unaligned32 (fixed + TIB_TREE_OFF_LINK_COOKIE)) != 0)
	{
		grub_uint32_t link_chars;

		link_chars = grub_le_to_cpu32 (grub_get_unaligned32 (fixed + TIB_TREE_OFF_LINK_CHARS));
		if (link_chars == 0 || link_chars > TIB_MAX_NAME_CHARS
		    || link_chars > (tail - sub - TIB_TREE_OFF_LINK_PATH) / 2)
		{
			grub_free (path);
			goto bad;
		}
		link = tib_utf16_path (fixed + TIB_TREE_OFF_LINK_PATH, link_chars);
		if (!link)
		{
			grub_free (path);
			return grub_errno;
		}
		if (!*link)
		{
			grub_free (path);
			grub_free (link);
			goto bad;
		}
	}
	ent->path = path;
	ent->link = link;
	ent->size = grub_le_to_cpu64 (grub_get_unaligned64 (fixed + TIB_TREE_OFF_SIZE));
	ent->order = grub_le_to_cpu64 (grub_get_unaligned64 (fixed + TIB_TREE_OFF_ORDER));
	ent->dir = (grub_le_to_cpu32 (grub_get_unaligned32 (fixed + TIB_TREE_OFF_ATTR)) & TIB_ATTR_DIR) != 0;
	ent->file_no = TIB_NO_FILE;
	ent->source = TIB_NO_FILE;
	ent->base = 0;
	for (n = 0; path[n]; n++)
		if (path[n] == '/')
			ent->base = n + 1;

	*pos = p + tail;
	return GRUB_ERR_NONE;

bad:
	return grub_error (GRUB_ERR_BAD_FS, "malformed tib directory tree");
}

static grub_err_t
tib_parse_tree (struct tib_data *data, const grub_uint8_t *blob, grub_size_t len)
{
	grub_size_t pos = 0;
	grub_uint32_t nrec, i, nfiles = 0;
	grub_uint32_t *tmp = NULL;
	grub_err_t err;

	if (len < 4)
		return grub_error (GRUB_ERR_BAD_FS, "empty tib directory tree");
	nrec = grub_le_to_cpu32 (grub_get_unaligned32 (blob));
	pos = 4;
	if (nrec == 0 || nrec > TIB_MAX_ENTRIES)
		return grub_error (GRUB_ERR_BAD_FS, "bad tib record count");

	data->ents = grub_calloc (nrec, sizeof (*data->ents));
	data->by_path = grub_calloc (nrec, sizeof (*data->by_path));
	tmp = grub_calloc (nrec, sizeof (*tmp));
	if (!data->ents || !data->by_path || !tmp)
	{
		err = grub_errno;
		goto fail;
	}

	for (i = 0; i < nrec; i++)
	{
		err = tib_parse_record (blob, len, &pos, &data->ents[i]);
		if (err)
			goto fail;
		data->nents = i + 1;
	}

	for (i = 0; i < nrec; i++)
		data->by_path[i] = i;
	tib_sort (data->by_path, tmp, nrec, data->ents, tib_cmp_path);

	/* Resolve the explicit target carried by every hard-link alias before
	   counting block-stream files.  The alias and its target must describe
	   the same logical file and therefore the same stream-order key.  */
	for (i = 0; i < nrec; i++)
		data->ents[i].source = i;
	for (i = 0; i < nrec; i++)
		if (data->ents[i].link)
		{
			struct tib_ent *ent = &data->ents[i];
			struct tib_ent *target = tib_lookup (data, ent->link);

			if (!target || target == ent || target->dir
			    || target->size != ent->size || target->order != ent->order)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "bad tib hard link `%s'", ent->path);
				goto fail;
			}
			ent->source = (grub_uint32_t) (target - data->ents);
			grub_free (ent->link);
			ent->link = NULL;
		}
	for (i = 0; i < nrec; i++)
	{
		grub_uint32_t source = i, hops;

		for (hops = 0; data->ents[source].source != source && hops < nrec; hops++)
			source = data->ents[source].source;
		if (hops == nrec)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "cyclic tib hard link");
			goto fail;
		}
		data->ents[i].source = source;
	}

	for (i = 0; i < nrec; i++)
		if (!data->ents[i].dir && data->ents[i].size
		    && data->ents[i].source == i)
			nfiles++;

	data->nfiles = nfiles;
	if (nfiles)
	{
		grub_uint32_t *order;
		grub_uint32_t n = 0;

		order = grub_calloc (nfiles, sizeof (*order));
		data->by_file = grub_calloc (nfiles, sizeof (*data->by_file));
		data->group = grub_calloc (nfiles, sizeof (*data->group));
		if (!order || !data->by_file || !data->group)
		{
			grub_free (order);
			err = grub_errno;
			goto fail;
		}
		for (i = 0; i < nrec; i++)
			if (!data->ents[i].dir && data->ents[i].size
			    && data->ents[i].source == i)
				order[n++] = i;
		tib_sort (order, tmp, nfiles, data->ents, tib_cmp_order);
		for (n = 0; n < nfiles; n++)
		{
			data->by_file[n] = order[n];
			data->ents[order[n]].file_no = n;
		}
		grub_free (order);
	}
	for (i = 0; i < nrec; i++)
		if (data->ents[i].source != i)
			data->ents[i].file_no = data->ents[data->ents[i].source].file_no;

	grub_free (tmp);
	return GRUB_ERR_NONE;

fail:
	grub_free (tmp);
	return err;
}

/* ---------------- mount ---------------- */

static void
tib_free (struct tib_data *data)
{
	grub_uint32_t i;

	for (i = 0; i < data->nents; i++)
	{
		grub_free (data->ents[i].path);
		grub_free (data->ents[i].link);
	}
	grub_free (data->ents);
	grub_free (data->by_path);
	grub_free (data->by_file);
	grub_free (data->group);
	grub_free (data);
}

/* Drop idle archives once the cache is over budget.  */
static void
tib_cache_trim (void)
{
	struct tib_data **prev = &tib_cache;
	grub_uint32_t n = 0;

	while (*prev)
	{
		struct tib_data *data = *prev;

		if (data->refcnt == 0 && n >= TIB_CACHE_MAX)
		{
			*prev = data->next;
			tib_free (data);
			continue;
		}
		n++;
		prev = &data->next;
	}
}

/* Locate the end of the archive inside the last sector: a loopback disk
   rounds the image up to a sector and zero-fills the gap, and the last
   four bytes of a .tib are the volume magic byte-reversed.  */
static grub_err_t
tib_find_end (grub_disk_t disk, grub_uint64_t *end)
{
	grub_uint8_t tail[GRUB_DISK_SECTOR_SIZE];
	grub_uint64_t total = grub_disk_native_sectors (disk);
	grub_uint64_t base;
	int i;

	if (total == GRUB_DISK_SIZE_UNKNOWN || total == 0)
		return grub_error (GRUB_ERR_BAD_FS, "unknown tib size");
	base = (total - 1) << GRUB_DISK_SECTOR_BITS;
	if (grub_disk_read (disk, 0, base, sizeof (tail), tail))
		return grub_errno;
	for (i = GRUB_DISK_SECTOR_SIZE - 4; i >= 0; i--)
		if (tail[i] == 0xa2 && tail[i + 1] == 0xb9 && tail[i + 2] == 0x24 && tail[i + 3] == 0xce)
		{
			*end = base + i + 4;
			return GRUB_ERR_NONE;
		}
	return grub_error (GRUB_ERR_BAD_FS, "no tib volume footer");
}

/* Walk the trailing region and hand back the inflated directory tree.  */
static grub_err_t
tib_read_tree (struct tib_data *data, grub_uint64_t end, grub_uint64_t hdr_len, grub_uint8_t **blob, grub_size_t *blob_len)
{
	grub_uint8_t footer[TIB_FOOTER_SIZE];
	grub_uint8_t locator[TIB_LOCATOR_SIZE + 4];
	grub_uint8_t frame[TIB_TREE_SEEK_MAX];
	grub_uint64_t concat_end, info_off;
	grub_uint8_t *meta = NULL;
	grub_size_t cap = 0, len = 0, used = 0;
	grub_size_t skip;
	grub_err_t err;

	if (end < hdr_len + TIB_FOOTER_SIZE)
		return grub_error (GRUB_ERR_BAD_FS, "tib too small");
	if (grub_disk_read (data->disk, 0, end - TIB_FOOTER_SIZE, sizeof (footer), footer))
		return grub_errno;

	concat_end = hdr_len + grub_le_to_cpu64 (grub_get_unaligned64 (footer + 8));
	if (concat_end < hdr_len + TIB_LOCATOR_SIZE + 4 || concat_end > end)
		return grub_error (GRUB_ERR_BAD_FS, "bad tib slice size");
	if (grub_disk_read (data->disk, 0, concat_end - sizeof (locator), sizeof (locator), locator))
		return grub_errno;
	if (grub_le_to_cpu32 (grub_get_unaligned32 (locator + TIB_LOCATOR_SIZE))
	    != TIB_TRAILER_FS)
		return grub_error (GRUB_ERR_BAD_FS, "not a filesystem-mode tib");

	info_off = hdr_len + grub_le_to_cpu64 (grub_get_unaligned64 (locator + 8));
	if (info_off <= hdr_len || info_off >= concat_end - TIB_LOCATOR_SIZE)
		return grub_error (GRUB_ERR_BAD_FS, "bad tib tree offset");

	if (grub_disk_read (data->disk, 0, info_off, 1, frame))
		return grub_errno;
	if (frame[0] != TIB_REC_INFO)
		return grub_error (GRUB_ERR_BAD_FS, "bad tib tree record");

	/* Product metainfo comes first; only its length matters here.  */
	err = tib_inflate (data->disk, info_off + 1, concat_end, 1, &meta, &cap, &len, &used);
	if (err)
		return err;
	grub_free (meta);

	/* The tree record follows the metainfo checksum.  */
	if (grub_disk_read (data->disk, 0, info_off + 1 + used, sizeof (frame), frame))
		return grub_errno;
	skip = TIB_TREE_CKSUM_LEN;
	if (frame[skip] != TIB_REC_TREE)
		for (skip = 0; skip < sizeof (frame); skip++)
			if (frame[skip] == TIB_REC_TREE)
				break;
	if (skip >= sizeof (frame))
		return grub_error (GRUB_ERR_BAD_FS, "bad tib tree framing");

	*blob = NULL;
	cap = 0;
	err = tib_inflate (data->disk, info_off + 1 + used + skip + 1, concat_end, 1, blob, &cap, blob_len, &used);
	if (err)
		return err;

	data->body_start = hdr_len;
	data->body_end = info_off;
	return GRUB_ERR_NONE;
}

static struct tib_data *
tib_mount (grub_disk_t disk)
{
	struct tib_data *data;
	grub_uint8_t hdr[TIB_HDR_LEN_MAX];
	grub_uint8_t first[3];
	grub_uint8_t *blob = NULL;
	grub_size_t blob_len = 0;
	grub_uint64_t total, end, hdr_len;
	grub_err_t err;

	if (grub_disk_read (disk, 0, 0, sizeof (hdr), hdr))
		return NULL;
	if (grub_le_to_cpu32 (grub_get_unaligned32 (hdr)) != TIB_VOLUME_MAGIC)
	{
		grub_error (GRUB_ERR_BAD_FS, "not a tib archive");
		return NULL;
	}
	hdr_len = (grub_uint64_t) (hdr[4] | (hdr[5] << 8));
	if (hdr_len < TIB_HDR_LEN_MIN || hdr_len > TIB_HDR_LEN_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "bad tib header length");
		return NULL;
	}
	total = grub_disk_native_sectors (disk);

	for (data = tib_cache; data; data = data->next)
		if (data->total_sectors == total && grub_memcmp (data->hdr, hdr, sizeof (hdr)) == 0)
		{
			data->refcnt++;
			data->disk = disk;
			grub_errno = GRUB_ERR_NONE;
			return data;
		}

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	grub_memcpy (data->hdr, hdr, sizeof (hdr));
	data->total_sectors = total;
	data->disk = disk;

	err = tib_find_end (disk, &end);
	if (err)
		goto fail;
	err = tib_read_tree (data, end, hdr_len, &blob, &blob_len);
	if (err)
		goto fail;
	err = tib_parse_tree (data, blob, blob_len);
	grub_free (blob);
	blob = NULL;
	if (err)
		goto fail;

	/* The first record of the block stream fixes the zlib header the
	   writer uses, which the 'n' record scanner matches against.  */
	if (data->nfiles)
	{
		if (grub_disk_read (disk, 0, data->body_start, sizeof (first), first))
		{
			err = grub_errno;
			goto fail;
		}
		if (first[0] != TIB_REC_CHUNK)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "bad tib block stream");
			goto fail;
		}
		data->zhdr[0] = first[1];
		data->zhdr[1] = first[2];
		data->group[0] = data->body_start;
		data->ngroup = 1;
	}
	data->scan_pos = data->body_start;

	data->refcnt = 1;
	data->next = tib_cache;
	tib_cache = data;
	tib_cache_trim ();
	grub_errno = GRUB_ERR_NONE;
	return data;

fail:
	grub_free (blob);
	tib_free (data);
	grub_errno = err;
	return NULL;
}

static void
tib_umount (struct tib_data *data)
{
	if (data->refcnt)
		data->refcnt--;
	data->disk = NULL;
	tib_cache_trim ();
}

/* ---------------- block stream ---------------- */

/* True if a record header sits at BUF and starts a file chunk.  */
static int
tib_is_chunk (const struct tib_data *data, const grub_uint8_t *buf)
{
	return buf[0] == TIB_REC_CHUNK && buf[1] == data->zhdr[0] && buf[2] == data->zhdr[1];
}

/* An 'n' record is a zlib stream of nothing: a single fixed-Huffman
   end-of-block followed by the Adler-32 of the empty string.  The
   compression level byte is left free so that the match does not depend
   on the writer's zlib settings.  */
static int
tib_is_end (const grub_uint8_t *buf)
{
	return buf[0] == TIB_REC_END && buf[1] == 0x78 && buf[3] == 0x03
		&& buf[4] == 0x00 && buf[5] == 0x00 && buf[6] == 0x00
		&& buf[7] == 0x00 && buf[8] == 0x01;
}

/* Byte offset of the first chunk record of file FILE_NO, scanning the
   block stream for the end markers of the files before it as needed.  */
static grub_err_t
tib_group_start (struct tib_data *data, grub_uint32_t file_no,
		 grub_uint64_t *start)
{
	/* The last file's end marker is followed by the 'e' record, so the
	   scan is allowed to look at that one byte past the block stream.  */
	grub_uint64_t scan_end = data->body_end + 1;
	grub_uint8_t *buf = NULL;
	grub_err_t err = GRUB_ERR_NONE;

	if (file_no >= data->nfiles)
		return grub_error (GRUB_ERR_FILE_NOT_FOUND, "no such tib file");
	if (file_no < data->ngroup)
	{
		*start = data->group[file_no];
		return GRUB_ERR_NONE;
	}

	buf = grub_malloc (TIB_SCAN_WINDOW);
	if (!buf)
		return grub_errno;

	while (data->ngroup <= file_no)
	{
		grub_uint64_t pos = data->scan_pos;
		grub_uint64_t found = 0;

		/* Locate the end marker of the file the scanner is on.  */
		while (!found)
		{
			grub_size_t n, i;

			if (pos + 10 > scan_end)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "truncated tib block stream");
				goto out;
			}
			n = scan_end - pos > TIB_SCAN_WINDOW ? TIB_SCAN_WINDOW : (grub_size_t) (scan_end - pos);
			if (grub_disk_read (data->disk, 0, pos, n, buf))
			{
				err = grub_errno;
				goto out;
			}
			for (i = 0; i + 10 <= n; i++)
				if (tib_is_end (buf + i)
					&& (buf[i + 9] == TIB_REC_CHUNK || buf[i + 9] == TIB_REC_META || buf[i + 9] == TIB_REC_INFO))
				{
					found = pos + i + 9;
					break;
				}
			if (found)
				break;
			/* Keep the bytes a marker could straddle.  */
			pos += n - 9;
		}

		data->scan_pos = found;

		/* Metadata batches are flushed between files; step over them
		   to the record that actually starts the next file.  */
		pos = found;
		while (pos + 3 <= data->body_end)
		{
			grub_size_t n, i;
			int hit = 0;

			n = data->body_end - pos > TIB_SCAN_WINDOW ? TIB_SCAN_WINDOW : (grub_size_t) (data->body_end - pos);
			if (grub_disk_read (data->disk, 0, pos, n, buf))
			{
				err = grub_errno;
				goto out;
			}
			for (i = 0; i + 3 <= n; i++)
				if (tib_is_chunk (data, buf + i))
				{
					pos += i;
					hit = 1;
					break;
				}
			if (hit)
				break;
			pos += n - 2;
			if (pos - found > TIB_RESYNC_MAX)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "lost the tib block stream");
				goto out;
			}
		}
		if (pos + 3 > data->body_end)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "truncated tib block stream");
			goto out;
		}
		data->group[data->ngroup++] = pos;
		data->scan_pos = pos;
	}

	*start = data->group[file_no];

out:
	grub_free (buf);
	return err;
}

/* Make chunk NR of F the one held in F->buf.  */
static grub_err_t
tib_load_chunk (struct tib_file *f, grub_uint32_t nr)
{
	struct tib_data *data = f->data;
	grub_uint8_t type;
	grub_err_t err;

	/* A chunk record can only be located by decoding the ones ahead of
	   it, so walk forward from the furthest record already seen.  */
	while (f->cached != nr)
	{
		grub_uint32_t want = nr < f->known ? nr : f->known - 1;
		grub_uint64_t off = f->chunk[want];
		grub_uint64_t nominal;
		grub_size_t cap = TIB_CHUNK_SIZE;
		grub_size_t len, used;
		grub_uint8_t *buf = f->buf;

		if (grub_disk_read (data->disk, 0, off, 1, &type))
			return grub_errno;
		if (type != TIB_REC_CHUNK)
			return grub_error (GRUB_ERR_BAD_FS, "tib chunk %u is missing", want);
		err = tib_inflate (data->disk, off + 1, data->body_end, 0, &buf, &cap, &len, &used);
		if (err)
			return err;

		/* The writer strips the chunk's trailing zeros; put them back.  */
		nominal = f->size - (grub_uint64_t) want * TIB_CHUNK_SIZE;
		if (nominal > TIB_CHUNK_SIZE)
			nominal = TIB_CHUNK_SIZE;
		if (len > nominal)
			return grub_error (GRUB_ERR_BAD_FS, "oversized tib chunk %u", want);
		grub_memset (f->buf + len, 0, (grub_size_t) nominal - len);

		f->cached = want;
		if (want + 1 >= f->known)
		{
			f->chunk[want + 1] = off + 1 + used;
			f->known = want + 2;
		}
	}
	return GRUB_ERR_NONE;
}

/* ---------------- path lookup ---------------- */

/* Strip the leading slash and any trailing one, and fold repeated
   separators, so that the result compares against a stored path.  */
static char *
tib_normalize (const char *path)
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

/* Index into by_path of the first entry that does not case-fold below
   KEY.  by_path is ordered case insensitively first, so this lands on
   the start of the run of entries KEY matches or prefixes.  */
static grub_uint32_t
tib_lower_bound (const struct tib_data *data, const char *key)
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

/* Windows names are case insensitive, so an exact hit wins but any
   case-folded match will do.  */
static struct tib_ent *
tib_lookup (const struct tib_data *data, const char *path)
{
	struct tib_ent *folded = NULL;
	grub_uint32_t i;

	for (i = tib_lower_bound (data, path); i < data->nents; i++)
	{
		struct tib_ent *ent = &data->ents[data->by_path[i]];

		if (grub_strcasecmp (ent->path, path) != 0)
			break;
		if (grub_strcmp (ent->path, path) == 0)
			return ent;
		if (!folded)
			folded = ent;
	}
	return folded;
}

/* ---------------- filesystem hooks ---------------- */

static grub_err_t
grub_tib_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct tib_data *data;
	char *dir = NULL;
	char *prefix = NULL;
	grub_size_t plen;
	grub_uint32_t i;

	data = tib_mount (device->disk);
	if (!data)
		return grub_errno;

	dir = tib_normalize (path);
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
		struct tib_ent *ent = tib_lookup (data, dir);

		if (!ent || !ent->dir)
		{
			grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);
			goto out;
		}
	}

	for (i = tib_lower_bound (data, prefix); i < data->nents; i++)
	{
		struct tib_ent *ent = &data->ents[data->by_path[i]];
		struct grub_dirhook_info info;

		if (grub_strncasecmp (ent->path, prefix, plen) != 0)
			break;
		if (ent->path[plen] == '\0' || grub_strchr (ent->path + plen, '/'))
			continue;
		grub_memset (&info, 0, sizeof (info));
		info.dir = ent->dir;
		info.inodeset = 1;
		info.inode = ent->source;
		if (!info.dir)
		{
			info.sizeset = 1;
			info.size = ent->size;
		}
		if (hook (ent->path + plen, &info, hook_data))
			break;
	}
	grub_errno = GRUB_ERR_NONE;

out:
	grub_free (dir);
	grub_free (prefix);
	tib_umount (data);
	return grub_errno;
}

static grub_err_t
grub_tib_open (struct grub_file *file, const char *name)
{
	struct tib_data *data;
	struct tib_file *f = NULL;
	struct tib_ent *ent;
	char *path = NULL;
	grub_uint64_t start;
	grub_uint32_t nchunks;

	data = tib_mount (file->device->disk);
	if (!data)
		return grub_errno;

	path = tib_normalize (name);
	if (!path)
		goto fail;
	ent = tib_lookup (data, path);
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
	f->file_no = ent->file_no;
	f->cached = TIB_NO_FILE;

	if (f->file_no != TIB_NO_FILE)
	{
		if (tib_group_start (data, f->file_no, &start))
			goto fail;
		nchunks = (grub_uint32_t) ((ent->size + TIB_CHUNK_SIZE - 1) / TIB_CHUNK_SIZE);
		f->nchunks = nchunks;
		f->chunk = grub_calloc ((grub_size_t) nchunks + 1, sizeof (*f->chunk));
		f->buf = grub_malloc (TIB_CHUNK_SIZE);
		if (!f->chunk || !f->buf)
			goto fail;
		f->chunk[0] = start;
		f->known = 1;
	}

	grub_free (path);
	file->data = f;
	file->size = ent->size;
	grub_errno = GRUB_ERR_NONE;
	return GRUB_ERR_NONE;

fail:
	grub_free (path);
	if (f)
	{
		grub_free (f->chunk);
		grub_free (f->buf);
		grub_free (f);
	}
	tib_umount (data);
	return grub_errno;
}

static grub_ssize_t
grub_tib_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct tib_file *f = file->data;
	grub_uint64_t off = file->offset;
	grub_size_t done = 0;

	f->data->disk = file->device->disk;
	if (off >= f->size)
		return 0;
	if (len > f->size - off)
		len = (grub_size_t) (f->size - off);

	while (done < len)
	{
		grub_uint32_t nr = (grub_uint32_t) (off / TIB_CHUNK_SIZE);
		grub_size_t in = (grub_size_t) (off % TIB_CHUNK_SIZE);
		grub_size_t n = TIB_CHUNK_SIZE - in;

		if (nr >= f->nchunks)
			break;
		if (n > len - done)
			n = len - done;
		if (tib_load_chunk (f, nr))
			return -1;
		grub_memcpy (buf + done, f->buf + in, n);
		done += n;
		off += n;
	}
	/* A short block stream still yields the file's declared length.  */
	if (done < len)
		grub_memset (buf + done, 0, len - done);
	return (grub_ssize_t) len;
}

static grub_err_t
grub_tib_close (grub_file_t file)
{
	struct tib_file *f = file->data;

	tib_umount (f->data);
	grub_free (f->chunk);
	grub_free (f->buf);
	grub_free (f);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_tib_label (grub_device_t device, char **label)
{
	struct tib_data *data;

	*label = NULL;
	data = tib_mount (device->disk);
	if (!data)
		return grub_errno;
	/* The tree lists its root first: the drive or share it came from.  */
	if (data->nents)
		*label = grub_strdup (data->ents[0].path);
	tib_umount (data);
	return grub_errno;
}

static grub_err_t
grub_tib_uuid (grub_device_t device, char **uuid)
{
	struct tib_data *data;

	*uuid = NULL;
	data = tib_mount (device->disk);
	if (!data)
		return grub_errno;
	/* The archive and volume ids the catalog knows this backup by.  */
	*uuid = grub_xasprintf ("%016llx-%08x",
				(unsigned long long)
				grub_le_to_cpu64 (grub_get_unaligned64 (data->hdr + TIB_HDR_ARCHIVE_ID)),
				grub_le_to_cpu32 (grub_get_unaligned32 (data->hdr + TIB_HDR_VOLUME_ID)));
	tib_umount (data);
	return grub_errno;
}

static struct grub_fs grub_tib_fs =
{
	.name = "tib",
	.fs_dir = grub_tib_dir,
	.fs_open = grub_tib_open,
	.fs_read = grub_tib_read,
	.fs_close = grub_tib_close,
	.fs_label = grub_tib_label,
	.fs_uuid = grub_tib_uuid,
	.next = 0
};

/* The module is "tibfs" so that the sector-mode io filter can keep the
   plain "tib" name; the filesystem it registers is still "tib".  */
GRUB_MOD_INIT (tibfs)
{
	grub_tib_fs.mod = mod;
	grub_fs_register (&grub_tib_fs);
}

GRUB_MOD_FINI (tibfs)
{
	struct tib_data *data;

	grub_fs_unregister (&grub_tib_fs);
	while ((data = tib_cache))
	{
		tib_cache = data->next;
		tib_free (data);
	}
}
