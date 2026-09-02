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
 * ntfsclone special image io filter
 * Implemented from ntfs-3g's ntfsprogs\ntfsclone.c.
 *
 * `ntfsclone --save-image` writes a 50 byte header followed by a command
 * stream that walks the volume cluster by cluster: CMD_GAP skips a signed
 * number of clusters that were never stored, CMD_NEXT is followed by one
 * cluster of data.  There is no index, so the extent table is built by
 * walking that stream; the walk is incremental because a full walk means
 * reading the whole image.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define NTFSCLONE_MAGIC		"\0ntfsclone-image"
#define NTFSCLONE_MAGIC_SIZE	16

/* Header size before offset_to_image_data was appended in version 10.0;
   older images end here and start the stream right after.  */
#define NTFSCLONE_HEADER_SIZE_OLD	46
#define NTFSCLONE_HEADER_SIZE		50

/* First endianness safe format version, and the newest one understood.  */
#define NTFSCLONE_VER_SAFE	10
#define NTFSCLONE_VER_MAJOR	10

#define NTFSCLONE_CMD_GAP	0
#define NTFSCLONE_CMD_NEXT	1

/* A gap record is the command byte plus a signed 64 bit cluster count.  */
#define NTFSCLONE_GAP_SIZE	9

/* Sanity caps against corrupt images.  */
#define NTFSCLONE_CLUSTER_SIZE_MAX	(64u << 20)
#define NTFSCLONE_EXTENTS_MAX		(8u << 20)

/* The scan only ever wants the command byte of a record, and the records
   of a run of stored clusters sit a cluster apart.  A window turns those
   strided probes back into sequential reads.  */
#define NTFSCLONE_WINDOW_SIZE	(64u << 10)

PRAGMA_BEGIN_PACKED
struct ntfsclone_header
{
	grub_uint8_t magic[NTFSCLONE_MAGIC_SIZE];
	grub_uint8_t major_ver;
	grub_uint8_t minor_ver;
	/* Everything below is misaligned, hence the packing.  */
	grub_uint32_t cluster_size;
	grub_uint64_t device_size;	/* size of the cloned device */
	grub_int64_t nr_clusters;	/* clusters in the NTFS volume */
	grub_uint64_t inuse;		/* clusters actually stored */
	grub_uint32_t offset_to_image_data;
} GRUB_PACKED;
PRAGMA_END_PACKED

/* Clusters LCN .. LCN + COUNT - 1 stored back to back from OFF, each one
   preceded by its own CMD_NEXT byte, so cluster LCN + I has its data at
   OFF + I * (cluster_size + 1) + 1.  */
struct ntfsclone_extent
{
	grub_uint64_t lcn;
	grub_uint64_t off;
	grub_uint64_t count;
};

struct ntfsclone_image
{
	grub_file_t file;
	grub_uint64_t total_bytes;	/* device_size, the virtual disk size */
	grub_uint32_t cluster_size;
	grub_int64_t nr_clusters;

	/* Scan state.  The walk stops as soon as the wanted cluster is known
	   and resumes from here when a later read needs more of the map.  */
	grub_uint64_t scan_off;		/* file offset of the next record */
	grub_int64_t scan_lcn;		/* cluster the next record applies to */
	int scan_done;
	int ordered;			/* the stream has only moved forward */
	int extend;			/* last record was a full cluster */

	struct ntfsclone_extent *extents;
	grub_size_t nextents;
	grub_size_t nalloc;
	grub_size_t cached_nr;		/* extent hit by the previous read */

	grub_uint8_t *window;
	grub_uint64_t window_off;
	grub_size_t window_len;
};

static grub_err_t
ntfsclone_pread (grub_file_t file, grub_uint64_t off, void *buf,
		 grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (file) || len > grub_file_size (file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone image truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone image truncated");
	return GRUB_ERR_NONE;
}

/* Return LEN bytes of the image at OFF.  NULL with grub_errno unset means
   the stream ended cleanly there; NULL with grub_errno set is a failure.  */
static const grub_uint8_t *
ntfsclone_peek (struct ntfsclone_image *image, grub_uint64_t off,
		grub_size_t len)
{
	grub_uint64_t size = grub_file_size (image->file);
	grub_size_t want;
	grub_ssize_t n;

	if (off >= size)
		return NULL;
	if (size - off < len)
	{
		grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone image truncated");
		return NULL;
	}
	if (off >= image->window_off
		&& off - image->window_off + len <= image->window_len)
		return image->window + (off - image->window_off);

	want = NTFSCLONE_WINDOW_SIZE;
	if (size - off < want)
		want = (grub_size_t) (size - off);
	image->window_len = 0;
	if (grub_file_seek (image->file, off) == (grub_off_t) -1)
		return NULL;
	n = grub_file_read (image->file, image->window, want);
	if (n < 0 || (grub_size_t) n < len)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone image truncated");
		return NULL;
	}
	image->window_off = off;
	image->window_len = (grub_size_t) n;
	return image->window;
}

static grub_err_t
ntfsclone_add_extent (struct ntfsclone_image *image, grub_uint64_t lcn, grub_uint64_t off)
{
	struct ntfsclone_extent *ext;

	if (image->nextents == image->nalloc)
	{
		grub_size_t nalloc = image->nalloc ? image->nalloc * 2 : 256;
		grub_size_t sz;

		if (nalloc > NTFSCLONE_EXTENTS_MAX || grub_mul (nalloc, sizeof (*ext), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many ntfsclone image extents");
		ext = grub_realloc (image->extents, sz);
		if (!ext)
			return grub_errno;
		image->extents = ext;
		image->nalloc = nalloc;
	}

	ext = &image->extents[image->nextents++];
	ext->lcn = lcn;
	ext->off = off;
	ext->count = 1;
	return GRUB_ERR_NONE;
}

/* Cluster ascending, and where two runs start on the same cluster the one
   written later first.  The walk appends in stream order, so a higher file
   offset is exactly "later in the stream".  */
static int
ntfsclone_before (const struct ntfsclone_extent *a, const struct ntfsclone_extent *b)
{
	if (a->lcn != b->lcn)
		return a->lcn < b->lcn;
	return a->off > b->off;
}

static void
ntfsclone_sift (struct ntfsclone_extent *ext, grub_size_t root, grub_size_t n)
{
	while (1)
	{
		struct ntfsclone_extent tmp;
		grub_size_t child = 2 * root + 1;

		if (child >= n)
			return;
		if (child + 1 < n && ntfsclone_before (&ext[child], &ext[child + 1]))
			child++;
		if (!ntfsclone_before (&ext[root], &ext[child]))
			return;
		tmp = ext[root];
		ext[root] = ext[child];
		ext[child] = tmp;
		root = child;
	}
}

/* Metadata images (ntfsclone --metadata --save-image) walk the MFT in
   record order rather than cluster order, so their gaps can be negative
   and the extents come out unsorted.  Heapsort needs no extra memory.  */
static void
ntfsclone_sort_extents (struct ntfsclone_image *image)
{
	struct ntfsclone_extent *ext = image->extents;
	grub_size_t n = image->nextents;
	grub_size_t i;

	for (i = n / 2; i > 0; i--)
		ntfsclone_sift (ext, i - 1, n);
	for (i = n; i > 1; i--)
	{
		struct ntfsclone_extent tmp = ext[0];

		ext[0] = ext[i - 1];
		ext[i - 1] = tmp;
		ntfsclone_sift (ext, 0, i - 1);
	}
}

/* Cut away what a run has already lost to the run in front of it, leaving
   the table disjoint.  Metadata images do store a few clusters twice -- the
   MFT walk revisits them -- and restore_image() simply lets the later write
   stand, which after the sort above is the run that comes first.  */
static void
ntfsclone_drop_overlaps (struct ntfsclone_image *image)
{
	struct ntfsclone_extent *ext = image->extents;
	grub_uint64_t stride = (grub_uint64_t) image->cluster_size + 1;
	grub_uint64_t covered = 0;
	grub_size_t i, out = 0;

	for (i = 0; i < image->nextents; i++)
	{
		struct ntfsclone_extent e = ext[i];

		if (e.lcn < covered)
		{
			grub_uint64_t skip = covered - e.lcn;

			if (skip >= e.count)
				continue;
			e.lcn += skip;
			e.off += skip * stride;
			e.count -= skip;
		}
		covered = e.lcn + e.count;
		ext[out++] = e;
	}
	image->nextents = out;
}

static void
ntfsclone_finish_scan (struct ntfsclone_image *image)
{
	image->scan_done = 1;
	image->cached_nr = 0;
	if (image->ordered)
		return;

	ntfsclone_sort_extents (image);
	ntfsclone_drop_overlaps (image);
}

/* Walk the command stream until cluster WANT is mapped or the stream ends.
   Stopping on a hit is what keeps browsing cheap, since a save image holds
   every cluster the filesystem uses; only a read that lands in a hole has
   to pay for the rest of the walk.  An out of order stream cannot be
   searched before it is complete, so once one is spotted the walk always
   runs to the end.  */
static grub_err_t
ntfsclone_scan (struct ntfsclone_image *image, grub_int64_t want)
{
	while (!image->scan_done)
	{
		const grub_uint8_t *rec;
		grub_uint64_t vaddr, data_len, end;
		grub_int64_t mapped;
		grub_err_t err;

		/* restore_image() stops right after the cluster holding the
		   alternate boot sector.  */
		if (image->scan_lcn > image->nr_clusters)
		{
			ntfsclone_finish_scan (image);
			return GRUB_ERR_NONE;
		}

		rec = ntfsclone_peek (image, image->scan_off, 1);
		if (!rec)
		{
			/* Images written before 10.1 stop without the
			   alternate boot sector.  */
			if (grub_errno)
				return grub_errno;
			ntfsclone_finish_scan (image);
			return GRUB_ERR_NONE;
		}

		if (rec[0] == NTFSCLONE_CMD_GAP)
		{
			grub_uint64_t raw;
			grub_int64_t count, next;

			rec = ntfsclone_peek (image, image->scan_off, NTFSCLONE_GAP_SIZE);
			if (!rec)
			{
				if (grub_errno)
					return grub_errno;
				ntfsclone_finish_scan (image);
				return GRUB_ERR_NONE;
			}
			grub_memcpy (&raw, rec + 1, sizeof (raw));
			count = (grub_int64_t) grub_le_to_cpu64 (raw);
			if (count == 0)
				return grub_error (GRUB_ERR_BAD_DEVICE, "empty ntfsclone gap");

			next = image->scan_lcn + count;
			if ((count > 0) != (next > image->scan_lcn))
				return grub_error (GRUB_ERR_BAD_DEVICE, "bad ntfsclone gap");
			/* clone_ntfs() closes the stream with a gap that runs
			   one past the last cluster.  */
			if (next < 0 || next > image->nr_clusters + 1)
				return grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone gap out of range");
			if (next < image->scan_lcn)
				image->ordered = 0;

			image->scan_lcn = next;
			image->scan_off += NTFSCLONE_GAP_SIZE;
			image->extend = 0;
			continue;
		}

		if (rec[0] != NTFSCLONE_CMD_NEXT)
			return grub_error (GRUB_ERR_BAD_DEVICE, "unknown ntfsclone command 0x%x", rec[0]);

		if (grub_mul ((grub_uint64_t) image->scan_lcn, image->cluster_size, &vaddr) || vaddr >= image->total_bytes)
			return grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone cluster past the device");
		/* copy_cluster() truncates the cluster that holds the
		   alternate boot sector to the end of the device.  */
		data_len = image->total_bytes - vaddr;
		if (data_len > image->cluster_size)
			data_len = image->cluster_size;
		if (grub_add (image->scan_off, 1 + data_len, &end) || end > grub_file_size (image->file))
			return grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone image truncated");

		if (image->extend)
			image->extents[image->nextents - 1].count++;
		else
		{
			err = ntfsclone_add_extent (image, (grub_uint64_t) image->scan_lcn, image->scan_off);
			if (err)
				return err;
		}
		/* A truncated cluster breaks the stride, so it always ends its run.  */
		image->extend = (data_len == image->cluster_size);
		mapped = image->scan_lcn;
		image->scan_off = end;
		image->scan_lcn++;
		if (image->ordered && mapped == want)
			return GRUB_ERR_NONE;
	}
	return GRUB_ERR_NONE;
}

/* Locate LCN in the extent table as it stands: *HIT gets the extent that
   holds it or NULL, *NEXT the first extent that starts after it or NULL.
   The table is only ever searched while it is sorted -- an out of order
   stream is sorted the moment its walk finishes.  */
static void
ntfsclone_find (struct ntfsclone_image *image, grub_uint64_t lcn,
	const struct ntfsclone_extent **hit, const struct ntfsclone_extent **next)
{
	grub_size_t ub = image->cached_nr;

	/* Sequential reads keep landing in the extent hit last time.  */
	if (ub < image->nextents && image->extents[ub].lcn <= lcn
		&& (ub + 1 == image->nextents || image->extents[ub + 1].lcn > lcn))
		ub++;
	else
	{
		/* Invariant: every extent below LO starts at or before LCN,
		   every extent from HI up starts after it.  */
		grub_size_t lo = 0, hi = image->nextents;

		while (lo < hi)
		{
			grub_size_t mid = lo + (hi - lo) / 2;

			if (image->extents[mid].lcn <= lcn)
				lo = mid + 1;
			else
				hi = mid;
		}
		ub = lo;
		image->cached_nr = ub ? ub - 1 : 0;
	}

	*hit = NULL;
	if (ub > 0 && lcn - image->extents[ub - 1].lcn < image->extents[ub - 1].count)
		*hit = &image->extents[ub - 1];
	*next = ub < image->nextents ? &image->extents[ub] : NULL;
}

static grub_err_t
ntfsclone_lookup (struct ntfsclone_image *image, grub_uint64_t lcn,
	const struct ntfsclone_extent **hit, const struct ntfsclone_extent **next)
{
	grub_err_t err;

	ntfsclone_find (image, lcn, hit, next);
	/* A hit off a half built map stands: where a cluster is stored twice
	   both copies carry the same bytes, since nothing writes to the
	   volume while ntfsclone walks it.  A miss does not stand -- the rest
	   of the stream may still map the cluster, backwards even -- so the
	   walk has to finish before anything is called a hole.  That in turn
	   is what leaves the map sorted whenever it is searched.  */
	if (!*hit && !image->scan_done)
	{
		err = ntfsclone_scan (image, (grub_int64_t) lcn);
		if (err)
			return err;
		ntfsclone_find (image, lcn, hit, next);
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
ntfsclone_read (struct ntfsclone_image *image, grub_uint64_t off, void *buf,
	grub_size_t len, grub_size_t *actually_read)
{
	const struct ntfsclone_extent *hit, *next;
	grub_uint64_t lcn, off_in_cluster, limit;
	grub_err_t err;

	*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of ntfsclone image");
	if (len == 0)
		return GRUB_ERR_NONE;

	lcn = off / image->cluster_size;
	off_in_cluster = off % image->cluster_size;

	err = ntfsclone_lookup (image, lcn, &hit, &next);
	if (err)
		return err;

	if (hit)
	{
		grub_uint64_t data_off;

		/* Clip to the cluster; never grow the request.  */
		if (len > image->cluster_size - off_in_cluster)
			len = (grub_size_t) (image->cluster_size - off_in_cluster);
		data_off = hit->off + (lcn - hit->lcn) * ((grub_uint64_t) image->cluster_size + 1) + 1 + off_in_cluster;
		err = ntfsclone_pread (image->file, data_off, buf, len);
		if (err)
			return err;
		*actually_read = len;
		return GRUB_ERR_NONE;
	}

	/* A hole: clusters the volume never used read back as zeros.  Holes
	   only come off a finished map, so this runs to the next extent, or
	   to the end of a device that stops short of the last cluster.  */
	limit = next ? next->lcn * image->cluster_size : image->total_bytes;
	if (limit > image->total_bytes)
		limit = image->total_bytes;
	if (len > limit - off)
		len = (grub_size_t) (limit - off);
	grub_memset (buf, 0, len);

	*actually_read = len;
	return GRUB_ERR_NONE;
}

static void
ntfsclone_free_image (struct ntfsclone_image *image)
{
	grub_free (image->extents);
	image->extents = NULL;
	grub_free (image->window);
	image->window = NULL;
}

static grub_err_t
ntfsclone_open_image (struct ntfsclone_image *image)
{
	struct ntfsclone_header hdr;
	grub_uint64_t total, end;
	grub_uint32_t csize, data_off;
	grub_int64_t nr_clusters;
	grub_err_t err;

	COMPILE_TIME_ASSERT (sizeof (struct ntfsclone_header) == NTFSCLONE_HEADER_SIZE);

	err = ntfsclone_pread (image->file, 0, &hdr, NTFSCLONE_HEADER_SIZE_OLD);
	if (err)
		return err;
	if (grub_memcmp (hdr.magic, NTFSCLONE_MAGIC, NTFSCLONE_MAGIC_SIZE) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "not an ntfsclone image");

	if (hdr.major_ver < NTFSCLONE_VER_SAFE)
		/* Pre 10.0 images have no offset_to_image_data and hold the
		   header and the gap counts in host byte order; the stream
		   starts right after the 46 byte header.  Rover only targets
		   little endian, which is what the accessors below assume. */
		data_off = NTFSCLONE_HEADER_SIZE_OLD;
	else
	{
		grub_uint32_t raw;

		if (hdr.major_ver > NTFSCLONE_VER_MAJOR)
			return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported ntfsclone v%u.%u", hdr.major_ver, hdr.minor_ver);
		err = ntfsclone_pread (image->file, NTFSCLONE_HEADER_SIZE_OLD, &raw, sizeof (raw));
		if (err)
			return err;
		/* open_image() reads the fields it knows and skips the rest,
		   so a header shorter than its own leaves the stream right
		   after it.  This keeps later minor versions readable.  */
		data_off = grub_le_to_cpu32 (raw);
		if (data_off < NTFSCLONE_HEADER_SIZE)
			data_off = NTFSCLONE_HEADER_SIZE;
	}

	csize = grub_le_to_cpu32 (hdr.cluster_size);
	total = grub_le_to_cpu64 (hdr.device_size);
	nr_clusters = (grub_int64_t) grub_le_to_cpu64 ((grub_uint64_t) hdr.nr_clusters);

	if (csize < 512 || csize > NTFSCLONE_CLUSTER_SIZE_MAX || (csize & (csize - 1)) != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ntfsclone cluster size %u", csize);
	if (nr_clusters <= 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad ntfsclone cluster count");
	/* The alternate boot sector lives one cluster past the volume.  */
	if (grub_mul ((grub_uint64_t) nr_clusters + 1, csize, &end))
		return grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone image too large");
	if (total < end - csize)
		return grub_error (GRUB_ERR_BAD_DEVICE, "ntfsclone device smaller than the volume");

	image->total_bytes = total;
	image->cluster_size = csize;
	image->nr_clusters = nr_clusters;
	image->scan_off = data_off;
	image->scan_lcn = 0;
	image->ordered = 1;

	image->window = grub_malloc (NTFSCLONE_WINDOW_SIZE);
	if (!image->window)
		return grub_errno;

	/* Map cluster 0 now: it makes sure the stream really is one, and
	   every caller starts by reading the boot sector anyway.  */
	return ntfsclone_scan (image, 0);
}

struct grub_ntfsclone
{
	grub_file_t file;
	struct ntfsclone_image *ntfsclone;
};
typedef struct grub_ntfsclone *grub_ntfsclone_t;

static struct grub_fs grub_ntfsclone_fs;

static grub_err_t
grub_ntfsclone_close (grub_file_t file)
{
	grub_ntfsclone_t ncio = file->data;

	ntfsclone_free_image (ncio->ntfsclone);
	grub_free (ncio->ntfsclone);
	grub_file_close (ncio->file);
	grub_free (ncio);
	/* The inner close released the shared device; the outer name is
	   freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_ntfsclone_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_ntfsclone_t ncio;
	struct ntfsclone_image *image;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < NTFSCLONE_HEADER_SIZE_OLD || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (ntfsclone_open_image (image) != GRUB_ERR_NONE)
	{
		ntfsclone_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	ncio = grub_zalloc (sizeof (*ncio));
	if (!file || !ncio)
	{
		ntfsclone_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (ncio);
		return 0;
	}
	ncio->file = io;
	ncio->ntfsclone = image;

	file->device = io->device;
	file->data = ncio;
	file->fs = &grub_ntfsclone_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;

	return file;
}

static grub_ssize_t
grub_ntfsclone_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_ntfsclone_t ncio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = ntfsclone_read (ncio->ntfsclone, read_offset, buf, len, &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR, "ntfsclone read made no progress");
			break;
		}
		read_offset += real_size;
		buf += real_size;
		size += real_size;
		if (real_size >= len)
			break;
		len -= real_size;
	}

	if (err != GRUB_ERR_NONE)
	{
		if (!grub_errno)
			grub_error (err, "ntfsclone image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_ntfsclone_fs =
{
	.name = "ntfsclone",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_ntfsclone_read,
	.fs_close = grub_ntfsclone_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (ntfsclone)
{
	grub_file_filter_register (GRUB_FILE_FILTER_NTFSCLONE, grub_ntfsclone_open);
}

GRUB_MOD_FINI (ntfsclone)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_NTFSCLONE);
}
