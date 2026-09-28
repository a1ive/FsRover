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
 * Lost partition search: the scan engine and its rover.h interface.
 *
 * Deviations from TestDisk: partitions of the scanned device whose
 * filesystem GRUB reads are skipped; results are checked by mounting
 * them read-only through lostdisk.  Stepping over a found filesystem is
 * taken back when something points inside it -- a table entry or
 * unreadable partition before the step, or a later result starting
 * there, which queues the stepped-over range for a second pass: a stale
 * boot sector left by an earlier format no longer hides the partitions
 * made after it.
 *
 * ROVER_LOST_SCAN_DEEP looks for primaries -- and for copies that carry
 * their own position (ext group, XFS allocation group, Btrfs mirror) and
 * extended boot records -- at every sector, never stepping over a
 * filesystem, and reads the device in large chunks.  As in TestDisk's
 * deeper search, backups found by their distance from the start (FAT32,
 * exFAT, F2FS, JFS, the NTFS and HFS copies at the end) are only looked
 * for at the quick search's candidate offsets, where they cannot be a
 * primary misread.  The hits are kept until the end, where one of the
 * same type and size that starts inside another -- a backup read as a
 * primary -- is dropped.
 */

#include <grub/device.h>
#include <grub/disk.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/partition.h>
#include <grub/types.h>

#include "rover.h"
#include "lost.h"
#include "lostint.h"

int
lost_read (struct rover_lost_scan *scan, grub_uint64_t offset, grub_size_t len, void *buf)
{
	if (grub_disk_read (scan->disk, offset >> GRUB_DISK_SECTOR_BITS,
		offset & (GRUB_DISK_SECTOR_SIZE - 1), len, buf) != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		return -1;
	}
	return 0;
}

/* Read LEN bytes at OFFSET; what cannot be read (bad sectors) reads
   as zeros.  */
static void
lost_read_fill (struct rover_lost_scan *scan, grub_uint64_t offset, grub_size_t len,
	grub_uint8_t *buf)
{
	grub_size_t done, piece;

	if (lost_read (scan, offset, len, buf) == 0)
		return;
	for (done = 0; done < len; done += piece)
	{
		piece = len - done < LOST_AUX ? len - done : LOST_AUX;
		if (lost_read (scan, offset + done, piece, buf + done))
			grub_memset (buf + done, 0, piece);
	}
}

int
lost_add_hint (struct rover_lost_scan *scan, grub_uint64_t offset)
{
	grub_size_t lo = 0, hi = scan->nhints;

	if (offset > scan->size || offset % scan->sector_size)
		return 0;
	while (lo < hi)
	{
		grub_size_t mid = lo + (hi - lo) / 2;

		if (scan->hints[mid] < offset)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < scan->nhints && scan->hints[lo] == offset)
		return 0;
	if (scan->nhints == scan->hints_alloc)
	{
		grub_size_t alloc = scan->hints_alloc ? scan->hints_alloc * 2 : 64;
		grub_uint64_t *hints = grub_realloc (scan->hints, alloc * sizeof (*hints));

		if (!hints)
			return -1;
		scan->hints = hints;
		scan->hints_alloc = alloc;
	}
	grub_memmove (scan->hints + lo + 1, scan->hints + lo, (scan->nhints - lo) * sizeof (*scan->hints));
	scan->hints[lo] = offset;
	scan->nhints++;
	return 0;
}

/* godmode.c: after a partition, try where the next one would start.  */
int
lost_add_end_hints (struct rover_lost_scan *scan, grub_uint64_t end)
{
	grub_uint64_t track = lost_round_up (end, LOST_TRACK);

	if (lost_add_hint (scan, end))
		return -1;
	if (scan->sector_size != 512)
		return 0;
	if (lost_add_hint (scan, end + LOST_TRACK) || lost_add_hint (scan, track)
		|| lost_add_hint (scan, track + LOST_TRACK))
		return -1;
	return 0;
}

/* A result or table entry starts at START: search again any range the
   quick search stepped over it with.  */
void
lost_conflict (struct rover_lost_scan *scan, grub_uint64_t start)
{
	grub_size_t i;

	for (i = 0; i < scan->nskips; i++)
		if (scan->skips[i].state == LOST_SKIP_PASSED
			&& scan->skips[i].from <= start && start < scan->skips[i].to)
			scan->skips[i].state = LOST_SKIP_QUEUED;
}

/* Does a table entry, an unreadable partition or an earlier result
   start in [FROM, TO)?  */
static int
lost_evidence (const struct rover_lost_scan *scan, grub_uint64_t from, grub_uint64_t to)
{
	grub_size_t i;

	for (i = 0; i < scan->ntables; i++)
		if (scan->tables[i].start >= from && scan->tables[i].start < to)
			return 1;
	for (i = 0; i < scan->nranges; i++)
		if (!scan->ranges[i].readable && scan->ranges[i].start >= from
			&& scan->ranges[i].start < to)
			return 1;
	for (i = 0; i < scan->nfound; i++)
		if (scan->found[i].start >= from && scan->found[i].start < to)
			return 1;
	return 0;
}

/* Quick search: continue at END, after a filesystem just found, unless
   something already points inside it.  The range stepped over is kept
   in case something does later.  */
static int
lost_jump (struct rover_lost_scan *scan, grub_uint64_t end)
{
	if (end <= scan->pos || end > scan->size || lost_evidence (scan, scan->pos, end))
		return 0;
	if (scan->nskips == scan->skips_alloc)
	{
		grub_size_t alloc = scan->skips_alloc ? scan->skips_alloc * 2 : 16;
		struct lost_skip *skips = grub_realloc (scan->skips, alloc * sizeof (*skips));

		if (!skips)
			return -1;
		scan->skips = skips;
		scan->skips_alloc = alloc;
	}
	scan->skips[scan->nskips].from = scan->pos;
	scan->skips[scan->nskips].to = end;
	scan->skips[scan->nskips].state = LOST_SKIP_PASSED;
	scan->nskips++;
	scan->pos = end;
	return 0;
}

/* Start searching the next queued range; zero when there is none.  */
static int
lost_next_pass (struct rover_lost_scan *scan)
{
	grub_size_t i;

	for (i = 0; i < scan->nskips; i++)
		if (scan->skips[i].state == LOST_SKIP_QUEUED)
		{
			scan->skips[i].state = LOST_SKIP_DONE;
			scan->pos = scan->skips[i].from;
			scan->limit = scan->skips[i].to;
			scan->rescanning = 1;
			return 1;
		}
	return 0;
}

/* The smallest candidate offset at or after FROM, or scan->size + 1.
   Candidates: every MiB (next.c, "Vista" alignment), the first sector of
   heads 0..2 of every cylinder for 512-byte sectors (next.c, i386), and
   the hints.  The device end is a hint: its last sectors may hold an
   NTFS backup boot sector or an HFS alternate header.  */
static grub_uint64_t
lost_next (const struct rover_lost_scan *scan, grub_uint64_t from)
{
	grub_uint64_t best = lost_round_up (from, LOST_MIB);
	grub_size_t lo = 0, hi = scan->nhints;

	if (scan->sector_size == 512)
	{
		grub_uint64_t cyl = from / LOST_CYLINDER * LOST_CYLINDER;
		unsigned int head;

		for (head = 0; head < 3; head++)
		{
			grub_uint64_t c = cyl + head * LOST_TRACK;

			if (c < from)
				c += LOST_CYLINDER;
			if (c < best)
				best = c;
		}
	}
	while (lo < hi)
	{
		grub_size_t mid = lo + (hi - lo) / 2;

		if (scan->hints[mid] < from)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < scan->nhints && scan->hints[lo] < best)
		best = scan->hints[lo];
	if (best > scan->size)
		best = scan->size + 1;
	return best;
}

static const struct lost_range *
lost_range_at (const struct rover_lost_scan *scan, grub_uint64_t offset, int readable)
{
	grub_size_t i;

	for (i = 0; i < scan->nranges; i++)
		if (scan->ranges[i].readable == readable
			&& offset >= scan->ranges[i].start && offset < scan->ranges[i].end)
			return &scan->ranges[i];
	return NULL;
}

/* Report HIT unless it duplicates an earlier result or lies in a
   readable partition.  Returns the callback's value, or -1 on error.  */
static int
lost_report (struct rover_lost_scan *scan, const struct lost_hit *found_hit,
	unsigned int flags, rover_lost_hook cb, void *data)
{
	struct rover_lost_part part;
	struct lost_hit primary;
	const struct lost_hit *hit = found_hit;
	grub_uint64_t end, window;
	char *label = NULL;
	char *uuid = NULL;
	grub_size_t i;
	int ret;

	if (hit->size == 0 || hit->start >= scan->size || lost_range_at (scan, hit->start, 1))
		return 0;
	if (hit->backup && lost_primary_ok (scan, hit))
	{
		/* Found through a backup, but the primary is fine: no remap.  */
		primary = *hit;
		primary.backup = 0;
		primary.remap_count = 0;
		hit = &primary;
	}
	end = hit->start + hit->size;
	/* Known already: still step over it.  */
	for (i = 0; i < scan->nfound; i++)
		if (scan->found[i].start == hit->start && scan->found[i].size == hit->size
			&& grub_strcmp (scan->found[i].type, hit->type) == 0)
			return end > hit->start && lost_jump (scan, end) ? -1 : 0;

	grub_memset (&part, 0, sizeof (part));
	part.offset = hit->start;
	part.size = hit->size;
	part.type = hit->type;
	part.flags = flags;
	if (hit->backup)
		part.flags |= ROVER_LOST_BACKUP;
	if (end < hit->start || end > scan->size)
		part.flags |= ROVER_LOST_TRUNCATED;
	for (i = 0; i < scan->nranges; i++)
	{
		const struct lost_range *r = &scan->ranges[i];

		if (!r->readable && r->start == hit->start)
			part.flags |= ROVER_LOST_EXISTING;
		if (r->readable && hit->start < r->end && (end > r->start || end < hit->start))
			part.flags |= ROVER_LOST_OVERLAP;
	}
	for (i = 0; i < scan->nfound; i++)
		if (hit->start < scan->found[i].start + scan->found[i].size && end > scan->found[i].start)
			part.flags |= ROVER_LOST_OVERLAP;
	for (i = 0; i < scan->ntables; i++)
		if (scan->tables[i].start == hit->start)
		{
			scan->tables[i].claimed = 1;
			part.flags |= ROVER_LOST_TABLE;
		}

	/* Open what the device holds of it through lostdisk, with the
	   backups that lie inside that window standing in for primaries.  */
	window = (part.flags & ROVER_LOST_TRUNCATED) ? scan->size - hit->start : hit->size;
	window -= window % scan->sector_size;
	part.window = window;
	for (i = 0; i < hit->remap_count; i++)
	{
		const struct rover_lost_remap *r = &hit->remap[i];

		if (r->length <= window && r->target <= window - r->length
			&& r->source <= window - r->length)
			part.remap[part.remap_count++] = *r;
	}
	if (window && grub_lostdisk_probe (scan->disk, hit->start >> GRUB_DISK_SECTOR_BITS,
		window >> GRUB_DISK_SECTOR_BITS, part.remap, part.remap_count,
		&part.fs, &label, &uuid) == GRUB_ERR_NONE)
	{
		part.flags |= ROVER_LOST_VERIFIED;
		part.label = label;
		part.fs_uuid = uuid;
	}
	grub_errno = GRUB_ERR_NONE;

	if (scan->nfound == scan->found_alloc)
	{
		grub_size_t alloc = scan->found_alloc ? scan->found_alloc * 2 : 16;
		struct lost_found *found = grub_realloc (scan->found, alloc * sizeof (*found));

		if (!found)
			goto fail;
		scan->found = found;
		scan->found_alloc = alloc;
	}
	scan->found[scan->nfound].start = hit->start;
	scan->found[scan->nfound].size = hit->size;
	scan->found[scan->nfound].type = hit->type;
	scan->nfound++;
	lost_conflict (scan, hit->start);

	if (!(part.flags & ROVER_LOST_TRUNCATED)
		&& (lost_add_end_hints (scan, end) || lost_jump (scan, end)))
		goto fail;

	ret = cb (&part, data) ? 1 : 0;
	grub_free (label);
	grub_free (uuid);
	return ret;

fail:
	grub_free (label);
	grub_free (uuid);
	return -1;
}

/* Deep search: keep HIT for the end, once; a copy found through its
   primary replaces one found through a backup.  */
static int
lost_pend (struct rover_lost_scan *scan, const struct lost_hit *hit)
{
	grub_size_t i;

	if (hit->size == 0)
		return 0;
	for (i = 0; i < scan->npending; i++)
	{
		struct lost_hit *p = &scan->pending[i];

		if (p->start == hit->start && p->size == hit->size && grub_strcmp (p->type, hit->type) == 0)
		{
			if (p->backup && !hit->backup)
				*p = *hit;
			return 0;
		}
	}
	if (scan->npending == scan->pending_alloc)
	{
		grub_size_t alloc = scan->pending_alloc ? scan->pending_alloc * 2 : 64;
		struct lost_hit *pending = grub_realloc (scan->pending, alloc * sizeof (*pending));

		if (!pending)
			return -1;
		scan->pending = pending;
		scan->pending_alloc = alloc;
	}
	scan->pending[scan->npending++] = *hit;
	return 0;
}

/* Deep search over: order the hits and drop superblock copies read as
   primaries -- a hit of the same type and size starting inside another.  */
static void
lost_settle (struct rover_lost_scan *scan)
{
	grub_size_t i, j, kept = 0;

	/* Insertion sort by start: hits arrive nearly in order.  */
	for (i = 1; i < scan->npending; i++)
	{
		struct lost_hit h = scan->pending[i];

		for (j = i; j > 0 && scan->pending[j - 1].start > h.start; j--)
			scan->pending[j] = scan->pending[j - 1];
		scan->pending[j] = h;
	}
	for (i = 0; i < scan->npending; i++)
	{
		const struct lost_hit *b = &scan->pending[i];
		int copy = 0;

		for (j = 0; j < scan->npending && !copy; j++)
		{
			const struct lost_hit *a = &scan->pending[j];

			copy = j != i && a->size == b->size && grub_strcmp (a->type, b->type) == 0
				&& a->start < b->start && b->start - a->start < a->size;
		}
		if (!copy)
			scan->pending[kept++] = *b;
	}
	scan->npending = kept;
	scan->pending_ready = 1;
}

/* Quick search: examine candidate S, reading around it.  */
static int
lost_quick_candidate (struct rover_lost_scan *scan, grub_uint64_t s, int end_only,
	struct lost_hit *hits)
{
	unsigned int tail = lost_tail_len (scan);
	grub_size_t len;
	int n = 0, ret;

	if (s >= tail && lost_read (scan, s - tail, tail, scan->tail) == 0)
		n = lost_examine_end (scan, s, scan->tail + tail, hits);
	if (end_only || s >= scan->size)
		return n;
	len = (grub_size_t) (scan->size - s < LOST_WINDOW ? scan->size - s : LOST_WINDOW);
	if (lost_read (scan, s, len, scan->buf))
		return n;
	if (len < LOST_WINDOW)
		grub_memset (scan->buf + len, 0, LOST_WINDOW - len);
	ret = lost_examine (scan, s, scan->buf, len, 1, &hits[n]);
	return ret < 0 ? -1 : n + ret;
}

/* Deep search: examine every sector from scan->pos on in one chunk,
   keeping the hits.  A readable partition is skipped; its start still
   counts as the end of a volume before it.  */
static int
lost_deep_chunk (struct rover_lost_scan *scan)
{
	unsigned int ss = scan->sector_size;
	unsigned int tail = lost_tail_len (scan);
	grub_uint64_t base = scan->pos, end, first, last, s, candidate;
	const struct lost_range *r = lost_range_at (scan, base, 1);
	struct lost_hit hits[3];
	grub_size_t i;
	int n, ret;

	if (r && r->start != base)
	{
		scan->pos = r->end;
		return 0;
	}
	end = r ? base + 1 : base + LOST_DEEP_CHUNK;
	for (i = 0; i < scan->nranges; i++)
		if (scan->ranges[i].readable && scan->ranges[i].start > base && scan->ranges[i].start < end)
			end = scan->ranges[i].start;
	if (end > scan->size + 1)
		end = scan->size + 1;

	/* The buffer holds [base - LOST_TAIL, end + LOST_WINDOW).  */
	grub_memset (scan->deep, 0, LOST_TAIL + LOST_DEEP_CHUNK + LOST_WINDOW);
	first = base > LOST_TAIL ? base - LOST_TAIL : 0;
	last = end + LOST_WINDOW < scan->size ? end + LOST_WINDOW : scan->size;
	if (last > first)
		lost_read_fill (scan, first, (grub_size_t) (last - first),
			scan->deep + (first + LOST_TAIL - base));

	candidate = lost_next (scan, base);
	for (s = base; s < end; s += ss)
	{
		const grub_uint8_t *at = scan->deep + LOST_TAIL + (s - base);
		int positional;

		if (candidate < s)
			candidate = lost_next (scan, s);
		positional = candidate == s;
		grub_memset (hits, 0, sizeof (hits));
		n = positional && s >= tail ? lost_examine_end (scan, s, at, hits) : 0;
		if (!r && s < scan->size)
		{
			ret = lost_examine (scan, s, at,
				(grub_size_t) (scan->size - s < LOST_WINDOW ? scan->size - s : LOST_WINDOW),
				positional, &hits[n]);
			if (ret < 0)
				return -1;
			n += ret;
		}
		for (ret = 0; ret < n; ret++)
			if (lost_pend (scan, &hits[ret]))
				return -1;
	}
	scan->pos = r ? r->end : end;
	return 0;
}

struct lost_part_ctx
{
	struct rover_lost_scan *scan;
	grub_disk_addr_t base;
	char **names;
	grub_size_t alloc;
	int failed;
};

static int
lost_collect_part (grub_disk_t disk, const grub_partition_t p, void *data)
{
	struct lost_part_ctx *ctx = data;
	struct rover_lost_scan *scan = ctx->scan;
	struct lost_range *r;
	char *pname;

	if (scan->nranges == ctx->alloc)
	{
		grub_size_t alloc = ctx->alloc ? ctx->alloc * 2 : 16;
		struct lost_range *ranges = grub_realloc (scan->ranges, alloc * sizeof (*ranges));
		char **names;

		if (!ranges)
			goto fail;
		scan->ranges = ranges;
		names = grub_realloc (ctx->names, alloc * sizeof (*names));
		if (!names)
			goto fail;
		ctx->names = names;
		ctx->alloc = alloc;
	}
	pname = grub_partition_get_name (p);
	if (!pname)
		goto fail;
	ctx->names[scan->nranges] = grub_xasprintf ("%s,%s", disk->name, pname);
	grub_free (pname);
	if (!ctx->names[scan->nranges])
		goto fail;

	r = &scan->ranges[scan->nranges++];
	r->start = (grub_partition_get_start (p) - ctx->base) << GRUB_DISK_SECTOR_BITS;
	r->end = r->start + (grub_partition_get_len (p) << GRUB_DISK_SECTOR_BITS);
	r->readable = 0;
	return 0;

fail:
	ctx->failed = 1;
	return 1;
}

static int
lost_readable (const char *name)
{
	grub_device_t dev = grub_device_open (name);
	int readable;

	if (!dev)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	readable = grub_fs_probe (dev) != NULL;
	grub_device_close (dev);
	grub_errno = GRUB_ERR_NONE;
	return readable;
}

rover_lost_scan *
rover_lost_scan_begin (const char *device, unsigned int flags)
{
	struct rover_lost_scan *scan;
	struct lost_part_ctx ctx;
	grub_uint64_t sectors, lba_size;
	grub_size_t i;
	static const unsigned int hints[] =
	{
		/* godmode.c search_add_hints: common starts under wrong or
		   unusual geometries, and the GPT "first usable LBA".  */
		32, 63, 16 * 63, 17 * 63, 240 * 63, 241 * 63, 255 * 63, 256 * 63, 34,
	};

	grub_errno = GRUB_ERR_NONE;
	grub_memset (&ctx, 0, sizeof (ctx));

	scan = grub_zalloc (sizeof (*scan));
	if (!scan)
		return NULL;
	scan->flags = flags;
	scan->limit = ~0ULL;
	scan->disk = grub_disk_open (device);
	if (!scan->disk)
		goto fail;
	sectors = grub_disk_native_sectors (scan->disk);
	if (sectors == GRUB_DISK_SIZE_UNKNOWN)
	{
		grub_error (GRUB_ERR_BAD_DEVICE, "size of `%s' is unknown", device);
		goto fail;
	}
	scan->size = sectors << GRUB_DISK_SECTOR_BITS;
	scan->sector_size = 1U << scan->disk->log_sector_size;
	scan->buf = grub_malloc (LOST_WINDOW);
	scan->tail = grub_malloc (LOST_TAIL);
	scan->aux = grub_malloc (LOST_AUX);
	if (flags & ROVER_LOST_SCAN_DEEP)
		scan->deep = grub_malloc (LOST_TAIL + LOST_DEEP_CHUNK + LOST_WINDOW);
	if (!scan->buf || !scan->tail || !scan->aux
		|| ((flags & ROVER_LOST_SCAN_DEEP) && !scan->deep))
		goto fail;

	/* A filesystem on the device itself: nothing is lost at offset 0.  */
	scan->base_readable = lost_readable (device);

	ctx.scan = scan;
	ctx.base = scan->disk->partition ? grub_partition_get_start (scan->disk->partition) : 0;
	grub_partition_iterate (scan->disk, lost_collect_part, &ctx);
	grub_errno = GRUB_ERR_NONE;
	if (ctx.failed)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
		goto fail;
	}
	for (i = 0; i < scan->nranges; i++)
	{
		struct lost_range *r = &scan->ranges[i];

		r->readable = lost_readable (ctx.names[i]);
		/* godmode.c: known partitions are search hints.  */
		if ((!r->readable && lost_add_hint (scan, r->start)) || lost_add_end_hints (scan, r->end))
			goto fail;
	}

	/* Both GPT headers, in the device's block size and, for 512-byte
	   sectors, in 4 KiB blocks as an image of a 4Kn disk has them.  */
	for (lba_size = scan->sector_size; lba_size <= 4096; lba_size <<= 3)
	{
		if (lost_gpt (scan, lba_size, 1) || lost_gpt (scan, lba_size, scan->size / lba_size - 1))
			goto fail;
		if (scan->sector_size != 512)
			break;
	}

	for (i = 0; i < ARRAY_SIZE (hints); i++)
		if (lost_add_hint (scan, hints[i] * 512ULL))
			goto fail;
	if (lost_add_hint (scan, scan->size))
		goto fail;
	if (scan->base_readable)
		scan->pos = scan->sector_size;

	for (i = 0; i < scan->nranges; i++)
		grub_free (ctx.names[i]);
	grub_free (ctx.names);
	return scan;

fail:
	for (i = 0; i < scan->nranges && ctx.names; i++)
		grub_free (ctx.names[i]);
	grub_free (ctx.names);
	rover_lost_scan_end (scan);
	return NULL;
}

int
rover_lost_scan_step (rover_lost_scan *scan, unsigned long long budget,
	rover_lost_hook cb, void *data)
{
	grub_uint64_t stop = scan->pos + budget;
	struct lost_hit hits[3];

	grub_errno = GRUB_ERR_NONE;
	if (budget == 0 || stop < scan->pos)
		stop = ~0ULL;

	while (!scan->done)
	{
		const struct lost_range *r;
		grub_uint64_t s;
		int n, i, ret, stopped = 0;

		if (scan->finishing && scan->next_pending < scan->npending)
		{
			/* Deep search: report what it kept.  */
			ret = lost_report (scan, &scan->pending[scan->next_pending++], 0, cb, data);
			if (ret < 0)
				goto fail;
			if (ret)
				break;
			continue;
		}
		if (scan->finishing)
		{
			/* Table entries no filesystem found at: GRUB may still
			   read what they hold.  */
			struct lost_table *t;
			struct lost_hit hit;

			if (scan->next_table == scan->ntables)
			{
				scan->done = 1;
				break;
			}
			t = &scan->tables[scan->next_table++];
			if (t->claimed)
				continue;
			lost_set_hit (&hit, t->start, t->size, "partition", 0);
			ret = lost_report (scan, &hit, 0, cb, data);
			if (ret < 0)
				goto fail;
			if (ret)
				break;
			continue;
		}

		if (scan->pos >= stop)
			break;
		if (scan->flags & ROVER_LOST_SCAN_DEEP)
		{
			if (scan->pos > scan->size)
			{
				lost_settle (scan);
				scan->pos = scan->size;
				scan->finishing = 1;
				continue;
			}
			if (lost_deep_chunk (scan))
				goto fail;
			continue;
		}
		s = lost_next (scan, scan->pos);
		if (s > scan->size || s >= scan->limit)
		{
			/* This pass is over: search a range stepped over after
			   all, or report the table entries.  */
			if (!lost_next_pass (scan))
				scan->finishing = 1;
			else if (budget)
				stop = scan->pos + budget;
			continue;
		}
		scan->pos = s + 1;
		if (s % scan->sector_size)
			continue;
		/* Readable partitions are not searched; their last sectors
		   still count for backups of a volume ending at S.  */
		r = lost_range_at (scan, s, 1);
		if (r && r->start != s)
		{
			scan->pos = r->end;
			continue;
		}

		grub_memset (hits, 0, sizeof (hits));
		n = lost_quick_candidate (scan, s, r != NULL, hits);
		if (n < 0)
			goto fail;
		for (i = 0; i < n; i++)
		{
			ret = lost_report (scan, &hits[i], 0, cb, data);
			if (ret < 0)
				goto fail;
			stopped |= ret;
		}
		if (stopped)
			break;
	}
	if (scan->pos > scan->size || scan->done)
		scan->pos = scan->size;
	return !scan->done;

fail:
	scan->done = 1;
	scan->pos = scan->size;
	if (grub_errno == GRUB_ERR_NONE)
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
	return -1;
}

void
rover_lost_scan_progress (const rover_lost_scan *scan,
	unsigned long long *done, unsigned long long *total)
{
	*done = scan->done || scan->rescanning ? scan->size : scan->pos;
	*total = scan->size;
}

void
rover_lost_scan_end (rover_lost_scan *scan)
{
	if (!scan)
		return;
	if (scan->disk)
		grub_disk_close (scan->disk);
	grub_free (scan->ranges);
	grub_free (scan->hints);
	grub_free (scan->found);
	grub_free (scan->tables);
	grub_free (scan->skips);
	grub_free (scan->pending);
	grub_free (scan->deep);
	grub_free (scan->aux);
	grub_free (scan->buf);
	grub_free (scan->tail);
	grub_free (scan);
}
