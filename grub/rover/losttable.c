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
 * Partition table entries of the lost partition search that GRUB does
 * not use: the GPT tables GRUB skips -- the backup, or a primary without
 * protective MBR.
 * Entries GRUB lists are left out; the others become search candidates
 * and, where no filesystem is found at their start, results of their own.
 */

#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>

#include "lostint.h"

/* Remember a partition table entry GRUB does not use, unless it is one
   GRUB lists.  Its start becomes a candidate.  */
int
lost_add_table (struct rover_lost_scan *scan, grub_uint64_t start, grub_uint64_t size)
{
	grub_size_t i;

	if (size == 0 || start % scan->sector_size || start >= scan->size)
		return 0;
	for (i = 0; i < scan->nranges; i++)
		if (scan->ranges[i].start == start && scan->ranges[i].end - start == size)
			return 0;
	for (i = 0; i < scan->ntables; i++)
		if (scan->tables[i].start == start && scan->tables[i].size == size)
			return 0;
	if (scan->ntables == scan->tables_alloc)
	{
		grub_size_t alloc = scan->tables_alloc ? scan->tables_alloc * 2 : 16;
		struct lost_table *tables = grub_realloc (scan->tables, alloc * sizeof (*tables));

		if (!tables)
			return -1;
		scan->tables = tables;
		scan->tables_alloc = alloc;
	}
	scan->tables[scan->ntables].start = start;
	scan->tables[scan->ntables].size = size;
	scan->tables[scan->ntables].claimed = 0;
	scan->ntables++;
	lost_conflict (scan, start);
	if (lost_add_hint (scan, start))
		return -1;
	if (start + size > start && start + size <= scan->size && lost_add_end_hints (scan, start + size))
		return -1;
	return 0;
}

/* partgpt.c read_part_gpt_aux: the GPT header at LBA (LBA_SIZE bytes
   per block) and its entries, both checksummed.  */
int
lost_gpt (struct rover_lost_scan *scan, grub_uint64_t lba_size, grub_uint64_t lba)
{
	grub_uint8_t *hdr = scan->buf;
	grub_uint8_t *entries = NULL;
	grub_uint64_t entries_off;
	grub_uint32_t count, entry_size, hdr_size, crc, i;
	grub_size_t len;
	int ret = 0;

	if (lba_size > LOST_WINDOW || (lba + 1) * lba_size > scan->size
		|| lost_read (scan, lba * lba_size, (grub_size_t) lba_size, hdr)
		|| grub_memcmp (hdr, "EFI PART", 8) != 0)
		return 0;
	hdr_size = lost_le32 (hdr + 12);
	if (hdr_size < 92 || hdr_size > lba_size)
		return 0;
	crc = lost_le32 (hdr + 16);
	grub_memset (hdr + 16, 0, 4);
	if (lost_crc32 (hdr, hdr_size) != crc
		|| lost_le64 (hdr + 24) != lba	/* my LBA */
		|| lost_le64 (hdr + 40) >= lost_le64 (hdr + 48))	/* usable range */
		return 0;
	count = lost_le32 (hdr + 80);
	entry_size = lost_le32 (hdr + 84);
	crc = lost_le32 (hdr + 88);
	entries_off = lost_le64 (hdr + 72) * lba_size;
	if (count == 0 || count > LOST_GPT_MAX_ENTRIES
		|| entry_size < 128 || entry_size > 4096 || entry_size % 8
		|| entries_off / lba_size != lost_le64 (hdr + 72))
		return 0;
	len = (grub_size_t) count * entry_size;
	if (entries_off > scan->size || len > scan->size - entries_off)
		return 0;

	entries = grub_malloc (len);
	if (!entries)
		return -1;
	if (lost_read (scan, entries_off, len, entries) || lost_crc32 (entries, len) != crc)
		goto out;
	for (i = 0; i < count; i++)
	{
		const grub_uint8_t *e = entries + (grub_size_t) i * entry_size;
		grub_uint64_t first = lost_le64 (e + 32);
		grub_uint64_t last = lost_le64 (e + 40);
		unsigned int k;

		for (k = 0; k < 16 && !e[k]; k++)
			;
		if (k == 16 || first == 0 || first > last || last >= ~0ULL / lba_size)
			continue;
		if (lost_add_table (scan, first * lba_size, (last - first + 1) * lba_size))
		{
			ret = -1;
			goto out;
		}
	}
out:
	grub_free (entries);
	return ret;
}
