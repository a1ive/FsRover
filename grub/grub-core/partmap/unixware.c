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
 * SCO UnixWare slices.
 *
 * UnixWare puts the whole installation into one MSDOS partition of type
 * 0x63 and divides it into slices with a disk label that lives in sector
 * 29 of that partition.
 * A slice table entry addresses the disk, not the partition,
 * so the starts are turned back into partition relative ones here.
 * Slice 0 covers the whole partition and is left out, as are the
 * ones tagged unused.
 */

#include <grub/partition.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/err.h>

GRUB_MOD_LICENSE("GPLv3+");

#define UNIXWARE_MSDOS_TYPE	0x63
#define UNIXWARE_LABEL_SECTOR	29
/* the disk magic follows the drive type, the vtoc follows the geometry */
#define UNIXWARE_DISK_MAGIC	0xca5e600dU
#define UNIXWARE_MAGIC_OFFSET	4
#define UNIXWARE_VTOC_MAGIC	0x600ddeeeU
#define UNIXWARE_VTOC_OFFSET	156
#define UNIXWARE_NUMSLICE	16

/* vtoc byte offsets */
#define UNIXWARE_VTOC_NSLICES	16
#define UNIXWARE_VTOC_SLICE	60

/* slice entry byte offsets */
#define UNIXWARE_SLICE_LABEL	0x00
#define UNIXWARE_SLICE_START	0x04
#define UNIXWARE_SLICE_SECTORS	0x08
#define UNIXWARE_SLICE_SIZE	0x0c

#define UNIXWARE_SLICE_UNUSED	0

static struct grub_partition_map grub_unixware_partition_map;

static grub_uint16_t
unixware_get16(const grub_uint8_t *p)
{
	return grub_le_to_cpu16(grub_get_unaligned16(p));
}

static grub_uint32_t
unixware_get32(const grub_uint8_t *p)
{
	return grub_le_to_cpu32(grub_get_unaligned32(p));
}

static grub_err_t
unixware_partition_map_iterate(grub_disk_t disk,
	grub_partition_iterate_hook_t hook, void *hook_data)
{
	struct grub_partition p;
	grub_uint8_t label[GRUB_DISK_SECTOR_SIZE];
	grub_disk_addr_t base;
	grub_uint32_t nslices;
	unsigned i;

	/* the label describes one MSDOS partition of the UnixWare type */
	if (!disk->partition
		|| grub_strcmp(disk->partition->partmap->name, "msdos") != 0
		|| disk->partition->msdostype != UNIXWARE_MSDOS_TYPE)
		return grub_error(GRUB_ERR_BAD_PART_TABLE,
			"not a unixware partition");

	if (grub_disk_read(disk, UNIXWARE_LABEL_SECTOR, 0, sizeof(label), label))
		return grub_errno;

	if (unixware_get32(label + UNIXWARE_MAGIC_OFFSET) != UNIXWARE_DISK_MAGIC)
		return grub_error(GRUB_ERR_BAD_PART_TABLE,
			"no unixware disk label");
	if (unixware_get32(label + UNIXWARE_VTOC_OFFSET) != UNIXWARE_VTOC_MAGIC)
		return grub_error(GRUB_ERR_BAD_PART_TABLE, "no unixware vtoc");

	nslices = unixware_get16(label + UNIXWARE_VTOC_OFFSET
		+ UNIXWARE_VTOC_NSLICES);
	if (nslices > UNIXWARE_NUMSLICE)
		nslices = UNIXWARE_NUMSLICE;

	base = grub_partition_get_start(disk->partition);
	p.partmap = &grub_unixware_partition_map;

	/* slice 0 is the whole partition; the rest keep their slice number,
	   so that slice 1 shows up as unixware1 */
	for (i = 1; i < nslices; i++)
	{
		grub_uint32_t off = UNIXWARE_VTOC_OFFSET + UNIXWARE_VTOC_SLICE
			+ i * UNIXWARE_SLICE_SIZE;
		grub_uint32_t start = unixware_get32(label + off
			+ UNIXWARE_SLICE_START);
		grub_uint32_t len = unixware_get32(label + off
			+ UNIXWARE_SLICE_SECTORS);

		if (unixware_get16(label + off + UNIXWARE_SLICE_LABEL)
			== UNIXWARE_SLICE_UNUSED || !len || start < base)
			continue;

		p.start = start - base;
		p.len = len;
		p.number = (int) i - 1;
		p.offset = UNIXWARE_LABEL_SECTOR;
		p.index = (int) off;

		if (hook(disk, &p, hook_data))
			break;
	}

	return grub_errno;
}

static struct grub_partition_map grub_unixware_partition_map =
{
	.name = "unixware",
	.iterate = unixware_partition_map_iterate,
};

GRUB_MOD_INIT(part_unixware)
{
	grub_partition_map_register(&grub_unixware_partition_map);
}

GRUB_MOD_FINI(part_unixware)
{
	grub_partition_map_unregister(&grub_unixware_partition_map);
}
