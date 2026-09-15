/*
 *  Rover -- Filesystem browser
 *  Copyright (C) 2026 A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* SCO Xenix 2.2+ divisions inside a primary MBR partition of type 0x02. */

#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/msdos_partition.h>
#include <grub/partition.h>

GRUB_MOD_LICENSE("GPLv3+");

#define XENIX_MSDOS_TYPE		0x02
#define XENIX_DIVVY_SECTOR	42
#define XENIX_BADTRK_SECTOR	44
#define XENIX_SYSTEM_SECTORS	52
#define XENIX_DIVVY_MAGIC		0x1234
#define XENIX_BADTRK_MAGIC	0x4321
#define XENIX_WHOLE_DIVISION	7
#define XENIX_MAX_BAD_TRACKS	1023

static struct grub_partition_map grub_xenix_partition_map;

static grub_uint16_t
xenix_get16(const grub_uint8_t *p)
{
	return grub_le_to_cpu16(grub_get_unaligned16(p));
}

static grub_uint32_t
xenix_get32(const grub_uint8_t *p)
{
	return grub_le_to_cpu32(grub_get_unaligned32(p));
}

static int
xenix_chs_matches(grub_disk_addr_t lba, unsigned head, unsigned sector,
	unsigned cylinder, unsigned heads, unsigned sectors)
{
	grub_disk_addr_t track = lba / sectors;

	/* Xenix fdisk can wrap the 10-bit cylinder field on large disks. */
	return head == track % heads
		&& (sector & 63) == lba % sectors + 1
		&& (cylinder | ((sector & 0xc0) << 2))
			== ((track / heads) & 1023);
}

static grub_err_t
xenix_partition_map_iterate(grub_disk_t disk,
	grub_partition_iterate_hook_t hook, void *hook_data)
{
	grub_partition_t parent = disk->partition;
	struct grub_msdos_partition_mbr mbr;
	const struct grub_msdos_partition_entry *entry;
	struct grub_partition parts[XENIX_WHOLE_DIVISION];
	grub_uint8_t label[66];
	grub_uint8_t badtrk[8];
	grub_disk_addr_t start, length, track, data_start, reserved;
	unsigned heads, sectors, aliases, i;

	/* Geometry comes from the primary MBR in the same address space.
	 * Standalone division images and extended/nested MBRs need a separate
	 * geometry source and are not recognized by this parser.
	 */
	if (!parent || parent->parent || parent->offset != 0
		|| grub_strcmp(parent->partmap->name, "msdos") != 0
		|| parent->msdostype != XENIX_MSDOS_TYPE
		|| parent->index < 0 || parent->index >= 4
		|| disk->log_sector_size != GRUB_DISK_SECTOR_BITS
		|| parent->len < XENIX_SYSTEM_SECTORS)
		return grub_error(GRUB_ERR_BAD_PART_TABLE, "not a xenix partition");

	if (grub_disk_read(disk, XENIX_DIVVY_SECTOR, 0, sizeof(label), label))
		goto fail;
	if (xenix_get16(label) != XENIX_DIVVY_MAGIC)
	{
		grub_error(GRUB_ERR_BAD_PART_TABLE, "no xenix 2.2+ division table");
		goto fail;
	}
	if (grub_disk_read(disk, XENIX_BADTRK_SECTOR, 0, sizeof(badtrk), badtrk))
		goto fail;
	aliases = xenix_get16(badtrk + 2);
	if (xenix_get16(badtrk) != XENIX_BADTRK_MAGIC
		|| aliases > XENIX_MAX_BAD_TRACKS)
	{
		grub_error(GRUB_ERR_BAD_PART_TABLE, "invalid xenix bad-track table");
		goto fail;
	}
	/* A partition map can express contiguous ranges, not track remapping.
	 * An empty table still reserves aliases tracks. The first sentinel
	 * terminates the table; unused bytes after it have no meaning.
	 */
	if (xenix_get16(badtrk + 4) != 0xffff
		|| xenix_get16(badtrk + 6) != 0xffff)
	{
		grub_error(GRUB_ERR_BAD_PART_TABLE,
			"xenix bad-track remapping is not supported");
		goto fail;
	}

	disk->partition = NULL;
	if (grub_disk_read(disk, 0, 0, sizeof(mbr), &mbr))
		goto fail;
	disk->partition = parent;
	entry = &mbr.entries[parent->index];
	start = grub_le_to_cpu32(entry->start);
	length = grub_le_to_cpu32(entry->length);
	if (grub_le_to_cpu16(mbr.signature) != GRUB_PC_PARTITION_SIGNATURE
		|| entry->type != XENIX_MSDOS_TYPE
		|| start != parent->start || length != parent->len)
	{
		grub_error(GRUB_ERR_BAD_PART_TABLE, "inconsistent xenix outer partition");
		goto fail;
	}

	/* SCO fdisk ends its partition on a cylinder boundary. Recover the
	 * geometry from that endpoint, then verify both CHS addresses against
	 * their LBAs. Do not guess a geometry or use a fixed filesystem offset.
	 */
	heads = (unsigned) entry->end_head + 1;
	sectors = entry->end_sector & 63;
	if (!sectors
		|| !xenix_chs_matches(start, entry->start_head, entry->start_sector,
			entry->start_cylinder, heads, sectors)
		|| !xenix_chs_matches(start + length - 1, entry->end_head,
			entry->end_sector, entry->end_cylinder, heads, sectors))
	{
		grub_error(GRUB_ERR_BAD_PART_TABLE, "inconsistent xenix CHS geometry");
		goto fail;
	}

	/* Round the start and the fixed system area to tracks separately,
	 * add spare tracks, and round the result to the next cylinder.
	 */
	track = (start + sectors - 1) / sectors;
	track += (XENIX_SYSTEM_SECTORS + sectors - 1) / sectors + aliases;
	data_start = ((track + heads - 1) / heads) * heads * sectors;
	reserved = data_start - start;
	if (reserved >= length
		|| xenix_get32(label + 2 + XENIX_WHOLE_DIVISION * 8) != 0
		|| xenix_get32(label + 6 + XENIX_WHOLE_DIVISION * 8)
			!= (length + 1) / 2)
	{
		grub_error(GRUB_ERR_BAD_PART_TABLE, "invalid xenix reserved or whole area");
		goto fail;
	}

	grub_memset(parts, 0, sizeof(parts));
	/* Validate all entries before exposing any of them. Division 7 is
	 * the whole outer partition, without reserved-area displacement, and
	 * is omitted. Its length can round an odd sector count up by one.
	 */
	for (i = 0; i < XENIX_WHOLE_DIVISION; i++)
	{
		grub_uint32_t off = xenix_get32(label + 2 + i * 8);
		grub_uint32_t size = xenix_get32(label + 6 + i * 8);
		struct grub_partition *p = &parts[i];

		if (!size)
			continue;
		p->start = reserved + (grub_disk_addr_t) off * 2;
		p->len = (grub_disk_addr_t) size * 2;
		if ((off | size) & 0x80000000U
			|| p->start >= length || p->len > length - p->start)
		{
			grub_error(GRUB_ERR_BAD_PART_TABLE, "xenix division outside parent");
			goto fail;
		}
		p->partmap = &grub_xenix_partition_map;
		p->number = (int) i;
		p->offset = XENIX_DIVVY_SECTOR;
		p->index = 2 + (int) i * 8;
	}

	/* Overlapping one-block placeholder divisions are legitimate. Keep
	 * the original slot numbers: Xenix division 0 is GRUB xenix1.
	 */
	for (i = 0; i < XENIX_WHOLE_DIVISION; i++)
	{
		if (parts[i].len && hook(disk, &parts[i], hook_data))
			break;
	}

fail:
	disk->partition = parent;
	return grub_errno;
}

static struct grub_partition_map grub_xenix_partition_map =
{
	.name = "xenix",
	.iterate = xenix_partition_map_iterate,
};

GRUB_MOD_INIT(part_xenix)
{
	grub_partition_map_register(&grub_xenix_partition_map);
}

GRUB_MOD_FINI(part_xenix)
{
	grub_partition_map_unregister(&grub_xenix_partition_map);
}
