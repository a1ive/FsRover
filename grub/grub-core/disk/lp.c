/* lp.c - Android dynamic-partition (super image) support.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2026  A1ive
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/crypto.h>
#include <grub/disk.h>
#include <grub/diskfilter.h>
#include <grub/dl.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/partition.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define LP_RESERVED_BYTES		4096U
#define LP_GEOMETRY_BLOCK_SIZE		4096U
#define LP_GEOMETRY_STRUCT_SIZE		52U
#define LP_GEOMETRY_MAGIC		0x616c4467U

#define LP_METADATA_HEADER_MAGIC	0x414c5030U
#define LP_METADATA_MAJOR_VERSION	10U
#define LP_METADATA_HEADER10_SIZE	128U
#define LP_METADATA_HEADER12_SIZE	256U

#define LP_PARTITION_ENTRY_SIZE		52U
#define LP_EXTENT_ENTRY_SIZE		24U
#define LP_GROUP_ENTRY_SIZE		48U
#define LP_DEVICE_ENTRY_SIZE		64U
#define LP_NAME_LEN			36U

#define LP_TARGET_LINEAR		0U
#define LP_TARGET_ZERO			1U

#define LP_PARTITION_ATTR_SLOT_SUFFIXED	(1U << 1)
#define LP_PARTITION_ATTR_DISABLED	(1U << 3)

#define LP_ID_SIZE			32U
#define LP_UINT64_MAX			(~(grub_uint64_t) 0)

struct lp_desc
{
	grub_uint32_t offset;
	grub_uint32_t count;
	grub_uint32_t entry_size;
};

struct lp_geometry
{
	grub_uint32_t metadata_max_size;
	grub_uint32_t slot_count;
	grub_uint32_t logical_block_size;
};

struct lp_metadata
{
	grub_uint8_t *buf;
	grub_uint8_t *tables;
	grub_uint32_t header_size;
	grub_uint32_t tables_size;
	grub_uint32_t slot;
	struct lp_desc partitions;
	struct lp_desc extents;
	struct lp_desc groups;
	struct lp_desc devices;
};

static grub_uint16_t
lp_get16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
lp_get32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
lp_get64 (const grub_uint8_t *p)
{
	return grub_le_to_cpu64 (grub_get_unaligned64 (p));
}

static int
lp_check_sha256 (grub_uint8_t *buf, grub_size_t size, grub_size_t checksum_offset)
{
	const gcry_md_spec_t *sha256;
	grub_uint8_t expected[32];
	grub_uint8_t actual[32];

	if (checksum_offset > size || size - checksum_offset < sizeof (expected))
		return 0;
	sha256 = grub_crypto_lookup_md_by_name ("sha256");
	if (!sha256)
		return 0;
	grub_memcpy (expected, buf + checksum_offset, sizeof (expected));
	grub_memset (buf + checksum_offset, 0, sizeof (expected));
	grub_crypto_hash (sha256, actual, buf, size);
	grub_memcpy (buf + checksum_offset, expected, sizeof (expected));
	return grub_memcmp (actual, expected, sizeof (actual)) == 0;
}

static int
lp_check_digest (const grub_uint8_t *buf, grub_size_t size,
	const grub_uint8_t expected[32])
{
	const gcry_md_spec_t *sha256;
	grub_uint8_t actual[32];

	sha256 = grub_crypto_lookup_md_by_name ("sha256");
	if (!sha256)
		return 0;
	grub_crypto_hash (sha256, actual, buf, size);
	return grub_memcmp (actual, expected, sizeof (actual)) == 0;
}

static int
lp_parse_geometry (grub_uint8_t *buf, struct lp_geometry *geometry)
{
	grub_uint32_t struct_size;

	if (lp_get32 (buf) != LP_GEOMETRY_MAGIC)
		return 0;
	struct_size = lp_get32 (buf + 4);
	if (struct_size < LP_GEOMETRY_STRUCT_SIZE
		|| struct_size > LP_GEOMETRY_BLOCK_SIZE
		|| !lp_check_sha256 (buf, struct_size, 8))
		return 0;

	geometry->metadata_max_size = lp_get32 (buf + 40);
	geometry->slot_count = lp_get32 (buf + 44);
	geometry->logical_block_size = lp_get32 (buf + 48);
	if (geometry->metadata_max_size == 0
		|| (geometry->metadata_max_size & (GRUB_DISK_SECTOR_SIZE - 1)) != 0
		|| geometry->slot_count == 0 || geometry->slot_count >= (1U << 20)
		|| geometry->logical_block_size < GRUB_DISK_SECTOR_SIZE
		|| (geometry->logical_block_size & (geometry->logical_block_size - 1)) != 0)
		return 0;
	return 1;
}

static int
lp_read_geometry (grub_disk_t disk, struct lp_geometry *geometry)
{
	grub_uint8_t *buf;
	unsigned int copy;
	int saw_magic = 0;

	buf = grub_malloc (LP_GEOMETRY_BLOCK_SIZE);
	if (!buf)
		return 0;
	for (copy = 0; copy < 2; copy++)
	{
		grub_off_t offset = LP_RESERVED_BYTES
			+ (grub_off_t) copy * LP_GEOMETRY_BLOCK_SIZE;

		if (grub_disk_read (disk, 0, offset, LP_GEOMETRY_BLOCK_SIZE, buf))
		{
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		if (lp_get32 (buf) == LP_GEOMETRY_MAGIC)
			saw_magic = 1;
		if (lp_parse_geometry (buf, geometry))
		{
			grub_free (buf);
			return 1;
		}
	}
	grub_free (buf);
	if (saw_magic)
		grub_error (GRUB_ERR_BAD_FS, "invalid Android LP geometry");
	return 0;
}

static void
lp_parse_desc (const grub_uint8_t *p, struct lp_desc *desc)
{
	desc->offset = lp_get32 (p);
	desc->count = lp_get32 (p + 4);
	desc->entry_size = lp_get32 (p + 8);
}

static int
lp_check_desc (const struct lp_desc *desc, grub_uint32_t tables_size,
	grub_uint32_t expected_size)
{
	grub_uint64_t size = (grub_uint64_t) desc->count * desc->entry_size;

	return desc->entry_size == expected_size
		&& desc->offset <= tables_size
		&& size <= tables_size - desc->offset;
}

static int
lp_read_metadata_copy (grub_disk_t disk, grub_uint64_t offset,
	grub_uint32_t max_size, struct lp_metadata *metadata)
{
	grub_uint8_t head[LP_METADATA_HEADER10_SIZE];
	grub_uint32_t header_size;
	grub_uint32_t tables_size;
	grub_uint64_t total;
	grub_uint8_t tables_checksum[32];

	if (grub_disk_read (disk, 0, offset, sizeof (head), head))
		return 0;
	if (lp_get32 (head) != LP_METADATA_HEADER_MAGIC
		|| lp_get16 (head + 4) != LP_METADATA_MAJOR_VERSION)
		return 0;
	header_size = lp_get32 (head + 8);
	tables_size = lp_get32 (head + 44);
	if (header_size != LP_METADATA_HEADER10_SIZE
		&& header_size != LP_METADATA_HEADER12_SIZE)
		return 0;
	total = (grub_uint64_t) header_size + tables_size;
	if (total > max_size || total > GRUB_SIZE_MAX)
		return 0;

	metadata->buf = grub_malloc ((grub_size_t) total);
	if (!metadata->buf)
		return 0;
	if (grub_disk_read (disk, 0, offset, (grub_size_t) total, metadata->buf))
		goto fail;
	if (!lp_check_sha256 (metadata->buf, header_size, 12))
		goto fail;
	grub_memcpy (tables_checksum, metadata->buf + 48, sizeof (tables_checksum));
	metadata->tables = metadata->buf + header_size;
	if (!lp_check_digest (metadata->tables, tables_size, tables_checksum))
		goto fail;

	metadata->header_size = header_size;
	metadata->tables_size = tables_size;
	lp_parse_desc (metadata->buf + 80, &metadata->partitions);
	lp_parse_desc (metadata->buf + 92, &metadata->extents);
	lp_parse_desc (metadata->buf + 104, &metadata->groups);
	lp_parse_desc (metadata->buf + 116, &metadata->devices);
	if (!lp_check_desc (&metadata->partitions, tables_size, LP_PARTITION_ENTRY_SIZE)
		|| !lp_check_desc (&metadata->extents, tables_size, LP_EXTENT_ENTRY_SIZE)
		|| !lp_check_desc (&metadata->groups, tables_size, LP_GROUP_ENTRY_SIZE)
		|| !lp_check_desc (&metadata->devices, tables_size, LP_DEVICE_ENTRY_SIZE)
		|| metadata->devices.count == 0)
		goto fail;
	return 1;

fail:
	grub_free (metadata->buf);
	grub_memset (metadata, 0, sizeof (*metadata));
	return 0;
}

static int
lp_read_metadata (grub_disk_t disk, const struct lp_geometry *geometry,
	struct lp_metadata *metadata)
{
	grub_uint64_t primary;
	grub_uint64_t backup;
	grub_uint64_t slot_area;
	grub_uint64_t total_metadata;
	grub_uint64_t disk_sectors;
	grub_uint32_t slot;

	primary = LP_RESERVED_BYTES + 2U * LP_GEOMETRY_BLOCK_SIZE;
	slot_area = (grub_uint64_t) geometry->metadata_max_size * geometry->slot_count;
	if (slot_area > (LP_UINT64_MAX - primary) / 2)
		return 0;
	total_metadata = primary + slot_area * 2;
	disk_sectors = grub_disk_native_sectors (disk);
	if (disk_sectors != GRUB_DISK_SIZE_UNKNOWN
		&& (total_metadata >> GRUB_DISK_SECTOR_BITS)
			+ ((total_metadata & (GRUB_DISK_SECTOR_SIZE - 1)) != 0)
			> disk_sectors)
		return 0;
	backup = primary + slot_area;

	for (slot = 0; slot < geometry->slot_count; slot++)
	{
		grub_uint64_t slot_offset = (grub_uint64_t) slot
			* geometry->metadata_max_size;

		grub_errno = GRUB_ERR_NONE;
		if (lp_read_metadata_copy (disk, primary + slot_offset,
			geometry->metadata_max_size, metadata))
		{
			metadata->slot = slot;
			return 1;
		}
		grub_errno = GRUB_ERR_NONE;
		if (lp_read_metadata_copy (disk, backup + slot_offset,
			geometry->metadata_max_size, metadata))
		{
			metadata->slot = slot;
			return 1;
		}
	}
	grub_errno = GRUB_ERR_NONE;
	grub_error (GRUB_ERR_BAD_FS, "invalid Android LP metadata");
	return 0;
}

static const grub_uint8_t *
lp_entry (const struct lp_metadata *metadata, const struct lp_desc *desc,
	grub_uint32_t index)
{
	return metadata->tables + desc->offset
		+ (grub_size_t) index * desc->entry_size;
}

static char *
lp_partition_name (const grub_uint8_t *entry, grub_uint32_t attributes,
	grub_uint32_t slot)
{
	grub_size_t len;
	char *name;
	grub_size_t i;

	for (len = 0; len < LP_NAME_LEN && entry[len] != 0; len++);
	if (len == 0)
		return NULL;
	for (i = 0; i < len; i++)
		if (!grub_isalnum (entry[i]) && entry[i] != '_')
			return NULL;
	name = grub_strndup ((const char *) entry, len);
	if (!name)
		return NULL;
	if (attributes & LP_PARTITION_ATTR_SLOT_SUFFIXED)
	{
		char *suffixed;

		if (slot < 26)
			suffixed = grub_xasprintf ("%s_%c", name, 'a' + slot);
		else
			suffixed = grub_xasprintf ("%s_%" PRIuGRUB_UINT32_T, name, slot);
		grub_free (name);
		name = suffixed;
	}
	return name;
}

static char *
lp_volume_name (grub_disk_t disk)
{
	char *name;
	grub_size_t i;

	if (disk->partition)
		name = grub_xasprintf ("%s_p%" PRIuGRUB_UINT64_T, disk->name,
			(grub_uint64_t) grub_partition_get_start (disk->partition));
	else
		name = grub_strdup (disk->name);
	if (!name)
		return NULL;
	for (i = 0; name[i]; i++)
		if (!grub_isalnum (name[i]) && name[i] != '_' && name[i] != '.')
			name[i] = '_';
	return name;
}

static void
lp_make_id (grub_disk_t disk, grub_uint8_t id[LP_ID_SIZE])
{
	grub_uint32_t dev_id = (grub_uint32_t) disk->dev->id;
	grub_uint64_t disk_id = (grub_uint64_t) disk->id;
	grub_uint64_t part_start = grub_partition_get_start (disk->partition);
	grub_uint64_t part_size = grub_disk_native_sectors (disk);

	grub_memset (id, 0, LP_ID_SIZE);
	grub_memcpy (id, &dev_id, sizeof (dev_id));
	grub_memcpy (id + 8, &disk_id, sizeof (disk_id));
	grub_memcpy (id + 16, &part_start, sizeof (part_start));
	grub_memcpy (id + 24, &part_size, sizeof (part_size));
}

static int
lp_set_detect_id (struct grub_diskfilter_pv_id *id,
	const grub_uint8_t value[LP_ID_SIZE])
{
	id->uuid = grub_malloc (LP_ID_SIZE);
	if (!id->uuid)
		return 0;
	grub_memcpy (id->uuid, value, LP_ID_SIZE);
	id->uuidlen = LP_ID_SIZE;
	return 1;
}

static void
lp_free_lv (struct grub_diskfilter_lv *lv)
{
	unsigned int i;

	if (!lv)
		return;
	if (lv->segments)
		for (i = 0; i < lv->segment_count; i++)
			grub_free (lv->segments[i].nodes);
	grub_free (lv->segments);
	grub_free (lv->fullname);
	grub_free (lv->name);
	grub_free (lv);
}

static void
lp_free_vg (struct grub_diskfilter_vg *vg)
{
	struct grub_diskfilter_pv *pv;
	struct grub_diskfilter_lv *lv;

	if (!vg)
		return;
	while ((pv = vg->pvs) != NULL)
	{
		vg->pvs = pv->next;
		grub_free (pv->id.uuid);
		grub_free (pv->name);
		grub_free (pv);
	}
	while ((lv = vg->lvs) != NULL)
	{
		vg->lvs = lv->next;
		lp_free_lv (lv);
	}
	grub_free (vg->uuid);
	grub_free (vg->name);
	grub_free (vg);
}

static int
lp_validate_extents (grub_disk_t disk, const struct lp_metadata *metadata,
	grub_uint64_t device_sectors)
{
	grub_uint64_t actual_sectors = grub_disk_native_sectors (disk);
	grub_uint32_t i;

	if (actual_sectors != GRUB_DISK_SIZE_UNKNOWN
		&& device_sectors > actual_sectors)
		return 0;
	for (i = 0; i < metadata->extents.count; i++)
	{
		const grub_uint8_t *entry = lp_entry (metadata, &metadata->extents, i);
		grub_uint64_t sectors = lp_get64 (entry);
		grub_uint32_t type = lp_get32 (entry + 8);
		grub_uint64_t target = lp_get64 (entry + 12);
		grub_uint32_t source = lp_get32 (entry + 20);

		if (sectors == 0)
			return 0;
		if (type == LP_TARGET_LINEAR)
		{
			if (source != 0 || target > device_sectors
				|| sectors > device_sectors - target)
				return 0;
		}
		else if (type == LP_TARGET_ZERO)
		{
			if (target != 0 || source != 0)
				return 0;
		}
		else
			return 0;
	}
	return 1;
}

static struct grub_diskfilter_vg *
lp_build_vg (grub_disk_t disk, const struct lp_geometry *geometry,
	const struct lp_metadata *metadata, const grub_uint8_t id[LP_ID_SIZE])
{
	const grub_uint8_t *device;
	grub_uint64_t first_logical_sector;
	grub_uint64_t device_size;
	grub_uint64_t metadata_size;
	struct grub_diskfilter_vg *vg = NULL;
	struct grub_diskfilter_pv *pv = NULL;
	struct grub_diskfilter_lv **lv_tail;
	grub_uint32_t i;

	device = lp_entry (metadata, &metadata->devices, 0);
	first_logical_sector = lp_get64 (device);
	device_size = lp_get64 (device + 16);
	metadata_size = LP_RESERVED_BYTES + 2U * LP_GEOMETRY_BLOCK_SIZE
		+ (grub_uint64_t) geometry->metadata_max_size
			* geometry->slot_count * 2U;
	if ((device_size & (GRUB_DISK_SECTOR_SIZE - 1)) != 0
		|| first_logical_sector > (LP_UINT64_MAX >> GRUB_DISK_SECTOR_BITS)
		|| (first_logical_sector << GRUB_DISK_SECTOR_BITS) < metadata_size
		|| !lp_validate_extents (disk, metadata,
			device_size >> GRUB_DISK_SECTOR_BITS))
		return NULL;

	vg = grub_zalloc (sizeof (*vg));
	pv = grub_zalloc (sizeof (*pv));
	if (!vg || !pv)
		goto fail;
	vg->name = lp_volume_name (disk);
	vg->uuid = grub_malloc (LP_ID_SIZE);
	pv->id.uuid = grub_malloc (LP_ID_SIZE);
	pv->name = vg->name ? grub_strdup (vg->name) : NULL;
	if (!vg->name || !vg->uuid || !pv->id.uuid || !pv->name)
		goto fail;
	grub_memcpy (vg->uuid, id, LP_ID_SIZE);
	vg->uuid_len = LP_ID_SIZE;
	vg->extent_size = 1;
	grub_memcpy (pv->id.uuid, id, LP_ID_SIZE);
	pv->id.uuidlen = LP_ID_SIZE;
	vg->pvs = pv;
	pv = NULL;
	lv_tail = &vg->lvs;

	for (i = 0; i < metadata->partitions.count; i++)
	{
		const grub_uint8_t *part = lp_entry (metadata, &metadata->partitions, i);
		grub_uint32_t attributes = lp_get32 (part + 36);
		grub_uint32_t first = lp_get32 (part + 40);
		grub_uint32_t count = lp_get32 (part + 44);
		grub_uint32_t group = lp_get32 (part + 48);
		struct grub_diskfilter_lv *lv;
		struct grub_diskfilter_lv *other;
		grub_uint64_t logical = 0;
		grub_uint32_t j;

		if (first > metadata->extents.count
			|| count > metadata->extents.count - first
			|| group >= metadata->groups.count)
			goto fail;
		lv = grub_zalloc (sizeof (*lv));
		if (!lv)
			goto fail;
		lv->name = lp_partition_name (part, attributes, metadata->slot);
		if (!lv->name)
		{
			lp_free_lv (lv);
			goto fail;
		}
		for (other = vg->lvs; other; other = other->next)
			if (grub_strcmp (other->name, lv->name) == 0)
			{
				lp_free_lv (lv);
				goto fail;
			}
		lv->fullname = grub_xasprintf ("lp/%s-%s", vg->name, lv->name);
		lv->segments = count ? grub_calloc (count, sizeof (*lv->segments)) : NULL;
		lv->segment_count = count;
		lv->segment_alloc = count;
		if (!lv->fullname || (count && !lv->segments))
		{
			lp_free_lv (lv);
			goto fail;
		}
		lv->vg = vg;
		lv->visible = !(attributes & LP_PARTITION_ATTR_DISABLED);

		for (j = 0; j < count; j++)
		{
			const grub_uint8_t *extent = lp_entry (metadata,
				&metadata->extents, first + j);
			grub_uint64_t sectors = lp_get64 (extent);
			grub_uint32_t type = lp_get32 (extent + 8);
			struct grub_diskfilter_segment *segment = &lv->segments[j];

			if (sectors > LP_UINT64_MAX - logical)
			{
				lp_free_lv (lv);
				goto fail;
			}
			segment->start_extent = logical;
			segment->extent_count = sectors;
			if (type == LP_TARGET_LINEAR)
			{
				segment->type = GRUB_DISKFILTER_STRIPED;
				segment->node_count = 1;
				segment->nodes = grub_zalloc (sizeof (*segment->nodes));
				if (!segment->nodes)
				{
					lp_free_lv (lv);
					goto fail;
				}
				segment->nodes[0].pv = vg->pvs;
				segment->nodes[0].start = lp_get64 (extent + 12);
			}
			else
				segment->type = GRUB_DISKFILTER_ZERO;
			logical += sectors;
		}
		lv->size = logical;
		*lv_tail = lv;
		lv_tail = &lv->next;
	}
	return vg;

fail:
	if (pv)
	{
		grub_free (pv->id.uuid);
		grub_free (pv->name);
		grub_free (pv);
	}
	lp_free_vg (vg);
	return NULL;
}

static struct grub_diskfilter_vg *
grub_lp_detect (grub_disk_t disk, struct grub_diskfilter_pv_id *detect_id,
	grub_disk_addr_t *start_sector)
{
	struct lp_geometry geometry;
	struct lp_metadata metadata;
	struct grub_diskfilter_vg *vg;
	grub_uint8_t id[LP_ID_SIZE];

	grub_memset (&metadata, 0, sizeof (metadata));
	if (!lp_read_geometry (disk, &geometry))
		return NULL;
	if (!lp_read_metadata (disk, &geometry, &metadata))
		return NULL;
	lp_make_id (disk, id);
	vg = grub_diskfilter_get_vg_by_uuid (LP_ID_SIZE, (char *) id);
	if (!vg)
	{
		vg = lp_build_vg (disk, &geometry, &metadata, id);
		if (!vg)
		{
			grub_free (metadata.buf);
			if (grub_errno == GRUB_ERR_NONE)
				grub_error (GRUB_ERR_BAD_FS, "invalid Android LP metadata tables");
			return NULL;
		}
		if (grub_diskfilter_vg_register (vg))
		{
			lp_free_vg (vg);
			grub_free (metadata.buf);
			return NULL;
		}
	}
	grub_free (metadata.buf);
	if (!lp_set_detect_id (detect_id, id))
		return NULL;
	*start_sector = (grub_disk_addr_t) -1;
	return vg;
}

static struct grub_diskfilter grub_lp_dev =
{
	.name = "lp",
	.detect = grub_lp_detect,
	.next = 0
};

GRUB_MOD_INIT (lp)
{
	grub_diskfilter_register_back (&grub_lp_dev);
}

GRUB_MOD_FINI (lp)
{
	grub_diskfilter_unregister (&grub_lp_dev);
}
