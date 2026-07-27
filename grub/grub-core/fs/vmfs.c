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
 * VMFS (VMware vSphere VMFS3 / VMFS5) read-only driver.
 *
 * On-disk layout follows vmfs-tools (libvmfs), which reverse engineered
 * the format.  A VMFS partition (MBR type 0xfb) starts with the volume
 * header at 0x100000, holding the LVM information: a logical volume is
 * the concatenation of one or more extents, each contributing a range of
 * 256 MiB segments identified by a shared LVM UUID.  All volume-relative
 * offsets below are translated to extent-relative ones and shifted by
 * another 0x1000000 bytes, exactly like vmfs_vol_read() does.
 *
 * The filesystem header sits at volume offset 0x200000 and gives the
 * block size plus the volume label / UUID.  Everything else lives in
 * four meta files in the root directory (.fbb.sf, .fdc.sf, .pbc.sf and
 * .sbc.sf); each is a "bitmap": a header, then areas of 1 KiB allocation
 * entries followed by that area's fixed-size items.  Inodes are the
 * items of .fdc.sf, pointer blocks those of .pbc.sf and sub-blocks those
 * of .sbc.sf; file blocks are raw volume space addressed by index.  A
 * block ID packs the item and entry numbers plus a 3-bit type tag, and
 * an inode's "zla" field says which block type its 256 block slots hold
 * (VMFS5 adds 4301 to it, and 4301+FD means the data is stored inline in
 * the inode itself).
 *
 * Bootstrapping is circular: reading any inode needs .fdc.sf, which is
 * itself a file described by an inode.  The way out (again from
 * vmfs-tools) is that .fdc.sf always begins in the first block past the
 * heartbeat area, so a synthetic one-block inode is enough to reach the
 * root directory and from there the real meta files.
 *
 * Limitations: read-only, no RDM (raw device mapping) pass-through, and
 * .fbb.sf is never opened because file blocks are read straight off the
 * volume.  Only VMFS3 and VMFS5 are recognised (VMFS6 has a different
 * layout).  Extents of a spanned volume are located by scanning all
 * devices for a matching LVM UUID.
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/device.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fs.h>
#include <grub/fshelp.h>

GRUB_MOD_LICENSE("GPLv2+");

/* === volume header (extent relative) === */
#define VMFS_VOLINFO_BASE		0x100000
#define VMFS_VOLINFO_MAGIC		0xc001d00d
#define VMFS_VOLINFO_LEN		0x300

#define VMFS_VOLINFO_OFS_MAGIC		0
#define VMFS_VOLINFO_OFS_VER		4
#define VMFS_VOLINFO_OFS_NAME		18
#define VMFS_VOLINFO_NAME_LEN		28

/* LVM information, at 0x200 inside the volume header */
#define VMFS_LVMINFO_OFS_UUID		0x254
#define VMFS_LVMINFO_OFS_NUM_SEGMENTS	0x274
#define VMFS_LVMINFO_OFS_FIRST_SEGMENT	0x278
#define VMFS_LVMINFO_OFS_LAST_SEGMENT	0x280
#define VMFS_LVMINFO_OFS_NUM_EXTENTS	0x290

#define VMFS_LVM_SEGMENT_SIZE		0x10000000ULL	/* 256 MiB */
#define VMFS_LVM_MAX_EXTENTS		32

/* volume offset 0 maps here inside its extent */
#define VMFS_VOLUME_DATA_BASE		(VMFS_VOLINFO_BASE + 0x1000000)

/* === filesystem header (volume relative) === */
#define VMFS_FSINFO_BASE		0x200000
#define VMFS_FSINFO_MAGIC		0x2fabf15e
#define VMFS_FSINFO_LEN			512

#define VMFS_FSINFO_OFS_MAGIC		0
#define VMFS_FSINFO_OFS_UUID		9
#define VMFS_FSINFO_OFS_LABEL		29
#define VMFS_FSINFO_LABEL_LEN		128
#define VMFS_FSINFO_OFS_BLKSIZE		161
#define VMFS_FSINFO_OFS_LVM_UUID	177

/* === heartbeat area (volume relative), .fdc.sf starts right after === */
#define VMFS_HB_BASE			0x300000
#define VMFS_HB_SIZE			0x200
#define VMFS_HB_NUM			2048

/* === metadata header, shared prefix of inodes and bitmap entries === */
#define VMFS_MDH_OFS_MAGIC		0

/* === bitmaps === */
#define VMFS_BITMAP_HDR_LEN		512
#define VMFS_BITMAP_ENTRY_SIZE		0x400

#define VMFS_BMH_OFS_ITEMS_PER_ENTRY	0x00
#define VMFS_BMH_OFS_ENTRIES_PER_AREA	0x04
#define VMFS_BMH_OFS_HDR_SIZE		0x08
#define VMFS_BMH_OFS_DATA_SIZE		0x0c
#define VMFS_BMH_OFS_AREA_SIZE		0x10
#define VMFS_BMH_OFS_TOTAL_ITEMS	0x14
#define VMFS_BMH_OFS_AREA_COUNT		0x18

/* === inodes (items of .fdc.sf) === */
#define VMFS_INODE_SIZE			0x800
#define VMFS_INODE_MAGIC		0x10c00001
#define VMFS_INODE_BLK_COUNT		0x100

#define VMFS_INODE_OFS_ID		512
#define VMFS_INODE_OFS_TYPE		524
#define VMFS_INODE_OFS_SIZE		532
#define VMFS_INODE_OFS_BLK_SIZE		540
#define VMFS_INODE_OFS_MTIME		556
#define VMFS_INODE_OFS_ZLA		580
#define VMFS_INODE_OFS_BLK_ARRAY	1024

/* size of the block array, doubling as the inline data area */
#define VMFS_INODE_CONTENT_LEN		(VMFS_INODE_BLK_COUNT * 4)

/* file types, in inodes and directory records alike */
#define VMFS_FILE_TYPE_DIR		0x02
#define VMFS_FILE_TYPE_FILE		0x03
#define VMFS_FILE_TYPE_SYMLINK		0x04
#define VMFS_FILE_TYPE_META		0x05
#define VMFS_FILE_TYPE_RDM		0x06

/* VMFS5 offsets the zla field of an inode by this much */
#define VMFS5_ZLA_BASE			4301

/* === directory records === */
#define VMFS_DIRENT_SIZE		0x8c
#define VMFS_DIRENT_OFS_TYPE		0
#define VMFS_DIRENT_OFS_BLK_ID		4
#define VMFS_DIRENT_OFS_NAME		12
#define VMFS_DIRENT_NAME_LEN		128

/* directory records read per disk round trip */
#define VMFS_DIRENT_BATCH		32

/* the meta files, all in the root directory */
#define VMFS_FDC_FILENAME		".fdc.sf"
#define VMFS_PBC_FILENAME		".pbc.sf"
#define VMFS_SBC_FILENAME		".sbc.sf"

/* longest symlink target we are willing to allocate */
#define VMFS_SYMLINK_MAX		4096

/* === block IDs === */
#define VMFS_BLK_TYPE_NONE		0
#define VMFS_BLK_TYPE_FB		1	/* file block */
#define VMFS_BLK_TYPE_SB		2	/* sub-block */
#define VMFS_BLK_TYPE_PB		3	/* pointer block */
#define VMFS_BLK_TYPE_FD		4	/* file descriptor (inode) */

#define VMFS_BLK_TYPE(id)	((id) & 0x7)

#define VMFS_BLK_FB_ITEM(id)	(((id) & 0xffffffc0u) >> 6)
#define VMFS_BLK_FB_TBZ(id)	((((id) & 0x38u) >> 3) & 0x4u)
#define VMFS_BLK_FB_BUILD(item)	((((item) << 6) & 0xffffffc0u) | VMFS_BLK_TYPE_FB)

#define VMFS_BLK_SB_ENTRY(id)	(((id) & 0x0fffffc0u) >> 6)
#define VMFS_BLK_SB_ITEM(id)	((((id) >> 28) & 0xfu) | ((((id) >> 3) & 0x3u) << 4))

#define VMFS_BLK_PB_ENTRY(id)	(((id) & 0x0fffffc0u) >> 6)
#define VMFS_BLK_PB_ITEM(id)	(((id) & 0xf0000000u) >> 28)

#define VMFS_BLK_FD_ENTRY(id)	(((id) & 0x003fffc0u) >> 6)
#define VMFS_BLK_FD_ITEM(id)	(((id) & 0xffc00000u) >> 22)
#define VMFS_BLK_FD_ROOT	VMFS_BLK_TYPE_FD	/* entry 0, item 0 */

struct grub_vmfs_data;

/* an in-core inode; also the fshelp node handed out by the directory
   iterator */
struct grub_fshelp_node
{
	struct grub_vmfs_data *data;
	grub_uint32_t id;			/* its own FD block ID */
	grub_uint32_t type;			/* VMFS_FILE_TYPE_* */
	grub_uint32_t zla;			/* type of the block slots */
	grub_uint64_t size;
	grub_uint64_t blk_size;
	grub_int32_t mtime;
	/* raw block array, or the inline data for a 4301+FD zla */
	grub_uint8_t blocks[VMFS_INODE_CONTENT_LEN];
};

/* one physical volume backing a range of the logical volume */
struct grub_vmfs_extent
{
	grub_disk_t disk;
	int own;				/* we opened it, we close it */
	grub_uint32_t first_segment;
	grub_uint32_t last_segment;
};

/* an opened meta file */
struct grub_vmfs_bitmap
{
	struct grub_fshelp_node *inode;
	grub_uint32_t items_per_entry;
	grub_uint32_t entries_per_area;
	grub_uint32_t hdr_size;
	grub_uint32_t data_size;
	grub_uint32_t area_size;
	grub_uint32_t total_items;
	grub_uint32_t area_count;
};

struct grub_vmfs_data
{
	struct grub_vmfs_extent extents[VMFS_LVM_MAX_EXTENTS];
	grub_uint32_t nextents;

	grub_uint64_t blocksize;
	grub_uint8_t uuid[16];
	char label[VMFS_FSINFO_LABEL_LEN + 1];

	struct grub_vmfs_bitmap fdc, pbc, sbc;
	int have_pbc, have_sbc;

	struct grub_fshelp_node root;
	struct grub_fshelp_node fdc_inode;
	struct grub_fshelp_node pbc_inode;
	struct grub_fshelp_node sbc_inode;
};

/* volume header fields needed to assemble the logical volume */
struct grub_vmfs_volinfo
{
	grub_uint32_t version;
	grub_uint32_t first_segment;
	grub_uint32_t last_segment;
	grub_uint32_t num_extents;
	grub_uint8_t lvm_uuid[16];
	char name[VMFS_VOLINFO_NAME_LEN + 1];
};

static grub_uint32_t
vmfs_get32(const grub_uint8_t *p, grub_uint32_t off)
{
	return grub_le_to_cpu32(grub_get_unaligned32(p + off));
}

static grub_uint64_t
vmfs_get64(const grub_uint8_t *p, grub_uint32_t off)
{
	return grub_le_to_cpu64(grub_get_unaligned64(p + off));
}

/* Read LEN bytes at volume offset POS, crossing extents as needed. */
static grub_err_t
grub_vmfs_dev_read(struct grub_vmfs_data *data, grub_uint64_t pos,
	grub_size_t len, void *buf)
{
	grub_uint8_t *out = buf;

	while (len > 0)
	{
		const struct grub_vmfs_extent *ext = NULL;
		grub_uint64_t seg = pos / VMFS_LVM_SEGMENT_SIZE;
		grub_uint64_t end, take;
		grub_uint32_t i;

		for (i = 0; i < data->nextents; i++)
			if (seg >= data->extents[i].first_segment
				&& seg <= data->extents[i].last_segment)
			{
				ext = &data->extents[i];
				break;
			}
		if (!ext)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: no extent holds offset 0x%llx",
				(unsigned long long) pos);

		end = ((grub_uint64_t) ext->last_segment + 1)
			* VMFS_LVM_SEGMENT_SIZE;
		take = end - pos;
		if (take > len)
			take = len;

		if (grub_disk_read(ext->disk, 0,
			pos - (grub_uint64_t) ext->first_segment
				* VMFS_LVM_SEGMENT_SIZE
				+ VMFS_VOLUME_DATA_BASE,
			(grub_size_t) take, out))
			return grub_errno;

		pos += take;
		out += take;
		len -= (grub_size_t) take;
	}
	return GRUB_ERR_NONE;
}

/* Offset of a bitmap item inside its meta file. */
static grub_err_t
grub_vmfs_item_pos(const struct grub_vmfs_bitmap *bmp, grub_uint32_t entry,
	grub_uint32_t item, grub_uint64_t *pos)
{
	grub_uint64_t items_per_area, addr, area;

	items_per_area = (grub_uint64_t) bmp->entries_per_area
		* bmp->items_per_entry;
	addr = (grub_uint64_t) entry * bmp->items_per_entry + item;
	area = addr / items_per_area;

	if (addr >= bmp->total_items || area >= bmp->area_count)
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: bitmap item 0x%llx is out of range",
			(unsigned long long) addr);

	*pos = (grub_uint64_t) bmp->hdr_size + area * bmp->area_size;
	*pos += (grub_uint64_t) bmp->entries_per_area * VMFS_BITMAP_ENTRY_SIZE;
	*pos += (addr % items_per_area) * bmp->data_size;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_vmfs_read_file(struct grub_fshelp_node *node, grub_uint64_t pos,
	grub_size_t len, void *buf);

/* Read one whole item of BMP into BUF (bmp->data_size bytes). */
static grub_err_t
grub_vmfs_get_item(struct grub_vmfs_bitmap *bmp, grub_uint32_t entry,
	grub_uint32_t item, void *buf)
{
	grub_uint64_t pos;

	if (grub_vmfs_item_pos(bmp, entry, item, &pos))
		return grub_errno;
	return grub_vmfs_read_file(bmp->inode, pos, bmp->data_size, buf);
}

/*
 * Resolve the block ID holding volume file offset POS.  ZLA is the
 * inode's block type with the VMFS5 bias already removed; PB_BUF is a
 * scratch buffer of pbc.data_size bytes, only touched for pointer
 * blocks.  A zero block ID means the block is not allocated.
 */
static grub_err_t
grub_vmfs_get_block(struct grub_fshelp_node *node, grub_uint64_t pos,
	grub_uint32_t zla, grub_uint8_t *pb_buf, grub_uint32_t *blk_id)
{
	struct grub_vmfs_data *data = node->data;
	grub_uint64_t blk_index = pos / node->blk_size;

	*blk_id = 0;
	switch (zla)
	{
	case VMFS_BLK_TYPE_FB:
	case VMFS_BLK_TYPE_SB:
		if (blk_index >= VMFS_INODE_BLK_COUNT)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: block index out of range");
		*blk_id = vmfs_get32(node->blocks,
			(grub_uint32_t) blk_index * 4);
		break;

	case VMFS_BLK_TYPE_PB:
	{
		grub_uint32_t blk_per_pb = data->pbc.data_size / 4;
		grub_uint64_t pb_index = blk_index / blk_per_pb;
		grub_uint32_t sub_index =
			(grub_uint32_t) (blk_index % blk_per_pb);
		grub_uint32_t pb_blk;

		if (pb_index >= VMFS_INODE_BLK_COUNT)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: pointer block index out of range");
		pb_blk = vmfs_get32(node->blocks,
			(grub_uint32_t) pb_index * 4);
		if (!pb_blk)
			break;
		if (VMFS_BLK_TYPE(pb_blk) != VMFS_BLK_TYPE_PB)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: bad pointer block 0x%x", pb_blk);
		if (grub_vmfs_get_item(&data->pbc, VMFS_BLK_PB_ENTRY(pb_blk),
			VMFS_BLK_PB_ITEM(pb_blk), pb_buf))
			return grub_errno;
		*blk_id = vmfs_get32(pb_buf, sub_index * 4);
		break;
	}

	default:
		/* only reached for an inline (VMFS5 4301+FD) inode */
		*blk_id = node->id;
		break;
	}
	return GRUB_ERR_NONE;
}

/* Read LEN bytes of NODE's contents starting at POS. */
static grub_err_t
grub_vmfs_read_file(struct grub_fshelp_node *node, grub_uint64_t pos,
	grub_size_t len, void *buf)
{
	struct grub_vmfs_data *data = node->data;
	grub_uint8_t *out = buf;
	grub_uint8_t *sb_buf = NULL;
	grub_uint8_t *pb_buf = NULL;
	grub_uint32_t zla = node->zla;
	int inline_data = 0;

	if (node->type == VMFS_FILE_TYPE_RDM)
		return grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
			"vmfs: raw device mappings are not supported");
	if (!node->blk_size)
		return grub_error(GRUB_ERR_BAD_FS, "vmfs: inode has no block size");
	if (pos > node->size || len > node->size - pos)
		return grub_error(GRUB_ERR_OUT_OF_RANGE, "read past end of file");
	if (len == 0)
		return GRUB_ERR_NONE;

	if (zla >= VMFS5_ZLA_BASE)
	{
		zla -= VMFS5_ZLA_BASE;
		inline_data = (zla == VMFS_BLK_TYPE_FD);
	}

	switch (zla)
	{
	case VMFS_BLK_TYPE_FB:
		break;

	case VMFS_BLK_TYPE_SB:
		if (!data->have_sbc || !data->sbc.data_size)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: sub-block bitmap is unavailable");
		sb_buf = grub_malloc(data->sbc.data_size);
		if (!sb_buf)
			return grub_errno;
		break;

	case VMFS_BLK_TYPE_PB:
		if (!data->have_pbc || data->pbc.data_size < 4)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: pointer block bitmap is unavailable");
		pb_buf = grub_malloc(data->pbc.data_size);
		if (!pb_buf)
			return grub_errno;
		break;

	default:
		if (!inline_data)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: unsupported inode layout %u", node->zla);
		break;
	}

	while (len > 0)
	{
		grub_uint32_t blk_id, blk_type;
		grub_uint64_t off;
		grub_size_t take;

		if (grub_vmfs_get_block(node, pos, zla, pb_buf, &blk_id))
			goto fail;

		blk_type = VMFS_BLK_TYPE(blk_id);
		if (blk_type == VMFS_BLK_TYPE_FB && VMFS_BLK_FB_TBZ(blk_id))
			blk_type = VMFS_BLK_TYPE_NONE;
		if (inline_data)
			blk_type = VMFS_BLK_TYPE_FD;

		switch (blk_type)
		{
		/* not allocated: reads as zeroes */
		case VMFS_BLK_TYPE_NONE:
			off = pos % node->blk_size;
			take = (grub_size_t) (node->blk_size - off);
			if (take > len)
				take = len;
			grub_memset(out, 0, take);
			break;

		case VMFS_BLK_TYPE_FB:
			off = pos % data->blocksize;
			take = (grub_size_t) (data->blocksize - off);
			if (take > len)
				take = len;
			if (grub_vmfs_dev_read(data,
				(grub_uint64_t) VMFS_BLK_FB_ITEM(blk_id)
					* data->blocksize + off,
				take, out))
				goto fail;
			break;

		case VMFS_BLK_TYPE_SB:
			if (!sb_buf)
			{
				grub_error(GRUB_ERR_BAD_FS,
					"vmfs: unexpected sub-block 0x%x",
					blk_id);
				goto fail;
			}
			off = pos % data->sbc.data_size;
			take = (grub_size_t) (data->sbc.data_size - off);
			if (take > len)
				take = len;
			if (grub_vmfs_get_item(&data->sbc,
				VMFS_BLK_SB_ENTRY(blk_id),
				VMFS_BLK_SB_ITEM(blk_id), sb_buf))
				goto fail;
			grub_memcpy(out, sb_buf + (grub_size_t) off, take);
			break;

		/* stored inline in the inode itself */
		case VMFS_BLK_TYPE_FD:
			if (!inline_data || pos >= VMFS_INODE_CONTENT_LEN)
			{
				grub_error(GRUB_ERR_BAD_FS,
					"vmfs: unexpected file descriptor 0x%x",
					blk_id);
				goto fail;
			}
			take = VMFS_INODE_CONTENT_LEN - (grub_size_t) pos;
			if (take > len)
				take = len;
			grub_memcpy(out, node->blocks + (grub_size_t) pos, take);
			break;

		default:
			grub_error(GRUB_ERR_BAD_FS,
				"vmfs: unknown block type %u", blk_type);
			goto fail;
		}

		pos += take;
		out += take;
		len -= take;
	}

	grub_free(sb_buf);
	grub_free(pb_buf);
	return GRUB_ERR_NONE;

fail:
	grub_free(sb_buf);
	grub_free(pb_buf);
	return grub_errno;
}

/* Read the inode addressed by BLK_ID through the .fdc.sf bitmap. */
static grub_err_t
grub_vmfs_read_inode(struct grub_vmfs_data *data, grub_uint32_t blk_id,
	struct grub_fshelp_node *node)
{
	grub_uint8_t *raw;
	grub_uint64_t pos;

	if (VMFS_BLK_TYPE(blk_id) != VMFS_BLK_TYPE_FD)
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: 0x%x is not a file descriptor", blk_id);
	if (data->fdc.data_size < VMFS_INODE_SIZE)
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: file descriptors are too small");
	if (grub_vmfs_item_pos(&data->fdc, VMFS_BLK_FD_ENTRY(blk_id),
		VMFS_BLK_FD_ITEM(blk_id), &pos))
		return grub_errno;

	raw = grub_malloc(VMFS_INODE_SIZE);
	if (!raw)
		return grub_errno;

	if (grub_vmfs_read_file(data->fdc.inode, pos, VMFS_INODE_SIZE, raw))
		goto fail;
	if (vmfs_get32(raw, VMFS_MDH_OFS_MAGIC) != VMFS_INODE_MAGIC)
	{
		grub_error(GRUB_ERR_BAD_FS, "vmfs: bad inode magic");
		goto fail;
	}

	node->data = data;
	node->id = vmfs_get32(raw, VMFS_INODE_OFS_ID);
	node->type = vmfs_get32(raw, VMFS_INODE_OFS_TYPE);
	node->zla = vmfs_get32(raw, VMFS_INODE_OFS_ZLA);
	node->size = vmfs_get64(raw, VMFS_INODE_OFS_SIZE);
	node->blk_size = vmfs_get64(raw, VMFS_INODE_OFS_BLK_SIZE);
	node->mtime = (grub_int32_t) vmfs_get32(raw, VMFS_INODE_OFS_MTIME);
	grub_memcpy(node->blocks, raw + VMFS_INODE_OFS_BLK_ARRAY,
		sizeof(node->blocks));

	grub_free(raw);
	return GRUB_ERR_NONE;

fail:
	grub_free(raw);
	return grub_errno;
}

/* Read a meta file's bitmap header and attach it to INODE. */
static grub_err_t
grub_vmfs_bitmap_open(struct grub_vmfs_bitmap *bmp,
	struct grub_fshelp_node *inode)
{
	grub_uint8_t hdr[VMFS_BITMAP_HDR_LEN];

	bmp->inode = inode;
	if (grub_vmfs_read_file(inode, 0, sizeof(hdr), hdr))
		return grub_errno;

	bmp->items_per_entry = vmfs_get32(hdr, VMFS_BMH_OFS_ITEMS_PER_ENTRY);
	bmp->entries_per_area = vmfs_get32(hdr, VMFS_BMH_OFS_ENTRIES_PER_AREA);
	bmp->hdr_size = vmfs_get32(hdr, VMFS_BMH_OFS_HDR_SIZE);
	bmp->data_size = vmfs_get32(hdr, VMFS_BMH_OFS_DATA_SIZE);
	bmp->area_size = vmfs_get32(hdr, VMFS_BMH_OFS_AREA_SIZE);
	bmp->total_items = vmfs_get32(hdr, VMFS_BMH_OFS_TOTAL_ITEMS);
	bmp->area_count = vmfs_get32(hdr, VMFS_BMH_OFS_AREA_COUNT);

	if (!bmp->items_per_entry || !bmp->entries_per_area || !bmp->data_size)
		return grub_error(GRUB_ERR_BAD_FS, "vmfs: bad bitmap header");
	return GRUB_ERR_NONE;
}

/*
 * Feed every directory record of DIR to HOOK, which returns non-zero to
 * stop.  Read errors abort the walk with grub_errno set.
 */
static void
grub_vmfs_scan_dir(struct grub_fshelp_node *dir,
	int (*hook) (const grub_uint8_t *rec, void *data), void *hook_data)
{
	grub_uint8_t *chunk;
	grub_uint64_t pos = 0;

	chunk = grub_malloc(VMFS_DIRENT_SIZE * VMFS_DIRENT_BATCH);
	if (!chunk)
		return;

	while (dir->size - pos >= VMFS_DIRENT_SIZE)
	{
		grub_uint64_t left = dir->size - pos;
		grub_uint32_t i, n;
		grub_size_t got;

		n = VMFS_DIRENT_BATCH;
		if (left / VMFS_DIRENT_SIZE < n)
			n = (grub_uint32_t) (left / VMFS_DIRENT_SIZE);
		got = (grub_size_t) n * VMFS_DIRENT_SIZE;

		if (grub_vmfs_read_file(dir, pos, got, chunk))
			break;

		for (i = 0; i < n; i++)
			if (hook(chunk + i * VMFS_DIRENT_SIZE, hook_data))
				goto done;
		pos += got;
	}

done:
	grub_free(chunk);
}

/* context for grub_vmfs_lookup_rec */
struct grub_vmfs_lookup_ctx
{
	const char *name;
	grub_uint32_t blk_id;
};

static int
grub_vmfs_lookup_rec(const grub_uint8_t *rec, void *ctx_in)
{
	struct grub_vmfs_lookup_ctx *ctx = ctx_in;
	char name[VMFS_DIRENT_NAME_LEN + 1];

	grub_memcpy(name, rec + VMFS_DIRENT_OFS_NAME, VMFS_DIRENT_NAME_LEN);
	name[VMFS_DIRENT_NAME_LEN] = '\0';
	if (grub_strcmp(name, ctx->name) != 0)
		return 0;

	ctx->blk_id = vmfs_get32(rec, VMFS_DIRENT_OFS_BLK_ID);
	return 1;
}

/*
 * Look up NAME in the root directory by name only.  The meta files are
 * opened this way during mount, when reading the inode of every record
 * is neither possible nor needed.
 */
static grub_err_t
grub_vmfs_lookup_meta(struct grub_vmfs_data *data, const char *name,
	grub_uint32_t *blk_id)
{
	struct grub_vmfs_lookup_ctx ctx = { name, 0 };

	grub_vmfs_scan_dir(&data->root, grub_vmfs_lookup_rec, &ctx);
	if (grub_errno)
		return grub_errno;
	if (!ctx.blk_id)
		return grub_error(GRUB_ERR_BAD_FS, "vmfs: %s is missing", name);

	*blk_id = ctx.blk_id;
	return GRUB_ERR_NONE;
}

/* context for grub_vmfs_iter_rec */
struct grub_vmfs_iter_ctx
{
	struct grub_vmfs_data *data;
	grub_fshelp_iterate_dir_hook_t hook;
	void *hook_data;
	int stop;
};

static int
grub_vmfs_iter_rec(const grub_uint8_t *rec, void *ctx_in)
{
	struct grub_vmfs_iter_ctx *ctx = ctx_in;
	struct grub_fshelp_node *node;
	char name[VMFS_DIRENT_NAME_LEN + 1];
	enum grub_fshelp_filetype type;
	grub_uint32_t blk_id;

	blk_id = vmfs_get32(rec, VMFS_DIRENT_OFS_BLK_ID);
	grub_memcpy(name, rec + VMFS_DIRENT_OFS_NAME, VMFS_DIRENT_NAME_LEN);
	name[VMFS_DIRENT_NAME_LEN] = '\0';

	/* fshelp resolves "." and ".." on its own */
	if (!blk_id || !name[0] || grub_strcmp(name, ".") == 0
		|| grub_strcmp(name, "..") == 0)
		return 0;

	node = grub_malloc(sizeof(*node));
	if (!node)
		return 1;
	if (grub_vmfs_read_inode(ctx->data, blk_id, node))
	{
		/* a damaged record must not hide the rest of the listing */
		grub_errno = GRUB_ERR_NONE;
		grub_free(node);
		return 0;
	}

	switch (node->type)
	{
	case VMFS_FILE_TYPE_DIR:
		type = GRUB_FSHELP_DIR;
		break;
	case VMFS_FILE_TYPE_SYMLINK:
		type = GRUB_FSHELP_SYMLINK;
		break;
	default:
		/* meta files and raw device mappings show up as plain
		   files, the way vmfs_file_type2mode() reports them */
		type = GRUB_FSHELP_REG;
		break;
	}

	if (ctx->hook(name, type, node, ctx->hook_data))
	{
		ctx->stop = 1;
		return 1;
	}
	return 0;
}

static int
grub_vmfs_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_vmfs_iter_ctx ctx;

	if (dir->type != VMFS_FILE_TYPE_DIR)
	{
		grub_error(GRUB_ERR_BAD_FILE_TYPE, "not a directory");
		return 0;
	}

	ctx.data = dir->data;
	ctx.hook = hook;
	ctx.hook_data = hook_data;
	ctx.stop = 0;
	grub_vmfs_scan_dir(dir, grub_vmfs_iter_rec, &ctx);
	return ctx.stop;
}

static char *
grub_vmfs_read_symlink(grub_fshelp_node_t node)
{
	char *target;

	if (node->size > VMFS_SYMLINK_MAX)
	{
		grub_error(GRUB_ERR_BAD_FS, "vmfs: symlink target is too long");
		return NULL;
	}

	target = grub_malloc((grub_size_t) node->size + 1);
	if (!target)
		return NULL;
	if (node->size
		&& grub_vmfs_read_file(node, 0, (grub_size_t) node->size, target))
	{
		grub_free(target);
		return NULL;
	}
	target[(grub_size_t) node->size] = '\0';
	return target;
}

/* Read and validate the volume header of DISK. */
static grub_err_t
grub_vmfs_read_volinfo(grub_disk_t disk, struct grub_vmfs_volinfo *vi)
{
	grub_uint8_t buf[VMFS_VOLINFO_LEN];

	if (grub_disk_read(disk, 0, VMFS_VOLINFO_BASE, sizeof(buf), buf))
		return grub_errno;
	if (vmfs_get32(buf, VMFS_VOLINFO_OFS_MAGIC) != VMFS_VOLINFO_MAGIC)
		return grub_error(GRUB_ERR_BAD_FS, "not a vmfs volume");

	vi->version = vmfs_get32(buf, VMFS_VOLINFO_OFS_VER);
	if (vi->version != 3 && vi->version != 5)
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: unsupported version %u", vi->version);

	vi->first_segment = vmfs_get32(buf, VMFS_LVMINFO_OFS_FIRST_SEGMENT);
	vi->last_segment = vmfs_get32(buf, VMFS_LVMINFO_OFS_LAST_SEGMENT);
	vi->num_extents = vmfs_get32(buf, VMFS_LVMINFO_OFS_NUM_EXTENTS);
	grub_memcpy(vi->lvm_uuid, buf + VMFS_LVMINFO_OFS_UUID,
		sizeof(vi->lvm_uuid));
	grub_memcpy(vi->name, buf + VMFS_VOLINFO_OFS_NAME,
		VMFS_VOLINFO_NAME_LEN);
	vi->name[VMFS_VOLINFO_NAME_LEN] = '\0';

	if (vi->last_segment < vi->first_segment)
		return grub_error(GRUB_ERR_BAD_FS, "vmfs: bad segment range");
	return GRUB_ERR_NONE;
}

/* context for grub_vmfs_scan_extent */
struct grub_vmfs_scan_ctx
{
	struct grub_vmfs_data *data;
	const grub_uint8_t *lvm_uuid;
	grub_uint32_t num_extents;
};

/* Collect the extents of a spanned volume, ordered by starting segment. */
static int
grub_vmfs_scan_extent(const char *name, void *ctx_in)
{
	struct grub_vmfs_scan_ctx *ctx = ctx_in;
	struct grub_vmfs_data *data = ctx->data;
	struct grub_vmfs_volinfo vi;
	grub_disk_t disk;
	grub_uint32_t i;

	if (data->nextents >= ctx->num_extents)
		return 1;

	disk = grub_disk_open(name);
	if (!disk)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}

	if (grub_vmfs_read_volinfo(disk, &vi)
		|| vi.num_extents != ctx->num_extents
		|| grub_memcmp(vi.lvm_uuid, ctx->lvm_uuid, 16) != 0)
		goto skip;

	/* our own disk comes back from the scan as well */
	for (i = 0; i < data->nextents; i++)
		if (data->extents[i].first_segment == vi.first_segment)
			goto skip;

	for (i = data->nextents; i > 0; i--)
	{
		if (data->extents[i - 1].first_segment < vi.first_segment)
			break;
		data->extents[i] = data->extents[i - 1];
	}
	data->extents[i].disk = disk;
	data->extents[i].own = 1;
	data->extents[i].first_segment = vi.first_segment;
	data->extents[i].last_segment = vi.last_segment;
	data->nextents++;
	return 0;

skip:
	grub_errno = GRUB_ERR_NONE;
	grub_disk_close(disk);
	return 0;
}

static void
grub_vmfs_unmount(struct grub_vmfs_data *data)
{
	grub_uint32_t i;

	if (!data)
		return;
	for (i = 0; i < data->nextents; i++)
		if (data->extents[i].own)
			grub_disk_close(data->extents[i].disk);
	grub_free(data);
}

static struct grub_vmfs_data *
grub_vmfs_mount(grub_disk_t disk)
{
	struct grub_vmfs_data *data;
	struct grub_vmfs_volinfo vi;
	struct grub_fshelp_node *tmp = NULL;
	grub_uint8_t fsi[VMFS_FSINFO_LEN];
	grub_uint32_t fdc_base, blk_id;

	if (grub_vmfs_read_volinfo(disk, &vi))
		return NULL;
	if (vi.num_extents == 0 || vi.num_extents > VMFS_LVM_MAX_EXTENTS)
	{
		grub_error(GRUB_ERR_BAD_FS, "vmfs: bad extent count %u",
			vi.num_extents);
		return NULL;
	}

	data = grub_zalloc(sizeof(*data));
	if (!data)
		return NULL;

	data->extents[0].disk = disk;
	data->extents[0].first_segment = vi.first_segment;
	data->extents[0].last_segment = vi.last_segment;
	data->nextents = 1;

	/* a spanned volume needs every extent that carries its LVM UUID */
	if (vi.num_extents > 1)
	{
		struct grub_vmfs_scan_ctx ctx;

		ctx.data = data;
		ctx.lvm_uuid = vi.lvm_uuid;
		ctx.num_extents = vi.num_extents;
		grub_device_iterate(grub_vmfs_scan_extent, &ctx);
		grub_errno = GRUB_ERR_NONE;

		if (data->nextents != vi.num_extents)
		{
			grub_error(GRUB_ERR_BAD_FS,
				"vmfs: found %u of %u volume extents",
				data->nextents, vi.num_extents);
			goto fail;
		}
	}

	if (grub_vmfs_dev_read(data, VMFS_FSINFO_BASE, sizeof(fsi), fsi))
		goto fail;
	if (vmfs_get32(fsi, VMFS_FSINFO_OFS_MAGIC) != VMFS_FSINFO_MAGIC)
	{
		grub_error(GRUB_ERR_BAD_FS, "vmfs: bad filesystem magic");
		goto fail;
	}
	if (grub_memcmp(fsi + VMFS_FSINFO_OFS_LVM_UUID, vi.lvm_uuid, 16) != 0)
	{
		grub_error(GRUB_ERR_BAD_FS,
			"vmfs: filesystem does not belong to this volume");
		goto fail;
	}

	data->blocksize = vmfs_get64(fsi, VMFS_FSINFO_OFS_BLKSIZE);
	if (data->blocksize < 0x10000 || data->blocksize > 0x4000000
		|| (data->blocksize & (data->blocksize - 1)) != 0)
	{
		grub_error(GRUB_ERR_BAD_FS, "vmfs: bad block size 0x%llx",
			(unsigned long long) data->blocksize);
		goto fail;
	}

	grub_memcpy(data->uuid, fsi + VMFS_FSINFO_OFS_UUID, sizeof(data->uuid));
	grub_memcpy(data->label, fsi + VMFS_FSINFO_OFS_LABEL,
		VMFS_FSINFO_LABEL_LEN);
	data->label[VMFS_FSINFO_LABEL_LEN] = '\0';
	if (!data->label[0])
		grub_strcpy(data->label, vi.name);

	/*
	 * Bootstrap: .fdc.sf begins in the first block past the heartbeat
	 * area, so a synthetic single-block inode reaches its header and
	 * the first file descriptors -- enough for the root directory and
	 * the meta files themselves.
	 */
	fdc_base = (grub_uint32_t) ((VMFS_HB_BASE
		+ (grub_uint64_t) VMFS_HB_NUM * VMFS_HB_SIZE) / data->blocksize);
	if (fdc_base == 0)
		fdc_base = 1;

	data->fdc_inode.data = data;
	data->fdc_inode.type = VMFS_FILE_TYPE_META;
	data->fdc_inode.zla = VMFS_BLK_TYPE_FB;
	data->fdc_inode.size = data->blocksize;
	data->fdc_inode.blk_size = data->blocksize;
	grub_set_unaligned32(data->fdc_inode.blocks,
		grub_cpu_to_le32(VMFS_BLK_FB_BUILD(fdc_base)));

	if (grub_vmfs_bitmap_open(&data->fdc, &data->fdc_inode))
		goto fail;
	if (grub_vmfs_read_inode(data, VMFS_BLK_FD_ROOT, &data->root))
		goto fail;
	if (data->root.type != VMFS_FILE_TYPE_DIR)
	{
		grub_error(GRUB_ERR_BAD_FS, "vmfs: root is not a directory");
		goto fail;
	}

	/*
	 * Open .pbc.sf first: the real .fdc.sf and .sbc.sf are large enough
	 * to be described by pointer blocks themselves.
	 */
	if (grub_vmfs_lookup_meta(data, VMFS_PBC_FILENAME, &blk_id)
		|| grub_vmfs_read_inode(data, blk_id, &data->pbc_inode)
		|| grub_vmfs_bitmap_open(&data->pbc, &data->pbc_inode))
		goto fail;
	data->have_pbc = 1;

	tmp = grub_malloc(sizeof(*tmp));
	if (!tmp)
		goto fail;
	if (grub_vmfs_lookup_meta(data, VMFS_FDC_FILENAME, &blk_id)
		|| grub_vmfs_read_inode(data, blk_id, tmp))
		goto fail;
	grub_memcpy(&data->fdc_inode, tmp, sizeof(*tmp));
	if (grub_vmfs_bitmap_open(&data->fdc, &data->fdc_inode))
		goto fail;

	if (grub_vmfs_lookup_meta(data, VMFS_SBC_FILENAME, &blk_id)
		|| grub_vmfs_read_inode(data, blk_id, &data->sbc_inode)
		|| grub_vmfs_bitmap_open(&data->sbc, &data->sbc_inode))
		goto fail;
	data->have_sbc = 1;

	grub_free(tmp);
	return data;

fail:
	grub_free(tmp);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "not a vmfs filesystem");
	grub_vmfs_unmount(data);
	return NULL;
}

/* context for grub_vmfs_dir */
struct grub_vmfs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_vmfs_dir_iter(const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *ctx_in)
{
	struct grub_vmfs_dir_ctx *ctx = ctx_in;
	struct grub_dirhook_info info;

	grub_memset(&info, 0, sizeof(info));
	info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink =
		((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK);
	info.mtimeset = 1;
	info.mtime = node->mtime;
	info.inodeset = 1;
	info.inode = node->id;
	grub_free(node);
	return ctx->hook(filename, &info, ctx->hook_data);
}

static grub_err_t
grub_vmfs_dir(grub_device_t device, const char *path, grub_fs_dir_hook_t hook,
	void *hook_data)
{
	struct grub_vmfs_dir_ctx ctx = { hook, hook_data };
	struct grub_vmfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_vmfs_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(path, &data->root, &fdiro, grub_vmfs_iterate_dir,
		grub_vmfs_read_symlink, GRUB_FSHELP_DIR);
	if (grub_errno)
		goto fail;

	grub_vmfs_iterate_dir(fdiro, grub_vmfs_dir_iter, &ctx);

fail:
	if (fdiro != &data->root)
		grub_free(fdiro);
	grub_vmfs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_vmfs_open(struct grub_file *file, const char *name)
{
	struct grub_vmfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_vmfs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(name, &data->root, &fdiro, grub_vmfs_iterate_dir,
		grub_vmfs_read_symlink, GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	file->size = fdiro->size;
	file->data = fdiro;
	return GRUB_ERR_NONE;

fail:
	if (fdiro != &data->root)
		grub_free(fdiro);
	grub_vmfs_unmount(data);
	return grub_errno;
}

static grub_ssize_t
grub_vmfs_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fshelp_node *node = file->data;

	if (len == 0)
		return 0;
	if (grub_vmfs_read_file(node, file->offset, len, buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_vmfs_close(grub_file_t file)
{
	struct grub_fshelp_node *node = file->data;
	struct grub_vmfs_data *data = node->data;

	if (node != &data->root)
		grub_free(node);
	grub_vmfs_unmount(data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_vmfs_label(grub_device_t device, char **label)
{
	struct grub_vmfs_data *data;

	*label = NULL;
	data = grub_vmfs_mount(device->disk);
	if (!data)
		return grub_errno;

	*label = grub_strdup(data->label);
	grub_vmfs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_vmfs_uuid(grub_device_t device, char **uuid)
{
	struct grub_vmfs_data *data;
	const grub_uint8_t *u;

	*uuid = NULL;
	data = grub_vmfs_mount(device->disk);
	if (!data)
		return grub_errno;

	/* the grouping VMware itself displays: 4-4-2-6 bytes, the first
	   three groups byte swapped */
	u = data->uuid;
	*uuid = grub_xasprintf("%02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x-"
		"%02x%02x%02x%02x%02x%02x",
		u[3], u[2], u[1], u[0], u[7], u[6], u[5], u[4], u[9], u[8],
		u[10], u[11], u[12], u[13], u[14], u[15]);

	grub_vmfs_unmount(data);
	return grub_errno;
}

static struct grub_fs grub_vmfs_fs =
{
	.name = "vmfs",
	.fs_dir = grub_vmfs_dir,
	.fs_open = grub_vmfs_open,
	.fs_read = grub_vmfs_read,
	.fs_close = grub_vmfs_close,
	.fs_label = grub_vmfs_label,
	.fs_uuid = grub_vmfs_uuid,
	.next = 0
};

GRUB_MOD_INIT(vmfs)
{
	grub_vmfs_fs.mod = mod;
	grub_fs_register(&grub_vmfs_fs);
}

GRUB_MOD_FINI(vmfs)
{
	grub_fs_unregister(&grub_vmfs_fs);
}
