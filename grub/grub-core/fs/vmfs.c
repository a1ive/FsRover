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
 * VMFS (VMware vSphere VMFS3 / VMFS5 / VMFS6) read-only driver.
 *
 * On-disk semantics follow vmfs-tools (libvmfs) for VMFS3 and VMFS5, and
 * its vmfs6-tool fork for VMFS6; both reverse engineered the format.
 *
 * A VMFS partition starts with the volume header at 0x100000, holding the
 * LVM information: a logical volume is the concatenation of one or more
 * extents, each contributing a range of 256 MiB segments identified by a
 * shared LVM UUID.  All volume-relative offsets below are translated to
 * extent-relative ones and shifted by another 0x1000000 bytes, exactly
 * like vmfs_vol_read() does.
 *
 * The filesystem header sits at volume offset 0x200000 and gives the
 * block size plus the volume label / UUID.  Everything else lives in
 * meta files in the root directory (.fbb.sf, .fdc.sf, .pbc.sf, .sbc.sf
 * and, on VMFS6, .pb2.sf); each is a "bitmap": a header, then areas of
 * fixed-size allocation entries followed by that area's fixed-size
 * items.  Inodes are the items of .fdc.sf, sub-blocks those of .sbc.sf,
 * pointer blocks those of .pbc.sf (VMFS3/5) or .sbc.sf and .pb2.sf
 * (VMFS6); file blocks are raw volume space addressed by index.  A block
 * ID packs the item and entry numbers plus a 3-bit type tag, and an
 * inode's "zla" field says which block type its block slots hold (VMFS5
 * adds 4301 to it, and 4301+FD means the data is stored inline in the
 * inode itself).
 *
 * Bootstrapping is circular: reading any inode needs .fdc.sf, which is
 * itself a file described by an inode.  The way out (again from
 * vmfs-tools) is that .fdc.sf always begins in the first block past the
 * heartbeat area, so a synthetic one-block inode is enough to reach the
 * root directory and from there the real meta files.
 *
 * VMFS6 keeps that architecture but widens nearly every structure: 4 KiB
 * metadata headers, 8 KiB inodes with 320 64-bit block slots, 8 KiB
 * bitmap entries, 64-bit block IDs with a split file-block item field,
 * 288-byte directory records laid out in 4 KiB pages behind a presence
 * bitmap, a second pointer block level (.pb2.sf), 512 MiB large file
 * blocks, and the LVM header at 0x1000 instead of 0x200.  Everything
 * version dependent is collected in struct grub_vmfs_layout.
 *
 * Limitations: read-only, no RDM (raw device mapping) pass-through, and
 * .fbb.sf is never opened because file blocks are read straight off the
 * volume.  Extents of a spanned volume are located by scanning all
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

#define VMFS_VOLINFO_OFS_MAGIC		0
#define VMFS_VOLINFO_OFS_VER		4
#define VMFS_VOLINFO_OFS_NAME		18
#define VMFS_VOLINFO_NAME_LEN		28
#define VMFS_VOLINFO_HDR_LEN		256

/* LVM information, at a version dependent offset in the volume header */
#define VMFS_LVMINFO_OFS_UUID		0x54
#define VMFS_LVMINFO_OFS_NUM_SEGMENTS	0x74
#define VMFS_LVMINFO_OFS_FIRST_SEGMENT	0x78
#define VMFS_LVMINFO_OFS_LAST_SEGMENT	0x80
#define VMFS_LVMINFO_OFS_NUM_EXTENTS	0x90
#define VMFS_LVMINFO_LEN		0x100

#define VMFS_LVM_SEGMENT_SIZE		0x10000000ULL	/* 256 MiB */
#define VMFS_LVM_MAX_EXTENTS		32

/* volume offset 0 maps here inside its extent */
#define VMFS_VOLUME_DATA_BASE		(VMFS_VOLINFO_BASE + 0x1000000)

/* === filesystem header (volume relative) === */
#define VMFS_FSINFO_BASE		0x200000
#define VMFS_FSINFO_MAGIC		0x2fabf15e
#define VMFSL_FSINFO_MAGIC		0x2fabf15f
#define VMFS_FSINFO_LEN			512

#define VMFS_FSINFO_OFS_MAGIC		0
#define VMFS_FSINFO_OFS_UUID		9
#define VMFS_FSINFO_OFS_LABEL		29
#define VMFS_FSINFO_LABEL_LEN		128
#define VMFS_FSINFO_OFS_BLKSIZE		161
#define VMFS_FSINFO_OFS_LVM_UUID	177

/* === metadata header, shared prefix of inodes and bitmap entries === */
#define VMFS_MDH_OFS_MAGIC		0

/* === bitmaps === */
#define VMFS_BITMAP_HDR_LEN		512

#define VMFS_BMH_OFS_ITEMS_PER_ENTRY	0x00
#define VMFS_BMH_OFS_ENTRIES_PER_AREA	0x04
#define VMFS_BMH_OFS_HDR_SIZE		0x08
#define VMFS_BMH_OFS_DATA_SIZE		0x0c
#define VMFS_BMH_OFS_AREA_SIZE		0x10
#define VMFS_BMH_OFS_TOTAL_ITEMS	0x14
#define VMFS_BMH_OFS_AREA_COUNT		0x18

/* === inodes (items of .fdc.sf) === */
#define VMFS_INODE_MAGIC		0x10c00001

/* inode field offsets, relative to the end of the metadata header */
#define VMFS_INODE_D_ID			0
#define VMFS_INODE_D_TYPE		12
#define VMFS_INODE_D_SIZE		20
#define VMFS_INODE_D_BLK_SIZE		28
#define VMFS_INODE_D_MTIME		44
#define VMFS_INODE_D_MODE		64
#define VMFS_INODE_D_ZLA		68

/* largest block array / inline data area of any version (VMFS6) */
#define VMFS_INODE_UNION_MAX		3584

/* file types, in inodes and directory records alike */
#define VMFS_FILE_TYPE_DIR		0x02
#define VMFS_FILE_TYPE_FILE		0x03
#define VMFS_FILE_TYPE_SYMLINK		0x04
#define VMFS_FILE_TYPE_META		0x05
#define VMFS_FILE_TYPE_RDM		0x06

/* POSIX mode bits; VMFS6 marks directories here rather than in "type" */
#define VMFS_S_IFMT			0xf000
#define VMFS_S_IFDIR			0x4000
#define VMFS_S_IFLNK			0xa000

/* VMFS5 offsets the zla field of an inode by this much */
#define VMFS5_ZLA_BASE			4301

/* === directory records === */
#define VMFS_DIRENT_OFS_TYPE		0
#define VMFS_DIRENT_OFS_BLK_ID		4
#define VMFS_DIRENT_NAME_LEN		128

/* VMFS3/5 records are packed from offset 0; VMFS6 keeps "." and ".." in
   the directory header and the rest in 4 KiB pages, each with a small
   header, gated by a nibble per page in a presence bitmap */
#define VMFS6_DIR_HEAD			0x3b8
#define VMFS6_DIR_PRESENT		0x10040
#define VMFS6_DIR_PAGE0			0x11000
#define VMFS6_DIR_PAGE_SIZE		0x1000
#define VMFS6_DIR_PAGE_HEAD		0x40
#define VMFS6_DIR_PRESENT_LAST		0x8	/* no further pages */
#define VMFS6_DIR_PRESENT_HERE		0x1	/* this page is allocated */

/* VMFS3/5 directory records read per disk round trip */
#define VMFS_DIRENT_BATCH		32

/* the meta files, all in the root directory */
#define VMFS_FDC_FILENAME		".fdc.sf"
#define VMFS_PBC_FILENAME		".pbc.sf"
#define VMFS_SBC_FILENAME		".sbc.sf"
#define VMFS_PB2_FILENAME		".pb2.sf"

/* longest symlink target we are willing to allocate */
#define VMFS_SYMLINK_MAX		4096

/* === block IDs === */
#define VMFS_BLK_TYPE_NONE		0
#define VMFS_BLK_TYPE_FB		1	/* file block */
#define VMFS_BLK_TYPE_SB		2	/* sub-block */
#define VMFS_BLK_TYPE_PB		3	/* pointer block */
#define VMFS_BLK_TYPE_FD		4	/* file descriptor (inode) */
#define VMFS_BLK_TYPE_PB2		5	/* 2nd level pointer block */
#define VMFS_BLK_TYPE_LFB		7	/* large file block (VMFS6) */

#define VMFS_BLK_TYPE(id)	((grub_uint32_t) ((id) & 0x7))
#define VMFS_BLK_TBZ(id)	((grub_uint32_t) (((id) >> 3) & 0x4))

/* VMFS6 large file blocks span 512 MiB of volume space */
#define VMFS_LARGE_BLOCK_SIZE		0x20000000ULL

/* fields that keep the same encoding on every version */
#define VMFS_BLK_FD_ENTRY(id)	((grub_uint32_t) (((id) >> 6) & 0xffff))
#define VMFS_BLK_FD_ITEM(id)	((grub_uint32_t) (((id) >> 22) & 0x3ff))
#define VMFS_BLK_PB_ENTRY(id)	((grub_uint32_t) (((id) >> 6) & 0x3fffff))
#define VMFS_BLK_PB_ITEM(id)	((grub_uint32_t) (((id) >> 28) & 0xf))
#define VMFS_BLK_PB2_ENTRY(id)	((grub_uint32_t) (((id) >> 6) & 0x1fffff))
#define VMFS_BLK_PB2_ITEM(id)	((grub_uint32_t) (((id) >> 27) & 0x1f))

#define VMFS_BLK_FD_ROOT	VMFS_BLK_TYPE_FD	/* entry 0, item 0 */

struct grub_vmfs_data;

/* Everything that moved between VMFS3/5 and VMFS6. */
struct grub_vmfs_layout
{
	int v6;
	grub_uint32_t lvminfo;		/* LVM info offset in the volume header */
	grub_uint64_t hb_end;		/* first byte past the heartbeat area */
	grub_uint32_t bme_size;		/* bitmap allocation entry size */
	grub_uint32_t mdh_size;		/* metadata header size */
	grub_uint32_t inode_size;
	grub_uint32_t union_ofs;	/* inode offset of the block array area */
	grub_uint32_t union_len;
	grub_uint32_t blk_ofs;		/* block array offset inside that area */
	grub_uint32_t blk_count;	/* number of block slots */
	grub_uint32_t blk_bytes;	/* bytes per block slot */
	grub_uint32_t dirent_size;
	grub_uint32_t dirent_name;	/* name offset inside a record */
};

/* VMFS3 and VMFS5 share one layout, VMFS6 has its own */
static const struct grub_vmfs_layout grub_vmfs_layout_v5 =
{
	0, 0x200, 0x400000, 0x400, 512, 0x800, 1024, 1024, 0, 256, 4, 0x8c, 12
};

static const struct grub_vmfs_layout grub_vmfs_layout_v6 =
{
	1, 0x1000, 0x700000, 0x2000, 4096, 0x2000, 4608, 3584, 1024, 320, 8,
	0x120, 24
};

/* an in-core inode; also the fshelp node handed out by the directory
   iterator */
struct grub_fshelp_node
{
	struct grub_vmfs_data *data;
	grub_uint32_t id;			/* its own FD block ID */
	grub_uint32_t type;			/* VMFS_FILE_TYPE_* */
	grub_uint32_t mode;			/* POSIX mode bits */
	grub_uint32_t zla;			/* type of the block slots */
	grub_uint64_t size;
	grub_uint64_t blk_size;
	grub_int32_t mtime;
	/* raw block array, prefixed by the inline data area */
	grub_uint8_t blocks[VMFS_INODE_UNION_MAX];
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
	const struct grub_vmfs_layout *l;
	struct grub_vmfs_extent extents[VMFS_LVM_MAX_EXTENTS];
	grub_uint32_t nextents;

	grub_uint64_t blocksize;
	grub_uint8_t uuid[16];
	char label[VMFS_FSINFO_LABEL_LEN + 1];

	struct grub_vmfs_bitmap fdc, pbc, sbc, pb2;
	int have_pbc, have_sbc, have_pb2;

	struct grub_fshelp_node root;
	struct grub_fshelp_node fdc_inode;
	struct grub_fshelp_node pbc_inode;
	struct grub_fshelp_node sbc_inode;
	struct grub_fshelp_node pb2_inode;
};

/* volume header fields needed to assemble the logical volume */
struct grub_vmfs_volinfo
{
	const struct grub_vmfs_layout *l;
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

/* One entry of a block array, 32 bits on VMFS3/5 and 64 on VMFS6. */
static grub_uint64_t
vmfs_get_blk(const struct grub_vmfs_data *data, const grub_uint8_t *p,
	grub_uint32_t index)
{
	if (data->l->blk_bytes == 8)
		return vmfs_get64(p, index * 8);
	return vmfs_get32(p, index * 4);
}

/*
 * File block item number.  VMFS3/5 keep it in one field; VMFS6 splits it
 * across a 64-bit ID, low 9 bits at 51 and high 17 bits at 15.
 */
static grub_uint64_t
vmfs_blk_fb_item(const struct grub_vmfs_data *data, grub_uint64_t blk_id)
{
	if (!data->l->v6)
		return (blk_id & 0xffffffc0ULL) >> 6;
	return ((blk_id >> 51) & 0x1ff) | (((blk_id >> 15) & 0x1ffff) << 9);
}

static grub_uint32_t
vmfs_blk_sb_entry(const struct grub_vmfs_data *data, grub_uint64_t blk_id)
{
	if (!data->l->v6)
		return (grub_uint32_t) ((blk_id & 0x0fffffc0ULL) >> 6);
	return (grub_uint32_t) ((blk_id >> 6) & 0xff);
}

static grub_uint32_t
vmfs_blk_sb_item(const struct grub_vmfs_data *data, grub_uint64_t blk_id)
{
	if (!data->l->v6)
		return (grub_uint32_t) (((blk_id >> 28) & 0xf)
			| (((blk_id >> 3) & 0x3) << 4));
	return (grub_uint32_t) (((blk_id >> 56) & 0xff)
		| (((blk_id >> 14) & 0xf) << 8));
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
grub_vmfs_item_pos(const struct grub_vmfs_data *data,
	const struct grub_vmfs_bitmap *bmp, grub_uint32_t entry,
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
	*pos += (grub_uint64_t) bmp->entries_per_area * data->l->bme_size;
	*pos += (addr % items_per_area) * bmp->data_size;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_vmfs_read_file(struct grub_fshelp_node *node, grub_uint64_t pos,
	grub_size_t len, void *buf);

/* Read one whole item of BMP into BUF (bmp->data_size bytes). */
static grub_err_t
grub_vmfs_get_item(struct grub_vmfs_data *data, struct grub_vmfs_bitmap *bmp,
	grub_uint32_t entry, grub_uint32_t item, void *buf)
{
	grub_uint64_t pos;

	if (grub_vmfs_item_pos(data, bmp, entry, item, &pos))
		return grub_errno;
	return grub_vmfs_read_file(bmp->inode, pos, bmp->data_size, buf);
}

/*
 * VMFS6 double indirection: the inode slot points at a sub-block full of
 * pointers to further sub-blocks, which in turn hold the block IDs.
 * Both levels live in .sbc.sf.
 */
static grub_err_t
grub_vmfs_get_block_2(struct grub_fshelp_node *node, grub_uint64_t blk_index,
	grub_uint8_t *pb_buf, grub_uint64_t *blk_id)
{
	struct grub_vmfs_data *data = node->data;
	grub_uint32_t per_pb = data->sbc.data_size / 8;
	grub_uint64_t primary = blk_index / ((grub_uint64_t) per_pb * per_pb);
	grub_uint64_t rest = blk_index % ((grub_uint64_t) per_pb * per_pb);
	grub_uint32_t second = (grub_uint32_t) (rest / per_pb);
	grub_uint32_t leaf = (grub_uint32_t) (rest % per_pb);
	grub_uint64_t id;

	if (primary >= data->l->blk_count)
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: pointer block index out of range");

	id = vmfs_get_blk(data, node->blocks + data->l->blk_ofs,
		(grub_uint32_t) primary);
	if (!id)
		return GRUB_ERR_NONE;
	if (grub_vmfs_get_item(data, &data->sbc, vmfs_blk_sb_entry(data, id),
		vmfs_blk_sb_item(data, id), pb_buf))
		return grub_errno;

	id = vmfs_get64(pb_buf, second * 8);
	if (!id)
		return GRUB_ERR_NONE;
	if (grub_vmfs_get_item(data, &data->sbc, vmfs_blk_sb_entry(data, id),
		vmfs_blk_sb_item(data, id), pb_buf))
		return grub_errno;

	*blk_id = vmfs_get64(pb_buf, leaf * 8);
	return GRUB_ERR_NONE;
}

/*
 * Resolve the block ID holding volume file offset POS.  ZLA is the
 * inode's block type with the VMFS5 bias already removed, DOUBLE says
 * the bias was present on a pointer block inode; PB_BUF is a scratch
 * buffer for the pointer block, only touched for indirect layouts.  A
 * zero block ID means the block is not allocated.
 */
static grub_err_t
grub_vmfs_get_block(struct grub_fshelp_node *node, grub_uint64_t pos,
	grub_uint32_t zla, int dbl, grub_uint8_t *pb_buf, grub_uint64_t *blk_id)
{
	struct grub_vmfs_data *data = node->data;
	const struct grub_vmfs_layout *l = data->l;
	grub_uint64_t blk_index = pos / node->blk_size;
	struct grub_vmfs_bitmap *bmp;
	grub_uint32_t per_pb, sub_index;
	grub_uint64_t pb_index, pb_blk;

	*blk_id = 0;
	switch (zla)
	{
	case VMFS_BLK_TYPE_FB:
	case VMFS_BLK_TYPE_SB:
		if (blk_index >= l->blk_count)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: block index out of range");
		*blk_id = vmfs_get_blk(data, node->blocks + l->blk_ofs,
			(grub_uint32_t) blk_index);
		return GRUB_ERR_NONE;

	case VMFS_BLK_TYPE_PB:
		/* VMFS6 keeps pointer blocks in .sbc.sf, and uses a second
		   level when the VMFS5 bias is set */
		if (l->v6 && dbl)
			return grub_vmfs_get_block_2(node, blk_index, pb_buf,
				blk_id);
		bmp = l->v6 ? &data->sbc : &data->pbc;
		break;

	case VMFS_BLK_TYPE_PB2:
		bmp = &data->pb2;
		break;

	default:
		/* only reached for an inline (VMFS5 4301+FD) inode */
		*blk_id = node->id;
		return GRUB_ERR_NONE;
	}

	per_pb = bmp->data_size / l->blk_bytes;
	pb_index = blk_index / per_pb;
	sub_index = (grub_uint32_t) (blk_index % per_pb);

	if (pb_index >= l->blk_count)
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: pointer block index out of range");
	pb_blk = vmfs_get_blk(data, node->blocks + l->blk_ofs,
		(grub_uint32_t) pb_index);
	if (!pb_blk)
		return GRUB_ERR_NONE;

	if (zla == VMFS_BLK_TYPE_PB2)
	{
		if (grub_vmfs_get_item(data, bmp, VMFS_BLK_PB2_ENTRY(pb_blk),
			VMFS_BLK_PB2_ITEM(pb_blk), pb_buf))
			return grub_errno;
	}
	else if (l->v6)
	{
		if (grub_vmfs_get_item(data, bmp, vmfs_blk_sb_entry(data, pb_blk),
			vmfs_blk_sb_item(data, pb_blk), pb_buf))
			return grub_errno;
	}
	else
	{
		if (VMFS_BLK_TYPE(pb_blk) != VMFS_BLK_TYPE_PB)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: bad pointer block 0x%llx",
				(unsigned long long) pb_blk);
		if (grub_vmfs_get_item(data, bmp, VMFS_BLK_PB_ENTRY(pb_blk),
			VMFS_BLK_PB_ITEM(pb_blk), pb_buf))
			return grub_errno;
	}

	*blk_id = vmfs_get_blk(data, pb_buf, sub_index);
	return GRUB_ERR_NONE;
}

/* Read LEN bytes of NODE's contents starting at POS. */
static grub_err_t
grub_vmfs_read_file(struct grub_fshelp_node *node, grub_uint64_t pos,
	grub_size_t len, void *buf)
{
	struct grub_vmfs_data *data = node->data;
	const struct grub_vmfs_layout *l = data->l;
	grub_uint8_t *out = buf;
	grub_uint8_t *sb_buf = NULL;
	grub_uint8_t *pb_buf = NULL;
	grub_uint32_t zla = node->zla;
	int inline_data = 0, dbl = 0;

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
		dbl = 1;
	}

	switch (zla)
	{
	case VMFS_BLK_TYPE_FB:
		break;

	/* sub-block buffers are allocated on first use below, because a
	   pointer block inode can have sub-block leaves too */
	case VMFS_BLK_TYPE_SB:
		if (!data->have_sbc)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: sub-block bitmap is unavailable");
		break;

	case VMFS_BLK_TYPE_PB:
		/* VMFS6 keeps pointer blocks in .sbc.sf */
		if (l->v6 ? !data->have_sbc : !data->have_pbc)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: pointer block bitmap is unavailable");
		pb_buf = grub_malloc(l->v6 ? data->sbc.data_size
			: data->pbc.data_size);
		if (!pb_buf)
			return grub_errno;
		break;

	case VMFS_BLK_TYPE_PB2:
		if (!data->have_pb2)
			return grub_error(GRUB_ERR_BAD_FS,
				"vmfs: 2nd level pointer block bitmap is unavailable");
		pb_buf = grub_malloc(data->pb2.data_size);
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
		grub_uint64_t blk_id, off;
		grub_uint32_t blk_type;
		grub_size_t take;

		if (grub_vmfs_get_block(node, pos, zla, dbl, pb_buf, &blk_id))
			goto fail;

		blk_type = VMFS_BLK_TYPE(blk_id);
		if (blk_type == VMFS_BLK_TYPE_FB && VMFS_BLK_TBZ(blk_id))
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

		/* a leaf tagged PB2 is a plain file block, as in vmfs6-tool */
		case VMFS_BLK_TYPE_FB:
		case VMFS_BLK_TYPE_PB2:
			off = pos % data->blocksize;
			take = (grub_size_t) (data->blocksize - off);
			if (take > len)
				take = len;
			if (grub_vmfs_dev_read(data,
				vmfs_blk_fb_item(data, blk_id) * data->blocksize
					+ off,
				take, out))
				goto fail;
			break;

		/* 512 MiB extent, its item still counted in file blocks */
		case VMFS_BLK_TYPE_LFB:
			off = pos % VMFS_LARGE_BLOCK_SIZE;
			take = (grub_size_t) (VMFS_LARGE_BLOCK_SIZE - off);
			if (take > len)
				take = len;
			if (grub_vmfs_dev_read(data,
				vmfs_blk_fb_item(data, blk_id) * data->blocksize
					+ off,
				take, out))
				goto fail;
			break;

		case VMFS_BLK_TYPE_SB:
			if (!data->have_sbc)
			{
				grub_error(GRUB_ERR_BAD_FS,
					"vmfs: unexpected sub-block 0x%llx",
					(unsigned long long) blk_id);
				goto fail;
			}
			if (!sb_buf)
			{
				sb_buf = grub_malloc(data->sbc.data_size);
				if (!sb_buf)
					goto fail;
			}
			off = pos % data->sbc.data_size;
			take = (grub_size_t) (data->sbc.data_size - off);
			if (take > len)
				take = len;
			if (grub_vmfs_get_item(data, &data->sbc,
				vmfs_blk_sb_entry(data, blk_id),
				vmfs_blk_sb_item(data, blk_id), sb_buf))
				goto fail;
			grub_memcpy(out, sb_buf + (grub_size_t) off, take);
			break;

		/* stored inline in the inode itself */
		case VMFS_BLK_TYPE_FD:
			if (!inline_data || pos >= l->union_len)
			{
				grub_error(GRUB_ERR_BAD_FS,
					"vmfs: unexpected file descriptor 0x%llx",
					(unsigned long long) blk_id);
				goto fail;
			}
			take = l->union_len - (grub_size_t) pos;
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
	const struct grub_vmfs_layout *l = data->l;
	grub_uint8_t *raw;
	grub_uint64_t pos;

	if (VMFS_BLK_TYPE(blk_id) != VMFS_BLK_TYPE_FD)
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: 0x%x is not a file descriptor", blk_id);
	if (data->fdc.data_size < l->inode_size)
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: file descriptors are too small");
	if (grub_vmfs_item_pos(data, &data->fdc, VMFS_BLK_FD_ENTRY(blk_id),
		VMFS_BLK_FD_ITEM(blk_id), &pos))
		return grub_errno;

	raw = grub_malloc(l->inode_size);
	if (!raw)
		return grub_errno;

	if (grub_vmfs_read_file(data->fdc.inode, pos, l->inode_size, raw))
		goto fail;
	if (vmfs_get32(raw, VMFS_MDH_OFS_MAGIC) != VMFS_INODE_MAGIC)
	{
		grub_error(GRUB_ERR_BAD_FS, "vmfs: bad inode magic");
		goto fail;
	}

	node->data = data;
	node->id = vmfs_get32(raw, l->mdh_size + VMFS_INODE_D_ID);
	node->type = vmfs_get32(raw, l->mdh_size + VMFS_INODE_D_TYPE);
	node->mode = vmfs_get32(raw, l->mdh_size + VMFS_INODE_D_MODE);
	node->zla = vmfs_get32(raw, l->mdh_size + VMFS_INODE_D_ZLA);
	node->size = vmfs_get64(raw, l->mdh_size + VMFS_INODE_D_SIZE);
	node->blk_size = vmfs_get64(raw, l->mdh_size + VMFS_INODE_D_BLK_SIZE);
	node->mtime = (grub_int32_t) vmfs_get32(raw,
		l->mdh_size + VMFS_INODE_D_MTIME);
	grub_memset(node->blocks, 0, sizeof(node->blocks));
	grub_memcpy(node->blocks, raw + l->union_ofs, l->union_len);

	grub_free(raw);
	return GRUB_ERR_NONE;

fail:
	grub_free(raw);
	return grub_errno;
}

/* VMFS6 flags directories in the mode bits rather than in "type". */
static int
grub_vmfs_is_dir(const struct grub_fshelp_node *node)
{
	return node->type == VMFS_FILE_TYPE_DIR
		|| (node->mode & VMFS_S_IFMT) == VMFS_S_IFDIR;
}

static int
grub_vmfs_is_symlink(const struct grub_fshelp_node *node)
{
	return node->type == VMFS_FILE_TYPE_SYMLINK
		|| (node->mode & VMFS_S_IFMT) == VMFS_S_IFLNK;
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

	if (!bmp->items_per_entry || !bmp->entries_per_area
		|| bmp->data_size < inode->data->l->blk_bytes)
		return grub_error(GRUB_ERR_BAD_FS, "vmfs: bad bitmap header");
	return GRUB_ERR_NONE;
}

/* Look up NAME in the root directory and open it as a meta file. */
static grub_err_t
grub_vmfs_lookup_meta(struct grub_vmfs_data *data, const char *name,
	grub_uint32_t *blk_id);

static grub_err_t
grub_vmfs_open_meta(struct grub_vmfs_data *data, const char *name,
	struct grub_vmfs_bitmap *bmp, struct grub_fshelp_node *inode)
{
	grub_uint32_t blk_id;

	if (grub_vmfs_lookup_meta(data, name, &blk_id)
		|| grub_vmfs_read_inode(data, blk_id, inode)
		|| grub_vmfs_bitmap_open(bmp, inode))
		return grub_errno;
	return GRUB_ERR_NONE;
}

/*
 * Feed every directory record of DIR to HOOK, which returns non-zero to
 * stop.  Read errors abort the walk with grub_errno set.
 *
 * VMFS3/5 records are packed from offset 0.  VMFS6 puts "." and ".." in
 * the directory header and the rest in 4 KiB pages, each holding a
 * 0x40-byte header and 14 records; a nibble per page in the presence
 * bitmap says whether the page is allocated (bit 0) and whether it is
 * past the last one (bit 3).
 */
static void
grub_vmfs_scan_dir(struct grub_fshelp_node *dir,
	int (*hook) (const grub_uint8_t *rec, void *data), void *hook_data)
{
	const struct grub_vmfs_layout *l = dir->data->l;
	grub_uint8_t *chunk;
	grub_uint32_t page, nib_byte = 0xffffffff;
	grub_uint8_t nib = 0;

	if (!l->v6)
	{
		grub_uint64_t pos = 0;

		chunk = grub_malloc((grub_size_t) l->dirent_size
			* VMFS_DIRENT_BATCH);
		if (!chunk)
			return;

		while (dir->size - pos >= l->dirent_size)
		{
			grub_uint64_t left = dir->size - pos;
			grub_uint32_t i, n;
			grub_size_t got;

			n = VMFS_DIRENT_BATCH;
			if (left / l->dirent_size < n)
				n = (grub_uint32_t) (left / l->dirent_size);
			got = (grub_size_t) n * l->dirent_size;

			if (grub_vmfs_read_file(dir, pos, got, chunk))
				break;

			for (i = 0; i < n; i++)
				if (hook(chunk + i * l->dirent_size, hook_data))
					goto done;
			pos += got;
		}
		goto done;
	}

	chunk = grub_malloc(VMFS6_DIR_PAGE_SIZE);
	if (!chunk)
		return;

	/* "." and ".." live in the header and share page 0's nibble */
	for (page = 0; ; page++)
	{
		grub_uint32_t nib_idx = page + 1;
		grub_uint64_t off = VMFS6_DIR_PAGE0
			+ (grub_uint64_t) page * VMFS6_DIR_PAGE_SIZE;
		grub_uint32_t slot, n;
		grub_uint8_t present;

		if (off + VMFS6_DIR_PAGE_SIZE > dir->size)
			break;

		if (nib_idx / 2 != nib_byte)
		{
			nib_byte = nib_idx / 2;
			if (grub_vmfs_read_file(dir,
				VMFS6_DIR_PRESENT + nib_byte, 1, &nib))
				break;
		}
		present = (nib_idx & 1) ? (nib & 0x0f) : (nib >> 4);

		if (present & VMFS6_DIR_PRESENT_LAST)
			break;
		if (!(present & VMFS6_DIR_PRESENT_HERE))
			continue;

		if (page == 0)
		{
			n = 2;
			if (grub_vmfs_read_file(dir, VMFS6_DIR_HEAD,
				(grub_size_t) n * l->dirent_size, chunk))
				break;
			for (slot = 0; slot < n; slot++)
				if (hook(chunk + slot * l->dirent_size, hook_data))
					goto done;
		}

		if (grub_vmfs_read_file(dir, off, VMFS6_DIR_PAGE_SIZE, chunk))
			break;

		n = (VMFS6_DIR_PAGE_SIZE - VMFS6_DIR_PAGE_HEAD) / l->dirent_size;
		for (slot = 0; slot < n; slot++)
			if (hook(chunk + VMFS6_DIR_PAGE_HEAD
				+ slot * l->dirent_size, hook_data))
				goto done;
	}

done:
	grub_free(chunk);
}

/* context for grub_vmfs_lookup_rec */
struct grub_vmfs_lookup_ctx
{
	const struct grub_vmfs_layout *l;
	const char *name;
	grub_uint32_t blk_id;
};

static int
grub_vmfs_lookup_rec(const grub_uint8_t *rec, void *ctx_in)
{
	struct grub_vmfs_lookup_ctx *ctx = ctx_in;
	char name[VMFS_DIRENT_NAME_LEN + 1];

	grub_memcpy(name, rec + ctx->l->dirent_name, VMFS_DIRENT_NAME_LEN);
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
	struct grub_vmfs_lookup_ctx ctx = { data->l, name, 0 };

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
	grub_memcpy(name, rec + ctx->data->l->dirent_name, VMFS_DIRENT_NAME_LEN);
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

	if (grub_vmfs_is_dir(node))
		type = GRUB_FSHELP_DIR;
	else if (grub_vmfs_is_symlink(node))
		type = GRUB_FSHELP_SYMLINK;
	else
		/* meta files and raw device mappings show up as plain files,
		   the way vmfs_file_type2mode() reports them */
		type = GRUB_FSHELP_REG;

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

	if (!grub_vmfs_is_dir(dir))
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
	grub_uint8_t buf[VMFS_VOLINFO_HDR_LEN];
	grub_uint8_t lvm[VMFS_LVMINFO_LEN];

	if (grub_disk_read(disk, 0, VMFS_VOLINFO_BASE, sizeof(buf), buf))
		return grub_errno;
	if (vmfs_get32(buf, VMFS_VOLINFO_OFS_MAGIC) != VMFS_VOLINFO_MAGIC)
		return grub_error(GRUB_ERR_BAD_FS, "not a vmfs volume");

	vi->version = vmfs_get32(buf, VMFS_VOLINFO_OFS_VER);
	if (vi->version == 3 || vi->version == 5)
		vi->l = &grub_vmfs_layout_v5;
	else if (vi->version == 6)
		vi->l = &grub_vmfs_layout_v6;
	else
		return grub_error(GRUB_ERR_BAD_FS,
			"vmfs: unsupported version %u", vi->version);

	grub_memcpy(vi->name, buf + VMFS_VOLINFO_OFS_NAME,
		VMFS_VOLINFO_NAME_LEN);
	vi->name[VMFS_VOLINFO_NAME_LEN] = '\0';

	if (grub_disk_read(disk, 0, VMFS_VOLINFO_BASE + vi->l->lvminfo,
		sizeof(lvm), lvm))
		return grub_errno;

	vi->first_segment = vmfs_get32(lvm, VMFS_LVMINFO_OFS_FIRST_SEGMENT);
	vi->last_segment = vmfs_get32(lvm, VMFS_LVMINFO_OFS_LAST_SEGMENT);
	vi->num_extents = vmfs_get32(lvm, VMFS_LVMINFO_OFS_NUM_EXTENTS);
	grub_memcpy(vi->lvm_uuid, lvm + VMFS_LVMINFO_OFS_UUID,
		sizeof(vi->lvm_uuid));

	if (vi->last_segment < vi->first_segment)
		return grub_error(GRUB_ERR_BAD_FS, "vmfs: bad segment range");
	return GRUB_ERR_NONE;
}

/* context for grub_vmfs_scan_extent */
struct grub_vmfs_scan_ctx
{
	struct grub_vmfs_data *data;
	const grub_uint8_t *lvm_uuid;
	grub_uint32_t version;
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
		|| vi.version != ctx->version
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
	const struct grub_vmfs_layout *l;
	struct grub_vmfs_data *data;
	struct grub_vmfs_volinfo vi;
	struct grub_fshelp_node *tmp = NULL;
	grub_uint8_t fsi[VMFS_FSINFO_LEN];
	grub_uint32_t magic, fdc_base, blk_id;

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

	l = data->l = vi.l;
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
		ctx.version = vi.version;
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
	magic = vmfs_get32(fsi, VMFS_FSINFO_OFS_MAGIC);
	if (magic != VMFS_FSINFO_MAGIC && magic != VMFSL_FSINFO_MAGIC)
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
	fdc_base = (grub_uint32_t) (l->hb_end / data->blocksize);
	if (fdc_base == 0)
		fdc_base = 1;

	data->fdc_inode.data = data;
	data->fdc_inode.type = VMFS_FILE_TYPE_META;
	data->fdc_inode.zla = VMFS_BLK_TYPE_FB;
	data->fdc_inode.size = data->blocksize;
	data->fdc_inode.blk_size = data->blocksize;
	if (l->v6)
		grub_set_unaligned64(data->fdc_inode.blocks + l->blk_ofs,
			grub_cpu_to_le64(
				((grub_uint64_t) (fdc_base & 0x1ff) << 51)
				| ((grub_uint64_t) ((fdc_base >> 9) & 0x1ffff)
					<< 15)
				| VMFS_BLK_TYPE_FB));
	else
		grub_set_unaligned32(data->fdc_inode.blocks + l->blk_ofs,
			grub_cpu_to_le32(((fdc_base << 6) & 0xffffffc0u)
				| VMFS_BLK_TYPE_FB));

	if (grub_vmfs_bitmap_open(&data->fdc, &data->fdc_inode))
		goto fail;
	if (grub_vmfs_read_inode(data, VMFS_BLK_FD_ROOT, &data->root))
		goto fail;
	if (!grub_vmfs_is_dir(&data->root))
	{
		grub_error(GRUB_ERR_BAD_FS, "vmfs: root is not a directory");
		goto fail;
	}

	tmp = grub_malloc(sizeof(*tmp));
	if (!tmp)
		goto fail;

	if (l->v6)
	{
		/*
		 * VMFS6 stores pointer blocks in .sbc.sf, so the real
		 * .fdc.sf has to come first: everything else is then read
		 * through a descriptor table that is no longer capped at
		 * one block.
		 */
		if (grub_vmfs_lookup_meta(data, VMFS_FDC_FILENAME, &blk_id)
			|| grub_vmfs_read_inode(data, blk_id, tmp))
			goto fail;
		grub_memcpy(&data->fdc_inode, tmp, sizeof(*tmp));
		if (grub_vmfs_bitmap_open(&data->fdc, &data->fdc_inode))
			goto fail;

		/*
		 * .pb2.sf must come before .sbc.sf: on a real volume
		 * .sbc.sf is itself addressed through second level
		 * pointer blocks (zla = PB2), while .pb2.sf uses direct
		 * blocks and so depends on nothing.
		 */
		if (grub_vmfs_open_meta(data, VMFS_PB2_FILENAME, &data->pb2,
			&data->pb2_inode) == GRUB_ERR_NONE)
			data->have_pb2 = 1;
		else
			grub_errno = GRUB_ERR_NONE;

		if (grub_vmfs_open_meta(data, VMFS_SBC_FILENAME, &data->sbc,
			&data->sbc_inode))
			goto fail;
		data->have_sbc = 1;
	}
	else
	{
		/*
		 * Open .pbc.sf first: the real .fdc.sf and .sbc.sf are large
		 * enough to be described by pointer blocks themselves.
		 */
		if (grub_vmfs_open_meta(data, VMFS_PBC_FILENAME, &data->pbc,
			&data->pbc_inode))
			goto fail;
		data->have_pbc = 1;

		if (grub_vmfs_lookup_meta(data, VMFS_FDC_FILENAME, &blk_id)
			|| grub_vmfs_read_inode(data, blk_id, tmp))
			goto fail;
		grub_memcpy(&data->fdc_inode, tmp, sizeof(*tmp));
		if (grub_vmfs_bitmap_open(&data->fdc, &data->fdc_inode))
			goto fail;

		if (grub_vmfs_open_meta(data, VMFS_SBC_FILENAME, &data->sbc,
			&data->sbc_inode))
			goto fail;
		data->have_sbc = 1;
	}

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
	if (!info.dir && !info.symlink)
	{
		info.sizeset = 1;
		info.size = node->size;
	}
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
