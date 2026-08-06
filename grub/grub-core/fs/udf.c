/* udf.c - Universal Disk Format filesystem.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008,2009  Free Software Foundation, Inc.
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

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>
#include <grub/charset.h>
#include <grub/datetime.h>
#include <grub/lockdown.h>
#include <grub/udf.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_UDF_MAX_PDS		4
#define GRUB_UDF_MAX_PMS		6
#define GRUB_UDF_MAX_SPARING_TABLES	4

/*
 * How far back from the last recorded block the Virtual Allocation Table
 * file entry is looked for.  It is supposed to sit exactly in the last
 * block but some writers are off by a few blocks.
 */
#define GRUB_UDF_VAT_SEARCH_BACK	4

#define U16				grub_le_to_cpu16
#define U32				grub_le_to_cpu32
#define U64				grub_le_to_cpu64

#define GRUB_UDF_TAG_IDENT_PVD		0x0001
#define GRUB_UDF_TAG_IDENT_AVDP		0x0002
#define GRUB_UDF_TAG_IDENT_VDP		0x0003
#define GRUB_UDF_TAG_IDENT_IUVD		0x0004
#define GRUB_UDF_TAG_IDENT_PD		0x0005
#define GRUB_UDF_TAG_IDENT_LVD		0x0006
#define GRUB_UDF_TAG_IDENT_USD		0x0007
#define GRUB_UDF_TAG_IDENT_TD		0x0008
#define GRUB_UDF_TAG_IDENT_LVID		0x0009

#define GRUB_UDF_TAG_IDENT_FSD		0x0100
#define GRUB_UDF_TAG_IDENT_FID		0x0101
#define GRUB_UDF_TAG_IDENT_AED		0x0102
#define GRUB_UDF_TAG_IDENT_IE		0x0103
#define GRUB_UDF_TAG_IDENT_TE		0x0104
#define GRUB_UDF_TAG_IDENT_FE		0x0105
#define GRUB_UDF_TAG_IDENT_EAHD		0x0106
#define GRUB_UDF_TAG_IDENT_USE		0x0107
#define GRUB_UDF_TAG_IDENT_SBD		0x0108
#define GRUB_UDF_TAG_IDENT_PIE		0x0109
#define GRUB_UDF_TAG_IDENT_EFE		0x010A

#define GRUB_UDF_ICBTAG_TYPE_UNDEF	0x00
#define GRUB_UDF_ICBTAG_TYPE_USE	0x01
#define GRUB_UDF_ICBTAG_TYPE_PIE	0x02
#define GRUB_UDF_ICBTAG_TYPE_IE		0x03
#define GRUB_UDF_ICBTAG_TYPE_DIRECTORY	0x04
#define GRUB_UDF_ICBTAG_TYPE_REGULAR	0x05
#define GRUB_UDF_ICBTAG_TYPE_BLOCK	0x06
#define GRUB_UDF_ICBTAG_TYPE_CHAR	0x07
#define GRUB_UDF_ICBTAG_TYPE_EA		0x08
#define GRUB_UDF_ICBTAG_TYPE_FIFO	0x09
#define GRUB_UDF_ICBTAG_TYPE_SOCKET	0x0A
#define GRUB_UDF_ICBTAG_TYPE_TE		0x0B
#define GRUB_UDF_ICBTAG_TYPE_SYMLINK	0x0C
#define GRUB_UDF_ICBTAG_TYPE_STREAMDIR	0x0D
#define GRUB_UDF_ICBTAG_TYPE_VAT20	0xF8

#define GRUB_UDF_ICBTAG_FLAG_AD_MASK	0x0007
#define GRUB_UDF_ICBTAG_FLAG_AD_SHORT	0x0000
#define GRUB_UDF_ICBTAG_FLAG_AD_LONG	0x0001
#define GRUB_UDF_ICBTAG_FLAG_AD_EXT	0x0002
#define GRUB_UDF_ICBTAG_FLAG_AD_IN_ICB	0x0003

#define GRUB_UDF_EXT_NORMAL		0x00000000
#define GRUB_UDF_EXT_NREC_ALLOC		0x40000000
#define GRUB_UDF_EXT_NREC_NALLOC	0x80000000
#define GRUB_UDF_EXT_MASK		0xC0000000

#define GRUB_UDF_FID_CHAR_HIDDEN	0x01
#define GRUB_UDF_FID_CHAR_DIRECTORY	0x02
#define GRUB_UDF_FID_CHAR_DELETED	0x04
#define GRUB_UDF_FID_CHAR_PARENT	0x08
#define GRUB_UDF_FID_CHAR_METADATA	0x10

#define GRUB_UDF_STD_IDENT_BEA01	"BEA01"
#define GRUB_UDF_STD_IDENT_BOOT2	"BOOT2"
#define GRUB_UDF_STD_IDENT_CD001	"CD001"
#define GRUB_UDF_STD_IDENT_CDW02	"CDW02"
#define GRUB_UDF_STD_IDENT_NSR02	"NSR02"
#define GRUB_UDF_STD_IDENT_NSR03	"NSR03"
#define GRUB_UDF_STD_IDENT_TEA01	"TEA01"

#define GRUB_UDF_CHARSPEC_TYPE_CS0	0x00
#define GRUB_UDF_CHARSPEC_TYPE_CS1	0x01
#define GRUB_UDF_CHARSPEC_TYPE_CS2	0x02
#define GRUB_UDF_CHARSPEC_TYPE_CS3	0x03
#define GRUB_UDF_CHARSPEC_TYPE_CS4	0x04
#define GRUB_UDF_CHARSPEC_TYPE_CS5	0x05
#define GRUB_UDF_CHARSPEC_TYPE_CS6	0x06
#define GRUB_UDF_CHARSPEC_TYPE_CS7	0x07
#define GRUB_UDF_CHARSPEC_TYPE_CS8	0x08

#define GRUB_UDF_PARTMAP_TYPE_1		1
#define GRUB_UDF_PARTMAP_TYPE_2		2

/* Entity identifiers of the type 2 partition maps (UDF 2.60 2.2.8-2.2.10).  */
#define GRUB_UDF_ID_VIRTUAL		"*UDF Virtual Partition"
#define GRUB_UDF_ID_SPARABLE		"*UDF Sparable Partition"
#define GRUB_UDF_ID_METADATA		"*UDF Metadata Partition"
#define GRUB_UDF_ID_SPARING		"*UDF Sparing Table"

/* In-core flavour of a partition map.  */
#define GRUB_UDF_PMAP_NONE		0
#define GRUB_UDF_PMAP_PHYSICAL		1
#define GRUB_UDF_PMAP_VIRTUAL		2
#define GRUB_UDF_PMAP_SPARABLE		3
#define GRUB_UDF_PMAP_METADATA		4

/*
 * How deep partition maps may be stacked.  A metadata or virtual map sits
 * on one physical or sparable map and that is the end of it; the limit is
 * only here to stop a corrupted medium from recursing forever.
 */
#define GRUB_UDF_MAX_NEST		4

#define GRUB_UDF_INVALID_STRUCT_PTR(_ptr, _struct)	\
  ((char *) (_ptr) >= end_ptr || \
   ((grub_ssize_t) (end_ptr - (char *) (_ptr)) < (grub_ssize_t) sizeof (_struct)))

PRAGMA_BEGIN_PACKED
struct grub_udf_lb_addr
{
  grub_uint32_t block_num;
  grub_uint16_t part_ref;
} GRUB_PACKED;

struct grub_udf_short_ad
{
  grub_uint32_t length;
  grub_uint32_t position;
} GRUB_PACKED;

struct grub_udf_long_ad
{
  grub_uint32_t length;
  struct grub_udf_lb_addr block;
  grub_uint8_t imp_use[6];
} GRUB_PACKED;

struct grub_udf_extent_ad
{
  grub_uint32_t length;
  grub_uint32_t start;
} GRUB_PACKED;

struct grub_udf_charspec
{
  grub_uint8_t charset_type;
  grub_uint8_t charset_info[63];
} GRUB_PACKED;

struct grub_udf_timestamp
{
  grub_uint16_t type_and_timezone;
  grub_uint16_t year;
  grub_uint8_t month;
  grub_uint8_t day;
  grub_uint8_t hour;
  grub_uint8_t minute;
  grub_uint8_t second;
  grub_uint8_t centi_seconds;
  grub_uint8_t hundreds_of_micro_seconds;
  grub_uint8_t micro_seconds;
} GRUB_PACKED;

struct grub_udf_regid
{
  grub_uint8_t flags;
  grub_uint8_t ident[23];
  grub_uint8_t ident_suffix[8];
} GRUB_PACKED;

struct grub_udf_tag
{
  grub_uint16_t tag_ident;
  grub_uint16_t desc_version;
  grub_uint8_t tag_checksum;
  grub_uint8_t reserved;
  grub_uint16_t tag_serial_number;
  grub_uint16_t desc_crc;
  grub_uint16_t desc_crc_length;
  grub_uint32_t tag_location;
} GRUB_PACKED;

struct grub_udf_fileset
{
  struct grub_udf_tag tag;
  struct grub_udf_timestamp datetime;
  grub_uint16_t interchange_level;
  grub_uint16_t max_interchange_level;
  grub_uint32_t charset_list;
  grub_uint32_t max_charset_list;
  grub_uint32_t fileset_num;
  grub_uint32_t fileset_desc_num;
  struct grub_udf_charspec vol_charset;
  grub_uint8_t vol_ident[128];
  struct grub_udf_charspec fileset_charset;
  grub_uint8_t fileset_ident[32];
  grub_uint8_t copyright_file_ident[32];
  grub_uint8_t abstract_file_ident[32];
  struct grub_udf_long_ad root_icb;
  struct grub_udf_regid domain_ident;
  struct grub_udf_long_ad next_ext;
  struct grub_udf_long_ad streamdir_icb;
} GRUB_PACKED;

struct grub_udf_icbtag
{
  grub_uint32_t prior_recorded_num_direct_entries;
  grub_uint16_t strategy_type;
  grub_uint16_t strategy_parameter;
  grub_uint16_t num_entries;
  grub_uint8_t reserved;
  grub_uint8_t file_type;
  struct grub_udf_lb_addr parent_idb;
  grub_uint16_t flags;
} GRUB_PACKED;

struct grub_udf_file_ident
{
  struct grub_udf_tag tag;
  grub_uint16_t version_num;
  grub_uint8_t characteristics;
#define MAX_FILE_IDENT_LENGTH 256
  grub_uint8_t file_ident_length;
  struct grub_udf_long_ad icb;
  grub_uint16_t imp_use_length;
} GRUB_PACKED;

struct grub_udf_file_entry
{
  struct grub_udf_tag tag;
  struct grub_udf_icbtag icbtag;
  grub_uint32_t uid;
  grub_uint32_t gid;
  grub_uint32_t permissions;
  grub_uint16_t link_count;
  grub_uint8_t record_format;
  grub_uint8_t record_display_attr;
  grub_uint32_t record_length;
  grub_uint64_t file_size;
  grub_uint64_t blocks_recorded;
  struct grub_udf_timestamp access_time;
  struct grub_udf_timestamp modification_time;
  struct grub_udf_timestamp attr_time;
  grub_uint32_t checkpoint;
  struct grub_udf_long_ad extended_attr_idb;
  struct grub_udf_regid imp_ident;
  grub_uint64_t unique_id;
  grub_uint32_t ext_attr_length;
  grub_uint32_t alloc_descs_length;
  grub_uint8_t ext_attr[0];
} GRUB_PACKED;

struct grub_udf_extended_file_entry
{
  struct grub_udf_tag tag;
  struct grub_udf_icbtag icbtag;
  grub_uint32_t uid;
  grub_uint32_t gid;
  grub_uint32_t permissions;
  grub_uint16_t link_count;
  grub_uint8_t record_format;
  grub_uint8_t record_display_attr;
  grub_uint32_t record_length;
  grub_uint64_t file_size;
  grub_uint64_t object_size;
  grub_uint64_t blocks_recorded;
  struct grub_udf_timestamp access_time;
  struct grub_udf_timestamp modification_time;
  struct grub_udf_timestamp create_time;
  struct grub_udf_timestamp attr_time;
  grub_uint32_t checkpoint;
  grub_uint32_t reserved;
  struct grub_udf_long_ad extended_attr_icb;
  struct grub_udf_long_ad streamdir_icb;
  struct grub_udf_regid imp_ident;
  grub_uint64_t unique_id;
  grub_uint32_t ext_attr_length;
  grub_uint32_t alloc_descs_length;
  grub_uint8_t ext_attr[0];
} GRUB_PACKED;

struct grub_udf_vrs
{
  grub_uint8_t type;
  grub_uint8_t magic[5];
  grub_uint8_t version;
} GRUB_PACKED;

struct grub_udf_avdp
{
  struct grub_udf_tag tag;
  struct grub_udf_extent_ad vds;
  struct grub_udf_extent_ad rvds;
} GRUB_PACKED;

struct grub_udf_pd
{
  struct grub_udf_tag tag;
  grub_uint32_t seq_num;
  grub_uint16_t flags;
  grub_uint16_t part_num;
  struct grub_udf_regid contents;
  grub_uint8_t contents_use[128];
  grub_uint32_t access_type;
  grub_uint32_t start;
  grub_uint32_t length;
} GRUB_PACKED;

/*
 * All type 2 partition maps share the first 40 bytes (ECMA-167 10.7.2 plus
 * the OSTA entity identifier); the flavour is told apart by that
 * identifier and each flavour appends its own fields.
 */
struct grub_udf_partmap
{
  grub_uint8_t type;
  grub_uint8_t length;
  union
  {
    struct
    {
      grub_uint16_t seq_num;
      grub_uint16_t part_num;
    } type1;

    struct
    {
      grub_uint8_t reserved[2];
      struct grub_udf_regid part_ident;
      grub_uint16_t seq_num;
      grub_uint16_t part_num;
    } type2;

    struct
    {
      grub_uint8_t reserved[2];
      struct grub_udf_regid part_ident;
      grub_uint16_t seq_num;
      grub_uint16_t part_num;
      grub_uint16_t packet_length;
      grub_uint8_t num_sparing_tables;
      grub_uint8_t reserved2;
      grub_uint32_t size_sparing_table;
      grub_uint32_t loc_sparing_table[GRUB_UDF_MAX_SPARING_TABLES];
    } spar;

    struct
    {
      grub_uint8_t reserved[2];
      struct grub_udf_regid part_ident;
      grub_uint16_t seq_num;
      grub_uint16_t part_num;
      grub_uint32_t meta_file_loc;
      grub_uint32_t meta_mirror_file_loc;
      grub_uint32_t meta_bitmap_file_loc;
      grub_uint32_t alloc_unit_size;
      grub_uint16_t align_unit_size;
      grub_uint8_t flags;
      grub_uint8_t reserved2[5];
    } meta;
  };
} GRUB_PACKED;

struct grub_udf_sparing_entry
{
  grub_uint32_t orig;
  grub_uint32_t mapped;
} GRUB_PACKED;

/* The reallocation table follows this header.  */
struct grub_udf_sparing_table
{
  struct grub_udf_tag tag;
  struct grub_udf_regid sparing_ident;
  grub_uint16_t rt_len;
  grub_uint16_t reserved;
  grub_uint32_t seq_num;
} GRUB_PACKED;

/* Header of a UDF 2.00+ Virtual Allocation Table (UDF 2.60 2.2.11).  */
struct grub_udf_vat20
{
  grub_uint16_t length_header;
  grub_uint16_t length_imp_use;
  grub_uint8_t logvol_ident[128];
  grub_uint32_t prev_vat_icb_loc;
  grub_uint32_t num_files;
  grub_uint32_t num_dirs;
  grub_uint16_t min_read_rev;
  grub_uint16_t min_write_rev;
  grub_uint16_t max_write_rev;
  grub_uint16_t reserved;
} GRUB_PACKED;

struct grub_udf_pvd
{
  struct grub_udf_tag tag;
  grub_uint32_t seq_num;
  grub_uint32_t pvd_num;
  grub_uint8_t ident[32];
  grub_uint16_t vol_seq_num;
  grub_uint16_t max_vol_seq_num;
  grub_uint16_t interchange_level;
  grub_uint16_t max_interchange_level;
  grub_uint32_t charset_list;
  grub_uint32_t max_charset_list;
  grub_uint8_t volset_ident[128];
  struct grub_udf_charspec desc_charset;
  struct grub_udf_charspec expl_charset;
  struct grub_udf_extent_ad vol_abstract;
  struct grub_udf_extent_ad vol_copyright;
  struct grub_udf_regid app_ident;
  struct grub_udf_timestamp recording_time;
  struct grub_udf_regid imp_ident;
  grub_uint8_t imp_use[64];
  grub_uint32_t pred_vds_loc;
  grub_uint16_t flags;
  grub_uint8_t reserved[22];
} GRUB_PACKED;

struct grub_udf_lvd
{
  struct grub_udf_tag tag;
  grub_uint32_t seq_num;
  struct grub_udf_charspec charset;
  grub_uint8_t ident[128];
  grub_uint32_t bsize;
  struct grub_udf_regid domain_ident;
  struct grub_udf_long_ad root_fileset;
  grub_uint32_t map_table_length;
  grub_uint32_t num_part_maps;
  struct grub_udf_regid imp_ident;
  grub_uint8_t imp_use[128];
  struct grub_udf_extent_ad integrity_seq_ext;
  grub_uint8_t part_maps[1608];
} GRUB_PACKED;

struct grub_udf_aed
{
  struct grub_udf_tag tag;
  grub_uint32_t prev_ae;
  grub_uint32_t ae_len;
} GRUB_PACKED;
PRAGMA_END_PACKED

/* In-core description of one entry of the partition map table.  */
struct grub_udf_part
{
  int type;
  grub_uint16_t part_num;

  /* Extent of the backing physical partition, from the PD.  */
  grub_uint32_t start;
  grub_uint32_t length;

  /*
   * Physical or sparable partition this map is layered on top of, for
   * the virtual and metadata flavours.  Index into grub_udf_data::parts.
   */
  grub_uint32_t phys_ref;

  /* GRUB_UDF_PMAP_VIRTUAL.  */
  struct grub_fshelp_node *vat;
  grub_uint32_t vat_offset;
  grub_uint32_t vat_entries;
  int vat20;

  /* GRUB_UDF_PMAP_SPARABLE.  */
  grub_uint32_t packet_len;
  grub_uint32_t spar_entries;
  struct grub_udf_sparing_entry *spar_table;

  /* GRUB_UDF_PMAP_METADATA.  */
  struct grub_fshelp_node *meta;
  grub_uint32_t meta_file_loc;
  grub_uint32_t meta_mirror_loc;
};

struct grub_udf_data
{
  grub_disk_t disk;
  struct grub_udf_pvd pvd;
  struct grub_udf_lvd lvd;
  struct grub_udf_pd pds[GRUB_UDF_MAX_PDS];
  struct grub_udf_part parts[GRUB_UDF_MAX_PMS];
  struct grub_udf_long_ad root_icb;
  grub_uint32_t last_block;
  int npd, npm, lbshift, nest;
};

struct grub_fshelp_node
{
  struct grub_udf_data *data;
  grub_uint32_t part_ref;
  union
  {
    struct grub_udf_file_entry fe;
    struct grub_udf_extended_file_entry efe;
    char raw[0];
  } block;
};

static inline grub_size_t
get_fshelp_size (struct grub_udf_data *data)
{
  struct grub_fshelp_node *x = NULL;
  return sizeof (*x)
    + (1 << (GRUB_DISK_SECTOR_BITS
	     + data->lbshift)) - sizeof (x->block);
}

static grub_dl_t my_mod;

static grub_disk_addr_t
grub_udf_read_block (grub_fshelp_node_t node, grub_disk_addr_t fileblock);

static grub_ssize_t
grub_udf_read_file (grub_fshelp_node_t node,
		    grub_disk_read_hook_t read_hook, void *read_hook_data,
		    grub_off_t pos, grub_size_t len, char *buf);

static grub_uint32_t
grub_udf_get_block (struct grub_udf_data *data, grub_uint32_t part_ref,
		    grub_uint32_t block, grub_uint32_t offset);

/*
 * A virtual partition (UDF 1.50 and 2.00, used on sequentially recorded
 * media such as CD-R/DVD-R) indirects every logical block through the
 * Virtual Allocation Table, a plain file living in the underlying
 * physical partition.
 */
static grub_uint32_t
grub_udf_get_block_virt (struct grub_udf_data *data,
			 struct grub_udf_part *part,
			 grub_uint32_t block, grub_uint32_t offset)
{
  grub_uint32_t entry;

  if (!part->vat || block >= part->vat_entries)
    {
      grub_error (GRUB_ERR_BAD_FS, "block outside of the VAT");
      return 0;
    }

  if (grub_udf_read_file (part->vat, 0, 0,
			  (grub_off_t) part->vat_offset
			  + (grub_off_t) block * sizeof (entry),
			  sizeof (entry), (char *) &entry)
      != (grub_ssize_t) sizeof (entry))
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_BAD_FS, "can\'t read the VAT");
      return 0;
    }

  return grub_udf_get_block (data, part->phys_ref, U32 (entry), offset);
}

/*
 * A sparable partition (UDF 1.50+, used on CD-RW/DVD-RW) relocates
 * defective packets through the sparing table.
 */
static grub_uint32_t
grub_udf_get_block_spar (struct grub_udf_part *part,
			 grub_uint32_t block, grub_uint32_t offset)
{
  grub_uint32_t i, lbn, packet;

  lbn = block + offset;
  packet = lbn & ~(part->packet_len - 1);

  /* The reallocation table is sorted by the original location.  */
  for (i = 0; i < part->spar_entries; i++)
    {
      grub_uint32_t orig = U32 (part->spar_table[i].orig);

      /* 0xfffffff0 and above mark unused and defective entries.  */
      if (orig >= 0xfffffff0)
	break;
      if (orig == packet)
	return (U32 (part->spar_table[i].mapped)
		+ (lbn & (part->packet_len - 1)));
      if (orig > packet)
	break;
    }

  return part->start + lbn;
}

/*
 * A metadata partition (UDF 2.50+, used on Blu-ray) stores all metadata
 * in one regular file of the underlying partition, so that it can be
 * clustered; mapping a block means resolving that file's extents.
 */
static grub_uint32_t
grub_udf_get_block_meta (struct grub_udf_part *part,
			 grub_uint32_t block, grub_uint32_t offset)
{
  if (!part->meta)
    {
      grub_error (GRUB_ERR_BAD_FS, "no metadata file");
      return 0;
    }

  return (grub_uint32_t) grub_udf_read_block (part->meta,
					      (grub_disk_addr_t) block
					      + offset);
}

/*
 * Map BLOCK + OFFSET, a logical block number within the partition
 * PART_REF refers to, onto a physical block number.  Both are native
 * endian.  Returns 0 on error, with grub_errno set.
 */
static grub_uint32_t
grub_udf_get_block (struct grub_udf_data *data, grub_uint32_t part_ref,
		    grub_uint32_t block, grub_uint32_t offset)
{
  struct grub_udf_part *part;
  grub_uint32_t ret;

  if (part_ref >= (grub_uint32_t) data->npm)
    {
      grub_error (GRUB_ERR_BAD_FS, "invalid part ref");
      return 0;
    }

  part = &data->parts[part_ref];

  if (part->type == GRUB_UDF_PMAP_PHYSICAL)
    return part->start + block + offset;

  if (part->type == GRUB_UDF_PMAP_SPARABLE)
    return grub_udf_get_block_spar (part, block, offset);

  /*
   * The virtual and metadata maps resolve a block by reading a file, and
   * on a corrupted medium that file's own descriptors can point straight
   * back here.  Bound the nesting rather than the stack.
   */
  if (data->nest >= GRUB_UDF_MAX_NEST)
    {
      grub_error (GRUB_ERR_BAD_FS, "too many nested partition maps");
      return 0;
    }

  data->nest++;
  switch (part->type)
    {
    case GRUB_UDF_PMAP_VIRTUAL:
      ret = grub_udf_get_block_virt (data, part, block, offset);
      break;

    case GRUB_UDF_PMAP_METADATA:
      ret = grub_udf_get_block_meta (part, block, offset);
      break;

    default:
      grub_error (GRUB_ERR_BAD_FS, "partmap type not supported");
      ret = 0;
    }
  data->nest--;

  return ret;
}

static grub_err_t
grub_udf_read_icb (struct grub_udf_data *data, grub_uint32_t part_ref,
		   grub_uint32_t block_num, struct grub_fshelp_node *node)
{
  grub_uint32_t block;

  block = grub_udf_get_block (data, part_ref, block_num, 0);

  if (grub_errno)
    return grub_errno;

  if (grub_disk_read (data->disk, (grub_disk_addr_t) block << data->lbshift, 0,
		      1 << (GRUB_DISK_SECTOR_BITS
			    + data->lbshift),
		      &node->block))
    return grub_errno;

  if ((U16 (node->block.fe.tag.tag_ident) != GRUB_UDF_TAG_IDENT_FE) &&
      (U16 (node->block.fe.tag.tag_ident) != GRUB_UDF_TAG_IDENT_EFE))
    return grub_error (GRUB_ERR_BAD_FS, "invalid fe/efe descriptor");

  node->part_ref = part_ref;
  node->data = data;
  return 0;
}

static grub_err_t
grub_udf_read_icb_ad (struct grub_udf_data *data,
		      struct grub_udf_long_ad *icb,
		      struct grub_fshelp_node *node)
{
  return grub_udf_read_icb (data, U16 (icb->block.part_ref),
			    U32 (icb->block.block_num), node);
}

/*
 * Follow an allocation extent descriptor: load the continuation of the
 * allocation descriptor list into *BUF and hand back its new bounds.
 */
static grub_err_t
grub_udf_read_aed (grub_fshelp_node_t node, char **buf, char **end_ptr,
		   grub_uint32_t sec, grub_uint32_t adlen, grub_ssize_t *len)
{
  grub_uint32_t bsize = U32 (node->data->lvd.bsize);
  struct grub_udf_aed *extension;
  grub_ssize_t ae_len;

  if (grub_errno)
    return grub_errno;

  if (adlen < sizeof (struct grub_udf_aed) || adlen > bsize)
    return grub_error (GRUB_ERR_BAD_FS, "invalid aed length");

  if (!*buf)
    {
      *buf = grub_malloc (bsize);
      if (!*buf)
	return grub_errno;
    }

  if (grub_disk_read (node->data->disk,
		      (grub_disk_addr_t) sec << node->data->lbshift,
		      0, adlen, *buf))
    return grub_errno;

  extension = (struct grub_udf_aed *) *buf;
  if (U16 (extension->tag.tag_ident) != GRUB_UDF_TAG_IDENT_AED)
    return grub_error (GRUB_ERR_BAD_FS, "invalid aed tag");

  ae_len = (grub_ssize_t) U32 (extension->ae_len);
  /*
   * The continued list has to fit in the extent that was just read,
   * which itself is at most one block per UDF spec v2.01 section 2.3.11.
   */
  if (ae_len < 0
      || ae_len > (grub_ssize_t) (adlen - sizeof (struct grub_udf_aed)))
    return grub_error (GRUB_ERR_BAD_FS, "invalid ae length");

  *end_ptr = *buf + adlen;
  *len = ae_len;
  return GRUB_ERR_NONE;
}

static grub_disk_addr_t
grub_udf_read_block (grub_fshelp_node_t node, grub_disk_addr_t fileblock)
{
  char *buf = NULL;
  char *ptr;
  grub_ssize_t len;
  grub_disk_addr_t filebytes;
  grub_disk_addr_t ret = 0;
  char *end_ptr;

  switch (U16 (node->block.fe.tag.tag_ident))
    {
    case GRUB_UDF_TAG_IDENT_FE:
      ptr = (char *) &node->block.fe.ext_attr[0] + U32 (node->block.fe.ext_attr_length);
      len = U32 (node->block.fe.alloc_descs_length);
      break;

    case GRUB_UDF_TAG_IDENT_EFE:
      ptr = (char *) &node->block.efe.ext_attr[0] + U32 (node->block.efe.ext_attr_length);
      len = U32 (node->block.efe.alloc_descs_length);
      break;

    default:
      grub_error (GRUB_ERR_BAD_FS, "invalid file entry");
      return 0;
    }

  end_ptr = (char *) node + get_fshelp_size (node->data);

  if ((U16 (node->block.fe.icbtag.flags) & GRUB_UDF_ICBTAG_FLAG_AD_MASK)
      == GRUB_UDF_ICBTAG_FLAG_AD_SHORT)
    {
      if (GRUB_UDF_INVALID_STRUCT_PTR (ptr, struct grub_udf_short_ad))
	{
	  grub_error (GRUB_ERR_BAD_FS, "corrupted UDF file system");
	  goto fail;
	}

      struct grub_udf_short_ad *ad = (struct grub_udf_short_ad *) ptr;

      filebytes = fileblock * U32 (node->data->lvd.bsize);
      while (len >= (grub_ssize_t) sizeof (struct grub_udf_short_ad))
	{
	  grub_uint32_t adlen = U32 (ad->length) & 0x3fffffff;
	  grub_uint32_t adtype = U32 (ad->length) >> 30;
	  if (adtype == 3)
	    {
	      grub_uint32_t sec = grub_udf_get_block (node->data,
						      node->part_ref,
						      U32 (ad->position), 0);

	      if (grub_udf_read_aed (node, &buf, &end_ptr, sec, adlen, &len))
		goto fail;

	      ad = (struct grub_udf_short_ad *)
		    (buf + sizeof (struct grub_udf_aed));
	      continue;
	    }

	  if (filebytes < adlen)
	    {
	      /* Extents that are not recorded read back as zeroes.  */
	      if (adtype == 0)
		ret = grub_udf_get_block (node->data, node->part_ref,
					  U32 (ad->position),
					  (grub_uint32_t)
					  (filebytes >> (GRUB_DISK_SECTOR_BITS
						 + node->data->lbshift)));
	      goto fail;
	    }

	  filebytes -= adlen;
	  ad++;
	  len -= sizeof (struct grub_udf_short_ad);

	  if (len >= (grub_ssize_t) sizeof (struct grub_udf_short_ad)
	      && GRUB_UDF_INVALID_STRUCT_PTR (ad, struct grub_udf_short_ad))
	    {
	      grub_error (GRUB_ERR_BAD_FS, "corrupted UDF file system");
	      goto fail;
	    }
	}
    }
  else
    {
      if (GRUB_UDF_INVALID_STRUCT_PTR (ptr, struct grub_udf_long_ad))
	{
	  grub_error (GRUB_ERR_BAD_FS, "corrupted UDF file system");
	  goto fail;
	}

      struct grub_udf_long_ad *ad = (struct grub_udf_long_ad *) ptr;

      filebytes = fileblock * U32 (node->data->lvd.bsize);
      while (len >= (grub_ssize_t) sizeof (struct grub_udf_long_ad))
	{
	  grub_uint32_t adlen = U32 (ad->length) & 0x3fffffff;
	  grub_uint32_t adtype = U32 (ad->length) >> 30;
	  if (adtype == 3)
	    {
	      grub_uint32_t sec = grub_udf_get_block (node->data,
						      U16 (ad->block.part_ref),
						      U32 (ad->block.block_num),
						      0);

	      if (grub_udf_read_aed (node, &buf, &end_ptr, sec, adlen, &len))
		goto fail;

	      ad = (struct grub_udf_long_ad *)
		    (buf + sizeof (struct grub_udf_aed));
	      continue;
	    }

	  if (filebytes < adlen)
	    {
	      /* Extents that are not recorded read back as zeroes.  */
	      if (adtype == 0)
		ret = grub_udf_get_block (node->data,
					  U16 (ad->block.part_ref),
					  U32 (ad->block.block_num),
					  (grub_uint32_t)
					  (filebytes >> (GRUB_DISK_SECTOR_BITS
						 + node->data->lbshift)));
	      goto fail;
	    }

	  filebytes -= adlen;
	  ad++;
	  len -= sizeof (struct grub_udf_long_ad);

	  if (len >= (grub_ssize_t) sizeof (struct grub_udf_long_ad)
	      && GRUB_UDF_INVALID_STRUCT_PTR (ad, struct grub_udf_long_ad))
	    {
	      grub_error (GRUB_ERR_BAD_FS, "corrupted UDF file system");
	      goto fail;
	    }
	}
    }

fail:
  grub_free (buf);

  return ret;
}

static grub_ssize_t
grub_udf_read_file (grub_fshelp_node_t node,
		    grub_disk_read_hook_t read_hook, void *read_hook_data,
		    grub_off_t pos, grub_size_t len, char *buf)
{
  switch (U16 (node->block.fe.icbtag.flags) & GRUB_UDF_ICBTAG_FLAG_AD_MASK)
    {
    case GRUB_UDF_ICBTAG_FLAG_AD_IN_ICB:
      {
	char *ptr;
	char *end_ptr = (char *) node + get_fshelp_size (node->data);

	ptr = ((U16 (node->block.fe.tag.tag_ident) == GRUB_UDF_TAG_IDENT_FE) ?
	       ((char *) &node->block.fe.ext_attr[0]
                + U32 (node->block.fe.ext_attr_length)) :
	       ((char *) &node->block.efe.ext_attr[0]
                + U32 (node->block.efe.ext_attr_length)));

	if (ptr < (char *) &node->block || ptr > end_ptr
	    || pos > (grub_off_t) (end_ptr - ptr)
	    || len > (grub_size_t) (end_ptr - ptr) - pos)
	  {
	    grub_error (GRUB_ERR_BAD_FS, "corrupted UDF file system");
	    return 0;
	  }

	grub_memcpy (buf, ptr + pos, len);

	return len;
      }

    case GRUB_UDF_ICBTAG_FLAG_AD_EXT:
      grub_error (GRUB_ERR_BAD_FS, "invalid extent type");
      return 0;
    }

  return grub_fshelp_read_file (node->data->disk, node,
				read_hook, read_hook_data,
				pos, len, buf, grub_udf_read_block,
				U64 (node->block.fe.file_size),
				node->data->lbshift, 0);
}

/* Release everything the partition maps hang off.  */
static void
grub_udf_free_parts (struct grub_udf_data *data)
{
  int i;

  for (i = 0; i < GRUB_UDF_MAX_PMS; i++)
    {
      grub_free (data->parts[i].spar_table);
      grub_free (data->parts[i].vat);
      grub_free (data->parts[i].meta);
    }

  grub_memset (data->parts, 0, sizeof (data->parts));
  data->npd = data->npm = 0;
}

static void
grub_udf_free_data (struct grub_udf_data *data)
{
  if (!data)
    return;

  grub_udf_free_parts (data);
  grub_free (data);
}

/*
 * Look for an Anchor Volume Descriptor Pointer at BLOCK.  Returns 1 and
 * fills in AVDP when one is found there.
 */
static int
grub_udf_check_anchor (grub_disk_t disk, int lbshift, grub_uint32_t block,
		       struct grub_udf_avdp *avdp)
{
  if (grub_disk_read (disk, (grub_disk_addr_t) block << lbshift, 0,
		      sizeof (*avdp), avdp))
    {
      /* Reading past the end of the medium just means "not here".  */
      grub_errno = GRUB_ERR_NONE;
      return 0;
    }

  return (U16 (avdp->tag.tag_ident) == GRUB_UDF_TAG_IDENT_AVDP
	  && U32 (avdp->tag.tag_location) == block);
}

/*
 * An anchor is recorded at block 256, at the last recorded block and at
 * the last recorded block minus 256 (ECMA-167 3/8.4.2.1); media that are
 * still open only carry the one at 512.  Where the recording ends is
 * frequently misreported, so a few blocks around it get probed as well -
 * this mirrors udf_scan_anchors() of the Linux driver.
 *
 * LAST_BLOCK is set to where the recording was found to end, which is
 * also where the VAT file entry of a sequentially recorded medium lives.
 */
static int
grub_udf_scan_anchor (grub_disk_t disk, int lbshift, grub_uint64_t total,
		      struct grub_udf_avdp *avdp, grub_uint32_t *last_block)
{
  static const grub_uint32_t back[] = { 0, 1, 2, 150, 152 };
  grub_uint64_t last = 0;
  unsigned i;

  if (total != GRUB_DISK_SIZE_UNKNOWN && (total >> lbshift) != 0)
    last = (total >> lbshift) - 1;
  if (last > 0xffffffffULL)
    last = 0;

  *last_block = (grub_uint32_t) last;

  if (grub_udf_check_anchor (disk, lbshift, 256, avdp))
    return 1;

  for (i = 0; last != 0 && i < ARRAY_SIZE (back); i++)
    {
      grub_uint32_t cand;

      if (last < back[i])
	continue;
      cand = (grub_uint32_t) (last - back[i]);

      if (grub_udf_check_anchor (disk, lbshift, cand, avdp)
	  || (cand >= 256
	      && grub_udf_check_anchor (disk, lbshift, cand - 256, avdp)))
	{
	  *last_block = cand;
	  return 1;
	}
    }

  return grub_udf_check_anchor (disk, lbshift, 512, avdp);
}

/*
 * Load the sparing table of a sparable partition (UDF 1.50 2.2.11).
 * Not finding a usable one is not fatal: the partition then simply has
 * no relocated packets.
 */
static grub_err_t
grub_udf_load_sparing (struct grub_udf_data *data, struct grub_udf_part *part,
		       struct grub_udf_partmap *pm)
{
  grub_uint32_t bsize = 1U << (GRUB_DISK_SECTOR_BITS + data->lbshift);
  grub_uint32_t size;
  grub_err_t err = GRUB_ERR_NONE;
  unsigned i, n;
  char *buf;

  if (pm->length < 64)
    return grub_error (GRUB_ERR_BAD_FS, "invalid sparable partition map");

  part->packet_len = U16 (pm->spar.packet_length);
  if (!part->packet_len || (part->packet_len & (part->packet_len - 1)))
    return grub_error (GRUB_ERR_BAD_FS, "invalid sparing packet length");

  n = pm->spar.num_sparing_tables;
  if (n > GRUB_UDF_MAX_SPARING_TABLES)
    return grub_error (GRUB_ERR_BAD_FS, "too many sparing tables");

  size = U32 (pm->spar.size_sparing_table);
  if (size < sizeof (struct grub_udf_sparing_table) || size > bsize)
    return grub_error (GRUB_ERR_BAD_FS, "invalid sparing table size");

  buf = grub_malloc (bsize);
  if (!buf)
    return grub_errno;

  for (i = 0; i < n; i++)
    {
      struct grub_udf_sparing_table *st = (struct grub_udf_sparing_table *) buf;
      grub_uint32_t loc = U32 (pm->spar.loc_sparing_table[i]);
      grub_uint32_t entries;

      if (grub_disk_read (data->disk, (grub_disk_addr_t) loc << data->lbshift,
			  0, size, buf))
	{
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}

      if (U32 (st->tag.tag_location) != loc
	  || grub_memcmp (st->sparing_ident.ident, GRUB_UDF_ID_SPARING,
			  sizeof (GRUB_UDF_ID_SPARING) - 1))
	continue;

      entries = U16 (st->rt_len);
      if (sizeof (*st) + (grub_uint64_t) entries
	  * sizeof (struct grub_udf_sparing_entry) > size)
	continue;

      if (entries)
	{
	  part->spar_table =
	    grub_calloc (entries, sizeof (struct grub_udf_sparing_entry));
	  if (!part->spar_table)
	    {
	      err = grub_errno;
	      break;
	    }

	  grub_memcpy (part->spar_table, buf + sizeof (*st),
		       entries * sizeof (struct grub_udf_sparing_entry));
	}

      part->spar_entries = entries;
      break;
    }

  grub_free (buf);
  return err;
}

static grub_err_t
grub_udf_parse_partmap (struct grub_udf_data *data, struct grub_udf_part *part,
			struct grub_udf_partmap *pm)
{
  const grub_uint8_t *ident;

  if (pm->type == GRUB_UDF_PARTMAP_TYPE_1)
    {
      if (pm->length < 6)
	return grub_error (GRUB_ERR_BAD_FS, "invalid type 1 partition map");

      part->type = GRUB_UDF_PMAP_PHYSICAL;
      part->part_num = U16 (pm->type1.part_num);
      return GRUB_ERR_NONE;
    }

  if (pm->type != GRUB_UDF_PARTMAP_TYPE_2 || pm->length < 40)
    return grub_error (GRUB_ERR_BAD_FS, "partmap type not supported");

  ident = pm->type2.part_ident.ident;
  part->part_num = U16 (pm->type2.part_num);

  if (!grub_memcmp (ident, GRUB_UDF_ID_VIRTUAL,
		    sizeof (GRUB_UDF_ID_VIRTUAL) - 1))
    {
      part->type = GRUB_UDF_PMAP_VIRTUAL;
      /* The identifier suffix opens with the UDF revision.  */
      part->vat20 = ((pm->type2.part_ident.ident_suffix[0]
		      | (pm->type2.part_ident.ident_suffix[1] << 8)) >= 0x0200);
      return GRUB_ERR_NONE;
    }

  if (!grub_memcmp (ident, GRUB_UDF_ID_SPARABLE,
		    sizeof (GRUB_UDF_ID_SPARABLE) - 1))
    {
      part->type = GRUB_UDF_PMAP_SPARABLE;
      return grub_udf_load_sparing (data, part, pm);
    }

  if (!grub_memcmp (ident, GRUB_UDF_ID_METADATA,
		    sizeof (GRUB_UDF_ID_METADATA) - 1))
    {
      if (pm->length < 64)
	return grub_error (GRUB_ERR_BAD_FS, "invalid metadata partition map");

      part->type = GRUB_UDF_PMAP_METADATA;
      part->meta_file_loc = U32 (pm->meta.meta_file_loc);
      part->meta_mirror_loc = U32 (pm->meta.meta_mirror_file_loc);
      return GRUB_ERR_NONE;
    }

  /*
   * Keep the slot: a partition reference number indexes the map table,
   * so dropping an unknown map would shift every later reference.  Using
   * it is what fails, not merely having it around.
   */
  part->type = GRUB_UDF_PMAP_NONE;
  return GRUB_ERR_NONE;
}

/* Walk one Volume Descriptor Sequence, collecting the PVD, PDs and LVD.  */
static grub_err_t
grub_udf_load_vds (struct grub_udf_data *data, struct grub_udf_extent_ad *vds)
{
  grub_uint32_t block = U32 (vds->start);
  grub_uint32_t count = (U32 (vds->length)
			 >> (GRUB_DISK_SECTOR_BITS + data->lbshift));

  if (!count)
    return grub_error (GRUB_ERR_BAD_FS, "empty volume descriptor sequence");
  if (count > 256)
    count = 256;

  for (; count; count--, block++)
    {
      struct grub_udf_tag tag;
      grub_uint16_t ident;

      if (grub_disk_read (data->disk,
			  (grub_disk_addr_t) block << data->lbshift, 0,
			  sizeof (struct grub_udf_tag), &tag))
	return grub_errno;

      ident = U16 (tag.tag_ident);
      if (ident == GRUB_UDF_TAG_IDENT_TD)
	break;

      if (ident == GRUB_UDF_TAG_IDENT_PVD)
	{
	  if (grub_disk_read (data->disk,
			      (grub_disk_addr_t) block << data->lbshift, 0,
			      sizeof (struct grub_udf_pvd), &data->pvd))
	    return grub_errno;
	}
      else if (ident == GRUB_UDF_TAG_IDENT_PD)
	{
	  if (data->npd >= GRUB_UDF_MAX_PDS)
	    return grub_error (GRUB_ERR_BAD_FS, "too many PDs");

	  if (grub_disk_read (data->disk,
			      (grub_disk_addr_t) block << data->lbshift, 0,
			      sizeof (struct grub_udf_pd),
			      &data->pds[data->npd]))
	    return grub_errno;

	  data->npd++;
	}
      else if (ident == GRUB_UDF_TAG_IDENT_LVD)
	{
	  grub_uint32_t k, npm, table_len, offset;

	  if (grub_disk_read (data->disk,
			      (grub_disk_addr_t) block << data->lbshift, 0,
			      sizeof (struct grub_udf_lvd), &data->lvd))
	    return grub_errno;

	  if (U32 (data->lvd.bsize)
	      != (1U << (GRUB_DISK_SECTOR_BITS + data->lbshift)))
	    return grub_error (GRUB_ERR_BAD_FS, "invalid logical block size");

	  table_len = U32 (data->lvd.map_table_length);
	  if (table_len > sizeof (data->lvd.part_maps)
	      || (sizeof (data->lvd) - sizeof (data->lvd.part_maps) + table_len
		  > U32 (data->lvd.bsize)))
	    return grub_error (GRUB_ERR_BAD_FS, "partition table too long");

	  npm = U32 (data->lvd.num_part_maps);
	  if ((grub_uint32_t) data->npm + npm > GRUB_UDF_MAX_PMS)
	    return grub_error (GRUB_ERR_BAD_FS, "too many partition maps");

	  for (k = 0, offset = 0; k < npm; k++)
	    {
	      struct grub_udf_partmap *ppm;

	      if (offset + 2 > table_len)
		return grub_error (GRUB_ERR_BAD_FS, "truncated partition map");

	      ppm = (struct grub_udf_partmap *) (data->lvd.part_maps + offset);
	      if (ppm->length < 2 || offset + ppm->length > table_len)
		return grub_error (GRUB_ERR_BAD_FS, "invalid partition map");

	      if (grub_udf_parse_partmap (data, &data->parts[data->npm], ppm))
		return grub_errno;

	      data->npm++;
	      offset += ppm->length;
	    }
	}
      else if (ident > GRUB_UDF_TAG_IDENT_TD)
	return grub_error (GRUB_ERR_BAD_FS, "invalid tag ident");
    }

  if (!data->npd || !data->npm)
    return grub_error (GRUB_ERR_BAD_FS, "no partition found");

  return GRUB_ERR_NONE;
}

/*
 * Load the file entry of the metadata file of a metadata partition,
 * falling back on the mirror copy.
 */
static grub_err_t
grub_udf_load_metadata (struct grub_udf_data *data, struct grub_udf_part *part)
{
  struct grub_fshelp_node *node;

  node = grub_malloc (get_fshelp_size (data));
  if (!node)
    return grub_errno;

  if (grub_udf_read_icb (data, part->phys_ref, part->meta_file_loc, node))
    {
      grub_errno = GRUB_ERR_NONE;

      if (grub_udf_read_icb (data, part->phys_ref, part->meta_mirror_loc, node))
	{
	  grub_free (node);
	  grub_errno = GRUB_ERR_NONE;
	  return grub_error (GRUB_ERR_BAD_FS,
			     "can\'t read the metadata file entry");
	}
    }

  part->meta = node;
  return GRUB_ERR_NONE;
}

/* Load the Virtual Allocation Table of a virtual partition.  */
static grub_err_t
grub_udf_load_vat (struct grub_udf_data *data, struct grub_udf_part *part)
{
  struct grub_udf_part *phys = &data->parts[part->phys_ref];
  struct grub_fshelp_node *node;
  struct grub_udf_vat20 vat20;
  grub_uint64_t size;
  int i, found = 0;

  node = grub_malloc (get_fshelp_size (data));
  if (!node)
    return grub_errno;

  /*
   * The VAT file entry is the last thing written to the medium.  Some
   * writers leave a few blocks of slack, so search backwards a bit.
   */
  for (i = 0; i < GRUB_UDF_VAT_SEARCH_BACK; i++)
    {
      grub_uint32_t blk;

      if (data->last_block < (grub_uint32_t) i)
	break;

      blk = data->last_block - i;
      if (blk < phys->start)
	break;

      if (!grub_udf_read_icb (data, part->phys_ref, blk - phys->start, node))
	{
	  found = 1;
	  break;
	}

      grub_errno = GRUB_ERR_NONE;
    }

  if (!found)
    {
      grub_free (node);
      return grub_error (GRUB_ERR_BAD_FS, "can\'t find the VAT");
    }

  size = U64 (node->block.fe.file_size);
  if (size > 0xffffffffULL)
    goto fail;

  if (part->vat20
      || node->block.fe.icbtag.file_type == GRUB_UDF_ICBTAG_TYPE_VAT20)
    {
      if (size < sizeof (vat20)
	  || (grub_udf_read_file (node, 0, 0, 0, sizeof (vat20),
				  (char *) &vat20)
	      != (grub_ssize_t) sizeof (vat20)))
	goto fail;

      part->vat_offset = U16 (vat20.length_header);
      if (part->vat_offset < sizeof (vat20) || part->vat_offset > size)
	goto fail;
    }
  else
    {
      /* UDF 1.50 puts the entries first and a 36 byte trailer last.  */
      if (size < 36)
	goto fail;

      part->vat_offset = 0;
      size -= 36;
    }

  part->vat_entries = (grub_uint32_t) ((size - part->vat_offset) >> 2);
  part->vat = node;
  return GRUB_ERR_NONE;

fail:
  grub_free (node);
  grub_errno = GRUB_ERR_NONE;
  return grub_error (GRUB_ERR_BAD_FS, "invalid VAT");
}

static grub_err_t
grub_udf_setup_partitions (struct grub_udf_data *data)
{
  int i, j;

  /* Bind every map to the partition descriptor carrying its number.  */
  for (i = 0; i < data->npm; i++)
    {
      struct grub_udf_part *part = &data->parts[i];

      if (part->type == GRUB_UDF_PMAP_NONE)
	continue;

      for (j = 0; j < data->npd; j++)
	if (U16 (data->pds[j].part_num) == part->part_num)
	  break;

      if (j == data->npd)
	return grub_error (GRUB_ERR_BAD_FS, "can\'t find PD");

      part->start = U32 (data->pds[j].start);
      part->length = U32 (data->pds[j].length);
    }

  /*
   * Virtual and metadata maps are layered on top of the physical or
   * sparable map that shares their partition number.
   */
  for (i = 0; i < data->npm; i++)
    {
      struct grub_udf_part *part = &data->parts[i];

      if (part->type != GRUB_UDF_PMAP_VIRTUAL
	  && part->type != GRUB_UDF_PMAP_METADATA)
	continue;

      for (j = 0; j < data->npm; j++)
	if (j != i && data->parts[j].part_num == part->part_num
	    && (data->parts[j].type == GRUB_UDF_PMAP_PHYSICAL
		|| data->parts[j].type == GRUB_UDF_PMAP_SPARABLE))
	  break;

      if (j == data->npm)
	return grub_error (GRUB_ERR_BAD_FS, "can\'t find the backing partition");

      part->phys_ref = (grub_uint32_t) j;
    }

  /* With the physical mapping in place the metadata can be read.  */
  for (i = 0; i < data->npm; i++)
    {
      struct grub_udf_part *part = &data->parts[i];

      if (part->type == GRUB_UDF_PMAP_METADATA
	  && grub_udf_load_metadata (data, part))
	return grub_errno;

      if (part->type == GRUB_UDF_PMAP_VIRTUAL
	  && grub_udf_load_vat (data, part))
	return grub_errno;
    }

  return GRUB_ERR_NONE;
}

static struct grub_udf_data *
grub_udf_mount (grub_disk_t disk)
{
  struct grub_udf_data *data = 0;
  struct grub_udf_fileset root_fs;
  struct grub_udf_avdp avdp;
  grub_uint64_t total;
  grub_uint32_t block, vblock;
  int lbshift;

  data = grub_zalloc (sizeof (struct grub_udf_data));
  if (!data)
    return 0;

  data->disk = disk;
  total = grub_disk_native_sectors (disk);

  /* Search for Anchor Volume Descriptor Pointer (AVDP)
   * and determine logical block size.  */
  for (lbshift = 0; lbshift < 4; lbshift++)
    if (grub_udf_scan_anchor (disk, lbshift, total, &avdp, &data->last_block))
      break;

  if (lbshift == 4)
    {
      grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
      goto fail;
    }
  data->lbshift = lbshift;

  /* Search for Volume Recognition Sequence (VRS).  */
  for (vblock = (32767 >> (lbshift + GRUB_DISK_SECTOR_BITS)) + 1;;
       vblock += (2047 >> (lbshift + GRUB_DISK_SECTOR_BITS)) + 1)
    {
      struct grub_udf_vrs vrs;

      if (grub_disk_read (disk, vblock << lbshift, 0,
			  sizeof (struct grub_udf_vrs), &vrs))
	{
	  grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	  goto fail;
	}

      if ((!grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_NSR03, 5)) ||
	  (!grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_NSR02, 5)))
	break;

      if ((grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_BEA01, 5)) &&
	  (grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_BOOT2, 5)) &&
	  (grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_CD001, 5)) &&
	  (grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_CDW02, 5)) &&
	  (grub_memcmp (vrs.magic, GRUB_UDF_STD_IDENT_TEA01, 5)))
	{
	  grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
	  goto fail;
	}
    }

  /* Locate Partition Descriptor (PD) and Logical Volume Descriptor (LVD).  */
  if (grub_udf_load_vds (data, &avdp.vds))
    {
      /* The main sequence is unusable, fall back on the reserve one.  */
      grub_errno = GRUB_ERR_NONE;
      grub_udf_free_parts (data);

      if (grub_udf_load_vds (data, &avdp.rvds))
	goto fail;
    }

  if (grub_udf_setup_partitions (data))
    goto fail;

  block = grub_udf_get_block (data,
			      U16 (data->lvd.root_fileset.block.part_ref),
			      U32 (data->lvd.root_fileset.block.block_num), 0);

  if (grub_errno)
    goto fail;

  if (grub_disk_read (disk, (grub_disk_addr_t) block << lbshift, 0,
		      sizeof (struct grub_udf_fileset), &root_fs))
    {
      grub_error (GRUB_ERR_BAD_FS, "not an UDF filesystem");
      goto fail;
    }

  if (U16 (root_fs.tag.tag_ident) != GRUB_UDF_TAG_IDENT_FSD)
    {
      grub_error (GRUB_ERR_BAD_FS, "invalid fileset descriptor");
      goto fail;
    }

  data->root_icb = root_fs.root_icb;

  return data;

fail:
  grub_udf_free_data (data);
  return 0;
}

#ifdef GRUB_UTIL
grub_disk_addr_t
grub_udf_get_cluster_sector (grub_disk_t disk, grub_uint64_t *sec_per_lcn)
{
  grub_disk_addr_t ret;
  static struct grub_udf_data *data;

  data = grub_udf_mount (disk);
  if (!data)
    return 0;

  ret = data->parts[0].start;
  *sec_per_lcn = 1ULL << data->lbshift;
  grub_udf_free_data (data);
  return ret;
}
#endif

static char *
read_string (const grub_uint8_t *raw, grub_size_t sz, char *outbuf)
{
  grub_uint16_t *utf16 = NULL;
  grub_size_t utf16len = 0;

  if (sz == 0)
    return NULL;

  if (raw[0] != 8 && raw[0] != 16)
    return NULL;

  if (raw[0] == 8)
    {
      unsigned i;
      utf16len = sz - 1;
      utf16 = grub_calloc (utf16len, sizeof (utf16[0]));
      if (!utf16)
	return NULL;
      for (i = 0; i < utf16len; i++)
	utf16[i] = raw[i + 1];
    }
  if (raw[0] == 16)
    {
      unsigned i;
      utf16len = (sz - 1) / 2;
      utf16 = grub_calloc (utf16len, sizeof (utf16[0]));
      if (!utf16)
	return NULL;
      for (i = 0; i < utf16len; i++)
	utf16[i] = (raw[2 * i + 1] << 8) | raw[2*i + 2];
    }
  if (!outbuf)
    {
      grub_size_t size;

      if (grub_mul (utf16len, GRUB_MAX_UTF8_PER_UTF16, &size) ||
	  grub_add (size, 1, &size))
	goto fail;

      outbuf = grub_malloc (size);
    }
  if (outbuf)
    *grub_utf16_to_utf8 ((grub_uint8_t *) outbuf, utf16, utf16len) = '\0';

 fail:
  grub_free (utf16);
  return outbuf;
}

static char *
read_dstring (const grub_uint8_t *raw, grub_size_t sz)
{
  grub_size_t len;

  if (raw[0] == 0) {
      char *outbuf = grub_malloc (1);
      if (!outbuf)
	return NULL;
      outbuf[0] = 0;
      return outbuf;
    }

  len = raw[sz - 1];
  if (len > sz - 1)
    len = sz - 1;
  return read_string (raw, len, NULL);
}

static int
grub_udf_iterate_dir (grub_fshelp_node_t dir,
		      grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
  grub_fshelp_node_t child;
  struct grub_udf_file_ident dirent;
  grub_off_t offset = 0;

  child = grub_malloc (get_fshelp_size (dir->data));
  if (!child)
    return 0;

  /* The current directory is not stored.  */
  grub_memcpy (child, dir, get_fshelp_size (dir->data));

  if (hook (".", GRUB_FSHELP_DIR, child, hook_data))
    return 1;

  while (offset < U64 (dir->block.fe.file_size))
    {
      if (grub_udf_read_file (dir, 0, 0, offset, sizeof (dirent),
			      (char *) &dirent) != sizeof (dirent))
	return 0;

      if (U16 (dirent.tag.tag_ident) != GRUB_UDF_TAG_IDENT_FID)
	{
	  grub_error (GRUB_ERR_BAD_FS, "invalid fid tag");
	  return 0;
	}

      offset += sizeof (dirent) + U16 (dirent.imp_use_length);
      if (!(dirent.characteristics & GRUB_UDF_FID_CHAR_DELETED))
	{
	  child = grub_malloc (get_fshelp_size (dir->data));
	  if (!child)
	    return 0;

          if (grub_udf_read_icb_ad (dir->data, &dirent.icb, child))
	    {
	      grub_free (child);
	      return 0;
	    }
          if (dirent.characteristics & GRUB_UDF_FID_CHAR_PARENT)
	    {
	      /* This is the parent directory.  */
	      if (hook ("..", GRUB_FSHELP_DIR, child, hook_data))
	        return 1;
	    }
          else
	    {
	      enum grub_fshelp_filetype type;
	      char *filename;
	      grub_uint8_t raw[MAX_FILE_IDENT_LENGTH];

	      type = ((dirent.characteristics & GRUB_UDF_FID_CHAR_DIRECTORY) ?
		      (GRUB_FSHELP_DIR) : (GRUB_FSHELP_REG));
	      if (child->block.fe.icbtag.file_type == GRUB_UDF_ICBTAG_TYPE_SYMLINK)
		type = GRUB_FSHELP_SYMLINK;

	      if ((grub_udf_read_file (dir, 0, 0, offset,
				       dirent.file_ident_length,
				       (char *) raw))
		  != dirent.file_ident_length)
		{
		  grub_free (child);
		  return 0;
		}

	      filename = read_string (raw, dirent.file_ident_length, 0);
	      if (!filename)
		{
		  /* As the hook won't get called. */
		  grub_free (child);
		  grub_print_error ();
		}

	      if (filename && hook (filename, type, child, hook_data))
		{
		  grub_free (filename);
		  return 1;
		}
	      grub_free (filename);
	    }
	}

      /* Align to dword boundary.  */
      offset = (offset + dirent.file_ident_length + 3) & (~3);
    }

  return 0;
}

static char *
grub_udf_read_symlink (grub_fshelp_node_t node)
{
  grub_size_t s, sz = U64 (node->block.fe.file_size);
  grub_uint8_t *raw;
  const grub_uint8_t *ptr;
  char *out = NULL, *optr;

  if (sz < 4)
    return NULL;
  raw = grub_malloc (sz);
  if (!raw)
    return NULL;
  if (grub_udf_read_file (node, NULL, NULL, 0, sz, (char *) raw) < 0)
    goto fail_1;

  /*
   * Local sz is the size of the symlink file data, which contains a sequence
   * of path components (ECMA-167 14.16.1) representing the link destination.
   * This size is an upper-bound on the number of bytes of a contained and
   * potentially compressed UTF-16 character string. Allocate 2*sz for the
   * output buffer containing the string converted to UTF-8 because the
   * resulting string can not be more than double the size (2-byte unicode
   * code points will be converted to a maximum of 3 bytes in UTF-8).
   */
  if (grub_mul (sz, 2, &s))
    goto fail_0;

  out = grub_malloc (s);
  if (!out)
    {
 fail_0:
      grub_free (raw);
      return NULL;
    }

  optr = out;

  for (ptr = raw; ptr < raw + sz; )
    {
      if ((grub_size_t) (ptr - raw + 4) > sz)
	goto fail_1;
      if (!(ptr[2] == 0 && ptr[3] == 0))
	goto fail_1;
      s = 4 + ptr[1];
      if ((grub_size_t) (ptr - raw + s) > sz)
	goto fail_1;
      switch (*ptr)
	{
	case 1:
	  if (ptr[1])
	    goto fail_1;
	  /* Fallthrough.  */
	case 2:
	  /* in 4 bytes. out: 1 byte.  */
	  optr = out;
	  *optr++ = '/';
	  break;
	case 3:
	  /* in 4 bytes. out: 3 bytes.  */
	  if (optr != out)
	    *optr++ = '/';
	  *optr++ = '.';
	  *optr++ = '.';
	  break;
	case 4:
	  /* in 4 bytes. out: 2 bytes.  */
	  if (optr != out)
	    *optr++ = '/';
	  *optr++ = '.';
	  break;
	case 5:
	  /* in 4 + n bytes. out, at most: 1 + 2 * n bytes.  */
	  if (optr != out)
	    *optr++ = '/';
	  if (!read_string (ptr + 4, s - 4, optr))
	    goto fail_1;
	  optr += grub_strlen (optr);
	  break;
	default:
	  goto fail_1;
	}
      ptr += s;
    }
  *optr = 0;
  grub_free (raw);
  return out;

 fail_1:
  grub_free (raw);
  grub_free (out);
  grub_error (GRUB_ERR_BAD_FS, "invalid symlink");
  return NULL;
}

/* Context for grub_udf_dir.  */
struct grub_udf_dir_ctx
{
  grub_fs_dir_hook_t hook;
  void *hook_data;
};

/* Helper for grub_udf_dir.  */
static int
grub_udf_dir_iter (const char *filename, enum grub_fshelp_filetype filetype,
		   grub_fshelp_node_t node, void *data)
{
  struct grub_udf_dir_ctx *ctx = data;
  struct grub_dirhook_info info;
  const struct grub_udf_timestamp *tstamp = NULL;

  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  info.symlink = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK);
  if (U16 (node->block.fe.tag.tag_ident) == GRUB_UDF_TAG_IDENT_FE)
    tstamp = &node->block.fe.modification_time;
  else if (U16 (node->block.fe.tag.tag_ident) == GRUB_UDF_TAG_IDENT_EFE)
    tstamp = &node->block.efe.modification_time;

  if (tstamp && (U16 (tstamp->type_and_timezone) & 0xf000) == 0x1000)
    {
      grub_int16_t tz;
      struct grub_datetime datetime;

      datetime.year = U16 (tstamp->year);
      datetime.month = tstamp->month;
      datetime.day = tstamp->day;
      datetime.hour = tstamp->hour;
      datetime.minute = tstamp->minute;
      datetime.second = tstamp->second;

      tz = U16 (tstamp->type_and_timezone) & 0xfff;
      if (tz & 0x800)
	tz |= 0xf000;
      if (tz == -2047)
	tz = 0;

      info.mtimeset = !!grub_datetime2unixtime (&datetime, &info.mtime);

      info.mtime -= 60 * tz;
    }
  grub_free (node);
  return ctx->hook (filename, &info, ctx->hook_data);
}

static grub_err_t
grub_udf_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
  struct grub_udf_dir_ctx ctx = { hook, hook_data };
  struct grub_udf_data *data = 0;
  struct grub_fshelp_node *rootnode = 0;
  struct grub_fshelp_node *foundnode = 0;

  grub_dl_ref (my_mod);

  data = grub_udf_mount (device->disk);
  if (!data)
    goto fail;

  rootnode = grub_malloc (get_fshelp_size (data));
  if (!rootnode)
    goto fail;

  if (grub_udf_read_icb_ad (data, &data->root_icb, rootnode))
    goto fail;

  if (grub_fshelp_find_file (path, rootnode,
			     &foundnode,
			     grub_udf_iterate_dir, grub_udf_read_symlink,
			     GRUB_FSHELP_DIR))
    goto fail;

  grub_udf_iterate_dir (foundnode, grub_udf_dir_iter, &ctx);

  if (foundnode != rootnode)
    grub_free (foundnode);

fail:
  grub_free (rootnode);

  grub_udf_free_data (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_udf_open (struct grub_file *file, const char *name)
{
  struct grub_udf_data *data;
  struct grub_fshelp_node *rootnode = 0;
  struct grub_fshelp_node *foundnode;

  grub_dl_ref (my_mod);

  data = grub_udf_mount (file->device->disk);
  if (!data)
    goto fail;

  rootnode = grub_malloc (get_fshelp_size (data));
  if (!rootnode)
    goto fail;

  if (grub_udf_read_icb_ad (data, &data->root_icb, rootnode))
    goto fail;

  if (grub_fshelp_find_file (name, rootnode,
			     &foundnode,
			     grub_udf_iterate_dir, grub_udf_read_symlink,
			     GRUB_FSHELP_REG))
    goto fail;

  file->data = foundnode;
  file->offset = 0;
  file->size = U64 (foundnode->block.fe.file_size);

  grub_free (rootnode);

  return 0;

fail:
  grub_dl_unref (my_mod);

  grub_udf_free_data (data);
  grub_free (rootnode);

  return grub_errno;
}

static grub_ssize_t
grub_udf_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_fshelp_node *node = (struct grub_fshelp_node *) file->data;

  return grub_udf_read_file (node, file->read_hook, file->read_hook_data,
			     file->offset, len, buf);
}

static grub_err_t
grub_udf_close (grub_file_t file)
{
  if (file->data)
    {
      struct grub_fshelp_node *node = (struct grub_fshelp_node *) file->data;

      grub_udf_free_data (node->data);
      grub_free (node);
    }

  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_udf_label (grub_device_t device, char **label)
{
  struct grub_udf_data *data;
  data = grub_udf_mount (device->disk);

  if (data)
    {
      *label = read_dstring (data->lvd.ident, sizeof (data->lvd.ident));
      grub_udf_free_data (data);
    }
  else
    *label = 0;

  return grub_errno;
}

static char *
gen_uuid_from_volset (char *volset_ident)
{
  grub_size_t i;
  grub_size_t len;
  grub_size_t nonhexpos;
  grub_uint8_t buf[17];
  char *uuid;

  len = grub_strlen (volset_ident);
  if (len < 8)
    return NULL;

  uuid = grub_malloc (17);
  if (!uuid)
    return NULL;

  if (len > 16)
    len = 16;

  grub_memset (buf, 0, sizeof (buf));
  grub_memcpy (buf, volset_ident, len);

  nonhexpos = 16;
  for (i = 0; i < 16; ++i)
    {
      if (!grub_isxdigit (buf[i]))
        {
          nonhexpos = i;
          break;
        }
    }

  if (nonhexpos < 8)
    {
      grub_snprintf (uuid, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
                    buf[0], buf[1], buf[2], buf[3],
                    buf[4], buf[5], buf[6], buf[7]);
    }
  else if (nonhexpos < 16)
    {
      for (i = 0; i < 8; ++i)
        uuid[i] = grub_tolower (buf[i]);
      grub_snprintf (uuid+8, 9, "%02x%02x%02x%02x",
                    buf[8], buf[9], buf[10], buf[11]);
    }
  else
    {
      for (i = 0; i < 16; ++i)
        uuid[i] = grub_tolower (buf[i]);
      uuid[16] = 0;
    }

  return uuid;
}

static grub_err_t
grub_udf_uuid (grub_device_t device, char **uuid)
{
  char *volset_ident;
  struct grub_udf_data *data;
  data = grub_udf_mount (device->disk);

  if (data)
    {
      volset_ident = read_dstring (data->pvd.volset_ident, sizeof (data->pvd.volset_ident));
      if (volset_ident)
        {
          *uuid = gen_uuid_from_volset (volset_ident);
          grub_free (volset_ident);
        }
      else
        *uuid = 0;
      grub_udf_free_data (data);
    }
  else
    *uuid = 0;

  return grub_errno;
}

static struct grub_fs grub_udf_fs = {
  .name = "udf",
  .fs_dir = grub_udf_dir,
  .fs_open = grub_udf_open,
  .fs_read = grub_udf_read,
  .fs_close = grub_udf_close,
  .fs_label = grub_udf_label,
  .fs_uuid = grub_udf_uuid,
#ifdef GRUB_UTIL
  .reserved_first_sector = 1,
  .blocklist_install = 1,
#endif
  .next = 0
};

GRUB_MOD_INIT (udf)
{
  if (!grub_is_lockdown ())
    {
      grub_udf_fs.mod = mod;
      grub_fs_register (&grub_udf_fs);
    }
  my_mod = mod;
}

GRUB_MOD_FINI (udf)
{
  if (!grub_is_lockdown ())
    grub_fs_unregister (&grub_udf_fs);
}
