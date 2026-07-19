/* $Id: VHDX.cpp $ */
/** @file
 * VHDX - VHDX Disk image, Core Code.
 */

 /*
  * Copyright (C) 2012-2023 Oracle and/or its affiliates.
  *
  * This file is part of VirtualBox base platform packages, as
  * available from https://www.virtualbox.org.
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of the GNU General Public License
  * as published by the Free Software Foundation, in version 3 of the
  * License.
  *
  * This program is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, see <https://www.gnu.org/licenses>.
  *
  * SPDX-License-Identifier: GPL-3.0-only
  */


#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>

#include <vbox.h>

GRUB_MOD_LICENSE("GPLv3+");

  /*********************************************************************************************************************************
  *   On disk data structures                                                                                                      *
  *********************************************************************************************************************************/

  /**
   * VHDX file type identifier.
   */
#pragma pack(1)
typedef struct VhdxFileIdentifier
{
	/** Signature. */
	grub_uint64_t    u64Signature;
	/** Creator ID - UTF-16 string (not neccessarily null terminated). */
	grub_uint16_t    awszCreator[256];
} VhdxFileIdentifier;
#pragma pack()
/** Pointer to an on disk VHDX file type identifier. */
typedef VhdxFileIdentifier* PVhdxFileIdentifier;

/** VHDX file type identifier signature ("vhdxfile"). */
#define VHDX_FILE_IDENTIFIER_SIGNATURE 0x656c696678646876ULL
/** Start offset of the VHDX file type identifier. */
#define VHDX_FILE_IDENTIFIER_OFFSET    0

/**
 * VHDX header.
 */
#pragma pack(1)
typedef struct VhdxHeader
{
	/** Signature. */
	grub_uint32_t    u32Signature;
	/** Checksum. */
	grub_uint32_t    u32Checksum;
	/** Sequence number. */
	grub_uint64_t    u64SequenceNumber;
	/** File write UUID. */
	RTUUID      UuidFileWrite;
	/** Data write UUID. */
	RTUUID      UuidDataWrite;
	/** Log UUID. */
	RTUUID      UuidLog;
	/** Version of the log format. */
	grub_uint16_t    u16LogVersion;
	/** VHDX format version. */
	grub_uint16_t    u16Version;
	/** Length of the log region. */
	grub_uint32_t    u32LogLength;
	/** Start offset of the log offset in the file. */
	grub_uint64_t    u64LogOffset;
	/** Reserved bytes. */
	grub_uint8_t     u8Reserved[4016];
} VhdxHeader;
#pragma pack()
/** Pointer to an on disk VHDX header. */
typedef VhdxHeader* PVhdxHeader;

/** VHDX header signature ("head"). */
#define VHDX_HEADER_SIGNATURE    0x64616568U
/** Start offset of the first VHDX header. */
#define VHDX_HEADER1_OFFSET      _64K
/** Start offset of the second VHDX header. */
#define VHDX_HEADER2_OFFSET      _128K
/** Current Log format version. */
#define VHDX_HEADER_LOG_VERSION  0U
/** Current VHDX format version. */
#define VHDX_HEADER_VHDX_VERSION 1U

/**
 * VHDX region table header
 */
#pragma pack(1)
typedef struct VhdxRegionTblHdr
{
	/** Signature. */
	grub_uint32_t    u32Signature;
	/** Checksum. */
	grub_uint32_t    u32Checksum;
	/** Number of region table entries following this header. */
	grub_uint32_t    u32EntryCount;
	/** Reserved. */
	grub_uint32_t    u32Reserved;
} VhdxRegionTblHdr;
#pragma pack()
/** Pointer to an on disk VHDX region table header. */
typedef VhdxRegionTblHdr* PVhdxRegionTblHdr;

/** VHDX region table header signature. */
#define VHDX_REGION_TBL_HDR_SIGNATURE       0x69676572U
/** Maximum number of entries which can follow. */
#define VHDX_REGION_TBL_HDR_ENTRY_COUNT_MAX 2047U
/** Offset where the region table is stored (192 KB). */
#define VHDX_REGION_TBL_HDR_OFFSET          196608ULL
/** Maximum size of the region table. */
#define VHDX_REGION_TBL_SIZE_MAX            _64K

/**
 * VHDX region table entry.
 */
#pragma pack(1)
typedef struct VhdxRegionTblEntry
{
	/** Object UUID. */
	RTUUID      UuidObject;
	/** File offset of the region. */
	grub_uint64_t    u64FileOffset;
	/** Length of the region in bytes. */
	grub_uint32_t    u32Length;
	/** Flags for this object. */
	grub_uint32_t    u32Flags;
} VhdxRegionTblEntry;
#pragma pack()
/** Pointer to an on disk VHDX region table entry. */
typedef struct VhdxRegionTblEntry* PVhdxRegionTblEntry;

/** Flag whether this region is required. */
#define VHDX_REGION_TBL_ENTRY_FLAGS_IS_REQUIRED RT_BIT_32(0)
/** UUID for the BAT region. */
#define VHDX_REGION_TBL_ENTRY_UUID_BAT          "2dc27766-f623-4200-9d64-115e9bfd4a08"
/** UUID for the metadata region. */
#define VHDX_REGION_TBL_ENTRY_UUID_METADATA     "8b7ca206-4790-4b9a-b8fe-575f050f886e"

/**
 * VHDX Log entry header.
 */
#pragma pack(1)
typedef struct VhdxLogEntryHdr
{
	/** Signature. */
	grub_uint32_t    u32Signature;
	/** Checksum. */
	grub_uint32_t    u32Checksum;
	/** Total length of the entry in bytes. */
	grub_uint32_t    u32EntryLength;
	/** Tail of the log entries. */
	grub_uint32_t    u32Tail;
	/** Sequence number. */
	grub_uint64_t    u64SequenceNumber;
	/** Number of descriptors in this log entry. */
	grub_uint32_t    u32DescriptorCount;
	/** Reserved. */
	grub_uint32_t    u32Reserved;
	/** Log UUID. */
	RTUUID      UuidLog;
	/** VHDX file size in bytes while the log entry was written. */
	grub_uint64_t    u64FlushedFileOffset;
	/** File size in bytes all allocated file structures fit into when the
	 * log entry was written. */
	grub_uint64_t    u64LastFileOffset;
} VhdxLogEntryHdr;
#pragma pack()
/** Pointer to an on disk VHDX log entry header. */
typedef struct VhdxLogEntryHdr* PVhdxLogEntryHdr;

/** VHDX log entry signature ("loge"). */
#define VHDX_LOG_ENTRY_HEADER_SIGNATURE 0x65676f6cU

/**
 * VHDX log zero descriptor.
 */
#pragma pack(1)
typedef struct VhdxLogZeroDesc
{
	/** Signature of this descriptor. */
	grub_uint32_t    u32ZeroSignature;
	/** Reserved. */
	grub_uint32_t    u32Reserved;
	/** Length of the section to zero. */
	grub_uint64_t    u64ZeroLength;
	/** File offset to write zeros to. */
	grub_uint64_t    u64FileOffset;
	/** Sequence number (must macht the field in the log entry header). */
	grub_uint64_t    u64SequenceNumber;
} VhdxLogZeroDesc;
#pragma pack()
/** Pointer to an on disk VHDX log zero descriptor. */
typedef struct VhdxLogZeroDesc* PVhdxLogZeroDesc;

/** Signature of a VHDX log zero descriptor ("zero"). */
#define VHDX_LOG_ZERO_DESC_SIGNATURE 0x6f72657aU

/**
 * VHDX log data descriptor.
 */
#pragma pack(1)
typedef struct VhdxLogDataDesc
{
	/** Signature of this descriptor. */
	grub_uint32_t    u32DataSignature;
	/** Trailing 4 bytes removed from the update. */
	grub_uint32_t    u32TrailingBytes;
	/** Leading 8 bytes removed from the update. */
	grub_uint64_t    u64LeadingBytes;
	/** File offset to write zeros to. */
	grub_uint64_t    u64FileOffset;
	/** Sequence number (must macht the field in the log entry header). */
	grub_uint64_t    u64SequenceNumber;
} VhdxLogDataDesc;
#pragma pack()
/** Pointer to an on disk VHDX log data descriptor. */
typedef struct VhdxLogDataDesc* PVhdxLogDataDesc;

/** Signature of a VHDX log data descriptor ("desc"). */
#define VHDX_LOG_DATA_DESC_SIGNATURE 0x63736564U

/**
 * VHDX log data sector.
 */
#pragma pack(1)
typedef struct VhdxLogDataSector
{
	/** Signature of the data sector. */
	grub_uint32_t    u32DataSignature;
	/** 4 most significant bytes of the sequence number. */
	grub_uint32_t    u32SequenceHigh;
	/** Raw data associated with the update. */
	grub_uint8_t     u8Data[4084];
	/** 4 least significant bytes of the sequence number. */
	grub_uint32_t    u32SequenceLow;
} VhdxLogDataSector;
#pragma pack()
/** Pointer to an on disk VHDX log data sector. */
typedef VhdxLogDataSector* PVhdxLogDataSector;

/** Signature of a VHDX log data sector ("data"). */
#define VHDX_LOG_DATA_SECTOR_SIGNATURE 0x61746164U

/**
 * VHDX BAT entry.
 */
#pragma pack(1)
typedef struct VhdxBatEntry
{
	/** The BAT entry, contains state and offset. */
	grub_uint64_t    u64BatEntry;
} VhdxBatEntry;
#pragma pack()
typedef VhdxBatEntry* PVhdxBatEntry;

/** Return the BAT state from a given entry. */
#define VHDX_BAT_ENTRY_GET_STATE(bat) ((bat) & 0x7ULL)
/** Get the FileOffsetMB field from a given BAT entry. */
#define VHDX_BAT_ENTRY_GET_FILE_OFFSET_MB(bat) (((bat) & 0xfffffffffff00000ULL) >> 20)
/** Get a byte offset from the BAT entry. */
#define VHDX_BAT_ENTRY_GET_FILE_OFFSET(bat) (VHDX_BAT_ENTRY_GET_FILE_OFFSET_MB(bat) * (grub_uint64_t)_1M)
#define VHDX_BAT_ENTRY_VALID_MASK             0xfffffffffff00007ULL

/** Minimum and maximum payload block sizes allowed by the specification. */
#define VHDX_BLOCK_SIZE_MIN _1M
#define VHDX_BLOCK_SIZE_MAX (256U * _1M)
#define VHDX_VDISK_SIZE_MAX RT_BIT_64(46)

/** Block not present and the data is undefined. */
#define VHDX_BAT_ENTRY_PAYLOAD_BLOCK_NOT_PRESENT       (0)
/** Data in this block is undefined. */
#define VHDX_BAT_ENTRY_PAYLOAD_BLOCK_UNDEFINED         (1)
/** Data in this block contains zeros. */
#define VHDX_BAT_ENTRY_PAYLOAD_BLOCK_ZERO              (2)
/** Block was unmapped by the application or system and data is either zero or
 * the data before the block was unmapped. */
#define VHDX_BAT_ENTRY_PAYLOAD_BLOCK_UNMAPPED          (3)
 /** Block data is in the file pointed to by the FileOffsetMB field. */
#define VHDX_BAT_ENTRY_PAYLOAD_BLOCK_FULLY_PRESENT     (6)
/** Block is partially present, use sector bitmap to get present sectors. */
#define VHDX_BAT_ENTRY_PAYLOAD_BLOCK_PARTIALLY_PRESENT (7)

/** The sector bitmap block is undefined and not allocated in the file. */
#define VHDX_BAT_ENTRY_SB_BLOCK_NOT_PRESENT            (0)
/** The sector bitmap block is defined at the file location. */
#define VHDX_BAT_ENTRY_SB_BLOCK_PRESENT                (6)

/**
 * VHDX Metadata tabl header.
 */
#pragma pack(1)
typedef struct VhdxMetadataTblHdr
{
	/** Signature. */
	grub_uint64_t    u64Signature;
	/** Reserved. */
	grub_uint16_t    u16Reserved;
	/** Number of entries in the table. */
	grub_uint16_t    u16EntryCount;
	/** Reserved */
	grub_uint32_t    u32Reserved2[5];
} VhdxMetadataTblHdr;
#pragma pack()
/** Pointer to an on disk metadata table header. */
typedef VhdxMetadataTblHdr* PVhdxMetadataTblHdr;

/** Signature of a VHDX metadata table header ("metadata"). */
#define VHDX_METADATA_TBL_HDR_SIGNATURE       0x617461646174656dULL
/** Maximum number of entries the metadata table can have. */
#define VHDX_METADATA_TBL_HDR_ENTRY_COUNT_MAX 2047U

/**
 * VHDX Metadata table entry.
 */
#pragma pack(1)
typedef struct VhdxMetadataTblEntry
{
	/** Item UUID. */
	RTUUID      UuidItem;
	/** Offset of the metadata item. */
	grub_uint32_t    u32Offset;
	/** Length of the metadata item. */
	grub_uint32_t    u32Length;
	/** Flags for the metadata item. */
	grub_uint32_t    u32Flags;
	/** Reserved. */
	grub_uint32_t    u32Reserved;
} VhdxMetadataTblEntry;
#pragma pack()
/** Pointer to an on disk metadata table entry. */
typedef VhdxMetadataTblEntry* PVhdxMetadataTblEntry;

/** FLag whether the metadata item is system or user metadata. */
#define VHDX_METADATA_TBL_ENTRY_FLAGS_IS_USER     RT_BIT_32(0)
/** FLag whether the metadata item is file or virtual disk metadata. */
#define VHDX_METADATA_TBL_ENTRY_FLAGS_IS_VDISK    RT_BIT_32(1)
/** FLag whether the backend must understand the metadata item to load the image. */
#define VHDX_METADATA_TBL_ENTRY_FLAGS_IS_REQUIRED RT_BIT_32(2)

/** File parameters item UUID. */
#define VHDX_METADATA_TBL_ENTRY_ITEM_FILE_PARAMS    "caa16737-fa36-4d43-b3b6-33f0aa44e76b"
/** Virtual disk size item UUID. */
#define VHDX_METADATA_TBL_ENTRY_ITEM_VDISK_SIZE     "2fa54224-cd1b-4876-b211-5dbed83bf4b8"
/** Page 83 UUID. */
#define VHDX_METADATA_TBL_ENTRY_ITEM_PAGE83_DATA    "beca12ab-b2e6-4523-93ef-c309e000c746"
/** Logical sector size UUID. */
#define VHDX_METADATA_TBL_ENTRY_ITEM_LOG_SECT_SIZE  "8141bf1d-a96f-4709-ba47-f233a8faab5f"
/** Physical sector size UUID. */
#define VHDX_METADATA_TBL_ENTRY_ITEM_PHYS_SECT_SIZE "cda348c7-445d-4471-9cc9-e9885251c556"
/** Parent locator UUID. */
#define VHDX_METADATA_TBL_ENTRY_ITEM_PARENT_LOCATOR "a8d35f2d-b30b-454d-abf7-d3d84834ab0c"

/**
 * VHDX File parameters metadata item.
 */
#pragma pack(1)
typedef struct VhdxFileParameters
{
	/** Block size. */
	grub_uint32_t    u32BlockSize;
	/** Flags. */
	grub_uint32_t    u32Flags;
} VhdxFileParameters;
#pragma pack()
/** Pointer to an on disk VHDX file parameters metadata item. */
typedef struct VhdxFileParameters* PVhdxFileParameters;

/** Flag whether to leave blocks allocated in the file or if it is possible to unmap them. */
#define VHDX_FILE_PARAMETERS_FLAGS_LEAVE_BLOCKS_ALLOCATED RT_BIT_32(0)
/** Flag whether this file has a parent VHDX file. */
#define VHDX_FILE_PARAMETERS_FLAGS_HAS_PARENT             RT_BIT_32(1)

/**
 * VHDX virtual disk size metadata item.
 */
#pragma pack(1)
typedef struct VhdxVDiskSize
{
	/** Virtual disk size. */
	grub_uint64_t    u64VDiskSize;
} VhdxVDiskSize;
#pragma pack()
/** Pointer to an on disk VHDX virtual disk size metadata item. */
typedef struct VhdxVDiskSize* PVhdxVDiskSize;

/**
 * VHDX page 83 data metadata item.
 */
#pragma pack(1)
typedef struct VhdxPage83Data
{
	/** UUID for the SCSI device. */
	RTUUID      UuidPage83Data;
} VhdxPage83Data;
#pragma pack()
/** Pointer to an on disk VHDX vpage 83 data metadata item. */
typedef struct VhdxPage83Data* PVhdxPage83Data;

/**
 * VHDX virtual disk logical sector size.
 */
#pragma pack(1)
typedef struct VhdxVDiskLogicalSectorSize
{
	/** Logical sector size. */
	grub_uint32_t    u32LogicalSectorSize;
} VhdxVDiskLogicalSectorSize;
#pragma pack()
/** Pointer to an on disk VHDX virtual disk logical sector size metadata item. */
typedef struct VhdxVDiskLogicalSectorSize* PVhdxVDiskLogicalSectorSize;

/**
 * VHDX virtual disk physical sector size.
 */
#pragma pack(1)
typedef struct VhdxVDiskPhysicalSectorSize
{
	/** Physical sector size. */
	grub_uint32_t    u32PhysicalSectorSize;
} VhdxVDiskPhysicalSectorSize;
#pragma pack()
/** Pointer to an on disk VHDX virtual disk physical sector size metadata item. */
typedef struct VhdxVDiskPhysicalSectorSize* PVhdxVDiskPhysicalSectorSize;

/**
 * VHDX parent locator header.
 */
#pragma pack(1)
typedef struct VhdxParentLocatorHeader
{
	/** Locator type UUID. */
	RTUUID      UuidLocatorType;
	/** Reserved. */
	grub_uint16_t    u16Reserved;
	/** Number of key value pairs. */
	grub_uint16_t    u16KeyValueCount;
} VhdxParentLocatorHeader;
#pragma pack()
/** Pointer to an on disk VHDX parent locator header metadata item. */
typedef struct VhdxParentLocatorHeader* PVhdxParentLocatorHeader;

/** VHDX parent locator type. */
#define VHDX_PARENT_LOCATOR_TYPE_VHDX "b04aefb7-d19e-4a81-b789-25b8e9445913"

/**
 * VHDX parent locator entry.
 */
#pragma pack(1)
typedef struct VhdxParentLocatorEntry
{
	/** Offset of the key. */
	grub_uint32_t    u32KeyOffset;
	/** Offset of the value. */
	grub_uint32_t    u32ValueOffset;
	/** Length of the key. */
	grub_uint16_t    u16KeyLength;
	/** Length of the value. */
	grub_uint16_t    u16ValueLength;
} VhdxParentLocatorEntry;
#pragma pack()
/** Pointer to an on disk VHDX parent locator entry. */
typedef struct VhdxParentLocatorEntry* PVhdxParentLocatorEntry;


/*********************************************************************************************************************************
*   Constants And Macros, Structures and Typedefs                                                                                *
*********************************************************************************************************************************/

typedef enum VHDXMETADATAITEM
{
	VHDXMETADATAITEM_UNKNOWN = 0,
	VHDXMETADATAITEM_FILE_PARAMS,
	VHDXMETADATAITEM_VDISK_SIZE,
	VHDXMETADATAITEM_PAGE83_DATA,
	VHDXMETADATAITEM_LOGICAL_SECTOR_SIZE,
	VHDXMETADATAITEM_PHYSICAL_SECTOR_SIZE,
	VHDXMETADATAITEM_PARENT_LOCATOR,
	VHDXMETADATAITEM_32BIT_HACK = 0x7fffffff
} VHDXMETADATAITEM;

/**
 * Table to validate the metadata item UUIDs and the flags.
 */
typedef struct VHDXMETADATAITEMPROPS
{
	/** Item UUID. */
	const char* pszItemUuid;
	/** Flag whether this is a user or system metadata item. */
	int                 fIsUser;
	/** Flag whether this is a virtual disk or file metadata item. */
	int                 fIsVDisk;
	/** Flag whether this metadata item is required to load the file. */
	int                 fIsRequired;
	/** Metadata item enum associated with this UUID. */
	VHDXMETADATAITEM     enmMetadataItem;
} VHDXMETADATAITEMPROPS;

/**
 * VHDX image data structure.
 */
typedef struct VHDXIMAGE
{
	/** Descriptor file if applicable. */
	grub_file_t File;
	/** File size on the host disk (including all headers). */
	grub_uint64_t   FileSize;

	/** Open flags passed by VBoxHD layer. */
	unsigned            uOpenFlags;
	/** Image flags defined during creation or determined during open. */
	unsigned            uImageFlags;
	/** Version of the VHDX image format. */
	unsigned            uVersion;
	/** Data write UUID of the current header. */
	RTUUID               UuidDataWrite;
	/** Reserved log region from the current header. */
	grub_uint64_t        offLog;
	grub_uint32_t        cbLog;
	/** Total size of the image. */
	grub_uint64_t            cbSize;
	/** Logical sector size of the image. */
	grub_uint32_t            cbLogicalSector;
	/** Block size of the image. */
	grub_size_t              cbBlock;

	/** The BAT. */
	PVhdxBatEntry       paBat;
	/** Number of entries in the BAT (including sector bitmap entries). */
	grub_uint32_t            cBatEntries;
	/** Chunk ratio. */
	grub_uint32_t            uChunkRatio;

	/** Parent path from the parent locator (UTF-8), if any. */
	char* pszParentPath;
	/** Expected data write UUID of the parent image. */
	RTUUID               UuidParentLinkage;
	/** Whether a valid parent_linkage locator entry was present. */
	int                   fParentLinkagePresent;
	/** Opened parent image (differencing images only). */
	grub_file_t         Parent;
} VHDXIMAGE, * PVHDXIMAGE;

struct grub_vhdx
{
	grub_file_t file;
	void* vhdx;
};
typedef struct grub_vhdx* grub_vhdx_t;

static struct grub_fs grub_vhdx_fs;

/**
 * Endianess conversion direction.
 */
typedef enum VHDXECONV
{
	/** Host to file endianess. */
	VHDXECONV_H2F = 0,
	/** File to host endianess. */
	VHDXECONV_F2H
} VHDXECONV;

/** Macros for endianess conversion. */
#define SET_ENDIAN_U16(u16) (enmConv == VHDXECONV_H2F ? RT_H2LE_U16(u16) : RT_LE2H_U16(u16))
#define SET_ENDIAN_U32(u32) (enmConv == VHDXECONV_H2F ? RT_H2LE_U32(u32) : RT_LE2H_U32(u32))
#define SET_ENDIAN_U64(u64) (enmConv == VHDXECONV_H2F ? RT_H2LE_U64(u64) : RT_LE2H_U64(u64))


/*********************************************************************************************************************************
*   Static Variables                                                                                                             *
*********************************************************************************************************************************/

/**
 * Static table to verify the metadata item properties and the flags.
 */
static const VHDXMETADATAITEMPROPS s_aVhdxMetadataItemProps[] =
{
	/* pcszItemUuid                               fIsUser, fIsVDisk, fIsRequired, enmMetadataItem */
	{VHDX_METADATA_TBL_ENTRY_ITEM_FILE_PARAMS,    0,   0,     1,        VHDXMETADATAITEM_FILE_PARAMS},
	{VHDX_METADATA_TBL_ENTRY_ITEM_VDISK_SIZE,     0,   1,     1,        VHDXMETADATAITEM_VDISK_SIZE},
	{VHDX_METADATA_TBL_ENTRY_ITEM_PAGE83_DATA,    0,   1,     1,        VHDXMETADATAITEM_PAGE83_DATA},
	{VHDX_METADATA_TBL_ENTRY_ITEM_LOG_SECT_SIZE,  0,   1,     1,        VHDXMETADATAITEM_LOGICAL_SECTOR_SIZE},
	{VHDX_METADATA_TBL_ENTRY_ITEM_PHYS_SECT_SIZE, 0,   1,     1,        VHDXMETADATAITEM_PHYSICAL_SECTOR_SIZE},
	{VHDX_METADATA_TBL_ENTRY_ITEM_PARENT_LOCATOR, 0,   0,     1,        VHDXMETADATAITEM_PARENT_LOCATOR}
};

#define VHDX_METADATA_PRESENT(item) RT_BIT_32((item) - 1)
#define VHDX_METADATA_REQUIRED \
	(VHDX_METADATA_PRESENT(VHDXMETADATAITEM_FILE_PARAMS) \
		| VHDX_METADATA_PRESENT(VHDXMETADATAITEM_VDISK_SIZE) \
		| VHDX_METADATA_PRESENT(VHDXMETADATAITEM_PAGE83_DATA) \
		| VHDX_METADATA_PRESENT(VHDXMETADATAITEM_LOGICAL_SECTOR_SIZE) \
		| VHDX_METADATA_PRESENT(VHDXMETADATAITEM_PHYSICAL_SECTOR_SIZE))

static int
vhdxFileReadSync(PVHDXIMAGE pImage, grub_uint64_t off, void* pvBuf, grub_size_t cbRead, grub_ssize_t* pcbRead)
{
	grub_ssize_t bytesRead;
	if (grub_file_seek(pImage->File, off) == (grub_off_t)-1)
	{
		if (pcbRead)
			*pcbRead = -1;
		return GRUB_ERR_OUT_OF_RANGE;
	}

	bytesRead = grub_file_read(pImage->File, pvBuf, cbRead);
	if (pcbRead)
		*pcbRead = bytesRead;
	if (bytesRead < 0)
		return GRUB_ERR_FILE_READ_ERROR;
	if ((grub_size_t)bytesRead != cbRead)
		return grub_error(GRUB_ERR_FILE_READ_ERROR, "short read in VHDX image");
	return GRUB_ERR_NONE;
}

/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

/**
 * Converts the file identifier between file and host endianness.
 *
 * @param   enmConv             Direction of the conversion.
 * @param   pFileIdentifierConv Where to store the converted file identifier.
 * @param   pFileIdentifier     The file identifier to convert.
 *
 * @note It is safe to use the same pointer for pFileIdentifierConv and pFileIdentifier.
 */
static void
vhdxConvFileIdentifierEndianess(VHDXECONV enmConv, PVhdxFileIdentifier pFileIdentifierConv,
	PVhdxFileIdentifier pFileIdentifier)
{
	pFileIdentifierConv->u64Signature = SET_ENDIAN_U64(pFileIdentifier->u64Signature);
	for (unsigned i = 0; i < RT_ELEMENTS(pFileIdentifierConv->awszCreator); i++)
		pFileIdentifierConv->awszCreator[i] = SET_ENDIAN_U16(pFileIdentifier->awszCreator[i]);
}

/**
 * Converts a UUID between file and host endianness.
 *
 * @param   enmConv             Direction of the conversion.
 * @param   pUuidConv           Where to store the converted UUID.
 * @param   pUuid               The UUID to convert.
 *
 * @note It is safe to use the same pointer for pUuidConv and pUuid.
 */
static void
vhdxConvUuidEndianess(VHDXECONV enmConv, PRTUUID pUuidConv, PRTUUID pUuid)
{
	(void)enmConv;
	/** @todo r=andy Code looks temporary disabled to me, fixes strict release builds:
	 *        "accessing 16 bytes at offsets 0 and 0 overlaps 16 bytes at offset 0 [-Werror=restrict]" */
	RTUUID uuidTmp;
	grub_memcpy(&uuidTmp, pUuid, sizeof(RTUUID));
	grub_memcpy(pUuidConv, &uuidTmp, sizeof(RTUUID));
}

/**
 * Converts a VHDX header between file and host endianness.
 *
 * @param   enmConv             Direction of the conversion.
 * @param   pHdrConv            Where to store the converted header.
 * @param   pHdr                The VHDX header to convert.
 *
 * @note It is safe to use the same pointer for pHdrConv and pHdr.
 */
static void
vhdxConvHeaderEndianess(VHDXECONV enmConv, PVhdxHeader pHdrConv, PVhdxHeader pHdr)
{
	pHdrConv->u32Signature = SET_ENDIAN_U32(pHdr->u32Signature);
	pHdrConv->u32Checksum = SET_ENDIAN_U32(pHdr->u32Checksum);
	pHdrConv->u64SequenceNumber = SET_ENDIAN_U64(pHdr->u64SequenceNumber);
	vhdxConvUuidEndianess(enmConv, &pHdrConv->UuidFileWrite, &pHdr->UuidFileWrite);
	vhdxConvUuidEndianess(enmConv, &pHdrConv->UuidDataWrite, &pHdr->UuidDataWrite);
	vhdxConvUuidEndianess(enmConv, &pHdrConv->UuidLog, &pHdr->UuidLog);
	pHdrConv->u16LogVersion = SET_ENDIAN_U16(pHdr->u16LogVersion);
	pHdrConv->u16Version = SET_ENDIAN_U16(pHdr->u16Version);
	pHdrConv->u32LogLength = SET_ENDIAN_U32(pHdr->u32LogLength);
	pHdrConv->u64LogOffset = SET_ENDIAN_U64(pHdr->u64LogOffset);
}

/**
 * Converts a VHDX region table header between file and host endianness.
 *
 * @param   enmConv             Direction of the conversion.
 * @param   pRegTblHdrConv      Where to store the converted header.
 * @param   pRegTblHdr          The VHDX region table header to convert.
 *
 * @note It is safe to use the same pointer for pRegTblHdrConv and pRegTblHdr.
 */
static void
vhdxConvRegionTblHdrEndianess(VHDXECONV enmConv, PVhdxRegionTblHdr pRegTblHdrConv,
	PVhdxRegionTblHdr pRegTblHdr)
{
	pRegTblHdrConv->u32Signature = SET_ENDIAN_U32(pRegTblHdr->u32Signature);
	pRegTblHdrConv->u32Checksum = SET_ENDIAN_U32(pRegTblHdr->u32Checksum);
	pRegTblHdrConv->u32EntryCount = SET_ENDIAN_U32(pRegTblHdr->u32EntryCount);
	pRegTblHdrConv->u32Reserved = SET_ENDIAN_U32(pRegTblHdr->u32Reserved);
}

/**
 * Converts a VHDX region table entry between file and host endianness.
 *
 * @param   enmConv             Direction of the conversion.
 * @param   pRegTblEntConv      Where to store the converted region table entry.
 * @param   pRegTblEnt          The VHDX region table entry to convert.
 *
 * @note It is safe to use the same pointer for pRegTblEntConv and pRegTblEnt.
 */
static void
vhdxConvRegionTblEntryEndianess(VHDXECONV enmConv, PVhdxRegionTblEntry pRegTblEntConv,
	PVhdxRegionTblEntry pRegTblEnt)
{
	vhdxConvUuidEndianess(enmConv, &pRegTblEntConv->UuidObject, &pRegTblEnt->UuidObject);
	pRegTblEntConv->u64FileOffset = SET_ENDIAN_U64(pRegTblEnt->u64FileOffset);
	pRegTblEntConv->u32Length = SET_ENDIAN_U32(pRegTblEnt->u32Length);
	pRegTblEntConv->u32Flags = SET_ENDIAN_U32(pRegTblEnt->u32Flags);
}

/**
 * Converts a BAT between file and host endianess.
 *
 * @param   enmConv             Direction of the conversion.
 * @param   paBatEntriesConv    Where to store the converted BAT.
 * @param   paBatEntries        The VHDX BAT to convert.
 * @param   cBatEntries         Number of entries in the BAT.
 *
 * @note It is safe to use the same pointer for paBatEntriesConv and paBatEntries.
 */
static void
vhdxConvBatTableEndianess(VHDXECONV enmConv, PVhdxBatEntry paBatEntriesConv,
	PVhdxBatEntry paBatEntries, grub_uint32_t cBatEntries)
{
	for (grub_uint32_t i = 0; i < cBatEntries; i++)
		paBatEntriesConv[i].u64BatEntry = SET_ENDIAN_U64(paBatEntries[i].u64BatEntry);
}

/**
 * Converts a VHDX metadata table header between file and host endianness.
 *
 * @param   enmConv             Direction of the conversion.
 * @param   pMetadataTblHdrConv Where to store the converted metadata table header.
 * @param   pMetadataTblHdr     The VHDX metadata table header to convert.
 *
 * @note It is safe to use the same pointer for pMetadataTblHdrConv and pMetadataTblHdr.
 */
static void
vhdxConvMetadataTblHdrEndianess(VHDXECONV enmConv, PVhdxMetadataTblHdr pMetadataTblHdrConv,
	PVhdxMetadataTblHdr pMetadataTblHdr)
{
	pMetadataTblHdrConv->u64Signature = SET_ENDIAN_U64(pMetadataTblHdr->u64Signature);
	pMetadataTblHdrConv->u16Reserved = SET_ENDIAN_U16(pMetadataTblHdr->u16Reserved);
	pMetadataTblHdrConv->u16EntryCount = SET_ENDIAN_U16(pMetadataTblHdr->u16EntryCount);
	for (unsigned i = 0; i < RT_ELEMENTS(pMetadataTblHdr->u32Reserved2); i++)
		pMetadataTblHdrConv->u32Reserved2[i] = SET_ENDIAN_U32(pMetadataTblHdr->u32Reserved2[i]);
}

/**
 * Converts a VHDX metadata table entry between file and host endianness.
 *
 * @param   enmConv               Direction of the conversion.
 * @param   pMetadataTblEntryConv Where to store the converted metadata table entry.
 * @param   pMetadataTblEntry     The VHDX metadata table entry to convert.
 *
 * @note It is safe to use the same pointer for pMetadataTblEntryConv and pMetadataTblEntry.
 */
static void
vhdxConvMetadataTblEntryEndianess(VHDXECONV enmConv, PVhdxMetadataTblEntry pMetadataTblEntryConv,
	PVhdxMetadataTblEntry pMetadataTblEntry)
{
	vhdxConvUuidEndianess(enmConv, &pMetadataTblEntryConv->UuidItem, &pMetadataTblEntry->UuidItem);
	pMetadataTblEntryConv->u32Offset = SET_ENDIAN_U32(pMetadataTblEntry->u32Offset);
	pMetadataTblEntryConv->u32Length = SET_ENDIAN_U32(pMetadataTblEntry->u32Length);
	pMetadataTblEntryConv->u32Flags = SET_ENDIAN_U32(pMetadataTblEntry->u32Flags);
	pMetadataTblEntryConv->u32Reserved = SET_ENDIAN_U32(pMetadataTblEntry->u32Reserved);
}

/**
 * Converts a VHDX file parameters item between file and host endianness.
 *
 * @param   enmConv               Direction of the conversion.
 * @param   pFileParamsConv       Where to store the converted file parameters item entry.
 * @param   pFileParams           The VHDX file parameters item to convert.
 *
 * @note It is safe to use the same pointer for pFileParamsConv and pFileParams.
 */
static void
vhdxConvFileParamsEndianess(VHDXECONV enmConv, PVhdxFileParameters pFileParamsConv,
	PVhdxFileParameters pFileParams)
{
	pFileParamsConv->u32BlockSize = SET_ENDIAN_U32(pFileParams->u32BlockSize);
	pFileParamsConv->u32Flags = SET_ENDIAN_U32(pFileParams->u32Flags);
}

/**
 * Converts a VHDX virtual disk size item between file and host endianness.
 *
 * @param   enmConv               Direction of the conversion.
 * @param   pVDiskSizeConv        Where to store the converted virtual disk size item entry.
 * @param   pVDiskSize            The VHDX virtual disk size item to convert.
 *
 * @note It is safe to use the same pointer for pVDiskSizeConv and pVDiskSize.
 */
static void
vhdxConvVDiskSizeEndianess(VHDXECONV enmConv, PVhdxVDiskSize pVDiskSizeConv,
	PVhdxVDiskSize pVDiskSize)
{
	pVDiskSizeConv->u64VDiskSize = SET_ENDIAN_U64(pVDiskSize->u64VDiskSize);
}

/**
 * Converts a VHDX logical sector size item between file and host endianness.
 *
 * @param   enmConv               Direction of the conversion.
 * @param   pVDiskLogSectSizeConv Where to store the converted logical sector size item entry.
 * @param   pVDiskLogSectSize     The VHDX logical sector size item to convert.
 *
 * @note It is safe to use the same pointer for pVDiskLogSectSizeConv and pVDiskLogSectSize.
 */
static void
vhdxConvVDiskLogSectSizeEndianess(VHDXECONV enmConv, PVhdxVDiskLogicalSectorSize pVDiskLogSectSizeConv,
	PVhdxVDiskLogicalSectorSize pVDiskLogSectSize)
{
	pVDiskLogSectSizeConv->u32LogicalSectorSize = SET_ENDIAN_U32(pVDiskLogSectSize->u32LogicalSectorSize);
}

static void
vhdxConvVDiskPhysSectSizeEndianess(VHDXECONV enmConv, PVhdxVDiskPhysicalSectorSize pVDiskPhysSectSizeConv,
	PVhdxVDiskPhysicalSectorSize pVDiskPhysSectSize)
{
	pVDiskPhysSectSizeConv->u32PhysicalSectorSize = SET_ENDIAN_U32(pVDiskPhysSectSize->u32PhysicalSectorSize);
}

/**
 * Internal. Free all allocated space for representing an image except pImage,
 * and optionally delete the image from disk.
 */
static int vhdxFreeImage(PVHDXIMAGE pImage)
{
	int rc = GRUB_ERR_NONE;

	/* Freeing a never allocated image (e.g. because the open failed) is
	 * not signalled as an error. After all nothing bad happens. */
	if (pImage)
	{
		if (pImage->Parent)
		{
			grub_file_close(pImage->Parent);
			pImage->Parent = NULL;
		}
		if (pImage->pszParentPath)
		{
			grub_free(pImage->pszParentPath);
			pImage->pszParentPath = NULL;
		}
		if (pImage->paBat)
		{
			grub_free(pImage->paBat);
			pImage->paBat = NULL;
		}
	}

	return rc;
}

/**
 * Loads all required fields from the given VHDX header.
 * The header must be converted to the host endianess and validated already.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 * @param   pHdr      The header to load.
 */
static int vhdxLoadHeader(PVHDXIMAGE pImage, PVhdxHeader pHdr)
{
	int rc = GRUB_ERR_NONE;
	/*
	 * Most fields in the header are not required because the backend implements
	 * readonly access only so far.
	 * We just have to check that the log is empty, we have to refuse to load the
	 * image otherwsie because replaying the log is not implemented.
	 */
	if (pHdr->u16Version == VHDX_HEADER_VHDX_VERSION
		&& pHdr->u16LogVersion == VHDX_HEADER_LOG_VERSION
		&& (pHdr->u32LogLength & (_1M - 1)) == 0
		&& (pHdr->u64LogOffset & (_1M - 1)) == 0
		&& (pHdr->u32LogLength == 0
			|| (pHdr->u64LogOffset >= _1M
				&& pHdr->u64LogOffset <= pImage->FileSize
				&& pHdr->u32LogLength <= pImage->FileSize - pHdr->u64LogOffset)))
	{
		/* Check that the log UUID is zero. */
		pImage->uVersion = pHdr->u16Version;
		if (!RTUuidIsNull(&pHdr->UuidLog))
			rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
		else
		{
			grub_memcpy(&pImage->UuidDataWrite, &pHdr->UuidDataWrite,
				sizeof(pImage->UuidDataWrite));
			pImage->offLog = pHdr->u64LogOffset;
			pImage->cbLog = pHdr->u32LogLength;
		}
	}
	else
		rc = GRUB_ERR_NOT_IMPLEMENTED_YET;

	return rc;
}

/**
 * Determines the current header and loads it.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 */
static int vhdxFindAndLoadCurrentHeader(PVHDXIMAGE pImage)
{
	PVhdxHeader pHdr1, pHdr2;
	grub_uint32_t u32ChkSum = 0;
	grub_uint32_t u32ChkSumSaved = 0;
	int fHdr1Valid = 0;
	int fHdr2Valid = 0;
	int rc = GRUB_ERR_NONE;

	/*
	 * The VHDX format defines two headers at different offsets to provide failure
	 * consistency. Only one header is current. This can be determined using the
	 * sequence number and checksum fields in the header.
	 */
	pHdr1 = (PVhdxHeader)grub_zalloc(sizeof(VhdxHeader));
	pHdr2 = (PVhdxHeader)grub_zalloc(sizeof(VhdxHeader));

	if (pHdr1 && pHdr2)
	{
		/* Read the first header. */
		rc = vhdxFileReadSync(pImage, VHDX_HEADER1_OFFSET,
			pHdr1, sizeof(*pHdr1), NULL);
		if (RT_SUCCESS(rc))
		{
			vhdxConvHeaderEndianess(VHDXECONV_F2H, pHdr1, pHdr1);

			/* Validate checksum. */
			u32ChkSumSaved = pHdr1->u32Checksum;
			pHdr1->u32Checksum = 0;
			u32ChkSum = RTCrc32C(pHdr1, sizeof(VhdxHeader));

			if (pHdr1->u32Signature == VHDX_HEADER_SIGNATURE
				&& u32ChkSum == u32ChkSumSaved)
				fHdr1Valid = 1;
		}

		/* Try to read the second header in any case (even if reading the first failed). */
		rc = vhdxFileReadSync(pImage, VHDX_HEADER2_OFFSET,
			pHdr2, sizeof(*pHdr2), NULL);
		if (RT_SUCCESS(rc))
		{
			vhdxConvHeaderEndianess(VHDXECONV_F2H, pHdr2, pHdr2);

			/* Validate checksum. */
			u32ChkSumSaved = pHdr2->u32Checksum;
			pHdr2->u32Checksum = 0;
			u32ChkSum = RTCrc32C(pHdr2, sizeof(VhdxHeader));

			if (pHdr2->u32Signature == VHDX_HEADER_SIGNATURE
				&& u32ChkSum == u32ChkSumSaved)
				fHdr2Valid = 1;
		}

		/* Determine the current header. */
		if (fHdr1Valid != fHdr2Valid)
		{
			/* Only one header is valid - use it. */
			rc = vhdxLoadHeader(pImage, fHdr1Valid ? pHdr1 : pHdr2);
		}
		else if (!fHdr1Valid && !fHdr2Valid)
		{
			/* Crap, both headers are corrupt, refuse to load the image. */
			rc = GRUB_ERR_BAD_DEVICE;
		}
		else
		{
			/* Both headers are valid. Use the sequence number to find the current one. */
			if (pHdr1->u64SequenceNumber > pHdr2->u64SequenceNumber)
				rc = vhdxLoadHeader(pImage, pHdr1);
			else if (pHdr1->u64SequenceNumber < pHdr2->u64SequenceNumber)
				rc = vhdxLoadHeader(pImage, pHdr2);
			else if (!grub_memcmp(pHdr1, pHdr2, sizeof(*pHdr1)))
				rc = vhdxLoadHeader(pImage, pHdr1);
			else
				rc = GRUB_ERR_BAD_DEVICE;
		}
	}
	else
		rc = GRUB_ERR_OUT_OF_MEMORY;

	if (pHdr1)
		grub_free(pHdr1);
	if (pHdr2)
		grub_free(pHdr2);

	return rc;
}

/**
 * Loads the BAT region.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 * @param   offRegion Start offset of the region.
 * @param   cbRegion  Size of the region.
 */
static int
vhdxLoadBatRegion(PVHDXIMAGE pImage, grub_uint64_t offRegion,
	grub_size_t cbRegion, PVhdxRegionTblEntry paRegions, grub_uint32_t cRegions)
{
	int rc = GRUB_ERR_NONE;
	grub_uint32_t cDataBlocks;
	grub_uint32_t uChunkRatio;
	grub_uint32_t cChunks;
	grub_uint32_t cBatEntries;
	grub_uint32_t cbBatEntries;
	PVhdxBatEntry paBatEntries = NULL;
	grub_uint64_t uChunkRatio64;
	grub_uint64_t cDataBlocks64;
	grub_uint64_t cBatEntries64;
	grub_uint64_t cbBatEntries64;

	/* The metadata region has been processed by now; make sure the
	 * values the calculations below depend on are sane. */
	if (pImage->cbSize == 0
		|| pImage->cbSize > VHDX_VDISK_SIZE_MAX
		|| pImage->cbBlock < VHDX_BLOCK_SIZE_MIN
		|| pImage->cbBlock > VHDX_BLOCK_SIZE_MAX
		|| (pImage->cbBlock & (pImage->cbBlock - 1)) != 0
		|| (pImage->cbLogicalSector != 512 && pImage->cbLogicalSector != 4096)
		|| pImage->cbSize % pImage->cbLogicalSector)
		return GRUB_ERR_BAD_DEVICE;

	/* Calculate required values first. */
	uChunkRatio64 = (RT_BIT_64(23) * pImage->cbLogicalSector) / pImage->cbBlock;
	uChunkRatio = (grub_uint32_t)uChunkRatio64;
	if (uChunkRatio == 0)
		return GRUB_ERR_BAD_DEVICE;
	cDataBlocks64 = pImage->cbSize / pImage->cbBlock;
	if (pImage->cbSize % pImage->cbBlock)
		cDataBlocks64++;
	if (cDataBlocks64 > ~(grub_uint32_t)0)
		return GRUB_ERR_BAD_DEVICE;
	cDataBlocks = (grub_uint32_t)cDataBlocks64;

	cChunks = cDataBlocks / uChunkRatio;
	if (cDataBlocks % uChunkRatio)
		cChunks++;

	/* Payload block n lives at BAT index n + n / uChunkRatio (a sector
	 * bitmap entry is interleaved after every uChunkRatio payload
	 * entries).  Differencing images additionally need the trailing
	 * sector bitmap entry of the last (possibly partial) chunk. */
	cBatEntries64 = cDataBlocks64 + (cDataBlocks64 - 1) / uChunkRatio;
	if (pImage->uImageFlags & VD_IMAGE_FLAGS_DIFF)
	{
		grub_uint64_t cBatEntriesDiff = (grub_uint64_t)cChunks * (uChunkRatio + 1);
		if (cBatEntriesDiff > cBatEntries64)
			cBatEntries64 = cBatEntriesDiff;
	}
	cbBatEntries64 = cBatEntries64 * sizeof(VhdxBatEntry);
	if (cBatEntries64 > ~(grub_uint32_t)0
		|| cbBatEntries64 > ~(grub_uint32_t)0)
		return GRUB_ERR_BAD_DEVICE;
	cBatEntries = (grub_uint32_t)cBatEntries64;
	cbBatEntries = (grub_uint32_t)cbBatEntries64;

	if (cbBatEntries <= cbRegion)
	{
		/*
		 * Load the complete BAT region first, convert to host endianess and process
		 * it afterwards. The SB entries can be removed because they are not needed yet.
		 */
		paBatEntries = (PVhdxBatEntry)grub_malloc(cbBatEntries);
		if (paBatEntries)
		{
			rc = vhdxFileReadSync(pImage, offRegion,
				paBatEntries, cbBatEntries, NULL);
			if (RT_SUCCESS(rc))
			{
				vhdxConvBatTableEndianess(VHDXECONV_F2H, paBatEntries, paBatEntries,
					cBatEntries);

				/* Validate entry states, reserved bits and all referenced
				 * file ranges before exposing the image. */
				for (grub_uint32_t i = 0, idxData = 0; i < cBatEntries; i++)
				{
					grub_uint64_t uEntry = paBatEntries[i].u64BatEntry;
					grub_uint64_t offFile = VHDX_BAT_ENTRY_GET_FILE_OFFSET(uEntry);
					grub_uint32_t uState = (grub_uint32_t)VHDX_BAT_ENTRY_GET_STATE(uEntry);
					int fSectorBitmap = (i % (uChunkRatio + 1)) == uChunkRatio;

					if (uEntry & ~VHDX_BAT_ENTRY_VALID_MASK)
					{
						rc = GRUB_ERR_BAD_DEVICE;
						break;
					}

					if (fSectorBitmap)
					{
						if (uState == VHDX_BAT_ENTRY_SB_BLOCK_NOT_PRESENT)
						{
							/* The file offset is reserved; tolerate legacy images
							 * which did not clear it. */
						}
						else if (uState == VHDX_BAT_ENTRY_SB_BLOCK_PRESENT)
						{
							if (offFile < _1M
								|| offFile > pImage->FileSize
								|| _1M > pImage->FileSize - offFile)
								rc = GRUB_ERR_BAD_DEVICE;
							for (grub_uint32_t j = 0; RT_SUCCESS(rc) && j < cRegions; j++)
								if (offFile < paRegions[j].u64FileOffset + paRegions[j].u32Length
									&& paRegions[j].u64FileOffset < offFile + _1M)
									rc = GRUB_ERR_BAD_DEVICE;
							if (RT_SUCCESS(rc) && pImage->cbLog != 0
								&& offFile < pImage->offLog + pImage->cbLog
								&& pImage->offLog < offFile + _1M)
								rc = GRUB_ERR_BAD_DEVICE;
						}
						else
							rc = GRUB_ERR_BAD_DEVICE;
					}
					else
					{
						if (idxData >= cDataBlocks)
						{
							if (uEntry != 0)
								rc = GRUB_ERR_BAD_DEVICE;
						}
						else if (uState == VHDX_BAT_ENTRY_PAYLOAD_BLOCK_FULLY_PRESENT
							|| uState == VHDX_BAT_ENTRY_PAYLOAD_BLOCK_PARTIALLY_PRESENT)
						{
							grub_uint64_t offVirtual = (grub_uint64_t)idxData * pImage->cbBlock;
							grub_uint64_t cbBlock = RT_MIN((grub_uint64_t)pImage->cbBlock,
								pImage->cbSize - offVirtual);

							if ((uState == VHDX_BAT_ENTRY_PAYLOAD_BLOCK_PARTIALLY_PRESENT
									&& !(pImage->uImageFlags & VD_IMAGE_FLAGS_DIFF))
								|| offFile < _1M
								|| offFile > pImage->FileSize
								|| cbBlock > pImage->FileSize - offFile)
								rc = GRUB_ERR_BAD_DEVICE;
							for (grub_uint32_t j = 0; RT_SUCCESS(rc) && j < cRegions; j++)
								if (offFile < paRegions[j].u64FileOffset + paRegions[j].u32Length
									&& paRegions[j].u64FileOffset < offFile + cbBlock)
									rc = GRUB_ERR_BAD_DEVICE;
							if (RT_SUCCESS(rc) && pImage->cbLog != 0
								&& offFile < pImage->offLog + pImage->cbLog
								&& pImage->offLog < offFile + cbBlock)
								rc = GRUB_ERR_BAD_DEVICE;
						}
						else if (uState == VHDX_BAT_ENTRY_PAYLOAD_BLOCK_NOT_PRESENT
							|| uState == VHDX_BAT_ENTRY_PAYLOAD_BLOCK_UNDEFINED
							|| uState == VHDX_BAT_ENTRY_PAYLOAD_BLOCK_ZERO
							|| uState == VHDX_BAT_ENTRY_PAYLOAD_BLOCK_UNMAPPED)
						{
							/* No file range is read for these states. */
						}
						else
							rc = GRUB_ERR_BAD_DEVICE;
						idxData++;
					}

					if (RT_FAILURE(rc))
						break;
				}

				if (RT_SUCCESS(rc))
				{
					pImage->paBat = paBatEntries;
					pImage->cBatEntries = cBatEntries;
					pImage->uChunkRatio = uChunkRatio;
				}
			}
			else
				rc = GRUB_ERR_BAD_DEVICE;
		}
		else
			rc = GRUB_ERR_OUT_OF_MEMORY;
	}
	else
		rc = GRUB_ERR_BAD_DEVICE;

	if (RT_FAILURE(rc)
		&& paBatEntries)
		grub_free(paBatEntries);

	return rc;
}

/**
 * Load the file parameters metadata item from the file.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 * @param   offItem   File offset where the data is stored.
 * @param   cbItem    Size of the item in the file.
 */
static int
vhdxLoadFileParametersMetadata(PVHDXIMAGE pImage, grub_uint64_t offItem, grub_size_t cbItem)
{
	int rc = GRUB_ERR_NONE;

	if (cbItem != sizeof(VhdxFileParameters))
		rc = GRUB_ERR_BAD_DEVICE;
	else
	{
		VhdxFileParameters FileParameters;

		rc = vhdxFileReadSync(pImage, offItem,
			&FileParameters, sizeof(FileParameters), NULL);
		if (RT_SUCCESS(rc))
		{
			vhdxConvFileParamsEndianess(VHDXECONV_F2H, &FileParameters, &FileParameters);
			if (FileParameters.u32Flags
				& ~(VHDX_FILE_PARAMETERS_FLAGS_LEAVE_BLOCKS_ALLOCATED
					| VHDX_FILE_PARAMETERS_FLAGS_HAS_PARENT))
				return GRUB_ERR_BAD_DEVICE;
			pImage->cbBlock = FileParameters.u32BlockSize;

			/* Differencing image, the parent is opened after the
			 * parent locator has been seen. */
			if (FileParameters.u32Flags & VHDX_FILE_PARAMETERS_FLAGS_HAS_PARENT)
				pImage->uImageFlags |= VD_IMAGE_FLAGS_DIFF;
		}
		else
			rc = GRUB_ERR_IO;
	}

	return rc;
}

/**
 * Load the virtual disk size metadata item from the file.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 * @param   offItem   File offset where the data is stored.
 * @param   cbItem    Size of the item in the file.
 */
static int
vhdxLoadVDiskSizeMetadata(PVHDXIMAGE pImage, grub_uint64_t offItem, grub_size_t cbItem)
{
	int rc = GRUB_ERR_NONE;

	if (cbItem != sizeof(VhdxVDiskSize))
		rc = GRUB_ERR_BAD_DEVICE;
	else
	{
		VhdxVDiskSize VDiskSize;

		rc = vhdxFileReadSync(pImage, offItem,
			&VDiskSize, sizeof(VDiskSize), NULL);
		if (RT_SUCCESS(rc))
		{
			vhdxConvVDiskSizeEndianess(VHDXECONV_F2H, &VDiskSize, &VDiskSize);
			pImage->cbSize = VDiskSize.u64VDiskSize;
		}
		else
			rc = GRUB_ERR_BAD_DEVICE;
	}

	return rc;
}

/**
 * Load the logical sector size metadata item from the file.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 * @param   offItem   File offset where the data is stored.
 * @param   cbItem    Size of the item in the file.
 */
static int
vhdxLoadVDiskLogSectorSizeMetadata(PVHDXIMAGE pImage, grub_uint64_t offItem, grub_size_t cbItem)
{
	int rc = GRUB_ERR_NONE;

	if (cbItem != sizeof(VhdxVDiskLogicalSectorSize))
		rc = GRUB_ERR_BAD_DEVICE;
	else
	{
		VhdxVDiskLogicalSectorSize VDiskLogSectSize;

		rc = vhdxFileReadSync(pImage, offItem,
			&VDiskLogSectSize, sizeof(VDiskLogSectSize), NULL);
		if (RT_SUCCESS(rc))
		{
			vhdxConvVDiskLogSectSizeEndianess(VHDXECONV_F2H, &VDiskLogSectSize,
				&VDiskLogSectSize);
			pImage->cbLogicalSector = VDiskLogSectSize.u32LogicalSectorSize;
		}
		else
			rc = GRUB_ERR_BAD_DEVICE;
	}

	return rc;
}

static int
vhdxLoadVDiskPhysSectorSizeMetadata(PVHDXIMAGE pImage, grub_uint64_t offItem, grub_size_t cbItem)
{
	VhdxVDiskPhysicalSectorSize VDiskPhysSectSize;
	int rc;

	if (cbItem != sizeof(VDiskPhysSectSize))
		return GRUB_ERR_BAD_DEVICE;
	rc = vhdxFileReadSync(pImage, offItem, &VDiskPhysSectSize,
		sizeof(VDiskPhysSectSize), NULL);
	if (RT_FAILURE(rc))
		return GRUB_ERR_IO;
	vhdxConvVDiskPhysSectSizeEndianess(VHDXECONV_F2H, &VDiskPhysSectSize,
		&VDiskPhysSectSize);
	if (VDiskPhysSectSize.u32PhysicalSectorSize != 512
		&& VDiskPhysSectSize.u32PhysicalSectorSize != 4096)
		return GRUB_ERR_BAD_DEVICE;
	return GRUB_ERR_NONE;
}

/**
 * Load the parent locator metadata item and extract the parent path.
 * (Rover addition, VirtualBox never implemented differencing VHDX.)
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 * @param   offItem   File offset where the data is stored.
 * @param   cbItem    Size of the item in the file.
 */
static int
vhdxLoadParentLocatorMetadata(PVHDXIMAGE pImage, grub_uint64_t offItem, grub_size_t cbItem)
{
	int rc = GRUB_ERR_NONE;
	VhdxParentLocatorHeader LocatorHdr;
	grub_uint8_t* pbLocator = NULL;
	PVhdxParentLocatorEntry pEntry;
	char* pszRelPath = NULL;
	char* pszAbsPath = NULL;
	unsigned i;

	if (cbItem < sizeof(VhdxParentLocatorHeader) || cbItem > _64K)
		return GRUB_ERR_BAD_DEVICE;

	pbLocator = (grub_uint8_t*)grub_malloc(cbItem);
	if (!pbLocator)
		return GRUB_ERR_OUT_OF_MEMORY;

	rc = vhdxFileReadSync(pImage, offItem, pbLocator, cbItem, NULL);
	if (RT_FAILURE(rc))
	{
		grub_free(pbLocator);
		return GRUB_ERR_IO;
	}

	grub_memcpy(&LocatorHdr, pbLocator, sizeof(LocatorHdr));
	LocatorHdr.u16Reserved = RT_LE2H_U16(LocatorHdr.u16Reserved);
	LocatorHdr.u16KeyValueCount = RT_LE2H_U16(LocatorHdr.u16KeyValueCount);

	if (RTUuidCompareStr(&LocatorHdr.UuidLocatorType, VHDX_PARENT_LOCATOR_TYPE_VHDX)
		|| LocatorHdr.u16Reserved != 0
		|| LocatorHdr.u16KeyValueCount >
			(cbItem - sizeof(VhdxParentLocatorHeader)) / sizeof(VhdxParentLocatorEntry))
	{
		grub_free(pbLocator);
		return GRUB_ERR_BAD_DEVICE;
	}

	pEntry = (PVhdxParentLocatorEntry)(pbLocator + sizeof(VhdxParentLocatorHeader));
	for (i = 0; i < LocatorHdr.u16KeyValueCount; i++, pEntry++)
	{
		grub_uint32_t offKey, offValue;
		grub_uint32_t cbKey, cbValue;
		char* pszKey;

		offKey = RT_LE2H_U32(pEntry->u32KeyOffset);
		offValue = RT_LE2H_U32(pEntry->u32ValueOffset);
		cbKey = RT_LE2H_U16(pEntry->u16KeyLength);
		cbValue = RT_LE2H_U16(pEntry->u16ValueLength);
		if ((cbKey & 1) || (cbValue & 1)
			|| (grub_uint64_t)offKey + cbKey > cbItem
			|| (grub_uint64_t)offValue + cbValue > cbItem)
		{
			rc = GRUB_ERR_BAD_DEVICE;
			break;
		}

		pszKey = grub_vdisk_utf16_to_utf8_dup(pbLocator + offKey, cbKey / 2, 0);
		if (!pszKey)
		{
			rc = GRUB_ERR_OUT_OF_MEMORY;
			break;
		}

		if (!grub_strcmp(pszKey, "relative_path") && !pszRelPath)
			pszRelPath = grub_vdisk_utf16_to_utf8_dup(pbLocator + offValue, cbValue / 2, 0);
		else if (!grub_strcmp(pszKey, "absolute_win32_path") && !pszAbsPath)
			pszAbsPath = grub_vdisk_utf16_to_utf8_dup(pbLocator + offValue, cbValue / 2, 0);
		else if (!grub_strcmp(pszKey, "parent_linkage")
			&& !pImage->fParentLinkagePresent)
		{
			char* pszLinkage = grub_vdisk_utf16_to_utf8_dup(pbLocator + offValue,
				cbValue / 2, 0);
			grub_size_t cchLinkage;

			if (!pszLinkage)
				rc = GRUB_ERR_OUT_OF_MEMORY;
			else
			{
				cchLinkage = grub_strlen(pszLinkage);
				if ((cchLinkage != 36 && cchLinkage != 38)
					|| RTUuidFromStr(&pImage->UuidParentLinkage, pszLinkage)
						!= GRUB_ERR_NONE)
					rc = GRUB_ERR_BAD_DEVICE;
				else
					pImage->fParentLinkagePresent = 1;
				grub_free(pszLinkage);
			}
		}
		grub_free(pszKey);
		if (RT_FAILURE(rc))
			break;
	}

	grub_free(pbLocator);

	if (RT_SUCCESS(rc) && !pImage->pszParentPath)
	{
		if (pszRelPath && pszRelPath[0])
		{
			pImage->pszParentPath = pszRelPath;
			pszRelPath = NULL;
		}
		else if (pszAbsPath && pszAbsPath[0])
		{
			pImage->pszParentPath = pszAbsPath;
			pszAbsPath = NULL;
		}
	}
	grub_free(pszRelPath);
	grub_free(pszAbsPath);

	return rc;
}

/**
 * Loads the metadata region.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 * @param   offRegion Start offset of the region.
 * @param   cbRegion  Size of the region.
 */
static int
vhdxLoadMetadataRegion(PVHDXIMAGE pImage, grub_uint64_t offRegion,
	grub_size_t cbRegion)
{
	VhdxMetadataTblHdr MetadataTblHdr;
	int rc = GRUB_ERR_NONE;
	grub_uint32_t fMetadataPresent = 0;

	if (offRegion > pImage->FileSize
		|| cbRegion > pImage->FileSize - offRegion
		|| cbRegion < sizeof(MetadataTblHdr))
		return GRUB_ERR_BAD_DEVICE;

	/* Load the header first. */
	rc = vhdxFileReadSync(pImage, offRegion,
		&MetadataTblHdr, sizeof(MetadataTblHdr), NULL);
	if (RT_SUCCESS(rc))
	{
		vhdxConvMetadataTblHdrEndianess(VHDXECONV_F2H, &MetadataTblHdr, &MetadataTblHdr);

		/* Validate structure. */
		if (MetadataTblHdr.u64Signature != VHDX_METADATA_TBL_HDR_SIGNATURE)
			rc = GRUB_ERR_BAD_DEVICE;
		else if (MetadataTblHdr.u16Reserved != 0
			|| MetadataTblHdr.u32Reserved2[0] != 0
			|| MetadataTblHdr.u32Reserved2[1] != 0
			|| MetadataTblHdr.u32Reserved2[2] != 0
			|| MetadataTblHdr.u32Reserved2[3] != 0
			|| MetadataTblHdr.u32Reserved2[4] != 0)
			rc = GRUB_ERR_BAD_DEVICE;
		else if (MetadataTblHdr.u16EntryCount > VHDX_METADATA_TBL_HDR_ENTRY_COUNT_MAX)
			rc = GRUB_ERR_BAD_DEVICE;
		else if (cbRegion < (MetadataTblHdr.u16EntryCount * sizeof(VhdxMetadataTblEntry) + sizeof(VhdxMetadataTblHdr)))
			rc = GRUB_ERR_BAD_DEVICE;

		if (RT_SUCCESS(rc))
		{
			grub_uint64_t offMetadataTblEntry = offRegion + sizeof(VhdxMetadataTblHdr);

			for (unsigned i = 0; i < MetadataTblHdr.u16EntryCount; i++)
			{
				grub_uint64_t offMetadataItem = 0;
				VHDXMETADATAITEM enmMetadataItem = VHDXMETADATAITEM_UNKNOWN;
				VhdxMetadataTblEntry MetadataTblEntry;

				rc = vhdxFileReadSync(pImage, offMetadataTblEntry,
					&MetadataTblEntry, sizeof(MetadataTblEntry), NULL);
				if (RT_FAILURE(rc))
				{
					rc = GRUB_ERR_IO;
					break;
				}

				vhdxConvMetadataTblEntryEndianess(VHDXECONV_F2H, &MetadataTblEntry, &MetadataTblEntry);
				if (MetadataTblEntry.u32Reserved != 0
					|| (MetadataTblEntry.u32Flags
						& ~(VHDX_METADATA_TBL_ENTRY_FLAGS_IS_USER
							| VHDX_METADATA_TBL_ENTRY_FLAGS_IS_VDISK
							| VHDX_METADATA_TBL_ENTRY_FLAGS_IS_REQUIRED)) != 0
					|| MetadataTblEntry.u32Offset > cbRegion
					|| MetadataTblEntry.u32Length > cbRegion - MetadataTblEntry.u32Offset)
				{
					rc = GRUB_ERR_BAD_DEVICE;
					break;
				}

				/* Check whether the flags match the expectations. */
				for (unsigned idxProp = 0; idxProp < RT_ELEMENTS(s_aVhdxMetadataItemProps); idxProp++)
				{
					if (!RTUuidCompareStr(&MetadataTblEntry.UuidItem,
						s_aVhdxMetadataItemProps[idxProp].pszItemUuid))
					{
						/*
						 * Check for specification violations and bail out, except
						 * for the required flag of the physical sector size metadata item.
						 * Early images had the required flag not set opposed to the specification.
						 * We don't want to brerak those images.
						 */
						if (!!(MetadataTblEntry.u32Flags & VHDX_METADATA_TBL_ENTRY_FLAGS_IS_USER)
							!= s_aVhdxMetadataItemProps[idxProp].fIsUser)
							rc = GRUB_ERR_BAD_DEVICE;
						else if (!!(MetadataTblEntry.u32Flags & VHDX_METADATA_TBL_ENTRY_FLAGS_IS_VDISK)
							!= s_aVhdxMetadataItemProps[idxProp].fIsVDisk)
							rc = GRUB_ERR_BAD_DEVICE;
						else if (!!(MetadataTblEntry.u32Flags & VHDX_METADATA_TBL_ENTRY_FLAGS_IS_REQUIRED)
							!= s_aVhdxMetadataItemProps[idxProp].fIsRequired
							&& (s_aVhdxMetadataItemProps[idxProp].enmMetadataItem != VHDXMETADATAITEM_PHYSICAL_SECTOR_SIZE))
							rc = GRUB_ERR_BAD_DEVICE;
						else
							enmMetadataItem = s_aVhdxMetadataItemProps[idxProp].enmMetadataItem;

						break;
					}
				}

				if (RT_FAILURE(rc))
					break;
				if (enmMetadataItem != VHDXMETADATAITEM_UNKNOWN)
				{
					grub_uint32_t fItem = VHDX_METADATA_PRESENT(enmMetadataItem);
					if (fMetadataPresent & fItem)
					{
						rc = GRUB_ERR_BAD_DEVICE;
						break;
					}
					fMetadataPresent |= fItem;
				}

				offMetadataItem = offRegion + MetadataTblEntry.u32Offset;

				switch (enmMetadataItem)
				{
				case VHDXMETADATAITEM_FILE_PARAMS:
				{
					rc = vhdxLoadFileParametersMetadata(pImage, offMetadataItem,
						MetadataTblEntry.u32Length);
					break;
				}
				case VHDXMETADATAITEM_VDISK_SIZE:
				{
					rc = vhdxLoadVDiskSizeMetadata(pImage, offMetadataItem,
						MetadataTblEntry.u32Length);
					break;
				}
				case VHDXMETADATAITEM_PAGE83_DATA:
				{
					if (MetadataTblEntry.u32Length != sizeof(VhdxPage83Data))
						rc = GRUB_ERR_BAD_DEVICE;
					break;
				}
				case VHDXMETADATAITEM_LOGICAL_SECTOR_SIZE:
				{
					rc = vhdxLoadVDiskLogSectorSizeMetadata(pImage, offMetadataItem,
						MetadataTblEntry.u32Length);
					break;
				}
				case VHDXMETADATAITEM_PHYSICAL_SECTOR_SIZE:
				{
					rc = vhdxLoadVDiskPhysSectorSizeMetadata(pImage, offMetadataItem,
						MetadataTblEntry.u32Length);
					break;
				}
				case VHDXMETADATAITEM_PARENT_LOCATOR:
				{
					rc = vhdxLoadParentLocatorMetadata(pImage, offMetadataItem,
						MetadataTblEntry.u32Length);
					break;
				}
				case VHDXMETADATAITEM_UNKNOWN:
				default:
					if (MetadataTblEntry.u32Flags & VHDX_METADATA_TBL_ENTRY_FLAGS_IS_REQUIRED)
						rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
				}

				if (RT_FAILURE(rc))
					break;

				offMetadataTblEntry += sizeof(MetadataTblEntry);
			}
			if (RT_SUCCESS(rc)
				&& (fMetadataPresent & VHDX_METADATA_REQUIRED) != VHDX_METADATA_REQUIRED)
				rc = GRUB_ERR_BAD_DEVICE;
		}
	}
	else
		rc = GRUB_ERR_IO;

	return rc;
}

/**
 * Loads the region table and the associated regions.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 */
static int
vhdxLoadRegionTable(PVHDXIMAGE pImage)
{
	grub_uint8_t* pbRegionTbl = NULL;
	int rc = GRUB_ERR_NONE;

	/* Load the complete region table into memory. */
	pbRegionTbl = (grub_uint8_t*)grub_malloc(VHDX_REGION_TBL_SIZE_MAX);
	if (pbRegionTbl)
	{
		rc = vhdxFileReadSync(pImage, VHDX_REGION_TBL_HDR_OFFSET,
			pbRegionTbl, VHDX_REGION_TBL_SIZE_MAX, NULL);
		if (RT_SUCCESS(rc))
		{
			PVhdxRegionTblHdr pRegionTblHdr;
			VhdxRegionTblHdr RegionTblHdr;
			grub_uint32_t u32ChkSum = 0;

			/*
			 * Copy the region table header to a dedicated structure where we can
			 * convert it to host endianess.
			 */
			grub_memcpy(&RegionTblHdr, pbRegionTbl, sizeof(RegionTblHdr));
			vhdxConvRegionTblHdrEndianess(VHDXECONV_F2H, &RegionTblHdr, &RegionTblHdr);

			/* Set checksum field to 0 during crc computation. */
			pRegionTblHdr = (PVhdxRegionTblHdr)pbRegionTbl;
			pRegionTblHdr->u32Checksum = 0;

			/* Verify the region table integrity. */
			u32ChkSum = RTCrc32C(pbRegionTbl, VHDX_REGION_TBL_SIZE_MAX);

			if (RegionTblHdr.u32Signature != VHDX_REGION_TBL_HDR_SIGNATURE)
				rc = GRUB_ERR_BAD_DEVICE;
			else if (u32ChkSum != RegionTblHdr.u32Checksum)
				rc = GRUB_ERR_BAD_DEVICE;
			else if (RegionTblHdr.u32Reserved != 0)
				rc = GRUB_ERR_BAD_DEVICE;
			else if (RegionTblHdr.u32EntryCount > VHDX_REGION_TBL_HDR_ENTRY_COUNT_MAX)
				rc = GRUB_ERR_BAD_DEVICE;

			if (RT_SUCCESS(rc))
			{
				/* Parse the region table entries. */
				PVhdxRegionTblEntry paRegTblEntries = (PVhdxRegionTblEntry)(pbRegionTbl + sizeof(VhdxRegionTblHdr));
				VhdxRegionTblEntry RegTblEntryBat;
				VhdxRegionTblEntry RegTblEntryMetadata;
				int fBatRegPresent = 0;
				int fMetadataRegPresent = 0;
				grub_memset(&RegTblEntryBat, 0, sizeof(RegTblEntryBat));
				grub_memset(&RegTblEntryMetadata, 0, sizeof(RegTblEntryMetadata));

				for (unsigned i = 0; i < RegionTblHdr.u32EntryCount; i++)
				{
					PVhdxRegionTblEntry pRegTblEntry = &paRegTblEntries[i];
					vhdxConvRegionTblEntryEndianess(VHDXECONV_F2H, pRegTblEntry, pRegTblEntry);
					if ((pRegTblEntry->u32Flags & ~VHDX_REGION_TBL_ENTRY_FLAGS_IS_REQUIRED) != 0
						|| pRegTblEntry->u32Length == 0
						|| (pRegTblEntry->u64FileOffset & (_1M - 1)) != 0
						|| (pRegTblEntry->u32Length & (_1M - 1)) != 0
						|| pRegTblEntry->u64FileOffset < _1M
						|| pRegTblEntry->u64FileOffset > pImage->FileSize
						|| pRegTblEntry->u32Length > pImage->FileSize - pRegTblEntry->u64FileOffset
						|| (pImage->cbLog != 0
							&& pRegTblEntry->u64FileOffset < pImage->offLog + pImage->cbLog
							&& pImage->offLog < pRegTblEntry->u64FileOffset + pRegTblEntry->u32Length))
					{
						rc = GRUB_ERR_BAD_DEVICE;
						break;
					}

					for (unsigned j = 0; j < i; j++)
					{
						PVhdxRegionTblEntry pPrev = &paRegTblEntries[j];
						if (pRegTblEntry->u64FileOffset < pPrev->u64FileOffset + pPrev->u32Length
							&& pPrev->u64FileOffset < pRegTblEntry->u64FileOffset + pRegTblEntry->u32Length)
						{
							rc = GRUB_ERR_BAD_DEVICE;
							break;
						}
					}
					if (RT_FAILURE(rc))
						break;

					/* Check the uuid for known regions. */
					if (!RTUuidCompareStr(&pRegTblEntry->UuidObject, VHDX_REGION_TBL_ENTRY_UUID_BAT))
					{
						/*
						 * Save the BAT region and process it later.
						 * It may come before the metadata region but needs the block size.
						 */
						if ((pRegTblEntry->u32Flags & VHDX_REGION_TBL_ENTRY_FLAGS_IS_REQUIRED)
							&& !fBatRegPresent)
						{
							fBatRegPresent = 1;
							grub_memcpy(&RegTblEntryBat, pRegTblEntry, sizeof(RegTblEntryBat));
						}
						else
							rc = GRUB_ERR_BAD_DEVICE;
					}
					else if (!RTUuidCompareStr(&pRegTblEntry->UuidObject, VHDX_REGION_TBL_ENTRY_UUID_METADATA))
					{
						if ((pRegTblEntry->u32Flags & VHDX_REGION_TBL_ENTRY_FLAGS_IS_REQUIRED)
							&& !fMetadataRegPresent)
						{
							fMetadataRegPresent = 1;
							grub_memcpy(&RegTblEntryMetadata, pRegTblEntry, sizeof(RegTblEntryMetadata));
						}
						else
							rc = GRUB_ERR_BAD_DEVICE;
					}
					else if (pRegTblEntry->u32Flags & VHDX_REGION_TBL_ENTRY_FLAGS_IS_REQUIRED)
					{
						/* The region is not known but marked as required, fail to load the image. */
						rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
					}

					if (RT_FAILURE(rc))
						break;
				}

				if (RT_SUCCESS(rc) && fBatRegPresent && fMetadataRegPresent)
					rc = vhdxLoadMetadataRegion(pImage, RegTblEntryMetadata.u64FileOffset,
						RegTblEntryMetadata.u32Length);
				else if (RT_SUCCESS(rc))
					rc = GRUB_ERR_BAD_DEVICE;
				if (RT_SUCCESS(rc))
					rc = vhdxLoadBatRegion(pImage, RegTblEntryBat.u64FileOffset,
						RegTblEntryBat.u32Length, paRegTblEntries,
						RegionTblHdr.u32EntryCount);
			}
		}
		else
			rc = GRUB_ERR_IO;
	}
	else
		rc = GRUB_ERR_OUT_OF_MEMORY;

	if (pbRegionTbl)
		grub_free(pbRegionTbl);

	return rc;
}

static int
vhdxValidateParent(PVHDXIMAGE pImage)
{
	grub_vhdx_t pParentIo;
	PVHDXIMAGE pParentImage;

	if (!pImage->Parent || pImage->Parent->fs != &grub_vhdx_fs
		|| !pImage->Parent->data)
		return grub_error(GRUB_ERR_BAD_DEVICE,
			"VHDX parent is not a VHDX image");
	pParentIo = (grub_vhdx_t)pImage->Parent->data;
	pParentImage = (PVHDXIMAGE)pParentIo->vhdx;
	if (!pParentImage || pParentImage->cbSize != pImage->cbSize)
		return grub_error(GRUB_ERR_BAD_DEVICE,
			"VHDX parent virtual size does not match child");
	if (RTUuidCompare(&pImage->UuidParentLinkage, &pParentImage->UuidDataWrite))
		return grub_error(GRUB_ERR_BAD_DEVICE,
			"VHDX parent linkage does not match parent image");
	return GRUB_ERR_NONE;
}

/**
 * Internal: Open an image, constructing all necessary data structures.
 */
static int
vhdxOpenImage(PVHDXIMAGE pImage)
{
	VhdxFileIdentifier FileIdentifier;
	grub_uint64_t cbFile = grub_file_size(pImage->File);
	int rc = GRUB_ERR_NONE;

	pImage->FileSize = cbFile;
	if (cbFile > sizeof(FileIdentifier))
	{
		rc = vhdxFileReadSync(pImage, VHDX_FILE_IDENTIFIER_OFFSET,
			&FileIdentifier, sizeof(FileIdentifier), NULL);
		if (RT_SUCCESS(rc))
		{
			vhdxConvFileIdentifierEndianess(VHDXECONV_F2H, &FileIdentifier,
				&FileIdentifier);
			if (FileIdentifier.u64Signature != VHDX_FILE_IDENTIFIER_SIGNATURE)
				rc = GRUB_ERR_BAD_DEVICE;
			else
				rc = vhdxFindAndLoadCurrentHeader(pImage);

			/* Load the region table. */
			if (RT_SUCCESS(rc))
				rc = vhdxLoadRegionTable(pImage);

			/* Open the parent of a differencing image. */
			if (RT_SUCCESS(rc)
				&& (pImage->uImageFlags & VD_IMAGE_FLAGS_DIFF))
			{
				if (!pImage->pszParentPath)
					rc = grub_error(GRUB_ERR_BAD_DEVICE,
						"VHDX differencing image has no parent locator");
				else if (!pImage->fParentLinkagePresent)
					rc = grub_error(GRUB_ERR_BAD_DEVICE,
						"VHDX differencing image has no parent linkage");
				else
				{
					pImage->Parent = grub_vdisk_open_parent(pImage->File->name,
						pImage->pszParentPath);
					if (!pImage->Parent)
						rc = grub_errno;
					else
						rc = vhdxValidateParent(pImage);
				}
			}
		}
		else
			rc = GRUB_ERR_BAD_DEVICE;
	}

	if (RT_FAILURE(rc))
		vhdxFreeImage(pImage);

	return rc;
}

static int
vhdxOpen(grub_file_t File, void** ppBackendData)
{
	int rc;
	PVHDXIMAGE pImage = (PVHDXIMAGE)grub_zalloc(sizeof(VHDXIMAGE));
	if (!pImage)
	{
		rc = GRUB_ERR_OUT_OF_MEMORY;
		return rc;
	}

	pImage->File = File;
	rc = vhdxOpenImage(pImage);

	if (RT_SUCCESS(rc))
		*ppBackendData = pImage;
	else
		grub_free(pImage);

	return rc;
}

static int
vhdxClose(void* pBackendData)
{
	PVHDXIMAGE pImage = (PVHDXIMAGE)pBackendData;

	int rc = vhdxFreeImage(pImage);
	grub_free(pImage);

	return rc;
}

static int
vhdxRead(void* pBackendData, grub_uint64_t uOffset, void* pvBuf, grub_size_t cbToRead,
	grub_size_t* pcbActuallyRead)
{
	PVHDXIMAGE pImage = (PVHDXIMAGE)pBackendData;
	int rc = GRUB_ERR_NONE;

	if (pcbActuallyRead)
		*pcbActuallyRead = 0;
	if (uOffset > pImage->cbSize || cbToRead > pImage->cbSize - uOffset)
		rc = GRUB_ERR_OUT_OF_RANGE;
	else if (cbToRead == 0)
		return GRUB_ERR_NONE;
	else
	{
		grub_uint32_t idxBlock = (grub_uint32_t)(uOffset / pImage->cbBlock);
		grub_uint32_t idxBat = idxBlock;
		grub_uint32_t offRead = (grub_uint32_t)(uOffset % pImage->cbBlock);
		grub_uint64_t uBatEntry;

		idxBat += idxBlock / pImage->uChunkRatio; /* Add interleaving sector bitmap entries. */
		if (idxBat >= pImage->cBatEntries)
			return GRUB_ERR_BAD_ARGUMENT;
		uBatEntry = pImage->paBat[idxBat].u64BatEntry;

		cbToRead = RT_MIN(cbToRead, pImage->cbBlock - offRead);

		switch (VHDX_BAT_ENTRY_GET_STATE(uBatEntry))
		{
		case VHDX_BAT_ENTRY_PAYLOAD_BLOCK_NOT_PRESENT:
		{
			/* In a differencing image an absent block lives in the
			 * parent chain. */
			if (pImage->Parent)
			{
				rc = grub_vdisk_read_parent(pImage->Parent, uOffset, pvBuf, cbToRead);
				break;
			}
			grub_memset(pvBuf, 0, cbToRead);
			break;
		}
		case VHDX_BAT_ENTRY_PAYLOAD_BLOCK_UNDEFINED:
		case VHDX_BAT_ENTRY_PAYLOAD_BLOCK_ZERO:
		case VHDX_BAT_ENTRY_PAYLOAD_BLOCK_UNMAPPED:
		{
			grub_memset(pvBuf, 0, cbToRead);
			break;
		}
		case VHDX_BAT_ENTRY_PAYLOAD_BLOCK_FULLY_PRESENT:
		{
			grub_uint64_t offFile = VHDX_BAT_ENTRY_GET_FILE_OFFSET(uBatEntry) + offRead;
			if (offFile > pImage->FileSize || cbToRead > pImage->FileSize - offFile)
				rc = GRUB_ERR_OUT_OF_RANGE;
			else
				rc = vhdxFileReadSync(pImage, offFile,
					pvBuf, cbToRead, NULL);
			break;
		}
		case VHDX_BAT_ENTRY_PAYLOAD_BLOCK_PARTIALLY_PRESENT:
		{
			/* Sectors flagged in the chunk's sector bitmap live in
			 * this file, clean sectors come from the parent. */
			grub_uint32_t idxChunk = idxBlock / pImage->uChunkRatio;
			grub_uint32_t idxSb = (idxChunk + 1) * (pImage->uChunkRatio + 1) - 1;
			grub_uint64_t uSbEntry;
			grub_uint64_t cSectorsPerChunk;
			grub_uint64_t uSector, uSectorInChunk;
			grub_uint32_t cSectors, cRun;
			grub_uint32_t offBitmapFirst;
			grub_size_t cbBitmap;
			grub_uint8_t abBitmap[264];
			int fFirstDirty;

			if (!pImage->Parent || idxSb >= pImage->cBatEntries)
			{
				rc = GRUB_ERR_BAD_ARGUMENT;
				break;
			}
			uSbEntry = pImage->paBat[idxSb].u64BatEntry;
			if (VHDX_BAT_ENTRY_GET_STATE(uSbEntry)
				!= VHDX_BAT_ENTRY_SB_BLOCK_PRESENT)
			{
				rc = GRUB_ERR_BAD_DEVICE;
				break;
			}

			/* Cap the request so the bitmap slice below stays small;
			 * the caller loops for the remainder. */
			if (cbToRead > _1M)
				cbToRead = _1M;

			cSectorsPerChunk = ((grub_uint64_t)pImage->cbBlock * pImage->uChunkRatio)
				/ pImage->cbLogicalSector;
			uSector = uOffset / pImage->cbLogicalSector;
			uSectorInChunk = uSector % cSectorsPerChunk;
			cSectors = (grub_uint32_t)(((uOffset + cbToRead - 1) / pImage->cbLogicalSector)
				- uSector + 1);

			/* Read the bitmap slice covering the request (LSB first,
			 * one bit per logical sector of the chunk). */
			offBitmapFirst = (grub_uint32_t)(uSectorInChunk / 8);
			cbBitmap = (grub_size_t)((uSectorInChunk + cSectors - 1) / 8)
				- offBitmapFirst + 1;
			rc = vhdxFileReadSync(pImage,
				VHDX_BAT_ENTRY_GET_FILE_OFFSET(uSbEntry) + offBitmapFirst,
				abBitmap,
				cbBitmap,
				NULL);
			if (RT_FAILURE(rc))
				break;

#define VHDX_SB_BIT(iSec) \
	((abBitmap[(grub_uint32_t)((iSec) / 8) - offBitmapFirst] \
	  >> ((iSec) % 8)) & 1)

			fFirstDirty = VHDX_SB_BIT(uSectorInChunk);
			cRun = 1;
			while (cRun < cSectors
				&& VHDX_SB_BIT(uSectorInChunk + cRun) == fFirstDirty)
				cRun++;
#undef VHDX_SB_BIT

			/* Clip to the run of identical bits. */
			if (cRun < cSectors)
			{
				grub_uint64_t offRunEnd = (uSector + cRun) * pImage->cbLogicalSector;
				cbToRead = (grub_size_t)(offRunEnd - uOffset);
			}

			if (fFirstDirty)
				rc = vhdxFileReadSync(pImage,
					VHDX_BAT_ENTRY_GET_FILE_OFFSET(uBatEntry) + offRead,
					pvBuf, cbToRead, NULL);
			else
				rc = grub_vdisk_read_parent(pImage->Parent, uOffset, pvBuf, cbToRead);
			break;
		}
		default:
			rc = GRUB_ERR_BAD_DEVICE;
			break;
		}

		if (RT_SUCCESS(rc) && pcbActuallyRead)
			*pcbActuallyRead = cbToRead;
	}

	return rc;
}

static grub_uint64_t
vhdxGetSize(void* pBackendData)
{
	PVHDXIMAGE pImage = (PVHDXIMAGE)pBackendData;

	if (pImage)
		return pImage->cbSize;
	return 0;
}

static grub_err_t
grub_vhdx_close(grub_file_t file)
{
	grub_vhdx_t vhdxio = file->data;

	vhdxClose(vhdxio->vhdx);
	grub_file_close(vhdxio->file);
	grub_free(vhdxio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_vhdx_open(grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_vhdx_t vhdxio;
	void* vhdx = NULL;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < 0x10000 || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	if (vhdxOpen(io, &vhdx) != GRUB_ERR_NONE)
	{
		grub_file_seek(io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t)grub_zalloc(sizeof(*file));
	if (!file)
	{
		vhdxClose(vhdx);
		return 0;
	}

	vhdxio = grub_zalloc(sizeof(*vhdxio));
	if (!vhdxio)
	{
		vhdxClose(vhdx);
		grub_free(file);
		return 0;
	}
	vhdxio->file = io;
	vhdxio->vhdx = vhdx;

	file->device = io->device;
	file->data = vhdxio;
	file->fs = &grub_vhdx_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = vhdxGetSize(vhdx);

	return file;
}

static grub_ssize_t
grub_vhdx_read(grub_file_t file, char* buf, grub_size_t len)
{
	int rc = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_vhdx_t vhdxio = file->data;

	while (len > 0 && rc == GRUB_ERR_NONE)
	{
		real_size = 0;
		rc = vhdxRead(vhdxio->vhdx, read_offset, buf, len, &real_size);
		if (RT_FAILURE(rc))
			break;
		if (real_size == 0)
		{
			rc = GRUB_ERR_FILE_READ_ERROR;
			break;
		}
		read_offset += real_size;
		buf += real_size;
		size += real_size;
		if (real_size >= len)
			break;
		len -= real_size;
	}

	if (rc != GRUB_ERR_NONE)
	{
		grub_error((grub_err_t)rc, "VHDX image read failed");
		return -1;
	}
	return (grub_ssize_t)size;
}

static struct grub_fs grub_vhdx_fs =
{
	.name = "vhdx",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_vhdx_read,
	.fs_close = grub_vhdx_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT(vhdx)
{
	grub_file_filter_register(GRUB_FILE_FILTER_VHDX, grub_vhdx_open);
}

GRUB_MOD_FINI(vhdx)
{
	grub_file_filter_unregister(GRUB_FILE_FILTER_VHDX);
}
