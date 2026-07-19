/* $Id: VDI.cpp $ */
/** @file
 * Virtual Disk Image (VDI), Core Code.
 */

 /*
  * Copyright (C) 2006-2023 Oracle and/or its affiliates.
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

/*******************************************************************************
 *   Constants And Macros, Structures and Typedefs                             *
 *******************************************************************************/

/** Current VDI image major version. */
#define VDI_IMAGE_VERSION_MAJOR     (0x0001)
/** Current VDI image minor version. */
#define VDI_IMAGE_VERSION_MINOR     (0x0001)
/** Current VDI image version. */
#define VDI_IMAGE_VERSION           ((VDI_IMAGE_VERSION_MAJOR << 16) | VDI_IMAGE_VERSION_MINOR)

/** Mask of valid image flags for VDI. */
#define VD_VDI_IMAGE_FLAGS_MASK     (VD_IMAGE_FLAGS_FIXED | VD_IMAGE_FLAGS_DIFF | VD_IMAGE_FLAGS_NONE | VD_VDI_IMAGE_FLAGS_ZERO_EXPAND)

/** Get VDI major version from combined version. */
#define VDI_GET_VERSION_MAJOR(uVer)    ((uVer) >> 16)
/** Get VDI minor version from combined version. */
#define VDI_GET_VERSION_MINOR(uVer)    ((uVer) & 0xffff)

/** Image info, not handled anyhow.
 *  Must be less than 64 bytes in length, including the trailing 0.
 */
#define VDI_IMAGE_FILE_INFO   "<<< Oracle VM VirtualBox Disk Image >>>\n"

/** The Sector size.
 * Currently we support only 512 bytes sectors.
 */
#define VDI_GEOMETRY_SECTOR_SIZE    (512)
  /**  512 = 2^^9 */
#define VDI_GEOMETRY_SECTOR_SHIFT   (9)

/**
 * Harddisk geometry.
 */
#pragma pack(1)
typedef struct VDIDISKGEOMETRY
{
	/** Cylinders. */
	grub_uint32_t    cCylinders;
	/** Heads. */
	grub_uint32_t    cHeads;
	/** Sectors per track. */
	grub_uint32_t    cSectors;
	/** Sector size. (bytes per sector) */
	grub_uint32_t    cbSector;
} VDIDISKGEOMETRY, * PVDIDISKGEOMETRY;
#pragma pack()

/** Image signature. */
#define VDI_IMAGE_SIGNATURE   (0xbeda107f)

/**
 * Pre-Header to be stored in image file - used for version control.
 */
#pragma pack(1)
typedef struct VDIPREHEADER
{
	/** Just text info about image type, for eyes only. */
	char            szFileInfo[64];
	/** The image signature (VDI_IMAGE_SIGNATURE). */
	grub_uint32_t        u32Signature;
	/** The image version (VDI_IMAGE_VERSION). */
	grub_uint32_t        u32Version;
} VDIPREHEADER, * PVDIPREHEADER;
#pragma pack()

/**
 * Size of szComment field of HDD image header.
 */
#define VDI_IMAGE_COMMENT_SIZE    256

 /**
  * Header to be stored in image file, VDI_IMAGE_VERSION_MAJOR = 0.
  * Prepended by VDIPREHEADER.
  */
#pragma pack(1)
typedef struct VDIHEADER0
{
	/** The image type (VDI_IMAGE_TYPE_*). */
	grub_uint32_t        u32Type;
	/** Image flags (VDI_IMAGE_FLAGS_*). */
	grub_uint32_t        fFlags;
	/** Image comment. (UTF-8) */
	char            szComment[VDI_IMAGE_COMMENT_SIZE];
	/** Legacy image geometry (previous code stored PCHS there). */
	VDIDISKGEOMETRY LegacyGeometry;
	/** Size of disk (in bytes). */
	grub_uint64_t        cbDisk;
	/** Block size. (For instance VDI_IMAGE_BLOCK_SIZE.) */
	grub_uint32_t        cbBlock;
	/** Number of blocks. */
	grub_uint32_t        cBlocks;
	/** Number of allocated blocks. */
	grub_uint32_t        cBlocksAllocated;
	/** UUID of image. */
	RTUUID          uuidCreate;
	/** UUID of image's last modification. */
	RTUUID          uuidModify;
	/** Only for secondary images - UUID of primary image. */
	RTUUID          uuidLinkage;
} VDIHEADER0, * PVDIHEADER0;
#pragma pack()

/**
 * Header to be stored in image file, VDI_IMAGE_VERSION_MAJOR = 1,
 * VDI_IMAGE_VERSION_MINOR = 1. Prepended by VDIPREHEADER.
 */
#pragma pack(1)
typedef struct VDIHEADER1
{
	/** Size of this structure in bytes. */
	grub_uint32_t        cbHeader;
	/** The image type (VDI_IMAGE_TYPE_*). */
	grub_uint32_t        u32Type;
	/** Image flags (VDI_IMAGE_FLAGS_*). */
	grub_uint32_t        fFlags;
	/** Image comment. (UTF-8) */
	char            szComment[VDI_IMAGE_COMMENT_SIZE];
	/** Offset of Blocks array from the beginning of image file.
	 * Should be sector-aligned for HDD access optimization. */
	grub_uint32_t        offBlocks;
	/** Offset of image data from the beginning of image file.
	 * Should be sector-aligned for HDD access optimization. */
	grub_uint32_t        offData;
	/** Legacy image geometry (previous code stored PCHS there). */
	VDIDISKGEOMETRY LegacyGeometry;
	/** Was BIOS HDD translation mode, now unused. */
	grub_uint32_t        u32Dummy;
	/** Size of disk (in bytes). */
	grub_uint64_t        cbDisk;
	/** Block size. (For instance VDI_IMAGE_BLOCK_SIZE.) Should be a power of 2! */
	grub_uint32_t        cbBlock;
	/** Size of additional service information of every data block.
	 * Prepended before block data. May be 0.
	 * Should be a power of 2 and sector-aligned for optimization reasons. */
	grub_uint32_t        cbBlockExtra;
	/** Number of blocks. */
	grub_uint32_t        cBlocks;
	/** Number of allocated blocks. */
	grub_uint32_t        cBlocksAllocated;
	/** UUID of image. */
	RTUUID          uuidCreate;
	/** UUID of image's last modification. */
	RTUUID          uuidModify;
	/** Only for secondary images - UUID of previous image. */
	RTUUID          uuidLinkage;
	/** Only for secondary images - UUID of previous image's last modification. */
	RTUUID          uuidParentModify;
} VDIHEADER1, * PVDIHEADER1;
#pragma pack()

/**
 * Header to be stored in image file, VDI_IMAGE_VERSION_MAJOR = 1,
 * VDI_IMAGE_VERSION_MINOR = 1, the slightly changed variant necessary as the
 * old released code doesn't support changing the minor version at all.
 */
#pragma pack(1)
typedef struct VDIHEADER1PLUS
{
	/** Size of this structure in bytes. */
	grub_uint32_t        cbHeader;
	/** The image type (VDI_IMAGE_TYPE_*). */
	grub_uint32_t        u32Type;
	/** Image flags (VDI_IMAGE_FLAGS_*). */
	grub_uint32_t        fFlags;
	/** Image comment. (UTF-8) */
	char            szComment[VDI_IMAGE_COMMENT_SIZE];
	/** Offset of blocks array from the beginning of image file.
	 * Should be sector-aligned for HDD access optimization. */
	grub_uint32_t        offBlocks;
	/** Offset of image data from the beginning of image file.
	 * Should be sector-aligned for HDD access optimization. */
	grub_uint32_t        offData;
	/** Legacy image geometry (previous code stored PCHS there). */
	VDIDISKGEOMETRY LegacyGeometry;
	/** Was BIOS HDD translation mode, now unused. */
	grub_uint32_t        u32Dummy;
	/** Size of disk (in bytes). */
	grub_uint64_t        cbDisk;
	/** Block size. (For instance VDI_IMAGE_BLOCK_SIZE.) Should be a power of 2! */
	grub_uint32_t        cbBlock;
	/** Size of additional service information of every data block.
	 * Prepended before block data. May be 0.
	 * Should be a power of 2 and sector-aligned for optimization reasons. */
	grub_uint32_t        cbBlockExtra;
	/** Number of blocks. */
	grub_uint32_t        cBlocks;
	/** Number of allocated blocks. */
	grub_uint32_t        cBlocksAllocated;
	/** UUID of image. */
	RTUUID          uuidCreate;
	/** UUID of image's last modification. */
	RTUUID          uuidModify;
	/** Only for secondary images - UUID of previous image. */
	RTUUID          uuidLinkage;
	/** Only for secondary images - UUID of previous image's last modification. */
	RTUUID          uuidParentModify;
	/** LCHS image geometry (new field in VDI1.2 version. */
	VDIDISKGEOMETRY LCHSGeometry;
} VDIHEADER1PLUS, * PVDIHEADER1PLUS;
#pragma pack()

/**
 * Header structure for all versions.
 */
typedef struct VDIHEADER
{
	unsigned        uVersion;
	union
	{
		VDIHEADER0    v0;
		VDIHEADER1    v1;
		VDIHEADER1PLUS v1plus;
	} u;
} VDIHEADER, * PVDIHEADER;

/** Block 'pointer'. */
typedef grub_uint32_t    VDIIMAGEBLOCKPOINTER;
/** Pointer to a block 'pointer'. */
typedef VDIIMAGEBLOCKPOINTER* PVDIIMAGEBLOCKPOINTER;

/**
 * Block marked as free is not allocated in image file, read from this
 * block may returns any random data.
 */
#define VDI_IMAGE_BLOCK_FREE   ((VDIIMAGEBLOCKPOINTER)~0)

 /**
  * Block marked as zero is not allocated in image file, read from this
  * block returns zeroes.
  */
#define VDI_IMAGE_BLOCK_ZERO   ((VDIIMAGEBLOCKPOINTER)~1)

#define GET_MAJOR_HEADER_VERSION(ph) (VDI_GET_VERSION_MAJOR((ph)->uVersion))
#define GET_MINOR_HEADER_VERSION(ph) (VDI_GET_VERSION_MINOR((ph)->uVersion))

typedef enum VDIIMAGETYPE
{
	/** Normal dynamically growing base image file. */
	VDI_IMAGE_TYPE_NORMAL = 1,
	/** Preallocated base image file of a fixed size. */
	VDI_IMAGE_TYPE_FIXED,
	/** Dynamically growing image file for undo/commit changes support. */
	VDI_IMAGE_TYPE_UNDO,
	/** Dynamically growing image file for differencing support. */
	VDI_IMAGE_TYPE_DIFF,

	/** First valid image type value. */
	VDI_IMAGE_TYPE_FIRST = VDI_IMAGE_TYPE_NORMAL,
	/** Last valid image type value. */
	VDI_IMAGE_TYPE_LAST = VDI_IMAGE_TYPE_DIFF
} VDIIMAGETYPE;
/** Pointer to VDI image type. */
typedef VDIIMAGETYPE* PVDIIMAGETYPE;

static VDIIMAGETYPE
getImageType(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return (VDIIMAGETYPE)ph->u.v0.u32Type;
	case 1: return (VDIIMAGETYPE)ph->u.v1.u32Type;
	}
	return (VDIIMAGETYPE)0;
}

static unsigned
getImageFlags(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0:
		/* VDI image flag conversion to VD image flags. */
		return ph->u.v0.fFlags << 8;
	case 1:
		/* VDI image flag conversion to VD image flags. */
		return ph->u.v1.fFlags << 8;
	}
	return 0;
}

static unsigned
getImageBlocksOffset(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return (unsigned)(sizeof(VDIPREHEADER) + sizeof(VDIHEADER0));
	case 1: return ph->u.v1.offBlocks;
	}
	return 0;
}

static grub_uint32_t
getImageDataOffset(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return (grub_uint32_t)(sizeof(VDIPREHEADER) + sizeof(VDIHEADER0) + \
		(ph->u.v0.cBlocks * sizeof(VDIIMAGEBLOCKPOINTER)));
	case 1: return ph->u.v1.offData;
	}
	return 0;
}

static PVDIDISKGEOMETRY
getImageLCHSGeometry(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return NULL;
	case 1:
		switch (GET_MINOR_HEADER_VERSION(ph))
		{
		case 1:
			if (ph->u.v1.cbHeader < sizeof(ph->u.v1plus))
				return NULL;
			else
				return &ph->u.v1plus.LCHSGeometry;
		}
	}
	return NULL;
}

static grub_uint64_t
getImageDiskSize(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return ph->u.v0.cbDisk;
	case 1: return ph->u.v1.cbDisk;
	}
	return 0;
}

static void
setImageDiskSize(PVDIHEADER ph, grub_uint64_t cbDisk)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: ph->u.v0.cbDisk = cbDisk; return;
	case 1: ph->u.v1.cbDisk = cbDisk; return;
	}
}

static unsigned
getImageBlockSize(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return ph->u.v0.cbBlock;
	case 1: return ph->u.v1.cbBlock;
	}
	return 0;
}

static unsigned
getImageExtraBlockSize(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return 0;
	case 1: return ph->u.v1.cbBlockExtra;
	}
	return 0;
}

static unsigned
getImageBlocks(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return ph->u.v0.cBlocks;
	case 1: return ph->u.v1.cBlocks;
	}
	return 0;
}

static unsigned
getImageBlocksAllocated(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return ph->u.v0.cBlocksAllocated;
	case 1: return ph->u.v1.cBlocksAllocated;
	}
	return 0;
}

#ifdef _MSC_VER
# pragma warning(disable:4366) /* (harmless "misalignment") */
#endif

static PRTUUID
getImageCreationUUID(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return &ph->u.v0.uuidCreate;
	case 1: return &ph->u.v1.uuidCreate;
	}
	return NULL;
}

static PRTUUID
getImageModificationUUID(PVDIHEADER ph)
{
	switch (GET_MAJOR_HEADER_VERSION(ph))
	{
	case 0: return &ph->u.v0.uuidModify;
	case 1: return &ph->u.v1.uuidModify;
	}
	return NULL;
}

#ifdef _MSC_VER
# pragma warning(default:4366)
#endif

/**
 * Image structure
 */
typedef struct VDIIMAGEDESC
{
	/** Descriptor file if applicable. */
	grub_file_t File;
	/** File size on the host disk (including all headers). */
	grub_uint64_t   FileSize;

	/** Image open flags, VD_OPEN_FLAGS_*. */
	//unsigned                uOpenFlags;
	/** Image pre-header. */
	VDIPREHEADER            PreHeader;
	/** Image header. */
	VDIHEADER               Header;
	/** Pointer to a block array. */
	PVDIIMAGEBLOCKPOINTER   paBlocks;
	/** Pointer to the block array for back resolving (used if discarding is enabled). */
	unsigned* paBlocksRev;
	/** fFlags copy from image header, for speed optimization. */
	unsigned                uImageFlags;
	/** Start offset of block array in image file, here for speed optimization. */
	unsigned                offStartBlocks;
	/** Start offset of data in image file, here for speed optimization. */
	unsigned                offStartData;
	/** Block mask for getting the offset into a block from a byte hdd offset. */
	unsigned                uBlockMask;
	/** Block shift value for converting byte hdd offset into paBlock index. */
	unsigned                uShiftOffset2Index;
	/** Offset of data from the beginning of block. */
	unsigned                offStartBlockData;
	/** Total size of image block (including the extra data). */
	unsigned                cbTotalBlockData;
	/** Allocation Block Size */
	unsigned                cbAllocationBlock;
	/** Container filename. (UTF-8) */
	//const char* pszFilename;

	/** Current size of the image (used for range validation when reading). */
	grub_uint64_t                cbImage;
} VDIIMAGEDESC, * PVDIIMAGEDESC;

/**
 * Endianess conversion direction.
 */
typedef enum VDIECONV
{
	/** Host to file endianess. */
	VDIECONV_H2F = 0,
	/** File to host endianess. */
	VDIECONV_F2H
} VDIECONV;

/** Macros for endianess conversion. */
#define SET_ENDIAN_U32(conv, u32) ((conv) == VDIECONV_H2F ? RT_H2LE_U32(u32) : RT_LE2H_U32(u32))
#define SET_ENDIAN_U64(conv, u64) ((conv) == VDIECONV_H2F ? RT_H2LE_U64(u64) : RT_LE2H_U64(u64))

/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/
static unsigned getPowerOfTwo(unsigned uNumber);
static int  vdiValidatePreHeader(PVDIPREHEADER pPreHdr);
static int  vdiValidateHeader(PVDIHEADER pHeader);
static void vdiSetupImageDesc(PVDIIMAGEDESC pImage);

/**
 * Internal: Convert the PreHeader fields to the appropriate endianess.
 * @param   enmConv     Direction of the conversion.
 * @param   pPreHdrConv Where to store the converted pre header.
 * @param   pPreHdr     PreHeader pointer.
 */
static void vdiConvPreHeaderEndianess(VDIECONV enmConv, PVDIPREHEADER pPreHdrConv,
	PVDIPREHEADER pPreHdr)
{
	grub_memcpy(pPreHdrConv->szFileInfo, pPreHdr->szFileInfo, sizeof(pPreHdr->szFileInfo));
	pPreHdrConv->u32Signature = SET_ENDIAN_U32(enmConv, pPreHdr->u32Signature);
	pPreHdrConv->u32Version = SET_ENDIAN_U32(enmConv, pPreHdr->u32Version);
}

/**
 * Internal: Convert the VDIDISKGEOMETRY fields to the appropriate endianess.
 * @param   enmConv      Direction of the conversion.
 * @param   pDiskGeoConv Where to store the converted geometry.
 * @param   pDiskGeo     Pointer to the disk geometry to convert.
 */
static void vdiConvGeometryEndianess(VDIECONV enmConv, PVDIDISKGEOMETRY pDiskGeoConv,
	PVDIDISKGEOMETRY pDiskGeo)
{
	pDiskGeoConv->cCylinders = SET_ENDIAN_U32(enmConv, pDiskGeo->cCylinders);
	pDiskGeoConv->cHeads = SET_ENDIAN_U32(enmConv, pDiskGeo->cHeads);
	pDiskGeoConv->cSectors = SET_ENDIAN_U32(enmConv, pDiskGeo->cSectors);
	pDiskGeoConv->cbSector = SET_ENDIAN_U32(enmConv, pDiskGeo->cbSector);
}

/**
 * Internal: Convert the Header - version 0 fields to the appropriate endianess.
 * @param   enmConv      Direction of the conversion.
 * @param   pHdrConv     Where to store the converted header.
 * @param   pHdr         Pointer to the version 0 header.
 */
static void vdiConvHeaderEndianessV0(VDIECONV enmConv, PVDIHEADER0 pHdrConv,
	PVDIHEADER0 pHdr)
{
	grub_memmove(pHdrConv->szComment, pHdr->szComment, sizeof(pHdr->szComment));
	pHdrConv->u32Type = SET_ENDIAN_U32(enmConv, pHdr->u32Type);
	pHdrConv->fFlags = SET_ENDIAN_U32(enmConv, pHdr->fFlags);
	vdiConvGeometryEndianess(enmConv, &pHdrConv->LegacyGeometry, &pHdr->LegacyGeometry);
	pHdrConv->cbDisk = SET_ENDIAN_U64(enmConv, pHdr->cbDisk);
	pHdrConv->cbBlock = SET_ENDIAN_U32(enmConv, pHdr->cbBlock);
	pHdrConv->cBlocks = SET_ENDIAN_U32(enmConv, pHdr->cBlocks);
	pHdrConv->cBlocksAllocated = SET_ENDIAN_U32(enmConv, pHdr->cBlocksAllocated);
	/* Don't convert the RTUUID fields. */
	pHdrConv->uuidCreate = pHdr->uuidCreate;
	pHdrConv->uuidModify = pHdr->uuidModify;
	pHdrConv->uuidLinkage = pHdr->uuidLinkage;
}

/**
 * Internal: Set the Header - version 1 fields to the appropriate endianess.
 * @param   enmConv      Direction of the conversion.
 * @param   pHdrConv     Where to store the converted header.
 * @param   pHdr         Version 1 Header pointer.
 */
static void vdiConvHeaderEndianessV1(VDIECONV enmConv, PVDIHEADER1 pHdrConv,
	PVDIHEADER1 pHdr)
{
	grub_memmove(pHdrConv->szComment, pHdr->szComment, sizeof(pHdr->szComment));
	pHdrConv->cbHeader = SET_ENDIAN_U32(enmConv, pHdr->cbHeader);
	pHdrConv->u32Type = SET_ENDIAN_U32(enmConv, pHdr->u32Type);
	pHdrConv->fFlags = SET_ENDIAN_U32(enmConv, pHdr->fFlags);
	pHdrConv->offBlocks = SET_ENDIAN_U32(enmConv, pHdr->offBlocks);
	pHdrConv->offData = SET_ENDIAN_U32(enmConv, pHdr->offData);
	vdiConvGeometryEndianess(enmConv, &pHdrConv->LegacyGeometry, &pHdr->LegacyGeometry);
	pHdrConv->u32Dummy = SET_ENDIAN_U32(enmConv, pHdr->u32Dummy);
	pHdrConv->cbDisk = SET_ENDIAN_U64(enmConv, pHdr->cbDisk);
	pHdrConv->cbBlock = SET_ENDIAN_U32(enmConv, pHdr->cbBlock);
	pHdrConv->cbBlockExtra = SET_ENDIAN_U32(enmConv, pHdr->cbBlockExtra);
	pHdrConv->cBlocks = SET_ENDIAN_U32(enmConv, pHdr->cBlocks);
	pHdrConv->cBlocksAllocated = SET_ENDIAN_U32(enmConv, pHdr->cBlocksAllocated);
	/* Don't convert the RTUUID fields. */
	pHdrConv->uuidCreate = pHdr->uuidCreate;
	pHdrConv->uuidModify = pHdr->uuidModify;
	pHdrConv->uuidLinkage = pHdr->uuidLinkage;
	pHdrConv->uuidParentModify = pHdr->uuidParentModify;
}

/**
 * Internal: Set the Header - version 1plus fields to the appropriate endianess.
 * @param   enmConv      Direction of the conversion.
 * @param   pHdrConv     Where to store the converted header.
 * @param   pHdr         Version 1+ Header pointer.
 */
static void vdiConvHeaderEndianessV1p(VDIECONV enmConv, PVDIHEADER1PLUS pHdrConv,
	PVDIHEADER1PLUS pHdr)
{
	grub_memmove(pHdrConv->szComment, pHdr->szComment, sizeof(pHdr->szComment));
	pHdrConv->cbHeader = SET_ENDIAN_U32(enmConv, pHdr->cbHeader);
	pHdrConv->u32Type = SET_ENDIAN_U32(enmConv, pHdr->u32Type);
	pHdrConv->fFlags = SET_ENDIAN_U32(enmConv, pHdr->fFlags);
	pHdrConv->offBlocks = SET_ENDIAN_U32(enmConv, pHdr->offBlocks);
	pHdrConv->offData = SET_ENDIAN_U32(enmConv, pHdr->offData);
	vdiConvGeometryEndianess(enmConv, &pHdrConv->LegacyGeometry, &pHdr->LegacyGeometry);
	pHdrConv->u32Dummy = SET_ENDIAN_U32(enmConv, pHdr->u32Dummy);
	pHdrConv->cbDisk = SET_ENDIAN_U64(enmConv, pHdr->cbDisk);
	pHdrConv->cbBlock = SET_ENDIAN_U32(enmConv, pHdr->cbBlock);
	pHdrConv->cbBlockExtra = SET_ENDIAN_U32(enmConv, pHdr->cbBlockExtra);
	pHdrConv->cBlocks = SET_ENDIAN_U32(enmConv, pHdr->cBlocks);
	pHdrConv->cBlocksAllocated = SET_ENDIAN_U32(enmConv, pHdr->cBlocksAllocated);
	/* Don't convert the RTUUID fields. */
	pHdrConv->uuidCreate = pHdr->uuidCreate;
	pHdrConv->uuidModify = pHdr->uuidModify;
	pHdrConv->uuidLinkage = pHdr->uuidLinkage;
	pHdrConv->uuidParentModify = pHdr->uuidParentModify;
	vdiConvGeometryEndianess(enmConv, &pHdrConv->LCHSGeometry, &pHdr->LCHSGeometry);
}

/**
 * Internal: Set the appropriate endianess on all the Blocks pointed.
 * @param   enmConv      Direction of the conversion.
 * @param   paBlocks     Pointer to the block array.
 * @param   cEntries     Number of entries in the block array.
 *
 * @note Unlike the other conversion functions this method does an in place conversion
 *       to avoid temporary memory allocations when writing the block array.
 */
static void vdiConvBlocksEndianess(VDIECONV enmConv, PVDIIMAGEBLOCKPOINTER paBlocks,
	unsigned cEntries)
{
	for (unsigned i = 0; i < cEntries; i++)
		paBlocks[i] = SET_ENDIAN_U32(enmConv, paBlocks[i]);
}

/**
 * Internal: Free all allocated space for representing an image, and optionally
 * delete the image from disk.
 */
static int vdiFreeImage(PVDIIMAGEDESC pImage)
{
	int rc = GRUB_ERR_NONE;

	/* Freeing a never allocated image (e.g. because the open failed) is
	 * not signalled as an error. After all nothing bad happens. */
	if (pImage)
	{
		if (pImage->paBlocks)
		{
			grub_free(pImage->paBlocks);
			pImage->paBlocks = NULL;
		}

		if (pImage->paBlocksRev)
		{
			grub_free(pImage->paBlocksRev);
			pImage->paBlocksRev = NULL;
		}
	}

	return rc;
}

/**
 * internal: return power of 2 or 0 if num error.
 */
static unsigned getPowerOfTwo(unsigned uNumber)
{
	if (uNumber == 0)
		return 0;
	unsigned uPower2 = 0;
	while ((uNumber & 1) == 0)
	{
		uNumber >>= 1;
		uPower2++;
	}
	return uNumber == 1 ? uPower2 : 0;
}

/**
 * Internal: check VDI preheader.
 */
static int vdiValidatePreHeader(PVDIPREHEADER pPreHdr)
{
	if (pPreHdr->u32Signature != VDI_IMAGE_SIGNATURE)
		return GRUB_ERR_BAD_DEVICE;

	if (VDI_GET_VERSION_MAJOR(pPreHdr->u32Version) != VDI_IMAGE_VERSION_MAJOR
		&& pPreHdr->u32Version != 0x00000002)    /* old version. */
		return GRUB_ERR_NOT_IMPLEMENTED_YET;

	return GRUB_ERR_NONE;
}

/**
 * Internal: translate VDI image type enum to VD image type enum.
 */
static unsigned vdiTranslateVDI2ImageFlags(VDIIMAGETYPE enmType)
{
	switch (enmType)
	{
	case VDI_IMAGE_TYPE_NORMAL:
		return VD_IMAGE_FLAGS_NONE;
	case VDI_IMAGE_TYPE_FIXED:
		return VD_IMAGE_FLAGS_FIXED;
	case VDI_IMAGE_TYPE_DIFF:
		return VD_IMAGE_FLAGS_DIFF;
	default:
		return VD_IMAGE_FLAGS_NONE;
	}
}

/**
 * Internal: Check VDI header.
 */
static int vdiValidateHeader(PVDIHEADER pHeader)
{
	/* Check version-dependent header parameters. */
	switch (GET_MAJOR_HEADER_VERSION(pHeader))
	{
	case 0:
	{
		/* Old header version. */
		break;
	}
	case 1:
	{
		/* Current header version. */

		if (pHeader->u.v1.cbHeader < sizeof(VDIHEADER1))
		{
			return GRUB_ERR_BAD_DEVICE;
		}

		if (getImageBlocksOffset(pHeader) < (sizeof(VDIPREHEADER) + sizeof(VDIHEADER1)))
		{
			return GRUB_ERR_BAD_DEVICE;
		}

		if (getImageDataOffset(pHeader) < (getImageBlocksOffset(pHeader) + getImageBlocks(pHeader) * sizeof(VDIIMAGEBLOCKPOINTER)))
		{
			return GRUB_ERR_BAD_DEVICE;
		}

		break;
	}
	default:
		/* Unsupported. */
		return GRUB_ERR_NOT_IMPLEMENTED_YET;
	}

	/* Check common header parameters. */

	int fFailed = 0;

	if (getImageType(pHeader) < VDI_IMAGE_TYPE_FIRST
		|| getImageType(pHeader) > VDI_IMAGE_TYPE_LAST)
	{
		fFailed = 1;
	}

	/* Undo/differencing VDIs reference their parent through the
	 * VirtualBox media registry (by UUID, no path stored in the
	 * image), so they cannot be resolved here.  Refuse them instead
	 * of silently presenting incomplete data. */
	if (getImageType(pHeader) == VDI_IMAGE_TYPE_UNDO
		|| getImageType(pHeader) == VDI_IMAGE_TYPE_DIFF)
	{
		fFailed = 1;
	}

	if (getImageFlags(pHeader) & ~VD_VDI_IMAGE_FLAGS_MASK)
	{
		fFailed = 1;
	}

	if (getImageLCHSGeometry(pHeader)
		&& (getImageLCHSGeometry(pHeader))->cbSector != VDI_GEOMETRY_SECTOR_SIZE)
	{
		fFailed = 1;
	}

	if (getImageDiskSize(pHeader) == 0
		|| getImageBlockSize(pHeader) == 0
		|| getImageBlocks(pHeader) == 0
		|| getPowerOfTwo(getImageBlockSize(pHeader)) == 0)
	{
		fFailed = 1;
	}

	if (getImageBlocksAllocated(pHeader) > getImageBlocks(pHeader))
	{
		fFailed = 1;
	}

	if (getImageExtraBlockSize(pHeader) != 0
		&& getPowerOfTwo(getImageExtraBlockSize(pHeader)) == 0)
	{
		fFailed = 1;
	}

	if ((grub_uint64_t)getImageBlockSize(pHeader) * getImageBlocks(pHeader) < getImageDiskSize(pHeader))
	{
		fFailed = 1;
	}

	if (RTUuidIsNull(getImageCreationUUID(pHeader)))
	{
		fFailed = 1;
	}

	if (RTUuidIsNull(getImageModificationUUID(pHeader)))
	{
		fFailed = 1;
	}

	return fFailed ? GRUB_ERR_BAD_DEVICE : GRUB_ERR_NONE;
}

/**
 * Internal: Set up VDIIMAGEDESC structure by image header.
 */
static void vdiSetupImageDesc(PVDIIMAGEDESC pImage)
{
	pImage->uImageFlags = getImageFlags(&pImage->Header);
	pImage->uImageFlags |= vdiTranslateVDI2ImageFlags(getImageType(&pImage->Header));
	pImage->offStartBlocks = getImageBlocksOffset(&pImage->Header);
	pImage->offStartData = getImageDataOffset(&pImage->Header);
	pImage->uBlockMask = getImageBlockSize(&pImage->Header) - 1;
	pImage->uShiftOffset2Index = getPowerOfTwo(getImageBlockSize(&pImage->Header));
	pImage->offStartBlockData = getImageExtraBlockSize(&pImage->Header);
	pImage->cbAllocationBlock = getImageBlockSize(&pImage->Header);
	pImage->cbTotalBlockData = pImage->offStartBlockData
		+ getImageBlockSize(&pImage->Header);
}

static int vdiFileReadSync(PVDIIMAGEDESC pImage, grub_uint64_t off, void* pvBuf, grub_size_t cbRead, grub_ssize_t* pcbRead)
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
		return grub_error(GRUB_ERR_FILE_READ_ERROR, "short read in VDI image");
	return GRUB_ERR_NONE;
}

/**
 * Reads and validates the header for the given image descriptor.
 *
 * @returns VBox status code.
 * @param   pImage          The VDI image descriptor.
 */
static int vdiImageReadHeader(PVDIIMAGEDESC pImage)
{
	/* Get file size. */
	pImage->cbImage = pImage->FileSize;

	/* Read pre-header. */
	VDIPREHEADER PreHeader;
	int rc = vdiFileReadSync(pImage, 0,
		&PreHeader, sizeof(PreHeader), NULL);
	if (RT_SUCCESS(rc))
	{
		vdiConvPreHeaderEndianess(VDIECONV_F2H, &pImage->PreHeader, &PreHeader);
		rc = vdiValidatePreHeader(&pImage->PreHeader);
		if (RT_SUCCESS(rc))
		{
			/* Read header. */
			pImage->Header.uVersion = pImage->PreHeader.u32Version;
			switch (GET_MAJOR_HEADER_VERSION(&pImage->Header))
			{
			case 0:
				rc = vdiFileReadSync(pImage, sizeof(pImage->PreHeader),
					&pImage->Header.u.v0, sizeof(pImage->Header.u.v0), NULL);
				if (RT_SUCCESS(rc))
					vdiConvHeaderEndianessV0(VDIECONV_F2H, &pImage->Header.u.v0, &pImage->Header.u.v0);
				else
					rc = GRUB_ERR_FILE_READ_ERROR;
				break;
			case 1:
				rc = vdiFileReadSync(pImage, sizeof(pImage->PreHeader),
					&pImage->Header.u.v1, sizeof(pImage->Header.u.v1), NULL);
				if (RT_SUCCESS(rc))
				{
					vdiConvHeaderEndianessV1(VDIECONV_F2H, &pImage->Header.u.v1, &pImage->Header.u.v1);
					/* Convert VDI 1.1 images to VDI 1.1+ on open in read/write mode.
					 * Conversion is harmless, as any VirtualBox version supporting VDI
					 * 1.1 doesn't touch fields it doesn't know about. */
					if (GET_MINOR_HEADER_VERSION(&pImage->Header) == 1
						&& pImage->Header.u.v1.cbHeader < sizeof(pImage->Header.u.v1plus))
					{
						pImage->Header.u.v1plus.cbHeader = sizeof(pImage->Header.u.v1plus);
						/* Mark LCHS geometry not-calculated. */
						pImage->Header.u.v1plus.LCHSGeometry.cCylinders = 0;
						pImage->Header.u.v1plus.LCHSGeometry.cHeads = 0;
						pImage->Header.u.v1plus.LCHSGeometry.cSectors = 0;
						pImage->Header.u.v1plus.LCHSGeometry.cbSector = VDI_GEOMETRY_SECTOR_SIZE;
					}
					else if (pImage->Header.u.v1.cbHeader >= sizeof(pImage->Header.u.v1plus))
					{
						/* Read the actual VDI 1.1+ header completely. */
						rc = vdiFileReadSync(pImage, sizeof(pImage->PreHeader),
							&pImage->Header.u.v1plus,
							sizeof(pImage->Header.u.v1plus), NULL);
						if (RT_SUCCESS(rc))
							vdiConvHeaderEndianessV1p(VDIECONV_F2H, &pImage->Header.u.v1plus, &pImage->Header.u.v1plus);
						else
							rc = GRUB_ERR_FILE_READ_ERROR;
					}
				}
				else
					rc = GRUB_ERR_FILE_READ_ERROR;
				break;
			default:
				rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
			}

			if (RT_SUCCESS(rc))
			{
				rc = vdiValidateHeader(&pImage->Header);
				if (RT_SUCCESS(rc))
				{
					/* Setup image parameters by header. */
					vdiSetupImageDesc(pImage);

					/*
					 * Until revision r111992 there was no check that the size was sector aligned
					 * when creating a new image and a bug in the VirtualBox GUI on OS X resulted
					 * in such images being created which caused issues when writing to the
					 * end of the image.
					 *
					 * Detect such images and repair the small damage by rounding down to the next
					 * aligned size. This is no problem as the guest would see a sector count
					 * only anyway from the device emulations so it already sees only the smaller
					 * size as result of the integer division of the size and sector size.
					 *
					 * This might not be written to the image if it is opened readonly
					 * which is not much of a problem because only writing to the last block
					 * causes trouble.
					 */
					grub_uint64_t cbDisk = getImageDiskSize(&pImage->Header);
					if (cbDisk & 0x1ff)
						setImageDiskSize(&pImage->Header, cbDisk & ~0x1ffULL);
				}
				else
					rc = GRUB_ERR_BAD_DEVICE;
			}
		}
		else
			rc = GRUB_ERR_BAD_DEVICE;
	}
	else
	{
		rc = GRUB_ERR_BAD_DEVICE;
	}

	return rc;
}

/**
 * Internal: Open a VDI image.
 */
static int
vdiOpenImage(PVDIIMAGEDESC pImage)
{
	grub_uint64_t cbBlockTable;

	pImage->FileSize = grub_file_size(pImage->File);

	int rc = vdiImageReadHeader(pImage);
	if (RT_SUCCESS(rc))
	{
		cbBlockTable = (grub_uint64_t)getImageBlocks(&pImage->Header)
			* sizeof(VDIIMAGEBLOCKPOINTER);
		if (pImage->offStartBlocks > pImage->FileSize
			|| cbBlockTable > pImage->FileSize - pImage->offStartBlocks
			|| pImage->offStartData > pImage->FileSize)
			rc = GRUB_ERR_BAD_DEVICE;
		else
		{
			/* Allocate memory for blocks array. */
			pImage->paBlocks = (PVDIIMAGEBLOCKPOINTER)grub_calloc(
				getImageBlocks(&pImage->Header), sizeof(VDIIMAGEBLOCKPOINTER));
			if (pImage->paBlocks)
			{
				/* Read blocks array. */
				rc = vdiFileReadSync(pImage, pImage->offStartBlocks,
					pImage->paBlocks, (grub_size_t)cbBlockTable, NULL);
				if (RT_SUCCESS(rc))
					vdiConvBlocksEndianess(VDIECONV_F2H, pImage->paBlocks,
						getImageBlocks(&pImage->Header));
			}
			else
				rc = GRUB_ERR_OUT_OF_MEMORY;
		}
	}

	if (RT_FAILURE(rc))
		vdiFreeImage(pImage);
	return rc;
}

static int
vdiOpen(grub_file_t File, void** ppBackendData)
{
	int rc;

	PVDIIMAGEDESC pImage = (PVDIIMAGEDESC)grub_zalloc(sizeof(VDIIMAGEDESC));
	if (pImage)
	{
		pImage->File = File;
		pImage->paBlocks = NULL;

		rc = vdiOpenImage(pImage);
		if (RT_SUCCESS(rc))
			*ppBackendData = pImage;
		else
			grub_free(pImage);
	}
	else
		rc = GRUB_ERR_OUT_OF_MEMORY;

	return rc;
}

/** @copydoc VDIMAGEBACKEND::pfnClose */
static int
vdiClose(void* pBackendData)
{
	PVDIIMAGEDESC pImage = (PVDIIMAGEDESC)pBackendData;

	int rc = vdiFreeImage(pImage);
	grub_free(pImage);

	return rc;
}

static int
vdiRead(void* pBackendData, grub_uint64_t uOffset, void* pvBuf, grub_size_t cbToRead, grub_size_t* pcbActuallyRead)
{
	PVDIIMAGEDESC pImage = (PVDIIMAGEDESC)pBackendData;
	grub_uint64_t cbDisk = getImageDiskSize(&pImage->Header);
	unsigned uBlock;
	unsigned offRead;
	int rc = GRUB_ERR_NONE;

	if (pcbActuallyRead)
		*pcbActuallyRead = 0;

	if (uOffset > cbDisk || cbToRead > cbDisk - uOffset)
		return GRUB_ERR_OUT_OF_RANGE;

	/* Calculate starting block number and offset inside it. */
	uBlock = (unsigned)(uOffset >> pImage->uShiftOffset2Index);
	offRead = (unsigned)uOffset & pImage->uBlockMask;

	/* Clip read range to at most the rest of the block. */
	cbToRead = RT_MIN(cbToRead, getImageBlockSize(&pImage->Header) - offRead);

	if (pImage->paBlocks[uBlock] == VDI_IMAGE_BLOCK_FREE
		|| pImage->paBlocks[uBlock] == VDI_IMAGE_BLOCK_ZERO)
	{
		grub_memset(pvBuf, 0, cbToRead);
	}
	else
	{
		/* Block present in image file, read relevant data. */
		grub_uint64_t u64Offset = (grub_uint64_t)pImage->paBlocks[uBlock] * pImage->cbTotalBlockData
			+ (pImage->offStartData + pImage->offStartBlockData + offRead);

		if (u64Offset <= pImage->cbImage
			&& cbToRead <= pImage->cbImage - u64Offset)
			rc = vdiFileReadSync(pImage, u64Offset,
				pvBuf, cbToRead, NULL);
		else
		{
			grub_memset(pvBuf, 0, cbToRead);
			rc = GRUB_ERR_OUT_OF_RANGE;
		}
	}

	if (rc == GRUB_ERR_NONE && pcbActuallyRead)
		*pcbActuallyRead = cbToRead;

	return rc;
}

static grub_uint64_t
vdiGetSize(void* pBackendData)
{
	PVDIIMAGEDESC pImage = (PVDIIMAGEDESC)pBackendData;

	if (pImage)
		return getImageDiskSize(&pImage->Header);
	return 0;
}


struct grub_vdi
{
	grub_file_t file;
	void* vdi;
};
typedef struct grub_vdi* grub_vdi_t;

static struct grub_fs grub_vdi_fs;

static grub_err_t
grub_vdi_close(grub_file_t file)
{
	grub_vdi_t vdiio = file->data;

	vdiClose(vdiio->vdi);
	grub_file_close(vdiio->file);
	grub_free(vdiio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_vdi_open(grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_vdi_t vdiio;
	void* vdi = NULL;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < 0x10000 || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	if (vdiOpen(io, &vdi) != GRUB_ERR_NONE)
	{
		grub_file_seek(io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t)grub_zalloc(sizeof(*file));
	if (!file)
	{
		vdiClose(vdi);
		return 0;
	}

	vdiio = grub_zalloc(sizeof(*vdiio));
	if (!vdiio)
	{
		vdiClose(vdi);
		grub_free(file);
		return 0;
	}
	vdiio->file = io;
	vdiio->vdi = vdi;

	file->device = io->device;
	file->data = vdiio;
	file->fs = &grub_vdi_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = vdiGetSize(vdi);

	return file;
}

static grub_ssize_t
grub_vdi_read(grub_file_t file, char* buf, grub_size_t len)
{
	int rc = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_size_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_vdi_t vdiio = file->data;

	while (len > 0 && rc == GRUB_ERR_NONE)
	{
		real_size = 0;
		rc = vdiRead(vdiio->vdi, read_offset, buf, len, &real_size);
		if (rc != GRUB_ERR_NONE)
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
		grub_error((grub_err_t)rc, "VDI image read failed");
		return -1;
	}
	return (grub_ssize_t)size;
}

static struct grub_fs grub_vdi_fs =
{
	.name = "vdi",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_vdi_read,
	.fs_close = grub_vdi_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT(vdi)
{
	grub_file_filter_register(GRUB_FILE_FILTER_VDI, grub_vdi_open);
}

GRUB_MOD_FINI(vdi)
{
	grub_file_filter_unregister(GRUB_FILE_FILTER_VDI);
}
