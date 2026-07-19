/* $Id: QCOW.cpp $ */
/** @file
 * QCOW - QCOW Disk image.
 */

 /*
  * Copyright (C) 2011-2023 Oracle and/or its affiliates.
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

/* For ZSTD_findFrameCompressedSize(). */
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <vbox.h>

GRUB_MOD_LICENSE("GPLv3+");

/** @page pg_storage_qcow   QCOW Storage Backend
 * The QCOW backend implements support for the qemu copy on write format (short QCOW).
 *
 * The official specification for qcow is available at
 * https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt version 2 and 3.
 * For version 1 there is no official specification available but the format is described
 * at http://people.gnome.org/~markmc/qcow-image-format-version-1.html.
 *
 * Missing things to implement:
 *    - v2 image creation and handling of the reference count table. (Blocker to enable support for V2 images)
 *    - cluster encryption
 *    - cluster compression
 *    - compaction
 *    - resizing
 */

/*********************************************************************************************************************************
 *   Structures in a QCOW image, big endian                                                                                       *
 *********************************************************************************************************************************/

#pragma pack(1) /* Completely unnecessary. */
typedef struct QCowHeader
{
	/** Magic value. */
	grub_uint32_t    u32Magic;
	/** Version of the image. */
	grub_uint32_t    u32Version;
	/** Version dependent data. */
	union
	{
		/** Version 1. */
		struct
		{
			/** Backing file offset. */
			grub_uint64_t    u64BackingFileOffset;
			/** Size of the backing file. */
			grub_uint32_t    u32BackingFileSize;
			/** mtime (Modification time?) - can be ignored. */
			grub_uint32_t    u32MTime;
			/** Logical size of the image in bytes. */
			grub_uint64_t    u64Size;
			/** Number of bits in the virtual offset used as a cluster offset. */
			grub_uint8_t     u8ClusterBits;
			/** Number of bits in the virtual offset used for the L2 index. */
			grub_uint8_t     u8L2Bits;
			/** Padding because the header is not packed in the original source. */
			grub_uint16_t    u16Padding;
			/** Used cryptographic method. */
			grub_uint32_t    u32CryptMethod;
			/** Offset of the L1 table in the image in bytes. */
			grub_uint64_t    u64L1TableOffset;
		} v1;
		/** Version 2 (and also containing extensions for version 3). */
		struct
		{
			/** Backing file offset. */
			grub_uint64_t    u64BackingFileOffset;
			/** Size of the backing file. */
			grub_uint32_t    u32BackingFileSize;
			/** Number of bits in the virtual offset used as a cluster offset. */
			grub_uint32_t    u32ClusterBits;
			/** Logical size of the image. */
			grub_uint64_t    u64Size;
			/** Used cryptographic method. */
			grub_uint32_t    u32CryptMethod;
			/** Size of the L1 table in entries (each 8bytes big). */
			grub_uint32_t    u32L1Size;
			/** Offset of the L1 table in the image in bytes. */
			grub_uint64_t    u64L1TableOffset;
			/** Start of the refcount table in the image. */
			grub_uint64_t    u64RefcountTableOffset;
			/** Size of the refcount table in clusters. */
			grub_uint32_t    u32RefcountTableClusters;
			/** Number of snapshots in the image. */
			grub_uint32_t    u32NbSnapshots;
			/** Offset of the first snapshot header in the image. */
			grub_uint64_t    u64SnapshotsOffset;
			/** Version 3 additional data. */
			struct
			{
				/** Incompatible features. */
				grub_uint64_t    u64IncompatFeat;
				/** Compatible features. */
				grub_uint64_t    u64CompatFeat;
				/** Autoclear features. */
				grub_uint64_t    u64AutoClrFeat;
				/** Width in bits of a reference count block. */
				grub_uint32_t    u32RefCntWidth;
				/** Lenght of the header structure in bytes (for the header extensions). */
				grub_uint32_t    u32HdrLenBytes;
				/** Compression type (present if the incompatible
				 * compression type feature bit is set). */
				grub_uint8_t     u8CompressionType;
				/** Pad the header to an 8 byte multiple. */
				grub_uint8_t     au8Padding[7];
			} v3;
		} v2;
	} Version;
} QCowHeader;
#pragma pack()
/** Pointer to a on disk QCOW header. */
typedef QCowHeader* PQCowHeader;

/** QCOW magic value. */
#define QCOW_MAGIC                            0x514649fbU /* QFI\0xfb */
/** Size of the V1 header. */
#define QCOW_V1_HDR_SIZE                      (48)
/** Size of the V2 header. */
#define QCOW_V2_HDR_SIZE                      (72)

/** Supported QCOW1 cluster and L2 table bit ranges. */
#define QCOW_V1_CLUSTER_BITS_MIN              9
#define QCOW_V1_CLUSTER_BITS_MAX              16
#define QCOW_V1_L2_BITS_MIN                   6
#define QCOW_V1_L2_BITS_MAX                   13
/** Supported QCOW2 cluster bit range (512 bytes through 2 MiB). */
#define QCOW_V2_CLUSTER_BITS_MIN              9
#define QCOW_V2_CLUSTER_BITS_MAX              21
/** Keep metadata allocations bounded like QEMU's active L1 limit. */
#define QCOW_L1_TABLE_SIZE_MAX                (32*_1M)

/** Cluster is compressed flag for QCOW images. */
#define QCOW_V1_COMPRESSED_FLAG               RT_BIT_64(63)

/** Copied flag for QCOW2 images. */
#define QCOW_V2_COPIED_FLAG                   RT_BIT_64(63)
/** Cluster is compressed flag for QCOW2 images. */
#define QCOW_V2_COMPRESSED_FLAG               RT_BIT_64(62)
/** The mask for extracting the offset from either the L1 or L2 table. */
#define QCOW_V2_TBL_OFFSET_MASK               0x00fffffffffffe00ULL

/** Incompatible feature: Dirty bit, reference count may be inconsistent. */
#define QCOW_V3_INCOMPAT_FEAT_F_DIRTY         RT_BIT_64(0)
/** Incompatible feature: Image is corrupt and needs repair. */
#define QCOW_V3_INCOMPAT_FEAT_F_CORRUPT       RT_BIT_64(1)
/** Incompatible feature: External data file. */
#define QCOW_V3_INCOMPAT_FEAT_F_EXTERNAL_DATA RT_BIT_64(2)
/** Incompatible feature: Non-deflate compression type in the header. */
#define QCOW_V3_INCOMPAT_FEAT_F_COMPRESSION   RT_BIT_64(3)
/** The incompatible features we support currently.  The dirty bit only
 * means the refcounts may be stale, which read-only access never uses. */
#define QCOW_V3_INCOMPAT_FEAT_SUPPORTED_MASK \
	(QCOW_V3_INCOMPAT_FEAT_F_DIRTY | QCOW_V3_INCOMPAT_FEAT_F_COMPRESSION)

/** Compression type: deflate (raw zlib). */
#define QCOW_COMPRESSION_TYPE_ZLIB            0
/** Compression type: zstandard. */
#define QCOW_COMPRESSION_TYPE_ZSTD            1

/** Cluster lookup outcome: data in this file. */
#define QCOW_CLUSTER_ALLOCATED                0
/** Cluster lookup outcome: unallocated, backing file or zeros. */
#define QCOW_CLUSTER_FREE                     1
/** Cluster lookup outcome: reads as zeros. */
#define QCOW_CLUSTER_ZERO                     2

/** Compatible feature: Lazy reference counters. */
#define QCOW_V3_COMPAT_FEAT_F_LAZY_REF_COUNT  RT_BIT_64(0)
/** The compatible features we support currently. */
#define QCOW_V3_COMPAT_FEAT_SUPPORTED_MASK    0x0ULL

/** Auto clear feature: Bitmaps extension. */
#define QCOW_V3_AUTOCLR_FEAT_F_BITMAPS        RT_BIT_64(0)
/** Auto clear feature: The external data file is raw image which can be accessed standalone. */
#define QCOW_V3_AUTOCLR_FEAT_F_EXT_RAW_DATA   RT_BIT_64(1)
/** The autoclear features we support currently. */
#define QCOW_V3_AUTOCLR_FEAT_SUPPORTED_MASK   0x0ULL


/*********************************************************************************************************************************
*   Constants And Macros, Structures and Typedefs                                                                                *
*********************************************************************************************************************************/

/**
 * QCOW L2 cache entry.
 */
typedef struct QCOWL2CACHEENTRY
{
	/** List node for the search list. */
	RTLISTNODE              NodeSearch;
	/** List node for the LRU list. */
	RTLISTNODE              NodeLru;
	/** Reference counter. */
	grub_uint32_t           cRefs;
	/** The offset of the L2 table, used as search key. */
	grub_uint64_t           offL2Tbl;
	/** Pointer to the cached L2 table. */
	grub_uint64_t* paL2Tbl;
} QCOWL2CACHEENTRY, * PQCOWL2CACHEENTRY;

/** Maximum amount of memory the cache is allowed to use. */
#define QCOW_L2_CACHE_MEMORY_MAX (2*_1M)

/** QCOW default cluster size for image version 2. */
#define QCOW2_CLUSTER_SIZE_DEFAULT (64*_1K)
/** QCOW default cluster size for image version 1. */
#define QCOW_CLUSTER_SIZE_DEFAULT (4*_1K)
/** QCOW default L2 table size in clusters. */
#define QCOW_L2_CLUSTERS_DEFAULT (1)

/**
 * QCOW image data structure.
 */
typedef struct QCOWIMAGE
{
	/** Descriptor file if applicable. */
	grub_file_t File;
	/** File size on the host disk (including all headers). */
	grub_uint64_t   FileSize;

	/** Open flags passed by VBoxHD layer. */
	//unsigned            uOpenFlags;
	/** Image flags defined during creation or determined during open. */
	unsigned            uImageFlags;
	/** Total size of the image. */
	grub_uint64_t            cbSize;

	/** Image version. */
	unsigned            uVersion;
	/** Cluster compression type (QCOW_COMPRESSION_TYPE_*). */
	grub_uint8_t             u8CompressionType;
	/** MTime field - used only to preserve value in opened images, unmodified otherwise. */
	grub_uint32_t            MTime;

	/** Opened backing file, if any. */
	grub_file_t         Backing;

	/** Filename of the backing file if any. */
	//char* pszBackingFilename;
	/** Offset of the filename in the image. */
	grub_uint64_t            offBackingFilename;
	/** Size of the backing filename excluding \0. */
	grub_uint32_t            cbBackingFilename;

	/** Next offset of a new cluster, aligned to sector size. */
	grub_uint64_t            offNextCluster;
	/** Cluster size in bytes. */
	grub_uint32_t            cbCluster;
	/** Number of bits in the virtual offset used as the cluster offset. */
	grub_uint32_t            cClusterBits;
	/** Bitmask to extract the offset from a compressed cluster descriptor. */
	grub_uint64_t            fMaskCompressedClusterOffset;
	/** Bitmask to extract the sector count from a compressed cluster descriptor. */
	grub_uint64_t            fMaskCompressedClusterSectors;
	/** Number of bits to shift the sector count to the right to get the final value. */
	grub_uint32_t            cBitsShiftRCompressedClusterSectors;
	/** Number of entries in the L1 table. */
	grub_uint32_t            cL1TableEntries;
	/** Size of the active L1 table in bytes. */
	grub_uint32_t            cbL1Table;
	/** Pointer to the L1 table. */
	grub_uint64_t* paL1Table;
	/** Offset of the L1 table. */
	grub_uint64_t            offL1Table;

	/** Size of the L2 table in bytes. */
	grub_uint32_t            cbL2Table;
	/** Number of entries in the L2 table. */
	grub_uint32_t            cL2TableEntries;
	/** Memory occupied by the L2 table cache. */
	grub_size_t              cbL2Cache;
	/** The sorted L2 entry list used for searching. */
	RTLISTNODE          ListSearch;
	/** The LRU L2 entry list used for eviction. */
	RTLISTNODE          ListLru;

	/** Offset of the refcount table. */
	grub_uint64_t            offRefcountTable;
	/** Size of the refcount table in bytes. */
	grub_uint32_t            cbRefcountTable;
	/** Number of entries in the refcount table. */
	grub_uint32_t            cRefcountTableEntries;
	/** Pointer to the refcount table. */
	//grub_uint64_t* paRefcountTable;

	/** Offset mask for a cluster. */
	grub_uint64_t            fOffsetMask;
	/** Number of bits to shift to get the L1 index. */
	grub_uint32_t            cL1Shift;
	/** L2 table mask to get the L2 index. */
	grub_uint64_t            fL2Mask;
	/** Number of bits to shift to get the L2 index. */
	grub_uint32_t            cL2Shift;

	/** Size of compressed cluster buffer. */
	grub_size_t              cbCompCluster;
	/** Compressed cluster buffer. */
	void* pvCompCluster;
	/** Buffer to hold the uncompressed data. */
	void* pvCluster;

	/** Pointer to the L2 table we are currently allocating
	 * (can be only one at a time). */
	PQCOWL2CACHEENTRY   pL2TblAlloc;
} QCOWIMAGE, * PQCOWIMAGE;

/**
 * State of the async cluster allocation.
 */
typedef enum QCOWCLUSTERASYNCALLOCSTATE
{
	/** Invalid. */
	QCOWCLUSTERASYNCALLOCSTATE_INVALID = 0,
	/** L2 table allocation. */
	QCOWCLUSTERASYNCALLOCSTATE_L2_ALLOC,
	/** Link L2 table into L1. */
	QCOWCLUSTERASYNCALLOCSTATE_L2_LINK,
	/** Allocate user data cluster. */
	QCOWCLUSTERASYNCALLOCSTATE_USER_ALLOC,
	/** Link user data cluster. */
	QCOWCLUSTERASYNCALLOCSTATE_USER_LINK,
	/** 32bit blowup. */
	QCOWCLUSTERASYNCALLOCSTATE_32BIT_HACK = 0x7fffffff
} QCOWCLUSTERASYNCALLOCSTATE, * PQCOWCLUSTERASYNCALLOCSTATE;

/**
 * Data needed to track async cluster allocation.
 */
typedef struct QCOWCLUSTERASYNCALLOC
{
	/** The state of the cluster allocation. */
	QCOWCLUSTERASYNCALLOCSTATE enmAllocState;
	/** Old image size to rollback in case of an error. */
	grub_uint64_t                   offNextClusterOld;
	/** L1 index to link if any. */
	grub_uint32_t                   idxL1;
	/** L2 index to link, required in any case. */
	grub_uint32_t                   idxL2;
	/** Start offset of the allocated cluster. */
	grub_uint64_t                   offClusterNew;
	/** L2 cache entry if a L2 table is allocated. */
	PQCOWL2CACHEENTRY          pL2Entry;
	/** Number of bytes to write. */
	grub_size_t                     cbToWrite;
} QCOWCLUSTERASYNCALLOC, * PQCOWCLUSTERASYNCALLOC;

/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

static int qcowFileReadSync(PQCOWIMAGE pImage, grub_uint64_t off, void* pvBuf, grub_size_t cbRead, grub_ssize_t* pcbRead)
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
		return grub_error(GRUB_ERR_FILE_READ_ERROR, "short read in QCOW image");
	return GRUB_ERR_NONE;
}

static int qcowRangeValid(grub_uint64_t off, grub_uint64_t cb, grub_uint64_t cbLimit)
{
	return off <= cbLimit && cb <= cbLimit - off;
}

/**
 * Return power of 2 or 0 if num error.
 *
 * @returns The power of 2 or 0 if the given number is not a power of 2.
 * @param   u32    The number.
 */
static grub_uint32_t qcowGetPowerOfTwo(grub_uint32_t u32)
{
	if (u32 == 0)
		return 0;
	grub_uint32_t uPower2 = 0;
	while ((u32 & 1) == 0)
	{
		u32 >>= 1;
		uPower2++;
	}
	return u32 == 1 ? uPower2 : 0;
}


/**
 * Converts the image header to the host endianess and performs basic checks.
 *
 * @returns Whether the given header is valid or not.
 * @param   pHeader    Pointer to the header to convert.
 */
static int qcowHdrConvertToHostEndianess(PQCowHeader pHeader)
{
	pHeader->u32Magic = RT_BE2H_U32(pHeader->u32Magic);
	pHeader->u32Version = RT_BE2H_U32(pHeader->u32Version);

	if (pHeader->u32Magic != QCOW_MAGIC)
		return false;

	if (pHeader->u32Version == 1)
	{
		pHeader->Version.v1.u64BackingFileOffset = RT_BE2H_U64(pHeader->Version.v1.u64BackingFileOffset);
		pHeader->Version.v1.u32BackingFileSize = RT_BE2H_U32(pHeader->Version.v1.u32BackingFileSize);
		pHeader->Version.v1.u32MTime = RT_BE2H_U32(pHeader->Version.v1.u32MTime);
		pHeader->Version.v1.u64Size = RT_BE2H_U64(pHeader->Version.v1.u64Size);
		pHeader->Version.v1.u32CryptMethod = RT_BE2H_U32(pHeader->Version.v1.u32CryptMethod);
		pHeader->Version.v1.u64L1TableOffset = RT_BE2H_U64(pHeader->Version.v1.u64L1TableOffset);
	}
	else if (pHeader->u32Version == 2 || pHeader->u32Version == 3)
	{
		pHeader->Version.v2.u64BackingFileOffset = RT_BE2H_U64(pHeader->Version.v2.u64BackingFileOffset);
		pHeader->Version.v2.u32BackingFileSize = RT_BE2H_U32(pHeader->Version.v2.u32BackingFileSize);
		pHeader->Version.v2.u32ClusterBits = RT_BE2H_U32(pHeader->Version.v2.u32ClusterBits);
		pHeader->Version.v2.u64Size = RT_BE2H_U64(pHeader->Version.v2.u64Size);
		pHeader->Version.v2.u32CryptMethod = RT_BE2H_U32(pHeader->Version.v2.u32CryptMethod);
		pHeader->Version.v2.u32L1Size = RT_BE2H_U32(pHeader->Version.v2.u32L1Size);
		pHeader->Version.v2.u64L1TableOffset = RT_BE2H_U64(pHeader->Version.v2.u64L1TableOffset);
		pHeader->Version.v2.u64RefcountTableOffset = RT_BE2H_U64(pHeader->Version.v2.u64RefcountTableOffset);
		pHeader->Version.v2.u32RefcountTableClusters = RT_BE2H_U32(pHeader->Version.v2.u32RefcountTableClusters);
		pHeader->Version.v2.u32NbSnapshots = RT_BE2H_U32(pHeader->Version.v2.u32NbSnapshots);
		pHeader->Version.v2.u64SnapshotsOffset = RT_BE2H_U64(pHeader->Version.v2.u64SnapshotsOffset);

		if (pHeader->u32Version == 3)
		{
			pHeader->Version.v2.v3.u64IncompatFeat = RT_BE2H_U64(pHeader->Version.v2.v3.u64IncompatFeat);
			pHeader->Version.v2.v3.u64CompatFeat = RT_BE2H_U64(pHeader->Version.v2.v3.u64CompatFeat);
			pHeader->Version.v2.v3.u64AutoClrFeat = RT_BE2H_U64(pHeader->Version.v2.v3.u64AutoClrFeat);
			pHeader->Version.v2.v3.u32RefCntWidth = RT_BE2H_U32(pHeader->Version.v2.v3.u32RefCntWidth);
			pHeader->Version.v2.v3.u32HdrLenBytes = RT_BE2H_U32(pHeader->Version.v2.v3.u32HdrLenBytes);
		}
	}
	else
		return false;

	return true;
}

/**
 * Convert table entries from little endian to host endianess.
 *
 * @param   paTbl       Pointer to the table.
 * @param   cEntries    Number of entries in the table.
 */
static void qcowTableConvertToHostEndianess(grub_uint64_t* paTbl, grub_uint32_t cEntries)
{
	while (cEntries-- > 0)
	{
		*paTbl = RT_BE2H_U64(*paTbl);
		paTbl++;
	}
}

/**
 * Creates the L2 table cache.
 *
 * @returns VBox status code.
 * @param   pImage    The image instance data.
 */
static int qcowL2TblCacheCreate(PQCOWIMAGE pImage)
{
	pImage->cbL2Cache = 0;
	RTListInit(&pImage->ListSearch);
	RTListInit(&pImage->ListLru);

	return GRUB_ERR_NONE;
}

/**
 * Destroys the L2 table cache.
 *
 * @param   pImage    The image instance data.
 */
static void qcowL2TblCacheDestroy(PQCOWIMAGE pImage)
{
	PQCOWL2CACHEENTRY pL2Entry;
	PQCOWL2CACHEENTRY pL2Next;
	RTListForEachSafe(&pImage->ListSearch, pL2Entry, pL2Next, QCOWL2CACHEENTRY, NodeSearch)
	{
		RTListNodeRemove(&pL2Entry->NodeSearch);
		grub_free(pL2Entry->paL2Tbl);
		grub_free(pL2Entry);
	}

	pImage->cbL2Cache = 0;
	RTListInit(&pImage->ListSearch);
	RTListInit(&pImage->ListLru);
}

/**
 * Returns the L2 table matching the given offset or NULL if none could be found.
 *
 * @returns Pointer to the L2 table cache entry or NULL.
 * @param   pImage    The image instance data.
 * @param   offL2Tbl  Offset of the L2 table to search for.
 */
static PQCOWL2CACHEENTRY qcowL2TblCacheRetain(PQCOWIMAGE pImage, grub_uint64_t offL2Tbl)
{
	if (pImage->pL2TblAlloc
		&& pImage->pL2TblAlloc->offL2Tbl == offL2Tbl)
	{
		pImage->pL2TblAlloc->cRefs++;
		return pImage->pL2TblAlloc;
	}

	PQCOWL2CACHEENTRY pL2Entry;
	RTListForEach(&pImage->ListSearch, pL2Entry, QCOWL2CACHEENTRY, NodeSearch)
	{
		if (pL2Entry->offL2Tbl == offL2Tbl)
			break;
	}

	if (!RTListNodeIsDummy(&pImage->ListSearch, pL2Entry, QCOWL2CACHEENTRY, NodeSearch))
	{
		/* Update LRU list. */
		RTListNodeRemove(&pL2Entry->NodeLru);
		RTListPrepend(&pImage->ListLru, &pL2Entry->NodeLru);
		pL2Entry->cRefs++;
		return pL2Entry;
	}

	return NULL;
}

/**
 * Releases a L2 table cache entry.
 *
 * @param   pL2Entry    The L2 cache entry.
 */
static void qcowL2TblCacheEntryRelease(PQCOWL2CACHEENTRY pL2Entry)
{
	pL2Entry->cRefs--;
}

/**
 * Allocates a new L2 table from the cache evicting old entries if required.
 *
 * @returns Pointer to the L2 cache entry or NULL.
 * @param   pImage    The image instance data.
 */
static PQCOWL2CACHEENTRY qcowL2TblCacheEntryAlloc(PQCOWIMAGE pImage)
{
	PQCOWL2CACHEENTRY pL2Entry = NULL;

	if (pImage->cbL2Cache + pImage->cbL2Table <= QCOW_L2_CACHE_MEMORY_MAX)
	{
		/* Add a new entry. */
		pL2Entry = (PQCOWL2CACHEENTRY)grub_zalloc(sizeof(QCOWL2CACHEENTRY));
		if (pL2Entry)
		{
			pL2Entry->paL2Tbl = (grub_uint64_t*)grub_zalloc(pImage->cbL2Table);
			if (!pL2Entry->paL2Tbl)
			{
				grub_free(pL2Entry);
				pL2Entry = NULL;
			}
			else
			{
				pL2Entry->cRefs = 1;
				pImage->cbL2Cache += pImage->cbL2Table;
			}
		}
	}
	else
	{
		/* Evict the last not in use entry and use it */
		RTListForEachReverse(&pImage->ListLru, pL2Entry, QCOWL2CACHEENTRY, NodeLru)
		{
			if (!pL2Entry->cRefs)
				break;
		}

		if (!RTListNodeIsDummy(&pImage->ListSearch, pL2Entry, QCOWL2CACHEENTRY, NodeSearch))
		{
			RTListNodeRemove(&pL2Entry->NodeSearch);
			RTListNodeRemove(&pL2Entry->NodeLru);
			pL2Entry->offL2Tbl = 0;
			pL2Entry->cRefs = 1;
		}
		else
			pL2Entry = NULL;
	}

	return pL2Entry;
}

/**
 * Frees a L2 table cache entry.
 *
 * @param   pImage    The image instance data.
 * @param   pL2Entry  The L2 cache entry to free.
 */
static void qcowL2TblCacheEntryFree(PQCOWIMAGE pImage, PQCOWL2CACHEENTRY pL2Entry)
{
	grub_free(pL2Entry->paL2Tbl);
	grub_free(pL2Entry);

	pImage->cbL2Cache -= pImage->cbL2Table;
}

/**
 * Inserts an entry in the L2 table cache.
 *
 * @param   pImage    The image instance data.
 * @param   pL2Entry  The L2 cache entry to insert.
 */
static void qcowL2TblCacheEntryInsert(PQCOWIMAGE pImage, PQCOWL2CACHEENTRY pL2Entry)
{
	/* Insert at the top of the LRU list. */
	RTListPrepend(&pImage->ListLru, &pL2Entry->NodeLru);

	if (RTListIsEmpty(&pImage->ListSearch))
	{
		RTListAppend(&pImage->ListSearch, &pL2Entry->NodeSearch);
	}
	else
	{
		/* Insert into search list. */
		PQCOWL2CACHEENTRY pIt;
		pIt = RTListGetFirst(&pImage->ListSearch, QCOWL2CACHEENTRY, NodeSearch);
		if (pIt->offL2Tbl > pL2Entry->offL2Tbl)
			RTListPrepend(&pImage->ListSearch, &pL2Entry->NodeSearch);
		else
		{
			int fInserted = false;

			RTListForEach(&pImage->ListSearch, pIt, QCOWL2CACHEENTRY, NodeSearch)
			{
				if (pIt->offL2Tbl < pL2Entry->offL2Tbl)
				{
					RTListNodeInsertAfter(&pIt->NodeSearch, &pL2Entry->NodeSearch);
					fInserted = true;
					break;
				}
			}
		}
	}
}

/**
 * Fetches the L2 from the given offset trying the LRU cache first and
 * reading it from the image after a cache miss.
 *
 * @returns VBox status code.
 * @param   pImage    Image instance data.
 * @param   pIoCtx    The I/O context.
 * @param   offL2Tbl  The offset of the L2 table in the image.
 * @param   ppL2Entry Where to store the L2 table on success.
 */
static int qcowL2TblCacheFetch(PQCOWIMAGE pImage, grub_uint64_t offL2Tbl,
	PQCOWL2CACHEENTRY* ppL2Entry)
{
	int rc = GRUB_ERR_NONE;

	/* Try to fetch the L2 table from the cache first. */
	PQCOWL2CACHEENTRY pL2Entry = qcowL2TblCacheRetain(pImage, offL2Tbl);
	if (!pL2Entry)
	{
		pL2Entry = qcowL2TblCacheEntryAlloc(pImage);

		if (pL2Entry)
		{
			/* Read from the image. */
			pL2Entry->offL2Tbl = offL2Tbl;
			rc = qcowFileReadSync(pImage,
				offL2Tbl, pL2Entry->paL2Tbl,
				pImage->cbL2Table, NULL);
			if (RT_SUCCESS(rc))
			{
#if defined(RT_LITTLE_ENDIAN)
				qcowTableConvertToHostEndianess(pL2Entry->paL2Tbl, pImage->cL2TableEntries);
#endif
				qcowL2TblCacheEntryInsert(pImage, pL2Entry);
			}
			else
			{
				qcowL2TblCacheEntryRelease(pL2Entry);
				qcowL2TblCacheEntryFree(pImage, pL2Entry);
			}
		}
		else
			rc = GRUB_ERR_OUT_OF_MEMORY;
	}

	if (RT_SUCCESS(rc))
		*ppL2Entry = pL2Entry;

	return rc;
}

/**
 * Sets the L1, L2 and offset bitmasks and L1 and L2 bit shift members.
 *
 * @param   pImage    The image instance data.
 */
static void qcowTableMasksInit(PQCOWIMAGE pImage)
{
	grub_uint32_t cClusterBits, cL2TableBits;

	cClusterBits = qcowGetPowerOfTwo(pImage->cbCluster);
	cL2TableBits = qcowGetPowerOfTwo(pImage->cL2TableEntries);

	pImage->fOffsetMask = ((grub_uint64_t)pImage->cbCluster - 1);
	pImage->fL2Mask = ((grub_uint64_t)pImage->cL2TableEntries - 1) << cClusterBits;
	pImage->cL2Shift = cClusterBits;
	pImage->cL1Shift = cClusterBits + cL2TableBits;
}

/**
 * Converts a given logical offset into the
 *
 * @param   pImage         The image instance data.
 * @param   off            The logical offset to convert.
 * @param   pidxL1         Where to store the index in the L1 table on success.
 * @param   pidxL2         Where to store the index in the L2 table on success.
 * @param   poffCluster    Where to store the offset in the cluster on success.
 */
static void qcowConvertLogicalOffset(PQCOWIMAGE pImage, grub_uint64_t off, grub_uint32_t* pidxL1,
	grub_uint32_t* pidxL2, grub_uint32_t* poffCluster)
{
	*poffCluster = off & pImage->fOffsetMask;
	*pidxL1 = off >> pImage->cL1Shift;
	*pidxL2 = (off & pImage->fL2Mask) >> pImage->cL2Shift;
}

/**
 * Converts Cluster size to a byte size.
 *
 * @returns Number of bytes derived from the given number of clusters.
 * @param   pImage    The image instance data.
 * @param   cClusters The clusters to convert.
 */
static grub_uint64_t qcowCluster2Byte(PQCOWIMAGE pImage, grub_uint64_t cClusters)
{
	return cClusters * pImage->cbCluster;
}

/**
 * Returns the real image offset for a given cluster or an error if the cluster is not
 * yet allocated.
 *
 * @returns VBox status code.
 *          VERR_VD_BLOCK_FREE if the cluster is not yet allocated.
 * @param   pImage        The image instance data.
 * @param   pIoCtx        The I/O context.
 * @param   idxL1         The L1 index.
 * @param   idxL2         The L2 index.
 * @param   offCluster    Offset inside the cluster.
 * @param   poffImage     Where to store the image offset on success.
 * @param   pfCompressed  Where to store the flag whether the cluster is compressed on success.
 * @param   pcbCompressed Where to store the size of the compressed cluster in bytes on success.
 *                        Only valid when the cluster comrpessed flag is true.
 */
static int qcowConvertToImageOffset(PQCOWIMAGE pImage,
	grub_uint32_t idxL1, grub_uint32_t idxL2,
	grub_uint32_t offCluster, grub_uint64_t* poffImage,
	int* penmState, int* pfCompressed, grub_size_t* pcbCompressed)
{
	int rc = GRUB_ERR_NONE;

	*penmState = QCOW_CLUSTER_FREE;
	*pfCompressed = false;
	*pcbCompressed = 0;
	if (pImage->paL1Table[idxL1])
	{
		PQCOWL2CACHEENTRY pL2Entry;

		grub_uint64_t offL2Tbl = pImage->paL1Table[idxL1];
		if (pImage->uVersion == 2)
		{
			if (offL2Tbl & ~(QCOW_V2_COPIED_FLAG | QCOW_V2_TBL_OFFSET_MASK))
				return GRUB_ERR_BAD_DEVICE;
			offL2Tbl &= QCOW_V2_TBL_OFFSET_MASK;
		}
		if (!offL2Tbl)
			return GRUB_ERR_NONE;
		if ((offL2Tbl & (pImage->cbCluster - 1))
			|| !qcowRangeValid(offL2Tbl, pImage->cbL2Table, pImage->FileSize))
			return GRUB_ERR_OUT_OF_RANGE;
		rc = qcowL2TblCacheFetch(pImage, offL2Tbl, &pL2Entry);
		if (RT_SUCCESS(rc))
		{
			/* Get real file offset. */
			if (pL2Entry->paL2Tbl[idxL2])
			{
				grub_uint64_t off = pL2Entry->paL2Tbl[idxL2];

				/* Strip flags */
				if (pImage->uVersion == 2)
				{
					if (off & QCOW_V2_COMPRESSED_FLAG)
					{
						grub_size_t cCompressedClusterSectors = (grub_size_t)((off & pImage->fMaskCompressedClusterSectors) >> pImage->cBitsShiftRCompressedClusterSectors);
						grub_uint64_t offImage = off & pImage->fMaskCompressedClusterOffset;
						grub_size_t cbCompressed = (cCompressedClusterSectors + 1) * 512
							- (grub_size_t)(offImage & 511ULL);

						if ((off & QCOW_V2_COPIED_FLAG) || !cbCompressed
							|| cbCompressed > pImage->cbCluster
							|| !qcowRangeValid(offImage, cbCompressed, pImage->FileSize))
							rc = GRUB_ERR_BAD_DEVICE;
						else
						{
							*penmState = QCOW_CLUSTER_ALLOCATED;
							*pfCompressed = true;
							*poffImage = offImage;
							*pcbCompressed = cbCompressed;
						}
					}
					else
					{
						if (off & ~(QCOW_V2_COPIED_FLAG | QCOW_V2_TBL_OFFSET_MASK | 1ULL))
							rc = GRUB_ERR_BAD_DEVICE;
						/* The zero flag (bit 0, v3) means the cluster
						 * reads as zeros regardless of the offset. */
						else if (off & 1)
							*penmState = QCOW_CLUSTER_ZERO;
						else if (!(off & QCOW_V2_TBL_OFFSET_MASK))
							*penmState = QCOW_CLUSTER_FREE;
						else
						{
							off &= QCOW_V2_TBL_OFFSET_MASK;
							if ((off & (pImage->cbCluster - 1))
								|| !qcowRangeValid(off, pImage->cbCluster, pImage->FileSize))
								rc = GRUB_ERR_OUT_OF_RANGE;
							else
							{
								*penmState = QCOW_CLUSTER_ALLOCATED;
								*poffImage = off + offCluster;
							}
						}
					}
				}
				else
				{
					if (off & QCOW_V1_COMPRESSED_FLAG)
					{
						grub_uint64_t offImage = off & pImage->fMaskCompressedClusterOffset;
						grub_size_t cbCompressed = (grub_size_t)((off
							& pImage->fMaskCompressedClusterSectors)
							>> pImage->cBitsShiftRCompressedClusterSectors);

						/* v1 stores the compressed size in bytes, not in
						 * sectors (see qemu block/qcow.c). */
						if (!cbCompressed || cbCompressed > pImage->cbCluster
							|| !qcowRangeValid(offImage, cbCompressed, pImage->FileSize))
							rc = GRUB_ERR_BAD_DEVICE;
						else
						{
							*penmState = QCOW_CLUSTER_ALLOCATED;
							*pfCompressed = true;
							*poffImage = offImage;
							*pcbCompressed = cbCompressed;
						}
					}
					else
					{
						if ((off & (pImage->cbCluster - 1))
							|| !qcowRangeValid(off, pImage->cbCluster, pImage->FileSize))
							rc = GRUB_ERR_OUT_OF_RANGE;
						else
						{
							*penmState = QCOW_CLUSTER_ALLOCATED;
							*poffImage = off + offCluster;
						}
					}
				}
			}
			else
				rc = GRUB_ERR_NONE;

			qcowL2TblCacheEntryRelease(pL2Entry);
		}
	}

	return rc;
}

/**
 * Internal. Free all allocated space for representing an image except pImage,
 * and optionally delete the image from disk.
 */
static int qcowFreeImage(PQCOWIMAGE pImage)
{
	int rc = GRUB_ERR_NONE;

	/* Freeing a never allocated image (e.g. because the open failed) is
	 * not signalled as an error. After all nothing bad happens. */
	if (pImage)
	{
		if (pImage->Backing)
		{
			grub_file_close(pImage->Backing);
			pImage->Backing = NULL;
		}

		if (pImage->paL1Table)
			grub_free(pImage->paL1Table);

		if (pImage->pvCompCluster)
		{
			grub_free(pImage->pvCompCluster);
			pImage->pvCompCluster = NULL;
			pImage->cbCompCluster = 0;
		}

		if (pImage->pvCluster)
		{
			grub_free(pImage->pvCluster);
			pImage->pvCluster = NULL;
		}

		qcowL2TblCacheDestroy(pImage);
	}

	return rc;
}

/**
 * Validates the header.
 *
 * @returns VBox status code.
 * @param   pImage    Image backend instance data.
 * @param   pHdr      The header to validate.
 * @param   cbFile    The image file size in bytes.
 */
static int qcowHdrValidate(PQCowHeader pHdr, grub_uint64_t cbFile)
{
	if (pHdr->u32Version == 1)
	{
		grub_uint32_t cClusterBits = pHdr->Version.v1.u8ClusterBits;
		grub_uint32_t cL2Bits = pHdr->Version.v1.u8L2Bits;
		grub_uint64_t cbCoverage;
		grub_uint64_t cL1Entries;

		if (cbFile < QCOW_V1_HDR_SIZE || !pHdr->Version.v1.u64Size)
			return GRUB_ERR_BAD_DEVICE;
		if (cClusterBits < QCOW_V1_CLUSTER_BITS_MIN
			|| cClusterBits > QCOW_V1_CLUSTER_BITS_MAX
			|| cL2Bits < QCOW_V1_L2_BITS_MIN
			|| cL2Bits > QCOW_V1_L2_BITS_MAX)
			return GRUB_ERR_BAD_DEVICE;
		if (!!pHdr->Version.v1.u64BackingFileOffset
			!= !!pHdr->Version.v1.u32BackingFileSize
			|| !qcowRangeValid(pHdr->Version.v1.u64BackingFileOffset,
				pHdr->Version.v1.u32BackingFileSize, cbFile))
			return GRUB_ERR_OUT_OF_RANGE;

		cbCoverage = RT_BIT_64(cClusterBits + cL2Bits);
		cL1Entries = pHdr->Version.v1.u64Size / cbCoverage;
		if (pHdr->Version.v1.u64Size % cbCoverage)
			cL1Entries++;
		if (!cL1Entries
			|| cL1Entries > QCOW_L1_TABLE_SIZE_MAX / sizeof(grub_uint64_t)
			|| !qcowRangeValid(pHdr->Version.v1.u64L1TableOffset,
				cL1Entries * sizeof(grub_uint64_t), cbFile))
			return GRUB_ERR_OUT_OF_RANGE;
	}
	else if (pHdr->u32Version == 2 || pHdr->u32Version == 3)
	{
		grub_uint32_t cClusterBits = pHdr->Version.v2.u32ClusterBits;
		grub_uint64_t cbCluster;
		grub_uint64_t cbCoverage;
		grub_uint64_t cL1Required;
		grub_uint32_t cbHeader = QCOW_V2_HDR_SIZE;

		if (cbFile < QCOW_V2_HDR_SIZE || !pHdr->Version.v2.u64Size
			|| cClusterBits < QCOW_V2_CLUSTER_BITS_MIN
			|| cClusterBits > QCOW_V2_CLUSTER_BITS_MAX)
			return GRUB_ERR_BAD_DEVICE;
		cbCluster = RT_BIT_64(cClusterBits);

		/* Some additional checks for v3 images. */
		if (pHdr->u32Version == 3)
		{
			cbHeader = pHdr->Version.v2.v3.u32HdrLenBytes;
			if (pHdr->Version.v2.v3.u32RefCntWidth > 6
				|| cbHeader < 104 || (cbHeader & 7)
				|| cbHeader > cbCluster || cbHeader > cbFile)
				return GRUB_ERR_BAD_DEVICE;
		}

		if (!!pHdr->Version.v2.u64BackingFileOffset
			!= !!pHdr->Version.v2.u32BackingFileSize
			|| !qcowRangeValid(pHdr->Version.v2.u64BackingFileOffset,
				pHdr->Version.v2.u32BackingFileSize, cbFile))
			return GRUB_ERR_OUT_OF_RANGE;
		if (pHdr->Version.v2.u64BackingFileOffset
			&& (pHdr->Version.v2.u64BackingFileOffset < cbHeader
				|| pHdr->Version.v2.u64BackingFileOffset > cbCluster
				|| pHdr->Version.v2.u32BackingFileSize
					> cbCluster - pHdr->Version.v2.u64BackingFileOffset))
			return GRUB_ERR_BAD_DEVICE;

		if (!pHdr->Version.v2.u32L1Size
			|| pHdr->Version.v2.u32L1Size
				> QCOW_L1_TABLE_SIZE_MAX / sizeof(grub_uint64_t)
			|| (pHdr->Version.v2.u64L1TableOffset & (cbCluster - 1))
			|| !qcowRangeValid(pHdr->Version.v2.u64L1TableOffset,
				(grub_uint64_t)pHdr->Version.v2.u32L1Size
					* sizeof(grub_uint64_t), cbFile))
			return GRUB_ERR_OUT_OF_RANGE;

		cbCoverage = RT_BIT_64(2 * cClusterBits - 3);
		cL1Required = pHdr->Version.v2.u64Size / cbCoverage;
		if (pHdr->Version.v2.u64Size % cbCoverage)
			cL1Required++;
		if (pHdr->Version.v2.u32L1Size < cL1Required)
			return GRUB_ERR_BAD_DEVICE;
	}
	else
		return GRUB_ERR_NOT_IMPLEMENTED_YET;

	return GRUB_ERR_NONE;
}

/**
 * Internal: Open an image, constructing all necessary data structures.
 */
static int qcowOpenImage(PQCOWIMAGE pImage)
{
	grub_uint64_t cbFile = grub_file_size(pImage->File);

	int rc = qcowL2TblCacheCreate(pImage);
	if (RT_SUCCESS(rc))
	{
		QCowHeader Header;

		pImage->FileSize = cbFile;
		rc = qcowFileReadSync(pImage, 0, &Header, sizeof(Header), NULL);
		if (RT_SUCCESS(rc)
			&& qcowHdrConvertToHostEndianess(&Header))
		{
			pImage->offNextCluster = RT_ALIGN_64(cbFile, 512); /* Align image to sector boundary. */

			rc = qcowHdrValidate(&Header, cbFile);
			if (RT_SUCCESS(rc))
			{
				if (Header.u32Version == 1)
				{
					if (!Header.Version.v1.u32CryptMethod)
					{
						pImage->uVersion = 1;
						pImage->offBackingFilename = Header.Version.v1.u64BackingFileOffset;
						pImage->cbBackingFilename = Header.Version.v1.u32BackingFileSize;
						pImage->MTime = Header.Version.v1.u32MTime;
						pImage->cbSize = Header.Version.v1.u64Size;
						pImage->cClusterBits = Header.Version.v1.u8ClusterBits;
						pImage->cbCluster = RT_BIT_32(Header.Version.v1.u8ClusterBits);
						pImage->cL2TableEntries = RT_BIT_32(Header.Version.v1.u8L2Bits);
						pImage->cbL2Table = pImage->cL2TableEntries * sizeof(grub_uint64_t);
						pImage->offL1Table = Header.Version.v1.u64L1TableOffset;
						pImage->cL1TableEntries = (grub_uint32_t)(pImage->cbSize
							/ RT_BIT_64(pImage->cClusterBits + Header.Version.v1.u8L2Bits));
						if (pImage->cbSize
							% RT_BIT_64(pImage->cClusterBits + Header.Version.v1.u8L2Bits))
							pImage->cL1TableEntries++;

						/* Init the masks for a v1 compressed cluster descriptor:
						 * bit 63 is the compressed flag, the following
						 * cClusterBits bits hold the compressed size in bytes,
						 * the rest is the file offset (see qemu block/qcow.c). */
						pImage->cBitsShiftRCompressedClusterSectors = 63 - pImage->cClusterBits;
						pImage->fMaskCompressedClusterOffset = RT_BIT_64(63 - pImage->cClusterBits) - 1;
						pImage->fMaskCompressedClusterSectors = ((grub_uint64_t)pImage->cbCluster - 1) << pImage->cBitsShiftRCompressedClusterSectors;
					}
					else
						rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
				}
				else if (Header.u32Version == 2 || Header.u32Version == 3)
				{
					if (Header.Version.v2.u32CryptMethod)
						rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
					else if (Header.Version.v2.u32NbSnapshots)
						rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
					else
					{
						pImage->uVersion = 2;
						pImage->offBackingFilename = Header.Version.v2.u64BackingFileOffset;
						pImage->cbBackingFilename = Header.Version.v2.u32BackingFileSize;
						pImage->cbSize = Header.Version.v2.u64Size;
						pImage->cClusterBits = Header.Version.v2.u32ClusterBits;
						pImage->cbCluster = RT_BIT_32(Header.Version.v2.u32ClusterBits);
						pImage->cL2TableEntries = pImage->cbCluster / sizeof(grub_uint64_t);
						pImage->cbL2Table = pImage->cbCluster;
						pImage->offL1Table = Header.Version.v2.u64L1TableOffset;
						pImage->cL1TableEntries = Header.Version.v2.u32L1Size;
						pImage->offRefcountTable = Header.Version.v2.u64RefcountTableOffset;
						if (Header.Version.v2.u32RefcountTableClusters
							> 0xffffffffU / pImage->cbCluster)
							rc = GRUB_ERR_OUT_OF_RANGE;
						else
						{
							pImage->cbRefcountTable = (grub_uint32_t)qcowCluster2Byte(pImage,
								Header.Version.v2.u32RefcountTableClusters);
							pImage->cRefcountTableEntries = pImage->cbRefcountTable / sizeof(grub_uint64_t);
						}

						/* Init the masks to extract offset and sector count from a compressed cluster descriptor. */
						grub_uint32_t cBitsCompressedClusterOffset = 62 - (pImage->cClusterBits - 8);
						pImage->fMaskCompressedClusterOffset = RT_BIT_64(cBitsCompressedClusterOffset) - 1;
						pImage->fMaskCompressedClusterSectors = (RT_BIT_64(62) - 1) & ~pImage->fMaskCompressedClusterOffset;
						pImage->cBitsShiftRCompressedClusterSectors = cBitsCompressedClusterOffset;

						if (RT_SUCCESS(rc) && Header.u32Version == 3)
						{
							if (Header.Version.v2.v3.u64IncompatFeat & ~QCOW_V3_INCOMPAT_FEAT_SUPPORTED_MASK)
								rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
							else if (Header.Version.v2.v3.u64IncompatFeat & QCOW_V3_INCOMPAT_FEAT_F_COMPRESSION)
							{
								if (Header.Version.v2.v3.u32HdrLenBytes <= 104
									|| Header.Version.v2.v3.u8CompressionType
										!= QCOW_COMPRESSION_TYPE_ZSTD)
									rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
								else
									pImage->u8CompressionType = Header.Version.v2.v3.u8CompressionType;
							}

							/** @todo Auto clear features need to be reset as soon as write support is added. */
						}
					}
				}
				else
					rc = GRUB_ERR_NOT_IMPLEMENTED_YET;

				if (RT_SUCCESS(rc))
				{
					pImage->cbL1Table = pImage->cL1TableEntries * sizeof(grub_uint64_t);
				}
			}

			/** @todo Check that there are no compressed clusters in the image
			 *  (by traversing the L2 tables and checking each offset).
			 *  Refuse to open such images.
			 */

			if (RT_SUCCESS(rc))
			{
				qcowTableMasksInit(pImage);

				/* Allocate L1 table. */
				pImage->paL1Table = (grub_uint64_t*)grub_zalloc(pImage->cbL1Table);
				if (pImage->paL1Table)
				{
					/* Read from the image. */
					rc = qcowFileReadSync(pImage,
						pImage->offL1Table, pImage->paL1Table,
						pImage->cbL1Table, NULL);
					if (RT_SUCCESS(rc))
						qcowTableConvertToHostEndianess(pImage->paL1Table, pImage->cL1TableEntries);
					else
						rc = GRUB_ERR_BAD_DEVICE;
				}
				else
					rc = GRUB_ERR_OUT_OF_MEMORY;
			}

			/* Open the backing file, if any. */
			if (RT_SUCCESS(rc) && pImage->cbBackingFilename)
			{
				if (pImage->cbBackingFilename >= 1024
					|| !qcowRangeValid(pImage->offBackingFilename,
						pImage->cbBackingFilename, cbFile))
					rc = GRUB_ERR_BAD_DEVICE;
				else
				{
					char* pszBacking = (char*)grub_zalloc(pImage->cbBackingFilename + 1);
					if (!pszBacking)
						rc = GRUB_ERR_OUT_OF_MEMORY;
					else
					{
						rc = qcowFileReadSync(pImage, pImage->offBackingFilename,
							pszBacking, pImage->cbBackingFilename, NULL);
						if (RT_SUCCESS(rc))
						{
							pImage->Backing = grub_vdisk_open_parent(pImage->File->name,
								pszBacking);
							if (!pImage->Backing)
								rc = grub_errno;
						}
						grub_free(pszBacking);
					}
				}
			}
		}
		else if (RT_SUCCESS(rc))
			rc = GRUB_ERR_BAD_DEVICE;
	}
	else
		rc = GRUB_ERR_OUT_OF_MEMORY;

	if (RT_FAILURE(rc))
		qcowFreeImage(pImage);
	return rc;
}

/**
 * Reads a compressed cluster, inflates it and copies the amount of data requested
 * into the given I/O context.
 *
 * @returns VBox status code.
 * @param   pImage              The image instance data.
 * @param   pvBuf               The output data.
 * @param   offCluster          Where to start reading in the uncompressed cluster.
 * @param   cbToRead            How much to read in the uncomrpessed cluster.
 * @param   offFile             Offset where the compressed cluster is stored in the image.
 * @param   cbCompressedCluster Size of the comrpessed cluster in bytes.
 */
static int qcowReadCompressedCluster(PQCOWIMAGE pImage, void* pvBuf,
	grub_uint32_t offCluster, grub_size_t cbToRead,
	grub_uint64_t offFile, grub_size_t cbCompressedCluster)
{
	int rc = GRUB_ERR_NONE;

	if (cbCompressedCluster > pImage->cbCompCluster)
	{
		void* pvCompClusterNew = grub_realloc(pImage->pvCompCluster, cbCompressedCluster);
		if (pvCompClusterNew)
		{
			pImage->pvCompCluster = pvCompClusterNew;
			pImage->cbCompCluster = cbCompressedCluster;
		}
		else
			rc = GRUB_ERR_OUT_OF_MEMORY;
	}

	if (RT_SUCCESS(rc))
	{
		rc = qcowFileReadSync(pImage,
			offFile, pImage->pvCompCluster,
			cbCompressedCluster, NULL);
		if (RT_SUCCESS(rc))
		{
			if (!pImage->pvCluster)
			{
				pImage->pvCluster = grub_zalloc(pImage->cbCluster);
				if (!pImage->pvCluster)
					rc = GRUB_ERR_OUT_OF_MEMORY;
			}

			if (RT_SUCCESS(rc))
			{
				grub_size_t cbDecomp = 0;

				if (pImage->u8CompressionType == QCOW_COMPRESSION_TYPE_ZSTD)
				{
					/* The stored size is rounded up to whole sectors;
					 * locate the real frame end first, trailing garbage
					 * makes ZSTD_decompress() fail. */
					grub_size_t cbFrame = ZSTD_findFrameCompressedSize(pImage->pvCompCluster,
						cbCompressedCluster);
					if (ZSTD_isError(cbFrame))
						rc = GRUB_ERR_BAD_COMPRESSED_DATA;
					else
					{
						cbDecomp = ZSTD_decompress(pImage->pvCluster, pImage->cbCluster,
							pImage->pvCompCluster, cbFrame);
						if (ZSTD_isError(cbDecomp))
							rc = GRUB_ERR_BAD_COMPRESSED_DATA;
					}
				}
				else
					rc = RTZipBlockDecompress(RTZIPTYPE_ZLIB_NO_HEADER, 0 /*fFlags*/,
						pImage->pvCompCluster, cbCompressedCluster, NULL,
						pImage->pvCluster, pImage->cbCluster, &cbDecomp);
				if (RT_SUCCESS(rc) && cbDecomp != pImage->cbCluster)
					rc = GRUB_ERR_BAD_COMPRESSED_DATA;
				if (RT_SUCCESS(rc))
				{
					grub_memcpy(pvBuf,
						(grub_uint8_t*)pImage->pvCluster + offCluster,
						cbToRead);
				}
			}
		}
	}

	return rc;
}

static int
qcowOpen(grub_file_t File, void** ppBackendData)
{
	int rc;

	PQCOWIMAGE pImage = (PQCOWIMAGE)grub_zalloc(sizeof(QCOWIMAGE));
	if (!pImage)
	{
		rc = GRUB_ERR_OUT_OF_MEMORY;
		return rc;
	}

	pImage->File = File;
	rc = qcowOpenImage(pImage);
	if (RT_SUCCESS(rc))
		*ppBackendData = pImage;
	else
		grub_free(pImage);

	return rc;
}

static int
qcowClose(void* pBackendData)
{
	
	PQCOWIMAGE pImage = (PQCOWIMAGE)pBackendData;

	int rc = qcowFreeImage(pImage);
	grub_free(pImage);

	return rc;
}

static int
qcowRead(void* pBackendData, grub_uint64_t uOffset, void* pvBuf, grub_size_t cbToRead,
	grub_size_t* pcbActuallyRead)
{
	PQCOWIMAGE pImage = (PQCOWIMAGE)pBackendData;
	grub_uint32_t offCluster = 0;
	grub_uint32_t idxL1 = 0;
	grub_uint32_t idxL2 = 0;
	grub_uint64_t offFile = 0;
	int rc;

	if (uOffset > pImage->cbSize || cbToRead > pImage->cbSize - uOffset)
		return GRUB_ERR_BAD_ARGUMENT;

	qcowConvertLogicalOffset(pImage, uOffset, &idxL1, &idxL2, &offCluster);
	if (idxL1 >= pImage->cL1TableEntries || idxL2 >= pImage->cL2TableEntries)
		return GRUB_ERR_OUT_OF_RANGE;

	/* Clip read size to remain in the cluster. */
	cbToRead = RT_MIN(cbToRead, pImage->cbCluster - offCluster);

	/* Get offset in image. */
	int enmState = QCOW_CLUSTER_FREE;
	int fCompressedCluster = false;
	grub_size_t cbCompressedCluster = 0;
	rc = qcowConvertToImageOffset(pImage, idxL1, idxL2, offCluster,
		&offFile, &enmState, &fCompressedCluster, &cbCompressedCluster);
	if (RT_SUCCESS(rc))
	{
		if (enmState == QCOW_CLUSTER_ZERO)
			grub_memset(pvBuf, 0, cbToRead);
		else if (enmState == QCOW_CLUSTER_FREE)
		{
			/* Unallocated clusters come from the backing file if
			 * there is one and read as zeros otherwise. */
			if (pImage->Backing)
				rc = grub_vdisk_read_parent(pImage->Backing, uOffset, pvBuf, cbToRead);
			else
				grub_memset(pvBuf, 0, cbToRead);
		}
		else if (!fCompressedCluster)
			rc = qcowFileReadSync(pImage, offFile,
				pvBuf, cbToRead, NULL);
		else
			rc = qcowReadCompressedCluster(pImage, pvBuf, offCluster, cbToRead, offFile, cbCompressedCluster);
	}

	if (RT_SUCCESS(rc) && pcbActuallyRead)
		*pcbActuallyRead = cbToRead;

	return rc;
}

static grub_uint64_t
qcowGetSize(void* pBackendData)
{
	PQCOWIMAGE pImage = (PQCOWIMAGE)pBackendData;

	if (pImage)
		return pImage->cbSize;
	return 0;
}


struct grub_qcow
{
	grub_file_t file;
	void* qcow;
};
typedef struct grub_qcow* grub_qcow_t;

static struct grub_fs grub_qcow_fs;

static grub_err_t
grub_qcow_close(grub_file_t file)
{
	grub_qcow_t qcowio = file->data;

	qcowClose(qcowio->qcow);
	grub_file_close(qcowio->file);
	grub_free(qcowio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_qcow_open(grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_qcow_t qcowio;
	void* qcow = NULL;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < QCOW_V1_HDR_SIZE || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	if (qcowOpen(io, &qcow) != GRUB_ERR_NONE)
	{
		grub_file_seek(io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t)grub_zalloc(sizeof(*file));
	if (!file)
	{
		qcowClose(qcow);
		return 0;
	}

	qcowio = grub_zalloc(sizeof(*qcowio));
	if (!qcowio)
	{
		qcowClose(qcow);
		grub_free(file);
		return 0;
	}
	qcowio->file = io;
	qcowio->qcow = qcow;

	file->device = io->device;
	file->data = qcowio;
	file->fs = &grub_qcow_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = qcowGetSize(qcow);

	return file;
}

static grub_ssize_t
grub_qcow_read(grub_file_t file, char* buf, grub_size_t len)
{
	int rc = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_size_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_qcow_t qcowio = file->data;

	while (len > 0 && rc == GRUB_ERR_NONE)
	{
		real_size = 0;
		rc = qcowRead(qcowio->qcow, read_offset, buf, len, &real_size);
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
		grub_error((grub_err_t)rc, "QCOW image read failed");
		return -1;
	}
	return (grub_ssize_t)size;
}

static struct grub_fs grub_qcow_fs =
{
	.name = "qcow",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_qcow_read,
	.fs_close = grub_qcow_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT(qcow)
{
	grub_file_filter_register(GRUB_FILE_FILTER_QCOW, grub_qcow_open);
}

GRUB_MOD_FINI(qcow)
{
	grub_file_filter_unregister(GRUB_FILE_FILTER_QCOW);
}
