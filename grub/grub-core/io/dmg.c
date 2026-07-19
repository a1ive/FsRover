/* $Id: DMG.cpp $ */
/** @file
 * VBoxDMG - Interpreter for Apple Disk Images (DMG).
 */

 /*
  * Copyright (C) 2010-2023 Oracle and/or its affiliates.
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
#include <grub/deflate.h>
#include <grub/dl.h>

#include <bzlib.h>
#include <lzfse.h>

#include <vbox.h>

GRUB_MOD_LICENSE("GPLv3+");

/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/

/** Sector size, multiply with all sector counts to get number of bytes. */
#define DMG_SECTOR_SIZE 512

/** Convert block number/size to byte offset/size. */
#define DMG_BLOCK2BYTE(u)          ((grub_uint64_t)(u) << 9)

/** Convert byte offset/size to block number/size. */
#define DMG_BYTE2BLOCK(u)          ((u) >> 9)

/** Maximum compressed or decompressed size of a non-zero extent. */
#define DMG_EXTENT_SIZE_MAX        (64U * 1024U * 1024U)

/** Maximum sectors in a non-zero extent. */
#define DMG_EXTENT_SECTORS_MAX     (DMG_EXTENT_SIZE_MAX / DMG_SECTOR_SIZE)

/**
 * UDIF checksum structure.
 */
typedef struct DMGUDIFCKSUM
{
	grub_uint32_t        u32Kind;                    /**< The kind of checksum.  */
	grub_uint32_t        cBits;                      /**< The size of the checksum. */
	union
	{
		grub_uint8_t     au8[128];                   /**< 8-bit view. */
		grub_uint32_t    au32[32];                   /**< 32-bit view. */
	}                    uSum;                       /**< The checksum. */
} DMGUDIFCKSUM;

typedef DMGUDIFCKSUM* PDMGUDIFCKSUM;
typedef const DMGUDIFCKSUM* PCDMGUDIFCKSUM;

/** @name Checksum Kind (DMGUDIFCKSUM::u32Kind)
 * @{ */
 /** No checksum. */
#define DMGUDIFCKSUM_NONE          0U
/** CRC-32. */
#define DMGUDIFCKSUM_CRC32         2U
/** @} */

/**
 * UDIF ID.
 * This is kind of like a UUID only it isn't, but we'll use the UUID
 * representation of it for simplicity.
 */
typedef RTUUID DMGUDIFID;

typedef DMGUDIFID* PDMGUDIFID;
typedef const DMGUDIFID* PCDMGUDIFID;

/**
 * UDIF footer used by Apple Disk Images (DMG).
 *
 * This is a footer placed 512 bytes from the end of the file. Typically a DMG
 * file starts with the data, which is followed by the block table and then ends
 * with this structure.
 *
 * All fields are stored in big endian format.
 */
#pragma pack(1)
typedef struct DMGUDIF
{
	grub_uint32_t            u32Magic;               /**< 0x000 - Magic, 'koly' (DMGUDIF_MAGIC).                       (fUDIFSignature) */
	grub_uint32_t            u32Version;             /**< 0x004 - The UDIF version (DMGUDIF_VER_CURRENT).              (fUDIFVersion) */
	grub_uint32_t            cbFooter;               /**< 0x008 - The size of the this structure (512).                 (fUDIFHeaderSize) */
	grub_uint32_t            fFlags;                 /**< 0x00c - Flags.                                                (fUDIFFlags) */
	grub_uint64_t            offRunData;             /**< 0x010 - Where the running data fork starts (usually 0).       (fUDIFRunningDataForkOffset) */
	grub_uint64_t            offData;                /**< 0x018 - Where the data fork starts (usually 0).               (fUDIFDataForkOffset) */
	grub_uint64_t            cbData;                 /**< 0x020 - Size of the data fork (in bytes).                     (fUDIFDataForkLength) */
	grub_uint64_t            offRsrc;                /**< 0x028 - Where the resource fork starts (usually cbData or 0). (fUDIFRsrcForkOffset) */
	grub_uint64_t            cbRsrc;                 /**< 0x030 - The size of the resource fork.                        (fUDIFRsrcForkLength)*/
	grub_uint32_t            iSegment;               /**< 0x038 - The segment number of this file.                      (fUDIFSegmentNumber) */
	grub_uint32_t            cSegments;              /**< 0x03c - The number of segments.                               (fUDIFSegmentCount) */
	DMGUDIFID                SegmentId;              /**< 0x040 - The segment ID.                                       (fUDIFSegmentID) */
	DMGUDIFCKSUM             DataCkSum;              /**< 0x050 - The data checksum.                                    (fUDIFDataForkChecksum) */
	grub_uint64_t            offXml;                 /**< 0x0d8 - The XML offset (.plist kind of data).                 (fUDIFXMLOffset) */
	grub_uint64_t            cbXml;                  /**< 0x0e0 - The size of the XML.                                  (fUDIFXMLSize) */
	grub_uint8_t             abUnknown[120];         /**< 0x0e8 - Unknown stuff, hdiutil doesn't dump it... */
	DMGUDIFCKSUM             MasterCkSum;            /**< 0x160 - The master checksum.                                  (fUDIFMasterChecksum) */
	grub_uint32_t            u32Type;                /**< 0x1e8 - The image type.                                       (fUDIFImageVariant) */
	grub_uint64_t            cSectors;               /**< 0x1ec - The sector count. Warning! Unaligned!                 (fUDISectorCount) */
	grub_uint32_t            au32Unknown[3];         /**< 0x1f4 - Unknown stuff, hdiutil doesn't dump it... */
} DMGUDIF;
#pragma pack()

typedef DMGUDIF* PDMGUDIF;
typedef const DMGUDIF* PCDMGUDIF;

/** The UDIF magic 'koly' (DMGUDIF::u32Magic). */
#define DMGUDIF_MAGIC              0x6b6f6c79U

/** The current UDIF version (DMGUDIF::u32Version).
 * This is currently the only we recognizes and will create. */
#define DMGUDIF_VER_CURRENT        4

 /** @name UDIF flags (DMGUDIF::fFlags).
  * @{ */
  /** Flatten image whatever that means.
   * (hdiutil -debug calls it kUDIFFlagsFlattened.) */
#define DMGUDIF_FLAGS_FLATTENED    RT_BIT_32(0)
   /** Internet enabled image.
	* (hdiutil -debug calls it kUDIFFlagsInternetEnabled) */
#define DMGUDIF_FLAGS_INET_ENABLED RT_BIT_32(2)
	/** Mask of known bits. */
#define DMGUDIF_FLAGS_KNOWN_MASK   (RT_BIT_32(0) | RT_BIT_32(2))
/** @} */

/** UDIF Image Types (DMGUDIF::u32Type). */
/** Device image type. (kUDIFDeviceImageType) */
#define DMGUDIF_TYPE_DEVICE        1
/** Device image type. (kUDIFPartitionImageType) */
#define DMGUDIF_TYPE_PARTITION     2

/**
 * BLKX data.
 *
 * This contains the start offset and size of raw data stored in the image.
 *
 * All fields are stored in big endian format.
 */
#pragma pack(1)
typedef struct DMGBLKX
{
	grub_uint32_t            u32Magic;               /**< 0x000 - Magic, 'mish' (DMGBLKX_MAGIC). */
	grub_uint32_t            u32Version;             /**< 0x004 - The BLKX version (DMGBLKX_VER_CURRENT). */
	grub_uint64_t            cSectornumberFirst;     /**< 0x008 - The first sector number the block represents in the virtual device. */
	grub_uint64_t            cSectors;               /**< 0x010 - Number of sectors this block represents. */
	grub_uint64_t            offDataStart;           /**< 0x018 - Start offset for raw data. */
	grub_uint32_t            cSectorsDecompress;     /**< 0x020 - Size of the buffer in sectors needed to decompress. */
	grub_uint32_t            u32BlocksDescriptor;    /**< 0x024 - Blocks descriptor. */
	grub_uint8_t             abReserved[24];
	DMGUDIFCKSUM             BlkxCkSum;              /**< 0x03c - Checksum for the BLKX table. */
	grub_uint32_t            cBlocksRunCount;        /**< 0x    - Number of entries in the blkx run table afterwards. */
} DMGBLKX;
#pragma pack()

typedef DMGBLKX* PDMGBLKX;
typedef const DMGBLKX* PCDMGBLKX;

/** The BLKX magic 'mish' (DMGBLKX::u32Magic). */
#define DMGBLKX_MAGIC              0x6d697368U
/** BLKX version (DMGBLKX::u32Version). */
#define DMGBLKX_VERSION            0x00000001U

/** Blocks descriptor type: entire device. */
#define DMGBLKX_DESC_ENTIRE_DEVICE 0xfffffffeU

/**
 * BLKX table descriptor.
 *
 * All fields are stored in big endian format.
 */
#pragma pack(1)
typedef struct DMGBLKXDESC
{
	grub_uint32_t            u32Type;                /**< 0x000 - Type of the descriptor. */
	grub_uint32_t            u32Reserved;            /**< 0x004 - Reserved, but contains +beg or +end in case thisi is a comment descriptor. */
	grub_uint64_t            u64SectorStart;         /**< 0x008 - First sector number in the block this entry describes. */
	grub_uint64_t            u64SectorCount;         /**< 0x010 - Number of sectors this entry describes. */
	grub_uint64_t            offData;                /**< 0x018 - Offset in the image where the data starts. */
	grub_uint64_t            cbData;                 /**< 0x020 - Number of bytes in the image. */
} DMGBLKXDESC;
#pragma pack()

typedef DMGBLKXDESC* PDMGBLKXDESC;
typedef const DMGBLKXDESC* PCDMGBLKXDESC;

/** Raw image data type. */
#define DMGBLKXDESC_TYPE_RAW        1
/** Ignore type. */
#define DMGBLKXDESC_TYPE_IGNORE     2
/** Compressed with adc type. */
#define DMGBLKXDESC_TYPE_ADC        0x80000004U
/** Compressed with zlib type. */
#define DMGBLKXDESC_TYPE_ZLIB       0x80000005U
/** Compressed with bzlib type. */
#define DMGBLKXDESC_TYPE_BZLIB      0x80000006U
/** Compressed with lzfse type. */
#define DMGBLKXDESC_TYPE_LZFSE      0x80000007U
/** Comment type. */
#define DMGBLKXDESC_TYPE_COMMENT    0x7ffffffeU
/** Terminator type. */
#define DMGBLKXDESC_TYPE_TERMINATOR 0xffffffffU

/**
 * UDIF Resource Entry.
 */
typedef struct DMGUDIFRSRCENTRY
{
	/** The ID. */
	grub_int32_t             iId;
	/** Attributes. */
	grub_uint32_t            fAttributes;
	/** The name. */
	char* pszName;
	/** The CoreFoundation name. Can be NULL. */
	char* pszCFName;
	/** The size of the data. */
	grub_size_t              cbData;
	/** The raw data. */
	grub_uint8_t* pbData;
} DMGUDIFRSRCENTRY;
/** Pointer to an UDIF resource entry. */
typedef DMGUDIFRSRCENTRY* PDMGUDIFRSRCENTRY;
/** Pointer to a const UDIF resource entry. */
typedef DMGUDIFRSRCENTRY const* PCDMGUDIFRSRCENTRY;

/**
 * UDIF Resource Array.
 */
typedef struct DMGUDIFRSRCARRAY
{
	/** The array name. */
	char                szName[12];
	/** The number of occupied entries. */
	grub_uint32_t       cEntries;
	/** The array entries.
	 * A lazy bird ASSUME there are no more than 4 entries in any DMG. Increase the
	 * size if DMGs with more are found.
	 * r=aeichner: Saw one with 6 here (image of a whole DVD) */
	DMGUDIFRSRCENTRY    aEntries[10];
} DMGUDIFRSRCARRAY;
/** Pointer to a UDIF resource array. */
typedef DMGUDIFRSRCARRAY* PDMGUDIFRSRCARRAY;
/** Pointer to a const UDIF resource array. */
typedef DMGUDIFRSRCARRAY const* PCDMGUDIFRSRCARRAY;

/**
 * DMG extent types.
 */
typedef enum DMGEXTENTTYPE
{
	/** Null, never used. */
	DMGEXTENTTYPE_NULL = 0,
	/** Raw image data. */
	DMGEXTENTTYPE_RAW,
	/** Zero extent, reads return 0 and writes have no effect. */
	DMGEXTENTTYPE_ZERO,
	/** Compressed extent - compression method ZLIB. */
	DMGEXTENTTYPE_COMP_ZLIB,
	DMGEXTENTTYPE_COMP_BZIP2,
	DMGEXTENTTYPE_COMP_LZFSE,
	DMGEXTENTTYPE_COMP_ADC,
	/** 32bit hack. */
	DMGEXTENTTYPE_32BIT_HACK = 0x7fffffff
} DMGEXTENTTYPE, * PDMGEXTENTTYPE;

/**
 * DMG extent mapping a virtual image block to real file offsets.
 */
typedef struct DMGEXTENT
{
	/** Extent type. */
	DMGEXTENTTYPE             enmType;
	/** First sector this extent describes. */
	grub_uint64_t             uSectorExtent;
	/** Number of sectors this extent describes. */
	grub_uint64_t             cSectorsExtent;
	/** Start offset in the real file. */
	grub_uint64_t             offFileStart;
	/** Number of bytes for the extent data in the file. */
	grub_uint64_t             cbFile;
} DMGEXTENT;
/** Pointer to an DMG extent. */
typedef DMGEXTENT* PDMGEXTENT;

/**
 * VirtualBox Apple Disk Image (DMG) interpreter instance data.
 */
typedef struct DMGIMAGE
{
	/** Descriptor file if applicable. */
	grub_file_t File;
	/** File size on the host disk (including all headers). */
	grub_uint64_t   FileSize;

	/** Flags the image was opened with. */
	//grub_uint32_t            uOpenFlags;
	/** Image flags. */
	unsigned            uImageFlags;
	/** Total size of the virtual image. */
	grub_uint64_t            cbSize;
	/** Size of the image. */
	grub_uint64_t            cbFile;

	/** The resources.
	 * A lazy bird ASSUME there are only two arrays in the resource-fork section in
	 * the XML, namely 'blkx' and 'plst'. These have been assigned fixed indexes. */
	DMGUDIFRSRCARRAY    aRsrcs[2];
	/** The UDIF footer. */
	DMGUDIF             Ftr;

	/** Number of valid extents in the array. */
	unsigned            cExtents;
	/** Number of entries the array can hold. */
	unsigned            cExtentsMax;
	/** Pointer to the extent array. */
	PDMGEXTENT          paExtents;
	/** Index of the last accessed extent. */
	unsigned            idxExtentLast;

	/** Extent which owns the data in the buffer. */
	PDMGEXTENT          pExtentDecomp;
	/** Buffer holding the decompressed data for a extent. */
	void* pvDecompExtent;
	/** Size of the buffer. */
	grub_size_t         cbDecompExtent;
} DMGIMAGE;
/** Pointer to an instance of the DMG Image Interpreter. */
typedef DMGIMAGE* PDMGIMAGE;

/** @name Resources indexes (into DMG::aRsrcs). */
#define DMG_RSRC_IDX_BLKX   0
#define DMG_RSRC_IDX_PLST   1

/** State for the input callout of the inflate reader. */
typedef struct DMGINFLATESTATE
{
	/* Image this operation relates to. */
	PDMGIMAGE pImage;
	/* Total size of the data to read. */
	grub_size_t    cbSize;
	/* Offset in the file to read. */
	grub_uint64_t  uFileOffset;
	/* Current read position. */
	grub_ssize_t   iOffset;
} DMGINFLATESTATE;


/*********************************************************************************************************************************
*   Defined Constants And Macros                                                                                                 *
*********************************************************************************************************************************/

/** @def DMG_VALIDATE
 * For validating a struct thing and log/print what's wrong.
 */
# define DMG_VALIDATE(expr, logstuff) \
    do { \
        if (!(expr)) \
        { \
            fRc = false; \
        } \
    } while (0)

/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/

static void dmgUdifFtrFile2HostEndian(PDMGUDIF pUdif);

static void dmgUdifIdHost2FileEndian(PDMGUDIFID pId);
static void dmgUdifIdFile2HostEndian(PDMGUDIFID pId);

static void dmgUdifCkSumFile2HostEndian(PDMGUDIFCKSUM pCkSum);
static bool dmgUdifCkSumIsValid(PCDMGUDIFCKSUM pCkSum, const char* pszPrefix);

static int
dmgFileReadSync(PDMGIMAGE pImage, grub_uint64_t off, void* pvBuf, grub_size_t cbRead, grub_ssize_t* pcbRead)
{
	grub_ssize_t bytesRead;
	if (grub_file_seek(pImage->File, off) == (grub_off_t)-1)
	{
		if (pcbRead)
			*pcbRead = -1;
		return GRUB_ERR_FILE_READ_ERROR;
	}

	bytesRead = grub_file_read(pImage->File, pvBuf, cbRead);
	if (pcbRead)
		*pcbRead = bytesRead;
	if (bytesRead < 0)
		return GRUB_ERR_FILE_READ_ERROR;
	if ((grub_size_t)bytesRead != cbRead)
		return grub_error(GRUB_ERR_FILE_READ_ERROR, "short read in DMG image");
	return GRUB_ERR_NONE;
}

/**
 * Internal: decompress an ADC (Apple Data Compression) stream.
 *
 * ADC is an LZ77 style scheme used by older DMG images. The stream is a
 * sequence of chunks, each led by a control byte:
 *   - 0x80 set: literal run of (b & 0x7f) + 1 bytes follows.
 *   - 0x40 set: 3-byte back reference, length (b & 0x3f) + 4, distance from
 *     the next two big-endian bytes.
 *   - otherwise: 2-byte back reference, length ((b & 0x3f) >> 2) + 3, distance
 *     from the low two bits and the next byte.
 * The stored distance is one less than the actual back distance.
 *
 * @returns Number of decompressed bytes.
 */
static grub_ssize_t
dmgAdcDecompress(const grub_uint8_t* pbSrc, grub_size_t cbSrc,
	grub_uint8_t* pbDst, grub_size_t cbDst)
{
	grub_size_t iSrc = 0;
	grub_size_t iDst = 0;

	while (iSrc < cbSrc)
	{
		grub_uint8_t b = pbSrc[iSrc];
		grub_size_t cbChunk;
		grub_size_t offCopy;

		if (b & 0x80)
		{
			cbChunk = (b & 0x7f) + 1;
			if (cbChunk > cbSrc - iSrc - 1 || cbChunk > cbDst - iDst)
				return -1;
			grub_memcpy(&pbDst[iDst], &pbSrc[iSrc + 1], cbChunk);
			iSrc += cbChunk + 1;
			iDst += cbChunk;
		}
		else if (b & 0x40)
		{
			cbChunk = (b & 0x3f) + 4;
			if (cbSrc - iSrc < 3)
				return -1;
			offCopy = ((grub_size_t)pbSrc[iSrc + 1] << 8) + pbSrc[iSrc + 2] + 1;
			if (offCopy > iDst || cbChunk > cbDst - iDst)
				return -1;
			for (grub_size_t i = 0; i < cbChunk; i++, iDst++)
				pbDst[iDst] = pbDst[iDst - offCopy];
			iSrc += 3;
		}
		else
		{
			cbChunk = ((b & 0x3f) >> 2) + 3;
			if (cbSrc - iSrc < 2)
				return -1;
			offCopy = (((grub_size_t)(b & 0x03)) << 8) + pbSrc[iSrc + 1] + 1;
			if (offCopy > iDst || cbChunk > cbDst - iDst)
				return -1;
			for (grub_size_t i = 0; i < cbChunk; i++, iDst++)
				pbDst[iDst] = pbDst[iDst - offCopy];
			iSrc += 2;
		}
	}

	if (iDst != cbDst)
		return -1;
	return (grub_ssize_t)iDst;
}

/**
 * Internal: read from a file and inflate the compressed data,
 * distinguishing between async and normal operation
 */
static int
dmgFileInflateSync(PDMGIMAGE pImage, DMGEXTENTTYPE emnType,
	grub_uint64_t uOffset, grub_size_t cbToRead,
	void* pvBuf, grub_size_t cbBuf)
{
	int rc = GRUB_ERR_BAD_COMPRESSED_DATA;
	grub_ssize_t cbActuallyRead;
	if (cbToRead == 0 || cbToRead > DMG_EXTENT_SIZE_MAX
		|| cbBuf == 0 || cbBuf > DMG_EXTENT_SIZE_MAX)
		return GRUB_ERR_BAD_COMPRESSED_DATA;

	char* pbBuf = grub_malloc(cbToRead);
	if (!pbBuf)
		return GRUB_ERR_OUT_OF_MEMORY;

	rc = dmgFileReadSync(pImage, uOffset, pbBuf, cbToRead, &cbActuallyRead);
	if (RT_FAILURE(rc))
		goto fail;
	rc = GRUB_ERR_BAD_COMPRESSED_DATA;
	switch (emnType)
	{
	case DMGEXTENTTYPE_COMP_ZLIB:
		cbActuallyRead = grub_zlib_decompress(pbBuf, cbActuallyRead, 0, pvBuf, cbBuf);
		break;
	case DMGEXTENTTYPE_COMP_BZIP2:
	{
		bz_stream bz = { 0 };
		if (BZ2_bzDecompressInit(&bz, 0, 0) != BZ_OK)
			goto fail;
		bz.avail_in = (unsigned int)cbActuallyRead;
		bz.next_in = pbBuf;
		bz.avail_out = (unsigned int)cbBuf;
		bz.next_out = pvBuf;
		int err = BZ2_bzDecompress(&bz);
		if (err != BZ_STREAM_END || bz.avail_out != 0)
		{
			BZ2_bzDecompressEnd(&bz);
			goto fail;
		}
		cbActuallyRead = (grub_ssize_t)cbBuf;
		BZ2_bzDecompressEnd(&bz);
	}
		break;
	case DMGEXTENTTYPE_COMP_LZFSE:
	{
		size_t cbOut = lzfse_decode_buffer((grub_uint8_t*)pvBuf, cbBuf,
			(const grub_uint8_t*)pbBuf, (size_t)cbActuallyRead, NULL);
		if (cbOut != cbBuf)
			goto fail;
		cbActuallyRead = (grub_ssize_t)cbOut;
	}
		break;
	case DMGEXTENTTYPE_COMP_ADC:
	{
		grub_ssize_t cbOut = dmgAdcDecompress((const grub_uint8_t*)pbBuf, cbActuallyRead,
			(grub_uint8_t*)pvBuf, cbBuf);
		if (cbOut != (grub_ssize_t)cbBuf)
			goto fail;
		cbActuallyRead = cbOut;
	}
		break;
	default:
		rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
		goto fail;
	}
	if (cbActuallyRead != (grub_ssize_t)cbBuf)
		goto fail;
	rc = GRUB_ERR_NONE;
fail:
	grub_free(pbBuf);
	return rc;
}

/**
 * Swaps endian.
 * @param   pUdif       The structure.
 */
static void dmgSwapEndianUdif(PDMGUDIF pUdif)
{
#ifndef RT_BIG_ENDIAN
	pUdif->u32Magic = RT_BE2H_U32(pUdif->u32Magic);
	pUdif->u32Version = RT_BE2H_U32(pUdif->u32Version);
	pUdif->cbFooter = RT_BE2H_U32(pUdif->cbFooter);
	pUdif->fFlags = RT_BE2H_U32(pUdif->fFlags);
	pUdif->offRunData = RT_BE2H_U64(pUdif->offRunData);
	pUdif->offData = RT_BE2H_U64(pUdif->offData);
	pUdif->cbData = RT_BE2H_U64(pUdif->cbData);
	pUdif->offRsrc = RT_BE2H_U64(pUdif->offRsrc);
	pUdif->cbRsrc = RT_BE2H_U64(pUdif->cbRsrc);
	pUdif->iSegment = RT_BE2H_U32(pUdif->iSegment);
	pUdif->cSegments = RT_BE2H_U32(pUdif->cSegments);
	pUdif->offXml = RT_BE2H_U64(pUdif->offXml);
	pUdif->cbXml = RT_BE2H_U64(pUdif->cbXml);
	pUdif->u32Type = RT_BE2H_U32(pUdif->u32Type);
	pUdif->cSectors = RT_BE2H_U64(pUdif->cSectors);
#endif
}

/**
 * Swaps endian from file to host cpu.
 * @param   pUdif       The structure.
 */
static void dmgUdifFtrFile2HostEndian(PDMGUDIF pUdif)
{
	dmgSwapEndianUdif(pUdif);
	dmgUdifIdFile2HostEndian(&pUdif->SegmentId);
	dmgUdifCkSumFile2HostEndian(&pUdif->DataCkSum);
	dmgUdifCkSumFile2HostEndian(&pUdif->MasterCkSum);
}

/**
 * Swaps endian from file to host cpu.
 * @param   pBlkx       The blkx structure.
 */
static void dmgBlkxFile2HostEndian(PDMGBLKX pBlkx)
{
	pBlkx->u32Magic = RT_BE2H_U32(pBlkx->u32Magic);
	pBlkx->u32Version = RT_BE2H_U32(pBlkx->u32Version);
	pBlkx->cSectornumberFirst = RT_BE2H_U64(pBlkx->cSectornumberFirst);
	pBlkx->cSectors = RT_BE2H_U64(pBlkx->cSectors);
	pBlkx->offDataStart = RT_BE2H_U64(pBlkx->offDataStart);
	pBlkx->cSectorsDecompress = RT_BE2H_U32(pBlkx->cSectorsDecompress);
	pBlkx->u32BlocksDescriptor = RT_BE2H_U32(pBlkx->u32BlocksDescriptor);
	pBlkx->cBlocksRunCount = RT_BE2H_U32(pBlkx->cBlocksRunCount);
	dmgUdifCkSumFile2HostEndian(&pBlkx->BlkxCkSum);
}

/**
 * Swaps endian from file to host cpu.
 * @param   pBlkxDesc   The blkx descriptor structure.
 */
static void dmgBlkxDescFile2HostEndian(PDMGBLKXDESC pBlkxDesc)
{
	pBlkxDesc->u32Type = RT_BE2H_U32(pBlkxDesc->u32Type);
	pBlkxDesc->u32Reserved = RT_BE2H_U32(pBlkxDesc->u32Reserved);
	pBlkxDesc->u64SectorStart = RT_BE2H_U64(pBlkxDesc->u64SectorStart);
	pBlkxDesc->u64SectorCount = RT_BE2H_U64(pBlkxDesc->u64SectorCount);
	pBlkxDesc->offData = RT_BE2H_U64(pBlkxDesc->offData);
	pBlkxDesc->cbData = RT_BE2H_U64(pBlkxDesc->cbData);
}

/**
 * Validates an UDIF footer structure.
 *
 * @returns true if valid, false and LogRel()s on failure.
 * @param   pFtr        The UDIF footer to validate.
 * @param   offFtr      The offset of the structure.
 */
static bool dmgUdifFtrIsValid(PCDMGUDIF pFtr, grub_uint64_t offFtr)
{
	bool fRc = true;

	DMG_VALIDATE(!(pFtr->fFlags & ~DMGUDIF_FLAGS_KNOWN_MASK), ("fFlags=%#RX32 fKnown=%RX32\n", pFtr->fFlags, DMGUDIF_FLAGS_KNOWN_MASK));
	DMG_VALIDATE(pFtr->offRunData < offFtr, ("offRunData=%#RX64\n", pFtr->offRunData));
	DMG_VALIDATE(pFtr->offData <= offFtr && pFtr->cbData <= offFtr - pFtr->offData, ("cbData=%#RX64 offData=%#RX64 offFtr=%#RX64\n", pFtr->cbData, pFtr->offData, offFtr));
	DMG_VALIDATE(pFtr->offRsrc <= offFtr && pFtr->cbRsrc <= offFtr - pFtr->offRsrc, ("cbRsrc=%#RX64 offRsrc=%#RX64 offFtr=%#RX64\n", pFtr->cbRsrc, pFtr->offRsrc, offFtr));
	DMG_VALIDATE(pFtr->cSegments <= 1, ("cSegments=%RU32\n", pFtr->cSegments));
	DMG_VALIDATE(pFtr->iSegment == 0 || pFtr->iSegment == 1, ("iSegment=%RU32 cSegments=%RU32\n", pFtr->iSegment, pFtr->cSegments));
	DMG_VALIDATE(pFtr->offXml <= offFtr && pFtr->cbXml <= offFtr - pFtr->offXml, ("cbXml=%#RX64 offXml=%#RX64 offFtr=%#RX64\n", pFtr->cbXml, pFtr->offXml, offFtr));
	DMG_VALIDATE(pFtr->cbXml > 128, ("cbXml=%#RX64\n", pFtr->cbXml));
	DMG_VALIDATE(pFtr->cbXml < 10 * _1M, ("cbXml=%#RX64\n", pFtr->cbXml));
	DMG_VALIDATE(pFtr->u32Type == DMGUDIF_TYPE_DEVICE || pFtr->u32Type == DMGUDIF_TYPE_PARTITION, ("u32Type=%RU32\n", pFtr->u32Type));
	DMG_VALIDATE(pFtr->cSectors != 0, ("cSectors=%#RX64\n", pFtr->cSectors));
	DMG_VALIDATE(pFtr->cSectors <= (~(grub_uint64_t)0 >> 9), ("cSectors=%#RX64\n", pFtr->cSectors));
	fRc = fRc && dmgUdifCkSumIsValid(&pFtr->DataCkSum, "DataCkSum");
	fRc = fRc && dmgUdifCkSumIsValid(&pFtr->MasterCkSum, "MasterCkSum");

	return fRc;
}

static bool dmgBlkxIsValid(PCDMGBLKX pBlkx)
{
	bool fRc = true;

	fRc = fRc && dmgUdifCkSumIsValid(&pBlkx->BlkxCkSum, "BlkxCkSum");
	DMG_VALIDATE(pBlkx->u32Magic == DMGBLKX_MAGIC, ("u32Magic=%#RX32 u32MagicExpected=%#RX32\n", pBlkx->u32Magic, DMGBLKX_MAGIC));
	DMG_VALIDATE(pBlkx->u32Version == DMGBLKX_VERSION, ("u32Version=%#RX32 u32VersionExpected=%#RX32\n", pBlkx->u32Magic, DMGBLKX_VERSION));

	return fRc;
}

/**
 * Swaps endian from host cpu to file.
 * @param   pId         The structure.
 */
static void dmgUdifIdHost2FileEndian(PDMGUDIFID pId)
{
	(void)pId;
}

/**
 * Swaps endian from file to host cpu.
 * @param   pId         The structure.
 */
static void dmgUdifIdFile2HostEndian(PDMGUDIFID pId)
{
	dmgUdifIdHost2FileEndian(pId);
}

/**
 * Swaps endian.
 * @param   pCkSum      The structure.
 * @param   u32Kind     Kind of the checksum (CRC32, none)
 * @param   cBits       Size of the checksum in bits.
 */
static void dmgSwapEndianUdifCkSum(PDMGUDIFCKSUM pCkSum, grub_uint32_t u32Kind, grub_uint32_t cBits)
{
#ifdef RT_BIG_ENDIAN
	(void)pCkSum;
	(void)u32Kind;
	(void)cBits;
#else
	switch (u32Kind)
	{
	case DMGUDIFCKSUM_NONE:
		/* nothing to do here */
		break;

	case DMGUDIFCKSUM_CRC32:
		pCkSum->u32Kind = RT_BE2H_U32(pCkSum->u32Kind);
		pCkSum->cBits = RT_BE2H_U32(pCkSum->cBits);
		pCkSum->uSum.au32[0] = RT_BE2H_U32(pCkSum->uSum.au32[0]);
		break;

	default:
		break;
	}
	(void)cBits;
#endif
}

/**
 * Swaps endian from file to host cpu.
 * @param   pCkSum      The structure.
 */
static void dmgUdifCkSumFile2HostEndian(PDMGUDIFCKSUM pCkSum)
{
	dmgSwapEndianUdifCkSum(pCkSum, RT_BE2H_U32(pCkSum->u32Kind), RT_BE2H_U32(pCkSum->cBits));
}


/**
 * Validates an UDIF checksum structure.
 *
 * @returns true if valid, false and LogRel()s on failure.
 * @param   pCkSum      The checksum structure.
 * @param   pszPrefix   The message prefix.
 * @remarks This does not check the checksummed data.
 */
static bool dmgUdifCkSumIsValid(PCDMGUDIFCKSUM pCkSum, const char* pszPrefix)
{
	bool fRc = true;

	switch (pCkSum->u32Kind)
	{
	case DMGUDIFCKSUM_NONE:
		DMG_VALIDATE(pCkSum->cBits == 0, ("%s/NONE: cBits=%d\n", pszPrefix, pCkSum->cBits));
		break;

	case DMGUDIFCKSUM_CRC32:
		DMG_VALIDATE(pCkSum->cBits == 32, ("%s/NONE: cBits=%d\n", pszPrefix, pCkSum->cBits));
		break;

	default:
		DMG_VALIDATE(0, ("%s: u32Kind=%#RX32\n", pszPrefix, pCkSum->u32Kind));
		break;
	}
	return fRc;
}

/**
 * Internal. Free all allocated space for representing an image except pThis,
 * and optionally delete the image from disk.
 */
static int dmgFreeImage(PDMGIMAGE pThis)
{
	int rc = GRUB_ERR_NONE;

	/* Freeing a never allocated image (e.g. because the open failed) is
	 * not signalled as an error. After all nothing bad happens. */
	if (pThis)
	{
		for (unsigned iRsrc = 0; iRsrc < RT_ELEMENTS(pThis->aRsrcs); iRsrc++)
			for (unsigned i = 0; i < pThis->aRsrcs[iRsrc].cEntries; i++)
			{
				if (pThis->aRsrcs[iRsrc].aEntries[i].pbData)
				{
					grub_free(pThis->aRsrcs[iRsrc].aEntries[i].pbData);
					pThis->aRsrcs[iRsrc].aEntries[i].pbData = NULL;
				}
				if (pThis->aRsrcs[iRsrc].aEntries[i].pszName)
				{
					grub_free(pThis->aRsrcs[iRsrc].aEntries[i].pszName);
					pThis->aRsrcs[iRsrc].aEntries[i].pszName = NULL;
				}
				if (pThis->aRsrcs[iRsrc].aEntries[i].pszCFName)
				{
					grub_free(pThis->aRsrcs[iRsrc].aEntries[i].pszCFName);
					pThis->aRsrcs[iRsrc].aEntries[i].pszCFName = NULL;
				}
			}

		if (pThis->pvDecompExtent)
		{
			grub_free(pThis->pvDecompExtent);
			pThis->pvDecompExtent = NULL;
			pThis->cbDecompExtent = 0;
		}

		if (pThis->paExtents)
		{
			grub_free(pThis->paExtents);
			pThis->paExtents = NULL;
		}
	}

	return rc;
}

static char* RTStrStripL(const char* psz)
{
	/* left */
	while (grub_isspace(*psz))
		psz++;

	return (char*)psz;
}

#define STARTS_WITH(pszString, szStart) \
        ( grub_strncmp(pszString, szStart, sizeof(szStart) - 1) == 0 )

#define STARTS_WITH_WORD(pszString, szWord) \
        (   STARTS_WITH(pszString, szWord) \
         && !grub_isalnum((pszString)[sizeof(szWord) - 1]) )

#define SKIP_AHEAD(psz, szWord) \
        do { \
            (psz) = RTStrStripL((psz) + sizeof(szWord) - 1); \
        } while (0)

#define REQUIRE_WORD(psz, szWord) \
        do { \
            if (!STARTS_WITH_WORD(psz, szWord)) \
                return psz; \
            (psz) = RTStrStripL((psz) + sizeof(szWord) - 1); \
        } while (0)

#define REQUIRE_TAG(psz, szTag) \
        do { \
            if (!STARTS_WITH(psz, "<" szTag ">")) \
                return psz; \
            (psz) = RTStrStripL((psz) + sizeof("<" szTag ">") - 1); \
        } while (0)

#define REQUIRE_TAG_NO_STRIP(psz, szTag) \
        do { \
            if (!STARTS_WITH(psz, "<" szTag ">")) \
                return psz; \
            (psz) += sizeof("<" szTag ">") - 1; \
        } while (0)

#define REQUIRE_END_TAG(psz, szTag) \
        do { \
            if (!STARTS_WITH(psz, "</" szTag ">")) \
                return psz; \
            (psz) = RTStrStripL((psz) + sizeof("</" szTag ">") - 1); \
        } while (0)

/**
 * Finds the next tag end.
 *
 * @returns Pointer to a '>' or '\0'.
 * @param   pszCur      The current position.
 */
static const char* dmgXmlFindTagEnd(const char* pszCur)
{
	/* Might want to take quoted '>' into account? */
	char ch;
	while ((ch = *pszCur) != '\0' && ch != '>')
		pszCur++;
	return pszCur;
}

/**
 * Finds the end tag.
 *
 * Does not deal with @verbatim<tag attr="1"/>@endverbatim style tags.
 *
 * @returns Pointer to the first char in the end tag. NULL if another tag
 *          was encountered first or if we hit the end of the file.
 * @param   ppszCur     The current position (IN/OUT).
 * @param   pszTag      The tag name.
 */
static const char* dmgXmlFindEndTag(const char** ppszCur, const char* pszTag)
{
	const char* psz = *ppszCur;
	char                ch;
	while ((ch = *psz))
	{
		if (ch == '<')
		{
			grub_size_t const cchTag = grub_strlen(pszTag);
			if (psz[1] == '/'
				&& !grub_strncmp(&psz[2], pszTag, cchTag)
				&& psz[2 + cchTag] == '>')
			{
				*ppszCur = psz + 2 + cchTag + 1;
				return psz;
			}
			break;
		}
		psz++;
	}
	return NULL;
}

static int
RTStrToInt32Ex(const char* pszValue, const char** ppszNext, grub_int32_t* pi32)
{
	long l = grub_strtol(pszValue, ppszNext, 0);
	grub_errno = GRUB_ERR_NONE;
	if (pi32)
		*pi32 = (grub_int32_t)l;
	const char* psz = *ppszNext;
	while (*psz == ' ' || *psz == '\t')
		psz++;
	if (*psz)
		return -1;
	return 0;
}

static int
RTStrToUInt32Ex(const char* pszValue, const char** ppszNext, grub_uint32_t* pi32)
{
	unsigned long ul = grub_strtoul(pszValue, ppszNext, 0);
	grub_errno = GRUB_ERR_NONE;
	if (pi32)
		*pi32 = (grub_uint32_t)ul;
	const char* psz = *ppszNext;
	while (*psz == ' ' || *psz == '\t')
		psz++;
	if (*psz)
		return -1;
	return 0;
}

static void*
RTMemDupEx(const void* pvSrc, size_t cbSrc, size_t cbExtra)
{
	void* pvDst = grub_malloc(cbSrc + cbExtra);
	if (pvDst)
	{
		grub_memcpy(pvDst, pvSrc, cbSrc);
		grub_memset((grub_uint8_t*)pvDst + cbSrc, 0, cbExtra);
	}
	return pvDst;
}

/**
 * Reads a signed 32-bit value.
 *
 * @returns NULL on success, pointer to the offending text on failure.
 * @param   ppszCur     The text position (IN/OUT).
 * @param   pi32        Where to store the value.
 */
static const char* dmgXmlParseS32(const char** ppszCur, grub_int32_t* pi32)
{
	const char* psz = *ppszCur;
	/*
	 * <string>-1</string>
	 */
	REQUIRE_TAG_NO_STRIP(psz, "string");

	const char* pszNext;
	int rc = RTStrToInt32Ex(psz, &pszNext, pi32);
	if (rc != -1)
		return *ppszCur;
	psz = pszNext;

	REQUIRE_END_TAG(psz, "string");
	*ppszCur = psz;
	return NULL;
}

/**
 * Reads an unsigned 32-bit value.
 *
 * @returns NULL on success, pointer to the offending text on failure.
 * @param   ppszCur     The text position (IN/OUT).
 * @param   pu32        Where to store the value.
 */
static const char* dmgXmlParseU32(const char** ppszCur, grub_uint32_t* pu32)
{
	const char* psz = *ppszCur;
	/*
	 * <string>0x00ff</string>
	 */
	REQUIRE_TAG_NO_STRIP(psz, "string");

	const char* pszNext;
	int rc = RTStrToUInt32Ex(psz, &pszNext, pu32);
	if (rc != -1)
		return *ppszCur;
	psz = pszNext;

	REQUIRE_END_TAG(psz, "string");
	*ppszCur = psz;
	return NULL;
}

/**
 * Reads a string value.
 *
 * @returns NULL on success, pointer to the offending text on failure.
 * @param   ppszCur     The text position (IN/OUT).
 * @param   ppszString  Where to store the pointer to the string. The caller
 *                      must free this using grub_free.
 */
static const char* dmgXmlParseString(const char** ppszCur, char** ppszString)
{
	const char* psz = *ppszCur;
	/*
	 * <string>Driver Descriptor Map (DDM : 0)</string>
	 */
	REQUIRE_TAG_NO_STRIP(psz, "string");

	const char* pszStart = psz;
	const char* pszEnd = dmgXmlFindEndTag(&psz, "string");
	if (!pszEnd)
		return *ppszCur;
	psz = RTStrStripL(psz);

	*ppszString = (char*)RTMemDupEx(pszStart, pszEnd - pszStart, 1);
	if (!*ppszString)
		return *ppszCur;

	*ppszCur = psz;
	return NULL;
}

/**
 * Parses the BASE-64 coded data tags.
 *
 * @returns NULL on success, pointer to the offending text on failure.
 * @param   ppszCur     The text position (IN/OUT).
 * @param   ppbData     Where to store the pointer to the data we've read. The
 *                      caller must free this using grub_free.
 * @param   pcbData     The number of bytes we're returning.
 */
static const char* dmgXmlParseData(const char** ppszCur, grub_uint8_t** ppbData, grub_size_t* pcbData)
{
	const char* psz = *ppszCur;

	/*
	 * <data>   AAAAA...    </data>
	 */
	REQUIRE_TAG(psz, "data");

	const char* pszStart = psz;
	grub_ssize_t cbData = RTBase64DecodedSize(pszStart, (char**)&psz);
	if (cbData == -1)
		return *ppszCur;

	REQUIRE_END_TAG(psz, "data");

	*ppbData = (grub_uint8_t*)grub_malloc(cbData);
	if (!*ppbData)
		return *ppszCur;
	char* pszIgnored;
	int rc = RTBase64Decode(pszStart, *ppbData, cbData, pcbData, &pszIgnored);
	if (RT_FAILURE(rc))
	{
		grub_free(*ppbData);
		*ppbData = NULL;
		return *ppszCur;
	}

	*ppszCur = psz;
	return NULL;
}

/**
 * Parses the XML resource-fork in a rather presumptive manner.
 *
 * This function is supposed to construct the DMG::aRsrcs instance data
 * parts.
 *
 * @returns NULL on success, pointer to the problematic text on failure.
 * @param   pThis       The DMG instance data.
 * @param   pszXml      The XML text to parse, UTF-8.
 */
static const char* dmgOpenXmlToRsrc(PDMGIMAGE pThis, char const* pszXml)
{
	const char* psz = pszXml;

	/*
	 * Verify the ?xml, !DOCTYPE and plist tags.
	 */
	SKIP_AHEAD(psz, "");

	/* <?xml version="1.0" encoding="UTF-8"?> */
	REQUIRE_WORD(psz, "<?xml");
	while (*psz != '?')
	{
		if (!*psz)
			return psz;
		if (STARTS_WITH_WORD(psz, "version="))
		{
			SKIP_AHEAD(psz, "version=");
			REQUIRE_WORD(psz, "\"1.0\"");
		}
		else if (STARTS_WITH_WORD(psz, "encoding="))
		{
			SKIP_AHEAD(psz, "encoding=");
			REQUIRE_WORD(psz, "\"UTF-8\"");
		}
		else
			return psz;
	}
	if (!STARTS_WITH(psz, "?>"))
		return psz;
	SKIP_AHEAD(psz, "?>");

	/* <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> */
	REQUIRE_WORD(psz, "<!DOCTYPE");
	REQUIRE_WORD(psz, "plist");
	REQUIRE_WORD(psz, "PUBLIC");
	psz = dmgXmlFindTagEnd(psz);
	REQUIRE_WORD(psz, ">");

	/* <plist version="1.0"> */
	REQUIRE_WORD(psz, "<plist");
	REQUIRE_WORD(psz, "version=");
	REQUIRE_WORD(psz, "\"1.0\"");
	REQUIRE_WORD(psz, ">");

	/*
	 * Descend down to the 'resource-fork' dictionary.
	 * ASSUME it's the only top level dictionary.
	 */
	 /* <dict> <key>resource-fork</key> */
	REQUIRE_TAG(psz, "dict");
	REQUIRE_WORD(psz, "<key>resource-fork</key>");

	/*
	 * Parse the keys in the resource-fork dictionary.
	 * ASSUME that there are just two, 'blkx' and 'plst'.
	 */
	REQUIRE_TAG(psz, "dict");
	while (!STARTS_WITH_WORD(psz, "</dict>"))
	{
		if (!*psz)
			return psz;

		/*
		 * Parse the key and Create the resource-fork entry.
		 */
		unsigned iRsrc;
		if (STARTS_WITH_WORD(psz, "<key>blkx</key>"))
		{
			REQUIRE_WORD(psz, "<key>blkx</key>");
			iRsrc = DMG_RSRC_IDX_BLKX;
			grub_strcpy(&pThis->aRsrcs[iRsrc].szName[0], "blkx");
		}
		else if (STARTS_WITH_WORD(psz, "<key>plst</key>"))
		{
			REQUIRE_WORD(psz, "<key>plst</key>");
			iRsrc = DMG_RSRC_IDX_PLST;
			grub_strcpy(&pThis->aRsrcs[iRsrc].szName[0], "plst");
		}
		else
			return psz;


		/*
		 * Descend into the array and add the elements to the resource entry.
		 */
		 /* <array> */
		REQUIRE_TAG(psz, "array");
		while (!STARTS_WITH_WORD(psz, "</array>"))
		{
			if (!*psz)
				return psz;
			REQUIRE_TAG(psz, "dict");
			grub_uint32_t i = pThis->aRsrcs[iRsrc].cEntries;
			if (i == RT_ELEMENTS(pThis->aRsrcs[iRsrc].aEntries))
				return psz;

			while (!STARTS_WITH_WORD(psz, "</dict>"))
			{
				if (!*psz)
					return psz;

				/* switch on the key. */
				const char* pszErr;
				if (STARTS_WITH_WORD(psz, "<key>Attributes</key>"))
				{
					REQUIRE_WORD(psz, "<key>Attributes</key>");
					pszErr = dmgXmlParseU32(&psz, &pThis->aRsrcs[iRsrc].aEntries[i].fAttributes);
				}
				else if (STARTS_WITH_WORD(psz, "<key>ID</key>"))
				{
					REQUIRE_WORD(psz, "<key>ID</key>");
					pszErr = dmgXmlParseS32(&psz, &pThis->aRsrcs[iRsrc].aEntries[i].iId);
				}
				else if (STARTS_WITH_WORD(psz, "<key>Name</key>"))
				{
					REQUIRE_WORD(psz, "<key>Name</key>");
					pszErr = dmgXmlParseString(&psz, &pThis->aRsrcs[iRsrc].aEntries[i].pszName);
				}
				else if (STARTS_WITH_WORD(psz, "<key>CFName</key>"))
				{
					REQUIRE_WORD(psz, "<key>CFName</key>");
					pszErr = dmgXmlParseString(&psz, &pThis->aRsrcs[iRsrc].aEntries[i].pszCFName);
				}
				else if (STARTS_WITH_WORD(psz, "<key>Data</key>"))
				{
					REQUIRE_WORD(psz, "<key>Data</key>");
					pszErr = dmgXmlParseData(&psz, &pThis->aRsrcs[iRsrc].aEntries[i].pbData, &pThis->aRsrcs[iRsrc].aEntries[i].cbData);
				}
				else
					pszErr = psz;
				if (pszErr)
					return pszErr;
			} /* while not </dict> */
			REQUIRE_END_TAG(psz, "dict");

			pThis->aRsrcs[iRsrc].cEntries++;
		} /* while not </array> */
		REQUIRE_END_TAG(psz, "array");

	} /* while not </dict> */
	REQUIRE_END_TAG(psz, "dict");

	/*
	 * ASSUMING there is only the 'resource-fork', we'll now see the end of
	 * the outer dict, plist and text.
	 */
	 /* </dict> </plist> */
	REQUIRE_END_TAG(psz, "dict");
	REQUIRE_END_TAG(psz, "plist");

	/* the end */
	if (*psz)
		return psz;

	return NULL;
}

#undef REQUIRE_END_TAG
#undef REQUIRE_TAG_NO_STRIP
#undef REQUIRE_TAG
#undef REQUIRE_WORD
#undef SKIP_AHEAD
#undef STARTS_WITH_WORD
#undef STARTS_WITH

/**
 * Returns the data attached to a resource.
 *
 * @returns VBox status code.
 * @param   pThis        The DMG instance data.
 * @param   pcszRsrcName Name of the resource to get.
 * @param   ppcRsrc      Where to store the pointer to the resource data on success.
 */
static int dmgGetRsrcData(PDMGIMAGE pThis, const char* pcszRsrcName,
	PCDMGUDIFRSRCARRAY* ppcRsrc)
{
	int rc = GRUB_ERR_FILE_NOT_FOUND;

	for (unsigned i = 0; i < RT_ELEMENTS(pThis->aRsrcs); i++)
	{
		if (!grub_strcmp(pThis->aRsrcs[i].szName, pcszRsrcName))
		{
			*ppcRsrc = &pThis->aRsrcs[i];
			rc = GRUB_ERR_NONE;
			break;
		}
	}

	return rc;
}

/**
 * Creates a new extent from the given blkx descriptor.
 *
 * @returns VBox status code.
 * @param   pThis          DMG instance data.
 * @param   uSectorPart    First sector the partition owning the blkx descriptor has.
 * @param   pBlkxDesc      The blkx descriptor.
 */
static int dmgExtentCreateFromBlkxDesc(PDMGIMAGE pThis, grub_uint64_t uSectorPart,
	grub_uint64_t cSectorsPart, grub_uint64_t offDataStart, PDMGBLKXDESC pBlkxDesc)
{
	int rc = GRUB_ERR_NONE;
	DMGEXTENTTYPE enmExtentTypeNew;
	PDMGEXTENT pExtentNew = NULL;
	grub_uint64_t uSectorExtent;
	grub_uint64_t cbExtent;
	grub_uint64_t offFileStart = 0;

	if (pBlkxDesc->u32Type == DMGBLKXDESC_TYPE_RAW)
		enmExtentTypeNew = DMGEXTENTTYPE_RAW;
	else if (pBlkxDesc->u32Type == DMGBLKXDESC_TYPE_IGNORE)
		enmExtentTypeNew = DMGEXTENTTYPE_ZERO;
	else if (pBlkxDesc->u32Type == DMGBLKXDESC_TYPE_ZLIB)
		enmExtentTypeNew = DMGEXTENTTYPE_COMP_ZLIB;
	else if (pBlkxDesc->u32Type == DMGBLKXDESC_TYPE_BZLIB)
		enmExtentTypeNew = DMGEXTENTTYPE_COMP_BZIP2;
	else if (pBlkxDesc->u32Type == DMGBLKXDESC_TYPE_LZFSE)
		enmExtentTypeNew = DMGEXTENTTYPE_COMP_LZFSE;
	else if (pBlkxDesc->u32Type == DMGBLKXDESC_TYPE_ADC)
		enmExtentTypeNew = DMGEXTENTTYPE_COMP_ADC;
	else
	{
		return GRUB_ERR_NOT_IMPLEMENTED_YET;
	}

	if (pBlkxDesc->u64SectorCount == 0
		|| pBlkxDesc->u64SectorStart > cSectorsPart
		|| pBlkxDesc->u64SectorCount > cSectorsPart - pBlkxDesc->u64SectorStart)
		return GRUB_ERR_BAD_DEVICE;
	uSectorExtent = uSectorPart + pBlkxDesc->u64SectorStart;
	cbExtent = DMG_BLOCK2BYTE(pBlkxDesc->u64SectorCount);

	if (enmExtentTypeNew != DMGEXTENTTYPE_ZERO)
	{
		grub_uint64_t offDataRelative;
		if (pBlkxDesc->u64SectorCount > DMG_EXTENT_SECTORS_MAX
			|| pBlkxDesc->cbData == 0 || pBlkxDesc->cbData > DMG_EXTENT_SIZE_MAX
			|| offDataStart > pThis->Ftr.cbData
			|| pBlkxDesc->offData > pThis->Ftr.cbData - offDataStart)
			return GRUB_ERR_BAD_DEVICE;
		offDataRelative = offDataStart + pBlkxDesc->offData;
		if (pBlkxDesc->cbData > pThis->Ftr.cbData - offDataRelative)
			return GRUB_ERR_BAD_DEVICE;
		if (enmExtentTypeNew == DMGEXTENTTYPE_RAW && pBlkxDesc->cbData != cbExtent)
			return GRUB_ERR_BAD_DEVICE;
		offFileStart = pThis->Ftr.offData + offDataRelative;
	}

	if (pThis->cExtents)
	{
		const DMGEXTENT* pExtentPrev = &pThis->paExtents[pThis->cExtents - 1];
		if (uSectorExtent < pExtentPrev->uSectorExtent + pExtentPrev->cSectorsExtent)
			return GRUB_ERR_BAD_DEVICE;
	}

	{
		if (pThis->cExtentsMax == pThis->cExtents)
		{
			if (pThis->cExtentsMax > (~0U) - 64)
				return GRUB_ERR_OUT_OF_MEMORY;
			pThis->cExtentsMax += 64;

			/* Increase the array. */
			PDMGEXTENT paExtentsNew = (PDMGEXTENT)grub_realloc(pThis->paExtents, sizeof(DMGEXTENT) * pThis->cExtentsMax);
			if (!paExtentsNew)
			{
				rc = GRUB_ERR_OUT_OF_MEMORY;
				pThis->cExtentsMax -= 64;
			}
			else
				pThis->paExtents = paExtentsNew;
		}

		if (RT_SUCCESS(rc))
		{
			pExtentNew = &pThis->paExtents[pThis->cExtents++];

			pExtentNew->enmType = enmExtentTypeNew;
			pExtentNew->uSectorExtent = uSectorExtent;
			pExtentNew->cSectorsExtent = pBlkxDesc->u64SectorCount;
			pExtentNew->offFileStart = offFileStart;
			pExtentNew->cbFile = enmExtentTypeNew == DMGEXTENTTYPE_ZERO ? 0 : pBlkxDesc->cbData;
		}
	}

	return rc;
}

/**
 * Find the extent for the given sector number.
 */
static PDMGEXTENT dmgExtentGetFromOffset(PDMGIMAGE pThis, grub_uint64_t uSector)
{
	/*
	 * We assume that the array is ordered from lower to higher sector
	 * numbers.
	 * This makes it possible to bisect the array to find the extent
	 * faster than using a linked list.
	 */
	PDMGEXTENT pExtent = NULL;
	unsigned idxCur = pThis->idxExtentLast;
	unsigned idxMax = pThis->cExtents;
	unsigned idxMin = 0;

	while (idxMin < idxMax)
	{
		PDMGEXTENT pExtentCur = &pThis->paExtents[idxCur];

		/* Determine the search direction. */
		if (uSector < pExtentCur->uSectorExtent)
		{
			/* Search left from the current extent. */
			idxMax = idxCur;
		}
		else if (uSector >= pExtentCur->uSectorExtent + pExtentCur->cSectorsExtent)
		{
			/* Search right from the current extent. */
			idxMin = idxCur + 1;
		}
		else
		{
			/* The sector lies in the extent, stop searching. */
			pExtent = pExtentCur;
			break;
		}

		idxCur = idxMin + (idxMax - idxMin) / 2;
	}

	if (pExtent)
		pThis->idxExtentLast = idxCur;

	return pExtent;
}

/**
 * Goes through the BLKX structure and creates the necessary extents.
 */
static int dmgBlkxParse(PDMGIMAGE pThis, PDMGBLKX pBlkx)
{
	int rc = GRUB_ERR_NONE;
	PDMGBLKXDESC pBlkxDesc = (PDMGBLKXDESC)(pBlkx + 1);

	if (pBlkx->cBlocksRunCount == 0 || pBlkx->cSectors == 0
		|| pBlkx->cSectornumberFirst > pThis->Ftr.cSectors
		|| pBlkx->cSectors > pThis->Ftr.cSectors - pBlkx->cSectornumberFirst
		|| pBlkx->offDataStart > pThis->Ftr.cbData)
		return GRUB_ERR_BAD_DEVICE;

	for (unsigned i = 0; i < pBlkx->cBlocksRunCount; i++)
	{
		dmgBlkxDescFile2HostEndian(pBlkxDesc);

		switch (pBlkxDesc->u32Type)
		{
		case DMGBLKXDESC_TYPE_RAW:
		case DMGBLKXDESC_TYPE_IGNORE:
		case DMGBLKXDESC_TYPE_ADC:
		case DMGBLKXDESC_TYPE_ZLIB:
		case DMGBLKXDESC_TYPE_BZLIB:
		case DMGBLKXDESC_TYPE_LZFSE:
		{
			rc = dmgExtentCreateFromBlkxDesc(pThis, pBlkx->cSectornumberFirst,
				pBlkx->cSectors, pBlkx->offDataStart, pBlkxDesc);
			break;
		}
		case DMGBLKXDESC_TYPE_COMMENT:
		case DMGBLKXDESC_TYPE_TERMINATOR:
			break;
		default:
			rc = GRUB_ERR_BAD_DEVICE;
			break;
		}

		if (pBlkxDesc->u32Type == DMGBLKXDESC_TYPE_TERMINATOR
			|| RT_FAILURE(rc))
			break;

		pBlkxDesc++;
	}

	return rc;
}

/**
 * Worker for dmgOpen that reads in and validates all the necessary
 * structures from the image.
 *
 * @returns VBox status code.
 * @param   pThis       The DMG instance data.
 */
static int
dmgOpenImage(PDMGIMAGE pThis)
{
	int rc;

	pThis->FileSize = grub_file_size(pThis->File);
	pThis->cbFile = pThis->FileSize;
	/*
	 * Read the footer.
	 */
	rc = dmgFileReadSync(pThis, pThis->cbFile - sizeof(pThis->Ftr), &pThis->Ftr, sizeof(pThis->Ftr), NULL);
	if (RT_FAILURE(rc))
		return rc;
	dmgUdifFtrFile2HostEndian(&pThis->Ftr);

	/*
	 * Do we recognize the footer structure? If so, is it valid?
	 */
	if (pThis->Ftr.u32Magic != DMGUDIF_MAGIC)
		return GRUB_ERR_BAD_DEVICE;
	if (pThis->Ftr.u32Version != DMGUDIF_VER_CURRENT)
		return GRUB_ERR_BAD_DEVICE;
	if (pThis->Ftr.cbFooter != sizeof(pThis->Ftr))
		return GRUB_ERR_BAD_DEVICE;

	if (!dmgUdifFtrIsValid(&pThis->Ftr, pThis->cbFile - sizeof(pThis->Ftr)))
		return GRUB_ERR_BAD_DEVICE;

	pThis->cbSize = DMG_BLOCK2BYTE(pThis->Ftr.cSectors);

	/*
	 * Read and parse the XML portion.
	 */
	grub_size_t cchXml = (grub_size_t)pThis->Ftr.cbXml;
	char* pszXml = (char*)grub_malloc(cchXml + 1);
	if (!pszXml)
		return GRUB_ERR_OUT_OF_MEMORY;
	rc = dmgFileReadSync(pThis, pThis->Ftr.offXml, pszXml, cchXml, NULL);
	if (RT_SUCCESS(rc))
	{
		pszXml[cchXml] = '\0';
		const char* pszError = dmgOpenXmlToRsrc(pThis, pszXml);
		if (!pszError)
		{
			PCDMGUDIFRSRCARRAY pRsrcBlkx = NULL;

			rc = dmgGetRsrcData(pThis, "blkx", &pRsrcBlkx);
			if (RT_SUCCESS(rc))
			{
				for (unsigned idxBlkx = 0; idxBlkx < pRsrcBlkx->cEntries; idxBlkx++)
				{
					PDMGBLKX pBlkx = NULL;

					if (pRsrcBlkx->aEntries[idxBlkx].cbData < sizeof(DMGBLKX))
					{
						rc = GRUB_ERR_BAD_DEVICE;
						break;
					}

					pBlkx = (PDMGBLKX)grub_zalloc(pRsrcBlkx->aEntries[idxBlkx].cbData);
					if (!pBlkx)
					{
						rc = GRUB_ERR_OUT_OF_MEMORY;
						break;
					}

					grub_memcpy(pBlkx, pRsrcBlkx->aEntries[idxBlkx].pbData, pRsrcBlkx->aEntries[idxBlkx].cbData);

					dmgBlkxFile2HostEndian(pBlkx);

					grub_size_t cbBlkxDescs = pRsrcBlkx->aEntries[idxBlkx].cbData - sizeof(DMGBLKX);
					if (dmgBlkxIsValid(pBlkx)
						&& cbBlkxDescs % sizeof(DMGBLKXDESC) == 0
						&& cbBlkxDescs / sizeof(DMGBLKXDESC) == pBlkx->cBlocksRunCount)
						rc = dmgBlkxParse(pThis, pBlkx);
					else
						rc = GRUB_ERR_BAD_DEVICE;

					grub_free(pBlkx);

					if (RT_FAILURE(rc))
						break;
				}
			}
			else
				rc = GRUB_ERR_BAD_DEVICE;
		}
		else
		{
			rc = GRUB_ERR_BAD_SIGNATURE;
		}
	}
	grub_free(pszXml);
	if (RT_SUCCESS(rc) && pThis->cExtents == 0)
		rc = GRUB_ERR_BAD_DEVICE;

	if (RT_FAILURE(rc))
		dmgFreeImage(pThis);
	return rc;
}

static int
dmgOpen(grub_file_t File, void** ppBackendData)
{
	/*
	 * Create the basic instance data structure and open the file,
	 * then hand it over to a worker function that does all the rest.
	 */
	int rc = GRUB_ERR_NONE;
	PDMGIMAGE pThis = (PDMGIMAGE)grub_zalloc(sizeof(DMGIMAGE));
	if (!pThis)
	{
		rc = GRUB_ERR_OUT_OF_MEMORY;
		return rc;
	}
	pThis->File = File;
	rc = dmgOpenImage(pThis);
	if (RT_SUCCESS(rc))
		*ppBackendData = pThis;
	else
		grub_free(pThis);

	return rc;
}

static int
dmgClose(void* pBackendData)
{
	PDMGIMAGE pThis = (PDMGIMAGE)pBackendData;

	int rc = dmgFreeImage(pThis);
	grub_free(pThis);

	return rc;
}

static int
dmgRead(void* pBackendData, grub_uint64_t uOffset, void* pvBuf, grub_size_t cbToRead,
	grub_size_t* pcbActuallyRead)
{
	PDMGIMAGE pThis = (PDMGIMAGE)pBackendData;
	PDMGEXTENT pExtent = NULL;
	int rc = GRUB_ERR_NONE;
	grub_uint64_t offExtent;
	grub_uint64_t cbExtent;
	grub_uint64_t offExtentRelative;

	*pcbActuallyRead = 0;
	if (uOffset > pThis->cbSize || cbToRead > pThis->cbSize - uOffset)
		return GRUB_ERR_BAD_ARGUMENT;

	pExtent = dmgExtentGetFromOffset(pThis, DMG_BYTE2BLOCK(uOffset));

	if (pExtent)
	{
		offExtent = DMG_BLOCK2BYTE(pExtent->uSectorExtent);
		cbExtent = DMG_BLOCK2BYTE(pExtent->cSectorsExtent);
		offExtentRelative = uOffset - offExtent;

		/* Remain in this extent. */
		if (cbExtent - offExtentRelative < cbToRead)
			cbToRead = (grub_size_t)(cbExtent - offExtentRelative);

		switch (pExtent->enmType)
		{
		case DMGEXTENTTYPE_RAW:
		{
			rc = dmgFileReadSync(pThis, pExtent->offFileStart + offExtentRelative,
				pvBuf, cbToRead, NULL);
			break;
		}
		case DMGEXTENTTYPE_ZERO:
		{
			grub_memset(pvBuf, 0, cbToRead);
			break;
		}
		case DMGEXTENTTYPE_COMP_ZLIB:
		case DMGEXTENTTYPE_COMP_BZIP2:
		case DMGEXTENTTYPE_COMP_LZFSE:
		case DMGEXTENTTYPE_COMP_ADC:
		{
			if (pThis->pExtentDecomp != pExtent)
			{
				grub_size_t cbDecompExtent = (grub_size_t)cbExtent;
				if (cbDecompExtent > pThis->cbDecompExtent)
				{
					if (pThis->pvDecompExtent)
						grub_free(pThis->pvDecompExtent);
					pThis->pvDecompExtent = NULL;
					pThis->cbDecompExtent = 0;
					pThis->pExtentDecomp = NULL;

					pThis->pvDecompExtent = grub_zalloc(cbDecompExtent);
					if (!pThis->pvDecompExtent)
						rc = GRUB_ERR_OUT_OF_MEMORY;
					else
						pThis->cbDecompExtent = cbDecompExtent;
				}

				if (RT_SUCCESS(rc))
				{
					rc = dmgFileInflateSync(pThis, pExtent->enmType,
						pExtent->offFileStart, pExtent->cbFile, pThis->pvDecompExtent,
						cbDecompExtent);
					if (RT_SUCCESS(rc))
						pThis->pExtentDecomp = pExtent;
				}
			}

			if (RT_SUCCESS(rc))
			{
				grub_memcpy(pvBuf,
					(grub_uint8_t*)pThis->pvDecompExtent + offExtentRelative,
					cbToRead);
			}
			break;
		}
		default:
			rc = GRUB_ERR_NOT_IMPLEMENTED_YET;
		}

		if (RT_SUCCESS(rc))
			*pcbActuallyRead = cbToRead;
	}
	else
		rc = GRUB_ERR_BAD_ARGUMENT;

	return rc;
}

static grub_uint64_t
dmgGetSize(void* pBackendData)
{
	PDMGIMAGE pImage = (PDMGIMAGE)pBackendData;

	if (pImage)
		return pImage->cbSize;
	return 0;
}


struct grub_dmg
{
	grub_file_t file;
	void* dmg;
};
typedef struct grub_dmg* grub_dmg_t;

static struct grub_fs grub_dmg_fs;

static grub_err_t
grub_dmg_close(grub_file_t file)
{
	grub_dmg_t dmgio = file->data;

	dmgClose(dmgio->dmg);
	grub_file_close(dmgio->file);
	grub_free(dmgio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_dmg_open(grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_dmg_t dmgio;
	void* dmg = NULL;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < sizeof(DMGUDIF) || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	if (dmgOpen(io, &dmg) != GRUB_ERR_NONE)
	{
		grub_file_seek(io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t)grub_zalloc(sizeof(*file));
	if (!file)
	{
		dmgClose(dmg);
		return 0;
	}

	dmgio = grub_zalloc(sizeof(*dmgio));
	if (!dmgio)
	{
		dmgClose(dmg);
		grub_free(file);
		return 0;
	}
	dmgio->file = io;
	dmgio->dmg = dmg;

	file->device = io->device;
	file->data = dmgio;
	file->fs = &grub_dmg_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = dmgGetSize(dmg);

	return file;
}

static grub_ssize_t
grub_dmg_read(grub_file_t file, char* buf, grub_size_t len)
{
	int rc = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_size_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_dmg_t dmgio = file->data;

	while (len > 0 && rc == GRUB_ERR_NONE)
	{
		real_size = 0;
		rc = dmgRead(dmgio->dmg, read_offset, buf, len, &real_size);
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
		grub_error((grub_err_t)rc, "DMG image read failed");
		return -1;
	}
	return (grub_ssize_t)size;
}

static struct grub_fs grub_dmg_fs =
{
	.name = "dmg",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_dmg_read,
	.fs_close = grub_dmg_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT(dmg)
{
	grub_file_filter_register(GRUB_FILE_FILTER_DMG, grub_dmg_open);
}

GRUB_MOD_FINI(dmg)
{
	grub_file_filter_unregister(GRUB_FILE_FILTER_DMG);
}
