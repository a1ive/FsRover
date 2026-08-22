/* $Id: QED.cpp $ */
/** @file
 * QED - QEMU enhanced disk image.
 */

/*
 * Copyright (C) 2011-2025 Oracle and/or its affiliates.
 *
 * This file is part of VirtualBox base platform packages, as available from
 * https://www.virtualbox.org, and was adapted for Rover's read-only GRUB file
 * filter interface.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, in version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <https://www.gnu.org/licenses>.
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
 *   Structures in a QED image, little endian                                                                                    *
 *********************************************************************************************************************************/

#pragma pack(1)
typedef struct QedHeader
{
	grub_uint32_t u32Magic;
	grub_uint32_t u32ClusterSize;
	grub_uint32_t u32TableSize;
	grub_uint32_t u32HeaderSize;
	grub_uint64_t u64FeatureFlags;
	grub_uint64_t u64CompatFeatureFlags;
	grub_uint64_t u64AutoresetFeatureFlags;
	grub_uint64_t u64OffL1Table;
	grub_uint64_t u64Size;
	grub_uint32_t u32OffBackingFilename;
	grub_uint32_t u32BackingFilenameSize;
} QedHeader, *PQedHeader;
#pragma pack()

#define QED_MAGIC                            0x00444551U /* QED\0 */
#define QED_CLUSTER_SIZE_MIN                 (4U * _1K)
#define QED_CLUSTER_SIZE_MAX                 (64U * _1M)
#define QED_TABLE_SIZE_MIN                   1U
#define QED_TABLE_SIZE_MAX                   16U

#define QED_FEATURE_BACKING_FILE             RT_BIT_64(0)
#define QED_FEATURE_NEED_CHECK               RT_BIT_64(1)
#define QED_FEATURE_BACKING_FILE_NO_PROBE    RT_BIT_64(2)
#define QED_FEATURE_MASK                     (QED_FEATURE_BACKING_FILE | QED_FEATURE_NEED_CHECK \
												 | QED_FEATURE_BACKING_FILE_NO_PROBE)

/* Bound the eagerly loaded L1/L2 tables.  The common 64 KiB cluster and four
 * table clusters use only 256 KiB; 32 MiB still covers unusually large valid
 * layouts without permitting hostile headers to request gigabyte allocations. */
#define QED_TABLE_BYTES_MAX                  (32U * _1M)

typedef struct QEDIMAGE
{
	grub_file_t File;
	grub_uint64_t FileSize;
	grub_file_t Backing;

	grub_uint64_t cbSize;
	grub_uint64_t cbHeader;
	grub_uint32_t cbCluster;
	grub_uint32_t cbTable;
	grub_uint32_t cTableEntries;
	grub_uint64_t offL1Table;
	grub_uint64_t *paL1Table;

	grub_uint64_t fOffsetMask;
	grub_uint64_t fL2Mask;
	grub_uint32_t cL1Shift;
	grub_uint32_t cL2Shift;

	grub_uint64_t offCachedL2Table;
	grub_uint64_t *paCachedL2Table;
} QEDIMAGE, *PQEDIMAGE;

static int
qedFileReadSync(PQEDIMAGE pImage, grub_uint64_t off, void *pvBuf,
	grub_size_t cbRead)
{
	grub_ssize_t cbActual;

	if (grub_file_seek(pImage->File, off) == (grub_off_t)-1)
		return GRUB_ERR_OUT_OF_RANGE;
	cbActual = grub_file_read(pImage->File, pvBuf, cbRead);
	if (cbActual < 0)
		return GRUB_ERR_FILE_READ_ERROR;
	if ((grub_size_t)cbActual != cbRead)
		return grub_error(GRUB_ERR_FILE_READ_ERROR,
			"short read in QED image");
	return GRUB_ERR_NONE;
}

static int
qedRangeValid(grub_uint64_t off, grub_uint64_t cb, grub_uint64_t cbLimit)
{
	return off <= cbLimit && cb <= cbLimit - off;
}

static grub_uint32_t
qedGetPowerOfTwo(grub_uint32_t u32)
{
	grub_uint32_t uPower2 = 0;

	if (!u32)
		return 0;
	while ((u32 & 1) == 0)
	{
		u32 >>= 1;
		uPower2++;
	}
	return u32 == 1 ? uPower2 : 0;
}

static int
qedIsPowerOfTwo(grub_uint32_t u32)
{
	return u32 && !(u32 & (u32 - 1));
}

static int
qedHdrConvertToHostEndianess(PQedHeader pHeader)
{
	pHeader->u32Magic = RT_LE2H_U32(pHeader->u32Magic);
	pHeader->u32ClusterSize = RT_LE2H_U32(pHeader->u32ClusterSize);
	pHeader->u32TableSize = RT_LE2H_U32(pHeader->u32TableSize);
	pHeader->u32HeaderSize = RT_LE2H_U32(pHeader->u32HeaderSize);
	pHeader->u64FeatureFlags = RT_LE2H_U64(pHeader->u64FeatureFlags);
	pHeader->u64CompatFeatureFlags = RT_LE2H_U64(pHeader->u64CompatFeatureFlags);
	pHeader->u64AutoresetFeatureFlags = RT_LE2H_U64(pHeader->u64AutoresetFeatureFlags);
	pHeader->u64OffL1Table = RT_LE2H_U64(pHeader->u64OffL1Table);
	pHeader->u64Size = RT_LE2H_U64(pHeader->u64Size);
	pHeader->u32OffBackingFilename = RT_LE2H_U32(pHeader->u32OffBackingFilename);
	pHeader->u32BackingFilenameSize = RT_LE2H_U32(pHeader->u32BackingFilenameSize);

	return pHeader->u32Magic == QED_MAGIC;
}

static void
qedTableConvertToHostEndianess(grub_uint64_t *paTable,
	grub_uint32_t cEntries)
{
	while (cEntries--)
	{
		*paTable = RT_LE2H_U64(*paTable);
		paTable++;
	}
}

static int
qedHdrValidate(PQedHeader pHeader, grub_uint64_t cbFile)
{
	grub_uint64_t cbHeader;
	grub_uint64_t cbTable;
	grub_uint64_t cTableEntries;
	grub_uint64_t cGuestClusters;
	grub_uint32_t cClusterBits;
	grub_uint32_t cTableBits;

	if (cbFile < sizeof(*pHeader)
		|| pHeader->u32ClusterSize < QED_CLUSTER_SIZE_MIN
		|| pHeader->u32ClusterSize > QED_CLUSTER_SIZE_MAX
		|| !qedIsPowerOfTwo(pHeader->u32ClusterSize)
		|| pHeader->u32TableSize < QED_TABLE_SIZE_MIN
		|| pHeader->u32TableSize > QED_TABLE_SIZE_MAX
		|| !qedIsPowerOfTwo(pHeader->u32TableSize)
		|| !pHeader->u32HeaderSize
		|| !pHeader->u64Size || (pHeader->u64Size & 511))
		return GRUB_ERR_BAD_DEVICE;

	if (pHeader->u64FeatureFlags & ~QED_FEATURE_MASK)
		return GRUB_ERR_NOT_IMPLEMENTED_YET;
	if (pHeader->u64FeatureFlags
		& (QED_FEATURE_NEED_CHECK | QED_FEATURE_BACKING_FILE_NO_PROBE))
		return GRUB_ERR_NOT_IMPLEMENTED_YET;

	cbHeader = (grub_uint64_t)pHeader->u32HeaderSize
		* pHeader->u32ClusterSize;
	cbTable = (grub_uint64_t)pHeader->u32TableSize
		* pHeader->u32ClusterSize;
	if (cbHeader < sizeof(*pHeader) || cbHeader > cbFile
		|| cbTable > QED_TABLE_BYTES_MAX)
		return GRUB_ERR_OUT_OF_RANGE;

	cTableEntries = cbTable / sizeof(grub_uint64_t);
	cClusterBits = qedGetPowerOfTwo(pHeader->u32ClusterSize);
	cTableBits = qedGetPowerOfTwo((grub_uint32_t)cTableEntries);
	cGuestClusters = pHeader->u64Size / pHeader->u32ClusterSize;
	if (pHeader->u64Size % pHeader->u32ClusterSize)
		cGuestClusters++;
	if (!cTableEntries || cClusterBits + 2 * cTableBits > 64
		|| cGuestClusters > cTableEntries * cTableEntries)
		return GRUB_ERR_OUT_OF_RANGE;

	if (!pHeader->u64OffL1Table
		|| (pHeader->u64OffL1Table & (pHeader->u32ClusterSize - 1))
		|| pHeader->u64OffL1Table < cbHeader
		|| !qedRangeValid(pHeader->u64OffL1Table, cbTable, cbFile))
		return GRUB_ERR_OUT_OF_RANGE;

	if (pHeader->u64FeatureFlags & QED_FEATURE_BACKING_FILE)
	{
		if (!pHeader->u32BackingFilenameSize
			|| pHeader->u32BackingFilenameSize == 0xffffffffU
			|| pHeader->u32OffBackingFilename < sizeof(*pHeader)
			|| !qedRangeValid(pHeader->u32OffBackingFilename,
				pHeader->u32BackingFilenameSize, cbHeader))
			return GRUB_ERR_BAD_DEVICE;
	}
	else if (pHeader->u32OffBackingFilename
		|| pHeader->u32BackingFilenameSize)
		return GRUB_ERR_BAD_DEVICE;

	return GRUB_ERR_NONE;
}

static void
qedTableMasksInit(PQEDIMAGE pImage)
{
	grub_uint32_t cClusterBits = qedGetPowerOfTwo(pImage->cbCluster);
	grub_uint32_t cTableBits = qedGetPowerOfTwo(pImage->cTableEntries);

	pImage->fOffsetMask = (grub_uint64_t)pImage->cbCluster - 1;
	pImage->fL2Mask = ((grub_uint64_t)pImage->cTableEntries - 1)
		<< cClusterBits;
	pImage->cL2Shift = cClusterBits;
	pImage->cL1Shift = cClusterBits + cTableBits;
}

static void
qedConvertLogicalOffset(PQEDIMAGE pImage, grub_uint64_t off,
	grub_uint32_t *pidxL1, grub_uint32_t *pidxL2,
	grub_uint32_t *poffCluster)
{
	*poffCluster = (grub_uint32_t)(off & pImage->fOffsetMask);
	*pidxL1 = (grub_uint32_t)(off >> pImage->cL1Shift);
	*pidxL2 = (grub_uint32_t)((off & pImage->fL2Mask)
		>> pImage->cL2Shift);
}

static int
qedTableOffsetValid(PQEDIMAGE pImage, grub_uint64_t off)
{
	return off >= pImage->cbHeader
		&& !(off & (pImage->cbCluster - 1))
		&& qedRangeValid(off, pImage->cbTable, pImage->FileSize);
}

static int
qedDataOffsetValid(PQEDIMAGE pImage, grub_uint64_t off)
{
	return off >= pImage->cbHeader
		&& !(off & (pImage->cbCluster - 1))
		&& qedRangeValid(off, pImage->cbCluster, pImage->FileSize);
}

static int
qedL2TableFetch(PQEDIMAGE pImage, grub_uint64_t offL2Table)
{
	int rc;

	if (!qedTableOffsetValid(pImage, offL2Table))
		return GRUB_ERR_OUT_OF_RANGE;
	if (pImage->offCachedL2Table == offL2Table)
		return GRUB_ERR_NONE;

	rc = qedFileReadSync(pImage, offL2Table, pImage->paCachedL2Table,
		pImage->cbTable);
	if (rc == GRUB_ERR_NONE)
	{
		qedTableConvertToHostEndianess(pImage->paCachedL2Table,
			pImage->cTableEntries);
		pImage->offCachedL2Table = offL2Table;
	}
	return rc;
}

static int
qedConvertToImageOffset(PQEDIMAGE pImage, grub_uint32_t idxL1,
	grub_uint32_t idxL2, grub_uint32_t offCluster,
	grub_uint64_t *poffImage, int *pfAllocated)
{
	grub_uint64_t offL2Table;
	grub_uint64_t offData;
	int rc;

	*pfAllocated = 0;
	if (idxL1 >= pImage->cTableEntries
		|| idxL2 >= pImage->cTableEntries)
		return GRUB_ERR_OUT_OF_RANGE;

	offL2Table = pImage->paL1Table[idxL1];
	if (!offL2Table)
		return GRUB_ERR_NONE;
	rc = qedL2TableFetch(pImage, offL2Table);
	if (rc != GRUB_ERR_NONE)
		return rc;

	offData = pImage->paCachedL2Table[idxL2];
	if (!offData)
		return GRUB_ERR_NONE;
	if (!qedDataOffsetValid(pImage, offData))
		return GRUB_ERR_OUT_OF_RANGE;

	*poffImage = offData + offCluster;
	*pfAllocated = 1;
	return GRUB_ERR_NONE;
}

static void
qedFreeImage(PQEDIMAGE pImage)
{
	if (pImage->Backing)
	{
		grub_file_close(pImage->Backing);
		pImage->Backing = NULL;
	}
	grub_free(pImage->paL1Table);
	pImage->paL1Table = NULL;
	grub_free(pImage->paCachedL2Table);
	pImage->paCachedL2Table = NULL;
}

static int
qedOpenImage(PQEDIMAGE pImage)
{
	QedHeader Header;
	grub_uint64_t cbTable;
	grub_uint32_t i;
	int rc;

	pImage->FileSize = grub_file_size(pImage->File);
	rc = qedFileReadSync(pImage, 0, &Header, sizeof(Header));
	if (rc != GRUB_ERR_NONE)
		return rc;
	if (!qedHdrConvertToHostEndianess(&Header))
		return GRUB_ERR_BAD_DEVICE;
	rc = qedHdrValidate(&Header, pImage->FileSize);
	if (rc != GRUB_ERR_NONE)
		return rc;

	cbTable = (grub_uint64_t)Header.u32TableSize
		* Header.u32ClusterSize;
	pImage->cbSize = Header.u64Size;
	pImage->cbHeader = (grub_uint64_t)Header.u32HeaderSize
		* Header.u32ClusterSize;
	pImage->cbCluster = Header.u32ClusterSize;
	pImage->cbTable = (grub_uint32_t)cbTable;
	pImage->cTableEntries = pImage->cbTable / sizeof(grub_uint64_t);
	pImage->offL1Table = Header.u64OffL1Table;
	qedTableMasksInit(pImage);

	pImage->paL1Table = (grub_uint64_t *)grub_malloc(pImage->cbTable);
	pImage->paCachedL2Table = (grub_uint64_t *)grub_malloc(pImage->cbTable);
	if (!pImage->paL1Table || !pImage->paCachedL2Table)
	{
		rc = GRUB_ERR_OUT_OF_MEMORY;
		goto fail;
	}
	rc = qedFileReadSync(pImage, pImage->offL1Table,
		pImage->paL1Table, pImage->cbTable);
	if (rc != GRUB_ERR_NONE)
		goto fail;
	qedTableConvertToHostEndianess(pImage->paL1Table,
		pImage->cTableEntries);
	for (i = 0; i < pImage->cTableEntries; i++)
		if (pImage->paL1Table[i]
			&& !qedTableOffsetValid(pImage, pImage->paL1Table[i]))
		{
			rc = GRUB_ERR_OUT_OF_RANGE;
			goto fail;
		}

	if (Header.u64FeatureFlags & QED_FEATURE_BACKING_FILE)
	{
		char *pszBacking;

		if (Header.u32BackingFilenameSize >= 1024)
		{
			rc = GRUB_ERR_BAD_DEVICE;
			goto fail;
		}
		pszBacking = (char *)grub_malloc(
			Header.u32BackingFilenameSize + 1);
		if (!pszBacking)
		{
			rc = GRUB_ERR_OUT_OF_MEMORY;
			goto fail;
		}
		rc = qedFileReadSync(pImage, Header.u32OffBackingFilename,
			pszBacking, Header.u32BackingFilenameSize);
		pszBacking[Header.u32BackingFilenameSize] = '\0';
		if (rc == GRUB_ERR_NONE
			&& grub_memchr(pszBacking, '\0',
				Header.u32BackingFilenameSize))
			rc = GRUB_ERR_BAD_DEVICE;
		if (rc == GRUB_ERR_NONE)
		{
			pImage->Backing = grub_vdisk_open_parent(pImage->File,
				pszBacking);
			if (!pImage->Backing)
				rc = grub_errno;
		}
		grub_free(pszBacking);
		if (rc != GRUB_ERR_NONE)
			goto fail;
	}

	return GRUB_ERR_NONE;

fail:
	qedFreeImage(pImage);
	return rc;
}

static int
qedOpen(grub_file_t File, void **ppBackendData)
{
	PQEDIMAGE pImage;
	int rc;

	pImage = (PQEDIMAGE)grub_zalloc(sizeof(*pImage));
	if (!pImage)
		return GRUB_ERR_OUT_OF_MEMORY;
	pImage->File = File;
	rc = qedOpenImage(pImage);
	if (rc == GRUB_ERR_NONE)
		*ppBackendData = pImage;
	else
		grub_free(pImage);
	return rc;
}

static void
qedClose(void *pBackendData)
{
	PQEDIMAGE pImage = (PQEDIMAGE)pBackendData;

	qedFreeImage(pImage);
	grub_free(pImage);
}

static int
qedRead(void *pBackendData, grub_uint64_t uOffset, void *pvBuf,
	grub_size_t cbToRead, grub_size_t *pcbActuallyRead)
{
	PQEDIMAGE pImage = (PQEDIMAGE)pBackendData;
	grub_uint32_t offCluster;
	grub_uint32_t idxL1;
	grub_uint32_t idxL2;
	grub_uint64_t offFile = 0;
	int fAllocated;
	int rc;

	if (uOffset > pImage->cbSize || cbToRead > pImage->cbSize - uOffset)
		return GRUB_ERR_BAD_ARGUMENT;
	qedConvertLogicalOffset(pImage, uOffset, &idxL1, &idxL2,
		&offCluster);
	cbToRead = RT_MIN(cbToRead, pImage->cbCluster - offCluster);
	rc = qedConvertToImageOffset(pImage, idxL1, idxL2, offCluster,
		&offFile, &fAllocated);
	if (rc == GRUB_ERR_NONE)
	{
		if (fAllocated)
			rc = qedFileReadSync(pImage, offFile, pvBuf, cbToRead);
		else if (pImage->Backing)
			rc = grub_vdisk_read_parent(pImage->Backing, uOffset,
				pvBuf, cbToRead);
		else
			grub_memset(pvBuf, 0, cbToRead);
	}
	if (rc == GRUB_ERR_NONE && pcbActuallyRead)
		*pcbActuallyRead = cbToRead;
	return rc;
}

static grub_uint64_t
qedGetSize(void *pBackendData)
{
	PQEDIMAGE pImage = (PQEDIMAGE)pBackendData;

	return pImage ? pImage->cbSize : 0;
}

struct grub_qed
{
	grub_file_t file;
	void *qed;
};
typedef struct grub_qed *grub_qed_t;

static struct grub_fs grub_qed_fs;

static grub_err_t
grub_qed_close(grub_file_t file)
{
	grub_qed_t qedio = file->data;

	qedClose(qedio->qed);
	grub_file_close(qedio->file);
	grub_free(qedio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_qed_open(grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_qed_t qedio;
	void *qed = NULL;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < sizeof(QedHeader)
		|| io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;
	if (qedOpen(io, &qed) != GRUB_ERR_NONE)
	{
		grub_file_seek(io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t)grub_zalloc(sizeof(*file));
	if (!file)
	{
		qedClose(qed);
		return NULL;
	}
	qedio = (grub_qed_t)grub_zalloc(sizeof(*qedio));
	if (!qedio)
	{
		qedClose(qed);
		grub_free(file);
		return NULL;
	}
	qedio->file = io;
	qedio->qed = qed;
	file->device = io->device;
	file->data = qedio;
	file->fs = &grub_qed_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = qedGetSize(qed);
	return file;
}

static grub_ssize_t
grub_qed_read(grub_file_t file, char *buf, grub_size_t len)
{
	grub_qed_t qedio = file->data;
	grub_uint64_t readOffset = file->offset;
	grub_size_t cbTotal = 0;
	int rc = GRUB_ERR_NONE;

	while (len && rc == GRUB_ERR_NONE)
	{
		grub_size_t cbActual = 0;

		rc = qedRead(qedio->qed, readOffset, buf, len, &cbActual);
		if (rc != GRUB_ERR_NONE)
			break;
		if (!cbActual)
		{
			rc = GRUB_ERR_FILE_READ_ERROR;
			break;
		}
		readOffset += cbActual;
		buf += cbActual;
		cbTotal += cbActual;
		if (cbActual >= len)
			break;
		len -= cbActual;
	}
	if (rc != GRUB_ERR_NONE)
	{
		grub_error((grub_err_t)rc, "QED image read failed");
		return -1;
	}
	return (grub_ssize_t)cbTotal;
}

static struct grub_fs grub_qed_fs =
{
	.name = "qed",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_qed_read,
	.fs_close = grub_qed_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT(qed)
{
	grub_file_filter_register(GRUB_FILE_FILTER_QED, grub_qed_open);
}

GRUB_MOD_FINI(qed)
{
	grub_file_filter_unregister(GRUB_FILE_FILTER_QED);
}
