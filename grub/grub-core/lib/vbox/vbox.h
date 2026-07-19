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
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL), a copy of it is provided in the "COPYING.CDDL" file included
 * in the VirtualBox distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 *
 * SPDX-License-Identifier: GPL-3.0-only OR CDDL-1.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <grub/types.h>

#define _1K                    0x00000400
#define _2K                    0x00000800
#define _4K                    0x00001000
#define _8K                    0x00002000
#define _16K                   0x00004000
#define _32K                   0x00008000
#define _64K                   0x00010000
#define _128K                  0x00020000
#define _256K                  0x00040000
#define _512K                  0x00080000
#define _1M                    0x00100000
#define _1T                    0x0000010000000000LL

#define RTSTR_MAX       (~(grub_size_t)0)

#define RT_SUCCESS(rc) (rc == GRUB_ERR_NONE)
#define RT_FAILURE(rc) (rc != GRUB_ERR_NONE)

#define RT_MIN(Value1, Value2) ((Value1) <= (Value2) ? (Value1) : (Value2))

#define RT_BIT(bit)            (1U << (bit))
#define RT_BIT_32(bit)         (1U << (bit))
#define RT_BIT_64(bit)         (1ULL << (bit))

#define RT_UOFFSETOF(type, member)             ((uintptr_t)&(((type *)(void *)0)->member))
#define RT_SIZEOFMEMB(type, member)            (sizeof(((type *)(void *)0)->member))
#define RT_UOFFSET_AFTER(a_Type, a_Member)     (RT_UOFFSETOF(a_Type, a_Member) + RT_SIZEOFMEMB(a_Type, a_Member))
#define RT_FROM_MEMBER(pMem, Type, Member)      ((Type *)((grub_uint8_t *)(void *)(pMem) - RT_UOFFSETOF(Type, Member)))

#define RT_ALIGN_T(u, uAlignment, type)         (((type)(u) + ((uAlignment) - 1)) & ~(type)((uAlignment) - 1))
#define RT_ALIGN_64(u64, uAlignment)            RT_ALIGN_T(u64, uAlignment, grub_uint64_t)

/** No flags. */
#define VD_IMAGE_FLAGS_NONE                     (0)
/** Fixed image. */
#define VD_IMAGE_FLAGS_FIXED                    (0x10000)
/** Diff image. Mutually exclusive with fixed image. */
#define VD_IMAGE_FLAGS_DIFF                     (0x20000)
/** VMDK: Split image into 2GB extents. */
#define VD_VMDK_IMAGE_FLAGS_SPLIT_2G            (0x0001)
/** VMDK: Raw disk image (giving access to a number of host partitions). */
#define VD_VMDK_IMAGE_FLAGS_RAWDISK             (0x0002)
/** VMDK: stream optimized image, read only. */
#define VD_VMDK_IMAGE_FLAGS_STREAM_OPTIMIZED    (0x0004)
/** VMDK: ESX variant, use in addition to other flags. */
#define VD_VMDK_IMAGE_FLAGS_ESX                 (0x0008)
/** VDI: Fill new blocks with zeroes while expanding image file. Only valid
 * for newly created images, never set for opened existing images. */
#define VD_VDI_IMAGE_FLAGS_ZERO_EXPAND          (0x0100)

typedef union RTUUID
{
	/** 8-bit view. */
	grub_uint8_t     au8[16];
	/** 16-bit view. */
	grub_uint16_t    au16[8];
	/** 32-bit view. */
	grub_uint32_t    au32[4];
	/** 64-bit view. */
	grub_uint64_t    au64[2];
	/** The way the UUID is declared by the DCE specification. */
	struct
	{
		grub_uint32_t    u32TimeLow;
		grub_uint16_t    u16TimeMid;
		grub_uint16_t    u16TimeHiAndVersion;
		grub_uint8_t     u8ClockSeqHiAndReserved;
		grub_uint8_t     u8ClockSeqLow;
		grub_uint8_t     au8Node[6];
	} Gen;
} RTUUID;
/** Pointer to UUID data. */
typedef RTUUID* PRTUUID;
/** Pointer to readonly UUID data. */
typedef const RTUUID* PCRTUUID;

#ifdef GRUB_CPU_WORDS_BIGENDIAN

#define RT_BIG_ENDIAN

#define RT_BE2H_U16(x) ((grub_uint16_t) (x)
#define RT_BE2H_U32(x) ((grub_uint32_t) (x)
#define RT_BE2H_U64(x) ((grub_uint64_t) (x))

#define RT_H2LE_U64(x)   grub_swap_bytes64(x)
#define RT_H2LE_U32(x)   grub_swap_bytes32(x)
#define RT_H2LE_U16(x)   grub_swap_bytes16(x)

#define RT_LE2H_U64(x)   grub_swap_bytes64(x)
#define RT_LE2H_U32(x)   grub_swap_bytes32(x)
#define RT_LE2H_U16(x)   grub_swap_bytes16(x)

#else

#define RT_LITTLE_ENDIAN

#define RT_BE2H_U16(x) (grub_swap_bytes16 (x))
#define RT_BE2H_U32(x) (grub_swap_bytes32 (x))
#define RT_BE2H_U64(x) (grub_swap_bytes64 (x))

#define RT_H2LE_U64(x)  ((grub_uint64_t) (x))
#define RT_H2LE_U32(x)  ((grub_uint32_t) (x))
#define RT_H2LE_U16(x)  ((grub_uint16_t) (x))

#define RT_LE2H_U64(x)  ((grub_uint64_t) (x))
#define RT_LE2H_U32(x)  ((grub_uint32_t) (x))
#define RT_LE2H_U16(x)  ((grub_uint16_t) (x))

#endif

/** @def RT_ELEMENTS
 * Calculates the number of elements in a statically sized array.
 * @returns Element count.
 * @param   aArray      Array in question.
 */
#define RT_ELEMENTS(aArray) (sizeof(aArray) / sizeof((aArray)[0]))

int
RTUuidIsNull(PCRTUUID pUuid);

int
RTUuidCompare(PCRTUUID pUuid1, PCRTUUID pUuid2);

int
RTUuidFromStr(PRTUUID pUuid, const char* pszString);

int
RTUuidCompareStr(PCRTUUID pUuid1, const char* pszString2);

grub_uint32_t
RTCrc32C(const void* pv, grub_size_t cb);

grub_ssize_t
RTBase64DecodedSize(const char* pszString, char** ppszEnd);

int
RTBase64Decode(const char* pszString, void* pvData, grub_size_t cbData, grub_size_t* pcbActual, char** ppszEnd);

typedef struct RTLISTNODE
{
	/** Pointer to the next list node. */
	struct RTLISTNODE* pNext;
	/** Pointer to the previous list node. */
	struct RTLISTNODE* pPrev;
} RTLISTNODE;
/** Pointer to a list node. */
typedef RTLISTNODE* PRTLISTNODE;
/** Pointer to a const list node. */
typedef RTLISTNODE const* PCRTLISTNODE;
/** Pointer to a list node pointer. */
typedef PRTLISTNODE* PPRTLISTNODE;

static inline void RTListInit(PRTLISTNODE pList)
{
	pList->pNext = pList;
	pList->pPrev = pList;
}

static inline void RTListAppend(PRTLISTNODE pList, PRTLISTNODE pNode)
{
	pList->pPrev->pNext = pNode;
	pNode->pPrev = pList->pPrev;
	pNode->pNext = pList;
	pList->pPrev = pNode;
}

static inline void RTListPrepend(PRTLISTNODE pList, PRTLISTNODE pNode)
{
	pList->pNext->pPrev = pNode;
	pNode->pNext = pList->pNext;
	pNode->pPrev = pList;
	pList->pNext = pNode;
}

static inline void RTListNodeInsertAfter(PRTLISTNODE pCurNode, PRTLISTNODE pNewNode)
{
	RTListPrepend(pCurNode, pNewNode);
}

static inline void RTListNodeInsertBefore(PRTLISTNODE pCurNode, PRTLISTNODE pNewNode)
{
	RTListAppend(pCurNode, pNewNode);
}

static inline void RTListNodeRemove(PRTLISTNODE pNode)
{
	PRTLISTNODE pPrev = pNode->pPrev;
	PRTLISTNODE pNext = pNode->pNext;

	pPrev->pNext = pNext;
	pNext->pPrev = pPrev;

	/* poison */
	pNode->pNext = NULL;
	pNode->pPrev = NULL;
}

static inline PRTLISTNODE RTListNodeRemoveRet(PRTLISTNODE pNode)
{
	PRTLISTNODE pPrev = pNode->pPrev;
	PRTLISTNODE pNext = pNode->pNext;

	pPrev->pNext = pNext;
	pNext->pPrev = pPrev;

	/* poison */
	pNode->pNext = NULL;
	pNode->pPrev = NULL;

	return pNode;
}

#define RTListNodeIsDummy(pList, pNode, Type, Member) \
         ((pNode) == RT_FROM_MEMBER((pList), Type, Member))

#define RTListIsEmpty(pList)            ((pList)->pPrev == (pList))

#define RTListNodeGetNext(pCurNode, Type, Member) \
    RT_FROM_MEMBER((pCurNode)->pNext, Type, Member)

#define RTListNodeGetPrev(pCurNode, Type, Member) \
    RT_FROM_MEMBER((pCurNode)->pPrev, Type, Member)

#define RTListGetFirst(pList, Type, Member) \
    (!RTListIsEmpty(pList) ? RTListNodeGetNext(pList, Type, Member) : NULL)

#define RTListForEach(pList, pIterator, Type, Member) \
    for ((pIterator) = RTListNodeGetNext(pList, Type, Member); \
         !RTListNodeIsDummy(pList, pIterator, Type, Member); \
         (pIterator) = RT_FROM_MEMBER((pIterator)->Member.pNext, Type, Member))

#define RTListForEachSafe(pList, pIterator, pIterNext, Type, Member) \
    for ((pIterator) = RTListNodeGetNext(pList, Type, Member), \
         (pIterNext) = RT_FROM_MEMBER((pIterator)->Member.pNext, Type, Member); \
         !RTListNodeIsDummy(pList, pIterator, Type, Member); \
         (pIterator) = (pIterNext), \
         (pIterNext) = RT_FROM_MEMBER((pIterator)->Member.pNext, Type, Member))

#define RTListForEachReverse(pList, pIterator, Type, Member) \
    for ((pIterator) = RTListNodeGetPrev(pList, Type, Member); \
         !RTListNodeIsDummy(pList, pIterator, Type, Member); \
         (pIterator) = RT_FROM_MEMBER((pIterator)->Member.pPrev, Type, Member))

typedef enum RTZIPTYPE
{
	/** Invalid. */
	RTZIPTYPE_INVALID = 0,
	/** Choose best fitting one. */
	RTZIPTYPE_AUTO,
	/** Store the data. */
	RTZIPTYPE_STORE,
	/** Zlib compression the data. */
	RTZIPTYPE_ZLIB,
	/** BZlib compress. */
	RTZIPTYPE_BZLIB,
	/** libLZF compress. */
	RTZIPTYPE_LZF,
	/** Lempel-Ziv-Jeff-Bonwick compression. */
	RTZIPTYPE_LZJB,
	/** Lempel-Ziv-Oberhumer compression. */
	RTZIPTYPE_LZO,
	/* Zlib compression the data without zlib header. */
	RTZIPTYPE_ZLIB_NO_HEADER,
	/** End of valid the valid compression types.  */
	RTZIPTYPE_END
} RTZIPTYPE;

typedef enum RTZIPLEVEL
{
	/** Store, don't compress. */
	RTZIPLEVEL_STORE = 0,
	/** Fast compression. */
	RTZIPLEVEL_FAST,
	/** Default compression. */
	RTZIPLEVEL_DEFAULT,
	/** Maximal compression. */
	RTZIPLEVEL_MAX
} RTZIPLEVEL;

int RTZipBlockDecompress(RTZIPTYPE enmType, grub_uint32_t fFlags,
	void const* pvSrc, grub_size_t cbSrc, grub_size_t* pcbSrcActual,
	void* pvDst, grub_size_t cbDst, grub_size_t* pcbDstActual);

/*
 * Rover additions (vdparent.c): parent / backing file support shared by
 * the vhd, vhdx and qcow io filters.  Not part of VirtualBox.
 */

struct grub_file;

/* Convert an on-disk UTF-16 string (nunits code units, stops at NUL,
   unaligned source is fine) to a malloc'd UTF-8 string.  big_endian
   selects the source byte order.  */
char *
grub_vdisk_utf16_to_utf8_dup (const void *src, grub_size_t nunits,
			      int big_endian);

/* Resolve PARENT (Windows or POSIX style, relative or absolute) against
   the directory of IMAGE (a grub path like "(disk)/dir/child.vhd") and
   return a malloc'd grub path.  Foreign absolute paths (drive letter or
   UNC) fall back to the basename next to IMAGE.  */
char *
grub_vdisk_parent_path (const char *image, const char *parent);

/* Open the parent image PARENT of IMAGE through the vdisk filter chain.
   Guards against runaway parent chains.  Returns NULL with grub_errno
   set on failure.  */
struct grub_file *
grub_vdisk_open_parent (const char *image, const char *parent);

/* Open MEMBER (an extent file referenced by IMAGE, e.g. a vmdk flat or
   sparse extent) raw, without running the vdisk filters on it.  */
struct grub_file *
grub_vdisk_open_member (const char *image, const char *member);

/* Read LEN bytes at virtual offset OFF from an opened parent, zero
   filling anything past its end.  */
int
grub_vdisk_read_parent (struct grub_file *parent, grub_uint64_t off,
			void *buf, grub_size_t len);
