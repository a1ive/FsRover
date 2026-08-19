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
 * Shared bits of the Symantec (Norton) Ghost image format, used by the
 * io\gho.c virtual disk filter and the fs\gho.c catalogue browser.
 */

#ifndef GRUB_GHOST_HEADER
#define GRUB_GHOST_HEADER	1

#include <grub/types.h>
#include <grub/err.h>

/* Both the file header and each partition header are this long.  */
#define GRUB_GHOST_HEADER_SIZE		512

/* Record header: [2B kind][2B stale][4B magic][2B len].  Only the low
   byte of the first field is a kind; the rest is uninitialised memory
   in every writer seen.  */
#define GRUB_GHOST_REC_HDR_SIZE		10
#define GRUB_GHOST_REC_MAGIC		0x012f18d8

/* Record kinds.  */
#define GRUB_GHOST_REC_DATA		0x02	/* file contents */
#define GRUB_GHOST_REC_END		0x03	/* end of a data run */
#define GRUB_GHOST_REC_DIRENT		0x04	/* 32 byte FAT directory entry */
#define GRUB_GHOST_REC_TRACK0		0x06	/* pre-partition sectors */
#define GRUB_GHOST_REC_BOOT		0x17	/* boot sector */
#define GRUB_GHOST_REC_RESERVED		0x18	/* reserved sector area */
#define GRUB_GHOST_REC_DIRENT_OLD	0x19	/* old FAT directory entry */

/* File header byte 2.  */
#define GRUB_GHOST_FILE_PRIMARY		0x01
#define GRUB_GHOST_FILE_SPAN		0x09

/* Partition header byte 2.  */
#define GRUB_GHOST_PART_SECTOR		0x02	/* raw sector chain */
#define GRUB_GHOST_PART_FAT		0x03	/* FAT catalogue */
#define GRUB_GHOST_PART_NTFS		0x04	/* NTFS filesystem packets */

/* File header byte 3.  */
#define GRUB_GHOST_COMP_NONE		0
#define GRUB_GHOST_COMP_FAST		2	/* Fast LZ, "-z1" */
#define GRUB_GHOST_COMP_ZLIB_FIRST	3	/* High, "-z2" and up */
#define GRUB_GHOST_COMP_ZLIB_LAST	9
#define GRUB_GHOST_COMP_NTFS		10	/* filesystem-aware NTFS stream */

/* Uncompressed bytes one block holds.  stored_len is a 16 bit field
   that counts itself, so a stored block cannot exceed this either.  */
#define GRUB_GHOST_BLOCK_SIZE		32768
#define GRUB_GHOST_BLOCK_MAX		65536
#define GRUB_GHOST_STORED_MAX		0xffff
#define GRUB_GHOST_STORED_MIN		4

/* Fast LZ hash table, allocated by the caller and reused across blocks.  */
#define GRUB_GHOST_FASTLZ_HASH_SIZE	4096

static inline grub_uint16_t
grub_ghost_get16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) (p[0] | ((grub_uint16_t) p[1] << 8));
}

static inline grub_uint32_t
grub_ghost_get32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8)
	       | ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

static inline int
grub_ghost_comp_supported (grub_uint8_t comp)
{
	return comp == GRUB_GHOST_COMP_NONE || comp == GRUB_GHOST_COMP_FAST
	       || (comp >= GRUB_GHOST_COMP_ZLIB_FIRST
		   && comp <= GRUB_GHOST_COMP_ZLIB_LAST)
	       || comp == GRUB_GHOST_COMP_NTFS;
}

/*
 * Decode one block payload (the stored_len prefix, where there is one,
 * already stripped).  HASH must point at GRUB_GHOST_FASTLZ_HASH_SIZE
 * entries and is scratch space.
 */
grub_err_t
grub_ghost_decode (grub_uint8_t comp, grub_int32_t *hash,
		   const grub_uint8_t *src, grub_size_t clen,
		   grub_uint8_t *dst, grub_size_t dstcap, grub_size_t *outlen);

#endif /* ! GRUB_GHOST_HEADER */
