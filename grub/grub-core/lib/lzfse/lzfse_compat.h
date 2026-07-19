/*
 *  Rover -- GRUB 2 filesystem browser for Windows
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
 * Replaces the <linux/*.h> includes of the linux-apfs-rw port of the
 * lzfse/lzvn decoders so they build with MSVC.  Allocation goes through
 * grub_malloc so the decoders follow grub's heap.
 */

#ifndef LZFSE_COMPAT_H
#define LZFSE_COMPAT_H	1

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <grub/mm.h>

#ifdef _MSC_VER

#include <intrin.h>

/* Callers never pass 0 (undefined for __builtin_clz as well).  */
static __forceinline int
lzfse_clz32 (uint32_t x)
{
	unsigned long index;
	_BitScanReverse (&index, x);
	return 31 - (int) index;
}

#define __builtin_clz(x)	lzfse_clz32 (x)
#define __builtin_expect(expr, val)	(expr)
#define __builtin_constant_p(expr)	0
#define __always_inline	__forceinline

/*
 * lzfse_compressed_block_header_v2 is declared __packed but has no
 * internal padding anyway (4+4+24 bytes, then a byte array), so empty
 * definitions keep the on-disk layout.
 */
#define __packed
#define __aligned(x)

#else /* ! _MSC_VER */

#ifndef __always_inline
#define __always_inline	inline __attribute__ ((always_inline))
#endif

#endif /* ! _MSC_VER */

#define kmalloc(size, flags)	grub_malloc (size)
#define kfree(ptr)	grub_free (ptr)
#define GFP_KERNEL	0

#endif /* ! LZFSE_COMPAT_H */
