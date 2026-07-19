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
 * Minimal GRUB config.h for building grub-core with MSVC.
 * Force-included into every translation unit of grub.lib
 * (vcxproj <ForcedIncludeFiles>).
 */

#ifndef ROVER_GRUB_CONFIG_H
#define ROVER_GRUB_CONFIG_H	1

#if defined(_MSC_VER)
/* GNU extensions used throughout grub that MSVC does not know.  */
#define __attribute__(x)
#define __attribute(x)

/* "unary minus operator applied to unsigned type" */
#pragma warning(disable: 4146)
/* "conversion, possible loss of data" */
#pragma warning(disable: 4244)
#pragma warning(disable: 4267)
/* "result of 32-bit shift implicitly converted to 64 bits" */
#pragma warning(disable: 4334)
/* "function must return a value" (noreturn is expanded away) */
#pragma warning(disable: 4716)

/*
 * grub_log2ull() (include/grub/misc.h) uses __builtin_clzll, which MSVC
 * does not provide.  Map it onto the bit-scan intrinsics.  Callers never
 * pass 0 (undefined for __builtin_clzll too).
 */
#if defined(_M_X64) || defined(_M_ARM64)
unsigned char _BitScanReverse64 (unsigned long *_Index, unsigned __int64 _Mask);
#pragma intrinsic(_BitScanReverse64)
static __forceinline int
__rover_clzll (unsigned __int64 x)
{
	unsigned long i;
	_BitScanReverse64 (&i, x);
	return 63 - (int) i;
}
#else
unsigned char _BitScanReverse (unsigned long *_Index, unsigned long _Mask);
#pragma intrinsic(_BitScanReverse)
static __forceinline int
__rover_clzll (unsigned __int64 x)
{
	unsigned long i;
	unsigned long hi = (unsigned long) (x >> 32);
	if (hi != 0)
	{
		_BitScanReverse (&i, hi);
		return 31 - (int) i;
	}
	_BitScanReverse (&i, (unsigned long) x);
	return 63 - (int) i;
}
#endif
#define __builtin_clzll(x) __rover_clzll (x)
#endif

#if defined(_M_X64) || defined(__x86_64__)
#define GRUB_TARGET_CPU "x86_64"
#elif defined(_M_IX86) || defined(__i386__)
#define GRUB_TARGET_CPU "i386"
#elif defined(_M_ARM64) || defined(__aarch64__)
#define GRUB_TARGET_CPU "arm64"
#else
#error "unsupported architecture"
#endif

#define GRUB_PLATFORM "windows"

/*
 * GRUB_KERNEL selects the GRUB_MOD_INIT(x) flavour that emits a public
 * grub_x_init/grub_x_fini pair; rover\init.c calls them all since the
 * dynamic module loader (kern\dl.c) is not built.
 */
#define GRUB_KERNEL	1

#define GRUB_FILE	__FILE__
#define PACKAGE_STRING	"GRUB 2.15"

#if !defined(__CHAR_BIT__)
#define __CHAR_BIT__	8
#endif

#endif /* ! ROVER_GRUB_CONFIG_H */
