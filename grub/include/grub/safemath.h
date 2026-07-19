/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020  Free Software Foundation, Inc.
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
 *
 *  Arithmetic operations that protect against overflow.
 */

#ifndef GRUB_SAFEMATH_H
#define GRUB_SAFEMATH_H 1

#include <grub/compiler.h>

/* These appear in gcc 5.1 and clang 8.0. */
#if GNUC_PREREQ(5, 1) || CLANG_PREREQ(8, 0)

#define grub_add(a, b, res)	__builtin_add_overflow(a, b, res)
#define grub_sub(a, b, res)	__builtin_sub_overflow(a, b, res)
#define grub_mul(a, b, res)	__builtin_mul_overflow(a, b, res)

#define grub_cast(a, res)	grub_add ((a), 0, (res))

/*
 * It's caller's responsibility to check "align" does not equal 0 and
 * is power of 2.
 */
#define ALIGN_UP_OVF(v, align, res) 			\
({							\
  bool __failed;					\
  typeof(v) __a = ((typeof(v))(align) - 1);		\
							\
  __failed = grub_add (v, __a, res);			\
  if (__failed == false)				\
    *(res) &= ~__a;					\
  __failed;						\
})

#elif defined(_MSC_VER)

#define ENABLE_INTSAFE_SIGNED_FUNCTIONS
#include <intsafe.h>
#include <stdbool.h>
#include <intrin.h>

/*
 * Like __builtin_*_overflow these return true (nonzero) ON OVERFLOW,
 * hence FAILED() around the intsafe.h calls.
 */
#define grub_add(a, b, res) \
FAILED(_Generic(*(res), \
INT:       IntAdd, \
UINT:      UIntAdd, \
USHORT:    UShortAdd, \
ULONGLONG: ULongLongAdd \
)((a), (b), (res)))

#define grub_sub(a, b, res) \
FAILED(_Generic(*(res), \
INT:       IntSub, \
UINT:      UIntSub, \
USHORT:    UShortSub, \
ULONGLONG: ULongLongSub \
)((a), (b), (res)))

#define grub_mul(a, b, res) \
FAILED(_Generic(*(res), \
INT:       IntMult, \
UINT:      UIntMult, \
USHORT:    UShortMult, \
ULONGLONG: ULongLongMult \
)((a), (b), (res)))

#define grub_cast(a, res)	grub_add ((a), 0, (res))

/* Only used by EROFS (with grub_uint64_t operands) for now.  */
static __inline bool ALIGN_UP_OVF(grub_uint64_t v, grub_uint64_t align,
				  grub_uint64_t* res)
{
  bool __failed;
  grub_uint64_t __a = align - 1;

  __failed = grub_add (v, __a, res);
  if (__failed == false)
    *(res) &= ~__a;
  return __failed;
}

#else
#error gcc 5.1 or newer or clang 8.0 or newer is required
#endif

#endif /* GRUB_SAFEMATH_H */
