/* dgcomp.h -- payload codecs used by DiskGenius PMF/PMFX backup images */
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

#ifndef GRUB_DGCOMP_HEADER
#define GRUB_DGCOMP_HEADER	1

#include <grub/types.h>
#include <grub/err.h>

/* Expand one stored block of a DiskGenius image into OUT, which must be
   exactly as long as the block's plaintext.  The payload is a zlib
   stream, a stream of the LZ77 variant DiskGenius uses for its faster
   compression setting, or the plaintext itself when IN_LEN equals
   OUT_LEN.  */
grub_err_t
grub_dgcomp_block (const grub_uint8_t *in, grub_size_t in_len,
		   grub_uint8_t *out, grub_size_t out_len);

/* The LZ77 variant on its own.  */
grub_err_t
grub_dgcomp_lz (const grub_uint8_t *in, grub_size_t in_len,
		grub_uint8_t *out, grub_size_t out_len);

#endif
