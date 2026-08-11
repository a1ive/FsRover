/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010 Free Software Foundation, Inc.
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
 */

#ifndef GRUB_DEFLATE_HEADER
#define GRUB_DEFLATE_HEADER 1

#include <grub/file.h>

/* Wraps IO in a decompressor for the bare zlib stream it holds.  SIZE is
   the uncompressed length; the format does not store one.  Returns 0
   without closing IO when the stream does not start with a zlib header.  */
grub_file_t
grub_zlibio_open (grub_file_t io, grub_off_t size);

grub_ssize_t
grub_zlib_decompress (char *inbuf, grub_size_t insize, grub_off_t off,
		      char *outbuf, grub_size_t outsize);

grub_ssize_t
grub_deflate_decompress (char *inbuf, grub_size_t insize, grub_off_t off,
			 char *outbuf, grub_size_t outsize);

#endif
