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

/* Opaque BLAKE3 hasher for C++ callers.  blake3/blake3.h is not
   C++-friendly to include: it disables C4244 without a push/pop and
   defines INLINE/IS_X86 macros, static helpers and PARENT/ROOT
   enumerators, so only blake3_glue.c sees it.  */

#ifndef FSROVER_BLAKE3_GLUE_H
#define FSROVER_BLAKE3_GLUE_H	1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROVER_BLAKE3_LEN	32

typedef struct rover_blake3 rover_blake3;

/* Null on allocation failure.  */
rover_blake3 *rover_blake3_new (void);
void rover_blake3_update (rover_blake3 *b, const void *data, size_t len);
void rover_blake3_final (const rover_blake3 *b, unsigned char out[ROVER_BLAKE3_LEN]);
void rover_blake3_free (rover_blake3 *b);

#ifdef __cplusplus
}
#endif

#endif
