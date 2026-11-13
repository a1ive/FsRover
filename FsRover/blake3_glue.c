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

/* BLAKE3 for the properties dialog's hash calculator.  blake3/ is the
   portable single-file build from 7-Zip-zstd (C/hashes), kept as is.  */

#include <stdlib.h>

#include "blake3_glue.h"
#include "blake3/blake3.h"

struct rover_blake3
{
	blake3_hasher hasher;
};

rover_blake3 *
rover_blake3_new (void)
{
	rover_blake3 *b = malloc (sizeof (*b));

	if (b)
		blake3_hasher_init (&b->hasher);
	return b;
}

void
rover_blake3_update (rover_blake3 *b, const void *data, size_t len)
{
	blake3_hasher_update (&b->hasher, data, len);
}

void
rover_blake3_final (const rover_blake3 *b, unsigned char out[ROVER_BLAKE3_LEN])
{
	blake3_hasher_finalize (&b->hasher, out, ROVER_BLAKE3_LEN);
}

void
rover_blake3_free (rover_blake3 *b)
{
	free (b);
}
