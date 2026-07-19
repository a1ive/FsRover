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
 * Replaces grub-core\kern\mm.c: forward the grub allocator to the CRT
 * heap.  grub_memalign is intentionally missing -- its only caller is
 * the dynamic module loader, which Rover does not build.
 */

#include <stdlib.h>

#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/err.h>
#include <grub/types.h>

void *
grub_malloc (grub_size_t size)
{
	void *ptr;

	ptr = malloc (size ? size : 1);
	if (!ptr)
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
	return ptr;
}

void *
grub_calloc (grub_size_t nmemb, grub_size_t size)
{
	void *ptr;

	ptr = calloc (nmemb ? nmemb : 1, size ? size : 1);
	if (!ptr)
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
	return ptr;
}

void *
grub_zalloc (grub_size_t size)
{
	return grub_calloc (1, size);
}

void *
grub_realloc (void *ptr, grub_size_t size)
{
	void *ret;

	ret = realloc (ptr, size ? size : 1);
	if (!ret)
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
	return ret;
}

void
grub_free (void *ptr)
{
	free (ptr);
}
