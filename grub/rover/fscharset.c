/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <windows.h>

#include <limits.h>

#include <grub/err.h>
#include <grub/misc.h>
#include <grub/mm.h>

#include "fscharset.h"

grub_uint32_t grub_fs_char_encoding = GRUB_FS_CHAR_ENCODING_UTF8;

char *
grub_fs_bytes_to_utf8 (const char *src, grub_size_t size,
	grub_uint32_t encoding)
{
	wchar_t *wide = NULL;
	char *utf8 = NULL;
	int wide_size;
	int utf8_size;

	if (size == 0)
		return grub_strdup ("");
	/* Preserve the historical UTF-8 path byte-for-byte, including malformed
	   input that GRUB drivers previously passed through unchanged. */
	if (encoding == GRUB_FS_CHAR_ENCODING_UTF8)
		return grub_strndup (src, size);
	if (size > INT_MAX)
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "filesystem name is too long");
		goto fail;
	}

	wide_size = MultiByteToWideChar ((UINT) encoding, 0, src, (int) size,
		NULL, 0);
	if (wide_size <= 0)
	{
		grub_error (GRUB_ERR_BAD_FILENAME, "invalid filesystem name encoding");
		goto fail;
	}
	wide = grub_malloc ((grub_size_t) wide_size * sizeof (*wide));
	if (!wide)
		goto fail;
	if (MultiByteToWideChar ((UINT) encoding, 0, src, (int) size, wide,
		wide_size) != wide_size)
	{
		grub_error (GRUB_ERR_BAD_FILENAME, "invalid filesystem name encoding");
		goto fail;
	}

	utf8_size = WideCharToMultiByte (CP_UTF8, 0, wide, wide_size, NULL, 0,
		NULL, NULL);
	if (utf8_size <= 0)
	{
		grub_error (GRUB_ERR_BAD_FILENAME, "cannot convert filesystem name");
		goto fail;
	}
	utf8 = grub_malloc ((grub_size_t) utf8_size + 1);
	if (!utf8)
		goto fail;
	if (WideCharToMultiByte (CP_UTF8, 0, wide, wide_size, utf8, utf8_size,
		NULL, NULL) != utf8_size)
	{
		grub_error (GRUB_ERR_BAD_FILENAME, "cannot convert filesystem name");
		goto fail;
	}
	utf8[utf8_size] = '\0';
	grub_free (wide);
	return utf8;

fail:
	grub_free (wide);
	grub_free (utf8);
	return NULL;
}
