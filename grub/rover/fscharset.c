/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#if defined(_WIN32)
#include <windows.h>
#else
#include <errno.h>
#include <iconv.h>
#include <stdint.h>
#endif

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
#if defined(_WIN32)
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
#else
	const char *charset;
	iconv_t converter;
	char *utf8;
	char *out;
	char *in;
	size_t input_left;
	size_t output_left;
	size_t capacity;

	if (size == 0)
		return grub_strdup ("");
	if (encoding == GRUB_FS_CHAR_ENCODING_UTF8)
		return grub_strndup (src, size);
	switch (encoding)
	{
	case GRUB_FS_CHAR_ENCODING_GBK:
		charset = "GBK";
		break;
	case GRUB_FS_CHAR_ENCODING_BIG5:
		charset = "BIG5";
		break;
	case GRUB_FS_CHAR_ENCODING_SHIFT_JIS:
		charset = "SHIFT-JIS";
		break;
	case GRUB_FS_CHAR_ENCODING_EUC_KR:
		charset = "EUC-KR";
		break;
	default:
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
			"unsupported filesystem name encoding"), NULL;
	}
	if (size > (SIZE_MAX - 1) / 4)
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
			"filesystem name is too long"), NULL;
	capacity = size * 4 + 1;
	utf8 = grub_malloc (capacity);
	if (!utf8)
		return NULL;
	converter = iconv_open ("UTF-8", charset);
	if (converter == (iconv_t) -1)
	{
		grub_free (utf8);
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
			"filesystem name encoding is unavailable"), NULL;
	}
	in = (char *) src;
	out = utf8;
	input_left = size;
	output_left = capacity - 1;
	errno = 0;
	if (iconv (converter, &in, &input_left, &out, &output_left)
		== (size_t) -1 || input_left != 0)
	{
		iconv_close (converter);
		grub_free (utf8);
		return grub_error (GRUB_ERR_BAD_FILENAME,
			"invalid filesystem name encoding"), NULL;
	}
	*out = '\0';
	iconv_close (converter);
	return utf8;
#endif
}
