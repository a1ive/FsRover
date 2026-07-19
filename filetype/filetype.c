/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * libmagic glue.  The magic database is the compiled magic.mgc,
 * zstd-compressed and linked into FsRover.exe as an RCDATA resource
 * (magic\magic.zst); it is inflated on first use with the zstd
 * decoder that grub.lib already carries for zstdio, so this library
 * ships no zstd copy of its own -- the executable resolves ZSTD_*.
 *
 * Everything here runs on the single backend thread (grub's thread),
 * so no locking: a magic_t is not thread-safe anyway.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdlib.h>

#include <zstd.h>

#include "filetype.h"
#include "resource.h"

#include "config.h"	/* msvc shim: ssize_t etc. for magic.h */
#include "magic.h"

/* magic.c uses PathRemoveFileSpecA in its default-path lookup.  */
#pragma comment (lib, "shlwapi.lib")

static magic_t g_magic;
static void *g_magic_mgc;	/* magic_load_buffers() keeps pointers into the buffer: freed only after close */
static int g_magic_failed;	/* do not retry a failed load */

/* Inflate the RCDATA resource into a malloc'd buffer.  */
static void *
load_magic_zst (size_t *out_size)
{
	HMODULE module = GetModuleHandleW (NULL);
	HRSRC found;
	HGLOBAL loaded;
	const void *data;
	DWORD size;
	unsigned long long content;
	void *out;

	found = FindResourceW (module,
			       MAKEINTRESOURCEW (IDR_FILETYPE_MAGIC_ZST),
			       (LPCWSTR) RT_RCDATA);
	if (!found)
		return NULL;
	size = SizeofResource (module, found);
	loaded = LoadResource (module, found);
	if (!size || !loaded)
		return NULL;
	data = LockResource (loaded);
	if (!data)
		return NULL;

	content = ZSTD_getFrameContentSize (data, size);
	if (content == ZSTD_CONTENTSIZE_ERROR
	    || content == ZSTD_CONTENTSIZE_UNKNOWN
	    || content == 0 || content != (size_t) content)
		return NULL;
	out = malloc ((size_t) content);
	if (!out)
		return NULL;
	if (ZSTD_decompress (out, (size_t) content, data, size)
	    != (size_t) content)
	{
		free (out);
		return NULL;
	}
	*out_size = (size_t) content;
	return out;
}

static magic_t
open_magic (void)
{
	magic_t magic;
	void *bufs[1];
	size_t sizes[1];

	if (g_magic || g_magic_failed)
		return g_magic;
	g_magic_failed = 1;

	magic = magic_open (MAGIC_NONE);
	if (!magic)
		return NULL;
	g_magic_mgc = load_magic_zst (&sizes[0]);
	if (!g_magic_mgc)
		goto fail;
	bufs[0] = g_magic_mgc;
	if (magic_load_buffers (magic, bufs, sizes, 1) == -1)
		goto fail;

	g_magic = magic;
	g_magic_failed = 0;
	return g_magic;

fail:
	magic_close (magic);
	free (g_magic_mgc);
	g_magic_mgc = NULL;
	return NULL;
}

const char *
filetype_describe (const void *data, size_t size)
{
	magic_t magic = open_magic ();

	if (!magic)
		return NULL;
	return magic_buffer (magic, data, size);
}

void
filetype_shutdown (void)
{
	if (g_magic)
	{
		magic_close (g_magic);
		g_magic = NULL;
	}
	free (g_magic_mgc);
	g_magic_mgc = NULL;
	g_magic_failed = 0;
}
