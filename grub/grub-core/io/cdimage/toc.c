/* toc.c - cdrdao toc file parser */
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
 * Unlike a cue sheet, a toc file describes the disc as a sequence of
 * sub-tracks laid end to end: every TRACK is built from statements that
 * each contribute a run of sectors, either read from a file (DATAFILE,
 * FILE, AUDIOFILE) or generated (PREGAP, SILENCE, ZERO).  Keeping a
 * running disc address and emitting one image track per file-backed
 * statement reproduces that layout exactly, with the generated runs
 * left as holes that read back as zeros.
 *
 * A file offset may be given explicitly as `#<bytes>'; when it is not,
 * consecutive statements naming the same file continue where the
 * previous one stopped, which is how cdrdao writes multi track images
 * into a single data file.
 *
 * CATALOG, ISRC, CD_TEXT blocks, COPY/PRE_EMPHASIS flags and the
 * channel mode statements carry nothing we can use and are skipped.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>

#include "cdimage.h"

struct toc_mode
{
	const char *name;
	grub_uint32_t sector_size;
	grub_uint32_t data_offset;
	int mode;
};

static const struct toc_mode toc_modes[] =
{
	{ "AUDIO",	   CD_FRAMESIZE_RAW,	0,	CDIMAGE_MODE_AUDIO },
	{ "MODE1",	   CD_FRAMESIZE,	0,	CDIMAGE_MODE_1 },
	{ "MODE1_RAW",	   CD_FRAMESIZE_RAW,	CD_M1_DATA_OFFSET, CDIMAGE_MODE_1 },
	{ "MODE2",	   CD_FRAMESIZE_M2,	CD_SUBHEADER_SIZE, CDIMAGE_MODE_2 },
	{ "MODE2_FORM1",   CD_FRAMESIZE,	0,	CDIMAGE_MODE_2 },
	{ "MODE2_FORM2",   CD_FRAMESIZE_FORM2,	0,	CDIMAGE_MODE_2 },
	{ "MODE2_FORM_MIX", CD_FRAMESIZE_M2,	CD_SUBHEADER_SIZE, CDIMAGE_MODE_2 },
	{ "MODE2_RAW",	   CD_FRAMESIZE_RAW,	CD_M2_DATA_OFFSET, CDIMAGE_MODE_2 }
};

/* Per data file we remember where the previous statement stopped, so a
   statement without an explicit `#offset' continues from there.  */
struct toc_cursor
{
	grub_file_t src;
	grub_uint64_t offset;
};

struct toc_state
{
	struct cdimage *img;
	struct toc_cursor cursors[CDIMAGE_FILES_MAX];
	unsigned ncursors;
	/* Current track template.  */
	const struct toc_mode *mode;
	grub_uint32_t sector_size;
	/* Running disc address, in sectors.  */
	grub_uint32_t lsn;
};

static const struct toc_mode *
toc_find_mode (const char *name)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE (toc_modes); i++)
		if (grub_strcasecmp (name, toc_modes[i].name) == 0)
			return &toc_modes[i];
	return NULL;
}

static struct toc_cursor *
toc_cursor_for (struct toc_state *st, grub_file_t src)
{
	unsigned i;

	for (i = 0; i < st->ncursors; i++)
		if (st->cursors[i].src == src)
			return &st->cursors[i];
	if (st->ncursors >= ARRAY_SIZE (st->cursors))
		return NULL;
	st->cursors[st->ncursors].src = src;
	st->cursors[st->ncursors].offset = 0;
	return &st->cursors[st->ncursors++];
}

/* Parse `#<bytes>' into a byte offset.  */
static int
toc_byte_offset (const char *field, grub_uint64_t *offset)
{
	const char *end;
	unsigned long long bytes;

	if (field[0] != '#')
		return 0;
	bytes = grub_strtoull (field + 1, &end, 10);
	if (grub_errno || *end)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	*offset = bytes;
	return 1;
}

/* DATAFILE "<name>" [#<offset>] [<length>]
   FILE|AUDIOFILE "<name>" [#<offset>|<start>] [<length>]

   The difference matters: a bare MSF after DATAFILE is the length, but
   after AUDIOFILE it is the start position inside the file.  */
static grub_err_t
toc_file_statement (struct toc_state *st, char **cursor, int is_data)
{
	struct cdimage_track track;
	struct toc_cursor *pos;
	grub_file_t src;
	char *field;
	grub_uint64_t offset;
	grub_uint32_t lsn;
	grub_uint32_t nsectors = 0;

	field = grub_cdimage_field (cursor);
	if (!field || !*field)
		return grub_error (GRUB_ERR_BAD_FS, "toc file statement without a name");
	src = grub_cdimage_open_member (st->img, field);
	if (!src)
		return grub_errno ? grub_errno : GRUB_ERR_FILE_NOT_FOUND;

	pos = toc_cursor_for (st, src);
	if (!pos)
		return grub_error (GRUB_ERR_BAD_FS, "too many data files in toc file");
	offset = pos->offset;

	field = grub_cdimage_field (cursor);
	if (field && toc_byte_offset (field, &offset))
		field = grub_cdimage_field (cursor);
	else if (field && !is_data && grub_cdimage_msf_to_lsn (field, &lsn))
	{
		offset = (grub_uint64_t) lsn * st->sector_size;
		field = grub_cdimage_field (cursor);
	}
	if (field && grub_cdimage_msf_to_lsn (field, &lsn))
		nsectors = lsn;

	if (!nsectors)
	{
		/* No length: the statement runs to the end of the file.  */
		if (src->size == GRUB_FILE_SIZE_UNKNOWN || offset >= src->size)
			return grub_error (GRUB_ERR_BAD_FS, "toc file statement past end of `%s'", src->name);
		nsectors = (grub_uint32_t) ((src->size - offset) / st->sector_size);
	}

	grub_memset (&track, 0, sizeof (track));
	track.start_lsn = st->lsn;
	track.nsectors = nsectors;
	track.sector_size = st->sector_size;
	track.data_offset = st->mode->data_offset;
	track.mode = st->mode->mode;
	track.src = src;
	track.src_offset = offset;

	st->lsn += nsectors;
	pos->offset = offset + (grub_uint64_t) nsectors * st->sector_size;

	return grub_cdimage_add_track (st->img, &track);
}

grub_err_t
grub_cdimage_parse_toc (struct cdimage *img)
{
	struct toc_state *st = NULL;
	char *text = NULL;
	char *pos;
	char *line;
	unsigned depth = 0;
	int seen_track = 0;
	grub_err_t err = GRUB_ERR_NONE;

	text = grub_cdimage_read_text (img->container);
	if (!text)
		return grub_errno;

	st = grub_zalloc (sizeof (*st));
	if (!st)
	{
		err = grub_errno;
		goto fail;
	}
	st->img = img;

	pos = text;
	while ((line = grub_cdimage_next_line (&pos)) != NULL)
	{
		char *cursor = line;
		char *keyword;
		char *comment;
		char *p;
		unsigned was_inside = depth;

		comment = grub_strstr (line, "//");
		if (comment)
			*comment = '\0';

		/* Braces only ever appear in CD_TEXT blocks, which nest.  */
		for (p = line; *p; p++)
		{
			if (*p == '{')
				depth++;
			else if (*p == '}' && depth)
				depth--;
		}
		if (was_inside || grub_strchr (line, '{'))
			continue;

		keyword = grub_cdimage_field (&cursor);
		if (!keyword)
			continue;

		if (grub_strcasecmp (keyword, "TRACK") == 0)
		{
			char *field = grub_cdimage_field (&cursor);

			if (!field)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "toc TRACK without a mode");
				goto fail;
			}
			st->mode = toc_find_mode (field);
			if (!st->mode)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "unsupported toc track mode `%s'", field);
				goto fail;
			}
			st->sector_size = st->mode->sector_size;

			/* An optional subchannel mode appends 96 bytes.  */
			field = grub_cdimage_field (&cursor);
			if (field && (grub_strcasecmp (field, "RW") == 0 || grub_strcasecmp (field, "RW_RAW") == 0))
				st->sector_size += CD_FRAMESIZE_SUB - CD_FRAMESIZE_RAW;
			seen_track = 1;
		}
		else if (!seen_track)
		{
			/* Global section: CATALOG, CD_DA, CD_ROM, CD_ROM_XA.  */
			continue;
		}
		else if (grub_strcasecmp (keyword, "DATAFILE") == 0
			|| grub_strcasecmp (keyword, "FILE") == 0
			|| grub_strcasecmp (keyword, "AUDIOFILE") == 0)
		{
			err = toc_file_statement (st, &cursor, grub_strcasecmp (keyword, "DATAFILE") == 0);
			if (err != GRUB_ERR_NONE)
				goto fail;
		}
		else if (grub_strcasecmp (keyword, "PREGAP") == 0
			|| grub_strcasecmp (keyword, "SILENCE") == 0
			|| grub_strcasecmp (keyword, "ZERO") == 0)
		{
			char *field;
			grub_uint32_t lsn = 0;

			/* ZERO may be preceded by data and subchannel modes.  */
			while ((field = grub_cdimage_field (&cursor)) != NULL)
				if (grub_cdimage_msf_to_lsn (field, &lsn))
					break;
			st->lsn += lsn;
		}
	}

	if (!img->ntracks)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "no track in toc file");
		goto fail;
	}

fail:
	grub_free (st);
	grub_free (text);
	return err;
}
