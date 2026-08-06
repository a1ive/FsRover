/* cue.c - CDRWIN cue sheet parser */
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
 * A cue sheet is a list of FILE blocks, each holding one or more TRACKs
 * whose INDEX timestamps are relative to the start of that file.  The
 * disc address of a track is therefore the file's own base plus its
 * INDEX 01 time, where the base of the first file is chosen so that
 * track 1's INDEX 01 lands on LSN 0 (an INDEX 00 before it is the
 * pregap and lives outside the addressable area).  PREGAP and POSTGAP
 * describe sectors that were never written to the file, so they push
 * every later track further down the disc.
 *
 * CATALOG, ISRC, FLAGS, CD-TEXT and REM lines carry no information we
 * can use and are skipped.  WAVE/MP3/AIFF FILE types are treated as
 * audio, that is, as a hole in the address space.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>

#include "cdimage.h"

struct cue_entry
{
	grub_file_t src;
	grub_uint32_t idx0, idx1;
	int has_idx0;
	grub_uint32_t pregap, postgap;
	grub_uint32_t sector_size, data_offset;
	int mode;
};

struct cue_mode
{
	const char *name;
	grub_uint32_t sector_size;
	grub_uint32_t data_offset;
	int mode;
};

static const struct cue_mode cue_modes[] =
{
	{ "AUDIO",	CD_FRAMESIZE_RAW,	0,	CDIMAGE_MODE_AUDIO },
	{ "CDG",	CD_FRAMESIZE_SUB,	0,	CDIMAGE_MODE_AUDIO },
	{ "MODE1/2048",	CD_FRAMESIZE,		0,	CDIMAGE_MODE_1 },
	{ "MODE1/2352",	CD_FRAMESIZE_RAW,	CD_M1_DATA_OFFSET, CDIMAGE_MODE_1 },
	{ "MODE1/2448",	CD_FRAMESIZE_SUB,	CD_M1_DATA_OFFSET, CDIMAGE_MODE_1 },
	{ "MODE2/2048",	CD_FRAMESIZE,		0,	CDIMAGE_MODE_2 },
	{ "MODE2/2324",	CD_FRAMESIZE_FORM2,	0,	CDIMAGE_MODE_2 },
	{ "MODE2/2336",	CD_FRAMESIZE_M2,	CD_SUBHEADER_SIZE, CDIMAGE_MODE_2 },
	{ "MODE2/2352",	CD_FRAMESIZE_RAW,	CD_M2_DATA_OFFSET, CDIMAGE_MODE_2 },
	{ "MODE2/2448",	CD_FRAMESIZE_SUB,	CD_M2_DATA_OFFSET, CDIMAGE_MODE_2 },
	{ "CDI/2336",	CD_FRAMESIZE_M2,	CD_SUBHEADER_SIZE, CDIMAGE_MODE_2 },
	{ "CDI/2352",	CD_FRAMESIZE_RAW,	CD_M2_DATA_OFFSET, CDIMAGE_MODE_2 }
};

static const struct cue_mode *
cue_find_mode (const char *name)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE (cue_modes); i++)
		if (grub_strcasecmp (name, cue_modes[i].name) == 0)
			return &cue_modes[i];
	return NULL;
}

/* Turn the collected entries into absolute disc tracks.  */
static grub_err_t
cue_lay_out (struct cdimage *img, struct cue_entry *ent, unsigned n)
{
	grub_int64_t base = 0, shift = 0;
	grub_file_t cur = NULL;
	unsigned i;

	for (i = 0; i < n; i++)
	{
		struct cue_entry *e = &ent[i];
		struct cdimage_track track;
		grub_uint64_t file_sectors;
		grub_uint32_t end;
		grub_int64_t start;
		grub_err_t err;

		if (e->src != cur)
		{
			if (cur)
				base += (grub_int64_t) (cur->size / ent[i - 1].sector_size);
			else
				base = -(grub_int64_t) e->idx1;
			cur = e->src;
		}

		shift += e->pregap;
		start = base + shift + e->idx1;
		if (start < 0)
			start = 0;

		file_sectors = e->src->size / e->sector_size;
		if (i + 1 < n && ent[i + 1].src == e->src)
			end = ent[i + 1].has_idx0 ? ent[i + 1].idx0 : ent[i + 1].idx1;
		else
			end = (grub_uint32_t) file_sectors;

		grub_memset (&track, 0, sizeof (track));
		track.start_lsn = (grub_uint32_t) start;
		track.nsectors = end > e->idx1 ? end - e->idx1 : 0;
		track.sector_size = e->sector_size;
		track.data_offset = e->data_offset;
		track.mode = e->mode;
		track.src = e->src;
		track.src_offset = (grub_uint64_t) e->idx1 * e->sector_size;

		err = grub_cdimage_add_track (img, &track);
		if (err != GRUB_ERR_NONE)
			return err;

		shift += e->postgap;
	}

	return GRUB_ERR_NONE;
}

grub_err_t
grub_cdimage_parse_cue (struct cdimage *img)
{
	char *text = NULL;
	char *pos;
	char *line;
	struct cue_entry *ent = NULL;
	unsigned n = 0;
	grub_file_t src = NULL;
	int in_track = 0;
	grub_err_t err = GRUB_ERR_NONE;

	text = grub_cdimage_read_text (img->container);
	if (!text)
		return grub_errno;

	ent = grub_calloc (CD_MAX_TRACKS, sizeof (ent[0]));
	if (!ent)
	{
		err = grub_errno;
		goto fail;
	}

	pos = text;
	while ((line = grub_cdimage_next_line (&pos)) != NULL)
	{
		char *cursor = line;
		char *keyword = grub_cdimage_field (&cursor);
		char *field;

		if (!keyword)
			continue;

		if (grub_strcasecmp (keyword, "FILE") == 0)
		{
			field = grub_cdimage_field (&cursor);
			if (!field || !*field)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "cue sheet FILE without a name");
				goto fail;
			}
			src = grub_cdimage_open_member (img, field);
			if (!src)
			{
				err = grub_errno ? grub_errno : GRUB_ERR_FILE_NOT_FOUND;
				goto fail;
			}
			in_track = 0;
		}
		else if (grub_strcasecmp (keyword, "TRACK") == 0)
		{
			const struct cue_mode *mode;

			if (!src)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "cue sheet TRACK before FILE");
				goto fail;
			}
			/* Skip the track number.  */
			grub_cdimage_field (&cursor);
			field = grub_cdimage_field (&cursor);
			if (!field)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "cue sheet TRACK without a mode");
				goto fail;
			}
			mode = cue_find_mode (field);
			if (!mode)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "unsupported cue track mode `%s'", field);
				goto fail;
			}
			if (n >= CD_MAX_TRACKS)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "too many tracks in cue sheet");
				goto fail;
			}

			ent[n].src = src;
			ent[n].sector_size = mode->sector_size;
			ent[n].data_offset = mode->data_offset;
			ent[n].mode = mode->mode;
			n++;
			in_track = 1;
		}
		else if (!in_track)
			continue;
		else if (grub_strcasecmp (keyword, "INDEX") == 0)
		{
			unsigned long index;
			grub_uint32_t lsn;
			const char *end;

			field = grub_cdimage_field (&cursor);
			if (!field)
				continue;
			index = grub_strtoul (field, &end, 10);
			if (grub_errno || *end)
			{
				grub_errno = GRUB_ERR_NONE;
				continue;
			}
			field = grub_cdimage_field (&cursor);
			if (!field || !grub_cdimage_msf_to_lsn (field, &lsn))
				continue;

			if (index == 0)
			{
				ent[n - 1].idx0 = lsn;
				ent[n - 1].has_idx0 = 1;
			}
			else if (index == 1)
				ent[n - 1].idx1 = lsn;
		}
		else if (grub_strcasecmp (keyword, "PREGAP") == 0)
		{
			grub_uint32_t lsn;

			field = grub_cdimage_field (&cursor);
			if (field && grub_cdimage_msf_to_lsn (field, &lsn))
				ent[n - 1].pregap = lsn;
		}
		else if (grub_strcasecmp (keyword, "POSTGAP") == 0)
		{
			grub_uint32_t lsn;

			field = grub_cdimage_field (&cursor);
			if (field && grub_cdimage_msf_to_lsn (field, &lsn))
				ent[n - 1].postgap = lsn;
		}
	}

	if (!n)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "no track in cue sheet");
		goto fail;
	}

	err = cue_lay_out (img, ent, n);

fail:
	grub_free (ent);
	grub_free (text);
	return err;
}
