/* ccd.c - CloneCD image parser */
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
 * A .ccd file is an INI style dump of the disc's table of contents: one
 * [Entry N] section per TOC entry, where Point 0x01..0x63 is a track and
 * PLBA its start address, Point 0xa2 is the lead-out and thus the end of
 * the disc.  [TRACK N] sections add the recording mode.  The sectors
 * themselves live in a sibling .img holding one contiguous raw run of
 * the whole disc, so a disc address maps straight onto a file offset --
 * anchored on the address the first stored sector claims in its own
 * header, because CloneCD may or may not have written out track 1's
 * pregap.
 *
 * The .sub sidecar (96 bytes of subchannel per sector) is not read; it
 * holds nothing a filesystem needs.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>

#include "cdimage.h"

#define CCD_POINT_LEADOUT	0xa2

struct ccd_track
{
	int seen;
	int mode;
	grub_uint32_t start;
};

struct ccd_state
{
	struct ccd_track tracks[CD_MAX_TRACKS + 1];
	grub_uint32_t leadout;
	int have_leadout;
	/* Pending [Entry N] section.  */
	long point;
	long plba;
	int in_entry;
	/* Current [TRACK N] section, 0 when outside one.  */
	unsigned track;
};

/* Trim leading and trailing blanks in place.  */
static char *
ccd_trim (char *s)
{
	char *end;

	while (*s == ' ' || *s == '\t')
		s++;
	end = s + grub_strlen (s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	*end = '\0';
	return s;
}

static int
ccd_number (const char *value, long *out)
{
	const char *end;
	long v = grub_strtol (value, &end, 0);

	if (grub_errno || end == value || *end)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	*out = v;
	return 1;
}

static void
ccd_flush_entry (struct ccd_state *st)
{
	if (!st->in_entry)
		return;
	st->in_entry = 0;

	if (st->point == CCD_POINT_LEADOUT)
	{
		if (st->plba > 0)
		{
			st->leadout = (grub_uint32_t) st->plba;
			st->have_leadout = 1;
		}
	}
	else if (st->point >= 1 && st->point <= CD_MAX_TRACKS && st->plba >= 0)
	{
		struct ccd_track *track = &st->tracks[st->point];

		track->seen = 1;
		track->start = (grub_uint32_t) st->plba;
	}
}

static void
ccd_section (struct ccd_state *st, char *name)
{
	const char *end;

	ccd_flush_entry (st);
	st->track = 0;

	if (grub_strncasecmp (name, "Entry", 5) == 0)
	{
		st->in_entry = 1;
		st->point = -1;
		st->plba = -1;
	}
	else if (grub_strncasecmp (name, "TRACK", 5) == 0)
	{
		unsigned long n = grub_strtoul (name + 5, &end, 10);

		if (grub_errno)
			grub_errno = GRUB_ERR_NONE;
		else if (n >= 1 && n <= CD_MAX_TRACKS)
		{
			st->track = (unsigned) n;
			st->tracks[n].seen = 1;
			/* Mode 1 unless the section says otherwise.  */
			st->tracks[n].mode = 1;
		}
	}
}

grub_err_t
grub_cdimage_parse_ccd (struct cdimage *img)
{
	static const char *const img_exts[] = { ".img", ".IMG", NULL };
	struct ccd_state *st = NULL;
	char *text = NULL;
	char *pos;
	char *line;
	grub_file_t src;
	grub_uint32_t sector_size;
	grub_int32_t base = 0;
	unsigned i;
	grub_err_t err = GRUB_ERR_NONE;

	text = grub_cdimage_read_text (img->container);
	if (!text)
		return grub_errno;
	if (grub_strncasecmp (text, "[CloneCD]", 9) != 0)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a CloneCD descriptor");
		goto fail;
	}

	st = grub_zalloc (sizeof (*st));
	if (!st)
	{
		err = grub_errno;
		goto fail;
	}

	pos = text;
	while ((line = grub_cdimage_next_line (&pos)) != NULL)
	{
		char *key;
		char *value;

		line = ccd_trim (line);
		if (!*line)
			continue;

		if (line[0] == '[')
		{
			char *close = grub_strchr (line, ']');

			if (close)
				*close = '\0';
			ccd_section (st, line + 1);
			continue;
		}

		value = grub_strchr (line, '=');
		if (!value)
			continue;
		*value++ = '\0';
		key = ccd_trim (line);
		value = ccd_trim (value);

		if (st->in_entry)
		{
			if (grub_strcasecmp (key, "Point") == 0)
				ccd_number (value, &st->point);
			else if (grub_strcasecmp (key, "PLBA") == 0)
				ccd_number (value, &st->plba);
		}
		else if (st->track)
		{
			long v;

			if (grub_strcasecmp (key, "MODE") == 0 && ccd_number (value, &v))
				st->tracks[st->track].mode = (int) v;
			else if (grub_strcasecmp (key, "INDEX 1") == 0
				 && ccd_number (value, &v) && v >= 0)
				st->tracks[st->track].start = (grub_uint32_t) v;
		}
	}
	ccd_flush_entry (st);

	if (!st->have_leadout)
	{
		err = grub_error (GRUB_ERR_BAD_FS, "no lead-out in CloneCD descriptor");
		goto fail;
	}

	src = grub_cdimage_open_ext (img, img_exts);
	if (!src)
	{
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
				  "CloneCD image data file not found");
		goto fail;
	}

	/* CloneCD writes raw sectors; with a subchannel dump interleaved
	   they are 2448 bytes instead of the usual 2352.  */
	if (src->size % CD_FRAMESIZE_RAW == 0)
		sector_size = CD_FRAMESIZE_RAW;
	else if (src->size % CD_FRAMESIZE_SUB == 0)
		sector_size = CD_FRAMESIZE_SUB;
	else
	{
		err = grub_error (GRUB_ERR_BAD_FS,
				  "CloneCD image is not a whole number of sectors");
		goto fail;
	}

	grub_cdimage_raw_base_lsn (src, 0, &base);

	for (i = 1; i <= CD_MAX_TRACKS; i++)
	{
		struct cdimage_track track;
		grub_uint32_t end;
		unsigned j;

		if (!st->tracks[i].seen)
			continue;

		/* Up to the next track that was recorded, or the lead-out.  */
		end = st->leadout;
		for (j = i + 1; j <= CD_MAX_TRACKS; j++)
			if (st->tracks[j].seen)
			{
				end = st->tracks[j].start;
				break;
			}
		if (end <= st->tracks[i].start)
			continue;

		grub_memset (&track, 0, sizeof (track));
		track.start_lsn = st->tracks[i].start;
		track.nsectors = end - st->tracks[i].start;
		track.sector_size = sector_size;
		switch (st->tracks[i].mode)
		{
		case 1:
			track.mode = CDIMAGE_MODE_1;
			track.data_offset = CD_M1_DATA_OFFSET;
			break;
		case 2:
			track.mode = CDIMAGE_MODE_2;
			track.data_offset = CD_M2_DATA_OFFSET;
			break;
		default:
			track.mode = CDIMAGE_MODE_AUDIO;
			break;
		}
		track.src = src;
		track.src_offset = (grub_uint64_t) ((grub_int64_t) track.start_lsn
						    - base) * sector_size;

		err = grub_cdimage_add_track (img, &track);
		if (err != GRUB_ERR_NONE)
			goto fail;
	}

	if (!img->ntracks)
		err = grub_error (GRUB_ERR_BAD_FS, "no track in CloneCD descriptor");

fail:
	grub_free (st);
	grub_free (text);
	return err;
}
