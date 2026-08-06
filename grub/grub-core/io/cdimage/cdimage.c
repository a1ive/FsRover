/* cdimage.c - CD/DVD image container io filter */
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
 * A CD image container describes a disc as a list of tracks, each of
 * which stores its sectors in some raw or cooked layout.  This filter
 * turns that back into the flat 2048-byte-per-sector stream that the
 * iso9660 and udf drivers expect, addressed by absolute disc LSN so
 * that mixed mode discs (data track 1 followed by audio) keep their
 * on-disc addressing.  Audio tracks and gaps read back as zeros.
 *
 * Supported containers: CDRWIN .cue, cdrdao .toc, Nero .nrg, CloneCD
 * .ccd and Alcohol 120% .mds, plus raw 2352/2448 byte sector dumps
 * named .cdr.
 *
 * Not supported: reading a session other than the first one (the
 * iso9660 driver looks for its volume descriptor at LSN 16, so a disc
 * whose first session is audio -- CD-Extra -- does not mount), CD-TEXT,
 * subchannel data and audio track extraction.  Mode 2 form 2 sectors
 * are exposed as the first 2048 of their 2324 user bytes, which is what
 * bin-to-iso converters do; they carry no filesystem of their own.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>

#include <vbox.h>

#include "cdimage.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Grow the track table in steps; a disc has at most 99 tracks.  */
#define CDIMAGE_TRACK_CHUNK	16

struct grub_cdimage_io
{
	struct cdimage *img;
};

static struct grub_fs grub_cdimage_fs;

/* Read exactly LEN bytes at OFF.  */
grub_err_t
grub_cdimage_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t got;

	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno ? grub_errno : GRUB_ERR_OUT_OF_RANGE;
	got = grub_file_read (file, buf, len);
	if (got < 0)
		return grub_errno ? grub_errno : GRUB_ERR_FILE_READ_ERROR;
	if ((grub_size_t) got != len)
		return grub_error (GRUB_ERR_FILE_READ_ERROR, "short read in CD image");
	return GRUB_ERR_NONE;
}

grub_err_t
grub_cdimage_add_track (struct cdimage *img,
			const struct cdimage_track *track)
{
	if (img->ntracks >= CD_MAX_TRACKS)
		return grub_error (GRUB_ERR_BAD_FS, "too many tracks in %s image", img->fmt);
	if (!track->nsectors || !track->src || !track->sector_size)
		return GRUB_ERR_NONE;

	if (img->ntracks % CDIMAGE_TRACK_CHUNK == 0)
	{
		struct cdimage_track *grown;

		grown = grub_realloc (img->tracks, (img->ntracks + CDIMAGE_TRACK_CHUNK) * sizeof (grown[0]));
		if (!grown)
			return grub_errno;
		img->tracks = grown;
	}
	img->tracks[img->ntracks++] = *track;
	return GRUB_ERR_NONE;
}

/* Take ownership of FILE, or close it when there is no room left.  */
static grub_file_t
cdimage_own_file (struct cdimage *img, grub_file_t file)
{
	if (img->nfiles >= CDIMAGE_FILES_MAX)
	{
		grub_file_close (file);
		grub_error (GRUB_ERR_BAD_FS, "too many data files in %s image", img->fmt);
		return NULL;
	}
	img->files[img->nfiles++] = file;
	return file;
}

static const char *
cdimage_basename (const char *path)
{
	const char *p, *base = path;

	for (p = path; *p; p++)
		if (*p == '/' || *p == '\\')
			base = p + 1;
	return base;
}

/* The descriptor's own name carrying MEMBER's extension, or NULL when
   that is what was asked for in the first place.  */
static char *
cdimage_renamed (const char *image, const char *member)
{
	const char *base = cdimage_basename (image);
	const char *suffix = grub_file_get_suffix (image);
	const char *ext = grub_file_get_suffix (member);
	grub_size_t stem;
	char *guess;

	if (!ext)
		return NULL;
	stem = suffix ? (grub_size_t) (suffix - base) : grub_strlen (base);

	guess = grub_malloc (stem + grub_strlen (ext) + 1);
	if (!guess)
		return NULL;
	grub_memcpy (guess, base, stem);
	grub_strcpy (guess + stem, ext);

	if (grub_strcasecmp (guess, cdimage_basename (member)) == 0)
	{
		grub_free (guess);
		return NULL;
	}
	return guess;
}

grub_file_t
grub_cdimage_open_member (struct cdimage *img, const char *member)
{
	grub_file_t file;
	unsigned i;

	/* Resolves next to the descriptor in whichever namespace it came
	   from, grub device or Windows filesystem.  */
	file = grub_vdisk_open_member (img->container, member);

	if (!file && img->nfiles == 0)
	{
		/* Renaming the data file and leaving the descriptor alone is
		   common enough to be worth one retry under the descriptor's
		   own name.  Only for the first data file: a descriptor that
		   names several would otherwise collapse them onto one.  */
		char *guess = cdimage_renamed (img->container->name, member);

		if (guess)
		{
			grub_errno = GRUB_ERR_NONE;
			file = grub_vdisk_open_member (img->container, guess);
			grub_free (guess);
		}
	}
	if (!file)
		return NULL;

	/* Every track of a single-file cue sheet names the same bin.  */
	for (i = 0; i < img->nfiles; i++)
		if (grub_strcmp (img->files[i]->name, file->name) == 0)
		{
			grub_file_close (file);
			return img->files[i];
		}

	return cdimage_own_file (img, file);
}

grub_file_t
grub_cdimage_open_ext (struct cdimage *img, const char *const *exts)
{
	const char *name = img->container->name;
	const char *suffix;
	const char *base;
	grub_size_t stem;
	unsigned i;

	base = grub_strrchr (name, '/');
	base = base ? base + 1 : name;
	suffix = grub_file_get_suffix (name);
	stem = suffix ? (grub_size_t) (suffix - base) : grub_strlen (base);

	for (i = 0; exts[i]; i++)
	{
		char *member;
		grub_file_t file;

		member = grub_malloc (stem + grub_strlen (exts[i]) + 1);
		if (!member)
			return NULL;
		grub_memcpy (member, base, stem);
		grub_strcpy (member + stem, exts[i]);

		file = grub_cdimage_open_member (img, member);
		grub_free (member);
		if (file)
			return file;
		grub_errno = GRUB_ERR_NONE;
	}

	return NULL;
}

char *
grub_cdimage_read_text (grub_file_t file)
{
	grub_size_t len;
	char *buf;

	if (file->size == GRUB_FILE_SIZE_UNKNOWN || file->size > CDIMAGE_TEXT_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "CD image descriptor too large");
		return NULL;
	}
	len = (grub_size_t) file->size;

	buf = grub_malloc (len + 1);
	if (!buf)
		return NULL;
	if (grub_cdimage_pread (file, 0, buf, len) != GRUB_ERR_NONE)
	{
		grub_free (buf);
		return NULL;
	}
	buf[len] = '\0';

	/* Descriptors written by Windows tools often carry a BOM.  */
	if (len >= 3 && (grub_uint8_t) buf[0] == 0xef && (grub_uint8_t) buf[1] == 0xbb && (grub_uint8_t) buf[2] == 0xbf)
		grub_memmove (buf, buf + 3, len - 2);

	return buf;
}

char *
grub_cdimage_next_line (char **pos)
{
	char *line = *pos;
	char *p;

	if (!line || !*line)
		return NULL;

	for (p = line; *p && *p != '\n' && *p != '\r'; p++)
		;
	if (*p == '\r' && p[1] == '\n')
	{
		*p = '\0';
		*pos = p + 2;
	}
	else if (*p)
	{
		*p = '\0';
		*pos = p + 1;
	}
	else
		*pos = p;

	return line;
}

char *
grub_cdimage_token (char **pos, const char *delim)
{
	char *start = *pos;
	char *p;

	if (!start)
		return NULL;
	while (*start && grub_strchr (delim, *start))
		start++;
	if (!*start)
	{
		*pos = start;
		return NULL;
	}
	for (p = start; *p && !grub_strchr (delim, *p); p++)
		;
	if (*p)
	{
		*p = '\0';
		*pos = p + 1;
	}
	else
		*pos = p;

	return start;
}

char *
grub_cdimage_field (char **pos)
{
	char *p = *pos;
	char *start;

	while (*p == ' ' || *p == '\t')
		p++;
	if (!*p)
	{
		*pos = p;
		return NULL;
	}
	if (*p == '"')
	{
		start = ++p;
		while (*p && *p != '"')
			p++;
	}
	else
	{
		start = p;
		while (*p && *p != ' ' && *p != '\t')
			p++;
	}
	if (*p)
		*p++ = '\0';
	*pos = p;
	return start;
}

int
grub_cdimage_msf_to_lsn (const char *str, grub_uint32_t *lsn)
{
	unsigned long mm, ss, ff;
	const char *end;

	mm = grub_strtoul (str, &end, 10);
	if (grub_errno || *end != ':')
		goto fail;
	ss = grub_strtoul (end + 1, &end, 10);
	if (grub_errno || *end != ':')
		goto fail;
	ff = grub_strtoul (end + 1, &end, 10);
	if (grub_errno || *end)
		goto fail;
	if (ss > 59 || ff > 74 || mm > 0xffff)
		goto fail;

	*lsn = (grub_uint32_t) ((mm * 60 + ss) * 75 + ff);
	return 1;

fail:
	grub_errno = GRUB_ERR_NONE;
	return 0;
}

/* A raw sector starts with 00 ff ff ff ff ff ff ff ff ff ff 00 followed
   by the MSF address and the mode byte.  */
static const grub_uint8_t cdimage_sync[CD_SYNC_SIZE] =
{
	0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0x00
};

static grub_uint32_t
cdimage_bcd (grub_uint8_t b)
{
	return (grub_uint32_t) ((b >> 4) * 10 + (b & 0x0f));
}

int
grub_cdimage_raw_base_lsn (grub_file_t src, grub_uint64_t offset, grub_int32_t *lsn)
{
	grub_uint8_t head[CD_SYNC_SIZE + CD_HEADER_SIZE];
	grub_uint32_t mm, ss, ff;

	if (grub_cdimage_pread (src, offset, head, sizeof (head)) != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	if (grub_memcmp (head, cdimage_sync, CD_SYNC_SIZE) != 0)
		return 0;

	mm = cdimage_bcd (head[CD_SYNC_SIZE]);
	ss = cdimage_bcd (head[CD_SYNC_SIZE + 1]);
	ff = cdimage_bcd (head[CD_SYNC_SIZE + 2]);
	if (ss > 59 || ff > 74)
		return 0;

	*lsn = (grub_int32_t) ((mm * 60 + ss) * 75 + ff) - CD_PREGAP_SECTORS;
	return 1;
}

/* Look at the stored sector header of TRACK and correct its mode and
   data offset.  Cooked layouts carry no header and are left alone; a
   track whose header cannot be read keeps whatever the container
   claimed.  */
static void
cdimage_refine_track (struct cdimage_track *track)
{
	grub_uint8_t head[CD_SYNC_SIZE + CD_HEADER_SIZE];

	if (track->sector_size < CD_FRAMESIZE_RAW)
		return;
	if (grub_cdimage_pread (track->src, track->src_offset, head, sizeof (head)) != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		return;
	}
	if (grub_memcmp (head, cdimage_sync, CD_SYNC_SIZE) != 0)
		return;

	switch (head[CD_SYNC_SIZE + 3])
	{
	case 1:
		track->mode = CDIMAGE_MODE_1;
		track->data_offset = CD_M1_DATA_OFFSET;
		break;
	case 2:
		track->mode = CDIMAGE_MODE_2;
		track->data_offset = CD_M2_DATA_OFFSET;
		break;
	default:
		/* Mode 0 sectors are all zeros; leave them as a gap.  */
		track->mode = CDIMAGE_MODE_AUDIO;
		break;
	}
}

static void
cdimage_sort_tracks (struct cdimage *img)
{
	unsigned i, j;

	for (i = 1; i < img->ntracks; i++)
	{
		struct cdimage_track key = img->tracks[i];

		for (j = i; j > 0 && img->tracks[j - 1].start_lsn > key.start_lsn; j--)
			img->tracks[j] = img->tracks[j - 1];
		img->tracks[j] = key;
	}
}

grub_err_t
grub_cdimage_finish (struct cdimage *img)
{
	unsigned i, keep = 0;
	grub_uint64_t end = 0;

	for (i = 0; i < img->ntracks; i++)
	{
		struct cdimage_track *track = &img->tracks[i];
		grub_uint64_t avail;

		if (track->src->size == GRUB_FILE_SIZE_UNKNOWN
		    || track->src_offset >= track->src->size)
			continue;
		avail = (track->src->size - track->src_offset)
			/ track->sector_size;
		if (avail == 0)
			continue;
		if (track->nsectors > avail)
			track->nsectors = (grub_uint32_t) avail;
		if (track->start_lsn > CDIMAGE_MAX_LSN
			|| track->nsectors > CDIMAGE_MAX_LSN
			|| track->start_lsn + track->nsectors > CDIMAGE_MAX_LSN)
			return grub_error (GRUB_ERR_BAD_FS, "%s image track out of range", img->fmt);
		if (track->mode != CDIMAGE_MODE_AUDIO)
			cdimage_refine_track (track);
		if (track->data_offset + CD_FRAMESIZE > track->sector_size)
			track->mode = CDIMAGE_MODE_AUDIO;

		img->tracks[keep++] = *track;
	}
	img->ntracks = keep;
	if (!img->ntracks)
		return grub_error (GRUB_ERR_BAD_FS, "no usable track in %s image", img->fmt);

	cdimage_sort_tracks (img);

	/* Overlapping tracks would make the disc address space ambiguous;
	   the earlier track wins only up to where the next one starts.  */
	for (i = 0; i + 1 < img->ntracks; i++)
	{
		struct cdimage_track *track = &img->tracks[i];
		grub_uint32_t next = img->tracks[i + 1].start_lsn;

		if (track->start_lsn + track->nsectors > next)
			track->nsectors = next - track->start_lsn;
	}

	for (i = 0; i < img->ntracks; i++)
	{
		struct cdimage_track *track = &img->tracks[i];

		if (track->mode == CDIMAGE_MODE_AUDIO || !track->nsectors)
			continue;
		if ((grub_uint64_t) track->start_lsn + track->nsectors > end)
			end = (grub_uint64_t) track->start_lsn + track->nsectors;
	}
	if (!end)
		return grub_error (GRUB_ERR_BAD_FS, "no data track in %s image", img->fmt);

	img->size = end * CD_FRAMESIZE;
	return GRUB_ERR_NONE;
}

static const struct cdimage_track *
cdimage_find_track (struct cdimage *img, grub_uint32_t lsn)
{
	unsigned lo = 0, hi = img->ntracks;

	while (lo < hi)
	{
		unsigned mid = lo + (hi - lo) / 2;
		const struct cdimage_track *track = &img->tracks[mid];

		if (lsn < track->start_lsn)
			hi = mid;
		else if (lsn >= track->start_lsn + track->nsectors)
			lo = mid + 1;
		else
			return track;
	}
	return NULL;
}

grub_err_t
grub_cdimage_read (struct cdimage *img, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_uint8_t *out = buf;

	while (len)
	{
		const struct cdimage_track *track;
		grub_uint32_t lsn = (grub_uint32_t) (off / CD_FRAMESIZE);
		grub_uint32_t in = (grub_uint32_t) (off % CD_FRAMESIZE);
		grub_size_t chunk = CD_FRAMESIZE - in;
		grub_err_t err;

		if (chunk > len)
			chunk = len;

		track = cdimage_find_track (img, lsn);
		if (!track || track->mode == CDIMAGE_MODE_AUDIO)
		{
			grub_memset (out, 0, chunk);
			goto advance;
		}

		/* Cooked tracks are already the stream we expose, so serve
		   whole runs of them in one read.  */
		if (track->sector_size == CD_FRAMESIZE && track->data_offset == 0)
		{
			grub_uint64_t left;

			left = (grub_uint64_t) (track->start_lsn + track->nsectors
						- lsn) * CD_FRAMESIZE - in;
			chunk = len;
			if (chunk > left)
				chunk = (grub_size_t) left;
		}

		err = grub_cdimage_pread (track->src,
				track->src_offset
				+ (grub_uint64_t) (lsn - track->start_lsn) * track->sector_size
				+ track->data_offset + in,
				out, chunk);
		if (err != GRUB_ERR_NONE)
			return err;

	advance:
		off += chunk;
		out += chunk;
		len -= chunk;
	}

	return GRUB_ERR_NONE;
}

void
grub_cdimage_free (struct cdimage *img)
{
	unsigned i;

	for (i = 0; i < img->nfiles; i++)
		grub_file_close (img->files[i]);
	img->nfiles = 0;
	grub_free (img->tracks);
	img->tracks = NULL;
	img->ntracks = 0;
}

/*
 * A bare dump of raw sectors: no descriptor, so the sync pattern is the
 * only thing that tells us the sector size.  Only used for the .cdr
 * extension, where the alternative reading (a cooked ISO image) needs no
 * filter at all.
 */
grub_err_t
grub_cdimage_parse_raw (struct cdimage *img)
{
	static const grub_uint32_t sizes[] =
	{
		CD_FRAMESIZE_RAW, CD_FRAMESIZE_SUB
	};
	grub_file_t file = img->container;
	grub_uint8_t head[CD_SYNC_SIZE];
	unsigned i;

	if (grub_cdimage_pread (file, 0, head, sizeof (head)) != GRUB_ERR_NONE)
		return grub_errno;
	if (grub_memcmp (head, cdimage_sync, CD_SYNC_SIZE) != 0)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a raw CD sector dump");

	for (i = 0; i < ARRAY_SIZE (sizes); i++)
	{
		struct cdimage_track track;

		if (file->size % sizes[i] != 0 || file->size < 2 * sizes[i])
			continue;
		/* The second sector must be in sync too, otherwise the size
		   just happened to divide.  */
		if (grub_cdimage_pread (file, sizes[i], head, sizeof (head)) != GRUB_ERR_NONE)
			return grub_errno;
		if (grub_memcmp (head, cdimage_sync, CD_SYNC_SIZE) != 0)
			continue;

		grub_memset (&track, 0, sizeof (track));
		track.start_lsn = 0;
		track.nsectors = (grub_uint32_t) (file->size / sizes[i]);
		track.sector_size = sizes[i];
		track.data_offset = CD_M1_DATA_OFFSET;
		track.mode = CDIMAGE_MODE_1;
		track.src = file;
		track.src_offset = 0;
		return grub_cdimage_add_track (img, &track);
	}

	return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a raw CD sector dump");
}

/* Nero images carry their descriptor at the end of the file, so they can
   be recognised without going by the name.  */
static int
cdimage_looks_like_nrg (grub_file_t file)
{
	grub_uint8_t foot[12];

	if (file->size < sizeof (foot))
		return 0;
	if (grub_cdimage_pread (file, file->size - sizeof (foot), foot, sizeof (foot)) != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	return grub_memcmp (foot + 4, "NERO", 4) == 0 || grub_memcmp (foot, "NER5", 4) == 0;
}

/* Containers are named, not magic: a cue sheet and a toc file are both
   just text, and the data they point at lives in a sibling file.  */
static const struct
{
	const char *ext;
	const char *fmt;
	grub_err_t (*parse) (struct cdimage *img);
} cdimage_containers[] =
{
	{ ".cue", "cue", grub_cdimage_parse_cue },
	{ ".toc", "toc", grub_cdimage_parse_toc },
	{ ".ccd", "ccd", grub_cdimage_parse_ccd },
	{ ".mds", "mds", grub_cdimage_parse_mds },
	{ ".nrg", "nrg", grub_cdimage_parse_nrg },
	{ ".cdr", "cdr", grub_cdimage_parse_raw }
};

static grub_file_t
grub_cdimage_open (grub_file_t io, enum grub_file_type type)
{
	struct grub_cdimage_io *cdio;
	struct cdimage *img;
	grub_file_t file;
	const char *suffix;
	grub_err_t (*parse) (struct cdimage *img) = NULL;
	const char *fmt = NULL;
	unsigned i;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	/* A descriptor is a few hundred bytes; only the data file it names
	   has to be sector sized.  */
	if (io->size == GRUB_FILE_SIZE_UNKNOWN || io->size < 16 || !io->name)
		return io;

	suffix = grub_file_get_suffix (io->name);
	for (i = 0; suffix && i < ARRAY_SIZE (cdimage_containers); i++)
		if (grub_strcasecmp (suffix, cdimage_containers[i].ext) == 0)
		{
			parse = cdimage_containers[i].parse;
			fmt = cdimage_containers[i].fmt;
			break;
		}
	if (!parse && cdimage_looks_like_nrg (io))
	{
		parse = grub_cdimage_parse_nrg;
		fmt = "nrg";
	}
	if (!parse)
		return io;

	img = grub_zalloc (sizeof (*img));
	if (!img)
		return 0;
	img->fmt = fmt;
	img->container = io;

	if (parse (img) != GRUB_ERR_NONE || grub_cdimage_finish (img) != GRUB_ERR_NONE)
	{
		grub_cdimage_free (img);
		grub_free (img);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = grub_zalloc (sizeof (*file));
	cdio = grub_zalloc (sizeof (*cdio));
	if (!file || !cdio)
	{
		grub_cdimage_free (img);
		grub_free (img);
		grub_free (file);
		grub_free (cdio);
		return 0;
	}
	cdio->img = img;

	file->device = io->device;
	file->data = cdio;
	file->fs = &grub_cdimage_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = img->size;

	return file;
}

static grub_ssize_t
grub_cdimage_fs_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_cdimage_io *cdio = file->data;

	if (file->offset >= cdio->img->size)
		return 0;
	if (len > cdio->img->size - file->offset)
		len = (grub_size_t) (cdio->img->size - file->offset);
	if (grub_cdimage_read (cdio->img, file->offset, buf, len) != GRUB_ERR_NONE)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_FILE_READ_ERROR, "CD image read failed");
		return -1;
	}
	return (grub_ssize_t) len;
}

static grub_err_t
grub_cdimage_fs_close (grub_file_t file)
{
	struct grub_cdimage_io *cdio = file->data;
	grub_file_t container = cdio->img->container;

	grub_cdimage_free (cdio->img);
	grub_free (cdio->img);
	grub_free (cdio);
	grub_file_close (container);
	/* The inner close released the shared device; the outer name is
	   freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static struct grub_fs grub_cdimage_fs =
{
	.name = "cdimage",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_cdimage_fs_read,
	.fs_close = grub_cdimage_fs_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (cdimage)
{
	grub_file_filter_register (GRUB_FILE_FILTER_CDIMAGE, grub_cdimage_open);
}

GRUB_MOD_FINI (cdimage)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_CDIMAGE);
}
