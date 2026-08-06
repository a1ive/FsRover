/* cdimage.h - shared track model for CD/DVD image containers */
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

#ifndef GRUB_CDIMAGE_HEADER
#define GRUB_CDIMAGE_HEADER	1

#include <grub/types.h>
#include <grub/err.h>
#include <grub/file.h>

/* Sector layouts we can decode into 2048 byte user data.  */
#define CD_FRAMESIZE		2048	/* cooked user data only */
#define CD_FRAMESIZE_FORM2	2324	/* mode 2 form 2 user data only */
#define CD_FRAMESIZE_M2		2336	/* subheader + data + EDC/ECC */
#define CD_FRAMESIZE_RAW	2352	/* sync + header + the above */
#define CD_FRAMESIZE_SUB	2448	/* raw + 96 bytes of subchannel */

#define CD_SYNC_SIZE		12
#define CD_HEADER_SIZE		4
#define CD_SUBHEADER_SIZE	8

/* Offset of the user data inside a raw (2352/2448) sector.  */
#define CD_M1_DATA_OFFSET	(CD_SYNC_SIZE + CD_HEADER_SIZE)
#define CD_M2_DATA_OFFSET	(CD_SYNC_SIZE + CD_HEADER_SIZE + CD_SUBHEADER_SIZE)

#define CD_MAX_TRACKS		99
#define CD_PREGAP_SECTORS	150

/* Sanity caps against corrupt containers.  */
#define CDIMAGE_MAX_LSN		0x02000000u	/* 64 GiB of user data */
#define CDIMAGE_TEXT_MAX	(4u << 20)
#define CDIMAGE_FILES_MAX	CD_MAX_TRACKS

enum cdimage_mode
{
	/* No addressable user data; reads back as zeros.  */
	CDIMAGE_MODE_AUDIO,
	/* CD-ROM mode 1: 2048 user bytes.  */
	CDIMAGE_MODE_1,
	/* CD-ROM XA mode 2: the form 1 payload is the addressable one.  */
	CDIMAGE_MODE_2
};

struct cdimage_track
{
	/* Absolute disc address of the first sector, in 2048 byte units.  */
	grub_uint32_t start_lsn;
	grub_uint32_t nsectors;
	/* Stride of one sector inside SRC.  */
	grub_uint32_t sector_size;
	/* User data offset inside one stored sector.  */
	grub_uint32_t data_offset;
	int mode;
	/* Backing file, owned by cdimage::files.  */
	grub_file_t src;
	/* Byte offset of START_LSN inside SRC.  */
	grub_uint64_t src_offset;
};

struct cdimage
{
	/* Container name, used in diagnostics.  */
	const char *fmt;
	/* The file the container was opened from.  Self contained formats
	   (nrg, raw) point their tracks at it.  Owned by the io filter,
	   never closed by grub_cdimage_free.  */
	grub_file_t container;
	struct cdimage_track *tracks;
	unsigned ntracks;
	/* Backing files, all owned and closed by grub_cdimage_free.  */
	grub_file_t files[CDIMAGE_FILES_MAX];
	unsigned nfiles;
	/* Size of the exposed stream: 2048 bytes per disc sector.  */
	grub_uint64_t size;
};

/* Container parsers.  Each reads IMG->container and fills in the track
   table; the caller frees IMG either way.  */
grub_err_t grub_cdimage_parse_cue (struct cdimage *img);
grub_err_t grub_cdimage_parse_toc (struct cdimage *img);
grub_err_t grub_cdimage_parse_ccd (struct cdimage *img);
grub_err_t grub_cdimage_parse_mds (struct cdimage *img);
grub_err_t grub_cdimage_parse_nrg (struct cdimage *img);
grub_err_t grub_cdimage_parse_raw (struct cdimage *img);

/* Append a track.  The table is grown in place.  A track with no
   sectors, no backing file or no sector size is dropped silently.  */
grub_err_t grub_cdimage_add_track (struct cdimage *img, const struct cdimage_track *track);

/* Read exactly LEN bytes at OFF; a short read is an error.  */
grub_err_t grub_cdimage_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len);

/* Open MEMBER (a path recorded inside the container) next to it and take
   ownership of the result.  Reuses an already opened backing file when
   MEMBER resolves to the same path.  */
grub_file_t grub_cdimage_open_member (struct cdimage *img, const char *member);

/* Open the sibling of the container whose extension is replaced by one
   of EXTS (a NULL terminated list, tried in order).  */
grub_file_t grub_cdimage_open_ext (struct cdimage *img, const char *const *exts);

/* Read the whole of FILE as text into a NUL terminated buffer, minus any
   UTF-8 BOM.  */
char *grub_cdimage_read_text (grub_file_t file);

/* Cut the next line out of *POS, stripping CR/LF.  Returns NULL at the
   end of the buffer.  */
char *grub_cdimage_next_line (char **pos);

/* strtok_r over a mutable buffer.  */
char *grub_cdimage_token (char **pos, const char *delim);

/* Take the next whitespace separated field of *POS, honouring one level
   of double quotes so that file names with spaces survive.  */
char *grub_cdimage_field (char **pos);

/* Parse "MM:SS:FF" into a sector count.  Returns 0 on a malformed
   string.  */
int grub_cdimage_msf_to_lsn (const char *str, grub_uint32_t *lsn);

/* Decode the address a raw sector stores in its own header, so that a
   container which only records disc addresses can be matched up with an
   image whose first stored sector is not LSN 0.  Returns 0 when there is
   no raw header at OFFSET.  */
int grub_cdimage_raw_base_lsn (grub_file_t src, grub_uint64_t offset, grub_int32_t *lsn);

/* Sort tracks, clamp them to their backing files, refine raw sector
   layouts from the on-disc headers and compute the exposed size.  */
grub_err_t grub_cdimage_finish (struct cdimage *img);

/* Read LEN bytes of user data at byte offset OFF of the exposed
   stream.  */
grub_err_t grub_cdimage_read (struct cdimage *img, grub_uint64_t off, void *buf, grub_size_t len);

void grub_cdimage_free (struct cdimage *img);

#endif /* ! GRUB_CDIMAGE_HEADER */
