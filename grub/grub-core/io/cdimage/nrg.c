/* nrg.c - Nero Burning ROM image parser */
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
 * An NRG image is self contained: the sector data comes first and a
 * chunk list describing it sits at the end, located through a footer in
 * the last 8 (Nero 5.0) or 12 (Nero 5.5 and later) bytes.  Everything
 * in the chunk list is big endian.
 *
 * Two layouts describe the tracks.  Track-at-once images carry ETNF or
 * ETN2 chunks, which give each track's file offset, byte length, mode
 * and disc address directly.  Disc-at-once images carry DAOI or DAOX
 * instead: one contiguous run of sectors covering the whole disc, with
 * per track byte offsets and, usefully, the sector size and mode.  For
 * those the disc address follows from the file offset, rebased so that
 * track 1 starts at LSN 0 whether or not its pregap was written out.
 *
 * The CUES/CUEX table of contents is not read: DAOI/DAOX already say
 * where every track lives, and CUES stores its addresses as MSF in a
 * layout libcdio itself flags as guesswork.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>

#include "cdimage.h"

/* The chunk list is tiny: 99 DAOX entries plus overhead is under 5 KiB.  */
#define NRG_FOOTER_MAX		(1u << 20)
#define NRG_CHUNK_HEADER	8

#define NRG_DAO_COMMON_SIZE	22
#define NRG_DAOI_ENTRY_SIZE	30
#define NRG_DAOX_ENTRY_SIZE	42
#define NRG_ETNF_ENTRY_SIZE	20
#define NRG_ETN2_ENTRY_SIZE	32

/* Offsets inside one DAOI/DAOX track entry.  */
#define NRG_DAO_SECTOR_SIZE	12
#define NRG_DAO_MODE		14
#define NRG_DAO_INDEX0		18

static grub_uint16_t
nrg_be16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) ((p[0] << 8) | p[1]);
}

static grub_uint32_t
nrg_be32 (const grub_uint8_t *p)
{
	return grub_be_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
nrg_be64 (const grub_uint8_t *p)
{
	return grub_be_to_cpu64 (grub_get_unaligned64 (p));
}

/* Nero's track mode byte, as used by DAOI/DAOX and ETNF/ETN2.  */
static int
nrg_mode (grub_uint32_t type, grub_uint32_t *sector_size,
	  grub_uint32_t *data_offset)
{
	switch (type)
	{
	case 0x00:	/* mode 1 */
		*sector_size = CD_FRAMESIZE;
		*data_offset = 0;
		return CDIMAGE_MODE_1;
	case 0x02:	/* mode 2 form 1 */
		*sector_size = CD_FRAMESIZE;
		*data_offset = 0;
		return CDIMAGE_MODE_2;
	case 0x03:	/* mode 2, 2336 byte sectors */
	case 0x06:	/* mode 2 form mix */
	case 0x20:	/* mode 2, seen on some XA images */
		*sector_size = CD_FRAMESIZE_M2;
		*data_offset = CD_SUBHEADER_SIZE;
		return CDIMAGE_MODE_2;
	case 0x05:	/* mode 1, raw sectors */
		*sector_size = CD_FRAMESIZE_RAW;
		*data_offset = CD_M1_DATA_OFFSET;
		return CDIMAGE_MODE_1;
	case 0x07:	/* audio */
		*sector_size = CD_FRAMESIZE_RAW;
		*data_offset = 0;
		return CDIMAGE_MODE_AUDIO;
	default:
		return -1;
	}
}

/* Disc-at-once: one contiguous stream, DAO entries give byte offsets.  */
static grub_err_t
nrg_parse_dao (struct cdimage *img, const grub_uint8_t *data, grub_uint32_t len, int wide)
{
	grub_uint32_t entry_size = wide ? NRG_DAOX_ENTRY_SIZE : NRG_DAOI_ENTRY_SIZE;
	grub_uint32_t ntracks;
	grub_uint32_t i;
	grub_int64_t rebase = 0;
	int have_rebase = 0;

	if (len < NRG_DAO_COMMON_SIZE)
		return grub_error (GRUB_ERR_BAD_FS, "truncated nrg DAO chunk");
	ntracks = (len - NRG_DAO_COMMON_SIZE) / entry_size;
	if (!ntracks || ntracks > CD_MAX_TRACKS)
		return grub_error (GRUB_ERR_BAD_FS, "bad track count in nrg image");

	for (i = 0; i < ntracks; i++)
	{
		const grub_uint8_t *e = data + NRG_DAO_COMMON_SIZE + i * entry_size;
		struct cdimage_track track;
		grub_uint64_t index1, end;
		grub_uint32_t sector_size, data_offset, mode_size;
		grub_int64_t lsn;
		int mode;
		grub_err_t err;

		/* The mode byte gives the layout, but the entry carries the
		   real sector size, so keep that one.  */
		mode = nrg_mode (e[NRG_DAO_MODE], &mode_size, &data_offset);
		if (mode < 0)
			return grub_error (GRUB_ERR_BAD_FS, "unsupported nrg track mode 0x%x", e[NRG_DAO_MODE]);
		sector_size = nrg_be16 (e + NRG_DAO_SECTOR_SIZE);
		if (!sector_size)
			sector_size = mode_size;
		switch (sector_size)
		{
		case CD_FRAMESIZE:
			data_offset = 0;
			break;
		case CD_FRAMESIZE_M2:
			data_offset = CD_SUBHEADER_SIZE;
			break;
		case CD_FRAMESIZE_RAW:
		case CD_FRAMESIZE_SUB:
			data_offset = mode == CDIMAGE_MODE_2 ? CD_M2_DATA_OFFSET : CD_M1_DATA_OFFSET;
			break;
		default:
			data_offset = 0;
			break;
		}

		if (wide)
		{
			index1 = nrg_be64 (e + NRG_DAO_INDEX0 + 8);
			end = nrg_be64 (e + NRG_DAO_INDEX0 + 16);
		}
		else
		{
			index1 = nrg_be32 (e + NRG_DAO_INDEX0 + 4);
			end = nrg_be32 (e + NRG_DAO_INDEX0 + 8);
		}
		if (end <= index1)
			continue;

		lsn = (grub_int64_t) (index1 / sector_size) - CD_PREGAP_SECTORS;
		if (!have_rebase)
		{
			/* Track 1 defines LSN 0, whether or not its pregap was
			   written into the image.  */
			rebase = -lsn;
			have_rebase = 1;
		}
		lsn += rebase;
		if (lsn < 0)
			continue;

		grub_memset (&track, 0, sizeof (track));
		track.start_lsn = (grub_uint32_t) lsn;
		track.nsectors = (grub_uint32_t) ((end - index1) / sector_size);
		track.sector_size = sector_size;
		track.data_offset = data_offset;
		track.mode = mode;
		track.src = img->container;
		track.src_offset = index1;

		err = grub_cdimage_add_track (img, &track);
		if (err != GRUB_ERR_NONE)
			return err;
	}

	return GRUB_ERR_NONE;
}

/* Track-at-once: every entry stands on its own.  */
static grub_err_t
nrg_parse_etn (struct cdimage *img, const grub_uint8_t *data, grub_uint32_t len, int wide)
{
	grub_uint32_t entry_size = wide ? NRG_ETN2_ENTRY_SIZE : NRG_ETNF_ENTRY_SIZE;
	grub_uint32_t ntracks = len / entry_size;
	grub_uint32_t i;

	if (!ntracks || ntracks > CD_MAX_TRACKS)
		return grub_error (GRUB_ERR_BAD_FS, "bad track count in nrg image");

	for (i = 0; i < ntracks; i++)
	{
		const grub_uint8_t *e = data + i * entry_size;
		struct cdimage_track track;
		grub_uint64_t start, length;
		grub_uint32_t type, start_lsn;
		grub_uint32_t sector_size, data_offset;
		int mode;
		grub_err_t err;

		if (wide)
		{
			start = nrg_be64 (e);
			length = nrg_be64 (e + 8);
			type = nrg_be32 (e + 16);
			start_lsn = nrg_be32 (e + 20);
		}
		else
		{
			start = nrg_be32 (e);
			length = nrg_be32 (e + 4);
			type = nrg_be32 (e + 8);
			start_lsn = nrg_be32 (e + 12);
		}

		mode = nrg_mode (type, &sector_size, &data_offset);
		if (mode < 0)
			return grub_error (GRUB_ERR_BAD_FS, "unsupported nrg track mode 0x%x", type);
		if (!length)
			continue;

		/* The recorded address leaves out the gap in front of every
		   track after the first one.  */
		start_lsn += i * CD_PREGAP_SECTORS;

		grub_memset (&track, 0, sizeof (track));
		track.start_lsn = start_lsn;
		track.nsectors = (grub_uint32_t) (length / sector_size);
		track.sector_size = sector_size;
		track.data_offset = data_offset;
		track.mode = mode;
		track.src = img->container;
		track.src_offset = start;

		err = grub_cdimage_add_track (img, &track);
		if (err != GRUB_ERR_NONE)
			return err;
	}

	return GRUB_ERR_NONE;
}

grub_err_t
grub_cdimage_parse_nrg (struct cdimage *img)
{
	grub_file_t file = img->container;
	grub_uint8_t foot[12];
	grub_uint8_t *chunks = NULL;
	grub_uint64_t start;
	grub_uint32_t size;
	grub_uint32_t pos;
	grub_err_t err;

	if (file->size < sizeof (foot))
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not an nrg image");
	err = grub_cdimage_pread (file, file->size - sizeof (foot), foot, sizeof (foot));
	if (err != GRUB_ERR_NONE)
		return err;

	if (grub_memcmp (foot, "NER5", 4) == 0)
		start = nrg_be64 (foot + 4);
	else if (grub_memcmp (foot + 4, "NERO", 4) == 0)
		start = nrg_be32 (foot + 8);
	else
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not an nrg image");

	if (start >= file->size
		|| file->size - start > NRG_FOOTER_MAX
		|| file->size - start < NRG_CHUNK_HEADER)
		return grub_error (GRUB_ERR_BAD_FS, "bad chunk list in nrg image");
	size = (grub_uint32_t) (file->size - start);

	chunks = grub_malloc (size);
	if (!chunks)
		return grub_errno;
	err = grub_cdimage_pread (file, start, chunks, size);
	if (err != GRUB_ERR_NONE)
		goto fail;

	for (pos = 0; pos + NRG_CHUNK_HEADER <= size; )
	{
		const grub_uint8_t *id = chunks + pos;
		grub_uint32_t len = nrg_be32 (chunks + pos + 4);
		const grub_uint8_t *data = chunks + pos + NRG_CHUNK_HEADER;

		if (grub_memcmp (id, "END!", 4) == 0)
			break;
		if (len > size - pos - NRG_CHUNK_HEADER)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "truncated chunk in nrg image");
			goto fail;
		}

		if (grub_memcmp (id, "DAOX", 4) == 0)
			err = nrg_parse_dao (img, data, len, 1);
		else if (grub_memcmp (id, "DAOI", 4) == 0)
			err = nrg_parse_dao (img, data, len, 0);
		else if (grub_memcmp (id, "ETN2", 4) == 0)
			err = nrg_parse_etn (img, data, len, 1);
		else if (grub_memcmp (id, "ETNF", 4) == 0)
			err = nrg_parse_etn (img, data, len, 0);
		else
			err = GRUB_ERR_NONE;
		if (err != GRUB_ERR_NONE)
			goto fail;

		pos += NRG_CHUNK_HEADER + len;
	}

	if (!img->ntracks)
		err = grub_error (GRUB_ERR_BAD_FS, "no track chunk in nrg image");

fail:
	grub_free (chunks);
	return err;
}
