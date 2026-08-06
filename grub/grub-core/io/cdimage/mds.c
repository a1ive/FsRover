/* mds.c - Alcohol 120% image parser */
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
 * An .mds file is a small binary descriptor: a fixed header points at a
 * run of session blocks, each of which points at a run of track blocks.
 * Track blocks whose point is 0xa0 and up describe the lead-in and are
 * skipped; the rest give the recording mode, the stored sector size, the
 * disc address and the byte offset of the track inside the .mdf that
 * holds the sectors.  Track lengths come from an extra block, except on
 * DVD media where the same field is the length itself.
 *
 * The data file name is recorded in a footer, usually as the placeholder
 * "*.mdf" meaning "the sibling of this descriptor".
 *
 * Not supported: DPM timing blocks, disc structures and BCA data, none
 * of which a filesystem needs.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>

#include <vbox.h>

#include "cdimage.h"

#define MDS_MAX_SIZE		(4u << 20)

#define MDS_HEADER_SIZE		88
#define MDS_SESSION_SIZE	24
#define MDS_TRACK_SIZE		80
#define MDS_EXTRA_SIZE		8
#define MDS_FOOTER_SIZE		16

/* Header fields.  */
#define MDS_H_MEDIUM_TYPE	0x12
#define MDS_H_NSESSIONS		0x14
#define MDS_H_SESSIONS_OFF	0x50

/* Session block fields.  */
#define MDS_S_NBLOCKS		0x0a
#define MDS_S_TRACKS_OFF	0x14

/* Track block fields.  */
#define MDS_T_MODE		0x00
#define MDS_T_SUBCHANNEL	0x01
#define MDS_T_POINT		0x04
#define MDS_T_EXTRA_OFF		0x0c
#define MDS_T_SECTOR_SIZE	0x10
#define MDS_T_START_SECTOR	0x24
#define MDS_T_START_OFFSET	0x28
#define MDS_T_FOOTER_OFF	0x34

/* Anything from this medium type up is a DVD, where the extra offset
   field holds the track length outright.  */
#define MDS_MEDIUM_DVD		0x10

#define MDS_MODE_AUDIO		0xa9
#define MDS_MODE_MODE1		0xaa
#define MDS_MODE_MODE2		0xab
#define MDS_MODE_MODE2_FORM1	0xac
#define MDS_MODE_MODE2_FORM2	0xad
#define MDS_MODE_MODE2_SUB	0xec

struct mds_image
{
	grub_uint8_t *desc;
	grub_uint32_t desc_size;
	struct cdimage *img;
	grub_file_t src;
	int is_dvd;
};

static grub_uint16_t
mds_le16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
mds_le32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
mds_le64 (const grub_uint8_t *p)
{
	return grub_le_to_cpu64 (grub_get_unaligned64 (p));
}

/* Bounds checked view of a block inside the descriptor.  */
static const grub_uint8_t *
mds_block (struct mds_image *mds, grub_uint32_t offset, grub_uint32_t size)
{
	if (!offset || offset >= mds->desc_size || size > mds->desc_size - offset)
		return NULL;
	return mds->desc + offset;
}

/* Read the data file name out of a track footer.  */
static char *
mds_data_file_name (struct mds_image *mds, grub_uint32_t footer_off)
{
	const grub_uint8_t *footer = mds_block (mds, footer_off, MDS_FOOTER_SIZE);
	grub_uint32_t name_off;
	int wide;
	grub_size_t max;

	if (!footer)
		return NULL;
	name_off = mds_le32 (footer);
	wide = mds_le32 (footer + 4) != 0;
	if (!name_off || name_off >= mds->desc_size)
		return NULL;
	max = mds->desc_size - name_off;

	if (wide)
		return grub_vdisk_utf16_to_utf8_dup (mds->desc + name_off, max / 2, 0);
	return grub_strndup ((const char *) mds->desc + name_off, max);
}

/* "*.mdf" and friends mean "the sibling of the descriptor".  */
static grub_file_t
mds_open_data (struct mds_image *mds, const char *name)
{
	static const char *const mdf_exts[] = { ".mdf", ".MDF", NULL };

	if (!name || !*name || name[0] == '*')
	{
		const char *exts[3];

		if (name && name[0] == '*' && name[1])
		{
			exts[0] = name + 1;
			exts[1] = NULL;
			return grub_cdimage_open_ext (mds->img, exts);
		}
		return grub_cdimage_open_ext (mds->img, mdf_exts);
	}
	return grub_cdimage_open_member (mds->img, name);
}

static grub_err_t
mds_add_track (struct mds_image *mds, const grub_uint8_t *tb)
{
	struct cdimage_track track;
	grub_uint32_t sector_size = mds_le16 (tb + MDS_T_SECTOR_SIZE);
	grub_uint32_t extra_off = mds_le32 (tb + MDS_T_EXTRA_OFF);
	grub_uint32_t nsectors = 0;
	grub_uint8_t mode = tb[MDS_T_MODE];

	grub_memset (&track, 0, sizeof (track));

	switch (mode)
	{
	case MDS_MODE_AUDIO:
		track.mode = CDIMAGE_MODE_AUDIO;
		if (!sector_size)
			sector_size = CD_FRAMESIZE_RAW;
		break;
	case MDS_MODE_MODE1:
		track.mode = CDIMAGE_MODE_1;
		if (!sector_size)
			sector_size = CD_FRAMESIZE;
		break;
	case MDS_MODE_MODE2:
	case MDS_MODE_MODE2_FORM1:
	case MDS_MODE_MODE2_FORM2:
	case MDS_MODE_MODE2_SUB:
		track.mode = CDIMAGE_MODE_2;
		if (!sector_size)
			sector_size = CD_FRAMESIZE_M2;
		break;
	default:
		return grub_error (GRUB_ERR_BAD_FS, "unsupported mds track mode 0x%x", mode);
	}

	switch (sector_size)
	{
	case CD_FRAMESIZE:
	case CD_FRAMESIZE_FORM2:
		track.data_offset = 0;
		break;
	case CD_FRAMESIZE_M2:
		track.data_offset = CD_SUBHEADER_SIZE;
		break;
	case CD_FRAMESIZE_RAW:
	case CD_FRAMESIZE_SUB:
		track.data_offset = track.mode == CDIMAGE_MODE_2 ? CD_M2_DATA_OFFSET : CD_M1_DATA_OFFSET;
		break;
	default:
		return grub_error (GRUB_ERR_BAD_FS, "bad sector size %u in mds image", sector_size);
	}

	if (mds->is_dvd)
		nsectors = extra_off;
	else
	{
		const grub_uint8_t *extra;

		extra = mds_block (mds, extra_off, MDS_EXTRA_SIZE);
		if (extra)
			nsectors = mds_le32 (extra + 4);
	}

	track.start_lsn = mds_le32 (tb + MDS_T_START_SECTOR);
	track.sector_size = sector_size;
	track.src = mds->src;
	track.src_offset = mds_le64 (tb + MDS_T_START_OFFSET);

	if (!nsectors)
	{
		/* No usable length: run to the end of the data file and let
		   the next track clip us.  */
		if (mds->src->size == GRUB_FILE_SIZE_UNKNOWN || track.src_offset >= mds->src->size)
			return GRUB_ERR_NONE;
		nsectors = (grub_uint32_t) ((mds->src->size - track.src_offset) / sector_size);
	}
	track.nsectors = nsectors;

	return grub_cdimage_add_track (mds->img, &track);
}

grub_err_t
grub_cdimage_parse_mds (struct cdimage *img)
{
	struct mds_image mds;
	grub_file_t file = img->container;
	grub_uint32_t sessions_off;
	grub_uint32_t nsessions;
	grub_uint32_t s;
	char *name = NULL;
	grub_err_t err = GRUB_ERR_NONE;

	grub_memset (&mds, 0, sizeof (mds));
	mds.img = img;

	if (file->size < MDS_HEADER_SIZE || file->size > MDS_MAX_SIZE)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not an mds descriptor");
	mds.desc_size = (grub_uint32_t) file->size;
	/* Two spare NUL bytes so that a name running to the very end of the
	   descriptor still terminates, in either character width.  */
	mds.desc = grub_zalloc (mds.desc_size + 2);
	if (!mds.desc)
		return grub_errno;
	err = grub_cdimage_pread (file, 0, mds.desc, mds.desc_size);
	if (err != GRUB_ERR_NONE)
		goto fail;

	if (grub_memcmp (mds.desc, "MEDIA DESCRIPTOR", 16) != 0)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "not an mds descriptor");
		goto fail;
	}
	mds.is_dvd = mds_le16 (mds.desc + MDS_H_MEDIUM_TYPE) >= MDS_MEDIUM_DVD;

	nsessions = mds_le16 (mds.desc + MDS_H_NSESSIONS);
	sessions_off = mds_le32 (mds.desc + MDS_H_SESSIONS_OFF);
	if (!nsessions || nsessions > CD_MAX_TRACKS)
	{
		err = grub_error (GRUB_ERR_BAD_FS, "bad session count in mds image");
		goto fail;
	}

	for (s = 0; s < nsessions; s++)
	{
		const grub_uint8_t *sb;
		const grub_uint8_t *tb;
		grub_uint32_t tracks_off;
		grub_uint32_t nblocks;
		grub_uint32_t t;

		sb = mds_block (&mds, sessions_off + s * MDS_SESSION_SIZE,
				MDS_SESSION_SIZE);
		if (!sb)
		{
			err = grub_error (GRUB_ERR_BAD_FS, "truncated session block in mds image");
			goto fail;
		}
		nblocks = sb[MDS_S_NBLOCKS];
		tracks_off = mds_le32 (sb + MDS_S_TRACKS_OFF);

		for (t = 0; t < nblocks; t++)
		{
			tb = mds_block (&mds, tracks_off + t * MDS_TRACK_SIZE,
					MDS_TRACK_SIZE);
			if (!tb)
			{
				err = grub_error (GRUB_ERR_BAD_FS, "truncated track block in mds image");
				goto fail;
			}
			/* Points 0xa0..0xaf describe the lead-in, not a track.  */
			if (tb[MDS_T_POINT] < 1 || tb[MDS_T_POINT] > CD_MAX_TRACKS)
				continue;

			/* Each track names its own data file; images that
			   share one just repeat the name, and reopening it
			   hands back the file we already have.  */
			name = mds_data_file_name (&mds, mds_le32 (tb + MDS_T_FOOTER_OFF));
			mds.src = mds_open_data (&mds, name);
			grub_free (name);
			name = NULL;
			if (!mds.src)
			{
				err = grub_error (GRUB_ERR_FILE_NOT_FOUND, "mds image data file not found");
				goto fail;
			}

			err = mds_add_track (&mds, tb);
			if (err != GRUB_ERR_NONE)
				goto fail;
		}
	}

	if (!img->ntracks)
		err = grub_error (GRUB_ERR_BAD_FS, "no track in mds descriptor");

fail:
	grub_free (mds.desc);
	return err;
}
