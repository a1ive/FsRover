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
 *  Read-only FMOD sound bank filesystem driver.
 *
 *  An FMOD Studio bank (.bank) is a RIFF "FEV " file: the Studio project
 *  data sits in LIST "PROJ", and its SNDH chunk points at one or more FSB5
 *  sound banks holding the audio.  A bare FSB5 file (.fsb) is accepted as
 *  well.  Container parsing follows vgmstream (src/meta/fsb5.c and
 *  fsb5_fev.c).  Every subsound of every FSB5 becomes a file at the root:
 *
 *      PCM8/16/24/32/float	name.wav, a RIFF header over the samples
 *      Vorbis			name.ogg, remuxed losslessly (see below)
 *      MPEG Layer III		name.mp3, with FSB frame padding removed
 *      anything else		name.<codec>, the raw stream
 *
 *  FSB5 Vorbis keeps bare audio packets, each behind a 16-bit length, and
 *  replaces the three Vorbis header packets with the CRC32 of the setup
 *  packet FMOD's encoder used.  The setup packets come from the table in
 *  fmod_vorbis.h; the identification and comment packets are rebuilt, and
 *  the audio packets are laid into Ogg pages whose granule positions follow
 *  from each packet's mode blockflag.  Sizing an .ogg means walking every
 *  packet header of the stream, so the page index is built once at mount
 *  time and kept in a one slot cache, like pkghelp's entry lists.
 *
 *  A stream that cannot be remuxed -- an unknown setup id, a broken packet
 *  chain, big-endian PCM -- is presented raw rather than hidden.
 *  Encrypted banks are reported as such; Studio metadata (events, buses,
 *  string tables) is not interpreted.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/partition.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/dl.h>

#include "xz.h"
#include "fmod_vorbis.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define FMOD_SIG_SIZE		512
#define FMOD_FSB_V0_HEAD	0x40
#define FMOD_FSB_V1_HEAD	0x3c
#define FMOD_MAX_TABLE		(64 << 20)	/* sample headers / names */
#define FMOD_MAX_SNDH		(1 << 20)
#define FMOD_SCAN_BUF		0x10000
#define FMOD_NAME_MAX		255

#define FMOD_WAV_HEAD		44

#define OGG_PAGE_HEAD		27
#define OGG_PAGE_BODY		4096	/* close a page once it holds this */
#define OGG_MAX_SEGS		255
#define OGG_BOS			0x02
#define OGG_EOS			0x04
#define OGG_SERIAL		0x524f5652	/* "ROVR" */

#define VORBIS_ID_LEN		30
#define VORBIS_VENDOR		"Rover"
#define VORBIS_VENDOR_LEN	5
#define VORBIS_COMMENT_LEN	(7 + 4 + VORBIS_VENDOR_LEN + 4 + 1)
#define VORBIS_SHORT_BLOCK	256	/* FMOD encodes with fixed blocksizes */
#define VORBIS_LONG_BLOCK	2048
#define VORBIS_BLOCK_EXPS	0xb8	/* log2: long << 4 | short */

enum
{
	FMOD_CODEC_NONE,
	FMOD_CODEC_PCM8,
	FMOD_CODEC_PCM16,
	FMOD_CODEC_PCM24,
	FMOD_CODEC_PCM32,
	FMOD_CODEC_PCMFLOAT,
	FMOD_CODEC_GCADPCM,
	FMOD_CODEC_IMAADPCM,
	FMOD_CODEC_VAG,
	FMOD_CODEC_HEVAG,
	FMOD_CODEC_XMA,
	FMOD_CODEC_MPEG,
	FMOD_CODEC_CELT,
	FMOD_CODEC_AT9,
	FMOD_CODEC_XWMA,
	FMOD_CODEC_VORBIS,
	FMOD_CODEC_FADPCM,
	FMOD_CODEC_OPUS,
	FMOD_CODEC_COUNT
};

/* extension of the raw stream of each codec */
static const char *const fmod_codec_ext[FMOD_CODEC_COUNT] =
{
	"bin", "pcm8", "pcm16", "pcm24", "pcm32", "pcmf32", "dsp", "ima",
	"vag", "hevag", "xma", "fsb-mpeg", "celt", "at9", "xwma", "vorbis",
	"fadpcm", "opus"
};

/* bits 1..4 of a sample header; 11..15 are rejected by FMOD */
static const grub_uint32_t fmod_rates[] =
{
	4000, 8000, 11000, 11025, 16000, 22050, 24000, 32000, 44100, 48000,
	96000
};

static const unsigned fmod_channels[4] = { 1, 2, 6, 8 };

enum fmod_kind
{
	FMOD_KIND_RAW,
	FMOD_KIND_WAV,
	FMOD_KIND_MP3,
	FMOD_KIND_OGG
};

/* one Ogg page of a remuxed Vorbis stream */
struct fmod_page
{
	grub_uint64_t ogg_off;		/* where the page starts in the .ogg */
	grub_uint64_t granule;
	grub_uint32_t src_off;		/* first length prefix, from the stream */
	grub_uint32_t src_len;		/* the packets with their prefixes */
	grub_uint16_t packets;
	grub_uint8_t segs;		/* lacing values */
	grub_uint8_t type;		/* OGG_BOS / OGG_EOS */
};

struct fmod_setup
{
	grub_uint32_t crc;
	grub_uint32_t size;
	unsigned modes;
	grub_uint64_t blockflags;
	grub_uint8_t *packet;
};

/* A run of adjacent MPEG frames with no FSB padding between them. */
struct fmod_mp3_run
{
	grub_uint32_t src_off;
	grub_uint32_t file_end;
};

struct fmod_sample
{
	char *name;
	grub_uint64_t off;		/* stream start on the disk */
	grub_uint32_t len;		/* stream bytes, alignment padding included */
	grub_uint64_t size;		/* size of the file presented */
	grub_uint32_t rate;
	grub_uint32_t frames;
	unsigned channels;
	unsigned codec;
	unsigned big_endian:1;
	unsigned has_setup:1;
	grub_uint32_t setup_crc;
	enum fmod_kind kind;

	/* FMOD_KIND_WAV */
	grub_uint32_t wav_len;

	struct fmod_mp3_run *runs;
	unsigned num_runs;

	/* FMOD_KIND_OGG */
	int setup;
	grub_uint32_t head_len;
	struct fmod_page *pages;
	grub_uint32_t num_pages;
};

struct fmod_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct fmod_sample *samples;
	unsigned num_samples;
	unsigned max_samples;
	struct fmod_setup *setups;
	unsigned num_setups;
};

struct fmod_file
{
	grub_disk_t disk;
	enum fmod_kind kind;
	grub_uint64_t off;
	grub_uint8_t *head;
	grub_uint32_t head_len;
	unsigned wav_pad;
	struct fmod_mp3_run *runs;
	unsigned num_runs;

	/* FMOD_KIND_OGG */
	struct fmod_page *pages;
	grub_uint32_t num_pages;
	grub_uint32_t serial;
	grub_uint8_t *src;		/* packets of the page being built */
	grub_uint8_t *page;		/* the page last built */
	grub_uint32_t page_len;
	grub_uint32_t cur;		/* index of that page, num_pages if none */
};

static grub_uint32_t fmod_ogg_crc_table[256];
static grub_uint32_t fmod_zip_crc_table[256];

static void
fmod_crc_init (void)
{
	unsigned i, j;

	for (i = 0; i < 256; i++)
	{
		grub_uint32_t ogg = (grub_uint32_t) i << 24;
		grub_uint32_t zip = i;

		for (j = 0; j < 8; j++)
		{
			ogg = (ogg & 0x80000000) ? (ogg << 1) ^ 0x04c11db7 : ogg << 1;
			zip = (zip & 1) ? (zip >> 1) ^ 0xedb88320 : zip >> 1;
		}
		fmod_ogg_crc_table[i] = ogg;
		fmod_zip_crc_table[i] = zip;
	}
}

static grub_uint32_t
fmod_ogg_crc (const grub_uint8_t *buf, grub_size_t len)
{
	grub_uint32_t crc = 0;

	while (len--)
		crc = (crc << 8) ^ fmod_ogg_crc_table[(crc >> 24) ^ *buf++];
	return crc;
}

static grub_uint32_t
fmod_zip_crc (const grub_uint8_t *buf, grub_size_t len)
{
	grub_uint32_t crc = 0xffffffff;

	while (len--)
		crc = (crc >> 8) ^ fmod_zip_crc_table[(crc ^ *buf++) & 0xff];
	return crc ^ 0xffffffff;
}

static grub_uint16_t
fmod_le16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) (p[0] | (p[1] << 8));
}

static grub_uint32_t
fmod_le32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8)
	       | ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

static grub_uint64_t
fmod_le64 (const grub_uint8_t *p)
{
	return (grub_uint64_t) fmod_le32 (p)
	       | ((grub_uint64_t) fmod_le32 (p + 4) << 32);
}

static void
fmod_put16 (grub_uint8_t *p, grub_uint32_t val)
{
	p[0] = (grub_uint8_t) val;
	p[1] = (grub_uint8_t) (val >> 8);
}

static void
fmod_put32 (grub_uint8_t *p, grub_uint32_t val)
{
	p[0] = (grub_uint8_t) val;
	p[1] = (grub_uint8_t) (val >> 8);
	p[2] = (grub_uint8_t) (val >> 16);
	p[3] = (grub_uint8_t) (val >> 24);
}

static void
fmod_put64 (grub_uint8_t *p, grub_uint64_t val)
{
	fmod_put32 (p, (grub_uint32_t) val);
	fmod_put32 (p + 4, (grub_uint32_t) (val >> 32));
}

static grub_err_t
fmod_read (struct fmod_data *data, grub_uint64_t off, grub_size_t len,
	   void *buf)
{
	if (off > data->disk_size || data->disk_size - off < len)
		return grub_error (GRUB_ERR_BAD_FS, "FMOD sound bank truncated");
	return grub_disk_read (data->disk, 0, off, len, buf);
}

static void
fmod_free_data (struct fmod_data *data)
{
	unsigned i;

	for (i = 0; i < data->num_samples; i++)
	{
		grub_free (data->samples[i].name);
		grub_free (data->samples[i].pages);
		grub_free (data->samples[i].runs);
	}
	for (i = 0; i < data->num_setups; i++)
		grub_free (data->setups[i].packet);
	grub_free (data->samples);
	grub_free (data->setups);
	grub_free (data);
}

static struct fmod_sample *
fmod_new_sample (struct fmod_data *data)
{
	struct fmod_sample *s;

	if (data->num_samples == data->max_samples)
	{
		unsigned max = data->max_samples ? data->max_samples * 2 : 64;

		s = grub_realloc (data->samples, max * sizeof (*s));
		if (!s)
			return 0;
		data->samples = s;
		data->max_samples = max;
	}
	s = &data->samples[data->num_samples++];
	grub_memset (s, 0, sizeof (*s));
	s->setup = -1;
	return s;
}

/* FSB5 sound banks */

static void
fmod_sample_ext (struct fmod_sample *s, const grub_uint8_t *p,
		 grub_uint32_t type, grub_uint32_t size)
{
	switch (type)
	{
	case 0x01:	/* channel count */
		if (size >= 1)
			s->channels = p[0];
		break;
	case 0x02:	/* sample rate */
		if (size >= 4)
			s->rate = fmod_le32 (p);
		break;
	case 0x0b:	/* Vorbis setup id, then the seek table */
		if (size >= 4)
		{
			s->setup_crc = fmod_le32 (p);
			s->has_setup = 1;
		}
		break;
	case 0x0e:	/* Vorbis intra layers: one N channel stream */
		if (size >= 4)
		{
			grub_uint32_t layers = fmod_le32 (p);

			s->channels = (layers > 0 && layers <= 255)
				      ? s->channels * layers : 0;
		}
		break;
	default:
		break;
	}
}

/* *OUT stays NULL for a subsound the name table does not name */
static grub_err_t
fmod_sample_name (const grub_uint8_t *names, grub_uint32_t names_len,
		  unsigned index, char **out)
{
	grub_uint32_t off, end;
	char *name;
	unsigned i;

	*out = 0;
	if (!names || (grub_uint64_t) index * 4 + 4 > names_len)
		return GRUB_ERR_NONE;
	off = fmod_le32 (names + (grub_size_t) index * 4);
	if (off >= names_len)
		return GRUB_ERR_NONE;
	for (end = off; end < names_len && end - off < FMOD_NAME_MAX && names[end]; end++)
		;
	if (end == off)
		return GRUB_ERR_NONE;

	name = grub_malloc (end - off + 1);
	if (!name)
		return grub_errno;
	grub_memcpy (name, names + off, end - off);
	name[end - off] = '\0';
	for (i = 0; name[i]; i++)
		if ((grub_uint8_t) name[i] < 0x20 || name[i] == '/'
		    || name[i] == '\\')
			name[i] = '_';
	*out = name;
	return GRUB_ERR_NONE;
}

/* adds the subsounds of the FSB5 at [BASE, BASE + LIMIT) */
static grub_err_t
fmod_scan_fsb (struct fmod_data *data, grub_uint64_t base, grub_uint64_t limit)
{
	grub_uint8_t hd[FMOD_FSB_V0_HEAD];
	grub_uint8_t *table = 0, *names = 0;
	grub_uint32_t version, count, table_len, names_len, data_len, codec;
	grub_uint32_t flags, head_len, pos, i;
	grub_uint64_t data_base;
	unsigned first = data->num_samples;
	grub_err_t err;

	if (limit < FMOD_FSB_V1_HEAD)
		return grub_error (GRUB_ERR_BAD_FS, "FSB5 header truncated");
	err = fmod_read (data, base, FMOD_FSB_V1_HEAD, hd);
	if (err)
		return err;
	if (grub_memcmp (hd, "FSB5", 4) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "not an FSB5 sound bank");

	version = fmod_le32 (hd + 0x04);
	count = fmod_le32 (hd + 0x08);
	table_len = fmod_le32 (hd + 0x0c);
	names_len = fmod_le32 (hd + 0x10);
	data_len = fmod_le32 (hd + 0x14);
	codec = fmod_le32 (hd + 0x18);
	if (version > 1)
		return grub_error (GRUB_ERR_BAD_FS,
				   "unsupported FSB5 version %u", version);
	flags = version ? fmod_le32 (hd + 0x20) : 0;
	head_len = version ? FMOD_FSB_V1_HEAD : FMOD_FSB_V0_HEAD;

	if ((grub_uint64_t) head_len + table_len + names_len + data_len > limit
	    || table_len > FMOD_MAX_TABLE || names_len > FMOD_MAX_TABLE
	    || count > table_len / 8)
		return grub_error (GRUB_ERR_BAD_FS, "corrupt FSB5 header");
	if (count == 0)
		return GRUB_ERR_NONE;
	if (codec >= FMOD_CODEC_COUNT)
		codec = FMOD_CODEC_NONE;

	table = grub_malloc (table_len);
	if (!table)
		return grub_errno;
	err = fmod_read (data, base + head_len, table_len, table);
	if (err)
		goto fail;
	if (names_len)
	{
		names = grub_malloc (names_len);
		if (!names)
		{
			err = grub_errno;
			goto fail;
		}
		err = fmod_read (data, base + head_len + table_len, names_len,
				 names);
		if (err)
			goto fail;
	}
	data_base = base + head_len + table_len + names_len;

	for (i = 0, pos = 0; i < count; i++)
	{
		struct fmod_sample *s;
		grub_uint64_t mode;
		unsigned rate;
		int more;

		if (table_len - pos < 8)
			goto corrupt;
		mode = fmod_le64 (table + pos);
		pos += 8;

		s = fmod_new_sample (data);
		if (!s)
		{
			err = grub_errno;
			goto fail;
		}
		s->codec = codec;
		s->big_endian = (flags & 1) != 0;
		s->frames = (grub_uint32_t) ((mode >> 34) & 0x3fffffff);
		/* the stream offset, relative to the data section until below */
		s->off = ((mode >> 7) & 0x07ffffff) << 5;
		s->channels = fmod_channels[(mode >> 5) & 3];
		rate = (unsigned) ((mode >> 1) & 0x0f);
		s->rate = (rate < ARRAY_SIZE (fmod_rates)) ? fmod_rates[rate] : 0;

		for (more = (int) (mode & 1); more; )
		{
			grub_uint32_t ext, size;

			if (table_len - pos < 4)
				goto corrupt;
			ext = fmod_le32 (table + pos);
			pos += 4;
			more = (int) (ext & 1);
			size = (ext >> 1) & 0xffffff;
			if (size > table_len - pos)
				goto corrupt;
			fmod_sample_ext (s, table + pos, (ext >> 25) & 0x7f,
					 size);
			pos += size;
		}

		err = fmod_sample_name (names, names_len, i, &s->name);
		if (err)
			goto fail;
	}

	/* a stream runs up to where the next one starts */
	for (i = first; i < data->num_samples; i++)
	{
		struct fmod_sample *s = &data->samples[i];
		grub_uint64_t next = (i + 1 < data->num_samples)
				     ? data->samples[i + 1].off : data_len;

		if (s->off > data_len || next > data_len || next < s->off)
			goto corrupt;
		s->len = (grub_uint32_t) (next - s->off);
		s->off += data_base;
	}

	grub_free (table);
	grub_free (names);
	return GRUB_ERR_NONE;

corrupt:
	err = grub_error (GRUB_ERR_BAD_FS, "corrupt FSB5 sample headers");
fail:
	grub_free (table);
	grub_free (names);
	return err;
}

/* FMOD Studio banks: RIFF "FEV " with LIST "PROJ" */

static grub_err_t
fmod_parse_bank (struct fmod_data *data, const grub_uint8_t *hd)
{
	grub_uint64_t riff_end, pos, proj = 0, proj_end = 0;
	grub_uint64_t sndh = 0;
	grub_uint32_t sndh_len = 0, version = 0, entry_len, entries, i;
	grub_uint8_t ch[12], *table = 0;
	grub_err_t err;

	riff_end = 8 + (grub_uint64_t) fmod_le32 (hd + 4);
	if (riff_end > data->disk_size)
		riff_end = data->disk_size;

	for (pos = 12; pos + 8 <= riff_end; )
	{
		grub_uint32_t size;

		err = fmod_read (data, pos, 12, ch);
		if (err)
			return err;
		size = fmod_le32 (ch + 4);
		if (grub_memcmp (ch, "FMT ", 4) == 0 && size >= 4)
			version = fmod_le32 (ch + 8);
		else if (grub_memcmp (ch, "LIST", 4) == 0 && size >= 4
			 && grub_memcmp (ch + 8, "PROJ", 4) == 0)
		{
			proj = pos + 12;
			proj_end = pos + 8 + size;
			break;
		}
		pos += 8 + (grub_uint64_t) size;
	}
	if (!proj || proj_end > riff_end)
		return grub_error (GRUB_ERR_BAD_FS, "not an FMOD sound bank");

	/* event-only .fev files carry OBCT here instead of BNKI */
	for (pos = proj; pos + 8 <= proj_end; )
	{
		grub_uint32_t size;

		err = fmod_read (data, pos, 12, ch);
		if (err)
			return err;
		size = fmod_le32 (ch + 4);
		if (pos == proj && grub_memcmp (ch, "BNKI", 4) != 0)
			return grub_error (GRUB_ERR_BAD_FS,
					   "not an FMOD sound bank");
		if (grub_memcmp (ch, "SNDH", 4) == 0)
		{
			sndh = pos + 8;
			sndh_len = size;
			break;
		}
		if (grub_memcmp (ch, "LIST", 4) == 0 && size >= 12)
		{
			grub_uint8_t sub[8];

			err = fmod_read (data, pos + 12, 8, sub);
			if (err)
				return err;
			if (grub_memcmp (sub, "SNDH", 4) == 0)
			{
				sndh = pos + 20;
				sndh_len = fmod_le32 (sub + 4);
				break;
			}
		}
		pos += 8 + (grub_uint64_t) size;
	}

	/* banks with events but no audio (Master.strings.bank) are empty */
	entry_len = (version <= 0x28) ? 4 : 8;
	if (!sndh || sndh_len < 4 + entry_len)
		return GRUB_ERR_NONE;
	if (sndh_len > FMOD_MAX_SNDH || sndh + sndh_len > proj_end)
		return grub_error (GRUB_ERR_BAD_FS, "corrupt FMOD SNDH chunk");

	table = grub_malloc (sndh_len);
	if (!table)
		return grub_errno;
	err = fmod_read (data, sndh, sndh_len, table);
	if (err)
		goto fail;

	entries = (sndh_len - 4) / entry_len;
	for (i = 0; i < entries; i++)
	{
		const grub_uint8_t *ent = table + 4 + (grub_size_t) i * entry_len;
		grub_uint64_t off = fmod_le32 (ent), len;
		grub_uint8_t magic[4];

		if (entry_len == 8)
			len = fmod_le32 (ent + 4);
		else
			len = data->disk_size - off;	/* checked again below */
		if (off > data->disk_size || len > data->disk_size - off)
		{
			err = grub_error (GRUB_ERR_BAD_FS,
					  "corrupt FMOD SNDH chunk");
			goto fail;
		}
		err = fmod_read (data, off, 4, magic);
		if (err)
			goto fail;
		if (grub_memcmp (magic, "FSB5", 4) != 0)
		{
			err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
					  "encrypted FMOD sound banks are not supported");
			goto fail;
		}
		err = fmod_scan_fsb (data, off, len);
		if (err)
			goto fail;
	}

fail:
	grub_free (table);
	return err;
}

/* Vorbis setup packets */

static int
fmod_table_find (grub_uint32_t crc)
{
	int lo = 0, hi = FMOD_VORBIS_COUNT - 1;

	while (lo <= hi)
	{
		int mid = (lo + hi) / 2;

		if (fmod_vorbis_setups[mid].crc == crc)
			return mid;
		if (fmod_vorbis_setups[mid].crc < crc)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return -1;
}

static int
fmod_setup_find (struct fmod_data *data, grub_uint32_t crc)
{
	unsigned i;

	for (i = 0; i < data->num_setups; i++)
		if (data->setups[i].crc == crc)
			return (int) i;
	return -1;
}

/*
 * Copies out the setup packets the Vorbis streams of DATA name.  The table
 * is only unpacked when at least one of them is known; a packet that does
 * not match its CRC is left out, which turns its streams raw.
 */
static grub_err_t
fmod_load_setups (struct fmod_data *data)
{
	struct xz_dec *dec;
	struct xz_buf buf;
	grub_uint8_t *raw;
	enum xz_ret ret;
	unsigned i, wanted = 0;

	for (i = 0; i < data->num_samples; i++)
	{
		struct fmod_sample *s = &data->samples[i];

		if (s->codec == FMOD_CODEC_VORBIS && s->has_setup
		    && fmod_table_find (s->setup_crc) >= 0)
			wanted++;
	}
	if (!wanted)
		return GRUB_ERR_NONE;

	data->setups = grub_calloc (wanted, sizeof (*data->setups));
	if (!data->setups)
		return grub_errno;
	raw = grub_malloc (FMOD_VORBIS_RAW_SIZE);
	if (!raw)
		return grub_errno;

	/* single-call mode: the output buffer doubles as the dictionary */
	dec = xz_dec_init (0);
	if (!dec)
	{
		grub_free (raw);
		return grub_errno ? grub_errno
				  : grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
	}
	buf.in = fmod_vorbis_xz;
	buf.in_pos = 0;
	buf.in_size = sizeof (fmod_vorbis_xz);
	buf.out = raw;
	buf.out_pos = 0;
	buf.out_size = FMOD_VORBIS_RAW_SIZE;
	ret = xz_dec_run (dec, &buf);
	xz_dec_end (dec);
	if (ret != XZ_STREAM_END || buf.out_pos != FMOD_VORBIS_RAW_SIZE)
	{
		grub_free (raw);
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				   "corrupt FMOD Vorbis setup table");
	}

	for (i = 0; i < data->num_samples; i++)
	{
		struct fmod_sample *s = &data->samples[i];
		const struct fmod_vorbis_setup *ent;
		struct fmod_setup *setup;
		int idx;

		if (s->codec != FMOD_CODEC_VORBIS || !s->has_setup
		    || fmod_setup_find (data, s->setup_crc) >= 0)
			continue;
		idx = fmod_table_find (s->setup_crc);
		if (idx < 0)
			continue;
		ent = &fmod_vorbis_setups[idx];
		if (fmod_zip_crc (raw + ent->off, ent->size) != ent->crc)
			continue;

		setup = &data->setups[data->num_setups];
		setup->packet = grub_malloc (ent->size);
		if (!setup->packet)
		{
			grub_free (raw);
			return grub_errno;
		}
		grub_memcpy (setup->packet, raw + ent->off, ent->size);
		setup->crc = ent->crc;
		setup->size = ent->size;
		setup->modes = ent->modes;
		setup->blockflags = ent->blockflags;
		data->num_setups++;
	}

	grub_free (raw);
	return GRUB_ERR_NONE;
}

/* Ogg remuxing */

static grub_uint32_t
fmod_lacing (grub_uint32_t len)
{
	return len / 255 + 1;
}

/* the BOS page with the identification packet, then comment + setup */
static grub_uint32_t
fmod_head_len (const struct fmod_setup *setup)
{
	return OGG_PAGE_HEAD + 1 + VORBIS_ID_LEN
	       + OGG_PAGE_HEAD + fmod_lacing (VORBIS_COMMENT_LEN)
	       + fmod_lacing (setup->size) + VORBIS_COMMENT_LEN + setup->size;
}

struct fmod_scan
{
	grub_uint8_t *buf;
	grub_uint32_t off;		/* stream offset of buf[0] */
	grub_uint32_t len;
};

/* the page being filled while a packet chain is walked */
struct fmod_pager
{
	struct fmod_page *pages;
	grub_uint32_t num;
	grub_uint32_t max;
	grub_uint64_t ogg;		/* .ogg offset of the open page */
	grub_uint64_t granule;		/* after its last packet */
	grub_uint32_t start;		/* stream offset of its first packet */
	grub_uint32_t end;
	grub_uint32_t segs;
	grub_uint32_t body;
	grub_uint32_t packets;
};

static grub_err_t
fmod_pager_flush (struct fmod_pager *pg)
{
	struct fmod_page *page;

	if (pg->num == pg->max)
	{
		grub_uint32_t max = pg->max ? pg->max * 2 : 256;

		page = grub_realloc (pg->pages, (grub_size_t) max * sizeof (*page));
		if (!page)
			return grub_errno;
		pg->pages = page;
		pg->max = max;
	}
	page = &pg->pages[pg->num++];
	page->ogg_off = pg->ogg;
	page->granule = pg->granule;
	page->src_off = pg->start;
	page->src_len = pg->end - pg->start;
	page->packets = (grub_uint16_t) pg->packets;
	page->segs = (grub_uint8_t) pg->segs;
	page->type = 0;

	pg->ogg += OGG_PAGE_HEAD + pg->segs + pg->body;
	pg->start = pg->end;
	pg->segs = 0;
	pg->body = 0;
	pg->packets = 0;
	return GRUB_ERR_NONE;
}

/*
 * Walks the packet chain of a Vorbis stream and lays it into pages.
 * Returns 1 when the stream remuxes, 0 when it has to stay raw, and -1
 * on a read or allocation failure.
 */
static int
fmod_scan_vorbis (struct fmod_data *data, struct fmod_sample *s,
		  struct fmod_scan *scan)
{
	const struct fmod_setup *setup;
	struct fmod_pager pg;
	grub_uint64_t granule = 0;
	grub_uint32_t pos = 0;
	unsigned mode_bits = 0, prev = 0;
	int idx;

	idx = fmod_setup_find (data, s->setup_crc);
	if (!s->has_setup || idx < 0 || s->channels == 0 || s->channels > 255
	    || s->rate == 0)
		return 0;
	setup = &data->setups[idx];
	while ((1u << mode_bits) < setup->modes)
		mode_bits++;

	grub_memset (&pg, 0, sizeof (pg));
	pg.ogg = fmod_head_len (setup);
	scan->len = 0;
	while (s->len - pos >= 2)
	{
		grub_uint32_t plen, lace, bs;
		grub_uint8_t *p;
		unsigned mode;

		if (pos < scan->off || pos - scan->off + 3 > scan->len)
		{
			grub_uint32_t want = s->len - pos;

			if (want > FMOD_SCAN_BUF)
				want = FMOD_SCAN_BUF;
			if (grub_disk_read (data->disk, 0, s->off + pos, want,
					    scan->buf))
				goto fail;
			scan->off = pos;
			scan->len = want;
		}
		p = scan->buf + (pos - scan->off);

		/* zero or 0xffff ends the chain, as does the end padding */
		plen = fmod_le16 (p);
		if (plen == 0 || plen == 0xffff)
			break;
		if (plen > s->len - pos - 2 || (p[2] & 1))
			goto raw;
		mode = (p[2] >> 1) & ((1u << mode_bits) - 1);
		if (mode >= setup->modes)
			goto raw;
		bs = ((setup->blockflags >> mode) & 1)
		     ? VORBIS_LONG_BLOCK : VORBIS_SHORT_BLOCK;
		lace = fmod_lacing (plen);
		if (lace > OGG_MAX_SEGS)
			goto raw;

		/* the first packet only primes the overlap */
		if (prev)
			granule += prev / 4 + bs / 4;
		prev = bs;

		if (pg.packets && pg.segs + lace > OGG_MAX_SEGS
		    && fmod_pager_flush (&pg))
			goto fail;
		pg.packets++;
		pg.segs += lace;
		pg.body += plen;
		pg.end = pos + 2 + plen;
		pg.granule = granule;
		pos = pg.end;
		if (pg.body >= OGG_PAGE_BODY && fmod_pager_flush (&pg))
			goto fail;
	}
	if (granule < s->frames)
		goto raw;
	if (pg.packets && fmod_pager_flush (&pg))
		goto fail;

	if (pg.num)
	{
		struct fmod_page *last = &pg.pages[pg.num - 1];

		last->type |= OGG_EOS;
		/* end trimming: the stream decodes a little past its length */
		if (s->frames < last->granule
		    && (pg.num == 1 || s->frames >= pg.pages[pg.num - 2].granule))
			last->granule = s->frames;
	}

	s->setup = idx;
	s->head_len = fmod_head_len (setup);
	s->pages = pg.pages;
	s->num_pages = pg.num;
	s->size = pg.ogg;
	return 1;

raw:
	grub_free (pg.pages);
	return 0;
fail:
	grub_free (pg.pages);
	return -1;
}

/* Layer III frame lengths include the MPEG padding bit. FSB alignment is
 * separate and may contain arbitrary bytes between complete frames. */
static unsigned
fmod_mp3_frame_size (const grub_uint8_t *h, const struct fmod_sample *s,
		     unsigned *frame_samples)
{
	static const unsigned rates[] = { 44100, 48000, 32000 };
	static const grub_uint16_t kbps[2][15] =
	{
		{ 0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160 },
		{ 0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320 }
	};
	unsigned version = (h[1] >> 3) & 3, mpeg1 = version == 3;
	unsigned bitrate = h[2] >> 4, rate_index = (h[2] >> 2) & 3;
	unsigned rate;

	if (h[0] != 0xff || (h[1] & 0xe6) != 0xe2 || version == 1
	    || rate_index == 3 || bitrate == 0 || bitrate == 15
	    || ((h[3] >> 6) == 3 ? 1u : 2u) != s->channels)
		return 0;
	rate = rates[rate_index] >> (mpeg1 ? 0 : version == 2 ? 1 : 2);
	if (rate != s->rate)
		return 0;
	*frame_samples = mpeg1 ? 1152 : 576;
	return (mpeg1 ? 144000u : 72000u) * kbps[mpeg1][bitrate] / rate
	       + ((h[2] >> 1) & 1);
}

/* Publish the byte map only after the entire subsound has been checked. */
static grub_err_t
fmod_scan_mp3 (struct fmod_data *data, struct fmod_sample *s, unsigned align)
{
	struct fmod_mp3_run *runs = 0;
	unsigned count = 0, capacity = 0, frame_samples = 0;
	grub_uint32_t pos = 0, file_end = 0;
	grub_uint64_t samples = 0;
	unsigned gap = 0;
	grub_err_t err = GRUB_ERR_NONE;

	while (pos < s->len)
	{
		grub_uint8_t h[4], tail[31];
		grub_uint32_t left = s->len - pos;
		unsigned n = 0;

		if (left >= sizeof (h))
		{
			err = fmod_read (data, s->off + pos, sizeof (h), h);
			if (err)
				goto out;
			n = fmod_mp3_frame_size (h, s, &frame_samples);
		}
		if (!n)
		{
			/* The next subsound starts on a 32-byte boundary. */
			if (left > sizeof (tail))
				goto out;
			err = fmod_read (data, s->off + pos, left, tail);
			if (err)
				goto out;
			while (left)
				if (tail[--left] != 0)
					goto out;
			break;
		}
		if (n > left)
			goto out;
		if (!count || gap)
		{
			if (count == capacity)
			{
				unsigned max = capacity ? capacity * 2 : 16;
				struct fmod_mp3_run *p = grub_realloc (runs, max * sizeof (*p));

				if (!p)
				{
					err = grub_errno;
					goto out;
				}
				runs = p;
				capacity = max;
			}
			runs[count++].src_off = pos;
		}
		file_end += n;
		runs[count - 1].file_end = file_end;
		samples += frame_samples;
		gap = (0u - n) & (align - 1);
		pos += n + grub_min (gap, left - n);
	}
	if (count && samples >= s->frames)
	{
		s->runs = runs;
		s->num_runs = count;
		s->size = file_end;
		s->kind = FMOD_KIND_MP3;
		return GRUB_ERR_NONE;
	}
out:
	grub_free (runs);
	return err;
}

static void
fmod_prepare_pcm (struct fmod_sample *s)
{
	static const unsigned bits[] = { 0, 8, 16, 24, 32, 32 };
	grub_uint64_t block, len;

	if (s->channels == 0 || s->rate == 0
	    || (s->codec == FMOD_CODEC_PCM16 && s->big_endian))
		return;
	block = (grub_uint64_t) s->channels * bits[s->codec] / 8;
	len = (grub_uint64_t) s->frames * block;
	if (len > s->len)
		len = s->len - s->len % block;
	if (FMOD_WAV_HEAD - 8 + len + (len & 1) > GRUB_UINT_MAX)
		return;
	s->kind = FMOD_KIND_WAV;
	s->wav_len = (grub_uint32_t) len;
	s->size = FMOD_WAV_HEAD + len + (len & 1);
}

static const char *
fmod_sample_ext_name (const struct fmod_sample *s)
{
	switch (s->kind)
	{
	case FMOD_KIND_WAV:
		return "wav";
	case FMOD_KIND_MP3:
		return "mp3";
	case FMOD_KIND_OGG:
		return "ogg";
	default:
		return fmod_codec_ext[s->codec];
	}
}

static grub_uint32_t
fmod_name_hash (const char *name)
{
	grub_uint32_t hash = 2166136261u;

	for (; *name; name++)
		hash = (hash ^ (grub_uint32_t) grub_tolower ((grub_uint8_t) *name))
		       * 16777619u;
	return hash;
}

/* Reserve room for the complete suffix and never split a UTF-8 character. */
static char *
fmod_file_name (const char *base, const char *ext, unsigned tries)
{
	char suffix[32], *name;
	grub_size_t len = grub_strlen (base), suffix_len;

	if (tries)
		grub_snprintf (suffix, sizeof (suffix), "_%u.%s", tries, ext);
	else
		grub_snprintf (suffix, sizeof (suffix), ".%s", ext);
	suffix_len = grub_strlen (suffix);
	if (len > FMOD_NAME_MAX - suffix_len)
	{
		len = FMOD_NAME_MAX - suffix_len;
		while (len && ((grub_uint8_t) base[len] & 0xc0) == 0x80)
			len--;
	}
	name = grub_malloc (len + suffix_len + 1);
	if (name)
	{
		grub_memcpy (name, base, len);
		grub_memcpy (name + len, suffix, suffix_len + 1);
	}
	return name;
}

/*
 * Gives every sample a "<name>.<ext>" file name, unique without regard to
 * case so that extraction to a Windows directory cannot collide.
 */
static grub_err_t
fmod_name_samples (struct fmod_data *data)
{
	unsigned *slots, mask = 15, i;
	grub_err_t err = GRUB_ERR_NONE;

	while (mask < data->num_samples * 2)
		mask = mask * 2 + 1;
	slots = grub_calloc ((grub_size_t) mask + 1, sizeof (*slots));
	if (!slots)
		return grub_errno;

	for (i = 0; i < data->num_samples; i++)
	{
		struct fmod_sample *s = &data->samples[i];
		const char *ext = fmod_sample_ext_name (s);
		const char *base = s->name;
		char num[12], *name;
		unsigned tries;

		/* unnamed subsounds go by their index */
		if (!base)
		{
			grub_snprintf (num, sizeof (num), "%u", i);
			base = num;
		}
		for (tries = 0; ; tries++)
		{
			grub_uint32_t slot;
			int clash = 0;

			name = fmod_file_name (base, ext, tries);
			if (!name)
			{
				err = grub_errno;
				goto out;
			}

			for (slot = fmod_name_hash (name) & mask; slots[slot];
			     slot = (slot + 1) & mask)
				if (grub_strcasecmp (data->samples[slots[slot] - 1].name,
						     name) == 0)
				{
					clash = 1;
					break;
				}
			if (!clash)
			{
				slots[slot] = i + 1;
				break;
			}
			grub_free (name);
		}
		grub_free (s->name);
		s->name = name;
	}

out:
	grub_free (slots);
	return err;
}

static grub_err_t
fmod_prepare (struct fmod_data *data)
{
	struct fmod_scan scan;
	unsigned i;
	grub_err_t err;

	err = fmod_load_setups (data);
	if (err)
		return err;

	scan.buf = 0;
	scan.off = 0;
	scan.len = 0;
	for (i = 0; i < data->num_samples; i++)
	{
		struct fmod_sample *s = &data->samples[i];

		s->kind = FMOD_KIND_RAW;
		s->size = s->len;
		switch (s->codec)
		{
		case FMOD_CODEC_PCM8:
		case FMOD_CODEC_PCM16:
		case FMOD_CODEC_PCM24:
		case FMOD_CODEC_PCM32:
		case FMOD_CODEC_PCMFLOAT:
			fmod_prepare_pcm (s);
			break;
		case FMOD_CODEC_MPEG:
			if (s->channels == 1 || s->channels == 2)
			{
				err = fmod_scan_mp3 (data, s, 4);
				if (!err && s->kind == FMOD_KIND_RAW)
					err = fmod_scan_mp3 (data, s, 1);
				if (err)
				{
					grub_free (scan.buf);
					return err;
				}
			}
			break;
		case FMOD_CODEC_VORBIS:
			if (!scan.buf)
			{
				scan.buf = grub_malloc (FMOD_SCAN_BUF);
				if (!scan.buf)
					return grub_errno;
			}
			switch (fmod_scan_vorbis (data, s, &scan))
			{
			case 1:
				s->kind = FMOD_KIND_OGG;
				break;
			case -1:
				grub_free (scan.buf);
				return grub_errno;
			default:
				break;
			}
			break;
		default:
			break;
		}
	}
	grub_free (scan.buf);

	return fmod_name_samples (data);
}

static grub_err_t
fmod_parse (struct fmod_data *data)
{
	grub_uint8_t hd[12];
	grub_err_t err;

	if (data->disk_size < sizeof (hd)
	    || grub_disk_read (data->disk, 0, 0, sizeof (hd), hd))
		return grub_error (GRUB_ERR_BAD_FS, "not an FMOD sound bank");

	if (grub_memcmp (hd, "FSB5", 4) == 0)
		err = fmod_scan_fsb (data, 0, data->disk_size);
	else if (grub_memcmp (hd, "RIFF", 4) == 0
		 && grub_memcmp (hd + 8, "FEV ", 4) == 0)
		err = fmod_parse_bank (data, hd);
	else
		return grub_error (GRUB_ERR_BAD_FS, "not an FMOD sound bank");
	if (err)
		return err;
	return fmod_prepare (data);
}

/*
 * Mount cache.  One slot: the GUI sizes a directory listing by opening every
 * entry in turn, and each mount of a Vorbis bank reads all of its packet
 * headers, so the parsed bank stays around for the next call.
 */

struct fmod_cache
{
	char *name;
	unsigned long id;
	grub_disk_addr_t start;
	grub_uint64_t size;
	grub_size_t siglen;
	grub_uint8_t sig[FMOD_SIG_SIZE];
	struct fmod_data *data;
};

static struct fmod_cache fmod_cache;

static void
fmod_cache_clear (void)
{
	if (fmod_cache.data)
		fmod_free_data (fmod_cache.data);
	grub_free (fmod_cache.name);
	grub_memset (&fmod_cache, 0, sizeof (fmod_cache));
}

static struct fmod_data *
fmod_mount (grub_disk_t disk)
{
	struct fmod_data *data;
	grub_uint8_t sig[FMOD_SIG_SIZE];
	grub_uint64_t sectors, size;
	grub_disk_addr_t start = grub_partition_get_start (disk->partition);
	grub_size_t siglen;
	char *name;

	sectors = grub_disk_native_sectors (disk);
	size = (sectors == GRUB_DISK_SIZE_UNKNOWN)
	       ? GRUB_DISK_SIZE_UNKNOWN : sectors << GRUB_DISK_SECTOR_BITS;
	siglen = (size < FMOD_SIG_SIZE) ? (grub_size_t) size : FMOD_SIG_SIZE;
	if (siglen < 12 || grub_disk_read (disk, 0, 0, siglen, sig))
	{
		grub_error (GRUB_ERR_BAD_FS, "not an FMOD sound bank");
		return 0;
	}
	/* cheap rejection before the cache or any allocation */
	if (grub_memcmp (sig, "FSB5", 4) != 0
	    && (grub_memcmp (sig, "RIFF", 4) != 0
		|| grub_memcmp (sig + 8, "FEV ", 4) != 0))
	{
		grub_error (GRUB_ERR_BAD_FS, "not an FMOD sound bank");
		return 0;
	}

	if (fmod_cache.data && fmod_cache.id == disk->id && fmod_cache.start == start
	    && fmod_cache.size == size && fmod_cache.siglen == siglen
	    && grub_memcmp (fmod_cache.sig, sig, siglen) == 0
	    && grub_strcmp (fmod_cache.name, disk->name) == 0)
	{
		fmod_cache.data->disk = disk;
		return fmod_cache.data;
	}

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return 0;
	data->disk = disk;
	data->disk_size = size;
	if (fmod_parse (data))
	{
		grub_err_t err = grub_errno;

		fmod_free_data (data);
		grub_errno = err ? err : GRUB_ERR_BAD_FS;
		return 0;
	}

	/* caching is an optimisation: carry on uncached when out of memory */
	name = grub_strdup (disk->name);
	if (!name)
	{
		grub_errno = GRUB_ERR_NONE;
		return data;
	}
	fmod_cache_clear ();
	fmod_cache.name = name;
	fmod_cache.id = disk->id;
	fmod_cache.start = start;
	fmod_cache.size = size;
	fmod_cache.siglen = siglen;
	grub_memcpy (fmod_cache.sig, sig, siglen);
	fmod_cache.data = data;
	return data;
}

static void
fmod_unmount (struct fmod_data *data)
{
	if (data != fmod_cache.data)
		fmod_free_data (data);
}

static const char *
fmod_skip_slashes (const char *path)
{
	while (*path == '/')
		path++;
	return path;
}

static int
fmod_find (struct fmod_data *data, const char *path)
{
	unsigned i;

	path = fmod_skip_slashes (path);
	for (i = 0; i < data->num_samples; i++)
		if (grub_strcmp (data->samples[i].name, path) == 0)
			return (int) i;
	return -1;
}

static grub_err_t
grub_fmod_dir (grub_device_t device, const char *path,
	       grub_fs_dir_hook_t hook, void *hook_data)
{
	struct fmod_data *data;
	const char *rest;
	grub_err_t err = GRUB_ERR_NONE;
	unsigned i;

	data = fmod_mount (device->disk);
	if (!data)
		return grub_errno;

	rest = fmod_skip_slashes (path);
	if (*rest)
	{
		grub_size_t len = grub_strlen (rest);

		while (len && rest[len - 1] == '/')
			len--;
		for (i = 0; i < data->num_samples; i++)
			if (grub_strncmp (data->samples[i].name, rest, len) == 0
			    && data->samples[i].name[len] == '\0')
				break;
		if (i < data->num_samples)
			err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
					  N_("not a directory"));
		else
			err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
					  N_("file `%s' not found"), path);
		goto out;
	}

	for (i = 0; i < data->num_samples; i++)
	{
		struct grub_dirhook_info info;

		grub_memset (&info, 0, sizeof (info));
		info.inodeset = 1;
		info.inode = i;
		info.sizeset = 1;
		info.size = data->samples[i].size;
		if (hook (data->samples[i].name, &info, hook_data))
			break;
	}

out:
	fmod_unmount (data);
	return err;
}

static void
fmod_page_header (grub_uint8_t *p, grub_uint8_t type, grub_uint64_t granule,
		  grub_uint32_t serial, grub_uint32_t seq, grub_uint32_t segs)
{
	grub_memcpy (p, "OggS", 4);
	p[4] = 0;
	p[5] = type;
	fmod_put64 (p + 6, granule);
	fmod_put32 (p + 14, serial);
	fmod_put32 (p + 18, seq);
	fmod_put32 (p + 22, 0);
	p[26] = (grub_uint8_t) segs;
}

static grub_uint8_t *
fmod_put_lacing (grub_uint8_t *p, grub_uint32_t len)
{
	for (; len >= 255; len -= 255)
		*p++ = 255;
	*p++ = (grub_uint8_t) len;
	return p;
}

/* the two Vorbis header pages, ready to hand out */
static grub_uint8_t *
fmod_build_head (const struct fmod_sample *s, const struct fmod_setup *setup,
		 grub_uint32_t serial)
{
	grub_uint8_t *head, *page, *p;
	grub_uint32_t segs;

	head = grub_malloc (s->head_len);
	if (!head)
		return 0;

	page = head;
	fmod_page_header (page, OGG_BOS, 0, serial, 0, 1);
	p = page + OGG_PAGE_HEAD;
	*p++ = VORBIS_ID_LEN;
	*p++ = 1;
	grub_memcpy (p, "vorbis", 6);
	p += 6;
	fmod_put32 (p, 0);
	p[4] = (grub_uint8_t) s->channels;
	fmod_put32 (p + 5, s->rate);
	fmod_put32 (p + 9, 0);
	fmod_put32 (p + 13, 0);
	fmod_put32 (p + 17, 0);
	p[21] = VORBIS_BLOCK_EXPS;
	p[22] = 1;
	p += 23;
	fmod_put32 (page + 22, fmod_ogg_crc (page, (grub_size_t) (p - page)));

	page = p;
	segs = fmod_lacing (VORBIS_COMMENT_LEN) + fmod_lacing (setup->size);
	fmod_page_header (page, s->num_pages ? 0 : OGG_EOS, 0, serial, 1, segs);
	p = page + OGG_PAGE_HEAD;
	p = fmod_put_lacing (p, VORBIS_COMMENT_LEN);
	p = fmod_put_lacing (p, setup->size);
	*p++ = 3;
	grub_memcpy (p, "vorbis", 6);
	p += 6;
	fmod_put32 (p, VORBIS_VENDOR_LEN);
	grub_memcpy (p + 4, VORBIS_VENDOR, VORBIS_VENDOR_LEN);
	p += 4 + VORBIS_VENDOR_LEN;
	fmod_put32 (p, 0);
	p[4] = 1;
	p += 5;
	grub_memcpy (p, setup->packet, setup->size);
	p += setup->size;
	fmod_put32 (page + 22, fmod_ogg_crc (page, (grub_size_t) (p - page)));
	return head;
}

static grub_uint8_t *
fmod_build_wav (const struct fmod_sample *s)
{
	static const unsigned bits[] = { 0, 8, 16, 24, 32, 32 };
	grub_uint8_t *p;
	grub_uint32_t block = s->channels * bits[s->codec] / 8;

	p = grub_malloc (FMOD_WAV_HEAD);
	if (!p)
		return 0;
	grub_memcpy (p, "RIFF", 4);
	fmod_put32 (p + 4, (grub_uint32_t) (s->size - 8));
	grub_memcpy (p + 8, "WAVEfmt ", 8);
	fmod_put32 (p + 16, 16);
	fmod_put16 (p + 20, (s->codec == FMOD_CODEC_PCMFLOAT) ? 3 : 1);
	fmod_put16 (p + 22, s->channels);
	fmod_put32 (p + 24, s->rate);
	fmod_put32 (p + 28, s->rate * block);
	fmod_put16 (p + 32, block);
	fmod_put16 (p + 34, bits[s->codec]);
	grub_memcpy (p + 36, "data", 4);
	fmod_put32 (p + 40, s->wav_len);
	return p;
}

static void
fmod_file_free (struct fmod_file *ctx)
{
	grub_free (ctx->head);
	grub_free (ctx->runs);
	grub_free (ctx->pages);
	grub_free (ctx->src);
	grub_free (ctx->page);
	grub_free (ctx);
}

static grub_err_t
grub_fmod_open (grub_file_t file, const char *name)
{
	struct fmod_data *data;
	struct fmod_sample *s;
	struct fmod_file *ctx;
	int index;

	data = fmod_mount (file->device->disk);
	if (!data)
		return grub_errno;

	index = fmod_find (data, name);
	if (index < 0)
	{
		fmod_unmount (data);
		return grub_error (GRUB_ERR_FILE_NOT_FOUND,
				   N_("file `%s' not found"), name);
	}
	s = &data->samples[index];

	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
		goto fail;

	/*
	 * Everything the read path needs is copied out: an open file must not
	 * point into the sample list, which the cache may drop.
	 */
	ctx->disk = data->disk;
	ctx->kind = s->kind;
	ctx->off = s->off;
	if (s->kind == FMOD_KIND_WAV)
	{
		ctx->head = fmod_build_wav (s);
		if (!ctx->head)
			goto fail;
		ctx->head_len = FMOD_WAV_HEAD;
		ctx->wav_pad = s->wav_len & 1;
	}
	else if (s->kind == FMOD_KIND_MP3)
	{
		ctx->runs = grub_calloc (s->num_runs, sizeof (*ctx->runs));
		if (!ctx->runs)
			goto fail;
		grub_memcpy (ctx->runs, s->runs, s->num_runs * sizeof (*ctx->runs));
		ctx->num_runs = s->num_runs;
	}
	else if (s->kind == FMOD_KIND_OGG)
	{
		grub_uint32_t i, src_max = 0, page_max = 0;

		ctx->serial = OGG_SERIAL ^ (grub_uint32_t) index;
		ctx->head = fmod_build_head (s, &data->setups[s->setup],
					     ctx->serial);
		if (!ctx->head)
			goto fail;
		ctx->head_len = s->head_len;
		ctx->num_pages = s->num_pages;
		ctx->cur = s->num_pages;
		if (s->num_pages)
		{
			ctx->pages = grub_calloc (s->num_pages,
						  sizeof (*ctx->pages));
			if (!ctx->pages)
				goto fail;
			grub_memcpy (ctx->pages, s->pages,
				     s->num_pages * sizeof (*ctx->pages));
			for (i = 0; i < s->num_pages; i++)
			{
				const struct fmod_page *pg = &s->pages[i];
				grub_uint32_t len = OGG_PAGE_HEAD + pg->segs
						    + pg->src_len - 2u * pg->packets;

				if (pg->src_len > src_max)
					src_max = pg->src_len;
				if (len > page_max)
					page_max = len;
			}
			ctx->src = grub_malloc (src_max);
			ctx->page = grub_malloc (page_max);
			if (!ctx->src || !ctx->page)
				goto fail;
		}
	}

	file->data = ctx;
	file->size = s->size;
	fmod_unmount (data);
	return GRUB_ERR_NONE;

fail:
	if (ctx)
		fmod_file_free (ctx);
	fmod_unmount (data);
	return grub_errno;
}

static grub_err_t
fmod_build_page (struct fmod_file *ctx, grub_uint32_t index)
{
	const struct fmod_page *pg = &ctx->pages[index];
	grub_uint8_t *lace, *body;
	grub_uint32_t pos, n;

	if (grub_disk_read (ctx->disk, 0, ctx->off + pg->src_off, pg->src_len,
			    ctx->src))
		return grub_errno;

	fmod_page_header (ctx->page, pg->type, pg->granule, ctx->serial,
			  index + 2, pg->segs);
	lace = ctx->page + OGG_PAGE_HEAD;
	body = lace + pg->segs;
	for (pos = 0, n = 0; n < pg->packets; n++)
	{
		grub_uint32_t plen;

		if (pg->src_len - pos < 2)
			goto changed;
		plen = fmod_le16 (ctx->src + pos);
		if (plen > pg->src_len - pos - 2
		    || (grub_uint32_t) (lace - ctx->page - OGG_PAGE_HEAD)
		       + fmod_lacing (plen) > pg->segs)
			goto changed;
		lace = fmod_put_lacing (lace, plen);
		grub_memcpy (body, ctx->src + pos + 2, plen);
		body += plen;
		pos += 2 + plen;
	}
	if (pos != pg->src_len
	    || lace != ctx->page + OGG_PAGE_HEAD + pg->segs)
		goto changed;

	ctx->page_len = (grub_uint32_t) (body - ctx->page);
	fmod_put32 (ctx->page + 22, fmod_ogg_crc (ctx->page, ctx->page_len));
	ctx->cur = index;
	return GRUB_ERR_NONE;

changed:
	ctx->cur = ctx->num_pages;
	return grub_error (GRUB_ERR_BAD_FS, "FMOD Vorbis stream changed");
}

static grub_ssize_t
fmod_read_ogg (struct fmod_file *ctx, grub_uint64_t off, char *buf,
	       grub_size_t len)
{
	grub_size_t done = 0;

	while (done < len)
	{
		grub_uint32_t lo = 0, hi = ctx->num_pages;
		grub_uint64_t at;
		grub_size_t n;

		/* the file ends with its header pages then: not reached */
		if (ctx->num_pages == 0)
		{
			grub_error (GRUB_ERR_OUT_OF_RANGE, N_("attempt to read past the end of file"));
			return -1;
		}

		/* last page starting at or before OFF */
		while (hi - lo > 1)
		{
			grub_uint32_t mid = lo + (hi - lo) / 2;

			if (ctx->pages[mid].ogg_off <= off)
				lo = mid;
			else
				hi = mid;
		}
		if (ctx->cur != lo && fmod_build_page (ctx, lo))
			return -1;
		at = off - ctx->pages[lo].ogg_off;
		if (at >= ctx->page_len)
		{
			grub_error (GRUB_ERR_BAD_FS, "FMOD Vorbis stream changed");
			return -1;
		}
		n = ctx->page_len - (grub_size_t) at;
		if (n > len - done)
			n = len - done;
		grub_memcpy (buf + done, ctx->page + at, n);
		done += n;
		off += n;
	}
	return (grub_ssize_t) done;
}

static grub_err_t
fmod_read_mp3 (struct fmod_file *ctx, grub_uint32_t off, char *buf, grub_size_t len)
{
	unsigned lo = 0, hi = ctx->num_runs;

	while (lo < hi)
	{
		unsigned mid = lo + (hi - lo) / 2;

		if (ctx->runs[mid].file_end <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	while (len)
	{
		const struct fmod_mp3_run *run = &ctx->runs[lo];
		grub_uint32_t start = lo ? ctx->runs[lo - 1].file_end : 0;
		grub_size_t n = grub_min (len, (grub_size_t) (run->file_end - off));
		grub_err_t err = grub_disk_read (ctx->disk, 0, ctx->off + run->src_off
						+ (off - start), n, buf);

		if (err)
			return err;
		off += (grub_uint32_t) n;
		buf += n;
		len -= n;
		lo++;
	}
	return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_fmod_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct fmod_file *ctx = file->data;
	grub_uint64_t off = file->offset;
	grub_size_t done = 0;

	if (len == 0)
		return 0;

	if (off < ctx->head_len)
	{
		done = ctx->head_len - (grub_size_t) off;
		if (done > len)
			done = len;
		grub_memcpy (buf, ctx->head + off, done);
		off += done;
	}
	if (done < len)
	{
		if (ctx->kind == FMOD_KIND_OGG)
		{
			if (fmod_read_ogg (ctx, off, buf + done, len - done) < 0)
				return -1;
		}
		else if (ctx->kind == FMOD_KIND_MP3)
		{
			if (fmod_read_mp3 (ctx, (grub_uint32_t) off, buf + done, len - done))
				return -1;
		}
		else
		{
			grub_size_t payload = len - done;

			if (ctx->wav_pad && payload == file->size - off)
			{
				buf[len - 1] = 0;
				payload--;
			}
			if (payload && grub_disk_read (ctx->disk, 0,
					ctx->off + off - ctx->head_len, payload, buf + done))
				return -1;
		}
	}

	/*
	 * Nothing above reaches the disk read hook, so report the bytes
	 * handed out here to keep grub_file_progress_hook working.
	 */
	if (file->read_hook)
		file->read_hook (0, 0, (unsigned) len, buf,
				 file->read_hook_data);
	return (grub_ssize_t) len;
}

static grub_err_t
grub_fmod_close (grub_file_t file)
{
	fmod_file_free (file->data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_fmod_fs =
{
	.name = "fmod",
	.fs_dir = grub_fmod_dir,
	.fs_open = grub_fmod_open,
	.fs_read = grub_fmod_read,
	.fs_close = grub_fmod_close,
	.fs_label = 0,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (fmod)
{
	fmod_crc_init ();
	grub_fmod_fs.mod = mod;
	grub_fs_register (&grub_fmod_fs);
}

GRUB_MOD_FINI (fmod)
{
	grub_fs_unregister (&grub_fmod_fs);
	fmod_cache_clear ();
}
