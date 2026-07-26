/*
 *  Rover -- Filesystem browser for Windows
 *  RAR 2.0 decoder, ported to C from 7-Zip 26.02 (Rar2Decoder.cpp).
 *
 *  7-Zip Copyright (C) 1999-2025 Igor Pavlov.
 *  Licensed under the GNU LGPL, with the unRAR license restriction:
 *  this code may not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include "rar_core.h"

#define RAR2_NUM_REPS		4
#define RAR2_DIST_TABLE_SIZE	48
#define RAR2_NUM_LEN2_SYMS	8
#define RAR2_LEN_TABLE_SIZE	28
#define RAR2_MAIN_TABLE_SIZE	(256 + 2 + RAR2_NUM_REPS \
				 + RAR2_NUM_LEN2_SYMS + RAR2_LEN_TABLE_SIZE)
#define RAR2_HEAP_TABLES_SUM	(RAR2_MAIN_TABLE_SIZE + RAR2_DIST_TABLE_SIZE \
				 + RAR2_LEN_TABLE_SIZE)
#define RAR2_MM_TABLE_SIZE	(256 + 1)
#define RAR2_MM_NUM_CHANNELS	4
#define RAR2_MM_TABLES_SUM	(RAR2_MM_TABLE_SIZE * RAR2_MM_NUM_CHANNELS)
#define RAR2_MAX_TABLE_SIZE	RAR2_MM_TABLES_SUM

#define RAR2_HISTORY_SIZE	(1u << 20)

#define kRepBothNumber		256
#define kRepNumber		(kRepBothNumber + 1)
#define kLen2Number		(kRepNumber + RAR2_NUM_REPS)
#define kReadTableNumber	(kLen2Number + RAR2_NUM_LEN2_SYMS)
#define kMatchNumber		(kReadTableNumber + 1)

static const grub_uint32_t kDistStart[RAR2_DIST_TABLE_SIZE] =
{
	0,1,2,3,4,6,8,12,16,24,32,48,64,96,128,192,256,384,512,768,1024,1536,
	2048,3072,4096,6144,8192,12288,16384,24576,32768u,49152u,65536,98304,
	131072,196608,262144,327680,393216,458752,524288,589824,655360,720896,
	786432,851968,917504,983040
};

static const grub_uint8_t kDistDirectBits[RAR2_DIST_TABLE_SIZE] =
{
	0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,
	14,14,15,15,16,16,16,16,16,16,16,16,16,16,16,16,16,16
};

static const grub_uint8_t kLen2DistStarts[RAR2_NUM_LEN2_SYMS] =
	{ 0,4,8,16,32,64,128,192 };
static const grub_uint8_t kLen2DistDirectBits[RAR2_NUM_LEN2_SYMS] =
	{ 2,2,3,4,5,6,6,6 };

#define kDistLimit2	(0x101 - 1)
#define kDistLimit3	(0x2000 - 1)
#define kDistLimit4	(0x40000 - 1)

/* multimedia (audio) filter */
struct rar2_mm_filter
{
	grub_int32_t k1, k2, k3, k4, k5;
	grub_int32_t d1, d2, d3, d4;
	grub_int32_t last_delta;
	grub_uint32_t dif[11];
	grub_uint32_t byte_count;
	grub_int32_t last_char;
};

struct rar2_mm_filter2
{
	struct rar2_mm_filter filters[RAR2_MM_NUM_CHANNELS];
	grub_int32_t channel_delta;
	unsigned current_channel;
};

struct rar2_dec
{
	struct rar_decoder base;

	int is_solid;
	int solid_allowed;
	int tables_ok;
	int audio_mode;
	int item_done;		/* zero-size item, nothing to run */

	struct rar_ow ow;
	struct rar_bitm bi;

	grub_uint32_t rep_dist_ptr;
	grub_uint32_t rep_dists[RAR2_NUM_REPS];
	grub_uint32_t last_length;
	unsigned num_channels;

	struct rar_huff main_dec;
	struct rar_huff dist_dec;
	struct rar_huff len_dec;
	struct rar_huff mm_dec[RAR2_MM_NUM_CHANNELS];

	grub_uint64_t pack_size;
	grub_uint64_t unp_size;
	grub_uint64_t pos;	/* unpacked bytes produced for this item */
	grub_uint64_t start_processed;

	struct rar2_mm_filter2 mm_filter;
	grub_uint8_t last_levels[RAR2_MAX_TABLE_SIZE];
};

#define my_abs(x) ((unsigned) ((x) < 0 ? -(x) : (x)))

static grub_uint8_t
rar2_mm_decode (struct rar2_mm_filter *f, grub_int32_t *channel_delta,
		grub_uint8_t delta_byte)
{
	grub_int32_t predicted_value;
	grub_uint8_t real_value;

	f->d4 = f->d3;
	f->d3 = f->d2;
	f->d2 = f->last_delta - f->d1;
	f->d1 = f->last_delta;
	predicted_value = ((8 * f->last_char + f->k1 * f->d1 + f->k2 * f->d2
			    + f->k3 * f->d3 + f->k4 * f->d4
			    + f->k5 * *channel_delta) >> 3);

	real_value = (grub_uint8_t) (predicted_value - delta_byte);

	{
		const grub_int32_t i = ((grub_int32_t) (grub_int8_t) delta_byte) << 3;

		f->dif[0] += my_abs (i);
		f->dif[1] += my_abs (i - f->d1);
		f->dif[2] += my_abs (i + f->d1);
		f->dif[3] += my_abs (i - f->d2);
		f->dif[4] += my_abs (i + f->d2);
		f->dif[5] += my_abs (i - f->d3);
		f->dif[6] += my_abs (i + f->d3);
		f->dif[7] += my_abs (i - f->d4);
		f->dif[8] += my_abs (i + f->d4);
		f->dif[9] += my_abs (i - *channel_delta);
		f->dif[10] += my_abs (i + *channel_delta);
	}

	*channel_delta = f->last_delta =
		(grub_int8_t) (real_value - f->last_char);
	f->last_char = real_value;

	if (((++f->byte_count) & 0x1F) == 0)
	{
		grub_uint32_t min_dif = f->dif[0];
		unsigned num_min_dif = 0;
		unsigned i;

		f->dif[0] = 0;
		for (i = 1; i < 11; i++)
		{
			if (f->dif[i] < min_dif)
			{
				min_dif = f->dif[i];
				num_min_dif = i;
			}
			f->dif[i] = 0;
		}

		switch (num_min_dif)
		{
		case 1: if (f->k1 >= -16) f->k1--; break;
		case 2: if (f->k1 <   16) f->k1++; break;
		case 3: if (f->k2 >= -16) f->k2--; break;
		case 4: if (f->k2 <   16) f->k2++; break;
		case 5: if (f->k3 >= -16) f->k3--; break;
		case 6: if (f->k3 <   16) f->k3++; break;
		case 7: if (f->k4 >= -16) f->k4--; break;
		case 8: if (f->k4 <   16) f->k4++; break;
		case 9: if (f->k5 >= -16) f->k5--; break;
		case 10:if (f->k5 <   16) f->k5++; break;
		}
	}

	return real_value;
}

static void
rar2_init_structures (struct rar2_dec *p)
{
	unsigned i;

	grub_memset (&p->mm_filter, 0, sizeof (p->mm_filter));
	for (i = 0; i < RAR2_NUM_REPS; i++)
		p->rep_dists[i] = 0;
	p->rep_dist_ptr = 0;
	p->last_length = 0;
	grub_memset (p->last_levels, 0, RAR2_MAX_TABLE_SIZE);
}

static grub_uint32_t
rar2_read_bits (struct rar2_dec *p, unsigned numbits)
{
	return rar_bitm_readbits (&p->bi, numbits);
}

static int
rar2_read_tables (struct rar2_dec *p)
{
	grub_uint8_t level_levels[19];
	grub_uint8_t lens[RAR2_MAX_TABLE_SIZE];
	struct rar_huff *level_dec = 0;
	unsigned num_levels;
	unsigned i;
	int ok = 0;

	p->tables_ok = 0;

	p->audio_mode = (rar2_read_bits (p, 1) == 1);

	if (rar2_read_bits (p, 1) == 0)
		grub_memset (p->last_levels, 0, RAR2_MAX_TABLE_SIZE);

	if (p->audio_mode)
	{
		p->num_channels = rar2_read_bits (p, 2) + 1;
		if (p->mm_filter.current_channel >= p->num_channels)
			p->mm_filter.current_channel = 0;
		num_levels = p->num_channels * RAR2_MM_TABLE_SIZE;
	}
	else
		num_levels = RAR2_HEAP_TABLES_SUM;

	level_dec = grub_malloc (sizeof (*level_dec));
	if (!level_dec)
		return RAR_ERR_MEM;

	for (i = 0; i < 19; i++)
		level_levels[i] = (grub_uint8_t) rar2_read_bits (p, 4);
	if (rar_huff_build (level_dec, level_levels, 19, RAR_HUFF_FULL))
		goto fail;

	i = 0;
	do
	{
		int sym = rar_bitm_huff (&p->bi, level_dec);
		if (sym < 0)
			goto fail;
		if (sym < 16)
		{
			lens[i] = (grub_uint8_t) ((sym + p->last_levels[i]) & 15);
			i++;
		}
		else
		{
			unsigned num;
			grub_uint8_t v;
			if (sym == 16)
			{
				if (i == 0)
					goto fail;
				num = rar2_read_bits (p, 2) + 3;
				v = lens[i - 1];
			}
			else
			{
				num = ((unsigned) sym - 17) * 4;
				num += num + 3 + rar2_read_bits (p, 3 + num);
				v = 0;
			}
			num += i;
			if (num > num_levels)
				num = num_levels;	/* original unRAR */
			do
				lens[i++] = v;
			while (i < num);
		}
	}
	while (i < num_levels);

	if (rar_bitm_extra_read (&p->bi))
		goto fail;

	if (p->audio_mode)
	{
		for (i = 0; i < p->num_channels; i++)
			if (rar_huff_build (&p->mm_dec[i],
					    &lens[i * RAR2_MM_TABLE_SIZE],
					    RAR2_MM_TABLE_SIZE,
					    RAR_HUFF_PARTIAL))
				goto fail;
	}
	else
	{
		if (rar_huff_build (&p->main_dec, &lens[0],
				    RAR2_MAIN_TABLE_SIZE, RAR_HUFF_PARTIAL))
			goto fail;
		if (rar_huff_build (&p->dist_dec, &lens[RAR2_MAIN_TABLE_SIZE],
				    RAR2_DIST_TABLE_SIZE, RAR_HUFF_PARTIAL))
			goto fail;
		if (rar_huff_build (&p->len_dec,
				    &lens[RAR2_MAIN_TABLE_SIZE
					  + RAR2_DIST_TABLE_SIZE],
				    RAR2_LEN_TABLE_SIZE, RAR_HUFF_PARTIAL))
			goto fail;
	}

	grub_memcpy (p->last_levels, lens, RAR2_MAX_TABLE_SIZE);

	p->tables_ok = 1;
	ok = 1;

fail:
	grub_free (level_dec);
	return ok ? 0 : RAR_ERR_DATA;
}

static int
rar2_read_last_tables (struct rar2_dec *p)
{
	/*
	 * It differs a little from pure RAR sources: read one symbol
	 * ahead to catch a trailing table update for solid streams.
	 */
	if (rar_bitm_processed (&p->bi) + 7 <= p->pack_size)
	{
		if (p->audio_mode)
		{
			int sym = rar_bitm_huff (&p->bi,
				&p->mm_dec[p->mm_filter.current_channel]);
			if (sym == 256)
				return rar2_read_tables (p);
			if (sym < 0 || sym >= RAR2_MM_TABLE_SIZE)
				return RAR_ERR_DATA;
		}
		else
		{
			int sym = rar_bitm_huff (&p->bi, &p->main_dec);
			if (sym == kReadTableNumber)
				return rar2_read_tables (p);
			if (sym < 0 || sym >= RAR2_MAIN_TABLE_SIZE)
				return RAR_ERR_DATA;
		}
	}
	return 0;
}

/* returns 0 = block done or table-read escape, RAR_ERR_* on error;
   *escape is set when the block ended with the table-read symbol */
static int
rar2_decode_mm (struct rar2_dec *p, grub_uint32_t num, int *escape)
{
	*escape = 0;
	while (num-- != 0)
	{
		int symbol = rar_bitm_huff (&p->bi,
			&p->mm_dec[p->mm_filter.current_channel]);
		grub_uint8_t by_real;

		if (rar_bitm_extra_read (&p->bi))
			return RAR_ERR_DATA;
		if (symbol < 0)
			return RAR_ERR_DATA;
		if (symbol >= 256)
		{
			if (symbol == 256)
			{
				*escape = 1;
				return 0;
			}
			return RAR_ERR_DATA;
		}
		by_real = rar2_mm_decode (
			&p->mm_filter.filters[p->mm_filter.current_channel],
			&p->mm_filter.channel_delta, (grub_uint8_t) symbol);
		rar_ow_put_byte (&p->ow, by_real);
		if (++p->mm_filter.current_channel == p->num_channels)
			p->mm_filter.current_channel = 0;
	}
	return 0;
}

static grub_uint32_t
rar2_slot_to_len (struct rar2_dec *p, grub_uint32_t slot)
{
	const unsigned numbits = ((unsigned) slot >> 2) - 1;
	return ((4 | (slot & 3)) << numbits) + rar2_read_bits (p, numbits);
}

static int
rar2_decode_lz (struct rar2_dec *p, grub_int32_t num, int *escape)
{
	*escape = 0;
	while (num > 0)
	{
		int sym = rar_bitm_huff (&p->bi, &p->main_dec);
		grub_uint32_t len, distance;

		if (rar_bitm_extra_read (&p->bi))
			return RAR_ERR_DATA;
		if (sym < 0)
			return RAR_ERR_DATA;
		if (sym < 256)
		{
			rar_ow_put_byte (&p->ow, (grub_uint8_t) sym);
			num--;
			continue;
		}
		else if (sym >= kMatchNumber)
		{
			int sym2;
			if (sym >= RAR2_MAIN_TABLE_SIZE)
				return RAR_ERR_DATA;
			len = (unsigned) sym - kMatchNumber;
			if (len >= 8)
				len = rar2_slot_to_len (p, len);
			len += 3;

			sym2 = rar_bitm_huff (&p->bi, &p->dist_dec);
			if (sym2 < 0 || sym2 >= RAR2_DIST_TABLE_SIZE)
				return RAR_ERR_DATA;
			distance = kDistStart[sym2]
				   + rar2_read_bits (p, kDistDirectBits[sym2]);
			if (distance >= kDistLimit3)
			{
				len += 2 - ((distance - kDistLimit4) >> 31);
			}
		}
		else if (sym == kRepBothNumber)
		{
			len = p->last_length;
			if (len == 0)
				return RAR_ERR_DATA;
			distance = p->rep_dists[(p->rep_dist_ptr + 4 - 1) & 3];
		}
		else if (sym < kLen2Number)
		{
			int sym2;
			distance = p->rep_dists[(p->rep_dist_ptr
						 - ((unsigned) sym - kRepNumber
						    + 1)) & 3];
			sym2 = rar_bitm_huff (&p->bi, &p->len_dec);
			if (sym2 < 0 || sym2 >= RAR2_LEN_TABLE_SIZE)
				return RAR_ERR_DATA;
			len = (unsigned) sym2;
			if (len >= 8)
				len = rar2_slot_to_len (p, len);
			len += 2;

			if (distance >= kDistLimit2)
			{
				len++;
				if (distance >= kDistLimit3)
				{
					len += 2 - ((distance - kDistLimit4)
						    >> 31);
				}
			}
		}
		else if (sym < kReadTableNumber)
		{
			unsigned s = (unsigned) sym - kLen2Number;
			distance = kLen2DistStarts[s]
				   + rar2_read_bits (p, kLen2DistDirectBits[s]);
			len = 2;
		}
		else	/* sym == kReadTableNumber */
		{
			*escape = 1;
			return 0;
		}

		p->rep_dists[p->rep_dist_ptr++ & 3] = distance;
		p->last_length = len;
		if (rar_ow_copy_block (&p->ow, distance, len))
			return RAR_ERR_DATA;
		num -= len;
	}
	return 0;
}

static int
rar2_start_item (struct rar_decoder *d, const struct rar_dec_props *props)
{
	struct rar2_dec *p = (struct rar2_dec *) d;
	int err;

	p->is_solid = props->solid;
	if (p->is_solid && !p->solid_allowed)
		return RAR_ERR_DATA;
	p->solid_allowed = 0;
	p->item_done = 0;

	err = rar_ow_create (&p->ow, RAR2_HISTORY_SIZE, d);
	if (err)
		return err;
	err = rar_bytein_create (&p->bi.in, 1u << 20);
	if (err)
		return err;

	p->pack_size = props->pack_size;
	p->unp_size = props->unp_size;
	p->pos = 0;

	rar_ow_init (&p->ow, p->is_solid);
	rar_bitm_init (&p->bi, d->read_cb, d->read_opaque);

	if (!p->is_solid)
	{
		rar2_init_structures (p);
		if (p->unp_size == 0)
		{
			if (rar_bitm_processed (&p->bi) + 2 <= p->pack_size)
			{
				err = rar2_read_tables (p);
				if (err)
					return err;
			}
			p->solid_allowed = 1;
			p->item_done = 1;
			return 0;
		}
		rar2_read_tables (p);
	}

	if (!p->tables_ok)
		return RAR_ERR_DATA;

	p->start_processed = rar_ow_processed (&p->ow);
	return 0;
}

static int
rar2_run (struct rar_decoder *d)
{
	struct rar2_dec *p = (struct rar2_dec *) d;
	int err;

	d->pause_req = 0;

	if (p->item_done)
		return RAR_DONE;

	while (p->pos < p->unp_size)
	{
		grub_uint32_t block_size = 1u << 20;
		grub_uint64_t block_start_pos;
		grub_uint64_t global_pos;
		int escape;

		if (d->pause_req)
		{
			d->pause_req = 0;
			return RAR_PAUSED;
		}
		if (p->ow.err)
			return p->ow.err;
		if (p->bi.in.read_err)
			return RAR_ERR_READ;

		if (block_size > p->unp_size - p->pos)
			block_size = (grub_uint32_t) (p->unp_size - p->pos);
		block_start_pos = rar_ow_processed (&p->ow);

		if (p->audio_mode)
			err = rar2_decode_mm (p, block_size, &escape);
		else
			err = rar2_decode_lz (p, (grub_int32_t) block_size,
					      &escape);
		if (err)
			return err;

		if (rar_bitm_extra_read (&p->bi))
			return RAR_ERR_DATA;

		global_pos = rar_ow_processed (&p->ow);
		if (global_pos - block_start_pos < block_size)
		{
			err = rar2_read_tables (p);
			if (err)
				return err;
		}
		p->pos = global_pos - p->start_processed;
	}
	if (p->pos > p->unp_size)
		return RAR_ERR_DATA;

	err = rar2_read_last_tables (p);
	if (err)
		return err;

	p->solid_allowed = 1;
	p->item_done = 1;

	err = rar_ow_flush (&p->ow);
	if (err)
		return err;
	return RAR_DONE;
}

static void
rar2_free (struct rar_decoder *d)
{
	struct rar2_dec *p = (struct rar2_dec *) d;

	rar_ow_free (&p->ow);
	rar_bytein_free (&p->bi.in);
	grub_free (p);
}

rar_decoder *
rar2_decoder_create (void)
{
	struct rar2_dec *p = grub_zalloc (sizeof (*p));

	if (!p)
		return 0;
	p->base.start_item = rar2_start_item;
	p->base.run = rar2_run;
	p->base.free = rar2_free;
	return &p->base;
}
