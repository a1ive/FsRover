/*
 *  Rover -- Filesystem browser for Windows
 *  RAR 1.5 decoder, ported to C from 7-Zip 26.02 (Rar1Decoder.cpp).
 *
 *  7-Zip Copyright (C) 1999-2025 Igor Pavlov.
 *  Licensed under the GNU LGPL, with the unRAR license restriction:
 *  this code may not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include "rar_core.h"

#define RAR1_NUM_BITS		12
#define RAR1_HISTORY_SIZE	(1u << 16)
#define RAR1_NUM_REP_DISTS	4

static const grub_uint8_t kShortLen1[16 * 3] =
{
	0,0xa0,0xd0,0xe0,0xf0,0xf8,0xfc,0xfe,0xff,0xc0,0x80,0x90,0x98,0x9c,0xb0,0,
	1,3,4,4,5,6,7,8,8,4,4,5,6,6,0,0,
	1,4,4,4,5,6,7,8,8,4,4,5,6,6,4,0
};

static const grub_uint8_t kShortLen2[16 * 3] =
{
	0,0x40,0x60,0xa0,0xd0,0xe0,0xf0,0xf8,0xfc,0xc0,0x80,0x90,0x98,0x9c,0xb0,0,
	2,3,3,3,4,4,5,6,6,4,4,5,6,6,0,0,
	2,3,3,4,4,4,5,6,6,4,4,5,6,6,4,0
};

static const grub_uint8_t PosL1[RAR1_NUM_BITS + 1]  = { 0,0,2,1,2,2,4,5,4,4,8,0,224 };
static const grub_uint8_t PosL2[RAR1_NUM_BITS + 1]  = { 0,0,0,5,2,2,4,5,4,4,8,2,220 };

static const grub_uint8_t PosHf0[RAR1_NUM_BITS + 1] = { 0,0,0,0,8,8,8,9,0,0,0,0,224 };
static const grub_uint8_t PosHf1[RAR1_NUM_BITS + 1] = { 0,0,0,0,0,4,40,16,16,4,0,47,130 };
static const grub_uint8_t PosHf2[RAR1_NUM_BITS + 1] = { 0,0,0,0,0,2,5,46,64,116,24,0,0 };
static const grub_uint8_t PosHf3[RAR1_NUM_BITS + 1] = { 0,0,0,0,0,0,2,14,202,33,6,0,0 };
static const grub_uint8_t PosHf4[RAR1_NUM_BITS + 1] = { 0,0,0,0,0,0,0,0,255,2,0,0,0 };

struct rar1_dec
{
	struct rar_decoder base;

	int is_solid;
	int solid_allowed;
	int st_mode;
	int inited;

	struct rar_ow ow;
	struct rar_bitm bi;

	grub_uint64_t unp_size;

	grub_uint32_t last_dist;
	grub_uint32_t last_length;

	grub_uint32_t rep_dist_ptr;
	grub_uint32_t rep_dists[RAR1_NUM_REP_DISTS];

	int flags_cnt;
	grub_uint32_t flag_buf, avr_plc, avr_plcb, avr_ln1, avr_ln2, avr_ln3;
	unsigned buf60, num_huf, lcount;
	grub_uint32_t nhfb, nlzb, max_dist3;

	grub_uint32_t ch_set[256], ch_set_a[256], ch_set_b[256], ch_set_c[256];
	grub_uint32_t place[256], place_a[256], place_b[256], place_c[256];
	grub_uint32_t nto_pl[256], nto_pl_b[256], nto_pl_c[256];
};

static grub_uint32_t
rar1_read_bits (struct rar1_dec *p, unsigned numbits)
{
	return rar_bitm_readbits (&p->bi, numbits);
}

static int
rar1_copy_block (struct rar1_dec *p, grub_uint32_t distance, grub_uint32_t len)
{
	if (len == 0)
		return RAR_ERR_DATA;
	if (p->unp_size < len)
		return RAR_ERR_DATA;
	p->unp_size -= len;
	if (rar_ow_copy_block (&p->ow, distance, len))
		return RAR_ERR_DATA;
	return 0;
}

static grub_uint32_t
rar1_decode_num (struct rar1_dec *p, const grub_uint8_t *num_tab)
{
	grub_uint32_t val = rar_bitm_getval (&p->bi, RAR1_NUM_BITS);
	grub_uint32_t sum = 0;
	unsigned i = 2;

	for (;;)
	{
		const grub_uint32_t num = num_tab[i];
		const grub_uint32_t cur = num << (RAR1_NUM_BITS - i);
		if (val < cur)
			break;
		i++;
		val -= cur;
		sum += num;
	}
	rar_bitm_movepos (&p->bi, i);
	return (val >> (RAR1_NUM_BITS - i)) + sum;
}

static void
rar1_corr_huff (struct rar1_dec *p, grub_uint32_t *char_set,
		grub_uint32_t *num_to_place)
{
	int i;
	unsigned j;

	(void) p;
	for (i = 7; i >= 0; i--)
		for (j = 0; j < 32; j++, char_set++)
			*char_set = (*char_set & ~(grub_uint32_t) 0xff)
				    | (unsigned) i;
	grub_memset (num_to_place, 0, sizeof (p->nto_pl));
	for (i = 6; i >= 0; i--)
		num_to_place[i] = (7 - (unsigned) i) * 32;
}

static int
rar1_short_lz (struct rar1_dec *p)
{
	grub_uint32_t len, dist;
	grub_uint32_t bit_field;

	p->num_huf = 0;

	if (p->lcount == 2)
	{
		if (rar1_read_bits (p, 1))
			return rar1_copy_block (p, p->last_dist, p->last_length);
		p->lcount = 0;
	}

	bit_field = rar_bitm_getval (&p->bi, 8);

	{
		const grub_uint8_t *xors = (p->avr_ln1 < 37) ? kShortLen1
							     : kShortLen2;
		const grub_uint8_t *lens = xors + 16 + p->buf60;
		for (len = 0;
		     ((bit_field ^ xors[len]) >> (8 - lens[len])) != 0; len++)
			;
		rar_bitm_movepos (&p->bi, lens[len]);
	}

	if (len >= 9)
	{
		if (len == 9)
		{
			p->lcount++;
			return rar1_copy_block (p, p->last_dist,
						p->last_length);
		}

		p->lcount = 0;

		if (len == 14)
		{
			len = rar1_decode_num (p, PosL2) + 5;
			dist = 0x8000 + rar1_read_bits (p, 15) - 1;
			p->last_length = len;
			p->last_dist = dist;
			return rar1_copy_block (p, dist, len);
		}

		{
			const grub_uint32_t save_len = len;
			dist = p->rep_dists[(p->rep_dist_ptr - (len - 9)) & 3];

			len = rar1_decode_num (p, PosL1);

			if (len == 0xff && save_len == 10)
			{
				p->buf60 ^= 16;
				return 0;
			}
			if (dist >= 256)
			{
				len++;
				if (dist >= p->max_dist3 - 1)
					len++;
			}
		}
	}
	else
	{
		unsigned distance_place;

		p->lcount = 0;
		p->avr_ln1 += len;
		p->avr_ln1 -= p->avr_ln1 >> 4;

		distance_place = rar1_decode_num (p, PosHf2) & 0xff;

		dist = p->ch_set_a[distance_place];

		if (distance_place != 0)
		{
			grub_uint32_t last_distance;
			p->place_a[dist]--;
			last_distance = p->ch_set_a[distance_place - 1];
			p->place_a[last_distance]++;
			p->ch_set_a[distance_place] = last_distance;
			p->ch_set_a[distance_place - 1] = dist;
		}
	}

	p->rep_dists[p->rep_dist_ptr++] = dist;
	p->rep_dist_ptr &= 3;
	len += 2;
	p->last_length = len;
	p->last_dist = dist;
	return rar1_copy_block (p, dist, len);
}

static int
rar1_long_lz (struct rar1_dec *p)
{
	grub_uint32_t len;
	grub_uint32_t dist;
	grub_uint32_t distance_place, new_distance_place;
	grub_uint32_t old_avr2, old_avr3;

	p->num_huf = 0;
	p->nlzb += 16;
	if (p->nlzb > 0xff)
	{
		p->nlzb = 0x90;
		p->nhfb >>= 1;
	}
	old_avr2 = p->avr_ln2;

	if (p->avr_ln2 >= 64)
		len = rar1_decode_num (p, p->avr_ln2 < 122 ? PosL1 : PosL2);
	else
	{
		grub_uint32_t bit_field = rar_bitm_getval (&p->bi, 16);
		if (bit_field < 0x100)
		{
			len = bit_field;
			rar_bitm_movepos (&p->bi, 16);
		}
		else
		{
			for (len = 0;
			     ((bit_field << len) & 0x8000) == 0; len++)
				;
			rar_bitm_movepos (&p->bi, len + 1);
		}
	}

	p->avr_ln2 += len;
	p->avr_ln2 -= p->avr_ln2 >> 5;

	{
		const grub_uint8_t *tab;
		if (p->avr_plcb >= 0x2900)
			tab = PosHf2;
		else if (p->avr_plcb >= 0x0700)
			tab = PosHf1;
		else
			tab = PosHf0;
		distance_place = rar1_decode_num (p, tab);	/* [0, 256] */
	}

	p->avr_plcb += distance_place;
	p->avr_plcb -= p->avr_plcb >> 8;

	distance_place &= 0xff;

	for (;;)
	{
		dist = p->ch_set_b[distance_place];
		new_distance_place = p->nto_pl_b[dist++ & 0xff]++;
		if (dist & 0xff)
			break;
		rar1_corr_huff (p, p->ch_set_b, p->nto_pl_b);
	}

	p->ch_set_b[distance_place] = p->ch_set_b[new_distance_place];
	p->ch_set_b[new_distance_place] = dist;

	dist = ((dist & 0xff00) >> 1) | rar1_read_bits (p, 7);

	old_avr3 = p->avr_ln3;

	if (len != 1 && len != 4)
	{
		if (len == 0 && dist <= p->max_dist3)
		{
			p->avr_ln3++;
			p->avr_ln3 -= p->avr_ln3 >> 8;
		}
		else if (p->avr_ln3 > 0)
			p->avr_ln3--;
	}

	len += 3;

	if (dist >= p->max_dist3)
		len++;
	if (dist <= 256)
		len += 8;

	if (old_avr3 > 0xb0
	    || (p->avr_plc >= 0x2a00 && old_avr2 < 0x40))
		p->max_dist3 = 0x7f00;
	else
		p->max_dist3 = 0x2001;

	p->rep_dists[p->rep_dist_ptr++] = --dist;
	p->rep_dist_ptr &= 3;
	p->last_length = len;
	p->last_dist = dist;

	return rar1_copy_block (p, dist, len);
}

static int
rar1_huff_decode (struct rar1_dec *p)
{
	grub_uint32_t cur_byte, new_byte_place;
	grub_uint32_t len;
	grub_uint32_t dist;
	unsigned byte_place;

	{
		const grub_uint8_t *tab;

		if (p->avr_plc >= 0x7600)
			tab = PosHf4;
		else if (p->avr_plc >= 0x5e00)
			tab = PosHf3;
		else if (p->avr_plc >= 0x3600)
			tab = PosHf2;
		else if (p->avr_plc >= 0x0e00)
			tab = PosHf1;
		else
			tab = PosHf0;

		byte_place = rar1_decode_num (p, tab);	/* [0, 256] */
	}

	if (p->st_mode)
	{
		if (byte_place == 0)
		{
			if (rar1_read_bits (p, 1))
			{
				p->num_huf = 0;
				p->st_mode = 0;
				return 0;
			}
			len = rar1_read_bits (p, 1) + 3;
			dist = rar1_decode_num (p, PosHf2);
			dist = (dist << 5) | rar1_read_bits (p, 5);
			if (dist == 0)
				return RAR_ERR_DATA;
			return rar1_copy_block (p, dist - 1, len);
		}
		byte_place--;	/* byte_place is [0, 255] */
	}
	else if (p->num_huf++ >= 16 && p->flags_cnt == 0)
		p->st_mode = 1;

	byte_place &= 0xff;
	p->avr_plc += byte_place;
	p->avr_plc -= p->avr_plc >> 8;
	p->nhfb += 16;

	if (p->nhfb > 0xff)
	{
		p->nhfb = 0x90;
		p->nlzb >>= 1;
	}

	p->unp_size--;
	rar_ow_put_byte (&p->ow, (grub_uint8_t) (p->ch_set[byte_place] >> 8));

	for (;;)
	{
		cur_byte = p->ch_set[byte_place];
		new_byte_place = p->nto_pl[cur_byte++ & 0xff]++;
		if ((cur_byte & 0xff) <= 0xa1)
			break;
		rar1_corr_huff (p, p->ch_set, p->nto_pl);
	}

	p->ch_set[byte_place] = p->ch_set[new_byte_place];
	p->ch_set[new_byte_place] = cur_byte;
	return 0;
}

static void
rar1_get_flags_buf (struct rar1_dec *p)
{
	grub_uint32_t flags, new_flags_place;
	const grub_uint32_t flags_place = rar1_decode_num (p, PosHf2);

	if (flags_place >= 256)
		return;

	for (;;)
	{
		flags = p->ch_set_c[flags_place];
		p->flag_buf = flags >> 8;
		new_flags_place = p->nto_pl_c[flags++ & 0xff]++;
		if ((flags & 0xff) != 0)
			break;
		rar1_corr_huff (p, p->ch_set_c, p->nto_pl_c);
	}

	p->ch_set_c[flags_place] = p->ch_set_c[new_flags_place];
	p->ch_set_c[new_flags_place] = flags;
}

static int
rar1_start_item (struct rar_decoder *d, const struct rar_dec_props *props)
{
	struct rar1_dec *p = (struct rar1_dec *) d;
	int err;

	p->is_solid = props->solid;
	if (p->is_solid && !p->solid_allowed)
		return RAR_ERR_DATA;
	p->solid_allowed = 0;

	err = rar_ow_create (&p->ow, RAR1_HISTORY_SIZE, d);
	if (err)
		return err;
	err = rar_bytein_create (&p->bi.in, 1u << 20);
	if (err)
		return err;

	p->unp_size = props->unp_size;

	rar_ow_init (&p->ow, p->is_solid);
	rar_bitm_init (&p->bi, d->read_cb, d->read_opaque);

	p->flags_cnt = 0;
	p->flag_buf = 0;
	p->st_mode = 0;
	p->lcount = 0;

	if (!p->is_solid)
	{
		grub_uint32_t i;

		p->avr_plcb = p->avr_ln1 = p->avr_ln2 = p->avr_ln3 = 0;
		p->num_huf = p->buf60 = 0;
		p->avr_plc = 0x3500;
		p->max_dist3 = 0x2001;
		p->nhfb = p->nlzb = 0x80;

		for (i = 0; i < RAR1_NUM_REP_DISTS; i++)
			p->rep_dists[i] = 0;
		p->rep_dist_ptr = 0;
		p->last_length = 0;
		p->last_dist = 0;

		for (i = 0; i < 256; i++)
		{
			grub_uint32_t c = (~i + 1) & 0xff;
			p->place[i] = p->place_a[i] = p->place_b[i] = i;
			p->place_c[i] = c;
			p->ch_set[i] = p->ch_set_b[i] = i << 8;
			p->ch_set_a[i] = i;
			p->ch_set_c[i] = c << 8;
		}
		grub_memset (p->nto_pl, 0, sizeof (p->nto_pl));
		grub_memset (p->nto_pl_b, 0, sizeof (p->nto_pl_b));
		grub_memset (p->nto_pl_c, 0, sizeof (p->nto_pl_c));
		rar1_corr_huff (p, p->ch_set_b, p->nto_pl_b);
	}

	if (p->unp_size > 0)
	{
		rar1_get_flags_buf (p);
		p->flags_cnt = 8;
	}

	return 0;
}

static int
rar1_run (struct rar_decoder *d)
{
	struct rar1_dec *p = (struct rar1_dec *) d;
	int err;

	d->pause_req = 0;

	while (p->unp_size != 0)
	{
		if (d->pause_req)
		{
			d->pause_req = 0;
			return RAR_PAUSED;
		}
		if (p->ow.err)
			return p->ow.err;
		if (rar_bitm_extra_read (&p->bi))
			return p->bi.in.read_err ? RAR_ERR_READ : RAR_ERR_DATA;

		if (!p->st_mode)
		{
			if (--p->flags_cnt < 0)
			{
				rar1_get_flags_buf (p);
				p->flags_cnt = 7;
			}

			if (p->flag_buf & 0x80)
			{
				p->flag_buf <<= 1;
				if (p->nlzb > p->nhfb)
				{
					err = rar1_long_lz (p);
					if (err)
						return err;
					continue;
				}
			}
			else
			{
				p->flag_buf <<= 1;

				if (--p->flags_cnt < 0)
				{
					rar1_get_flags_buf (p);
					p->flags_cnt = 7;
				}

				if ((p->flag_buf & 0x80) == 0)
				{
					p->flag_buf <<= 1;
					err = rar1_short_lz (p);
					if (err)
						return err;
					continue;
				}

				p->flag_buf <<= 1;

				if (p->nlzb <= p->nhfb)
				{
					err = rar1_long_lz (p);
					if (err)
						return err;
					continue;
				}
			}
		}

		err = rar1_huff_decode (p);
		if (err)
			return err;
	}

	p->solid_allowed = 1;
	err = rar_ow_flush (&p->ow);
	if (err)
		return err;
	return RAR_DONE;
}

static void
rar1_free (struct rar_decoder *d)
{
	struct rar1_dec *p = (struct rar1_dec *) d;

	rar_ow_free (&p->ow);
	rar_bytein_free (&p->bi.in);
	grub_free (p);
}

rar_decoder *
rar1_decoder_create (void)
{
	struct rar1_dec *p = grub_zalloc (sizeof (*p));

	if (!p)
		return 0;
	p->base.start_item = rar1_start_item;
	p->base.run = rar1_run;
	p->base.free = rar1_free;
	return &p->base;
}
