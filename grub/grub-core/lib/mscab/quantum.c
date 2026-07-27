/*
 *  Rover -- Filesystem browser for Windows
 *  Cabinet Quantum decompressor.
 *
 *  C port of 7-Zip 26.02 CPP\7zip\Compress\QuantumDecoder.cpp (LGPL):
 *  adaptive frequency models with periodic reordering feeding a 16-bit
 *  range decoder; the window (32 KiB .. 2 MiB) persists between CFDATA
 *  blocks of a folder.
 *
 *  Copyright (C) 2026  A1ive
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/misc.h>

#include "mscab.h"

#define QTM_NUM_LIT_SELECTORS	4
#define QTM_NUM_LIT_SYMBOLS	64
#define QTM_NUM_MATCH_SELECTORS	3
#define QTM_NUM_SELECTORS	(QTM_NUM_LIT_SELECTORS + QTM_NUM_MATCH_SELECTORS)
#define QTM_NUM_SYMBOLS_MAX	QTM_NUM_LIT_SYMBOLS

#define QTM_NUM_LEN_SYMBOLS	27
#define QTM_MATCH_MIN_LEN	3
#define QTM_NUM_SIMPLE_LEN_SLOTS	6

#define QTM_UPDATE_STEP		8
#define QTM_FREQ_SUM_MAX	3800
#define QTM_REORDER_START	4
#define QTM_REORDER_COUNT	50

/* ---------------- range decoder ---------------- */

struct qtm_rc
{
	grub_uint32_t low;
	grub_uint32_t range;
	grub_uint32_t code;
	unsigned bit_offset;
	const grub_uint8_t *buf;
	const grub_uint8_t *buf_lim;
};

/* big-endian 32-bit read, zero padded past the block end */
static grub_uint32_t
qtm_be32 (const struct qtm_rc *rc)
{
	grub_uint32_t v = 0;
	unsigned i;

	for (i = 0; i < 4; i++)
	{
		v <<= 8;
		if (rc->buf + i < rc->buf_lim)
			v |= rc->buf[i];
	}
	return v;
}

static void
qtm_rc_init (struct qtm_rc *rc, const grub_uint8_t *in, grub_size_t in_size)
{
	rc->code = ((grub_uint32_t) in[0] << 8) | in[1];
	rc->buf = in + 2;
	rc->buf_lim = in + in_size;
	rc->bit_offset = 0;
	rc->low = 0;
	rc->range = 0x10000;
}

static int
qtm_rc_extra_read (const struct qtm_rc *rc)
{
	return rc->buf > rc->buf_lim;
}

/* numBits > 0 */
static grub_uint32_t
qtm_rc_read_bits (struct qtm_rc *rc, unsigned num_bits)
{
	const grub_uint32_t res = qtm_be32 (rc) << rc->bit_offset;
	unsigned bit_offset = rc->bit_offset + num_bits;

	rc->buf += bit_offset >> 3;
	rc->bit_offset = bit_offset & 7;
	return res >> (32 - num_bits);
}

static int
qtm_rc_finish (struct qtm_rc *rc)
{
	const unsigned num_bits = 2 + ((16 - 2 - rc->bit_offset) & 7);

	if (qtm_rc_read_bits (rc, num_bits) != 0)
		return 0;
	return rc->buf == rc->buf_lim;
}

static grub_uint32_t
qtm_rc_threshold (const struct qtm_rc *rc, grub_uint32_t total)
{
	return ((rc->code + 1) * total - 1) / rc->range;
}

static void
qtm_rc_decode (struct qtm_rc *rc, grub_uint32_t start, grub_uint32_t end,
	       grub_uint32_t total)
{
	grub_uint32_t hi = 0 - (rc->low + end * rc->range / total);
	const grub_uint32_t offset = start * rc->range / total;
	grub_uint32_t lo = rc->low + offset;
	grub_uint32_t an, num_bits = 0;

	rc->code -= offset;
	lo ^= hi;
	while (lo & (1u << 15))
	{
		lo <<= 1;
		hi <<= 1;
		num_bits++;
	}
	lo ^= hi;
	an = lo & hi;
	while (an & (1u << 14))
	{
		an <<= 1;
		lo <<= 1;
		hi <<= 1;
		num_bits++;
	}
	rc->low = lo;
	rc->range = ((~hi - lo) & 0xffff) + 1;
	if (num_bits)
		rc->code = (rc->code << num_bits)
			   + qtm_rc_read_bits (rc, num_bits);
}

/* ---------------- adaptive model ---------------- */

struct qtm_model
{
	unsigned num_items;
	unsigned reorder_count;
	grub_uint8_t vals[QTM_NUM_SYMBOLS_MAX];
	grub_uint16_t freqs[QTM_NUM_SYMBOLS_MAX + 1];
};

static void
qtm_model_init (struct qtm_model *m, unsigned num_items, unsigned start_val)
{
	unsigned i;

	m->num_items = num_items;
	m->reorder_count = QTM_REORDER_START;
	m->freqs[num_items] = 0;
	for (i = 0; i < num_items; i++)
	{
		m->freqs[i] = (grub_uint16_t) (num_items - i);
		m->vals[i] = (grub_uint8_t) (start_val + i);
	}
}

static unsigned
qtm_model_decode (struct qtm_model *m, struct qtm_rc *rc)
{
	unsigned res;

	if (m->freqs[0] > QTM_FREQ_SUM_MAX)
	{
		if (--m->reorder_count == 0)
		{
			unsigned i, freq;

			m->reorder_count = QTM_REORDER_COUNT;
			/* cumulative -> individual, halved */
			{
				unsigned next = 0;

				i = m->num_items;
				do
				{
					const unsigned f = m->freqs[i - 1];

					m->freqs[i - 1] = (grub_uint16_t)
						((f - next + 1) >> 1);
					next = f;
					i--;
				}
				while (i);
			}
			/* sort by frequency, descending */
			for (i = 0; i + 1 < m->num_items; i++)
			{
				grub_uint16_t f = m->freqs[i];
				unsigned k;

				for (k = i + 1; k < m->num_items; k++)
					if (f < m->freqs[k])
					{
						const grub_uint16_t f2 =
							m->freqs[k];
						grub_uint8_t v;

						m->freqs[k] = f;
						m->freqs[i] = f2;
						f = f2;
						v = m->vals[i];
						m->vals[i] = m->vals[k];
						m->vals[k] = v;
					}
			}
			/* individual -> cumulative */
			freq = 0;
			i = m->num_items;
			do
			{
				freq += m->freqs[i - 1];
				m->freqs[i - 1] = (grub_uint16_t) freq;
				i--;
			}
			while (i);
		}
		else
		{
			unsigned next = 1;
			unsigned i = m->num_items;

			do
			{
				unsigned freq = m->freqs[i - 1] >> 1;

				if (freq < next)
					freq = next;
				m->freqs[i - 1] = (grub_uint16_t) freq;
				next = freq + 1;
				i--;
			}
			while (i);
		}
	}

	{
		const unsigned freq0 = m->freqs[0];
		const unsigned threshold = qtm_rc_threshold (rc, freq0);
		unsigned i = 1;
		unsigned freq;

		m->freqs[0] = (grub_uint16_t) (freq0 + QTM_UPDATE_STEP);
		freq = m->freqs[1];
		while (freq > threshold)
		{
			m->freqs[i] = (grub_uint16_t) (freq + QTM_UPDATE_STEP);
			i++;
			freq = m->freqs[i];
		}
		res = m->vals[i - 1];
		qtm_rc_decode (rc, freq, m->freqs[i - 1] - QTM_UPDATE_STEP,
			       freq0);
	}
	return res;
}

/* ---------------- decoder ---------------- */

struct cab_qtm
{
	grub_uint8_t *win;
	grub_uint32_t win_size;
	grub_uint32_t win_pos;
	int over_win;
	int keep_history;
	unsigned num_dict_bits;

	struct qtm_model selector;
	struct qtm_model literals[QTM_NUM_LIT_SELECTORS];
	struct qtm_model pos_slot[QTM_NUM_MATCH_SELECTORS];
	struct qtm_model len_slot;
};

cab_qtm *
cab_qtm_create (unsigned dict_bits)
{
	struct cab_qtm *p;
	unsigned win_bits;

	if (dict_bits > 21)
		return 0;
	p = grub_zalloc (sizeof (*p));
	if (!p)
		return 0;
	p->num_dict_bits = dict_bits;
	win_bits = dict_bits < 15 ? 15 : dict_bits;
	p->win_size = (grub_uint32_t) 1 << win_bits;
	p->win = grub_malloc (p->win_size);
	if (!p->win)
	{
		grub_free (p);
		return 0;
	}
	return p;
}

void
cab_qtm_free (cab_qtm *p)
{
	if (!p)
		return;
	grub_free (p->win);
	grub_free (p);
}

void
cab_qtm_reset (cab_qtm *p)
{
	p->keep_history = 0;
	p->win_pos = 0;
	p->over_win = 0;
}

int
cab_qtm_block (cab_qtm *p, const grub_uint8_t *in, grub_size_t in_size,
	       grub_uint32_t out_size, const grub_uint8_t **out)
{
	struct qtm_rc rc;
	grub_uint8_t *const win = p->win;
	const grub_uint32_t win_size = p->win_size;
	grub_uint32_t pos;

	if (in_size < 2)
		return CAB_ERR_DATA;

	if (!p->keep_history)
	{
		unsigned i;
		const unsigned num_items = p->num_dict_bits == 0
					   ? 1 : p->num_dict_bits * 2;

		p->win_pos = 0;
		qtm_model_init (&p->selector, QTM_NUM_SELECTORS, 0);
		for (i = 0; i < QTM_NUM_LIT_SELECTORS; i++)
			qtm_model_init (&p->literals[i], QTM_NUM_LIT_SYMBOLS,
					i * QTM_NUM_LIT_SYMBOLS);
		for (i = 0; i < QTM_NUM_MATCH_SELECTORS; i++)
		{
			const unsigned num = 24 + i * 6 + ((i + 1) & 2) * 3;

			qtm_model_init (&p->pos_slot[i],
					num_items < num ? num_items : num, 0);
		}
		qtm_model_init (&p->len_slot, QTM_NUM_LEN_SYMBOLS,
				QTM_MATCH_MIN_LEN + QTM_NUM_MATCH_SELECTORS
				- 1);
	}
	p->keep_history = 1;

	qtm_rc_init (&rc, in, in_size);

	if (p->win_pos == win_size)
	{
		p->win_pos = 0;
		p->over_win = 1;
	}
	pos = p->win_pos;
	if (out_size > win_size - pos || out_size > CAB_BLOCK_MAX)
		return CAB_ERR_DATA;
	*out = win + pos;

	while (out_size != 0)
	{
		unsigned selector;

		if (qtm_rc_extra_read (&rc))
			return CAB_ERR_DATA;

		selector = qtm_model_decode (&p->selector, &rc);

		if (selector < QTM_NUM_LIT_SELECTORS)
		{
			win[pos++] = (grub_uint8_t)
				qtm_model_decode (&p->literals[selector], &rc);
			out_size--;
			continue;
		}

		{
			unsigned len = selector - QTM_NUM_LIT_SELECTORS
				       + QTM_MATCH_MIN_LEN;
			grub_uint32_t dist;
			grub_int32_t src;
			grub_uint32_t s;

			if (selector == QTM_NUM_SELECTORS - 1)
			{
				len = qtm_model_decode (&p->len_slot, &rc);
				if (len >= QTM_NUM_SIMPLE_LEN_SLOTS
					   + QTM_MATCH_MIN_LEN
					   + QTM_NUM_MATCH_SELECTORS - 1)
				{
					unsigned nbits;

					len -= QTM_NUM_SIMPLE_LEN_SLOTS - 4
					       + QTM_MATCH_MIN_LEN
					       + QTM_NUM_MATCH_SELECTORS - 1;
					nbits = len >> 2;
					len = ((4 | (len & 3)) << nbits)
					      - (4 << 1)
					      + QTM_NUM_SIMPLE_LEN_SLOTS
					      + QTM_MATCH_MIN_LEN
					      + QTM_NUM_MATCH_SELECTORS - 1;
					if (nbits < 6)
						len += qtm_rc_read_bits
							(&rc, nbits);
				}
			}

			dist = qtm_model_decode
				(&p->pos_slot[selector
					      - QTM_NUM_LIT_SELECTORS], &rc);
			if (dist >= 4)
			{
				const unsigned nbits = (dist >> 1) - 1;

				dist = ((2 | (dist & 1)) << nbits)
				       + qtm_rc_read_bits (&rc, nbits);
			}

			if (len > out_size)
				return CAB_ERR_DATA;
			out_size -= len;

			src = (grub_int32_t) pos - (grub_int32_t) dist - 1;
			if (src < 0)
			{
				grub_uint32_t rem;

				if (!p->over_win)
					return CAB_ERR_DATA;
				rem = (grub_uint32_t) - src;
				src += (grub_int32_t) win_size;
				if (rem < len)
				{
					s = (grub_uint32_t) src;
					len -= rem;
					do
						win[pos++] = win[s++];
					while (--rem);
					src = 0;
				}
			}
			s = (grub_uint32_t) src;
			do
				win[pos++] = win[s++];
			while (--len);
		}
	}

	p->win_pos = pos;
	return qtm_rc_finish (&rc) ? CAB_OK : CAB_ERR_DATA;
}
