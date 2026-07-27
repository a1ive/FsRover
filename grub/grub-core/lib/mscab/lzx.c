/*
 *  Rover -- Filesystem browser for Windows
 *  Cabinet LZX decompressor.
 *
 *  C port of 7-Zip 26.02 CPP\7zip\Compress\LzxDecoder.cpp (LGPL),
 *  CAB variant only (no WIM mode): 15..21 bit windows, verbatim /
 *  aligned / uncompressed blocks that may span CFDATA frames, delta
 *  coded level tables kept between blocks, and the x86 E8 call filter
 *  with 7-Zip v24 corner-case semantics.  The bitstream is a sequence
 *  of little-endian 16-bit words consumed MSB first.
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

#define LZX_BLOCK_VERBATIM	1
#define LZX_BLOCK_ALIGNED	2
#define LZX_BLOCK_UNCOMPRESSED	3

#define LZX_NUM_HUFFMAN_BITS	16
#define LZX_NUM_REPS		3

#define LZX_NUM_LEN_SLOTS	8
#define LZX_MATCH_MIN_LEN	2
#define LZX_NUM_LEN_SYMBOLS	249

#define LZX_NUM_ALIGN_LEVEL_BITS	3
#define LZX_ALIGN_TABLE_SIZE	8

#define LZX_NUM_POS_SLOTS	50
#define LZX_MAIN_TABLE_SIZE	(256 + LZX_NUM_POS_SLOTS * LZX_NUM_LEN_SLOTS)

#define LZX_LEVEL_TABLE_SIZE	20
#define LZX_NUM_LEVEL_BITS	4

#define LZX_LEVEL_SYM_ZERO1	17
#define LZX_LEVEL_SYM_ZERO2	18
#define LZX_LEVEL_SYM_SAME	19

#define LZX_NUM_LINEAR_POS_SLOT_BITS	17

#define LZX_DICT_BITS_MIN	15
#define LZX_DICT_BITS_MAX	21

/* ---------------- canonical huffman decoder ---------------- */

#define HUFF_QBITS	10

struct lzx_huff
{
	/* left-justified 16-bit code boundaries per length */
	grub_uint32_t limit[LZX_NUM_HUFFMAN_BITS + 1];
	grub_uint32_t start[LZX_NUM_HUFFMAN_BITS + 1];
	grub_uint16_t pos[LZX_NUM_HUFFMAN_BITS + 1];
	grub_uint16_t syms[LZX_MAIN_TABLE_SIZE];
	grub_uint8_t quick_len[1 << HUFF_QBITS];
	grub_uint16_t quick_sym[1 << HUFF_QBITS];
	int empty;
};

/* builds the canonical decoder; the code space must be filled exactly
   (or, when allow_empty, entirely unused) */
static int
lzx_huff_build (struct lzx_huff *h, const grub_uint8_t *lens, unsigned n,
		int allow_empty)
{
	unsigned counts[LZX_NUM_HUFFMAN_BITS + 1];
	grub_uint16_t cursor[LZX_NUM_HUFFMAN_BITS + 1];
	grub_uint32_t code;
	unsigned i, l, total;

	grub_memset (counts, 0, sizeof (counts));
	for (i = 0; i < n; i++)
	{
		if (lens[i] > LZX_NUM_HUFFMAN_BITS)
			return 0;
		counts[lens[i]]++;
	}

	if (counts[0] == n)
	{
		if (!allow_empty)
			return 0;
		h->empty = 1;
		return 1;
	}
	h->empty = 0;

	code = 0;
	total = 0;
	for (l = 1; l <= LZX_NUM_HUFFMAN_BITS; l++)
	{
		h->start[l] = code;
		h->pos[l] = (grub_uint16_t) total;
		cursor[l] = (grub_uint16_t) total;
		code += counts[l] << (LZX_NUM_HUFFMAN_BITS - l);
		if (code > (1u << LZX_NUM_HUFFMAN_BITS))
			return 0;
		h->limit[l] = code;
		total += counts[l];
	}
	if (code != (1u << LZX_NUM_HUFFMAN_BITS))
		return 0;

	for (i = 0; i < n; i++)
		if (lens[i])
			h->syms[cursor[lens[i]]++] = (grub_uint16_t) i;

	grub_memset (h->quick_len, 0, sizeof (h->quick_len));
	for (l = 1; l <= HUFF_QBITS; l++)
	{
		grub_uint32_t c = h->start[l];
		unsigned k;

		for (k = 0; k < counts[l]; k++)
		{
			const grub_uint32_t lo = c >> (LZX_NUM_HUFFMAN_BITS
						       - HUFF_QBITS);
			const grub_uint32_t hi = lo
				+ (1u << (HUFF_QBITS - l));
			grub_uint32_t q;

			for (q = lo; q < hi; q++)
			{
				h->quick_len[q] = (grub_uint8_t) l;
				h->quick_sym[q] = h->syms[h->pos[l] + k];
			}
			c += 1u << (LZX_NUM_HUFFMAN_BITS - l);
		}
	}
	return 1;
}

/* ---------------- bitstream ---------------- */

struct lzx_bs
{
	const grub_uint8_t *data;
	grub_size_t size;
	grub_size_t base;	/* where the current bit-mode region starts */
	grub_size_t bit_pos;	/* bits consumed since base */
	grub_size_t bit_total;	/* bits available (whole 16-bit words) */
	grub_size_t byte_pos;	/* byte-mode cursor */
	int byte_mode;
	int err;
};

static void
lzx_bs_init_bits (struct lzx_bs *bs, grub_size_t base)
{
	bs->base = base;
	bs->bit_pos = 0;
	bs->bit_total = ((bs->size - base) & ~(grub_size_t) 1) * 8;
	bs->byte_mode = 0;
}

/* 16-bit word i of the bit region, zero past the end */
static grub_uint32_t
lzx_bs_word (const struct lzx_bs *bs, grub_size_t i)
{
	const grub_size_t off = bs->base + i * 2;

	if (off + 2 <= bs->size)
		return (grub_uint32_t) bs->data[off]
		       | ((grub_uint32_t) bs->data[off + 1] << 8);
	return 0;
}

/* peeks up to 17 bits without consuming them (zero padded at the end) */
static grub_uint32_t
lzx_bs_peek (const struct lzx_bs *bs, unsigned n)
{
	const grub_size_t w = bs->bit_pos >> 4;
	const unsigned off = (unsigned) (bs->bit_pos & 15);
	const grub_uint32_t v = ((lzx_bs_word (bs, w) << 16)
				 | lzx_bs_word (bs, w + 1)) << off;

	return v >> (32 - n);
}

static void
lzx_bs_consume (struct lzx_bs *bs, unsigned n)
{
	bs->bit_pos += n;
	if (bs->bit_pos > bs->bit_total)
		bs->err = 1;
}

static grub_uint32_t
lzx_bs_read (struct lzx_bs *bs, unsigned n)
{
	grub_uint32_t v;

	if (n == 0)
		return 0;
	v = lzx_bs_peek (bs, n);
	lzx_bs_consume (bs, n);
	return v;
}

/* returns the symbol, or -1 on a bad code */
static int
lzx_huff_decode (const struct lzx_huff *h, struct lzx_bs *bs)
{
	grub_uint32_t v;
	unsigned l;

	if (h->empty)
		return -1;
	v = lzx_bs_peek (bs, LZX_NUM_HUFFMAN_BITS);
	l = h->quick_len[v >> (LZX_NUM_HUFFMAN_BITS - HUFF_QBITS)];
	if (l != 0)
	{
		lzx_bs_consume (bs, l);
		return h->quick_sym[v >> (LZX_NUM_HUFFMAN_BITS - HUFF_QBITS)];
	}
	for (l = HUFF_QBITS + 1; l <= LZX_NUM_HUFFMAN_BITS; l++)
		if (v < h->limit[l])
		{
			lzx_bs_consume (bs, l);
			return h->syms[h->pos[l]
				       + ((v - h->start[l])
					  >> (LZX_NUM_HUFFMAN_BITS - l))];
		}
	bs->err = 1;
	return -1;
}

/*
 * Leaves bit mode before an uncompressed block: 1..16 padding bits
 * (a full zero word when already aligned) must all be zero.
 */
static int
lzx_bs_to_bytes (struct lzx_bs *bs)
{
	const unsigned used = (unsigned) (bs->bit_pos & 15);
	const unsigned n = 16 - used;

	if (lzx_bs_peek (bs, n) != 0)
		return 0;
	bs->bit_pos += n;
	if (bs->bit_pos > bs->bit_total)
		return 0;
	bs->byte_pos = bs->base + (bs->bit_pos >> 3);
	bs->byte_mode = 1;
	return 1;
}

static void
lzx_bs_to_bits (struct lzx_bs *bs)
{
	lzx_bs_init_bits (bs, bs->byte_pos);
}

static grub_size_t
lzx_bs_byte_rem (const struct lzx_bs *bs)
{
	return bs->size - bs->byte_pos;
}

/* all data consumed and the 0..15 unused trailing bits are zero */
static int
lzx_bs_finished_ok (const struct lzx_bs *bs)
{
	const grub_size_t rem = bs->bit_total - bs->bit_pos;

	if (rem == 0)
		return 1;
	if (rem >= 16)
		return 0;
	return lzx_bs_peek (bs, (unsigned) rem) == 0;
}

/* ---------------- decoder state ---------------- */

struct cab_lzx
{
	grub_uint8_t *win;
	grub_uint32_t win_size;
	grub_uint32_t pos;
	grub_uint32_t write_pos;
	int over_dict;
	int keep_history;

	int is_uncompressed;
	int skip_byte;
	grub_uint32_t block_left;
	int use_align;
	unsigned num_pos_len_slots;

	grub_uint32_t reps[LZX_NUM_REPS];

	grub_uint32_t trans_size;	/* x86 E8 translation size, 0 = off */
	grub_uint32_t x86_processed;
	grub_uint8_t *x86_buf;

	const grub_uint8_t *out_ptr;

	grub_uint32_t base[LZX_NUM_POS_SLOTS];
	grub_uint8_t extra[LZX_NUM_POS_SLOTS];

	struct lzx_huff main_huff;
	struct lzx_huff len_huff;
	struct lzx_huff align_huff;
	grub_uint8_t main_levels[LZX_MAIN_TABLE_SIZE];
	grub_uint8_t len_levels[LZX_NUM_LEN_SYMBOLS];
};

/* ---------------- x86 E8 call filter ---------------- */

/*
 * Decode-side transform, 7-Zip v24 semantics: values are compared
 * against (pos = -1 - stream_position) as unsigned 32-bit numbers.
 * The last 10 bytes of a chunk are never converted.
 */
static void
lzx_x86_filter (grub_uint8_t *data, grub_size_t size,
		grub_uint32_t processed, grub_uint32_t trans_size)
{
	grub_size_t e;

	if (size <= 10)
		return;
	for (e = 0; e + 11 <= size;)
	{
		grub_uint32_t v, pos;

		if (data[e] != 0xE8)
		{
			e++;
			continue;
		}
		v = (grub_uint32_t) data[e + 1]
		    | ((grub_uint32_t) data[e + 2] << 8)
		    | ((grub_uint32_t) data[e + 3] << 16)
		    | ((grub_uint32_t) data[e + 4] << 24);
		pos = (grub_uint32_t) 0 - 1 - (processed + (grub_uint32_t) e);
		if (v < trans_size)
			v += pos + 1;
		else if (v > pos)
			v += trans_size;
		else
		{
			e += 5;
			continue;
		}
		data[e + 1] = (grub_uint8_t) v;
		data[e + 2] = (grub_uint8_t) (v >> 8);
		data[e + 3] = (grub_uint8_t) (v >> 16);
		data[e + 4] = (grub_uint8_t) (v >> 24);
		e += 5;
	}
}

/* ---------------- level table reading ---------------- */

/*
 * Levels are delta coded against their previous values (which survive
 * from the preceding block of the folder), with zero-run and same-run
 * escapes.
 */
static int
lzx_read_level_table (struct lzx_bs *bs, grub_uint8_t *levels, unsigned n)
{
	struct lzx_huff lev;
	grub_uint8_t pre[LZX_LEVEL_TABLE_SIZE];
	unsigned i;

	for (i = 0; i < LZX_LEVEL_TABLE_SIZE; i++)
		pre[i] = (grub_uint8_t) lzx_bs_read (bs, LZX_NUM_LEVEL_BITS);
	if (bs->err || !lzx_huff_build (&lev, pre, LZX_LEVEL_TABLE_SIZE, 0))
		return 0;

	for (i = 0; i < n;)
	{
		int sym = lzx_huff_decode (&lev, bs);
		unsigned num, val;

		if (sym < 0 || bs->err)
			return 0;
		if (sym <= LZX_NUM_HUFFMAN_BITS)
		{
			int d = (int) levels[i] - sym;

			if (d < 0)
				d += LZX_NUM_HUFFMAN_BITS + 1;
			levels[i++] = (grub_uint8_t) d;
			continue;
		}

		if (sym == LZX_LEVEL_SYM_ZERO1)
		{
			num = 4 + lzx_bs_read (bs, 4);
			val = 0;
		}
		else if (sym == LZX_LEVEL_SYM_ZERO2)
		{
			num = 20 + lzx_bs_read (bs, 5);
			val = 0;
		}
		else	/* LZX_LEVEL_SYM_SAME */
		{
			int d;

			num = 4 + lzx_bs_read (bs, 1);
			sym = lzx_huff_decode (&lev, bs);
			if (sym < 0 || sym > LZX_NUM_HUFFMAN_BITS || bs->err)
				return 0;
			d = (int) levels[i] - sym;
			if (d < 0)
				d += LZX_NUM_HUFFMAN_BITS + 1;
			val = (unsigned) d;
		}

		if (num > n - i)
			return 0;
		while (num--)
			levels[i++] = (grub_uint8_t) val;
	}
	return !bs->err;
}

/* ---------------- block header ---------------- */

static int
lzx_read_tables (struct cab_lzx *p, struct lzx_bs *bs)
{
	unsigned block_type;

	block_type = lzx_bs_read (bs, 3);
	if (block_type < LZX_BLOCK_VERBATIM
	    || block_type > LZX_BLOCK_UNCOMPRESSED)
		return 0;

	p->block_left = lzx_bs_read (bs, 16) << 8;
	p->block_left |= lzx_bs_read (bs, 8);
	if (bs->err)
		return 0;

	p->is_uncompressed = (block_type == LZX_BLOCK_UNCOMPRESSED);
	p->skip_byte = 0;

	if (p->is_uncompressed)
	{
		unsigned i;

		p->skip_byte = (int) (p->block_left & 1);
		if (!lzx_bs_to_bytes (bs))
			return 0;
		if (lzx_bs_byte_rem (bs) < LZX_NUM_REPS * 4)
			return 0;
		for (i = 0; i < LZX_NUM_REPS; i++)
		{
			const grub_size_t o = bs->byte_pos;
			const grub_uint32_t rep = (grub_uint32_t) bs->data[o]
				| ((grub_uint32_t) bs->data[o + 1] << 8)
				| ((grub_uint32_t) bs->data[o + 2] << 16)
				| ((grub_uint32_t) bs->data[o + 3] << 24);

			bs->byte_pos += 4;
			if (rep == 0 || rep > p->win_size - LZX_NUM_REPS)
				return 0;
			p->reps[i] = rep;
		}
		return 1;
	}

	p->use_align = 0;
	if (block_type == LZX_BLOCK_ALIGNED)
	{
		grub_uint8_t levels[LZX_ALIGN_TABLE_SIZE];
		unsigned i, not3 = 0;

		for (i = 0; i < LZX_ALIGN_TABLE_SIZE; i++)
		{
			levels[i] = (grub_uint8_t)
				lzx_bs_read (bs, LZX_NUM_ALIGN_LEVEL_BITS);
			not3 |= levels[i] ^ 3;
		}
		if (bs->err)
			return 0;
		/* all-3 levels mean the aligned path is never cheaper;
		   7-Zip then decodes the block as verbatim */
		if (not3)
		{
			if (!lzx_huff_build (&p->align_huff, levels,
					     LZX_ALIGN_TABLE_SIZE, 0))
				return 0;
			p->use_align = 1;
		}
	}

	if (!lzx_read_level_table (bs, p->main_levels, 256))
		return 0;
	if (!lzx_read_level_table (bs, p->main_levels + 256,
				   p->num_pos_len_slots))
		return 0;
	grub_memset (p->main_levels + 256 + p->num_pos_len_slots, 0,
		     LZX_MAIN_TABLE_SIZE - 256 - p->num_pos_len_slots);
	if (!lzx_huff_build (&p->main_huff, p->main_levels,
			     LZX_MAIN_TABLE_SIZE, 0))
		return 0;
	if (!lzx_read_level_table (bs, p->len_levels, LZX_NUM_LEN_SYMBOLS))
		return 0;
	if (!lzx_huff_build (&p->len_huff, p->len_levels,
			     LZX_NUM_LEN_SYMBOLS, 1))
		return 0;
	return 1;
}

/* ---------------- LZ decoding ---------------- */

static int
lzx_code_lz (struct cab_lzx *p, struct lzx_bs *bs, grub_uint32_t next)
{
	grub_uint8_t *const win = p->win;
	const grub_uint32_t win_size = p->win_size;
	grub_uint32_t pos = p->pos;
	const grub_uint32_t pos_end = pos + next;

	while (pos != pos_end)
	{
		int sym = lzx_huff_decode (&p->main_huff, bs);
		unsigned slot, len;
		grub_uint32_t dist;

		if (sym < 0 || bs->err)
			return 0;

		if (sym < 256)
		{
			win[pos++] = (grub_uint8_t) sym;
			continue;
		}

		sym -= 256;
		slot = (unsigned) sym / LZX_NUM_LEN_SLOTS;
		len = (unsigned) sym % LZX_NUM_LEN_SLOTS + LZX_MATCH_MIN_LEN;
		if (len == LZX_NUM_LEN_SLOTS - 1 + LZX_MATCH_MIN_LEN)
		{
			const int len_sym = lzx_huff_decode (&p->len_huff, bs);

			if (len_sym < 0 || bs->err)
				return 0;
			len = (unsigned) len_sym
			      + LZX_NUM_LEN_SLOTS - 1 + LZX_MATCH_MIN_LEN;
		}

		if (slot < LZX_NUM_REPS)
		{
			dist = p->reps[slot];
			p->reps[slot] = p->reps[0];
		}
		else
		{
			unsigned nbits = p->extra[slot];

			dist = p->base[slot];
			p->reps[2] = p->reps[1];
			p->reps[1] = p->reps[0];
			if (p->use_align && nbits >= 3)
			{
				int align_sym;

				dist += lzx_bs_read (bs, nbits - 3) << 3;
				align_sym = lzx_huff_decode (&p->align_huff,
							     bs);
				if (align_sym < 0)
					return 0;
				dist += (grub_uint32_t) align_sym;
			}
			else
				dist += lzx_bs_read (bs, nbits);
		}
		p->reps[0] = dist;

		if (len > pos_end - pos)
			return 0;
		{
			grub_int32_t src = (grub_int32_t) pos
					   - (grub_int32_t) dist;
			grub_uint32_t s;

			if (src < 0)
			{
				if (!p->over_dict)
					return 0;
				s = (grub_uint32_t) src & (win_size - 1);
			}
			else
				s = (grub_uint32_t) src;

			if (win_size - s >= len && s < pos)
				while (len--)
					win[pos++] = win[s++];
			else
				while (len--)
				{
					win[pos++] = win[s];
					s = (s + 1) & (win_size - 1);
				}
		}
	}

	p->pos = pos;
	return !bs->err;
}

/* ---------------- per-block driver ---------------- */

static int
lzx_code_spec (struct cab_lzx *p, const grub_uint8_t *in, grub_size_t in_size,
	       grub_uint32_t out_size)
{
	struct lzx_bs bs;

	bs.data = in;
	bs.size = in_size;
	bs.err = 0;
	if (p->keep_history && p->is_uncompressed)
	{
		bs.byte_mode = 1;
		bs.byte_pos = 0;
		bs.base = 0;
		bs.bit_pos = 0;
		bs.bit_total = 0;
	}
	else
		lzx_bs_init_bits (&bs, 0);

	if (!p->keep_history)
	{
		p->is_uncompressed = 0;
		p->skip_byte = 0;
		p->block_left = 0;
		grub_memset (p->main_levels, 0, sizeof (p->main_levels));
		grub_memset (p->len_levels, 0, sizeof (p->len_levels));
		p->trans_size = 0;
		if (lzx_bs_read (&bs, 1) != 0)
		{
			grub_uint32_t v = lzx_bs_read (&bs, 16) << 16;

			v |= lzx_bs_read (&bs, 16);
			p->trans_size = v;
		}
		p->x86_processed = 0;
		p->reps[0] = 1;
		p->reps[1] = 1;
		p->reps[2] = 1;
	}

	while (out_size)
	{
		grub_uint32_t next;

		if (p->block_left == 0)
		{
			if (p->skip_byte)
			{
				if (lzx_bs_byte_rem (&bs) < 1)
					return 0;
				if (bs.data[bs.byte_pos++] != 0)
					return 0;
				p->skip_byte = 0;
			}
			if (p->is_uncompressed)
				lzx_bs_to_bits (&bs);
			if (!lzx_read_tables (p, &bs) || bs.err)
				return 0;
			continue;
		}

		next = p->block_left;
		if (next > out_size)
			next = out_size;

		if (p->is_uncompressed)
		{
			if (lzx_bs_byte_rem (&bs) < next)
				return 0;
			grub_memcpy (p->win + p->pos, bs.data + bs.byte_pos,
				     next);
			bs.byte_pos += next;
			p->pos += next;
		}
		else if (!lzx_code_lz (p, &bs, next))
			return 0;

		p->block_left -= next;
		out_size -= next;
	}

	/* a trailing pad byte may sit at the very end of this frame */
	if (p->is_uncompressed && p->block_left == 0 && p->skip_byte
	    && bs.byte_mode && lzx_bs_byte_rem (&bs) == 1)
	{
		p->skip_byte = 0;
		if (bs.data[bs.byte_pos++] != 0)
			return 0;
	}

	if (bs.byte_mode)
		return lzx_bs_byte_rem (&bs) == 0;
	if ((bs.size - bs.base) & 1)
		return 0;
	if (!p->is_uncompressed && !lzx_bs_finished_ok (&bs))
		return 0;
	return !bs.err;
}

/* ---------------- public interface ---------------- */

cab_lzx *
cab_lzx_create (unsigned dict_bits)
{
	struct cab_lzx *p;
	unsigned num_slots, i;
	grub_uint32_t a, delta;

	if (dict_bits < LZX_DICT_BITS_MIN || dict_bits > LZX_DICT_BITS_MAX)
		return 0;

	p = grub_zalloc (sizeof (*p));
	if (!p)
		return 0;
	p->win_size = (grub_uint32_t) 1 << dict_bits;
	p->win = grub_malloc (p->win_size);
	p->x86_buf = grub_malloc (CAB_BLOCK_MAX);
	if (!p->win || !p->x86_buf)
	{
		cab_lzx_free (p);
		return 0;
	}

	num_slots = dict_bits < 20 ? dict_bits : 17 + (1u << (dict_bits - 18));
	p->num_pos_len_slots = num_slots * (LZX_NUM_LEN_SLOTS * 2);

	/* distance bases and footer bit counts per position slot
	   (bases already have the LZX "formal offset - 2" folded in) */
	a = 2 - (LZX_NUM_REPS - 1);
	delta = 1;
	for (i = 0; i < LZX_NUM_LINEAR_POS_SLOT_BITS; i++)
	{
		p->extra[i * 2 + 2] = (grub_uint8_t) i;
		p->extra[i * 2 + 3] = (grub_uint8_t) i;
		p->base[i * 2 + 2] = a;
		a += delta;
		p->base[i * 2 + 3] = a;
		a += delta;
		delta += delta;
	}
	for (i = LZX_NUM_LINEAR_POS_SLOT_BITS * 2 + 2;
	     i < LZX_NUM_POS_SLOTS; i++)
	{
		p->extra[i] = LZX_NUM_LINEAR_POS_SLOT_BITS;
		p->base[i] = a;
		a += (grub_uint32_t) 1 << LZX_NUM_LINEAR_POS_SLOT_BITS;
	}

	return p;
}

void
cab_lzx_free (cab_lzx *p)
{
	if (!p)
		return;
	grub_free (p->win);
	grub_free (p->x86_buf);
	grub_free (p);
}

void
cab_lzx_reset (cab_lzx *p)
{
	p->keep_history = 0;
}

int
cab_lzx_block (cab_lzx *p, const grub_uint8_t *in, grub_size_t in_size,
	       grub_uint32_t out_size, const grub_uint8_t **out)
{
	grub_uint32_t chunk;

	if (!p->keep_history)
	{
		p->pos = 0;
		p->over_dict = 0;
	}
	else if (p->pos == p->win_size)
	{
		p->pos = 0;
		p->over_dict = 1;
	}
	p->write_pos = p->pos;

	if (out_size > p->win_size - p->pos || out_size > CAB_BLOCK_MAX
	    || in_size == 0)
		return CAB_ERR_DATA;

	if (!lzx_code_spec (p, in, in_size, out_size))
		return CAB_ERR_DATA;
	p->keep_history = 1;

	chunk = p->pos - p->write_pos;
	if (p->trans_size != 0)
	{
		grub_memcpy (p->x86_buf, p->win + p->write_pos, chunk);
		lzx_x86_filter (p->x86_buf, chunk, p->x86_processed,
				p->trans_size);
		p->x86_processed += chunk;
		if (p->x86_processed >= (1u << 30))
			p->trans_size = 0;
		*out = p->x86_buf;
	}
	else
		*out = p->win + p->write_pos;
	return CAB_OK;
}
