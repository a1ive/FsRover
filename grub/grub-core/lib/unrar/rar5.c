/*
 *  Rover -- Filesystem browser for Windows
 *  RAR5 (and RAR7) decoder, ported to C from 7-Zip 26.02
 *  (Rar5Decoder.cpp).
 *
 *  7-Zip Copyright (C) 1999-2025 Igor Pavlov.
 *  Licensed under the GNU LGPL, with the unRAR license restriction:
 *  this code may not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include "rar_core.h"

#define kNumReps		4
#define kLenTableSize		(11 * 4)
#define kMainTableSize		(256 + 1 + 1 + kNumReps + kLenTableSize)
#define kExtraDistSymbols_v7	16
#define kDistTableSize_v6	64
#define kDistTableSize_MAX	(64 + kExtraDistSymbols_v7)
#define kNumAlignBits		4
#define kAlignTableSize		(1 << kNumAlignBits)
#define kLevelTableSize		20
#define kTablesSizesSum_MAX	(kMainTableSize + kDistTableSize_MAX \
				 + kAlignTableSize + kLenTableSize)

#define kSymbolRep		258
#define kMaxMatchLen		(0x1001 + 3)

#define kInputBufSize		((grub_size_t) 1 << 20)
#define kLookaheadSize		16
#define kWriteStep		((grub_size_t) 1 << 18)
#define kWinSize_Min		((grub_size_t) 1 << 18)

#define k_Filter_BlockSize_MAX	((grub_uint32_t) 1 << 22)
#define k_Filter_AfterPad_Size	64

#define MAX_UNPACK_FILTERS	8192

#define DICT_SIZE_BITS_MAX	40

#if GRUB_CPU_SIZEOF_VOID_P >= 8
#define MAX_DICT_LOG		36
#else
#define MAX_DICT_LOG		31
#endif

/* filter types */
#define FILTER_DELTA	0
#define FILTER_E8	1
#define FILTER_E8E9	2
#define FILTER_ARM	3

/* DecodeLZ2 exit reasons */
#define EXIT_TYPE_NONE		0
#define EXIT_TYPE_ADD_FILTER	1

/* LZ error kinds (mirrors upstream _lzError) */
#define LZ_ERROR_TYPE_NO	0
#define LZ_ERROR_TYPE_HEADER	1
#define LZ_ERROR_TYPE_DIST	2

static const grub_uint8_t k_LenPlusTable[DICT_SIZE_BITS_MAX] =
{
	0,0,0,0,0,0,0,1,1,1,1,1,2,2,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
	3,3,3,3,3,3,3,3
};

struct rar5_filter
{
	grub_uint8_t type;
	grub_uint8_t channels;
	grub_uint32_t size;
	grub_uint64_t start;
};

struct rar5_bits
{
	const grub_uint8_t *buf;
	const grub_uint8_t *buf_check_block;
	const grub_uint8_t *buf_check;
	grub_uint8_t *buf_lim;
	grub_uint8_t *buf_base;
	unsigned bit_pos;
	int was_finished;
	int minor_error;
	int read_err;
	unsigned block_end_bits7;
	grub_uint64_t processed_size;
	grub_uint64_t block_end;
	rar_read_cb read_cb;
	void *read_opaque;
};

struct rar5_dec
{
	struct rar_decoder base;

	int use_align_bits;
	int is_last_block;
	int unpack_size_defined;
	int unsupported_filter;
	grub_uint8_t lz_error;
	int is_solid;
	int is_v7;
	int table_was_filled;
	int was_init;
	int item_done;
	int exit_type;

	grub_size_t dict_size;
	grub_uint8_t *window;
	grub_size_t win_pos;
	grub_size_t win_size;
	grub_size_t dict_size_for_check;
	grub_size_t limit;
	grub_uint64_t lz_size;
	grub_size_t reps[kNumReps];
	grub_uint32_t last_len;

	unsigned num_unused_filters;
	unsigned num_filters;

	grub_uint64_t lz_written;
	grub_uint64_t lz_file_start;
	grub_uint64_t unpack_size;
	grub_uint64_t lz_end;
	grub_uint64_t written_file_size;
	grub_uint64_t filter_end;

	grub_uint8_t *filter_src;
	grub_size_t filter_src_size;
	grub_uint8_t *filter_dst;
	grub_size_t filter_dst_size;

	struct rar5_filter *filters;
	grub_size_t win_size_allocated;
	grub_uint8_t *input_buf;

	struct rar5_bits bits;

	struct rar_huff main_dec;
	struct rar_huff dist_dec;
	struct rar_huff align_dec;
	struct rar_huff len_dec;
};

/* ---------------- bit stream ---------------- */

static void
rar5_bits_set_check_for_block (struct rar5_bits *b)
{
	b->buf_check_block = b->buf_check;
	if (b->buf_check > b->buf)
	{
		const grub_uint64_t processed = b->processed_size
			+ (grub_size_t) (b->buf - b->buf_base);
		if (b->block_end < processed)
			b->buf_check_block = b->buf;
		else
		{
			const grub_uint64_t delta = b->block_end - processed;
			if ((grub_size_t) (b->buf_check - b->buf) > delta)
				b->buf_check_block = b->buf
					+ (grub_size_t) delta;
		}
	}
}

static void
rar5_bits_init (struct rar5_bits *b, grub_uint8_t *base,
		rar_read_cb read_cb, void *opaque)
{
	b->buf_base = base;
	b->read_cb = read_cb;
	b->read_opaque = opaque;
	b->block_end = 0;
	b->block_end_bits7 = 0;
	b->bit_pos = 0;
	b->processed_size = 0;
	b->buf = base;
	b->buf_lim = base;
	b->buf_check = base;
	b->buf_check_block = base;
	b->was_finished = 0;
	b->minor_error = 0;
	b->read_err = 0;
}

static void
rar5_bits_prepare2 (struct rar5_bits *b)
{
	grub_size_t rem;

	if (b->buf > b->buf_lim)
		return;

	rem = (grub_size_t) (b->buf_lim - b->buf);
	if (rem != 0)
		grub_memmove (b->buf_base, b->buf, rem);

	b->buf_lim = b->buf_base + rem;
	b->processed_size += (grub_size_t) (b->buf - b->buf_base);
	b->buf = b->buf_base;

	if (!b->was_finished)
	{
		while (rem <= kLookaheadSize)
		{
			grub_ssize_t got = b->read_cb (b->read_opaque,
						       b->buf_lim,
						       kInputBufSize - rem);
			if (got < 0)
			{
				b->read_err = 1;
				got = 0;
			}
			b->buf_lim += got;
			rem += (grub_size_t) got;
			if (got == 0)
			{
				b->was_finished = 1;
				break;
			}
		}
	}

	/* the pad zone lets the readers look ahead without bounds checks */
	grub_memset (b->buf_lim, 0xFF, kLookaheadSize);

	if (rem < kLookaheadSize)
		b->buf_check = b->buf;
	else
		b->buf_check = b->buf_lim - kLookaheadSize;

	rar5_bits_set_check_for_block (b);
}

static void
rar5_bits_prepare (struct rar5_bits *b)
{
	if (b->buf >= b->buf_check)
		rar5_bits_prepare2 (b);
}

static grub_uint64_t
rar5_bits_processed_round (const struct rar5_bits *b)
{
	return b->processed_size + (grub_size_t) (b->buf - b->buf_base);
}

static grub_uint64_t
rar5_bits_processed (const struct rar5_bits *b)
{
	return b->processed_size + (grub_size_t) (b->buf - b->buf_base)
	       + ((b->bit_pos + 7) >> 3);
}

static int
rar5_bits_is_block_overread (const struct rar5_bits *b)
{
	const grub_uint64_t v = rar5_bits_processed_round (b);
	if (v < b->block_end)
		return 0;
	if (v > b->block_end)
		return 1;
	return b->bit_pos > b->block_end_bits7;
}

static int
rar5_bits_extra_read (const struct rar5_bits *b)
{
	return b->buf >= b->buf_lim
	       && (b->buf > b->buf_lim || b->bit_pos != 0);
}

static void
rar5_bits_align (struct rar5_bits *b)
{
	if (b->bit_pos != 0)
	{
		const unsigned v = (unsigned) *b->buf << b->bit_pos;
		if (v & 0xff)
			b->minor_error = 1;
		b->buf++;
		b->bit_pos = 0;
	}
}

static grub_uint8_t
rar5_bits_read_byte_aligned (struct rar5_bits *b)
{
	return *b->buf++;
}

/* 0 < numbits <= 17 */
static grub_uint32_t
rar5_bits_getval (const struct rar5_bits *b, unsigned numbits)
{
	const grub_uint32_t v = rar_get_be32 (b->buf);
	return (v >> (32 - numbits - b->bit_pos)) & ((1u << numbits) - 1);
}

static void
rar5_bits_movepos (struct rar5_bits *b, unsigned numbits)
{
	numbits += b->bit_pos;
	b->buf += numbits >> 3;
	b->bit_pos = numbits & 7;
}

static grub_uint32_t
rar5_bits_readbits9 (struct rar5_bits *b, unsigned numbits)
{
	const grub_uint8_t *buf = b->buf;
	grub_uint32_t v = ((grub_uint32_t) buf[0] << 8) | (grub_uint32_t) buf[1];
	v &= (grub_uint32_t) 0xFFFF >> b->bit_pos;
	numbits += b->bit_pos;
	v >>= 16 - numbits;
	b->buf = buf + (numbits >> 3);
	b->bit_pos = numbits & 7;
	return v;
}

static grub_uint32_t
rar5_bits_readbits_9fix (struct rar5_bits *b, unsigned numbits)
{
	const grub_uint8_t *buf = b->buf;
	grub_uint32_t v = ((grub_uint32_t) buf[0] << 8) | (grub_uint32_t) buf[1];
	const grub_uint32_t mask = (1u << numbits) - 1;
	numbits += b->bit_pos;
	v >>= 16 - numbits;
	b->buf = buf + (numbits >> 3);
	b->bit_pos = numbits & 7;
	return v & mask;
}

/* numbits != 0, numbits + bit_pos <= 64; v = big-endian 64 bits at buf */
static grub_size_t
rar5_bits_readbits_big (struct rar5_bits *b, unsigned numbits,
			grub_uint64_t v)
{
	const grub_uint64_t mask = ((grub_uint64_t) 1 << numbits) - 1;
	numbits += b->bit_pos;
	v >>= 64 - numbits;
	b->buf += numbits >> 3;
	b->bit_pos = numbits & 7;
	return (grub_size_t) (v & mask);
}

static int
rar5_bits_huff (struct rar5_bits *b, const struct rar_huff *h)
{
	unsigned nb;
	const int sym = rar_huff_decode_val (h,
		rar5_bits_getval (b, RAR_HUFF_MAX_BITS), &nb);
	if (sym >= 0)
		rar5_bits_movepos (b, nb);
	return sym;
}

/* ---------------- output ---------------- */

static int
rar5_write_data (struct rar5_dec *p, const grub_uint8_t *data,
		 grub_size_t size)
{
	int res = 0;

	if (!p->unpack_size_defined || p->written_file_size < p->unpack_size)
	{
		grub_size_t cur = size;
		if (p->unpack_size_defined)
		{
			const grub_uint64_t rem = p->unpack_size
						  - p->written_file_size;
			if (cur > rem)
				cur = (grub_size_t) rem;
		}
		res = rar_deliver (&p->base, data, cur);
	}
	p->written_file_size += size;
	return res;
}

/* ---------------- filters ---------------- */

static int
rar5_alloc_buf (grub_uint8_t **buf, grub_size_t *cur_size,
		grub_size_t need, grub_size_t max_size)
{
	grub_uint8_t *tmp;

	if (*buf && *cur_size >= need)
		return 0;
	if (need < max_size)
		need = max_size;
	tmp = grub_malloc (need);
	if (!tmp)
		return RAR_ERR_MEM;
	grub_free (*buf);
	*buf = tmp;
	*cur_size = need;
	return 0;
}

static void
rar5_delete_unused_filters (struct rar5_dec *p)
{
	if (p->num_unused_filters != 0)
	{
		const unsigned n = p->num_filters - p->num_unused_filters;
		p->num_filters = n;
		grub_memmove (p->filters, p->filters + p->num_unused_filters,
			      n * sizeof (struct rar5_filter));
		p->num_unused_filters = 0;
	}
}

static void
rar5_e8_filter (grub_uint8_t *data, grub_uint32_t data_size,
		grub_uint32_t pc, int e9)
{
	const grub_uint32_t kFileSize = (grub_uint32_t) 1 << 24;
	const grub_uint8_t mask = (grub_uint8_t) (e9 ? 0xFE : 0xFF);
	grub_uint32_t cur = 0;

	if (data_size <= 4)
		return;
	data_size -= 4;
	while (cur < data_size)
	{
		const grub_uint8_t b = data[cur];
		cur++;
		if ((b & mask) == 0xE8)
		{
			const grub_uint32_t offset = (pc + cur)
						     & (kFileSize - 1);
			const grub_uint32_t addr = rar_get_le32 (data + cur);
			if (addr < kFileSize)
				rar_set_le32 (data + cur, addr - offset);
			else if (addr > ~offset)
				rar_set_le32 (data + cur, addr + kFileSize);
			cur += 4;
		}
	}
}

static void
rar5_arm_filter (grub_uint8_t *data, grub_uint32_t data_size,
		 grub_uint32_t pc)
{
	grub_uint32_t i;

	data_size &= ~(grub_uint32_t) 3;
	for (i = 0; i + 4 <= data_size; i += 4)
	{
		if (data[i + 3] == 0xEB)
		{
			grub_uint32_t v = rar_get_le32 (data + i);
			v -= (pc + i) >> 2;
			v &= 0x00FFFFFF;
			v |= 0xEB000000;
			rar_set_le32 (data + i, v);
		}
	}
}

static int
rar5_execute_filter (struct rar5_dec *p, const struct rar5_filter *f)
{
	grub_uint8_t *data = p->filter_src;
	grub_uint32_t data_size = f->size;
	int err;

	if (f->type == FILTER_DELTA)
	{
		const unsigned num_channels = f->channels;
		unsigned cur_channel = 0;
		grub_uint8_t *dest;
		const grub_uint8_t *src = data;

		err = rar5_alloc_buf (&p->filter_dst, &p->filter_dst_size,
				      data_size, k_Filter_BlockSize_MAX);
		if (err)
			return err;
		dest = p->filter_dst;
		do
		{
			grub_uint8_t prev_byte = 0;
			grub_uint8_t *dest2 = dest + cur_channel;
			const grub_uint8_t *dest_lim = dest + data_size;
			for (; dest2 < dest_lim; dest2 += num_channels)
				*dest2 = (prev_byte = (grub_uint8_t)
					  (prev_byte - *src++));
		}
		while (++cur_channel != num_channels);
		data = dest;
	}
	else if (f->type < FILTER_ARM)
	{
		const grub_uint32_t pc = (grub_uint32_t)
			(f->start - p->lz_file_start);
		rar5_e8_filter (data, data_size, pc, f->type == FILTER_E8E9);
	}
	else if (f->type == FILTER_ARM)
	{
		const grub_uint32_t pc = (grub_uint32_t)
			(f->start - p->lz_file_start);
		rar5_arm_filter (data, data_size, pc);
	}
	else
	{
		p->unsupported_filter = 1;
		grub_memset (data, 0, data_size);
	}
	return rar5_write_data (p, data, (grub_size_t) f->size);
}

static int
rar5_write_buf (struct rar5_dec *p)
{
	const grub_uint64_t lz_size = p->lz_size + p->win_pos;
	unsigned i;
	grub_size_t lz_avail;

	rar5_delete_unused_filters (p);

	for (i = 0; i < p->num_filters;)
	{
		const struct rar5_filter *f;
		grub_uint64_t block_start;
		grub_uint32_t block_size;
		grub_size_t offset, block_rem, size;
		int err;

		lz_avail = (grub_size_t) (lz_size - p->lz_written);
		if (lz_avail == 0)
			break;
		f = &p->filters[i];
		block_start = f->start;
		if (block_start > p->lz_written)
		{
			const grub_uint64_t rem = block_start - p->lz_written;
			size = lz_avail;
			if (size > rem)
				size = (grub_size_t) rem;
			err = rar5_write_data (p,
				p->window + p->win_pos - lz_avail, size);
			if (err)
				return err;
			p->lz_written += size;
			continue;
		}

		block_size = f->size;
		offset = (grub_size_t) (p->lz_written - block_start);
		if (offset == 0)
		{
			err = rar5_alloc_buf (&p->filter_src,
				&p->filter_src_size,
				(grub_size_t) block_size
					+ k_Filter_AfterPad_Size,
				k_Filter_BlockSize_MAX
					+ k_Filter_AfterPad_Size);
			if (err)
				return err;
		}

		block_rem = (grub_size_t) block_size - offset;
		size = lz_avail;
		if (size > block_rem)
			size = block_rem;
		grub_memcpy (p->filter_src + offset,
			     p->window + p->win_pos - lz_avail, size);
		p->lz_written += size;
		offset += size;
		if (offset != block_size)
			return 0;

		p->num_unused_filters = ++i;
		err = rar5_execute_filter (p, f);
		if (err)
			return err;
	}

	rar5_delete_unused_filters (p);
	if (p->num_filters)
		return 0;
	lz_avail = (grub_size_t) (lz_size - p->lz_written);
	{
		int err = rar5_write_data (p,
			p->window + p->win_pos - lz_avail, lz_avail);
		if (err)
			return err;
	}
	p->lz_written += lz_avail;
	return 0;
}

static grub_uint32_t
rar5_read_uint32 (struct rar5_bits *b)
{
	const unsigned numbits = (unsigned) rar5_bits_readbits_9fix (b, 2) * 8
				 + 8;
	grub_uint32_t v = 0;
	unsigned i = 0;

	do
	{
		v += (grub_uint32_t) rar5_bits_readbits_9fix (b, 8) << i;
		i += 8;
	}
	while (i != numbits);
	return v;
}

static int
rar5_add_filter (struct rar5_dec *p)
{
	struct rar5_bits *b = &p->bits;
	struct rar5_filter f;
	grub_uint32_t block_start;

	rar5_delete_unused_filters (p);

	if (p->num_filters >= MAX_UNPACK_FILTERS)
	{
		int err = rar5_write_buf (p);
		if (err)
			return err;
		rar5_delete_unused_filters (p);
		if (p->num_filters >= MAX_UNPACK_FILTERS)
		{
			p->unsupported_filter = 1;
			p->num_unused_filters = 0;
			p->num_filters = 0;
		}
	}

	rar5_bits_prepare (b);

	block_start = rar5_read_uint32 (b);
	f.size = rar5_read_uint32 (b);

	if (f.size > k_Filter_BlockSize_MAX)
	{
		p->unsupported_filter = 1;
		f.size = 0;
	}

	f.type = (grub_uint8_t) rar5_bits_readbits_9fix (b, 3);
	f.channels = 0;
	if (f.type == FILTER_DELTA)
		f.channels = (grub_uint8_t)
			(rar5_bits_readbits_9fix (b, 5) + 1);
	f.start = p->lz_size + p->win_pos + block_start;

	if (f.start < p->filter_end)
		p->unsupported_filter = 1;
	else
	{
		p->filter_end = f.start + f.size;
		if (f.size != 0)
		{
			if (!p->filters)
			{
				p->filters = grub_calloc (MAX_UNPACK_FILTERS,
					sizeof (struct rar5_filter));
				if (!p->filters)
					return RAR_ERR_MEM;
			}
			p->filters[p->num_filters++] = f;
		}
	}

	return 0;
}

/* ---------------- tables ---------------- */

static int
rar5_read_tables (struct rar5_dec *p)
{
	struct rar5_bits *b = &p->bits;
	struct rar_huff *level_dec;
	grub_uint8_t *lens;
	unsigned i, table_size;
	int err = RAR_ERR_DATA;

	/* _bitStream is aligned already */
	rar5_bits_prepare (b);
	{
		const unsigned flags = rar5_bits_read_byte_aligned (b);
		unsigned check_sum = rar5_bits_read_byte_aligned (b);
		const unsigned num = (flags >> 3) & 3;
		grub_uint32_t block_size;
		unsigned block_size_bits7;

		check_sum ^= flags;
		if (num >= 3)
			return RAR_ERR_DATA;
		block_size = rar5_bits_read_byte_aligned (b);
		check_sum ^= block_size;
		if (num != 0)
		{
			unsigned by = rar5_bits_read_byte_aligned (b);
			check_sum ^= by;
			block_size += (grub_uint32_t) by << 8;
			if (num > 1)
			{
				by = rar5_bits_read_byte_aligned (b);
				check_sum ^= by;
				block_size += (grub_uint32_t) by << 16;
			}
		}
		if (check_sum != 0x5A)
			return RAR_ERR_DATA;
		block_size_bits7 = (flags & 7) + 1;
		block_size += (grub_uint32_t) (block_size_bits7 >> 3);
		if (block_size == 0)
		{
			/* error in stream; original-unrar ignores it */
			b->minor_error = 1;
			block_size_bits7 = 0;
			block_size = 1;
		}
		block_size--;
		block_size_bits7 &= 7;
		b->block_end_bits7 = block_size_bits7;
		b->block_end = rar5_bits_processed_round (b) + block_size;
		rar5_bits_set_check_for_block (b);
		p->is_last_block = ((flags & 0x40) != 0);
		if ((flags & 0x80) == 0)
		{
			if (!p->table_was_filled
			    && block_size + block_size_bits7 != 0)
				return RAR_ERR_DATA;
			return 0;
		}
		p->table_was_filled = 0;
	}

	lens = grub_malloc (kTablesSizesSum_MAX);
	level_dec = grub_malloc (sizeof (*level_dec));
	if (!lens || !level_dec)
	{
		err = RAR_ERR_MEM;
		goto fail;
	}

	i = 0;
	do
	{
		unsigned len;

		if (b->buf >= b->buf_check_block)
		{
			rar5_bits_prepare (b);
			if (rar5_bits_is_block_overread (b))
				goto fail;
		}
		len = (unsigned) rar5_bits_readbits_9fix (b, 4);
		if (len == 15)
		{
			unsigned num = (unsigned) rar5_bits_readbits_9fix (b,
									   4);
			if (num != 0)
			{
				num += 2;
				num += i;
				if (num > kLevelTableSize)
					num = kLevelTableSize;
				do
					lens[i++] = 0;
				while (i < num);
				continue;
			}
		}
		lens[i++] = (grub_uint8_t) len;
	}
	while (i < kLevelTableSize);

	if (rar5_bits_is_block_overread (b))
		goto fail;
	if (rar_huff_build (level_dec, lens, kLevelTableSize, RAR_HUFF_FULL))
		goto fail;

	i = 0;
	table_size = p->is_v7 ? kTablesSizesSum_MAX
			      : kTablesSizesSum_MAX - kExtraDistSymbols_v7;
	do
	{
		int sym;

		if (b->buf >= b->buf_check_block)
		{
			rar5_bits_prepare (b);
			if (rar5_bits_is_block_overread (b))
				goto fail;
		}
		sym = rar5_bits_huff (b, level_dec);
		if (sym < 0)
			goto fail;
		if (sym < 16)
			lens[i++] = (grub_uint8_t) sym;
		else
		{
			unsigned num = ((unsigned) sym & 1) * 4;
			unsigned v = 0;
			num += num + 3
			       + (unsigned) rar5_bits_readbits9 (b, num + 3);
			num += i;
			if (num > table_size)
				num = table_size;	/* as original-unrar */
			if (sym < 16 + 2)
			{
				if (i == 0)
					goto fail;
				v = lens[i - 1];
			}
			do
				lens[i++] = (grub_uint8_t) v;
			while (i < num);
		}
	}
	while (i < table_size);

	if (rar5_bits_is_block_overread (b))
		goto fail;
	if (rar5_bits_extra_read (b))
		goto fail;

	if (rar_huff_build (&p->main_dec, &lens[0], kMainTableSize,
			    RAR_HUFF_FULL_OR_EMPTY))
		goto fail;

	if (!p->is_v7)
	{
		/* v6 streams have no extra distance symbols; shift them in */
		grub_uint8_t *dest = lens + kMainTableSize + kDistTableSize_v6
				     + kAlignTableSize + kLenTableSize - 1;
		unsigned num = kAlignTableSize + kLenTableSize;
		do
		{
			dest[kExtraDistSymbols_v7] = dest[0];
			dest--;
		}
		while (--num);
		grub_memset (lens + kMainTableSize + kDistTableSize_v6, 0,
			     kExtraDistSymbols_v7);
	}

	if (rar_huff_build (&p->dist_dec, &lens[kMainTableSize],
			    kDistTableSize_MAX, RAR_HUFF_FULL_OR_EMPTY))
		goto fail;
	if (rar_huff_build (&p->len_dec,
			    &lens[kMainTableSize + kDistTableSize_MAX
				  + kAlignTableSize],
			    kLenTableSize, RAR_HUFF_FULL_OR_EMPTY))
		goto fail;

	p->use_align_bits = 0;
	for (i = 0; i < kAlignTableSize; i++)
		if (lens[kMainTableSize + kDistTableSize_MAX + i]
		    != kNumAlignBits)
		{
			if (rar_huff_build (&p->align_dec,
					    &lens[kMainTableSize
						  + kDistTableSize_MAX],
					    kAlignTableSize,
					    RAR_HUFF_FULL_OR_EMPTY))
				goto fail;
			p->use_align_bits = 1;
			break;
		}

	p->table_was_filled = 1;
	err = 0;

fail:
	grub_free (lens);
	grub_free (level_dec);
	return err;
}

static grub_uint32_t
rar5_slot_to_len (struct rar5_bits *b, grub_uint32_t slot)
{
	const unsigned numbits = ((unsigned) slot >> 2) - 1;
	return ((4 | (slot & 3)) << numbits) + rar5_bits_readbits9 (b, numbits);
}

/* copy a match of len bytes; handles overlap */
static void
rar5_copy_match (grub_uint8_t *dest, const grub_uint8_t *src,
		 const grub_uint8_t *lim)
{
	do
		*dest++ = *src++;
	while (dest < lim);
}

/*
 * Decodes until win_pos >= limit or the block ends.  Returns 0 on OK,
 * RAR_ERR_DATA on a fatal symbol error.
 */
static int
rar5_decode_lz2 (struct rar5_dec *p)
{
	struct rar5_bits *b = &p->bits;
	grub_size_t rep0 = p->reps[0];
	grub_uint8_t *win_pos = p->window + p->win_pos;
	const grub_uint8_t *limit = p->window + p->limit;
	int err = 0;

	p->exit_type = EXIT_TYPE_NONE;

	for (;;)
	{
		int sym;
		grub_uint32_t len;

		if (win_pos >= limit)
			break;

		if (b->buf >= b->buf_check_block)
		{
			grub_uint64_t processed;

			if (rar5_bits_extra_read (b))
				break;
			if (b->buf >= b->buf_check)
			{
				if (!b->was_finished)
					break;
				/*
				 * All input has been read and the pad zone
				 * after it is filled, so no refill is needed.
				 */
			}
			processed = rar5_bits_processed_round (b);
			if (processed >= b->block_end
			    && (processed > b->block_end
				|| b->bit_pos >= b->block_end_bits7))
				break;
			if (!p->table_was_filled)
			{
				err = RAR_ERR_DATA;
				goto done;
			}
		}

		sym = rar5_bits_huff (b, &p->main_dec);
		if (sym < 0)
		{
			err = RAR_ERR_DATA;
			goto done;
		}

		if (sym < 256)
		{
			*win_pos++ = (grub_uint8_t) sym;
			continue;
		}

		if (sym < kSymbolRep + kNumReps)
		{
			if (sym >= kSymbolRep)
			{
				int slot;

				if (sym != kSymbolRep)
				{
					grub_size_t dist = p->reps[1];
					p->reps[1] = rep0;
					rep0 = dist;
					if (sym >= kSymbolRep + 2)
					{
						const unsigned k =
							(unsigned) sym
							- kSymbolRep;
						rep0 = p->reps[k];
						p->reps[k] = p->reps[2];
						p->reps[2] = dist;
					}
				}
				slot = rar5_bits_huff (b, &p->len_dec);
				if (slot < 0)
				{
					err = RAR_ERR_DATA;
					goto done;
				}
				len = (grub_uint32_t) slot;
				if (len >= 8)
					len = rar5_slot_to_len (b, len);
				len += 2;
			}
			else if (sym != 256)
			{
				len = p->last_len;
				if (len == 0)
				{
					/* ignored, like original-unrar */
					continue;
				}
			}
			else
			{
				p->exit_type = EXIT_TYPE_ADD_FILTER;
				break;
			}
		}
		else
		{
			int slot;

			p->reps[3] = p->reps[2];
			p->reps[2] = p->reps[1];
			p->reps[1] = rep0;
			len = (grub_uint32_t) sym - (kSymbolRep + kNumReps);
			if (len >= 8)
				len = rar5_slot_to_len (b, len);
			len += 2;

			slot = rar5_bits_huff (b, &p->dist_dec);
			if (slot < 0)
			{
				err = RAR_ERR_DATA;
				goto done;
			}
			rep0 = (grub_size_t) slot;

			if (rep0 >= 4)
			{
				const unsigned numbits =
					((unsigned) rep0 - 2) >> 1;
				const grub_uint64_t v = rar_get_be64 (b->buf);

				rep0 = (grub_size_t) (2 | (rep0 & 1))
				       << numbits;

				if (numbits < kNumAlignBits)
					rep0 += rar5_bits_readbits_big (b,
									numbits,
									v);
				else
				{
					len += k_LenPlusTable[numbits];
					if (p->use_align_bits)
					{
						int a;
						rep0 += (rar5_bits_readbits_big
							 (b,
							  numbits
							  - kNumAlignBits, v)
							 << kNumAlignBits);
						a = rar5_bits_huff (b,
							&p->align_dec);
						if (a < 0)
						{
							err = RAR_ERR_DATA;
							goto done;
						}
						rep0 += (grub_size_t) a;
					}
					else
						rep0 += rar5_bits_readbits_big (
							b, numbits, v);
					if (sizeof (grub_size_t) == 4
					    && numbits >= 30)
						rep0 = (grub_size_t) 0 - 1 - 1;
				}
			}
			rep0++;
		}

		{
			grub_uint8_t *dest = win_pos;

			p->last_len = len;
			win_pos += len;

			if (rep0 <= p->dict_size_for_check)
			{
				const grub_uint8_t *src;
				const grub_size_t wp =
					(grub_size_t) (dest - p->window);
				if (rep0 > wp)
				{
					grub_size_t back;
					if (p->lz_size == 0)
						goto error_dist;
					back = rep0 - wp;
					src = dest + (p->win_size - rep0);
					if (back < len)
					{
						do
							*dest++ = *src++;
						while (--back);
						src = dest - rep0;
					}
				}
				else
					src = dest - rep0;
				rar5_copy_match (dest, src, win_pos);
				continue;
			}

error_dist:
			p->lz_error = LZ_ERROR_TYPE_DIST;
			do
				*dest++ = 0;
			while (dest < win_pos);
			continue;
		}
	}

done:
	p->reps[0] = rep0;
	p->win_pos = (grub_size_t) (win_pos - p->window);
	return err;
}

/*
 * Returns 0 when the item finished normally, RAR_PAUSED when the sink
 * asked to stop, or an RAR_ERR_* code.
 */
static int
rar5_decode_lz (struct rar5_dec *p)
{
	struct rar5_bits *b = &p->bits;
	grub_size_t win_pos = p->win_pos;
	grub_uint8_t *win = p->window;
	grub_size_t limit;
	int err;

	{
		grub_size_t rem = p->win_size - win_pos;
		if (rem > kWriteStep)
			rem = kWriteStep;
		limit = win_pos + rem;
	}

	for (;;)
	{
		if (win_pos >= limit)
		{
			grub_size_t wp, rem;
			int paused;

			p->win_pos = win_pos < p->win_size ? win_pos
							   : p->win_size;
			err = rar5_write_buf (p);
			if (err)
				return err;
			if (p->unpack_size_defined
			    && p->written_file_size > p->unpack_size)
				break;
			/*
			 * A pause may only be taken once the window has been
			 * normalized below: win_pos can still point past
			 * win_size here because a match is allowed to
			 * overrun the limit.
			 */
			paused = p->base.pause_req;
			wp = p->win_pos;
			rem = p->win_size - wp;
			if (rem == 0)
			{
				p->lz_size += wp;
				win_pos -= wp;
				/* win_pos < kMaxMatchLen < win_size */
				if (win_pos)
					grub_memcpy (win, win + p->win_size,
						     win_pos);
				rem = p->win_size - win_pos;
			}
			if (rem > kWriteStep)
				rem = kWriteStep;
			limit = win_pos + rem;
			if (paused)
			{
				p->win_pos = win_pos;
				return RAR_PAUSED;
			}
			continue;
		}

		if (b->buf >= b->buf_check_block)
		{
			grub_uint64_t processed;

			p->win_pos = win_pos;
			if (rar5_bits_extra_read (b))
				break;
			rar5_bits_prepare (b);

			processed = rar5_bits_processed_round (b);
			if (processed >= b->block_end)
			{
				unsigned bits7;

				if (processed > b->block_end)
					break;
				bits7 = b->bit_pos;
				if (bits7 >= b->block_end_bits7)
				{
					if (bits7 > b->block_end_bits7)
						b->minor_error = 1;
					rar5_bits_align (b);
					if (p->is_last_block)
					{
						if (rar5_bits_extra_read (b))
							break;
						if (b->minor_error)
							return RAR_ERR_DATA;
						if (b->read_err)
							return RAR_ERR_READ;
						return 0;
					}
					err = rar5_read_tables (p);
					if (err)
						return err;
					continue;
				}
			}

			if (!p->table_was_filled)
				break;
		}

		p->limit = limit;
		p->win_pos = win_pos;
		err = rar5_decode_lz2 (p);
		if (err)
			return err;

		win_pos = p->win_pos;
		if (p->exit_type == EXIT_TYPE_ADD_FILTER)
		{
			err = rar5_add_filter (p);
			if (err)
				return err;
			continue;
		}
	}

	p->win_pos = win_pos;

	if (b->read_err)
		return RAR_ERR_READ;
	return RAR_ERR_DATA;
}

/* ---------------- top level ---------------- */

static int
rar5_code_real (struct rar5_dec *p)
{
	int res, res2;

	res = rar5_decode_lz (p);
	if (res == RAR_PAUSED)
		return RAR_PAUSED;

	res2 = 0;
	if (!p->base.sink_err && res != RAR_ERR_MEM)
		res2 = rar5_write_buf (p);
	if (res == 0)
		res = res2;
	if (res == 0 && p->unpack_size_defined
	    && p->written_file_size != p->unpack_size)
		return RAR_ERR_DATA;
	return res;
}

static int
rar5_start_item (struct rar_decoder *d, const struct rar_dec_props *props)
{
	struct rar5_dec *p = (struct rar5_dec *) d;
	grub_size_t new_size;
	const unsigned pow = props->dict_main;
	const unsigned frac = props->dict_frac;

	p->is_solid = props->solid;
	p->is_v7 = props->is_v7;
	p->item_done = 0;
	p->lz_error = LZ_ERROR_TYPE_NO;
	p->unsupported_filter = 0;
	d->sink_err = 0;

	if (pow + ((frac + 31) >> 5) > MAX_DICT_LOG - 17)
		return RAR_ERR_UNSUP;
	p->dict_size = (grub_size_t) (frac + 32) << (pow + 12);

	{
		const grub_uint64_t lz_size = p->lz_size + p->win_pos;

		if (!p->window || !p->is_solid || !p->was_init
		    || (lz_size < p->lz_end
			&& lz_size + (1u << 20) < p->lz_end))
		{
			unsigned i;
			if (p->is_solid)
				p->lz_error = LZ_ERROR_TYPE_HEADER;
			p->lz_size = 0;
			p->win_pos = 0;
			for (i = 0; i < kNumReps; i++)
				p->reps[i] = (grub_size_t) 0 - 1;
			p->last_len = 0;
			p->table_was_filled = 0;
			p->was_init = 1;
		}
		else
		{
			const grub_size_t ws = p->win_size;

			if (p->win_pos >= ws)
			{
				p->win_pos -= ws;
				p->lz_size += ws;
				grub_memcpy (p->window, p->window + ws,
					     p->win_pos);
			}

			if (lz_size < p->lz_end)
			{
				/* fill the area lost to a previous error */
				grub_uint64_t rem = p->lz_end - lz_size;
				if (rem >= ws)
				{
					grub_memset (p->window, 0, ws);
					p->lz_size = ws;
					p->win_pos = 0;
				}
				else
				{
					const grub_size_t cur = ws - p->win_pos;
					if (cur <= rem)
					{
						rem -= cur;
						grub_memset (p->window
							     + p->win_pos, 0,
							     cur);
						p->lz_size = ws;
						p->win_pos = 0;
					}
					grub_memset (p->window + p->win_pos, 0,
						     (grub_size_t) rem);
					p->win_pos += (grub_size_t) rem;
				}
			}
		}
	}

	if (p->lz_size >= ((grub_uint64_t) 1 << DICT_SIZE_BITS_MAX))
		p->lz_size = (grub_uint64_t) 1 << DICT_SIZE_BITS_MAX;
	p->lz_end = p->lz_size + p->win_pos;

	new_size = p->dict_size;
	if (new_size < kWinSize_Min)
		new_size = kWinSize_Min;

	p->unpack_size = props->unp_size;
	p->unpack_size_defined = 1;
	p->lz_end += p->unpack_size;

	if (p->is_solid && p->window)
	{
		/* a solid stream must not grow the dictionary */
		if (new_size > p->dict_size_for_check)
			return RAR_ERR_DATA;
	}
	else
	{
		grub_size_t alloc_size;

		p->dict_size_for_check = new_size;
		{
			const grub_size_t new_size_small = new_size;
			const grub_size_t align = 1u << 18;
			new_size += (1 << 7) + align;
			new_size &= ~(grub_size_t) (align - 1);
			if (new_size < new_size_small)
				return RAR_ERR_MEM;
		}
		alloc_size = new_size + kMaxMatchLen + 64;
		if (alloc_size < new_size)
			return RAR_ERR_MEM;
		if (!p->window || alloc_size > p->win_size_allocated)
		{
			grub_uint8_t *win = grub_malloc (alloc_size);
			if (!win)
				return RAR_ERR_MEM;
			grub_free (p->window);
			p->window = win;
			p->win_size_allocated = alloc_size;
		}
		p->win_size = new_size;
	}

	if (!p->input_buf)
	{
		p->input_buf = grub_malloc (kInputBufSize + kLookaheadSize);
		if (!p->input_buf)
			return RAR_ERR_MEM;
	}

	p->is_last_block = 0;
	p->num_unused_filters = 0;
	p->num_filters = 0;
	p->filter_end = 0;
	p->written_file_size = 0;
	{
		const grub_uint64_t lz_size = p->lz_size + p->win_pos;
		p->lz_file_start = lz_size;
		p->lz_written = lz_size;
	}

	rar5_bits_init (&p->bits, p->input_buf, d->read_cb, d->read_opaque);
	return 0;
}

static int
rar5_run (struct rar_decoder *d)
{
	struct rar5_dec *p = (struct rar5_dec *) d;
	int res;

	d->pause_req = 0;

	if (p->item_done)
		return RAR_DONE;

	res = rar5_code_real (p);
	if (res == RAR_PAUSED)
	{
		d->pause_req = 0;
		return RAR_PAUSED;
	}

	p->item_done = 1;
	if (res != 0)
		return res;
	if (p->lz_error)
		return RAR_ERR_DATA;
	if (p->unsupported_filter)
		return RAR_ERR_UNSUP;
	return RAR_DONE;
}

static void
rar5_free (struct rar_decoder *d)
{
	struct rar5_dec *p = (struct rar5_dec *) d;

	grub_free (p->window);
	grub_free (p->input_buf);
	grub_free (p->filters);
	grub_free (p->filter_src);
	grub_free (p->filter_dst);
	grub_free (p);
}

rar_decoder *
rar5_decoder_create (void)
{
	struct rar5_dec *p = grub_zalloc (sizeof (*p));

	if (!p)
		return 0;
	p->base.start_item = rar5_start_item;
	p->base.run = rar5_run;
	p->base.free = rar5_free;
	p->dict_size = kWinSize_Min;
	return &p->base;
}
