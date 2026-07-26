/*
 *  Rover -- Filesystem browser for Windows
 *  RAR decompression library, ported to C from 7-Zip 26.02.
 *  Shared infrastructure: CRC32, canonical Huffman decoder, buffered
 *  byte reader, MSB-first bit reader (NBitm), LZ output window
 *  (CLzOutWindow / COutBuffer).
 *
 *  7-Zip Copyright (C) 1999-2025 Igor Pavlov.
 *  Licensed under the GNU LGPL, with the unRAR license restriction:
 *  this code may not be used to develop a RAR (WinRAR) compatible archiver.
 */

#ifndef GRUB_UNRAR_CORE_HEADER
#define GRUB_UNRAR_CORE_HEADER	1

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/misc.h>

#include "unrar.h"

static inline grub_uint32_t
rar_get_be32 (const void *p)
{
	return grub_be_to_cpu32 (grub_get_unaligned32 (p));
}

static inline grub_uint64_t
rar_get_be64 (const void *p)
{
	return grub_be_to_cpu64 (grub_get_unaligned64 (p));
}

static inline grub_uint32_t
rar_get_le32 (const void *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static inline void
rar_set_le32 (void *p, grub_uint32_t v)
{
	grub_set_unaligned32 (p, grub_cpu_to_le32 (v));
}

grub_uint32_t rar_crc32 (grub_uint32_t crc, const void *buf, grub_size_t size);

/* ---------------- canonical Huffman decoder ---------------- */

#define RAR_HUFF_MAX_BITS	15
#define RAR_HUFF_TABLE_BITS	10
#define RAR_HUFF_MAX_SYMS	306

/* build modes, mirroring 7-Zip NHuffman::enum_BuildMode */
#define RAR_HUFF_PARTIAL	0
#define RAR_HUFF_FULL		1
#define RAR_HUFF_FULL_OR_EMPTY	2

struct rar_huff
{
	/*
	 * limits[i]: first value (normalized to RAR_HUFF_MAX_BITS bits) not
	 * covered by codes of length <= i.  limits[0] = 0.
	 * limits[RAR_HUFF_MAX_BITS + 1] = 1 << RAR_HUFF_MAX_BITS (sentinel).
	 */
	grub_uint32_t limits[RAR_HUFF_MAX_BITS + 2];
	/* poses[i]: number of symbols with code length < i */
	grub_uint32_t poses[RAR_HUFF_MAX_BITS + 1];
	/* fast table for codes of length <= RAR_HUFF_TABLE_BITS: (sym << 4) | len */
	grub_uint16_t table[1 << RAR_HUFF_TABLE_BITS];
	/* symbols in canonical order (sorted by (len, symbol)) */
	grub_uint16_t symbols[RAR_HUFF_MAX_SYMS];
};

int rar_huff_build (struct rar_huff *h, const grub_uint8_t *lens,
		    unsigned num_syms, int mode);

/*
 * Decode from v = next RAR_HUFF_MAX_BITS bits of the stream (MSB first,
 * value in [0, 1 << RAR_HUFF_MAX_BITS)).  Returns the symbol and stores
 * the code length in *numbits, or returns -1 on invalid code.
 */
static inline int
rar_huff_decode_val (const struct rar_huff *h, grub_uint32_t v,
		     unsigned *numbits)
{
	unsigned nb;

	if (v < h->limits[RAR_HUFF_TABLE_BITS])
	{
		unsigned pair = h->table[v >> (RAR_HUFF_MAX_BITS
					       - RAR_HUFF_TABLE_BITS)];
		*numbits = pair & 15;
		return pair >> 4;
	}
	for (nb = RAR_HUFF_TABLE_BITS + 1; v >= h->limits[nb]; nb++)
		;
	if (nb > RAR_HUFF_MAX_BITS)
		return -1;
	*numbits = nb;
	return h->symbols[h->poses[nb]
			  + ((v - h->limits[nb - 1])
			     >> (RAR_HUFF_MAX_BITS - nb))];
}

/* ---------------- buffered byte reader (CInBuffer) ---------------- */

struct rar_bytein
{
	grub_uint8_t *buf;
	grub_size_t bufsize;
	grub_size_t pos;	/* next byte to consume */
	grub_size_t lim;	/* valid bytes in buf */
	grub_uint64_t processed;/* stream bytes consumed before buf */
	grub_uint32_t extra;	/* 0xFF bytes fabricated after EOF */
	int read_err;
	rar_read_cb read_cb;
	void *opaque;
};

int rar_bytein_create (struct rar_bytein *b, grub_size_t bufsize);
void rar_bytein_free (struct rar_bytein *b);
grub_uint8_t rar_bytein_fill (struct rar_bytein *b);

static inline void
rar_bytein_init (struct rar_bytein *b, rar_read_cb read_cb, void *opaque)
{
	b->pos = 0;
	b->lim = 0;
	b->processed = 0;
	b->extra = 0;
	b->read_err = 0;
	b->read_cb = read_cb;
	b->opaque = opaque;
}

static inline grub_uint8_t
rar_bytein_byte (struct rar_bytein *b)
{
	if (b->pos < b->lim)
		return b->buf[b->pos++];
	return rar_bytein_fill (b);
}

static inline grub_uint64_t
rar_bytein_processed (const struct rar_bytein *b)
{
	return b->processed + b->extra + b->pos;
}

/* ------------- MSB-first bit reader (NBitm::CDecoder) ------------- */

struct rar_bitm
{
	struct rar_bytein in;
	unsigned bitpos;	/* number of free high bits in value, [0..8] */
	grub_uint32_t value;
};

static inline void
rar_bitm_normalize (struct rar_bitm *b)
{
	for (; b->bitpos >= 8; b->bitpos -= 8)
		b->value = (b->value << 8) | rar_bytein_byte (&b->in);
}

static inline void
rar_bitm_init (struct rar_bitm *b, rar_read_cb read_cb, void *opaque)
{
	rar_bytein_init (&b->in, read_cb, opaque);
	b->bitpos = 32;
	b->value = 0;
	rar_bitm_normalize (b);
}

/* numbits <= 24 */
static inline grub_uint32_t
rar_bitm_getval (const struct rar_bitm *b, unsigned numbits)
{
	return ((b->value >> (8 - b->bitpos)) & 0xFFFFFF) >> (24 - numbits);
}

static inline void
rar_bitm_movepos (struct rar_bitm *b, unsigned numbits)
{
	b->bitpos += numbits;
	rar_bitm_normalize (b);
}

static inline grub_uint32_t
rar_bitm_readbits (struct rar_bitm *b, unsigned numbits)
{
	grub_uint32_t res = rar_bitm_getval (b, numbits);
	rar_bitm_movepos (b, numbits);
	return res;
}

static inline int
rar_bitm_extra_read (const struct rar_bitm *b)
{
	return (b->in.extra > 4
		|| 32 - b->bitpos < (b->in.extra << 3));
}

static inline grub_uint64_t
rar_bitm_processed (const struct rar_bitm *b)
{
	return rar_bytein_processed (&b->in) - ((32 - b->bitpos) >> 3);
}

/* decode a Huffman symbol via a rar_bitm reader; -1 on error */
static inline int
rar_bitm_huff (struct rar_bitm *b, const struct rar_huff *h)
{
	unsigned nb;
	int sym = rar_huff_decode_val (h, rar_bitm_getval (b, RAR_HUFF_MAX_BITS),
				       &nb);
	if (sym >= 0)
		rar_bitm_movepos (b, nb);
	return sym;
}

/* ------------- LZ output window (CLzOutWindow) ------------- */

struct rar_ow
{
	grub_uint8_t *buf;
	grub_uint32_t bufsize;
	grub_uint32_t pos;
	grub_uint32_t streampos;
	grub_uint32_t limitpos;
	grub_uint64_t processed;
	int overdict;
	int err;		/* sticky sink error (RAR_ERR_WRITE) */
	struct rar_decoder *d;	/* deliver target */
};

int rar_ow_create (struct rar_ow *ow, grub_uint32_t bufsize,
		   struct rar_decoder *d);
void rar_ow_free (struct rar_ow *ow);
void rar_ow_init (struct rar_ow *ow, int solid);
int rar_ow_flush (struct rar_ow *ow);
void rar_ow_flush_check (struct rar_ow *ow);
int rar_ow_copy_block (struct rar_ow *ow, grub_uint32_t distance,
		       grub_uint32_t len);

static inline void
rar_ow_put_byte (struct rar_ow *ow, grub_uint8_t byte)
{
	grub_uint32_t pos = ow->pos;
	ow->buf[pos++] = byte;
	ow->pos = pos;
	if (pos == ow->limitpos)
		rar_ow_flush_check (ow);
}

static inline grub_uint64_t
rar_ow_processed (const struct rar_ow *ow)
{
	grub_uint64_t res = ow->processed + ow->pos - ow->streampos;
	if (ow->streampos > ow->pos)
		res += ow->bufsize;
	return res;
}

/* deliver decoded bytes to the sink; returns 0 or RAR_ERR_WRITE */
static inline int
rar_deliver (struct rar_decoder *d, const grub_uint8_t *data,
	     grub_size_t size)
{
	int r;
	if (size == 0)
		return 0;
	r = d->sink_cb (d->sink_opaque, data, size);
	if (r > 0)
		d->pause_req = 1;
	else if (r < 0)
	{
		d->sink_err = 1;
		return RAR_ERR_WRITE;
	}
	return 0;
}

#endif /* GRUB_UNRAR_CORE_HEADER */
