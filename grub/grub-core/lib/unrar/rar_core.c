/*
 *  Rover -- Filesystem browser for Windows
 *  RAR decompression library, ported to C from 7-Zip 26.02.
 *  Shared infrastructure implementation.
 *
 *  7-Zip Copyright (C) 1999-2025 Igor Pavlov.
 *  Licensed under the GNU LGPL, with the unRAR license restriction:
 *  this code may not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include "rar_core.h"

/* ---------------- CRC32 (IEEE 802.3, as used by RAR) ---------------- */

static grub_uint32_t rar_crc_table[256];
static int rar_crc_ready;

grub_uint32_t
rar_crc32 (grub_uint32_t crc, const void *buf, grub_size_t size)
{
	const grub_uint8_t *p = buf;

	if (!rar_crc_ready)
	{
		grub_uint32_t i, j;
		for (i = 0; i < 256; i++)
		{
			grub_uint32_t c = i;
			for (j = 0; j < 8; j++)
				c = (c >> 1) ^ ((c & 1) ? 0xEDB88320u : 0);
			rar_crc_table[i] = c;
		}
		rar_crc_ready = 1;
	}

	crc = ~crc;
	while (size--)
		crc = rar_crc_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
	return ~crc;
}

/* ---------------- canonical Huffman decoder ---------------- */

int
rar_huff_build (struct rar_huff *h, const grub_uint8_t *lens,
		unsigned num_syms, int mode)
{
	unsigned counts[RAR_HUFF_MAX_BITS + 1];
	unsigned cursor[RAR_HUFF_MAX_BITS + 1];
	grub_uint32_t startpos, sum;
	unsigned i, len;

	for (i = 0; i <= RAR_HUFF_MAX_BITS; i++)
		counts[i] = 0;
	for (i = 0; i < num_syms; i++)
		counts[lens[i]]++;
	counts[0] = 0;

	startpos = 0;
	sum = 0;
	h->limits[0] = 0;
	for (i = 1; i <= RAR_HUFF_MAX_BITS; i++)
	{
		h->poses[i] = sum;
		cursor[i] = sum;
		sum += counts[i];
		startpos += (grub_uint32_t) counts[i]
			    << (RAR_HUFF_MAX_BITS - i);
		if (startpos > (1u << RAR_HUFF_MAX_BITS))
			return 1;	/* oversubscribed */
		h->limits[i] = startpos;
	}
	h->limits[RAR_HUFF_MAX_BITS + 1] = 1u << RAR_HUFF_MAX_BITS;

	if (mode == RAR_HUFF_FULL
	    && startpos != (1u << RAR_HUFF_MAX_BITS))
		return 1;
	if (mode == RAR_HUFF_FULL_OR_EMPTY
	    && startpos != (1u << RAR_HUFF_MAX_BITS) && startpos != 0)
		return 1;

	/* symbols in canonical order */
	for (i = 0; i < num_syms; i++)
	{
		len = lens[i];
		if (len != 0)
			h->symbols[cursor[len]++] = (grub_uint16_t) i;
	}

	/* fast table for short codes */
	grub_memset (h->table, 0, sizeof (h->table));
	{
		grub_uint32_t pos = 0;
		for (len = 1; len <= RAR_HUFF_TABLE_BITS; len++)
		{
			unsigned k;
			for (k = 0; k < counts[len]; k++)
			{
				grub_uint16_t entry;
				grub_uint32_t idx, fill, j;
				entry = (grub_uint16_t)
					((h->symbols[h->poses[len] + k] << 4)
					 | len);
				idx = pos >> (RAR_HUFF_MAX_BITS
					      - RAR_HUFF_TABLE_BITS);
				fill = 1u << (RAR_HUFF_TABLE_BITS - len);
				for (j = 0; j < fill; j++)
					h->table[idx + j] = entry;
				pos += 1u << (RAR_HUFF_MAX_BITS - len);
			}
		}
	}

	return 0;
}

/* ---------------- buffered byte reader ---------------- */

int
rar_bytein_create (struct rar_bytein *b, grub_size_t bufsize)
{
	if (b->buf && b->bufsize == bufsize)
		return 0;
	grub_free (b->buf);
	b->buf = grub_malloc (bufsize);
	if (!b->buf)
	{
		b->bufsize = 0;
		return RAR_ERR_MEM;
	}
	b->bufsize = bufsize;
	return 0;
}

void
rar_bytein_free (struct rar_bytein *b)
{
	grub_free (b->buf);
	b->buf = 0;
	b->bufsize = 0;
}

/* refill and return the next byte; 0xFF after EOF (like CInBuffer) */
grub_uint8_t
rar_bytein_fill (struct rar_bytein *b)
{
	grub_ssize_t got;

	if (b->read_err)
	{
		b->extra++;
		return 0xFF;
	}
	b->processed += b->lim;
	b->pos = 0;
	b->lim = 0;
	got = b->read_cb (b->opaque, b->buf, b->bufsize);
	if (got < 0)
	{
		b->read_err = 1;
		got = 0;
	}
	b->lim = (grub_size_t) got;
	if (b->lim == 0)
	{
		b->extra++;
		return 0xFF;
	}
	b->pos = 1;
	return b->buf[0];
}

/* ---------------- LZ output window ---------------- */

int
rar_ow_create (struct rar_ow *ow, grub_uint32_t bufsize,
	       struct rar_decoder *d)
{
	ow->d = d;
	if (ow->buf && ow->bufsize == bufsize)
		return 0;
	grub_free (ow->buf);
	ow->buf = grub_malloc (bufsize);
	if (!ow->buf)
	{
		ow->bufsize = 0;
		return RAR_ERR_MEM;
	}
	ow->bufsize = bufsize;
	return 0;
}

void
rar_ow_free (struct rar_ow *ow)
{
	grub_free (ow->buf);
	ow->buf = 0;
	ow->bufsize = 0;
}

void
rar_ow_init (struct rar_ow *ow, int solid)
{
	if (!solid)
	{
		ow->streampos = 0;
		ow->limitpos = ow->bufsize;
		ow->pos = 0;
		ow->processed = 0;
		ow->overdict = 0;
	}
	ow->err = 0;
}

static int
rar_ow_flush_part (struct rar_ow *ow)
{
	grub_uint32_t size = (ow->streampos >= ow->pos)
			     ? (ow->bufsize - ow->streampos)
			     : (ow->pos - ow->streampos);
	int res = ow->err;

	if (res == 0)
		res = rar_deliver (ow->d, ow->buf + ow->streampos, size);
	ow->streampos += size;
	if (ow->streampos == ow->bufsize)
		ow->streampos = 0;
	if (ow->pos == ow->bufsize)
	{
		ow->overdict = 1;
		ow->pos = 0;
	}
	ow->limitpos = (ow->streampos > ow->pos) ? ow->streampos : ow->bufsize;
	ow->processed += size;
	return res;
}

int
rar_ow_flush (struct rar_ow *ow)
{
	if (ow->err)
		return ow->err;
	while (ow->streampos != ow->pos)
	{
		int res = rar_ow_flush_part (ow);
		if (res != 0)
			return res;
	}
	return 0;
}

void
rar_ow_flush_check (struct rar_ow *ow)
{
	int res = rar_ow_flush (ow);
	if (res != 0)
		ow->err = res;
}

/* distance >= 0, len > 0; returns 0 on OK, 1 on bad distance */
int
rar_ow_copy_block (struct rar_ow *ow, grub_uint32_t distance,
		   grub_uint32_t len)
{
	grub_uint32_t pos = ow->pos - distance - 1;

	if (distance >= ow->pos)
	{
		if (!ow->overdict || distance >= ow->bufsize)
			return 1;
		pos += ow->bufsize;
	}
	if (ow->limitpos - ow->pos > len && ow->bufsize - pos > len)
	{
		const grub_uint8_t *src = ow->buf + pos;
		grub_uint8_t *dest = ow->buf + ow->pos;
		ow->pos += len;
		do
			*dest++ = *src++;
		while (--len != 0);
	}
	else do
	{
		grub_uint32_t pos2;
		if (pos == ow->bufsize)
			pos = 0;
		pos2 = ow->pos;
		ow->buf[pos2++] = ow->buf[pos++];
		ow->pos = pos2;
		if (pos2 == ow->limitpos)
			rar_ow_flush_check (ow);
	}
	while (--len != 0);
	return 0;
}
