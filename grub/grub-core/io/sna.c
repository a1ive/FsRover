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
 * Drive Snapshot .sna image io filter, presenting the volume the image
 * holds.  Implemented from ref\snapshot.md, a reverse engineering of
 * Drive Snapshot 1.51 checked against ten sample images.
 *
 * An image is a chain of records -- a 4 byte tag, a length, an adler32
 * and the payload -- laid end to end.  The head of the first file names
 * the volume (SNV0) and, for a differential image, the base image it
 * builds on (SNI0); after that come the data chunks (SND0 for a full
 * image, SNH0 for a differential one), and the last file closes with the
 * chunk index (SNO0) and a padding record.
 *
 * The backup is sector level but filesystem aware: the volume is cut
 * into 64 KiB chunks and only the chunks holding at least one allocated
 * cluster are stored, each compressed on its own.  The index lists every
 * chunk slot in volume order, so a slot with no record is a region that
 * was never backed up and reads back as zeros -- or, in a differential
 * image, as the base image's copy of it.
 *
 * Chunks are not written in volume order (the writer is threaded), so
 * random access has to go through the index; and because the index only
 * lives in the last file of a split set, opening one means opening all
 * of them.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>
#include <grub/crypto.h>

/* grub_vdisk_open_member(), shared with the other image filters.  */
#include <vbox.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define SNA_CHUNK_SIZE		65536
#define SNA_SUBBLOCK_SIZE	4096
#define SNA_SUBBLOCKS		16	/* 4 KiB subblocks in one chunk */

#define SNA_REC_HDR_SIZE	12
/* SNO0, END_ and NEXT close their payload with the length of the rest
   of it and 'SNRE', which is what makes the index reachable from EOF.  */
#define SNA_REC_TAIL_SIZE	8

#define SNA_SNV0_SIZE		200
#define SNA_SNI0_SIZE		536	/* directory, file name, timestamp */
#define SNA_SNO0_HDR_SIZE	0x30
#define SNA_TIME_SIZE		16	/* Win32 SYSTEMTIME */

/* SNV0 +0xaf.  Only the differential value is acted on, and only as a
   cross check: SNI0 is what says an image has a base.  */
#define SNA_TYPE_DIFF		68

/* The index has 8 bits of volume number, and a differential image can
   in principle stand on another one.  */
#define SNA_MAX_FILES		256
#define SNA_MAX_DEPTH		8

/* Sanity caps against corrupt images.  */
#define SNA_MAX_HEAD_RECS	16
#define SNA_MAX_HEAD_SIZE	(64u << 10)
#define SNA_MAX_INDEX_SIZE	(64u << 20)
#define SNA_MAX_SLOTS		(64u << 20)	/* a 4 TiB volume */
#define SNA_MAX_CHUNKS		(8u << 20)	/* 512 GiB of stored data */
#define SNA_MAX_VOLUME		(1ull << 48)
/* A chunk that compressed to more than twice its own size would have
   been stored verbatim instead.  */
#define SNA_MAX_REC_SIZE	(2 * SNA_CHUNK_SIZE + 4096)

struct sna_record
{
	/* Tag and length as they sit in the file: the checksum covers
	   the record header without the checksum itself.  */
	grub_uint8_t hdr[8];
	grub_uint64_t off;	/* header offset inside its own file */
	grub_uint32_t size;	/* payload bytes */
	grub_uint32_t adler;
};

/* One stored chunk.  POS is the index entry as encoded: the volume of a
   split set in the top 8 bits, the record offset inside it below.  */
struct sna_chunk
{
	grub_uint64_t pos;
	grub_uint32_t slot;
};

struct sna_image
{
	/* files[0] is the file the image was opened from; the rest are
	   the continuation volumes of a split set.  BORROWED means
	   files[0] belongs to the caller and is not ours to close.  */
	grub_file_t files[SNA_MAX_FILES];
	unsigned nfiles;
	int borrowed;

	/* lib\adler32.c, looked up once per image the way the other io
	   modules do it.  */
	const gcry_md_spec_t *adler;

	grub_uint64_t volume_size;	/* SNV0 +0x47, the size we expose */
	grub_uint64_t span;		/* SNO0 +0x18, what the index covers */
	grub_uint64_t cut;		/* SNO0 +0x08, start of the data area */
	grub_uint32_t cut_slot;		/* first slot at or after CUT */
	grub_uint32_t nslots;		/* SNO0 +0x24 */
	grub_uint8_t time[SNA_TIME_SIZE];	/* SNV0 +0x4f */

	struct sna_chunk *chunks;
	grub_size_t nchunks;
	grub_size_t nalloc;

	/* Base image of a differential one, and ours to close.  */
	struct sna_image *base;

	/* The chunk decoded last.  Neighbouring sector reads land in it.  */
	grub_uint8_t *cache;
	grub_uint32_t cache_slot;
	int cache_valid;

	grub_uint8_t *rec;	/* record payload being decoded */
	grub_uint8_t *lz;	/* the LZ stream inside a huffman chunk */
};

/* Little endian loads: SNV0 packs its fields without any alignment.  */

static grub_uint16_t
sna_get16 (const grub_uint8_t *p)
{
	grub_uint16_t v;

	grub_memcpy (&v, p, sizeof (v));
	return grub_le_to_cpu16 (v);
}

static grub_uint32_t
sna_get32 (const grub_uint8_t *p)
{
	grub_uint32_t v;

	grub_memcpy (&v, p, sizeof (v));
	return grub_le_to_cpu32 (v);
}

static grub_uint64_t
sna_get64 (const grub_uint8_t *p)
{
	grub_uint64_t v;

	grub_memcpy (&v, p, sizeof (v));
	return grub_le_to_cpu64 (v);
}

/*
 * A record's checksum covers the record header with the checksum field
 * itself left out, then the payload.  The payload is sometimes in hand
 * and sometimes has to be streamed off the file, so the two ends of the
 * digest are split and the caller does the writing in between.
 */
#define SNA_DIGEST_CTX(name)	\
	GRUB_PROPERLY_ALIGNED_ARRAY (name, GRUB_CRYPTO_MAX_MD_CONTEXT_SIZE)

static void
sna_digest_begin (const struct sna_image *img, void *ctx, const struct sna_record *rec)
{
	img->adler->init (ctx, 0);
	img->adler->write (ctx, rec->hdr, sizeof (rec->hdr));
}

static int
sna_digest_ok (const struct sna_image *img, void *ctx, const struct sna_record *rec)
{
	grub_uint32_t sum;

	img->adler->final (ctx);
	/* adler32_read() hands back the four bytes big endian.  */
	grub_memcpy (&sum, img->adler->read (ctx), sizeof (sum));
	return grub_be_to_cpu32 (sum) == rec->adler;
}

static grub_err_t
sna_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (file) || len > grub_file_size (file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna image truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna image truncated");
	return GRUB_ERR_NONE;
}

static int
sna_tag_is (const struct sna_record *rec, const char *tag)
{
	return grub_memcmp (rec->hdr, tag, 4) == 0;
}

static grub_err_t
sna_read_record (grub_file_t file, grub_uint64_t off, struct sna_record *rec)
{
	grub_uint8_t raw[SNA_REC_HDR_SIZE];
	grub_err_t err;

	err = sna_pread (file, off, raw, sizeof (raw));
	if (err)
		return err;
	grub_memcpy (rec->hdr, raw, sizeof (rec->hdr));
	rec->off = off;
	rec->size = sna_get32 (raw + 4);
	rec->adler = sna_get32 (raw + 8);
	if (rec->size > grub_file_size (file) - off - SNA_REC_HDR_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna record runs past the image");
	return GRUB_ERR_NONE;
}

static int
sna_adler_ok (const struct sna_image *img, const struct sna_record *rec, const void *payload, grub_size_t len)
{
	SNA_DIGEST_CTX (ctx);

	sna_digest_begin (img, &ctx, rec);
	img->adler->write (&ctx, payload, len);
	return sna_digest_ok (img, &ctx, rec);
}

/* Checksum a record whose payload is not being kept.  */
static grub_err_t
sna_verify_record (const struct sna_image *img, grub_file_t file, const struct sna_record *rec)
{
	SNA_DIGEST_CTX (ctx);
	grub_uint8_t buf[512];
	grub_uint64_t off = rec->off + SNA_REC_HDR_SIZE;
	grub_uint32_t left = rec->size;

	sna_digest_begin (img, &ctx, rec);
	while (left)
	{
		grub_size_t n = left > sizeof (buf) ? sizeof (buf) : left;
		grub_err_t err = sna_pread (file, off, buf, n);

		if (err)
			return err;
		img->adler->write (&ctx, buf, n);
		off += n;
		left -= (grub_uint32_t) n;
	}
	if (!sna_digest_ok (img, &ctx, rec))
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad sna record checksum");
	return GRUB_ERR_NONE;
}

/* The record whose payload ends at END, found through its 'SNRE' tail.
   This is how the index at the far end of a multi hundred megabyte image
   is reached without walking every record in front of it.  */
static grub_err_t
sna_tail_record (grub_file_t file, grub_uint64_t end, struct sna_record *rec)
{
	grub_uint8_t tail[SNA_REC_TAIL_SIZE];
	grub_uint64_t body, start;
	grub_err_t err;

	if (end < SNA_REC_HDR_SIZE + SNA_REC_TAIL_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna image too short");
	err = sna_pread (file, end - SNA_REC_TAIL_SIZE, tail, sizeof (tail));
	if (err)
		return err;
	if (grub_memcmp (tail + 4, "SNRE", 4) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "no sna record trailer");
	body = sna_get32 (tail);
	start = end - SNA_REC_TAIL_SIZE - body;
	if (body > end - SNA_REC_TAIL_SIZE || start < SNA_REC_HDR_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna record trailer");

	err = sna_read_record (file, start - SNA_REC_HDR_SIZE, rec);
	if (err)
		return err;
	if (rec->size != body + SNA_REC_TAIL_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna record trailer does not match");
	return GRUB_ERR_NONE;
}

/* Chunk geometry.  Chunks are 64 KiB slices of the volume, with an extra
   cut at the start of the filesystem data area (so that the data area is
   aligned to its own 64 KiB grid) and a last chunk truncated at SPAN.  */

static grub_uint32_t
sna_slot_of (const struct sna_image *img, grub_uint64_t off)
{
	if (off < img->cut)
		return (grub_uint32_t) (off / SNA_CHUNK_SIZE);
	return img->cut_slot + (grub_uint32_t) ((off - img->cut) / SNA_CHUNK_SIZE);
}

static grub_uint64_t
sna_slot_start (const struct sna_image *img, grub_uint32_t slot)
{
	if (slot < img->cut_slot)
		return (grub_uint64_t) slot * SNA_CHUNK_SIZE;
	return img->cut + (grub_uint64_t) (slot - img->cut_slot) * SNA_CHUNK_SIZE;
}

static grub_uint64_t
sna_slot_end (const struct sna_image *img, grub_uint32_t slot)
{
	grub_uint64_t end;

	if (slot < img->cut_slot)
	{
		end = (grub_uint64_t) (slot + 1) * SNA_CHUNK_SIZE;
		if (end > img->cut)
			end = img->cut;
	}
	else
		end = sna_slot_start (img, slot) + SNA_CHUNK_SIZE;
	if (end > img->span)
		end = img->span;
	return end;
}

static const struct sna_chunk *
sna_find_chunk (const struct sna_image *img, grub_uint32_t slot)
{
	grub_size_t lo = 0, hi = img->nchunks;

	while (lo < hi)
	{
		grub_size_t mid = lo + (hi - lo) / 2;

		if (img->chunks[mid].slot < slot)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < img->nchunks && img->chunks[lo].slot == slot)
		return &img->chunks[lo];
	return NULL;
}

/*
 * LZSS with 12 bit distances and 4 bit lengths, the control bits pulled
 * out into their own bytes, most significant first: a clear bit is a
 * literal, a set one a match.  This is the whole of encoding 1 and the
 * second stage of encoding 3.
 */
static grub_err_t
sna_lzss (const grub_uint8_t *src, grub_size_t srclen, grub_uint8_t *out, grub_size_t outlen)
{
	grub_size_t s = 0, o = 0;
	grub_uint32_t ctrl = 0;
	unsigned nbits = 0;

	while (o < outlen)
	{
		unsigned bit;

		if (nbits == 0)
		{
			if (s >= srclen)
				goto truncated;
			ctrl = src[s++];
			nbits = 8;
		}
		bit = (ctrl >> 7) & 1;
		ctrl = (ctrl << 1) & 0xff;
		nbits--;

		if (!bit)
		{
			if (s >= srclen)
				goto truncated;
			out[o++] = src[s++];
			continue;
		}

		{
			unsigned dist, len, nl;

			if (srclen - s < 2)
				goto truncated;
			dist = src[s] | ((src[s + 1] & 0x0f) << 8);
			nl = src[s + 1] >> 4;
			s += 2;

			if (nl < 15)
				len = nl + 3;
			else
			{
				/* The escape byte is the length itself, and
				   0xff escapes once more to 16 bits.  */
				if (s >= srclen)
					goto truncated;
				len = src[s++];
				if (len == 0xff)
				{
					if (srclen - s < 2)
						goto truncated;
					len = src[s] | ((unsigned) src[s + 1] << 8);
					s += 2;
				}
			}

			if (dist == 0 || dist > o || len == 0)
				return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna lzss match");
			/* The match that fills the block may overrun it --
			   an all zero chunk is one 65535 byte match.  */
			if (len > outlen - o)
				len = (unsigned) (outlen - o);
			while (len--)
			{
				out[o] = out[o - dist];
				o++;
			}
		}
	}
	return GRUB_ERR_NONE;

truncated:
	return grub_error (GRUB_ERR_BAD_DEVICE, "truncated sna lzss stream");
}

/*
 * Huffman, the first stage of encodings 2 and 3.  The code lengths come
 * as a 256 bit map of "same length as the previous symbol" plus a nibble
 * array holding the lengths that do change, and the codes are assigned
 * canonically from the longest length down.
 */
struct sna_huff
{
	grub_uint8_t len[256];
	grub_uint16_t cnt[16];
	grub_uint16_t first_code[16];
	grub_uint16_t first_index[16];
	/* Symbols in assignment order: length descending, symbol
	   ascending inside a length.  */
	grub_uint8_t sym[256];
};

static grub_err_t
sna_huff_table (struct sna_huff *h, const grub_uint8_t *src, grub_size_t srclen, grub_size_t *bits_off)
{
	grub_uint16_t next[16];
	const grub_uint8_t *bitmap = src + 4;
	const grub_uint8_t *nibbles = src + 36;
	unsigned i, explicit_count = 0, nnibbles, nibble = 0;
	unsigned prev = 8;	/* the length symbol 0 inherits */
	unsigned index = 0, code = 0, plen = 0;
	int len;

	if (srclen < 36)
		goto truncated;
	for (i = 0; i < 256; i++)
		if (!((bitmap[i >> 3] >> (i & 7)) & 1))
			explicit_count++;
	nnibbles = (explicit_count + 1) / 2;
	if (srclen - 36 < nnibbles)
		goto truncated;

	for (i = 0; i < 256; i++)
	{
		if ((bitmap[i >> 3] >> (i & 7)) & 1)
			h->len[i] = (grub_uint8_t) prev;
		else
		{
			grub_uint8_t b = nibbles[nibble >> 1];

			/* High nibble first.  */
			prev = (nibble & 1) ? (b & 0xf) : (unsigned) (b >> 4);
			h->len[i] = (grub_uint8_t) prev;
			nibble++;
		}
	}
	*bits_off = 36 + nnibbles;

	grub_memset (h->cnt, 0, sizeof (h->cnt));
	for (i = 0; i < 256; i++)
		if (h->len[i])
			h->cnt[h->len[i]]++;

	for (len = 15; len >= 1; len--)
	{
		h->first_index[len] = (grub_uint16_t) index;
		next[len] = (grub_uint16_t) index;
		index += h->cnt[len];
	}
	if (index == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "empty sna huffman table");
	for (i = 0; i < 256; i++)
		if (h->len[i])
			h->sym[next[h->len[i]]++] = (grub_uint8_t) i;

	for (len = 15; len >= 1; len--)
	{
		if (!h->cnt[len])
			continue;
		if (plen)
			code >>= (plen - len);
		h->first_code[len] = (grub_uint16_t) code;
		code += h->cnt[len];
		plen = len;
		if (code > (1u << len))
			return grub_error (GRUB_ERR_BAD_DEVICE, "oversubscribed sna huffman table");
	}
	return GRUB_ERR_NONE;

truncated:
	return grub_error (GRUB_ERR_BAD_DEVICE, "truncated sna huffman table");
}

static grub_err_t
sna_huffman (const grub_uint8_t *src, grub_size_t srclen, grub_uint8_t *out, grub_size_t outlen)
{
	struct sna_huff h;
	grub_size_t p, o = 0;
	grub_uint32_t acc = 0;
	int nbits = 0;
	grub_err_t err;

	err = sna_huff_table (&h, src, srclen, &p);
	if (err)
		return err;

	/* The bit stream comes in 16 bit little endian words, consumed
	   most significant bit first.  */
	while (o < outlen)
	{
		unsigned code = 0;
		int len;

		while (nbits <= 16 && srclen - p >= 2)
		{
			acc = (acc << 16) | src[p] | ((grub_uint32_t) src[p + 1] << 8);
			p += 2;
			nbits += 16;
		}
		for (len = 1; len <= 15; len++)
		{
			if (nbits == 0)
				return grub_error (GRUB_ERR_BAD_DEVICE, "truncated sna huffman stream");
			nbits--;
			code = (code << 1) | ((acc >> nbits) & 1);
			acc &= (1u << nbits) - 1;
			if (h.cnt[len] && code - (unsigned) h.first_code[len] < (unsigned) h.cnt[len])
			{
				out[o++] = h.sym[h.first_index[len] + code - (unsigned) h.first_code[len]];
				break;
			}
		}
		if (len > 15)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna huffman code");
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
sna_decode (struct sna_image *img, unsigned method, const grub_uint8_t *data,
	grub_size_t dlen, grub_uint8_t *out, grub_size_t outlen)
{
	grub_uint32_t n;
	grub_err_t err;

	switch (method)
	{
	case 0:
		if (dlen != outlen)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad stored sna chunk");
		grub_memcpy (out, data, outlen);
		return GRUB_ERR_NONE;

	case 1:
		return sna_lzss (data, dlen, out, outlen);

	case 2:
		if (dlen < 4)
			return grub_error (GRUB_ERR_BAD_DEVICE, "truncated sna huffman chunk");
		if (sna_get32 (data) != outlen)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna huffman chunk length");
		return sna_huffman (data, dlen, out, outlen);

	case 3:
		if (dlen < 4)
			return grub_error (GRUB_ERR_BAD_DEVICE, "truncated sna huffman chunk");
		n = sna_get32 (data);
		if (n == 0 || n > SNA_MAX_REC_SIZE)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna lz stream length");
		err = sna_huffman (data, dlen, img->lz, n);
		if (err)
			return err;
		return sna_lzss (img->lz, n, out, outlen);
	}
	return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unknown sna chunk encoding %u", method);
}

static grub_err_t sna_read_all (struct sna_image *img, grub_uint64_t off, void *buf, grub_size_t len);

/* Decode the chunk in SLOT into the cache.  A differential chunk only
   carries the 4 KiB subblocks its bitmap marks; the rest is zero filled
   and has to be taken from the base image.  */
static grub_err_t
sna_load_chunk (struct sna_image *img, grub_uint32_t slot, const struct sna_chunk *chunk)
{
	struct sna_record rec;
	grub_file_t file;
	grub_uint64_t start = sna_slot_start (img, slot);
	grub_uint64_t vol_off;
	grub_uint32_t vol_len, data_len;
	unsigned method, bitmap, i, volno;
	grub_err_t err;

	if (img->cache_valid && img->cache_slot == slot)
		return GRUB_ERR_NONE;
	img->cache_valid = 0;

	volno = (unsigned) (chunk->pos >> 56);
	if (volno >= img->nfiles)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna index names volume %u", volno);
	file = img->files[volno];

	err = sna_read_record (file, chunk->pos & 0x00ffffffffffffffull, &rec);
	if (err)
		return err;
	if (!sna_tag_is (&rec, "SND0") && !sna_tag_is (&rec, "SNH0"))
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna index does not point at a chunk");
	if (rec.size < 20 || rec.size > SNA_MAX_REC_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna chunk size %u", rec.size);
	err = sna_pread (file, rec.off + SNA_REC_HDR_SIZE, img->rec, rec.size);
	if (err)
		return err;
	/* Every record is checksummed, and a backup reader that hands back
	   quietly wrong bytes is worse than one that says so.  */
	if (!sna_adler_ok (img, &rec, img->rec, rec.size))
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad sna chunk checksum");

	vol_off = sna_get64 (img->rec);
	vol_len = sna_get32 (img->rec + 8);
	data_len = sna_get32 (img->rec + 12);
	method = sna_get16 (img->rec + 16);
	bitmap = sna_get16 (img->rec + 18);

	if (vol_off != start || vol_len != sna_slot_end (img, slot) - start)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna chunk does not cover its slot");
	if (data_len != rec.size - 20)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna chunk payload length");

	err = sna_decode (img, method, img->rec + 20, data_len, img->cache, vol_len);
	if (err)
		return err;

	if (img->base)
		for (i = 0; i < SNA_SUBBLOCKS; i++)
		{
			grub_uint32_t sub = i * SNA_SUBBLOCK_SIZE;
			grub_uint32_t n;

			if ((bitmap & (1u << i)) || sub >= vol_len)
				continue;
			n = vol_len - sub;
			if (n > SNA_SUBBLOCK_SIZE)
				n = SNA_SUBBLOCK_SIZE;
			err = sna_read_all (img->base, start + sub, img->cache + sub, n);
			if (err)
				return err;
		}

	img->cache_slot = slot;
	img->cache_valid = 1;
	return GRUB_ERR_NONE;
}

/* Read as much of [OFF, OFF + LEN) as one chunk can serve.  */
static grub_err_t
sna_read (struct sna_image *img, grub_uint64_t off, void *buf, grub_size_t len, grub_size_t *actually_read)
{
	const struct sna_chunk *chunk;
	grub_uint32_t slot;
	grub_uint64_t start, end;
	grub_err_t err;

	*actually_read = 0;
	if (off > img->volume_size || len > img->volume_size - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of sna image");
	if (len == 0)
		return GRUB_ERR_NONE;

	/* The tail of a volume that was never in use has no index entries
	   at all.  */
	if (off >= img->span)
	{
		grub_memset (buf, 0, len);
		*actually_read = len;
		return GRUB_ERR_NONE;
	}

	slot = sna_slot_of (img, off);
	start = sna_slot_start (img, slot);
	end = sna_slot_end (img, slot);
	if (len > end - off)
		len = (grub_size_t) (end - off);

	chunk = sna_find_chunk (img, slot);
	if (!chunk)
	{
		/* A slot with no record: never backed up in a full image,
		   unchanged since the base in a differential one.  */
		if (img->base)
		{
			err = sna_read_all (img->base, off, buf, len);
			if (err)
				return err;
		}
		else
			grub_memset (buf, 0, len);
		*actually_read = len;
		return GRUB_ERR_NONE;
	}

	err = sna_load_chunk (img, slot, chunk);
	if (err)
		return err;
	grub_memcpy (buf, img->cache + (off - start), len);
	*actually_read = len;
	return GRUB_ERR_NONE;
}

static grub_err_t
sna_read_all (struct sna_image *img, grub_uint64_t off, void *buf, grub_size_t len)
{
	while (len)
	{
		grub_size_t got = 0;
		grub_err_t err = sna_read (img, off, buf, len, &got);

		if (err)
			return err;
		if (got == 0)
			return grub_error (GRUB_ERR_FILE_READ_ERROR, "sna read made no progress");
		off += got;
		buf = (grub_uint8_t *) buf + got;
		len -= got;
	}
	return GRUB_ERR_NONE;
}

static void
sna_free_image (struct sna_image *img)
{
	unsigned i;

	if (!img)
		return;
	sna_free_image (img->base);
	for (i = img->borrowed ? 1 : 0; i < img->nfiles; i++)
		grub_file_close (img->files[i]);
	grub_free (img->chunks);
	grub_free (img->cache);
	grub_free (img->rec);
	grub_free (img->lz);
	grub_free (img);
}

/* Walk the head records of the first file, which are the only ones that
   describe the image rather than carry data.  */
static grub_err_t
sna_read_head (struct sna_image *img, grub_uint8_t *snv0, grub_uint8_t *sni0, int *have_sni0)
{
	grub_file_t file = img->files[0];
	grub_uint64_t off = 0;
	int have_snv0 = 0;
	unsigned i;

	*have_sni0 = 0;
	for (i = 0; i < SNA_MAX_HEAD_RECS; i++)
	{
		struct sna_record rec;
		grub_err_t err = sna_read_record (file, off, &rec);

		if (err)
			return err;

		if (i == 0)
		{
			/* The text header is the magic: it is always the
			   first record and small enough to checksum.  */
			if (!sna_tag_is (&rec, "SNTE"))
				return grub_error (GRUB_ERR_BAD_SIGNATURE, "not a sna image");
			if (rec.size > SNA_MAX_HEAD_SIZE)
				return grub_error (GRUB_ERR_BAD_SIGNATURE, "not a sna image");
			err = sna_verify_record (img, file, &rec);
			if (err)
				return err;
		}
		else if (sna_tag_is (&rec, "SNV0"))
		{
			if (rec.size < SNA_SNV0_SIZE || rec.size > SNA_MAX_HEAD_SIZE)
				return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna volume record");
			err = sna_verify_record (img, file, &rec);
			if (err)
				return err;
			err = sna_pread (file, rec.off + SNA_REC_HDR_SIZE, snv0, SNA_SNV0_SIZE);
			if (err)
				return err;
			have_snv0 = 1;
		}
		else if (sna_tag_is (&rec, "SNI0"))
		{
			if (rec.size < SNA_SNI0_SIZE)
				return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna base image record");
			err = sna_pread (file, rec.off + SNA_REC_HDR_SIZE, sni0, SNA_SNI0_SIZE);
			if (err)
				return err;
			*have_sni0 = 1;
		}
		else if (!sna_tag_is (&rec, "SDRI"))
			break;	/* the data records start here */

		off += SNA_REC_HDR_SIZE + rec.size;
	}

	if (!have_snv0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna image has no volume record");
	return GRUB_ERR_NONE;
}

/* Name of volume IDX of a split set, derived from the first one:
   ".sna" -> ".sn1" ... ".sn9", then ".s10" and up.  No sample goes past
   nine, so the four character spelling is tried as well.  */
static char *
sna_volume_name (const char *image, unsigned idx, unsigned candidate)
{
	const char *base = image, *dot;
	char ext[8];
	char *name;
	grub_size_t stem;

	if (!image)
		return NULL;
	for (; *image; image++)
		if (*image == '/' || *image == '\\')
			base = image + 1;
	dot = grub_strrchr (base, '.');
	if (!dot || dot == base)
		return NULL;

	if (candidate == 0 && idx <= 9)
		grub_snprintf (ext, sizeof (ext), "sn%u", idx);
	else if (candidate == 0)
		grub_snprintf (ext, sizeof (ext), "s%02u", idx);
	else if (idx > 9)
		grub_snprintf (ext, sizeof (ext), "sn%u", idx);
	else
		return NULL;

	if (grub_toupper (dot[1]) == dot[1])
	{
		char *p;

		for (p = ext; *p; p++)
			*p = (char) grub_toupper (*p);
	}

	stem = (grub_size_t) (dot - base) + 1;
	name = grub_malloc (stem + grub_strlen (ext) + 1);
	if (!name)
		return NULL;
	grub_memcpy (name, base, stem);
	grub_strcpy (name + stem, ext);
	return name;
}

/* Open the rest of a split set.  Every file but the last closes with a
   NEXT record instead of END_, and every continuation opens with a copy
   of the volume record.  */
static grub_err_t
sna_open_volumes (struct sna_image *img)
{
	while (1)
	{
		struct sna_record rec;
		grub_file_t next = NULL;
		unsigned candidate;
		grub_err_t err;

		err = sna_tail_record (img->files[img->nfiles - 1], grub_file_size (img->files[img->nfiles - 1]), &rec);
		if (err)
			return err;
		if (sna_tag_is (&rec, "END_"))
			return GRUB_ERR_NONE;
		if (!sna_tag_is (&rec, "NEXT"))
			return grub_error (GRUB_ERR_BAD_DEVICE, "sna image has no end record");
		if (img->nfiles >= SNA_MAX_FILES)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many sna volumes");

		for (candidate = 0; candidate < 2 && !next; candidate++)
		{
			char *name = sna_volume_name (img->files[0]->name, img->nfiles, candidate);

			if (!name)
				continue;
			grub_errno = GRUB_ERR_NONE;
			next = grub_vdisk_open_member (img->files[0], name);
			grub_free (name);
		}
		grub_errno = GRUB_ERR_NONE;
		if (!next)
			return grub_error (GRUB_ERR_FILE_NOT_FOUND, "sna volume %u is missing", img->nfiles);

		err = sna_read_record (next, 0, &rec);
		if (!err && !sna_tag_is (&rec, "SNCO"))
			err = grub_error (GRUB_ERR_BAD_DEVICE, "sna volume %u is not a continuation", img->nfiles);
		if (err)
		{
			grub_file_close (next);
			return err;
		}
		img->files[img->nfiles++] = next;
	}
}

static grub_err_t
sna_add_chunk (struct sna_image *img, grub_uint32_t slot, grub_uint64_t pos)
{
	struct sna_chunk *chunks;

	if (img->nchunks == img->nalloc)
	{
		grub_size_t nalloc = img->nalloc ? img->nalloc * 2 : 256;
		grub_size_t sz;

		if (nalloc > SNA_MAX_CHUNKS || grub_mul (nalloc, sizeof (*chunks), &sz))
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many sna chunks");
		chunks = grub_realloc (img->chunks, sz);
		if (!chunks)
			return grub_errno;
		img->chunks = chunks;
		img->nalloc = nalloc;
	}

	chunks = &img->chunks[img->nchunks++];
	chunks->slot = slot;
	chunks->pos = pos;
	return GRUB_ERR_NONE;
}

/*
 * The index is one signed varint per chunk slot, in volume order: zero
 * means the slot holds nothing, anything else is the distance from the
 * previous record to this one.  The running position carries the volume
 * number of a split set in its top byte, so a step into the next file is
 * just a very large delta.
 */
static grub_err_t
sna_parse_index (struct sna_image *img, const grub_uint8_t *pay, grub_size_t len)
{
	const grub_uint8_t *p = pay + SNA_SNO0_HDR_SIZE;
	const grub_uint8_t *end = pay + len - SNA_REC_TAIL_SIZE;
	grub_uint64_t pos = 0, nslots;
	grub_uint32_t slot;
	grub_err_t err;

	img->cut = sna_get64 (pay + 0x08);
	img->span = sna_get64 (pay + 0x18);
	img->nslots = sna_get32 (pay + 0x24);

	if (img->span > img->volume_size)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna index covers more than the volume");
	if (img->cut > img->span)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna data area starts past the index");
	if (img->nslots > SNA_MAX_SLOTS)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "too many sna chunk slots");

	img->cut_slot = (grub_uint32_t) ((img->cut + SNA_CHUNK_SIZE - 1) / SNA_CHUNK_SIZE);
	nslots = (img->cut + SNA_CHUNK_SIZE - 1) / SNA_CHUNK_SIZE;
	if (img->span > img->cut)
		nslots += (img->span - img->cut + SNA_CHUNK_SIZE - 1) / SNA_CHUNK_SIZE;
	if (nslots != img->nslots || sna_get32 (pay + 0x20) != img->cut_slot)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna chunk layout does not add up");

	for (slot = 0; slot < img->nslots; slot++)
	{
		grub_uint64_t v = 0, sign;
		grub_int64_t delta;
		int shift = 0, b;

		do
		{
			if (p >= end || shift > 56)
				return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna index entry");
			b = *p++;
			v |= (grub_uint64_t) (b & 0x7f) << shift;
			shift += 7;
		}
		while (b & 0x80);

		/* The sign bit is the top bit of the encoded value.  */
		sign = 1ull << (shift - 1);
		delta = (v & sign) ? -(grub_int64_t) (v - sign) : (grub_int64_t) v;
		if (delta == 0)
			continue;
		if (delta < 0 && (grub_uint64_t) -delta > pos)
			return grub_error (GRUB_ERR_BAD_DEVICE, "sna index entry runs backwards");
		pos += (grub_uint64_t) delta;

		err = sna_add_chunk (img, slot, pos);
		if (err)
			return err;
	}
	if (p != end)
		return grub_error (GRUB_ERR_BAD_DEVICE, "trailing sna index data");
	return GRUB_ERR_NONE;
}

static grub_err_t
sna_read_index (struct sna_image *img)
{
	grub_file_t last = img->files[img->nfiles - 1];
	struct sna_record end, index;
	grub_uint8_t *pay;
	grub_err_t err;

	err = sna_tail_record (last, grub_file_size (last), &end);
	if (err)
		return err;
	/* The index is the record right in front of the padding one.  */
	err = sna_tail_record (last, end.off, &index);
	if (err)
		return err;
	if (!sna_tag_is (&index, "SNO0"))
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna image has no chunk index");
	if (index.size < SNA_SNO0_HDR_SIZE + SNA_REC_TAIL_SIZE || index.size > SNA_MAX_INDEX_SIZE)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "bad sna chunk index size");

	pay = grub_malloc (index.size);
	if (!pay)
		return grub_errno;
	err = sna_pread (last, index.off + SNA_REC_HDR_SIZE, pay, index.size);
	if (!err && !sna_adler_ok (img, &index, pay, index.size))
		err = grub_error (GRUB_ERR_BAD_SIGNATURE, "bad sna chunk index checksum");
	if (!err)
		err = sna_parse_index (img, pay, index.size);
	grub_free (pay);
	return err;
}

static grub_err_t sna_open_image (struct sna_image *img, int depth);

/* Open the image a differential one builds on.  It is read by this same
   code rather than through the filter chain, which is what lets the
   timestamp in SNI0 be checked against the base's own volume record.  */
static grub_err_t
sna_open_base (struct sna_image *img, const grub_uint8_t *sni0, int depth)
{
	char member[SNA_SNI0_SIZE + 2];
	char *name;
	grub_size_t dirlen;
	grub_file_t file;
	struct sna_image *base;
	grub_err_t err;

	grub_memcpy (member, sni0, 260);
	member[260] = '\0';
	dirlen = grub_strlen (member);
	if (dirlen && member[dirlen - 1] != '\\' && member[dirlen - 1] != '/')
		member[dirlen++] = '\\';
	name = member + dirlen;
	grub_memcpy (name, sni0 + 260, 260);
	name[260] = '\0';
	if (!name[0])
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna base image is not named");

	file = grub_vdisk_open_member (img->files[0], member);
	if (!file)
		return grub_errno ? grub_errno : grub_error (GRUB_ERR_FILE_NOT_FOUND, "cannot open sna base image");

	base = grub_zalloc (sizeof (*base));
	if (!base)
	{
		grub_file_close (file);
		return grub_errno;
	}
	base->files[0] = file;
	base->nfiles = 1;
	img->base = base;

	err = sna_open_image (base, depth + 1);
	if (err)
		return err;

	if (grub_memcmp (base->time, sni0 + 520, SNA_TIME_SIZE) != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna base image is not the one the image was taken against");
	if (base->volume_size != img->volume_size || base->span != img->span)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna base image covers a different volume");
	return GRUB_ERR_NONE;
}

static grub_err_t
sna_open_image (struct sna_image *img, int depth)
{
	grub_uint8_t snv0[SNA_SNV0_SIZE];
	grub_uint8_t sni0[SNA_SNI0_SIZE];
	int have_sni0;
	grub_err_t err;

	if (depth >= SNA_MAX_DEPTH)
		return grub_error (GRUB_ERR_BAD_DEVICE, "sna base image chain too deep");

	/* Every record in the format is adler32 checksummed, so there is
	   nothing to read without it.  */
	img->adler = grub_crypto_lookup_md_by_name ("adler32");
	if (!img->adler
		|| img->adler->mdlen != sizeof (grub_uint32_t)
		|| img->adler->contextsize > GRUB_CRYPTO_MAX_MD_CONTEXT_SIZE)
		return grub_error (GRUB_ERR_BAD_MODULE, "no usable adler32 digest");

	err = sna_read_head (img, snv0, sni0, &have_sni0);
	if (err)
		return err;

	img->volume_size = sna_get64 (snv0 + 0x47);
	grub_memcpy (img->time, snv0 + 0x4f, SNA_TIME_SIZE);
	if (img->volume_size == 0 || img->volume_size > SNA_MAX_VOLUME)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad sna volume size");
	if (sna_get32 (snv0 + 0xaf) == SNA_TYPE_DIFF && !have_sni0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "differential sna image names no base image");

	err = sna_open_volumes (img);
	if (err)
		return err;
	err = sna_read_index (img);
	if (err)
		return err;

	img->cache = grub_malloc (SNA_CHUNK_SIZE);
	img->rec = grub_malloc (SNA_MAX_REC_SIZE);
	img->lz = grub_malloc (SNA_MAX_REC_SIZE);
	if (!img->cache || !img->rec || !img->lz)
		return grub_errno;

	if (have_sni0)
		return sna_open_base (img, sni0, depth);
	return GRUB_ERR_NONE;
}

struct grub_sna
{
	grub_file_t file;
	struct sna_image *image;
};
typedef struct grub_sna *grub_sna_t;

static struct grub_fs grub_sna_fs;

static grub_err_t
grub_sna_close (grub_file_t file)
{
	grub_sna_t snaio = file->data;

	sna_free_image (snaio->image);
	grub_file_close (snaio->file);
	grub_free (snaio);
	/* The inner close released the shared device; the outer name is
	   freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_sna_open (grub_file_t io, enum grub_file_type type)
{
	grub_uint8_t magic[4];
	grub_file_t file;
	grub_sna_t snaio;
	struct sna_image *image;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size == GRUB_FILE_SIZE_UNKNOWN
		|| io->size < SNA_REC_HDR_SIZE + SNA_REC_TAIL_SIZE)
		return io;
	if (grub_file_seek (io, 0) == (grub_off_t) -1
		|| grub_file_read (io, magic, sizeof (magic)) != (grub_ssize_t) sizeof (magic)
		|| grub_memcmp (magic, "SNTE", sizeof (magic)) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->files[0] = io;
	image->nfiles = 1;
	image->borrowed = 1;

	if (sna_open_image (image, 0) != GRUB_ERR_NONE)
	{
		sna_free_image (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	snaio = grub_zalloc (sizeof (*snaio));
	if (!file || !snaio)
	{
		sna_free_image (image);
		grub_free (file);
		grub_free (snaio);
		return 0;
	}
	snaio->file = io;
	snaio->image = image;

	file->device = io->device;
	file->data = snaio;
	file->fs = &grub_sna_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->volume_size;

	return file;
}

static grub_ssize_t
grub_sna_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_sna_t snaio = file->data;

	if (file->offset >= snaio->image->volume_size)
		return 0;
	if (len > snaio->image->volume_size - file->offset)
		len = (grub_size_t) (snaio->image->volume_size - file->offset);
	if (sna_read_all (snaio->image, file->offset, buf, len) != GRUB_ERR_NONE)
		return -1;
	return (grub_ssize_t) len;
}

static struct grub_fs grub_sna_fs =
{
	.name = "sna",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_sna_read,
	.fs_close = grub_sna_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (sna)
{
	grub_file_filter_register (GRUB_FILE_FILTER_SNA, grub_sna_open);
}

GRUB_MOD_FINI (sna)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_SNA);
}
