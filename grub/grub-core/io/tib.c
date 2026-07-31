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
 * Acronis True Image sector-mode .tib archives -- a partition image --
 * presented as the volume they hold.  Filesystem-mode .tib archives wear
 * the same volume header but a different trailer magic and are left to
 * the tib filesystem driver instead.
 *
 * Layout:
 *
 *	+0x00		volume header		32 bytes (36 on Mac)
 *	hdr_len		block stream		[preamble][zlib stream] ...
 *			post-data region	chunk map, dedup metadata,
 *						  LDM copy, XML metainfo
 *			metadata blob		TLV, holds the chunk-map locator
 *			trailer body		holds the blob's own offset
 *			u32 size, u32 magic	0x94E18A2B
 *	EOF-48		volume footer		byte-reversed header mirror
 *
 * A block covers a fixed run of 4 KiB clusters -- 128 of them in True
 * Image 2018 and later.  Its 16-byte preamble is a bitmap of which of
 * those clusters were stored, and the deflate stream that follows holds
 * exactly those clusters back to back; the rest of the volume was empty
 * and reads back as zeros.
 *
 * Blocks are not written in volume order, so random access needs the
 * chunk map: one 12-byte record per block giving the block's offset and
 * stored length, zigzag-delta coded, byte-transposed and deflated.  Its
 * position is not in the header either -- the metadata blob near the end
 * of the archive carries the locator, reached through the trailer.
 *
 * True Image 2014-2016 archives, which spread the chunk map through the
 * block stream as inline records instead, are passed through untouched,
 * as are encrypted and multi-volume archives.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>

#include <miniz.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define TIB_VOLUME_MAGIC	0xa2b924ceU
#define TIB_TRAILER_SECTOR	0x94e18a2bU

#define TIB_HDR_LEN		0x04	/* u16, where the block stream starts */
#define TIB_HDR_LEN_MIN		32
#define TIB_HDR_LEN_MAX		36
#define TIB_HDR_VERSION		0x06	/* u16, 0 on Windows */
#define TIB_HDR_SEQUENCE	0x14	/* u32, volume index of a split set */
#define TIB_HDR_SECTOR_SIZE	0x1c
#define TIB_FOOTER_SIZE		48
#define TIB_FOOTER_SLICE	0x08	/* u64 payload length */

/* A cluster is the unit a preamble bit covers.  */
#define TIB_CLUSTER_SIZE	4096
/* True Image 2018 and later; 2014-2016 used 64 clusters and 8 bytes.  */
#define TIB_CLUSTERS_MODERN	128
#define TIB_PREAMBLE_MODERN	16
#define TIB_CLUSTERS_LEGACY	64
#define TIB_PREAMBLE_LEGACY	8

/* The chunk-map locator inside the metadata blob:
     06 <u48 LE offset> 01 00 03 <u24 LE size>  */
#define TIB_LOCATOR_SIZE	13
#define TIB_LOCATOR_SCAN	4096
#define TIB_LOCATOR_MIN_SIZE	1024
#define TIB_LOCATOR_MAX_SIZE	(100u << 20)
#define TIB_LOCATOR_MAX_BACK	(1ull << 30)

/* One chunk-map record: {u64 zigzag offset delta, u32 stored length}.  */
#define TIB_RECORD_SIZE		12

/* Sanity caps against a corrupt archive.  */
#define TIB_BLOCKS_MAX		(64u << 20)
#define TIB_IN_WINDOW		65536

/* Decompressed blocks held on to between reads.  */
#define TIB_BLOCK_CACHE		4

struct tib_block
{
	grub_uint32_t nr;		/* block this holds, or TIB_NO_BLOCK */
	grub_uint32_t age;
	grub_uint32_t len;		/* plaintext bytes */
	grub_uint8_t preamble[TIB_PREAMBLE_MODERN];
	grub_uint8_t *data;
};

#define TIB_NO_BLOCK		0xffffffffU

struct tib_image
{
	grub_file_t file;
	grub_uint64_t data_start;
	grub_uint64_t size;		/* size of the volume this exposes */

	grub_uint64_t *off;		/* per block, relative to data_start */
	grub_uint32_t *len;		/* per block, 0 when the block is empty */
	grub_uint32_t blocks;

	grub_uint32_t clusters;		/* clusters covered by one block */
	grub_uint32_t preamble;		/* bytes of bitmap in front of a block */

	struct tib_block cache[TIB_BLOCK_CACHE];
	grub_uint32_t clock;
};

/* A field whose width the format varies: the metadata-blob offset is
   4 to 8 bytes wide depending on how large the archive is, and the
   chunk-map locator packs its two values into 6 and 3 bytes.  */
static grub_uint64_t
tib_le (const grub_uint8_t *p, unsigned n)
{
	grub_uint64_t v = 0;
	unsigned i;

	for (i = 0; i < n; i++)
		v |= (grub_uint64_t) p[i] << (8 * i);
	return v;
}

static grub_err_t
tib_pread (struct tib_image *img, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (img->file) || len > grub_file_size (img->file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "tib archive truncated");
	if (grub_file_seek (img->file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (img->file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "tib archive truncated");
	return GRUB_ERR_NONE;
}

/* Inflate the zlib stream at OFF, which is IN_LEN bytes long, into a
   buffer of at most CAP bytes.  With *BUFP NULL the buffer is allocated
   and grown instead.  */
static grub_err_t
tib_inflate (struct tib_image *img, grub_uint64_t off, grub_uint64_t in_len,
	grub_uint8_t **bufp, grub_size_t cap, grub_size_t *outlen)
{
	tinfl_decompressor *dec = NULL;
	grub_uint8_t *win = NULL;
	grub_uint8_t *out = *bufp;
	grub_size_t out_cap = cap;
	grub_size_t out_total = 0, in_total = 0;
	int grow = (out == NULL);
	grub_err_t err;

	dec = grub_malloc (sizeof (*dec));
	win = grub_malloc (TIB_IN_WINDOW);
	if (!dec || !win)
	{
		err = grub_errno;
		goto fail;
	}
	if (grow)
	{
		out_cap = TIB_IN_WINDOW;
		out = grub_malloc (out_cap);
		if (!out)
		{
			err = grub_errno;
			goto fail;
		}
	}

	tinfl_init (dec);
	for (;;)
	{
		mz_uint32 flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF | TINFL_FLAG_PARSE_ZLIB_HEADER;
		grub_uint64_t remain;
		grub_size_t in_size, out_size;
		tinfl_status st;

		if (out_total == out_cap)
		{
			grub_uint8_t *bigger;

			if (!grow || out_cap >= cap)
			{
				err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "oversized tib stream");
				goto fail;
			}
			out_cap = out_cap * 2 > cap ? cap : out_cap * 2;
			bigger = grub_realloc (out, out_cap);
			if (!bigger)
			{
				err = grub_errno;
				goto fail;
			}
			out = bigger;
		}

		remain = in_len - in_total;
		in_size = remain > TIB_IN_WINDOW ? TIB_IN_WINDOW : (grub_size_t) remain;
		if (in_size == 0)
		{
			err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "truncated tib stream");
			goto fail;
		}
		err = tib_pread (img, off + in_total, win, in_size);
		if (err)
			goto fail;
		if (remain > in_size)
			flags |= TINFL_FLAG_HAS_MORE_INPUT;

		out_size = out_cap - out_total;
		st = tinfl_decompress (dec, win, &in_size, out, out + out_total, &out_size, flags);
		in_total += in_size;
		out_total += out_size;
		if (st == TINFL_STATUS_DONE)
			break;
		if (st < TINFL_STATUS_DONE || (in_size == 0 && out_size == 0))
		{
			err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad tib stream at 0x%llx", (unsigned long long) off);
			goto fail;
		}
	}

	grub_free (dec);
	grub_free (win);
	*bufp = out;
	*outlen = out_total;
	return GRUB_ERR_NONE;

fail:
	grub_free (dec);
	grub_free (win);
	if (grow)
		grub_free (out);
	return err;
}

/* ---------------- chunk map ---------------- */

/* Find the last byte of the archive.  A .tib closes with its volume
   header mirrored byte for byte, so the magic reversed marks the end
   even when the file is presented padded out to a sector.  */
static grub_err_t
tib_find_end (struct tib_image *img, grub_uint64_t *end)
{
	grub_uint8_t tail[512];
	grub_uint64_t size = grub_file_size (img->file);
	grub_size_t n = size > sizeof (tail) ? sizeof (tail) : (grub_size_t) size;
	grub_err_t err;
	int i;

	err = tib_pread (img, size - n, tail, n);
	if (err)
		return err;
	for (i = (int) n - 4; i >= 0; i--)
		if (tail[i] == 0xa2 && tail[i + 1] == 0xb9 && tail[i + 2] == 0x24 && tail[i + 3] == 0xce)
		{
			*end = size - n + i + 4;
			return GRUB_ERR_NONE;
		}
	return grub_error (GRUB_ERR_BAD_FILE_TYPE, "no tib volume footer");
}

/* Walk header, footer and trailer to the chunk map's zlib stream.  */
static grub_err_t
tib_find_chunk_map (struct tib_image *img, grub_uint64_t *map_off, grub_uint32_t *map_len)
{
	grub_uint8_t hdr[TIB_HDR_LEN_MAX];
	grub_uint8_t footer[TIB_FOOTER_SIZE];
	grub_uint8_t tail[8];
	grub_uint8_t *body = NULL;
	grub_uint8_t *blob = NULL;
	grub_uint64_t file_end;
	grub_uint64_t concat_end, meta_off, blob_end, blob_start;
	grub_uint32_t trailer_size, blob_len, i;
	unsigned n;
	grub_err_t err;

	err = tib_pread (img, 0, hdr, sizeof (hdr));
	if (err)
		return err;
	if (grub_le_to_cpu32 (grub_get_unaligned32 (hdr)) != TIB_VOLUME_MAGIC)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a tib archive");
	img->data_start = grub_le_to_cpu16 (grub_get_unaligned16 (hdr + TIB_HDR_LEN));
	if (img->data_start < TIB_HDR_LEN_MIN || img->data_start > TIB_HDR_LEN_MAX)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad tib header length");
	if (grub_le_to_cpu16 (grub_get_unaligned16 (hdr + TIB_HDR_VERSION)) != 0)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "only Windows tib archives are supported");
	/* Only the last volume of a split set carries the chunk map.  */
	if (grub_le_to_cpu32 (grub_get_unaligned32 (hdr + TIB_HDR_SEQUENCE)) > 1)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "multi-volume tib archives are not supported");
	if (grub_le_to_cpu32 (grub_get_unaligned32 (hdr + TIB_HDR_SECTOR_SIZE)) == 0x1000)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "pre-2014 tib archives are not supported");

	err = tib_find_end (img, &file_end);
	if (err)
		return err;
	if (file_end < img->data_start + TIB_FOOTER_SIZE)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "tib archive too small");
	err = tib_pread (img, file_end - TIB_FOOTER_SIZE, footer, sizeof (footer));
	if (err)
		return err;
	concat_end = img->data_start + grub_le_to_cpu64 (grub_get_unaligned64 (footer + TIB_FOOTER_SLICE));
	if (concat_end < img->data_start + 8 || concat_end > file_end)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad tib slice size");

	err = tib_pread (img, concat_end - 8, tail, sizeof (tail));
	if (err)
		return err;
	if (grub_le_to_cpu32 (grub_get_unaligned32 (tail + 4)) != TIB_TRAILER_SECTOR)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a sector-mode tib archive");
	trailer_size = grub_le_to_cpu32 (grub_get_unaligned32 (tail));
	if (trailer_size < 11 || trailer_size > 4096 || concat_end - 8 - trailer_size < img->data_start)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad tib trailer");

	body = grub_malloc (trailer_size);
	if (!body)
		return grub_errno;
	err = tib_pread (img, concat_end - 8 - trailer_size, body, trailer_size);
	if (err)
		goto out;
	/* The trailer body opens with a length-prefixed metadata-blob offset,
	   its width chosen to cover the archive size.  */
	n = body[2];
	if (n < 4 || n > 8 || 3 + n > trailer_size)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad tib trailer body");
		goto out;
	}
	meta_off = tib_le (body + 3, n);

	blob_end = concat_end - 8 - trailer_size;
	blob_start = blob_end > img->data_start + TIB_LOCATOR_SCAN ? blob_end - TIB_LOCATOR_SCAN : img->data_start;
	blob_len = (grub_uint32_t) (blob_end - blob_start);
	if (blob_len < TIB_LOCATOR_SIZE)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "tib metadata blob missing");
		goto out;
	}
	blob = grub_malloc (blob_len);
	if (!blob)
	{
		err = grub_errno;
		goto out;
	}
	err = tib_pread (img, blob_start, blob, blob_len);
	if (err)
		goto out;

	/* Scan for the locator, keeping the earliest chunk map it points at:
	   that is the start of the post-data region.  */
	*map_off = 0;
	*map_len = 0;
	for (i = 0; i + TIB_LOCATOR_SIZE <= blob_len; i++)
	{
		grub_uint64_t v;
		grub_uint32_t s;

		if (blob[i] != 0x06 || blob[i + 7] != 0x01 || blob[i + 8] != 0x00 || blob[i + 9] != 0x03)
			continue;
		v = tib_le (blob + i + 1, 6);
		s = (grub_uint32_t) tib_le (blob + i + 10, 3);
		if (v == 0 || v >= meta_off || meta_off - v >= TIB_LOCATOR_MAX_BACK)
			continue;
		if (s <= TIB_LOCATOR_MIN_SIZE || s >= TIB_LOCATOR_MAX_SIZE)
			continue;
		if (*map_len == 0 || v < *map_off)
		{
			*map_off = v;
			*map_len = s;
		}
	}
	if (*map_len == 0)
	{
		err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "tib archive has no chunk-map locator");
		goto out;
	}

	/* The map opens with a length-prefixed descriptor; the zlib stream
	   starts right after it.  */
	*map_off += img->data_start;
	err = tib_pread (img, *map_off, tail, 1);
	if (err)
		goto out;
	n = 1u + tail[0];
	if (n >= *map_len)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad tib chunk-map header");
		goto out;
	}
	*map_off += n;
	*map_len -= n;
	err = tib_pread (img, *map_off, tail, 2);
	if (err)
		goto out;
	if (tail[0] != 0x78)
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "tib chunk map is not zlib");

out:
	grub_free (body);
	grub_free (blob);
	return err;
}

/* Decode the chunk map into per-block offsets and stored lengths.  The
   plaintext is a column-major byte matrix of 12-byte records; byte J of
   record I sits at J * BLOCKS + I.  Each record's offset is a zigzag
   delta from the end of the previous block.  */
static grub_err_t
tib_decode_chunk_map (struct tib_image *img, grub_uint64_t map_off, grub_uint32_t map_len)
{
	grub_uint8_t *plain = NULL;
	grub_size_t plain_len = 0;
	grub_uint64_t running = 0;
	grub_uint32_t blocks, i;
	grub_err_t err;

	err = tib_inflate (img, map_off, map_len, &plain, (grub_size_t) TIB_BLOCKS_MAX * TIB_RECORD_SIZE, &plain_len);
	if (err)
		return err;
	if (plain_len == 0 || plain_len % TIB_RECORD_SIZE != 0)
	{
		grub_free (plain);
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad tib chunk-map size");
	}
	blocks = (grub_uint32_t) (plain_len / TIB_RECORD_SIZE);

	img->off = grub_calloc (blocks, sizeof (*img->off));
	img->len = grub_calloc (blocks, sizeof (*img->len));
	if (!img->off || !img->len)
	{
		grub_free (plain);
		return grub_errno;
	}
	img->blocks = blocks;

	for (i = 0; i < blocks; i++)
	{
		grub_uint8_t rec[TIB_RECORD_SIZE];
		grub_uint32_t lo, hi, len;
		grub_uint64_t mag, delta;
		unsigned j;

		for (j = 0; j < TIB_RECORD_SIZE; j++)
			rec[j] = plain[(grub_size_t) j * blocks + i];
		lo = grub_le_to_cpu32 (grub_get_unaligned32 (rec));
		hi = grub_le_to_cpu32 (grub_get_unaligned32 (rec + 4));
		len = grub_le_to_cpu32 (grub_get_unaligned32 (rec + 8));
		mag = ((grub_uint64_t) (hi >> 1) << 32) | ((grub_uint64_t) (lo >> 1) | ((grub_uint64_t) (hi & 1) << 31));
		delta = (lo & 1) ? ~mag + 1 : mag;
		running += delta;
		img->off[i] = running;
		img->len[i] = len;
		running += len;
	}
	grub_free (plain);
	return GRUB_ERR_NONE;
}

/* ---------------- blocks ---------------- */

static grub_uint32_t
tib_popcount (const grub_uint8_t *bits, grub_uint32_t upto)
{
	grub_uint32_t n = 0, i;

	for (i = 0; i < upto; i++)
		if (bits[i >> 3] & (1 << (i & 7)))
			n++;
	return n;
}

/* Decompress block NR, keeping it and its preamble in the cache.  */
static grub_err_t
tib_load_block (struct tib_image *img, grub_uint32_t nr,
		struct tib_block **out)
{
	struct tib_block *slot = NULL;
	grub_uint64_t off = img->data_start + img->off[nr];
	grub_uint32_t want;
	grub_size_t len;
	grub_uint8_t *data;
	grub_uint32_t i;
	grub_err_t err;

	for (i = 0; i < TIB_BLOCK_CACHE; i++)
		if (img->cache[i].nr == nr)
		{
			img->cache[i].age = ++img->clock;
			*out = &img->cache[i];
			return GRUB_ERR_NONE;
		}
	for (i = 0; i < TIB_BLOCK_CACHE; i++)
	{
		if (img->cache[i].nr == TIB_NO_BLOCK)
		{
			slot = &img->cache[i];
			break;
		}
		if (!slot || img->cache[i].age < slot->age)
			slot = &img->cache[i];
	}

	if (img->len[nr] <= img->preamble)
		return grub_error (GRUB_ERR_BAD_DEVICE, "short tib block %u", nr);
	slot->nr = TIB_NO_BLOCK;
	err = tib_pread (img, off, slot->preamble, img->preamble);
	if (err)
		return err;
	want = tib_popcount (slot->preamble, img->clusters) * TIB_CLUSTER_SIZE;
	if (want == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "empty tib block %u", nr);

	if (!slot->data)
	{
		slot->data = grub_calloc ((grub_size_t) img->clusters, TIB_CLUSTER_SIZE);
		if (!slot->data)
			return grub_errno;
	}
	data = slot->data;
	err = tib_inflate (img, off + img->preamble, img->len[nr] - img->preamble,
		&data, (grub_size_t) img->clusters * TIB_CLUSTER_SIZE, &len);
	if (err)
		return err;
	if (len != want)
		return grub_error (GRUB_ERR_BAD_DEVICE, "tib block %u holds %llu bytes, expected %u", nr, (unsigned long long) len, want);
	slot->nr = nr;
	slot->len = (grub_uint32_t) len;
	slot->age = ++img->clock;
	*out = slot;
	return GRUB_ERR_NONE;
}

/* The block geometry is not recorded anywhere, so try the modern one and
   fall back to the 2014-2016 layout if the first stored block does not
   inflate to the size its bitmap implies.  */
static grub_err_t
tib_probe_geometry (struct tib_image *img)
{
	struct tib_block *blk;
	grub_uint32_t nr;

	for (nr = 0; nr < img->blocks; nr++)
		if (img->len[nr])
			break;
	if (nr == img->blocks)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "tib archive is empty");

	img->clusters = TIB_CLUSTERS_MODERN;
	img->preamble = TIB_PREAMBLE_MODERN;
	if (tib_load_block (img, nr, &blk) == GRUB_ERR_NONE)
		return GRUB_ERR_NONE;

	grub_errno = GRUB_ERR_NONE;
	img->clusters = TIB_CLUSTERS_LEGACY;
	img->preamble = TIB_PREAMBLE_LEGACY;
	if (tib_load_block (img, nr, &blk) == GRUB_ERR_NONE)
		return GRUB_ERR_NONE;
	return grub_errno ? grub_errno : grub_error (GRUB_ERR_BAD_FILE_TYPE, "unknown tib block geometry");
}

static void
tib_free_image (struct tib_image *img)
{
	grub_uint32_t i;

	for (i = 0; i < TIB_BLOCK_CACHE; i++)
	{
		grub_free (img->cache[i].data);
		img->cache[i].data = NULL;
		img->cache[i].nr = TIB_NO_BLOCK;
	}
	grub_free (img->off);
	grub_free (img->len);
	img->off = NULL;
	img->len = NULL;
}

static grub_err_t
tib_open_image (struct tib_image *img)
{
	grub_uint64_t map_off;
	grub_uint32_t map_len, i;
	grub_err_t err;

	for (i = 0; i < TIB_BLOCK_CACHE; i++)
		img->cache[i].nr = TIB_NO_BLOCK;

	err = tib_find_chunk_map (img, &map_off, &map_len);
	if (err)
		return err;
	err = tib_decode_chunk_map (img, map_off, map_len);
	if (err)
		return err;
	err = tib_probe_geometry (img);
	if (err)
		return err;
	img->size = (grub_uint64_t) img->blocks * img->clusters * TIB_CLUSTER_SIZE;
	return GRUB_ERR_NONE;
}

/* ---------------- reads ---------------- */

static grub_err_t
tib_read (struct tib_image *img, grub_uint64_t off, void *buf, grub_size_t len,
	  grub_size_t *actually_read)
{
	struct tib_block *blk;
	grub_uint64_t block_size = (grub_uint64_t) img->clusters * TIB_CLUSTER_SIZE;
	grub_uint32_t nr, local, in_cluster, at;
	grub_size_t n;
	grub_err_t err;

	*actually_read = 0;
	if (off >= img->size)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past the end of the tib volume");
	if (len > img->size - off)
		len = (grub_size_t) (img->size - off);
	if (len == 0)
		return GRUB_ERR_NONE;

	nr = (grub_uint32_t) (off / block_size);
	local = (grub_uint32_t) ((off % block_size) / TIB_CLUSTER_SIZE);
	in_cluster = (grub_uint32_t) (off % TIB_CLUSTER_SIZE);
	n = TIB_CLUSTER_SIZE - in_cluster;
	if (n > len)
		n = len;

	if (img->len[nr] == 0)
	{
		/* Whole block omitted: zero to the end of it in one go.  */
		n = (grub_size_t) (block_size - (off % block_size));
		if (n > len)
			n = len;
		grub_memset (buf, 0, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}

	err = tib_load_block (img, nr, &blk);
	if (err)
		return err;
	if (!(blk->preamble[local >> 3] & (1 << (local & 7))))
	{
		grub_memset (buf, 0, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}

	/* Stored clusters sit back to back in the plaintext, so a whole run
	   of them can be served from one memcpy.  */
	for (at = local + 1; at < img->clusters && n < len; at++)
	{
		if (!(blk->preamble[at >> 3] & (1 << (at & 7))))
			break;
		n += TIB_CLUSTER_SIZE;
	}
	if (n > len)
		n = len;
	at = tib_popcount (blk->preamble, local) * TIB_CLUSTER_SIZE + in_cluster;
	if (at >= blk->len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad tib block %u", nr);
	if (n > blk->len - at)
		n = blk->len - at;
	grub_memcpy (buf, blk->data + at, n);
	*actually_read = n;
	return GRUB_ERR_NONE;
}

/* ---------------- io filter ---------------- */

struct grub_tib
{
	grub_file_t file;
	struct tib_image *image;
};
typedef struct grub_tib *grub_tib_t;

static struct grub_fs grub_tib_fs;

static grub_err_t
grub_tib_close (grub_file_t file)
{
	grub_tib_t tibio = file->data;

	tib_free_image (tibio->image);
	grub_free (tibio->image);
	grub_file_close (tibio->file);
	grub_free (tibio);
	/* The inner close released the shared device; the outer name is
	   freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_tib_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_tib_t tibio;
	struct tib_image *image;
	grub_uint8_t probe[4];

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < TIB_HDR_LEN_MIN + TIB_FOOTER_SIZE || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;
	if (grub_file_seek (io, 0) == (grub_off_t) -1
		|| grub_file_read (io, probe, sizeof (probe)) != (grub_ssize_t) sizeof (probe)
		|| grub_le_to_cpu32 (grub_get_unaligned32 (probe)) != TIB_VOLUME_MAGIC)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (tib_open_image (image) != GRUB_ERR_NONE)
	{
		tib_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	tibio = grub_zalloc (sizeof (*tibio));
	if (!file || !tibio)
	{
		tib_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (tibio);
		return 0;
	}
	tibio->file = io;
	tibio->image = image;

	file->device = io->device;
	file->data = tibio;
	file->fs = &grub_tib_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->size;

	return file;
}

static grub_ssize_t
grub_tib_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_tib_t tibio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = tib_read (tibio->image, read_offset, buf, len, &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR, "tib read made no progress");
			break;
		}
		read_offset += real_size;
		buf += real_size;
		size += real_size;
		if (real_size >= len)
			break;
		len -= real_size;
	}

	if (err != GRUB_ERR_NONE)
	{
		if (!grub_errno)
			grub_error (err, "tib archive read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_tib_fs =
{
	.name = "tib",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_tib_read,
	.fs_close = grub_tib_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (tib)
{
	grub_file_filter_register (GRUB_FILE_FILTER_TIB, grub_tib_open);
}

GRUB_MOD_FINI (tib)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_TIB);
}
