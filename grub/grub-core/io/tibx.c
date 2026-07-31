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
 * Acronis True Image .tibx archives (True Image 2020 and later), the
 * "archive3" container, presented as the volume image they hold.
 *
 * A .tibx is a store of 4 KiB pages.  Every page opens with an eight
 * byte envelope, 41 <type> 00 00 followed by a big-endian CRC-32C of the
 * page, and the rest of the page is the body:
 *
 *	0x01  ARCH  archive header, with a 19 entry TLV directory
 *	0x02  ARCI  commit record
 *	0x03  LEAF  LSM tree leaf
 *	0x04  LDIR  LSM tree interior node
 *	0x05        dedup filter
 *	0xff        bulk data: an SG segment header or its continuation
 *
 * Bulk content lives in Zstd-compressed segments; two LSM trees index
 * them.  data_map (TLV slot 1) maps (volume, source byte offset) to a
 * segment id, and segment_map (TLV slot 2) maps a segment id to the page
 * it starts on.  Reading a byte of the backed-up volume therefore means
 * a data_map lookup, a segment_map lookup, and one segment decompression.
 * Both trees are held in memory after the first open; LSM pages are
 * LZ4-compressed and decompressed segments are cached.
 *
 * An archive holds several streams: the source disk's first sectors, the
 * content of each backed-up partition, and a set of small TLV
 * descriptors -- one for the disk, giving its sector size and length,
 * and one per partition, giving where it starts and how long it is.
 * Those descriptors are what makes the source disk reconstructible.
 *
 * A backup of two or more partitions is therefore presented as the whole
 * source disk, with every partition at its own offset, so the partition
 * map and filesystem drivers see the layout the disk really had.  When
 * the disk was GPT-partitioned the archive only keeps the protective
 * MBR -- Acronis rebuilds the GPT from the descriptors on restore -- so
 * this filter rebuilds one too, from the same fields.  A backup holding
 * a single partition skips all that and is presented as that partition,
 * ready to mount.
 *
 * Encrypted archives (segments with a non-zero key id) are rejected.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>
#include <grub/gpt_partition.h>
#include <grub/msdos_partition.h>

#include <lz4.h>
#include <zstd.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define TIBX_PAGE_SIZE		4096
#define TIBX_ENVELOPE		8
#define TIBX_PAGE_BODY		(TIBX_PAGE_SIZE - TIBX_ENVELOPE)

#define TIBX_PAGE_MAGIC		0x41
#define TIBX_PAGE_ARCH		0x01
#define TIBX_PAGE_LEAF		0x03
#define TIBX_PAGE_LDIR		0x04
#define TIBX_PAGE_DATA		0xff

/* Archive header, relative to the start of the page body.  */
#define TIBX_ARCH_SIZE		0x04	/* BE u32 total header length */
#define TIBX_ARCH_VERSION	0x08	/* BE u16 */
#define TIBX_ARCH_SEQ		0x188	/* BE u64 commit sequence */
#define TIBX_ARCH_TLV		0x400	/* start of the TLV directory */
#define TIBX_TLV_SLOTS		19
#define TIBX_TLV_DATA_MAP	1
#define TIBX_TLV_SEGMENT_MAP	2

/* LSM superblock ("L-SB") fields.  */
#define TIBX_LSB_SEQ		0x08
#define TIBX_LSB_KEY_LEN	0x10
#define TIBX_LSB_VAL_LEN	0x14
#define TIBX_LSB_CTREES		0x18
#define TIBX_LSB_CTREE_SIZE	32
#define TIBX_LSB_MEM_ENC	0x158
#define TIBX_LSB_MEM_COUNT	0x15a
#define TIBX_LSB_MEM_EXTRA	0x15c
#define TIBX_LSB_MEM_PAYLOAD	0x178
#define TIBX_LSB_MIN_SIZE	0x178

/* LEAF / LDIR page header, relative to the start of the page body.  */
#define TIBX_LSM_ENC		0x05
#define TIBX_LSM_CELLS		0x06	/* BE u16 */
#define TIBX_LSM_ULEN		0x08	/* BE u32 */
#define TIBX_LSM_CLEN		0x0c	/* BE u32 */
#define TIBX_LSM_STREAM		0x34
#define TIBX_LSM_ENC_RAW	0
#define TIBX_LSM_ENC_LZ4	1
#define TIBX_LSM_ENC_CRYPT	0x80
/* Cells are emitted in groups of at most 24, each group headed by a
   little-endian u32 whose low byte is the group's cell count and whose
   top three bytes are a bitmap of which cells carry a value.  */
#define TIBX_CELL_GROUP_MAX	24

/* SG segment header, relative to the start of the page.  */
#define TIBX_SG_MAGIC		0x08	/* "SG\0\1" */
#define TIBX_SG_LEN		0x0c	/* BE u32 plaintext length */
#define TIBX_SG_ZLEN		0x10	/* BE u32 stored length */
#define TIBX_SG_KEY		0x14	/* BE u32 encryption key id */
#define TIBX_SG_COMP		0x18	/* BE u16 codec */
#define TIBX_SG_PAYLOAD		0x2c
#define TIBX_SG_FIRST_BYTES	(TIBX_PAGE_SIZE - TIBX_SG_PAYLOAD)
#define TIBX_COMP_FAMILY(c)	((c) >> 8)
#define TIBX_COMP_NONE		0
#define TIBX_COMP_ZSTD		3

/* data_map record layout.  */
#define TIBX_DMAP_KEY_LEN	31
#define TIBX_DMAP_VAL_LEN	10
#define TIBX_DMAP_KEY_ID	23	/* BE u64 extent id, rises over time */
/* An extent that fills its whole segment.  Otherwise the value's index
   field counts 16-byte units from the start of the segment.  */
#define TIBX_EXTENT_WHOLE	0xffff
#define TIBX_EXTENT_GRAIN	16

/* segment_map record layout: 8-byte key, and a value whose first eight
   bytes are the page count (LE) and the first page (BE).  */
#define TIBX_SMAP_KEY_LEN	8
#define TIBX_SMAP_VAL_LEN	32

/* Stream descriptors.  Their records are tag(u16 LE) + length, where a
   length byte with bit 7 set means the length is the low 15 bits of the
   next two bytes, big-endian.  */
#define TIBX_DESC_MAX		4096	/* bytes of descriptor we look at */
#define TIBX_TAG_SECTOR_SIZE	0x0002
#define TIBX_TAG_FIRST_LBA	0x0011	/* partition descriptors only */
#define TIBX_TAG_SECTORS	0x0012
#define TIBX_TAG_PART_GUID	0x006a
#define TIBX_TAG_TYPE_GUID	0x00b6

/* The reconstructed disk is presented in 512-byte sectors, so only a
   source disk with that sector size can be rebuilt.  */
#define TIBX_SECTOR		512

/* A rebuilt GPT: one header sector then 128 entries of 128 bytes.  */
#define TIBX_GPT_HEADER_SIZE	sizeof (struct grub_gpt_header)
#define TIBX_GPT_ENTRIES	128
#define TIBX_GPT_ENTRY_SIZE	sizeof (struct grub_gpt_partentry)
#define TIBX_GPT_SECTORS	(1 + TIBX_GPT_ENTRIES * TIBX_GPT_ENTRY_SIZE \
				 / TIBX_SECTOR)
#define TIBX_GPT_FIRST_USABLE	(1 + TIBX_GPT_SECTORS)
#define TIBX_PARTS_MAX		TIBX_GPT_ENTRIES

/* Sanity caps.  */
#define TIBX_ARCH_SCAN		64		/* pages searched for a header */
#define TIBX_HDR_MAX		(1 << 20)
#define TIBX_LSM_DEPTH_MAX	16
#define TIBX_LSM_PAGES_MAX	(1u << 24)
#define TIBX_CELL_BUF_MAX	(1 << 20)
#define TIBX_SEGMENT_MAX	(64 << 20)
#define TIBX_RECORDS_MAX	(64u << 20)

/* Decompressed segments held on to between reads.  */
#define TIBX_SEG_CACHE		8

struct tibx_extent
{
	grub_uint64_t off;	/* byte offset on the disk being presented */
	grub_uint64_t seg;	/* segment holding the bytes, 0 for a hole */
	grub_uint64_t id;	/* extent id: rises with every slice written */
	grub_uint32_t len;
	grub_uint32_t at;	/* byte offset within the segment */
};

struct tibx_seg
{
	grub_uint64_t id;
	grub_uint32_t page;
};

/* One backed-up stream, while the archive is being sized up.  The
   locator is for the extent at offset 0, which is where a descriptor
   stream keeps its records and a partition its boot sector.  */
struct tibx_vol
{
	grub_uint64_t id;
	grub_uint64_t end;
	grub_uint64_t seg;
	grub_uint32_t idx;
	grub_uint32_t head;	/* length of that extent */
};

/* One partition, as its descriptor describes it.  */
struct tibx_part
{
	grub_uint64_t desc;	/* stream the descriptor came from */
	grub_uint64_t first_lba;
	grub_uint64_t sectors;
	grub_uint8_t type[16];	/* GPT type GUID, all zero if unknown */
	grub_uint8_t guid[16];
};

/* A stream and where its bytes land on the disk being presented.  */
struct tibx_place
{
	grub_uint64_t vol;
	grub_uint64_t base;
};

struct tibx_cached_seg
{
	grub_uint64_t id;
	grub_uint8_t *data;
	grub_uint32_t len;
	grub_uint32_t age;
};

struct tibx_image
{
	grub_file_t file;
	grub_uint64_t pages;
	grub_uint64_t size;	/* size of the volume this exposes */

	struct tibx_extent *ext;
	grub_uint32_t next;	/* extents collected so far */
	grub_uint32_t cap;
	grub_uint32_t cur;	/* extent the previous read landed in */

	struct tibx_seg *seg;
	grub_uint32_t nseg;
	grub_uint32_t seg_cap;

	struct tibx_vol *vol;
	grub_uint32_t nvol;
	grub_uint32_t vol_cap;

	struct tibx_cached_seg cache[TIBX_SEG_CACHE];
	grub_uint32_t clock;

	/* Where each kept stream lands; the extent collector skips any
	   stream not listed here.  */
	struct tibx_place place[TIBX_PARTS_MAX + 1];
	grub_uint32_t nplace;
	grub_uint32_t cur_place;	/* entry the previous extent matched */

	/* Partition table rebuilt for a disk whose own one is not stored.  */
	grub_uint8_t *synth;
	grub_uint64_t synth_at;
	grub_uint32_t synth_len;
};

/* An N-byte little-endian field, N being whatever the record carried:
   a descriptor sizes each of its values to fit.  */
static grub_uint64_t
tibx_le (const grub_uint8_t *p, grub_uint32_t n)
{
	grub_uint64_t v = 0;
	grub_uint32_t i;

	for (i = 0; i < n; i++)
		v |= (grub_uint64_t) p[i] << (8 * i);
	return v;
}

static grub_err_t
tibx_pread (struct tibx_image *img, grub_uint64_t off, void *buf,
	    grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (img->file) || len > grub_file_size (img->file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "tibx image truncated");
	if (grub_file_seek (img->file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (img->file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "tibx image truncated");
	return GRUB_ERR_NONE;
}

static grub_err_t
tibx_read_page (struct tibx_image *img, grub_uint64_t page, grub_uint8_t *buf)
{
	if (page >= img->pages)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "tibx page %llu is past the end", (unsigned long long) page);
	return tibx_pread (img, page * TIBX_PAGE_SIZE, buf, TIBX_PAGE_SIZE);
}

/* ---------------- segments ---------------- */

/* Gather a segment's stored bytes: the first page carries them from
   +0x2C, and any continuation page from just past its envelope.  */
static grub_err_t
tibx_read_stored (struct tibx_image *img, grub_uint64_t page, grub_uint8_t *buf, grub_uint32_t zlen)
{
	grub_uint32_t done;
	grub_err_t err;

	done = zlen < TIBX_SG_FIRST_BYTES ? zlen : TIBX_SG_FIRST_BYTES;
	err = tibx_pread (img, page * TIBX_PAGE_SIZE + TIBX_SG_PAYLOAD, buf, done);
	if (err)
		return err;
	while (done < zlen)
	{
		grub_uint32_t take = zlen - done;

		page++;
		if (take > TIBX_PAGE_BODY)
			take = TIBX_PAGE_BODY;
		err = tibx_pread (img, page * TIBX_PAGE_SIZE + TIBX_ENVELOPE, buf + done, take);
		if (err)
			return err;
		done += take;
	}
	return GRUB_ERR_NONE;
}

/* Decompress the segment whose header page is PAGE.  */
static grub_err_t
tibx_load_segment (struct tibx_image *img, grub_uint64_t page, grub_uint8_t **out, grub_uint32_t *outlen)
{
	grub_uint8_t hdr[TIBX_SG_PAYLOAD];
	grub_uint8_t *raw = NULL;
	grub_uint8_t *plain = NULL;
	grub_uint32_t len, zlen, key;
	grub_uint16_t comp;
	grub_err_t err;

	if (page >= img->pages)
		return grub_error (GRUB_ERR_BAD_DEVICE, "tibx segment page %llu is past the end", (unsigned long long) page);
	err = tibx_pread (img, page * TIBX_PAGE_SIZE, hdr, sizeof (hdr));
	if (err)
		return err;
	if (hdr[0] != TIBX_PAGE_MAGIC || hdr[1] != TIBX_PAGE_DATA
		|| grub_memcmp (hdr + TIBX_SG_MAGIC, "SG\0\1", 4) != 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "no tibx segment on page %llu", (unsigned long long) page);
	len = grub_be_to_cpu32 (grub_get_unaligned32 (hdr + TIBX_SG_LEN));
	zlen = grub_be_to_cpu32 (grub_get_unaligned32 (hdr + TIBX_SG_ZLEN));
	key = grub_be_to_cpu32 (grub_get_unaligned32 (hdr + TIBX_SG_KEY));
	comp = grub_be_to_cpu16 (grub_get_unaligned16 (hdr + TIBX_SG_COMP));
	if (key != 0)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "encrypted tibx archives are not supported");
	if (len == 0 || len > TIBX_SEGMENT_MAX || zlen > TIBX_SEGMENT_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad tibx segment size");

	raw = grub_malloc (zlen ? zlen : 1);
	if (!raw)
		return grub_errno;
	err = tibx_read_stored (img, page, raw, zlen);
	if (err)
		goto fail;

	if (TIBX_COMP_FAMILY (comp) == TIBX_COMP_NONE)
	{
		if (zlen != len)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE, "bad stored tibx segment");
			goto fail;
		}
		*out = raw;
		*outlen = len;
		return GRUB_ERR_NONE;
	}
	if (TIBX_COMP_FAMILY (comp) != TIBX_COMP_ZSTD)
	{
		err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unknown tibx codec 0x%x", comp);
		goto fail;
	}

	plain = grub_malloc (len);
	if (!plain)
	{
		err = grub_errno;
		goto fail;
	}
	if (ZSTD_decompress (plain, len, raw, zlen) != len)
	{
		err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad tibx segment on page %llu", (unsigned long long) page);
		goto fail;
	}
	grub_free (raw);
	*out = plain;
	*outlen = len;
	return GRUB_ERR_NONE;

fail:
	grub_free (raw);
	grub_free (plain);
	return err;
}

/* Index of segment ID in the sorted segment_map, or -1.  */
static grub_uint32_t
tibx_find_segment (struct tibx_image *img, grub_uint64_t id)
{
	grub_uint32_t lo = 0, hi = img->nseg;

	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (img->seg[mid].id < id)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < img->nseg && img->seg[lo].id == id)
		return lo;
	return (grub_uint32_t) -1;
}

static grub_err_t
tibx_segment (struct tibx_image *img, grub_uint64_t id, const grub_uint8_t **data, grub_uint32_t *len)
{
	struct tibx_cached_seg *slot = NULL;
	grub_uint32_t i, nr;
	grub_uint8_t *plain;
	grub_uint32_t plen;
	grub_err_t err;

	for (i = 0; i < TIBX_SEG_CACHE; i++)
		if (img->cache[i].data && img->cache[i].id == id)
		{
			img->cache[i].age = ++img->clock;
			*data = img->cache[i].data;
			*len = img->cache[i].len;
			return GRUB_ERR_NONE;
		}

	nr = tibx_find_segment (img, id);
	if (nr == (grub_uint32_t) -1)
		return grub_error (GRUB_ERR_BAD_DEVICE, "tibx segment %llu is not mapped", (unsigned long long) id);
	err = tibx_load_segment (img, img->seg[nr].page, &plain, &plen);
	if (err)
		return err;

	for (i = 0; i < TIBX_SEG_CACHE; i++)
	{
		if (!img->cache[i].data)
		{
			slot = &img->cache[i];
			break;
		}
		if (!slot || img->cache[i].age < slot->age)
			slot = &img->cache[i];
	}
	grub_free (slot->data);
	slot->id = id;
	slot->data = plain;
	slot->len = plen;
	slot->age = ++img->clock;
	*data = plain;
	*len = plen;
	return GRUB_ERR_NONE;
}

/* ---------------- LSM trees ---------------- */

/* Decode the cell stream of a LEAF or LDIR page into OUT.  */
static grub_err_t
tibx_cell_stream (const grub_uint8_t *body, grub_uint8_t **out,
		  grub_uint32_t *outlen)
{
	grub_uint32_t ulen = grub_be_to_cpu32 (grub_get_unaligned32 (body + TIBX_LSM_ULEN));
	grub_uint32_t clen = grub_be_to_cpu32 (grub_get_unaligned32 (body + TIBX_LSM_CLEN));
	grub_uint8_t enc = body[TIBX_LSM_ENC];
	const grub_uint8_t *in = body + TIBX_LSM_STREAM;
	grub_uint8_t *buf;
	grub_uint32_t pos = 0, done = 0;

	if (enc & TIBX_LSM_ENC_CRYPT)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "encrypted tibx archives are not supported");
	if (ulen > TIBX_CELL_BUF_MAX || clen > TIBX_PAGE_BODY - TIBX_LSM_STREAM)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad tibx page sizes");

	buf = grub_malloc (ulen ? ulen : 1);
	if (!buf)
		return grub_errno;

	if ((enc & ~TIBX_LSM_ENC_CRYPT) == TIBX_LSM_ENC_RAW)
	{
		if (clen != ulen)
		{
			grub_free (buf);
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad raw tibx page");
		}
		grub_memcpy (buf, in, ulen);
		*out = buf;
		*outlen = ulen;
		return GRUB_ERR_NONE;
	}
	if ((enc & ~TIBX_LSM_ENC_CRYPT) != TIBX_LSM_ENC_LZ4)
	{
		grub_free (buf);
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unknown tibx page encoding %u", enc);
	}

	/* A run of LZ4 blocks, each decompressed against the bytes already
	   emitted, exactly as LZ4_decompress_safe_continue would.  */
	while (pos + 8 <= clen)
	{
		grub_uint32_t cs = grub_be_to_cpu32 (grub_get_unaligned32 (in + pos));
		grub_uint32_t ds = grub_be_to_cpu32 (grub_get_unaligned32 (in + pos + 4));
		int dict = done > 65536 ? 65536 : (int) done;
		int got;

		pos += 8;
		if (cs > clen - pos || ds > ulen - done)
		{
			grub_free (buf);
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad tibx lz4 block");
		}
		got = LZ4_decompress_safe_usingDict ((const char *) in + pos, (char *) buf + done,
				(int) cs, (int) ds, (const char *) buf + done - dict, dict);
		if (got != (int) ds)
		{
			grub_free (buf);
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad tibx lz4 stream");
		}
		pos += cs;
		done += ds;
	}
	if (done != ulen)
	{
		grub_free (buf);
		return grub_error (GRUB_ERR_BAD_DEVICE, "short tibx page");
	}
	*out = buf;
	*outlen = ulen;
	return GRUB_ERR_NONE;
}

typedef grub_err_t (*tibx_cell_hook) (struct tibx_image *img, const grub_uint8_t *key, const grub_uint8_t *val);

/* Walk a subtree, feeding every live leaf cell to HOOK.  */
static grub_err_t
tibx_walk_page (struct tibx_image *img, grub_uint64_t page,
	grub_uint32_t klen, grub_uint32_t vlen, int depth, grub_uint32_t *budget, tibx_cell_hook hook)
{
	grub_uint8_t *raw = NULL;
	grub_uint8_t *cells = NULL;
	grub_uint32_t clen, ncell, i, pos = 0;
	grub_err_t err = GRUB_ERR_NONE;

	if (depth > TIBX_LSM_DEPTH_MAX || page >= img->pages)
		return GRUB_ERR_NONE;
	if (*budget == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "tibx tree too large");
	(*budget)--;

	raw = grub_malloc (TIBX_PAGE_SIZE);
	if (!raw)
		return grub_errno;
	err = tibx_read_page (img, page, raw);
	if (err)
		goto out;
	if (raw[0] != TIBX_PAGE_MAGIC || (raw[1] != TIBX_PAGE_LEAF && raw[1] != TIBX_PAGE_LDIR))
		goto out;	/* pruned or foreign page; skip it */

	err = tibx_cell_stream (raw + TIBX_ENVELOPE, &cells, &clen);
	if (err)
		goto out;
	ncell = grub_be_to_cpu16 (grub_get_unaligned16 (raw + TIBX_ENVELOPE + TIBX_LSM_CELLS));

	if (raw[1] == TIBX_PAGE_LDIR)
	{
		/* Interior cells are a flat key plus an 8-byte child offset.  */
		for (i = 0; i < ncell; i++)
		{
			grub_uint64_t child;

			if (pos + klen + 8 > clen)
				break;
			child = grub_be_to_cpu64 (grub_get_unaligned64 (cells + pos + klen));
			pos += klen + 8;
			err = tibx_walk_page (img, child / TIBX_PAGE_SIZE, klen, vlen, depth + 1, budget, hook);
			if (err)
				goto out;
		}
		goto out;
	}

	for (i = 0; i < ncell;)
	{
		grub_uint32_t group, bitmap, j;

		if (pos + 4 > clen)
			break;
		group = cells[pos];
		bitmap = ((grub_uint32_t) cells[pos + 3]) | ((grub_uint32_t) cells[pos + 2] << 8) | ((grub_uint32_t) cells[pos + 1] << 16);
		pos += 4;
		if (group == 0 || group > TIBX_CELL_GROUP_MAX)
		{
			err = grub_error (GRUB_ERR_BAD_DEVICE, "bad tibx cell group");
			goto out;
		}
		for (j = 0; j < group && i < ncell; j++, i++)
		{
			int alive = (bitmap >> j) & 1;

			if (pos + klen + (alive ? vlen : 0) > clen)
			{
				i = ncell;
				break;
			}
			if (alive)
			{
				err = hook (img, cells + pos, cells + pos + klen);
				if (err)
					goto out;
			}
			pos += klen + (alive ? vlen : 0);
		}
	}

out:
	grub_free (raw);
	grub_free (cells);
	return err;
}

/* Decode the residual mem-tree an L-SB carries inline.  Records not yet
   flushed to an on-disk run live only here.  */
static grub_err_t
tibx_walk_memtree (struct tibx_image *img, const grub_uint8_t *sb,
	grub_uint32_t sb_len, grub_uint32_t klen, grub_uint32_t vlen, tibx_cell_hook hook)
{
	const grub_uint8_t *extra = sb + TIBX_LSB_MEM_PAYLOAD;
	grub_uint32_t extra_len;
	grub_uint32_t ncell, i, pos = 0;
	grub_uint8_t enc;
	grub_uint8_t *cells = NULL;
	grub_uint32_t clen;
	grub_err_t err = GRUB_ERR_NONE;

	if (sb_len <= TIBX_LSB_MEM_PAYLOAD)
		return GRUB_ERR_NONE;
	extra_len = sb_len - TIBX_LSB_MEM_PAYLOAD;
	enc = sb[TIBX_LSB_MEM_ENC];
	ncell = grub_be_to_cpu16 (grub_get_unaligned16 (sb + TIBX_LSB_MEM_COUNT));
	if (ncell == 0 || klen == 0)
		return GRUB_ERR_NONE;
	if (enc & TIBX_LSM_ENC_CRYPT)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "encrypted tibx archives are not supported");

	if ((enc & ~TIBX_LSM_ENC_CRYPT) == TIBX_LSM_ENC_RAW)
	{
		clen = extra_len;
		cells = grub_malloc (clen ? clen : 1);
		if (!cells)
			return grub_errno;
		grub_memcpy (cells, extra, clen);
	}
	else if ((enc & ~TIBX_LSM_ENC_CRYPT) == TIBX_LSM_ENC_LZ4)
	{
		grub_uint32_t cs, ds;

		if (extra_len < 8)
			return GRUB_ERR_NONE;
		cs = grub_be_to_cpu32 (grub_get_unaligned32 (extra));
		ds = grub_be_to_cpu32 (grub_get_unaligned32 (extra + 4));
		if (cs > extra_len - 8 || ds > TIBX_CELL_BUF_MAX)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad tibx mem-tree");
		cells = grub_malloc (ds ? ds : 1);
		if (!cells)
			return grub_errno;
		if (LZ4_decompress_safe ((const char *) extra + 8, (char *) cells, (int) cs, (int) ds) != (int) ds)
		{
			grub_free (cells);
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad tibx mem-tree");
		}
		clen = ds;
	}
	else
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unknown tibx mem-tree encoding %u", enc);

	for (i = 0; i < ncell;)
	{
		grub_uint32_t group, bitmap, j;

		if (pos + 4 > clen)
			break;
		group = cells[pos];
		bitmap = ((grub_uint32_t) cells[pos + 3]) | ((grub_uint32_t) cells[pos + 2] << 8) | ((grub_uint32_t) cells[pos + 1] << 16);
		pos += 4;
		if (group == 0 || group > TIBX_CELL_GROUP_MAX)
			break;
		for (j = 0; j < group && i < ncell; j++, i++)
		{
			int alive = (bitmap >> j) & 1;

			if (pos + klen + (alive ? vlen : 0) > clen)
			{
				i = ncell;
				break;
			}
			if (alive)
			{
				err = hook (img, cells + pos, cells + pos + klen);
				if (err)
					goto out;
			}
			pos += klen + (alive ? vlen : 0);
		}
	}

out:
	grub_free (cells);
	return err;
}

/* Walk every record of one LSM tree: its frozen on-disk runs first, then
   the residual mem-tree.  */
static grub_err_t
tibx_walk_tree (struct tibx_image *img, const grub_uint8_t *sb, grub_uint32_t sb_len, tibx_cell_hook hook)
{
	grub_uint32_t klen, vlen, ctrees, i;
	grub_uint32_t budget = TIBX_LSM_PAGES_MAX;
	grub_err_t err;

	if (sb_len < TIBX_LSB_MIN_SIZE)
		return grub_error (GRUB_ERR_BAD_DEVICE, "short tibx superblock");
	klen = grub_be_to_cpu32 (grub_get_unaligned32 (sb + TIBX_LSB_KEY_LEN));
	vlen = grub_be_to_cpu32 (grub_get_unaligned32 (sb + TIBX_LSB_VAL_LEN));
	if (klen == 0 || klen > TIBX_PAGE_BODY || vlen > TIBX_PAGE_BODY)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad tibx record sizes");
	ctrees = (grub_uint32_t) sb[5] + 2;

	for (i = 0; i < ctrees; i++)
	{
		const grub_uint8_t *slot = sb + TIBX_LSB_CTREES + (grub_size_t) i * TIBX_LSB_CTREE_SIZE;
		grub_uint64_t root;

		if (TIBX_LSB_CTREES + (i + 1) * TIBX_LSB_CTREE_SIZE > sb_len)
			break;
		root = grub_be_to_cpu64 (grub_get_unaligned64 (slot));
		/* An empty run is either the explicit sentinel or all zeros.  */
		if (root == ~(grub_uint64_t) 0
		    || (root == 0
			&& grub_be_to_cpu64 (grub_get_unaligned64 (slot + 8)) == 0))
			continue;
		err = tibx_walk_page (img, root / TIBX_PAGE_SIZE, klen, vlen, 0, &budget, hook);
		if (err)
			return err;
	}
	return tibx_walk_memtree (img, sb, sb_len, klen, vlen, hook);
}

/* ---------------- record collection ---------------- */

static grub_err_t
tibx_add_segment (struct tibx_image *img, const grub_uint8_t *key, const grub_uint8_t *val)
{
	if (img->nseg == img->seg_cap)
	{
		grub_uint32_t cap = img->seg_cap ? img->seg_cap * 2 : 1024;
		struct tibx_seg *bigger;

		if (cap > TIBX_RECORDS_MAX)
			return grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many tibx segments");
		bigger = grub_realloc (img->seg, (grub_size_t) cap * sizeof (*bigger));
		if (!bigger)
			return grub_errno;
		img->seg = bigger;
		img->seg_cap = cap;
	}
	img->seg[img->nseg].id = grub_be_to_cpu64 (grub_get_unaligned64 (key));
	img->seg[img->nseg].page = grub_be_to_cpu32 (grub_get_unaligned32 (val + 4));
	img->nseg++;
	return GRUB_ERR_NONE;
}

static grub_err_t
tibx_add_extent (struct tibx_image *img, const grub_uint8_t *key, const grub_uint8_t *val)
{
	grub_uint64_t vol = grub_be_to_cpu64 (grub_get_unaligned64 (key));
	grub_uint64_t base = 0;
	struct tibx_extent *e;
	grub_uint32_t idx;
	grub_uint32_t i;

	/* data_map keys lead with the stream, so a run of extents shares
	   one entry and the previous hit almost always answers.  */
	i = img->cur_place;
	if (i >= img->nplace || img->place[i].vol != vol)
	{
		for (i = 0; i < img->nplace; i++)
			if (img->place[i].vol == vol)
				break;
		if (i == img->nplace)
			return GRUB_ERR_NONE;
		img->cur_place = i;
	}
	base = img->place[i].base;

	if (img->next == img->cap)
	{
		grub_uint32_t cap = img->cap ? img->cap * 2 : 1024;
		struct tibx_extent *bigger;

		if (cap > TIBX_RECORDS_MAX)
			return grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many tibx extents");
		bigger = grub_realloc (img->ext, (grub_size_t) cap * sizeof (*bigger));
		if (!bigger)
			return grub_errno;
		img->ext = bigger;
		img->cap = cap;
	}
	e = &img->ext[img->next++];
	e->off = base + grub_be_to_cpu64 (grub_get_unaligned64 (key + 8));
	e->len = ((grub_uint32_t) key[16] << 16) | ((grub_uint32_t) key[17] << 8) | key[18];
	e->id = grub_be_to_cpu64 (grub_get_unaligned64 (key + TIBX_DMAP_KEY_ID));
	e->seg = grub_be_to_cpu64 (grub_get_unaligned64 (val));
	idx = grub_be_to_cpu16 (grub_get_unaligned16 (val + 8));
	e->at = idx == TIBX_EXTENT_WHOLE ? 0 : idx * TIBX_EXTENT_GRAIN;
	return GRUB_ERR_NONE;
}

/* Note the extent a stream starts with: a descriptor keeps its records
   there and a partition its boot sector.  */
static void
tibx_note_head (struct tibx_vol *vol, const grub_uint8_t *val, grub_uint32_t len)
{
	vol->seg = grub_be_to_cpu64 (grub_get_unaligned64 (val));
	vol->idx = grub_be_to_cpu16 (grub_get_unaligned16 (val + 8));
	vol->head = len;
}

/* First pass over data_map: how far each stream reaches.  There are only
   a handful of them, so a linear scan per record is cheap.  */
static grub_err_t
tibx_measure_volume (struct tibx_image *img, const grub_uint8_t *key, const grub_uint8_t *val)
{
	grub_uint64_t id = grub_be_to_cpu64 (grub_get_unaligned64 (key));
	grub_uint64_t off = grub_be_to_cpu64 (grub_get_unaligned64 (key + 8));
	grub_uint32_t len = ((grub_uint32_t) key[16] << 16) | ((grub_uint32_t) key[17] << 8) | key[18];
	grub_uint64_t end = off + len;
	grub_uint32_t i;

	for (i = 0; i < img->nvol; i++)
		if (img->vol[i].id == id)
		{
			if (end > img->vol[i].end)
				img->vol[i].end = end;
			if (off == 0)
				tibx_note_head (&img->vol[i], val, len);
			return GRUB_ERR_NONE;
		}
	if (img->nvol == img->vol_cap)
	{
		grub_uint32_t cap = img->vol_cap ? img->vol_cap * 2 : 16;
		struct tibx_vol *bigger;

		if (cap > 4096)
			return grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many tibx streams");
		bigger = grub_realloc (img->vol, (grub_size_t) cap * sizeof (*bigger));
		if (!bigger)
			return grub_errno;
		img->vol = bigger;
		img->vol_cap = cap;
	}
	grub_memset (&img->vol[img->nvol], 0, sizeof (*img->vol));
	img->vol[img->nvol].id = id;
	img->vol[img->nvol].end = end;
	if (off == 0)
		tibx_note_head (&img->vol[img->nvol], val, len);
	img->nvol++;
	return GRUB_ERR_NONE;
}

static void
tibx_sort_extents (struct tibx_extent *ext, struct tibx_extent *tmp, grub_uint32_t n)
{
	grub_uint32_t width;

	for (width = 1; width < n; width *= 2)
	{
		grub_uint32_t i;

		for (i = 0; i < n; i += 2 * width)
		{
			grub_uint32_t l = i, r = i + width, o = i;
			grub_uint32_t lend = r > n ? n : r;
			grub_uint32_t rend = i + 2 * width > n ? n : i + 2 * width;

			if (r > n)
				r = n;
			while (l < lend && r < rend)
			{
				/* By offset, and within one offset the newest
				   extent first, so that flattening can let it
				   shadow the ones the earlier slices wrote.  */
				if (ext[r].off < ext[l].off || (ext[r].off == ext[l].off && ext[r].id > ext[l].id))
					tmp[o++] = ext[r++];
				else
					tmp[o++] = ext[l++];
			}
			while (l < lend)
				tmp[o++] = ext[l++];
			while (r < rend)
				tmp[o++] = ext[r++];
		}
		grub_memcpy (ext, tmp, (grub_size_t) n * sizeof (*ext));
	}
}

/* Reduce the sorted extents to a run of non-overlapping ones.  Writing a
   further slice into an archive re-states ranges the earlier ones had
   already covered, so where two extents meet the newer one wins and the
   older keeps only the part sticking out past it.  */
static grub_uint32_t
tibx_flatten_extents (struct tibx_extent *ext, grub_uint32_t n)
{
	grub_uint64_t covered = 0;
	grub_uint32_t i, out = 0;

	for (i = 0; i < n; i++)
	{
		struct tibx_extent e = ext[i];
		grub_uint64_t end = e.off + e.len;

		if (end <= covered)
			continue;	/* a newer extent has all of it */
		if (e.off < covered)
		{
			/* Keep the tail only, and follow it in its segment.  */
			e.at += (grub_uint32_t) (covered - e.off);
			e.len -= (grub_uint32_t) (covered - e.off);
			e.off = covered;
		}
		covered = end;
		ext[out++] = e;
	}
	return out;
}

static void
tibx_sort_segments (struct tibx_seg *seg, struct tibx_seg *tmp, grub_uint32_t n)
{
	grub_uint32_t width;

	for (width = 1; width < n; width *= 2)
	{
		grub_uint32_t i;

		for (i = 0; i < n; i += 2 * width)
		{
			grub_uint32_t l = i, r = i + width, o = i;
			grub_uint32_t lend = r > n ? n : r;
			grub_uint32_t rend = i + 2 * width > n ? n : i + 2 * width;

			if (r > n)
				r = n;
			while (l < lend && r < rend)
			{
				if (seg[r].id < seg[l].id)
					tmp[o++] = seg[r++];
				else
					tmp[o++] = seg[l++];
			}
			while (l < lend)
				tmp[o++] = seg[l++];
			while (r < rend)
				tmp[o++] = seg[r++];
		}
		grub_memcpy (seg, tmp, (grub_size_t) n * sizeof (*seg));
	}
}

/* Streams are few, and reading the layout out of them depends on seeing
   them in the order the archive assigned their ids.  */
static void
tibx_sort_volumes (struct tibx_vol *vol, grub_uint32_t n)
{
	grub_uint32_t i, j;

	for (i = 1; i < n; i++)
	{
		struct tibx_vol tmp = vol[i];

		for (j = i; j > 0 && vol[j - 1].id > tmp.id; j--)
			vol[j] = vol[j - 1];
		vol[j] = tmp;
	}
}

/* ---------------- source disk layout ---------------- */

/* Read the head of a stream, which is where a descriptor keeps its
   records and a partition its boot sector.  */
static grub_err_t
tibx_stream_head (struct tibx_image *img, const struct tibx_vol *vol,
		  grub_uint8_t *buf, grub_uint32_t want, grub_uint32_t *got)
{
	const grub_uint8_t *seg;
	grub_uint32_t seg_len, at;
	grub_err_t err;

	*got = 0;
	if (vol->head == 0)
		return GRUB_ERR_NONE;
	err = tibx_segment (img, vol->seg, &seg, &seg_len);
	if (err)
		return err;
	at = vol->idx == TIBX_EXTENT_WHOLE ? 0 : vol->idx * TIBX_EXTENT_GRAIN;
	if (at >= seg_len)
		return GRUB_ERR_NONE;
	if (want > vol->head)
		want = vol->head;
	if (want > seg_len - at)
		want = seg_len - at;
	grub_memcpy (buf, seg + at, want);
	*got = want;
	return GRUB_ERR_NONE;
}

/* Decode a descriptor stream.  Returns 1 when BUF is one, filling in
   PART; its first_lba is left at zero for the descriptor of the disk
   itself, which is the one record that carries no start.  */
static int
tibx_parse_desc (const grub_uint8_t *buf, grub_uint32_t len,
		 struct tibx_part *part, grub_uint32_t *sector_size)
{
	grub_uint32_t p = 0;
	int seen_size = 0, seen_sectors = 0;

	grub_memset (part, 0, sizeof (*part));
	while (p + 3 <= len)
	{
		grub_uint32_t tag = (grub_uint32_t) buf[p] | ((grub_uint32_t) buf[p + 1] << 8);
		grub_uint32_t n = buf[p + 2];

		p += 3;
		if (n & 0x80)
		{
			if (p >= len)
				return 0;
			n = ((n & 0x7f) << 8) | buf[p];
			p++;
		}
		if (n > len - p)
			return 0;
		switch (tag)
		{
		case TIBX_TAG_SECTOR_SIZE:
			if (n < 1 || n > 4)
				return 0;
			*sector_size = (grub_uint32_t) tibx_le (buf + p, n);
			seen_size = 1;
			break;
		case TIBX_TAG_FIRST_LBA:
			if (n > 8)
				return 0;
			part->first_lba = tibx_le (buf + p, n);
			break;
		case TIBX_TAG_SECTORS:
			if (n > 8)
				return 0;
			part->sectors = tibx_le (buf + p, n);
			seen_sectors = 1;
			break;
		case TIBX_TAG_TYPE_GUID:
			if (n == sizeof (part->type))
				grub_memcpy (part->type, buf + p, n);
			break;
		case TIBX_TAG_PART_GUID:
			if (n == sizeof (part->guid))
				grub_memcpy (part->guid, buf + p, n);
			break;
		}
		p += n;
	}
	/* A descriptor's records fill it exactly; anything else that
	   happened to start with a plausible record does not.  */
	return p == len && seen_size && seen_sectors && *sector_size != 0;
}

static grub_uint32_t
tibx_crc32 (const void *buf, grub_size_t len)
{
	const grub_uint8_t *p = buf;
	grub_uint32_t crc = 0xffffffffU;
	grub_size_t i;
	int j;

	for (i = 0; i < len; i++)
	{
		crc ^= p[i];
		for (j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (0xedb88320U & (~(crc & 1) + 1));
	}
	return ~crc;
}

/* Data partition type GUID, used for a partition whose descriptor did
   not record one; any non-zero type makes the map iterator report it.  */
static const grub_uint8_t tibx_type_data[16] =
{
	0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,
	0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7
};

/* Rebuild the GPT of a disk that only kept its protective MBR, from the
   starts and lengths its partition descriptors recorded.  WITH_MBR also
   lays down the protective MBR, for a disk that kept nothing at all.  */
static grub_err_t
tibx_build_gpt (struct tibx_image *img, const struct tibx_part *parts,
	grub_uint32_t nparts, grub_uint64_t disk_sectors, int with_mbr)
{
	grub_uint32_t bytes = (TIBX_GPT_SECTORS + (with_mbr ? 1 : 0)) * TIBX_SECTOR;
	struct grub_gpt_partentry *ent;
	struct grub_gpt_header *hdr;
	grub_uint8_t *buf;
	grub_uint32_t i;

	buf = grub_zalloc (bytes);
	if (!buf)
		return grub_errno;
	img->synth = buf;
	img->synth_at = with_mbr ? 0 : TIBX_SECTOR;
	img->synth_len = bytes;

	if (with_mbr)
	{
		struct grub_msdos_partition_mbr *mbr;

		mbr = (struct grub_msdos_partition_mbr *) buf;
		mbr->entries[0].type = GRUB_PC_PARTITION_TYPE_GPT_DISK;
		mbr->entries[0].start = grub_cpu_to_le32 (1);
		mbr->entries[0].length
			= grub_cpu_to_le32 (disk_sectors - 1 > 0xffffffffU ? 0xffffffffU : (grub_uint32_t) (disk_sectors - 1));
		mbr->signature
			= grub_cpu_to_le16_compile_time (GRUB_PC_PARTITION_SIGNATURE);
		buf += TIBX_SECTOR;
	}

	hdr = (struct grub_gpt_header *) buf;
	ent = (struct grub_gpt_partentry *) (buf + TIBX_SECTOR);
	for (i = 0; i < nparts && i < TIBX_GPT_ENTRIES; i++)
	{
		int empty = 1;
		grub_uint32_t j;

		for (j = 0; j < sizeof (parts[i].type); j++)
			if (parts[i].type[j])
				empty = 0;
		grub_memcpy (&ent[i].type, empty ? tibx_type_data : parts[i].type, sizeof (ent[i].type));
		grub_memcpy (&ent[i].guid, parts[i].guid, sizeof (ent[i].guid));
		ent[i].start = grub_cpu_to_le64 (parts[i].first_lba);
		ent[i].end = grub_cpu_to_le64 (parts[i].first_lba + parts[i].sectors - 1);
	}

	grub_memcpy (hdr->magic, "EFI PART", sizeof (hdr->magic));
	hdr->version = grub_cpu_to_le32_compile_time (0x00010000);
	hdr->headersize = grub_cpu_to_le32_compile_time (TIBX_GPT_HEADER_SIZE);
	hdr->primary = grub_cpu_to_le64_compile_time (1);
	hdr->backup = grub_cpu_to_le64 (disk_sectors - 1);
	hdr->start = grub_cpu_to_le64_compile_time (TIBX_GPT_FIRST_USABLE);
	hdr->end = grub_cpu_to_le64 (disk_sectors - TIBX_GPT_FIRST_USABLE);
	hdr->partitions = grub_cpu_to_le64_compile_time (2);
	hdr->maxpart = grub_cpu_to_le32_compile_time (TIBX_GPT_ENTRIES);
	hdr->partentry_size = grub_cpu_to_le32_compile_time (TIBX_GPT_ENTRY_SIZE);
	hdr->partentry_crc32
		= grub_cpu_to_le32 (tibx_crc32 (ent, (grub_size_t) TIBX_GPT_ENTRIES * TIBX_GPT_ENTRY_SIZE));
	hdr->crc32 = grub_cpu_to_le32 (tibx_crc32 (hdr, TIBX_GPT_HEADER_SIZE));
	return GRUB_ERR_NONE;
}

/* Work out what the archive holds and where it belongs on the source
   disk.  Returns the size of the image to present, or zero to fall back
   to exposing a single stream.  */
static grub_uint64_t
tibx_layout (struct tibx_image *img)
{
	struct tibx_part *parts = NULL;
	grub_uint32_t *part_vol = NULL;
	grub_uint8_t *head = NULL;
	struct tibx_vol *best = NULL;
	grub_uint64_t disk_sectors = 0, size = 0;
	grub_uint32_t sector_size = 0;
	grub_uint32_t nparts = 0;
	grub_uint32_t i, got;
	int have_disk = 0;
	int protective = 0, mbr_ok = 0;

	parts = grub_calloc (TIBX_PARTS_MAX, sizeof (*parts));
	part_vol = grub_calloc (TIBX_PARTS_MAX, sizeof (*part_vol));
	head = grub_malloc (TIBX_DESC_MAX);
	if (!parts || !part_vol || !head)
		goto out;

	/* Streams come in source order: the disk's own sectors, the disk
	   descriptor, then each partition's content followed by its
	   descriptor.  So a partition's content is the largest stream seen
	   since the descriptor before it.  */
	for (i = 0; i < img->nvol; i++)
	{
		struct tibx_vol *vol = &img->vol[i];
		struct tibx_part part;
		grub_uint32_t bps = 0;

		if (vol->end > TIBX_DESC_MAX
			|| tibx_stream_head (img, vol, head, TIBX_DESC_MAX, &got)
			|| got == 0 || !tibx_parse_desc (head, got, &part, &bps))
		{
			grub_errno = GRUB_ERR_NONE;
			if (!best || vol->end > best->end)
				best = vol;
			continue;
		}
		if (part.first_lba == 0)
		{
			/* The disk itself: a length and no start.  */
			if (have_disk)
				goto out;
			have_disk = 1;
			disk_sectors = part.sectors;
			sector_size = bps;
			best = NULL;
			continue;
		}
		if (!have_disk || bps != sector_size || !best
			|| nparts == TIBX_PARTS_MAX
			|| part.sectors == 0 || part.first_lba >= disk_sectors
			|| part.sectors > disk_sectors - part.first_lba)
			goto out;
		part.desc = vol->id;
		parts[nparts] = part;
		part_vol[nparts] = (grub_uint32_t) (best - img->vol);
		nparts++;
		best = NULL;
	}

	/* A single partition is more useful presented on its own, and a
	   disk we cannot address in 512-byte sectors is no use at all.  */
	if (nparts < 2 || sector_size != TIBX_SECTOR || disk_sectors == 0)
		goto out;

	/* The disk's own sectors are the largest stream ahead of the first
	   partition, and they have to carry a partition table for the
	   rebuilt disk to be worth anything.  */
	best = NULL;
	for (i = 0; i < img->nvol; i++)
	{
		grub_uint32_t j;

		if (img->vol[i].id >= parts[0].desc)
			break;
		if (img->vol[i].end < TIBX_SECTOR)
			continue;
		for (j = 0; j < nparts; j++)
			if (part_vol[j] == i)
				break;
		if (j < nparts)
			continue;	/* that one is a partition's content */
		if (!best || img->vol[i].end > best->end)
			best = &img->vol[i];
	}

	img->nplace = 0;
	if (best)
	{
		const struct grub_msdos_partition_mbr *mbr = (const struct grub_msdos_partition_mbr *) head;

		if (tibx_stream_head (img, best, head, TIBX_DESC_MAX, &got))
			grub_errno = GRUB_ERR_NONE;
		else if (got >= sizeof (*mbr)
			 && mbr->signature == grub_cpu_to_le16_compile_time (GRUB_PC_PARTITION_SIGNATURE))
		{
			mbr_ok = 1;
			protective = 1;
			for (i = 0; i < ARRAY_SIZE (mbr->entries); i++)
			{
				grub_uint8_t type = mbr->entries[i].type;

				if (!grub_msdos_partition_is_empty (type) && type != GRUB_PC_PARTITION_TYPE_GPT_DISK)
					protective = 0;
			}
			/* A stored GPT beats anything we could rebuild.  */
			if (protective && got >= 2 * TIBX_SECTOR && grub_memcmp (head + TIBX_SECTOR, "EFI PART", 8) == 0)
				protective = 0;
		}
		img->place[img->nplace].vol = best->id;
		img->place[img->nplace].base = 0;
		img->nplace++;
	}
	for (i = 0; i < nparts; i++)
	{
		img->place[img->nplace].vol = img->vol[part_vol[i]].id;
		img->place[img->nplace].base = parts[i].first_lba * TIBX_SECTOR;
		img->nplace++;
	}

	if ((!mbr_ok || protective)
		&& tibx_build_gpt (img, parts, nparts, disk_sectors, !mbr_ok) != GRUB_ERR_NONE)
	{
		grub_errno = GRUB_ERR_NONE;
		img->nplace = 0;
		goto out;
	}
	size = disk_sectors * TIBX_SECTOR;

out:
	grub_free (parts);
	grub_free (part_vol);
	grub_free (head);
	return size;
}

/* ---------------- archive header ---------------- */

/* Read the newest archive header, following its continuation pages.  */
static grub_err_t
tibx_read_header (struct tibx_image *img, grub_uint8_t **body, grub_uint32_t *body_len)
{
	grub_uint8_t page[TIBX_PAGE_SIZE];
	grub_uint64_t best = 0, best_seq = 0;
	grub_uint64_t p, first;
	grub_uint32_t hdr_size, have;
	grub_uint8_t *buf;
	int found = 0;
	grub_err_t err;

	first = img->pages > TIBX_ARCH_SCAN ? img->pages - TIBX_ARCH_SCAN : 0;
	for (p = img->pages; p > first; p--)
	{
		grub_uint64_t seq;

		if (tibx_read_page (img, p - 1, page))
		{
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		if (page[0] != TIBX_PAGE_MAGIC || page[1] != TIBX_PAGE_ARCH
			|| grub_memcmp (page + TIBX_ENVELOPE, "ARCH", 4) != 0)
			continue;
		seq = grub_be_to_cpu64 (grub_get_unaligned64 (page + TIBX_ENVELOPE + TIBX_ARCH_SEQ));
		if (!found || seq >= best_seq)
		{
			found = 1;
			best_seq = seq;
			best = p - 1;
		}
	}
	if (!found)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "no tibx archive header");

	err = tibx_read_page (img, best, page);
	if (err)
		return err;
	hdr_size = grub_be_to_cpu32 (grub_get_unaligned32 (page + TIBX_ENVELOPE + TIBX_ARCH_SIZE));
	if (hdr_size < TIBX_ARCH_TLV + 4 || hdr_size > TIBX_HDR_MAX)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad tibx header size");

	buf = grub_malloc (hdr_size);
	if (!buf)
		return grub_errno;
	have = hdr_size < TIBX_PAGE_BODY ? hdr_size : TIBX_PAGE_BODY;
	grub_memcpy (buf, page + TIBX_ENVELOPE, have);
	for (p = best + 1; have < hdr_size && p < img->pages; p++)
	{
		grub_uint32_t take = hdr_size - have;

		if (tibx_read_page (img, p, page))
		{
			grub_free (buf);
			return grub_errno;
		}
		if (page[0] != TIBX_PAGE_MAGIC || page[1] != TIBX_PAGE_ARCH)
			break;
		if (take > TIBX_PAGE_BODY)
			take = TIBX_PAGE_BODY;
		grub_memcpy (buf + have, page + TIBX_ENVELOPE, take);
		have += take;
	}
	if (have < hdr_size)
	{
		grub_free (buf);
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "truncated tibx header");
	}
	*body = buf;
	*body_len = hdr_size;
	return GRUB_ERR_NONE;
}

/* Locate one TLV slot's payload inside the archive header.  */
static grub_err_t
tibx_tlv (const grub_uint8_t *body, grub_uint32_t body_len, grub_uint32_t want, const grub_uint8_t **payload, grub_uint32_t *len)
{
	grub_uint16_t version = grub_be_to_cpu16 (grub_get_unaligned16 (body + TIBX_ARCH_VERSION));
	grub_uint32_t p = TIBX_ARCH_TLV;
	grub_uint32_t i;

	*payload = NULL;
	*len = 0;
	for (i = 0; i < TIBX_TLV_SLOTS; i++)
	{
		grub_uint32_t n;

		/* Older headers leave some slots out entirely.  */
		if ((version < 7 && i == 8) || (version < 8 && i >= 12 && i <= 16))
			continue;
		if (p + 4 > body_len)
			break;
		n = grub_be_to_cpu32 (grub_get_unaligned32 (body + p));
		if (n > body_len - p - 4)
			return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad tibx TLV entry %u", i);
		if (i == want)
		{
			*payload = body + p + 4;
			*len = n;
			return GRUB_ERR_NONE;
		}
		p += (n + 7) & ~3u;
	}
	return grub_error (GRUB_ERR_BAD_FILE_TYPE, "tibx TLV entry %u is missing", want);
}

static grub_err_t
tibx_open_tree (struct tibx_image *img, const grub_uint8_t *body,
	grub_uint32_t body_len, grub_uint32_t slot, tibx_cell_hook hook)
{
	const grub_uint8_t *sb;
	grub_uint32_t sb_len;
	grub_err_t err;

	err = tibx_tlv (body, body_len, slot, &sb, &sb_len);
	if (err)
		return err;
	if (sb_len < TIBX_LSB_MIN_SIZE || grub_memcmp (sb, "L-SB", 4) != 0)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "tibx TLV entry %u is not a superblock", slot);
	return tibx_walk_tree (img, sb, sb_len, hook);
}

/* The extents stop at the last stored byte, but a filesystem needs its
   whole volume addressable.  Recover the real length from the boot
   sector when the volume starts with one.  */
static grub_uint64_t
tibx_volume_size (const grub_uint8_t *boot, grub_uint64_t covered)
{
	grub_uint32_t sector;
	grub_uint64_t total = 0;

	if (boot[510] != 0x55 || boot[511] != 0xaa)
		return covered;
	sector = (grub_uint32_t) boot[11] | ((grub_uint32_t) boot[12] << 8);

	if (grub_memcmp (boot + 3, "NTFS    ", 8) == 0)
	{
		/* NTFS counts every sector but the backup boot sector.  */
		total = grub_le_to_cpu32 (grub_get_unaligned32 (boot + 0x28))
			| ((grub_uint64_t) grub_le_to_cpu32 (grub_get_unaligned32 (boot + 0x2c)) << 32);
		total++;
	}
	else if (grub_memcmp (boot + 3, "EXFAT   ", 8) == 0)
	{
		sector = 1u << boot[0x6c];
		total = grub_le_to_cpu32 (grub_get_unaligned32 (boot + 0x48))
			| ((grub_uint64_t) grub_le_to_cpu32 (grub_get_unaligned32 (boot + 0x4c)) << 32);
	}
	else if (boot[0] == 0xeb || boot[0] == 0xe9)
	{
		total = (grub_uint32_t) boot[0x13] | ((grub_uint32_t) boot[0x14] << 8);
		if (total == 0)
			total = grub_le_to_cpu32 (grub_get_unaligned32 (boot + 0x20));
	}
	if (sector < 512 || sector > 4096 || total == 0)
		return covered;
	total *= sector;
	return total > covered ? total : covered;
}

static void
tibx_free_image (struct tibx_image *img)
{
	grub_uint32_t i;

	for (i = 0; i < TIBX_SEG_CACHE; i++)
	{
		grub_free (img->cache[i].data);
		img->cache[i].data = NULL;
	}
	grub_free (img->ext);
	grub_free (img->seg);
	grub_free (img->vol);
	grub_free (img->synth);
	img->ext = NULL;
	img->seg = NULL;
	img->vol = NULL;
	img->synth = NULL;
}

static grub_err_t
tibx_open_image (struct tibx_image *img)
{
	grub_uint8_t *body = NULL;
	grub_uint8_t *tmp = NULL;
	grub_uint64_t covered = 0;
	grub_size_t ext_bytes;
	grub_uint32_t body_len, i;
	grub_err_t err;

	img->pages = grub_file_size (img->file) / TIBX_PAGE_SIZE;
	if (img->pages < 8)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "tibx image too small");

	err = tibx_read_header (img, &body, &body_len);
	if (err)
		return err;

	err = tibx_open_tree (img, body, body_len, TIBX_TLV_SEGMENT_MAP, tibx_add_segment);
	if (err)
		goto out;
	if (img->nseg == 0)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "empty tibx segment map");
		goto out;
	}
	tmp = grub_malloc ((grub_size_t) img->nseg * sizeof (struct tibx_seg));
	if (!tmp)
	{
		err = grub_errno;
		goto out;
	}
	tibx_sort_segments (img->seg, (struct tibx_seg *) tmp, img->nseg);
	grub_free (tmp);
	tmp = NULL;

	/* Tally the streams, then work out whether they add up to a whole
	   source disk or to one partition on its own.  */
	err = tibx_open_tree (img, body, body_len, TIBX_TLV_DATA_MAP, tibx_measure_volume);
	if (err)
		goto out;
	if (img->nvol == 0)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "tibx archive is empty");
		goto out;
	}
	tibx_sort_volumes (img->vol, img->nvol);

	covered = tibx_layout (img);
	if (covered == 0)
	{
		/* One stream it is: the one reaching furthest is the volume,
		   the rest are the disk's first sectors and descriptors.  */
		grub_uint64_t reach = 0;

		img->nplace = 1;
		for (i = 0; i < img->nvol; i++)
			if (img->vol[i].end > reach)
			{
				reach = img->vol[i].end;
				img->place[0].vol = img->vol[i].id;
				img->place[0].base = 0;
			}
		if (reach == 0)
		{
			err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "tibx archive is empty");
			goto out;
		}
		covered = reach;
	}

	err = tibx_open_tree (img, body, body_len, TIBX_TLV_DATA_MAP, tibx_add_extent);
	if (err)
		goto out;
	if (img->next == 0 || img->nseg == 0)
	{
		err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "empty tibx index");
		goto out;
	}

	ext_bytes = (grub_size_t) img->next * sizeof (struct tibx_extent);
	tmp = grub_malloc (ext_bytes);
	if (!tmp)
	{
		err = grub_errno;
		goto out;
	}
	tibx_sort_extents (img->ext, (struct tibx_extent *) tmp, img->next);
	img->next = tibx_flatten_extents (img->ext, img->next);

	img->size = covered;
	img->cur = 0;

	/* A lone volume's extents stop at its last stored byte, but a
	   filesystem needs the whole volume addressable; its boot sector
	   knows how long it really is.  A rebuilt disk is already sized by
	   its descriptor.  */
	if (img->nplace == 1 && img->ext[0].off == 0 && img->ext[0].len >= 512)
	{
		const grub_uint8_t *seg;
		grub_uint32_t seg_len;
		grub_uint32_t at = img->ext[0].at;

		if (tibx_segment (img, img->ext[0].seg, &seg, &seg_len) == GRUB_ERR_NONE && seg_len >= at + 512)
			img->size = tibx_volume_size (seg + at, covered);
		else
			grub_errno = GRUB_ERR_NONE;
	}

out:
	grub_free (body);
	grub_free (tmp);
	grub_free (img->vol);
	img->vol = NULL;
	img->nvol = img->vol_cap = 0;
	if (err)
		tibx_free_image (img);
	return err;
}

/* ---------------- reads ---------------- */

/* Index of the last extent starting at or before OFF, or -1.  */
static grub_uint32_t
tibx_find_extent (struct tibx_image *img, grub_uint64_t off)
{
	grub_uint32_t lo = 0, hi = img->next;

	if (img->cur < img->next && img->ext[img->cur].off <= off
		&& (img->cur + 1 == img->next || off < img->ext[img->cur + 1].off))
		return img->cur;
	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (img->ext[mid].off <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0)
		return (grub_uint32_t) -1;
	img->cur = lo - 1;
	return lo - 1;
}

static grub_err_t
tibx_read (struct tibx_image *img, grub_uint64_t off, void *buf, grub_size_t len, grub_size_t *actually_read)
{
	const struct tibx_extent *e;
	const grub_uint8_t *seg;
	grub_uint32_t nr, seg_len, at;
	grub_uint64_t gap;
	grub_size_t n;
	grub_err_t err;

	*actually_read = 0;
	if (off >= img->size)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past the end of the tibx volume");
	if (len > img->size - off)
		len = (grub_size_t) (img->size - off);
	if (len == 0)
		return GRUB_ERR_NONE;

	/* A rebuilt partition table sits over whatever the archive kept.  */
	if (img->synth && off < img->synth_at + img->synth_len)
	{
		if (off < img->synth_at)
		{
			gap = img->synth_at - off;
			if (gap < len)
				len = (grub_size_t) gap;
		}
		else
		{
			n = (grub_size_t) (img->synth_at + img->synth_len - off);
			if (n > len)
				n = len;
			grub_memcpy (buf, img->synth + (off - img->synth_at), n);
			*actually_read = n;
			return GRUB_ERR_NONE;
		}
	}

	nr = tibx_find_extent (img, off);
	if (nr == (grub_uint32_t) -1 || off >= img->ext[nr].off + img->ext[nr].len)
	{
		/* Sparse: zero up to the next stored extent.  */
		if (nr == (grub_uint32_t) -1)
			gap = img->ext[0].off - off;
		else if (nr + 1 < img->next)
			gap = img->ext[nr + 1].off - off;
		else
			gap = img->size - off;
		n = gap < len ? (grub_size_t) gap : len;
		grub_memset (buf, 0, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}

	e = &img->ext[nr];
	gap = e->off + e->len - off;
	n = gap < len ? (grub_size_t) gap : len;

	/* Segment ids start at one, so a record naming segment zero is a
	   later slice saying the range went away.  */
	if (e->seg == 0)
	{
		grub_memset (buf, 0, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}
	err = tibx_segment (img, e->seg, &seg, &seg_len);
	if (err)
		return err;
	at = e->at;
	if (at > seg_len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad tibx extent offset");
	at += (grub_uint32_t) (off - e->off);
	if (at >= seg_len)
	{
		grub_memset (buf, 0, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}
	if (n > seg_len - at)
		n = seg_len - at;
	grub_memcpy (buf, seg + at, n);
	*actually_read = n;
	return GRUB_ERR_NONE;
}

/* ---------------- io filter ---------------- */

struct grub_tibx
{
	grub_file_t file;
	struct tibx_image *image;
};
typedef struct grub_tibx *grub_tibx_t;

static struct grub_fs grub_tibx_fs;

static grub_err_t
grub_tibx_close (grub_file_t file)
{
	grub_tibx_t tibxio = file->data;

	tibx_free_image (tibxio->image);
	grub_free (tibxio->image);
	grub_file_close (tibxio->file);
	grub_free (tibxio);
	/* The inner close released the shared device; the outer name is
	   freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_tibx_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_tibx_t tibxio;
	struct tibx_image *image;
	grub_uint8_t probe[TIBX_ENVELOPE + 4];

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < TIBX_PAGE_SIZE || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;
	if (grub_file_seek (io, 0) == (grub_off_t) -1
		|| grub_file_read (io, probe, sizeof (probe)) != (grub_ssize_t) sizeof (probe)
		|| probe[0] != TIBX_PAGE_MAGIC || probe[1] != TIBX_PAGE_ARCH
		|| grub_memcmp (probe + TIBX_ENVELOPE, "ARCH", 4) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (tibx_open_image (image) != GRUB_ERR_NONE)
	{
		tibx_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	tibxio = grub_zalloc (sizeof (*tibxio));
	if (!file || !tibxio)
	{
		tibx_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (tibxio);
		return 0;
	}
	tibxio->file = io;
	tibxio->image = image;

	file->device = io->device;
	file->data = tibxio;
	file->fs = &grub_tibx_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->size;

	return file;
}

static grub_ssize_t
grub_tibx_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_tibx_t tibxio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = tibx_read (tibxio->image, read_offset, buf, len, &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR, "tibx read made no progress");
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
			grub_error (err, "tibx image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_tibx_fs =
{
	.name = "tibx",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_tibx_read,
	.fs_close = grub_tibx_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (tibx)
{
	grub_file_filter_register (GRUB_FILE_FILTER_TIBX, grub_tibx_open);
}

GRUB_MOD_FINI (tibx)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_TIBX);
}
