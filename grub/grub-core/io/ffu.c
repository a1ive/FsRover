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
 * Windows Full Flash Update (FFU) io filter
 * Implemented from the on-disk layout read by img2ffu <https://github.com/MobileTooling/img2ffu>
 * (Img2Ffu.Library\Reader), which follows the FFU structures of the
 * Windows manufacturing documentation.
 *
 * Layout: SecurityHeader, catalog and table of hashes (both only needed to
 * verify the image), then the ImageHeader with the INI manifest, then the
 * header of every store back to back, then the payload of every store in
 * store order.  Each of those regions is padded out to the chunk size.
 *
 * A store is a sparse image of one whole disk: its write descriptors name,
 * for every payload block, the disk blocks that block is written to, either
 * counted from the start of the disk or from its end.  Only the first store
 * is exposed -- V1 images only ever hold one, and it is the main disk of a
 * multi store V2 image.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>

#include <xca.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define FFU_SEC_MAGIC		"SignedImage "
#define FFU_IMG_MAGIC		"ImageFlash  "
#define FFU_MAGIC_SIZE		12

#define FFU_SECURITY_HEADER_SIZE	32
#define FFU_IMAGE_HEADER_SIZE		24
/* An ImageHeader of this size is followed by a device targeting info count.  */
#define FFU_IMAGE_HEADER_SIZE_DTI	28
#define FFU_STORE_HEADER_SIZE		248
#define FFU_STORE_HEADER_V2_SIZE	14
#define FFU_PLATFORM_ID_SIZE		192

/* Fields of a device targeting info record that carry a string length.  */
#define FFU_DTI_FIELDS		7

/* BlockDataEntry and DiskLocation are fixed size and appear in the middle
   of the variable sized write descriptors, so they are parsed by hand.  */
#define FFU_BLOCK_DATA_ENTRY_SIZE	8
#define FFU_DISK_LOCATION_SIZE		8

/* Store format, from (MajorVersion, FullFlashMajorVersion).  */
#define FFU_V1			0	/* (1, 2) */
#define FFU_V1_COMPRESSED	1	/* (1, 3), + CompressionAlgorithm */
#define FFU_V2			2	/* (2, 2), + store count, device path */

/* Store.CompressionAlgorithm, matching Windows COMPRESSION_FORMAT_*.  */
#define FFU_COMPRESS_NONE		0
#define FFU_COMPRESS_DEFAULT		1
#define FFU_COMPRESS_LZNT1		2
#define FFU_COMPRESS_XPRESS		3
#define FFU_COMPRESS_XPRESS_HUFF	4

/* DiskLocation.DiskAccessMethod */
#define FFU_DISK_BEGIN		0
#define FFU_DISK_END		2

/* LZNT1 works on chunks of this many output bytes.  */
#define FFU_LZNT1_CHUNK		4096

/* Sanity caps against corrupt images.  Both leading headers carry their own
   size, used as the stride to whatever follows them; a chunk (= the store
   block size) stays under 32 MiB, and the write descriptors under 256 MiB,
   which is enough to map a 4 TiB disk in 128 KiB blocks.  */
#define FFU_HEADER_MAX		4096
#define FFU_CHUNK_MAX		(32ULL << 20)
#define FFU_BLOCK_MIN		512
#define FFU_MANIFEST_MAX	(1UL << 20)
#define FFU_DTI_MAX		256
#define FFU_DTI_BYTES_MAX	(1ULL << 20)
#define FFU_STORES_MAX		64
#define FFU_WDESC_BYTES_MAX	(256UL << 20)
#define FFU_SECTOR_SIZE_MAX	65536
#define FFU_DISK_BYTES_MAX	(1ULL << 52)

PRAGMA_BEGIN_PACKED
struct ffu_security_header
{
	grub_uint32_t size;			/* of this struct, = 32 */
	char signature[FFU_MAGIC_SIZE];		/* FFU_SEC_MAGIC */
	grub_uint32_t chunk_size_kb;		/* hashed chunk size, in KiB */
	grub_uint32_t algorithm_id;		/* hash algorithm */
	grub_uint32_t catalog_size;
	grub_uint32_t hash_table_size;
} GRUB_PACKED;

struct ffu_image_header
{
	grub_uint32_t size;			/* of this struct, = 24 or 28 */
	char signature[FFU_MAGIC_SIZE];		/* FFU_IMG_MAGIC */
	grub_uint32_t manifest_length;		/* in bytes */
	grub_uint32_t chunk_size_kb;
} GRUB_PACKED;

struct ffu_store_header
{
	grub_uint32_t update_type;		/* full or partial flash */
	grub_uint16_t major_version;
	grub_uint16_t minor_version;
	grub_uint16_t full_flash_major_version;	/* the image format */
	grub_uint16_t full_flash_minor_version;
	grub_uint8_t platform_id[FFU_PLATFORM_ID_SIZE];
	grub_uint32_t block_size;		/* payload block size, in bytes */
	grub_uint32_t write_desc_count;		/* = payload blocks */
	grub_uint32_t write_desc_length;	/* their total size, in bytes */
	grub_uint32_t validate_desc_count;
	grub_uint32_t validate_desc_length;
	grub_uint32_t initial_table_index;	/* the invalid GPT */
	grub_uint32_t initial_table_count;
	grub_uint32_t flash_only_table_index;	/* the flash only GPT */
	grub_uint32_t flash_only_table_count;
	grub_uint32_t final_table_index;	/* the real GPT */
	grub_uint32_t final_table_count;
} GRUB_PACKED;

struct ffu_store_header_v2
{
	grub_uint16_t number_of_stores;
	grub_uint16_t store_index;		/* 1 based */
	grub_uint64_t store_payload_size;	/* payload only, no padding */
	grub_uint16_t device_path_length;	/* in UTF-16 code units */
} GRUB_PACKED;
PRAGMA_END_PACKED

struct ffu_image
{
	grub_file_t file;
	grub_uint64_t total_bytes;	/* size of the guest disk */
	grub_uint64_t data_off;		/* file offset of the store payload */
	grub_uint32_t block_size;
	grub_uint32_t total_blocks;	/* guest disk size, in blocks */
	/* map[] holds (guest block << 32 | payload block index) sorted
	   ascending, so a lookup is a binary search on the upper half and
	   duplicate guest blocks come out in write descriptor order.  */
	grub_uint32_t nblocks;
	grub_uint64_t *map;
	grub_uint32_t ndesc;		/* payload blocks in the store */
	grub_uint32_t compression;	/* FFU_COMPRESS_* */
	/* Compressed stores only: payload block offsets relative to data_off
	   (ndesc + 1 entries), plus one decompressed block of cache.  */
	grub_uint64_t *poff;
	grub_uint8_t *cache;
	grub_uint32_t cached;		/* payload block held in cache[] */
};

/* Collected while walking the write descriptors of the store.  */
struct ffu_scan
{
	grub_uint64_t nloc;		/* mapped disk locations */
	grub_uint32_t max_start;	/* highest block counted from the start */
	grub_uint32_t max_end;		/* highest block counted from the end */
	int has_start;
	int has_end;
};

static grub_err_t
ffu_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (file) || len > grub_file_size (file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");
	return GRUB_ERR_NONE;
}

/* Every region of an FFU is padded out to a multiple of UNIT; this is how
   the one after it is found.  */
static grub_err_t
ffu_align_up (grub_uint64_t *pos, grub_uint64_t unit, grub_uint64_t limit)
{
	grub_uint64_t rem = *pos % unit;

	if (rem != 0 && grub_add (*pos, unit - rem, pos))
		return grub_error (GRUB_ERR_BAD_DEVICE, "malformed FFU image");
	if (*pos > limit)
		return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");
	return GRUB_ERR_NONE;
}

/* LZNT1 (Windows COMPRESSION_FORMAT_LZNT1) decompression, following the
   same tag layout as the NTFS decompressor in fs\ntfscomp.c.  Returns the
   number of bytes produced, or -1 on malformed input.  */
static grub_ssize_t
ffu_lznt1_decompress (const grub_uint8_t *src, grub_size_t srclen, grub_uint8_t *dst, grub_size_t dstlen)
{
	grub_size_t out = 0;

	while (srclen >= 2 && out < dstlen)
	{
		const grub_uint8_t *p;
		grub_uint8_t *cbuf = dst + out;
		grub_size_t climit = dstlen - out;
		grub_size_t copied = 0;
		grub_uint32_t hdr, csize, left;

		hdr = grub_le_to_cpu16 (grub_get_unaligned16 (src));
		if (hdr == 0)
			break;			/* end of stream */
		csize = (hdr & 0xfff) + 1;
		src += 2;
		srclen -= 2;
		if (csize > srclen)
			return -1;

		/* A chunk never yields more than FFU_LZNT1_CHUNK bytes, and
		   its matches reach back only within the chunk itself.  */
		if (climit > FFU_LZNT1_CHUNK)
			climit = FFU_LZNT1_CHUNK;

		if (!(hdr & 0x8000))
		{
			/* Stored verbatim.  */
			if (csize > climit)
				return -1;
			grub_memcpy (cbuf, src, csize);
			src += csize;
			srclen -= csize;
			out += csize;
			continue;
		}

		p = src;
		left = csize;
		while (left > 0)
		{
			grub_uint32_t tag = *(p++);
			int bit;

			left--;
			for (bit = 0; bit < 8 && left > 0; bit++, tag >>= 1)
			{
				grub_uint32_t code, i, len, delta;
				grub_uint32_t lmask, dshift;

				if (!(tag & 1))
				{
					if (copied >= climit)
						return -1;
					cbuf[copied++] = *(p++);
					left--;
					continue;
				}

				if (left < 2)
					return -1;
				code = grub_le_to_cpu16 (grub_get_unaligned16 (p));
				p += 2;
				left -= 2;
				if (copied == 0)
					return -1;

				/* The split between offset and length widens
				   as the chunk fills up.  */
				for (i = (grub_uint32_t) copied - 1, lmask = 0xfff, dshift = 12; i >= 0x10; i >>= 1)
				{
					lmask >>= 1;
					dshift--;
				}
				delta = code >> dshift;
				len = (code & lmask) + 3;
				if ((grub_size_t) delta + 1 > copied
				    || len > climit - copied)
					return -1;

				for (i = 0; i < len; i++, copied++)
					cbuf[copied] = cbuf[copied - delta - 1];
			}
		}
		src += csize;
		srclen -= csize;
		out += copied;
	}
	return (grub_ssize_t) out;
}

/* Plain Xpress (Windows COMPRESSION_FORMAT_XPRESS) decompression, i.e. the
   LZ77+DIRECT2 stream of [MS-XCA] 2.1, which is the Huffman free sibling of
   the format lib\wimboot\xca.c handles.  Returns the number of bytes
   produced, or -1 on malformed input.  */
static grub_ssize_t
ffu_xpress_decompress (const grub_uint8_t *src, grub_size_t srclen, grub_uint8_t *dst, grub_size_t dstlen)
{
	grub_size_t in = 0, out = 0;
	grub_size_t half_byte = 0;	/* 1 based, 0 = no nibble pending */
	grub_uint32_t flags = 0;
	int nflags = 0;

	while (out < dstlen)
	{
		grub_uint32_t mbytes, mlen, moff;

		if (nflags == 0)
		{
			if (srclen - in < sizeof (grub_uint32_t))
				break;
			flags = grub_le_to_cpu32 (grub_get_unaligned32 (src + in));
			in += sizeof (grub_uint32_t);
			nflags = 32;
		}
		nflags--;

		if (!(flags & (1UL << nflags)))
		{
			/* Literal byte.  */
			if (in >= srclen)
				break;
			dst[out++] = src[in++];
			continue;
		}

		if (in == srclen)
			break;			/* end of stream */
		if (srclen - in < sizeof (grub_uint16_t))
			return -1;
		mbytes = grub_le_to_cpu16 (grub_get_unaligned16 (src + in));
		in += sizeof (grub_uint16_t);
		mlen = mbytes & 7;
		moff = (mbytes >> 3) + 1;

		if (mlen == 7)
		{
			/* Lengths of 10 and up spill into a nibble, which the
			   next long match shares the other half of.  */
			if (half_byte == 0)
			{
				if (in >= srclen)
					return -1;
				mlen = src[in] & 0x0f;
				half_byte = in + 1;
				in++;
			}
			else
			{
				mlen = src[half_byte - 1] >> 4;
				half_byte = 0;
			}
			if (mlen == 15)
			{
				if (in >= srclen)
					return -1;
				mlen = src[in++];
				if (mlen == 255)
				{
					if (srclen - in < sizeof (grub_uint16_t))
						return -1;
					mlen = grub_le_to_cpu16 (grub_get_unaligned16 (src + in));
					in += sizeof (grub_uint16_t);
					if (mlen == 0)
					{
						if (srclen - in < sizeof (grub_uint32_t))
							return -1;
						mlen = grub_le_to_cpu32 (grub_get_unaligned32 (src + in));
						in += sizeof (grub_uint32_t);
					}
					if (mlen < 15 + 7)
						return -1;
					mlen -= 15 + 7;
				}
				mlen += 15;
			}
			mlen += 7;
		}
		mlen += 3;

		if (moff > out || mlen > dstlen - out)
			return -1;
		for (; mlen > 0; mlen--, out++)
			dst[out] = dst[out - moff];
	}
	return (grub_ssize_t) out;
}

static void
ffu_free_image (struct ffu_image *image)
{
	grub_free (image->map);
	grub_free (image->poff);
	grub_free (image->cache);
	image->map = NULL;
	image->poff = NULL;
	image->cache = NULL;
}

/* Decode decimal digits at the head of [P, P + N), which is a slice of the
   manifest and therefore not terminated.  */
static int
ffu_parse_u64 (const char *p, grub_size_t n, grub_uint64_t *out)
{
	grub_uint64_t v = 0;
	grub_size_t i;

	for (i = 0; i < n && p[i] >= '0' && p[i] <= '9'; i++)
	{
		if (v > (~0ULL - (grub_uint64_t) (p[i] - '0')) / 10)
			return 0;
		v = v * 10 + (grub_uint64_t) (p[i] - '0');
	}
	if (i == 0)
		return 0;
	*out = v;
	return 1;
}

/* Match "KEY = <number>" against the manifest line [LINE, LINE + N).  */
static int
ffu_manifest_value (const char *line, grub_size_t n, const char *key, grub_uint64_t *out)
{
	grub_size_t klen = grub_strlen (key);

	if (n <= klen || grub_strncasecmp (line, key, klen) != 0)
		return 0;
	line += klen;
	n -= klen;
	while (n > 0 && (*line == ' ' || *line == '\t'))
	{
		line++;
		n--;
	}
	if (n == 0 || *line != '=')
		return 0;
	line++;
	n--;
	while (n > 0 && (*line == ' ' || *line == '\t'))
	{
		line++;
		n--;
	}
	return ffu_parse_u64 (line, n, out);
}

/* The manifest is an INI listing one [Store] section per store.  Its
   MinSectorCount and SectorSize give the size of the guest disk, which the
   write descriptors alone only put a lower bound on.  Anything that cannot
   be read out of it leaves *MIN_BYTES at zero.  */
static grub_err_t
ffu_read_manifest (grub_file_t file, grub_uint64_t off, grub_uint32_t len, grub_uint64_t *min_bytes)
{
	char *manifest;
	grub_size_t i = 0;
	grub_uint64_t min_sectors = 0, sector_size = 0;
	int in_store = 0;
	grub_err_t err;

	manifest = grub_malloc (len);
	if (!manifest)
		return grub_errno;
	err = ffu_pread (file, off, manifest, len);
	if (err)
		goto done;

	while (i < len)
	{
		const char *line = manifest + i;
		grub_size_t j = i, n;

		while (j < len && manifest[j] != '\n')
			j++;
		n = j - i;
		i = j + 1;

		while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t'))
			n--;
		while (n > 0 && (*line == ' ' || *line == '\t'))
		{
			line++;
			n--;
		}
		if (n == 0)
			continue;

		if (*line == '[')
		{
			grub_size_t k = 1;

			/* Only the first store is exposed, so stop at the
			   section that follows its own.  */
			if (in_store)
				break;
			while (k < n && line[k] != ']')
				k++;
			in_store = (k == 6 && grub_strncasecmp (line + 1, "Store", 5) == 0);
			continue;
		}
		if (!in_store)
			continue;
		if (ffu_manifest_value (line, n, "MinSectorCount", &min_sectors))
			continue;
		ffu_manifest_value (line, n, "SectorSize", &sector_size);
	}

	*min_bytes = 0;
	if (min_sectors != 0 && sector_size >= FFU_BLOCK_MIN
		&& sector_size <= FFU_SECTOR_SIZE_MAX
		&& grub_mul (min_sectors, sector_size, min_bytes))
		*min_bytes = 0;	/* overflowed, so of no use */
	if (*min_bytes > FFU_DISK_BYTES_MAX)
		*min_bytes = 0;

done:
	grub_free (manifest);
	return err;
}

/* Validate the write descriptors of the store, note how far the disk they
   describe reaches and, for a compressed store, where every payload block
   starts.  */
static grub_err_t
ffu_scan_descriptors (struct ffu_image *image, const grub_uint8_t *buf, grub_size_t len, struct ffu_scan *scan)
{
	grub_uint64_t payload = 0;
	grub_size_t p = 0;
	grub_uint32_t i;

	for (i = 0; i < image->ndesc; i++)
	{
		grub_uint32_t nloc, j;

		/* BlockDataEntry: location count, then an unused block count.  */
		if (len - p < FFU_BLOCK_DATA_ENTRY_SIZE)
			return grub_error (GRUB_ERR_BAD_DEVICE, "truncated FFU write descriptor");
		nloc = grub_le_to_cpu32 (grub_get_unaligned32 (buf + p));
		p += FFU_BLOCK_DATA_ENTRY_SIZE;

		if (image->poff)
		{
			if (len - p < sizeof (grub_uint32_t))
				return grub_error (GRUB_ERR_BAD_DEVICE, "truncated FFU write descriptor");
			image->poff[i] = payload;
			payload += grub_le_to_cpu32 (grub_get_unaligned32 (buf + p));
			p += sizeof (grub_uint32_t);
		}

		if (nloc > (len - p) / FFU_DISK_LOCATION_SIZE)
			return grub_error (GRUB_ERR_BAD_DEVICE, "truncated FFU write descriptor");
		for (j = 0; j < nloc; j++, p += FFU_DISK_LOCATION_SIZE)
		{
			grub_uint32_t method, index;

			method = grub_le_to_cpu32 (grub_get_unaligned32 (buf + p));
			index = grub_le_to_cpu32 (grub_get_unaligned32 (buf + p + 4));
			switch (method)
			{
			case FFU_DISK_BEGIN:
				if (!scan->has_start || index > scan->max_start)
					scan->max_start = index;
				scan->has_start = 1;
				break;
			case FFU_DISK_END:
				if (!scan->has_end || index > scan->max_end)
					scan->max_end = index;
				scan->has_end = 1;
				break;
			default:
				return grub_error (GRUB_ERR_BAD_DEVICE, "unknown FFU disk access method %u", method);
			}
			scan->nloc++;
		}
	}

	if (p != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "trailing FFU write descriptor data");
	if (image->poff)
	{
		image->poff[image->ndesc] = payload;
		if (payload > grub_file_size (image->file) - image->data_off)
			return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");
	}
	return GRUB_ERR_NONE;
}

static void
ffu_sift_down (grub_uint64_t *a, grub_size_t root, grub_size_t n)
{
	while (1)
	{
		grub_size_t child = 2 * root + 1;
		grub_size_t big = root;
		grub_uint64_t t;

		if (child >= n)
			return;
		if (a[big] < a[child])
			big = child;
		if (child + 1 < n && a[big] < a[child + 1])
			big = child + 1;
		if (big == root)
			return;
		t = a[root];
		a[root] = a[big];
		a[big] = t;
		root = big;
	}
}

/* Heapsort: the map may hold a few hundred thousand entries and needs no
   scratch space beyond itself.  */
static void
ffu_sort_map (grub_uint64_t *a, grub_size_t n)
{
	grub_size_t i;

	for (i = n / 2; i > 0; i--)
		ffu_sift_down (a, i - 1, n);
	for (i = n; i > 1; i--)
	{
		grub_uint64_t t = a[0];

		a[0] = a[i - 1];
		a[i - 1] = t;
		ffu_sift_down (a, 0, i - 1);
	}
}

/* Fill in map[] from the write descriptors, whose layout ffu_scan_descriptors
   has already validated.  */
static void
ffu_build_map (struct ffu_image *image, const grub_uint8_t *buf)
{
	grub_size_t p = 0;
	grub_uint32_t i, n = 0;

	for (i = 0; i < image->ndesc; i++)
	{
		grub_uint32_t nloc, j;

		nloc = grub_le_to_cpu32 (grub_get_unaligned32 (buf + p));
		p += FFU_BLOCK_DATA_ENTRY_SIZE;
		if (image->poff)
			p += sizeof (grub_uint32_t);

		for (j = 0; j < nloc; j++, p += FFU_DISK_LOCATION_SIZE)
		{
			grub_uint32_t method, index, vblock;

			method = grub_le_to_cpu32 (grub_get_unaligned32 (buf + p));
			index = grub_le_to_cpu32 (grub_get_unaligned32 (buf + p + 4));
			/* total_blocks covers the highest index of either
			   kind, so neither can run off the disk.  */
			if (method == FFU_DISK_BEGIN)
				vblock = index;
			else
				vblock = image->total_blocks - 1 - index;
			image->map[n++] = ((grub_uint64_t) vblock << 32) | i;
		}
	}

	image->nblocks = n;
	ffu_sort_map (image->map, n);
}

/* Find the payload block holding guest block VBLOCK.  Where a block is
   written more than once -- FFU images blank the GPT out and write the real
   one post mortem -- the last write descriptor to name it wins, which is the
   last of the run of map[] entries carrying that block.  */
static int
ffu_lookup (const struct ffu_image *image, grub_uint32_t vblock, grub_uint32_t *didx)
{
	grub_uint64_t key = ((grub_uint64_t) vblock + 1) << 32;
	grub_uint32_t lo = 0, hi = image->nblocks;

	/* Upper bound: the first entry belonging to a later block.  */
	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (image->map[mid] < key)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0 || (image->map[lo - 1] >> 32) != vblock)
		return 0;
	*didx = (grub_uint32_t) (image->map[lo - 1] & 0xffffffffULL);
	return 1;
}

/* Bring payload block DIDX of a compressed store into cache[].  */
static grub_err_t
ffu_cache_block (struct ffu_image *image, grub_uint32_t didx)
{
	grub_uint64_t off = image->poff[didx];
	grub_uint64_t end = image->poff[didx + 1];
	grub_uint8_t *cbuf;
	grub_size_t csize;
	grub_ssize_t n = -1;
	grub_err_t err;

	if (image->cached == didx)
		return GRUB_ERR_NONE;
	/* Incompressible blocks grow a little; anything past that is bogus.  */
	if (end <= off || end - off > 2ULL * image->block_size)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU payload block %u size", didx);
	csize = (grub_size_t) (end - off);

	/* The MS-XCA bitstream reader may overread its input by up to two
	   bytes; the zeroed slack keeps that inside the allocation.  */
	cbuf = grub_malloc (csize + 8);
	if (!cbuf)
		return grub_errno;
	grub_memset (cbuf + csize, 0, 8);
	err = ffu_pread (image->file, image->data_off + off, cbuf, csize);
	if (err)
		goto done;

	switch (image->compression)
	{
	case FFU_COMPRESS_LZNT1:
		n = ffu_lznt1_decompress (cbuf, csize, image->cache, image->block_size);
		break;
	case FFU_COMPRESS_XPRESS_HUFF:
		/* xca_decompress takes no output limit, so measure first.  */
		n = xca_decompress (cbuf, csize, NULL);
		if (n >= 0 && (grub_uint64_t) n == image->block_size)
			n = xca_decompress (cbuf, csize, image->cache);
		break;
	default:	/* DEFAULT and XPRESS, both plain Xpress.  */
		n = ffu_xpress_decompress (cbuf, csize, image->cache, image->block_size);
		break;
	}
	if (n < 0 || (grub_uint64_t) n != image->block_size)
	{
		err = grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt FFU payload block %u", didx);
		goto done;
	}
	image->cached = didx;

done:
	grub_free (cbuf);
	return err;
}

static int
ffu_store_version (const struct ffu_store_header *sh)
{
	grub_uint32_t major = grub_le_to_cpu16 (sh->major_version);
	grub_uint32_t full = grub_le_to_cpu16 (sh->full_flash_major_version);

	if (major == 1 && full == 2)
		return FFU_V1;
	if (major == 1 && full == 3)
		return FFU_V1_COMPRESSED;
	if (major == 2 && full == 2)
		return FFU_V2;
	return -1;
}

static grub_err_t
ffu_open_image (struct ffu_image *image)
{
	struct ffu_security_header shdr;
	struct ffu_image_header ihdr;
	struct ffu_scan scan;
	grub_uint64_t file_size = grub_file_size (image->file);
	grub_uint64_t pos, hdr_off, chunk, img_chunk, total;
	grub_uint64_t desc_off = 0, min_bytes = 0;
	grub_uint32_t desc_len = 0, desc_count = 0;
	grub_uint32_t stride, manifest_len, dti_count = 0;
	grub_uint32_t nstores = 1, s;
	grub_uint8_t *buf = NULL;
	grub_err_t err;

	COMPILE_TIME_ASSERT (sizeof (struct ffu_security_header) == FFU_SECURITY_HEADER_SIZE);
	COMPILE_TIME_ASSERT (sizeof (struct ffu_image_header) == FFU_IMAGE_HEADER_SIZE);
	COMPILE_TIME_ASSERT (sizeof (struct ffu_store_header) == FFU_STORE_HEADER_SIZE);
	COMPILE_TIME_ASSERT (sizeof (struct ffu_store_header_v2) == FFU_STORE_HEADER_V2_SIZE);

	err = ffu_pread (image->file, 0, &shdr, sizeof (shdr));
	if (err)
		return err;
	if (grub_memcmp (shdr.signature, FFU_SEC_MAGIC, FFU_MAGIC_SIZE) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "not an FFU image");

	chunk = (grub_uint64_t) grub_le_to_cpu32 (shdr.chunk_size_kb) << 10;
	if (chunk < FFU_BLOCK_MIN || chunk > FFU_CHUNK_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU chunk size");

	/* The catalog and the table of hashes only serve to verify the image;
	   skip over both to the padded out end of the security header.  */
	pos = grub_le_to_cpu32 (shdr.size);
	if (pos < FFU_SECURITY_HEADER_SIZE || pos > FFU_HEADER_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU security header size");
	if (grub_add (pos, grub_le_to_cpu32 (shdr.catalog_size), &pos)
		|| grub_add (pos, grub_le_to_cpu32 (shdr.hash_table_size), &pos)
		|| pos > file_size)
		return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");
	err = ffu_align_up (&pos, chunk, file_size);
	if (err)
		return err;

	hdr_off = pos;
	err = ffu_pread (image->file, hdr_off, &ihdr, sizeof (ihdr));
	if (err)
		return err;
	if (grub_memcmp (ihdr.signature, FFU_IMG_MAGIC, FFU_MAGIC_SIZE) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad FFU image header");

	img_chunk = (grub_uint64_t) grub_le_to_cpu32 (ihdr.chunk_size_kb) << 10;
	if (img_chunk < FFU_BLOCK_MIN || img_chunk > FFU_CHUNK_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU chunk size");
	stride = grub_le_to_cpu32 (ihdr.size);
	if (stride < FFU_IMAGE_HEADER_SIZE || stride > FFU_HEADER_MAX)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU image header size");
	if (stride == FFU_IMAGE_HEADER_SIZE_DTI)
	{
		grub_uint32_t raw;

		err = ffu_pread (image->file, hdr_off + FFU_IMAGE_HEADER_SIZE, &raw, sizeof (raw));
		if (err)
			return err;
		dti_count = grub_le_to_cpu32 (raw);
		if (dti_count > FFU_DTI_MAX)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU device target info count");
	}

	pos = hdr_off + stride;
	manifest_len = grub_le_to_cpu32 (ihdr.manifest_length);
	if (manifest_len != 0 && manifest_len <= FFU_MANIFEST_MAX)
	{
		err = ffu_read_manifest (image->file, pos, manifest_len, &min_bytes);
		if (err)
			return err;
	}
	if (grub_add (pos, manifest_len, &pos) || pos > file_size)
		return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");

	/* Device targeting info records are variable length and of no use
	   here; only their size matters, the store headers follow them.  */
	for (s = 0; s < dti_count; s++)
	{
		grub_uint32_t lens[FFU_DTI_FIELDS];
		grub_uint64_t bytes = sizeof (lens);
		grub_uint32_t i;

		err = ffu_pread (image->file, pos, lens, sizeof (lens));
		if (err)
			return err;
		for (i = 0; i < FFU_DTI_FIELDS; i++)
			bytes += grub_le_to_cpu32 (lens[i]);
		if (bytes > FFU_DTI_BYTES_MAX)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU device target info");
		if (grub_add (pos, bytes, &pos) || pos > file_size)
			return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");
	}
	err = ffu_align_up (&pos, img_chunk, file_size);
	if (err)
		return err;

	/* Walk the header of every store: they sit back to back and the
	   payload of the first one starts past the last of them.  */
	for (s = 0; s < nstores; s++)
	{
		struct ffu_store_header sh;
		struct ffu_store_header_v2 sh2;
		grub_uint64_t block_size, skip;
		grub_uint32_t compression = FFU_COMPRESS_NONE;
		int version;

		err = ffu_pread (image->file, pos, &sh, sizeof (sh));
		if (err)
			return err;
		version = ffu_store_version (&sh);
		if (version < 0)
			return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported FFU store format %u.%u",
				grub_le_to_cpu16 (sh.major_version),
				grub_le_to_cpu16 (sh.full_flash_major_version));

		block_size = grub_le_to_cpu32 (sh.block_size);
		if (block_size < FFU_BLOCK_MIN || block_size > FFU_CHUNK_MAX || block_size % FFU_BLOCK_MIN != 0)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU store block size");

		skip = FFU_STORE_HEADER_SIZE;
		if (version == FFU_V1_COMPRESSED)
		{
			grub_uint32_t raw;

			err = ffu_pread (image->file, pos + skip, &raw, sizeof (raw));
			if (err)
				return err;
			compression = grub_le_to_cpu32 (raw);
			skip += sizeof (raw);
		}
		else if (version == FFU_V2)
		{
			err = ffu_pread (image->file, pos + skip, &sh2, sizeof (sh2));
			if (err)
				return err;
			skip += sizeof (sh2) + 2ULL * grub_le_to_cpu16 (sh2.device_path_length);
			if (s == 0)
			{
				nstores = grub_le_to_cpu16 (sh2.number_of_stores);
				if (nstores == 0 || nstores > FFU_STORES_MAX)
					return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU store count");
			}
		}

		/* Validation descriptors sit between the store header and the
		   write descriptors and are not needed for reading.  */
		if (grub_add (skip, grub_le_to_cpu32 (sh.validate_desc_length), &skip))
			return grub_error (GRUB_ERR_BAD_DEVICE, "malformed FFU store");
		if (s == 0)
		{
			image->block_size = (grub_uint32_t) block_size;
			image->compression = compression;
			desc_count = grub_le_to_cpu32 (sh.write_desc_count);
			desc_len = grub_le_to_cpu32 (sh.write_desc_length);
			desc_off = pos + skip;
		}
		if (grub_add (skip, grub_le_to_cpu32 (sh.write_desc_length), &skip)
			|| grub_add (pos, skip, &pos) || pos > file_size)
			return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");
		err = ffu_align_up (&pos, block_size, file_size);
		if (err)
			return err;
	}
	image->data_off = pos;

	switch (image->compression)
	{
	case FFU_COMPRESS_NONE:
	case FFU_COMPRESS_DEFAULT:
	case FFU_COMPRESS_LZNT1:
	case FFU_COMPRESS_XPRESS:
		break;
	case FFU_COMPRESS_XPRESS_HUFF:
		/* One Huffman table covers a whole MS-XCA stream, and the LZ77
		   offsets in it are 16 bit, so a stream can only carry 64 KiB.
		   Past that RtlCompressBuffer starts a second table, at a
		   boundary that is not recoverable from the stream itself, and
		   lib\wimboot\xca.c cannot follow it.  Refuse rather than hand
		   back a block that decoded into garbage halfway through.  */
		if (image->block_size > XCA_BLOCK_SIZE)
			return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "FFU XPRESS_HUFF blocks over %u bytes are not supported", XCA_BLOCK_SIZE);
		break;
	default:
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported FFU compression algorithm %u", image->compression);
	}

	if (desc_count == 0)
		return grub_error (GRUB_ERR_BAD_DEVICE, "empty FFU store");
	if (desc_len == 0 || desc_len > FFU_WDESC_BYTES_MAX
		|| desc_len > file_size - desc_off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU write descriptor length");
	/* An uncompressed store stores every block at full size, so the payload
	   it promises has to be there.  A compressed one is sized from the
	   per block DataSize fields instead, checked while scanning them.  */
	if (image->compression == FFU_COMPRESS_NONE
		&& (grub_uint64_t) desc_count * image->block_size > file_size - image->data_off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "FFU image truncated");
	image->ndesc = desc_count;

	buf = grub_malloc (desc_len);
	if (!buf)
		return grub_errno;
	err = ffu_pread (image->file, desc_off, buf, desc_len);
	if (err)
		goto fail;

	if (image->compression != FFU_COMPRESS_NONE)
	{
		image->poff = grub_calloc ((grub_size_t) desc_count + 1, sizeof (*image->poff));
		image->cache = grub_malloc (image->block_size);
		if (!image->poff || !image->cache)
		{
			err = grub_errno;
			goto fail;
		}
		image->cached = ~0U;
	}

	grub_memset (&scan, 0, sizeof (scan));
	err = ffu_scan_descriptors (image, buf, desc_len, &scan);
	if (err)
		goto fail;

	/* The descriptors put a lower bound on the size of the guest disk;
	   the manifest, where it has one, knows the real size.  Rounding up
	   to whole blocks keeps the blocks counted from the end of the disk
	   landing on block boundaries.  */
	total = 0;
	if (scan.has_start)
		total = (grub_uint64_t) scan.max_start + 1;
	if (scan.has_end)
		total += (grub_uint64_t) scan.max_end + 1;
	if (total == 0)
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE, "empty FFU store");
		goto fail;
	}
	if (min_bytes != 0)
	{
		grub_uint64_t need = (min_bytes + image->block_size - 1) / image->block_size;

		/* A manifest claiming something absurd is ignored; the write
		   descriptors on their own still describe a readable disk.  */
		if (need > total && need <= 0xffffffffULL)
			total = need;
	}
	if (total > 0xffffffffULL
		|| grub_mul (total, (grub_uint64_t) image->block_size, &image->total_bytes))
	{
		err = grub_error (GRUB_ERR_BAD_DEVICE, "bad FFU image size");
		goto fail;
	}
	image->total_blocks = (grub_uint32_t) total;

	image->map = grub_calloc ((grub_size_t) scan.nloc, sizeof (*image->map));
	if (!image->map)
	{
		err = grub_errno;
		goto fail;
	}
	ffu_build_map (image, buf);

	grub_free (buf);
	return GRUB_ERR_NONE;

fail:
	grub_free (buf);
	ffu_free_image (image);
	return err;
}

static grub_err_t
ffu_read (struct ffu_image *image, grub_uint64_t off, void *buf, grub_size_t len, grub_size_t *actually_read)
{
	grub_uint64_t vblock, off_in_block;
	grub_uint32_t didx;
	grub_err_t err;

	*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of FFU image");
	if (len == 0)
		return GRUB_ERR_NONE;

	vblock = off / image->block_size;
	off_in_block = off % image->block_size;

	/* Clip to the block; never grow the request.  */
	if (len > image->block_size - off_in_block)
		len = (grub_size_t) (image->block_size - off_in_block);

	/* A block the store never writes reads back as zeros.  */
	if (!ffu_lookup (image, (grub_uint32_t) vblock, &didx))
		grub_memset (buf, 0, len);
	else if (image->compression == FFU_COMPRESS_NONE)
	{
		err = ffu_pread (image->file, image->data_off + (grub_uint64_t) didx * image->block_size + off_in_block, buf, len);
		if (err)
			return err;
	}
	else
	{
		err = ffu_cache_block (image, didx);
		if (err)
			return err;
		grub_memcpy (buf, image->cache + off_in_block, len);
	}

	*actually_read = len;
	return GRUB_ERR_NONE;
}

struct grub_ffu
{
	grub_file_t file;
	struct ffu_image *ffu;
};
typedef struct grub_ffu *grub_ffu_t;

static struct grub_fs grub_ffu_fs;

static grub_err_t
grub_ffu_close (grub_file_t file)
{
	grub_ffu_t fio = file->data;

	ffu_free_image (fio->ffu);
	grub_free (fio->ffu);
	grub_file_close (fio->file);
	grub_free (fio);
	/* The inner close released the shared device;
	   the outer name is freed by kern\file.c.  */
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_ffu_open (grub_file_t io, enum grub_file_type type)
{
	grub_file_t file;
	grub_ffu_t fio;
	struct ffu_image *image;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size < sizeof (struct ffu_security_header) || io->size == GRUB_FILE_SIZE_UNKNOWN)
		return io;

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;

	if (ffu_open_image (image) != GRUB_ERR_NONE)
	{
		ffu_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = (grub_file_t) grub_zalloc (sizeof (*file));
	fio = grub_zalloc (sizeof (*fio));
	if (!file || !fio)
	{
		ffu_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (fio);
		return 0;
	}
	fio->file = io;
	fio->ffu = image;

	file->device = io->device;
	file->data = fio;
	file->fs = &grub_ffu_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;

	return file;
}

static grub_ssize_t
grub_ffu_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_err_t err = GRUB_ERR_NONE;
	grub_size_t real_size = 0;
	grub_ssize_t size = 0;
	grub_uint64_t read_offset = file->offset;
	grub_ffu_t fio = file->data;

	while (len > 0 && err == GRUB_ERR_NONE)
	{
		real_size = 0;
		err = ffu_read (fio->ffu, read_offset, buf, len, &real_size);
		if (err != GRUB_ERR_NONE)
			break;
		if (real_size == 0)
		{
			err = grub_error (GRUB_ERR_FILE_READ_ERROR, "FFU read made no progress");
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
			grub_error (err, "FFU image read failed");
		return -1;
	}
	return size;
}

static struct grub_fs grub_ffu_fs =
{
	.name = "ffu",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_ffu_read,
	.fs_close = grub_ffu_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (ffu)
{
	grub_file_filter_register (GRUB_FILE_FILTER_FFU, grub_ffu_open);
}

GRUB_MOD_FINI (ffu)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_FFU);
}
