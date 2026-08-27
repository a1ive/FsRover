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
 * Partclone image formats 0001 and 0002, implemented from
 * <https://github.com/Thomas-Tsai/partclone/blob/master/IMAGE_FORMATS.md>
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/safemath.h>

#define XXH_STATIC_LINKING_ONLY
#include <xxhash.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define PARTCLONE_MAGIC		"partclone-image"
#define PARTCLONE_MAGIC_SIZE	15
#define PARTCLONE_BITMAP_MAGIC	"BiTmAgIc"
#define PARTCLONE_BITMAP_MAGIC_SIZE 8

#define PARTCLONE_VERSION_OFFSET	30
#define PARTCLONE_HEADER_V1_SIZE	4160
#define PARTCLONE_HEADER_V2_SIZE	110
#define PARTCLONE_HEADER_V2_CRC_OFFSET 106
#define PARTCLONE_FEATURE_V2_SIZE	18

#define PARTCLONE_ENDIAN_LITTLE	0xc0de
#define PARTCLONE_BITMAP_BIT	1
#define PARTCLONE_CHECKSUM_NONE	0x00
#define PARTCLONE_CHECKSUM_CRC32	0x20
#define PARTCLONE_CHECKSUM_XXH64	0x30
#define PARTCLONE_CHECKSUM_V1	0xff

#define PARTCLONE_BLOCK_SIZE_MAX	(64U << 20)
#define PARTCLONE_BITMAP_SIZE_MAX	(256U << 20)
#define PARTCLONE_RANK_SHIFT	12
#define PARTCLONE_RANK_BLOCKS	(1U << PARTCLONE_RANK_SHIFT)
#define PARTCLONE_BITMAP_V1_BUFFER_SIZE (16U << 10)
#define PARTCLONE_VERIFY_BUFFER_SIZE (64U << 10)

struct partclone_image
{
	grub_file_t file;
	grub_uint64_t total_bytes;
	grub_uint64_t total_blocks;
	grub_uint64_t used_blocks;
	grub_uint32_t block_size;
	grub_uint16_t version;

	grub_uint8_t *bitmap;
	grub_size_t bitmap_size;
	grub_uint64_t *rank;
	grub_size_t rank_count;

	grub_uint64_t data_offset;
	grub_uint16_t checksum_mode;
	grub_uint16_t checksum_size;
	grub_uint32_t blocks_per_checksum;
	grub_uint8_t reseed_checksum;
	grub_uint8_t v1_checksum_stride;
	grub_uint64_t strip_count;

	grub_uint8_t *verified;
	grub_uint64_t verified_through;
	grub_uint32_t running_crc;
	XXH64_state_t running_xxh64;
	grub_uint8_t *verify_buffer;
};

struct grub_partclone
{
	grub_file_t file;
	struct partclone_image *image;
};
typedef struct grub_partclone *grub_partclone_t;

static struct grub_fs grub_partclone_fs;
static grub_uint32_t partclone_crc_table[256];

static grub_uint16_t
partclone_get16 (const grub_uint8_t *p)
{
	return (grub_uint16_t) p[0] | ((grub_uint16_t) p[1] << 8);
}

static grub_uint32_t
partclone_get32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8)
		| ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

static grub_uint64_t
partclone_get64 (const grub_uint8_t *p)
{
	return (grub_uint64_t) partclone_get32 (p)
		| ((grub_uint64_t) partclone_get32 (p + 4) << 32);
}

static grub_err_t
partclone_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;
	grub_uint64_t size = grub_file_size (file);

	if (off > size || len > size - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "partclone image truncated");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "partclone image truncated");
	return GRUB_ERR_NONE;
}

static void
partclone_crc_init (void)
{
	grub_uint32_t i;

	for (i = 0; i < 256; i++)
	{
		grub_uint32_t crc = i;
		unsigned bit;

		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0);
		partclone_crc_table[i] = crc;
	}
}

static grub_uint32_t
partclone_crc32 (grub_uint32_t crc, const void *data, grub_size_t len)
{
	const grub_uint8_t *p = data;

	while (len--)
		crc = (crc >> 8) ^ partclone_crc_table[(crc ^ *p++) & 0xff];
	return crc;
}

/* Format 0001's historical checksum bug updates every byte with the first
   byte of the block.  Checksums also continue cumulatively between blocks. */
static grub_uint32_t
partclone_crc32_v1 (grub_uint32_t crc, grub_uint8_t byte, grub_uint32_t len)
{
	while (len--)
		crc = (crc >> 8) ^ partclone_crc_table[(crc ^ byte) & 0xff];
	return crc;
}

static unsigned
partclone_popcount8 (grub_uint8_t value)
{
	value = (grub_uint8_t) (value - ((value >> 1) & 0x55));
	value = (grub_uint8_t) ((value & 0x33) + ((value >> 2) & 0x33));
	return (value + (value >> 4)) & 0x0f;
}

static int
partclone_block_used (const struct partclone_image *image, grub_uint64_t block)
{
	return (image->bitmap[block >> 3] >> (block & 7)) & 1;
}

/* Return the number of stored blocks before BLOCK.  A checkpoint every 4096
   logical blocks keeps the index small while bounding each lookup to 512
   bitmap bytes. */
static grub_uint64_t
partclone_rank (const struct partclone_image *image, grub_uint64_t block)
{
	grub_uint64_t first = (block >> PARTCLONE_RANK_SHIFT) << PARTCLONE_RANK_SHIFT;
	grub_uint64_t byte = first >> 3;
	grub_uint64_t end_byte = block >> 3;
	grub_uint64_t rank = image->rank[block >> PARTCLONE_RANK_SHIFT];

	while (byte < end_byte)
		rank += partclone_popcount8 (image->bitmap[byte++]);
	if (block & 7)
		rank += partclone_popcount8 ((grub_uint8_t) (image->bitmap[end_byte] & ((1U << (block & 7)) - 1)));
	return rank;
}

static grub_err_t
partclone_build_rank (struct partclone_image *image)
{
	grub_uint64_t blocks = image->total_blocks;
	grub_uint64_t groups = blocks / PARTCLONE_RANK_BLOCKS + (blocks % PARTCLONE_RANK_BLOCKS != 0);
	grub_uint64_t block;
	grub_uint64_t used = 0;
	grub_size_t bytes;

	if (!groups || groups > GRUB_SIZE_MAX / sizeof (*image->rank))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "partclone rank index too large");
	bytes = (grub_size_t) groups * sizeof (*image->rank);
	image->rank = grub_malloc (bytes);
	if (!image->rank)
		return grub_errno;
	image->rank_count = (grub_size_t) groups;

	for (block = 0; block < blocks; block++)
	{
		if ((block & (PARTCLONE_RANK_BLOCKS - 1)) == 0)
			image->rank[block >> PARTCLONE_RANK_SHIFT] = used;
		if (partclone_block_used (image, block))
			used++;
	}
	if (used != image->used_blocks)
		return grub_error (GRUB_ERR_BAD_DEVICE, "partclone bitmap block count mismatch");
	return GRUB_ERR_NONE;
}

static grub_err_t
partclone_expected_size (struct partclone_image *image, grub_uint64_t *expected)
{
	grub_uint64_t data_bytes, checksum_bytes, total;

	if (grub_mul (image->used_blocks, image->block_size, &data_bytes))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "partclone data size overflow");
	if (grub_mul (image->strip_count, image->checksum_size, &checksum_bytes)
		|| grub_add (image->data_offset, data_bytes, &total)
		|| grub_add (total, checksum_bytes, &total))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "partclone image size overflow");
	*expected = total;
	return GRUB_ERR_NONE;
}

static grub_err_t
partclone_load_bitmap_v1 (struct partclone_image *image)
{
	grub_uint8_t *buf;
	grub_uint8_t magic[PARTCLONE_BITMAP_MAGIC_SIZE];
	grub_uint64_t done = 0;
	grub_err_t err;

	buf = grub_malloc (PARTCLONE_BITMAP_V1_BUFFER_SIZE);
	if (!buf)
		return grub_errno;
	while (done < image->total_blocks)
	{
		grub_size_t want = PARTCLONE_BITMAP_V1_BUFFER_SIZE;
		grub_size_t i;

		if (image->total_blocks - done < want)
			want = (grub_size_t) (image->total_blocks - done);
		err = partclone_pread (image->file, PARTCLONE_HEADER_V1_SIZE + done, buf, want);
		if (err)
			goto out;
		for (i = 0; i < want; i++)
			if (buf[i] == 1)
				image->bitmap[(done + i) >> 3] |= (grub_uint8_t) (1U << ((done + i) & 7));
		done += want;
	}
	err = partclone_pread (image->file, PARTCLONE_HEADER_V1_SIZE + image->total_blocks, magic, sizeof (magic));
	if (err)
		goto out;
	if (grub_memcmp (magic, PARTCLONE_BITMAP_MAGIC, sizeof (magic)) != 0)
		err = grub_error (GRUB_ERR_BAD_SIGNATURE, "bad partclone 0001 bitmap signature");
out:
	grub_free (buf);
	return err;
}

static grub_err_t
partclone_load_bitmap_v2 (struct partclone_image *image)
{
	grub_uint8_t raw_crc[4];
	grub_uint32_t crc = 0xffffffffU;
	grub_err_t err;

	err = partclone_pread (image->file, PARTCLONE_HEADER_V2_SIZE, image->bitmap, image->bitmap_size);
	if (err)
		return err;
	err = partclone_pread (image->file,
		PARTCLONE_HEADER_V2_SIZE + image->bitmap_size,
		raw_crc, sizeof (raw_crc));
	if (err)
		return err;
	crc = partclone_crc32 (crc, image->bitmap, image->bitmap_size);
	if (crc != partclone_get32 (raw_crc))
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad partclone 0002 bitmap checksum");
	return GRUB_ERR_NONE;
}

static grub_err_t
partclone_open_v1 (struct partclone_image *image, const grub_uint8_t *header)
{
	grub_uint64_t logical_bytes, expected4, expected8;
	grub_uint64_t file_size = grub_file_size (image->file);
	grub_err_t err;

	image->version = 1;
	image->block_size = partclone_get32 (header + 36);
	image->total_bytes = partclone_get64 (header + 40);
	image->total_blocks = partclone_get64 (header + 48);
	image->used_blocks = partclone_get64 (header + 56);
	image->checksum_mode = PARTCLONE_CHECKSUM_V1;
	image->checksum_size = 4;
	image->blocks_per_checksum = 1;
	image->reseed_checksum = 0;

	if (!image->block_size || image->block_size > PARTCLONE_BLOCK_SIZE_MAX
		|| !image->total_blocks || image->used_blocks > image->total_blocks)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad partclone 0001 geometry");
	if (grub_mul (image->total_blocks, image->block_size, &logical_bytes)
		|| logical_bytes > image->total_bytes)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad partclone 0001 device size");
	if (image->total_blocks > PARTCLONE_BITMAP_SIZE_MAX * 8ULL)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "partclone 0001 bitmap is too large");

	image->bitmap_size = (grub_size_t) ((image->total_blocks + 7) >> 3);
	image->bitmap = grub_zalloc (image->bitmap_size);
	if (!image->bitmap)
		return grub_errno;
	err = partclone_load_bitmap_v1 (image);
	if (err)
		return err;
	err = partclone_build_rank (image);
	if (err)
		return err;
	image->data_offset = PARTCLONE_HEADER_V1_SIZE + image->total_blocks + PARTCLONE_BITMAP_MAGIC_SIZE;
	image->strip_count = image->used_blocks;

	image->v1_checksum_stride = 4;
	err = partclone_expected_size (image, &expected4);
	if (err)
		return err;
	image->checksum_size = 8;
	err = partclone_expected_size (image, &expected8);
	if (err)
		return err;
	if (file_size == expected4)
	{
		image->checksum_size = 4;
		image->v1_checksum_stride = 4;
	}
	else if (file_size == expected8)
	{
		/* Some old 64-bit builds wrote an eight-byte unsigned long for
		   the nominal four-byte checksum. */
		image->checksum_size = 8;
		image->v1_checksum_stride = 8;
	}
	else
		return grub_error (GRUB_ERR_BAD_DEVICE, "partclone 0001 data stream has the wrong size");
	return GRUB_ERR_NONE;
}

static grub_err_t
partclone_open_v2 (struct partclone_image *image, const grub_uint8_t *header)
{
	grub_uint64_t logical_bytes, expected;
	grub_uint32_t feature_size = partclone_get32 (header + 88);
	grub_uint32_t header_crc;
	grub_err_t err;

	header_crc = partclone_crc32 (0xffffffffU, header, PARTCLONE_HEADER_V2_CRC_OFFSET);
	if (header_crc != partclone_get32 (header + PARTCLONE_HEADER_V2_CRC_OFFSET))
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad partclone 0002 header checksum");
	if (partclone_get16 (header + 34) != PARTCLONE_ENDIAN_LITTLE)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "big-endian partclone images are not supported");
	if (feature_size != PARTCLONE_FEATURE_V2_SIZE
		|| partclone_get16 (header + 92) != 2
		|| (partclone_get16 (header + 94) != 32 && partclone_get16 (header + 94) != 64)
		|| header[105] != PARTCLONE_BITMAP_BIT)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported partclone 0002 feature layout");

	image->version = 2;
	image->total_bytes = partclone_get64 (header + 52);
	image->total_blocks = partclone_get64 (header + 60);
	image->used_blocks = partclone_get64 (header + 76);
	image->block_size = partclone_get32 (header + 84);
	image->checksum_mode = partclone_get16 (header + 96);
	image->checksum_size = partclone_get16 (header + 98);
	image->blocks_per_checksum = partclone_get32 (header + 100);
	image->reseed_checksum = header[104];

	if (!image->block_size || image->block_size > PARTCLONE_BLOCK_SIZE_MAX
		|| !image->total_blocks || image->used_blocks > image->total_blocks
		|| image->reseed_checksum > 1)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad partclone 0002 geometry");
	if (grub_mul (image->total_blocks, image->block_size, &logical_bytes)
		|| logical_bytes > image->total_bytes)
		return grub_error (GRUB_ERR_BAD_DEVICE, "bad partclone 0002 device size");
	if (image->total_blocks > PARTCLONE_BITMAP_SIZE_MAX * 8ULL)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "partclone 0002 bitmap is too large");

	switch (image->checksum_mode)
	{
	case PARTCLONE_CHECKSUM_NONE:
		if (image->checksum_size || image->blocks_per_checksum
			|| !image->reseed_checksum)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad checksum-free partclone options");
		break;
	case PARTCLONE_CHECKSUM_CRC32:
		if (image->checksum_size != 4 || !image->blocks_per_checksum)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad partclone CRC32 options");
		break;
	case PARTCLONE_CHECKSUM_XXH64:
		if (image->checksum_size != 8 || !image->blocks_per_checksum)
			return grub_error (GRUB_ERR_BAD_DEVICE, "bad partclone XXH64 options");
		break;
	default:
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported partclone checksum mode 0x%x", image->checksum_mode);
	}

	image->bitmap_size = (grub_size_t) ((image->total_blocks + 7) >> 3);
	image->bitmap = grub_zalloc (image->bitmap_size);
	if (!image->bitmap)
		return grub_errno;
	err = partclone_load_bitmap_v2 (image);
	if (err)
		return err;
	err = partclone_build_rank (image);
	if (err)
		return err;
	image->data_offset = PARTCLONE_HEADER_V2_SIZE + image->bitmap_size + 4;
	if (image->checksum_mode != PARTCLONE_CHECKSUM_NONE)
		image->strip_count = image->used_blocks / image->blocks_per_checksum + (image->used_blocks % image->blocks_per_checksum != 0);
	err = partclone_expected_size (image, &expected);
	if (err)
		return err;
	if (grub_file_size (image->file) != expected)
		return grub_error (GRUB_ERR_BAD_DEVICE, "partclone 0002 data stream has the wrong size");
	return GRUB_ERR_NONE;
}

static grub_err_t
partclone_open_image (struct partclone_image *image)
{
	grub_uint8_t header[PARTCLONE_HEADER_V1_SIZE];
	grub_size_t header_size;
	grub_err_t err;

	err = partclone_pread (image->file, 0, header,
		PARTCLONE_HEADER_V2_SIZE);
	if (err)
		return err;
	if (grub_memcmp (header, PARTCLONE_MAGIC, PARTCLONE_MAGIC_SIZE) != 0)
		return grub_error (GRUB_ERR_BAD_SIGNATURE, "not a partclone image");
	if (grub_memcmp (header + PARTCLONE_VERSION_OFFSET, "0001", 4) == 0)
		header_size = PARTCLONE_HEADER_V1_SIZE;
	else if (grub_memcmp (header + PARTCLONE_VERSION_OFFSET, "0002", 4) == 0)
		header_size = PARTCLONE_HEADER_V2_SIZE;
	else
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported partclone image version");
	if (header_size > PARTCLONE_HEADER_V2_SIZE)
	{
		err = partclone_pread (image->file, PARTCLONE_HEADER_V2_SIZE,
			header + PARTCLONE_HEADER_V2_SIZE,
			header_size - PARTCLONE_HEADER_V2_SIZE);
		if (err)
			return err;
	}

	err = header_size == PARTCLONE_HEADER_V1_SIZE
		? partclone_open_v1 (image, header)
		: partclone_open_v2 (image, header);
	if (err)
		return err;

	image->verify_buffer = grub_malloc (PARTCLONE_VERIFY_BUFFER_SIZE);
	if (!image->verify_buffer)
		return grub_errno;
	image->running_crc = 0xffffffffU;
	if (image->checksum_mode == PARTCLONE_CHECKSUM_XXH64
		&& XXH64_reset (&image->running_xxh64, 0) != XXH_OK)
		return grub_error (GRUB_ERR_BAD_DEVICE, "cannot initialize partclone XXH64 state");
	if (image->reseed_checksum && image->strip_count)
	{
		grub_uint64_t bytes = image->strip_count / 8 + (image->strip_count % 8 != 0);

		if (bytes > GRUB_SIZE_MAX)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "partclone checksum index too large");
		image->verified = grub_zalloc ((grub_size_t) bytes);
		if (!image->verified)
			return grub_errno;
	}
	return GRUB_ERR_NONE;
}

static grub_uint64_t
partclone_stored_offset (const struct partclone_image *image,
	grub_uint64_t stored_block)
{
	if (image->version == 1)
		return image->data_offset + stored_block * ((grub_uint64_t) image->block_size + image->v1_checksum_stride);
	if (image->checksum_mode == PARTCLONE_CHECKSUM_NONE)
		return image->data_offset + stored_block * image->block_size;
	return image->data_offset + stored_block * image->block_size + (stored_block / image->blocks_per_checksum) * image->checksum_size;
}

static grub_err_t
partclone_verify_strip (struct partclone_image *image, grub_uint64_t strip, int continuing)
{
	grub_uint64_t first, count, data_off, data_bytes, done = 0;
	grub_uint8_t stored[8];
	grub_uint32_t crc;
	XXH64_state_t xxh64;
	grub_err_t err;

	if (image->version == 1)
	{
		grub_uint8_t first_byte;

		first = strip;
		data_off = partclone_stored_offset (image, first);
		err = partclone_pread (image->file, data_off, &first_byte, 1);
		if (err)
			return err;
		crc = continuing ? image->running_crc : 0xffffffffU;
		crc = partclone_crc32_v1 (crc, first_byte, image->block_size);
		err = partclone_pread (image->file, data_off + image->block_size, stored, image->v1_checksum_stride);
		if (err)
			return err;
		if (crc != partclone_get32 (stored))
			return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad partclone 0001 block checksum");
		image->running_crc = crc;
		return GRUB_ERR_NONE;
	}

	first = strip * image->blocks_per_checksum;
	count = image->used_blocks - first;
	if (count > image->blocks_per_checksum)
		count = image->blocks_per_checksum;
	data_off = partclone_stored_offset (image, first);
	if (grub_mul (count, image->block_size, &data_bytes))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "partclone checksum strip too large");
	crc = continuing ? image->running_crc : 0xffffffffU;
	if (image->checksum_mode == PARTCLONE_CHECKSUM_XXH64)
	{
		if (continuing)
			xxh64 = image->running_xxh64;
		else if (XXH64_reset (&xxh64, 0) != XXH_OK)
			return grub_error (GRUB_ERR_BAD_DEVICE, "cannot initialize partclone XXH64 state");
	}
	while (done < data_bytes)
	{
		grub_size_t want = PARTCLONE_VERIFY_BUFFER_SIZE;

		if (data_bytes - done < want)
			want = (grub_size_t) (data_bytes - done);
		err = partclone_pread (image->file, data_off + done, image->verify_buffer, want);
		if (err)
			return err;
		if (image->checksum_mode == PARTCLONE_CHECKSUM_CRC32)
			crc = partclone_crc32 (crc, image->verify_buffer, want);
		else if (XXH64_update (&xxh64, image->verify_buffer, want) != XXH_OK)
			return grub_error (GRUB_ERR_BAD_DEVICE, "cannot update partclone XXH64 state");
		done += want;
	}
	err = partclone_pread (image->file, data_off + data_bytes, stored, image->checksum_size);
	if (err)
		return err;
	if (image->checksum_mode == PARTCLONE_CHECKSUM_CRC32)
	{
		if (crc != partclone_get32 (stored))
			return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad partclone CRC32 block strip");
		if (continuing)
			image->running_crc = crc;
	}
	else
	{
		grub_uint64_t digest = XXH64_digest (&xxh64);

		if (digest != partclone_get64 (stored))
			return grub_error (GRUB_ERR_BAD_SIGNATURE, "bad partclone XXH64 block strip");
		if (continuing)
			image->running_xxh64 = xxh64;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
partclone_verify_block (struct partclone_image *image, grub_uint64_t stored_block)
{
	grub_uint64_t strip;
	grub_err_t err;

	if (image->checksum_mode == PARTCLONE_CHECKSUM_NONE)
		return GRUB_ERR_NONE;
	strip = image->version == 1 ? stored_block : stored_block / image->blocks_per_checksum;
	if (image->reseed_checksum)
	{
		grub_uint8_t mask = (grub_uint8_t) (1U << (strip & 7));

		if (image->verified[strip >> 3] & mask)
			return GRUB_ERR_NONE;
		err = partclone_verify_strip (image, strip, 0);
		if (!err)
			image->verified[strip >> 3] |= mask;
		return err;
	}

	while (image->verified_through <= strip)
	{
		err = partclone_verify_strip (image, image->verified_through, 1);
		if (err)
			return err;
		image->verified_through++;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
partclone_read (struct partclone_image *image, grub_uint64_t off, void *buf,
	grub_size_t len, grub_size_t *actually_read)
{
	grub_uint64_t logical_bytes;
	grub_uint64_t block, in_block;
	grub_size_t want;
	grub_err_t err;

	*actually_read = 0;
	if (off > image->total_bytes || len > image->total_bytes - off)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past end of partclone image");
	if (!len)
		return GRUB_ERR_NONE;
	logical_bytes = image->total_blocks * (grub_uint64_t) image->block_size;
	if (off >= logical_bytes)
	{
		want = len;
		if ((grub_uint64_t) want > image->total_bytes - off)
			want = (grub_size_t) (image->total_bytes - off);
		grub_memset (buf, 0, want);
		*actually_read = want;
		return GRUB_ERR_NONE;
	}

	block = off / image->block_size;
	in_block = off % image->block_size;
	want = len;
	if (want > image->block_size - in_block)
		want = (grub_size_t) (image->block_size - in_block);
	if (!partclone_block_used (image, block))
		grub_memset (buf, 0, want);
	else
	{
		grub_uint64_t stored_block = partclone_rank (image, block);
		grub_uint64_t data_off;

		err = partclone_verify_block (image, stored_block);
		if (err)
			return err;
		data_off = partclone_stored_offset (image, stored_block) + in_block;
		err = partclone_pread (image->file, data_off, buf, want);
		if (err)
			return err;
	}
	*actually_read = want;
	return GRUB_ERR_NONE;
}

static void
partclone_free_image (struct partclone_image *image)
{
	grub_free (image->bitmap);
	image->bitmap = NULL;
	grub_free (image->rank);
	image->rank = NULL;
	grub_free (image->verified);
	image->verified = NULL;
	grub_free (image->verify_buffer);
	image->verify_buffer = NULL;
}

static grub_err_t
grub_partclone_close (grub_file_t file)
{
	grub_partclone_t pcio = file->data;

	partclone_free_image (pcio->image);
	grub_free (pcio->image);
	grub_file_close (pcio->file);
	grub_free (pcio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_partclone_open (grub_file_t io, enum grub_file_type type)
{
	grub_uint8_t probe[PARTCLONE_VERSION_OFFSET + 4];
	struct partclone_image *image;
	grub_partclone_t pcio;
	grub_file_t file;
	grub_err_t err;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK)
		|| io->size == GRUB_FILE_SIZE_UNKNOWN || io->size < sizeof (probe))
		return io;
	if (partclone_pread (io, 0, probe, sizeof (probe)) != GRUB_ERR_NONE)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}
	if (grub_memcmp (probe, PARTCLONE_MAGIC, PARTCLONE_MAGIC_SIZE) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return NULL;
	image->file = io;
	err = partclone_open_image (image);
	if (err)
	{
		partclone_free_image (image);
		grub_free (image);
		return NULL;
	}

	file = grub_zalloc (sizeof (*file));
	pcio = grub_zalloc (sizeof (*pcio));
	if (!file || !pcio)
	{
		partclone_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (pcio);
		return NULL;
	}
	pcio->file = io;
	pcio->image = image;
	file->device = io->device;
	file->data = pcio;
	file->fs = &grub_partclone_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->total_bytes;
	return file;
}

static grub_ssize_t
grub_partclone_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_partclone_t pcio = file->data;
	grub_uint64_t read_offset = file->offset;
	grub_ssize_t total = 0;

	while (len > 0)
	{
		grub_size_t got = 0;
		grub_err_t err = partclone_read (pcio->image, read_offset, buf, len, &got);

		if (err)
			return -1;
		if (!got)
		{
			grub_error (GRUB_ERR_FILE_READ_ERROR, "partclone read made no progress");
			return -1;
		}
		read_offset += got;
		buf += got;
		total += got;
		len -= got;
	}
	return total;
}

static struct grub_fs grub_partclone_fs =
{
	.name = "partclone",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_partclone_read,
	.fs_close = grub_partclone_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (partclone)
{
	partclone_crc_init ();
	grub_file_filter_register (GRUB_FILE_FILTER_PARTCLONE, grub_partclone_open);
}

GRUB_MOD_FINI (partclone)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_PARTCLONE);
}
