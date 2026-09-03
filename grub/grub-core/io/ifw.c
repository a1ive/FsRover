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
 * TeraByte Image for Windows v3/v4 IMG2 container and block format.
 *
 * Only full, unencrypted backups are supported.  A single backed-up partition
 * is exposed as a volume.  Several partitions are placed at their original
 * LBAs behind a synthetic GPT, because the TBI stores partition streams rather
 * than a complete source-disk sector image.
 *
 * Container layout
 * ----------------
 *
 *   0x0000  IMG2 global metadata record chain
 *            terminator and zero padding
 *   first recorded stream_base (0x1000 or later): partition stream 0
 *            (16-byte stream header, blocks, footer/index), then padding
 *            partition stream 1, if present
 *            ...
 *
 * Global metadata is a little-endian record chain ending before the first
 * partition stream; saved track-zero data can make it exceed 4 KiB:
 *
 *   u32 type;
 *   u32 payload_size;
 *   u32 aux;              // checksum or type-specific flags
 *   u8  payload[payload_size];
 *
 * A type value of UINT32_MAX ends the chain.  Relevant record payloads are:
 *
 *   type 0, IMG2 header
 *     +0x00  char[4] "IMG2"
 *     +0x04  u32 version marker (observed: 0x32600000, 0x33c00000, 0x40c00000)
 *     +0x08  u64 creation time as Windows FILETIME
 *     +0x10  u16 feature bits used below
 *     +0x18  u32 producer/subversion value (observed: 0x33200 / 0x40600)
 *
 *   type 1, one partition descriptor (payload is at least 0xfc bytes)
 *     +0x6c  u64 first source LBA
 *     +0x74  u64 last source LBA, inclusive
 *     +0x7c  u8[16] GPT partition-type GUID
 *     +0x8c  u8[16] GPT unique-partition GUID
 *     +0xa4  u8 MBR partition type (legacy disks have zero GPT GUIDs)
 *     +0xe4  u64 block-region length (footer - stream_base)
 *     +0xec  u64 stream_base
 *     +0xf4  u64 footer anchor (the block limit is this value - 0x18)
 *
 *   type 6, encryption descriptor
 *     +0x00  nonzero means encrypted
 *
 * Changes-only images add a type 7 record containing the base image FILETIME
 * and a type 9 record containing its NUL-terminated path.  Their type 5 flags
 * and partition-stream grammar also differ from full images.  They are not
 * decoded here.  The optional .#_# companion is an exact copy of the first
 * 4 KiB of its TBI; .#0 starts with a 24-byte "#HH#" sector-hash header.  Both
 * are backup-creation accelerators, not image volumes or restore-time splits.
 *
 * Feature and codec selection
 * ---------------------------
 *
 *   0x0080  blocks have the 8-byte header, otherwise the header is 4 bytes
 *   0x0001  IPP/raw Deflate
 *   0x0040  ZLIB/raw Deflate
 *   0x0020  TB Fast token stream
 *   0x0100  Zstandard frame
 *
 * With none of the codec bits, compressed blocks use the default TB Standard
 * codec.  A block with stored_size == plain_size is verbatim and therefore
 * works regardless of the selected codec; this is also how the observed
 * no-compression images are represented.
 *
 * Partition stream and block format
 * ---------------------------------
 *
 * Each stream begins with an opaque 16-byte header.  Full-image blocks follow
 * consecutively up to the descriptor's footer limit.  A block header is:
 *
 *   u16 plain_size_raw;   // 0 means 65536; bit 0 is a flag and is stripped
 *   u16 stored_size_raw;  // 0 means 65536
 *   u32 aux;              // present only when feature 0x0080 is set
 *   u8  payload[stored_size];
 *
 * A decoded size divisible by 512 is ordinary sector data and advances the
 * current logical position by plain_size bytes.  Otherwise it is a sparse
 * control block.  Its decoded payload is a little-endian u32 command array
 * followed by the rotating-add checksum implemented by ifw_checksum():
 *
 *   kind  = command >> 28;
 *   count = command & 0x0fffffff;       // number of 512-byte sectors
 *
 * Kind 0 terminates the command array.  Other full-image kinds advance over
 * sparse sectors, which read as zero.  Kind 8 means that the sectors must be
 * obtained from a base image and is rejected as a backup-chain reference.
 * Unmapped space after the final block is also exposed as zero up to the
 * partition's declared last LBA.
 *
 * The footer starts with a fixed-shape prefix and contains a type 1 index
 * record whose payload is:
 *
 *   u32 reserved;
 *   u32 count;
 *   struct { u64 source_lba; u64 file_offset; } entry[count];
 *
 * The index maps absolute source LBAs to block-header offsets for random
 * access.  This filter does not consume it; it scans each stream once, checks
 * that the block region ends exactly at the descriptor's footer limit, and
 * builds its own in-memory extent table.
 *
 * Codec details
 * -------------
 *
 * Deflate blocks are raw streams without a zlib wrapper.  ZSTD blocks are
 * ordinary frames.  TB Standard is an LSB-first bit stream beginning at bit
 * offset 3.  A zero token bit introduces an 8-bit literal.  A one introduces
 * an LZ match whose length is an Elias-gamma value plus one.  Length two uses
 * an 8-bit distance; longer matches use an Elias-gamma high part minus one and
 * an 8-bit low part.  TB Fast uses one-byte tokens: bit 7 clear is a literal
 * run; bit 7 set is an LZ match.  Bit 5 selects a 16-bit length extension and
 * bit 6 selects a 16-bit distance (or a long literal).  The decoders below
 * record the exact length and distance biases.
 *
 * Split TBI data files, encrypted images, and all differential/incremental
 * chains are deliberately outside this filter.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/gpt_partition.h>
#include <grub/msdos_partition.h>

#include <miniz.h>
#include <zstd.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define IFW_MIN_IMAGE_SIZE	4096
#define IFW_META_RECORDS_MAX	4096
#define IFW_REC_HEADER		12
#define IFW_STREAM_HEADER	16
#define IFW_BLOCK_HEADER_LONG	8
#define IFW_BLOCK_HEADER_SHORT	4
#define IFW_BLOCK_MAX		65536
#define IFW_SECTOR		512

#define IFW_PART_PAYLOAD_MIN	0xfc
#define IFW_PART_FIRST_LBA	0x6c
#define IFW_PART_LAST_LBA	0x74
#define IFW_PART_TYPE_GUID	0x7c
#define IFW_PART_GUID		0x8c
#define IFW_PART_MBR_TYPE	0xa4
#define IFW_PART_STREAM_BASE	0xec
#define IFW_PART_FOOTER_END	0xf4

#define IFW_GPT_ENTRIES		128
#define IFW_GPT_ENTRY_SIZE	sizeof (struct grub_gpt_partentry)
#define IFW_GPT_HEADER_SIZE	sizeof (struct grub_gpt_header)
#define IFW_GPT_SECTORS		(1 + IFW_GPT_ENTRIES * IFW_GPT_ENTRY_SIZE / IFW_SECTOR)
#define IFW_GPT_FIRST_USABLE	(1 + IFW_GPT_SECTORS)

#define IFW_EXTENTS_MAX		(64u << 20)
#define IFW_NO_CACHE		(~(grub_uint64_t) 0)

enum ifw_codec
{
	IFW_CODEC_STANDARD,
	IFW_CODEC_DEFLATE,
	IFW_CODEC_TB_FAST,
	IFW_CODEC_ZSTD
};

struct ifw_part
{
	grub_uint64_t first_lba;
	grub_uint64_t last_lba;
	grub_uint64_t stream_base;
	grub_uint64_t footer;
	grub_uint8_t type[16];
	grub_uint8_t guid[16];
	grub_uint8_t mbr_type;
};

struct ifw_extent
{
	grub_uint64_t off;
	grub_uint64_t phys;
	grub_uint32_t len;
};

struct ifw_image
{
	grub_file_t file;
	grub_uint64_t size;
	enum ifw_codec codec;
	grub_uint32_t block_header;

	struct ifw_part part[IFW_GPT_ENTRIES];
	grub_uint32_t npart;

	struct ifw_extent *ext;
	grub_uint32_t next;
	grub_uint32_t cap;
	grub_uint32_t cur;

	grub_uint8_t *stored;
	grub_uint8_t *plain;
	grub_uint64_t cached_phys;
	grub_uint32_t cached_len;

	grub_uint8_t *synth;
	grub_uint32_t synth_len;
};

static grub_uint16_t
ifw_get16 (const grub_uint8_t *p)
{
	grub_uint16_t v;

	grub_memcpy (&v, p, sizeof (v));
	return grub_le_to_cpu16 (v);
}

static grub_uint32_t
ifw_get32 (const grub_uint8_t *p)
{
	grub_uint32_t v;

	grub_memcpy (&v, p, sizeof (v));
	return grub_le_to_cpu32 (v);
}

static grub_uint64_t
ifw_get64 (const grub_uint8_t *p)
{
	grub_uint64_t v;

	grub_memcpy (&v, p, sizeof (v));
	return grub_le_to_cpu64 (v);
}

static grub_err_t
ifw_pread (struct ifw_image *img, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t n;

	if (off > grub_file_size (img->file) || len > grub_file_size (img->file) - off)
		return grub_error (GRUB_ERR_BAD_DEVICE, "IFW image truncated");
	if (grub_file_seek (img->file, off) == (grub_off_t) -1)
		return grub_errno;
	n = grub_file_read (img->file, buf, len);
	if (n < 0)
		return grub_errno;
	if ((grub_size_t) n != len)
		return grub_error (GRUB_ERR_BAD_DEVICE, "IFW image truncated");
	return GRUB_ERR_NONE;
}

/* The checksum used inside sparse-control blocks.  */
static grub_uint32_t
ifw_checksum (const grub_uint8_t *p, grub_uint32_t len)
{
	grub_uint32_t sum = 0;

	while (len >= 4)
	{
		grub_uint32_t word = ifw_get32 (p);

		sum += word;
		sum = (sum << 1) | (sum >> 31);
		sum ^= word;
		p += 4;
		len -= 4;
	}
	if (len)
	{
		grub_uint32_t word = 0;
		unsigned i;

		for (i = 0; i < len; i++)
			word |= (grub_uint32_t) p[i] << (8 * i);
		sum += word;
		sum = (sum << 1) | (sum >> 31);
		sum ^= word;
	}
	return sum;
}

struct ifw_std_bits
{
	const grub_uint8_t *in;
	grub_uint32_t in_len;
	grub_uint32_t bit;
};

static int
ifw_std_get_bits (struct ifw_std_bits *bits, unsigned count,
	grub_uint32_t *value)
{
	grub_uint32_t byte, word = 0;
	grub_uint32_t total = bits->in_len << 3;
	unsigned i;

	if (count > 16 || bits->bit > total || count > total - bits->bit)
		return 0;
	byte = bits->bit >> 3;
	for (i = 0; i < 4 && byte + i < bits->in_len; i++)
		word |= (grub_uint32_t) bits->in[byte + i] << (8 * i);
	word >>= bits->bit & 7;
	*value = count ? word & ((1u << count) - 1) : 0;
	bits->bit += count;
	return 1;
}

static int
ifw_std_gamma (struct ifw_std_bits *bits, grub_uint32_t *value)
{
	grub_uint32_t bit, suffix;
	unsigned zeros = 0;

	do
	{
		if (!ifw_std_get_bits (bits, 1, &bit))
			return 0;
		if (bit)
			break;
		if (++zeros > 15)
			return 0;
	} while (1);
	if (!ifw_std_get_bits (bits, zeros, &suffix))
		return 0;
	*value = (1u << zeros) | suffix;
	return 1;
}

/* TB Standard.  Tokens are read LSB first from bit offset three and the
   expected output length terminates the stream.  */
static grub_err_t
ifw_tb_standard (const grub_uint8_t *in, grub_uint32_t in_len,
	grub_uint8_t *out, grub_uint32_t out_len)
{
	struct ifw_std_bits bits = { in, in_len, 3 };
	grub_uint32_t op = 0;

	while (op < out_len)
	{
		grub_uint32_t token, code, len, dist, low, i;

		if (!ifw_std_get_bits (&bits, 1, &token))
			goto bad;
		if (!token)
		{
			if (!ifw_std_get_bits (&bits, 8, &code))
				goto bad;
			out[op++] = (grub_uint8_t) code;
			continue;
		}

		if (!ifw_std_gamma (&bits, &code))
			goto bad;
		len = code + 1;
		if (len == 2)
		{
			if (!ifw_std_get_bits (&bits, 8, &dist))
				goto bad;
		}
		else
		{
			if (!ifw_std_gamma (&bits, &code) || code > 0x100
				|| !ifw_std_get_bits (&bits, 8, &low))
				goto bad;
			dist = ((code - 1) << 8) | low;
		}
		if (!dist || dist > op || len > out_len - op)
			goto bad;
		for (i = 0; i < len; i++)
			out[op + i] = out[op - dist + i];
		op += len;
	}
	return GRUB_ERR_NONE;

bad:
	return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
		"bad IFW TB Standard block");
}

/* TB Fast (compression values 14 and 15).  A token is either a literal
   run or an LZ match; the token bits select one- or two-byte lengths and
   distances.  */
static grub_err_t
ifw_tb_fast (const grub_uint8_t *in, grub_uint32_t in_len,
	grub_uint8_t *out, grub_uint32_t out_len)
{
	grub_uint32_t ip = 0, op = 0;

	while (op < out_len)
	{
		grub_uint32_t len, dist, i;
		grub_uint8_t token;

		if (ip >= in_len)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "truncated IFW TB Fast block");
		token = in[ip++];
		if (!(token & 0x80))
		{
			if (token & 0x40)
			{
				if (token & 0x20)
				{
					if (in_len - ip < 2)
						goto bad;
					len = ifw_get16 (in + ip);
					ip += 2;
				}
				else
				{
					if (ip >= in_len)
						goto bad;
					len = in[ip++];
				}
				len += 65;
			}
			else
				len = (token & 0x3f) + 1;
			if (len > in_len - ip || len > out_len - op)
				goto bad;
			grub_memcpy (out + op, in + ip, len);
			ip += len;
			op += len;
			continue;
		}

		if (token & 0x20)
		{
			if (in_len - ip < 2)
				goto bad;
			len = ifw_get16 (in + ip);
			ip += 2;
		}
		else
			len = token & 0x1f;
		len += 4;
		if (token & 0x40)
		{
			if (in_len - ip < 2)
				goto bad;
			dist = ifw_get16 (in + ip);
			ip += 2;
		}
		else
		{
			if (ip >= in_len)
				goto bad;
			dist = in[ip++];
		}
		dist++;
		if (dist > op || len > out_len - op)
			goto bad;
		for (i = 0; i < len; i++)
			out[op + i] = out[op - dist + i];
		op += len;
	}
	return GRUB_ERR_NONE;

bad:
	return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad IFW TB Fast block");
}

static grub_err_t
ifw_decode (struct ifw_image *img, grub_uint32_t stored_len,
	grub_uint32_t plain_len)
{
	size_t n;

	if (stored_len == plain_len)
	{
		grub_memcpy (img->plain, img->stored, plain_len);
		return GRUB_ERR_NONE;
	}
	switch (img->codec)
	{
	case IFW_CODEC_DEFLATE:
		n = tinfl_decompress_mem_to_mem (img->plain, plain_len,
			img->stored, stored_len, 0);
		if (n != plain_len)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad IFW Deflate block");
		return GRUB_ERR_NONE;
	case IFW_CODEC_TB_FAST:
		return ifw_tb_fast (img->stored, stored_len, img->plain, plain_len);
	case IFW_CODEC_ZSTD:
		n = ZSTD_decompress (img->plain, plain_len, img->stored, stored_len);
		if (n != plain_len)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad IFW ZSTD block");
		return GRUB_ERR_NONE;
	case IFW_CODEC_STANDARD:
		return ifw_tb_standard (img->stored, stored_len, img->plain, plain_len);
	default:
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad IFW compression type");
	}
}

static grub_err_t
ifw_read_block_header (struct ifw_image *img, grub_uint64_t phys,
	grub_uint32_t *plain_len, grub_uint32_t *stored_len)
{
	grub_uint8_t hdr[IFW_BLOCK_HEADER_LONG];
	grub_uint32_t raw;
	grub_err_t err;

	err = ifw_pread (img, phys, hdr, img->block_header);
	if (err)
		return err;
	raw = ifw_get16 (hdr);
	*plain_len = (raw ? raw : IFW_BLOCK_MAX) & ~1u;
	raw = ifw_get16 (hdr + 2);
	*stored_len = raw ? raw : IFW_BLOCK_MAX;
	if (*plain_len == 0 || *plain_len > IFW_BLOCK_MAX || *stored_len > IFW_BLOCK_MAX)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad IFW block size");
	return GRUB_ERR_NONE;
}

static grub_err_t
ifw_read_block (struct ifw_image *img, grub_uint64_t phys,
	grub_uint32_t *plain_len, grub_uint32_t *stored_len)
{
	grub_err_t err;

	err = ifw_read_block_header (img, phys, plain_len, stored_len);
	if (err)
		return err;
	err = ifw_pread (img, phys + img->block_header, img->stored, *stored_len);
	if (err)
		return err;
	return ifw_decode (img, *stored_len, *plain_len);
}

static grub_err_t
ifw_add_extent (struct ifw_image *img, grub_uint64_t off,
	grub_uint64_t phys, grub_uint32_t len)
{
	struct ifw_extent *larger;
	grub_uint32_t cap;

	if (img->next == img->cap)
	{
		if (img->cap >= IFW_EXTENTS_MAX)
			return grub_error (GRUB_ERR_OUT_OF_MEMORY, "too many IFW blocks");
		cap = img->cap ? img->cap * 2 : 4096;
		if (cap > IFW_EXTENTS_MAX)
			cap = IFW_EXTENTS_MAX;
		larger = grub_realloc (img->ext, (grub_size_t) cap * sizeof (*larger));
		if (!larger)
			return grub_errno;
		img->ext = larger;
		img->cap = cap;
	}
	img->ext[img->next].off = off;
	img->ext[img->next].phys = phys;
	img->ext[img->next].len = len;
	img->next++;
	return GRUB_ERR_NONE;
}

static grub_err_t
ifw_scan_stream (struct ifw_image *img, const struct ifw_part *part,
	grub_uint64_t target_base)
{
	grub_uint64_t phys = part->stream_base + IFW_STREAM_HEADER;
	grub_uint64_t logical = 0;
	grub_uint64_t sectors = part->last_lba - part->first_lba + 1;
	grub_uint64_t limit = sectors * IFW_SECTOR;

	while (phys < part->footer)
	{
		grub_uint32_t plain_len, stored_len;
		grub_err_t err;

		err = ifw_read_block_header (img, phys, &plain_len, &stored_len);
		if (err)
			return err;
		if (part->footer - phys < img->block_header
			|| stored_len > part->footer - phys - img->block_header)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "IFW block runs past its stream");
		if (plain_len % IFW_SECTOR == 0)
		{
			if (plain_len > limit - logical)
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "IFW data exceeds its partition");
			err = ifw_add_extent (img, target_base + logical, phys, plain_len);
			if (err)
				return err;
			logical += plain_len;
		}
		else
		{
			grub_uint32_t at;

			err = ifw_read_block (img, phys, &plain_len, &stored_len);
			if (err)
				return err;
			if (plain_len < 8 || (plain_len & 3)
				|| ifw_get32 (img->plain + plain_len - 4)
				   != ifw_checksum (img->plain, plain_len - 4))
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad IFW sparse-control block");
			for (at = 0; at < plain_len - 4; at += 4)
			{
				grub_uint32_t word = ifw_get32 (img->plain + at);
				grub_uint32_t kind = word >> 28;
				grub_uint32_t count = word & 0x0fffffffU;
				grub_uint64_t bytes;

				if (kind == 0)
					break;
				if (kind == 8)
					return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
						"differential IFW backups are not supported");
				bytes = (grub_uint64_t) count * IFW_SECTOR;
				if (bytes > limit - logical)
					return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "IFW sparse run exceeds its partition");
				logical += bytes;
			}
		}
		phys += img->block_header + stored_len;
	}
	if (phys != part->footer)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "IFW stream does not end at its footer");
	return GRUB_ERR_NONE;
}

static grub_uint32_t
ifw_crc32 (const void *buf, grub_size_t len)
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

static const grub_uint8_t ifw_type_data[16] =
{
	0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,
	0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7
};

/* MBR Linux types have no source GPT GUID in their descriptors.  */
static const grub_uint8_t ifw_type_linux[16] =
{
	0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47,
	0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4
};

static const grub_uint8_t ifw_type_swap[16] =
{
	0x6d, 0xfd, 0x57, 0x06, 0xab, 0xa4, 0xc4, 0x43,
	0x84, 0xe5, 0x09, 0x33, 0xc8, 0x4b, 0x4f, 0x4f
};

static grub_err_t
ifw_build_gpt (struct ifw_image *img, grub_uint64_t disk_sectors)
{
	grub_uint32_t bytes = (1 + IFW_GPT_SECTORS) * IFW_SECTOR;
	struct grub_msdos_partition_mbr *mbr;
	struct grub_gpt_partentry *ent;
	struct grub_gpt_header *hdr;
	grub_uint32_t i;

	img->synth = grub_zalloc (bytes);
	if (!img->synth)
		return grub_errno;
	img->synth_len = bytes;
	mbr = (struct grub_msdos_partition_mbr *) img->synth;
	mbr->entries[0].type = GRUB_PC_PARTITION_TYPE_GPT_DISK;
	mbr->entries[0].start = grub_cpu_to_le32 (1);
	mbr->entries[0].length = grub_cpu_to_le32 (disk_sectors - 1 > 0xffffffffU
		? 0xffffffffU : (grub_uint32_t) (disk_sectors - 1));
	mbr->signature = grub_cpu_to_le16_compile_time (GRUB_PC_PARTITION_SIGNATURE);

	hdr = (struct grub_gpt_header *) (img->synth + IFW_SECTOR);
	ent = (struct grub_gpt_partentry *) (img->synth + 2 * IFW_SECTOR);
	for (i = 0; i < img->npart; i++)
	{
		const grub_uint8_t *type = img->part[i].type;
		unsigned j;
		int empty = 1;

		for (j = 0; j < sizeof (img->part[i].type); j++)
			if (type[j])
				empty = 0;
		if (empty)
		{
			if (img->part[i].mbr_type == GRUB_PC_PARTITION_TYPE_LINUX_SWAP)
				type = ifw_type_swap;
			else if (img->part[i].mbr_type == GRUB_PC_PARTITION_TYPE_EXT2FS)
				type = ifw_type_linux;
			else
				type = ifw_type_data;
		}
		grub_memcpy (&ent[i].type, type, sizeof (ent[i].type));
		grub_memcpy (&ent[i].guid, img->part[i].guid, sizeof (ent[i].guid));
		ent[i].start = grub_cpu_to_le64 (img->part[i].first_lba);
		ent[i].end = grub_cpu_to_le64 (img->part[i].last_lba);
	}

	grub_memcpy (hdr->magic, "EFI PART", sizeof (hdr->magic));
	hdr->version = grub_cpu_to_le32_compile_time (0x00010000);
	hdr->headersize = grub_cpu_to_le32_compile_time (IFW_GPT_HEADER_SIZE);
	hdr->primary = grub_cpu_to_le64_compile_time (1);
	hdr->backup = grub_cpu_to_le64 (disk_sectors - 1);
	hdr->start = grub_cpu_to_le64_compile_time (IFW_GPT_FIRST_USABLE);
	hdr->end = grub_cpu_to_le64 (disk_sectors - IFW_GPT_FIRST_USABLE);
	hdr->partitions = grub_cpu_to_le64_compile_time (2);
	hdr->maxpart = grub_cpu_to_le32_compile_time (IFW_GPT_ENTRIES);
	hdr->partentry_size = grub_cpu_to_le32_compile_time (IFW_GPT_ENTRY_SIZE);
	hdr->partentry_crc32 = grub_cpu_to_le32 (ifw_crc32 (ent,
		(grub_size_t) IFW_GPT_ENTRIES * IFW_GPT_ENTRY_SIZE));
	hdr->crc32 = grub_cpu_to_le32 (ifw_crc32 (hdr, IFW_GPT_HEADER_SIZE));
	return GRUB_ERR_NONE;
}

static void
ifw_sort_parts (struct ifw_image *img)
{
	grub_uint32_t i;

	for (i = 1; i < img->npart; i++)
	{
		struct ifw_part part = img->part[i];
		grub_uint32_t j = i;

		while (j && img->part[j - 1].first_lba > part.first_lba)
		{
			img->part[j] = img->part[j - 1];
			j--;
		}
		img->part[j] = part;
	}
}

static grub_err_t
ifw_open_image (struct ifw_image *img)
{
	grub_uint8_t meta[IFW_PART_PAYLOAD_MIN];
	grub_uint64_t at = 0;
	grub_uint64_t meta_limit = grub_file_size (img->file);
	grub_uint32_t records = 0;
	grub_uint32_t features = 0;
	int have_head = 0, have_crypt = 0, have_end = 0;
	grub_uint32_t i;
	grub_err_t err;

	/* Saved track-zero data can push the descriptors past the first
	   4 KiB.  Read record headers and only the payload prefixes we use,
	   bounding the chain by the earliest partition stream once known.  */
	while (at <= meta_limit && meta_limit - at >= IFW_REC_HEADER
		&& records++ < IFW_META_RECORDS_MAX)
	{
		grub_uint8_t header[IFW_REC_HEADER];
		grub_uint32_t type, len;
		const grub_uint8_t *p = meta;

		err = ifw_pread (img, at, header, sizeof (header));
		if (err)
			return err;
		type = ifw_get32 (header);
		len = ifw_get32 (header + 4);
		at += IFW_REC_HEADER;
		if (type == 0xffffffffU)
		{
			have_end = 1;
			break;
		}
		if (len > meta_limit - at)
			return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad IFW metadata record");
		if (type == 0 || type == 1 || type == 6)
		{
			grub_size_t take = len < sizeof (meta) ? len : sizeof (meta);

			err = ifw_pread (img, at, meta, take);
			if (err)
				return err;
		}
		switch (type)
		{
		case 0:
			if (have_head || len < 0x1c || grub_memcmp (p, "IMG2", 4) != 0)
				return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not an IFW IMG2 image");
			features = ifw_get16 (p + 0x10);
			have_head = 1;
			break;

		case 1:
		{
			struct ifw_part *part;

			if (len < IFW_PART_PAYLOAD_MIN || img->npart == IFW_GPT_ENTRIES)
				return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad IFW partition descriptor");
			part = &img->part[img->npart++];
			part->first_lba = ifw_get64 (p + IFW_PART_FIRST_LBA);
			part->last_lba = ifw_get64 (p + IFW_PART_LAST_LBA);
			part->stream_base = ifw_get64 (p + IFW_PART_STREAM_BASE);
			if (part->stream_base < at + len)
				return grub_error (GRUB_ERR_BAD_FILE_TYPE, "IFW stream overlaps metadata");
			if (part->stream_base < meta_limit)
				meta_limit = part->stream_base;
			part->footer = ifw_get64 (p + IFW_PART_FOOTER_END);
			if (part->footer < 0x18)
				return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad IFW stream footer");
			part->footer -= 0x18;
			grub_memcpy (part->type, p + IFW_PART_TYPE_GUID, sizeof (part->type));
			grub_memcpy (part->guid, p + IFW_PART_GUID, sizeof (part->guid));
			part->mbr_type = p[IFW_PART_MBR_TYPE];
			break;
		}

		case 6:
			if (len >= 4)
				have_crypt |= ifw_get32 (p) != 0;
			break;

		default:
			break;
		}
		at += len;
	}
	if (!have_end)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "unterminated IFW metadata");
	if (!have_head || !img->npart)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "IFW image has no partition stream");
	if (have_crypt)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "encrypted IFW backups are not supported");

	img->block_header = features & 0x80 ? IFW_BLOCK_HEADER_LONG : IFW_BLOCK_HEADER_SHORT;
	if (features & 1)
		img->codec = IFW_CODEC_DEFLATE;
	else if (features & 0x40)
		img->codec = IFW_CODEC_DEFLATE;
	else if (features & 0x20)
		img->codec = IFW_CODEC_TB_FAST;
	else if (features & 0x100)
		img->codec = IFW_CODEC_ZSTD;
	else
		img->codec = IFW_CODEC_STANDARD;

	ifw_sort_parts (img);
	for (i = 0; i < img->npart; i++)
	{
		struct ifw_part *part = &img->part[i];

		if (part->first_lba > part->last_lba
			|| part->stream_base > grub_file_size (img->file) - IFW_STREAM_HEADER
			|| part->footer < part->stream_base + IFW_STREAM_HEADER
			|| part->footer > grub_file_size (img->file))
			return grub_error (GRUB_ERR_BAD_FILE_TYPE, "bad IFW partition stream");
		if (i && part->first_lba <= img->part[i - 1].last_lba)
			return grub_error (GRUB_ERR_BAD_FILE_TYPE, "overlapping IFW partitions");
	}

	img->stored = grub_malloc (IFW_BLOCK_MAX);
	img->plain = grub_malloc (IFW_BLOCK_MAX);
	if (!img->stored || !img->plain)
		return grub_errno;
	img->cached_phys = IFW_NO_CACHE;

	if (img->npart == 1)
	{
		grub_uint64_t sectors = img->part[0].last_lba - img->part[0].first_lba + 1;

		if (sectors > (~(grub_uint64_t) 0) / IFW_SECTOR)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "IFW partition is too large");
		img->size = sectors * IFW_SECTOR;
		err = ifw_scan_stream (img, &img->part[0], 0);
		if (err)
			return err;
	}
	else
	{
		grub_uint64_t disk_sectors;

		if (img->part[img->npart - 1].last_lba > (~(grub_uint64_t) 0) - IFW_GPT_FIRST_USABLE)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "IFW source disk is too large");
		disk_sectors = img->part[img->npart - 1].last_lba + IFW_GPT_FIRST_USABLE;
		if (disk_sectors > (~(grub_uint64_t) 0) / IFW_SECTOR)
			return grub_error (GRUB_ERR_OUT_OF_RANGE, "IFW source disk is too large");
		img->size = disk_sectors * IFW_SECTOR;
		err = ifw_build_gpt (img, disk_sectors);
		if (err)
			return err;
		for (i = 0; i < img->npart; i++)
		{
			err = ifw_scan_stream (img, &img->part[i], img->part[i].first_lba * IFW_SECTOR);
			if (err)
				return err;
		}
	}
	return GRUB_ERR_NONE;
}

static void
ifw_free_image (struct ifw_image *img)
{
	grub_free (img->ext);
	grub_free (img->stored);
	grub_free (img->plain);
	grub_free (img->synth);
	img->ext = NULL;
	img->stored = NULL;
	img->plain = NULL;
	img->synth = NULL;
}

static grub_uint32_t
ifw_find_extent (struct ifw_image *img, grub_uint64_t off)
{
	grub_uint32_t lo = 0, hi = img->next;

	if (img->cur < img->next && img->ext[img->cur].off <= off
		&& off < img->ext[img->cur].off + img->ext[img->cur].len)
		return img->cur;
	while (lo < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;

		if (img->ext[mid].off <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo && off < img->ext[lo - 1].off + img->ext[lo - 1].len)
		return lo - 1;
	return img->next;
}

static grub_err_t
ifw_read (struct ifw_image *img, grub_uint64_t off, void *buf,
	grub_size_t len, grub_size_t *actually_read)
{
	struct ifw_extent *ext;
	grub_uint32_t nr;
	grub_size_t n;
	grub_err_t err;

	*actually_read = 0;
	if (off >= img->size)
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "read past the end of the IFW image");
	if (len > img->size - off)
		len = (grub_size_t) (img->size - off);
	if (!len)
		return GRUB_ERR_NONE;

	if (img->synth && off < img->synth_len)
	{
		n = img->synth_len - (grub_size_t) off;
		if (n > len)
			n = len;
		grub_memcpy (buf, img->synth + off, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}

	nr = ifw_find_extent (img, off);
	if (nr == img->next)
	{
		grub_uint32_t lo = 0, hi = img->next;
		grub_uint64_t end = img->size;

		while (lo < hi)
		{
			grub_uint32_t mid = lo + (hi - lo) / 2;

			if (img->ext[mid].off <= off)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (lo < img->next)
			end = img->ext[lo].off;
		n = len;
		if (n > end - off)
			n = (grub_size_t) (end - off);
		grub_memset (buf, 0, n);
		*actually_read = n;
		return GRUB_ERR_NONE;
	}

	img->cur = nr;
	ext = &img->ext[nr];
	if (img->cached_phys != ext->phys)
	{
		grub_uint32_t stored_len;

		err = ifw_read_block (img, ext->phys, &img->cached_len, &stored_len);
		if (err)
			return err;
		if (img->cached_len != ext->len)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "IFW block size changed");
		img->cached_phys = ext->phys;
	}
	n = ext->len - (grub_size_t) (off - ext->off);
	if (n > len)
		n = len;
	grub_memcpy (buf, img->plain + (off - ext->off), n);
	*actually_read = n;
	return GRUB_ERR_NONE;
}

struct grub_ifw
{
	grub_file_t file;
	struct ifw_image *image;
};
typedef struct grub_ifw *grub_ifw_t;

static struct grub_fs grub_ifw_fs;

static grub_err_t
grub_ifw_close (grub_file_t file)
{
	grub_ifw_t ifwio = file->data;

	ifw_free_image (ifwio->image);
	grub_free (ifwio->image);
	grub_file_close (ifwio->file);
	grub_free (ifwio);
	file->device = 0;
	return grub_errno;
}

static grub_file_t
grub_ifw_open (grub_file_t io, enum grub_file_type type)
{
	grub_uint8_t probe[IFW_REC_HEADER + 4];
	struct ifw_image *image;
	grub_ifw_t ifwio;
	grub_file_t file;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK))
		return io;
	if (io->size == GRUB_FILE_SIZE_UNKNOWN || io->size < IFW_MIN_IMAGE_SIZE)
		return io;
	if (grub_file_seek (io, 0) == (grub_off_t) -1
		|| grub_file_read (io, probe, sizeof (probe)) != (grub_ssize_t) sizeof (probe)
		|| ifw_get32 (probe) != 0 || ifw_get32 (probe + 4) < 0x1c
		|| grub_memcmp (probe + IFW_REC_HEADER, "IMG2", 4) != 0)
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	image = grub_zalloc (sizeof (*image));
	if (!image)
		return 0;
	image->file = io;
	if (ifw_open_image (image) != GRUB_ERR_NONE)
	{
		ifw_free_image (image);
		grub_free (image);
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}

	file = grub_zalloc (sizeof (*file));
	ifwio = grub_zalloc (sizeof (*ifwio));
	if (!file || !ifwio)
	{
		ifw_free_image (image);
		grub_free (image);
		grub_free (file);
		grub_free (ifwio);
		return 0;
	}
	ifwio->file = io;
	ifwio->image = image;
	file->device = io->device;
	file->data = ifwio;
	file->fs = &grub_ifw_fs;
	file->not_easily_seekable = io->not_easily_seekable;
	file->size = image->size;
	return file;
}

static grub_ssize_t
grub_ifw_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_ifw_t ifwio = file->data;
	grub_uint64_t off = file->offset;
	grub_ssize_t total = 0;

	while (len)
	{
		grub_size_t got = 0;
		grub_err_t err = ifw_read (ifwio->image, off, buf, len, &got);

		if (err)
			return -1;
		if (!got)
			return grub_error (GRUB_ERR_FILE_READ_ERROR, "IFW read made no progress"), -1;
		off += got;
		buf += got;
		total += got;
		len -= got;
	}
	return total;
}

static struct grub_fs grub_ifw_fs =
{
	.name = "ifw",
	.fs_dir = 0,
	.fs_open = 0,
	.fs_read = grub_ifw_read,
	.fs_close = grub_ifw_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (ifw)
{
	grub_file_filter_register (GRUB_FILE_FILTER_IFW, grub_ifw_open);
}

GRUB_MOD_FINI (ifw)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_IFW);
}
