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

#include <grub/types.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/dl.h>

#include <7zTypes.h>
#include <LzmaDec.h>
#include <Bra.h>
#include <miniz.h>
#include <zstd.h>
#include <bzlib.h>

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define NSIS_FIRST_HEADER_SIZE	28
#define NSIS_SIGNATURE_SIZE	16
#define NSIS_SCAN_LIMIT		(1u << 20)
#define NSIS_HEADER_MAX		(128u << 20)
#define NSIS_FILE_MAX		((grub_size_t) 1 << 30)
#define NSIS_ITEMS_MAX		(1u << 20)
#define NSIS_NAME_MAX		(1u << 12)
#define NSIS_IO_SIZE		(1u << 15)
#define NSIS_SEEN_BUCKETS	512

#define NSIS_FLAG_NO_CRC	0x04
#define NSIS_FLAG_FORCE_CRC	0x08
#define NSIS_FLAGS_MASK		0x0f
#define NSIS_COMPRESSED		0x80000000u

#define NSIS_CMD_SIZE		28
#define NSIS_CMD_CREATEDIR	11
#define NSIS_CMD_EXTRACTFILE	20

enum nsis_method
{
	NSIS_METHOD_COPY,
	NSIS_METHOD_DEFLATE,
	NSIS_METHOD_BZIP2,
	NSIS_METHOD_LZMA,
	NSIS_METHOD_ZSTD
};

enum nsis_type
{
	NSIS_TYPE_2,
	NSIS_TYPE_3,
	NSIS_TYPE_PARK
};

struct nsis_item
{
	char *name;
	grub_uint32_t pos;
	grub_uint32_t estimated_size;
	grub_int64_t mtime;
	unsigned estimated_size_set:1;
};

struct grub_nsis_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	grub_uint64_t archive_pos;
	grub_uint64_t data_pos;
	grub_uint64_t packed_end;
	grub_uint32_t flags;
	grub_uint32_t header_size;
	grub_uint32_t archive_size;
	grub_uint32_t non_solid_start;
	enum nsis_method method;
	enum nsis_type type;
	int solid;
	int filter_flag;
	int unicode;
	grub_uint8_t *header;
	grub_uint32_t strings_pos;
	grub_uint32_t strings_chars;
	struct nsis_item *items;
	unsigned num_items;
	unsigned max_items;
};

struct grub_nsis_file
{
	struct grub_nsis_data *data;
	unsigned index;
	grub_uint8_t *buf;
	grub_uint32_t size;
	grub_uint64_t raw_pos;
	int raw;
};

static const grub_uint8_t nsis_signature[NSIS_SIGNATURE_SIZE] =
{
	0xef, 0xbe, 0xad, 0xde, 'N', 'u', 'l', 'l',
	's', 'o', 'f', 't', 'I', 'n', 's', 't'
};

static grub_uint16_t
nsis_get16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
nsis_get32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static int
nsis_range (grub_uint64_t off, grub_uint64_t len, grub_uint64_t size)
{
	return off <= size && len <= size - off;
}

static int
nsis_read (struct grub_nsis_data *data, grub_uint64_t pos, void *buf, grub_size_t len)
{
	if (!nsis_range (pos, len, data->disk_size))
	{
		grub_error (GRUB_ERR_BAD_FS, "truncated nsis archive");
		return 0;
	}
	if (len != 0 && grub_disk_read (data->disk, 0, pos, len, buf))
		return 0;
	return 1;
}

static void *
nsis_alloc (ISzAllocPtr p, size_t size)
{
	(void) p;
	return grub_malloc (size);
}

static void
nsis_free (ISzAllocPtr p, void *address)
{
	(void) p;
	grub_free (address);
}

static const ISzAlloc nsis_allocator = { nsis_alloc, nsis_free };

struct nsis_input
{
	struct grub_nsis_data *data;
	grub_uint64_t pos;
	grub_uint64_t end;
	grub_uint8_t buf[NSIS_IO_SIZE];
	grub_size_t next;
	grub_size_t size;
};

static int
nsis_input_fill (struct nsis_input *in)
{
	grub_size_t size;

	if (in->pos >= in->end)
	{
		in->next = 0;
		in->size = 0;
		return 0;
	}
	size = (in->end - in->pos > NSIS_IO_SIZE) ? NSIS_IO_SIZE : (grub_size_t) (in->end - in->pos);
	if (!nsis_read (in->data, in->pos, in->buf, size))
		return -1;
	in->pos += size;
	in->next = 0;
	in->size = size;
	return 1;
}

static int
nsis_input_byte (struct nsis_input *in, grub_uint8_t *value)
{
	if (in->next == in->size && nsis_input_fill (in) <= 0)
		return 0;
	*value = in->buf[in->next++];
	return 1;
}

struct nsis_sink
{
	grub_uint8_t *buf;
	grub_size_t size;
	grub_size_t cap;
	grub_size_t skip;
	grub_size_t target;
	grub_uint8_t prefix[4];
	unsigned prefix_size;
	unsigned size_prefix:1;
	unsigned dynamic:1;
	unsigned done:1;
};

static int
nsis_sink_reserve (struct nsis_sink *sink, grub_size_t need)
{
	grub_size_t cap;
	grub_uint8_t *buf;

	if (need <= sink->cap)
		return 1;
	if (need > NSIS_FILE_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "nsis file is too large");
		return 0;
	}
	cap = sink->cap ? sink->cap : NSIS_IO_SIZE;
	while (cap < need)
	{
		if (cap > NSIS_FILE_MAX / 2)
		{
			cap = NSIS_FILE_MAX;
			break;
		}
		cap *= 2;
	}
	buf = grub_realloc (sink->buf, cap ? cap : 1);
	if (!buf)
		return 0;
	sink->buf = buf;
	sink->cap = cap;
	return 1;
}

static int
nsis_sink_write (struct nsis_sink *sink, const grub_uint8_t *buf, grub_size_t size)
{
	grub_size_t take;

	if (sink->done)
		return 1;
	if (sink->skip)
	{
		take = size < sink->skip ? size : sink->skip;
		sink->skip -= take;
		buf += take;
		size -= take;
	}
	while (sink->size_prefix && sink->prefix_size < 4 && size)
	{
		sink->prefix[sink->prefix_size++] = *buf++;
		size--;
		if (sink->prefix_size == 4)
		{
			sink->target = nsis_get32 (sink->prefix);
			if (sink->target > NSIS_FILE_MAX || !nsis_sink_reserve (sink, sink->target))
				return 0;
			if (sink->target == 0)
				sink->done = 1;
		}
	}
	if (sink->size_prefix && sink->prefix_size != 4)
		return 1;
	if (sink->done)
		return 1;
	if (sink->dynamic)
	{
		if (size > NSIS_FILE_MAX - sink->size || !nsis_sink_reserve (sink, sink->size + size))
			return 0;
		take = size;
	}
	else
	{
		take = sink->target - sink->size;
		if (take > size)
			take = size;
		if (!nsis_sink_reserve (sink, sink->target))
			return 0;
	}
	if (take)
	{
		grub_memcpy (sink->buf + sink->size, buf, take);
		sink->size += take;
	}
	if (!sink->dynamic && sink->size == sink->target)
		sink->done = 1;
	return 1;
}

static int
nsis_copy_decode (struct nsis_input *in, struct nsis_sink *sink)
{
	while (!sink->done)
	{
		int res = nsis_input_fill (in);

		if (res < 0)
			return 0;
		if (res == 0)
			break;
		if (!nsis_sink_write (sink, in->buf, in->size))
			return 0;
		in->next = in->size;
	}
	return sink->done || sink->dynamic;
}

static int
nsis_lzma_decode (struct nsis_input *in, struct nsis_sink *sink, int filter_flag)
{
	CLzmaDec dec;
	grub_uint8_t props[LZMA_PROPS_SIZE];
	grub_uint8_t out[NSIS_IO_SIZE];
	grub_uint8_t filtered[NSIS_IO_SIZE + 8];
	grub_uint8_t tail[8];
	grub_size_t tail_size = 0;
	grub_uint32_t bcj_state = Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL;
	grub_uint32_t bcj_pc = 0;
	grub_uint8_t flag = 0;
	unsigned i;
	int ok = 0;

	LzmaDec_CONSTRUCT (&dec)
	if (filter_flag && (!nsis_input_byte (in, &flag) || flag > 1))
		goto out;
	for (i = 0; i < LZMA_PROPS_SIZE; i++)
		if (!nsis_input_byte (in, &props[i]))
			goto out;
	if (LzmaDec_Allocate (&dec, props, LZMA_PROPS_SIZE, &nsis_allocator) != SZ_OK)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_FS, "bad nsis lzma properties");
		goto out;
	}
	LzmaDec_Init (&dec);
	while (!sink->done)
	{
		SizeT src_size, dst_size;
		ELzmaStatus status;
		int filled;

		if (in->next == in->size)
		{
			filled = nsis_input_fill (in);
			if (filled < 0)
				goto free_dec;
		}
		src_size = in->size - in->next;
		dst_size = sizeof (out);
		if (LzmaDec_DecodeToBuf (&dec, out, &dst_size,
			in->buf + in->next, &src_size, LZMA_FINISH_ANY, &status) != SZ_OK)
		{
			grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt nsis lzma stream");
			goto free_dec;
		}
		in->next += src_size;
		if (flag)
		{
			grub_uint8_t *end;
			grub_size_t total;
			grub_size_t processed;

			grub_memcpy (filtered, tail, tail_size);
			grub_memcpy (filtered + tail_size, out, dst_size);
			total = tail_size + dst_size;
			end = z7_BranchConvSt_X86_Dec (filtered, total, bcj_pc, &bcj_state);
			processed = (grub_size_t) (end - filtered);
			if (!nsis_sink_write (sink, filtered, processed))
				goto free_dec;
			bcj_pc += (grub_uint32_t) processed;
			tail_size = total - processed;
			grub_memcpy (tail, filtered + processed, tail_size);
		}
		else if (!nsis_sink_write (sink, out, dst_size))
			goto free_dec;
		if (status == LZMA_STATUS_FINISHED_WITH_MARK)
		{
			if (flag && tail_size && !nsis_sink_write (sink, tail, tail_size))
				goto free_dec;
			ok = sink->done || sink->dynamic;
			break;
		}
		if (src_size == 0 && dst_size == 0)
		{
			if (in->pos == in->end && in->next == in->size)
				break;
			grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "stalled nsis lzma stream");
			goto free_dec;
		}
	}
	if (sink->done)
		ok = 1;

free_dec:
	LzmaDec_Free (&dec, &nsis_allocator);
out:
	return ok;
}

static int
nsis_deflate_decode (struct nsis_input *in, struct nsis_sink *sink)
{
	tinfl_decompressor *dec;
	grub_uint8_t *dict;
	grub_size_t dict_pos = 0;
	int ok = 0;
	int finished = 0;

	dec = grub_malloc (sizeof (*dec));
	dict = grub_malloc (TINFL_LZ_DICT_SIZE);
	if (!dec || !dict)
		goto out;
	tinfl_init (dec);
	while (!sink->done && !finished)
	{
		size_t src_size, dst_size;
		tinfl_status status;
		mz_uint32 flags;
		int filled;

		if (in->next == in->size)
		{
			filled = nsis_input_fill (in);
			if (filled < 0)
				goto out;
		}
		src_size = in->size - in->next;
		dst_size = TINFL_LZ_DICT_SIZE - dict_pos;
		flags = (in->pos < in->end || in->next < in->size)
			? TINFL_FLAG_HAS_MORE_INPUT : 0;
		status = tinfl_decompress (dec, in->buf + in->next,
			&src_size, dict, dict + dict_pos, &dst_size, flags);
		in->next += src_size;
		if (!nsis_sink_write (sink, dict + dict_pos, dst_size))
			goto out;
		dict_pos = (dict_pos + dst_size) & (TINFL_LZ_DICT_SIZE - 1);
		if (status == TINFL_STATUS_DONE)
			finished = 1;
		else if (status < TINFL_STATUS_DONE)
		{
			grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt nsis deflate stream");
			goto out;
		}
		else if (src_size == 0 && dst_size == 0 && in->pos == in->end && in->next == in->size)
			break;
	}
	ok = sink->done || (sink->dynamic && finished);

out:
	grub_free (dict);
	grub_free (dec);
	return ok;
}

static int
nsis_zstd_decode (struct nsis_input *in, struct nsis_sink *sink)
{
	ZSTD_DStream *stream;
	grub_uint8_t out[NSIS_IO_SIZE];
	size_t res;
	int ok = 0;

	stream = ZSTD_createDStream ();
	if (!stream)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
		return 0;
	}
	res = ZSTD_initDStream (stream);
	if (ZSTD_isError (res))
	{
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "cannot initialize nsis zstd stream");
		goto out;
	}
	while (!sink->done)
	{
		ZSTD_inBuffer input;
		ZSTD_outBuffer output;
		int filled;

		if (in->next == in->size)
		{
			filled = nsis_input_fill (in);
			if (filled < 0)
				goto out;
		}
		input.src = in->buf;
		input.size = in->size;
		input.pos = in->next;
		output.dst = out;
		output.size = sizeof (out);
		output.pos = 0;
		res = ZSTD_decompressStream (stream, &output, &input);
		if (ZSTD_isError (res))
		{
			grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt nsis zstd stream");
			goto out;
		}
		in->next = input.pos;
		if (!nsis_sink_write (sink, out, output.pos))
			goto out;
		if (res == 0)
		{
			ok = sink->done || sink->dynamic;
			break;
		}
		if (output.pos == 0 && input.pos == input.size
			 && in->pos == in->end)
			break;
	}
	if (sink->done)
		ok = 1;

out:
	ZSTD_freeDStream (stream);
	return ok;
}

static int
nsis_bzip2_decode (struct nsis_input *in, struct nsis_sink *sink)
{
	bz_stream stream;
	grub_uint8_t out[NSIS_IO_SIZE];
	int result;
	int ok = 0;

	grub_memset (&stream, 0, sizeof (stream));
	result = BZ2_bzDecompressInitNSis (&stream, 0, 0);
	if (result != BZ_OK)
	{
		grub_error (result == BZ_MEM_ERROR ? GRUB_ERR_OUT_OF_MEMORY
			: GRUB_ERR_BAD_COMPRESSED_DATA, "cannot initialize nsis bzip2 stream");
		return 0;
	}
	while (!sink->done)
	{
		unsigned consumed;
		unsigned produced;

		if (in->next == in->size && nsis_input_fill (in) < 0)
			goto fail;
		stream.next_in = (char *) in->buf + in->next;
		stream.avail_in = (unsigned) (in->size - in->next);
		consumed = stream.avail_in;
		stream.next_out = (char *) out;
		stream.avail_out = sizeof (out);
		result = BZ2_bzDecompress (&stream);
		consumed -= stream.avail_in;
		produced = sizeof (out) - stream.avail_out;
		in->next += consumed;
		if (result != BZ_OK && result != BZ_STREAM_END)
		{
			grub_error (result == BZ_MEM_ERROR ? GRUB_ERR_OUT_OF_MEMORY
				: GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt nsis bzip2 stream");
			goto fail;
		}
		if (!nsis_sink_write (sink, out, produced))
			goto fail;
		if (result == BZ_STREAM_END)
		{
			ok = sink->done || sink->dynamic;
			goto fail;
		}
		if (consumed == 0 && produced == 0)
			goto fail;
	}
	ok = 1;

fail:
	BZ2_bzDecompressEnd (&stream);
	return ok;
}

static int
nsis_decode (struct grub_nsis_data *data, grub_uint64_t pos,
	grub_uint64_t packed_size, enum nsis_method method, int filter_flag, struct nsis_sink *sink)
{
	struct nsis_input in;
	int ok;

	if (!nsis_range (pos, packed_size, data->disk_size))
		return 0;
	grub_memset (&in, 0, sizeof (in));
	in.data = data;
	in.pos = pos;
	in.end = pos + packed_size;

	switch (method)
	{
	case NSIS_METHOD_COPY:
		ok = nsis_copy_decode (&in, sink);
		break;
	case NSIS_METHOD_LZMA:
		ok = nsis_lzma_decode (&in, sink, filter_flag);
		break;
	case NSIS_METHOD_DEFLATE:
		ok = nsis_deflate_decode (&in, sink);
		break;
	case NSIS_METHOD_ZSTD:
		ok = nsis_zstd_decode (&in, sink);
		break;
	case NSIS_METHOD_BZIP2:
		ok = nsis_bzip2_decode (&in, sink);
		break;
	default:
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "unsupported nsis compression");
		return 0;
	}
	if (!ok && !grub_errno)
		grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "truncated nsis compressed stream");
	return ok;
}

static int
nsis_is_lzma (const grub_uint8_t *p, grub_size_t size, int *filter_flag)
{
	unsigned off = 0;

	if (size >= 7 && p[0] <= 1 && p[1] == 0x5d)
	{
		*filter_flag = 1;
		off = 1;
	}
	else
		*filter_flag = 0;
	if (size < off + 7)
		return 0;
	return p[off] == 0x5d && p[off + 1] == 0
		&& p[off + 2] == 0 && p[off + 5] == 0
		&& (p[off + 6] & 0x80) == 0;
}

static enum nsis_method
nsis_detect_method (const grub_uint8_t *p, grub_size_t size, int *filter_flag)
{
	if (nsis_is_lzma (p, size, filter_flag))
		return NSIS_METHOD_LZMA;
	*filter_flag = 0;
	if (size >= 2 && p[0] == 0x31 && p[1] < 14)
		return NSIS_METHOD_BZIP2;
	if (size >= 4 && p[0] == 0x28 && p[1] == 0xb5 && p[2] == 0x2f && p[3] == 0xfd)
		return NSIS_METHOD_ZSTD;
	return NSIS_METHOD_DEFLATE;
}

static void
nsis_free_data (struct grub_nsis_data *data)
{
	unsigned i;

	if (!data)
		return;
	for (i = 0; i < data->num_items; i++)
		grub_free (data->items[i].name);
	grub_free (data->items);
	grub_free (data->header);
	grub_free (data);
}

static char *
nsis_var_name (unsigned index)
{
	static const char *const vars[] =
	{
		"CMDLINE", "INSTDIR", "OUTDIR", "EXEDIR", "LANGUAGE",
		"TEMP", "PLUGINSDIR", "EXEPATH", "EXEFILE", "HWNDPARENT",
		"_CLICK", "_OUTDIR"
	};
	char buf[24];

	if (index < 10)
		grub_snprintf (buf, sizeof (buf), "$%u", index);
	else if (index < 20)
		grub_snprintf (buf, sizeof (buf), "$R%u", index - 10);
	else if (index - 20 < ARRAY_SIZE (vars))
		grub_snprintf (buf, sizeof (buf), "$%s", vars[index - 20]);
	else
		grub_snprintf (buf, sizeof (buf), "$_%u_", index - 32);
	return grub_strdup (buf);
}

static int
nsis_append (grub_uint8_t *out, grub_size_t *len, const char *s)
{
	grub_size_t n = grub_strlen (s);

	if (n > NSIS_NAME_MAX - *len)
		return 0;
	grub_memcpy (out + *len, s, n);
	*len += n;
	return 1;
}

static int
nsis_append_codepoint (grub_uint8_t *out, grub_size_t *len, grub_uint32_t code)
{
	grub_uint16_t u16[2];
	grub_size_t n;
	grub_uint8_t *end;

	if (code <= 0xffff)
	{
		u16[0] = (grub_uint16_t) code;
		n = 1;
	}
	else if (code <= 0x10ffff)
	{
		code -= 0x10000;
		u16[0] = (grub_uint16_t) (0xd800 + (code >> 10));
		u16[1] = (grub_uint16_t) (0xdc00 + (code & 0x3ff));
		n = 2;
	}
	else
		return nsis_append (out, len, "?");
	if (*len > NSIS_NAME_MAX - 4)
		return 0;
	end = grub_utf16_to_utf8 (out + *len, u16, n);
	*len = (grub_size_t) (end - out);
	return 1;
}

static char *
nsis_decode_string (struct grub_nsis_data *data, grub_uint32_t offset)
{
	grub_uint8_t raw[NSIS_NAME_MAX + 1];
	grub_size_t len = 0;
	grub_uint32_t pos = offset;
	char *converted;

	if (offset >= data->strings_chars)
		return 0;
	while (pos < data->strings_chars && len < NSIS_NAME_MAX)
	{
		grub_uint32_t c;
		grub_uint32_t n;
		char *var;

		if (data->unicode)
		{
			c = nsis_get16 (data->header + data->strings_pos + pos * 2);
			pos++;
			if (c == 0)
				break;
			if (data->type == NSIS_TYPE_PARK)
			{
				if (c < 0xe000 || c > 0xe003)
				{
					if (!nsis_append_codepoint (raw, &len, c))
						return 0;
					continue;
				}
				if (pos >= data->strings_chars)
					return 0;
				n = nsis_get16 (data->header + data->strings_pos + pos * 2);
				pos++;
				if (c == 0xe000)
				{
					if (!nsis_append_codepoint (raw, &len, n))
						return 0;
					continue;
				}
				n &= 0x7fff;
			}
			else
			{
				if (c > 4)
				{
					if (!nsis_append_codepoint (raw, &len, c))
						return 0;
					continue;
				}
				if (pos >= data->strings_chars)
					return 0;
				n = nsis_get16 (data->header + data->strings_pos + pos * 2);
				pos++;
				if (c == 4)
				{
					if (!nsis_append_codepoint (raw, &len, n))
						return 0;
					continue;
				}
				n = (n & 0x7f) | (((n >> 8) & 0x7f) << 7);
			}
			if (c == 3 || c == 0xe001)
			{
				var = nsis_var_name (n);
				if (!var || !nsis_append (raw, &len, var))
				{
					grub_free (var);
					return 0;
				}
				grub_free (var);
			}
			else
			{
				char special[24];

				grub_snprintf (special, sizeof (special), "$SHELL%u", n);
				if (!nsis_append (raw, &len, special))
					return 0;
			}
		}
		else
		{
			c = data->header[data->strings_pos + pos++];
			if (c == 0)
				break;
			if ((data->type == NSIS_TYPE_3 && c <= 4)
				|| (data->type != NSIS_TYPE_3 && c >= 252))
			{
				grub_uint32_t code_var = (data->type == NSIS_TYPE_3) ? 3 : 253;
				grub_uint32_t code_skip = (data->type == NSIS_TYPE_3) ? 4 : 252;

				if (pos >= data->strings_chars)
					return 0;
				n = data->header[data->strings_pos + pos++];
				if (c == code_skip)
				{
					raw[len++] = (grub_uint8_t) n;
					continue;
				}
				if (pos >= data->strings_chars)
					return 0;
				n = (n & 0x7f) | ((data->header[data->strings_pos + pos++] & 0x7f) << 7);
				if (c == code_var)
				{
					var = nsis_var_name (n);
					if (!var || !nsis_append (raw, &len, var))
					{
						grub_free (var);
						return 0;
					}
					grub_free (var);
				}
				else
				{
					char special[24];

					grub_snprintf (special, sizeof (special), "$SHELL%u", n);
					if (!nsis_append (raw, &len, special))
						return 0;
				}
			}
			else
				raw[len++] = (grub_uint8_t) c;
		}
	}
	if (pos >= data->strings_chars)
	{
		int nul_terminated;
		if (data->unicode)
		{
			const grub_uint8_t *last = data->header + data->strings_pos + (data->strings_chars - 1) * 2;
			nul_terminated = nsis_get16 (last) == 0;
		}
		else
			nul_terminated = data->header[data->strings_pos + data->strings_chars - 1] == 0;
		if (!nul_terminated)
			return 0;
	}
	raw[len] = 0;
	if (data->unicode)
		return grub_strdup ((const char *) raw);
	converted = grub_fs_bytes_to_utf8 ((const char *) raw, len, grub_fs_char_encoding);
	return converted;
}

static char *
nsis_normalize (const char *prefix, const char *name)
{
	char *joined;
	char *out;
	char *dst;
	const char *src;
	grub_size_t plen = prefix ? grub_strlen (prefix) : 0;
	grub_size_t nlen = grub_strlen (name);
	int absolute;

	absolute = name[0] == '/' || name[0] == '\\' || (name[0] && name[1] == ':') || name[0] == '$';
	joined = grub_malloc (plen + nlen + 2);
	if (!joined)
		return 0;
	joined[0] = 0;
	if (!absolute && plen)
	{
		grub_memcpy (joined, prefix, plen);
		joined[plen] = '/';
		grub_memcpy (joined + plen + 1, name, nlen + 1);
	}
	else
		grub_memcpy (joined, name, nlen + 1);
	for (dst = joined; *dst; dst++)
		if (*dst == '\\')
			*dst = '/';
	src = joined;
	if (grub_strncasecmp (src, "$INSTDIR", 8) == 0 && (src[8] == 0 || src[8] == '/'))
		src += src[8] ? 9 : 8;
	while (*src == '/')
		src++;
	if (src[0] && src[1] == ':')
		src += 2;
	while (*src == '/')
		src++;

	out = grub_malloc (grub_strlen (src) + 1);
	if (!out)
	{
		grub_free (joined);
		return 0;
	}
	dst = out;
	while (*src)
	{
		const char *component = src;
		grub_size_t len;

		while (*src && *src != '/')
			src++;
		len = (grub_size_t) (src - component);
		while (*src == '/')
			src++;
		if (len == 0 || (len == 1 && component[0] == '.'))
			continue;
		if (len == 2 && component[0] == '.' && component[1] == '.')
		{
			grub_error (GRUB_ERR_BAD_FS, "unsafe path in nsis archive");
			grub_free (joined);
			grub_free (out);
			return 0;
		}
		if (dst != out)
			*dst++ = '/';
		grub_memcpy (dst, component, len);
		dst += len;
	}
	*dst = 0;
	grub_free (joined);
	if (dst == out)
	{
		grub_free (out);
		return 0;
	}
	return out;
}

static struct nsis_item *
nsis_add_item (struct grub_nsis_data *data, char *name)
{
	struct nsis_item *item;

	if (data->num_items == data->max_items)
	{
		unsigned cap = data->max_items ? data->max_items * 2 : 64;
		struct nsis_item *items;

		if (cap > NSIS_ITEMS_MAX)
		{
			grub_error (GRUB_ERR_BAD_FS, "too many files in nsis archive");
			grub_free (name);
			return 0;
		}
		items = grub_realloc (data->items, cap * sizeof (*items));
		if (!items)
		{
			grub_free (name);
			return 0;
		}
		data->items = items;
		data->max_items = cap;
	}
	item = &data->items[data->num_items++];
	grub_memset (item, 0, sizeof (*item));
	item->name = name;
	return item;
}

static void
nsis_detect_type (struct grub_nsis_data *data)
{
	grub_uint32_t i;
	const grub_uint8_t *strings = data->header + data->strings_pos;

	data->type = NSIS_TYPE_2;
	if (data->unicode)
	{
		data->type = NSIS_TYPE_PARK;
		for (i = 0; i + 2 < data->strings_chars; i++)
			if (nsis_get16 (strings + i * 2) == 0
				&& nsis_get16 (strings + (i + 1) * 2) == 3
				&& (nsis_get16 (strings + (i + 2) * 2)
				& 0x8080) == 0x8080)
			{
				data->type = NSIS_TYPE_3;
				break;
			}
	}
	else
		for (i = 0; i + 2 < data->strings_chars; i++)
			if (strings[i] == 0 && strings[i + 1] == 3 && (strings[i + 2] & 0x80))
			{
				data->type = NSIS_TYPE_3;
				break;
			}
}

static grub_int64_t
nsis_filetime (grub_uint32_t low, grub_uint32_t high)
{
	grub_uint64_t value = ((grub_uint64_t) high << 32) | low;
	const grub_uint64_t epoch = 116444736000000000ULL;

	if (high <= 0x01000000 || high >= 0xff000000 || value < epoch)
		return 0;
	return (grub_int64_t) ((value - epoch) / 10000000ULL);
}

static grub_err_t
nsis_parse_header (struct grub_nsis_data *data)
{
	grub_uint32_t entries_off, entries_num;
	grub_uint32_t strings_off, lang_off;
	unsigned bho;
	grub_uint32_t i;
	char *prefix = 0;

	if (data->header_size < 4 + 8 * 8)
		return grub_error (GRUB_ERR_BAD_FS, "short nsis header");
	bho = 8;
	if (data->header_size >= 4 + 12 * 8)
	{
		bho = 12;
		for (i = 0; i < 8; i++)
			if (nsis_get32 (data->header + 4 + i * 12 + 4) != 0)
			{
				bho = 8;
				break;
			}
	}
	entries_off = nsis_get32 (data->header + 4 + 2 * bho);
	entries_num = nsis_get32 (data->header + 4 + 2 * bho + bho - 4);
	strings_off = nsis_get32 (data->header + 4 + 3 * bho);
	lang_off = nsis_get32 (data->header + 4 + 4 * bho);
	if (entries_num > NSIS_ITEMS_MAX
		|| entries_off > data->header_size
		|| (grub_uint64_t) entries_num * NSIS_CMD_SIZE > data->header_size - entries_off
		|| strings_off > lang_off || lang_off > data->header_size
		|| lang_off - strings_off < 2)
		return grub_error (GRUB_ERR_BAD_FS, "corrupt nsis header tables");
	data->strings_pos = strings_off;
	data->unicode = nsis_get16 (data->header + strings_off) == 0;
	if (data->unicode)
	{
		if (((lang_off - strings_off) & 1) || nsis_get16 (data->header + lang_off - 2) != 0)
			return grub_error (GRUB_ERR_BAD_FS, "corrupt nsis string table");
		data->strings_chars = (lang_off - strings_off) / 2;
	}
	else
	{
		if (data->header[lang_off - 1] != 0)
			return grub_error (GRUB_ERR_BAD_FS, "corrupt nsis string table");
		data->strings_chars = lang_off - strings_off;
	}
	nsis_detect_type (data);
	prefix = grub_strdup ("");
	if (!prefix)
		return grub_errno;

	for (i = 0; i < entries_num; i++)
	{
		const grub_uint8_t *cmd = data->header + entries_off + (grub_size_t) i * NSIS_CMD_SIZE;
		grub_uint32_t id = nsis_get32 (cmd);
		grub_uint32_t param0 = nsis_get32 (cmd + 4);
		grub_uint32_t param1 = nsis_get32 (cmd + 8);

		if (id == NSIS_CMD_CREATEDIR && param1 != 0)
		{
			char *raw = nsis_decode_string (data, param0);
			char *name;

			if (!raw)
				goto fail;
			name = nsis_normalize (0, raw);
			grub_free (raw);
			if (!name)
			{
				if (grub_errno)
					goto fail;
				name = grub_strdup ("");
				if (!name)
					goto fail;
			}
			grub_free (prefix);
			prefix = name;
		}
		else if (id == NSIS_CMD_EXTRACTFILE)
		{
			char *raw = nsis_decode_string (data, param1);
			char *name;
			struct nsis_item *item;

			if (!raw)
				goto fail;
			name = nsis_normalize (prefix, raw);
			grub_free (raw);
			if (!name)
			{
				if (grub_errno)
					goto fail;
				continue;
			}
			item = nsis_add_item (data, name);
			if (!item)
				goto fail;
			item->pos = nsis_get32 (cmd + 12);
			item->mtime = nsis_filetime (nsis_get32 (cmd + 16), nsis_get32 (cmd + 20));
		}
	}
	grub_free (prefix);

	if (data->solid)
	{
		int ordered = 1;

		for (i = 1; i < data->num_items; i++)
			if (data->items[i].pos <= data->items[i - 1].pos)
			{
				ordered = 0;
				break;
			}
		if (ordered)
			for (i = 0; i + 1 < data->num_items; i++)
				if ((grub_uint64_t) data->items[i + 1].pos >= (grub_uint64_t) data->items[i].pos + 4)
				{
					data->items[i].estimated_size = data->items[i + 1].pos - data->items[i].pos - 4;
					data->items[i].estimated_size_set = 1;
				}
	}
	else
		for (i = 0; i < data->num_items; i++)
		{
			grub_uint64_t marker_pos = data->data_pos + 4 + data->non_solid_start + data->items[i].pos;
			grub_uint8_t marker_buf[4];
			grub_uint32_t marker;

			if (!nsis_range (marker_pos, sizeof (marker_buf), data->packed_end)
				|| !nsis_read (data, marker_pos, marker_buf, sizeof (marker_buf)))
				goto fail;
			marker = nsis_get32 (marker_buf);
			if ((marker & NSIS_COMPRESSED) == 0)
			{
				data->items[i].estimated_size = marker;
				data->items[i].estimated_size_set = 1;
			}
		}
	return GRUB_ERR_NONE;

fail:
	grub_free (prefix);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

static struct grub_nsis_data *
grub_nsis_mount (grub_disk_t disk)
{
	struct grub_nsis_data *data;
	grub_uint8_t first[NSIS_FIRST_HEADER_SIZE + 16];
	grub_uint64_t scan_end;
	grub_uint64_t pos;
	grub_uint32_t marker;
	struct nsis_sink sink;
	int crc;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return 0;
	data->disk = disk;
	data->disk_size = grub_disk_native_sectors (disk);
	if (data->disk_size == GRUB_DISK_SIZE_UNKNOWN
		|| data->disk_size > (GRUB_DISK_SIZE_UNKNOWN >> GRUB_DISK_SECTOR_BITS))
		data->disk_size = GRUB_DISK_SIZE_UNKNOWN;
	else
		data->disk_size <<= GRUB_DISK_SECTOR_BITS;
	if (data->disk_size < NSIS_FIRST_HEADER_SIZE)
		goto not_nsis;
	scan_end = data->disk_size < NSIS_SCAN_LIMIT ? data->disk_size : NSIS_SCAN_LIMIT;
	for (pos = 0; pos + NSIS_FIRST_HEADER_SIZE <= scan_end; pos += 512)
	{
		if (!nsis_read (data, pos, first, NSIS_FIRST_HEADER_SIZE))
			goto fail;
		if (grub_memcmp (first + 4, nsis_signature, NSIS_SIGNATURE_SIZE) == 0)
			break;
	}
	if (pos + NSIS_FIRST_HEADER_SIZE > scan_end)
		goto not_nsis;
	data->archive_pos = pos;
	data->flags = nsis_get32 (first);
	data->header_size = nsis_get32 (first + 20);
	data->archive_size = nsis_get32 (first + 24);
	if ((data->flags & ~NSIS_FLAGS_MASK) != 0
		|| data->header_size == 0 || data->header_size > NSIS_HEADER_MAX
		|| data->archive_size <= NSIS_FIRST_HEADER_SIZE
		|| !nsis_range (pos, data->archive_size, data->disk_size))
		goto not_nsis;
	data->data_pos = pos + NSIS_FIRST_HEADER_SIZE;
	crc = (data->flags & NSIS_FLAG_FORCE_CRC) || !(data->flags & NSIS_FLAG_NO_CRC);
	data->packed_end = pos + data->archive_size - (crc ? 4 : 0);
	if (data->packed_end < data->data_pos
		|| !nsis_range (data->data_pos, sizeof (first), data->packed_end)
		|| !nsis_read (data, data->data_pos, first, sizeof (first)))
		goto fail;
	marker = nsis_get32 (first);
	if (marker == data->header_size)
	{
		data->solid = 0;
		data->method = NSIS_METHOD_COPY;
		data->non_solid_start = marker;
		if (!nsis_range (data->data_pos + 4, data->non_solid_start, data->packed_end))
			goto not_nsis;
		data->header = grub_malloc (data->header_size);
		if (!data->header)
			goto fail;
		if (!nsis_read (data, data->data_pos + 4, data->header, data->header_size))
			goto fail;
	}
	else if (!nsis_is_lzma (first, sizeof (first), &data->filter_flag) && first[3] == 0x80)
	{
		data->solid = 0;
		data->non_solid_start = marker & ~NSIS_COMPRESSED;
		if (!nsis_range (data->data_pos + 4, data->non_solid_start, data->packed_end))
			goto not_nsis;
		data->method = nsis_detect_method (first + 4, sizeof (first) - 4, &data->filter_flag);
		if ((marker & NSIS_COMPRESSED) == 0)
		{
			if (data->non_solid_start != data->header_size)
				goto not_nsis;
			data->header = grub_malloc (data->header_size);
			if (!data->header
				|| !nsis_read (data, data->data_pos + 4, data->header, data->header_size))
				goto fail;
		}
		else
		{
			grub_memset (&sink, 0, sizeof (sink));
			sink.target = data->header_size;
			if (!nsis_decode (data, data->data_pos + 4, data->non_solid_start,
				data->method, data->filter_flag, &sink))
			{
				grub_free (sink.buf);
				goto fail;
			}
			data->header = sink.buf;
		}
	}
	else
	{
		data->solid = 1;
		data->method = nsis_detect_method (first, sizeof (first), &data->filter_flag);
		grub_memset (&sink, 0, sizeof (sink));
		sink.target = (grub_size_t) data->header_size + 4;
		if (!nsis_decode (data, data->data_pos, data->packed_end - data->data_pos,
			data->method, data->filter_flag, &sink))
		{
			grub_free (sink.buf);
			goto fail;
		}
		if (sink.size != (grub_size_t) data->header_size + 4
			|| nsis_get32 (sink.buf) != data->header_size)
		{
			grub_free (sink.buf);
			goto not_nsis;
		}
		data->header = grub_malloc (data->header_size);
		if (!data->header)
		{
			grub_free (sink.buf);
			goto fail;
		}
		grub_memcpy (data->header, sink.buf + 4, data->header_size);
		grub_free (sink.buf);
	}
	if (nsis_parse_header (data))
		goto fail;
	return data;

not_nsis:
	grub_error (GRUB_ERR_BAD_FS, "not an nsis archive");
fail:
	nsis_free_data (data);
	return 0;
}

static const char *
nsis_norm_path (const char *path, grub_size_t *len)
{
	while (*path == '/')
		path++;
	*len = grub_strlen (path);
	while (*len && path[*len - 1] == '/')
		(*len)--;
	return path;
}

static int
nsis_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
	const char **child, grub_size_t *child_len, int *is_dir)
{
	const char *rest;
	const char *slash;

	if (dir_len)
	{
		if (grub_strncmp (name, dir, dir_len) != 0 || name[dir_len] != '/')
			return 0;
		rest = name + dir_len + 1;
	}
	else
		rest = name;
	if (*rest == 0)
		return 0;
	slash = grub_strchr (rest, '/');
	*child = rest;
	*child_len = slash ? (grub_size_t) (slash - rest) : grub_strlen (rest);
	*is_dir = slash != 0;
	return *child_len != 0;
}

struct nsis_seen
{
	struct nsis_seen *next;
	char *name;
};

static grub_uint32_t
nsis_hash (const char *name)
{
	grub_uint32_t hash = 5381;

	while (*name)
		hash = hash * 33 + (grub_uint8_t) *name++;
	return hash & (NSIS_SEEN_BUCKETS - 1);
}

static int
nsis_seen_add (struct nsis_seen **buckets, char *name)
{
	grub_uint32_t hash = nsis_hash (name);
	struct nsis_seen *entry;

	for (entry = buckets[hash]; entry; entry = entry->next)
		if (grub_strcmp (entry->name, name) == 0)
			return 1;
	entry = grub_malloc (sizeof (*entry));
	if (!entry)
		return -1;
	entry->name = name;
	entry->next = buckets[hash];
	buckets[hash] = entry;
	return 0;
}

static grub_err_t
grub_nsis_dir (grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_nsis_data *data;
	struct nsis_seen **buckets;
	const char *dir;
	grub_size_t dir_len;
	grub_err_t err = GRUB_ERR_NONE;
	unsigned i;
	int found;

	data = grub_nsis_mount (device->disk);
	if (!data)
		return grub_errno;
	dir = nsis_norm_path (path, &dir_len);
	found = dir_len == 0;
	buckets = grub_calloc (NSIS_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		nsis_free_data (data);
		return grub_errno;
	}
	for (i = 0; i < data->num_items; i++)
	{
		struct grub_dirhook_info info;
		const char *child;
		grub_size_t child_len;
		int child_is_dir;
		char *name;
		int dup;

		if (!nsis_name_in_dir (data->items[i].name, dir, dir_len, &child, &child_len, &child_is_dir))
		{
			if (dir_len && grub_strcmp (data->items[i].name, dir) == 0)
				found = 1;
			continue;
		}
		found = 1;
		name = grub_malloc (child_len + 1);
		if (!name)
		{
			err = grub_errno;
			goto out;
		}
		grub_memcpy (name, child, child_len);
		name[child_len] = 0;
		dup = nsis_seen_add (buckets, name);
		if (dup)
		{
			grub_free (name);
			if (dup < 0)
			{
				err = grub_errno;
				goto out;
			}
			continue;
		}
		grub_memset (&info, 0, sizeof (info));
		info.dir = child_is_dir;
		info.inodeset = 1;
		info.inode = i;
		if (!child_is_dir && data->items[i].estimated_size_set)
		{
			info.sizeset = 1;
			info.size = data->items[i].estimated_size;
		}
		if (!child_is_dir && data->items[i].mtime)
		{
			info.mtimeset = 1;
			info.mtime = data->items[i].mtime;
		}
		if (hook (name, &info, hook_data))
			goto out;
	}
	if (!found)
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);

out:
	for (i = 0; i < NSIS_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct nsis_seen *entry = buckets[i];

			buckets[i] = entry->next;
			grub_free (entry->name);
			grub_free (entry);
		}
	grub_free (buckets);
	nsis_free_data (data);
	return err;
}

static int
nsis_find_item (struct grub_nsis_data *data, const char *name)
{
	grub_size_t len;
	const char *path = nsis_norm_path (name, &len);
	unsigned i;

	for (i = 0; i < data->num_items; i++)
		if (grub_strlen (data->items[i].name) == len
			&& grub_strncmp (data->items[i].name, path, len) == 0)
			return (int) i;
	return -1;
}

static grub_err_t
grub_nsis_open (grub_file_t file, const char *name)
{
	struct grub_nsis_data *data;
	struct grub_nsis_file *ctx;
	struct nsis_item *item;
	struct nsis_sink sink;
	grub_uint64_t marker_pos;
	grub_uint8_t marker_buf[4];
	grub_uint32_t marker;
	int index;

	data = grub_nsis_mount (file->device->disk);
	if (!data)
		return grub_errno;
	index = nsis_find_item (data, name);
	if (index < 0)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", name);
		goto fail;
	}
	item = &data->items[index];
	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
		goto fail;
	ctx->data = data;
	ctx->index = (unsigned) index;
	grub_memset (&sink, 0, sizeof (sink));
	if (data->solid)
	{
		grub_uint64_t skip = (grub_uint64_t) data->header_size + 4 + item->pos;

		if (skip > GRUB_SIZE_MAX)
		{
			grub_error (GRUB_ERR_BAD_FS, "nsis solid offset is too large");
			goto fail_ctx;
		}
		sink.skip = (grub_size_t) skip;
		sink.size_prefix = 1;
		if (!nsis_decode (data, data->data_pos, data->packed_end - data->data_pos,
			data->method, data->filter_flag, &sink))
			goto fail_ctx;
		ctx->buf = sink.buf;
		ctx->size = (grub_uint32_t) sink.size;
	}
	else
	{
		marker_pos = data->data_pos + 4 + data->non_solid_start + item->pos;
		if (!nsis_range (marker_pos, sizeof (marker_buf), data->packed_end)
			|| !nsis_read (data, marker_pos, marker_buf, sizeof (marker_buf)))
			goto fail_ctx;
		marker = nsis_get32 (marker_buf);
		if ((marker & NSIS_COMPRESSED) == 0)
		{
			if (marker > NSIS_FILE_MAX)
			{
				grub_error (GRUB_ERR_BAD_FS, "nsis file is too large");
				goto fail_ctx;
			}
			if (!nsis_range (marker_pos + 4, marker, data->packed_end))
				goto fail_ctx;
			ctx->raw = 1;
			ctx->raw_pos = marker_pos + 4;
			ctx->size = marker;
		}
		else
		{
			marker &= ~NSIS_COMPRESSED;
			if (!nsis_range (marker_pos + 4, marker, data->packed_end))
				goto fail_ctx;
			sink.dynamic = 1;
			if (!nsis_decode (data, marker_pos + 4, marker, data->method, data->filter_flag, &sink))
				goto fail_ctx;
			ctx->buf = sink.buf;
			ctx->size = (grub_uint32_t) sink.size;
		}
	}
	file->data = ctx;
	file->size = ctx->size;
	return GRUB_ERR_NONE;

fail_ctx:
	grub_free (sink.buf);
	grub_free (ctx);
fail:
	nsis_free_data (data);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

static grub_ssize_t
grub_nsis_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_nsis_file *ctx = file->data;
	grub_uint64_t left;

	if ((grub_uint64_t) file->offset >= ctx->size)
		return 0;
	left = ctx->size - file->offset;
	if (len > left)
		len = (grub_size_t) left;
	if (ctx->raw)
	{
		if (grub_disk_read (ctx->data->disk, 0, ctx->raw_pos + file->offset, len, buf))
			return -1;
	}
	else
		grub_memcpy (buf, ctx->buf + file->offset, len);
	return (grub_ssize_t) len;
}

static grub_err_t
grub_nsis_close (grub_file_t file)
{
	struct grub_nsis_file *ctx = file->data;

	if (ctx)
	{
		nsis_free_data (ctx->data);
		grub_free (ctx->buf);
		grub_free (ctx);
		file->data = 0;
	}
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_nsis_fs =
{
	.name = "nsis",
	.fs_dir = grub_nsis_dir,
	.fs_open = grub_nsis_open,
	.fs_read = grub_nsis_read,
	.fs_close = grub_nsis_close,
	.fs_label = 0,
	.next = 0
};

GRUB_MOD_INIT (nsis)
{
	grub_nsis_fs.mod = mod;
	grub_fs_register (&grub_nsis_fs);
}

GRUB_MOD_FINI (nsis)
{
	grub_fs_unregister (&grub_nsis_fs);
}
