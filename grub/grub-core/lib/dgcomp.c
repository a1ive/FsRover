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
 * The two codecs a DiskGenius .pmf / .pmfx backup stores its blocks
 * with.  The default setting deflates them; the faster one uses a
 * byte-oriented LZ77 of its own:
 *
 *	The stream opens with a literal run, its length in the low five
 *	bits of the first byte (plus one).  After that every operation
 *	is one token byte, h = token >> 5 and l = token & 0x1f:
 *
 *	  h == 0	a run of l + 1 literals
 *	  h == 7	a match of 9 + e bytes, e being the next byte and
 *			every further byte while the last one was 0xff
 *	  otherwise	a match of h + 2 bytes
 *
 *	A match then reads one more byte for its distance, (l << 8) |
 *	byte, plus one.  The largest such distance, 0x1fff, means a
 *	16-bit big-endian extension follows and adds to it.  Matches may
 *	overlap the bytes they produce, which is how runs are coded.
 *
 * A block whose stored length equals its plaintext length was written
 * verbatim, which is how both containers spell an incompressible block.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dgcomp.h>

#include <miniz.h>

/* Marks a match whose distance carries a big-endian 16-bit extension.  */
#define DGCOMP_LZ_DIST_MAX	0x1fff
/* A deflate stream with a 32 KiB window, the only CMF DiskGenius emits;
   no first byte of an LZ77 stream can look like one.  */
#define DGCOMP_ZLIB_CMF		0x78

grub_err_t
grub_dgcomp_lz (const grub_uint8_t *in, grub_size_t in_len, grub_uint8_t *out, grub_size_t out_len)
{
	grub_size_t ip = 0, op = 0;
	grub_uint32_t n;

	if (in_len == 0)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "empty DiskGenius block");

	n = (grub_uint32_t) (in[ip++] & 0x1f) + 1;
	if (n > in_len - ip || n > out_len)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "truncated DiskGenius block");
	grub_memcpy (out, in + ip, n);
	ip += n;
	op = n;

	while (op < out_len)
	{
		grub_uint32_t t, h, l, len, dist, i;

		if (ip >= in_len)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "truncated DiskGenius block");
		t = in[ip++];
		h = t >> 5;
		l = t & 0x1f;

		if (h == 0)
		{
			len = l + 1;
			if (len > in_len - ip || len > out_len - op)
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad DiskGenius literal run");
			grub_memcpy (out + op, in + ip, len);
			ip += len;
			op += len;
			continue;
		}

		if (h == 7)
		{
			grub_uint32_t e;

			if (ip >= in_len)
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "truncated DiskGenius block");
			e = in[ip++];
			len = 9 + e;
			while (e == 0xff)
			{
				if (ip >= in_len || len > out_len)
					return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad DiskGenius match length");
				e = in[ip++];
				len += e;
			}
		}
		else
			len = h + 2;

		if (ip >= in_len)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "truncated DiskGenius block");
		dist = (l << 8) | in[ip++];
		if (dist == DGCOMP_LZ_DIST_MAX)
		{
			if (in_len - ip < 2)
				return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "truncated DiskGenius block");
			dist += ((grub_uint32_t) in[ip] << 8) | in[ip + 1];
			ip += 2;
		}
		dist++;

		if (dist > op || len > out_len - op)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad DiskGenius match");
		/* A match may reach into the bytes it is producing, so it has
		   to be copied one byte at a time.  */
		for (i = 0; i < len; i++)
			out[op + i] = out[op - dist + i];
		op += len;
	}

	return GRUB_ERR_NONE;
}

static grub_err_t
dgcomp_zlib (const grub_uint8_t *in, grub_size_t in_len, grub_uint8_t *out, grub_size_t out_len)
{
	tinfl_decompressor *dec;
	grub_size_t in_size = in_len, out_size = out_len;
	tinfl_status st;

	dec = grub_malloc (sizeof (*dec));
	if (!dec)
		return grub_errno;
	tinfl_init (dec);
	st = tinfl_decompress (dec, in, &in_size, out, out, &out_size,
		TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
	grub_free (dec);
	if (st != TINFL_STATUS_DONE || out_size != out_len)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "bad DiskGenius zlib block");
	return GRUB_ERR_NONE;
}

grub_err_t
grub_dgcomp_block (const grub_uint8_t *in, grub_size_t in_len, grub_uint8_t *out, grub_size_t out_len)
{
	if (in_len == out_len)
	{
		grub_memcpy (out, in, out_len);
		return GRUB_ERR_NONE;
	}
	if (in_len >= 2 && in[0] == DGCOMP_ZLIB_CMF)
		return dgcomp_zlib (in, in_len, out, out_len);
	return grub_dgcomp_lz (in, in_len, out, out_len);
}
