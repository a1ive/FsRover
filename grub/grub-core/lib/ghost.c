/* ghost.c - Ghost block decoding, shared by io\gho.c and fs\gho.c */
/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  The Fast LZ token stream follows <https://github.com/nyarime/gho> (MIT),
 *  reverse engineered from Norton Ghost 11.5.1.
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
#include <grub/misc.h>
#include <grub/err.h>
#include <grub/deflate.h>
#include <grub/ghost.h>

/* Bytes of block header in front of a Fast LZ token stream.  */
#define GHO_FASTLZ_SKIP		4

/* Ghost primes its hash table with pointers into this literal, so a
   match against a slot that was never filled reproduces it.  Matches
   copy at most 3 + 15 bytes, which is exactly its length.  */
static const char gho_fastlz_seed[] = "123456789012345678";

static grub_uint32_t
gho_fastlz_hash (grub_uint8_t b0, grub_uint8_t b1, grub_uint8_t b2)
{
	grub_uint32_t v;

	v = (grub_uint32_t) b2 ^ (((grub_uint32_t) b1 ^ ((grub_uint32_t) b0 << 4)) << 4);
	/* 0xffff9e5f is -24993 taken modulo 2^32.  */
	return ((0xffff9e5fu * v) >> 4) & 0xfff;
}

/*
 * Control words are 16 bit and are consumed low bit first: a clear bit
 * copies one literal, a set bit takes a two byte match token holding a
 * hash slot and the length beyond the three byte minimum.  The slot is
 * then repointed at the freshly emitted run, which is what makes the
 * decoder rebuild the encoder's table as it goes.
 */
static grub_err_t
gho_fastlz (grub_int32_t *hash, const grub_uint8_t *src, grub_size_t srclen,
	grub_uint8_t *dst, grub_size_t dstcap, grub_size_t *outlen)
{
	grub_size_t sp = 0;
	grub_size_t out = 0;
	grub_uint32_t ctrl = 1;
	unsigned lit = 0;
	unsigned prev_lit = 0;
	unsigned i;

	for (i = 0; i < GRUB_GHOST_FASTLZ_HASH_SIZE; i++)
		hash[i] = -1;

	while (sp < srclen)
	{
		unsigned tokens;
		unsigned t;

		if (ctrl == 1)
		{
			if (srclen - sp < 2)
				break;
			ctrl = (grub_uint32_t) src[sp] | ((grub_uint32_t) src[sp + 1] << 8) | 0x10000;
			sp += 2;
		}

		/* The encoder stops filling whole control words near the
		   end of the block, so only trust one token there.  */
		tokens = (srclen - sp < 32) ? 1 : 16;
		for (t = 0; t < tokens; t++)
		{
			if (sp >= srclen)
				break;

			if (ctrl & 1)
			{
				grub_size_t start = out;
				grub_uint32_t idx;
				grub_uint32_t total;
				grub_uint32_t j;
				grub_int32_t match;

				if (srclen - sp < 2)
					goto done;
				idx = (grub_uint32_t) src[sp + 1] | (((grub_uint32_t) src[sp] & 0xf0) << 4);
				total = 3 + (src[sp] & 0x0f);
				match = hash[idx];
				sp += 2;

				if (total > dstcap - out)
					return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "overlong match in Ghost block");
				for (j = 0; j < total; j++)
				{
					if (match < 0)
						dst[out] = (grub_uint8_t) gho_fastlz_seed[j];
					else
					{
						grub_size_t from = (grub_size_t) match + j;

						dst[out] = (from < out) ? dst[from] : 0;
					}
					out++;
				}

				/* Literals only enter the table once the run
				   they belong to is closed by a match.  */
				if (lit > 0 && start >= lit)
				{
					grub_size_t pos = start - lit;

					if (pos + 2 < out)
					{
						hash[gho_fastlz_hash (dst[pos], dst[pos + 1], dst[pos + 2])] = (grub_int32_t) pos;
						if (prev_lit == 2 && pos + 3 < out)
							hash[gho_fastlz_hash (dst[pos + 1], dst[pos + 2], dst[pos + 3])] = (grub_int32_t) (pos + 1);
					}
				}
				if (lit > 0)
				{
					lit = 0;
					prev_lit = 0;
				}
				hash[idx] = (grub_int32_t) start;
			}
			else
			{
				if (out >= dstcap)
					return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "overlong Ghost block");
				dst[out++] = src[sp++];
				lit++;
				prev_lit = lit;
				if (lit == 3)
				{
					grub_size_t pos = out - 3;

					hash[gho_fastlz_hash (dst[pos], dst[pos + 1], dst[pos + 2])] = (grub_int32_t) pos;
					lit = 2;
					prev_lit = 2;
				}
			}

			ctrl >>= 1;
			if (ctrl == 1)
				break;
		}
	}

done:
	*outlen = out;
	return GRUB_ERR_NONE;
}

grub_err_t
grub_ghost_decode (grub_uint8_t comp, grub_int32_t *hash,
	const grub_uint8_t *src, grub_size_t clen,
	grub_uint8_t *dst, grub_size_t dstcap, grub_size_t *outlen)
{
	grub_ssize_t n;

	if (clen < 2)
		return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "empty Ghost block");

	/* Incompressible blocks are escaped with a four byte header.  No
	   compressor emits a stream starting like that.  */
	if (clen > 4 && src[0] == 1 && src[1] == 0 && src[2] == 0 && src[3] == 0)
	{
		if (clen - 4 > dstcap)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "overlong Ghost block");
		grub_memcpy (dst, src + 4, clen - 4);
		*outlen = clen - 4;
		return GRUB_ERR_NONE;
	}

	switch (comp)
	{
	case GRUB_GHOST_COMP_NONE:
		if (clen > dstcap)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "overlong Ghost block");
		grub_memcpy (dst, src, clen);
		*outlen = clen;
		return GRUB_ERR_NONE;

	case GRUB_GHOST_COMP_FAST:
		if (clen <= GHO_FASTLZ_SKIP)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "short Fast LZ block");
		return gho_fastlz (hash, src + GHO_FASTLZ_SKIP, clen - GHO_FASTLZ_SKIP, dst, dstcap, outlen);

	default:
		n = grub_zlib_decompress ((char *) src, clen, 0, (char *) dst, dstcap);
		if (n < 0)
			return grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "corrupt zlib block in Ghost image");
		*outlen = (grub_size_t) n;
		return GRUB_ERR_NONE;
	}
}
