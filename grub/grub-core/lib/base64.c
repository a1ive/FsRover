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
 * Minimal Base64 decoder (RFC 4648) used by luks2.c.  Whole-buffer
 * decoding only; the ctx argument is always NULL in that caller.
 */

#include <grub/types.h>
#include <grub/misc.h>

#include "base64.h"

static signed char
b64_value (char c)
{
	if (c >= 'A' && c <= 'Z')
		return (signed char) (c - 'A');
	if (c >= 'a' && c <= 'z')
		return (signed char) (c - 'a' + 26);
	if (c >= '0' && c <= '9')
		return (signed char) (c - '0' + 52);
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

bool
isbase64 (char ch)
{
	return b64_value (ch) >= 0;
}

bool
base64_decode_ctx (struct base64_decode_context *ctx,
		   const char *in, idx_t inlen,
		   char *out, idx_t *outlen)
{
	idx_t avail = *outlen;
	idx_t produced = 0;

	/* Only whole-buffer decoding (NULL context) is supported.  */
	(void) ctx;

	while (inlen >= 2)
	{
		signed char v0 = b64_value (in[0]);
		signed char v1 = b64_value (in[1]);

		if (v0 < 0 || v1 < 0)
			return false;

		if (produced >= avail)
			return false;
		out[produced++] = (char) ((v0 << 2) | (v1 >> 4));

		if (inlen == 2 || in[2] == '=')
			break;

		{
			signed char v2 = b64_value (in[2]);

			if (v2 < 0)
				return false;
			if (produced >= avail)
				return false;
			out[produced++] = (char) ((v1 << 4) | (v2 >> 2));

			if (inlen == 3 || in[3] == '=')
				break;

			{
				signed char v3 = b64_value (in[3]);

				if (v3 < 0)
					return false;
				if (produced >= avail)
					return false;
				out[produced++] = (char) ((v2 << 6) | v3);
			}
		}

		in += 4;
		inlen -= 4;
	}

	/* A lone trailing character cannot be valid base64.  */
	if (inlen == 1)
		return false;

	*outlen = produced;
	return true;
}
