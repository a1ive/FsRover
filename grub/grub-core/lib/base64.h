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
 * Minimal Base64 decoder for luks2.c.  gnulib's base64.h pulls in
 * <idx.h>/<ialloc.h>/<intprops.h> which are not part of the Rover grub
 * import, and LUKS2 only ever decodes, so this provides just the decode
 * side with a gnulib-compatible signature (the base64_decode() macro
 * with a NULL context decodes a whole buffer).
 */

#ifndef GRUB_BASE64_HEADER
#define GRUB_BASE64_HEADER	1

#include <grub/types.h>

/* gnulib names its length type idx_t (a signed size type).  */
typedef grub_ssize_t idx_t;

struct base64_decode_context
{
  int i;
  char buf[4];
};

bool isbase64 (char ch);

/*
 * Decode the base64 data IN (INLEN bytes) into OUT.  On entry *OUTLEN
 * is the size of OUT; on success it is set to the number of decoded
 * bytes and true is returned.  CTX must be NULL (whole-buffer decode,
 * the only mode luks2.c uses).
 */
bool base64_decode_ctx (struct base64_decode_context *ctx,
			const char *in, idx_t inlen,
			char *out, idx_t *outlen);

#define base64_decode(in, inlen, out, outlen) \
	base64_decode_ctx (NULL, in, inlen, out, outlen)

#endif /* ! GRUB_BASE64_HEADER */
