/* sha512.c - SHA-384 and SHA-512 hash functions
 * Copyright (C) 2003, 2008, 2009 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Self-contained SHA-512/384 for Rover, styled after this project's
 * gcry_sha256.c (single file, gcry_wrap.h shim, no libgcrypt internal
 * headers).  Fills _gcry_digest_spec_sha512 / _sha384 for the crypto.c
 * registry (LUKS PBKDF2/HMAC and AF-splitter use these).  FIPS 180-4.
 */

#include <grub/types.h>
#include <grub/crypto.h>
#include <grub/misc.h>
#include "gcry_wrap.h"

#pragma warning(disable:4244)

#define ror64(x,n) ( ((u64)(x) >> (n)) | ((u64)(x) << (64 - (n))) )

typedef struct
{
	u64  h0, h1, h2, h3, h4, h5, h6, h7;
	u64  nblocks;
	byte buf[128];
	int  count;
} SHA512_CONTEXT;

static void
sha512_init(void* context, unsigned int flags)
{
	SHA512_CONTEXT* hd = context;

	(void)flags;

	hd->h0 = 0x6a09e667f3bcc908ULL;
	hd->h1 = 0xbb67ae8584caa73bULL;
	hd->h2 = 0x3c6ef372fe94f82bULL;
	hd->h3 = 0xa54ff53a5f1d36f1ULL;
	hd->h4 = 0x510e527fade682d1ULL;
	hd->h5 = 0x9b05688c2b3e6c1fULL;
	hd->h6 = 0x1f83d9abfb41bd6bULL;
	hd->h7 = 0x5be0cd19137e2179ULL;

	hd->nblocks = 0;
	hd->count = 0;
}

static void
sha384_init(void* context, unsigned int flags)
{
	SHA512_CONTEXT* hd = context;

	(void)flags;

	hd->h0 = 0xcbbb9d5dc1059ed8ULL;
	hd->h1 = 0x629a292a367cd507ULL;
	hd->h2 = 0x9159015a3070dd17ULL;
	hd->h3 = 0x152fecd8f70e5939ULL;
	hd->h4 = 0x67332667ffc00b31ULL;
	hd->h5 = 0x8eb44a8768581511ULL;
	hd->h6 = 0xdb0c2e0d64f98fa7ULL;
	hd->h7 = 0x47b5481dbefa4fa4ULL;

	hd->nblocks = 0;
	hd->count = 0;
}

static const u64 k[] =
{
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define Cho(x,y,z) ( (z) ^ ((x) & ((y) ^ (z))) )
#define Maj(x,y,z) ( ((x) & (y)) | ((z) & ((x) | (y))) )
#define Sum0(x) ( ror64((x), 28) ^ ror64((x), 34) ^ ror64((x), 39) )
#define Sum1(x) ( ror64((x), 14) ^ ror64((x), 18) ^ ror64((x), 41) )
#define S0(x) ( ror64((x), 1) ^ ror64((x), 8) ^ ((x) >> 7) )
#define S1(x) ( ror64((x), 19) ^ ror64((x), 61) ^ ((x) >> 6) )

static void
transform(SHA512_CONTEXT* hd, const unsigned char* data)
{
	u64 a, b, c, d, e, f, g, h, t1, t2;
	u64 w[80];
	unsigned int i;

	a = hd->h0;
	b = hd->h1;
	c = hd->h2;
	d = hd->h3;
	e = hd->h4;
	f = hd->h5;
	g = hd->h6;
	h = hd->h7;

	for (i = 0; i < 16; i++)
		w[i] = buf_get_be64(data + i * 8);
	for (; i < 80; i++)
		w[i] = S1(w[i - 2]) + w[i - 7] + S0(w[i - 15]) + w[i - 16];

	for (i = 0; i < 80; i++)
	{
		t1 = h + Sum1(e) + Cho(e, f, g) + k[i] + w[i];
		t2 = Sum0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	hd->h0 += a;
	hd->h1 += b;
	hd->h2 += c;
	hd->h3 += d;
	hd->h4 += e;
	hd->h5 += f;
	hd->h6 += g;
	hd->h7 += h;
}

/* Update the message digest with the contents of INBUF.  */
static void
sha512_write(void* context, const void* inbuf_arg, grub_size_t inlen)
{
	const unsigned char* inbuf = inbuf_arg;
	SHA512_CONTEXT* hd = context;

	if (hd->count == 128)
	{
		/* flush the buffer */
		transform(hd, hd->buf);
		_gcry_burn_stack(768);
		hd->count = 0;
		hd->nblocks++;
	}
	if (!inbuf)
		return;
	if (hd->count)
	{
		for (; inlen && hd->count < 128; inlen--)
			hd->buf[hd->count++] = *inbuf++;
		sha512_write(hd, NULL, 0);
		if (!inlen)
			return;
	}

	while (inlen >= 128)
	{
		transform(hd, inbuf);
		hd->count = 0;
		hd->nblocks++;
		inlen -= 128;
		inbuf += 128;
	}
	_gcry_burn_stack(768);
	for (; inlen && hd->count < 128; inlen--)
		hd->buf[hd->count++] = *inbuf++;
}

/* The routine finally terminates the computation and returns the
   digest.  */
static void
sha512_final(void* context)
{
	SHA512_CONTEXT* hd = context;
	u64 t, msb, lsb;
	byte* p;

	sha512_write(hd, NULL, 0); /* flush */

	t = hd->nblocks;
	/* multiply by 128 to make a byte count */
	lsb = t << 7;
	msb = t >> 57;
	/* add the count */
	t = lsb;
	if ((lsb += hd->count) < t)
		msb++;
	/* multiply by 8 to make a bit count */
	t = lsb;
	lsb <<= 3;
	msb <<= 3;
	msb |= t >> 61;

	if (hd->count < 112)
	{
		/* enough room */
		hd->buf[hd->count++] = 0x80; /* pad */
		while (hd->count < 112)
			hd->buf[hd->count++] = 0;  /* pad */
	}
	else
	{
		/* need one extra block */
		hd->buf[hd->count++] = 0x80; /* pad character */
		while (hd->count < 128)
			hd->buf[hd->count++] = 0;
		sha512_write(hd, NULL, 0);  /* flush */
		grub_memset(hd->buf, 0, 112); /* fill next block with zeroes */
	}
	/* append the 128 bit count */
	buf_put_be64(hd->buf + 112, msb);
	buf_put_be64(hd->buf + 120, lsb);
	transform(hd, hd->buf);
	_gcry_burn_stack(768);

	p = hd->buf;
	buf_put_be64(p +  0, hd->h0);
	buf_put_be64(p +  8, hd->h1);
	buf_put_be64(p + 16, hd->h2);
	buf_put_be64(p + 24, hd->h3);
	buf_put_be64(p + 32, hd->h4);
	buf_put_be64(p + 40, hd->h5);
	buf_put_be64(p + 48, hd->h6);
	buf_put_be64(p + 56, hd->h7);
}

static byte*
sha512_read(void* context)
{
	SHA512_CONTEXT* hd = context;

	return hd->buf;
}

static byte asn512[19] = /* Object ID is 2.16.840.1.101.3.4.2.3 */
{
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
	0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
	0x40
};

static gcry_md_oid_spec_t oid_spec_sha512[] =
{
	{ "2.16.840.1.101.3.4.2.3" },
	/* PKCS#1 sha512WithRSAEncryption */
	{ "1.2.840.113549.1.1.13" },
	{ NULL },
};

static byte asn384[19] = /* Object ID is 2.16.840.1.101.3.4.2.2 */
{
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
	0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
	0x30
};

static gcry_md_oid_spec_t oid_spec_sha384[] =
{
	{ "2.16.840.1.101.3.4.2.2" },
	/* PKCS#1 sha384WithRSAEncryption */
	{ "1.2.840.113549.1.1.12" },
	{ NULL },
};

gcry_md_spec_t _gcry_digest_spec_sha512 =
{
	.name = "SHA512",
	.asnoid = asn512,
	.asnlen = DIM(asn512),
	.oids = oid_spec_sha512,
	.mdlen = 64,
	.init = sha512_init,
	.write = sha512_write,
	.final = sha512_final,
	.read = sha512_read,
	.contextsize = sizeof(SHA512_CONTEXT),
	.blocksize = 128
};

gcry_md_spec_t _gcry_digest_spec_sha384 =
{
	.name = "SHA384",
	.asnoid = asn384,
	.asnlen = DIM(asn384),
	.oids = oid_spec_sha384,
	.mdlen = 48,
	.init = sha384_init,
	.write = sha512_write,
	.final = sha512_final,
	.read = sha512_read,
	.contextsize = sizeof(SHA512_CONTEXT),
	.blocksize = 128
};
