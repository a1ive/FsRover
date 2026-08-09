/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_GCRY_TYPES_HEADER
#define GRUB_GCRY_TYPES_HEADER 1

#include <grub/types.h>

#undef WORDS_BIGENDIAN

#define DIM(v) (sizeof(v)/sizeof((v)[0]))

#define wipememory(ptr, len) grub_memset ((ptr), 0, (len))

typedef grub_uint64_t u64;
typedef grub_uint32_t u32;
typedef grub_uint16_t u16;
typedef grub_uint8_t byte;

typedef union
{
	int a;
	short b;
	char c[1];
	long d;
	u64 e;
} PROPERLY_ALIGNED_TYPE;

/****************
 * Rotate the 32 bit unsigned integer X by N bits left/right
 */
static inline u32 rol(u32 x, int n)
{
	return ((x << (n & (32 - 1))) | (x >> ((32 - n) & (32 - 1))));
}

static inline u32 ror(u32 x, int n)
{
	return ((x >> (n & (32 - 1))) | (x << ((32 - n) & (32 - 1))));
}

static inline u64 rol64(u64 x, int n)
{
	return ((x << (n & (64 - 1))) | (x >> ((64 - n) & (64 - 1))));
}

/* Byte swap for 32-bit and 64-bit integers.  If available, use compiler
   provided helpers.  */
static inline u32
_gcry_bswap32(u32 x)
{
	return ((rol(x, 8) & 0x00ff00ffL) | (ror(x, 8) & 0xff00ff00L));
}

static inline u64
_gcry_bswap64(u64 x)
{
	return ((u64)_gcry_bswap32(x) << 32) | (_gcry_bswap32(x >> 32));
}

/* Endian dependent byte swap operations.  */
#ifdef WORDS_BIGENDIAN
# define le_bswap32(x) _gcry_bswap32(x)
# define be_bswap32(x) ((u32)(x))
# define le_bswap64(x) _gcry_bswap64(x)
# define be_bswap64(x) ((u64)(x))
#else
# define le_bswap32(x) ((u32)(x))
# define be_bswap32(x) _gcry_bswap32(x)
# define le_bswap64(x) ((u64)(x))
# define be_bswap64(x) _gcry_bswap64(x)
#endif

/* Count trailing zero bits in an unsigend int.  We return an int
   because that is what gcc's builtin does.  X must not be zero. */
static inline int
_gcry_ctz_no_zero(unsigned int x)
{
	/* See
	 * http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightModLookup
	 */
	static const unsigned char mod37[] =
	{
	  sizeof(unsigned int) * 8,
		  0,  1, 26,  2, 23, 27,  0,  3, 16, 24, 30, 28, 11,  0, 13,
	  4,  7, 17,  0, 25, 22, 31, 15, 29, 10, 12,  6,  0, 21, 14,  9,
	  5, 20,  8, 19, 18
	};
	return (int)mod37[(-x & x) % 37];
}


/* Count trailing zero bits in an unsigend int.  We return an int
   because that is what gcc's builtin does.  Returns the number of
   bits in X if X is 0. */
static inline int
_gcry_ctz(unsigned int x)
{
	return x ? _gcry_ctz_no_zero(x) : 8 * sizeof(x);
}

/* Count trailing zero bits in an u64.  We return an int because that
   is what gcc's builtin does.  Returns the number of bits in X if X
   is 0.  */
static inline int
_gcry_ctz64(u64 x)
{
	if ((x & 0xffffffff))
		return _gcry_ctz(x);
	else
		return 32 + _gcry_ctz(x >> 32);
}

/* Algorithm IDs for the hash functions we know about. Not all of them
   are implemented. */
enum gcry_md_algos
{
	GCRY_MD_NONE = 0,
	GCRY_MD_MD5 = 1,
	GCRY_MD_SHA1 = 2,
	GCRY_MD_RMD160 = 3,
	GCRY_MD_MD2 = 5,
	GCRY_MD_TIGER = 6,   /* TIGER/192 as used by gpg <= 1.3.2. */
	GCRY_MD_HAVAL = 7,   /* HAVAL, 5 pass, 160 bit. */
	GCRY_MD_SHA256 = 8,
	GCRY_MD_SHA384 = 9,
	GCRY_MD_SHA512 = 10,
	GCRY_MD_SHA224 = 11,

	GCRY_MD_MD4 = 301,
	GCRY_MD_CRC32 = 302,
	GCRY_MD_CRC32_RFC1510 = 303,
	GCRY_MD_CRC24_RFC2440 = 304,
	GCRY_MD_WHIRLPOOL = 305,
	GCRY_MD_TIGER1 = 306, /* TIGER fixed.  */
	GCRY_MD_TIGER2 = 307, /* TIGER2 variant.   */
	GCRY_MD_GOSTR3411_94 = 308, /* GOST R 34.11-94.  */
	GCRY_MD_STRIBOG256 = 309, /* GOST R 34.11-2012, 256 bit.  */
	GCRY_MD_STRIBOG512 = 310, /* GOST R 34.11-2012, 512 bit.  */
	GCRY_MD_GOSTR3411_CP = 311, /* GOST R 34.11-94 with CryptoPro-A S-Box.  */
	GCRY_MD_SHA3_224 = 312,
	GCRY_MD_SHA3_256 = 313,
	GCRY_MD_SHA3_384 = 314,
	GCRY_MD_SHA3_512 = 315,
	GCRY_MD_SHAKE128 = 316,
	GCRY_MD_SHAKE256 = 317,
	GCRY_MD_BLAKE2B_512 = 318,
	GCRY_MD_BLAKE2B_384 = 319,
	GCRY_MD_BLAKE2B_256 = 320,
	GCRY_MD_BLAKE2B_160 = 321,
	GCRY_MD_BLAKE2S_256 = 322,
	GCRY_MD_BLAKE2S_224 = 323,
	GCRY_MD_BLAKE2S_160 = 324,
	GCRY_MD_BLAKE2S_128 = 325,
	GCRY_MD_SM3 = 326,
	GCRY_MD_SHA512_256 = 327,
	GCRY_MD_SHA512_224 = 328,
	GCRY_MD_CSHAKE128 = 329,
	GCRY_MD_CSHAKE256 = 330
};

/* Flags used with the open function.  */
enum gcry_md_flags
{
	GCRY_MD_FLAG_SECURE = 1,  /* Allocate all buffers in "secure" memory.  */
	GCRY_MD_FLAG_HMAC = 2,  /* Make an HMAC out of this algorithm.  */
	GCRY_MD_FLAG_BUGEMU1 = 0x0100
};

/* Algorithm IDs for the KDFs.  */
enum gcry_kdf_algos
{
	GCRY_KDF_NONE = 0,
	GCRY_KDF_SIMPLE_S2K = 16,
	GCRY_KDF_SALTED_S2K = 17,
	GCRY_KDF_ITERSALTED_S2K = 19,
	GCRY_KDF_PBKDF1 = 33,
	GCRY_KDF_PBKDF2 = 34,
	GCRY_KDF_SCRYPT = 48,
	/**/
	GCRY_KDF_ARGON2 = 64,
	GCRY_KDF_BALLOON = 65,
	/**/
	/* In the original SP 800-56A, it's called
	 * "Concatenation Key Derivation Function".
	 * Now (as of 2022), it's defined in SP 800-56C rev.2, as
	 * "One-Step Key Derivation".
	 */
	GCRY_KDF_ONESTEP_KDF = 96, /* One-Step Key Derivation with hash */
	GCRY_KDF_ONESTEP_KDF_MAC = 97, /* One-Step Key Derivation with MAC */
	GCRY_KDF_HKDF = 98,
	/* Two-Step Key Derivation with HMAC */
	/* Two-Step Key Derivation with CMAC */
	/* KDF PRF in SP 800-108r1 */
	GCRY_KDF_X963_KDF = 101
};

enum gcry_kdf_subalgo_argon2
{
	GCRY_KDF_ARGON2D = 0,
	GCRY_KDF_ARGON2I = 1,
	GCRY_KDF_ARGON2ID = 2
};

/* Another API to derive a key from a passphrase.  */
typedef struct gcry_kdf_handle* gcry_kdf_hd_t;

typedef void (*gcry_kdf_job_fn_t) (void* priv);
typedef int (*gcry_kdf_dispatch_job_fn_t) (void* jobs_context, gcry_kdf_job_fn_t job_fn, void* job_priv);
typedef int (*gcry_kdf_wait_all_jobs_fn_t) (void* jobs_context);

/* Exposed structure for KDF computation to decouple thread functionality.  */
typedef struct gcry_kdf_thread_ops
{
	void* jobs_context;
	gcry_kdf_dispatch_job_fn_t dispatch_job;
	gcry_kdf_wait_all_jobs_fn_t wait_all_jobs;
} gcry_kdf_thread_ops_t;

/* The data object used to hold a handle to an encryption object.  */
struct gcry_cipher_handle;
typedef struct gcry_cipher_handle* gcry_cipher_hd_t;

/* All symmetric encryption algorithms are identified by their IDs.
   More IDs may be registered at runtime. */
enum gcry_cipher_algos
{
	GCRY_CIPHER_NONE = 0,
	GCRY_CIPHER_IDEA = 1,
	GCRY_CIPHER_3DES = 2,
	GCRY_CIPHER_CAST5 = 3,
	GCRY_CIPHER_BLOWFISH = 4,
	GCRY_CIPHER_SAFER_SK128 = 5,
	GCRY_CIPHER_DES_SK = 6,
	GCRY_CIPHER_AES = 7,
	GCRY_CIPHER_AES192 = 8,
	GCRY_CIPHER_AES256 = 9,
	GCRY_CIPHER_TWOFISH = 10,

	/* Other cipher numbers are above 300 for OpenPGP reasons. */
	GCRY_CIPHER_ARCFOUR = 301,  /* Fully compatible with RSA's RC4 (tm). */
	GCRY_CIPHER_DES = 302,  /* Yes, this is single key 56 bit DES. */
	GCRY_CIPHER_TWOFISH128 = 303,
	GCRY_CIPHER_SERPENT128 = 304,
	GCRY_CIPHER_SERPENT192 = 305,
	GCRY_CIPHER_SERPENT256 = 306,
	GCRY_CIPHER_RFC2268_40 = 307,  /* Ron's Cipher 2 (40 bit). */
	GCRY_CIPHER_RFC2268_128 = 308,  /* Ron's Cipher 2 (128 bit). */
	GCRY_CIPHER_SEED = 309,  /* 128 bit cipher described in RFC4269. */
	GCRY_CIPHER_CAMELLIA128 = 310,
	GCRY_CIPHER_CAMELLIA192 = 311,
	GCRY_CIPHER_CAMELLIA256 = 312,
	GCRY_CIPHER_SALSA20 = 313,
	GCRY_CIPHER_SALSA20R12 = 314,
	GCRY_CIPHER_GOST28147 = 315,
	GCRY_CIPHER_CHACHA20 = 316,
	GCRY_CIPHER_GOST28147_MESH = 317, /* With CryptoPro key meshing.  */
	GCRY_CIPHER_SM4 = 318,
	GCRY_CIPHER_ARIA128 = 319,
	GCRY_CIPHER_ARIA192 = 320,
	GCRY_CIPHER_ARIA256 = 321
};

/* The Rijndael algorithm is basically AES, so provide some macros. */
#define GCRY_CIPHER_AES128      GCRY_CIPHER_AES
#define GCRY_CIPHER_RIJNDAEL    GCRY_CIPHER_AES
#define GCRY_CIPHER_RIJNDAEL128 GCRY_CIPHER_AES128
#define GCRY_CIPHER_RIJNDAEL192 GCRY_CIPHER_AES192
#define GCRY_CIPHER_RIJNDAEL256 GCRY_CIPHER_AES256

/* The supported encryption modes.  Note that not all of them are
   supported for each algorithm. */
enum gcry_cipher_modes
{
	GCRY_CIPHER_MODE_NONE = 0,   /* Not yet specified. */
	GCRY_CIPHER_MODE_ECB = 1,   /* Electronic codebook. */
	GCRY_CIPHER_MODE_CFB = 2,   /* Cipher feedback. */
	GCRY_CIPHER_MODE_CBC = 3,   /* Cipher block chaining. */
	GCRY_CIPHER_MODE_STREAM = 4,   /* Used with stream ciphers. */
	GCRY_CIPHER_MODE_OFB = 5,   /* Outer feedback. */
	GCRY_CIPHER_MODE_CTR = 6,   /* Counter. */
	GCRY_CIPHER_MODE_AESWRAP = 7,   /* AES-WRAP algorithm.  */
	GCRY_CIPHER_MODE_CCM = 8,   /* Counter with CBC-MAC.  */
	GCRY_CIPHER_MODE_GCM = 9,   /* Galois Counter Mode. */
	GCRY_CIPHER_MODE_POLY1305 = 10,  /* Poly1305 based AEAD mode. */
	GCRY_CIPHER_MODE_OCB = 11,  /* OCB3 mode.  */
	GCRY_CIPHER_MODE_CFB8 = 12,  /* Cipher feedback (8 bit mode). */
	GCRY_CIPHER_MODE_XTS = 13,  /* XTS mode.  */
	GCRY_CIPHER_MODE_EAX = 14,  /* EAX mode.  */
	GCRY_CIPHER_MODE_SIV = 15,  /* SIV mode.  */
	GCRY_CIPHER_MODE_GCM_SIV = 16   /* GCM-SIV mode.  */
};

/* Flags used with the open function. */
enum gcry_cipher_flags
{
	GCRY_CIPHER_SECURE = 1,  /* Allocate in secure memory. */
	GCRY_CIPHER_ENABLE_SYNC = 2,  /* Enable CFB sync mode. */
	GCRY_CIPHER_CBC_CTS = 4,  /* Enable CBC cipher text stealing (CTS). */
	GCRY_CIPHER_CBC_MAC = 8,  /* Enable CBC message auth. code (MAC).  */
	GCRY_CIPHER_EXTENDED = 16  /* Enable extended AES-WRAP.  */
};

/* Methods used for AEAD IV generation. */
enum gcry_cipher_geniv_methods
{
	GCRY_CIPHER_GENIV_METHOD_CONCAT = 1,
	GCRY_CIPHER_GENIV_METHOD_XOR = 2
};

/* GCM works only with blocks of 128 bits */
#define GCRY_GCM_BLOCK_LEN  (128 / 8)

/* CCM works only with blocks of 128 bits.  */
#define GCRY_CCM_BLOCK_LEN  (128 / 8)

/* OCB works only with blocks of 128 bits.  */
#define GCRY_OCB_BLOCK_LEN  (128 / 8)

/* XTS works only with blocks of 128 bits.  */
#define GCRY_XTS_BLOCK_LEN  (128 / 8)

/* SIV and GCM-SIV works only with blocks of 128 bits */
#define GCRY_SIV_BLOCK_LEN  (128 / 8)

/* Functions for loading and storing unaligned u32 values of different
   endianness.  */
static inline u32 buf_get_be32(const void* _buf)
{
	const byte* in = _buf;
	return ((u32)in[0] << 24) | ((u32)in[1] << 16) |
		((u32)in[2] << 8) | (u32)in[3];
}

static inline u32 buf_get_le32(const void* _buf)
{
	const byte* in = _buf;
	return ((u32)in[3] << 24) | ((u32)in[2] << 16) |
		((u32)in[1] << 8) | (u32)in[0];
}

static inline void buf_put_be32(void* _buf, u32 val)
{
	byte* out = _buf;
	out[0] = (byte)(val >> 24);
	out[1] = (byte)(val >> 16);
	out[2] = (byte)(val >> 8);
	out[3] = (byte)val;
}

static inline void buf_put_le32(void* _buf, u32 val)
{
	byte* out = _buf;
	out[3] = (byte)(val >> 24);
	out[2] = (byte)(val >> 16);
	out[1] = (byte)(val >> 8);
	out[0] = (byte)val;
}

/* Functions for loading and storing unaligned u64 values of different
   endianness.  */
static inline u64 buf_get_be64(const void* _buf)
{
	const byte* in = _buf;
	return ((u64)in[0] << 56) | ((u64)in[1] << 48) |
		((u64)in[2] << 40) | ((u64)in[3] << 32) |
		((u64)in[4] << 24) | ((u64)in[5] << 16) |
		((u64)in[6] << 8) | (u64)in[7];
}

static inline u64 buf_get_le64(const void* _buf)
{
	const byte* in = _buf;
	return ((u64)in[7] << 56) | ((u64)in[6] << 48) |
		((u64)in[5] << 40) | ((u64)in[4] << 32) |
		((u64)in[3] << 24) | ((u64)in[2] << 16) |
		((u64)in[1] << 8) | (u64)in[0];
}

static inline void buf_put_be64(void* _buf, u64 val)
{
	byte* out = _buf;
	out[0] = (byte)(val >> 56);
	out[1] = (byte)(val >> 48);
	out[2] = (byte)(val >> 40);
	out[3] = (byte)(val >> 32);
	out[4] = (byte)(val >> 24);
	out[5] = (byte)(val >> 16);
	out[6] = (byte)(val >> 8);
	out[7] = (byte)val;
}

static inline void buf_put_le64(void* _buf, u64 val)
{
	byte* out = _buf;
	out[7] = (byte)(val >> 56);
	out[6] = (byte)(val >> 48);
	out[5] = (byte)(val >> 40);
	out[4] = (byte)(val >> 32);
	out[3] = (byte)(val >> 24);
	out[2] = (byte)(val >> 16);
	out[1] = (byte)(val >> 8);
	out[0] = (byte)val;
}

/* Host-endian get/put macros */
#ifdef WORDS_BIGENDIAN
# define buf_get_he32 buf_get_be32
# define buf_put_he32 buf_put_be32
# define buf_get_he64 buf_get_be64
# define buf_put_he64 buf_put_be64
#else
# define buf_get_he32 buf_get_le32
# define buf_put_he32 buf_put_le32
# define buf_get_he64 buf_get_le64
# define buf_put_he64 buf_put_le64
#endif

#define buf_cpy(d, s, n) grub_memcpy ((d), (s), (n))

/* Optimized function for buffer xoring */
static inline void
buf_xor(void* _dst, const void* _src1, const void* _src2, size_t len)
{
	byte* dst = _dst;
	const byte* src1 = _src1;
	const byte* src2 = _src2;

	while (len >= sizeof(u64))
	{
		buf_put_he64(dst, buf_get_he64(src1) ^ buf_get_he64(src2));
		dst += sizeof(u64);
		src1 += sizeof(u64);
		src2 += sizeof(u64);
		len -= sizeof(u64);
	}

	if (len > sizeof(u32))
	{
		buf_put_he32(dst, buf_get_he32(src1) ^ buf_get_he32(src2));
		dst += sizeof(u32);
		src1 += sizeof(u32);
		src2 += sizeof(u32);
		len -= sizeof(u32);
	}

	/* Handle tail.  */
	for (; len; len--)
		*dst++ = *src1++ ^ *src2++;
}

/* Optimized function for buffer xoring with two destination buffers.  Used
   mainly by CFB mode encryption.  */
static inline void
buf_xor_2dst(void* _dst1, void* _dst2, const void* _src, size_t len)
{
	byte* dst1 = _dst1;
	byte* dst2 = _dst2;
	const byte* src = _src;

	while (len >= sizeof(u64))
	{
		u64 temp = buf_get_he64(dst2) ^ buf_get_he64(src);
		buf_put_he64(dst2, temp);
		buf_put_he64(dst1, temp);
		dst2 += sizeof(u64);
		dst1 += sizeof(u64);
		src += sizeof(u64);
		len -= sizeof(u64);
	}

	if (len >= sizeof(u32))
	{
		u32 temp = buf_get_he32(dst2) ^ buf_get_he32(src);
		buf_put_he32(dst2, temp);
		buf_put_he32(dst1, temp);
		dst2 += sizeof(u32);
		dst1 += sizeof(u32);
		src += sizeof(u32);
		len -= sizeof(u32);
	}

	/* Handle tail.  */
	for (; len; len--)
		*dst1++ = (*dst2++ ^= *src++);
}


/* Optimized function for combined buffer xoring and copying.  Used by mainly
   CBC mode decryption.  */
static inline void
buf_xor_n_copy_2(void* _dst_xor, const void* _src_xor, void* _srcdst_cpy,
	const void* _src_cpy, size_t len)
{
	byte* dst_xor = _dst_xor;
	byte* srcdst_cpy = _srcdst_cpy;
	const byte* src_xor = _src_xor;
	const byte* src_cpy = _src_cpy;

	while (len >= sizeof(u64))
	{
		u64 temp = buf_get_he64(src_cpy);
		buf_put_he64(dst_xor, buf_get_he64(srcdst_cpy) ^ buf_get_he64(src_xor));
		buf_put_he64(srcdst_cpy, temp);
		dst_xor += sizeof(u64);
		srcdst_cpy += sizeof(u64);
		src_xor += sizeof(u64);
		src_cpy += sizeof(u64);
		len -= sizeof(u64);
	}

	if (len >= sizeof(u32))
	{
		u32 temp = buf_get_he32(src_cpy);
		buf_put_he32(dst_xor, buf_get_he32(srcdst_cpy) ^ buf_get_he32(src_xor));
		buf_put_he32(srcdst_cpy, temp);
		dst_xor += sizeof(u32);
		srcdst_cpy += sizeof(u32);
		src_xor += sizeof(u32);
		src_cpy += sizeof(u32);
		len -= sizeof(u32);
	}

	/* Handle tail.  */
	for (; len; len--)
	{
		byte temp = *src_cpy++;
		*dst_xor++ = *srcdst_cpy ^ *src_xor++;
		*srcdst_cpy++ = temp;
	}
}


/* Optimized function for combined buffer xoring and copying.  Used by mainly
   CFB mode decryption.  */
static inline void
buf_xor_n_copy(void* _dst_xor, void* _srcdst_cpy, const void* _src, size_t len)
{
	buf_xor_n_copy_2(_dst_xor, _src, _srcdst_cpy, _src, len);
}

/* libgcrypt gcry_buffer_t (an iov element); used by blake2b hash_buffers
   and argon2 (gcry_kdf.c / gcry_blake2.c).  */
typedef struct
{
	grub_size_t size;
	grub_size_t off;
	grub_size_t len;
	void* data;
} gcry_buffer_t;

/* A structure with function pointers for mode operations. */
typedef struct cipher_mode_ops
{
	gcry_err_code_t(*encrypt)(gcry_cipher_hd_t c, unsigned char* outbuf,
		size_t outbuflen, const unsigned char* inbuf,
		size_t inbuflen);
	gcry_err_code_t(*decrypt)(gcry_cipher_hd_t c, unsigned char* outbuf,
		size_t outbuflen, const unsigned char* inbuf,
		size_t inbuflen);
	gcry_err_code_t(*setiv)(gcry_cipher_hd_t c, const unsigned char* iv,
		size_t ivlen);

	gcry_err_code_t(*authenticate)(gcry_cipher_hd_t c,
		const unsigned char* abuf, size_t abuflen);
	gcry_err_code_t(*get_tag)(gcry_cipher_hd_t c, unsigned char* outtag,
		size_t taglen);
	gcry_err_code_t(*check_tag)(gcry_cipher_hd_t c, const unsigned char* intag,
		size_t taglen);
} cipher_mode_ops_t;


/* A structure with function pointers for bulk operations.  The cipher
   algorithm setkey function initializes them when bulk operations are
   available and the actual encryption routines use them if they are
   not NULL.  */
typedef struct cipher_bulk_ops
{
	void (*ecb_crypt)(void* context, void* outbuf_arg, const void* inbuf_arg,
		size_t nblocks, int encrypt);
	void (*cfb_enc)(void* context, unsigned char* iv, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks);
	void (*cfb_dec)(void* context, unsigned char* iv, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks);
	void (*cbc_enc)(void* context, unsigned char* iv, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks, int cbc_mac);
	void (*cbc_dec)(void* context, unsigned char* iv, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks);
	void (*ofb_enc)(void* context, unsigned char* iv, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks);
	void (*ctr_enc)(void* context, unsigned char* iv, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks);
	void (*ctr32le_enc)(void* context, unsigned char* iv, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks);
	size_t(*ocb_crypt)(gcry_cipher_hd_t c, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks, int encrypt);
	size_t(*ocb_auth)(gcry_cipher_hd_t c, const void* abuf_arg, size_t nblocks);
	void (*xts_crypt)(void* context, unsigned char* tweak, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks, int encrypt);
	size_t(*gcm_crypt)(gcry_cipher_hd_t c, void* outbuf_arg,
		const void* inbuf_arg, size_t nblocks, int encrypt);
} cipher_bulk_ops_t;

#endif
