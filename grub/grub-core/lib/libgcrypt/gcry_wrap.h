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

#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#define ror(x,n) ( ((x) >> (n)) | ((x) << (32-(n))) )

typedef grub_uint64_t u64;
typedef grub_uint32_t u32;
typedef grub_uint16_t u16;
typedef grub_uint8_t byte;

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

/* libgcrypt gcry_buffer_t (an iov element); used by blake2b hash_buffers
   and argon2 (gcry_kdf.c / gcry_blake2.c).  */
typedef struct
{
	grub_size_t size;
	grub_size_t off;
	grub_size_t len;
	void* data;
} gcry_buffer_t;

/* BLAKE2b-512 over a gcry_buffer_t vector; defined in gcry_blake2.c and
   called by argon2's H0 derivation in gcry_kdf.c.  */
void grub_blake2b_512_hash_buffers(void* out, const gcry_buffer_t* iov,
				   int iovcnt);

#endif
