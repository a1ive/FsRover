/*
 *  Rover -- Filesystem browser for Windows
 *  Cabinet (.cab) block decompressors: LZX and Quantum.
 *
 *  C ports of 7-Zip 26.02 CPP\7zip\Compress\LzxDecoder.cpp and
 *  QuantumDecoder.cpp (LGPL); decompression only.  Both decoders work
 *  on whole CFDATA blocks and keep their history between blocks the
 *  way CPP\7zip\Archive\Cab\CabHandler.cpp drives them.
 *
 *  Copyright (C) 2026  A1ive
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef GRUB_MSCAB_HEADER
#define GRUB_MSCAB_HEADER	1

#include <grub/types.h>

/* every CFDATA block unpacks to at most 32 KiB */
#define CAB_BLOCK_MAX		(1u << 15)

#define CAB_OK			0
#define CAB_ERR_DATA		1	/* corrupt stream */
#define CAB_ERR_MEM		2

/*
 * A decoder decodes one CFDATA block per call: `in` holds the packed
 * block bytes, `out_size` is the block's unpacked size (<= CAB_BLOCK_MAX)
 * and on success *out points at the unpacked bytes, valid until the
 * next call.  cab_*_reset() forgets the history before a new folder.
 */

typedef struct cab_lzx cab_lzx;

cab_lzx *cab_lzx_create (unsigned dict_bits);	/* 15..21 */
void cab_lzx_free (cab_lzx *p);
void cab_lzx_reset (cab_lzx *p);
int cab_lzx_block (cab_lzx *p, const grub_uint8_t *in, grub_size_t in_size,
		   grub_uint32_t out_size, const grub_uint8_t **out);

typedef struct cab_qtm cab_qtm;

cab_qtm *cab_qtm_create (unsigned dict_bits);	/* 0..21 */
void cab_qtm_free (cab_qtm *p);
void cab_qtm_reset (cab_qtm *p);
int cab_qtm_block (cab_qtm *p, const grub_uint8_t *in, grub_size_t in_size,
		   grub_uint32_t out_size, const grub_uint8_t **out);

#endif /* ! GRUB_MSCAB_HEADER */
