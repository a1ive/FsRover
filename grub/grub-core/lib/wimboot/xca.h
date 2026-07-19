#ifndef _XCA_H
#define _XCA_H

/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * @file
 *
 * Xpress Compression Algorithm (MS-XCA) decompression
 *
 * Imported from ref\wimboot and adapted for Rover/MSVC: grub types,
 * no GNU statement expressions.
 *
 * Note: the bitstream reader may read up to two bytes beyond the end
 * of the compressed input; callers must provide that much slack after
 * the input buffer.
 *
 */

#include <grub/types.h>
#include "huffman.h"

/** Number of XCA codes */
#define XCA_CODES 512

/** XCA decompressor */
struct xca {
	/** Huffman alphabet */
	struct huffman_alphabet alphabet;
	/** Raw symbols */
	huffman_raw_symbol_t raw[XCA_CODES];
	/** Code lengths */
	grub_uint8_t lengths[XCA_CODES];
};

/** Length of the XCA symbol Huffman lengths table (4 bits per symbol) */
#define XCA_HUF_LEN_BYTES ( XCA_CODES / 2 )

/**
 * Extract Huffman-coded length of a raw symbol
 *
 * @v lengths		Huffman lengths table (nibble-packed)
 * @v symbol		Raw symbol
 * @ret len		Huffman-coded length
 */
static inline unsigned int xca_huf_len ( const grub_uint8_t *lengths,
					 unsigned int symbol ) {
	return ( ( ( lengths[ symbol / 2 ] ) >>
		   ( 4 * ( symbol % 2 ) ) ) & 0x0f );
}

/** XCA source data stream end marker */
#define XCA_END_MARKER 256

/** XCA block size */
#define XCA_BLOCK_SIZE ( 64 * 1024 )

extern grub_ssize_t xca_decompress ( const void *data, grub_size_t len,
				     void *buf );

#endif /* _XCA_H */
