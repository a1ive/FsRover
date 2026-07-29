/* LzhDecoder.h -- LZH / LZS decoders shared by the LZH, ARJ and UEFI readers
 *
 * C port of 7-Zip 26.02 CPP\7zip\Compress\LzhDecoder.cpp and of the small
 * method-4 decoder embedded in CPP\7zip\Archive\ArjHandler.cpp, both of
 * which are LGPL.  Decompression only.
 *
 * The same bit stream is used by three formats:
 *   - LHA / LZH archives, methods -lh4- .. -lh7- (dictionary 1<<12 .. 1<<16)
 *   - ARJ methods 1..3 (dictionary 26624) and method 4 (ArjDecode)
 *   - EFI / Tiano compressed sections (dictionary 1<<19, or 1<<14 on EFI 1.1)
 *
 * The sliding window of CLzOutWindow is replaced by the caller's flat output
 * buffer: every caller knows the unpacked size up front and the decoders
 * never emit more than that, so a match distance is in range exactly when it
 * is smaller than the number of bytes produced so far.
 */

#ifndef ZIP7_INC_LZH_DECODER_H
#define ZIP7_INC_LZH_DECODER_H

#include "7zTypes.h"

EXTERN_C_BEGIN

#define LZH_OK		0
#define LZH_ERR_DATA	1

/* dictionary sizes of the EFI / Tiano section compressor */
#define LZH_DICT_TIANO	((UInt32)1 << 19)
#define LZH_DICT_EFI11	((UInt32)1 << 14)
/* dictionary ARJ methods 1..3 are built with */
#define LZH_DICT_ARJ	26624

/*
 * Decode one LZH stream into `out`, which must hold exactly `outSize` bytes.
 * `dictSize` selects the window and, with it, the width the distance table is
 * read with (4 bits up to 16 KiB, 5 bits above).  On success `*inProcessed`,
 * when not NULL, receives the number of packed bytes consumed, the way
 * CCoder::GetInputProcessedSize() reports it.
 */
int LzhDecode(const Byte *in, SizeT inSize, Byte *out, SizeT outSize,
    UInt32 dictSize, SizeT *inProcessed);

/* Same, for the ARJ method 4 stream (fixed 32 KiB window, no Huffman). */
int ArjDecode(const Byte *in, SizeT inSize, Byte *out, SizeT outSize,
    SizeT *inProcessed);

EXTERN_C_END

#endif
