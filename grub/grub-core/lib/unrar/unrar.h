/*
 *  Rover -- Filesystem browser for Windows
 *  RAR decompression library, ported to C from 7-Zip 26.02
 *  (CPP\7zip\Compress\Rar*Decoder.*, Rar3Vm.*).
 *
 *  7-Zip Copyright (C) 1999-2025 Igor Pavlov.
 *  Licensed under the GNU LGPL, with the unRAR license restriction:
 *  this code may not be used to develop a RAR (WinRAR) compatible archiver.
 */

#ifndef GRUB_UNRAR_HEADER
#define GRUB_UNRAR_HEADER	1

#include <grub/types.h>

/* results of rar_decoder_run() / rar_decoder_start_item() */
#define RAR_DONE	0	/* current item fully decoded */
#define RAR_PAUSED	1	/* sink requested pause; call run() again to resume */
#define RAR_ERR_DATA	2	/* corrupt compressed data */
#define RAR_ERR_MEM	3	/* out of memory */
#define RAR_ERR_UNSUP	4	/* unsupported method / filter / dictionary */
#define RAR_ERR_READ	5	/* input callback failed */
#define RAR_ERR_WRITE	6	/* sink callback failed */

/* compression algorithm families */
#define RAR_ALGO_15	0	/* unpack version < 20 */
#define RAR_ALGO_20	1	/* unpack version 20..28 */
#define RAR_ALGO_29	2	/* unpack version 29..40 */
#define RAR_ALGO_50	3	/* RAR5 (algo version 0/1) */

/*
 * Input callback: read up to size bytes of packed data of the current item.
 * Returns bytes read, 0 on end of item data, -1 on I/O error.
 */
typedef grub_ssize_t (*rar_read_cb) (void *opaque, void *buf, grub_size_t size);

/*
 * Output sink: receives decoded bytes in stream order.  The sink must
 * consume all bytes.  Return 0 to continue, 1 to request a pause (the
 * decoder returns RAR_PAUSED at the next safe point; more data may still
 * be delivered before that), -1 on fatal error.
 */
typedef int (*rar_sink_cb) (void *opaque, const grub_uint8_t *data,
			    grub_size_t size);

struct rar_dec_props
{
	int solid;		/* item continues the previous solid stream */
	/* RAR5 only */
	unsigned dict_main;	/* dictionary size exponent bits */
	unsigned dict_frac;	/* dictionary fraction (algo v1) */
	int is_v7;		/* RAR7 huffman table layout */
	grub_uint64_t unp_size;	/* unpacked size of this item */
	grub_uint64_t pack_size;/* packed size of this item */
};

struct rar_decoder
{
	int (*start_item) (struct rar_decoder *d, const struct rar_dec_props *p);
	int (*run) (struct rar_decoder *d);
	void (*free) (struct rar_decoder *d);
	rar_read_cb read_cb;
	void *read_opaque;
	rar_sink_cb sink_cb;
	void *sink_opaque;
	int pause_req;		/* sink asked for a pause */
	int sink_err;		/* sink reported an error */
};

typedef struct rar_decoder rar_decoder;

rar_decoder *rar1_decoder_create (void);
rar_decoder *rar2_decoder_create (void);
rar_decoder *rar3_decoder_create (void);
rar_decoder *rar5_decoder_create (void);

/* convenience wrappers */
static inline rar_decoder *
rar_decoder_create (int algo)
{
	switch (algo)
	{
	case RAR_ALGO_15:
		return rar1_decoder_create ();
	case RAR_ALGO_20:
		return rar2_decoder_create ();
	case RAR_ALGO_29:
		return rar3_decoder_create ();
	case RAR_ALGO_50:
		return rar5_decoder_create ();
	}
	return 0;
}

static inline void
rar_decoder_free (rar_decoder *d)
{
	if (d)
		d->free (d);
}

#endif /* GRUB_UNRAR_HEADER */
