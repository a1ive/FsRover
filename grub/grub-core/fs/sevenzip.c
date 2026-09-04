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

/*  Read-only 7z archive filesystem driver.
 *
 *  Header parsing uses the 7-Zip 26.02 ANSI-C reader as-is
 *  (grub-core\lib\7z: 7zArcIn.c and friends); folder decoding is
 *  reimplemented here as a chain of pull streams so that entries of
 *  any size can be read in constant memory instead of materializing
 *  whole folders the way C\7zDec.c does.  Semantics follow
 *  CPP\7zip\Archive\7z.
 *
 *  Supported coders: Copy, LZMA, LZMA2, PPMd7, BZip2, Deflate, ZSTD
 *  (both the 0x4015D id and the 7-Zip-zstd fork's 0x4F71101), LZ4
 *  (fork id 0x4F71104, standard LZ4 frames), Delta, BCJ (x86), BCJ2,
 *  ARM, ARMT, ARM64, PPC, SPARC, IA64, RISCV, SWAP2/SWAP4.
 *  Encrypted entries and multi-volume sets are not supported.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/dl.h>

#include <7z.h>
#include <7zCrc.h>
#include <Bcj2.h>
#include <Bra.h>
#include <Delta.h>
#include <LzmaDec.h>
#include <Lzma2Dec.h>
#include <Ppmd7.h>

#include <miniz.h>
#include <bzlib.h>
#include <zstd.h>
#include <xxhash.h>
#include <lz4.h>

GRUB_MOD_LICENSE ("GPLv3+");

/* 7z method ids (CPP\7zip\Archive\7z\7zHeader.h) */
#define SZ_M_COPY	0x00
#define SZ_M_DELTA	0x03
#define SZ_M_ARM64	0x0a
#define SZ_M_RISCV	0x0b
#define SZ_M_SWAP2	0x20302
#define SZ_M_SWAP4	0x20304
#define SZ_M_LZMA2	0x21
#define SZ_M_LZMA	0x30101
#define SZ_M_PPMD	0x30401
#define SZ_M_DEFLATE	0x40108
#define SZ_M_BZIP2	0x40202
#define SZ_M_ZSTD	0x4015D
/* 7-Zip-zstd fork ids (CPP\7zip\Archive\7z\7zHeader.h there) */
#define SZ_M_ZSTD_F	0x4F71101
#define SZ_M_LZ4	0x4F71104
#define SZ_M_BCJ	0x3030103
#define SZ_M_BCJ2	0x303011B
#define SZ_M_PPC	0x3030205
#define SZ_M_IA64	0x3030401
#define SZ_M_ARM	0x3030501
#define SZ_M_ARMT	0x3030701
#define SZ_M_SPARC	0x3030805
#define SZ_M_AES256	0x6F10701

#define SZ_NO_FOLDER	((grub_uint32_t) 0xFFFFFFFF)

#define SZ_LOOK_BUF	(1 << 16)	/* header parsing window */
#define SZ_IBUF_SIZE	(1 << 16)	/* packed input per coder */
#define SZ_BRA_BUF	(1 << 15)	/* branch filter window */
#define SZ_BCJ2_BUF	(1 << 14)	/* per BCJ2 input stream */
#define SZ_SKIP_BUF	(1 << 16)	/* seek-forward scratch */

#define SZ_SEEN_BUCKETS	512

/* 7-Zip stores the unix mode in the attribute high word */
#define SZ_ATTR_UNIX_EXTENSION	0x8000
#define SZ_ATTR_DIRECTORY	0x10

struct grub_7z_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	CSzArEx db;
	char **names;		/* per file, UTF-8, '\' turned into '/' */
};

static void *
sz_mem_alloc (ISzAllocPtr p, size_t size)
{
	(void) p;
	return grub_malloc (size);
}

static void
sz_mem_free (ISzAllocPtr p, void *address)
{
	(void) p;
	grub_free (address);
}

static const ISzAlloc sz_allocator = { sz_mem_alloc, sz_mem_free };

static grub_ssize_t
sz_data_error (void)
{
	grub_error (GRUB_ERR_BAD_FS, "corrupt 7z data");
	return -1;
}

struct sz_stm;

/* returns produced bytes, 0 on end of stream, -1 with grub_errno set */
typedef grub_ssize_t (*sz_stm_read_t) (struct sz_stm *stm, grub_uint8_t *buf,
				       grub_size_t len);
typedef void (*sz_stm_free_t) (struct sz_stm *stm);

struct sz_stm
{
	sz_stm_read_t read;
	sz_stm_free_t free;
};

/* buffered packed-side input shared by the coder implementations */
struct sz_in
{
	struct sz_stm *src;
	grub_uint8_t *buf;
	grub_size_t pos;
	grub_size_t len;
	int eof;
};

/* adopts src regardless of the outcome */
static grub_err_t
sz_in_init (struct sz_in *in, struct sz_stm *src)
{
	in->src = src;
	in->buf = grub_malloc (SZ_IBUF_SIZE);
	if (!in->buf)
		return grub_errno;
	return GRUB_ERR_NONE;
}

static void
sz_in_fini (struct sz_in *in)
{
	if (in->src)
		in->src->free (in->src);
	grub_free (in->buf);
}

static grub_ssize_t
sz_in_fill (struct sz_in *in)
{
	grub_ssize_t got;

	if (in->eof)
		return 0;
	got = in->src->read (in->src, in->buf, SZ_IBUF_SIZE);
	if (got < 0)
		return -1;
	in->pos = 0;
	in->len = (grub_size_t) got;
	if (got == 0)
		in->eof = 1;
	return got;
}

struct sz_src
{
	struct sz_stm stm;
	grub_disk_t disk;
	grub_uint64_t pos;
	grub_uint64_t left;
};

static grub_ssize_t
sz_src_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_src *s = (struct sz_src *) stm;

	if ((grub_uint64_t) len > s->left)
		len = (grub_size_t) s->left;
	if (len == 0)
		return 0;
	if (grub_disk_read (s->disk, 0, s->pos, len, buf))
		return -1;
	s->pos += len;
	s->left -= len;
	return (grub_ssize_t) len;
}

static void
sz_src_free (struct sz_stm *stm)
{
	grub_free (stm);
}

static struct sz_stm *
sz_src_create (struct grub_7z_data *data, grub_uint32_t folder_index,
	       unsigned pack_slot)
{
	const CSzAr *ar = &data->db.db;
	grub_uint32_t base = ar->FoStartPackStreamIndex[folder_index]
			     + (grub_uint32_t) pack_slot;
	struct sz_src *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
		return 0;
	s->stm.read = sz_src_read;
	s->stm.free = sz_src_free;
	s->disk = data->disk;
	s->pos = data->db.dataPos + ar->PackPositions[base];
	s->left = ar->PackPositions[base + 1] - ar->PackPositions[base];
	return &s->stm;
}

struct sz_lzma
{
	struct sz_stm stm;
	struct sz_in in;
	CLzmaDec dec;
	grub_uint64_t out_left;
};

static grub_ssize_t
sz_lzma_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_lzma *s = (struct sz_lzma *) stm;
	grub_size_t done = 0;

	if ((grub_uint64_t) len > s->out_left)
		len = (grub_size_t) s->out_left;
	if (len == 0)
		return 0;

	while (done < len)
	{
		SizeT dl, sl;
		ELzmaStatus st;

		if (s->in.pos == s->in.len && !s->in.eof
		    && sz_in_fill (&s->in) < 0)
			return -1;

		dl = len - done;
		sl = s->in.len - s->in.pos;
		if (LzmaDec_DecodeToBuf (&s->dec, buf + done, &dl,
					 s->in.buf + s->in.pos, &sl,
					 LZMA_FINISH_ANY, &st) != SZ_OK)
			return sz_data_error ();
		s->in.pos += sl;
		done += dl;
		s->out_left -= dl;

		if (dl == 0 && sl == 0
		    && (s->in.eof || s->in.pos < s->in.len))
			return sz_data_error ();
	}
	return (grub_ssize_t) done;
}

static void
sz_lzma_free (struct sz_stm *stm)
{
	struct sz_lzma *s = (struct sz_lzma *) stm;

	LzmaDec_Free (&s->dec, &sz_allocator);
	sz_in_fini (&s->in);
	grub_free (s);
}

static struct sz_stm *
sz_lzma_create (struct sz_stm *src, const grub_uint8_t *props,
		unsigned props_size, grub_uint64_t unp)
{
	struct sz_lzma *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_lzma_read;
	s->stm.free = sz_lzma_free;
	LzmaDec_CONSTRUCT (&s->dec)
	s->out_left = unp;
	if (sz_in_init (&s->in, src))
		goto fail;
	if (props_size != LZMA_PROPS_SIZE)
	{
		grub_error (GRUB_ERR_BAD_FS, "bad lzma properties");
		goto fail;
	}
	if (LzmaDec_Allocate (&s->dec, props, props_size, &sz_allocator)
	    != SZ_OK)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_FS, "bad lzma properties");
		goto fail;
	}
	LzmaDec_Init (&s->dec);
	return &s->stm;

fail:
	sz_lzma_free (&s->stm);
	return 0;
}

struct sz_lzma2
{
	struct sz_stm stm;
	struct sz_in in;
	CLzma2Dec dec;
	grub_uint64_t out_left;
};

static grub_ssize_t
sz_lzma2_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_lzma2 *s = (struct sz_lzma2 *) stm;
	grub_size_t done = 0;

	if ((grub_uint64_t) len > s->out_left)
		len = (grub_size_t) s->out_left;
	if (len == 0)
		return 0;

	while (done < len)
	{
		SizeT dl, sl;
		ELzmaStatus st;

		if (s->in.pos == s->in.len && !s->in.eof
		    && sz_in_fill (&s->in) < 0)
			return -1;

		dl = len - done;
		sl = s->in.len - s->in.pos;
		if (Lzma2Dec_DecodeToBuf (&s->dec, buf + done, &dl,
					  s->in.buf + s->in.pos, &sl,
					  LZMA_FINISH_ANY, &st) != SZ_OK)
			return sz_data_error ();
		s->in.pos += sl;
		done += dl;
		s->out_left -= dl;

		if (dl == 0 && sl == 0
		    && (s->in.eof || s->in.pos < s->in.len))
			return sz_data_error ();
	}
	return (grub_ssize_t) done;
}

static void
sz_lzma2_free (struct sz_stm *stm)
{
	struct sz_lzma2 *s = (struct sz_lzma2 *) stm;

	Lzma2Dec_Free (&s->dec, &sz_allocator);
	sz_in_fini (&s->in);
	grub_free (s);
}

static struct sz_stm *
sz_lzma2_create (struct sz_stm *src, const grub_uint8_t *props,
		 unsigned props_size, grub_uint64_t unp)
{
	struct sz_lzma2 *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_lzma2_read;
	s->stm.free = sz_lzma2_free;
	Lzma2Dec_CONSTRUCT (&s->dec)
	s->out_left = unp;
	if (sz_in_init (&s->in, src))
		goto fail;
	if (props_size != 1)
	{
		grub_error (GRUB_ERR_BAD_FS, "bad lzma2 properties");
		goto fail;
	}
	if (Lzma2Dec_Allocate (&s->dec, props[0], &sz_allocator) != SZ_OK)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_FS, "bad lzma2 properties");
		goto fail;
	}
	Lzma2Dec_Init (&s->dec);
	return &s->stm;

fail:
	sz_lzma2_free (&s->stm);
	return 0;
}

struct sz_ppmd;

struct sz_ppmd_bytein
{
	IByteIn vt;
	struct sz_ppmd *owner;
};

struct sz_ppmd
{
	struct sz_stm stm;
	struct sz_ppmd_bytein byte_in;
	struct sz_in in;
	CPpmd7 ppmd;
	grub_uint64_t out_left;
	int inited;
	int extra;	/* ran past the end of the packed stream */
	int io_err;
};

static Byte
sz_ppmd_byte (IByteInPtr pp)
{
	struct sz_ppmd *s = ((struct sz_ppmd_bytein *) pp)->owner;

	if (s->in.pos == s->in.len)
	{
		grub_ssize_t got;

		if (s->in.eof)
		{
			s->extra = 1;
			return 0;
		}
		got = sz_in_fill (&s->in);
		if (got < 0)
		{
			s->extra = 1;
			s->io_err = 1;
			return 0;
		}
		if (got == 0)
		{
			s->extra = 1;
			return 0;
		}
	}
	return s->in.buf[s->in.pos++];
}

static grub_ssize_t
sz_ppmd_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_ppmd *s = (struct sz_ppmd *) stm;
	grub_size_t i;

	if ((grub_uint64_t) len > s->out_left)
		len = (grub_size_t) s->out_left;
	if (len == 0)
		return 0;

	if (!s->inited)
	{
		if (!Ppmd7z_RangeDec_Init (&s->ppmd.rc.dec) || s->extra)
		{
			if (s->io_err)
				return -1;
			return sz_data_error ();
		}
		s->inited = 1;
	}

	for (i = 0; i < len; i++)
	{
		int sym = Ppmd7z_DecodeSymbol (&s->ppmd);

		if (s->extra || sym < 0)
		{
			if (s->io_err)
				return -1;
			return sz_data_error ();
		}
		buf[i] = (grub_uint8_t) sym;
	}
	s->out_left -= len;
	return (grub_ssize_t) len;
}

static void
sz_ppmd_free (struct sz_stm *stm)
{
	struct sz_ppmd *s = (struct sz_ppmd *) stm;

	Ppmd7_Free (&s->ppmd, &sz_allocator);
	sz_in_fini (&s->in);
	grub_free (s);
}

static struct sz_stm *
sz_ppmd_create (struct sz_stm *src, const grub_uint8_t *props,
		unsigned props_size, grub_uint64_t unp)
{
	struct sz_ppmd *s;
	unsigned order;
	grub_uint32_t mem;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_ppmd_read;
	s->stm.free = sz_ppmd_free;
	s->byte_in.vt.Read = sz_ppmd_byte;
	s->byte_in.owner = s;
	s->out_left = unp;
	Ppmd7_Construct (&s->ppmd);
	if (sz_in_init (&s->in, src))
		goto fail;

	if (props_size != 5)
	{
		grub_error (GRUB_ERR_BAD_FS, "bad ppmd properties");
		goto fail;
	}
	order = props[0];
	mem = (grub_uint32_t) props[1] | ((grub_uint32_t) props[2] << 8)
	      | ((grub_uint32_t) props[3] << 16)
	      | ((grub_uint32_t) props[4] << 24);
	if (order < PPMD7_MIN_ORDER || order > PPMD7_MAX_ORDER
	    || mem < PPMD7_MIN_MEM_SIZE || mem > PPMD7_MAX_MEM_SIZE)
	{
		grub_error (GRUB_ERR_BAD_FS, "bad ppmd properties");
		goto fail;
	}
	if (!Ppmd7_Alloc (&s->ppmd, mem, &sz_allocator))
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
		goto fail;
	}
	Ppmd7_Init (&s->ppmd, order);
	s->ppmd.rc.dec.Stream = &s->byte_in.vt;
	return &s->stm;

fail:
	sz_ppmd_free (&s->stm);
	return 0;
}

struct sz_delta
{
	struct sz_stm stm;
	struct sz_stm *src;
	Byte state[DELTA_STATE_SIZE];
	unsigned dist;
};

static grub_ssize_t
sz_delta_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_delta *s = (struct sz_delta *) stm;
	grub_ssize_t got;

	got = s->src->read (s->src, buf, len);
	if (got > 0)
		Delta_Decode (s->state, s->dist, buf, (grub_size_t) got);
	return got;
}

static void
sz_delta_free (struct sz_stm *stm)
{
	struct sz_delta *s = (struct sz_delta *) stm;

	if (s->src)
		s->src->free (s->src);
	grub_free (s);
}

static struct sz_stm *
sz_delta_create (struct sz_stm *src, unsigned dist)
{
	struct sz_delta *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_delta_read;
	s->stm.free = sz_delta_free;
	s->src = src;
	s->dist = dist;
	Delta_Init (s->state);
	return &s->stm;
}

struct sz_bra
{
	struct sz_stm stm;
	struct sz_stm *src;
	grub_uint32_t method;
	grub_uint32_t pc;
	grub_uint32_t x86_state;
	grub_uint8_t *buf;
	grub_size_t out_pos;	/* consumed part of the converted region */
	grub_size_t conv_len;	/* converted bytes at the buffer start */
	grub_size_t fill;	/* total valid bytes */
	int src_eof;
};

static grub_uint8_t *
sz_swap_convert (grub_uint8_t *p, grub_size_t size, unsigned step)
{
	grub_uint8_t *end = p + (size - size % step);
	grub_uint8_t *q;

	for (q = p; q < end; q += step)
	{
		grub_uint8_t t = q[0];

		if (step == 2)
		{
			q[0] = q[1];
			q[1] = t;
		}
		else
		{
			q[0] = q[3];
			q[3] = t;
			t = q[1];
			q[1] = q[2];
			q[2] = t;
		}
	}
	return end;
}

static grub_uint8_t *
sz_bra_convert (struct sz_bra *s, grub_uint8_t *p, grub_size_t size)
{
	switch (s->method)
	{
	case SZ_M_BCJ:
		return z7_BranchConvSt_X86_Dec (p, size, s->pc, &s->x86_state);
	case SZ_M_ARM:
		return z7_BranchConv_ARM_Dec (p, size, s->pc);
	case SZ_M_ARMT:
		return z7_BranchConv_ARMT_Dec (p, size, s->pc);
	case SZ_M_ARM64:
		return z7_BranchConv_ARM64_Dec (p, size, s->pc);
	case SZ_M_PPC:
		return z7_BranchConv_PPC_Dec (p, size, s->pc);
	case SZ_M_SPARC:
		return z7_BranchConv_SPARC_Dec (p, size, s->pc);
	case SZ_M_IA64:
		return z7_BranchConv_IA64_Dec (p, size, s->pc);
	case SZ_M_RISCV:
		return z7_BranchConv_RISCV_Dec (p, size, s->pc);
	case SZ_M_SWAP2:
		return sz_swap_convert (p, size, 2);
	default:	/* SZ_M_SWAP4 */
		return sz_swap_convert (p, size, 4);
	}
}

static grub_ssize_t
sz_bra_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_bra *s = (struct sz_bra *) stm;
	grub_size_t n;

	while (s->out_pos == s->conv_len)
	{
		grub_uint8_t *end;

		if (s->out_pos)
		{
			grub_memmove (s->buf, s->buf + s->out_pos,
				      s->fill - s->out_pos);
			s->fill -= s->out_pos;
			s->out_pos = 0;
			s->conv_len = 0;
		}
		while (s->fill < SZ_BRA_BUF && !s->src_eof)
		{
			grub_ssize_t got = s->src->read (s->src,
							 s->buf + s->fill,
							 SZ_BRA_BUF - s->fill);

			if (got < 0)
				return -1;
			if (got == 0)
			{
				s->src_eof = 1;
				break;
			}
			s->fill += (grub_size_t) got;
		}
		if (s->fill == 0)
			return 0;

		end = sz_bra_convert (s, s->buf, s->fill);
		s->conv_len = (grub_size_t) (end - s->buf);
		s->pc += (grub_uint32_t) s->conv_len;
		if (s->conv_len == 0)
		{
			if (s->src_eof)
				s->conv_len = s->fill;	/* flush the tail */
			else
				return sz_data_error ();
		}
	}

	n = s->conv_len - s->out_pos;
	if (n > len)
		n = len;
	grub_memcpy (buf, s->buf + s->out_pos, n);
	s->out_pos += n;
	return (grub_ssize_t) n;
}

static void
sz_bra_free (struct sz_stm *stm)
{
	struct sz_bra *s = (struct sz_bra *) stm;

	if (s->src)
		s->src->free (s->src);
	grub_free (s->buf);
	grub_free (s);
}

static struct sz_stm *
sz_bra_create (struct sz_stm *src, grub_uint32_t method, grub_uint32_t pc)
{
	struct sz_bra *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_bra_read;
	s->stm.free = sz_bra_free;
	s->src = src;
	s->method = method;
	s->pc = pc;
	s->x86_state = Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL;
	s->buf = grub_malloc (SZ_BRA_BUF);
	if (!s->buf)
	{
		sz_bra_free (&s->stm);
		return 0;
	}
	return &s->stm;
}

struct sz_bcj2
{
	struct sz_stm stm;
	struct sz_stm *src[BCJ2_NUM_STREAMS];
	grub_uint8_t *buf[BCJ2_NUM_STREAMS];
	grub_size_t have[BCJ2_NUM_STREAMS];
	int eof[BCJ2_NUM_STREAMS];
	CBcj2Dec dec;
	grub_uint64_t out_left;
};

static grub_ssize_t
sz_bcj2_refill (struct sz_bcj2 *s, unsigned i)
{
	grub_size_t consumed = (grub_size_t) (s->dec.bufs[i] - s->buf[i]);
	grub_size_t hand;

	if (consumed)
	{
		grub_memmove (s->buf[i], s->buf[i] + consumed,
			      s->have[i] - consumed);
		s->have[i] -= consumed;
	}
	while (s->have[i] < SZ_BCJ2_BUF && !s->eof[i])
	{
		grub_ssize_t got = s->src[i]->read (s->src[i],
						    s->buf[i] + s->have[i],
						    SZ_BCJ2_BUF - s->have[i]);

		if (got < 0)
			return -1;
		if (got == 0)
		{
			s->eof[i] = 1;
			break;
		}
		s->have[i] += (grub_size_t) got;
	}

	hand = s->have[i];
	if (BCJ2_IS_32BIT_STREAM (i) && !s->eof[i])
		hand -= hand % 4;
	if (hand == 0)
		return sz_data_error ();	/* decoder still wants data */
	s->dec.bufs[i] = s->buf[i];
	s->dec.lims[i] = s->buf[i] + hand;
	return (grub_ssize_t) hand;
}

static grub_ssize_t
sz_bcj2_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_bcj2 *s = (struct sz_bcj2 *) stm;

	if ((grub_uint64_t) len > s->out_left)
		len = (grub_size_t) s->out_left;
	if (len == 0)
		return 0;

	s->dec.dest = buf;
	s->dec.destLim = buf + len;

	for (;;)
	{
		if (Bcj2Dec_Decode (&s->dec) != SZ_OK)
			return sz_data_error ();
		if (s->dec.dest == s->dec.destLim)
			break;
		if (s->dec.state < BCJ2_NUM_STREAMS)
		{
			/*
			 * The consumed part of this input window is gone;
			 * shift the leftover and pull more from the chain.
			 */
			if (sz_bcj2_refill (s, s->dec.state) < 0)
				return -1;
			continue;
		}
		return sz_data_error ();
	}

	s->out_left -= len;
	return (grub_ssize_t) len;
}

static void
sz_bcj2_free (struct sz_stm *stm)
{
	struct sz_bcj2 *s = (struct sz_bcj2 *) stm;
	unsigned i;

	for (i = 0; i < BCJ2_NUM_STREAMS; i++)
	{
		if (s->src[i])
			s->src[i]->free (s->src[i]);
		grub_free (s->buf[i]);
	}
	grub_free (s);
}

static struct sz_stm *
sz_bcj2_create (struct sz_stm **ins, grub_uint64_t unp)
{
	struct sz_bcj2 *s;
	unsigned i;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		for (i = 0; i < BCJ2_NUM_STREAMS; i++)
			ins[i]->free (ins[i]);
		return 0;
	}
	s->stm.read = sz_bcj2_read;
	s->stm.free = sz_bcj2_free;
	for (i = 0; i < BCJ2_NUM_STREAMS; i++)
		s->src[i] = ins[i];
	s->out_left = unp;
	for (i = 0; i < BCJ2_NUM_STREAMS; i++)
	{
		s->buf[i] = grub_malloc (SZ_BCJ2_BUF);
		if (!s->buf[i])
		{
			sz_bcj2_free (&s->stm);
			return 0;
		}
	}
	Bcj2Dec_Init (&s->dec);
	for (i = 0; i < BCJ2_NUM_STREAMS; i++)
	{
		s->dec.bufs[i] = s->buf[i];
		s->dec.lims[i] = s->buf[i];
	}
	return &s->stm;
}

struct sz_bz
{
	struct sz_stm stm;
	struct sz_in in;
	bz_stream strm;
	grub_uint64_t out_left;
	int inited;
};

static grub_ssize_t
sz_bz_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_bz *s = (struct sz_bz *) stm;
	grub_size_t done = 0;

	if ((grub_uint64_t) len > s->out_left)
		len = (grub_size_t) s->out_left;
	if (len == 0)
		return 0;

	while (done < len)
	{
		grub_size_t chunk = len - done;
		grub_size_t in_avail;
		unsigned out_got, in_got;
		int r;

		if (!s->inited)
		{
			grub_memset (&s->strm, 0, sizeof (s->strm));
			if (BZ2_bzDecompressInit (&s->strm, 0, 0) != BZ_OK)
				return sz_data_error ();
			s->inited = 1;
		}
		if (s->in.pos == s->in.len && !s->in.eof
		    && sz_in_fill (&s->in) < 0)
			return -1;

		if (chunk > (1u << 30))
			chunk = 1u << 30;
		in_avail = s->in.len - s->in.pos;
		s->strm.next_in = (char *) (s->in.buf + s->in.pos);
		s->strm.avail_in = (unsigned) in_avail;
		s->strm.next_out = (char *) (buf + done);
		s->strm.avail_out = (unsigned) chunk;

		r = BZ2_bzDecompress (&s->strm);

		in_got = (unsigned) in_avail - s->strm.avail_in;
		out_got = (unsigned) chunk - s->strm.avail_out;
		s->in.pos += in_got;
		done += out_got;

		if (r == BZ_STREAM_END)
		{
			/* the coder may concatenate several bzip2 streams */
			BZ2_bzDecompressEnd (&s->strm);
			s->inited = 0;
			if (done == len)
				break;
			if (s->in.pos == s->in.len && s->in.eof)
				return sz_data_error ();
			continue;
		}
		if (r != BZ_OK)
			return sz_data_error ();
		if (out_got == 0 && in_got == 0 && s->in.eof)
			return sz_data_error ();
	}

	s->out_left -= done;
	return (grub_ssize_t) done;
}

static void
sz_bz_free (struct sz_stm *stm)
{
	struct sz_bz *s = (struct sz_bz *) stm;

	if (s->inited)
		BZ2_bzDecompressEnd (&s->strm);
	sz_in_fini (&s->in);
	grub_free (s);
}

static struct sz_stm *
sz_bz_create (struct sz_stm *src, grub_uint64_t unp)
{
	struct sz_bz *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_bz_read;
	s->stm.free = sz_bz_free;
	s->out_left = unp;
	if (sz_in_init (&s->in, src))
	{
		sz_bz_free (&s->stm);
		return 0;
	}
	return &s->stm;
}

struct sz_infl
{
	struct sz_stm stm;
	struct sz_in in;
	tinfl_decompressor *infl;
	grub_uint8_t *dict;
	grub_size_t dict_pos;	/* write cursor inside the window */
	grub_size_t out_start;	/* pending output start */
	grub_size_t out_avail;	/* pending output bytes */
	grub_uint64_t out_left;
	int done;
};

static grub_ssize_t
sz_infl_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_infl *s = (struct sz_infl *) stm;
	grub_size_t done = 0;

	if ((grub_uint64_t) len > s->out_left)
		len = (grub_size_t) s->out_left;
	if (len == 0)
		return 0;

	while (done < len)
	{
		size_t in_bytes, out_bytes;
		tinfl_status st;

		if (s->out_avail)
		{
			grub_size_t n = s->out_avail;

			if (n > len - done)
				n = len - done;
			grub_memcpy (buf + done, s->dict + s->out_start, n);
			s->out_start += n;
			s->out_avail -= n;
			done += n;
			continue;
		}
		if (s->done)
			return sz_data_error ();	/* short stream */

		if (s->in.pos == s->in.len && !s->in.eof
		    && sz_in_fill (&s->in) < 0)
			return -1;

		in_bytes = s->in.len - s->in.pos;
		out_bytes = TINFL_LZ_DICT_SIZE - s->dict_pos;
		st = tinfl_decompress (s->infl, s->in.buf + s->in.pos,
				       &in_bytes, s->dict,
				       s->dict + s->dict_pos, &out_bytes,
				       s->in.eof
				       ? 0 : TINFL_FLAG_HAS_MORE_INPUT);
		s->in.pos += in_bytes;
		s->out_start = s->dict_pos;
		s->out_avail = out_bytes;
		s->dict_pos = (s->dict_pos + out_bytes)
			      & (TINFL_LZ_DICT_SIZE - 1);

		if (st == TINFL_STATUS_DONE)
			s->done = 1;
		else if (st < TINFL_STATUS_DONE)
			return sz_data_error ();
		else if (st == TINFL_STATUS_NEEDS_MORE_INPUT && s->in.eof
			 && s->out_avail == 0)
			return sz_data_error ();
	}

	s->out_left -= done;
	return (grub_ssize_t) done;
}

static void
sz_infl_free (struct sz_stm *stm)
{
	struct sz_infl *s = (struct sz_infl *) stm;

	grub_free (s->infl);
	grub_free (s->dict);
	sz_in_fini (&s->in);
	grub_free (s);
}

static struct sz_stm *
sz_infl_create (struct sz_stm *src, grub_uint64_t unp)
{
	struct sz_infl *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_infl_read;
	s->stm.free = sz_infl_free;
	s->out_left = unp;
	if (sz_in_init (&s->in, src))
		goto fail;
	s->infl = grub_malloc (sizeof (*s->infl));
	s->dict = grub_malloc (TINFL_LZ_DICT_SIZE);
	if (!s->infl || !s->dict)
		goto fail;
	tinfl_init (s->infl);
	return &s->stm;

fail:
	sz_infl_free (&s->stm);
	return 0;
}

struct sz_zstd
{
	struct sz_stm stm;
	struct sz_in in;
	ZSTD_DStream *ds;
	grub_uint64_t out_left;
};

static grub_ssize_t
sz_zstd_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_zstd *s = (struct sz_zstd *) stm;
	grub_size_t done = 0;

	if ((grub_uint64_t) len > s->out_left)
		len = (grub_size_t) s->out_left;
	if (len == 0)
		return 0;

	while (done < len)
	{
		ZSTD_inBuffer ib;
		ZSTD_outBuffer ob;
		size_t r;

		if (s->in.pos == s->in.len && !s->in.eof
		    && sz_in_fill (&s->in) < 0)
			return -1;

		ib.src = s->in.buf;
		ib.size = s->in.len;
		ib.pos = s->in.pos;
		ob.dst = buf;
		ob.size = len;
		ob.pos = done;

		r = ZSTD_decompressStream (s->ds, &ob, &ib);
		if (ZSTD_isError (r))
			return sz_data_error ();

		if (ib.pos == s->in.pos && ob.pos == done && s->in.eof)
			return sz_data_error ();
		s->in.pos = ib.pos;
		done = ob.pos;
	}

	s->out_left -= done;
	return (grub_ssize_t) done;
}

static void
sz_zstd_free (struct sz_stm *stm)
{
	struct sz_zstd *s = (struct sz_zstd *) stm;

	if (s->ds)
		ZSTD_freeDStream (s->ds);
	sz_in_fini (&s->in);
	grub_free (s);
}

static struct sz_stm *
sz_zstd_create (struct sz_stm *src, grub_uint64_t unp)
{
	struct sz_zstd *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_zstd_read;
	s->stm.free = sz_zstd_free;
	s->out_left = unp;
	if (sz_in_init (&s->in, src))
		goto fail;
	s->ds = ZSTD_createDStream ();
	if (!s->ds)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
		goto fail;
	}
	return &s->stm;

fail:
	sz_zstd_free (&s->stm);
	return 0;
}

/*
 * The 7-Zip-zstd fork's coder stream is a sequence of standard LZ4 frames; the
 * multi-threaded writer interleaves skippable frames as chunk hints.
 * Frame parsing mirrors io\lz4io.c, including the 64 KiB rolling
 * dictionary for linked blocks.
 */

#define SZ_LZ4_MAGIC		0x184D2204u
#define SZ_LZ4_MAGIC_SKIP	0x184D2A50u	/* low nibble is free */
#define SZ_LZ4_DICT_SIZE	(64 * 1024)

struct sz_lz4
{
	struct sz_stm stm;
	struct sz_in in;
	grub_uint64_t out_left;

	int in_frame;
	int b_indep;
	int b_checksum;
	int c_checksum;
	grub_size_t max_block;

	grub_uint8_t *cbuf;
	grub_uint8_t *ubuf;
	grub_size_t buf_size;	/* capacity of cbuf/ubuf */
	grub_uint8_t *dict;
	grub_size_t dict_size;

	grub_uint32_t u_size;	/* current decoded block */
	grub_uint32_t u_pos;
};

/* reads exactly n packed bytes; anything less is a data error */
static grub_err_t
sz_lz4_pull (struct sz_lz4 *s, grub_uint8_t *dst, grub_size_t n)
{
	grub_size_t done = 0;

	while (done < n)
	{
		grub_size_t avail = s->in.len - s->in.pos;

		if (avail == 0)
		{
			grub_ssize_t got = sz_in_fill (&s->in);

			if (got < 0)
				return grub_errno;
			if (got == 0)
				return grub_error (GRUB_ERR_BAD_FS,
						   "truncated lz4 frame");
			continue;
		}
		if (avail > n - done)
			avail = n - done;
		grub_memcpy (dst + done, s->in.buf + s->in.pos, avail);
		s->in.pos += avail;
		done += avail;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
sz_lz4_skip_in (struct sz_lz4 *s, grub_size_t n)
{
	while (n)
	{
		grub_size_t avail = s->in.len - s->in.pos;

		if (avail == 0)
		{
			grub_ssize_t got = sz_in_fill (&s->in);

			if (got < 0)
				return grub_errno;
			if (got == 0)
				return grub_error (GRUB_ERR_BAD_FS,
						   "truncated lz4 frame");
			continue;
		}
		if (avail > n)
			avail = n;
		s->in.pos += avail;
		n -= avail;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
sz_lz4_read_u32 (struct sz_lz4 *s, grub_uint32_t *v)
{
	grub_uint8_t b[4];
	grub_err_t err = sz_lz4_pull (s, b, 4);

	if (err)
		return err;
	*v = (grub_uint32_t) b[0] | ((grub_uint32_t) b[1] << 8)
	     | ((grub_uint32_t) b[2] << 16) | ((grub_uint32_t) b[3] << 24);
	return GRUB_ERR_NONE;
}

static grub_err_t
sz_lz4_frame_header (struct sz_lz4 *s)
{
	grub_uint8_t desc[15];
	grub_size_t desc_len = 2;
	unsigned flg, bd, bsid;
	grub_err_t err;

	err = sz_lz4_pull (s, desc, 2);
	if (err)
		return err;
	flg = desc[0];
	bd = desc[1];
	if ((flg >> 6) != 1 || (flg & 0x02) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "bad lz4 frame header");
	if (flg & 0x01)
		return grub_error (GRUB_ERR_BAD_FS,
				   "lz4 external dictionaries are not supported");
	if ((bd & 0x8f) != 0)
		return grub_error (GRUB_ERR_BAD_FS, "bad lz4 frame header");
	bsid = (bd >> 4) & 7;
	if (bsid < 4)
		return grub_error (GRUB_ERR_BAD_FS, "bad lz4 frame header");

	if (flg & 0x08)		/* content size */
	{
		err = sz_lz4_pull (s, desc + desc_len, 8);
		if (err)
			return err;
		desc_len += 8;
	}

	/* header checksum: second byte of XXH32 over the descriptor */
	err = sz_lz4_pull (s, desc + desc_len, 1);
	if (err)
		return err;
	if (((XXH32 (desc, desc_len, 0) >> 8) & 0xFF) != desc[desc_len])
		return grub_error (GRUB_ERR_BAD_FS,
				   "lz4 frame header checksum mismatch");

	s->b_indep = (flg & 0x20) != 0;
	s->b_checksum = (flg & 0x10) != 0;
	s->c_checksum = (flg & 0x04) != 0;
	s->max_block = (grub_size_t) 1 << (2 * bsid + 8);

	if (s->max_block > s->buf_size)
	{
		grub_free (s->cbuf);
		grub_free (s->ubuf);
		s->buf_size = 0;
		s->cbuf = grub_malloc (s->max_block);
		s->ubuf = grub_malloc (s->max_block);
		if (!s->cbuf || !s->ubuf)
			return grub_errno;
		s->buf_size = s->max_block;
	}

	s->dict_size = 0;	/* linked blocks never cross frames */
	s->in_frame = 1;
	return GRUB_ERR_NONE;
}

static void
sz_lz4_update_dict (struct sz_lz4 *s)
{
	grub_size_t keep;

	if (s->b_indep)
		return;
	if (s->u_size >= SZ_LZ4_DICT_SIZE)
	{
		grub_memcpy (s->dict, s->ubuf + s->u_size - SZ_LZ4_DICT_SIZE,
			     SZ_LZ4_DICT_SIZE);
		s->dict_size = SZ_LZ4_DICT_SIZE;
		return;
	}
	keep = SZ_LZ4_DICT_SIZE - s->u_size;
	if (keep > s->dict_size)
		keep = s->dict_size;
	if (keep != 0)
		grub_memmove (s->dict, s->dict + s->dict_size - keep, keep);
	grub_memcpy (s->dict + keep, s->ubuf, s->u_size);
	s->dict_size = keep + s->u_size;
}

/* decodes the next data block of the current frame into ubuf */
static grub_err_t
sz_lz4_next_block (struct sz_lz4 *s)
{
	for (;;)
	{
		grub_uint32_t hdr, size;
		int uncompressed;
		int result;
		grub_err_t err;

		if (!s->in_frame)
		{
			grub_uint32_t magic;

			err = sz_lz4_read_u32 (s, &magic);
			if (err)
				return err;
			if ((magic & 0xFFFFFFF0u) == SZ_LZ4_MAGIC_SKIP)
			{
				err = sz_lz4_read_u32 (s, &size);
				if (err)
					return err;
				err = sz_lz4_skip_in (s, size);
				if (err)
					return err;
				continue;
			}
			if (magic != SZ_LZ4_MAGIC)
				return grub_error (GRUB_ERR_BAD_FS,
						   "bad lz4 frame magic");
			err = sz_lz4_frame_header (s);
			if (err)
				return err;
			continue;
		}

		err = sz_lz4_read_u32 (s, &hdr);
		if (err)
			return err;
		if (hdr == 0)	/* EndMark */
		{
			if (s->c_checksum)
			{
				err = sz_lz4_skip_in (s, 4);
				if (err)
					return err;
			}
			s->in_frame = 0;
			continue;
		}

		uncompressed = (hdr & 0x80000000u) != 0;
		size = hdr & 0x7FFFFFFFu;
		if (size == 0 || size > s->max_block)
			return grub_error (GRUB_ERR_BAD_FS,
					   "bad lz4 block size");
		err = sz_lz4_pull (s, s->cbuf, size);
		if (err)
			return err;
		if (s->b_checksum)
		{
			grub_uint32_t stored;

			err = sz_lz4_read_u32 (s, &stored);
			if (err)
				return err;
			if (stored != XXH32 (s->cbuf, size, 0))
				return grub_error (GRUB_ERR_BAD_FS,
					"lz4 block checksum mismatch");
		}

		if (uncompressed)
		{
			grub_memcpy (s->ubuf, s->cbuf, size);
			s->u_size = size;
		}
		else if (s->b_indep)
		{
			result = LZ4_decompress_safe ((const char *) s->cbuf,
						      (char *) s->ubuf,
						      (int) size,
						      (int) s->max_block);
			if (result <= 0)
				return grub_error (GRUB_ERR_BAD_FS,
						   "bad lz4 block");
			s->u_size = (grub_uint32_t) result;
		}
		else
		{
			result = LZ4_decompress_safe_usingDict
				((const char *) s->cbuf, (char *) s->ubuf,
				 (int) size, (int) s->max_block,
				 (const char *) s->dict, (int) s->dict_size);
			if (result <= 0)
				return grub_error (GRUB_ERR_BAD_FS,
						   "bad lz4 block");
			s->u_size = (grub_uint32_t) result;
		}

		sz_lz4_update_dict (s);
		s->u_pos = 0;
		return GRUB_ERR_NONE;
	}
}

static grub_ssize_t
sz_lz4_read (struct sz_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct sz_lz4 *s = (struct sz_lz4 *) stm;
	grub_size_t done = 0;

	if ((grub_uint64_t) len > s->out_left)
		len = (grub_size_t) s->out_left;
	if (len == 0)
		return 0;

	while (done < len)
	{
		grub_size_t n;

		if (s->u_pos == s->u_size)
		{
			if (sz_lz4_next_block (s))
				return -1;
		}
		n = s->u_size - s->u_pos;
		if (n > len - done)
			n = len - done;
		grub_memcpy (buf + done, s->ubuf + s->u_pos, n);
		s->u_pos += (grub_uint32_t) n;
		done += n;
	}

	s->out_left -= done;
	return (grub_ssize_t) done;
}

static void
sz_lz4_free (struct sz_stm *stm)
{
	struct sz_lz4 *s = (struct sz_lz4 *) stm;

	grub_free (s->cbuf);
	grub_free (s->ubuf);
	grub_free (s->dict);
	sz_in_fini (&s->in);
	grub_free (s);
}

static struct sz_stm *
sz_lz4_create (struct sz_stm *src, grub_uint64_t unp)
{
	struct sz_lz4 *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = sz_lz4_read;
	s->stm.free = sz_lz4_free;
	s->out_left = unp;
	if (sz_in_init (&s->in, src))
		goto fail;
	s->dict = grub_malloc (SZ_LZ4_DICT_SIZE);
	if (!s->dict)
		goto fail;
	return &s->stm;

fail:
	sz_lz4_free (&s->stm);
	return 0;
}

static grub_err_t
sz_parse_folder (struct grub_7z_data *data, grub_uint32_t folder_index,
		 CSzFolder *fo)
{
	const CSzAr *ar = &data->db.db;
	CSzData sd;

	sd.Data = ar->CodersData + ar->FoCodersOffsets[folder_index];
	sd.Size = ar->FoCodersOffsets[folder_index + 1]
		  - ar->FoCodersOffsets[folder_index];
	if (SzGetNextFolderItem (fo, &sd) != SZ_OK)
		return grub_error (GRUB_ERR_BAD_FS, "corrupt 7z folder");
	return GRUB_ERR_NONE;
}

/* rejects folders using coders this driver cannot run */
static grub_err_t
sz_check_folder (struct grub_7z_data *data, grub_uint32_t folder_index)
{
	CSzFolder fo;
	grub_uint32_t i;

	if (sz_parse_folder (data, folder_index, &fo))
		return grub_errno;

	for (i = 0; i < fo.NumCoders; i++)
		switch (fo.Coders[i].MethodID)
		{
		case SZ_M_COPY:
		case SZ_M_DELTA:
		case SZ_M_ARM64:
		case SZ_M_RISCV:
		case SZ_M_SWAP2:
		case SZ_M_SWAP4:
		case SZ_M_LZMA2:
		case SZ_M_LZMA:
		case SZ_M_PPMD:
		case SZ_M_DEFLATE:
		case SZ_M_BZIP2:
		case SZ_M_ZSTD:
		case SZ_M_ZSTD_F:
		case SZ_M_LZ4:
		case SZ_M_BCJ:
		case SZ_M_BCJ2:
		case SZ_M_PPC:
		case SZ_M_IA64:
		case SZ_M_ARM:
		case SZ_M_ARMT:
		case SZ_M_SPARC:
			break;
		case SZ_M_AES256:
			return grub_error (GRUB_ERR_BAD_FS,
				"encrypted 7z entries are not supported");
		default:
			return grub_error (GRUB_ERR_BAD_FS,
				"unsupported 7z method 0x%x",
				(unsigned) fo.Coders[i].MethodID);
		}
	return GRUB_ERR_NONE;
}

static struct sz_stm *
sz_build_stream (struct grub_7z_data *data, const CSzFolder *fo,
		 const grub_uint8_t *props_base, grub_uint32_t folder_index,
		 unsigned coder_index, unsigned *visited)
{
	const CSzAr *ar = &data->db.db;
	const CSzCoderInfo *coder = &fo->Coders[coder_index];
	const grub_uint8_t *props = props_base + coder->PropsOffset;
	struct sz_stm *ins[BCJ2_NUM_STREAMS] = { 0, 0, 0, 0 };
	unsigned nin = coder->NumStreams;
	unsigned in_base = 0;
	unsigned i;
	grub_uint32_t pc = 0;
	grub_uint64_t unp;

	if (*visited & (1u << coder_index))
	{
		grub_error (GRUB_ERR_BAD_FS, "corrupt 7z folder");
		return 0;
	}
	*visited |= 1u << coder_index;

	if (nin != (coder->MethodID == SZ_M_BCJ2 ? 4u : 1u)
	    || nin > BCJ2_NUM_STREAMS)
	{
		grub_error (GRUB_ERR_BAD_FS, "unsupported 7z coder layout");
		return 0;
	}

	for (i = 0; i < coder_index; i++)
		in_base += fo->Coders[i].NumStreams;
	unp = ar->CoderUnpackSizes[ar->FoToCoderUnpackSizes[folder_index]
				   + coder_index];

	for (i = 0; i < nin; i++)
	{
		const grub_uint32_t g = (grub_uint32_t) (in_base + i);
		grub_uint32_t b;
		int wired = 0;

		for (b = 0; b < fo->NumBonds; b++)
			if (fo->Bonds[b].InIndex == g)
			{
				ins[i] = sz_build_stream (data, fo, props_base,
							  folder_index,
							  fo->Bonds[b].OutIndex,
							  visited);
				wired = 1;
				break;
			}
		if (!wired)
			for (b = 0; b < fo->NumPackStreams; b++)
				if (fo->PackStreams[b] == g)
				{
					ins[i] = sz_src_create (data,
								folder_index,
								b);
					wired = 1;
					break;
				}
		if (!wired)
			grub_error (GRUB_ERR_BAD_FS, "corrupt 7z folder");
		if (!ins[i])
			goto fail;
	}

	switch (coder->MethodID)
	{
	case SZ_M_COPY:
		if (coder->PropsSize != 0)
			break;
		return ins[0];
	case SZ_M_LZMA:
		return sz_lzma_create (ins[0], props, coder->PropsSize, unp);
	case SZ_M_LZMA2:
		return sz_lzma2_create (ins[0], props, coder->PropsSize, unp);
	case SZ_M_PPMD:
		return sz_ppmd_create (ins[0], props, coder->PropsSize, unp);
	case SZ_M_BZIP2:
		return sz_bz_create (ins[0], unp);
	case SZ_M_DEFLATE:
		return sz_infl_create (ins[0], unp);
	case SZ_M_ZSTD:
	case SZ_M_ZSTD_F:
		return sz_zstd_create (ins[0], unp);
	case SZ_M_LZ4:
		return sz_lz4_create (ins[0], unp);
	case SZ_M_DELTA:
		if (coder->PropsSize != 1)
			break;
		return sz_delta_create (ins[0], (unsigned) props[0] + 1);
	case SZ_M_ARM64:
	case SZ_M_RISCV:
		if (coder->PropsSize == 4)
		{
			pc = (grub_uint32_t) props[0]
			     | ((grub_uint32_t) props[1] << 8)
			     | ((grub_uint32_t) props[2] << 16)
			     | ((grub_uint32_t) props[3] << 24);
			if (pc & (coder->MethodID == SZ_M_ARM64 ? 3u : 1u))
				break;
		}
		else if (coder->PropsSize != 0)
			break;
		return sz_bra_create (ins[0], coder->MethodID, pc);
	case SZ_M_BCJ:
	case SZ_M_PPC:
	case SZ_M_IA64:
	case SZ_M_ARM:
	case SZ_M_ARMT:
	case SZ_M_SPARC:
	case SZ_M_SWAP2:
	case SZ_M_SWAP4:
		if (coder->PropsSize != 0)
			break;
		return sz_bra_create (ins[0], coder->MethodID, 0);
	case SZ_M_BCJ2:
		if (coder->PropsSize != 0)
			break;
		return sz_bcj2_create (ins, unp);
	case SZ_M_AES256:
		grub_error (GRUB_ERR_BAD_FS,
			    "encrypted 7z entries are not supported");
		goto fail;
	default:
		grub_error (GRUB_ERR_BAD_FS, "unsupported 7z method 0x%x",
			    (unsigned) coder->MethodID);
		goto fail;
	}

	grub_error (GRUB_ERR_BAD_FS, "unsupported 7z coder properties");

fail:
	for (i = 0; i < nin; i++)
		if (ins[i])
			ins[i]->free (ins[i]);
	return 0;
}

/* builds the pull chain producing the decoded output of a folder */
static struct sz_stm *
sz_open_folder (struct grub_7z_data *data, grub_uint32_t folder_index)
{
	CSzFolder fo;
	unsigned visited = 0;

	if (sz_parse_folder (data, folder_index, &fo))
		return 0;
	return sz_build_stream (data, &fo,
				data->db.db.CodersData
				+ data->db.db.FoCodersOffsets[folder_index],
				folder_index, fo.UnpackStream, &visited);
}

struct sz_disk_stream
{
	ISeekInStream vt;
	grub_disk_t disk;
	grub_uint64_t size;
	grub_uint64_t pos;
};

static SRes
sz_disk_stream_read (ISeekInStreamPtr pp, void *buf, size_t *size)
{
	struct sz_disk_stream *s = (struct sz_disk_stream *) pp;
	grub_size_t n = *size;

	if (s->pos >= s->size)
	{
		*size = 0;
		return SZ_OK;
	}
	if ((grub_uint64_t) n > s->size - s->pos)
		n = (grub_size_t) (s->size - s->pos);
	if (grub_disk_read (s->disk, 0, s->pos, n, buf))
	{
		grub_errno = GRUB_ERR_NONE;
		return SZ_ERROR_READ;
	}
	s->pos += n;
	*size = n;
	return SZ_OK;
}

static SRes
sz_disk_stream_seek (ISeekInStreamPtr pp, Int64 *pos, ESzSeek origin)
{
	struct sz_disk_stream *s = (struct sz_disk_stream *) pp;
	Int64 base;

	switch (origin)
	{
	case SZ_SEEK_SET:
		base = 0;
		break;
	case SZ_SEEK_CUR:
		base = (Int64) s->pos;
		break;
	case SZ_SEEK_END:
		base = (Int64) s->size;
		break;
	default:
		return SZ_ERROR_PARAM;
	}
	base += *pos;
	if (base < 0)
		return SZ_ERROR_PARAM;
	s->pos = (grub_uint64_t) base;
	*pos = base;
	return SZ_OK;
}

static void
sz_free_data (struct grub_7z_data *data)
{
	grub_uint32_t i;

	if (!data)
		return;
	if (data->names)
	{
		for (i = 0; i < data->db.NumFiles; i++)
			grub_free (data->names[i]);
		grub_free (data->names);
	}
	SzArEx_Free (&data->db, &sz_allocator);
	grub_free (data);
}

static struct grub_7z_data *
grub_7z_mount (grub_disk_t disk)
{
	struct grub_7z_data *data = 0;
	struct sz_disk_stream stream;
	CLookToRead2 look;
	grub_uint8_t magic[k7zSignatureSize];
	grub_uint16_t *u16 = 0;
	grub_size_t u16_max = 0;
	grub_uint32_t i;

	look.buf = 0;

	if (grub_disk_read (disk, 0, 0, sizeof (magic), magic))
		goto fail;
	if (grub_memcmp (magic, k7zSignature, k7zSignatureSize) != 0)
		goto fail;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		goto fail_data;
	data->disk = disk;
	data->disk_size = grub_disk_native_sectors (disk)
			  << GRUB_DISK_SECTOR_BITS;
	SzArEx_Init (&data->db);

	stream.vt.Read = sz_disk_stream_read;
	stream.vt.Seek = sz_disk_stream_seek;
	stream.disk = disk;
	stream.size = data->disk_size;
	stream.pos = 0;

	LookToRead2_CreateVTable (&look, 0);
	look.realStream = &stream.vt;
	look.buf = grub_malloc (SZ_LOOK_BUF);
	if (!look.buf)
		goto fail_data;
	look.bufSize = SZ_LOOK_BUF;
	LookToRead2_INIT (&look)

	if (SzArEx_Open (&data->db, &look.vt, &sz_allocator, &sz_allocator)
	    != SZ_OK)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_FS,
				    "unsupported or corrupt 7z archive");
		goto fail_data;
	}

	if (data->db.NumFiles)
	{
		data->names = grub_calloc (data->db.NumFiles,
					   sizeof (*data->names));
		if (!data->names)
			goto fail_data;
	}
	for (i = 0; i < data->db.NumFiles; i++)
	{
		grub_size_t n16 = SzArEx_GetFileNameUtf16 (&data->db, i, 0);
		grub_uint8_t *end;
		char *name;
		grub_size_t j;

		if (n16 < 2)
			continue;
		if (n16 > u16_max)
		{
			grub_free (u16);
			u16_max = n16;
			u16 = grub_malloc (u16_max * sizeof (*u16));
			if (!u16)
				goto fail_data;
		}
		SzArEx_GetFileNameUtf16 (&data->db, i, (UInt16 *) u16);
		name = grub_malloc ((n16 - 1) * GRUB_MAX_UTF8_PER_UTF16 + 1);
		if (!name)
			goto fail_data;
		end = grub_utf16_to_utf8 ((grub_uint8_t *) name, u16,
					  n16 - 1);
		*end = '\0';
		for (j = 0; name[j]; j++)
			if (name[j] == '\\')
				name[j] = '/';
		data->names[i] = name;
	}

	grub_free (u16);
	grub_free (look.buf);
	return data;

fail_data:
	grub_free (u16);
	grub_free (look.buf);
	sz_free_data (data);
	return 0;

fail:
	grub_error (GRUB_ERR_BAD_FS, "not a 7z filesystem");
	return 0;
}

/* skips leading slashes and returns the normalized path length */
static const char *
sz_norm_path (const char *path, grub_size_t *len)
{
	grub_size_t n;

	while (*path == '/')
		path++;
	n = grub_strlen (path);
	while (n > 0 && path[n - 1] == '/')
		n--;
	*len = n;
	return path;
}

static int
sz_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
		const char **child, grub_size_t *child_len, int *is_dir)
{
	const char *rest;
	const char *slash;

	if (dir_len != 0)
	{
		if (grub_strncmp (name, dir, dir_len) != 0)
			return 0;
		if (name[dir_len] != '/')
			return 0;
		rest = name + dir_len + 1;
	}
	else
		rest = name;

	if (*rest == '\0')
		return 0;
	slash = grub_strchr (rest, '/');
	if (slash)
	{
		*child = rest;
		*child_len = (grub_size_t) (slash - rest);
		*is_dir = 1;
	}
	else
	{
		*child = rest;
		*child_len = grub_strlen (rest);
		*is_dir = 0;
	}
	return *child_len != 0;
}

static int
sz_find_item (struct grub_7z_data *data, const char *name)
{
	grub_size_t len;
	const char *path = sz_norm_path (name, &len);
	grub_uint32_t i;

	for (i = 0; i < data->db.NumFiles; i++)
	{
		const char *n = data->names[i];

		if (!n)
			continue;
		if (grub_strncmp (n, path, len) == 0 && n[len] == '\0')
			return (int) i;
	}
	return -1;
}

static grub_int64_t
sz_ntfs_time (const CNtfsFileTime *t)
{
	grub_uint64_t v = ((grub_uint64_t) t->High << 32) | t->Low;

	return (grub_int64_t) (v / 10000000) - 11644473600LL;
}

static int
sz_is_symlink (struct grub_7z_data *data, grub_uint32_t i)
{
	grub_uint32_t attrib;

	if (!SzBitWithVals_Check (&data->db.Attribs, i))
		return 0;
	attrib = data->db.Attribs.Vals[i];
	if (!(attrib & SZ_ATTR_UNIX_EXTENSION))
		return 0;
	return ((attrib >> 16) & 0xF000) == 0xA000;
}

struct sz_seen
{
	struct sz_seen *next;
	char *name;
};

static grub_uint32_t
sz_hash_name (const char *s)
{
	grub_uint32_t h = 5381;

	while (*s)
		h = h * 33 + (grub_uint8_t) *s++;
	return h & (SZ_SEEN_BUCKETS - 1);
}

/* returns 1 when the name was seen before, -1 on allocation failure */
static int
sz_seen_add (struct sz_seen **buckets, char *name)
{
	const grub_uint32_t h = sz_hash_name (name);
	struct sz_seen *ent;

	for (ent = buckets[h]; ent; ent = ent->next)
		if (grub_strcmp (ent->name, name) == 0)
			return 1;
	ent = grub_malloc (sizeof (*ent));
	if (!ent)
		return -1;
	ent->name = name;
	ent->next = buckets[h];
	buckets[h] = ent;
	return 0;
}

static grub_err_t
grub_7z_dir (grub_device_t device, const char *path,
	     grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_7z_data *data;
	const char *dir;
	grub_size_t dir_len;
	struct sz_seen **buckets;
	grub_uint32_t i;
	int found;
	grub_err_t err = GRUB_ERR_NONE;

	data = grub_7z_mount (device->disk);
	if (!data)
		return grub_errno;

	dir = sz_norm_path (path, &dir_len);
	found = (dir_len == 0);

	buckets = grub_calloc (SZ_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		sz_free_data (data);
		return grub_errno;
	}

	for (i = 0; i < data->db.NumFiles; i++)
	{
		struct grub_dirhook_info info;
		const char *child;
		grub_size_t child_len;
		int child_is_dir;
		char *name;
		int dup;

		if (!data->names[i])
			continue;
		if (!sz_name_in_dir (data->names[i], dir, dir_len,
				     &child, &child_len, &child_is_dir))
		{
			/* the path itself may be a stored directory entry */
			if (dir_len != 0
			    && grub_strcmp (data->names[i], dir) == 0)
				found = 1;
			continue;
		}
		found = 1;

		name = grub_malloc (child_len + 1);
		if (!name)
		{
			err = grub_errno;
			goto out;
		}
		grub_memcpy (name, child, child_len);
		name[child_len] = '\0';

		dup = sz_seen_add (buckets, name);
		if (dup)
		{
			grub_free (name);
			if (dup < 0)
			{
				err = grub_errno;
				goto out;
			}
			continue;
		}

		grub_memset (&info, 0, sizeof (info));
		info.dir = child_is_dir || SzArEx_IsDir (&data->db, i);
		info.inodeset = 1;
		info.inode = i;
		if (!child_is_dir)
		{
			info.symlink = sz_is_symlink (data, i);
			if (SzBitWithVals_Check (&data->db.MTime, i))
			{
				info.mtimeset = 1;
				info.mtime = sz_ntfs_time
					(&data->db.MTime.Vals[i]);
			}
			if (!info.symlink)
			{
				info.sizeset = 1;
				info.size = SzArEx_GetFileSize (&data->db, i);
			}
		}

		if (hook (name, &info, hook_data))
			goto out;
	}

	if (!found)
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
				  "file `%s' not found", path);

out:
	for (i = 0; i < SZ_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct sz_seen *ent = buckets[i];

			buckets[i] = ent->next;
			grub_free (ent->name);
			grub_free (ent);
		}
	grub_free (buckets);
	sz_free_data (data);
	return err;
}

struct grub_7z_file
{
	struct grub_7z_data *data;
	grub_uint32_t folder;
	grub_uint64_t folder_off;	/* file start in the folder output */
	struct sz_stm *stm;
	grub_uint64_t stm_pos;		/* folder output bytes consumed */
	grub_uint8_t *skip_buf;
};

static grub_err_t
grub_7z_open (struct grub_file *file, const char *name)
{
	struct grub_7z_data *data;
	struct grub_7z_file *ctx = 0;
	int index;

	data = grub_7z_mount (file->device->disk);
	if (!data)
		return grub_errno;

	index = sz_find_item (data, name);
	if (index < 0)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found",
			    name);
		goto fail;
	}
	if (SzArEx_IsDir (&data->db, (grub_uint32_t) index))
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "is a directory");
		goto fail;
	}

	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
		goto fail;
	ctx->data = data;
	ctx->folder = data->db.FileToFolder[index];
	if (ctx->folder != SZ_NO_FOLDER)
	{
		const grub_uint32_t first =
			data->db.FolderToFile[ctx->folder];

		if (sz_check_folder (data, ctx->folder))
			goto fail;
		ctx->folder_off = data->db.UnpackPositions[index]
				  - data->db.UnpackPositions[first];
	}

	file->data = ctx;
	file->size = SzArEx_GetFileSize (&data->db, index);
	file->not_easily_seekable = 1;
	return GRUB_ERR_NONE;

fail:
	grub_free (ctx);
	sz_free_data (data);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

static grub_ssize_t
grub_7z_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_7z_file *ctx = file->data;
	grub_uint64_t want;
	grub_size_t done = 0;

	if (len == 0 || ctx->folder == SZ_NO_FOLDER)
		return 0;

	want = ctx->folder_off + file->offset;

	/* going backwards means restarting the folder from scratch */
	if (ctx->stm && want < ctx->stm_pos)
	{
		ctx->stm->free (ctx->stm);
		ctx->stm = 0;
	}
	if (!ctx->stm)
	{
		ctx->stm = sz_open_folder (ctx->data, ctx->folder);
		if (!ctx->stm)
			return -1;
		ctx->stm_pos = 0;
	}

	if (ctx->stm_pos < want && !ctx->skip_buf)
	{
		ctx->skip_buf = grub_malloc (SZ_SKIP_BUF);
		if (!ctx->skip_buf)
			return -1;
	}
	while (ctx->stm_pos < want)
	{
		grub_size_t n = SZ_SKIP_BUF;
		grub_ssize_t got;

		if ((grub_uint64_t) n > want - ctx->stm_pos)
			n = (grub_size_t) (want - ctx->stm_pos);
		got = ctx->stm->read (ctx->stm, ctx->skip_buf, n);
		if (got < 0)
			return -1;
		if (got == 0)
			return sz_data_error ();
		ctx->stm_pos += (grub_uint64_t) got;
	}

	while (done < len)
	{
		grub_ssize_t got = ctx->stm->read (ctx->stm,
						   (grub_uint8_t *) buf + done,
						   len - done);

		if (got < 0)
			return -1;
		if (got == 0)
			break;
		done += (grub_size_t) got;
		ctx->stm_pos += (grub_uint64_t) got;
	}
	return (grub_ssize_t) done;
}

static grub_err_t
grub_7z_close (grub_file_t file)
{
	struct grub_7z_file *ctx = file->data;

	if (ctx)
	{
		if (ctx->stm)
			ctx->stm->free (ctx->stm);
		grub_free (ctx->skip_buf);
		sz_free_data (ctx->data);
		grub_free (ctx);
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_7z_mtime (grub_device_t device, grub_int64_t *tm)
{
	struct grub_7z_data *data;
	grub_uint32_t i;

	*tm = 0;
	data = grub_7z_mount (device->disk);
	if (!data)
		return grub_errno;
	for (i = 0; i < data->db.NumFiles; i++)
		if (SzBitWithVals_Check (&data->db.MTime, i))
		{
			const grub_int64_t t =
				sz_ntfs_time (&data->db.MTime.Vals[i]);

			if (t > *tm)
				*tm = t;
		}
	sz_free_data (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_7z_fs =
{
	.name = "7z",
	.fs_dir = grub_7z_dir,
	.fs_open = grub_7z_open,
	.fs_read = grub_7z_read,
	.fs_close = grub_7z_close,
	.fs_label = 0,
	.fs_mtime = grub_7z_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (sevenzip)
{
	CrcGenerateTable ();
	grub_7z_fs.mod = mod;
	grub_fs_register (&grub_7z_fs);
}

GRUB_MOD_FINI (sevenzip)
{
	grub_fs_unregister (&grub_7z_fs);
}
