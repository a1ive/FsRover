/*
 *  Rover -- Filesystem browser for Windows
 *  RAR 2.9/3.x decoder, ported to C from 7-Zip 26.02
 *  (Rar3Decoder.cpp, Rar3Vm.cpp).  PPMd variant H comes from the
 *  original 7-Zip C sources in 7z/.
 *
 *  This code uses a carryless rangecoder (1999) by Dmitry Subbotin,
 *  public domain.
 *
 *  7-Zip Copyright (C) 1999-2025 Igor Pavlov.
 *  Licensed under the GNU LGPL, with the unRAR license restriction:
 *  this code may not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include "rar_core.h"

#include <Ppmd7.h>

#define kNumHuffmanBits		15

#define kWindowSize		(1u << 22)
#define kWindowMask		(kWindowSize - 1)

#define kNumReps		4
#define kNumLen2Symbols		8
#define kLenTableSize		28
#define kMainTableSize		(256 + 3 + kNumReps + kNumLen2Symbols \
				 + kLenTableSize)
#define kDistTableSize		60
#define kNumAlignBits		4
#define kAlignTableSize		((1 << kNumAlignBits) + 1)
#define kTablesSizesSum		(kMainTableSize + kDistTableSize \
				 + kAlignTableSize + kLenTableSize)

#define kNumAlignReps		15
#define kSymbolReadTable	256
#define kSymbolRep		259

#define kVmDataSizeMax		(1u << 16)
#define kVmCodeSizeMax		(1u << 16)

#define kDistLimit3		(0x2000 - 2)
#define kDistLimit4		(0x40000 - 2)
#define kNormalMatchMinLen	3

/* RAR virtual machine address space */
#define VM_SPACE_SIZE		0x40000u
#define VM_SPACE_MASK		(VM_SPACE_SIZE - 1)
#define VM_GLOBAL_OFFSET	0x3C000u
#define VM_GLOBAL_SIZE		0x2000u
#define VM_FIXED_GLOBAL_SIZE	64u
#define VM_NUM_REGS		8
#define VM_NUM_GP_REGS		(VM_NUM_REGS - 1)

#define VM_GO_BLOCK_SIZE	0x1Cu
#define VM_GO_BLOCK_POS		0x20u
#define VM_GO_EXEC_COUNT	0x2Cu
#define VM_GO_GLOBAL_MEM_OUT	0x30u

#define MAX_UNPACK_FILTERS	8192

static const grub_uint8_t kDistDirectBits[kDistTableSize] =
{
	0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,
	14,14,15,15,
	16,16,16,16,16,16,16,16,16,16,16,16,16,16,
	18,18,18,18,18,18,18,18,18,18,18,18
};

static const grub_uint8_t kLen2DistStarts[kNumLen2Symbols] =
	{ 0,4,8,16,32,64,128,192 };
static const grub_uint8_t kLen2DistDirectBits[kNumLen2Symbols] =
	{ 2,2,3,4,5,6,6,6 };

static grub_uint32_t
my_abs32 (grub_int32_t v)
{
	return (grub_uint32_t) (v < 0 ? -v : v);
}

/* ---------------- RAR3 bit decoder ---------------- */

struct rar3_bitdec
{
	grub_uint32_t value;
	unsigned bitpos;	/* number of buffered bits in value */
	struct rar_bytein stream;
};

static void
rar3_bd_init (struct rar3_bitdec *b, rar_read_cb read_cb, void *opaque)
{
	rar_bytein_init (&b->stream, read_cb, opaque);
	b->bitpos = 0;
	b->value = 0;
}

static int
rar3_bd_extra_read (const struct rar3_bitdec *b)
{
	return (b->stream.extra > 4 || b->bitpos < (b->stream.extra << 3));
}

static grub_uint64_t
rar3_bd_processed (const struct rar3_bitdec *b)
{
	return rar_bytein_processed (&b->stream) - (b->bitpos >> 3);
}

static void
rar3_bd_align (struct rar3_bitdec *b)
{
	b->bitpos &= ~(unsigned) 7;
	b->value = b->value & ((1u << b->bitpos) - 1);
}

static grub_uint32_t
rar3_bd_getval (struct rar3_bitdec *b, unsigned numbits)
{
	if (b->bitpos < numbits)
	{
		b->bitpos += 8;
		b->value = (b->value << 8) | rar_bytein_byte (&b->stream);
		if (b->bitpos < numbits)
		{
			b->bitpos += 8;
			b->value = (b->value << 8)
				   | rar_bytein_byte (&b->stream);
		}
	}
	return b->value >> (b->bitpos - numbits);
}

static void
rar3_bd_movepos (struct rar3_bitdec *b, unsigned numbits)
{
	b->bitpos -= numbits;
	b->value = b->value & ((1u << b->bitpos) - 1);
}

static grub_uint32_t
rar3_bd_readbits (struct rar3_bitdec *b, unsigned numbits)
{
	const grub_uint32_t res = rar3_bd_getval (b, numbits);
	rar3_bd_movepos (b, numbits);
	return res;
}

static grub_uint32_t
rar3_bd_readbits8 (struct rar3_bitdec *b, unsigned numbits)
{
	grub_uint32_t res;

	if (b->bitpos < numbits)
	{
		b->bitpos += 8;
		b->value = (b->value << 8) | rar_bytein_byte (&b->stream);
	}
	b->bitpos -= numbits;
	res = b->value >> b->bitpos;
	b->value = b->value & ((1u << b->bitpos) - 1);
	return res;
}

static grub_uint8_t
rar3_bd_byte_aligned (struct rar3_bitdec *b)
{
	unsigned bitspos;
	grub_uint8_t v;

	if (b->bitpos == 0)
		return rar_bytein_byte (&b->stream);
	bitspos = b->bitpos - 8;
	v = (grub_uint8_t) (b->value >> bitspos);
	b->value = b->value & ((1u << bitspos) - 1);
	b->bitpos = bitspos;
	return v;
}

static int
rar3_bd_huff (struct rar3_bitdec *b, const struct rar_huff *h)
{
	unsigned nb;
	int sym = rar_huff_decode_val (h,
		rar3_bd_getval (b, kNumHuffmanBits), &nb);
	if (sym >= 0)
		rar3_bd_movepos (b, nb);
	return sym;
}

/* ---------------- memory bit decoder (VM code stream) ---------------- */

struct rar3_membits
{
	const grub_uint8_t *data;
	grub_uint32_t bitsize;
	grub_uint32_t bitpos;
};

static grub_uint32_t
rar3_mb_readbits (struct rar3_membits *m, unsigned numbits)
{
	grub_uint32_t res = 0;

	for (;;)
	{
		const unsigned b = m->bitpos < m->bitsize
				   ? (unsigned) m->data[m->bitpos >> 3] : 0;
		const unsigned avail = (unsigned) (8 - (m->bitpos & 7));
		if (numbits <= avail)
		{
			m->bitpos += numbits;
			return res | ((b >> (avail - numbits))
				      & ((1u << numbits) - 1));
		}
		numbits -= avail;
		res |= (grub_uint32_t) (b & ((1u << avail) - 1)) << numbits;
		m->bitpos += avail;
	}
}

static grub_uint32_t
rar3_mb_read_encoded (struct rar3_membits *m)
{
	const unsigned v = (unsigned) rar3_mb_readbits (m, 2);
	grub_uint32_t res = rar3_mb_readbits (m, 4u << v);
	if (v == 1 && res < 16)
		res = 0xFFFFFF00u | (res << 4) | rar3_mb_readbits (m, 4);
	return res;
}

/* ---------------- standard VM filters ---------------- */

enum rar3_std_filter
{
	SF_E8,
	SF_E8E9,
	SF_ITANIUM,
	SF_RGB,
	SF_AUDIO,
	SF_DELTA
};

static const struct
{
	grub_uint32_t length;
	grub_uint32_t crc;
	enum rar3_std_filter type;
}
kStdFilters[] =
{
	{  53, 0xad576887, SF_E8 },
	{  57, 0x3cd7e57e, SF_E8E9 },
	{ 120, 0x3769893f, SF_ITANIUM },
	{  29, 0x0e06077d, SF_DELTA },
	{ 149, 0x1c2c5dc8, SF_RGB },
	{ 216, 0xbc85e701, SF_AUDIO }
};

static int
rar3_find_std_filter (const grub_uint8_t *code, grub_uint32_t code_size)
{
	const grub_uint32_t crc = rar_crc32 (0, code, code_size);
	unsigned i;

	for (i = 0; i < ARRAY_SIZE (kStdFilters); i++)
		if (kStdFilters[i].crc == crc
		    && kStdFilters[i].length == code_size)
			return (int) i;
	return -1;
}

struct rar3_filter
{
	int std_index;		/* -1 = not a known standard filter */
	int is_supported;
	grub_uint32_t block_size;
	grub_uint32_t exec_count;
};

struct rar3_temp_filter
{
	int used;
	grub_uint32_t init_r[VM_NUM_GP_REGS];
	grub_uint8_t global_data[VM_GLOBAL_SIZE];
	grub_uint32_t global_size;
	grub_uint32_t block_start;
	grub_uint32_t block_size;
	int next_window;
	grub_uint32_t filter_index;
};

struct rar3_dec
{
	struct rar_decoder base;

	int is_solid;
	int solid_allowed;
	int lz_mode;
	int unsupported_filter;
	int item_done;
	int init_done;		/* window/vm/ppmd allocated */

	struct rar3_bitdec bd;
	IByteIn byte_in;	/* PPMd input interface */

	grub_uint8_t *window;
	grub_uint32_t win_pos;
	grub_uint32_t wr_ptr;
	grub_uint64_t lz_size;
	grub_uint64_t unpack_size;
	grub_uint64_t written_file_size;

	struct rar_huff main_dec;
	struct rar_huff dist_dec;
	struct rar_huff align_dec;
	struct rar_huff len_dec;
	grub_uint32_t dist_start[kDistTableSize];

	grub_uint32_t reps[kNumReps];
	grub_uint32_t last_length;

	grub_uint8_t last_levels[kTablesSizesSum];

	grub_uint8_t *vm_data;	/* kVmDataSizeMax + kVmCodeSizeMax */
	grub_uint8_t *vm_code;
	grub_uint8_t *vm_mem;	/* VM_SPACE_SIZE + 4 */
	grub_uint32_t vm_r[VM_NUM_REGS + 1];

	struct rar3_filter *filters;
	unsigned num_filters;
	struct rar3_temp_filter **temp_filters;
	unsigned num_temp_filters;
	unsigned num_empty_temp_filters;
	grub_uint32_t last_filter;

	grub_uint32_t prev_align_bits;
	grub_uint32_t prev_align_count;

	int tables_read;
	int tables_ok;
	int ppm_error;
	int ppm_esc_char;
	CPpmd7 ppmd;
	int ppmd_constructed;
};

/* ---------------- PPMd glue ---------------- */

static void *
rar3_ppmd_alloc (ISzAllocPtr p, grub_size_t size)
{
	(void) p;
	return grub_malloc (size);
}

static void
rar3_ppmd_free (ISzAllocPtr p, void *address)
{
	(void) p;
	grub_free (address);
}

static const ISzAlloc rar3_ppmd_allocator =
	{ rar3_ppmd_alloc, rar3_ppmd_free };

/* the two IByteIn flavours used by the RAR3 PPMd stream */
static struct rar3_dec *
rar3_from_bytein (IByteInPtr pp)
{
	return (struct rar3_dec *)
		((grub_uint8_t *) pp - offsetof (struct rar3_dec, byte_in));
}

static Byte
rar3_wrap_read_byte (IByteInPtr pp)
{
	struct rar3_dec *p = rar3_from_bytein (pp);
	return rar_bytein_byte (&p->bd.stream);
}

static Byte
rar3_wrap_read_bits8 (IByteInPtr pp)
{
	struct rar3_dec *p = rar3_from_bytein (pp);
	return rar3_bd_byte_aligned (&p->bd);
}

#define rar3_ppm_sym(p) Ppmd7a_DecodeSymbol (&(p)->ppmd)

/* ---------------- output ---------------- */

static int
rar3_write_data_to_stream (struct rar3_dec *p, const grub_uint8_t *data,
			   grub_uint32_t size)
{
	return rar_deliver (&p->base, data, size);
}

static int
rar3_write_data (struct rar3_dec *p, const grub_uint8_t *data,
		 grub_uint32_t size)
{
	int res = 0;

	if (p->written_file_size < p->unpack_size)
	{
		grub_uint32_t cur = size;
		const grub_uint64_t remain = p->unpack_size
					     - p->written_file_size;
		if (remain < cur)
			cur = (grub_uint32_t) remain;
		res = rar3_write_data_to_stream (p, data, cur);
	}
	p->written_file_size += size;
	return res;
}

static int
rar3_write_area (struct rar3_dec *p, grub_uint32_t start, grub_uint32_t end)
{
	int res;

	if (start <= end)
		return rar3_write_data (p, p->window + start, end - start);
	res = rar3_write_data (p, p->window + start, kWindowSize - start);
	if (res)
		return res;
	return rar3_write_data (p, p->window, end);
}

/* ---------------- VM standard filter implementations ---------------- */

static void
rar3_vm_set_value (void *addr, grub_uint32_t value)
{
	rar_set_le32 (addr, value);
}

static grub_uint32_t
rar3_vm_get_value (const void *addr)
{
	return rar_get_le32 (addr);
}

static void
rar3_vm_set_block_pos (struct rar3_dec *p, grub_uint32_t v)
{
	rar3_vm_set_value (&p->vm_mem[VM_GLOBAL_OFFSET + VM_GO_BLOCK_POS], v);
}

static grub_uint32_t
rar3_vm_get_global32 (struct rar3_dec *p, grub_uint32_t global_offset)
{
	return rar3_vm_get_value (&p->vm_mem[VM_GLOBAL_OFFSET
					     + global_offset]);
}

static void
rar3_e8e9_decode (grub_uint8_t *data, grub_uint32_t data_size,
		  grub_uint32_t file_offset, int e9)
{
	const grub_uint32_t kFileSize = 0x1000000;
	const grub_uint8_t cmp_mask = (grub_uint8_t) (e9 ? 0xFE : 0xFF);
	grub_uint32_t cur_pos;

	if (data_size <= 4)
		return;
	data_size -= 4;
	for (cur_pos = 0; cur_pos < data_size;)
	{
		cur_pos++;
		if (((*data++) & cmp_mask) == 0xE8)
		{
			const grub_uint32_t offset = cur_pos + file_offset;
			const grub_uint32_t addr = rar3_vm_get_value (data);
			if (addr < kFileSize)
				rar3_vm_set_value (data, addr - offset);
			else if ((addr & 0x80000000) != 0
				 && ((addr + offset) & 0x80000000) == 0)
				rar3_vm_set_value (data, addr + kFileSize);
			data += 4;
			cur_pos += 4;
		}
	}
}

static void
rar3_itanium_decode (grub_uint8_t *data, grub_uint32_t data_size,
		     grub_uint32_t file_offset)
{
	if (data_size <= 21)
		return;
	file_offset >>= 4;
	data_size -= 21;
	data_size += 15;
	data_size >>= 4;
	data_size += file_offset;
	do
	{
		unsigned m = ((grub_uint32_t) 0x334B0000 >> (data[0] & 0x1E))
			     & 3;
		if (m)
		{
			m++;
			do
			{
				grub_uint8_t *q = data
						  + ((grub_size_t) m * 5 - 8);
				if (((q[3] >> m) & 15) == 5)
				{
					const grub_uint32_t kMask = 0xFFFFF;
					grub_uint32_t raw = rar3_vm_get_value (q);
					grub_uint32_t v = raw >> m;
					v -= file_offset;
					v &= kMask;
					raw &= ~(kMask << m);
					raw |= (v << m);
					rar3_vm_set_value (q, raw);
				}
			}
			while (++m <= 4);
		}
		data += 16;
	}
	while (++file_offset != data_size);
}

static void
rar3_delta_decode (grub_uint8_t *data, grub_uint32_t data_size,
		   grub_uint32_t num_channels)
{
	grub_uint32_t src_pos = 0;
	const grub_uint32_t border = data_size * 2;
	grub_uint32_t cur_channel;

	for (cur_channel = 0; cur_channel < num_channels; cur_channel++)
	{
		grub_uint8_t prev_byte = 0;
		grub_uint32_t dest_pos;
		for (dest_pos = data_size + cur_channel; dest_pos < border;
		     dest_pos += num_channels)
			data[dest_pos] = (prev_byte = (grub_uint8_t)
					  (prev_byte - data[src_pos++]));
	}
}

static void
rar3_rgb_decode (grub_uint8_t *src_data, grub_uint32_t data_size,
		 grub_uint32_t width, grub_uint32_t pos_r)
{
	grub_uint8_t *dest_data = src_data + data_size;
	const grub_uint32_t kNumChannels = 3;
	grub_uint32_t cur_channel, border, i;

	for (cur_channel = 0; cur_channel < kNumChannels; cur_channel++)
	{
		grub_uint8_t prev_byte = 0;

		for (i = cur_channel; i < data_size; i += kNumChannels)
		{
			unsigned predicted;
			if (i < width)
				predicted = prev_byte;
			else
			{
				const unsigned upper_left =
					dest_data[i - width];
				const unsigned upper =
					dest_data[i - width + 3];
				int pa, pb, pc;
				predicted = prev_byte + upper - upper_left;
				pa = (int) (predicted - prev_byte);
				pb = (int) (predicted - upper);
				pc = (int) (predicted - upper_left);
				if (pa < 0)
					pa = -pa;
				if (pb < 0)
					pb = -pb;
				if (pc < 0)
					pc = -pc;
				if (pa <= pb && pa <= pc)
					predicted = prev_byte;
				else if (pb <= pc)
					predicted = upper;
				else
					predicted = upper_left;
			}
			dest_data[i] = prev_byte = (grub_uint8_t)
				(predicted - *(src_data++));
		}
	}
	if (data_size < 3)
		return;
	border = data_size - 2;
	for (i = pos_r; i < border; i += 3)
	{
		const grub_uint8_t g = dest_data[i + 1];
		dest_data[i]     = (grub_uint8_t) (dest_data[i] + g);
		dest_data[i + 2] = (grub_uint8_t) (dest_data[i + 2] + g);
	}
}

static void
rar3_audio_decode (grub_uint8_t *src_data, grub_uint32_t data_size,
		   grub_uint32_t num_channels)
{
	grub_uint8_t *dest_data = src_data + data_size;
	grub_uint32_t cur_channel;

	for (cur_channel = 0; cur_channel < num_channels; cur_channel++)
	{
		grub_uint32_t prev_byte = 0, prev_delta = 0, dif[7];
		grub_int32_t d1 = 0, d2 = 0, d3;
		grub_int32_t k1 = 0, k2 = 0, k3 = 0;
		grub_uint32_t i, byte_count;

		grub_memset (dif, 0, sizeof (dif));

		for (i = cur_channel, byte_count = 0; i < data_size;
		     i += num_channels, byte_count++)
		{
			grub_uint32_t predicted, cur_byte;
			grub_int32_t d;

			d3 = d2;
			d2 = (grub_int32_t) prev_delta - d1;
			d1 = (grub_int32_t) prev_delta;

			predicted = (grub_uint32_t)
				((grub_int32_t) (8 * prev_byte)
				 + k1 * d1 + k2 * d2 + k3 * d3);
			predicted = (predicted >> 3) & 0xFF;

			cur_byte = *(src_data++);

			predicted -= cur_byte;
			dest_data[i] = (grub_uint8_t) predicted;
			prev_delta = (grub_uint32_t) (grub_int32_t)
				(grub_int8_t) (predicted - prev_byte);
			prev_byte = predicted;

			d = ((grub_int32_t) (grub_int8_t) cur_byte) << 3;

			dif[0] += my_abs32 (d);
			dif[1] += my_abs32 (d - d1);
			dif[2] += my_abs32 (d + d1);
			dif[3] += my_abs32 (d - d2);
			dif[4] += my_abs32 (d + d2);
			dif[5] += my_abs32 (d - d3);
			dif[6] += my_abs32 (d + d3);

			if ((byte_count & 0x1F) == 0)
			{
				grub_uint32_t min_dif = dif[0];
				grub_uint32_t num_min_dif = 0;
				unsigned j;
				dif[0] = 0;
				for (j = 1; j < 7; j++)
				{
					if (dif[j] < min_dif)
					{
						min_dif = dif[j];
						num_min_dif = j;
					}
					dif[j] = 0;
				}
				switch (num_min_dif)
				{
				case 1: if (k1 >= -16) k1--; break;
				case 2: if (k1 <   16) k1++; break;
				case 3: if (k2 >= -16) k2--; break;
				case 4: if (k2 <   16) k2++; break;
				case 5: if (k3 >= -16) k3--; break;
				case 6: if (k3 <   16) k3++; break;
				}
			}
		}
	}
}

static int
rar3_execute_std_filter (struct rar3_dec *p, unsigned filter_index)
{
	const grub_uint32_t data_size = p->vm_r[4];
	enum rar3_std_filter type;

	if (data_size >= VM_GLOBAL_OFFSET)
		return 0;
	type = kStdFilters[filter_index].type;

	switch (type)
	{
	case SF_E8:
	case SF_E8E9:
		rar3_e8e9_decode (p->vm_mem, data_size, p->vm_r[6],
				  (type == SF_E8E9));
		break;

	case SF_ITANIUM:
		rar3_itanium_decode (p->vm_mem, data_size, p->vm_r[6]);
		break;

	case SF_DELTA:
	{
		const grub_uint32_t num_channels = p->vm_r[0];
		if (data_size >= VM_GLOBAL_OFFSET / 2)
			return 0;
		if (num_channels == 0 || num_channels > 1024)
			return 0;
		rar3_vm_set_block_pos (p, data_size);
		rar3_delta_decode (p->vm_mem, data_size, num_channels);
		break;
	}

	case SF_RGB:
	{
		const grub_uint32_t width = p->vm_r[0];
		const grub_uint32_t pos_r = p->vm_r[1];
		if (data_size >= VM_GLOBAL_OFFSET / 2 || data_size < 3)
			return 0;
		if (width < 3 || width - 3 > data_size || pos_r > 2)
			return 0;
		rar3_vm_set_block_pos (p, data_size);
		rar3_rgb_decode (p->vm_mem, data_size, width, pos_r);
		break;
	}

	case SF_AUDIO:
	{
		const grub_uint32_t num_channels = p->vm_r[0];
		if (data_size >= VM_GLOBAL_OFFSET / 2)
			return 0;
		if (num_channels == 0 || num_channels > 128)
			return 0;
		rar3_vm_set_block_pos (p, data_size);
		rar3_audio_decode (p->vm_mem, data_size, num_channels);
		break;
	}
	}
	return 1;
}

static void
rar3_vm_set_memory (struct rar3_dec *p, grub_uint32_t pos,
		    const grub_uint8_t *data, grub_uint32_t data_size)
{
	if (pos < VM_SPACE_SIZE && data != p->vm_mem + pos)
	{
		grub_uint32_t n = VM_SPACE_SIZE - pos;
		if (data_size < n)
			n = data_size;
		grub_memmove (p->vm_mem + pos, data, n);
	}
}

/*
 * Executes a filter program.  Only the six standard filters are
 * supported; the general RAR VM interpreter is not implemented (same
 * configuration as 7-Zip's default build).  Returns 1 on success.
 */
static int
rar3_vm_execute (struct rar3_dec *p, const struct rar3_filter *filter,
		 const struct rar3_temp_filter *temp,
		 grub_uint32_t *out_offset, grub_uint32_t *out_size)
{
	grub_uint32_t global_size;
	grub_uint32_t new_block_pos, new_block_size;
	int res;

	grub_memcpy (p->vm_r, temp->init_r, sizeof (temp->init_r));
	p->vm_r[VM_NUM_REGS - 1] = VM_SPACE_SIZE;
	p->vm_r[VM_NUM_REGS] = 0;

	global_size = temp->global_size;
	if (global_size > VM_GLOBAL_SIZE)
		global_size = VM_GLOBAL_SIZE;
	if (global_size != 0)
		grub_memcpy (p->vm_mem + VM_GLOBAL_OFFSET, temp->global_data,
			     global_size);

	if (filter->std_index >= 0)
		res = rar3_execute_std_filter (p,
					       (unsigned) filter->std_index);
	else
		res = 0;

	new_block_pos = rar3_vm_get_global32 (p, VM_GO_BLOCK_POS)
			& VM_SPACE_MASK;
	new_block_size = rar3_vm_get_global32 (p, VM_GO_BLOCK_SIZE)
			 & VM_SPACE_MASK;
	if (new_block_pos + new_block_size >= VM_SPACE_SIZE)
		new_block_pos = new_block_size = 0;
	*out_offset = new_block_pos;
	*out_size = new_block_size;

	/*
	 * Upstream also copies the VM global area back into the filter's
	 * GlobalData here; that copy is never read again, so it is omitted.
	 */
	return res;
}

/* ---------------- filter bookkeeping ---------------- */

static void
rar3_init_filters (struct rar3_dec *p)
{
	unsigned i;

	p->last_filter = 0;
	p->num_empty_temp_filters = 0;
	for (i = 0; i < p->num_temp_filters; i++)
	{
		grub_free (p->temp_filters[i]);
		p->temp_filters[i] = 0;
	}
	p->num_temp_filters = 0;
	p->num_filters = 0;
}

static void
rar3_execute_filter (struct rar3_dec *p, unsigned temp_index,
		     grub_uint32_t *out_offset, grub_uint32_t *out_size)
{
	struct rar3_temp_filter *temp = p->temp_filters[temp_index];
	struct rar3_filter *filter = &p->filters[temp->filter_index];

	temp->init_r[6] = (grub_uint32_t) p->written_file_size;
	rar3_vm_set_value (&temp->global_data[0x24],
			   (grub_uint32_t) p->written_file_size);
	rar3_vm_set_value (&temp->global_data[0x28],
			   (grub_uint32_t) (p->written_file_size >> 32));
	if (!filter->is_supported)
		p->unsupported_filter = 1;
	if (!rar3_vm_execute (p, filter, temp, out_offset, out_size))
		p->unsupported_filter = 1;
	grub_free (temp);
	p->temp_filters[temp_index] = 0;
	p->num_empty_temp_filters++;
}

static int
rar3_write_buf (struct rar3_dec *p)
{
	grub_uint32_t written_border = p->wr_ptr;
	grub_uint32_t write_size = (p->win_pos - written_border) & kWindowMask;
	unsigned i;

	for (i = 0; i < p->num_temp_filters; i++)
	{
		struct rar3_temp_filter *filter = p->temp_filters[i];
		grub_uint32_t block_start, block_size;

		if (!filter)
			continue;
		if (filter->next_window)
		{
			filter->next_window = 0;
			continue;
		}
		block_start = filter->block_start;
		block_size = filter->block_size;
		if (((block_start - written_border) & kWindowMask) >= write_size)
			continue;

		if (written_border != block_start)
		{
			int res = rar3_write_area (p, written_border,
						   block_start);
			if (res)
				return res;
			written_border = block_start;
			write_size = (p->win_pos - written_border)
				     & kWindowMask;
		}
		if (block_size <= write_size)
		{
			grub_uint32_t block_end = (block_start + block_size)
						  & kWindowMask;
			grub_uint32_t out_offset = 0, out_size = 0;
			int res;

			if (block_start < block_end || block_end == 0)
				rar3_vm_set_memory (p, 0,
						    p->window + block_start,
						    block_size);
			else
			{
				grub_uint32_t tail = kWindowSize - block_start;
				rar3_vm_set_memory (p, 0,
						    p->window + block_start,
						    tail);
				rar3_vm_set_memory (p, tail, p->window,
						    block_end);
			}
			rar3_execute_filter (p, i, &out_offset, &out_size);
			while (i + 1 < p->num_temp_filters)
			{
				struct rar3_temp_filter *next =
					p->temp_filters[i + 1];
				if (!next
				    || next->block_start != block_start
				    || next->block_size != out_size
				    || next->next_window)
					break;
				rar3_vm_set_memory (p, 0,
						    p->vm_mem + out_offset,
						    out_size);
				rar3_execute_filter (p, ++i, &out_offset,
						     &out_size);
			}
			res = rar3_write_data_to_stream (p,
				p->vm_mem + out_offset, out_size);
			if (res)
				return res;
			p->written_file_size += out_size;
			written_border = block_end;
			write_size = (p->win_pos - written_border)
				     & kWindowMask;
		}
		else
		{
			unsigned j;
			for (j = i; j < p->num_temp_filters; j++)
			{
				struct rar3_temp_filter *f2 =
					p->temp_filters[j];
				if (f2 && f2->next_window)
					f2->next_window = 0;
			}
			p->wr_ptr = written_border;
			return 0;
		}
	}

	p->wr_ptr = p->win_pos;
	return rar3_write_area (p, written_border, p->win_pos);
}

static int
rar3_add_vm_code (struct rar3_dec *p, grub_uint32_t first_byte,
		  grub_uint32_t code_size)
{
	struct rar3_membits inp;
	struct rar3_filter *filter;
	struct rar3_temp_filter *temp;
	grub_uint32_t filter_index;
	grub_uint32_t block_start;
	int new_filter;
	int is_ok = 1;
	unsigned i;

	inp.data = p->vm_data;
	inp.bitsize = code_size << 3;
	inp.bitpos = 0;

	if (first_byte & 0x80)
	{
		filter_index = rar3_mb_read_encoded (&inp);
		if (filter_index == 0)
			rar3_init_filters (p);
		else
			filter_index--;
	}
	else
		filter_index = p->last_filter;

	if (filter_index > p->num_filters)
		return 0;
	p->last_filter = filter_index;
	new_filter = (filter_index == p->num_filters);

	if (new_filter)
	{
		/* the filter array is fixed size, so this bound is strict */
		if (p->num_filters >= MAX_UNPACK_FILTERS)
			return 0;
		filter = &p->filters[p->num_filters++];
		filter->std_index = -1;
		filter->is_supported = 0;
		filter->block_size = 0;
		filter->exec_count = 0;
	}
	else
	{
		filter = &p->filters[filter_index];
		filter->exec_count++;
	}

	if (p->num_empty_temp_filters != 0)
	{
		unsigned w = 0;
		for (i = 0; i < p->num_temp_filters; i++)
			if (p->temp_filters[i])
				p->temp_filters[w++] = p->temp_filters[i];
		p->num_temp_filters = w;
		p->num_empty_temp_filters = 0;
	}

	if (p->num_temp_filters >= MAX_UNPACK_FILTERS)
		return 0;
	temp = grub_zalloc (sizeof (*temp));
	if (!temp)
		return 0;
	temp->global_size = VM_FIXED_GLOBAL_SIZE;
	p->temp_filters[p->num_temp_filters++] = temp;
	temp->filter_index = filter_index;

	block_start = rar3_mb_read_encoded (&inp);
	if (first_byte & 0x40)
		block_start += 258;
	temp->block_start = (block_start + p->win_pos) & kWindowMask;
	if (first_byte & 0x20)
		filter->block_size = rar3_mb_read_encoded (&inp);
	temp->block_size = filter->block_size;
	temp->next_window = p->wr_ptr != p->win_pos
			    && ((p->wr_ptr - p->win_pos) & kWindowMask)
			       <= block_start;

	grub_memset (temp->init_r, 0, sizeof (temp->init_r));
	temp->init_r[3] = VM_GLOBAL_OFFSET;
	temp->init_r[4] = temp->block_size;
	temp->init_r[5] = filter->exec_count;
	if (first_byte & 0x10)
	{
		grub_uint32_t init_mask = rar3_mb_readbits (&inp,
							    VM_NUM_GP_REGS);
		for (i = 0; i < VM_NUM_GP_REGS; i++)
			if (init_mask & (1u << i))
				temp->init_r[i] = rar3_mb_read_encoded (&inp);
	}

	if (new_filter)
	{
		grub_uint32_t vm_code_size = rar3_mb_read_encoded (&inp);
		grub_uint32_t k;
		grub_uint8_t xor_sum = 0;

		if (vm_code_size >= kVmCodeSizeMax || vm_code_size == 0)
			return 0;
		for (k = 0; k < vm_code_size; k++)
			p->vm_code[k] = (grub_uint8_t) rar3_mb_readbits (&inp,
									8);
		/* CProgram::PrepareProgram */
		for (k = 0; k < vm_code_size; k++)
			xor_sum ^= p->vm_code[k];
		is_ok = 0;
		if (xor_sum == 0)
		{
			is_ok = 1;
			filter->is_supported = 1;
			filter->std_index = rar3_find_std_filter (p->vm_code,
								  vm_code_size);
			if (filter->std_index < 0)
				filter->is_supported = 0;
		}
	}

	{
		grub_uint8_t *global_data = temp->global_data;
		for (i = 0; i < VM_NUM_GP_REGS; i++)
			rar3_vm_set_value (&global_data[i * 4],
					   temp->init_r[i]);
		rar3_vm_set_value (&global_data[VM_GO_BLOCK_SIZE],
				   temp->block_size);
		rar3_vm_set_value (&global_data[VM_GO_BLOCK_POS], 0);
		rar3_vm_set_value (&global_data[VM_GO_EXEC_COUNT],
				   filter->exec_count);
	}

	if (first_byte & 8)
	{
		grub_uint32_t data_size = rar3_mb_read_encoded (&inp);
		grub_uint32_t k;
		grub_uint8_t *dest;

		if (data_size > VM_GLOBAL_SIZE - VM_FIXED_GLOBAL_SIZE)
			return 0;
		if (temp->global_size < data_size + VM_FIXED_GLOBAL_SIZE)
			temp->global_size = data_size + VM_FIXED_GLOBAL_SIZE;
		dest = &temp->global_data[VM_FIXED_GLOBAL_SIZE];
		for (k = 0; k < data_size; k++)
			dest[k] = (grub_uint8_t) rar3_mb_readbits (&inp, 8);
	}

	return is_ok;
}

static int
rar3_read_vm_code_lz (struct rar3_dec *p)
{
	grub_uint32_t first_byte = rar3_bd_readbits (&p->bd, 8);
	grub_uint32_t len = (first_byte & 7) + 1;
	grub_uint32_t i;

	if (len == 7)
		len = rar3_bd_readbits (&p->bd, 8) + 7;
	else if (len == 8)
		len = rar3_bd_readbits (&p->bd, 16);
	if (len > kVmDataSizeMax)
		return 0;
	for (i = 0; i < len; i++)
		p->vm_data[i] = (grub_uint8_t) rar3_bd_readbits (&p->bd, 8);
	return rar3_add_vm_code (p, first_byte, len);
}

static int
rar3_read_vm_code_ppm (struct rar3_dec *p)
{
	const int first_byte = rar3_ppm_sym (p);
	grub_uint32_t len;
	grub_uint32_t i;

	if (first_byte < 0)
		return 0;
	len = (grub_uint32_t) (first_byte & 7) + 1;
	if (len == 7)
	{
		const int b1 = rar3_ppm_sym (p);
		if (b1 < 0)
			return 0;
		len = (grub_uint32_t) b1 + 7;
	}
	else if (len == 8)
	{
		const int b1 = rar3_ppm_sym (p);
		int b2;
		if (b1 < 0)
			return 0;
		b2 = rar3_ppm_sym (p);
		if (b2 < 0)
			return 0;
		len = (grub_uint32_t) b1 * 256 + (grub_uint32_t) b2;
	}
	if (len > kVmDataSizeMax)
		return 0;
	if (p->bd.stream.extra > 2)
		return 0;
	for (i = 0; i < len; i++)
	{
		const int b = rar3_ppm_sym (p);
		if (b < 0)
			return 0;
		p->vm_data[i] = (grub_uint8_t) b;
	}
	return rar3_add_vm_code (p, (grub_uint32_t) first_byte, len);
}

/* ---------------- window helpers ---------------- */

static void
rar3_put_byte (struct rar3_dec *p, grub_uint8_t b)
{
	const grub_uint32_t wp = p->win_pos;
	p->window[wp] = b;
	p->win_pos = (wp + 1) & kWindowMask;
	p->lz_size++;
}

static void
rar3_copy_block (struct rar3_dec *p, grub_uint32_t dist, grub_uint32_t len)
{
	grub_uint32_t pos = (p->win_pos - dist - 1) & kWindowMask;
	grub_uint8_t *window = p->window;
	grub_uint32_t win_pos = p->win_pos;

	p->lz_size += len;
	if (kWindowSize - win_pos > len && kWindowSize - pos > len)
	{
		const grub_uint8_t *src = window + pos;
		grub_uint8_t *dest = window + win_pos;
		p->win_pos += len;
		do
			*dest++ = *src++;
		while (--len != 0);
		return;
	}
	do
	{
		window[win_pos] = window[pos];
		win_pos = (win_pos + 1) & kWindowMask;
		pos = (pos + 1) & kWindowMask;
	}
	while (--len != 0);
	p->win_pos = win_pos;
}

/* ---------------- table reading ---------------- */

static int rar3_read_tables (struct rar3_dec *p, int *keep);

static int
rar3_init_ppm (struct rar3_dec *p)
{
	unsigned max_order = (unsigned) rar3_bd_readbits (&p->bd, 7);
	int reset = ((max_order & 0x20) != 0);
	grub_uint32_t max_mb = 0;

	if (reset)
		max_mb = rar3_bd_byte_aligned (&p->bd);
	else if (p->ppm_error || !Ppmd7_WasAllocated (&p->ppmd))
		return RAR_ERR_DATA;

	if (max_order & 0x40)
		p->ppm_esc_char = rar3_bd_byte_aligned (&p->bd);

	p->ppmd.rc.dec.Stream = &p->byte_in;
	p->byte_in.Read = rar3_wrap_read_bits8;

	Ppmd7a_RangeDec_Init (&p->ppmd.rc.dec);

	p->byte_in.Read = rar3_wrap_read_byte;

	if (reset)
	{
		p->ppm_error = 1;
		max_order = (max_order & 0x1F) + 1;
		if (max_order > 16)
			max_order = 16 + (max_order - 16) * 3;
		if (max_order == 1)
		{
			Ppmd7_Free (&p->ppmd, &rar3_ppmd_allocator);
			return RAR_ERR_DATA;
		}
		if (!Ppmd7_Alloc (&p->ppmd, (max_mb + 1) << 20,
				  &rar3_ppmd_allocator))
			return RAR_ERR_MEM;
		Ppmd7_Init (&p->ppmd, max_order);
		p->ppm_error = 0;
	}
	return 0;
}

static int
rar3_read_tables (struct rar3_dec *p, int *keep)
{
	grub_uint8_t level_levels[20];
	grub_uint8_t *lens;
	struct rar_huff *level_dec;
	unsigned i;
	int err = RAR_ERR_DATA;

	*keep = 1;
	rar3_bd_align (&p->bd);
	if (rar3_bd_readbits (&p->bd, 1) != 0)
	{
		p->lz_mode = 0;
		return rar3_init_ppm (p);
	}

	p->tables_read = 0;
	p->tables_ok = 0;

	p->lz_mode = 1;
	p->prev_align_bits = 0;
	p->prev_align_count = 0;

	if (rar3_bd_readbits (&p->bd, 1) == 0)
		grub_memset (p->last_levels, 0, kTablesSizesSum);

	lens = grub_malloc (kTablesSizesSum);
	level_dec = grub_malloc (sizeof (*level_dec));
	if (!lens || !level_dec)
	{
		err = RAR_ERR_MEM;
		goto fail;
	}

	for (i = 0; i < 20; i++)
	{
		const grub_uint32_t len = rar3_bd_readbits (&p->bd, 4);
		if (len == 15)
		{
			grub_uint32_t zero_count = rar3_bd_readbits (&p->bd, 4);
			if (zero_count != 0)
			{
				zero_count += 2;
				while (zero_count-- > 0 && i < 20)
					level_levels[i++] = 0;
				i--;
				continue;
			}
		}
		level_levels[i] = (grub_uint8_t) len;
	}

	if (rar_huff_build (level_dec, level_levels, 20, RAR_HUFF_FULL))
		goto fail;

	i = 0;
	do
	{
		const int sym = rar3_bd_huff (&p->bd, level_dec);
		if (sym < 0)
			goto fail;
		if (sym < 16)
		{
			lens[i] = (grub_uint8_t) ((sym + p->last_levels[i])
						  & 15);
			i++;
		}
		else
		{
			unsigned num = ((unsigned) sym & 1) * 4;
			grub_uint8_t v = 0;
			num += num + 3 + (unsigned) rar3_bd_readbits (&p->bd,
								      num + 3);
			num += i;
			if (num > kTablesSizesSum)
				num = kTablesSizesSum;
			if (sym < 16 + 2)
			{
				if (i == 0)
					goto fail;
				v = lens[i - 1];
			}
			do
				lens[i++] = v;
			while (i < num);
		}
	}
	while (i < kTablesSizesSum);

	if (rar3_bd_extra_read (&p->bd))
		goto fail;

	p->tables_read = 1;

	if (rar_huff_build (&p->main_dec, &lens[0], kMainTableSize,
			    RAR_HUFF_PARTIAL))
		goto fail;
	if (rar_huff_build (&p->dist_dec, &lens[kMainTableSize],
			    kDistTableSize, RAR_HUFF_PARTIAL))
		goto fail;
	if (rar_huff_build (&p->align_dec,
			    &lens[kMainTableSize + kDistTableSize],
			    kAlignTableSize, RAR_HUFF_PARTIAL))
		goto fail;
	if (rar_huff_build (&p->len_dec,
			    &lens[kMainTableSize + kDistTableSize
				  + kAlignTableSize],
			    kLenTableSize, RAR_HUFF_PARTIAL))
		goto fail;

	grub_memcpy (p->last_levels, lens, kTablesSizesSum);

	p->tables_ok = 1;
	err = 0;

fail:
	grub_free (lens);
	grub_free (level_dec);
	return err;
}

static int
rar3_read_end_of_block (struct rar3_dec *p, int *keep)
{
	if (rar3_bd_readbits (&p->bd, 1) == 0)
	{
		/* new file */
		*keep = 0;
		p->tables_read = (rar3_bd_readbits (&p->bd, 1) == 0);
		return 0;
	}
	p->tables_read = 0;
	return rar3_read_tables (p, keep);
}

/* ---------------- LZ / PPM decode loops ---------------- */

static int
rar3_decode_lz (struct rar3_dec *p, int *keep)
{
	for (;;)
	{
		int sym;
		grub_uint32_t len = p->last_length;

		if (((p->wr_ptr - p->win_pos) & kWindowMask) < 260
		    && p->wr_ptr != p->win_pos)
		{
			int res = rar3_write_buf (p);
			if (res)
				return res;
			if (p->written_file_size > p->unpack_size)
			{
				*keep = 0;
				return 0;
			}
			if (p->base.pause_req)
				return RAR_PAUSED;
		}

		if (p->bd.stream.extra > 2)
			return RAR_ERR_DATA;

		sym = rar3_bd_huff (&p->bd, &p->main_dec);
		if (sym < 0)
			return RAR_ERR_DATA;
		if (sym < 256)
		{
			rar3_put_byte (p, (grub_uint8_t) sym);
			continue;
		}
		else if (sym == kSymbolReadTable)
		{
			return rar3_read_end_of_block (p, keep);
		}
		else if (sym == 257)
		{
			if (!rar3_read_vm_code_lz (p))
				return RAR_ERR_DATA;
			continue;
		}
		else if (sym == 258)
		{
			if (len == 0)
				return RAR_ERR_DATA;
		}
		else if (sym < kSymbolRep + 4)
		{
			int sym2;
			if (sym != kSymbolRep)
			{
				grub_uint32_t dist;
				if (sym == kSymbolRep + 1)
					dist = p->reps[1];
				else
				{
					if (sym == kSymbolRep + 2)
						dist = p->reps[2];
					else
					{
						dist = p->reps[3];
						p->reps[3] = p->reps[2];
					}
					p->reps[2] = p->reps[1];
				}
				p->reps[1] = p->reps[0];
				p->reps[0] = dist;
			}

			sym2 = rar3_bd_huff (&p->bd, &p->len_dec);
			if (sym2 < 0 || sym2 >= (int) kLenTableSize)
				return RAR_ERR_DATA;
			len = 2 + (grub_uint32_t) sym2;
			if (sym2 >= 8)
			{
				const unsigned num = ((unsigned) sym2 >> 2) - 1;
				len = 2 + (grub_uint32_t)
					((4 + ((unsigned) sym2 & 3)) << num)
					+ rar3_bd_readbits8 (&p->bd, num);
			}
		}
		else
		{
			p->reps[3] = p->reps[2];
			p->reps[2] = p->reps[1];
			p->reps[1] = p->reps[0];
			if (sym < 271)
			{
				const unsigned s = (unsigned) sym - 263;
				p->reps[0] = kLen2DistStarts[s]
					+ rar3_bd_readbits8 (&p->bd,
						kLen2DistDirectBits[s]);
				len = 2;
			}
			else if (sym < 299)
			{
				const unsigned s = (unsigned) sym - 271;
				int sym2;
				unsigned numbits;

				len = kNormalMatchMinLen + s;
				if (s >= 8)
				{
					const unsigned num = (s >> 2) - 1;
					len = kNormalMatchMinLen
					      + (grub_uint32_t)
						((4 + (s & 3)) << num)
					      + rar3_bd_readbits8 (&p->bd, num);
				}
				sym2 = rar3_bd_huff (&p->bd, &p->dist_dec);
				if (sym2 < 0 || sym2 >= (int) kDistTableSize)
					return RAR_ERR_DATA;
				p->reps[0] = p->dist_start[sym2];
				numbits = kDistDirectBits[sym2];
				if (sym2 >= (kNumAlignBits * 2) + 2)
				{
					if (numbits > kNumAlignBits)
						p->reps[0] +=
						  (rar3_bd_readbits (&p->bd,
						    numbits - kNumAlignBits)
						   << kNumAlignBits);
					if (p->prev_align_count > 0)
					{
						p->prev_align_count--;
						p->reps[0] += p->prev_align_bits;
					}
					else
					{
						const int sym3 = rar3_bd_huff (
							&p->bd, &p->align_dec);
						if (sym3 < 0)
							return RAR_ERR_DATA;
						if (sym3 < (1 << kNumAlignBits))
						{
							p->reps[0] +=
								(grub_uint32_t) sym3;
							p->prev_align_bits =
								(grub_uint32_t) sym3;
						}
						else if (sym3
							 == (1 << kNumAlignBits))
						{
							p->prev_align_count =
								kNumAlignReps;
							p->reps[0] +=
								p->prev_align_bits;
						}
						else
							return RAR_ERR_DATA;
					}
				}
				else
					p->reps[0] += rar3_bd_readbits8 (&p->bd,
									 numbits);
				len += ((grub_uint32_t)
					(kDistLimit4 - p->reps[0]) >> 31)
				       + ((grub_uint32_t)
					  (kDistLimit3 - p->reps[0]) >> 31);
			}
			else
				return RAR_ERR_DATA;
		}
		p->last_length = len;
		if (p->reps[0] >= p->lz_size)
			return RAR_ERR_DATA;
		rar3_copy_block (p, p->reps[0], len);
	}
}

static int
rar3_decode_ppm (struct rar3_dec *p, grub_int32_t num, int *keep)
{
	*keep = 0;
	if (p->ppm_error)
		return RAR_ERR_DATA;
	do
	{
		int c;

		if (((p->wr_ptr - p->win_pos) & kWindowMask) < 260
		    && p->wr_ptr != p->win_pos)
		{
			int res = rar3_write_buf (p);
			if (res)
				return res;
			if (p->written_file_size > p->unpack_size)
			{
				*keep = 0;
				return 0;
			}
		}
		if (p->bd.stream.extra > 2)
			return RAR_ERR_DATA;
		c = rar3_ppm_sym (p);
		if (c < 0)
		{
			p->ppm_error = 1;
			return RAR_ERR_DATA;
		}
		if (c == p->ppm_esc_char)
		{
			const int next_ch = rar3_ppm_sym (p);
			if (next_ch < 0)
			{
				p->ppm_error = 1;
				return RAR_ERR_DATA;
			}
			if (next_ch == 0)
				return rar3_read_tables (p, keep);
			if (next_ch == 2)
				return 0;
			if (next_ch == 3)
			{
				if (!rar3_read_vm_code_ppm (p))
				{
					p->ppm_error = 1;
					return RAR_ERR_DATA;
				}
				continue;
			}
			if (next_ch == 4 || next_ch == 5)
			{
				grub_uint32_t dist = 0;
				grub_uint32_t len = 4;
				int c2;

				if (next_ch == 4)
				{
					int i;
					for (i = 0; i < 3; i++)
					{
						c2 = rar3_ppm_sym (p);
						if (c2 < 0)
						{
							p->ppm_error = 1;
							return RAR_ERR_DATA;
						}
						dist = (dist << 8)
						       + (grub_uint8_t) c2;
					}
					dist++;
					len += 28;
				}
				c2 = rar3_ppm_sym (p);
				if (c2 < 0)
				{
					p->ppm_error = 1;
					return RAR_ERR_DATA;
				}
				len += (grub_uint32_t) c2;
				if (dist >= p->lz_size)
					return RAR_ERR_DATA;
				rar3_copy_block (p, dist, len);
				num -= (grub_int32_t) len;
				continue;
			}
		}
		rar3_put_byte (p, (grub_uint8_t) c);
		num--;
	}
	while (num >= 0);
	*keep = 1;
	return 0;
}

/* ---------------- top level ---------------- */

static int
rar3_start_item (struct rar_decoder *d, const struct rar_dec_props *props)
{
	struct rar3_dec *p = (struct rar3_dec *) d;
	int err;

	p->is_solid = props->solid;
	if (p->is_solid && !p->solid_allowed)
		return RAR_ERR_DATA;
	p->solid_allowed = 0;
	p->item_done = 0;

	if (!p->vm_data)
	{
		p->vm_data = grub_malloc (kVmDataSizeMax + kVmCodeSizeMax);
		if (!p->vm_data)
			return RAR_ERR_MEM;
		p->vm_code = p->vm_data + kVmDataSizeMax;
	}
	if (!p->window)
	{
		p->window = grub_malloc (kWindowSize);
		if (!p->window)
			return RAR_ERR_MEM;
	}
	if (!p->vm_mem)
	{
		p->vm_mem = grub_zalloc (VM_SPACE_SIZE + 4);
		if (!p->vm_mem)
			return RAR_ERR_MEM;
	}
	if (!p->filters)
	{
		p->filters = grub_calloc (MAX_UNPACK_FILTERS,
					  sizeof (*p->filters));
		if (!p->filters)
			return RAR_ERR_MEM;
	}
	if (!p->temp_filters)
	{
		p->temp_filters = grub_calloc (MAX_UNPACK_FILTERS,
					       sizeof (*p->temp_filters));
		if (!p->temp_filters)
			return RAR_ERR_MEM;
	}
	err = rar_bytein_create (&p->bd.stream, 1u << 20);
	if (err)
		return err;

	rar3_bd_init (&p->bd, d->read_cb, d->read_opaque);
	p->unpack_size = props->unp_size;
	p->written_file_size = 0;
	p->unsupported_filter = 0;

	if (!p->is_solid)
	{
		unsigned i;
		p->lz_size = 0;
		p->win_pos = 0;
		p->wr_ptr = 0;
		for (i = 0; i < kNumReps; i++)
			p->reps[i] = 0;
		p->last_length = 0;
		grub_memset (p->last_levels, 0, kTablesSizesSum);
		p->tables_read = 0;
		p->ppm_esc_char = 2;
		p->ppm_error = 1;
		rar3_init_filters (p);
	}

	if (!p->is_solid || !p->tables_read)
	{
		int keep = 1;
		err = rar3_read_tables (p, &keep);
		if (err)
			return err;
		if (!keep)
		{
			p->solid_allowed = 1;
			p->item_done = 1;
		}
	}

	return 0;
}

static int
rar3_run (struct rar_decoder *d)
{
	struct rar3_dec *p = (struct rar3_dec *) d;
	int err;

	d->pause_req = 0;

	while (!p->item_done)
	{
		int keep = 0;

		if (p->lz_mode)
		{
			if (!p->tables_ok)
				return RAR_ERR_DATA;
			err = rar3_decode_lz (p, &keep);
		}
		else
			err = rar3_decode_ppm (p, 1 << 18, &keep);

		if (err == RAR_PAUSED)
			return RAR_PAUSED;
		if (err)
			return err;

		if (rar3_bd_extra_read (&p->bd))
			return p->bd.stream.read_err ? RAR_ERR_READ
						     : RAR_ERR_DATA;

		if (!keep)
			break;

		if (d->pause_req)
		{
			d->pause_req = 0;
			return RAR_PAUSED;
		}
	}

	p->solid_allowed = 1;
	p->item_done = 1;

	err = rar3_write_buf (p);
	if (err)
		return err;
	if (p->written_file_size < p->unpack_size)
		return RAR_ERR_DATA;
	if (p->unsupported_filter)
		return RAR_ERR_UNSUP;

	return RAR_DONE;
}

static void
rar3_free (struct rar_decoder *d)
{
	struct rar3_dec *p = (struct rar3_dec *) d;

	if (p->temp_filters)
	{
		rar3_init_filters (p);
		grub_free (p->temp_filters);
	}
	grub_free (p->filters);
	grub_free (p->vm_data);
	grub_free (p->vm_mem);
	grub_free (p->window);
	rar_bytein_free (&p->bd.stream);
	if (p->ppmd_constructed)
		Ppmd7_Free (&p->ppmd, &rar3_ppmd_allocator);
	grub_free (p);
}

rar_decoder *
rar3_decoder_create (void)
{
	struct rar3_dec *p = grub_zalloc (sizeof (*p));
	grub_uint32_t start = 0;
	unsigned i;

	if (!p)
		return 0;
	p->base.start_item = rar3_start_item;
	p->base.run = rar3_run;
	p->base.free = rar3_free;
	p->byte_in.Read = rar3_wrap_read_byte;

	Ppmd7_Construct (&p->ppmd);
	p->ppmd_constructed = 1;

	for (i = 0; i < kDistTableSize; i++)
	{
		p->dist_start[i] = start;
		start += (grub_uint32_t) 1 << kDistDirectBits[i];
	}
	return &p->base;
}
