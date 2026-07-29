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

/*  Read-only UEFI firmware image filesystem driver.
 *
 *  Container and naming semantics follow 7-Zip 26.02
 *  CPP\7zip\Archive\UefiHandler.cpp (the "UEFIc" and "UEFIf" handlers):
 *  capsule header, FFS firmware volumes, FFS files, sections, the
 *  COMPRESSION / GUID_DEFINED / FIRMWARE_VOLUME_IMAGE recursion and the
 *  single-child directory collapsing that gives entries their names.
 *  LZMA and EFI/Tiano LZH are decoded with grub-core\lib\7z (LzmaDec.c and
 *  LzhDecoder.c, the latter shared with the LZH and ARJ readers).
 *
 *  The whole image is parsed into memory at mount time, exactly like the
 *  7-Zip handler does, because everything below a compressed section only
 *  exists once it has been decompressed.  A one entry mount cache keeps
 *  the parsed image around so that browsing and extracting do not redo
 *  the work for every directory listing and every file opened.
 *
 *  Deviations from the 7-Zip handler, all of them needed by real images:
 *    - an Intel flash descriptor is recognised by its FLVALSIG dword alone
 *      (UefiHandler.cpp also demands 16 leading 0xFF bytes, which newer
 *      boards do not have), and its regions become directories whose
 *      firmware volumes are parsed instead of one opaque blob;
 *    - the image (and every flash region) is scanned for further volumes
 *      rather than only the one at its start;
 *    - the FFS3 filesystem GUID is accepted;
 *    - entry names are made unique inside their directory by appending
 *      ~1, ~2, ... since a path has to address exactly one entry here.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/dl.h>

#include <7zCrc.h>
#include <7zTypes.h>
#include <LzmaDec.h>
#include <LzhDecoder.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define UEFI_GUID_SIZE		16
#define UEFI_FV_HEADER_SIZE	0x38
#define UEFI_FILE_HEADER_SIZE	24
#define UEFI_FV_SIGNATURE	0x4856465F	/* "_FVH" */
#define UEFI_FFS_GUID_OFFSET	16
#define UEFI_FVB_ERASE_POLARITY	(1 << 11)
#define UEFI_INTEL_FLVALSIG	0x0FF0A55A

/* limits, mirroring UefiHandler.cpp */
#define UEFI_ITEMS_MAX		(1u << 18)
#define UEFI_BUFS_TOTAL_MAX	((grub_size_t) 1 << 29)
#define UEFI_LEVEL_MAX		64
/* an image we are willing to pull into memory whole */
#define UEFI_IMAGE_MAX		((grub_uint64_t) 256 << 20)
/* window scanned for a volume when the image does not start with one */
#define UEFI_PROBE_SIZE		0x10000
/* cache key: leading bytes compared before a cached mount is reused */
#define UEFI_PROBE_KEY		512
#define UEFI_FVS_MAX		256
#define UEFI_PATH_BUCKETS	1024

/* parse results */
#define UEFI_OK			0
#define UEFI_FALSE		1	/* not valid, give up on this branch */
#define UEFI_FATAL		2	/* out of memory or a limit was hit */

/* FFS file types */
#define UEFI_FILETYPE_RAW	0x01
#define UEFI_FILETYPE_FFS_PAD	0xF0

/*
 * FFS file attributes.  Bit 0 means TAIL_PRESENT in the EFI 1.x layout the
 * 7-Zip handler implements and LARGE_FILE in the PI spec; the two are told
 * apart by the volume's filesystem GUID, only FFS3 uses the latter.
 */
#define UEFI_FFS_ATTRIB_TAIL	0x01
#define UEFI_FFS_ATTRIB_LARGE	0x01
#define UEFI_FFS_ATTRIB_CHECKSUM 0x40

/* the size field that says "a 64/32 bit size follows the header" */
#define UEFI_SIZE_EXTENDED	0xFFFFFF
#define UEFI_FILE_HEADER2_SIZE	32
#define UEFI_SECTION_HEADER2_SIZE 8

#define UEFI_FILE_DATA_VALID	0x04

/* section types */
#define UEFI_SECTION_COMPRESSION	0x01
#define UEFI_SECTION_GUID_DEFINED	0x02
#define UEFI_SECTION_DXE_DEPEX		0x13
#define UEFI_SECTION_VERSION		0x14
#define UEFI_SECTION_USER_INTERFACE	0x15
#define UEFI_SECTION_FV_IMAGE		0x17
#define UEFI_SECTION_FREEFORM_SUBTYPE	0x18
#define UEFI_SECTION_RAW		0x19
#define UEFI_SECTION_PEI_DEPEX		0x1B

#define UEFI_COMPRESSION_NONE	0
#define UEFI_COMPRESSION_LZH	1
#define UEFI_COMPRESSION_LZMA	2

static const grub_uint8_t uefi_guids_capsule[][UEFI_GUID_SIZE] =
{
	{ 0xBD, 0x86, 0x66, 0x3B, 0x76, 0x0D, 0x30, 0x40,
	  0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0 },
	{ 0x8B, 0xA6, 0x3C, 0x4A, 0x23, 0x77, 0xFB, 0x48,
	  0x80, 0x3D, 0x57, 0x8C, 0xC1, 0xFE, 0xC4, 0x4D },
	{ 0xB9, 0x82, 0x91, 0x53, 0xB5, 0xAB, 0x91, 0x43,
	  0xB6, 0x9A, 0xE3, 0xA9, 0x43, 0xF7, 0x2F, 0xCC }
};

/* filesystem GUIDs an FFS volume may carry: FFS1, FFS2, FFS3, MacFS */
static const grub_uint8_t uefi_guids_fs[][UEFI_GUID_SIZE] =
{
	{ 0xD9, 0x54, 0x93, 0x7A, 0x68, 0x04, 0x4A, 0x44,
	  0x81, 0xCE, 0x0B, 0xF6, 0x17, 0xD8, 0x90, 0xDF },
	{ 0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F,
	  0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3 },
	{ 0x7A, 0xC0, 0x73, 0x54, 0xCB, 0x3D, 0xCA, 0x4D,
	  0xBD, 0x6F, 0x1E, 0x96, 0x89, 0xE7, 0x34, 0x9A },
	{ 0xAD, 0xEE, 0xAD, 0x04, 0xFF, 0x61, 0x31, 0x4D,
	  0xB6, 0xBA, 0x64, 0xF8, 0xBF, 0x90, 0x1F, 0x5A }
};

static const grub_uint8_t uefi_guid_lzma[UEFI_GUID_SIZE] =
{
	0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42,
	0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF
};

#define UEFI_GUID_INDEX_CRC	0

static const grub_uint8_t uefi_guids_named[][UEFI_GUID_SIZE] =
{
	{ 0xB0, 0xCD, 0x1B, 0xFC, 0x31, 0x7D, 0xAA, 0x49,
	  0x93, 0x6A, 0xA4, 0x60, 0x0D, 0x9D, 0xD0, 0x83 },
	{ 0x2E, 0x06, 0xA0, 0x1B, 0x79, 0xC7, 0x82, 0x45,
	  0x85, 0x66, 0x33, 0x6A, 0xE8, 0xF7, 0x8F, 0x09 },
	{ 0x25, 0x4E, 0x37, 0x7E, 0x01, 0x8E, 0xEE, 0x4F,
	  0x87, 0xF2, 0x39, 0x0C, 0x23, 0xC6, 0x06, 0xCD },
	{ 0x97, 0xE5, 0x1B, 0x16, 0xC5, 0xE9, 0xDB, 0x49,
	  0xAE, 0x50, 0xC4, 0x62, 0xAB, 0x54, 0xEE, 0xDA },
	{ 0xDB, 0x7F, 0xAD, 0x77, 0x2A, 0xDF, 0x02, 0x43,
	  0x88, 0x98, 0xC7, 0x2E, 0x4C, 0xDB, 0xD0, 0xF4 },
	{ 0xAB, 0x71, 0xCF, 0xF5, 0x4B, 0xB0, 0x7E, 0x4B,
	  0x98, 0x8A, 0xD8, 0xA0, 0xD4, 0x98, 0xE6, 0x92 },
	{ 0x91, 0x45, 0x53, 0x7A, 0xCE, 0x37, 0x81, 0x48,
	  0xB3, 0xC9, 0x71, 0x38, 0x14, 0xF4, 0x5D, 0x6B },
	{ 0x84, 0xE6, 0x7A, 0x36, 0x5D, 0x33, 0x71, 0x46,
	  0xA1, 0x6D, 0x89, 0x9D, 0xBF, 0xEA, 0x6B, 0x88 },
	{ 0x98, 0x07, 0x40, 0x24, 0x07, 0x38, 0x42, 0x4A,
	  0xB4, 0x13, 0xA1, 0xEC, 0xEE, 0x20, 0x5D, 0xD8 },
	{ 0xEE, 0xA2, 0x3F, 0x28, 0x2C, 0x53, 0x4D, 0x48,
	  0x93, 0x83, 0x9F, 0x93, 0xB3, 0x6F, 0x0B, 0x7E },
	{ 0x9B, 0xD5, 0xB8, 0x98, 0xBA, 0xE8, 0xEE, 0x48,
	  0x98, 0xDD, 0xC2, 0x95, 0x39, 0x2F, 0x1E, 0xDB },
	{ 0x09, 0x6D, 0xE3, 0xC3, 0x94, 0x82, 0x97, 0x4B,
	  0xA8, 0x57, 0xD5, 0x28, 0x8F, 0xE3, 0x3E, 0x28 },
	{ 0x18, 0x88, 0x53, 0x4A, 0xE0, 0x5A, 0xB2, 0x4E,
	  0xB2, 0xEB, 0x48, 0x8B, 0x23, 0x65, 0x70, 0x22 },
	/* volume filesystem GUIDs, so that a [VOL] blob says what it is */
	{ 0x8D, 0x2B, 0xF1, 0xFF, 0x96, 0x76, 0x8B, 0x4C,
	  0xA9, 0x85, 0x27, 0x47, 0x07, 0x5B, 0x4F, 0x50 },
	{ 0xA3, 0xB9, 0xF5, 0xCE, 0x6D, 0x47, 0x7F, 0x49,
	  0x9F, 0xDC, 0xE9, 0x81, 0x43, 0xE0, 0x42, 0x2C },
	{ 0x24, 0x46, 0x50, 0x00, 0x59, 0x8A, 0xEB, 0x4E,
	  0xBD, 0x0F, 0x6B, 0x36, 0xE9, 0x61, 0x28, 0xE0 }
};

static const char *const uefi_guid_names[] =
{
	"CRC",
	"VolumeTopFile",
	"ACPI",
	"ACPI2",
	"Main",
	"Intel32",
	"Intel64",
	"Intel32c",
	"Intel64c",
	"MacVolume",
	"MacUpdate.txt",
	"MacName",
	"Insyde",
	"NVRAM_EVSA",
	"NVRAM_NVAR",
	"NVRAM_EVSA2"
};

static const char *const uefi_file_types[] =
{
	"ALL",
	"RAW",
	"FREEFORM",
	"SECURITY_CORE",
	"PEI_CORE",
	"DXE_CORE",
	"PEIM",
	"DRIVER",
	"COMBINED_PEIM_DRIVER",
	"APPLICATION",
	"0xA",
	"VOLUME"
};

static const char *const uefi_region_names[] =
{
	"Descriptor",
	"BIOS",
	"ME",
	"GbE",
	"PDR",
	"Region5",
	"Region6",
	"Region7"
};

static const char *const uefi_methods[] = { "COPY", "LZH", "LZMA" };

struct uefi_type_pair
{
	grub_uint32_t value;
	const char *name;
};

static const struct uefi_type_pair uefi_section_types[] =
{
	{ 0x01, "COMPRESSION" },
	{ 0x02, "GUID" },
	{ 0x10, "efi" },
	{ 0x11, "PIC" },
	{ 0x12, "te" },
	{ 0x13, "DXE_DEPEX" },
	{ 0x14, "VERSION" },
	{ 0x15, "USER_INTERFACE" },
	{ 0x16, "COMPATIBILITY16" },
	{ 0x17, "VOLUME" },
	{ 0x18, "FREEFORM_SUBTYPE_GUID" },
	{ 0x19, "raw" },
	{ 0x1B, "PEI_DEPEX" }
};

static const char *const uefi_depex_commands[] =
{
	"BEFORE", "AFTER", "PUSH", "AND", "OR", "NOT", "TRUE", "FALSE",
	"END", "SOR"
};

struct uefi_sig_ext
{
	const char *ext;
	unsigned size;
	grub_uint8_t sig[16];
};

static const struct uefi_sig_ext uefi_sigs[] =
{
	{ "bmp",  2, { 'B', 'M' } },
	{ "riff", 4, { 'R', 'I', 'F', 'F' } },
	{ "pe",   2, { 'M', 'Z' } },
	{ "gif",  6, { 'G', 'I', 'F', '8', '9', 'a' } },
	{ "png",  8, { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } },
	{ "jpg", 10, { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
		       0x49, 0x46 } },
	{ "rom",  2, { 0x55, 0xAA } }
};

#define UEFI_SIG_BMP	0
#define UEFI_SIG_RIFF	1
#define UEFI_SIG_PE	2

struct uefi_buf
{
	grub_uint8_t *data;
	grub_size_t size;
};

struct uefi_item
{
	char *name;
	int parent;
	int name_index;
	unsigned num_childs;
	grub_uint8_t is_dir;
	grub_uint8_t skip;
	grub_uint8_t there_are_subdirs;
	grub_uint8_t unique_name;
	grub_uint8_t keep_name;
	unsigned buf_index;
	grub_uint32_t offset;
	grub_uint32_t size;
};

/* the flattened, path addressable view handed to the fs hooks */
struct uefi_ent
{
	char *path;
	grub_uint8_t is_dir;
	unsigned buf_index;
	grub_uint32_t offset;
	grub_uint32_t size;
};

struct grub_uefi_data
{
	struct uefi_buf *bufs;
	unsigned num_bufs;
	unsigned cap_bufs;
	grub_size_t total_bufs;

	struct uefi_item *items;
	unsigned num_items;
	unsigned cap_items;

	struct uefi_ent *ents;
	unsigned num_ents;

	/* the mount cache holds one, every open file holds one more */
	unsigned refs;

	/* set while the volume header parse hits a broken section chain */
	int headers_error;
};

/* file context: an entry plus a reference on the image it lives in */
struct grub_uefi_file
{
	struct grub_uefi_data *data;
	unsigned index;
};

struct uefi_fvloc
{
	grub_uint32_t off;
	grub_uint32_t size;
};

/* the GUID prefixes already used inside one volume, kept sorted */
struct uefi_guid_set
{
	grub_uint32_t *keys;
	unsigned num;
	unsigned cap;
};

struct uefi_fv_header
{
	grub_uint32_t header_len;
	grub_uint64_t vol_size;
};

/*
 * Insert a key and report whether it was there already.  Returns -1 when
 * the set could not grow.
 */
static int
uefi_guid_set_add (struct uefi_guid_set *s, grub_uint32_t key)
{
	unsigned lo = 0, hi = s->num;

	while (lo < hi)
	{
		const unsigned mid = lo + (hi - lo) / 2;

		if (s->keys[mid] < key)
			lo = mid + 1;
		else if (s->keys[mid] > key)
			hi = mid;
		else
			return 1;
	}
	if (s->num == s->cap)
	{
		const unsigned cap = s->cap ? s->cap * 2 : 64;
		grub_uint32_t *n;

		if (cap > UEFI_ITEMS_MAX)
			return -1;
		n = grub_realloc (s->keys, cap * sizeof (*n));
		if (!n)
			return -1;
		s->keys = n;
		s->cap = cap;
	}
	grub_memmove (s->keys + lo + 1, s->keys + lo,
		      (s->num - lo) * sizeof (*s->keys));
	s->keys[lo] = key;
	s->num++;
	return 0;
}

/* ---------------- little endian accessors ---------------- */

static grub_uint16_t
uefi_get16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
uefi_get32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

static grub_uint64_t
uefi_get64 (const grub_uint8_t *p)
{
	return grub_le_to_cpu64 (grub_get_unaligned64 (p));
}

static grub_uint32_t
uefi_get24 (const grub_uint8_t *p)
{
	return uefi_get32 (p) & 0xFFFFFF;
}

/* ---------------- allocation helpers ---------------- */

static void *
uefi_lzma_alloc (ISzAllocPtr p, size_t size)
{
	(void) p;
	return grub_malloc (size);
}

static void
uefi_lzma_free (ISzAllocPtr p, void *address)
{
	(void) p;
	grub_free (address);
}

static const ISzAlloc uefi_allocator = { uefi_lzma_alloc, uefi_lzma_free };

/* returns the new buffer index, or -1 */
static int
uefi_add_buf (struct grub_uefi_data *d, grub_size_t size)
{
	struct uefi_buf *buf;

	if (size > UEFI_BUFS_TOTAL_MAX - d->total_bufs)
		return -1;
	if (d->num_bufs == d->cap_bufs)
	{
		const unsigned cap = d->cap_bufs ? d->cap_bufs * 2 : 8;
		struct uefi_buf *n = grub_realloc (d->bufs,
						   cap * sizeof (*n));

		if (!n)
			return -1;
		d->bufs = n;
		d->cap_bufs = cap;
	}
	buf = &d->bufs[d->num_bufs];
	buf->data = grub_malloc (size ? size : 1);
	if (!buf->data)
		return -1;
	buf->size = size;
	d->total_bufs += size;
	return (int) d->num_bufs++;
}

/* returns the new item index, or -1 */
static int
uefi_add_item (struct grub_uefi_data *d, const struct uefi_item *item)
{
	if (d->num_items >= UEFI_ITEMS_MAX)
		return -1;
	if (d->num_items == d->cap_items)
	{
		const unsigned cap = d->cap_items ? d->cap_items * 2 : 64;
		struct uefi_item *n = grub_realloc (d->items,
						    cap * sizeof (*n));

		if (!n)
			return -1;
		d->items = n;
		d->cap_items = cap;
	}
	d->items[d->num_items] = *item;
	return (int) d->num_items++;
}

static void
uefi_item_init (struct uefi_item *item, int parent)
{
	grub_memset (item, 0, sizeof (*item));
	item->parent = parent;
	item->name_index = -1;
	item->keep_name = 1;
}

static int
uefi_add_file_item (struct grub_uefi_data *d, struct uefi_item *item)
{
	unsigned name_index = d->num_items;

	if (item->parent >= 0)
		name_index = d->items[item->parent].num_childs++;
	item->name_index = (int) name_index;
	return uefi_add_item (d, item);
}

static int
uefi_add_dir_item (struct grub_uefi_data *d, struct uefi_item *item)
{
	if (item->parent >= 0)
		d->items[item->parent].there_are_subdirs = 1;
	item->is_dir = 1;
	item->size = 0;
	return uefi_add_item (d, item);
}

/* ---------------- name helpers ---------------- */

static int
uefi_set_name (struct uefi_item *item, const char *name)
{
	char *s = grub_strdup (name);

	if (!s)
		return 0;
	grub_free (item->name);
	item->name = s;
	return 1;
}

static int
uefi_guids_eq (const grub_uint8_t *a, const grub_uint8_t *b)
{
	return grub_memcmp (a, b, UEFI_GUID_SIZE) == 0;
}

static int
uefi_find_named_guid (const grub_uint8_t *p)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE (uefi_guids_named); i++)
		if (uefi_guids_eq (p, uefi_guids_named[i]))
			return (int) i;
	return -1;
}

/* RawLeGuidToString(): XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX, upper case */
static void
uefi_guid_to_string (const grub_uint8_t *g, char *s)
{
	static const grub_uint8_t pos[UEFI_GUID_SIZE] =
	{ 6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34 };
	static const char hex[] = "0123456789ABCDEF";
	unsigned i;

	s[8] = '-';
	s[13] = '-';
	s[18] = '-';
	s[23] = '-';
	s[36] = '\0';
	for (i = 0; i < UEFI_GUID_SIZE; i++)
	{
		char *d = s + pos[i];

		d[0] = hex[g[i] >> 4];
		d[1] = hex[g[i] & 0xF];
	}
}

static int
uefi_item_set_guid (struct uefi_item *item, const grub_uint8_t *guid, int full)
{
	char s[40];
	const int index = uefi_find_named_guid (guid);

	item->unique_name = 1;
	if (index >= 0)
		return uefi_set_name (item, uefi_guid_names[index]);
	uefi_guid_to_string (guid, s);
	if (!full)
		s[8] = '\0';
	return uefi_set_name (item, s);
}

static const char *
uefi_type_pair_name (const struct uefi_type_pair *pairs, unsigned num,
		     grub_uint32_t value, char *scratch)
{
	unsigned i;

	for (i = 0; i < num; i++)
		if (pairs[i].value == value)
			return pairs[i].name;
	grub_snprintf (scratch, 16, "%u", value);
	return scratch;
}

/* CItem::GetName(): "NN.name" once the parent holds more than one child */
static char *
uefi_item_full_name (const struct uefi_item *item, int num_childs_in_parent)
{
	char sz[16];
	char sz2[16];
	grub_size_t zeros, len;
	char *res;

	if (num_childs_in_parent <= 1 || item->name_index < 0)
		return grub_strdup (item->name ? item->name : "");

	grub_snprintf (sz, sizeof (sz), "%d", item->name_index);
	grub_snprintf (sz2, sizeof (sz2), "%d", num_childs_in_parent - 1);
	zeros = grub_strlen (sz2);
	zeros = zeros > grub_strlen (sz) ? zeros - grub_strlen (sz) : 0;

	len = grub_strlen (item->name ? item->name : "");
	res = grub_malloc (zeros + grub_strlen (sz) + 1 + len + 1);
	if (!res)
		return 0;
	grub_memset (res, '0', zeros);
	grub_strcpy (res + zeros, sz);
	res[zeros + grub_strlen (sz)] = '.';
	grub_strcpy (res + zeros + grub_strlen (sz) + 1,
		     item->name ? item->name : "");
	return res;
}

/* ---------------- small parsers ---------------- */

static const char *
uefi_find_ext (const grub_uint8_t *p, grub_uint32_t size)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE (uefi_sigs); i++)
		if (size >= uefi_sigs[i].size
		    && grub_memcmp (p, uefi_sigs[i].sig,
				    uefi_sigs[i].size) == 0)
			break;
	if (i == ARRAY_SIZE (uefi_sigs))
		return 0;

	switch (i)
	{
	case UEFI_SIG_BMP:
		if (size < 14 || uefi_get32 (p + 2) > size
		    || uefi_get32 (p + 0xA) > size)
			return 0;
		break;
	case UEFI_SIG_RIFF:
		if (size >= 16
		    && (uefi_get32 (p + 8) == 0x45564157
			|| uefi_get32 (p + 0xC) == 0x20746D66))
			return "wav";
		break;
	case UEFI_SIG_PE:
	{
		grub_uint32_t pe_offset;

		if (size < 512)
			return 0;
		pe_offset = uefi_get32 (p + 0x3C);
		if (pe_offset >= 0x1000 || pe_offset + 512 > size
		    || (pe_offset & 7) != 0)
			return 0;
		if (uefi_get32 (p + pe_offset) != 0x00004550)
			return 0;
		break;
	}
	}
	return uefi_sigs[i].ext;
}

/*
 * ParseDepedencyExpression(): builds the text form and reports its length.
 * Returns 0 when the blob is not a dependency expression.
 */
static int
uefi_parse_depex (const grub_uint8_t *p, grub_uint32_t size, char **out,
		  grub_size_t *out_len)
{
	grub_size_t cap = 64;
	grub_size_t len = 0;
	char *res;
	grub_uint32_t i;

	res = grub_malloc (cap);
	if (!res)
		return -1;

	for (i = 0; i < size;)
	{
		const unsigned command = p[i++];
		const char *name;
		grub_size_t need;

		if (command >= ARRAY_SIZE (uefi_depex_commands))
			goto bad;
		name = uefi_depex_commands[command];
		need = len + grub_strlen (name) + 2 + 40;
		if (need > cap)
		{
			char *n;

			while (cap < need)
				cap *= 2;
			n = grub_realloc (res, cap);
			if (!n)
			{
				grub_free (res);
				return -1;
			}
			res = n;
		}
		grub_strcpy (res + len, name);
		len += grub_strlen (name);
		if (command < 3)
		{
			if (i + UEFI_GUID_SIZE > size)
				goto bad;
			res[len++] = ' ';
			uefi_guid_to_string (p + i, res + len);
			res[len + 8] = '\0';
			len += 8;
			i += UEFI_GUID_SIZE;
		}
		res[len++] = ';';
		res[len++] = ' ';
	}
	res[len] = '\0';
	*out = res;
	*out_len = len;
	return 1;

bad:
	grub_free (res);
	return 0;
}

/*
 * ParseUtf16zString(): the blob has to be one NUL terminated UTF-16LE
 * string filling it exactly.  Returns an allocated UTF-8 copy.
 */
static char *
uefi_parse_utf16z (const grub_uint8_t *p, grub_uint32_t size)
{
	grub_uint16_t *u16;
	grub_uint8_t *utf8;
	grub_uint32_t i, n;

	if ((size & 1) != 0 || size < 2)
		return 0;
	for (i = 0; i < size; i += 2)
		if (uefi_get16 (p + i) == 0)
			break;
	if (i != size - 2)
		return 0;

	n = i / 2;
	u16 = grub_calloc (n + 1, sizeof (*u16));
	if (!u16)
		return 0;
	for (i = 0; i < n; i++)
		u16[i] = uefi_get16 (p + i * 2);

	utf8 = grub_calloc (n + 1, GRUB_MAX_UTF8_PER_UTF16);
	if (!utf8)
	{
		grub_free (u16);
		return 0;
	}
	*grub_utf16_to_utf8 (utf8, u16, n) = '\0';
	grub_free (u16);
	return (char *) utf8;
}

/* ---------------- firmware volume headers ---------------- */

static int
uefi_is_ffs (const grub_uint8_t *p)
{
	unsigned i;

	if (uefi_get32 (p + 0x28) != UEFI_FV_SIGNATURE)
		return 0;
	for (i = 0; i < ARRAY_SIZE (uefi_guids_fs); i++)
		if (uefi_guids_eq (p + UEFI_FFS_GUID_OFFSET, uefi_guids_fs[i]))
			return 1;
	return 0;
}

/* FFS3 volumes may carry the PI spec's extended file and section headers */
static int
uefi_is_ffs3 (const grub_uint8_t *p)
{
	return uefi_guids_eq (p + UEFI_FFS_GUID_OFFSET, uefi_guids_fs[2]);
}

static int
uefi_fv_header_parse (const grub_uint8_t *p, struct uefi_fv_header *h)
{
	grub_uint32_t attribs;

	if (uefi_get32 (p + 0x28) != UEFI_FV_SIGNATURE)
		return 0;
	attribs = uefi_get32 (p + 0x2C);
	if ((attribs & UEFI_FVB_ERASE_POLARITY) == 0)
		return 0;
	h->vol_size = uefi_get64 (p + 0x20);
	h->header_len = uefi_get16 (p + 0x30);
	if (h->header_len < UEFI_FV_HEADER_SIZE || (h->header_len & 7) != 0
	    || h->vol_size < h->header_len)
		return 0;
	return 1;
}

static int
uefi_fv_checksum_ok (const grub_uint8_t *p, grub_uint32_t header_len)
{
	grub_uint32_t sum = 0;
	grub_uint32_t i;

	for (i = 0; i < header_len; i += 2)
		sum += uefi_get16 (p + i);
	return (sum & 0xFFFF) == 0;
}

/*
 * Look for firmware volumes in a buffer.  Headers are looked for inside
 * [base, base + scan_size), while `avail` says how many bytes really follow
 * `base` (the two differ while probing, where only the head of the image has
 * been read but the volume it announces is much bigger).  With
 * `base_any` the volume at `base` is taken whatever its filesystem GUID says
 * -- that is the plain "this image is one volume" case, and it lets
 * uefi_parse_volume() emit the [VOL] blob for an NVRAM store.  Every other
 * candidate has to sit on a 4 KiB boundary and carry a known FFS GUID, so
 * that code bytes spelling _FVH are not mistaken for a volume.
 */
static unsigned
uefi_scan_fvs (const grub_uint8_t *buf, grub_uint32_t base,
	       grub_uint32_t scan_size, grub_uint64_t avail, int base_any,
	       struct uefi_fvloc *out, unsigned max)
{
	unsigned count = 0;
	grub_uint32_t pos = 0;

	while (pos + UEFI_FV_HEADER_SIZE <= scan_size && count < max)
	{
		const grub_uint8_t *p = buf + base + pos;
		struct uefi_fv_header h;

		if (uefi_fv_header_parse (p, &h)
		    && ((pos == 0 && base_any) || uefi_is_ffs (p))
		    && h.vol_size <= avail - pos
		    && h.header_len <= scan_size - pos
		    && uefi_fv_checksum_ok (p, h.header_len))
		{
			out[count].off = base + pos;
			out[count].size = (grub_uint32_t) h.vol_size;
			count++;
			pos += (grub_uint32_t) h.vol_size;
			pos = ALIGN_UP (pos, 0x1000);
			continue;
		}
		pos = ALIGN_UP (pos + 1, 0x1000);
	}
	return count;
}

/* ---------------- decompressors ---------------- */

/* DecodeLzma(): the 13 byte LZMA1 header is followed by the stream */
static int
uefi_decode_lzma (struct grub_uefi_data *d, const grub_uint8_t *data,
		  grub_size_t in_size, int *buf_index)
{
	grub_uint64_t unpack_size;
	SizeT dest_len, src_len, src_len2;
	ELzmaStatus status;
	int index;

	if (in_size < 5 + 8)
		return UEFI_FALSE;
	unpack_size = uefi_get64 (data + 5);
	if (unpack_size > ((grub_uint64_t) 1 << 30))
		return UEFI_FALSE;

	index = uefi_add_buf (d, (grub_size_t) unpack_size);
	if (index < 0)
		return UEFI_FATAL;

	dest_len = (SizeT) unpack_size;
	src_len = (SizeT) (in_size - (5 + 8));
	src_len2 = src_len;
	if (LzmaDecode (d->bufs[index].data, &dest_len, data + 13, &src_len,
			data, 5, LZMA_FINISH_END, &status,
			&uefi_allocator) != SZ_OK)
		return UEFI_FALSE;
	if (src_len != src_len2 || dest_len != unpack_size
	    || (status != LZMA_STATUS_FINISHED_WITH_MARK
		&& status != LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK))
		return UEFI_FALSE;

	*buf_index = index;
	return UEFI_OK;
}

/*
 * EFI 1.1 built LZH with a 16 KiB dictionary (and a 4 bit distance table
 * width), Tiano uses 512 KiB; try the modern one first, exactly as
 * UefiHandler.cpp does.
 */
static int
uefi_decode_lzh (struct grub_uefi_data *d, const grub_uint8_t *data,
		 grub_size_t in_size, grub_size_t out_size, int *buf_index)
{
	int index = uefi_add_buf (d, out_size);

	if (index < 0)
		return UEFI_FATAL;

	if (LzhDecode (data, in_size, d->bufs[index].data, out_size,
		       LZH_DICT_TIANO, 0) != LZH_OK
	    && LzhDecode (data, in_size, d->bufs[index].data, out_size,
			  LZH_DICT_EFI11, 0) != LZH_OK)
		return UEFI_FALSE;

	*buf_index = index;
	return UEFI_OK;
}

/* ---------------- FFS file header ---------------- */

struct uefi_ffs_header
{
	grub_uint8_t guid[UEFI_GUID_SIZE];
	grub_uint8_t check_header;
	grub_uint8_t check_file;
	grub_uint8_t type;
	grub_uint8_t attrib;
	grub_uint8_t state;
	grub_uint64_t size;
	grub_uint32_t hdr_size;
	grub_uint32_t tail;
};

static int
uefi_ffs_parse (struct uefi_ffs_header *h, const grub_uint8_t *p,
		grub_uint32_t rem, int ffs3)
{
	unsigned i;

	for (i = 0; i < UEFI_FILE_HEADER_SIZE; i++)
		if (p[i] != 0xFF)
			break;
	if (i == UEFI_FILE_HEADER_SIZE)
		return 0;
	grub_memcpy (h->guid, p, UEFI_GUID_SIZE);
	h->check_header = p[0x10];
	h->check_file = p[0x11];
	h->type = p[0x12];
	h->attrib = p[0x13];
	h->size = uefi_get24 (p + 0x14);
	h->state = p[0x17];
	h->hdr_size = UEFI_FILE_HEADER_SIZE;
	h->tail = 0;

	if (ffs3)
	{
		/* EFI_FFS_FILE_HEADER2: a 64 bit size follows the header */
		if ((h->attrib & UEFI_FFS_ATTRIB_LARGE)
		    && h->size == UEFI_SIZE_EXTENDED)
		{
			if (rem < UEFI_FILE_HEADER2_SIZE)
				return 0;
			h->size = uefi_get64 (p + UEFI_FILE_HEADER_SIZE);
			h->hdr_size = UEFI_FILE_HEADER2_SIZE;
		}
	}
	else if (h->attrib & UEFI_FFS_ATTRIB_TAIL)
		h->tail = 2;
	return 1;
}

static int
uefi_ffs_check (const struct uefi_ffs_header *h, const grub_uint8_t *p,
		grub_uint32_t size)
{
	grub_uint32_t i;
	unsigned sum;
	int bit;

	if (h->size > size)
		return 0;
	if (h->size < h->hdr_size + h->tail)
		return 0;

	sum = 0;
	for (i = 0; i < h->hdr_size; i++)
		sum += p[i];
	sum -= p[0x17];
	sum -= p[0x11];
	if ((grub_uint8_t) sum != 0)
	{
		/*
		 * Tools disagree on whether the extended size field is part of
		 * the header checksum; accept a header that only sums up over
		 * the 24 byte part as well.  No sample of one was available.
		 */
		if (h->hdr_size == UEFI_FILE_HEADER_SIZE)
			return 0;
		sum = 0;
		for (i = 0; i < UEFI_FILE_HEADER_SIZE; i++)
			sum += p[i];
		sum -= p[0x17];
		sum -= p[0x11];
		if ((grub_uint8_t) sum != 0)
			return 0;
	}

	if (h->attrib & UEFI_FFS_ATTRIB_CHECKSUM)
	{
		const grub_uint64_t n = h->size - h->tail;

		sum = 0;
		for (i = 0; i < n; i++)
			sum += p[i];
		sum -= p[0x17];
		if ((grub_uint8_t) sum != 0)
			return 0;
	}

	if (h->tail != 0)
	{
		const grub_uint16_t ref = (grub_uint16_t) (h->check_header
			| ((grub_uint16_t) h->check_file << 8));

		if (ref != (grub_uint16_t) ~uefi_get16 (p + h->size - 2))
			return 0;
	}

	for (bit = 5; bit >= 0; bit--)
		if (((h->state >> bit) & 1) == 0)
		{
			if ((1 << bit) != UEFI_FILE_DATA_VALID)
				return 0;
			break;
		}
	return bit >= 0;
}

/* ---------------- the recursive parsers ---------------- */

static int uefi_parse_volume (struct grub_uefi_data *d, unsigned buf_index,
			      grub_uint32_t posbase, grub_uint32_t exact_size,
			      grub_uint32_t limit_size, int parent,
			      unsigned level);

static grub_uint32_t
uefi_count_ff (const grub_uint8_t *p, grub_uint32_t size)
{
	grub_uint32_t i;

	for (i = 0; i < size && p[i] == 0xFF; i++)
		;
	return i;
}

static int
uefi_parse_sections (struct grub_uefi_data *d, unsigned buf_index,
		     grub_uint32_t posbase, grub_uint32_t size, int parent,
		     unsigned level, int ffs3, int *error)
{
	const grub_uint8_t *bufdata = d->bufs[buf_index].data;
	grub_uint32_t pos = 0;

	*error = 0;
	if (level > UEFI_LEVEL_MAX)
		return UEFI_FALSE;
	level++;

	for (;;)
	{
		struct uefi_item item;
		const grub_uint8_t *p;
		grub_uint32_t rem, sect_size, data_size, hdr;
		grub_uint8_t type;
		char scratch[16];
		int ret = UEFI_OK;

		if (size == pos)
			return UEFI_OK;
		pos = ALIGN_UP (pos, 4);
		if (pos > size)
			return UEFI_FALSE;
		rem = size - pos;
		if (rem == 0)
			return UEFI_OK;
		if (rem < 4)
			return UEFI_FALSE;

		p = bufdata + posbase + pos;
		sect_size = uefi_get24 (p);
		type = p[3];
		hdr = 4;

		/* EFI_COMMON_SECTION_HEADER2, FFS3 volumes only */
		if (ffs3 && sect_size == UEFI_SIZE_EXTENDED
		    && rem >= UEFI_SECTION_HEADER2_SIZE)
		{
			sect_size = uefi_get32 (p + 4);
			hdr = UEFI_SECTION_HEADER2_SIZE;
		}

		if (sect_size > rem || sect_size < hdr)
		{
			d->headers_error = 1;
			*error = 1;
			return UEFI_OK;
		}

		uefi_item_init (&item, parent);
		item.buf_index = buf_index;
		item.offset = posbase + pos + hdr;
		data_size = sect_size - hdr;
		item.size = data_size;
		if (!uefi_set_name (&item,
				    uefi_type_pair_name (uefi_section_types,
					ARRAY_SIZE (uefi_section_types),
					type, scratch)))
			goto fatal;

		if (type == UEFI_SECTION_COMPRESSION)
		{
			grub_uint32_t unpacked, new_size, new_offset;
			const grub_uint8_t *start;
			grub_uint8_t method;
			int sub_error, index;

			if (sect_size < hdr + 5)
				goto bad;
			unpacked = uefi_get32 (p + hdr);
			method = p[hdr + 4];
			new_size = sect_size - (hdr + 5);
			new_offset = posbase + pos + hdr + 5;
			start = p + hdr + 5;

			if (method > UEFI_COMPRESSION_LZMA)
				goto bad;
			if (!uefi_set_name (&item, uefi_methods[method]))
				goto fatal;
			item.keep_name = 0;

			if (method == UEFI_COMPRESSION_NONE)
			{
				ret = uefi_parse_sections (d, buf_index,
							   new_offset,
							   new_size, parent,
							   level, ffs3,
							   &sub_error);
				if (ret != UEFI_OK)
					goto out_ret;
			}
			else if (method == UEFI_COMPRESSION_LZH)
			{
				grub_uint32_t pack_size, unpack_size;

				if (new_size < 8)
					goto bad;
				pack_size = uefi_get32 (start);
				unpack_size = uefi_get32 (start + 4);
				if (unpacked != unpack_size
				    || new_size - 8 != pack_size)
					goto bad;
				if (pack_size < 1)
					goto bad;
				pack_size--;
				start += 8;
				if (start[pack_size] != 0)
					goto bad;

				ret = uefi_decode_lzh (d, start, pack_size,
						       unpack_size, &index);
				if (ret != UEFI_OK)
					goto out_ret;
				ret = uefi_parse_sections (d,
							   (unsigned) index, 0,
							   unpack_size, parent,
							   level, ffs3,
							   &sub_error);
				if (ret != UEFI_OK)
					goto out_ret;
			}
			else
			{
				grub_uint32_t add = 4;
				grub_size_t unpacked_size;

				if (new_size < 4 + 5 + 8)
					goto bad;
				if (start[0] == 0x5D && start[1] == 0
				    && start[2] == 0 && start[3] == 0x80
				    && start[4] == 0)
					add = 0;
				start += add;

				ret = uefi_decode_lzma (d, start,
							new_size - add,
							&index);
				if (ret != UEFI_OK)
					goto out_ret;
				unpacked_size = d->bufs[index].size;
				if (unpacked_size < unpacked)
					goto bad;
				ret = uefi_parse_sections (d,
							   (unsigned) index, 0,
							   (grub_uint32_t)
							   unpacked_size,
							   parent, level,
							   ffs3, &sub_error);
				if (ret != UEFI_OK)
					goto out_ret;
			}
		}
		else if (type == UEFI_SECTION_GUID_DEFINED)
		{
			const grub_uint32_t ghdr = hdr + UEFI_GUID_SIZE + 4;
			grub_uint32_t data_offset, new_size, new_offset;
			grub_uint32_t props_size;
			unsigned new_buf = buf_index;
			int need_dir = 1;
			int new_parent, sub_error;

			if (sect_size < ghdr)
				goto bad;
			if (!uefi_item_set_guid (&item, p + hdr, 0))
				goto fatal;
			data_offset = uefi_get16 (p + hdr + UEFI_GUID_SIZE);
			if (data_offset > sect_size || data_offset < ghdr)
				goto bad;
			new_size = sect_size - data_offset;
			new_offset = posbase + pos + data_offset;
			props_size = data_offset - ghdr;
			item.size = new_size;
			item.offset = new_offset;

			if (uefi_guids_eq (p + hdr, uefi_guid_lzma))
			{
				int index;

				ret = uefi_decode_lzma (d,
							bufdata + new_offset,
							new_size, &index);
				if (ret != UEFI_OK)
					goto out_ret;
				new_buf = (unsigned) index;
				new_offset = 0;
				new_size = (grub_uint32_t)
					   d->bufs[index].size;
			}
			else if (uefi_guids_eq (p + hdr,
						uefi_guids_named
						[UEFI_GUID_INDEX_CRC])
				 && props_size == 4)
			{
				need_dir = 0;
				item.keep_name = 0;
				if (CrcCalc (bufdata + new_offset, new_size)
				    != uefi_get32 (p + ghdr))
					goto bad;
			}
			else if (props_size != 0)
			{
				struct uefi_item prop = item;
				char *name;

				prop.name = 0;
				name = grub_malloc (grub_strlen (item.name)
						    + 6);
				if (!name)
					goto fatal;
				grub_strcpy (name, item.name);
				grub_strcpy (name + grub_strlen (item.name),
					     ".prop");
				prop.name = name;
				prop.size = props_size;
				prop.offset = posbase + pos + ghdr;
				if (uefi_add_item (d, &prop) < 0)
				{
					grub_free (name);
					goto fatal;
				}
			}

			new_parent = parent;
			if (need_dir)
			{
				new_parent = uefi_add_dir_item (d, &item);
				if (new_parent < 0)
					goto fatal;
				item.name = 0;
			}
			ret = uefi_parse_sections (d, new_buf, new_offset,
						   new_size, new_parent,
						   level, ffs3, &sub_error);
			if (ret != UEFI_OK)
				goto out_ret;
		}
		else if (type == UEFI_SECTION_FV_IMAGE)
		{
			int new_parent;

			item.keep_name = 0;
			new_parent = uefi_add_dir_item (d, &item);
			if (new_parent < 0)
				goto fatal;
			item.name = 0;
			ret = uefi_parse_volume (d, buf_index,
						 posbase + pos + hdr,
						 sect_size - hdr,
						 sect_size - hdr,
						 new_parent, level);
			if (ret != UEFI_OK)
				goto out_ret;
		}
		else
		{
			int need_add = 1;

			switch (type)
			{
			case UEFI_SECTION_RAW:
			{
				const grub_uint32_t insyde = 12;

				if (data_size >= UEFI_FV_HEADER_SIZE + insyde)
				{
					const grub_uint8_t *q = p + hdr
								+ insyde;

					if (uefi_is_ffs (q)
					    && data_size - insyde
					       == uefi_get64 (q + 0x20))
					{
						int new_parent;

						need_add = 0;
						if (!uefi_set_name (&item,
								    "vol"))
							goto fatal;
						new_parent =
						  uefi_add_dir_item (d, &item);
						if (new_parent < 0)
							goto fatal;
						item.name = 0;
						ret = uefi_parse_volume (d,
							buf_index,
							posbase + pos + hdr
							+ insyde,
							data_size - insyde,
							data_size - insyde,
							new_parent, level);
						if (ret != UEFI_OK)
							goto out_ret;
					}

					if (need_add)
					{
						const char *ext =
						  uefi_find_ext (p + hdr,
								 data_size);

						if (ext
						    && !uefi_set_name (&item,
								       ext))
							goto fatal;
					}
				}
				break;
			}
			case UEFI_SECTION_DXE_DEPEX:
			case UEFI_SECTION_PEI_DEPEX:
			{
				char *text = 0;
				grub_size_t text_len = 0;
				int r = uefi_parse_depex (p + hdr, data_size,
							  &text, &text_len);

				if (r < 0)
					goto fatal;
				if (r > 0)
				{
					if (text_len < (1 << 9))
						need_add = 0;
					else
					{
						int index =
						  uefi_add_buf (d, text_len);

						if (index < 0)
						{
							grub_free (text);
							goto fatal;
						}
						grub_memcpy (d->bufs[index]
							     .data, text,
							     text_len);
						item.buf_index =
						  (unsigned) index;
						item.offset = 0;
						item.size =
						  (grub_uint32_t) text_len;
					}
					grub_free (text);
				}
				break;
			}
			case UEFI_SECTION_VERSION:
				if (data_size > 2)
				{
					char *s = uefi_parse_utf16z (p + hdr
							+ 2, data_size - 2);

					if (s)
					{
						grub_free (s);
						need_add = 0;
					}
				}
				break;
			case UEFI_SECTION_USER_INTERFACE:
			{
				char *s = uefi_parse_utf16z (p + hdr,
							     data_size);

				if (s)
				{
					if (parent >= 0
					    && !uefi_set_name (&d->items
							       [parent], s))
					{
						grub_free (s);
						goto fatal;
					}
					grub_free (s);
					need_add = 0;
				}
				break;
			}
			case UEFI_SECTION_FREEFORM_SUBTYPE:
				if (data_size >= UEFI_GUID_SIZE)
				{
					if (!uefi_item_set_guid (&item, p + hdr,
								 0))
						goto fatal;
					item.size = data_size
						    - UEFI_GUID_SIZE;
					item.offset = posbase + pos + hdr
						      + UEFI_GUID_SIZE;
				}
				break;
			}

			if (need_add)
			{
				if (uefi_add_file_item (d, &item) < 0)
					goto fatal;
				item.name = 0;
			}
		}

		grub_free (item.name);
		pos += sect_size;
		continue;

	bad:
		grub_free (item.name);
		return UEFI_FALSE;
	fatal:
		grub_free (item.name);
		return UEFI_FATAL;
	out_ret:
		grub_free (item.name);
		return ret;
	}
}

static int
uefi_parse_volume (struct grub_uefi_data *d, unsigned buf_index,
		   grub_uint32_t posbase, grub_uint32_t exact_size,
		   grub_uint32_t limit_size, int parent, unsigned level)
{
	const grub_uint8_t *bufdata = d->bufs[buf_index].data;
	const grub_uint8_t *p;
	struct uefi_fv_header fvh;
	struct uefi_item item;
	grub_uint32_t pos, vol_size;
	struct uefi_guid_set seen;
	int ffs3;
	int ret = UEFI_OK;

	if (level > UEFI_LEVEL_MAX)
		return UEFI_FALSE;
	level++;
	if (exact_size < UEFI_FV_HEADER_SIZE)
		return UEFI_FALSE;
	if (posbase > d->bufs[buf_index].size
	    || limit_size > d->bufs[buf_index].size - posbase)
		return UEFI_FALSE;

	p = bufdata + posbase;

	/* not an FFS volume: hand the whole thing out as one blob */
	if (!uefi_is_ffs (p))
	{
		uefi_item_init (&item, parent);
		item.buf_index = buf_index;
		item.offset = posbase;
		item.size = exact_size;
		if (uefi_count_ff (p + UEFI_FFS_GUID_OFFSET, 16) != 16
		    && !uefi_item_set_guid (&item, p + UEFI_FFS_GUID_OFFSET,
					    0))
			return UEFI_FATAL;
		{
			const grub_size_t n = item.name ?
					      grub_strlen (item.name) : 0;
			char *name = grub_malloc (n + 6);

			if (!name)
			{
				grub_free (item.name);
				return UEFI_FATAL;
			}
			if (n)
				grub_memcpy (name, item.name, n);
			grub_strcpy (name + n, "[VOL]");
			grub_free (item.name);
			item.name = name;
		}
		if (uefi_add_item (d, &item) < 0)
		{
			grub_free (item.name);
			return UEFI_FATAL;
		}
		return UEFI_OK;
	}

	ffs3 = uefi_is_ffs3 (p);

	if (!uefi_fv_header_parse (p, &fvh))
		return UEFI_FALSE;
	if (fvh.header_len > limit_size || fvh.vol_size > limit_size)
		return UEFI_FALSE;
	if (!uefi_fv_checksum_ok (p, fvh.header_len))
		return UEFI_FALSE;

	vol_size = (grub_uint32_t) fvh.vol_size;

	/* the block map runs to the end of the header */
	pos = UEFI_FV_HEADER_SIZE;
	for (;;)
	{
		grub_uint32_t num_blocks, length;

		if (pos >= fvh.header_len || fvh.header_len - pos < 8)
			return UEFI_FALSE;
		num_blocks = uefi_get32 (p + pos);
		length = uefi_get32 (p + pos + 4);
		pos += 8;
		if (num_blocks == 0 && length == 0)
			break;
	}
	if (pos != fvh.header_len)
		return UEFI_FALSE;

	seen.keys = 0;
	seen.num = 0;
	seen.cap = 0;

	for (;;)
	{
		struct uefi_ffs_header fh;
		const grub_uint8_t *pfile;
		grub_uint32_t rem, offset, sect_size, guid32;
		int new_parent, full;

		rem = vol_size - pos;
		if (rem < UEFI_FILE_HEADER_SIZE)
			break;
		pos = ALIGN_UP (pos, 8);
		rem = vol_size - pos;
		if (rem < UEFI_FILE_HEADER_SIZE)
			break;

		uefi_item_init (&item, parent);
		item.buf_index = buf_index;

		pfile = p + pos;
		if (!uefi_ffs_parse (&fh, pfile, rem, ffs3))
		{
			const grub_uint32_t ff = uefi_count_ff (pfile, rem);

			if (ff != rem)
			{
				item.offset = posbase + pos + ff;
				item.size = rem - ff;
				if (!uefi_set_name (&item, "[junk]"))
					goto fatal;
				if (uefi_add_item (d, &item) < 0)
					goto fatal;
				item.name = 0;
			}
			grub_free (item.name);
			break;
		}

		if (!uefi_ffs_check (&fh, pfile, rem))
		{
			grub_free (item.name);
			ret = UEFI_FALSE;
			goto out;
		}

		offset = posbase + pos + fh.hdr_size;
		sect_size = (grub_uint32_t) (fh.size - fh.hdr_size - fh.tail);
		item.offset = offset;
		item.size = sect_size;

		pos += (grub_uint32_t) fh.size;

		if (fh.type == UEFI_FILETYPE_FFS_PAD
		    && uefi_count_ff (pfile + fh.hdr_size, sect_size)
		       == sect_size)
		{
			grub_free (item.name);
			continue;
		}

		guid32 = uefi_get32 (fh.guid);
		full = uefi_guid_set_add (&seen, guid32);
		if (full < 0)
			goto fatal;
		if (!uefi_item_set_guid (&item, fh.guid, full))
			goto fatal;

		if (fh.type == UEFI_FILETYPE_FFS_PAD
		    || fh.type == UEFI_FILETYPE_RAW)
		{
			int is_volume = 0;

			if (fh.type == UEFI_FILETYPE_RAW
			    && sect_size >= UEFI_FV_HEADER_SIZE
			    && uefi_is_ffs (pfile + fh.hdr_size))
				is_volume = 1;

			if (is_volume)
			{
				const grub_uint32_t lim = rem - fh.hdr_size
							  - fh.tail;

				new_parent = uefi_add_dir_item (d, &item);
				if (new_parent < 0)
					goto fatal;
				item.name = 0;
				ret = uefi_parse_volume (d, buf_index, offset,
							 sect_size, lim,
							 new_parent, level);
				if (ret != UEFI_OK)
					goto out;
			}
			else
			{
				if (uefi_add_item (d, &item) < 0)
					goto fatal;
				item.name = 0;
			}
		}
		else
		{
			int sub_error = 0;
			char *saved = item.name;

			item.name = grub_strdup (saved ? saved : "");
			if (!item.name)
			{
				item.name = saved;
				goto fatal;
			}
			new_parent = uefi_add_dir_item (d, &item);
			if (new_parent < 0)
			{
				grub_free (saved);
				goto fatal;
			}
			item.name = saved;

			ret = uefi_parse_sections (d, buf_index, offset,
						   sect_size, new_parent,
						   level + 1, ffs3,
						   &sub_error);
			if (ret != UEFI_OK)
				goto out;
			if (sub_error)
			{
				/*
				 * Not a section chain after all (an Intel BIOS
				 * has a FREEFORM file that is a plain wav):
				 * publish the file as one blob as well.
				 */
				char *name = grub_malloc (grub_strlen
							  (item.name) + 8);

				if (!name)
					goto fatal;
				grub_strcpy (name, "[ERROR]");
				grub_strcpy (name + 7, item.name);
				grub_free (item.name);
				item.name = name;
				item.is_dir = 0;
				item.size = sect_size;
				if (uefi_add_item (d, &item) < 0)
					goto fatal;
				item.name = 0;
			}
		}
		grub_free (item.name);
		continue;

	fatal:
		grub_free (item.name);
		ret = UEFI_FATAL;
		goto out;
	}

out:
	grub_free (seen.keys);
	return ret;
}

/*
 * Parse every firmware volume inside a byte range.  A range holding a
 * single volume is parsed straight into `parent` (that is what the 7-Zip
 * handler does for a whole image), otherwise each volume gets a volN
 * directory of its own.
 */
static int
uefi_parse_fv_area (struct grub_uefi_data *d, unsigned buf_index,
		    grub_uint32_t base, grub_uint32_t size, int base_any,
		    int parent, unsigned level, unsigned *found)
{
	struct uefi_fvloc *locs;
	unsigned count, i;
	int ret = UEFI_OK;

	*found = 0;
	if (size < UEFI_FV_HEADER_SIZE)
		return UEFI_FALSE;
	if (base > d->bufs[buf_index].size
	    || size > d->bufs[buf_index].size - base)
		return UEFI_FALSE;

	locs = grub_calloc (UEFI_FVS_MAX, sizeof (*locs));
	if (!locs)
		return UEFI_FATAL;
	count = uefi_scan_fvs (d->bufs[buf_index].data, base, size, size,
			       base_any, locs, UEFI_FVS_MAX);
	*found = count;
	if (count == 0)
	{
		grub_free (locs);
		return UEFI_FALSE;
	}

	for (i = 0; i < count; i++)
	{
		int vol_parent = parent;

		if (count > 1)
		{
			struct uefi_item item;
			char name[16];

			uefi_item_init (&item, parent);
			grub_snprintf (name, sizeof (name), "vol%u", i);
			if (!uefi_set_name (&item, name))
			{
				ret = UEFI_FATAL;
				goto out;
			}
			item.unique_name = 1;
			vol_parent = uefi_add_dir_item (d, &item);
			if (vol_parent < 0)
			{
				grub_free (item.name);
				ret = UEFI_FATAL;
				goto out;
			}
		}

		ret = uefi_parse_volume (d, buf_index, locs[i].off,
					 locs[i].size, locs[i].size,
					 vol_parent, level);
		if (ret == UEFI_FATAL)
			goto out;
		/* one broken volume must not hide the others */
		ret = UEFI_OK;
	}

out:
	grub_free (locs);
	return ret;
}

/* ParseIntelMe(): the flash descriptor's region table */
static int
uefi_parse_intel (struct grub_uefi_data *d, unsigned buf_index,
		  grub_uint32_t posbase, grub_uint32_t size, int parent,
		  unsigned level)
{
	const grub_uint8_t *p = d->bufs[buf_index].data + posbase;
	grub_uint32_t v0, reg_addr;
	unsigned i;

	if (size < 16 + 16)
		return UEFI_FALSE;
	if (uefi_get32 (p + 0x10) != UEFI_INTEL_FLVALSIG)
		return UEFI_FALSE;

	v0 = uefi_get32 (p + 20);
	reg_addr = (v0 >> 12) & 0xFF0;

	/* the region count in the header reads 0 on newer images */
	for (i = 0; i < ARRAY_SIZE (uefi_region_names); i++)
	{
		const grub_uint32_t off = reg_addr + i * 4;
		const grub_uint32_t mask = 0xFFF;
		grub_uint32_t val, lim, base, roff, rsize;
		struct uefi_item item;
		struct uefi_fvloc loc;
		unsigned found;
		int dir, ret;

		if (off + 4 > size)
			break;
		val = uefi_get32 (p + off);
		lim = (val >> 16) & mask;
		base = val & mask;
		if ((base == mask && lim == 0) || lim < base)
			continue;

		roff = base << 12;
		rsize = (lim + 1 - base) << 12;
		if (roff >= size)
			continue;
		if (rsize > size - roff)
			rsize = size - roff;

		uefi_item_init (&item, parent);
		item.buf_index = buf_index;
		item.offset = posbase + roff;
		item.size = rsize;
		if (!uefi_set_name (&item, uefi_region_names[i]))
			return UEFI_FATAL;
		item.unique_name = 1;

		found = 0;
		if (rsize >= UEFI_FV_HEADER_SIZE)
			found = uefi_scan_fvs (d->bufs[buf_index].data,
					       posbase + roff, rsize, rsize, 0,
					       &loc, 1);
		if (found == 0)
		{
			if (uefi_add_item (d, &item) < 0)
			{
				grub_free (item.name);
				return UEFI_FATAL;
			}
			continue;
		}

		dir = uefi_add_dir_item (d, &item);
		if (dir < 0)
		{
			grub_free (item.name);
			return UEFI_FATAL;
		}
		ret = uefi_parse_fv_area (d, buf_index, posbase + roff, rsize,
					  0, dir, level + 1, &found);
		if (ret == UEFI_FATAL)
			return ret;
	}
	return UEFI_OK;
}

/* OpenCapsule() */
static int
uefi_parse_capsule (struct grub_uefi_data *d, grub_uint32_t size)
{
	const grub_uint8_t *p = d->bufs[0].data;
	grub_uint32_t header_size, image_size, body, body_size;
	unsigned found;

	header_size = uefi_get32 (p + 0x10);
	image_size = uefi_get32 (p + 0x18);
	if (header_size < 0x1C)
		return UEFI_FALSE;

	if (uefi_guids_eq (p, uefi_guids_capsule[0]))
	{
		if (header_size != 80)
			return UEFI_FALSE;
		/* split capsules and sequenced parts are not supported */
		if (uefi_get32 (p + 0x1C) != 0 || uefi_get32 (p + 0x30) != 0)
			return UEFI_FALSE;
		body = uefi_get32 (p + 0x34);
	}
	else if (uefi_guids_eq (p, uefi_guids_capsule[1]))
		body = uefi_get16 (p + 0x1C);
	else if (uefi_guids_eq (p, uefi_guids_capsule[2]))
		body = header_size;
	else
		return UEFI_FALSE;

	if (image_size < 80 || image_size < header_size
	    || body < header_size || body > image_size
	    || image_size > ((grub_uint32_t) 1 << 30)
	    || header_size > ((grub_uint32_t) 1 << 28))
		return UEFI_FALSE;
	if (image_size > size)
		return UEFI_FALSE;

	body_size = image_size - body;
	if (body_size >= 32
	    && uefi_get32 (p + body + 0x10) == UEFI_INTEL_FLVALSIG)
		return uefi_parse_intel (d, 0, body, body_size, -1, 0);

	return uefi_parse_fv_area (d, 0, body, body_size, 1, -1, 0, &found);
}

static int
uefi_parse_image (struct grub_uefi_data *d, grub_uint32_t size)
{
	const grub_uint8_t *p = d->bufs[0].data;
	unsigned i, found;

	if (size >= 80)
		for (i = 0; i < ARRAY_SIZE (uefi_guids_capsule); i++)
			if (uefi_guids_eq (p, uefi_guids_capsule[i]))
				return uefi_parse_capsule (d, size);

	if (size >= 0x1000 && uefi_get32 (p + 0x10) == UEFI_INTEL_FLVALSIG)
		return uefi_parse_intel (d, 0, 0, size, -1, 0);

	return uefi_parse_fv_area (d, 0, 0, size, 1, -1, 0, &found);
}

/* ---------------- flattening into paths ---------------- */

struct uefi_path_node
{
	struct uefi_path_node *next;
	const char *path;
};

static grub_uint32_t
uefi_hash_path (const char *s)
{
	grub_uint32_t h = 5381;

	while (*s)
		h = h * 33 + (grub_uint8_t) *s++;
	return h & (UEFI_PATH_BUCKETS - 1);
}

static int
uefi_path_seen (struct uefi_path_node **buckets, const char *path)
{
	const struct uefi_path_node *n;

	for (n = buckets[uefi_hash_path (path)]; n; n = n->next)
		if (grub_strcmp (n->path, path) == 0)
			return 1;
	return 0;
}

static int
uefi_path_add (struct uefi_path_node **buckets, const char *path)
{
	const grub_uint32_t h = uefi_hash_path (path);
	struct uefi_path_node *n = grub_malloc (sizeof (*n));

	if (!n)
		return 0;
	n->path = path;
	n->next = buckets[h];
	buckets[h] = n;
	return 1;
}

/* names come from GUIDs, type tags and UTF-16 blobs; keep them path safe */
static void
uefi_sanitize (char *s)
{
	char *w;

	for (w = s; *w; w++)
		if (*w == '/' || *w == '\\' || (grub_uint8_t) *w < 0x20)
			*w = '_';
	if (s[0] == '\0' || grub_strcmp (s, ".") == 0
	    || grub_strcmp (s, "..") == 0)
	{
		s[0] = '_';
		s[1] = '\0';
	}
}

static char *
uefi_join (const char *dir, const char *name, const char *suffix)
{
	const grub_size_t dl = dir ? grub_strlen (dir) : 0;
	const grub_size_t nl = grub_strlen (name);
	const grub_size_t sl = suffix ? grub_strlen (suffix) : 0;
	char *res = grub_malloc (dl + 1 + nl + sl + 1);

	if (!res)
		return 0;
	if (dl)
	{
		grub_memcpy (res, dir, dl);
		res[dl] = '/';
	}
	grub_memcpy (res + (dl ? dl + 1 : 0), name, nl);
	if (sl)
		grub_memcpy (res + (dl ? dl + 1 : 0) + nl, suffix, sl);
	res[(dl ? dl + 1 : 0) + nl + sl] = '\0';
	return res;
}

/*
 * Open2()'s second half: drop directories that only wrap a single child,
 * fold their names into that child and turn what is left into paths.
 */
static int
uefi_build_paths (struct grub_uefi_data *d)
{
	unsigned *num_childs = 0;
	int *reduced = 0;
	struct uefi_path_node **buckets = 0;
	unsigned i;
	int ok = 0;

	if (d->num_items == 0)
		return 0;

	num_childs = grub_calloc (d->num_items, sizeof (*num_childs));
	reduced = grub_calloc (d->num_items, sizeof (*reduced));
	buckets = grub_calloc (UEFI_PATH_BUCKETS, sizeof (*buckets));
	d->ents = grub_calloc (d->num_items, sizeof (*d->ents));
	if (!num_childs || !reduced || !buckets || !d->ents)
		goto out;

	for (i = 0; i < d->num_items; i++)
		if (d->items[i].parent >= 0)
			num_childs[d->items[i].parent]++;

	for (i = 0; i < d->num_items; i++)
	{
		const int parent = d->items[i].parent;

		if (parent < 0)
			continue;
		if (num_childs[parent] == 1
		    && (!d->items[i].unique_name
			|| !d->items[parent].unique_name
			|| !d->items[parent].there_are_subdirs))
			d->items[parent].skip = 1;
	}

	for (i = 0; i < d->num_items; i++)
	{
		const struct uefi_item *item = &d->items[i];
		char *name = 0;
		char *name2;
		char *path;
		int parent = item->parent;
		int num = -1;
		unsigned attempt;

		reduced[i] = (int) d->num_ents;
		if (item->skip)
			continue;

		if (parent >= 0)
			num = (int) num_childs[parent];
		name2 = uefi_item_full_name (item, num);
		if (!name2)
			goto out;
		if (item->keep_name)
		{
			name = grub_strdup (name2);
			if (!name)
			{
				grub_free (name2);
				goto out;
			}
		}

		while (parent >= 0)
		{
			const struct uefi_item *up = &d->items[parent];
			char *name3;

			if (!up->skip)
				break;
			if (up->keep_name)
			{
				name3 = uefi_item_full_name (up, -1);
				if (!name3)
				{
					grub_free (name);
					grub_free (name2);
					goto out;
				}
				if (!name)
					name = name3;
				else
				{
					char *merged = grub_malloc
						 (grub_strlen (name3)
						  + grub_strlen (name) + 2);

					if (!merged)
					{
						grub_free (name3);
						grub_free (name);
						grub_free (name2);
						goto out;
					}
					grub_strcpy (merged, name3);
					merged[grub_strlen (name3)] = '.';
					grub_strcpy (merged
						     + grub_strlen (name3) + 1,
						     name);
					grub_free (name3);
					grub_free (name);
					name = merged;
				}
			}
			parent = up->parent;
		}

		if (!name)
			name = name2;
		else
			grub_free (name2);

		uefi_sanitize (name);

		path = uefi_join (parent >= 0 ? d->ents[reduced[parent]].path
				  : 0, name, 0);
		if (!path)
		{
			grub_free (name);
			goto out;
		}
		for (attempt = 1; uefi_path_seen (buckets, path); attempt++)
		{
			char suffix[16];

			grub_free (path);
			grub_snprintf (suffix, sizeof (suffix), "~%u",
				       attempt);
			path = uefi_join (parent >= 0
					  ? d->ents[reduced[parent]].path : 0,
					  name, suffix);
			if (!path)
			{
				grub_free (name);
				goto out;
			}
		}
		grub_free (name);

		if (!uefi_path_add (buckets, path))
		{
			grub_free (path);
			goto out;
		}

		d->ents[d->num_ents].path = path;
		d->ents[d->num_ents].is_dir = item->is_dir;
		d->ents[d->num_ents].buf_index = item->buf_index;
		d->ents[d->num_ents].offset = item->offset;
		d->ents[d->num_ents].size = item->size;
		d->num_ents++;
	}
	ok = 1;

out:
	if (buckets)
	{
		for (i = 0; i < UEFI_PATH_BUCKETS; i++)
			while (buckets[i])
			{
				struct uefi_path_node *n = buckets[i];

				buckets[i] = n->next;
				grub_free (n);
			}
		grub_free (buckets);
	}
	grub_free (num_childs);
	grub_free (reduced);
	return ok;
}

/* ---------------- mount, with a one entry cache ---------------- */

static void
uefi_free_data (struct grub_uefi_data *d)
{
	unsigned i;

	if (!d)
		return;
	for (i = 0; i < d->num_bufs; i++)
		grub_free (d->bufs[i].data);
	grub_free (d->bufs);
	for (i = 0; i < d->num_items; i++)
		grub_free (d->items[i].name);
	grub_free (d->items);
	for (i = 0; i < d->num_ents; i++)
		grub_free (d->ents[i].path);
	grub_free (d->ents);
	grub_free (d);
}

static void
uefi_data_put (struct grub_uefi_data *d)
{
	if (d && --d->refs == 0)
		uefi_free_data (d);
}

static struct grub_uefi_data *uefi_cache_data;
static char *uefi_cache_name;
static grub_uint64_t uefi_cache_size;
static grub_uint8_t uefi_cache_key[UEFI_PROBE_KEY];

static void
uefi_cache_drop (void)
{
	uefi_data_put (uefi_cache_data);
	uefi_cache_data = 0;
	grub_free (uefi_cache_name);
	uefi_cache_name = 0;
	uefi_cache_size = 0;
}

/* is there anything at all that looks like a firmware image here? */
static int
uefi_probe (const grub_uint8_t *head, grub_size_t head_size,
	    grub_uint64_t total)
{
	struct uefi_fvloc loc;
	unsigned i;

	if (head_size >= 80)
		for (i = 0; i < ARRAY_SIZE (uefi_guids_capsule); i++)
			if (uefi_guids_eq (head, uefi_guids_capsule[i]))
				return 1;
	if (head_size >= 0x14 && total >= 0x1000
	    && uefi_get32 (head + 0x10) == UEFI_INTEL_FLVALSIG)
		return 1;
	if (head_size < UEFI_FV_HEADER_SIZE)
		return 0;
	return uefi_scan_fvs (head, 0, (grub_uint32_t) head_size, total, 1,
			      &loc, 1) != 0;
}

static struct grub_uefi_data *
grub_uefi_mount (grub_disk_t disk)
{
	struct grub_uefi_data *d = 0;
	grub_uint8_t *head = 0;
	grub_uint64_t total;
	grub_size_t head_size;
	int index;

	total = grub_disk_native_sectors (disk);
	if (total == GRUB_DISK_SIZE_UNKNOWN)
		goto not_ours;
	total <<= GRUB_DISK_SECTOR_BITS;
	if (total < UEFI_FV_HEADER_SIZE)
		goto not_ours;

	head_size = total < UEFI_PROBE_SIZE ? (grub_size_t) total
					    : UEFI_PROBE_SIZE;
	head = grub_zalloc (UEFI_PROBE_SIZE);
	if (!head)
		return 0;
	if (grub_disk_read (disk, 0, 0, head_size, head))
		goto not_ours;
	if (!uefi_probe (head, head_size, total))
		goto not_ours;

	if (uefi_cache_data && uefi_cache_name
	    && grub_strcmp (uefi_cache_name, disk->name) == 0
	    && uefi_cache_size == total
	    && grub_memcmp (uefi_cache_key, head,
			    head_size < UEFI_PROBE_KEY ? head_size
						       : UEFI_PROBE_KEY) == 0)
	{
		grub_free (head);
		return uefi_cache_data;
	}

	if (total > UEFI_IMAGE_MAX)
	{
		grub_error (GRUB_ERR_BAD_FS, "uefi image too large");
		grub_free (head);
		return 0;
	}

	uefi_cache_drop ();

	d = grub_zalloc (sizeof (*d));
	if (!d)
		goto fail;
	d->refs = 1;

	index = uefi_add_buf (d, (grub_size_t) total);
	if (index != 0)
		goto fail_mem;
	if (grub_disk_read (disk, 0, 0, (grub_size_t) total,
			    d->bufs[0].data))
		goto fail;

	if (uefi_parse_image (d, (grub_uint32_t) total) != UEFI_OK
	    || d->num_items == 0)
	{
		if (!grub_errno)
			grub_error (GRUB_ERR_BAD_FS,
				    "not a uefi firmware image");
		goto fail;
	}
	if (!uefi_build_paths (d))
		goto fail_mem;

	uefi_cache_name = grub_strdup (disk->name);
	if (!uefi_cache_name)
		goto fail_mem;
	uefi_cache_size = total;
	grub_memcpy (uefi_cache_key, head,
		     head_size < UEFI_PROBE_KEY ? head_size : UEFI_PROBE_KEY);
	uefi_cache_data = d;
	grub_free (head);
	return d;

fail_mem:
	if (!grub_errno)
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
fail:
	uefi_free_data (d);
	grub_free (head);
	return 0;

not_ours:
	grub_free (head);
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "not a uefi firmware image");
	return 0;
}

/* ---------------- filesystem hooks ---------------- */

static const char *
uefi_norm_path (const char *path, grub_size_t *len)
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

static grub_err_t
grub_uefi_dir (grub_device_t device, const char *path,
	       grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_uefi_data *d;
	const char *dir;
	grub_size_t dir_len;
	unsigned i;
	int found;

	d = grub_uefi_mount (device->disk);
	if (!d)
		return grub_errno;

	dir = uefi_norm_path (path, &dir_len);
	found = (dir_len == 0);

	for (i = 0; i < d->num_ents; i++)
	{
		struct grub_dirhook_info info;
		const char *name = d->ents[i].path;
		const char *rest;

		if (dir_len != 0)
		{
			if (grub_strncmp (name, dir, dir_len) != 0)
				continue;
			if (name[dir_len] == '\0')
			{
				found = 1;
				continue;
			}
			if (name[dir_len] != '/')
				continue;
			rest = name + dir_len + 1;
		}
		else
			rest = name;

		if (*rest == '\0' || grub_strchr (rest, '/'))
			continue;
		found = 1;

		grub_memset (&info, 0, sizeof (info));
		info.dir = d->ents[i].is_dir;
		info.inodeset = 1;
		info.inode = i;
		if (hook (rest, &info, hook_data))
			return GRUB_ERR_NONE;
	}

	if (!found)
		return grub_error (GRUB_ERR_FILE_NOT_FOUND,
				   "file `%s' not found", path);
	return GRUB_ERR_NONE;
}

static int
uefi_find_ent (struct grub_uefi_data *d, const char *name)
{
	grub_size_t len;
	const char *path = uefi_norm_path (name, &len);
	unsigned i;

	for (i = 0; i < d->num_ents; i++)
	{
		const char *p = d->ents[i].path;

		if (grub_strncmp (p, path, len) == 0 && p[len] == '\0')
			return (int) i;
	}
	return -1;
}

static grub_err_t
grub_uefi_open (struct grub_file *file, const char *name)
{
	struct grub_uefi_data *d;
	struct grub_uefi_file *ctx;
	int index;

	d = grub_uefi_mount (file->device->disk);
	if (!d)
		return grub_errno;

	index = uefi_find_ent (d, name);
	if (index < 0)
		return grub_error (GRUB_ERR_FILE_NOT_FOUND,
				   "file `%s' not found", name);
	if (d->ents[index].is_dir)
		return grub_error (GRUB_ERR_BAD_FILE_TYPE, "is a directory");

	ctx = grub_malloc (sizeof (*ctx));
	if (!ctx)
		return grub_errno;
	ctx->data = d;
	ctx->index = (unsigned) index;
	d->refs++;

	file->data = ctx;
	file->size = d->ents[index].size;
	return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_uefi_read (grub_file_t file, char *buf, grub_size_t len)
{
	const struct grub_uefi_file *ctx = file->data;
	const struct grub_uefi_data *d = ctx->data;
	const struct uefi_ent *ent = &d->ents[ctx->index];
	const struct uefi_buf *b;
	grub_size_t avail;

	if (ent->buf_index >= d->num_bufs)
		return -1;
	b = &d->bufs[ent->buf_index];
	if (ent->offset > b->size)
		return -1;
	avail = b->size - ent->offset;
	if (avail > ent->size)
		avail = ent->size;
	if ((grub_uint64_t) file->offset >= avail)
		return 0;
	avail -= (grub_size_t) file->offset;
	if (len > avail)
		len = avail;
	grub_memcpy (buf, b->data + ent->offset + file->offset, len);
	return (grub_ssize_t) len;
}

static grub_err_t
grub_uefi_close (grub_file_t file)
{
	struct grub_uefi_file *ctx = file->data;

	if (ctx)
	{
		uefi_data_put (ctx->data);
		grub_free (ctx);
		file->data = 0;
	}
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_uefi_fs =
{
	.name = "uefi",
	.fs_dir = grub_uefi_dir,
	.fs_open = grub_uefi_open,
	.fs_read = grub_uefi_read,
	.fs_close = grub_uefi_close,
	.fs_label = 0,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (uefi)
{
	CrcGenerateTable ();
	grub_uefi_fs.mod = mod;
	grub_fs_register (&grub_uefi_fs);
}

GRUB_MOD_FINI (uefi)
{
	grub_fs_unregister (&grub_uefi_fs);
	uefi_cache_drop ();
}
