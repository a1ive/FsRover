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

/*  Read-only NSIS installer filesystem driver.
 *
 *  Container semantics follow 7-Zip 26.03
 *  CPP\7zip\Archive\Nsis (NsisIn/NsisDecode/NsisHandler).  An NSIS
 *  installer is a PE stub followed, at a 512 byte aligned offset, by a
 *  first header and a compressed or stored command stream.  The command
 *  stream is walked to recover the File/SetOutPath entries; file data
 *  follows in either a single solid stream or one independently packed
 *  chunk per entry.
 *
 *  Methods: Copy, Deflate (NSIS' altered stored blocks without the LEN
 *  one's complement), BZip2 (trimmed stream without stream header, block
 *  CRCs or combined CRC) and LZMA, each optionally passed through the
 *  x86 BCJ filter.  Patched uninstallers that need the original EXE stub
 *  are listed but cannot be read.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/err.h>
#include <grub/charset.h>
#include <grub/dl.h>

#include <LzmaDec.h>
#include <Bra.h>
#include <miniz.h>
#include <bzlib.h>

#include "fscharset.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define NSIS_SIG_SIZE		16
#define NSIS_START_HEADER_SIZE	28	/* flags + sig + hsize + arcsize */
#define NSIS_CMD_SIZE		28	/* opcode + 6 params */
#define NSIS_MAX_HEADER		((grub_uint32_t) 1 << 27)

/* the installer data block is 512 byte aligned and sits behind the stub */
#define NSIS_SCAN_MAX		((grub_uint64_t) 4 << 20)
#define NSIS_SCAN_STEP		512

#define NSIS_FLAG_UNINSTALL	1
#define NSIS_FLAG_MASK		0xF

#define NSIS_MASK_COMPRESSED	0x80000000u

#define NSIS_UNPACK_MAX		((grub_uint64_t) 256 << 20)
#define NSIS_ITEMS_MAX		(1u << 20)
#define NSIS_SEEN_BUCKETS	512
#define NSIS_IN_BUF		(1 << 16)
#define NSIS_BRA_BUF		(1 << 15)

static const grub_uint8_t nsis_signature[NSIS_SIG_SIZE] =
{
	0xEF, 0xBE, 0xAD, 0xDE, 'N', 'u', 'l', 'l',
	's', 'o', 'f', 't', 'I', 'n', 's', 't'
};

enum nsis_method
{
	NSIS_M_COPY,
	NSIS_M_DEFLATE,
	NSIS_M_BZIP2,
	NSIS_M_LZMA
};

enum nsis_type
{
	NSIS_TYPE_NSIS2,
	NSIS_TYPE_NSIS3,
	NSIS_TYPE_PARK1,
	NSIS_TYPE_PARK2,
	NSIS_TYPE_PARK3
};

enum
{
	EW_INVALID_OPCODE,
	EW_RET,
	EW_NOP,
	EW_ABORT,
	EW_QUIT,
	EW_CALL,
	EW_UPDATETEXT,
	EW_SLEEP,
	EW_BRINGTOFRONT,
	EW_CHDETAILSVIEW,
	EW_SETFILEATTRIBUTES,
	EW_CREATEDIR,
	EW_IFFILEEXISTS,
	EW_SETFLAG,
	EW_IFFLAG,
	EW_GETFLAG,
	EW_RENAME,
	EW_GETFULLPATHNAME,
	EW_SEARCHPATH,
	EW_GETTEMPFILENAME,
	EW_EXTRACTFILE,
	EW_DELETEFILE,
	EW_MESSAGEBOX,
	EW_RMDIR,
	EW_STRLEN,
	EW_ASSIGNVAR,
	EW_STRCMP,
	EW_READENVSTR,
	EW_INTCMP,
	EW_INTOP,
	EW_INTFMT,
	EW_PUSHPOP,
	EW_FINDWINDOW,
	EW_SENDMESSAGE,
	EW_ISWINDOW,
	EW_GETDLGITEM,
	EW_SETCTLCOLORS,
	EW_SETBRANDINGIMAGE,
	EW_CREATEFONT,
	EW_SHOWWINDOW,
	EW_SHELLEXEC,
	EW_EXECUTE,
	EW_GETFILETIME,
	EW_GETDLLVERSION,
	EW_REGISTERDLL,
	EW_CREATESHORTCUT,
	EW_COPYFILES,
	EW_REBOOT,
	EW_WRITEINI,
	EW_READINISTR,
	EW_DELREG,
	EW_WRITEREG,
	EW_READREGSTR,
	EW_REGENUM,
	EW_FCLOSE,
	EW_FOPEN,
	EW_FPUTS,
	EW_FGETS,
	EW_FSEEK,
	EW_FINDCLOSE,
	EW_FINDNEXT,
	EW_FINDFIRST,
	EW_WRITEUNINSTALLER,
	EW_SECTIONSET,
	EW_INSTTYPESET,
	EW_GETOSINFO,
	EW_RESERVEDOPCODE,
	EW_LOCKWINDOW,
	EW_FPUTWS,
	EW_FGETWS,
	EW_LOG,
	EW_FINDPROC,
	EW_GETFONTVERSION,
	EW_GETFONTNAME,
	NSIS_NUM_CMDS
};

/* parameter counts from NsisIn.cpp k_Commands[], used by the layout
   detection the same way 7-Zip does */
static const grub_uint8_t nsis_cmd_params[NSIS_NUM_CMDS] =
{
	0, 0, 1, 1, 0, 2, 6, 1, 0, 2, 2, 3, 3, 4, 4, 2, 4, 3, 2, 2,
	6, 2, 6, 2, 2, 4, 5, 3, 6, 4, 4, 6, 5, 6, 3, 3, 2, 4, 5, 4,
	6, 3, 3, 4, 6, 6, 4, 1, 5, 4, 5, 6, 5, 5, 1, 4, 3, 4, 4, 1,
	2, 3, 4, 5, 4, 6, 2, 1, 4, 4, 2, 2, 2, 2
};

/* shell folder names from NsisIn.cpp kShellStrings[] */
static const char *const nsis_shell_strings[] =
{
	"DESKTOP", "INTERNET", "SMPROGRAMS", "CONTROLS", "PRINTERS",
	"DOCUMENTS", "FAVORITES", "SMSTARTUP", "RECENT", "SENDTO",
	"BITBUCKET", "STARTMENU", 0, "MUSIC", "VIDEOS", 0,
	"DESKTOP", "DRIVES", "NETWORK", "NETHOOD", "FONTS",
	"TEMPLATES", "STARTMENU", "SMPROGRAMS", "SMSTARTUP", "DESKTOP",
	"APPDATA", "PRINTHOOD", "LOCALAPPDATA", "ALTSTARTUP", "ALTSTARTUP",
	"FAVORITES", "INTERNET_CACHE", "COOKIES", "HISTORY", "APPDATA",
	"WINDIR", "SYSDIR", "PROGRAM_FILES", "PICTURES", "PROFILE",
	"SYSTEMX86", "PROGRAM_FILESX86", "PROGRAM_FILES_COMMON",
	"PROGRAM_FILES_COMMONX8", "TEMPLATES", "DOCUMENTS", "ADMINTOOLS",
	"ADMINTOOLS", "CONNECTIONS", 0, 0, 0, "MUSIC", "PICTURES",
	"VIDEOS", "RESOURCES", "RESOURCES_LOCALIZED", "COMMON_OEM_LINKS",
	"CDBURN_AREA", 0, "COMPUTERSNEARME"
};

static const char *const nsis_var_strings[] =
{
	"CMDLINE", "INSTDIR", "OUTDIR", "EXEDIR", "LANGUAGE", "TEMP",
	"PLUGINSDIR", "EXEPATH", "EXEFILE", "HWNDPARENT", "_CLICK",
	"_OUTDIR"
};

#define NSIS_NUM_INTERNAL_VARS	(20 + (unsigned) (sizeof (nsis_var_strings) / sizeof (nsis_var_strings[0])))

#define kVar_INSTDIR		21
#define kVar_OUTDIR		22
#define kVar_EXEDIR		23
#define kVar_TEMP		25
#define kVar_PLUGINSDIR		26
#define kVar_EXEPATH		27
#define kVar_HWNDPARENT_225	27
#define kVar_Spec_OUTDIR_225	29
#define kVar_Spec_OUTDIR	31

#define NS_CODE_SKIP		252
#define NS_CODE_VAR		253
#define NS_CODE_SHELL		254
#define NS_3_CODE_SHELL		2
#define NS_3_CODE_VAR		3
#define NS_3_CODE_SKIP		4
#define PARK_CODE_SKIP		0xE000
#define PARK_CODE_VAR		0xE001
#define PARK_CODE_SHELL		0xE002
#define PARK_CODE_LANG		0xE003

#define NSIS_SPEC_CHAR(c)	((c) >= NS_CODE_SKIP)
#define NSIS_PARK_SPEC_CHAR(c)	((c) >= PARK_CODE_SKIP && (c) <= PARK_CODE_LANG)
#define NSIS_DECODE_NUM(c0, c1)	(((unsigned) (c0) & 0x7F) | (((unsigned) (c1) & 0x7F) << 7))
#define NSIS_CONV_NS3(n)	((n) = ((n) & 0x7F) | ((((n) >> 8) & 0x7F) << 7))
#define NSIS_CONV_PARK(n)	((n) &= 0x7FFF)

#define Z7_NSIS_WIN_GENERIC_WRITE	((grub_uint32_t) 1 << 30)
#define Z7_NSIS_WIN_CREATE_ALWAYS	2

static grub_uint16_t
nsis_get16 (const grub_uint8_t *p)
{
	return grub_le_to_cpu16 (grub_get_unaligned16 (p));
}

static grub_uint32_t
nsis_get32 (const grub_uint8_t *p)
{
	return grub_le_to_cpu32 (grub_get_unaligned32 (p));
}

/* ---------------- dynamic string builders ---------------- */

struct nsis_buf
{
	union
	{
		grub_uint8_t *a;
		grub_uint16_t *u;
	} d;
	grub_size_t len;
	grub_size_t cap;
	int unicode;
	int err;
};

static void
nsis_buf_init (struct nsis_buf *b, int unicode)
{
	b->d.a = 0;
	b->len = 0;
	b->cap = 0;
	b->unicode = unicode;
	b->err = 0;
}

static void
nsis_buf_fini (struct nsis_buf *b)
{
	grub_free (b->d.a);
	b->d.a = 0;
}

static int
nsis_buf_grow (struct nsis_buf *b, grub_size_t extra)
{
	grub_size_t need = b->len + extra + 1;
	grub_size_t unit = b->unicode ? sizeof (grub_uint16_t) : 1;
	grub_size_t cap;
	void *n;

	if (b->err)
		return 0;
	if (need <= b->cap)
		return 1;
	cap = b->cap ? b->cap : 32;
	while (cap < need)
		cap *= 2;
	n = grub_realloc (b->d.a, cap * unit);
	if (!n)
	{
		b->err = 1;
		return 0;
	}
	b->d.a = n;
	b->cap = cap;
	return 1;
}

static void
nsis_buf_putc (struct nsis_buf *b, unsigned c)
{
	if (!nsis_buf_grow (b, 1))
		return;
	if (b->unicode)
		b->d.u[b->len++] = (grub_uint16_t) c;
	else
		b->d.a[b->len++] = (grub_uint8_t) c;
}

static void
nsis_buf_put16 (struct nsis_buf *b, unsigned c)
{
	/* append an already decoded 16 bit code point */
	nsis_buf_putc (b, c);
}

static void
nsis_buf_puts (struct nsis_buf *b, const char *s)
{
	while (*s)
		nsis_buf_putc (b, (grub_uint8_t) *s++);
}

static void
nsis_buf_putnum (struct nsis_buf *b, grub_uint32_t v)
{
	char tmp[16];
	unsigned i = 0;

	do
	{
		tmp[i++] = (char) ('0' + v % 10);
		v /= 10;
	}
	while (v != 0);
	while (i > 0)
		nsis_buf_putc (b, (unsigned) (grub_uint8_t) tmp[--i]);
}

static char *
nsis_buf_to_utf8 (struct nsis_buf *b)
{
	char *out;

	if (b->err)
		return 0;
	if (b->unicode)
	{
		grub_size_t max = b->len * GRUB_MAX_UTF8_PER_UTF16 + 1;
		grub_uint8_t *end;

		out = grub_malloc (max);
		if (!out)
			return 0;
		end = grub_utf16_to_utf8 ((grub_uint8_t *) out, b->d.u, b->len);
		*end = '\0';
		if ((char *) end == out)
		{
			grub_free (out);
			return grub_strdup ("");
		}
	}
	else
		out = grub_fs_bytes_to_utf8 ((const char *) b->d.a, b->len,
					     grub_fs_char_encoding);
	return out;
}

/* ---------------- item / archive data ---------------- */

struct nsis_item
{
	char *name;		/* normalized UTF-8 path, '/' separated */
	grub_uint32_t pos;	/* offset relative to the data section */
	grub_uint32_t packed;	/* non-solid packed size, 0 if unknown */
	grub_uint64_t size;
	grub_int64_t mtime;
	grub_uint32_t attrib;
	grub_uint32_t patch_size;
	grub_uint8_t size_known;
	grub_uint8_t is_empty;
	grub_uint8_t is_uninstaller;
	grub_uint8_t unsupported;
};

struct nsis_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct nsis_item *items;
	unsigned num_items;
	unsigned cap_items;

	/* archive geometry */
	grub_uint64_t arc_pos;
	grub_uint64_t data_section_base;
	grub_uint32_t header_size;
	grub_uint32_t arc_size;
	grub_uint32_t dict_size;
	grub_uint8_t is_solid;
	grub_uint8_t header_compressed;
	grub_uint8_t method;
	grub_uint8_t filter_flag;
	grub_uint8_t use_filter;
	grub_uint8_t is_unicode;
	grub_uint8_t is_64bit;
	grub_uint8_t nsis_deflate;

	/* header parse context */
	grub_uint8_t *hdr;
	grub_size_t hdr_size;
	grub_uint32_t strings_pos;
	grub_uint32_t num_string_chars;
	grub_uint8_t nsis_type;
	grub_uint8_t is_nsis200;
	grub_uint8_t is_nsis225;
	grub_uint8_t log_cmd;
	grub_int32_t bad_cmd;

	char **prefixes;
	unsigned num_prefixes;
	unsigned cap_prefixes;
	char *spec_outdir;
};

/* ---------------- buffered packed input ---------------- */

struct nsis_stm;

typedef grub_ssize_t (*nsis_stm_read_t) (struct nsis_stm *stm,
					 grub_uint8_t *buf, grub_size_t len);
typedef void (*nsis_stm_free_t) (struct nsis_stm *stm);

struct nsis_stm
{
	nsis_stm_read_t read;
	nsis_stm_free_t free;
};

struct nsis_src
{
	struct nsis_stm stm;
	grub_disk_t disk;
	grub_uint64_t pos;
	grub_uint64_t left;
};

static grub_ssize_t
nsis_src_read (struct nsis_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct nsis_src *s = (struct nsis_src *) stm;

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
nsis_src_free (struct nsis_stm *stm)
{
	grub_free (stm);
}

static struct nsis_stm *
nsis_src_create (grub_disk_t disk, grub_uint64_t pos, grub_uint64_t len)
{
	struct nsis_src *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
		return 0;
	s->stm.read = nsis_src_read;
	s->stm.free = nsis_src_free;
	s->disk = disk;
	s->pos = pos;
	s->left = len;
	return &s->stm;
}

struct nsis_in
{
	struct nsis_stm *src;
	grub_uint8_t *buf;
	grub_size_t pos;
	grub_size_t len;
	int eof;
};

static int
nsis_in_init (struct nsis_in *in, struct nsis_stm *src)
{
	in->src = src;
	in->pos = 0;
	in->len = 0;
	in->eof = 0;
	in->buf = grub_malloc (NSIS_IN_BUF);
	if (!in->buf)
		return 0;
	return 1;
}

static void
nsis_in_fini (struct nsis_in *in)
{
	if (in->src)
		in->src->free (in->src);
	grub_free (in->buf);
	in->buf = 0;
	in->src = 0;
}

static grub_ssize_t
nsis_in_fill (struct nsis_in *in)
{
	grub_ssize_t got;

	if (in->eof)
		return 0;
	got = in->src->read (in->src, in->buf, NSIS_IN_BUF);
	if (got < 0)
		return -1;
	in->pos = 0;
	in->len = (grub_size_t) got;
	if (got == 0)
		in->eof = 1;
	return got;
}

static int
nsis_in_getbyte (struct nsis_in *in)
{
	if (in->pos == in->len)
	{
		if (in->eof || nsis_in_fill (in) <= 0)
			return -1;
	}
	return in->buf[in->pos++];
}

/* ---------------- Copy ---------------- */

struct nsis_copy
{
	struct nsis_stm stm;
	struct nsis_in in;
};

static grub_ssize_t
nsis_copy_read (struct nsis_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct nsis_copy *s = (struct nsis_copy *) stm;
	grub_size_t done = 0;

	while (done < len)
	{
		grub_size_t avail;
		grub_size_t n;

		if (s->in.pos == s->in.len)
		{
			grub_ssize_t got = nsis_in_fill (&s->in);

			if (got < 0)
				return -1;
			if (got == 0)
				break;
		}
		avail = s->in.len - s->in.pos;
		n = len - done;
		if (n > avail)
			n = avail;
		grub_memcpy (buf + done, s->in.buf + s->in.pos, n);
		s->in.pos += n;
		done += n;
	}
	return (grub_ssize_t) done;
}

static void
nsis_copy_free (struct nsis_stm *stm)
{
	struct nsis_copy *s = (struct nsis_copy *) stm;

	nsis_in_fini (&s->in);
	grub_free (s);
}

static struct nsis_stm *
nsis_copy_create (struct nsis_in *in)
{
	struct nsis_copy *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		nsis_in_fini (in);
		return 0;
	}
	s->stm.read = nsis_copy_read;
	s->stm.free = nsis_copy_free;
	s->in = *in;
	in->buf = 0;	/* adopted */
	in->src = 0;
	return &s->stm;
}

/* ---------------- Deflate (miniz, NSIS stored block layout) ---------------- */

struct nsis_infl
{
	struct nsis_stm stm;
	struct nsis_in in;
	tinfl_decompressor *infl;
	grub_uint8_t *dict;
	grub_size_t dict_pos;
	grub_size_t out_start;
	grub_size_t out_avail;
	int done;
};

static grub_ssize_t
nsis_infl_read (struct nsis_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct nsis_infl *s = (struct nsis_infl *) stm;
	grub_size_t done = 0;

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
			break;

		if (s->in.pos == s->in.len && !s->in.eof
		    && nsis_in_fill (&s->in) < 0)
			return -1;

		in_bytes = s->in.len - s->in.pos;
		out_bytes = TINFL_LZ_DICT_SIZE - s->dict_pos;
		st = tinfl_decompress (s->infl, s->in.buf + s->in.pos, &in_bytes,
				       s->dict, s->dict + s->dict_pos,
				       &out_bytes,
				       s->in.eof ? 0
				       : TINFL_FLAG_HAS_MORE_INPUT);
		s->in.pos += in_bytes;
		s->out_start = s->dict_pos;
		s->out_avail = out_bytes;
		s->dict_pos = (s->dict_pos + out_bytes)
			      & (TINFL_LZ_DICT_SIZE - 1);

		if (st == TINFL_STATUS_DONE)
			s->done = 1;
		else if (st < TINFL_STATUS_DONE)
		{
			grub_error (GRUB_ERR_BAD_FS, "corrupt nsis deflate stream");
			return -1;
		}
		else if (st == TINFL_STATUS_NEEDS_MORE_INPUT && s->in.eof
			 && s->out_avail == 0)
		{
			grub_error (GRUB_ERR_BAD_FS, "truncated nsis deflate stream");
			return -1;
		}
	}
	return (grub_ssize_t) done;
}

static void
nsis_infl_free (struct nsis_stm *stm)
{
	struct nsis_infl *s = (struct nsis_infl *) stm;

	grub_free (s->infl);
	grub_free (s->dict);
	nsis_in_fini (&s->in);
	grub_free (s);
}

static struct nsis_stm *
nsis_infl_create (struct nsis_in *in, int nsis_mode)
{
	struct nsis_infl *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		nsis_in_fini (in);
		return 0;
	}
	s->stm.read = nsis_infl_read;
	s->stm.free = nsis_infl_free;
	s->in = *in;
	in->buf = 0;
	in->src = 0;
	s->infl = grub_malloc (sizeof (*s->infl));
	s->dict = grub_malloc (TINFL_LZ_DICT_SIZE);
	if (!s->infl || !s->dict)
		goto fail;
	tinfl_init (s->infl);
	if (nsis_mode)
		tinfl_set_nsis_mode (s->infl);
	return &s->stm;

fail:
	nsis_infl_free (&s->stm);
	return 0;
}

/* ---------------- BZip2 (trimmed NSIS stream) ---------------- */

struct nsis_bz
{
	struct nsis_stm stm;
	struct nsis_in in;
	bz_stream strm;
	int inited;
};

static grub_ssize_t
nsis_bz_read (struct nsis_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct nsis_bz *s = (struct nsis_bz *) stm;
	grub_size_t done = 0;

	while (done < len)
	{
		grub_size_t chunk = len - done;
		grub_size_t in_avail;
		unsigned out_got, in_got;
		int r;

		if (!s->inited)
		{
			grub_memset (&s->strm, 0, sizeof (s->strm));
			if (BZ2_bzDecompressInitNSis (&s->strm, 0, 0) != BZ_OK)
			{
				grub_error (GRUB_ERR_BAD_FS, "bad nsis bzip2 stream");
				return -1;
			}
			s->inited = 1;
		}
		if (s->in.pos == s->in.len && !s->in.eof
		    && nsis_in_fill (&s->in) < 0)
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
			break;
		if (r != BZ_OK)
		{
			grub_error (GRUB_ERR_BAD_FS, "corrupt nsis bzip2 stream");
			return -1;
		}
		if (out_got == 0 && in_got == 0 && s->in.eof)
		{
			grub_error (GRUB_ERR_BAD_FS, "truncated nsis bzip2 stream");
			return -1;
		}
	}
	return (grub_ssize_t) done;
}

static void
nsis_bz_free (struct nsis_stm *stm)
{
	struct nsis_bz *s = (struct nsis_bz *) stm;

	if (s->inited)
		BZ2_bzDecompressEnd (&s->strm);
	nsis_in_fini (&s->in);
	grub_free (s);
}

static struct nsis_stm *
nsis_bz_create (struct nsis_in *in)
{
	struct nsis_bz *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		nsis_in_fini (in);
		return 0;
	}
	s->stm.read = nsis_bz_read;
	s->stm.free = nsis_bz_free;
	s->in = *in;
	in->buf = 0;
	in->src = 0;
	return &s->stm;
}

/* ---------------- LZMA (raw NSIS stream) ---------------- */

struct nsis_lzma
{
	struct nsis_stm stm;
	struct nsis_in in;
	CLzmaDec dec;
};

static void *
nsis_alloc (ISzAllocPtr p, size_t size)
{
	(void) p;
	return grub_malloc (size);
}

static void
nsis_free (ISzAllocPtr p, void *address)
{
	(void) p;
	grub_free (address);
}

static const ISzAlloc nsis_allocator = { nsis_alloc, nsis_free };

static grub_ssize_t
nsis_lzma_read (struct nsis_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct nsis_lzma *s = (struct nsis_lzma *) stm;
	grub_size_t done = 0;

	while (done < len)
	{
		SizeT dl, sl;
		ELzmaStatus status;

		if (s->in.pos == s->in.len && !s->in.eof
		    && nsis_in_fill (&s->in) < 0)
			return -1;

		dl = len - done;
		sl = s->in.len - s->in.pos;
		if (LzmaDec_DecodeToBuf (&s->dec, buf + done, &dl,
					 s->in.buf + s->in.pos, &sl,
					 LZMA_FINISH_ANY, &status) != SZ_OK)
		{
			grub_error (GRUB_ERR_BAD_FS, "corrupt nsis lzma stream");
			return -1;
		}
		s->in.pos += sl;
		done += dl;

		if (dl == 0 && sl == 0)
			break;
		if (status == LZMA_STATUS_FINISHED_WITH_MARK)
			break;
	}
	return (grub_ssize_t) done;
}

static void
nsis_lzma_free (struct nsis_stm *stm)
{
	struct nsis_lzma *s = (struct nsis_lzma *) stm;

	LzmaDec_Free (&s->dec, &nsis_allocator);
	nsis_in_fini (&s->in);
	grub_free (s);
}

static struct nsis_stm *
nsis_lzma_create (struct nsis_in *in, const grub_uint8_t *props)
{
	struct nsis_lzma *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		nsis_in_fini (in);
		return 0;
	}
	s->stm.read = nsis_lzma_read;
	s->stm.free = nsis_lzma_free;
	s->in = *in;
	in->buf = 0;
	in->src = 0;
	LzmaDec_CONSTRUCT (&s->dec)
	if (LzmaDec_Allocate (&s->dec, props, LZMA_PROPS_SIZE,
			      &nsis_allocator) != SZ_OK)
	{
		grub_error (GRUB_ERR_BAD_FS, "bad nsis lzma properties");
		nsis_lzma_free (&s->stm);
		return 0;
	}
	LzmaDec_Init (&s->dec);
	return &s->stm;
}

/* ---------------- x86 BCJ filter ---------------- */

struct nsis_bra
{
	struct nsis_stm stm;
	struct nsis_stm *src;
	grub_uint32_t pc;
	grub_uint32_t state;
	grub_uint8_t *buf;
	grub_size_t out_pos;
	grub_size_t conv_len;
	grub_size_t fill;
	int src_eof;
};

static grub_ssize_t
nsis_bra_read (struct nsis_stm *stm, grub_uint8_t *buf, grub_size_t len)
{
	struct nsis_bra *s = (struct nsis_bra *) stm;
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
		while (s->fill < NSIS_BRA_BUF && !s->src_eof)
		{
			grub_ssize_t got = s->src->read (s->src,
							 s->buf + s->fill,
							 NSIS_BRA_BUF - s->fill);

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

		end = z7_BranchConvSt_X86_Dec (s->buf, s->fill, s->pc,
					       &s->state);
		s->conv_len = (grub_size_t) (end - s->buf);
		s->pc += (grub_uint32_t) s->conv_len;
		if (s->conv_len == 0)
		{
			if (s->src_eof)
				s->conv_len = s->fill;
			else
			{
				grub_error (GRUB_ERR_BAD_FS, "bad nsis bcj stream");
				return -1;
			}
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
nsis_bra_free (struct nsis_stm *stm)
{
	struct nsis_bra *s = (struct nsis_bra *) stm;

	if (s->src)
		s->src->free (s->src);
	grub_free (s->buf);
	grub_free (s);
}

static struct nsis_stm *
nsis_bra_create (struct nsis_stm *src)
{
	struct nsis_bra *s;

	s = grub_zalloc (sizeof (*s));
	if (!s)
	{
		src->free (src);
		return 0;
	}
	s->stm.read = nsis_bra_read;
	s->stm.free = nsis_bra_free;
	s->src = src;
	s->state = Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL;
	s->buf = grub_malloc (NSIS_BRA_BUF);
	if (!s->buf)
	{
		nsis_bra_free (&s->stm);
		return 0;
	}
	return &s->stm;
}

/* ---------------- decoder factory ---------------- */

static struct nsis_stm *
nsis_decoder_create (grub_disk_t disk, grub_uint64_t pos, grub_uint64_t len,
		     int method, int filter_flag, int nsis_deflate)
{
	struct nsis_stm *src;
	struct nsis_in in;
	struct nsis_stm *base;
	int use_filter = 0;
	grub_uint8_t props[LZMA_PROPS_SIZE];
	unsigned i;

	src = nsis_src_create (disk, pos, len);
	if (!src)
		return 0;
	if (!nsis_in_init (&in, src))
	{
		src->free (src);
		return 0;
	}
	if (filter_flag)
	{
		int b = nsis_in_getbyte (&in);

		if (b < 0)
		{
			nsis_in_fini (&in);
			grub_error (GRUB_ERR_BAD_FS, "truncated nsis stream");
			return 0;
		}
		use_filter = (b != 0);
	}

	switch (method)
	{
	case NSIS_M_COPY:
		base = nsis_copy_create (&in);
		break;
	case NSIS_M_DEFLATE:
		base = nsis_infl_create (&in, nsis_deflate);
		break;
	case NSIS_M_BZIP2:
		base = nsis_bz_create (&in);
		break;
	default:
		for (i = 0; i < LZMA_PROPS_SIZE; i++)
		{
			int b = nsis_in_getbyte (&in);

			if (b < 0)
			{
				nsis_in_fini (&in);
				grub_error (GRUB_ERR_BAD_FS,
					    "truncated nsis lzma stream");
				return 0;
			}
			props[i] = (grub_uint8_t) b;
		}
		base = nsis_lzma_create (&in, props);
		break;
	}

	if (!base)
		return 0;
	if (use_filter)
		return nsis_bra_create (base);
	return base;
}

/* ---------------- string decoding (NsisIn.cpp port) ---------------- */

static void nsis_get_shell_string (struct nsis_data *a, struct nsis_buf *b,
				   unsigned index1, unsigned index2);

static void
nsis_get_var2 (struct nsis_data *a, struct nsis_buf *b, grub_uint32_t index)
{
	if (index < 20)
	{
		if (index >= 10)
		{
			nsis_buf_putc (b, 'R');
			index -= 10;
		}
		nsis_buf_putnum (b, index);
	}
	else
	{
		unsigned niv = NSIS_NUM_INTERNAL_VARS;

		if (a->is_nsis200)
			niv -= 3;
		else if (a->is_nsis225)
			niv -= 2;
		if (index < niv)
		{
			if (a->is_nsis225 && index >= kVar_EXEPATH)
				index += 2;
			nsis_buf_puts (b, nsis_var_strings[index - 20]);
		}
		else
		{
			nsis_buf_putc (b, '_');
			nsis_buf_putnum (b, index - niv);
			nsis_buf_putc (b, '_');
		}
	}
}

static void
nsis_get_var (struct nsis_data *a, struct nsis_buf *b, grub_uint32_t index)
{
	nsis_buf_putc (b, '$');
	nsis_get_var2 (a, b, index);
}

static void
nsis_add_langstr (struct nsis_buf *b, grub_uint32_t id)
{
	nsis_buf_puts (b, "$(LSTR_");
	nsis_buf_putnum (b, id);
	nsis_buf_putc (b, ')');
}

static void
nsis_get_shell_string (struct nsis_data *a, struct nsis_buf *b,
		       unsigned index1, unsigned index2)
{
	(void) a;
	if ((index1 & 0x80) != 0)
	{
		/* registry lookup: not resolved offline */
		nsis_buf_puts (b, "$_ERROR_UNSUPPORTED_VALUE_REGISTRY_");
		if ((index1 & 0x40) != 0)
			nsis_buf_puts (b, "64");
		return;
	}
	nsis_buf_putc (b, '$');
	if (index1 < sizeof (nsis_shell_strings) / sizeof (nsis_shell_strings[0])
	    && nsis_shell_strings[index1])
	{
		nsis_buf_puts (b, nsis_shell_strings[index1]);
		return;
	}
	if (index2 < sizeof (nsis_shell_strings) / sizeof (nsis_shell_strings[0])
	    && nsis_shell_strings[index2])
	{
		nsis_buf_puts (b, nsis_shell_strings[index2]);
		return;
	}
	nsis_buf_puts (b, "_ERROR_UNSUPPORTED_SHELL_[");
	nsis_buf_putnum (b, index1);
	nsis_buf_putc (b, ',');
	nsis_buf_putnum (b, index2);
	nsis_buf_putc (b, ']');
}

static int
nsis_str_at_end (struct nsis_data *a, const grub_uint8_t *p)
{
	return p >= a->hdr + a->hdr_size;
}

static void
nsis_get_string_raw (struct nsis_data *a, struct nsis_buf *b,
		     const grub_uint8_t *s)
{
	unsigned c;

	if (a->nsis_type != NSIS_TYPE_NSIS3)
	{
		for (;;)
		{
			if (nsis_str_at_end (a, s))
				return;
			c = *s++;
			if (c == 0)
				return;
			if (NSIS_SPEC_CHAR (c))
			{
				unsigned c0, c1;

				if (nsis_str_at_end (a, s))
					return;
				c0 = *s++;
				if (c0 == 0)
					return;
				if (c != NS_CODE_SKIP)
				{
					if (nsis_str_at_end (a, s))
						return;
					c1 = *s++;
					if (c1 == 0)
						return;
					if (c == NS_CODE_SHELL)
						nsis_get_shell_string (a, b, c0,
								       c1);
					else
					{
						unsigned n =
							NSIS_DECODE_NUM (c0, c1);

					if (c == NS_CODE_VAR)
						nsis_get_var (a, b, n);
						else
							nsis_add_langstr (b, n);
					}
					continue;
				}
				c = c0;
			}
			nsis_buf_putc (b, c);
		}
	}

	for (;;)
	{
		if (nsis_str_at_end (a, s))
			return;
		c = *s++;
		if (c <= NS_3_CODE_SKIP)
		{
			unsigned c0, c1;

			if (c == 0)
				return;
			if (nsis_str_at_end (a, s))
				return;
			c0 = *s++;
			if (c0 == 0)
				return;
			if (c != NS_3_CODE_SKIP)
			{
				if (nsis_str_at_end (a, s))
					return;
				c1 = *s++;
				if (c1 == 0)
					return;
				if (c == NS_3_CODE_SHELL)
					nsis_get_shell_string (a, b, c0, c1);
				else
				{
					unsigned n = NSIS_DECODE_NUM (c0, c1);

					if (c == NS_3_CODE_VAR)
						nsis_get_var (a, b, n);
					else
						nsis_add_langstr (b, n);
				}
				continue;
			}
			c = c0;
		}
		nsis_buf_putc (b, c);
	}
}

static void
nsis_get_string_unicode_raw (struct nsis_data *a, struct nsis_buf *b,
			     const grub_uint8_t *p)
{
	if (a->nsis_type >= NSIS_TYPE_PARK1)
	{
		for (;;)
		{
			unsigned c;

			if (p + 2 > a->hdr + a->hdr_size)
				return;
			c = nsis_get16 (p);
			p += 2;
			if (c == 0)
				break;
			if (c < 0x80)
			{
				nsis_buf_putc (b, c);
				continue;
			}
			if (NSIS_PARK_SPEC_CHAR (c))
			{
				unsigned n;

				if (p + 2 > a->hdr + a->hdr_size)
					return;
				n = nsis_get16 (p);
				p += 2;
				if (n == 0)
					break;
				if (c != PARK_CODE_SKIP)
				{
					if (c == PARK_CODE_SHELL)
						nsis_get_shell_string (a, b,
								       n & 0xFF,
								       n >> 8);
					else
					{
						NSIS_CONV_PARK (n);
						if (c == PARK_CODE_VAR)
							nsis_get_var (a, b, n);
						else
							nsis_add_langstr (b, n);
					}
					continue;
				}
				c = n;
			}
			nsis_buf_put16 (b, c);
		}
		return;
	}

	for (;;)
	{
		unsigned c;

		if (p + 2 > a->hdr + a->hdr_size)
			return;
		c = nsis_get16 (p);
		p += 2;
		if (c > NS_3_CODE_SKIP)
		{
			nsis_buf_put16 (b, c);
			continue;
		}
		if (c == 0)
			break;

		{
			unsigned n;

			if (p + 2 > a->hdr + a->hdr_size)
				return;
			n = nsis_get16 (p);
			p += 2;
			if (n == 0)
				break;
			if (c == NS_3_CODE_SKIP)
			{
				nsis_buf_put16 (b, n);
				continue;
			}
			if (c == NS_3_CODE_SHELL)
				nsis_get_shell_string (a, b, n & 0xFF, n >> 8);
			else
			{
				NSIS_CONV_NS3 (n);
				if (c == NS_3_CODE_VAR)
					nsis_get_var (a, b, n);
				else
					nsis_add_langstr (b, n);
			}
		}
	}
}

static void
nsis_read_string_raw (struct nsis_data *a, struct nsis_buf *b,
		      grub_uint32_t pos)
{
	b->len = 0;
	if ((grub_int32_t) pos < 0)
		nsis_add_langstr (b, (grub_uint32_t) (0u - (pos + 1u)));
	else if (pos >= a->num_string_chars)
		nsis_buf_puts (b, "$_ERROR_STR_");
	else if (a->is_unicode)
		nsis_get_string_unicode_raw (a, b,
					     a->hdr + a->strings_pos
					     + (grub_size_t) pos * 2);
	else
		nsis_get_string_raw (a, b,
				     a->hdr + a->strings_pos + pos);
}

/* ---------------- command stream helpers ---------------- */

static grub_uint32_t
nsis_get_cmd (struct nsis_data *a, grub_uint32_t v)
{
	if (a->nsis_type < NSIS_TYPE_PARK1)
	{
		if (!a->log_cmd)
			return v;
		if (v < EW_SECTIONSET)
			return v;
		if (v == EW_SECTIONSET)
			return EW_LOG;
		return v - 1;
	}

	if (v < EW_REGISTERDLL)
		return v;
	if (a->nsis_type >= NSIS_TYPE_PARK2)
	{
		if (v == EW_REGISTERDLL)
			return EW_GETFONTVERSION;
		v--;
	}
	if (a->nsis_type >= NSIS_TYPE_PARK3)
	{
		if (v == EW_REGISTERDLL)
			return EW_GETFONTNAME;
		v--;
	}
	if (v >= EW_FSEEK)
	{
		if (a->is_unicode)
		{
			if (v == EW_FSEEK)
				return EW_FPUTWS;
			if (v == EW_FSEEK + 1)
				return EW_FPUTWS + 1;
			v -= 2;
		}
		if (v >= EW_SECTIONSET && a->log_cmd)
		{
			if (v == EW_SECTIONSET)
				return EW_LOG;
			return v - 1;
		}
		if (v == EW_FPUTWS)
			return EW_FINDPROC;
	}
	return v;
}

static grub_int32_t
nsis_get_var_index (struct nsis_data *a, grub_uint32_t strpos)
{
	const grub_uint8_t *p;

	if (strpos >= a->num_string_chars)
		return -1;

	if (a->is_unicode)
	{
		unsigned code, n;

		if (a->num_string_chars - strpos < 6)
			return -1;
		p = a->hdr + a->strings_pos + (grub_size_t) strpos * 2;
		if (a->nsis_type >= NSIS_TYPE_PARK1)
		{
			code = nsis_get16 (p);
			if (code != PARK_CODE_VAR)
				return -1;
			n = nsis_get16 (p + 2);
			if (n == 0)
				return -1;
			NSIS_CONV_PARK (n);
			return (grub_int32_t) n;
		}
		code = nsis_get16 (p);
		if (code != NS_3_CODE_VAR)
			return -1;
		n = nsis_get16 (p + 2);
		if (n == 0)
			return -1;
		NSIS_CONV_NS3 (n);
		return (grub_int32_t) n;
	}

	if (a->num_string_chars - strpos < 4)
		return -1;
	p = a->hdr + a->strings_pos + strpos;
	if (a->nsis_type == NSIS_TYPE_NSIS3)
	{
		if (*p != NS_3_CODE_VAR)
			return -1;
	}
	else if (*p != NS_CODE_VAR)
		return -1;
	if (p[1] == 0 || p[2] == 0)
		return -1;
	return (grub_int32_t) NSIS_DECODE_NUM (p[1], p[2]);
}

static grub_int32_t
nsis_get_var_index_off (struct nsis_data *a, grub_uint32_t strpos,
			grub_uint32_t *res_offset)
{
	grub_int32_t v;

	*res_offset = 0;
	v = nsis_get_var_index (a, strpos);
	if (v < 0)
		return v;
	if (a->is_unicode)
	{
		if (a->num_string_chars - strpos < 4)
			return -1;
		*res_offset = 2;
	}
	else
	{
		if (a->num_string_chars - strpos < 3)
			return -1;
		*res_offset = 3;
	}
	return v;
}

static grub_int32_t
nsis_get_var_index_finished (struct nsis_data *a, grub_uint32_t strpos,
			     grub_uint8_t endchar, grub_uint32_t *res_offset)
{
	grub_int32_t v;

	*res_offset = 0;
	v = nsis_get_var_index (a, strpos);
	if (v < 0)
		return v;
	if (a->is_unicode)
	{
		const grub_uint8_t *p;

		if (a->num_string_chars - strpos < 6)
			return -1;
		p = a->hdr + a->strings_pos + (grub_size_t) strpos * 2;
		if (nsis_get16 (p + 4) != endchar)
			return -1;
		*res_offset = 3;
	}
	else
	{
		const grub_uint8_t *p;

		if (a->num_string_chars - strpos < 4)
			return -1;
		p = a->hdr + a->strings_pos + strpos;
		if (p[3] != endchar)
			return -1;
		*res_offset = 4;
	}
	return v;
}

static int
nsis_is_var_str (struct nsis_data *a, grub_uint32_t strpos,
		 grub_uint32_t varindex)
{
	grub_uint32_t off;

	if (varindex > 0x7FFF)
		return 0;
	return nsis_get_var_index_finished (a, strpos, 0, &off)
	       == (grub_int32_t) varindex;
}

static int
nsis_is_good_string (struct nsis_data *a, grub_uint32_t param)
{
	const grub_uint8_t *p;
	unsigned c;

	if (param >= a->num_string_chars)
		return 0;
	if (param == 0)
		return 1;
	p = a->hdr + a->strings_pos;
	if (a->is_unicode)
		c = nsis_get16 (p + (grub_size_t) param * 2 - 2);
	else
		c = p[param - 1];
	return (c == 0 || c == '\\');
}

static int
nsis_two_strings_equal (struct nsis_data *a, grub_uint32_t p1,
			grub_uint32_t p2)
{
	const grub_uint8_t *p;

	if (p1 == p2)
		return 1;
	if (p1 >= a->num_string_chars || p2 >= a->num_string_chars)
		return 0;
	p = a->hdr + a->strings_pos;
	if (a->is_unicode)
	{
		const grub_uint8_t *a1 = p + (grub_size_t) p1 * 2;
		const grub_uint8_t *a2 = p + (grub_size_t) p2 * 2;

		for (;;)
		{
			grub_uint16_t c = nsis_get16 (a1);

			if (c != nsis_get16 (a2))
				return 0;
			if (c == 0)
				return 1;
			a1 += 2;
			a2 += 2;
		}
	}
	else
	{
		const grub_uint8_t *a1 = p + p1;
		const grub_uint8_t *a2 = p + p2;

		for (;;)
		{
			grub_uint8_t c = *a1++;

			if (c != *a2++)
				return 0;
			if (c == 0)
				return 1;
		}
	}
}

static void
nsis_find_bad_cmd (struct nsis_data *a, grub_uint32_t num,
		   const grub_uint8_t *p)
{
	grub_uint32_t k;

	a->bad_cmd = -1;
	for (k = 0; k < num; k++, p += NSIS_CMD_SIZE)
	{
		grub_uint32_t id = nsis_get_cmd (a, nsis_get32 (p));
		unsigned i;

		if (id >= NSIS_NUM_CMDS)
			continue;
		if (a->bad_cmd >= 0 && id >= (grub_uint32_t) a->bad_cmd)
			continue;
		if (a->nsis_type == NSIS_TYPE_NSIS3)
		{
			if (id == EW_RESERVEDOPCODE)
			{
				a->bad_cmd = (grub_int32_t) id;
				continue;
			}
		}
		else if (id == EW_RESERVEDOPCODE || id == EW_GETOSINFO)
		{
			a->bad_cmd = (grub_int32_t) id;
			continue;
		}
		for (i = 6; i != 0; i--)
			if (nsis_get32 (p + i * 4) != 0)
				break;
		if (id == EW_FINDPROC && i == 0)
		{
			a->bad_cmd = (grub_int32_t) id;
			continue;
		}
		if (nsis_cmd_params[id] < i)
			a->bad_cmd = (grub_int32_t) id;
	}
}

static void
nsis_detect_type (struct nsis_data *a, grub_uint32_t num,
		  const grub_uint8_t *p)
{
	int strong_park = 0, strong_nsis = 0;
	grub_uint32_t i;

	if (a->num_string_chars > 2)
	{
		const grub_uint8_t *str = a->hdr + a->strings_pos;
		grub_uint32_t n = a->num_string_chars - 2;

		if (a->is_unicode)
		{
			for (i = 0; i < n; i++)
				if (nsis_get16 (str + (grub_size_t) i * 2) == 0)
				{
					unsigned c2 = nsis_get16 (str + 2
							+ (grub_size_t) i * 2);

					if (c2 == NS_3_CODE_VAR
					    && (nsis_get16 (str + 4
						+ (grub_size_t) i * 2)
						& 0x8080) == 0x8080)
					{
						a->nsis_type = NSIS_TYPE_NSIS3;
						strong_nsis = 1;
						break;
					}
				}
			if (!strong_nsis)
			{
				a->nsis_type = NSIS_TYPE_PARK1;
				strong_park = 1;
			}
		}
		else
		{
			for (i = 0; i < n; i++)
				if (str[i] == 0)
				{
					unsigned char c2 = str[i + 1];

					if (c2 == NS_3_CODE_VAR
					    && (str[i + 2] & 0x80) != 0)
					{
						a->nsis_type = NSIS_TYPE_NSIS3;
						strong_nsis = 1;
						break;
					}
				}
		}
	}

	if (a->nsis_type == NSIS_TYPE_NSIS2 && !a->is_unicode)
	{
		const grub_uint8_t *p2 = p;

		for (i = 0; i < num; i++, p2 += NSIS_CMD_SIZE)
		{
			grub_uint32_t cmd = nsis_get_cmd (a, nsis_get32 (p2));
			grub_uint32_t params[6];
			unsigned j;

			if (cmd != EW_GETDLGITEM && cmd != EW_ASSIGNVAR)
				continue;
			for (j = 0; j < 6; j++)
				params[j] = nsis_get32 (p2 + 4 + 4 * j);
			if (cmd == EW_GETDLGITEM)
			{
				if (nsis_is_var_str (a, params[1],
						     kVar_HWNDPARENT_225))
				{
					a->is_nsis225 = 1;
					if (params[0] == kVar_Spec_OUTDIR_225)
					{
						a->is_nsis200 = 1;
						break;
					}
				}
			}
			else if (params[0] == kVar_Spec_OUTDIR_225
				 && params[2] == 0 && params[3] == 0
				 && nsis_is_var_str (a, params[1],
						     kVar_OUTDIR))
				a->is_nsis225 = 1;
		}
	}

	{
		int park_detected = 0;

		if (!strong_nsis && !a->is_nsis225 && !a->is_nsis200)
		{
			unsigned mask = 0;
			unsigned num_insert_max = a->is_unicode ? 4 : 2;
			const grub_uint8_t *p2 = p;

			for (i = 0; i < num; i++, p2 += NSIS_CMD_SIZE)
			{
				grub_uint32_t cmd = nsis_get32 (p2);
				grub_uint32_t params[6];
				grub_uint32_t alt, additional = 0;
				unsigned j, num_inserts;

				if (cmd < EW_WRITEUNINSTALLER
				    || cmd > EW_WRITEUNINSTALLER + num_insert_max)
					continue;
				for (j = 0; j < 6; j++)
					params[j] = nsis_get32 (p2 + 4 + 4 * j);
				if (params[4] != 0 || params[5] != 0
				    || params[0] <= 1 || params[3] <= 1)
					continue;
				alt = params[3];
				if (!nsis_is_good_string (a, params[0])
				    || !nsis_is_good_string (a, alt))
					continue;
				if (nsis_get_var_index_finished (a, alt, '\\',
						&additional) != kVar_INSTDIR)
					continue;
				if (nsis_two_strings_equal (a, alt + additional,
							    params[0]))
				{
					num_inserts = cmd - EW_WRITEUNINSTALLER;
					mask |= (unsigned) 1 << num_inserts;
				}
			}

			if (mask == 1)
				park_detected = 1;
			else if (mask != 0)
			{
				grub_uint8_t new_type = a->nsis_type;

				if (a->is_unicode)
				{
					if (mask == (1u << 3))
						new_type = NSIS_TYPE_PARK2;
					else if (mask == (1u << 4))
						new_type = NSIS_TYPE_PARK3;
				}
				else
				{
					if (mask == (1u << 1))
						new_type = NSIS_TYPE_PARK2;
					else if (mask == (1u << 2))
						new_type = NSIS_TYPE_PARK3;
				}
				if (new_type != a->nsis_type)
				{
					park_detected = 1;
					a->nsis_type = new_type;
				}
			}
		}

		nsis_find_bad_cmd (a, num, p);

		if (a->bad_cmd < EW_REGISTERDLL)
			return;

		if (strong_park && !park_detected)
		{
			if (a->bad_cmd < EW_SECTIONSET)
			{
				a->nsis_type = NSIS_TYPE_PARK3;
				a->log_cmd = 1;
				nsis_find_bad_cmd (a, num, p);
				if (a->bad_cmd > 0 && a->bad_cmd < EW_SECTIONSET)
				{
					a->nsis_type = NSIS_TYPE_PARK2;
					a->log_cmd = 0;
					nsis_find_bad_cmd (a, num, p);
					if (a->bad_cmd > 0
					    && a->bad_cmd < EW_SECTIONSET)
					{
						a->nsis_type = NSIS_TYPE_PARK1;
						nsis_find_bad_cmd (a, num, p);
					}
				}
			}
		}

		if (a->bad_cmd >= EW_SECTIONSET)
		{
			a->log_cmd = !a->log_cmd;
			nsis_find_bad_cmd (a, num, p);
			if (a->bad_cmd >= EW_SECTIONSET && a->log_cmd)
			{
				a->log_cmd = 0;
				nsis_find_bad_cmd (a, num, p);
			}
		}
	}
}

/* ---------------- path assembly ---------------- */

static int
nsis_is_letter (char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int
nsis_is_absolute (const char *s)
{
	if (grub_strncasecmp (s, "$INSTDIR", 8) == 0
	    || grub_strncasecmp (s, "$EXEDIR", 7) == 0
	    || grub_strncasecmp (s, "$TEMP", 5) == 0
	    || grub_strncasecmp (s, "$PLUGINSDIR", 11) == 0)
		return 1;
	if (s[0] == '\\' && s[1] == '\\')
		return 1;
	if (s[0] != '\0' && nsis_is_letter (s[0]) && s[1] == ':')
		return 1;
	return 0;
}

/* converts separators and drops empty, "." and ".." components in place */
static void
nsis_normalize_path (char *s)
{
	char *rd;
	char *wr = s;
	int first = 1;

	for (rd = s; *rd; rd++)
		if (*rd == '\\')
			*rd = '/';

	rd = s;
	while (*rd)
	{
		char *comp;
		grub_size_t len;

		while (*rd == '/')
			rd++;
		comp = rd;
		while (*rd && *rd != '/')
			rd++;
		len = (grub_size_t) (rd - comp);
		if (len == 0)
			continue;
		if (len == 1 && comp[0] == '.')
			continue;
		if (len == 2 && comp[0] == '.' && comp[1] == '.')
			continue;
		if (first && len == 8
		    && grub_strncasecmp (comp, "$INSTDIR", 8) == 0)
		{
			first = 0;
			continue;
		}
		first = 0;
		if (wr != s)
			*wr++ = '/';
		grub_memmove (wr, comp, len);
		wr += len;
	}
	*wr = '\0';
}

static char *
nsis_join_path (const char *prefix, const char *name)
{
	grub_size_t pl = grub_strlen (prefix);
	grub_size_t nl = grub_strlen (name);
	char *s = grub_malloc (pl + nl + 2);

	if (!s)
		return 0;
	grub_memcpy (s, prefix, pl);
	s[pl] = '/';
	grub_memcpy (s + pl + 1, name, nl);
	s[pl + nl + 1] = '\0';
	return s;
}

/*
 * Decodes the name at STRPOS and stores the normalized full path in the
 * item.  Returns non-zero when the name was treated as an absolute path.
 */
static int
nsis_set_item_name (struct nsis_data *a, struct nsis_item *it,
		    grub_uint32_t strpos, int force_abs)
{
	struct nsis_buf b;
	char *decoded;
	char *full;
	int is_abs;

	nsis_buf_init (&b, a->is_unicode);
	nsis_read_string_raw (a, &b, strpos);
	decoded = nsis_buf_to_utf8 (&b);
	nsis_buf_fini (&b);
	if (!decoded)
		return force_abs;

	is_abs = force_abs || nsis_is_absolute (decoded);
	if (!is_abs && a->num_prefixes > 0)
		full = nsis_join_path (a->prefixes[a->num_prefixes - 1], decoded);
	else
		full = grub_strdup (decoded);
	grub_free (decoded);
	if (!full)
		return is_abs;

	nsis_normalize_path (full);
	if (full[0] == '\0')
	{
		grub_free (full);
		return is_abs;
	}
	grub_free (it->name);
	it->name = full;
	return is_abs;
}

/* ---------------- prefix list ---------------- */

static int
nsis_add_prefix (struct nsis_data *a, const char *s)
{
	if (a->num_prefixes == a->cap_prefixes)
	{
		unsigned cap = a->cap_prefixes ? a->cap_prefixes * 2 : 16;
		char **n = grub_realloc (a->prefixes, cap * sizeof (*n));

		if (!n)
			return 0;
		a->prefixes = n;
		a->cap_prefixes = cap;
	}
	a->prefixes[a->num_prefixes] = grub_strdup (s);
	if (!a->prefixes[a->num_prefixes])
		return 0;
	a->num_prefixes++;
	return 1;
}

/* ---------------- header parse ---------------- */

static int
nsis_add_item (struct nsis_data *a)
{
	struct nsis_item *it;

	if (a->num_items >= NSIS_ITEMS_MAX)
		return 0;
	if (a->num_items == a->cap_items)
	{
		unsigned cap = a->cap_items ? a->cap_items * 2 : 64;
		struct nsis_item *n = grub_realloc (a->items,
						    cap * sizeof (*n));

		if (!n)
			return 0;
		a->items = n;
		a->cap_items = cap;
	}
	it = &a->items[a->num_items++];
	grub_memset (it, 0, sizeof (*it));
	it->size_known = 0;
	return 1;
}

static void
nsis_read_entries (struct nsis_data *a, grub_uint32_t num,
		   grub_uint32_t offset)
{
	const grub_uint8_t *base = a->hdr + offset;
	grub_uint32_t k;
	grub_uint32_t spec_outdir_varindex =
		a->is_nsis225 ? kVar_Spec_OUTDIR_225 : kVar_Spec_OUTDIR;
	char *prefix0;

	/* the implicit root the SetOutPath values are relative to */
	prefix0 = grub_strdup ("$INSTDIR");
	if (!prefix0 || !nsis_add_prefix (a, prefix0))
	{
		grub_free (prefix0);
		return;
	}
	grub_free (prefix0);

	for (k = 0; k < num; k++)
	{
		const grub_uint8_t *p = base + (grub_size_t) k * NSIS_CMD_SIZE;
		grub_uint32_t command_id = nsis_get_cmd (a, nsis_get32 (p));
		grub_uint32_t params[6];
		unsigned j;

		for (j = 0; j < 6; j++)
			params[j] = nsis_get32 (p + 4 + 4 * j);

		switch (command_id)
		{
		case EW_CREATEDIR:
		{
			int is_set_out_path = (params[1] != 0);

			if (is_set_out_path)
			{
				grub_uint32_t par0 = params[0];
				grub_uint32_t res_offset = 0;
				grub_int32_t idx = nsis_get_var_index_off (a, par0,
									&res_offset);
				const char *pfx = 0;
				struct nsis_buf b;
				char *rest;
				char *full;
				grub_size_t pl, rl;

				if (idx == (grub_int32_t) spec_outdir_varindex
				    && a->spec_outdir)
					pfx = a->spec_outdir;
				else if (idx == kVar_OUTDIR && a->num_prefixes > 0)
					pfx = a->prefixes[a->num_prefixes - 1];
				if (idx == (grub_int32_t) spec_outdir_varindex
				    || idx == kVar_OUTDIR)
					par0 += res_offset;

				nsis_buf_init (&b, a->is_unicode);
				nsis_read_string_raw (a, &b, par0);
				rest = nsis_buf_to_utf8 (&b);
				nsis_buf_fini (&b);
				if (!rest)
					break;
				pl = pfx ? grub_strlen (pfx) : 0;
				rl = grub_strlen (rest);
				full = grub_malloc (pl + rl + 1);
				if (full)
				{
					if (pl)
						grub_memcpy (full, pfx, pl);
					grub_memcpy (full + pl, rest, rl + 1);
					nsis_normalize_path (full);
					if (full[0] != '\0')
						nsis_add_prefix (a, full);
					grub_free (full);
				}
				grub_free (rest);
			}
			break;
		}

		case EW_ASSIGNVAR:
			if (params[0] == spec_outdir_varindex)
			{
				grub_free (a->spec_outdir);
				a->spec_outdir = 0;
				if (nsis_is_var_str (a, params[1], kVar_OUTDIR)
				    && params[2] == 0 && params[3] == 0
				    && a->num_prefixes > 0)
					a->spec_outdir = grub_strdup (
						a->prefixes[a->num_prefixes - 1]);
			}
			break;

		case EW_EXTRACTFILE:
		{
			struct nsis_item *it;

			if (!nsis_add_item (a))
				break;
			it = &a->items[a->num_items - 1];
			nsis_set_item_name (a, it, params[1], 0);
			it->pos = params[2];
			it->mtime = ((grub_int64_t) params[4] << 32) | params[3];
			if (it->mtime != 0)
			{
				grub_uint32_t hi = params[4];

				if (hi <= 0x01000000 || hi >= 0xFF000000)
					it->mtime = 0;
				else
					it->mtime = it->mtime / 10000000
						    - 11644473600LL;
			}

			if (nsis_is_var_str (a, params[1], 10))
			{
				unsigned back = 28;

				if (k > 1 && nsis_get32 (p - NSIS_CMD_SIZE)
						== EW_NOP)
					back -= 2;
				if (k > back)
				{
					const grub_uint8_t *p2 = p - back * NSIS_CMD_SIZE;

					if (nsis_get32 (p2) == EW_ASSIGNVAR)
					{
						grub_uint32_t pars[6];
						unsigned q;

						for (q = 0; q < 6; q++)
							pars[q] = nsis_get32 (p2 + 4 + 4 * q);
						if (pars[0] == 10 + 4 && pars[2] == 0
						    && pars[3] == 0)
						{
							grub_free (it->name);
							it->name = 0;
							nsis_set_item_name (a, it,
									pars[1], 0);
						}
					}
				}
			}
			break;
		}

		case EW_SETFILEATTRIBUTES:
			if (k > 0 && nsis_get32 (p - NSIS_CMD_SIZE) == EW_EXTRACTFILE)
			{
				if (params[0] == nsis_get32 (p - NSIS_CMD_SIZE + 4 + 4))
				{
					struct nsis_item *it = &a->items[a->num_items - 1];

					it->attrib = params[1];
				}
			}
			break;

		case EW_WRITEUNINSTALLER:
		{
			struct nsis_item *it;

			if (!(params[0] > 0 && nsis_is_good_string (a, params[0])))
				break;
			if (a->bad_cmd >= 0 && a->bad_cmd <= EW_WRITEUNINSTALLER)
				break;
			if (!nsis_add_item (a))
				break;
			it = &a->items[a->num_items - 1];
			{
				int was_abs = nsis_set_item_name (a, it,
								  params[0], 0);

				it->pos = params[1];
				it->patch_size = params[2];
				it->is_uninstaller = 1;
				if (params[3] != 0 && !was_abs)
					nsis_set_item_name (a, it, params[3], 1);
			}
			it->unsupported = (it->patch_size != 0);
			break;
		}

		case EW_FOPEN:
			if (params[1] == Z7_NSIS_WIN_GENERIC_WRITE
			    && params[2] == Z7_NSIS_WIN_CREATE_ALWAYS
			    && k + 1 < num
			    && nsis_get32 (p + NSIS_CMD_SIZE) == EW_FCLOSE
			    && nsis_get32 (p + NSIS_CMD_SIZE + 4) == params[0])
			{
				struct nsis_item *it;

				if (!nsis_add_item (a))
					break;
				it = &a->items[a->num_items - 1];
				nsis_set_item_name (a, it, params[3], 0);
				it->is_empty = 1;
			}
			break;

		default:
			break;
		}
	}
}

static int
nsis_item_cmp (const struct nsis_item *a, const struct nsis_item *b)
{
	if (a->pos != b->pos)
		return a->pos < b->pos ? -1 : 1;
	if (a->is_empty != b->is_empty)
		return a->is_empty ? -1 : 1;
	return grub_strcmp (a->name ? a->name : "", b->name ? b->name : "");
}

static void
nsis_sort_items (struct nsis_data *a)
{
	unsigned n = a->num_items, gap, i;

	for (gap = n / 2; gap > 0; gap /= 2)
		for (i = gap; i < n; i++)
		{
			struct nsis_item tmp = a->items[i];
			unsigned j = i;

			while (j >= gap && nsis_item_cmp (&a->items[j - gap], &tmp) > 0)
			{
				a->items[j] = a->items[j - gap];
				j -= gap;
			}
			a->items[j] = tmp;
		}
}

/* reads the 4 byte size/method prefix of a non-solid item */
static void
nsis_non_solid_probe (struct nsis_data *a)
{
	unsigned i;

	for (i = 0; i < a->num_items; i++)
	{
		struct nsis_item *it = &a->items[i];
		grub_uint64_t pos;
		grub_uint8_t raw[4];
		grub_uint32_t v;

		if (it->is_empty || it->is_uninstaller || it->patch_size != 0)
			continue;
		pos = a->data_section_base + it->pos;
		if (pos + 4 > a->disk_size)
			continue;
		if (grub_disk_read (a->disk, 0, pos, 4, raw))
		{
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		v = nsis_get32 (raw);
		if ((v & NSIS_MASK_COMPRESSED) != 0)
		{
			it->packed = v & ~NSIS_MASK_COMPRESSED;
		}
		else
		{
			it->size = v;
			it->size_known = 1;
		}
	}
}

/* solid items carry their uncompressed size right before their data */
static void
nsis_estimate_sizes (struct nsis_data *a)
{
	unsigned i;

	for (i = 0; i < a->num_items; i++)
	{
		struct nsis_item *it = &a->items[i];
		unsigned j;

		if (it->size_known || it->is_empty || it->is_uninstaller)
			continue;
		for (j = i + 1; j < a->num_items; j++)
		{
			grub_uint32_t next = a->items[j].pos;

			if (it->pos + 4 <= next)
			{
				it->size = next - it->pos - 4;
				it->size_known = 1;
				break;
			}
		}
	}
}

static int
nsis_parse_header (struct nsis_data *a)
{
	grub_uint8_t bho_size;
	const grub_uint8_t *p1 = a->hdr;
	grub_uint32_t bh_entries_off, bh_entries_num;
	grub_uint32_t bh_strings_off;
	grub_uint32_t bh_lang_off;
	grub_uint32_t string_table_size;
	const grub_uint8_t *str_data;
	grub_uint32_t k;
	grub_uint8_t is64 = 0;

	if (a->hdr_size < 4 + 12 * 8)
		is64 = 0;
	else
	{
		is64 = 1;
		for (k = 0; k < 8; k++)
			if (nsis_get32 (p1 + 4 + 12 * k + 4) != 0)
				is64 = 0;
	}
	a->is_64bit = is64;
	bho_size = is64 ? 12 : 8;
	if (a->hdr_size < (grub_size_t) 4 + (grub_size_t) bho_size * 8)
		return 0;

#define NSIS_BH_OFF(i)	nsis_get32 (p1 + 4 + bho_size * (i))
#define NSIS_BH_NUM(i)	nsis_get32 (p1 + 4 + bho_size * (i) + bho_size - 4)

	if (bho_size == 12)
		for (k = 0; k < 8; k++)
			if (nsis_get32 (p1 + 4 + 12 * k + 4) != 0)
				return 0;

	bh_entries_off = NSIS_BH_OFF (2);
	bh_entries_num = NSIS_BH_NUM (2);
	bh_strings_off = NSIS_BH_OFF (3);
	bh_lang_off = NSIS_BH_OFF (4);

#undef NSIS_BH_OFF
#undef NSIS_BH_NUM

	if (bh_strings_off > a->hdr_size || bh_lang_off > a->hdr_size
	    || bh_entries_off > a->hdr_size)
		return 0;
	if (bh_lang_off < bh_strings_off)
		return 0;
	string_table_size = bh_lang_off - bh_strings_off;
	if (string_table_size < 2)
		return 0;
	str_data = a->hdr + bh_strings_off;
	if (str_data[string_table_size - 1] != 0)
		return 0;
	a->strings_pos = bh_strings_off;
	a->is_unicode = (nsis_get16 (str_data) == 0);
	a->num_string_chars = string_table_size;
	if (a->is_unicode)
	{
		if ((string_table_size & 1) != 0)
			return 0;
		a->num_string_chars >>= 1;
		if (str_data[string_table_size - 2] != 0)
			return 0;
	}

	if (bh_entries_num > (1u << 24))
		return 0;
	if ((grub_uint64_t) bh_entries_num * NSIS_CMD_SIZE
	    > (grub_uint64_t) a->hdr_size - bh_entries_off)
		return 0;

	a->nsis_type = NSIS_TYPE_NSIS2;
	a->is_nsis200 = 0;
	a->is_nsis225 = 0;
	a->log_cmd = 0;
	a->bad_cmd = -1;

	nsis_detect_type (a, bh_entries_num, a->hdr + bh_entries_off);
	nsis_read_entries (a, bh_entries_num, bh_entries_off);

	nsis_sort_items (a);
	nsis_estimate_sizes (a);

	a->nsis_deflate = (a->nsis_type != NSIS_TYPE_NSIS3);
	return 1;
}

/* ---------------- archive open ---------------- */

static int
nsis_is_lzma (const grub_uint8_t *p, grub_uint32_t *dict, int *there_flag)
{
	if (p[0] == 0x5D && p[1] == 0x00 && p[2] == 0x00
	    && p[5] == 0x00 && (p[6] & 0x80) == 0x00)
	{
		*dict = nsis_get32 (p + 1);
		*there_flag = 0;
		return 1;
	}
	if (p[0] <= 1 && p[1] == 0x5D && p[2] == 0x00 && p[3] == 0x00
	    && p[6] == 0x00 && (p[7] & 0x80) == 0x00)
	{
		*dict = nsis_get32 (p + 2);
		*there_flag = 1;
		return 1;
	}
	return 0;
}

static int
nsis_is_bzip2 (const grub_uint8_t *p)
{
	return (p[0] == 0x31 && p[1] < 14);
}

/* reads HeaderSize bytes of decompressed command data into a->hdr */
static grub_err_t
nsis_load_header (struct nsis_data *a, const grub_uint8_t *sig)
{
	grub_uint32_t comp_hdr_size = nsis_get32 (sig);
	grub_ssize_t got;
	grub_size_t want;
	struct nsis_stm *stm;
	grub_uint8_t temp[4];

	a->is_solid = 1;
	a->header_compressed = 1;
	a->method = NSIS_M_COPY;
	a->filter_flag = 0;
	a->dict_size = 1;
	a->use_filter = 0;

	if (comp_hdr_size == a->header_size)
	{
		a->header_compressed = 0;
		a->is_solid = 0;
		a->method = NSIS_M_COPY;
	}
	else
	{
		int there_flag = 0;

		if (nsis_is_lzma (sig, &a->dict_size, &there_flag))
		{
			a->method = NSIS_M_LZMA;
			a->filter_flag = (grub_uint8_t) there_flag;
		}
		else if (sig[3] == 0x80)
		{
			a->is_solid = 0;
			if (nsis_is_lzma (sig + 4, &a->dict_size, &there_flag))
			{
				a->method = NSIS_M_LZMA;
				a->filter_flag = (grub_uint8_t) there_flag;
			}
			else if (nsis_is_bzip2 (sig + 4))
				a->method = NSIS_M_BZIP2;
			else
				a->method = NSIS_M_DEFLATE;
		}
		else if (nsis_is_bzip2 (sig))
			a->method = NSIS_M_BZIP2;
		else
			a->method = NSIS_M_DEFLATE;

		if (!a->is_solid)
		{
			a->header_compressed =
				((comp_hdr_size & NSIS_MASK_COMPRESSED) != 0);
			comp_hdr_size &= ~NSIS_MASK_COMPRESSED;
		}
	}

	/* the data section starts right behind the (compressed) header;
	   for non-solid archives the leading size field is 4 bytes */
	if (!a->is_solid)
		a->data_section_base = a->arc_pos + NSIS_START_HEADER_SIZE
				       + 4 + comp_hdr_size;

	a->hdr = grub_malloc (a->header_size ? a->header_size : 1);
	if (!a->hdr)
		return grub_errno;
	a->hdr_size = a->header_size;

	if (!a->header_compressed)
	{
		grub_uint64_t pos = a->arc_pos + NSIS_START_HEADER_SIZE + 4;

		if (pos + a->header_size > a->disk_size)
			goto truncated;
		if (grub_disk_read (a->disk, 0, pos, a->header_size, a->hdr))
			return grub_errno;
		return GRUB_ERR_NONE;
	}

	{
		grub_uint64_t pos = a->arc_pos + NSIS_START_HEADER_SIZE;
		grub_uint64_t len;

		if (a->is_solid)
			pos += 0;
		else
			pos += 4;
		if (a->arc_size < (pos - a->arc_pos))
			goto truncated;
		len = a->arc_size - (pos - a->arc_pos);

		stm = nsis_decoder_create (a->disk, pos, len, a->method,
					   a->filter_flag, 1);
		if (!stm)
			return grub_errno;

		if (a->is_solid)
		{
			got = stm->read (stm, temp, 4);
			if (got != 4)
			{
				stm->free (stm);
				goto truncated;
			}
			if (nsis_get32 (temp) != a->header_size)
			{
				stm->free (stm);
				grub_error (GRUB_ERR_BAD_FS,
					    "bad nsis solid header size");
				return grub_errno;
			}
		}

		want = 0;
		while (want < a->header_size)
		{
			grub_size_t n = a->header_size - want;
			grub_ssize_t r = stm->read (stm, a->hdr + want, n);

			if (r < 0)
			{
				stm->free (stm);
				return grub_errno;
			}
			if (r == 0)
			{
				stm->free (stm);
				goto truncated;
			}
			want += (grub_size_t) r;
		}
		stm->free (stm);
	}
	return GRUB_ERR_NONE;

truncated:
	if (!grub_errno)
		grub_error (GRUB_ERR_BAD_FS, "truncated nsis archive");
	return grub_errno;
}

static void
nsis_free_data (struct nsis_data *a)
{
	unsigned i;

	if (!a)
		return;
	for (i = 0; i < a->num_items; i++)
		grub_free (a->items[i].name);
	grub_free (a->items);
	for (i = 0; i < a->num_prefixes; i++)
		grub_free (a->prefixes[i]);
	grub_free (a->prefixes);
	grub_free (a->spec_outdir);
	grub_free (a->hdr);
	grub_free (a);
}

static struct nsis_data *
grub_nsis_mount (grub_disk_t disk)
{
	struct nsis_data *a = 0;
	grub_uint8_t block[NSIS_SCAN_STEP];
	grub_uint64_t scan_max, pos;
	grub_uint32_t flags;
	int found = 0;

	if (grub_disk_read (disk, 0, 0, NSIS_SCAN_STEP, block))
	{
		grub_error (GRUB_ERR_BAD_FS, "not an nsis installer");
		return 0;
	}

	scan_max = grub_disk_native_sectors (disk) << GRUB_DISK_SECTOR_BITS;
	if (scan_max > NSIS_SCAN_MAX)
		scan_max = NSIS_SCAN_MAX;

	for (pos = 0; pos + NSIS_START_HEADER_SIZE <= scan_max;
	     pos += NSIS_SCAN_STEP)
	{
		if (pos != 0
		    && grub_disk_read (disk, 0, pos, NSIS_SCAN_STEP, block))
			break;
		if (grub_memcmp (block + 4, nsis_signature, NSIS_SIG_SIZE) == 0)
		{
			found = 1;
			break;
		}
		if (scan_max - pos <= NSIS_SCAN_STEP)
			break;
	}
	if (!found)
		goto fail;

	flags = nsis_get32 (block);
	if ((flags & ~NSIS_FLAG_MASK) != 0)
		goto fail;

	a = grub_zalloc (sizeof (*a));
	if (!a)
		goto fail;
	a->disk = disk;
	a->disk_size = grub_disk_native_sectors (disk) << GRUB_DISK_SECTOR_BITS;
	a->arc_pos = pos;
	a->header_size = nsis_get32 (block + 4 + NSIS_SIG_SIZE);
	a->arc_size = nsis_get32 (block + 4 + NSIS_SIG_SIZE + 4);

	if (a->header_size == 0 || a->header_size > NSIS_MAX_HEADER
	    || a->arc_size <= NSIS_START_HEADER_SIZE
	    || a->arc_pos + a->arc_size > a->disk_size)
	{
		grub_error (GRUB_ERR_BAD_FS, "bad nsis archive geometry");
		goto fail;
	}

	if (nsis_load_header (a, block + NSIS_START_HEADER_SIZE))
		goto fail;
	if (!nsis_parse_header (a))
	{
		grub_error (GRUB_ERR_BAD_FS, "corrupt nsis command stream");
		goto fail;
	}

	if (!a->is_solid)
		nsis_non_solid_probe (a);

	if (a->num_items == 0)
	{
		grub_error (GRUB_ERR_BAD_FS, "nsis archive has no entries");
		goto fail;
	}
	return a;

fail:
	nsis_free_data (a);
	return 0;
}

/* ---------------- directory listing ---------------- */

static const char *
nsis_norm_path (const char *path, grub_size_t *len)
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
nsis_name_in_dir (const char *name, const char *dir, grub_size_t dir_len,
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
	*child = rest;
	*child_len = slash ? (grub_size_t) (slash - rest) : grub_strlen (rest);
	*is_dir = slash != 0;
	return *child_len != 0;
}

struct nsis_seen
{
	struct nsis_seen *next;
	char *name;
};

static grub_uint32_t
nsis_hash_name (const char *s)
{
	grub_uint32_t h = 5381;

	while (*s)
		h = h * 33 + (grub_uint8_t) *s++;
	return h & (NSIS_SEEN_BUCKETS - 1);
}

/* implicit directories have no item of their own, so identify them by path */
static grub_uint64_t
nsis_dir_id (const char *dir, grub_size_t dir_len, const char *child,
	     grub_size_t child_len)
{
	grub_uint64_t h = 1469598103934665603ULL;
	grub_size_t i;

	for (i = 0; i < dir_len; i++)
	{
		h ^= (grub_uint8_t) dir[i];
		h *= 1099511628211ULL;
	}
	h ^= (grub_uint8_t) '/';
	h *= 1099511628211ULL;
	for (i = 0; i < child_len; i++)
	{
		h ^= (grub_uint8_t) child[i];
		h *= 1099511628211ULL;
	}
	return h;
}

static int
nsis_seen_add (struct nsis_seen **buckets, char *name)
{
	grub_uint32_t h = nsis_hash_name (name);
	struct nsis_seen *e;

	for (e = buckets[h]; e; e = e->next)
		if (grub_strcmp (e->name, name) == 0)
			return 1;
	e = grub_malloc (sizeof (*e));
	if (!e)
		return -1;
	e->name = name;
	e->next = buckets[h];
	buckets[h] = e;
	return 0;
}

static grub_err_t
grub_nsis_dir (grub_device_t device, const char *path,
	       grub_fs_dir_hook_t hook, void *hook_data)
{
	struct nsis_data *a;
	const char *dir;
	grub_size_t dir_len;
	struct nsis_seen **buckets;
	unsigned i;
	int found;
	grub_err_t err = GRUB_ERR_NONE;

	a = grub_nsis_mount (device->disk);
	if (!a)
		return grub_errno;

	dir = nsis_norm_path (path, &dir_len);
	found = (dir_len == 0);

	buckets = grub_calloc (NSIS_SEEN_BUCKETS, sizeof (*buckets));
	if (!buckets)
	{
		grub_errno = GRUB_ERR_OUT_OF_MEMORY;
		nsis_free_data (a);
		return grub_errno;
	}

	for (i = 0; i < a->num_items; i++)
	{
		struct grub_dirhook_info info;
		const char *child;
		grub_size_t child_len;
		int child_is_dir;
		char *name;
		int dup;
		struct nsis_item *it = &a->items[i];

		if (!it->name)
			continue;
		if (!nsis_name_in_dir (it->name, dir, dir_len, &child,
				       &child_len, &child_is_dir))
		{
			if (dir_len != 0 && grub_strcmp (it->name, dir) == 0)
				found = 1;
			continue;
		}
		found = 1;

		name = grub_malloc (child_len + 1);
		if (!name)
		{
			err = GRUB_ERR_OUT_OF_MEMORY;
			goto out;
		}
		grub_memcpy (name, child, child_len);
		name[child_len] = '\0';

		dup = nsis_seen_add (buckets, name);
		if (dup)
		{
			grub_free (name);
			if (dup < 0)
			{
				err = GRUB_ERR_OUT_OF_MEMORY;
				goto out;
			}
			continue;
		}

		grub_memset (&info, 0, sizeof (info));
		info.dir = child_is_dir;
		info.inodeset = 1;
		info.inode = child_is_dir
			? nsis_dir_id (dir, dir_len, child, child_len)
			: i;
		if (!child_is_dir)
		{
			if (it->attrib & 0x10)
				info.dir = 1;
			if (it->mtime != 0)
			{
				info.mtimeset = 1;
				info.mtime = it->mtime;
			}
			if (it->size_known)
			{
				info.sizeset = 1;
				info.size = it->size;
			}
		}

		if (hook (name, &info, hook_data))
			goto out;
	}

	if (!found)
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found",
				  path);

out:
	for (i = 0; i < NSIS_SEEN_BUCKETS; i++)
		while (buckets[i])
		{
			struct nsis_seen *e = buckets[i];

			buckets[i] = e->next;
			grub_free (e->name);
			grub_free (e);
		}
	grub_free (buckets);
	nsis_free_data (a);
	return err;
}

/* ---------------- file access ---------------- */

static struct nsis_item *
nsis_find_item (struct nsis_data *a, const char *name)
{
	grub_size_t len;
	const char *path = nsis_norm_path (name, &len);
	unsigned i;

	for (i = 0; i < a->num_items; i++)
	{
		const char *n = a->items[i].name;

		if (!n)
			continue;
		if (grub_strncmp (n, path, len) == 0 && n[len] == '\0')
			return &a->items[i];
	}
	return 0;
}

struct grub_nsis_file
{
	struct nsis_data *data;
	struct nsis_item *item;
	/* solid incremental stream */
	struct nsis_stm *stm;
	grub_uint64_t stm_pos;
	grub_uint64_t prefix_pos;
	grub_uint8_t *skip_buf;
	/* non-solid stored */
	int direct;
	/* non-solid compressed, fully decoded */
	grub_uint8_t *buf;
	grub_uint64_t buf_size;
};

static grub_err_t
nsis_solid_restart (struct grub_nsis_file *ctx)
{
	struct nsis_data *a = ctx->data;
	grub_uint8_t temp[4];
	grub_ssize_t got;

	if (ctx->stm)
	{
		ctx->stm->free (ctx->stm);
		ctx->stm = 0;
	}
	ctx->stm = nsis_decoder_create (a->disk, a->arc_pos + NSIS_START_HEADER_SIZE,
					a->arc_size - NSIS_START_HEADER_SIZE,
					a->method, a->filter_flag,
					a->nsis_deflate);
	if (!ctx->stm)
		return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;

	if (!ctx->skip_buf)
	{
		ctx->skip_buf = grub_malloc (NSIS_IN_BUF);
		if (!ctx->skip_buf)
			return grub_errno;
	}

	{
		grub_uint64_t left = ctx->prefix_pos;

		while (left > 0)
		{
			grub_size_t n = NSIS_IN_BUF;
			grub_ssize_t r;

			if ((grub_uint64_t) n > left)
				n = (grub_size_t) left;
			r = ctx->stm->read (ctx->stm, ctx->skip_buf, n);
			if (r < 0)
				return grub_errno;
			if (r == 0)
				return grub_error (GRUB_ERR_BAD_FS,
						   "truncated nsis solid stream");
			left -= (grub_uint64_t) r;
		}
	}

	got = ctx->stm->read (ctx->stm, temp, 4);
	if (got != 4)
		return grub_error (GRUB_ERR_BAD_FS, "truncated nsis entry");
	/* every solid entry is preceded by its uncompressed size */
	ctx->item->size = nsis_get32 (temp);
	ctx->item->size_known = 1;
	ctx->stm_pos = 0;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_nsis_open (struct grub_file *file, const char *name)
{
	struct nsis_data *a;
	struct nsis_item *it;
	struct grub_nsis_file *ctx;

	a = grub_nsis_mount (file->device->disk);
	if (!a)
		return grub_errno;

	it = nsis_find_item (a, name);
	if (!it)
	{
		grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", name);
		goto fail;
	}
	if (it->attrib & 0x10)
	{
		grub_error (GRUB_ERR_BAD_FILE_TYPE, "is a directory");
		goto fail;
	}
	if (it->unsupported)
	{
		grub_error (GRUB_ERR_BAD_FS,
			    "patched nsis uninstaller cannot be read");
		goto fail;
	}

	ctx = grub_zalloc (sizeof (*ctx));
	if (!ctx)
		goto fail;
	ctx->data = a;
	ctx->item = it;

	if (it->is_empty)
	{
		file->size = 0;
	}
	else if (a->is_solid)
	{
		ctx->prefix_pos = 4 + a->header_size + it->pos;
		if (nsis_solid_restart (ctx))
			goto fail_ctx;
		file->size = it->size;
	}
	else if (it->packed == 0)
	{
		ctx->direct = 1;
		file->size = it->size;
	}
	else
	{
		struct nsis_stm *stm;
		grub_uint64_t cap = it->packed;
		grub_uint64_t got_total = 0;
		grub_uint8_t *buf;

		if (cap > NSIS_UNPACK_MAX)
			cap = NSIS_UNPACK_MAX;
		if (cap < 4096)
			cap = 4096;
		buf = grub_malloc ((grub_size_t) cap);
		if (!buf)
			goto fail_ctx;

		stm = nsis_decoder_create (a->disk,
					   a->data_section_base + it->pos + 4,
					   it->packed, a->method,
					   a->filter_flag, a->nsis_deflate);
		if (!stm)
		{
			grub_free (buf);
			goto fail_ctx;
		}
		for (;;)
		{
			grub_ssize_t r;
			grub_size_t room;

			if (got_total == cap)
			{
				grub_uint64_t ncap = cap * 2;

				if (ncap > NSIS_UNPACK_MAX)
				{
					stm->free (stm);
					grub_free (buf);
					grub_error (GRUB_ERR_BAD_FS,
						    "nsis entry too large to unpack");
					goto fail_ctx;
				}
				{
					grub_uint8_t *nb = grub_realloc (buf,
						(grub_size_t) ncap);

					if (!nb)
					{
						stm->free (stm);
						grub_free (buf);
						goto fail_ctx;
					}
					buf = nb;
					cap = ncap;
				}
			}
			room = (grub_size_t) (cap - got_total);
			r = stm->read (stm, buf + got_total, room);
			if (r < 0)
			{
				stm->free (stm);
				grub_free (buf);
				goto fail_ctx;
			}
			if (r == 0)
				break;
			got_total += (grub_uint64_t) r;
		}
		stm->free (stm);
		ctx->buf = buf;
		ctx->buf_size = got_total;
		file->size = got_total;
	}

	file->data = ctx;
	file->not_easily_seekable = 1;
	return GRUB_ERR_NONE;

fail_ctx:
	nsis_free_data (a);
	grub_free (ctx);
	grub_errno = grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
	return grub_errno;

fail:
	nsis_free_data (a);
	return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
}

static grub_ssize_t
grub_nsis_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_nsis_file *ctx = file->data;
	struct nsis_data *a = ctx->data;
	struct nsis_item *it = ctx->item;
	grub_size_t done = 0;

	if (it->is_empty)
		return 0;

	if (ctx->buf)
	{
		grub_uint64_t off = (grub_uint64_t) file->offset;

		if (off >= ctx->buf_size)
			return 0;
		if (len > ctx->buf_size - off)
			len = (grub_size_t) (ctx->buf_size - off);
		grub_memcpy (buf, ctx->buf + off, len);
		return (grub_ssize_t) len;
	}

	if (ctx->direct)
	{
		grub_uint64_t off = (grub_uint64_t) file->offset;

		if (it->size == 0 || off >= it->size)
			return 0;
		if (len > it->size - off)
			len = (grub_size_t) (it->size - off);
		if (len == 0)
			return 0;
		if (grub_disk_read (a->disk, 0,
				    a->data_section_base + it->pos + 4 + off,
				    len, buf))
			return -1;
		return (grub_ssize_t) len;
	}

	/* solid stream */
	if ((grub_uint64_t) file->offset < ctx->stm_pos || !ctx->stm)
	{
		if (nsis_solid_restart (ctx))
			return -1;
	}
	while (ctx->stm_pos < (grub_uint64_t) file->offset)
	{
		grub_size_t n = NSIS_IN_BUF;
		grub_ssize_t r;

		if ((grub_uint64_t) n > (grub_uint64_t) file->offset - ctx->stm_pos)
			n = (grub_size_t) ((grub_uint64_t) file->offset - ctx->stm_pos);
		r = ctx->stm->read (ctx->stm, ctx->skip_buf, n);
		if (r < 0)
			return -1;
		if (r == 0)
		{
			grub_error (GRUB_ERR_BAD_FS, "truncated nsis entry");
			return -1;
		}
		ctx->stm_pos += (grub_uint64_t) r;
	}

	while (done < len)
	{
		grub_ssize_t r = ctx->stm->read (ctx->stm,
						 (grub_uint8_t *) buf + done,
						 len - done);

		if (r < 0)
			return -1;
		if (r == 0)
			break;
		done += (grub_size_t) r;
		ctx->stm_pos += (grub_uint64_t) r;
	}
	return (grub_ssize_t) done;
}

static grub_err_t
grub_nsis_close (grub_file_t file)
{
	struct grub_nsis_file *ctx = file->data;

	if (ctx)
	{
		if (ctx->stm)
			ctx->stm->free (ctx->stm);
		grub_free (ctx->skip_buf);
		grub_free (ctx->buf);
		nsis_free_data (ctx->data);
		grub_free (ctx);
		file->data = 0;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_nsis_mtime (grub_device_t device, grub_int64_t *tm)
{
	struct nsis_data *a;
	unsigned i;

	*tm = 0;
	a = grub_nsis_mount (device->disk);
	if (!a)
		return grub_errno;
	for (i = 0; i < a->num_items; i++)
		if (a->items[i].mtime > *tm)
			*tm = a->items[i].mtime;
	nsis_free_data (a);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_nsis_fs =
{
	.name = "nsis",
	.fs_dir = grub_nsis_dir,
	.fs_open = grub_nsis_open,
	.fs_read = grub_nsis_read,
	.fs_close = grub_nsis_close,
	.fs_label = 0,
	.fs_mtime = grub_nsis_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (nsis)
{
	grub_nsis_fs.mod = mod;
	grub_fs_register (&grub_nsis_fs);
}

GRUB_MOD_FINI (nsis)
{
	grub_fs_unregister (&grub_nsis_fs);
}
