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

/*
 *  Read-only eXtensible ARchive (.xar / .pkg / .xip) filesystem driver.
 *
 *  A xar is a big endian header, a zlib compressed XML table of contents
 *  and a heap.  Every file names its own byte range of the heap and its
 *  own compressor, so unlike a tarball nothing has to be walked to list
 *  the archive: the whole directory tree is in the table of contents.
 */

#include <grub/types.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/datetime.h>
#include <grub/deflate.h>
#include <grub/pkghelp.h>
#include <grub/dl.h>

#include <yxml.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define XAR_MAGIC		0x78617221	/* "xar!" */
#define XAR_HEAD_MIN		28
/* the format allows any header size; a bigger one is not a xar to us */
#define XAR_HEAD_MAX		64

#define XAR_TOC_PACK_MAX	(16UL << 20)
#define XAR_TOC_MAX		(64UL << 20)

#define XAR_STACK_SIZE		8192	/* yxml element name stack */
#define XAR_FIELD_MAX		4096	/* longest table of contents value */
#define XAR_MAX_NODES		(1U << 20)
#define XAR_MAX_DEPTH		256

#define XAR_TOC_NAME		"[TOC].xml"

PRAGMA_BEGIN_PACKED
struct xar_header
{
	grub_uint32_t magic;
	grub_uint16_t size;
	grub_uint16_t version;
	grub_uint64_t toc_packed;
	grub_uint64_t toc_unpacked;
	grub_uint32_t cksum_alg;
} GRUB_PACKED;
PRAGMA_END_PACKED

/* one <file> element of the table of contents */
struct xar_node
{
	char *name;
	char *link;		/* symlink target */
	grub_off_t off;		/* start of the data within the heap */
	grub_off_t plen;	/* its length there */
	grub_off_t size;	/* length once decoded */
	grub_int64_t mtime;
	int parent;		/* index of the enclosing <file>, -1 at the root */
	int depth;		/* XML depth of the <file> element */
	int codec;		/* GRUB_PKG_CODEC_* */
	unsigned is_dir:1;
	unsigned is_lnk:1;
	unsigned has_data:1;
};

/* the value being collected out of the table of contents */
enum xar_field
{
	XAR_F_NONE = 0,
	XAR_F_CREATED,
	XAR_F_NAME,
	XAR_F_TYPE,
	XAR_F_LINK,
	XAR_F_MTIME,
	XAR_F_OFFSET,
	XAR_F_LENGTH,
	XAR_F_SIZE,
	XAR_F_ENCODING
};

struct xar_parser
{
	struct xar_node *nodes;
	unsigned num_nodes;
	unsigned max_nodes;
	int cur;		/* innermost open <file>, -1 when outside one */
	int depth;		/* current XML element depth */
	int data_depth;		/* depth of the open <data>, 0 when none */
	int enc_depth;		/* depth of the open <encoding>, 0 when none */
	int field;		/* enum xar_field, what is being collected */
	int field_depth;
	int in_toc;
	int overflow;
	grub_int64_t created;
	grub_size_t len;
	char buf[XAR_FIELD_MAX + 1];
};

/* the encoding style is a MIME type; the reference tool writes these */
static const struct
{
	const char *style;
	int codec;
}
xar_encodings[] =
{
	{ "application/octet-stream",	GRUB_PKG_CODEC_NONE },
	{ "application/x-gzip",		GRUB_PKG_CODEC_ZLIB },
	{ "application/x-bzip2",	GRUB_PKG_CODEC_BZIP2 },
	{ "application/x-xz",		GRUB_PKG_CODEC_XZ }
};

static int
xar_codec (const char *style)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE (xar_encodings); i++)
		if (grub_strcmp (style, xar_encodings[i].style) == 0)
			return xar_encodings[i].codec;
	return GRUB_PKG_CODEC_OTHER;
}

/* saturates instead of wrapping, so a silly value stays a silly value */
static grub_uint64_t
xar_number (const char *str)
{
	const grub_uint64_t max = ~(grub_uint64_t) 0;
	grub_uint64_t ret = 0;

	if (*str < '0' || *str > '9')
		return max;
	for (; *str >= '0' && *str <= '9'; str++)
	{
		if (ret > (max - (grub_uint64_t) (*str - '0')) / 10)
			return max;
		ret = ret * 10 + (grub_uint64_t) (*str - '0');
	}
	return ret;
}

static unsigned
xar_dec (const char *str, unsigned num)
{
	unsigned ret = 0;

	while (num--)
		ret = ret * 10 + (unsigned) (*str++ - '0');
	return ret;
}

/* "YYYY-MM-DDThh:mm:ssZ"; the zone and any fraction are ignored */
static grub_int64_t
xar_time (const char *str)
{
	struct grub_datetime dt;
	grub_int64_t nix;
	unsigned i;

	for (i = 0; i < 19; i++)
	{
		char c = str[i];

		if (i == 4 || i == 7)
		{
			if (c != '-')
				return 0;
		}
		else if (i == 10)
		{
			if (c != 'T')
				return 0;
		}
		else if (i == 13 || i == 16)
		{
			if (c != ':')
				return 0;
		}
		else if (c < '0' || c > '9')
			return 0;
	}

	dt.year = (grub_uint16_t) xar_dec (str, 4);
	dt.month = (grub_uint8_t) xar_dec (str + 5, 2);
	dt.day = (grub_uint8_t) xar_dec (str + 8, 2);
	dt.hour = (grub_uint8_t) xar_dec (str + 11, 2);
	dt.minute = (grub_uint8_t) xar_dec (str + 14, 2);
	dt.second = (grub_uint8_t) xar_dec (str + 17, 2);

	if (!grub_datetime2unixtime (&dt, &nix))
		return 0;
	return nix;
}

/* Table of contents parser */

static struct xar_node *
xar_new_node (struct xar_parser *ps)
{
	struct xar_node *nd;

	if (ps->num_nodes == ps->max_nodes)
	{
		unsigned num = ps->max_nodes ? ps->max_nodes * 2 : 64;
		struct xar_node *grown;

		if (num > XAR_MAX_NODES)
		{
			grub_error (GRUB_ERR_BAD_FS, "too many files in archive");
			return 0;
		}
		grown = grub_realloc (ps->nodes, num * sizeof (*grown));
		if (!grown)
			return 0;
		ps->nodes = grown;
		ps->max_nodes = num;
	}

	nd = &ps->nodes[ps->num_nodes++];
	grub_memset (nd, 0, sizeof (*nd));
	nd->parent = ps->cur;
	nd->depth = ps->depth;
	nd->codec = GRUB_PKG_CODEC_NONE;
	return nd;
}

/* depth of the <file> element the parser is inside of, 2 = <toc> itself */
static int
xar_file_depth (const struct xar_parser *ps)
{
	return (ps->cur < 0) ? 2 : ps->nodes[ps->cur].depth;
}

static void
xar_collect (struct xar_parser *ps, int field)
{
	ps->field = field;
	ps->field_depth = ps->depth;
	ps->len = 0;
	ps->overflow = 0;
}

static int
xar_file_field (const char *name)
{
	if (grub_strcmp (name, "name") == 0)
		return XAR_F_NAME;
	if (grub_strcmp (name, "type") == 0)
		return XAR_F_TYPE;
	if (grub_strcmp (name, "link") == 0)
		return XAR_F_LINK;
	if (grub_strcmp (name, "mtime") == 0)
		return XAR_F_MTIME;
	return XAR_F_NONE;
}

static int
xar_data_field (const char *name)
{
	if (grub_strcmp (name, "offset") == 0)
		return XAR_F_OFFSET;
	if (grub_strcmp (name, "length") == 0)
		return XAR_F_LENGTH;
	if (grub_strcmp (name, "size") == 0)
		return XAR_F_SIZE;
	return XAR_F_NONE;
}

static grub_err_t
xar_elem_start (struct xar_parser *ps, const char *name)
{
	ps->depth++;
	if (ps->depth > XAR_MAX_DEPTH)
		return grub_error (GRUB_ERR_BAD_FS, "xar tree too deep");

	/* a value never has child elements; one ends the collection */
	if (ps->field != XAR_F_NONE && ps->depth > ps->field_depth)
		ps->field = XAR_F_NONE;

	if (ps->depth == 1)
	{
		if (grub_strcmp (name, "xar") != 0)
			return grub_error (GRUB_ERR_BAD_FS,
					   "not a xar table of contents");
		return GRUB_ERR_NONE;
	}
	if (ps->depth == 2)
	{
		ps->in_toc = (grub_strcmp (name, "toc") == 0);
		return GRUB_ERR_NONE;
	}
	if (!ps->in_toc)
		return GRUB_ERR_NONE;

	/* <file> only nests directly inside <toc> or another <file> */
	if (grub_strcmp (name, "file") == 0
	    && ps->depth == xar_file_depth (ps) + 1)
	{
		if (!xar_new_node (ps))
			return grub_errno ? grub_errno : GRUB_ERR_BAD_FS;
		ps->cur = (int) ps->num_nodes - 1;
		return GRUB_ERR_NONE;
	}

	if (ps->cur < 0)
	{
		if (ps->depth == 3 && grub_strcmp (name, "creation-time") == 0)
			xar_collect (ps, XAR_F_CREATED);
		return GRUB_ERR_NONE;
	}

	if (ps->depth == ps->nodes[ps->cur].depth + 1)
	{
		/* <ea> carries the same children as <data>, for a fork */
		if (grub_strcmp (name, "data") == 0)
		{
			ps->data_depth = ps->depth;
			ps->nodes[ps->cur].has_data = 1;
		}
		else
			xar_collect (ps, xar_file_field (name));
	}
	else if (ps->data_depth != 0 && ps->depth == ps->data_depth + 1)
	{
		if (grub_strcmp (name, "encoding") == 0)
			ps->enc_depth = ps->depth;
		else
			xar_collect (ps, xar_data_field (name));
	}
	return GRUB_ERR_NONE;
}

static void
xar_add_text (struct xar_parser *ps, const char *text)
{
	grub_size_t len = grub_strlen (text);

	if (ps->len + len > XAR_FIELD_MAX)
	{
		ps->overflow = 1;
		return;
	}
	grub_memcpy (ps->buf + ps->len, text, len);
	ps->len += len;
}

static grub_err_t
xar_commit (struct xar_parser *ps)
{
	struct xar_node *nd;

	if (ps->overflow)
		return grub_error (GRUB_ERR_BAD_FS,
				   "xar table of contents value too long");
	ps->buf[ps->len] = '\0';

	if (ps->field == XAR_F_CREATED)
	{
		ps->created = xar_time (ps->buf);
		return GRUB_ERR_NONE;
	}

	nd = &ps->nodes[ps->cur];
	switch (ps->field)
	{
	case XAR_F_NAME:
		grub_free (nd->name);
		nd->name = grub_strdup (ps->buf);
		if (!nd->name)
			return grub_errno;
		break;

	case XAR_F_TYPE:
		nd->is_dir = (grub_strcmp (ps->buf, "directory") == 0);
		nd->is_lnk = (grub_strcmp (ps->buf, "symlink") == 0);
		break;

	case XAR_F_LINK:
		grub_free (nd->link);
		nd->link = grub_strdup (ps->buf);
		if (!nd->link)
			return grub_errno;
		break;

	case XAR_F_MTIME:
		nd->mtime = xar_time (ps->buf);
		break;

	case XAR_F_OFFSET:
		nd->off = (grub_off_t) xar_number (ps->buf);
		break;

	case XAR_F_LENGTH:
		nd->plen = (grub_off_t) xar_number (ps->buf);
		break;

	case XAR_F_SIZE:
		nd->size = (grub_off_t) xar_number (ps->buf);
		break;

	case XAR_F_ENCODING:
		nd->codec = xar_codec (ps->buf);
		break;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
xar_elem_end (struct xar_parser *ps)
{
	grub_err_t err = GRUB_ERR_NONE;

	if (ps->field != XAR_F_NONE && ps->depth == ps->field_depth)
	{
		err = xar_commit (ps);
		ps->field = XAR_F_NONE;
	}
	if (ps->enc_depth == ps->depth)
		ps->enc_depth = 0;
	if (ps->data_depth == ps->depth)
		ps->data_depth = 0;
	if (ps->cur >= 0 && ps->nodes[ps->cur].depth == ps->depth)
		ps->cur = ps->nodes[ps->cur].parent;
	if (ps->depth == 2)
		ps->in_toc = 0;
	ps->depth--;
	return err;
}

static void
xar_attr_start (struct xar_parser *ps, const char *name)
{
	if (ps->enc_depth == ps->depth && grub_strcmp (name, "style") == 0)
		xar_collect (ps, XAR_F_ENCODING);
	else if (ps->field == XAR_F_ENCODING)
		ps->field = XAR_F_NONE;
}

static grub_err_t
xar_attr_end (struct xar_parser *ps)
{
	grub_err_t err = GRUB_ERR_NONE;

	if (ps->field == XAR_F_ENCODING)
	{
		err = xar_commit (ps);
		ps->field = XAR_F_NONE;
	}
	return err;
}

static grub_err_t
xar_parse_toc (struct xar_parser *ps, const char *toc, grub_size_t len)
{
	yxml_t *x;
	void *stack;
	grub_size_t i;
	grub_err_t err = GRUB_ERR_NONE;

	x = grub_malloc (sizeof (*x));
	stack = grub_malloc (XAR_STACK_SIZE);
	if (!x || !stack)
	{
		err = grub_errno;
		goto out;
	}
	yxml_init (x, stack, XAR_STACK_SIZE);

	ps->cur = -1;
	for (i = 0; i < len && !err; i++)
	{
		switch (yxml_parse (x, toc[i]))
		{
		case YXML_ELEMSTART:
			err = xar_elem_start (ps, x->elem);
			break;

		case YXML_ELEMEND:
			err = xar_elem_end (ps);
			break;

		case YXML_ATTRSTART:
			xar_attr_start (ps, x->attr);
			break;

		case YXML_ATTREND:
			err = xar_attr_end (ps);
			break;

		case YXML_CONTENT:
			if (ps->field != XAR_F_NONE
			    && ps->field != XAR_F_ENCODING)
				xar_add_text (ps, x->data);
			break;

		case YXML_ATTRVAL:
			if (ps->field == XAR_F_ENCODING)
				xar_add_text (ps, x->data);
			break;

		case YXML_OK:
		case YXML_PISTART:
		case YXML_PICONTENT:
		case YXML_PIEND:
			break;

		default:
			err = grub_error (GRUB_ERR_BAD_FS,
					  "broken xar table of contents");
			break;
		}
	}
	if (!err && yxml_eof (x) != YXML_OK)
		err = grub_error (GRUB_ERR_BAD_FS,
				  "truncated xar table of contents");

out:
	grub_free (stack);
	grub_free (x);
	return err;
}

/* Entry list */

/* whether NAME can be used as a path component as it stands */
static int
xar_name_ok (const char *name)
{
	return name && name[0] != '\0' && grub_strcmp (name, ".") != 0
	       && grub_strcmp (name, "..") != 0;
}

/*
 * Gives every node a usable path component: a name that would change the
 * shape of the tree is replaced by the "[index]" 7-Zip shows, and the
 * separator is taken out of the rest.  Nothing else is rewritten -- these
 * names are handed to the caller as the archive spelled them.
 */
static grub_err_t
xar_fix_names (struct xar_parser *ps)
{
	unsigned i;

	for (i = 0; i < ps->num_nodes; i++)
	{
		struct xar_node *nd = &ps->nodes[i];
		char *p;

		if (!xar_name_ok (nd->name))
		{
			grub_free (nd->name);
			nd->name = grub_xasprintf ("[%u]", i);
			if (!nd->name)
				return grub_errno;
			continue;
		}
		for (p = nd->name; *p; p++)
			if (*p == '/')
				*p = '_';
	}
	return GRUB_ERR_NONE;
}

/* joins the names from the root down to INDEX */
static grub_err_t
xar_node_path (struct xar_parser *ps, unsigned index, char **out)
{
	unsigned chain[XAR_MAX_DEPTH];
	unsigned num = 0;
	grub_size_t len = 1;
	char *buf, *dst;
	int i;

	for (i = (int) index; i >= 0; i = ps->nodes[i].parent)
	{
		if (num == XAR_MAX_DEPTH)
			return grub_error (GRUB_ERR_BAD_FS, "xar tree too deep");
		chain[num++] = (unsigned) i;
		len += grub_strlen (ps->nodes[i].name) + 1;
	}

	buf = grub_malloc (len);
	if (!buf)
		return grub_errno;

	dst = buf;
	while (num--)
	{
		const char *name = ps->nodes[chain[num]].name;
		grub_size_t nlen = grub_strlen (name);

		if (dst != buf)
			*dst++ = '/';
		grub_memcpy (dst, name, nlen);
		dst += nlen;
	}
	*dst = '\0';

	*out = buf;
	return GRUB_ERR_NONE;
}

static grub_err_t
xar_add_entries (struct grub_pkg_data *data, struct xar_parser *ps,
		 grub_off_t heap)
{
	unsigned i;

	for (i = 0; i < ps->num_nodes; i++)
	{
		struct xar_node *nd = &ps->nodes[i];
		struct grub_pkg_entry *ent;
		char *name;
		grub_err_t err;

		if (nd->size > GRUB_PKG_MAX_SIZE || nd->plen > GRUB_PKG_MAX_SIZE
		    || nd->off > GRUB_PKG_MAX_SIZE)
			return grub_error (GRUB_ERR_BAD_FS,
					   "xar data range out of range");

		err = xar_node_path (ps, i, &name);
		if (err)
			return err;
		ent = grub_pkg_new_entry (data, name);
		if (!ent)
			return grub_errno;
		ent->mtime = nd->mtime;

		if (nd->is_dir)
		{
			ent->is_dir = 1;
			ent->stream = GRUB_PKG_STREAM_MEM;
			continue;
		}
		if (nd->is_lnk)
		{
			ent->target = grub_strdup (nd->link ? nd->link : "");
			if (!ent->target)
				return grub_errno;
			ent->is_lnk = 1;
			ent->stream = GRUB_PKG_STREAM_MEM;
			ent->size = grub_strlen (ent->target);
			continue;
		}
		if (!nd->has_data)
		{
			/* an empty file, or one whose data is a hard link */
			ent->stream = GRUB_PKG_STREAM_MEM;
			continue;
		}
		if (nd->codec == GRUB_PKG_CODEC_NONE)
		{
			/* stored: read it straight off the disk */
			ent->stream = GRUB_PKG_STREAM_RAW;
			ent->off = heap + nd->off;
			ent->size = (nd->size < nd->plen) ? nd->size : nd->plen;
			continue;
		}
		ent->stream = GRUB_PKG_STREAM_SUB;
		ent->codec = nd->codec;
		ent->off = heap + nd->off;
		ent->plen = nd->plen;
		ent->size = nd->size;
	}
	return GRUB_ERR_NONE;
}

/* the table of contents, browsable as the file 7-Zip calls it */
static grub_err_t
xar_add_toc_entry (struct grub_pkg_data *data, const struct xar_header *hd)
{
	struct grub_pkg_entry *ent;
	char *name;

	name = grub_strdup (XAR_TOC_NAME);
	if (!name)
		return grub_errno;
	ent = grub_pkg_new_entry (data, name);
	if (!ent)
		return grub_errno;

	ent->stream = GRUB_PKG_STREAM_SUB;
	ent->codec = GRUB_PKG_CODEC_ZLIB;
	ent->off = hd->size;
	ent->plen = hd->toc_packed;
	ent->size = hd->toc_unpacked;
	ent->mtime = data->mtime;
	return GRUB_ERR_NONE;
}

/* Mounting */

static void
xar_free_parser (struct xar_parser *ps)
{
	unsigned i;

	for (i = 0; i < ps->num_nodes; i++)
	{
		grub_free (ps->nodes[i].name);
		grub_free (ps->nodes[i].link);
	}
	grub_free (ps->nodes);
	grub_free (ps);
}

static grub_err_t
xar_read_header (struct grub_pkg_data *data, struct xar_header *hd)
{
	struct xar_header raw;

	if (data->disk_size < XAR_HEAD_MIN
	    || grub_disk_read (data->disk, 0, 0, sizeof (raw), &raw))
	{
		grub_errno = GRUB_ERR_NONE;
		return grub_error (GRUB_ERR_BAD_FS, "not a xar archive");
	}

	hd->magic = grub_be_to_cpu32 (raw.magic);
	hd->size = grub_be_to_cpu16 (raw.size);
	hd->version = grub_be_to_cpu16 (raw.version);
	hd->toc_packed = grub_be_to_cpu64 (raw.toc_packed);
	hd->toc_unpacked = grub_be_to_cpu64 (raw.toc_unpacked);
	hd->cksum_alg = grub_be_to_cpu32 (raw.cksum_alg);

	if (hd->magic != XAR_MAGIC || hd->version > 1
	    || hd->size < XAR_HEAD_MIN || hd->size > XAR_HEAD_MAX)
		return grub_error (GRUB_ERR_BAD_FS, "not a xar archive");
	if (hd->toc_packed == 0 || hd->toc_packed > XAR_TOC_PACK_MAX
	    || hd->toc_unpacked == 0 || hd->toc_unpacked > XAR_TOC_MAX)
		return grub_error (GRUB_ERR_BAD_FS,
				   "xar table of contents out of range");
	return GRUB_ERR_NONE;
}

/* reads and inflates the table of contents; *OUT is NUL terminated */
static grub_err_t
xar_read_toc (struct grub_pkg_data *data, const struct xar_header *hd,
	      char **out)
{
	char *packed = NULL, *toc = NULL;
	grub_size_t plen = (grub_size_t) hd->toc_packed;
	grub_size_t len = (grub_size_t) hd->toc_unpacked;
	grub_err_t err = GRUB_ERR_NONE;

	packed = grub_malloc (plen);
	toc = grub_malloc (len + 1);
	if (!packed || !toc)
	{
		err = grub_errno;
		goto out;
	}

	if (grub_disk_read (data->disk, 0, hd->size, plen, packed))
	{
		err = grub_error (GRUB_ERR_BAD_FS,
				  "truncated xar table of contents");
		goto out;
	}
	if (grub_zlib_decompress (packed, plen, 0, toc, len)
	    != (grub_ssize_t) len)
	{
		err = grub_error (GRUB_ERR_BAD_FS,
				  "cannot decompress the xar table of contents");
		goto out;
	}
	toc[len] = '\0';

	*out = toc;
	toc = NULL;

out:
	grub_free (toc);
	grub_free (packed);
	grub_errno = err;
	return err;
}

static grub_err_t
xar_parse (struct grub_pkg_data *data)
{
	struct xar_header hd;
	struct xar_parser *ps = NULL;
	char *toc = NULL;
	grub_err_t err;

	err = xar_read_header (data, &hd);
	if (err)
		goto out;
	err = xar_read_toc (data, &hd, &toc);
	if (err)
		goto out;

	ps = grub_zalloc (sizeof (*ps));
	if (!ps)
	{
		err = grub_errno;
		goto out;
	}

	err = xar_parse_toc (ps, toc, (grub_size_t) hd.toc_unpacked);
	if (err)
		goto out;
	err = xar_fix_names (ps);
	if (err)
		goto out;

	data->mtime = ps->created;
	err = xar_add_toc_entry (data, &hd);
	if (err)
		goto out;
	err = xar_add_entries (data, ps, (grub_off_t) hd.size + hd.toc_packed);

out:
	if (ps)
		xar_free_parser (ps);
	grub_free (toc);
	grub_errno = err;
	return err;
}

static struct grub_pkg_ops xar_ops =
{
	.name = "xar",
	.parse = xar_parse
};

static grub_err_t
grub_xar_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	return grub_pkg_dir (device, &xar_ops, path, hook, hook_data);
}

static grub_err_t
grub_xar_open (grub_file_t file, const char *name)
{
	return grub_pkg_open (file, &xar_ops, name);
}

static grub_err_t
grub_xar_mtime (grub_device_t device, grub_int64_t *tm)
{
	return grub_pkg_mtime (device, &xar_ops, tm);
}

static struct grub_fs grub_xar_fs =
{
	.name = "xar",
	.fs_dir = grub_xar_dir,
	.fs_open = grub_xar_open,
	.fs_read = grub_pkg_read,
	.fs_close = grub_pkg_close,
	.fs_label = 0,
	.fs_mtime = grub_xar_mtime,
	.fs_uuid = 0,
	.next = 0
};

GRUB_MOD_INIT (xar)
{
	grub_xar_fs.mod = mod;
	grub_fs_register (&grub_xar_fs);
}

GRUB_MOD_FINI (xar)
{
	grub_fs_unregister (&grub_xar_fs);
	grub_pkg_cache_release (&xar_ops);
}
