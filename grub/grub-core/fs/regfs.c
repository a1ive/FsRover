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

#include <grub/types.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/fshelp.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

/* The hive bin data area follows the 4 KiB header block; every cell
   offset in a hive is relative to the start of that area.  */
#define REGFS_HBINS_BASE	0x1000

#define REGFS_SIG_REGF		0x66676572	/* "regf" */
#define REGFS_SIG_HBIN		0x6e696268	/* "hbin" */
#define REGFS_SIG_NK		0x6b6e		/* "nk" */
#define REGFS_SIG_VK		0x6b76		/* "vk" */
#define REGFS_SIG_DB		0x6264		/* "db" */
#define REGFS_SIG_LF		0x666c		/* "lf" */
#define REGFS_SIG_LH		0x686c		/* "lh" */
#define REGFS_SIG_LI		0x696c		/* "li" */
#define REGFS_SIG_RI		0x6972		/* "ri" */

/* named key flags */
#define REGFS_KEY_SYM_LINK	0x0010	/* key redirects to another key */
#define REGFS_KEY_COMP_NAME	0x0020	/* name is a byte string */
/* value key flags */
#define REGFS_VALUE_COMP_NAME	0x0001	/* name is a byte string */

/* data size flag: the data sits in the data offset field itself */
#define REGFS_VALUE_INLINE	0x80000000
/* payload one "db" segment contributes, whatever its cell says */
#define REGFS_SEGMENT_MAX	16344

/* "not present" offset */
#define REGFS_NIL		0xffffffff

/* an "ri" list may point at further lists; bound the recursion */
#define REGFS_RI_DEPTH_MAX	4
/* no real hive has a cell, or a key with a value count, this large */
#define REGFS_CELL_MAX		(16 << 20)
#define REGFS_VALUES_MAX	65536

/* name given to the unnamed value, and to a key without a name */
#define REGFS_DEFAULT_NAME	"(default)"
#define REGFS_UNNAMED_KEY	"(unnamed)"

/* seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01 */
#define REGFS_EPOCH_BIAS	11644473600ULL

PRAGMA_BEGIN_PACKED
struct grub_regfs_header
{
	grub_uint32_t signature;	/* "regf" */
	grub_uint32_t sequence1;
	grub_uint32_t sequence2;
	grub_uint64_t timestamp;
	grub_uint32_t major;
	grub_uint32_t minor;
	grub_uint32_t type;		/* 0 = hive, else transaction log */
	grub_uint32_t format;		/* 1 = direct memory load */
	grub_uint32_t root_cell;
	grub_uint32_t hbins_size;
	grub_uint32_t cluster;
	grub_uint16_t name[32];		/* tail of the hive's path, if any */
	grub_uint8_t reserved[396];
	grub_uint32_t checksum;		/* XOR-32 of the 508 bytes before */
};

struct grub_regfs_nk
{
	grub_uint16_t signature;	/* "nk" */
	grub_uint16_t flags;
	grub_uint64_t last_written;
	grub_uint32_t unknown1;
	grub_uint32_t parent;
	grub_uint32_t nsubkeys;
	grub_uint32_t nvolatile_subkeys;
	grub_uint32_t subkeys_off;
	grub_uint32_t volatile_subkeys_off;
	grub_uint32_t nvalues;
	grub_uint32_t values_off;
	grub_uint32_t security_off;
	grub_uint32_t class_off;
	grub_uint32_t largest_subkey_name;
	grub_uint32_t largest_subkey_class;
	grub_uint32_t largest_value_name;
	grub_uint32_t largest_value_data;
	grub_uint32_t unknown2;
	grub_uint16_t name_size;
	grub_uint16_t class_size;
	/* name follows */
};

struct grub_regfs_vk
{
	grub_uint16_t signature;	/* "vk" */
	grub_uint16_t name_size;
	grub_uint32_t data_size;
	grub_uint32_t data_off;
	grub_uint32_t type;
	grub_uint16_t flags;
	grub_uint16_t unknown;
	/* name follows */
};
PRAGMA_END_PACKED

struct grub_regfs_data
{
	grub_disk_t disk;
	grub_uint32_t root_cell;
	grub_uint32_t hbins_size;
	/* format 1.1 puts four unused bytes in front of every cell value */
	grub_uint32_t cell_extra;
	grub_int64_t mtime;
};

/* one run of value data on the disk */
struct grub_regfs_seg
{
	grub_uint64_t off;
	grub_uint32_t len;
};

struct grub_fshelp_node
{
	struct grub_regfs_data *data;
	grub_uint32_t cell;		/* "nk" for a key, "vk" for a value */
	grub_int64_t mtime;
	int is_value;
	int is_symlink;			/* KEY_SYM_LINK key */
	/* value data, filled in by grub_regfs_open() */
	grub_uint32_t size;
	struct grub_regfs_seg *segs;
	grub_uint32_t nsegs;
	grub_uint8_t inline_data[4];
	grub_uint32_t inline_len;
};

/* one value of the key being listed */
struct grub_regfs_value
{
	char *name;
	grub_uint32_t cell;
	int collides;	/* a sub key of this key goes by the same name */
	int recheck;	/* the name may clash with another value's name */
};

struct grub_regfs_iter_ctx
{
	struct grub_regfs_data *data;
	grub_fshelp_iterate_dir_hook_t hook;
	void *hook_data;
	grub_int64_t mtime;		/* of the key being listed */
	struct grub_regfs_value *values;
	grub_uint32_t nvalues;
};

static grub_int64_t
grub_regfs_filetime_to_unix (grub_uint64_t ft)
{
	return (grub_int64_t) grub_divmod64 (ft, 10000000, 0) - (grub_int64_t) REGFS_EPOCH_BIAS;
}

/* A damaged record must not abort the whole listing: swallow the
   structural errors and let the I/O and allocation ones through.
   Returns 1 when the caller may carry on.  */
static int
grub_regfs_skip_bad (void)
{
	if (grub_errno != GRUB_ERR_BAD_FS)
		return 0;
	grub_errno = GRUB_ERR_NONE;
	return 1;
}

/* Locate the cell at hive bin relative OFFSET.  *DISK_OFF gets the byte
   offset of its value on the disk and *LEN the value's length, both
   with the format 1.1 prefix already accounted for.  */
static int
grub_regfs_cell_at (struct grub_regfs_data *data, grub_uint32_t offset,
	grub_uint64_t *disk_off, grub_uint32_t *len)
{
	grub_uint32_t head = 4 + data->cell_extra;
	grub_uint32_t raw;
	grub_uint32_t size;

	if (offset >= data->hbins_size || data->hbins_size - offset < head)
		goto bad;
	if (grub_disk_read (data->disk, 0, REGFS_HBINS_BASE + offset,
		sizeof (raw), &raw))
		return -1;

	/* an allocated cell carries its size negated */
	raw = grub_le_to_cpu32 (raw);
	if (!(raw & 0x80000000))
		goto bad;
	size = 0 - raw;
	if (size < head || size > REGFS_CELL_MAX
		|| size > data->hbins_size - offset)
		goto bad;

	*disk_off = (grub_uint64_t) REGFS_HBINS_BASE + offset + head;
	*len = size - head;
	return 0;

bad:
	grub_error (GRUB_ERR_BAD_FS, "invalid registry cell at 0x%x", offset);
	return -1;
}

/* Read the value of the cell at hive bin relative OFFSET into a fresh
   buffer, its length in *LEN.  */
static void *
grub_regfs_read_cell (struct grub_regfs_data *data, grub_uint32_t offset,
	grub_uint32_t *len)
{
	grub_uint64_t disk_off;
	grub_uint32_t size;
	void *buf;

	if (grub_regfs_cell_at (data, offset, &disk_off, &size) != 0)
		return NULL;
	buf = grub_zalloc (size ? size : 1);
	if (!buf)
		return NULL;
	if (size && grub_disk_read (data->disk, 0, disk_off, size, buf))
	{
		grub_free (buf);
		return NULL;
	}
	*len = size;
	return buf;
}

/* '/' separates path components and the rest are rejected by Windows
   when the entry is extracted; '%' introduces the escape itself.  */
static int
grub_regfs_must_escape (grub_uint8_t c)
{
	return c < 0x20 || c == 0x7f || c == '%' || c == '/' || c == '\\'
		|| c == ':' || c == '*' || c == '?' || c == '"'
		|| c == '<' || c == '>' || c == '|';
}

/* Turn a key or value name of SIZE bytes into an escaped UTF-8 string.
   COMP selects the byte string form (KEY_COMP_NAME / VALUE_COMP_NAME),
   whose high bytes are taken as latin-1; otherwise the name is
   UTF-16LE.  */
static char *
grub_regfs_name (const grub_uint8_t *raw, grub_uint32_t size, int comp)
{
	static const char hex[] = "0123456789ABCDEF";
	grub_uint8_t *utf8;
	char *out;
	grub_size_t i, n, len;
	int hide_dot;

	if (comp)
	{
		utf8 = grub_calloc (size + 1, 2);
		if (!utf8)
			return NULL;
		for (i = 0, n = 0; i < size; i++)
		{
			if (raw[i] < 0x80)
				utf8[n++] = raw[i];
			else
			{
				utf8[n++] = 0xc0 | (raw[i] >> 6);
				utf8[n++] = 0x80 | (raw[i] & 0x3f);
			}
		}
	}
	else
	{
		grub_size_t units = size / sizeof (grub_uint16_t);
		grub_uint16_t *tmp;

		utf8 = grub_calloc (units + 1, GRUB_MAX_UTF8_PER_UTF16);
		tmp = grub_calloc (units + 1, sizeof (tmp[0]));
		if (!utf8 || !tmp)
		{
			grub_free (utf8);
			grub_free (tmp);
			return NULL;
		}
		for (i = 0; i < units; i++)
			tmp[i] = grub_le_to_cpu16 (
				grub_get_unaligned16 (raw + 2 * i));
		*grub_utf16_to_utf8 (utf8, tmp, units) = '\0';
		grub_free (tmp);
	}

	len = grub_strlen ((char *) utf8);
	hide_dot = (grub_strcmp ((char *) utf8, ".") == 0
		|| grub_strcmp ((char *) utf8, "..") == 0);
	out = grub_malloc (3 * len + 1);
	if (!out)
	{
		grub_free (utf8);
		return NULL;
	}
	for (i = 0, n = 0; i < len; i++)
	{
		grub_uint8_t c = utf8[i];

		if (grub_regfs_must_escape (c) || (i == 0 && hide_dot))
		{
			out[n++] = '%';
			out[n++] = hex[c >> 4];
			out[n++] = hex[c & 0xf];
		}
		else
			out[n++] = (char) c;
	}
	out[n] = '\0';
	grub_free (utf8);
	return out;
}

/* Collect the values of the key NK; the count is returned, the array in
   *OUT.  Values whose records are damaged are left out.  */
static grub_uint32_t
grub_regfs_read_values (struct grub_regfs_data *data,
	const struct grub_regfs_nk *nk, struct grub_regfs_value **out)
{
	struct grub_regfs_value *values;
	grub_uint32_t list_off = grub_le_to_cpu32 (nk->values_off);
	grub_uint32_t count = grub_le_to_cpu32 (nk->nvalues);
	grub_uint32_t len;
	grub_uint32_t i, n;
	grub_uint8_t *list;

	*out = NULL;
	if (!count || list_off == REGFS_NIL)
		return 0;
	if (count > REGFS_VALUES_MAX)
		count = REGFS_VALUES_MAX;

	list = grub_regfs_read_cell (data, list_off, &len);
	if (!list)
	{
		grub_regfs_skip_bad ();
		return 0;
	}
	if (count > len / sizeof (grub_uint32_t))
		count = len / sizeof (grub_uint32_t);

	values = grub_calloc (count ? count : 1, sizeof (*values));
	if (!values)
	{
		grub_free (list);
		return 0;
	}

	for (i = 0, n = 0; i < count; i++)
	{
		grub_uint32_t cell = grub_le_to_cpu32 (grub_get_unaligned32 (list + i * sizeof (grub_uint32_t)));
		struct grub_regfs_vk *vk;
		grub_uint32_t vk_len;
		grub_uint32_t name_size;
		char *name;

		vk = grub_regfs_read_cell (data, cell, &vk_len);
		if (!vk)
		{
			if (grub_regfs_skip_bad ())
				continue;
			break;
		}
		if (vk_len < sizeof (*vk) || grub_le_to_cpu16 (vk->signature) != REGFS_SIG_VK)
		{
			grub_free (vk);
			continue;
		}

		name_size = grub_le_to_cpu16 (vk->name_size);
		if (name_size > vk_len - sizeof (*vk))
			name_size = vk_len - sizeof (*vk);
		name = grub_regfs_name ((const grub_uint8_t *) (vk + 1),
			name_size,
			grub_le_to_cpu16 (vk->flags) & REGFS_VALUE_COMP_NAME);
		grub_free (vk);
		if (!name)
			break;

		if (!*name)
		{
			grub_free (name);
			name = grub_strdup (REGFS_DEFAULT_NAME);
			if (!name)
				break;
		}

		values[n].name = name;
		values[n].cell = cell;
		/* the name the unnamed value borrows may be taken already */
		values[n].recheck = (grub_strcasecmp (name, REGFS_DEFAULT_NAME) == 0);
		n++;
	}

	grub_free (list);
	*out = values;
	return n;
}

/* Hand one named key to the hook.  Returns 1 when it asked to stop.  */
static int
grub_regfs_emit_key (struct grub_regfs_iter_ctx *ctx, grub_uint32_t cell)
{
	struct grub_fshelp_node *node;
	struct grub_regfs_nk *nk;
	grub_uint32_t len;
	grub_uint32_t name_size;
	grub_uint32_t flags;
	grub_uint32_t i;
	char *name = NULL;
	int ret = 0;

	nk = grub_regfs_read_cell (ctx->data, cell, &len);
	if (!nk)
		goto out;
	if (len < sizeof (*nk) || grub_le_to_cpu16 (nk->signature) != REGFS_SIG_NK)
		goto out;

	flags = grub_le_to_cpu16 (nk->flags);
	name_size = grub_le_to_cpu16 (nk->name_size);
	if (name_size > len - sizeof (*nk))
		name_size = len - sizeof (*nk);
	name = grub_regfs_name ((const grub_uint8_t *) (nk + 1), name_size, flags & REGFS_KEY_COMP_NAME);
	if (!name)
		goto out;
	if (!*name)
	{
		grub_free (name);
		name = grub_strdup (REGFS_UNNAMED_KEY);
		if (!name)
			goto out;
	}

	/* a value of the same name has to move out of the way */
	for (i = 0; i < ctx->nvalues; i++)
		if (grub_strcasecmp (ctx->values[i].name, name) == 0)
			ctx->values[i].collides = 1;

	node = grub_zalloc (sizeof (*node));
	if (!node)
		goto out;
	node->data = ctx->data;
	node->cell = cell;
	node->mtime = grub_regfs_filetime_to_unix (grub_le_to_cpu64 (nk->last_written));
	node->is_symlink = ((flags & REGFS_KEY_SYM_LINK) != 0);
	/* A link key stays a directory: it really holds the
	   SymbolicLinkValue naming its target, and nothing here resolves
	   that target.  The flag only marks it in the listing.  */
	ret = ctx->hook (name, GRUB_FSHELP_DIR | GRUB_FSHELP_CASE_INSENSITIVE, node, ctx->hook_data);

out:
	grub_regfs_skip_bad ();
	grub_free (name);
	grub_free (nk);
	return ret;
}

/* Walk a sub keys list, handing every named key below it to the hook.
   Returns 1 when the hook asked to stop.  */
static int
grub_regfs_walk_subkeys (struct grub_regfs_iter_ctx *ctx, grub_uint32_t off, int depth)
{
	grub_uint8_t *list;
	grub_uint32_t len;
	grub_uint32_t count, i, stride;
	grub_uint16_t sig;
	int ret = 0;

	if (off == REGFS_NIL || depth > REGFS_RI_DEPTH_MAX)
		return 0;
	list = grub_regfs_read_cell (ctx->data, off, &len);
	if (!list)
	{
		grub_regfs_skip_bad ();
		return 0;
	}
	if (len < 4)
		goto out;

	sig = grub_le_to_cpu16 (grub_get_unaligned16 (list));
	count = grub_le_to_cpu16 (grub_get_unaligned16 (list + 2));
	switch (sig)
	{
	case REGFS_SIG_LF:
	case REGFS_SIG_LH:
		stride = 8;	/* cell offset + name hash */
		break;
	case REGFS_SIG_LI:
	case REGFS_SIG_RI:
		stride = 4;
		break;
	default:
		goto out;
	}
	if (count > (len - 4) / stride)
		count = (len - 4) / stride;

	for (i = 0; i < count && !ret && !grub_errno; i++)
	{
		grub_uint32_t cell = grub_le_to_cpu32 (
			grub_get_unaligned32 (list + 4 + i * stride));

		if (sig == REGFS_SIG_RI)
			ret = grub_regfs_walk_subkeys (ctx, cell, depth + 1);
		else
			ret = grub_regfs_emit_key (ctx, cell);
	}

out:
	grub_free (list);
	return ret;
}

/* Hand the collected values to the hook, renaming the ones that clash
   with a sub key or with an earlier value.  Returns 1 when the hook
   asked to stop.  */
static int
grub_regfs_emit_values (struct grub_regfs_iter_ctx *ctx)
{
	grub_uint32_t i, j;
	int ret = 0;

	for (i = 0; i < ctx->nvalues && !ret; i++)
	{
		struct grub_regfs_value *value = &ctx->values[i];
		struct grub_fshelp_node *node;
		char *name = value->name;
		unsigned suffix = value->collides ? 1 : 0;

		/* A sub key already took the name, so the value has to be
		   renamed; the renamed one then has to clear the values
		   listed before it, whose names are final by now.  */
		while (suffix || value->recheck)
		{
			if (suffix)
			{
				if (name != value->name)
					grub_free (name);
				name = grub_xasprintf ("%s~%u", value->name, suffix);
				if (!name)
					return 0;
			}
			for (j = 0; j < i; j++)
				if (grub_strcasecmp (ctx->values[j].name, name) == 0)
					break;
			if (j == i)
				break;
			suffix++;
		}
		if (name != value->name)
		{
			grub_free (value->name);
			value->name = name;
		}

		node = grub_zalloc (sizeof (*node));
		if (!node)
			return 0;
		node->data = ctx->data;
		node->cell = value->cell;
		node->mtime = ctx->mtime;
		node->is_value = 1;
		ret = ctx->hook (name, GRUB_FSHELP_REG | GRUB_FSHELP_CASE_INSENSITIVE, node, ctx->hook_data);
	}

	return ret;
}

static int
grub_regfs_iterate_dir (grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_regfs_iter_ctx ctx;
	struct grub_regfs_nk *nk;
	grub_uint32_t len;
	grub_uint32_t i;
	int ret = 0;

	nk = grub_regfs_read_cell (dir->data, dir->cell, &len);
	if (!nk)
	{
		grub_regfs_skip_bad ();
		return 0;
	}
	if (len < sizeof (*nk) || grub_le_to_cpu16 (nk->signature) != REGFS_SIG_NK)
	{
		grub_free (nk);
		return 0;
	}

	ctx.data = dir->data;
	ctx.hook = hook;
	ctx.hook_data = hook_data;
	ctx.mtime = grub_regfs_filetime_to_unix (grub_le_to_cpu64 (nk->last_written));
	ctx.nvalues = grub_regfs_read_values (dir->data, nk, &ctx.values);

	/* sub keys first: the value renaming depends on their names */
	ret = grub_regfs_walk_subkeys (&ctx,
		grub_le_to_cpu32 (nk->subkeys_off), 0);
	if (!ret && !grub_errno)
		ret = grub_regfs_emit_values (&ctx);

	for (i = 0; i < ctx.nvalues; i++)
		grub_free (ctx.values[i].name);
	grub_free (ctx.values);
	grub_free (nk);
	return ret;
}

/* Build the data segment list of the value NODE points at.  */
static int
grub_regfs_open_value (struct grub_fshelp_node *node)
{
	struct grub_regfs_data *data = node->data;
	struct grub_regfs_vk *vk;
	struct grub_regfs_seg *segs = NULL;
	grub_uint8_t *list = NULL;
	grub_uint64_t disk_off;
	grub_uint32_t vk_len, cell_len, list_len;
	grub_uint32_t size, off, total, nsegs, i;
	int ret = -1;

	vk = grub_regfs_read_cell (data, node->cell, &vk_len);
	if (!vk)
		return -1;
	if (vk_len < sizeof (*vk) || grub_le_to_cpu16 (vk->signature) != REGFS_SIG_VK)
	{
		grub_error (GRUB_ERR_BAD_FS, "invalid registry value record");
		goto out;
	}

	size = grub_le_to_cpu32 (vk->data_size);
	off = grub_le_to_cpu32 (vk->data_off);

	if (size & REGFS_VALUE_INLINE)
	{
		/* the data offset field is the data */
		size &= ~REGFS_VALUE_INLINE;
		if (size > sizeof (vk->data_off))
			size = sizeof (vk->data_off);
		grub_memcpy (node->inline_data, &vk->data_off, size);
		node->inline_len = size;
		node->size = size;
		ret = 0;
		goto out;
	}
	if (!size || off == REGFS_NIL)
	{
		ret = 0;
		goto out;
	}
	if (grub_regfs_cell_at (data, off, &disk_off, &cell_len) != 0)
		goto out;

	/* Big values live in a "db" record: a count and the offset of a
	   list of cells, each holding up to 16344 bytes.  */
	if (size > REGFS_SEGMENT_MAX && cell_len >= 8 && cell_len <= 32)
	{
		grub_uint8_t db[8];

		if (grub_disk_read (data->disk, 0, disk_off, sizeof (db), db))
			goto out;
		if (grub_le_to_cpu16 (grub_get_unaligned16 (db)) != REGFS_SIG_DB)
			goto single;

		nsegs = grub_le_to_cpu16 (grub_get_unaligned16 (db + 2));
		list = grub_regfs_read_cell (data,
			grub_le_to_cpu32 (grub_get_unaligned32 (db + 4)),
			&list_len);
		if (!list)
			goto out;
		if (nsegs > list_len / sizeof (grub_uint32_t))
			nsegs = list_len / sizeof (grub_uint32_t);

		segs = grub_calloc (nsegs ? nsegs : 1, sizeof (*segs));
		if (!segs)
			goto out;

		total = 0;
		for (i = 0; i < nsegs && total < size; i++)
		{
			grub_uint32_t seg_len;

			if (grub_regfs_cell_at (data,
				grub_le_to_cpu32 (grub_get_unaligned32 (list + i * sizeof (grub_uint32_t))),
				&disk_off, &seg_len) != 0)
				goto out;
			if (seg_len > REGFS_SEGMENT_MAX)
				seg_len = REGFS_SEGMENT_MAX;
			if (seg_len > size - total)
				seg_len = size - total;
			segs[i].off = disk_off;
			segs[i].len = seg_len;
			total += seg_len;
		}

		node->segs = segs;
		node->nsegs = i;
		node->size = total;
		segs = NULL;
		ret = 0;
		goto out;
	}

single:
	/* the data size may overstate what its cell can hold */
	if (size > cell_len)
		size = cell_len;
	segs = grub_calloc (1, sizeof (*segs));
	if (!segs)
		goto out;
	segs[0].off = disk_off;
	segs[0].len = size;
	node->segs = segs;
	node->nsegs = 1;
	node->size = size;
	segs = NULL;
	ret = 0;

out:
	grub_free (segs);
	grub_free (list);
	grub_free (vk);
	return ret;
}

/* Read the 4 KiB header block and check it describes a hive we can walk.  */
static struct grub_regfs_data *
grub_regfs_mount (grub_disk_t disk)
{
	union
	{
		struct grub_regfs_header hdr;
		grub_uint32_t dw[128];
	} h;
	struct grub_regfs_data *data;
	struct grub_regfs_nk *root;
	grub_uint32_t magic, csum, len, minor;
	grub_uint32_t i;

	if (grub_disk_read (disk, 0, 0, sizeof (h), &h))
		return NULL;
	if (grub_le_to_cpu32 (h.hdr.signature) != REGFS_SIG_REGF
		|| grub_le_to_cpu32 (h.hdr.major) != 1
		|| grub_le_to_cpu32 (h.hdr.format) != 1)
		goto bad;
	/* a non-zero type is a transaction log, which has no hive bins */
	if (grub_le_to_cpu32 (h.hdr.type) != 0)
		goto bad;
	minor = grub_le_to_cpu32 (h.hdr.minor);
	if (minor < 1 || minor > 6)
		goto bad;
	if (grub_disk_read (disk, 0, REGFS_HBINS_BASE, sizeof (magic), &magic))
		return NULL;
	if (grub_le_to_cpu32 (magic) != REGFS_SIG_HBIN)
		goto bad;

	for (i = 0, csum = 0; i < 127; i++)
		csum ^= grub_le_to_cpu32 (h.dw[i]);
	if (csum != grub_le_to_cpu32 (h.hdr.checksum)
		|| h.hdr.sequence1 != h.hdr.sequence2)
		grub_dprintf ("regfs", "hive is dirty, logs are not replayed\n");

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return NULL;
	data->disk = disk;
	data->root_cell = grub_le_to_cpu32 (h.hdr.root_cell);
	data->hbins_size = grub_le_to_cpu32 (h.hdr.hbins_size);
	/* format 1.1 pads every cell value with four leading bytes */
	data->cell_extra = (minor <= 1) ? 4 : 0;
	data->mtime = grub_regfs_filetime_to_unix (grub_le_to_cpu64 (h.hdr.timestamp));

	/* the header may promise more hive bins than the image holds */
	if (disk->total_sectors != GRUB_DISK_SIZE_UNKNOWN)
	{
		grub_uint64_t avail = disk->total_sectors << disk->log_sector_size;

		avail = (avail > REGFS_HBINS_BASE) ? avail - REGFS_HBINS_BASE : 0;
		if (data->hbins_size > avail)
			data->hbins_size = (grub_uint32_t) avail;
	}

	root = grub_regfs_read_cell (data, data->root_cell, &len);
	if (!root)
	{
		grub_free (data);
		if (grub_errno != GRUB_ERR_BAD_FS)
			return NULL;
		goto bad;
	}
	if (len < sizeof (*root) || grub_le_to_cpu16 (root->signature) != REGFS_SIG_NK)
	{
		grub_free (root);
		grub_free (data);
		goto bad;
	}
	grub_free (root);
	return data;

bad:
	grub_errno = GRUB_ERR_NONE;
	grub_error (GRUB_ERR_BAD_FS, "not a registry hive");
	return NULL;
}

static void
grub_regfs_root_node (struct grub_fshelp_node *node,
	struct grub_regfs_data *data)
{
	grub_memset (node, 0, sizeof (*node));
	node->data = data;
	node->cell = data->root_cell;
	node->mtime = data->mtime;
}

struct grub_regfs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_regfs_dir_iter (const char *filename,
	enum grub_fshelp_filetype filetype, grub_fshelp_node_t node,
	void *data)
{
	struct grub_regfs_dir_ctx *ctx = data;
	struct grub_dirhook_info info;

	grub_memset (&info, 0, sizeof (info));
	info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink = node->is_symlink;
	info.case_insensitive = 1;
	info.mtimeset = 1;
	info.mtime = node->mtime;
	grub_free (node);
	return ctx->hook (filename, &info, ctx->hook_data);
}

static grub_err_t
grub_regfs_dir (grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_regfs_dir_ctx ctx = { hook, hook_data };
	struct grub_regfs_data *data;
	struct grub_fshelp_node root;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_regfs_mount (device->disk);
	if (!data)
		return grub_errno;

	grub_regfs_root_node (&root, data);
	grub_fshelp_find_file (path, &root, &fdiro, grub_regfs_iterate_dir, NULL, GRUB_FSHELP_DIR);
	if (grub_errno)
		goto done;

	grub_regfs_iterate_dir (fdiro, grub_regfs_dir_iter, &ctx);

done:
	if (fdiro != &root)
		grub_free (fdiro);
	grub_free (data);
	return grub_errno;
}

static grub_err_t
grub_regfs_open (struct grub_file *file, const char *name)
{
	struct grub_regfs_data *data;
	struct grub_fshelp_node root;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_regfs_mount (file->device->disk);
	if (!data)
		return grub_errno;

	grub_regfs_root_node (&root, data);
	grub_fshelp_find_file (name, &root, &fdiro, grub_regfs_iterate_dir, NULL, GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	if (grub_regfs_open_value (fdiro) != 0)
		goto fail;

	file->size = fdiro->size;
	file->data = fdiro;
	return GRUB_ERR_NONE;

fail:
	if (fdiro != &root)
	{
		if (fdiro)
			grub_free (fdiro->segs);
		grub_free (fdiro);
	}
	grub_free (data);
	return grub_errno;
}

static grub_ssize_t
grub_regfs_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fshelp_node *node = file->data;
	grub_uint64_t pos = file->offset;
	grub_size_t done = 0;
	grub_uint32_t i;

	if (pos >= node->size)
		return 0;
	if (len > node->size - pos)
		len = (grub_size_t) (node->size - pos);

	if (node->inline_len)
	{
		grub_memcpy (buf, node->inline_data + pos, len);
		return len;
	}

	for (i = 0; i < node->nsegs && done < len; i++)
	{
		grub_uint32_t seg_len = node->segs[i].len;
		grub_size_t n;

		if (pos >= seg_len)
		{
			pos -= seg_len;
			continue;
		}
		n = seg_len - (grub_uint32_t) pos;
		if (n > len - done)
			n = len - done;
		if (grub_disk_read (node->data->disk, 0, node->segs[i].off + pos, n, buf + done))
			return -1;
		done += n;
		pos = 0;
	}

	return done;
}

static grub_err_t
grub_regfs_close (grub_file_t file)
{
	struct grub_fshelp_node *node = file->data;

	grub_free (node->segs);
	grub_free (node->data);
	grub_free (node);
	return GRUB_ERR_NONE;
}

/* The header keeps the tail of the hive's path ("...\config\SOFTWARE");
   its last component makes a better label than the root key's name,
   which is usually an internal one like "CMI-CreateHive{...}".  */
static char *
grub_regfs_header_label (const struct grub_regfs_header *hdr)
{
	grub_uint16_t name[ARRAY_SIZE (hdr->name)];
	grub_uint8_t *utf8;
	grub_size_t units;
	char *sep;

	for (units = 0; units < ARRAY_SIZE (name); units++)
	{
		name[units] = grub_le_to_cpu16 (hdr->name[units]);
		if (!name[units])
			break;
		/* remnant data rather than a path */
		if (name[units] < 0x20)
			return NULL;
	}
	if (!units)
		return NULL;

	utf8 = grub_calloc (units + 1, GRUB_MAX_UTF8_PER_UTF16);
	if (!utf8)
		return NULL;
	*grub_utf16_to_utf8 (utf8, name, units) = '\0';

	sep = grub_strrchr ((char *) utf8, '\\');
	if (sep && sep[1])
	{
		char *label = grub_strdup (sep + 1);

		grub_free (utf8);
		return label;
	}
	return (char *) utf8;
}

static grub_err_t
grub_regfs_label (grub_device_t device, char **label)
{
	struct grub_regfs_header hdr;
	struct grub_regfs_data *data;
	struct grub_regfs_nk *root;
	grub_uint32_t len;
	grub_uint32_t name_size;

	*label = NULL;
	data = grub_regfs_mount (device->disk);
	if (!data)
		return grub_errno;

	if (grub_disk_read (device->disk, 0, 0, sizeof (hdr), &hdr))
		goto out;
	*label = grub_regfs_header_label (&hdr);
	if (*label)
		goto out;

	/* fall back to the name of the root key */
	root = grub_regfs_read_cell (data, data->root_cell, &len);
	if (!root)
	{
		grub_regfs_skip_bad ();
		goto out;
	}
	if (len < sizeof (*root))
	{
		grub_free (root);
		goto out;
	}
	name_size = grub_le_to_cpu16 (root->name_size);
	if (name_size > len - sizeof (*root))
		name_size = len - sizeof (*root);
	*label = grub_regfs_name ((const grub_uint8_t *) (root + 1), name_size,
		grub_le_to_cpu16 (root->flags) & REGFS_KEY_COMP_NAME);
	grub_free (root);

out:
	grub_free (data);
	return grub_errno;
}

static grub_err_t
grub_regfs_mtime (grub_device_t device, grub_int64_t *timebuf)
{
	struct grub_regfs_data *data;

	*timebuf = 0;
	data = grub_regfs_mount (device->disk);
	if (!data)
		return grub_errno;
	*timebuf = data->mtime;
	grub_free (data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_regfs_fs =
{
	.name = "regfs",
	.fs_dir = grub_regfs_dir,
	.fs_open = grub_regfs_open,
	.fs_read = grub_regfs_read,
	.fs_close = grub_regfs_close,
	.fs_label = grub_regfs_label,
	.fs_mtime = grub_regfs_mtime,
	.next = 0
};

GRUB_MOD_INIT(regfs)
{
	grub_regfs_fs.mod = mod;
	grub_fs_register (&grub_regfs_fs);
}

GRUB_MOD_FINI(regfs)
{
	grub_fs_unregister (&grub_regfs_fs);
}
