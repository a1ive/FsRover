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
 * JFFS2 (journalling flash filesystem v2) read-only driver.
 *
 * Modeled after u-boot\fs\jffs2\jffs2_1pass.c: the whole image is
 * scanned once per mount for valid inode-data and directory-entry
 * nodes (there is no superblock or index on flash).  Directory
 * entries are sorted so that the highest version of a name wins and
 * deletion entries (ino 0) hide it; file contents are rebuilt by
 * replaying data nodes in version order into a fragment map, honouring
 * truncations.  Both little- and big-endian images are accepted.
 * Compression: none/zero/rtime/zlib/lzo (rubin variants rejected).
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>
#include <grub/deflate.h>
#include <grub/safemath.h>
#include <minilzo.h>

GRUB_MOD_LICENSE("GPLv2+");

#define JFFS2_MAGIC		0x1985

/* node types (JFFS2_FEATURE_* | JFFS2_NODE_ACCURATE | n) */
#define JFFS2_NODETYPE_DIRENT	0xe001
#define JFFS2_NODETYPE_INODE	0xe002

/* compression types */
#define JFFS2_COMPR_NONE	0x00
#define JFFS2_COMPR_ZERO	0x01
#define JFFS2_COMPR_RTIME	0x02
#define JFFS2_COMPR_RUBINMIPS	0x03
#define JFFS2_COMPR_COPY	0x04
#define JFFS2_COMPR_DYNRUBIN	0x05
#define JFFS2_COMPR_ZLIB	0x06
#define JFFS2_COMPR_LZO		0x07

/* dirent type field (Linux DT_*) */
#define JFFS2_DT_DIR		4
#define JFFS2_DT_REG		8
#define JFFS2_DT_LNK		10

/* common node header: magic @0, nodetype @2, totlen @4, hdr_crc @8 */
#define JFFS2_HDR_LEN		12
/* raw inode: ino @12, version @16, mode @20, uid @24, gid @26,
   isize @28, atime @32, mtime @36, ctime @40, offset @44, csize @48,
   dsize @52, compr @56, usercompr @57, flags @58, data_crc @60,
   node_crc @64, data @68; node_crc covers the first 60 bytes */
#define JFFS2_INODE_LEN		68
/* raw dirent: pino @12, version @16, ino @20, mctime @24, nsize @28,
   type @29, node_crc @32, name_crc @36, name @40; node_crc covers
   the first 32 bytes */
#define JFFS2_DIRENT_LEN	40

#define JFFS2_MAX_NAME_LEN	254
#define JFFS2_ROOT_INO		1

/* keep probing/scanning sane */
#define JFFS2_PROBE_LEN		0x20000	/* look for the first node here */
#define JFFS2_MAX_DSIZE		0x100000
#define JFFS2_SCAN_CHUNK	0x10000
#define JFFS2_SCAN_SLACK	512	/* max header + name we parse */

/* one accepted inode-data node (28 bytes + padding each) */
struct grub_jffs2_ref
{
	grub_uint64_t off;		/* node position on disk */
	grub_uint32_t ino;
	grub_uint32_t version;
	grub_uint32_t foffset;		/* file offset of this write */
	grub_uint32_t dsize;		/* uncompressed length */
	grub_uint32_t isize;		/* file size after this write */
};

/* one accepted directory entry node */
struct grub_jffs2_dirent
{
	grub_uint32_t pino;
	grub_uint32_t version;
	grub_uint32_t ino;		/* 0 = deletion marker */
	grub_uint32_t mctime;
	grub_uint8_t type;
	grub_uint8_t nsize;
	char name[];			/* nsize bytes + NUL */
};

struct grub_jffs2_data
{
	grub_disk_t disk;
	int swap;			/* wrong-endian image */
	grub_uint64_t size;		/* device size in bytes */
	struct grub_jffs2_ref *refs;	/* sorted by (ino, version) */
	grub_size_t nrefs;
	struct grub_jffs2_dirent **dents;	/* sorted, see dent_cmp */
	grub_size_t ndents;
	struct grub_fshelp_node *root;
};

struct grub_fshelp_node
{
	struct grub_jffs2_data *data;
	grub_uint32_t ino;
	grub_uint8_t type;		/* JFFS2_DT_* */
};

/* rebuilt extent of file contents: [start, start+len) is stored in
   the node at NODE_OFF whose write covers [node_start, ...) */
struct grub_jffs2_frag
{
	grub_uint32_t start;
	grub_uint32_t len;
	grub_uint32_t node_start;
	grub_uint64_t node_off;
};

struct grub_jffs2_file
{
	struct grub_jffs2_data *data;
	struct grub_jffs2_frag *frags;
	grub_size_t nfrags;
	grub_uint32_t isize;
	/* one-node decompression cache */
	grub_uint64_t cached_off;
	int cache_valid;
	grub_uint8_t *dbuf;
	grub_uint32_t dbuf_len;
};

/* JFFS2 CRC-32: poly 0xEDB88320, seed passed in, no bit inversion
   (u-boot's crc32_no_comp) -- not the zlib/gcry variant */
static grub_uint32_t grub_jffs2_crc_table[256];
static int grub_jffs2_crc_ready;

static grub_uint32_t
grub_jffs2_crc(grub_uint32_t crc, const grub_uint8_t *buf, grub_size_t len)
{
	if (!grub_jffs2_crc_ready)
	{
		grub_uint32_t i, j, c;

		for (i = 0; i < 256; i++)
		{
			c = i;
			for (j = 0; j < 8; j++)
				c = (c >> 1) ^ ((c & 1) ? 0xedb88320 : 0);
			grub_jffs2_crc_table[i] = c;
		}
		grub_jffs2_crc_ready = 1;
	}
	while (len--)
		crc = grub_jffs2_crc_table[(crc ^ *buf++) & 0xff]
			^ (crc >> 8);
	return crc;
}

static grub_uint16_t
grub_jffs2_get16(const struct grub_jffs2_data *data, const grub_uint8_t *p)
{
	grub_uint16_t v = grub_get_unaligned16(p);

	return data->swap ? grub_swap_bytes16(v) : grub_le_to_cpu16(v);
}

static grub_uint32_t
grub_jffs2_get32(const struct grub_jffs2_data *data, const grub_uint8_t *p)
{
	grub_uint32_t v = grub_get_unaligned32(p);

	return data->swap ? grub_swap_bytes32(v) : grub_le_to_cpu32(v);
}

/*
 * Node scan.  Every 4-byte aligned position is a candidate; a node is
 * accepted when its 12-byte header checksums and its type-specific CRCs
 * hold.  The header CRC makes totlen trustworthy for skipping.
 */

struct grub_jffs2_scan
{
	grub_uint8_t *buf;
	grub_uint64_t base;
	grub_size_t len;
};

static const grub_uint8_t *
grub_jffs2_scan_get(struct grub_jffs2_data *data,
	struct grub_jffs2_scan *scan, grub_uint64_t pos, grub_size_t need)
{
	if (pos < scan->base || pos + need > scan->base + scan->len)
	{
		grub_size_t want = JFFS2_SCAN_CHUNK + JFFS2_SCAN_SLACK;

		if (want > data->size - pos)
			want = (grub_size_t) (data->size - pos);
		if (want < need)
			return NULL;
		if (grub_disk_read(data->disk, 0, pos, want, scan->buf))
			return NULL;
		scan->base = pos;
		scan->len = want;
	}
	return scan->buf + (pos - scan->base);
}

static grub_err_t
grub_jffs2_append_ref(struct grub_jffs2_data *data, grub_size_t *cap,
	const struct grub_jffs2_ref *ref)
{
	if (data->nrefs == *cap)
	{
		struct grub_jffs2_ref *n;
		grub_size_t ncap = *cap ? *cap * 2 : 64;

		n = grub_realloc(data->refs, ncap * sizeof(*n));
		if (!n)
			return grub_errno;
		data->refs = n;
		*cap = ncap;
	}
	data->refs[data->nrefs++] = *ref;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_jffs2_append_dent(struct grub_jffs2_data *data, grub_size_t *cap,
	struct grub_jffs2_dirent *dent)
{
	if (data->ndents == *cap)
	{
		struct grub_jffs2_dirent **n;
		grub_size_t ncap = *cap ? *cap * 2 : 64;

		n = grub_realloc(data->dents, ncap * sizeof(*n));
		if (!n)
			return grub_errno;
		data->dents = n;
		*cap = ncap;
	}
	data->dents[data->ndents++] = dent;
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_jffs2_scan_media(struct grub_jffs2_data *data)
{
	struct grub_jffs2_scan scan = { NULL, 0, 0 };
	grub_size_t ref_cap = 0, dent_cap = 0;
	grub_uint64_t pos;

	scan.buf = grub_malloc(JFFS2_SCAN_CHUNK + JFFS2_SCAN_SLACK);
	if (!scan.buf)
		return grub_errno;

	for (pos = 0; pos + JFFS2_HDR_LEN <= data->size;)
	{
		const grub_uint8_t *p;
		grub_uint32_t totlen;
		grub_uint16_t nodetype;

		p = grub_jffs2_scan_get(data, &scan, pos, JFFS2_HDR_LEN);
		if (!p)
			goto fail;
		if (grub_jffs2_get16(data, p) != JFFS2_MAGIC
			|| grub_jffs2_get32(data, p + 8)
				!= grub_jffs2_crc(0, p, 8))
		{
			pos += 4;
			continue;
		}
		totlen = grub_jffs2_get32(data, p + 4);
		if (totlen < JFFS2_HDR_LEN || totlen > data->size - pos)
		{
			pos += 4;
			continue;
		}
		nodetype = grub_jffs2_get16(data, p + 2);

		if (nodetype == JFFS2_NODETYPE_INODE
			&& totlen >= JFFS2_INODE_LEN)
		{
			struct grub_jffs2_ref ref;
			grub_uint32_t csize, dsize;
			grub_uint8_t compr;

			p = grub_jffs2_scan_get(data, &scan, pos,
				JFFS2_INODE_LEN);
			if (!p)
				goto fail;
			if (grub_jffs2_get32(data, p + 64)
				!= grub_jffs2_crc(0, p, 60))
				goto next;
			csize = grub_jffs2_get32(data, p + 48);
			dsize = grub_jffs2_get32(data, p + 52);
			compr = p[56];
			if (csize > totlen - JFFS2_INODE_LEN
				|| dsize > JFFS2_MAX_DSIZE
				|| (compr == JFFS2_COMPR_NONE
					&& csize != dsize))
				goto next;
			ref.off = pos;
			ref.ino = grub_jffs2_get32(data, p + 12);
			ref.version = grub_jffs2_get32(data, p + 16);
			ref.foffset = grub_jffs2_get32(data, p + 44);
			ref.dsize = dsize;
			ref.isize = grub_jffs2_get32(data, p + 28);
			if (ref.ino != 0
				&& grub_jffs2_append_ref(data, &ref_cap,
					&ref))
				goto fail;
		}
		else if (nodetype == JFFS2_NODETYPE_DIRENT
			&& totlen >= JFFS2_DIRENT_LEN + 1)
		{
			struct grub_jffs2_dirent *dent;
			grub_uint8_t nsize;

			p = grub_jffs2_scan_get(data, &scan, pos,
				JFFS2_DIRENT_LEN);
			if (!p)
				goto fail;
			nsize = p[28];
			if (nsize == 0
				|| (grub_uint32_t) JFFS2_DIRENT_LEN + nsize
					> totlen)
				goto next;
			p = grub_jffs2_scan_get(data, &scan, pos,
				(grub_size_t) JFFS2_DIRENT_LEN + nsize);
			if (!p)
				goto fail;
			if (grub_jffs2_get32(data, p + 32)
				!= grub_jffs2_crc(0, p, 32)
				|| grub_jffs2_get32(data, p + 36)
					!= grub_jffs2_crc(0, p + 40, nsize))
				goto next;
			dent = grub_malloc(sizeof(*dent) + nsize + 1);
			if (!dent)
				goto fail;
			dent->pino = grub_jffs2_get32(data, p + 12);
			dent->version = grub_jffs2_get32(data, p + 16);
			dent->ino = grub_jffs2_get32(data, p + 20);
			dent->mctime = grub_jffs2_get32(data, p + 24);
			dent->type = p[29];
			dent->nsize = nsize;
			grub_memcpy(dent->name, p + 40, nsize);
			dent->name[nsize] = '\0';
			if (grub_jffs2_append_dent(data, &dent_cap, dent))
			{
				grub_free(dent);
				goto fail;
			}
		}

next:
		pos += (totlen + 3) & ~(grub_uint32_t) 3;
	}

	grub_free(scan.buf);
	return GRUB_ERR_NONE;

fail:
	grub_free(scan.buf);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "jffs2: scan failed");
	return grub_errno;
}

/* ascending (ino, version) */
static int
grub_jffs2_ref_cmp(const struct grub_jffs2_ref *a,
	const struct grub_jffs2_ref *b)
{
	if (a->ino != b->ino)
		return a->ino < b->ino ? -1 : 1;
	if (a->version != b->version)
		return a->version < b->version ? -1 : 1;
	return 0;
}

/* ascending (pino, nsize, name, version) -- same directory entries for
   one name become one run whose last element has the highest version */
static int
grub_jffs2_dent_cmp(const struct grub_jffs2_dirent *a,
	const struct grub_jffs2_dirent *b)
{
	int r;

	if (a->pino != b->pino)
		return a->pino < b->pino ? -1 : 1;
	if (a->nsize != b->nsize)
		return a->nsize < b->nsize ? -1 : 1;
	r = grub_memcmp(a->name, b->name, a->nsize);
	if (r != 0)
		return r;
	if (a->version != b->version)
		return a->version < b->version ? -1 : 1;
	return 0;
}

static grub_err_t
grub_jffs2_sort_refs(struct grub_jffs2_data *data)
{
	struct grub_jffs2_ref *a = data->refs, *b, *tmp;
	grub_size_t n = data->nrefs, width;

	if (n < 2)
		return GRUB_ERR_NONE;
	b = grub_malloc(n * sizeof(*b));
	if (!b)
		return grub_errno;

	/* bottom-up stable merge sort, ping-ponging between a and b */
	for (width = 1; width < n; width *= 2)
	{
		grub_size_t i;

		for (i = 0; i < n; i += 2 * width)
		{
			grub_size_t l = i, m = i + width, r = i + 2 * width;
			grub_size_t li, ri, o;

			if (m > n)
				m = n;
			if (r > n)
				r = n;
			for (li = l, ri = m, o = l; o < r; o++)
			{
				if (ri >= r || (li < m
					&& grub_jffs2_ref_cmp(&a[li],
						&a[ri]) <= 0))
					b[o] = a[li++];
				else
					b[o] = a[ri++];
			}
		}
		tmp = a;
		a = b;
		b = tmp;
	}

	if (a != data->refs)
	{
		grub_memcpy(data->refs, a, n * sizeof(*a));
		b = a;
	}
	grub_free(b);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_jffs2_sort_dents(struct grub_jffs2_data *data)
{
	struct grub_jffs2_dirent **a = data->dents, **b, **tmp;
	grub_size_t n = data->ndents, width;

	if (n < 2)
		return GRUB_ERR_NONE;
	b = grub_malloc(n * sizeof(*b));
	if (!b)
		return grub_errno;

	for (width = 1; width < n; width *= 2)
	{
		grub_size_t i;

		for (i = 0; i < n; i += 2 * width)
		{
			grub_size_t l = i, m = i + width, r = i + 2 * width;
			grub_size_t li, ri, o;

			if (m > n)
				m = n;
			if (r > n)
				r = n;
			for (li = l, ri = m, o = l; o < r; o++)
			{
				if (ri >= r || (li < m
					&& grub_jffs2_dent_cmp(a[li],
						a[ri]) <= 0))
					b[o] = a[li++];
				else
					b[o] = a[ri++];
			}
		}
		tmp = a;
		a = b;
		b = tmp;
	}

	if (a != data->dents)
	{
		grub_memcpy(data->dents, a, n * sizeof(*a));
		b = a;
	}
	grub_free(b);
	return GRUB_ERR_NONE;
}

static void
grub_jffs2_unmount(struct grub_jffs2_data *data)
{
	grub_size_t i;

	if (!data)
		return;
	for (i = 0; i < data->ndents; i++)
		grub_free(data->dents[i]);
	grub_free(data->dents);
	grub_free(data->refs);
	grub_free(data);
}

static struct grub_jffs2_data *
grub_jffs2_mount(grub_disk_t disk)
{
	struct grub_jffs2_data *data = NULL;
	grub_uint8_t *probe = NULL;
	grub_uint64_t size;
	grub_size_t probe_len, i;
	int found = 0;

	if (disk->total_sectors == GRUB_DISK_SIZE_UNKNOWN)
		goto fail;
	size = disk->total_sectors << GRUB_DISK_SECTOR_BITS;
	if (size < JFFS2_HDR_LEN)
		goto fail;

	data = grub_zalloc(sizeof(*data) + sizeof(*data->root));
	if (!data)
		return NULL;
	data->disk = disk;
	data->size = size;
	data->root = (struct grub_fshelp_node *) (data + 1);
	data->root->data = data;
	data->root->ino = JFFS2_ROOT_INO;
	data->root->type = JFFS2_DT_DIR;

	/* cheap probe: a checksummed node header near the start decides
	   both acceptance and byte order (no superblock exists) */
	probe_len = JFFS2_PROBE_LEN;
	if (probe_len > size)
		probe_len = (grub_size_t) size;
	probe = grub_malloc(probe_len);
	if (!probe)
		goto fail;
	if (grub_disk_read(disk, 0, 0, probe_len, probe))
		goto fail;
	for (i = 0; i + JFFS2_HDR_LEN <= probe_len && !found; i += 4)
	{
		grub_uint16_t magic = grub_get_unaligned16(probe + i);

		if (magic != grub_cpu_to_le16_compile_time(JFFS2_MAGIC)
			&& magic
				!= grub_cpu_to_be16_compile_time(JFFS2_MAGIC))
			continue;
		data->swap =
			(magic == grub_cpu_to_be16_compile_time(JFFS2_MAGIC));
		if (grub_jffs2_get32(data, probe + i + 8)
			== grub_jffs2_crc(0, probe + i, 8))
			found = 1;
	}
	grub_free(probe);
	probe = NULL;
	if (!found)
		goto fail;

	if (grub_jffs2_scan_media(data)
		|| grub_jffs2_sort_refs(data)
		|| grub_jffs2_sort_dents(data))
	{
		grub_jffs2_unmount(data);
		return NULL;
	}
	return data;

fail:
	grub_free(probe);
	grub_free(data);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "not a jffs2 filesystem");
	return NULL;
}

/* first index whose ref is >= (ino, version) */
static grub_size_t
grub_jffs2_ref_lower(struct grub_jffs2_data *data, grub_uint32_t ino,
	grub_uint32_t version)
{
	grub_size_t lo = 0, hi = data->nrefs;

	while (lo < hi)
	{
		grub_size_t mid = lo + (hi - lo) / 2;
		const struct grub_jffs2_ref *r = &data->refs[mid];

		if (r->ino < ino
			|| (r->ino == ino && r->version < version))
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

/* first index whose dent is >= the given key (version 0) */
static grub_size_t
grub_jffs2_dent_lower(struct grub_jffs2_data *data, grub_uint32_t pino,
	grub_uint8_t nsize, const char *name)
{
	grub_size_t lo = 0, hi = data->ndents;

	while (lo < hi)
	{
		grub_size_t mid = lo + (hi - lo) / 2;
		const struct grub_jffs2_dirent *d = data->dents[mid];
		int less;

		if (d->pino != pino)
			less = d->pino < pino;
		else if (!name)
			less = 0;
		else if (d->nsize != nsize)
			less = d->nsize < nsize;
		else
			less = grub_memcmp(d->name, name, nsize) < 0;
		if (less)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

/*
 * Fragment map: replay data nodes in version order.  Later writes
 * override earlier ones; a shrinking isize prunes everything past it
 * (truncation), matching the kernel's fragtree semantics.
 */

static grub_err_t
grub_jffs2_frag_insert(struct grub_jffs2_file *fp, grub_size_t *cap,
	const struct grub_jffs2_ref *ref)
{
	struct grub_jffs2_frag *f = fp->frags;
	grub_uint32_t start = ref->foffset;
	grub_uint32_t end = ref->foffset + ref->dsize;
	grub_size_t i, j, lo, hi;

	if (fp->nfrags + 2 > *cap)
	{
		grub_size_t ncap = *cap ? *cap * 2 : 16;

		f = grub_realloc(fp->frags, ncap * sizeof(*f));
		if (!f)
			return grub_errno;
		fp->frags = f;
		*cap = ncap;
	}

	/* i = first fragment ending after start (they are sorted and
	   disjoint, so end offsets are monotonic too) */
	for (lo = 0, hi = fp->nfrags; lo < hi;)
	{
		grub_size_t mid = lo + (hi - lo) / 2;

		if (f[mid].start + f[mid].len <= start)
			lo = mid + 1;
		else
			hi = mid;
	}
	i = lo;
	/* split a fragment that sticks out on the left */
	if (i < fp->nfrags && f[i].start < start)
	{
		grub_uint32_t tail = f[i].start + f[i].len;

		f[i].len = start - f[i].start;
		if (tail > end)
		{
			/* the old fragment also sticks out on the right */
			grub_memmove(f + i + 2, f + i + 1,
				(fp->nfrags - i - 1) * sizeof(*f));
			f[i + 1].start = end;
			f[i + 1].len = tail - end;
			f[i + 1].node_start = f[i].node_start;
			f[i + 1].node_off = f[i].node_off;
			fp->nfrags++;
		}
		i++;
	}
	/* drop fragments fully covered, trim one crossing the end */
	for (j = i; j < fp->nfrags && f[j].start < end; j++)
	{
		grub_uint32_t tail = f[j].start + f[j].len;

		if (tail > end)
		{
			f[j].len = tail - end;
			f[j].start = end;
			break;
		}
	}
	if (j > i)
		grub_memmove(f + i, f + j, (fp->nfrags - j) * sizeof(*f));
	fp->nfrags -= j - i;

	grub_memmove(f + i + 1, f + i, (fp->nfrags - i) * sizeof(*f));
	f[i].start = start;
	f[i].len = ref->dsize;
	f[i].node_start = ref->foffset;
	f[i].node_off = ref->off;
	fp->nfrags++;
	return GRUB_ERR_NONE;
}

static void
grub_jffs2_frag_truncate(struct grub_jffs2_file *fp, grub_uint32_t isize)
{
	while (fp->nfrags > 0)
	{
		struct grub_jffs2_frag *f = &fp->frags[fp->nfrags - 1];

		if (f->start + f->len <= isize)
			break;
		if (f->start >= isize)
		{
			fp->nfrags--;
			continue;
		}
		f->len = isize - f->start;
		break;
	}
}

static struct grub_jffs2_file *
grub_jffs2_open_ino(struct grub_jffs2_data *data, grub_uint32_t ino)
{
	struct grub_jffs2_file *fp;
	grub_size_t lo, hi, i, cap = 0;

	fp = grub_zalloc(sizeof(*fp));
	if (!fp)
		return NULL;
	fp->data = data;

	lo = grub_jffs2_ref_lower(data, ino, 0);
	hi = (ino == 0xffffffff) ? data->nrefs
		: grub_jffs2_ref_lower(data, ino + 1, 0);
	for (i = lo; i < hi; i++)
	{
		const struct grub_jffs2_ref *ref = &data->refs[i];

		if (ref->isize < fp->isize)
			grub_jffs2_frag_truncate(fp, ref->isize);
		fp->isize = ref->isize;
		if (ref->dsize != 0
			&& grub_jffs2_frag_insert(fp, &cap, ref))
		{
			grub_free(fp->frags);
			grub_free(fp);
			return NULL;
		}
	}
	grub_jffs2_frag_truncate(fp, fp->isize);
	return fp;
}

static void
grub_jffs2_file_free(struct grub_jffs2_file *fp)
{
	if (!fp)
		return;
	grub_free(fp->frags);
	grub_free(fp->dbuf);
	grub_free(fp);
}

/* decompress the whole data node at OFF into fp->dbuf */
static grub_err_t
grub_jffs2_load_node(struct grub_jffs2_file *fp, grub_uint64_t off)
{
	struct grub_jffs2_data *data = fp->data;
	grub_uint8_t hdr[JFFS2_INODE_LEN];
	grub_uint8_t *cbuf = NULL;
	grub_uint32_t csize, dsize;
	grub_uint8_t compr;

	if (fp->cache_valid && fp->cached_off == off)
		return GRUB_ERR_NONE;
	fp->cache_valid = 0;

	if (grub_disk_read(data->disk, 0, off, sizeof(hdr), hdr))
		return grub_errno;
	csize = grub_jffs2_get32(data, hdr + 48);
	dsize = grub_jffs2_get32(data, hdr + 52);
	compr = hdr[56];

	if (dsize > fp->dbuf_len)
	{
		grub_uint8_t *n = grub_realloc(fp->dbuf, dsize);

		if (!n)
			return grub_errno;
		fp->dbuf = n;
		fp->dbuf_len = dsize;
	}

	if (compr == JFFS2_COMPR_ZERO)
	{
		grub_memset(fp->dbuf, 0, dsize);
		goto done;
	}

	cbuf = grub_malloc(csize ? csize : 1);
	if (!cbuf)
		return grub_errno;
	if (grub_disk_read(data->disk, 0, off + JFFS2_INODE_LEN, csize,
		cbuf))
		goto fail;
	if (grub_jffs2_get32(data, hdr + 60)
		!= grub_jffs2_crc(0, cbuf, csize))
	{
		grub_error(GRUB_ERR_BAD_FS, "jffs2: bad data CRC");
		goto fail;
	}

	switch (compr)
	{
	case JFFS2_COMPR_NONE:
	case JFFS2_COMPR_COPY:
		if (csize < dsize)
			goto corrupt;
		grub_memcpy(fp->dbuf, cbuf, dsize);
		break;
	case JFFS2_COMPR_RTIME:
	{
		/* u-boot compr_rtime.c: LZ77-ish backreference scheme
		   keyed by last occurrence of each byte value */
		grub_uint32_t positions[256];
		grub_uint32_t outpos = 0, pos = 0;

		grub_memset(positions, 0, sizeof(positions));
		while (outpos < dsize)
		{
			grub_uint8_t value;
			grub_uint32_t backoffs, repeat;

			if (pos + 2 > csize)
				goto corrupt;
			value = cbuf[pos++];
			fp->dbuf[outpos++] = value;
			repeat = cbuf[pos++];
			backoffs = positions[value];
			positions[value] = outpos;
			if (repeat > dsize - outpos
				|| (repeat && backoffs >= outpos))
				goto corrupt;
			while (repeat--)
				fp->dbuf[outpos++] = fp->dbuf[backoffs++];
		}
		break;
	}
	case JFFS2_COMPR_ZLIB:
	{
		grub_ssize_t n = grub_zlib_decompress((char *) cbuf, csize,
			0, (char *) fp->dbuf, dsize);

		if (n < 0)
			goto fail;
		if ((grub_uint32_t) n < dsize)
			goto corrupt;
		break;
	}
	case JFFS2_COMPR_LZO:
	{
		lzo_uint dst_len = dsize;

		if (lzo1x_decompress_safe(cbuf, csize, fp->dbuf, &dst_len,
			NULL) != LZO_E_OK || dst_len != dsize)
			goto corrupt;
		break;
	}
	default:
		grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
			"jffs2: compression type %d not supported", compr);
		goto fail;
	}

	grub_free(cbuf);
	cbuf = NULL;
done:
	fp->cached_off = off;
	fp->cache_valid = 1;
	return GRUB_ERR_NONE;

corrupt:
	grub_error(GRUB_ERR_BAD_FS, "jffs2: corrupt data node");
fail:
	grub_free(cbuf);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "jffs2: read error");
	return grub_errno;
}

static grub_err_t
grub_jffs2_read_file(struct grub_jffs2_file *fp, grub_off_t pos,
	grub_size_t len, char *buf)
{
	grub_size_t i;
	grub_uint32_t start, end;

	if (pos >= fp->isize || len > fp->isize - pos)
		return grub_error(GRUB_ERR_OUT_OF_RANGE,
			"read past end of file");
	if (len == 0)
		return GRUB_ERR_NONE;
	start = (grub_uint32_t) pos;
	end = start + (grub_uint32_t) len;

	/* holes read as zeros */
	grub_memset(buf, 0, len);

	for (i = 0; i < fp->nfrags; i++)
	{
		const struct grub_jffs2_frag *f = &fp->frags[i];
		grub_uint32_t fs = f->start, fe = f->start + f->len;
		grub_uint32_t cs, ce;

		if (fe <= start)
			continue;
		if (fs >= end)
			break;
		cs = fs > start ? fs : start;
		ce = fe < end ? fe : end;
		if (grub_jffs2_load_node(fp, f->node_off))
			return grub_errno;
		grub_memcpy(buf + (cs - start),
			fp->dbuf + (cs - f->node_start), ce - cs);
	}
	return GRUB_ERR_NONE;
}

/* fetch size/mtime from the newest inode node of INO */
static void
grub_jffs2_stat_ino(struct grub_jffs2_data *data, grub_uint32_t ino,
	grub_uint32_t *isize, grub_uint32_t *mtime)
{
	grub_size_t hi;
	grub_uint8_t hdr[JFFS2_INODE_LEN];

	*isize = 0;
	*mtime = 0;
	hi = (ino == 0xffffffff) ? data->nrefs
		: grub_jffs2_ref_lower(data, ino + 1, 0);
	if (hi == 0 || data->refs[hi - 1].ino != ino)
		return;
	*isize = data->refs[hi - 1].isize;
	if (grub_disk_read(data->disk, 0, data->refs[hi - 1].off,
		sizeof(hdr), hdr) == GRUB_ERR_NONE)
		*mtime = grub_jffs2_get32(data, hdr + 36);
	else
		grub_errno = GRUB_ERR_NONE;
}

/* iterate winning directory entries of DIR; HOOK receives a malloc'ed
   node (also used as fshelp iterate_dir) */
struct grub_jffs2_iter_ctx
{
	int (*hook) (const char *filename, grub_uint8_t type,
		grub_uint32_t ino, grub_uint32_t mctime, void *hook_data);
	void *hook_data;
};

static int
grub_jffs2_iterate_entries(struct grub_jffs2_data *data, grub_uint32_t pino,
	struct grub_jffs2_iter_ctx *ctx)
{
	grub_size_t i;

	i = grub_jffs2_dent_lower(data, pino, 0, NULL);
	while (i < data->ndents && data->dents[i]->pino == pino)
	{
		const struct grub_jffs2_dirent *win = data->dents[i];

		/* advance over the whole run of this name; the last
		   entry carries the highest version and wins */
		while (i + 1 < data->ndents
			&& data->dents[i + 1]->pino == pino
			&& data->dents[i + 1]->nsize == win->nsize
			&& grub_memcmp(data->dents[i + 1]->name, win->name,
				win->nsize) == 0)
			win = data->dents[++i];
		i++;
		if (win->ino == 0)
			continue;	/* deleted */
		if (ctx->hook(win->name, win->type, win->ino, win->mctime,
			ctx->hook_data))
			return 1;
	}
	return 0;
}

struct grub_jffs2_fshelp_ctx
{
	struct grub_jffs2_data *data;
	grub_fshelp_iterate_dir_hook_t hook;
	void *hook_data;
};

static int
grub_jffs2_fshelp_iter(const char *filename, grub_uint8_t type,
	grub_uint32_t ino, grub_uint32_t mctime, void *ctx_in)
{
	struct grub_jffs2_fshelp_ctx *ctx = ctx_in;
	struct grub_fshelp_node *node;
	enum grub_fshelp_filetype ftype;

	(void) mctime;
	node = grub_malloc(sizeof(*node));
	if (!node)
		return 1;
	node->data = ctx->data;
	node->ino = ino;
	node->type = type;
	switch (type)
	{
	case JFFS2_DT_DIR:
		ftype = GRUB_FSHELP_DIR;
		break;
	case JFFS2_DT_LNK:
		ftype = GRUB_FSHELP_SYMLINK;
		break;
	case JFFS2_DT_REG:
		ftype = GRUB_FSHELP_REG;
		break;
	default:
		ftype = GRUB_FSHELP_UNKNOWN;
		break;
	}
	return ctx->hook(filename, ftype, node, ctx->hook_data);
}

static int
grub_jffs2_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_jffs2_fshelp_ctx fctx = { dir->data, hook, hook_data };
	struct grub_jffs2_iter_ctx ctx =
		{ grub_jffs2_fshelp_iter, &fctx };

	return grub_jffs2_iterate_entries(dir->data, dir->ino, &ctx);
}

static char *
grub_jffs2_read_symlink(grub_fshelp_node_t node)
{
	struct grub_jffs2_file *fp;
	char *target = NULL;

	fp = grub_jffs2_open_ino(node->data, node->ino);
	if (!fp)
		return NULL;
	target = grub_malloc((grub_size_t) fp->isize + 1);
	if (!target)
		goto fail;
	if (fp->isize != 0
		&& grub_jffs2_read_file(fp, 0, fp->isize, target))
	{
		grub_free(target);
		target = NULL;
		goto fail;
	}
	target[fp->isize] = '\0';

fail:
	grub_jffs2_file_free(fp);
	return target;
}

/* grub_fs dir: emit winning entries with mtime from the inode node */
struct grub_jffs2_dir_ctx
{
	struct grub_jffs2_data *data;
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_jffs2_dir_iter(const char *filename, grub_uint8_t type,
	grub_uint32_t ino, grub_uint32_t mctime, void *ctx_in)
{
	struct grub_jffs2_dir_ctx *ctx = ctx_in;
	struct grub_dirhook_info info;
	grub_uint32_t isize, mtime;

	grub_memset(&info, 0, sizeof(info));
	info.dir = (type == JFFS2_DT_DIR);
	info.symlink = (type == JFFS2_DT_LNK);
	info.inodeset = 1;
	info.inode = ino;
	grub_jffs2_stat_ino(ctx->data, ino, &isize, &mtime);
	info.mtimeset = 1;
	info.mtime = mtime ? mtime : mctime;
	return ctx->hook(filename, &info, ctx->hook_data);
}

static grub_err_t
grub_jffs2_dir(grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_jffs2_data *data;
	struct grub_jffs2_dir_ctx dctx;
	struct grub_jffs2_iter_ctx ctx;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_jffs2_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(path, data->root, &fdiro,
		grub_jffs2_iterate_dir, grub_jffs2_read_symlink,
		GRUB_FSHELP_DIR);
	if (grub_errno)
		goto fail;

	dctx.data = data;
	dctx.hook = hook;
	dctx.hook_data = hook_data;
	ctx.hook = grub_jffs2_dir_iter;
	ctx.hook_data = &dctx;
	grub_jffs2_iterate_entries(data, fdiro->ino, &ctx);

fail:
	if (fdiro != data->root)
		grub_free(fdiro);
	grub_jffs2_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_jffs2_open(struct grub_file *file, const char *name)
{
	struct grub_jffs2_data *data;
	struct grub_fshelp_node *fdiro = NULL;
	struct grub_jffs2_file *fp = NULL;

	data = grub_jffs2_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(name, data->root, &fdiro,
		grub_jffs2_iterate_dir, grub_jffs2_read_symlink,
		GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	fp = grub_jffs2_open_ino(data, fdiro->ino);
	if (!fp)
		goto fail;

	file->size = fp->isize;
	file->data = fp;
	if (fdiro != data->root)
		grub_free(fdiro);
	return GRUB_ERR_NONE;

fail:
	if (fdiro != data->root)
		grub_free(fdiro);
	grub_jffs2_unmount(data);
	return grub_errno;
}

static grub_ssize_t
grub_jffs2_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_jffs2_file *fp = file->data;

	if (len == 0)
		return 0;
	if (grub_jffs2_read_file(fp, file->offset, len, buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_jffs2_close(grub_file_t file)
{
	struct grub_jffs2_file *fp = file->data;
	struct grub_jffs2_data *data = fp->data;

	grub_jffs2_file_free(fp);
	grub_jffs2_unmount(data);
	return GRUB_ERR_NONE;
}

static struct grub_fs grub_jffs2_fs =
{
	.name = "jffs2",
	.fs_dir = grub_jffs2_dir,
	.fs_open = grub_jffs2_open,
	.fs_read = grub_jffs2_read,
	.fs_close = grub_jffs2_close,
	.next = 0
};

GRUB_MOD_INIT(jffs2)
{
	grub_jffs2_fs.mod = mod;
	grub_fs_register(&grub_jffs2_fs);
}

GRUB_MOD_FINI(jffs2)
{
	grub_fs_unregister(&grub_jffs2_fs);
}
