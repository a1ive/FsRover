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
 * HPFS (OS/2 High Performance File System) read-only driver.
 *
 * The on-disk layout follows Linux fs/hpfs (fs/hpfs/hpfs.h).  Sectors are
 * always 512 bytes: sector 16 carries the superblock (which points at the
 * root fnode), sector 17 the spare block (which points at the bad sector
 * hotfix map).  Every file and directory owns a 512-byte fnode.  A
 * directory fnode points at the root of a B-tree of 2 KiB dnodes holding
 * the directory entries in upcased name order; a file fnode carries the
 * root of a B+ tree of (file sector, length, disk sector) extents whose
 * inner nodes live in 512-byte anodes.  Symbolic links are the "SYMLINK"
 * extended attribute written by the Linux driver.  ACLs, HPFS386 extended
 * permissions and the code page tables (which only matter for upcasing
 * names beyond ASCII) are ignored.
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>

GRUB_MOD_LICENSE("GPLv3+");

#define HPFS_SECTOR_SIZE	512U
#define HPFS_SECTOR_BITS	9
#define HPFS_SECTOR_MASK	(HPFS_SECTOR_SIZE - 1)
#define HPFS_DNODE_SIZE		2048U

#define HPFS_SUPER_SECTOR	16
#define HPFS_SPARE_SECTOR	17

/* the first 0x12 sectors are reserved for boot block, super block,
   spare block and the two unused sectors behind them */
#define HPFS_FIRST_SECTOR	0x12
/* sector numbers are signed in OS/2 tools */
#define HPFS_MAX_SECTORS	0x80000000U

#define HPFS_SB_MAGIC		0xf995e849U
#define HPFS_SP_MAGIC		0xf9911849U
#define HPFS_DNODE_MAGIC	0x77e40aaeU
#define HPFS_FNODE_MAGIC	0xf7e40aaeU
#define HPFS_ANODE_MAGIC	0x37e40aaeU

/* boot block (sector 0) byte offsets */
#define HPFS_BB_VOL_SERNO	0x27
#define HPFS_BB_VOL_LABEL	0x2b
#define HPFS_BB_LABEL_LEN	11
#define HPFS_BB_SIG_HPFS	0x36

/* super block (sector 16) byte offsets */
#define HPFS_SB_ROOT		0x0c
#define HPFS_SB_N_SECTORS	0x10

/* spare block (sector 17) byte offsets */
#define HPFS_SP_HOTFIX_MAP	0x0c
#define HPFS_SP_N_SPARES_USED	0x10
#define HPFS_SP_N_SPARES	0x14
#define HPFS_MAX_SPARES		256

/* dnode byte offsets */
#define HPFS_DNODE_FIRST_FREE	0x04
#define HPFS_DNODE_DIRENT	0x14

/* directory entry byte offsets */
#define HPFS_DE_LENGTH		0x00
#define HPFS_DE_FLAGS		0x02
#define HPFS_DE_ATTRS		0x03
#define HPFS_DE_FNODE		0x04
#define HPFS_DE_WRITE_DATE	0x08
#define HPFS_DE_FILE_SIZE	0x0c
#define HPFS_DE_EA_SIZE		0x18
#define HPFS_DE_NAMELEN		0x1e
#define HPFS_DE_NAME		0x1f
#define HPFS_DE_MIN_LENGTH	0x20

/* directory entry flags (byte 2) */
#define HPFS_DE_FLAG_FIRST	0x01
#define HPFS_DE_FLAG_DOWN	0x04
#define HPFS_DE_FLAG_LAST	0x08

/* directory entry DOS attributes (byte 3) */
#define HPFS_DE_ATTR_DIRECTORY	0x10

/* fnode byte offsets */
#define HPFS_FNODE_ACL_SIZE_S	0x28
#define HPFS_FNODE_EA_SIZE_L	0x2c
#define HPFS_FNODE_EA_SECNO	0x30
#define HPFS_FNODE_EA_SIZE_S	0x34
#define HPFS_FNODE_FLAGS	0x36
#define HPFS_FNODE_BTREE	0x38
#define HPFS_FNODE_BTREE_END	0xa0
#define HPFS_FNODE_EA_OFFS	0xb8
/* fnode resident EAs never start before this */
#define HPFS_FNODE_EA_MIN	0xc4

/* fnode flags */
#define HPFS_FNODE_FLAG_ANODE	0x0002
#define HPFS_FNODE_FLAG_DIR	0x0100

/* anode byte offsets */
#define HPFS_ANODE_BTREE	0x0c

/* B+ tree header: flags, fill[3], n_free_nodes, n_used_nodes, first_free */
#define HPFS_BP_FLAGS		0x00
#define HPFS_BP_N_USED		0x05
#define HPFS_BP_NODES		0x08
#define HPFS_BP_INTERNAL	0x80
#define HPFS_BP_INT_SIZE	8
#define HPFS_BP_EXT_SIZE	12

/* extended attribute byte offsets */
#define HPFS_EA_FLAGS		0x00
#define HPFS_EA_NAMELEN		0x01
#define HPFS_EA_VALUELEN_LO	0x02
#define HPFS_EA_VALUELEN_HI	0x03
#define HPFS_EA_NAME		0x04
#define HPFS_EA_HDR_LEN		0x05

/* extended attribute flags */
#define HPFS_EA_FLAG_INDIRECT	0x01
#define HPFS_EA_FLAG_ANODE	0x02

/* EA lists and values we are willing to walk */
#define HPFS_MAX_EA_SIZE	0x10000U

/* corrupted images must not send us into an endless descent */
#define HPFS_MAX_BTREE_DEPTH	16
#define HPFS_MAX_DNODE_DEPTH	32

struct grub_hpfs_data;

struct grub_fshelp_node
{
	struct grub_hpfs_data *data;
	grub_uint32_t fnode;		/* fnode sector */
	grub_uint32_t dno;		/* root dnode (directories), 0 = unknown */
	grub_uint32_t size;		/* file length in bytes */
	grub_uint32_t mtime;
	/* last extent returned by the allocation tree, see hpfs_bmap() */
	grub_uint32_t cache_file_sec;
	grub_uint32_t cache_disk_sec;
	grub_uint32_t cache_n_secs;
};

struct grub_hpfs_data
{
	grub_disk_t disk;
	grub_uint32_t fs_size;		/* filesystem length in sectors */
	grub_uint32_t n_hotfixes;
	grub_uint32_t *hotfix_from;
	grub_uint32_t *hotfix_to;
	grub_uint32_t serial;		/* volume serial number */
	int has_boot_block;
	char label[HPFS_BB_LABEL_LEN + 1];
	struct grub_fshelp_node root;
};

/* iteration state shared by all dnodes of one directory */
struct grub_hpfs_dir_iter
{
	struct grub_fshelp_node *dir;
	grub_fshelp_iterate_dir_hook_t hook;
	void *hook_data;
	grub_uint8_t *fnode;		/* scratch buffer for EA probing */
};

/* context for grub_hpfs_dir */
struct grub_hpfs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static grub_uint16_t
hpfs_get16(const grub_uint8_t *p)
{
	return grub_le_to_cpu16(grub_get_unaligned16(p));
}

static grub_uint32_t
hpfs_get32(const grub_uint8_t *p)
{
	return grub_le_to_cpu32(grub_get_unaligned32(p));
}

/* Map SEC through the bad sector hotfix map.  *N is the number of
   sectors the caller wants to read from SEC on and is clipped to the
   sectors that can be read in one go.  */
static grub_uint32_t
grub_hpfs_hotfix(struct grub_hpfs_data *data, grub_uint32_t sec,
	grub_uint32_t *n)
{
	grub_uint32_t i, run = *n, mapped = sec;

	for (i = 0; i < data->n_hotfixes; i++)
	{
		if (data->hotfix_from[i] == sec)
			mapped = data->hotfix_to[i];
		else if (data->hotfix_from[i] > sec
			&& data->hotfix_from[i] - sec < run)
			run = data->hotfix_from[i] - sec;
	}
	if (mapped != sec)
		run = 1;
	*n = run;
	return mapped;
}

/* Read LEN bytes starting OFF bytes into sector SEC.  */
static grub_err_t
grub_hpfs_read_bytes(struct grub_hpfs_data *data, grub_uint32_t sec,
	grub_uint32_t off, grub_size_t len, void *buf)
{
	grub_uint8_t *p = buf;

	sec += off >> HPFS_SECTOR_BITS;
	off &= HPFS_SECTOR_MASK;

	while (len)
	{
		grub_uint32_t nsec, phys;
		grub_size_t chunk;

		nsec = (grub_uint32_t) ((off + len + HPFS_SECTOR_MASK)
			>> HPFS_SECTOR_BITS);
		if (sec < HPFS_FIRST_SECTOR || sec >= data->fs_size
			|| nsec > data->fs_size - sec)
			return grub_error(GRUB_ERR_BAD_FS,
				"hpfs: read outside of the filesystem at 0x%x",
				(unsigned) sec);

		phys = grub_hpfs_hotfix(data, sec, &nsec);
		chunk = (grub_size_t) nsec * HPFS_SECTOR_SIZE - off;
		if (chunk > len)
			chunk = len;
		if (grub_disk_read(data->disk, phys, off, chunk, p))
			return grub_errno;

		p += chunk;
		len -= chunk;
		off += (grub_uint32_t) chunk;
		sec += off >> HPFS_SECTOR_BITS;
		off &= HPFS_SECTOR_MASK;
	}
	return GRUB_ERR_NONE;
}

/* Load a one sector long fnode or anode and check its magic.  */
static grub_err_t
grub_hpfs_read_node(struct grub_hpfs_data *data, grub_uint32_t sec,
	grub_uint32_t magic, grub_uint8_t *buf)
{
	if (grub_hpfs_read_bytes(data, sec, 0, HPFS_SECTOR_SIZE, buf))
		return grub_errno;
	if (hpfs_get32(buf) != magic)
		return grub_error(GRUB_ERR_BAD_FS,
			"hpfs: bad magic on sector 0x%x", (unsigned) sec);
	return GRUB_ERR_NONE;
}

/* Load a four sector long dnode and check its magic.  */
static grub_err_t
grub_hpfs_read_dnode(struct grub_hpfs_data *data, grub_uint32_t sec,
	grub_uint8_t *buf)
{
	if (sec & 3)
		return grub_error(GRUB_ERR_BAD_FS,
			"hpfs: dnode 0x%x is not aligned", (unsigned) sec);
	if (grub_hpfs_read_bytes(data, sec, 0, HPFS_DNODE_SIZE, buf))
		return grub_errno;
	if (hpfs_get32(buf) != HPFS_DNODE_MAGIC)
		return grub_error(GRUB_ERR_BAD_FS,
			"hpfs: bad magic on dnode 0x%x", (unsigned) sec);
	return GRUB_ERR_NONE;
}

/* Walk the allocation B+ tree whose header sits at HDR_OFF in the node
   image NODE (the entry array must end before LIMIT) and translate the
   file relative sector SEC.  The number of contiguous sectors following
   it is returned in N_SECS.  */
static grub_err_t
grub_hpfs_btree_lookup(struct grub_hpfs_data *data, const grub_uint8_t *node,
	grub_uint32_t hdr_off, grub_uint32_t limit, grub_uint32_t sec,
	grub_uint32_t *disk_sec, grub_uint32_t *n_secs)
{
	grub_uint8_t *anode = NULL;
	int depth;

	for (depth = 0; depth <= HPFS_MAX_BTREE_DEPTH; depth++)
	{
		const grub_uint8_t *e;
		grub_uint32_t nodes_off = hdr_off + HPFS_BP_NODES;
		grub_uint32_t n_used = node[hdr_off + HPFS_BP_N_USED];
		grub_uint32_t i, esize, down = 0;
		int internal = (node[hdr_off + HPFS_BP_FLAGS]
			& HPFS_BP_INTERNAL) != 0;

		esize = internal ? HPFS_BP_INT_SIZE : HPFS_BP_EXT_SIZE;
		if (nodes_off + n_used * esize > limit)
			goto bad;

		for (i = 0; i < n_used; i++)
		{
			grub_uint32_t first, len;

			e = node + nodes_off + i * esize;
			first = hpfs_get32(e);
			if (internal)
			{
				if (first > sec)
				{
					down = hpfs_get32(e + 4);
					break;
				}
				continue;
			}
			len = hpfs_get32(e + 4);
			if (first > sec || len <= sec - first)
				continue;
			*disk_sec = hpfs_get32(e + 8) + (sec - first);
			*n_secs = len - (sec - first);
			if (*disk_sec < HPFS_FIRST_SECTOR
				|| *n_secs > data->fs_size
				|| *disk_sec > data->fs_size - *n_secs)
				goto bad;
			grub_free(anode);
			return GRUB_ERR_NONE;
		}
		if (!internal || i == n_used)
			goto bad;

		if (!anode)
		{
			anode = grub_malloc(HPFS_SECTOR_SIZE);
			if (!anode)
				return grub_errno;
		}
		if (grub_hpfs_read_node(data, down, HPFS_ANODE_MAGIC, anode))
		{
			grub_free(anode);
			return grub_errno;
		}
		node = anode;
		hdr_off = HPFS_ANODE_BTREE;
		limit = HPFS_SECTOR_SIZE;
	}

bad:
	grub_free(anode);
	return grub_error(GRUB_ERR_BAD_FS,
		"hpfs: sector 0x%x not found in the allocation tree",
		(unsigned) sec);
}

/* Read LEN bytes at byte offset POS of an extended attribute run: either
   the plain sector run starting at A or, if ANO is set, the file mapped
   by the anode tree rooted at A.  */
static grub_err_t
grub_hpfs_ea_read(struct grub_hpfs_data *data, grub_uint32_t a, int ano,
	grub_uint32_t pos, grub_uint32_t len, void *buf)
{
	grub_uint8_t *anode = NULL;
	grub_uint8_t *p = buf;
	grub_err_t err = GRUB_ERR_NONE;

	if (ano)
	{
		anode = grub_malloc(HPFS_SECTOR_SIZE);
		if (!anode)
			return grub_errno;
		err = grub_hpfs_read_node(data, a, HPFS_ANODE_MAGIC, anode);
		if (err)
			goto out;
	}

	while (len)
	{
		grub_uint32_t sec, off, n_secs, l;

		off = pos & HPFS_SECTOR_MASK;
		if (ano)
		{
			err = grub_hpfs_btree_lookup(data, anode,
				HPFS_ANODE_BTREE, HPFS_SECTOR_SIZE,
				pos >> HPFS_SECTOR_BITS, &sec, &n_secs);
			if (err)
				goto out;
		}
		else
			sec = a + (pos >> HPFS_SECTOR_BITS);

		l = HPFS_SECTOR_SIZE - off;
		if (l > len)
			l = len;
		err = grub_hpfs_read_bytes(data, sec, off, l, p);
		if (err)
			goto out;
		p += l;
		pos += l;
		len -= l;
	}

out:
	grub_free(anode);
	return err;
}

/* Copy out the value of one extended attribute; VALUE points at the
   value field, which for indirect attributes holds the real length and
   the first sector of the run instead.  */
static char *
grub_hpfs_ea_value(struct grub_hpfs_data *data, grub_uint32_t flags,
	const grub_uint8_t *value, grub_uint32_t vlen, grub_uint32_t *size)
{
	char *ret;

	if (flags & HPFS_EA_FLAG_INDIRECT)
	{
		grub_uint32_t len, sec;

		if (vlen < 8)
		{
			grub_error(GRUB_ERR_BAD_FS, "hpfs: bad indirect EA");
			return NULL;
		}
		len = hpfs_get32(value);
		sec = hpfs_get32(value + 4);
		if (len > HPFS_MAX_EA_SIZE)
		{
			grub_error(GRUB_ERR_BAD_FS, "hpfs: EA value too big");
			return NULL;
		}
		ret = grub_malloc(len + 1);
		if (!ret)
			return NULL;
		if (grub_hpfs_ea_read(data, sec,
			flags & HPFS_EA_FLAG_ANODE, 0, len, ret))
		{
			grub_free(ret);
			return NULL;
		}
		ret[len] = '\0';
		*size = len;
		return ret;
	}

	ret = grub_malloc(vlen + 1);
	if (!ret)
		return NULL;
	grub_memcpy(ret, value, vlen);
	ret[vlen] = '\0';
	*size = vlen;
	return ret;
}

/* Look up the extended attribute KEY of the file whose fnode image is
   FNODE.  Attributes live either inside the fnode or in a run of their
   own.  Returns a NUL terminated copy of the value or NULL if there is
   no such attribute.  */
static char *
grub_hpfs_get_ea(struct grub_hpfs_data *data, const grub_uint8_t *fnode,
	const char *key, grub_uint32_t *size)
{
	grub_uint32_t keylen = (grub_uint32_t) grub_strlen(key);
	grub_uint32_t start, end, pos, len, sec;
	int ano;

	/* fnode resident list */
	start = hpfs_get16(fnode + HPFS_FNODE_EA_OFFS)
		+ hpfs_get16(fnode + HPFS_FNODE_ACL_SIZE_S);
	end = start + hpfs_get16(fnode + HPFS_FNODE_EA_SIZE_S);
	if (start >= HPFS_FNODE_EA_MIN && end <= HPFS_SECTOR_SIZE)
		for (pos = start; pos + HPFS_EA_HDR_LEN <= end; )
		{
			const grub_uint8_t *ea = fnode + pos;
			grub_uint32_t namelen = ea[HPFS_EA_NAMELEN];
			grub_uint32_t vlen = ea[HPFS_EA_VALUELEN_LO]
				+ 256 * ea[HPFS_EA_VALUELEN_HI];

			if (pos + HPFS_EA_HDR_LEN + namelen + vlen > end)
				break;
			if (namelen == keylen
				&& grub_memcmp(ea + HPFS_EA_NAME, key, keylen) == 0)
				return grub_hpfs_ea_value(data, ea[HPFS_EA_FLAGS],
					ea + HPFS_EA_HDR_LEN + namelen, vlen, size);
			pos += HPFS_EA_HDR_LEN + namelen + vlen;
		}

	/* list stored outside of the fnode */
	sec = hpfs_get32(fnode + HPFS_FNODE_EA_SECNO);
	len = hpfs_get32(fnode + HPFS_FNODE_EA_SIZE_L);
	ano = (hpfs_get16(fnode + HPFS_FNODE_FLAGS)
		& HPFS_FNODE_FLAG_ANODE) != 0;
	if (len > HPFS_MAX_EA_SIZE)
	{
		grub_error(GRUB_ERR_BAD_FS, "hpfs: EA list too big");
		return NULL;
	}
	for (pos = 0; pos + HPFS_EA_HDR_LEN <= len; )
	{
		grub_uint8_t ea[HPFS_EA_NAME + 255 + 1 + 8];
		grub_uint32_t namelen, vlen;

		if (grub_hpfs_ea_read(data, sec, ano, pos, HPFS_EA_NAME, ea))
			return NULL;
		namelen = ea[HPFS_EA_NAMELEN];
		vlen = ea[HPFS_EA_VALUELEN_LO] + 256 * ea[HPFS_EA_VALUELEN_HI];
		if (pos + HPFS_EA_HDR_LEN + namelen + vlen > len)
			break;
		if (grub_hpfs_ea_read(data, sec, ano, pos + HPFS_EA_NAME,
			namelen + 1
			+ ((ea[HPFS_EA_FLAGS] & HPFS_EA_FLAG_INDIRECT) ? 8 : 0),
			ea + HPFS_EA_NAME))
			return NULL;
		if (namelen == keylen
			&& grub_memcmp(ea + HPFS_EA_NAME, key, keylen) == 0)
		{
			char *ret;

			if (ea[HPFS_EA_FLAGS] & HPFS_EA_FLAG_INDIRECT)
				return grub_hpfs_ea_value(data, ea[HPFS_EA_FLAGS],
					ea + HPFS_EA_HDR_LEN + namelen, vlen, size);
			ret = grub_malloc(vlen + 1);
			if (!ret)
				return NULL;
			if (grub_hpfs_ea_read(data, sec, ano,
				pos + HPFS_EA_HDR_LEN + namelen, vlen, ret))
			{
				grub_free(ret);
				return NULL;
			}
			ret[vlen] = '\0';
			*size = vlen;
			return ret;
		}
		pos += HPFS_EA_HDR_LEN + namelen + vlen;
	}
	return NULL;
}

static void
grub_hpfs_unmount(struct grub_hpfs_data *data)
{
	if (!data)
		return;
	grub_free(data->hotfix_from);
	grub_free(data->hotfix_to);
	grub_free(data);
}

/* Load the map of bad sectors that were remapped to spare ones.  */
static grub_err_t
grub_hpfs_load_hotfix_map(struct grub_hpfs_data *data,
	const grub_uint8_t *spare)
{
	grub_uint8_t *map = NULL;
	grub_uint32_t n_spares, n_used, sec, i;

	n_used = hpfs_get32(spare + HPFS_SP_N_SPARES_USED);
	n_spares = hpfs_get32(spare + HPFS_SP_N_SPARES);
	if (!n_used)
		return GRUB_ERR_NONE;
	if (n_spares > HPFS_MAX_SPARES || n_used > n_spares)
		return grub_error(GRUB_ERR_BAD_FS,
			"hpfs: invalid number of hotfixes");

	sec = hpfs_get32(spare + HPFS_SP_HOTFIX_MAP);
	if (sec < HPFS_FIRST_SECTOR || sec > data->fs_size - 4)
		return grub_error(GRUB_ERR_BAD_FS, "hpfs: invalid hotfix map");

	map = grub_malloc(HPFS_DNODE_SIZE);
	data->hotfix_from = grub_malloc(n_used * sizeof(grub_uint32_t));
	data->hotfix_to = grub_malloc(n_used * sizeof(grub_uint32_t));
	if (!map || !data->hotfix_from || !data->hotfix_to)
		goto fail;
	/* the map itself is never hotfixed */
	if (grub_disk_read(data->disk, sec, 0, HPFS_DNODE_SIZE, map))
		goto fail;

	for (i = 0; i < n_used; i++)
	{
		data->hotfix_from[i] = hpfs_get32(map + 4 * i);
		data->hotfix_to[i] = hpfs_get32(map + 4 * (n_spares + i));
		/* a bogus target would silently return foreign data */
		if (data->hotfix_to[i] < HPFS_FIRST_SECTOR
			|| data->hotfix_to[i] >= data->fs_size)
		{
			grub_error(GRUB_ERR_BAD_FS,
				"hpfs: invalid hotfix target 0x%x",
				(unsigned) data->hotfix_to[i]);
			goto fail;
		}
	}
	data->n_hotfixes = n_used;
	grub_free(map);
	return GRUB_ERR_NONE;

fail:
	grub_free(map);
	return grub_errno;
}

static struct grub_hpfs_data *
grub_hpfs_mount(grub_disk_t disk)
{
	struct grub_hpfs_data *data = NULL;
	grub_uint8_t super[HPFS_SECTOR_SIZE];
	grub_uint8_t spare[HPFS_SECTOR_SIZE];
	grub_uint8_t boot[HPFS_SECTOR_SIZE];
	grub_uint32_t root;

	if (grub_disk_read(disk, HPFS_SUPER_SECTOR, 0, sizeof(super), super)
		|| grub_disk_read(disk, HPFS_SPARE_SECTOR, 0, sizeof(spare),
			spare))
		goto fail;
	if (hpfs_get32(super) != HPFS_SB_MAGIC
		|| hpfs_get32(spare) != HPFS_SP_MAGIC)
		goto fail;

	data = grub_zalloc(sizeof(*data));
	if (!data)
		return NULL;
	data->disk = disk;
	data->fs_size = hpfs_get32(super + HPFS_SB_N_SECTORS);
	root = hpfs_get32(super + HPFS_SB_ROOT);
	if (data->fs_size >= HPFS_MAX_SECTORS
		|| data->fs_size <= HPFS_FIRST_SECTOR + 4)
	{
		grub_error(GRUB_ERR_BAD_FS, "hpfs: invalid filesystem size");
		goto fail;
	}
	if (root < HPFS_FIRST_SECTOR || root >= data->fs_size)
	{
		grub_error(GRUB_ERR_BAD_FS, "hpfs: invalid root fnode");
		goto fail;
	}
	if (grub_hpfs_load_hotfix_map(data, spare))
		goto fail;

	/* the volume label and serial number live in the FAT style BPB */
	if (grub_disk_read(disk, 0, 0, sizeof(boot), boot) == GRUB_ERR_NONE
		&& grub_memcmp(boot + HPFS_BB_SIG_HPFS, "HPFS    ", 8) == 0)
	{
		int i;

		data->has_boot_block = 1;
		data->serial = hpfs_get32(boot + HPFS_BB_VOL_SERNO);
		grub_memcpy(data->label, boot + HPFS_BB_VOL_LABEL,
			HPFS_BB_LABEL_LEN);
		for (i = HPFS_BB_LABEL_LEN; i > 0; i--)
		{
			if (data->label[i - 1] != ' ' && data->label[i - 1] != '\0')
				break;
			data->label[i - 1] = '\0';
		}
	}
	grub_errno = GRUB_ERR_NONE;

	data->root.data = data;
	data->root.fnode = root;
	return data;

fail:
	grub_hpfs_unmount(data);
	if (grub_errno == GRUB_ERR_NONE || grub_errno == GRUB_ERR_OUT_OF_RANGE)
		grub_error(GRUB_ERR_BAD_FS, "not an hpfs filesystem");
	return NULL;
}

/* Translate the file relative sector SEC of NODE into a disk sector and
   the number of contiguous sectors that follow it.  */
static grub_err_t
grub_hpfs_bmap(struct grub_fshelp_node *node, grub_uint8_t **fnode,
	grub_uint32_t sec, grub_uint32_t *disk_sec, grub_uint32_t *n_secs)
{
	grub_uint32_t skip;

	skip = sec - node->cache_file_sec;
	if (node->cache_n_secs && sec >= node->cache_file_sec
		&& skip < node->cache_n_secs)
	{
		*disk_sec = node->cache_disk_sec + skip;
		*n_secs = node->cache_n_secs - skip;
		return GRUB_ERR_NONE;
	}

	if (!*fnode)
	{
		*fnode = grub_malloc(HPFS_SECTOR_SIZE);
		if (!*fnode)
			return grub_errno;
		if (grub_hpfs_read_node(node->data, node->fnode,
			HPFS_FNODE_MAGIC, *fnode))
			return grub_errno;
	}
	if (grub_hpfs_btree_lookup(node->data, *fnode, HPFS_FNODE_BTREE,
		HPFS_FNODE_BTREE_END, sec, disk_sec, n_secs))
		return grub_errno;

	node->cache_file_sec = sec;
	node->cache_disk_sec = *disk_sec;
	node->cache_n_secs = *n_secs;
	return GRUB_ERR_NONE;
}

/* read LEN bytes of the file NODE starting at POS */
static grub_err_t
grub_hpfs_read_file(struct grub_fshelp_node *node, grub_off_t pos,
	grub_size_t len, char *buf)
{
	grub_uint8_t *fnode = NULL;

	if (pos > node->size || len > node->size - pos)
	{
		grub_error(GRUB_ERR_OUT_OF_RANGE, "read past end of file");
		goto fail;
	}

	while (len)
	{
		grub_uint32_t disk_sec, n_secs, off;
		grub_size_t chunk;

		off = (grub_uint32_t) pos & HPFS_SECTOR_MASK;
		if (grub_hpfs_bmap(node, &fnode,
			(grub_uint32_t) (pos >> HPFS_SECTOR_BITS),
			&disk_sec, &n_secs))
			goto fail;

		chunk = (grub_size_t) n_secs * HPFS_SECTOR_SIZE - off;
		if (chunk > len)
			chunk = len;
		if (grub_hpfs_read_bytes(node->data, disk_sec, off, chunk, buf))
			goto fail;

		buf += chunk;
		pos += chunk;
		len -= chunk;
	}

	grub_free(fnode);
	return GRUB_ERR_NONE;

fail:
	grub_free(fnode);
	if (grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "hpfs: read error");
	return grub_errno;
}

/* Files created by the Linux driver keep their target in a "SYMLINK"
   extended attribute.  Probing costs one fnode read, so it is only done
   for directory entries that carry extended attributes at all.  */
static int
grub_hpfs_probe_symlink(struct grub_hpfs_dir_iter *it, grub_uint32_t fnode_sec,
	grub_uint32_t *size)
{
	struct grub_hpfs_data *data = it->dir->data;
	char *target;
	grub_uint32_t len = 0;

	if (!it->fnode)
	{
		it->fnode = grub_malloc(HPFS_SECTOR_SIZE);
		if (!it->fnode)
			return 0;
	}
	if (grub_hpfs_read_node(data, fnode_sec, HPFS_FNODE_MAGIC, it->fnode))
	{
		/* a broken fnode must not abort the whole listing */
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	target = grub_hpfs_get_ea(data, it->fnode, "SYMLINK", &len);
	grub_errno = GRUB_ERR_NONE;
	if (!target)
		return 0;
	grub_free(target);
	*size = len;
	return 1;
}

/* Walk one dnode of a directory B-tree in name order, descending into
   the subtree of every entry before reporting the entry itself.  Returns
   1 when the caller asked to stop, or on error with grub_errno set.  */
static int
grub_hpfs_iterate_dnode(struct grub_hpfs_dir_iter *it, grub_uint32_t dno,
	int depth)
{
	struct grub_hpfs_data *data = it->dir->data;
	grub_uint8_t *dnode;
	grub_uint32_t first_free, p, len;
	int ret = 0;

	if (depth > HPFS_MAX_DNODE_DEPTH)
	{
		grub_error(GRUB_ERR_BAD_FS, "hpfs: directory tree too deep");
		return 1;
	}
	dnode = grub_malloc(HPFS_DNODE_SIZE);
	if (!dnode)
		return 1;
	if (grub_hpfs_read_dnode(data, dno, dnode))
	{
		ret = 1;
		goto out;
	}

	first_free = hpfs_get32(dnode + HPFS_DNODE_FIRST_FREE);
	if (first_free < HPFS_DNODE_DIRENT || first_free > HPFS_DNODE_SIZE)
	{
		grub_error(GRUB_ERR_BAD_FS,
			"hpfs: dnode 0x%x has a bad first free offset",
			(unsigned) dno);
		ret = 1;
		goto out;
	}

	for (p = HPFS_DNODE_DIRENT;
		p + HPFS_DE_MIN_LENGTH <= first_free; p += len)
	{
		const grub_uint8_t *de = dnode + p;
		struct grub_fshelp_node *node;
		enum grub_fshelp_filetype type;
		char name[256];
		grub_uint32_t namelen, down = 0, fnode_sec, size;
		grub_uint8_t flags, attrs;

		len = hpfs_get16(de + HPFS_DE_LENGTH);
		flags = de[HPFS_DE_FLAGS];
		attrs = de[HPFS_DE_ATTRS];
		namelen = de[HPFS_DE_NAMELEN];
		if (len < HPFS_DE_MIN_LENGTH || (len & 3)
			|| p + len > HPFS_DNODE_SIZE
			|| HPFS_DE_NAME + namelen
				+ ((flags & HPFS_DE_FLAG_DOWN) ? 4 : 0) > len)
		{
			grub_error(GRUB_ERR_BAD_FS,
				"hpfs: bad directory entry in dnode 0x%x",
				(unsigned) dno);
			ret = 1;
			goto out;
		}
		if (flags & HPFS_DE_FLAG_DOWN)
			down = hpfs_get32(de + len - 4);

		/* the entries below this one sort before it */
		if (down)
		{
			ret = grub_hpfs_iterate_dnode(it, down, depth + 1);
			if (ret)
				goto out;
		}
		/* the phony ^A^A and \377 entries are not real files */
		if (flags & (HPFS_DE_FLAG_FIRST | HPFS_DE_FLAG_LAST))
			continue;

		grub_memcpy(name, de + HPFS_DE_NAME, namelen);
		name[namelen] = '\0';
		fnode_sec = hpfs_get32(de + HPFS_DE_FNODE);
		size = hpfs_get32(de + HPFS_DE_FILE_SIZE);

		if (attrs & HPFS_DE_ATTR_DIRECTORY)
			type = GRUB_FSHELP_DIR;
		else if (hpfs_get32(de + HPFS_DE_EA_SIZE)
			&& grub_hpfs_probe_symlink(it, fnode_sec, &size))
			type = GRUB_FSHELP_SYMLINK;
		else
			type = GRUB_FSHELP_REG;

		node = grub_zalloc(sizeof(*node));
		if (!node)
		{
			ret = 1;
			goto out;
		}
		node->data = data;
		node->fnode = fnode_sec;
		node->size = size;
		node->mtime = hpfs_get32(de + HPFS_DE_WRITE_DATE);

		ret = it->hook(name, type | GRUB_FSHELP_CASE_INSENSITIVE, node,
			it->hook_data);
		if (ret)
			goto out;
	}

out:
	grub_free(dnode);
	return ret;
}

/* A directory fnode's only extent points at the root of its dnode tree;
   it is read on demand because listing a directory does not need the
   fnodes of the subdirectories it contains.  */
static grub_err_t
grub_hpfs_dir_dnode(struct grub_fshelp_node *dir)
{
	grub_uint8_t *fnode;
	grub_uint32_t dno;
	grub_err_t err = GRUB_ERR_NONE;

	if (dir->dno)
		return GRUB_ERR_NONE;

	fnode = grub_malloc(HPFS_SECTOR_SIZE);
	if (!fnode)
		return grub_errno;
	err = grub_hpfs_read_node(dir->data, dir->fnode, HPFS_FNODE_MAGIC,
		fnode);
	if (err)
		goto out;
	if (!(hpfs_get16(fnode + HPFS_FNODE_FLAGS) & HPFS_FNODE_FLAG_DIR))
	{
		err = grub_error(GRUB_ERR_BAD_FILE_TYPE, "hpfs: fnode 0x%x "
			"is not a directory", (unsigned) dir->fnode);
		goto out;
	}
	/* The dnode is the first extent of the tree.  The btree header is
	   not checked: formatters leave n_used_nodes at 0 on directory
	   fnodes and the Linux driver reads the pointer unconditionally
	   too; the sector itself is validated below and by its magic.  */
	dno = hpfs_get32(fnode + HPFS_FNODE_BTREE + HPFS_BP_NODES + 8);
	if (dno < HPFS_FIRST_SECTOR || dno > dir->data->fs_size - 4)
	{
		err = grub_error(GRUB_ERR_BAD_FS, "hpfs: invalid root dnode 0x%x",
			(unsigned) dno);
		goto out;
	}
	dir->dno = dno;

out:
	grub_free(fnode);
	return err;
}

static int
grub_hpfs_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_hpfs_dir_iter it;
	int ret;

	if (grub_hpfs_dir_dnode(dir))
		return 1;

	it.dir = dir;
	it.hook = hook;
	it.hook_data = hook_data;
	it.fnode = NULL;
	ret = grub_hpfs_iterate_dnode(&it, dir->dno, 0);
	grub_free(it.fnode);
	return ret;
}

static char *
grub_hpfs_read_symlink(grub_fshelp_node_t node)
{
	grub_uint8_t *fnode;
	char *target = NULL;
	grub_uint32_t len = 0;

	fnode = grub_malloc(HPFS_SECTOR_SIZE);
	if (!fnode)
		return NULL;
	if (grub_hpfs_read_node(node->data, node->fnode, HPFS_FNODE_MAGIC,
		fnode))
		goto out;
	target = grub_hpfs_get_ea(node->data, fnode, "SYMLINK", &len);
	if (!target && grub_errno == GRUB_ERR_NONE)
		grub_error(GRUB_ERR_BAD_FS, "hpfs: symlink target not found");

out:
	grub_free(fnode);
	return target;
}

static int
grub_hpfs_dir_iter(const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *ctx_in)
{
	struct grub_hpfs_dir_ctx *ctx = ctx_in;
	struct grub_dirhook_info info;

	grub_memset(&info, 0, sizeof(info));
	info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink =
		((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK);
	info.case_insensitive = 1;
	info.mtimeset = 1;
	info.mtime = node->mtime;
	grub_free(node);
	return ctx->hook(filename, &info, ctx->hook_data);
}

static grub_err_t
grub_hpfs_dir(grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_hpfs_dir_ctx ctx = { hook, hook_data };
	struct grub_hpfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_hpfs_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(path, &data->root, &fdiro,
		grub_hpfs_iterate_dir, grub_hpfs_read_symlink,
		GRUB_FSHELP_DIR);
	if (grub_errno)
		goto fail;

	grub_hpfs_iterate_dir(fdiro, grub_hpfs_dir_iter, &ctx);

fail:
	if (fdiro != &data->root)
		grub_free(fdiro);
	grub_hpfs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_hpfs_open(struct grub_file *file, const char *name)
{
	struct grub_hpfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_hpfs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(name, &data->root, &fdiro,
		grub_hpfs_iterate_dir, grub_hpfs_read_symlink,
		GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	file->size = fdiro->size;
	file->data = fdiro;
	return GRUB_ERR_NONE;

fail:
	if (fdiro != &data->root)
		grub_free(fdiro);
	grub_hpfs_unmount(data);
	return grub_errno;
}

static grub_ssize_t
grub_hpfs_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fshelp_node *node = file->data;

	if (len == 0)
		return 0;
	if (grub_hpfs_read_file(node, file->offset, len, buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_hpfs_close(grub_file_t file)
{
	struct grub_fshelp_node *node = file->data;
	struct grub_hpfs_data *data = node->data;

	if (node != &data->root)
		grub_free(node);
	grub_hpfs_unmount(data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_hpfs_label(grub_device_t device, char **label)
{
	struct grub_hpfs_data *data;

	*label = NULL;
	data = grub_hpfs_mount(device->disk);
	if (!data)
		return grub_errno;

	*label = grub_strdup(data->label);
	grub_hpfs_unmount(data);
	return grub_errno;
}

static grub_err_t
grub_hpfs_uuid(grub_device_t device, char **uuid)
{
	struct grub_hpfs_data *data;

	*uuid = NULL;
	data = grub_hpfs_mount(device->disk);
	if (!data)
		return grub_errno;

	if (data->has_boot_block)
		*uuid = grub_xasprintf("%04x-%04x",
			(unsigned) (data->serial >> 16),
			(unsigned) (data->serial & 0xffff));
	grub_hpfs_unmount(data);
	return grub_errno;
}

static struct grub_fs grub_hpfs_fs =
{
	.name = "hpfs",
	.fs_dir = grub_hpfs_dir,
	.fs_open = grub_hpfs_open,
	.fs_read = grub_hpfs_read,
	.fs_close = grub_hpfs_close,
	.fs_label = grub_hpfs_label,
	.fs_uuid = grub_hpfs_uuid,
	.next = 0
};

GRUB_MOD_INIT(hpfs)
{
	grub_hpfs_fs.mod = mod;
	grub_fs_register(&grub_hpfs_fs);
}

GRUB_MOD_FINI(hpfs)
{
	grub_fs_unregister(&grub_hpfs_fs);
}
