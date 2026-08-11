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
 * VERITAS Filesystem (VxFS) read-only driver, disk layout version 2 to 4.
 *
 * The super block sits at byte 1024 on little endian (UnixWare, x86)
 * and at byte 8192 on big endian (HP-UX, PA-RISC) volumes;
 * everything else is addressed in filesystem blocks of vs_bsize bytes.
 * Mounting walks a chain of metadata inodes:
 *
 *   super block -> object location table (OLT) -> fileset header inode
 *      -> structural fileset header -> structural inode list inode
 *      -> primary fileset header -> inode list inode -> root inode
 *
 * The first two inodes of that chain are read straight out of the initial
 * inode list extent recorded in the OLT, the rest are read as file data of
 * the inode list they belong to.  File data itself comes in three flavours
 * selected by vdi_orgtype: immediate (up to 96 bytes stored in the inode),
 * "ext4" (ten direct extents plus a single and a double indirect address
 * extent) and typed (six extent descriptors that may point at further
 * blocks full of descriptors).
 *
 * Two details differ from what fs/freevxfs does, both verified against a
 * SCO UnixWare 7.1.4 volume with 2 KiB blocks:
 *
 *   - vs_oltext is a filesystem block address.  freevxfs scales it by
 *     s_blocksize / 1024, which only happens to be right for the 1 KiB
 *     block filesystems it was developed against.
 *   - the file offsets in typed extent descriptors are absolute file
 *     block numbers, in indirect blocks as well.  freevxfs subtracts the
 *     parent offset before descending, which again is only right as long
 *     as the parent descriptor starts at offset zero.
 *
 * Not supported: writing, VxFS 5 and newer, the multi volume (DEV4) extent
 * descriptors, extended attributes and quotas.
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

#define VXFS_SUPER_MAGIC	0xa501fcf5U
#define VXFS_OLT_MAGIC		0xa504fcf5U

/* the super block lives in the second 1 KiB block, big endian volumes
   keep it in the ninth one instead */
#define VXFS_SUPER_OFFSET_LE	1024
#define VXFS_SUPER_OFFSET_BE	8192

#define VXFS_ROOT_INO		2
#define VXFS_ISIZE		256
#define VXFS_NDADDR		10
#define VXFS_NTYPED		6
#define VXFS_NIMMED		96
#define VXFS_TYPED_SIZE		16
#define VXFS_NAMELEN		256

#define VXFS_MIN_VERSION	2
#define VXFS_MAX_VERSION	4
#define VXFS_MIN_BSIZE		512
#define VXFS_MAX_BSIZE		8192
#define VXFS_MAX_OLTSIZE	8
#define VXFS_MAX_SYMLINK	4096
/* corrupted images must not send us into an endless descent, nor make us
   walk a directory or a descriptor list that could not possibly fit */
#define VXFS_MAX_INDIR_DEPTH	8
#define VXFS_MAX_INDIR_BLOCKS	1024

/* super block byte offsets */
#define VXFS_SB_MAGIC		0x000
#define VXFS_SB_VERSION		0x004
#define VXFS_SB_BSIZE		0x020
#define VXFS_SB_SIZE		0x024
#define VXFS_SB_IMMEDLEN	0x040
#define VXFS_SB_NDADDR		0x044
#define VXFS_SB_FNAME		0x15c
#define VXFS_SB_FPACK		0x162
#define VXFS_SB_NAMELEN		6
#define VXFS_SB_OLTEXT		0x170
#define VXFS_SB_OLTSIZE		0x178
#define VXFS_SB_DINOSIZE	0x184
#define VXFS_SB_LEN		0x188

/* object location table byte offsets */
#define VXFS_OLT_HDR_MAGIC	0x00
#define VXFS_OLT_HDR_SIZE	0x04
#define VXFS_OLT_TYPE		0x00
#define VXFS_OLT_SIZE		0x04
#define VXFS_OLT_VALUE		0x08
#define VXFS_OLT_MIN_SIZE	0x0c

/* OLT record types */
#define VXFS_OLT_FSHEAD		2
#define VXFS_OLT_ILIST		4

/* fileset header byte offsets */
#define VXFS_FSH_ILISTINO	0x30
#define VXFS_FSH_LEN		0x3c

/* inode byte offsets */
#define VXFS_INO_MODE		0x00
#define VXFS_INO_SIZE		0x10
#define VXFS_INO_MTIME		0x20
#define VXFS_INO_ORGTYPE	0x31
#define VXFS_INO_BLOCKS		0x40
#define VXFS_INO_ORG		0x50

/* byte offsets inside the ext4 flavour of the vdi_org union */
#define VXFS_EXT4_INDSIZE	0x04
#define VXFS_EXT4_INDIR		0x08
#define VXFS_EXT4_DIRECT	0x10

/* directory block header and directory entry byte offsets */
#define VXFS_DIRBLK_NHASH	0x02
#define VXFS_DIRBLK_HDR		0x04
#define VXFS_DIRENT_INO		0x00
#define VXFS_DIRENT_RECLEN	0x04
#define VXFS_DIRENT_NAMELEN	0x06
#define VXFS_DIRENT_NAME	0x0a

/* file types, the low twelve bits of vdi_mode carry the permissions */
#define VXFS_TYPE_MASK		0xfffff000U
#define VXFS_IFDIR		0x00004000U
#define VXFS_IFREG		0x00008000U
#define VXFS_IFLNK		0x0000a000U
#define VXFS_IFFSH		0x10000000U	/* fileset header */
#define VXFS_IFILT		0x20000000U	/* inode list */

/* inode organisation types (vdi_orgtype) */
#define VXFS_ORG_NONE		0
#define VXFS_ORG_EXT4		1
#define VXFS_ORG_IMMED		2
#define VXFS_ORG_TYPED		3

/* typed extent descriptor types */
#define VXFS_TYPED_NONE		0
#define VXFS_TYPED_INDIRECT	1
#define VXFS_TYPED_DATA		2
#define VXFS_TYPED_INDIRECT_DEV4 3
#define VXFS_TYPED_DATA_DEV4	4

#define VXFS_TYPED_OFFSETMASK	0x00ffffffffffffffULL
#define VXFS_TYPED_TYPESHIFT	56

struct grub_vxfs_data;

struct grub_fshelp_node
{
	struct grub_vxfs_data *data;
	grub_uint32_t ino;
	grub_uint32_t mode;
	grub_uint32_t mtime;
	grub_uint32_t blocks;		/* blocks the inode occupies */
	grub_uint64_t size;
	grub_uint8_t orgtype;
	grub_uint8_t org[VXFS_NIMMED];	/* the vdi_org union, unswapped */
};

struct grub_vxfs_data
{
	grub_disk_t disk;
	int be;				/* big endian volume */
	grub_uint32_t version;
	grub_uint32_t bsize;
	int log2_bsize;			/* log2 of bsize in 512 byte sectors */
	grub_uint64_t blocks;		/* filesystem length in blocks */
	grub_uint64_t iext;		/* initial inode list extent */
	char label[VXFS_SB_NAMELEN + 1];
	struct grub_fshelp_node fship;
	struct grub_fshelp_node stilist;
	struct grub_fshelp_node ilist;
	struct grub_fshelp_node root;
};

/* context for grub_vxfs_dir */
struct grub_vxfs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static grub_uint16_t
vxfs_get16(struct grub_vxfs_data *data, const grub_uint8_t *p)
{
	grub_uint16_t v = grub_get_unaligned16(p);

	return data->be ? grub_be_to_cpu16(v) : grub_le_to_cpu16(v);
}

static grub_uint32_t
vxfs_get32(struct grub_vxfs_data *data, const grub_uint8_t *p)
{
	grub_uint32_t v = grub_get_unaligned32(p);

	return data->be ? grub_be_to_cpu32(v) : grub_le_to_cpu32(v);
}

static grub_uint64_t
vxfs_get64(struct grub_vxfs_data *data, const grub_uint8_t *p)
{
	grub_uint64_t v = grub_get_unaligned64(p);

	return data->be ? grub_be_to_cpu64(v) : grub_le_to_cpu64(v);
}

/* Copy a fixed size, NUL padded name field out of the super block.  */
static void
grub_vxfs_get_name(const grub_uint8_t *p, char *out)
{
	int i, len = 0;

	for (i = 0; i < VXFS_SB_NAMELEN && p[i]; i++)
	{
		/* fields the formatter left uninitialized carry binary junk */
		if (p[i] < 0x20 || p[i] > 0x7e)
			return;
		if (p[i] != ' ')
			len = i + 1;
	}
	grub_memcpy(out, p, len);
	out[len] = '\0';
}

static grub_err_t
grub_vxfs_read_blocks(struct grub_vxfs_data *data, grub_uint64_t block,
	grub_uint32_t n, void *buf)
{
	if (block >= data->blocks || n > data->blocks - block)
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: block %llu is outside of the filesystem",
			(unsigned long long) block);
	return grub_disk_read(data->disk, block << data->log2_bsize, 0,
		(grub_size_t) n * data->bsize, buf);
}

static grub_err_t
grub_vxfs_bmap_recs(struct grub_vxfs_data *data, const grub_uint8_t *recs,
	grub_uint32_t count, grub_uint64_t iblock, grub_uint64_t *pblock,
	int *done, int depth);

/* Search the descriptors held by the NBLOCKS blocks starting at START.  */
static grub_err_t
grub_vxfs_bmap_indir(struct grub_vxfs_data *data, grub_uint64_t start,
	grub_uint32_t nblocks, grub_uint64_t iblock, grub_uint64_t *pblock,
	int depth)
{
	grub_uint8_t *buf;
	grub_uint32_t i;
	grub_err_t err = GRUB_ERR_NONE;
	int done = 0;

	if (depth > VXFS_MAX_INDIR_DEPTH)
		return grub_error(GRUB_ERR_BAD_FS, "vxfs: extent tree too deep");
	if (nblocks > VXFS_MAX_INDIR_BLOCKS)
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: indirect extent of %u blocks is too big",
			(unsigned) nblocks);

	buf = grub_malloc(data->bsize);
	if (!buf)
		return grub_errno;

	for (i = 0; i < nblocks && !done && !*pblock; i++)
	{
		err = grub_vxfs_read_blocks(data, start + i, 1, buf);
		if (err)
			break;
		err = grub_vxfs_bmap_recs(data, buf,
			data->bsize / VXFS_TYPED_SIZE, iblock, pblock, &done,
			depth);
		if (err)
			break;
	}

	grub_free(buf);
	return err;
}

/* Look for the file block IBLOCK in COUNT typed extent descriptors.
   *PBLOCK stays zero when the block is not described (a hole), *DONE is
   set once the descriptor list has ended.  */
static grub_err_t
grub_vxfs_bmap_recs(struct grub_vxfs_data *data, const grub_uint8_t *recs,
	grub_uint32_t count, grub_uint64_t iblock, grub_uint64_t *pblock,
	int *done, int depth)
{
	grub_uint32_t i;

	for (i = 0; i < count; i++)
	{
		const grub_uint8_t *r = recs + i * VXFS_TYPED_SIZE;
		grub_uint64_t hdr = vxfs_get64(data, r);
		grub_uint64_t off = hdr & VXFS_TYPED_OFFSETMASK;
		grub_uint64_t block = vxfs_get32(data, r + 8);
		grub_uint64_t size = vxfs_get32(data, r + 12);
		grub_uint32_t type = (grub_uint32_t) (hdr >> VXFS_TYPED_TYPESHIFT);
		grub_err_t err;

		switch (type)
		{
		case VXFS_TYPED_NONE:
			*done = 1;
			return GRUB_ERR_NONE;

		case VXFS_TYPED_INDIRECT:
			if (iblock < off || !block)
				break;
			err = grub_vxfs_bmap_indir(data, block,
				(grub_uint32_t) size, iblock, pblock, depth + 1);
			if (err || *pblock)
				return err;
			break;

		case VXFS_TYPED_DATA:
			if (iblock < off || iblock - off >= size)
				break;
			*pblock = block ? block + (iblock - off) : 0;
			*done = 1;
			return GRUB_ERR_NONE;

		case VXFS_TYPED_INDIRECT_DEV4:
		case VXFS_TYPED_DATA_DEV4:
			return grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
				"vxfs: multi volume extents are not supported");

		default:
			return grub_error(GRUB_ERR_BAD_FS,
				"vxfs: unknown typed extent %u", (unsigned) type);
		}
	}
	return GRUB_ERR_NONE;
}

/* Read entry IDX of an indirect address extent of NBLOCKS blocks
   starting at START.  */
static grub_err_t
grub_vxfs_indir_entry(struct grub_vxfs_data *data, grub_uint64_t start,
	grub_uint32_t nblocks, grub_uint64_t idx, grub_uint64_t *out)
{
	grub_uint8_t buf[4];
	grub_uint64_t off;

	if (!start || idx >= (grub_uint64_t) nblocks * (data->bsize / 4))
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: invalid indirect address extent");
	if (start >= data->blocks)
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: block %llu is outside of the filesystem",
			(unsigned long long) start);

	off = start * data->bsize + idx * 4;
	if (grub_disk_read(data->disk, off >> GRUB_DISK_SECTOR_BITS,
		off & (GRUB_DISK_SECTOR_SIZE - 1), sizeof(buf), buf))
		return grub_errno;

	*out = vxfs_get32(data, buf);
	return GRUB_ERR_NONE;
}

/* Ten direct extents are followed by an indirect address extent holding
   one block address per entry and a double indirect one holding the
   addresses of further indirect address extents.  */
static grub_err_t
grub_vxfs_bmap_ext4(struct grub_fshelp_node *node, grub_uint64_t iblock,
	grub_uint64_t *pblock)
{
	struct grub_vxfs_data *data = node->data;
	grub_uint32_t indsize = vxfs_get32(data, node->org + VXFS_EXT4_INDSIZE);
	grub_uint64_t nindir, bn = iblock, next = 0;
	grub_err_t err;
	int i;

	for (i = 0; i < VXFS_NDADDR; i++)
	{
		const grub_uint8_t *d = node->org + VXFS_EXT4_DIRECT + 8 * i;
		grub_uint32_t ext = vxfs_get32(data, d);
		grub_uint32_t size = vxfs_get32(data, d + 4);

		if (bn < size)
		{
			*pblock = ext ? ext + bn : 0;
			return GRUB_ERR_NONE;
		}
		bn -= size;
	}

	/* a file whose tail was never written has no indirect area at all,
	   the blocks the direct extents leave out are holes */
	if (!indsize)
		return GRUB_ERR_NONE;
	nindir = (grub_uint64_t) indsize * (data->bsize / 4);

	if (bn < nindir)
	{
		next = vxfs_get32(data, node->org + VXFS_EXT4_INDIR);
		if (!next)
			return GRUB_ERR_NONE;
		return grub_vxfs_indir_entry(data, next, indsize, bn, pblock);
	}

	bn -= nindir;
	if (bn >= nindir * nindir)
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: block %llu is outside of inode %u",
			(unsigned long long) iblock, (unsigned) node->ino);

	next = vxfs_get32(data, node->org + VXFS_EXT4_INDIR + 4);
	if (!next)
		return GRUB_ERR_NONE;
	err = grub_vxfs_indir_entry(data, next, indsize, bn / nindir, &next);
	if (err)
		return err;
	if (!next)
		return GRUB_ERR_NONE;
	return grub_vxfs_indir_entry(data, next, indsize, bn % nindir, pblock);
}

/* Translate the file block IBLOCK of NODE, zero means a hole.  */
static grub_err_t
grub_vxfs_bmap(struct grub_fshelp_node *node, grub_uint64_t iblock,
	grub_uint64_t *pblock)
{
	struct grub_vxfs_data *data = node->data;
	grub_err_t err;
	int done = 0;

	*pblock = 0;
	switch (node->orgtype)
	{
	case VXFS_ORG_EXT4:
		err = grub_vxfs_bmap_ext4(node, iblock, pblock);
		break;

	case VXFS_ORG_TYPED:
		err = grub_vxfs_bmap_recs(data, node->org, VXFS_NTYPED, iblock,
			pblock, &done, 0);
		break;

	default:
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: inode %u has an unsupported organisation type %u",
			(unsigned) node->ino, (unsigned) node->orgtype);
	}

	if (err)
		return err;
	if (*pblock >= data->blocks)
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: block %llu is outside of the filesystem",
			(unsigned long long) *pblock);
	return GRUB_ERR_NONE;
}

static grub_disk_addr_t
grub_vxfs_get_block(grub_fshelp_node_t node, grub_disk_addr_t block)
{
	grub_uint64_t pblock;

	if (grub_vxfs_bmap(node, block, &pblock))
		return 0;
	return pblock;
}

static grub_err_t
grub_vxfs_read_file(struct grub_fshelp_node *node, grub_off_t pos,
	grub_size_t len, char *buf)
{
	if (pos > node->size || len > node->size - pos)
		return grub_error(GRUB_ERR_OUT_OF_RANGE, "read past end of file");

	/* small files live in the inode itself */
	if (node->orgtype == VXFS_ORG_IMMED)
	{
		if (pos + len > VXFS_NIMMED)
			return grub_error(GRUB_ERR_BAD_FS,
				"vxfs: immediate data of inode %u is too big",
				(unsigned) node->ino);
		grub_memcpy(buf, node->org + (grub_size_t) pos, len);
		return GRUB_ERR_NONE;
	}
	if (node->orgtype == VXFS_ORG_NONE)
	{
		grub_memset(buf, 0, len);
		return GRUB_ERR_NONE;
	}

	if (grub_fshelp_read_file(node->data->disk, node, NULL, NULL, pos, len,
		buf, grub_vxfs_get_block, node->size, node->data->log2_bsize,
		0) < 0)
	{
		if (grub_errno == GRUB_ERR_NONE)
			grub_error(GRUB_ERR_BAD_FS, "vxfs: read error");
		return grub_errno;
	}
	return GRUB_ERR_NONE;
}

/* Load inode INO into NODE.  It is read as file data of the inode list
   ILIST, or straight out of the initial inode list extent when ILIST is
   NULL -- which is how the two inodes describing the inode lists
   themselves are found.  */
static grub_err_t
grub_vxfs_read_inode(struct grub_vxfs_data *data,
	struct grub_fshelp_node *ilist, grub_uint32_t ino,
	struct grub_fshelp_node *node)
{
	grub_uint8_t raw[VXFS_ISIZE];
	grub_uint64_t off = (grub_uint64_t) ino * VXFS_ISIZE;

	if (ilist)
	{
		if (off + VXFS_ISIZE > ilist->size)
			return grub_error(GRUB_ERR_BAD_FS,
				"vxfs: inode %u is outside of the inode list",
				(unsigned) ino);
		if (grub_vxfs_read_file(ilist, off, sizeof(raw), (char *) raw))
			return grub_errno;
	}
	else
	{
		off += data->iext * data->bsize;
		if (grub_disk_read(data->disk, off >> GRUB_DISK_SECTOR_BITS,
			off & (GRUB_DISK_SECTOR_SIZE - 1), sizeof(raw), raw))
			return grub_errno;
	}

	node->data = data;
	node->ino = ino;
	node->mode = vxfs_get32(data, raw + VXFS_INO_MODE);
	node->size = vxfs_get64(data, raw + VXFS_INO_SIZE);
	node->mtime = vxfs_get32(data, raw + VXFS_INO_MTIME);
	node->blocks = vxfs_get32(data, raw + VXFS_INO_BLOCKS);
	node->orgtype = raw[VXFS_INO_ORGTYPE];
	/* the organisation area is swapped on access, its layout depends on
	   the organisation type */
	grub_memcpy(node->org, raw + VXFS_INO_ORG, VXFS_NIMMED);

	if (node->orgtype == VXFS_ORG_IMMED && node->size > VXFS_NIMMED)
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: immediate data of inode %u is too big",
			(unsigned) ino);
	return GRUB_ERR_NONE;
}

static enum grub_fshelp_filetype
grub_vxfs_filetype(grub_uint32_t mode)
{
	switch (mode & VXFS_TYPE_MASK)
	{
	case VXFS_IFDIR:
		return GRUB_FSHELP_DIR;
	case VXFS_IFLNK:
		return GRUB_FSHELP_SYMLINK;
	case VXFS_IFREG:
		return GRUB_FSHELP_REG;
	default:
		return GRUB_FSHELP_UNKNOWN;
	}
}

/* Read one of the two fileset headers stored in the fileset header inode
   and return the number of the inode list inode it describes.  */
static grub_err_t
grub_vxfs_read_fsh(struct grub_vxfs_data *data, int which,
	grub_uint32_t *ilistino)
{
	grub_uint8_t fsh[VXFS_FSH_LEN];

	if (grub_vxfs_read_file(&data->fship, (grub_off_t) which * data->bsize,
		sizeof(fsh), (char *) fsh))
		return grub_errno;

	*ilistino = vxfs_get32(data, fsh + VXFS_FSH_ILISTINO);
	if (!*ilistino)
		return grub_error(GRUB_ERR_BAD_FS,
			"vxfs: fileset header %d has no inode list", which);
	return GRUB_ERR_NONE;
}

/* The object location table points at the fileset header inode and at the
   extent the initial inode list lives in.  */
static grub_err_t
grub_vxfs_read_olt(struct grub_vxfs_data *data, grub_uint64_t oltext,
	grub_uint32_t oltsize, grub_uint32_t *fshino)
{
	grub_uint8_t *olt;
	grub_uint32_t len = oltsize * data->bsize, pos;
	grub_err_t err;

	olt = grub_malloc(len);
	if (!olt)
		return grub_errno;
	err = grub_vxfs_read_blocks(data, oltext, oltsize, olt);
	if (err)
		goto out;

	if (vxfs_get32(data, olt + VXFS_OLT_HDR_MAGIC) != VXFS_OLT_MAGIC)
	{
		err = grub_error(GRUB_ERR_BAD_FS, "vxfs: invalid olt magic");
		goto out;
	}

	*fshino = 0;
	data->iext = 0;
	pos = vxfs_get32(data, olt + VXFS_OLT_HDR_SIZE);
	while (pos <= len - VXFS_OLT_MIN_SIZE)
	{
		grub_uint32_t type = vxfs_get32(data, olt + pos + VXFS_OLT_TYPE);
		grub_uint32_t value = vxfs_get32(data, olt + pos + VXFS_OLT_VALUE);
		grub_uint32_t size = vxfs_get32(data, olt + pos + VXFS_OLT_SIZE);

		/* the record has to advance and to stay inside the extent */
		if (size < VXFS_OLT_MIN_SIZE || size > len - pos)
			break;
		if (type == VXFS_OLT_FSHEAD)
			*fshino = value;
		else if (type == VXFS_OLT_ILIST)
			data->iext = value;
		pos += size;
	}

	if (!*fshino || !data->iext)
		err = grub_error(GRUB_ERR_BAD_FS,
			"vxfs: olt has no fileset header or inode list");

out:
	grub_free(olt);
	return err;
}

static struct grub_vxfs_data *
grub_vxfs_mount(grub_disk_t disk)
{
	struct grub_vxfs_data *data;
	grub_uint8_t sb[VXFS_SB_LEN];
	grub_uint64_t total, oltext;
	grub_uint32_t oltsize, dinosize, fshino, ilistino;

	data = grub_zalloc(sizeof(*data));
	if (!data)
		return NULL;
	data->disk = disk;

	if (grub_disk_read(disk, VXFS_SUPER_OFFSET_LE >> GRUB_DISK_SECTOR_BITS,
		0, sizeof(sb), sb))
		goto fail;
	if (grub_get_unaligned32(sb + VXFS_SB_MAGIC)
		!= grub_cpu_to_le32_compile_time(VXFS_SUPER_MAGIC))
	{
		if (grub_disk_read(disk,
			VXFS_SUPER_OFFSET_BE >> GRUB_DISK_SECTOR_BITS, 0,
			sizeof(sb), sb))
			goto fail;
		if (grub_get_unaligned32(sb + VXFS_SB_MAGIC)
			!= grub_cpu_to_be32_compile_time(VXFS_SUPER_MAGIC))
			goto fail;
		data->be = 1;
	}

	data->version = vxfs_get32(data, sb + VXFS_SB_VERSION);
	if (data->version < VXFS_MIN_VERSION
		|| data->version > VXFS_MAX_VERSION)
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: unsupported disk layout "
			"version %u", (unsigned) data->version);
		goto fail;
	}

	data->bsize = vxfs_get32(data, sb + VXFS_SB_BSIZE);
	if (data->bsize < VXFS_MIN_BSIZE || data->bsize > VXFS_MAX_BSIZE
		|| (data->bsize & (data->bsize - 1)))
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: invalid block size %u",
			(unsigned) data->bsize);
		goto fail;
	}
	for (data->log2_bsize = 0;
		(grub_uint32_t) (GRUB_DISK_SECTOR_SIZE << data->log2_bsize)
			< data->bsize; data->log2_bsize++)
		;

	dinosize = vxfs_get32(data, sb + VXFS_SB_DINOSIZE);
	if (dinosize && dinosize != VXFS_ISIZE)
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: unsupported inode size %u",
			(unsigned) dinosize);
		goto fail;
	}

	data->blocks = vxfs_get32(data, sb + VXFS_SB_SIZE);
	total = grub_disk_native_sectors(disk);
	if (!data->blocks
		|| (total != GRUB_DISK_SIZE_UNKNOWN
			&& (data->blocks << data->log2_bsize) > total))
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: invalid filesystem size");
		goto fail;
	}

	oltext = vxfs_get32(data, sb + VXFS_SB_OLTEXT);
	oltsize = vxfs_get32(data, sb + VXFS_SB_OLTSIZE);
	if (!oltext || !oltsize || oltsize > VXFS_MAX_OLTSIZE)
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: invalid olt extent");
		goto fail;
	}
	if (grub_vxfs_read_olt(data, oltext, oltsize, &fshino))
		goto fail;

	/* the fileset header inode and the structural inode list inode are
	   the only ones addressed by the initial inode list extent */
	if (grub_vxfs_read_inode(data, NULL, fshino, &data->fship))
		goto fail;
	if ((data->fship.mode & VXFS_TYPE_MASK) != VXFS_IFFSH)
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: inode %u is not a fileset "
			"header", (unsigned) fshino);
		goto fail;
	}

	if (grub_vxfs_read_fsh(data, 0, &ilistino)
		|| grub_vxfs_read_inode(data, NULL, ilistino, &data->stilist))
		goto fail;
	if ((data->stilist.mode & VXFS_TYPE_MASK) != VXFS_IFILT)
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: inode %u is not the "
			"structural inode list", (unsigned) ilistino);
		goto fail;
	}

	if (grub_vxfs_read_fsh(data, 1, &ilistino)
		|| grub_vxfs_read_inode(data, &data->stilist, ilistino,
			&data->ilist))
		goto fail;
	if ((data->ilist.mode & VXFS_TYPE_MASK) != VXFS_IFILT)
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: inode %u is not the inode "
			"list", (unsigned) ilistino);
		goto fail;
	}

	if (grub_vxfs_read_inode(data, &data->ilist, VXFS_ROOT_INO, &data->root))
		goto fail;
	if ((data->root.mode & VXFS_TYPE_MASK) != VXFS_IFDIR)
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: root inode is not a directory");
		goto fail;
	}

	grub_vxfs_get_name(sb + VXFS_SB_FPACK, data->label);
	return data;

fail:
	grub_free(data);
	if (grub_errno == GRUB_ERR_NONE || grub_errno == GRUB_ERR_OUT_OF_RANGE)
		grub_error(GRUB_ERR_BAD_FS, "not a vxfs filesystem");
	return NULL;
}

/* Walk one directory block: a header with an optional hash chain array
   followed by the entries, the free space behind the last one is marked
   by a zero record length.  */
static int
grub_vxfs_iterate_dirblk(struct grub_fshelp_node *dir, grub_uint8_t *buf,
	grub_uint32_t len, grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_vxfs_data *data = dir->data;
	grub_uint32_t pos;

	pos = VXFS_DIRBLK_HDR
		+ 2 * vxfs_get16(data, buf + VXFS_DIRBLK_NHASH);

	while (pos + VXFS_DIRENT_NAME <= len)
	{
		struct grub_fshelp_node *node;
		char name[VXFS_NAMELEN + 1];
		grub_uint32_t ino = vxfs_get32(data, buf + pos + VXFS_DIRENT_INO);
		grub_uint32_t reclen =
			vxfs_get16(data, buf + pos + VXFS_DIRENT_RECLEN);
		grub_uint32_t namelen =
			vxfs_get16(data, buf + pos + VXFS_DIRENT_NAMELEN);

		/* the rest of the block is free space */
		if (!reclen)
			break;
		if (reclen < VXFS_DIRENT_NAME || (reclen & 3)
			|| pos + reclen > len)
		{
			grub_error(GRUB_ERR_BAD_FS,
				"vxfs: bad directory entry in inode %u",
				(unsigned) dir->ino);
			return 1;
		}
		pos += reclen;
		if (!ino || !namelen || namelen > VXFS_NAMELEN
			|| VXFS_DIRENT_NAME + namelen > reclen)
			continue;

		grub_memcpy(name, buf + pos - reclen + VXFS_DIRENT_NAME, namelen);
		name[namelen] = '\0';

		node = grub_zalloc(sizeof(*node));
		if (!node)
			return 1;
		if (grub_vxfs_read_inode(data, &data->ilist, ino, node))
		{
			/* a single broken entry must not abort the listing */
			grub_errno = GRUB_ERR_NONE;
			grub_free(node);
			continue;
		}
		if (hook(name, grub_vxfs_filetype(node->mode), node, hook_data))
			return 1;
	}
	return 0;
}

static int
grub_vxfs_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_vxfs_data *data = dir->data;
	grub_uint8_t *buf;
	grub_uint64_t pos;
	int ret = 0;

	if ((dir->mode & VXFS_TYPE_MASK) != VXFS_IFDIR)
	{
		grub_error(GRUB_ERR_BAD_FILE_TYPE,
			"vxfs: inode %u is not a directory", (unsigned) dir->ino);
		return 1;
	}
	/* Directories are never sparse, so their size has to be covered by the
	   blocks the inode claims -- without that bound a corrupted size would
	   send the loop below through billions of holes.  */
	if (dir->orgtype != VXFS_ORG_IMMED
		&& (dir->size > (grub_uint64_t) dir->blocks * data->bsize
			|| dir->size > data->blocks * data->bsize))
	{
		grub_error(GRUB_ERR_BAD_FS,
			"vxfs: directory inode %u is too big", (unsigned) dir->ino);
		return 1;
	}

	buf = grub_malloc(data->bsize);
	if (!buf)
		return 1;

	for (pos = 0; pos < dir->size && !ret; pos += data->bsize)
	{
		grub_uint32_t len = data->bsize;

		if (dir->size - pos < len)
			len = (grub_uint32_t) (dir->size - pos);
		if (dir->orgtype != VXFS_ORG_IMMED)
		{
			grub_uint64_t pblock;

			/* an unmapped directory block means a corrupted inode */
			if (grub_vxfs_bmap(dir, pos / data->bsize, &pblock))
			{
				ret = 1;
				break;
			}
			if (!pblock)
			{
				grub_error(GRUB_ERR_BAD_FS, "vxfs: directory inode "
					"%u has an unmapped block",
					(unsigned) dir->ino);
				ret = 1;
				break;
			}
		}
		if (grub_vxfs_read_file(dir, pos, len, (char *) buf))
		{
			ret = 1;
			break;
		}
		ret = grub_vxfs_iterate_dirblk(dir, buf, len, hook, hook_data);
	}

	grub_free(buf);
	return ret;
}

static char *
grub_vxfs_read_symlink(grub_fshelp_node_t node)
{
	char *target;

	if (!node->size || node->size > VXFS_MAX_SYMLINK)
	{
		grub_error(GRUB_ERR_BAD_FS, "vxfs: invalid symlink in inode %u",
			(unsigned) node->ino);
		return NULL;
	}

	target = grub_malloc((grub_size_t) node->size + 1);
	if (!target)
		return NULL;
	if (grub_vxfs_read_file(node, 0, (grub_size_t) node->size, target))
	{
		grub_free(target);
		return NULL;
	}
	target[node->size] = '\0';
	return target;
}

static int
grub_vxfs_dir_iter(const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *ctx_in)
{
	struct grub_vxfs_dir_ctx *ctx = ctx_in;
	struct grub_dirhook_info info;

	grub_memset(&info, 0, sizeof(info));
	info.dir = (filetype == GRUB_FSHELP_DIR);
	info.symlink = (filetype == GRUB_FSHELP_SYMLINK);
	info.mtimeset = 1;
	info.mtime = node->mtime;
	info.inodeset = 1;
	info.inode = node->ino;
	grub_free(node);
	return ctx->hook(filename, &info, ctx->hook_data);
}

static grub_err_t
grub_vxfs_dir(grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_vxfs_dir_ctx ctx = { hook, hook_data };
	struct grub_vxfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_vxfs_mount(device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(path, &data->root, &fdiro, grub_vxfs_iterate_dir,
		grub_vxfs_read_symlink, GRUB_FSHELP_DIR);
	if (grub_errno)
		goto fail;

	grub_vxfs_iterate_dir(fdiro, grub_vxfs_dir_iter, &ctx);

fail:
	if (fdiro != &data->root)
		grub_free(fdiro);
	grub_free(data);
	return grub_errno;
}

static grub_err_t
grub_vxfs_open(struct grub_file *file, const char *name)
{
	struct grub_vxfs_data *data;
	struct grub_fshelp_node *fdiro = NULL;

	data = grub_vxfs_mount(file->device->disk);
	if (!data)
		return grub_errno;

	grub_fshelp_find_file(name, &data->root, &fdiro, grub_vxfs_iterate_dir,
		grub_vxfs_read_symlink, GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	file->size = fdiro->size;
	file->data = fdiro;
	return GRUB_ERR_NONE;

fail:
	if (fdiro != &data->root)
		grub_free(fdiro);
	grub_free(data);
	return grub_errno;
}

static grub_ssize_t
grub_vxfs_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fshelp_node *node = file->data;

	if (len == 0)
		return 0;
	if (grub_vxfs_read_file(node, file->offset, len, buf))
		return -1;
	return (grub_ssize_t) len;
}

static grub_err_t
grub_vxfs_close(grub_file_t file)
{
	struct grub_fshelp_node *node = file->data;
	struct grub_vxfs_data *data = node->data;

	if (node != &data->root)
		grub_free(node);
	grub_free(data);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_vxfs_label(grub_device_t device, char **label)
{
	struct grub_vxfs_data *data;

	*label = NULL;
	data = grub_vxfs_mount(device->disk);
	if (!data)
		return grub_errno;

	if (data->label[0])
		*label = grub_strdup(data->label);
	grub_free(data);
	return grub_errno;
}

static struct grub_fs grub_vxfs_fs =
{
	.name = "vxfs",
	.fs_dir = grub_vxfs_dir,
	.fs_open = grub_vxfs_open,
	.fs_read = grub_vxfs_read,
	.fs_close = grub_vxfs_close,
	.fs_label = grub_vxfs_label,
	.next = 0
};

GRUB_MOD_INIT(vxfs)
{
	grub_vxfs_fs.mod = mod;
	grub_fs_register(&grub_vxfs_fs);
}

GRUB_MOD_FINI(vxfs)
{
	grub_fs_unregister(&grub_vxfs_fs);
}
