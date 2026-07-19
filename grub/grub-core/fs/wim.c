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
 * WIM (Windows Imaging) read-only filesystem.
 *
 * The root of the filesystem mirrors 7-Zip's presentation of a WIM
 * archive: one directory per image ("1", "2", ...) plus the raw XML
 * metadata blob exposed as "[1].xml".
 *
 * On-disk structures and the resource/chunk pipeline follow
 * wimboot (wim.h / wim.c); XPRESS and LZX chunk decompressors
 * live in grub-core\lib\wimboot.  Unlike wimboot, directory
 * iteration skips over named stream entries and falls back to the
 * unnamed stream entry's hash when the directory entry carries none
 * (wimlib-written images).  Solid/LZMS resources (ESD) are rejected
 * at read time.
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

#include <lzx.h>
#include <xca.h>

GRUB_MOD_LICENSE("GPLv3+");

#define WIM_CHUNK_LEN		32768
#define WIM_XML_NAME		"[1].xml"
#define WIM_HASH_LEN		20

/* wim_header::flags */
#define WIM_HDR_COMPRESS_XPRESS	0x00020000
#define WIM_HDR_COMPRESS_LZX	0x00040000

/* wim_resource_header::zlen__flags */
#define WIM_RESHDR_ZLEN_MASK	0x00ffffffffffffffULL
#define WIM_RESHDR_METADATA	(0x02ULL << 56)
#define WIM_RESHDR_COMPRESSED	(0x04ULL << 56)
#define WIM_RESHDR_PACKED_STREAMS	(0x10ULL << 56)

/* wim_directory_entry::attributes */
#define WIM_ATTR_DIRECTORY	0x00000010

/* seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01 */
#define WIM_EPOCH_BIAS		11644473600ULL

PRAGMA_BEGIN_PACKED
struct wim_resource_header
{
	grub_uint64_t zlen__flags;
	grub_uint64_t offset;
	grub_uint64_t len;
};

struct wim_header
{
	grub_uint8_t signature[8];	/* "MSWIM\0\0" */
	grub_uint32_t header_len;
	grub_uint32_t version;
	grub_uint32_t flags;
	grub_uint32_t chunk_len;
	grub_packed_guid_t guid;
	grub_uint16_t part;
	grub_uint16_t parts;
	grub_uint32_t images;
	struct wim_resource_header lookup;
	struct wim_resource_header xml;
	struct wim_resource_header boot;
	grub_uint32_t boot_index;
	struct wim_resource_header integrity;
	grub_uint8_t reserved[60];
};

struct wim_security_header
{
	grub_uint32_t len;
	grub_uint32_t count;
};

struct wim_directory_entry
{
	grub_uint64_t len;
	grub_uint32_t attributes;
	grub_uint32_t security;
	grub_uint64_t subdir;
	grub_uint8_t reserved1[16];
	grub_uint64_t ctime;
	grub_uint64_t atime;
	grub_uint64_t mtime;
	grub_uint8_t hash[WIM_HASH_LEN];
	grub_uint8_t reserved2[12];
	grub_uint16_t streams;
	grub_uint16_t short_name_len;
	grub_uint16_t name_len;
	/* UTF-16LE name follows */
};

struct wim_stream_entry
{
	grub_uint64_t len;
	grub_uint64_t reserved;
	grub_uint8_t hash[WIM_HASH_LEN];
	grub_uint16_t name_len;
	/* UTF-16LE stream name follows */
};

struct wim_lookup_entry
{
	struct wim_resource_header resource;
	grub_uint16_t part;
	grub_uint32_t refcnt;
	grub_uint8_t hash[WIM_HASH_LEN];
};
PRAGMA_END_PACKED

struct grub_wim_data
{
	grub_disk_t disk;
	grub_uint64_t size;		/* device size in bytes (upper bound) */
	struct wim_header header;
	grub_uint32_t nimages;		/* number of entries in meta[] */
	/* single-chunk decompression cache */
	int cache_valid;
	grub_uint64_t cached_res_offset;
	grub_uint64_t cached_chunk;
	grub_uint8_t chunk_data[WIM_CHUNK_LEN];
	struct wim_resource_header meta[];	/* meta[i] = image i+1 */
};

struct grub_fshelp_node
{
	struct grub_wim_data *data;
	struct wim_resource_header *meta;	/* image metadata resource */
	grub_uint64_t subdir;		/* children offset in metadata */
	grub_uint64_t mtime;		/* Windows FILETIME */
	grub_uint32_t attributes;
	grub_uint8_t hash[WIM_HASH_LEN];	/* main data stream hash */
	struct wim_resource_header resource;	/* file data (open only) */
};

static grub_int64_t
grub_wim_filetime_to_unix(grub_uint64_t ft)
{
	return (grub_int64_t) grub_divmod64(ft, 10000000, 0)
		- (grub_int64_t) WIM_EPOCH_BIAS;
}

static int
grub_wim_hash_empty(const grub_uint8_t *hash)
{
	unsigned int i;

	for (i = 0; i < WIM_HASH_LEN; i++)
		if (hash[i])
			return 0;
	return 1;
}

/* convert an UTF-16LE name (LEN 16-bit units, not NUL-terminated) to
   a freshly allocated UTF-8 string */
static char *
grub_wim_get_utf8(const grub_uint8_t *in, grub_size_t len)
{
	grub_uint8_t *buf;
	grub_uint16_t *tmp;
	grub_size_t i;

	buf = grub_calloc(len + 1, GRUB_MAX_UTF8_PER_UTF16);
	tmp = grub_calloc(len + 1, sizeof(tmp[0]));
	if (!buf || !tmp)
		goto fail;
	for (i = 0; i < len; i++)
		tmp[i] = grub_le_to_cpu16(grub_get_unaligned16(in + 2 * i));
	*grub_utf16_to_utf8(buf, tmp, len) = '\0';
	grub_free(tmp);
	return (char *) buf;

fail:
	grub_free(buf);
	grub_free(tmp);
	return NULL;
}

/*
 * Chunked resource reading, modeled on wimboot's wim_chunk_offset() /
 * wim_chunk() / wim_read().
 */

static int
grub_wim_get_chunk_offset(struct grub_wim_data *data,
	const struct wim_resource_header *res, grub_uint64_t chunk,
	grub_uint64_t *offset)
{
	grub_uint64_t zlen = grub_le_to_cpu64(res->zlen__flags)
		& WIM_RESHDR_ZLEN_MASK;
	grub_uint64_t len = grub_le_to_cpu64(res->len);
	grub_uint64_t chunks;
	grub_uint64_t offset_offset;
	grub_uint64_t chunks_len;
	grub_size_t offset_len;
	union
	{
		grub_uint32_t offset_32;
		grub_uint64_t offset_64;
	} u;

	/* zero-length resources have no chunks */
	if (!len)
	{
		*offset = 0;
		return 0;
	}

	/* the chunk table precedes the chunk data; chunk 0 has no entry */
	chunks = (len + WIM_CHUNK_LEN - 1) / WIM_CHUNK_LEN;
	offset_len = (len > 0xffffffffULL) ?
		sizeof(u.offset_64) : sizeof(u.offset_32);
	chunks_len = (chunks - 1) * offset_len;
	if (chunks_len > zlen)
		goto fail;

	if (!chunk)
	{
		*offset = chunks_len;
		return 0;
	}

	/* out-of-range chunk = end of resource (final chunk length calc) */
	if (chunk >= chunks)
	{
		*offset = zlen;
		return 0;
	}

	u.offset_64 = 0;
	offset_offset = (chunk - 1) * offset_len;
	if (grub_disk_read(data->disk, 0,
		grub_le_to_cpu64(res->offset) + offset_offset, offset_len, &u))
		return -1;
	*offset = chunks_len + ((offset_len == sizeof(u.offset_64)) ?
		grub_le_to_cpu64(u.offset_64) : grub_le_to_cpu32(u.offset_32));
	if (*offset > zlen)
		goto fail;
	return 0;

fail:
	grub_error(GRUB_ERR_BAD_FS, "wim chunk table corrupt");
	return -1;
}

/* read + decompress one 32 KiB chunk into data->chunk_data */
static int
grub_wim_get_chunk(struct grub_wim_data *data,
	const struct wim_resource_header *res, grub_uint64_t chunk)
{
	grub_uint64_t len64 = grub_le_to_cpu64(res->len);
	grub_uint64_t res_offset = grub_le_to_cpu64(res->offset);
	grub_uint32_t flags = grub_le_to_cpu32(data->header.flags);
	grub_uint64_t chunks;
	grub_uint64_t offset;
	grub_uint64_t next_offset;
	grub_size_t len;
	grub_size_t expected_out_len;

	if (grub_wim_get_chunk_offset(data, res, chunk, &offset) != 0)
		return -1;
	if (grub_wim_get_chunk_offset(data, res, chunk + 1, &next_offset) != 0)
		return -1;
	if (next_offset < offset || next_offset - offset > 2 * WIM_CHUNK_LEN)
	{
		grub_error(GRUB_ERR_BAD_FS, "wim chunk table corrupt");
		return -1;
	}
	len = (grub_size_t) (next_offset - offset);

	chunks = (len64 + WIM_CHUNK_LEN - 1) / WIM_CHUNK_LEN;
	expected_out_len = WIM_CHUNK_LEN;
	if (chunk >= chunks - 1)
		expected_out_len -= (grub_size_t) (-len64 & (WIM_CHUNK_LEN - 1));

	if (len == expected_out_len)
	{
		/* chunk did not compress; stored raw */
		if (grub_disk_read(data->disk, 0,
			res_offset + offset, len, data->chunk_data))
			return -1;
	}
	else
	{
		grub_ssize_t (*decompress)(const void *src, grub_size_t n,
			void *dest);
		grub_ssize_t out_len;
		grub_uint8_t *zbuf;

		if (flags & WIM_HDR_COMPRESS_LZX)
			decompress = lzx_decompress;
		else if (flags & WIM_HDR_COMPRESS_XPRESS)
			decompress = xca_decompress;
		else
		{
			grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
				"unsupported wim compression (LZMS/solid?)");
			return -1;
		}

		if (len == 0)
		{
			grub_error(GRUB_ERR_BAD_FS, "wim chunk table corrupt");
			return -1;
		}

		/* the XPRESS bitstream reader may overread its input by
		   up to two bytes; give it some zeroed slack */
		zbuf = grub_malloc(len + 8);
		if (!zbuf)
			return -1;
		grub_memset(zbuf + len, 0, 8);
		if (grub_disk_read(data->disk, 0, res_offset + offset, len,
			zbuf))
		{
			grub_free(zbuf);
			return -1;
		}
		out_len = decompress(zbuf, len, NULL);
		if (out_len == (grub_ssize_t) expected_out_len)
			decompress(zbuf, len, data->chunk_data);
		grub_free(zbuf);
		if (out_len != (grub_ssize_t) expected_out_len)
		{
			grub_error(GRUB_ERR_BAD_COMPRESSED_DATA,
				"wim chunk decompression failed");
			return -1;
		}
	}

	return 0;
}

/* read LEN bytes at OFFSET from a (possibly compressed) resource */
static int
grub_wim_get_resource(struct grub_wim_data *data,
	const struct wim_resource_header *res, void *buf,
	grub_uint64_t offset, grub_uint64_t len)
{
	grub_uint64_t flags = grub_le_to_cpu64(res->zlen__flags);
	grub_uint64_t zlen = flags & WIM_RESHDR_ZLEN_MASK;
	grub_uint64_t res_offset = grub_le_to_cpu64(res->offset);
	grub_uint8_t *p = buf;

	if (len == 0)
		return 0;
	if (offset + len < offset
		|| offset + len > grub_le_to_cpu64(res->len))
	{
		grub_error(GRUB_ERR_OUT_OF_RANGE,
			"attempt to read past the end of wim resource");
		return -1;
	}
	if (res_offset + zlen > data->size)
	{
		grub_error(GRUB_ERR_BAD_FS, "wim resource outside device");
		return -1;
	}

	if (flags & WIM_RESHDR_PACKED_STREAMS)
	{
		grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
			"solid wim resources are not supported");
		return -1;
	}

	/* uncompressed resource: read the raw bytes */
	if (!(flags & WIM_RESHDR_COMPRESSED))
		return grub_disk_read(data->disk, 0, res_offset + offset,
			len, buf) ? -1 : 0;

	/* copy out of each chunk overlapping the target region */
	while (len)
	{
		grub_uint64_t chunk = grub_divmod64(offset, WIM_CHUNK_LEN, 0);
		grub_size_t skip_len = (grub_size_t) (offset % WIM_CHUNK_LEN);
		grub_size_t frag_len = WIM_CHUNK_LEN - skip_len;

		if (!data->cache_valid
			|| res_offset != data->cached_res_offset
			|| chunk != data->cached_chunk)
		{
			if (grub_wim_get_chunk(data, res, chunk) != 0)
			{
				data->cache_valid = 0;
				return -1;
			}
			data->cache_valid = 1;
			data->cached_res_offset = res_offset;
			data->cached_chunk = chunk;
		}

		if (frag_len > len)
			frag_len = (grub_size_t) len;
		grub_memcpy(p, data->chunk_data + skip_len, frag_len);
		p += frag_len;
		offset += frag_len;
		len -= frag_len;
	}

	return 0;
}

static struct grub_wim_data *
grub_wim_mount(grub_disk_t disk)
{
	struct wim_header header;
	struct grub_wim_data *data = NULL;
	grub_uint64_t offset;
	grub_uint64_t lookup_len;
	grub_uint32_t max_images;

	if (grub_disk_read(disk, 0, 0, sizeof(header), &header))
		goto fail;
	if (grub_memcmp(header.signature, "MSWIM\0\0", 8) != 0)
		goto fail;
	if (grub_le_to_cpu32(header.header_len) < sizeof(header))
		goto fail;

	/* one metadata resource per image; trust the header count as the
	   upper bound for the array (sanity-capped) */
	max_images = grub_le_to_cpu32(header.images);
	if (max_images > 0xffff)
		goto fail;

	data = grub_zalloc(sizeof(*data)
		+ max_images * sizeof(data->meta[0]));
	if (!data)
		goto fail;

	grub_memcpy(&data->header, &header, sizeof(header));
	data->disk = disk;
	data->size = grub_disk_native_sectors(disk) << GRUB_DISK_SECTOR_BITS;

	/* collect the per-image metadata resources from the lookup table */
	lookup_len = grub_le_to_cpu64(data->header.lookup.len);
	for (offset = 0;
		offset + sizeof(struct wim_lookup_entry) <= lookup_len
		&& data->nimages < max_images;
		offset += sizeof(struct wim_lookup_entry))
	{
		struct wim_lookup_entry entry;

		if (grub_wim_get_resource(data, &data->header.lookup, &entry,
			offset, sizeof(entry)) != 0)
			goto fail;
		if (grub_le_to_cpu64(entry.resource.zlen__flags)
			& WIM_RESHDR_METADATA)
			data->meta[data->nimages++] = entry.resource;
	}

	grub_errno = GRUB_ERR_NONE;
	return data;

fail:
	grub_free(data);
	grub_error(GRUB_ERR_BAD_FS, "not a wim filesystem");
	return NULL;
}

/* locate a file resource in the lookup table by SHA-1 hash */
static int
grub_wim_find_resource(struct grub_wim_data *data, const grub_uint8_t *hash,
	struct wim_resource_header *res)
{
	grub_uint64_t lookup_len = grub_le_to_cpu64(data->header.lookup.len);
	grub_uint64_t offset;

	for (offset = 0;
		offset + sizeof(struct wim_lookup_entry) <= lookup_len;
		offset += sizeof(struct wim_lookup_entry))
	{
		struct wim_lookup_entry entry;

		if (grub_wim_get_resource(data, &data->header.lookup, &entry,
			offset, sizeof(entry)) != 0)
			return -1;
		if (grub_memcmp(entry.hash, hash, WIM_HASH_LEN) == 0)
		{
			*res = entry.resource;
			return 0;
		}
	}

	grub_error(GRUB_ERR_FILE_NOT_FOUND, "wim stream not found");
	return -1;
}

/* build the fshelp node for the root directory of image IMAGE (1-based) */
static int
grub_wim_get_root(struct grub_wim_data *data, unsigned long image,
	struct grub_fshelp_node *root)
{
	struct wim_security_header security;
	struct wim_directory_entry direntry;
	grub_uint64_t offset;

	if (image < 1 || image > data->nimages)
	{
		grub_error(GRUB_ERR_FILE_NOT_FOUND, "no such wim image");
		return -1;
	}

	grub_memset(root, 0, sizeof(*root));
	root->data = data;
	root->meta = &data->meta[image - 1];

	if (grub_wim_get_resource(data, root->meta, &security, 0,
		sizeof(security)) != 0)
		return -1;

	/* the root directory entry follows the 8-byte aligned security
	   data (whose length includes this header, but some writers
	   store 0 there when the table is empty) */
	offset = (grub_le_to_cpu32(security.len) + 7) & ~7ULL;
	if (offset < sizeof(security))
		offset = sizeof(security);

	if (grub_wim_get_resource(data, root->meta, &direntry, offset,
		sizeof(direntry)) != 0)
		return -1;
	if (!direntry.len
		|| !(grub_le_to_cpu32(direntry.attributes) & WIM_ATTR_DIRECTORY))
	{
		grub_error(GRUB_ERR_BAD_FS, "wim root directory not found");
		return -1;
	}

	root->subdir = grub_le_to_cpu64(direntry.subdir);
	root->attributes = grub_le_to_cpu32(direntry.attributes);
	root->mtime = grub_le_to_cpu64(direntry.mtime);
	return 0;
}

static char *
grub_wim_read_symlink(grub_fshelp_node_t node __attribute__((unused)))
{
	/* reparse points are exposed as regular entries */
	return NULL;
}

static int
grub_wim_iterate_dir(grub_fshelp_node_t dir,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_wim_data *data = dir->data;
	grub_uint64_t offset = dir->subdir;

	/* a directory with no children has subdir == 0 */
	if (!offset)
		return 0;

	for (;;)
	{
		struct wim_directory_entry direntry;
		grub_uint8_t hash[WIM_HASH_LEN];
		grub_uint64_t next;
		grub_uint32_t attributes;
		grub_uint16_t streams;
		grub_uint16_t name_len;
		grub_uint8_t *namebuf = NULL;
		char *name = NULL;
		struct grub_fshelp_node *node;
		enum grub_fshelp_filetype filetype;
		int hash_empty;
		int ret;

		if (grub_wim_get_resource(data, dir->meta, &direntry, offset,
			sizeof(direntry.len)) != 0)
			return 0;
		if (!direntry.len)
			break;
		if (grub_wim_get_resource(data, dir->meta, &direntry, offset,
			sizeof(direntry)) != 0)
			return 0;

		grub_memcpy(hash, direntry.hash, WIM_HASH_LEN);
		hash_empty = grub_wim_hash_empty(hash);

		/* step over this entry and any named stream entries; the
		   unnamed stream entry, when present, carries the data
		   hash for entries that have none of their own */
		next = offset + ((grub_le_to_cpu64(direntry.len) + 7) & ~7ULL);
		streams = grub_le_to_cpu16(direntry.streams);
		while (streams--)
		{
			struct wim_stream_entry stream;

			if (grub_wim_get_resource(data, dir->meta, &stream,
				next, sizeof(stream)) != 0)
				return 0;
			if (!stream.len)
			{
				grub_error(GRUB_ERR_BAD_FS,
					"wim stream entry corrupt");
				return 0;
			}
			if (hash_empty && stream.name_len == 0)
			{
				grub_memcpy(hash, stream.hash, WIM_HASH_LEN);
				hash_empty = grub_wim_hash_empty(hash);
			}
			next += (grub_le_to_cpu64(stream.len) + 7) & ~7ULL;
		}

		name_len = grub_le_to_cpu16(direntry.name_len);
		if (name_len < sizeof(grub_uint16_t))
			goto next_entry;

		namebuf = grub_malloc(name_len);
		if (!namebuf)
			return 0;
		if (grub_wim_get_resource(data, dir->meta, namebuf,
			offset + sizeof(direntry), name_len) != 0)
		{
			grub_free(namebuf);
			return 0;
		}
		name = grub_wim_get_utf8(namebuf,
			name_len / sizeof(grub_uint16_t));
		grub_free(namebuf);
		if (!name)
			return 0;

		node = grub_zalloc(sizeof(*node));
		if (!node)
		{
			grub_free(name);
			return 0;
		}
		node->data = data;
		node->meta = dir->meta;
		node->subdir = grub_le_to_cpu64(direntry.subdir);
		node->mtime = grub_le_to_cpu64(direntry.mtime);
		attributes = grub_le_to_cpu32(direntry.attributes);
		node->attributes = attributes;
		grub_memcpy(node->hash, hash, WIM_HASH_LEN);

		filetype = (attributes & WIM_ATTR_DIRECTORY) ?
			GRUB_FSHELP_DIR : GRUB_FSHELP_REG;
		filetype |= GRUB_FSHELP_CASE_INSENSITIVE;

		ret = hook(name, filetype, node, hook_data);
		grub_free(name);
		if (ret)
			return ret;

	next_entry:
		offset = next;
	}

	return 0;
}

/* context + hook adapter for directory listing */
struct grub_wim_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_wim_dir_iter(const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *data)
{
	struct grub_wim_dir_ctx *ctx = data;
	struct grub_dirhook_info info;

	grub_memset(&info, 0, sizeof(info));
	info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
	info.symlink = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK);
	info.case_insensitive = 1;
	info.mtimeset = 1;
	info.mtime = grub_wim_filetime_to_unix(node->mtime);
	grub_free(node);
	return ctx->hook(filename, &info, ctx->hook_data);
}

static const char *
grub_wim_skip_slashes(const char *path)
{
	while (*path == '/')
		path++;
	return path;
}

/* parse the leading image index of PATH; on success *PATH_OUT points at
   the remainder ("" or "/...") */
static int
grub_wim_parse_image(const char *path, const char **path_out,
	unsigned long *image)
{
	*image = grub_strtoul(path, path_out, 10);
	if (grub_errno)
	{
		grub_errno = GRUB_ERR_NONE;
		goto fail;
	}
	if (**path_out != '\0' && **path_out != '/')
		goto fail;
	return 0;

fail:
	grub_error(GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);
	return -1;
}

static grub_err_t
grub_wim_dir(grub_device_t device, const char *path,
	grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_wim_dir_ctx ctx = { hook, hook_data };
	struct grub_wim_data *data;
	struct grub_fshelp_node root;
	struct grub_fshelp_node *fdiro = NULL;
	struct grub_dirhook_info info;
	unsigned long image;

	data = grub_wim_mount(device->disk);
	if (!data)
		return grub_errno;

	path = grub_wim_skip_slashes(path);
	if (*path == '\0')
	{
		/* virtual root: [1].xml plus one directory per image */
		grub_uint32_t i;
		char name[16];

		grub_memset(&info, 0, sizeof(info));
		info.case_insensitive = 1;
		if (grub_le_to_cpu64(data->header.xml.len) > 0)
		{
			if (hook(WIM_XML_NAME, &info, hook_data))
				goto done;
		}
		info.dir = 1;
		for (i = 1; i <= data->nimages; i++)
		{
			grub_snprintf(name, sizeof(name), "%u", i);
			if (hook(name, &info, hook_data))
				break;
		}
		goto done;
	}

	if (grub_strcasecmp(path, WIM_XML_NAME) == 0)
	{
		/* fs_dir on the XML pseudo-file itself */
		grub_memset(&info, 0, sizeof(info));
		info.case_insensitive = 1;
		hook(WIM_XML_NAME, &info, hook_data);
		goto done;
	}

	if (grub_wim_parse_image(path, &path, &image) != 0
		|| grub_wim_get_root(data, image, &root) != 0)
		goto done;

	if (*grub_wim_skip_slashes(path) == '\0')
		fdiro = &root;
	else
	{
		grub_fshelp_find_file(path, &root, &fdiro,
			grub_wim_iterate_dir, grub_wim_read_symlink,
			GRUB_FSHELP_DIR);
		if (grub_errno)
			goto done;
	}

	grub_wim_iterate_dir(fdiro, grub_wim_dir_iter, &ctx);

done:
	if (fdiro && fdiro != &root)
		grub_free(fdiro);
	grub_free(data);
	return grub_errno;
}

static grub_err_t
grub_wim_open(struct grub_file *file, const char *name)
{
	struct grub_wim_data *data;
	struct grub_fshelp_node root;
	struct grub_fshelp_node *fdiro = NULL;
	unsigned long image;
	const char *path;

	data = grub_wim_mount(file->device->disk);
	if (!data)
		return grub_errno;

	path = grub_wim_skip_slashes(name);
	if (*path == '\0')
	{
		grub_error(GRUB_ERR_BAD_FILE_TYPE, "not a regular file");
		goto fail;
	}

	if (grub_strcasecmp(path, WIM_XML_NAME) == 0)
	{
		fdiro = grub_zalloc(sizeof(*fdiro));
		if (!fdiro)
			goto fail;
		fdiro->data = data;
		fdiro->resource = data->header.xml;
		file->data = fdiro;
		file->size = grub_le_to_cpu64(data->header.xml.len);
		return GRUB_ERR_NONE;
	}

	if (grub_wim_parse_image(path, &path, &image) != 0)
		goto fail;
	if (*path == '\0')
	{
		grub_error(GRUB_ERR_BAD_FILE_TYPE, "not a regular file");
		goto fail;
	}
	if (grub_wim_get_root(data, image, &root) != 0)
		goto fail;

	grub_fshelp_find_file(path, &root, &fdiro, grub_wim_iterate_dir,
		grub_wim_read_symlink, GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	if (grub_wim_hash_empty(fdiro->hash))
	{
		/* zero-length file: no lookup table entry */
		grub_memset(&fdiro->resource, 0, sizeof(fdiro->resource));
		file->size = 0;
	}
	else
	{
		if (grub_wim_find_resource(data, fdiro->hash,
			&fdiro->resource) != 0)
			goto fail;
		file->size = grub_le_to_cpu64(fdiro->resource.len);
	}

	file->data = fdiro;
	return GRUB_ERR_NONE;

fail:
	if (fdiro && fdiro != &root)
		grub_free(fdiro);
	grub_free(data);
	return grub_errno;
}

static grub_ssize_t
grub_wim_read(grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_fshelp_node *node = file->data;

	if (grub_wim_get_resource(node->data, &node->resource, buf,
		file->offset, len) != 0)
		return -1;
	return len;
}

static grub_err_t
grub_wim_close(grub_file_t file)
{
	struct grub_fshelp_node *node = file->data;

	grub_free(node->data);
	grub_free(node);
	return GRUB_ERR_NONE;
}

static grub_err_t
grub_wim_uuid(grub_device_t device, char **uuid)
{
	struct wim_header header;

	*uuid = 0;
	if (grub_disk_read(device->disk, 0, 0, sizeof(header), &header))
		return grub_errno;
	if (grub_memcmp(header.signature, "MSWIM\0\0", 8) != 0)
		return grub_error(GRUB_ERR_BAD_FS, "not a wim filesystem");

	*uuid = grub_xasprintf(
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		grub_le_to_cpu32(header.guid.data1),
		grub_le_to_cpu16(header.guid.data2),
		grub_le_to_cpu16(header.guid.data3),
		header.guid.data4[0], header.guid.data4[1],
		header.guid.data4[2], header.guid.data4[3],
		header.guid.data4[4], header.guid.data4[5],
		header.guid.data4[6], header.guid.data4[7]);
	return grub_errno;
}

static struct grub_fs grub_wim_fs =
{
	.name = "wim",
	.fs_dir = grub_wim_dir,
	.fs_open = grub_wim_open,
	.fs_read = grub_wim_read,
	.fs_close = grub_wim_close,
	.fs_uuid = grub_wim_uuid,
	.next = 0
};

GRUB_MOD_INIT(wim)
{
	grub_wim_fs.mod = mod;
	grub_fs_register(&grub_wim_fs);
}

GRUB_MOD_FINI(wim)
{
	grub_fs_unregister(&grub_wim_fs);
}
