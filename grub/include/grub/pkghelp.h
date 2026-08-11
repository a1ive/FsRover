/* pkghelp.h -- Linux software package helper functions */
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

#ifndef GRUB_PKGHELP_HEADER
#define GRUB_PKGHELP_HEADER	1

#include <grub/types.h>
#include <grub/err.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/fs.h>

/* grub_pkg_entry.stream: a payload index, or one of these */
#define GRUB_PKG_STREAM_RAW	(-1)	/* plain byte range of the disk */
#define GRUB_PKG_STREAM_MEM	(-2)	/* grub_pkg_entry.target is the data */
#define GRUB_PKG_STREAM_SUB	(-3)	/* own compressed byte range of the disk */

/*
 * grub_pkg_entry.codec, for GRUB_PKG_STREAM_SUB entries: which decoder
 * turns the [off, off + plen) byte range into the SIZE bytes of the file.
 * Formats that name their compressor in an index -- as opposed to the deb
 * and rpm payloads, which are recognised by magic -- select it here.
 */
#define GRUB_PKG_CODEC_NONE	0	/* stored; plen must equal size */
#define GRUB_PKG_CODEC_ZLIB	1	/* bare zlib stream, no gzip header */
#define GRUB_PKG_CODEC_BZIP2	2
#define GRUB_PKG_CODEC_XZ	3
#define GRUB_PKG_CODEC_OTHER	4	/* named, but not built into grub.lib */

#define GRUB_PKG_MAX_STREAMS	8
#define GRUB_PKG_MAX_SIZE	((grub_off_t) 1 << 48)

/* one compressed payload of the package */
struct grub_pkg_stream
{
	grub_off_t off;		/* start of the compressed data on the disk */
	grub_off_t len;
};

/* one file of the package, named by its full path from the root */
struct grub_pkg_entry
{
	char *name;
	char *target;		/* link target, NULL when not a link */
	grub_off_t off;		/* data offset within STREAM */
	grub_off_t plen;	/* compressed length, GRUB_PKG_STREAM_SUB only */
	grub_off_t size;
	grub_int64_t mtime;
	int stream;
	int codec;		/* GRUB_PKG_CODEC_*, GRUB_PKG_STREAM_SUB only */
	unsigned is_dir:1;
	unsigned is_lnk:1;
};

struct grub_pkg_data
{
	grub_disk_t disk;
	grub_uint64_t disk_size;
	struct grub_pkg_entry *entries;
	unsigned num_entries;
	unsigned max_entries;
	struct grub_pkg_stream streams[GRUB_PKG_MAX_STREAMS];
	unsigned num_streams;
	grub_int64_t mtime;
	char *label;
};

struct grub_pkg_ops
{
	/* short name of the format, used in "not a <name> archive" errors */
	const char *name;

	/*
	 * Recognises the container on DATA->disk and fills in DATA's entry
	 * list, payload streams, mtime and label.  Must fail with
	 * GRUB_ERR_BAD_FS when the disk holds some other format, otherwise
	 * grub_fs_probe() gives up instead of trying the next filesystem.
	 */
	grub_err_t (*parse) (struct grub_pkg_data *data);
};

/* grub_fs hooks; forward the driver's own hooks to these */
grub_err_t
grub_pkg_dir (grub_device_t device, struct grub_pkg_ops *ops,
	      const char *path, grub_fs_dir_hook_t hook, void *hook_data);

grub_err_t
grub_pkg_open (grub_file_t file, struct grub_pkg_ops *ops, const char *name);

/* these two need no ops, assign them to fs_read / fs_close directly */
grub_ssize_t
grub_pkg_read (grub_file_t file, char *buf, grub_size_t len);

grub_err_t
grub_pkg_close (grub_file_t file);

grub_err_t
grub_pkg_label (grub_device_t device, struct grub_pkg_ops *ops, char **label);

grub_err_t
grub_pkg_mtime (grub_device_t device, struct grub_pkg_ops *ops,
		grub_int64_t *tm);

/*
 * Walking a payload means decompressing it, which is far too expensive to
 * redo for every grub_file_open() the GUI makes while sizing a directory
 * listing, so a parsed entry list is kept in a one slot cache.  Drivers
 * drop their own cached list from GRUB_MOD_FINI.
 */
void
grub_pkg_cache_release (struct grub_pkg_ops *ops);

/* Building the entry list, for use from the parse callback */

/*
 * Builds "PREFIX/RAW" with the empty and "." path components of RAW
 * dropped.  *OUT is left NULL when nothing is left of the name, which is
 * how the "./" root entry of a tar or cpio payload gets skipped.
 */
grub_err_t
grub_pkg_norm_name (const char *prefix, const char *raw, char **out);

/* appends a zeroed entry owning NAME; NULL on failure (NAME is freed) */
struct grub_pkg_entry *
grub_pkg_new_entry (struct grub_pkg_data *data, char *name);

/* drops the entries added after the list held NUM of them */
void
grub_pkg_truncate_entries (struct grub_pkg_data *data, unsigned num);

/* returns the index of the entry named NAME, -1 when there is none */
int
grub_pkg_find_entry (struct grub_pkg_data *data, const char *name);

/* registers a compressed payload, returning its index or -1 when full */
int
grub_pkg_add_stream (struct grub_pkg_data *data, grub_off_t off,
		     grub_off_t len);

/* forgets the payload registered last */
void
grub_pkg_drop_stream (struct grub_pkg_data *data);

/*
 * Opens a payload as a decompressed file: the byte range goes through
 * grub_file_offset_open(), which runs the gzip / xz / lzop / lz4 / zstd io
 * filters over it, so every compressor with a filter built into grub.lib
 * is decoded transparently and anything else is seen verbatim.  Close the
 * result with grub_file_close().  GRUB_PKG_STREAM_SUB entries do not come
 * through here: their decoder is named by the index, not probed for.
 */
grub_file_t
grub_pkg_stream_open (struct grub_pkg_data *data, int stream);

/*
 * Record every member of the tar / cpio payload in STREAM under PREFIX.
 * Both fail with GRUB_ERR_BAD_FS when the payload does not decode as the
 * expected archive, which is how a driver learns that the payload has to
 * be exposed verbatim instead.  The cpio scanner understands the
 * "new ASCII" (070701/070702) and "portable ASCII" (070707) headers.
 */
grub_err_t
grub_pkg_scan_tar (struct grub_pkg_data *data, int stream, const char *prefix);

grub_err_t
grub_pkg_scan_cpio (struct grub_pkg_data *data, int stream, const char *prefix);

#endif /* ! GRUB_PKGHELP_HEADER */
