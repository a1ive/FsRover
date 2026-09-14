/* Metadata-only file mapping helpers. GPL-3.0-or-later. */
#ifndef GRUB_FILEMAP_H
#define GRUB_FILEMAP_H
#include <grub/file.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/safemath.h>

/* Content and placement are independent flags. DIRECT means byte-for-byte
 * readable at the reported address layer, not at the ultimate host device. */
#define GRUB_FILE_MAP_DIRECT 1U
#define GRUB_FILE_MAP_ZERO 2U
#define GRUB_FILE_MAP_HOLE 4U
#define GRUB_FILE_MAP_INLINE 8U
#define GRUB_FILE_MAP_COMPRESSED 16U
#define GRUB_FILE_MAP_UNWRITTEN 32U
#define GRUB_FILE_MAP_UNKNOWN 64U
#define GRUB_FILE_MAP_TRANSFORMED 128U
#define GRUB_FILE_MAP_SHARED 256U
#define GRUB_FILE_MAP_VOLUME 0U
#define GRUB_FILE_MAP_FS_LOGICAL 1U

struct grub_file_map_storage
{
	grub_uint64_t offset;
	grub_uint64_t length;
	unsigned int address_space;
};
struct grub_file_map_extent
{
	grub_uint64_t logical_offset;
	grub_uint64_t logical_length;
	/* Offset within the decoded storage object. For DIRECT this is zero;
	 * for encoded objects this survives clipping the queried range. */
	grub_uint64_t decoded_offset;
	grub_uint64_t decoded_length;
	unsigned int flags;
	const char *encoding;
	const struct grub_file_map_storage *storage;
	unsigned int storage_count;
};
/* Optional per-query poll; no reentrant Rover/GRUB calls. */
typedef int (*grub_file_map_cancel_hook) (void *);

/* All borrowed pointers expire when the callback returns. Return 0 to
 * continue, nonzero to stop. No reentrant Rover/GRUB calls are allowed. */
typedef int (*grub_file_map_hook) (const struct grub_file_map_extent *, void *);

/* Driver callbacks return a GRUB error; callback stop is carried separately
 * by the shared context and must be checked at metadata traversal points. */
struct grub_file_map_context
{
	grub_uint64_t start, end, next;
	grub_file_map_hook hook;
	void *data;
	int stopped;
	grub_disk_t disk;
	grub_file_map_cancel_hook cancelled;
	void *cancel_data;
	struct grub_file_map_extent pending;
	struct grub_file_map_storage pending_storage;
};
/* Poll without emitting a record; cancellation is success plus stopped. */
int grub_file_map_cancelled (struct grub_file_map_context *ctx);
grub_err_t grub_file_map_range_ex (grub_file_t file, grub_uint64_t offset,
	grub_uint64_t length, grub_file_map_hook hook, void *data,
	grub_file_map_cancel_hook cancelled, void *cancel_data, int *stopped);
grub_err_t grub_file_map_range (grub_file_t file, grub_uint64_t offset,
	grub_uint64_t length, grub_file_map_hook hook, void *data, int *stopped);
grub_err_t grub_file_map_emit (struct grub_file_map_context *ctx,
	const struct grub_file_map_extent *extent);
grub_err_t grub_file_map_simple (struct grub_file_map_context *ctx,
	grub_uint64_t offset, grub_uint64_t length, unsigned flags,
	grub_uint64_t physical);
#endif
