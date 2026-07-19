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

#ifndef GRUB_REDOXFS_H
#define GRUB_REDOXFS_H

#include <stddef.h>

#include <grub/err.h>
#include <grub/types.h>

/* GRUB_PACKED and PRAGMA_BEGIN/END_PACKED come from <grub/types.h>.  Under
 * MSVC GRUB_PACKED expands to nothing, so the on-disk structs below are held
 * together by the PRAGMA_BEGIN_PACKED / PRAGMA_END_PACKED (pack(1)) wrapper;
 * the _Static_assert size checks at the bottom catch any layout mistake.  */

#define REDOXFS_BLOCK_SIZE 4096
#define REDOXFS_SIGNATURE "RedoxFS"
#define REDOXFS_VERSION 8
#define REDOXFS_RECORD_LEVEL 5
#define REDOXFS_RECORD_SIZE (REDOXFS_BLOCK_SIZE << REDOXFS_RECORD_LEVEL)
#define REDOXFS_DIR_ENTRY_MAX_LENGTH 252
#define REDOXFS_TREE_LIST_ENTRIES 254
#define REDOXFS_BLOCK_LIST_ENTRIES 256
#define REDOXFS_HTREE_IDX_ENTRIES 204

#define REDOXFS_NODE_LEVEL0_COUNT 128
#define REDOXFS_NODE_LEVEL1_COUNT 64
#define REDOXFS_NODE_LEVEL2_COUNT 32
#define REDOXFS_NODE_LEVEL3_COUNT 16
#define REDOXFS_NODE_LEVEL4_COUNT 8

#define REDOXFS_MODE_TYPE 0xF000
#define REDOXFS_MODE_FILE 0x8000
#define REDOXFS_MODE_DIR 0x4000
#define REDOXFS_MODE_SYMLINK 0xA000
#define REDOXFS_FLAG_INLINE_DATA 0x1

PRAGMA_BEGIN_PACKED

struct grub_redoxfs_blockptr {
  grub_uint64_t addr;
  grub_uint64_t hash;
} GRUB_PACKED;

struct grub_redoxfs_treeptr {
  grub_uint32_t id;
} GRUB_PACKED;

struct grub_redoxfs_header {
  grub_uint8_t signature[8];
  grub_uint64_t version;
  grub_uint8_t uuid[16];
  grub_uint64_t size;
  grub_uint64_t generation;
  struct grub_redoxfs_blockptr tree;
  struct grub_redoxfs_blockptr alloc;
  grub_uint8_t key_slots[3072];
  struct grub_redoxfs_blockptr release;
  grub_uint8_t padding[904];
  grub_uint8_t encrypted_hash[16];
  grub_uint64_t hash;
} GRUB_PACKED;

struct grub_redoxfs_node {
  grub_uint16_t mode;
  grub_uint32_t uid;
  grub_uint32_t gid;
  grub_uint32_t links;
  grub_uint64_t size;
  grub_uint64_t blocks;
  grub_uint64_t ctime;
  grub_uint32_t ctime_nsec;
  grub_uint64_t mtime;
  grub_uint32_t mtime_nsec;
  grub_uint64_t atime;
  grub_uint32_t atime_nsec;
  grub_uint32_t record_level;
  grub_uint32_t flags;
  grub_uint8_t padding[54];
  grub_uint8_t level_data[3968];
} GRUB_PACKED;

struct grub_redoxfs_treelist {
  struct grub_redoxfs_blockptr ptrs[REDOXFS_TREE_LIST_ENTRIES];
  grub_uint8_t full_flags[32];
} GRUB_PACKED;

struct grub_redoxfs_htreeptr {
  grub_uint32_t htree_hash;
  struct grub_redoxfs_blockptr ptr;
} GRUB_PACKED;

struct grub_redoxfs_htreenode {
  struct grub_redoxfs_htreeptr ptrs[REDOXFS_HTREE_IDX_ENTRIES];
  grub_uint8_t padding[16];
} GRUB_PACKED;

struct grub_redoxfs_dirlist {
  grub_uint8_t entry_bytes[4092];
  grub_uint16_t count;
  grub_uint16_t entry_bytes_len;
} GRUB_PACKED;

struct grub_redoxfs_blocklist {
  struct grub_redoxfs_blockptr ptrs[REDOXFS_BLOCK_LIST_ENTRIES];
} GRUB_PACKED;

PRAGMA_END_PACKED

struct grub_redoxfs_data {
  struct grub_redoxfs_header header;
  void *disk;
};

struct grub_fshelp_node {
  struct grub_redoxfs_data *data;
  struct grub_redoxfs_node node;
};

static inline grub_uint64_t
grub_redoxfs_blockptr_addr (const struct grub_redoxfs_blockptr *ptr)
{
  return grub_le_to_cpu64 (ptr->addr);
}

static inline grub_uint64_t
grub_redoxfs_blockptr_hash (const struct grub_redoxfs_blockptr *ptr)
{
  return grub_le_to_cpu64 (ptr->hash);
}

static inline int
grub_redoxfs_blockptr_is_null (const struct grub_redoxfs_blockptr *ptr)
{
  return (grub_redoxfs_blockptr_addr (ptr) >> 8) == 0;
}

static inline int
grub_redoxfs_blockptr_is_marker (const struct grub_redoxfs_blockptr *ptr)
{
  return (grub_redoxfs_blockptr_addr (ptr) | 0xFULL) == 0xFFFFFFFFFFFFFFFFULL
    && grub_redoxfs_blockptr_hash (ptr) == 0xFFFFFFFFFFFFFFFFULL;
}

static inline grub_uint64_t
grub_redoxfs_blockptr_block_index (const struct grub_redoxfs_blockptr *ptr)
{
  return grub_redoxfs_blockptr_addr (ptr) >> 8;
}

static inline grub_uint8_t
grub_redoxfs_blockptr_level (const struct grub_redoxfs_blockptr *ptr)
{
  return (grub_uint8_t) (grub_redoxfs_blockptr_addr (ptr) & 0xF);
}

static inline grub_uint8_t
grub_redoxfs_blockptr_decomp_level (const struct grub_redoxfs_blockptr *ptr)
{
  return (grub_uint8_t) ((grub_redoxfs_blockptr_addr (ptr) >> 4) & 0xF);
}

static inline grub_disk_addr_t
grub_redoxfs_blockptr_sector (const struct grub_redoxfs_blockptr *ptr)
{
  return (grub_disk_addr_t) grub_redoxfs_blockptr_block_index (ptr)
    * (REDOXFS_BLOCK_SIZE / 512);
}

static inline grub_uint8_t
grub_redoxfs_treeptr_i3 (const struct grub_redoxfs_treeptr *ptr)
{
  return (grub_uint8_t) ((grub_le_to_cpu32 (ptr->id) >> 24) & 0xFF);
}

static inline grub_uint8_t
grub_redoxfs_treeptr_i2 (const struct grub_redoxfs_treeptr *ptr)
{
  return (grub_uint8_t) ((grub_le_to_cpu32 (ptr->id) >> 16) & 0xFF);
}

static inline grub_uint8_t
grub_redoxfs_treeptr_i1 (const struct grub_redoxfs_treeptr *ptr)
{
  return (grub_uint8_t) ((grub_le_to_cpu32 (ptr->id) >> 8) & 0xFF);
}

static inline grub_uint8_t
grub_redoxfs_treeptr_i0 (const struct grub_redoxfs_treeptr *ptr)
{
  return (grub_uint8_t) (grub_le_to_cpu32 (ptr->id) & 0xFF);
}

static inline int
grub_redoxfs_header_is_encrypted (const struct grub_redoxfs_header *hdr)
{
  grub_uint8_t expected[16] = { 0 };
  grub_uint64_t h = grub_le_to_cpu64 (hdr->hash);
  grub_size_t i;

  for (i = 0; i < 8; i++)
    expected[i] = (grub_uint8_t) (h >> (8 * i));

  for (i = 0; i < 16; i++)
    if (hdr->encrypted_hash[i] != expected[i])
      return 1;

  return 0;
}

grub_uint64_t grub_redoxfs_seahash (const void *data, grub_size_t size);
grub_err_t grub_redoxfs_probe (void *disk);
struct grub_redoxfs_data *grub_redoxfs_mount (void *disk);
void grub_redoxfs_unmount (struct grub_redoxfs_data *data);
grub_err_t grub_redoxfs_read_block (const struct grub_redoxfs_data *data,
                                    const struct grub_redoxfs_blockptr *ptr,
                                    void *buf);
grub_err_t grub_redoxfs_read_block_cap (const struct grub_redoxfs_data *data,
                                        const struct grub_redoxfs_blockptr *ptr,
                                        void *buf, grub_size_t buf_cap);
grub_err_t grub_redoxfs_read_tree (const struct grub_redoxfs_data *data,
                                   const struct grub_redoxfs_treeptr *tptr,
                                   void *buf);
grub_err_t grub_redoxfs_read_node (const struct grub_redoxfs_data *data,
                                   const struct grub_redoxfs_treeptr *tptr,
                                   struct grub_redoxfs_node *node);
grub_err_t grub_redoxfs_read_root (const struct grub_redoxfs_data *data,
                                    struct grub_redoxfs_node *node);

grub_uint32_t grub_redoxfs_htree_hash (const char *name, grub_size_t namelen);
grub_err_t grub_redoxfs_dir_get_info (const struct grub_redoxfs_node *dir,
                                       int *depth_out,
                                       struct grub_redoxfs_blockptr *root_ptr_out);
grub_err_t grub_redoxfs_dir_lookup (const struct grub_redoxfs_data *data,
                                     const struct grub_redoxfs_node *dir,
                                     const char *name,
                                     struct grub_redoxfs_treeptr *result);

typedef int (*grub_redoxfs_dir_iter_hook_t) (const char *name,
                                              grub_size_t namelen,
                                              const struct grub_redoxfs_treeptr *ptr,
                                              void *hook_data);

grub_err_t grub_redoxfs_dir_iterate (const struct grub_redoxfs_data *data,
                                       const struct grub_redoxfs_node *dir,
                                       grub_redoxfs_dir_iter_hook_t hook,
                                       void *hook_data);

grub_err_t path_lookup (const struct grub_redoxfs_data *data,
                         const char *path,
                         int follow_symlinks,
                         int symlink_depth,
                         struct grub_redoxfs_node *out_node);
grub_err_t grub_redoxfs_read_record (const struct grub_redoxfs_data *data,
                                     const struct grub_redoxfs_node *node,
                                     grub_uint64_t record_index,
                                     grub_uint32_t record_level,
                                     void *buf);
grub_ssize_t grub_redoxfs_read_file_data (const struct grub_redoxfs_data *data,
                                          const struct grub_redoxfs_node *node,
                                          grub_off_t offset,
                                          void *buf,
                                          grub_size_t len);

_Static_assert (sizeof (struct grub_redoxfs_blockptr) == 16,
                "grub_redoxfs_blockptr must be 16 bytes");
_Static_assert (sizeof (struct grub_redoxfs_htreeptr) == 20,
                "grub_redoxfs_htreeptr must be 20 bytes");
_Static_assert (sizeof (struct grub_redoxfs_header) == REDOXFS_BLOCK_SIZE,
                "grub_redoxfs_header must be 4096 bytes");
_Static_assert (sizeof (struct grub_redoxfs_node) == REDOXFS_BLOCK_SIZE,
                "grub_redoxfs_node must be 4096 bytes");
_Static_assert (sizeof (struct grub_redoxfs_treelist) == REDOXFS_BLOCK_SIZE,
                "grub_redoxfs_treelist must be 4096 bytes");
_Static_assert (sizeof (struct grub_redoxfs_htreenode) == REDOXFS_BLOCK_SIZE,
                "grub_redoxfs_htreenode must be 4096 bytes");
_Static_assert (sizeof (struct grub_redoxfs_dirlist) == REDOXFS_BLOCK_SIZE,
                 "grub_redoxfs_dirlist must be 4096 bytes");
_Static_assert (sizeof (struct grub_redoxfs_blocklist) == REDOXFS_BLOCK_SIZE,
                 "grub_redoxfs_blocklist must be 4096 bytes");

#endif
