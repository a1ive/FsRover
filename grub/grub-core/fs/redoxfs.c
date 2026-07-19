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

#include <grub/redoxfs.h>

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/device.h>
#include <grub/fs.h>

#include <lz4.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define redoxfs_malloc grub_malloc
#define redoxfs_free grub_free

#define REDOXFS_MAX_SYMLINK_DEPTH 8
#define REDOXFS_MAX_PATH_LEN 1024
#define REDOXFS_MAX_HTREE_DEPTH 4
#define REDOXFS_HEADER_RING 256

/* Seahash v4 -- used for the header/block checksums and the H-tree name hash. */
static inline grub_uint64_t
seahash_diffuse (grub_uint64_t x)
{
  grub_uint64_t a;
  grub_uint64_t b;

  x *= 0x6eed0e9da4d94a4fULL;
  a = x >> 32;
  b = x >> 60;
  x ^= a >> b;
  x *= 0x6eed0e9da4d94a4fULL;
  return x;
}

static inline grub_uint64_t
seahash_read_le64 (const grub_uint8_t *buf, grub_size_t len)
{
  grub_uint64_t x = 0;
  grub_size_t i;

  for (i = 0; i < len; i++)
    x |= (grub_uint64_t) buf[i] << (8 * i);

  return x;
}

grub_uint64_t
grub_redoxfs_seahash (const void *data, grub_size_t size)
{
  const grub_uint8_t *buf = (const grub_uint8_t *) data;
  grub_uint64_t a = 0x16f11fe89b0d677cULL;
  grub_uint64_t b = 0xb480a793d8e6c86cULL;
  grub_uint64_t c = 0x6fe2e5aaf078ebc9ULL;
  grub_uint64_t d = 0x14f994a4c5259381ULL;
  grub_size_t i = 0;

  for (; i + 8 <= size; i += 8)
    {
      grub_uint64_t n = seahash_read_le64 (buf + i, 8);
      grub_uint64_t new_a = seahash_diffuse (a ^ n);

      a = b;
      b = c;
      c = d;
      d = new_a;
    }

  if (i < size)
    {
      grub_uint64_t n = seahash_read_le64 (buf + i, size - i);
      grub_uint64_t new_a = seahash_diffuse (a ^ n);

      a = b;
      b = c;
      c = d;
      d = new_a;
    }

  return seahash_diffuse (a ^ b ^ c ^ d ^ (grub_uint64_t) size);
}

struct grub_redoxfs_data *
grub_redoxfs_mount (void *disk)
{
  struct grub_redoxfs_header hdr;
  struct grub_redoxfs_header ring_hdr;
  grub_err_t err;
  struct grub_redoxfs_data *data;
  grub_uint64_t best_generation;
  int i;

  err = grub_disk_read (disk, 0, 0, REDOXFS_BLOCK_SIZE, &hdr);
  if (err != GRUB_ERR_NONE)
    return NULL;

  if (grub_memcmp (hdr.signature, REDOXFS_SIGNATURE "\0", 8) != 0)
    {
      grub_error (GRUB_ERR_BAD_FS, "not a redoxfs filesystem");
      return NULL;
    }

  if (grub_le_to_cpu64 (hdr.version) != REDOXFS_VERSION)
    {
      grub_error (GRUB_ERR_BAD_FS, "unsupported redoxfs version %d",
          (int) grub_le_to_cpu64 (hdr.version));
      return NULL;
    }

  if (grub_redoxfs_seahash (&hdr,
                offsetof (struct grub_redoxfs_header,
                      encrypted_hash)) != grub_le_to_cpu64 (hdr.hash))
    {
      grub_error (GRUB_ERR_BAD_FS, "redoxfs header checksum mismatch");
      return NULL;
    }

  if (grub_redoxfs_header_is_encrypted (&hdr))
    {
      grub_error (GRUB_ERR_BAD_FS,
          "encrypted redoxfs volumes not supported");
      return NULL;
    }

  /* Scan the header ring for the newest generation.
   *
   * RedoxFS maintains a ring of REDOXFS_HEADER_RING header copies.
   * Each transaction writes the header to slot (generation % HEADER_RING).
   * The header with the highest generation number is the current one.
   * Using a stale header causes block hash mismatches because the
   * tree/alloc/release pointers reference blocks that may have been
   * overwritten by newer transactions. */
  best_generation = grub_le_to_cpu64 (hdr.generation);

  for (i = 1; i < REDOXFS_HEADER_RING; i++)
    {
      grub_disk_addr_t sector;

      sector = (grub_disk_addr_t) i * (REDOXFS_BLOCK_SIZE / 512);

      grub_errno = GRUB_ERR_NONE;
      err = grub_disk_read (disk, sector, 0, REDOXFS_BLOCK_SIZE, &ring_hdr);
      if (err != GRUB_ERR_NONE)
    continue;

      if (grub_memcmp (ring_hdr.signature, REDOXFS_SIGNATURE "\0", 8) != 0)
    continue;
      if (grub_le_to_cpu64 (ring_hdr.version) != REDOXFS_VERSION)
    continue;

      if (grub_redoxfs_seahash (&ring_hdr,
                offsetof (struct grub_redoxfs_header,
                      encrypted_hash)) != grub_le_to_cpu64 (ring_hdr.hash))
    continue;

      if (grub_le_to_cpu64 (ring_hdr.generation) > best_generation)
    {
      if (grub_redoxfs_header_is_encrypted (&ring_hdr))
        continue;
      hdr = ring_hdr;
      best_generation = grub_le_to_cpu64 (ring_hdr.generation);
    }
    }

  grub_errno = GRUB_ERR_NONE;
  data = redoxfs_malloc (sizeof (*data));
  if (!data)
    return NULL;

  data->header = hdr;
  data->disk = disk;
  return data;
}

void
grub_redoxfs_unmount (struct grub_redoxfs_data *data)
{
  redoxfs_free (data);
}

grub_err_t
grub_redoxfs_read_block_cap (const struct grub_redoxfs_data *data,
                  const struct grub_redoxfs_blockptr *ptr,
                  void *buf, grub_size_t buf_cap)
{
  grub_disk_addr_t sector;
  grub_size_t block_count;
  grub_size_t total_size;
  grub_err_t err;

  if (grub_redoxfs_blockptr_is_null (ptr))
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs null block pointer");

  sector = grub_redoxfs_blockptr_sector (ptr);
  block_count = 1U << grub_redoxfs_blockptr_level (ptr);
  total_size = REDOXFS_BLOCK_SIZE * block_count;

  if (total_size > buf_cap)
    return grub_error (GRUB_ERR_BAD_FS,
               "redoxfs compressed block overflows buffer");

  err = grub_disk_read (data->disk, sector, 0, total_size, buf);
  if (err != GRUB_ERR_NONE)
    return err;

  if (grub_redoxfs_seahash (buf, total_size) != grub_redoxfs_blockptr_hash (ptr))
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs block checksum mismatch");

  {
    grub_uint8_t decomp_level = grub_redoxfs_blockptr_decomp_level (ptr);

    if (decomp_level != 0)
      {
    grub_size_t decomp_size;
    grub_uint16_t comp_total;
    grub_uint8_t *temp;

    decomp_size = (grub_size_t) REDOXFS_BLOCK_SIZE << decomp_level;
    grub_memcpy (&comp_total, buf, 2);
    comp_total = grub_le_to_cpu16 (comp_total);

    if (comp_total < 2 || (grub_size_t) comp_total + 2 > total_size)
      return grub_error (GRUB_ERR_BAD_FS,
                 "redoxfs invalid compressed block header");

    if (decomp_size > buf_cap)
      return grub_error (GRUB_ERR_BAD_FS,
                 "redoxfs decompressed block overflows buffer");

    temp = redoxfs_malloc (decomp_size);
    if (!temp)
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                 "redoxfs out of memory");

    if (LZ4_decompress_safe ((const char *) buf + 2, (char *) temp,
                  (int) comp_total, (int) decomp_size)
        != (int) decomp_size)
      {
        redoxfs_free (temp);
        return grub_error (GRUB_ERR_BAD_FS,
                   "redoxfs block decompression failed");
      }

    grub_memcpy (buf, temp, decomp_size);
    redoxfs_free (temp);
      }
  }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_redoxfs_read_block (const struct grub_redoxfs_data *data,
              const struct grub_redoxfs_blockptr *ptr,
              void *buf)
{
  return grub_redoxfs_read_block_cap (data, ptr, buf, REDOXFS_BLOCK_SIZE);
}

grub_err_t
grub_redoxfs_read_tree (const struct grub_redoxfs_data *data,
             const struct grub_redoxfs_treeptr *tptr,
             void *buf)
{
  grub_uint8_t indices[4];
  struct grub_redoxfs_treelist tl;
  struct grub_redoxfs_blockptr saved;
  const struct grub_redoxfs_blockptr *next_ptr;
  grub_err_t err;
  int level;

  indices[0] = grub_redoxfs_treeptr_i3 (tptr);
  indices[1] = grub_redoxfs_treeptr_i2 (tptr);
  indices[2] = grub_redoxfs_treeptr_i1 (tptr);
  indices[3] = grub_redoxfs_treeptr_i0 (tptr);

  next_ptr = &data->header.tree;

  for (level = 0; level < 4; level++)
    {
      grub_uint8_t idx = indices[level];

      err = grub_redoxfs_read_block (data, next_ptr, &tl);
      if (err != GRUB_ERR_NONE)
    return err;
      if (idx >= REDOXFS_TREE_LIST_ENTRIES
      || grub_redoxfs_blockptr_is_null (&tl.ptrs[idx]))
    return grub_error (GRUB_ERR_BAD_FS,
               "redoxfs tree index out of range");

      saved = tl.ptrs[idx];
      next_ptr = &saved;
    }

  return grub_redoxfs_read_block (data, next_ptr, buf);
}

grub_err_t
grub_redoxfs_read_node (const struct grub_redoxfs_data *data,
                        const struct grub_redoxfs_treeptr *tptr,
                        struct grub_redoxfs_node *node)
{
  return grub_redoxfs_read_tree (data, tptr, node);
}

grub_err_t
grub_redoxfs_read_root (const struct grub_redoxfs_data *data,
                         struct grub_redoxfs_node *node)
{
  struct grub_redoxfs_treeptr root_ptr;

  root_ptr.id = 1;
  return grub_redoxfs_read_node (data, &root_ptr, node);
}

#define redoxfs_strlen grub_strlen

grub_uint32_t
grub_redoxfs_htree_hash (const char *name, grub_size_t namelen)
{
  grub_uint64_t h;
  grub_uint32_t hash;

  h = grub_redoxfs_seahash (name, namelen);
  hash = (grub_uint32_t) h;
  if (hash == 0xFFFFFFFFU)
    hash = 0xFFFFFFFEU;
  return hash;
}

grub_err_t
grub_redoxfs_dir_get_info (const struct grub_redoxfs_node *dir,
                            int *depth_out,
                            struct grub_redoxfs_blockptr *root_ptr_out)
{
  const struct grub_redoxfs_blockptr *level0;

  if ((grub_le_to_cpu16 (dir->mode) & REDOXFS_MODE_TYPE) != REDOXFS_MODE_DIR)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  level0 = (const struct grub_redoxfs_blockptr *) dir->level_data;

  if (!grub_redoxfs_blockptr_is_marker (&level0[0]))
    {
      *depth_out = -1;
      grub_memset (root_ptr_out, 0, sizeof (*root_ptr_out));
      return GRUB_ERR_NONE;
    }

  *depth_out = (int) grub_redoxfs_blockptr_level (&level0[0]);
  *root_ptr_out = level0[1];
  return GRUB_ERR_NONE;
}

static grub_err_t
search_dirlist (const struct grub_redoxfs_dirlist *dl,
                const char *name,
                struct grub_redoxfs_treeptr *result)
{
  grub_uint16_t count = grub_le_to_cpu16 (dl->count);
  grub_uint16_t entry_bytes_len = grub_le_to_cpu16 (dl->entry_bytes_len);
  grub_size_t pos = 0;
  grub_size_t namelen = redoxfs_strlen (name);
  int i;

  if (entry_bytes_len > sizeof (dl->entry_bytes)
      || (grub_size_t) count * 6 > entry_bytes_len)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  for (i = 0; i < count; i++)
    {
      grub_uint8_t entry_name_len;
      struct grub_redoxfs_treeptr entry_ptr;

      if (pos + 5 > entry_bytes_len)
        return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

      grub_memcpy (&entry_ptr, &dl->entry_bytes[pos], 4);
      entry_name_len = dl->entry_bytes[pos + 4];

      if (entry_name_len < 1 || entry_name_len > REDOXFS_DIR_ENTRY_MAX_LENGTH)
        return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

      if (pos + 5 + entry_name_len > entry_bytes_len)
        return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

      if (entry_name_len == namelen
          && grub_memcmp (&dl->entry_bytes[pos + 5], name, namelen) == 0)
        {
          *result = entry_ptr;
          return GRUB_ERR_NONE;
        }

      pos += 5 + entry_name_len;
    }

  if (pos != entry_bytes_len)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  return GRUB_ERR_FILE_NOT_FOUND;
}

static int
find_ptrs_for_read (const struct grub_redoxfs_htreenode *node,
                    grub_uint32_t target_hash,
                    struct grub_redoxfs_blockptr *out_ptrs)
{
  int count = 0;
  grub_uint32_t last_hash = 0;
  int i;

  for (i = 0; i < REDOXFS_HTREE_IDX_ENTRIES; i++)
    {
      grub_uint32_t entry_hash;

      if (grub_redoxfs_blockptr_is_null (&node->ptrs[i].ptr))
        break;

      entry_hash = grub_le_to_cpu32 (node->ptrs[i].htree_hash);

      if (entry_hash < target_hash)
        continue;

      if (last_hash > target_hash)
        break;

      out_ptrs[count++] = node->ptrs[i].ptr;
      last_hash = entry_hash;
    }

  return count;
}

static grub_err_t
dir_lookup_inner (const struct grub_redoxfs_data *data,
                  const struct grub_redoxfs_blockptr *candidates,
                  int n_candidates,
                  const char *name,
                  grub_uint32_t name_hash,
                  int depth,
                  struct grub_redoxfs_treeptr *result)
{
  int i;

  for (i = 0; i < n_candidates; i++)
    {
      grub_err_t err;

      if (depth == 1)
        {
          struct grub_redoxfs_dirlist dl;

          err = grub_redoxfs_read_block (data, &candidates[i], &dl);
          if (err != GRUB_ERR_NONE)
            return err;

          err = search_dirlist (&dl, name, result);
          if (err == GRUB_ERR_NONE)
            return GRUB_ERR_NONE;
          if (err != GRUB_ERR_FILE_NOT_FOUND)
            return err;
        }
      else
        {
          struct grub_redoxfs_htreenode child;
          struct grub_redoxfs_blockptr child_cands[REDOXFS_HTREE_IDX_ENTRIES];
          int n_child;

          err = grub_redoxfs_read_block (data, &candidates[i], &child);
          if (err != GRUB_ERR_NONE)
            return err;

          n_child = find_ptrs_for_read (&child, name_hash, child_cands);
          if (n_child > 0)
            {
              err = dir_lookup_inner (data, child_cands, n_child,
                                       name, name_hash, depth - 1, result);
              if (err == GRUB_ERR_NONE)
                return GRUB_ERR_NONE;
              if (err != GRUB_ERR_FILE_NOT_FOUND)
                return err;
            }
        }
    }

  return GRUB_ERR_FILE_NOT_FOUND;
}

grub_err_t
grub_redoxfs_dir_lookup (const struct grub_redoxfs_data *data,
                          const struct grub_redoxfs_node *dir,
                          const char *name,
                          struct grub_redoxfs_treeptr *result)
{
  const struct grub_redoxfs_blockptr *level0;
  int depth;
  struct grub_redoxfs_blockptr root_ptr;
  grub_uint32_t name_hash;

  if ((grub_le_to_cpu16 (dir->mode) & REDOXFS_MODE_TYPE) != REDOXFS_MODE_DIR)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  level0 = (const struct grub_redoxfs_blockptr *) dir->level_data;

  if (!grub_redoxfs_blockptr_is_marker (&level0[0]))
    return GRUB_ERR_FILE_NOT_FOUND;

  depth = (int) grub_redoxfs_blockptr_level (&level0[0]);
  if (depth > REDOXFS_MAX_HTREE_DEPTH)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
  root_ptr = level0[1];

  if (grub_redoxfs_blockptr_is_null (&root_ptr))
    return GRUB_ERR_FILE_NOT_FOUND;

  name_hash = grub_redoxfs_htree_hash (name, redoxfs_strlen (name));

  if (depth == 0)
    {
      return dir_lookup_inner (data, &root_ptr, 1,
                name, name_hash, 1, result);
    }

  {
    struct grub_redoxfs_htreenode root_node;
    struct grub_redoxfs_blockptr candidates[REDOXFS_HTREE_IDX_ENTRIES];
    int n_candidates;
    grub_err_t err;

    err = grub_redoxfs_read_block (data, &root_ptr, &root_node);
    if (err != GRUB_ERR_NONE)
      return err;

    n_candidates = find_ptrs_for_read (&root_node, name_hash, candidates);
    if (n_candidates == 0)
      return GRUB_ERR_FILE_NOT_FOUND;

    return dir_lookup_inner (data, candidates, n_candidates,
                  name, name_hash, depth, result);
  }
}

static grub_err_t
dir_iterate_inner (const struct grub_redoxfs_data *data,
                   const struct grub_redoxfs_blockptr *candidates,
                   int n_candidates,
                   int depth,
                   grub_redoxfs_dir_iter_hook_t hook,
                   void *hook_data,
                   int *stop)
{
  int i;

  for (i = 0; i < n_candidates; i++)
    {
      grub_err_t err;

      if (*stop)
        return GRUB_ERR_NONE;

      if (depth == 1)
        {
          struct grub_redoxfs_dirlist dl;
          grub_uint16_t count;
          grub_uint16_t entry_bytes_len;
          grub_size_t pos;
          int j;

          err = grub_redoxfs_read_block (data, &candidates[i], &dl);
          if (err != GRUB_ERR_NONE)
            return err;

          count = grub_le_to_cpu16 (dl.count);
          entry_bytes_len = grub_le_to_cpu16 (dl.entry_bytes_len);
          pos = 0;
          if (entry_bytes_len > sizeof (dl.entry_bytes)
              || (grub_size_t) count * 6 > entry_bytes_len)
            return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

          for (j = 0; j < count; j++)
            {
              grub_uint8_t name_len;
              struct grub_redoxfs_treeptr entry_ptr;

              if (pos + 5 > entry_bytes_len)
                return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

              grub_memcpy (&entry_ptr, &dl.entry_bytes[pos], 4);
              name_len = dl.entry_bytes[pos + 4];

              if (name_len < 1 || name_len > REDOXFS_DIR_ENTRY_MAX_LENGTH)
                return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

              if (pos + 5 + name_len > entry_bytes_len)
                return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

              if (hook ((const char *) &dl.entry_bytes[pos + 5],
                        name_len, &entry_ptr, hook_data) != 0)
                {
                  *stop = 1;
                  return GRUB_ERR_NONE;
                }

              pos += 5 + name_len;
            }

          if (pos != entry_bytes_len)
            return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
        }
      else
        {
          struct grub_redoxfs_htreenode child;
          int j;

          err = grub_redoxfs_read_block (data, &candidates[i], &child);
          if (err != GRUB_ERR_NONE)
            return err;

          for (j = 0; j < REDOXFS_HTREE_IDX_ENTRIES; j++)
            {
              if (grub_redoxfs_blockptr_is_null (&child.ptrs[j].ptr))
                break;

              err = dir_iterate_inner (data, &child.ptrs[j].ptr, 1,
                                        depth - 1, hook, hook_data, stop);
              if (err != GRUB_ERR_NONE)
                return err;
              if (*stop)
                return GRUB_ERR_NONE;
            }
        }
    }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_redoxfs_dir_iterate (const struct grub_redoxfs_data *data,
                           const struct grub_redoxfs_node *dir,
                           grub_redoxfs_dir_iter_hook_t hook,
                           void *hook_data)
{
  const struct grub_redoxfs_blockptr *level0;
  int depth;
  struct grub_redoxfs_blockptr root_ptr;
  grub_err_t err;
  int stop = 0;

  if ((grub_le_to_cpu16 (dir->mode) & REDOXFS_MODE_TYPE) != REDOXFS_MODE_DIR)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  level0 = (const struct grub_redoxfs_blockptr *) dir->level_data;

  if (!grub_redoxfs_blockptr_is_marker (&level0[0]))
    return GRUB_ERR_NONE;

  depth = (int) grub_redoxfs_blockptr_level (&level0[0]);
  if (depth > REDOXFS_MAX_HTREE_DEPTH)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
  root_ptr = level0[1];

  if (grub_redoxfs_blockptr_is_null (&root_ptr))
    return GRUB_ERR_NONE;

  if (depth == 0)
    {
      return dir_iterate_inner (data, &root_ptr, 1, 1, hook, hook_data,
                                &stop);
    }

  {
    struct grub_redoxfs_htreenode root_node;
    struct grub_redoxfs_blockptr root_candidates[REDOXFS_HTREE_IDX_ENTRIES];
    int n_entries;
    int j;

    err = grub_redoxfs_read_block (data, &root_ptr, &root_node);
    if (err != GRUB_ERR_NONE)
      return err;

    n_entries = 0;
    for (j = 0; j < REDOXFS_HTREE_IDX_ENTRIES; j++)
      {
        if (grub_redoxfs_blockptr_is_null (&root_node.ptrs[j].ptr))
          break;
        root_candidates[n_entries++] = root_node.ptrs[j].ptr;
      }

  return dir_iterate_inner (data, root_candidates, n_entries,
                  depth, hook, hook_data, &stop);
  }
}

static const struct grub_redoxfs_blockptr *
node_level0_ptr (const struct grub_redoxfs_node *node)
{
  return (const struct grub_redoxfs_blockptr *) node->level_data;
}

static const struct grub_redoxfs_blockptr *
node_level1_ptrs (const struct grub_redoxfs_node *node)
{
  return (const struct grub_redoxfs_blockptr *) node->level_data
    + REDOXFS_NODE_LEVEL0_COUNT;
}

static const struct grub_redoxfs_blockptr *
node_level2_ptrs (const struct grub_redoxfs_node *node)
{
  return (const struct grub_redoxfs_blockptr *) node->level_data
    + REDOXFS_NODE_LEVEL0_COUNT + REDOXFS_NODE_LEVEL1_COUNT;
}

static const struct grub_redoxfs_blockptr *
node_level3_ptrs (const struct grub_redoxfs_node *node)
{
  return (const struct grub_redoxfs_blockptr *) node->level_data
    + REDOXFS_NODE_LEVEL0_COUNT + REDOXFS_NODE_LEVEL1_COUNT
    + REDOXFS_NODE_LEVEL2_COUNT;
}

static const struct grub_redoxfs_blockptr *
node_level4_ptrs (const struct grub_redoxfs_node *node)
{
  return (const struct grub_redoxfs_blockptr *) node->level_data
    + REDOXFS_NODE_LEVEL0_COUNT + REDOXFS_NODE_LEVEL1_COUNT
    + REDOXFS_NODE_LEVEL2_COUNT + REDOXFS_NODE_LEVEL3_COUNT;
}

grub_err_t
grub_redoxfs_read_record (const struct grub_redoxfs_data *data,
               const struct grub_redoxfs_node *node,
               grub_uint64_t record_index,
               grub_uint32_t record_level,
               void *buf)
{
  grub_size_t record_size;
  grub_err_t err;

  if (record_level > REDOXFS_RECORD_LEVEL)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  record_size = (grub_size_t) REDOXFS_BLOCK_SIZE << record_level;
  grub_memset (buf, 0, record_size);

  /* Level 0: direct pointer from node */
  if (record_index < REDOXFS_NODE_LEVEL0_COUNT)
    {
      const struct grub_redoxfs_blockptr *ptr;

      ptr = &node_level0_ptr (node)[record_index];
      if (grub_redoxfs_blockptr_is_null (ptr))
    return GRUB_ERR_NONE;

      return grub_redoxfs_read_block_cap (data, ptr, buf, record_size);
    }

  record_index -= REDOXFS_NODE_LEVEL0_COUNT;

  /* Level 1: single indirection (node -> BlockList -> data) */
  if (record_index < (grub_uint64_t) REDOXFS_NODE_LEVEL1_COUNT * REDOXFS_BLOCK_LIST_ENTRIES)
    {
      grub_uint64_t i1 = record_index / REDOXFS_BLOCK_LIST_ENTRIES;
      grub_uint64_t i0 = record_index % REDOXFS_BLOCK_LIST_ENTRIES;
      struct grub_redoxfs_blocklist bl;
      const struct grub_redoxfs_blockptr *l1_ptr;

      l1_ptr = &node_level1_ptrs (node)[i1];
      if (grub_redoxfs_blockptr_is_null (l1_ptr))
    return GRUB_ERR_NONE;

      err = grub_redoxfs_read_block (data, l1_ptr, &bl);
      if (err != GRUB_ERR_NONE)
    return err;

      if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i0]))
    return GRUB_ERR_NONE;

      return grub_redoxfs_read_block_cap (data, &bl.ptrs[i0], buf,
                       record_size);
    }

  record_index -= (grub_uint64_t) REDOXFS_NODE_LEVEL1_COUNT * REDOXFS_BLOCK_LIST_ENTRIES;

  /* Level 2: double indirection (node -> BL -> BL -> data) */
  if (record_index < (grub_uint64_t) REDOXFS_NODE_LEVEL2_COUNT
      * REDOXFS_BLOCK_LIST_ENTRIES * REDOXFS_BLOCK_LIST_ENTRIES)
    {
      grub_uint64_t i2 = record_index / ((grub_uint64_t) REDOXFS_BLOCK_LIST_ENTRIES
                      * REDOXFS_BLOCK_LIST_ENTRIES);
      grub_uint64_t rem = record_index % ((grub_uint64_t) REDOXFS_BLOCK_LIST_ENTRIES
                       * REDOXFS_BLOCK_LIST_ENTRIES);
      grub_uint64_t i1 = rem / REDOXFS_BLOCK_LIST_ENTRIES;
      grub_uint64_t i0 = rem % REDOXFS_BLOCK_LIST_ENTRIES;
      struct grub_redoxfs_blocklist bl;
      struct grub_redoxfs_blockptr saved;
      const struct grub_redoxfs_blockptr *l2_ptr;

      l2_ptr = &node_level2_ptrs (node)[i2];
      if (grub_redoxfs_blockptr_is_null (l2_ptr))
    return GRUB_ERR_NONE;

      err = grub_redoxfs_read_block (data, l2_ptr, &bl);
      if (err != GRUB_ERR_NONE)
    return err;

      if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i1]))
    return GRUB_ERR_NONE;

      saved = bl.ptrs[i1];
      err = grub_redoxfs_read_block (data, &saved, &bl);
      if (err != GRUB_ERR_NONE)
    return err;

      if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i0]))
    return GRUB_ERR_NONE;

      return grub_redoxfs_read_block_cap (data, &bl.ptrs[i0], buf,
                       record_size);
    }

  record_index -= (grub_uint64_t) REDOXFS_NODE_LEVEL2_COUNT
    * REDOXFS_BLOCK_LIST_ENTRIES * REDOXFS_BLOCK_LIST_ENTRIES;

  /* Level 3: triple indirection (node -> BL -> BL -> BL -> data) */
  if (record_index < (grub_uint64_t) REDOXFS_NODE_LEVEL3_COUNT
      * REDOXFS_BLOCK_LIST_ENTRIES * REDOXFS_BLOCK_LIST_ENTRIES
      * REDOXFS_BLOCK_LIST_ENTRIES)
    {
      grub_uint64_t stride2 = (grub_uint64_t) REDOXFS_BLOCK_LIST_ENTRIES
    * REDOXFS_BLOCK_LIST_ENTRIES;
      grub_uint64_t i3 = record_index / (stride2 * REDOXFS_BLOCK_LIST_ENTRIES);
      grub_uint64_t rem = record_index % (stride2 * REDOXFS_BLOCK_LIST_ENTRIES);
      grub_uint64_t i2 = rem / stride2;
      rem = rem % stride2;
      grub_uint64_t i1 = rem / REDOXFS_BLOCK_LIST_ENTRIES;
      grub_uint64_t i0 = rem % REDOXFS_BLOCK_LIST_ENTRIES;
      struct grub_redoxfs_blocklist bl;
      struct grub_redoxfs_blockptr saved;
      const struct grub_redoxfs_blockptr *l3_ptr;

      l3_ptr = &node_level3_ptrs (node)[i3];
      if (grub_redoxfs_blockptr_is_null (l3_ptr))
    return GRUB_ERR_NONE;

      err = grub_redoxfs_read_block (data, l3_ptr, &bl);
      if (err != GRUB_ERR_NONE)
    return err;

      if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i2]))
    return GRUB_ERR_NONE;

      saved = bl.ptrs[i2];
      err = grub_redoxfs_read_block (data, &saved, &bl);
      if (err != GRUB_ERR_NONE)
    return err;

      if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i1]))
    return GRUB_ERR_NONE;

      saved = bl.ptrs[i1];
      err = grub_redoxfs_read_block (data, &saved, &bl);
      if (err != GRUB_ERR_NONE)
    return err;

      if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i0]))
    return GRUB_ERR_NONE;

      return grub_redoxfs_read_block_cap (data, &bl.ptrs[i0], buf,
                       record_size);
    }

  record_index -= (grub_uint64_t) REDOXFS_NODE_LEVEL3_COUNT
    * REDOXFS_BLOCK_LIST_ENTRIES * REDOXFS_BLOCK_LIST_ENTRIES
    * REDOXFS_BLOCK_LIST_ENTRIES;

  /* Level 4: quad indirection (node -> BL -> BL -> BL -> BL -> data) */
  {
    grub_uint64_t stride3 = (grub_uint64_t) REDOXFS_BLOCK_LIST_ENTRIES
      * REDOXFS_BLOCK_LIST_ENTRIES * REDOXFS_BLOCK_LIST_ENTRIES;
    grub_uint64_t stride2 = (grub_uint64_t) REDOXFS_BLOCK_LIST_ENTRIES
      * REDOXFS_BLOCK_LIST_ENTRIES;
    grub_uint64_t i4 = record_index / (stride3 * REDOXFS_BLOCK_LIST_ENTRIES);
    grub_uint64_t rem = record_index % (stride3 * REDOXFS_BLOCK_LIST_ENTRIES);
    grub_uint64_t i3 = rem / stride3;
    rem = rem % stride3;
    grub_uint64_t i2 = rem / stride2;
    rem = rem % stride2;
    grub_uint64_t i1 = rem / REDOXFS_BLOCK_LIST_ENTRIES;
    grub_uint64_t i0 = rem % REDOXFS_BLOCK_LIST_ENTRIES;
    struct grub_redoxfs_blocklist bl;
    struct grub_redoxfs_blockptr saved;
    const struct grub_redoxfs_blockptr *l4_ptr;

    if (i4 >= REDOXFS_NODE_LEVEL4_COUNT)
      return grub_error (GRUB_ERR_OUT_OF_RANGE, "redoxfs out of range");

    l4_ptr = &node_level4_ptrs (node)[i4];
    if (grub_redoxfs_blockptr_is_null (l4_ptr))
      return GRUB_ERR_NONE;

    err = grub_redoxfs_read_block (data, l4_ptr, &bl);
    if (err != GRUB_ERR_NONE)
      return err;

    if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i3]))
      return GRUB_ERR_NONE;

    saved = bl.ptrs[i3];
    err = grub_redoxfs_read_block (data, &saved, &bl);
    if (err != GRUB_ERR_NONE)
      return err;

    if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i2]))
      return GRUB_ERR_NONE;

    saved = bl.ptrs[i2];
    err = grub_redoxfs_read_block (data, &saved, &bl);
    if (err != GRUB_ERR_NONE)
      return err;

    if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i1]))
      return GRUB_ERR_NONE;

    saved = bl.ptrs[i1];
    err = grub_redoxfs_read_block (data, &saved, &bl);
    if (err != GRUB_ERR_NONE)
      return err;

    if (grub_redoxfs_blockptr_is_null (&bl.ptrs[i0]))
      return GRUB_ERR_NONE;

    return grub_redoxfs_read_block_cap (data, &bl.ptrs[i0], buf,
                     record_size);
  }
}

grub_ssize_t
grub_redoxfs_read_file_data (const struct grub_redoxfs_data *data,
                             const struct grub_redoxfs_node *node,
                             grub_off_t offset,
                             void *buf,
                             grub_size_t len)
{
  grub_uint64_t node_size;
  grub_size_t record_size;
  grub_uint32_t record_level;
  grub_uint8_t *out;
  grub_size_t done;

  node_size = grub_le_to_cpu64 (node->size);

  if (offset >= node_size)
    return 0;

  if (grub_le_to_cpu32 (node->flags) & REDOXFS_FLAG_INLINE_DATA)
    {
      grub_size_t inline_len;
      grub_size_t to_copy;

      inline_len = sizeof (node->level_data);
      out = (grub_uint8_t *) buf;
      done = 0;

      if (offset < inline_len)
        {
          grub_size_t avail;

          to_copy = (grub_size_t) node_size - (grub_size_t) offset;
          if (to_copy > len)
            to_copy = len;

          avail = inline_len - (grub_size_t) offset;
          if (to_copy > avail)
            to_copy = avail;

          grub_memcpy (out, &node->level_data[(grub_size_t) offset], to_copy);
          done = to_copy;
          offset += to_copy;
        }

      while (done < len && offset < node_size)
        out[done++] = 0;

      return (grub_ssize_t) done;
    }

  record_level = grub_le_to_cpu32 (node->record_level);
  if (record_level > REDOXFS_RECORD_LEVEL)
    {
      grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
      return -1;
    }
  record_size = (grub_size_t) REDOXFS_BLOCK_SIZE << record_level;
  out = (grub_uint8_t *) buf;
  done = 0;

  while (done < len && offset < node_size)
    {
      grub_uint64_t record_index;
      grub_size_t offset_within;
      grub_size_t to_read;
      grub_uint64_t remaining_in_node;
      grub_size_t remaining_in_record;
      grub_uint8_t *record_buf;
      grub_err_t err;

      record_index = offset / record_size;
      offset_within = (grub_size_t) (offset % record_size);

      remaining_in_node = node_size - offset;
      remaining_in_record = record_size - offset_within;

      to_read = len - done;
      if ((grub_uint64_t) to_read > remaining_in_node)
        to_read = (grub_size_t) remaining_in_node;
      if (to_read > remaining_in_record)
        to_read = remaining_in_record;

      record_buf = redoxfs_malloc (record_size);
      if (!record_buf)
        return (grub_ssize_t) done > 0 ? (grub_ssize_t) done : -1;

      err = grub_redoxfs_read_record (data, node, record_index,
                                      record_level, record_buf);
      if (err != GRUB_ERR_NONE)
        {
          redoxfs_free (record_buf);
          return (grub_ssize_t) done > 0 ? (grub_ssize_t) done : -1;
        }

      grub_memcpy (out + done, record_buf + offset_within, to_read);
      redoxfs_free (record_buf);

      done += to_read;
      offset += to_read;
    }

  return (grub_ssize_t) done;
}

grub_err_t
grub_redoxfs_probe (void *disk)
{
  struct grub_redoxfs_header hdr;
  grub_uint64_t computed;
  grub_err_t err;

  err = grub_disk_read (disk, 0, 0, REDOXFS_BLOCK_SIZE, &hdr);
  if (err != GRUB_ERR_NONE)
    return err;

  if (grub_memcmp (hdr.signature, REDOXFS_SIGNATURE "\0", 8) != 0)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  if (grub_le_to_cpu64 (hdr.version) != REDOXFS_VERSION)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  computed = grub_redoxfs_seahash (&hdr,
                                   offsetof (struct grub_redoxfs_header,
                                             encrypted_hash));
  if (computed != grub_le_to_cpu64 (hdr.hash))
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  if (grub_redoxfs_header_is_encrypted (&hdr))
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  return GRUB_ERR_NONE;
}

struct dir_hook_ctx {
  grub_fs_dir_hook_t hook;
  void *hook_data;
  const struct grub_redoxfs_data *data;
  grub_err_t stored_err;
};

static int
dir_hook_wrapper (const char *name, grub_size_t namelen,
                  const struct grub_redoxfs_treeptr *ptr, void *hook_data)
{
  struct dir_hook_ctx *ctx;
  struct grub_redoxfs_node node;
  grub_err_t err;
  char name_buf[REDOXFS_DIR_ENTRY_MAX_LENGTH + 1];
  struct grub_dirhook_info info;

  ctx = (struct dir_hook_ctx *) hook_data;

  err = grub_redoxfs_read_node (ctx->data, ptr, &node);
  if (err != GRUB_ERR_NONE)
    {
      ctx->stored_err = err;
      return 1;
    }

  grub_memset (&info, 0, sizeof (info));
  info.dir = ((grub_le_to_cpu16 (node.mode) & REDOXFS_MODE_TYPE)
          == REDOXFS_MODE_DIR) ? 1 : 0;
  info.symlink = ((grub_le_to_cpu16 (node.mode) & REDOXFS_MODE_TYPE)
          == REDOXFS_MODE_SYMLINK) ? 1 : 0;

  if (namelen > REDOXFS_DIR_ENTRY_MAX_LENGTH)
    namelen = REDOXFS_DIR_ENTRY_MAX_LENGTH;
  grub_memcpy (name_buf, name, namelen);
  name_buf[namelen] = '\0';

  return ctx->hook (name_buf, &info, ctx->hook_data);
}

grub_err_t
path_lookup (const struct grub_redoxfs_data *data,
         const char *path_arg,
         int follow_symlinks,
         int symlink_depth,
         struct grub_redoxfs_node *out_node)
{
  struct grub_redoxfs_node current;
  char path_buf[REDOXFS_MAX_PATH_LEN];
  const char *path;
  grub_size_t pathlen;
  grub_size_t pos;
  char cwd[REDOXFS_MAX_PATH_LEN];
  grub_size_t cwd_len;
  grub_err_t err;

  {
    grub_size_t plen = redoxfs_strlen (path_arg);
    if (plen >= REDOXFS_MAX_PATH_LEN)
      return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
    grub_memcpy (path_buf, path_arg, plen + 1);
  }

restart:
  if (symlink_depth > REDOXFS_MAX_SYMLINK_DEPTH)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

  err = grub_redoxfs_read_root (data, &current);
  if (err != GRUB_ERR_NONE)
    return err;

  path = path_buf;
  pathlen = redoxfs_strlen (path);
  pos = 0;
  cwd[0] = '/';
  cwd_len = 1;

  if (pos < pathlen && path[pos] == '/')
    pos++;

  while (pos < pathlen)
    {
      const char *component;
      grub_size_t comp_len;
      struct grub_redoxfs_treeptr entry_ptr;
      struct grub_redoxfs_node entry_node;

      component = &path[pos];
      while (pos < pathlen && path[pos] != '/')
    pos++;
      comp_len = (grub_size_t) (&path[pos] - component);

      if (comp_len == 0)
    {
      while (pos < pathlen && path[pos] == '/')
        pos++;
      continue;
    }

      if (comp_len == 1 && component[0] == '.')
    {
      while (pos < pathlen && path[pos] == '/')
        pos++;
      continue;
    }

      if (comp_len == 2 && component[0] == '.' && component[1] == '.')
    {
      grub_size_t remaining_len;

      while (cwd_len > 1)
        {
          cwd_len--;
          if (cwd[cwd_len - 1] == '/')
        break;
        }
      if (cwd_len > 1)
        cwd_len--;
      cwd[cwd_len] = '\0';

      while (pos < pathlen && path[pos] == '/')
        pos++;

      remaining_len = pathlen - pos;

      {
        grub_size_t rpos = 0;

        if (cwd_len > 1)
          {
        grub_memcpy (path_buf, cwd, cwd_len);
        rpos = cwd_len;
          }

        if (remaining_len > 0)
          {
        if (rpos > 0)
          path_buf[rpos++] = '/';
        grub_memcpy (path_buf + rpos, &path[pos], remaining_len);
        rpos += remaining_len;
          }

        path_buf[rpos] = '\0';
      }

      goto restart;
    }

      if ((grub_le_to_cpu16 (current.mode) & REDOXFS_MODE_TYPE) != REDOXFS_MODE_DIR)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

      {
    char comp_buf[REDOXFS_DIR_ENTRY_MAX_LENGTH + 1];

    if (comp_len > REDOXFS_DIR_ENTRY_MAX_LENGTH)
      return grub_error (GRUB_ERR_FILE_NOT_FOUND,
                         "redoxfs file not found");

    grub_memcpy (comp_buf, component, comp_len);
    comp_buf[comp_len] = '\0';

    err = grub_redoxfs_dir_lookup (data, &current, comp_buf, &entry_ptr);
    if (err != GRUB_ERR_NONE)
      {
        if (err == GRUB_ERR_FILE_NOT_FOUND)
          return grub_error (err, "redoxfs file not found");
        return err;
      }
      }

      err = grub_redoxfs_read_node (data, &entry_ptr, &entry_node);
      if (err != GRUB_ERR_NONE)
    return err;

      while (pos < pathlen && path[pos] == '/')
    pos++;

      if (follow_symlinks
      && (grub_le_to_cpu16 (entry_node.mode) & REDOXFS_MODE_TYPE) == REDOXFS_MODE_SYMLINK)
    {
      grub_uint64_t target_len;
      char *target;
      grub_ssize_t n;
      grub_size_t remaining_len;
      char saved_remaining[REDOXFS_MAX_PATH_LEN];

      target_len = grub_le_to_cpu64 (entry_node.size);
      if (target_len == 0 || target_len >= 3969)
        return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

      target = redoxfs_malloc ((grub_size_t) target_len + 1);
      if (!target)
        return grub_errno;

      n = grub_redoxfs_read_file_data (data, &entry_node, 0,
                         target, (grub_size_t) target_len);
      if (n != (grub_ssize_t) target_len)
        {
          redoxfs_free (target);
          return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
        }

      target[target_len] = '\0';

      remaining_len = pathlen - pos;
      if (remaining_len > 0)
        grub_memcpy (saved_remaining, &path[pos], remaining_len);

      {
        grub_size_t rpos = 0;

        if (target[0] == '/')
          {
        if ((grub_size_t) target_len >= REDOXFS_MAX_PATH_LEN)
          {
            redoxfs_free (target);
            return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
          }
        grub_memcpy (path_buf, target, (grub_size_t) target_len);
        rpos = (grub_size_t) target_len;
          }
        else
          {
        rpos = cwd_len;
        if (rpos + 1 + (grub_size_t) target_len >= REDOXFS_MAX_PATH_LEN)
          {
            redoxfs_free (target);
            return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
          }
        grub_memcpy (path_buf, cwd, cwd_len);
        path_buf[rpos++] = '/';
        grub_memcpy (path_buf + rpos, target, (grub_size_t) target_len);
        rpos += (grub_size_t) target_len;
          }

        if (remaining_len > 0)
          {
        if (rpos + 1 + remaining_len >= REDOXFS_MAX_PATH_LEN)
          {
            redoxfs_free (target);
            return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
          }
        path_buf[rpos++] = '/';
        grub_memcpy (path_buf + rpos, saved_remaining, remaining_len);
        rpos += remaining_len;
          }

        path_buf[rpos] = '\0';
      }

      redoxfs_free (target);
      symlink_depth++;
      goto restart;
    }

      if (cwd_len + 1 + comp_len >= REDOXFS_MAX_PATH_LEN)
    return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");

      if (cwd_len > 1)
    cwd[cwd_len++] = '/';
      grub_memcpy (cwd + cwd_len, component, comp_len);
      cwd_len += comp_len;
      cwd[cwd_len] = '\0';

      current = entry_node;
    }

  *out_node = current;
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_redoxfs_dir (grub_device_t device, const char *path,
                  grub_fs_dir_hook_t hook, void *hook_data)
{
  struct grub_redoxfs_data *data;
  struct grub_redoxfs_node target_dir;
  grub_err_t err;
  struct dir_hook_ctx ctx;

  data = grub_redoxfs_mount (device->disk);
  if (!data)
    return grub_errno;

  err = path_lookup (data, path, 1, 0, &target_dir);
  if (err != GRUB_ERR_NONE)
    {
      grub_redoxfs_unmount (data);
      return err;
    }

  if ((grub_le_to_cpu16 (target_dir.mode) & REDOXFS_MODE_TYPE) != REDOXFS_MODE_DIR)
    {
      grub_redoxfs_unmount (data);
      return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
    }

  ctx.hook = hook;
  ctx.hook_data = hook_data;
  ctx.data = data;
  ctx.stored_err = GRUB_ERR_NONE;

  err = grub_redoxfs_dir_iterate (data, &target_dir, dir_hook_wrapper, &ctx);
  grub_redoxfs_unmount (data);

  if (err == GRUB_ERR_NONE && ctx.stored_err != GRUB_ERR_NONE)
    return ctx.stored_err;

  return err;
}

static grub_err_t
grub_redoxfs_open (struct grub_file *file, const char *name)
{
  struct grub_redoxfs_data *data;
  struct grub_redoxfs_node target;
  struct grub_fshelp_node *fnode;
  grub_err_t err;

  data = grub_redoxfs_mount (file->device->disk);
  if (!data)
    return grub_errno;

  err = path_lookup (data, name, 1, 0, &target);
  if (err != GRUB_ERR_NONE)
    {
      grub_redoxfs_unmount (data);
      return err;
    }

  if ((grub_le_to_cpu16 (target.mode) & REDOXFS_MODE_TYPE) != REDOXFS_MODE_FILE)
    {
      grub_redoxfs_unmount (data);
      return grub_error (GRUB_ERR_BAD_FS, "redoxfs corruption detected");
    }

  fnode = redoxfs_malloc (sizeof (*fnode));
  if (!fnode)
    {
      err = grub_errno;
      grub_redoxfs_unmount (data);
      return err;
    }

  fnode->data = data;
  fnode->node = target;

  file->data = fnode;
  file->size = grub_le_to_cpu64 (fnode->node.size);
  return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_redoxfs_read (struct grub_file *file, char *buf, grub_size_t len)
{
  struct grub_fshelp_node *fnode;

  fnode = (struct grub_fshelp_node *) file->data;
  if (!fnode)
    return -1;

  return grub_redoxfs_read_file_data (fnode->data, &fnode->node,
                                       file->offset, buf, len);
}

static grub_err_t
grub_redoxfs_close (struct grub_file *file)
{
  struct grub_fshelp_node *fnode;

  fnode = (struct grub_fshelp_node *) file->data;
  if (fnode)
    {
      grub_redoxfs_unmount (fnode->data);
      redoxfs_free (fnode);
      file->data = 0;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_redoxfs_label (grub_device_t device, char **label)
{
  (void) device;
  if (label)
    *label = 0;
  return GRUB_ERR_NONE;
}

static char *
format_uuid (const grub_uint8_t *raw)
{
  char *out;
  static const char hex[] = "0123456789abcdef";
  int i, j;

  out = redoxfs_malloc (37);
  if (!out)
    return 0;

  j = 0;
  for (i = 0; i < 16; i++)
    {
      out[j++] = hex[raw[i] >> 4];
      out[j++] = hex[raw[i] & 0xF];
      if (i == 3 || i == 5 || i == 7 || i == 9)
        out[j++] = '-';
    }
  out[36] = '\0';
  return out;
}

static grub_err_t
grub_redoxfs_uuid (grub_device_t device, char **uuid)
{
  struct grub_redoxfs_data *data;

  if (!uuid)
    return GRUB_ERR_NONE;

  data = grub_redoxfs_mount (device->disk);
  if (!data)
    {
      *uuid = 0;
      return grub_errno;
    }

  *uuid = format_uuid (data->header.uuid);
  if (!*uuid)
    {
      grub_err_t err = grub_errno;

      grub_redoxfs_unmount (data);
      return err;
    }
  grub_redoxfs_unmount (data);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_redoxfs_mtime (grub_device_t device, grub_int64_t *tm)
{
  struct grub_redoxfs_data *data;
  struct grub_redoxfs_node root;
  grub_err_t err;

  if (!tm)
    return GRUB_ERR_NONE;

  data = grub_redoxfs_mount (device->disk);
  if (!data)
    return grub_errno;

  err = grub_redoxfs_read_root (data, &root);
  if (err != GRUB_ERR_NONE)
    {
      grub_redoxfs_unmount (data);
      return err;
    }

  *tm = (grub_int64_t) grub_le_to_cpu64 (root.mtime);
  grub_redoxfs_unmount (data);
  return GRUB_ERR_NONE;
}

/* Module registration */
static struct grub_fs grub_redoxfs_fs = {
  .name = "redoxfs",
  .fs_dir = grub_redoxfs_dir,
  .fs_open = grub_redoxfs_open,
  .fs_read = grub_redoxfs_read,
  .fs_close = grub_redoxfs_close,
  .fs_label = grub_redoxfs_label,
  .fs_uuid = grub_redoxfs_uuid,
  .fs_mtime = grub_redoxfs_mtime,
  .next = 0
};

GRUB_MOD_INIT(redoxfs)
{
  grub_redoxfs_fs.mod = mod;
  grub_fs_register (&grub_redoxfs_fs);
}

GRUB_MOD_FINI(redoxfs)
{
  grub_fs_unregister (&grub_redoxfs_fs);
}
