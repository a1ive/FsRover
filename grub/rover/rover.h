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
 * Public entry points of grub.lib -- the VFS boundary shared by the
 * GUI backend thread and (later) the dokan driver.  Everything here
 * must be called from a single thread: grub keeps global state
 * (grub_errno, device lists, disk cache).
 *
 * This header deliberately avoids grub headers so that C++ callers
 * do not inherit grub's compilation environment.  All strings are
 * UTF-8; paths look like "(hd0,gpt2)/dir/file".  Functions returning
 * int return 0 on success and a grub_err_t value on failure; the
 * matching message is available from rover_last_error().
 */

#ifndef ROVER_H
#define ROVER_H	1

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes that could not be determined (mirrors GRUB_FILE_SIZE_UNKNOWN
   and GRUB_DISK_SIZE_UNKNOWN).  */
#define ROVER_SIZE_UNKNOWN	0xffffffffffffffffULL

/* Leave the windisk backend (physical drives and optical discs)
   unregistered.  It is the only module that wants an elevated token,
   so a caller that came to browse one image file can drop it and never
   touch a device it has no business opening.  */
#define ROVER_INIT_NO_WINDISK	0x1

/* Register all built-in grub modules.  Call once before anything else.
   FLAGS is a combination of the ROVER_INIT_* bits above, or 0.  */
void rover_init (int flags);

/* Unregister all modules and release grub state.  */
void rover_fini (void);

/* Message for the most recent failure, or NULL if the last call
   succeeded.  Valid until the next rover/grub call.  */
const char *rover_last_error (void);

/*
 * Disk/volume enumeration.  The callback receives every grub device:
 * whole disks ("hd0"), partitions ("hd0,gpt2"), and volume-manager
 * volumes ("lvm/vg-root", "ldm/...", "md/...").  Pointers in the info
 * struct are only valid during the callback.
 */

/* Driver class of a device, condensed from grub_disk_dev_id (this
   header deliberately avoids grub headers).  Unlisted drivers report
   ROVER_DEV_OTHER.  */
#define ROVER_DEV_OTHER	0
#define ROVER_DEV_WINDISK	1	/* physical disk/volume (windisk) */
#define ROVER_DEV_LOOPBACK	2	/* loopdisk image mount */
#define ROVER_DEV_DISKFILTER	3	/* lvm/ldm/mdraid/dmraid volume */
#define ROVER_DEV_CRYPTODISK	4	/* unlocked crypto volume */
#define ROVER_DEV_PROCFS	5	/* (proc) pseudo-device */
#define ROVER_DEV_WINFILE	6	/* winfile host image mount */

struct rover_disk_info
{
	const char *name;	/* grub device name, without parens */
	int is_partition;
	int dev_id;	/* ROVER_DEV_* driver class */
	unsigned long long size;	/* bytes, ROVER_SIZE_UNKNOWN if unknown */
	const char *fs;	/* filesystem name, NULL if unrecognized */
	const char *label;	/* filesystem label, NULL if none */
	const char *fs_uuid;	/* filesystem UUID, NULL if none */
	/* Geometry.  start_lba is the partition's first sector on its parent
	   disk in sector_size units (0 for whole disks and synthetic devices);
	   sector_size is the disk's logical sector size in bytes (0 if the
	   device has no backing disk).  start_lba * sector_size is the byte
	   offset of the partition.  */
	unsigned long long start_lba;
	unsigned int sector_size;
	/* Parentage, all valid only during the callback and all NULL unless
	   the device is of the matching class: parent_file is a loopback's
	   backing file (grub path); parent_device is the source device an
	   unlocked cryptodisk decrypts; parents is a diskfilter volume's
	   member devices, one per line ('\n'-separated).  */
	const char *parent_file;
	const char *parent_device;
	const char *parents;
	/* A locked LUKS/LUKS2, BitLocker or GELI container (no readable fs
	   until unlocked).  crypto_type is "luks", "luks2", "bitlocker" or
	   "geli"; crypto_uuid is its UUID.
	   Both pointers are valid only during the callback.  */
	int encrypted;
	const char *crypto_type;
	const char *crypto_uuid;
};

typedef int (*rover_disk_hook) (const struct rover_disk_info *info, void *data);

/* Returns nonzero if the callback stopped the enumeration.  */
int rover_enum_disks (rover_disk_hook cb, void *data);

/*
 * Directory enumeration.  "." and ".." are filtered out.  Entry sizes
 * are not available here (grub dir hooks do not report them); use
 * rover_stat() per entry.  Pointers are only valid during the callback.
 */

struct rover_dirent
{
	const char *name;
	int is_dir;
	int is_symlink;
	int mtime_set;
	long long mtime;	/* seconds since Unix epoch */
	/* On-disk identity of the entry (inode number, MFT record, start
	   cluster -- whatever the driver uses to tell two objects apart
	   within one volume).  Not every driver reports one: inode_set is
	   0 then and inode is meaningless.  Two entries of the same volume
	   with equal inodes are the same object, which is how a walker
	   tells a hard link or a corrupt directory cycle from a fresh
	   subtree.  */
	int inode_set;
	unsigned long long inode;
};

typedef int (*rover_dir_hook) (const struct rover_dirent *ent, void *data);

int rover_dir_list (const char *path, rover_dir_hook cb, void *data);

/*
 * File access.  Files are opened raw: transparent decompression
 * (gzio/xzio/...) is disabled so extraction copies the stored bytes.
 */

typedef struct rover_file rover_file;

rover_file *rover_file_open (const char *path);	/* NULL on failure */
/* Returns bytes read, 0 at EOF, negative on error.  */
long long rover_file_read (rover_file *f, void *buf, unsigned long long len);
int rover_file_seek (rover_file *f, unsigned long long offset);
unsigned long long rover_file_size (rover_file *f);
void rover_file_close (rover_file *f);

/*
 * Read progress.  The callback fires from inside rover_file_read()
 * whenever grub reads file data (kern/file.c grub_file_progress_hook),
 * with the bytes delivered so far and the file size.  Pass NULL to
 * disable.  Cancellation is the caller's job: read in chunks and stop
 * between them.
 */

typedef void (*rover_progress_hook) (unsigned long long done, unsigned long long total, void *data);

void rover_set_progress (rover_progress_hook cb, void *data);

/* Metadata for a single path (directory entry match + file size).  */

struct rover_stat
{
	int is_dir;
	int is_symlink;
	int mtime_set;
	long long mtime;	/* seconds since Unix epoch */
	unsigned long long size;	/* 0 for directories */
	int inode_set;	/* see struct rover_dirent */
	unsigned long long inode;
};
typedef struct rover_stat rover_stat_t;

int rover_stat (const char *path, rover_stat_t *st);

/* Filesystem name of a device given without parens ("hd0,gpt2" ->
   "ntfs"), NULL if none.  The returned string is static.  */
const char *rover_fs_name (const char *device);

/*
 * Registered feature names, for the GUI's "supported features" list.
 * The callback receives each name in registration order; returning
 * nonzero stops the enumeration (and is passed through).  The lists
 * are fixed once rover_init() has run.
 */

#define ROVER_SUPPORT_FS	0	/* filesystems */
#define ROVER_SUPPORT_PARTMAP	1	/* partition maps */
#define ROVER_SUPPORT_DISKFILTER	2	/* volume managers / RAID */
#define ROVER_SUPPORT_CRYPTODISK	3	/* LUKS/LUKS2/BitLocker/GELI */
#define ROVER_SUPPORT_IOFILTER	4	/* compression + vdisk io filters */

typedef int (*rover_support_hook) (const char *name, void *data);

int rover_enum_support (int category, rover_support_hook cb, void *data);

/*
 * Loopback: expose the file at grub PATH as read-only virtual disk
 * DEVNAME ("loop0"); it then appears in rover_enum_disks and can be
 * browsed like any disk.  Nonzero DECOMPRESS lets the gzip/xz/...
 * io filters decode a compressed image transparently instead of
 * exposing its raw bytes.  Deleting fails while the device is open.
 */
int rover_loopback_add (const char *devname, const char *path, int decompress);
int rover_loopback_del (const char *devname);

/* Backing file (grub path) of loopback device DEVNAME, or NULL if there is
   no such device.  The returned string is owned by the loopback and stays
   valid until the device is deleted.  */
const char *rover_loopback_get_file (const char *devname);

/*
 * Host images: the same thing for a file on the Windows filesystem,
 * which has no grub device to name it by.  PATH is a Windows path in
 * UTF-8 ("C:\\images\\disk.vhd"); the file is opened with the Win32 API
 * and exposed as read-only virtual disk DEVNAME ("img0"), decoded
 * through the same io filters (vhd/vhdx/qcow/... always, gzip/xz/...
 * when DECOMPRESS is nonzero).  Deleting fails while the device is
 * open.  rover_winfile_get_path() returns the Windows path a device was
 * created from, owned by the device and valid until it is deleted.
 */
int rover_winfile_add (const char *devname, const char *path, int decompress);
int rover_winfile_del (const char *devname);
const char *rover_winfile_get_path (const char *devname);

/*
 * Unlock the LUKS/LUKS2 volume on grub device DEVICE ("hd0,gpt2") using
 * KEY (KEY_LEN bytes: a passphrase as typed, or a keyfile's raw bytes).
 * On success returns 0 and writes the resulting crypto device name
 * ("crypto0") into OUT_DEV (capacity OUT_SIZE), which then shows up in
 * rover_enum_disks and browses like any disk.  A wrong key returns a
 * nonzero grub_err_t (rover_last_error() gives the message).
 */
int rover_crypto_unlock (const char *device,
	const void *key, unsigned long long key_len,
	char *out_dev, unsigned long long out_size);

/*
 * VeraCrypt / TrueCrypt volumes, which are not auto-detected: nothing about
 * such a volume is plaintext, so it can only be recognised by decrypting its
 * header, and the parameters that are not stored in it have to be supplied.
 *
 * PASS is the passphrase as typed; when key files are used the caller folds
 * them into the passphrase first (the 64/128 byte pool of VeraCrypt's key
 * file algorithm) and passes the pool.  PIM is the personal iterations
 * multiplier (0 = the volume's default), PRF one of ROVER_VC_PRF_* with
 * ROVER_VC_PRF_AUTO meaning "try all five", which can take tens of seconds.
 * FLAGS is a combination of ROVER_VC_*.  On success returns 0 and writes the
 * crypto device name ("crypto0") into OUT_DEV; a wrong passphrase (or wrong
 * PIM, or wrong mode) returns nonzero.
 */
#define ROVER_VC_PRF_AUTO	0
#define ROVER_VC_PRF_SHA512	1
#define ROVER_VC_PRF_WHIRLPOOL	2
#define ROVER_VC_PRF_SHA256	3
#define ROVER_VC_PRF_RIPEMD160	4
#define ROVER_VC_PRF_STREEBOG	5

#define ROVER_VC_TRUECRYPT	0x1	/* TrueCrypt volume ('TRUE' magic) */
#define ROVER_VC_HIDDEN		0x2	/* unlock the hidden volume only */
#define ROVER_VC_BACKUP		0x4	/* use the backup headers */

int rover_veracrypt_unlock (const char *device,
	const void *pass, unsigned long long pass_len,
	unsigned int pim, int prf, unsigned int flags,
	char *out_dev, unsigned long long out_size);

/*
 * Progress for the slow unlock key derivation (PBKDF2/Argon2).  The
 * callback fires from inside rover_crypto_unlock() with the done/total
 * step count of the current KDF pass (not bytes).  Pass NULL to disable.
 * Install it before calling rover_crypto_unlock and clear it after.
 */
void rover_set_crypto_progress (rover_progress_hook cb, void *data);

#ifdef __cplusplus
}
#endif

#endif /* ! ROVER_H */
