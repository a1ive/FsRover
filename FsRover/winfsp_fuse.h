/*
 * Minimal WinFsp-FUSE 2.8 ABI declarations used by FsRover.
 * Derived from winfsp/inc/fuse (GPLv3); keep structure layout in sync
 * when updating the bundled WinFsp reference.
 */

#ifndef FSROVER_WINFSP_FUSE_H
#define FSROVER_WINFSP_FUSE_H	1

#include <stddef.h>
#include <stdint.h>

typedef uint32_t fuse_uid_t;
typedef uint32_t fuse_gid_t;
typedef int32_t fuse_pid_t;
typedef uint32_t fuse_dev_t;
typedef uint64_t fuse_ino_t;
typedef uint32_t fuse_mode_t;
typedef uint16_t fuse_nlink_t;
typedef int64_t fuse_off_t;
#if defined(_WIN64)
typedef uint64_t fuse_fsblkcnt_t;
typedef uint64_t fuse_fsfilcnt_t;
#else
typedef uint32_t fuse_fsblkcnt_t;
typedef uint32_t fuse_fsfilcnt_t;
#endif
typedef int32_t fuse_blksize_t;
typedef int64_t fuse_blkcnt_t;

struct fuse_timespec
{
#if defined(_WIN64)
	int64_t tv_sec;
	int64_t tv_nsec;
#else
	int32_t tv_sec;
	int32_t tv_nsec;
#endif
};

struct fuse_utimbuf
{
#if defined(_WIN64)
	int64_t actime;
	int64_t modtime;
#else
	int32_t actime;
	int32_t modtime;
#endif
};

struct fuse_stat
{
	fuse_dev_t st_dev;
	fuse_ino_t st_ino;
	fuse_mode_t st_mode;
	fuse_nlink_t st_nlink;
	fuse_uid_t st_uid;
	fuse_gid_t st_gid;
	fuse_dev_t st_rdev;
	fuse_off_t st_size;
	fuse_timespec st_atim;
	fuse_timespec st_mtim;
	fuse_timespec st_ctim;
	fuse_blksize_t st_blksize;
	fuse_blkcnt_t st_blocks;
	fuse_timespec st_birthtim;
};

struct fuse_statvfs
{
#if defined(_WIN64)
	uint64_t f_bsize;
	uint64_t f_frsize;
#else
	uint32_t f_bsize;
	uint32_t f_frsize;
#endif
	fuse_fsblkcnt_t f_blocks;
	fuse_fsblkcnt_t f_bfree;
	fuse_fsblkcnt_t f_bavail;
	fuse_fsfilcnt_t f_files;
	fuse_fsfilcnt_t f_ffree;
	fuse_fsfilcnt_t f_favail;
#if defined(_WIN64)
	uint64_t f_fsid;
	uint64_t f_flag;
	uint64_t f_namemax;
#else
	uint32_t f_fsid;
	uint32_t f_flag;
	uint32_t f_namemax;
#endif
};

struct fuse_flock
{
	int16_t l_type;
	int16_t l_whence;
	fuse_off_t l_start;
	fuse_off_t l_len;
	fuse_pid_t l_pid;
};

struct fsp_fuse_env
{
	unsigned environment;
	void *(*memalloc) (size_t);
	void (*memfree) (void *);
	int (*daemonize) (int);
	int (*set_signal_handlers) (void *);
	char *(*conv_to_win_path) (const char *);
	fuse_pid_t (*winpid_to_pid) (uint32_t);
	void (*reserved[2]) ();
};

struct fuse_args
{
	int argc;
	char **argv;
	int allocated;
};

struct fuse_file_info
{
	int flags;
	unsigned int fh_old;
	int writepage;
	unsigned int direct_io : 1;
	unsigned int keep_cache : 1;
	unsigned int flush : 1;
	unsigned int nonseekable : 1;
	unsigned int padding : 28;
	uint64_t fh;
	uint64_t lock_owner;
};

struct fuse_conn_info
{
	unsigned proto_major;
	unsigned proto_minor;
	unsigned async_read;
	unsigned max_write;
	unsigned max_readahead;
	unsigned capable;
	unsigned want;
	unsigned reserved[25];
};

struct fuse;
struct fuse_chan;
struct fuse_dirhandle;
struct fuse_pollhandle;
struct fuse_bufvec;
struct fuse_statfs;
struct fuse_setattr_x;

struct fuse_context
{
	fuse *fuse;
	fuse_uid_t uid;
	fuse_gid_t gid;
	fuse_pid_t pid;
	void *private_data;
	fuse_mode_t umask;
};

typedef struct fuse_dirhandle *fuse_dirh_t;
typedef int (*fuse_dirfil_t) (fuse_dirh_t, const char *, int, fuse_ino_t);
typedef int (*fuse_fill_dir_t) (void *, const char *, const fuse_stat *, fuse_off_t);

struct fuse_operations
{
	int (*getattr) (const char *, fuse_stat *);
	int (*getdir) (const char *, fuse_dirh_t, fuse_dirfil_t);
	int (*readlink) (const char *, char *, size_t);
	int (*mknod) (const char *, fuse_mode_t, fuse_dev_t);
	int (*mkdir) (const char *, fuse_mode_t);
	int (*unlink) (const char *);
	int (*rmdir) (const char *);
	int (*symlink) (const char *, const char *);
	int (*rename) (const char *, const char *);
	int (*link) (const char *, const char *);
	int (*chmod) (const char *, fuse_mode_t);
	int (*chown) (const char *, fuse_uid_t, fuse_gid_t);
	int (*truncate) (const char *, fuse_off_t);
	int (*utime) (const char *, fuse_utimbuf *);
	int (*open) (const char *, fuse_file_info *);
	int (*read) (const char *, char *, size_t, fuse_off_t, fuse_file_info *);
	int (*write) (const char *, const char *, size_t, fuse_off_t, fuse_file_info *);
	int (*statfs) (const char *, fuse_statvfs *);
	int (*flush) (const char *, fuse_file_info *);
	int (*release) (const char *, fuse_file_info *);
	int (*fsync) (const char *, int, fuse_file_info *);
	int (*setxattr) (const char *, const char *, const char *, size_t, int);
	int (*getxattr) (const char *, const char *, char *, size_t);
	int (*listxattr) (const char *, char *, size_t);
	int (*removexattr) (const char *, const char *);
	int (*opendir) (const char *, fuse_file_info *);
	int (*readdir) (const char *, void *, fuse_fill_dir_t, fuse_off_t, fuse_file_info *);
	int (*releasedir) (const char *, fuse_file_info *);
	int (*fsyncdir) (const char *, int, fuse_file_info *);
	void *(*init) (fuse_conn_info *);
	void (*destroy) (void *);
	int (*access) (const char *, int);
	int (*create) (const char *, fuse_mode_t, fuse_file_info *);
	int (*ftruncate) (const char *, fuse_off_t, fuse_file_info *);
	int (*fgetattr) (const char *, fuse_stat *, fuse_file_info *);
	int (*lock) (const char *, fuse_file_info *, int, fuse_flock *);
	int (*utimens) (const char *, const fuse_timespec[2]);
	int (*bmap) (const char *, size_t, uint64_t *);
	unsigned int flag_nullpath_ok : 1;
	unsigned int flag_nopath : 1;
	unsigned int flag_utime_omit_ok : 1;
	unsigned int flag_reserved : 29;
	int (*ioctl) (const char *, int, void *, fuse_file_info *, unsigned, void *);
	int (*poll) (const char *, fuse_file_info *, fuse_pollhandle *, unsigned *);
	int (*write_buf) (const char *, fuse_bufvec *, fuse_off_t, fuse_file_info *);
	int (*read_buf) (const char *, fuse_bufvec **, size_t, fuse_off_t, fuse_file_info *);
	int (*flock) (const char *, fuse_file_info *, int);
	int (*fallocate) (const char *, int, fuse_off_t, fuse_off_t, fuse_file_info *);
	int (*getpath) (const char *, char *, size_t, fuse_file_info *);
	int (*reserved01) ();
	int (*reserved02) ();
	int (*statfs_x) (const char *, fuse_statfs *);
	int (*setvolname) (const char *);
	int (*exchange) (const char *, const char *, unsigned long);
	int (*getxtimes) (const char *, fuse_timespec *, fuse_timespec *);
	int (*setbkuptime) (const char *, const fuse_timespec *);
	int (*setchgtime) (const char *, const fuse_timespec *);
	int (*setcrtime) (const char *, const fuse_timespec *);
	int (*chflags) (const char *, uint32_t);
	int (*setattr_x) (const char *, fuse_setattr_x *);
	int (*fsetattr_x) (const char *, fuse_setattr_x *, fuse_file_info *);
};

constexpr unsigned FSP_FUSE_CAP_READ_ONLY = 1u << 22;

#endif
