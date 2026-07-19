/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * MSVC configuration for the vendored file/libmagic sources.
 */
#ifndef FILEXRAY_LIBMAGIC_CONFIG_H
#define FILEXRAY_LIBMAGIC_CONFIG_H

#ifndef WIN32
#define WIN32 1
#endif
#ifndef _WIN32
#define _WIN32 1
#endif

#define BUILD_AS_WINDOWS_STATIC_LIBARAY 1
#define VERSION "5.47"
#define PACKAGE_VERSION "5.47"
#define MAGIC "magic"

#define HAVE_CONFIG_H 1
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE_WCHAR_H 1
#define HAVE_WCTYPE_H 1
#define HAVE_STRTOF 1
#define HAVE_VISIBILITY 0
#define HAVE_FORK 0

#define BUILTIN_ELF 1
#define ELFCORE 1
#define FILEXRAY_SUPPRESS_MAGIC_WARNINGS 1

#define _CRT_SECURE_NO_WARNINGS 1
#define _CRT_NONSTDC_NO_DEPRECATE 1

#include <BaseTsd.h>
#include <fcntl.h>
#include <io.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifndef ssize_t
typedef SSIZE_T ssize_t;
#endif

#ifndef mode_t
typedef int mode_t;
#endif

#ifndef R_OK
#define R_OK 4
#endif
#ifndef W_OK
#define W_OK 2
#endif
#ifndef X_OK
#define X_OK 1
#endif
#ifndef F_OK
#define F_OK 0
#endif

#ifndef S_IFMT
#define S_IFMT _S_IFMT
#endif
#ifndef S_IFDIR
#define S_IFDIR _S_IFDIR
#endif
#ifndef S_IFREG
#define S_IFREG _S_IFREG
#endif
#ifndef S_IFCHR
#define S_IFCHR _S_IFCHR
#endif
#ifndef S_IFIFO
#define S_IFIFO 0010000
#endif
#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif

#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif
#ifndef S_ISCHR
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
#ifndef O_RDONLY
#define O_RDONLY _O_RDONLY
#endif
#ifndef O_WRONLY
#define O_WRONLY _O_WRONLY
#endif
#ifndef O_RDWR
#define O_RDWR _O_RDWR
#endif
#ifndef O_CREAT
#define O_CREAT _O_CREAT
#endif
#ifndef O_TRUNC
#define O_TRUNC _O_TRUNC
#endif
#ifndef O_EXCL
#define O_EXCL _O_EXCL
#endif

#ifndef stricmp
#define stricmp _stricmp
#endif
#ifndef strdup
#define strdup _strdup
#endif
#ifndef fileno
#define fileno _fileno
#endif

int fx_msvc_pipe(int fds[2]);

#define pipe fx_msvc_pipe
#define open _open
#define read _read
#define write _write
#define close _close
#define lseek _lseeki64
#define off_t __int64
#define stat _stat64
#define fstat _fstat64
#define access _access
#define dup2 _dup2
#define unlink _unlink
#define mktemp _mktemp
#define umask _umask

#endif
