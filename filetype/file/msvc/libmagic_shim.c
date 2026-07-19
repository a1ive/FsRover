/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dirent.h"

struct filexray_msvc_dir
{
	HANDLE find;
	WIN32_FIND_DATAA data;
	struct dirent entry;
	int first;
};

int fx_msvc_pipe(int fds[2])
{
	return _pipe(fds, 4096, _O_BINARY);
}

DIR *opendir(const char *path)
{
	DIR *dir = NULL;
	char pattern[MAX_PATH];
	size_t len;

	if (!path)
	{
		errno = EINVAL;
		return NULL;
	}

	len = strlen(path);
	if (len + 3 >= sizeof(pattern))
	{
		errno = ENAMETOOLONG;
		return NULL;
	}

	memcpy(pattern, path, len + 1);
	if (len != 0 && pattern[len - 1] != '/' && pattern[len - 1] != '\\')
	{
		pattern[len++] = '\\';
		pattern[len] = '\0';
	}
	strcat(pattern, "*");

	dir = (DIR *)calloc(1, sizeof(*dir));
	if (!dir)
	{
		errno = ENOMEM;
		return NULL;
	}

	dir->find = FindFirstFileA(pattern, &dir->data);
	if (dir->find == INVALID_HANDLE_VALUE)
	{
		free(dir);
		errno = ENOENT;
		return NULL;
	}

	dir->first = 1;
	return dir;
}

struct dirent *readdir(DIR *dir)
{
	if (!dir)
	{
		errno = EINVAL;
		return NULL;
	}

	if (dir->first)
		dir->first = 0;
	else if (!FindNextFileA(dir->find, &dir->data))
		return NULL;

	strncpy(dir->entry.d_name, dir->data.cFileName, sizeof(dir->entry.d_name) - 1);
	dir->entry.d_name[sizeof(dir->entry.d_name) - 1] = '\0';
	return &dir->entry;
}

int closedir(DIR *dir)
{
	if (!dir)
	{
		errno = EINVAL;
		return -1;
	}

	FindClose(dir->find);
	free(dir);
	return 0;
}

int vasprintf(char **strp, const char *fmt, va_list ap)
{
	va_list aq;
	int len;
	char *buffer;

	if (!strp || !fmt)
	{
		errno = EINVAL;
		return -1;
	}

	*strp = NULL;
	va_copy(aq, ap);
	len = _vscprintf(fmt, aq);
	va_end(aq);
	if (len < 0)
		return -1;

	buffer = (char *)malloc((size_t)len + 1);
	if (!buffer)
	{
		errno = ENOMEM;
		return -1;
	}

	if (vsnprintf(buffer, (size_t)len + 1, fmt, ap) < 0)
	{
		free(buffer);
		return -1;
	}

	*strp = buffer;
	return len;
}

int asprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vasprintf(strp, fmt, ap);
	va_end(ap);
	return ret;
}

int dprintf(int fd, const char *fmt, ...)
{
	va_list ap;
	char *buffer = NULL;
	int len;
	int written;

	va_start(ap, fmt);
	len = vasprintf(&buffer, fmt, ap);
	va_end(ap);
	if (len < 0)
		return -1;

	written = _write(fd, buffer, (unsigned int)len);
	free(buffer);
	return written == len ? len : -1;
}

const char *fmtcheck(const char *fmt, const char *fallback)
{
	return fmt ? fmt : fallback;
}

size_t strlcpy(char *dst, const char *src, size_t dsize)
{
	size_t len = strlen(src);

	if (dsize != 0)
	{
		size_t copy = len >= dsize ? dsize - 1 : len;
		memcpy(dst, src, copy);
		dst[copy] = '\0';
	}

	return len;
}

size_t strlcat(char *dst, const char *src, size_t dsize)
{
	size_t used = strnlen(dst, dsize);
	size_t len = strlen(src);

	if (used != dsize)
	{
		size_t copy = len >= dsize - used ? dsize - used - 1 : len;
		memcpy(dst + used, src, copy);
		dst[used + copy] = '\0';
	}

	return used + len;
}

char *strcasestr(const char *string, const char *find)
{
	size_t find_len;

	if (!*find)
		return (char *)string;

	find_len = strlen(find);
	for (; *string; string++)
	{
		if (_strnicmp(string, find, find_len) == 0)
			return (char *)string;
	}

	return NULL;
}

ssize_t pread(int fd, void *buf, size_t len, off_t off)
{
	off_t old;
	ssize_t ret;

	old = _lseek(fd, 0, SEEK_CUR);
	if (old == (off_t)-1)
		return -1;
	if (_lseek(fd, off, SEEK_SET) == (off_t)-1)
		return -1;

	ret = _read(fd, buf, (unsigned int)len);
	if (_lseek(fd, old, SEEK_SET) == (off_t)-1)
		return -1;

	return ret;
}

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
	size_t used = 0;
	int ch;

	if (!lineptr || !n || !stream)
	{
		errno = EINVAL;
		return -1;
	}

	if (!*lineptr || *n == 0)
	{
		*n = 256;
		*lineptr = (char *)malloc(*n);
		if (!*lineptr)
		{
			errno = ENOMEM;
			return -1;
		}
	}

	while ((ch = fgetc(stream)) != EOF)
	{
		if (used + 1 >= *n)
		{
			size_t next = *n * 2;
			char *grown = (char *)realloc(*lineptr, next);
			if (!grown)
			{
				errno = ENOMEM;
				return -1;
			}
			*lineptr = grown;
			*n = next;
		}
		(*lineptr)[used++] = (char)ch;
		if (ch == delim)
			break;
	}

	if (used == 0 && ch == EOF)
		return -1;

	(*lineptr)[used] = '\0';
	return (ssize_t)used;
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
	return getdelim(lineptr, n, '\n', stream);
}

char *ctime_r(const time_t *clock, char *buf)
{
	return ctime_s(buf, 26, clock) == 0 ? buf : NULL;
}

char *asctime_r(const struct tm *tm, char *buf)
{
	return asctime_s(buf, 26, tm) == 0 ? buf : NULL;
}

struct tm *gmtime_r(const time_t *clock, struct tm *result)
{
	return gmtime_s(result, clock) == 0 ? result : NULL;
}

struct tm *localtime_r(const time_t *clock, struct tm *result)
{
	return localtime_s(result, clock) == 0 ? result : NULL;
}

static void filexray_vwarn(const char *fmt, va_list ap)
{
	if (fmt)
		vfprintf(stderr, fmt, ap);
	if (errno)
		fprintf(stderr, ": %s", strerror(errno));
	fputc('\n', stderr);
}

void warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	filexray_vwarn(fmt, ap);
	va_end(ap);
}

void warnx(const char *fmt, ...)
{
	va_list ap;
	int saved = errno;

	errno = 0;
	va_start(ap, fmt);
	filexray_vwarn(fmt, ap);
	va_end(ap);
	errno = saved;
}

void err(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	filexray_vwarn(fmt, ap);
	va_end(ap);
	exit(eval);
}

void errx(int eval, const char *fmt, ...)
{
	va_list ap;
	int saved = errno;

	errno = 0;
	va_start(ap, fmt);
	filexray_vwarn(fmt, ap);
	va_end(ap);
	errno = saved;
	exit(eval);
}
