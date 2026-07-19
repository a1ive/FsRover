/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#ifndef FILEXRAY_MSVC_REGEX_H
#define FILEXRAY_MSVC_REGEX_H

#include <stddef.h>

#define REG_EXTENDED 1
#define REG_ICASE 2
#define REG_NOSUB 4
#define REG_NEWLINE 8
#define REG_NOTBOL 16
#define REG_NOTEOL 32

#define REG_NOMATCH 1
#define REG_BADPAT 2
#define REG_ESPACE 3

typedef ptrdiff_t regoff_t;

typedef struct
{
	void *opaque;
	int cflags;
} regex_t;

typedef struct
{
	regoff_t rm_so;
	regoff_t rm_eo;
} regmatch_t;

#ifdef __cplusplus
extern "C" {
#endif

int regcomp(regex_t *preg, const char *pattern, int cflags);
int regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags);
size_t regerror(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size);
void regfree(regex_t *preg);

#ifdef __cplusplus
}
#endif

#endif
