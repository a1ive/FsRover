/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#ifndef FILEXRAY_MSVC_DIRENT_H
#define FILEXRAY_MSVC_DIRENT_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct filexray_msvc_dir DIR;

struct dirent
{
	char d_name[MAX_PATH];
};

DIR *opendir(const char *path);
struct dirent *readdir(DIR *dir);
int closedir(DIR *dir);

#ifdef __cplusplus
}
#endif

#endif
