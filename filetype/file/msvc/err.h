/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#ifndef FILEXRAY_MSVC_ERR_H
#define FILEXRAY_MSVC_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

void warn(const char *fmt, ...);
void warnx(const char *fmt, ...);
void err(int eval, const char *fmt, ...);
void errx(int eval, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
