/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef ROVER_FSCHARSET_H
#define ROVER_FSCHARSET_H	1

#include <grub/types.h>

#define GRUB_FS_CHAR_ENCODING_UTF8	65001U

/* Source encoding for byte-oriented filesystem names.  Unicode-native
   names, such as FAT long names and exFAT names, do not use this setting. */
extern grub_uint32_t grub_fs_char_encoding;

/* Convert exactly SIZE source bytes and return an allocated UTF-8 string. */
char *grub_fs_bytes_to_utf8 (const char *src, grub_size_t size,
	grub_uint32_t encoding);

#endif /* ! ROVER_FSCHARSET_H */
