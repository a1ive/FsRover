/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef ROVER_FILETYPE_H
#define ROVER_FILETYPE_H	1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Human-readable description of a file whose first SIZE bytes are in
   DATA ("ASCII text, with CRLF line terminators", "ELF 64-bit LSB
   executable", ...).  Returns NULL if the magic database cannot be
   loaded or the buffer defeats libmagic; the pointer stays valid
   until the next call or filetype_shutdown().

   Not thread-safe: FsRover only calls this from the backend thread.  */
const char *filetype_describe (const void *data, size_t size);

/* Release the magic database.  */
void filetype_shutdown (void);

#ifdef __cplusplus
}
#endif

#endif /* ! ROVER_FILETYPE_H */
