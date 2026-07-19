/*
 *  Rover -- GRUB 2 filesystem browser for Windows
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
 * xzembed's xz.h includes <unistd.h> but uses nothing from it; the
 * MSVC CRT has no such header.  grub's posix_wrap cannot be used
 * instead because its static-inline strlen/strcmp definitions collide
 * with MSVC intrinsics (C2169).  Everything else xzembed needs
 * (stdint.h, string.h, stdbool.h, stdlib.h) comes from the CRT.
 */

#ifndef ROVER_POSIX_UNISTD_H
#define ROVER_POSIX_UNISTD_H	1

#include <stddef.h>

#endif /* ! ROVER_POSIX_UNISTD_H */
