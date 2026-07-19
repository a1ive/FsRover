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
 * GRUB resolves <grub/cpu/...> via symlinks created at configure time.
 * Rover uses this dispatcher header instead, selecting the architecture
 * at compile time.
 */

#ifndef GRUB_CPU_TYPES_DISPATCH_HEADER
#define GRUB_CPU_TYPES_DISPATCH_HEADER	1

#if defined(_M_X64) || defined(__x86_64__)
#include <grub/x86_64/types.h>
#elif defined(_M_IX86) || defined(__i386__)
#include <grub/i386/types.h>
#elif defined(_M_ARM64) || defined(__aarch64__)
#include <grub/arm64/types.h>
#else
#error "unsupported architecture"
#endif

#endif /* ! GRUB_CPU_TYPES_DISPATCH_HEADER */
