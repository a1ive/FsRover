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
 * Merged <grub/cpu/time.h>: grub_cpu_idle is a no-op on every
 * architecture Rover targets (identical to the upstream stubs).
 */

#ifndef GRUB_CPU_TIME_DISPATCH_HEADER
#define GRUB_CPU_TIME_DISPATCH_HEADER	1

static __inline void
grub_cpu_idle (void)
{
}

#endif /* ! GRUB_CPU_TIME_DISPATCH_HEADER */
