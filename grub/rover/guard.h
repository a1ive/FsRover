/*
 *  Rover -- Filesystem browser for Windows
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

#ifndef ROVER_GUARD_H
#define ROVER_GUARD_H	1

/*
 * Rover calling contract, enforced at the public entry points.
 *
 * GRUB keeps global state (grub_errno, device list, disk cache, file
 * filters), so the library has one owner: the thread that ran
 * rover_init().  Every public function must be called on that thread,
 * and a function that does I/O or changes devices (a "task") must not be
 * called from inside a callback Rover is running, because the driver
 * that invoked the callback has not returned yet.
 *
 * Before rover_init() and after rover_fini() there is no owner and only
 * the callback rule applies, so hooks may be installed from any thread
 * ahead of initialization.  A violation prints a diagnostic and aborts:
 * a concurrent or re-entrant GRUB call cannot be undone safely.
 */

/* rover_init(): make the calling thread the owner.  */
void rover_guard_bind (const char *api);
/* rover_fini(): drop the owner once cleanup is complete.  */
void rover_guard_unbind (void);

/* Lightweight queries and hook setters: owner thread only.  */
void rover_guard_check (const char *api);
/* I/O and device changes: owner thread, outside Rover callbacks.  */
void rover_guard_task (const char *api);

/* Bracket every call into a frontend-supplied callback.  */
void rover_guard_hook_begin (void);
void rover_guard_hook_end (void);

#endif
