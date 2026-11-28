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

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "guard.h"

/*
 * The owner is published atomically because the threads it rejects read
 * it concurrently.  POSIX compares pthread_t rather than a kernel thread
 * id: LinuxRover initializes before libfuse daemonizes, and pthread_self()
 * survives fork() in the child where gettid() does not.
 */
#if defined(_WIN32)
static volatile LONG owner;	/* thread id; 0 = no owner */

static unsigned long
self_id (void)
{
	return GetCurrentThreadId ();
}

static int
owner_id (unsigned long *id)
{
	*id = (unsigned long) InterlockedCompareExchange (&owner, 0, 0);
	return *id != 0;
}

static void
set_owner (int bound)
{
	InterlockedExchange (&owner, bound ? (LONG) GetCurrentThreadId () : 0);
}

static int
is_owner (void)
{
	return (DWORD) InterlockedCompareExchange (&owner, 0, 0) == GetCurrentThreadId ();
}
#else
static pthread_t owner;
static int owner_bound;

static unsigned long
self_id (void)
{
	return (unsigned long) pthread_self ();
}

static int
owner_id (unsigned long *id)
{
	if (!__atomic_load_n (&owner_bound, __ATOMIC_ACQUIRE))
		return 0;
	*id = (unsigned long) owner;
	return 1;
}

static void
set_owner (int bound)
{
	if (bound)
		owner = pthread_self ();
	__atomic_store_n (&owner_bound, bound, __ATOMIC_RELEASE);
}

static int
is_owner (void)
{
	return pthread_equal (owner, pthread_self ());
}
#endif

/* Owner thread only: callbacks run on the thread that called Rover.  */
static int hook_depth;

static void
guard_fail (const char *api, const char *reason)
{
	char msg[256];

	snprintf (msg, sizeof (msg), "rover: %s %s\n", api, reason);
#if defined(_WIN32)
	OutputDebugStringA (msg);
#endif
	fputs (msg, stderr);
	fflush (stderr);
	abort ();
}

static void
check_owner (const char *api)
{
	unsigned long id;
	char reason[160];

	if (!owner_id (&id) || is_owner ())
		return;
	snprintf (reason, sizeof (reason),
		"called on thread %lu, but Rover belongs to thread %lu (rover_init)",
		self_id (), id);
	guard_fail (api, reason);
}

void
rover_guard_bind (const char *api)
{
	check_owner (api);
	if (hook_depth)
		guard_fail (api, "called from inside a Rover callback");
	set_owner (1);
}

void
rover_guard_unbind (void)
{
	set_owner (0);
}

void
rover_guard_check (const char *api)
{
	check_owner (api);
}

void
rover_guard_task (const char *api)
{
	check_owner (api);
	if (hook_depth)
		guard_fail (api, "called from inside a Rover callback; the driver has not returned");
}

void
rover_guard_hook_begin (void)
{
	hook_depth++;
}

void
rover_guard_hook_end (void)
{
	hook_depth--;
}
