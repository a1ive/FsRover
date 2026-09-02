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

#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <errno.h>
#endif

#include <grub/time.h>
#include <grub/datetime.h>
#include <grub/err.h>

void
grub_millisleep (grub_uint32_t ms)
{
#if defined(_WIN32)
	Sleep (ms);
#else
	struct timespec delay;

	delay.tv_sec = ms / 1000;
	delay.tv_nsec = (long) (ms % 1000) * 1000000L;
	while (nanosleep (&delay, &delay) != 0 && errno == EINTR)
		;
#endif
}

grub_uint64_t
grub_get_time_ms (void)
{
#if defined(_WIN32)
	return GetTickCount64 ();
#else
	struct timespec now;

	if (clock_gettime (CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return (grub_uint64_t) now.tv_sec * 1000
		+ (grub_uint64_t) now.tv_nsec / 1000000;
#endif
}

grub_err_t
grub_get_datetime (struct grub_datetime *datetime)
{
	struct tm tm;
	time_t now;

	time (&now);
#if defined(_WIN32)
	if (gmtime_s (&tm, &now) != 0)
		return grub_error (GRUB_ERR_BUG, "gmtime_s failed");
#else
	if (!gmtime_r (&now, &tm))
		return grub_error (GRUB_ERR_BUG, "gmtime_r failed");
#endif

	datetime->year = tm.tm_year + 1900;
	datetime->month = tm.tm_mon + 1;
	datetime->day = tm.tm_mday;
	datetime->hour = tm.tm_hour;
	datetime->minute = tm.tm_min;
	datetime->second = tm.tm_sec;
	return GRUB_ERR_NONE;
}

grub_err_t
grub_set_datetime (struct grub_datetime *datetime)
{
	(void) datetime;
	return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "cannot set the clock");
}
