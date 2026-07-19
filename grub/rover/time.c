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

#include <windows.h>

#include <grub/time.h>
#include <grub/datetime.h>
#include <grub/err.h>

void
grub_millisleep (grub_uint32_t ms)
{
	Sleep (ms);
}

grub_uint64_t
grub_get_time_ms (void)
{
	return GetTickCount64 ();
}

grub_err_t
grub_get_datetime (struct grub_datetime *datetime)
{
	struct tm tm;
	time_t now;

	time (&now);
	if (gmtime_s (&tm, &now) != 0)
		return grub_error (GRUB_ERR_BUG, "gmtime_s failed");

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
