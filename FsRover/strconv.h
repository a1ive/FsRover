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

/* grub talks UTF-8, Win32 UTF-16; convert at the boundaries only.  */

#ifndef FSROVER_STRCONV_H
#define FSROVER_STRCONV_H	1

#include <windows.h>

#include <string>

inline std::wstring
widen (const std::string &text)
{
	if (text.empty ())
		return {};
	int len = MultiByteToWideChar (CP_UTF8, 0, text.c_str (), (int) text.size (), nullptr, 0);
	std::wstring out ((size_t) len, L'\0');
	MultiByteToWideChar (CP_UTF8, 0, text.c_str (), (int) text.size (), out.data (), len);
	return out;
}

inline std::string
narrow (const std::wstring &text)
{
	if (text.empty ())
		return {};
	int len = WideCharToMultiByte (CP_UTF8, 0, text.c_str (), (int) text.size (), nullptr, 0, nullptr, nullptr);
	std::string out ((size_t) len, '\0');
	WideCharToMultiByte (CP_UTF8, 0, text.c_str (), (int) text.size (), out.data (), len, nullptr, nullptr);
	return out;
}

#endif /* ! FSROVER_STRCONV_H */
