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

#include "natural_sort.h"

#include <cstring>

namespace rover_sort
{
namespace
{

size_t
digit_run (const char *text)
{
	size_t len = 0;

	while (text[len] >= '0' && text[len] <= '9')
		len++;
	return len;
}

} /* namespace */

/*
 * Order for names listed by Rover.  A run of digits compares as a number,
 * so "img2" comes before "img10" and "hd0,gpt2" before "hd0,gpt10";
 * ASCII letters compare case-insensitively and everything else by byte,
 * which for UTF-8 is codepoint order.
 *
 * Deliberately not the shell's StrCmpLogicalW: that one collates by the
 * user's locale, which would tie a listing to the system language and pull
 * a UTF-16 conversion into every comparison.  These rules produce the same
 * result on every machine, at the price of not matching Explorer for
 * non-ASCII names.
 *
 * Two distinct names never compare equal, so std::sort cannot leave a pair
 * in an arbitrary order: a difference these rules look past
 * ("README"/"readme", "1"/"01") is retained as the tiebreak.
 */
int
natural_compare (const char *left, const char *right)
{
	int tie = 0;

	while (*left && *right)
	{
		size_t left_digits = digit_run (left);
		size_t right_digits = digit_run (right);

		if (left_digits && right_digits)
		{
			size_t left_zeroes = 0;
			size_t right_zeroes = 0;
			while (left_zeroes < left_digits - 1 && left[left_zeroes] == '0')
				left_zeroes++;
			while (right_zeroes < right_digits - 1 && right[right_zeroes] == '0')
				right_zeroes++;
			if (left_digits - left_zeroes != right_digits - right_zeroes)
				return left_digits - left_zeroes < right_digits - right_zeroes ? -1 : 1;
			int result = std::memcmp (left + left_zeroes, right + right_zeroes,
				left_digits - left_zeroes);
			if (result)
				return result < 0 ? -1 : 1;
			if (!tie && left_zeroes != right_zeroes)
				tie = left_zeroes < right_zeroes ? -1 : 1;
			left += left_digits;
			right += right_digits;
			continue;
		}
		if (left_digits != right_digits)
			return left_digits ? -1 : 1;

		unsigned char left_char = static_cast<unsigned char> (*left);
		unsigned char right_char = static_cast<unsigned char> (*right);
		if (left_char >= 'A' && left_char <= 'Z')
			left_char += 'a' - 'A';
		if (right_char >= 'A' && right_char <= 'Z')
			right_char += 'a' - 'A';
		if (left_char != right_char)
			return left_char < right_char ? -1 : 1;
		if (!tie && *left != *right)
			tie = static_cast<unsigned char> (*left) < static_cast<unsigned char> (*right)
				? -1 : 1;
		left++;
		right++;
	}
	/* A prefix sorts before what extends it, which puts a disk ahead of
	   its own partitions in the device tree.  */
	if (*left || *right)
		return *left ? 1 : -1;
	return tie;
}

bool
natural_less (const std::string &left, const std::string &right)
{
	return natural_compare (left.c_str (), right.c_str ()) < 0;
}

} /* namespace rover_sort */
