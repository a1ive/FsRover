#ifndef ROVER_COMMON_FS_ENCODING_H
#define ROVER_COMMON_FS_ENCODING_H	1

#include <wchar.h>

#include <rover.h>

namespace rover_fs_encoding
{

struct option
{
	const wchar_t *name;
	unsigned int code_page;
};

inline constexpr option OPTIONS[] =
{
	{ L"UTF-8", ROVER_FS_ENCODING_UTF8 },
	{ L"GBK", ROVER_FS_ENCODING_GBK },
	{ L"Big5", ROVER_FS_ENCODING_BIG5 },
	{ L"Shift-JIS", ROVER_FS_ENCODING_SHIFT_JIS },
	{ L"EUC-KR", ROVER_FS_ENCODING_EUC_KR },
};

inline const option *
find (const wchar_t *name)
{
	for (const option &encoding : OPTIONS)
		if (_wcsicmp (name, encoding.name) == 0)
			return &encoding;
	return nullptr;
}

} /* namespace rover_fs_encoding */

#endif /* ! ROVER_COMMON_FS_ENCODING_H */
