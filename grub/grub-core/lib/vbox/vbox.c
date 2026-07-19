/*
 * Copyright (C) 2006-2023 Oracle and/or its affiliates.
 *
 * This file is part of VirtualBox base platform packages, as
 * available from https://www.virtualbox.org.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, in version 3 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses>.
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL), a copy of it is provided in the "COPYING.CDDL" file included
 * in the VirtualBox distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 *
 * SPDX-License-Identifier: GPL-3.0-only OR CDDL-1.0
 */

#include "vbox.h"
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/deflate.h>

#define MINILZO_HAVE_CONFIG_H
#include "../minilzo/minilzo.h"

#include "../bzip2/bzlib.h"

 /** Conversion table used by the conversion functions.
  * 0xff if not a hex number, otherwise the value. */
static const grub_uint8_t g_au8Digits[256] =
{
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 0..0f */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 10..1f */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 20..2f */
	0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,  0x08,0x09,0xff,0xff, 0xff,0xff,0xff,0xff, /* 30..3f */
	0xff,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 40..4f */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 50..5f */
	0xff,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 60..6f */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 70..7f */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 80..8f */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* 90..9f */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* a0..af */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* b0..bf */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* c0..cf */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* d0..df */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* e0..ef */
	0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, /* f0..ff */
};
/** Conversion to string. */
static const char g_achDigits[17] = "0123456789abcdef";

int
RTUuidIsNull(PCRTUUID pUuid)
{
	return !pUuid->au64[0] && !pUuid->au64[1];
}

int
RTUuidCompare(PCRTUUID pUuid1, PCRTUUID pUuid2)
{
	/*
	 * Special cases.
	 */
	if (pUuid1 == pUuid2)
		return 0;
	if (!pUuid1)
		return RTUuidIsNull(pUuid2) ? 0 : -1;
	if (!pUuid2)
		return RTUuidIsNull(pUuid1) ? 0 : 1;

	/*
	 * Standard cases.
	 */
	if (pUuid1->Gen.u32TimeLow != pUuid2->Gen.u32TimeLow)
		return pUuid1->Gen.u32TimeLow < pUuid2->Gen.u32TimeLow ? -1 : 1;
	if (pUuid1->Gen.u16TimeMid != pUuid2->Gen.u16TimeMid)
		return pUuid1->Gen.u16TimeMid < pUuid2->Gen.u16TimeMid ? -1 : 1;
	if (pUuid1->Gen.u16TimeHiAndVersion != pUuid2->Gen.u16TimeHiAndVersion)
		return pUuid1->Gen.u16TimeHiAndVersion < pUuid2->Gen.u16TimeHiAndVersion ? -1 : 1;
	if (pUuid1->Gen.u8ClockSeqHiAndReserved != pUuid2->Gen.u8ClockSeqHiAndReserved)
		return pUuid1->Gen.u8ClockSeqHiAndReserved < pUuid2->Gen.u8ClockSeqHiAndReserved ? -1 : 1;
	if (pUuid1->Gen.u8ClockSeqLow != pUuid2->Gen.u8ClockSeqLow)
		return pUuid1->Gen.u8ClockSeqLow < pUuid2->Gen.u8ClockSeqLow ? -1 : 1;
	if (pUuid1->Gen.au8Node[0] != pUuid2->Gen.au8Node[0])
		return pUuid1->Gen.au8Node[0] < pUuid2->Gen.au8Node[0] ? -1 : 1;
	if (pUuid1->Gen.au8Node[1] != pUuid2->Gen.au8Node[1])
		return pUuid1->Gen.au8Node[1] < pUuid2->Gen.au8Node[1] ? -1 : 1;
	if (pUuid1->Gen.au8Node[2] != pUuid2->Gen.au8Node[2])
		return pUuid1->Gen.au8Node[2] < pUuid2->Gen.au8Node[2] ? -1 : 1;
	if (pUuid1->Gen.au8Node[3] != pUuid2->Gen.au8Node[3])
		return pUuid1->Gen.au8Node[3] < pUuid2->Gen.au8Node[3] ? -1 : 1;
	if (pUuid1->Gen.au8Node[4] != pUuid2->Gen.au8Node[4])
		return pUuid1->Gen.au8Node[4] < pUuid2->Gen.au8Node[4] ? -1 : 1;
	if (pUuid1->Gen.au8Node[5] != pUuid2->Gen.au8Node[5])
		return pUuid1->Gen.au8Node[5] < pUuid2->Gen.au8Node[5] ? -1 : 1;
	return 0;
}

int
RTUuidFromStr(PRTUUID pUuid, const char* pszString)
{
	int fHaveBraces = pszString[0] == '{';
	pszString += fHaveBraces;
#define MY_CHECK(expr) do { if (!(expr)) return GRUB_ERR_BAD_NUMBER; } while (0)
#define MY_ISXDIGIT(ch) (g_au8Digits[(ch) & 0xff] != 0xff)
	MY_CHECK(MY_ISXDIGIT(pszString[0]));
	MY_CHECK(MY_ISXDIGIT(pszString[1]));
	MY_CHECK(MY_ISXDIGIT(pszString[2]));
	MY_CHECK(MY_ISXDIGIT(pszString[3]));
	MY_CHECK(MY_ISXDIGIT(pszString[4]));
	MY_CHECK(MY_ISXDIGIT(pszString[5]));
	MY_CHECK(MY_ISXDIGIT(pszString[6]));
	MY_CHECK(MY_ISXDIGIT(pszString[7]));
	MY_CHECK(pszString[8] == '-');
	MY_CHECK(MY_ISXDIGIT(pszString[9]));
	MY_CHECK(MY_ISXDIGIT(pszString[10]));
	MY_CHECK(MY_ISXDIGIT(pszString[11]));
	MY_CHECK(MY_ISXDIGIT(pszString[12]));
	MY_CHECK(pszString[13] == '-');
	MY_CHECK(MY_ISXDIGIT(pszString[14]));
	MY_CHECK(MY_ISXDIGIT(pszString[15]));
	MY_CHECK(MY_ISXDIGIT(pszString[16]));
	MY_CHECK(MY_ISXDIGIT(pszString[17]));
	MY_CHECK(pszString[18] == '-');
	MY_CHECK(MY_ISXDIGIT(pszString[19]));
	MY_CHECK(MY_ISXDIGIT(pszString[20]));
	MY_CHECK(MY_ISXDIGIT(pszString[21]));
	MY_CHECK(MY_ISXDIGIT(pszString[22]));
	MY_CHECK(pszString[23] == '-');
	MY_CHECK(MY_ISXDIGIT(pszString[24]));
	MY_CHECK(MY_ISXDIGIT(pszString[25]));
	MY_CHECK(MY_ISXDIGIT(pszString[26]));
	MY_CHECK(MY_ISXDIGIT(pszString[27]));
	MY_CHECK(MY_ISXDIGIT(pszString[28]));
	MY_CHECK(MY_ISXDIGIT(pszString[29]));
	MY_CHECK(MY_ISXDIGIT(pszString[30]));
	MY_CHECK(MY_ISXDIGIT(pszString[31]));
	MY_CHECK(MY_ISXDIGIT(pszString[32]));
	MY_CHECK(MY_ISXDIGIT(pszString[33]));
	MY_CHECK(MY_ISXDIGIT(pszString[34]));
	MY_CHECK(MY_ISXDIGIT(pszString[35]));
	if (fHaveBraces)
		MY_CHECK(pszString[36] == '}');
	MY_CHECK(!pszString[36 + fHaveBraces]);
#undef MY_ISXDIGIT
#undef MY_CHECK

	/*
	 * Inverse of RTUuidToStr (see above).
	 */
#define MY_TONUM(ch) (g_au8Digits[(ch) & 0xff])
	pUuid->Gen.u32TimeLow = RT_LE2H_U32((grub_uint32_t)MY_TONUM(pszString[0]) << 28
		| (grub_uint32_t)MY_TONUM(pszString[1]) << 24
		| (grub_uint32_t)MY_TONUM(pszString[2]) << 20
		| (grub_uint32_t)MY_TONUM(pszString[3]) << 16
		| (grub_uint32_t)MY_TONUM(pszString[4]) << 12
		| (grub_uint32_t)MY_TONUM(pszString[5]) << 8
		| (grub_uint32_t)MY_TONUM(pszString[6]) << 4
		| (grub_uint32_t)MY_TONUM(pszString[7]));
	pUuid->Gen.u16TimeMid = RT_LE2H_U16((grub_uint16_t)MY_TONUM(pszString[9]) << 12
		| (grub_uint16_t)MY_TONUM(pszString[10]) << 8
		| (grub_uint16_t)MY_TONUM(pszString[11]) << 4
		| (grub_uint16_t)MY_TONUM(pszString[12]));
	pUuid->Gen.u16TimeHiAndVersion = RT_LE2H_U16(
		(grub_uint16_t)MY_TONUM(pszString[14]) << 12
		| (grub_uint16_t)MY_TONUM(pszString[15]) << 8
		| (grub_uint16_t)MY_TONUM(pszString[16]) << 4
		| (grub_uint16_t)MY_TONUM(pszString[17]));
	pUuid->Gen.u8ClockSeqHiAndReserved = (grub_uint8_t)
		((grub_uint16_t)MY_TONUM(pszString[19]) << 4
		| (grub_uint16_t)MY_TONUM(pszString[20]));
	pUuid->Gen.u8ClockSeqLow = (grub_uint8_t)
		((grub_uint16_t)MY_TONUM(pszString[21]) << 4
		| (grub_uint16_t)MY_TONUM(pszString[22]));
	pUuid->Gen.au8Node[0] = (grub_uint8_t)(MY_TONUM(pszString[24]) << 4
		| MY_TONUM(pszString[25]));
	pUuid->Gen.au8Node[1] = (grub_uint8_t)(MY_TONUM(pszString[26]) << 4
		| MY_TONUM(pszString[27]));
	pUuid->Gen.au8Node[2] = (grub_uint8_t)(MY_TONUM(pszString[28]) << 4
		| MY_TONUM(pszString[29]));
	pUuid->Gen.au8Node[3] = (grub_uint8_t)(MY_TONUM(pszString[30]) << 4
		| MY_TONUM(pszString[31]));
	pUuid->Gen.au8Node[4] = (grub_uint8_t)(MY_TONUM(pszString[32]) << 4
		| MY_TONUM(pszString[33]));
	pUuid->Gen.au8Node[5] = (grub_uint8_t)(MY_TONUM(pszString[34]) << 4
		| MY_TONUM(pszString[35]));
#undef MY_TONUM
	return GRUB_ERR_NONE;
}

int
RTUuidCompareStr(PCRTUUID pUuid1, const char* pszString2)
{
	RTUUID Uuid2;

	/*
	 * Try convert the string to a UUID and then compare the two.
	 */
	RTUuidFromStr(&Uuid2, pszString2);

	return RTUuidCompare(pUuid1, &Uuid2);
}

/**
 * Generated using the pycrc tool using model crc-32c.
 */
static grub_uint32_t const g_au32Crc32C[] =
{
	0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xc79a971f, 0x35f1141c,
	0x26a1e7e8, 0xd4ca64eb, 0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b,
	0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24, 0x105ec76f, 0xe235446c,
	0xf165b798, 0x030e349b, 0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
	0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54, 0x5d1d08bf, 0xaf768bbc,
	0xbc267848, 0x4e4dfb4b, 0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a,
	0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35, 0xaa64d611, 0x580f5512,
	0x4b5fa6e6, 0xb93425e5, 0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
	0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45, 0xf779deae, 0x05125dad,
	0x1642ae59, 0xe4292d5a, 0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a,
	0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595, 0x417b1dbc, 0xb3109ebf,
	0xa0406d4b, 0x522bee48, 0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
	0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687, 0x0c38d26c, 0xfe53516f,
	0xed03a29b, 0x1f682198, 0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927,
	0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38, 0xdbfc821c, 0x2997011f,
	0x3ac7f2eb, 0xc8ac71e8, 0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
	0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096, 0xa65c047d, 0x5437877e,
	0x4767748a, 0xb50cf789, 0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859,
	0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46, 0x7198540d, 0x83f3d70e,
	0x90a324fa, 0x62c8a7f9, 0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
	0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36, 0x3cdb9bdd, 0xceb018de,
	0xdde0eb2a, 0x2f8b6829, 0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c,
	0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93, 0x082f63b7, 0xfa44e0b4,
	0xe9141340, 0x1b7f9043, 0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
	0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3, 0x55326b08, 0xa759e80b,
	0xb4091bff, 0x466298fc, 0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c,
	0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033, 0xa24bb5a6, 0x502036a5,
	0x4370c551, 0xb11b4652, 0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
	0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d, 0xef087a76, 0x1d63f975,
	0x0e330a81, 0xfc588982, 0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d,
	0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622, 0x38cc2a06, 0xcaa7a905,
	0xd9f75af1, 0x2b9cd9f2, 0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
	0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530, 0x0417b1db, 0xf67c32d8,
	0xe52cc12c, 0x1747422f, 0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff,
	0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0, 0xd3d3e1ab, 0x21b862a8,
	0x32e8915c, 0xc083125f, 0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
	0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90, 0x9e902e7b, 0x6cfbad78,
	0x7fab5e8c, 0x8dc0dd8f, 0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee,
	0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1, 0x69e9f0d5, 0x9b8273d6,
	0x88d28022, 0x7ab90321, 0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
	0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81, 0x34f4f86a, 0xc69f7b69,
	0xd5cf889d, 0x27a40b9e, 0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e,
	0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351
};

static grub_uint32_t
rtCrc32CProcessWithTable(const grub_uint32_t* pau32Crc32,
	grub_uint32_t uCrc32, const void* pv, grub_size_t cb)
{
	const grub_uint8_t* pu8 = (const grub_uint8_t*)pv;

	while (cb--)
		uCrc32 = pau32Crc32[(uCrc32 ^ *pu8++) & 0xff] ^ (uCrc32 >> 8);

	return uCrc32;
}

static grub_uint32_t
RTCrc32CStart(void)
{
	return ~0U;
}

static grub_uint32_t
RTCrc32CFinish(grub_uint32_t uCRC32)
{
	return uCRC32 ^ ~0U;
}

grub_uint32_t
RTCrc32C(const void* pv, grub_size_t cb)
{
	grub_uint32_t uCrc32C = RTCrc32CStart();

	uCrc32C = rtCrc32CProcessWithTable(g_au32Crc32C, uCrc32C, pv, cb);
	return RTCrc32CFinish(uCrc32C);
}

/** @def RTBASE64_EOL_SIZE
 * The size of the end-of-line marker. */
#if defined(_WIN32)
# define RTBASE64_EOL_SIZE      (sizeof("\r\n") - 1)
#else
# define RTBASE64_EOL_SIZE      (sizeof("\n")   - 1)
#endif


/** Insert line breaks into encoded string.
 * The size of the end-of-line marker is that that of the host platform.
 */
#define RTBASE64_FLAGS_EOL_NATIVE       0U /**< Use native newlines. */
#define RTBASE64_FLAGS_NO_LINE_BREAKS   1U /**< No newlines.  */
#define RTBASE64_FLAGS_EOL_LF           2U /**< Use UNIX-style newlines. */
#define RTBASE64_FLAGS_EOL_CRLF         3U /**< Use DOS-style newlines. */
#define RTBASE64_FLAGS_EOL_STYLE_MASK   3U /**< End-of-line style mask. */

/** The line length used for encoding. */
#define RTBASE64_LINE_LEN   64

#define BASE64_SPACE        0xc0
#define BASE64_PAD          0xe0
#define BASE64_NULL         0xfe
#define BASE64_INVALID      0xff

/** Base64 character to value. (RFC 2045)
 * ASSUMES ASCII / UTF-8. */
static const grub_uint8_t g_au8rtBase64CharToVal[256] =
{
	0xfe, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xc0, 0xc0, 0xc0,   0xc0, 0xc0, 0xff, 0xff, /* 0x00..0x0f */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0x10..0x1f */
	0xc0, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff,   62,   0xff, 0xff, 0xff,   63, /* 0x20..0x2f */
	  52,   53,   54,   55,     56,   57,   58,   59,     60,   61, 0xff, 0xff,   0xff, 0xe0, 0xff, 0xff, /* 0x30..0x3f */
	0xff,    0,    1,    2,      3,    4,    5,    6,      7,    8,    9,   10,     11,   12,   13,   14, /* 0x40..0x4f */
	  15,   16,   17,   18,     19,   20,   21,   22,     23,   24,   25, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0x50..0x5f */
	0xff,   26,   27,   28,     29,   30,   31,   32,     33,   34,   35,   36,     37,   38,   39,   40, /* 0x60..0x6f */
	  41,   42,   43,   44,     45,   46,   47,   48,     49,   50,   51, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0x70..0x7f */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0x80..0x8f */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0x90..0x9f */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0xa0..0xaf */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0xb0..0xbf */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0xc0..0xcf */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0xd0..0xdf */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff, /* 0xe0..0xef */
	0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff,   0xff, 0xff, 0xff, 0xff  /* 0xf0..0xff */
};

/** Value to Base64 character. (RFC 2045) */
static const char g_szrtBase64ValToChar[64 + 1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** The end-of-line lengths (indexed by style flag value). */
static const grub_size_t g_acchrtBase64EolStyles[RTBASE64_FLAGS_EOL_STYLE_MASK + 1] =
{
	/*[RTBASE64_FLAGS_EOL_NATIVE    ]:*/ RTBASE64_EOL_SIZE,
	/*[RTBASE64_FLAGS_NO_LINE_BREAKS]:*/ 0,
	/*[RTBASE64_FLAGS_EOL_LF        ]:*/ 1,
	/*[RTBASE64_FLAGS_EOL_CRLF      ]:*/ 2
};

/** The end-of-line characters (zero, one or two). */
static const char g_aachrtBase64EolStyles[RTBASE64_FLAGS_EOL_STYLE_MASK + 1][2] =
{
	/*[RTBASE64_FLAGS_EOL_NATIVE    ]:*/ { RTBASE64_EOL_SIZE == 1 ? '\n' : '\r', RTBASE64_EOL_SIZE == 1 ? '\0' : '\n', },
	/*[RTBASE64_FLAGS_NO_LINE_BREAKS]:*/ { '\0', '\0' },
	/*[RTBASE64_FLAGS_EOL_LF        ]:*/ { '\n', '\0' },
	/*[RTBASE64_FLAGS_EOL_CRLF      ]:*/ { '\r', '\n' },
};

/** Fetched the next character in the string and translates it. */
static grub_uint8_t rtBase64TranslateNext(const char* pszString, grub_size_t cchStringMax)
{
	if (cchStringMax > 0)
		return g_au8rtBase64CharToVal[(unsigned char)*pszString];
	return BASE64_NULL;
}

/**
 * Recalcs 6-bit to 8-bit and adjust for padding.
 */
static grub_ssize_t rtBase64DecodedSizeRecalc(grub_uint32_t c6Bits, unsigned cbPad)
{
	size_t cb;
	if (c6Bits * 3 / 3 == c6Bits)
	{
		if ((c6Bits * 3 % 4) != 0)
			return -1;
		cb = c6Bits * 3 / 4;
	}
	else
	{
		if ((c6Bits * (grub_uint64_t)3 % 4) != 0)
			return -1;
		cb = c6Bits * (grub_uint64_t)3 / 4;
	}

	if (cb < cbPad)
		return -1;
	cb -= cbPad;
	return cb;
}

/*
 * Mostly the same as RTBase64DecodedUtf16SizeEx, except for the simpler
 * character type.  Fixes must be applied to both copies of the code.
 */
static grub_ssize_t RTBase64DecodedSizeEx(const char* pszString, grub_size_t cchStringMax, char** ppszEnd)
{
	/*
	 * Walk the string until a non-encoded or non-space character is encountered.
	 */
	grub_uint32_t    c6Bits = 0;
	grub_uint8_t     u8;

	while ((u8 = rtBase64TranslateNext(pszString, cchStringMax)) != BASE64_NULL)
	{
		if (u8 < 64)
			c6Bits++;
		else if (u8 != BASE64_SPACE)
			break;

		/* advance */
		pszString++;
		cchStringMax--;
	}

	/*
	 * Padding can only be found at the end and there is
	 * only 1 or 2 padding chars. Deal with it first.
	 */
	unsigned    cbPad = 0;
	if (u8 == BASE64_PAD)
	{
		cbPad = 1;
		c6Bits++;
		pszString++;
		cchStringMax--;
		while ((u8 = rtBase64TranslateNext(pszString, cchStringMax)) != BASE64_NULL)
		{
			if (u8 != BASE64_SPACE)
			{
				if (u8 != BASE64_PAD)
					break;
				c6Bits++;
				cbPad++;
			}
			pszString++;
			cchStringMax--;
		}
		if (cbPad >= 3)
			return -1;
	}

	/*
	 * Invalid char and no where to indicate where the
	 * Base64 text ends? Return failure.
	 */
	if (u8 == BASE64_INVALID
		&& !ppszEnd)
		return -1;

	/*
	 * Recalc 6-bit to 8-bit and adjust for padding.
	 */
	if (ppszEnd)
		*ppszEnd = (char*)pszString;
	return rtBase64DecodedSizeRecalc(c6Bits, cbPad);
}

grub_ssize_t RTBase64DecodedSize(const char* pszString, char** ppszEnd)
{
	return RTBase64DecodedSizeEx(pszString, RTSTR_MAX, ppszEnd);
}

static int RTBase64DecodeEx(const char* pszString, grub_size_t cchStringMax, void* pvData, grub_size_t cbData,
	grub_size_t* pcbActual, char** ppszEnd)
{
	/*
	 * Process input in groups of 4 input / 3 output chars.
	 */
	grub_uint8_t     u8Trio[3] = { 0, 0, 0 }; /* shuts up gcc */
	grub_uint8_t* pbData = (grub_uint8_t*)pvData;
	grub_uint8_t     u8;
	unsigned    c6Bits = 0;

	for (;;)
	{
		/* The first 6-bit group. */
		while ((u8 = rtBase64TranslateNext(pszString, cchStringMax)) == BASE64_SPACE)
			pszString++, cchStringMax--;
		if (u8 >= 64)
		{
			c6Bits = 0;
			break;
		}
		u8Trio[0] = (grub_uint8_t)(u8 << 2);
		pszString++;
		cchStringMax--;

		/* The second 6-bit group. */
		while ((u8 = rtBase64TranslateNext(pszString, cchStringMax)) == BASE64_SPACE)
			pszString++, cchStringMax--;
		if (u8 >= 64)
		{
			c6Bits = 1;
			break;
		}
		u8Trio[0] |= (grub_uint8_t)(u8 >> 4);
		u8Trio[1] = (grub_uint8_t)(u8 << 4);
		pszString++;
		cchStringMax--;

		/* The third 6-bit group. */
		u8 = BASE64_INVALID;
		while ((u8 = rtBase64TranslateNext(pszString, cchStringMax)) == BASE64_SPACE)
			pszString++, cchStringMax--;
		if (u8 >= 64)
		{
			c6Bits = 2;
			break;
		}
		u8Trio[1] |= (grub_uint8_t)(u8 >> 2);
		u8Trio[2] = (grub_uint8_t)(u8 << 6);
		pszString++;
		cchStringMax--;

		/* The fourth 6-bit group. */
		u8 = BASE64_INVALID;
		while ((u8 = rtBase64TranslateNext(pszString, cchStringMax)) == BASE64_SPACE)
			pszString++, cchStringMax--;
		if (u8 >= 64)
		{
			c6Bits = 3;
			break;
		}
		u8Trio[2] |= u8;
		pszString++;
		cchStringMax--;

		/* flush the trio */
		if (cbData < 3)
			return GRUB_ERR_OUT_OF_RANGE;
		cbData -= 3;
		pbData[0] = u8Trio[0];
		pbData[1] = u8Trio[1];
		pbData[2] = u8Trio[2];
		pbData += 3;
	}

	/*
	 * Padding can only be found at the end and there is
	 * only 1 or 2 padding chars. Deal with it first.
	 */
	unsigned cbPad = 0;
	if (u8 == BASE64_PAD)
	{
		cbPad = 1;
		pszString++;
		cchStringMax--;
		while ((u8 = rtBase64TranslateNext(pszString, cchStringMax)) != BASE64_NULL)
		{
			if (u8 != BASE64_SPACE)
			{
				if (u8 != BASE64_PAD)
					break;
				cbPad++;
			}
			pszString++;
			cchStringMax--;
		}
		if (cbPad >= 3)
			return GRUB_ERR_BAD_ARGUMENT;
	}

	/*
	 * Invalid char and no where to indicate where the
	 * Base64 text ends? Return failure.
	 */
	if (u8 == BASE64_INVALID
		&& !ppszEnd)
		return GRUB_ERR_BAD_ARGUMENT;

	/*
	 * Check padding vs. pending sextets, if anything left to do finish it off.
	 */
	if (c6Bits || cbPad)
	{
		if (c6Bits + cbPad != 4)
			return GRUB_ERR_BAD_ARGUMENT;

		switch (c6Bits)
		{
		case 1:
			u8Trio[1] = u8Trio[2] = 0;
			break;
		case 2:
			u8Trio[2] = 0;
			break;
		case 3:
		default:
			break;
		}
		switch (3 - cbPad)
		{
		case 1:
			if (cbData < 1)
				return GRUB_ERR_OUT_OF_RANGE;
			cbData--;
			pbData[0] = u8Trio[0];
			pbData++;
			break;

		case 2:
			if (cbData < 2)
				return GRUB_ERR_OUT_OF_RANGE;
			cbData -= 2;
			pbData[0] = u8Trio[0];
			pbData[1] = u8Trio[1];
			pbData += 2;
			break;

		default:
			break;
		}
	}

	/*
	 * Set optional return values and return successfully.
	 */
	if (ppszEnd)
		*ppszEnd = (char*)pszString;
	if (pcbActual)
		*pcbActual = pbData - (grub_uint8_t*)pvData;
	return GRUB_ERR_NONE;
}

int RTBase64Decode(const char* pszString, void* pvData, grub_size_t cbData, grub_size_t* pcbActual, char** ppszEnd)
{
	return RTBase64DecodeEx(pszString, RTSTR_MAX, pvData, cbData, pcbActual, ppszEnd);
}

int
RTZipBlockDecompress(RTZIPTYPE enmType, grub_uint32_t fFlags,
	void const* pvSrc, grub_size_t cbSrc, grub_size_t* pcbSrcActual,
	void* pvDst, grub_size_t cbDst, grub_size_t* pcbDstActual)
{
	(void)fFlags;

	/*
	 * Deal with flags involving prefixes.
	 */
	 /** @todo later: type and/or compressed length prefix. */

	 /*
	  * The type specific part.
	  */
	switch (enmType)
	{
	case RTZIPTYPE_LZF:
	{
#ifdef RTZIP_USE_LZF
		unsigned cbDstActual = lzf_decompress(pvSrc, (unsigned)cbSrc, pvDst, (unsigned)cbDst);  /** @todo deal with size type overflows */
		if (RT_UNLIKELY(cbDstActual < 1))
		{
# ifndef IPRT_NO_CRT /* no errno */
			if (errno == E2BIG)
				return VERR_BUFFER_OVERFLOW;
			Assert(errno == EINVAL);
# endif
			return VERR_GENERAL_FAILURE;
		}
		if (pcbDstActual)
			*pcbDstActual = cbDstActual;
		if (pcbSrcActual)
			*pcbSrcActual = cbSrc;
		break;
#else
		return GRUB_ERR_NOT_IMPLEMENTED_YET;
#endif
	}

	case RTZIPTYPE_STORE:
	{
		if (cbDst < cbSrc)
			return GRUB_ERR_OUT_OF_RANGE;
		grub_memcpy(pvDst, pvSrc, cbSrc);
		if (pcbDstActual)
			*pcbDstActual = cbSrc;
		if (pcbSrcActual)
			*pcbSrcActual = cbSrc;
		break;
	}

	case RTZIPTYPE_LZJB:
	{
#ifdef RTZIP_USE_LZJB
		if (*(grub_uint8_t*)pvSrc == 1)
		{
			int rc = lzjb_decompress((grub_uint8_t*)pvSrc + 1, pvDst, cbSrc - 1, cbDst, 0 /*??*/);
			if (RT_UNLIKELY(rc != 0))
				return VERR_GENERAL_FAILURE;
			if (pcbDstActual)
				*pcbDstActual = cbDst;
		}
		else
		{
			AssertReturn(cbDst >= cbSrc - 1, VERR_BUFFER_OVERFLOW);
			memcpy(pvDst, (grub_uint8_t*)pvSrc + 1, cbSrc - 1);
			if (pcbDstActual)
				*pcbDstActual = cbSrc - 1;
		}
		if (pcbSrcActual)
			*pcbSrcActual = cbSrc;
		break;
#else
		return GRUB_ERR_NOT_IMPLEMENTED_YET;
#endif
	}

	case RTZIPTYPE_LZO:
	{
		int rc = lzo_init();
		if (rc != LZO_E_OK)
			return GRUB_ERR_BAD_COMPRESSED_DATA;
		lzo_uint cbDstInOut = (lzo_uint)cbDst;
		rc = lzo1x_decompress((const lzo_bytep)pvSrc, (lzo_uint)cbSrc, (lzo_bytep)pvDst, &cbDstInOut, NULL);
		if (rc != LZO_E_OK)
			switch (rc)
			{
			case LZO_E_OUTPUT_OVERRUN:  return GRUB_ERR_OUT_OF_RANGE;
			default:
			case LZO_E_INPUT_OVERRUN:   return GRUB_ERR_BAD_COMPRESSED_DATA;
			}
		if (pcbSrcActual)
			*pcbSrcActual = cbSrc;
		if (pcbDstActual)
			*pcbDstActual = cbDstInOut;
		break;
	}
	case RTZIPTYPE_ZLIB:
	{
		grub_ssize_t cbDstActual = grub_zlib_decompress((void *)pvSrc, cbSrc, 0, pvDst, cbDst);
		if (cbDstActual < 0)
			return GRUB_ERR_BAD_COMPRESSED_DATA;
		if (pcbSrcActual)
			*pcbSrcActual = cbSrc;
		if (pcbDstActual)
			*pcbDstActual = cbDstActual;
		break;
	}
	case RTZIPTYPE_ZLIB_NO_HEADER:
	{
		grub_ssize_t cbDstActual = grub_deflate_decompress((void*)pvSrc, cbSrc, 0, pvDst, cbDst);
		if (cbDstActual < 0)
			return GRUB_ERR_BAD_COMPRESSED_DATA;
		if (pcbSrcActual)
			*pcbSrcActual = cbSrc;
		if (pcbDstActual)
			*pcbDstActual = cbDstActual;
		break;
	}
	case RTZIPTYPE_BZLIB:
		return GRUB_ERR_NOT_IMPLEMENTED_YET;

	default:
		return GRUB_ERR_BAD_ARGUMENT;
	}
	return GRUB_ERR_NONE;
}
