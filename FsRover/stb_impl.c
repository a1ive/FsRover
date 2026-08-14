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

/* Third-party image decoder implementation unit, kept out of the C++
   viewer so the large single headers are compiled once as plain C.  */

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_STDIO

#include "stb_image.h"

#pragma warning(push)
#pragma warning(disable: 4244)

#define NANOSVG_ALL_COLOR_KEYWORDS
#define NANOSVG_IMPLEMENTATION

#include "nanosvg/nanosvg.h"

#define NANOSVGRAST_IMPLEMENTATION

#include "nanosvg/nanosvgrast.h"

#pragma warning(pop)

#define twp_IMPLEMENTATION
#define twp_NO_SIMD

#include "tiny-webp/tiny_webp.h"
