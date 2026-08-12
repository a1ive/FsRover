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

#pragma once

#define QUOTE_(x) #x
#define QUOTE(x) QUOTE_(x)

#define ROVER_MAJOR_VERSION 0
#define ROVER_MINOR_VERSION 3
#define ROVER_MICRO_VERSION 4
#define ROVER_BUILD_VERSION 0

#define ROVER_VERSION   ROVER_MAJOR_VERSION,ROVER_MINOR_VERSION,ROVER_MICRO_VERSION,ROVER_BUILD_VERSION
#define ROVER_VERSION_STR  QUOTE(ROVER_MAJOR_VERSION.ROVER_MINOR_VERSION.ROVER_MICRO_VERSION.ROVER_BUILD_VERSION)

#define ROVER_COMPANY      "A1ive"
#define ROVER_COPYRIGHT    "Copyright (c) 2026 A1ive"
#define ROVER_FILEDESC     "FsRover -- Filesystem browser"

#define ROVER_NAME         "Rover"
#define ROVER_PRODUCT      ROVER_NAME
#define ROVER_INTERNALNAME ROVER_NAME
#define ROVER_ORIGINALNAME ROVER_NAME ".exe"
