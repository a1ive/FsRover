cmake_minimum_required(VERSION 3.21)

project(FsRover VERSION 0.1 LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
	message(FATAL_ERROR "The CMake build currently targets Linux; use Rover.slnx on Windows")
endif()

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

# Keep the Linux archive in lockstep with the curated MSVC source inventory.
# CMake substitutes the two host backends below; GUI-only sources are never read.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/grub/grub.vcxproj" GRUB_PROJECT_XML)
string(REGEX MATCHALL "<ClCompile Include=\"[^\"]+\\.c\"" GRUB_SOURCE_TAGS "${GRUB_PROJECT_XML}")
set(GRUB_SOURCES)
foreach(TAG IN LISTS GRUB_SOURCE_TAGS)
	string(REGEX REPLACE ".*Include=\"([^\"]+)\".*" "\\1" SOURCE "${TAG}")
	string(REPLACE "\\" "/" SOURCE "${SOURCE}")
	if(NOT SOURCE MATCHES "grub-core/disk/(windisk|winfile)\\.c$")
		list(APPEND GRUB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/grub/${SOURCE}")
	endif()
endforeach()
list(APPEND GRUB_SOURCES
	"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/disk/posixdisk.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/disk/posixfile.c")

set_property(SOURCE
	"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/libgcrypt/const-time.c"
	APPEND PROPERTY COMPILE_OPTIONS -include stdint.h)

add_library(rover-grub STATIC ${GRUB_SOURCES})
target_include_directories(rover-grub
	PUBLIC
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/rover"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/include"
	PRIVATE
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/7z"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/brotli/include"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/json"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/libzbitmap"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/lzfse"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/lz4"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/minilzo"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/miniz"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/mscab"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/unrar"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/vbox"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/wimboot"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/xzembed"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/yxml"
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/zstd")
target_compile_definitions(rover-grub PRIVATE
	GRUB=1
	GRUB_MACHINE_EMU=1
	MINIZ_NO_STDIO
	MINIZ_NO_DEFLATE_APIS
	Z7_CRC_NUM_TABLES=1
	Z7_PPMD_SUPPORT)
target_compile_options(rover-grub PRIVATE
	-include "${CMAKE_CURRENT_SOURCE_DIR}/grub/rover/config.h"
	-Wall -Wextra -Werror
	-Wno-unused-parameter
	-Wno-unused-function
	-Wno-sign-compare
	-Wno-missing-field-initializers
	-Wno-unknown-pragmas
	-Wno-comment
	-Wno-maybe-uninitialized
	-Wno-format
	-Wno-parentheses
	-Wno-type-limits
	-Wno-unused-const-variable
	-Wno-pointer-sign
	-Wno-unused-but-set-variable
	-Wno-unused-variable
	-Wno-implicit-fallthrough)

add_executable(LinuxRover
	LinuxRover/main.cpp
	common/fusefs.cpp)
target_include_directories(LinuxRover PRIVATE
	"${CMAKE_CURRENT_SOURCE_DIR}/common"
	"${CMAKE_CURRENT_SOURCE_DIR}/FsRover"
	"${CMAKE_CURRENT_SOURCE_DIR}/grub/rover")
target_compile_options(LinuxRover PRIVATE -Wall -Wextra -Werror)
target_link_libraries(LinuxRover PRIVATE rover-grub PkgConfig::FUSE3 pthread)

install(TARGETS LinuxRover RUNTIME DESTINATION bin)
