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

# libFuzzer build: instruments rover-grub and builds fuzz targets only.
option(ROVER_FUZZ "Build libFuzzer targets instead of LinuxRover" OFF)
set(ROVER_FUZZ_SANITIZERS "address,undefined" CACHE STRING
	"Sanitizers combined with -fsanitize=fuzzer")

if(ROVER_FUZZ)
	if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
		message(FATAL_ERROR "ROVER_FUZZ requires Clang (CC=clang CXX=clang++)")
	endif()
	set(ROVER_FUZZ_FLAGS -g -O1 -fno-omit-frame-pointer)
	if(ROVER_FUZZ_SANITIZERS)
		list(APPEND ROVER_FUZZ_FLAGS -fsanitize=${ROVER_FUZZ_SANITIZERS} -fno-sanitize-recover=all)
	endif()
else()
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)
endif()

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
		"${CMAKE_CURRENT_SOURCE_DIR}/grub/grub-core/lib/bzip2"
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
	$<$<C_COMPILER_ID:GNU>:-Wno-maybe-uninitialized>
	-Wno-format
	-Wno-parentheses
	-Wno-type-limits
	$<$<C_COMPILER_ID:Clang>:-Wno-tautological-constant-out-of-range-compare>
	-Wno-unused-const-variable
	-Wno-pointer-sign
	-Wno-unused-but-set-variable
	-Wno-unused-variable
	-Wno-implicit-fallthrough)

if(ROVER_FUZZ)
	target_compile_definitions(rover-grub PRIVATE ROVER_FUZZ=1)
	target_compile_options(rover-grub PRIVATE ${ROVER_FUZZ_FLAGS} -fsanitize=fuzzer-no-link)
	if(ROVER_FUZZ_SANITIZERS)
		# GRUB_AS_LIST() and RT_UOFFSETOF() take &((T *) 0)->field; real NULL
		# loads still fault and ASan already covers object bounds.
		target_compile_options(rover-grub PRIVATE -fno-sanitize=null,object-size)
	endif()
	target_link_options(rover-grub INTERFACE ${ROVER_FUZZ_FLAGS})

	add_executable(fs_fuzz fuzz/fs_fuzz.c)
	target_compile_options(fs_fuzz PRIVATE -Wall -Wextra -Werror ${ROVER_FUZZ_FLAGS} -fsanitize=fuzzer)
	target_link_options(fs_fuzz PRIVATE -fsanitize=fuzzer)
	target_link_libraries(fs_fuzz PRIVATE rover-grub)
	return()
endif()

add_executable(LinuxRover
	LinuxRover/main.cpp
	common/fusefs.cpp
	common/extract_core.cpp)
target_include_directories(LinuxRover PRIVATE
	"${CMAKE_CURRENT_SOURCE_DIR}/common"
	"${CMAKE_CURRENT_SOURCE_DIR}/FsRover"
	"${CMAKE_CURRENT_SOURCE_DIR}/grub/rover")
target_compile_options(LinuxRover PRIVATE -Wall -Wextra -Werror)
target_link_libraries(LinuxRover PRIVATE rover-grub PkgConfig::FUSE3 pthread)

install(TARGETS LinuxRover RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
	find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
	add_executable(product_probe tests/product_probe.cpp tests/fusefs_probe.cpp tests/readlink_probe.cpp tests/filemap_probe.c tests/printf_probe.c tests/strtol_probe.c
		common/extract_core.cpp common/fusefs.cpp)
	set_property(SOURCE tests/filemap_probe.c tests/printf_probe.c tests/strtol_probe.c APPEND PROPERTY COMPILE_OPTIONS
		-include "${CMAKE_CURRENT_SOURCE_DIR}/grub/rover/config.h")
	target_compile_options(product_probe PRIVATE -Wall -Wextra -Werror)
	target_link_libraries(product_probe PRIVATE rover-grub pthread)
	add_test(NAME product-regression
		COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_product.py"
			--cli $<TARGET_FILE:LinuxRover> --probe $<TARGET_FILE:product_probe>
			--output "${CMAKE_CURRENT_BINARY_DIR}/product-tests")
	set_tests_properties(product-regression PROPERTIES TIMEOUT 300)
endif()
