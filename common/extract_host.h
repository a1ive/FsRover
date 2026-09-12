// Private destination filesystem adapter for extract_core.cpp.
#ifndef ROVER_EXTRACT_HOST_H
#define ROVER_EXTRACT_HOST_H
#include "extract_core.h"
#include <algorithm>
#include <climits>
#ifdef _WIN32
#include <windows.h>
#include <cwchar>
#else
#include <cerrno>
#include <fcntl.h>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace rover_extract
{
namespace
{
constexpr size_t MAX_COMPONENT_LENGTH = 255;
#ifdef _WIN32
using host_handle = HANDLE;
const host_handle invalid_host_handle = INVALID_HANDLE_VALUE;
host_path
widen (const std::string &text)
{
	if (text.empty () || text.size () > INT_MAX)
		return {};
	int len = MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS,
		text.data (), static_cast<int> (text.size ()), nullptr, 0);
	if (!len)
		return {};
	host_path wide (static_cast<size_t> (len), L'\0');
	MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS, text.data (),
		static_cast<int> (text.size ()), wide.data (), len);
	return wide;
}

host_path
sanitize_component (const std::string &name)
{
	host_path out = widen (name);

	for (wchar_t &c : out)
		if (c < 32 || wcschr (L"<>:\"/\\|?*", c))
			c = L'_';
	if (out.empty ())
		out = L"_";
	while (out.back () == L'.' || out.back () == L' ')
		out.back () = L'_';

	size_t dot = out.find (L'.');
	host_path stem = out.substr (0, dot);
	while (!stem.empty () && (stem.back () == L'.' || stem.back () == L' '))
		stem.pop_back ();
	auto reserved = [&stem] (const wchar_t *word)
	{
		return CompareStringOrdinal (stem.c_str (), static_cast<int> (stem.size ()),
			word, -1, TRUE) == CSTR_EQUAL;
	};
	bool device = reserved (L"CON") || reserved (L"PRN")
		|| reserved (L"AUX") || reserved (L"NUL");
	if (!device && stem.size () == 4)
	{
		wchar_t digit = stem[3];
		bool numbered = (digit >= L'1' && digit <= L'9')
			|| digit == 0x00b9 || digit == 0x00b2 || digit == 0x00b3;
		host_path prefix = stem.substr (0, 3);
		device = numbered
			&& (CompareStringOrdinal (prefix.c_str (), 3, L"COM", 3, TRUE)
				== CSTR_EQUAL
				|| CompareStringOrdinal (prefix.c_str (), 3, L"LPT", 3, TRUE)
				== CSTR_EQUAL);
	}
	if (device)
		out.insert (dot == host_path::npos ? out.size () : dot, 1, L'_');
	if (out.size () > MAX_COMPONENT_LENGTH)
	{
		out.resize (MAX_COMPONENT_LENGTH);
		if (out.back () >= 0xd800 && out.back () <= 0xdbff)
			out.pop_back ();
	}
	return out;
}

host_path
numbered_component (const host_path &base, unsigned long long number,
	bool is_dir)
{
	host_path suffix = L" (" + std::to_wstring (number) + L')';
	size_t insert = base.size ();
	if (!is_dir)
	{
		size_t dot = base.find_last_of (L'.');
		if (dot != host_path::npos && dot != 0)
			insert = dot;
	}

	host_path out = base;
	if (out.size () + suffix.size () > MAX_COMPONENT_LENGTH)
	{
		size_t overflow = out.size () + suffix.size () - MAX_COMPONENT_LENGTH;
		if (insert > overflow)
		{
			out.erase (insert - overflow, overflow);
			insert -= overflow;
		}
		else
		{
			out.resize (MAX_COMPONENT_LENGTH - suffix.size ());
			if (insert > out.size ())
				insert = out.size ();
		}
		if (insert && out[insert - 1] >= 0xd800 && out[insert - 1] <= 0xdbff)
			out[insert - 1] = L'_';
	}
	out.insert (insert, suffix);
	return out;
}

host_path
candidate_path (const host_path &parent, const host_path &base,
	unsigned long long number, bool is_dir)
{
	return parent + L'\\' + (number ? numbered_component (base, number, is_dir)
		: base);
}

/* Reserve each destination name with the creating Win32 call itself.  This
   follows the target filesystem's case and Unicode rules without a racy
   exists-then-create window, and keeps files and directories in one namespace.  */
bool
create_unique_directory (const host_path &parent, const host_path &base,
	host_path &target)
{
	for (unsigned long long number = 0;; number++)
	{
		target = candidate_path (parent, base, number, true);
		if (CreateDirectoryW (target.c_str (), nullptr))
			return true;
		DWORD winerr = GetLastError ();
		if (winerr != ERROR_ALREADY_EXISTS && winerr != ERROR_FILE_EXISTS)
			return false;
		if (number == ULLONG_MAX)
			return false;
	}
}

host_handle
create_unique_file (const host_path &parent, const host_path &base,
	host_path &target)
{
	for (unsigned long long number = 0;; number++)
	{
		target = candidate_path (parent, base, number, false);
		host_handle output = CreateFileW (target.c_str (), GENERIC_WRITE, 0,
			nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (output != INVALID_HANDLE_VALUE)
			return output;
		DWORD winerr = GetLastError ();
		bool collision = winerr == ERROR_ALREADY_EXISTS
			|| winerr == ERROR_FILE_EXISTS;
		if (!collision && winerr == ERROR_ACCESS_DENIED)
			collision = GetFileAttributesW (target.c_str ())
				!= INVALID_FILE_ATTRIBUTES;
		if (!collision)
			return INVALID_HANDLE_VALUE;
		if (number == ULLONG_MAX)
			return INVALID_HANDLE_VALUE;
	}
}

bool
unix_to_filetime (long long seconds, FILETIME *filetime)
{
	if (seconds < -11644473600LL || seconds > 1833029933770LL)
		return false;
	unsigned long long ticks = static_cast<unsigned long long> (
		(seconds + 11644473600LL) * 10000000LL);
	filetime->dwLowDateTime = static_cast<DWORD> (ticks);
	filetime->dwHighDateTime = static_cast<DWORD> (ticks >> 32);
	return true;
}

void
set_mtime (HANDLE handle, long long mtime)
{
	FILETIME filetime;

	if (mtime && unix_to_filetime (mtime, &filetime))
		SetFileTime (handle, nullptr, nullptr, &filetime);
}

host_path
long_path (host_path path)
{
	while (path.size () > 3 && (path.back () == L'\\' || path.back () == L'/'))
		path.pop_back ();
	if (path.rfind (L"\\\\?\\", 0) == 0)
		return path;
	if (path.rfind (L"\\\\", 0) == 0)
		return L"\\\\?\\UNC\\" + path.substr (2);
	return L"\\\\?\\" + path;
}

bool
create_one_directory (const host_path &path)
{
	if (CreateDirectoryW (path.c_str (), nullptr))
		return true;
	if (GetLastError () != ERROR_ALREADY_EXISTS)
		return false;
	DWORD attributes = GetFileAttributesW (path.c_str ());
	return attributes != INVALID_FILE_ATTRIBUTES
		&& (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool
create_directory_tree (const host_path &path)
{
	size_t start;

	if (path.rfind (L"\\\\?\\UNC\\", 0) == 0)
	{
		size_t server = path.find (L'\\', 8);
		if (server == host_path::npos)
			return false;
		size_t share = path.find (L'\\', server + 1);
		if (share == host_path::npos)
			return true;
		start = share + 1;
	}
	else if (path.rfind (L"\\\\?\\", 0) == 0)
		start = 7;
	else
		start = 3;

	for (size_t slash = path.find (L'\\', start);
		slash != host_path::npos; slash = path.find (L'\\', slash + 1))
		if (!create_one_directory (path.substr (0, slash)))
			return false;
	return create_one_directory (path);
}

bool write_output (host_handle file, const char *data, size_t size)
{
	DWORD written = 0;
	return WriteFile (file, data, static_cast<DWORD> (size), &written, nullptr)
		&& written == size;
}
bool close_output (host_handle file) { return CloseHandle (file) != FALSE; }
void remove_output (const host_path &path) { DeleteFileW (path.c_str ()); }
void stamp_directory (const host_path &path, long long mtime)
{
	HANDLE handle = CreateFileW (path.c_str (), FILE_WRITE_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
		OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	if (handle == INVALID_HANDLE_VALUE)
		return;
	set_mtime (handle, mtime);
	CloseHandle (handle);
}

#else
using host_handle = int;
constexpr host_handle invalid_host_handle = -1;

host_path sanitize_component (const std::string &name)
{
	host_path out = name;
	for (char &c : out)
		if (c == '/' || c == '\0') c = '_';
	if (out.empty () || out == "." || out == "..") out = "_";
	if (out.size () > MAX_COMPONENT_LENGTH) out.resize (MAX_COMPONENT_LENGTH);
	return out;
}

host_path candidate_path (const host_path &parent, const host_path &base,
	unsigned long long number, bool is_dir)
{
	host_path name = base;
	if (number)
	{
		std::string suffix = " (" + std::to_string (number) + ')';
		size_t insert = is_dir ? name.size () : name.find_last_of ('.');
		if (insert == std::string::npos || insert == 0) insert = name.size ();
		if (name.size () + suffix.size () > MAX_COMPONENT_LENGTH)
		{
			name.resize (MAX_COMPONENT_LENGTH - suffix.size ());
			insert = std::min (insert, name.size ());
		}
		name.insert (insert, suffix);
	}
	return parent + '/' + name;
}

bool create_unique_directory (const host_path &parent, const host_path &base,
	host_path &target)
{
	for (unsigned long long number = 0;; number++)
	{
		target = candidate_path (parent, base, number, true);
		if (mkdir (target.c_str (), 0777) == 0) return true;
		if (errno != EEXIST || number == ULLONG_MAX) return false;
	}
}

host_handle create_unique_file (const host_path &parent, const host_path &base,
	host_path &target)
{
	for (unsigned long long number = 0;; number++)
	{
		target = candidate_path (parent, base, number, false);
		int fd = open (target.c_str (), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
		if (fd >= 0) return fd;
		if (errno != EEXIST || number == ULLONG_MAX) return invalid_host_handle;
	}
}

void set_mtime (host_handle file, long long mtime)
{
	if (!mtime) return;
	timespec times[2] = { { 0, UTIME_OMIT }, { static_cast<time_t> (mtime), 0 } };
	futimens (file, times);
}

host_path long_path (const host_path &path) { return path; }

bool create_directory_tree (const host_path &path)
{
	std::error_code error;
	std::filesystem::create_directories (path, error);
	return !error && std::filesystem::is_directory (path, error);
}

bool write_output (host_handle file, const char *data, size_t size)
{
	while (size)
	{
		ssize_t written = write (file, data, size);
		if (written < 0 && errno == EINTR) continue;
		if (written <= 0) return false;
		data += written;
		size -= static_cast<size_t> (written);
	}
	return true;
}
bool close_output (host_handle file) { return close (file) == 0; }
void remove_output (const host_path &path) { unlink (path.c_str ()); }
void stamp_directory (const host_path &path, long long mtime)
{
	int fd = open (path.c_str (), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) return;
	set_mtime (fd, mtime);
	close (fd);
}

#endif
}
}
#endif
