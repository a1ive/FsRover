/* Product API recovery and cooperative cancellation regression. GPL-3.0-or-later. */
#include <rover.h>
#include "../common/extract_core.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

static void require (bool value, const char *message)
{
	if (!value)
		throw std::runtime_error (message);
}

static int collect (const rover_dirent *, void *opaque)
{
	++*static_cast<unsigned *> (opaque);
	return 0;
}

static void attach (const char *name, const std::filesystem::path &path)
{
#ifdef _WIN32
	const auto utf8 = path.u8string ();
	int error = rover_winfile_add (name, reinterpret_cast<const char *> (utf8.c_str ()), 0);
#else
	int error = rover_posixfile_add (name, path.c_str (), 0);
#endif
	require (!error, "attach failed");
}

static void check_good ()
{
	unsigned count = 0;
	require (!rover_dir_list ("(good)/", collect, &count) && count == 3,
		"good directory did not recover");
	require (!rover_last_error (), "stale error after successful enumeration");
	rover_file *file = rover_file_open ("(good)/hello.txt");
	require (file != nullptr, "good file did not recover");
	char buffer[1024];
	long long size = rover_file_read (file, buffer, sizeof (buffer));
	bool correct = size == 840;
	for (long long i = 0; correct && i < size; i++)
		correct = buffer[i] == "FAT12 payload\n"[i % 14];
	bool eof = rover_file_read (file, buffer, sizeof (buffer)) == 0;
	rover_file_close (file);
	require (correct && eof, "good file content/EOF changed after failure");
}

static void run (const std::filesystem::path &fixtures, const std::filesystem::path &out)
{
	attach ("bad", fixtures / "unknown.img");
	attach ("broken", fixtures / "broken.img");
	attach ("good", fixtures / "basic.img");
	attach ("cancel", fixtures / "cancel.tar");
	for (int attempt = 0; attempt < 3; attempt++)
	{
		unsigned count = 0;
		require (rover_dir_list ("(bad)/", collect, &count) != 0,
			"unknown filesystem unexpectedly listed");
		require (rover_last_error () != nullptr, "failure missing diagnostic");
		check_good ();
		require (!rover_file_open ("(good)/missing"), "missing file unexpectedly opened");
		check_good ();
		rover_file *file = rover_file_open ("(broken)/bad.bin");
		require (file != nullptr, "broken-chain fixture failed before read");
		char buffer[2048];
		long long size = rover_file_read (file, buffer, sizeof (buffer));
		rover_file_close (file);
		require (size < 0, "broken chain unexpectedly read");
		check_good ();
	}
	puts ("PASS same-process recovery");

	bool requested = false, saw_written = false;
	std::filesystem::create_directories (out / "cancel");
	{
		std::ofstream sentinel (out / "cancel" / "keep.txt", std::ios::binary);
		sentinel << "existing destination";
		require (sentinel.good (), "cannot create cancellation sentinel");
	}
	rover_extract::options options;
	// service() executes between driver calls. Trigger only after actual bytes
	// reached the host file, without timing, threads or re-entering Rover.
	options.service = [&] ()
	{
		std::error_code error;
		auto size = std::filesystem::file_size (out / "cancel" / "large.bin", error);
		if (!error && size >= (1U << 20))
			requested = saw_written = true;
	};
	options.cancelled = [&] () { return requested; };
	rover_extract::result stats;
	std::string error;
	bool ok = rover_extract::extract ({ "(good)/hello.txt", "(cancel)/large.bin", "(cancel)/after.txt" },
		(out / "cancel").native (), options, &stats, &error);
	require (!ok && saw_written && error == "extraction cancelled", "cancellation not exercised");
	require (stats.files == 1 && stats.bytes == 840 && stats.errors.empty (),
		"cancelled file counted as success/error or completed file lost");
	require (!std::filesystem::exists (out / "cancel" / "large.bin")
		&& !std::filesystem::exists (out / "cancel" / "after.txt"), "cancelled output/next file retained");
	check_good ();

	// Reuse the same process and core after cancellation.
	options = {};
	ok = rover_extract::extract ({ "(good)/hello.txt" }, (out / "recovered").native (),
		options, &stats, &error);
	require (ok && stats.files == 1 && stats.bytes == 840 && error.empty (),
		"extraction did not recover after cancellation");
	puts ("PASS cancellation rollback and recovery");
}

#ifdef _WIN32
int wmain (int argc, wchar_t **argv)
#else
int main (int argc, char **argv)
#endif
{
	if (argc != 3)
		return 2;
	rover_init (ROVER_INIT_NO_HOSTDISK);
	int status = 0;
	try
	{
		run (std::filesystem::path (argv[1]), std::filesystem::path (argv[2]));
	}
	catch (const std::exception &error)
	{
		fprintf (stderr, "FAIL: %s\n", error.what ());
		status = 1;
	}
	rover_fini ();
	return status;
}
