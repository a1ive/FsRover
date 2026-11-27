/* Symbolic link target regression. GPL-3.0-or-later. */
#include <errno.h>
#include <rover.h>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace
{

void require (bool value, const std::string &message)
{
	if (!value)
		throw std::runtime_error (message);
}

void attach (const char *name, const std::filesystem::path &path)
{
#ifdef _WIN32
	const auto utf8 = path.u8string ();
	int error = rover_winfile_add (name, reinterpret_cast<const char *> (utf8.c_str ()), 0);
#else
	int error = rover_posixfile_add (name, path.c_str (), 0);
#endif
	require (!error, std::string ("attach failed: ") + name);
}

void target (const std::string &path, const std::string &expected)
{
	char buffer[256];
	unsigned long long length = 0;

	require (!rover_readlink (path.c_str (), buffer, sizeof (buffer), &length),
		path + ": " + (rover_last_error () ? rover_last_error () : "readlink failed"));
	require (buffer == expected && length == expected.size (),
		path + ": target `" + buffer + "', expected `" + expected + "'");
}

void fails (const std::string &path, int expected)
{
	char buffer[16] = "unchanged";

	require (rover_readlink (path.c_str (), buffer, sizeof (buffer), nullptr) != 0,
		path + ": readlink unexpectedly succeeded");
	require (rover_last_errno () == expected, path + ": errno "
		+ std::to_string (rover_last_errno ()) + ", expected " + std::to_string (expected));
	require (std::string (buffer) == "unchanged", path + ": buffer written on failure");
}

std::string content (const std::string &path)
{
	rover_file *file = rover_file_open (path.c_str ());
	require (file != nullptr, path + ": open failed");
	std::string data (static_cast<size_t> (rover_file_size (file)), '\0');
	long long got = data.empty () ? 0 : rover_file_read (file, data.data (), data.size ());
	rover_file_close (file);
	require (got == static_cast<long long> (data.size ()), path + ": short read");
	return data;
}

void run ()
{
	/* ext2 (fshelp): final component returned, leading links followed. */
	target ("(ext)/link.txt", "hello.txt");
	target ("(ext)/dirlink", "nested");
	fails ("(ext)/hello.txt", EINVAL);
	fails ("(ext)/nested", EINVAL);
	fails ("(ext)/dirlink/data.bin", EINVAL);
	fails ("(ext)/missing", ENOENT);
	fails ("(ext)/", EINVAL);

	/* Truncation reports the full length; SIZE 0 only measures. */
	char small[4];
	unsigned long long length = 0;
	require (!rover_readlink ("(ext)/link.txt", small, sizeof (small), &length)
		&& std::string (small) == "hel" && length == 9, "truncated target");
	length = 0;
	require (!rover_readlink ("(ext)/link.txt", nullptr, 0, &length) && length == 9,
		"length-only query");
	printf ("PASS readlink ext2\n");

	/* archelp: links in leading components resolve from their directory. */
	target ("(tar)/link.txt", "hello.txt");
	target ("(dir)/dirlink", "nested");
	target ("(dir)/abs", "/nested/data.bin");
	target ("(dir)/nested/up", "../hello.txt");
	target ("(dir)/dirlink/up", "../hello.txt");
	fails ("(dir)/nested", EINVAL);
	fails ("(dir)/hello.txt", EINVAL);
	fails ("(dir)/missing", ENOENT);
	const std::string data = content ("(dir)/nested/data.bin");
	require (content ("(dir)/dirlink/data.bin") == data, "open through directory link");
	require (content ("(dir)/abs") == data, "open through absolute link");
	require (content ("(dir)/dirlink/up") == content ("(dir)/hello.txt"),
		"open through two links");
	printf ("PASS readlink archive\n");

	/* FAT has no symbolic links at all. */
	fails ("(fat)/hello.txt", ENOTSUP);
	printf ("PASS readlink unsupported filesystem\n");
}

/* NTFS reparse points (tests/ntfs_links.sh): read_symlink used to free the
   node's MFT buffer and leave it for free_file to free again, so repeat each
   lookup until a double free would have corrupted the heap. */
void run_ntfs ()
{
	for (int i = 0; i < 64; i++)
	{
		target ("(ntfs)/Documents and Settings", "/Users");
		target ("(ntfs)/abs", "/Users/Public");
		target ("(ntfs)/rel.lnk", "Users/Public/hello.txt");
		fails ("(ntfs)/odd", EIO);
	}
	fails ("(ntfs)/Users", EINVAL);
	fails ("(ntfs)/Documents and Settings/Public", EINVAL);
	fails ("(ntfs)/missing", ENOENT);
	const std::string data = content ("(ntfs)/Users/Public/hello.txt");
	require (data == "hello from public\n", "NTFS fixture content");
	require (content ("(ntfs)/Documents and Settings/Public/hello.txt") == data,
		"open through junction");
	require (content ("(ntfs)/abs/hello.txt") == data, "open through absolute link");
	require (content ("(ntfs)/rel.lnk") == data, "open through relative link");
	printf ("PASS readlink ntfs\n");
}

} // namespace

int product_readlink_probe (const std::filesystem::path &fixtures,
	const std::filesystem::path &ntfs)
{
	rover_init (ROVER_INIT_NO_HOSTDISK);
	int status = 0;
	try
	{
		attach ("ext", fixtures / "basic.ext2");
		attach ("tar", fixtures / "links.tar");
		attach ("dir", fixtures / "dirlinks.tar");
		attach ("fat", fixtures / "basic.img");
		run ();
		if (!ntfs.empty ())
		{
			attach ("ntfs", ntfs);
			run_ntfs ();
		}
	}
	catch (const std::exception &error)
	{
		fprintf (stderr, "FAIL: %s\n", error.what ());
		status = 1;
	}
	rover_fini ();
	return status;
}
