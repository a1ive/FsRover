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

#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <rover.h>

#include "fusefs.h"
#include "../common/blocklist.h"
#include "../common/extract_core.h"

namespace
{

constexpr const char *USAGE =
	"Usage:\n"
	"  LinuxRover [options] --list[=PATH]\n"
	"  LinuxRover [options] --extract=PATH --output=DIR\n"
	"  LinuxRover [options] --mount=DEVICE MOUNTPOINT\n\n"
	"Options:\n"
	"  -f, --file=IMAGE       Attach a host image as imgN (repeatable)\n"
	"  -d, --file-dec=IMAGE   Attach and transparently decompress IMAGE\n"
	"  -p, --loop=PATH       Attach a GRUB file as loopN (repeatable)\n"
	"      --loop-dec=PATH   Attach and transparently decompress a GRUB file\n"
	"  -l, --list[=PATH]      List devices, a directory, or a file\n"
	"  -b, --blocklist=PATH   Enumerate metadata mappings as byte-based TSV\n"
	"  -e, --extract=PATH     Extract a file or directory (repeatable)\n"
	"  -o, --output=DIR       Destination directory for --extract\n"
	"  -n, --no-times         Do not preserve extracted timestamps\n"
	"  -m, --mount=DEVICE     Mount DEVICE through FUSE3\n"
	"  -F, --foreground       Keep the FUSE process in the foreground\n"
	"  -c, --fs-encoding=ENC  UTF-8, GBK, Big5, Shift-JIS, or EUC-KR\n"
	"  -h, --help             Show this help\n";

struct mount_option
{
	std::string path;
	bool decompress;
	bool loopback;
};

struct options
{
	std::vector<mount_option> mounts;
	std::vector<std::string> extracts;
	std::string output;
	bool preserve_times = true;
	std::string list_path;
	std::string mount_device;
	std::string mountpoint;
	unsigned int encoding = ROVER_FS_ENCODING_UTF8;
	bool list = false;
	bool blocklist = false;
	std::string blocklist_path;
	bool foreground = false;
};

struct mounted_device
{
	std::string name;
	std::string fs;
	unsigned long long size = ROVER_SIZE_UNKNOWN;
	bool found = false;
};

std::string
strip_device_syntax (std::string device)
{
	if (device.size () >= 2 && device.front () == '(' && device.back () == ')')
		return device.substr (1, device.size () - 2);
	return device;
}

bool
parse_encoding (const char *name, unsigned int *encoding)
{
	struct entry { const char *name; unsigned int value; };
	static constexpr entry entries[] =
	{
		{ "UTF-8", ROVER_FS_ENCODING_UTF8 },
		{ "GBK", ROVER_FS_ENCODING_GBK },
		{ "Big5", ROVER_FS_ENCODING_BIG5 },
		{ "Shift-JIS", ROVER_FS_ENCODING_SHIFT_JIS },
		{ "EUC-KR", ROVER_FS_ENCODING_EUC_KR }
	};
	for (const entry &item : entries)
		if (strcasecmp (name, item.name) == 0)
		{
			*encoding = item.value;
			return true;
		}
	return false;
}

bool
parse_options (int argc, char **argv, options *out)
{
	constexpr int OPT_LOOP_DEC = 256;
	static const option long_options[] =
	{
		{ "file", required_argument, nullptr, 'f' },
		{ "file-dec", required_argument, nullptr, 'd' },
		{ "loop", required_argument, nullptr, 'p' },
		{ "loop-dec", required_argument, nullptr, OPT_LOOP_DEC },
		{ "list", optional_argument, nullptr, 'l' },
		{ "blocklist", required_argument, nullptr, 'b' },
		{ "extract", required_argument, nullptr, 'e' },
		{ "output", required_argument, nullptr, 'o' },
		{ "no-times", no_argument, nullptr, 'n' },
		{ "mount", required_argument, nullptr, 'm' },
		{ "foreground", no_argument, nullptr, 'F' },
		{ "fs-encoding", required_argument, nullptr, 'c' },
		{ "help", no_argument, nullptr, 'h' },
		{ nullptr, 0, nullptr, 0 }
	};
	int ch;
	bool output_seen = false;

	while ((ch = getopt_long (argc, argv, "f:d:p:l::b:e:o:nm:Fc:h", long_options,
		nullptr)) != -1)
	{
		switch (ch)
		{
		case 'f':
		case 'd':
		case 'p':
		case OPT_LOOP_DEC:
			if (!optarg[0])
			{
				std::cerr << "LinuxRover: image and loop options require a nonempty path\n";
				return false;
			}
			out->mounts.push_back ({ optarg, ch == 'd' || ch == OPT_LOOP_DEC,
				ch == 'p' || ch == OPT_LOOP_DEC });
			break;
		case 'l':
			out->list = true;
			if (optarg)
				out->list_path = optarg;
			break;
		case 'b':
			if (out->blocklist || !optarg[0])
			{
				std::cerr << "LinuxRover: --blocklist requires one nonempty path and may only be specified once\n";
				return false;
			}
			out->blocklist = true;
			out->blocklist_path = optarg;
			break;
		case 'e':
			if (!optarg[0])
			{
				std::cerr << "LinuxRover: --extract requires a nonempty path\n";
				return false;
			}
			out->extracts.push_back (optarg);
			break;
		case 'o':
			if (output_seen || !optarg[0])
			{
				std::cerr << "LinuxRover: --output requires a nonempty directory and may only be specified once\n";
				return false;
			}
			output_seen = true;
			out->output = optarg;
			break;
		case 'n':
			out->preserve_times = false;
			break;
		case 'm':
			out->mount_device = strip_device_syntax (optarg);
			break;
		case 'F':
			out->foreground = true;
			break;
		case 'c':
			if (!parse_encoding (optarg, &out->encoding))
			{
				std::cerr << "LinuxRover: invalid file name encoding '"
					<< optarg << "'\n";
				return false;
			}
			break;
		case 'h':
			std::cout << USAGE;
			exit (0);
		default:
			return false;
		}
	}
	if (int (out->list) + int (out->blocklist) + int (!out->extracts.empty ()) + int (!out->mount_device.empty ()) != 1)
	{
		std::cerr << "LinuxRover: specify exactly one of --list, --blocklist, --extract or --mount\n";
		return false;
	}
	if (out->extracts.empty () != out->output.empty ())
	{
		std::cerr << "LinuxRover: --extract and --output must be used together\n";
		return false;
	}
	if (!out->mount_device.empty ())
	{
		if (optind + 1 != argc)
		{
			std::cerr << "LinuxRover: --mount requires one MOUNTPOINT\n";
			return false;
		}
		out->mountpoint = argv[optind];
	}
	else if (optind != argc)
	{
		if (out->list && out->list_path.empty () && optind + 1 == argc)
			out->list_path = argv[optind];
		else
		{
			std::cerr << "LinuxRover: unexpected positional argument\n";
			return false;
		}
	}
	return true;
}

fusefs *
current_fs ()
{
	fuse_context *context = fuse_get_context ();
	return context ? static_cast<fusefs *> (context->private_data) : nullptr;
}

void
copy_stat (const fusefs_stat &in, struct stat *out)
{
	memset (out, 0, sizeof (*out));
	out->st_mode = in.mode;
	out->st_nlink = (in.mode & S_IFMT) == S_IFDIR ? 2 : 1;
	out->st_ino = in.inode;
	out->st_size = static_cast<off_t> (in.size);
	out->st_mtime = static_cast<time_t> (in.mtime);
}

int
fs_getattr (const char *path, struct stat *st, fuse_file_info *)
{
	fusefs_stat status = {};
	fusefs *fs = current_fs ();
	int rc = fs ? fusefs_getattr (fs, path, &status) : -EIO;

	if (!rc)
		copy_stat (status, st);
	return rc;
}

int
fs_open (const char *path, fuse_file_info *info)
{
	fusefs *fs = current_fs ();
	return fs ? fusefs_open (fs, path, info->flags, &info->fh) : -EIO;
}

int
fs_read (const char *path, char *buf, size_t size, off_t offset,
	fuse_file_info *info)
{
	fusefs *fs = current_fs ();
	return fs ? fusefs_read (fs, path, buf, size, offset, &info->fh) : -EIO;
}

int
fs_release (const char *, fuse_file_info *info)
{
	fusefs *fs = current_fs ();
	return fs ? fusefs_release (fs, &info->fh) : -EIO;
}

struct fill_context
{
	void *buffer;
	fuse_fill_dir_t fill;
};

int
fill_directory (void *opaque, const char *name, const fusefs_stat *status)
{
	auto *context = static_cast<fill_context *> (opaque);
	struct stat st;

	copy_stat (*status, &st);
	return context->fill (context->buffer, name, &st, 0,
		static_cast<fuse_fill_dir_flags> (0));
}

int
fs_readdir (const char *path, void *buffer, fuse_fill_dir_t fill, off_t,
	fuse_file_info *, fuse_readdir_flags)
{
	fusefs *fs = current_fs ();
	fill_context context = { buffer, fill };
	return fs ? fusefs_readdir (fs, path, fill_directory, &context) : -EIO;
}

int
fs_statfs (const char *, struct statvfs *st)
{
	fusefs *fs = current_fs ();
	fusefs_statvfs status = {};
	int rc = fs ? fusefs_statfs (fs, &status) : -EIO;

	if (rc)
		return rc;
	memset (st, 0, sizeof (*st));
	st->f_bsize = status.block_size;
	st->f_frsize = status.block_size;
	st->f_blocks = status.blocks;
	st->f_namemax = status.name_max;
	st->f_flag = ST_RDONLY;
	return 0;
}

int
find_mount_device (const rover_disk_info *info, void *opaque)
{
	auto *wanted = static_cast<mounted_device *> (opaque);
	if (wanted->name != info->name)
		return 0;
	wanted->found = true;
	wanted->size = info->size;
	if (info->fs)
		wanted->fs = info->fs;
	return 1;
}

int
print_device (const rover_disk_info *info, void *)
{
	std::cout << '(' << info->name << ')';
	if (info->fs)
		std::cout << '\t' << info->fs;
	std::cout << '\n';
	return 0;
}

int
print_entry (const rover_dirent *entry, void *)
{
	std::cout << entry->name << (entry->is_dir ? "/" : "") << '\n';
	return 0;
}

int
run_list (const std::string &path)
{
	if (path.empty ())
	{
		rover_enum_disks (print_device, nullptr);
		return 0;
	}
	rover_stat_t st = {};
	if (rover_stat (path.c_str (), &st))
		return 1;
	if (!st.is_dir)
	{
		std::cout << path << '\n';
		return 0;
	}
	return rover_dir_list (path.c_str (), print_entry, nullptr) ? 1 : 0;
}

volatile sig_atomic_t extract_cancelled = 0;

void cancel_extract (int)
{
	extract_cancelled = 1;
}

int run_extract (const options &command)
{
	rover_extract::options opts;
	rover_extract::result stats;
	std::string error;
	struct sigaction action = {}, old_int = {}, old_term = {};
	action.sa_handler = cancel_extract;
	sigemptyset (&action.sa_mask);
	extract_cancelled = 0;
	bool have_int = sigaction (SIGINT, &action, &old_int) == 0;
	bool have_term = sigaction (SIGTERM, &action, &old_term) == 0;
	opts.preserve_times = command.preserve_times;
	opts.cancelled = [] () { return extract_cancelled != 0; };
	opts.report_progress = [] (const rover_extract::progress &progress)
	{
		if (progress.kind != rover_extract::progress_kind::completed) return;
		std::string path = progress.source;
		for (char &c : path)
			if (static_cast<unsigned char> (c) < 32 || c == 127) c = '?';
		std::cerr << "Extracted [" << progress.file_index << '/'
			<< progress.file_total << "] " << path << '\n';
	};
	bool ok = rover_extract::extract (command.extracts, command.output, opts, &stats, &error);
	if (have_int) sigaction (SIGINT, &old_int, nullptr);
	if (have_term) sigaction (SIGTERM, &old_term, nullptr);
	for (const std::string &item : stats.errors)
		std::cerr << "LinuxRover: " << item << '\n';
	if (!error.empty ()) std::cerr << "LinuxRover: " << error << '\n';
	std::cerr << "Extracted " << stats.files << " file(s), " << stats.bytes
		<< " bytes; skipped " << stats.links << " symlink(s); failed "
		<< stats.errors.size () << " file(s).\n";
	return ok ? 0 : 1;
}

} // namespace

int
main (int argc, char **argv)
{
	options command;
	mounted_device device;
	fusefs core;
	fuse_operations operations = {};
	std::vector<char *> fuse_args;
	int result = 1;

	if (!parse_options (argc, argv, &command))
	{
		std::cerr << '\n' << USAGE;
		return 2;
	}
	bool has_host_mount = std::any_of (command.mounts.begin (), command.mounts.end (),
		[] (const mount_option &mount) { return !mount.loopback; });
	size_t img_seq = 0;
	size_t loop_seq = 0;
	rover_init (has_host_mount ? ROVER_INIT_NO_HOSTDISK : 0);
	if (rover_set_fs_char_encoding (command.encoding))
		goto out;
	/* Preserve command-line order: a loop can depend on an earlier image or loop. */
	for (const mount_option &mount : command.mounts)
	{
		std::string name = mount.loopback
			? "loop" + std::to_string (loop_seq)
			: "img" + std::to_string (img_seq);
		int rc = mount.loopback
			? rover_loopback_add (name.c_str (), mount.path.c_str (), mount.decompress ? 1 : 0)
			: rover_posixfile_add (name.c_str (), mount.path.c_str (), mount.decompress ? 1 : 0);
		if (rc)
		{
			std::cerr << "LinuxRover: cannot mount '" << mount.path << "' as (" << name << ")\n";
			goto out;
		}
		if (mount.loopback)
			loop_seq++;
		else
			img_seq++;
	}
	if (!command.extracts.empty ())
	{
		result = run_extract (command);
		goto out;
	}
	if (command.blocklist)
	{
		std::string error;
		result = rover_blocklist::run (command.blocklist_path,
			[] (const std::string &line) { std::cout << line; return bool (std::cout); }, &error) ? 0 : 1;
		if (result) std::cerr << "LinuxRover: " << error << '\n';
		goto out;
	}
	if (command.list)
	{
		result = run_list (command.list_path);
		goto out;
	}

	device.name = command.mount_device;
	rover_enum_disks (find_mount_device, &device);
	if (!device.found || device.fs.empty ())
	{
		std::cerr << "LinuxRover: device '" << device.name
			<< "' has no supported filesystem\n";
		goto out;
	}

	fusefs_init (&core, device.name, device.fs, device.size,
		[] (const std::function<void ()> &fn) { fn (); return true; });
	operations.getattr = fs_getattr;
	operations.open = fs_open;
	operations.read = fs_read;
	operations.release = fs_release;
	operations.readdir = fs_readdir;
	operations.statfs = fs_statfs;
	fuse_args.push_back (argv[0]);
	fuse_args.push_back (const_cast<char *> ("-s"));
	fuse_args.push_back (const_cast<char *> ("-o"));
	fuse_args.push_back (const_cast<char *> ("ro,default_permissions"));
	if (command.foreground)
		fuse_args.push_back (const_cast<char *> ("-f"));
	fuse_args.push_back (command.mountpoint.data ());
	result = fuse_main (static_cast<int> (fuse_args.size ()), fuse_args.data (),
		&operations, &core);

out:
	if (result && rover_last_error ())
		std::cerr << "LinuxRover: " << rover_last_error () << '\n';
	rover_fini ();
	return result;
}
