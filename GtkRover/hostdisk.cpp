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

/*
 * Physical disks without running the GUI as root.  GtkRover stays an
 * ordinary process; only the descriptors are obtained with privilege:
 *
 *  1. udisks2's Block.OpenDevice ("r"), authorised by polkit (the desktop's
 *     agent asks for the password once and remembers it for a while);
 *  2. where udisks2 is missing, "pkexec GtkRover --open-devices ..." -- a
 *     helper mode that opens the named block devices read-only and sends
 *     the descriptors back over its standard input, a Unix socket.
 *
 * posixdisk asks rover_set_host_open_hook()'s callback when open(2) is
 * refused; the callback hands out duplicates of the cached descriptors.
 */

#include "app.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gio/gunixfdlist.h>

#include <algorithm>
#include <map>
#include <mutex>
#include <thread>

#include <rover.h>

namespace
{

/* Device path -> descriptor; read by the grub thread through the hook.  */
std::mutex cache_lock;
std::map<std::string, int> cache;

int
open_hook (const char *device, void *)
{
	std::lock_guard<std::mutex> guard (cache_lock);
	auto it = cache.find (device);

	return it == cache.end () ? -1 : fcntl (it->second, F_DUPFD_CLOEXEC, 0);
}

void
remember (const std::string &path, int fd)
{
	std::lock_guard<std::mutex> guard (cache_lock);
	auto it = cache.find (path);

	if (it != cache.end ())
		close (it->second);
	cache[path] = fd;
}

bool
cached (const std::string &path)
{
	std::lock_guard<std::mutex> guard (cache_lock);

	return cache.count (path) != 0;
}

/* The whole disks posixdisk registers, by the same rules.  */
std::vector<std::string>
host_devices ()
{
	std::vector<std::string> out;
	DIR *dir = opendir ("/sys/class/block");

	if (!dir)
		return out;
	while (struct dirent *ent = readdir (dir))
	{
		std::string name = ent->d_name;
		if (name[0] == '.' || name.rfind ("loop", 0) == 0 || name.rfind ("ram", 0) == 0
			|| name.rfind ("zram", 0) == 0 || name.rfind ("fd", 0) == 0)
			continue;
		if (g_file_test (("/sys/class/block/" + name + "/partition").c_str (), G_FILE_TEST_EXISTS))
			continue;
		out.push_back ("/dev/" + name);
	}
	closedir (dir);
	std::sort (out.begin (), out.end ());
	return out;
}

std::vector<std::string>
inaccessible ()
{
	std::vector<std::string> out;

	if (geteuid () == 0)
		return out;
	for (const std::string &path : host_devices ())
		if (access (path.c_str (), R_OK) != 0 && errno != ENOENT && !cached (path))
			out.push_back (path);
	return out;
}

/* udisks2 names block objects after the kernel name, escaping everything
   but ASCII letters and digits as _XX.  */
std::string
udisks_object (const std::string &path)
{
	std::string out = "/org/freedesktop/UDisks2/block_devices/";

	for (unsigned char c : basename_of (path))
		out += g_ascii_isalnum (c) ? std::string (1, (char) c) : fmt ("_%02x", c);
	return out;
}

struct access_request
{
	GDBusConnection *bus = nullptr;
	std::vector<std::string> todo;
	std::vector<std::string> fallback;	/* for the pkexec helper */
	size_t granted = 0;
	std::string error;
};

void finish_request (access_request *r);
void next_udisks (access_request *r);
bool request_running;

bool
have_pkexec ()
{
	char *path = g_find_program_in_path ("pkexec");
	bool found = path != nullptr;

	g_free (path);
	return found;
}

/* Errors that mean "udisks cannot do it", not "the user said no".  */
bool
udisks_unavailable (GError *error)
{
	char *remote = g_dbus_error_get_remote_error (error);
	bool unavailable = g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)
		|| g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD)
		|| g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_OBJECT)
		|| g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_NAME_HAS_NO_OWNER)
		|| (remote && (g_str_has_suffix (remote, "UnknownMethod")
			|| g_str_has_suffix (remote, "UnknownObject")
			|| g_str_has_suffix (remote, "NotSupported")));

	g_free (remote);
	return unavailable;
}

void
on_opened (GObject *source, GAsyncResult *result, gpointer data)
{
	auto *r = static_cast<access_request *> (data);
	GUnixFDList *fds = nullptr;
	GError *error = nullptr;
	GVariant *reply = g_dbus_connection_call_with_unix_fd_list_finish (G_DBUS_CONNECTION (source),
		&fds, result, &error);
	std::string path = r->todo.front ();

	r->todo.erase (r->todo.begin ());
	if (reply)
	{
		gint32 handle = -1;
		g_variant_get (reply, "(h)", &handle);
		int fd = fds ? g_unix_fd_list_get (fds, handle, nullptr) : -1;
		if (fd >= 0)
		{
			remember (path, fd);
			r->granted++;
		}
		g_variant_unref (reply);
	}
	else if (udisks_unavailable (error))
		r->fallback.push_back (path);
	else
	{
		/* Refused or dismissed: do not ask again for the other disks.  */
		g_dbus_error_strip_remote_error (error);
		r->error = error->message;
		r->fallback.clear ();
		r->todo.clear ();
	}
	g_clear_object (&fds);
	g_clear_error (&error);
	next_udisks (r);
}

void
next_udisks (access_request *r)
{
	if (r->todo.empty () || !r->bus)
	{
		finish_request (r);
		return;
	}
	g_dbus_connection_call_with_unix_fd_list (r->bus, "org.freedesktop.UDisks2",
		udisks_object (r->todo.front ()).c_str (), "org.freedesktop.UDisks2.Block", "OpenDevice",
		g_variant_new ("(s@a{sv})", "r", g_variant_new_array (G_VARIANT_TYPE ("{sv}"), nullptr, 0)),
		G_VARIANT_TYPE ("(h)"), G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION,
		G_MAXINT, nullptr, nullptr, on_opened, r);
}

struct helper_result
{
	std::vector<std::pair<std::string, int>> fds;
	std::string error;
};

/* Worker thread: run the helper and collect what it sends.  */
helper_result
run_helper (const std::vector<std::string> &paths)
{
	helper_result out;
	char *self = g_file_read_link ("/proc/self/exe", nullptr);
	int pair[2];

	if (!self || socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0)
	{
		out.error = g_strerror (errno);
		g_free (self);
		return out;
	}
	GSubprocessLauncher *launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDERR_SILENCE);
	std::vector<const char *> argv = { "pkexec", self, "--open-devices" };
	for (const std::string &path : paths)
		argv.push_back (path.c_str ());
	argv.push_back (nullptr);
	g_subprocess_launcher_take_stdin_fd (launcher, pair[1]);
	GError *error = nullptr;
	GSubprocess *child = g_subprocess_launcher_spawnv (launcher, argv.data (), &error);
	g_object_unref (launcher);
	g_free (self);
	if (!child)
	{
		out.error = error->message;
		g_error_free (error);
		close (pair[0]);
		return out;
	}
	for (;;)
	{
		char buf[4096];
		char control[CMSG_SPACE (sizeof (int))];
		struct iovec iov = { buf, sizeof (buf) - 1 };
		struct msghdr msg = {};
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control;
		msg.msg_controllen = sizeof (control);
		ssize_t n = recvmsg (pair[0], &msg, MSG_CMSG_CLOEXEC);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		buf[n] = '\0';
		int fd = -1;
		for (struct cmsghdr *c = CMSG_FIRSTHDR (&msg); c; c = CMSG_NXTHDR (&msg, c))
			if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
				memcpy (&fd, CMSG_DATA (c), sizeof (fd));
		if (fd >= 0)
			out.fds.push_back ({ buf, fd });
	}
	close (pair[0]);
	g_subprocess_wait (child, nullptr, nullptr);
	/* pkexec exits 126 when the user dismissed the dialog, 127 when not
	   authorised.  */
	if (out.fds.empty () && g_subprocess_get_if_exited (child)
		&& g_subprocess_get_exit_status (child) != 0)
		out.error = fmt (_("The helper failed (pkexec exit status %d)."),
			g_subprocess_get_exit_status (child));
	g_object_unref (child);
	return out;
}

void
finish_request (access_request *r)
{
	if (!r->fallback.empty () && have_pkexec ())
	{
		std::vector<std::string> paths = std::move (r->fallback);
		r->fallback.clear ();
		std::thread ([r, paths]
		{
			auto result = std::make_shared<helper_result> (run_helper (paths));
			backend::ui ([r, result]
			{
				for (const auto &[path, fd] : result->fds)
				{
					remember (path, fd);
					r->granted++;
				}
				if (r->error.empty ())
					r->error = result->error;
				finish_request (r);
			});
		}).detach ();
		return;
	}
	if (!S.closing)
	{
		if (r->granted)
			set_status (fmt (g_dngettext (nullptr, "Access granted to %zu disk",
				"Access granted to %zu disks", r->granted), r->granted));
		else if (!r->error.empty ())
			show_error (_("No access to the physical disks"), r->error);
		else
			set_status (_("No physical disk could be opened"));
		refresh_disks (nullptr);
	}
	request_running = false;
	if (!S.closing)
		update_actions ();
	g_clear_object (&r->bus);
	delete r;
}

} /* namespace */

void
hostdisk_install_hook ()
{
	rover_set_host_open_hook (open_hook, nullptr);
}

bool
hostdisk_needed ()
{
	static gint64 checked;
	static bool needed;
	gint64 now = g_get_monotonic_time ();

	/* update_actions() runs on every selection change; sysfs need not.  */
	if (!request_running && now - checked > 2 * G_USEC_PER_SEC)
	{
		checked = now;
		needed = !inaccessible ().empty ();
	}
	return needed && !request_running;
}

void
hostdisk_request_access ()
{
	auto *r = new access_request;

	r->todo = inaccessible ();
	if (r->todo.empty ())
	{
		set_status (_("All physical disks are already readable"));
		delete r;
		return;
	}
	request_running = true;
	update_actions ();
	set_status (_("Waiting for authorization…"));
	r->bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, nullptr, nullptr);
	if (!r->bus)
		r->fallback = std::move (r->todo);
	next_udisks (r);
}

/*
 * The pkexec helper: open each argument read-only if it is a block device
 * under /dev, and send it over standard input (a Unix socket) as
 * SCM_RIGHTS with its path as the payload.  Nothing else; no GTK.
 */
int
hostdisk_helper_main (int argc, char **argv)
{
	struct stat st;

	if (fstat (0, &st) != 0 || !S_ISSOCK (st.st_mode))
		return 2;
	for (int i = 2; i < argc; i++)
	{
		const char *path = argv[i];
		if (strncmp (path, "/dev/", 5) != 0 || strstr (path, "/..")
			|| stat (path, &st) != 0 || !S_ISBLK (st.st_mode))
			continue;
		int fd = open (path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
		if (fd < 0)
			continue;
		char control[CMSG_SPACE (sizeof (int))] = {};
		struct iovec iov = { const_cast<char *> (path), strlen (path) };
		struct msghdr msg = {};
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control;
		msg.msg_controllen = sizeof (control);
		struct cmsghdr *c = CMSG_FIRSTHDR (&msg);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN (sizeof (int));
		memcpy (CMSG_DATA (c), &fd, sizeof (fd));
		ssize_t sent;
		do
			sent = sendmsg (0, &msg, MSG_NOSIGNAL);
		while (sent < 0 && errno == EINTR);
		close (fd);
		if (sent < 0)
			return 1;
	}
	return 0;
}
