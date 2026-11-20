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

#include <locale.h>
#include <string.h>

#include "app.h"
#include "window.h"

static void
on_activate (GApplication *app, gpointer)
{
	rover_window_open (GTK_APPLICATION (app), {});
}

static void
on_open (GApplication *app, GFile **files, int n_files, const char *, gpointer)
{
	std::vector<std::string> images;

	for (int i = 0; i < n_files; i++)
	{
		char *path = g_file_get_path (files[i]);
		if (path)
			images.push_back (path);
		g_free (path);
	}
	rover_window_open (GTK_APPLICATION (app), images);
}

static void
on_shutdown (GApplication *, gpointer)
{
	rover_window_shutdown ();
}

std::string
exe_relative (const char *rel)
{
	char *self = g_file_read_link ("/proc/self/exe", nullptr);
	char *dir = self ? g_path_get_dirname (self) : nullptr;
	char *path = dir ? g_build_filename (dir, rel, nullptr) : nullptr;
	std::string out = path ? path : "";

	g_free (path);
	g_free (dir);
	g_free (self);
	return out;
}

/* Translations live in "locale" next to an uninstalled binary, then at the
   install layout's place relative to the binary (a relocated tree such as
   an AppImage), and last under the configured prefix.  */
static void
setup_i18n ()
{
	std::string local = exe_relative ("locale");
	std::string relocated = exe_relative (ROVER_LOCALEDIR_REL);
	const char *dir = ROVER_LOCALEDIR;

	if (g_file_test (local.c_str (), G_FILE_TEST_IS_DIR))
		dir = local.c_str ();
	else if (g_file_test (relocated.c_str (), G_FILE_TEST_IS_DIR))
		dir = relocated.c_str ();
	setlocale (LC_ALL, "");
	bindtextdomain (GETTEXT_PACKAGE, dir);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
}

int
main (int argc, char **argv)
{
	GtkApplication *app;
	int status;

	/* pkexec helper mode: no GTK, no grub, just open the devices.  */
	if (argc >= 2 && strcmp (argv[1], "--open-devices") == 0)
		return hostdisk_helper_main (argc, argv);

	setup_i18n ();
	app = gtk_application_new ("io.github.a1ive.FsRover",
		(GApplicationFlags) (G_APPLICATION_HANDLES_OPEN | G_APPLICATION_NON_UNIQUE));
	g_signal_connect (app, "activate", G_CALLBACK (on_activate), nullptr);
	g_signal_connect (app, "open", G_CALLBACK (on_open), nullptr);
	g_signal_connect (app, "shutdown", G_CALLBACK (on_shutdown), nullptr);
	status = g_application_run (G_APPLICATION (app), argc, argv);
	g_object_unref (app);
	return status;
}
