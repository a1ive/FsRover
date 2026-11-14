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

#include "backend.h"

#include <glib.h>

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

#include <rover.h>

namespace backend
{

namespace
{

std::thread worker;
std::mutex lock;
std::condition_variable wake;
std::deque<std::function<void ()>> jobs;
bool quitting;

gboolean
run_closure (gpointer data)
{
	(*static_cast<std::function<void ()> *> (data)) ();
	return G_SOURCE_REMOVE;
}

void
free_closure (gpointer data)
{
	delete static_cast<std::function<void ()> *> (data);
}

void
thread_main (int flags, std::function<void ()> on_ready)
{
	rover_init (flags);
	ui (std::move (on_ready));
	for (;;)
	{
		std::function<void ()> job;
		{
			std::unique_lock<std::mutex> guard (lock);
			wake.wait (guard, [] { return quitting || !jobs.empty (); });
			if (quitting)
				break;
			job = std::move (jobs.front ());
			jobs.pop_front ();
		}
		job ();
	}
	rover_fini ();
}

} /* namespace */

void
start (int flags, std::function<void ()> on_ready)
{
	worker = std::thread (thread_main, flags, std::move (on_ready));
}

void
post (std::function<void ()> work)
{
	{
		std::lock_guard<std::mutex> guard (lock);
		jobs.push_back (std::move (work));
	}
	wake.notify_one ();
}

void
ui (std::function<void ()> fn)
{
	g_idle_add_full (G_PRIORITY_DEFAULT, run_closure,
		new std::function<void ()> (std::move (fn)), free_closure);
}

void
stop ()
{
	{
		std::lock_guard<std::mutex> guard (lock);
		quitting = true;
		jobs.clear ();
	}
	wake.notify_one ();
	if (worker.joinable ())
		worker.join ();
}

} /* namespace backend */
