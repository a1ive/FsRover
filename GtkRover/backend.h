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
 * GTK GUI <-> grub backend thread.
 *
 * grub keeps global state, so every rover_* call runs on the one thread
 * owned by this module, in the order the jobs were posted.  A job hands
 * its result back with backend::ui(), which queues a closure on the GTK
 * main loop; the GUI thread never calls rover_* itself.
 */

#ifndef GTKROVER_BACKEND_H
#define GTKROVER_BACKEND_H	1

#include <functional>

namespace backend
{

/* Start the thread: rover_init (FLAGS), then ON_READY on the GUI thread.  */
void start (int flags, std::function<void ()> on_ready);

/* Queue WORK for the grub thread.  Callable from any thread.  */
void post (std::function<void ()> work);

/* Queue FN for the GTK main loop.  Callable from any thread.  */
void ui (std::function<void ()> fn);

/* Drop queued jobs, wait for the running one, rover_fini () and join.  */
void stop ();

} /* namespace backend */

#endif /* ! GTKROVER_BACKEND_H */
