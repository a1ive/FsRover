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

/* Mars Runner, the About-box easter egg, without a GUI toolkit.  The
   game renders into a WIDTH x HEIGHT framebuffer of 0x00RRGGBB pixels
   (native-endian 32-bit words, row-major, no padding); a host window
   feeds it key presses, focus changes and wall-clock time, and scales
   the framebuffer up with nearest-neighbour sampling.  Everything here
   belongs to the host's GUI thread and never touches grub.  */

#ifndef ROVER_GAME_H
#define ROVER_GAME_H	1

#include <cstdint>

namespace rover_game
{

constexpr int WIDTH = 320;
constexpr int HEIGHT = 180;

/* Space and Up jump, Down ducks; any other key only starts the game.  */
enum class key
{
	jump,
	duck,
	other
};

struct state;

/* A fresh game waiting for its first key, its first frame drawn.  Any
   seed works; hosts pass something time-based.  */
state *create (std::uint32_t seed);
void destroy (state *g);

/* Key auto-repeat may be passed through: a held jump key fires once.  */
void key_down (state *g, key k);
void key_up (state *g, key k);

/* The game pauses while its window is inactive.  Key-up events go to
   whichever window is active, so losing focus releases every key.  */
void set_active (state *g, bool active);

/* Advance by dt seconds of wall-clock time (any value; large steps are
   clamped) and redraw.  Returns false when the frame did not change, so
   the host can skip repainting.  */
bool tick (state *g, double dt);

const std::uint32_t *pixels (const state *g);

/* The largest whole multiple of the framebuffer that fits in w x h, so
   every game pixel is the same size; 0 when not even 1:1 fits.  */
int integer_scale (int w, int h);

} /* namespace rover_game */

#endif /* ! ROVER_GAME_H */
