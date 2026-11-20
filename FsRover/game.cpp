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

/* The About-box easter egg.  Everything is rendered into a 320 x 180
   software framebuffer: sprites and the 5 x 7 font are deliberately
   data-driven, and StretchDIBits uses nearest-neighbour scaling.  The
   game is GUI-thread-only and never touches grub's backend state.  */

#include <windows.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"

namespace
{

constexpr int GAME_W = 320;
constexpr int GAME_H = 180;
constexpr int GROUND_Y = 145;
constexpr int ROVER_X = 48;
/* The rover speeds up linearly over the first SPEED_RAMP_METRES.  */
constexpr double BASE_METRES_PER_SECOND = 6.0;
constexpr double MAX_METRES_PER_SECOND = 10.0;
constexpr double SPEED_RAMP_METRES = 4000.0;
constexpr double PIXELS_PER_METRE = 24.0;
constexpr double JUMP_VELOCITY = 205.0;
constexpr double JUMP_GRAVITY = 330.0;
constexpr double FAST_FALL_GRAVITY = 850.0;
/* Releasing the jump key while rising caps the upward speed: a tap
   still clears a rock (about 18 px apex from the ground) and holding
   gives the full 64 px arc.  A press up to JUMP_BUFFER_SECONDS before
   touchdown is kept and fires on landing.  */
constexpr double JUMP_CUT_VELOCITY = 110.0;
constexpr double JUMP_BUFFER_SECONDS = 0.12;
constexpr int SATELLITE_HEIGHT_ABOVE_GROUND = 65;
constexpr int INGENUITY_HEIGHT_ABOVE_GROUND = 40;
constexpr int DUST_DEVIL_HEIGHT = 40;
constexpr int UFO_MIN_HEIGHT_ABOVE_GROUND = 5;
constexpr int UFO_MAX_HEIGHT_ABOVE_GROUND = 80;

constexpr unsigned ROCK_SPAWN_PERCENT = 42;
constexpr unsigned TRENCH_SPAWN_PERCENT = 41;
constexpr unsigned SATELLITE_SPAWN_PERCENT = 9;
constexpr unsigned SAMPLE_SPAWN_PERCENT = 5;
constexpr unsigned DUST_DEVIL_SPAWN_PERCENT = 2;
constexpr unsigned UFO_SPAWN_PERCENT = 1;
constexpr unsigned RANDOM_SPAWN_PERCENT_TOTAL = 100;
constexpr double ROCK_SPEED_METRES_PER_SECOND = 0.0;
constexpr double TRENCH_SPEED_METRES_PER_SECOND = 0.0;
constexpr double SATELLITE_SPEED_METRES_PER_SECOND = -4.0;
constexpr double UFO_SPEED_METRES_PER_SECOND = 2.0;
constexpr double DUST_DEVIL_SPEED_METRES_PER_SECOND = -1.0;
constexpr double ACTIVE_ROVER_SPEED_METRES_PER_SECOND = 1.0;
constexpr double FIRST_RANDOM_OBSTACLE_METRES = 22.0;
constexpr double LOOKAHEAD_METRES = (GAME_W - ROVER_X) / PIXELS_PER_METRE + 3.0;

/* Random obstacles are spaced by the time at which each one reaches
   the rover, not by where it lies: satellites and UFOs move on their
   own and would otherwise drift onto a neighbour, and a metre spacing
   would shrink in time as the rover speeds up.  The largest gap
   narrows as the speed ramps up; the smallest one never does.  */
constexpr double OBSTACLE_MIN_GAP_SECONDS = 1.4;
constexpr double OBSTACLE_MAX_GAP_START_SECONDS = 2.6;
constexpr double OBSTACLE_MAX_GAP_END_SECONDS = 1.8;

static_assert (ROCK_SPAWN_PERCENT + TRENCH_SPAWN_PERCENT
	+ SATELLITE_SPAWN_PERCENT + SAMPLE_SPAWN_PERCENT + DUST_DEVIL_SPAWN_PERCENT + UFO_SPAWN_PERCENT
	== RANDOM_SPAWN_PERCENT_TOTAL);
/* Solvability: any full jump over one obstacle lands before the next
   one must be jumped, with time to react, so neighbours never demand
   overlapping jumps and no gap needs the fast fall.  The air time is
   1.24 s; the hitbox lead times differ by under 0.05 s between kinds.  */
static_assert (OBSTACLE_MIN_GAP_SECONDS >= 2.0 * JUMP_VELOCITY / JUMP_GRAVITY + 0.15);
static_assert (OBSTACLE_MIN_GAP_SECONDS <= OBSTACLE_MAX_GAP_END_SECONDS
	&& OBSTACLE_MAX_GAP_END_SECONDS <= OBSTACLE_MAX_GAP_START_SECONDS);
/* Now and then a satellite passes over the rover just after it clears a
   rock.  Rover top = lift + 12 px; the satellite's underside sways from
   63 to 67 px, so the rover must stay under about 51 px.  Arriving
   CEILING_SATELLITE_DELAY_SECONDS after the rock puts the satellite
   where a full jump at the usual timing is near its apex; only a jump
   pressed some 0.65 s or more early has already come down.  The lowest
   hop still clears the 12 px rock, and any tap released within about
   0.19 s peaks under 51 px.  */
constexpr double CEILING_ROCK_CHANCE = 0.15;
constexpr double CEILING_MIN_METRES = 200.0;
constexpr double CEILING_SATELLITE_DELAY_SECONDS = 0.3;
static_assert (CEILING_SATELLITE_DELAY_SECONDS + 0.2 < OBSTACLE_MIN_GAP_SECONDS);
constexpr double JUMP_CUT_APEX = JUMP_CUT_VELOCITY * JUMP_CUT_VELOCITY / (2.0 * JUMP_GRAVITY);
static_assert (JUMP_CUT_APEX > 12.0 + 4.0);
static_assert (JUMP_CUT_APEX + 12.0 < SATELLITE_HEIGHT_ABOVE_GROUND - 2.0);

/* Every random obstacle must close in on the rover.  */
static_assert (BASE_METRES_PER_SECOND > UFO_SPEED_METRES_PER_SECOND
	&& BASE_METRES_PER_SECOND > ACTIVE_ROVER_SPEED_METRES_PER_SECOND);

constexpr double BATTERY_CAPACITY = 1000.0;
constexpr double SOLAR_CLEAR_CHARGE_PER_SECOND = 5.0;
constexpr double SOLAR_HAZE_CHARGE_PER_SECOND = 2.0;
constexpr double SOLAR_SNOW_CHARGE_PER_SECOND = 1.0;
constexpr double SYSTEM_DRAIN_PER_SECOND = 1.0;
constexpr double HEATER_DRAIN_PER_SECOND = 1.0;
constexpr double STORM_DRAG_DRAIN_PER_SECOND = 4.0;
constexpr double STORM_NIGHT_DRAIN_PER_SECOND = 10.0;
/* Dust settling on the solar panels scales every daytime charge rate.
   Only driving (not jumping) through a dust devil blows them clean,
   as happened to Spirit and Opportunity.  */
constexpr double PANEL_DUST_HAZE_PER_SECOND = 0.002;
constexpr double PANEL_DUST_STORM_PER_SECOND = 0.01;
constexpr double PANEL_MIN_EFFICIENCY = 0.3;
/* Science: hematite spherules ("blueberries", after Opportunity) are
   picked up by driving over them into a small store.  Files reach Earth
   only when the rover passes under an orbiter after dark, at a battery
   cost per file; whatever is still on board at a crash is lost.  */
constexpr int DATA_CAPACITY = 4;
constexpr double UPLINK_BATTERY_COST_PER_FILE = 20.0;
constexpr double UPLINK_LINK_SECONDS = 0.6;
constexpr double NOTICE_SECONDS = 1.5;
constexpr double LANDING_SQUASH_SECONDS = 0.08;
constexpr double DUST_PARTICLE_SECONDS = 0.35;
constexpr double DUST_PARTICLE_GRAVITY = 160.0;
constexpr double TRENCH_BATTERY_COST = 10.0;
constexpr double UFO_BATTERY_CHARGE = 100.0;
constexpr double JUMP_BATTERY_COST = 1.0;
constexpr double BATTERY_FLASH_SECONDS = 0.5;
constexpr double RETRY_LOCK_SECONDS = 0.6;

static_assert (UFO_MIN_HEIGHT_ABOVE_GROUND <= UFO_MAX_HEIGHT_ABOVE_GROUND);

constexpr UINT_PTR GAME_TIMER = 1;

using pixel_t = std::uint32_t;

constexpr pixel_t
rgb (unsigned r, unsigned g, unsigned b)
{
	return (pixel_t) ((r << 16) | (g << 8) | b);
}

struct canvas
{
	std::array<pixel_t, GAME_W * GAME_H> pixels;

	void clear (pixel_t color)
	{
		pixels.fill (color);
	}

	void put (int x, int y, pixel_t color)
	{
		if ((unsigned) x < GAME_W && (unsigned) y < GAME_H)
			pixels[(size_t) y * GAME_W + x] = color;
	}

	void rect (int x, int y, int w, int h, pixel_t color)
	{
		int x0 = (std::max) (x, 0);
		int y0 = (std::max) (y, 0);
		int x1 = (std::min) (x + w, GAME_W);
		int y1 = (std::min) (y + h, GAME_H);

		for (int py = y0; py < y1; py++)
			for (int px = x0; px < x1; px++)
				pixels[(size_t) py * GAME_W + px] = color;
	}

	void blend (int x, int y, pixel_t color, unsigned amount)
	{
		if ((unsigned) x >= GAME_W || (unsigned) y >= GAME_H)
			return;
		pixel_t old = pixels[(size_t) y * GAME_W + x];
		unsigned r = (((old >> 16) & 255) * (255 - amount) + ((color >> 16) & 255) * amount) / 255;
		unsigned g = (((old >> 8) & 255) * (255 - amount) + ((color >> 8) & 255) * amount) / 255;
		unsigned b = ((old & 255) * (255 - amount) + (color & 255) * amount) / 255;
		put (x, y, rgb (r, g, b));
	}
};

struct glyph
{
	char ch;
	std::array<unsigned char, 7> rows;
};

constexpr glyph k_font[] =
{
	{ 'A', { 14, 17, 17, 31, 17, 17, 17 } },
	{ 'B', { 30, 17, 17, 30, 17, 17, 30 } },
	{ 'C', { 14, 17, 16, 16, 16, 17, 14 } },
	{ 'D', { 30, 17, 17, 17, 17, 17, 30 } },
	{ 'E', { 31, 16, 16, 30, 16, 16, 31 } },
	{ 'F', { 31, 16, 16, 30, 16, 16, 16 } },
	{ 'G', { 14, 17, 16, 23, 17, 17, 15 } },
	{ 'H', { 17, 17, 17, 31, 17, 17, 17 } },
	{ 'I', { 31, 4, 4, 4, 4, 4, 31 } },
	{ 'J', { 1, 1, 1, 1, 17, 17, 14 } },
	{ 'K', { 17, 18, 20, 24, 20, 18, 17 } },
	{ 'L', { 16, 16, 16, 16, 16, 16, 31 } },
	{ 'M', { 17, 27, 21, 21, 17, 17, 17 } },
	{ 'N', { 17, 25, 21, 19, 17, 17, 17 } },
	{ 'O', { 14, 17, 17, 17, 17, 17, 14 } },
	{ 'P', { 30, 17, 17, 30, 16, 16, 16 } },
	{ 'Q', { 14, 17, 17, 17, 21, 18, 13 } },
	{ 'R', { 30, 17, 17, 30, 20, 18, 17 } },
	{ 'S', { 15, 16, 16, 14, 1, 1, 30 } },
	{ 'T', { 31, 4, 4, 4, 4, 4, 4 } },
	{ 'U', { 17, 17, 17, 17, 17, 17, 14 } },
	{ 'V', { 17, 17, 17, 17, 17, 10, 4 } },
	{ 'W', { 17, 17, 17, 21, 21, 21, 10 } },
	{ 'X', { 17, 17, 10, 4, 10, 17, 17 } },
	{ 'Y', { 17, 17, 10, 4, 4, 4, 4 } },
	{ 'Z', { 31, 1, 2, 4, 8, 16, 31 } },
	{ '0', { 14, 17, 19, 21, 25, 17, 14 } },
	{ '1', { 4, 12, 4, 4, 4, 4, 14 } },
	{ '2', { 14, 17, 1, 2, 4, 8, 31 } },
	{ '3', { 30, 1, 1, 14, 1, 1, 30 } },
	{ '4', { 2, 6, 10, 18, 31, 2, 2 } },
	{ '5', { 31, 16, 16, 30, 1, 1, 30 } },
	{ '6', { 14, 16, 16, 30, 17, 17, 14 } },
	{ '7', { 31, 1, 2, 4, 8, 8, 8 } },
	{ '8', { 14, 17, 17, 14, 17, 17, 14 } },
	{ '9', { 14, 17, 17, 15, 1, 1, 14 } },
	{ '%', { 17, 2, 4, 8, 16, 17, 0 } },
	{ '.', { 0, 0, 0, 0, 0, 12, 12 } },
	{ '-', { 0, 0, 0, 31, 0, 0, 0 } },
	{ '+', { 0, 4, 4, 31, 4, 4, 0 } },
	{ ':', { 0, 12, 12, 0, 12, 12, 0 } },
	{ '/', { 1, 2, 2, 4, 8, 8, 16 } },
	{ '?', { 14, 17, 1, 2, 4, 0, 4 } }
};

const glyph *
find_glyph (char ch)
{
	for (const glyph &g : k_font)
		if (g.ch == ch)
			return &g;
	return nullptr;
}

int
text_width (const std::string &text, int scale)
{
	return text.empty () ? 0 : ((int) text.size () * 6 - 1) * scale;
}

void
draw_text (canvas &c, int x, int y, const std::string &text, pixel_t color, int scale = 1)
{
	for (char ch : text)
	{
		if (ch != ' ')
		{
			const glyph *g = find_glyph (ch);
			if (g)
			{
				for (int row = 0; row < 7; row++)
					for (int col = 0; col < 5; col++)
						if (g->rows[(size_t) row] & (1 << (4 - col)))
							c.rect (x + col * scale, y + row * scale, scale, scale, color);
			}
		}
		x += 6 * scale;
	}
}

void
draw_text_center (canvas &c, int y, const std::string &text, pixel_t color, int scale = 1)
{
	draw_text (c, (GAME_W - text_width (text, scale)) / 2, y, text, color, scale);
}

constexpr const char *k_rover_0[] =
{
	"............CCCCC............",
	"............CDDDC............",
	"..............G..............",
	"..O...........G..............",
	"..O....BBBBBBBBBBBBBBBB......",
	"BBBBBBBBBBBBBBBBBBBBBBBBBB...",
	".....GGGGGGGGGGGGGGGGGG......",
	".....YYYYYYYYYYYYYYYYYYY.....",
	".....YYOOYYYYYYYYYYYYYYY.....",
	".....YYYYYYYYYYYYYYYYYYY.....",
	".......D....D....D...........",
	"....DDDDD.DDDDD.DDDDD........",
	"...DWWWWWDWWWWWDWWWWWD.......",
	"...DWCCWWDWCCWWDWCCWWD.......",
	"...DWWWWWDWWWWWDWWWWWD.......",
	"....DDDDD.DDDDD.DDDDD........"
};

constexpr const char *k_rover_1[] =
{
	"............CCCCC............",
	"............CDDDC............",
	"..............G..............",
	"..O...........G..............",
	"..O....BBBBBBBBBBBBBBBB......",
	"BBBBBBBBBBBBBBBBBBBBBBBBBB...",
	".....GGGGGGGGGGGGGGGGGG......",
	".....YYYYYYYYYYYYYYYYYYY.....",
	".....YYOOYYYYYYYYYYYYYYY.....",
	".....YYYYYYYYYYYYYYYYYYY.....",
	".......D....D....D...........",
	"....DDDDD.DDDDD.DDDDD........",
	"...DWWWWWDWWWWWDWWWWWD.......",
	"...DWCWWWDWCWWWDWCWWWD.......",
	"...DWWWWWDWWWWWDWWWWWD.......",
	"....DDDDD.DDDDD.DDDDD........"
};

constexpr const char *k_rover_crouch[] =
{
	"..O.........CCCCC............",
	"..O.........CDDDC............",
	"..O....BBBBBBBBBBBBBBBB......",
	"BBBBBBBBBBBBBBBBBBBBBBBBBB...",
	".....GGGGGGGGGGGGGGGGGG......",
	".....YYYYYYYYYYYYYYYYYYY.....",
	".....YYOOYYYYYYYYYYYYYYY.....",
	".....YYYYYYYYYYYYYYYYYYY.....",
	"....DDDDD.DDDDD.DDDDD........",
	"...DWWWWWDWWWWWDWWWWWD.......",
	"...DWCCWWDWCCWWDWCCWWD.......",
	"....DDDDD.DDDDD.DDDDD........"
};

constexpr const char *k_ufo[] =
{
	".......UUUU.......",
	".....UUllllUU.....",
	"....UUllllllUU....",
	"..UUUUUUUUUUUUUU..",
	"UUUUUUUUUUUUUUUUUU",
	"..u..u..u..u..u...",
	".....UUUUUUUU....."
};

constexpr const char *k_satellite[] =
{
	"SSSSS.......SSSSS",
	"SsssS...DD..SsssS",
	"SSSSS..DDDD.SSSSS",
	".......DDDD......",
	"......DDLLDD.....",
	".......DDDD......",
	"SSSSS..DDDD.SSSSS",
	"SsssS...DD..SsssS",
	"SSSSS.......SSSSS"
};

constexpr const char *k_other_rover[] =
{
	"........AA.........",
	".......A..A........",
	"..SSSSSSSSSS.......",
	".SSSSSSSSSSSS..RR..",
	"....RRRRRRRRRRRRR..",
	"...RRRRRRRRRRRRRRR.",
	"..DDDDDDDDDDDDDDDD.",
	".DWWD.DWWD..DWWD.DW",
	"DWWWWDWWWWDDWWWWDWW",
	".DWWD.DWWD..DWWD.DW",
	"..DD...DD....DD...D"
};

constexpr const char *k_mars3[] =
{
	"......AA......",
	".....A..A.....",
	"......AA......",
	"....RRRRRR....",
	"...RRLRRLRR...",
	"..RRRRRRRRRR..",
	"....DDDDDD....",
	"...D..DD..D...",
	"..D...DD...D..",
	".D....DD....D.",
	"D.....DD.....D"
};

constexpr const char *k_helicopter[] =
{
	"......DD...........",
	"DDDDDDDDDDDDDDDDDDD",
	"......DD...........",
	".......D...........",
	".....RRRRRR........",
	"....RRRRRRRRRR.....",
	"....RRRLLRRRRR.....",
	".....RRRRRRRR......",
	".......DD..........",
	".....DDDDDD........"
};

template <size_t N>
constexpr int
sprite_width (const char *const (&rows)[N])
{
	int width = 0;
	while (rows[0][width] != 0)
		width++;
	return width;
}

template <size_t N>
constexpr bool
sprite_is_rectangular (const char *const (&rows)[N])
{
	for (size_t y = 0; y < N; y++)
	{
		int width = 0;
		while (rows[y][width] != 0)
			width++;
		if (width != sprite_width (rows))
			return false;
	}
	return true;
}

static_assert (sprite_is_rectangular (k_rover_0));
static_assert (sprite_is_rectangular (k_rover_1));
static_assert (sprite_is_rectangular (k_rover_crouch));
static_assert (sprite_is_rectangular (k_ufo));
static_assert (sprite_is_rectangular (k_satellite));
static_assert (sprite_is_rectangular (k_other_rover));
static_assert (sprite_is_rectangular (k_mars3));
static_assert (sprite_is_rectangular (k_helicopter));

pixel_t
sprite_color (char p, pixel_t accent)
{
	switch (p)
	{
	case 'R': return accent;
	case 'B': return rgb (57, 76, 127);
	case 'b': return rgb (91, 111, 165);
	case 'C': return rgb (218, 225, 224);
	case 'G': return rgb (112, 116, 117);
	case 'Y': return rgb (190, 145, 55);
	case 'O': return rgb (224, 83, 30);
	case 'S': return rgb (51, 90, 120);
	case 's': return rgb (88, 128, 150);
	case 'D': return rgb (31, 28, 31);
	case 'W': return rgb (114, 109, 102);
	case 'L': return rgb (221, 235, 180);
	case 'A': return rgb (66, 58, 55);
	case 'X': return rgb (92, 58, 43);
	case 'x': return rgb (134, 82, 55);
	case 'U': return rgb (132, 148, 154);
	case 'u': return rgb (70, 83, 91);
	case 'l': return rgb (118, 210, 217);
	default: return rgb (255, 0, 255);
	}
}

template <size_t N>
void
draw_sprite (canvas &c, int x, int y, const char *const (&rows)[N], pixel_t accent)
{
	for (size_t py = 0; py < N; py++)
		for (int px = 0; rows[py][px] != 0; px++)
			if (rows[py][px] != '.')
				c.put (x + px, y + (int) py, sprite_color (rows[py][px], accent));
}

enum class weather
{
	clear,
	haze,
	snow
};

enum class entity_kind
{
	rock,
	trench,
	ufo,
	satellite,
	sample,
	dust_devil,
	mars2,
	mars3,
	sojourner,
	zhurong,
	spirit,
	ingenuity,
	curiosity,
	perseverance,
	opportunity
};

enum class failure
{
	none,
	io_error,
	unknown_device,
	power
};

struct entity
{
	entity_kind kind;
	double position;
	bool handled;
	bool rewarded;
	double phase;
	int height_above_ground;
};

struct particle
{
	double x;
	double y;
	double vx;
	double vy;
	double life;
};

struct special_info
{
	entity_kind kind;
	double position;
	const char *name;
	const char *years;
	bool moving;
};

constexpr special_info k_specials[] =
{
	{ entity_kind::mars2, -1.0, "MARS 2", "1971", false },
	{ entity_kind::mars3, 20.0, "MARS 3", "1972", false },
	{ entity_kind::sojourner, 100.0, "SOJOURNER", "1997", false },
	{ entity_kind::zhurong, 1921.0, "ZHURONG", "2021-2022", false },
	{ entity_kind::spirit, 7730.0, "SPIRIT", "2004-2010", false },
	{ entity_kind::ingenuity, 17000.0, "INGENUITY", "2021-2024", false },
	{ entity_kind::curiosity, 37430.0, "CURIOSITY", "2012-", true },
	{ entity_kind::perseverance, 43610.0, "PERSEVERANCE", "2021-", true },
	{ entity_kind::opportunity, 45160.0, "OPPORTUNITY", "2004-2018", false }
};

struct rect_i
{
	int left;
	int top;
	int right;
	int bottom;
};

bool
intersects (const rect_i &a, const rect_i &b)
{
	return a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
}

struct game_state
{
	canvas screen;
	std::vector<entity> entities;
	std::vector<particle> particles;
	std::array<bool, std::size (k_specials)> special_spawned = {};
	std::uint32_t random = 1;
	double elapsed = 0.0;
	double distance = 0.0;
	double battery = BATTERY_CAPACITY;
	double jump_height = 0.0;
	double jump_velocity = 0.0;
	double jump_buffer = 0.0;
	double land_squash = 0.0;
	double panel_efficiency = 1.0;
	double notice_left = 0.0;
	char notice[32] = {};
	double rover_flash_left = 0.0;
	char rover_flash[16] = {};
	pixel_t rover_flash_color = 0;
	int files = 0;
	int files_sent = 0;
	double uplink_left = 0.0;
	bool uplink_hint_seen = false;
	double next_arrival = 0.0;
	entity_kind next_kind = entity_kind::rock;
	bool next_ceiling = false;
	bool ceiling_seen = false;
	double storm_pending = -1.0;
	double storm_left = 0.0;
	double storm_cooldown = 0.0;
	double retry_lock = 0.0;
	int weather_period = -1;
	weather current_weather = weather::clear;
	failure stopped = failure::none;
	bool down = false;
	bool jump_held = false;
	bool started = false;
	bool active = true;
	bool dirty = false;
	UINT dpi = 96;
	LARGE_INTEGER counter = {};
	LARGE_INTEGER frequency = {};
};

std::uint32_t
random_u32 (game_state &g)
{
	std::uint32_t x = g.random;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	g.random = x;
	return x;
}

double
random_unit (game_state &g)
{
	return (double) (random_u32 (g) & 0x00ffffff) / 16777216.0;
}

entity
make_entity (game_state &g, entity_kind kind, double position)
{
	double phase = random_unit (g) * 6.283185307;
	int height_above_ground = 0;
	if (kind == entity_kind::ufo)
	{
		constexpr unsigned height_count = UFO_MAX_HEIGHT_ABOVE_GROUND
			- UFO_MIN_HEIGHT_ABOVE_GROUND + 1;
		height_above_ground = UFO_MIN_HEIGHT_ABOVE_GROUND
			+ (int) (random_u32 (g) % height_count);
	}
	return { kind, position, false, false, phase, height_above_ground };
}

void
show_notice (game_state &g, const char *text)
{
	strcpy_s (g.notice, text);
	g.notice_left = NOTICE_SECONDS;
}

bool
is_daylight (double elapsed)
{
	return std::fmod (elapsed, 60.0) < 30.0;
}

/* Dust devils are raised by a sun-warmed surface, so one due to reach
   the rover after dark is rerolled.  */
entity_kind
random_obstacle_kind (game_state &g, double arrival)
{
	for (;;)
	{
		unsigned roll = random_u32 (g) % RANDOM_SPAWN_PERCENT_TOTAL;
		if (roll < ROCK_SPAWN_PERCENT)
			return entity_kind::rock;
		roll -= ROCK_SPAWN_PERCENT;
		if (roll < TRENCH_SPAWN_PERCENT)
			return entity_kind::trench;
		roll -= TRENCH_SPAWN_PERCENT;
		if (roll < SATELLITE_SPAWN_PERCENT)
			return entity_kind::satellite;
		roll -= SATELLITE_SPAWN_PERCENT;
		if (roll < SAMPLE_SPAWN_PERCENT)
			return entity_kind::sample;
		roll -= SAMPLE_SPAWN_PERCENT;
		if (roll >= DUST_DEVIL_SPAWN_PERCENT)
			return entity_kind::ufo;
		if (is_daylight (arrival))
			return entity_kind::dust_devil;
	}
}

void
choose_weather (game_state &g)
{
	double roll = random_unit (g);

	if (roll < 0.48)
		g.current_weather = weather::clear;
	else if (roll < 0.98)
		g.current_weather = weather::haze;
	else
		g.current_weather = weather::snow;

	g.storm_pending = -1.0;
	/* A haze period has one 10% storm roll.  Its random delay makes the
	   event unpredictable without changing the documented chance.  */
	if (g.current_weather == weather::haze && g.storm_left <= 0.0
	    && g.storm_cooldown <= 0.0 && random_unit (g) < 0.10)
		g.storm_pending = 2.0 + random_unit (g) * 18.0;
}

void
reset_game (game_state &g)
{
	g.entities.clear ();
	g.particles.clear ();
	g.special_spawned.fill (false);
	g.elapsed = 0.0;
	g.distance = 0.0;
	g.battery = BATTERY_CAPACITY;
	g.jump_height = 0.0;
	g.jump_velocity = 0.0;
	g.jump_buffer = 0.0;
	g.land_squash = 0.0;
	g.jump_held = false;
	g.next_ceiling = false;
	g.ceiling_seen = false;
	g.panel_efficiency = 1.0;
	g.notice_left = 0.0;
	g.rover_flash_left = 0.0;
	g.files = 0;
	g.files_sent = 0;
	g.uplink_left = 0.0;
	g.next_arrival = FIRST_RANDOM_OBSTACLE_METRES / BASE_METRES_PER_SECOND;
	g.next_kind = random_obstacle_kind (g, g.next_arrival);
	g.storm_pending = -1.0;
	g.storm_left = 0.0;
	g.storm_cooldown = 0.0;
	g.retry_lock = 0.0;
	g.weather_period = -1;
	g.current_weather = weather::clear;
	g.stopped = failure::none;
	g.down = false;
	QueryPerformanceCounter (&g.counter);
}

const special_info *
special_for (entity_kind kind)
{
	for (const special_info &s : k_specials)
		if (s.kind == kind)
			return &s;
	return nullptr;
}

double
entity_speed (entity_kind kind)
{
	switch (kind)
	{
	case entity_kind::rock: return ROCK_SPEED_METRES_PER_SECOND;
	case entity_kind::trench: return TRENCH_SPEED_METRES_PER_SECOND;
	case entity_kind::satellite: return SATELLITE_SPEED_METRES_PER_SECOND;
	case entity_kind::ufo: return UFO_SPEED_METRES_PER_SECOND;
	case entity_kind::dust_devil: return DUST_DEVIL_SPEED_METRES_PER_SECOND;
	default:
		const special_info *special = special_for (kind);
		return special && special->moving ? ACTIVE_ROVER_SPEED_METRES_PER_SECOND : 0.0;
	}
}

/* 0 at the start, 1 once the speed ramp is complete.  */
double
difficulty (const game_state &g)
{
	return (std::min) (1.0, g.distance / SPEED_RAMP_METRES);
}

double
rover_speed (const game_state &g)
{
	return BASE_METRES_PER_SECOND
		+ (MAX_METRES_PER_SECOND - BASE_METRES_PER_SECOND) * difficulty (g);
}

/* Puff dust from under the wheels.  It is thrown back at half the
   ground's scroll speed, so it trails the rover.  */
void
kick_dust (game_state &g, int count)
{
	double drift = -rover_speed (g) * PIXELS_PER_METRE * 0.5;
	for (int i = 0; i < count; i++)
	{
		particle p;
		p.x = ROVER_X + 2 + random_unit (g) * 22.0;
		p.y = GROUND_Y - 2;
		p.vx = drift + (random_unit (g) - 0.5) * 60.0;
		p.vy = -(35.0 + random_unit (g) * 45.0);
		p.life = DUST_PARTICLE_SECONDS * (0.6 + 0.4 * random_unit (g));
		g.particles.push_back (p);
	}
}

void
update_particles (game_state &g, double dt)
{
	for (particle &p : g.particles)
	{
		p.vy += DUST_PARTICLE_GRAVITY * dt;
		p.x += p.vx * dt;
		p.y += p.vy * dt;
		p.life -= dt;
	}
	g.particles.erase (std::remove_if (g.particles.begin (), g.particles.end (),
		[] (const particle &p) { return p.life <= 0.0 || p.y >= GROUND_Y; }),
		g.particles.end ());
}

/* Where the rover will meet a landmark.  A driving rover starts moving
   when it is spawned at the lookahead edge, so it is met beyond its
   landing site.  */
double
special_meeting_distance (const special_info &s, double speed)
{
	double own = s.moving ? ACTIVE_ROVER_SPEED_METRES_PER_SECOND : 0.0;
	return s.position + LOOKAHEAD_METRES * own / (speed - own);
}

/* Keep a full obstacle gap clear around every landmark, which has to
   be jumped like a rock.  */
bool
near_special (double distance, double speed)
{
	for (const special_info &s : k_specials)
		if (std::abs (distance - special_meeting_distance (s, speed))
		    < speed * OBSTACLE_MIN_GAP_SECONDS)
			return true;
	return false;
}

void
schedule_obstacle (game_state &g, double arrival)
{
	double max_gap = OBSTACLE_MAX_GAP_START_SECONDS
		+ (OBSTACLE_MAX_GAP_END_SECONDS - OBSTACLE_MAX_GAP_START_SECONDS) * difficulty (g);
	g.next_arrival = arrival + OBSTACLE_MIN_GAP_SECONDS
		+ random_unit (g) * (max_gap - OBSTACLE_MIN_GAP_SECONDS);
	g.next_kind = random_obstacle_kind (g, g.next_arrival);
	g.next_ceiling = g.next_kind == entity_kind::rock && g.distance >= CEILING_MIN_METRES
		&& random_unit (g) < CEILING_ROCK_CHANCE;
}

void
spawn_entities (game_state &g)
{
	for (size_t i = 0; i < std::size (k_specials); i++)
	{
		const special_info &s = k_specials[i];
		if (!g.special_spawned[i] && g.distance + LOOKAHEAD_METRES >= s.position)
		{
			g.entities.push_back (make_entity (g, s.kind, s.position));
			g.special_spawned[i] = true;
		}
	}

	/* Each obstacle enters at the lookahead edge just in time to reach
	   the rover at its scheduled moment.  The speed ramp is slow enough
	   that the speed can be taken as constant over that lead time.  */
	double speed = rover_speed (g);
	for (;;)
	{
		double closing = speed - entity_speed (g.next_kind);
		double lead = g.next_arrival - g.elapsed;
		if (lead * closing > LOOKAHEAD_METRES)
			break;
		if (!near_special (g.distance + speed * lead, speed))
		{
			g.entities.push_back (make_entity (g, g.next_kind, g.distance + closing * lead));
			/* The satellite enters further out, as it closes faster, and
			   meets the rover just after the rock.  */
			if (g.next_ceiling)
			{
				double satellite_closing = speed - SATELLITE_SPEED_METRES_PER_SECOND;
				g.entities.push_back (make_entity (g, entity_kind::satellite, g.distance
					+ satellite_closing * (lead + CEILING_SATELLITE_DELAY_SECONDS)));
				if (!g.ceiling_seen)
				{
					g.ceiling_seen = true;
					show_notice (g, "LOW ORBIT - TAP TO HOP");
				}
			}
		}
		schedule_obstacle (g, g.next_arrival);
	}
}

int
entity_width (entity_kind kind)
{
	switch (kind)
	{
	case entity_kind::rock: return 20;
	case entity_kind::trench: return 28;
	case entity_kind::dust_devil: return 20;
	case entity_kind::sample: return 9;
	case entity_kind::ufo: return sprite_width (k_ufo);
	case entity_kind::satellite: return sprite_width (k_satellite);
	case entity_kind::mars2:
	case entity_kind::mars3: return sprite_width (k_mars3);
	case entity_kind::ingenuity: return sprite_width (k_helicopter);
	default: return sprite_width (k_other_rover);
	}
}

int
air_obstacle_bottom (const entity &e)
{
	switch (e.kind)
	{
	case entity_kind::ufo: return GROUND_Y - e.height_above_ground;
	case entity_kind::satellite: return GROUND_Y - SATELLITE_HEIGHT_ABOVE_GROUND;
	case entity_kind::ingenuity: return GROUND_Y - INGENUITY_HEIGHT_ABOVE_GROUND;
	default: return GROUND_Y;
	}
}

rect_i
entity_rect (const entity &e, int x, int bob)
{
	/* Collision uses the solid core of each silhouette.  The previous
	   full-width boxes overlapped for longer than the rover could stay
	   above an obstacle, making a visually clean jump still fatal.  */
	switch (e.kind)
	{
	case entity_kind::rock: return { x + 2, GROUND_Y - 12, x + 18, GROUND_Y };
	case entity_kind::trench: return { x, GROUND_Y - 1, x + 28, GROUND_Y + 2 };
	case entity_kind::dust_devil: return { x + 6, GROUND_Y - DUST_DEVIL_HEIGHT, x + 14, GROUND_Y };
	case entity_kind::sample: return { x, GROUND_Y - 4, x + 9, GROUND_Y };
	case entity_kind::ufo: return { x + 3, air_obstacle_bottom (e) - 7 + bob,
			x + 17, air_obstacle_bottom (e) + bob };
	case entity_kind::satellite: return { x + 3, air_obstacle_bottom (e) - 9 + bob,
			x + 16, air_obstacle_bottom (e) + bob };
	case entity_kind::ingenuity: return { x + 4, air_obstacle_bottom (e) - 10 + bob,
			x + 17, air_obstacle_bottom (e) + bob };
	case entity_kind::mars2:
	case entity_kind::mars3: return { x + 2, GROUND_Y - 11, x + 12, GROUND_Y };
	case entity_kind::curiosity:
	case entity_kind::perseverance:
		return { x + 8, GROUND_Y - 11, x + 14, GROUND_Y };
	default: return { x + 4, GROUND_Y - 11, x + 18, GROUND_Y };
	}
}

void
end_game (game_state &g, failure why)
{
	if (g.stopped != failure::none)
		return;
	g.stopped = why;
	/* A jump pressed at the moment of impact must not dismiss the
	   game-over screen before it has been seen.  */
	g.retry_lock = RETRY_LOCK_SECONDS;
}

/* A short label floating above the rover.  */
void
flash_rover (game_state &g, const char *text, pixel_t color)
{
	strcpy_s (g.rover_flash, text);
	g.rover_flash_color = color;
	g.rover_flash_left = BATTERY_FLASH_SECONDS;
}

/* Shown in percent, the unit of the HUD gauge.  */
void
flash_battery_change (game_state &g, double delta)
{
	char text[16];
	sprintf_s (text, "%+.15g%%", delta * 100.0 / BATTERY_CAPACITY);
	flash_rover (g, text, delta < 0.0 ? rgb (255, 213, 90) : rgb (130, 230, 150));
}

/* The orbiter's pass is the uplink window: everything on board is sent,
   each file costing battery.  */
void
uplink_files (game_state &g)
{
	char text[32];
	sprintf_s (text, "UPLINK %d FILE%s", g.files, g.files == 1 ? "" : "S");
	show_notice (g, text);
	g.battery = (std::max) (0.0, g.battery - UPLINK_BATTERY_COST_PER_FILE * g.files);
	g.files_sent += g.files;
	g.files = 0;
	g.uplink_left = UPLINK_LINK_SECONDS;
}

void
collect_sample (game_state &g, entity &e)
{
	if (g.files >= DATA_CAPACITY)
	{
		show_notice (g, "DISK FULL");
		return;
	}
	e.rewarded = true;
	g.files++;
	flash_rover (g, "+DATA", rgb (150, 180, 235));
	if (!g.uplink_hint_seen)
	{
		g.uplink_hint_seen = true;
		show_notice (g, "UPLINK AT NIGHT UNDER ORBITERS");
	}
}


/* A buffered press whose key is already up fires as a short hop.  */
void
start_jump (game_state &g)
{
	g.jump_buffer = 0.0;
	g.battery = (std::max) (0.0, g.battery - JUMP_BATTERY_COST);
	if (g.battery <= 0.0)
	{
		end_game (g, failure::power);
		return;
	}
	g.down = false;
	g.jump_velocity = g.jump_held ? JUMP_VELOCITY : JUMP_CUT_VELOCITY;
	kick_dust (g, 3);
}

void
update_entities (game_state &g, double dt)
{
	/* Round the lift exactly as draw_rover() does, so the hitbox never
	   sits a pixel away from the sprite.  */
	int lift = (int) std::lround (g.jump_height);
	int rover_h = g.down && g.jump_height <= 0.0 ? 9 : 13;
	rect_i rover = { ROVER_X + 6, GROUND_Y - rover_h - lift + 1,
		ROVER_X + 24, GROUND_Y - lift };

	for (entity &e : g.entities)
	{
		e.position += entity_speed (e.kind) * dt;

		int x = ROVER_X + (int) std::lround ((e.position - g.distance) * PIXELS_PER_METRE);
		int bob = (int) std::lround (std::sin (g.elapsed * 3.0 + e.phase) * 2.0);
		rect_i obstacle = entity_rect (e, x, bob);

		if (e.kind == entity_kind::trench)
		{
			if (!e.handled && rover.right > obstacle.left && rover.left < obstacle.right)
			{
				e.handled = true;
				if (g.jump_height < 5.0)
				{
					g.battery = (std::max) (0.0, g.battery - TRENCH_BATTERY_COST);
					flash_battery_change (g, -TRENCH_BATTERY_COST);
				}
			}
			continue;
		}

		/* Dust devils are harmless; they clean the panels only for a
		   rover that drives through instead of jumping.  */
		if (e.kind == entity_kind::dust_devil)
		{
			if (!e.handled && g.jump_height < 3.0 && intersects (rover, obstacle))
			{
				e.handled = true;
				g.panel_efficiency = 1.0;
				show_notice (g, "PANELS CLEAN");
			}
			continue;
		}

		/* Samples are picked up only by driving over them.  */
		if (e.kind == entity_kind::sample)
		{
			if (!e.handled && g.jump_height < 3.0 && intersects (rover, obstacle))
			{
				e.handled = true;
				collect_sample (g, e);
			}
			continue;
		}

		/* An orbiter overhead after dark takes the files on board, at
		   any height: touching it is fatal anyway.  */
		if (e.kind == entity_kind::satellite && !e.rewarded && g.files > 0
		    && !is_daylight (g.elapsed)
		    && rover.right > obstacle.left && rover.left < obstacle.right)
		{
			e.rewarded = true;
			uplink_files (g);
		}

		if (e.kind == entity_kind::ufo && !e.rewarded
		    && ROVER_X + 12 >= obstacle.left && ROVER_X + 12 < obstacle.right
		    && g.jump_height < 3.0)
		{
			e.rewarded = true;
			g.battery = (std::min) (BATTERY_CAPACITY, g.battery + UFO_BATTERY_CHARGE);
			flash_battery_change (g, UFO_BATTERY_CHARGE);
		}

		if (intersects (rover, obstacle))
			end_game (g, e.kind == entity_kind::ufo ? failure::unknown_device : failure::io_error);
	}

	g.entities.erase (std::remove_if (g.entities.begin (), g.entities.end (), [&g] (const entity &e)
	{
		int x = ROVER_X + (int) std::lround ((e.position - g.distance) * PIXELS_PER_METRE);
		return x + entity_width (e.kind) < -8;
	}), g.entities.end ());
}

void
update_game (game_state &g, double dt)
{
	if (g.stopped != failure::none)
	{
		g.retry_lock = (std::max) (0.0, g.retry_lock - dt);
		return;
	}

	g.elapsed += dt;
	g.distance += rover_speed (g) * dt;
	g.rover_flash_left = (std::max) (0.0, g.rover_flash_left - dt);
	g.notice_left = (std::max) (0.0, g.notice_left - dt);
	g.uplink_left = (std::max) (0.0, g.uplink_left - dt);
	g.land_squash = (std::max) (0.0, g.land_squash - dt);

	bool airborne = g.jump_height > 0.0;
	if (g.down && airborne)
		g.jump_velocity -= FAST_FALL_GRAVITY * dt;
	g.jump_velocity -= JUMP_GRAVITY * dt;
	g.jump_height += g.jump_velocity * dt;
	if (g.jump_height <= 0.0)
	{
		g.jump_height = 0.0;
		g.jump_velocity = 0.0;
		if (airborne)
		{
			g.land_squash = LANDING_SQUASH_SECONDS;
			kick_dust (g, 10);
		}
	}
	update_particles (g, dt);
	if (g.jump_buffer > 0.0)
	{
		if (g.jump_height <= 0.0)
			start_jump (g);
		else
			g.jump_buffer = (std::max) (0.0, g.jump_buffer - dt);
	}

	int period = (int) (g.elapsed / 30.0);
	if (period != g.weather_period)
	{
		g.weather_period = period;
		choose_weather (g);
	}

	if (g.storm_cooldown > 0.0)
		g.storm_cooldown = (std::max) (0.0, g.storm_cooldown - dt);
	if (g.storm_left > 0.0)
	{
		g.storm_left -= dt;
		if (g.storm_left <= 0.0)
		{
			g.storm_left = 0.0;
			g.storm_cooldown = 30.0;
		}
	}
	else if (g.storm_pending >= 0.0)
	{
		g.storm_pending -= dt;
		if (g.storm_pending <= 0.0)
		{
			g.storm_pending = -1.0;
			g.storm_left = 20.0 + random_unit (g) * 40.0;
		}
	}

	double dust = g.storm_left > 0.0 ? PANEL_DUST_STORM_PER_SECOND
		: (g.current_weather == weather::haze ? PANEL_DUST_HAZE_PER_SECOND : 0.0);
	g.panel_efficiency = (std::max) (PANEL_MIN_EFFICIENCY, g.panel_efficiency - dust * dt);

	bool daylight = is_daylight (g.elapsed);
	double power = -SYSTEM_DRAIN_PER_SECOND;
	if (!daylight)
		power -= HEATER_DRAIN_PER_SECOND;
	if (g.storm_left > 0.0)
	{
		power -= STORM_DRAG_DRAIN_PER_SECOND;
		/* A storm after dark is the real threat: the heaters fight the
		   wind chill on top of the drag, at 16 per second in all.  */
		if (!daylight)
			power -= STORM_NIGHT_DRAIN_PER_SECOND;
	}
	else if (daylight)
	{
		double solar = g.current_weather == weather::clear ? SOLAR_CLEAR_CHARGE_PER_SECOND
			: (g.current_weather == weather::haze ? SOLAR_HAZE_CHARGE_PER_SECOND
			: SOLAR_SNOW_CHARGE_PER_SECOND);
		power += solar * g.panel_efficiency;
	}
	g.battery = std::clamp (g.battery + power * dt, 0.0, BATTERY_CAPACITY);
	if (g.battery <= 0.0)
		end_game (g, failure::power);

	spawn_entities (g);
	update_entities (g, dt);
}

pixel_t
lerp_color (pixel_t a, pixel_t b, double t)
{
	t = std::clamp (t, 0.0, 1.0);
	auto part = [t] (unsigned x, unsigned y)
	{
		return (unsigned) std::lround (x + ((double) y - x) * t);
	};
	return rgb (part ((a >> 16) & 255, (b >> 16) & 255),
		part ((a >> 8) & 255, (b >> 8) & 255), part (a & 255, b & 255));
}

pixel_t
sky_color (double cycle)
{
	constexpr pixel_t day = rgb (194, 139, 87);
	constexpr pixel_t sunset = rgb (199, 70, 48);
	constexpr pixel_t night = rgb (8, 15, 35);
	constexpr pixel_t sunrise = rgb (79, 96, 111);

	if (cycle < 24.0)
		return day;
	if (cycle < 27.0)
		return lerp_color (day, sunset, (cycle - 24.0) / 3.0);
	if (cycle < 30.0)
		return lerp_color (sunset, night, (cycle - 27.0) / 3.0);
	if (cycle < 54.0)
		return night;
	if (cycle < 57.0)
		return lerp_color (night, sunrise, (cycle - 54.0) / 3.0);
	return lerp_color (sunrise, day, (cycle - 57.0) / 3.0);
}

void
draw_disc (canvas &c, int cx, int cy, int radius, pixel_t color)
{
	for (int y = -radius; y <= radius; y++)
		for (int x = -radius; x <= radius; x++)
			if (x * x + y * y <= radius * radius)
				c.put (cx + x, cy + y, color);
}

void
draw_background (game_state &g)
{
	double cycle = std::fmod (g.elapsed, 60.0);
	pixel_t sky = sky_color (cycle);
	g.screen.clear (sky);

	/* Fixed stars emerge as the sky darkens.  */
	if (cycle >= 28.0 && cycle < 56.0)
	{
		constexpr POINT stars[] =
		{
			{ 12, 18 }, { 31, 42 }, { 55, 15 }, { 80, 33 }, { 106, 12 },
			{ 136, 27 }, { 159, 8 }, { 188, 38 }, { 214, 17 }, { 239, 31 },
			{ 267, 10 }, { 292, 43 }, { 309, 21 }, { 18, 70 }, { 116, 61 },
			{ 201, 69 }, { 281, 65 }
		};
		for (size_t i = 0; i < std::size (stars); i++)
		{
			pixel_t star = (i + (size_t) (g.elapsed * 3.0)) % 4 == 0
				? rgb (236, 228, 190) : rgb (143, 156, 169);
			g.screen.put (stars[i].x, stars[i].y, star);
		}
	}

	/* The sun crosses only the daylight half.  Sunset gets the requested
	   blue-grey surround; sunrise ends exactly where the next day starts.  */
	if (cycle < 30.0 || cycle >= 54.0)
	{
		double daylight_pos = cycle < 30.0 ? cycle / 30.0 : (cycle - 54.0) / 6.0;
		int sx = cycle < 30.0 ? 28 + (int) (daylight_pos * 264.0)
			: 8 + (int) std::lround (daylight_pos * 20.0);
		int sy = cycle < 30.0 ? 77 - (int) (std::sin (daylight_pos * 3.141592654) * 55.0)
			: 100 - (int) std::lround (daylight_pos * 23.0);
		if (cycle >= 24.0)
			draw_disc (g.screen, sx, sy, 11, rgb (91, 105, 113));
		draw_disc (g.screen, sx, sy, 6, rgb (238, 188, 85));
	}

	/* Two parallax ridgelines.  */
	pixel_t far_color = lerp_color (sky, rgb (91, 63, 62), 0.55);
	pixel_t near_color = lerp_color (sky, rgb (72, 47, 39), 0.72);
	int far_scroll = (int) std::fmod (g.distance * 3.0, 80.0);
	for (int base = -far_scroll - 80; base < GAME_W + 80; base += 80)
	{
		for (int x = 0; x < 80; x++)
		{
			int h = x < 27 ? x / 3 : (x < 47 ? 9 - (x - 27) / 5 : 5 - (x - 47) / 8);
			g.screen.rect (base + x, 112 - h, 1, GROUND_Y - (112 - h), far_color);
		}
	}
	int near_scroll = (int) std::fmod (g.distance * 7.0, 57.0);
	for (int base = -near_scroll - 57; base < GAME_W + 57; base += 57)
	{
		for (int x = 0; x < 57; x++)
		{
			int h = x < 17 ? x / 2 : (x < 31 ? 8 - (x - 17) / 2 : 2);
			g.screen.rect (base + x, 127 - h, 1, GROUND_Y - (127 - h), near_color);
		}
	}

	g.screen.rect (0, GROUND_Y, GAME_W, GAME_H - GROUND_Y, rgb (89, 50, 36));
	g.screen.rect (0, GROUND_Y, GAME_W, 2, rgb (145, 84, 54));
	int ground_scroll = (int) std::fmod (g.distance * PIXELS_PER_METRE, 37.0);
	for (int x = -ground_scroll; x < GAME_W; x += 37)
	{
		g.screen.rect (x, 154, 12, 2, rgb (116, 66, 44));
		g.screen.rect (x + 18, 166, 7, 2, rgb (65, 39, 33));
	}
}

void
draw_trench (canvas &c, int x)
{
	c.rect (x, GROUND_Y - 1, 28, 3, rgb (38, 29, 31));
	c.rect (x + 3, GROUND_Y + 2, 22, 4, rgb (25, 24, 28));
	c.rect (x + 7, GROUND_Y + 6, 14, 6, rgb (14, 18, 24));
	c.rect (x - 2, GROUND_Y - 2, 5, 2, rgb (151, 86, 54));
	c.rect (x + 25, GROUND_Y - 2, 5, 2, rgb (151, 86, 54));
}

void
draw_rock_rise (canvas &c, int x)
{
	constexpr pixel_t edge = rgb (101, 55, 42);
	constexpr pixel_t face = rgb (166, 88, 52);
	constexpr pixel_t light = rgb (218, 133, 72);
	constexpr pixel_t shade = rgb (126, 62, 44);

	/* A stepped Martian outcrop grows directly out of the terrain instead
	   of reading as a separate round boulder.  */
	c.rect (x + 8, GROUND_Y - 12, 4, 2, face);
	c.rect (x + 6, GROUND_Y - 10, 8, 2, face);
	c.rect (x + 4, GROUND_Y - 8, 12, 2, face);
	c.rect (x + 2, GROUND_Y - 6, 16, 2, face);
	c.rect (x, GROUND_Y - 4, 20, 4, face);
	c.rect (x + 8, GROUND_Y - 12, 4, 1, edge);
	c.rect (x + 6, GROUND_Y - 10, 2, 1, edge);
	c.rect (x + 12, GROUND_Y - 10, 2, 1, edge);
	c.rect (x + 4, GROUND_Y - 8, 2, 1, edge);
	c.rect (x + 14, GROUND_Y - 8, 2, 1, edge);
	c.rect (x + 2, GROUND_Y - 6, 2, 1, edge);
	c.rect (x + 16, GROUND_Y - 6, 2, 1, edge);
	c.rect (x, GROUND_Y - 4, 2, 1, edge);
	c.rect (x + 18, GROUND_Y - 4, 2, 1, edge);
	c.rect (x + 8, GROUND_Y - 11, 4, 1, light);
	c.rect (x + 7, GROUND_Y - 9, 4, 1, light);
	c.rect (x + 5, GROUND_Y - 7, 5, 1, light);
	c.rect (x + 13, GROUND_Y - 3, 7, 3, shade);
	c.rect (x + 10, GROUND_Y - 2, 3, 1, shade);
}

/* A translucent funnel, narrow at the ground and swaying as it widens,
   with a dithered swirl that climbs over time.  */
void
draw_dust_devil (canvas &c, int x, double t)
{
	constexpr pixel_t dust = rgb (226, 176, 120);
	int tick = (int) (t * 20.0);

	for (int r = 0; r < DUST_DEVIL_HEIGHT; r++)
	{
		int y = GROUND_Y - 1 - r;
		int half = 2 + r / 5;
		int cx = x + 10 + (int) std::lround (std::sin (t * 4.0 + r * 0.15) * (1.0 + r / 12.0));
		unsigned amount = (unsigned) (190 - r * 2);
		for (int dx = -half; dx <= half; dx++)
			if (((dx + r * 2 + tick) & 3) != 0)
				c.blend (cx + dx, y, dust, amount);
	}
}

/* Three hematite spherules with a glint, and a twinkle above so they
   are spotted in time to decide against jumping.  */
void
draw_sample (canvas &c, int x, double t)
{
	constexpr pixel_t body = rgb (66, 74, 102);
	constexpr pixel_t glint = rgb (176, 192, 226);
	struct { int cx, cy; } balls[] = { { x + 2, GROUND_Y - 2 }, { x + 6, GROUND_Y - 2 },
		{ x + 4, GROUND_Y - 5 } };

	for (const auto &b : balls)
	{
		c.rect (b.cx - 1, b.cy - 1, 3, 3, body);
		c.put (b.cx - 1, b.cy - 1, glint);
	}
	if (std::sin (t * 6.0) > 0.2)
	{
		constexpr pixel_t star = rgb (224, 236, 255);
		int sy = GROUND_Y - 10;
		c.put (x + 4, sy, star);
		c.put (x + 3, sy, star);
		c.put (x + 5, sy, star);
		c.put (x + 4, sy - 1, star);
		c.put (x + 4, sy + 1, star);
	}
}

/* Dotted radio link from the rover's mast to an orbiter, fading out.  */
void
draw_uplink (game_state &g, int sat_x, int sat_y)
{
	int x0 = ROVER_X + 14;
	int y0 = GROUND_Y - 16 - (int) std::lround (g.jump_height);
	int n = (std::max) (std::abs (sat_x - x0), std::abs (sat_y - y0));
	unsigned amount = (unsigned) (220.0 * g.uplink_left / UPLINK_LINK_SECONDS);
	int phase = (int) (g.elapsed * 30.0);

	for (int i = 0; i <= n; i++)
		if (((i + phase) & 3) < 2)
			g.screen.blend (x0 + (sat_x - x0) * i / (std::max) (n, 1),
				y0 + (sat_y - y0) * i / (std::max) (n, 1), rgb (130, 204, 198), amount);
}

pixel_t
special_accent (entity_kind kind)
{
	switch (kind)
	{
	case entity_kind::sojourner: return rgb (155, 128, 82);
	case entity_kind::zhurong: return rgb (176, 103, 55);
	case entity_kind::spirit: return rgb (165, 142, 94);
	case entity_kind::curiosity: return rgb (189, 173, 134);
	case entity_kind::perseverance: return rgb (184, 131, 70);
	case entity_kind::opportunity: return rgb (148, 132, 91);
	default: return rgb (166, 104, 65);
	}
}

void
draw_entity (game_state &g, const entity &e)
{
	int x = ROVER_X + (int) std::lround ((e.position - g.distance) * PIXELS_PER_METRE);
	int bob = (int) std::lround (std::sin (g.elapsed * 3.0 + e.phase) * 2.0);

	switch (e.kind)
	{
	case entity_kind::rock:
		draw_rock_rise (g.screen, x);
		break;
	case entity_kind::trench:
		draw_trench (g.screen, x);
		break;
	case entity_kind::dust_devil:
		draw_dust_devil (g.screen, x, g.elapsed + e.phase);
		break;
	case entity_kind::ufo:
	{
		int y = air_obstacle_bottom (e) - 7 + bob;
		int beam_x = x + entity_width (e.kind) / 2;
		if (!e.rewarded && std::abs (beam_x - (ROVER_X + 12)) < 15)
		{
			for (int by = y + 7; by < GROUND_Y; by++)
			{
				int half = 2 + (by - (y + 7)) / 5;
				for (int bx = -half; bx <= half; bx++)
					if (((bx + by) & 1) == 0)
						g.screen.blend (beam_x + bx, by, rgb (125, 235, 220), 150);
			}
		}
		draw_sprite (g.screen, x, y, k_ufo, rgb (160, 160, 160));
		break;
	}
	case entity_kind::satellite:
		if (e.rewarded && g.uplink_left > 0.0)
			draw_uplink (g, x + entity_width (e.kind) / 2, air_obstacle_bottom (e) + bob);
		draw_sprite (g.screen, x, air_obstacle_bottom (e) - 9 + bob,
			k_satellite, rgb (150, 150, 150));
		break;
	case entity_kind::sample:
		if (!e.rewarded)
			draw_sample (g.screen, x, g.elapsed + e.phase);
		break;
	case entity_kind::mars2:
	case entity_kind::mars3:
		draw_sprite (g.screen, x, GROUND_Y - 11, k_mars3, rgb (150, 113, 77));
		break;
	case entity_kind::ingenuity:
		draw_sprite (g.screen, x, air_obstacle_bottom (e) - 10 + bob,
			k_helicopter, rgb (175, 120, 68));
		break;
	default:
		draw_sprite (g.screen, x, GROUND_Y - 11, k_other_rover, special_accent (e.kind));
		break;
	}

	const special_info *special = special_for (e.kind);
	if (special && x > -60 && x < GAME_W + 10)
	{
		int center_x = x + entity_width (e.kind) / 2;
		int name_x = center_x - text_width (special->name, 1) / 2;
		int years_x = center_x - text_width (special->years, 1) / 2;
		draw_text (g.screen, name_x, GROUND_Y + 5, special->name, rgb (238, 218, 169));
		draw_text (g.screen, years_x, GROUND_Y + 14, special->years, rgb (194, 172, 136));
	}
}

void
draw_particles (game_state &g)
{
	/* 2 x 2 puffs in pale dust, so they read against the dark ridges.  */
	for (const particle &p : g.particles)
	{
		int x = (int) std::lround (p.x);
		int y = (int) std::lround (p.y);
		unsigned amount = (unsigned) (230.0 * (std::min) (1.0, 2.0 * p.life / DUST_PARTICLE_SECONDS));
		for (int dy = 0; dy < 2; dy++)
			for (int dx = 0; dx < 2; dx++)
				g.screen.blend (x + dx, y + dy, rgb (232, 190, 140), amount);
	}
}

void
draw_rover (game_state &g)
{
	int y;
	/* The crouch frame doubles as a brief squash on touchdown; the
	   hitbox follows only the duck key.  */
	if ((g.down || g.land_squash > 0.0) && g.jump_height <= 0.0)
	{
		y = GROUND_Y - 12;
		draw_sprite (g.screen, ROVER_X, y, k_rover_crouch, rgb (177, 100, 51));
	}
	else
	{
		y = GROUND_Y - 16 - (int) std::lround (g.jump_height);
		if (((int) (g.elapsed * 10.0) & 1) == 0)
			draw_sprite (g.screen, ROVER_X, y, k_rover_0, rgb (177, 100, 51));
		else
			draw_sprite (g.screen, ROVER_X, y, k_rover_1, rgb (177, 100, 51));
	}

	if (g.rover_flash_left > 0.0)
		draw_text (g.screen, ROVER_X + 5, y - 10, g.rover_flash, g.rover_flash_color);
}

void
draw_weather (game_state &g)
{
	std::uint32_t tick = (std::uint32_t) (g.elapsed * 18.0);

	if (g.current_weather == weather::snow && g.storm_left <= 0.0)
	{
		for (unsigned i = 0; i < 48; i++)
		{
			int x = (int) ((i * 67 + tick * (1 + i % 3)) % GAME_W);
			int y = (int) ((i * 41 + tick * (2 + i % 2)) % GROUND_Y);
			g.screen.put (x, y, i % 4 == 0 ? rgb (235, 241, 235) : rgb (185, 201, 201));
		}
	}
	else if (g.current_weather == weather::haze && g.storm_left <= 0.0)
	{
		for (int y = 18; y < GROUND_Y; y += 4)
			for (int x = (y & 7); x < GAME_W; x += 8)
				g.screen.blend (x, y, rgb (184, 125, 73), 55);
	}

	if (g.storm_left > 0.0)
	{
		for (int y = 0; y < GAME_H; y++)
			for (int x = 0; x < GAME_W; x++)
				if (((x * 3 + y * 5 + (int) tick) & 15) < 5)
					g.screen.blend (x, y, rgb (96, 59, 41), 105);
		for (unsigned i = 0; i < 70; i++)
		{
			int x = (int) ((i * 47 + tick * 7) % (GAME_W + 40)) - 20;
			int y = (int) ((i * 29 + tick * 2) % GROUND_Y);
			g.screen.rect (x, y, 7, 1, rgb (176, 106, 60));
		}
		/* Dust closes in at both sides without hiding the HUD.  */
		for (int x = 0; x < 46; x++)
			for (int y = 15; y < GROUND_Y; y++)
				if (((x + y + (int) tick) & 3) != 0)
				{
					g.screen.blend (x, y, rgb (53, 38, 34), (unsigned) (120 - x * 2));
					g.screen.blend (GAME_W - 1 - x, y, rgb (53, 38, 34), (unsigned) (120 - x * 2));
				}
	}
}

/* The first landmark still ahead of the rover, following a driving
   rover once it has been spawned and set off.  */
const special_info *
next_landmark (const game_state &g, double &remaining)
{
	for (size_t i = 0; i < std::size (k_specials); i++)
	{
		const special_info &s = k_specials[i];
		double position = s.position;
		if (g.special_spawned[i])
			for (const entity &e : g.entities)
				if (e.kind == s.kind)
					position = e.position;
		if (position > g.distance)
		{
			remaining = position - g.distance;
			return &s;
		}
	}
	return nullptr;
}

void
draw_hud (game_state &g)
{
	char distance[32];
	char percent[16];
	int battery_percent = (int) std::lround (g.battery * 100.0 / BATTERY_CAPACITY);

	sprintf_s (distance, "%llu M", (unsigned long long) std::floor (g.distance));
	sprintf_s (percent, "%d%%", battery_percent);
	pixel_t ink = rgb (244, 231, 189);
	pixel_t shadow = rgb (49, 38, 37);
	draw_text (g.screen, 7, 7, distance, shadow);
	draw_text (g.screen, 6, 6, distance, ink);

	double remaining;
	const special_info *next = next_landmark (g, remaining);
	if (next)
	{
		char target[48];
		if (remaining >= 1000.0)
			sprintf_s (target, "%s %.1fKM", next->name, remaining / 1000.0);
		else
			sprintf_s (target, "%s %dM", next->name, (int) std::ceil (remaining));
		draw_text (g.screen, 7, 17, target, shadow);
		draw_text (g.screen, 6, 16, target, rgb (194, 172, 136));
	}

	/* Science store, once there is anything to report.  */
	if (g.files > 0 || g.files_sent > 0)
	{
		char data[32];
		sprintf_s (data, "DATA %d/%d  SENT %d", g.files, DATA_CAPACITY, g.files_sent);
		draw_text (g.screen, 7, 27, data, shadow);
		draw_text (g.screen, 6, 26, data,
			g.files >= DATA_CAPACITY ? rgb (224, 120, 90) : rgb (150, 180, 235));
	}

	/* The icon is pinned to the right margin and the percentage is
	   right-aligned against it, so a change in digit count moves only
	   the text's left edge.  The 9 px icon is centred on the 7 px text.  */
	int battery_x = GAME_W - 6 - 32;
	int battery_y = 5;
	int pct_x = battery_x - 4 - text_width (percent, 1);
	g.screen.rect (battery_x, battery_y, 30, 9, ink);
	g.screen.rect (battery_x + 1, battery_y + 1, 28, 7, shadow);
	g.screen.rect (battery_x + 30, battery_y + 2, 2, 5, ink);
	int filled = (battery_percent * 28 + 99) / 100;
	pixel_t charge = battery_percent <= 20 ? rgb (224, 71, 53) : rgb (113, 205, 100);
	if (filled > 0)
		g.screen.rect (battery_x + 1, battery_y + 1, filled, 7, charge);
	draw_text (g.screen, pct_x + 1, 7, percent, shadow);
	draw_text (g.screen, pct_x, 6, percent, ink);

	/* Solar panel efficiency, right-aligned under the battery.  */
	char solar[16];
	int solar_percent = (int) std::lround (g.panel_efficiency * 100.0);
	sprintf_s (solar, "SOLAR %d%%", solar_percent);
	int solar_x = battery_x + 32 - text_width (solar, 1);
	draw_text (g.screen, solar_x + 1, 17, solar, shadow);
	draw_text (g.screen, solar_x, 16, solar,
		solar_percent < 50 ? rgb (224, 120, 90) : rgb (194, 172, 136));

	/* Below the three HUD lines on the left.  */
	if (g.notice_left > 0.0)
	{
		draw_text_center (g.screen, 41, g.notice, shadow);
		draw_text_center (g.screen, 40, g.notice, rgb (130, 204, 198));
	}

	if (g.started && g.elapsed < 5.0 && g.stopped == failure::none)
	{
		draw_text_center (g.screen, 108, "SPACE/UP JUMP  HOLD FOR HIGHER", ink);
		draw_text_center (g.screen, 118, "DOWN DUCK", ink);
	}
}

void
draw_game_over (game_state &g)
{
	if (g.stopped == failure::none)
		return;

	for (int y = 49; y < 126; y++)
		for (int x = 53; x < 267; x++)
			if (((x + y) & 1) == 0)
				g.screen.blend (x, y, rgb (5, 10, 20), 220);
	g.screen.rect (52, 48, 216, 1, rgb (200, 164, 106));
	g.screen.rect (52, 126, 216, 1, rgb (200, 164, 106));

	draw_text_center (g.screen, 56, "ROVER OFFLINE", rgb (237, 190, 92), 2);
	const char *reason = g.stopped == failure::io_error ? "I/O ERROR"
		: (g.stopped == failure::unknown_device ? "UNKNOWN DEVICE" : "POWER FAILURE");
	draw_text_center (g.screen, 75, reason, rgb (235, 226, 194));

	char score[48];
	sprintf_s (score, "DISTANCE %lluM", (unsigned long long) std::floor (g.distance));
	draw_text_center (g.screen, 87, score, rgb (235, 226, 194));
	/* Files still on board at the crash never reach Earth.  */
	if (g.files > 0)
		sprintf_s (score, "SCIENCE %d  LOST %d", g.files_sent, g.files);
	else
		sprintf_s (score, "SCIENCE %d", g.files_sent);
	draw_text_center (g.screen, 97, score,
		g.files > 0 ? rgb (224, 150, 110) : rgb (150, 180, 235));
	if (g.retry_lock <= 0.0)
		draw_text_center (g.screen, 112, "PRESS SPACE TO RETRY", rgb (130, 204, 198));
}

void
draw_start_prompt (game_state &g)
{
	if (g.started)
		return;
	draw_text_center (g.screen, 91, "PRESS ANY KEY TO START", rgb (244, 231, 189));
}

void
render_game (game_state &g)
{
	draw_background (g);
	for (const entity &e : g.entities)
		draw_entity (g, e);
	draw_rover (g);
	draw_particles (g);
	draw_weather (g);
	draw_hud (g);
	draw_start_prompt (g);
	draw_game_over (g);
}

/* The largest whole multiple of the framebuffer that fits, so every
   game pixel is the same size under nearest-neighbour scaling.  */
int
integer_scale (int client_w, int client_h)
{
	return (std::min) (client_w / GAME_W, client_h / GAME_H);
}

/* Snap the client area to a whole multiple of the framebuffer so the
   default window has no letterbox.  */
void
fit_window_to_scale (HWND dlg)
{
	RECT client;
	RECT window;
	GetClientRect (dlg, &client);
	GetWindowRect (dlg, &window);
	int scale = (std::max) (1, integer_scale (client.right, client.bottom));
	int dw = GAME_W * scale - client.right;
	int dh = GAME_H * scale - client.bottom;
	SetWindowPos (dlg, nullptr, window.left - dw / 2, window.top - dh / 2,
		window.right - window.left + dw, window.bottom - window.top + dh,
		SWP_NOZORDER | SWP_NOACTIVATE);
}

void
paint_game (HWND dlg, game_state &g)
{
	PAINTSTRUCT ps;
	HDC dc = BeginPaint (dlg, &ps);
	RECT rc;
	GetClientRect (dlg, &rc);
	int client_w = rc.right;
	int client_h = rc.bottom;
	if (client_w <= 0 || client_h <= 0)
	{
		EndPaint (dlg, &ps);
		return;
	}
	int draw_w;
	int draw_h;
	int scale = integer_scale (client_w, client_h);
	if (scale >= 1)
	{
		draw_w = GAME_W * scale;
		draw_h = GAME_H * scale;
	}
	else
	{
		/* Below 1:1 only a fractional fit is possible.  */
		draw_w = client_w;
		draw_h = draw_w * GAME_H / GAME_W;
		if (draw_h > client_h)
		{
			draw_h = client_h;
			draw_w = draw_h * GAME_W / GAME_H;
		}
	}
	int draw_x = (client_w - draw_w) / 2;
	int draw_y = (client_h - draw_h) / 2;

	BITMAPINFO bmi = {};
	bmi.bmiHeader.biSize = sizeof (bmi.bmiHeader);
	bmi.bmiHeader.biWidth = GAME_W;
	bmi.bmiHeader.biHeight = -GAME_H;
	bmi.bmiHeader.biPlanes = 1;
	bmi.bmiHeader.biBitCount = 32;
	bmi.bmiHeader.biCompression = BI_RGB;
	SetStretchBltMode (dc, COLORONCOLOR);
	StretchDIBits (dc, draw_x, draw_y, draw_w, draw_h, 0, 0, GAME_W, GAME_H,
		g.screen.pixels.data (), &bmi, DIB_RGB_COLORS, SRCCOPY);

	/* Paint the letterbox around the image, never under it: with no
	   pixel drawn twice there is no intermediate black frame for the
	   compositor to catch, so no back buffer is needed.  */
	ExcludeClipRect (dc, draw_x, draw_y, draw_x + draw_w, draw_y + draw_h);
	FillRect (dc, &rc, (HBRUSH) GetStockObject (BLACK_BRUSH));
	EndPaint (dlg, &ps);
}

void
press_jump (game_state &g)
{
	if (g.stopped != failure::none)
	{
		if (g.retry_lock <= 0.0)
			reset_game (g);
		return;
	}
	g.jump_held = true;
	if (g.jump_height <= 0.0)
		start_jump (g);
	else
		g.jump_buffer = JUMP_BUFFER_SECONDS;
}

void
release_jump (game_state &g)
{
	g.jump_held = false;
	if (g.jump_velocity > JUMP_CUT_VELOCITY)
		g.jump_velocity = JUMP_CUT_VELOCITY;
}

game_state *
state_from (HWND dlg)
{
	return (game_state *) GetWindowLongPtrW (dlg, DWLP_USER);
}

INT_PTR CALLBACK
game_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	game_state *g = state_from (dlg);

	switch (msg)
	{
	case WM_INITDIALOG:
	{
		g = new game_state;
		SetWindowLongPtrW (dlg, DWLP_USER, (LONG_PTR) g);
		g->dpi = dpi_for_window (dlg);
		LARGE_INTEGER seed;
		QueryPerformanceCounter (&seed);
		g->random = (std::uint32_t) seed.QuadPart ^ (std::uint32_t) GetTickCount64 ();
		if (g->random == 0)
			g->random = 1;
		QueryPerformanceFrequency (&g->frequency);
		reset_game (*g);
		render_game (*g);
		SetWindowTextW (dlg, L"FSROVER : MARS RUNNER");
		center_on_owner (dlg, dpi_scale (g->dpi, 660), dpi_scale (g->dpi, 400));
		fit_window_to_scale (dlg);
		SetTimer (dlg, GAME_TIMER, 16, nullptr);
		SetFocus (dlg);
		return FALSE;
	}
	case WM_TIMER:
		if (g && wp == GAME_TIMER)
		{
			LARGE_INTEGER now;
			QueryPerformanceCounter (&now);
			double dt = (double) (now.QuadPart - g->counter.QuadPart) / (double) g->frequency.QuadPart;
			g->counter = now;
			/* Paused, waiting to start and a settled game-over screen
			   are still frames: redraw only when something moved.  */
			if (g->active && g->started
			    && (g->stopped == failure::none || g->retry_lock > 0.0))
			{
				update_game (*g, (std::min) (dt, 0.05));
				g->dirty = true;
			}
			if (g->dirty)
			{
				g->dirty = false;
				render_game (*g);
				InvalidateRect (dlg, nullptr, FALSE);
			}
		}
		return TRUE;
	case WM_KEYDOWN:
		if (g)
		{
			if (!g->started)
			{
				g->started = true;
				QueryPerformanceCounter (&g->counter);
			}
			if ((wp == VK_SPACE || wp == VK_UP) && !(lp & (1LL << 30)))
				press_jump (*g);
			else if (wp == VK_DOWN)
				g->down = true;
			g->dirty = true;
		}
		return TRUE;
	case WM_KEYUP:
		if (g && wp == VK_DOWN)
		{
			g->down = false;
			g->dirty = true;
		}
		else if (g && (wp == VK_SPACE || wp == VK_UP))
			release_jump (*g);
		return TRUE;
	case WM_GETDLGCODE:
		/* DialogBox treats arrow keys as focus navigation unless the focused
		   window explicitly requests them.  Keep other dialog keys, notably
		   Escape, on the normal dialog path.  */
		SetWindowLongPtrW (dlg, DWLP_MSGRESULT, DLGC_WANTARROWS);
		return TRUE;
	case WM_ACTIVATE:
		if (g)
		{
			g->active = LOWORD (wp) != WA_INACTIVE;
			QueryPerformanceCounter (&g->counter);
			/* Key-up messages go to the newly active window.  */
			if (!g->active)
			{
				g->down = false;
				g->jump_buffer = 0.0;
				release_jump (*g);
			}
		}
		return TRUE;
	case WM_PAINT:
		if (g)
			paint_game (dlg, *g);
		return TRUE;
	case WM_ERASEBKGND:
		SetWindowLongPtrW (dlg, DWLP_MSGRESULT, 1);
		return TRUE;
	case WM_SIZE:
		InvalidateRect (dlg, nullptr, FALSE);
		return TRUE;
	case WM_GETMINMAXINFO:
		if (g)
			((MINMAXINFO *) lp)->ptMinTrackSize =
				{ dpi_scale (g->dpi, 400), dpi_scale (g->dpi, 260) };
		return TRUE;
	case WM_DPICHANGED:
		if (g)
			g->dpi = HIWORD (wp);
		dpi_take_suggested (dlg, lp);
		return FALSE;
	case WM_COMMAND:
		if (LOWORD (wp) == IDCANCEL)
		{
			EndDialog (dlg, 0);
			return TRUE;
		}
		break;
	case WM_CLOSE:
		EndDialog (dlg, 0);
		return TRUE;
	case WM_DESTROY:
		KillTimer (dlg, GAME_TIMER);
		delete g;
		SetWindowLongPtrW (dlg, DWLP_USER, 0);
		return TRUE;
	}
	return FALSE;
}

} // namespace

void
show_rover_game (HWND owner)
{
	modal_scope hold;
	DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_GAME), owner, game_dlg_proc, 0);
}
