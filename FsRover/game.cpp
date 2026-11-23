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

/* The About-box easter egg: a dialog hosting the toolkit-free game in
   common/rover_game.cpp.  StretchDIBits scales its framebuffer with
   nearest-neighbour sampling.  The game is GUI-thread-only and never
   touches grub's backend state.  */

#include <windows.h>

#include <algorithm>

#include "gui.h"
#include "resource.h"
#include "../common/rover_game.h"

namespace
{

constexpr int GAME_W = rover_game::WIDTH;
constexpr int GAME_H = rover_game::HEIGHT;
constexpr UINT_PTR GAME_TIMER = 1;

struct game_window
{
	rover_game::state *game;
	UINT dpi;
	LARGE_INTEGER counter;
	LARGE_INTEGER frequency;
};

/* Snap the client area to a whole multiple of the framebuffer so the
   default window has no letterbox.  */
void
fit_window_to_scale (HWND dlg)
{
	RECT client;
	RECT window;
	GetClientRect (dlg, &client);
	GetWindowRect (dlg, &window);
	int scale = (std::max) (1, rover_game::integer_scale (client.right, client.bottom));
	int dw = GAME_W * scale - client.right;
	int dh = GAME_H * scale - client.bottom;
	SetWindowPos (dlg, nullptr, window.left - dw / 2, window.top - dh / 2,
		window.right - window.left + dw, window.bottom - window.top + dh,
		SWP_NOZORDER | SWP_NOACTIVATE);
}

void
paint_game (HWND dlg, const game_window &w)
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
	int scale = rover_game::integer_scale (client_w, client_h);
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

	/* The framebuffer's 0x00RRGGBB words are exactly a top-down 32-bit
	   BI_RGB DIB.  */
	BITMAPINFO bmi = {};
	bmi.bmiHeader.biSize = sizeof (bmi.bmiHeader);
	bmi.bmiHeader.biWidth = GAME_W;
	bmi.bmiHeader.biHeight = -GAME_H;
	bmi.bmiHeader.biPlanes = 1;
	bmi.bmiHeader.biBitCount = 32;
	bmi.bmiHeader.biCompression = BI_RGB;
	SetStretchBltMode (dc, COLORONCOLOR);
	StretchDIBits (dc, draw_x, draw_y, draw_w, draw_h, 0, 0, GAME_W, GAME_H,
		rover_game::pixels (w.game), &bmi, DIB_RGB_COLORS, SRCCOPY);

	/* Paint the letterbox around the image, never under it: with no
	   pixel drawn twice there is no intermediate black frame for the
	   compositor to catch, so no back buffer is needed.  */
	ExcludeClipRect (dc, draw_x, draw_y, draw_x + draw_w, draw_y + draw_h);
	FillRect (dc, &rc, (HBRUSH) GetStockObject (BLACK_BRUSH));
	EndPaint (dlg, &ps);
}

rover_game::key
game_key (WPARAM vk)
{
	if (vk == VK_SPACE || vk == VK_UP)
		return rover_game::key::jump;
	if (vk == VK_DOWN)
		return rover_game::key::duck;
	return rover_game::key::other;
}

game_window *
window_from (HWND dlg)
{
	return (game_window *) GetWindowLongPtrW (dlg, DWLP_USER);
}

INT_PTR CALLBACK
game_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	game_window *w = window_from (dlg);

	switch (msg)
	{
	case WM_INITDIALOG:
	{
		LARGE_INTEGER seed;
		QueryPerformanceCounter (&seed);
		w = new game_window;
		w->game = rover_game::create ((std::uint32_t) seed.QuadPart
			^ (std::uint32_t) GetTickCount64 ());
		w->dpi = dpi_for_window (dlg);
		QueryPerformanceFrequency (&w->frequency);
		QueryPerformanceCounter (&w->counter);
		SetWindowLongPtrW (dlg, DWLP_USER, (LONG_PTR) w);
		SetWindowTextW (dlg, L"FSROVER : MARS RUNNER");
		center_on_owner (dlg, dpi_scale (w->dpi, 660), dpi_scale (w->dpi, 400));
		fit_window_to_scale (dlg);
		SetTimer (dlg, GAME_TIMER, 16, nullptr);
		SetFocus (dlg);
		return FALSE;
	}
	case WM_TIMER:
		if (w && wp == GAME_TIMER)
		{
			LARGE_INTEGER now;
			QueryPerformanceCounter (&now);
			double dt = (double) (now.QuadPart - w->counter.QuadPart) / (double) w->frequency.QuadPart;
			w->counter = now;
			if (rover_game::tick (w->game, dt))
				InvalidateRect (dlg, nullptr, FALSE);
		}
		return TRUE;
	case WM_KEYDOWN:
		if (w)
			rover_game::key_down (w->game, game_key (wp));
		return TRUE;
	case WM_KEYUP:
		if (w)
			rover_game::key_up (w->game, game_key (wp));
		return TRUE;
	case WM_GETDLGCODE:
		/* DialogBox treats arrow keys as focus navigation unless the focused
		   window explicitly requests them.  Keep other dialog keys, notably
		   Escape, on the normal dialog path.  */
		SetWindowLongPtrW (dlg, DWLP_MSGRESULT, DLGC_WANTARROWS);
		return TRUE;
	case WM_ACTIVATE:
		if (w)
			rover_game::set_active (w->game, LOWORD (wp) != WA_INACTIVE);
		return TRUE;
	case WM_PAINT:
		if (w)
			paint_game (dlg, *w);
		return TRUE;
	case WM_ERASEBKGND:
		SetWindowLongPtrW (dlg, DWLP_MSGRESULT, 1);
		return TRUE;
	case WM_SIZE:
		InvalidateRect (dlg, nullptr, FALSE);
		return TRUE;
	case WM_GETMINMAXINFO:
		if (w)
			((MINMAXINFO *) lp)->ptMinTrackSize =
				{ dpi_scale (w->dpi, 400), dpi_scale (w->dpi, 260) };
		return TRUE;
	case WM_DPICHANGED:
		if (w)
			w->dpi = HIWORD (wp);
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
		if (w)
		{
			rover_game::destroy (w->game);
			delete w;
		}
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
