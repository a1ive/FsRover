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

/* Image viewer: one read_chunk task loads the whole file (a small probe
 * read first, so oversized files are refused before the big transfer),
 * stb_image decodes it to RGBA which is premultiplied/swapped to the
 * BGRA Direct2D wants (formats stb lacks fall back to WIC), and the
 * dialog's client area is rendered with an ID2D1HwndRenderTarget --
 * fit-to-window by default, mouse wheel zooms at the cursor, dragging
 * pans, double click toggles fit/100%.  GIF animations decode all
 * frames at once (stb's API) and advance on a timer.  d2d1.dll is
 * resolved with LoadLibrary and WIC through plain COM activation, so
 * the executable takes no import on either, like the DPI and dokan
 * APIs.  */

#include <windows.h>
#include <d2d1.h>
#include <initguid.h>	/* define the WIC GUIDs here instead of linking */
#include <wincodec.h>

#include <string>
#include <vector>

#include "gui.h"
#include "resource.h"
#include "strconv.h"

/* Declarations only; the implementation is compiled in stb_impl.c.  */
#define STBI_NO_STDIO
#include "stb_image.h"

HWND g_img;	/* modal image viewer, null when closed */

namespace
{

/* Image viewer state; see the block comment at the top of the file.  */
constexpr UINT IMG_PROBE = 4096;	/* first-stage sniff read */
constexpr UINT64 IMG_WARN = 32u << 20;	/* ask before loading above this */
constexpr UINT64 IMG_MAX = 256u << 20;	/* refuse above this */
constexpr UINT IMG_TIMER_ID = 1;	/* GIF frame advance */

std::string g_img_path;	/* file being viewed, UTF-8 */
UINT g_seq_img;	/* in-flight read_chunk task */
bool g_img_probing;	/* the in-flight read is the sniff stage */
stbi_uc *g_img_pixels;	/* decoded frames, premultiplied BGRA */
int *g_img_delays;	/* per-frame delay in ms (animated GIF) */
int g_img_w;
int g_img_h;
int g_img_frames;	/* 1 for still images */
int g_img_frame;	/* frame currently shown */
float g_img_zoom = 1.0f;
bool g_img_fit;	/* auto-fit zoom; wheel/double-click leaves it */
float g_img_off_x;	/* image-center offset from client center */
float g_img_off_y;
bool g_img_drag;
POINT g_img_drag_pt;
HMODULE g_d2d1;	/* d2d1.dll, loaded on first use, kept loaded */
ID2D1Factory *g_d2d_factory;
ID2D1HwndRenderTarget *g_img_rt;	/* per-viewer, lost on device reset */
ID2D1Bitmap *g_img_bmp;	/* current frame */

bool
img_load_d2d (void)
{
	using create_t = HRESULT (WINAPI *) (D2D1_FACTORY_TYPE, REFIID, const D2D1_FACTORY_OPTIONS *, void **);

	if (g_d2d_factory)
		return true;
	if (!g_d2d1)
		g_d2d1 = LoadLibraryW (L"d2d1.dll");
	if (!g_d2d1)
		return false;
	create_t create = reinterpret_cast<create_t> (
		GetProcAddress (g_d2d1, "D2D1CreateFactory"));
	if (!create)
		return false;
	if (FAILED (create (D2D1_FACTORY_TYPE_SINGLE_THREADED,
		__uuidof (ID2D1Factory), nullptr, reinterpret_cast<void **> (&g_d2d_factory))))
		g_d2d_factory = nullptr;
	return g_d2d_factory != nullptr;
}

void
img_release_gfx (void)
{
	if (g_img_bmp)
	{
		g_img_bmp->Release ();
		g_img_bmp = nullptr;
	}
	if (g_img_rt)
	{
		g_img_rt->Release ();
		g_img_rt = nullptr;
	}
}

void
img_free_image (void)
{
	if (g_img_pixels)
	{
		stbi_image_free (g_img_pixels);
		g_img_pixels = nullptr;
	}
	if (g_img_delays)
	{
		stbi_image_free (g_img_delays);
		g_img_delays = nullptr;
	}
	g_img_frames = 0;
}

/* Fit is shrink-only: small images show at 100%.  */
float
img_fit_zoom (HWND dlg)
{
	RECT rc;

	GetClientRect (dlg, &rc);
	if (g_img_w < 1 || g_img_h < 1 || rc.right < 1 || rc.bottom < 1)
		return 1.0f;
	float zx = (float) rc.right / (float) g_img_w;
	float zy = (float) rc.bottom / (float) g_img_h;
	float z = zx < zy ? zx : zy;
	return z < 1.0f ? z : 1.0f;
}

/* Keep at least a margin of the image inside the client area so a pan
   can never lose it entirely.  */
void
img_clamp_offset (HWND dlg)
{
	RECT rc;

	GetClientRect (dlg, &rc);
	float lim_x = ((float) g_img_w * g_img_zoom + (float) rc.right) / 2
		- (float) dpi_scale (32);
	float lim_y = ((float) g_img_h * g_img_zoom + (float) rc.bottom) / 2
		- (float) dpi_scale (32);
	if (lim_x < 0.0f)
		lim_x = 0.0f;
	if (lim_y < 0.0f)
		lim_y = 0.0f;
	if (g_img_off_x > lim_x)
		g_img_off_x = lim_x;
	if (g_img_off_x < -lim_x)
		g_img_off_x = -lim_x;
	if (g_img_off_y > lim_y)
		g_img_off_y = lim_y;
	if (g_img_off_y < -lim_y)
		g_img_off_y = -lim_y;
}

void
img_update_title (HWND dlg)
{
	size_t cut = g_img_path.find_last_of ('/');
	std::wstring name = widen (cut == std::string::npos ? g_img_path : g_img_path.substr (cut + 1));
	std::wstring title = name + L" - " + res_str (IDS_IMAGE_TITLE);

	if (g_img_pixels)
	{
		wchar_t buf[64];
		swprintf (buf, 64, L" (%dx%d, %d%%)", g_img_w, g_img_h, (int) (g_img_zoom * 100.0f + 0.5f));
		title += buf;
	}
	SetWindowTextW (dlg, title.c_str ());
}

/* (Re)create the render target and the current-frame bitmap.  An image
   above the hardware texture limit retries on the software rasterizer,
   whose limit is far larger.  */
bool
img_ensure_target (HWND dlg)
{
	if (!g_img_pixels)
		return false;
	if (g_img_rt && g_img_bmp)
		return true;

	RECT rc;
	GetClientRect (dlg, &rc);
	for (int pass = 0; !g_img_rt && pass < 2; pass++)
	{
		D2D1_RENDER_TARGET_PROPERTIES rtp = {};
		rtp.type = pass ? D2D1_RENDER_TARGET_TYPE_SOFTWARE : D2D1_RENDER_TARGET_TYPE_DEFAULT;
		rtp.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
		rtp.pixelFormat.alphaMode = D2D1_ALPHA_MODE_IGNORE;
		D2D1_HWND_RENDER_TARGET_PROPERTIES hp = {};
		hp.hwnd = dlg;
		hp.pixelSize.width = (UINT32) rc.right;
		hp.pixelSize.height = (UINT32) rc.bottom;
		ID2D1HwndRenderTarget *rt = nullptr;
		if (FAILED (g_d2d_factory->CreateHwndRenderTarget (&rtp, &hp, &rt)))
			continue;
		if ((UINT32) g_img_w > rt->GetMaximumBitmapSize () || (UINT32) g_img_h > rt->GetMaximumBitmapSize ())
		{
			rt->Release ();
			continue;
		}
		g_img_rt = rt;
	}
	if (!g_img_rt)
		return false;

	D2D1_SIZE_U size = { (UINT32) g_img_w, (UINT32) g_img_h };
	D2D1_BITMAP_PROPERTIES bp = {};
	bp.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
	bp.pixelFormat.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
	const stbi_uc *frame = g_img_pixels + (size_t) g_img_frame * g_img_w * g_img_h * 4;
	if (FAILED (g_img_rt->CreateBitmap (size, frame, (UINT32) g_img_w * 4, &bp, &g_img_bmp)))
	{
		g_img_bmp = nullptr;
		return false;
	}
	return true;
}

void
img_paint (HWND dlg)
{
	PAINTSTRUCT ps;
	HDC dc = BeginPaint (dlg, &ps);

	if (!img_ensure_target (dlg))
	{
		/* Nothing decoded yet (or D2D lost): plain background.  */
		FillRect (dc, &ps.rcPaint, GetSysColorBrush (COLOR_BTNFACE));
		EndPaint (dlg, &ps);
		return;
	}

	RECT rc;
	GetClientRect (dlg, &rc);
	float iw = (float) g_img_w * g_img_zoom;
	float ih = (float) g_img_h * g_img_zoom;
	D2D1_RECT_F dest;
	dest.left = ((float) rc.right - iw) / 2 + g_img_off_x;
	dest.top = ((float) rc.bottom - ih) / 2 + g_img_off_y;
	dest.right = dest.left + iw;
	dest.bottom = dest.top + ih;

	g_img_rt->BeginDraw ();
	D2D1_COLOR_F bg = { 0.25f, 0.25f, 0.25f, 1.0f };
	g_img_rt->Clear (&bg);
	/* Nearest neighbour once pixels get big enough to inspect.  */
	g_img_rt->DrawBitmap (g_img_bmp, &dest, 1.0f,
		g_img_zoom >= 2.0f ? D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR : D2D1_BITMAP_INTERPOLATION_MODE_LINEAR,
		nullptr);
	if (g_img_rt->EndDraw () == D2DERR_RECREATE_TARGET)
	{
		/* Device lost: rebuild lazily on the next paint.  */
		img_release_gfx ();
		InvalidateRect (dlg, nullptr, FALSE);
	}
	EndPaint (dlg, &ps);
}

/* ANCHOR (client coords), when given, is the point that keeps showing
   the same image pixel across the zoom change.  */
void
img_set_zoom (HWND dlg, float zoom, const POINT *anchor)
{
	RECT rc;

	if (zoom < 0.02f)
		zoom = 0.02f;
	if (zoom > 64.0f)
		zoom = 64.0f;
	GetClientRect (dlg, &rc);
	if (anchor)
	{
		float cx = (float) rc.right / 2;
		float cy = (float) rc.bottom / 2;
		float rel_x = (float) anchor->x - cx - g_img_off_x;
		float rel_y = (float) anchor->y - cy - g_img_off_y;
		g_img_off_x = (float) anchor->x - cx - rel_x * zoom / g_img_zoom;
		g_img_off_y = (float) anchor->y - cy - rel_y * zoom / g_img_zoom;
	}
	g_img_zoom = zoom;
	img_clamp_offset (dlg);
	img_update_title (dlg);
	InvalidateRect (dlg, nullptr, FALSE);
}

void
img_wheel (HWND dlg, WPARAM wp, LPARAM lp)
{
	if (!g_img_pixels)
		return;
	POINT pt = { (short) LOWORD (lp), (short) HIWORD (lp) };
	ScreenToClient (dlg, &pt);
	g_img_fit = false;
	img_set_zoom (dlg, g_img_zoom * (GET_WHEEL_DELTA_WPARAM (wp) > 0 ? 1.25f : 0.8f), &pt);
}

UINT
img_frame_delay (int frame)
{
	int d = g_img_delays ? g_img_delays[frame] : 100;

	/* Zero/near-zero GIF delays render at ~100 ms everywhere.  */
	return d < 20 ? 100 : (UINT) d;
}

void
img_next_frame (HWND dlg)
{
	g_img_frame = (g_img_frame + 1) % g_img_frames;
	if (g_img_bmp)
	{
		const stbi_uc *frame = g_img_pixels + (size_t) g_img_frame * g_img_w * g_img_h * 4;
		g_img_bmp->CopyFromMemory (nullptr, frame, (UINT32) g_img_w * 4);
	}
	SetTimer (dlg, IMG_TIMER_ID, img_frame_delay (g_img_frame), nullptr);
	InvalidateRect (dlg, nullptr, FALSE);
}

/* WIC fallback for the formats stb_image lacks (TIFF/ICO/WebP...; WebP
   additionally needs the system codec).  The factory comes from COM,
   so windowscodecs.dll loads at runtime and the import table stays
   unchanged.  CLSID_WICImagingFactory1 is the Vista-era class, present
   on every supported Windows.  32bppPBGRA output is already what D2D
   wants, no conversion pass needed.  */
bool
img_decode_wic (const std::vector<char> &raw)
{
	IWICImagingFactory *factory = nullptr;
	IWICStream *stream = nullptr;
	IWICBitmapDecoder *decoder = nullptr;
	IWICBitmapFrameDecode *frame = nullptr;
	IWICFormatConverter *conv = nullptr;
	stbi_uc *pixels = nullptr;
	UINT count = 0;
	UINT best = 0;
	UINT64 best_px = 0;
	UINT w = 0;
	UINT h = 0;
	bool ok = false;

	if (FAILED (CoCreateInstance (CLSID_WICImagingFactory1, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS (&factory))))
		return false;
	if (FAILED (factory->CreateStream (&stream))
		|| FAILED (stream->InitializeFromMemory ((BYTE *) raw.data (), (DWORD) raw.size ()))
		|| FAILED (factory->CreateDecoderFromStream (stream, nullptr, WICDecodeMetadataCacheOnDemand, &decoder))
		|| FAILED (decoder->GetFrameCount (&count)))
		goto fail;

	/* An .ico carries several sizes; show the largest.  Multi-page
	   formats (TIFF) end up on their first page.  */
	for (UINT i = 0; i < count; i++)
	{
		IWICBitmapFrameDecode *f = nullptr;
		UINT fw = 0;
		UINT fh = 0;
		if (FAILED (decoder->GetFrame (i, &f)))
			continue;
		if (SUCCEEDED (f->GetSize (&fw, &fh)) && (UINT64) fw * fh > best_px)
		{
			best_px = (UINT64) fw * fh;
			best = i;
		}
		f->Release ();
	}
	if (!best_px
		|| FAILED (decoder->GetFrame (best, &frame))
		|| FAILED (factory->CreateFormatConverter (&conv))
		|| FAILED (conv->Initialize (frame, GUID_WICPixelFormat32bppPBGRA, WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom))
		|| FAILED (conv->GetSize (&w, &h)))
		goto fail;
	if (!w || !h || (UINT64) w * h * 4 > 0xffffffffu)
		goto fail;	/* CopyPixels takes a 32-bit byte count */
	/* Freed by img_free_image via stbi_image_free (plain free).  */
	pixels = (stbi_uc *) malloc ((size_t) w * h * 4);
	if (!pixels
		|| FAILED (conv->CopyPixels (nullptr, w * 4, (UINT) ((UINT64) w * h * 4), pixels)))
		goto fail;

	g_img_pixels = pixels;
	pixels = nullptr;
	g_img_w = (int) w;
	g_img_h = (int) h;
	g_img_frames = 1;
	ok = true;
fail:
	free (pixels);
	if (conv)
		conv->Release ();
	if (frame)
		frame->Release ();
	if (decoder)
		decoder->Release ();
	if (stream)
		stream->Release ();
	factory->Release ();
	return ok;
}

/* Decode into premultiplied BGRA frames; false = not a decodable image.  */
bool
img_decode (const std::vector<char> &raw)
{
	const stbi_uc *buf = (const stbi_uc *) raw.data ();
	int len = (int) raw.size ();
	int comp = 0;

	if (len >= 4 && memcmp (buf, "GIF8", 4) == 0)
		g_img_pixels = stbi_load_gif_from_memory (buf, len, &g_img_delays, &g_img_w, &g_img_h, &g_img_frames, &comp, 4);
	else
	{
		g_img_pixels = stbi_load_from_memory (buf, len, &g_img_w, &g_img_h, &comp, 4);
		g_img_frames = 1;
	}
	if (!g_img_pixels)
		return img_decode_wic (raw);

	/* stb emits straight RGBA; D2D wants premultiplied BGRA.  */
	stbi_uc *p = g_img_pixels;
	size_t n = (size_t) g_img_w * (size_t) g_img_h * (size_t) g_img_frames;
	for (size_t i = 0; i < n; i++, p += 4)
	{
		stbi_uc r = p[0];
		stbi_uc a = p[3];
		p[0] = (stbi_uc) (p[2] * a / 255);
		p[1] = (stbi_uc) (p[1] * a / 255);
		p[2] = (stbi_uc) (r * a / 255);
	}
	return true;
}

void
img_close (HWND dlg)
{
	g_img = nullptr;	/* drop any late read result */
	EndDialog (dlg, 0);
}

void
img_init_dialog (HWND dlg)
{
	g_img = dlg;
	img_update_title (dlg);

	/* Default frame centered on the work area (the template size is
	   just a fallback).  */
	RECT wa;
	SystemParametersInfoW (SPI_GETWORKAREA, 0, &wa, 0);
	int width = dpi_scale (760);
	int height = dpi_scale (540);
	if (width > wa.right - wa.left)
		width = wa.right - wa.left;
	if (height > wa.bottom - wa.top)
		height = wa.bottom - wa.top;
	SetWindowPos (dlg, nullptr,
		wa.left + ((wa.right - wa.left) - width) / 2,
		wa.top + ((wa.bottom - wa.top) - height) / 2,
		width, height, SWP_NOZORDER);

	backend_task task;
	task.type = backend_task_type::read_chunk;
	task.path = g_img_path;
	task.offset = 0;
	task.length = IMG_PROBE;
	g_img_probing = true;
	g_seq_img = backend_post (std::move (task));
}

INT_PTR CALLBACK
img_dlg_proc (HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		img_init_dialog (dlg);
		return TRUE;
	case WM_SIZE:
		if (g_img_rt)
		{
			D2D1_SIZE_U size = { LOWORD (lp), HIWORD (lp) };
			g_img_rt->Resize (&size);
		}
		if (g_img_fit)
		{
			g_img_off_x = 0.0f;
			g_img_off_y = 0.0f;
			g_img_zoom = img_fit_zoom (dlg);
			img_update_title (dlg);
		}
		else
			img_clamp_offset (dlg);
		InvalidateRect (dlg, nullptr, FALSE);
		return TRUE;
	case WM_GETMINMAXINFO:
		((MINMAXINFO *) lp)->ptMinTrackSize =
			{ dpi_scale (240), dpi_scale (180) };
		return TRUE;
	case WM_PAINT:
		img_paint (dlg);
		return TRUE;
	case WM_ERASEBKGND:
		/* The paint handler covers the whole client area.  */
		SetWindowLongPtrW (dlg, DWLP_MSGRESULT, 1);
		return TRUE;
	case WM_MOUSEWHEEL:
		img_wheel (dlg, wp, lp);
		return TRUE;
	case WM_LBUTTONDOWN:
		if (g_img_pixels)
		{
			g_img_drag = true;
			g_img_drag_pt = { (short) LOWORD (lp), (short) HIWORD (lp) };
			SetCapture (dlg);
		}
		return TRUE;
	case WM_MOUSEMOVE:
		if (g_img_drag)
		{
			POINT pt = { (short) LOWORD (lp), (short) HIWORD (lp) };
			g_img_off_x += (float) (pt.x - g_img_drag_pt.x);
			g_img_off_y += (float) (pt.y - g_img_drag_pt.y);
			g_img_drag_pt = pt;
			img_clamp_offset (dlg);
			InvalidateRect (dlg, nullptr, FALSE);
		}
		return TRUE;
	case WM_LBUTTONUP:
		if (g_img_drag)
			ReleaseCapture ();
		return TRUE;
	case WM_CAPTURECHANGED:
		g_img_drag = false;
		return TRUE;
	case WM_LBUTTONDBLCLK:
		if (g_img_pixels)
		{
			g_img_fit = !g_img_fit;
			g_img_off_x = 0.0f;
			g_img_off_y = 0.0f;
			img_set_zoom (dlg, g_img_fit ? img_fit_zoom (dlg) : 1.0f, nullptr);
		}
		return TRUE;
	case WM_TIMER:
		if (wp == IMG_TIMER_ID && g_img_frames > 1)
			img_next_frame (dlg);
		return TRUE;
	case WM_COMMAND:
		if (LOWORD (wp) == IDCANCEL)
		{
			img_close (dlg);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

} // namespace

/* Extensions the viewer can decode: stb_image's set plus the WIC
   fallback formats (WebP needs the system codec, in-box on newer
   Windows).  The menu item is only offered for these.  */
bool
is_image_name (const std::string &name)
{
	static const char *exts[] =
	{
		"jpg", "jpeg", "png", "bmp", "gif", "tga", "psd",
		"hdr", "pic", "pnm", "pgm", "ppm", "tif", "tiff",
		"ico", "webp",
	};
	size_t dot = name.find_last_of ('.');

	if (dot == std::string::npos)
		return false;
	std::string ext = name.substr (dot + 1);
	for (const char *e : exts)
		if (_stricmp (ext.c_str (), e) == 0)
			return true;
	return false;
}

void
img_on_chunk (backend_result *res)
{
	if (!g_img || res->seq != g_seq_img)
		return;
	if (!res->error.empty ())
	{
		HWND dlg = g_img;
		g_img = nullptr;
		MessageBoxW (dlg, widen (res->error).c_str (), res_str (IDS_IMAGE_TITLE).c_str (), MB_ICONERROR);
		EndDialog (dlg, 0);
		return;
	}

	/* Stage one: the sniff read supplies the size, gating the full
	   transfer (and the decode allocations that follow).  */
	if (g_img_probing)
	{
		g_img_probing = false;
		if (res->file_size > IMG_MAX)
		{
			HWND dlg = g_img;
			g_img = nullptr;
			MessageBoxW (dlg, res_str (IDS_IMAGE_TOOBIG).c_str (), res_str (IDS_IMAGE_TITLE).c_str (), MB_ICONWARNING);
			EndDialog (dlg, 0);
			return;
		}
		if (res->file_size > IMG_WARN)
		{
			wchar_t buf[256];
			swprintf (buf, 256, res_str (IDS_ASK_TEXT_BIG).c_str (),
				  format_size (res->file_size).c_str ());
			if (MessageBoxW (g_img, buf, res_str (IDS_IMAGE_TITLE).c_str (), MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES)
			{
				img_close (g_img);
				return;
			}
		}
		if (res->file_size > res->data.size ())
		{
			backend_task task;
			task.type = backend_task_type::read_chunk;
			task.path = g_img_path;
			task.offset = 0;
			task.length = (UINT) res->file_size;
			g_seq_img = backend_post (std::move (task));
			return;
		}
		/* The probe already covered the whole file.  */
	}

	SetCursor (LoadCursorW (nullptr, IDC_WAIT));	/* decode may take a moment */
	if (!img_decode (res->data))
	{
		HWND dlg = g_img;
		g_img = nullptr;
		MessageBoxW (dlg, res_str (IDS_IMAGE_BAD).c_str (),
			     res_str (IDS_IMAGE_TITLE).c_str (), MB_ICONERROR);
		EndDialog (dlg, 0);
		return;
	}
	g_img_frame = 0;
	g_img_fit = true;
	g_img_off_x = 0.0f;
	g_img_off_y = 0.0f;
	g_img_zoom = img_fit_zoom (g_img);
	img_update_title (g_img);
	if (g_img_frames > 1)
		SetTimer (g_img, IMG_TIMER_ID, img_frame_delay (0), nullptr);
	InvalidateRect (g_img, nullptr, FALSE);
}

void
show_image (const std::string &path)
{
	if (!img_load_d2d ())
	{
		MessageBoxW (g_main, res_str (IDS_IMAGE_NO_D2D).c_str (), res_str (IDS_IMAGE_TITLE).c_str (), MB_ICONERROR);
		return;
	}
	g_img_path = path;
	DialogBoxParamW (GetModuleHandleW (nullptr), MAKEINTRESOURCEW (IDD_IMAGE), g_main, img_dlg_proc, 0);
	g_img = nullptr;
	g_img_drag = false;
	img_release_gfx ();
	img_free_image ();
}
