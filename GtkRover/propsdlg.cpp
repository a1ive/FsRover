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
 * Property dialogs.  A file shows its directory entry, link target and
 * libmagic description; hashes are computed on request on the grub
 * thread, cancelled when the dialog closes.  A device shows what
 * rover_enum_disks() reported for it.
 */

#include "app.h"

#ifdef HAVE_LIBMAGIC
#include <magic.h>
#endif

#include <rover.h>

#include <cerrno>

#include "../FsRover/blake2/blake2.h"
#include "../FsRover/blake3_glue.h"

namespace
{

/* label/value pairs as one copyable text block */
struct prop_grid
{
	GtkGrid *grid;
	int rows = 0;
	std::string text;
};

GtkWidget *
value_label (const std::string &value)
{
	GtkWidget *label = gtk_label_new (value.c_str ());
	PangoAttrList *attrs = pango_attr_list_new ();

	/* Digests and paths break mid-word; a hyphen there would read as
	   part of the value.  */
	pango_attr_list_insert (attrs, pango_attr_insert_hyphens_new (FALSE));
	gtk_label_set_attributes (GTK_LABEL (label), attrs);
	pango_attr_list_unref (attrs);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_label_set_selectable (GTK_LABEL (label), TRUE);
	gtk_label_set_wrap (GTK_LABEL (label), TRUE);
	gtk_label_set_wrap_mode (GTK_LABEL (label), PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (label), 60);
	gtk_widget_set_hexpand (label, TRUE);
	return label;
}

GtkLabel *
add_prop (prop_grid &g, const char *name, const std::string &value)
{
	GtkWidget *caption = gtk_label_new (name);
	GtkWidget *label = value_label (value);

	gtk_label_set_xalign (GTK_LABEL (caption), 1);
	gtk_label_set_yalign (GTK_LABEL (caption), 0);
	gtk_widget_add_css_class (caption, "dim-label");
	gtk_grid_attach (g.grid, caption, 0, g.rows, 1, 1);
	gtk_grid_attach (g.grid, label, 1, g.rows, 1, 1);
	g.rows++;
	g.text += std::string (name) + " " + value + "\n";
	return GTK_LABEL (label);
}

prop_grid
new_prop_grid ()
{
	prop_grid g;

	g.grid = GTK_GRID (gtk_grid_new ());
	gtk_grid_set_row_spacing (g.grid, 6);
	gtk_grid_set_column_spacing (g.grid, 12);
	return g;
}

void
on_copy_clicked (GtkButton *button, gpointer)
{
	const char *text = static_cast<const char *> (g_object_get_data (G_OBJECT (button), "rover-text"));

	copy_text (text ? text : "");
	set_status (_("Copied to the clipboard"));
}

GtkWidget *
copy_button (const std::string &text)
{
	GtkWidget *button = gtk_button_new_with_mnemonic (_("C_opy"));

	g_object_set_data_full (G_OBJECT (button), "rover-text", g_strdup (text.c_str ()), g_free);
	g_signal_connect (button, "clicked", G_CALLBACK (on_copy_clicked), nullptr);
	return button;
}

void
on_close_clicked (GtkButton *, gpointer dialog)
{
	gtk_window_close (GTK_WINDOW (dialog));
}

GtkWidget *
close_button (GtkWindow *dialog)
{
	GtkWidget *button = gtk_button_new_with_mnemonic (_("_Close"));

	g_signal_connect (button, "clicked", G_CALLBACK (on_close_clicked), dialog);
	return button;
}

/* ---- file properties ------------------------------------------------ */

struct file_info
{
	std::string error;
	bool stat_ok = false;
	rover_stat_t st = {};
	std::string link;
	std::string magic;
};

/* libmagic looks at a prefix of the file; 1 MiB is the classic file(1)
   sniff size and keeps the dialog snappy on slow filesystems.  */
constexpr size_t SNIFF_MAX = 1 << 20;

std::string
describe (const std::vector<unsigned char> &data)
{
#ifdef HAVE_LIBMAGIC
	static magic_t cookie;
	static bool tried;

	if (!tried)
	{
		tried = true;
		cookie = magic_open (MAGIC_NONE);
		if (cookie && magic_load (cookie, nullptr) != 0)
		{
			magic_close (cookie);
			cookie = nullptr;
		}
	}
	if (cookie)
	{
		const char *text = magic_buffer (cookie, data.data (), data.size ());
		if (text)
			return text;
	}
#else
	(void) data;
#endif
	return "";
}

/* Grub thread.  */
file_info
probe_file (const std::string &path)
{
	file_info out;

	/* Identity first, and on its own: it comes from the directory entry
	   rather than the file, so it is worth showing for a file whose
	   contents cannot be read.  */
	out.stat_ok = rover_stat (path.c_str (), &out.st) == 0;
	if (!out.stat_ok)
	{
		out.error = last_error ();
		return out;
	}
	if (out.st.is_symlink)
	{
		char buf[4096];
		unsigned long long len = 0;
		if (rover_readlink (path.c_str (), buf, sizeof (buf), &len) == 0)
			out.link = buf;
	}
	if (!out.st.is_dir)
	{
		chunk head = read_chunk (path, 0, SNIFF_MAX);
		if (head.error.empty ())
			out.magic = describe (head.data);
	}
	return out;
}

enum
{
	HASH_MD5,
	HASH_SHA1,
	HASH_SHA256,
	HASH_SHA512,
	HASH_CRC32,
	HASH_CRC64,
	HASH_BLAKE2SP,
	HASH_BLAKE3,
	HASH_COUNT
};

const char *const HASH_NAMES[HASH_COUNT] =
	{ "MD5", "SHA-1", "SHA-256", "SHA-512", "CRC32", "CRC64", "BLAKE2sp", "BLAKE3" };

struct hash_result
{
	std::string error;
	std::string values[HASH_COUNT];
};

struct props_ui
{
	GtkWindow *dialog = nullptr;
	GtkWidget *checks[HASH_COUNT] = {};
	GtkLabel *values[HASH_COUNT] = {};
	GtkWidget *compute = nullptr;
	GtkProgressBar *progress = nullptr;
	std::string path;
	std::atomic<bool> cancel { false };
	bool running = false;
};

using props_ptr = std::shared_ptr<props_ui>;

struct blake3_deleter
{
	void operator() (rover_blake3 *b) const { rover_blake3_free (b); }
};

std::string
hex_digest (const unsigned char *digest, size_t len)
{
	static const char DIGITS[] = "0123456789abcdef";
	std::string out (len * 2, '0');

	for (size_t i = 0; i < len; i++)
	{
		out[i * 2] = DIGITS[digest[i] >> 4];
		out[i * 2 + 1] = DIGITS[digest[i] & 15];
	}
	return out;
}

/* Grub thread: one pass over the file feeding every selected digest.  */
hash_result
hash_file (const props_ptr &u, unsigned mask)
{
	static const GChecksumType types[] =
		{ G_CHECKSUM_MD5, G_CHECKSUM_SHA1, G_CHECKSUM_SHA256, G_CHECKSUM_SHA512 };
	hash_result out;
	GChecksum *sums[4] = {};
	guint32 crc32_table[256];
	guint64 crc64_table[256];
	guint32 crc32 = 0xffffffffu;
	guint64 crc64 = ~(guint64) 0;
	blake2sp_state blake2sp {};
	std::unique_ptr<rover_blake3, blake3_deleter> blake3;
	std::vector<unsigned char> buf ((size_t) 1 << 20);
	unsigned long long total;
	unsigned long long done = 0;
	gint64 last = 0;
	rover_file *f;

	/* Reflected CRC-32 (zip) and CRC-64/XZ (ECMA-182), as FsRover.  */
	for (guint32 i = 0; i < 256; i++)
	{
		guint32 c = i;
		guint64 d = i;
		for (int bit = 0; bit < 8; bit++)
		{
			c = (c & 1) ? ((c >> 1) ^ 0xedb88320u) : (c >> 1);
			d = (d & 1) ? ((d >> 1) ^ 0xc96c5795d7870f42ULL) : (d >> 1);
		}
		crc32_table[i] = c;
		crc64_table[i] = d;
	}
	if ((mask & (1u << HASH_BLAKE2SP)) && blake2sp_init (&blake2sp, BLAKE2S_OUTBYTES) < 0)
	{
		out.error = "BLAKE2sp initialization failed";
		return out;
	}
	if (mask & (1u << HASH_BLAKE3))
	{
		blake3.reset (rover_blake3_new ());
		if (!blake3)
		{
			out.error = g_strerror (ENOMEM);
			return out;
		}
	}
	f = rover_file_open (u->path.c_str ());
	if (!f)
	{
		out.error = last_error ();
		return out;
	}
	for (int i = 0; i < 4; i++)
		if (mask & (1u << i))
			sums[i] = g_checksum_new (types[i]);
	total = rover_file_size (f);
	for (;;)
	{
		if (u->cancel || S.closing)
		{
			out.error = _("Cancelled");
			break;
		}
		long long r = rover_file_read (f, buf.data (), buf.size ());
		if (r < 0)
		{
			out.error = last_error ();
			break;
		}
		if (r == 0)
			break;
		for (int i = 0; i < 4; i++)
			if (sums[i])
				g_checksum_update (sums[i], buf.data (), (gssize) r);
		if (mask & (1u << HASH_CRC32))
			for (long long i = 0; i < r; i++)
				crc32 = crc32_table[(crc32 ^ buf[(size_t) i]) & 0xff] ^ (crc32 >> 8);
		if (mask & (1u << HASH_CRC64))
			for (long long i = 0; i < r; i++)
				crc64 = crc64_table[(crc64 ^ buf[(size_t) i]) & 0xff] ^ (crc64 >> 8);
		if (mask & (1u << HASH_BLAKE2SP))
			blake2sp_update (&blake2sp, buf.data (), (size_t) r);
		if (blake3)
			rover_blake3_update (blake3.get (), buf.data (), (size_t) r);
		done += (unsigned long long) r;
		gint64 now = g_get_monotonic_time ();
		if (now - last >= 100000)
		{
			last = now;
			double fraction = total ? (double) done / total : 0;
			props_ptr ui = u;
			backend::ui ([ui, fraction]
			{
				if (ui->running)
					gtk_progress_bar_set_fraction (ui->progress, fraction);
			});
		}
	}
	rover_file_close (f);
	for (int i = 0; i < 4; i++)
		if (sums[i])
		{
			if (out.error.empty ())
				out.values[i] = g_checksum_get_string (sums[i]);
			g_checksum_free (sums[i]);
		}
	if (out.error.empty () && (mask & (1u << HASH_CRC32)))
		out.values[HASH_CRC32] = fmt ("%08x", (unsigned) (crc32 ^ 0xffffffffu));
	if (out.error.empty () && (mask & (1u << HASH_CRC64)))
		out.values[HASH_CRC64] = fmt ("%016llx", (unsigned long long) (crc64 ^ ~(guint64) 0));
	if (out.error.empty () && (mask & (1u << HASH_BLAKE2SP)))
	{
		unsigned char digest[BLAKE2S_OUTBYTES];
		blake2sp_final (&blake2sp, digest, sizeof (digest));
		out.values[HASH_BLAKE2SP] = hex_digest (digest, sizeof (digest));
	}
	if (out.error.empty () && blake3)
	{
		unsigned char digest[ROVER_BLAKE3_LEN];
		rover_blake3_final (blake3.get (), digest);
		out.values[HASH_BLAKE3] = hex_digest (digest, sizeof (digest));
	}
	return out;
}

props_ptr
props_of (gpointer dialog)
{
	return *static_cast<props_ptr *> (g_object_get_data (G_OBJECT (dialog), "rover-props"));
}

void
on_compute_clicked (GtkButton *, gpointer dialog)
{
	props_ptr u = props_of (dialog);
	unsigned mask = 0;

	for (int i = 0; i < HASH_COUNT; i++)
		if (gtk_check_button_get_active (GTK_CHECK_BUTTON (u->checks[i])))
		{
			mask |= 1u << i;
			gtk_label_set_text (u->values[i], _("Calculating…"));
		}
		else
			gtk_label_set_text (u->values[i], "");
	if (!mask)
		return;
	u->running = true;
	u->cancel = false;
	gtk_widget_set_sensitive (u->compute, FALSE);
	gtk_progress_bar_set_fraction (u->progress, 0);
	gtk_widget_set_visible (GTK_WIDGET (u->progress), TRUE);
	run_job ([u, mask] { return hash_file (u, mask); }, [u, mask] (hash_result r)
	{
		u->running = false;
		if (u->cancel)
			return;	/* the dialog is gone */
		gtk_widget_set_sensitive (u->compute, TRUE);
		gtk_widget_set_visible (GTK_WIDGET (u->progress), FALSE);
		for (int i = 0; i < HASH_COUNT; i++)
			if (mask & (1u << i))
				gtk_label_set_text (u->values[i], r.error.empty () ? r.values[i].c_str ()
					: r.error.c_str ());
	});
}

void
on_props_destroy (GtkWidget *dialog, gpointer)
{
	props_of (dialog)->cancel = true;
}

void
fill_file_props (const props_ptr &u, GtkWidget *box, const file_info &info)
{
	prop_grid g = new_prop_grid ();
	const rover_stat_t &st = info.st;
	char *type = nullptr;

	add_prop (g, _("Name:"), basename_of (u->path));
	add_prop (g, _("Location:"), parent_path (u->path));
	if (!info.stat_ok)
		add_prop (g, _("Error:"), info.error);
	else
	{
		if (st.is_dir)
			type = g_content_type_get_description ("inode/directory");
		else if (st.is_symlink)
			type = g_content_type_get_description ("inode/symlink");
		else
		{
			char *ct = g_content_type_guess (basename_of (u->path).c_str (), nullptr, 0, nullptr);
			type = g_content_type_get_description (ct);
			g_free (ct);
		}
		add_prop (g, _("Type:"), type);
		g_free (type);
		if (!info.link.empty ())
			add_prop (g, _("Link target:"), info.link);
		if (!info.magic.empty ())
			add_prop (g, _("Contents:"), info.magic);
		if (!st.is_dir)
			add_prop (g, _("Size:"), format_exact (st.size) + " (" + format_size (st.size) + ")");
		if (st.mtime_set)
			add_prop (g, _("Modified:"), format_time (st.mtime));
		add_prop (g, _("Inode:"), st.inode_set ? std::to_string (st.inode)
			: std::string (_("not reported by this filesystem")));
	}
	gtk_box_append (GTK_BOX (box), GTK_WIDGET (g.grid));

	if (info.stat_ok && !st.is_dir)
	{
		GtkWidget *frame = gtk_frame_new (_("Checksums"));
		GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
		GtkWidget *checks = gtk_flow_box_new ();
		prop_grid h = new_prop_grid ();

		gtk_widget_set_margin_top (inner, 8);
		gtk_widget_set_margin_bottom (inner, 8);
		gtk_widget_set_margin_start (inner, 8);
		gtk_widget_set_margin_end (inner, 8);
		gtk_flow_box_set_selection_mode (GTK_FLOW_BOX (checks), GTK_SELECTION_NONE);
		gtk_flow_box_set_max_children_per_line (GTK_FLOW_BOX (checks), 4);
		for (int i = 0; i < HASH_COUNT; i++)
		{
			u->checks[i] = gtk_check_button_new_with_label (HASH_NAMES[i]);
			gtk_check_button_set_active (GTK_CHECK_BUTTON (u->checks[i]),
				i == HASH_MD5 || i == HASH_SHA256);
			gtk_flow_box_append (GTK_FLOW_BOX (checks), u->checks[i]);
			u->values[i] = add_prop (h, HASH_NAMES[i], "");
			gtk_widget_add_css_class (GTK_WIDGET (u->values[i]), "monospace");
		}
		u->compute = gtk_button_new_with_mnemonic (_("C_alculate"));
		gtk_widget_set_halign (u->compute, GTK_ALIGN_START);
		u->progress = GTK_PROGRESS_BAR (gtk_progress_bar_new ());
		gtk_widget_set_visible (GTK_WIDGET (u->progress), FALSE);
		gtk_box_append (GTK_BOX (inner), checks);
		gtk_box_append (GTK_BOX (inner), u->compute);
		gtk_box_append (GTK_BOX (inner), GTK_WIDGET (u->progress));
		gtk_box_append (GTK_BOX (inner), GTK_WIDGET (h.grid));
		gtk_frame_set_child (GTK_FRAME (frame), inner);
		gtk_box_append (GTK_BOX (box), frame);
		g_signal_connect (u->compute, "clicked", G_CALLBACK (on_compute_clicked), u->dialog);
	}
	GtkWidget *close = close_button (u->dialog);
	gtk_box_append (GTK_BOX (box), button_row ({ copy_button (g.text), close }));
	/* Not the first selectable label: it would open with its text selected.  */
	gtk_window_set_focus (u->dialog, close);
}

} /* namespace */

void
show_file_props (const std::string &path)
{
	auto u = std::make_shared<props_ui> ();
	GtkWindow *dialog = new_dialog (fmt (_("%s Properties"), basename_of (path).c_str ()), 520, -1);
	GtkWidget *box = dialog_box (dialog);

	u->dialog = dialog;
	u->path = path;
	g_object_set_data_full (G_OBJECT (dialog), "rover-props", new props_ptr (u),
		[] (gpointer p) { delete static_cast<props_ptr *> (p); });
	g_signal_connect (dialog, "destroy", G_CALLBACK (on_props_destroy), nullptr);
	/* Shown once filled, so it opens at its full size.  */
	g_object_ref (dialog);
	run_job ([path] { return probe_file (path); }, [u, box] (file_info info)
	{
		fill_file_props (u, box, info);
		gtk_window_present (u->dialog);
		g_object_unref (u->dialog);
	});
}

/* ---- device properties ---------------------------------------------- */

void
show_disk_props (const row_data &d)
{
	GtkWindow *dialog = new_dialog (fmt (_("(%s) Properties"), d.name.c_str ()), 480, -1);
	GtkWidget *box = dialog_box (dialog);
	prop_grid g = new_prop_grid ();
	const char *type;

	if (d.dev_id == ROVER_DEV_CRYPTODISK)
		type = _("Unlocked encrypted volume");
	else if (d.is_partition)
		type = _("Partition");
	else if (d.dev_id == ROVER_DEV_POSIXFILE)
		type = _("Disk image file");
	else if (d.dev_id == ROVER_DEV_LOOPBACK)
		type = _("Disk image inside a filesystem");
	else if (d.dev_id == ROVER_DEV_LOST)
		type = _("Lost partition window");
	else if (d.dev_id == ROVER_DEV_DISKFILTER)
		type = _("Volume (LVM, RAID or LDM)");
	else if (d.name.rfind ("cd", 0) == 0)
		type = _("Optical drive");
	else if (d.dev_id == ROVER_DEV_WINDISK)
		type = _("Physical disk");
	else
		type = _("Device");

	add_prop (g, _("Device:"), "(" + d.name + ")");
	add_prop (g, _("Type:"), type);
	if (d.size != ROVER_SIZE_UNKNOWN)
		add_prop (g, _("Size:"), format_exact (d.size) + " (" + format_size (d.size) + ")");
	if (d.sector_size)
		add_prop (g, _("Sector size:"), format_exact (d.sector_size));
	if (d.is_partition || d.dev_id == ROVER_DEV_LOST)
		add_prop (g, _("Start:"), fmt (_("sector %llu (byte offset %llu)"), d.start_lba,
			d.start_lba * (d.sector_size ? d.sector_size : 512)));
	add_prop (g, _("Filesystem:"), d.fs.empty () ? std::string (_("none recognized")) : d.fs);
	if (!d.label.empty ())
		add_prop (g, _("Label:"), d.label);
	if (!d.fs_uuid.empty ())
		add_prop (g, _("UUID:"), d.fs_uuid);
	if (!d.crypto_type.empty ())
		add_prop (g, _("Encryption:"), d.crypto_type + (d.encrypted ? _(", locked") : _(", unlocked")));
	if (!d.crypto_uuid.empty ())
		add_prop (g, _("Encryption UUID:"), d.crypto_uuid);
	if (!d.parent.empty ())
		add_prop (g, _("Read from:"), "(" + d.parent + ")");
	if (!d.parent_file.empty ())
		add_prop (g, _("Backing file:"), d.parent_file);
	if (!d.parents.empty ())
		add_prop (g, _("Members:"), d.parents);
	if (!d.mountpoint.empty ())
		add_prop (g, _("Mounted at:"), d.mountpoint);
	gtk_box_append (GTK_BOX (box), GTK_WIDGET (g.grid));
	GtkWidget *close = close_button (dialog);
	gtk_box_append (GTK_BOX (box), button_row ({ copy_button (g.text), close }));
	gtk_window_set_focus (dialog, close);
	gtk_window_present (dialog);
}
