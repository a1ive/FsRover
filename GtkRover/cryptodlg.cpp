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
 * Unlock dialogs: LUKS/LUKS2/BitLocker/GELI (detected), VeraCrypt and
 * TrueCrypt (never detected: their headers look like random data), and
 * headerless plain dm-crypt.  The key derivation runs on the grub thread;
 * the dialog stays up, insensitive, until it answers, and cannot be closed
 * meanwhile because the job still refers to it.
 */

#include "app.h"

#include <string.h>

#include <rover.h>

namespace
{

struct crypto_ui
{
	GtkWindow *dialog = nullptr;
	GtkWidget *inputs = nullptr;	/* made insensitive while unlocking */
	GtkWidget *unlock_button = nullptr;
	GtkLabel *message = nullptr;
	std::string device;
	bool running = false;
	/* Gathers the secret and the call to make; false (with MESSAGE set)
	   when the inputs are incomplete.  */
	std::function<bool (std::function<int (char *, size_t)> *call)> prepare;
};

using crypto_ptr = std::shared_ptr<crypto_ui>;

crypto_ptr
crypto_of (gpointer dialog)
{
	return *static_cast<crypto_ptr *> (g_object_get_data (G_OBJECT (dialog), "rover-crypto"));
}

void
wipe (std::vector<char> &key)
{
	explicit_bzero (key.data (), key.size ());
	key.clear ();
}

void
crypto_progress (unsigned long long done, unsigned long long total, void *)
{
	if (total)
		post_progress (static_cast<double> (done) / total, "");
}

void
set_running (const crypto_ptr &u, bool running)
{
	u->running = running;
	gtk_widget_set_sensitive (u->inputs, !running);
	gtk_widget_set_sensitive (u->unlock_button, !running);
}

struct unlock_result
{
	int rc;
	std::string error;
	std::string device;
};

void
on_unlock_clicked (GtkButton *, gpointer dialog)
{
	crypto_ptr u = crypto_of (dialog);
	std::function<int (char *, size_t)> call;

	gtk_label_set_text (u->message, "");
	if (!u->prepare (&call))
		return;
	if (!begin_job (fmt (_("Unlocking (%s)…"), u->device.c_str ()), false))
	{
		gtk_label_set_text (u->message, _("Another operation is still running."));
		return;
	}
	set_running (u, true);
	run_job ([call]
	{
		char dev[64] = "";
		rover_set_crypto_progress (crypto_progress, nullptr);
		int rc = call (dev, sizeof (dev));
		rover_set_crypto_progress (nullptr, nullptr);
		return unlock_result { rc, rc ? last_error () : "", dev };
	},
	[u] (unlock_result r)
	{
		set_running (u, false);
		if (r.rc)
		{
			end_job (fmt (_("Unlock (%s) failed"), u->device.c_str ()));
			gtk_label_set_text (u->message, r.error.c_str ());
			return;
		}
		end_job (fmt (_("Unlocked (%s) as (%s)"), u->device.c_str (), r.device.c_str ()));
		gtk_window_destroy (u->dialog);
		std::string out = r.device;
		refresh_disks ([out] { auto_enter (out); });
	});
}

gboolean
on_crypto_close (GtkWindow *dialog, gpointer)
{
	return crypto_of (dialog)->running;
}

void
on_crypto_destroy (GtkWidget *, gpointer)
{
	/* Cancelled: point the sidebar back at the volume being shown.  */
	if (!S.closing && !S.cur_path.empty ())
		select_disk (device_of (S.cur_path));
}

void
on_cancel_clicked (GtkButton *, gpointer dialog)
{
	gtk_window_close (GTK_WINDOW (dialog));
}

/* The dialog frame shared by all three: title, INPUTS, message, buttons.  */
crypto_ptr
make_crypto_dialog (const std::string &title, const std::string &device, GtkWidget *inputs)
{
	auto u = std::make_shared<crypto_ui> ();
	GtkWindow *dialog = new_dialog (title, 440, -1);
	GtkWidget *box = dialog_box (dialog);
	GtkWidget *cancel = gtk_button_new_with_mnemonic (_("_Cancel"));

	u->dialog = dialog;
	u->device = device;
	u->inputs = inputs;
	gtk_window_set_modal (dialog, TRUE);
	gtk_window_set_resizable (dialog, FALSE);
	u->message = GTK_LABEL (gtk_label_new (nullptr));
	gtk_label_set_xalign (u->message, 0);
	gtk_label_set_wrap (u->message, TRUE);
	gtk_label_set_max_width_chars (u->message, 50);
	gtk_widget_add_css_class (GTK_WIDGET (u->message), "error");
	u->unlock_button = gtk_button_new_with_mnemonic (_("_Unlock"));
	gtk_widget_add_css_class (u->unlock_button, "suggested-action");
	gtk_box_append (GTK_BOX (box), inputs);
	gtk_box_append (GTK_BOX (box), GTK_WIDGET (u->message));
	gtk_box_append (GTK_BOX (box), button_row ({ cancel, u->unlock_button }));
	gtk_window_set_default_widget (dialog, u->unlock_button);

	g_object_set_data_full (G_OBJECT (dialog), "rover-crypto", new crypto_ptr (u),
		[] (gpointer p) { delete static_cast<crypto_ptr *> (p); });
	g_signal_connect (u->unlock_button, "clicked", G_CALLBACK (on_unlock_clicked), dialog);
	g_signal_connect (cancel, "clicked", G_CALLBACK (on_cancel_clicked), dialog);
	g_signal_connect (dialog, "close-request", G_CALLBACK (on_crypto_close), nullptr);
	g_signal_connect (dialog, "destroy", G_CALLBACK (on_crypto_destroy), nullptr);
	return u;
}

GtkWidget *
password_entry ()
{
	GtkWidget *entry = gtk_password_entry_new ();

	gtk_password_entry_set_show_peek_icon (GTK_PASSWORD_ENTRY (entry), TRUE);
	g_object_set (entry, "activates-default", TRUE, "placeholder-text", _("Passphrase"), nullptr);
	return entry;
}

GtkWidget *
form_label (const char *text)
{
	GtkWidget *label = gtk_label_new_with_mnemonic (text);

	gtk_label_set_xalign (GTK_LABEL (label), 1);
	return label;
}

void
grid_row (GtkGrid *grid, int row, const char *label, GtkWidget *widget)
{
	GtkWidget *caption = form_label (label);

	gtk_label_set_mnemonic_widget (GTK_LABEL (caption), widget);
	gtk_widget_set_hexpand (widget, TRUE);
	gtk_grid_attach (grid, caption, 0, row, 1, 1);
	gtk_grid_attach (grid, widget, 1, row, 1, 1);
}

GtkGrid *
new_grid ()
{
	GtkGrid *grid = GTK_GRID (gtk_grid_new ());

	gtk_grid_set_row_spacing (grid, 8);
	gtk_grid_set_column_spacing (grid, 10);
	return grid;
}

/* A local file of at most MAX bytes, read whole.  */
bool
read_key_file (const std::string &path, size_t max, std::vector<char> *out,
	std::string *error)
{
	char *data = nullptr;
	gsize size = 0;
	GError *err = nullptr;

	if (!g_file_get_contents (path.c_str (), &data, &size, &err))
	{
		*error = err->message;
		g_error_free (err);
		return false;
	}
	if (size > max)
		size = max;
	out->assign (data, data + size);
	explicit_bzero (data, size);
	g_free (data);
	return true;
}

/* Browse button that fills ENTRY with a local file path.  */
void
on_browse_chosen (GObject *source, GAsyncResult *result, gpointer entry)
{
	GFile *file = gtk_file_dialog_open_finish (GTK_FILE_DIALOG (source), result, nullptr);

	if (file)
	{
		char *path = g_file_get_path (file);
		if (path)
			gtk_editable_set_text (GTK_EDITABLE (entry), path);
		g_free (path);
		g_object_unref (file);
	}
	g_object_unref (entry);
}

void
on_browse_clicked (GtkButton *button, gpointer entry)
{
	GtkFileDialog *dialog = gtk_file_dialog_new ();

	gtk_file_dialog_set_title (dialog, _("Choose Key File"));
	gtk_file_dialog_open (dialog, GTK_WINDOW (gtk_widget_get_root (GTK_WIDGET (button))),
		nullptr, on_browse_chosen, g_object_ref (entry));
	g_object_unref (dialog);
}

GtkWidget *
file_picker (GtkWidget **entry)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *browse = gtk_button_new_with_label (_("Browse…"));

	*entry = gtk_entry_new ();
	gtk_widget_set_hexpand (*entry, TRUE);
	gtk_box_append (GTK_BOX (box), *entry);
	gtk_box_append (GTK_BOX (box), browse);
	g_signal_connect (browse, "clicked", G_CALLBACK (on_browse_clicked), *entry);
	return box;
}

std::string
entry_text (GtkWidget *entry)
{
	return gtk_editable_get_text (GTK_EDITABLE (entry));
}

/* ---- LUKS / BitLocker / GELI ---------------------------------------- */

struct luks_widgets
{
	GtkWidget *pass;
	GtkWidget *use_keyfile;
	GtkWidget *keyfile;
	GtkWidget *keyfile_row;
};

void
on_luks_keyfile_toggled (GtkCheckButton *check, gpointer data)
{
	auto *w = static_cast<luks_widgets *> (data);
	bool kf = gtk_check_button_get_active (check);

	gtk_widget_set_sensitive (w->pass, !kf);
	gtk_widget_set_sensitive (w->keyfile_row, kf);
}

} /* namespace */

void
show_unlock (const std::string &device, const std::string &type)
{
	GtkWidget *inputs = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
	auto *w = new luks_widgets;
	row_data disk;
	std::string uuid;

	if (find_disk (device, &disk) && !disk.crypto_uuid.empty ())
		uuid = " (" + disk.crypto_uuid + ")";
	gtk_box_append (GTK_BOX (inputs), heading_label (fmt (_("Unlock (%s)"), device.c_str ())));
	GtkWidget *hint = gtk_label_new ((type.empty () ? std::string (_("Encrypted volume."))
		: fmt (_("%s volume%s. Enter its passphrase or choose a key file."),
			type.c_str (), uuid.c_str ())).c_str ());
	gtk_label_set_xalign (GTK_LABEL (hint), 0);
	gtk_label_set_wrap (GTK_LABEL (hint), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (hint), 50);
	gtk_box_append (GTK_BOX (inputs), hint);
	w->pass = password_entry ();
	gtk_box_append (GTK_BOX (inputs), w->pass);
	w->use_keyfile = gtk_check_button_new_with_mnemonic (_("Use a _key file"));
	gtk_box_append (GTK_BOX (inputs), w->use_keyfile);
	w->keyfile_row = file_picker (&w->keyfile);
	gtk_widget_set_sensitive (w->keyfile_row, FALSE);
	gtk_box_append (GTK_BOX (inputs), w->keyfile_row);

	crypto_ptr u = make_crypto_dialog (_("Unlock Volume"), device, inputs);
	g_object_set_data_full (G_OBJECT (u->dialog), "rover-widgets", w,
		[] (gpointer p) { delete static_cast<luks_widgets *> (p); });
	g_signal_connect (w->use_keyfile, "toggled", G_CALLBACK (on_luks_keyfile_toggled), w);
	u->prepare = [w, ui = u.get ()] (std::function<int (char *, size_t)> *call)
	{
		auto key = std::make_shared<std::vector<char>> ();
		std::string error;

		if (gtk_check_button_get_active (GTK_CHECK_BUTTON (w->use_keyfile)))
		{
			/* cryptsetup's default key file size limit.  */
			if (!read_key_file (entry_text (w->keyfile), 8 << 20, key.get (), &error))
			{
				gtk_label_set_text (ui->message, error.c_str ());
				return false;
			}
		}
		else
		{
			std::string pass = entry_text (w->pass);
			key->assign (pass.begin (), pass.end ());
			explicit_bzero (pass.data (), pass.size ());
		}
		if (key->empty ())
		{
			gtk_label_set_text (ui->message, _("Enter a passphrase or choose a non-empty key file."));
			return false;
		}
		std::string dev = ui->device;
		*call = [dev, key] (char *out, size_t size)
		{
			int rc = rover_crypto_unlock (dev.c_str (), key->data (), key->size (), out, size);
			wipe (*key);
			return rc;
		};
		return true;
	};
	gtk_window_present (u->dialog);
	gtk_widget_grab_focus (w->pass);
}

/* ---- VeraCrypt / TrueCrypt ------------------------------------------ */

namespace
{

struct vc_widgets
{
	GtkWidget *pass;
	GtkWidget *pim;
	GtkWidget *prf;
	GtkWidget *truecrypt;
	GtkWidget *hidden;
	GtkWidget *backup;
	GtkWidget *keyfile_list;
	std::vector<std::string> keyfiles;
};

/*
 * Fold a key file into the pool the way VeraCrypt does: run a CRC-32 over
 * its first megabyte and add the four bytes of the running register (not
 * the finished checksum) into successive pool bytes, wrapping at the end.
 */
bool
vc_apply_keyfile (const std::string &path, std::vector<unsigned char> &pool)
{
	static guint32 table[256];
	static bool ready;
	std::vector<char> data;
	std::string error;
	guint32 crc = 0xffffffffu;
	size_t pos = 0;

	if (!ready)
	{
		for (guint32 i = 0; i < 256; i++)
		{
			guint32 c = i;
			for (int k = 0; k < 8; k++)
				c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
			table[i] = c;
		}
		ready = true;
	}
	if (!read_key_file (path, 1 << 20, &data, &error) || data.empty ())
		return false;	/* VeraCrypt rejects an empty key file */
	for (char byte : data)
	{
		crc = table[(crc ^ (unsigned char) byte) & 0xff] ^ (crc >> 8);
		pool[pos++] += (unsigned char) (crc >> 24);
		pool[pos++] += (unsigned char) (crc >> 16);
		pool[pos++] += (unsigned char) (crc >> 8);
		pool[pos++] += (unsigned char) crc;
		if (pos >= pool.size ())
			pos = 0;
	}
	explicit_bzero (data.data (), data.size ());
	return true;
}

void
vc_show_keyfiles (vc_widgets *w)
{
	std::string text;

	for (const std::string &path : w->keyfiles)
		text += (text.empty () ? "" : "\n") + basename_of (path);
	gtk_label_set_text (GTK_LABEL (w->keyfile_list), text.empty () ? _("No key files") : text.c_str ());
}

void
on_vc_keyfiles_chosen (GObject *source, GAsyncResult *result, gpointer data)
{
	auto *w = static_cast<vc_widgets *> (data);
	GListModel *files = gtk_file_dialog_open_multiple_finish (GTK_FILE_DIALOG (source), result,
		nullptr);

	if (!files)
		return;
	for (guint i = 0; i < g_list_model_get_n_items (files); i++)
	{
		GFile *file = G_FILE (g_list_model_get_item (files, i));
		char *path = g_file_get_path (file);
		if (path)
			w->keyfiles.push_back (path);
		g_free (path);
		g_object_unref (file);
	}
	g_object_unref (files);
	vc_show_keyfiles (w);
}

void
on_vc_add_keyfiles (GtkButton *button, gpointer data)
{
	GtkFileDialog *dialog = gtk_file_dialog_new ();

	gtk_file_dialog_set_title (dialog, _("Add Key Files"));
	gtk_file_dialog_open_multiple (dialog, GTK_WINDOW (gtk_widget_get_root (GTK_WIDGET (button))),
		nullptr, on_vc_keyfiles_chosen, data);
	g_object_unref (dialog);
}

void
on_vc_clear_keyfiles (GtkButton *, gpointer data)
{
	auto *w = static_cast<vc_widgets *> (data);

	w->keyfiles.clear ();
	vc_show_keyfiles (w);
}

} /* namespace */

void
show_veracrypt (const std::string &device)
{
	static const char *const prfs[] =
		{ N_("Autodetect (slow)"), "SHA-512", "Whirlpool", "SHA-256", "RIPEMD-160", "Streebog", nullptr };
	GtkWidget *inputs = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
	GtkGrid *grid = new_grid ();
	auto *w = new vc_widgets;
	const char *prf_names[G_N_ELEMENTS (prfs)];

	for (size_t i = 0; i < G_N_ELEMENTS (prfs); i++)
		prf_names[i] = i == 0 ? _(prfs[0]) : prfs[i];
	gtk_box_append (GTK_BOX (inputs), heading_label (fmt (_("Unlock VeraCrypt volume (%s)"),
		device.c_str ())));
	w->pass = password_entry ();
	w->pim = gtk_spin_button_new_with_range (0, 2147483647, 1);
	gtk_widget_set_tooltip_text (w->pim, _("Personal Iterations Multiplier; 0 uses the volume's default"));
	w->prf = gtk_drop_down_new_from_strings (prf_names);
	grid_row (grid, 0, _("_Password:"), w->pass);
	grid_row (grid, 1, _("P_IM:"), w->pim);
	grid_row (grid, 2, _("_Hash:"), w->prf);
	gtk_box_append (GTK_BOX (inputs), GTK_WIDGET (grid));
	w->truecrypt = gtk_check_button_new_with_mnemonic (_("_TrueCrypt volume"));
	w->hidden = gtk_check_button_new_with_mnemonic (_("Open the hi_dden volume"));
	w->backup = gtk_check_button_new_with_mnemonic (_("Use the _backup headers"));
	gtk_box_append (GTK_BOX (inputs), w->truecrypt);
	gtk_box_append (GTK_BOX (inputs), w->hidden);
	gtk_box_append (GTK_BOX (inputs), w->backup);

	GtkWidget *keys = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *add = gtk_button_new_with_mnemonic (_("Add _Key Files…"));
	GtkWidget *clear = gtk_button_new_with_label (_("Clear"));
	w->keyfile_list = gtk_label_new (nullptr);
	gtk_label_set_xalign (GTK_LABEL (w->keyfile_list), 0);
	gtk_label_set_ellipsize (GTK_LABEL (w->keyfile_list), PANGO_ELLIPSIZE_MIDDLE);
	gtk_widget_set_hexpand (w->keyfile_list, TRUE);
	gtk_widget_add_css_class (w->keyfile_list, "dim-label");
	gtk_box_append (GTK_BOX (keys), w->keyfile_list);
	gtk_box_append (GTK_BOX (keys), add);
	gtk_box_append (GTK_BOX (keys), clear);
	gtk_box_append (GTK_BOX (inputs), keys);
	vc_show_keyfiles (w);

	crypto_ptr u = make_crypto_dialog (_("Unlock VeraCrypt / TrueCrypt"), device, inputs);
	g_object_set_data_full (G_OBJECT (u->dialog), "rover-widgets", w,
		[] (gpointer p) { delete static_cast<vc_widgets *> (p); });
	g_signal_connect (add, "clicked", G_CALLBACK (on_vc_add_keyfiles), w);
	g_signal_connect (clear, "clicked", G_CALLBACK (on_vc_clear_keyfiles), w);
	u->prepare = [w, ui = u.get ()] (std::function<int (char *, size_t)> *call)
	{
		auto key = std::make_shared<std::vector<char>> ();
		std::string pass = entry_text (w->pass);

		/* VeraCrypt's own limit; longer passphrases open nothing.  */
		if (pass.size () > 128)
			pass.resize (128);
		if (w->keyfiles.empty ())
			key->assign (pass.begin (), pass.end ());
		else
		{
			std::vector<unsigned char> pool (pass.size () <= 64 ? 64 : 128, 0);
			std::copy (pass.begin (), pass.end (), pool.begin ());
			for (const std::string &path : w->keyfiles)
				if (!vc_apply_keyfile (path, pool))
				{
					gtk_label_set_text (ui->message, fmt (_("Cannot use key file %s"),
						path.c_str ()).c_str ());
					explicit_bzero (pool.data (), pool.size ());
					explicit_bzero (pass.data (), pass.size ());
					return false;
				}
			key->assign (pool.begin (), pool.end ());
			explicit_bzero (pool.data (), pool.size ());
		}
		explicit_bzero (pass.data (), pass.size ());
		if (key->empty ())
		{
			gtk_label_set_text (ui->message, _("Enter a password or add key files."));
			return false;
		}
		unsigned pim = (unsigned) gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (w->pim));
		int prf = (int) gtk_drop_down_get_selected (GTK_DROP_DOWN (w->prf));
		unsigned flags = (gtk_check_button_get_active (GTK_CHECK_BUTTON (w->truecrypt))
				? ROVER_VC_TRUECRYPT : 0)
			| (gtk_check_button_get_active (GTK_CHECK_BUTTON (w->hidden)) ? ROVER_VC_HIDDEN : 0)
			| (gtk_check_button_get_active (GTK_CHECK_BUTTON (w->backup)) ? ROVER_VC_BACKUP : 0);
		if (prf == ROVER_VC_PRF_AUTO)
			gtk_label_set_text (ui->message, _("Trying every hash; this can take a while…"));
		std::string dev = ui->device;
		*call = [dev, key, pim, prf, flags] (char *out, size_t size)
		{
			int rc = rover_veracrypt_unlock (dev.c_str (), key->data (), key->size (),
				pim, prf, flags, out, size);
			wipe (*key);
			return rc;
		};
		return true;
	};
	gtk_window_present (u->dialog);
	gtk_widget_grab_focus (w->pass);
}

/* ---- plain dm-crypt ------------------------------------------------- */

namespace
{

const char *const PM_CIPHERS[] =
{
	"aes-xts-plain64", "aes-cbc-essiv:sha256", "aes-cbc-plain64", "aes-cbc-plain",
	"serpent-xts-plain64", "twofish-xts-plain64", "camellia-xts-plain64",
	"kuznyechik-xts-plain64", "aes-lrw-benbi", "aes-ecb", nullptr
};
/* Index 0 means "no hashing", which the backend spells "plain".  */
const char *const PM_HASHES[] =
	{ N_("None (use as is)"), "ripemd160", "sha1", "sha256", "sha512", "whirlpool", "stribog512", nullptr };
const char *const PM_KEYBITS[] = { "512", "256", "128", "192", "1024", nullptr };
const char *const PM_SECTORS[] = { "512", "1024", "2048", "4096", nullptr };

struct pm_widgets
{
	GtkWidget *cipher;
	GtkWidget *hash;
	GtkWidget *key_bits;
	GtkWidget *sector;
	GtkWidget *offset;
	GtkWidget *skip;
	GtkWidget *pass;
	GtkWidget *use_keyfile;
	GtkWidget *keyfile_row;
	GtkWidget *keyfile;
	GtkWidget *key_offset;
};

void
on_pm_keyfile_toggled (GtkCheckButton *check, gpointer data)
{
	auto *w = static_cast<pm_widgets *> (data);
	bool kf = gtk_check_button_get_active (check);

	gtk_widget_set_sensitive (w->pass, !kf);
	/* Hashing applies to a passphrase only; a key file is the key.  */
	gtk_widget_set_sensitive (w->hash, !kf);
	gtk_widget_set_sensitive (w->keyfile_row, kf);
	gtk_widget_set_sensitive (w->key_offset, kf);
}

void
on_pm_preset (GtkDropDown *presets, GParamSpec *, gpointer cipher)
{
	guint index = gtk_drop_down_get_selected (presets);

	if (index < G_N_ELEMENTS (PM_CIPHERS) - 1)
		gtk_editable_set_text (GTK_EDITABLE (cipher), PM_CIPHERS[index]);
}

GtkWidget *
number_spin (double max)
{
	GtkWidget *spin = gtk_spin_button_new_with_range (0, max, 1);

	gtk_spin_button_set_digits (GTK_SPIN_BUTTON (spin), 0);
	return spin;
}

unsigned long long
spin_value (GtkWidget *spin)
{
	return (unsigned long long) gtk_spin_button_get_value (GTK_SPIN_BUTTON (spin));
}

} /* namespace */

void
show_plain_unlock (const std::string &device)
{
	GtkWidget *inputs = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
	GtkGrid *grid = new_grid ();
	auto *w = new pm_widgets;
	const char *hash_names[G_N_ELEMENTS (PM_HASHES)];
	GtkWidget *presets = gtk_drop_down_new_from_strings (PM_CIPHERS);

	for (size_t i = 0; i < G_N_ELEMENTS (PM_HASHES); i++)
		hash_names[i] = i == 0 ? _(PM_HASHES[0]) : PM_HASHES[i];
	gtk_box_append (GTK_BOX (inputs), heading_label (fmt (_("Open plain dm-crypt volume (%s)"),
		device.c_str ())));
	GtkWidget *warning = gtk_label_new (_("A plain volume has no header: wrong parameters are not "
		"detected and simply show garbage."));
	gtk_label_set_xalign (GTK_LABEL (warning), 0);
	gtk_label_set_wrap (GTK_LABEL (warning), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (warning), 50);
	gtk_widget_add_css_class (warning, "dim-label");
	gtk_box_append (GTK_BOX (inputs), warning);

	w->cipher = gtk_entry_new ();
	gtk_editable_set_text (GTK_EDITABLE (w->cipher), PM_CIPHERS[0]);
	gtk_widget_set_hexpand (w->cipher, TRUE);
	g_signal_connect (presets, "notify::selected", G_CALLBACK (on_pm_preset), w->cipher);
	w->hash = gtk_drop_down_new_from_strings (hash_names);
	gtk_drop_down_set_selected (GTK_DROP_DOWN (w->hash), 1);	/* cryptsetup's default */
	w->key_bits = gtk_drop_down_new_from_strings (PM_KEYBITS);
	w->sector = gtk_drop_down_new_from_strings (PM_SECTORS);
	w->offset = number_spin (9007199254740992.0 / 512);
	w->skip = number_spin (9007199254740992.0 / 512);
	w->pass = password_entry ();
	grid_row (grid, 0, _("_Cipher:"), w->cipher);
	grid_row (grid, 1, _("P_resets:"), presets);
	grid_row (grid, 2, _("_Hash:"), w->hash);
	grid_row (grid, 3, _("_Key size (bits):"), w->key_bits);
	grid_row (grid, 4, _("_Sector size:"), w->sector);
	grid_row (grid, 5, _("_Offset (512-byte sectors):"), w->offset);
	grid_row (grid, 6, _("S_kip (IV sectors):"), w->skip);
	grid_row (grid, 7, _("_Passphrase:"), w->pass);
	/* One grid, so the key file rows line up with the rest.  */
	w->use_keyfile = gtk_check_button_new_with_mnemonic (_("Use a key _file as the volume key"));
	gtk_grid_attach (grid, w->use_keyfile, 1, 8, 1, 1);
	w->keyfile_row = file_picker (&w->keyfile);
	w->key_offset = number_spin (9007199254740992.0);
	grid_row (grid, 9, _("Key _file:"), w->keyfile_row);
	grid_row (grid, 10, _("Key file o_ffset (bytes):"), w->key_offset);
	gtk_widget_set_sensitive (w->keyfile_row, FALSE);
	gtk_widget_set_sensitive (w->key_offset, FALSE);
	gtk_box_append (GTK_BOX (inputs), GTK_WIDGET (grid));

	crypto_ptr u = make_crypto_dialog (_("Open Plain dm-crypt"), device, inputs);
	g_object_set_data_full (G_OBJECT (u->dialog), "rover-widgets", w,
		[] (gpointer p) { delete static_cast<pm_widgets *> (p); });
	g_signal_connect (w->use_keyfile, "toggled", G_CALLBACK (on_pm_keyfile_toggled), w);
	u->prepare = [w, ui = u.get ()] (std::function<int (char *, size_t)> *call)
	{
		auto key = std::make_shared<std::vector<char>> ();
		std::string cipher = entry_text (w->cipher);
		guint hash = gtk_drop_down_get_selected (GTK_DROP_DOWN (w->hash));
		unsigned long long key_bits = g_ascii_strtoull (
			PM_KEYBITS[gtk_drop_down_get_selected (GTK_DROP_DOWN (w->key_bits))], nullptr, 10);
		unsigned long long sector = g_ascii_strtoull (
			PM_SECTORS[gtk_drop_down_get_selected (GTK_DROP_DOWN (w->sector))], nullptr, 10);
		unsigned long long offset = spin_value (w->offset);
		unsigned long long skip = spin_value (w->skip);
		bool keyfile = gtk_check_button_get_active (GTK_CHECK_BUTTON (w->use_keyfile));

		/* A cipher without a mode cannot be mounted at all.  */
		if (cipher.find ('-') == std::string::npos)
		{
			gtk_label_set_text (ui->message, _("The cipher must name a mode, e.g. aes-xts-plain64."));
			return false;
		}
		if (keyfile)
		{
			std::vector<char> data;
			std::string error;
			unsigned long long at = spin_value (w->key_offset);
			if (!read_key_file (entry_text (w->keyfile), (size_t) (at + key_bits / 8), &data, &error))
			{
				gtk_label_set_text (ui->message, error.c_str ());
				return false;
			}
			if (data.size () < at + key_bits / 8)
			{
				gtk_label_set_text (ui->message, _("The key file is too short for this key size."));
				wipe (data);
				return false;
			}
			key->assign (data.begin () + (long) at, data.end ());
			wipe (data);
		}
		else
		{
			std::string pass = entry_text (w->pass);
			key->assign (pass.begin (), pass.end ());
			explicit_bzero (pass.data (), pass.size ());
		}
		if (key->empty ())
		{
			gtk_label_set_text (ui->message, _("Enter a passphrase or choose a key file."));
			return false;
		}
		std::string dev = ui->device;
		std::string hash_name = keyfile || hash == 0 ? ROVER_PM_HASH_NONE : PM_HASHES[hash];
		*call = [dev, cipher, hash_name, key_bits, sector, offset, skip, key, keyfile]
			(char *out, size_t size)
		{
			int rc = rover_plainmount_unlock (dev.c_str (), cipher.c_str (), hash_name.c_str (),
				key_bits, sector, offset, skip, key->data (), key->size (),
				keyfile ? ROVER_PM_KEYFILE : 0, nullptr, out, size);
			wipe (*key);
			return rc;
		};
		return true;
	};
	gtk_window_present (u->dialog);
	gtk_widget_grab_focus (w->pass);
}
