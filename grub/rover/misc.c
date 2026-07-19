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
 * Terminal and machine symbols expected by grub-core\kern that have no
 * meaning in a Windows GUI process.  grub_printf output goes to the
 * debugger; grub never reads keys.
 */

#include <windows.h>

#include <grub/misc.h>
#include <grub/term.h>
#include <grub/dl.h>
#include <grub/command.h>
#include <grub/crypto.h>

static void
rover_xputs (const char *str)
{
	OutputDebugStringA (str);
}

void (*grub_xputs) (const char *str) = rover_xputs;

struct grub_term_input *grub_term_inputs = NULL;
struct grub_term_input *grub_term_inputs_disabled = NULL;
struct grub_term_output *grub_term_outputs = NULL;
struct grub_term_output *grub_term_outputs_disabled = NULL;

int
grub_getkey (void)
{
	return GRUB_TERM_NO_KEY;
}

void
grub_refresh (void)
{
}

void
grub_exit (void)
{
	ExitProcess (1);
}

/*
 * Modules are linked statically and never unloaded; reference
 * counting (kern\dl.c) is not built.
 */
grub_uint64_t
grub_dl_ref (grub_dl_t mod)
{
	(void) mod;
	return 0;
}

grub_uint64_t
grub_dl_unref (grub_dl_t mod)
{
	(void) mod;
	return 0;
}

/*
 * Rover has no grub shell; command registration (diskfilter's
 * "cryptocheck") is accepted and dropped.
 */
grub_command_t
grub_register_command_prio (const char *name, grub_command_func_t func,
	const char *summary, const char *description, int prio)
{
	(void) name;
	(void) func;
	(void) summary;
	(void) description;
	(void) prio;
	return NULL;
}

void
grub_unregister_command (grub_command_t cmd)
{
	(void) cmd;
}

/*
 * libgcrypt queries CPU features to pick accelerated code paths.  Rover
 * builds only the portable C implementations (gcry_blake2.c and friends),
 * so report no hardware features.
 */
unsigned int
_gcry_get_hw_features (void)
{
	return 0;
}

/*
 * Progress hook for the cryptodisk unlock KDF (declared in grub/crypto.h;
 * called by pbkdf2.c and gcry_kdf.c).  rover_set_crypto_progress installs
 * it so the GUI can show a bar during the slow Argon2/PBKDF2 pass.
 */
void (*grub_cryptodisk_kdf_progress) (unsigned int done, unsigned int total, void *data) = 0;
void *grub_cryptodisk_kdf_progress_data = 0;
