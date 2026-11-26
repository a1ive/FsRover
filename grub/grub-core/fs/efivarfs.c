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
 * UEFI runtime variables of the running machine as the read-only
 * "(efivars)" pseudo-device, laid out like Linux efivarfs: one flat
 * directory, one file per variable named "Name-xxxxxxxx-xxxx-xxxx-xxxx-
 * xxxxxxxxxxxx" (lower-case vendor GUID), holding the 4-byte
 * little-endian attribute mask followed by the value.
 *
 * Enumerating makes the kernel walk the firmware's GetNextVariableName /
 * GetVariable in ring 0, and firmware bugs there are out of anyone's
 * reach from user mode: a firmware that loops or faults hangs or crashes
 * the machine.  So nothing here runs until the user asks for it
 * (rover_efivars_enable), the device and filesystem stay unregistered
 * until then, and nothing is ever written.
 *
 * One NtEnumerateSystemEnvironmentValuesEx call (names, attributes and
 * values together) takes a snapshot; listings and file opens are served
 * from it, so the sizes a listing reports are the bytes an open returns
 * and extracting every variable costs one firmware walk, not one per
 * file.  The snapshot is dropped whenever the devices are enumerated
 * again (a refresh), and the next listing takes a fresh one.
 */

#include <grub/charset.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/safemath.h>
#include <grub/types.h>

#include <windows.h>

#include "rover.h"

#pragma comment (lib, "advapi32.lib")

GRUB_MOD_LICENSE ("GPLv3+");

#define EFIVARS_DEVICE	"efivars"

/* SystemEnvironmentValueInformation: VARIABLE_NAME_AND_VALUE records.  */
#define EFIVARS_INFO_VALUES	2

/* VARIABLE_NAME_AND_VALUE, read by offset.  */
#define EFIVARS_REC_NEXT	0
#define EFIVARS_REC_VALUE_OFFSET	4
#define EFIVARS_REC_VALUE_LENGTH	8
#define EFIVARS_REC_ATTRIBUTES	12
#define EFIVARS_REC_GUID	16
#define EFIVARS_REC_NAME	32

/* "-" + 36-character GUID.  */
#define EFIVARS_GUID_SUFFIX	37

/* The first try is sized for a whole typical variable store, since every
   retry is another full firmware walk; the cap only stops a runaway
   length from a broken kernel answer.  */
#define EFIVARS_BUF_INITIAL	(256U * 1024U)
#define EFIVARS_BUF_MAX	(64U * 1024U * 1024U)
#define EFIVARS_TRIES	4

#define EFIVARS_STATUS_NOT_IMPLEMENTED	((LONG) 0xC0000002L)
#define EFIVARS_STATUS_BUFFER_TOO_SMALL	((LONG) 0xC0000023L)
#define EFIVARS_STATUS_PRIVILEGE_NOT_HELD	((LONG) 0xC0000061L)
#define EFIVARS_STATUS_NOT_SUPPORTED	((LONG) 0xC00000BBL)
#define EFIVARS_STATUS_VARIABLE_NOT_FOUND	((LONG) 0xC0000100L)

/* GetFirmwareType's FirmwareTypeBios.  */
#define EFIVARS_FIRMWARE_BIOS	1

typedef LONG (NTAPI *efivars_enum_fn) (ULONG info_class, PVOID buffer, PULONG length);
typedef BOOL (WINAPI *efivars_fwtype_fn) (DWORD *type);

struct efivar
{
	char *name;
	grub_uint32_t attributes;
	const grub_uint8_t *value;
	grub_uint32_t size;
};

struct efivars_snapshot
{
	grub_uint8_t *buf;
	struct efivar *vars;
	grub_size_t count;
};

static efivars_enum_fn efivars_enum;
static struct efivars_snapshot *efivars_snap;
static int efivars_registered;
/* The privilege's state before enable turned it on, put back by disable. */
static int efivars_priv_changed;
static TOKEN_PRIVILEGES efivars_priv_prev;

static grub_uint32_t
rd32 (const grub_uint8_t *p)
{
	grub_uint32_t v;

	grub_memcpy (&v, p, sizeof (v));
	return v;
}

static grub_uint16_t
rd16 (const grub_uint8_t *p)
{
	grub_uint16_t v;

	grub_memcpy (&v, p, sizeof (v));
	return v;
}

static void
snapshot_free (struct efivars_snapshot *snap)
{
	grub_size_t i;

	if (!snap)
		return;
	for (i = 0; i < snap->count; i++)
		grub_free (snap->vars[i].name);
	grub_free (snap->vars);
	grub_free (snap->buf);
	grub_free (snap);
}

static void
snapshot_drop (void)
{
	snapshot_free (efivars_snap);
	efivars_snap = NULL;
}

static struct efivar *
snapshot_find (struct efivars_snapshot *snap, const char *name)
{
	grub_size_t i;

	for (i = 0; i < snap->count; i++)
		if (grub_strcmp (snap->vars[i].name, name) == 0)
			return &snap->vars[i];
	return NULL;
}

/* "Name-guid" for the record at REC, NAME_CHARS UTF-16 units long.  */
static char *
format_name (const grub_uint8_t *rec, grub_size_t name_chars)
{
	const grub_uint8_t *g = rec + EFIVARS_REC_GUID;
	grub_uint16_t *wide = NULL;
	char *name = NULL;
	grub_uint8_t *end;
	grub_size_t bytes, i;

	if (grub_mul (name_chars, GRUB_MAX_UTF8_PER_UTF16, &bytes)
		|| grub_add (bytes, EFIVARS_GUID_SUFFIX + 1, &bytes))
		goto fail;
	wide = grub_calloc (name_chars, sizeof (*wide));
	name = grub_malloc (bytes);
	if (!wide || !name)
		goto fail;
	for (i = 0; i < name_chars; i++)
		wide[i] = rd16 (rec + EFIVARS_REC_NAME + i * 2);
	end = grub_utf16_to_utf8 ((grub_uint8_t *) name, wide, name_chars);
	grub_snprintf ((char *) end, EFIVARS_GUID_SUFFIX + 1,
		"-%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		rd32 (g), rd16 (g + 4), rd16 (g + 6), g[8], g[9],
		g[10], g[11], g[12], g[13], g[14], g[15]);
	grub_free (wide);
	return name;

fail:
	grub_free (wide);
	grub_free (name);
	return NULL;
}

/* Turn the kernel's record list into SNAP->vars.  A record that does not
   fit the buffer ends the list there; names that cannot be file names
   (empty, or holding '/') are left out, and so is a repeat of a name
   already seen, which is what a firmware that loops through its
   variables hands back.  */
static grub_err_t
snapshot_parse (struct efivars_snapshot *snap, grub_size_t len)
{
	grub_size_t offset = 0, cap = 0;

	while (len - offset >= EFIVARS_REC_NAME)
	{
		const grub_uint8_t *rec = snap->buf + offset;
		grub_size_t avail = len - offset;
		grub_uint32_t next = rd32 (rec + EFIVARS_REC_NEXT);
		grub_uint32_t voff = rd32 (rec + EFIVARS_REC_VALUE_OFFSET);
		grub_uint32_t vlen = rd32 (rec + EFIVARS_REC_VALUE_LENGTH);
		grub_size_t limit = next ? next : avail;
		grub_size_t name_chars = 0, vend;
		int slash = 0;
		char *name;

		if (limit > avail || limit < EFIVARS_REC_NAME)
			break;
		for (;;)
		{
			grub_size_t at = EFIVARS_REC_NAME + name_chars * 2;
			grub_uint16_t c;

			if (at + 2 > limit)
				goto out;
			c = rd16 (rec + at);
			if (!c)
				break;
			if (c == '/')
				slash = 1;
			name_chars++;
		}
		if (grub_add ((grub_size_t) voff, (grub_size_t) vlen, &vend) || vend > avail)
			break;
		if (name_chars && !slash)
		{
			name = format_name (rec, name_chars);
			if (!name)
				return grub_errno ? grub_errno
					: grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
			if (snapshot_find (snap, name))
				grub_free (name);
			else
			{
				struct efivar *var;

				if (snap->count == cap)
				{
					grub_size_t ncap = cap ? cap * 2 : 64;
					struct efivar *nv = grub_realloc (snap->vars, ncap * sizeof (*nv));

					if (!nv)
					{
						grub_free (name);
						return grub_errno;
					}
					snap->vars = nv;
					cap = ncap;
				}
				var = &snap->vars[snap->count++];
				var->name = name;
				var->attributes = rd32 (rec + EFIVARS_REC_ATTRIBUTES);
				var->value = rec + voff;
				var->size = vlen;
			}
		}
		if (!next)
			break;
		offset += next;
	}
out:
	return GRUB_ERR_NONE;
}

static struct efivars_snapshot *
snapshot_get (void)
{
	struct efivars_snapshot *snap;
	ULONG alloc = EFIVARS_BUF_INITIAL;
	ULONG len = 0;
	LONG status = EFIVARS_STATUS_BUFFER_TOO_SMALL;
	int tries;

	if (efivars_snap)
		return efivars_snap;
	snap = grub_zalloc (sizeof (*snap));
	if (!snap)
		return NULL;
	for (tries = 0; tries < EFIVARS_TRIES; tries++)
	{
		ULONG want = alloc;

		grub_free (snap->buf);
		snap->buf = grub_malloc (alloc);
		if (!snap->buf)
			goto fail;
		status = efivars_enum (EFIVARS_INFO_VALUES, snap->buf, &want);
		if (status != EFIVARS_STATUS_BUFFER_TOO_SMALL)
		{
			/* Never trust a length past what was handed in.  */
			len = want < alloc ? want : alloc;
			break;
		}
		/* Room for a variable or two created since the kernel
		   measured.  */
		if (want <= alloc || want > EFIVARS_BUF_MAX - 4096)
			want = alloc * 2;
		else
			want += 4096;
		if (want > EFIVARS_BUF_MAX)
			break;
		alloc = want;
	}
	if (status == EFIVARS_STATUS_VARIABLE_NOT_FOUND)
		len = 0;
	else if (status == EFIVARS_STATUS_PRIVILEGE_NOT_HELD)
	{
		grub_error (GRUB_ERR_ACCESS_DENIED, "reading UEFI variables needs an elevated token");
		goto fail;
	}
	else if (status == EFIVARS_STATUS_NOT_IMPLEMENTED || status == EFIVARS_STATUS_NOT_SUPPORTED)
	{
		grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "this system does not expose UEFI variables");
		goto fail;
	}
	else if (status < 0)
	{
		grub_error (GRUB_ERR_IO, "cannot enumerate UEFI variables (NTSTATUS 0x%08lx)",
			(unsigned long) status);
		goto fail;
	}
	if (snapshot_parse (snap, len) != GRUB_ERR_NONE)
		goto fail;
	efivars_snap = snap;
	return snap;

fail:
	snapshot_free (snap);
	return NULL;
}

static int
efivars_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data, grub_disk_pull_t pull)
{
	if (pull != GRUB_DISK_PULL_NONE)
		return 0;
	/* A device enumeration is a refresh: the next listing reads the
	   firmware again.  */
	snapshot_drop ();
	return hook (EFIVARS_DEVICE, hook_data);
}

static grub_err_t
efivars_open (const char *name, grub_disk_t disk)
{
	if (grub_strcmp (name, EFIVARS_DEVICE) != 0)
		return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not an efivars disk");
	disk->total_sectors = 0;
	/* (proc) is id 0 under the same device class.  */
	disk->id = 1;
	disk->data = NULL;
	return GRUB_ERR_NONE;
}

static void
efivars_close (grub_disk_t disk)
{
	(void) disk;
}

static grub_err_t
efivars_read (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, char *buf)
{
	(void) disk;
	(void) sector;
	(void) size;
	(void) buf;
	return GRUB_ERR_OUT_OF_RANGE;
}

static grub_err_t
efivars_write (grub_disk_t disk, grub_disk_addr_t sector, grub_size_t size, const char *buf)
{
	(void) disk;
	(void) sector;
	(void) size;
	(void) buf;
	return GRUB_ERR_OUT_OF_RANGE;
}

/* Shares the procfs device class: both are synthetic, sector-less
   devices, which is all the class tells the frontends.  */
static struct grub_disk_dev efivars_dev =
{
	.name = EFIVARS_DEVICE,
	.id = GRUB_DISK_DEVICE_PROCFS_ID,
	.disk_iterate = efivars_iterate,
	.disk_open = efivars_open,
	.disk_close = efivars_close,
	.disk_read = efivars_read,
	.disk_write = efivars_write,
	.next = 0
};

static const char *
skip_slashes (const char *path)
{
	while (*path == '/')
		path++;
	return path;
}

static grub_err_t
efivarfs_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook, void *hook_data)
{
	struct efivars_snapshot *snap;
	grub_size_t i;

	if (!device->disk || device->disk->dev != &efivars_dev)
		return grub_error (GRUB_ERR_BAD_FS, "not an efivarfs");
	snap = snapshot_get ();
	if (!snap)
		return grub_errno;
	path = skip_slashes (path);
	if (*path)
	{
		if (snapshot_find (snap, path))
			return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
		return grub_error (GRUB_ERR_FILE_NOT_FOUND, "file `%s' not found", path);
	}
	for (i = 0; i < snap->count; i++)
	{
		struct grub_dirhook_info info;

		grub_memset (&info, 0, sizeof (info));
		info.sizeset = 1;
		info.size = (grub_uint64_t) snap->vars[i].size + 4;
		if (hook (snap->vars[i].name, &info, hook_data))
			break;
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
efivarfs_open (grub_file_t file, const char *path)
{
	struct efivars_snapshot *snap;
	struct efivar *var;
	grub_uint8_t *data;
	grub_size_t size;

	snap = snapshot_get ();
	if (!snap)
		return grub_errno;
	path = skip_slashes (path);
	var = *path ? snapshot_find (snap, path) : NULL;
	if (!var)
		return grub_error (*path ? GRUB_ERR_FILE_NOT_FOUND : GRUB_ERR_BAD_FILE_TYPE,
			*path ? "file `%s' not found" : "not a regular file", path);
	/* A copy: the snapshot may be dropped while the file is open.  */
	size = (grub_size_t) var->size + 4;
	data = grub_malloc (size);
	if (!data)
		return grub_errno;
	grub_memcpy (data, &var->attributes, 4);
	grub_memcpy (data + 4, var->value, var->size);
	file->data = data;
	file->size = size;
	return GRUB_ERR_NONE;
}

static grub_ssize_t
efivarfs_read (grub_file_t file, char *buf, grub_size_t len)
{
	grub_memcpy (buf, (char *) file->data + file->offset, len);
	return (grub_ssize_t) len;
}

static grub_err_t
efivarfs_close (grub_file_t file)
{
	grub_free (file->data);
	return GRUB_ERR_NONE;
}

static struct grub_fs efivarfs_fs =
{
	.name = "efivarfs",
	.fs_dir = efivarfs_dir,
	.fs_open = efivarfs_open,
	.fs_read = efivarfs_read,
	.fs_close = efivarfs_close,
	.next = 0
};

/* Enable or disable SeSystemEnvironmentPrivilege on the process token.
   Enabling records the previous state; disabling puts it back.  */
static grub_err_t
set_privilege (int enable)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES tp;
	DWORD prev_len = sizeof (efivars_priv_prev);
	grub_err_t err = GRUB_ERR_NONE;

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
	{
		err = grub_error (GRUB_ERR_ACCESS_DENIED, "cannot open the process token (%lu)",
			(unsigned long) GetLastError ());
		goto out;
	}
	if (!enable)
	{
		AdjustTokenPrivileges (token, FALSE, &efivars_priv_prev, 0, NULL, NULL);
		efivars_priv_changed = 0;
		goto out;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValueW (NULL, SE_SYSTEM_ENVIRONMENT_NAME, &tp.Privileges[0].Luid))
	{
		err = grub_error (GRUB_ERR_ACCESS_DENIED, "cannot look up the firmware privilege (%lu)",
			(unsigned long) GetLastError ());
		goto out;
	}
	if (!AdjustTokenPrivileges (token, FALSE, &tp, sizeof (efivars_priv_prev),
		&efivars_priv_prev, &prev_len)
		|| GetLastError () == ERROR_NOT_ALL_ASSIGNED)
	{
		err = grub_error (GRUB_ERR_ACCESS_DENIED,
			"reading UEFI variables needs an elevated token");
		goto out;
	}
	efivars_priv_changed = 1;
out:
	if (token)
		CloseHandle (token);
	return err;
}

int
rover_efivars_enable (void)
{
	HMODULE mod;
	efivars_fwtype_fn fwtype;
	DWORD type;

	grub_errno = GRUB_ERR_NONE;
	if (efivars_registered)
		return 0;
	mod = GetModuleHandleW (L"ntdll.dll");
	efivars_enum = mod ? (efivars_enum_fn) GetProcAddress (mod,
		"NtEnumerateSystemEnvironmentValuesEx") : NULL;
	if (!efivars_enum)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			"this Windows cannot enumerate UEFI variables");
	/* Windows 8 and later name the firmware; refuse only a definite
	   legacy BIOS boot.  Before that, or when the answer is "unknown",
	   the enumeration's own status says it.  */
	mod = GetModuleHandleW (L"kernel32.dll");
	fwtype = mod ? (efivars_fwtype_fn) GetProcAddress (mod, "GetFirmwareType") : NULL;
	if (fwtype && fwtype (&type) && type == EFIVARS_FIRMWARE_BIOS)
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			"this system was not booted through UEFI");
	if (set_privilege (1) != GRUB_ERR_NONE)
		return grub_errno;
	grub_disk_dev_register (&efivars_dev);
	grub_fs_register (&efivarfs_fs);
	efivars_registered = 1;
	return 0;
}

void
rover_efivars_disable (void)
{
	if (!efivars_registered)
		return;
	grub_fs_unregister (&efivarfs_fs);
	grub_disk_dev_unregister (&efivars_dev);
	snapshot_drop ();
	if (efivars_priv_changed)
		set_privilege (0);
	efivars_registered = 0;
}

int
rover_efivars_enabled (void)
{
	return efivars_registered;
}
