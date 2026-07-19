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
 * grub disk backend for Windows physical drives ("hdN" maps to
 * \\.\PhysicalDriveN) and optical drives ("cdN" maps to \\.\CdRomN).
 * Read-only by design.
 */

#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>

#include <wchar.h>

#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>

#pragma comment (lib, "setupapi.lib")

GRUB_MOD_LICENSE ("GPLv3+");

/* hd0 and cd0 share the HOSTDISK dev id, so the optical drives take a
   high disk->id bit to keep the (dev_id, disk_id, sector) block cache
   from aliasing a physical drive with the same number.  */
#define WINDISK_CDROM_ID	0x80000000UL

struct windisk_data
{
	HANDLE handle;
};

static BOOL
get_drive_id (const char *name, DWORD *drive, BOOL *is_cdrom)
{
	if (name[0] == 'h' && name[1] == 'd' && grub_isdigit (name[2]))
		*is_cdrom = FALSE;
	else if (name[0] == 'c' && name[1] == 'd' && grub_isdigit (name[2]))
		*is_cdrom = TRUE;
	else
		goto fail;
	*drive = grub_strtoul (name + 2, NULL, 10);
	return TRUE;
fail:
	grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not a windisk");
	return FALSE;
}

static HANDLE
open_drive (DWORD id, BOOL is_cdrom)
{
	WCHAR path[] = L"\\\\.\\PhysicalDrive4294967295";
	if (is_cdrom)
		swprintf_s (path, ARRAYSIZE (path), L"\\\\.\\CdRom%u", id);
	else
		swprintf_s (path, ARRAYSIZE (path), L"\\\\.\\PhysicalDrive%u", id);
	return CreateFileW (path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

static UINT64
get_drive_size (HANDLE handle, DWORD *sector_size)
{
	DWORD bytes;
	GET_LENGTH_INFORMATION li = { 0 };
	DISK_GEOMETRY geo = { 0 };

	*sector_size = GRUB_DISK_SECTOR_SIZE;
	if (DeviceIoControl (handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geo, sizeof (geo), &bytes, NULL)
		&& geo.BytesPerSector >= GRUB_DISK_SECTOR_SIZE)
		*sector_size = geo.BytesPerSector;

	if (DeviceIoControl (handle, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &li, sizeof (li), &bytes, NULL))
		return li.Length.QuadPart;

	/* Optical class drivers often reject GET_LENGTH_INFO; fall back to
	   the CHS product from the geometry (zero if no media is present).  */
	return (UINT64) geo.Cylinders.QuadPart * geo.TracksPerCylinder * geo.SectorsPerTrack * geo.BytesPerSector;
}

/* SP_DEVICE_INTERFACE_DETAIL_DATA_W with room for a real path.  */
struct devif_detail
{
	DWORD cbSize;
	WCHAR DevicePath[512];
};

static int
call_hook (grub_disk_dev_iterate_hook_t hook, void *hook_data, DWORD drive, BOOL is_cdrom)
{
	char name[] = "hd4294967295";
	grub_snprintf (name, sizeof (name), "%s%u", is_cdrom ? "cd" : "hd", (unsigned) drive);
	return hook (name, hook_data);
}

/* Enumerate one device-interface class (disks or optical drives),
   naming each by its storage device number ("hdN" / "cdN").  */
static int
iterate_class (grub_disk_dev_iterate_hook_t hook, void *hook_data, const GUID *class_guid, BOOL is_cdrom)
{
	DWORD index;
	SP_DEVICE_INTERFACE_DATA sdid = { .cbSize = sizeof (sdid) };
	struct devif_detail detail = { .cbSize = sizeof (SP_DEVICE_INTERFACE_DETAIL_DATA_W) };
	SP_DEVINFO_DATA sdd = { .cbSize = sizeof (sdd) };
	GUID guid = *class_guid;
	HDEVINFO dev_info;
	int ret = 0;

	dev_info = SetupDiGetClassDevsW (&guid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (dev_info == INVALID_HANDLE_VALUE)
		return 0;

	for (index = 0;
		SetupDiEnumDeviceInterfaces (dev_info, NULL, &guid, index, &sdid);
		index++)
	{
		DWORD bytes;
		STORAGE_DEVICE_NUMBER sdn = { 0 };
		HANDLE handle;
		BOOL rc;

		if (!SetupDiGetDeviceInterfaceDetailW (dev_info, &sdid,
			(PSP_DEVICE_INTERFACE_DETAIL_DATA_W) &detail,
			sizeof (detail), NULL, &sdd))
			continue;
		handle = CreateFileW (detail.DevicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE)
			continue;
		rc = DeviceIoControl (handle, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn, sizeof (sdn), &bytes, NULL);
		CloseHandle (handle);
		if (!rc)
			continue;
		if (call_hook (hook, hook_data, sdn.DeviceNumber, is_cdrom))
		{
			ret = 1;
			goto done;
		}
	}
done:
	SetupDiDestroyDeviceInfoList (dev_info);
	return ret;
}

static int
windisk_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data, grub_disk_pull_t pull)
{
	GUID disk_guid = GUID_DEVINTERFACE_DISK;
	GUID cdrom_guid = GUID_DEVINTERFACE_CDROM;

	if (pull != GRUB_DISK_PULL_NONE)
		return 0;

	if (iterate_class (hook, hook_data, &disk_guid, FALSE))
		return 1;
	return iterate_class (hook, hook_data, &cdrom_guid, TRUE);
}

static grub_err_t
windisk_open (const char *name, grub_disk_t disk)
{
	DWORD drive;
	BOOL is_cdrom;
	DWORD sector_size;
	UINT64 size;
	struct windisk_data *data;
	HANDLE handle;

	if (!get_drive_id (name, &drive, &is_cdrom))
		return grub_errno;

	handle = open_drive (drive, is_cdrom);
	if (handle == INVALID_HANDLE_VALUE)
		return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "cannot open windisk %s", name);

	data = grub_malloc (sizeof (*data));
	if (!data)
		goto fail;
	data->handle = handle;

	size = get_drive_size (handle, &sector_size);
	disk->id = is_cdrom ? (drive | WINDISK_CDROM_ID) : drive;
	for (disk->log_sector_size = 0; (1U << disk->log_sector_size) < sector_size; disk->log_sector_size++)
		;
	disk->total_sectors = size >> disk->log_sector_size;
	disk->max_agglomerate = 1048576 >> (GRUB_DISK_SECTOR_BITS + GRUB_DISK_CACHE_BITS);
	disk->data = data;

	return GRUB_ERR_NONE;

fail:
	CloseHandle (handle);
	return grub_errno;
}

static void
windisk_close (grub_disk_t disk)
{
	struct windisk_data *data = disk->data;

	if (!data)
		return;
	CloseHandle (data->handle);
	grub_free (data);
	disk->data = NULL;
}

static grub_err_t
windisk_read (struct grub_disk *disk, grub_disk_addr_t sector, grub_size_t size, char *buf)
{
	struct windisk_data *data = disk->data;
	LARGE_INTEGER offset;
	DWORD bytes;
	DWORD bytes_read;
	DWORD win_error;
	char *read_buf = buf;

	if (size > (0xFFFFFFFFULL >> disk->log_sector_size))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "attempt to read more than 4GB at once");

	offset.QuadPart = (LONGLONG) (sector << disk->log_sector_size);
	if (!SetFilePointerEx (data->handle, offset, NULL, FILE_BEGIN))
		return grub_error (GRUB_ERR_OUT_OF_RANGE, "attempt to seek outside of disk %s", disk->name);

	bytes = (DWORD) (size << disk->log_sector_size);
	/* Some raw disk drivers reject a buffer not aligned to DWORD.  */
	if ((grub_addr_t) buf & (sizeof (DWORD) - 1))
	{
		read_buf = grub_malloc (bytes);
		if (!read_buf)
			return grub_errno;
	}
	if (!ReadFile (data->handle, read_buf, bytes, &bytes_read, NULL))
	{
		win_error = GetLastError ();
		grub_error (GRUB_ERR_READ_ERROR, "failure reading %llu sectors at 0x%llx from %s (Windows error %lu)",
			(unsigned long long) size,
			(unsigned long long) sector, disk->name,
			(unsigned long) win_error);
		goto fail;
	}
	if (bytes_read != bytes)
	{
		grub_error (GRUB_ERR_READ_ERROR, "short read at sector 0x%llx from %s", (unsigned long long) sector, disk->name);
		goto fail;
	}
	if (read_buf != buf)
	{
		grub_memcpy (buf, read_buf, bytes);
		grub_free (read_buf);
	}
	return GRUB_ERR_NONE;

fail:
	if (read_buf != buf)
		grub_free (read_buf);
	return grub_errno;
}

static grub_err_t
windisk_write (struct grub_disk *disk, grub_disk_addr_t sector, grub_size_t size, const char *buf)
{
	(void) disk;
	(void) sector;
	(void) size;
	(void) buf;
	return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "windisk writes are not supported");
}

static struct grub_disk_dev grub_windisk_dev =
{
	.name = "windisk",
	.id = GRUB_DISK_DEVICE_HOSTDISK_ID,
	.disk_iterate = windisk_iterate,
	.disk_open = windisk_open,
	.disk_close = windisk_close,
	.disk_read = windisk_read,
	.disk_write = windisk_write,
	.next = 0
};

GRUB_MOD_INIT (windisk)
{
	grub_disk_dev_register (&grub_windisk_dev);
}

GRUB_MOD_FINI (windisk)
{
	grub_disk_dev_unregister (&grub_windisk_dev);
}
