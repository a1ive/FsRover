/*
 *  NkArc
 *  Copyright (C) 2023 A1ive
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

#include <grub/disk.h>
#include <wchar.h>
#include <windows.h>
#include <intsafe.h>
#include <setupapi.h>

#pragma comment (lib, "setupapi.lib")

static BOOL
get_drive_id(const char* name, DWORD* drive)
{
	DWORD d;
	if (!name || name[0] != 'h' || name[1] != 'd' || !grub_isdigit(name[2]))
		goto fail;
	d = grub_strtoul(name + 2, NULL, 10);
	*drive = d;
	return TRUE;
fail:
	grub_error(GRUB_ERR_UNKNOWN_DEVICE, "not a windisk");
	return FALSE;
}

static HANDLE
get_drive_handle(DWORD id)
{
	HANDLE disk;
	WCHAR path[] = L"\\\\.\\PhysicalDrive4294967295";
	swprintf(path, ARRAYSIZE(path), L"\\\\.\\PhysicalDrive%u", id);
#ifdef GRUB_WINDISK_WRITE
	disk = CreateFileW(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		0, OPEN_EXISTING, 0, 0);
	if (disk == NULL || disk == INVALID_HANDLE_VALUE)
#endif
	{
		disk = CreateFileW(path,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			0, OPEN_EXISTING, 0, 0);
	}
	if (disk == NULL)
		disk = INVALID_HANDLE_VALUE;
	return disk;
}

static UINT64
get_drive_size(HANDLE disk)
{
	DWORD dw_bytes;
	UINT64 size = 0;
	GET_LENGTH_INFORMATION LengthInfo = { 0 };
	if (DeviceIoControl(disk, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0,
		&LengthInfo, sizeof(LengthInfo), &dw_bytes, NULL))
		size = LengthInfo.Length.QuadPart;
	return size;
}

static int
hd_call_hook(grub_disk_dev_iterate_hook_t hook, void* hook_data, DWORD drive)
{
	char name[] = "hd4294967295";
	grub_snprintf(name, sizeof(name), "hd%lu", drive);
	return hook(name, hook_data);
}

typedef struct
{
	DWORD  cbSize;
	WCHAR  DevicePath[512];
} MY_DEVIF_DETAIL_DATA;

static int
windisk_iterate(grub_disk_dev_iterate_hook_t hook, void* hook_data, grub_disk_pull_t pull)
{
	switch (pull)
	{
	case GRUB_DISK_PULL_NONE:
	{
		DWORD index = 0;
		SP_DEVICE_INTERFACE_DATA sdid = { .cbSize = sizeof(SP_DEVICE_INTERFACE_DATA) };
		MY_DEVIF_DETAIL_DATA mddd = { .cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) };
		SP_DEVINFO_DATA sdd = { .cbSize = sizeof(SP_DEVINFO_DATA) };
		GUID guid = GUID_DEVINTERFACE_DISK;
		HDEVINFO dev_info = SetupDiGetClassDevsW(&guid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
		if (dev_info == INVALID_HANDLE_VALUE)
			return 0;
		for (index = 0; SetupDiEnumDeviceInterfaces(dev_info, NULL, &guid, index, &sdid); index++)
		{
			if (SetupDiGetDeviceInterfaceDetailW(dev_info, &sdid, (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)&mddd,
				sizeof(MY_DEVIF_DETAIL_DATA), NULL, &sdd))
			{
				BOOL rc = FALSE;
				DWORD bufsz;
				STORAGE_DEVICE_NUMBER sdn = { 0 };
				HANDLE disk = CreateFileW(mddd.DevicePath,
					GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (disk == INVALID_HANDLE_VALUE || disk == NULL)
					continue;
				rc = DeviceIoControl(disk, IOCTL_STORAGE_GET_DEVICE_NUMBER,
					NULL, 0, &sdn, (DWORD)(sizeof(STORAGE_DEVICE_NUMBER)),
					&bufsz, NULL);
				CloseHandle(disk);
				if (rc == FALSE)
					continue;
				if (hd_call_hook(hook, hook_data, sdn.DeviceNumber))
					return 1;
			}
		}
		SetupDiDestroyDeviceInfoList(dev_info);
		return 0;
	}
	case GRUB_DISK_PULL_REMOVABLE:
		// TODO: support cdrom
		return 0;
	}

	return 0;
}

static grub_err_t
windisk_open(const char* name, grub_disk_t disk)
{
	DWORD drive;
	HANDLE* data;

	if (!get_drive_id(name, &drive))
		return grub_errno;

	data = get_drive_handle(drive);
	if (data == INVALID_HANDLE_VALUE)
		return grub_error(GRUB_ERR_UNKNOWN_DEVICE, "invalid windisk");

	disk->id = drive;
	disk->log_sector_size = GRUB_DISK_SECTOR_BITS;
	disk->total_sectors = get_drive_size(data) >> GRUB_DISK_SECTOR_BITS;
	disk->max_agglomerate = 1048576 >> (GRUB_DISK_SECTOR_BITS + GRUB_DISK_CACHE_BITS);

	disk->data = data;

	return GRUB_ERR_NONE;
}

static void
windisk_close(grub_disk_t disk)
{
	HANDLE* data = disk->data;
	if (data && data != INVALID_HANDLE_VALUE)
		CloseHandle(data);
	disk->data = NULL;
}

static grub_err_t
windisk_read(struct grub_disk* disk, grub_disk_addr_t sector, grub_size_t size, char* buf)
{
	HANDLE dh = disk->data;
	__int64 distance = sector << GRUB_DISK_SECTOR_BITS;
	LARGE_INTEGER li = { 0 };
	DWORD dwsize;
	grub_dprintf("windisk", "windisk read %s sector 0x%llx size 0x%llx\n", disk->name, sector, size);
	if (size > (DWORD_MAX >> GRUB_DISK_SECTOR_BITS))
		return grub_error(GRUB_ERR_OUT_OF_RANGE, "attempt to read more than 4GB data");
	dwsize = (DWORD)(size << GRUB_DISK_SECTOR_BITS);
	li.QuadPart = distance;
	li.LowPart = SetFilePointer(dh, li.LowPart, &li.HighPart, FILE_BEGIN);
	if (li.LowPart == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
		return grub_error(GRUB_ERR_OUT_OF_RANGE, "attempt to read outside of disk %s", disk->name);
	grub_dprintf("windisk", "windisk readfile offset 0x%llx size 0x%lx\n", distance, dwsize);
	if (ReadFile(dh, buf, dwsize, &dwsize, NULL))
		return GRUB_ERR_NONE;
	grub_dprintf("windisk", "windisk readfile failed %u\n", GetLastError());
	return grub_error(GRUB_ERR_READ_ERROR, "failure reading sector 0x%llx from %s", sector, disk->name);
}

static grub_err_t
windisk_write(struct grub_disk* disk, grub_disk_addr_t sector, grub_size_t size, const char* buf)
{
#ifdef GRUB_WINDISK_WRITE
	HANDLE dh = disk->data;
	__int64 distance = sector << GRUB_DISK_SECTOR_BITS;
	LARGE_INTEGER li = { 0 };
	DWORD dwsize;
	if (size > (DWORD_MAX >> GRUB_DISK_SECTOR_BITS))
		return grub_error(GRUB_ERR_OUT_OF_RANGE, "attempt to write more than 4GB data");
	dwsize = (DWORD)(size << GRUB_DISK_SECTOR_BITS);
	li.QuadPart = distance;
	li.LowPart = SetFilePointer(dh, li.LowPart, &li.HighPart, FILE_BEGIN);
	if (li.LowPart == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
		return grub_error(GRUB_ERR_OUT_OF_RANGE, "attempt to write outside of disk %s", disk->name);

	if (WriteFile(dh, buf, dwsize, &dwsize, NULL))
		return GRUB_ERR_NONE;
	return grub_error(GRUB_ERR_READ_ERROR, "failure writing sector 0x%llx from %s", sector, disk->name);
#else
	return grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
		"windisk writes are not supported");
#endif
}

static struct grub_disk_dev grub_windisk_dev =
{
	.name = "windisk",
	.id = GRUB_DISK_DEVICE_WINDISK_ID,
	.disk_iterate = windisk_iterate,
	.disk_open = windisk_open,
	.disk_close = windisk_close,
	.disk_read = windisk_read,
	.disk_write = windisk_write,
	.next = 0
};

GRUB_MOD_INIT(windisk)
{
	grub_disk_dev_register(&grub_windisk_dev);
}

GRUB_MOD_FINI(windisk)
{
	grub_disk_dev_unregister(&grub_windisk_dev);
}
