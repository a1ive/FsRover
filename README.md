<br />
<div align="center">
  <img src="FsRover/FsRover.ico" width="64" height="64" alt="Rover icon">
  <h3 align="center">Rover</h3>
  <img src="https://img.shields.io/github/license/a1ive/FsRover" alt="License">
  <img src="https://img.shields.io/github/actions/workflow/status/a1ive/FsRover/msbuild.yml" alt="Build status">
</div>
<br />

FsRover is a read-only multi-filesystem explorer for Windows, powered by GNU GRUB.

## Features

- Browse physical disks, optical discs, disk images, partitions, RAID, and logical volumes.
- Extract files or mount a filesystem as a Windows drive through the bundled Dokany runtime.
- Open nested and compressed disk images as virtual disks.
- Inspect files with built-in properties, hashes, text, image, and hex views.
- Unlock LUKS1, LUKS2, BitLocker, and GELI volumes.

## Supported Filesystems

- **Linux:** Btrfs, cramfs, EROFS, ext2/3/4, F2FS, JFS, JFFS2, NILFS2, ReiserFS, UBIFS, XFS
- **Windows:** FAT12/16/32, exFAT, NTFS, ReFS 3.x
- **macOS:** APFS, HFS, HFS+
- **Unix and other:** AFFS, AFS, BFS, FbFS, LynxFS, MINIX1/2/3, QNX4/6, RedoxFS, romfs, SFS, UFS1/2, ZFS
- **Optical media:** ISO9660, UDF
- **Archives:** cpio, SquashFS, tar, WIM, ZIP

APFS and ZFS native encryption are not supported.

## Other Supported Formats

- **Virtual disks:** VHD, VHDX, VDI, QCOW1/2/3, VMDK, DMG, ISZ
- **Compression:** gzip, LZ4, LZOP, XZ, Zstandard
- **Dynamic disks and RAID:** Windows LDM, Linux LVM, mdraid, RAID5/6, NVIDIA dmraid
- **Partition tables:** MBR, GPT, Apple, BSD, DragonFly BSD, Acorn, Amiga, DVH, Plan 9, Sun

## Credits

- [GNU GRUB](https://www.gnu.org/software/grub/)
- [Dokany](https://github.com/dokan-dev/dokany)
- [VirtualBox](https://www.virtualbox.org/)
- [wimboot](https://ipxe.org/wimboot)
- [file](https://www.darwinsys.com/file/)
- [stb_image](https://github.com/nothings/stb)
- [VC-LTL and YY-Thunks](https://github.com/Chuyu-Team)

FsRover is licensed under [GPL-3.0-or-later](LICENSE).
