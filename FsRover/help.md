# FsRover Help

FsRover is a read-only multi-filesystem explorer for Windows.

---

## Contents

1. [Filesystems](#1-filesystems)
2. [I/O filters](#2-io-filters)
3. [Disk filters (RAID / LVM)](#3-disk-filters-raid--lvm)
4. [Encrypted volumes](#4-encrypted-volumes)
5. [Dokan](#5-dokan)
6. [S.M.A.R.T.](#6-smart)
7. [Keyboard shortcuts](#7-keyboard-shortcuts)
8. [Command line](#8-command-line)

---

## 1. Filesystems

### 1.1 Linux and flash filesystems

#### Btrfs — `btrfs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

**Compression:** zlib, LZO, Zstandard.

**Multi-device profiles:** single, RAID0, RAID1, RAID1C3, RAID1C4, RAID10,
RAID5, RAID6 — with RAID5/6 reconstruction when a member is missing. All member
devices must be visible to FsRover at the same time.

The default subvolume is presented.

**Not supported:** send/receive streams, per-file encryption.

#### cramfs — `cramfs`

> Origin: Linux · Label: yes · UUID: no · Timestamps: none · Symlinks: resolved

cramfs v2, in both little- and big-endian byte order.

**Compression:** zlib. The Linux 4.15 `CRAMFS_BLK_FLAG_UNCOMPRESSED` extension
is honoured, and zero-length block regions are read back as holes.

Images carrying a 512-byte boot prefix are accepted.

**Not supported:** XIP images, which use direct block pointers.

#### EROFS — `erofs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

**Compression:** LZ4, LZMA, DEFLATE, Zstandard.

#### ext2 / ext3 / ext4 — `ext2`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

One driver covers all three generations.

**Features used to mount:** `filetype`, `extents`, `flex_bg`, `meta_bg`,
`64bit`.

**Features ignored rather than refused:** `has_journal`, `mmp`, `csum_seed`,
`largedir`. The journal is **not** replayed, so an uncleanly unmounted
filesystem is read as of its last commit.

A volume with the `encrypt` feature mounts, but encrypted file contents come
back as stored ciphertext.

#### F2FS — `f2fs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

**Compression:** LZO, LZ4, Zstandard.

#### JFFS2 — `jffs2`

> Origin: u-boot · Label: no · UUID: no · Timestamps: per-file · Symlinks: resolved

Both little- and big-endian images are accepted.

**Compression:** none, zero, rtime, zlib, LZO. The `rubin` variants are
rejected.

#### JFS — `jfs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

#### littlefs — `littlefs`

> Origin: FsRover · Label: no · UUID: no · Timestamps: none · Symlinks: none

**Supported versions:** 2.0 and 2.1.

#### NILFS2 — `nilfs2`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

Revision 2 only.

#### ReiserFS — `reiserfs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

ReiserFS 3.5 and 3.6. Reiser4 is a different format and is not supported.

#### SquashFS — `squash4`

> Origin: GRUB · Label: no · UUID: no · Timestamps: per-file + volume · Symlinks: resolved

**SquashFS 4.0 only** — versions 1.x through 3.x are a different superblock
layout and are not recognised.

**Compression:** zlib, LZO, XZ, LZ4, Zstandard. The legacy LZMA1 compressor id
is not supported.

#### UBIFS — `ubifs`

> Origin: u-boot · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

Two image shapes are accepted:

- a **bare UBIFS image** (`mkfs.ubifs` output, LEB *n* at byte *n* × leb_size);
- a **UBI image or raw flash dump** — `UBI#` erase-counter headers, with the
  physical eraseblock size detected from the header spacing, volumes mapped
  through the big-endian EC/VID headers, and the first volume carrying a UBIFS
  superblock mounted and labelled with its volume-table name.

**Compression:** none, LZO, zlib (raw deflate), Zstandard.

Unlike u-boot, this driver does **not replay the journal** — it walks the
committed on-flash index. Changes written after the last commit of an uncleanly
detached image are therefore invisible.

**Not supported:** encrypted and authenticated filesystems.

#### XFS — `xfs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

XFS v4 and v5 (CRC-enabled) superblocks. Short-form, block, leaf and B-tree
directories are handled, as are inline symbolic links.

#### ZFS / OpenZFS — `zfs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

**Compression:** LZJB, ZLE, gzip-1 … gzip-9, LZ4, Zstandard.

**Read-supported pool features** — a pool with any *other* active feature is
refused:

`org.illumos:lz4_compress`, `com.delphix:hole_birth`,
`com.delphix:embedded_data`, `com.delphix:extensible_dataset`,
`org.open-zfs:large_blocks`, `com.klarasystems:vdev_zaps_v2`,
`com.delphix:head_errlog`, `org.freebsd:zstd_compress`.

**Not supported: native ZFS encryption** — the `zfscrypt` module is not built
in, so an encrypted dataset reports an error.

---

### 1.2 Windows filesystems

#### FAT12 / FAT16 / FAT32 — `fat`

> Origin: GRUB · Label: yes · UUID: volume serial · Timestamps: per-file · Symlinks: none

Long file names (VFAT) are read.

#### exFAT — `exfat`

> Origin: GRUB · Label: yes · UUID: volume serial · Timestamps: per-file · Symlinks: none

#### NTFS — `ntfs`

> Origin: GRUB · Label: yes · UUID: volume serial · Timestamps: per-file · Symlinks: resolved

**Compression:** LZNT1 and Windows Compact / WOF compression using XPRESS4K,
XPRESS8K, XPRESS16K, or LZX32K. Sparse files, non-resident attribute lists
and `$ATTRIBUTE_LIST` overflow are handled. Reparse points are read through
the `$SYMLINK` attribute, which covers ordinary symbolic links and junctions;
supported WOF files are exposed as regular files.

**Not supported:**

- alternate data streams (ADS);
- EFS-encrypted files — the contents come back as ciphertext;
- reparse-point target resolution beyond symbolic links and junctions.

#### ReFS — `refs`

> Origin: refsprogs · Label: yes · UUID: boot serial · Timestamps: per-file · Symlinks: flagged

**Supported versions:** ReFS 1.x and ReFS 3.x.

**Not supported:**

- alternate data streams (ADS);
- reparse-point target resolution;

#### Windows registry hive — `regfs`

> Origin: FsRover · Label: yes · UUID: no · Timestamps: per-file + volume · Symlinks: flagged

Browses a registry hive file — `SOFTWARE`, `SYSTEM`, `NTUSER.DAT`, `BCD`, … —
as if it were a filesystem. REGF format versions 1.1 and 1.3 – 1.6 are read, and
cells are fetched from disk on demand rather than loaded whole.

**Mapping** (values and subkeys share one namespace, the way regedit shows a
key):

- the root key is the root directory;
- a subkey is a directory, carrying the key's last-written time;
- a value is a file whose content is the **raw value data** — string types are
  UTF-16LE, DWORD/QWORD are little-endian integers;
- the unnamed value is called `(default)`;
- the volume label is the tail of the hive's own path (`…\config\SOFTWARE` →
  `SOFTWARE`).

**Name rewriting.** A path has to address exactly one entry, and extracted names
have to be legal Windows filenames, so `/`, the illegal characters
`\ : * ? " < > |`, control characters and `%` itself are escaped as `%XX`, and
`.` / `..` get their first byte escaped. When a value and a subkey in the same
key collide, the value is renamed `name~1`, `name~2`, …

Keys flagged `KEY_SYM_LINK` are marked as links but stay enterable.

**Not exposed:** security descriptors (`sk`), key class names, volatile keys
(these exist only in a running system's memory image, never in the file).

**Rejected:** transaction logs (`.LOG`, `.LOG1`, `.LOG2`). A dirty hive is read
as-is, without replaying its log.

---

### 1.3 Apple filesystems

#### APFS — `apfs`

> Origin: linux-apfs-rw · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

**Compression** (`decmpfs`), in both the attribute-inline and resource-fork
layouts: uncompressed, zlib, LZVN, LZFSE, LZBITMAP.

**Not supported:** FileVault-encrypted volumes (skipped at mount time),
snapshots, Fusion containers.

#### HFS — `hfs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: none

Mac OS Standard.

#### HFS+ / HFSX — `hfsplus`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

Mac OS Extended, including case-sensitive HFSX volumes.

**Compression:** `decmpfs` **zlib types only**. LZVN- and LZFSE-compressed files on HFS+ are not decompressed.

---

### 1.4 Unix and legacy filesystems

#### Amiga FFS — `affs`

> Origin: GRUB · Label: yes · UUID: no · Timestamps: per-file + volume · Symlinks: resolved

#### BeOS / Haiku AFS — `afs`

> Origin: GRUB · Label: yes · UUID: no · Timestamps: per-file · Symlinks: resolved

#### BFS (Be File System) — `bfs`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

#### HPFS — `hpfs`

> Origin: Linux · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

OS/2 High Performance File System.

Symbolic links are the `SYMLINK` extended attribute written by the Linux driver.
Bad-sector hotfix remapping is applied on every read.

**Not interpreted:** ACLs, HPFS386 extended permissions, the code page tables.

#### LynxFS — `lynxfs`

> Origin: third-party GRUB module · Label: no · UUID: no · Timestamps: per-file · Symlinks: resolved

#### MINIX — `minix`, `minix_be`, `minix2`, `minix2_be`, `minix3`, `minix3_be`

> Origin: GRUB · Label: no · UUID: no · Timestamps: per-file · Symlinks: resolved

MINIX v1, v2 and v3. The `_be` drivers are the big-endian variants of the same
on-disk format (m68k, SPARC, PowerPC hosts).

#### QNX 4 — `qnx4`

> Origin: third-party GRUB module · Label: no · UUID: no · Timestamps: per-file · Symlinks: resolved

#### QNX 6 — `qnx6`

> Origin: third-party GRUB module · Label: no · UUID: no · Timestamps: per-file · Symlinks: resolved

#### RedoxFS — `redoxfs`

> Origin: third-party GRUB module · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

**Unencrypted RedoxFS v8 only** — encrypted volumes are refused at mount time.

**Compression:** LZ4 extents.

#### romfs — `romfs`

> Origin: GRUB · Label: yes · UUID: no · Timestamps: none · Symlinks: resolved

#### SCO UnixWare BFS — `bootfs`

> Origin: Linux · Label: yes · UUID: no · Timestamps: per-file · Symlinks: none

The boot filesystem UnixWare mounts on `/stand`. It is named `bootfs` here
because `bfs` is taken by the Be File System. Files occupy one contiguous run
of 512-byte blocks each, the root is the only directory the format can hold,
and there are no symbolic links.

The volume label is only reported when the field holds printable text.

#### Amiga Smart File System — `sfs`

> Origin: GRUB · Label: yes · UUID: no · Timestamps: per-file · Symlinks: resolved

#### UFS1 / UFS2 — `ufs1`, `ufs1_be`, `ufs2`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

BSD and Solaris UFS. `ufs1_be` is the big-endian variant of UFS1; UFS2 handles
both byte orders in one driver.

#### VERITAS VxFS — `vxfs`

> Origin: Linux · Label: yes · UUID: no · Timestamps: per-file · Symlinks: resolved

**Supported disk layouts:** version 2, 3 and 4, in both byte orders (UnixWare
volumes are little-endian, HP-UX ones big-endian). Version 5 and newer are
refused at mount time.

All three data layouts are read: immediate (small files stored in the inode),
extent-based ("ext4") and typed extents, including their indirect blocks.
Sparse files read back as zeros. The label is the pack name (`vs_fpack`) set
by `labelit`.

**Not supported:** multi-volume (DEV4) extents, extended attributes, quotas.

#### VMFS — `vmfs`

> Origin: vmfs-tool · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

**Supported versions:** VMFS3, VMFS5, VMFS6.

Spanned (multi-extent) volumes are supported.

**Not supported:** RDM (raw device mapping) entries.

#### FbFS — `ud`

> Origin: FsRover · Label: no · UUID: no · Timestamps: none · Symlinks: none

Fbinst is a USB partition/format utility by Bean designed to provide
maximum 'bootability' on all systems.

**Supported versions:** 1.6, 1.7.

---

### 1.5 Optical media

#### ISO 9660 — `iso9660`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file + volume · Symlinks: resolved

SUSP / Rock Ridge extensions give long names, POSIX attributes and symbolic
links; Joliet gives Unicode names.

The primary volume descriptor is read from the standard offset, so the later
sessions of a multi-session disc are not picked up.

#### UDF — `udf`

> Origin: GRUB · Label: yes · UUID: yes · Timestamps: per-file · Symlinks: resolved

**Supported versions:** UDF 1.02 through 2.60.

**Supported partition maps:**

| Map | Written by | How a block is found |
| --- | --- | --- |
| type 1, physical | hard disks, DVD-ROM, plain images | directly, at the partition's start |
| virtual (VAT) | CD-R, DVD-R, BD-R and other write-once media | through the Virtual Allocation Table |
| sparable | CD-RW, DVD-RW | through the sparing table |
| metadata | UDF 2.50 / 2.60, Blu-ray | through the metadata file's extents |

Files the medium marks hidden are listed rather than filtered, so a sparable
disc shows its `Non-Allocatable Space` placeholder alongside real files.

**Not supported:** sessions other than the first — the volume recognition
sequence is read from the start of the medium, so a multi-session disc is read
as its first session. Named streams and extended attributes are not exposed.

---

### 1.6 Archives and packages

Archives are browsed exactly like a filesystem: open a `.zip`, `.7z`,
`.tar.gz`, `.rpm`, … from any volume with **Mount as disk**, or pass it on the
command line, and its contents appear as a directory tree.

#### 7z — `7z`

> Origin: 7-Zip · Label: no · UUID: no · Timestamps: per-file + volume · Symlinks: flagged

**Solid archives** are supported; seeking backwards inside a solid block re-runs
the chain from its start.

**Coders:** Copy, LZMA, LZMA2, PPMd7, BZip2, Deflate, Zstandard (both the
`0x4015D` id and the 7-Zip-zstd fork's `0x4F71101`), LZ4 (fork id `0x4F71104`,
standard LZ4 frames).

**Filters:** Delta, BCJ (x86), BCJ2, ARM, ARMT, ARM64, PPC, SPARC, IA64,
RISC-V, SWAP2, SWAP4.

Folders are wired up generically from the archive's bonds and pack streams, not
limited to the three fixed topologies of the reference decoder.

**Not supported:** encrypted entries, multi-volume sets, Deflate64.

#### ARJ — `arj`

> Origin: 7-Zip · Label: no · UUID: no · Timestamps: per-file + volume · Symlinks: none

**Methods:** 0 (stored), 1–3 (LZH with a 26 624-byte dictionary), 4 (ARJ's own
coder). Methods 8 and 9 carry no data.

Names are stored in an OEM code page and are not transcoded.

**Not supported:** garbled (password-protected) entries and entries continued in
another volume.

#### Microsoft Cabinet — `cab`

> Origin: 7-Zip · Label: no · UUID: no · Timestamps: per-file + volume · Symlinks: none

**Methods:** None (stored), MSZIP, LZX with 15- to 21-bit windows, Quantum with
dictionaries up to 21 bits.

Reading tracks the folder's output position and skips forward; a backwards seek
re-decodes the folder from its start. Opening an entry builds the decoder but
decodes nothing, so listing an archive never triggers decompression.

**Not supported:** entries that span cabinets, and folders continued from a
previous cabinet. Listing a spanned cabinet still works.

#### cpio — `cpiofs`, `cpiofs_be`, `newc`, `odc`

> Origin: GRUB · Label: no · UUID: no · Timestamps: per-file · Symlinks: resolved

Four cpio variants, one driver each:

| Driver | Variant |
| --- | --- |
| `cpiofs` | old binary format |
| `cpiofs_be` | old binary format, big-endian |
| `newc` | SVR4 "new ASCII" format |
| `odc` | POSIX "old character" format |

#### Debian package — `deb`

> Origin: FsRover · Label: package name · UUID: no · Timestamps: per-file + volume · Symlinks: resolved

Handles `.deb` and `.udeb`. A deb is an `!<arch>` (ar) archive whose first
member is `debian-binary`.
Both the control and data tarballs are expanded in place, so a package browses as:

```
/debian-binary
/control/...    maintainer scripts, md5sums, conffiles, ...
/data/...       the files the package installs
```

The volume label comes from the `Package` field of `control/control`.

**Payload compression:** whatever the [compression filters](#21-compression-filters)
detect by magic — gzip, xz, Zstandard, LZO, LZ4, bzip2 — or none.

#### LHA / LZH — `lzh`

> Origin: 7-Zip · Label: no · UUID: no · Timestamps: per-file + volume · Symlinks: none

**Methods:** `-lhd-` (directory), `-lh0-` and `-lz4-` (stored), `-lh4-` through
`-lh7-` (4 KiB – 64 KiB dictionaries).

Names are stored in an OEM code page and are not transcoded.

**Not supported:** `-lh1-`, `-lh2-`, `-lh3-`, `-lzs-`, `-lz5-`.

#### RAR — `rar`

> Origin: 7-Zip · Label: `RAR` / `RAR5` · UUID: no · Timestamps: per-file + volume · Symlinks: flagged

Covers all five generations of the format:

| Generation | Coders |
| --- | --- |
| RAR 1.5 | ShortLZ / LongLZ with adaptive Huffman tables |
| RAR 2.0 | LZ plus the 4-channel multimedia audio filter |
| RAR 2.9 / 3.x | LZ, PPMd variant H, and the RAR virtual machine |
| RAR5 | sliding window with Delta / E8 / E8E9 / ARM filters |
| RAR7 | as RAR5, with the 80-slot distance tables |

For RAR3, the six **standard** VM filters are implemented — E8, E8E9, Itanium,
RGB, Audio, Delta — identified by code CRC. The general VM interpreter is not
implemented.

RAR4 names in the compressed UTF-16 encoding are decoded, and `\` is normalised
to `/`.

**Not supported:** encrypted archives, multi-volume sets,
entries of unknown size or unknown method.

#### RPM package — `rpm`

> Origin: FsRover · Label: `name-version-release.arch` · UUID: no · Timestamps: per-file + volume · Symlinks: resolved

Handles `.rpm` and `.srpm`. The payload cpio is expanded in place,
so a package browses straight as the file tree it installs (`/usr/bin/…`, `/etc/…`).

Only the few header tags that name the package are read, so the frequently large
rest of the header costs nothing.

**Payload compression:** gzip, xz, Zstandard, LZO, LZ4, or none. A plain-LZMA
payload is not decoded.

#### tar — `tarfs`

> Origin: GRUB · Label: no · UUID: no · Timestamps: per-file · Symlinks: resolved

Covers the v7 (magic-less), ustar, GNU and pax variants, including GNU `L` / `K`
long-name records, pax `path=` records, and base-256 numeric fields. Numeric
fields with leading spaces, as old tars wrote them, are accepted, and a
typeflag of `\0` is treated as a regular file (or a directory when the name ends
in `/`).

#### Apple XAR / macOS installer package — `xar`

> Origin: FsRover · Label: no · UUID: no · Timestamps: per-file + volume · Symlinks: flagged

Handles `.xar`, `.pkg` and `.xip`. The table of contents itself is browsable as `/[TOC].xml`.

**Encodings:** `application/octet-stream` (stored), `application/x-gzip`
(a bare zlib stream), `application/x-bzip2`, `application/x-xz`.

Names that would change the shape of the tree are rewritten: a `/` inside a name
becomes `_`, and an empty, `.` or `..` name becomes `[index]`, as 7-Zip
does. Extended attribute forks (`<ea>`), checksums, and the archive signature
are not exposed.

#### Windows Imaging — `wim`

> Origin: FsRover · Label: no · UUID: WIM GUID · Timestamps: per-file · Symlinks: resolved

The root mirrors 7-Zip's presentation of a WIM archive: one directory per image
(`1`, `2`, …) plus the raw XML metadata blob exposed as `[1].xml`.

**Chunk compression:** XPRESS, LZX.

**Not supported:** solid / LZMS resources (ESD files).

#### ZIP — `zip`

> Origin: FsRover · Label: first entry name · UUID: no · Timestamps: per-file + volume · Symlinks: none

ZIP and ZIP64, through miniz.

**Methods that can be read:** stored, Deflate.

**Not supported:** Deflate64, bzip2, LZMA, XZ, Zstandard, PPMd, and **encrypted
entries**. Such entries still appear in the listing but fail on open.

---

### 1.7 Firmware and pseudo-filesystems

#### UEFI firmware image — `uefi`

> Origin: FsRover · Label: no · UUID: no · Timestamps: none · Symlinks: none

Covers UEFI capsules, FFS1/2/3 firmware volumes, and Intel flash descriptor
images.

**Compression:** LZMA and EFI/Tiano LZH sections are decoded.

#### coreboot CBFS — `cbfs`

> Origin: GRUB · Label: no · UUID: no · Timestamps: none · Symlinks: none

**Supported layouts:** legacy, FMAP-partitioned.

**Compression:** none. A stage or payload stored LZMA-compressed is listed and
extracted as the raw compressed component, not as its contents.

#### proc filesystem — `procfs`

> Origin: GRUB · Label: no · UUID: no · Timestamps: none · Symlinks: none

A synthetic device that appears in the tree as `(proc)`.It exposes:

- `luks_script` — the master keys of unlocked LUKS volumes, in hex;
- `fve_keys` — the credential used for each unlocked BitLocker volume.

---

## 2. I/O filters

An I/O filter transforms a file on its way in. Three groups are registered:
compression filters, virtual-disk filters and backup-archive filters.

### 2.1 Compression filters

These are applied when you open an image with **Open Image (decompress)…** or
`--file-dec`, or with **Mount as disk (decompress)**, and automatically to
nested streams such as a package payload.

Three of these formats — bzip2, Brotli and LZMA-alone — store no uncompressed
length, so the file size stays unknown until the stream has been decoded to its
end, and seeking backwards restarts the decoder at offset 0.

#### gzip — `gzio`

> Origin: GRUB · Detection: magic

RFC 1952. Concatenated streams (`cat a.gz b.gz`) read as one continuous file.

#### XZ — `xzio`

> Origin: GRUB · Detection: magic

#### lzop — `lzopio`

> Origin: GRUB · Detection: magic

#### LZ4 frame — `lz4io`

> Origin: FsRover · Detection: magic

Independent and linked blocks, optional content-size field, block and content
checksums, and uncompressed blocks are all handled.

**Not supported:** frames referencing an external dictionary id — there is no
dictionary source to satisfy them.

#### Zstandard — `zstdio`

> Origin: GRUB · Detection: magic

#### bzip2 — `bz2io`

> Origin: FsRover · Detection: magic

Detection reads the `BZh` signature plus the block-size digit and the block or
end-of-stream magic that follows it; four bytes alone are too weak to probe
every file open with.

Concatenated streams (`bzip2 -c a b`, pbzip2) read as one continuous file;
trailing bytes that do not start a further stream end the file.

#### Brotli — `brio`

> Origin: FsRover · Detection: **`.br` suffix**

Brotli (RFC 7932) is a bare bit stream — no magic, no container, no stored
length. A stream opens with the window-size bits, so almost any byte string is a
syntactically plausible start and content sniffing alone cannot decide. A filter
that guessed from content would corrupt unrelated files every few tens of
thousands of opens, so detection is driven by the customary `.br` suffix and the
stream head only has to decode. Rename the file if it does not carry the suffix.

**Not supported:** concatenated streams. Unlike gzip and bzip2 this is not a
defined Brotli usage, so the first stream ends the file.

#### LZMA-alone — `lzmaio`

> Origin: FsRover · Detection: **`.lzma` / `.tlz` suffix**

The container that `lzma`(1) and 7-Zip's `-tlzma` write: a 13-byte header — one
properties byte holding lc/lp/pb, a 32-bit dictionary size and a 64-bit
uncompressed size — followed by the raw LZMA stream. That is a weak signature,
and the range coder behind it decodes almost any bit string without complaining,
so detection is suffix-driven and the header is then validated the way 7-Zip's
`LzmaHandler` does: properties below 9×5×5, stored size below 1<<56, and a
dictionary size out of the set encoders round to.

That last test is the one that earns its keep — a 4 KiB run of zeros, which disk
images and tar padding are full of, otherwise parses as a valid header and
decodes without complaint until it is applied.

When the encoder did not know the size it writes all ones and ends the stream
with an end marker; the size then stays unknown until the stream is fully
decoded.

---

### 2.2 Virtual disk images

These turn a container into a raw disk, which is then partition-scanned and
mounted as if it were a physical drive. They apply whenever an image is opened
as a disk.

**A note on files an image refers to.** A differencing VHD, VHDX, QCOW or VMDK
names its parent, and a VMDK descriptor names its extents, by a path relative to
the image itself.

When the parent or extent cannot be found, the image is not decoded at all and
its raw bytes are shown instead.

#### Microsoft VHD — `vhd`

> Origin: VirtualBox

**Supported:** fixed, dynamic and differencing images, with the parent chain
followed. Differencing support is written for this project; the NkArc original
lacked it.

#### Microsoft VHDX — `vhdx`

> Origin: VirtualBox

**Supported:** fixed, dynamic and differencing images, with the parent chain
followed.

**Not supported:** log replay — an image with an unflushed log is read as of its
last flush.

#### VirtualBox VDI — `vdi`

> Origin: VirtualBox

**Supported:** fixed and dynamic images.

**Not supported:** differencing / UNDO images. The parent is referenced by UUID
through the VirtualBox registry, which is not reachable from the image itself,
so such an image is refused rather than misread.

#### QEMU QCOW — `qcow`

> Origin: VirtualBox

**Supported:** QCOW1, QCOW2 and QCOW3; zlib- and Zstandard-compressed clusters;
backing files (written for this project). Of the QCOW3 incompatible feature bits,
`DIRTY` is let through — this is a read-only reader that never consults
refcounts — as is `COMPRESSION_TYPE` (type 0 deflate, type 1 Zstandard).

**Not supported:** cluster encryption (QCOW1 encryption is likewise refused),
`EXTERNAL_DATA`, `CORRUPT`, and images carrying snapshots.

#### VMware VMDK — `vmdk`

> Origin: FsRover

**Supported:** `monolithicSparse` (VMDK4 `KDMV` hosted sparse),
`streamOptimized` (footer plus zlib-compressed grains with markers), text
descriptor files with FLAT / VMFS / SPARSE / ZERO extents, and differencing
images via `parentFileNameHint`.

**Not supported:** VMDK3 (`COWD` / `vmfsSparse`), `seSparse`, encrypted images.
`parentCID` validation is skipped, because the parent is only visible here as a
decoded disk and its descriptor text is out of reach.

#### Apple Disk Image — `dmg`

> Origin: VirtualBox

**Supported extents:** raw, zero, ADC (the LZ77 scheme of older images), zlib,
bzip2, and LZFSE (BLKX type `0x80000007`).

**Not supported:** encrypted disk images, and segmented images (`cSegments` > 1).

#### UltraISO ISZ — `isz`

> Origin: FsRover

Implemented from the ISZ File Format Specification 1.00 (EZB Systems, 2006). The
segment and chunk tables are obfuscated with a repeating XOR key that the public
specification omits; that is handled.

**Supported:** single-file images with zero / raw / zlib / bzip2 chunks, with or
without a chunk definition table (no table means raw contiguous data).

**Not supported:** segmented images (`.i01` sibling files) and AES encryption —
the specification does not define the password key derivation, so it cannot be
implemented from it.

#### Android sparse image — `sparse`

> Origin: FsRover

Implemented from the AOSP libsparse on-disk format.

**Supported:** raw, fill, don't-care and CRC chunks. Both header sizes are read
from the file and used as strides, so a future revision that grows them still
parses.

#### Parallels HDD — `parallels`

> Origin: FsRover

#### Windows Full Flash Update — `ffu`

> Origin: FsRover

**Supported:** V1 and V2 images. Only the first store is exposed — V1 images
only ever hold one, and it is the main disk of a multi-store V2 image.

**Not supported:** the further stores of a multi-store V2 image.

#### ntfsclone image — `ntfsclone`

> Origin: FsRover

**Supported:** format version 10.0 (the first endianness-safe version) and the
older pre-10.0 layout.

#### CD/DVD image containers — `cdimage`

> Origin: FsRover / libcdio

A CD image describes the disc as tracks of raw or cooked sectors rather than as
a flat volume. This filter rebuilds the flat 2048-byte-per-sector stream the
iso9660 and udf drivers expect, addressed by absolute disc LSN so that a data
track keeps its on-disc position. Audio tracks and unwritten gaps read back as
zeros.

**Supported containers**, all recognised by extension:

| Extension | Format | Sector data |
|---|---|---|
| `.cue` | CDRWIN cue sheet | one or more sibling `FILE`s |
| `.toc` | cdrdao toc file | sibling `DATAFILE` / `AUDIOFILE`s |
| `.nrg` | Nero Burning ROM | inside the same file |
| `.ccd` | CloneCD | sibling `.img` |
| `.mds` | Alcohol 120% | sibling `.mdf` |
| `.cdr` | raw sector dump | inside the same file |

**Supported sector layouts:** 2048 cooked, 2324 (mode 2 form 2), 2336 (mode 2
without the sync and header), 2352 raw, and 2448 raw with 96 bytes of
interleaved subchannel.

**Track sources.** Multi-`FILE` cue sheets, cdrdao statements with explicit
`#byte-offset`s, `PREGAP` / `POSTGAP` / `SILENCE` / `ZERO` runs, and pregap
sectors stored in the image are all placed at the right disc address.

**Not supported:** sessions other than the first. The iso9660 driver looks for
its volume descriptor at LSN 16, so a disc whose first session is audio — a
CD-Extra — exposes the right address space but does not mount. Mode 2 form 2
sectors are exposed as the first 2048 of their 2324 user bytes, which is what
bin-to-iso converters do; they carry no filesystem of their own. CD-TEXT,
subchannel data and audio track extraction are all ignored.

---

### 2.3 Backup archives

#### Acronis True Image — `tib`, `tibx`

> Origin: FsRover

**`.tib`, sector mode — I/O filter `tib`.** A partition image. Layout: a 32-byte
volume header (36 on Mac), a block stream, a post-data region, a metadata blob,
the trailer, and a volume footer at EOF−48 that mirrors the header byte-reversed.
A block covers a fixed run of 4 KiB clusters — 128 of them in True Image 2018 and
later — and its 16-byte preamble is a bitmap of which of those clusters were
stored; the rest of the volume was empty and reads back as zeros. Blocks are not
written in volume order, so random access needs the chunk map (one 12-byte record
per block, zigzag-delta coded, byte-transposed and deflated), whose position is
reached through the trailer and the metadata blob.

**`.tib`, file mode — filesystem `tib`.** What the product writes when it backs
up files and folders, or a network share, rather than a block device. Such an
archive wears the sector-mode volume header but closes with a different trailer
magic, so the two never collide. A file is the run of `m` records up to the next
`n` record; each covers 256 KiB, with the chunk's trailing zeros stripped before
deflating and padded back out on read. Names live only in the trailing directory
tree, which carries no pointer into the block stream, so the stream order is
recovered by sorting the non-empty files by the archive offset of their metadata.
That scan is incremental and its results are cached across mounts, so walking a
whole archive costs one pass over it. Reports a label and a UUID; entries carry
no timestamps.

**`.tibx` — I/O filter `tibx`.** True Image 2020 and later, the "archive3"
container: a store of 4 KiB pages, each with an 8-byte envelope and a big-endian
CRC-32C. Bulk content lives in Zstandard-compressed segments indexed by two LSM
trees (LZ4-compressed pages), so reading one byte means a `data_map` lookup, a
`segment_map` lookup and one segment decompression. Both trees are held in
memory after the first open and decompressed segments are cached. **Incremental
slices are supported.** An archive holding **two or more partitions is presented
as the whole source disk**, with each partition at its own offset, so the
partition map and filesystem drivers see the layout the disk really had — for a
GPT source disk the partition table is rebuilt, since the archive only keeps the
protective MBR.

**Not supported (`.tib` sector mode):** True Image 2014–2016 archives, which
spread the chunk map through the block stream as inline records; encrypted
archives; multi-volume archives.

#### DiskGenius — `pmf`, `pmfx`

> Origin: FsRover

All modes share one container: a `VIMG` (partition) or `PMFX` (whole disk)
header, with the backup mode stored as a `u32`. Blocks are deflated, stored
verbatim, or written with the DiskGenius LZ77 codec.

**`.pmf`, sector modes — I/O filter `pmf`.** Presents the partition the image
holds. In *all sectors* mode the stored stream simply is the partition. In *used
sectors* mode it holds only the clusters the source filesystem had in use, in
ascending cluster order, so rebuilding the partition means knowing which those
were — and how the stream says so depends on the source filesystem:

| Source | How the used clusters are identified |
| --- | --- |
| FAT12/16/32 | a `u32` counts the sectors stored verbatim at the front (reserved area plus the first FAT); the FAT is the map, and the further FATs are not stored |
| exFAT | the same verbatim head, covering the boot region and the FAT, then a 13-byte record naming the length of the allocation bitmap that follows; the bitmap is the map |
| NTFS | no verbatim head and no leading count — the map comes from the volume's own metadata |

**`.pmf`, file mode — filesystem `pmf`.** What "backup all files" writes. How the
files are catalogued depends on the volume they came from, and both shapes are
read: a **FAT or exFAT** backup catalogues them by full path, with a deflated
catalog at `0x10400` followed by one 9-byte locator record per entry and then the
per-entry blobs; an **ext4** backup instead keeps the volume's own inodes, one
32-byte record each, with every blob being that inode exactly as ext4 wrote it
followed by the file's content — so the directory tree is whatever the directory
blocks in that content say, starting at inode 2. NTFS backups are read as well,
with the file content taken from the unnamed `$DATA` attribute, resident or not.

**`.pmfx` — I/O filter `pmfx`.** A whole-disk backup, presented as the disk it
holds. A block table at `0x1000` gives one 16-byte entry per block; an all-zero
entry means the block was never written, and reads back as zeros. **All three
backup modes** — all sectors, used sectors and files — are the same container and
are presented the same way, because the *files* mode is still a sector image:
DiskGenius lays the files it saved into a freshly built filesystem and stores the
result.

Volumes in a format this build does not special-case are passed through, so an
unrecognised `.pmf` simply shows up as an ordinary file.

#### Drive Snapshot — `sna`

> Origin: FsRover

A partition image, presented as the volume it holds. The container is a chain
of records — a 4-byte tag, a length, an adler32 and the payload — laid end to
end: a text header, the physical disk geometry with a copy of the MBR/GPT, the
volume record, then the data chunks, and at the very end the chunk index.

The backup is sector-level but filesystem-aware. The volume is cut into 64 KiB
chunks (with an extra cut at the start of the filesystem data area, so the data
area gets its own aligned grid), and only the chunks holding at least one
allocated cluster are stored; unused sectors *inside* a stored chunk are written
as zeros rather than skipped. Chunks are compressed one by one with one of four
encodings — stored, LZSS, Huffman, or Huffman over LZSS — and are **not** written
in volume order, so random access goes through the index. Both codecs are
written for this project from the format notes; there is no library involved.

**Split sets are supported.** The index only lives in the last file, so opening
`x.sna` opens `x.sn1`, `x.sn2` … alongside it, and its entries carry the volume
number in their top byte. **Differential images are supported**: the image names
its base image and the timestamp it was taken against, both of which are checked,
and it stores only the 4 KiB subblocks that changed — the rest comes from the
base, which may itself be differential.

The text header, the volume record, the index and every chunk are checksum
verified, so a damaged image reports an error instead of handing back quietly
wrong bytes. Regions the backup never covered, and the
tail of a volume past the last index entry, read back as zeros — that is what the
format means, not an error, and it is why a restored volume is not byte-identical
to the source in its free space.

**Not supported:** encrypted images. The disk geometry record, and the copy of
the MBR/GPT it carries, are skipped: what you browse is the one volume the image
holds, not the disk it came from, so a backup set covering several partitions
shows up as one image per partition.

---

## 3. Disk filters (RAID / LVM)

Disk filters assemble several member disks, or several partitions, into one
logical device, which then appears in the tree as its own entry with the member
devices listed in its properties.

| Driver | Format |
| --- | --- |
| `lvm` | Linux LVM2 logical volumes |
| `ldm` | Windows Logical Disk Manager (dynamic disks) |
| `mdraid09`, `mdraid09_be` | Linux md RAID, superblock format 0.90 (little- and big-endian) |
| `mdraid1x` | Linux md RAID, superblock formats 1.0 / 1.1 / 1.2 |
| `dmraid_nv` | NVIDIA MediaShield (dmraid) fake RAID |
| `raid5rec` | RAID 5 reconstruction from parity |
| `raid6rec` | RAID 6 reconstruction from parity |
| `diskfilter` | The framework itself (always listed) |

**Array levels:** linear, RAID 0, RAID 1, RAID 4, RAID 5, RAID 6, RAID 10. With
`raid5rec` / `raid6rec` present, a degraded RAID 5 or RAID 6 array stays readable
as long as enough members are visible.

**LVM segment types:** linear, striped, mirror, and `raid1` / `raid4` / `raid5` /
`raid6`. Thin provisioning, cache volumes and snapshots are not assembled.

All members must be visible to FsRover at the same time. Physical disks are only
enumerated when the program runs elevated, so assembling an array that spans
physical drives requires **File ▸ Run as Administrator**.

---

## 4. Encrypted volumes

When FsRover recognises an encrypted volume it shows it with a padlock icon and
asks for the passphrase, or a key file, the first time you browse it. A successful unlock creates a `cryptoN` device in the tree, whose
plaintext filesystem is then browsed like any other.

**Two formats cannot be recognised at all**, so they never get a padlock and are
opened from the tree's right-click menu instead:
[VeraCrypt / TrueCrypt](#veracrypt--truecrypt--veracrypt), where everything past
the salt is ciphertext, and [plain dm-crypt](#plain-dm-crypt--plainmount), which
has no header whatsoever. Both take their parameters from a dialog, and neither
can tell a wrong parameter from a wrong passphrase.

### LUKS1 — `luks`

> Origin: GRUB

**Ciphers:** AES-128/192/256, Serpent-128/192/256, Twofish-128/256,
Camellia-128/192/256, CAST5, Blowfish, DES and 3DES.
**Hashes:** SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (including the SHA-512/224
and SHA-512/256 truncations), RIPEMD-160, Whirlpool, Streebog-256/512, MD5.
**Key derivation:** PBKDF2.

A key file up to 8 MiB may be used instead of a passphrase.

**Modes.** XTS and LRW need a 16-byte block, so they are available for AES,
Serpent, Twofish and Camellia only; the 8-byte-block ciphers — CAST5, Blowfish,
DES, 3DES — can be used in CBC and ECB. In XTS the LUKS key is split in half, so
`--key-size` there is twice the cipher's key size.

### LUKS2 — `luks2`

> Origin: GRUB

**Ciphers and hashes:** the same set as LUKS1 above, including the note on
modes.

**Key derivation:** PBKDF2, Argon2i, Argon2id.

The JSON metadata area and its base64 fields are parsed in full.

### BitLocker — `bitlocker`

> Origin: FsRover

Ported from dislocker, rewritten against the AES and SHA-256 primitives already
in the build.

**Unlocks with:** the user password, or the 48-digit recovery password. The
intermediate key is derived by SHA-256 stretching, then the VMK and the FVEK are
unwrapped with AES-CCM.

**Sector decryption:** AES-XTS-128/256 and AES-CBC-128/256, including the
Elephant diffuser.

Boot-sector relocation, zeroed in-place metadata regions and partially converted
(still unencrypted) areas are handled, as is the BitLocker To Go / exFAT layout.

**Not supported:** Vista-era and EOW volumes — Windows 7 and later only.

### VeraCrypt / TrueCrypt — `veracrypt`

> Origin: FsRover

**Not auto-detected.** Everything past a VeraCrypt volume's 64-byte salt is
ciphertext, with no magic and no plaintext structure to probe for, so the volume
is indistinguishable from unused space until a passphrase has actually decrypted
its header.

**Ciphers:** AES, Serpent, Twofish, Camellia, Kuznyechik, and the ten cascades
of two or three of them (AES-Twofish, AES-Twofish-Serpent, Serpent-AES,
Twofish-Serpent, Kuznyechik-Serpent-Camellia, …). All are 256-bit keys in XTS
mode, which is the only mode VeraCrypt has ever written. A cascade is not a
chained block cipher: each layer is a complete XTS pass with its own key pair.

**Hashes (PRF):** SHA-512, SHA-256, Whirlpool, RIPEMD-160, Streebog.

**Key derivation:** PBKDF2, with VeraCrypt's own iteration counts — 500 000 for
most hashes, 655 331 for RIPEMD-160 — or `15000 + PIM × 1000` when a PIM is
given. Leaving the hash set to **Try all** works, but that is up to five
derivations of half a million iterations each and takes tens of seconds; naming
the right hash is several times faster.

**PIM.** The Personal Iterations Multiplier is not stored anywhere in the
volume, so it has to be entered exactly as it was at creation. Leave the box
empty for volumes made without one.

**Key files:** any number of them. They are folded into the passphrase with
VeraCrypt's CRC-32 pool algorithm — over the first megabyte of each file — before
the key is derived, so the result is the same 64- or 128-byte pool VeraCrypt
itself would build.

**Volume layouts:** normal volumes, hidden volumes, the backup headers in the
last 128 KiB of the host, and the legacy 512-byte header written before
VeraCrypt 1.0b.

**TrueCrypt mode** reads TrueCrypt 6.0 – 7.1a volumes: the `TRUE` magic,
TrueCrypt's much lower iteration counts, and no PIM. Only SHA-512, Whirlpool and
RIPEMD-160 are tried, as TrueCrypt never had the others. Volumes older than
TrueCrypt 6.0 used LRW or CBC mode and cannot be read — VeraCrypt itself dropped
support for them.

**Not supported:** system-encrypted partitions, whose header lives outside the
partition on sector 62 of the whole drive; and GOST89 volumes, which VeraCrypt
has been unable to mount itself since 1.19.

### Plain dm-crypt — `plainmount`

> Origin: GRUB

What `cryptsetup plainOpen` maps: a volume with **no header at all**. Every
parameter — cipher, mode, IV generator, key size, sector size, where the data
starts, how the passphrase becomes the key — lives outside the volume and has to
be supplied. Nothing in the container identifies any of it and nothing can be
checked, so a wrong parameter is not reported as a wrong passphrase: the volume
maps and decrypts to plausible garbage, which normally surfaces as *unknown
filesystem*.

**Cipher.** cryptsetup's `-c` specification, `cipher-mode-iv` —
`aes-xts-plain64`, `aes-cbc-essiv:sha256`, `serpent-xts-plain64`, and so on. The
box lists the common ones but stays editable, because the three parts combine
freely and no fixed list covers them.

| Part | Accepted |
| --- | --- |
| cipher | `aes` — with 128-, 192- or 256-bit keys; `serpent`, `twofish`, `camellia`, `kuznyechik` — 256-bit keys only |
| mode | `xts`, `cbc`, `pcbc`, `lrw`, and `ecb`, which takes no IV part |
| IV | `plain64`, `plain`, `benbi`, `null`, `essiv:HASH` |

**Hash.** How the passphrase becomes the key, cryptsetup's `-h`: `ripemd160` —
cryptsetup's own default — `sha1`, `sha256`, `sha512`, `whirlpool`,
`stribog512`, or **none**. Block *r* of the key is `hash('A' × r ‖ passphrase)`,
and the blocks are concatenated until the key is full; **none** uses the
passphrase itself, zero-padded or truncated to the key size.

**Key size** is the volume key in bits and must be a multiple of 8. XTS splits
the key in half, so 512 bits there is AES-256. **Sector size** is what the mapped
device reports — 512, unless the volume was made with `--sector-size`.

**Offset and IV** are cryptsetup's `--offset` and `--skip`, both counted in
**512-byte sectors** whatever the sector size, and independent of each other.
*Offset* is where the encrypted data starts, so the byte at that offset is what
the mapped device shows at 0; it has to be a whole number of mapped sectors. *IV*
is the sector number the IV counts from. Leave both empty for a volume made
without them — and note that getting either wrong looks exactly like a wrong
passphrase.

**Key file.** Ticking *Use a key file instead* makes the file's bytes the volume
key directly, with no hashing, which is what cryptsetup does for a key file as
opposed to a passphrase. Exactly *key size* bytes are read, starting at *File
offset* — in bytes, cryptsetup's `--keyfile-offset` — so the file must be at
least that long.

### FreeBSD GELI — `geli`

> Origin: GRUB

**Ciphers:** every algorithm id GELI defines that has a name in GRUB's table —
DES (`0x01`), 3DES (`0x02`), Blowfish (`0x03`), CAST5 (`0x04`), AES (`0x0b`) and
Camellia-128 (`0x15`) in CBC, and AES (`0x16`) in XTS.
**Hashes:** SHA-256, SHA-512.
**Key derivation:** PBKDF2, plus the v5+ rekey scheme.

Metadata versions 1–7 are read. The metadata lives in the volume's **last**
sector, and the UUID is not stored but derived —
`hex(HMAC-SHA256(salt, "uuid"))`.

**Not supported:** Skipjack (`0x05`) and the null cipher (`0x10`), which GRUB's
algorithm table leaves unnamed.

---

## 5. Dokan

**Mount to drive letter** hands a browsed volume to the Dokan user-mode
filesystem driver, so it shows up as an ordinary Windows drive that any program
can read.

### Version

| | |
| --- | --- |
| Bundled runtime | **Dokany 2.3.1.1000** |
| API version requested | `DOKAN_VERSION` 231 |
| Minimum compatible driver | 200 — any installed Dokany **2.x** driver works |
| Bundled architectures | x64, x86, ARM64 — matching the FsRover build |

FsRover loads `dokan2.dll` dynamically. If a Dokany 2.x runtime is already
installed on the system, that one is used. If none is installed, the **Dokan**
menu offers **Install Dokan**, which writes the bundled runtime into `System32`,
then creates and starts the `Dokan2` service.

### Requirements

- **Administrator rights.** Without an elevated token FsRover does not even load
  `dokan2.dll`; the **Dokan** menu shows *"Using Dokan requires administrator
  rights"* and **Mount to drive letter** is greyed out. Use
  **File ▸ Run as Administrator** to restart elevated. Physical disks are
  likewise only enumerated when elevated.
- **A 64-bit build on 64-bit Windows.** The 32-bit FsRover running under WoW64
  cannot install Dokan — writes to `System32` would be redirected to `SysWOW64`,
  and an x86 driver cannot be loaded by a 64-bit kernel.
- **Windows version.** Dokany 2.x supports the Windows releases its driver is
  built for — Windows 7 SP1 and later, including Windows 10, Windows 11 and the
  corresponding Server editions. If the bundled driver refuses to start on your
  system, install a Dokany release that matches it and FsRover will use it.

### Behaviour of a mounted volume

- **Read-only, enforced by the driver.** The mount is created with
  `DOKAN_OPTION_WRITE_PROTECT` and every write-side callback is left null, so
  Windows reports `FILE_READ_ONLY_VOLUME` and refuses write opens itself.
- The volume reports **case-sensitive search**, **case-preserved names** and
  **Unicode on disk**, with a maximum path component length of 255.
- The Windows volume label is the grub device name (`hd0,gpt2`, `loop0`, …) and
  the filesystem name is the driver name (`ntfs`, `squash4`, …).
- Free space is reported as **0** — the volume is full by definition.

### Mounting and unmounting

- **Mount to drive letter** opens a dialog where you pick a free letter
  (**D:–Z:**, highest free letter preselected) and optionally tick *Open in
  Explorer after mounting*. That choice is remembered for the session.
- Mounted drives are listed under the **Dokan** menu and in the tray icon's
  context menu; either one unmounts a single drive.
- Closing FsRover while drives are still mounted prompts to unmount them all.
  The tray icon keeps FsRover running, and the mounts alive, when the window is
  minimised.
- Every Dokan callback is serviced by the single grub backend thread, so a
  mounted volume stays responsive while you browse in the GUI — but a long
  extraction and heavy I/O on a mounted drive share that thread.

---

## 6. S.M.A.R.T.

**View S.M.A.R.T.** on a physical disk (`hd0`, `hd1`, …) in the tree opens the
drive's own health report: status and temperature, identity and transfer mode,
the counters the drive keeps, and every S.M.A.R.T. attribute it exposes with the
values behind it. **Refresh** re-reads the drive; **HEX** shows raw values in
hexadecimal.

### Requirements

- **libcdi**, a DLL build of
  [CrystalDiskInfo](https://github.com/hiyohiyo/CrystalDiskInfo), next to
  `FsRover.exe`: `libcdi.dll` (x64), `libcdix86.dll` (x86) or `libcdiaa64.dll`
  (ARM64). Download it from [NWinfo Releases](https://github.com/a1ive/nwinfo/releases).
- **Administrator rights**, as for any raw drive access.

### Notes

- The first view scans every drive in the machine and takes a few seconds; the
  result is kept for the rest of the session, so later views and other drives
  open immediately.
- ATA, SATA, NVMe and many USB bridges are read, along with Intel VROC, LSI
  MegaRAID and CSMI RAID members. What each attribute means is the vendor's
  business.

---

## 7. Keyboard shortcuts

| Key | Action |
| --- | --- |
| <kbd>Alt</kbd>+<kbd>←</kbd> | Back |
| <kbd>Alt</kbd>+<kbd>→</kbd> | Forward |
| <kbd>Alt</kbd>+<kbd>↑</kbd> | Up one level |
| <kbd>Ctrl</kbd>+<kbd>A</kbd> | Select all |
| <kbd>Enter</kbd> | Go to the path typed in the address bar |

These are the navigation bindings Explorer uses. The same list is available in
the program under **Help ▸ Keyboard Shortcuts**.

While the address bar has focus it keeps its own editing keys — including
<kbd>Ctrl</kbd>+<kbd>A</kbd>, which selects the text rather than the file list.
Standard Windows conventions apply everywhere else: <kbd>F10</kbd> or
<kbd>Alt</kbd> opens the menu bar, the mnemonics shown in the menus
(<kbd>Alt</kbd>+<kbd>F</kbd> for **File**, and so on) work as usual, the
context-menu key opens the right-click menu for the current selection, and
<kbd>Esc</kbd> closes the viewer and property dialogs.

---

## 8. Command line

```
FsRover.exe [options]
```

| Option | Argument | Effect |
| --- | --- | --- |
| `-m`, `--minimize` | — | Start minimized to the notification area. The main window is never shown, so no taskbar button appears and disappears. |
| `-f`, `--file=FILE` | path | Mount `FILE` as a virtual disk at startup. |
| `-d`, `--file-dec=FILE` | path | The same, but run the compression filters over the image first (a `.img.gz`, `.iso.xz`, …). |
| `-h`, `--help` | — | Show the usage box and exit. |

### Syntax

- Long options accept both `--file=PATH` and `--file PATH`; short options accept
  both `-fPATH` and `-f PATH`.
- `-f` and `-d` may be repeated and mixed; every image is mounted in the order
  given, with decompression applied only to the corresponding `-d` argument.
- Option names are matched **case-insensitively**, and the Windows-style
  `/file=PATH` / `/m` spelling is accepted alongside `--file=PATH` / `-m`.
- `--` ends option parsing.

### Notes

- `FILE` is resolved against the current directory at startup, so relative paths
  work and the fully-qualified path is what the disk properties show.
- **`-f` and `-d` suppress physical disk enumeration entirely.** Browsing a file
  of your own needs no privileges, and physical drives are the only thing that
  does, so a session started this way never touches `\\.\PhysicalDrive*` — you
  see only the image you asked for, plus the `(proc)` pseudo-device.
- Anything the [I/O filters](#2-io-filters) or the archive and filesystem drivers
  recognise can be given to `-f`: a raw image, a VHD / VHDX / VDI / QCOW / VMDK /
  DMG container, a backup archive, or a plain `.zip` / `.tar` / `.7z` / `.rpm`.
- `-d` differs from `-f` only in that the *outer* stream is decompressed first.
  It is the command-line equivalent of **File ▸ Open Image (decompress)…** and of
  the **Mount as disk (decompress)** context-menu item.

### Examples

```bat
FsRover.exe --file "D:\images\rootfs.img"
FsRover.exe -d D:\images\sdcard.img.xz
FsRover.exe -f C:\downloads\package.rpm
FsRover.exe --minimize
```
