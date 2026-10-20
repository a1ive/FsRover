# Product regression tests

## FBFS and APFS regressions

`fs_boundaries.py` runs 15 synthetic FBFS checks through the CLI: versions 1.6/1.7,
short names, records crossing a 510-byte sector payload, a terminator in the last
valid byte, zero list sectors, truncated records, missing terminators and missing
filename NUL bytes. Extraction checks compare SHA-256 hashes. Use a fresh output
directory:

```sh
python tests/fs_boundaries.py --cli build/x64/CliRover.exe --output build/fs-boundaries-x64
```

Substitute `build/Win32/CliRover.exe` or `build/linux/LinuxRover` for other hosts.
The optional `--media DIR` adds existing `1.607.fba`, `1.701.fba`,
`rover-apfs-gpt.img`, `rover-apfs-udrw.dmg` and `rover-apfs-lzfse.dmg` samples.
Their names refer to the local regression collection; the script does not download
or generate them. FBA extraction is checked against a separate Python reader of
the archive records and payload offsets. APFS README content is checked against
the sample's SHA-256 manifest. All input images are hashed before and after use.

For an independent APFS comparison, extract `rover-apfs-gpt.img` with 7-Zip,
excluding `documents/nested/readme-symlink.txt`, and pass that directory with
`--oracle DIR` alongside `--media`. The CLI skips symlinks when extracting trees.
The comparison checks the ten other regular files against 7-Zip.
`sparse-16m.bin` is checked separately against the image manifest: 7-Zip 26.00
produces a different hash for that file. These existing APFS images provide basic
filesystem and DMG regression coverage; they do not establish coverage of every
decmpfs compression type.

Two C probes include the actual driver sources. `fbfs_list_probe.c` checks 50
exact-size list buffers, record types and rewind behavior. `apfs_compression_probe.c`
checks 101 cases covering stored-block markers and lengths, all 16 accepted zlib
escape bytes, LZFSE `bvx-`/`bvxn` streams, malformed headers, and multi-block PLAIN
and zlib resource forks with a partial last block and truncated input. The last
case reads A, partially overwrites its cache while decoding a short B,
then reads A again. It also checks progress/custom-hook separation for decoded
data. Resource forks are synthetic embedded buffers; the probe does not mount
APFS or exercise
stream-backed xattr lookup.

After building the Linux library, run from the repository root (tested with GCC 13):

```sh
gcc-13 -std=gnu2x -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
  -ffunction-sections -fdata-sections -include grub/rover/config.h \
  -Igrub/include -Igrub/rover tests/fbfs_list_probe.c \
  build/linux/librover-grub.a -Wl,--gc-sections -o build/linux/fbfs_list_probe
build/linux/fbfs_list_probe
gcc-13 -std=gnu2x -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
  -ffunction-sections -fdata-sections -include grub/rover/config.h \
  -Igrub/include -Igrub/rover -Igrub/grub-core/lib/lzfse \
  -Igrub/grub-core/lib/libzbitmap tests/apfs_compression_probe.c \
  grub/grub-core/lib/lzfse/lzfse_decode.c \
  grub/grub-core/lib/lzfse/lzfse_decode_base.c \
  grub/grub-core/lib/lzfse/lzfse_fse.c \
  grub/grub-core/lib/lzfse/lzvn_decode_base.c \
  grub/grub-core/lib/libzbitmap/libzbitmap.c \
  build/linux/librover-grub.a -Wl,--gc-sections -o build/linux/apfs_compression_probe
build/linux/apfs_compression_probe
```

The included driver sources and the listed compression decoders use sanitizers;
the remaining linked library keeps its normal Release flags.

## APFS and ReFS review regressions

`fs_review.py` builds synthetic APFS containers with colliding suffixes, empty
and dot names, 255-byte names, and 100 volumes. The CLI lists their volume names
and opens generated paths. The optional image collection has `extra/` and `vhd/`
subdirectories containing the existing APFS and ReFS samples named in the script.

```powershell
python tests/fs_review.py --cli build/x64/CliRover.exe --probe build/x64/product_probe.exe --output build/fs-review-x64 --media F:/image --apfs-oracle build/fs-boundaries-20261018/apfs-oracle
```

Use a fresh output directory. Omit `--media`, `--probe`, and `--apfs-oracle` to
run the synthetic volume-name cases alone. Substitute the Win32 or Linux
executables to test those builds. Build `product_probe` with the commands below.

Media checks compare APFS extraction with the supplied independent extraction
(except the sparse file, checked against its recorded manifest hash), compare
32 files between the LZ4/Zstd ReFS images, and verify 12 ReFS 1.2 files against
the image's SHA-256 manifest. Source image hashes are checked before and after.
The LZ4/Zstd filenames describe the sample collection: the selected checkpoint
can map the tested files as ordinary extents, so those results alone do not
establish compressed-container read coverage.

`product_probe --file-hooks IMAGE PATH RAW_BYTES` compares normal, progress-hook,
and custom-hook reads of the same file. It checks byte equality, complete logical
progress, custom-hook byte counts, and disk-hook cleanup. `RAW_BYTES` excludes
holes, resident data, and decoded compressed data. The optional script checks
seven existing APFS/ReFS files with known raw-byte counts.

`refs_review_probe.c` includes the driver and substitutes in-memory disk reads
and selected allocation failures. Its 41 cases cover checkpoint ordering and
fallback for synthetic 1.2/3.11/3.12/3.14 layouts, OOM during checkpoint probing,
reload, root reading and root-buffer allocation, failed LZ4 cache reloads,
compressed progress/custom hooks, and raw-read hook cleanup on I/O failure.
It does not validate a complete ReFS filesystem or all allocation-failure paths.

```sh
gcc-13 -std=gnu2x -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
  -ffunction-sections -fdata-sections -include grub/rover/config.h \
  -Igrub/include -Igrub/rover -Igrub/grub-core/lib/lz4 \
  -Igrub/grub-core/lib/zstd tests/refs_review_probe.c \
  build/linux/librover-grub.a -Wl,--gc-sections -o build/linux/refs_review_probe
build/linux/refs_review_probe
```

The included driver uses sanitizers; the linked library keeps its build flags.

## GRUB synchronization regressions

`upstream_sync.py` exercises TAR (USTAR, GNU, PAX, v7 and base-256), CPIO,
ext2 symlinks, GPT entry strides, and striped/cached LVM volumes through the CLI.
Malformed cases include oversized archive names, metadata-only archives, link
loops, the CPIO end-marker collision, invalid GPT strides, and truncated LVM
metadata before and after an ignored-feature LV has been allocated. Images are
generated from Python data structures. Use a fresh output directory for each run:

```sh
python tests/upstream_sync.py --generate --fixtures build/sync-fixtures
python tests/upstream_sync.py --cli build/x64/CliRover.exe --fixtures build/sync-fixtures --output build/sync-x64
```

On Linux, add images made by `mkfs.ext4`, `mkfs.btrfs`, `mksquashfs` and `zstd`:

```sh
python3 tests/upstream_sync.py --generate-media --fixtures build/sync-fixtures
python3 tests/upstream_sync.py --cli build/linux/LinuxRover --fixtures build/sync-fixtures --output build/sync-linux
```

These images cover directory listings, extraction, directory symlinks, gzip/LZO/
XZ/Zstandard SquashFS metadata, and multi-buffer Zstandard stream decompression.
Extracted bytes are compared with the input payloads; all tested images are
hashed before and after the run. They are generated images, not physical-media
tests. CLI extraction skips a final symlink, so link-resolution cases put the
link in a leading path component.

Two optional Linux probes compile the actual driver sources with ASan/UBSan.
The LVM probe replaces disk I/O with a bounded image buffer and tracks parser
allocations. It fails each allocation in turn, checking for leaks and duplicate
frees, including copies of cached-volume node names. Its VG registration stub
does not exercise diskfilter registration; the CLI cases cover that path.
The core probe checks LUKS2 indices 0/31/32/63/64/255, a malformed keyslot,
zero/one AF stripes, and dates in 1900/1970/2038/2100. It does not unlock a LUKS
volume. Build the normal Linux library first, then run from the repository root:

```sh
cc -std=gnu2x -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
  -ffunction-sections -fdata-sections -include grub/rover/config.h \
  -Igrub/include -Igrub/rover tests/lvm_alloc_probe.c \
  build/linux/librover-grub.a -Wl,--gc-sections -o build/linux/lvm_alloc_probe
build/linux/lvm_alloc_probe build/sync-fixtures/lvm.img 1
build/linux/lvm_alloc_probe build/sync-fixtures/lvm-truncated.img 0
build/linux/lvm_alloc_probe build/sync-fixtures/lvm-late-truncated.img 0
cc -std=gnu2x -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
  -ffunction-sections -fdata-sections -include grub/rover/config.h \
  -Igrub/include -Igrub/rover -Igrub/grub-core/lib -Igrub/grub-core/lib/json \
  tests/upstream_core_probe.c build/linux/librover-grub.a \
  -Wl,--gc-sections -o build/linux/upstream_core_probe
build/linux/upstream_core_probe
```

The probes instrument their included driver sources. The linked library keeps
its normal build flags. When running the full product suite under WSL, put its
output on the Linux filesystem: the multi-TiB sparse FAT fixtures can exceed
the sparse-file limits of `/mnt/c`.

## General product suite

These tests generate their own ZIP, TAR, FAT12 and ext2 images and run the actual
CLI, shared extraction core and metadata mapping APIs. Python 3.10+ and the standard library are
sufficient; no image downloads, mounts, administrator privileges or third-party
Python packages are required. All images, extracted files and logs stay in
build/run directories. No binary fixtures or encoded image dumps belong in Git.

TAR regressions cover contiguous and noncontiguous explicit directory entries,
plus interleaved children with implicit directories at multiple depths. Each case
requires unique directory listings and the exact extracted tree with SHA-256
checks; duplicate directories fail the suite.

## Run on Windows

The optional NSIS BZip2 regression requires `makensis` only when generating
fixtures. It covers solid/non-solid multi-block payloads, empty files, malformed
and truncated streams, plus standard bzip2 extraction and block-CRC rejection:

```sh
python tests/nsis_bzip2.py --generate build/nsis-bzip2
python tests/nsis_bzip2.py --cli build/x64/CliRover.exe build/nsis-bzip2
```

Generation may run under WSL; pass the same fixture directory to Windows Python.

The optional lost partition regression needs `mkfs.vfat`, `mkntfs`, `ntfscp`,
`mkfs.exfat`, `mkfs.ext4`, mtools, `mkfs.xfs`, `mkfs.btrfs`, hfsutils,
`mkfs.hfsplus`, `mkfs.f2fs`/`sload.f2fs`, `mksquashfs`, `sgdisk`, `sfdisk`,
`makefs`, `mkfs.jfs`, `mkreiserfs`, `mkudffs` and `genisoimage` only when
generating fixtures. It writes MBR and CHS layouts with an intact,
wiped or partially deleted table; NTFS, FAT32, exFAT, ext4, XFS, Btrfs, HFS,
HFS+ and F2FS volumes with their primary boot sector or superblock removed;
GPT disks without protective MBR, with only the backup GPT, or with a stale
backup GPT; an MBR whose extended boot record chain is cut; and a stale FAT32
boot sector whose claimed range covers partitions created after it. UFS1/UFS2, JFS
(also through its secondary superblock), ReiserFS, ISO9660, UDF and an
ISO9660/UDF bridge are covered, and `--scan-deep` runs over several of the
images plus one whose volumes sit at odd sector offsets only it finds. It checks the
`--scan-lost` results (type, flags, label), extracts the payload through
`--lost` windows with SHA-256 checks -- volumes found through a backup through
their remapped windows -- and covers truncated volumes and window and remap
argument errors. HFS+/HFSX and exFAT volumes are empty (no userland copy tool):

```sh
python3 tests/lostpart.py --generate build/lostpart
python tests/lostpart.py --cli build/x64/CliRover.exe build/lostpart
```
For Linux validation, substitute the built `LinuxRover` path.

From the repository root, after restoring the normal solution packages:

```powershell
$msbuild = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe'
& $msbuild Rover.slnx /m /p:Configuration=Release /p:Platform=x64
& $msbuild tests/product_probe.vcxproj /m /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$((Get-Location).Path)\"
python tests/run_product.py --cli build/x64/CliRover.exe --probe build/x64/product_probe.exe --output build/product-tests
```

The probe is a separate test project, not a release executable. It links the
product's `grub.lib` and compiles the actual `common/extract_core.cpp`; it does not
mock Rover or duplicate the extraction implementation. Its C mapping companion,
`filemap_probe.c`, compiles with the GRUB headers/configuration separately from
the C++ frontend and calls the actual `grub_file_map_range` and read APIs.
`--fusefs FIXTURES` drives the shared mount core (`common/fusefs.cpp`) directly on
the generated ext2 (`basic.ext2`, `links.ext2`) and FAT12 images, in both link
modes (native `S_IFLNK` + readlink, and follow). Cached getattr/readdir/open/readlink
results must match an uncached POSIX walk over `rover_stat`/`rover_readlink`
(links in leading components, chains, absolute, dangling and looping links, `.`
and `..`, missing and non-directory parents, case variants). Follow-mode listings
must leave out dangling links, loops and directory links back onto their own path.
Repeated and listing-seeded lookups must not reach the
backend dispatcher, the LRU bound (a small per-mount limit, since every insert is a
real lookup) evicts oldest first, and concurrent lookups,
listings and invalidations stay consistent. It does not mount anything. `--readlink FIXTURES`
checks `rover_readlink` on the ext2 image and on `dirlinks.tar` (relative, absolute and
directory links, one used as a leading component): exact targets, truncation and
length-only queries, EINVAL/ENOENT/ENOTSUP, and reads through directory links. x86 uses `Win32` for the
probe project and `build/Win32/` for executable paths; ARM64 uses `ARM64` and
requires an appropriate runtime host to execute.

## Run on Linux

Install the normal Linux build dependencies and Python 3, then run:

```sh
cmake -S . -B build/linux -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build/linux --parallel
ctest --test-dir build/linux --verbose
```

`BUILD_TESTING=OFF` disables the probe, CTest entry and Python requirement. To
test an already built LinuxRover directly:

```sh
python3 tests/run_product.py --cli build/linux/LinuxRover --probe build/linux/product_probe --output build/product-tests
```

The printf probe also runs in the default suite. To run it alone, use
`product_probe --printf formats`, `--printf trailing`, `--printf null`, and
`--printf minimum`. Incomplete conversions stop at NUL without consuming
arguments; `grub_printf_fmt_check` rejects them. `%C` widths count emitted UTF-8
bytes, matching `%s` width units. Existing `n == 0` behavior is unchanged.
The probe also covers unsigned values above `LLONG_MAX`, native `size_t` type
classification for `%z`, mixed pointer/integer/double arguments, repeated
positions, and rejection of pointer/integer format substitutions. These runtime
checks establish output compatibility; correct `va_arg` types must also be
verified in source, since equal ABI argument slots can hide type mismatches.

The `product_probe --strtol` check also runs in the default suite. It compares
`grub_strtol` with libc for signed `long` limits, adjacent and out-of-range
magnitudes in bases 8/10/16, automatic prefixes, leading whitespace, end
pointers and a NULL end pointer. The C probe includes the real inline function;
compiling it with UBSan can detect signed negation overflow at `LONG_MIN` even
when an ordinary run happens to return the expected value.

The default suite also runs `fat_large.py`: 29 driver-focused FAT32/exFAT
sparse-image cases cover 512/1024/2048/4096-byte sectors, data/FAT/heap addresses
beyond 2 TiB, FAT entries beyond 4 GiB, active FAT selection, chained and
contiguous files, extraction hashes, cross-cluster seeks, exact blocklist
addresses and invalid geometry. Volumes whose tail lies past the device end
still mount (only a cluster heap starting outside it is rejected); when the
cut runs through a file, blocklist and reads both stop at the device end. FAT32
entries with reserved high bits are followed like the blocklist does, and an
exFAT read past the 2^32nd cluster fails instead of wrapping to cluster 0. These synthetic images leave unused allocation
metadata sparse and are not OS-formatted or real-media validation. Source
integrity checks sample every written metadata/payload range; they do not hash
multi-TiB holes. Images are removed after each case so CI artifacts stay bounded.
To run the matrix independently:

```sh
python tests/fat_large.py --cli build/x64/CliRover.exe --probe build/x64/product_probe.exe --output build/fat-large-tests
```

Use `--keep-images` only for local inspection; retained images have multi-TiB
logical lengths and must not be copied or uploaded with tools that expand holes.
Windows fixtures use native sparse-file and EOF operations; Linux uses sparse
truncation. Linux binaries can be passed to the same script. When changing
`fat.c` on Windows, rebuild the GRUB project if incremental compilation omits
`exfat.c`, which includes `fat.c`; relink the CLI and probe before testing.

## Coverage and results

| Area | Checks |
| --- | --- |
| GRUB printf | Native `grub_vsnprintf` and `grub_xvasprintf` versus libc for flags, integer precision, dynamic width/precision, and truncation; guarded-page incomplete formats, `LLONG_MIN`, positional arguments, `%z`, `%c` including NUL, UTF-8 `%C` byte widths, GUID/null output, format-validator type checks, and `%f`/`%e`/`%g` including `%.17g` round-trip |
| Product path | ZIP/TAR/FAT12/ext2 root and child listings, directory extraction, exact file/directory inventory, sizes, SHA-256, empty files/directories, ext2 Unicode names |
| Destination protection | Existing files/directories/symlinks, repeated sources, file-versus-directory collisions, existing directories reserving file names, Windows case/invalid/reserved names, Unicode filenames |
| Failure recovery | Broken FAT chain followed by a valid file in one extraction: exit 1, diagnostic, success/error counters, failed output removal; truncated image; POSIX `RLIMIT_FSIZE` write failure with a later source still extracted |
| Timestamps and links | File and directory mtimes, `--no-times`, skipped TAR and ext2 symlinks |
| Loopback | `-p/--loop` and `--loop-dec` over files inside TAR images, nested loop levels, gzip decompression, corrupt gzip, option order and independent imgN/loopN counters |
| CLI errors | Help, invalid argument exit 2, unknown filesystem, missing path, output path that is an existing file |
| Same-process state | Three rounds of failed probe/open/read followed by correct directory enumeration and file content/EOF, without reinitialization |
| Cancellation | Request cancellation after at least 1 MiB is actually written; remove unfinished file, skip subsequent source, preserve completed/existing files and counters; successfully extract again in the same process; on POSIX, a real SIGINT during a CLI extraction removes the partial file and leaves completed files intact |
| File mapping | Generated fragmented FAT12 and sparse ext2; short/long blocklist TSV parity, complete coverage, direct-address reconstruction, sparse bytes, empty files, range clipping/EOF/zero-length queries, callback stop, preserved cursor, disk-read counters and payload-read exclusion, read-after-map/stop, exact normal-read slices, CLI extraction parity, corrupt/truncated FAT chains and CLI argument errors |
| System V family | 23 generated Xenix/System V R2/R4/V7/Coherent/SCO AFS layouts; little/big/PDP byte order, 512/1024/2048-byte blocks where applicable, alternate superblocks, exact directory inventories, fragmented extraction and hashes, 14-byte names, hard links, file/directory symlink resolution, sparse reads, seeks across all indirect transitions, missing indirect subtrees, and 16 corrupt/unsupported images with diagnostics and failed-output cleanup |
| SCO EAFS/ES51K | 12 generated extended layouts (both byte orders, 512/1024/2048-byte blocks); 14/15/28/29/252/255-byte names, UTF-8 characters split across entries, nonadjacent directory blocks, deleted prefixes, long directory and symlink lookup, extraction hashes; 9 corrupt/unsupported images with errors and failed-output cleanup |
| Lenovo OKR | Both 810/811 headers and 172/176-byte records; independent stream reconstruction; stored/LZ4/alternate markers; single/multiple backed partitions; ignored unbacked descriptors; split payloads and nested split images; full virtual-view comparison with unaligned/random reads; partial final units, empty bitmaps, checksum groups, damaged metadata/data/trailers, failed-output cleanup, and same-open A/bad-B/A cache recovery. Generated fixtures only. |
| Xenix divisions | Five generated geometries (17/63 sectors per track, cylinder-number wrap, separate track rounding, zero spare tracks); automatic nested names and exact LBA/length via procfs, whole-division omission, empty/overlapping slots, stale bytes after slot 7, fragmented extraction hashes; 19 malformed/unsupported images rejected before exposing any child |
| Read-only source | SHA-256 of every generated source image unchanged after the suite |

The runner creates a unique `run-*` subdirectory, prints its location and never
deletes previous runs. `results.json` contains statuses, fixture hashes, commands,
exit codes, stdout/stderr and durations. Any unexpected failure returns nonzero;
checks also remain active under `python -O`. Each child command has a 60-second
timeout; the CTest entry has a 300-second timeout.

Windows x64, x86 and Linux x64 CI run the suite, and upload run directories
on failure. The Windows build job publishes CliRover and the probe for x64 and x86,
and a separate job runs the suite on each (x86 under WOW64). ARM64 is built,
including the probe, but its runtime is not covered.
POSIX runs additionally send a real SIGINT through LinuxRover's signal handlers; on
Windows, cancellation is covered through the cooperative core at a deterministic
checkpoint between driver calls. Platform-only checks report `SKIP` when the host
cannot create symlinks or lacks POSIX resource limits. The suite does not exercise
GUI cancellation, live FUSE/WinFsp/Dokan mounts, real vendor media, other FAT
variants or exhaustive malformed input handling.

## Optional mapping fixture matrix

The default product run generates mapping fixtures itself; no extra CI command is
needed. `filemap.py` also retains the larger external fixture matrix formerly run
by the standalone script. Supply its existing directory explicitly:

```powershell
python tests/run_product.py --cli build/x64/CliRover.exe --probe build/x64/product_probe.exe --output build/product-tests --filemap-fixtures C:/mapping-fixtures
```

This adds FAT12/16/32, exFAT (512/4096-byte sectors), ext2/ext4, NTFS and XFS
mapping cases and five corruption cases to the same results/command log. The
exact filenames are in `EXTERNAL_CASES` and `EXTERNAL_ERRORS` in `filemap.py`.
Missing fixtures fail the requested matrix; they are never silently skipped,
downloaded or modified. This optional matrix is not covered by default CI.

For a native range query, use the existing product probe (offsets/lengths in bytes):

```powershell
build/x64/product_probe.exe --filemap disk.img "(img0)/file.bin" 7 611 0 after-map.bin
build/x64/product_probe.exe --filemap disk.img "(img0)/file.bin" 0 4096 1 after-stop.bin
build/x64/product_probe.exe --filemap disk.img "(img0)/file.bin" read 7 611 slice.bin
```

The first two commands emit mapping records on stdout and read traces, counters,
errors and cursor/stop status on stderr. Their optional output file contains a
full normal read after mapping. The `read` form writes exactly the requested
slice. Use a fresh output path: these diagnostic outputs overwrite existing
files. Linux uses the same arguments with `build/linux/product_probe`.

The no-payload-read assertion uses generated data blocks placed outside the FAT
metadata cache window; cache prefetch is counted as host I/O, not assumed to be a
logical file-data read. Synthetic mapping coverage does not establish support
for every real-media layout or filesystem version.

Mapping bounds/cancellation regressions also exercise the real core with synthetic
metadata (`product_probe --filemap core`): disk, nested partition, translation
overflow, 4Kn, unknown capacity, FS logical addresses, compressed fragments,
metadata cancellation and cancellation during extent coalescing. Generated ext2
corruption must fail both blocklist and normal reading. `cancel:4` in the STOP
argument polls cancellation independently of extent output and checks both the
native and public Rover APIs, then verifies a normal read after cancellation.
