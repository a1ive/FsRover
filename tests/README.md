# Product regression tests

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
the generated ext2 and FAT12 images: cached getattr/readdir/open results must
match an uncached `rover_stat` walk (symlink components, missing and non-directory
parents, case variants), repeated and listing-seeded lookups must not reach the
backend dispatcher, the LRU bound evicts oldest first, and concurrent lookups,
listings and invalidations stay consistent. It does not mount anything. x86 uses `Win32` for the
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
