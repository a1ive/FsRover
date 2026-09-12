# Product regression tests

These tests generate their own ZIP, TAR, FAT12 and ext2 images and run the actual
CLI and shared extraction core. Python 3.10+ and the standard library are
sufficient; no image downloads, mounts, administrator privileges or third-party
Python packages are required. All images, extracted files and logs stay in
build/run directories. No binary fixtures or encoded image dumps belong in Git.

**Known failure:** noncontiguous TAR directory entries currently produce duplicate
directories through `archelp`. The suite reports this as one explicit `XFAIL`,
separate from passing tests. It tolerates only the exact known duplicate listing
and extracted tree; other errors fail. When the driver is fixed, remove the
exemption and assert the correct tree. This is not a claim that all TAR layouts
pass. The normal TAR case uses contiguous directory entries and children.

## Run on Windows

From the repository root, after restoring the normal solution packages:

```powershell
$msbuild = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe'
& $msbuild Rover.slnx /m /p:Configuration=Release /p:Platform=x64
& $msbuild tests/product_probe.vcxproj /m /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$((Get-Location).Path)\"
python tests/run_product.py --cli build/x64/CliRover.exe --probe build/x64/product_probe.exe --output build/product-tests
```

The probe is a separate test project, not a release executable. It links the
product's `grub.lib` and compiles the actual `common/extract_core.cpp`; it does not
mock Rover or duplicate the extraction implementation. x86 uses `Win32` for the
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

## Coverage and results

| Area | Checks |
| --- | --- |
| Product path | ZIP/TAR/FAT12/ext2 root and child listings, directory extraction, exact file/directory inventory, sizes, SHA-256, empty files/directories, ext2 Unicode names |
| Destination protection | Existing files/directories/symlinks, repeated sources, file-versus-directory collisions, existing directories reserving file names, Windows case/invalid/reserved names, Unicode filenames |
| Failure recovery | Broken FAT chain followed by a valid file in one extraction: exit 1, diagnostic, success/error counters, failed output removal; truncated image; POSIX `RLIMIT_FSIZE` write failure with a later source still extracted |
| Timestamps and links | File and directory mtimes, `--no-times`, skipped TAR and ext2 symlinks |
| Loopback | `-p/--loop` and `--loop-dec` over files inside TAR images, nested loop levels, gzip decompression, corrupt gzip, option order and independent imgN/loopN counters |
| CLI errors | Help, invalid argument exit 2, unknown filesystem, missing path, output path that is an existing file |
| Same-process state | Three rounds of failed probe/open/read followed by correct directory enumeration and file content/EOF, without reinitialization |
| Cancellation | Request cancellation after at least 1 MiB is actually written; remove unfinished file, skip subsequent source, preserve completed/existing files and counters; successfully extract again in the same process; on POSIX, a real SIGINT during a CLI extraction removes the partial file and leaves completed files intact |
| Read-only source | SHA-256 of every generated source image unchanged after the suite |

The runner creates a unique `run-*` subdirectory, prints its location and never
deletes previous runs. `results.json` contains statuses, fixture hashes, commands,
exit codes, stdout/stderr and durations. Any unexpected failure returns nonzero;
checks also remain active under `python -O`. Each child command has a 60-second
timeout; the CTest entry has a 300-second timeout.

Windows x64 and Linux x64 CI run the suite, and upload run directories on failure.
The normal Windows x86/ARM64 build matrix remains separate from runtime coverage.
POSIX runs additionally send a real SIGINT through LinuxRover's signal handlers; on
Windows, cancellation is covered through the cooperative core at a deterministic
checkpoint between driver calls. Platform-only checks report `SKIP` when the host
cannot create symlinks or lacks POSIX resource limits. The suite does not exercise
GUI cancellation, live FUSE/WinFsp/Dokan mounts, real vendor media, other FAT
variants or exhaustive malformed input handling.
