"""Sparse, driver-focused FAT32/exFAT address-width regressions.

Images have multi-TiB logical lengths but only bounded metadata/payload writes.
They are not OS-formatted media; unused allocation metadata is left sparse.
Never read_bytes(), copy, or hash these images in their entirety.
"""
import argparse
import hashlib
import json
import os
import pathlib
import struct
import tempfile

from filemap import read_rows, require


def sparse_file(path, length):
    stream = path.open("x+b")
    try:
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes
            ioctl = ctypes.WinDLL("kernel32", use_last_error=True).DeviceIoControl
            ioctl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                             ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
            ioctl.restype = wintypes.BOOL
            returned = wintypes.DWORD()
            handle = msvcrt.get_osfhandle(stream.fileno())
            if not ioctl(handle, 0x900C4,
                         None, 0, None, 0, ctypes.byref(returned), None):
                raise ctypes.WinError(ctypes.get_last_error())
            # CRT _chsize_s may write zeros across the hole; set EOF natively.
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            seek = kernel.SetFilePointerEx
            seek.argtypes = [wintypes.HANDLE, ctypes.c_longlong, wintypes.LPVOID, wintypes.DWORD]
            seek.restype = wintypes.BOOL
            eof = kernel.SetEndOfFile
            eof.argtypes = [wintypes.HANDLE]
            eof.restype = wintypes.BOOL
            if not seek(handle, length, None, 0) or not eof(handle):
                raise ctypes.WinError(ctypes.get_last_error())
            stream.seek(0)
        else:
            stream.truncate(length)
        return stream
    except BaseException:
        stream.close()
        raise


def exfat_entry(name, cluster, length, contiguous):
    entry = bytearray(96)
    entry[0:2] = b"\x85\x02"
    struct.pack_into("<H", entry, 4, 0x20)
    entry[32:34] = bytes((0xC0, 3 if contiguous else 1))
    entry[35] = len(name)
    name_hash = 0
    for value in name.upper().encode("utf-16le"):
        name_hash = ((name_hash >> 1) | (name_hash << 15)) + value
        name_hash &= 0xffff
    struct.pack_into("<H", entry, 36, name_hash)
    struct.pack_into("<Q", entry, 40, length)
    struct.pack_into("<I", entry, 52, cluster)
    struct.pack_into("<Q", entry, 56, length)
    entry[64] = 0xC1
    entry[66:66 + len(name) * 2] = name.encode("utf-16le")
    checksum = 0
    for i, value in enumerate(entry):
        if i not in (2, 3):
            checksum = (((checksum >> 1) | (checksum << 15)) + value) & 0xffff
    struct.pack_into("<H", entry, 2, checksum)
    return entry


def make_image(path, kind="exfat", bps=4096, where="small", corrupt=None):
    spc = 8 if where == "data" else 1
    count = 0x04000100 if where == "data" else 65536
    first = 0x04000003 if where == "data" else 8
    if where == "fat-entry":
        count, first = 0x40000010, 0x40000002
    fat_start = 0x20000010 if where == "fat-base" else 32
    fat_length = ((count + 2) * 4 + bps - 1) // bps
    num_fats = 2 if where == "fat-length" else 1
    if where == "fat-length":
        fat_length = 0x20000010
    heap = fat_start + num_fats * fat_length
    if where == "heap":
        heap = 0x20000010
        if kind == "fat32":
            fat_length = heap - fat_start
    total = heap + count * spc
    cluster_bytes = bps * spc
    boot = bytearray(bps)
    boot[:3] = b"\xeb\x76\x90"
    boot[510:512] = b"\x55\xaa"
    if kind == "exfat":
        boot[3:11] = b"EXFAT   "
        struct.pack_into("<Q", boot, 72, total)
        struct.pack_into("<IIIIII", boot, 80, fat_start, fat_length,
                         heap, count, 2, 0x12345678)
        struct.pack_into("<H", boot, 104, 0x100)
        boot[108:113] = bytes((bps.bit_length() - 1, spc.bit_length() - 1, 1, 0x80, 0))
    else:
        boot[3:11] = b"MSWIN4.1"
        struct.pack_into("<HBHB", boot, 11, bps, spc, fat_start, num_fats)
        boot[21] = 0xF8
        struct.pack_into("<II", boot, 32, total, fat_length)
        if num_fats == 2:
            struct.pack_into("<H", boot, 40, 0x81)
        struct.pack_into("<IHH", boot, 44, 2, 0xffff, 0xffff)
        boot[64:67] = b"\x80\0\x29"
        struct.pack_into("<I", boot, 67, 0x12345678)
        boot[71:90] = b"LARGE TEST FAT32   "
    active_fat = fat_start + (fat_length if num_fats == 2 else 0)
    files = {}
    root = bytearray(cluster_bytes)
    writes = []
    stream = sparse_file(path, total * bps)
    with stream:
        def write(offset, data):
            stream.seek(offset)
            stream.write(data)
            writes.append((offset, len(data)))

        write(0, boot)
        write(active_fat * bps, struct.pack("<III", 0xfffffff8, 0xffffffff, 0xffffffff))
        names = [("chain.bin", False), ("linear.bin", True)] if kind == "exfat" else [("chain.bin", False)]
        for index, (name, contiguous) in enumerate(names):
            cluster = first + index * 8
            second = cluster + (1 if contiguous else 3)
            content = bytes((i * 17 + 31 + index) & 255 for i in range(cluster_bytes + min(713, cluster_bytes)))
            offsets = [(heap + (cluster - 2) * spc) * bps,
                       (heap + (second - 2) * spc) * bps]
            write(offsets[0], content[:cluster_bytes])
            write(offsets[1], content[cluster_bytes:])
            if not contiguous:
                write(active_fat * bps + cluster * 4, struct.pack("<I", second))
                write(active_fat * bps + second * 4, struct.pack("<I", 0xffffffff))
            if kind == "exfat":
                root[index * 96:(index + 1) * 96] = exfat_entry(name, cluster, len(content), contiguous)
            else:
                root[:11] = b"CHAIN   BIN"
                root[11] = 0x20
                struct.pack_into("<H", root, 20, cluster >> 16)
                struct.pack_into("<HI", root, 26, cluster & 0xffff, len(content))
            files[name] = (content, offsets)
        write(heap * bps, root)
        if corrupt:
            # Past the (2^32)th cluster: a 32-bit logical index would wrap to 0.
            declared = ((1 << 32) + 1) * cluster_bytes
            mutations = {
                "active-fat": [(40, "H", 0x81)],
                "volume-shift": [(72, "Q", 1 << 63)],
                "heap-outside": [(88, "I", total)],
                "count-wrap": [(92, "I", 0xffffffff)],
                "heap-short": [(92, "I", count + 1)],
                "fat-overlap": [(84, "I", fat_length + 1)],
                "fat-short": [(84, "I", 1)],
                "volume-outside": [(32 if kind == "fat32" else 72, "I" if kind == "fat32" else "Q", total + 1)],
                "heap-beyond": [(72, "Q", total * 2), (88, "I", total)],
                "fat-high-bits": [(active_fat * bps + first * 4, "I", (first + 3) | 0xF0000000)],
                "huge-size": [(heap * bps + 40, "Q", declared), (heap * bps + 56, "Q", declared)],
                "tail-cut": [],
            }
            for offset, fmt, value in mutations[corrupt]:
                write(offset, struct.pack("<" + fmt, value))
            if corrupt == "tail-cut":
                # The device ends where chain.bin's second cluster begins.
                stream.truncate(files["chain.bin"][1][1])
    return files, cluster_bytes, writes


def sampled_hash(path, ranges):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for offset, length in ranges:
            stream.seek(offset)
            digest.update(stream.read(length))
    return digest.hexdigest()


CASES = [(kind, bps, "small", None) for kind in ("fat32", "exfat")
         for bps in (512, 1024, 2048, 4096)]
CASES += [("fat32", 4096, where, None) for where in ("data", "heap", "fat-length")]
CASES += [("fat32", 4096, "small", "active-fat")]
CASES += [("exfat", 4096, where, None) for where in ("heap", "fat-base", "data", "fat-entry")]
CASES += [("exfat", 4096, "small", corrupt) for corrupt in
          ("volume-shift", "heap-outside", "count-wrap", "heap-short",
           "fat-overlap", "fat-short", "heap-beyond")]
# Damaged but still usable: a truncated tail, FAT32 reserved high bits.
CASES += [(kind, 4096, "small", "volume-outside") for kind in ("fat32", "exfat")]
CASES += [("fat32", 4096, "small", "fat-high-bits")]
CASES += [("exfat", 512, "small", "huge-size")]
CASES += [(kind, 4096, "small", "tail-cut") for kind in ("fat32", "exfat")]
MOUNTABLE = {"volume-outside", "fat-high-bits", "huge-size", "tail-cut"}


def check_case(suite, config):
    kind, bps, where, corrupt = config
    name = f"{kind}-{bps}-{where}-{corrupt or 'valid'}"
    directory = suite.root / "fat-large" / name
    directory.mkdir(parents=True)
    image = directory / "volume.img"
    files, cluster_bytes, ranges = make_image(image, *config)
    # Keep recipes/results, not multi-TiB sparse files, in CI artifacts.
    try:
        verify_image(suite, image, directory, name, files, cluster_bytes, ranges, corrupt)
    finally:
        if not getattr(suite, "keep_large_images", False):
            image.unlink()


def verify_image(suite, image, directory, name, files, cluster_bytes, ranges, corrupt):
    before = sampled_hash(image, ranges)
    rejected = corrupt is not None and corrupt not in MOUNTABLE
    result = suite.command([suite.cli, "-f", image, "--list=(img0)/"], expected=1 if rejected else 0)
    if corrupt == "huge-size":
        # Only the first two clusters exist; never extract the declared 2 TiB.
        content = files["chain.bin"][0]
        sliced = directory / "chain.bin.slice"
        start, length = cluster_bytes - 17, 99
        suite.command([suite.probe, "--filemap", image, "(img0)/chain.bin", "read", start, length, sliced])
        require(sliced.read_bytes() == content[start:start + length], "cross-cluster seek mismatch")
        far = suite.command([suite.probe, "--filemap", image, "(img0)/chain.bin", "read",
                             (1 << 32) * cluster_bytes, length, sliced], expected=1)
        require("invalid FAT data range" in far.stderr, f"{name}: wrapped cluster index was read")
    elif corrupt == "tail-cut":
        # Mapping and reading agree: the surviving cluster works, the cut one fails.
        content = files["chain.bin"][0]
        path = "(img0)/chain.bin"
        sliced = directory / "chain.bin.slice"
        suite.command([suite.probe, "--filemap", image, path, 0, cluster_bytes, 0])
        suite.command([suite.probe, "--filemap", image, path, "read", 0, cluster_bytes, sliced])
        require(sliced.read_bytes() == content[:cluster_bytes], f"{name}: surviving cluster mismatch")
        mapped = suite.command([suite.cli, "-f", image, "-b", path], expected=1)
        require("storage mapping outside disk" in mapped.stderr, f"{name}: blocklist passed the device end")
        read = suite.command([suite.cli, "-f", image, "-o", directory / "cut", "-e", path], expected=1)
        require("outside of disk" in read.stderr, f"{name}: extraction passed the device end")
    elif not rejected:
        for filename, (content, offsets) in files.items():
            require(filename in result.stdout.lower(), f"missing {filename}")
            destination = directory / (filename + ".out")
            target = destination / filename
            path = "(img0)/" + filename
            suite.command([suite.cli, "-f", image, "-o", destination, "-e", path])
            require(hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(content).digest(),
                    f"{name}: extraction hash mismatch")
            mapping = suite.command([suite.cli, "-f", image, "-b", path])
            rows = read_rows(mapping.stdout, len(content))
            for row in rows:
                pos, length = int(row["file_offset"]), int(row["file_length"])
                expected = offsets[pos // cluster_bytes] + pos % cluster_bytes
                require(row["type"] == "DIRECT" and int(row["storage_offset"]) == expected,
                        f"{name}: wrong physical mapping")
                with image.open("rb") as stream:
                    stream.seek(expected)
                    require(stream.read(length) == content[pos:pos + length], "mapped content mismatch")
            sliced = directory / (filename + ".slice")
            start, length = cluster_bytes - 17, 99
            suite.command([suite.probe, "--filemap", image, path, "read", start, length, sliced])
            require(sliced.read_bytes() == content[start:start + length], "cross-cluster seek mismatch")
    require(sampled_hash(image, ranges) == before, "source metadata/payload changed")


def check_fat_large(suite):
    for config in CASES:
        check_case(suite, config)


if __name__ == "__main__":
    from run_product import Suite
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=pathlib.Path, required=True)
    parser.add_argument("--probe", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--keep-images", action="store_true", help="retain sparse images for local inspection")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=args.output.resolve()))
    suite = Suite(args.cli.resolve(), args.probe.resolve(), root)
    suite.keep_large_images = args.keep_images
    for config in CASES:
        suite.case(str(config), lambda config=config: check_case(suite, config))
    (root / "results.json").write_text(json.dumps({"results": suite.results, "commands": suite.commands}, indent=2), encoding="utf-8")
    print(f"Results: {root}")
    raise SystemExit(any(result["status"] == "FAIL" for result in suite.results))
