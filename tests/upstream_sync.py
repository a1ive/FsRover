#!/usr/bin/env python3
"""GRUB synchronization regressions through CliRover/LinuxRover."""
import argparse
import hashlib
import io
import json
import pathlib
import struct
import subprocess
import sys
import tarfile
import zlib

sys.dont_write_bytecode = True
from fixtures import EXT2_FILES, make_ext2


def tar_header(name, kind=b"0", size=0, link=""):
    entry = tarfile.TarInfo(name)
    entry.type, entry.size, entry.linkname = kind, size, link
    return entry.tobuf(format=tarfile.GNU_FORMAT)


def make_lvm(path, payload):
    pv = "abcdef-1234-5678-9012-3456-7890-abcdef"
    metadata = f'''syncvg {{
id = "{pv}"
extent_size = 8
physical_volumes {{
pv0 {{
id = "{pv}"
pe_start = 2048
}}
}}
logical_volumes {{
base {{
id = "{pv}"
status = ["READ", "VISIBLE"]
segment_count = 1
segment1 {{
start_extent = 0
extent_count = 64
type = "striped"
stripe_count = 2
stripe_size = 1
stripes = ["pv0", 0, "pv0", 32]
}}
}}
cached {{
id = "{pv}"
status = ["READ", "VISIBLE"]
segment_count = 1
segment1 {{
start_extent = 0
extent_count = 64
type = "cache"
origin = "base"
}}
}}
}}
}}
'''.encode()
    image = bytearray(2 * 1024 * 1024)
    struct.pack_into("<8sQII8s", image, 512, b"LABELONE", 1, 0, 32, b"LVM2 001")
    struct.pack_into("<32sQ", image, 544, pv.replace("-", "").encode(), len(image))
    struct.pack_into("<QQQQQQ", image, 584, 1048576, 0, 0, 0, 4096, 65536)
    struct.pack_into("<I16sIQQQQ", image, 4096, 0, b" LVM2 x[5A%r0N*>", 1,
                     4096, 65536, 512, len(metadata))
    image[4608:4608 + len(metadata)] = metadata
    for block in range(len(payload) // 512):
        offset = 1048576 + (block % 2) * 131072 + (block // 2) * 512
        image[offset:offset + 512] = payload[block * 512:(block + 1) * 512]
    path.write_bytes(image)
    # Stop within the status array after several allocated LV fields.
    bad = bytearray(image)
    cut = metadata.index(b'"READ", "VISIBLE"') + 8
    struct.pack_into("<Q", bad, 4096 + 48, cut)
    path.with_name("lvm-truncated.img").write_bytes(bad)
    late = metadata[:-4] + b'broken { id = "short'
    bad = bytearray(image)
    bad[4608:4608 + len(late)] = late
    struct.pack_into("<Q", bad, 4096 + 48, len(late))
    path.with_name("lvm-late-truncated.img").write_bytes(bad)


def generate(root):
    root.mkdir(parents=True, exist_ok=True)
    payload = bytes(range(256)) * 8193
    (root / "payload.bin").write_bytes(payload)
    for fmt, name in ((tarfile.USTAR_FORMAT, "ustar"), (tarfile.PAX_FORMAT, "pax"),
                      (tarfile.GNU_FORMAT, "gnu")):
        with tarfile.open(root / (name + ".tar"), "w", format=fmt) as archive:
            entry = tarfile.TarInfo("payload.bin")
            entry.size = len(payload)
            if name == "pax":
                entry.pax_headers = {"path": "payload.bin", "mtime": "1700000000.25"}
            archive.addfile(entry, io.BytesIO(payload))
            if name != "ustar":
                entry = tarfile.TarInfo("x" * 120)
                entry.size = 3
                archive.addfile(entry, io.BytesIO(b"abc"))
    v7 = bytearray((root / "ustar.tar").read_bytes())
    v7[257:512] = bytes(255)
    v7[148:156] = b" " * 8
    v7[148:156] = ("%06o\0 " % sum(v7[:512])).encode()
    (root / "v7.tar").write_bytes(v7)
    binary = bytearray((root / "ustar.tar").read_bytes())
    binary[124:136] = (len(payload) | (1 << 95)).to_bytes(12, "big")
    binary[148:156] = b" " * 8
    binary[148:156] = ("%06o\0 " % sum(binary[:512])).encode()
    (root / "base256.tar").write_bytes(binary)
    long = tar_header("././@LongLink", b"L", 6) + b"hello\0" + bytes(506)
    for name, data in {
        "long-eof": long + bytes(1024),
        "long-invalid": long + b"invalid" + bytes(505),
        "long-truncated": tar_header("././@LongLink", b"L", 4096) + bytes(512),
        "long-huge": tar_header("././@LongLink", b"L", 1 << 32) + bytes(512),
        "link-huge": tar_header("././@LongLink", b"K", 1 << 32) + bytes(512),
        "metadata-only": long * 8 + bytes(1024),
        "symlink-loop": tar_header("loop", b"2", link="loop") + bytes(1024),
    }.items():
        (root / (name + ".tar")).write_bytes(data)
    make_ext2(root / "basic.ext2", links={"link": "nested"})
    ext = bytearray((root / "basic.ext2").read_bytes())
    # Locate the symlink inode in the generated inode table.
    for offset in range(5 * 1024, 13 * 1024, 128):
        if struct.unpack_from("<H", ext, offset)[0] & 0xf000 == 0xa000:
            struct.pack_into("<I", ext, offset + 4, 4097)
    (root / "longlink.ext2").write_bytes(ext)
    for mode, name in ((0o100644, "valid"), (0xffffffff, "sentinel")):
        def cpio_entry(filename, entry_mode, content):
            fields = [1, entry_mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0,
                      len(filename) + 1, 0]
            data = b"070701" + b"".join(("%08x" % x).encode() for x in fields)
            data += filename.encode() + b"\0"
            data += bytes(-len(data) % 4)
            data += content
            return data + bytes(-len(content) % 4)
        (root / (name + ".cpio")).write_bytes(cpio_entry("payload.bin", mode, payload)
                                             + cpio_entry("TRAILER!!!", 0, b""))
    make_lvm(root / "lvm.img", (root / "basic.ext2").read_bytes())
    for size in (128, 384, 1024, 0, 129):
        disk = bytearray(2 * 1024 * 1024)
        table = bytearray(max(size, 128) * 4)
        entry = max(size, 128) * 2
        table[entry:entry + 16] = bytes(range(1, 17))
        struct.pack_into("<QQ", table, entry + 32, 2048, 2559)
        header = bytearray(512)
        struct.pack_into("<8sIIIIQQQQ16sQIII", header, 0, b"EFI PART", 0x10000,
                         92, 0, 0, 1, 4095, 64, 4094, bytes(16), 2, 4, size,
                         zlib.crc32(table))
        struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
        disk[510:512] = b"\x55\xaa"
        disk[450] = 0xee
        disk[512:1024] = header
        disk[1024:1024 + len(table)] = table
        disk[1048576:1048576 + 262144] = (root / "basic.ext2").read_bytes()
        (root / ("gpt-%d.img" % size)).write_bytes(disk)


def generate_media(root):
    source = root / "source"
    source.mkdir(exist_ok=True)
    (source / "payload.bin").write_bytes((root / "payload.bin").read_bytes())
    (source / "nested").mkdir(exist_ok=True)
    (source / "nested" / "small.txt").write_bytes(b"metadata payload\n")
    (source / "link").symlink_to("nested")
    for comp in ("gzip", "lzo", "xz", "zstd"):
        subprocess.run(["mksquashfs", source, root / (comp + ".squashfs"),
                        "-noappend", "-processors", "1", "-comp", comp], check=True)
    for name, size, command in (("ext4.img", 32 * 1024 * 1024, ["mkfs.ext4", "-q", "-F", "-d", str(source)]),
                                ("btrfs.img", 128 * 1024 * 1024, ["mkfs.btrfs", "-q", "-f", "-r", str(source)])):
        path = root / name
        with path.open("wb") as out:
            out.truncate(size)
        subprocess.run([*command, str(path)], check=True)
    subprocess.run(["zstd", "-q", "-f", str(root / "ustar.tar"), "-o", str(root / "ustar.tar.zst")], check=True)


def run(cli, root, output):
    output.mkdir(parents=True, exist_ok=True)
    results = []
    def command(name, image, path, expected=None, bad=False, decompress=False):
        target = output / name
        args = [str(cli), "-d" if decompress else "-f", str(root / image)]
        args += ["-e", path, "-o", str(target)] if expected is not None else ["-l", path]
        result = subprocess.run(args, capture_output=True, timeout=30)
        ok = result.returncode == (1 if bad else 0)
        if expected is not None and not bad:
            files = list(target.rglob("*")) if target.exists() else []
            files = [p for p in files if p.is_file()]
            ok = ok and len(files) == 1 and files[0].read_bytes() == expected
        results.append({"name": name, "ok": ok, "exit": result.returncode,
                        "argv": args, "stdout": result.stdout.decode(errors="replace"),
                        "stderr": result.stderr.decode(errors="replace")})
        print("PASS" if ok else "FAIL", name, flush=True)
    tracked = list(root.glob("*.img")) + list(root.glob("*.tar")) + list(root.glob("*.ext2")) + list(root.glob("*.cpio")) + list(root.glob("*.squashfs")) + list(root.glob("*.zst"))
    hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}
    payload = (root / "payload.bin").read_bytes()
    for fmt in ("ustar", "pax", "gnu", "v7", "base256"):
        command(fmt, fmt + ".tar", "(img0)/payload.bin", payload)
    for fmt in ("pax", "gnu"):
        command(fmt + "-long", fmt + ".tar", "(img0)/" + "x" * 120, b"abc")
    command("long-eof", "long-eof.tar", "(img0)/")
    for name in ("long-invalid", "long-truncated", "long-huge", "link-huge", "metadata-only"):
        command(name, name + ".tar", "(img0)/", bad=True)
    command("symlink-loop", "symlink-loop.tar", "(img0)/loop/child", b"", bad=True)
    command("ext2-link", "basic.ext2", "(img0)/link/data.bin", EXT2_FILES["nested/data.bin"])
    command("ext2-longlink", "longlink.ext2", "(img0)/link/data.bin", b"", bad=True)
    command("cpio", "valid.cpio", "(img0)/payload.bin", payload)
    command("cpio-sentinel", "sentinel.cpio", "(img0)/", bad=True)
    for size in (128, 384, 1024, 0, 129):
        command("gpt-%d" % size, "gpt-%d.img" % size, "(img0,gpt3)/hello.txt",
                EXT2_FILES["hello.txt"], bad=size in (0, 129))
    for lv in ("base", "cached"):
        command("lvm-" + lv, "lvm.img", "(lvm/syncvg-" + lv + ")/hello.txt", EXT2_FILES["hello.txt"])
    for name in ("lvm-truncated", "lvm-late-truncated"):
        command(name, name + ".img", "(lvm/syncvg-base)/", bad=True)
    for name in ("ext4.img", "btrfs.img", "gzip.squashfs", "lzo.squashfs", "xz.squashfs", "zstd.squashfs"):
        if (root / name).exists():
            command(name + "-list", name, "(img0)/nested/")
            command(name, name, "(img0)/payload.bin", payload)
            command(name + "-link", name, "(img0)/link/small.txt", b"metadata payload\n")
    if (root / "ustar.tar.zst").exists():
        command("zstd", "ustar.tar.zst", "(img0)/payload.bin", payload, decompress=True)
    intact = all(hashlib.sha256(p.read_bytes()).hexdigest() == digest for p, digest in hashes.items())
    results.append({"name": "source-integrity", "ok": intact})
    (output / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--generate-media", action="store_true")
    parser.add_argument("--cli", type=pathlib.Path)
    parser.add_argument("--fixtures", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    options = parser.parse_args()
    if options.generate:
        generate(options.fixtures)
    if options.generate_media:
        generate_media(options.fixtures)
    if options.cli and not options.output:
        parser.error("--cli requires --output")
    if options.cli:
        sys.exit(run(options.cli.resolve(), options.fixtures.resolve(), options.output.resolve()))
