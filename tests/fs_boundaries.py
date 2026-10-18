#!/usr/bin/env python3
"""FBFS CLI regressions and optional existing FBFS/APFS image checks."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(name, minor=6, start=4, size=4):
    name = name.encode() + b"\0"
    extra = bytes(4) if minor == 7 else b""
    total = 14 + len(extra) + len(name)
    return struct.pack("<BBIII", total - 2, 0, start, size, 1700000000) + extra + name


def fixture(path, entries, minor=6, sectors=1):
    image = bytearray(4096)
    struct.pack_into("<4sBBHHHI", image, 0, b"FBAR", 1, minor, sectors, sectors, 0, 0)
    for i in range(sectors):
        block = entries[i * 510:(i + 1) * 510]
        image[512 + i * 512:512 + i * 512 + len(block)] = block
        image[512 + i * 512 + 510:512 + (i + 1) * 512] = b"\xA5\xA5"
    image[2048:2052] = b"abcd"
    path.write_bytes(image)


def fba_files(path):
    image = path.read_bytes()
    assert image[:4] == b"FBAR"
    minor, sectors = image[5], struct.unpack_from("<H", image, 6)[0]
    table = b"".join(image[512 + i * 512:1022 + i * 512] for i in range(sectors))
    pos, files = 0, {}
    while table[pos]:
        size, flags, start, length, stamp = struct.unpack_from("<BBIII", table, pos)
        end = pos + size + 2
        name = table[pos + (18 if minor == 7 else 14):end].split(b"\0", 1)[0].decode()
        files[name] = hashlib.sha256(image[start * 512:start * 512 + length]).hexdigest()
        assert start * 512 + length <= len(image)
        pos = end
    return files


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = output / "fixtures"
    root.mkdir()
    results = []
    sources = {}

    def command(name, image, path, expected=None, bad=False, decompress=False, names=(), ignored=()):
        sources.setdefault(image, digest(image))
        target = output / name
        argv = [str(args.cli.resolve()), "-d" if decompress else "-f", str(image)]
        argv += ["-l", path] if expected is None else ["-e", path, "-o", str(target)]
        result = subprocess.run(argv, capture_output=True, timeout=60)
        ok = result.returncode == (1 if bad else 0)
        actual = {}
        if expected is None and not bad:
            listing = result.stdout.decode("utf-8", errors="replace").splitlines()
            ok = ok and all(n in listing for n in names)
        if expected is not None and not bad:
            actual = {p.relative_to(target).as_posix(): digest(p)
                      for p in target.rglob("*") if p.is_file()}
            ok = ok and {k: v for k, v in actual.items() if k not in ignored} == expected
        results.append(dict(name=name, ok=ok, argv=argv, exit=result.returncode,
                            stdout=result.stdout.decode(errors="replace"),
                            stderr=result.stderr.decode(errors="replace"), hashes=actual))
        print("PASS" if ok else "FAIL", name, flush=True)

    payload_hash = hashlib.sha256(b"abcd").hexdigest()
    for minor in (6, 7):
        for kind in ("short-name", "cross-sector"):
            name = "a" if kind == "short-name" else "nested/b"
            entries = record(name, minor)
            names = (name,) if kind == "short-name" else ("nested/", "x" * 240)
            sectors = 1
            if kind == "cross-sector":
                extra = 4 if minor == 7 else 0
                # The third record crosses the first sector's 510-byte payload.
                entries = (record("x" * (240 - extra), minor)
                           + record("y" * (225 - extra), minor) + entries)
                names = ("nested/",)
                sectors = 2
            image = root / f"v{minor}-{kind}.fba"
            fixture(image, entries, minor, sectors)
            command(image.stem + "-list", image, "(img0)/", names=names)
            command(image.stem + "-extract", image, "(img0)/" + name,
                    {Path(name).name: payload_hash})
    entries = record("a" * 240) + record("b" * 239) + b"\0"
    image = root / "last-byte-terminator.fba"
    fixture(image, entries)
    command(image.stem, image, "(img0)/", names=("a" * 240, "b" * 239))
    for name, entries, sectors in (
        ("zero-list", b"", 0),
        ("short-entry", b"\x01\x00\x00", 1),
        ("unterminated-name", record("a")[:-1] + b"b", 1),
        ("missing-terminator", record("a" * 240) + record("b" * 240), 1),
        ("truncated-header", record("a" * 240) + record("b" * 239) + b"\x01", 1),
        ("entry-overrun", record("a" * 240) + b"\xFF" + bytes(254), 1),
    ):
        image = root / (name + ".fba")
        fixture(image, entries, sectors=sectors)
        command(name, image, "(img0)/", bad=True)
    if args.media:
        media = args.media.resolve()
        for name in ("1.607.fba", "1.701.fba"):
            image = media / name
            expected = {"img0/" + k: v for k, v in fba_files(image).items()}
            command(name + "-list", image, "(img0)/", names=("boot/", "grldr"))
            command(name + "-extract", image, "(img0)/", expected)
        for name in ("rover-apfs-gpt.img", "rover-apfs-udrw.dmg", "rover-apfs-lzfse.dmg"):
            image = media / name
            command(name + "-list", image, "(img0,gpt1)/ROVER_APFS/",
                    decompress=True, names=("documents/", "README.txt"))
            command(name + "-readme", image, "(img0,gpt1)/ROVER_APFS/README.txt",
                    {"README.txt": "c2f011eec399b004860572f9be7e88fb4cda926a21893c30e4f76fa51a1a466e"},
                    decompress=True)
        if args.oracle:
            expected = {"ROVER_APFS/" + p.relative_to(args.oracle).as_posix(): digest(p)
                        for p in args.oracle.rglob("*") if p.is_file()}
            # 7-Zip 26.00 disagrees with the image manifest for this sparse file.
            expected.pop("ROVER_APFS/sparse-16m.bin")
            command("apfs-tree-oracle-10-files", media / "rover-apfs-gpt.img",
                    "(img0,gpt1)/ROVER_APFS/", expected,
                    ignored=("ROVER_APFS/sparse-16m.bin",))
            command("apfs-sparse-manifest", media / "rover-apfs-gpt.img",
                    "(img0,gpt1)/ROVER_APFS/sparse-16m.bin",
                    {"sparse-16m.bin": "080acf35a507ac9849cfcba47dc2ad83e01b75663a516279c8b9d243b719643e"})
    for image, before in sources.items():
        results.append(dict(name="unchanged-" + image.name, ok=digest(image) == before,
                            source=str(image), sha256=before))
    (output / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if all(item["ok"] for item in results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--media", type=Path, help="directory with the optional existing FBA/APFS images")
    parser.add_argument("--oracle", type=Path, help="7-Zip extraction of the APFS image, excluding symlinks")
    raise SystemExit(run(parser.parse_args()))
