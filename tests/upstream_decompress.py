#!/usr/bin/env python3
"""Generate compression/HFS media and verify extraction through the product CLI."""
import argparse
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import zlib


def generate(root):
    root.mkdir(parents=True, exist_ok=False)
    payload = bytes(range(256)) * 8193 + b"upstream regression\n" * 17000
    (root / "payload.bin").write_bytes(payload)
    (root / "payload.zlib").write_bytes(zlib.compress(payload, 9))
    (root / "payload.xz").write_bytes(lzma.compress(payload, check=lzma.CHECK_SHA256))
    subprocess.run(["lzop", "-f", "-o", str(root / "payload.lzo"),
                    str(root / "payload.bin")], check=True)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        entry = tarfile.TarInfo("payload.bin")
        entry.size = len(payload)
        tar.addfile(entry, io.BytesIO(payload))
    data = archive.getvalue()
    (root / "payload.tar").write_bytes(data)
    (root / "payload.tar.gz").write_bytes(gzip.compress(data))
    (root / "payload.tar.xz").write_bytes(lzma.compress(data, check=lzma.CHECK_SHA256))
    subprocess.run(["lzop", "-f", "-o", str(root / "payload.tar.lzo"),
                    str(root / "payload.tar")], check=True)
    subprocess.run(["zstd", "-q", "-19", "-f", str(root / "payload.tar"),
                    "-o", str(root / "payload.tar.zst")], check=True)
    for suffix in ("gz", "xz", "lzo", "zst"):
        packed = (root / ("payload.tar." + suffix)).read_bytes()
        (root / ("truncated.tar." + suffix)).write_bytes(packed[:len(packed) // 2])
    with (root / "hfs.img").open("wb") as f:
        f.truncate(8 * 1024 * 1024)
    subprocess.run(["hformat", "-l", "Rover", str(root / "hfs.img")], check=True)
    subprocess.run(["hmount", str(root / "hfs.img")], check=True)
    try:
        subprocess.run(["hcopy", "-r", str(root / "payload.bin"), ":payload.bin"], check=True)
        subprocess.run(["hcopy", "-r", ":payload.bin", str(root / "hfs-oracle.bin")], check=True)
    finally:
        subprocess.run(["humount"], check=True)
    if (root / "hfs-oracle.bin").read_bytes() != payload:
        raise RuntimeError("hfsutils content oracle mismatch")
    from fixtures import make_ext2
    from upstream_sync import make_lvm
    make_ext2(root / "basic.ext2")
    original = root / "lvm.img"
    make_lvm(original, (root / "basic.ext2").read_bytes())
    image = original.read_bytes()
    length = struct.unpack_from("<Q", image, 4096 + 48)[0]
    metadata = image[4608:4608 + length]
    cases = {
        "lvm-overflow": metadata.replace(b"extent_count = 64", b"extent_count = 18446744073709551615"),
        "lvm-zero-raid": metadata.replace(b'type = "striped"', b'type = "raid4"').replace(b"stripe_count = 2", b"device_count = 0"),
        "lvm-short-raid": metadata.replace(b'type = "striped"', b'type = "raid4"').replace(b"stripe_count = 2", b"device_count = 1"),
    }
    for name, text in cases.items():
        changed = bytearray(image)
        changed[4608:4608 + len(text)] = text
        struct.pack_into("<Q", changed, 4096 + 48, len(text))
        (root / (name + ".img")).write_bytes(changed)


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def run(cli, root, output):
    output.mkdir(parents=True, exist_ok=False)
    sources = {p: digest(p) for p in root.iterdir() if p.is_file()}
    expected = digest(root / "payload.bin")
    results = []

    def command(name, image, path, bad=False):
        target = output / name
        argv = [str(cli), "-d", str(root / image), "-e", path, "-o", str(target)]
        p = subprocess.run(argv, capture_output=True, timeout=60)
        files = [f for f in target.rglob("*") if f.is_file()] if target.exists() else []
        ok = p.returncode == (1 if bad else 0)
        if bad:
            ok = ok and not files
        else:
            ok = ok and len(files) == 1 and digest(files[0]) == expected
        results.append(dict(name=name, ok=ok, argv=argv, exit=p.returncode,
                            stdout=p.stdout.decode(errors="replace"),
                            stderr=p.stderr.decode(errors="replace")))
        print("PASS" if ok else "FAIL", name, flush=True)

    for suffix in ("gz", "xz", "lzo", "zst"):
        image = "payload.tar." + suffix
        p = subprocess.run([str(cli), "-d", str(root / image), "-l", "(img0)/"],
                           capture_output=True, timeout=60)
        results.append(dict(name=suffix + "-list", ok=p.returncode == 0 and b"payload.bin" in p.stdout,
                            exit=p.returncode, stdout=p.stdout.decode(errors="replace"),
                            stderr=p.stderr.decode(errors="replace")))
        command(suffix, image, "(img0)/payload.bin")
        command(suffix + "-truncated", "truncated.tar." + suffix, "(img0)/payload.bin", bad=True)
    command("hfs", "hfs.img", "(img0)/payload.bin")
    for path in sorted(root.glob("lvm-*.img")):
        command(path.stem, path.name, "(lvm/syncvg-base)/hello.txt", bad=True)
    results.append(dict(name="source-integrity", ok=all(digest(p) == h for p, h in sources.items())))
    (output / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return int(not all(r["ok"] for r in results))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--generate", action="store_true", help="requires lzop, zstd and hfsutils")
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.generate:
        generate(args.fixtures.resolve())
    if args.cli:
        if not args.output:
            parser.error("--cli requires --output")
        sys.exit(run(args.cli.resolve(), args.fixtures.resolve(), args.output.resolve()))
