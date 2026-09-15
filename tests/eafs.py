"""SCO extended directories, based on ref/sco_fs (32-bit disk fields)."""
import struct

from sysv import fixture


CASES = [(kind, order, bs) for kind in ("eafs", "es51k")
         for order in ("le", "be") for bs in (512, 1024, 2048)]
NAMES = ["n" * size for size in (14, 15, 28, 29, 252, 255)]
NAMES += ["n" * 13 + "界-end"]  # UTF-8 bytes span prefix/suffix entries.
DIRECTORY = "directory-with-extended-name"
LINK = "symlink-with-extended-name"
DIRLINK = "directory-symlink-with-extended-name"


def filename(case):
    return "sco-%s-%s-%s.img" % case


def make_image(case):
    kind, order, bs = case
    data, files, _ = fixture(("afs" if kind == "eafs" else "sysv4", order, bs, 1))
    endian = "<" if order == "le" else ">"
    struct.pack_into(endian + "I", data, 1016, 0xfd187e21)
    # ES51K must retain the R4 layout even with a pre-1980 timestamp.
    struct.pack_into(endian + "I", data, 932, 1)

    def entry(ino, raw):
        return struct.pack(endian + "H", ino) + raw.ljust(14, b"\0")

    def extended(ino, name):
        raw = name.encode("utf-8")
        parts = [raw[i:i + 14] for i in range(0, len(raw), 14)]
        return b"".join(entry(65535, s) for s in parts[:-1]) + entry(ino, parts[-1])

    original = bytes(data[40 * bs:40 * bs + 9 * 16])
    # A name starting in the final slot must assemble correctly across
    # nonadjacent directory data blocks. Real samples need no such repair.
    raw = original.ljust(bs - 16, b"\0") + extended(3, "cross-block-name")
    for name in NAMES:
        raw += extended(3, name)
    raw += extended(4, DIRECTORY) + extended(6, LINK) + extended(9, DIRLINK)
    raw += entry(65535, b"deleted-prefix") + entry(0, b"deleted")
    raw += entry(3, b"after-deleted")
    blocks = [40, 43, 73, 74, 75, 76, 77, 78]
    used = (len(raw) + bs - 1) // bs
    if used > len(blocks):
        raise RuntimeError("fixture directory exceeds allocation")
    inode = 2 * bs + 64
    struct.pack_into(endian + "I", data, inode + 8, len(raw))
    data[inode + 12:inode + 51] = bytes(39)
    for i, block in enumerate(blocks[:used]):
        payload = raw[i * bs:(i + 1) * bs].ljust(bs, b"\0")
        data[block * bs:(block + 1) * bs] = payload
        data[inode + 12 + i * 3:inode + 15 + i * 3] = block.to_bytes(3, "little" if order == "le" else "big")
    return data, files, blocks, len(raw)


def generate_eafs(root):
    for case in CASES:
        data, _, _, _ = make_image(case)
        (root / filename(case)).write_bytes(data)
    data, _, blocks, size = make_image(("eafs", "le", 1024))
    prefix = 40 * 1024 + 1008
    suffix = 43 * 1024
    changes = {
        "prefix-nul": (prefix + 5, b"\0"),
        "prefix-slash": (prefix + 5, b"/"),
        "suffix-slash": (suffix + 2, b"/"),
        "empty-suffix": (suffix + 2, bytes(14)),
        "bad-inode": (suffix, struct.pack("<H", 500)),
        "dangling-prefix": (2 * 1024 + 64 + 8, struct.pack("<I", 1024)),
        "unsupported-blocksize": (1020, struct.pack("<I", 4)),
        # A classic directory must not gain EAFS prefix semantics.
        "classic-prefix": (1016, struct.pack("<I", 0xfd187e20)),
    }
    for key, (off, value) in changes.items():
        bad = data.copy()
        bad[off:off + len(value)] = value
        (root / ("sco-bad-" + key + ".img")).write_bytes(bad)
    bad = data.copy()
    # Nineteen full prefixes already exceed the 255-byte maximum.
    raw = (struct.pack("<H", 65535) + b"x" * 14) * 19
    raw += struct.pack("<H", 3) + b"tail".ljust(14, b"\0")
    bad[prefix:prefix + 16] = raw[:16]
    bad[suffix:suffix + len(raw) - 16] = raw[16:]
    struct.pack_into("<I", bad, 2 * 1024 + 64 + 8, 1008 + len(raw))
    (root / "sco-bad-long-overflow.img").write_bytes(bad)


def check_eafs(suite):
    from run_product import require, digest

    for case in CASES:
        image = filename(case)
        _, files, _, _ = make_image(case)
        result = suite.cli_run(image, "--list=(img0)/")
        actual = result.stdout.splitlines()
        original = ["hello.txt", "sub/", "fourteen-chars", "link", "sparse.bin", "indirect.bin", "dirlink"]
        expected = original + ["cross-block-name", *NAMES, DIRECTORY + "/", LINK, DIRLINK, "after-deleted"]
        require(sorted(actual) == sorted(expected), f"{image}: extended names {actual}")
        for index, name in enumerate(["cross-block-name", *NAMES, "after-deleted"]):
            out = suite.root / (image + f"-name{index}")
            suite.extract(image, out.name, [name], "--no-times")
            require(digest((out / name).read_bytes()) == digest(files["hello.txt"]),
                    f"{image}: extended name content {name}")
        listing = suite.cli_run(image, "--list=(img0)/" + DIRECTORY)
        require(listing.stdout.splitlines() == ["leaf.txt"], f"{image}: long directory lookup")
        for path in (DIRECTORY + "/leaf.txt", LINK, DIRLINK + "/leaf.txt"):
            out = suite.root / (image + "-read.bin")
            suite.command([suite.probe, "--filemap", suite.fixtures / image,
                           "(img0)/" + path, "read", 0, len(files["sub/leaf.txt"]), out])
            require(out.read_bytes() == files["sub/leaf.txt"], f"{image}: long path/symlink read")
    for path in sorted(suite.fixtures.glob("sco-bad-*.img")):
        suite.cli_run(path.name, "--list=(img0)/", expected=1)
        out = suite.root / path.stem
        suite.extract(path.name, out.name, ["cross-block-name"], "--no-times", expected=1)
        require(not any(p.is_file() for p in out.rglob("*")), f"{path.name}: partial output")
