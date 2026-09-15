"""System V family fixtures from Linux 6.12.109's documented disk layouts."""
import collections
import struct


CASES = [(kind, order, size, sector)
         for kind, sizes in (("xenix", (512, 1024)), ("sysv2", (512, 1024, 2048)),
                             ("sysv4", (512, 1024, 2048)))
         for order in ("le", "be") for size in sizes
         for sector in ((2,) if kind == "xenix" else (1,))]
CASES += [("v7", "le", 512, 1), ("v7", "pdp", 512, 1),
          ("coherent", "pdp", 512, 1), ("afs", "le", 1024, 1),
          ("sysv4", "le", 512, 19), ("sysv2", "be", 1024, 31),
          ("sysv4", "be", 2048, 37)]


def name(case):
    return "sysv-%s-%s-%s-%s.img" % case


def fixture(case):
    kind, order, bs, sector = case
    image = bytearray(128 * bs)
    endian = ">" if order == "be" else "<"

    def u16(n):
        return struct.pack(endian + "H", n)

    def u32(n):
        if order == "pdp":
            return struct.pack("<HH", n >> 16, n & 65535)
        return struct.pack(endian + "I", n)

    def u24(n):
        if order == "pdp":
            return bytes((n >> 16, n & 255, (n >> 8) & 255))
        return n.to_bytes(3, "big" if order == "be" else "little")

    def put(offset, value):
        image[offset:offset + len(value)] = value

    sb = sector * 512
    put(sb, u16(8))
    put(sb + (4 if kind in ("sysv4", "afs") else 2), u32(128))
    if kind == "xenix":
        put(sb + 1016, u32(0x2b5544))
        put(sb + 1020, u32(bs.bit_length() - 9))
        put(sb + 614, u32(1700000000))
        put(sb + 632, b"XENIX ")
    elif kind in ("sysv2", "sysv4", "afs"):
        put(sb + 504, u32(0xfd187e20))
        put(sb + 508, u32(bs.bit_length() - 9))
        put(sb + (414 if kind == "sysv2" else 420), u32(1700000000))
        put(sb + (432 if kind == "sysv2" else 440), b"SYSV  ")
        if kind == "afs":
            put(sb + 8, u16(65535))
    elif kind == "coherent":
        put(sb + 470, u32(1700000000))
        put(sb + 484, b"nonamenopack")
    else:
        put(sb + 414, u32(1700000000))
        put(sb + 428, b"V7    ")

    def inode(n, mode, size, blocks):
        raw = u16(mode) + u16(2) + u16(42) + u16(43) + u32(size)
        raw += b"".join(u24(b) for b in (blocks + [0] * 13)[:13]) + b"\0"
        raw += u32(1700000000) * 3
        put(2 * bs + (n - 1) * 64, raw)

    def directory(block, items):
        raw = b"".join(u16(n) + s.encode().ljust(14, b"\0") for n, s in items)
        put(block * bs, raw)
        return len(raw)

    # Keep payload above all alternate superblock locations (sector 37).
    root = [(2, "."), (2, ".."), (3, "hello.txt"), (4, "sub"),
            (3, "fourteen-chars"), (6, "link"), (7, "sparse.bin"),
            (8, "indirect.bin"), (9, "dirlink")]
    inode(2, 0o40755, directory(40, root), [40])
    hello = b"System V family: direct data\n"
    put(41 * bs, hello)
    inode(3, 0o100644, len(hello), [41])
    inode(4, 0o40755, directory(42, [(4, "."), (2, ".."), (5, "leaf.txt")]), [42])
    leaf = bytes((i * 29 + 7) & 255 for i in range(11 * bs + 73))
    blocks = [44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66]
    for i, block in enumerate(blocks):
        put(block * bs, leaf[i * bs:(i + 1) * bs])
    put(68 * bs, u32(64) + u32(66))
    inode(5, 0o100644, len(leaf), blocks[:10] + [68])
    put(69 * bs, b"sub/leaf.txt")
    inode(6, 0o120777, 12, [69])
    sparse = b"A" * bs + bytes(bs) + b"B" * bs + bytes(17)
    put(70 * bs, b"A" * bs)
    put(71 * bs, b"B" * bs)
    inode(7, 0o100644, len(sparse), [70, 0, 71, 0])
    put(72 * bs, b"sub")
    inode(9, 0o120777, 3, [72])

    # Sparse file with marked blocks on each side of all mapping transitions.
    ptrs = bs // 4
    logical_blocks = [9, 10, 10 + ptrs - 1, 10 + ptrs,
                      10 + ptrs + ptrs * ptrs - 1, 10 + ptrs + ptrs * ptrs,
                      10 + ptrs + ptrs * ptrs + 2]
    inode_blocks = [0] * 13
    next_block = 80
    tables = {}
    markers = {}
    for logical in logical_blocks:
        payload_block = next_block
        next_block += 1
        marker = bytes((logical & 255, (logical >> 8) & 255, 0x5a, 0xa5)) * (bs // 4)
        put(payload_block * bs, marker)
        markers[logical] = marker
        if logical < 10:
            inode_blocks[logical] = payload_block
            continue
        n = logical - 10
        if n < ptrs:
            path = [10, n]
        elif n - ptrs < ptrs * ptrs:
            n -= ptrs
            path = [11, n // ptrs, n % ptrs]
        else:
            n -= ptrs + ptrs * ptrs
            path = [12, n // (ptrs * ptrs), (n // ptrs) % ptrs, n % ptrs]
        for depth in range(1, len(path)):
            key = tuple(path[:depth])
            if key not in tables:
                tables[key] = next_block
                next_block += 1
                if depth == 1:
                    inode_blocks[path[0]] = tables[key]
                else:
                    put(tables[tuple(path[:depth - 1])] * bs + path[depth - 1] * 4,
                        u32(tables[key]))
        put(tables[tuple(path[:-1])] * bs + path[-1] * 4, u32(payload_block))
    inode(8, 0o100644, (logical_blocks[-1] + 1) * bs, inode_blocks)
    return image, {"hello.txt": hello, "fourteen-chars": hello, "sub/leaf.txt": leaf,
                   "sparse.bin": sparse}, markers


def generate_sysv(root):
    for case in CASES:
        image, _, _ = fixture(case)
        (root / name(case)).write_bytes(image)
    base, _, _ = fixture(("sysv4", "le", 1024, 1))
    changes = {
        "geometry": (516, struct.pack("<I", 129)),
        "inode-table": (512, struct.pack("<H", 2)),
        "root": (2048 + 64, struct.pack("<H", 0o100644)),
        "dir-size": (2048 + 64 + 8, struct.pack("<I", 33)),
        "dot": (40 * 1024, struct.pack("<H", 3)),
        "entry-inode": (40 * 1024 + 32, struct.pack("<H", 65535)),
        "entry-name": (40 * 1024 + 34, b"/"),
        "data-pointer": (2048 + 2 * 64 + 12, (128).to_bytes(3, "little")),
        "metadata-pointer": (2048 + 2 * 64 + 12, (2).to_bytes(3, "little")),
        "indirect-pointer": (68 * 1024, struct.pack("<I", 128)),
        "link-size": (2048 + 5 * 64 + 8, struct.pack("<I", 4097)),
        "link-loop": (69 * 1024, b"link" + b"/" * 8),
        "link-nul": (69 * 1024, bytes(12)),
        "isc-long-name": (1020, struct.pack("<I", 0x20)),
    }
    for key, (offset, value) in changes.items():
        data = base.copy()
        data[offset:offset + len(value)] = value
        (root / ("sysv-bad-" + key + ".img")).write_bytes(data)
    (root / "sysv-bad-truncated.img").write_bytes(base[:80 * 1024])
    # A no-magic V7-looking superblock must still prove its root directory.
    data, _, _ = fixture(("v7", "pdp", 512, 1))
    data[40 * 512:40 * 512 + 32] = bytes(32)
    (root / "sysv-bad-v7-dot.img").write_bytes(data)


def check_sysv(suite):
    from run_product import require, digest
    for case in CASES:
        image = name(case)
        bs = case[2]
        _, files, markers = fixture(case)
        listing = suite.cli_run(image, "--list=(img0)/")
        expected = ["hello.txt", "sub/", "fourteen-chars", "link", "dirlink",
                    "sparse.bin", "indirect.bin"]
        actual = [line.rstrip("/") for line in listing.stdout.splitlines()]
        require(collections.Counter(actual) == collections.Counter(x.rstrip("/") for x in expected),
                f"{image}: root inventory: {listing.stdout}")
        child = suite.cli_run(image, "--list=(img0)/sub/")
        require(child.stdout.splitlines() == ["leaf.txt"], f"{image}: child directory")
        for source, content in {**files, "link": files["sub/leaf.txt"], "dirlink/leaf.txt": files["sub/leaf.txt"]}.items():
            out = suite.root / (image + "-" + source.replace("/", "-"))
            # Explicit CLI extraction skips symbolic links by design; direct
            # read through the product probe verifies target resolution.
            if source in ("link", "dirlink/leaf.txt"):
                out.parent.mkdir(parents=True, exist_ok=True)
                suite.command([suite.probe, "--filemap", suite.fixtures / image,
                               "(img0)/" + source, "read", 0, len(content), out])
                actual_data = out.read_bytes()
            else:
                suite.extract(image, out.name, [source], "--no-times")
                actual_data = (out / source.split("/")[-1]).read_bytes()
            require(digest(actual_data) == digest(content), f"{image}/{source}: hash mismatch")
        for logical, marker in markers.items():
            out = suite.root / (image + "-slice.bin")
            suite.command([suite.probe, "--filemap", suite.fixtures / image,
                           "(img0)/indirect.bin", "read", logical * bs + 7, bs - 11, out])
            require(out.read_bytes() == marker[7:-4], f"{image}: indirect block {logical}")
            if logical != max(markers):
                suite.command([suite.probe, "--filemap", suite.fixtures / image,
                               "(img0)/indirect.bin", "read", (logical + 1) * bs - 7, 19, out])
                following = markers.get(logical + 1, bytes(bs))
                require(out.read_bytes() == marker[-7:] + following[:12],
                        f"{image}: read across mapping boundary {logical}")
        # The missing second triple-indirect leaf and missing direct block
        # must read as holes, despite adjacent marked blocks.
        for logical in (0, 10 + 2 * (bs // 4), 10 + bs // 4 + (bs // 4) ** 2 + 1):
            out = suite.root / (image + "-hole.bin")
            suite.command([suite.probe, "--filemap", suite.fixtures / image,
                           "(img0)/indirect.bin", "read", logical * bs, bs, out])
            require(out.read_bytes() == bytes(bs), f"{image}: sparse subtree")
    for path in sorted(suite.fixtures.glob("sysv-bad-*.img")):
        key = path.stem.removeprefix("sysv-bad-")
        if key in ("data-pointer", "metadata-pointer"):
            source = "hello.txt"
        elif key == "indirect-pointer":
            source = "sub/leaf.txt"
        elif key.startswith("link-"):
            out = suite.root / (path.stem + ".bin")
            suite.command([suite.probe, "--filemap", path, "(img0)/link", "read", 0, 1, out], expected=1)
            continue
        else:
            suite.cli_run(path.name, "--list=(img0)/", expected=1)
            continue
        out = suite.root / path.stem
        suite.extract(path.name, out.name, [source], expected=1)
        require(not any(p.is_file() for p in out.rglob("*")), f"partial output retained: {out}")
