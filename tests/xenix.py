"""Xenix divvy product tests; sector positions are independent test vectors."""
import struct

from sysv import fixture


# name, heads, sectors/track, start LBA, cylinders, spare tracks, data LBA
CASES = (
    ("chs17", 12, 17, 17, 8, 15, 408),
    ("chs63", 16, 63, 63, 4, 15, 2016),
    ("track-rounding", 4, 17, 18, 16, 3, 204),
    ("cylinder-wrap", 2, 3, 3, 1025, 15, 102),
    ("no-spares", 4, 17, 17, 16, 0, 136),
)


def make_image(case):
    _, heads, sectors, start, cylinders, spares, base = case
    end = heads * sectors * cylinders
    image = bytearray(end * 512)

    def chs(lba):
        cylinder, rem = divmod(lba, heads * sectors)
        head, sector = divmod(rem, sectors)
        return bytes((head, sector + 1 | ((cylinder >> 2) & 0xc0), cylinder & 255))

    image[494:510] = (b"\x80" + chs(start) + b"\x02" + chs(end - 1)
                      + struct.pack("<II", start, end - start))
    image[510:512] = b"\x55\xaa"
    table = (start + 42) * 512
    struct.pack_into("<H", image, table, 0x1234)
    # Slot 4 is absent even though its unused offset contains garbage.
    entries = ((0, 128), (0, 0), (320, 1), (320, 1), (0xffffffff, 0),
               (160, 128), (321, 10), (0, (end - start + 1) // 2))
    for i, pair in enumerate(entries):
        struct.pack_into("<II", image, table + 2 + 8 * i, *pair)
    # Real media has unrelated stale data here: there are 8 on-disk slots,
    # although the ioctl's partable buffer holds up to 16.
    image[table + 66:table + 130] = b"stale table data" * 4
    struct.pack_into("<HHHH", image, (start + 44) * 512,
                     0x4321, spares, 0xffff, 0xffff)
    fs, files, _ = fixture(("xenix", "le", 1024, 2))
    for offset in (0, 320):
        at = (base + offset) * 512
        image[at:at + len(fs)] = fs
    expected = {"img0,msdos4": (start, end - start)}
    for i, (off, size) in enumerate(entries[:7]):
        if size:
            expected[f"img0,msdos4,xenix{i + 1}"] = (base + off * 2, size * 2)
    return image, expected, files


def generate_xenix(root):
    for case in CASES:
        data, _, _ = make_image(case)
        (root / ("xenix-divvy-" + case[0] + ".img")).write_bytes(data)
    data, _, _ = make_image(CASES[0])
    start = CASES[0][3]
    table, bad = (start + 42) * 512, (start + 44) * 512
    changes = {
        "magic": (table, bytes(2)),
        "badtrk-magic": (bad, bytes(2)),
        "badtrk-count": (bad + 2, struct.pack("<H", 1024)),
        "badtrk-mapping": (bad + 4, struct.pack("<HH", 30, 0)),
        "badtrk-sentinel": (bad + 6, bytes(2)),
        "zero-sectors": (500, bytes(1)),
        "start-chs": (495, bytes(1)),
        "end-chs": (501, bytes(1)),
        "wrong-type": (498, b"\x63"),
        "negative-offset": (table + 2, struct.pack("<I", 0xffffffff)),
        "negative-size": (table + 6, struct.pack("<I", 0x80000000)),
        # A late failure must prevent even an earlier valid root from appearing.
        "late-outside": (table + 2 + 6 * 8, struct.pack("<I", 0x7fffffff)),
        "cross-end": (table + 6, struct.pack("<I", 800)),
        "whole-offset": (table + 2 + 7 * 8, struct.pack("<I", 1)),
        "whole-size": (table + 6 + 7 * 8, struct.pack("<I", 1)),
        "reserved-outside": (bad + 2, struct.pack("<H", 1023)),
        "short-parent": (506, struct.pack("<I", 45)),
    }
    for name, (offset, value) in changes.items():
        broken = data.copy()
        broken[offset:offset + len(value)] = value
        (root / ("xenix-divvy-bad-" + name + ".img")).write_bytes(broken)
    (root / "xenix-divvy-bad-truncated.img").write_bytes(data[:bad + 4])
    # The pre-2.2 layout uses another label position and reserved-area scheme.
    old = data.copy()
    old[(start + 4) * 512:(start + 4) * 512 + 66] = data[table:table + 66]
    old[table:table + 66] = bytes(66)
    (root / "xenix-divvy-bad-old-layout.img").write_bytes(old)


def check_xenix(suite):
    from run_product import require, digest

    for case in CASES:
        image = "xenix-divvy-" + case[0] + ".img"
        _, expected, files = make_image(case)
        devices = suite.cli_run(image, "--list").stdout.split()
        actual = {s.strip("()") for s in devices if s.startswith("(img0,")}
        require(actual == set(expected), f"{image}: division inventory {actual}")
        dest = suite.root / (image + "-partitions")
        suite.cli_run(image, "-e", "(proc)/partitions", "-o", dest, "--no-times")
        rows = [line.split("\t") for line in (dest / "partitions").read_text().splitlines()[1:]]
        actual = {row[0].strip("()"): (int(row[1]), int(row[2]))
                  for row in rows if row[0].strip("()").startswith("img0,")}
        require(actual == expected, f"{image}: division addresses {actual} != {expected}")
        for division in (1, 6):
            device = f"(img0,msdos4,xenix{division})"
            listing = suite.cli_run(image, "--list=" + device + "/").stdout.splitlines()
            require("hello.txt" in listing and "sub/" in listing, f"{image}: filesystem list")
            source = "sub/leaf.txt"  # Fragmented file crossing direct/indirect blocks.
            dest = suite.root / (image + f"-extract{division}")
            suite.cli_run(image, "-e", device + "/" + source, "-o", dest, "--no-times")
            require(digest((dest / "leaf.txt").read_bytes()) == digest(files[source]),
                    f"{image}: nested division extraction hash")
    for path in sorted(suite.fixtures.glob("xenix-divvy-bad-*.img")):
        devices = suite.cli_run(path.name, "--list").stdout
        require(",xenix" not in devices, f"{path.name}: exposed invalid divisions: {devices}")
        suite.cli_run(path.name, "--list=(img0,msdos4,xenix1)/", expected=1)
