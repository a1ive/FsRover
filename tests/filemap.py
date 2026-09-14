"""Metadata mapping regressions integrated with the product suite."""
import csv
import io
import hashlib
import json
import struct

from fixtures import EXT2_DIRS, EXT2_FILES, EXT2_LINKS, FAT_FILES, make_ext2, make_fat

# Preserve the original external-media matrix. These files are never downloaded
# or modified; the default CI cases below generate their own smaller fixtures.
EXTERNAL_CASES = {
    "fat.img": ["FRAGMENT.BIN", "EMPTY.BIN"],
    "fat16.img": ["data.bin"], "fat32.img": ["data.bin"],
    "exfat-512.img": ["tail.bin", "last.bin"],
    "exfat-4096.img": ["tail.bin", "last.bin"],
    "ext2.img": ["data.bin", "sparse.bin", "empty"],
    "ext4.img": ["data.bin", "sparse.bin", "tree.bin", "empty"],
    "ntfs.img": ["plain.bin", "sparse.bin", "zero.bin", "unwritten.bin", "inline.txt",
                 "compressed.bin", "fragment.bin", "mixed.bin", "wof.bin"],
    "xfs.img": ["data.bin", "sparse.bin", "tree.bin", "unwritten.bin", "empty"],
}
EXTERNAL_ERRORS = [("fat.img", "CYCLE.BIN"), ("ntfs.img", "bad-run.bin"),
                   ("ntfs.img", "bad-unit.bin"), ("bad-depth.img", "tree.bin"),
                   ("bad-count.img", "tree.bin")]
COLUMNS = ["group", "file_offset", "file_length", "type", "device", "address_space",
           "storage_offset", "storage_length", "encoding", "decoded_offset", "decoded_length"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def generate_mapping(fixtures):
    path = fixtures / "map-fat.img"
    make_fat(path)
    disk = bytearray(path.read_bytes())
    # Keep payload beyond the metadata cache window and fragment its two clusters.
    disk[101 * 512:102 * 512] = disk[33 * 512:34 * 512]
    disk[105 * 512:106 * 512] = disk[34 * 512:35 * 512]
    struct.pack_into("<H", disk, 19 * 512 + 26, 70)
    for start in (512, 10 * 512):
        for cluster, value in ((2, 0), (3, 0), (70, 74), (74, 0xfff)):
            offset = start + cluster * 3 // 2
            pair = int.from_bytes(disk[offset:offset + 2], "little")
            pair = (pair & 15) | (value << 4) if cluster & 1 else (pair & 0xf000) | value
            struct.pack_into("<H", disk, offset, pair)
    path.write_bytes(disk)
    # A two-cluster cycle with a file long enough to require the repeated link.
    for start in (512, 10 * 512):
        offset = start + 74 * 3 // 2
        pair = int.from_bytes(disk[offset:offset + 2], "little")
        struct.pack_into("<H", disk, offset, (pair & 0xf000) | 70)
    struct.pack_into("<I", disk, 19 * 512 + 28, 2048)
    (fixtures / "map-cycle.img").write_bytes(disk)

    path = fixtures / "map-sparse.ext2"
    make_ext2(path)
    disk = bytearray(path.read_bytes())
    names = sorted(EXT2_DIRS) + sorted(EXT2_FILES) + sorted(EXT2_LINKS)
    inode = 11 + names.index("nested/data.bin")
    # Remove one direct block pointer, retaining the file's logical size.
    struct.pack_into("<I", disk, 5 * 1024 + (inode - 1) * 128 + 0x28 + 4, 0)
    path.write_bytes(disk)
    # Valid metadata, but the first data block is far outside the image.
    struct.pack_into("<I", disk, 5 * 1024 + (inode - 1) * 128 + 0x28, 4194304)
    (fixtures / "map-outside.ext2").write_bytes(disk)


def read_rows(text, size=None):
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    require(reader.fieldnames == COLUMNS, "mapping TSV schema changed")
    rows = list(reader)
    pos, group, previous = 0, 0, None
    for row in rows:
        current = int(row["group"])
        if current == group:
            require(all(row[key] == previous[key] for key in
                        ("file_offset", "file_length", "type", "encoding", "decoded_offset", "decoded_length")),
                    "storage fragments disagree about their logical group")
            continue
        require(current == group + 1, "nonsequential mapping group")
        require(int(row["file_offset"]) == pos and int(row["file_length"]) > 0,
                "mapping has a gap, overlap or empty record")
        pos += int(row["file_length"])
        group, previous = current, row
    if size is not None:
        require(pos == size, "mapping does not cover the complete file")
    return rows


def probe(suite, image, path, offset, length, stop=0, output=None):
    args = [suite.probe, "--filemap", image, path, offset, length, stop]
    if output is not None:
        args.append(output)
    result = suite.command(args)
    records = [json.loads(line) for line in result.stdout.splitlines()]
    metadata = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
    summary = metadata[-1]
    require(summary["offset_preserved"] == 1 and summary["error"] == 0, "mapping changed cursor/failed")
    require(summary["records"] == len(records), "callback count mismatch")
    return records, metadata[:-1], summary


def default_mapping(suite):
    suite.command([suite.probe, "--filemap", "core"])
    suite.cli_run("map-outside.ext2", "-b", "(img0)/nested/data.bin", expected=1)
    suite.command([suite.probe, "--filemap", suite.fixtures / "map-outside.ext2",
                   "(img0)/nested/data.bin", "read", 0, 512, suite.root / "outside.bin"], expected=1)
    sparse = EXT2_FILES["nested/data.bin"]
    sparse = sparse[:1024] + bytes(1024) + sparse[2048:]
    cases = [("map-fat.img", "hello.txt", FAT_FILES["hello.txt"]),
             ("map-fat.img", "empty.bin", b""),
             ("map-sparse.ext2", "nested/data.bin", sparse)]
    for index, (image, name, content) in enumerate(cases):
        source, path = suite.fixtures / image, "(img0)/" + name
        short = suite.cli_run(image, "-b", path)
        long = suite.cli_run(image, "--blocklist=" + path)
        require(short.stdout == long.stdout, "short/long blocklist mismatch")
        rows = read_rows(short.stdout, len(content))
        rebuilt = bytearray()
        payload_ranges = []
        with source.open("rb") as stream:
            for row in rows:
                length = int(row["file_length"])
                if row["type"] == "DIRECT":
                    offset = int(row["storage_offset"])
                    require(row["address_space"] == "Volume" and int(row["storage_length"]) == length,
                            "DIRECT placement mismatch")
                    require(offset + length <= source.stat().st_size, "out-of-volume mapping")
                    stream.seek(offset)
                    rebuilt += stream.read(length)
                    payload_ranges.append((offset, offset + length))
                else:
                    require(row["type"] == "ZERO | HOLE", "unexpected generated-fixture flags")
                    rebuilt += bytes(length)
        require(bytes(rebuilt) == content, "mapped bytes differ from fixture content")
        output = suite.root / f"map-after-{index}.bin"
        records, reads, summary = probe(suite, source, path, 0, len(content), output=output)
        require(not summary["stopped"] and output.read_bytes() == content, "post-map read failed")
        require([(r["offset"], r["length"]) for r in records] ==
                [(int(r["file_offset"]), int(r["file_length"])) for r in rows],
                "native and public mapping ranges differ")
        for read in reads:
            start, end = read["read_sector"] * 512, (read["read_sector"] + read["sectors"]) * 512
            require(all(end <= a or start >= b for a, b in payload_ranges), "mapping read file payload")
        if not content:
            require(not records and not reads, "empty file performed mapping I/O")
            continue
        for offset, length in [(7, 611), (len(content) - 3, 100), (len(content), 20), (9, 0)]:
            records, _, summary = probe(suite, source, path, offset, length)
            pos = offset
            for record in records:
                require(record["offset"] == pos and record["length"] > 0, "range clipping gap")
                pos += record["length"]
            require(pos == offset + min(length, len(content) - offset), "range clipping end mismatch")
        stopped_output = suite.root / f"map-stopped-{index}.bin"
        records, _, summary = probe(suite, source, path, 0, len(content), 1, stopped_output)
        require(summary["stopped"] == 1 and len(records) == 1, "callback stop ignored")
        require(stopped_output.read_bytes() == content, "read after callback stop failed")
        cancelled_output = suite.root / f"map-cancelled-{index}.bin"
        records, _, summary = probe(suite, source, path, 0, len(content), "cancel:4", cancelled_output)
        require(summary["stopped"] == 1 and not records, "metadata cancellation emitted a record")
        require(cancelled_output.read_bytes() == content, "read after metadata cancellation failed")
        sliced = suite.root / f"map-slice-{index}.bin"
        suite.command([suite.probe, "--filemap", source, path, "read", 7, 611, sliced])
        require(sliced.read_bytes() == content[7:618], "normal-read slice mismatch")
        suite.extract(image, f"map-extract-{index}", [name])
        require((suite.root / f"map-extract-{index}" / name.split("/")[-1]).read_bytes() == content,
                "CLI extraction differs from mapping")
    suite.cli_run("map-cycle.img", "-b", "(img0)/hello.txt", expected=1)
    suite.cli_run("broken.img", "-b", "(img0)/bad.bin", expected=1)


def mapping_errors(suite):
    for args in [["-b"], ["--blocklist="], ["-b", "(img0)/x", "-l"],
                 ["-b", "(img0)/x", "-b", "(img0)/y"], ["-b", "(img0)/x", "extra"]]:
        suite.command([suite.cli, *args], expected=2)
    require("--blocklist" in suite.command([suite.cli, "--help"]).stdout, "missing blocklist help")


def external_mapping(suite, fixtures):
    sources = {image for image in EXTERNAL_CASES} | {image for image, _ in EXTERNAL_ERRORS}
    before = {}
    for image in sources:
        path = fixtures / image
        require(path.is_file(), f"Missing external mapping fixture: {path}")
        before[image] = hashlib.sha256(path.read_bytes()).hexdigest()
    for image, names in EXTERNAL_CASES.items():
        for name in names:
            path = "(img0)/" + name
            short = suite.command([suite.cli, "-f", fixtures / image, "-b", path])
            long = suite.command([suite.cli, "-f", fixtures / image, "--blocklist=" + path])
            require(short.stdout == long.stdout, "external short/long mismatch")
            read_rows(short.stdout)
    for image, name in EXTERNAL_ERRORS:
        suite.command([suite.cli, "-f", fixtures / image, "-b", "(img0)/" + name], expected=1)
    require(before == {name: hashlib.sha256((fixtures / name).read_bytes()).hexdigest() for name in sources},
            "external mapping fixture modified")
