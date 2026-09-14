"""Small, reproducible product fixtures; Python standard library only.

Images are generated at run time, never stored as encoded binary data in Git.
"""
import gzip
import io
import pathlib
import struct
import tarfile
import zipfile

MTIME = 946684800  # 2000-01-01 00:00:00 UTC
FILES = {
    "hello.txt": b"Rover product regression\n",
    "empty.bin": b"",
    "nested/data.bin": bytes(range(256)) * 4097 + b"tail",
}
DIRS = {"nested", "empty-dir"}
INTERLEAVED_FILES = {
    "alpha/deep/first.txt": b"first nested child",
    "beta/first.txt": b"other directory",
    "root.txt": b"separator",
    "alpha/peer.txt": b"parent child",
    "beta/second.txt": b"second other child",
    "alpha/deep/last.txt": b"last nested child",
}
INTERLEAVED_DIRS = {"alpha", "alpha/deep", "beta"}
FAT_FILES = {"hello.txt": b"FAT12 payload\n" * 60, "empty.bin": b"",
             "dir/child.txt": b"child\n"}
COLLISIONS = {"same.txt": b"lower", "SAME.TXT": b"upper",
              "a:b.txt": b"colon", "a?b.txt": b"question", "a_b.txt": b"underscore",
              "CON.txt": b"reserved", "trailing.": b"trailing",
              "unicode-\u6d4b\u8bd5.txt": b"unicode"}
EXT2_FILES = {
    "hello.txt": b"ext2 payload\n" * 12,
    "empty.bin": b"",
    "nested/data.bin": bytes(range(256)) * 33 + b"tail",
    "unicode-\u6d4b\u8bd5.txt": b"unicode\n",
}
EXT2_DIRS = {"nested", "empty-dir"}
EXT2_LINKS = {"link.txt": "hello.txt", "dirlink": "nested"}
SIGNAL_FILES = {f"signal-{index:02d}.bin": bytes([index]) * (256 * 1024)
                for index in range(32)}


def make_tar(path, files, dirs=(), links=False, grouped=True):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        entries = [(d + "/", None) for d in sorted(dirs)] + list(files.items())
        if grouped:
            entries.sort(key=lambda entry: entry[0])
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.mtime = MTIME
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            else:
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
        if links:
            info = tarfile.TarInfo("link.txt")
            info.type, info.linkname, info.mtime = tarfile.SYMTYPE, "hello.txt", MTIME
            archive.addfile(info)


def make_fat(path, broken=False):
    # Standard 1.44 MiB FAT12 superfloppy, 512-byte clusters, two FATs.
    disk = bytearray(2880 * 512)
    disk[:11] = b"\xeb\x3c\x90ROVER   "
    struct.pack_into("<HBHBHHBHHHII", disk, 11,
                     512, 1, 1, 2, 224, 2880, 0xf0, 9, 18, 2, 0, 0)
    disk[38] = 0x29
    struct.pack_into("<I", disk, 39, 0x524f5645)
    disk[43:62] = b"ROVER TEST FAT12   "
    disk[510:512] = b"\x55\xaa"
    fat = bytearray(9 * 512)
    fat[:3] = b"\xf0\xff\xff"

    def chain(cluster, value):
        offset = cluster * 3 // 2
        pair = int.from_bytes(fat[offset:offset + 2], "little")
        pair = (pair & 0x000f) | (value << 4) if cluster & 1 else (pair & 0xf000) | value
        struct.pack_into("<H", fat, offset, pair)

    def entry(name, cluster, size, directory=False):
        item = bytearray(32)
        item[:11] = name.encode("ascii")
        item[11] = 0x10 if directory else 0x20
        struct.pack_into("<HHHI", item, 22, 0, (20 << 9) | (1 << 5) | 1, cluster, size)
        return item

    def cluster_data(cluster, data):
        offset = (33 + cluster - 2) * 512
        disk[offset:offset + len(data)] = data

    hello = FAT_FILES["hello.txt"]
    chain(2, 3)
    chain(3, 0xfff)
    chain(4, 0xfff)
    chain(5, 0xfff)
    cluster_data(2, hello)
    cluster_data(5, FAT_FILES["dir/child.txt"])
    cluster_data(4, entry(".          ", 4, 0, True)
                 + entry("..         ", 0, 0, True)
                 + entry("CHILD   TXT", 5, len(FAT_FILES["dir/child.txt"])))
    entries = [entry("HELLO   TXT", 2, len(hello)), entry("EMPTY   BIN", 0, 0),
               entry("DIR        ", 4, 0, True)]
    if broken:
        # Valid directory metadata and first cluster; reading the second cluster
        # fails, so extraction has already created a target before rollback.
        chain(6, 0xff7)
        cluster_data(6, b"x" * 512)
        entries.insert(0, entry("BAD     BIN", 6, 1300))
    root = b"".join(entries)
    disk[19 * 512:19 * 512 + len(root)] = root
    disk[512:10 * 512] = fat
    disk[10 * 512:19 * 512] = fat
    path.write_bytes(disk)


def make_ext2(path):
    # Minimal revision-1 ext2: 1 KiB blocks, one block group, direct blocks only.
    block, total_blocks, total_inodes = 1024, 256, 64
    inode_size, first_ino = 128, 11
    dir_mode, reg_mode, link_mode = 0o040755, 0o100644, 0o120777
    types = {"reg": 1, "dir": 2, "symlink": 7}

    def dirent(inode, name, kind, length):
        raw = name.encode("utf-8")
        header = struct.pack("<IHBB", inode, length, len(raw), types[kind])
        return header + raw + b"\0" * (length - len(header) - len(raw))

    def directory(entries):
        data = bytearray(block)
        offset = 0
        for index, (inode, name, kind) in enumerate(entries):
            length = (8 + len(name.encode("utf-8")) + 3) & ~3
            if index == len(entries) - 1:
                length = block - offset
            data[offset:offset + length] = dirent(inode, name, kind, length)
            offset += length
        return bytes(data)

    def make_inode(mode, size, allocated, links=1, target=None):
        data = bytearray(inode_size)
        struct.pack_into("<H", data, 0x00, mode)
        struct.pack_into("<I", data, 0x04, size)
        for offset in (0x08, 0x0C, 0x10):
            struct.pack_into("<I", data, offset, MTIME)
        struct.pack_into("<H", data, 0x1A, links)
        struct.pack_into("<I", data, 0x1C, len(allocated) * (block // 512))
        if target is not None:
            data[0x28:0x28 + len(target)] = target
        else:
            for index, number in enumerate(allocated):
                struct.pack_into("<I", data, 0x28 + index * 4, number)
        return bytes(data)

    inodes, next_inode = {"root": 2}, first_ino
    for name in sorted(EXT2_DIRS) + sorted(EXT2_FILES) + sorted(EXT2_LINKS):
        inodes[name] = next_inode
        next_inode += 1

    layout = {"root": 13}
    next_block = 14
    for name in sorted(EXT2_DIRS):
        layout[name] = next_block
        next_block += 1
    for name in sorted(EXT2_FILES):
        count = max(1, (len(EXT2_FILES[name]) + block - 1) // block)
        layout[name] = list(range(next_block, next_block + count))
        next_block += count

    image = bytearray(total_blocks * block)
    root = [(inodes["root"], ".", "dir"), (inodes["root"], "..", "dir")]
    root += [(inodes[name], name, "reg") for name in sorted(EXT2_FILES) if "/" not in name]
    root += [(inodes[name], name, "dir") for name in sorted(EXT2_DIRS)]
    root += [(inodes[name], name, "symlink") for name in sorted(EXT2_LINKS)]
    image[layout["root"] * block:(layout["root"] + 1) * block] = directory(root)
    for name in sorted(EXT2_DIRS):
        entries = [(inodes[name], ".", "dir"), (inodes["root"], "..", "dir")]
        for other in sorted(EXT2_FILES):
            if other.startswith(name + "/"):
                entries.append((inodes[other], other.split("/", 1)[1], "reg"))
        image[layout[name] * block:(layout[name] + 1) * block] = directory(entries)
    for name, content in EXT2_FILES.items():
        for index, number in enumerate(layout[name]):
            chunk = content[index * block:(index + 1) * block]
            image[number * block:number * block + len(chunk)] = chunk

    table = bytearray(total_inodes * inode_size)

    def put_inode(number, payload):
        table[(number - 1) * inode_size:number * inode_size] = payload

    put_inode(inodes["root"], make_inode(dir_mode, block, [layout["root"]], links=3))
    for name in sorted(EXT2_DIRS):
        put_inode(inodes[name], make_inode(dir_mode, block, [layout[name]], links=2))
    for name, content in EXT2_FILES.items():
        put_inode(inodes[name], make_inode(reg_mode, len(content), layout[name]))
    for name, target in EXT2_LINKS.items():
        raw = target.encode("utf-8")
        put_inode(inodes[name], make_inode(link_mode, len(raw), [], target=raw))

    free_blocks = total_blocks - next_block
    free_inodes = total_inodes - (next_inode - 1)
    superblock = bytearray(block)
    struct.pack_into("<I", superblock, 0x00, total_inodes)
    struct.pack_into("<I", superblock, 0x04, total_blocks)
    struct.pack_into("<I", superblock, 0x0C, free_blocks)
    struct.pack_into("<I", superblock, 0x10, free_inodes)
    struct.pack_into("<I", superblock, 0x14, 1)
    struct.pack_into("<I", superblock, 0x18, 0)
    struct.pack_into("<I", superblock, 0x1C, 0)
    struct.pack_into("<I", superblock, 0x20, total_blocks)
    struct.pack_into("<I", superblock, 0x24, total_blocks)
    struct.pack_into("<I", superblock, 0x28, total_inodes)
    struct.pack_into("<I", superblock, 0x2C, MTIME)
    struct.pack_into("<I", superblock, 0x30, MTIME)
    struct.pack_into("<H", superblock, 0x36, 0xFFFF)
    struct.pack_into("<H", superblock, 0x38, 0xEF53)
    struct.pack_into("<H", superblock, 0x3A, 1)
    struct.pack_into("<H", superblock, 0x3C, 1)
    struct.pack_into("<I", superblock, 0x40, MTIME)
    struct.pack_into("<I", superblock, 0x4C, 1)
    struct.pack_into("<I", superblock, 0x54, first_ino)
    struct.pack_into("<H", superblock, 0x58, inode_size)
    struct.pack_into("<I", superblock, 0x60, 0x2)  # EXT2_FEATURE_INCOMPAT_FILETYPE
    superblock[0x78:0x88] = b"RoverTest".ljust(16, b"\0")
    image[block:2 * block] = superblock

    group = bytearray(32)
    struct.pack_into("<I", group, 0x00, 3)
    struct.pack_into("<I", group, 0x04, 4)
    struct.pack_into("<I", group, 0x08, 5)
    struct.pack_into("<H", group, 0x0C, free_blocks)
    struct.pack_into("<H", group, 0x0E, free_inodes)
    struct.pack_into("<H", group, 0x10, len(EXT2_DIRS) + 1)
    image[2 * block:2 * block + 32] = group

    block_bitmap = bytearray(block)
    for number in range(next_block):
        block_bitmap[number // 8] |= 1 << (number % 8)
    image[3 * block:4 * block] = block_bitmap
    inode_bitmap = bytearray(block)
    for number in range(1, next_inode):
        inode_bitmap[(number - 1) // 8] |= 1 << ((number - 1) % 8)
    image[4 * block:5 * block] = inode_bitmap
    image[5 * block:5 * block + len(table)] = table
    path.write_bytes(image)


def archive_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), MTIME, 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def make_loop_tar(path):
    deep = archive_bytes({"deep.txt": b"deep tar payload\n"})
    mid = archive_bytes({"deep.tar": deep, "mid.txt": b"mid tar payload\n"})
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in [("mid.tar", mid), ("mid.tar.gz", gzip.compress(mid)),
                           ("bad.gz", gzip.compress(mid)[:32])]:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), MTIME, 0o644
            archive.addfile(info, io.BytesIO(data))


def generate(root):
    root = pathlib.Path(root)
    root.mkdir(parents=True, exist_ok=True)
    make_tar(root / "basic.tar", FILES, DIRS)
    make_tar(root / "noncontiguous.tar", FILES, DIRS, grouped=False)
    make_tar(root / "interleaved.tar", INTERLEAVED_FILES, INTERLEAVED_DIRS, grouped=False)
    make_tar(root / "implicit.tar", INTERLEAVED_FILES, grouped=False)
    with zipfile.ZipFile(root / "basic.zip", "w") as archive:
        for name, data in [(d + "/", b"") for d in sorted(DIRS)] + list(FILES.items()):
            info = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    make_fat(root / "basic.img")
    make_fat(root / "broken.img", broken=True)
    (root / "basic.img.gz").write_bytes(gzip.compress((root / "basic.img").read_bytes()))
    (root / "unknown.img").write_bytes(bytes(4096))
    make_tar(root / "collisions.tar", COLLISIONS)
    make_tar(root / "links.tar", {"hello.txt": FILES["hello.txt"]}, links=True)
    make_tar(root / "cancel.tar", {"large.bin": bytes(range(256)) * 12289,
                                    "after.txt": b"must not be extracted"})
    make_ext2(root / "basic.ext2")
    make_loop_tar(root / "loop.tar")
    make_tar(root / "signal.tar", SIGNAL_FILES)
