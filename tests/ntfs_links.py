#!/usr/bin/env python3
"""Build the NTFS reparse-point fixture for run_product.py --ntfs-links.

Linux only (WSL works): needs mkntfs and ntfs-3g (ntfs-3g package), and root
to mount, e.g.  sudo python3 tests/ntfs_links.py /tmp/links.ntfs

Layout (targets are what rover_readlink must report):
  Users/Public/hello.txt   "hello from public\\n"
  Documents and Settings   junction 0xA0000003 -> \\??\\C:\\Users       "/Users"
  abs                      symlink  0xA000000C -> \\??\\C:\\Users\\Public "/Users/Public"
  rel.lnk                  symlink  0xA000000C, relative               "Users/Public/hello.txt"
  odd                      unknown tag 0x80000018                       readlink fails
"""
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

XATTR = "system.ntfs_reparse_data"


def utf16(text):
    return text.encode("utf-16-le")


def mount_point(substitute, printed):
    s, p = utf16(substitute), utf16(printed)
    body = struct.pack("<HHHH", 0, len(s), len(s) + 2, len(p)) + s + b"\0\0" + p + b"\0\0"
    return struct.pack("<IHH", 0xA0000003, len(body), 0) + body


def symlink(substitute, printed, relative):
    s, p = utf16(substitute), utf16(printed)
    body = struct.pack("<HHHHI", 0, len(s), len(s), len(p), 1 if relative else 0) + s + p
    return struct.pack("<IHH", 0xA000000C, len(body), 0) + body


def opaque(tag):
    body = b"\x11" * 16
    return struct.pack("<IHH", tag, len(body), 0) + body


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: ntfs_links.py OUTPUT")
    image = pathlib.Path(sys.argv[1]).resolve()
    with open(image, "wb") as f:
        f.truncate(16 << 20)
    subprocess.run(["mkntfs", "-F", "-Q", "-q", "-L", "LINKS", str(image)], check=True,
                   stderr=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory() as mnt:
        root = pathlib.Path(mnt)
        subprocess.run(["ntfs-3g", str(image), mnt], check=True)
        try:
            (root / "Users" / "Public").mkdir(parents=True)
            (root / "Users" / "Public" / "hello.txt").write_bytes(b"hello from public\n")
            (root / "Documents and Settings").mkdir()
            (root / "abs").mkdir()
            (root / "rel.lnk").write_bytes(b"")
            (root / "odd").write_bytes(b"")
            os.setxattr(root / "Documents and Settings", XATTR,
                        mount_point(r"\??\C:\Users", r"C:\Users"), follow_symlinks=False)
            os.setxattr(root / "abs", XATTR,
                        symlink(r"\??\C:\Users\Public", r"C:\Users\Public", False), follow_symlinks=False)
            os.setxattr(root / "rel.lnk", XATTR,
                        symlink(r"Users\Public\hello.txt", r"Users\Public\hello.txt", True),
                        follow_symlinks=False)
            os.setxattr(root / "odd", XATTR, opaque(0x80000018), follow_symlinks=False)
        finally:
            subprocess.run(["umount", mnt], check=True)
    if "SUDO_UID" in os.environ:
        os.chown(image, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))


if __name__ == "__main__":
    main()
