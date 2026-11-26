#!/usr/bin/env python3
"""Run FMOD export regressions against CliRover or LinuxRover."""

import argparse
from pathlib import Path
import struct
import subprocess
import tempfile


def fsb(codec, streams, *, channels=1, rate=8, extra=b""):
    headers, names, audio = bytearray(), bytearray(4 * len(streams)), bytearray()
    for index, (name, frames, data) in enumerate(streams):
        mode = (frames << 34) | ((len(audio) // 32) << 7) | (channels << 5) | (rate << 1)
        headers.extend(struct.pack("<Q", mode | bool(extra)) + extra)
        struct.pack_into("<I", names, 4 * index, len(names))
        names.extend(name.encode("utf-8") + b"\0")
        audio.extend(data)
        audio.extend(bytes(-len(audio) % 32))
    header = struct.pack("<4s6I", b"FSB5", 1, len(streams), len(headers), len(names), len(audio), codec)
    return header.ljust(60, b"\0") + headers + names + audio


def partitions(a, b):
    assert len(a) == len(b) and a[:512] == b[:512]
    sectors = (len(a) + 511) // 512
    mbr = bytearray(512)
    mbr[510:] = b"\x55\xaa"
    for i in range(2):
        off = 446 + 16 * i
        mbr[off + 4] = 0x83
        struct.pack_into("<II", mbr, off + 8, 1 + i * sectors, sectors)
    return mbr + a.ljust(512 * sectors, b"\0") + b.ljust(512 * sectors, b"\0")


def run(cli, root):
    def command(image, *args):
        result = subprocess.run([cli, "-f", image, *args], capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result.stdout

    def extract(label, bank):
        image = root / (label + ".fsb")
        image.write_bytes(bank)
        dest = root / label
        dest.mkdir()
        command(image, "--extract=(img0)/", "-o", dest)
        return {p.name: p.read_bytes() for p in dest.rglob("*") if p.is_file()}

    def named_bank(prefix):
        return fsb(1, [(prefix + str(i), 32, bytes(32)) for i in range(60)], channels=0)

    image = root / "parts.img"
    image.write_bytes(partitions(named_bank("alpha"), named_bank("bravo")))
    listing = command(image, "--loop=(img0,msdos1)/alpha0.wav", "--list=(img0,msdos2)/")
    assert b"bravo0.wav" in listing and b"alpha0.wav" not in listing

    # Distinct payload bytes make incorrect offsets and leaking source padding visible.
    odd = b"\x80\x81\x82"
    streams = [
        ("a" * 255, 3, odd + b"\xff"),
        ("a" * 255, 2, b"\x84\x85"),
        ("b" * 250 + "\u97f3" * 4, 3, odd),
    ]
    wavs = extract("names", fsb(1, streams, channels=0))
    for name, pcm in [("a" * 251, odd), ("a" * 249 + "_1", b"\x84\x85"), ("b" * 250, odd)]:
        wav = wavs[name + ".wav"]
        assert wav[44:] == pcm + bytes(len(pcm) % 2)
        assert struct.unpack_from("<I", wav, 4)[0] == len(wav) - 8
        assert struct.unpack_from("<I", wav, 40)[0] == len(pcm)

    # Alternate bitrates and MPEG padding bits independently of the FSB alignment.
    frames = []
    for i in range(650):
        bitrate, code = [(128, 9), (160, 10), (192, 11)][i % 3]
        padding = i % 2
        size = 144000 * bitrate // 44100 + padding
        header = bytes([0xff, 0xfb, code << 4 | padding << 1, 0])
        frames.append(header + bytes([i % 256]) * (size - 4))
    mp3 = b"".join(frames)
    padded = b"".join(f + b"\xa5" * (-len(f) % 4) for f in frames)
    for label, data in [("padded", padded), ("packed", mp3)]:
        assert extract(label, fsb(11, [("tone", len(frames) * 1152, data)])) == {"tone.mp3": mp3}
    for label, ch, data in [("multichannel", 2, padded), ("layer2", 1, b"\xff\xfd" + mp3[2:])]:
        raw = data + bytes(-len(data) % 32)
        assert extract(label, fsb(11, [("tone", 1152, data)], channels=ch)) == {"tone.fsb-mpeg": raw}

    # Both FSB end markers can occur before the declared audio is complete.
    setup = struct.pack("<II", (0x0b << 25) | (4 << 1), 0x070ba3b6)
    for label, data in [("no-packets", b"\0\0"), ("short-chain", b"\1\0\0" * 2 + b"\xff\xff")]:
        files = extract(label, fsb(15, [("short", 8192, data)], extra=setup))
        assert files == {"short.vorbis": data.ljust(32, b"\0")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        run(args.cli.resolve(), Path(temp))
    print("FMOD export regressions passed")
