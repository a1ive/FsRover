#!/usr/bin/env python3
"""APFS generated-volume names and existing APFS/ReFS media regressions."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def apfs_names(path, names, indices):
    """Minimal synthetic container with a shared empty filesystem tree."""
    blocks = [bytearray(4096) for _ in range(5 + len(names))]

    def put(block, offset, fmt, *values):
        struct.pack_into('<' + fmt, blocks[block], offset, *values)

    def header(block, kind, subtype=0):
        put(block, 8, 'QQII', block, 1, kind, subtype)

    def omap(block, entries):
        header(block, 2, 11)
        put(block, 32, 'HHIHH', 7, 0, len(entries), 0, 4 * len(entries))
        end = 4096 - 40
        put(block, end, 'IIII', 0, 4096, 16, 16)
        for i, (oid, physical) in enumerate(entries):
            put(block, 56 + 4 * i, 'HH', 16 * i, 16 * (i + 1))
            put(block, 56 + 4 * len(entries) + 16 * i, 'QQ', oid, 1)
            put(block, end - 16 * (i + 1), 'IIQ', 0, 4096, physical)

    header(0, 1)
    put(0, 32, 'IIQ', 0x4253584E, 4096, len(blocks))
    put(0, 0xA0, 'Q', 1)
    put(0, 0xB4, 'I', len(names))
    header(1, 11)
    put(1, 0x30, 'Q', 2)
    omap(2, [(1000 + i, 5 + i) for i in range(len(names))])
    # All volumes share the object map at block 3 and the empty root at block 4.
    header(3, 11)
    put(3, 0x30, 'Q', len(blocks))
    blocks.append(bytearray(4096))
    omap(len(blocks) - 1, [(2, 4)])
    header(4, 2, 14)
    put(4, 32, 'HHIHH', 3, 0, 0, 0, 0)
    for i, (name, index) in enumerate(zip(names, indices)):
        block = 5 + i
        put(0, 0xB8 + 8 * i, 'Q', 1000 + i)
        header(block, 13)
        put(block, 32, 'II', 0x42535041, index)
        put(block, 0x80, 'QQ', 3, 2)
        put(block, 0x108, 'Q', 1)
        encoded = name.encode()
        blocks[block][0x2C0:0x2C0 + len(encoded)] = encoded
    put(0, 0x28, 'Q', len(blocks))
    for block in blocks:
        a = b = 0
        for word in struct.unpack('<1022I', block[8:]):
            a += word
            b += a
        a %= 0xFFFFFFFF
        b %= 0xFFFFFFFF
        low = 0xFFFFFFFF - (a + b) % 0xFFFFFFFF
        high = 0xFFFFFFFF - (a + low) % 0xFFFFFFFF
        struct.pack_into('<Q', block, 0, low | high << 32)
    path.write_bytes(b''.join(blocks))


def run(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    results, sources = [], {}

    def record(name, ok, **details):
        results.append(dict(name=name, ok=bool(ok), **details))
        print('PASS' if ok else 'FAIL', name, flush=True)

    def command(name, image, path, extract=False):
        if image not in sources:
            sources[image] = digest(image)
        target = out / name
        cmd = [str(args.cli.resolve()), '-d', str(image), '-e' if extract else '-l', path]
        if extract:
            cmd += ['-o', str(target)]
        proc = subprocess.run(cmd, capture_output=True, timeout=180)
        record(name, proc.returncode == 0, argv=cmd, exit=proc.returncode,
               stdout=proc.stdout.decode('utf-8', errors='replace'),
               stderr=proc.stderr.decode('utf-8', errors='replace'))
        return target if extract else proc.stdout.decode('utf-8', errors='replace').splitlines()

    for tag, names, indices, expected in [
        ('suffix', ['Data', 'Data (3)', 'Data'], [1, 2, 3], ['Data', 'Data (3)', 'Data (1)']),
        ('special', ['', '.', '..', 'a/b', 'a_b', 'Volume0'], [0, 0, 0, 1, 1, 2],
         ['Volume0', 'Volume0 (0)', 'Volume0 (1)', 'a_b', 'a_b (1)', 'Volume0 (2)']),
        ('long', ['x' * 255] * 2, [0, 0xFFFFFFFF], ['x' * 255, 'x' * 255 + ' (4294967295)']),
        ('maximum', ['Data'] * 100, [0] * 100, ['Data'] + [f'Data ({i})' for i in range(99)]),
    ]:
        image = out / (tag + '.img')
        apfs_names(image, names, indices)
        listing = command(tag + '-list', image, '(img0)/')
        record(tag + '-names', sorted(listing) == sorted(n + '/' for n in expected))
        for i in (range(len(expected)) if len(expected) < 10 else (0, 1, 99)):
            command(f'{tag}-lookup-{i}', image, '(img0)/' + expected[i] + '/')

    if args.media:
        root = args.media.resolve()
        image = root / 'extra/rover-apfs-gpt.img'
        command('apfs-list', image, '(img0,gpt1)/ROVER_APFS/')
        tree = command('apfs-tree', image, '(img0,gpt1)/ROVER_APFS/', True) / 'ROVER_APFS'
        record('apfs-sparse-manifest', digest(tree / 'sparse-16m.bin') ==
               '080acf35a507ac9849cfcba47dc2ad83e01b75663a516279c8b9d243b719643e')
        if args.apfs_oracle:
            wanted = {p.relative_to(args.apfs_oracle).as_posix(): digest(p)
                      for p in args.apfs_oracle.rglob('*') if p.is_file() and p.name != 'sparse-16m.bin'}
            actual = {p.relative_to(tree).as_posix(): digest(p)
                      for p in tree.rglob('*') if p.is_file() and p.name != 'sparse-16m.bin'}
            record('apfs-oracle', actual == wanted, hashes=actual)
        for kind in ('lz4', 'zstd'):
            image = root / f'vhd/refs-{kind}.vhdx'
            command(f'{kind}-list', image, '(img0,msdos1)/')
            tree = command(f'{kind}-targets', image, '(img0,msdos1)/refs-compression-targets/', True)
            hashes = {p.relative_to(tree).as_posix(): digest(p) for p in tree.rglob('*') if p.is_file()}
            record(f'{kind}-target-count', len(hashes) == 32, hashes=hashes)
            if kind == 'lz4':
                lz4_hashes = hashes
            else:
                record('compression-algorithms-match', hashes == lz4_hashes)
        image = root / 'vhd/refs.vhdx'
        command('refs3-list', image, '(img0,msdos1)/RoverRefsTest/')
        command('refs3-tree', image, '(img0,msdos1)/RoverRefsTest/', True)
        image = root / 'vhd/refsv1.vhd'
        manifest = command('refs1-manifest', image, '(img0,msdos1)/refs_test/sha256.txt', True)
        for i, line in enumerate((manifest / 'sha256.txt').read_text(encoding='utf-8-sig').splitlines()):
            match = re.match(r'([0-9a-f]{64})\s+[A-Z]:\\(.+)', line)
            if not match:
                continue
            name = match[2].replace('\\', '/')
            target = command(f'refs1-file-{i}', image, '(img0,msdos1)/' + name, True)
            record(f'refs1-hash-{i}', digest(target / Path(name).name) == match[1])

        if args.probe:
            for name, image, path, raw_bytes in [
                ('apfs-raw', 'extra/rover-apfs-gpt.img', '(img0,gpt1)/ROVER_APFS/README.txt', 24),
                ('apfs-sparse', 'extra/rover-apfs-gpt.img', '(img0,gpt1)/ROVER_APFS/sparse-16m.bin', 16384),
                ('refs-raw', 'vhd/refs.vhdx', '(img0,msdos1)/RoverRefsTest/normal.bin', 1048576),
                ('refs-resident', 'vhd/refs.vhdx', '(img0,msdos1)/RoverRefsTest/resident.txt', 0),
                ('refs-sparse', 'vhd/refs.vhdx', '(img0,msdos1)/RoverRefsTest/sparse.bin', 8192),
                ('refs1-hole', 'vhd/refsv1.vhd', '(img0,msdos1)/refs_test/sparse/sparse-all.bin', 0),
                ('refs1-raw', 'vhd/refsv1.vhd', '(img0,msdos1)/refs_test/normal/size-65535.bin', 65535),
            ]:
                cmd = [str(args.probe.resolve()), '--file-hooks', str(root / image), path, str(raw_bytes)]
                proc = subprocess.run(cmd, capture_output=True, timeout=180)
                record('hooks-' + name, proc.returncode == 0, argv=cmd, exit=proc.returncode,
                       stdout=proc.stdout.decode('utf-8', errors='replace'),
                       stderr=proc.stderr.decode('utf-8', errors='replace'))

    for image, before in sources.items():
        record('unchanged-' + image.name, digest(image) == before, sha256=before)
    (out / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    return 0 if all(r['ok'] for r in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--media', type=Path, help='image collection root with extra/ and vhd/')
    parser.add_argument('--apfs-oracle', type=Path, help='independent extraction of ROVER_APFS')
    parser.add_argument('--probe', type=Path, help='product_probe executable for file hooks')
    raise SystemExit(run(parser.parse_args()))
