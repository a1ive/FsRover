#!/usr/bin/env python3
"""Generate with makensis, then validate NSIS and standard bzip2 via the CLI.

python tests/nsis_bzip2.py --generate build/nsis-bzip2
python tests/nsis_bzip2.py --cli build/x64/CliRover.exe build/nsis-bzip2
"""
import argparse
import bz2
import hashlib
import io
import pathlib
import random
import struct
import subprocess
import tarfile
import tempfile


def generate(root):
    root.mkdir(parents=True, exist_ok=True)
    source = root / 'source'
    source.mkdir(exist_ok=True)
    payload = random.Random(715).randbytes(1100000)
    (source / 'payload.bin').write_bytes(payload)
    (source / 'empty.bin').write_bytes(b'')
    for solid in (False, True):
        name = 'solid' if solid else 'members'
        script = source / (name + '.nsi')
        script.write_text(
            'Unicode true\nName "bzip2 regression"\n'
            f'OutFile "../{name}.exe"\n'
            f'SetCompressor {"/SOLID " if solid else ""}bzip2\n'
            'Section\nSetOutPath "$INSTDIR\\nested"\n'
            'File "payload.bin"\nSetOutPath "$INSTDIR"\n'
            'File "empty.bin"\nSectionEnd\n', encoding='utf-8')
        subprocess.run(['makensis', '-V1', script.name], cwd=source, check=True)
        data = bytearray((root / (name + '.exe')).read_bytes())
        start = data.index(bytes.fromhex('efbeadde') + b'NullsoftInst') - 4
        # Invalid first block marker; no checksum dependence.
        marker = start + 28 + (0 if solid else 4)
        data[marker] = 0x32
        (root / (name + '-bad.exe')).write_bytes(data)
        data = (root / (name + '.exe')).read_bytes()
        end = start + struct.unpack_from('<I', data, start + 24)[0]
        (root / (name + '-short.exe')).write_bytes(data[:end - 4096])
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as archive:
        info = tarfile.TarInfo('payload.bin')
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    compressed = bz2.compress(buf.getvalue())
    (root / 'standard.tar.bz2').write_bytes(compressed)
    damaged = bytearray(compressed)
    damaged[10] ^= 1  # First standard block's CRC.
    (root / 'standard-bad.tar.bz2').write_bytes(damaged)


def validate(root, cli):
    output = pathlib.Path(tempfile.mkdtemp(prefix='result-', dir=root))
    expected = hashlib.sha256((root / 'source/payload.bin').read_bytes()).digest()

    def run(image, args, success=True, decompressed=False):
        result = subprocess.run([str(cli), '-d' if decompressed else '-f',
                                 str(root / image), *args], capture_output=True,
                                timeout=120)
        if (result.returncode == 0) != success:
            raise RuntimeError(f'{image}: {result.returncode}: {result.stderr!r}')
        return result

    for name in ('members', 'solid'):
        listing = run(name + '.exe', ['--list=(img0)/']).stdout.decode().splitlines()
        if set(listing) != {'nested/', 'empty.bin'}:
            raise RuntimeError(f'bad listing: {listing}')
        target = output / name
        run(name + '.exe', ['-o', str(target), '-e', '(img0)/'])
        actual = (target / 'img0/nested/payload.bin').read_bytes()
        if hashlib.sha256(actual).digest() != expected:
            raise RuntimeError(name + ': payload mismatch')
        if (target / 'img0/empty.bin').read_bytes() != b'':
            raise RuntimeError(name + ': empty file mismatch')
        run(name + '-bad.exe', ['--list=(img0)/'], success=False)
        run(name + '-short.exe', ['-o', str(output / (name + '-short')),
                                '-e', '(img0)/'], success=False)
    target = output / 'standard'
    run('standard.tar.bz2', ['-o', str(target), '-e', '(img0)/'], decompressed=True)
    if hashlib.sha256((target / 'img0/payload.bin').read_bytes()).digest() != expected:
        raise RuntimeError('standard bzip2 mismatch')
    run('standard-bad.tar.bz2', ['-o', str(output / 'bad-standard'),
                               '-e', '(img0)/'], success=False, decompressed=True)
    print('PASS NSIS solid/members multi-block hashes, empty files, malformed/truncated streams, standard bzip2 and CRC rejection')
    print(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=pathlib.Path)
    parser.add_argument('--generate', action='store_true')
    parser.add_argument('--cli', type=pathlib.Path)
    args = parser.parse_args()
    if args.generate:
        generate(args.root.resolve())
    if args.cli:
        validate(args.root.resolve(), args.cli.resolve())
