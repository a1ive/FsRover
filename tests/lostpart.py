#!/usr/bin/env python3
"""Generate damaged disk images with mkfs tools, then validate the lost
partition search (--scan-lost) and lost partition windows (--lost).

python3 tests/lostpart.py --generate build/lostpart
    (Linux/WSL: mkfs.vfat, mkntfs, ntfscp, mkfs.exfat, mkfs.ext4, mtools,
    mkfs.xfs, mkfs.btrfs, hfsutils, hfsprogs, mkfs.f2fs, sload.f2fs,
    mksquashfs, sgdisk, sfdisk, makefs, mkfs.jfs, mkreiserfs, mkudffs,
    genisoimage)
python tests/lostpart.py --cli build/x64/CliRover.exe build/lostpart
"""
import argparse
import hashlib
import json
import os
import pathlib
import random
import shutil
import struct
import subprocess
import tempfile

MIB = 1 << 20
TRACK = 63 * 512
CYL = 255 * TRACK


def run(*argv, **kwargs):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, **kwargs)


def make_fs(kind, size, label, files, work, block_size=None):
    """Return the bytes of a SIZE-byte KIND filesystem holding FILES."""
    image = work / (label + '.fs')
    image.unlink(missing_ok=True)
    with open(image, 'wb') as f:
        f.truncate(size)
    src = work / (label + '.src')
    shutil.rmtree(src, ignore_errors=True)
    src.mkdir()
    for name, data in files.items():
        (src / name).write_bytes(data)
    if kind in ('fat12', 'fat16', 'fat32'):
        extra = ['-s', '1'] if kind == 'fat32' else []
        run('mkfs.vfat', '-F', kind[3:], *extra, '-n', label, str(image))
        env = dict(os.environ, MTOOLS_SKIP_CHECK='1')
        for name in files:
            run('mcopy', '-i', str(image), str(src / name), '::/' + name, env=env)
    elif kind == 'ntfs':
        run('mkntfs', '-F', '-Q', '-q', '-L', label, str(image))
        for name in files:
            run('ntfscp', '-f', str(image), str(src / name), '/' + name)
    elif kind == 'exfat':
        run('mkfs.exfat', '-L', label, str(image))
    elif kind == 'ext4':
        run('mkfs.ext4', '-q', '-F', '-b', str(block_size or 1024), '-L', label,
            '-d', str(src), str(image))
    elif kind == 'xfs':
        proto = work / (label + '.proto')
        proto.write_text('dummy\n0 0\nd--755 0 0\n' + ''.join(
            f'{name} ---644 0 0 {src / name}\n' for name in files) + '$\n')
        run('mkfs.xfs', '-q', '-f', '-L', label, '-p', str(proto), str(image))
        proto.unlink()
    elif kind == 'btrfs':
        run('mkfs.btrfs', '-q', '-f', '-L', label, '-m', 'single', '-d', 'single',
            '-r', str(src), str(image))
    elif kind == 'hfs':
        run('hformat', '-l', label, str(image))
        for name in files:
            run('hcopy', '-r', str(src / name), ':' + name)
        run('humount')
    elif kind in ('hfsplus', 'hfsx'):
        # hfsplus (hpcopy) does not take mkfs.hfsplus volumes: no files.
        run('mkfs.hfsplus', *(['-s'] if kind == 'hfsx' else []), '-v', label, str(image))
    elif kind == 'f2fs':
        run('mkfs.f2fs', '-q', '-f', '-l', label, str(image))
        run('sload.f2fs', '-f', str(src), str(image))
    elif kind == 'squashfs':
        image.unlink()
        run('mksquashfs', str(src), str(image), '-noappend', '-quiet')
        with open(image, 'r+b') as f:
            f.truncate(size)
    elif kind in ('ufs', 'ufs2'):
        image.unlink()
        run('makefs', '-t', 'ffs', '-o', 'version=' + ('2' if kind == 'ufs2' else '1'),
            '-B', 'le', '-s', str(size), str(image), str(src))
    elif kind == 'jfs':
        run('mkfs.jfs', '-q', '-L', label, str(image))
    elif kind == 'reiserfs':
        run('mkreiserfs', '-q', '-f', '-l', label, str(image))
    elif kind in ('iso9660', 'udfbridge'):
        image.unlink()
        run('genisoimage', '-quiet', '-R', '-J', *(['-udf'] if kind == 'udfbridge' else []),
            '-V', label, '-o', str(image), str(src))
        with open(image, 'r+b') as f:
            f.truncate(size)
    elif kind == 'udf':
        run('mkudffs', '--blocksize=512', '--label=' + label, str(image))
    data = image.read_bytes()
    image.unlink()
    shutil.rmtree(src)
    return data


def mbr(entries):
    sector = bytearray(512)
    for i, (start, size, ptype) in enumerate(entries):
        struct.pack_into('<B3sB3sII', sector, 446 + 16 * i, 0, b'\xfe\xff\xff',
                         ptype, b'\xfe\xff\xff', start // 512, size // 512)
    sector[510:512] = b'\x55\xaa'
    return bytes(sector)


def generate(root):
    root.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix='work-', dir=root))
    rng = random.Random(4096)
    manifest = {}

    def files(tag):
        return {f'{tag}-{i}.bin': rng.randbytes(rng.randrange(1, 300000)) for i in range(3)}

    def hashes(content):
        return {name: hashlib.sha256(data).hexdigest() for name, data in content.items()}

    # 1 MiB aligned layout; the FAT32 volume has no partition entry.
    parts = []
    for kind, offset, size, label in (
            ('fat16', 1 * MIB, 16 * MIB, 'LOSTFAT16'),
            ('ntfs', 17 * MIB, 32 * MIB, 'LOSTNTFS'),
            ('ext4', 49 * MIB, 32 * MIB, 'LOSTEXT4'),
            ('exfat', 81 * MIB, 16 * MIB, 'LOSTEXFAT'),
            ('fat32', 97 * MIB, 40 * MIB, 'LOSTFAT32')):
        content = files(kind) if kind != 'exfat' else {}
        parts.append(dict(kind=kind, offset=offset, size=size, label=label,
                          data=make_fs(kind, size, label, content, work),
                          files=hashes(content)))
    disk_size = 160 * MIB
    types = {'fat16': 0x06, 'ntfs': 0x07, 'ext4': 0x83, 'exfat': 0x07}
    table = mbr([(p['offset'], p['size'], types[p['kind']]) for p in parts[:4]])

    def disk(name, table, damage=()):
        data = bytearray(disk_size)
        data[:512] = table
        for p in parts:
            data[p['offset']:p['offset'] + p['size']] = p['data']
        for offset, length in damage:
            data[offset:offset + length] = bytes(length)
        (root / name).write_bytes(data)

    def expect(p, flags, verified):
        return dict(offset=p['offset'], type=p['kind'], label=p['label'], flags=flags,
                    verified=verified, files=p['files'] if verified else {})

    by = {p['kind']: p for p in parts}
    disk('intact.img', table)
    manifest['intact.img'] = dict(expect=[expect(by['fat32'], [], True)], absent=[])

    disk('wiped.img', bytes(512))
    manifest['wiped.img'] = dict(expect=[expect(p, [], True) for p in parts], absent=[])

    # The NTFS entry stays but its boot sector is gone: only the backup
    # at the end of the volume finds it, and the lost window opens it with
    # that backup in place.
    ntfs = by['ntfs']
    disk('ntfs-backup.img', table, [(ntfs['offset'], 512)])
    manifest['ntfs-backup.img'] = dict(
        expect=[expect(ntfs, ['BACKUP', 'EXISTING'], True), expect(by['fat32'], [], True)],
        absent=[])

    # No table; FAT32, exFAT boot sectors and the ext4 primary superblock
    # and group descriptors (1 KiB blocks: block 2) gone.
    disk('backups.img', bytes(512), [(by['fat32']['offset'], 512),
                                     (by['exfat']['offset'], 512),
                                     (by['ext4']['offset'] + 1024, 2048)])
    manifest['backups.img'] = dict(
        expect=[expect(by['fat16'], [], True), expect(ntfs, [], True),
                expect(by['ext4'], ['BACKUP'], True), expect(by['exfat'], ['BACKUP'], True),
                expect(by['fat32'], ['BACKUP'], True)],
        absent=[])

    # CHS layout (63 sectors, 255 heads).  The ext4 primary superblock and
    # group descriptors are gone and its group 1 copy is off every
    # candidate: only the group 3 search of --scan-ext-backup finds it.
    chs = []
    for kind, offset, size, label in (
            ('fat16', TRACK, 2 * CYL - TRACK, 'CHSFAT16'),
            ('ntfs', 2 * CYL + TRACK, 4 * CYL - TRACK, 'CHSNTFS'),
            ('ext4', 6 * CYL, 4 * CYL, 'CHSEXT4')):
        content = files('chs-' + kind)
        chs.append(dict(kind=kind, offset=offset, size=size, label=label,
                        data=make_fs(kind, size, label, content, work),
                        files=hashes(content)))
    data = bytearray(12 * CYL)
    for p in chs:
        data[p['offset']:p['offset'] + p['size']] = p['data']
    ext = chs[2]
    data[ext['offset'] + 1024:ext['offset'] + 3072] = bytes(2048)
    (root / 'chs.img').write_bytes(data)
    manifest['chs.img'] = dict(expect=[expect(chs[0], [], True), expect(chs[1], [], True)],
                               absent=[ext['offset']])
    manifest['chs.img#ext-backup'] = dict(
        expect=[expect(chs[0], [], True), expect(chs[1], [], True),
                expect(ext, ['BACKUP'], True)],
        absent=[])

    # A stale FAT32 boot sector from an earlier format at 1 MiB still
    # claims 48 MiB; the partitions made later (FAT16 at 2 MiB, NTFS at
    # 18 MiB) lie inside that claim.  The NTFS backup at 50 MiB points
    # back into it, so the range is searched after all.
    stale = dict(kind='fat32', offset=1 * MIB, size=48 * MIB, label='STALEFAT32',
                 data=make_fs('fat32', 48 * MIB, 'STALEFAT32', {}, work), files={})
    newer = []
    for kind, offset, size, label in (('fat16', 2 * MIB, 16 * MIB, 'NEWFAT16'),
                                      ('ntfs', 18 * MIB, 32 * MIB, 'NEWNTFS')):
        content = files('new-' + kind)
        newer.append(dict(kind=kind, offset=offset, size=size, label=label,
                          data=make_fs(kind, size, label, content, work),
                          files=hashes(content)))
    data = bytearray(64 * MIB)
    for p in [stale] + newer:
        data[p['offset']:p['offset'] + p['size']] = p['data']
    (root / 'stale.img').write_bytes(data)
    manifest['stale.img'] = dict(expect=[
        dict(expect(stale, ['OVERLAP'], None), label=None),
        expect(newer[0], ['OVERLAP'], True),
        expect(newer[1], ['OVERLAP'], True)], absent=[])

    # The deep search finds the same, and the CHS ext4 through its group 1
    # copy without --scan-ext-backup.
    for name in ('wiped.img', 'backups.img', 'stale.img'):
        manifest[name + '#deep'] = manifest[name]
    manifest['chs.img#deep'] = manifest['chs.img#ext-backup']

    generate_p1(root, work, files, hashes, manifest)
    shutil.rmtree(work)
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=1))


def generate_p1(root, work, files, hashes, manifest):
    def build(layout):
        parts = []
        for kind, offset, size, label in layout:
            # No userland tool writes files into these.
            empty = kind in ('hfsplus', 'hfsx', 'jfs', 'reiserfs', 'udf')
            content = files(label.lower()) if not empty else {}
            parts.append(dict(kind=kind, offset=offset, size=size, label=label,
                              data=make_fs(kind, size, label, content, work),
                              files=hashes(content)))
        return parts

    def place(size, parts, damage=()):
        data = bytearray(size)
        for p in parts:
            data[p['offset']:p['offset'] + len(p['data'])] = p['data']
        for offset, length in damage:
            data[offset:offset + length] = bytes(length)
        return data

    def expect(p, flags, verified, kind=None, label=True):
        return dict(offset=p['offset'], type=kind or p['kind'],
                    label=p['label'] if label else None, flags=flags,
                    verified=verified, files=p['files'] if verified else {})

    # XFS, Btrfs, HFS, HFS+, HFSX and F2FS with no table.
    parts = build((
        ('xfs', 1 * MIB, 300 * MIB, 'P1XFS'),
        ('btrfs', 301 * MIB, 128 * MIB, 'P1BTRFS'),
        ('hfs', 429 * MIB, 16 * MIB, 'P1HFS'),
        ('hfsplus', 445 * MIB, 16 * MIB, 'P1HFSP'),
        ('hfsx', 461 * MIB, 16 * MIB, 'P1HFSX'),
        ('f2fs', 477 * MIB, 64 * MIB, 'P1F2FS')))
    by = {p['kind']: p for p in parts}
    size = 542 * MIB
    (root / 'p1-wiped.img').write_bytes(place(size, parts))
    manifest['p1-wiped.img'] = dict(expect=[expect(p, [], True) for p in parts], absent=[])

    # Primary superblocks gone.  XFS turns up through its second
    # allocation group, Btrfs through its 64 MiB mirror, HFS/HFS+ through
    # the alternate header at the end, F2FS through its second superblock
    # (which the GRUB driver also reads).  All open with the copy in place.
    (root / 'p1-backups.img').write_bytes(place(size, parts, [
        (by['xfs']['offset'], 512), (by['btrfs']['offset'] + 65536, 4096),
        (by['hfs']['offset'] + 1024, 512), (by['hfsplus']['offset'] + 1024, 512),
        (by['f2fs']['offset'] + 1024, 1024)]))
    manifest['p1-backups.img'] = dict(expect=[
        expect(by['xfs'], ['BACKUP'], True), expect(by['btrfs'], ['BACKUP'], True),
        expect(by['hfs'], ['BACKUP'], True), expect(by['hfsplus'], ['BACKUP'], True),
        expect(by['hfsx'], [], True), expect(by['f2fs'], ['BACKUP'], True)], absent=[])
    manifest['p1-backups.img#deep'] = manifest['p1-backups.img']

    # UFS1, UFS2, JFS, ReiserFS, ISO9660, UDF and an ISO9660/UDF bridge
    # image with no table.  makefs writes no UFS label; the bridge reads
    # as UDF.
    p2 = build((
        ('ufs', 1 * MIB, 32 * MIB, 'P2UFS1'),
        ('ufs2', 33 * MIB, 32 * MIB, 'P2UFS2'),
        ('jfs', 65 * MIB, 32 * MIB, 'P2JFS'),
        ('reiserfs', 97 * MIB, 48 * MIB, 'P2REISER'),
        ('iso9660', 145 * MIB, 8 * MIB, 'P2ISO'),
        ('udf', 153 * MIB, 16 * MIB, 'P2UDF'),
        ('udfbridge', 169 * MIB, 8 * MIB, 'P2BRIDGE')))
    p2size = 180 * MIB
    p2expect = []
    for p in p2:
        kind = 'udf' if p['kind'] == 'udfbridge' else p['kind']
        p2expect.append(expect(p, [], True, kind, kind not in ('ufs', 'ufs2', 'udf')))
    (root / 'p2-wiped.img').write_bytes(place(p2size, p2))
    manifest['p2-wiped.img'] = dict(expect=p2expect, absent=[])
    manifest['p2-wiped.img#deep'] = dict(expect=p2expect, absent=[])
    # The JFS primary superblock gone: the secondary one at 60 KiB opens it.
    jfs = p2[2]
    (root / 'p2-backups.img').write_bytes(place(p2size, p2, [(jfs['offset'] + 0x8000, 4096)]))
    manifest['p2-backups.img'] = dict(
        expect=p2expect[:2] + [expect(jfs, ['BACKUP'], True)] + p2expect[3:], absent=[])

    # Volumes off every quick search candidate (odd sector offsets, no
    # table, no backup at a candidate): only the deep search finds them.
    odd = build((
        ('ext4', 1 * MIB + 7 * 512, 16 * MIB, 'DEEPEXT4'),
        ('fat16', 24 * MIB + 3 * 512, 16 * MIB, 'DEEPFAT16')))
    (root / 'deep.img').write_bytes(place(48 * MIB, odd))
    manifest['deep.img'] = dict(expect=[], absent=[p['offset'] for p in odd])
    manifest['deep.img#deep'] = dict(expect=[expect(p, [], True) for p in odd], absent=[])

    # GPT: FAT16, ext4 and a squashfs volume no detector knows.
    gparts = build((
        ('fat16', 1 * MIB, 16 * MIB, 'GPTFAT16'),
        ('ext4', 17 * MIB, 16 * MIB, 'GPTEXT4'),
        ('squashfs', 33 * MIB, 8 * MIB, 'GPTSQUASH')))
    gsize = 48 * MIB

    def gpt(parts):
        path = work / 'gpt.img'
        path.write_bytes(place(gsize, gparts))
        run('sgdisk', '-o', str(path))
        for i, p in enumerate(parts, 1):
            run('sgdisk', '-n', f"{i}:{p['offset'] // 512}:{(p['offset'] + p['size']) // 512 - 1}",
                '-t', f'{i}:8300', str(path))
        data = bytearray(path.read_bytes())
        path.unlink()
        return data

    three = gpt(gparts)
    table_expect = [expect(gparts[0], ['TABLE'], True), expect(gparts[1], ['TABLE'], True),
                    expect(gparts[2], ['TABLE'], True, 'partition', False)]
    # No protective MBR: GRUB ignores the GPT.
    data = bytearray(three)
    data[:512] = bytes(512)
    (root / 'gpt-noprotective.img').write_bytes(data)
    manifest['gpt-noprotective.img'] = dict(expect=table_expect, absent=[])
    # Primary header gone too: only the backup GPT is left.
    data[512:1024] = bytes(512)
    (root / 'gpt-backup.img').write_bytes(data)
    manifest['gpt-backup.img'] = dict(expect=table_expect, absent=[])
    # The primary GPT lost the squashfs entry; the backup still has it.
    two = gpt(gparts[:2])
    two[-33 * 512:] = three[-33 * 512:]
    (root / 'gpt-stale.img').write_bytes(two)
    manifest['gpt-stale.img'] = dict(expect=table_expect[2:], absent=[])

    # MBR with an extended partition; the first EBR loses its link, so
    # GRUB lists the first logical partition only.
    path = work / 'ebr.img'
    with open(path, 'wb') as f:
        f.truncate(64 * MIB)
    subprocess.run(['sfdisk', '-q', str(path)], check=True, text=True, input=(
        'label: dos\nsize=16MiB, type=6\ntype=5\nsize=8MiB, type=6\nsize=8MiB, type=83\n'
        'size=8MiB, type=83\n'))
    layout = json.loads(subprocess.run(['sfdisk', '-J', str(path)], check=True,
                                       capture_output=True, text=True).stdout)
    entries = layout['partitiontable']['partitions']
    extended = entries[1]['start'] * 512
    eparts = build([(kind, e['start'] * 512, e['size'] * 512, label) for (kind, label), e in zip(
        (('fat16', 'EBRFAT16'), ('fat12', 'EBRLOG5'), ('ext4', 'EBRLOG6'),
         ('squashfs', 'EBRLOG7')), entries[:1] + entries[2:])])
    data = bytearray(path.read_bytes())
    path.unlink()
    for p in eparts:
        data[p['offset']:p['offset'] + len(p['data'])] = p['data']
    data[extended + 0x1ce:extended + 0x1de] = bytes(16)
    (root / 'ebr.img').write_bytes(data)
    manifest['ebr.img'] = dict(expect=[
        expect(eparts[2], ['TABLE'], True),
        expect(eparts[3], ['TABLE'], True, 'partition', False)], absent=[])


def scan(cli, image, *extra):
    out = subprocess.run([str(cli), '-f', str(image), '-s', '(img0)', *extra],
                         check=True, capture_output=True, text=True).stdout
    lines = out.splitlines()
    header = lines[0].split('\t')
    assert header[0] == 'offset' and header[-1] == 'window', header
    return [dict(zip(header, line.split('\t'))) for line in lines[1:]]


def validate(root, cli):
    manifest = json.loads((root / 'manifest.json').read_text())
    failures = 0
    for key, case in manifest.items():
        name, _, variant = key.partition('#')
        extra = {'ext-backup': ['--scan-ext-backup'], 'deep': ['--scan-deep']}.get(variant, [])
        rows = scan(cli, root / name, *extra)
        found = {int(r['offset']): r for r in rows}
        problems = []
        for e in case['expect']:
            row = found.pop(e['offset'], None)
            if row is None:
                problems.append(f"missing {e['type']} at {e['offset']}")
                continue
            flags = set(row['flags'].split(' | ')) - {'-'}
            want = set(e['flags']) | ({'VERIFIED'} if e['verified'] else set())
            if e['verified'] is None:
                # Whether GRUB reads it does not matter here.
                flags.discard('VERIFIED')
            if row['type'] != e['type'] or flags != want:
                problems.append(f"{e['offset']}: got {row['type']} {sorted(flags)}, "
                                f"want {e['type']} {sorted(want)}")
            if e['verified'] and e['label'] is not None and row['label'] != e['label']:
                problems.append(f"{e['offset']}: label {row['label']!r} != {e['label']!r}")
            if e['files']:
                out = pathlib.Path(tempfile.mkdtemp(prefix='extract-', dir=root))
                sources = []
                for fname in e['files']:
                    sources += ['-e', '(lost0)/' + fname]
                subprocess.run([str(cli), '-f', str(root / name), '-w', row['window'],
                                *sources, '-o', str(out)],
                               check=True, capture_output=True)
                for fname, digest in e['files'].items():
                    path = out / fname
                    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                        problems.append(f"{e['offset']}: {fname} content mismatch")
                shutil.rmtree(out)
        for offset in case['absent']:
            if offset in found:
                problems.append(f'unexpected result at {offset}')
        problems += [f"extra {r['type']} at {o} ({r['flags']})" for o, r in found.items()]
        print(('FAIL ' if problems else 'PASS ') + key)
        for problem in problems:
            print('  ' + problem)
        failures += bool(problems)

    # Window arguments are checked before anything is read.
    image = str(root / 'wiped.img')
    for window, message in (('img0:1000:4096', 'multiple of 512'),
                            ('img0:0:' + str(1 << 40), 'beyond the end'),
                            ('img0:1048576', 'invalid --lost'),
                            ('img0:1048576:16777216:0=16777216+512', 'outside the range'),
                            ('img0:1048576:16777216:0=512', 'invalid --lost'),
                            ('img0:1048576:16777216:0=0+1,0=0+1,0=0+1', 'invalid --lost')):
        r = subprocess.run([str(cli), '-f', image, '-w', window, '-l'],
                           capture_output=True, text=True)
        ok = r.returncode != 0 and message in r.stderr
        print(('PASS ' if ok else 'FAIL ') + 'reject ' + window)
        failures += not ok
    r = subprocess.run([str(cli), '-f', image, '-w', 'img0:1048576:16777216', '-l'],
                       capture_output=True, text=True)
    ok = r.returncode == 0 and '(lost0)' in r.stdout.split()
    print(('PASS ' if ok else 'FAIL ') + 'list (lost0)')
    failures += not ok

    # A volume cut off by the end of the device: its window is clipped.
    truncated = root / 'truncated.img'
    truncated.write_bytes((root / 'wiped.img').read_bytes()[:120 * MIB])
    row = {int(r['offset']): r for r in scan(cli, truncated)}.get(97 * MIB)
    ok = (row is not None and row['flags'] == 'VERIFIED | TRUNCATED'
          and row['window'] == f'img0:{97 * MIB}:{23 * MIB}')
    if ok:
        r = subprocess.run([str(cli), '-f', str(truncated), '-w', row['window'], '-l', '(lost0)/'],
                           capture_output=True, text=True)
        ok = r.returncode == 0 and 'fat32-0.bin' in r.stdout.split()
    truncated.unlink()
    print(('PASS ' if ok else 'FAIL ') + 'truncated volume')
    failures += not ok
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=pathlib.Path)
    parser.add_argument('--generate', action='store_true')
    parser.add_argument('--cli', type=pathlib.Path)
    args = parser.parse_args()
    if args.generate:
        generate(args.root)
    if args.cli:
        raise SystemExit(1 if validate(args.root, args.cli) else 0)


if __name__ == '__main__':
    main()
