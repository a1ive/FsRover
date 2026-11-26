#!/usr/bin/env python3
"""Generate grub/grub-core/fs/fmod_vorbis.h from vgmstream's FSB setup table.

FSB5 Vorbis streams drop the three Vorbis header packets and keep only the
CRC32 of the setup packet FMOD's encoder used.  vgmstream ships those setup
packets (extracted from FMOD by python-fsb5) in
src/coding/libs/vorbis_codebooks_fsb.h; this script packs them into one
xz stream for grub's xzembed decoder and records, per setup, the mode
blockflags an Ogg remuxer needs to compute granule positions.

Every setup is parsed in full per the Vorbis I specification, so a packet
that does not decode to the end (framing bit set, only zero padding left)
or whose CRC32 does not match its id is rejected rather than emitted.

usage: python scripts/gen_fmod_vorbis.py [VGMSTREAM_DIR] [OUT_HEADER]
"""

import lzma
import os
import re
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join(ROOT, 'ref', 'vgmstream')
DEFAULT_OUT = os.path.join(ROOT, 'grub', 'grub-core', 'fs', 'fmod_vorbis.h')
TABLE = os.path.join('src', 'coding', 'libs', 'vorbis_codebooks_fsb.h')


class Bits:
	def __init__(self, data):
		self.data = data
		self.pos = 0

	def read(self, count):
		val = 0
		for i in range(count):
			byte = self.pos >> 3
			if byte >= len(self.data):
				raise ValueError('setup packet truncated')
			val |= ((self.data[byte] >> (self.pos & 7)) & 1) << i
			self.pos += 1
		return val


def ilog(val):
	ret = 0
	while val > 0:
		ret += 1
		val >>= 1
	return ret


def lookup1_values(entries, dims):
	ret = int(entries ** (1.0 / dims))
	while (ret + 1) ** dims <= entries:
		ret += 1
	while ret ** dims > entries:
		ret -= 1
	return ret


def parse_setup(packet, channels):
	"""Returns the list of mode blockflags, raising ValueError when PACKET
	does not parse as a Vorbis setup header for CHANNELS channels."""
	if packet[:7] != b'\x05vorbis':
		raise ValueError('not a setup header')
	br = Bits(packet[7:])

	for _ in range(br.read(8) + 1):
		if br.read(24) != 0x564342:
			raise ValueError('bad codebook sync')
		dims = br.read(16)
		entries = br.read(24)
		if br.read(1):
			cur = 0
			br.read(5)
			while cur < entries:
				cur += br.read(ilog(entries - cur))
			if cur > entries:
				raise ValueError('codebook lengths overrun')
		else:
			sparse = br.read(1)
			for _ in range(entries):
				if not sparse or br.read(1):
					br.read(5)
		lookup = br.read(4)
		if lookup in (1, 2):
			br.read(32)
			br.read(32)
			bits = br.read(4) + 1
			br.read(1)
			count = (lookup1_values(entries, dims) if lookup == 1
				 else entries * dims)
			br.read(bits * count)
		elif lookup != 0:
			raise ValueError('bad codebook lookup type')

	for _ in range(br.read(6) + 1):
		if br.read(16) != 0:
			raise ValueError('bad time domain transform')

	floors = br.read(6) + 1
	for _ in range(floors):
		kind = br.read(16)
		if kind == 0:
			br.read(8 + 16 + 16 + 6 + 8)
			br.read(8 * (br.read(4) + 1))
		elif kind == 1:
			parts = br.read(5)
			classes = [br.read(4) for _ in range(parts)]
			dims = []
			for _ in range(max(classes) + 1 if classes else 0):
				dims.append(br.read(3) + 1)
				sub = br.read(2)
				if sub:
					br.read(8)
				br.read(8 * (1 << sub))
			br.read(2)
			rangebits = br.read(4)
			for cls in classes:
				br.read(rangebits * dims[cls])
		else:
			raise ValueError('bad floor type')

	residues = br.read(6) + 1
	for _ in range(residues):
		if br.read(16) > 2:
			raise ValueError('bad residue type')
		br.read(24 + 24 + 24)
		classifications = br.read(6) + 1
		br.read(8)
		cascade = []
		for _ in range(classifications):
			low = br.read(3)
			high = br.read(5) if br.read(1) else 0
			cascade.append(high * 8 + low)
		for val in cascade:
			for bit in range(8):
				if val & (1 << bit):
					br.read(8)

	mappings = br.read(6) + 1
	for _ in range(mappings):
		if br.read(16) != 0:
			raise ValueError('bad mapping type')
		submaps = br.read(4) + 1 if br.read(1) else 1
		if br.read(1):
			for _ in range(br.read(8) + 1):
				mag = br.read(ilog(channels - 1))
				ang = br.read(ilog(channels - 1))
				if mag == ang or mag >= channels or ang >= channels:
					raise ValueError('bad channel coupling')
		if br.read(2) != 0:
			raise ValueError('bad mapping reserved bits')
		if submaps > 1:
			for _ in range(channels):
				if br.read(4) >= submaps:
					raise ValueError('bad mapping mux')
		for _ in range(submaps):
			br.read(8)
			if br.read(8) >= floors or br.read(8) >= residues:
				raise ValueError('bad submap')

	flags = []
	for _ in range(br.read(6) + 1):
		flags.append(br.read(1))
		if br.read(16) != 0 or br.read(16) != 0:
			raise ValueError('bad mode window/transform')
		if br.read(8) >= mappings:
			raise ValueError('bad mode mapping')
	if br.read(1) != 1:
		raise ValueError('missing framing bit')

	tail = br.pos
	if (tail + 7) >> 3 != len(br.data):
		raise ValueError('trailing bytes after setup header')
	if br.data[-1] >> (tail & 7 or 8):
		raise ValueError('nonzero padding after framing bit')
	return flags


def mode_flags(packet):
	"""The blockflags are the same for every channel count the coupling
	steps admit; insist on that instead of guessing the count."""
	found = {}
	for channels in range(1, 33):
		try:
			found[channels] = tuple(parse_setup(packet, channels))
		except ValueError:
			pass
	if not found:
		raise ValueError('setup header does not parse')
	results = set(found.values())
	if len(results) != 1:
		raise ValueError('mode table depends on the channel count')
	return list(results.pop())


def main():
	src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
	out = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
	with open(os.path.join(src, TABLE), encoding='utf-8') as fp:
		text = fp.read()

	blobs = {}
	for m in re.finditer(r'static const uint8_t vcb_([0-9a-f]+)\[\] = \{(.*?)\};',
			     text, re.S):
		blobs[int(m.group(1), 16)] = bytes(
			int(x, 16) for x in re.findall(r'0x([0-9a-f]{2})', m.group(2)))
	index = [int(m.group(1), 16) for m in re.finditer(
		r'\{0x([0-9a-f]+),0x[0-9a-f]+,vcb_[0-9a-f]+\}', text)]
	if not blobs or sorted(index) != sorted(blobs):
		sys.exit('unexpected layout of ' + TABLE)

	rows = []
	raw = bytearray()
	for crc in sorted(blobs):
		blob = blobs[crc]
		if zlib.crc32(blob) != crc:
			sys.exit('setup %08x: CRC32 mismatch' % crc)
		if len(blob) > 0xFFFF:
			sys.exit('setup %08x: too large' % crc)
		try:
			flags = mode_flags(blob)
		except ValueError as err:
			sys.exit('setup %08x: %s' % (crc, err))
		mask = 0
		for i, flag in enumerate(flags):
			mask |= flag << i
		rows.append((crc, len(raw), len(blob), len(flags), mask))
		raw += blob

	packed = lzma.compress(bytes(raw), format=lzma.FORMAT_XZ,
			       check=lzma.CHECK_NONE,
			       filters=[{'id': lzma.FILTER_LZMA2,
					 'preset': 9 | lzma.PRESET_EXTREME,
					 'dict_size': 1 << 20}])
	if lzma.decompress(packed) != bytes(raw):
		sys.exit('xz round trip failed')

	lines = [
		'/*',
		' *  Generated by scripts/gen_fmod_vorbis.py -- do not edit.',
		' *',
		' *  FMOD FSB5 Vorbis setup headers, keyed by their CRC32, from',
		' *  vgmstream src/coding/libs/vorbis_codebooks_fsb.h (extracted from',
		' *  FMOD by python-fsb5).  vgmstream is distributed under an ISC-style',
		' *  license, see THIRD_PARTY_NOTICES.txt.',
		' *',
		' *  The packets are stored back to back in one xz stream (LZMA2, no',
		' *  integrity check: every packet is verified against its CRC32 id).',
		' *  modes/blockflags describe the mode table at the end of each setup',
		' *  header, so audio packets can be sized without parsing it.',
		' */',
		'',
		'#define FMOD_VORBIS_RAW_SIZE\t%u' % len(raw),
		'#define FMOD_VORBIS_COUNT\t%u' % len(rows),
		'',
		'struct fmod_vorbis_setup',
		'{',
		'\tgrub_uint32_t crc;',
		'\tgrub_uint32_t off;',
		'\tgrub_uint16_t size;',
		'\tgrub_uint8_t modes;',
		'\tgrub_uint64_t blockflags;',
		'};',
		'',
		'static const struct fmod_vorbis_setup fmod_vorbis_setups[FMOD_VORBIS_COUNT] =',
		'{',
	]
	for crc, off, size, modes, mask in rows:
		lines.append('\t{ 0x%08x, 0x%05x, 0x%04x, %2u, 0x%x },'
			     % (crc, off, size, modes, mask))
	lines += ['};', '',
		  'static const grub_uint8_t fmod_vorbis_xz[%u] =' % len(packed),
		  '{']
	for i in range(0, len(packed), 16):
		lines.append('\t' + ','.join('0x%02x' % b for b in packed[i:i + 16]) + ',')
	lines += ['};', '']

	with open(out, 'w', encoding='ascii', newline='\r\n') as fp:
		fp.write('\n'.join(lines))
	print('%s: %u setups, %u bytes raw, %u bytes xz'
	      % (out, len(rows), len(raw), len(packed)))


if __name__ == '__main__':
	main()
