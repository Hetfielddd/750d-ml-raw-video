# SPDX-License-Identifier: GPL-2.0-or-later
"""Inspect a user-supplied ROM image without executing or modifying it.

Expected layout: a 32 MiB DIGIC 6 ROM1 image mapped at 0xFC000000.
The 0xFE000000 alias uses the same file offsets (QEMU EOS model).
The upstream additive signature is not a cryptographic authenticity check.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROM_SIZE = 0x02000000
ENTRY_OFFSET = 0x000A0000
SIGNATURE_WORDS = 0x10000
EXPECTED_SIGNATURE = 0xF005931A
MARKERS = (b'lv_raw_dump', b'lv_save_raw', b'lv_af_raw', b'lv_set_raw',
           b'CCDWriteEDmacCompleteCBR', b'evfReadOutDoneInterrupt', b'OmarInit',
           b'[MEM1DEV] Addr=%#x Data=%#x', b'Mem1 is Not Complete',
           b'Nothing DMA ch now!', b'ResInfo')


def occurrences(data, needle, limit=16):
    """Return bounded search results; additional hits are explicitly flagged."""
    offsets = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return offsets, False
        if len(offsets) == limit:
            return offsets, True
        offsets.append(offset)
        start = offset + 1


def inspect(data):
    if len(data) >= 0x15 and data[:4] == struct.pack('<I', 0x80000393):
        raise ValueError('Canon update container detected; provide plaintext ROM1, not FIR')
    if len(data) != ROM_SIZE:
        raise ValueError(f'Expected a full {ROM_SIZE}-byte ROM1 image; got {len(data)}')
    window = memoryview(data)[ENTRY_OFFSET:ENTRY_OFFSET + SIGNATURE_WORDS * 4]
    signature = sum(word[0] for word in struct.iter_unpack('<I', window)) & 0xffffffff
    markers = []
    for marker in MARKERS:
        hits, truncated = occurrences(data, marker)
        for offset in hits:
            references = {}
            for base in (0xFC000000, 0xFE000000):
                address = base + offset
                refs, capped = occurrences(data, struct.pack('<I', address))
                references[hex(address)] = {
                    'file_offsets': [hex(ref) for ref in refs], 'truncated': capped}
            markers.append({'marker': marker.decode('ascii'), 'file_offset': hex(offset),
                            'marker_search_truncated': truncated,
                            'literal_pointer_candidates': references})
    return {
        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
        'signature_window_offset': hex(ENTRY_OFFSET),
        'signature_window_bytes': SIGNATURE_WORDS * 4,
        'additive_signature': hex(signature), 'expected_signature': hex(EXPECTED_SIGNATURE),
        'matches_upstream_750d_110_signature': signature == EXPECTED_SIGNATURE,
        'cryptographic_authenticity_verified': False,
        'markers': markers,
        'limitations': 'A matching sum does not prove authenticity or completeness. '
                      'Literal pointers are candidates, not verified code references. '
                      'No Thumb instruction analysis or RAW address validation is performed.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rom', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.rom.read_bytes()), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f'Inspection failed: {error}\n')


if __name__ == '__main__':
    main()
