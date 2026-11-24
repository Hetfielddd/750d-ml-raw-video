# SPDX-License-Identifier: GPL-2.0-or-later
"""Read-only, narrow Thumb address-load candidate search for a 750D ROM1 image.

Finds LDR literal T1/T2 and adjacent same-register MOVW/MOVT pairs.
Not a disassembler, control-flow analyzer, function finder, or address verifier.
"""
import argparse
import json
from pathlib import Path
import re
import struct

from inspect_750d_rom import MARKERS, inspect, occurrences

# Use a zero-width lookahead to examine every halfword candidate, including
# overlapping encodings. Code/data boundaries and instruction starts are unknown.
PREFIX = re.compile(rb'(?=(.[\x48-\x4f]|[\xdf\x5f]\xf8|[\x40-\x4f][\xf2\xf6]))', re.DOTALL)


def mov_imm(first, second, opcode):
    if first & 0xfbf0 != opcode or second & 0x8000:
        return None
    register = second >> 8 & 15
    if register >= 13:  # Restrict to R0-R12; omit SP/LR/PC in this narrow subset.
        return None
    value = ((first & 15) << 12 | (first >> 10 & 1) << 11 |
             (second >> 12 & 7) << 8 | second & 255)
    return register, value


def scan(data, targets, base=0xfe000000, limit=16):
    """Return bounded candidates for exact uint32 values, never dereference host RAM."""
    if not 0 <= base <= 0xffffffff or base & 1 or len(data) > 0x100000000 - base:
        raise ValueError('Segment exceeds the 32-bit address space')
    if not 1 <= limit <= 256 or any(not 0 <= value <= 0xffffffff for value in targets):
        raise ValueError('Invalid limit or target address')
    found = {value: {'candidates': [], 'truncated': False} for value in targets}
    for match in PREFIX.finditer(data):
        offset = match.start()
        if offset & 1 or offset + 2 > len(data):
            continue
        first = struct.unpack_from('<H', data, offset)[0]
        pc = ((base + offset + 4) & ~3) & 0xffffffff
        literal = None
        kind = None
        value = None
        if first & 0xf800 == 0x4800:
            register = first >> 8 & 7
            literal = (pc + (first & 255) * 4) & 0xffffffff
            kind = 'ldr-literal-t1'
        elif first in (0xf8df, 0xf85f) and offset + 4 <= len(data):
            second = struct.unpack_from('<H', data, offset + 2)[0]
            register = second >> 12
            if register >= 13:
                continue
            delta = second & 0xfff
            literal = (pc + (delta if first == 0xf8df else -delta)) & 0xffffffff
            kind = 'ldr-literal-t2'
        elif offset + 8 <= len(data):
            second, third, fourth = struct.unpack_from('<HHH', data, offset + 2)
            low = mov_imm(first, second, 0xf240)
            high = mov_imm(third, fourth, 0xf2c0)
            if low is None or high is None or low[0] != high[0]:
                continue
            register = low[0]
            value = low[1] | high[1] << 16
            kind = 'adjacent-movw-movt'
        if literal is not None:
            pool_offset = literal - base
            if not 0 <= pool_offset <= len(data) - 4:
                continue
            value = struct.unpack_from('<I', data, pool_offset)[0]
        if value not in found:
            continue
        entry = found[value]
        if len(entry['candidates']) >= limit:
            entry['truncated'] = True
            continue
        item = {'file_offset': hex(offset), 'instruction_address': hex(base + offset),
                'kind': kind, 'register': register, 'loaded_value': hex(value)}
        if literal is not None:
            item['literal_address'] = hex(literal)
            item['literal_file_offset'] = hex(literal - base)
        entry['candidates'].append(item)
    return found


def report(data, markers=MARKERS, limit=16):
    identity = inspect(data)  # Enforces full ROM1 layout and rejects the FIR container.
    if not identity['matches_upstream_750d_110_signature']:
        raise ValueError('Input does not match the upstream 750D 1.1.0 additive signature')
    targets = {}
    labels = []
    for marker in markers:
        hits, truncated = occurrences(data, marker + b'\0', limit)
        for offset in hits:
            addresses = [base + offset for base in (0xfc000000, 0xfe000000)]
            for address in addresses:
                targets[address] = True
            labels.append({'marker': marker.decode('ascii'), 'file_offset': hex(offset),
                           'marker_search_truncated': truncated, 'addresses': addresses})
    scans = {base: scan(data, targets, base, limit) for base in (0xfc000000, 0xfe000000)}
    for label in labels:
        addresses = label.pop('addresses')
        label['address_load_candidates'] = {
            hex(base): {hex(address): scans[base][address] for address in addresses}
            for base in scans}
    return {'sha256': identity['sha256'], 'signature_matches': True,
            'cryptographic_authenticity_verified': False, 'markers': labels,
            'limitations': 'Scans aligned byte patterns without code/data boundaries. '
            'Hits may be data or the second half of another instruction. No execution, '
            'function identification, provenance validation, or RAW address verification. '
            'Only literal loads and adjacent same-register MOVW/MOVT are covered.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rom', type=Path)
    parser.add_argument('--marker', action='append', help='Exact NUL-terminated ASCII marker; repeatable')
    parser.add_argument('--limit', type=int, default=16)
    args = parser.parse_args()
    try:
        markers = tuple(m.encode('ascii') for m in args.marker) if args.marker else MARKERS
        if any(not m or b'\0' in m for m in markers) or not 1 <= args.limit <= 256:
            raise ValueError('Use nonempty ASCII markers without NUL and limit 1..256')
        print(json.dumps(report(args.rom.read_bytes(), markers, args.limit), indent=2))
    except (OSError, ValueError, UnicodeError) as error:
        parser.exit(1, f'Analysis failed: {error}\n')


if __name__ == '__main__':
    main()
