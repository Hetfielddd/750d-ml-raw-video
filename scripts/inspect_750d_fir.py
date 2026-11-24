# SPDX-License-Identifier: GPL-2.0-or-later
"""Read-only structural check of the Canon 750D 1.1.0 update container.

Does not decrypt, execute or write firmware; all output goes to stdout.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path


def inspect(path):
    return inspect_bytes(path.read_bytes())


def inspect_bytes(data):
    if len(data) < 0x120:
        raise ValueError('File too short for the expected container')
    u32 = lambda offset: struct.unpack_from('<I', data, offset)[0]
    if u32(0) != 0x80000393 or data[0x10:0x15] != b'1.1.0':
        raise ValueError('Expected Canon 750D model ID and version 1.1.0')
    if u32(0x38) != len(data):
        raise ValueError('Container length does not match header')
    calculated = (~(sum(data[:0x20]) + sum(data[0x24:]))) & 0xffffffff
    if calculated != u32(0x20):
        raise ValueError('Container checksum mismatch')
    header, updater, firmware = u32(0x24), u32(0x28), u32(0x30)
    if not (0x78 <= header < updater < firmware <= len(data) - 12):
        raise ValueError('Invalid section offsets')
    if header != 0xb0 or updater != 0x120:
        raise ValueError('Unsupported 750D updater header layout')
    updater_bytes, updater_declared = struct.unpack_from('<II', data, header)
    if not (0 < updater_declared <= updater_bytes <= firmware - updater):
        raise ValueError('Invalid updater lengths or overlap with firmware')
    dec, enc, size = struct.unpack_from('<III', data, firmware)
    if not (12 <= dec < enc < size and firmware + size == len(data)):
        raise ValueError('Invalid firmware section bounds')
    if dec + 0x70 != enc:
        raise ValueError('Unsupported firmware encryption-header layout')
    firmware_bytes, firmware_declared = struct.unpack_from('<II', data, firmware + dec)
    if not (0 < firmware_declared <= firmware_bytes == size - enc):
        raise ValueError('Invalid firmware ciphertext or declared content lengths')
    extended = any(data[header + 0x10:updater])
    return {
        'model': 'Canon EOS 750D', 'version': '1.1.0',
        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
        'container_checksum_valid': True,
        'signature_authenticity_verified': False,
        'updater_offset': hex(updater), 'firmware_section_offset': hex(firmware),
        'updater_ciphertext_bytes': updater_bytes,
        'updater_declared_content_bytes': updater_declared,
        'firmware_ciphertext_bytes': firmware_bytes,
        'firmware_declared_content_bytes': firmware_declared,
        'encrypted_payload_offset': hex(firmware + enc),
        'nonzero_extended_crypto_header': extended,
        'legacy_xor_extraction_policy': 'skip_extended_header' if extended else 'legacy_check_only',
        'crypto_classification_is_header_heuristic': True,
        'decrypted': False,
        'note': 'Structural validation only; this file is not a ROM dump.'
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('firmware', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.firmware), indent=2))
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f'Inspection failed: {error}\n')
