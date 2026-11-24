# SPDX-License-Identifier: GPL-2.0-or-later
"""Independently validate this project's single-file uncompressed RAW14 MLV subset.

Not a general MLV decoder or proof of camera/editor compatibility.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

FILE = struct.Struct('<4sI8sQHHIHHIIII')
VIDEO = struct.Struct('<4sIQIHHHHI')


def inspect_mlv(data):
    if len(data) < FILE.size:
        raise ValueError('Truncated MLVI')
    magic, size, version, guid, number, count, flags, video, audio, frames, audios, num, den = FILE.unpack_from(data)
    if magic != b'MLVI' or size != 52 or version != b'v2.0\0\0\0\0':
        raise ValueError('Unsupported MLVI header')
    if number != 0 or count != 1 or video != 1 or audio or audios or not guid or not num or not den:
        raise ValueError('Expected single-file uncompressed RAW without audio')
    offset = size
    geometry = None
    found = []
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError('Truncated block header')
        kind, block_size, timestamp = struct.unpack_from('<4sIQ', data, offset)
        if block_size < 16 or block_size > len(data) - offset:
            raise ValueError('Invalid block bounds')
        if kind == b'RAWI':
            if geometry or found or block_size != 180:
                raise ValueError('Unexpected RAWI layout/order')
            width, height = struct.unpack_from('<HH', data, offset + 16)
            info = struct.unpack_from('<40I', data, offset + 20)
            api, pointer, rh, rw, pitch, byte_count, depth, black, white = info[:9]
            if not width or width % 4 or not height or height % 2:
                raise ValueError('Unsupported RAW14 geometry')
            if (api, pointer, rh, rw, pitch, byte_count, depth) != (1, 0, height, width, width * 7 // 4, width * height * 7 // 4, 14):
                raise ValueError('RAWI geometry/layout mismatch')
            if not 0 <= black < white <= 16383:
                raise ValueError('Invalid calibration levels')
            geometry = {'width': width, 'height': height, 'pitch': pitch, 'frame_bytes': byte_count}
        elif kind == b'VIDF':
            if not geometry or block_size < VIDEO.size:
                raise ValueError('VIDF before RAWI or truncated VIDF')
            _, _, _, frame_number, crop_x, crop_y, pan_x, pan_y, space = VIDEO.unpack_from(data, offset)
            if block_size != VIDEO.size + space + geometry['frame_bytes'] or space > 3:
                raise ValueError('Unexpected VIDF payload size')
            if crop_x or pan_x or crop_y % 2 or pan_y != crop_y:
                raise ValueError('Unsupported crop metadata')
            if found and (frame_number <= found[-1]['number'] or timestamp < found[-1]['timestamp_us']):
                raise ValueError('Frame order/timestamps are not monotonic')
            if not found and frame_number != 0:
                raise ValueError('Expected first frame numbered zero')
            start = offset + VIDEO.size + space
            payload = data[start:offset + block_size]
            found.append({'number': frame_number, 'timestamp_us': timestamp, 'crop_y': crop_y,
                          'payload_sha256': hashlib.sha256(payload).hexdigest()})
        else:
            raise ValueError(f'Block not supported by this validator: {kind!r}')
        offset += block_size
    if geometry is None or len(found) != frames:
        raise ValueError('Missing RAWI or finalized frame count mismatch')
    if found and found[-1]['number'] + 1 != len(found) and not flags & 2:
        raise ValueError('Frame-number gap without dropped-frame flag')
    return {'bytes': len(data), 'frames': found, 'flags': flags, 'fps': [num, den],
            'geometry': geometry, 'structurally_valid': True,
            'camera_or_editor_compatibility_tested': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect_mlv(args.file.read_bytes()), indent=2))
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f'Inspection failed: {error}\n')
