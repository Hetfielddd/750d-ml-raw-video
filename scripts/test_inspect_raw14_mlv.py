# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import unittest
from inspect_raw14_mlv import FILE, VIDEO, inspect_mlv


def fixture():
    # Independent synthetic fixture, not produced by the C writer.
    header = FILE.pack(b'MLVI', 52, b'v2.0\0\0\0\0', 1, 0, 1, 0, 1, 0, 1, 0, 24, 1)
    info = [0] * 40
    info[:9] = [1, 0, 2, 4, 7, 14, 14, 0, 16383]
    rawi = struct.pack('<4sIQHH40I', b'RAWI', 180, 0, 4, 2, *info)
    video = VIDEO.pack(b'VIDF', 48, 0, 0, 0, 0, 0, 0, 2)
    return header + rawi + video + bytes(2) + bytes(range(14))


class MlvInspectionTests(unittest.TestCase):
    def test_accepts_padded_small_frame(self):
        report = inspect_mlv(fixture())
        self.assertEqual(report['geometry']['frame_bytes'], 14)
        self.assertEqual(len(report['frames']), 1)

    def test_rejects_truncated_payload(self):
        with self.assertRaisesRegex(ValueError, 'bounds'):
            inspect_mlv(fixture()[:-1])

    def test_rejects_incorrect_final_count(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 36, 2)
        with self.assertRaisesRegex(ValueError, 'count'):
            inspect_mlv(data)

    def test_rejects_oversized_padding(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 232 + 28, 0xffffffff)
        with self.assertRaisesRegex(ValueError, 'payload'):
            inspect_mlv(data)

    def test_rejects_raw_metadata_mismatch(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 52 + 20 + 24, 12)
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            inspect_mlv(data)


if __name__ == '__main__':
    unittest.main()
