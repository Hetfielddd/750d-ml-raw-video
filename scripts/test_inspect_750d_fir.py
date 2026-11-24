# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import unittest

from inspect_750d_fir import inspect_bytes


def checksum(data):
    value = ~(sum(data[:0x20]) + sum(data[0x24:])) & 0xffffffff
    struct.pack_into('<I', data, 0x20, value)
    return data


def fixture():
    data = bytearray(0x1c0)
    struct.pack_into('<I', data, 0, 0x80000393)
    data[0x10:0x15] = b'1.1.0'
    for offset, value in ((0x24, 0xb0), (0x28, 0x120), (0x30, 0x130),
                          (0x38, len(data)), (0xb0, 16), (0xb4, 16)):
        struct.pack_into('<I', data, offset, value)
    data[0xc0] = 1
    struct.pack_into('<III', data, 0x130, 0x10, 0x80, 0x90)
    struct.pack_into('<II', data, 0x140, 16, 8)
    return checksum(data)


class FirInspectionTests(unittest.TestCase):
    def test_extended_header_skips_legacy_extraction_and_preserves_input(self):
        data = fixture()
        original = bytes(data)
        result = inspect_bytes(data)
        self.assertEqual(result['legacy_xor_extraction_policy'], 'skip_extended_header')
        self.assertFalse(result['decrypted'])
        self.assertFalse(result['signature_authenticity_verified'])
        self.assertEqual(result['updater_ciphertext_bytes'], 16)
        self.assertEqual(result['firmware_declared_content_bytes'], 8)
        self.assertEqual(data, original)

    def test_zero_header_is_not_a_decryption_success(self):
        data = fixture()
        data[0xc0] = 0
        result = inspect_bytes(checksum(data))
        self.assertEqual(result['legacy_xor_extraction_policy'], 'legacy_check_only')
        self.assertFalse(result['decrypted'])

    def test_rejects_overlap_and_inconsistent_lengths_with_valid_checksums(self):
        for offset, value in ((0xb0, 17), (0xb4, 17), (0x140, 17), (0x144, 17),
                              (0x130, 0x11), (0x24, 0xaf), (0xb4, 0)):
            with self.subTest(offset=offset, value=value):
                data = fixture()
                struct.pack_into('<I', data, offset, value)
                with self.assertRaises(ValueError):
                    inspect_bytes(checksum(data))

    def test_rejects_wrong_identity_truncation_and_corruption(self):
        data = fixture()
        for modified in (data[:100], data[:-1], bytearray(data)):
            if len(modified) == len(data):
                modified[-1] ^= 1
            with self.assertRaises(ValueError):
                inspect_bytes(modified)
        struct.pack_into('<I', data, 0, 0x80000394)
        with self.assertRaises(ValueError):
            inspect_bytes(checksum(data))


if __name__ == '__main__':
    unittest.main()
