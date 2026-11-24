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
    struct.pack_into('<I', data, 0x44, 4)
    for index, (start, size) in enumerate(((0, 0x20), (0x24, 0x44),
                                          (0xb0, 0x80), (0x130, 0x90))):
        struct.pack_into('<II', data, 0x48 + 8 * index, start, size)
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
        self.assertTrue(result['region_descriptors_match_sections'])
        self.assertFalse(result['authentication_algorithm_verified'])
        self.assertEqual(result['crypto_headers'][0]['bytes'], 112)
        self.assertEqual(result['crypto_headers'][1]['opaque_fields'][-1],
                         {'file_offset': '0x190', 'bytes': 32})

    def test_rejects_forged_region_map_even_with_recomputed_checksum(self):
        # Mutation cases cover an out-of-file end, overlap, omission, a wrong
        # count and a table pointing into the authentication slots.
        for offset, value in ((0x44, 5), (0x44, 0), (0x48, 0x68),
                              (0x4c, 0x21), (0x58, 0xaf),
                              (0x5c, 0x81), (0x64, 0xffffffff)):
            with self.subTest(offset=offset, value=value):
                data = fixture()
                struct.pack_into('<I', data, offset, value)
                with self.assertRaisesRegex(ValueError, 'region|Region'):
                    inspect_bytes(checksum(data))

    def test_rejects_unaligned_extended_ciphertext(self):
        data = fixture()
        struct.pack_into('<II', data, 0xb0, 15, 15)
        with self.assertRaisesRegex(ValueError, 'aligned'):
            inspect_bytes(checksum(data))

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
