# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import unittest

from decrypt_750d_fir import parse_records, decrypt


def checksum(data):
    struct.pack_into('<I', data, 0, (~sum(data[4:])) & 0xffffffff)
    return data


def fixture():
    data = bytearray(88)
    struct.pack_into('<4I', data, 16, 2, 32, 24, 8)
    struct.pack_into('<6I', data, 32, 1, 0x100, 80, 4, 0xfc0a0000, 0)
    struct.pack_into('<6I', data, 56, 2, 0x100, 84, 4, 0xfd540000, 0)
    data[80:] = b'abcdefgh'
    return checksum(data)


class RecordTests(unittest.TestCase):
    def test_valid_disjoint_records_and_preserved_input(self):
        data = fixture()
        before = bytes(data)
        records = parse_records(data)
        self.assertEqual([r['destination'] for r in records], ['0xfc0a0000', '0xfd540000'])
        self.assertEqual([r['bytes'] for r in records], [4, 4])
        self.assertEqual(bytes(data), before)

    def test_truncated_and_corrupted_container(self):
        for data in (bytes(20), fixture()[:-1]):
            with self.assertRaises(ValueError):
                parse_records(data)
        data = fixture()
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'checksum'):
            parse_records(data)

    def test_forged_metadata_with_recomputed_checksum(self):
        # Unsafe counts, wrong stride/tail, duplicate ID, overlap, table access,
        # integer-sized overrun and zero-length records must all be rejected.
        for offset, value in ((16, 0xffffffff), (20, 0), (24, 28), (28, 7),
                              (56, 1), (64, 82), (40, 0), (44, 0xffffffff), (44, 0)):
            with self.subTest(offset=offset, value=value):
                data = fixture()
                struct.pack_into('<I', data, offset, value)
                with self.assertRaises(ValueError):
                    parse_records(checksum(data))

    def test_unidentified_rom_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, 'identified public 70D'):
            decrypt(b'not a ROM', b'not a FIR')


if __name__ == '__main__':
    unittest.main()
