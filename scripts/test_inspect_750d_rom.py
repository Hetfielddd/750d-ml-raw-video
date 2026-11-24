# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic parser tests, not camera or firmware validation."""
import struct
import unittest
from inspect_750d_rom import inspect, occurrences, ROM_SIZE, ENTRY_OFFSET


class RomInspectionTests(unittest.TestCase):
    def test_rejects_update_container(self):
        with self.assertRaisesRegex(ValueError, 'container'):
            inspect(struct.pack('<I', 0x80000393) + bytes(32))

    def test_rejects_truncated_dump(self):
        with self.assertRaisesRegex(ValueError, 'full'):
            inspect(bytes(0x10000))

    def test_word_count_wraparound_and_alias_candidates(self):
        data = bytearray(ROM_SIZE)
        struct.pack_into('<I', data, ENTRY_OFFSET, 0xffffffff)
        # This word is outside a mistaken 64 KiB window but inside 64K words.
        struct.pack_into('<I', data, ENTRY_OFFSET + 0x10000, 3)
        # This word is just outside the correct signature window.
        struct.pack_into('<I', data, ENTRY_OFFSET + 0x40000, 99)
        data[0x200:0x20b] = b'lv_raw_dump'
        struct.pack_into('<I', data, 0x300, 0xfc000200)
        struct.pack_into('<I', data, 0x304, 0xfe000200)
        result = inspect(data)
        self.assertEqual(result['additive_signature'], '0x2')
        self.assertFalse(result['matches_upstream_750d_110_signature'])
        self.assertEqual(result['markers'][0]['literal_pointer_candidates']['0xfc000200']['file_offsets'], ['0x300'])
        self.assertEqual(result['markers'][0]['literal_pointer_candidates']['0xfe000200']['file_offsets'], ['0x304'])

    def test_reports_capped_results(self):
        self.assertEqual(occurrences(b'aaaa', b'a', limit=2), ([0, 1], True))
        self.assertEqual(occurrences(b'aa', b'a', limit=2), ([0, 1], False))


if __name__ == '__main__':
    unittest.main()
