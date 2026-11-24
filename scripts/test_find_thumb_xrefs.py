# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import unittest

from find_thumb_xrefs import scan, report
from inspect_750d_rom import ROM_SIZE, ENTRY_OFFSET, EXPECTED_SIGNATURE


class ThumbCandidateTests(unittest.TestCase):
    def test_adr_encodings_and_pc_alignment(self):
        # ADR T1 at 0x1002; ADDW/SUBW use aligned PC as well.
        data = b'\0\0' + struct.pack('<HHHHH', 0xa101, 0xf20f, 0x0210,
                                     0xf2af, 0x0304)
        result = scan(data, {0x1008, 0x1018}, base=0x1000)
        self.assertEqual([(h['file_offset'], h['kind'], h['register'])
                          for h in result[0x1008]['candidates']],
                         [('0x2', 'adr-t1', 1), ('0x8', 'adr-t2', 3)])
        self.assertEqual(result[0x1018]['candidates'][0]['register'], 2)

    def test_adr_high_immediate_and_invalid_register(self):
        # imm12 = i:imm3:imm8 = 0xabc; T3 adds and T2 subtracts.
        data = struct.pack('<HHHH', 0xf60f, 0x22bc, 0xf6af, 0x23bc)
        result = scan(data, {0x1ac0, 0x54c}, base=0x1000)
        self.assertEqual(result[0x1ac0]['candidates'][0]['kind'], 'adr-t3')
        self.assertEqual(result[0x54c]['candidates'][0]['kind'], 'adr-t2')
        for second in (0x8abc, 0x2dbc, 0x2ebc, 0x2fbc):
            invalid = struct.pack('<HH', 0xf60f, second)
            self.assertFalse(scan(invalid, {0x1ac0}, 0x1000)[0x1ac0]['candidates'])
        self.assertFalse(scan(b'\x0f\xf2', {0x1004}, 0x1000)[0x1004]['candidates'])

    def test_pc_alignment_and_literal_bounds(self):
        # T1 at address 0x1002 uses Align(PC+4,4)==0x1004, plus imm8*4.
        data = b'\0\0' + struct.pack('<H', 0x4801) + b'\0' * 4 + struct.pack('<I', 0x12345678)
        hit = scan(data, {0x12345678: True}, base=0x1000)[0x12345678]['candidates']
        self.assertEqual([(h['file_offset'], h['literal_file_offset']) for h in hit], [('0x2', '0x8')])
        self.assertFalse(scan(data[:10], {0x12345678: True}, 0x1000)[0x12345678]['candidates'])

    def test_caps_and_odd_offsets(self):
        data = struct.pack('<HHI', 0x4800, 0x4900, 0x11223344)
        result = scan(data, {0x11223344: True}, 0x1000, limit=1)[0x11223344]
        self.assertEqual(len(result['candidates']), 1)
        self.assertTrue(result['truncated'])
        data = b'\0' + struct.pack('<H', 0x4800) + b'\0' * 5
        self.assertFalse(scan(data, {0: True}, 0x1000)[0]['candidates'])

    def test_truncated_wide_instruction_and_wrong_value(self):
        self.assertFalse(scan(b'\xdf\xf8', {0: True}, 0x1000)[0]['candidates'])
        data = struct.pack('<HHI', 0xf8df, 0x0000, 123)
        self.assertFalse(scan(data, {124: True}, 0x1000)[124]['candidates'])

    def test_address_space_and_limit(self):
        for base, size, limit in ((0xffffffff, 2, 16), (0x1001, 4, 16), (0x1000, 4, 0)):
            with self.assertRaises(ValueError):
                scan(bytes(size), {}, base, limit)

    def test_cli_report_rejects_fir_and_partial_dump(self):
        for data in (struct.pack('<I', 0x80000393) + bytes(32), bytes(64)):
            with self.assertRaises(ValueError):
                report(data)

    def test_full_synthetic_rom_report_and_both_aliases(self):
        data = bytearray(ROM_SIZE)
        data[0x100:0x10c] = b'lv_save_raw\0'
        struct.pack_into('<HHI', data, 0x200, 0x4800, 0xbf00, 0xfe000100)
        # Deliberately forge the additive sum: this must not imply authenticity.
        struct.pack_into('<I', data, ENTRY_OFFSET, EXPECTED_SIGNATURE)
        result = report(data, (b'lv_save_raw',))
        self.assertTrue(result['signature_matches'])
        self.assertFalse(result['cryptographic_authenticity_verified'])
        marker = result['markers'][0]
        self.assertEqual(marker['file_offset'], '0x100')
        for base, address in (('0xfc000000', '0xfc000200'), ('0xfe000000', '0xfe000200')):
            hit = marker['address_load_candidates'][base]['0xfe000100']['candidates'][0]
            self.assertEqual(hit['instruction_address'], address)
            self.assertEqual(hit['literal_file_offset'], '0x204')
        data[ENTRY_OFFSET] ^= 1
        with self.assertRaises(ValueError):
            report(data, (b'lv_save_raw',))


if __name__ == '__main__':
    unittest.main()
