# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute a bounded 750D geometry route with supplied RAM, without MMIO.

Copies caller fields through actual publishers, calculates RAW row size, and
packs a DMA descriptor. Does not determine live camera resolution or capture
pixels. Invalid synthetic cases characterize truncation, not supported modes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from decrypt_750d_fir import MAIN_SHA256


def probe(data):
    if len(data) != 0xcfb688 or hashlib.sha256(data).hexdigest() != MAIN_SHA256:
        raise ValueError('Expected the identified 750D 1.1.0 main-code record')
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                         UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R5,
                                   UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_SP,
                                   UC_ARM_REG_LR)
    base, stop, stack = 0xfe0a0000, 0x10f000, 0x10d000
    caller, driver, published = 0x100000, 0x101000, 0x6b31c
    config, state, shadow = published + 0x74, 0x1ac2220, 0x200000
    delta = 0x7e7473e0  # Scoped driver/table correspondence from destination probe.
    definitions = (
        ('aligned_14_bit', 2048, 1080, 0),
        ('aligned_16_bit', 2048, 1080, 1),
        ('different_width_14_bit', 1984, 1080, 0),
        ('different_height_14_bit', 2056, 720, 0),
        ('invalid_unaligned_width', 9, 3, 0),
        ('invalid_zero_height', 2048, 0, 0),
    )
    results = []
    for name, width, height, wide in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for runtime, size in ((0x8000c000, 4096), (0x8000f000, 4096)):
            offset = runtime + delta - base
            if offset < 0 or offset + size > len(data):
                raise RuntimeError('Driver alias outside identified record')
            uc.mem_map(runtime, size, UC_PROT_READ | UC_PROT_EXEC)
            uc.mem_write(runtime, data[offset:offset + size])
        for address, size in ((0x100000, 0xe000), (0x6b000, 4096),
                              (0x1ac2000, 4096), (0x1ac4000, 4096),
                              (shadow, 0x60000)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        # Fields belong to a dynamic caller structure. These are fixture values,
        # never observations from an owner's camera or assertions of its modes.
        for offset, value in ((108, 34), (112, wide), (116, width),
                              (120, height), (124, 1)):
            put(caller + offset, value)
        put(state + 28, 1)
        put(0x1ac40a4, shadow)
        ranges = ((0xfe2b9280, 0xfe2b92ae), (0xfe309f14, 0xfe309fae),
                  (0xfe28d9f6, 0xfe28da36), (0xfe83952c, 0xfe839536),
                  (0xfe83954e, 0xfe839560), (0x8000c67e, 0x8000c700),
                  (0x8000c454, 0x8000c460))
        done, errors = [], []
        boundary = [stop]

        def code_guard(emulator, address, size, _):
            if address == boundary[0]:
                done.append(True)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            allowed = ((stack - 256, stack + 0x130), (driver, driver + 0x120),
                       (published + 0x54, published + 0x124))
            if not any(lo <= address and address + size <= hi for lo, hi in allowed):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def run(entry, end):
            done.clear()
            boundary[0] = end
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            uc.emu_start(entry | 1, stop + 4, count=512, timeout=500_000)
            if errors or not done:
                raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')

        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_R4, caller)
        run(0xfe2b9280, 0xfe2b92ae)
        uc.reg_write(UC_ARM_REG_R0, stack + 0xc0)
        run(0xfe309f14, stop)
        expected = (34, wide, width, height, 1)
        if tuple(word(config + 124 + i * 4) for i in range(5)) != expected:
            raise RuntimeError('Geometry not propagated through native publisher')

        uc.reg_write(UC_ARM_REG_R4, config)
        uc.reg_write(UC_ARM_REG_R1, driver)
        uc.reg_write(UC_ARM_REG_R8, 0)
        run(0xfe28d9f6, 0xfe28da36)
        if word(driver + 144) != 1:
            raise RuntimeError('Wrong native channel selection')
        if tuple(word(driver + 148 + i * 4) for i in range(5)) != expected:
            raise RuntimeError('Wrong native driver geometry fields')

        uc.reg_write(UC_ARM_REG_R4, driver + 144)
        run(0xfe83952c, 0xfe839536)  # Stops before format-register write.
        bits = uc.reg_read(UC_ARM_REG_R7)
        if bits != (16 if wide else 14):
            raise RuntimeError('Wrong native row-size bit multiplier')
        # The surrounding initializer clears this descriptor via memset.
        # Supply zeroed scratch explicitly; that initializer is not executed.
        uc.mem_write(stack + 4, bytes(48))
        uc.reg_write(UC_ARM_REG_R5, state)
        run(0xfe83954e, 0xfe839560)  # Stops immediately before SetEDmac call.
        descriptor = uc.reg_read(UC_ARM_REG_R1)
        pitch = word(descriptor + 24)
        yb = word(descriptor + 32)
        if (uc.reg_read(UC_ARM_REG_R0) != 1 or pitch != ((width * bits) >> 3)
                or yb != ((height - 1) & 0xffffffff)):
            raise RuntimeError('Wrong native DMA geometry descriptor')

        # Invoke the actual packing routine and its actual shadow reader.
        # The stop precedes the first physical-write helper, not just pixel DMA.
        run(0x8000c67e, 0x8000c700)
        packed_stack = uc.reg_read(UC_ARM_REG_SP)
        packed = list(struct.unpack('<8I', uc.mem_read(packed_stack, 32)))
        expected_size_word = (pitch | ((yb << 16) & 0xffffffff)) & 0x7ffffffe
        if packed != [0, expected_size_word, 0, 0, 0, 0, 0, 0]:
            raise RuntimeError('Wrong native packed geometry words')
        packed_pitch, packed_yb = packed[1] & 0xffff, packed[1] >> 16
        valid_fixture = bool(height > 0 and (width * bits) % 8 == 0
                             and pitch == packed_pitch and height - 1 == packed_yb)
        if valid_fixture != (not name.startswith('invalid_')):
            raise RuntimeError('Unexpected fixture classification')
        results.append({'case': name, 'supplied_width': width, 'supplied_height': height,
                        'supplied_format_flag': wide, 'native_row_bit_multiplier': bits,
                        'native_line_bytes': pitch, 'native_yb': yb,
                        'packed_yb_xb': hex(packed[1]), 'packed_line_bytes': packed_pitch,
                        'packed_height_minus_one': packed_yb,
                        'fixture_geometry_preserved': valid_fixture, 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': results,
            'native_calls_stubbed': False, 'mmio_regions_mapped': False,
            'physical_stores_executed': False, 'raw_capture_demonstrated': False,
            'camera_binding_enabled': False,
            'limits': 'Separate native slices, synthetic caller fields and zeroed '
                      'descriptor scratch, scoped driver/table alias reconstruction. '
                      'Input dimensions are fixtures, not real camera modes. '
                      'No boot, format-register writes, mailbox, sensor, live packing '
                      'verification or completed-frame ownership is demonstrated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
