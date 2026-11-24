# SPDX-License-Identifier: GPL-2.0-or-later
"""PC-only test of actual 750D RAW address selection and parameter publication.

Executes a bounded slice with synthetic caller state; not a complete interrupt,
sensor model, DMA emulation, or completed-frame provider. Only logging is stubbed.
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
                                   UC_ARM_REG_R4, UC_ARM_REG_R7, UC_ARM_REG_R8,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    base, state, evf, published = 0xfe0a0000, 0x2af78, 0x26b94, 0x6b31c
    caller, argument, stack, stop = 0x100000, 0x101000, 0x10c000, 0x10f000
    candidate, fallback = 0x12345000, 0x56789000  # Values only, never mapped/dereferenced.
    definitions = [
        ('disabled_clean', 0, 0, 0, 0, 1, fallback),
        ('disabled_pending', 0, 7, 0, 0, 1, fallback),
        ('enabled', 1, 0, 0, 0, 1, candidate),
        ('enabled_clears_auxiliary', 1, 7, 0, 0, 1, candidate),
        ('selected_frame_matches', 1, 0, 1, 17, 1, candidate),
        ('selected_frame_mismatch', 1, 0, 1, 18, 1, fallback),
        ('caller_route_inactive', 1, 0, 0, 0, 0, fallback),
    ]
    results = []
    for name, requested, auxiliary, selection, selected_frame, active, expected in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for address, size in ((0x26000, 4096), (0x2a000, 4096),
                              (0x6b000, 4096), (0x100000, 0xe000)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(argument, requested)
        put(state + 12, auxiliary)
        put(state + 8, selection)
        put(state + 44, selected_frame)
        put(caller + 52, active)
        put(evf + 24, 17)
        put(evf + 88, candidate)
        for index in range(27):
            put(stack + 0xc0 + index * 4, 0xa0000000 + index)
        done, errors, logged = [], [], []
        boundary = [stop]
        ranges = ((0xfe308eb4, 0xfe308eca), (0xfe2b92ae, 0xfe2b9324),
                  (0xfe309cf0, 0xfe309d10), (0xfe309f14, 0xfe309fae))

        def guard(emulator, address, size, _):
            if address == boundary[0]:
                done.append(True)
                emulator.emu_stop()
            elif address == 0xfe3ce0fc:
                logged.append(True)
                # The debug logger has no modeled return value or side effects.
                emulator.reg_write(UC_ARM_REG_PC, emulator.reg_read(UC_ARM_REG_LR))
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution at {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            allowed = ((state, state + 64), (published + 0x54, published + 0x124),
                       (0x100000, 0x10e000))
            if not any(lo <= address and address + size <= hi for lo, hi in allowed):
                errors.append(f'Unexpected write at {address:#x}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def run(entry, end):
            boundary[0] = end
            done.clear()
            uc.emu_start(entry | 1, stop + 4, count=2000, timeout=1_000_000)
            if errors or not done:
                raise RuntimeError(f'{name}: incomplete/invalid execution: {errors}')

        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        uc.reg_write(UC_ARM_REG_R0, argument)
        run(0xfe308eb4, stop)  # Actual lv_save_raw setter, then actual consumers.
        uc.reg_write(UC_ARM_REG_R4, caller)
        uc.reg_write(UC_ARM_REG_R7, evf)
        uc.reg_write(UC_ARM_REG_R8, fallback)
        run(0xfe2b92ae, 0xfe2b9324)
        selected = word(stack + 0xdc)
        if selected != expected:
            raise RuntimeError(f'{name}: wrong selected address')
        uc.reg_write(UC_ARM_REG_R0, stack + 0xc0)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        run(0xfe309f14, stop)
        if word(published + 0x54) != expected or word(published + 0xc4) != expected:
            raise RuntimeError(f'{name}: selected address not propagated')
        expected_selection = 0 if name == 'selected_frame_matches' else selected_frame
        if word(state + 44) != expected_selection:
            raise RuntimeError(f'{name}: wrong one-frame selection state')
        results.append({'case': name, 'selected_address': hex(selected),
                        'published_address_1': hex(published + 0x54),
                        'published_address_2': hex(published + 0xc4),
                        'selection_tag_after': word(state + 44),
                        'debug_logger_calls_stubbed': len(logged), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': results,
            'actual_native_code': ['lv_save_raw setter', 'address-selection slice and getters',
                                   'parameter publisher'],
            'mmio_regions_mapped': False, 'pixel_buffers_mapped': False,
            'raw_capture_demonstrated': False,
            'limits': 'Synthetic caller state; only a slice of the preparation '
                      'handler executes. Logger is stubbed. The selected address '
                      'is a preparation parameter, not a proven completed-frame lease.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
