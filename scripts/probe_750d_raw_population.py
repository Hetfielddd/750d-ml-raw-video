# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify native manager -> ADST slot 2 -> RAW preparation pointer propagation.

Uses supplied manager/registry state, without allocation, image memory or DMA.
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
                                   UC_ARM_REG_R4, UC_ARM_REG_R7,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, manager, table, caller, stack = 0xfe0a0000, 0x100000, 0x101000, 0x102000, 0x10d000
    evf, registry = 0x26b94, 0x2b1e8
    cases = []
    for pointer in (0x12345000, 0x56789000, 0, 1):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(manager, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
        for address in (0x26000, 0x2b000):
            uc.mem_map(address, 4096, UC_PROT_READ | UC_PROT_WRITE)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(manager + 1808, pointer)
        put(manager + 1864, 0xdeadbeef)
        put(registry, 0xfdfd)
        put(registry + 4, table)
        uc.mem_write(table + 224, struct.pack('<H', 1))  # Supplied available state.
        put(table + 252, 5)  # Sentinel: native population must replace count with 1.
        put(table + 40, 0xdeadbeef)
        put(caller + 16, 0xa7)
        errors, reached, boundaries = [], [], []
        ranges = ((0xfe11fa2e, 0xfe11fa50), (0xfe120428, 0xfe1204e8),
                  (0xfe2053f6, 0xfe205412), (0xfe2054f0, 0xfe205540),
                  (0xfe2b8aae, 0xfe2b8acc))

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 128 <= address <= stack + 8 - size
                    or (address, size) in ((manager + 1864, 4), (table + 248, 4),
                                          (table + 252, 4), (table + 40, 4),
                                          (table + 224, 2), (evf + 88, 4), (evf + 100, 4))):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        def run(entry, stops):
            boundaries[:] = stops
            reached.clear()
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, 0x10f001)  # Unmapped: unexpected return fails.
            uc.emu_start(entry | 1, base + len(data), count=128, timeout=500_000)
            if errors or len(reached) != 1:
                raise RuntimeError(f'{pointer:#x}: invalid/incomplete stage: {errors}')

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.reg_write(UC_ARM_REG_R4, manager)
        run(0xfe11fa2e, (0xfe11fa50, 0xfe52fa48))
        if pointer in (0, 1):
            if reached != [0xfe52fa48] or word(manager + 1864) != 0xdeadbeef:
                raise RuntimeError('Invalid manager pointer did not reach assertion')
            cases.append({'supplied_pointer': hex(pointer), 'assertion_boundary': True,
                          'passed': True})
            continue
        if reached != [0xfe11fa50] or word(manager + 1864) != pointer:
            raise RuntimeError('Wrong manager resource publication')
        uc.reg_write(UC_ARM_REG_R0, manager)
        run(0xfe120428, (0xfe1204e8,))
        if word(table + 252) != 1 or word(table + 40) != pointer:
            raise RuntimeError('Wrong slot-2 descriptor population')
        uc.reg_write(UC_ARM_REG_R4, caller)
        uc.reg_write(UC_ARM_REG_R7, evf)
        run(0xfe2b8aae, (0xfe3ce0fc,))
        if (word(evf + 88) != pointer or word(evf + 100) != 1
                or uc.reg_read(UC_ARM_REG_LR) != 0xfe2b8acd
                or struct.unpack('<H', uc.mem_read(table + 224, 2))[0] != 2):
            raise RuntimeError('Wrong acquired RAW preparation address')
        cases.append({'supplied_pointer': hex(pointer), 'manager_resource': hex(word(manager + 1864)),
                      'slot_2_descriptor': hex(word(table + 40)), 'slot_2_count': word(table + 252),
                      'raw_preparation_pointer': hex(word(evf + 88)), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'pixels_mapped': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Supplied manager initial address, owner token, registry table, '
                      'available state and unrelated zero-count resources. Separate '
                      'native resource-publication, population and reservation stages. '
                      'No allocation, surrounding resource selection, actual buffer '
                      'contents, DMA, timing, cache or frame lease is validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
