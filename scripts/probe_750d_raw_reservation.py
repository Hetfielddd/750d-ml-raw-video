# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the RAW-address reservation route with a supplied ADST table.

No allocation, pixels, hardware transfers or frame ownership are simulated.
Native busy/error paths stop before diagnostics, never forced into success.
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
    base, evf, registry = 0xfe0a0000, 0x26b94, 0x2b1e8
    table, caller, stack = 0x100000, 0x101000, 0x10d000
    status, count, descriptor = table + 0xe0, table + 0xfc, table + 40
    results = []
    for name, initial, supplied_count in (('one_entry', 1, 1), ('two_entries', 1, 2),
                                          ('zero_count', 1, 0), ('already_reserved', 2, 1)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for address in (0x26000, 0x2b000):
            uc.mem_map(address, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(table, 0xe000, UC_PROT_READ | UC_PROT_WRITE)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        def slot_state():
            return struct.unpack('<H', uc.mem_read(status, 2))[0]

        put(registry + 4, table)
        uc.mem_write(status, struct.pack('<H', initial))
        put(count, supplied_count)
        put(descriptor, 0x12345000)
        put(descriptor + 4, 0x56789000)
        put(caller + 16, 0xa7)
        errors, reached, boundaries = [], [], []
        ranges = ((0xfe2b8aae, 0xfe2b8acc), (0xfe2054f0, 0xfe20556c),
                  (0xfe2ba284, 0xfe2ba28a))

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 128 <= address <= stack + 8 - size
                    or (address, size) in ((status, 2), (evf + 88, 4), (evf + 100, 4))):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        def run(entry, stops):
            reached.clear()
            boundaries[:] = stops
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, 0x10f001)  # Unmapped: unexpected return fails.
            uc.reg_write(UC_ARM_REG_R4, caller)
            uc.reg_write(UC_ARM_REG_R7, evf)
            uc.emu_start(entry | 1, base + len(data), count=96, timeout=500_000)
            if errors or len(reached) != 1:
                raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        run(0xfe2b8aae, (0xfe3ce0fc,))
        if initial != 1:
            if (slot_state() != 2 or word(evf + 88) != 0 or word(evf + 100) != 0
                    or uc.reg_read(UC_ARM_REG_LR) != 0xfe205513):
                raise RuntimeError('Busy acquisition modified reservation outputs')
            results.append({'case': name, 'diagnostic_boundary': True, 'passed': True})
            continue
        if (slot_state() != 2 or word(evf + 88) != 0x12345000
                or word(evf + 100) != supplied_count
                or uc.reg_read(UC_ARM_REG_LR) != 0xfe2b8acd):
            raise RuntimeError('Wrong reservation state/address/count')
        # Same registry entry cannot be acquired again without diagnostics.
        run(0xfe2b8aae, (0xfe3ce0fc,))
        if (slot_state() != 2 or word(evf + 88) != 0x12345000
                or uc.reg_read(UC_ARM_REG_LR) != 0xfe205513):
            raise RuntimeError('Repeated acquisition changed reserved address')
        # Run the reviewed teardown caller's slot-2 release, stopping before slot 9.
        run(0xfe2ba284, (0xfe2ba28a,))
        if (slot_state() != 1 or uc.reg_read(UC_ARM_REG_R0) != 0
                or word(evf + 88) != 0x12345000):
            raise RuntimeError('Wrong release state or unexpected address clearing')
        run(0xfe2b8aae, (0xfe3ce0fc,))
        if (slot_state() != 2 or word(evf + 88) != 0x12345000
                or uc.reg_read(UC_ARM_REG_LR) != 0xfe2b8acd):
            raise RuntimeError('Wrong reacquisition')
        results.append({'case': name, 'supplied_count': supplied_count,
                        'selected_pointer': hex(word(evf + 88)),
                        'state_sequence': [1, 2, 2, 1, 2], 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': results,
            'slot': 2, 'descriptor_stride': 20, 'selected_descriptor_word': 0,
            'native_calls_stubbed': False, 'pixels_mapped': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Supplied ADST table, descriptor pointers/counts, EVF globals and '
                      'saved caller context. Native setup and teardown slices only. '
                      'Busy paths stop before diagnostic/exception handling. No allocator, '
                      'actual buffers, whole start/stop, IRQ, DMA, cache or frame timing '
                      'is modeled. Reservation ownership is not per-frame ownership.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
