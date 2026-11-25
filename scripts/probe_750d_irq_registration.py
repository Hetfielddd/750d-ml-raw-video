# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace native RAW IRQ registration and enable boundaries without controller IO."""
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
                                   UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, stack, stop = 0xfe0a0000, 0x10d000, 0x10f000
    state, record = 0x1ac0044, 0x1ad8350
    cases = []

    def make_uc():
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(0x8000f000, 4096, UC_PROT_READ | UC_PROT_EXEC)
        offset = 0x8000f000 + 0x7e7473e0 - base
        uc.mem_write(0x8000f000, data[offset:offset + 4096])
        for address in (state & ~4095, record & ~4095, stack - 4096):
            uc.mem_map(address, 4096, UC_PROT_READ | UC_PROT_WRITE)
        for address in (0, stop):
            # Low page is fetchable only to stop before the unresolved import.
            uc.mem_map(address, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        return uc

    def put(uc, address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(uc, address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def run(uc, entry, boundaries, ranges, allowed):
        reached, errors = [], []

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected registration code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 128 <= address and address + size <= stack
                    or (address, size) in allowed):
                errors.append(f'Unexpected registration write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.emu_start(entry | 1, base + len(data), count=128, timeout=500_000)
        if errors or len(reached) != 1:
            raise RuntimeError(f'Invalid/incomplete registration stage: {errors}')
        return reached[0]

    for argument in (0, 0x12345678):
        uc = make_uc()
        uc.reg_write(UC_ARM_REG_R0, 1)
        uc.reg_write(UC_ARM_REG_R1, 0x1bb709b)
        uc.reg_write(UC_ARM_REG_R2, argument)
        reached = run(uc, 0xfe75432a, (0x6fc,),
                      ((0xfe75432a, 0xfe754356), (0xfe74b008, 0xfe74b02c),
                       (0xfe74f96c, 0xfe74f970)),
                      {(record + offset, 4) for offset in (0, 4, 8)})
        registers = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        if (reached != 0x6fc or registers != [0x8000d1ed, 1, 0x41]
                or [word(uc, record + offset) for offset in (0, 4, 8)]
                != [0x1bb709b, argument, 1]):
            raise RuntimeError('Wrong native registration record/import arguments')
        cases.append({'case': 'channel_1_registration', 'supplied_callback_argument': hex(argument),
                      'low_import_arguments': [hex(x) for x in registers],
                      'stopped_before': '0x6fc', 'passed': True})

    for irq, limit in ((0x41, 432), (431, 432), (0, 432), (0xffffffff, 432),
                       (432, 432), (0x41, 0x41)):
        uc = make_uc()
        put(uc, state, limit)
        uc.reg_write(UC_ARM_REG_R0, irq)
        accepted = 0 < irq < limit
        reached = run(uc, 0xfe747c20, (0xfe747c36, stop),
                      ((0xfe747c20, 0xfe747c36),), set())
        if (reached != (0xfe747c36 if accepted else stop)
                or accepted and (uc.reg_read(UC_ARM_REG_R0) != irq
                                 or uc.reg_read(UC_ARM_REG_R4) != 0xd5011000)
                or not accepted and uc.reg_read(UC_ARM_REG_R0) != 0xffffffff):
            raise RuntimeError('Wrong native IRQ enable bounds/store target')
        cases.append({'case': 'irq_enable', 'supplied_irq': hex(irq),
                      'supplied_irq_limit': limit, 'accepted': accepted,
                      'prepared_register': '0xd5011010' if accepted else None,
                      'stopped_before': hex(reached), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'low_import_executed': False,
            'controller_registers_mapped': False, 'camera_binding_enabled': False,
            'hardware_completion_validated': False,
            'limits': 'Supplied channel callback/argument and IRQ limit. Native installer '
                      'and wrapper reach the actual ARM import target, stopping before '
                      'its first instruction at 0x6FC. A separate enable call stops '
                      'before controller store or returns rejection. No import return '
                      'is fabricated. No controller delivery, DMA, pixels, timing, cache '
                      'or frame ownership is established.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
