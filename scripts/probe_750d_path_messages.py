# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify native Live View message preparation, stopping before mailbox writes.

Executes wrappers and a separate sender-packing slice with synthetic state.
Does not send messages, emulate a receiver, or establish DMA completion.
"""
import argparse
import hashlib
import json
from pathlib import Path

from decrypt_750d_fir import MAIN_SHA256


def probe(data):
    if len(data) != 0xcfb688 or hashlib.sha256(data).hexdigest() != MAIN_SHA256:
        raise ValueError('Expected the identified 750D 1.1.0 main-code record')
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                         UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                                   UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                                   UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_SP,
                                   UC_ARM_REG_LR)
    base, stack, counter, payload = 0xfe0a0000, 0x10d000, 0x101000, 0x12345000
    entries = (0xfe38074e, 0xfe38075a, 0xfe380766,
               0xfe380772, 0xfe3807a0, 0xfe3807ac)
    cases = []
    for operation, entry in enumerate(entries):
        for initial_count in (0, 255):
            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
            uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
            uc.mem_write(base, data)
            uc.mem_map(0x100000, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_write(counter, bytes([initial_count]))
            reached, errors, writes = [], [], []
            boundary = [0xfe48d25c]
            ranges = ((0xfe38074e, 0xfe380780), (0xfe3807a0, 0xfe3807b8),
                      (0xfe443016, 0xfe44302a), (0xfe48d2aa, 0xfe48d2bc))

            def code_guard(emulator, address, size, _):
                if address == boundary[0]:
                    reached.append(True)
                    emulator.emu_stop()
                elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                    errors.append(f'Unexpected execution: {address:#x}')
                    emulator.emu_stop()

            def write_guard(emulator, access, address, size, value, _):
                writes.append((address, size))
                if not (0x10cf00 <= address and address + size <= stack
                        or address == counter and size == 1):
                    errors.append(f'Unexpected write: {address:#x}/{size}')
                    emulator.emu_stop()

            uc.hook_add(UC_HOOK_CODE, code_guard)
            uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

            def run(start, end):
                reached.clear()
                boundary[0] = end
                uc.emu_start(start | 1, base + len(data), count=64, timeout=500_000)
                if errors or not reached:
                    raise RuntimeError(f'Invalid/incomplete execution: {errors}')

            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, 0x10f001)  # Unmapped: unexpected return fails.
            uc.reg_write(UC_ARM_REG_R0, payload)
            run(entry, 0xfe48d25c)
            args = [uc.reg_read(reg) for reg in
                    (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            if args != [4, 2, 0x200 | operation, payload]:
                raise RuntimeError(f'Wrong sender arguments: {args}')

            # Separate slice after the sender's semaphore/interrupt setup.
            # Those operations are not executed or stubbed into success.
            for reg, value in ((UC_ARM_REG_R4, counter), (UC_ARM_REG_R5, args[0]),
                               (UC_ARM_REG_R6, args[1]), (UC_ARM_REG_R7, args[2]),
                               (UC_ARM_REG_R8, args[3])):
                uc.reg_write(reg, value)
            run(0xfe48d2aa, 0xfe48d2bc)
            command = uc.reg_read(UC_ARM_REG_R7)
            register_base = uc.reg_read(UC_ARM_REG_R1)
            final_count = uc.mem_read(counter, 1)[0]
            if (command != (0x02000200 | operation) or register_base != 0xd2000100
                    or final_count != ((initial_count + 1) & 255)
                    or writes.count((counter, 1)) != 1
                    or uc.reg_read(UC_ARM_REG_R8) != payload):
                raise RuntimeError('Wrong packed message or counter')
            cases.append({'operation': operation, 'wrapper': hex(entry),
                          'counter_before': initial_count, 'counter_after': final_count,
                          'prepared_command': hex(command), 'payload_marker': hex(payload),
                          'next_store_address': hex(register_base + 4), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'actual_native_code': ['Live View command wrappers', 'service wrapper',
                                   'separate sender-packing slice'],
            'native_calls_stubbed': False, 'mmio_regions_mapped': False,
            'mailbox_stores_executed': False, 'peer_delivery_demonstrated': False,
            'raw_capture_demonstrated': False,
            'limits': 'Stops at the transport entry, then executes a separate '
                      'packing slice with supplied incoming registers. Semaphore '
                      'and interrupt setup, mailbox stores and receiver do not execute. '
                      'The payload is an unmapped marker, never dereferenced.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
