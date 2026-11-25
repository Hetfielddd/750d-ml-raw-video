# SPDX-License-Identifier: GPL-2.0-or-later
"""Check native start-gate preparation and event-bit decisions without scheduling.

OS wrappers stop before interrupt/object lookup operations. Pure low-level
decisions use a supplied event object; missing-bit paths stop before blocking.
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
                                   UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                                   UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, stack, event, output, driver = 0xfe0a0000, 0x10d000, 0x100000, 0x101000, 0x1ac1830
    mask, handle = 0x8000007f, 0x2468ace0
    cases = []
    app_delta, driver_delta = 0xfcc82368, 0x7e7473e0
    transition = struct.unpack_from('<2I', data, 0xfe9744f8 + 2 * 8 - base)
    targets = [struct.unpack_from('<I', data, address - base)[0]
               for address in (0xfe86f294, 0xfe86f28c)]
    if (transition != (0, (0xfe80fdae - app_delta) | 1)
            or targets != [((address - driver_delta) | 1)
                           for address in (0xfe750e8a, 0xfe750e1c)]):
        raise RuntimeError('Unexpected event-2 table entry or driver veneers')

    def make_uc():
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(event, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(0x1ac0000, 8192, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(0x10f000, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, 0x10f001)
        return uc

    def put(uc, address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(uc, address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def execute(uc, entry, stops, ranges, writes):
        reached, errors = [], []

        def code_guard(emulator, address, size, _):
            if address in stops:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected gate execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 256 <= address <= stack - size or (address, size) in writes):
                errors.append(f'Unexpected gate write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.emu_start(entry | 1, base + len(data), count=128, timeout=500_000)
        if errors or len(reached) != 1:
            raise RuntimeError(f'Invalid/incomplete gate execution: {errors}')
        return reached[0]

    decisions = [(flags, options, mask) for flags, options in
                 ((0, 4), (0x10, 4), (0x7f, 4), (0x80000000, 4),
                  (0x8000006f, 4), (mask, 4), (0xffffffff, 4), (0x10, 0))]
    decisions += [(0x6f, 4, 0x7f), (0x7f, 4, 0x7f)]
    for flags, options, requested in decisions:
        uc = make_uc()
        put(uc, event + 8, flags)
        put(uc, output, 0xdeadbeef)
        put(uc, stack, 0)  # Supplied timeout pointer; blocking path is not executed.
        for reg, value in ((UC_ARM_REG_R0, event), (UC_ARM_REG_R1, requested),
                           (UC_ARM_REG_R2, options), (UC_ARM_REG_R3, output)):
            uc.reg_write(reg, value)
        ready = (flags & requested) == requested if options == 4 else bool(flags & requested)
        stop = execute(uc, 0xfe74bda2, (0xfe74bddc, 0x10f000),
                       ((0xfe74bda2, 0xfe74bddc),), {(output, 4)})
        if (stop != (0x10f000 if ready else 0xfe74bddc)
                or word(uc, output) != (flags if ready else 0xdeadbeef)
                or word(uc, event + 8) != flags
                or ready and uc.reg_read(UC_ARM_REG_R0) != 0):
            raise RuntimeError('Wrong native all/any-bit decision')
        cases.append({'case': 'event_decision', 'supplied_flags': hex(flags),
                      'requested_bits': hex(requested),
                      'options': options, 'immediate_success': ready, 'passed': True})

    for name, entry, stop, ranges in (
            ('prepare_enables_timer', 0xfe750e90, 0xfe74b106,
             ((0xfe750e90, 0xfe750e9a),)),
            ('prepare_wait_request', 0xfe750e9a, 0xfe749dba,
             ((0xfe750e9a, 0xfe750ea4), (0xfe74fbaa, 0xfe74fc02))),
            ('cleanup_disables_timer', 0xfe75102c, 0xfe74b106,
             ((0xfe75102c, 0xfe751032),))):
        uc = make_uc()
        put(uc, driver + 40, 0 if name == 'prepare_enables_timer' else 1)
        put(uc, driver + 44, handle)
        put(uc, driver + 4, 0x6f)
        uc.reg_write(UC_ARM_REG_R4, driver)
        # Cleanup's reviewed preceding MOVS at FE751024 supplies zero R5.
        uc.reg_write(UC_ARM_REG_R5, 0)
        execute(uc, entry, (stop,), ranges, {(driver + 40, 4)})
        expected_enabled = 0 if name == 'cleanup_disables_timer' else 1
        if word(uc, driver + 40) != expected_enabled or word(uc, driver + 4) != 0x6f:
            raise RuntimeError('Wrong timer enable lifecycle or component-mask write')
        if name == 'prepare_wait_request':
            regs = tuple(uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            if regs != (handle >> 1, 0x7f, 4) or word(uc, uc.reg_read(UC_ARM_REG_SP)) != 0:
                raise RuntimeError('Wrong preparation wait arguments')
        cases.append({'case': name, 'timer_enabled': expected_enabled,
                      'component_mask_unchanged': True, 'stopped_before': hex(stop),
                      'passed': True})

    # Independent handler slices; the first imported call is never forced to return.
    for name, entry, stop in (('event2_first_call', 0xfe80fdae, 0xfe86f290),
                              ('event2_later_call', 0xfe80fdb8, 0xfe86f288)):
        uc = make_uc()
        uc.reg_write(UC_ARM_REG_R0, event)
        uc.reg_write(UC_ARM_REG_R1, output)
        uc.reg_write(UC_ARM_REG_R5, output)  # Supplied saved parameter in later slice.
        execute(uc, entry, (stop,), ((entry, 0xfe80fdbe),), set())
        if (name == 'event2_first_call' and uc.reg_read(UC_ARM_REG_R5) != output
                or name == 'event2_later_call' and uc.reg_read(UC_ARM_REG_R0) != output):
            raise RuntimeError('Wrong event-2 saved or forwarded parameter')
        cases.append({'case': name, 'stopped_before': hex(stop), 'passed': True})

    for name in ('wait_request', 'clear_request', 'timer_disabled', 'timer_enabled'):
        uc = make_uc()
        put(uc, driver + 44, handle)
        put(uc, driver + 40, 1 if name == 'timer_enabled' else 0)
        uc.reg_write(UC_ARM_REG_R4, driver)
        uc.reg_write(UC_ARM_REG_R6, mask)
        if name == 'wait_request':
            entry, stop = 0xfe750e2e, 0xfe749dba
            ranges = ((0xfe750e2e, 0xfe750e3a), (0xfe74fbaa, 0xfe74fc02))
        elif name == 'clear_request':
            entry, stop = 0xfe750e3a, 0xfe749d84
            ranges = ((0xfe750e3a, 0xfe750e42), (0xfe74fc58, 0xfe74fc70))
        else:
            entry, stop = 0xfe750d04, 0xfe749d84 if name == 'timer_enabled' else 0x10f000
            ranges = ((0xfe750d04, 0xfe750d16), (0xfe74fc2a, 0xfe74fc40))
        execute(uc, entry, (stop,), ranges, set())
        if name != 'timer_disabled':
            r0, r1, r2 = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
            expected_bits = (~mask & 0xffffffff) if name == 'clear_request' else mask
            if (r0, r1, r2) != (handle >> 1, expected_bits, 0 if name == 'timer_enabled' else 4):
                raise RuntimeError('Wrong wait/clear/timer wrapper arguments')
            if name == 'wait_request' and word(uc, uc.reg_read(UC_ARM_REG_SP)) != 0:
                raise RuntimeError('Wrong supplied timeout argument')
        cases.append({'case': name, 'stopped_before': hex(stop), 'passed': True})

    for operation, flags in (('set', 0), ('clear', 0xffffffff)):
        uc = make_uc()
        put(uc, event + 8, flags)
        # No waiters are supplied; no scheduler path is entered.
        for reg, value in ((UC_ARM_REG_R0, event),
                           (UC_ARM_REG_R1, mask if operation == 'set' else ~mask & 0xffffffff),
                           (UC_ARM_REG_R2, 0 if operation == 'set' else 4)):
            uc.reg_write(reg, value)
        execute(uc, 0xfe74bcd4, (0x10f000,), ((0xfe74bcd4, 0xfe74bcf2),), {(event + 8, 4)})
        expected = mask if operation == 'set' else ~mask & 0xffffffff
        if word(uc, event + 8) != expected:
            raise RuntimeError('Wrong native event-bit update')
        cases.append({'case': operation + '_bits_no_waiters',
                      'resulting_flags': hex(expected), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'driver_gate_mask': hex(mask), 'preparation_gate_mask': '0x7f',
            'event2_table_and_veneer_targets_checked': True, 'native_calls_stubbed': False,
            'scheduler_or_irq_helpers_executed': False, 'camera_binding_enabled': False,
            'frame_lease_validated': False,
            'limits': 'Supplied event object, flags, encoded handle, zero OS guard '
                      'globals and no waiters. Pure ready/missing decisions and flag '
                      'updates are native; wrapper stages stop before OS lookup/IRQ '
                      'work, missing-bit stages before blocking. Timer callback '
                      'invocation is supplied; its registration/timing is not executed. '
                      'Preparation/cleanup slices stop before IRQ restore; the cleanup '
                      'zero register and later event-2 saved parameter are supplied. '
                      'Two handler slices are independent, without returning an import. '
                      'No hardware completion, DMA, pixels, cache or ownership proof.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
