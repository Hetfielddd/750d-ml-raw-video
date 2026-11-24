# SPDX-License-Identifier: GPL-2.0-or-later
"""Characterize native 750D completion aggregation using supplied event order.

Runs callback slices with synthetic saved frames. Stops before OS event-flag
and interrupt-restore helpers; their effects are not emulated or stubbed into
success. No DMA, physical IRQ, pixel buffer or frame lease is demonstrated.
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
                                   UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR)

    base, state, stack, stop = 0xfe0a0000, 0x1ac1830, 0x10d000, 0x10f000
    signal, restore = 0xfe74fc2a, 0xfe74b106
    irq_token, handle = 0x13579bdf, 0x2468ace1  # Uninterpreted synthetic values.
    raw_leaf, all_leaf = 0xfe751130, 0xfe3807b8  # Actual one-instruction BX LR leaves.
    raw_arg, all_arg = 0x11223344, 0x55667788
    # After IRQ-disable call / after event-flag call / after IRQ-restore call.
    callbacks = {
        1: (0xfe750cce, 0xfe750ce2, 0xfe750cee),
        2: (0xfe751138, 0xfe75114c, 0xfe751158),
        4: (0xfe7511f4, 0xfe751208, 0xfe751214),
        8: (0xfe7511b8, 0xfe7511cc, 0xfe7511d8),
        16: (0xfe751174, 0xfe751190, 0xfe75119c),
        32: (0xfe751230, 0xfe751244, 0xfe751250),
        64: (0xfe7510a2, 0xfe7510b6, 0xfe7510c2),
    }
    definitions = (
        ('raw_only', 0, [16], True, True),
        ('raw_last', 0, [1, 2, 4, 8, 32, 64, 16], True, True),
        ('raw_first', 0, [16, 1, 2, 4, 8, 32, 64], True, True),
        ('raw_repeated_before_others', 0, [16, 16, 1, 2, 4, 8, 32, 64], True, True),
        ('missing_one_component', 0, [1, 2, 4, 8, 16, 32], True, True),
        ('two_complete_cycles', 0, [1, 2, 4, 8, 16, 32, 64] * 2, True, True),
        ('preseeded_other_components', 0x6f, [16], True, True),
        ('extra_bit_blocks_equality', 0x80, [1, 2, 4, 8, 16, 32, 64], True, True),
        ('raw_callback_absent', 0, [1, 2, 4, 8, 16, 32, 64], False, True),
        ('aggregate_callback_absent', 0, [1, 2, 4, 8, 16, 32, 64], True, False),
    )
    results = []
    for name, initial_mask, events, raw_enabled, all_enabled in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(state & ~4095, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stack - 4096, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(state + 4, initial_mask)
        put(state + 12, (all_leaf | 1) if all_enabled else 0)
        put(state + 16, all_arg)
        put(state + 20, (raw_leaf | 1) if raw_enabled else 0)
        put(state + 24, raw_arg)
        put(state + 44, handle)
        reached, errors, notifications = [], [], []
        boundary = [stop]
        ranges = ((0xfe750cce, 0xfe750d04), (0xfe7510a2, 0xfe7510d0),
                  (0xfe751128, 0xfe751266), (all_leaf, all_leaf + 2))

        def code_guard(emulator, address, size, _):
            if address == boundary[0]:
                reached.append(True)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()
            elif address in (raw_leaf, all_leaf):
                notifications.append({'kind': 'raw' if address == raw_leaf else 'aggregate',
                                      'argument': hex(emulator.reg_read(UC_ARM_REG_R0)),
                                      'mask_at_callback': hex(word(state + 4))})
                # Observe and execute the actual leaf. Do not synthesize a return.

        def write_guard(emulator, access, address, size, value, _):
            if address != state + 4 or size != 4:
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def run(entry, end):
            reached.clear()
            boundary[0] = end
            uc.emu_start(entry | 1, stop + 4, count=128, timeout=500_000)
            if errors or not reached:
                raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')

        expected_mask = initial_mask
        trace = []
        raw_calls = aggregate_calls = 0
        for bit in events:
            entry, after_signal, after_restore = callbacks[bit]
            before = expected_mask
            before_notifications = len(notifications)
            # Each entry is after the original PUSH and interrupt-disable call.
            # Supply their saved frame; we are not testing either operation.
            uc.mem_write(stack - 16, struct.pack('<4I', 0, 0, 0, stop | 1))
            uc.reg_write(UC_ARM_REG_SP, stack - 16)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            uc.reg_write(UC_ARM_REG_R0, irq_token)
            run(entry, signal)
            expected_mask |= bit
            expected_notifications = []
            if bit == 16 and raw_enabled:
                expected_notifications.append({'kind': 'raw', 'argument': hex(raw_arg),
                                               'mask_at_callback': hex(before)})
                raw_calls += 1
            if (word(state + 4) != expected_mask or uc.reg_read(UC_ARM_REG_R0) != handle
                    or uc.reg_read(UC_ARM_REG_R1) != bit):
                raise RuntimeError('Wrong pending mask or event-flag arguments')

            # Do not execute the event-flag helper or model its return value.
            # The next slice reloads the mask before making its decision.
            run(after_signal, restore)
            if uc.reg_read(UC_ARM_REG_R0) != irq_token:
                raise RuntimeError('Wrong saved interrupt token')
            if expected_mask == 0x7f:
                if (uc.reg_read(UC_ARM_REG_LR) != (after_restore | 1)
                        or uc.reg_read(UC_ARM_REG_SP) != stack - 16):
                    raise RuntimeError('Wrong full-mask continuation')
                if all_enabled:
                    expected_notifications.append({'kind': 'aggregate', 'argument': hex(all_arg),
                                                   'mask_at_callback': hex(0x7f)})
                    aggregate_calls += 1
                run(after_restore, stop)  # IRQ restore itself remains unexecuted.
                expected_mask = 0
            elif (uc.reg_read(UC_ARM_REG_LR) != (stop | 1)
                  or uc.reg_read(UC_ARM_REG_SP) != stack):
                raise RuntimeError('Wrong partial-mask continuation')
            actual = notifications[before_notifications:]
            if word(state + 4) != expected_mask or actual != expected_notifications:
                raise RuntimeError('Wrong callbacks, ordering, or mask reset')
            trace.append({'component_bit': hex(bit), 'mask_before': hex(before),
                          'mask_after': hex(expected_mask), 'callbacks': actual})
        results.append({'case': name, 'initial_mask': hex(initial_mask),
                        'events': trace, 'raw_callback_calls': raw_calls,
                        'aggregate_callback_calls': aggregate_calls,
                        'final_mask': hex(expected_mask), 'passed': True})
    notification_cases = []
    # The application's actual registrations use these task callbacks. Check
    # their request arguments separately, stopping before the queue operation.
    for name, entry, literal, event in (
            ('raw_component_task_event', 0xfe80fd20, 0xfe80fe50, 7),
            ('aggregate_task_event', 0xfe80fd3c, 0xfe80fe48, 6)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(0x100000, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
        task, subtask, header, queue_marker = 0x100000, 0x101000, 0x102000, 0x12345678
        for address, value in ((task, subtask), (subtask, header), (header, queue_marker)):
            uc.mem_write(address, struct.pack('<I', value))
        stored = struct.unpack_from('<I', data, literal - base)[0]
        if stored != ((entry - 0xfcc82368) | 1):
            raise RuntimeError('Unexpected application callback pointer')
        reached, errors = [], []

        def task_code_guard(emulator, address, size, _):
            if address == 0xfe86f740:
                reached.append(True)
                emulator.emu_stop()
            elif not (entry <= address and address + size <= entry + 20
                      or 0xfe86fb30 <= address and address + size <= 0xfe86fb4a):
                errors.append(f'Unexpected task execution: {address:#x}')
                emulator.emu_stop()

        def task_write_guard(emulator, access, address, size, value, _):
            if not (stack - 128 <= address and address + size <= stack
                    or address == subtask + 12 and size == 4):
                errors.append(f'Unexpected task write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, task_code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, task_write_guard)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)  # Unmapped; unexpected return fails.
        uc.reg_write(UC_ARM_REG_R0, task)
        uc.emu_start(entry | 1, base + len(data), count=64, timeout=500_000)
        if errors or not reached:
            raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')
        from unicorn.arm_const import UC_ARM_REG_R2, UC_ARM_REG_R3
        args = [uc.reg_read(reg) for reg in
                (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        fifth = struct.unpack('<I', uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
        association = struct.unpack('<I', uc.mem_read(subtask + 12, 4))[0]
        if args != [queue_marker, subtask, event, 0] or fifth != 0 or association != task:
            raise RuntimeError('Wrong queue request arguments or task association')
        notification_cases.append({'case': name, 'stored_callback': hex(stored),
                                   'event_number': event, 'passed': True})

    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': results,
            'task_notification_cases': notification_cases,
            'native_calls_stubbed': False, 'os_helpers_executed': False,
            'hardware_irq_or_dma_emulated': False, 'pixel_buffers_mapped': False,
            'raw_capture_demonstrated': False, 'camera_binding_enabled': False,
            'limits': 'Synthetic event order, callback registrations and saved frames. '
                      'Separate native slices stop before event-flag and IRQ-restore '
                      'helpers and resume at reviewed continuations. Callback endpoints '
                      'are existing native BX LR leaves. Actual application task '
                      'callbacks are checked separately before the queue operation. '
                      'No queue delivery, timing, ownership, cache, '
                      'pixel contents or actual delivery of events is validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
