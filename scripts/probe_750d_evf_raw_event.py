# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace supplied RAW-return events to the EVF AF-path handler on a PC.

Stages stop at OS/task, state-transition, logging and downstream boundaries.
The EVF table is decoded, not dispatched by an emulated low-memory OS.
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
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, context, stack = 0xfe0a0000, 0x100000, 0x10d000

    def source_word(address):
        return struct.unpack_from('<I', data, address - base)[0]

    table = source_word(0xfe2b83f0)
    if table != 0xfea0b174 or source_word(0xfe2b83f4) != 0x26b94:
        raise RuntimeError('Unexpected EVF constructor table or global')
    transitions = []
    for state in range(10):
        next_state = source_word(table + (19 * 10 + state) * 8)
        handler = source_word(table + (19 * 10 + state) * 8 + 4)
        expected = 0xfe2b969f if state in (3, 4, 5, 6) else (
            0xfe2ba913 if state in (2, 7, 8) else 0)
        if next_state != state or handler != expected:
            raise RuntimeError(f'Unexpected event-19 matrix entry: {state}')
        transitions.append({'old_state': state, 'next_state': next_state,
                            'stored_handler': hex(handler)})
    cases = []
    for name in ('post_raw_event', 'post_without_context', 'worker_forward',
                 'handler_af_branch', 'handler_skip_af_branch'):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(0x4000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(context, 0xe000, UC_PROT_READ | UC_PROT_WRITE)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        put(0x4af4, 0 if name == 'post_without_context' else context)
        put(context + 8, 0x12345678)  # Synthetic task handle.
        put(context + 12, 0x87654320)  # Synthetic state object marker.
        put(context + 16, 0xa7)  # Logging class field.
        put(context + 88, 1 if name == 'handler_skip_af_branch' else 0)
        put(context + 140, 0x102000)  # Synthetic descriptor aggregate.
        errors, reached, boundaries = [], [], []
        ranges = ((0xfe2686fc, 0xfe26871e), (0xfe268514, 0xfe268530),
                  (0xfe2b969e, 0xfe2b96d4))

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not stack - 128 <= address <= stack - size:
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        def run(entry, stops):
            boundaries[:] = stops
            reached.clear()
            uc.emu_start(entry | 1, base + len(data), count=64, timeout=500_000)
            if errors or len(reached) != 1:
                raise RuntimeError(f'{name}: invalid/incomplete stage: {errors}')

        def arguments():
            return [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3)]

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, 0x10f001)  # Unmapped: unexpected return fails.
        if name.startswith('post_'):
            run(0xfe2686fc, (0xfe3ce01c, 0xfe52fa48))
            if name == 'post_without_context':
                if reached != [0xfe52fa48] or uc.reg_read(UC_ARM_REG_R2) != 250:
                    raise RuntimeError('Missing context did not reach expected assertion')
            else:
                if (reached != [0xfe3ce01c]
                        or arguments() != [0x12345678, context, 19, 0]
                        or source_word(0xfe3ce020) != 0x2353):
                    raise RuntimeError('Wrong event-19 task request')
        elif name == 'worker_forward':
            for reg, value in ((UC_ARM_REG_R0, context), (UC_ARM_REG_R1, 19),
                               (UC_ARM_REG_R2, 0), (UC_ARM_REG_R3, 0)):
                uc.reg_write(reg, value)
            run(0xfe268514, (0xfe3ce004,))
            if arguments() != [0x87654320, context, 19, 0]:
                raise RuntimeError('Wrong event-19 state-transition request')
        else:
            uc.reg_write(UC_ARM_REG_R0, context)
            run(0xfe2b969e, (0xfe3ce0fc,))
            if arguments()[:3] != [0xa7, 1, 0xfe2b99c4]:
                raise RuntimeError('Wrong AF-path handler logging arguments')
            # A separate slice after the logger; no fabricated call return.
            run(0xfe2b96be, (0xfe247768, 0xfe548550))
            expected = 0xfe548550 if name.endswith('skip_af_branch') else 0xfe247768
            if reached != [expected] or (expected == 0xfe247768
                    and arguments()[:2] != [0x102084, 0x10209c]):
                raise RuntimeError('Wrong conditional AF-path branch')
        if name != 'post_without_context':
            fifth = struct.unpack('<I', uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
            if name in ('post_raw_event', 'worker_forward') and fifth != 0:
                raise RuntimeError('Wrong fifth request argument')
        cases.append({'case': name, 'stopped_before': hex(reached[0]), 'passed': True})
    pool_cases = []
    index_address, pool_base = source_word(0xfe268b80), source_word(0xfe268d88)
    if (index_address, pool_base) != (0x25f9c, 0x41080):
        raise RuntimeError('Unexpected downstream result-pool literals')
    for initial in (0, 1, 2, 255):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(index_address & ~4095, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(index_address, bytes([initial]))
        uc.mem_map(0x10f000, 4096, UC_PROT_READ | UC_PROT_EXEC)
        errors, reached = [], []

        def pool_code_guard(emulator, address, size, _):
            if address == 0x10f000:
                reached.append(True)
                emulator.emu_stop()
            elif not 0xfe268a94 <= address <= 0xfe268ab8 - size:
                errors.append(f'Unexpected pool execution: {address:#x}')
                emulator.emu_stop()

        def pool_write_guard(emulator, access, address, size, value, _):
            if address != index_address or size != 1:
                errors.append(f'Unexpected pool write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, pool_code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, pool_write_guard)
        uc.reg_write(UC_ARM_REG_LR, 0x10f001)
        uc.emu_start(0xfe268a95, base + len(data), count=32, timeout=500_000)
        expected_index = (initial + 1) & 255
        if expected_index > 1:
            expected_index = 0
        expected_pointer = pool_base + expected_index * 1728
        if (errors or reached != [True]
                or bytes(uc.mem_read(index_address, 1)) != bytes([expected_index])
                or uc.reg_read(UC_ARM_REG_R0) != expected_pointer):
            raise RuntimeError(f'Wrong result-pool selection: {initial}: {errors}')
        pool_cases.append({'initial_index': initial, 'next_index': expected_index,
                           'returned_pointer': hex(expected_pointer), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'native_cases': cases,
            'separate_downstream_pool_cases': pool_cases,
            'decoded_event_19_transitions': transitions,
            'event_19_handler_label': 'evfAfPathCompleteInterrupt',
            'native_calls_stubbed': False, 'os_or_transport_executed': False,
            'pixels_or_buffer_lease_validated': False, 'camera_binding_enabled': False,
            'limits': 'Supplied EVF context, handles, descriptor address and branch flag. '
                      'Separate native slices; logger not executed or stubbed. EVF matrix '
                      'is decoded only, low-memory OS dispatcher and queue not executed. '
                      'AF processing and common continuation stop before execution. '
                      'No actual frame, buffer reuse, cache or timing is demonstrated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
