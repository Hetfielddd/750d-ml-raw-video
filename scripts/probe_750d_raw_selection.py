# SPDX-License-Identifier: GPL-2.0-or-later
"""Check native counter-restricted RAW selection across supplied event sequences.

Logger boundaries use separately entered reviewed continuations, never a
fabricated logger return. Counter order and fallback are inputs, not hardware.
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
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, state, evf = 0xfe0a0000, 0x2af78, 0x26b94
    caller, argument, stack, stop = 0x100000, 0x101000, 0x10c000, 0x10f000
    transition = struct.unpack_from('<2I', data, 0xfea0b174 - base + (3 * 10 + 5) * 8)
    vd_global_literal = struct.unpack_from('<I', data, 0xfe2b8ea0 - base)[0]
    if transition != (5, 0xfe2b8c19) or vd_global_literal - 100 != evf:
        raise RuntimeError('Unexpected VD event table entry or EVF global literal')
    candidate, fallback = 0x5c62c000, 0x12345000  # Unmapped address markers.
    definitions = (
        ('restricted_sequence', 17, (16, 17, 18), fallback, None),
        ('same_counter_repeated', 17, (17, 17), fallback, None),
        ('zero_disables_restriction', 0, (17, 18), fallback, None),
        ('cleared_tag_matches_zero', 17, (17, 0), fallback, None),
        ('fallback_equals_candidate', 17, (18,), candidate, None),
        ('explicit_rearm', 17, (17, 18), fallback, 18),
        ('native_zero_fallback', 17, (17, 18), 0, None),
        ('native_zero_fallback_counter_zero', 17, (17, 0), 0, None),
        ('native_vd_first_then_increment', 1, (1, 2), 0, None),
        ('native_vd_increment', 17, (17, 18), 0, None),
        ('native_vd_wrap', 0xffffffff, (0xffffffff, 0), 0, None),
        ('native_vd_wrap_raw_disabled', 0xffffffff, (0xffffffff, 0), 0, None),
    )
    cases = []
    for name, tag, counters, supplied_fallback, rearm in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for address, size in ((0x26000, 4096), (0x2a000, 4096), (caller, 0xe000)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        reached, errors, boundary = [], [], []

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        def code_guard(emulator, address, size, _):
            if address in boundary:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in
                         ((0xfe308eb4, 0xfe308eda), (0xfe309cf0, 0xfe309d10),
                          (0xfe2b92ae, 0xfe2b9324), (0xfe2b911a, 0xfe2b9126),
                          (0xfe2b8cd4, 0xfe2b8ce8), (0xfe2b8cf8, 0xfe2b8cfa),
                          (0xfe2b9094, 0xfe2b909a))):
                errors.append(f'Unexpected selection code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 64 <= address and address + size <= stack
                    or (address, size) in {(state + offset, 4) for offset in (4, 8, 12, 44)}
                    or (address, size) in ((stack, 4), (stack + 0xdc, 4),
                                          (evf + 24, 4), (caller + 52, 4))):
                errors.append(f'Unexpected selection write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def run(entry, stops):
            reached.clear()
            boundary[:] = stops
            uc.emu_start(entry | 1, base + len(data), count=128, timeout=500_000)
            if errors or len(reached) != 1:
                raise RuntimeError(f'Invalid selection stage: {errors}/{reached}')
            return reached[0]

        def setter(entry, value):
            put(argument, value)
            uc.reg_write(UC_ARM_REG_R0, argument)
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            run(entry, (stop,))

        setter(0xfe308eb4, 1)
        setter(0xfe308eca, tag)
        if word(state + 44) != tag or word(state + 8) != bool(tag):
            raise RuntimeError('Wrong native counter restriction setter')
        put(caller + 52, 1)
        put(evf + 88, candidate)
        steps = []
        restricted = bool(tag)
        native_counter = name.startswith('native_vd_')
        enabled = True
        if native_counter:
            put(evf + 24, 0xffffffff if name == 'native_vd_first_then_increment'
                else (counters[0] - 1) & 0xffffffff)
            put(caller + 64, 39)  # Skip the first-frame notification call.
        for index, counter in enumerate(counters):
            if index and rearm is not None:
                setter(0xfe308eca, rearm)
                tag, restricted = rearm, bool(rearm)
            if index and name == 'native_vd_wrap_raw_disabled':
                setter(0xfe308eb4, 0)
                enabled = False
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_R4, caller)
            uc.reg_write(UC_ARM_REG_R7, evf)
            if native_counter:
                if index == 0 and name == 'native_vd_first_then_increment':
                    run(0xfe2b8cd4, (0xfe2b8ce8,))
                    # Separate post-call store, preserving the produced R5=1.
                    # Intervening helper calls are not executed or returned.
                    run(0xfe2b8cf8, (0xfe2b8cfa,))
                else:
                    run(0xfe2b9094, (0xfe2b909a,))
                if word(evf + 24) != counter:
                    raise RuntimeError('Wrong native VD counter update')
            else:
                put(evf + 24, counter)
            if supplied_fallback == 0:
                uc.reg_write(UC_ARM_REG_R8, 0xdeadbeef)
                run(0xfe2b911a, (0xfe2b9126,))
                if uc.reg_read(UC_ARM_REG_R8) != 0:
                    raise RuntimeError('Wrong native fallback initialization')
            else:
                uc.reg_write(UC_ARM_REG_R8, supplied_fallback)
            reached_at = run(0xfe2b92ae, (0xfe3ce0fc, 0xfe2b9324))
            matched = enabled and restricted and tag == counter
            if enabled:
                if reached_at != 0xfe3ce0fc:
                    raise RuntimeError('Expected reviewed logger boundary')
                continuation = uc.reg_read(UC_ARM_REG_LR) & ~1
                if continuation != (0xfe2b92e8 if matched else 0xfe2b9302):
                    raise RuntimeError('Wrong native selection branch')
                # Checked post-log continuation; no CPU return is synthesized.
                run(continuation, (0xfe2b9324,))
            elif reached_at != 0xfe2b9324:
                raise RuntimeError('Disabled RAW unexpectedly entered selection logger')
            expected = candidate if enabled and (not restricted or matched) else supplied_fallback
            if matched:
                tag = 0
            if (word(stack + 0xdc) != expected or word(state + 44) != tag
                    or word(state + 8) != restricted or word(state + 4) != enabled):
                raise RuntimeError('Wrong native sequence selection or tag lifetime')
            steps.append({'supplied_counter': counter, 'selected_address': hex(expected),
                          'remaining_tag': tag, 'restriction_enabled': restricted,
                          'raw_enabled': enabled, 'counter_updated_natively': native_counter})
        cases.append({'case': name, 'supplied_fallback': hex(supplied_fallback),
                      'native_zero_fallback_initialization': supplied_fallback == 0,
                      'steps': steps, 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'camera_binding_enabled': False,
            'frame_lease_validated': False,
            'limits': 'Supplied route-active caller, EVF counters, fallback and unmapped '
                      'candidate marker. Native setters/getters and selection slices; '
                      'reviewed post-log continuations entered separately. No logger '
                      'return modeled. Four cases execute reviewed VD counter-update '
                      'slices; first-frame setup/store are separated around unexecuted '
                      'helpers. No complete native event delivery, DMA, '
                      'pixel memory, cache coherence or buffer ownership validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
