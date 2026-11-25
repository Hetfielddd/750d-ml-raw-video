# SPDX-License-Identifier: GPL-2.0-or-later
"""Check readout-done callback ordering and a separate internal-phase slice.

Registered methods are supplied native BX LR leaves. Their real semantics,
the OS, sensor/DMA completion and frame ownership are not modeled.
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
                                   UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                                   UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, stack, evf = 0xfe0a0000, 0x10d000, 0x26b94

    def make_uc():
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(0x26000, 8192, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(0x100000, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, 0x10f001)
        return uc

    def put(uc, address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(uc, address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    signature = struct.unpack_from('<I', data, 0xfea517ec - base)[0]
    leaves = (0xfe205378, 0xfe20537a, 0xfe3807b8, 0xfe751130)
    if any(data[a - base:a - base + 2] != b'\x70\x47' for a in leaves):
        raise RuntimeError('Expected native BX LR observation leaves')
    callback_cases = []
    for name in ('methods_present', 'methods_absent', 'invalid_object_signature'):
        uc = make_uc()
        ops, obj = 0x100000, 0x101000
        put(uc, obj, signature ^ (1 if name.startswith('invalid') else 0))
        put(uc, 0x27258, 0 if name == 'methods_absent' else ops)
        for offset, leaf in zip((32, 8, 28, 4), leaves):
            put(uc, ops + offset, leaf | 1)
        reached, errors, calls = [], [], []

        def code_guard(emulator, address, size, _):
            if address in (0xfe2d1346, 0xfe3ce0fc):
                reached.append(address)
                emulator.emu_stop()
            elif address in leaves:
                calls.append({'native_leaf': hex(address),
                              'r0': hex(emulator.reg_read(UC_ARM_REG_R0))})
            elif not (0xfe30a6fc <= address <= 0xfe30a71a - size
                      or 0xfe30a728 <= address <= 0xfe30a738 - size
                      or 0xfe1c6bfa <= address <= 0xfe1c6c3e - size):
                errors.append(f'Unexpected completion execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not stack - 128 <= address <= stack - size:
                errors.append(f'Unexpected completion write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.reg_write(UC_ARM_REG_R0, obj)
        uc.emu_start(0xfe30a6fd, base + len(data), count=128, timeout=500_000)
        expected_calls = []
        if name == 'methods_present':
            expected_calls = [{'native_leaf': hex(a), 'r0': hex(arg)} for a, arg in
                              zip(leaves, (leaves[0] | 1, leaves[1] | 1, 0x6b380, 0x6b370))]
        expected_stop = 0xfe3ce0fc if name.startswith('invalid') else 0xfe2d1346
        if errors or reached != [expected_stop] or calls != expected_calls:
            raise RuntimeError(f'{name}: wrong completion path/order: {errors}')
        callback_cases.append({'case': name, 'calls': calls,
                               'stopped_before': hex(expected_stop), 'passed': True})

    phase_cases = []
    for flag, phase, expected in ((0, 4, 5), (0, 5, 5), (0, 3, 3),
                                   (1, 0, 1), (1, 1, 3), (1, 3, 4),
                                   (1, 4, 5), (1, 5, 5), (1, 6, 0), (1, 2, None)):
        uc = make_uc()
        globals_, notification, context = 0x100000, 0x101000, 0x102000
        uc.mem_write(globals_ + 232, struct.pack('<H', flag))
        put(uc, globals_ + 236, notification)
        put(uc, evf + 16, phase)
        put(uc, context + 16, 0xa7)
        reached, errors = [], []

        def phase_code_guard(emulator, address, size, _):
            if address in (0xfe30b1b4, 0xfe52fa48, 0xfe3ce0fc):
                reached.append(address)
                emulator.emu_stop()
            elif not 0xfe2b956a <= address <= 0xfe2b95d0 - size:
                errors.append(f'Unexpected phase execution: {address:#x}')
                emulator.emu_stop()

        def phase_write_guard(emulator, access, address, size, value, _):
            if (address, size) not in ((evf + 16, 4), (notification, 4)):
                errors.append(f'Unexpected phase write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, phase_code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, phase_write_guard)
        for reg, value in ((UC_ARM_REG_R4, context), (UC_ARM_REG_R5, evf),
                           (UC_ARM_REG_R6, 1), (UC_ARM_REG_R7, globals_)):
            uc.reg_write(reg, value)
        uc.emu_start(0xfe2b956b, base + len(data), count=64, timeout=500_000)
        if reached == [0xfe3ce0fc]:
            # Separate post-logger slice; no forced call return. The next
            # instruction reloads the phase, independent of a logger result.
            reached.clear()
            uc.emu_start(0xfe2b9587, base + len(data), count=64, timeout=500_000)
        target = 0xfe52fa48 if expected is None else 0xfe30b1b4
        if (errors or reached != [target]
                or word(uc, evf + 16) != (phase if expected is None else expected)
                or word(uc, notification) != (1 if flag and phase == 3 else 0)):
            raise RuntimeError(f'{flag}/{phase}: wrong phase transition: {errors}')
        phase_cases.append({'supplied_flag': flag, 'old_internal_phase': phase,
                            'new_internal_phase': word(uc, evf + 16),
                            'assertion_boundary': expected is None, 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True,
            'callback_cases': callback_cases, 'internal_phase_cases': phase_cases,
            'native_calls_stubbed': False, 'mmio_or_pixels_mapped': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Supplied operation-table registration and native BX LR leaves '
                      'test dispatch order, not the real methods. Separate mid-handler '
                      'phase slices supply registers and skip the logger without '
                      'fabricating its return. Internal phase at 0x26ba4 is distinct '
                      'from the state-object old state used by the donor VSYNC hook. '
                      'Downstream routines stop before execution; no DMA, cache, '
                      'buffer ownership, frame identity or live timing is validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
