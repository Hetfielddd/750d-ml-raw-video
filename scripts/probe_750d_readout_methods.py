# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute actual readout method rows up to transport or downstream boundaries.

Selector/configuration inputs are supplied. Logging is separated at reviewed
continuations; no transport, hardware restart or frame lease is emulated.
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
                                   UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, obj, descriptor, context, stack = 0xfe0a0000, 0x100000, 0x101000, 0x102000, 0x10d000
    method_base = struct.unpack_from('<I', data, 0xfe248b50 - base)[0]
    signature = struct.unpack_from('<I', data, 0xfea517ec - base)[0]
    if method_base != 0xfea559f4:
        raise RuntimeError('Unexpected method table base')
    rows = ((3, 0x2f244, (0xfe28d626, 0xfe28d3d8, 0xfe28d5f4, 0xfe28d3b0),
             (0xfe28d648, 0xfe28d618)),
            (9, 0x2f32c, (0xfe28fe38, 0xfe28f8e6, 0xfe28fe02, 0xfe28f8be),
             (0xfe28fe5e, 0xfe28fe2a)))
    cases = []
    for selector, state, methods, log_continuations in rows:
        for driver_active in (0, 1):
            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
            uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
            uc.mem_write(base, data)
            for page in (0x27000, 0x2f000, 0x6b000):
                uc.mem_map(page, 4096, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_map(obj, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_map(0x10f000, 4096, UC_PROT_READ | UC_PROT_EXEC)

            def put(address, value):
                uc.mem_write(address, struct.pack('<I', value))

            def word(address):
                return struct.unpack('<I', uc.mem_read(address, 4))[0]

            put(context, 1 if selector == 3 else 2)
            put(context + 8, 5)
            put(obj, signature)
            put(state, 1)  # Supplied initialized registration.
            put(state + 12, driver_active)
            put(state + 32, descriptor)
            put(descriptor, 0xdeadbeef)
            put(0x6b380, 0x10203040)  # Parameter marker, never a claimed image.
            errors, reached, boundary, calls = [], [], [], []
            ranges = ((0xfe248a12, 0xfe248a64), (0xfe2489d2, 0xfe2489e2),
                      (0xfe30a6fc, 0xfe30a71a), (0xfe30a728, 0xfe30a738),
                      (0xfe1c6bfa, 0xfe1c6c3e), (0xfe28d3b0, 0xfe28d3fe),
                      (0xfe28d5f4, 0xfe28d64c), (0xfe28f8be, 0xfe28f90c),
                      (0xfe28fe02, 0xfe28fe62), (0xfe380766, 0xfe380772),
                      (0xfe443016, 0xfe44302a))

            def code_guard(emulator, address, size, _):
                if address in boundary:
                    reached.append(address)
                    emulator.emu_stop()
                elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                    errors.append(f'Unexpected method execution: {address:#x}')
                    emulator.emu_stop()
                if address in methods:
                    calls.append(hex(address))

            def write_guard(emulator, access, address, size, value, _):
                if not (stack - 256 <= address <= stack - size
                        or (address, size) in ((0x27258, 4), (descriptor, 4))):
                    errors.append(f'Unexpected method write: {address:#x}/{size}')
                    emulator.emu_stop()

            def run(entry, stops):
                reached.clear()
                boundary[:] = stops
                uc.emu_start(entry | 1, base + len(data), count=256, timeout=500_000)
                if errors or len(reached) != 1:
                    raise RuntimeError(f'{selector}/{driver_active}: incomplete/invalid stage: {errors}')

            uc.hook_add(UC_HOOK_CODE, code_guard)
            uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_R4, context)
            uc.reg_write(UC_ARM_REG_R5, 19)
            run(0xfe248a12, (0xfe248b08,))  # Separate post-log selector core.
            if uc.reg_read(UC_ARM_REG_R5) != selector:
                raise RuntimeError('Wrong selector result')
            uc.mem_write(stack - 16, struct.pack('<4I', 0, 0, 0, 0x10f001))
            uc.reg_write(UC_ARM_REG_SP, stack - 16)
            uc.reg_write(UC_ARM_REG_R4, selector)
            uc.reg_write(UC_ARM_REG_R5, 0x27258)
            run(0xfe2489d2, (0x10f000,))  # Native table publication after its logger.
            table = method_base + selector * 72
            if word(0x27258) != table:
                raise RuntimeError('Wrong native operation-table publication')
            actual = [word(table + offset) & ~1 for offset in (32, 8, 28, 4)]
            if actual != list(methods):
                raise RuntimeError('Wrong registered native methods')
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, 0x10f001)
            uc.reg_write(UC_ARM_REG_R0, obj)
            entry, logs = 0xfe30a6fc, []
            for _ in range(3):
                run(entry, (0xfe3ce0fc, 0xfe48d25c, 0xfe2d1346))
                if reached != [0xfe3ce0fc]:
                    break
                entry = uc.reg_read(UC_ARM_REG_LR) & ~1
                if entry not in log_continuations:
                    raise RuntimeError('Unexpected logger continuation')
                logs.append(hex(entry))
                # Keep native frames; enter the reviewed continuation. No
                # fabricated logger return or modeled register side effects.
            expected_stop = 0xfe48d25c if driver_active else 0xfe2d1346
            expected_calls = [hex(a) for a in methods[:3 if driver_active else 4]]
            if reached != [expected_stop] or calls != expected_calls:
                raise RuntimeError('Wrong actual-method ordering or transport boundary')
            if driver_active:
                args = [uc.reg_read(r) for r in
                        (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
                if (args != [4, 2, 0x202, descriptor] or word(descriptor) != 0x10203040
                        or logs != [hex(x) for x in log_continuations]):
                    raise RuntimeError('Wrong StartDriver request preparation')
            elif word(descriptor) != 0xdeadbeef or logs:
                raise RuntimeError('Disabled driver path changed descriptor or logged')
            cases.append({'selector': selector, 'supplied_driver_active': driver_active,
                          'native_methods_reached': calls, 'stopped_before': hex(expected_stop),
                          'start_driver_operation_prepared': bool(driver_active), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'transport_or_mmio_executed': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Supplied selector context, initialized flags, driver-active flag, '
                      'descriptor storage and parameter marker. Native table selection '
                      'and real methods; reviewed logging continuations are entered '
                      'separately. No OS transport, peer receive, hardware restart, '
                      'pixels, cache, frame identity or live reuse timing is validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
