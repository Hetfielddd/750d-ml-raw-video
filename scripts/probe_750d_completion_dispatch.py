# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow supplied completion events through the native task dispatcher.

Uses scoped source/runtime copies, not a boot relocation model. Stops before
Postman transport. No OS queue, sensor pixels, buffer lease or DMA is modeled.
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

    base, app_delta, driver_delta = 0xfe0a0000, 0xfcc82368, 0x7e7473e0
    obj, context, stack, stop = 0x100000, 0x101000, 0x10d000, 0x10f000
    table, boundary = 0x1cf2190, 0xfe86f644 - app_delta
    signature = struct.unpack_from('<I', data, 0xfe756b40 - base)[0]
    cases = []
    definitions = [(f'event_{event}_route_{route:08x}_arg_{arg:x}', event, route, arg, True)
                   for event in (6, 7) for route in (0x20002, 0x30007)
                   for arg in (0, 0x12345678)]
    definitions += [('invalid_signature', 6, 0x20002, 0, False),
                    ('event_outside_limit', 9, 0x20002, 0, True)]
    for name, event, route, argument, valid_signature in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for runtime, delta in ((0x80005000, driver_delta), (0x8000f000, driver_delta),
                               (0x1b8d000, app_delta), (0x1bed000, app_delta),
                               (0x1cf2000, app_delta)):
            uc.mem_map(runtime, 4096, UC_PROT_READ | UC_PROT_EXEC)
            source = runtime + delta
            uc.mem_write(runtime, data[source - base:source - base + 4096])
        uc.mem_map(obj, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        # Constructor layout, supplied without invoking allocation or OS setup.
        fields = (signature if valid_signature else signature ^ 1, 0, 0,
                  (0xfe74cbfa - driver_delta) | 1, table, 8, 1, 0)
        for index, value in enumerate(fields):
            put(obj + 4 * index, value)
        put(context + 4, 0)
        put(context + 8, route)
        put(stack, 0)  # Fifth argument to dispatcher wrapper.
        errors, reached, path, writes = [], [], [], []
        ranges = ((0x800057fc, 0x80005886),
                  (0xfe80fe10 - app_delta, 0xfe80fe34 - app_delta),
                  (0xfe86fbde - app_delta, 0xfe86fbf2 - app_delta))

        def code_guard(emulator, address, size, _):
            if address in (boundary, stop):
                reached.append(address)
                emulator.emu_stop()
                return
            if not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()
            if address in (0xfe80fe10 - app_delta, 0xfe80fe22 - app_delta):
                path.append(hex(address))

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 128 <= address and address + size <= stack
                    or address == obj + 28 and size == 4):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()
            if address == obj + 28:
                writes.append(value)

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        for register, value in ((UC_ARM_REG_R0, obj), (UC_ARM_REG_R1, context),
                                (UC_ARM_REG_R2, event), (UC_ARM_REG_R3, argument),
                                (UC_ARM_REG_SP, stack), (UC_ARM_REG_LR, stop | 1)):
            uc.reg_write(register, value)
        uc.emu_start(0x800057fd, stop + 4, count=128, timeout=500_000)
        if errors or len(reached) != 1:
            raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')
        if valid_signature and event in (6, 7):
            operation = 2 if event == 6 else 6
            expected = [5, route >> 16, ((route & 0xffff) << 8) | operation, argument]
            actual = [uc.reg_read(register) for register in
                      (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            target = (0xfe80fe10 if event == 6 else 0xfe80fe22) - app_delta
            record = table + event * 8
            if (reached != [boundary] or actual != expected or path != [hex(target)]
                    or word(record) != 0 or word(record + 4) != (target | 1)
                    or writes != [0] or word(obj + 28) != 0):
                raise RuntimeError(f'{name}: wrong dispatch, state or transport arguments')
            cases.append({'case': name, 'event': event, 'handler_runtime': hex(target),
                          'postman_operation': operation, 'supplied_route': hex(route),
                          'transport_arguments': [hex(x) for x in actual], 'passed': True})
        else:
            expected = 7 if not valid_signature else 3
            if (reached != [stop] or uc.reg_read(UC_ARM_REG_R0) != expected
                    or path or writes):
                raise RuntimeError(f'{name}: wrong rejection')
            cases.append({'case': name, 'return_code': expected, 'passed': True})
    receiver_cases = []
    for operation, slot, target in ((2, 0, 0xfe28d2d0), (6, 8, 0xfe293028)):
        for enabled in (False, True):
            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
            uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
            uc.mem_write(base, data)
            uc.mem_map(0x36000, 4096, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
            uc.mem_write(0x36720 + slot, struct.pack('<2I', target | 1 if enabled else 0,
                                                   0x76543210))
            reached, errors = [], []

            def receive_code_guard(emulator, address, size, _):
                if address in (target, stop):
                    reached.append(address)
                    emulator.emu_stop()
                elif not (0xfe3806fe <= address and address + size <= 0xfe380706
                          or 0xfe3807ba <= address and address + size <= 0xfe3807c8
                          or 0xfe3807d0 <= address and address + size <= 0xfe3807de):
                    errors.append(f'Unexpected receiver execution: {address:#x}')
                    emulator.emu_stop()

            def receive_write_guard(emulator, access, address, size, value, _):
                errors.append(f'Unexpected receiver write: {address:#x}/{size}')
                emulator.emu_stop()

            uc.hook_add(UC_HOOK_CODE, receive_code_guard)
            uc.hook_add(UC_HOOK_MEM_WRITE, receive_write_guard)
            uc.reg_write(UC_ARM_REG_R0, 0x12345678)
            uc.reg_write(UC_ARM_REG_R1, operation)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            uc.emu_start(0xfe3806ff, base + len(data), count=32, timeout=500_000)
            if (errors or reached != [target if enabled else stop]
                    or enabled and uc.reg_read(UC_ARM_REG_R0) != 0x76543210):
                raise RuntimeError(f'Wrong receiver selection: {operation}/{enabled}: {errors}')
            receiver_cases.append({'operation': operation, 'callback_slot': slot,
                                   'supplied_callback_enabled': enabled,
                                   'callback_source': hex(target), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'separate_receiver_cases': receiver_cases,
            'native_calls_stubbed': False, 'queue_or_transport_executed': False,
            'camera_binding_enabled': False, 'raw_capture_demonstrated': False,
            'limits': 'Supplied object/context, state zero, routes and event delivery. '
                      'Scoped page copies are not validated boot relocations. Native '
                      'dispatcher and table select native application handlers; stop '
                      'before transport veneer. Separate receiver calls use supplied '
                      'slots and stop before the selected callbacks. No queue, MMIO, pixels, timing, cache '
                      'or buffer ownership is demonstrated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
