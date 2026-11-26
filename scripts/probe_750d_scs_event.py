# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the primary SCSState constructor and its actual event7 matrix dispatch.

The callback queue-to-object link is not established. Allocation and handler
execution past its first logger remain unexecuted; no frame ownership modeled.
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
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
                         UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, low_source = 0xfe0a0000, 0xfed58b7c
    obj, owner, stack, stop = 0x100000, 0x101000, 0x10d000, 0x10f000
    table, name, handler = 0xfea06d08, 0xfed522f8, 0xfe13dc5e
    active = (10, 11, 14, 15, 16)
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(base, data)
    uc.mem_map(0, 0x4000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(0, data[low_source - base:low_source - base + 0x4000])
    uc.mem_map(obj, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def args():
        return [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]

    ranges = ((0xfe13ca78, 0xfe13ca8e), (0x211a, 0x2150),
              (0x20ae, 0x211a), (handler, 0xfe13dc84))

    def run(entry, target, supplied=(), entry_sp=stack):
        errors, reached = [], []

        def code_guard(emulator, address, size, _):
            if address == target:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected SCS code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 256 <= address and address + size <= stack
                    or obj <= address and address + size <= obj + 32):
                errors.append(f'Unexpected SCS write: {address:#x}/{size}')
                emulator.emu_stop()

        hooks = [uc.hook_add(UC_HOOK_CODE, code_guard), uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)]
        uc.reg_write(UC_ARM_REG_SP, entry_sp)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        for register, value in supplied:
            uc.reg_write(register, value)
        try:
            uc.emu_start(entry | 1, base + len(data), count=192, timeout=500_000)
        finally:
            for hook in hooks:
                uc.hook_del(hook)
        if errors or reached != [target]:
            raise RuntimeError(f'Invalid SCS stage: {errors}/{reached}')
        if target == stop and uc.reg_read(UC_ARM_REG_SP) != stack:
            raise RuntimeError('SCS native return did not restore stack')

    run(0xfe13ca78, 0xfe3ce074)
    constructor_args = args()
    if constructor_args != [name, 0, table, 26] or word(uc.reg_read(UC_ARM_REG_SP)) != 18:
        raise RuntimeError('SCS constructor did not select the reviewed matrix/dimensions')
    # Execute actual primary low-kernel constructor prefix to allocation, then
    # a separate post-allocation slice with supplied scratch storage. The native
    # saved frame/registers are retained; no allocator return is synthesized.
    put(stack, 18)
    run(0x211a, 0x10ea, tuple(zip(
        (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), constructor_args)))
    if uc.reg_read(UC_ARM_REG_R0) != 32:
        raise RuntimeError('Native state constructor did not request32bytes')
    run(0x2138, stop, ((UC_ARM_REG_R0, obj),), entry_sp=uc.reg_read(UC_ARM_REG_SP))
    if [word(obj + off) for off in (4, 8, 12, 16, 20, 24, 28)] != [name, 0, 0x20af, table, 26, 18, 0]:
        raise RuntimeError('Native SCS state-object publication mismatch')
    signature = word(obj)
    cases = []
    for current in range(18):
        put(obj + 28, current)
        put(stack, 0)
        run(0x20ae, 0xfe3ce0fc if current in active else stop,
            ((UC_ARM_REG_R0, obj), (UC_ARM_REG_R1, owner),
             (UC_ARM_REG_R2, 7), (UC_ARM_REG_R3, 0)))
        if word(obj + 28) != current:
            raise RuntimeError('SCS event7 unexpectedly changed the current state')
        if current not in active and uc.reg_read(UC_ARM_REG_R0) != 0:
            raise RuntimeError('Absent SCS event7 handler did not return zero')
        entry = table + (7 * 18 + current) * 8
        if word(entry + 4) != (handler | 1 if current in active else 0):
            raise RuntimeError('Unexpected event7 table handler')
        cases.append({'current_state': current, 'input': 7,
                      'handler_source': hex(handler) if current in active else None,
                      'stopped_before_logger': current in active,
                      'no_handler_returned_zero': current not in active, 'passed': True})
    for label, sig, event, expected in (('invalid_signature', signature ^ 1, 7, 7),
                                        ('input_outside_limit', signature, 27, 3)):
        put(obj, sig)
        put(obj + 28, 0)
        put(stack, 0)
        run(0x20ae, stop, ((UC_ARM_REG_R0, obj), (UC_ARM_REG_R1, owner),
                           (UC_ARM_REG_R2, event), (UC_ARM_REG_R3, 0)))
        if uc.reg_read(UC_ARM_REG_R0) != expected:
            raise RuntimeError('Native SCS rejection returned an unexpected value')
        cases.append({'case': label, 'native_return': expected, 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'constructor_name': 'SCSState', 'matrix': hex(table), 'event7_active_states': list(active),
            'native_calls_stubbed': False, 'queue_to_this_object_validated': False,
            'allocation_or_handler_body_completed': False, 'camera_binding_enabled': False,
            'frame_lease_validated': False,
            'limits': 'Actual constructor argument preparation and primary low-kernel '
                      'constructor/dispatcher slices. Allocation stops at its boundary; '
                      'a separate post-allocation slice publishes into supplied scratch. '
                      'Current states, owner and event delivery are fixtures. Candidate '
                      'SCSState is distinct from EVF; callback queue routing to this object '
                      'is not established. Active handlers stop before their first logger. '
                      'No sensor transfer, pixels, completed capture or buffer ownership modeled.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
