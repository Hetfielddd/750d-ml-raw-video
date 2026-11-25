# SPDX-License-Identifier: GPL-2.0-or-later
"""Check native asynchronous pool request preparation and callback boundaries.

Separate stages use supplied message storage and callback inputs. Neither the
allocator nor task delivery is executed or fabricated as successful.
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
                                   UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                                   UC_ARM_REG_R8, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, manager, packet, task, stack = 0xfe0a0000, 0x100000, 0x101000, 0x102000, 0x10d000
    callback, minimum = 0xfe11f435, 0x5a00000
    if struct.unpack_from('<I', data, 0xfe11f77c - base)[0] != callback:
        raise RuntimeError('Unexpected pool callback literal')
    cases = []
    for name in ('request_prefix', 'packet_submission', 'callback_minimum',
                 'callback_larger', 'callback_too_small'):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(0x4000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(manager, 0xe000, UC_PROT_READ | UC_PROT_WRITE)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(0x4be0, task)
        put(task + 4, 0x12345678)
        put(manager + 1804, 0xdeadbeef)
        errors, reached = [], []
        boundaries = (0xfe3ce0e4, 0xfe3ce01c, 0xfe3ce0fc, 0xfe52fa48)
        ranges = ((0xfe11f4b8, 0xfe11f4c4), (0xfe3f9356, 0xfe3f9366),
                  (0xfe3f93be, 0xfe3f93da), (0xfe3f6308, 0xfe3f6316),
                  (0xfe11f434, 0xfe11f45c))

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 128 <= address <= stack + 8 - size
                    or packet <= address <= packet + 48 - size
                    or address == manager + 1804 and size == 4):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        def args():
            return [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3)]

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, 0x10f001)  # Unmapped: unexpected return fails.
        uc.reg_write(UC_ARM_REG_R4, manager)
        if name == 'request_prefix':
            entry = 0xfe11f4b8
        elif name == 'packet_submission':
            entry = 0xfe3f93be
            for reg, value in ((UC_ARM_REG_R4, packet), (UC_ARM_REG_R5, callback),
                               (UC_ARM_REG_R8, manager), (UC_ARM_REG_R7, 0x4be0)):
                uc.reg_write(reg, value)
        else:
            entry = 0xfe11f434
            supplied_size = minimum + (0x600000 if name == 'callback_larger' else
                                       -1 if name == 'callback_too_small' else 0)
            for reg, value in ((UC_ARM_REG_R0, manager), (UC_ARM_REG_R1, 0x20000123),
                               (UC_ARM_REG_R2, supplied_size)):
                uc.reg_write(reg, value)
        uc.emu_start(entry | 1, base + len(data), count=64, timeout=500_000)
        if errors or len(reached) != 1:
            raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')
        if name == 'request_prefix':
            if (reached != [0xfe3ce0e4] or uc.reg_read(UC_ARM_REG_R0) != 48
                    or uc.reg_read(UC_ARM_REG_R5) != callback
                    or uc.reg_read(UC_ARM_REG_R6) != minimum
                    or uc.reg_read(UC_ARM_REG_R8) != manager):
                raise RuntimeError('Wrong request allocation boundary or callback capture')
        elif name == 'packet_submission':
            expected_packet = [0] * 12
            for index, value in ((2, 37), (7, callback), (8, manager), (10, 178)):
                expected_packet[index] = value
            actual_packet = list(struct.unpack('<12I', uc.mem_read(packet, 48)))
            if (reached != [0xfe3ce01c] or args() != [0x12345678, task, 0, packet]
                    or word(uc.reg_read(UC_ARM_REG_SP)) != 48
                    or actual_packet != expected_packet):
                raise RuntimeError('Wrong native message preparation')
        elif name == 'callback_too_small':
            if reached != [0xfe52fa48] or word(manager + 1804) != 0xdeadbeef:
                raise RuntimeError('Undersized callback did not reach assertion')
        elif (reached != [0xfe3ce0fc] or word(manager + 1804) != 0x20000123
              or uc.reg_read(UC_ARM_REG_LR) != 0xfe11f45d):
            raise RuntimeError('Wrong callback base publication')
        result = {'case': name, 'stopped_before': hex(reached[0]), 'passed': True}
        if name.startswith('callback_'):
            result['supplied_size_bytes'] = supplied_size
        cases.append(result)
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'minimum_callback_size_bytes': minimum, 'message_storage_bytes': 48,
            'native_calls_stubbed': False, 'allocation_or_task_delivery_executed': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Separate request-prefix, post-clear message-preparation and '
                      'callback stages. Message storage is supplied zeroed; allocation, '
                      'availability query, clearing helper, OS send/receive and actual '
                      'callback delivery are not executed. Callback sizes/bases are '
                      'supplied. No physical pool, pixels, DMA, cache or frame timing.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
