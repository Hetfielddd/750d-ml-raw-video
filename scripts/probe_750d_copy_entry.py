# SPDX-License-Identifier: GPL-2.0-or-later
"""Check primary copy-wrapper admission and native cache dispatch boundaries.

Controller status and memory classification are artificial fixtures. No OS wait,
cache maintenance, descriptor submission, DMA transfer or pixels are executed.
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
    base, stack, stop = 0xfe0a0000, 0x10d000, 0x10f000
    cases = []

    def make_uc():
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for address, size in ((0x25000, 4096), (0x40000, 4096), (0x100000, 0xe000)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        return uc

    def put(uc, address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(uc, address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def run(uc, entry, boundaries, ranges):
        reached, errors = [], []

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected copy-preparation code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 128 <= address and address + size <= stack):
                errors.append(f'Unexpected copy-preparation write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.emu_start(entry | 1, base + len(data), count=128, timeout=500_000)
        if errors or len(reached) != 1:
            raise RuntimeError(f'Invalid copy-preparation stage: {errors}/{reached}')
        return reached[0]

    for channel, channel_mask, status, count in (
            (0, 1, 0x10000000, 4096), (0, 1, 0, 4096),
            (0, 0, 0x10000000, 4096), (4, 16, 0x10000000, 4096),
            (1, 3, 0x10000000, 4096), (0, 1, 0x10000000, 0)):
        uc = make_uc()
        uc.mem_map(0xd6030000, 4096, UC_PROT_READ)
        put(uc, 0xd6030000, status)  # Artificial read-only controller status.
        put(uc, 0x257a0, channel_mask)
        handle = 0x2468ace0 + channel * 2
        if channel < 4:
            put(uc, 0x40844 + channel * 4, handle)
        destination, source = 0x5e000000, 0x5c62c000  # Unmapped markers.
        for register, value in ((UC_ARM_REG_R0, channel), (UC_ARM_REG_R1, destination),
                                (UC_ARM_REG_R2, source), (UC_ARM_REG_R3, count)):
            uc.reg_write(register, value)
        admitted = channel < 4 and channel_mask & (1 << channel) and status & 0x10000000
        reached = run(uc, 0xfe133eb2, (0xfe3ce0ac, stop),
                      ((0xfe133eb2, 0xfe133eec), (0xfe133e7e, 0xfe133eb2)))
        if admitted:
            sp = uc.reg_read(UC_ARM_REG_SP)
            if (reached != 0xfe3ce0ac or uc.reg_read(UC_ARM_REG_R0) != handle
                    or uc.reg_read(UC_ARM_REG_R1) != 0
                    or [word(uc, sp + offset) for offset in (0, 4, 8)]
                    != [destination, source, count]):
                raise RuntimeError('Wrong copy-wrapper wait preparation')
            result = 'os_wait_boundary'
        else:
            expected = 0xfffffffe if channel < 4 and channel_mask & (1 << channel) else 0xffffffff
            if reached != stop or uc.reg_read(UC_ARM_REG_R0) != expected:
                raise RuntimeError('Wrong native copy-wrapper rejection')
            result = hex(expected)
        cases.append({'case': 'copy_entry', 'supplied_channel': channel,
                      'supplied_channel_mask': hex(channel_mask), 'supplied_status': hex(status),
                      'supplied_bytes': count, 'result': result, 'passed': True})

    decoded = {}
    for access in (0x121, 0x12c):
        uc = make_uc()
        put(uc, stack, 0)  # Supplied saved R4/LR for post-CP15 decoder slice.
        put(uc, stack + 4, stop | 1)
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_R2, access)
        run(uc, 0xfe1758aa, (stop,), ((0xfe1758aa, 0xfe1758e8), (0xfe175914, 0xfe175954)))
        flags = uc.reg_read(UC_ARM_REG_R0)
        if flags != (8 if access == 0x121 else 4):
            raise RuntimeError('Wrong native cache-class decoder result')
        decoded[access] = flags
        cases.append({'case': 'attribute_decoder', 'supplied_access': hex(access),
                      'native_flags': flags, 'passed': True})

    for access in (0x121, 0x12c):
        uc = make_uc()
        put(uc, 0x25770 + 4, 0x100000)
        put(uc, 0x100000 + 12, 0xffffffff)
        put(uc, 0x100000 + 16, decoded[access])
        uc.reg_write(UC_ARM_REG_R0, 0x5c62c000)
        run(uc, 0xfe175544, (stop,),
            ((0xfe175544, 0xfe175564), (0xfe175500, 0xfe17551a)))
        if uc.reg_read(UC_ARM_REG_R0) != 0x5c62c000:
            raise RuntimeError('Unexpected normal-RAM address conversion')
        cases.append({'case': 'address_conversion', 'supplied_range_access': hex(access),
                      'input_and_output': '0x5c62c000', 'range_is_artificial': True,
                      'passed': True})
        for operation in (0, 1):
            uc = make_uc()
            put(uc, 0x25770 + 4, 0x100000)
            put(uc, 0x100000 + 12, 0xffffffff)
            put(uc, 0x100000 + 16, decoded[access])
            pointer, length = 0x5c62c000, 4096
            for register, value in ((UC_ARM_REG_R0, pointer), (UC_ARM_REG_R1, length),
                                    (UC_ARM_REG_R2, operation)):
                uc.reg_write(register, value)
            target = (0xfe555b84 if operation else 0xfe555b36) if access == 0x121 else 0xfe22ccde
            reached = run(uc, 0xfe133bac, (target,),
                          ((0xfe133bac, 0xfe133bdc), (0xfe175500, 0xfe17551a)))
            if (reached != target or access == 0x121
                    and (uc.reg_read(UC_ARM_REG_R0) != pointer
                         or uc.reg_read(UC_ARM_REG_R1) != length)):
                raise RuntimeError('Wrong native cache dispatch or forwarded range')
            cases.append({'case': 'cache_dispatch', 'supplied_range_access': hex(access),
                          'supplied_operation': operation, 'stopped_before': hex(target),
                          'range_is_artificial': True, 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'copy_entry_candidate': '0xfe133eb2', 'native_calls_stubbed': False,
            'os_wait_or_dma_executed': False, 'cache_maintenance_executed': False,
            'primary_live_mapping_validated': False, 'camera_binding_enabled': False,
            'limits': 'Supplied channel mask, semaphore handles, artificial controller '
                      'status and artificial one-record memory classification list. '
                      'Attribute decoder enters after CP15 reads with a supplied saved '
                      'frame. Copy entry stops before OS wait; cache dispatch before '
                      'maintenance/barrier helper. No pixel memory, DMA execution, live '
                      'cache mapping, completion timing or frame ownership established.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
