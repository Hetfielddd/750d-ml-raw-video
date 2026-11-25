# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe peer MPU programming operands without executing CP15 writes.

Executes only scalar setup slices between explicit stop boundaries.
No MPU, cache, address aliasing or device behavior is emulated.
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
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE,
                         UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC)
    from unicorn.arm_const import UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0, UC_ARM_REG_R1
    base, entry = 0xfe0a0000, 0xfe744e10
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(base, data)
    boundary, reached, errors = [0], [], []

    def code_guard(emulator, address, size, _):
        if address == boundary[0]:
            reached.append(address)
            emulator.emu_stop()
        elif not (0xfe744e10 <= address and address + size <= 0xfe744ef0
                  or 0xfe0a003a <= address and address + size <= 0xfe0a004a):
            errors.append(f'Unexpected MPU operand setup: {address:#x}')
            emulator.emu_stop()
        elif struct.unpack_from('<I', data, address - base)[0] & 0xffff0f10 == 0xee060f10:
            errors.append('Unexpected CP15 instruction would execute')
            emulator.emu_stop()

    def write_guard(emulator, access, address, size, value, _):
        errors.append(f'Unexpected scalar setup write: {address:#x}/{size}')
        emulator.emu_stop()

    uc.hook_add(UC_HOOK_CODE, code_guard)
    uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
    regions = []
    for index in range(7):
        region = {'index': index}
        for field, offset, opcode, register in (
                ('index', 4, 0xee060f12, UC_ARM_REG_R0),
                ('base', 12, 0xee061f11, UC_ARM_REG_R1),
                ('size_enable', 20, 0xee061f51, UC_ARM_REG_R1),
                ('access', 28, 0xee061f91, UC_ARM_REG_R1)):
            address = 0xfe744e10 + index * 32 + offset
            if struct.unpack_from('<I', data, address - base)[0] != opcode:
                raise RuntimeError('Unexpected reviewed MPU instruction boundary')
            boundary[0] = address
            reached.clear()
            uc.emu_start(entry, address + 4, count=16, timeout=500_000)
            if errors or reached != [address]:
                raise RuntimeError(f'Invalid MPU operand stage: {errors}/{reached}')
            value = uc.reg_read(register)
            if field == 'index' and value != index:
                raise RuntimeError('Unexpected MPU region index')
            region[field] = value
            # This intentionally does not execute the observed MCR. Later
            # scalar setup does not read its effects or require an MPU result.
            entry = address + 4
        size = 1 << (((region['size_enable'] >> 1) & 31) + 1)
        if not region['size_enable'] & 1 or region['base'] % size:
            raise RuntimeError('Unexpected disabled/misaligned reviewed MPU region')
        region['bytes'] = size
        region['last_address'] = region['base'] + size - 1
        regions.append(region)

    primary_operands = {}
    for field, start, address, register, expected in (
            ('region_index', 0xfe0a003a, 0xfe0a003e, UC_ARM_REG_R0, 1),
            ('access', 0xfe0a0042, 0xfe0a0046, UC_ARM_REG_R1, 0x121)):
        boundary[0] = address
        reached.clear()
        uc.emu_start(start | 1, address + 4, count=4, timeout=500_000)
        value = uc.reg_read(register)
        if errors or reached != [address] or value != expected:
            raise RuntimeError('Invalid primary startup MPU operand observation')
        primary_operands[field] = value

    addresses = []
    for address in (0x1c62c000, 0x5c62c000):
        matching = [r for r in regions if r['base'] <= address <= r['last_address']]
        winner = max(matching, key=lambda r: r['index'])
        access = winner['access']
        addresses.append({'address': hex(address), 'highest_matching_region': winner['index'],
                          'prepared_access': hex(access), 'tex': (access >> 3) & 7,
                          'shareable': bool(access & 4), 'c': bool(access & 2),
                          'b': bool(access & 1)})
    if ([r['index'] for r in regions] != list(range(7))
            or [a['highest_matching_region'] for a in addresses] != [0, 1]
            or [a['prepared_access'] for a in addresses] != ['0x121', '0x12c']):
        raise RuntimeError('Unexpected candidate-address region classification')
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'regions': regions,
            'address_checks': addresses, 'observed_cp15_write_boundaries': 30,
            'primary_entry_operands': primary_operands,
            'native_calls_stubbed': False, 'cp15_writes_executed': False,
            'primary_core_attributes_validated': False, 'cache_behavior_emulated': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Peer startup scalar setup and two primary entry operand slices; each MCR is observed '
                      'before execution and the next scalar slice entered separately. '
                      'No CP15 write/MPU enable, cache, physical address alias, live '
                      'primary-core mapping, DMA completion or pixel read is validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
