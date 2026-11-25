# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the reviewed native resource-22 route without allocating pixels."""
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
                                   UC_ARM_REG_R4, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, config, manager, stack = 0xfe0a0000, 0x100000, 0x101000, 0x10d000
    definitions = (('mode_1', 1, 0x20000000, 0, 0),
                   ('mode_2_counter_wrap', 2, 0x30000000, 0xffffffff, 0),
                   ('existing_address', 1, 0x20000000, 17, 0x12345000),
                   ('missing_configuration', 0, 0, 0, 0),
                   ('wrong_requested_count', 1, 0x20000000, 0, 0))
    results = []
    for name, mode, pool_base, counter, existing in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(0x27000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(config, 0xe000, UC_PROT_READ | UC_PROT_WRITE)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(0x27b80, config if mode else 0)
        put(config, mode)
        put(config + 44, pool_base)
        put(config + 984, counter)
        put(manager + 1808, existing)
        put(manager + 1812, 0xdeadbeef)
        errors, reached, path = [], [], []
        boundaries = (0xfe11f4f8, 0xfe11f518, 0xfe52fa48, 0xfe3ce0fc)
        ranges = ((0xfe11f4e4, 0xfe11f4f8), (0xfe41c49c, 0xfe41c4b2),
                  (0xfe41c4f2, 0xfe41c572), (0xfe41c58c, 0xfe41c59a),
                  (0xfe41d882, 0xfe41d8cc), (0xfe41da1a, 0xfe41da1c),
                  (0xfe41db2e, 0xfe41db38), (0xfe41d916, 0xfe41d91a),
                  (0xfe41db9e, 0xfe41dbb2))

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()
            if address in (0xfe41c4f2, 0xfe41d882):
                path.append(hex(address))

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 256 <= address <= stack + 8 - size
                    or (address, size) in ((manager + 1808, 4), (manager + 1812, 4),
                                          (config + 984, 4))):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, 0x10f001)  # Unmapped: unexpected return fails.
        uc.reg_write(UC_ARM_REG_R4, manager)
        entry = 0xfe11f4e4
        if name == 'wrong_requested_count':
            entry = 0xfe41c4f2
            for reg, value in ((UC_ARM_REG_R0, manager + 1808),
                               (UC_ARM_REG_R1, manager + 1812),
                               (UC_ARM_REG_R2, 2), (UC_ARM_REG_R3, 22)):
                uc.reg_write(reg, value)
        uc.emu_start(entry | 1, base + len(data), count=192, timeout=500_000)
        if errors or len(reached) != 1:
            raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')
        if name.startswith('mode_'):
            if (reached != [0xfe11f4f8] or word(manager + 1808) != pool_base + 0x3dfc000
                    or word(manager + 1812) != 0x1d5d800
                    or word(config + 984) != (counter + 1) & 0xffffffff
                    or path != ['0xfe41c4f2', '0xfe41d882']):
                raise RuntimeError('Wrong resource-22 result or provider selection')
            results.append({'case': name, 'supplied_pool_base': hex(pool_base),
                            'address': hex(word(manager + 1808)),
                            'reported_size_bytes': word(manager + 1812), 'passed': True})
        else:
            expected = (0xfe11f518 if existing else
                        0xfe3ce0fc if name == 'wrong_requested_count' else 0xfe52fa48)
            if (reached != [expected] or word(manager + 1808) != existing
                    or word(manager + 1812) != 0xdeadbeef or word(config + 984) != counter):
                raise RuntimeError('Wrong skip/diagnostic behavior')
            results.append({'case': name, 'stopped_before': hex(expected), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': results,
            'resource_id': 22, 'expected_count': 1, 'provider_class': 2,
            'native_calls_stubbed': False, 'pool_or_pixels_mapped': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Supplied configuration mode, pool base and manager state. Native '
                      'resource lookup executes for modes 1/2 only; other provider modes '
                      'are untested. This computes a resource subregion, not an allocation '
                      'of physical RAM. No live address, image size/format, DMA completion, '
                      'cache, timing or frame ownership is validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
