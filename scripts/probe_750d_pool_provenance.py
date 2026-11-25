# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow a constant-pool service branch through native RAW pointer setup.

Separate reviewed stages, supplied service/configuration state. No task
delivery, camera boot, pool allocation, pixels or DMA are emulated.
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
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R4, UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, manager, packet, context = 0xfe0a0000, 0x100000, 0x101000, 0x102000
    config, table, stack, evf = 0x103000, 0x104000, 0x10d000, 0x26b94
    results = []
    for dispatch_index in (0, 2):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)  # Native alignment UDIV.
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(manager, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
        for page in (0x26000, 0x27000, 0x2a000, 0x2b000):
            uc.mem_map(page, 4096, UC_PROT_READ | UC_PROT_WRITE)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(context + 368, dispatch_index)
        put(packet + 8, 37)
        put(packet + 28, 0xfe11f435)
        put(packet + 32, manager)
        put(manager + 16, 0xa7)
        put(0x27b80, config)
        put(config, 2)  # Independent supplied provider mode; not dispatch_index.
        put(0x2b1e8, 0xfdfd)
        put(0x2b1ec, table)
        uc.mem_write(table + 224, struct.pack('<H', 1))
        reached, errors, boundary, callback_inputs = [], [], [], []
        ranges = ((0xfe42aeaa, 0xfe42aeb6), (0xfe42e928, 0xfe42e93c),
                  (0xfe42eb32, 0xfe42eb40), (0xfe11f434, 0xfe11f466),
                  (0xfe41be74, 0xfe41beb8), (0xfe41f730, 0xfe41f750),
                  (0xfe11f4e4, 0xfe11f4f8), (0xfe41c49c, 0xfe41c4b2),
                  (0xfe41c4f2, 0xfe41c572), (0xfe41c58c, 0xfe41c59a),
                  (0xfe41d882, 0xfe41d8cc), (0xfe41da1a, 0xfe41da1c),
                  (0xfe41db2e, 0xfe41db38), (0xfe41d916, 0xfe41d91a),
                  (0xfe41db9e, 0xfe41dbb2), (0xfe11fa2e, 0xfe11fa50),
                  (0xfe120428, 0xfe1204e8), (0xfe2053f6, 0xfe205412),
                  (0xfe2054f0, 0xfe205540), (0xfe2b8aae, 0xfe2b8acc))
        allowed = {(manager + n, 4) for n in (1804, 1808, 1812, 1864)}
        allowed |= {(config + n, 4) for n in (44, 984)}
        allowed |= {(table + n, 4) for n in (40, 248, 252)}
        allowed |= {(table + 224, 2), (evf + 88, 4), (evf + 100, 4)}

        def code_guard(emulator, address, size, _):
            if address == 0xfe11f434:
                callback_inputs.append([emulator.reg_read(r) for r in
                                        (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)])
            if address == boundary[0]:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 256 <= address <= stack + 8 - size
                    or (address, size) in allowed):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        def run(entry, stop):
            boundary[:] = [stop]
            reached.clear()
            # Explicit independent stage frame, not a fabricated native return.
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, 0x10f001)
            uc.emu_start(entry | 1, base + len(data), count=192, timeout=500_000)
            if errors or reached != [stop]:
                raise RuntimeError(f'{dispatch_index}: invalid/incomplete stage: {errors}')

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.reg_write(UC_ARM_REG_R0, context)
        uc.reg_write(UC_ARM_REG_R1, packet)
        run(0xfe42aeaa, 0xfe3ce0fc)
        if (word(manager + 1804) != 0x58830000 or uc.reg_read(UC_ARM_REG_LR) != 0xfe11f45d
                or callback_inputs != [[manager, 0x58830000, 0x6b48000]]):
            raise RuntimeError('Wrong constant-pool dispatch/callback')
        uc.reg_write(UC_ARM_REG_R4, manager)
        run(0xfe11f45c, 0xfe3ce0fc)
        if word(config + 44) != 0x58830000 or uc.reg_read(UC_ARM_REG_LR) != 0xfe41beb9:
            raise RuntimeError('Wrong aligned constant-pool publication')
        uc.reg_write(UC_ARM_REG_R4, manager)
        run(0xfe11f4e4, 0xfe11f4f8)
        if (word(manager + 1808) != 0x5c62c000 or word(manager + 1812) != 0x1d5d800):
            raise RuntimeError('Wrong constant-pool resource subregion')
        uc.reg_write(UC_ARM_REG_R4, manager)
        run(0xfe11fa2e, 0xfe11fa50)
        uc.reg_write(UC_ARM_REG_R0, manager)
        run(0xfe120428, 0xfe1204e8)
        uc.reg_write(UC_ARM_REG_R4, manager)
        uc.reg_write(UC_ARM_REG_R7, evf)
        run(0xfe2b8aae, 0xfe3ce0fc)
        if (word(manager + 1864) != 0x5c62c000 or word(table + 40) != 0x5c62c000
                or word(table + 252) != 1 or word(evf + 88) != 0x5c62c000
                or word(evf + 100) != 1 or uc.reg_read(UC_ARM_REG_LR) != 0xfe2b8acd):
            raise RuntimeError('Wrong constant-pool preparation provenance')
        pool_base, pool_size = callback_inputs[0][1:]
        inside = pool_base <= word(manager + 1808) and (
            word(manager + 1808) + word(manager + 1812) <= pool_base + pool_size)
        if not inside:
            raise RuntimeError('Resource does not fit the branch-reported pool')
        results.append({'supplied_service_dispatch_index': dispatch_index,
                        'supplied_resource_provider_mode': 2,
                        'pool_base_from_native_branch': hex(pool_base),
                        'pool_size_from_native_callback': hex(pool_size),
                        'resource_inside_reported_pool': inside,
                        'resource_22_address': hex(word(manager + 1808)),
                        'resource_22_size_bytes': word(manager + 1812),
                        'evf_raw_preparation_pointer': hex(word(evf + 88)), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': results,
            'native_calls_stubbed': False, 'pool_or_pixels_mapped': False,
            'os_delivery_or_boot_executed': False, 'camera_binding_enabled': False,
            'frame_lease_validated': False,
            'limits': 'Six separate native stages with fresh supplied stack frames. '
                      'Service dispatch indices 0/2, resource provider mode 2, registry '
                      'availability and unrelated zero-count resources are supplied. '
                      'The pool base/size come from the selected native branch. Other '
                      'states/configurations and live activation are unverified. '
                      'Cortex-A15 executes compatible instructions only. No task '
                      'delivery, RAM allocation, cache, DMA, pixels or frame timing.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
