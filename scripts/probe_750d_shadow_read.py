# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute two target register-shadow readers with synthetic RAM, without MMIO.

This identifies function behavior, not a coherent live-camera register bank.
No platform binding or completed-frame source is enabled.
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
    from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                         UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID,
                         UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
                         UC_MEM_READ_UNMAPPED, UC_ERR_READ_UNMAPPED)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_LR)

    variants = (
        ('primary_bank', 0xfe40a6a4, 0xfe40a6d8, 0xfe40a74e,
         0xfe40a794, 0x28f10, 0x200000),
        ('secondary_bank_candidate', 0xfe753800, 0xfe753834, 0xfe7538aa,
         0xfe7538f0, 0x1ac40a4, 0x300000),
    )
    # The initializing routines request 0x60000 bytes. Do not silently map the
    # larger 0x80000 range addressable by the readers' 19-bit mask.
    bank_size, stop, base = 0x60000, 0x10f000, 0xfe0a0000
    offsets = (0, 4, 0x4208, 0x4210, 0x4214, 0x12340, 0x5fffc)
    results = []
    for name, bind, reader, setter, literal, global_word, bank in variants:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(global_word & ~4095, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(bank, bank_size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        if struct.unpack_from('<I', data, literal - base)[0] != global_word:
            raise RuntimeError('Unexpected shadow global literal')

        accesses, errors, reached, invalid = [], [], [], []
        allowed_access = []
        routines = ((bind, bind + 6), (reader, reader + 12), (setter, setter + 12))

        def code_guard(emulator, address, size, _):
            if address == stop:
                reached.append(True)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in routines):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def access_guard(emulator, access, address, size, value, _):
            accesses.append((access, address, size))
            if (access, address, size) not in allowed_access:
                errors.append(f'Unexpected memory access: {address:#x}/{size}')
                emulator.emu_stop()

        def invalid_guard(emulator, access, address, size, value, _):
            invalid.append((access, address, size))
            return False  # Never manufacture backing RAM or successful reads.

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, access_guard)
        uc.hook_add(UC_HOOK_MEM_INVALID, invalid_guard)

        # Access constants are separate from hook constants.
        from unicorn import UC_MEM_READ, UC_MEM_WRITE

        def invoke(entry, argument, expected_accesses, value=0, expect_fault=None):
            allowed_access[:] = expected_accesses
            accesses.clear()
            errors.clear()
            reached.clear()
            invalid.clear()
            uc.reg_write(UC_ARM_REG_R0, argument)
            uc.reg_write(UC_ARM_REG_R1, value)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            fault = None
            try:
                uc.emu_start(entry | 1, stop + 4, count=32, timeout=500_000)
            except UcError as error:
                fault = error
            if errors:
                raise RuntimeError(f'{name}: {errors}')
            if expect_fault is not None:
                if (fault is None or fault.errno != UC_ERR_READ_UNMAPPED or reached
                        or invalid != [(UC_MEM_READ_UNMAPPED, expect_fault, 4)]):
                    raise RuntimeError(f'{name}: expected unmapped read was not observed')
                # Unicorn may also report the attempted invalid access to the
                # ordinary read hook; either ordering is acceptable.
            elif fault is not None or not reached or invalid:
                raise RuntimeError(f'{name}: incomplete execution: {fault}')
            elif accesses != expected_accesses:
                raise RuntimeError(f'{name}: unexpected access sequence: {accesses}')
            return uc.reg_read(UC_ARM_REG_R0)

        # Invoke the actual pointer setter; no allocator/initialization stub.
        invoke(bind, bank, [(UC_MEM_READ, literal, 4), (UC_MEM_WRITE, global_word, 4)])
        cases = []
        for index, offset in enumerate(offsets):
            value = (0x13579bdf ^ (index * 0x1020304)) & 0xffffffff
            address = 0xd0000000 | offset
            invoke(setter, address,
                   [(UC_MEM_READ, literal, 4), (UC_MEM_READ, global_word, 4),
                    (UC_MEM_WRITE, bank + offset, 4)], value=value)
            for alias in (address, address ^ 0x80000):
                actual = invoke(reader, alias,
                                [(UC_MEM_READ, literal, 4), (UC_MEM_READ, global_word, 4),
                                 (UC_MEM_READ, bank + offset, 4)])
                if actual != value:
                    raise RuntimeError(f'{name}: wrong shadow value at {alias:#x}')
            cases.append({'offset': hex(offset), 'value': hex(value),
                          'upper_address_bit_19_ignored': True, 'passed': True})

        # The native reader has no initialization or bounds check. Confirm
        # failure instead of allowing a successful read from invented memory.
        invoke(reader, 0xd0060000,
               [(UC_MEM_READ, literal, 4), (UC_MEM_READ, global_word, 4),
                (UC_MEM_READ, bank + bank_size, 4)], expect_fault=bank + bank_size)
        invoke(bind, 0, [(UC_MEM_READ, literal, 4), (UC_MEM_WRITE, global_word, 4)])
        invoke(reader, 0xd0004208,
               [(UC_MEM_READ, literal, 4), (UC_MEM_READ, global_word, 4),
                (UC_MEM_READ, 0x4208, 4)], expect_fault=0x4208)
        results.append({'bank': name, 'reader': hex(reader),
                        'global_pointer_word': hex(global_word),
                        'formula': '*uint32(global_pointer + (address & 0x7ffff))',
                        'synthetic_bank_bytes': bank_size, 'cases': cases,
                        'uninitialized_read_fault_observed': True,
                        'read_beyond_initialized_size_fault_observed': True,
                        'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'banks': results,
            'cpu_model': 'Cortex-A9 / compatible Thumb instruction subset', 'native_calls_stubbed': False,
            'mmio_regions_mapped': False, 'sensor_or_pixel_buffers_mapped': False,
            'camera_binding_enabled': False, 'raw_capture_demonstrated': False,
            'limits': 'Exact target readers, pointer setters and shadow-only writers '
                      'execute against synthetic RAM. MMIO-like arguments are values '
                      'only. Live initialization, cross-core visibility, freshness, '
                      'RAW channel selection and frame completion are unverified.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
