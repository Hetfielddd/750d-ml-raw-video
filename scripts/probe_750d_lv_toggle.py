# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute only the identified 750D lv_save_raw flag setter on a PC.

This verifies a small function's memory effects, not RAW capture or DMA.
Input is private record-06.bin from decrypt_750d_fir.py, not a full ROM.
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
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, entry, end = 0xfe0a0000, 0xfe308eb4, 0xfe308eca
    state_address = struct.unpack_from('<I', data, 0x3092b4 - 0xa0000)[0]
    if state_address != 0x2af78:
        raise ValueError('State pointer differs from the analyzed function')
    cases = []
    for enabled, previous in ((0, 7), (1, 7), (1, 0), (0, 0)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        uc.mem_map(0x2a000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(0x100000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        stop = 0x10f000
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        initial = bytearray([0xa5] * 64)
        struct.pack_into('<I', initial, 12, previous)
        uc.mem_write(state_address, bytes(initial))
        uc.mem_write(0x100000, struct.pack('<I', enabled))
        returned, writes, errors = [], [], []

        def guard(emulator, address, size, _):
            if address == stop:
                returned.append(True)
                emulator.emu_stop()
            elif not entry <= address or address + size > end:
                errors.append('Execution left the identified flag setter')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if size != 4 or address not in (state_address + 4, state_address + 12):
                errors.append('Unexpected write')
                emulator.emu_stop()
            writes.append({'address': hex(address), 'bytes': size, 'value': value})

        uc.hook_add(UC_HOOK_CODE, guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.reg_write(UC_ARM_REG_R0, 0x100000)
        uc.reg_write(UC_ARM_REG_SP, 0x100ff0)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        uc.emu_start(entry | 1, stop + 4, count=100, timeout=1_000_000)
        expected = bytearray(initial)
        struct.pack_into('<I', expected, 4, enabled)
        if enabled and previous:
            struct.pack_into('<I', expected, 12, 0)
        if errors or not returned or bytes(uc.mem_read(state_address, 64)) != expected:
            raise RuntimeError(f'Flag setter verification failed: {errors}')
        cases.append({'requested_value': enabled, 'previous_auxiliary_value': previous,
                      'returned': True, 'only_expected_writes': True, 'writes': writes})
    return {'main_code_sha256': MAIN_SHA256, 'entry_thumb_pointer': hex(entry | 1),
            'registration_site': '0xfe309854', 'state_address': hex(state_address),
            'cases': cases, 'passed': True, 'camera_execution_performed': False,
            'raw_capture_demonstrated': False,
            'limits': 'Only this setter and synthetic RAM execute. This does not '
                      'validate Live View state, DMA, cache behavior, geometry, '
                      'completed-frame ownership or sustained recording.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
