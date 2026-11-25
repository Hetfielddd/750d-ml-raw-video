# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute a RAW channel IRQ body against explicitly artificial register RAM.

Stores update ordinary RAM and the native software shadow. No peripheral,
interrupt controller, acknowledgement semantics or pixel transfer is modeled.
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
                         UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ,
                         UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)

    base, delta, app_delta = 0xfe0a0000, 0x7e7473e0, 0xfcc82368
    stack, stop, shadow = 0x10d000, 0x10f000, 0x200000
    channel_base, state, record = 0xd0004100, 0x1ac2220, 0x1ad8350
    callback = 0x80009d8e
    table = struct.unpack_from('<3I', data, 0xfe756cb4 + 12 - base)
    if table != (0x41, channel_base, 0x8000d1ed):
        raise RuntimeError('Unexpected native channel-1 IRQ table')
    cases = []
    for status in (0, 4):
        for software_flag in (0, 1):
            for secondary_flag in (0, 1):
                uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
                uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
                uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
                uc.mem_write(base, data)
                for runtime, mapping in ((0x8000f000, delta), (0x1bb7000, app_delta)):
                    uc.mem_map(runtime, 4096, UC_PROT_READ | UC_PROT_EXEC)
                    offset = runtime + mapping - base
                    uc.mem_write(runtime, data[offset:offset + 4096])
                for address, size in ((stack - 4096, 4096), (shadow, 0x60000),
                                      (0x1ac2000, 4096), (0x1ac4000, 4096),
                                      (0x1ad8000, 4096), (0xd0004000, 4096)):
                    uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
                uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
                # Fetchable stop boundary; no callback instruction is executed.
                uc.mem_map(callback & ~4095, 4096, UC_PROT_READ | UC_PROT_EXEC)

                def put(address, value):
                    uc.mem_write(address, struct.pack('<I', value))

                def word(address):
                    return struct.unpack('<I', uc.mem_read(address, 4))[0]

                start_marker, control_marker, argument = 0xa5a50003, 0xdeadbeef, 0x12345678
                put(channel_base + 0x30, status)
                for offset, value in ((0, start_marker), (4, control_marker)):
                    put(channel_base + offset, value)
                    put(shadow + 0x4100 + offset, value)
                put(0x1ac40a4, shadow)
                put(0x1ad81c8, software_flag)
                put(record, 0x1bb709b)
                put(record + 4, 0)
                put(record + 8, 1)
                put(0x1ad8288, secondary_flag)
                put(state + 8, callback | 1)
                put(state + 12, argument)
                errors, reached, register_writes, register_reads = [], [], [], []
                ranges = ((0xfe7545cc, 0xfe754630), (0xfe753806, 0xfe753814),
                          (0xfe753840, 0xfe753856), (0x1bb709a, 0x1bb70aa))

                def code_guard(emulator, address, size, _):
                    if address == callback:
                        reached.append(address)
                        emulator.emu_stop()
                    elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                        errors.append(f'Unexpected IRQ-body code: {address:#x}')
                        emulator.emu_stop()

                def write_guard(emulator, access, address, size, value, _):
                    allowed = {channel_base, channel_base + 4, shadow + 0x4100,
                               shadow + 0x4104}
                    if not (size == 4 and address in allowed
                            or stack - 128 <= address and address + size <= stack):
                        errors.append(f'Unexpected IRQ-body write: {address:#x}/{size}')
                        emulator.emu_stop()
                    if address in (channel_base, channel_base + 4):
                        register_writes.append([hex(address), hex(value & 0xffffffff)])

                def read_guard(emulator, access, address, size, value, _):
                    if 0xd0004000 <= address < 0xd0005000:
                        register_reads.append([hex(address), size])
                        if (address, size) != (channel_base + 0x30, 4):
                            errors.append('Unexpected artificial register read')
                            emulator.emu_stop()

                uc.hook_add(UC_HOOK_CODE, code_guard)
                uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
                uc.hook_add(UC_HOOK_MEM_READ, read_guard)
                uc.reg_write(UC_ARM_REG_R0, 1)
                uc.reg_write(UC_ARM_REG_SP, stack)
                uc.reg_write(UC_ARM_REG_LR, stop | 1)
                uc.emu_start(0xfe7545cd, base + len(data), count=128, timeout=500_000)
                expected_control = control_marker
                if status & 4 or software_flag == 1:
                    expected_control = (((control_marker & ~7) | 2)
                                        if not status & 4 and secondary_flag else 0)
                expected_writes = []
                if status & 4 or software_flag == 1:
                    expected_writes.append([hex(channel_base + 4), hex(expected_control)])
                expected_writes.append([hex(channel_base), hex((start_marker & 2) | 4)])
                if (errors or reached != [callback] or register_writes != expected_writes
                        or register_reads != [[hex(channel_base + 0x30), 4]]
                        or uc.reg_read(UC_ARM_REG_R0) != argument
                        or word(channel_base + 4) != expected_control
                        or word(shadow + 0x4104) != expected_control
                        or word(channel_base) != 6 or word(shadow + 0x4100) != 6):
                    raise RuntimeError(f'Invalid IRQ fixture {status}/{software_flag}/{secondary_flag}: '
                                       f'{errors}/{register_writes}/{expected_writes}; '
                                       f'reads={register_reads}, reached={reached}, '
                                       f'control={word(channel_base + 4):#x}, '
                                       f'shadow={word(shadow + 0x4104):#x}, '
                                       f'arg={uc.reg_read(UC_ARM_REG_R0):#x}')
                cases.append({'supplied_status': hex(status), 'software_flag': software_flag,
                              'secondary_flag': secondary_flag,
                              'artificial_register_writes': register_writes,
                              'driver_callback_reached': hex(callback), 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'channel_index': 1, 'table_irq_number': '0x41',
            'native_calls_stubbed': False, 'physical_hardware_accessed': False,
            'artificial_mmio_ram_mapped': True, 'camera_binding_enabled': False,
            'frame_lease_validated': False,
            'limits': 'Artificial register RAM and matching software shadow; native stores '
                      'have ordinary RAM semantics, not device acknowledgement semantics. '
                      'Supplied callback records, flags, status and direct handler invocation. '
                      'Scoped code/table copies are not validated boot relocations. Stops '
                      'before driver callback. No interrupt-controller delivery, hardware '
                      'status definition, DMA, pixels, cache or frame ownership established.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
