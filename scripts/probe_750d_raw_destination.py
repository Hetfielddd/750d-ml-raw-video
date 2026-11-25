# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace a target RAW preparation path to its first DMA destination store.

PC only: separate native stages with synthetic state and explicitly copied
function/table aliases. Stops BEFORE the hardware store. No mailbox, sensor,
DMA engine, boot sequence or completed frame is emulated.
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
                                   UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R5,
                                   UC_ARM_REG_R6, UC_ARM_REG_R7,
                                   UC_ARM_REG_R8, UC_ARM_REG_SP, UC_ARM_REG_LR)

    base, stop, stack = 0xfe0a0000, 0x10f000, 0x10d000
    config, driver, feature = 0x100000, 0x101000, 0x102000
    state, shadow = 0x1ac2220, 0x200000
    app_delta, driver_delta = 0xfcc82368, 0x7e7473e0
    aliases = ((0x1bb7000, 4096, app_delta),
               (0x8000c000, 8192, driver_delta),
               (0x8000f000, 4096, driver_delta))
    results = []
    for name, candidate in (('plain', 0x12345000), ('alias_bit_30', 0x52345000),
                            ('alias_bit_31', 0x92345000), ('no_pending_address', 0)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for runtime, size, delta in aliases:
            source = runtime + delta - base
            if source < 0 or source + size > len(data):
                raise RuntimeError('Alias source outside identified record')
            uc.mem_map(runtime, size, UC_PROT_READ | UC_PROT_EXEC)
            uc.mem_write(runtime, data[source:source + size])
        for address, size in ((0x100000, 0xe000), (shadow, 0x60000),
                              (0x1ac2000, 4096), (0x1ac4000, 4096),
                              (0x1ad8000, 4096)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        callback_stop = 0x10e000
        uc.mem_map(callback_stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(config + 80, candidate)
        put(config + 140, 1)  # Reviewed mode-3 auxiliary path enabled.
        put(driver + 204, 34)  # Marker for a packing enum, not a bit count.
        put(driver + 216, 0)
        put(0x1ac40a4, shadow)
        # Actual channel-classifier input, supplied as synthetic RAM.
        uc.mem_write(0x1ad8b84 + 44 + 40, b'\0')
        done, errors, writes = [], [], []
        boundary = [stop]
        ranges = ((0xfe28d9d6, 0xfe28da36), (0xfe83942c, 0xfe83944c),
                  (0xfe750f2c, 0xfe750f3a), (0xfe74f130, 0xfe74f138),
                  (0x1bb7348, 0x1bb7366), (0xfe8395c4, 0xfe839642),
                  (0xfe86f858, 0xfe86f860), (0x8000c654, 0x8000c67e),
                  (0x8000c5fe, 0x8000c654), (0x8000c426, 0x8000c432),
                  (0xfe839462, 0xfe83946c), (0xfe86f860, 0xfe86f868),
                  (0x8000cf4a, 0x8000cf76), (0x8000d23e, 0x8000d250),
                  (0x1bb709a, 0x1bb70a8))

        def code_guard(emulator, address, size, _):
            if address == boundary[0]:
                done.append(True)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            writes.append((address, size))
            allowed = ((driver, driver + 0x120), (state, state + 0x50),
                       (stack - 256, stack), (shadow + 0x4108, shadow + 0x410c))
            allowed += ((0x1ad8350, 0x1ad835c),)  # Channel-1 callback record.
            if not any(lo <= address and address + size <= hi for lo, hi in allowed):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def run(entry, end):
            done.clear()
            boundary[0] = end
            uc.emu_start(entry | 1, stop + 4, count=256, timeout=500_000)
            if errors or not done:
                raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')

        # The stages have explicit supplied registers; no claim of boot,
        # interrupt delivery or execution of the entire configuration method.
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_R4, config)
        uc.reg_write(UC_ARM_REG_R1, driver)
        uc.reg_write(UC_ARM_REG_R7, feature)
        uc.reg_write(UC_ARM_REG_R8, 0)
        run(0xfe28d9d6, 0xfe28da36)
        if word(driver + 144) != 1 or word(driver + 200) != candidate:
            raise RuntimeError('Wrong configuration channel/address')

        uc.reg_write(UC_ARM_REG_R4, driver + 144)
        uc.reg_write(UC_ARM_REG_R7, 0)
        run(0xfe83942c, 0xfe83944c)
        if word(state) != 1 or word(state + 24) != 0 or word(state + 28) != 1:
            raise RuntimeError('Wrong RAW writer state/channel')

        uc.reg_write(UC_ARM_REG_R4, driver + 208)
        run(0xfe750f2c, 0xfe750f3a)
        if word(state + 36) != candidate or word(state + 44) != 34:
            raise RuntimeError('Wrong pending RAW address/packing marker')

        uc.reg_write(UC_ARM_REG_R5, state)
        run(0xfe839462, 0x8000cf72)  # Before platform interrupt registration.
        if (word(0x1ad8350) != 0x1bb709b or word(0x1ad8354) != 0
                or word(0x1ad8358) != 1):
            raise RuntimeError('Wrong native channel callback record')

        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        physical_store = 0x8000c430
        run(0xfe8395c4, physical_store if candidate else stop)
        if candidate:
            expected = candidate & 0x3fffffff
            if (uc.reg_read(UC_ARM_REG_R0) != 0xd0004108
                    or uc.reg_read(UC_ARM_REG_R1) != expected
                    or word(shadow + 0x4108) != expected
                    or writes.count((shadow + 0x4108, 4)) != 1):
                raise RuntimeError('Wrong DMA destination or shadow update')
        elif (shadow + 0x4108, 4) in writes:
            raise RuntimeError('Zero pending address unexpectedly armed DMA')

        # Invoke only the IRQ dispatch tail using a supplied saved-register
        # frame. Hardware IRQ/status/acknowledgement is NOT executed.
        forwarded_argument = 0x76543210
        put(state + 8, callback_stop | 1)
        put(state + 12, forwarded_argument)
        uc.mem_write(stack - 16, struct.pack('<4I', 0, 0, 0, stop | 1))
        uc.reg_write(UC_ARM_REG_SP, stack - 16)
        uc.reg_write(UC_ARM_REG_R6, 3)  # Channel index 1 times table stride / 4.
        run(0x8000d23e, callback_stop)
        if uc.reg_read(UC_ARM_REG_R0) != forwarded_argument:
            raise RuntimeError('Wrong forwarded callback argument')
        results.append({'case': name, 'input_marker': hex(candidate),
                        'native_channel_index': word(state + 28),
                        'destination_register': '0xd0004108' if candidate else None,
                        'prepared_destination': hex(candidate & 0x3fffffff) if candidate else None,
                        'stopped_before_physical_store': bool(candidate),
                        'native_channel_callback_registered': '0x1bb709b',
                        'synthetic_irq_tail_forwarded_argument': hex(forwarded_argument),
                        'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': results,
            'source_alias_hypotheses': {'application_delta': hex(app_delta),
                                        'driver_delta': hex(driver_delta)},
            'native_calls_stubbed': False, 'mmio_regions_mapped': False,
            'physical_stores_executed': False, 'raw_capture_demonstrated': False,
            'camera_binding_enabled': False,
            'limits': 'Separate native stages; supplied incoming registers, '
                      'channel-classifier RAM and narrow function/table aliases. '
                      'Reviewed mode-3 path only. Boot relocation, mailbox delivery, '
                      'hardware channel activity, IRQ status/acknowledgement, '
                      'frame geometry and completion '
                      'are not validated. Address markers are never pixel buffers.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
