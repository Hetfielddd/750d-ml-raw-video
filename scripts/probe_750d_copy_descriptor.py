# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the target copy descriptor builder and native descriptor chaining.

Controller addresses use artificial RAM; execution stops before the start store.
No OS, cache maintenance or pixel memory is executed. The memory classifier and
channel settings are explicit artificial fixtures.
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
                                   UC_ARM_REG_R4, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, stack, stop = 0xfe0a0000, 0x10d000, 0x10f000
    first, second = 0x101020, 0x101060
    source, destination = 0x5c62c000, 0x5e000000  # Unmapped pointer markers.
    cases = []
    code_ranges = ((0xfe133b22, 0xfe133b88), (0xfe133bdc, 0xfe133cd8),
                   (0xfe1826de, 0xfe1826ea), (0xfe175500, 0xfe17551a),
                   (0xfe175544, 0xfe175564), (0xfe182700, 0xfe1827a8),
                   (0xfe1827ac, 0xfe182826), (0xfe3cda0c, 0xfe3cda14),
                   (0x800072c0, 0x80007314))

    def put(uc, address, values):
        uc.mem_write(address, struct.pack('<' + 'I' * len(values), *values))

    def words(uc, address, count):
        return list(struct.unpack('<' + 'I' * count, uc.mem_read(address, count * 4)))

    for channel, flags, length in [(ch, flag, 4096) for ch in (0, 3)
                                   for flag in range(4)] + [(1, 0, 1), (2, 0, 0)]:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        # Scoped primary-kernel import, not a claim of complete boot relocation.
        kernel_page_source = 0xfed630c8
        uc.mem_map(0x80007000, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(0x80007000, data[kernel_page_source - base:kernel_page_source - base + 4096])
        for address, size in ((0x25000, 4096), (0x52000, 4096), (0x100000, 0xe000)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(0x40000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        state = 0x52230 + channel * 28
        # Supplied mode/burst fields deliberately differ for the two sides.
        settings = [0, 1, 5, 3, 9, 0, 0]
        put(uc, state, settings)
        put(uc, 0x25774, [0x100000])
        put(uc, 0x100000, [0, 0, 0, 0xffffffff, 4])
        for descriptor in (first, second):
            uc.mem_write(descriptor - 8, b'\xa5' * 40)
        reached, errors, zero_calls, controller_writes = [], [], [], []
        submission = False
        controller = 0xd6030000 + channel * 48

        def code_guard(emulator, address, size, _):
            if address == stop or submission and address == 0xfe133b88:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in code_ranges):
                errors.append(f'Unexpected descriptor code: {address:#x}')
                emulator.emu_stop()
            if address == 0x800072c0:
                zero_calls.append((emulator.reg_read(UC_ARM_REG_R0),
                                   emulator.reg_read(UC_ARM_REG_R1)))

        def write_guard(emulator, access, address, size, value, _):
            allowed = ((stack - 128, stack), (state + 20, state + 28),
                       (first, first + 24), (second, second + 24))
            if submission:
                allowed += ((state, state + 4), (controller + 16, controller + 40))
                if controller <= address < controller + 48:
                    controller_writes.append((address, size, value))
            if not any(lo <= address and address + size <= hi for lo, hi in allowed):
                errors.append(f'Unexpected descriptor write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def build(descriptor, count):
            reached.clear()
            put(uc, stack, [count, flags])
            for register, value in ((UC_ARM_REG_R0, descriptor), (UC_ARM_REG_R1, channel),
                                    (UC_ARM_REG_R2, source), (UC_ARM_REG_R3, destination),
                                    (UC_ARM_REG_SP, stack), (UC_ARM_REG_LR, stop | 1)):
                uc.reg_write(register, value)
            uc.emu_start(0xfe133bf5, base + len(data), count=512, timeout=500_000)
            if errors or reached != [stop] or uc.reg_read(UC_ARM_REG_R0) != 0:
                raise RuntimeError(f'Invalid descriptor execution: {errors}/{reached}')
            if uc.reg_read(UC_ARM_REG_SP) != stack:
                raise RuntimeError('Descriptor builder did not restore stack')
            actual = words(uc, descriptor, 6)
            expected = [(count - 1) & 0xffffffff, destination, source,
                        0x20004 if flags & 1 else 0x10500,
                        0x20004 if flags & 2 else 0x30900, 0]
            if actual != expected:
                raise RuntimeError(f'Wrong descriptor: {actual}/{expected}')
            return actual

        first_words = build(first, length)
        if words(uc, state, 7) != settings[:5] + [first, first]:
            raise RuntimeError('Wrong first/last descriptor publication')
        second_words = build(second, 17)
        if (words(uc, state, 7) != settings[:5] + [first, second]
                or words(uc, first, 6) != first_words[:5] + [second | 1]
                or zero_calls != [(first, 24), (second, 24)]):
            raise RuntimeError('Wrong native descriptor chaining or zero-helper calls')
        for descriptor in (first, second):
            if (bytes(uc.mem_read(descriptor - 8, 8)) != b'\xa5' * 8
                    or bytes(uc.mem_read(descriptor + 24, 8)) != b'\xa5' * 8):
                raise RuntimeError('Descriptor canary changed')
        submission_result = 'not_attempted_zero_size_direct_builder_fixture'
        if length:
            # Same native-written descriptors/state; no host reconstruction.
            # These register addresses are ordinary RAM, with no DMA semantics.
            uc.mem_map(0xd6030000, 4096, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_write(0xd6030000, b'\xa5' * 4096)
            submission = True
            reached.clear()
            uc.reg_write(UC_ARM_REG_R0, channel)
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            uc.emu_start(0xfe133b23, base + len(data), count=128, timeout=500_000)
            payload = first_words[:5] + [second | 1]
            if (errors or reached != [0xfe133b88]
                    or controller_writes != [(controller + 16 + i * 4, 4, v)
                                             for i, v in enumerate(payload)]
                    or words(uc, controller + 16, 6) != payload
                    or words(uc, controller + 40, 1) != [0xa5a5a5a5]
                    or words(uc, state, 7) != [1] + settings[1:5] + [first, second]
                    or uc.reg_read(UC_ARM_REG_R4) != controller
                    or uc.reg_read(UC_ARM_REG_R1) != 0x11100003):
                raise RuntimeError(f'Wrong submission preparation: {errors}/{reached}')
            submission_result = 'six_payload_stores_to_artificial_ram_then_stop_before_start'
        cases.append({'channel': channel, 'supplied_flags': flags,
                      'supplied_first_bytes': length, 'supplied_second_bytes': 17,
                      'first_descriptor_before_link': [hex(v) for v in first_words],
                      'first_next_after_link': hex(second | 1),
                      'second_descriptor': [hex(v) for v in second_words],
                      'native_zero_helper_calls': 2, 'canaries_preserved': True,
                      'submission': submission_result,
                      'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'descriptor_builder': '0xfe133bf4',
            'scoped_zero_helper_source': '0xfed63388',
            'scoped_zero_helper_runtime': '0x800072c0',
            'native_calls_stubbed': False, 'controller_is_artificial_ram': True,
            'submission_preparations_checked': 9, 'start_store_executed': False,
            'os_or_cache_maintenance_executed': False, 'dma_executed': False,
            'camera_binding_enabled': False,
            'limits': 'Artificial channel format fields and catch-all classifier flag 4; '
                      'unmapped source/destination markers. Direct descriptor construction '
                      'and chaining bypass wrapper admission and list-core zero-size '
                      'filtering. Zero size underflows here, not proof the public wrapper '
                      'submits it. Scoped primary-kernel import, no complete boot relocation. '
                      'Nine separate submission-helper entries use native-written descriptors '
                      'and artificial register RAM, stopping before the start store. '
                      'No pixels, channel availability, hardware submission, completion, '
                      'cache coherence, safe calling context or frame ownership validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
