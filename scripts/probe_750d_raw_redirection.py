# SPDX-License-Identifier: GPL-2.0-or-later
"""Check native RAW address programming versus earlier redirection fixtures.

Controller addresses are ordinary RAM. The RAW entry stops before its channel
start call; no DMA, transport, frame event or source ownership is emulated.
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
                         UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                                   UC_ARM_REG_PC)
    base, delta = 0xfe0a0000, 0x7e7473e0
    stack, stop, callback, shadow = 0x10d000, 0x10f000, 0x10f100, 0x200000
    state, config, register = 0x1ac2220, 0x100000, 0xd0004108
    original, replacement = 0x5c62c000, 0x5e000000  # Unmapped image markers.
    cases = []
    ranges = ((0xfe8395c4, 0xfe839642), (0xfe8396b0, 0xfe8396ce),
              (0xfe86f858, 0xfe86f85c), (0x8000c654, 0x8000c67e),
              (0x8000c5fe, 0x8000c654), (0x8000c426, 0x8000c434),
              (0xfe7556e4, 0xfe75576c), (0xfe7557f6, 0xfe755878),
              (0xfe7558f8, 0xfe755900),
              (0xfe755902, 0xfe755918), (0xfe755950, 0xfe75598e),
              (0xfe75598e, 0xfe755a0c), (0xfe755a40, 0xfe755a62),
              (0xfe755262, 0xfe755264), (0xfe753806, 0xfe753888),
              (0xfe7539be, 0xfe753b1a),
              (0xfe74f924, 0xfe74f928), (0x14f0, 0x1544))

    for scenario in ('baseline', 'direct_register_before', 'native_address_before',
                     'native_pending_replacement', 'native_pending_zero',
                     'native_address_after_then_reenter', 'classifier_one_skips_address',
                     'native_snapshot_override_restore', 'override_repeat_without_restore',
                     'override_restore_then_switch', 'override_config_overwritten_before_use',
                     'override_duplicate_restore_clobbers_later_address',
                     'override_geometry_equal', 'override_geometry_larger_limit',
                     'override_geometry_exact_divisor', 'override_geometry_inexact_divisor',
                     'override_geometry_odd_limit', 'override_geometry_zero_limit',
                     'override_geometry_row_count_overflow'):
        override_experiment = scenario == 'native_snapshot_override_restore' or scenario.startswith('override_')
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for runtime, size in ((0x8000c000, 8192), (0x8000f000, 4096)):
            uc.mem_map(runtime, size, UC_PROT_READ | UC_PROT_EXEC)
            offset = runtime + delta - base
            uc.mem_write(runtime, data[offset:offset + size])
        for address, size in ((0x100000, 0xe000), (shadow, 0x60000),
                              (0x1ac2000, 4096), (0x1ac4000, 4096),
                              (0x1ad8000, 4096), (0xd0004000, 4096)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(0x1000, 4096, UC_PROT_READ | UC_PROT_EXEC)
        peer_page_source = 0xfe745d60
        uc.mem_write(0x1000, data[peer_page_source - base:peer_page_source - base + 4096])

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(0x1ac40a4, shadow)
        put(state, 1)
        put(state + 8, callback | 1)
        put(state + 12, 0x12345678)
        put(state + 28, 1)
        put(state + 36, original)
        put(register, original & 0x3fffffff)
        put(shadow + 0x4108, original & 0x3fffffff)
        # Alternate-mode flag is supplied zero. One case supplies classifier 1.
        errors, reached, stores, boundary = [], [], [], [stop]

        def code_guard(emulator, address, size, _):
            if address == boundary[0]:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected redirection code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            allowed = ((stack - 256, stack), (state + 36, state + 40),
                       (state + 44, state + 48), (register, register + 4),
                       (shadow + 0x4108, shadow + 0x410c))
            if override_experiment:
                allowed += ((0x1ad8bb0, 0x1ad8bdc), (0x1ad8288, 0x1ad828c),
                            (0xd0004104, 0xd000412c),
                            (shadow + 0x4104, shadow + 0x412c),
                            (0xd0004140, 0xd0004144), (0xd0004154, 0xd0004158),
                            (shadow + 0x4140, shadow + 0x4144),
                            (shadow + 0x4154, shadow + 0x4158),
                            (0x1ac40f4, 0x1ac40fc))
            if not any(lo <= address and address + size <= hi for lo, hi in allowed):
                errors.append(f'Unexpected redirection write: {address:#x}/{size}')
                emulator.emu_stop()
            if address == register:
                stores.append(value & 0xffffffff)

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def run(entry, target=stop, r0=0, r1=0):
            boundary[0] = target
            reached.clear()
            uc.reg_write(UC_ARM_REG_R0, r0)
            uc.reg_write(UC_ARM_REG_R1, r1)
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            try:
                uc.emu_start(entry | 1, base + len(data), count=1024, timeout=500_000)
            except UcError as error:
                raise RuntimeError(f'{scenario}: native fault at {uc.reg_read(UC_ARM_REG_PC):#x}') from error
            if errors or reached != [target]:
                raise RuntimeError(f'{scenario}: invalid redirection stage: {errors}/{reached}')
            if target == stop and uc.reg_read(UC_ARM_REG_SP) != stack:
                raise RuntimeError(f'{scenario}: native function did not restore stack')

        if scenario.startswith('override_'):
            second_replacement = 0x5f000000
            width, height = 3584, 32768 if scenario == 'override_geometry_row_count_overflow' else 1080
            snapshot = [0x4000, original & 0x3fffffff, 0, ((height - 1) << 16) | width] + [0] * 6
            for i, value in enumerate(snapshot):
                put(0xd0004104 + i * 4, value)
                put(shadow + 0x4104 + i * 4, value)

            def configure(pointer, limit):
                run(0xfe75598e, r0=pointer, r1=limit)
                if word(0x1ac40f4) != pointer or word(0x1ac40f8) != limit:
                    raise RuntimeError('Wrong native override configuration publication')

            def restored_words():
                return [word(0xd0004104 + i * 4) for i in range(10)]

            if scenario.startswith('override_geometry_'):
                limit = {'override_geometry_equal': 3584,
                         'override_geometry_larger_limit': 4096,
                         'override_geometry_exact_divisor': 1792,
                         'override_geometry_inexact_divisor': 2048,
                         'override_geometry_odd_limit': 1793,
                         'override_geometry_zero_limit': 0,
                         'override_geometry_row_count_overflow': 1792}[scenario]
                configure(replacement, limit)
                if limit == 0:
                    # Do not assume target divide-by-zero trap configuration.
                    run(0xfe755994, target=0xfe75595e, r0=1)
                    if (uc.reg_read(UC_ARM_REG_R3) != 0 or word(register) != original & 0x3fffffff
                            or bytes(uc.mem_read(0x1ad8bd8, 1)) != b'\0'):
                        raise RuntimeError('Unexpected zero-limit division boundary')
                    cases.append({'case': scenario, 'native_divisor': 0,
                                  'stopped_before_division': '0xfe75595e',
                                  'target_divide_by_zero_behavior_assumed': False, 'passed': True})
                    continue
                run(0xfe755994, r0=1)
                raw_line = min(width, limit)
                raw_rows = (width // limit) * height if width >= limit else height
                packed = (raw_line | (((raw_rows - 1) & 0xffffffff) << 16)) & 0x7ffffffe
                actual = word(0xd0004110)
                encoded_line, encoded_rows = actual & 0xffff, (actual >> 16) + 1
                if (actual != packed or word(register) != replacement & 0x3fffffff
                        or bytes(uc.mem_read(0x1ad8bd8, 1)) != b'\x01'):
                    raise RuntimeError('Wrong native override geometry or destination')
                run(0xfe755a40, r0=1)
                if restored_words() != snapshot or bytes(uc.mem_read(0x1ad8bd8, 1)) != b'\0':
                    raise RuntimeError('Geometry scenario did not restore its ten-word snapshot')
                cases.append({'case': scenario, 'supplied_source_line_bytes': width,
                              'supplied_source_rows': height, 'native_configured_row_limit': limit,
                              'native_encoded_line_bytes': encoded_line, 'native_encoded_rows': encoded_rows,
                              'source_geometry_bytes': width * height,
                              'encoded_geometry_bytes': encoded_line * encoded_rows,
                              'encoded_byte_count_preserved': width * height == encoded_line * encoded_rows,
                              'ten_word_snapshot_restored': True, 'passed': True})
                continue

            configure(replacement, width)
            if scenario == 'override_config_overwritten_before_use':
                configure(second_replacement, width)
            run(0xfe755994, r0=1)
            expected_first = second_replacement if scenario == 'override_config_overwritten_before_use' else replacement
            if word(register) != expected_first & 0x3fffffff:
                raise RuntimeError('Override did not consume the latest native configuration')
            if scenario == 'override_duplicate_restore_clobbers_later_address':
                run(0xfe755a40, r0=1)
                run(0x8000c654, r0=1, r1=second_replacement)
                if (word(register) != second_replacement & 0x3fffffff
                        or bytes(uc.mem_read(0x1ad8bd8, 1)) != b'\0'):
                    raise RuntimeError('Intervening native address setter did not take effect')
                run(0xfe755a40, r0=1)
                if restored_words() != snapshot:
                    raise RuntimeError('Unexpected duplicate-restore behavior')
                cases.append({'case': scenario,
                              'intervening_native_destination': hex(second_replacement & 0x3fffffff),
                              'after_duplicate_restore_destination': hex(word(register)),
                              'restore_ignored_zero_override_flag': True,
                              'frame_capture_or_restart_executed': False, 'passed': True})
                continue
            if scenario != 'override_config_overwritten_before_use':
                if scenario == 'override_restore_then_switch':
                    run(0xfe755a40, r0=1)
                    if restored_words() != snapshot:
                        raise RuntimeError('Intermediate restore lost original configuration')
                before_second_snapshot = restored_words()
                configure(second_replacement, width)
                stores.clear()
                run(0xfe755994, r0=1)
                expected_second = replacement if scenario == 'override_repeat_without_restore' else second_replacement
                if (word(register) != expected_second & 0x3fffffff
                        or bytes(uc.mem_read(0x1ad8bb0, 40)) != struct.pack('<10I', *before_second_snapshot)
                        or stores != ([] if scenario == 'override_repeat_without_restore'
                                      else [second_replacement & 0x3fffffff])):
                    raise RuntimeError('Wrong repeated-override snapshot or address-write suppression')
            run(0xfe755a40, r0=1)
            expected_after_restore = replacement if scenario == 'override_repeat_without_restore' else original
            expected_snapshot = before_second_snapshot if scenario != 'override_config_overwritten_before_use' else snapshot
            if (word(register) != expected_after_restore & 0x3fffffff
                    or restored_words() != expected_snapshot
                    or bytes(uc.mem_read(0x1ad8bd8, 1)) != b'\0'):
                raise RuntimeError('Wrong repeated-override restore destination')
            cases.append({'case': scenario, 'first_override_destination': hex(expected_first & 0x3fffffff),
                          'second_configured_destination': hex(second_replacement & 0x3fffffff),
                          'after_restore_destination': hex(word(register)),
                          'original_destination_restored': word(register) == original & 0x3fffffff,
                          'frame_capture_or_restart_executed': False, 'passed': True})
            continue

        if scenario == 'native_snapshot_override_restore':
            # A separate takeover/restore experiment. All register effects are
            # ordinary RAM writes, not stopping or owning a physical channel.
            snapshot = [0x4000, original & 0x3fffffff, 0, (1079 << 16) | 3584] + [0] * 6
            for i, value in enumerate(snapshot):
                put(0xd0004104 + i * 4, value)
                put(shadow + 0x4104 + i * 4, value)
            put(0x1ac40f4, replacement)
            put(0x1ac40f8, 3584)
            for offset, value in ((0x40, 0x13579bdf), (0x54, 0x2468ace0)):
                put(0xd0004100 + offset, value)
                put(shadow + 0x4100 + offset, value)
            put(0x1ad8288, 1)
            run(0xfe755994, r0=1)
            if (word(register) != replacement & 0x3fffffff
                    or bytes(uc.mem_read(0x1ad8bd8, 1)) != b'\x01'
                    or bytes(uc.mem_read(0x1ad8bb0, 40)) != struct.pack('<10I', *snapshot)):
                raise RuntimeError('Native override did not snapshot/retarget/set its flag')
            stores.clear()
            run(0xfe8395c4, target=0xfe86f878)
            if stores or word(register) != replacement & 0x3fffffff or word(state + 36) != original:
                raise RuntimeError('Native override did not suppress pending-address overwrite')
            run(0xfe755a40, r0=1)
            for i, value in enumerate(snapshot):
                if (word(0xd0004104 + i * 4) != value
                        or word(shadow + 0x4104 + i * 4) != value):
                    raise RuntimeError('Native restore did not restore saved register words')
            if bytes(uc.mem_read(0x1ad8bd8, 1)) != b'\0':
                raise RuntimeError('Native restore did not clear its flag')
            if (any(word(0xd0004100 + offset) != 0
                    or word(shadow + 0x4100 + offset) != 0 for offset in (0x40, 0x54))
                    or word(0x1ad8288) != 0):
                raise RuntimeError('Unexpected auxiliary-register/software-state restoration')
            cases.append({'case': scenario, 'saved_register_words': 10,
                          'override_flag_address': '0x1ad8bd8',
                          'native_override_destination': hex(replacement & 0x3fffffff),
                          'pending_address_retained': hex(word(state + 36)),
                          'raw_entry_address_write_suppressed': True,
                          'saved_words_restored_in_register_ram_and_shadow': True,
                          'auxiliary_registers_and_secondary_flag_remain_changed': True,
                          'override_flag_cleared': True, 'passed': True})
            continue
        if scenario == 'direct_register_before':
            # Host fixture represents an earlier direct write, not execution of ML.
            put(register, replacement & 0x3fffffff)
        elif scenario == 'classifier_one_skips_address':
            uc.mem_write(0x1ad8b84 + 44 + 40, b'\x01')
            put(register, replacement & 0x3fffffff)
        elif scenario == 'native_address_before':
            run(0x8000c654, r0=1, r1=replacement)
        elif scenario in ('native_pending_replacement', 'native_pending_zero'):
            put(config, replacement if scenario == 'native_pending_replacement' else 0)
            put(config + 4, 34)
            run(0xfe8396b0, r0=config)
        before = {'register': hex(word(register)), 'shadow': hex(word(shadow + 0x4108)),
                  'pending': hex(word(state + 36))}
        stores.clear()
        empty = scenario == 'native_pending_zero'
        run(0xfe8395c4, target=callback if empty else 0xfe86f878)
        expected = replacement if scenario == 'native_pending_replacement' else original
        skip_address = scenario == 'classifier_one_skips_address'
        expected_stores = [] if empty or skip_address else [expected & 0x3fffffff]
        expected_register = (replacement if skip_address else expected) & 0x3fffffff
        if (stores != expected_stores or word(register) != expected_register
                or word(shadow + 0x4108) != expected & 0x3fffffff
                or word(state + 36) != (0 if empty else expected)):
            raise RuntimeError(f'{scenario}: wrong native overwrite/pending behavior')
        if empty and uc.reg_read(UC_ARM_REG_R0) != 0x12345678:
            raise RuntimeError('Empty pending path lost callback argument')
        extra = None
        if scenario == 'native_address_after_then_reenter':
            run(0x8000c654, r0=1, r1=replacement)
            if word(register) != replacement & 0x3fffffff or word(state + 36) != original:
                raise RuntimeError('Address setter unexpectedly changed pending state')
            extra = {'after_native_address_setter': hex(word(register))}
            stores.clear()
            # Independent re-entry, not a completed capture cycle. Previous
            # entry stopped before start and did not consume pending state.
            run(0xfe8395c4, target=0xfe86f878)
            if stores != [original & 0x3fffffff] or word(register) != original & 0x3fffffff:
                raise RuntimeError('Re-entered start did not reload original pending address')
            extra['after_separate_start_reentry'] = hex(word(register))
        cases.append({'case': scenario, 'before_raw_entry': before,
                      'native_raw_entry_address_stores': [hex(v) for v in expected_stores],
                      'after_register': hex(word(register)),
                      'after_pending': hex(word(state + 36)),
                      'stopped_before_channel_start': not empty,
                      'empty_path_callback_reached': empty,
                      'separate_later_entries': extra, 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'emulator_cpu_model': 'Cortex-A15 compatible scalar ARM/Thumb subset',
            'native_calls_stubbed': False, 'controller_is_artificial_ram': True,
            'channel_start_or_dma_executed': False, 'camera_binding_enabled': False,
            'frame_lease_validated': False,
            'limits': 'Supplied active/non-alternate RAW state, channel1, pending pointer '
                      'and channel classification, including a native override/restore sequence; scoped '
                      'driver/table imports, not boot. '
                      'Source pointers are unmapped. Earlier direct register change is a '
                      'host fixture; other address/state setters execute natively. Native '
                      'RAW entries stop before FE86F878 channel-start call; empty pending '
                      'stops before supplied callback. Re-entry is separate, not capture '
                      'completion or a live event sequence. No transport, device semantics, '
                      'IRQ timing, pixel packing, cache coherence or ownership established. '
                      'Native snapshot override is not a verified allocation/locking or '
                      'completed-frame lease API; tested auxiliary registers and secondary '
                      'software flag remain changed after the ten-word restore. Repeated '
                      'override/restore and malformed geometry cases characterize supplied '
                      'states, not camera faults or supported capture modes. The zero-limit '
                      'case stops before division and assumes no divide-by-zero behavior.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
