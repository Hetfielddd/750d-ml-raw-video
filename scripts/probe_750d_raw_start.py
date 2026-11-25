# SPDX-License-Identifier: GPL-2.0-or-later
"""Inspect native RAW channel-start preparation, stopping before MMIO stores.

Control RMW and start-command tail are separate stages. No hardware state or
successful DMA start is simulated between them.
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
                                   UC_ARM_REG_R1, UC_ARM_REG_R3, UC_ARM_REG_R4,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, delta, shadow, stack = 0xfe0a0000, 0x7e7473e0, 0x200000, 0x10d000
    matrix_entry = 0xfea0b174 + (5 * 10 + 5) * 8
    transition = struct.unpack_from('<2I', data, matrix_entry - base)
    if transition != (5, 0xfe2b9537):
        raise RuntimeError('Unexpected EVF old-state-5/input-5 table entry')
    cases = []
    for name, initial in (('control_zero', 0), ('control_low_flags', 8),
                           ('control_all_bits', 0xffffffff), ('start_command_tail', 0)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for address, length in ((0x8000c000, 8192), (0x8000f000, 4096)):
            uc.mem_map(address, length, UC_PROT_READ | UC_PROT_EXEC)
            source = address + delta - base
            uc.mem_write(address, data[source:source + length])
        for address, length in ((0x1ac4000, 4096), (0x1ad8000, 4096),
                                 (0x10c000, 4096), (shadow, 0x60000)):
            uc.mem_map(address, length, UC_PROT_READ | UC_PROT_WRITE)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(0x1ac40a4, shadow)
        put(0x1ad81c8, 0x12345678)  # Supplied channel-1 software word.
        put(shadow + 0x4104, initial)
        put(shadow + 0x4100, 0xdeadbeef)
        tail = name == 'start_command_tail'
        stop = (0xfe753810 if tail else 0xfe753852) - delta
        reached, errors = [], []
        ranges = ((0xfe75395e - delta, 0xfe75399e - delta),
                  (0xfe753840 - delta, 0xfe753852 - delta),
                  (0xfe753806 - delta, 0xfe753810 - delta))

        def code_guard(emulator, address, size, _):
            if address == stop:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected execution: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 128 <= address <= stack - size
                    or (address, size) in ((0x1ad81c8, 4), (shadow + 0x4104, 4),
                                          (shadow + 0x4100, 4))):
                errors.append(f'Unexpected write: {address:#x}/{size}')
                emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, 0x10f001)  # Unmapped: unexpected return fails.
        if tail:
            # Reviewed continuation after the RMW call; no physical write is
            # executed or modeled as successful. Supply its original saved frame.
            uc.mem_write(stack - 8, struct.pack('<2I', 0, 0x10f001))
            uc.reg_write(UC_ARM_REG_SP, stack - 8)
            uc.reg_write(UC_ARM_REG_R4, 0x8000f8d4 + 12)
            entry = 0xfe75398e - delta
        else:
            uc.reg_write(UC_ARM_REG_R0, 1)
            entry = 0xfe75395e - delta
        uc.emu_start(entry | 1, base + len(data), count=64, timeout=500_000)
        if errors or reached != [stop]:
            raise RuntimeError(f'{name}: invalid/incomplete execution: {errors}')
        if tail:
            address, value = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
            if address != 0xd0004100 or value != 1 or word(shadow + 0x4100) != 1:
                raise RuntimeError('Wrong start command preparation')
        else:
            address, value = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R3)
            if (address != 0xd0004104 or value != initial | 0x20000000
                    or word(shadow + 0x4104) != value or word(0x1ad81c8) != 0):
                raise RuntimeError('Wrong control-register RMW preparation')
        cases.append({'case': name, 'initial_control_shadow': hex(initial),
                      'stopped_before_runtime': hex(stop), 'physical_address_argument': hex(address),
                      'pending_store_value': hex(value), 'passed': True})
    # Independently check software pending-address consumption. Enter only the
    # reviewed post-command tail; do not pretend the hardware commands succeeded.
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(base, data)
    uc.mem_map(0x1ac2000, 4096, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(0x100000, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(0x10f000, 4096, UC_PROT_READ | UC_PROT_EXEC)
    state, supplied_config = 0x1ac2220, 0x100000

    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    put(state, 1)
    reached, errors = [], []

    def pending_code_guard(emulator, address, size, _):
        if address == 0x10f000:
            reached.append(True)
            emulator.emu_stop()
        elif not (0xfe8395c4 <= address <= 0xfe839642 - size
                  or 0xfe8396b0 <= address <= 0xfe8396ce - size):
            errors.append(f'Unexpected pending-state execution: {address:#x}')
            emulator.emu_stop()

    def pending_write_guard(emulator, access, address, size, value, _):
        if not (stack - 128 <= address <= stack - size
                or (address, size) in ((state + 36, 4), (state + 44, 4))):
            errors.append(f'Unexpected pending-state write: {address:#x}/{size}')
            emulator.emu_stop()

    def pending_run(entry, saved_frame=False):
        reached.clear()
        if saved_frame:
            uc.mem_write(stack - 16, struct.pack('<4I', 0, 0, 0, 0x10f001))
        uc.reg_write(UC_ARM_REG_SP, stack - 16 if saved_frame else stack)
        uc.reg_write(UC_ARM_REG_LR, 0x10f001)
        uc.emu_start(entry | 1, 0x10f004, count=64, timeout=500_000)
        if errors or reached != [True]:
            raise RuntimeError(f'Invalid/incomplete pending-state stage: {errors}')

    uc.hook_add(UC_HOOK_CODE, pending_code_guard)
    uc.hook_add(UC_HOOK_MEM_WRITE, pending_write_guard)
    sequence = []
    for address in (0x5c62c000, 0x12345000):
        put(supplied_config, address)
        put(supplied_config + 4, 34)
        uc.reg_write(UC_ARM_REG_R0, supplied_config)
        uc.reg_write(UC_ARM_REG_R1, 0)
        pending_run(0xfe8396b0)
        if word(state + 36) != address or word(state + 44) != 34:
            raise RuntimeError('Wrong pending-address publication')
        sequence.append(hex(word(state + 36)))
        uc.reg_write(UC_ARM_REG_R4, state)
        from unicorn.arm_const import UC_ARM_REG_R5
        uc.reg_write(UC_ARM_REG_R5, 0)
        pending_run(0xfe83963c, saved_frame=True)
        if word(state + 36) != 0:
            raise RuntimeError('Post-command tail did not consume pending address')
        sequence.append(hex(word(state + 36)))
        # The whole handler with no pending address and no callback returns
        # without reaching any register writer. Its next nonzero request must
        # come from configuration, not a host-emulated DMA completion.
        pending_run(0xfe8395c4)
        if word(state + 36) != 0 or uc.reg_read(UC_ARM_REG_R0) != 0:
            raise RuntimeError('Empty-pending invocation changed state or return')
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'separate_pending_address_sequence': sequence,
            'decoded_only_vsync_candidate': {'old_state': 5, 'input': 5,
                                             'next_state': 5, 'handler_source': '0xfe2b9536'},
            'native_calls_stubbed': False, 'mmio_mapped_or_stored': False,
            'camera_binding_enabled': False, 'dma_start_or_frame_lease_validated': False,
            'limits': 'Channel 1 and register shadows are supplied. Scoped runtime '
                      'code/table copies are not validated boot relocations. Control '
                      'RMW and post-call start tail are separate native stages. '
                      'Separate configuration/post-command/empty-pending native calls '
                      'check software consumption only. Neither physical store is executed. No peripheral, successful '
                      'DMA start, completion, cache behavior, pixels or timing is modeled.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
