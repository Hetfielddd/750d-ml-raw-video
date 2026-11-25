# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute native RAW command ordering against artificial register RAM.

No peripheral behavior, DMA, pixels, task scheduling or frame completion is
modeled. The reviewed non-alternate software handler executes without call stubs.
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
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR,
                                   UC_ARM_REG_PC, UC_ARM_REG_CPSR)
    base, delta, peer_low = 0xfe0a0000, 0x7e7473e0, 0xfe744d60
    state, shadow, stack, stop, callback = 0x1ac2220, 0x200000, 0x10d000, 0x10f000, 0x10f100
    config, a, b = 0x100000, 0x5c62c000, 0x5e000000
    destination, control, command = 0xd0004108, 0xd0004104, 0xd0004100
    packing, trigger = 0xd0037014, 0xd0008090
    initial_control, initial_packing = 8, 0xa5a5b5df
    registers = (destination, control, command, packing, trigger)
    ranges = ((0xfe8395c4, 0xfe839642), (0xfe8396b0, 0xfe8396ce),
              (0xfe86f858, 0xfe86f85c), (0xfe86f878, 0xfe86f87c),
              (0xfe86f910, 0xfe86f920), (0xfe86f7e8, 0xfe86f7ec),
              (0xfe86f890, 0xfe86f894), (0x8000c5fe, 0x8000c67e),
              (0x8000c57e, 0x8000c5be), (0x8000c426, 0x8000c434),
              (0x8000c460, 0x8000c476), (0x80003d22, 0x80003d2a),
              (0x80007bc4, 0x80007bce), (0x80007b7e, 0x80007b88),
              (0x44c, 0x470))
    definitions = [(f'format_{fmt:x}_irq_{irq:x}', fmt, irq, 'normal')
                   for fmt in (0, 34, 0xffffffff) for irq in (0, 0x80)]
    definitions += [('skip_address_flag', 34, 0, 'override'),
                    ('empty_pending_callback', 34, 0, 'empty'),
                    ('uninitialized_callback', 34, 0, 'uninitialized'),
                    ('repeated_calls_and_republication', 34, 0, 'repeat')]
    cases = []
    for name, fmt, irq, kind in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for runtime in (0x80003000, 0x80007000, 0x8000c000, 0x8000f000):
            uc.mem_map(runtime, 4096, UC_PROT_READ | UC_PROT_EXEC)
            offset = runtime + delta - base
            uc.mem_write(runtime, data[offset:offset + 4096])
        uc.mem_map(0, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(0, data[peer_low - base:peer_low - base + 4096])
        for address, size in ((config, 0xe000), (0x1ac2000, 4096),
                              (0x1ac4000, 4096), (0x1ad8000, 4096), (shadow, 0x60000),
                              (0xd0004000, 4096), (0xd0008000, 4096), (0xd0037000, 4096)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.reg_write(UC_ARM_REG_CPSR, 0x13 | irq)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(0x1ac40a4, shadow)
        put(state, 0 if kind == 'uninitialized' else 1)
        put(state + 8, callback | 1)
        put(state + 12, 0x12345678)
        put(state + 28, 1)
        put(state + 36, 0 if kind == 'empty' else a)
        put(state + 44, fmt)
        uc.mem_write(0x1ad8bd8, bytes([1 if kind == 'override' else 0]))
        put(0x1ad81c8, 0x12345678)
        for address, value in ((destination, b & 0x3fffffff), (control, initial_control),
                               (command, 0xdeadbeef), (packing, initial_packing), (trigger, 0)):
            put(address, value)
            put(shadow + (address & 0x7ffff), value)
        # The RMW helper reads its shadow, not this deliberately different RAM.
        put(packing, 0x11223344)
        put(0xd0004110, 0x04370e00)
        put(shadow + 0x4110, 0x04370e00)
        stores, errors, reached = [], [], []

        def code_guard(emulator, address, size, _):
            if address in (stop, callback):
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected command-order code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            allowed = (state + 36, state + 44, 0x1ad81c8) + registers + tuple(
                shadow + (address & 0x7ffff) for address in registers)
            if not (stack - 256 <= address and address + size <= stack
                    or size == 4 and address in allowed):
                errors.append(f'Unexpected command-order write: {address:#x}/{size}')
                emulator.emu_stop()
            if address in registers or address == state + 36:
                stores.append({'address': hex(address), 'value': hex(value),
                               'irq_masked': bool(emulator.reg_read(UC_ARM_REG_CPSR) & 0x80)})

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def run(entry):
            reached.clear()
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            try:
                uc.emu_start(entry | 1, base + len(data), count=256, timeout=500_000)
            except UcError as error:
                raise RuntimeError(f'{name}: native fault at {uc.reg_read(UC_ARM_REG_PC):#x}') from error
            if errors or len(reached) != 1:
                raise RuntimeError(f'{name}: invalid command path: {errors}/{reached}')
            if reached == [stop] and (uc.reg_read(UC_ARM_REG_SP) != stack
                                     or uc.reg_read(UC_ARM_REG_R0) != 0):
                raise RuntimeError('Native RAW function failed to restore stack or return zero')
            if uc.reg_read(UC_ARM_REG_CPSR) & 0x80 != irq:
                raise RuntimeError('Native RAW function failed to restore the incoming IRQ mask')

        run(0xfe8395c4)
        if kind in ('empty', 'uninitialized'):
            if (reached != [callback] or stores or uc.reg_read(UC_ARM_REG_R0) != 0x12345678
                    or word(state + 36) != (0 if kind == 'empty' else a)):
                raise RuntimeError('Empty/uninitialized branch unexpectedly submitted register writes')
            cases.append({'case': name, 'callback_boundary_reached': True,
                          'register_writes': [], 'callback_body_executed': False, 'passed': True})
            continue
        if reached != [stop]:
            raise RuntimeError('Nonempty RAW handler did not return after its command stores')
        expected_destination = (b if kind == 'override' else a) & 0x3fffffff
        expected_registers = ([control, command, packing, trigger] if kind == 'override' else list(registers))
        expected_values = ([initial_control | 0x20000000, 1,
                            (initial_packing & ~63) | (fmt & 63), 1])
        if kind != 'override':
            expected_values.insert(0, expected_destination)
        expected_stores = [(hex(address), hex(value)) for address, value in
                           zip(expected_registers + [state + 36], expected_values + [0])]
        if [(entry['address'], entry['value']) for entry in stores] != expected_stores:
            raise RuntimeError(f'{name}: unexpected native store order: {stores}')
        if (word(destination) != expected_destination or word(state + 36) != 0
                or word(0x1ad81c8) != 0 or word(0xd0004110) != 0x04370e00
                or word(shadow + 0x4110) != 0x04370e00):
            raise RuntimeError('Native command sequence changed protected fixture fields')
        for address in registers:
            if word(address) != word(shadow + (address & 0x7ffff)):
                raise RuntimeError('Native register and shadow writes diverged')
        for entry in stores:
            if entry['irq_masked'] != (True if entry['address'] == hex(packing) else bool(irq)):
                raise RuntimeError('Unexpected IRQ mask at a native command store')
        first_stores = stores.copy()
        repeat_stores = []
        if kind == 'repeat':
            stores.clear()
            run(0xfe8395c4)
            if reached != [callback] or stores:
                raise RuntimeError('Second invocation reused the cleared pending address')
            put(config, b)
            put(config + 4, 34)
            uc.reg_write(UC_ARM_REG_R0, config)
            uc.reg_write(UC_ARM_REG_R1, 0)
            run(0xfe8396b0)
            if word(state + 36) != b:
                raise RuntimeError('Native republication did not restore pending B')
            stores.clear()
            run(0xfe8395c4)
            if reached != [stop] or word(destination) != b & 0x3fffffff or word(state + 36) != 0:
                raise RuntimeError('Republished pending B did not complete its software command sequence')
            expected_repeat = expected_stores.copy()
            expected_repeat[0] = (hex(destination), hex(b & 0x3fffffff))
            if [(entry['address'], entry['value']) for entry in stores] != expected_repeat:
                raise RuntimeError('Republished command changed native register order')
            repeat_stores = stores.copy()
        cases.append({'case': name, 'software_handler_returned': True,
                      'first_invocation_stores': first_stores,
                      'republished_invocation_stores': repeat_stores,
                      'destination_after_first_invocation': hex(expected_destination),
                      'pending_cleared_after_command_stores': True,
                      'irq_mask_restored': True, 'geometry_unchanged': True,
                      'republication_sequence_checked': kind == 'repeat', 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'register_addresses_are_artificial_ram': True,
            'dma_or_peripheral_behavior_modeled': False, 'pixel_memory_mapped': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Supplied initialized/non-alternate channel-1 state, shadow base, '
                      'register RAM, packing markers and optional skip-address flag. '
                      'Scoped driver/peer-kernel copies are experiment mappings, not '
                      'validated boot relocation. Full reviewed RAW software handler '
                      'executes register stores and native IRQ helpers; ordinary RAM '
                      'acceptance is not peripheral command acceptance. Empty branches '
                      'stop before the supplied callback. No scheduler, transport, '
                      'sensor, DMA, pixels, cache coherence or completion is modeled.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
