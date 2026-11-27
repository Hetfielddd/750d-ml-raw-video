# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute native RAW command ordering against artificial register RAM.

The reviewed non-alternate software handler executes without call stubs. Separate
cases check native register setup before start and address state at a direct IRQ.
No peripheral behavior, DMA, pixels, task scheduling or frame completion is modeled.
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
                         UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_PROT_READ,
                         UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R5,
                                   UC_ARM_REG_R6, UC_ARM_REG_SP, UC_ARM_REG_LR,
                                   UC_ARM_REG_PC, UC_ARM_REG_CPSR)
    base, delta, peer_low = 0xfe0a0000, 0x7e7473e0, 0xfe744d60
    state, shadow, stack, stop, callback = 0x1ac2220, 0x200000, 0x10d000, 0x10f000, 0x10f100
    config, a, b = 0x100000, 0x5c62c000, 0x5e000000
    destination, control, command = 0xd0004108, 0xd0004104, 0xd0004100
    status_register, irq_record = 0xd0004130, 0x1ad8350
    irq_forwarder, app_delta = 0x1bb709a, 0xfcc82368
    packing, trigger = 0xd0037014, 0xd0008090
    route = 0xd0005004
    setup_registers = (route, 0xd00370d4, 0xd0037074, trigger + 4, trigger + 8,
                       0xd0008264, 0xd0008268, 0xd0008bf0, 0xd0004140,
                       *range(0xd000410c, 0xd000412c, 4))
    initial_control, initial_packing = 8, 0xa5a5b5df
    registers = (destination, control, command, packing, trigger)
    ranges = ((0xfe8395c4, 0xfe839642), (0xfe8396b0, 0xfe8396ce),
              (0xfe86f858, 0xfe86f85c), (0xfe86f878, 0xfe86f87c),
              (0xfe86f910, 0xfe86f920), (0xfe86f7e8, 0xfe86f7ec),
              (0xfe86f890, 0xfe86f894), (0x8000c5fe, 0x8000c67e),
              (0x8000c57e, 0x8000c5be), (0x8000c426, 0x8000c434),
              (0x8000c460, 0x8000c476), (0x80003d22, 0x80003d2a),
              (0x80007bc4, 0x80007bce), (0x80007b7e, 0x80007b88),
              (0x44c, 0x470), (0xfe75399e, 0xfe7539be),
              (0xfe753806, 0xfe753814), (0xfe753834, 0xfe753856),
              (0xfe7545cc, 0xfe754630), (irq_forwarder, 0x1bb70aa))
    ranges += ((0xfe83945a, 0xfe839462), (0xfe83946c, 0xfe839488),
               (0xfe8394f2, 0xfe8395ba), (0xfe86f828, 0xfe86f82c),
               (0xfe86f850, 0xfe86f854), (0xfe86f868, 0xfe86f86c),
               (0xfe86f7d8, 0xfe86f7dc), (0xfe86f7e0, 0xfe86f7e4),
               (0xfe754310, 0xfe75432a), (0xfe75501e, 0xfe755034),
               (0xfe753822, 0xfe753826), (0xfe7554da, 0xfe7554f4))
    ranges += tuple((lo - delta, hi - delta) for lo, hi in
                    ((0xfe7542e6, 0xfe7542f8), (0xfe7539be, 0xfe7539de),
                     (0xfe753a5e, 0xfe753b1a), (0xfe753834, 0xfe753840),
                     (0xfe753856, 0xfe753888), (0xfe753c32, 0xfe753c62)))
    definitions = [(f'format_{fmt:x}_irq_{irq:x}', fmt, irq, 'normal')
                   for fmt in (0, 34, 0xffffffff) for irq in (0, 0x80)]
    definitions += [('skip_address_flag', 34, 0, 'override'),
                    ('empty_pending_callback', 34, 0, 'empty'),
                    ('uninitialized_callback', 34, 0, 'uninitialized'),
                    ('repeated_calls_and_republication', 34, 0, 'repeat')]
    irq_sequences = {
        f'irq_{step}_{status}': (step, status)
        for step in ('start', 'pending_b', 'started_b', 'override', 'stop')
        for status in (0, 4)
    }
    definitions += [(name, 34, 0, 'override' if step == 'override' else 'normal')
                    for name, (step, _) in irq_sequences.items()]
    setup_cases = {f'liveview_selector_{selector}': selector for selector in (1, 2, 3)}
    definitions += [(name, 34, 0, 'normal') for name in setup_cases]
    cases, irq_cases, config_cases = [], [], []
    for name, fmt, irq, kind in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        runtime_pages = (0x80003000, 0x80007000, 0x8000c000, 0x8000f000)
        if name in setup_cases:
            runtime_pages += (0x8000d000,)
        for runtime in runtime_pages:
            uc.mem_map(runtime, 4096, UC_PROT_READ | UC_PROT_EXEC)
            offset = runtime + delta - base
            uc.mem_write(runtime, data[offset:offset + 4096])
        uc.mem_map(0, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(0, data[peer_low - base:peer_low - base + 4096])
        if name in irq_sequences:
            page = irq_forwarder & ~4095
            uc.mem_map(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
            offset = page + app_delta - base
            uc.mem_write(page, data[offset:offset + 4096])
        for address, size in ((config, 0xe000), (0x1ac2000, 4096),
                              (0x1ac4000, 4096), (0x1ad8000, 4096), (shadow, 0x60000),
                              (0xd0004000, 4096), (0xd0008000, 4096), (0xd0037000, 4096)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        if name in setup_cases:
            uc.mem_map(route & ~4095, 4096, UC_PROT_READ | UC_PROT_WRITE)
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
        observed_registers = registers + (setup_registers if name in setup_cases else ())
        allowed = (state + 36, state + 44, 0x1ad81c8, 0x1ad8288) + observed_registers + tuple(
            shadow + (address & 0x7ffff) for address in observed_registers)
        boundary = stop
        irq_reads = []
        expected_register_read = None

        def code_guard(emulator, address, size, _):
            if address in (boundary, callback):
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected command-order code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 256 <= address and address + size <= stack
                    or name in setup_cases and stack + 4 <= address and address + size <= stack + 52
                    or size == 4 and address in allowed):
                errors.append(f'Unexpected command-order write: {address:#x}/{size}')
                emulator.emu_stop()
            if address in observed_registers or address == state + 36:
                stores.append({'address': hex(address), 'value': hex(value),
                               'irq_masked': bool(emulator.reg_read(UC_ARM_REG_CPSR) & 0x80)})

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)

        def irq_read_guard(emulator, access, address, size, value, _):
            if expected_register_read is not None and (0xd0004000 <= address < 0xd0005000
                                                       or address in (shadow + 0x4108, state + 36)):
                irq_reads.append((address, size))
                if (address, size) != (expected_register_read, 4):
                    errors.append(f'Unexpected channel register read: {address:#x}/{size}')
                    emulator.emu_stop()

        if name in irq_sequences or name in setup_cases:
            uc.hook_add(UC_HOOK_MEM_READ, irq_read_guard)

        def run(entry, *, expected_return=0, target=stop):
            nonlocal boundary
            boundary = target
            reached.clear()
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            try:
                uc.emu_start(entry | 1, base + len(data),
                             count=512 if target == 0xfe8395ba else 256, timeout=500_000)
            except UcError as error:
                raise RuntimeError(f'{name}: native fault at {uc.reg_read(UC_ARM_REG_PC):#x}') from error
            if errors or len(reached) != 1:
                raise RuntimeError(f'{name}: invalid command path: {errors}/{reached}')
            if reached == [stop] and (uc.reg_read(UC_ARM_REG_SP) != stack
                                     or uc.reg_read(UC_ARM_REG_R0) != expected_return):
                raise RuntimeError('Native RAW function failed to restore stack or return expected value')
            if uc.reg_read(UC_ARM_REG_CPSR) & 0x80 != irq:
                raise RuntimeError('Native RAW function failed to restore the incoming IRQ mask')

        start_control, start_packing, expected_geometry = initial_control, initial_packing, 0x04370e00
        if name in setup_cases:
            selector = setup_cases[name]
            # Supplied normal initializer context and cleared descriptor stack.
            # Enter the routing call after object setup, then skip callback
            # registration and enter the actual non-alternate register setup.
            for offset, value in enumerate((1, fmt, 0, 2048, 1080, selector)):
                put(config + offset * 4, value)
            put(route, 0x33)  # Contrast with the IPC route's actual store.
            for register, value in ((UC_ARM_REG_R4, config), (UC_ARM_REG_R5, state),
                                    (UC_ARM_REG_R6, 0)):
                uc.reg_write(register, value)
            run(0xfe83945a, target=0xfe839462)
            if reached != [0xfe839462] or [(s['address'], s['value']) for s in stores] != [(hex(route), '0x0')]:
                raise RuntimeError('Wrong RAW route store before callback registration')
            run(0xfe83946c, target=0xfe8395ba)
            # Selector 1 sets bit 30, selector 2 takes the bit-12 form,
            # and selector 3 bypasses both writes. All clear the low 3 bits.
            start_control = {1: 0x40000008, 2: 0x1008, 3: 8}[selector]
            start_packing = (initial_packing & ~63) | fmt
            setup_values = [word(address) for address in (route, control, packing, 0xd0004110, trigger)]
            if (reached != [0xfe8395ba]
                    or setup_values != [0, start_control, start_packing, expected_geometry, 0x80000000]
                    or word(state + 36) != 0):
                raise RuntimeError(f'{name}: unexpected native initialization {list(map(hex, setup_values))}')
            setup_stores = stores.copy()
            put(config, a)
            put(config + 4, fmt)
            uc.reg_write(UC_ARM_REG_R0, config)
            uc.reg_write(UC_ARM_REG_R1, 0)
            run(0xfe8396b0)
            if reached != [stop] or word(state + 36) != a:
                raise RuntimeError('Native publication after setup did not select A')
            stores.clear()

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
        expected_values = ([start_control | 0x20000000, 1,
                            (start_packing & ~63) | (fmt & 63), 1])
        if kind != 'override':
            expected_values.insert(0, expected_destination)
        expected_stores = [(hex(address), hex(value)) for address, value in
                           zip(expected_registers + [state + 36], expected_values + [0])]
        if [(entry['address'], entry['value']) for entry in stores] != expected_stores:
            raise RuntimeError(f'{name}: unexpected native store order: {stores}')
        if (word(destination) != expected_destination or word(state + 36) != 0
                or word(0x1ad81c8) != 0 or word(0xd0004110) != expected_geometry
                or word(shadow + 0x4110) != expected_geometry):
            raise RuntimeError('Native command sequence changed protected fixture fields')
        for address in registers:
            if word(address) != word(shadow + (address & 0x7ffff)):
                raise RuntimeError('Native register and shadow writes diverged')
        for entry in stores:
            if entry['irq_masked'] != (True if entry['address'] == hex(packing) else bool(irq)):
                raise RuntimeError('Unexpected IRQ mask at a native command store')
        first_stores = stores.copy()
        if name in setup_cases:
            if word(route) != 0 or word(shadow + 0x5004) != 0:
                raise RuntimeError('Native start changed the channel route')
            samples = []
            for status in (2, 6, 0x102):
                put(status_register, status)
                for entry, expected_value in ((0xfe754310, status & 3),
                                              (0xfe7554da, (status >> 2) & 1)):
                    expected_register_read = status_register
                    irq_reads.clear()
                    stores.clear()
                    uc.reg_write(UC_ARM_REG_R0, 1)
                    run(entry, expected_return=expected_value)
                    if reached != [stop] or stores or irq_reads != [(status_register, 4)]:
                        raise RuntimeError('Native status reader did not sample the channel register')
                samples.append({'supplied_status': hex(status), 'low_two_bits': status & 3,
                                'bit_two': (status >> 2) & 1})
            physical = expected_destination + 0x1000
            put(destination, physical)
            expected_register_read = destination
            irq_reads.clear()
            uc.reg_write(UC_ARM_REG_R0, 1)
            run(0xfe75501e, expected_return=physical)
            if (reached != [stop] or stores or irq_reads != [(destination, 4)]
                    or word(shadow + 0x4108) != expected_destination):
                raise RuntimeError('Native hardware address read did not differ from the shadow')
            config_cases.append({'selector': selector, 'setup_stores': setup_stores,
                                 'start_stores': first_stores, 'status_samples': samples,
                                 'physical_address_word': hex(physical),
                                 'programmed_address_shadow': hex(expected_destination),
                                 'passed': True})
            continue

        def publish_b():
            put(config, b)
            put(config + 4, 34)
            uc.reg_write(UC_ARM_REG_R0, config)
            uc.reg_write(UC_ARM_REG_R1, 0)
            run(0xfe8396b0)
            if reached != [stop] or word(state + 36) != b:
                raise RuntimeError('Native republication did not restore pending B')

        if name in irq_sequences:
            step, status = irq_sequences[name]
            if step in ('pending_b', 'started_b'):
                publish_b()
            if step == 'started_b':
                run(0xfe8395c4)
                if reached != [stop] or word(state + 36) != 0:
                    raise RuntimeError('Second native start did not consume pending B')
            if step == 'stop':
                uc.reg_write(UC_ARM_REG_R0, 1)
                run(0xfe75399e, expected_return=control)
                if reached != [stop] or word(0x1ad81c8) != 1:
                    raise RuntimeError('Native stop request did not set its flag')
            selected = (b if step in ('started_b', 'override') else a) & 0x3fffffff
            pending = b if step == 'pending_b' else 0
            if (word(destination), word(shadow + 0x4108), word(state + 36)) != (selected, selected, pending):
                raise RuntimeError('Native sequence did not establish expected address state')
            # Deliberately diverge physical-address RAM from the programmed
            # shadow. This marker does not simulate a cursor or DMA progress.
            physical = selected + 0x4000
            put(destination, physical)
            uc.reg_write(UC_ARM_REG_R0, destination)
            run(0xfe753834, expected_return=selected)
            if reached != [stop]:
                raise RuntimeError('Native address-shadow reader did not return')
            put(status_register, status)
            put(irq_record, irq_forwarder | 1)
            put(irq_record + 4, 0)
            stores.clear()
            expected_register_read = status_register
            uc.reg_write(UC_ARM_REG_R0, 1)
            run(0xfe7545cc)
            if (reached != [callback] or uc.reg_read(UC_ARM_REG_R0) != 0x12345678
                    or irq_reads != [(status_register, 4)] or word(destination) != physical
                    or word(shadow + 0x4108) != selected or word(state + 36) != pending
                    or word(command) != 4
                    or word(0x1ad81c8) != (step == 'stop')):
                raise RuntimeError(f'{name}: IRQ did not preserve address state and forward the same argument')
            irq_cases.append({'case': step, 'supplied_irq_status': status,
                              'programmed_address_shadow': hex(selected),
                              'supplied_physical_word': hex(physical),
                              'pending_address': hex(pending),
                              'stop_request_flag': word(0x1ad81c8),
                              'callback_argument': hex(uc.reg_read(UC_ARM_REG_R0)),
                              'irq_register_reads': [hex(address) for address, _ in irq_reads],
                              'irq_register_stores': stores.copy(), 'passed': True})
            continue

        repeat_stores = []
        if kind == 'repeat':
            stores.clear()
            run(0xfe8395c4)
            if reached != [callback] or stores:
                raise RuntimeError('Second invocation reused the cleared pending address')
            publish_b()
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
            'direct_irq_destination_cases': irq_cases,
            'liveview_configuration_cases': config_cases,
            'native_calls_stubbed': False, 'register_addresses_are_artificial_ram': True,
            'dma_or_peripheral_behavior_modeled': False, 'pixel_memory_mapped': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Supplied initialized/non-alternate channel-1 state, shadow base, '
                      'register RAM, packing markers and optional skip-address flag. '
                      'Scoped driver/peer-kernel copies are experiment mappings, not '
                      'validated boot relocation. Full reviewed RAW software handler '
                      'executes register stores and native IRQ helpers; ordinary RAM '
                      'acceptance is not peripheral command acceptance. Empty branches '
                      'stop before the supplied callback. Additional direct-IRQ cases '
                      'use supplied status and physical register markers and stop '
                      'before the registered driver callback. Configuration cases '
                      'use supplied local initializer context, omit callback registration '
                      'and sample supplied register words after start. No scheduler, transport, '
                      'sensor, DMA, pixels, cache coherence or completion is modeled.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
