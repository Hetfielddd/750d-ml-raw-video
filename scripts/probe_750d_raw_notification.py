# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace no-work RAW callbacks and a peer IRQ vector through native event code.

Kernel event objects and callbacks are supplied. No scheduler, physical IRQ,
DMA, pixels or peripheral acknowledgement behavior is modeled.
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
                         UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ,
                         UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
                                   UC_ARM_REG_CPSR, UC_ARM_REG_SPSR)
    base, delta, app_delta = 0xfe0a0000, 0x7e7473e0, 0xfcc82368
    raw, driver, event, stop, shadow = 0x1ac2220, 0x1ac1830, 0x100000, 0x10f000, 0x200000
    handle, callback = 0xe0002, 0x80009d8f
    controller, irq_slot, vector = 0xd5011000, 0x1acb264, 0x18
    irq_globals = (0x1ac0034, 0x1ac003c, 0x1ac0040)
    ranges = ((0xfe8395c4, 0xfe839642), (0x80009d8e, 0x80009dd2),
              (0x80009cee, 0x80009cf0), (0x80003d22, 0x80003d2a),
              (0x80007bc4, 0x80007bce), (0x80007b7e, 0x80007b88), (0x44c, 0x470),
              (0xfe74fc2a, 0xfe74fc58), (0xfe749d84, 0xfe749dba),
              (0xfe74bbd4, 0xfe74bc06), (0xfe74bcd4, 0xfe74bcf2),
              (0xfe74fb9e, 0xfe74fc2a), (0xfe749dba, 0xfe749e12),
              (0xfe74bda2, 0xfe74bddc),
              (0xfe74f9b4, 0xfe74f9b8), (0x230, 0x23a),
              (0xfe7545cc, 0xfe754630), (0xfe753806, 0xfe753814),
              (0xfe753840, 0xfe753856), (0x1bb709a, 0x1bb70aa))
    ranges += tuple((lo - delta, hi - delta) for lo, hi in
                    ((0xfe74fc2a, 0xfe74fc58), (0xfe749d84, 0xfe749dba),
                     (0xfe74bbd4, 0xfe74bc06), (0xfe74bcd4, 0xfe74bcf2),
                     (0xfe74f9b4, 0xfe74f9b8)))
    ranges += tuple((lo - delta, hi - delta) for lo, hi in
                    ((0xfe7545cc, 0xfe754630), (0xfe753806, 0xfe753814),
                     (0xfe753840, 0xfe753856)))
    ranges += ((vector, vector + 4), (0xdd8, 0xe8c), (0x67c, 0x6da),
               (0x258, 0x26a), (0x21a, 0x230), (0x6fc, 0x71e))
    definitions = [(kind, mask, irq, None) for kind in ('empty_pending', 'uninitialized')
                   for mask in (0, 0x6f) for irq in (0, 0x80)]
    definitions += [('direct_irq', 0x6f, 0, status) for status in (0, 4)]
    definitions += [('peer_vector', mask, 0, status) for mask in (0, 0x6f) for status in (0, 4)]
    cases = []
    for kind, mask, irq, status in definitions:
        from_vector = kind == 'peer_vector'
        check_wait = mask == 0x6f and not from_vector
        stack = 0x80101000 if from_vector else 0x10d000
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for runtime, mapping in ((0x80002000, delta), (0x80003000, delta),
                                 (0x80004000, delta), (0x80007000, delta), (0x80008000, delta),
                                 (0x80009000, delta), (0x8000a000, delta),
                                 (0x8000f000, delta), (0x1bb7000, app_delta)):
            uc.mem_map(runtime, 4096, UC_PROT_READ | UC_PROT_EXEC)
            offset = runtime + mapping - base
            uc.mem_write(runtime, data[offset:offset + 4096])
        uc.mem_map(0, 4096, UC_PROT_READ | UC_PROT_EXEC)
        offset = 0xfe744d60 - base
        uc.mem_write(0, data[offset:offset + 4096])
        for address, size in ((event, 0xe000), (0x1ac0000, 0x10000),
                              (0x1ad8000, 4096), (shadow, 0x60000)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        if from_vector:
            uc.mem_map(stack - 4096, 4096, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_map(controller, 4096, UC_PROT_READ | UC_PROT_WRITE)
            for runtime in (0x8000c000, 0x8000d000):
                uc.mem_map(runtime, 4096, UC_PROT_READ | UC_PROT_EXEC)
                offset = runtime + delta - base
                uc.mem_write(runtime, data[offset:offset + 4096])
        if status is not None:
            uc.mem_map(0xd0004000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        uc.reg_write(UC_ARM_REG_CPSR, 0x13 | irq)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        initial_flags = 0 if mask == 0 else 0x8000006f
        put(raw, 0 if kind == 'uninitialized' else 1)
        put(raw + 8, callback)
        put(raw + 12, 0x12345678)
        put(raw + 36, 0x5c62c000 if kind == 'uninitialized' else 0)
        put(driver + 4, mask)
        # Optional application RAW/aggregate callbacks are deliberately null.
        # The native driver callback and real kernel flag update still execute.
        put(driver + 44, handle)
        put(0x1ac05b8, event)
        put(0x1ac011c, 1)
        put(event + 8, initial_flags)
        uc.mem_write(event + 16, struct.pack('<h', 7))
        # Remaining fields, including waiter count +18 and active flags +20,
        # are supplied zero. No event allocation or blocked task is simulated.
        if status is not None:
            put(0x1ac40a4, shadow)
            put(0xd0004130, status)
            for address, value in ((0xd0004100, 1), (0xd0004104, 0x20000000)):
                put(address, value)
                put(shadow + (address & 0x7ffff), value)
            put(0x1ad8350, 0x1bb709b)
            put(0x1ad8354, 0)
            put(0x1ad8358, 1)
        errors, reached, writes, register_reads, entered = [], [], [], [], []
        controller_accesses = []
        boundary = [stop]

        def code_guard(emulator, address, size, _):
            if address == boundary[0]:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected notification code: {address:#x}')
                emulator.emu_stop()
            if address == callback & ~1:
                entered.append({'argument': hex(emulator.reg_read(UC_ARM_REG_R0)),
                                'irq_masked': bool(emulator.reg_read(UC_ARM_REG_CPSR) & 0x80)})

        def write_guard(emulator, access, address, size, value, _):
            allowed = (driver + 4, event + 8, 0xd0004100, 0xd0004104,
                       shadow + 0x4100, shadow + 0x4104)
            if from_vector:
                allowed += irq_globals + (irq_slot, irq_slot + 4, controller + 16)
            if not (stack - 256 <= address and address + size <= stack
                    or size == 4 and address in allowed):
                errors.append(f'Unexpected notification write: {address:#x}/{size}')
                emulator.emu_stop()
            if address in (driver + 4, event + 8) or 0xd0004000 <= address < 0xd0005000:
                writes.append({'address': hex(address), 'value': hex(value),
                               'irq_masked': bool(emulator.reg_read(UC_ARM_REG_CPSR) & 0x80)})
            if address == controller + 16:
                controller_accesses.append(['write', hex(address), value])
                if word(event + 8) != initial_flags | 16:
                    errors.append('Controller store preceded the native RAW event update')
                    emulator.emu_stop()

        def read_guard(emulator, access, address, size, value, _):
            if 0xd0000000 <= address < 0xe0000000:
                if from_vector and size == 4 and address in (controller, controller + 16):
                    controller_accesses.append(['read', hex(address), word(address)])
                    return
                register_reads.append([hex(address), size])
                if status is None or (address, size) != (0xd0004130, 4):
                    errors.append('Unexpected device-register RAM read')
                    emulator.emu_stop()

        uc.hook_add(UC_HOOK_CODE, code_guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.hook_add(UC_HOOK_MEM_READ, read_guard)
        wait_block_boundary_checked = False
        if check_wait:
            initial_cpu = uc.context_save()
            boundary[0] = 0xfe74bddc
            uc.reg_write(UC_ARM_REG_R0, handle)
            uc.reg_write(UC_ARM_REG_R1, 0x8000007f)
            uc.reg_write(UC_ARM_REG_R2, 0)
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            uc.emu_start(0xfe74fbab, base + len(data), count=256, timeout=500_000)
            if (errors or reached != [0xfe74bddc] or writes
                    or word(event + 8) != initial_flags
                    or not uc.reg_read(UC_ARM_REG_CPSR) & 0x80):
                raise RuntimeError('Initial missing-RAW-bit wait did not reach its blocking boundary')
            # This unreturned call is not woken up or assigned a success result.
            # A separate invocation starts from the original CPU state, using
            # the unchanged event object; scheduler bookkeeping never executes.
            uc.context_restore(initial_cpu)
            boundary[0] = stop
            reached.clear()
            wait_block_boundary_checked = True
        uc.reg_write(UC_ARM_REG_R0, 1)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        entry = 0xfe7545cc if status is not None else 0xfe8395c4
        if from_vector:
            # Native table installation. Controller enablement and the CPU's
            # hardware exception entry are outside this fixture.
            for register, value in ((UC_ARM_REG_R0, 0x8000d1ed), (UC_ARM_REG_R1, 1),
                                    (UC_ARM_REG_R2, 0x41)):
                uc.reg_write(register, value)
            uc.emu_start(0x6fd, base + len(data), count=64, timeout=500_000)
            if (errors or reached != [stop] or uc.reg_read(UC_ARM_REG_SP) != stack
                    or (word(irq_slot), word(irq_slot + 4)) != (0x8000d1ed, 1)):
                raise RuntimeError(f'Invalid native vector table registration: {errors}/{reached}')
            reached.clear()
            put(controller, 0x41)
            put(0x1ac003c, 1)  # Nested case bypasses the scheduler and stack switch.
            uc.reg_write(UC_ARM_REG_CPSR, 0xb2)  # Thumb IRQ mode, IRQ masked.
            uc.reg_write(UC_ARM_REG_SPSR, 0x33)  # Interrupted Thumb SVC context.
            uc.reg_write(UC_ARM_REG_LR, stop + 4)
            uc.reg_write(UC_ARM_REG_R0, 0x11223344)
            uc.reg_write(UC_ARM_REG_R1, 0x55667788)
            entry = vector
        try:
            uc.emu_start(entry | 1, base + len(data), count=384 if from_vector else 256,
                         timeout=500_000)
        except UcError as error:
            raise RuntimeError(f'{kind}: native fault at {uc.reg_read(UC_ARM_REG_PC):#x}') from error
        expected_mask = (mask | 16) if mask != 0x6f else 0
        expected_writes = [(hex(driver + 4), hex(mask | 16)),
                           (hex(event + 8), hex(initial_flags | 16))]
        if mask == 0x6f:
            expected_writes.append((hex(driver + 4), '0x0'))
        software_writes = [(entry['address'], entry['value']) for entry in writes
                           if entry['address'] in (hex(driver + 4), hex(event + 8))]
        if (errors or reached != [stop] or uc.reg_read(UC_ARM_REG_SP) != stack
                or uc.reg_read(UC_ARM_REG_CPSR) & 0x80 != irq
                or len(entered) != 1 or entered[0]['argument'] != '0x12345678'
                or word(driver + 4) != expected_mask or word(event + 8) != initial_flags | 16
                or software_writes != expected_writes):
            raise RuntimeError(f'Invalid notification flow: {errors}/{reached}/{writes}/{entered}')
        expected_register_reads = [['0xd0004130', 4]] if status is not None else []
        register_writes = [(entry['address'], entry['value']) for entry in writes
                           if entry['address'].startswith('0xd')]
        expected_register_writes = ([] if status is None else
                                    ([('0xd0004104', '0x0')] if status == 4 else [])
                                    + [('0xd0004100', '0x4')])
        if register_reads != expected_register_reads or register_writes != expected_register_writes:
            raise RuntimeError('Unexpected register access in notification source path')
        for entry in writes:
            if entry['address'] in (hex(driver + 4), hex(event + 8)):
                expected_irq = from_vector or bool(irq) or entry['value'] != '0x0'
                if entry['irq_masked'] != expected_irq:
                    raise RuntimeError('Native component/event update has an unexpected IRQ mask')
        wait_returned = None
        if check_wait:
            # Execute the actual ALL-bit wait wrapper and lookup on the event
            # just updated by the no-work/IRQ chain. The other bits, including
            # bit31, were explicitly preseeded; no live completion is inferred.
            reached.clear()
            uc.reg_write(UC_ARM_REG_R0, handle)
            uc.reg_write(UC_ARM_REG_R1, 0x8000007f)
            uc.reg_write(UC_ARM_REG_R2, 0)
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            uc.emu_start(0xfe74fbab, base + len(data), count=256, timeout=500_000)
            if (errors or reached != [stop] or uc.reg_read(UC_ARM_REG_R0) != 0
                    or uc.reg_read(UC_ARM_REG_SP) != stack
                    or uc.reg_read(UC_ARM_REG_CPSR) & 0x80 != irq
                    or word(event + 8) != 0x8000007f):
                raise RuntimeError('Native ALL-bit wait did not accept the updated fixture flags')
            wait_returned = True
        cases.append({'entry_kind': kind, 'supplied_component_mask': hex(mask),
                      'supplied_initial_event_flags': hex(initial_flags), 'incoming_irq_mask': hex(irq),
                      'supplied_irq_status': status, 'native_driver_callback_entries': entered,
                      'native_writes': writes, 'register_reads': register_reads,
                      'event_flags_after_return': hex(word(event + 8)),
                      'all_start_gate_bits_present': (word(event + 8) & 0x8000007f) == 0x8000007f,
                      'native_all_bit_wait_returned_zero': wait_returned,
                      'initial_all_bit_wait_stopped_before_blocking': wait_block_boundary_checked,
                      'driver_component_mask_after_return': hex(word(driver + 4)),
                      'irq_mask_restored': True, 'passed': True})
        if from_vector:
            expected_accesses = [['read', hex(controller), 0x41],
                                 ['write', hex(controller + 16), 0x41],
                                 ['read', hex(controller + 16), 0x41]]
            if (controller_accesses != expected_accesses or word(0x1ac0040) != 0x41
                    or word(0x1ac003c) != 1 or uc.reg_read(UC_ARM_REG_CPSR) & 0x3f != 0x33
                    or uc.reg_read(UC_ARM_REG_R0) != 0x11223344
                    or uc.reg_read(UC_ARM_REG_R1) != 0x55667788
                    or not entered[0]['irq_masked']):
                raise RuntimeError(f'Unexpected peer vector return or controller access: {controller_accesses}')
            cases[-1]['controller_accesses'] = controller_accesses
            cases[-1]['nested_irq_context_restored'] = True
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'native_event_lookup_and_update_executed': True,
            'application_raw_and_aggregate_callbacks_supplied_null': True,
            'nested_peer_vector_executed_on_passive_register_ram': True,
            'physical_irq_or_dma_modeled': False, 'frame_lease_validated': False,
            'camera_binding_enabled': False,
            'limits': 'Supplied initialized/empty or uninitialized RAW state, native '
                      'driver callback, component masks, valid event handle/table/object '
                      'and no waiters. Application RAW/aggregate callback slots are null; '
                      'their task notifications do not execute. Initial other-component '
                      'and high event bits are fixture inputs, not observed completions. '
                      'A missing-bit wait stops before scheduler bookkeeping; a separate '
                      'post-notification wait returns normally, not a simulated wakeup. '
                      'IRQ cases enter either the handler directly or the peer vector '
                      'in a supplied nested IRQ context on passive register RAM. '
                      'No controller delivery, first-level IRQ scheduling, event allocation, pixels, '
                      'sensor transfer, peripheral acknowledgement or ownership modeled.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
