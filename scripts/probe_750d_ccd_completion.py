# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace CCD writer completion registration, task events and return preparation.

Queue delivery and return transport remain explicit unexecuted boundaries.
No hardware IRQ, register access, pixel data or frame lease is modeled.
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
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    base, app_delta, driver_delta = 0xfe0a0000, 0xfcc82368, 0x7e7473e0
    context, subtask, state, task, stack, stop = 0x100000, 0x101000, 0x102000, 0x103000, 0x10d000, 0x10f000
    ccd, table, queue_marker = 0x1ac1978, 0x1cf253c, 0x2468ace0
    queue_boundary, transport_boundary = 0xfe86f740 - app_delta, 0xfe86f644 - app_delta
    cases = []
    definitions = [(event, route, False) for event in (13, 14) for route in (0x10000, 0x30009)]
    definitions += [(13, 0x10000, True)]
    ranges = ((0xfe810ce0, 0xfe810cf2), (0xfe810d72, 0xfe810d82),
              (0xfe80769c, 0xfe8076a6),
              (0xfe824704, 0xfe824728), (0xfe825062, 0xfe82506c),
              (0xfe825028, 0xfe825044), (0xfe824fd8, 0xfe824ff8),
              (0xfe810d26 - app_delta, 0xfe810d52 - app_delta),
              (0xfe86fb30 - app_delta, 0xfe86fb4a - app_delta),
              (0x800057fc, 0x80005886),
              (0xfe810ee0 - app_delta, 0xfe810f12 - app_delta),
              (0xfe86fbde - app_delta, 0xfe86fbf2 - app_delta))
    for event, route, removed in definitions:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for runtime, delta in ((0x1b8e000, app_delta), (0x1bed000, app_delta),
                               (0x1cf2000, app_delta), (0x80005000, driver_delta),
                               (0x8000f000, driver_delta)):
            uc.mem_map(runtime, 4096, UC_PROT_READ | UC_PROT_EXEC)
            offset = runtime + delta - base
            uc.mem_write(runtime, data[offset:offset + 4096])
        for address, size in ((context, 0xe000), (0x1ac1000, 4096)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        def args():
            return [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]

        def run(entry, target, supplied=()):
            errors, reached = [], []

            def code_guard(emulator, address, size, _):
                if address == target:
                    reached.append(address)
                    emulator.emu_stop()
                elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                    errors.append(f'Unexpected CCD completion code: {address:#x}')
                    emulator.emu_stop()

            def write_guard(emulator, access, address, size, value, _):
                if not (stack - 256 <= address and address + size <= stack
                        or ccd + 16 <= address and address + size <= ccd + 32
                        or (address, size) in ((ccd + 36, 4), (subtask + 12, 4), (state + 28, 4),
                                               (context, 4), (context + 8, 4))):
                    errors.append(f'Unexpected CCD completion write: {address:#x}/{size}')
                    emulator.emu_stop()

            hooks = [uc.hook_add(UC_HOOK_CODE, code_guard), uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)]
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            for register, value in supplied:
                uc.reg_write(register, value)
            try:
                uc.emu_start(entry | 1, base + len(data), count=192, timeout=500_000)
            except UcError as error:
                raise RuntimeError(f'Native CCD fault at {uc.reg_read(UC_ARM_REG_PC):#x}') from error
            finally:
                for hook in hooks:
                    uc.hook_del(hook)
            if errors or reached != [target]:
                raise RuntimeError(f'Invalid CCD completion stage: {errors}/{reached}')
            if target == stop and uc.reg_read(UC_ARM_REG_SP) != stack:
                raise RuntimeError('Native CCD helper did not restore its stack')

        # Native constructor supplies table, event count and state stride; stop
        # before the actual allocation/construction import, never fake its return.
        run(0xfe810ce0, 0xfe86f5d8)
        if args()[1:] != [0, table, 16] or word(uc.reg_read(UC_ARM_REG_SP)) != 1:
            raise RuntimeError('Unexpected CCD task state-object constructor arguments')
        signature = struct.unpack_from('<I', data, 0xfe756b40 - base)[0]
        uc.mem_write(state, struct.pack('<8I', signature, 0, 0, 0x8000581b, table, 16, 1, 0))
        put(context + 4, state)
        put(subtask, task)
        put(task, queue_marker)
        # Separate post-task-create constructor slice, with a supplied subtask
        # object. Its real instructions publish the actual service route.
        run(0xfe80769c, 0xfe8076a6,
            ((UC_ARM_REG_R4, context), (UC_ARM_REG_R0, subtask)))
        if word(context) != subtask or word(context + 8) != 0x10000:
            raise RuntimeError('Native ShtCapture service-route publication mismatch')
        if route != 0x10000:
            put(context + 8, route)  # Explicit dynamic-route control fixture.
        # Native caller continuation installs both actual callback pointers and
        # its supplied owner context using the real module registration setters.
        run(0xfe810d72, 0xfe810d82, ((UC_ARM_REG_R5, context),))
        if (word(ccd + 16) != 0x1b8e9d5 or word(ccd + 20) != context
                or word(ccd + 24) != 0x1b8e9bf or word(ccd + 28) != context):
            raise RuntimeError('Native CCD callback registration mismatch')
        # Separately enter the conditional channel-2 registration preparation.
        # Controller registration/enablement itself is not executed.
        run(0xfe825062, 0xfe86f860)
        registration = args()[:3]
        if registration != [2, 0x1ba2cc1, 0]:
            raise RuntimeError('CCD channel-2 callback preparation mismatch')
        if removed:
            run(0xfe82470c, stop)
        entry = 0xfe825028 if event == 13 else 0xfe824fd8
        run(entry, 0xfe8a48cc if removed else queue_boundary,
            ((UC_ARM_REG_R0, 0x5c62c000), (UC_ARM_REG_R1, 0x87654321)))
        if removed:
            if word(subtask + 12) != 0 or word(ccd + 16) or word(ccd + 20):
                raise RuntimeError('Unregistered CCD callback unexpectedly prepared a task event')
            cases.append({'case': 'native_completion_callback_removed', 'queue_request_reached': False,
                          'passed': True})
            continue
        queued = args()
        if (queued != [queue_marker, subtask, event, 0] or word(subtask + 12) != context
                or word(uc.reg_read(UC_ARM_REG_SP)) != 0):
            raise RuntimeError('CCD callback did not prepare its zero-payload task event')
        # Explicit unexecuted queue-delivery cut. The dispatcher consumes the
        # native-produced event and zero payload on the same supplied objects.
        put(stack, 0)
        run(0x800057fc, transport_boundary,
            ((UC_ARM_REG_R0, state), (UC_ARM_REG_R1, context),
             (UC_ARM_REG_R2, queued[2]), (UC_ARM_REG_R3, queued[3])))
        expected = [5, route >> 16, ((route & 0xffff) << 8) | event, 0]
        if args() != expected:
            raise RuntimeError('CCD state handler did not prepare the corresponding return operation')
        cases.append({'case': 'native_ccd_completion_route', 'task_event': event,
                      'native_constructor_service_route': '0x10000',
                      'supplied_route': hex(route), 'native_channel_registration_preparation': registration,
                      'queue_arguments': [hex(value) for value in queued],
                      'return_transport_arguments': [hex(value) for value in args()],
                      'incoming_pointer_marker_forwarded_as_payload': False,
                      'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'queue_or_transport_delivery_executed': False,
            'physical_irq_or_register_access_executed': False, 'camera_binding_enabled': False,
            'frame_lease_validated': False,
            'limits': 'Native caller registration continuation, constructor argument '
                      'preparation, CCD callback and separately entered actual task dispatcher. '
                      'Contexts, task/state objects, dynamic-route controls, state zero and incoming markers '
                      'are supplied. Constructor allocation, channel registration/enablement, '
                      'queue delivery and return transport remain unexecuted. Channel 2 is '
                      'a conditional writer branch, not a measured active configuration. '
                      'No relation to EVF event5, completed RAW channel1 pixels, cache '
                      'coherence or buffer lifetime has been established.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
