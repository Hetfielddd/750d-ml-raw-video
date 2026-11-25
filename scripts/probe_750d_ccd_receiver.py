# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace primary ShtCapture callback publication and completion dispatch.

Logger, OS-clear, transport, mode-query and task-queue boundaries remain explicit
cuts. No hardware operation or native helper success is fabricated.
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
                                   UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
                                   UC_ARM_REG_R7, UC_ARM_REG_R11,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    base, owner, holder, config, registry, stack, stop = 0xfe0a0000, 0x100000, 0x101000, 0x102000, 0x103000, 0x10d000, 0x10f000
    global_state, event_handle, queue_marker = 0x2d588, 0x2468ace0, 0x104000
    ranges = ((0xfe13eb2c, 0xfe13eb3c), (0xfe142330, 0xfe14233e),
              (0xfe1ee24a, 0xfe1ee292), (0xfe44303e, 0xfe44305c),
              (0xfe443016, 0xfe44302a), (0xfe1ee0ec, 0xfe1ee0f4),
              (0xfe1ee8f4, 0xfe1ee928), (0xfe1ee2a0, 0xfe1ee2b2),
              (0xfe13e912, 0xfe13e91c), (0xfe13e92a, 0xfe13e938),
              (0xfe142208, 0xfe142214))
    cases = []
    for caller in ('capture_path', 'alternate_path'):
        for operation in (13, 14):
            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
            uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
            uc.mem_write(base, data)
            for address, size in ((owner, 0xe000), (0x26000, 4096), (0x2d000, 4096), (0x51000, 4096)):
                uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

            def put(address, value):
                uc.mem_write(address, struct.pack('<I', value))

            def word(address):
                return struct.unpack('<I', uc.mem_read(address, 4))[0]

            def args():
                return [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]

            def run(entry, target, supplied=(), entry_sp=stack):
                errors, reached = [], []

                def code_guard(emulator, address, size, _):
                    if address == target:
                        reached.append(address)
                        emulator.emu_stop()
                    elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                        errors.append(f'Unexpected primary CCD code: {address:#x}')
                        emulator.emu_stop()

                def write_guard(emulator, access, address, size, value, _):
                    if not (stack - 256 <= address and address + size <= stack + 4
                            or global_state + 4 <= address and address + size <= global_state + 20
                            or (address, size) in ((registry, 4), (registry + 64, 4))):
                        errors.append(f'Unexpected primary CCD write: {address:#x}/{size}')
                        emulator.emu_stop()

                hooks = [uc.hook_add(UC_HOOK_CODE, code_guard), uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)]
                uc.reg_write(UC_ARM_REG_SP, entry_sp)
                uc.reg_write(UC_ARM_REG_LR, stop | 1)
                for register, value in supplied:
                    uc.reg_write(register, value)
                try:
                    uc.emu_start(entry | 1, base + len(data), count=192, timeout=500_000)
                except UcError as error:
                    raise RuntimeError(f'Native primary CCD fault at {uc.reg_read(UC_ARM_REG_PC):#x}') from error
                finally:
                    for hook in hooks:
                        uc.hook_del(hook)
                if errors or reached != [target]:
                    raise RuntimeError(f'Invalid primary CCD stage: {errors}/{reached}')

            put(holder, config)
            put(holder + 36, config)
            put(owner + 8, queue_marker)
            put(owner + 40, 0x1234)
            put(0x26468 + 32, 0x1234)
            put(global_state, event_handle)
            put(0x51e54 + 4, registry)  # Supplied primary service row for destination 1.
            entry = 0xfe13eb2c if caller == 'capture_path' else 0xfe142330
            run(entry, 0xfe1ee24a, ((UC_ARM_REG_R4, owner), (UC_ARM_REG_R11, holder),
                                    (UC_ARM_REG_R7, holder)))
            prepared = args()
            expected_callbacks = ((0xfe13e913, 0xfe13e8bf) if caller == 'capture_path' else
                                  (0xfe142209, 0xfe1421b5))
            if prepared != [config, expected_callbacks[0], owner, expected_callbacks[1]] or word(stack) != owner:
                raise RuntimeError('Actual caller did not prepare the expected capture callbacks')
            # Independently enter the real registration API with native caller
            # values. Preserve its frame across explicit logger and OS-clear cuts.
            run(0xfe1ee24a, 0xfe3ce0fc, tuple(zip(
                (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), prepared)))
            registration_sp = uc.reg_read(UC_ARM_REG_SP)
            run(0xfe1ee264, 0xfe3ce09c, entry_sp=registration_sp)
            run(0xfe1ee270, 0xfe48d25c, entry_sp=uc.reg_read(UC_ARM_REG_SP))
            if ([word(global_state + offset) for offset in (4, 8, 12, 16)] !=
                    [expected_callbacks[0], owner, expected_callbacks[1], owner]
                    or word(registry) != 0xfe1ee0ed or word(registry + 64) != 0
                    or args() != [4, 1, 2, config]):
                raise RuntimeError('Native callback/receiver publication or configuration-send preparation mismatch')
            callback = expected_callbacks[operation - 13] & ~1
            # Separate receive invocation: actual transport is not executed.
            run(0xfe1ee0ec, callback,
                ((UC_ARM_REG_R0, 0), (UC_ARM_REG_R1, operation)))
            if uc.reg_read(UC_ARM_REG_R0) != owner:
                raise RuntimeError('Primary completion did not substitute its registered owner argument')
            receiver_cpu = uc.context_save()
            downstream = None
            if operation == 13:
                # Execute the real callback prefix to its mode-query boundary.
                run(callback, 0xfe3ff59e, entry_sp=uc.reg_read(UC_ARM_REG_SP))
                if uc.reg_read(UC_ARM_REG_R0) != 0x1234:
                    raise RuntimeError('CMOS completion prefix selected an unexpected mode-query argument')
                if caller == 'capture_path':
                    # Separate post-logger slice: native R4/frame retained; no
                    # mode-query or logger return value is consumed by this slice.
                    run(0xfe13e92a, 0xfe43842e, entry_sp=uc.reg_read(UC_ARM_REG_SP))
                    if args() != [queue_marker, owner, 7, 0] or word(uc.reg_read(UC_ARM_REG_SP)) != 0:
                        raise RuntimeError('CMOS completion did not prepare primary task event7')
                    downstream = {'task_event': 7, 'payload': 0, 'queue_operation_executed': False}
            # Independently enter the post-callback continuation using the
            # receiver CPU/frame. This does not pretend its callback returned.
            uc.context_restore(receiver_cpu)
            continuation = 0xfe1ee900 if operation == 13 else 0xfe1ee91a
            run(continuation, 0xfe3cda82, entry_sp=uc.reg_read(UC_ARM_REG_SP))
            expected_mask = 0x1000 if operation == 13 else 0x2000
            if args()[:2] != [event_handle, expected_mask] or uc.reg_read(UC_ARM_REG_SP) != stack:
                raise RuntimeError('Primary completion epilogue prepared the wrong event mask/frame')
            cases.append({'caller': caller, 'operation': operation, 'registered_callback': hex(callback | 1),
                          'registered_argument': hex(owner), 'receiver': '0xfe1ee0ec',
                          'post_callback_signal_mask': hex(expected_mask),
                          'separate_primary_task_preparation': downstream,
                          'callback_finished_or_signal_executed': False, 'passed': True})
        # Two null-callback controls, on the last mapped fixture for this caller.
        run(0xfe1ee2a0, 0xfe1ee2b2)
        if any(word(global_state + offset) for offset in (4, 8, 12, 16)):
            raise RuntimeError('Native CCD clear slice left a callback or argument registered')
        for operation in (13, 14):
            run(0xfe1ee0ec, 0xfe3cda82, ((UC_ARM_REG_R0, 0), (UC_ARM_REG_R1, operation)))
            if (args()[:2] != [event_handle, 0x1000 if operation == 13 else 0x2000]
                    or uc.reg_read(UC_ARM_REG_SP) != stack):
                raise RuntimeError('Null callback did not retain completion event preparation')
        cases.append({'caller': caller, 'case': 'native_callbacks_cleared',
                      'operations_still_prepare_signal': [13, 14], 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'transport_or_os_signal_executed': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Actual caller slices and registration API with explicit logger/OS-clear cuts. '
                      'Primary service row, event handle, owner/parameter objects and mode-query '
                      'argument are supplied. Receive delivery is separately invoked. Actual '
                      'callbacks stop at body/query boundaries; separate post-logger or '
                      'post-callback continuations do not fabricate successful returns. '
                      'No queue, event signal, sensor, DMA, pixel data or EVF association validated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
