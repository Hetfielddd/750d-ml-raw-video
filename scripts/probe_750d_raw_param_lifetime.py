# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace native RAW parameter pointers across explicit transport/queue cuts.

No mailbox FIFO, queue delivery or DMA is simulated. Native registration,
dispatch and separately entered consumer slices retain actual memory effects.
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
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
                                   UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                                   UC_ARM_REG_R8, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    base, app_delta, driver_delta = 0xfe0a0000, 0xfcc82368, 0x7e7473e0
    task, subtask, first, second = 0x100000, 0x101000, 0x102000, 0x103000
    service, context, config, feature = 0x104000, 0x105000, 0x106000, 0x107000
    counter, stateobj, stack, stop, shadow = 0x108000, 0x109000, 0x10d000, 0x10f000, 0x200000
    queueobj, envelope = 0x10a000, 0x10b000
    peer, register = 0x1ac2220, 0xd0004108
    queue_boundary = 0xfe86f740 - app_delta
    postman_row = 0x1acdd8c + 2 * 88 + 2 * 8
    cases = []
    ranges = ((0xfe28d9d6, 0xfe28da36), (0xfe380766, 0xfe380772),
              (0xfe3807a0, 0xfe3807b8), (0xfe443016, 0xfe44302a),
              (0xfe3806fe, 0xfe380706), (0xfe3807b8, 0xfe3807ba),
              (0xfe48d2aa, 0xfe48d2bc), (0xfe74ee70, 0xfe74ee9e),
              (0xfe86fc06, 0xfe86fc44), (0xfe74ea86, 0xfe74ea9a),
              (0xfe74ea9c, 0xfe74eac2),
              (0xfe86fb88 - app_delta, 0xfe86fba8 - app_delta),
              (0xfe806384 - app_delta, 0xfe8063a0 - app_delta),
              (0xfe86fb30 - app_delta, 0xfe86fb4a - app_delta),
              (0xfe86faba, 0xfe86fac8),
              (0xfe8063a0 - app_delta, 0xfe8063b6 - app_delta),
              (0xfe86f728 - app_delta, 0xfe86f72c - app_delta),
              (0x800057fc, 0x80005886),
              (0xfe80fdf4 - app_delta, 0xfe80fe02 - app_delta),
              (0xfe80fdae - app_delta, 0xfe80fdc2 - app_delta),
              (0xfe80fe02 - app_delta, 0xfe80fe10 - app_delta),
              (0xfe86f298 - app_delta, 0xfe86f29c - app_delta),
              (0x80009b20, 0x80009b28), (0xfe750f2c, 0xfe750f3a),
              (0xfe74f130, 0xfe74f134), (0x1bb7348, 0x1bb7366),
              (0xfe8395c4, 0xfe839642), (0xfe86f858, 0xfe86f85c),
              (0x8000c654, 0x8000c67e), (0x8000c5fe, 0x8000c654),
              (0x8000c426, 0x8000c434), (0xfe74ce9e, 0xfe74ced2))

    for scenario in ('unchanged_block', 'same_block_republished', 'separate_block_prepared',
                     'native_service_unregistered', 'start_operation', 'operation_five'):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for runtime, delta in ((0x1b84000, app_delta), (0x1b8d000, app_delta),
                               (0x1bec000, app_delta), (0x1bed000, app_delta), (0x1cf1000, app_delta),
                               (0x1cf2000, app_delta), (0x1bb7000, app_delta),
                               (0x80005000, driver_delta), (0x80009000, driver_delta),
                               (0x8000a000, driver_delta),
                               (0x8000c000, driver_delta), (0x8000f000, driver_delta)):
            uc.mem_map(runtime, 4096, UC_PROT_READ | UC_PROT_EXEC)
            offset = runtime + delta - base
            uc.mem_write(runtime, data[offset:offset + 4096])
        for address, size in ((task, 0xe000), (0x1ac0000, 0x10000),
                              (0x1ad8000, 4096), (shadow, 0x60000), (0xd0004000, 4096)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        def args():
            return [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]

        def run(entry, boundaries, supplied=(), forbid_parameter_reads=False):
            reached, errors = [], []

            def code_guard(emulator, address, size, _):
                if address in boundaries:
                    reached.append(address)
                    emulator.emu_stop()
                elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                    errors.append(f'Unexpected parameter-path code: {address:#x}')
                    emulator.emu_stop()

            def write_guard(emulator, access, address, size, value, _):
                writable = ((stack - 256, stack), (first, first + 0x120),
                            (second, second + 0x120), (context, context + 12),
                            (service + 8, service + 12), (service + 72, service + 76),
                            (postman_row, postman_row + 8), (subtask + 12, subtask + 16),
                            (counter, counter + 1), (stateobj + 28, stateobj + 32),
                            (peer + 36, peer + 40), (peer + 44, peer + 48),
                            (envelope, envelope + 16),
                            (shadow + 0x4108, shadow + 0x410c), (register, register + 4))
                if not any(lo <= address and address + size <= hi for lo, hi in writable):
                    errors.append(f'Unexpected parameter-path write: {address:#x}/{size}')
                    emulator.emu_stop()

            def read_guard(emulator, access, address, size, value, _):
                if forbid_parameter_reads and any(address < hi and address + size > lo
                                                  for lo, hi in ((first, first + 0x120),
                                                                 (second, second + 0x120))):
                    errors.append('Queue-envelope stage unexpectedly read parameter contents')
                    emulator.emu_stop()

            hooks = [uc.hook_add(UC_HOOK_CODE, code_guard), uc.hook_add(UC_HOOK_MEM_WRITE, write_guard),
                     uc.hook_add(UC_HOOK_MEM_READ, read_guard)]
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
            for r, value in supplied:
                uc.reg_write(r, value)
            try:
                uc.emu_start(entry | 1, base + len(data), count=256, timeout=500_000)
            except UcError as error:
                raise RuntimeError(f'{scenario}: native fault at {uc.reg_read(UC_ARM_REG_PC):#x}') from error
            finally:
                for hook in hooks:
                    uc.hook_del(hook)
            if errors or len(reached) != 1:
                raise RuntimeError(f'{scenario}: invalid parameter stage: {errors}/{reached}')
            if reached == [stop] and uc.reg_read(UC_ARM_REG_SP) != stack:
                raise RuntimeError('Native parameter helper did not restore stack')
            return reached[0]

        def prepare(block, address):
            put(config + 80, address)
            put(config + 140, 1)
            for offset, value in ((124, 34), (128, 0), (132, 2048), (136, 1080)):
                put(config + offset, value)
            put(block + 204, 34)  # Separate packing marker; outside the reviewed producer slice.
            run(0xfe28d9d6, (0xfe28da36,), ((UC_ARM_REG_R4, config), (UC_ARM_REG_R1, block),
                                         (UC_ARM_REG_R7, feature), (UC_ARM_REG_R8, 0)))
            if word(block + 200) != address or word(block + 144) != 1:
                raise RuntimeError('Wrong native parameter address/channel production')

        put(context, subtask)
        put(context + 4, stateobj)
        put(context + 8, 0x20002)
        put(peer, 1)  # Supplied initialized/non-alternate RAW channel state.
        put(peer + 28, 1)
        put(subtask, task)
        put(subtask + 8, (0xfe8063a0 - app_delta) | 1)
        put(task, queueobj)  # Supplied task-queue object; underlying OS queue is not executed.
        signature_pointer = struct.unpack_from('<I', data, 0xfe74cf9c - base)[0]
        put(queueobj, word(signature_pointer))
        put(queueobj + 16, 0x2468ace0)
        signature = struct.unpack_from('<I', data, 0xfe756b40 - base)[0]
        uc.mem_write(stateobj, struct.pack('<8I', signature, 0, 0, 0x8000581b, 0x1cf2190, 8, 1, 0))
        put(0x1accbb8 + 2 * 4, service)
        # Supplied receive-channel map: physical channel 4 -> logical row 2.
        uc.mem_write(0x1ac083c, b'\xff' * 8)
        uc.mem_write(0x1ac083c + 4, b'\x02')
        callback = struct.unpack_from('<I', data, 0xfe8064ac - base)[0]
        generic = struct.unpack_from('<I', data, 0xfe86fc54 - base)[0]
        run(0xfe86fc06, (stop,), ((UC_ARM_REG_R0, callback), (UC_ARM_REG_R1, context),
                                (UC_ARM_REG_R2, 0x20002)))
        run(0xfe74ee70, (stop,), ((UC_ARM_REG_R0, generic), (UC_ARM_REG_R1, service),
                                (UC_ARM_REG_R2, 4), (UC_ARM_REG_R3, 2)))
        if word(service + 8) != callback or word(service + 72) != context or word(postman_row) != generic:
            raise RuntimeError('Native service/Postman registration mismatch')
        if scenario == 'native_service_unregistered':
            run(0xfe86fc24, (stop,), ((UC_ARM_REG_R0, 0x20002),))
        a, b = 0x5c62c000, 0x5e000000
        prepare(first, a)
        initial_geometry = bytes(uc.mem_read(first + 144, 36))
        operation = 2 if scenario == 'start_operation' else 5 if scenario == 'operation_five' else 4
        entry = {2: 0xfe380766, 4: 0xfe3807a0, 5: 0xfe3807ac}[operation]
        run(entry, (0xfe48d25c,), ((UC_ARM_REG_R0, first),))
        sent = args()
        if sent != [4, 2, 0x200 | operation, first]:
            raise RuntimeError('Wrong native sender arguments')
        run(0xfe48d2aa, (0xfe48d2bc,), ((UC_ARM_REG_R4, counter), (UC_ARM_REG_R5, sent[0]),
                                      (UC_ARM_REG_R6, sent[1]), (UC_ARM_REG_R7, sent[2]),
                                      (UC_ARM_REG_R8, sent[3])))
        header, payload = uc.reg_read(UC_ARM_REG_R7), uc.reg_read(UC_ARM_REG_R8)
        if header != 0x02000200 | operation or payload != first:
            raise RuntimeError('Wrong native command packing or original payload pointer')
        # Explicit cut after the unexecuted FIFO header load; validate header.
        run(0xfe74ea86, (0xfe74ea9a,), ((UC_ARM_REG_R4, header),))
        # Explicit cut after the unexecuted FIFO payload load, preserving native
        # sender values. No mailbox store/read or hardware delivery is claimed.
        target = 0xfe74eac2 if scenario == 'native_service_unregistered' else queue_boundary
        run(0xfe74ea9c, (target,), ((UC_ARM_REG_R4, header), (UC_ARM_REG_R2, payload),
                                  (UC_ARM_REG_R7, 4)))
        if scenario == 'native_service_unregistered':
            if word(subtask + 12) != 0 or word(service + 8) or word(service + 72):
                raise RuntimeError('Unregistered service unexpectedly prepared queue delivery')
            cases.append({'case': scenario, 'native_queue_boundary_reached': False, 'passed': True})
            continue
        queued = args()
        if (queued != [queueobj, subtask, operation, first]
                or word(subtask + 12) != context or word(uc.reg_read(UC_ARM_REG_SP)) != 0):
            raise RuntimeError('Wrong native operation/event or parameter-pointer forwarding')
        queued_extra = word(uc.reg_read(UC_ARM_REG_SP))
        put(stack, queued_extra)
        run(0xfe74ce9e, (0xfe74f95c,),
            tuple(zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), queued)),
            forbid_parameter_reads=True)
        if uc.reg_read(UC_ARM_REG_R0) != 16 or uc.reg_read(UC_ARM_REG_R8) != first:
            raise RuntimeError('Queue request did not request a sixteen-byte envelope')
        # Separate post-allocation slice with supplied scratch storage. The
        # allocator is not run, returned from, or replaced by a success stub.
        run(0xfe74cec4, (0xfe74ff10,), ((UC_ARM_REG_R0, envelope),), forbid_parameter_reads=True)
        enqueued = [word(envelope + i * 4) for i in range(4)]
        if enqueued != [subtask, operation, first, queued_extra] or args()[:2] != [0x2468ace0, envelope]:
            raise RuntimeError('Wrong native queue envelope or copied payload pointer')
        if scenario == 'same_block_republished':
            prepare(first, b)
        elif scenario == 'separate_block_prepared':
            prepare(second, b)
        # Explicit queue-delivery cut: native worker consumes the association
        # written by the request helper. No queue is run or returns fabricated.
        expected_boundary = (0xfe751c9c - driver_delta if operation == 4 else
                             0xfe86f290 - app_delta if operation == 2 else 0xfe86f2a0 - app_delta)
        reached = run(0xfe86faba, (expected_boundary,),
                      ((UC_ARM_REG_R0, enqueued[0]), (UC_ARM_REG_R1, enqueued[1]),
                       (UC_ARM_REG_R2, enqueued[2]), (UC_ARM_REG_R3, enqueued[3])))
        if reached != expected_boundary or word(stateobj + 28) != 0:
            raise RuntimeError('Wrong actual task worker/state-table dispatch')
        if operation != 4:
            cases.append({'case': scenario, 'native_operation_and_event': operation,
                          'payload_pointer': hex(queued[3]), 'stopped_before': hex(reached), 'passed': True})
            continue
        if uc.reg_read(UC_ARM_REG_R4) != queued[3] or uc.reg_read(UC_ARM_REG_R0) != queued[3]:
            raise RuntimeError('Native driver prefix did not receive original queued pointer')
        # Separate RAW-tail entry: earlier/later component updates are unexecuted.
        run(0xfe750f2c, (0xfe750f3a,), ((UC_ARM_REG_R4, uc.reg_read(UC_ARM_REG_R4) + 208),))
        expected = b if scenario == 'same_block_republished' else a
        if word(peer + 36) != expected or word(peer + 44) != 34:
            raise RuntimeError('RAW pending state did not reflect the consumed parameter block')
        put(0x1ac40a4, shadow)
        geometry = (1079 << 16) | 3584
        put(0xd0004110, geometry)
        put(shadow + 0x4110, geometry)
        run(0xfe8395c4, (0xfe86f878,))
        if (word(register) != expected & 0x3fffffff or word(shadow + 0x4108) != expected & 0x3fffffff
                or word(0xd0004110) != geometry or word(shadow + 0x4110) != geometry
                or bytes(uc.mem_read(first + 144, 36)) != initial_geometry):
            raise RuntimeError('Wrong native destination or changed supplied geometry')
        cases.append({'case': scenario, 'native_operation_and_event': operation,
                      'original_payload_pointer': hex(first), 'queued_payload_pointer': hex(queued[3]),
                      'native_envelope_bytes': 16, 'parameter_contents_read_by_envelope_stages': False,
                      'first_prepared_address': hex(a), 'consumed_pending_address': hex(expected),
                      'prepared_dma_address': hex(word(register)),
                      'supplied_geometry_unchanged_in_reviewed_address_path': True,
                      'channel_start_executed': False, 'passed': True})
    # Reuse the last mapped fixture solely for two independently entered
    # primary return checks. Operations 4/5 select the existing BX LR leaf,
    # rather than the semaphore-signaling operation-3 return handler.
    for operation in (4, 5):
        reached = run(0xfe3806fe, (stop,), ((UC_ARM_REG_R0, 0x12345678), (UC_ARM_REG_R1, operation)))
        if reached != stop or uc.reg_read(UC_ARM_REG_R0) != 0x12345678:
            raise RuntimeError('Unexpected primary configuration-return dispatch')
        cases.append({'case': 'primary_return_dispatch_leaf', 'operation': operation,
                      'semaphore_signal_executed': False, 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'native_registration_and_dispatch_executed': True,
            'mailbox_or_queue_delivery_executed': False, 'channel_start_or_dma_executed': False,
            'camera_binding_enabled': False, 'frame_lease_validated': False,
            'limits': 'Supplied task/context/state objects, queue handle, receive-channel map '
                      'and separately entered stage order. Native sender values are passed '
                      'across explicit unexecuted mailbox loads/stores and queue-delivery '
                      'cuts. Queue wrapper checks its supplied object and reaches the '
                      'allocator boundary; a separate post-allocation envelope slice uses '
                      'supplied scratch storage, not a fabricated allocator return. Actual '
                      'allocation, enqueue/dequeue and scheduler do not execute. Driver RAW '
                      'tail is separately entered past unexecuted other '
                      'component configuration calls. Actual parameter RAM is retained, not '
                      'deep-copied or replaced between stages except the named native '
                      'republication fixtures. Artificial register RAM and supplied channel '
                      'state/classifier/geometry. No hardware timing, cross-core visibility, '
                      'allocation, completed pixels or ownership demonstrated.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
