# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute native copy semaphore fast paths with supplied kernel objects.

Scoped kernel imports and synthetic semaphore/task state are not a booted OS.
Blocked waits stop before queue/scheduler code; no OS result is fabricated.
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
                                   UC_ARM_REG_R4, UC_ARM_REG_R5,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR,
                                   UC_ARM_REG_CPSR)
    base, stack, stop = 0xfe0a0000, 0x10d000, 0x10f000
    table, task = 0x103000, 0x102000
    handle = (7 << 17) | 2  # Upper wrapper: even tagged handle; generation 7/index 1.
    cases = []
    ranges = ((0xfe3ce08c, 0xfe3ce090), (0xfe3ce0ac, 0xfe3ce0b0),
              (0xfe3cdd6c, 0xfe3cdd76), (0x30b2, 0x315c),
              (0x1bd0, 0x1be0), (0x8000208a, 0x800020f0),
              (0x80003468, 0x8000349a), (0x8000356c, 0x80003608),
              (0x800056dc, 0x800056ec), (0xfe172b84, 0xfe172b9a))

    def put(uc, address, values):
        uc.mem_write(address, struct.pack('<' + 'I' * len(values), *values))

    def word(uc, address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def make_uc(count, irq_mask=0, context_gate=0):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        # Reviewed copy correspondences, not complete boot or scheduler models.
        for runtime, source, size in ((0, 0xfed58b7c, 0x4000),
                                       (0x80000000, 0xfed5c0c8, 0x8000)):
            uc.mem_map(runtime, size, UC_PROT_READ | UC_PROT_EXEC)
            uc.mem_write(runtime, data[source - base:source - base + size])
        for address, size in ((0x4000, 4096), (0x26000, 4096), (0x2a000, 4096),
                              (0x100000, 0xe000)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        put(uc, 0x467c, [1])  # Supplied table capacity.
        put(uc, 0x2615c, [table])
        put(uc, table, [0, 0, count, 1, 0, 7 | (2 << 16)])
        put(uc, 0x44f4, [task])
        put(uc, 0x44f8, [context_gate])
        uc.reg_write(UC_ARM_REG_CPSR, 0x13 | irq_mask)
        return uc

    def run(uc, entry, supplied_handle=handle, timeout=0, extra_ranges=(),
            extra_writable=(), boundaries=(stop, 0x80000960, 0x1e0c),
            extra_registers=(), reset_context=True, local_stack=stack, budget=256):
        reached, errors, trace = [], [], []
        initial_irq_mask = uc.reg_read(UC_ARM_REG_CPSR) & 0x80

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi
                         for lo, hi in ranges + extra_ranges):
                errors.append(f'Unexpected synchronization code: {address:#x}')
                emulator.emu_stop()
            if address in (0x8000208a, 0x800020b2):
                trace.append({'entry': hex(address),
                              'handle': hex(emulator.reg_read(UC_ARM_REG_R0)),
                              'timeout_pointer': hex(emulator.reg_read(UC_ARM_REG_R1))})

        def write_guard(emulator, access, address, size, value, _):
            allowed = ((stack - 1024, stack), (local_stack - 256, local_stack),
                       (table + 8, table + 12),
                       (task + 20, task + 24), (task + 77, task + 78)) + extra_writable
            if not any(lo <= address and address + size <= hi for lo, hi in allowed):
                errors.append(f'Unexpected synchronization write: {address:#x}/{size}')
                emulator.emu_stop()

        hooks = [uc.hook_add(UC_HOOK_CODE, code_guard),
                 uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)]
        if reset_context:
            uc.reg_write(UC_ARM_REG_R0, supplied_handle)
            uc.reg_write(UC_ARM_REG_R1, timeout)
            uc.reg_write(UC_ARM_REG_SP, local_stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
        for register, value in extra_registers:
            uc.reg_write(register, value)
        try:
            uc.emu_start(entry, base + len(data), count=budget, timeout=500_000)
        finally:
            for hook in hooks:
                uc.hook_del(hook)
        if errors or len(reached) != 1:
            raise RuntimeError(f'Invalid synchronization stage: {errors}/{reached}')
        if reached == [stop] and (uc.reg_read(UC_ARM_REG_SP) != local_stack
                                 or uc.reg_read(UC_ARM_REG_CPSR) & 0x80 != initial_irq_mask):
            raise RuntimeError('Synchronization did not restore stack/IRQ mask')
        return reached[0], trace

    for irq_mask in (0, 0x80):
        uc = make_uc(1, irq_mask)
        reached, trace = run(uc, 0xfe3ce0ac)
        if (reached != stop or word(uc, table + 8) != 0
                or uc.reg_read(UC_ARM_REG_R0) != 0
                or trace != [{'entry': '0x800020b2', 'handle': hex(handle >> 1),
                              'timeout_pointer': '0x0'}]):
            raise RuntimeError('Wrong native take fast path')
        reached, _ = run(uc, 0xfe3ce08c)
        if reached != stop or word(uc, table + 8) != 1 or uc.reg_read(UC_ARM_REG_R0) != 0:
            raise RuntimeError('Wrong native give fast path')
        cases.append({'case': 'native_take_then_give', 'supplied_irq_mask': irq_mask,
                      'count_sequence': [1, 0, 1], 'irq_mask_restored': True, 'passed': True})

    uc = make_uc(0)
    reached, trace = run(uc, 0xfe3ce0ac)
    if (reached != 0x80000960 or word(uc, table + 8) != 0xffffffff
            or word(uc, task + 20) != table or bytes(uc.mem_read(task + 77, 1)) != b'\x01'
            or trace[0]['timeout_pointer'] != '0x0'):
        raise RuntimeError('Zero timeout did not reach blocking-wait queue boundary')
    cases.append({'case': 'empty_take_zero_timeout', 'stopped_before': '0x80000960',
                  'native_count': '-1', 'timeout_pointer': '0x0', 'passed': True})

    # The upper give path discards the saturated object's inner error result.
    uc = make_uc(1)
    reached, _ = run(uc, 0xfe3ce08c)
    if reached != stop or word(uc, table + 8) != 1 or uc.reg_read(UC_ARM_REG_R0) != 0:
        raise RuntimeError('Wrong full-object give behavior')
    cases.append({'case': 'give_full_binary_object', 'native_result': 0,
                  'count_remains': 1, 'passed': True})

    for label, supplied_handle in (('zero', 0), ('odd', handle | 1),
                                   ('wrong_generation', handle + (1 << 17)),
                                   ('index_out_of_range', handle + 2)):
        uc = make_uc(1)
        reached, _ = run(uc, 0xfe3ce0ac, supplied_handle)
        if reached != 0x1e0c or word(uc, table + 8) != 1:
            raise RuntimeError('Invalid handle was not rejected before object mutation')
        cases.append({'case': 'invalid_take_handle', 'supplied_kind': label,
                      'stopped_before': '0x1e0c', 'passed': True})

    uc = make_uc(1, context_gate=1)
    reached, _ = run(uc, 0xfe3ce0ac)
    if reached != 0x1e0c or word(uc, table + 8) != 1:
        raise RuntimeError('Context gate did not reject null-timeout take')
    cases.append({'case': 'supplied_context_gate', 'global_44f8': 1,
                  'stopped_before': '0x1e0c', 'passed': True})

    for channel in range(4):
        uc = make_uc(0)
        for address in (0x25000, 0x40000, 0x52000, 0xd6030000):
            uc.mem_map(address, 4096, UC_PROT_READ | UC_PROT_WRITE)
        state = 0x52230 + channel * 28
        register = 0xd6030030 + channel * 48
        put(uc, state, [1, 1, 5, 3, 9, 0x101020, 0x101060])
        put(uc, register, [8])
        put(uc, 0x40834 + channel * 4, [handle])
        reached, _ = run(uc, 0xfe1339b5, 0x13e + channel * 16,
                         extra_ranges=((0xfe1339b4, 0xfe133a36), (0xfe1826ea, 0xfe182700)),
                         extra_writable=((0x257a4, 0x257a8), (register, register + 4),
                                         (state, state + 4), (state + 20, state + 28)))
        if (reached != stop or word(uc, table + 8) != 1
                or word(uc, 0x257a4) != 8 or word(uc, state) != 0):
            raise RuntimeError('Actual copy IRQ did not give supplied completion object')
        reached, _ = run(uc, 0xfe3ce0ac)
        if reached != stop or word(uc, table + 8) != 0:
            raise RuntimeError('Native take did not consume native IRQ signal')
        cases.append({'case': 'actual_irq_to_native_signal_then_take', 'channel': channel,
                      'supplied_status': 8, 'count_sequence': [0, 1, 0], 'passed': True})

    for channel in range(4):
        uc = make_uc(0)
        for address in (0x25000, 0x40000, 0x52000, 0xd6030000):
            uc.mem_map(address, 4096, UC_PROT_READ | UC_PROT_WRITE)
        state = 0x52230 + channel * 28
        register = 0xd6030030 + channel * 48
        slot = 0x40854 + channel * 8
        callback, argument = stop + 0x100, 0xabcdef00 + channel
        put(uc, state, [1, 1, 5, 3, 9, 0x101020, 0x101060])
        put(uc, register, [8])
        put(uc, 0x40844 + channel * 4, [handle])
        put(uc, slot, [callback | 1, argument])
        reached, _ = run(uc, 0xfe1339b5, 0x13e + channel * 16,
                         extra_ranges=((0xfe1339b4, 0xfe133a36), (0xfe1826ea, 0xfe182700)),
                         extra_writable=((0x257a4, 0x257a8), (register, register + 4),
                                         (state, state + 4), (state + 20, state + 28),
                                         (slot, slot + 8)), boundaries=(callback, 0x1e0c))
        if (reached != callback or uc.reg_read(UC_ARM_REG_R0) != argument
                or uc.reg_read(UC_ARM_REG_SP) != stack or word(uc, table + 8) != 1
                or word(uc, slot) != 0 or word(uc, slot + 4) != 0):
            raise RuntimeError('Wrong uninterrupted native IRQ unlock/callback path')
        cases.append({'case': 'actual_irq_native_unlock_to_callback_boundary', 'channel': channel,
                      'lock_count_sequence': [0, 1], 'callback_argument_preserved': True,
                      'callback_executed': False, 'passed': True})

    wrapper_ranges = ((0xfe133acc, 0xfe133ad0), (0xfe133b22, 0xfe133bdc),
                      (0xfe133bdc, 0xfe133dc0), (0xfe133df8, 0xfe133eec),
                      (0xfe1826de, 0xfe182826), (0xfe175500, 0xfe175564),
                      (0xfe3ce0f4, 0xfe3ce0f8), (0xfe3cda0c, 0xfe3cda14),
                      (0x800072c0, 0x80007314), (0xfe22ccde, 0xfe22cce4))
    for scenario in ('zero_size', 'irq_status_8', 'irq_status_1', 'missing_signal', 'stale_signal'):
        uc = make_uc(1)
        for address in (0x25000, 0x40000, 0x52000, 0xd6030000):
            uc.mem_map(address, 4096, UC_PROT_READ | UC_PROT_WRITE)
        # Two synthetic binary objects: channel lock and completion signal.
        put(uc, 0x467c, [2])
        put(uc, table + 24, [0, 0, int(scenario == 'stale_signal'), 1, 0, 7 | (2 << 16)])
        completion_handle = handle + 2
        put(uc, 0x40844, [handle])
        put(uc, 0x40834, [completion_handle])
        put(uc, 0x257a0, [1, 8, 1, 1])
        put(uc, 0xd6030000, [0x10000000])
        put(uc, 0x25774, [0x100000])
        put(uc, 0x100000, [0, 0, 0, 0xffffffff, 4])
        size = 0 if scenario == 'zero_size' else 4096
        # Source/destination remain unmapped. Source reads and copying are absent.
        writable = ((0x52230, 0x5224c), (0xd6030010, 0xd6030028),
                    (table + 32, table + 36))
        reached, _ = run(uc, 0xfe133eb3, 0, 0x5e000000,
                         extra_registers=((UC_ARM_REG_R2, 0x5c62c000), (UC_ARM_REG_R3, size)),
                         extra_ranges=wrapper_ranges, extra_writable=writable,
                         boundaries=(stop, 0xfe133b88, 0x80000960, 0x1e0c), budget=2048)
        if size == 0:
            if (reached != stop or uc.reg_read(UC_ARM_REG_R0) != 0
                    or word(uc, table + 8) != 1 or word(uc, table + 32) != 0
                    or bytes(uc.mem_read(0xd6030010, 28)) != bytes(28)):
                raise RuntimeError('Zero-size wrapper did not skip controller submission')
            cases.append({'case': 'native_wrapper_zero_size', 'native_result': 0,
                          'submission_skipped': True, 'passed': True})
            continue
        if (reached != 0xfe133b88 or word(uc, table + 8) != 0
                or word(uc, 0xd6030014) != 0x5c62c000
                or word(uc, 0xd6030018) != 0x5e000000
                or word(uc, 0xd6030028) != 0):
            raise RuntimeError('Wrong full-wrapper preparation or source/destination order')
        context = uc.context_save()
        if scenario.startswith('irq_'):
            status = 8 if scenario == 'irq_status_8' else 1
            put(uc, 0xd6030030, [status])  # Supplied event status, not DMA completion.
            reached, _ = run(uc, 0xfe1339b5, 0x13e, local_stack=0x10b000,
                             extra_ranges=((0xfe1339b4, 0xfe133a36), (0xfe1826ea, 0xfe182700)),
                             extra_writable=((0x257a4, 0x257a8), (0xd6030030, 0xd6030034),
                                             (0x52230, 0x52234), (0x52244, 0x5224c),
                                             (table + 32, table + 36)))
            if reached != stop or word(uc, table + 32) != 1:
                raise RuntimeError('IRQ did not natively signal the supplied wrapper object')
        # Explicit experiment cut: omit the hardware-start store, restore the
        # saved CPU context and enter its reviewed following instruction.
        # Kernel objects, descriptors, status and other RAM are NOT restored.
        uc.context_restore(context)
        reached, _ = run(uc, 0xfe133b8b, reset_context=False, extra_ranges=wrapper_ranges,
                         extra_writable=writable, budget=2048)
        if scenario == 'missing_signal':
            if (reached != 0x80000960 or word(uc, table + 8) != 0
                    or word(uc, table + 32) != 0xffffffff):
                raise RuntimeError('Wrapper completed without the supplied signal')
            result = 'blocked_before_wait_queue'
        else:
            expected = 1 if scenario == 'irq_status_1' else 0
            if (reached != stop or uc.reg_read(UC_ARM_REG_R0) != expected
                    or word(uc, table + 8) != 1 or word(uc, table + 32) != 0
                    or word(uc, 0xd6030028) != 0):
                raise RuntimeError('Wrong native wrapper completion/result/lock release')
            result = expected
        cases.append({'case': 'native_wrapper_with_explicit_start_cut',
                      'supplied_scenario': scenario, 'native_result': result,
                      'hardware_start_store_omitted': True,
                      'source_register': '0xd6030014', 'destination_register': '0xd6030018',
                      'passed': True})

    for channel in range(4):
        uc = make_uc(0)
        for address in (0x25000, 0x3a000, 0x40000, 0x52000):
            uc.mem_map(address, 4096, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(0x52230, b'\xa5' * 112)
        put(uc, 0x44d8, [432])  # Supplied IRQ-enable bound.
        irq = 0x13e + channel * 16
        row = 0x3a3a0 + irq * 8
        reached, _ = run(uc, 0xfe133a39, channel,
                         extra_ranges=((0xfe133a38, 0xfe133ae2), (0xfe1826a8, 0xfe1826d2),
                                       (0xfe3cdf9c, 0xfe3cdfa0), (0x1774, 0x17a2),
                                       (0x1d8c, 0x1d94), (0x1d94, 0x1d9c),
                                       (0xfe22cd80, 0xfe22cda2), (0xfe172b68, 0xfe172b7e),
                                       (0xfe1c1d78, 0xfe1c1d8e)),
                         extra_writable=((0x52230, 0x522a0), (0x257a8, 0x257ac), (row, row + 8)),
                         boundaries=(0xfe1c1d8e, 0x1e0c), budget=512)
        expected_state = struct.pack('<7I', 0, 2, 0, 2, 0, 0, 0) * 4
        if (reached != 0xfe1c1d8e or word(uc, row) != 0xfe133a37
                or word(uc, row + 4) != irq or word(uc, 0x257a8) != 1
                or word(uc, 0x257a0) != 0
                or bytes(uc.mem_read(0x52230, 112)) != expected_state):
            raise RuntimeError('Wrong channel initialization or native IRQ registration')
        cases.append({'case': 'channel_init_to_irq_enable_boundary', 'channel': channel,
                      'native_irq': hex(irq), 'native_table_row': hex(row),
                      'channel_available_mask_still_zero': True,
                      'physical_irq_enable_executed': False, 'passed': True})

    for already_initialized in (False, True):
        uc = make_uc(0)
        uc.mem_map(0x25000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        put(uc, 0x257ac, [int(already_initialized)])
        writable = ((0x257ac, 0x257b0),)
        if not already_initialized:
            uc.mem_map(0xd6030000, 4096, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_write(0xd6030000, b'\xa5' * 4096)
            writable += ((0xd6030000, 0xd60300c4),)
        reached, _ = run(uc, 0xfe133ae3,
                         extra_ranges=((0xfe133ae2, 0xfe133b22),), extra_writable=writable)
        if reached != stop or word(uc, 0x257ac) != 1:
            raise RuntimeError('Wrong controller initialization guard')
        if not already_initialized:
            expected = bytearray(b'\xa5' * 4096)
            struct.pack_into('<I', expected, 0, 0x10000000)
            for channel in range(4):
                for offset in range(16, 49, 4):
                    struct.pack_into('<I', expected, channel * 48 + offset, 0)
            if bytes(uc.mem_read(0xd6030000, 4096)) != expected:
                raise RuntimeError('Wrong artificial controller initialization writes')
        cases.append({'case': 'controller_init', 'supplied_already_initialized': already_initialized,
                      'controller_is_artificial_ram': not already_initialized, 'passed': True})

    uc = make_uc(0)
    uc.mem_map(0x5000, 4096, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(0x5028, b'\xa5' * 64)
    reached, _ = run(uc, 0xfe0cdeb5, extra_registers=((UC_ARM_REG_R4, 0x11223344),),
                     extra_ranges=((0xfe0cdeb4, 0xfe0cdec2), (0xfe448aac, 0xfe448acc)),
                     extra_writable=((0x5028, 0x5068), (stack, stack + 4)),
                     boundaries=(0xfe3ce0b4,))
    if reached != 0xfe3ce0b4 or word(uc, 0x5050) != 0:
        raise RuntimeError('Native property initialization did not select channel zero')
    put(uc, 0x104018, [0x5e000000])
    reached, _ = run(uc, 0xfe4466ef, 4096,
                     extra_registers=((UC_ARM_REG_R4, 0x104000), (UC_ARM_REG_R5, 0x5c62c000)),
                     extra_ranges=((0xfe4466ee, 0xfe4466fc),), boundaries=(0xfe133eb2,))
    if (reached != 0xfe133eb2 or [uc.reg_read(r) for r in
            (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            != [0, 0x5e000000, 0x5c62c000, 4096]):
        raise RuntimeError('Wrong property caller arguments or initialized channel')
    cases.append({'case': 'property_init_and_separate_copy_caller',
                  'native_selected_channel': 0, 'camera_property_path_executed_fully': False,
                  'camera_channel_zero_exclusive': False, 'passed': True})

    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'native_calls_stubbed': False, 'native_semaphore_fast_paths_executed': True,
            'scheduler_or_wait_queue_executed': False,
            'hardware_irq_delivery_or_dma_executed': False, 'camera_binding_enabled': False,
            'limits': 'Artificial kernel object table, generation-tagged handles, current task, '
                      'context globals, controller RAM and directly invoked IRQs. Scoped '
                      'primary low/high kernel imports, not full boot or a running OS. '
                      'Native CPSR save/mask/restore executes in the emulator only. '
                      'Empty wait stops before queue/scheduler; assertion paths stop before '
                      'logger. Wrapper sequences explicitly omit the hardware-start store '
                      'and restore a saved CPU context after an independently invoked IRQ; '
                      'RAM retains native effects. Classifier flag4 is supplied and native '
                      'DSB executes without a cache/coherence model. No successful OS return '
                      'is fabricated. No scheduling, blocked-task '
                      'wakeup, real completion, cache coherence or source lease established.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
