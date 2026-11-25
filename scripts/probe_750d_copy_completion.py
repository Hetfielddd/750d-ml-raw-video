# SPDX-License-Identifier: GPL-2.0-or-later
"""Check native copy IRQ cleanup and separately entered status-return slices.

IRQ numbers, status and OS handles are supplied fixtures. Controller addresses
are ordinary RAM. No interrupt delivery, OS operation or DMA is emulated.
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
                                   UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, stack, stop, callback = 0xfe0a0000, 0x10d000, 0x10f000, 0x10f100
    irqs = (0x13e, 0x14e, 0x15e, 0x16e)
    cases = []

    def put(uc, address, values):
        uc.mem_write(address, struct.pack('<' + 'I' * len(values), *values))

    def words(uc, address, count=1):
        return list(struct.unpack('<' + 'I' * count, uc.mem_read(address, count * 4)))

    def make_uc():
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(base, data)
        for address, size in ((0x25000, 4096), (0x40000, 4096), (0x52000, 4096),
                              (0x100000, 0xe000), (0xd6030000, 4096)):
            uc.mem_map(address, size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
        # Distinct neighboring channels make incorrect indexing observable.
        for channel in range(4):
            put(uc, 0x52230 + channel * 28,
                [1, 1 + channel, 5, 3, 9, 0x101020 + channel * 64, 0x101040 + channel * 64])
            put(uc, 0x40834 + channel * 4, [0x24680000 + channel * 4])
            put(uc, 0x40844 + channel * 4, [0x13570000 + channel * 4])
        put(uc, 0x257a4, [0xdeadbeef])
        return uc

    def run(uc, entry, boundaries, ranges, writable):
        reached, errors, writes = [], [], []

        def code_guard(emulator, address, size, _):
            if address in boundaries:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected completion code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not stack - 128 <= address < stack:
                writes.append((address, size, value))
            if not any(lo <= address and address + size <= hi for lo, hi in writable):
                errors.append(f'Unexpected completion write: {address:#x}/{size}')
                emulator.emu_stop()

        hooks = [uc.hook_add(UC_HOOK_CODE, code_guard),
                 uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)]
        try:
            uc.emu_start(entry | 1, base + len(data), count=128, timeout=500_000)
        finally:
            for hook in hooks:
                uc.hook_del(hook)
        if errors or len(reached) != 1:
            raise RuntimeError(f'Invalid completion stage: {errors}/{reached}')
        return reached[0], writes

    def irq_stage(uc, irq, status, with_callback=False):
        channel = irqs.index(irq) if irq in irqs else None
        state = 0x52230 + channel * 28 if channel is not None else 0
        register = 0xd6030030 + channel * 48 if channel is not None else 0
        slot = 0x40854 + channel * 8 if channel is not None else 0
        argument = 0xabcdef00 + (channel or 0)
        before_states = bytes(uc.mem_read(0x52230, 112))
        if channel is not None:
            put(uc, register, [status])
            put(uc, slot, [callback | 1 if with_callback else 0, argument])
        before_globals = bytes(uc.mem_read(0x257a0, 16))
        before_slots = bytes(uc.mem_read(0x40834, 64))
        before_registers = bytes(uc.mem_read(0xd6030000, 4096))
        uc.reg_write(UC_ARM_REG_R0, irq)
        uc.reg_write(UC_ARM_REG_SP, stack)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        writable = [(stack - 128, stack)]
        if channel is not None:
            writable += [(0x257a4, 0x257a8), (register, register + 4),
                         (state, state + 4), (state + 20, state + 28)]
            if with_callback:
                writable += [(slot, slot + 8)]
        reached, writes = run(uc, 0xfe1339b4, (stop, 0xfe3cdd6c, 0xfe3ce08c),
                              ((0xfe1339b4, 0xfe133a36), (0xfe1826ea, 0xfe182700)),
                              writable)
        if channel is None:
            if (reached != stop or writes or uc.reg_read(UC_ARM_REG_SP) != stack
                    or bytes(uc.mem_read(0x52230, 112)) != before_states
                    or bytes(uc.mem_read(0x257a0, 16)) != before_globals
                    or bytes(uc.mem_read(0x40834, 64)) != before_slots
                    or bytes(uc.mem_read(0xd6030000, 4096)) != before_registers):
                raise RuntimeError('Invalid IRQ modified completion state')
            return
        expected_writes = [(0x257a4, 4, status), (register, 4, status & ~15),
                           (state, 4, 0), (state + 20, 4, 0), (state + 24, 4, 0)]
        if with_callback:
            expected_writes += [(slot, 4, 0), (slot + 4, 4, 0)]
        expected_state = bytearray(before_states)
        for offset in (0, 20, 24):
            struct.pack_into('<I', expected_state, channel * 28 + offset, 0)
        expected_handle = (0x13570000 if with_callback else 0x24680000) + channel * 4
        if (reached != (0xfe3ce08c if with_callback else 0xfe3cdd6c)
                or writes != expected_writes
                or words(uc, 0x257a4) != [status]
                or words(uc, register) != [status & ~15]
                or bytes(uc.mem_read(0x52230, 112)) != expected_state
                or uc.reg_read(UC_ARM_REG_R0) != expected_handle
                or uc.reg_read(UC_ARM_REG_SP) != stack - (16 if with_callback else 0)):
            raise RuntimeError('Wrong IRQ cleanup or notification boundary')
        if with_callback:
            if (uc.reg_read(UC_ARM_REG_R5) != callback | 1
                    or uc.reg_read(UC_ARM_REG_R6) != argument
                    or words(uc, slot, 2) != [0, 0]):
                raise RuntimeError('Wrong saved callback or one-shot slot cleanup')
            # Separate continuation entry, NOT a fabricated OS-unlock return.
            reached, writes = run(uc, 0xfe133a2a, (callback,),
                                  ((0xfe133a2a, 0xfe133a34),), ())
            if (reached != callback or writes or uc.reg_read(UC_ARM_REG_R0) != argument
                    or uc.reg_read(UC_ARM_REG_SP) != stack):
                raise RuntimeError('Wrong separately entered callback forwarding')
        elif words(uc, slot, 2) != [0, argument]:
            raise RuntimeError('Null-callback slot unexpectedly modified')

    for channel, irq in enumerate(irqs):
        for low in (0, 1, 8, 15):
            for with_callback in (False, True):
                uc = make_uc()
                status = 0xa5300000 | low
                irq_stage(uc, irq, status, with_callback)
                cases.append({'case': 'irq_cleanup', 'channel': channel, 'irq': hex(irq),
                              'supplied_status': hex(status), 'callback': with_callback,
                              'os_boundary': 'unlock' if with_callback else 'signal',
                              'separate_callback_continuation_checked': with_callback,
                              'passed': True})

    def decode(uc):
        # This is the post-wait instruction slice, not an executed wait.
        uc.reg_write(UC_ARM_REG_R7, 0)
        run(uc, 0xfe133b9a, (0xfe133ba8,), ((0xfe133b9a, 0xfe133ba8),), ())
        return uc.reg_read(UC_ARM_REG_R7)

    for low in range(16):
        uc = make_uc()
        # Feed the decoder status written by the actual IRQ, without host replacement.
        irq_stage(uc, irqs[0], 0xa5300000 | low)
        result = decode(uc)
        if result != (0 if low == 8 else low):
            raise RuntimeError('Wrong native post-wait status mapping')
        cases.append({'case': 'separate_post_wait_decode', 'supplied_low_nibble': low,
                      'native_result': result, 'passed': True})

    for irq in (0, 0x13d, 0x13f, 0xffffffff):
        irq_stage(make_uc(), irq, 0)
        cases.append({'case': 'invalid_irq', 'supplied_irq': hex(irq), 'passed': True})

    uc = make_uc()
    irq_stage(uc, irqs[0], 8)
    first_result = decode(uc)
    irq_stage(uc, irqs[1], 1)
    after_other_channel = decode(uc)
    if (first_result, after_other_channel) != (0, 1):
        raise RuntimeError('Unexpected shared status behavior')
    cases.append({'case': 'separately_invoked_two_channel_status_sequence',
                  'first_channel_result_before_second_irq': first_result,
                  'first_channel_decoder_after_second_irq': after_other_channel,
                  'actual_concurrency_or_os_scheduling_tested': False, 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'irq_handler': '0xfe1339b4', 'shared_status_word': '0x257a4',
            'native_calls_stubbed': False, 'os_operations_executed': False,
            'hardware_irq_delivery_or_dma_executed': False,
            'camera_binding_enabled': False,
            'limits': 'Supplied IRQ numbers, status, channel state, callback and OS handles; '
                      'ordinary RAM at controller addresses, no device/W1C semantics. '
                      'Stops before signal/unlock. Callback continuation and post-wait '
                      'decoder are separately entered reviewed slices, not successful OS '
                      'returns. Zero and eight both map to zero in the return slice; this '
                      'alone cannot qualify hardware completion. Shared status sequence '
                      'does not establish a live race: OS serialization is untested. '
                      'No copied pixels, throughput, cache coherence or source lease proven.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
