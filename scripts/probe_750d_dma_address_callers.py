# SPDX-License-Identifier: GPL-2.0-or-later
"""Replay native DMA-address callers and the RAW/SAF Live View teardown boundary."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from decrypt_750d_fir import MAIN_SHA256


def probe(data):
    if len(data) != 0xcfb688 or hashlib.sha256(data).hexdigest() != MAIN_SHA256:
        raise ValueError('Expected the identified 750D 1.1.0 main-code record')
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ,
                         UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
                                   UC_ARM_REG_R5, UC_ARM_REG_CPSR, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, delta, low_source = 0xfe0a0000, 0x7e7473e0, 0xfe744d60
    params, stack, stop = 0x100000, 0x10cfe0, 0x10f000
    raw, saf, trigger = 0x1ac2220, 0x1ac22d0, 0xd0008090
    logger, wait_veneer, saf_stop_next = 0xfe8a48cc, 0xfe86f758, 0xfe920334
    address_a, address_b = 0x1c62c100, 0x1e004000
    register_a, register_b = 0xd0004108, 0xd0004208
    callers = ((0xfe822560, 0x1ac1808, 0xfe8225ac, 0xfe8225b4),
               (0xfe822c46, 0x1ac1870, 0xfe822c9e, 0xfe822ca6))
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    rx, rw = UC_PROT_READ | UC_PROT_EXEC, UC_PROT_READ | UC_PROT_WRITE
    uc.mem_map(base, (len(data) + 4095) & ~4095, rx)
    uc.mem_write(base, data)
    for page, source in ((0, low_source),) + tuple(
            (page, page + delta) for page in (0x80003000, 0x80007000, 0x8000c000,
                                             0x8000d000, 0x8000f000)):
        uc.mem_map(page, 4096, rx)
        uc.mem_write(page, data[source - base:source - base + 4096])
    for page in (params, stack & ~4095, 0x1ac1000, 0x1ac2000, 0x1ac4000,
                 0x208000, 0xd0004000, 0xd0008000):
        uc.mem_map(page, 4096, rw)
    uc.mem_map(stop, 4096, rx)

    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def args():
        return [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3)]

    def fifth():
        return word(uc.reg_read(UC_ARM_REG_SP))

    ranges = ((0xfe822560, 0xfe82257a), (0xfe822c46, 0xfe822c60),
              (0xfe8225ac, 0xfe8225b4), (0xfe822c9e, 0xfe822ca6),
              (0xfe839690, 0xfe8396b0), (0xfe83a724, 0xfe83a752), (0xfe83a78a, 0xfe83a78c),
              (0xfe83a23e, 0xfe83a246), (0xfe83a4b2, 0xfe83a4b6), (0xfe8255ba, 0xfe8255ce),
              (0xfe86f5f0, 0xfe86f5f4), (0xfe86f890, 0xfe86f894), (0xfe86f910, 0xfe86f920),
              (0x80003d22, 0x80003d2a), (0x80007bc4, 0x80007bce),
              (0x80007b7e, 0x80007b88), (0x44c, 0x470),
              (0x8000c426, 0x8000c434), (0x8000c442, 0x8000c446), (0x8000dc3e, 0x8000dc54))
    allowed_writes = {saf + 36, saf + 40, trigger, 0x208090} | {owner + 32 for _, owner, _, _ in callers}
    boundary, reached, errors, reads, writes = stop, [], [], [], []

    def code_guard(emulator, address, width, _):
        if address == boundary:
            reached.append(address)
            emulator.emu_stop()
        elif not any(lo <= address and address + width <= hi for lo, hi in ranges):
            errors.append(f'Unexpected code {address:#x}')
            emulator.emu_stop()

    def read_guard(emulator, _access, address, width, _value, _):
        if 0xd0000000 <= address < 0xe0000000:
            if width != 4 or address not in (register_a, register_b):
                errors.append(f'Unexpected register read {address:#x}/{width}')
                emulator.emu_stop()
            reads.append(hex(address))

    def write_guard(emulator, _access, address, width, value, _):
        if stack - 128 <= address and address + width <= stack + 4:
            return
        if width != 4 or address not in allowed_writes:
            errors.append(f'Unexpected write {address:#x}/{width}')
            emulator.emu_stop()
        writes.append([hex(address), hex(value)])

    for hook, guard in ((UC_HOOK_CODE, code_guard), (UC_HOOK_MEM_READ, read_guard),
                        (UC_HOOK_MEM_WRITE, write_guard)):
        uc.hook_add(hook, guard)

    def run(entry, target, supplied=(), *, fresh=True):
        nonlocal boundary
        boundary = target
        for items in (reached, reads, writes):
            items.clear()
        if fresh:
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
        for reg, value in supplied:
            uc.reg_write(reg, value)
        uc.emu_start(entry | 1, base + len(data), count=160, timeout=500_000)
        if errors or reached != [target]:
            raise RuntimeError(f'{entry:#x} failed to reach {target:#x}: {errors}/{reached}')

    uc.reg_write(UC_ARM_REG_CPSR, 0x13)
    put(0x1ac40a4, 0x200000)
    wait_cases, sampling_cases = [], []
    for entry, owner, tail, continuation in callers:
        put(owner + 36, 0x12345678)
        run(entry, wait_veneer)
        if (args()[:3] != [0x12345678, 0x7f, 0] or reads or word(owner + 32) != 1
                or uc.reg_read(UC_ARM_REG_CPSR) & 0x80):
            raise RuntimeError('Wrong teardown flag, native mask restoration or wait arguments')
        wait_cases.append({'source': hex(entry), 'wait_mask': '0x7f', 'wait_executed': False})

        for saf_enabled, raw_enabled, swap in ((0, 1, False), (1, 0, False), (1, 1, True)):
            # Independent local publication slices skip other SAF setup calls.
            channels = (2, 1) if swap else (1, 2)
            put(params + 4, channels[0])
            put(params + 16, channels[1])
            for start, end in ((0xfe83a23e, 0xfe83a246), (0xfe83a4b2, 0xfe83a4b6)):
                run(start, end, ((UC_ARM_REG_R4, params), (UC_ARM_REG_R5, saf)))
            if [word(saf + offset) for offset in (36, 40)] != list(channels):
                raise RuntimeError('SAF channel indices were not published by the real setup slices')
            put(saf, saf_enabled)
            put(raw, raw_enabled)
            put(raw + 24, 0)  # Reviewed non-alternate RAW path.
            put(raw + 36, 0x5c62c000)
            put(trigger, 0)
            put(register_a, address_a)
            put(register_b, address_b)
            # Teardown tail is a separate slice after the unexecuted wait and
            # intervening cleanup calls. No successful wait return is supplied.
            run(tail, logger if saf_enabled else continuation)
            channel_register = {1: register_a, 2: register_b}
            expected_reads = [hex(channel_register[ch]) for ch in reversed(channels)] if saf_enabled else []
            expected_trigger = 0x80000000 if raw_enabled else 0
            expected_writes = [[hex(address), hex(expected_trigger)]
                               for address in (0x208090, trigger)] if raw_enabled else []
            if (reads != expected_reads or writes != expected_writes
                    or word(trigger) != expected_trigger or word(raw + 36) != 0x5c62c000):
                raise RuntimeError('Wrong RAW trigger change or SAF register reads')
            case = {'source': hex(tail), 'raw_initialized': bool(raw_enabled),
                    'saf_initialized': bool(saf_enabled), 'saf_channels': list(channels),
                    'register_reads': reads.copy(), 'raw_trigger_after': hex(word(trigger))}
            if saf_enabled:
                first, second = ((address_b, address_a) if swap else (address_a, address_b))
                if args() != [0x98, 1, 0xfe83aa3c, first] or fifth() != second:
                    raise RuntimeError('Native SAF stop logger did not receive sampled addresses')
                case['logger_address_words'] = [hex(first), hex(second)]
                run(0xfe83a74c, saf_stop_next, fresh=False)
                if args()[0] != 2 or reads or writes:
                    raise RuntimeError('Wrong SAF post-logger continuation')
            sampling_cases.append(case)

    run(0xfe8255ba, logger)
    if reads != [hex(register_a)] or writes or args() != [0x92, 3, 0xfe8256f0, 1] or fifth() != address_a:
        raise RuntimeError('Wrong native channel-1 Image2 diagnostic argument')
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'teardown_wait_requests': wait_cases,
            'teardown_tail_cases': sampling_cases,
            'image_diagnostic': {'register_reads': reads, 'logger_address_word': hex(fifth())},
            'native_calls_stubbed': False, 'live_frame_completion_validated': False,
            'camera_binding_enabled': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
