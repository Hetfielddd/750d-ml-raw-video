# SPDX-License-Identifier: GPL-2.0-or-later
"""Check how a Canon IPC diagnostic uses the same channel as the RAW writer."""
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
                                   UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                                   UC_ARM_REG_R8, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, stack, halt = 0xfe0a0000, 0x10cfe0, 0x10f000
    channel, tx, route = 0xd0004100, 0xd0030900, 0xd0005004
    logger, delay = 0xfe3ce0fc, 0xfe3ce104
    start, size = 0x1c62c000, 4097
    arg_regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(base, data)
    uc.mem_map(halt, 4096, UC_PROT_READ | UC_PROT_EXEC)
    for page in (stack & ~4095, channel & ~4095, tx & ~4095, route & ~4095):
        uc.mem_map(page, 4096, UC_PROT_READ | UC_PROT_WRITE)

    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def args():
        return [uc.reg_read(register) for register in arg_regs]

    def fifth():
        return word(uc.reg_read(UC_ARM_REG_SP))

    ranges = ((0xfe1898c4, 0xfe1898d8), (0xfe218a4a, 0xfe218a64),
              (0xfe218a66, 0xfe218a80), (0xfe2185bc, 0xfe218654),
              (0xfe218426, 0xfe218498), (0xfe2183ce, 0xfe2183d2))
    boundaries, reached, errors, reads, writes = (), [], [], [], []

    def code_guard(emulator, address, width, _):
        if address in boundaries:
            reached.append(address)
            emulator.emu_stop()
        elif not any(lo <= address and address + width <= hi for lo, hi in ranges):
            errors.append(f'Unexpected instruction {address:#x}')
            emulator.emu_stop()

    def read_guard(emulator, _access, address, width, _value, _):
        if not 0xd0000000 <= address < 0xe0000000:
            return
        if width != 4 or address not in (channel + 8, channel + 0x30, tx + 8, tx + 0x30):
            errors.append(f'Unexpected register read {address:#x}/{width}')
            emulator.emu_stop()
        reads.append(address)

    def write_guard(emulator, _access, address, width, value, _):
        if stack - 128 <= address and address + width <= stack + 4:
            return
        if width != 4 or not (channel <= address <= channel + 0x28 or address == route):
            errors.append(f'Unexpected write {address:#x}/{width}')
            emulator.emu_stop()
        writes.append([hex(address), hex(value)])

    for event, guard in ((UC_HOOK_CODE, code_guard), (UC_HOOK_MEM_READ, read_guard),
                         (UC_HOOK_MEM_WRITE, write_guard)):
        uc.hook_add(event, guard)

    def run(entry, target, supplied=(), *, fresh=False):
        nonlocal boundaries
        boundaries = (target,)
        reached.clear()
        reads.clear()
        writes.clear()
        if fresh:
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, halt | 1)
        for reg, value in supplied:
            uc.reg_write(reg, value)
        uc.emu_start(entry | 1, base + len(data), count=96, timeout=500_000)
        if errors or reached != [target]:
            raise RuntimeError(f'{entry:#x} failed to reach {target:#x}: {errors}/{reached}')

    dumps = []
    for site, label, handler, registers, summary in (
            (0xfe1898c4, 0xfe189928, 0xfe218a4a, channel, 0xfe218b0c),
            (0xfe1898ce, 0xfe189938, 0xfe218a66, tx, 0xfe218b30)):
        run(site, 0xfe4431ea, fresh=True)
        if args()[:3] != [label, 0, handler | 1]:
            raise RuntimeError('Wrong diagnostic command registration arguments')
        put(registers + 0x30, 0x123)
        put(registers + 8, start + 4096)
        run(handler, logger, fresh=True)
        if (reads != [registers + 0x30, registers + 8] or writes
                or args() != [0, 6, summary, 0x123] or fifth() != start + 4096):
            raise RuntimeError('Wrong diagnostic hardware-register sampling')
        dumps.append({'command': 'ipcRecvDump' if registers == channel else 'ipcSendDump',
                      'register_reads': list(map(hex, reads)), 'passed': True})

    poll_cases = []
    for phase, entry, accepted, retry_pc, log_string in (
            (1, 0xfe2185bc, 0xfe2185e4, 0xfe2185dc, 0xfe2188a8),
            (2, 0xfe21861c, 0xfe218642, 0xfe21863a, 0xfe218818)):
        for status, pointer in ((2, start), (2, start + 8192), (0, start + 8192),
                                (4, start + 8192), (6, start + 8192), (0x102, start + 8192)):
            put(channel + 0x30, status)
            put(channel + 8, pointer)
            run(entry, accepted if status == 2 else logger,
                ((UC_ARM_REG_R5, 1), (UC_ARM_REG_R7, 0xd0004000)), fresh=True)
            expected_reads = [channel + 0x30] if status == 2 else [channel + 0x30, channel + 8]
            if reads != expected_reads or writes != [[hex(channel), '0x1']]:
                raise RuntimeError('Wrong native channel status poll')
            if status != 2:
                if args() != [0, 2, log_string, status] or fifth() != pointer:
                    raise RuntimeError('Wrong waiting diagnostic arguments')
                run(retry_pc, delay)
                if args()[0] != 100 or reads or writes:
                    raise RuntimeError('Unaccepted status did not reach the native retry delay')
            poll_cases.append({'phase': phase, 'supplied_status': hex(status),
                               'supplied_address_word': hex(pointer),
                               'status_accepted': status == 2,
                               'register_reads': list(map(hex, expected_reads)), 'passed': True})

    configurations = []
    for count in (4096, size):
        # A separately entered success continuation after the first poll/logger.
        run(0xfe2185ee, logger, ((UC_ARM_REG_R4, count), (UC_ARM_REG_R5, 1),
                                (UC_ARM_REG_R6, start), (UC_ARM_REG_R7, 0xd0004000)), fresh=True)
        rows = (count + 4095) // 4096
        if args() != [0, 2, 0xfe218780, start] or fifth() != 4096 or word(uc.reg_read(UC_ARM_REG_SP) + 4) != rows:
            raise RuntimeError('Wrong native IPC receive configuration arguments')
        run(0xfe218446, 0xfe218612)
        if (reads or word(channel) != 0 or word(channel + 4) != 0x40000003
                or word(channel + 8) != start or word(channel + 16) != ((rows - 1) << 16 | 4096)
                or word(route) != 0x33 or uc.reg_read(UC_ARM_REG_SP) != stack):
            raise RuntimeError('Wrong native IPC receive configuration writes')
        configurations.append({'supplied_size': count, 'rounded_rows': rows,
                               'configuration_stores': writes.copy(), 'passed': True})

    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'diagnostic_dumps': dumps,
            'status_polls': poll_cases, 'ipc_receive_configurations': configurations,
            'native_calls_stubbed': False, 'hardware_completion_validated': False,
            'camera_binding_enabled': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
