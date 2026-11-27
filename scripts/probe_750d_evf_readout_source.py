# SPDX-License-Identifier: GPL-2.0-or-later
"""Replay 750D HEAD2 callback registration and EVF ReadOutDone routing on a PC.

Calls that require allocation, logging, kernel IRQ setup or peripheral state are
bounded by explicit cuts. No physical line interrupt or DMA transfer is modeled.
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
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
                         UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
                                   UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R8,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, low_source = 0xfe0a0000, 0xfed58b7c
    context, state_object, task, driver = 0x100000, 0x101000, 0x102000, 0x103000
    mode, profile, envelope = 0x104000, 0x105000, 0x106000
    mailbox, thread = 0x1234, 0x5678  # Supplied underlying OS handles.
    stack, stop = 0x10d000, 0x10f000
    logger, head2_callback, post_event = 0xfe3ce0fc, 0xfe2a182c, 0xfe2b8336
    readout, ignore = 0xfe2b9536, 0xfe2ba912
    table, name = 0xfea0b174, 0xfed52562
    callback_slot, head2_settings = 0x30af8, 0x30f54
    head2_ack, head2_registers = head2_settings + 56, (0xd0007064, 0xd000705c, 0xd0007060)
    evf_registration = 0x26b94
    argument_regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
    read_write = UC_PROT_READ | UC_PROT_WRITE
    read_execute = UC_PROT_READ | UC_PROT_EXEC
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    uc.mem_map(base, (len(data) + 4095) & ~4095, read_execute)
    uc.mem_write(base, data)
    uc.mem_map(0, 0x4000, read_execute)
    uc.mem_write(0, data[low_source - base:low_source - base + 0x4000])
    uc.mem_map(context, 0xe000, read_write)
    uc.mem_map(stop, 4096, read_execute)
    for page in (0x4000, 0x26000, 0x2b000, 0x30000, 0x6b000, 0xd0007000):
        uc.mem_map(page, 4096, read_write)

    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def args():
        return [uc.reg_read(reg) for reg in argument_regs]

    def require(condition, label):
        if not condition:
            raise RuntimeError(label)

    code_ranges = (
        (0xfe26855a, 0xfe2685cc), (0xfe2b7ff4, 0xfe2b800e),
        (0x211a, 0x2150), (0xfe2b9832, 0xfe2b983e),
        (0xfe2b9e00, 0xfe2b9e0a), (0xfe2b9f3c, 0xfe2b9f46),
        (0xfe30a32a, 0xfe30a38e), (0xfe30a248, 0xfe30a24a),
        (0xfe2d0528, 0xfe2d0544), (0xfe2d0214, 0xfe2d026a),
        (0xfe2cfcb6, 0xfe2cfd18), (0xfe2a1848, 0xfe2a188e),
        (head2_callback, 0xfe2a1848), (post_event, 0xfe2b834c),
        (0xfe268514, 0xfe268530), (0xfe3ce004, 0xfe3ce008),
        (0x2090, 0x211a), (0x21e0, 0x22cc), (0x2352, 0x2386),
        (0xfe3cdffc, 0xfe3ce000), (0xfe3ce01c, 0xfe3ce020),
        (readout, 0xfe2b9560), (ignore, 0xfe2ba932),
        (0xfe3b309c, 0xfe3b30dc),
    )
    writable = ((stack - 256, stack + 8), (state_object, state_object + 32),
                (context, context + 28), (context + 56, context + 60),
                (task, task + 24), (envelope, envelope + 16),
                (driver + 16, driver + 20), (0x4af4, 0x4af8),
                (evf_registration, evf_registration + 4), (0x6b650, 0x6b65c),
                (callback_slot, callback_slot + 4), (callback_slot + 32, callback_slot + 36),
                (head2_settings + 4, head2_settings + 8)) + tuple(
                    (register, register + 4) for register in head2_registers)
    targets, reached, errors = (), [], []

    def code_guard(emulator, address, size, _):
        if address in targets:
            reached.append(address)
            emulator.emu_stop()
        elif not any(lo <= address and address + size <= hi for lo, hi in code_ranges):
            errors.append(f'Unexpected code {address:#x}')
            emulator.emu_stop()

    def write_guard(emulator, _access, address, size, _value, _data):
        if not any(lo <= address and address + size <= hi for lo, hi in writable):
            errors.append(f'Unexpected write {address:#x}/{size}')
            emulator.emu_stop()

    def run(entry, target, supplied=(), *, fresh=False, arm_entry=False):
        nonlocal targets
        targets = (target,)
        reached.clear()
        if fresh:
            uc.reg_write(UC_ARM_REG_SP, stack)
            uc.reg_write(UC_ARM_REG_LR, stop | 1)
        for reg, value in supplied:
            uc.reg_write(reg, value)
        uc.emu_start(entry if arm_entry else entry | 1, base + len(data),
                     count=192, timeout=500_000)
        require(not errors and reached == [target], f'{entry:#x} to {target:#x}: {errors}/{reached}')

    def fifth():
        return word(uc.reg_read(UC_ARM_REG_SP))

    uc.hook_add(UC_HOOK_CODE, code_guard)
    uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
    run(0xfe26855a, 0xfe4386b4, ((UC_ARM_REG_R0, 0xa7), (UC_ARM_REG_R1, 0x31),
                                 (UC_ARM_REG_R2, 0), (UC_ARM_REG_R3, 0)), fresh=True)
    require(args()[:2] == [0xa7, 200], 'Wrong EVF context allocation')
    run(0xfe268576, 0xfe3ce074, ((UC_ARM_REG_R0, context),))
    constructor_args = args()
    require(constructor_args == [name, 0, table, 20] and fifth() == 10, 'Wrong EvfState constructor')
    # Keep the nested native EVF frame; enter the primary state constructor
    # directly at the thumb target of the ARM veneer.
    require(word(0xfe3ce078) == 0x211b, 'Wrong state constructor veneer')
    run(0x211a, 0x10ea)
    require(args()[0] == 32, 'Wrong EvfState object allocation')
    run(0x2138, 0xfe3cdffc, ((UC_ARM_REG_R0, state_object),))
    require(word(evf_registration) == state_object and word(context + 12) == state_object,
            'Wrong EVF state publication')
    require([word(state_object + off) for off in (4, 8, 12, 16, 20, 24, 28)]
            == [name, 0, 0x20af, table, 20, 10, 0], 'Wrong native EvfState layout')
    require(args()[1:] == [0x31, 3072, 200] and fifth() == 0xfe268515,
            'Wrong EVF task callback or dimensions')
    run(0xfe3cdffc, 0x10ea, arm_entry=True)
    require(args()[0] == 24, 'Wrong low-kernel EVF task allocation')
    run(0x2280, 0x2ce8, ((UC_ARM_REG_R0, task),))
    require(word(task + 20) == 0xfe268515 and word(task + 8) == 1,
            'Wrong native EVF task layout')
    run(0x229e, 0x1e44, ((UC_ARM_REG_R0, mailbox),))
    require(args()[1:] == [0x31, 3072, 0x2233] and fifth() == task,
            'Wrong native task thread entry')
    run(0x22ba, 0xfe2685cc, ((UC_ARM_REG_R0, thread),))
    require(word(0x4af4) == context and word(context + 8) == task,
            'Wrong context or task publication')

    put(evf_registration + 60, driver)
    put(driver, word(word(0xfe30a71c)))
    put(driver + 36, mode)
    put(mode + 8, 1)
    put(mode + 12, 2)
    put(0x2b350 + 68, profile)
    # Seed the two tables from the verified boot data-copy source. The hardware
    # address page is passive RAM and its stores have no peripheral semantics.
    init_source = word(0xfe0a0120)
    init_destination = word(0xfe0a0124)
    init_limit = word(0xfe0a0128)
    require((init_source, init_destination, init_limit) == (0xfed652e8, 0x4000, 0x3a3a0),
            'Wrong primary boot data-copy literals')
    for address, size in ((head2_settings, 28), (head2_ack, 12)):
        offset = init_source + address - init_destination - base
        uc.mem_write(address, data[offset:offset + size])
    registrations = []
    for site, owner_reg, line in ((0xfe2b9832, UC_ARM_REG_R8, 523),
                                  (0xfe2b9e00, UC_ARM_REG_R5, 524),
                                  (0xfe2b9f3c, UC_ARM_REG_R6, 900)):
        put(driver + 16, 0)
        put(0x6b650, 0)
        put(profile + 0x2a8 + 42, line)  # Profile index 2 * 20 + mode index 1 * 2.
        threshold = max(line, 524)
        run(site, logger, ((UC_ARM_REG_R4, context), (owner_reg, evf_registration)), fresh=True)
        require(args() == [0xac, 3, 0xfe2d05e8, threshold], 'Wrong HEAD2 line threshold')
        run(0xfe2d022a, logger)
        require(args() == [0xac, 1, 0xfe2d0038, 0], 'Wrong HD callback slot')
        require([word(0x6b650 + offset) for offset in (0, 4, 8)]
                == [post_event | 1, context, threshold], 'Wrong native HD registry entry')
        run(0xfe2cfcce, 0xfe3cdf9c)
        require(args() == [0xfe2a1a0c, 32, head2_callback | 1, 0],
                'Wrong HEAD2 IRQ registration request')
        run(0xfe2a1862, 0xfe3b309c)
        require(args()[0] == head2_settings and word(head2_settings + 4) == threshold,
                'Wrong HEAD2 register-list value')
        require(word(callback_slot) == (post_event | 1) and word(callback_slot + 32) == context,
                'Wrong native HEAD2 context/callback installation')
        run(0xfe3b309c, logger)
        run(0xfe3b30ba, logger)
        run(0xfe3b30ba, logger)
        # LDR.W in the first call site and LDR in the other two.
        run(0xfe3b30ba, site + (12 if site == 0xfe2b9832 else 10))
        require([word(register) for register in head2_registers] == [threshold, 4, 12],
                'Wrong HEAD2 configuration stores')
        require(word(driver + 16) == 0x6b650 and uc.reg_read(UC_ARM_REG_SP) == stack,
                'Wrong completed HEAD2 registration')
        registrations.append({'evf_site': hex(site), 'supplied_line': line, 'selected_line': threshold})

    run(head2_callback, 0xfe3b309c, fresh=True)
    require(args()[0] == head2_ack, 'Wrong HEAD2 IRQ register list')
    put(head2_registers[1], 0)
    run(0xfe3b309c, logger)
    run(0xfe3b30ba, 0xfe54854c)
    require(word(head2_registers[1]) == 4, 'Wrong HEAD2 acknowledge store')
    require(args()[0] == context, 'Wrong HEAD2 callback owner')
    run(0xfe2b833e, 0xfe3ce01c)
    task_request = args()
    extra = fifth()
    require(task_request == [task, context, 5, 0] and extra == 0, 'Wrong EVF event-5 request')
    run(0xfe3ce01c, 0x10ea, arm_entry=True)
    require(args()[0] == 16, 'Wrong EVF envelope allocation size')
    run(0x2378, 0x2f04, ((UC_ARM_REG_R0, envelope),))
    payload_words = [word(envelope + offset) for offset in (0, 4, 8, 12)]
    require(args()[:2] == [mailbox, envelope] and payload_words == task_request[1:] + [extra],
            'Wrong native EVF envelope or mailbox selection')
    uc.mem_protect(envelope, 4096, UC_PROT_READ)
    put(callback_slot, 0)
    run(head2_callback, logger, fresh=True)
    run(0xfe3b30ba, stop)  # Null installed callback returns directly after acknowledge.
    require(uc.reg_read(UC_ARM_REG_SP) == stack, 'Wrong null-callback IRQ return')

    cases = []
    for current in range(10):
        put(state_object + 28, current)
        put(context + 56, 0)
        handler = readout if 3 <= current <= 6 else ignore if current in (2, 7, 8) else 0
        require(word(table + (50 + current) * 8 + 4) == (handler | 1 if handler else 0),
                f'Wrong event-5 matrix handler at state {current}')
        run(0x2232, 0x2db0, ((UC_ARM_REG_R0, task),), fresh=True)
        loop_sp = stack - 40
        require(args()[:2] == [mailbox, uc.reg_read(UC_ARM_REG_SP)], 'Wrong EVF receive request')
        # Mailbox delivery is supplied as an envelope pointer in the actual
        # receive output slot. Extract the four fields natively before free.
        put(args()[1], envelope)
        run(0x220e, 0x1284)
        require([word(loop_sp + offset) for offset in (24, 20, 16, 12)] == payload_words,
                'Wrong native envelope extraction order')
        # Skip the envelope-free call/receive epilogue. Resume the queue loop
        # on its delivered-message branch with the original loop frame and task.
        uc.reg_write(UC_ARM_REG_SP, loop_sp)
        run(0x2250, logger if handler else 0xfe268530, ((UC_ARM_REG_R4, task),))
        require(word(state_object + 28) == current, f'Wrong event-5 resulting state {current}')
        if handler == readout:
            require(args()[:3] == [0xa7, 1, 0xfe2b9944], 'Wrong ReadOutDone log entry')
            run(0xfe2b9558, 0xfe418752)
            require(word(context + 56) == 1, 'ReadOutDone did not publish software flag')
        elif handler == ignore:
            require(args()[:3] == [0xa7, 3, 0xfe2baa28], 'Wrong EVF ignore log entry')
        else:
            require(args()[0] == 0, 'Empty native state transition did not return zero')
        cases.append({'state': current, 'handler': hex(handler) if handler else None,
                      'readout_flag': word(context + 56)})

    return {'main_code_sha256': MAIN_SHA256, 'passed': True,
            'head2_registrations': registrations, 'native_head2_dispatch': True,
            'head2_registers': [hex(register) for register in head2_registers],
            'null_callback_returns': True, 'event': task_request[2],
            'payload': task_request[3], 'extra': extra, 'native_state_cases': cases,
            'native_envelope_words': [hex(value) for value in payload_words],
            'native_task_callback_offset': 20, 'mailbox_delivery_executed': False,
            'hardware_irq_or_dma_modeled': False, 'camera_binding_enabled': False,
            'native_calls_stubbed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
