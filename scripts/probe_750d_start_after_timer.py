# SPDX-License-Identifier: GPL-2.0-or-later
"""Run the peer timer, native event gate and RAW start slices on passive RAM."""
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
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_CPSR,
                                   UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, delta, app_delta = 0xfe0a0000, 0x7e7473e0, 0xfcc82368
    raw, driver, shadow = 0x1ac2220, 0x1ac1830, 0x200000
    event, descriptor, stack, stop = 0x100000, 0x101000, 0x10d000, 0x10f000
    channel, packing, trigger = 0xd0004100, 0xd0037014, 0xd0008090
    pending_address, gate_mask = 0x5c62c000, 0x8000007f
    preparation_state, preparation_settings = 0x1ad7ba8, 0x1ac388c
    preparation_register = 0xd001a014
    ranges = ((0xfe750d04, 0xfe750d16), (0xfe750e1c, 0xfe750e46),
              (0xfe750e46, 0xfe750e4a), (0xfe750e52, 0xfe750e56), (0xfe74f118, 0xfe74f11c),
              (0xfe8395c4 - app_delta, 0xfe839642 - app_delta),
              (0xfe86f858 - app_delta, 0xfe86f85c - app_delta),
              (0xfe86f878 - app_delta, 0xfe86f87c - app_delta),
              (0xfe86f910 - app_delta, 0xfe86f920 - app_delta),
              (0xfe86f7e8 - app_delta, 0xfe86f7ec - app_delta),
              (0xfe86f890 - app_delta, 0xfe86f894 - app_delta),
              (0x8000c5fe, 0x8000c67e), (0x8000c57e, 0x8000c5be),
              (0x8000c426, 0x8000c434), (0x8000c460, 0x8000c476),
              (0x80003d22, 0x80003d2a), (0x80007bc4, 0x80007bce),
              (0x80007b7e, 0x80007b88), (0x44c, 0x470), (0x230, 0x23a),
              (0x80009d8e, 0x80009dd2), (0x80009cee, 0x80009cf0),
              (0xfe74fb9e, 0xfe74fc88), (0xfe749d84, 0xfe749e12),
              (0xfe74bbd4, 0xfe74bc06), (0xfe74bcd4, 0xfe74bcf2),
              (0xfe74bda2, 0xfe74bddc), (0xfe74f9b4, 0xfe74f9b8))
    ranges += tuple((lo - delta, hi - delta) for lo, hi in ranges[-6:])
    ranges += ((0xfe74f434, 0xfe74f438), (0xfe86f080 - app_delta, 0xfe86f08a - app_delta),
               (0xfe8954b8 - app_delta, 0xfe8954c2 - app_delta),
               (0xfe8b7ddc - app_delta, 0xfe8b7e1a - app_delta),
               (0xfe8b7eee - app_delta, 0xfe8b7ef2 - app_delta))

    cases = []
    for timer_enabled, initial_flags, pending, prepare in (
            (False, 0x27f, pending_address, False), (True, 0x200, pending_address, False),
            (True, 0x200, 0, False), (False, gate_mask | 0x200, pending_address, False),
            (True, 0x200, pending_address, True)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        rx, rw = UC_PROT_READ | UC_PROT_EXEC, UC_PROT_READ | UC_PROT_WRITE
        uc.mem_map(base, (len(data) + 4095) & ~4095, rx)
        uc.mem_write(base, data)
        pages = ((0, 0xfe744d60),) + tuple((page, page + delta) for page in (
            0x80002000, 0x80003000, 0x80004000, 0x80007000, 0x80008000,
            0x80009000, 0x8000a000, 0x8000c000, 0x8000f000))
        pages += tuple((page, page + app_delta) for page in (0x1bb7000, 0x1bed000))
        if prepare:
            pages += tuple((page, page + app_delta) for page in (
                (0xfe8b7ddc - app_delta) & ~4095, (0xfe8954b8 - app_delta) & ~4095,
                (0xfe86f080 - app_delta) & ~4095))
        for page, source in pages:
            uc.mem_map(page, 4096, rx)
            uc.mem_write(page, data[source - base:source - base + 4096])
        for page, size in ((event, 0xe000), (0x1ac0000, 0x10000), (0x1ad8000, 4096),
                           (shadow, 0x60000), (channel & ~4095, 4096),
                           (packing & ~4095, 4096), (trigger & ~4095, 4096)):
            uc.mem_map(page, size, rw)
        if prepare:
            uc.mem_map(preparation_state & ~4095, 4096, rw)
            uc.mem_map(preparation_register & ~4095, 4096, rw)
        uc.mem_map(stop, 4096, rx)

        def put(address, value):
            uc.mem_write(address, struct.pack('<I', value))

        def word(address):
            return struct.unpack('<I', uc.mem_read(address, 4))[0]

        put(raw, 1)
        put(raw + 8, 0x80009d8f)
        put(raw + 28, 1)
        put(raw + 36, pending)
        put(raw + 44, 34)
        put(driver + 4, 0x22)
        put(driver + 40, int(timer_enabled))
        put(driver + 44, 0xe0002)
        put(0x1ac05b8, event)
        put(0x1ac011c, 1)
        put(event + 8, initial_flags)
        put(event + 16, 7)
        put(0x1ac40a4, shadow)
        uc.reg_write(UC_ARM_REG_CPSR, 0x13)
        hardware = (channel, channel + 4, channel + 8, packing, trigger)
        if prepare:
            hardware += (preparation_register,)
        allowed = {driver + 4, event + 8, descriptor + 84, raw + 36, 0x1ad81c8,
                   *hardware, *(shadow + (reg & 0x7ffff) for reg in hardware)}
        if prepare:
            allowed |= {preparation_state + 44, preparation_settings + 80}
        boundary, reached, errors, stores = stop, [], [], []

        def code_guard(emulator, address, size, _):
            if address == boundary:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected code {address:#x}')
                emulator.emu_stop()

        def read_guard(emulator, _access, address, size, _value, _):
            if 0xd0000000 <= address < 0xe0000000:
                errors.append(f'Unexpected physical register read {address:#x}/{size}')
                emulator.emu_stop()

        def write_guard(emulator, _access, address, size, value, _):
            if stack - 256 <= address and address + size <= stack:
                return
            if size != 4 or address not in allowed:
                errors.append(f'Unexpected store {address:#x}/{size}')
                emulator.emu_stop()
            if address in hardware or address in (driver + 4, event + 8):
                stores.append((address, value))

        for hook, guard in ((UC_HOOK_CODE, code_guard), (UC_HOOK_MEM_READ, read_guard),
                            (UC_HOOK_MEM_WRITE, write_guard)):
            uc.hook_add(hook, guard)

        def run(entry, target, *, fresh=True, argument=0):
            nonlocal boundary
            boundary = target
            reached.clear()
            stores.clear()
            if fresh:
                uc.reg_write(UC_ARM_REG_SP, stack)
                uc.reg_write(UC_ARM_REG_LR, stop | 1)
                uc.reg_write(UC_ARM_REG_R0, argument)
            uc.emu_start(entry | 1, base + len(data), count=320, timeout=500_000)
            if errors or reached != [target]:
                raise RuntimeError(f'{entry:#x} failed to reach {target:#x}: {errors}/{reached}')

        run(0xfe750d04, stop)
        ready_flags = initial_flags | gate_mask if timer_enabled else initial_flags
        timer_stores = stores.copy()
        if (word(event + 8) != ready_flags or word(driver + 4) != 0x22
                or timer_stores != ([(event + 8, ready_flags)] if timer_enabled else [])
                or uc.reg_read(UC_ARM_REG_SP) != stack or uc.reg_read(UC_ARM_REG_CPSR) & 0x80):
            raise RuntimeError('Unexpected timer event update')
        run(0xfe750e1c, 0xfe750e2e if prepare else 0xfe74f434, argument=descriptor)
        preparation_stores = stores.copy()
        if word(descriptor + 84) != 0x22:
            raise RuntimeError('Wrong saved software component mask or start argument')
        if prepare:
            if (word(preparation_state + 44) != 0 or word(preparation_settings + 80) != 1
                    or word(preparation_register) != 0x111
                    or word(shadow + 0x1a014) != 0x111
                    or preparation_stores != [(preparation_register, 0x111)]
                    or uc.reg_read(UC_ARM_REG_SP) != stack - 16):
                raise RuntimeError('Native disabled preparation branch did not return correctly')
        elif uc.reg_read(UC_ARM_REG_R0) != descriptor + 8:
            raise RuntimeError('Wrong descriptor preparation argument')
        # Preserve the original start frame. The fifth case has executed the
        # disabled preparation branch completely. Other cases enter this
        # continuation across an explicit unexecuted preparation cut.
        ready = ready_flags & gate_mask == gate_mask
        run(0xfe750e2e, 0xfe74f1e0 if ready else 0xfe74bddc, fresh=False)
        if ready:
            if (word(event + 8) != (ready_flags & ~gate_mask) or word(driver + 4)
                    or stores != [(event + 8, ready_flags & ~gate_mask), (driver + 4, 0)]):
                raise RuntimeError('Native start did not consume the event and component masks')
            # Omit the intervening driver and SAF starts. The RAW call itself
            # executes through the actual import, with no synthetic return.
            run(0xfe750e52, 0xfe750e56, fresh=False)
            expected = ([(channel + 8, 0x1c62c000), (channel + 4, 0x20000000),
                         (channel, 1), (packing, 34), (trigger, 1)] if pending
                        else [(driver + 4, 0x10), (event + 8, 0x210)])
            if (stores != expected or word(raw + 36)
                    or uc.reg_read(UC_ARM_REG_SP) != stack - 16
                    or uc.reg_read(UC_ARM_REG_CPSR) & 0x80):
                raise RuntimeError(f'Unexpected RAW start or empty callback stores: {stores}')
        elif stores or word(event + 8) != ready_flags or word(raw + 36) != pending:
            raise RuntimeError('Blocked start changed flag or address state')
        cases.append({'timer_enabled': timer_enabled, 'supplied_flags': hex(initial_flags),
                      'flags_after_timer': hex(ready_flags), 'start_gate_returned': ready,
                      'pending_address_before_start': hex(pending),
                      'saved_component_word': hex(word(descriptor + 84)),
                      'timer_stores': [[hex(a), hex(v)] for a, v in timer_stores],
                      **({'descriptor_helper_executed': True,
                          'preparation_register_stores': [[hex(a), hex(v)] for a, v in preparation_stores]}
                         if prepare else {}),
                      'flags_at_end': hex(word(event + 8)),
                      'final_stage_stores': [[hex(a), hex(v)] for a, v in stores]})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'physical_register_reads': False, 'native_calls_stubbed': False,
            'hardware_completion_validated': False, 'camera_binding_enabled': False,
            'limits': 'Supplied enabled timer and no-waiter event object, descriptor, '
                      'normal RAW state and passive register RAM. The fifth case '
                      'executes the disabled descriptor preparation branch completely. '
                      'Other cases omit it. Separate native slices omit intermediate '
                      'driver and SAF starts. '
                      'No success returns are supplied. Timer invocation and initial '
                      'flags are fixture inputs. Physical DMA, scheduling, frame identity '
                      'and buffer reuse timing remain unverified.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
