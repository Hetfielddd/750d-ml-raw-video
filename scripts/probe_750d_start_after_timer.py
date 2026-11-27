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
    component_state, saf_state = 0x1ac22a4, 0x1ac22d0
    component_registers = (0xd000a100, 0xd000a014, 0xd000a00c)
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
               (0xfe8b7ddc - app_delta, 0xfe8b7eee - app_delta),
               (0xfe8b7eee - app_delta, 0xfe8b7ef2 - app_delta))
    ranges += tuple((lo - app_delta, hi - app_delta) for lo, hi in (
        (0xfe894358, 0xfe894412), (0xfe89452a, 0xfe8945a4),
        (0xfe894652, 0xfe89474c), (0xfe89475c, 0xfe894768),
        (0xfe894970, 0xfe894984), (0xfe89498c, 0xfe8949a0),
        (0xfe8949a8, 0xfe8949bc), (0xfe8949c6, 0xfe8949da)))
    ranges += ((0xfe750e4a, 0xfe750e52), (0xfe74f1e0, 0xfe74f1e4),
               (0xfe74f228, 0xfe74f22c))
    ranges += tuple((lo - app_delta, hi - app_delta) for lo, hi in (
        (0xfe839eae, 0xfe839edc), (0xfe8ef62e, 0xfe8ef638),
        (0xfe8ef544, 0xfe8ef55c), (0xfe83a61a, 0xfe83a632),
        (0xfe83a6d8, 0xfe83a6da)))

    cases = []
    for timer_enabled, initial_flags, pending, prepare in (
            (False, 0x27f, pending_address, False), (True, 0x200, pending_address, False),
            (True, 0x200, 0, False), (False, gate_mask | 0x200, pending_address, False),
            (True, 0x200, pending_address, True),
            (True, 0x200, pending_address, 2),
            (True, 0x200, pending_address, 3),
            (True, 0x200, pending_address, 4)):
        active_preparation = prepare in (2, 3, 4)
        connected_start = prepare in (3, 4)
        component_pending = prepare == 3
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
        if active_preparation:
            pages += tuple((page, page + app_delta) for page in range(
                (0xfe894358 - app_delta) & ~4095,
                ((0xfe8949da - app_delta) & ~4095) + 4096, 4096))
        if connected_start:
            pages += tuple((page, page + app_delta) for page in (
                (0xfe8ef544 - app_delta) & ~4095, (0xfe83a61a - app_delta) & ~4095))
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
        if active_preparation:
            uc.mem_map(0xd0048000, 4096, rw)
        if connected_start:
            uc.mem_map(0xd000a000, 4096, rw)
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
        if connected_start:
            put(component_state, 1)
            put(component_state + 8, 0x13579bdf if component_pending else 0)
            put(saf_state, 0)
        if active_preparation:
            put(descriptor + 28, 1)
            put(preparation_settings + 68, 1080)
            put(preparation_settings + 72, 2048)
            for offset, value in ((24, 0), (28, 0), (32, 2048), (36, 1080),
                                  (40, 0x101), (44, 0x202), (48, 0x303), (52, 0x404)):
                put(descriptor + 8 + offset, value)
        uc.reg_write(UC_ARM_REG_CPSR, 0x13)
        hardware = (channel, channel + 4, channel + 8, packing, trigger)
        if prepare:
            hardware += (preparation_register,)
        if active_preparation:
            hardware += (0xd0048064, 0xd0048068, 0xd0048024, 0xd0048018)
            hardware += tuple(block + offset for block in (
                0xd0048000, 0xd0048900, 0xd0048a00, 0xd0048b00)
                for offset in (8, 12, 16, 0x80, 0x84, 0x88, 0x8c))
            hardware += (0xd0048918, 0xd0048a18, 0xd0048b18)
        if connected_start:
            hardware += component_registers
        allowed = {driver + 4, event + 8, descriptor + 84, raw + 36, 0x1ad81c8,
                   *hardware, *(shadow + (reg & 0x7ffff) for reg in hardware)}
        if prepare:
            allowed |= {preparation_state + 44, preparation_settings + 80}
        if active_preparation:
            allowed |= {preparation_state + offset for offset in (64, 68, 72, 76)}
        if connected_start:
            allowed |= {component_state + 4, component_state + 8}
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
            uc.emu_start(entry | 1, base + len(data),
                         count=1024 if active_preparation else 320, timeout=500_000)
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
            if (word(preparation_state + 44) != int(active_preparation)
                    or word(preparation_settings + 80) != (0x3d if active_preparation else 1)
                    or word(preparation_register) != 0x111
                    or word(shadow + 0x1a014) != 0x111
                    or not active_preparation and preparation_stores != [(preparation_register, 0x111)]
                    or uc.reg_read(UC_ARM_REG_SP) != stack - 16):
                raise RuntimeError('Native preparation branch did not return correctly')
            if active_preparation:
                if [word(preparation_state + offset) for offset in (64, 68, 72, 76)] != [0x101, 0x202, 0x303, 0x404]:
                    raise RuntimeError('Enabled preparation did not retain its four supplied words')
                for block in (0xd0048000, 0xd0048900, 0xd0048a00, 0xd0048b00):
                    if [word(block + offset) for offset in (0x84, 0x80, 0x88, 0x8c)] != [0x7ff0437, 1, 0, 0x43707ff]:
                        raise RuntimeError('Wrong configured processing dimensions or rectangle')
                if len(preparation_stores) != 39 or word(0xd0048024) != 0x1010101:
                    raise RuntimeError('Wrong enabled preparation command sequence')
        elif uc.reg_read(UC_ARM_REG_R0) != descriptor + 8:
            raise RuntimeError('Wrong descriptor preparation argument')
        # Keep the original driver frame throughout. The connected case
        # executes preparation, event gate, other component and SAF return
        # without omitting intervening calls or replacing their results.
        ready = ready_flags & gate_mask == gate_mask
        gate_target = 0xfe750e52 if connected_start else 0xfe74f1e0
        run(0xfe750e2e, gate_target if ready else 0xfe74bddc, fresh=False)
        if ready:
            expected_gate_stores = [(event + 8, ready_flags & ~gate_mask), (driver + 4, 0)]
            if component_pending:
                expected_gate_stores += list(zip(component_registers, (1, 0, 4)))
            if (word(event + 8) != (ready_flags & ~gate_mask) or word(driver + 4)
                    or stores != expected_gate_stores):
                raise RuntimeError('Native start did not consume the event and component masks')
            if connected_start and (word(component_state + 4) != (0x13579bdf if component_pending else 0)
                                    or word(component_state + 8) or word(saf_state)):
                raise RuntimeError('Wrong connected component pending-state consumption')
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
                      **({'extra_processing_enabled': True} if active_preparation else {}),
                      **({'continuous_driver_entry_to_raw_return': True,
                          'saf_initialized': False,
                          'component_had_pending_work': component_pending,
                          'intermediate_component_stores': [[hex(a), hex(v)] for a, v in zip(component_registers, (1, 0, 4))]
                          if component_pending else []}
                         if connected_start else {}),
                      'flags_at_end': hex(word(event + 8)),
                      'final_stage_stores': [[hex(a), hex(v)] for a, v in stores]})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'physical_register_reads': False, 'native_calls_stubbed': False,
            'hardware_completion_validated': False, 'camera_binding_enabled': False,
            'limits': 'Supplied enabled timer and no-waiter event object, descriptor, '
                      'normal RAW state and passive register RAM. Cases five through '
                      'eight execute descriptor preparation. Cases seven and eight '
                      'also execute intermediate component and inactive SAF paths '
                      'through RAW return, preserving the driver frame. Earlier cases '
                      'omit these intervening calls. '
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
