# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the primary SCSState constructor and its actual event7 matrix dispatch.

Native constructor and worker slices check the callback queue/object association
across explicit allocation/delivery cuts. No frame ownership is modeled.
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
                                   UC_ARM_REG_R6, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    base, low_source = 0xfe0a0000, 0xfed58b7c
    obj, owner, stack, stop = 0x100000, 0x101000, 0x10d000, 0x10f000
    table, name, handler = 0xfea06d08, 0xfed522f8, 0xfe13dc5e
    active = (10, 11, 14, 15, 16)
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    uc.mem_map(base, (len(data) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(base, data)
    uc.mem_map(0, 0x4000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(0, data[low_source - base:low_source - base + 0x4000])
    uc.mem_map(obj, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(0x4000, 4096, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(0x26000, 4096, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)

    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def word(address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]

    def args():
        return [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]

    ranges = ((0xfe13ca78, 0xfe13ca8e), (0x211a, 0x2150),
              (0x20ae, 0x211a), (handler, 0xfe13dc84))
    ranges += ((0xfe13ca8e, 0xfe13ca9a), (0xfe132bd2, 0xfe132bde),
               (0xfe132bde, 0xfe132be4), (0xfe132bec, 0xfe132c04),
               (0xfe132bb8, 0xfe132bbe), (0xfe132c0c, 0xfe132c10),
               (0xfe43832c, 0xfe43835c), (0xfe13e912, 0xfe13e91c),
               (0xfe13e92a, 0xfe13e938), (0xfe43842e, 0xfe43845a),
               (0xfe4382a0, 0xfe4382ca), (0xfe4382fa, 0xfe438328),
               (0xfe132b48, 0xfe132ba0), (0xfe3ce004, 0xfe3ce008),
               (0x2090, 0x20ae), (0xfe13dc84, 0xfe13dc94),
               (0xfe13dd78, 0xfe13ddb0), (0xfe13e17c, 0xfe13e192),
               (0xfe13e97e, 0xfe13e986), (0xfe13e05e, 0xfe13e096),
               (0xfe13e172, 0xfe13e17c))
    queue, envelope, loop_sp = 0x102000, 0x103000, stack - 64

    def run(entry, target, supplied=(), entry_sp=stack):
        errors, reached = [], []

        def code_guard(emulator, address, size, _):
            if address == target:
                reached.append(address)
                emulator.emu_stop()
            elif not any(lo <= address and address + size <= hi for lo, hi in ranges):
                errors.append(f'Unexpected SCS code: {address:#x}')
                emulator.emu_stop()

        def write_guard(emulator, access, address, size, value, _):
            if not (stack - 256 <= address and address + size <= stack + 8
                    or obj <= address and address + size <= obj + 32
                    or owner <= address and address + size <= owner + 16
                    or (address, size) == (owner + 56, 4)
                    or queue <= address and address + size <= queue + 28
                    or envelope <= address and address + size <= envelope + 16
                    or size == 4 and address in (0x4988, 0x263c4, 0x26418, 0x26420)):
                errors.append(f'Unexpected SCS write: {address:#x}/{size}')
                emulator.emu_stop()

        hooks = [uc.hook_add(UC_HOOK_CODE, code_guard), uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)]
        uc.reg_write(UC_ARM_REG_SP, entry_sp)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        for register, value in supplied:
            uc.reg_write(register, value)
        try:
            uc.emu_start(entry | 1, base + len(data), count=192, timeout=500_000)
        finally:
            for hook in hooks:
                uc.hook_del(hook)
        if errors or reached != [target]:
            raise RuntimeError(f'Invalid SCS stage: {errors}/{reached}')
        if target == stop and uc.reg_read(UC_ARM_REG_SP) != stack:
            raise RuntimeError('SCS native return did not restore stack')

    run(0xfe13ca78, 0xfe3ce074)
    constructor_args = args()
    if constructor_args != [name, 0, table, 26] or word(uc.reg_read(UC_ARM_REG_SP)) != 18:
        raise RuntimeError('SCS constructor did not select the reviewed matrix/dimensions')
    # Execute actual primary low-kernel constructor prefix to allocation, then
    # a separate post-allocation slice with supplied scratch storage. The native
    # saved frame/registers are retained; no allocator return is synthesized.
    put(stack, 18)
    run(0x211a, 0x10ea, tuple(zip(
        (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), constructor_args)))
    if uc.reg_read(UC_ARM_REG_R0) != 32:
        raise RuntimeError('Native state constructor did not request32bytes')
    run(0x2138, stop, ((UC_ARM_REG_R0, obj),), entry_sp=uc.reg_read(UC_ARM_REG_SP))
    if [word(obj + off) for off in (4, 8, 12, 16, 20, 24, 28)] != [name, 0, 0x20af, table, 26, 18, 0]:
        raise RuntimeError('Native SCS state-object publication mismatch')
    signature = word(obj)
    cases = []
    for current in range(18):
        put(obj + 28, current)
        put(stack, 0)
        run(0x20ae, 0xfe3ce0fc if current in active else stop,
            ((UC_ARM_REG_R0, obj), (UC_ARM_REG_R1, owner),
             (UC_ARM_REG_R2, 7), (UC_ARM_REG_R3, 0)))
        if word(obj + 28) != current:
            raise RuntimeError('SCS event7 unexpectedly changed the current state')
        if current not in active and uc.reg_read(UC_ARM_REG_R0) != 0:
            raise RuntimeError('Absent SCS event7 handler did not return zero')
        entry = table + (7 * 18 + current) * 8
        if word(entry + 4) != (handler | 1 if current in active else 0):
            raise RuntimeError('Unexpected event7 table handler')
        cases.append({'current_state': current, 'input': 7,
                      'handler_source': hex(handler) if current in active else None,
                      'stopped_before_logger': current in active,
                      'no_handler_returned_zero': current not in active, 'passed': True})
    for label, sig, event, expected in (('invalid_signature', signature ^ 1, 7, 7),
                                        ('input_outside_limit', signature, 27, 3)):
        put(obj, sig)
        put(obj + 28, 0)
        put(stack, 0)
        run(0x20ae, stop, ((UC_ARM_REG_R0, obj), (UC_ARM_REG_R1, owner),
                           (UC_ARM_REG_R2, event), (UC_ARM_REG_R3, 0)))
        if uc.reg_read(UC_ARM_REG_R0) != expected:
            raise RuntimeError('Native SCS rejection returned an unexpected value')
        cases.append({'case': label, 'native_return': expected, 'passed': True})
    # Native constructor publications and worker routing, across declared
    # allocation/task-create/queue-delivery cuts. This does NOT execute OS queue
    # allocation/enqueue/dequeue. The loop consumes native envelope words copied
    # into supplied post-receive stack slots, not a fabricated OS success return.
    put(obj, signature)
    routing_cases = []
    for current, branch in [(state, 0) for state in active] + [(10, 1)]:
        uc.mem_protect(envelope, 4096, UC_PROT_READ | UC_PROT_WRITE)
        put(obj + 28, current)
        put(owner + 40, 0x1234)
        put(owner + 56, branch)
        put(0x4988, 0)
        put(0x26420, 0)
        # The actual SCS constructor continuation publishes its native object.
        run(0xfe13ca8e, 0xfe13ca9a, ((UC_ARM_REG_R0, obj),))
        # Post-owner-allocation prefix prepares the real owner signature/R7.
        run(0xfe132bd2, 0xfe132bda, ((UC_ARM_REG_R4, owner),))
        run(0xfe132bde, 0xfe132bec, ((UC_ARM_REG_R0, obj),))
        if word(owner + 12) != obj or word(0x263c4) != obj:
            raise RuntimeError('Native constructor did not publish the SCS object association')
        run(0xfe132bec, 0xfe43832c, ((UC_ARM_REG_R8, stop + 256),))
        if word(stack) != 100 or word(stack + 4) != 0xfe132b49:
            raise RuntimeError('Native context constructor did not select the real queue worker')
        # Queue constructor prefix to allocation; separately initialize its
        # post-allocation structural fragment. Queue/sem/task creation is omitted.
        run(0xfe43832c, 0xfe3ce0e4)
        if uc.reg_read(UC_ARM_REG_R0) != 28:
            raise RuntimeError('Primary queue wrapper did not request a 28-byte object')
        run(0xfe438342, 0xfe43835c, ((UC_ARM_REG_R0, queue),),
            entry_sp=uc.reg_read(UC_ARM_REG_SP))
        if word(queue + 24) != 0xfe132b49 or word(queue + 8) != 1:
            raise RuntimeError('Native queue fragment did not publish its callback/active flag')
        run(0xfe132c00, 0xfe132c04, ((UC_ARM_REG_R0, queue), (UC_ARM_REG_R4, owner)))
        run(0xfe132bb8, 0xfe132bbe)
        run(0xfe132c0c, 0xfe132c10)
        if word(owner + 8) != queue or word(0x4988) != owner:
            raise RuntimeError('Native context publication did not link queue and global owner')
        # Real CMOS callback prefix plus separately entered post-logger slice;
        # the continuation consumes no mode-query/logger return value.
        run(0xfe13e912, 0xfe3ff59e, ((UC_ARM_REG_R0, owner),))
        run(0xfe13e92a, 0xfe43842e, entry_sp=uc.reg_read(UC_ARM_REG_SP))
        if args() != [queue, owner, 7, 0]:
            raise RuntimeError('CMOS callback did not use its natively published queue')
        run(0xfe43842e, 0xfe3ce0e4, entry_sp=uc.reg_read(UC_ARM_REG_SP))
        if uc.reg_read(UC_ARM_REG_R0) != 16:
            raise RuntimeError('Primary event request did not request a 16-byte envelope')
        run(0xfe438454, 0xfe43845a, ((UC_ARM_REG_R0, envelope),),
            entry_sp=uc.reg_read(UC_ARM_REG_SP))
        words = [word(envelope + offset) for offset in (0, 4, 8, 12)]
        if words != [owner, 7, 0, 0]:
            raise RuntimeError('Native primary envelope has an unexpected event/payload')
        for offset, value in zip((24, 20, 16, 12), words):
            put(loop_sp + offset, value)
        uc.mem_protect(envelope, 4096, 0)
        # Explicit unexecuted delivery/removal/free cut. Native loop loads these
        # stack words and its constructor-selected worker, which resolves the
        # natively published global-owner+12 state object itself.
        run(0xfe438310, 0xfe3ce0fc, ((UC_ARM_REG_R4, queue),), entry_sp=loop_sp)
        if word(obj + 28) != current:
            raise RuntimeError('Native worker dispatch selected an unexpected SCS transition')
        target = 0xfe4046ba if branch else 0xfe3cdfdc
        run(0xfe13dc84, target, entry_sp=uc.reg_read(UC_ARM_REG_SP))
        if word(0x26420) != (0 if branch else 1) or word(owner + 12) != obj:
            raise RuntimeError('SCS completion branch changed its flag/object association unexpectedly')
        if not branch and (uc.reg_read(UC_ARM_REG_SP) != loop_sp - 32
                           or uc.reg_read(UC_ARM_REG_R0) != word(queue + 16)):
            raise RuntimeError('Returning SCS worker did not reach the native receive wrapper frame')
        routing_cases.append({'current_state': current, 'supplied_owner_field56': branch,
                              'native_queue_callback': '0xfe132b49',
                              'native_state_object_at_owner_offset': 12,
                              'native_envelope_words': [hex(value) for value in words],
                              'completion_flag_after_slice': word(0x26420),
                              'stopped_before': hex(target),
                              'native_worker_returned_to_next_receive': not bool(branch),
                              'queue_delivery_executed': False, 'passed': True})
    flag_cases = []
    # Reviewed mid-handler flag consumer. Earlier calls are not executed or
    # assumed successful; only these supplied-register decision slices run.
    for initial in (0, 1, 2):
        put(0x26420, initial)
        target = handler if initial == 1 else 0xfe13d110
        run(0xfe13e17c, target,
            ((UC_ARM_REG_R6, 0x263bc), (UC_ARM_REG_R4, owner),
             (UC_ARM_REG_R9, 0x12345678), (UC_ARM_REG_R10, 0x87654321)))
        expected_args = [owner, 0x12345678, 0x87654321] if initial == 1 else [0x1234]
        if args()[:len(expected_args)] != expected_args or word(0x26420) != initial:
            raise RuntimeError('SCS retained completion flag did not select the exact-one branch')
        flag_cases.append({'case': 'completion_flag_reader', 'initial_flag': initial,
                           'reenters_completion_handler': initial == 1,
                           'flag_after_read': word(0x26420), 'stopped_before': hex(target), 'passed': True})
    for initial in (0, 1):
        put(0x263bc + 108, 1)
        put(0x26420, initial)
        put(owner + 56, 0)
        # Prefix natively produces R7=1; it is retained across the explicit
        # unexecuted middle-handler/helper cuts, rather than supplied at store.
        run(0xfe13e05e, 0xfe3ce0fc,
            ((UC_ARM_REG_R0, owner), (UC_ARM_REG_R1, 0x12345678),
             (UC_ARM_REG_R2, 0x87654321), (UC_ARM_REG_R9, 0x12345678)))
        run(0xfe13e172, 0xfe13ddb0, entry_sp=uc.reg_read(UC_ARM_REG_SP))
        if word(owner + 56) != 1:
            raise RuntimeError('Native follow-up handler did not publish owner field56')
        target = handler if initial == 1 else 0xfe13d110
        run(0xfe13e17c, target, entry_sp=uc.reg_read(UC_ARM_REG_SP))
        if initial == 1:
            run(handler, 0xfe3ce0fc, entry_sp=uc.reg_read(UC_ARM_REG_SP))
            run(0xfe13dc84, 0xfe4046ba, entry_sp=uc.reg_read(UC_ARM_REG_SP))
        if word(0x26420) != initial or word(owner + 56) != 1:
            raise RuntimeError('Follow-up changed the retained flag/owner readiness unexpectedly')
        flag_cases.append({'case': 'native_followup_readiness_publication', 'initial_flag': initial,
                           'owner_field56_after_native_store': 1,
                           'reentered_nonzero_completion_branch': initial == 1,
                           'flag_after_followup': word(0x26420),
                           'stopped_before': hex(0xfe4046ba if initial else target), 'passed': True})
    put(0x26418, 0x12345678)
    put(0x26420, 1)
    # Actual reset prefix reloads its own global base and zero value. It stops
    # before a subsequent decision; preceding capture/helper calls are omitted.
    run(0xfe13e97e, 0xfe13e986)
    if word(0x26420) != 0 or word(0x26418) != 0:
        raise RuntimeError('Native capture-path reset did not clear both software fields')
    flag_cases.append({'case': 'capture_path_completion_flag_reset',
                       'cleared_addresses': ['0x26418', '0x26420'], 'passed': True})
    return {'main_code_sha256': MAIN_SHA256, 'passed': True, 'cases': cases,
            'separate_constructor_worker_routing_cases': routing_cases,
            'separate_flag_lifecycle_cases': flag_cases,
            'constructor_name': 'SCSState', 'matrix': hex(table), 'event7_active_states': list(active),
            'native_calls_stubbed': False, 'os_queue_delivery_validated': False,
            'native_constructor_worker_object_association_checked': True,
            'allocation_executed': False, 'all_handler_branches_completed': False,
            'camera_binding_enabled': False,
            'frame_lease_validated': False,
            'limits': 'Actual constructor argument preparation and primary low-kernel '
                      'constructor/dispatcher slices. Allocation stops at its boundary; '
                      'a separate post-allocation slice publishes into supplied scratch. '
                      'Current states, owner and event delivery are fixtures. Candidate '
                      'SCSState is distinct from EVF. Additional constructor/worker '
                      'cases check its static object association across explicit owner, '
                      'queue, envelope allocation and task-create/delivery/free cuts. '
                      'No OS queue operation or successful allocator return is fabricated. '
                      'Loop stack inputs are supplied from native envelope words; '
                      'one supplied completion branch returns, another stops at its '
                      'first mode query. Active matrix-only cases stop at the logger. '
                      'Separate flag/readiness slices preserve native-produced readiness '
                      'value across unexecuted intervening helpers, test exact-one '
                      'reentry and native reset; they do not execute full capture handlers. '
                      'No sensor transfer, pixels, completed capture or buffer ownership modeled.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_record', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.main_record.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
