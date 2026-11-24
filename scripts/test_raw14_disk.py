# SPDX-License-Identifier: GPL-2.0-or-later
"""Run the ARM C recorder against real PC file operations through a test bridge.

Creates exclusive files in a new directory below --build-dir. No camera/SD API.
Requires the same Arm toolchain and Unicorn as test_raw14_arm.py.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from inspect_raw14_mlv import inspect_mlv
from test_raw14_arm import execute


class ArmDiskIO:
    """Only the four IO functions cross to Python; recording logic remains ARM C."""

    def __init__(self, file, fault=False, fio=False):
        self.file = file
        self.fault = fault
        self.fio = fio
        self.calls = dict.fromkeys(('write', 'seek', 'truncate', 'flush'), 0)
        self.injected = False
        self.errors = []

    def attach(self, emulator, symbols):
        from unicorn import UC_HOOK_CODE
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_PC,
                                       UC_ARM_REG_SP)
        operations = {symbols['bridge_' + name] & ~1: name for name in self.calls}
        emulator.mem_write(symbols['disk_demo_fault'], struct.pack('<I', int(self.fault)))

        def intercept(uc, address, size, user_data):
            name = operations.get(address)
            if name is None:
                return
            self.calls[name] += 1
            # AAPCS32: uint64 argument after ctx is aligned to the R2/R3 pair.
            wide = uc.reg_read(UC_ARM_REG_R2) | uc.reg_read(UC_ARM_REG_R3) << 32
            result = 0
            try:
                if name == 'write':
                    pointer, requested = uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)
                    count = min(requested, 511)  # Exercise positive short writes.
                    if self.fault:
                        remaining = (232 + 32 + 3584 + 35) - self.file.tell()
                        if remaining <= 0:
                            self.injected = True
                            count = 0
                        else:
                            count = min(count, remaining)
                    result = self.file.write(bytes(uc.mem_read(pointer, count))) if count else (0xffffffff if self.fio else 0)
                elif name == 'seek':
                    if self.fio:
                        # ctx uses R0, int64 offset R2/R3, then whence on the stack.
                        whence = struct.unpack('<I', uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
                        result = self.file.seek(wide if wide < 1 << 63 else wide - (1 << 64), whence)
                    else:
                        self.file.seek(wide)
                elif name == 'truncate':
                    self.file.truncate(wide)
                elif name == 'flush':
                    self.file.flush()
                    os.fsync(self.file.fileno())
            except (OSError, OverflowError, ValueError) as error:
                self.errors.append(str(error))
                result = -1
            uc.reg_write(UC_ARM_REG_R0, result & 0xffffffff)
            if name == 'seek' and self.fio:
                uc.reg_write(UC_ARM_REG_R1, (result >> 32) & 0xffffffff)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        emulator.hook_add(UC_HOOK_CODE, intercept)


def verify(path, fault, fio=False):
    data = path.read_bytes()
    finalized = not (fault and fio)
    if not finalized:
        # The adapter MUST leave this as an unfinalized error, not claim repair.
        if len(data) != 3883 or struct.unpack_from('<I', data, 36)[0] != 0:
            raise RuntimeError('Unexpected unfinalized partial-tail layout')
        try:
            inspect_mlv(data)
        except ValueError:
            pass
        else:
            raise RuntimeError('Partial file was incorrectly accepted as finalized')
        prefix = bytearray(data[:3848])
        # For independent verification ONLY, normalize the in-memory prefix.
        # The actual file remains untouched and invalid until separately repaired.
        struct.pack_into('<I', prefix, 28, 8)
        struct.pack_into('<I', prefix, 36, 1)
        checked = prefix
    else:
        checked = data
    report = inspect_mlv(checked)
    ids = [0] if fault else [i for i in range(48) if i % 4 != 3]
    expected = []
    for frame_id in ids:
        crop_y = 2 * (frame_id % 3)
        payload = bytes((frame_id * 17 + i) % 256
                        for i in range(crop_y * 112, crop_y * 112 + 3584))
        expected.append({'number': frame_id, 'timestamp_us': frame_id * 1000000 // 24,
                         'crop_y': crop_y, 'payload_sha256': hashlib.sha256(payload).hexdigest()})
    if report['frames'] != expected or report['flags'] != (8 if fault else 2):
        raise RuntimeError('Disk output differs from the independent frame model')
    return {'path': str(path), 'complete_frames_verified': len(ids), 'bytes': len(data),
            'finalized': finalized, 'payloads_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', required=True, type=Path)
    parser.add_argument('--build-dir', type=Path, default=Path('.tools/raw14-tests'))
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='disk-run-', dir=build))
    compiler = args.toolchain.resolve() / 'arm-none-eabi-gcc'
    if compiler.with_suffix('.exe').exists():
        compiler = compiler.with_suffix('.exe')
    flags = [str(compiler), '-std=c99', '-Wall', '-Wextra', '-Werror', '-Os',
                    '-ffreestanding', '-fno-builtin', '-mcpu=cortex-r4', '-mthumb',
                    '-nostdlib', '-Wl,-e,test_run', '-Wl,-Ttext=0x10000', '-Wl,-Tdata=0x20000',
                    *[str(project / 'experimental' / f) for f in
                      ('raw14_copy.c', 'raw14_queue.c', 'raw14_mlv.c', 'raw14_disk_demo.c')],
                    '-lgcc']
    nm = compiler.with_name(compiler.name.replace('gcc', 'nm'))
    results = {}
    for backend, fio in (('direct', False), ('fio-contract', True)):
        elf = run / (backend + '.elf')
        extra = ['-DRAW14_USE_FIO', str(project / 'experimental/raw14_fio.c')] if fio else []
        subprocess.run([*flags, *extra, '-o', str(elf)], check=True)
        symbols = {}
        for line in subprocess.check_output([str(nm), str(elf)], text=True).splitlines():
            parts = line.split()
            if len(parts) == 3:
                symbols[parts[2]] = int(parts[0], 16)
        for name, fault in (('normal', False), ('partial-write', True)):
            case = backend + '-' + name
            path = run / (case + '.MLV')
            with path.open('xb', buffering=0) as file:
                bridge = ArmDiskIO(file, fault, fio)
                execute(elf, 'raw14_disk_demo.c', symbols, io_bridge=bridge,
                        instruction_limit=30_000_000)
            if bridge.errors or bridge.injected != fault or (fio and bridge.calls['truncate']):
                raise RuntimeError(f'Unexpected host IO outcome: {bridge.errors}')
            results[case] = {**verify(path, fault, fio), 'io_calls': bridge.calls,
                             'error_injected': bridge.injected}
    print(json.dumps({'passed': True, 'hardware_validated': False, 'cases': results}, indent=2))


if __name__ == '__main__':
    main()
