# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile the experimental copy core for ARMv7-R and run it in Unicorn.

Requires Arm GNU Toolchain and unicorn==2.1.4. No ROM or camera is used.
Unicorn's Cortex-R5 model exercises the ARMv7-R/Thumb code generated for R4;
it does not emulate Canon peripherals, DMA, cache coherence or interrupts.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def execute(elf, test_source):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0,
                                   UC_CPU_ARM_CORTEX_R5, UC_ARM_REG_PC)
    data = elf.read_bytes()
    if data[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Expected little-endian ELF32')
    fields = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
    if fields[1] != 40:
        raise ValueError('Expected ARM ELF')
    entry, phoff, phsize, phcount = fields[3], fields[4], fields[8], fields[9]
    emulator = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    emulator.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_R5)
    # A flat, zero-initialized test address space; not Canon's memory map.
    emulator.mem_map(0x10000, 0x40000)
    for index in range(phcount):
        kind, offset, address, _, filesz, memsz, _, _ = struct.unpack_from(
            '<IIIIIIII', data, phoff + index * phsize)
        if kind != 1:
            continue
        if not (0x10000 <= address and address + memsz <= 0x50000):
            raise ValueError('Test segment outside the fixed test memory map')
        if offset + filesz > len(data) or filesz > memsz:
            raise ValueError('Invalid ELF segment bounds')
        emulator.mem_write(address, data[offset:offset + filesz])
    sentinel = 0x4f000
    stopped = []

    def stop_at_return(uc, address, size, user_data):
        if address == sentinel:
            stopped.append(True)
            uc.emu_stop()

    emulator.hook_add(UC_HOOK_CODE, stop_at_return)
    emulator.reg_write(UC_ARM_REG_SP, 0x4e000)
    emulator.reg_write(UC_ARM_REG_LR, sentinel | 1)
    emulator.emu_start(entry | 1, 0x50000, timeout=5_000_000, count=2_000_000)
    if not stopped:
        raise RuntimeError(f'Test did not return (PC={emulator.reg_read(UC_ARM_REG_PC):#x})')
    line = emulator.reg_read(UC_ARM_REG_R0)
    if line:
        raise RuntimeError(f'ARM test assertion failed at {test_source}:{line}')
    return {'passed': True, 'target': 'ARMv7-R Thumb, Cortex-R4 compiler target',
            'emulator_cpu': 'Cortex-R5 (Unicorn)',
            'elf_sha256': hashlib.sha256(data).hexdigest(),
            'hardware_validated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', required=True, type=Path, help='Toolchain bin directory')
    parser.add_argument('--build-dir', type=Path, default=Path('.tools/raw14-tests'))
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    compiler = args.toolchain.resolve() / 'arm-none-eabi-gcc'
    if compiler.with_suffix('.exe').exists():
        compiler = compiler.with_suffix('.exe')
    flags = ['-std=c99', '-Wall', '-Wextra', '-Werror', '-Os', '-ffreestanding',
             '-fno-builtin', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
             '-mcpu=cortex-r4', '-mthumb', '-nostdlib', '-Wl,-e,test_run',
             '-Wl,-Ttext=0x10000', '-Wl,-Tdata=0x20000']
    results = {}
    for suite, sources in {
        'copy': ['raw14_copy.c', 'test_raw14_copy.c'],
        'queue': ['raw14_copy.c', 'raw14_queue.c', 'test_raw14_queue.c'],
    }.items():
        elf = build / f'{suite}.elf'
        subprocess.run([str(compiler), *flags,
                        *[str(project / 'experimental' / name) for name in sources],
                        '-lgcc', '-o', str(elf)], check=True)
        results[suite] = execute(elf, sources[-1])
    print(json.dumps({'passed': True, 'suites': results}, indent=2))


if __name__ == '__main__':
    main()
