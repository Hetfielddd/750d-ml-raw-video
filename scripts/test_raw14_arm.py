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


def check_upstream_layout(compiler, source, build):
    """Compile assertions using actual upstream declarations, not our serializer."""
    text = (source / 'src/raw.h').read_text(encoding='utf-8')
    start = text.index('struct raw_info {')
    end = text.index('};\nSIZE_CHECK_STRUCT', start) + 2
    raw_declaration = text[start:end]
    checks = {
        'raw_size': 'sizeof(raw_info_t)==160',
        'file_size': 'sizeof(mlv_file_hdr_t)==52',
        'rawi_size': 'sizeof(mlv_rawi_hdr_t)==180',
        'video_size': 'sizeof(mlv_vidf_hdr_t)==32',
        'file_count': 'offsetof(mlv_file_hdr_t,videoFrameCount)==36',
        'file_fps': 'offsetof(mlv_file_hdr_t,sourceFpsNom)==44',
        'rawi_info': 'offsetof(mlv_rawi_hdr_t,raw_info)==20',
        'video_space': 'offsetof(mlv_vidf_hdr_t,frameSpace)==28',
        'video_crop_y': 'offsetof(mlv_vidf_hdr_t,cropPosY)==22',
        'video_pan_y': 'offsetof(mlv_vidf_hdr_t,panPosY)==26',
    }
    for field, offset in {'height': 8, 'width': 12, 'pitch': 16, 'frame_size': 20,
                          'bits_per_pixel': 24, 'black_level': 28, 'white_level': 32,
                          'cfa_pattern': 76, 'color_matrix1': 84}.items():
        checks['raw_' + field] = f'offsetof(raw_info_t,{field})=={offset}'
    generated = build / 'upstream_layout.c'
    generated.write_text('#include <stdint.h>\n#include <stddef.h>\n'
                         '/* Original declaration: Magic Lantern src/raw.h (GPL). */\n' +
                         raw_declaration + '\ntypedef struct raw_info raw_info_t;\n'
                         'typedef struct opaque_file FILE;\n#include "mlv.h"\n' +
                         '\n'.join(f'typedef char check_{key}[({expr})?1:-1];'
                                   for key, expr in checks.items()), encoding='utf-8')
    subprocess.run([str(compiler), '-std=c99', '-mcpu=cortex-r4', '-mthumb',
                    '-Wall', '-Wextra', '-Werror', '-c', str(generated),
                    '-I' + str(source / 'modules/raw_video/mlv_rec'),
                    '-o', str(build / 'upstream_layout.o')], check=True)
    return {'passed': True, 'assertions': len(checks)}


def execute(elf, test_source, symbols=None, sample=None, io_bridge=None,
            instruction_limit=2_000_000):
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
    if io_bridge is not None:
        io_bridge.attach(emulator, symbols)
    emulator.reg_write(UC_ARM_REG_SP, 0x4e000)
    emulator.reg_write(UC_ARM_REG_LR, sentinel | 1)
    emulator.emu_start(entry | 1, 0x50000, timeout=10_000_000, count=instruction_limit)
    if not stopped:
        raise RuntimeError(f'Test did not return (PC={emulator.reg_read(UC_ARM_REG_PC):#x})')
    line = emulator.reg_read(UC_ARM_REG_R0)
    if line:
        raise RuntimeError(f'ARM test assertion failed at {test_source}:{line}')
    if sample is not None:
        from inspect_raw14_mlv import inspect_mlv
        size = struct.unpack('<I', emulator.mem_read(symbols['mlv_test_size'], 4))[0]
        if not 0 < size <= 4096:
            raise RuntimeError('Invalid exported sample size')
        content = bytes(emulator.mem_read(symbols['mlv_test_output'], size))
        report = inspect_mlv(content)
        expected = [bytes(range(29, 85)), bytes(255 - i for i in range(56))]
        if ([f['number'] for f in report['frames']] != [0, 2] or
                [f['timestamp_us'] for f in report['frames']] != [0, 83333] or
                [f['crop_y'] for f in report['frames']] != [2, 0] or
                [f['payload_sha256'] for f in report['frames']] !=
                [hashlib.sha256(p).hexdigest() for p in expected]):
            raise RuntimeError('Independent sample verification failed')
        sample.write_bytes(content)
    return {'passed': True, 'target': 'ARMv7-R Thumb, Cortex-R4 compiler target',
            'emulator_cpu': 'Cortex-R5 (Unicorn)',
            'elf_sha256': hashlib.sha256(data).hexdigest(),
            'hardware_validated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', required=True, type=Path, help='Toolchain bin directory')
    parser.add_argument('--build-dir', type=Path, default=Path('.tools/raw14-tests'))
    parser.add_argument('--upstream-source', type=Path,
                        help='Optional pinned Magic Lantern checkout for wire-layout assertions')
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
    if args.upstream_source:
        results['upstream_layout'] = check_upstream_layout(compiler, args.upstream_source.resolve(), build)
    for suite, sources in {
        'copy': ['raw14_copy.c', 'test_raw14_copy.c'],
        'queue': ['raw14_copy.c', 'raw14_queue.c', 'test_raw14_queue.c'],
        'mlv': ['raw14_copy.c', 'raw14_queue.c', 'raw14_mlv.c', 'test_raw14_mlv.c'],
    }.items():
        elf = build / f'{suite}.elf'
        subprocess.run([str(compiler), *flags,
                        *[str(project / 'experimental' / name) for name in sources],
                        '-lgcc', '-o', str(elf)], check=True)
        symbols = {}
        if suite == 'mlv':
            nm = compiler.with_name(compiler.name.replace('gcc', 'nm'))
            for line in subprocess.check_output([str(nm), str(elf)], text=True).splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[2] in ('mlv_test_output', 'mlv_test_size'):
                    symbols[parts[2]] = int(parts[0], 16)
        results[suite] = execute(elf, sources[-1], symbols,
                                 build / 'synthetic-raw14.MLV' if suite == 'mlv' else None)
    print(json.dumps({'passed': True, 'suites': results}, indent=2))


if __name__ == '__main__':
    main()
