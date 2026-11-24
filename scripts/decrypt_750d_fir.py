# SPDX-License-Identifier: GPL-2.0-or-later
"""PC-only 750D 1.1.0 FIR extraction using one identified public 70D ROM.

Runs only the donor's isolated crypto component, not a camera boot or updater.
Never emits keys or creates an installable FIR. Firmware outputs are private.
Requires Unicorn 2.1.4. Input identities are checked before native execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from inspect_750d_fir import inspect_bytes

DONOR_SHA256 = '3fe42299deb577b269b6901f40597a1939ac5876f22c8c3a0b6ee47219fdd42e'
FIR_SHA256 = '91ae807b6ac27dcb9c2c6351557c131768cc06736957600fdd0f5014e5531450'
MAIN_SHA256 = '3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_records(data):
    """Validate the decrypted record container, without guessing ROM holes."""
    if len(data) < 32:
        raise ValueError('Truncated decrypted record container')
    checksum = struct.unpack_from('<I', data)[0]
    if checksum != (~sum(data[4:])) & 0xffffffff:
        raise ValueError('Decrypted record checksum mismatch')
    count, table, stride, tail = struct.unpack_from('<4I', data, 16)
    if not 1 <= count <= 64 or table != 32 or stride != 24:
        raise ValueError('Unsupported record table layout')
    table_end = table + count * stride
    if table_end + tail != len(data):
        raise ValueError('Record table/tail size mismatch')
    records, ids, previous_end = [], set(), table_end
    for index in range(count):
        number, tag, offset, size, address, auxiliary = struct.unpack_from(
            '<6I', data, table + index * stride)
        if number in ids or number == 0 or size == 0:
            raise ValueError('Invalid or duplicate record identifier/size')
        if offset < previous_end or offset > len(data) or size > len(data) - offset:
            raise ValueError('Record payload overlaps or exceeds its container')
        ids.add(number)
        previous_end = offset + size
        records.append({'number': number, 'tag': hex(tag),
                        'payload_offset': hex(offset), 'bytes': size,
                        'destination': hex(address), 'auxiliary': auxiliary,
                        'sha256': digest(data[offset:offset + size])})
    return records


def decrypt(rom, fir, progress=None):
    if len(rom) != 0x1000000 or digest(rom) != DONOR_SHA256:
        raise ValueError('Expected the identified public 70D 1.1.2 ROM1')
    if len(fir) != 23626960 or digest(fir) != FIR_SHA256:
        raise ValueError('Expected the identified official 750D 1.1.0 FIR')
    layout = inspect_bytes(fir)
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE,
                         UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    # Static loader evidence: donor file FD5000..FE1310 is linked at 200000.
    # Code pages are RX; initialized data, allocator arena and BSS are RW/NX.
    uc.mem_map(0x200000, 0x6000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(0x206000, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(0x200000, rom[0xfd5000:0xfe1310])
    uc.mem_map(0x800000, (len(fir) + 4095) & ~4095, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(0x800000, fir)
    uc.mem_map(0x100000, 0xe000, UC_PROT_READ | UC_PROT_WRITE)
    stop = 0x10f000
    uc.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
    returned = []

    def finish(emulator, address, size, _):
        returned.append(True)
        emulator.emu_stop()

    uc.hook_add(UC_HOOK_CODE, finish, begin=stop, end=stop)

    def call(name, address, *args, must_succeed=False):
        if progress:
            progress(name)
        returned.clear()
        uc.reg_write(UC_ARM_REG_SP, 0x10dff0)
        uc.reg_write(UC_ARM_REG_LR, stop)
        for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1,
                                     UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            uc.reg_write(register, value)
        uc.emu_start(address, stop + 4, count=3_000_000_000, timeout=45_000_000)
        if not returned:
            raise RuntimeError(f'{name}: instruction/time limit reached')
        result = uc.reg_read(UC_ARM_REG_R0)
        if must_succeed and result != 0:
            raise ValueError(f'{name}: native routine rejected the data')
        return result

    context = 0x100100
    call('Initialize verification context', 0x202e38, context, 0x206d58)
    call('Verify header/updater regions', 0x202468, 0x800000, context, must_succeed=True)
    call('Verify firmware region', 0x2025a0, 0x800000, context, must_succeed=True)
    call('Initialize decryption context', 0x202e84, context, 0x206d50)
    call('Decrypt updater', 0x20298c, 0x8000b0, context, must_succeed=True)
    call('Decrypt firmware', 0x20298c, 0x800000 + 0x264b00, context, must_succeed=True)
    updater = bytes(uc.mem_read(0x800120, layout['updater_declared_content_bytes']))
    firmware = bytes(uc.mem_read(0x800000 + 0x264b70, layout['firmware_declared_content_bytes']))
    records = parse_records(firmware)
    main_record = next((r for r in records if r['number'] == 6 and
                        r['tag'] == '0x100' and r['destination'] == '0xfc0a0000'), None)
    if main_record is None:
        raise ValueError('Expected main-code record missing')
    offset = int(main_record['payload_offset'], 16)
    main = firmware[offset:offset + main_record['bytes']]
    if digest(main) != MAIN_SHA256 or len(main) < 0x40000:
        raise ValueError('Main-code record identity mismatch')
    signature = sum(struct.unpack_from('<65536I', main)) & 0xffffffff
    if signature != 0xf005931a:
        raise ValueError('Main-code record does not match upstream 750D 1.1.0 signature')
    report = {'donor_sha256': DONOR_SHA256, 'fir_sha256': FIR_SHA256,
              'native_header_verification_passed': True,
              'native_firmware_verification_passed': True,
              'native_decryption_passed': True,
              'independent_decrypted_checksum_passed': True,
              'updater_bytes': len(updater), 'updater_sha256': digest(updater),
              'firmware_bytes': len(firmware), 'firmware_sha256': digest(firmware),
              'main_code_additive_signature': hex(signature),
              'matches_upstream_750d_110_signature': True, 'records': records,
              'full_rom_reconstructed': False, 'camera_execution_performed': False,
              'raw_video_recording_implemented': False,
              'limits': 'Update records are not a complete flash dump. Native '
                        'verification is reported against this identified public '
                        'donor, not independently authenticated Canon trust roots.'}
    return report, updater, firmware


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('donor_rom', type=Path)
    parser.add_argument('fir', type=Path)
    parser.add_argument('--output-dir', type=Path, help='New private directory outside this repository')
    args = parser.parse_args()
    if args.output_dir:
        destination = args.output_dir.resolve()
        if destination.is_relative_to(Path(__file__).resolve().parents[1]) or destination.exists():
            parser.error('Output must be a new private directory outside the repository')
    report, updater, firmware = decrypt(args.donor_rom.read_bytes(), args.fir.read_bytes(),
                                       progress=lambda name: print(name, file=sys.stderr, flush=True))
    if args.output_dir:
        destination.mkdir(parents=True, exist_ok=False)
        (destination / 'updater.bin').write_bytes(updater)
        (destination / 'firmware-records.bin').write_bytes(firmware)
        for record in report['records']:
            offset = int(record['payload_offset'], 16)
            (destination / f"record-{record['number']:02d}.bin").write_bytes(
                firmware[offset:offset + record['bytes']])
        (destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
