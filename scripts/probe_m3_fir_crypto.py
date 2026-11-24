# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded PC-only crypto experiment using one identified public M3 ROM.

Not a 750D decryptor. Requires locally supplied ROM/FIR and Unicorn 2.1.4.
No ROM bytes, keys, IVs or decrypted firmware are emitted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROM_SHA256 = '0545a9a2996b9fbd96dfc2c54d80c0f1b17867e1d9c2803660be9ca16c511fa2'
FIR_SHA256 = '91ae807b6ac27dcb9c2c6351557c131768cc06736957600fdd0f5014e5531450'
BASE = 0xfc000000


def probe(rom, fir):
    # Check before importing Unicorn or executing any supplied bytes.
    if len(rom) != 0x2000000 or hashlib.sha256(rom).hexdigest() != ROM_SHA256:
        raise ValueError('Expected the identified public M3 1.01A full ROM')
    if len(fir) != 23626960 or hashlib.sha256(fir).hexdigest() != FIR_SHA256:
        raise ValueError('Expected the identified official 750D 1.1.0 FIR')
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                         UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A9, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR)
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    # Pure Thumb integer routines; A9 permits execution at the ROM address.
    # R5 rejected this mapping in the tested setup; the cause was not isolated.
    # This does not configure a Canon MPU or model Canon peripherals.
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    uc.mem_map(BASE, len(rom), UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(BASE, rom)
    uc.mem_map(0x100000, 0xf000, UC_PROT_READ | UC_PROT_WRITE)
    stop = 0x10f000
    uc.mem_map(stop, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    state = {'returned': False, 'unexpected_pc': None}

    def guard(emulator, address, size, _):
        if address == stop:
            state['returned'] = True
            emulator.emu_stop()
        elif not (0xfc200ff8 <= address and address + size <= 0xfc2014d4 or
                  0xfc565dde <= address and address + size <= 0xfc565ef4 or
                  address == 0xfc565d34 and size == 4):  # Shared return.
            state['unexpected_pc'] = hex(address)
            emulator.emu_stop()

    uc.hook_add(UC_HOOK_CODE, guard)

    def call(address, *args):
        state.update(returned=False, unexpected_pc=None)
        uc.reg_write(UC_ARM_REG_SP, 0x10e000)
        uc.reg_write(UC_ARM_REG_LR, stop | 1)
        registers = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        for register, value in zip(registers, args):
            uc.reg_write(register, value)
        uc.emu_start(address | 1, stop + 4, count=100000, timeout=2_000_000)
        if not state['returned']:
            raise RuntimeError(f'Routine failed to return within its bounds: {state}')
        return uc.reg_read(UC_ARM_REG_R0)

    key, context, source, output = 0x100000, 0x100100, 0x100300, 0x100400
    # The key schedule takes four native words representing big-endian key
    # words; byte-swapping the public NIST key is needed at that interface.
    nist_key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    uc.mem_write(key, b''.join(nist_key[i:i + 4][::-1] for i in range(0, 16, 4)))
    call(0xfc200ff8, key, context)
    ciphertext = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    plaintext = bytes.fromhex('00112233445566778899aabbccddeeff')
    uc.mem_write(source, ciphertext)
    call(0xfc2012b6, source, output, context)
    if bytes(uc.mem_read(output, 16)) != plaintext:
        raise RuntimeError('NIST AES-128 decryption failed')

    # Also verify the CBC length wrapper, not just the underlying AES block.
    # Read the IV pointer from its literal pool, keeping bytes out of reports.
    iv_address = struct.unpack_from('<I', rom, 0x565ef0)[0]
    if not BASE <= iv_address <= BASE + len(rom) - 16:
        raise ValueError('IV pointer lies outside the identified ROM')
    iv = bytes(uc.mem_read(iv_address, 16))
    uc.mem_write(source, plaintext)
    call(0xfc2010c4, source, output, context)
    if bytes(uc.mem_read(output, 16)) != ciphertext:
        raise RuntimeError('NIST AES-128 encryption failed')
    for size in (0, 12, 28, 44):
        payload = bytes(range(size))
        blocks = struct.pack('>I', size) + payload
        blocks += bytes((-len(blocks)) % 16)
        generated = bytearray()
        previous = iv
        for offset in range(0, len(blocks), 16):
            block = blocks[offset:offset + 16]
            uc.mem_write(source, bytes(a ^ b for a, b in zip(block, previous)))
            call(0xfc2010c4, source, output, context)
            previous = bytes(uc.mem_read(output, 16))
            generated.extend(previous)
        uc.mem_write(source, bytes(generated))
        if call(0xfc565df0, source, context) != size:
            raise RuntimeError('Generated length-header check failed')
        if call(0xfc565e2e, source, len(generated), output, context) != size:
            raise RuntimeError('Generated CBC wrapper length check failed')
        if bytes(uc.mem_read(output, size)) != payload:
            raise RuntimeError('Generated CBC wrapper payload check failed')

    # The updater's initialized RAM function pointer resolves to the ROM
    # key accessor at FC000009, which returns FC00409C (static disassembly).
    accessor = call(0xfc565dde, 12)  # Independent size helper sanity check.
    if accessor != 16:
        raise RuntimeError('Encrypted-size helper check failed')
    call(0xfc200ff8, 0xfc00409c, context)
    observations = []
    for label, offset, available in (('updater', 0x120, 0x2649d0),
                                     ('firmware', 0x264b70, 21117280)):
        uc.mem_write(source, fir[offset:offset + 16])
        length = call(0xfc565df0, source, context)
        needed = (length + 4 + 15) & ~15
        observations.append({'region': label, 'file_offset': hex(offset),
                             'candidate_plaintext_length': length,
                             'encrypted_region_size': available,
                             'candidate_fits_region': needed <= available})
    return {'rom_sha256': ROM_SHA256, 'fir_sha256': FIR_SHA256,
            'emulator_cpu': 'Cortex-A9, integer Thumb routines only',
            'nist_aes128_decryption_passed': True,
            'nist_aes128_encryption_passed': True,
            'generated_cbc_wrapper_roundtrip_passed': True,
            'generated_cbc_wrapper_payload_sizes': [0, 12, 28, 44],
            'instruction_limit_per_call': 100000,
            'timeout_microseconds_per_call': 2000000,
            'observations': observations,
            'firmware_decrypted': False,
            'conclusion': 'The M3 native key/IV/wrapper applied directly at '
                          'these two 750D payload starts fails its length bounds. '
                          'This does not establish the 750D algorithm or key, '
                          'or rule out another transformation or framing.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rom', type=Path)
    parser.add_argument('fir', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.rom.read_bytes(), args.fir.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
