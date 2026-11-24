# 750D 1.1.0 plaintext recovered on the PC

On November 24, 2026, the official 750D 1.1.0 FIR was successfully decrypted using an isolated crypto component from a publicly available Canon 70D 1.1.2 ROM. Both the updater and main update-record container were recovered. This removes the missing-plaintext barrier for analysis of the target's main code. It does not implement RAW recording or reconstruct a full bootable flash dump.

## Inputs and provenance

The independent donor source is [this public 70D ROM entry](https://github.com/peva3/magiclantern_70D/blob/302806f5fb58a52ce458f65fb9612430ea0cf589/roms/70D/ROM1.BIN). It is not a mirror of the previously blocked 750D external-folder lead.

- Donor: 16,777,216 bytes, SHA-256 `3fe42299deb577b269b6901f40597a1939ac5876f22c8c3a0b6ee47219fdd42e`.
- Its computed Git blob SHA-1 matches the repository tree entry: `ddeefa968f6b3e6d0ac720745e09eff01dcb4bc1`.
- Its 65,536-word additive sum at file offset `0xc0000` matches upstream `SIG_70D_112 = 0xd8698f05`.
- Target input: the existing 23,626,960-byte `CCF23110.FIR`, SHA-256 `91ae807b6ac27dcb9c2c6351557c131768cc06736957600fdd0f5014e5531450`.

The donor identity and source are recorded, but this is not independent cryptographic authentication of Canon's trust roots. No image, key, IV, proprietary disassembly or decrypted code is included in this repository. All firmware files remain in the private analysis area outside the checkout. The original FIR is unchanged.

## What executed

Static inspection of the donor's update-loading path identifies a component copied from donor file offsets `0xfd5000..0xfe1310`. Its code is linked at `0x200000`; the original loader uses a cached address alias. The PC experiment maps its code pages read/execute, and its initialized data, allocator arena, BSS and input buffer read/write without execute permission. A separate executable return sentinel ends each call.

The script initializes the native verification context, verifies the header/updater region group and the firmware region, then initializes the decryption context and decrypts each 112-byte-header section. It does not boot the donor, execute the updater, emulate flash writes, intercept camera I/O, or contact any hardware. The isolated component's return values are checked; each call has a three-billion-instruction budget and a 45-second timeout.

The two native verification calls and both decryption calls return zero on the actual input. The algorithm is used as an oracle; the complete key derivation and authentication algorithm have not been independently reimplemented.

## Independent checks and outputs

- Updater: 2,509,264 bytes; SHA-256 `08b416ba1152a3975a6102264ba9631b4446309f2f4bb0a3e87e4815fd506f06`.
- Decrypted record container: 21,117,272 bytes; SHA-256 `7df2f81d098cb27ce315c3e90c665f5d1f01e385cd0793afa237633dca02b644`.
- Its first-word checksum matches the independently computed complement of the sum of every subsequent byte: `0x92221947`.
- Nine records have a bounded, non-overlapping table and payload layout. Tag interpretation follows the older public `dump_fir.py` tool; auxiliary fields remain uninterpreted.
- Record 6 is main code destined for `0xfc0a0000`, size 13,612,680 bytes. SHA-256: `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`.
- The first 65,536 words of that record sum to `0xf005931a`, exactly matching upstream `SIG_750D_110`.
- Two separately constructed emulator runs produced the same updater and main-record hashes.

As negative controls, a byte in each ciphertext section was changed and the outer byte checksum recomputed. In these test runs only, the expected input hash was adjusted to admit the deliberately mutated fixture; production identity gates were not changed. The native header/updater verification rejects the first mutation, and native firmware verification rejects the second. Neither test emits plaintext outputs. These checks are stronger than accepting readable strings alone.

The metadata-only results are [decryption and records](evidence/750d-decryption.json) and [native rejection controls](evidence/750d-native-rejections.json).

## Reproduction

With Unicorn 2.1.4 available to Python:

```sh
python scripts/decrypt_750d_fir.py /private/70D-ROM1.BIN /private/CCF23110.FIR
python scripts/decrypt_750d_fir.py /private/70D-ROM1.BIN /private/CCF23110.FIR --output-dir /private/new-750d-analysis
```

Without `--output-dir`, only metadata goes to stdout. With it, validated records are written into a new directory outside this checkout. Existing directories are refused. The hashes of both input files are checked before native execution; no output is written unless all checks succeed. These outputs are analysis records, not installation files.

The record parser rejects malformed tables, overlaps, out-of-bounds sizes, duplicate identifiers and checksum failures even when a test recalculates the outer checksum. All 27 Python tests pass. Existing recorder C code did not change in this step.

## First target-specific RAW finding

The main-code record contains exact strings and address-load candidates for `lv_save_raw`, `lv_raw_dump`, `evfReadOutDoneInterrupt`, `CCDWriteEDmacCompleteCBR` and `OmarInit`. Offsets are relative to this record, not a complete ROM file. The [bounded candidate report](evidence/750d-raw-marker-candidates.json) records the input hash and mapping explicitly.

At the `0xfe309854` runtime alias, a named-registration sequence pairs `lv_save_raw` with Thumb pointer `0xfe308eb5`; `lv_raw_dump` is paired with `0xfe308fe5`. The existing ML `call` stub at `0xfe445e02` matches the target code's named event-procedure dispatcher. Static disassembly shows that the small `lv_save_raw` routine reads an argument word and modifies a state structure at `0x2af78`.

`probe_750d_lv_toggle.py` executes only that identified setter against synthetic RAM, with exact main-record identity checks, a 100-instruction bound, an execution-range guard and a write-address guard. Four cases pass: the requested value is stored at state offset 4, and a nonzero auxiliary word at offset 12 is cleared only when enabling. All other bytes in the observed state block remain unchanged.

```sh
python scripts/probe_750d_lv_toggle.py /private/new-750d-analysis/record-06.bin
```

[Saved target-function result](evidence/750d-lv-toggle.json). These are analysis findings, not enabled platform bindings. This experiment does not demonstrate a RAW stream, a correct DMA channel, completed-frame ownership, cache behavior, geometry, throughput or hardware safety.

## What remains

We can now trace the actual 750D RAW-control state and image-transfer callbacks. The next work is to follow the setter's consumers and identify the RAW Live View source, its dimensions/packing and the event that makes a buffer safe to copy. Then the existing offline recorder needs verified target copy and file-operation integration.

The update does not contain every flash region, calibration value or boot dependency. No fabricated full ROM with guessed filler has been created; full-camera QEMU boot is still unverified. No camera or SD-card access occurred. Real RAW recording remains unimplemented, but the project has moved from searching for readable target code to analyzing it directly.
