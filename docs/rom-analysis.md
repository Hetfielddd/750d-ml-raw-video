# Read-only ROM inspection

This PC-side tool prepares analysis of an independently supplied, owner-authorized plaintext ROM1 dump. It does not obtain a dump, connect to a camera, execute firmware, or modify the input.

```sh
python scripts/inspect_750d_rom.py /private/path/ROM1.BIN
python -m unittest discover -s scripts -p 'test_*.py' -v
```

The current input layout is deliberately narrow: a complete 32 MiB image corresponding to the QEMU EOS DIGIC 6 ROM1 mapping. Partial dumps and Canon FIR update containers are rejected. Other layouts require explicit mapping work rather than guessing offsets.

## Verified source interpretation

At upstream commit `142472e95054d73640f50789ac0fd66325499d82`:

- `src/fw-signature.h` defines `SIG_750D_110 = 0xf005931a` and `SIG_LEN = 0x10000`.
- Its `compute_signature(uint32_t *start, uint32_t num)` adds **65,536 32-bit words**, a 256 KiB window. The constant is a word count, not a byte count.
- The signature comment refers to `0xFC0A0000`, whereas the platform firmware entry is `0xFE0A0000`.
- QEMU EOS `hw/eos/model_list.c` maps the DIGIC 6 ROM1 at `0xFC000000`, size `0x02000000`; `eos_init_rom` in `hw/eos/eos.c` creates repeated aliases. Under this model, both entry addresses correspond to file offset `0xA0000`.

These mappings are source evidence, not independent hardware validation. The inspected QEMU EOS revision is `4b667a1d3c08ab7a55835d15ddbd884fa754946d`.

## Output and limitations

The report contains SHA-256, the additive firmware signature, selected RAW/EVF/Omar string locations, and bounded searches for their literal little-endian pointers through both ROM aliases.

A matching additive checksum is not cryptographic authentication and cannot prove an unmodified or complete ROM. Literal pointer hits are analysis candidates, not proven function references. The tool does not decode Thumb instructions, follow MOVW/MOVT address construction, identify the fast-copy function, or validate RAW buffers. Absence of a marker does not prove that a function is absent.

Tests use artificial in-memory data only. They cover FIR rejection, truncated images, word count and overflow, window boundaries, both alias pointers, and capped search results. Passing these tests does not mean a real 750D ROM has been analyzed.

## Research refresh: November 24, 2026

The upstream `dev` head remained `142472e95054d73640f50789ac0fd66325499d82` when fetched. The reviewed Tragic Lantern default branch still showed Lua/PTP-related work rather than a verified 750D RAW frame-copy implementation. The forum topic returned HTTP 403 again. No usable plaintext dump or missing validated RAW address was acquired.

Next prerequisite for actual capture implementation remains plaintext 750D 1.1.0 analysis material or independently verified address findings. Camera-side code and the pinned upstream submodule have not been changed.

Sources:

- https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/src/fw-signature.h
- https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/platform/750D.110/Makefile
- https://github.com/reticulatedpines/qemu-eos/blob/qemu-eos-v4.2.1/hw/eos/model_list.c
- https://github.com/reticulatedpines/qemu-eos/blob/qemu-eos-v4.2.1/hw/eos/eos.c

## Targeted 750D source audit and instruction candidates

A further read-only audit on November 24, 2026 checked upstream 750D commit history and the Tragic Lantern main branch at `aa224f0bc8e177a456c119eba00263488ee51f5a`. No usable RAW channel, shadow-reader implementation, or fast-copy binding was found in the reviewed material. This is a scoped search result, not a claim that no private or unindexed implementation exists. Some broad GitHub searches timed out; narrower repository searches completed.

The Tragic Lantern 750D `function_overrides.c` still implements `shamem_read` as `return 0`; its reviewed `internals.h` does not enable RAW Live View or EVF state synchronization, and its `consts.h` supplies no RAW channel definition. Its recent platform history concerns PTP/Lua and related development workflows. The PTP registration stub also exists in our pinned upstream source; discovering that commit is not a new RAW address finding.

The upstream commit [aad23944](https://github.com/reticulatedpines/magiclantern_simplified/commit/aad2394431d388f11c54c0a872145e7b295f6127), despite mentioning crop_rec in its title, adds only `SRM_BUFFER_SIZE=0x296c000`. A memory-resource block size is not a RAW source pointer or evidence of working RAW capture.

Two tempting tool paths were checked and excluded:

- Upstream `tools/firmware/edmac_config.py` has a broad description, but its `CPU.DIGIC_6` constructor explicitly raises an unsupported error. DIGIC 7/8 configuration-table layouts cannot simply be applied to 750D.
- [lclevy/d8_oracle](https://github.com/lclevy/d8_oracle) documents DIGIC 8 update decryption using an EOS R/RP ROM dump and emulated camera code. It supplies no dump and is not a demonstrated 750D/DIGIC 6 or FIR-only solution. No such decryption was performed here.

Added [Thumb address-load candidate analysis](thumb-xrefs.md) to extend the existing literal-pointer search with instruction encoding checks. It finds narrow LDR-literal and adjacent MOVW/MOVT patterns and reports both ROM aliases. Tests use artificial images and GNU-assembled Thumb instructions. No plaintext 750D ROM, actual firmware reference, or validated capture address has been obtained by this step. The official FIR remains encrypted and the camera source/submodule pin remains unchanged.

Reviewed primary source snapshots:

- https://github.com/paweltokarz/tragiclantern/blob/aa224f0bc8e177a456c119eba00263488ee51f5a/platform/750D.110/function_overrides.c
- https://github.com/paweltokarz/tragiclantern/blob/aa224f0bc8e177a456c119eba00263488ee51f5a/platform/750D.110/internals.h
- https://github.com/paweltokarz/tragiclantern/blob/aa224f0bc8e177a456c119eba00263488ee51f5a/platform/750D.110/consts.h
- https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/tools/firmware/edmac_config.py

## Older branches and the actual FIR boundary

The follow-up audit checked these immutable branch snapshots from the original port contributor's fork:

- [`raw_draft`](https://github.com/kitor/magiclantern_simplified/tree/623fe9ce969510b5fa71a839448ebb7b372f5ff9)
- [`raw_draft_v2`](https://github.com/kitor/magiclantern_simplified/tree/26822466884ba43bc21cefc49346706638cb7fa3)
- [`d6_rom_patching`](https://github.com/kitor/magiclantern_simplified/tree/fcc52129d9a65250d477af45e2ea4f974531fa8f)
- Upstream [`edmac_cleanup`](https://github.com/reticulatedpines/magiclantern_simplified/tree/562c699589a98989e66ff2d0634748cf0f14bc44)

The reviewed 750D internals/constants/overrides/stubs in the three contributor branches still supply no RAW channel or fast-copy binding and retain the zero-return `shamem_read`. The reviewed cleanup-branch constants/overrides retain the same gaps. A branch named RAW is not proof of 750D support: the inspected `raw_draft_v2` RAW history includes EOS R work. The `d6_rom_patching` head reads CPU debug registers; it does not provide the missing sensor transfer implementation. None of these branches was installed, executed, or merged into the project.

Two older QEMU changes mentioning 750D were also inspected: [MEMDIV initialization](https://github.com/reticulatedpines/magiclantern_simplified/commit/cd374396a1378a8504f6afb514139bc912cfe63d) and [serial-flash DMA](https://github.com/reticulatedpines/magiclantern_simplified/commit/2ae6ea82819303ed25cc24da75a72fd0a2912a0c). The first adds modeled shared-memory setup behavior, while the second models serial-flash transfers. Neither establishes a RAW Live View channel or complete-frame lifetime. Their MMIO addresses and DMA identifiers must not be substituted for sensor-channel evidence.

A filename-only search in the configured Codex working folders found the already known official update and upstream `detect_rom_test_files` samples. The latter `rom1.bin`/`rom0.bin` are only 64/69 bytes, not full firmware images. This was not a search of the entire computer. No usable plaintext 750D image was found.

The actual `CCF23110.FIR` was rechecked with the enhanced read-only inspector. Its SHA-256 remains `91ae807b6ac27dcb9c2c6351557c131768cc06736957600fdd0f5014e5531450` and its container checksum passes. The updater ciphertext is 2,509,264 bytes; firmware ciphertext is 21,117,280 bytes with declared content length 21,117,272 bytes. These are container fields, not extracted code or validated RAM mappings.

The extended updater header is nonzero. The reviewed modern `fir_tool2.py` extraction policy skips its legacy XOR decoder in this case. The enhanced inspector reports `skip_extended_header` and `decrypted: false`; this header heuristic does not establish an encryption key, exact cryptographic scheme, or signature authenticity. Running the old XOR transform regardless would not demonstrate successful decryption.

The inspector now checks updater overlap, supported header spacing, firmware ciphertext bounds, and declared lengths in addition to identity and checksum. Four new tests include malformed sections with recomputed valid checksums, demonstrating why checksum success alone is insufficient. All 19 Python tests pass, and the real FIR passes the strengthened structural checks. The tool writes no firmware or decoded output.

At this checkpoint the remaining obstacle to finding actual capture addresses is readable 750D firmware material or independently substantiated address findings. Further synthetic recorder tests cannot substitute for that evidence. An already saved PC-side image would permit further analysis without interacting with the camera; no camera-side extraction has been requested or performed.

## FIR-only investigation after choosing the PC-only route

The owner confirmed that no saved dump is available and selected continued public-source/FIR research. This does not authorize running a dumper, PTP operations, an installer, or other code on the camera. The investigation below used only the existing PC files and public material.

[Check Point's primary EOS 80D research](https://research.checkpoint.com/2019/say-cheese-ransomware-ing-a-dslr-camera/) is directly relevant to DIGIC 6. Its researchers encountered an encrypted official update and obtained their readable firmware with a camera-side ROM dumper. They subsequently located cryptographic functions and keys in that firmware. The article therefore demonstrates a dump-dependent research path, not a FIR-only decryptor. Its discussion does not supply the needed 750D key material or executable decryption code. No exploit or camera interaction from that research was reproduced here.

[The Digic8 Oracle author's Hack.lu 2025 abstract](https://pretalx.com/hack-lu-2025/talk/3UEDY8/) distinguishes pre-2018 FIR cryptography from later models and explicitly requires an existing dump for its emulator-based method. It says no key or firmware dump accompanies the talk. Its claim about sharing key material within DIGIC 8 is not evidence that DIGIC 6/750D uses the same material or that the published emulator can process our FIR. Knowing the container layout, encryption algorithm family, checksum, or authentication fields does not supply a decryption key.

The pinned public `installer/750D.110/Makefile` selects `CCF23110.FIR`; the common `installer/Makefile` invokes `../../../dumper/build_fir.py`. That builder is absent from the checked public source tree. A build recipe referencing an external tool is not a working bundled encryption/decryption implementation. Searches for the builder found references rather than a verified 750D decryptor. Some GitHub repository searches timed out, so this is not an exhaustive claim about all public repositories.

A local read-only exact-byte search covered both declared ciphertext regions in the actual FIR: updater at `0x120` (2,509,264 bytes) and firmware payload at `0x264b70` (21,117,280 bytes). None contained the seven selected markers: `DRYOS version`, `DRYOS PANIC`, `gaonisoy`, `lv_save_raw`, `evfReadOutDoneInterrupt`, `Mem1 is Not Complete`, or `CCDWriteEDmacCompleteCBR`. SHA-256 before/after matched. The full small result is in [the marker-search evidence](evidence/fir-marker-search.json); it includes no firmware bytes.

Absence of these exact markers is not proof that every byte is encrypted or that decryption is impossible. It simply yielded no obvious plaintext lead in this experiment. No key was recovered, no plaintext payload was produced, and no RAW capture address was validated. The existing structural inspector still passes for the official file; this is not a new decryption or recorder milestone.

The next evidence that would change this result is a verifiable published 750D plaintext image, applicable DIGIC 6 decryption implementation with its required material, or independently substantiated firmware analysis. Public-source research may continue under the PC-only constraint, but the reviewed methods do not currently remove the missing-input dependency. No brute-force success, estimated completion date, or camera-readiness claim is justified by this investigation.
