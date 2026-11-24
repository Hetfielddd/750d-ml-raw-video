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
