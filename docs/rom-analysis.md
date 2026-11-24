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
