# Primary-core copy candidate and cache preparation

A target-specific copy candidate is now identified at **`0xFE133EB2`**. It accepts channel, destination, source and byte count, constructs a one-element copy list, validates channel/controller conditions and prepares an OS wait. Its downstream descriptor path contains explicit cache preparation. This is a candidate backend for a future port, not a validated DMA copy or an enabled Magic Lantern stub.

## Native wrapper admission

The entry stores the native triplet `[destination, source, count]` on its stack and calls validator `0xFE133E7E` with list count 1. The reviewed condition requires a channel below 4, its bit present in global mask `0x257A0`, and bit 28 set in controller word `0xD6030000`. The full validator also rejects list counts above 8.

Six native fixtures cover channel 0 accepted/rejected by the supplied mask/status, invalid channel 4, accepted channel 1, and a zero-byte request. Accepted fixtures stop before `0xFE3CE0AC` with the supplied per-channel handle from `0x40844 + channel * 4`, argument 1 equal to zero, and the original triplet preserved. Invalid mask/channel returns `0xFFFFFFFF`; missing controller status bit returns `0xFFFFFFFE`.

Zero byte count passes this **initial** admission test; no claim is made that it performs a transfer or that the downstream path accepts every size/alignment. The OS wait and its timeout semantics are not executed or assumed. Controller status is supplied read-only ordinary RAM, not a device model or a camera measurement.

## Downstream copy and cache path from static review

After its first wait, the wrapper calls the core at `0xFE133D92` through `0xFE133E7C`. That core handles a list of 12-byte `[destination, source, count]` entries. In the reviewed nonzero-count path:

1. Source at entry + 4 is passed to cache dispatcher `0xFE133BAC` with operation 0.
2. Destination at entry + 0 is passed to the same dispatcher with operation 1.
3. Descriptor builder `0xFE133BF4` converts both addresses through actual classifier-based converter `0xFE175544` and constructs a descriptor.
4. The descriptor block itself is passed through operation 0 before submission helper `0xFE133B22`.

The submission helper writes a separate controller beginning at **`0xD6030000`**, sets a channel start field and uses completion-related OS state. It is distinct from the sensor RAW writer at `0xD0004100`. None of that submission, completion, OS execution or actual copying is part of this probe.

## Native memory classification and cache dispatch

The primary classifier `0xFE175500` consults a range list rooted at `0x25770 + 4`. Static initializer `0xFE17580E` builds classification entries from CPU TCM/MPU registers, including size reader `0xFE175564` and attribute decoder `0xFE17589C`. The live list and MPU values remain unknown; this experiment supplies one artificial catch-all record rather than inventing a primary memory map.

Two native decoder cases enter after the CP15 reads with supplied access words from the [MPU operand investigation](750d-raw-alias.md): `0x121` yields classification flag 8, while `0x12C` yields flag 4. These decoder results do not assert that either attribute is active for the RAW buffer on the primary CPU.

Four further native cases run the actual classifier and cache dispatcher with those artificial range records:

- Flag 8 / operation 0 selects helper `0xFE555B36`. Static review identifies data-cache clean by address for short ranges (`c7,c10,1`), or a broader operation for ranges at least `0x4000` bytes.
- Flag 8 / operation 1 selects helper `0xFE555B84`, with clean-and-invalidate by address (`c7,c14,1`) for short ranges and a broader path for larger ranges.
- Flag 4 selects the barrier helper `0xFE22CCDE` for either operation.

The probe stops at these helper entries. No cache maintenance, barrier helper or CP15 operation is executed; no successful cache operation is simulated. The source/destination ordering above is a static call-path result, not an executed transfer.

Two native conversion cases use the same artificial classes and confirm `0xFE175544` leaves marker `0x5C62C000` unchanged. The routine has separate translations for other flag bits, so this is not a universal identity function. In particular, the sensor RAW writer's earlier bit-30/31 clearing must not be applied blindly to this primary copy backend. The engines have separate address-handling paths.

## Relation to the 7D2 donor

The pinned [7D2 source](https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/platform/7D2.112/function_overrides.c) uses a four-argument `_memcpy_fast` wrapper for full-width copying. The 750D entry has a matching outer argument shape and a multi-entry core, making it a concrete counterpart candidate. This does not prove binary equivalence, safe channel selection, availability in a VSYNC callback, throughput or synchronous completion on the 750D. No donor address or performance figure is adopted as a target guarantee.

## Reproduction and scope

```sh
python scripts/probe_750d_copy_entry.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-copy-entry.json) records **14 passing cases**: six admission checks, two attribute decoder cases, two address conversions and four cache dispatches. Exact main-record size/SHA-256 are checked before importing Unicorn 2.1.4. Cortex-A9 executes compatible Thumb instructions, not a camera DMA/cache model.

Firmware/return sentinel are read/execute; synthetic globals, classification records and stack are read/write without execute permission. Artificial controller status is read-only. Code/write guards permit only reviewed execution and native stack writes; each case is bounded to 128 instructions / 0.5 seconds. Pointer markers are unmapped. The decoder uses a supplied saved frame after its unexecuted CP15 reads. No native calls are stubbed, and successful OS waits are not fabricated.

Next requirements are actual primary classification/channel availability, full submission/completion semantics, and safe execution context. Separately, a completed sensor frame and source-buffer lifetime still need validation before any copy backend can record real RAW video. Camera bindings remain disabled.
