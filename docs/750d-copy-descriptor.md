# Primary copy descriptors and the submission boundary

The actual 750D 1.1.0 descriptor builder at `0xFE133BF4` now executes on the PC, including its real zeroing helper, address converter, field packers and channel-list helpers. Ten supplied scenarios each build two descriptors. Nine then enter submission helper `0xFE133B22` using the **same native-written descriptors and channel state**, stopping before its controller start store. This advances the [copy candidate investigation](750d-copy-entry.md), without executing a DMA transfer.

Follow-up: [copy IRQ cleanup and status decoding](750d-copy-completion.md) now tests the notification branches and separately entered return slice. OS synchronization and physical completion remain unverified.

The subsequent [longer wrapper and semaphore experiment](750d-copy-sync.md) executes actual semaphore fast paths and independently verifies source/destination order from the full caller, correcting the earlier builder labels used here. Hardware start and physical completion remain unexecuted.

## Descriptor construction

The builder takes descriptor pointer, channel, destination and source in R0–R3, with byte count and flags on the caller's stack. The list core at `0xFE133E4C` supplies R2 from list offset 0 (destination) and R3 from list offset 4 (source). This corrects the earlier reversed source/destination labels used for the direct builder probe; the public wrapper's triplet remains `[destination, source, count]`. The builder clears 24 bytes and fills six words:

- Offset 0: byte count minus one.
- Offset 4: source after actual address converter `0xFE175544`.
- Offset 8: destination after that converter.
- Offset 12: first control word, mode bits 16–17, burst field bits 8–11 and flag bit 2.
- Offset 16: second control word with corresponding fields.
- Offset 20: next-descriptor pointer in bits 4–31, with link bit 0.

These are observed field positions, not a complete hardware specification. Supplied channel settings `[active, mode1, burst1, mode2, burst2, first, last]` are `[0, 1, 5, 3, 9, 0, 0]`. Channel state is at `0x52230 + channel * 28`. With flags zero, the two packed control words are `0x10500` and `0x30900`. Input flag bit 0 forces the first control word to `0x20004`; bit 1 independently forces the second to that value.

The first descriptor becomes both first and last in channel state. Building a second preserves the first pointer, updates the last pointer, and writes `second_pointer | 1` into the first descriptor's link word. Both descriptors are 32-byte aligned in this experiment. Alignment acceptance for other inputs is not established.

The native converter preserves supplied source marker `0x5C62C000` and destination marker `0x5E000000` under an artificial catch-all classifier record with flag 4. Neither pixel buffer is mapped. This is not evidence of the camera's live memory classification.

## Real zero helper, without a replacement implementation

Builder helper `0xFE182820` supplies length 24 and tail-calls veneer `0xFE3CDA0C`. The veneer switches to ARM and jumps to runtime `0x800072C0`. A scoped primary-kernel page from main-record source `0xFED630C8` is mapped at runtime `0x80007000`, putting the actual ARM zero helper from source `0xFED63388` at that entry. This uses the reviewed primary-kernel copy relation, not the different peer-kernel mapping used for RAW IRQ research.

Each scenario observes two real zero-helper entries with the expected descriptor pointer and length. Eight-byte canaries immediately before and after each 24-byte descriptor remain unchanged. Native calls are not stubbed. This scoped import does not establish complete boot relocation.

## Submission preparation from native-written descriptors

For nine nonzero-length scenarios, a separate call to `0xFE133B22` reads the first descriptor pointer already written by the builder. It copies the descriptor's six words to offsets `0x10` through `0x24` of `0xD6030000 + channel * 48`, then sets the channel's software active word to 1.

The probe supplies ordinary read/write RAM at the controller addresses. It checks all six native stores in order against the original descriptor, including the native-written link to the second descriptor. Execution stops at `0xFE133B88`, **before** the store of `0x11100003` to controller offset `0x28`. That location retains its canary. No controller start, transfer, linked-list fetch, interrupt, OS wait or completion is emulated. The software active word alone is not proof of hardware activity.

The builder and submitter are separately entered functions in the same emulator instance. The public wrapper's OS wait, list-core cache preparation and descriptor-clean operation between them are not executed or bypassed with fake successful returns. This experiment therefore verifies data propagation between those two functions, not an end-to-end wrapper call.

## Bounds and zero size

Eight scenarios cover flags 0–3 on channels 0 and 3 with 4,096 bytes. A ninth covers a one-byte first descriptor on channel 1. All second descriptors request 17 bytes. A tenth directly calls the builder with zero bytes on channel 2: its count word becomes `0xFFFFFFFF`. This direct call bypasses the list core's reviewed zero-size filtering; it does not show that the public wrapper submits a zero-byte transfer. The zero-size scenario is not passed to the submitter.

## Reproduction and remaining work

```sh
python scripts/probe_750d_copy_descriptor.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-copy-descriptor.json) records ten passing two-descriptor scenarios and nine submission preparations. The input must match the exact identified main-record size and SHA-256. Unicorn 2.1.4 uses Cortex-A9 for the compatible ARM/Thumb instruction subset; this is not full Cortex-R4 or camera emulation.

Firmware, the scoped kernel page and the return sentinel are read/execute. Supplied globals, descriptors, stack and artificial register RAM are read/write without execute permission. Execution guards admit only reviewed function ranges. Native writes are restricted to the stack, descriptor spans, selected channel state and six controller payload words. Each builder invocation is bounded to 512 instructions / 0.5 seconds; submission preparation to 128 instructions / 0.5 seconds.

Next work is the copy engine's completion/error path and OS synchronization, actual channel availability, cache requirements and safe calling context. This copy engine is separate from sensor RAW DMA at `0xD0004100`. A completed sensor frame and its buffer lifetime remain unverified; no real pixels have been acquired and camera bindings remain disabled.
