# Primary copy IRQ cleanup, notification and return status

The actual copy-engine IRQ body `0xFE1339B4` now executes in bounded PC experiments. It saves the supplied controller status, clears channel software state and chooses either a completion-signal boundary or an unlock-before-callback boundary. The [descriptor/submission experiment](750d-copy-descriptor.md) stopped before starting this separate copy engine; this follow-up does not supply hardware completion or copied pixels.

## IRQ-to-channel mapping and cleanup

The handler recognizes IRQ identifiers `0x13E`, `0x14E`, `0x15E` and `0x16E` as channels 0–3. These are distinct from sensor RAW channel IRQ `0x41` reviewed elsewhere. No physical IRQ delivery or registration is exercised here.

For channel `c`, the native code:

1. Reads status at `0xD6030030 + c * 48`.
2. Saves the full word to **shared address `0x257A4`**.
3. Writes `status & ~0xF` back to the controller status address.
4. Calls real helper `0xFE1826EA`, clearing active word 0, first-descriptor pointer +20 and last-descriptor pointer +24 in channel state `0x52230 + c * 28`.
5. Selects notification using callback slot `0x40854 + c * 8`.

Controller addresses are artificial ordinary RAM. The write in step 3 is observed as an instruction result, not proof of real device acknowledgement or write-one-to-clear behavior. Software descriptor-list cleanup occurs for all supplied status patterns; it does not independently qualify successful transfer.

Thirty-two cases cover all four channels, status low nibbles 0, 1, 8 and 15, and both callback branches. Supplied high status bits `0xA5300000` must survive the writeback mask. Tests check the exact ordered non-stack stores, selected state cleanup and preservation of all neighboring channel state. Four invalid-IRQ cases return without modifying status, controller RAM, callback slots or channel state.

## Two notification branches

With a null callback, the handler loads the per-channel completion handle from `0x40834 + c * 4`, restores its stack and tail-calls signal veneer `0xFE3CDD6C`. Execution stops at that veneer; no semaphore signal is executed or assumed.

With a non-null callback, the handler saves callback and argument, clears **both slot words**, then loads the per-channel lock handle from `0x40844 + c * 4` and calls unlock veneer `0xFE3CE08C`. Execution stops before that OS operation. Sixteen cases additionally enter the reviewed continuation at `0xFE133A2A` separately, retaining the native saved registers and stack. They reach the supplied callback address with its original argument and a restored stack, without executing the callback.

The continuation is a separate function-slice experiment, **not a fabricated successful unlock return**. It establishes argument forwarding and one-shot slot clearing, but not callback timing or OS behavior. Callback arguments do not include the controller status in this reviewed path.

## Return decoding is not an independent completion test

The synchronous submitter's reviewed flow waits at `0xFE3CE0AC`, then reads the same shared status word at `0xFE133B9A`. Its actual instruction slice extracts the low nibble and leaves return accumulator R7 at zero for nibble 8; other nibbles are copied to R7. Consequently **both nibble 0 and nibble 8 produce zero**.

Sixteen native cases first run the IRQ handler with each supplied low nibble 0–15. They then enter only the post-wait decoder slice, consuming the status written by that handler without host replacement. R7 is explicitly supplied as zero, matching the submitter's reviewed initialization. The experiment stops before the return epilogue. It does not execute a wait or claim that arbitrary status can occur following a successful real wait.

Static review of the public wrapper at `0xFE133EB2` shows it acquires its channel handle, calls the list core, saves the returned result, releases that channel handle and returns the saved result. The core forwards the submitter result. That call path is not executed end-to-end here; its waits, cache operations and hardware start remain outside the experiment.

## Shared status and unresolved serialization

The status destination and the post-wait load are not indexed by channel. In one additional same-emulator sequence, separately invoking channel 0's handler with status 8 yields decoder result zero; invoking channel 1's handler with status 1 then makes the same decoder return 1. This confirms the shared-storage dependency from native code.

This is **not a demonstrated live race or a firmware defect**. IRQ scheduling, OS serialization, channel usage constraints and actual controller behavior remain untested. The wrapper's reviewed lock handles are channel-indexed, so a future adapter must establish the intended concurrency contract rather than assume these handles protect the shared result across channels. Likewise, a zero return must be interpreted together with valid completion synchronization, not used as standalone hardware evidence.

## Reproduction and scope

```sh
python scripts/probe_750d_copy_completion.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-copy-completion.json) contains **53 passing cases**: 32 channel/status/notification cases, 16 separately entered post-wait decoder cases, four invalid IRQs and one shared-status sequence. Callback continuation checks are included in the 16 non-null callback cases.

The input must match the exact identified main-record size and SHA-256. Unicorn 2.1.4 uses Cortex-A9 for compatible Thumb instructions, without full camera or Cortex-R4 emulation. Code and sentinel pages are read/execute; fixture globals, channel state, stack and artificial controller RAM are read/write without execute permission. Execution and write guards restrict each stage to reviewed ranges and selected state fields. Each stage is bounded to 128 instructions / 0.5 seconds. No native calls are stubbed.

OS wait/signal/unlock operations, interrupt delivery, DMA transfer, cache coherence, safe calling context and source-frame ownership remain unverified. Camera bindings remain disabled. Next work is to inspect the actual OS synchronization imports and channel initialization/usage, while preserving the distinction between this copy-engine completion path and completion of sensor RAW capture.
