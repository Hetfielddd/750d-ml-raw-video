# RAW preparation address comes from an ADST reservation

The earlier [address-selection experiment](750d-raw-address-route.md) showed that RAW preparation can select EVF global word `0x26B94 + 88` (`0x26BEC`). Its producer now traces into the actual firmware's `ADST_GetMemAddrArray` code. Four bounded native PC scenarios verify reservation, diagnostic handling, release and reacquisition with a supplied registry.

This establishes a setup-time memory reservation mechanism. It does not grant ownership of each sensor frame or prevent DMA from overwriting the selected address.

## Producer and reservation layout

Source function `0xFE2B8814`, labeled `evfActive`, loads EVF global base `0x26B94` into R7 at `0xFE2B8838`. The slice starting at `0xFE2B8AAE` supplies R1 = EVF base + 100 for the returned count and R0 = slot **2**, then calls `0xFE2054F0`. It loads the returned descriptor's first word and stores it at `0x26BEC` by `0xFE2B8ABA`. The earlier selection/publisher path can subsequently forward this word into the candidate destination configuration.

Debug strings identify `0xFE2054F0` as `ADST_GetMemAddrArray` and `0xFE205540` as `ADST_ReleaseMemAddrArray`. Literal `0xFE20556C` supplies registry base `0x2B1E8`; registry + 4 points to the table. For slot `i`:

```text
16-bit reservation state: table + 220 + i * 2
32-bit returned count:   table + 244 + i * 4
descriptor address:      table + i * 20
```

Acquisition expects state 1, stores state 2, writes the count output and returns the descriptor pointer. Other states reach diagnostics followed by an assertion path; the experiment stops before either executes. Release expects state 2, restores state 1 and returns zero. It does not clear the EVF address or erase the descriptor.

The checked slot-2 release caller is `0xFE2BA284..0xFE2BA28A`, within the handler labeled `evfEnd[FrameNo:%d]`. Surrounding service, semaphore and task operations are not executed. This is an activation/end reservation lifecycle, not a complete verified start/stop sequence or a per-frame lease.

## Native PC checks

```sh
python scripts/probe_750d_raw_reservation.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Gates run before importing Unicorn. Cortex-A9 executes the compatible instruction subset, not a Cortex-R4 camera-system model.

Three scenarios supply counts 1, 2 and 0 with distinct descriptor pointer markers. Each runs the native activation slice and acquisition helper, repeats acquisition up to diagnostics, invokes the native slot-2 teardown release, then reacquires. The state sequence is `1 -> 2 -> 2 -> 1 -> 2`. The selected address always comes from descriptor word zero. Count 2 does not make this slice alternate pointers. Count zero still selects word zero: this deliberately invalid fixture demonstrates a missing check in the reviewed slice, not a usable capture configuration.

A fourth scenario starts reserved and reaches diagnostics without publishing an address or count. Saved link-register checks distinguish the helper's diagnostic call from normal activation logging. No native function is stubbed into success.

Only the reservation halfword, EVF address/count words and supplied stack may be written. Code is read/execute; synthetic registry/context/stack pages are read/write without execute permission. Execution/write guards and 96-instruction / 0.5-second limits apply per stage. Pointer markers are never mapped as image buffers. [Machine-readable evidence](evidence/750d-raw-reservation.json).

## Consequences for recording

The [next investigation](750d-raw-population.md) identifies descriptor population from manager fields and verifies that the reviewed code supplies one slot-2 address. Its original allocation and per-frame reuse timing remain unverified.

We now know where the candidate preparation pointer comes from. Reserving memory for EVF and obtaining a completed image long enough to copy are separate requirements. Acquiring slot 2 while Canon already holds it reaches the native diagnostic path. The earlier [AF completion investigation](750d-evf-raw-event.md) also does not supply a frame lease.

Next: trace slot-2 descriptor population and destination reuse/redirection between frames. Allocation contents, real geometry, DMA completion, cache coherence and copy throughput remain unverified. No camera provider or RAW recording mode is enabled.
