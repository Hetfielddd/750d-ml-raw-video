# RAW start consumes timer-produced event flags

Four PC sequences connect the actual timer callback, kernel event lookup and update, driver's start wait and clear, and separately entered RAW start call. In the enabled-timer fixture, the software reaches address and command programming with no physical register reads in the executed slices. This extends the earlier separate start-gate and no-work notification checks across the same event object and driver state. [Start gate](750d-start-gate.md) · [No-work notifications](750d-raw-notification.md).

## Native sequence

Timer callback `0xFE750D04` checks driver offset 40 and sets event mask `0x8000007F` through the actual kernel wrapper, lookup and no-waiter update. The fixture's other event bit `0x200` remains set. The timer leaves software component word `driver + 4` at supplied marker `0x22`.

The start prefix at `0xFE750E1C` stores the component word in the caller's descriptor at offset 84. It reaches another component helper, where the experiment stops. The separately entered continuation at `0xFE750E2E` executes the actual ALL-bit wait and clear, then zeros the software component word. All those native calls return normally in the ready fixtures. The unrelated event bit `0x200` survives the clear.

Another independent slice begins at the real RAW call site `0xFE750E52`. It executes the actual ARM import and RAW software handler through return to the driver. A nonzero pending address produces the destination, control, channel-command, packing and sensor-path command stores already characterized by the command-order probe. A zero pending address instead invokes the registered RAW callback, whose real no-waiter kernel update sets event bit `0x10`. [RAW command order](750d-raw-command-order.md).

## Controls

- Timer disabled, initial event word `0x27F`. All seven component bits are present, but bit 31 is absent. The native wait reaches its blocking boundary, preserving the pending address and event flags.
- Timer enabled, initial word `0x200`, nonzero pending address. Timer update creates `0x8000027F`, the native start wait succeeds, and the RAW slice programs normalized destination `0x1C62C000` and commands.
- Timer enabled with the same initial event word and zero pending address. The wait and clear succeed. The RAW slice emits no channel commands and leaves event flags at `0x210` after its callback.
- Timer disabled, initial word `0x8000027F`. The preseeded full mask permits the native wait and the subsequent RAW start slice.

The test guards reject every physical register read. These cases therefore demonstrate how software event state admits the reviewed start path. A successful wait alone leaves the completion state and identity of any earlier physical transfer unresolved.

## Execution boundaries

The descriptor's component helper, driver preparation between the gate and RAW call, and the SAF start are omitted by explicitly entering reviewed continuations. Their behavior may affect the live camera's ordering or state. The probe supplies the enabled-timer word, event object, event flags, pending address and normal RAW configuration. It invokes the timer directly. It establishes neither a live timer policy nor a hardware race. The callback uses null optional application notifications, as in the earlier no-work probe.

```sh
python scripts/probe_750d_start_after_timer.py /private/750d-analysis/record-06.bin
```

Requires the identified 750D 1.1.0 main record and Unicorn 2.1.4. Identity gates run before importing Unicorn. The compatible scalar code runs in the Cortex-A9 model with guarded code, reads and writes, and limits of 320 instructions and 0.5 seconds per slice. Native event and RAW calls execute without success stubs. Register pages are passive RAM. Physical DMA, pixels, cache coherence, scheduling and source-buffer reuse timing remain unverified. [Machine-readable evidence](evidence/750d-start-after-timer.json).
