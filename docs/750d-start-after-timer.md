# RAW start consumes timer-produced event flags

Eight PC sequences connect the actual timer callback, kernel event lookup and update, driver's start wait and clear, and RAW start call. Two scenarios now execute the intervening component and inactive SAF paths as well, preserving the native driver frame from entry to the RAW function's return. The software reaches address and command programming with no physical register reads in the executed path. [Start gate](750d-start-gate.md) · [No-work notifications](750d-raw-notification.md).

## Native sequence

Timer callback `0xFE750D04` checks driver offset 40 and sets event mask `0x8000007F` through the actual kernel wrapper, lookup and no-waiter update. The fixture's other event bit `0x200` remains set. The timer leaves software component word `driver + 4` at supplied marker `0x22`.

The start prefix at `0xFE750E1C` stores the component word in the caller's descriptor at offset 84. It reaches another component helper, where the experiment stops. The separately entered continuation at `0xFE750E2E` executes the actual ALL-bit wait and clear, then zeros the software component word. All those native calls return normally in the ready fixtures. The unrelated event bit `0x200` survives the clear.

Another independent slice begins at the real RAW call site `0xFE750E52`. It executes the actual ARM import and RAW software handler through return to the driver. A nonzero pending address produces the destination, control, channel-command, packing and sensor-path command stores already characterized by the command-order probe. A zero pending address instead invokes the registered RAW callback, whose real no-waiter kernel update sets event bit `0x10`. [RAW command order](750d-raw-command-order.md).

## Controls

- Timer disabled, initial event word `0x27F`. All seven component bits are present, but bit 31 is absent. The native wait reaches its blocking boundary, preserving the pending address and event flags.
- Timer enabled, initial word `0x200`, nonzero pending address. Timer update creates `0x8000027F`, the native start wait succeeds, and the RAW slice programs normalized destination `0x1C62C000` and commands.
- Timer enabled with the same initial event word and zero pending address. The wait and clear succeed. The RAW slice emits no channel commands and leaves event flags at `0x210` after its callback.
- Timer disabled, initial word `0x8000027F`. The preseeded full mask permits the native wait and the subsequent RAW start slice.
- Timer enabled with nonzero pending address and the descriptor preparation helper executed. With its extra-processing selector zero, the actual helper returns to the native start frame, and the subsequent gate and RAW programming match the earlier enabled-timer case.
- Timer enabled with the extra-processing selector set to one. The entire preparation helper, including all reviewed setup calls, executes and returns before the wait. It configures four processing blocks with the supplied dimensions and rectangle, then the native wait and RAW command slice execute.
- Two connected driver-start cases use enabled descriptor preparation and run the intermediate component helper with and without pending work. In both, SAF is supplied uninitialized with a null callback. All calls from driver entry through the RAW start and return execute in sequence.

The test guards reject every physical register read. These cases therefore demonstrate how software event state admits the reviewed start path. A successful wait alone leaves the completion state and identity of any earlier physical transfer unresolved.

## Execution boundaries

In the fifth and sixth cases the descriptor helper at source `0xFE8B7DDC` executes through its real import, configuration writers and return. It receives `descriptor + 8`, stores the input selector at offset 20 in its own global state, and selects an internal configuration value using that state's offset 40. Another supplied input field selects the write of `0x111` to `0xD001A014`, through the actual register writer and shadow update. The full helper restores its stack before returning to `0xFE750E2E`.

The sixth case supplies selector 1, dimensions 2,048 by 1,080 and an origin of zero. The helper retains four additional supplied words in global memory, packs dimensions as `0x07FF0437` and rectangle bounds as `0x043707FF`, and invokes the native configuration routines for blocks based at `0xD0048000`, `0xD0048900`, `0xD0048A00` and `0xD0048B00`. Its 39 physical-location stores include the initial processing configuration, four dimension/rectangle groups and the later control commands. Every corresponding shadow write executes normally. The read guard rejects any physical register read, including channel status or address. The enabled processing path reaches its real return under that guard. Hardware effects and any later completion of these processing blocks remain unmodeled.

The descriptor helper remains a cut in the original four cases. Driver preparation between the gate and RAW call, and the SAF start are omitted in the first six cases. The last two execute that interval through real ARM imports and native returns, using the unchanged driver stack. Observation stops at instruction boundaries preserve all CPU and memory state between calls. Each resumption starts at the instruction where execution stopped.

The intermediate component helper is source `0xFE839EAE`, selected by import `0xFE74F1E0`. With an initialized component and a nonzero pending field, it calls `0xFE8EF62E` and `0xFE8EF544`. Native writers store 1 at `0xD000A100`, zero at `0xD000A014` and 4 at `0xD000A00C`, updating their shadows. The component moves its pending word into its current field and clears pending. With no pending work and a null callback it simply returns. In both scenarios the next real call reaches `LV_SAF_PATH_Start` at `0xFE83A61A`. The supplied uninitialized SAF state and null callback cause its native return without additional work. The driver then calls the actual RAW start and receives its normal return at `0xFE750E56`.

This removes the omitted calls before RAW start for these two specific states. Initialized SAF has more branches, and other state selections can affect the live path. The rest of the driver after RAW return remains outside this probe. The timer is directly invoked with supplied enabled state and an event object without waiters. Physical register words have ordinary RAM behavior. This verifies a possible native software path and leaves the camera's active state, real DMA completion and timing unresolved.

```sh
python scripts/probe_750d_start_after_timer.py /private/750d-analysis/record-06.bin
```

Requires the identified 750D 1.1.0 main record and Unicorn 2.1.4. Identity gates run before importing Unicorn. The compatible scalar code runs in the Cortex-A9 model with guarded code, reads and writes, and a 0.5-second limit per slice. Enabled-processing slices have a 1,024-instruction limit and the other cases use 320. Native event and RAW calls execute without success stubs. Register pages are passive RAM. Physical DMA, pixels, cache coherence, scheduling and source-buffer reuse timing remain unverified. [Machine-readable evidence](evidence/750d-start-after-timer.json).
