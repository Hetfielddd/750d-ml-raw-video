# Candidate primary SCSState event7 matrix

The [primary CCD receiver](750d-ccd-receiver.md) prepares event7 on an owner-provided primary queue object in one reviewed CMOS-completion callback. A new bounded investigation finds an **SCSState candidate** with an event7 handler labeled `scsCompleteCapture`. Twenty native PC cases check its actual constructor publication, dispatch across all 18 current states and two rejection controls.

Six additional constructor/worker scenarios now check the queue-to-object association using native publication and dispatch instructions. Actual allocation, task creation and OS queue delivery remain explicit unexecuted cuts. This is not proof of uninterrupted `CCD -> SCSState` delivery, EVF completion or a finished RAW frame.

## Actual constructor and distinct kernel mapping

Constructor argument preparation at `0xFE13CA78` selects name `SCSState` at `0xFED522F8`, matrix `0xFEA06D08`, input limit 26 and state stride 18. It reaches the real CreateStateObject veneer `0xFE3CE074`, whose actual target is primary low entry `0x211B`.

The experiment maps the **primary** low image from source `0xFED58B7C`, distinct from the peer low image used in the RAW event/queue probes. Native constructor prefix `0x211A` requests 32 bytes and stops before allocator `0x10EA`. A separately entered post-allocation slice at `0x2138` publishes into supplied scratch memory using the prefix's preserved registers/frame, then returns with its stack restored. No allocator return is fabricated.

The actual published object has handler pointer `0x20AF`, matrix pointer, limits 26/18 and current state zero. This establishes the layout through native instructions rather than constructing it solely in Python. It does not execute boot relocation or actual object allocation.

## Event7 dispatch

The actual primary low dispatcher `0x20AE` consumes that natively published object and its real table. With separately supplied current states 0–17 and input7:

- States **10, 11, 14, 15 and 16** select source `0xFE13DC5E`, labeled `scsCompleteCapture`. They retain their current state and reach the handler's first logger boundary.
- The other **13 states** have null event7 handlers and return zero without invoking that handler.

Two further native cases verify signature rejection (return7) and input27 outside limit26 (return3). The probe does not use an invalid current-state fixture or infer that all live states are safe to dispatch arbitrarily.

This also avoids a misleading proximity inference: the function immediately after the CMOS callback, `0xFE13E93A`, is not the event7 handler in this matrix. Actual table consumption selects a different function.

The matrix-only cases stop before the active handler's logger. The separate continuation cases below execute one bounded branch beyond that cut. No copy, frame metadata, image pointer, DMA completion or buffer release is obtained from those calls. This `SCSState` matrix is distinct from the reviewed EVF old-state5/input5 matrix. Similar completion names and numeric events do not establish equivalence.

## Native owner, queue and worker association

The owner constructor `0xFE132BA0` allocates an 88-byte context and calls the SCS constructor. Its post-call slice stores that state-object pointer at owner +12. The SCS constructor also publishes it at `0x263BC + 8`. Owner construction then prepares queue creation `0xFE43832C` with worker pointer `0xFE132B49`, and publishes its returned queue pointer at owner +8. Another native publication stores the owner at global `0x4984 + 4`.

The probe separately executes those publication slices with supplied storage; it does not pretend owner/queue/task creation returned successfully. The real queue-constructor prefix requests 28 bytes. Its separate post-allocation fragment publishes the active flag and actual worker at queue +24. OS queue, semaphore and task construction do not execute. The queue's underlying handle remains a supplied zero boundary marker and is never passed into an executed OS queue operation.

The actual CMOS callback prefix and post-logger continuation use that natively published owner +8 queue pointer to prepare event7. Native request prefix `0xFE43842E` reaches a 16-byte allocator request. A separate post-allocation fragment writes `[owner, 7, 0, 0]` into supplied envelope storage, stopping before enqueue preparation continues. No allocator return is synthesized.

An explicit unexecuted enqueue/receive/free cut transfers those native envelope words into the task loop's post-receive stack slots. The envelope page is then made inaccessible. Loop continuation `0xFE438310` loads its actual callback from queue +24, invokes worker `0xFE132B48`, and that worker resolves global owner `0x4988` and state object at owner +12. Through the real state import `0xFE3CE004` and primary low wrapper/dispatcher, it selects `scsCompleteCapture` using the same actual matrix. The host does not directly inject a selected handler or state-object pointer at the worker boundary.

This checks the structural association for the reviewed owner-construction path. Real queue delivery, live owner replacement, object allocation/lifetime and concurrent capture contexts are unverified.

## A flag-setting completion branch, rather than a pixel lease

For all five active current states, supplying owner field +56 equal to zero takes the branch from `0xFE13DC84` through `0xFE13DD78`. Native code stores 1 at global `0x263BC + 100` (`0x26420`), returns the published SCS object, and returns through the dispatcher and worker to the next task receive boundary `0xFE3CDFDC`. The native return stack/frame is checked. The OS receive itself is not executed.

In a sixth scenario, owner +56 equal to one instead reaches mode query `0xFE4046BA` and stops before it; the flag stays zero. No mode-query result or omitted branch completion is invented.

The tested zero branch does not copy pixels or create a per-frame pointer/ownership token. Its flag is a software condition and these supplied-state tests do not define its full lifecycle or authorize reading the RAW buffer. The nonzero branch has further capture-processing calls outside this experiment. The remaining research must distinguish this SCS completion path from the continuous EVF pipeline and establish the actual RAW frame identity/reuse interval.

## Reproduction

```sh
python scripts/probe_750d_scs_event.py /private/750d-analysis/record-06.bin
```

The [evidence](evidence/750d-scs-event.json) contains 18 state cases, two rejection controls and six separate constructor/worker routing cases. Exact identified main-record size/SHA-256 gates run before Unicorn import. Compatible Cortex-A9 ARM/Thumb code executes on the PC with code/write guards and 192-instruction / 0.5-second limits per stage.

Firmware, scoped primary-low pages and the stop page are read/execute; supplied objects, globals and stack pages are read/write without execute permission. No native calls are stubbed. Allocation, OS queue delivery, logger bodies, all capture-handler branches, hardware timing, pixels, cache coherence and a frame lease remain unverified. Camera bindings are disabled; camera and SD card are untouched.
