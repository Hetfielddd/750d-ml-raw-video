# Candidate primary SCSState event7 matrix

The [primary CCD receiver](750d-ccd-receiver.md) prepares event7 on an owner-provided primary queue object in one reviewed CMOS-completion callback. A new bounded investigation finds an **SCSState candidate** with an event7 handler labeled `scsCompleteCapture`. Twenty native PC cases check its actual constructor publication, dispatch across all 18 current states and two rejection controls.

The callback queue's link to this particular object is **not established**. This is a candidate matrix/handler contract, not proof of uninterrupted `CCD -> SCSState` delivery, EVF completion or a finished RAW frame.

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

The active handler prefix accesses a supplied owner and stops before logging; its capture/processing body does not execute. No copy, frame metadata, image pointer, DMA completion or buffer release is obtained from those calls. This `SCSState` matrix is distinct from the reviewed EVF old-state5/input5 matrix. Similar completion names and numeric events do not establish equivalence.

## Reproduction

```sh
python scripts/probe_750d_scs_event.py /private/750d-analysis/record-06.bin
```

The [evidence](evidence/750d-scs-event.json) contains 18 state cases and two rejection controls. Exact identified main-record size/SHA-256 gates run before Unicorn import. Compatible Cortex-A9 ARM/Thumb code executes on the PC with code/write guards and 192-instruction / 0.5-second limits per stage.

Firmware, scoped primary-low pages and the stop page are read/execute; supplied object/owner/stack pages are read/write without execute permission. No native calls are stubbed. Allocation, queue routing/delivery, logger bodies, complete capture handlers, hardware timing, pixels, cache coherence and a frame lease remain unverified. Camera bindings are disabled; camera and SD card are untouched.
