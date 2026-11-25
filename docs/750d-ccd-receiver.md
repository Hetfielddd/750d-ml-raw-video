# Primary ShtCapture receiver and CMOS completion callbacks

Six native PC cases identify and exercise the primary receiver of the [CCD writer return route](750d-ccd-completion.md). ShtCapture return operation 13 selects a registered CMOS completion callback, then prepares event flag `0x1000`; operation 14 uses another callback and flag `0x2000`. One actual operation-13 callback prepares primary task event 7 with a zero payload across explicit mode-query/logger cuts.

This connects the peer return number to a concrete primary-side continuation. It does not establish that this continuation is EVF `ReadOutDone`, a completed RAW channel-1 frame, or permission to copy its buffer.

## Primary receiver registration

Primary initialization at `0xFE1EE0F4` and subsequent API paths install receiver pointer `0xFE1EE0ED` for service `0x00010000`. Native dispatcher `0xFE1EE0EC` uses table `0xFEA67864`:

- Operation 13 selects `0xFE1EE8F5`.
- Operation 14 selects `0xFE1EE90F`.

Primary callback/event state begins at `0x2D588`. Offset 0 holds an event handle; offsets 4/8 hold the operation-13 callback/argument, and 12/16 hold the operation-14 callback/argument.

API `0xFE1EE24A`, labeled `SHT_CAPTURE_PATH_AsyncStartCapturePathSuite`, accepts parameters, the two callbacks and their arguments. The experiment executes its actual prefix to logging, separately resumes after that logger to the real event-clear boundary, then separately enters the post-clear continuation. No logger or OS-clear success is fabricated. The continuation stores all four callback words and calls real service registration `0xFE44303E`.

The supplied service-table root row at `0x51E54 + 4` points to a fixture registry. Native registration writes receiver `0xFE1EE0ED` and context zero for service index zero. Native command preparation then reaches transport entry with `[4, 1, 2, parameter_block]`. Neither the earlier event clear nor actual transport executes.

## Two actual caller branches

The probe executes bounded caller slices, with owner/parameter objects supplied, from two real API call sites:

- At `0xFE13EB2C`–`0xFE13EB38`, native literal loads supply operation-13 callback `0xFE13E913` and operation-14 callback `0xFE13E8BF`.
- At `0xFE142330`–`0xFE14233A`, they supply `0xFE142209` and `0xFE1421B5` respectively.

Both branches pass their owner object as each callback's saved argument. Surrounding conditions, complete caller execution and active camera mode are not established. The callbacks are firmware-selected values from these branches, not arbitrary observation endpoints.

## Receive dispatch and argument substitution

Across an explicit unexecuted transport-delivery boundary, the actual primary dispatcher receives operation 13/14 and incoming zero payload. It selects the natively installed callback and invokes it with the **saved owner argument**, replacing the incoming R0. The payload is not interpreted as an image pointer.

Operation-13 callback `0xFE13E912` has diagnostic `Complete CMOS Capture(%d)`. Its native prefix reads owner offset 40 and reaches mode-query `0xFE3FF59E`. The experiment stops before the query. A separately entered post-logger continuation at `0xFE13E92A` retains the native owner register and saved frame and does not consume a query/logger return value. It prepares:

```text
R0 = queue-object marker from owner + 8
R1 = owner
R2 = task event 7
R3 = payload 0
fifth argument = 0
```

Execution stops before queue operation `0xFE43842E`. No event is delivered or consumed. The owner of that primary task and its event-7 transition still need tracing.

Alternate operation-13 callback `0xFE142208` uses the same diagnostic but a different body. Its prefix loads the mode-query argument through global `0x26468 + 32`; the probe stops before the query. Static review finds a later logging tail, but that tail is not executed or assigned a made-up mode-query result. The two registered callbacks must not be assumed equivalent merely because they log the same text.

Operation-14 bodies are reached but not executed in the receiving checks. They have further work outside this probe.

## Post-callback event preparation and null controls

The experiment saves CPU state at the real receiver-to-callback boundary. Separate post-callback continuations at `0xFE1EE900` / `0xFE1EE91A` use that CPU state and the receiver's actual saved stack frame. They prepare event helper `0xFE3CDA82` with the supplied event handle and mask `0x1000` / `0x2000`, then stop before the helper. The callback body is not treated as completed and no event-setting success is invented.

The actual callback-clear slice at `0xFE1EE2A0` clears both callback/argument pairs. With those words null, independently invoked operations 13/14 skip callback dispatch and still reach the matching event-helper boundary. This tests the receiver's null behavior, not a live camera condition or completed frame.

The flags are primary API synchronization masks. They do not carry a RAW buffer identity, byte count or cache guarantee. Likewise primary task event 7, peer ShtCapture event 13, RAW auxiliary event 7 and EVF event 5 belong to different dispatch contexts; their numeric values cannot establish equivalence.

## Remaining connection

The new concrete continuation is `CCD writer -> peer ShtCapture event/return 13 -> primary receiver -> selected CMOS callback -> primary task-event-7 preparation` for the reviewed caller branch, with explicit queue/transport/query/logger cuts. The next target is the owner task behind that last event and its relation, if any, to EVF readout and source reuse.

No complete image or frame lease has been obtained. The 7D2 donor's opposite-buffer/VSYNC contract remains a separate requirement, and this route's active use for continuous RAW video has not been established.

## Reproduction

```sh
python scripts/probe_750d_ccd_receiver.py /private/750d-analysis/record-06.bin
```

The [evidence](evidence/750d-ccd-receiver.json) records four registered receive cases and two callback-clear controls. Exact main-record size `0xCFB688` and SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2` are checked before Unicorn import.

Unicorn 2.1.4 Cortex-A9 executes a compatible scalar subset, not a Cortex-R4 camera system. Firmware/stop pages are read/execute; supplied owner, registry, state and stack pages are read/write without execute permission. Code/write guards and 192-instruction / 0.5-second limits apply per stage. Device registers and pixels are unmapped. No native calls are stubbed. Event clear/set, queue delivery, transport, mode query, physical capture, cache coherence and buffer ownership remain unverified. Firmware/private disassembly are not distributed. Camera bindings are disabled; camera and SD card are untouched.
