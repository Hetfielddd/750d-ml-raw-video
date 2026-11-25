# CCD writer completion reaches a separate ShtCapture task route

Five native PC cases now trace the `CCDWriteEDmacCompleteCBR` candidate through real callback registration, task-request preparation and a separately entered actual state dispatcher to return-message preparation. The callback belongs to a reviewed conditional **channel-2** writer branch and the `ShtCapture` service route **`0x00010000`**. The previously studied RAW auxiliary route uses channel 1 and service `0x00020002`.

This is a concrete completion route to investigate, not a qualified source of completed RAW frames. Its relationship to EVF `ReadOutDone`, live mode activation and buffer lifetime remain unverified.

The later [primary-receiver investigation](750d-ccd-receiver.md) now identifies operation 13's registered CMOS callback and a separate primary task-event-7 preparation. It resolves the receiver selection for checked branches; the EVF relationship and completed RAW-frame contract remain unverified.

## Actual writer callback and channel preparation

The callback name occurs at source `0xFE8251FC`; its native body begins at `0xFE825028`, stored application pointer `0x01BA2CC1`. It reads callback/owner words at `0x01AC1978 + 16/+20`, calls that optional function with R0=owner and **R1=0**, then prepares logging. The incoming callback R0/R1 markers are not forwarded as an image address or frame identifier.

In a conditional setup branch, source slice `0xFE825062` prepares channel callback installer `0xFE86F860` with `[2, 0x01BA2CC1, 0]`. The experiment executes this preparation and stops before the installer. Channel registration/controller enablement do not execute. Channel 2 is the value for this reviewed branch, not a measurement of the camera's active configuration or a claim about every mode of the writer module.

## Real application callback registration

The caller at `0xFE810D52` contains a native registration continuation beginning at `0xFE810D72`. That continuation installs two callbacks using the real module setters:

- Setter `0xFE824704` writes pointer `0x01B8E9D5` and owner to module offsets 16/20. The callback's source is `0xFE810D3C`.
- Setter `0xFE824716` writes pointer `0x01B8E9BF` and owner to offsets 24/28. Its source is `0xFE810D26`.

The second module callback at `0xFE824FD8`, labeled `StlPreForSafPathCompleteCBR`, sets module word +36 to 1 and calls the second registered function with owner and zero. It is a separate notification from the CCD writer callback. Its label does not make it a validated RAW-frame completion event.

The experiment executes the actual registration continuation with a supplied owner context, then invokes either module callback. The registered functions prepare native task events **13** and **14**, respectively, through the actual request helper `0xFE86FB30`. Each reaches the queue-operation boundary with:

```text
queue-object marker, subtask pointer, event 13 or 14, payload 0
additional argument: 0
```

No queue operation or task delivery executes here. A native unregister control at `0xFE82470C` clears offsets 16/20; a subsequent CCD writer callback reaches logging without preparing a task event. The logger body is not executed or assigned a successful return.

## Task table and actual service route

Constructor `0xFE810CE0` prepares the `ShtCapture` state object with table pointer `0x01CF253C`, event limit 16 and state stride 1. Execution stops before allocation/construction import `0xFE86F5D8`; no allocator return is fabricated.

The outer service constructor at `0xFE80767E` calls that constructor. Its post-task-create slice `0xFE80769C` writes the actual service route `0x00010000` at context offset 8 and publishes its subtask at offset 0. The probe executes that slice with a supplied subtask object, stopping before the caller's saved-frame epilogue. Allocation and task creation remain explicit unexecuted boundaries.

Two positive cases use this native-published route. Two further cases deliberately replace it with `0x00030009` as a dynamic-route control. The latter is not asserted to be the camera's route. The fifth case is native callback removal.

## Separately entered receiving task dispatch

Across an explicit unexecuted queue-delivery cut, the actual dispatcher `0x800057FC` consumes the native-produced event and zero payload on a supplied state-zero object using the constructor's real table:

- Event 13 selects source `0xFE810EE0`, which prepares return operation 13.
- Event 14 selects source `0xFE810EF2`, which prepares return operation 14. Execution stops before transport, so that handler's later downstream call is not executed.

Both use helper `0xFE86FBDE`. For native route `0x00010000`, the return-transport boundary receives `[5, 1, 13, 0]` or `[5, 1, 14, 0]`. The dynamic-route control produces `[5, 3, 0x90D, 0]` or `[5, 3, 0x90E, 0]`.

These numbers occupy separate namespaces. Task event 13, return operation 13, transport channel argument 5 and EVF event 5 are not interchangeable. No primary-side receive or dispatch is executed by this probe; an indirect relationship to EVF `ReadOutDone` has neither been established nor excluded.

## Implication for RAW research

This route adds a precisely identified return operation and service to follow on the primary core. It does not justify copying from the RAW channel-1 destination after a channel-2 callback. The reviewed notification carries no image pointer, counter or ownership token; identifying the corresponding buffer will require other state and ordering evidence.

The [7D2 donor](similar-camera-raw.md) relies on its verified EVF/opposite-buffer sequence. The 750D [readout handler](750d-readout-methods.md) can prepare another StartDriver command before returning. The next investigation is the receiver of ShtCapture return operation 13 and its relationship, if any, to that readout transition and RAW reuse.

## Reproduction and limits

```sh
python scripts/probe_750d_ccd_completion.py /private/750d-analysis/record-06.bin
```

The [evidence](evidence/750d-ccd-completion.json) records five passing cases. Exact identified main-record size `0xCFB688` and SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2` are checked before Unicorn import.

Unicorn 2.1.4 Cortex-A9 executes a compatible instruction subset, not the camera's Cortex-R4 system. Main code, scoped application/driver/table copies and stop page are read/execute; supplied context/module/state/task/stack objects are read/write without execute permission. Code/write guards and 192-instruction / 0.5-second bounds apply per stage. Native calls are not stubbed. No device-register or pixel pages are mapped. Allocation, task creation, controller registration, queue delivery, return transport, physical completion, cache coherence and frame ownership remain unverified. Firmware bytes and private disassembly are not distributed. Camera bindings are disabled; camera and SD card are untouched.
