# Readout-done callbacks and internal phase updates

The [start/synchronization investigation](750d-raw-start.md) identified actual handler `0xFE2B9536`, labeled `evfReadOutDoneInterrupt`, for the donor's EVF old-state-5/input-5 condition. Following the handler shows that registered methods and additional notifications execute before it returns. A post-transition hook therefore still requires a target-specific buffer-lifetime check.

A later [CCD writer completion trace](750d-ccd-completion.md) identifies a separate conditional channel-2 callback, ShtCapture task event/return operation 13 and native service route `0x00010000`. Its relationship to this EVF event has not been established; the callback name or transport argument 5 must not be treated as proof of the same event.

## Completion calls before phase updates

After logging and setting caller offset 56 to one, the handler obtains a global structure and invokes source `0xFE30A6FC` using the object in EVF global offset 60. That helper checks the object's signature against the value referenced at `0xFEA517EC`.

For a valid supplied object, it calls dispatchers `0xFE1C6C20` then `0xFE1C6BFA`, followed by `0xFE2D1346`. The dispatchers read the operation-table pointer at RAM word `0x27258`. If present, their native call order is:

1. Method at operation-table offset 32.
2. Method at offset 8.
3. Method at offset 28, with R0 = `0x6B380`.
4. Method at offset 4, with R0 = `0x6B370`.

The last address is the preparation parameter block previously populated by the [RAW publisher](750d-raw-address-route.md); the preceding address is block + 16. They are parameter addresses, not proven image pointers.

Three native PC cases verify valid registration, absent registration and an invalid object signature. The supplied registration points to four distinct existing one-instruction `BX LR` functions, which execute normally while the experiment observes order and arguments. These are observation endpoints, not the real registered methods. Their real side effects, synchronization and buffer handling remain unverified. Execution stops before `0xFE2D1346`; the invalid signature stops before logging.

Static follow-up locates operation-table selection: `0xFE1C6A40` obtains a selector through `0xFE2489E2` and passes it to `0xFE2489C0`, which publishes a table address using a 72-byte stride. That selector and the actual methods are a concrete next lead, rather than a reason to assume all four callbacks are harmless.

## Separate internal-phase slice

After the completion helper returns, the handler examines a supplied halfword at global-structure offset 232 and an internal phase at EVF base `0x26B94 + 16` (`0x26BA4`). Ten native fixtures enter only this reviewed mid-handler slice:

- With halfword zero, phase 4 becomes 5; tested phases 3 and 5 remain unchanged.
- With halfword nonzero, tested phases `0 -> 1`, `1 -> 3`, `3 -> 4`, `4 -> 5`, `5 -> 5` and `6 -> 0` match the native code.
- The nonzero/phase-3 branch also sets a supplied notification word to one.
- Nonzero/phase-2 reaches the assertion boundary without changing phase.

The slice stops before `0xFE30B1B4`, the first downstream routine after phase processing. Where logging occurs, the experiment stops before the logger and separately resumes where the phase is reloaded; no logger return is fabricated.

This internal phase is **distinct from the state object's old state** used by Magic Lantern's VSYNC hook. The experiment does not equate the two numbers. It does not execute the full state transition or establish the relative timing of sensor readout, RAW DMA completion and buffer reuse.

## Downstream work and next check

Static review of the handler tail shows calls to `0xFE30B1B4`, `0xFE205F98` (a veneer to `0xFE269004`) and `0xFE548550` before returning. The reviewed `0xFE269004` prepares a small downstream object with value 10 at offset 160 and submits it through another helper; it is not a demonstrated call to rearm RAW DMA. These downstream routines are not executed in the new probe.

The next work is the actual registered operation-table selection and methods, then their ordering against subsequent parameter submission. We cannot conclude that returning from `evfReadOutDoneInterrupt` grants a stable RAW-frame lease just from its name or its match to the 7D2 hook condition.

## Reproduce and scope

The [next experiment](750d-readout-methods.md) executes the actual selected methods and finds conditional `StartDriver` command preparation inside this completion path, before it returns. Transport and real buffer timing remain unverified.

```sh
python scripts/probe_750d_readout_done.py /private/750d-analysis/record-06.bin
```

Three callback-dispatch cases and ten internal-phase cases pass. [Machine-readable evidence](evidence/750d-readout-done.json).

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Input gates precede import. Cortex-A9 executes the compatible instruction subset, not a Cortex-R4 camera system. Code is read/execute; explicit supplied state/stack pages are read/write without execute permission. Code/write guards restrict execution and writes. Limits: 128 instructions / 0.5 seconds for completion dispatch; 64 instructions / 0.5 seconds per phase slice. No native function is stubbed into success; MMIO and pixels are unmapped. Real registered methods, OS behavior, cache coherence, frame identity and timing remain unverified. Camera bindings stay disabled.
