# RAW IRQ registration reaches a low-memory import

The [IRQ-body experiment](750d-raw-irq.md) traced callback forwarding after direct invocation. This step executes the actual channel callback installer through the IRQ wrapper and ARM import veneer. Channel 1 requests IRQ **`0x41` (65 decimal)** with handler `0x8000D1ED` and handler argument **1**. The low-memory registration function and controller delivery remain unresolved, so this does not establish hardware RAW completion.

## Native registration boundary

Source `0xFE75432A` receives channel 1, application callback `0x01BB709B` and a supplied callback argument. It stores the application callback, argument and enabled tag 1 at `0x01AD8350/+4/+8`. Two fixtures use arguments zero and `0x12345678` to distinguish that callback argument from the argument passed to the IRQ controller registration.

The installer loads the real channel table and tail-calls wrapper `0xFE74B008`. That wrapper accepts IRQ values strictly between zero and 432, then calls ARM veneer `0xFE74F96C`. Its actual literal at `0xFE74F970` is **`0x000006FD`**. Native execution reaches Thumb entry **`0x6FC`** with:

```text
R0 = 0x8000D1ED  channel IRQ handler
R1 = 1           channel index passed as IRQ-handler argument
R2 = 0x41        IRQ number
```

The experiment stops before the first low-memory instruction. No registration table write, import return or successful IRQ installation is invented. On return from this import, static wrapper code would call `0xFE747C20`; the probe does not pretend the import returned in order to execute that continuation.

## Separate IRQ-enable boundary

Six independent calls execute `0xFE747C20` with supplied IRQ limits at global `0x01AC0044`. The native condition rejects nonpositive signed IRQs and IRQs at or above the limit. With supplied limit 432, IRQs `0x41` and 431 reach store instruction `0xFE747C36`, preparing the IRQ value for register **`0xD5011010`**. Execution stops before that store, with controller registers unmapped.

IRQ zero, signed -1, IRQ 432 with limit 432, and IRQ `0x41` with limit `0x41` return `0xFFFFFFFF`. This verifies the boundary check and write target, not the live limit, register semantics, actual enablement or interrupt delivery. Static code after the store has a barrier and reads `0xD5011200`; those instructions are outside the executed path.

## Why the low import is not replaced with a guessed function

The low address belongs to a distinct mapping problem. An initial main-image copy loop at `0xFE0A00B2` references source `0xFED58B7C`, destination zero and end `0x3D4A`. Applying only that initial-copy correspondence would place address `0x6FC` at source `0xFED59278`, inside a diagnostic/assertion sequence rather than an established three-argument IRQ-registration entry. This candidate is not sufficient to map the import. It does not prove that the low-memory code is absent from all update records, nor identify the active image/core or later copy sequence.

The experiment therefore maps a fetchable stop page at zero and executes **no** code from it. Boot-stage selection, later relocation/overlay and the actual low-memory function must be reconciled before following registration or IRQ dispatch through that address. Existing private FIR records can still be investigated on the PC; no new camera read is required for this bounded next step.

## Reproduction and limits

```sh
python scripts/probe_750d_irq_registration.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-irq-registration.json) records eight passing cases: two registration preparations and six independent enable checks. Exact identified main-record size `0xCFB688` and SHA-256 are checked before importing Unicorn 2.1.4. Cortex-A9 executes a compatible instruction subset, not a Cortex-R4 camera system.

Firmware, the scoped channel-table copy and stop pages are read/execute; supplied globals, callback record and stack are read/write without execute permission. Code/write guards restrict each stage, bounded to 128 instructions / 0.5 seconds. Scoped table copying is not validated boot relocation. No native calls are stubbed, no low import returns, and no controller registers are mapped. Hardware completion, DMA, sensor pixels, cache coherence and a frame lease remain unverified. Camera bindings stay disabled.
