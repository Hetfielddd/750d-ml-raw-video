# Peer-kernel mapping connects RAW IRQ registration to dispatch

The [IRQ-body experiment](750d-raw-irq.md) traced callback forwarding after direct invocation. This step executes the actual channel callback installer through the IRQ wrapper, ARM import veneer and a scoped copy of the peer kernel's low-memory registration function. A separately invoked dispatcher then consumes the table written by native registration and selects RAW handler `0x8000D1ED` with channel argument **1** for IRQ **`0x41` (65 decimal)**. Boot relocation and physical controller delivery are not executed, so hardware RAW completion remains unverified.

## Native registration boundary

Source `0xFE75432A` receives channel 1, application callback `0x01BB709B` and a supplied callback argument. It stores the application callback, argument and enabled tag 1 at `0x01AD8350/+4/+8`. Two fixtures use arguments zero and `0x12345678` to distinguish that callback argument from the argument passed to the IRQ controller registration.

The installer loads the real channel table and tail-calls wrapper `0xFE74B008`. That wrapper accepts IRQ values strictly between zero and 432, then calls ARM veneer `0xFE74F96C`. Its actual literal at `0xFE74F970` is **`0x000006FD`**. Native execution reaches Thumb entry **`0x6FC`** with:

```text
R0 = 0x8000D1ED  channel IRQ handler
R1 = 1           channel index passed as IRQ-handler argument
R2 = 0x41        IRQ number
```

Two original boundary fixtures stop before the first low-memory instruction. Four additional fixtures explicitly load the reviewed peer-kernel page, execute that actual function and its CPU interrupt-mask helper, and continue through its real return into `0xFE747C20`. They stop before the controller enable store. No import return or successful hardware IRQ installation is invented.

## The distinct peer-kernel page

Source **`0xFE744D60`** begins another exception-vector block. A separate data reference at `0xFE6E83E8` points to that source; adjacent references include `0xFE747BE0`, the source corresponding to the reviewed driver code at runtime `0x80000800`. These references support a separate peer image, but their loading consumer and live boot sequence are not executed here.

Under the scoped low-page correspondence, `0x6FC` maps to source **`0xFE74545C`**, an actual three-argument IRQ registration routine. It preserves the handler, argument and IRQ in registers, calls native CPU-mask helper `0x21A` (source `0xFE744F7A`), writes handler/argument into an eight-byte slot, then restores the prior IRQ mask through the same helper and returns zero. The helper executes native CPSR reads/writes; no mask operation is replaced by a stub.

Its actual table-base literal is `0x01ACB05C`. IRQ `0x41` selects slot **`0x01ACB264`**, populated with `[0x8000D1ED, 1]`. Four fixtures cover two application callback arguments and two supplied initial CPU IRQ-mask states. All preserve that initial mask and reach the real enable-store boundary. The distinct application callback record still receives `[0x01BB709B, supplied_argument, 1]`.

## Native table consumption by the dispatcher

The peer's IRQ-vector path references dispatcher `0x67D`, whose Thumb body `0x67C` corresponds to source `0xFE7453DC`. It reads the controller's current IRQ at `0xD5011000` before calling that dispatcher. Later PC cases execute the actual nested vector through the dispatcher, callback and exception return with a supplied controller value in passive RAM. [Peer vector experiment](750d-raw-notification.md#peer-irq-vector-through-native-exception-return).

After each of the four native registrations, a **separate direct invocation** of the actual dispatcher supplies IRQ `0x41` and uses the table just written by registration. Optional before/after dispatch hooks at `0x01AC001C/+4` are supplied null. The dispatcher selects `0x8000D1ED` and loads argument 1 from its table slot. Execution stops before the selected handler's first instruction. These calls do not finish the pending enable operation or simulate hardware delivery. Together with the earlier IRQ-body experiment, this identifies the native software route; it does not join separate experiments into a timed hardware transfer.

## Separate IRQ-enable boundary

Six independent calls execute `0xFE747C20` with supplied IRQ limits at global `0x01AC0044`. The native condition rejects nonpositive signed IRQs and IRQs at or above the limit. With supplied limit 432, IRQs `0x41` and 431 reach store instruction `0xFE747C36`, preparing the IRQ value for register **`0xD5011010`**. Execution stops before that store, with controller registers unmapped.

IRQ zero, signed -1, IRQ 432 with limit 432, and IRQ `0x41` with limit `0x41` return `0xFFFFFFFF`. This verifies the boundary check and write target, not the live limit, register semantics, actual enablement or interrupt delivery. Static code after the store has a barrier and reads `0xD5011200`; those instructions are outside the executed path.

## Why the primary-core copy was the wrong candidate

The low address belongs to a distinct mapping problem. An initial main-image copy loop at `0xFE0A00B2` references source `0xFED58B7C`, destination zero and end `0x3D4A`. Applying only that initial-copy correspondence would place address `0x6FC` at source `0xFED59278`, inside a diagnostic/assertion sequence rather than an established three-argument IRQ-registration entry. This candidate is not sufficient to map the import. It does not prove that the low-memory code is absent from all update records, nor identify the active image/core or later copy sequence.

The new peer page resolves the function-level mismatch without substituting unrelated code. It remains a scoped experimental copy: the peer loader, active core, memory protection and complete boot relocation still require independent validation. No complete low-memory image for the running camera is asserted.

## Reproduction and limits

```sh
python scripts/probe_750d_irq_registration.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-irq-registration.json) records 16 passing cases: two import-boundary preparations, four registrations through the peer low page, four separate table-consuming dispatches, and six independent enable checks. Exact identified main-record size `0xCFB688` and SHA-256 are checked before importing Unicorn 2.1.4. Cortex-A9 executes a compatible instruction subset, not a Cortex-R4 camera system. CPU mask fixtures use a supplied privileged SVC state; this is not a full interrupt-context model.

Firmware, the scoped channel-table/low-kernel copies and stop pages are read/execute; supplied globals, IRQ/application records and stack are read/write without execute permission. Code/write guards restrict each stage, bounded to 128 instructions / 0.5 seconds. Scoped copying is not validated boot relocation. No native calls are stubbed and no controller registers are mapped. Hardware completion, DMA, sensor pixels, cache coherence and a frame lease remain unverified. Camera bindings stay disabled.
