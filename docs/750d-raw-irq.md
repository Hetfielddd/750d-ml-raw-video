# RAW channel interrupt body with artificial register RAM

The [start-gate investigation](750d-start-gate.md) established that event bits alone cannot prove RAW completion. This experiment executes the channel-1 interrupt body, its real register-write helpers and the RAW application's callback forwarding together. It reaches the driver's registered callback in all eight supplied status/flag combinations, including a zero status word. The meaning of the interrupt delivered by the controller remains unverified.

## Actual table and callback route

Channel table source `0xFE756CB4`, stride 12, has channel-1 row `[0x41, 0xD0004100, 0x8000D1ED]`. The IRQ number is **hexadecimal `0x41` (65 decimal)**. Stored handler `0x8000D1ED` corresponds to source body `0xFE7545CC` under the reviewed driver mapping.

The body reads the channel's status word at base + `0x30`, here `0xD0004130`. It also reads software words `0x01AD81C8` and, on one branch, `0x01AD8288`. The second word is a separate array entry, **not** callback-record offset 8 at `0x01AD8358`.

For a supplied callback record at `0x01AD8350`, the body eventually selects function `0x01BB709B` and its argument. This actual application callback, source `0xFE839402`, loads a second callback and argument from RAW state `0x01AC2220 + 8/+12`. The fixture supplies the earlier identified driver callback `0x80009D8F` (source `0xFE75116E`) and a marker argument. Execution stops before that driver callback executes. No callback return or native helper success is fabricated.

## Verified branch behavior

Eight cases cover status word 0 or 4, software word `0x01AD81C8` equal to 0 or 1, and secondary word `0x01AD8288` equal to 0 or 1:

- Status bit 2 set: write zero to control register base + 4.
- Status bit 2 clear and software word not 1: leave control unchanged.
- Status bit 2 clear, software word 1 and secondary word zero: write zero to control.
- Status bit 2 clear, software word 1 and secondary word nonzero: write `(control_shadow & ~7) | 2` to control.

Every case then uses native shadow-based read/modify/write to request `(start_shadow & 2) | 4` at base + 0, followed by callback forwarding. Helpers `0xFE753806` and `0xFE753840` update both their software shadow and the artificial register RAM. Supplied start marker `0xA5A50003` yields value 6; supplied control marker `0xDEADBEEF` yields `0xDEADBEEA` on the masked-update branch.

This does not identify status bit 2 as a completion bit. The tested body has no rejection of a zero status value before callback dispatch. On real hardware, the controller's delivered IRQ may already qualify an event; direct handler invocation in this experiment bypasses that controller. Neither the zero-status fixture nor callback reachability proves a real spurious interrupt, successful DMA or a recorder-ready frame.

## Registration boundary from static review

The channel callback installer `0xFE75432A` publishes the callback record and loads the actual channel-table IRQ and handler. It tail-calls `0xFE74B008` with arguments `[0, 0x41, 0x8000D1ED, 1]` for channel 1. That wrapper checks the IRQ range, calls import veneer `0xFE74F96C` with handler, channel argument and IRQ, then calls `0xFE747C20`. Registration/controller operations are not executed by this probe. The [subsequent experiment](750d-irq-registration.md) executes registration preparation to low entry `0x6FC` and separately checks the enable boundary; low-memory routing remains unresolved.

## Reproduction and scope

```sh
python scripts/probe_750d_raw_irq.py /private/750d-analysis/record-06.bin
```

[Machine-readable evidence](evidence/750d-raw-irq.json) records eight passing cases and the exact artificial register writes. Input size `0xCFB688` and the identified main-record SHA-256 are checked before importing Unicorn. Requires Unicorn 2.1.4. Cortex-A9 executes compatible instructions; it is not a Cortex-R4 camera-system model.

The status/register page is explicitly mapped as ordinary read/write RAM. Native stores have ordinary RAM behavior; hardware write-one-to-clear, device acknowledgement, interrupt deassertion and DMA effects are **not** modeled. This differs from earlier probes that stopped before MMIO stores. No physical hardware is accessed.

Firmware and reviewed scoped table/application page copies are read/execute. Synthetic state, shadow, register RAM and stack are read/write without execute permission. These page copies are experimental source/runtime correspondences, not verified boot relocations. A mapped callback boundary permits instruction fetch only so the code hook can stop before its first instruction. Guards restrict executed ranges, writes and artificial register reads; each case is bounded to 128 instructions / 0.5 seconds. The record, flags, callback and invocation are supplied. No sensor pixels, cache contract, hardware completion, buffer ownership or usable RAW recording is established. Camera bindings remain disabled.
