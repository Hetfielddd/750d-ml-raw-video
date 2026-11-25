# RAW channel interrupt body with artificial register RAM

The [start-gate investigation](750d-start-gate.md) established that event bits alone cannot prove RAW completion. This experiment executes the channel-1 interrupt body, its real register-write helpers and the RAW application's callback forwarding together. It reaches the driver's registered callback in eight supplied status/flag combinations, including a zero status word. Four additional cases first execute native channel configuration and start, deriving the two software flags rather than supplying their IRQ-entry values. The meaning of the interrupt delivered by the controller remains unverified.

The [later no-work notification experiment](750d-raw-notification.md) now executes this driver's callback through actual kernel event lookup/update and return, with optional application task callbacks null. Empty RAW entries reach the same event bit without mapped capture registers; separate IRQ cases use the real forwarding wrapper. This qualifies software synchronization, not physical completion.

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

## Software flags derived from native configuration and start

The reviewed normal RAW initialization calls veneer `0xFE86F868` with channel index and zero at `0xFE8395B0`. Its stored target `0x8000C5DF` corresponds to source `0xFE7539BE`. The experiment executes that actual function on channel 1 with R1 zero: it clears secondary word `0x01AD8288` and updates control to `control_shadow & ~7` through the real shadow/register helper. This is a low-bit control setting, not an identified interrupt-enable mask.

Next, actual start routine `0xFE75395E` clears software word `0x01AD81C8`, updates channel-1 control to `control_shadow | 0x20000000` and writes start value 1 to `0xD0004100`. These native operations use the same artificial register RAM and shadow as the following IRQ-body invocation. Both software words start at 1 to make their native clearing observable.

Four sequence cases cover supplied initial control zero or `0xDEADBEEF`, and supplied status zero or 4. After native configuration/start, control is respectively `0x20000000` or `0xFEADBEE8`, and both software words are zero. Directly invoking the IRQ body then leaves that control unchanged for status zero, or clears it for status 4; its base-register update writes value 4 because the native start shadow is now 1. All four cases forward the supplied callback argument without changing those software flags.

This narrows the earlier branch matrix: the reviewed configuration/start sequence produces the software-zero branch. It does not prove that every live IRQ arrives with those flags unchanged; other intervening firmware operations and hardware state have not been excluded. No transfer or completion is simulated between native start and the directly invoked IRQ body.

## Comparison with the DIGIC 6 donor

At the pinned Magic Lantern revision, [7D2 function overrides](https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/platform/7D2.112/function_overrides.c) implement the ordinary `RegisterEDmacCompleteCBR`, abort/pop registration and related EDMAC entry points as empty overrides. Its full-width copy path instead uses `_memcpy_fast` through `dma_memcpy`, then invokes the writer callback synchronously. The source explicitly notes the separate Omar core and uncertainty about direct EDMAC control.

Those empty donor registration functions cannot define the meaning of 750D IRQ `0x41`. Their names are not a hardware completion contract. The donor remains useful for full-width synchronous copy and VSYNC ordering; IRQ-source qualification, source ownership and cache handling still require target-specific evidence.

## Registration boundary from static review

The channel callback installer `0xFE75432A` publishes the callback record and loads the actual channel-table IRQ and handler. It tail-calls `0xFE74B008` with arguments `[0, 0x41, 0x8000D1ED, 1]` for channel 1. That wrapper checks the IRQ range, calls import veneer `0xFE74F96C` with handler, channel argument and IRQ, then calls `0xFE747C20`. Registration/controller operations are not executed by this probe. The [subsequent experiment](750d-irq-registration.md) follows registration through a distinct scoped peer-kernel page at low entry `0x6FC`, checks actual table publication/dispatch and stops before controller enablement. Physical delivery and boot relocation remain unverified.

## Reproduction and scope

```sh
python scripts/probe_750d_raw_irq.py /private/750d-analysis/record-06.bin
```

[Machine-readable evidence](evidence/750d-raw-irq.json) records 12 passing cases and the exact artificial register writes, including four native configuration/start sequences. Input size `0xCFB688` and the identified main-record SHA-256 are checked before importing Unicorn. Requires Unicorn 2.1.4. Cortex-A9 executes compatible instructions; it is not a Cortex-R4 camera-system model.

The status/register page is explicitly mapped as ordinary read/write RAM. Native stores have ordinary RAM behavior; hardware write-one-to-clear, device acknowledgement, interrupt deassertion and DMA effects are **not** modeled. This differs from earlier probes that stopped before MMIO stores. No physical hardware is accessed.

Firmware and reviewed scoped table/application page copies are read/execute. Synthetic state, shadow, register RAM and stack are read/write without execute permission. These page copies are experimental source/runtime correspondences, not verified boot relocations. A mapped callback boundary permits instruction fetch only so the code hook can stop before its first instruction. Guards restrict executed ranges, writes and artificial register reads; each native stage is bounded to 128 instructions / 0.5 seconds. The record, initial flags, callback and invocation are supplied. No sensor pixels, cache contract, hardware completion, buffer ownership or usable RAW recording is established. Camera bindings remain disabled.
