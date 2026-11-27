# Complete RAW software command order on artificial register RAM

Ten native PC scenarios now execute the reviewed non-alternate RAW handler from entry `0xFE8395C4` through its real return, including its register writers and IRQ save/restore helpers. Earlier experiments stopped before channel start or separately entered the final pending-clear tail. This experiment removes those internal cuts **only by replacing device register locations with ordinary RAM**. It does not model a peripheral, transfer pixels or validate successful capture.

The caller's driver configuration and OS transport remain outside this experiment. This is the complete reviewed RAW sub-handler on supplied channel-1 state, not a full camera driver or Live View run.

## Native write sequence

With initialization word nonzero, alternate flag zero, pending address A=`0x5C62C000` and skip-address flag zero, native execution performs these observable stores in order:

1. Destination `0xD0004108` receives normalized address `0x1C62C000`.
2. Control `0xD0004104` receives its shadow-derived value with bit 29 set.
3. Channel command `0xD0004100` receives 1, after the native DSB instruction.
4. Register `0xD0037014` receives `(old_shadow & ~63) | (format_field & 63)` while IRQs are masked.
5. Register `0xD0008090` receives 1 after restoring the incoming IRQ mask.
6. Pending word `0x01AC2220 + 36` becomes zero.

Each register writer updates the supplied shadow and its artificial register location. A deliberately different initial RAM value at `0xD0037014` verifies that the read/modify/write uses the shadow. Geometry word `0xD0004110` and its shadow remain unchanged in these scenarios.

These names describe code usage, not a verified peripheral timing model. In particular, the ordering of the channel-command store before the format-field update does not establish when hardware latches either value or when a sensor transfer begins. The later `0xD0008090` store also needs peripheral qualification. Format markers 0, 34 and `0xFFFFFFFF` test six-bit masking and preservation of other bits; they do not establish which marker produces valid RAW14 pixels.

## Native interrupt helpers

The actual veneers at `0xFE86F910` / `0xFE86F918` select runtime `0x80003D23` / `0x80003D27`. Their driver trampolines reach peer low-kernel Thumb helpers `0x44D` / `0x45F`. The peer low page comes from main-record source `0xFE744D60`, separately from the primary core's different kernel mapping.

Those helpers execute MRS/MSR on CPSR: save the incoming IRQ bit, mask IRQs, then restore that bit. All three format fixtures run with incoming IRQs both enabled and masked. The format-register store is masked in all six cases; the other observed stores inherit the caller's IRQ state. Returned calls restore both the original stack and incoming IRQ mask.

The local IRQ section does not cover the entire address/command/pending-clear sequence. This is not proof of a live interrupt race: the caller may already serialize execution, and IRQ masking does not itself stop another core or a DMA engine. It supplies a concrete boundary for future hook analysis.

## Skip-address, empty and repeated invocation controls

With the channel's software skip-address byte at `0x01AD8BD8` set to 1, the normal destination store is omitted. An earlier B destination remains, while control, channel-command, format, later command and pending-clear stores still execute. Thus this flag suppresses an address update; it does not freeze the channel or establish a completed-buffer lease. The [snapshot/override mechanism](750d-raw-override-contract.md) still needs its own lifecycle and ownership contract.

Empty-pending and uninitialized fixtures reach the supplied callback boundary without any of these register stores. The callback argument is forwarded unchanged; its body is not executed. The initialized, nonempty path instead returns after the command stores, without reaching that callback. This further separates a software return or callback from verified sensor completion.

The repeated-invocation scenario runs the complete software handler for A, observes pending zero, then invokes it again without configuration. That second call takes the empty callback path and emits no register commands. Actual setter `0xFE8396B0` republishes B; a third invocation executes the complete command sequence for normalized B=`0x1E000000` and clears pending again. No post-command clear or internal return is supplied by the host in this scenario.

## Destination state at the RAW interrupt

Ten additional runs preserve the same RAM and shadow across the real command path, the native shadow reader at `0xFE753834`, the channel-1 IRQ body and its application forwarder. Each sequence is checked with supplied status words 0 and 4. The IRQ body is invoked explicitly after these five setups.

- Start A. The programmed address is A and the pending slot is empty.
- Start A, then publish B. The programmed address is A and the pending slot contains B.
- Start A, publish B, then execute a second start. The programmed address is B and the pending slot is empty.
- Submit a start with pending A and the skip-address flag set. The fixture's preprogrammed address B is preserved and the pending slot is emptied.
- Start A, then execute the native stop request. The programmed address is A and the stop flag is set.

The probe supplies a different word at the hardware-register location before the IRQ to distinguish it from the shadow. The native shadow reader still returns the earlier programmed address. The IRQ reads the status word at `0xD0004130` and preserves the destination word, the destination shadow and any pending address. At the driver callback boundary, it forwards the same registered argument in all ten cases. This observed route carries no snapshot of the address chosen at start and no per-transfer identifier. The supplied register word is a marker and has no DMA cursor semantics.

The result narrows the adapter requirement. A buffer reference needs to be retained when its destination is programmed, with separate evidence that a later hardware notification belongs to that transfer and that the buffer remains readable while the recorder copies it. Reading the pending address or the most recently programmed shadow at notification time can identify a later submission. The experiment prescribes no live ordering for these supplied interleavings.

## Native RAW setup compared with IPC

The RAW initializer call site at `0xFE83945A` passes channel 1 and routing value 0 through veneer `0xFE86F828`. The actual driver routine writes 0 to `0xD0005004` and updates the peer shadow. The IPC receive routine writes `0x33` to the same register and prepares control word `0x40000003`. The two paths program the same register block with different settings. [IPC configuration and status checks](750d-channel-status.md).

Three PC sequences execute the routing call and the normal RAW initializer's register setup on passive RAM. They supply channel 1, a 2,048 × 1,080 geometry fixture and selector 1, 2 or 3. The initializer writes its format controls and actual packed geometry, then clears the pending address. With initial control shadow `0x8`, the three paths leave control at `0x40000008`, `0x1008` and `0x8` respectively. The native publication and start path then writes destination `0x1C62C000`, sets control bit 29 and writes channel and sensor-path command values. It leaves the route at 0. These sequences use the supplied initialized context and a cleared local descriptor. They omit allocation and callback registration. Selector 1 is already present in the reviewed mode-3 fixture. The other selectors exercise native branches. [Source of the mode-3 fixture fields](750d-raw-geometry.md).

Separate post-start calls execute three target driver readers against supplied register words. The status reader at `0xFE754310` returns the low two bits of `0xD0004130`, collapsing `2`, `6` and `0x102` to the same result. The reader at `0xFE7554DA` isolates bit 2. The IPC poll, in comparison, accepts only the entire word `2`. The channel-address reader at `0xFE75501E` reaches the direct hardware load and returns a supplied marker at `0xD0004108`, independent of the programmed address still in the shadow. This is the same distinction used by Magic Lantern's EDMAC diagnostic, which compares an actual address read with a computed end. A live caller for the reviewed target reader and the behavior of the address during sensor DMA remain unverified. [Magic Lantern EDMAC diagnostic](https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/modules/dev_tools/edmac/edmac_test.c#L109).

## Consequence for a 7D2-style recorder

The native reader's callers were subsequently traced through the physical-address import. The checked Image2 and Live View SAF shutdown paths pass address words to diagnostics. The reviewed RAW teardown helper performs a separate command write. [Native caller checks](750d-dma-address-callers.md).

The donor's VSYNC callback redirects an upcoming capture and processes the opposite buffer. On the 750D route reviewed here, pending-address configuration is consumed once by software, normal address programming may replace an earlier override, and skip-address does not prevent command submission. The [two-command queue experiment](750d-task-queue-order.md) also shows that configurations share one pending slot.

A reliable rotation protocol must therefore identify a destination-selection point relative to a qualified sensor completion boundary. Neither an empty callback, software handler return, pending clear nor skip-address flag supplies that boundary. This experiment improves the address/command-order evidence; image contents, packing, hardware completion, cache coherence and a safe copy interval remain unverified.

## Reproduction

```sh
python scripts/probe_750d_raw_command_order.py /private/750d-analysis/record-06.bin
```

The evidence contains ten command-order checks, ten command-to-IRQ address checks and three configuration and start sequences with status and address sampling. Exact main-record size `0xCFB688` and SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2` are checked before Unicorn import. [Machine-readable results](evidence/750d-raw-command-order.json).

Unicorn 2.1.4 Cortex-A9 executes a compatible scalar ARM/Thumb subset, not a Cortex-R4 camera model. Main record, scoped runtime/peer-kernel copies and stop page are read/execute. Supplied state, stacks, shadows and artificial register pages are read/write without execute permission. Code and write guards apply with a 0.5-second limit per invocation and limits of 512 instructions for initialization and 256 for other slices. Register read guards check the IRQ and reader cases. Pixel addresses are unmapped. No native calls are stubbed; there is no scheduler, mailbox, sensor, DMA, cache or completion model. Firmware bytes are not distributed. Camera bindings remain disabled; the camera and SD card are untouched.
