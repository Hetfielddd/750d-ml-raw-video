# No-work RAW callbacks can satisfy native synchronization flags

Ten new PC scenarios execute the real RAW-to-driver callback and kernel event lookup/update chain without callback slices or synthesized success returns. Empty-pending and uninitialized RAW entries set the same component/event bit as a separately invoked channel IRQ. With other event bits explicitly preseeded, the actual ALL-bit wait returns zero after this no-work path.

This identifies a software synchronization contract, not a completed sensor frame. It does not demonstrate a camera bug, spurious IRQ or live stale-event sequence. Other-component and high event bits are experiment inputs, and application task callbacks are deliberately null.

## Complete callback and event-update route

The experiment enters actual RAW handler `0xFE8395C4` with one of two supplied states:

- Initialized, non-alternate state with pending address zero.
- Uninitialized state, retaining a nonzero pending address marker.

Both paths call the function/argument supplied at RAW state `0x01AC2220 + 8/+12`. The function is the previously identified real driver callback `0x80009D8F`, corresponding to source `0xFE75116E`. Its argument marker is forwarded unchanged.

The driver callback executes its actual IRQ mask helper, ORs `0x10` into component word `0x01AC1830 + 4`, and calls event-set wrapper source `0xFE74FC2A` (runtime `0x8000884A`). Native lower wrapper `0xFE749D84`, event-object lookup `0xFE74BBD4` and update core `0xFE74BCD4` all execute. The no-waiter update ORs `0x10` into the event object's flags.

If the component word becomes exactly `0x7F`, native code restores the incoming IRQ state and clears that component word. Otherwise it retains the partial word and restores IRQ state before returning. The corresponding event bits remain set. Complete callback invocations restore their native stack and incoming IRQ mask.

The driver's optional application RAW/aggregate callbacks at offsets 20/12 are supplied null. No task event 7/6 is enqueued in this experiment. Their absence lets the real driver/event path execute without a heap-allocation or task-scheduling cut; it is not a claim about the live camera's callback registrations.

## Real event-object lookup on supplied state

The native lookup uses table pointer global `0x01AC05B8` and capacity global `0x01AC011C`. A supplied 24-byte event object has flags at offset 8, generation at 16, waiter count at 18 and active flags at 20. Generation 7, index 1 produces fixture handle `0x000E0002` accepted by the actual wrappers and lookup. Capacity one and zero waiters are supplied inputs, not measured live state. No event creation, deletion or waiting-task structure is fabricated as successful.

Eight no-work cases cover both entry states, initial component masks 0/`0x6F`, and incoming IRQ masks 0/`0x80`:

- From component mask zero and event flags zero, the native path leaves both at `0x10`.
- From component mask `0x6F` and event flags `0x8000006F`, it writes component `0x7F`, writes event flags `0x8000007F`, and clears component mask to zero.

The high event bit and other-component bits in the second fixture are explicitly preseeded. They are not evidence that other hardware work completed or that the timer supplied them in this execution.

No device-register pages are mapped in these eight cases. The no-work path executes to its real return without channel command stores, a status read, IRQ delivery or sensor transfer. The uninitialized case retains its nonzero pending marker; a pointer's presence does not change this no-work notification route.

## Native ALL-bit wait before and after notification

For the preseeded fixtures, a separate call to actual wait wrapper `0xFE74FBAA` requests mask `0x8000007F`, options ALL and timeout argument zero. Before notification, the real lookup/decision path reaches `0xFE74BDDC`, before waiter bookkeeping and scheduler execution, because RAW bit `0x10` is missing. That call does not return; it remains IRQ-masked at the stop boundary.

The experiment does not wake that call or give it a successful result. It restores the initial CPU state for a separate no-work callback invocation on the unchanged event object. After the callback's native update, a new invocation of the actual wait wrapper returns zero, restores its stack and incoming IRQ mask, and leaves the now-complete event flags unchanged.

This executes native acceptance of flags after no-work notification. It does not execute a blocked wakeup, task switch, hardware completion or a real StartDriver operation. The [earlier timer analysis](750d-start-gate.md) separately identifies another possible producer of the full mask; no timer callback executes here.

## Comparison with the RAW IRQ body

Two further fixtures directly invoke channel-1 IRQ body `0xFE7545CC` with supplied status 0/4 and the software-zero branch derived by the earlier [configuration/start investigation](750d-raw-irq.md). They execute the actual application forwarding wrapper `0x01BB709B`, then the same real driver/event chain through return.

Status 4 clears channel control; status zero does not. Both issue the reviewed base-register update and set the same event bit. Artificial device registers are ordinary RAM only for these two cases. Controller delivery, acknowledgement/deassertion and DMA behavior are not modeled. These cases do not establish which physical status/IRQ corresponds to a valid completed RAW frame.

The driver/event path therefore does not preserve a distinction between the reviewed no-work entry and the directly invoked IRQ in its resulting RAW bit. Image-buffer identity, completion qualification and safe source reuse need independent evidence. The 7D2 donor's opposite-buffer/VSYNC contract cannot be replaced with this flag or a zero wait result.

## Peer IRQ vector through native exception return

Four additional PC cases run from the peer's Thumb exception vector at `0x18` through the RAW callback and back to the interrupted context. Native registration at `0x6FC` fills the IRQ `0x41` table slot with the channel-1 handler and its argument. The fixture supplies the CPU's nested IRQ entry state and places `0x41` at controller address `0xD5011000`. The native vector reads this word, stores the IRQ number at `0x01AC0040` and selects the handler through the real dispatcher and the installed table. Optional dispatch hooks are null.

Channel status 0 and 4 exercise two different channel cleanup branches. Each reaches the callback and updates the RAW event flag `0x10`. With the other flags preseeded, both cases reach event word `0x8000007F` and clear the driver component word. The vector then writes the IRQ number to `0xD5011010`, reads that register and returns through its actual exception-return instruction. The probe checks the order, restored stack and selected interrupted registers. It uses passive RAM for controller and channel registers.

This identifies where software obtains the IRQ number and how it uses it. The checked vector does not read a frame address or byte count. Which physical condition makes the controller present `0x41` remains an open question. The fixture supplies an already nested interrupt, so first-level IRQ scheduling and the controller's physical delivery or re-enable behavior remain outside the experiment.

## Reproduction and limits

```sh
python scripts/probe_750d_raw_notification.py /private/750d-analysis/record-06.bin
```

The evidence records fourteen passing cases, native mask/event writes, supplied flags, IRQ state, register accesses and separate wait results. Exact main-record size `0xCFB688` and SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2` are checked before Unicorn import. [Machine-readable results](evidence/750d-raw-notification.json).

Unicorn 2.1.4 Cortex-A9 executes compatible scalar instructions, not a Cortex-R4 camera system. Scoped driver/application and peer-low-kernel copies are explicit experiment mappings. Code pages are read/execute; supplied data/stacks/shadows and optional artificial register RAM are read/write without execute permission. Code/write/read guards and a 0.5-second time limit apply to each invocation. The instruction limits are 384 for vector execution, 64 for its registration and 256 for the other invocations. Native CPSR helpers execute; no native calls are stubbed. Firmware and pixel data are not distributed. Sensor capture, cache coherence, physical IRQ delivery and frame ownership remain unverified. Camera bindings remain disabled; camera and SD card are untouched.
