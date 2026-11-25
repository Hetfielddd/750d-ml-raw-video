# Driver start gate and the timer notification path

The [real readout methods](750d-readout-methods.md) prepare another StartDriver request inside completion processing. This experiment examines the receiving driver's event-bit gate. The gate requires all bits of `0x8000007F`, but a separate registered timer callback can request setting the entire mask. Passing this gate alone therefore does not independently establish RAW-DMA completion or permission to copy pixels.

The later [no-work RAW notification checks](750d-raw-notification.md) add a second qualification: an empty RAW entry sets its event bit through real kernel lookup/update, and the actual ALL-bit wait accepts the result when other bits were explicitly preseeded. No sensor transfer, live timing or blocked wakeup is inferred.

## Native wait and clear requests

Driver state is based at `0x01AC1830` (G). Start routine `0xFE750E1C` loads mask `0x8000007F` at `0xFE750E2E`. Its wait wrapper `0xFE74FBAA` prepares low-level call `0xFE749DBA` with the encoded event handle from G + 44 shifted right one, the mask, options 4 and an output pointer. A zero timeout input becomes a null timeout pointer. The experiment stops before low-level interrupt/object lookup, without entering scheduling.

The separately executed pure wait-decision core `0xFE74BDA2` treats options bit 2 as ALL: `(requested & ~flags) == 0`. Missing-bit cases stop at `0xFE74BDDC` before blocking. Ready cases return zero, copy current flags to the supplied output and leave flags unchanged. Options zero provides an ANY-bit control case.

The next start-path wrapper, entered at `0xFE750E3A`, prepares `0xFE749D84` with the complemented mask and options 4. The pure update core `0xFE74BCD4` uses these arguments to clear the requested bits. Component-mask reset at G + 4 and subsequent component starts are outside this probe.

## A second path can satisfy the whole mask

Callback body `0xFE750D04`, stored callback value `0x80009925` under the reviewed driver mapping, checks G + 40. When nonzero it tail-calls setter `0xFE74FC2A` with the same event handle and the **entire** `0x8000007F` mask. The native wrapper prepares `0xFE749D84` with options zero; the separately executed update core ORs these bits into a supplied event object without waiters.

Static initialization review at `0xFE750D16` finds event creation with initial bits `0x7F` and registration of callback value `0x80009925` through the veneer at `0xFE74F210`. Its reviewed application target is `0xFE839FE2`; the adjacent callback path carries the `_VtimerInterruptCBR` diagnostic label. Registration, timer delivery, frequency and scheduling are not executed or established here. A pre-start path writes G + 40, but the live conditions enabling this callback still need tracing. This evidence does not establish a timeout policy.

The OS event flags examined here are separate from software component mask G + 4. The earlier [component and aggregate callback experiment](750d-completion-events.md) remains evidence about that software mask and callback order, not proof of physical frame completion.

## Timer enable lifecycle and the preceding wait

The actual application transition table at source `0xFE9744F8` maps event 2 / state zero to `0xFE80FDAE` under the scoped application mapping. The handler calls ARM veneer `0xFE86F290` first, then forwards its saved parameter through `0xFE86F288`. Their actual stored targets `0x80009AAB` and `0x80009A3D` correspond to source `0xFE750E8A` and `0xFE750E1C` under the reviewed driver mapping. The probe verifies these table/veneer words and independently executes the two handler slices to their imported-call boundaries. It does not execute the first imported call and pretend it returned.

This identifies a preparation function **before** the start function. Its post-IRQ-disable slice at `0xFE750E90` writes G + 40 = 1, enabling the timer notification, and stops before IRQ restore. A separately entered post-restore slice at `0xFE750E9A` prepares a wait for **`0x7F`**, options 4, with a null timeout pointer. The pure decision core confirms that `0x7F` satisfies this preceding wait, whereas `0x6F` does not. Neither the enable slice nor this wrapper preparation changes software component mask G + 4.

Thus the full-mask start wait is preceded by another ALL-bit wait for the seven component bits. Both concern the same event handle; the enabled timer callback can request all seven bits as part of its full mask. The preceding wait therefore does not independently resolve the completion ambiguity. This is a call-order and condition result, not an observed live timer sequence or proof that every event-2 call returns.

The reviewed cleanup body beginning `0xFE750FE4` contains a separate post-IRQ-disable slice at `0xFE75102C` that clears G + 40 using zero R5 prepared at `0xFE751024`. The probe enters that slice with supplied zero R5 and stops before IRQ restore. Static code then calls unregister veneer `0xFE74F218` and deletes the event through `0xFE74FA80`; those operations and the earlier cleanup calls are not executed. No timer-flag clear occurs in the reviewed start body `0xFE750E1C`–`0xFE750E8A`. This is scoped lifecycle evidence, not a claim that all writers throughout the firmware have been enumerated.

## Reproduction and limits

```sh
python scripts/probe_750d_start_gate.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-start-gate.json): 21 native cases, comprising ten ALL/ANY decisions, wait/clear preparation, disabled/enabled callback preparation, three lifecycle/preparation slices, two event-2 handler slices and two pure flag updates. Inputs include an artificial even handle, event object, flags, zero OS guard globals and no waiters. Wrapper and pure-core stages are separate; OS object lookup is not simulated as successful.

The exact main-record size and SHA-256 are checked before importing Unicorn. Cortex-A9 executes a compatible instruction subset, not a Cortex-R4 camera system. Firmware and return sentinel are read/execute; supplied data and stack are read/write without execute permission. Guards restrict code ranges and writes. Each stage is bounded to 128 instructions / 0.5 seconds. No native calls are stubbed into success. No firmware bytes are published.

No scheduler, hardware interrupt, DMA transfer, live pixel memory, cache operation or frame ownership has been validated. Camera bindings remain disabled. The next requirement is an independent actual RAW-transfer completion condition paired with a boundary before reuse/restart; this event wait cannot supply that contract alone. The [next experiment](750d-raw-irq.md) executes the channel IRQ body against artificial register RAM and identifies the remaining controller-qualification boundary.
