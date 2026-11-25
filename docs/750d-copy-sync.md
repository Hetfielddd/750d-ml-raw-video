# Native copy synchronization and Canon channel usage

The PC experiment now executes the copy wrapper's **actual semaphore fast paths**, rather than stopping at every OS import. It also connects the public wrapper, descriptor preparation, an independently invoked IRQ and the real semaphore/result/unlock path across an explicit omitted hardware-start instruction. This tests more of the software contract; it does not emulate DMA, scheduling or completed sensor frames.

## Primary kernel imports

The reviewed initial primary copy correspondence maps source `0xFED58B7C` to runtime zero. This experiment maps its first four pages read/execute. A separate primary-kernel correspondence maps source `0xFED5C0C8` to runtime `0x80000000`; eight scoped pages supply the semaphore routines, helpers and zero function. These are explicit analysis imports, not a reconstructed booted OS. The peer-kernel mapping used for sensor RAW IRQ research is different.

The copy path resolves these actual veneers:

- Take: ARM veneer `0xFE3CE0AC` jumps to Thumb `0x30B2`, which validates the tagged handle and calls runtime `0x800020B2` through its native import.
- Give/unlock: ARM veneer `0xFE3CE08C` jumps to Thumb `0x312A`, reaching runtime `0x8000208A`.
- IRQ signal: Thumb veneer `0xFE3CDD6C` loads `0x312B` and reaches **the same give function**.

The addresses for take/give agree with the pinned 750D platform semaphore stubs. The lower table lookup at `0x80003468` validates a one-based index, signed generation and active object type. The supplied upper handle is even: generation 7 / index 1 becomes `0xE0002`; the wrapper shifts it right by one before lower lookup. The object table pointer, capacity, generation, count and maximum are artificial fixtures.

Native critical-section helpers `0xFE172B84` and `0xFE172B94` save, mask and restore CPSR. Two take/give sequences verify restoration with the initial IRQ-mask bit both clear and set. These are emulator CPU-state checks, not evidence of physical interrupt behavior.

## What zero timeout and repeated give actually do

With available count 1, actual take decrements to 0 and returns zero. Actual give increments back to 1 and returns zero. No return value is supplied by the host.

With empty count 0 and upper timeout argument 0, the upper function supplies a **null timeout pointer**, not a zero-valued polling interval. The lower function decrements the count to -1, marks the supplied task as waiting and reaches wait-queue function `0x80000960`. The probe stops before entering that function. The reviewed path is therefore blocking/unbounded at this boundary; it is not a nonblocking readiness check. Task scheduling and wakeup remain unexecuted.

For a full supplied binary object (count equals maximum 1), the inner give routine leaves the count unchanged and returns an error, but the enclosing native kernel wrapper discards that result and returns zero. The upper give function consequently also returns zero. Repeated give is not an independently observable completion count in this experiment.

Invalid zero/odd handles, an incorrect generation, an out-of-range index and a supplied nonzero context gate at `0x44F8` reach the actual assertion/logger boundary `0x1E0C` without modifying the object's count. The logger is not executed. The exact live meaning and permitted values of the context globals remain unverified.

Four further cases execute the actual copy IRQ for each channel with an artificial status 8 and a valid supplied completion handle. The IRQ calls its real signal veneer, the actual give path changes count 0 to 1 and returns. A subsequent actual take consumes that same native-written count back to zero. These directly invoked handlers do not establish interrupt delivery or device completion.

Four non-null callback cases also execute the IRQ's actual unlock and continuation uninterrupted. The supplied lock changes from 0 to 1, the one-shot callback slot is cleared, and execution reaches the callback boundary with its original argument and restored stack. The callback itself is not executed. Unlike the earlier continuation-only probe, these cases need no separate entry after the OS unlock.

## A longer wrapper experiment with an explicit hardware cut

Five scenarios use actual wrapper `0xFE133EB2` and two supplied binary objects: a channel lock initially 1 and a completion object initially 0, except for the deliberately stale-signal fixture. Native code executes admission, lock acquisition, list processing, real descriptor building and controller-payload preparation. It supplies its own cache-operation arguments. With artificial classifier flag 4, actual `DSB SY` executes; this is not a cache/coherence model or a live primary mapping.

For a nonzero request, execution stops **before `0xFE133B88`**, leaving the controller start word unchanged at zero. The host saves the CPU context. In the two IRQ scenarios it independently calls the actual IRQ on a separate supplied stack, lets the actual give path return, and retains all resulting RAM changes. It then restores only the saved CPU context and starts at reviewed instruction `0xFE133B8A`, explicitly omitting the hardware-start store. No OS return is fabricated, and no pixel data is copied.

The outcomes are:

- Supplied IRQ status 8: the native completion take consumes the IRQ's signal, the wrapper returns 0 and restores the channel lock to 1.
- Supplied IRQ status 1: the same native path returns 1 and also releases the channel lock.
- No signal: the wrapper reaches the blocked-wait queue boundary with completion count -1; the channel lock remains acquired.
- Deliberately pre-existing signal and stale shared status 8: the wrapper returns 0 without a new IRQ. This is a fixture demonstrating the need to establish signal freshness, not proof that stale events occur on the camera.
- Zero byte count: the **entire native wrapper returns zero without any start cut**, skips controller submission, consumes no completion signal and releases its channel lock. This confirms the list core's zero-size filter and distinguishes it from the direct descriptor-builder underflow fixture.

The nonzero scenarios are connected software-path experiments with a declared cut and supplied event timing. They are not uninterrupted end-to-end hardware execution, blocked-task wakeup tests or evidence of safe frame ownership.

## Address-order correction from the complete caller

Following the full wrapper into the list core exposed reversed semantic labels in the earlier direct-builder experiment. The public signature remains `(channel, destination, source, bytes)`. The list core passes `(descriptor, channel, destination, source)` to the builder. It therefore writes **source at descriptor +4 / controller +0x14**, and **destination at descriptor +8 / controller +0x18**.

The direct-builder probe, evidence and [descriptor documentation](750d-copy-descriptor.md) are corrected. The longer wrapper scenarios independently assert these propagated addresses. No physical copy was previously attempted using the mislabeled direct-builder setup.

## Initialization and channel 0 is already used by Canon

Native channel initialization `0xFE133A38` first uses actual helper `0xFE1826A8` to initialize all four software rows to `[0, 2, 0, 2, 0, 0, 0]`. Four cases then enter the actual primary IRQ-registration import, register handler `0xFE133A37` and argument equal to the channel's IRQ number in primary table `0x3A3A0 + irq * 8`. They stop at `0xFE1C1D8E`, before the hardware IRQ-enable store to controller `0xD4011000`. The per-channel availability mask is still zero at that point. No successful registration/enable return or semaphore creation is fabricated.

Separate controller initializer `0xFE133AE2` clears its channel payload/control/status locations and sets controller bit 28 and software initialized flag. Two cases check its writes against ordinary register RAM and its already-initialized skip path with controller memory unmapped. Real MMIO effects remain unknown.

Static startup review at `0xFE0CDDDE` shows controller initialization followed by initialization requests for channels 0 and 1. This does not establish the camera's live mask or that either channel is available to a recorder.

More specifically, native startup slice `0xFE0CDEB4` calls the property subsystem initializer at `0xFE448AAC` with channel argument 0; it writes zero to `0x5028 + 40`. The probe stops before that subsystem's OS object creation. A separately entered actual copy-caller slice at `0xFE4466EE` then reads this **native-written channel value** and reaches the public wrapper with `[0, destination, source, count]`. Static surrounding source diagnostics identify this as the property-save path. A second reviewed caller is at `0xFE44685E`; no complete property save or camera flash write is executed.

This is concrete Canon use of channel 0, so the 7D2 donor's channel-0 choice cannot establish exclusive ownership on 750D. The pinned donor itself comments that safety in all contexts is untested. Channel lock ownership, cross-channel shared-status serialization, allowed execution context and signal freshness remain integration requirements. Channels 2 and 3 must not be declared free merely because the reviewed startup requests 0 and 1.

## Reproduction and limits

```sh
python scripts/probe_750d_copy_sync.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-copy-sync.json) records **29 passing scenarios**: two take/give sequences, an empty wait, a saturated give, four invalid handles, one context gate, four IRQ-to-signal sequences, four IRQ-to-unlock/callback paths, five wrapper scenarios, four channel-initialization prefixes, two controller-initialization paths and one property initialization/caller pair.

The exact private main-record size/SHA-256 are checked before execution. Unicorn 2.1.4 uses Cortex-A9 for the compatible ARM/Thumb subset, not full Cortex-R4 or camera emulation. Firmware/import/sentinel pages are read/execute; synthetic globals, object/task/descriptor state, stacks and register RAM are read/write without execute permission. Code/write guards restrict each stage to reviewed ranges and supplied state. Stages are bounded to 256 instructions / 0.5 seconds, initialization prefixes to 512, longer wrapper segments to 2,048.

No native calls are stubbed. Wait-queue/scheduler code, blocked-task wakeup, physical IRQ enable/delivery, controller start, actual DMA, cache coherence, copied pixels, throughput and source-frame lifetime remain unverified. Camera bindings remain disabled. The next practical work is to establish a permitted caller context and channel-use contract, then connect this copy route to a genuinely completed sensor frame with a valid lifetime.
