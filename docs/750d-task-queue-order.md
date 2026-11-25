# Native task queue execution and RAW command ordering

The [RAW parameter probe](750d-raw-param-lifetime.md) now executes the actual peer queue fast paths. This removes the previous host-supplied queue-delivery step. Heap allocation, envelope freeing, mailbox delivery and task scheduling remain explicit unexecuted boundaries. No sensor frame is captured.

## Supplied kernel state

The private, identified 750D 1.1.0 main record supplies application/driver code and a peer low-kernel page mapped from source `0xFE744D60` to runtime zero. This peer mapping must not be mixed with the primary core's different low-kernel image. Compatible scalar ARM/Thumb instructions execute under Unicorn Cortex-A9; this is not a camera model.

The fixture supplies a generation-7, index-1 queue handle `0x000E0002`. Native lookup at `0xFE74BED6` resolves the handle through table pointer `0x01AC05C4` and capacity `0x01AC0120`. The supplied queue is a 44-byte object with these reviewed fields:

- 16-bit receiver/sender waiter counts at offsets 12/14, both zero.
- 16-bit capacity/occupancy at 16/18, initially 2/0.
- Ring pointer at 20; 16-bit tail/head at 24/26.
- Generation at 38 and normal FIFO flags at 40.

The capacity of two is an experiment input, not the camera's measured queue capacity. Context gates and other queue globals use supplied zero state. No task control block or waiting task is fabricated.

## Executed insertion and receive

The native request wrapper `0xFE74CE9E` checks its object and requests a 16-byte allocation, stopping before allocator veneer `0xFE74F95C`. A separately entered continuation at `0xFE74CEC4` constructs the envelope in supplied scratch memory, calls actual send-now `0xFE74FF10`, and returns through its original saved stack. This is not a successful allocator return stub.

Send-now reaches lower insertion wrapper `0xFE749F1A`, lookup and FIFO code. The actual IRQ helper veneer `0xFE74F9B4` enters peer Thumb helper `0x231`, saves CPSR and disables IRQs. Native wrapper exit restores the incoming IRQ mask. Its no-waiter queue path inserts the envelope pointer and increments occupancy.

Actual task receive `0xFE74CD2C` uses queue-receive `0xFE74FDBC` and lower wrapper `0xFE749ED0`. With an item available, native code removes it, decrements occupancy, restores IRQ state, and extracts the envelope's four words to the stack outputs used by the task loop. Execution stops before heap-free veneer `0xFE74F964` with the envelope pointer as its argument.

The experiment makes the old envelope page inaccessible and separately enters task-loop continuation `0xFE74CD9C`. The loop loads its callback and the four native-extracted stack words, then reaches the actual RAW configuration consumer prefix. Rewriting the parameter block during this supplied inter-stage interval changes the later pending address; preparing another block preserves the original address. The envelope lifetime therefore does not define the parameter-storage lifetime.

Heap free and the receive epilogue remain unexecuted. Full driver configuration stops before its first component update, with a separately entered RAW tail checked afterwards. A separate epilogue experiment now checks the return chain described below. It does not establish that all downstream use ends there.

## Separate return-chain experiment

At the first component boundary, the probe saves the emulator CPU state and retains the original stack. After the separate RAW-tail/address checks, it restores that CPU state and enters the actual driver epilogue at runtime `0x80009B94` (source `0xFE750F74`). This epilogue executes its own zero-result instruction and saved-register return. The omitted component body remains unexecuted; there is no component-call return stub or claim that configuration completed.

The native event-4 handler continuation at source `0xFE80FDFE` loads the state-object association from context offset 4, replacing the driver's result. The native dispatcher returns this nonzero association. Worker source `0xFE8063A0` takes its nonzero branch, stores the association back at context offset 4 and returns. The actual task loop then makes its next receive request. With an empty queue it reaches the pre-scheduler wait boundary; with a second command it removes that command and extracts its envelope.

In the three original lifetime scenarios, both parameter pages and the old envelope are inaccessible during this return-chain experiment. No parameter access or return transport occurs in the reviewed continuation. This narrows the relevant local read interval, but does not validate the omitted component bodies or an acknowledgment to the primary core. The worker's zero-result fallback is associated with an error-format string; it must not be assumed to acknowledge configuration either.

## Two queued configurations still share one pending RAW address

A new scenario prepares A and B in separate, stable parameter blocks, constructs two native envelopes, and accepts both into the supplied FIFO. The first native receive/consumer prefix and separate RAW setter tail establish pending A. The separate return-chain experiment then removes the second command through the actual loop/receive code. Its consumer prefix and separate RAW tail replace pending A with B.

Only then does the probe enter RAW start preparation. It programs B's normalized DMA address `0x1E000000` and stops before channel-start veneer `0xFE86F878`. The pending word still contains B at this boundary: its later clear is after the unexecuted start and other calls, at source `0xFE83963C`.

This supplied ordering checks the single pending-address slot, not a live dropped-frame event. FIFO acceptance preserves command order; it does not allocate a sensor capture for every configuration. There is no address queue inside the reviewed RAW pending setter. A future frame-buffer rotation protocol must synchronize configuration with actual capture boundaries and copying, rather than enqueue arbitrary configurations and count them as frames.

The [7D2 reference](similar-camera-raw.md) redirects the upcoming capture and processes the opposite buffer at its verified VSYNC hook. At the pinned revision, `mlv_lite.c` lines 2953–2960 implement this alternation. The 750D normal asynchronous configuration route has not been shown to provide the same timing contract; these queue tests do not make it a replacement for that hook.

## Full, empty and wraparound cases

An independent native transcript inserts A and B, rejects C from a full queue, removes A, inserts C after ring wraparound, then removes B and C. Successful calls return zero. The full insertion and receive-now on an empty queue return **13**; both preserve the queue and an empty receive leaves the output unchanged. Every returned call restores the IRQ mask.

A second full-queue fixture executes the real request wrapper through failed insertion. It reaches heap-free veneer `0xFE74F964` with the newly constructed envelope pointer and enqueue error 13 retained in R5. Existing queued items are unchanged. Cleanup preparation executes; actual free and the rejected wrapper's return are not executed. A future adapter must propagate enqueue failure and must not interpret attempted submission as accepted consumption.

Task receive's zero timeout argument differs from receive-now's pointer to a zero-valued timeout pair. With an empty queue, task receive follows a blocking branch. The probe stops at `0xFE74C23E` **before waiter bookkeeping and scheduler entry**. At this boundary, IRQs are still masked because the call has not returned. No blocked wakeup, context switch or deadlock behavior is modeled.

## Remaining integration contracts

Queue acceptance, parameter consumption and completed sensor pixels are separate events. These tests establish pointer forwarding and native FIFO behavior in supplied RAM, and show why envelope release alone cannot authorize parameter reuse. They do not establish live cross-core visibility, a consumption acknowledgment, safe RAW-buffer reuse, cache coherence, image packing or DMA completion.

Reproduce with `scripts/probe_750d_raw_param_lifetime.py` and a privately supplied identified main record. The [evidence](evidence/750d-raw-param-lifetime.json) contains twelve passing cases. Native code/write/read guards and per-stage execution limits apply; no native calls are stubbed. Firmware bytes are not distributed. Camera bindings remain disabled; the camera and SD card are untouched.
