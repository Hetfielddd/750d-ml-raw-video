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

Heap free and the receive epilogue remain unexecuted. The full consumer callback does not return in this probe: it stops before the first unexecuted component update, with a separately entered RAW tail checked afterwards. Static loop review shows the next receive follows callback return; it does not establish that all downstream use ends there.

## Full, empty and wraparound cases

An independent native transcript inserts A and B, rejects C from a full queue, removes A, inserts C after ring wraparound, then removes B and C. Successful calls return zero. The full insertion and receive-now on an empty queue return **13**; both preserve the queue and an empty receive leaves the output unchanged. Every returned call restores the IRQ mask.

A second full-queue fixture executes the real request wrapper through failed insertion. It reaches heap-free veneer `0xFE74F964` with the newly constructed envelope pointer and enqueue error 13 retained in R5. Existing queued items are unchanged. Cleanup preparation executes; actual free and the rejected wrapper's return are not executed. A future adapter must propagate enqueue failure and must not interpret attempted submission as accepted consumption.

Task receive's zero timeout argument differs from receive-now's pointer to a zero-valued timeout pair. With an empty queue, task receive follows a blocking branch. The probe stops at `0xFE74C23E` **before waiter bookkeeping and scheduler entry**. At this boundary, IRQs are still masked because the call has not returned. No blocked wakeup, context switch or deadlock behavior is modeled.

## Remaining integration contracts

Queue acceptance, parameter consumption and completed sensor pixels are separate events. These tests establish pointer forwarding and native FIFO behavior in supplied RAM, and show why envelope release alone cannot authorize parameter reuse. They do not establish live cross-core visibility, a consumption acknowledgment, safe RAW-buffer reuse, cache coherence, image packing or DMA completion.

Reproduce with `scripts/probe_750d_raw_param_lifetime.py` and a privately supplied identified main record. The [evidence](evidence/750d-raw-param-lifetime.json) contains eleven passing cases. Native code/write/read guards and per-stage execution limits apply; no native calls are stubbed. Firmware bytes are not distributed. Camera bindings remain disabled; the camera and SD card are untouched.
