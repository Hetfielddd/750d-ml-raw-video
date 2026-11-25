# Native RAW parameter routing and parameter-block lifetime

An alternative to the [snapshot/override helper](750d-raw-override-contract.md) is the normal RAW pending-address path. Twelve PC checks trace native service registration, parameter-command routing, actual queue insertion/removal, envelope extraction and separately entered consumer/epilogue code. They establish a **parameter-block lifetime requirement**, not a completed-image lease or working cross-core transport. The [queue execution contract](750d-task-queue-order.md) details the supplied kernel objects, single pending-address slot and remaining cuts.

## A registered configuration route, rather than an unreferenced override entry

The reviewed application constructor at `0xFE8063D6` creates the Live View capture state object through `0xFE80FD0C`. Its continuation records service `0x20002`, installs callback pointer `0x01B8401D` (source `0xFE806384`) and registers it through `0xFE86FC06`. Allocation and full constructor execution are not part of this probe.

The experiment executes the real service-registration function with the callback taken from literal `0xFE8064AC`, a supplied context and service `0x20002`. The service table is selected through pointer array `0x01ACCBB8`; function and context entries use offsets `service_index * 4` and `64 + service_index * 4` respectively. A separate actual Postman registration at `0xFE74EE70` installs dispatcher `0x01BED821` (source `0xFE86FB88`) and the native-written service table as its argument.

The receive-channel mapping is supplied: channel 4 maps to logical row 2. Native Postman registration and lookup agree on callback slot `0x01ACDD8C + logical_row * 88 + destination * 8`. This is a fixture for checked table arithmetic, not evidence of active mailbox configuration on the owner's camera.

## The pointer stays a pointer

The native mode-3 configuration slice `0xFE28D9D6`–`0xFE28DA36` builds channel-1 fields and writes a supplied candidate to driver-block offset 200. The normal operation-4 wrapper `0xFE3807A0` prepares `[4, 2, 0x204, driver_block]` for the sender. Its separately entered packing slice produces header `0x02000204` and retains that original block pointer as payload.

On the receiving side, actual header-validation and post-payload-load slices at `0xFE74EA86` and `0xFE74EA9C` select the native-registered Postman callback. The dispatcher strips destination bits, extracts service index 2 and operation 4, and invokes the real service callback. Its actual operation map at runtime `0x01CF10A0` maps operations 0–5 to events 0–5. Request helper `0xFE86FB30` associates the supplied subtask with its context and forwards the unchanged driver pointer to the task-queue wrapper.

Mailbox stores and FIFO reads are **not** executed. Native sender register values are explicitly supplied at the reviewed receive slices after those unexecuted loads. These are declared experiment cuts, not a FIFO model or proof of message delivery.

## Queue envelope construction

The actual queue wrapper at source `0xFE74CE9E` (runtime `0x80005ABE`) checks the supplied task-queue object's signature and reaches allocator veneer `0xFE74F95C` requesting **16 bytes**. The allocator is not executed.

A separately entered post-allocation slice at `0xFE74CEC4`, with supplied scratch storage and the wrapper's native-produced saved registers, constructs:

```text
word 0: subtask pointer
word 1: event number
word 2: original parameter-block pointer
word 3: additional argument (zero in these fixtures)
```

The post-allocation slice now continues through underlying enqueue helper `0xFE74FF10` and the wrapper's successful return, restoring its original entry stack. The queue is a supplied two-slot kernel object with no waiting tasks. Native queue lookup, FIFO insertion and IRQ save/restore execute. A read guard verifies that the queue stages do not read the parameter-block contents. No allocator return is fabricated; allocation remains an explicit cut.

The task loop uses receive wrapper `0xFE74CD2C`, which now executes through real queue removal and extraction into the loop's four stack outputs. It stops before heap-free veneer `0xFE74F964`. The envelope page is then made inaccessible as a lifetime fixture. The allocator, heap free and receive epilogue are not executed. No deep copy of the parameter block is established by these queue stages.

## Actual worker and state dispatch

A separately entered task-loop continuation at `0xFE74CD9C`, after the unexecuted heap free and receive epilogue, reads the native-extracted stack outputs and invokes its registered callback. Native trampoline source `0xFE86FABA` loads the worker and the context association written by the real request helper. It invokes actual worker source `0xFE8063A0`, which enters state-transition import `0xFE86F728`, runtime dispatcher `0x800057FC`, and the actual capture-path transition table at `0x01CF2190`. The worker is reached with its old queue envelope inaccessible.

With supplied state zero, event 4 selects source `0xFE80FDF4`, reaches real driver configuration entry `0xFE750F00` / runtime `0x80009B20`, and stops before its first component update at runtime `0x8000A8BC`. The driver receives the **same original parameter-block pointer**.

A separately entered RAW tail at `0xFE750F2C` then consumes that native-forwarded pointer and calls the actual RAW pending setter through `0xFE74F130`. Earlier and later component-configuration calls are not executed or replaced with successful returns. The RAW entry subsequently programs the native pending address into artificial destination-register RAM and stops before channel-start call `0xFE86F878`.

The tested producer fields and supplied channel geometry remain unchanged when only the address marker changes. This does not prove that the entire operation-4 configuration is side-effect-free: its other component calls remain outside this experiment.

## Memory lifetime scenarios

Three scenarios retain the same emulator RAM across the reviewed stages:

- **Unchanged block:** native production of A, routing, queue insertion/removal and envelope extraction followed by consumer execution produces pending A and destination `0x1C62C000`.
- **Same block republished:** after native queue removal/extraction and making the envelope inaccessible, the actual producer rewrites the same parameter block with B. The extracted pointer still addresses the original block, but later consumer execution produces pending B and destination `0x1E000000`.
- **Separate block prepared:** preparing B in another block leaves the original A block intact, and the consumer of the original envelope still produces A.

The second case is a supplied scheduling sequence, **not a demonstrated camera race**. Cross-core visibility and real task timing are untested. It shows why a future adapter must retain stable parameter storage until actual consumption, or establish a stronger verified ordering contract; returning from the sender is not independent evidence that the peer has finished reading it. A parameter-block lifetime and the lifetime of sensor-image pixels are different contracts.

Envelope release is also too early to reuse parameter storage: the native receive wrapper extracts pointers and reaches envelope free before the task loop calls the consumer. A separately entered actual driver epilogue, using CPU/stack state saved at the earlier component boundary, now executes the worker return and reaches the next native receive. Both parameter pages are inaccessible in these three epilogue fixtures. This checks the return-chain read behavior and lack of return transport, not execution of the omitted component bodies or a validated reclamation acknowledgment.

A two-command scenario accepts separate A/B parameter blocks into the native FIFO, consumes their RAW setters in order, and then enters one RAW start preparation. The single pending-address slot is replaced A then B, so only B's destination is prepared. Pending B remains stored at the channel-start boundary; clearing happens later in unexecuted code. Queue acceptance is not evidence of one capture per command. See [the ordering analysis](750d-task-queue-order.md).

Three control cases check native service removal (no queue request) and operation 2/5 routing through their actual task handlers. Operation 2 stops before its preparation import; operation 5 stops before its driver import. Neither control case starts hardware.

Two additional native primary-return dispatcher checks show that operations 4 and 5 select existing `BX LR` leaf `0xFE3807B8`. They do **not** select the semaphore-signaling operation-3 return handler `0xFE3807C8`. This reviewed dispatch therefore provides no per-configuration semaphore acknowledgment to release a parameter block. Other live synchronization mechanisms have not been excluded.

## Reproduction and limits

```sh
python scripts/probe_750d_raw_param_lifetime.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-raw-param-lifetime.json) records twelve passing cases: three memory-lifetime/epilogue scenarios, three routing/removal controls, two primary-return leaves, FIFO/full/empty/wraparound checks, rejected-request cleanup preparation, two configurations before one start preparation and the empty blocking-receive boundary. The identified main-record size/SHA-256 are checked before importing Unicorn 2.1.4. Cortex-A9 executes a compatible scalar subset, not a full Cortex-R4 camera model.

Firmware and scoped application/driver/table pages are read/execute. Supplied objects, parameter blocks, envelope, stacks, shadow and register RAM are read/write without execute permission. Code/write guards and a 256-instruction / 0.5-second limit apply to each stage. Successful native helper returns must restore their stacks. The fixture's parameter-block extent is not asserted to be the full camera protocol's structure size.

No native calls are stubbed. Allocation, heap free, actual mailbox delivery, scheduler-mediated queue wakeup, unexecuted component updates, channel start, real DMA, cache coherence, image packing and completed-frame ownership remain unverified. Queue fast paths execute only on supplied RAM objects. Camera bindings remain disabled. The next integration requirements are a verified consumption/ordering boundary for parameter storage and an independent completion/lifetime boundary for image data.
