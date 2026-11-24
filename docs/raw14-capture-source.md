# Completed-frame source integration

`experimental/raw14_capture.{h,c}` connects an explicitly leased completed-frame source to the RAW14 queue. It does not read Canon registers, redirect DMA, call firmware, or establish that an arbitrary memory address contains a finished image. This version accepts only `RAW14_SOURCE_PC_SYNTHETIC`; selecting `RAW14_SOURCE_CANON_750D` is rejected as UNVERIFIED before any source operation is invoked. The kind is a caller declaration and API policy, not hardware detection or a security boundary.

## Evidence from the closest working donor

Reference: Magic Lantern `142472e95054d73640f50789ac0fd66325499d82`. These are upstream source observations, not hardware measurements by this project.

- `src/raw.c:2470` waits for two Live View frames before enabling the non-SLURP stream with `lv_save_raw(1)`. `raw_lv_update` subsequently attempts geometry updates over settling frames. The request/release functions at lines 2597/2617 use a semaphore and a reference count. Their comment requires release even when Live View races with the request. Requesting RAW is not an ISR operation or proof that a frame is immediately ready.
- `src/raw.c:705` obtains the non-SLURP buffer address through the shadow reader. `raw_lv_get_resolution` at line 714 derives pitch from the low half of `yb_xb`, width from pitch times 8/14, and height from the larger of the low `yn_xn` or high `yb_xb` counts, plus one. These are source formulas, not confirmed 750D registers or geometry. Our input contract requires exact full-width RAW14 packing instead of silently rounding incompatible pitch.
- `src/state-object.c` invokes `vsync_func` after the original `StateTransition`. With `CONFIG_EVF_STATE_SYNC`, the condition uses the saved old state 5, input 5, and `EVF_STATE`. `vsync_func` dispatches `CBR_VSYNC`. The callback's name and comments do not make arbitrary blocking work safe in an interrupt context.
- `modules/raw_video/mlv_lite/mlv_lite.c:2937` checks recording state and `raw_lv_settings_still_valid`, redirects upcoming capture to `fullsize_buffers[fullsize_buffer_pos % 2]`, and sends the opposite buffer index to `process_frame`. That function skips startup frames and sends a job to the separate copy/compression task. Thus the currently programmed DMA destination and the completed buffer passed for processing are different roles. A pointer read alone does not establish frame ownership or lifetime.
- The 7D2 fast-copy wrapper still has an upstream comment that channel 0 is untested in all contexts. Its address, channel, dual-buffer timing, and cache behavior cannot be transferred to the 750D by processor family alone.

The 750D port still lacks the verified RAW channel and copy primitive; its `shamem_read` returns zero and it does not enable EVF state synchronization. The existing EVF pointer is upstream evidence, not project hardware validation. Nothing here enables those placeholders or writes a donor address to the 750D.

## Source contract

The caller initializes a fresh queue session, copy engine, fixed full-source geometry, and even vertical crop offset. Output is full-width RAW14 with even output height. Source height may be odd: only the copied Bayer-aligned rows need even parity. Initialization checks geometry arithmetic before any source calls.

`begin` owns one source request. `acquire` is nonblocking and returns a complete stable frame, no frame, or an error. A successful view includes a nonzero lease cookie, capacity, width, height, pitch, depth, monotonically increasing frame ID, and nondecreasing microsecond timestamp. A no-frame/error return must leave no outstanding lease. Completion status and lifetime are the source provider's responsibility; the capture layer cannot infer DMA completion from these fields.

`poll` validates the view against configured geometry, synchronously copies the selected full-width rows through the existing engine, then releases the source lease. Every successful acquisition is released even on malformed metadata, copy failure, or a full output queue. Only a successful copy is published to the queue. Queue overflow drops the newly acquired frame, releases it, and permits subsequent polling. IDs of dropped source frames are remembered, so replaying a dropped ID is rejected too.

Other errors stop new capture. If release fails, the layer retains the same cookie for cleanup retry. The provider must define a failed release as retaining that lease; it must not secretly release it and return failure. The same rule applies to a failed `end` and its request. A successful copied frame can already be READY when releasing its source fails; an error result must not be interpreted as proving no frame was queued.

`stop` first retries any outstanding release and then ends its own source request. It never shuts down another owner's reference or discards queued output. Failed cleanup remains FAILED and retryable. To finish a recording, stop capture, drain the remaining output queue, then finalize the writer. Restart after seen frames requires a fresh queue session and capture initialization; source IDs cannot restart in the same recording session.

All calls, queue/writer access, and callbacks must be externally serialized. Callbacks must not reinitialize the queue, change the configuration, or recursively mutate ownership. The busy flag rejects reentrant operations; it is not a lock or atomic synchronization. This implementation is not ISR-safe and does not implement a camera event mailbox, scheduling deadlines, or protection against a source that violates its lease.

## PC verification

```sh
python scripts/test_raw14_arm.py --toolchain /path/to/arm-toolchain/bin --upstream-source /path/to/magiclantern
python scripts/test_raw14_disk.py --toolchain /path/to/arm-toolchain/bin --build-dir .tools/raw14-tests
```

Five C suites run under ARM emulation: copy, queue, MLV, FIO, capture. The capture suite covers source gating, bounds/geometry, no-frame polling, odd full-source height, stable borrowing through copy, immediate overwrite on release, FIFO ownership, full-queue drops, replay of a dropped ID, format/capacity changes, regressing timestamps, copy/acquisition/release errors, retryable cleanup, partially failed startup, queue-session replacement, and reentrancy.

The disk workload now acquires all 48 synthetic submissions through this layer with a fixed two-row vertical crop. The source overwrites its borrowed buffer immediately on every successful release, including drops. All 36 recorded payloads are independently checked after disk readback. Both direct and FIO contract backends still run normal and partial-write scenarios (four files total).

This proves the software ownership path, not 750D sensor capture. To implement a real provider we still need verified 750D stream enablement, shadow-reader/channel, completion event and scheduling, full-frame capacity/packing, DMA redirection rules, source buffer lifetime, copy/cache constraints, and clean shutdown behavior. Those remain explicit gaps rather than guessed addresses.
