# Experimental frame queue

`experimental/raw14_queue.{h,c}` adds the producer/writer ownership layer on top of the experimental synchronous RAW14 copy component. It is not yet integrated into Magic Lantern and does not access Canon hardware or write a file.

## Buffer lifecycle

```text
FREE -> FILLING -> READY -> WRITING -> FREE
           |                  |
       copy fails         writer aborts
           |                  |
          FREE              READY
```

The caller supplies two to eight distinct, non-overlapping, validated output buffers. No heap allocation occurs. All buffers use the same full-width packed-14-bit geometry and an even height.

`raw14_queue_push` reserves a free slot, synchronously copies rows through the injected backend, and publishes metadata only after success. During copying, nested queue operations return BUSY. A failed or rejected copy returns the slot to FREE without publishing a frame, even if the backend modified part of its contents.

If no slot is free, the new frame is rejected with FULL. Existing READY and WRITING slots are never evicted. Saturating counters distinguish accepted frames, full-queue drops, and rejected copy attempts. The caller must decide whether to stop recording or report dropped frames; this component does not hide the loss.

`raw14_queue_take` gives a single writer the oldest READY frame. Ordering uses an internal admission ticket, not physical slot position, so reusing the first buffer does not reorder older frames in other buffers. Another take returns BUSY until the writer finishes or explicitly aborts.

The writer receives the frame descriptor, byte count, caller-supplied frame ID/timestamp, and a lease. IDs must increase across successful submissions in a session; timestamp values are preserved without inferring a clock model.

After confirmed complete I/O, `raw14_queue_release_written` frees the slot. After a write error, `raw14_queue_abort_write` returns the frame to READY in its original order. This permits explicit retry, but does not roll back partial filesystem writes: the future writer must repair/seek its output or stop the recording.

## Stale-lease protection

A lease includes session ID, slot index, and a unique 64-bit writer token. Each take gets a new token, including after an abort/retry. A duplicate release, release after buffer reuse, or old token from an aborted write cannot free the current writer's slot. Counters stop before token wraparound rather than reusing an identity.

Initialize only a new or quiescent queue. The caller must choose a different nonzero session ID for every reinitialization; otherwise an old lease could become indistinguishable from a new one. End all outstanding buffer use before reinitializing. This queue provides no force-reset operation that frees a buffer under an active writer.

## Execution and concurrency contract

All queue calls must be externally serialized. The busy flags detect nested calls; they are not interrupt-safe atomics or a task lock. Direct mutation of the queue/slot structures while it is in use violates the API contract. Buffer capacities and cache aliases must come from verified allocation metadata.

This queue supports the current synchronous copy contract. Async DMA would require a different completion/ownership protocol; returning from an asynchronous launch is not sufficient to publish READY.

## Tests on ARM

Run the same command as the [copy component](raw14-copy-core.md). The runner now builds and executes two separate ARM ELF suites: copy and queue.

The queue suite covers FIFO order through slot reuse, full-queue drops without overwriting, a slow writer, metadata, partial-copy failure/recovery, nested producer/writer calls, invalid initialization, stale/duplicate/retried/session leases, token exhaustion, the 32-to-64-bit counter boundary, and rejection propagation. A 1,000-step producer/writer schedule is compared against an independent reference FIFO, including frame bytes and a final drain.

These are actual compiled ARM C tests using synthetic buffers. Sensor capture, DMA, multicore/interrupt timing, cache coherence, MLV output, and SD-card performance remain untested.
