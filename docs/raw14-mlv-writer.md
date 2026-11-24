# Experimental MLV writer and end-to-end test

The C writer in `experimental/raw14_mlv.{h,c}` connects the copy/queue components to an abstract synchronous file backend. It writes a minimal single-file uncompressed RAW14 MLV stream. It is not yet connected to Canon's filesystem, DMA, or sensor.

## Format and metadata

The writer explicitly serializes little-endian MLVI (52 bytes), RAWI (180 bytes with 160-byte raw_info), and VIDF (32-byte header plus alignment and frame payload). No host pointer size or native struct packing is used for output. The raw_info buffer pointer is cleared.

The caller supplies verified geometry, GUID, frame rate, recording-start timestamp, and raw_info calibration. The output uses no invented camera identity, exposure, lens, or white-balance blocks. The test uses artificial calibration and data; it is not captured 750D footage.

Frame IDs are normalized to the first successfully written frame while preserving gaps. Gaps and queue overflow set MLVI flag 2. Timestamps are relative to the supplied recording start. Vertical source offsets are carried through the queue and recorded in VIDF crop/pan fields. Normal finalization updates the frame count and refuses to finish while queued or writer-owned frames remain.

## File backend and failure handling

Supply synchronous write, absolute seek, truncate, and flush callbacks for an exclusive new/empty file. Initialize only a new or quiescent writer, and externally serialize all use. A positive short write is completed with additional writes. Zero, SIZE_MAX, or an impossible byte count is treated as failure.

A buffer stays WRITING until its full VIDF header, alignment bytes, and payload have been consumed by the backend. Only then is its lease released. This does not imply durable media storage: callbacks must consume bytes before returning, while final flush durability depends on the eventual backend.

On a failed frame write, the writer attempts truncation and seek back to the last complete block, returns the frame to READY, and stops further append operations. There is no automatic in-place retry. If rollback succeeds, finalization can close the valid prefix with MLVI flag 8 (stopped due to error) and the count of complete frames. Successful *finalization* of that prefix does not mean recording itself succeeded. Failed rollback prevents successful finalization. A failed initialization attempts to truncate the new file to zero.

The queue's abort operation alone cannot repair a partial file; this layer supplies the necessary rollback. Actual Canon FIO behavior, size limits, error codes, and truncation facilities need a dedicated adapter later.

## Reproducible verification

```sh
python scripts/test_raw14_arm.py --toolchain /path/to/arm-toolchain/bin --upstream-source /path/to/magiclantern
python scripts/inspect_raw14_mlv.py .tools/raw14-tests/synthetic-raw14.MLV
python -m unittest discover -s scripts -p 'test_*.py' -v
```

The optional upstream check compiles 19 assertions using the actual raw_info declaration and MLV header from the pinned upstream source. It checks wire sizes and offsets against our serializer. Generated declaration copies are test intermediates in the build directory and retain their upstream origin notice.

Three C suites are compiled for Cortex-R4/Thumb and executed with Unicorn's Cortex-R5 ARMv7-R model: copy, queue, and MLV. The MLV suite uses an in-memory file backend with seven-byte short writes and injected write/seek/truncate/flush failures. Tests check writer reentrancy, pending queues, release timing, metadata validation, partial-payload rollback, failed rollback, initialization failure, and recovery finalization.

After the ARM test returns, the runner reads the exported synthetic clip from emulated RAM. An independent Python parser validates it, compares both frame payload hashes against known input patterns, checks frame numbers 0 and 2, timestamps 0 and 83,333 microseconds, crop offsets 2 and 0, then saves `synthetic-raw14.MLV` in the build directory. The clip is a tiny 8x4 two-frame data fixture, not a meaningful camera image.

Five Python parser tests independently cover padded frames, truncated payloads, wrong finalized counts, oversized padding, and mismatched RAW metadata. Together with the earlier ROM tests, nine Python tests pass.

This proves the software path **synthetic frame -> ARM copy core -> queue -> C MLV serialization -> disk file -> independent structural/payload check**. It does not prove compatibility with MLV App or other editors: they may need additional metadata. It also does not validate real sensor packing, camera FIO, DMA, cache coherence, concurrent tasks/interrupts, sustained recording speed, crash/power-loss recovery, audio, compression, or file splitting.

Wire-format sources: Magic Lantern `modules/raw_video/mlv_rec/mlv.h` and `src/raw.h` at commit `142472e95054d73640f50789ac0fd66325499d82`.
