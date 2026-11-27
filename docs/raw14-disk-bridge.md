# ARM recorder with real PC filesystem operations

`scripts/test_raw14_disk.py` executes the actual copy, queue, and MLV writer C code under ARM emulation. Four deliberately failing stub functions in `experimental/raw14_disk_demo.c` are intercepted by the test harness and routed to an exclusive PC file. Only write, seek, truncate, and flush cross into Python; Python does not generate the MLV headers or manage the recording queue.

This is a test bridge, not a native filesystem adapter, Canon emulator, sensor simulator, or camera installation package. Files are synthetic RAW14 data with artificial calibration. They are not intended to produce a meaningful image in an editor.

## Run

Use the Arm GNU toolchain and Unicorn environment described in [the copy core documentation](raw14-copy-core.md):

```sh
python scripts/test_raw14_disk.py --toolchain /path/to/arm-toolchain/bin --build-dir .tools/raw14-tests
```

Each run creates a new `disk-run-*` directory under the build directory and opens output files in exclusive-create mode. Existing files are not overwritten. All paths and IO call counts appear in the JSON report. No camera or SD discovery APIs are used. Choose a build directory on the PC.

The bridge uses the AAPCS32 argument convention: a 64-bit seek/truncate argument following the context pointer occupies R2/R3. It returns control to the ARM caller after performing the host operation. The file is unbuffered; flush also calls the host's `fsync`. This verifies successful host API completion, not resilience to actual power loss or physical disk failure.

## Verified scenarios

The synthetic recorder obtains frames through the completed-frame source layer and uses a fixed two-row crop. The original scenario overwrites each source buffer on release. The delayed-completion scenario reuses both source slots before the first queue entry is written. In both cases, payload verification checks that the queue owns its copy. [Completed-frame source](raw14-capture-source.md).

The harness runs a direct backend and an ML-style FIO contract adapter, producing six files per run. The FIO variant makes no truncate calls. Successful outputs finalize, while a partial tail remains explicitly unfinalized. The direct backend can truncate its PC file to the last complete frame. [FIO contract adapter](raw14-fio-adapter.md).

- Normal: 48 synthetic 64x32 frame submissions into three slots, drained after every four submissions. The fourth submission in each group is rejected because the queue is full. The output contains 36 frames, preserves source frame-number gaps, and sets the dropped-frame flag. File size: 130,408 bytes.
- Partial write: after one complete frame, the bridge accepts the next frame header and three payload bytes, then returns zero. The C writer rolls the real file back to the complete first frame and finalizes the 3,848-byte prefix with error flag 8. The failed frame remains READY rather than being falsely released as written.
- Delayed completion uses the two-buffer PC source. It exercises late notifications after switching buffers and after reusing the same address, a short transfer, a duplicate, queue overflow and completion after stopping. Only source IDs 2, 5 and 6 appear in the finalized output. The writer numbers them 0, 3 and 4 relative to the first recorded ID. Each backend produces an 11,080-byte file with verified timestamps, crop offsets and payload hashes. The PC fixture supplies transfer IDs and byte counts.

Every write is limited to 511 bytes to exercise short-write completion. After closing and reopening each file, an independent parser checks block structure, finalized count, flags, timestamps, crop offsets, and every frame payload hash against a separate deterministic source model. The normal run does not model simultaneous producer/writer tasks or measure camera throughput.

## What the pinned Magic Lantern implementation actually provides

Source revision: `142472e95054d73640f50789ac0fd66325499d82`.

- `src/fio-ml.h` declares `FIO_WriteFile` with a signed `int` result. A future adapter must map negative results to failure before converting to `size_t`, and limit individual requests to the supported signed count range.
- `FIO_SeekSkipFile` takes a signed 64-bit offset and returns the resulting absolute position. Its result is not a zero-success status. The header warns that seeking past EOF does not work on all cameras.
- The same header explains that `FILE *` is historically used for opaque DryOS handles; assumptions about zero/null differ between raw DryOS functions and ML wrappers. Handle creation must follow the actual wrapper's contract.
- `src/fio-ml.c`, `FIO_WriteFile`, synchronizes caches for cacheable buffers and passes an uncacheable alias to `_FIO_WriteFile`. Bypassing this wrapper would omit behavior the upstream project explicitly needs for DMA-backed IO.
- The comment above that wrapper says written data may require closing and reopening before readback, even with DryOS `FIO_Flush`. The 750D stub table lists `FIO_Flush`, but this alone does not establish its signature, durability, or a portable wrapper contract.
- `modules/raw_video/mlv_rec/mlv_rec.c` uses writer jobs, detects short/failed writes, tries to recover space by releasing dummy files, then stops recording on the error path. At writer exit it seeks to the beginning, rewrites the frame count, and closes the handle. This is a reference for a future adapter, not proof of the 750D's behavior.

No truncate operation is exposed in the reviewed public `fio-ml.h` interface. Our current rollback contract therefore cannot be mapped to Canon FIO by simply renaming functions. A future camera adapter must either establish a real truncation facility or use a separately designed and tested recovery strategy. A no-op truncate must never report success when a partial tail remains. The existing writer already refuses successful finalization after failed rollback.

The 750D addresses in upstream `platform/750D.110/stubs.S` remain upstream source evidence only; this project has not independently verified them on hardware. No camera integration is enabled by this test.
