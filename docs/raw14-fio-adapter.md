# Experimental FIO contract adapter

`experimental/raw14_fio.{h,c}` adapts the signed-write and absolute-position seek contracts declared in Magic Lantern's `src/fio-ml.h` to the experimental MLV writer. This is a portable C adapter with injected operations, not a binding to camera firmware addresses. No camera code is enabled or installed.

Reference source: Magic Lantern commit `142472e95054d73640f50789ac0fd66325499d82`. See also [upstream FIO findings](raw14-disk-bridge.md).

## Interface and ownership

The caller supplies an exclusively owned, already opened new/empty file, typed write/seek wrappers, and a separately verified zero-success flush operation. Initialization queries EOF and refuses a nonempty file. It does not create, close, or delete files. The caller must serialize all access and keep the adapter, queue, buffers, and handle alive.

The adapter does not interpret the opaque handle or reject zero. Actual ML file creation must follow the specific wrapper's success/failure contract before initialization. Use typed wrapper functions when bridging ML's `FILE *` API to `void *`; casting incompatible function pointers is not supported.

The future write wrapper must use ML's `FIO_WriteFile`, preserving its cache synchronization and uncacheable address handling. Do not bypass it with `_FIO_WriteFile`. A 750D `FIO_Flush` stub exists in upstream, but its signature and durability have not been established here; the adapter deliberately requires the caller to supply a verified flush implementation rather than guessing one.

## Conversion rules

- Individual write requests are capped at `INT_MAX`, matching the signed result. Positive short writes are returned to the MLV writer, which completes them. Negative or impossible counts become `SIZE_MAX`; zero stays zero and is a writer error for a nonempty request.
- Absolute seeks reject offsets above `INT64_MAX`. Success requires the returned absolute position to equal the requested offset. A nonzero position is not an error status.
- The adapter uses seek origins 0/1/2 (SET/CUR/END), matching the pinned ML header. It does not require seeking beyond EOF.
- Flush errors propagate. Successful flush is only as meaningful as the supplied backend contract.

## Operating without truncation

No public truncation operation is exposed in the reviewed ML header. The writer's truncate callback is therefore implemented as an **unchanged-EOF check**, not file truncation: query the current position, query actual EOF, restore the original position, and succeed only if EOF already equals the requested size and restoration succeeded. It never reports that a longer file was shortened.

This permits normal recording finalization without truncation. It also permits error finalization when a failed frame added no bytes and the backend reports the expected EOF. If any partial frame tail remains, rollback fails and the writer refuses successful finalization. The failed frame returns to READY and previous data is left in the file. Restoring a valid file after that case still requires an established truncation facility or a separate recovery mechanism. The current adapter does not repair the tail or retry recording.

EOF checks are not atomic against other writers, hence exclusive ownership is mandatory. A failed seek/flush or process/power loss can still leave an unfinalized file. This is not a crash-recovery or hardware-durability guarantee.

## Verification on the PC

```sh
python scripts/test_raw14_arm.py --toolchain /path/to/arm-toolchain/bin --upstream-source /path/to/magiclantern
python scripts/test_raw14_disk.py --toolchain /path/to/arm-toolchain/bin --build-dir .tools/raw14-tests
```

Four C suites now execute as Cortex-R4 Thumb code under Unicorn's Cortex-R5 model: copy, queue, MLV, and FIO adapter. The FIO tests cover negative/zero/impossible writes, the signed request cap, offsets beyond 4 GiB using a virtual seek backend, rejection beyond signed 64-bit range, wrong seek results, position restoration, nonempty-file refusal, flush errors, normal MLV finalization, failure before any new bytes, and refusal to finalize a partial frame tail.

The disk harness additionally builds the same synthetic recorder with this adapter (`RAW14_USE_FIO`). Only signed write, signed-64-bit seek, and flush cross the emulation boundary; truncate is never called. The harness exercises the actual ARM ABI, including the stack argument for seek origin and the R0/R1 64-bit return value.

With 48 submissions it records and independently checks 36 complete 64x32 frames, 12 deliberate overflow drops, and a finalized 130,408-byte file. In the partial-write case it leaves a 3,883-byte unfinalized file containing one complete frame and a 35-byte partial next block. The independent parser rejects that file. To verify the preserved frame only, the test normalizes a copy of the complete prefix in memory; it does not modify or claim to repair the output file. JSON distinguishes `finalized: false` from successful finalization.

The two previous direct-backend disk cases still run, providing four disk scenarios in total. Sensor access, concurrent camera tasks, Canon filesystem behavior, real frame rates, and editor compatibility remain unverified.
