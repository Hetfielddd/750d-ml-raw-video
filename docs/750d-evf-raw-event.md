# The RAW return notification reaches an EVF AF-path event

The [completion-dispatch investigation](750d-completion-dispatch.md) identified a separate RAW return callback in some primary-side setup branches. Following that callback now reaches the EVF handler labeled `evfAfPathCompleteInterrupt`. This is an important qualification: the earlier RAW-component notification must not be labeled a recorder-ready video-frame event.

It remains possible that a useful sensor buffer exists earlier in the route. The AF consumer alone establishes neither its image format nor its suitability for recording. No camera binding is enabled.

## Request and worker boundaries

The statically reviewed callback at source `0xFE293028` logs and tails to `0xFE2686FC`. With a supplied non-null context at RAM word `0x4AF4`, the latter prepares:

```text
R0 = context[8]   (task handle)
R1 = context
R2 = 19          (EVF event)
R3 = 0
fifth argument = 0
```

Native PC execution stops before ARM veneer `0xFE3CE01C`, whose literal target is low-memory entry `0x2353`. A missing context reaches the existing assertion boundary instead; that assertion is not forced to succeed.

EVF task setup at source `0xFE26855A` creates its state object via `0xFE2B7FF4`, stores it at context offset 12, and supplies worker `0xFE268514`. A separate native check enters that worker with supplied event 19 and verifies that it prepares `[context[12], context, 19, 0, 0]` for state-transition veneer `0xFE3CE004`. The queue, low-memory OS code and delivery between these stages are not executed.

## Actual EVF table

The state-object constructor uses table `0xFEA0B174`, 20 event rows and 10 states, and stores the object at RAM word `0x26B94`. The table is decoded from the identified main-code record; no low-memory dispatcher is emulated here.

For event 19, states 3, 4, 5 and 6 select source handler `0xFE2B969E` (stored pointer `0xFE2B969F`). States 2, 7 and 8 select another handler at `0xFE2BA912`. States 0, 1 and 9 have a null handler. All ten entries retain their current state. These are table facts, not a measurement of the camera's active state.

The selected handler uses the debug label `evfAfPathCompleteInterrupt`. After logging, it reads context offset 88. A zero value leads to source `0xFE247768`, passing addresses `context[140] + 132` and `context[140] + 156`. A nonzero value skips that call and proceeds to common continuation `0xFE548550`.

Two native checks verify this branch and its arguments with supplied structures. They execute a prefix up to the logger, then a separate reviewed slice after the logger; the logger is not executed or stubbed. Both downstream boundaries remain unexecuted by those checks.

## Small downstream result pool

Static review of `0xFE247768` shows a call to `0xFE268A94`. Four separate native checks execute that helper. It increments the byte at `0x25F9C`, wraps its normal sequence between indices 0 and 1, and returns:

```text
0x41080 + index * 1728
```

Inputs 0, 1, 2 and 255 verify normal alternation, out-of-range reset and byte overflow. Only the index byte is writable in this experiment; the returned pool is not mapped or read. The surrounding code writes status at returned-object offset 1724 and other small result fields. This pool must not be substituted for the much larger sensor-image buffer or interpreted as its ownership contract. Its reuse behavior concerns this downstream result object only.

## Reproduction and remaining work

```sh
python scripts/probe_750d_evf_raw_event.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Input gates run before importing Unicorn. Execution uses the Cortex-A9 compatible instruction subset, not a Cortex-R4 camera-system model. Code is read/execute; explicit supplied context/stack/global pages are read/write without execute permission. Instruction-range and write-range guards apply. Native stages are limited to 64 instructions / 0.5 seconds; pool calls to 32 instructions / 0.5 seconds. No native function is stubbed into success.

Five request/worker/handler checks and four independent pool checks pass. Ten event-19 table entries are decoded and checked separately. [Machine-readable evidence](evidence/750d-evf-raw-event.json).

This narrows the meaning of a previously found notification and identifies a downstream consumer. The full IRQ-to-task-to-EVF chain has not been run continuously. The next frame-capture work must establish the earlier destination buffer's actual layout and reuse timing independently of the AF result objects. Actual sensor pixels, cache coherence, throughput and a stable frame lease remain unverified.
