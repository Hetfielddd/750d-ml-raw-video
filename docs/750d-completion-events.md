# RAW-component notification and aggregate completion are distinct

The [destination investigation](750d-raw-destination.md) traced a candidate channel-1 callback into a RAW wrapper. This step follows the next layer: the driver's component callbacks and the application task notifications they prepare. Ten native aggregation scenarios and two task-request checks pass on the PC.

The result identifies separate notifications, not a safe completed-frame source. No hardware interrupt, sensor transfer, queue delivery or buffer ownership is emulated.

Input: actual 750D 1.1.0 main-code record, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`, source alias `0xFE0A0000`.

## Target-specific callback route

The previously traced RAW module forwards through its state at `0x01AC2220 + 8/+12`. Driver setup at source `0xFE751266` installs a callback whose stored address is `0x80009D8F`, corresponding to source body `0xFE75116E` under the scoped driver mapping. Its driver state begins at `0x01AC1830`.

Within that state:

- Offset 4 is a pending component mask.
- Offsets 12 and 16 hold an aggregate callback and its argument.
- Offsets 20 and 24 hold a RAW-specific callback and its argument.
- Offset 44 supplies the handle passed to an OS event-flag helper.

The RAW callback first invokes the optional function at offset 20. Only afterwards does it OR `0x10` into the pending mask and request that the OS event flag be set. Other reviewed callbacks OR the remaining bits `0x01`, `0x02`, `0x04`, `0x08`, `0x20` and `0x40` into the same word.

The completion test is an exact equality with `0x7F`. When equal, the code invokes the aggregate callback if present, then clears the mask. If the callback pointer is null, the mask still clears. An extra bit outside `0x7F` prevents this equality in the synthetic test; that does not establish whether such a state can occur on a running camera.

The RAW-specific callback therefore precedes the mask update in this code. The aggregate callback observes the complete mask before it is cleared. Neither notification contains a validated frame identifier, memory lease or cache-coherence guarantee in the reviewed path.

## Application notifications

Application setup at source `0xFE80FD50` installs distinct callbacks for these two driver slots. Its stored pointers agree with the scoped application source/runtime correspondence:

- RAW component: stored pointer `0x01B8D9B9`, source body `0xFE80FD20`. It prepares task event **7**.
- Aggregate completion: stored pointer `0x01B8D9D5`, source body `0xFE80FD3C`. It prepares task event **6**.

Both use the native task-request helper at source `0xFE86FB30`. With supplied task/subtask structures, the experiment verifies their queue-handle marker, associated subtask, event number and zero arguments. It stops before the external queue-operation veneer at `0xFE86F740`. No request is delivered and no receiving state-machine transition is executed. These numbers must not be confused with the previously traced Postman service operations.

## Bounded native experiment

```sh
python scripts/probe_750d_completion.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and the exact identified record. The script rejects the wrong size or SHA-256 before importing Unicorn. Code is read/execute; explicit synthetic state and stack memory are read/write without execute permission. No MMIO or pixel memory is mapped.

The aggregation experiment executes native callback slices after their interrupt-disable calls, using supplied saved-register frames. It stops before the OS event-flag helper, resumes after that call, and stops again before interrupt restoration. For the complete-mask path it separately resumes at the reviewed post-restoration continuation. These helper effects are **not executed or modeled as successful**. The continuation reloads the mask before testing it. The supplied interrupt-state token remains an uninterpreted marker.

Callback endpoints used for ordering observations are existing native one-instruction `BX LR` functions. They execute normally; the script observes their arguments and the mask at entry without synthesizing a return. The actual application task callbacks are tested separately, as described above. This is not execution of the entire callback chain with real OS synchronization.

Instruction-range and write-range guards restrict aggregation execution to the reviewed routines and mask word. Each stage is bounded to 128 instructions and 0.5 seconds. The separate task-request checks permit only expected stack/subtask writes and use 64 instructions / 0.5 seconds. Unicorn's Cortex-A9 model executes the compatible instruction subset, not a Cortex-R4 camera system.

## Results

Ten aggregation scenarios pass:

- RAW only: one RAW notification, no aggregate notification; mask remains `0x10`.
- RAW last and RAW first: one notification of each kind after all seven bits arrive.
- RAW repeated before the other components: two RAW notifications, but one aggregate notification.
- One missing component: no aggregate notification.
- Two complete cycles: two notifications of each kind, with mask reset between cycles.
- Other components preseeded as `0x6F`: RAW completes the set.
- An extra preseeded bit: exact equality does not trigger aggregate completion.
- RAW callback absent: aggregate completion still occurs.
- Aggregate callback absent: the completed mask still clears.

Two additional native checks verify application events 7 and 6. [Machine-readable evidence](evidence/750d-completion-events.json).

The duplicate-event scenario is supplied by the experiment; it is not evidence that the camera actually emits duplicate RAW notifications. It demonstrates that this callback logic does not itself enforce one RAW notification per aggregate cycle. A recorder cannot derive frame identity solely from the number of such calls.

## What remains before a frame lease

The [next bounded investigation](750d-completion-dispatch.md) follows supplied events through the actual task dispatcher to return operations 2 and 6, and separately checks primary-side callback selection. Delivery and buffer ownership remain unverified.

The target now has a traced candidate destination, [geometry arithmetic](750d-raw-geometry.md), and distinct component/aggregate task notifications. The missing bridge is the actual receiving state-machine path, its relationship to the next buffer reuse, and live timing/cache behavior. The earlier donor VSYNC old-state/input condition must not be substituted for these checks. No camera hook, platform binding or completed-frame provider is enabled by this experiment.
