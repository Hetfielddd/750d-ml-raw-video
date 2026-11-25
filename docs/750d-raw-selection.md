# Counter-restricted RAW selection and its lifetime limits

The RAW address selector has a native counter restriction that may help build a first single-frame capture experiment. In the reviewed handler, the fallback register is initialized to zero. With a nonzero requested counter, a match selects the RAW preparation address and clears the request tag; a subsequent different nonzero counter selects zero. This is address selection, not completed-frame ownership or a guaranteed stop of ongoing DMA.

## Actual setter and consumer

Setter **`0xFE308ECA`** reads a word through its input pointer, stores it at RAW state `0x2AF78 + 44`, and writes `tag != 0` at state + 8. Passing zero therefore disables the restriction; it does not disable RAW capture. The separate previously identified `lv_save_raw` setter at `0xFE308EB4` controls state + 4.

The selection slice **`0xFE2B92AE`** reads these actual getters and compares the requested tag with EVF state `0x26B94 + 24`. When RAW and the caller route are enabled:

- Restriction disabled: choose EVF candidate at `0x26B94 + 88`.
- Restriction enabled and tag equal to counter: choose that candidate, then actual clear helper `0xFE309D08` stores zero at RAW state + 44. State + 8 remains enabled.
- Restriction enabled and unequal: retain fallback R8.

The earlier handler slice **`0xFE2B911A`–`0xFE2B9126`** initializes R8 to zero. Two new fixtures execute this slice with an initial R8 marker, verify its native clearing, then separately enter the selection slice. Static review of the intervening handler body finds no other explicit R8 assignment before selection. Intervening callees and complete handler activation are not executed; this is a reviewed path, not a claim about every firmware route or arbitrary supplied R8.

## Verified sequences

The first eight [native cases](evidence/750d-raw-selection.json) use actual enable/restriction setters and preserve their state across multiple supplied counter values:

- Requested tag 17, counters 16/17/18: fallback, candidate, fallback; the tag is consumed only on the match.
- Tag 17, counter 17 repeated: candidate, then fallback because the remaining tag is zero.
- Setter input zero, counters 17/18: candidate both times because restriction is disabled.
- Tag 17, counters 17/0: candidate both times. **The consumed zero tag can match a later zero counter.** This does not establish whether a live counter zero occurs in this operating state.
- Deliberately supplied fallback equal to candidate: even a mismatch selects the same address. This adversarial fixture shows that tag consumption alone cannot guarantee memory separation; it is not the reviewed zero-fallback handler path.
- Explicitly rearming with tag 18 after consuming tag 17 selects the same candidate again for counter 18.
- Native zero-fallback initialization, tag 17, counters 17/18: candidate, then zero.
- Native zero-fallback initialization, tag 17, counters 17/0: candidate again on zero, confirming the same counter-zero limitation without a nonzero fallback fixture.

Candidate `0x5C62C000` and the nonzero fallback are unmapped address markers. This experiment does not read pixels from them. Those eight cases supply the EVF counter directly; none asserts a measured frame ID or observed camera sequence.

## VD counter producer and reset-to-one branch

The actual event table maps **event 3 / state 5** to handler `0xFE2B8C18`, identified by its `evfVdInterrupt` diagnostics. It remains in state 5. This is distinct from parameter event 4 and readout event 5.

In the reviewed first-frame branch, caller field +52 is initially zero. Native code at `0xFE2B8CD4` sets R5 to 1 and caller +52 to 1. After intervening calls, the store at `0xFE2B8CF8` sets EVF counter `0x26BAC` to 1 using R5. The ordinary later path ends with `0xFE2B9094`–`0xFE2B909A`, which loads that word, adds one and stores the 32-bit result. The reviewed increment has no special case that skips zero.

Four additional cases derive the counter from these native update slices, bringing the total to **12**:

- A supplied first-frame context uses the native prefix to produce R5 = 1 and the separately entered post-call store to reset an initial `0xFFFFFFFF` counter to 1. Selection for tag 1 succeeds, then a native increment to 2 selects zero.
- An initial counter 16 increments natively to 17, consumes tag 17, then increments to 18 and selects zero.
- An initial `0xFFFFFFFE` increments to `0xFFFFFFFF`, consuming that tag; the next native increment wraps to zero and selects the candidate again because the cleared tag is zero.
- The same wrap sequence, with the actual `lv_save_raw` setter invoked with zero after the first match, retains zero fallback on the subsequent zero counter. The selection restriction/tag are not replaced or patched by the experiment.

These results narrow the previous uncertainty: the first-frame branch initializes to **1**, and normal increments 1, 2, 3 do not immediately revisit zero. The zero-match issue is a demonstrated arithmetic boundary, not evidence of frequent repeats during a short recording. Reset/reinitialization outside the reviewed paths, the active event sequence and elapsed time per increment remain unverified. A VD notification count is not a proven count of completed RAW frames.

The first-frame fixture supplies caller +64 = 39 to avoid a notification call, stops before helper `0xFE30B15A`, then enters the post-call store separately with the produced R5. It does not fabricate returns from the intervening helpers or execute the complete first-frame handler. Other native increment cases execute the whole three-instruction increment slice.

## Consequence for buffer reuse

The [address route](750d-raw-address-route.md) propagates the selected word into RAW preparation. The separately reviewed peer configuration `0xFE8396B0` can publish zero pending address, and [RAW start](750d-raw-start.md) skips destination/start work when no address is pending. These separate results suggest a useful single-selection path with zero fallback. They do not prove end-to-end command delivery, cancellation of an already armed transfer, lack of intervening writers, or a completed frame becoming safe to copy.

The event table also distinguishes parameter event 4 (`evfSetParamInterrupt`) from readout event 5 (`evfReadOutDoneInterrupt`); both are self-transitions in reviewed states 3–6. The mode-3 parameter method submits service `0x20002` operation 4, while completion processing can prepare StartDriver operation 2. A state number or a consumed selection tag does not establish a time window between those operations. Their live ordering, complete counter lifecycle, hardware completion and cache contract remain required evidence. Disabling RAW after a match blocks subsequent selection in the tested slice; it does not cancel an already submitted transfer or establish a frame lease.

## Reproduction and scope

```sh
python scripts/probe_750d_raw_selection.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and exact identified main-record size/SHA-256; input gates run before importing Unicorn. Cortex-A9 executes compatible instructions, not a Cortex-R4 camera system. Firmware/stop pages are read/execute; supplied state and scratch/stack are read/write without execute permission. Code/write guards apply; each native stage is bounded to 128 instructions / 0.5 seconds.

Logger calls stop at their real entry. Execution resumes only at reviewed continuations `0xFE2B92E8` or `0xFE2B9302`; no logger return is synthesized and no native call is stubbed. Reviewed counter-update slices execute in four cases; the full interrupts, intermediate handler calls, downstream command delivery, DMA and cache operations are not executed. No camera binding or frame lease is enabled.
