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

Five additional cases derive the counter from these native update slices, bringing the total to **13**:

- A supplied first-frame context uses the native prefix to produce R5 = 1 and the separately entered post-call store to reset an initial `0xFFFFFFFF` counter to 1. Selection for tag 1 succeeds, then a native increment to 2 selects zero.
- An initial counter 16 increments natively to 17, consumes tag 17, then increments to 18 and selects zero.
- An initial `0xFFFFFFFE` increments to `0xFFFFFFFF`, consuming that tag; the next native increment wraps to zero and selects the candidate again because the cleared tag is zero.
- The same wrap sequence, with the actual `lv_save_raw` setter invoked with zero after the first match, retains zero fallback on the subsequent zero counter. The selection restriction/tag are not replaced or patched by the experiment.
- The 17/18 sequence with a supplied non-null peer callback verifies that the empty pending-address path invokes that callback without preparing a DMA destination. This callback boundary cannot itself mean a captured frame.

These results narrow the previous uncertainty: the first-frame branch initializes to **1**, and normal increments 1, 2, 3 do not immediately revisit zero. The zero-match issue is a demonstrated arithmetic boundary, not evidence of frequent repeats during a short recording. Reset/reinitialization outside the reviewed paths, the active event sequence and elapsed time per increment remain unverified. A VD notification count is not a proven count of completed RAW frames.

The first-frame fixture supplies caller +64 = 39 to avoid a notification call, stops before helper `0xFE30B15A`, then enters the post-call store separately with the produced R5. It does not fabricate returns from the intervening helpers or execute the complete first-frame handler. Other native increment cases execute the whole three-instruction increment slice.

## Native propagation into pending-address and start paths

All five counter-derived cases now propagate the selected word through additional native stages on the same synthetic memory. The host never copies the selected address between these stages:

1. Publisher `0xFE309F14` consumes the actual selection word at stack + `0xDC` and stores it at global `0x6B3E0` (configuration + 80).
2. Mode-3 configuration slice `0xFE28D9D6`–`0xFE28DA36` consumes that configuration and writes driver + 200. A supplied auxiliary-route flag selects channel index 1; unrelated mode/geometry fields are fixtures.
3. Separately invoked driver slice `0xFE750F2C` passes driver + 200 through actual veneer `0xFE74F130` to the scoped peer callback `0x01BB7349`, source `0xFE8396B0`. Its native code publishes the address to peer RAW state `0x01AC2220 + 36` and a supplied packing selector to +44.
4. Actual RAW-start function `0xFE8395C4` sees that pending address. Nonzero stops at destination-submission veneer `0xFE86F858` with channel 1 and the same address. Zero returns without destination submission when the supplied peer callback is null. In the fifth case it instead invokes supplied driver callback `0x80009D8F` with its argument; execution stops before the callback body.

Thus the 17/18 sequence produces candidate then zero through **both** parameter publication and pending-address state. The second start takes the empty path. The wrap sequence selects the candidate twice; disabling RAW after the first match changes its second pending address to zero and takes the empty path. Thirteen sequence cases contain ten such native propagation/start checks.

These are independently entered function/slice stages, **not an executed mailbox or transport chain**. The experiment supplies active/non-alternate peer state, channel 1, auxiliary routing, packing selector 34 and callback registration. The first nonzero start stops before destination submission; no transfer is ever armed, completed or canceled. A subsequent zero configuration replaces an unsubmitted pending address in this experiment, which cannot prove cancellation or safe access to an already active frame.

## Consequence for buffer reuse

The [address route](750d-raw-address-route.md) and the native data-propagation checks support a useful single-selection path with zero fallback. The [RAW start](750d-raw-start.md) empty path omits destination/start work, but can still notify its callback. These results do not prove end-to-end command delivery, cancellation of an already armed transfer, lack of intervening writers, or a completed frame becoming safe to copy.

The event table also distinguishes parameter event 4 (`evfSetParamInterrupt`) from readout event 5 (`evfReadOutDoneInterrupt`); both are self-transitions in reviewed states 3–6. The mode-3 parameter method submits service `0x20002` operation 4, while completion processing can prepare StartDriver operation 2. A state number or a consumed selection tag does not establish a time window between those operations. Their live ordering, complete counter lifecycle, hardware completion and cache contract remain required evidence. Disabling RAW after a match blocks subsequent selection in the tested slice; it does not cancel an already submitted transfer or establish a frame lease.

## Reproduction and scope

```sh
python scripts/probe_750d_raw_selection.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and exact identified main-record size/SHA-256; input gates run before importing Unicorn. Cortex-A9 executes compatible instructions, not a Cortex-R4 camera system. Firmware, a scoped peer-code copy and stop pages are read/execute; supplied state, driver/configuration and scratch/stack are read/write without execute permission. Code/write guards apply; each native stage is bounded to 128 instructions / 0.5 seconds. All MMIO is unmapped. The scoped peer-code copy is not verified boot relocation.

Logger calls stop at their real entry. Execution resumes only at reviewed continuations `0xFE2B92E8` or `0xFE2B9302`; no logger return is synthesized and no native call is stubbed. Reviewed counter-update slices execute in five cases; the full interrupts, intermediate handler calls, downstream command delivery, DMA and cache operations are not executed. No camera binding or frame lease is enabled.
