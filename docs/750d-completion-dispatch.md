# Completion events through the task dispatcher

The [previous investigation](750d-completion-events.md) distinguished application task event 7 (RAW component) from event 6 (aggregate completion). Native execution now follows supplied events through the actual dispatcher and application handlers to the return-transport boundary. A separate experiment checks the primary-side callback selection. The queue and transport gap between these stages remains unexecuted.

## Application dispatch

The task-object constructor at source `0xFE74CC66` stores the transition table at object offset 16, event limit at 20, per-event state stride at 24, and current state at 28. Its handler pointer at offset 12 is stored as `0x8000581B`, corresponding to source `0xFE74CBFA`. The checked wrapper is source `0xFE74CBDC`, runtime `0x800057FC`.

The application constructor wrapper at source `0xFE80FD0C` supplies table pointer `0x01CF2190`, event limit 8 and stride 1. Under the scoped application source/runtime correspondence the table is at source `0xFE9744F8`. For supplied state zero:

- Event 6 selects stored handler `0x01B8DAA9`, source `0xFE80FE10`.
- Event 7 selects stored handler `0x01B8DABB`, source `0xFE80FE22`.

Both table entries have next state zero. The dispatcher stores that state before invoking the selected handler. This particular transition does not itself record a frame identity or transfer buffer ownership.

The event-6 handler calls helper `0xFE86FBDE` with operation **2**. The event-7 handler calls it with operation **6**. The helper reads a route value from the supplied application context (offset 8), splits its high/low halves and prepares the Postman call at ARM veneer `0xFE86F644`:

```text
R0 = 5
R1 = route >> 16
R2 = ((route & 0xffff) << 8) | operation
R3 = supplied event argument
```

The experiment stops before executing this veneer or its imported transport target. With supplied route `0x00020002`, event 6 prepares `[5, 2, 0x202, argument]` and event 7 prepares `[5, 2, 0x206, argument]`. A second route verifies that the destination/service fields are dynamic; neither route is measured from a running camera. The previous task-request checks supply zero event arguments. Nonzero arguments here are arithmetic fixtures, not observed camera payloads.

## Separate primary-side receive check

The previously identified primary receiver at source `0xFE3806FE` uses its actual table at `0xFEB73800` to select:

- Operation 2: source `0xFE3807BA`, invoking function/argument at `0x36720 + 0/+4` when non-null.
- Operation 6: source `0xFE3807D0`, invoking function/argument at `0x36720 + 8/+12` when non-null.

Four separately invoked native cases verify both selections and null-pointer skipping. They supply the registrations and stop before the selected callback body. No mailbox decoding, arrival or delivery is simulated. The callback argument comes from the registration slot, replacing the incoming R0 marker; it is not a validated frame pointer.

Static registration review adds an important mode distinction. The earlier reviewed mode-3 setup calls `0xFE380706` at `0xFE28D562` with callback `0xFE28D2D1` and argument zero. That callback prepares a logging call, so its name or invocation alone is not evidence of a recorder-ready frame. In contrast, setup at `0xFE2932C2` installs aggregate callback `0xFE293011`, and at `0xFE2932CA` separately installs RAW callback `0xFE293029` via setter `0xFE380746`. These latter handlers have additional outgoing calls that have not yet been traced to buffer ownership. This is a scoped comparison of setup branches, not proof that the RAW slot is always null in mode 3 or that these branches are active on the owner's camera.

## Reproduce and limits

The [next investigation](750d-evf-raw-event.md) follows the separately registered RAW handler to EVF event 19, labeled `evfAfPathCompleteInterrupt`. This further qualifies its meaning; a RAW-component notification is not by itself a recorder-ready frame.

```sh
python scripts/probe_750d_completion_dispatch.py /private/750d-analysis/record-06.bin
```

Input must match actual 750D 1.1.0 main record size `0xCFB688` and SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Both are checked before importing Unicorn. The code executes with Unicorn 2.1.4's Cortex-A9 compatible instruction subset, not a Cortex-R4 camera-system model.

The experiment copies only reviewed pages to the scoped application/driver runtime aliases used by stored native pointers. These are explicit experiment copies, not validated boot relocations. Code/table pages are read/execute; supplied objects and stack are read/write without execute permission. Execution/write guards and 128-instruction / 0.5-second stage limits apply; receiver checks use 32 instructions / 0.5 seconds and permit no writes. No native calls are stubbed or forced to return success.

Ten dispatch cases pass: two events, two supplied routes, two arguments, plus invalid-signature and out-of-limit rejection. Four separate receiver cases pass. [Machine-readable evidence](evidence/750d-completion-dispatch.json).

This connects event numbers to concrete return operations and callback slots. It does not establish physical IRQ timing, OS queue behavior, delivery, sensor pixels, cache coherence, actual active geometry, or how long the destination remains valid before reuse. The camera provider remains disabled. The next useful steps are the mode-dependent RAW handler's outgoing path and the actual buffer-reuse/cache contract, rather than counting completion calls as frames.
