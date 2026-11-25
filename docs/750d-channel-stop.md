# Channel stop-request path and the shared RAW IRQ route

The RAW IRQ probe now covers **20 IRQ scenarios and two separate real callback preparations**. Eight new sequences execute native configuration, start, a stop-like request and a status reader before directly invoking the IRQ body. This derives the request flag from actual code rather than supplying its IRQ-entry value.

The result separates a request/notification protocol from a completed-image lease. No peripheral transfer, actual stop, delivered IRQ or complete frame is modeled. The generic request is called a stop request below because of its caller/wait pattern; its exact hardware effect remains unverified.

## Native request helper

Import veneer `0xFE86F69C` stores runtime target `0x8000C5BF`, source `0xFE75399E`. With channel index 1, this actual function:

1. Stores 1 to software word `0x01AD81C8`.
2. Reads the channel control shadow and computes `(shadow & ~7) | 6`.
3. Writes that value to the shadow and channel control `0xD0004104`.
4. Returns through the real register-write helper.

The function does not wait for a status change, copy pixels, supply a frame identity or establish that a partially written buffer contains a complete image.

The preceding native start helper `0xFE75395E` clears the same software word. The IRQ handler does not clear it again in the reviewed request cases. It is therefore a request-mode input to this logic, not a completion latch that this IRQ resets.

## Actual caller/wait evidence

Two scoped main-record paths reference this import:

- At `0xFE8B4B98`, a caller installs callback `0x01C32369` through `0xFE86F860`. At `0xFE8B4B9E` it calls the request import; after restoring IRQ state it prepares a wait through `0xFE86FA28`, using an owner handle at offset 24.
- At `0xFE930E8C`, another caller installs callback `0x01CAE941`, calls the request import at `0xFE930E92`, marks an owner-state bit, restores IRQ state and prepares the same wait using an owner handle at offset 68.

The callback installer import selects `0x8000CF4B`, source `0xFE75432A`, the same channel callback-record installer reviewed in [IRQ registration](750d-irq-registration.md). The wait import selects `0x80005D5B`, source `0xFE74D13A`, the semaphore-take wrapper. These surrounding caller paths are statically reviewed; their full execution, callback registration/controller enablement and waits are not executed here. Their channel indices come from owner objects, not an observed RAW channel selection.

Two separate native callback checks execute the actual bodies:

- Callback source `0xFE8B46D0` stores 1 at owner `0x01AC3704`, loads its offset-24 handle and reaches signal veneer `0xFE86F3D4`.
- Callback source `0xFE930CA8` loads owner `0x01AC615C` offset-68 handle and reaches the same signal veneer.

That signal trampoline selects runtime `0x80005DD3`, source `0xFE74D1B2`, the semaphore-give wrapper. Both checks stop **before the trampoline executes**. No give, caller wakeup, physical acknowledgement or completed stop is invented. The owner objects and handles are supplied fixtures.

This supplies concrete firmware use of request/callback/wait synchronization. It does not establish that either caller is the active RAW Live View owner, or that a stop acknowledgment qualifies a whole sensor frame.

## Eight request-to-IRQ sequences

Each new sequence uses channel 1 and the same artificial register RAM/shadow across these native functions:

1. Configuration `0xFE7539BE` stores supplied secondary value 0/1 at `0x01AD8288` and changes the control low bits.
2. Start `0xFE75395E` clears the primary software word, sets control bit 29 and writes channel command 1.
3. Request `0xFE75399E` sets the primary software word to 1 and changes control low bits to 6.
4. Status reader `0xFE7554DA` reads physical-location RAM at `0xD0004130` and returns exactly bit 2 as 0/1.
5. The experiment directly invokes IRQ body `0xFE7545CC`, retaining the actual request-produced flags.

Cases combine supplied status 0/4, secondary value 0/1 and initial control 0/`0xDEADBEEF`. Initial control high bits are preserved by the request. The later IRQ branches behave as follows:

- Status bit 2 set: control becomes zero.
- Status bit 2 clear, secondary zero: control becomes zero.
- Status bit 2 clear, secondary one: control becomes `(request_control & ~7) | 2`.

All eight then issue channel-base value 4 and reach the supplied RAW driver callback via the real application forwarding wrapper. The primary request word remains 1 and the secondary word retains its configured value. A subsequent native start, rather than this handler, is the reviewed writer that clears the request word.

For a controlled comparison with the earlier IRQ cases, these eight fixtures retain the RAW callback record. They do not execute either caller's replacement of that record with its stop-specific callback. The two real stop-callback preparations are separate checks, not a claimed uninterrupted stop/wakeup run.

## Status and ownership limits

The new status reader is more direct than the request word: it reads channel status, not software state. But the reviewed function only extracts bit 2; neither its physical meaning nor an active RAW caller has been established. The same bit selects one IRQ cleanup branch, while zero status still reaches notification in the supplied-RAM tests. A scalar bit extraction is not a frame-completion contract.

The register page is ordinary RAM. Status read-to-clear, command acknowledgement, actual stopping, drain completion and incomplete-frame contents are not modeled. The status-reader call before IRQ invocation is a supplied experiment order, not a proposed live polling sequence. The `[start -> request -> direct IRQ]` sequence contains no simulated DMA transfer between those calls.

At the pinned 7D2 revision, `AbortEDmac` and ordinary EDMAC completion/abort callback overrides are empty. They do not provide the missing target contract. That donor's useful recorder path instead combines VSYNC/opposite-buffer sequencing and its synchronous full-width copy backend. A future 750D implementation still needs to qualify real sensor completion, distinguish interrupted/partial buffers, establish safe reuse and handle cache visibility.

## Reproduction

```sh
python scripts/probe_750d_raw_irq.py /private/750d-analysis/record-06.bin
```

The [evidence](evidence/750d-raw-irq.json) records the original 12 cases, eight request sequences and two separate callback preparations. The identified main-record size/SHA-256 gates, guarded compatible Cortex-A9 execution, native stack checks and per-stage 128-instruction / 0.5-second limits apply. No native calls are stubbed. Firmware and disassembly remain private. Camera bindings are disabled; camera and SD card are untouched.
