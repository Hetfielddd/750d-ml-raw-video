# RAW destination overwrite and a native snapshot/override/restore candidate

Eight native PC scenarios now check what happens when an earlier destination override meets the 750D RAW module's next address-programming path. With a supplied zero override flag, the normal path replaces an earlier register-level destination with its software pending address. A newly traced native snapshot/override pair can suppress that address replacement, and a restore function reinstates ten saved register words. This is a concrete control-path candidate, **not a completed-frame lease or a usable recording backend**.

## Comparison with the working donor

At pinned Magic Lantern revision `142472e95054d73640f50789ac0fd66325499d82`, `raw_lv_redirect_edmac()` in `src/raw.c` directly writes `CACHEABLE(ptr)` to `raw_lv_edmac->ram_addr` for the non-SLURP path. The 7D2 configuration selects base `0xD0004200`; the reviewed 750D auxiliary path selects channel 1 / `0xD0004100`. Those model-specific choices must not be equated.

`mlv_lite`'s VSYNC callback redirects the upcoming capture to one of two full-size buffers and passes the opposite index to `process_frame()`, which queues work to a separate copy/compression task. Its state-object hook runs after the original transition. On the reviewed 750D method rows, the transition can already prepare another StartDriver request before returning. Directly transplanting the donor hook therefore does not establish that the requested destination survives until the 750D's next start, or that the opposite buffer is complete and stable.

## Pending address versus register and shadow

The normal 750D RAW entry at `0xFE8395C4`, with supplied initialized/non-alternate state, reads channel index from `0x01AC2220 + 28` and pending address from +36. For a nonzero pending address it calls veneer `0xFE86F858`, whose actual destination setter is runtime `0x8000C654` / source `0xFE753A34`. That setter consults `0xFE7539DE`, clears address bits 30/31, then uses the real shadow/register writer.

The byte consulted for channel 1 is **`0x01AD8BD8`**, derived from table base `0x01AD8B84`, **44-byte** row stride and offset 40. Value 1 skips the ordinary address write. Other tested value 0 permits it. This byte is mutable software state, not a verified hardware completion bit or an immutable channel type.

The earlier destination probe seeded an unused zero at a mistakenly calculated 108-byte stride. Its actual classifier byte was already zero in newly mapped RAM, so its result was unaffected. That fixture now explicitly seeds the correct 44-byte row; its saved output is unchanged. The new nonzero-flag case makes the distinction observable.

Seven simple scenarios check:

- Normal pending marker `0x5C62C000` programs `0x1C62C000`.
- An earlier direct-register fixture at `0x1E000000`, leaving the shadow unchanged, is overwritten by that normal pending value.
- Calling the actual address setter earlier updates both register RAM and shadow to `0x1E000000`, but the later RAW entry still replaces them from the old pending value.
- Calling actual pending setter `0xFE8396B0` with marker `0x5E000000` makes the RAW entry program `0x1E000000` instead.
- Setting pending zero via that same native function omits address programming and reaches the supplied callback, preserving its argument.
- A separately invoked later address setter changes the register, but a separate RAW-entry invocation reloads the retained old pending value. These invocations are not a completed capture cycle.
- Supplying flag 1 skips address programming even with nonzero pending state, preserving the deliberately different register/shadow fixture.

Every nonempty RAW entry stops **before channel-start call `0xFE86F878`**. Register locations are ordinary RAM; no channel is started and no pixels are mapped.

## A native producer of the skip flag

Tracing actual writers of the flag reveals a matched software mechanism:

1. Entry `0xFE755994` zeros a 48-byte scratch descriptor using the real peer-kernel zero helper. Its veneer `0xFE74F924` jumps to ARM runtime `0x14F0`, scoped from peer-kernel source `0xFE746250`.
2. Helper `0xFE7556E4` snapshots ten shadow words from channel offsets +4 through +`0x28` into its 44-byte software row.
3. Helper `0xFE755902` derives geometry from that saved state and a supplied global row-size limit at `0x01AC40F4 + 4`. The reviewed path may divide/reshape the row count. This is not a verified pixel format or safe geometry configuration.
4. The function updates control/geometry, clears auxiliary register offsets `0x40` and `0x54`, invokes the ordinary configuration helper with zero, and programs the destination from `0x01AC40F4` using the actual address setter.
5. **Only after that programming**, it stores 1 to the row's byte +40.
6. Restore entry `0xFE755A40` invokes `0xFE7557F6` to write back the ten saved words to both register RAM and shadow, then clears that flag.

The eighth scenario executes these functions without native stubs, with supplied channel 1, destination marker `0x5E000000`, row limit 3,584 bytes and saved geometry corresponding to 1,080 supplied rows. It verifies all ten saved words, the new destination and native flag 1. A subsequent normal RAW entry reads its unchanged old pending address but performs **no address store**, retaining the override. The restore function then restores the ten saved words and clears the flag.

This is more specific than manually changing a register or guessing a flag. It identifies an actual firmware mechanism that could help a future recorder preserve a destination through normal address programming. Its intended caller, live activation and ownership rules remain unknown; no static callable import to these entry addresses has been established by this investigation.

## Partial restore and lifetime limits

The experiment deliberately seeds nonzero auxiliary values at channel offsets `0x40` and `0x54`, and software word `0x01AD8288` equal to 1. The override clears them; after restoring the ten-word snapshot, **all three remain zero**. The pair therefore does not restore every affected field in this experiment.

Nor does skip-address flag 1 mean that the channel is stopped: the normal RAW entry still reaches its channel-start call, where this probe stops. This mechanism does not establish that the current buffer is complete, frozen, exclusively owned or safe to read. Reentrancy, repeated acquisition, caller serialization, geometry constraints, physical idle/completion, cross-core cache handling and complete cleanup require additional evidence. Do not enable it as a camera hook or call it an allocation/locking API based on these results.

For a future double-buffered recorder, destination control and permission to copy the previous buffer remain distinct requirements. The native override candidate addresses part of the former. The [completion-event limitations](750d-completion-events.md) and [RAW IRQ qualification gap](750d-raw-irq.md) still prevent claiming the latter.

## Reproduction

```sh
python scripts/probe_750d_raw_redirection.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-raw-redirection.json) records eight passing scenarios. Exact main-record size and SHA-256 are enforced before importing Unicorn 2.1.4. Cortex-A15 executes the compatible scalar ARM/Thumb subset, including native integer division used by geometry preparation; it does not model the camera's Cortex-R4 peripherals or memory system.

Firmware, scoped driver/table imports, the single peer-kernel page and boundary page are read/execute. Explicit state, scratch stacks, shadow and artificial register RAM are read/write without execute permission. Code/write guards bound all stages, including the byte flag, selected snapshot row and permitted auxiliary stores. Each stage is limited to 1,024 instructions / 0.5 seconds. Function entries and event order are supplied independently; OS transport, hardware start, physical IRQs, sensor capture, actual pixels, throughput and frame ownership remain unverified. Camera bindings remain disabled.
