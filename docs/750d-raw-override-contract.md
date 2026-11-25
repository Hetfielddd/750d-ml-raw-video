# Native RAW override: configuration lifetime, repeated use and geometry

The [snapshot/override candidate](750d-raw-redirection.md) is not a drop-in A/B-buffer switch. Eleven additional native PC scenarios now characterize repeated use and geometry, bringing the probe to **19 scenarios**. They execute actual firmware functions with artificial register RAM and unmapped image pointers. No capture or channel start occurs.

## Actual configuration setter and unresolved caller

Entry `0xFE75598E` stores R0 and R1 to the shared pair at `0x01AC40F4` and `0x01AC40F8`, then returns through the existing `BX LR` leaf at `0xFE755262`. New scenarios execute this real setter rather than supplying those globals directly.

The override later reads that pair for its destination and geometry calculation. A native sequence configuring A, then B, then invoking override consumes **B**. There is no per-request copy or generation token in this reviewed pair. This illustrates a serialization requirement; the supplied sequence does not demonstrate a real cross-task race.

A bounded search of the identified main record found no direct Thumb BL/B.W/BLX or ARM B/BL candidate to the configuration/override/restore entries, no supported ADR/adjacent-MOVW-MOVT address-load candidate, and no literal source/runtime pointer to them. A separate literal-pointer search of the other eight decrypted update records also found no exact entry pointers. The searches do not cover every indirect/computed call or reconstruct a booted address space, and **do not prove the functions are unused**. Their intended caller and live activation remain unresolved.

## Repeated override overwrites the saved state

The original native function snapshots current channel state before setting its flag. It does not reject an already-set flag before taking that snapshot. With the flag already 1, its ordinary destination setter skips the new address write.

The native repeated-use scenario observes:

1. Starting from original destination O, configure A and call override: destination becomes A; saved state is O; flag becomes 1.
2. Configure B and call override again: saved state becomes the current A configuration; the address setter skips B because flag is still 1.
3. Call restore: destination is **A**, not O, and the flag clears.

Thus repeated override is not a verified nested acquisition, and configuring B does not by itself advance the destination. A separate serialized sequence **override A → restore → configure B → override B → restore** programs B and restores the original ten-word configuration in the fixture. These are independently invoked functions with no intervening capture; they do not establish that restoring between frames is safe on a running channel.

## Duplicate restore can overwrite a later address

The restore function does not check flag 1 before writing its saved words. Another native scenario overrides A, restores O, then uses the actual ordinary address setter to select B while the flag is zero. Calling restore again replaces B with the old saved O configuration, even though the flag was already zero.

This is not a demonstrated camera fault. It shows that a future owner-controlled adapter would need its own state/serialization and must not treat repeated native restore as an unconditional harmless cleanup operation. The existing [capture-source contract](raw14-capture-source.md) cannot obtain lease validity or retry semantics from this raw firmware pair alone.

## Geometry does not always preserve the described byte count

Seven new cases execute the native configuration setter and the full override, except the zero-limit case, which stops before integer division. The saved channel word is a supplied simple row/height encoding; real sensor packing remains unverified.

For decoded source row bytes W, source row count H and configured limit L, the reviewed helper chooses:

```text
W < L:  line = W, rows = H
W >= L: line = L, rows = floor(W / L) * H
packed = (line | ((rows - 1) << 16)) & 0x7FFFFFFE
```

The encoded word has an even low-half line value and a 15-bit height-minus-one field. The tests check the actual native packed word and then restore the original ten-word snapshot.

- W=3,584, H=1,080, L=3,584 or 4,096 preserves the supplied 3,870,720-byte geometry.
- L=1,792 is an exact divisor: the native result is 1,792 bytes × 2,160 rows, preserving that byte count.
- L=2,048 is not an exact divisor: the result is 2,048 × 1,080 = **2,211,840** bytes. The code has no early rejection for that fixture.
- Odd L=1,793 produces an encoded line of 1,792 and 1,080 rows, reducing the described size further.
- L=0 reaches `0xFE75595E` with native divisor R3 equal to zero. The test stops **before division**, making no assumption about the target CPU's divide-by-zero trap setting or result. Address programming and flag setting have not occurred at that boundary.
- W=3,584, H=32,768 and L=1,792 would require 65,536 rows to preserve size; the final field encodes only 32,768 rows, halving the described byte count.

These are supplied boundary cases, not supported modes or captured payloads. Preserving this arithmetic byte count alone would still not validate row ordering, RAW packing, borders, capacity, alignment or cache handling. Future configuration must establish these properties before using the native helper.

## Reproduction and remaining work

```sh
python scripts/probe_750d_raw_redirection.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-raw-redirection.json) includes the original eight cases and eleven additions: four lifecycle/configuration sequences and seven geometry cases. Exact input size/SHA-256 checks, guarded ARM/Thumb execution and native stack restoration checks apply. No calls are stubbed and no OS success is fabricated. Cortex-A15 executes a compatible scalar subset under Unicorn 2.1.4; it is not a camera peripheral model.

The current outcome is a better-defined candidate and several concrete integration constraints, not an enabled recorder. Actual caller/activation, channel ownership, completion qualification, buffer lifetime, cross-core cache behavior and complete cleanup remain unverified. Camera bindings remain disabled.
