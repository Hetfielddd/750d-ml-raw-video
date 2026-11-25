# RAW address aliases and the two cores' cache attributes

The reviewed RAW preparation candidate `0x5C62C000` and DMA destination `0x1C62C000` are related by the address transformation already observed in the [native destination trace](750d-raw-destination.md). The new result is that the peer startup code also prepares distinct MPU attributes for these two address ranges. This supports examining an uncached CPU alias, but it does not establish safe pixel reads on the primary core.

## Address transformations already in the project

The pinned [Magic Lantern pointer macros](https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/src/mem_defs.h) use bit `0x40000000` for non-VxWorks cacheable/uncacheable RAM pointers. For this candidate, `CACHEABLE(0x5C62C000)` is `0x1C62C000`, and `UNCACHEABLE(0x1C62C000)` is `0x5C62C000`.

The actual reviewed 750D DMA address setter clears bits 30 and 31 for the supplied normal-channel classification, so its destination register receives `0x1C62C000` from input `0x5C62C000`. The pointer macros and DMA transformation have different scopes: neither proves that the primary CPU can read completed pixels from either address. The new probe does not dereference these candidates or model physical aliasing.

## Peer startup MPU operands

The peer-kernel ARM sequence `0xFE744E10`–`0xFE744EF0` prepares seven MPU regions. A new probe executes the scalar instructions between each CP15 write and stops before each write. It observes all 28 write operands without executing the writes, enabling the MPU, or simulating cache behavior.

For the two candidate addresses, the highest matching prepared regions are:

- `0x1C62C000`: region 0, base zero, size 4 GiB, access word `0x121`.
- `0x5C62C000`: region 1, base `0x40000000`, size 1 GiB, access word `0x12C`.

The other five prepared regions cover the peer communication, device and upper address ranges; none overlaps these two candidates with a higher priority. All seven observed size/enable values have no disabled subregions.

Using the [ARM Cortex-R4 TRM](https://documentation-service.arm.com/static/5e8e1efa88295d1e18d36cd8), sections 4.3.20, 7.3 and 8.7: `0x121` decodes to TEX 4, S/C/B = 0/0/1; `0x12C` to TEX 5, S/C/B = 1/0/0. Under that encoding, the latter has an inner non-cacheable policy and is shareable. The TRM permits only Normal non-shared memory in the local cache RAMs. Outer attributes and the camera's interconnect still require system-specific evidence; this is not a claim of globally coherent memory.

These are **prepared peer-startup operands**, not a measurement of live MPU state. Later changes, the complete peer boot sequence and actual processor implementation remain outside the experiment.

## Why the primary CPU remains a separate requirement

The main firmware entry at `0xFE0A003A` prepares region index 1; at `0xFE0A0042` it prepares access word **`0x121`**. Two additional native scalar slices observe these operands before their CP15 writes. This nearby primary startup code does not set that region's base/size, so its covered addresses cannot be inferred from the peer's region-number assignment.

Consequently, applying the peer's region-1 attributes directly to primary-core reads would be unsupported. The correct primary MPU base/size and any later changes still need tracing or eventual measurement. The pinned ML alias convention is useful evidence for a candidate reader address, not permission to bypass the recorder's unverified-source gate.

## Reproduction and limits

```sh
python scripts/probe_750d_raw_alias.py /private/750d-analysis/record-06.bin
```

[Evidence](evidence/750d-raw-alias.json) records seven peer region preparations, two address classifications and 30 observed CP15-write boundaries including the two primary operands. These are observations, not 30 independent hardware tests. Exact main-record size and SHA-256 are checked before importing Unicorn 2.1.4. Cortex-A9 executes compatible ARM/Thumb scalar instructions, not a Cortex-R4 MPU/cache model.

The firmware is read/execute; the probe maps no writable data, pixel buffers or MMIO. All native memory writes are rejected. At each CP15 boundary it reads the prepared CPU operand and explicitly enters the next scalar slice without executing the MCR. Those scalar slices do not read back MPU effects. No native function is stubbed, no cache or CP15 write is forced to succeed, and each stage is bounded to 16 instructions / 0.5 seconds (four instructions for primary slices).

The [next investigation](750d-copy-entry.md) identifies a primary copy candidate and its runtime memory classifier/cache-dispatch route without inventing live MPU values. Remaining requirements are primary-core memory attributes, completed-transfer synchronization, absence of conflicting writes and buffer lifetime during copying. No pixel data, RAW recording or camera binding is enabled by this result.
