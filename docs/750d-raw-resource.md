# Resource 22 supplies the original RAW preparation resource

The [descriptor-population investigation](750d-raw-population.md) traced manager fields into ADST slot 2. This step identifies the code that fills the original manager address field. It is a resource-subregion lookup, not an observed allocation on the camera.

## Manager request

In the reviewed manager initialization path, source `0xFE11F4E4` checks manager offset `0x710`. If nonzero, this slice skips the request. Otherwise the call at `0xFE11F4F4` invokes `0xFE41C4F2` with:

```text
R0 = manager + 0x710   (address output)
R1 = manager + 0x714   (size output)
R2 = 1                (requested count)
R3 = 22               (resource identifier)
```

The resource wrapper reads configuration through RAM word `0x27B80`. A missing configuration reaches an assertion. The actual expected-count table at `0xFEA1DA04` stores 1 for resource 22. A request for count 2 reaches a diagnostic boundary before the provider is called.

## Reviewed provider modes

### Pool-base publication

The earlier manager caller at `0xFE11F45C` passes its raw pool-input field at offset `0x70C` to source helper `0xFE41BE74`. That helper checks for non-null configuration and input, calls native alignment helper `0xFE41F730` with alignment `0x4000` (16 KiB), writes the aligned address to the caller's output, and publishes it at configuration offset 44. The original manager input field is retained. The alignment helper executes its actual `UDIV` instruction in the PC experiment; no arithmetic replacement is injected.

For supplied input `0x20000123`, the published base is `0x20004000`; the subsequent resource-22 lookup produces address `0x23E00000`. Zero input reaches the setup assertion. No physical RAM allocation or cache operation is performed by these slices. The experiment stops before setup logging, then starts a separate resource-lookup stage with a fresh supplied caller frame; it does not fake a logger return.

Static review finds direct calls selecting mode 2 at `0xFE120B7A..0xFE120B80` and mode 1 at `0xFE120FF4..0xFE120FFA`, both using mode-change function `0xFE41BF04`. That function stores the requested mode and class-method table after mode-specific work. These calls corroborate the presence of both configurations; their surrounding startup/teardown, synchronization and live selection have not been executed or measured.

### Resource lookup

For configuration word zero equal to **1 or 2**, the native classifier `0xFE41C49C` assigns resource 22 to class 2. The actual class table at `0xFEA1E864` supplies callback `0xFE41D883`, source body `0xFE41D882`.

That callback uses configuration offset 44 as a pool base. Its native resource-22 branch computes:

```text
address = pool_base + 0x03DFC000
reported resource size = 0x01D5D800 = 30,791,680 bytes
```

The branch is reached through the actual Thumb table branch for resource index `22 - 8`, then `0xFE41DA1A -> 0xFE41DB2E`. It stores address and size into the supplied manager fields and increments the configuration counter at offset 984. The counter also wraps at 32 bits in the tested fixture.

The reported size belongs to this resource subregion. It does not determine pixel dimensions, sensor bit depth, frame size, or how many usable recording buffers exist. Neither the live configuration mode nor the live pool base has been measured. Other wrapper configuration modes use a different callback route and remain untested.

Combining this with the previously checked stages gives the reviewed provenance:

```text
supplied resource pool base + fixed offset
    -> manager + 0x710, size at +0x714
    -> manager + 0x748
    -> ADST slot 2 (one address)
    -> RAW preparation word 0x26BEC
```

These stages have bounded native evidence; the complete allocation/startup/transfer chain has not been executed continuously.

## PC experiment

```sh
python scripts/probe_750d_raw_resource.py /private/750d-analysis/record-06.bin
```

Seven cases pass: aligned and unaligned mode-1 pool inputs, mode 2 with another input and counter overflow, a zero pool input, an existing manager address that skips the request, missing configuration, and an incorrect requested count. The valid lookup cases first execute native pool setup to its logging boundary, then separately execute the manager request, native resource wrapper/classifier, actual callback table selection and provider through return to the caller. They stop before the subsequent task notification. Failure cases stop before diagnostics/assertions execute. No native call is stubbed or forced to return success.

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Gates precede the Unicorn import. Cortex-A15 executes the compatible instruction subset, including native Thumb `UDIV`, not a Cortex-R4 camera-system model. The earlier Cortex-A9 setting rejected that instruction, so this extended probe now uses A15; other probes are unchanged. Code is read/execute and supplied state is read/write without execute permission. Guards permit only reviewed ranges and writes to the published pool base, address/size outputs, provider counter and stack. Setup is limited to 96 instructions / 0.5 seconds, lookup to 192 instructions / 0.5 seconds. The pool and returned addresses are never mapped as pixel memory. [Machine-readable evidence](evidence/750d-raw-resource.json).

The next missing links are configuration/pool setup and the per-frame destination reuse or redirection contract. The camera provider remains disabled; actual sensor pixels, cache coherence, frame timing and recording throughput remain unverified.
