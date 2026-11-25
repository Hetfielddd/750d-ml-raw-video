# Constant-pool branch yields a concrete RAW preparation candidate

The [asynchronous request investigation](750d-pool-request.md) identified message code 37 and its callback. The receiver-side branch now supplies concrete pool constants, allowing bounded native execution to propagate a firmware-derived address through the previously reviewed setup stages.

**Candidate RAW preparation address: `0x5C62C000`.** This is conditional on the reviewed service branch and supplied configuration. It is not a verified live frame pointer and must not be enabled as a platform binding.

## Receiver route and native constants

Service setup at source `0xFE3F68C6` creates its state object through `0xFE104B32`. That constructor supplies table `0xFEA1D308`, 40 event rows and two states. Both entries of task event zero select handler `0xFE42AEAA`.

The handler reads the supplied service context's offset 368 and dispatches through the actual table at `0xFEA3B3B0`. Indices 0, 2, 3, 4 and 5 point to source `0xFE42E928`. Indices 1, 6 and 7 select different functions and are not covered by this experiment. This service dispatch index is separate from the resource-provider configuration mode used later.

The common function reads message + 8. For message code **37**, its actual Thumb table branch reaches `0xFE42EB32`. The code loads:

```text
callback pool base: 0x58830000   (literal at 0xFE42ED74)
callback pool size: 0x06B48000   (literal at 0xFE42ED70)
```

It loads the registered callback and manager context from message + 28/+32 and calls the actual manager callback `0xFE11F434` with those values. The native experiment observes the callback arguments before its body executes; the pool address and size are not supplied by the host fixture.

The OS queue and state-transition dispatcher remain unexecuted. The constructor/table links above are static evidence; execution starts at their selected handler with supplied service context and message.

## Native propagation through six stages

Two cases, service dispatch indices 0 and 2, execute these native stages:

1. Receiver dispatch, message-code selection and actual manager callback up to logging. Manager + `0x70C` receives `0x58830000`.
2. Pool alignment/publication. This already aligned base becomes resource configuration + 44.
3. Resource-22 lookup with supplied provider mode **2**. Manager + `0x710` receives `0x58830000 + 0x03DFC000 = 0x5C62C000`; size at +`0x714` is `0x01D5D800` (30,791,680 bytes).
4. Resource publication from manager +`0x710` to +`0x748`.
5. ADST slot-2 descriptor population, fixing its count at one.
6. Native slot-2 reservation and publication at EVF RAW preparation word `0x26BEC`, which receives `0x5C62C000`.

The host also checks that this resource interval lies within the pool interval reported by the selected callback. This is arithmetic containment for the reviewed branch, not a proof of accessible physical memory or live ownership.

Fresh supplied stack frames separate the stages. Logging is stopped before execution, and pending frames are discarded rather than forcing native returns. Other resource counts are supplied as zero, and the ADST registry's available state is supplied. This is not uninterrupted execution of boot, allocation, task delivery and capture.

## Reproduce and limits

```sh
python scripts/probe_750d_pool_provenance.py /private/750d-analysis/record-06.bin
```

Two native provenance cases pass. [Machine-readable evidence](evidence/750d-pool-provenance.json).

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Gates precede Unicorn import. Cortex-A15 executes the compatible instruction subset, including native alignment `UDIV`, not a Cortex-R4 camera system. Code is read/execute; explicit supplied global/context/stack pages are read/write without execute permission. Guards restrict execution and writes; each stage is limited to 192 instructions / 0.5 seconds. No native calls are stubbed. Neither pool nor image addresses are mapped or dereferenced as image memory.

This is stronger pointer provenance than the earlier arbitrary address markers. It still depends on supplied service dispatch and resource configuration. Live branch activation, valid frame contents, geometry/packing, cache coherence, destination reuse timing and recording throughput remain unverified. No camera provider or RAW recorder hook is enabled. The next capture work must establish frame completion/reuse or safe redirection, rather than treating this address as a completed-frame lease.
