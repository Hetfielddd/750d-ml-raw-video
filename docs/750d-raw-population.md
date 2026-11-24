# Manager resource to ADST slot 2 to RAW preparation

The [reservation investigation](750d-raw-reservation.md) found that EVF activation reserves slot 2 and publishes descriptor word zero at `0x26BEC`. The descriptor population path is now identified and checked with native code on the PC.

## Actual field route

In the reviewed resource-selection branch, source `0xFE11FA2E` reads manager offset **1808 / 0x710**. Values zero and one lead to the existing assertion boundary. The continuation at `0xFE11FA48` copies that word into manager offset **1864 / 0x748**. Adjacent logging identifies the branch as `GMT_RESOURCE_CONDITION_MEM_MEM1`; the broader function dispatches on resource selector 8 before this branch. The experiment enters after that surrounding selection and does not establish the camera's active resource configuration.

Source function `0xFE120428` obtains the ADST table through `0xFE2053F6` using owner token `0xFDFD`. At `0xFE1204C8..0xFE1204E8`, it sets slot-2 count (table + 252) to **1** and copies manager offset 1864 into descriptor word zero (table + 40).

EVF activation's previously reviewed native call then reserves slot 2, marks its state 2 and publishes that descriptor word at `0x26BEC`, with returned count 1 at `0x26BF8`:

```text
supplied manager + 0x710
    -> manager + 0x748
    -> ADST table + 40, count at table + 252 = 1
    -> EVF RAW preparation word 0x26BEC
```

The count of one is established by this descriptor-population code, rather than inferred from the earlier synthetic counts. It does not establish the size of the image buffer, the format of its contents, or a safe interval for copying a completed frame. The original allocation and manager + 0x710 writer remain to be traced.

## Native checks

```sh
python scripts/probe_750d_raw_population.py /private/750d-analysis/record-06.bin
```

Two distinct supplied address markers pass through native resource publication, the native table-access helper and population prefix, then native reservation/publication. Sentinel descriptor/count values are replaced by the supplied address and count one. Markers zero and one reach the resource branch's assertion boundary before publication. Neither diagnostic nor assertion is forced to succeed.

The population function also visits unrelated earlier resources. Their input counts are supplied as zero; execution stops at `0xFE1204E8`, before later slot population and its external helper calls. The table's available state is supplied, not obtained by running global initialization. These are separate native stages with explicit incoming registers, not execution of the entire allocation/EVF startup sequence.

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Input is gated before importing Unicorn. Cortex-A9 executes the compatible instruction subset, not a Cortex-R4 camera-system model. Code is read/execute; supplied state is read/write without execute permission. Code/write guards permit only the reviewed ranges, expected destination words, reservation halfword and stack. Each stage is limited to 128 instructions and 0.5 seconds. No native calls are stubbed; no pointer marker is mapped as image memory. [Machine-readable evidence](evidence/750d-raw-population.json).

Four native scenarios pass. This extends the candidate address's provenance by two real field transfers. Actual allocation, live geometry, pixels, DMA completion, cache coherence, destination reuse timing and a stable frame lease remain unverified. The camera provider stays disabled.
