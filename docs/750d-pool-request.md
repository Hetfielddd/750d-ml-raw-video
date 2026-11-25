# Asynchronous request and callback for the manager pool

The [resource investigation](750d-raw-resource.md) established pool-base publication and the resource-22 subregion. This step follows the manager's asynchronous request and its registered callback, with separate bounded native PC checks. It does not allocate the actual image pool or deliver an OS task message.

## Request preparation

At source `0xFE11F4B8`, the manager supplies `0x05A00000` (94,371,840 bytes / 90 MiB), callback pointer `0xFE11F435`, and its own context to function `0xFE3F9356`. The callback literal is at `0xFE11F77C`; its source body is `0xFE11F434`.

The request function first allocates a **48-byte service object** through veneer `0xFE3CE0E4`. This is message storage, not the image pool. One native check follows the real caller into this function and stops before that allocation, verifying the captured minimum, callback and manager context.

Static review of the later prefix shows a service availability query at `0xFE432E82`, with arguments `0x71` and `0xFFFFFFFF`. Its return is compared with the requested minimum; insufficient availability reaches an assertion. Allocation, this query and the clearing helper are not executed by the experiment.

A separate native stage enters after the object's clear operation with supplied zeroed storage. It prepares the actual reviewed fields:

- Object + 8: request code **37**.
- Object + 28: callback `0xFE11F435`.
- Object + 32: manager context.
- Object + 40: marker `0xB2` (178).

It follows native helper `0xFE3F6308` until task-posting veneer `0xFE3CE01C`, verifying task handle, context, operation zero, object pointer and fifth argument 48. The service context referenced by RAM word `0x4BE0` is represented by supplied structures; no task message is actually posted or serviced.

The requested minimum is used by the reviewed availability check, but is not serialized into these prepared fields. This evidence does not establish an allocation of exactly 90 MiB. The service receiver and its pool-selection policy remain to be traced.

## Registered callback

The actual callback `0xFE11F434` receives manager context in R0, returned pool base in R1 and returned size in R2. It checks size against `0x05A00000`. Native fixtures verify:

- Exactly 90 MiB: the supplied base is stored at manager + `0x70C`.
- 96 MiB: the supplied base is also stored.
- 90 MiB minus one byte: execution reaches the assertion before publishing the base.

The callback then logs and continues into the previously checked [pool alignment/publication route](750d-raw-resource.md#pool-base-publication). The experiment stops before logging. It does not execute callback delivery or infer the actual returned size from these fixtures.

The minimum-size check alone is not proof that every configured subregion lies within the live pool. That requires the actual returned capacity and active resource layout. No camera binding is enabled by this callback analysis.

## Reproduce and scope

```sh
python scripts/probe_750d_pool_request.py /private/750d-analysis/record-06.bin
```

Five native scenarios pass. [Machine-readable evidence](evidence/750d-pool-request.json).

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Input gates precede Unicorn import. Cortex-A9 executes the compatible instruction subset, not a Cortex-R4 camera system. Code is read/execute; supplied storage/context/stack/global pages are read/write without execute permission. Code/write guards restrict the native slices and permit only message, pool-input output and stack writes. Each case is limited to 64 instructions / 0.5 seconds.

No native call is stubbed into success. The request prefix, post-clear object preparation and callback are independent stages with supplied inputs. The allocator, availability query, object clear, task delivery, physical pool and sensor transfers remain unexecuted. Cache coherence, live buffer capacity, per-frame reuse timing and a completed-frame lease remain unverified.
