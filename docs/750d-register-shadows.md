# 750D register-shadow readers identified and executed on the PC

The actual 750D 1.1.0 main-code record contains two implementations of a register-shadow reader. Both have now executed with synthetic RAM. This supplies target-specific candidates for a dependency used by the 7D Mark II RAW backend; it does not yet supply live RAW geometry or a completed sensor frame.

Input: record 6, mapped at `0xFE0A0000`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. No Canon firmware bytes or disassembly are distributed here.

## Two distinct banks

The primary reader is at `0xFE40A6D8`. It loads the bank pointer from RAM word `0x28F10`, masks its argument to 19 bits, and reads the word at that bank-relative offset. Its pointer setter is `0xFE40A6A4`; the shadow-only word writer is `0xFE40A74E`. Adjacent writer `0xFE40A6AA` updates both the shadow and the physical register. The experiment never invokes that physical writer.

The second reader is at `0xFE753834`, with its bank pointer at RAM word `0x1AC40A4`. Its pointer setter is `0xFE753800`, its shadow-only writer is `0xFE7538AA`, and its adjacent physical-plus-shadow writer is `0xFE753806`. The layout resembles the donor's code associated with Omar. Its relocation and accessibility from the primary core have not been established; it is labeled a secondary-bank candidate, not an enabled Omar binding.

Both readers implement:

```c
value = *(uint32_t *)(bank_pointer + (register_address & 0x7ffff));
```

The reader does not read the physical register and cannot refresh the shadow by itself. A value of zero is also a legitimate result, so a zero-return placeholder cannot be distinguished from a real zero using the value alone.

The two bank pointers are different globals. A matching function body is insufficient evidence that their contents are interchangeable. The primary initializer at `0xFE40A698` stores its incoming base and invokes a clearing routine with length `0x60000`. The corresponding second initializer is at `0xFE7537F4`. Reviewed primary call sites include `0xFE0D480A` and `0xFE0F43B6`. These identify setup dependencies without establishing the actual allocated addresses or their cross-core sharing contract.

The 19-bit mask can address more than the `0x60000` initialization length. Neither native reader performs a null check or a bounds check. Arbitrary register arguments must not be treated as safe.

## Bounded native experiment

```sh
python scripts/probe_750d_shadow_read.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and the exact identified record. The script rejects a wrong length or SHA-256 before importing Unicorn. It executes the original pointer setters, shadow-only writers and readers without stubbing native calls. Each invocation has a 32-instruction and 0.5-second limit, an instruction-range guard, and a memory-access guard checking addresses, sizes and access order.

The code and return sentinel are read/execute; only the explicit pointer globals and synthetic shadow banks are read/write. No MMIO, sensor or pixel memory is mapped. The synthetic banks have the reviewed initialization size, rather than silently extending them to the full mask range. Unicorn's Cortex-A9 model executes the compatible Thumb subset, as in the preceding native target probes; this is not a Cortex-R4 system emulation.

For each bank, seven offsets are written with distinct test words using the native shadow-only writer. Each is read through two argument aliases differing in bit 19. All **28 reads** return the expected values from synthetic RAM. Offsets `0x4208`, `0x4210` and `0x4214` are test inputs motivated by the donor; their successful lookup is **not evidence that channel `0xD0004200` captures RAW on 750D**.

Four negative executions also behave as expected: each reader faults with an unmapped bank pointer or an offset at the first word beyond the initialized test-bank size. These are emulator faults, not native validation errors. The script does not fill missing memory or replace failed reads with success. [Machine-readable result](evidence/750d-register-shadows.json).

## The writer route crosses a message boundary

Further static tracing of [the RAW preparation route](750d-raw-address-route.md) finds that the reviewed mode-3 configuration method copies its input field at offset 80 into driver-parameter offset 200, then sends the parameter block through `0xFE3807A0`. The latter sends operation 4 for service identifier `0x20002`. The readout descriptor path uses `0xFE380766`, operation 2 for the same service.

The wrapper at `0xFE443016` passes these to the Postman implementation at `0xFE48D25C`: transport argument 4, destination identifier 2, operation word `0x200 | operation`, and the original parameter pointer. The reviewed sender adds the destination in bits 24..31 and writes two words, command then payload, to the same mailbox register `0xD2000104`. For operations 2 and 4 the command words are respectively `0x02000202` and `0x02000204`.

An additional native experiment verifies all six command wrappers (operations 0..5), the service wrapper, and a separate sender-packing slice: **12 cases** cover initial sender counters 0 and 255, including byte wraparound. It stops before the first mailbox store. No native calls are stubbed: semaphore and interrupt setup are skipped by entering the later slice with supplied registers. The payload remains an unmapped marker. This verifies command preparation, not transport success or peer delivery. Instruction and write guards plus 64-instruction / 0.5-second limits bound each stage.

```sh
python scripts/probe_750d_path_messages.py /private/750d-analysis/record-06.bin
```

[Machine-readable command-preparation result](evidence/750d-path-messages.json). The register-store ordering remains a static finding; the experiment does not execute those stores.

The local receive callbacks at `0xFE3807BA` and `0xFE3807D0` invoke registered function pointers; `0xFE3807C8` signals the local semaphore. Their table is reached through `0xFE3806FE`. In particular, a returned sender call or a semaphore release cannot yet be labeled RAW DMA completion. The peer's receiving path, actual image writer and buffer lifetime remain to be traced.

## Relation to the 7D2 implementation and remaining work

The pinned 7D2 platform uses `shamem_read` to obtain the RAW channel's destination and geometry; its comments explicitly question calling Omar-associated code from the primary core. The same distinction matters here. We now have two target-specific readers with verified instruction behavior, rather than only a zero-return placeholder, but no verified live-bank choice.

Before using either as the 750D platform's `shamem_read`, establish live initialization, address visibility and cache attributes, which writer updates the relevant shadow, whether those values reflect the active RAW channel, and when a captured region is complete and stable. The current camera provider remains disabled. No physical-camera test, real RAW frame or recording is claimed.
