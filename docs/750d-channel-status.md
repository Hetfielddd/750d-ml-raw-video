# Native status polling on the 750D RAW channel's register block

A separate Canon IPC receive routine, identified by the `mossy_fast_dma_RX` diagnostic, polls the same physical register block `0xD0004100` as the peer RAW writer. Its two receive phases proceed when the entire word at `0xD0004130` equals `2`. They sample the address at `0xD0004108` for logging on the waiting branch. This establishes a status convention for the reviewed IPC routine and gives RAW investigation a concrete comparison on the same register block.

## Receive configuration and status check

The first phase prepares a four-byte receive using `0xFE218426`. The status loop starts at `0xFE2185C2`. On its success branch, the routine writes command value 4, computes the number of 4,096-byte rows needed for the supplied payload, and reuses the receive setup. The second status loop starts at `0xFE218620`. Its success path likewise writes command value 4. Both loops read the hardware-location status word and compare it for equality to 2.

With supplied values 0, 4, 6 and `0x102`, each loop reads the address word and reaches a logger and retry delay. With supplied status 2, both loops reach the success branch without reading the address. Both an unchanged address and an address at the end of the longer test configuration are accepted with status 2 in passive RAM. That checks the software predicate without assuming how the hardware sets these values.

Two native configuration fixtures use payload sizes 4,096 and 4,097. They program one and two rows respectively, at the same `0xD0004100` register block. The setup writes the supplied destination to `0xD0004108`, writes control `0x40000003`, encodes `(rows - 1) << 16 | 4096` at `0xD0004110`, and writes `0x33` to `0xD0005004`. Those control and route values describe the IPC configuration. Active-time contention between the IPC routine and Live View has not been demonstrated.

## Canon address diagnostics and comparison with Magic Lantern

Two native command-registration slices identify `ipcRecvDump` and `ipcSendDump`. The respective handlers load status followed by address from the receive block at `0xD0004100` and the send block at `0xD0030900`. The dump checks stop before logging. The address is passed as a raw word in both cases, without subtracting the programmed base or comparing it with an expected end.

The upstream Magic Lantern EDMAC diagnostic compares the physical address with the expected end of a transfer. Its `edmac_get_pointer()` reads the hardware register while `edmac_get_address()` reads the shadow of the programmed address. Canon's diagnostic confirms that the physical address word is readable on the 750D's same register block in a separate firmware path. RAW mode's cursor behavior, wrap and end-address convention still require evidence. [Magic Lantern EDMAC diagnostic](https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/modules/dev_tools/edmac/edmac_test.c#L109) · [Address helpers](https://github.com/reticulatedpines/magiclantern_simplified/blob/142472e95054d73640f50789ac0fd66325499d82/src/edmac.c#L185).

The peer RAW IRQ tests still permit notification with supplied status 0 or 4. The primary IPC receive gate establishes the exact comparison used by one mode. Before a RAW recorder relies on `status == 2` or an end address, the channel configuration and the behavior of the physical status and address registers must be established in the Live View mode being recorded. [Peer IRQ comparison](750d-raw-notification.md#peer-irq-vector-through-native-exception-return).

## Reproduction

```sh
python scripts/probe_750d_channel_status.py /private/750d-analysis/record-06.bin
```

The probe checks the main-record identity before importing Unicorn 2.1.4. It runs two command/dump checks, twelve poll checks and two receive configurations. Execution and memory guards limit each native slice to 96 instructions and 0.5 seconds. The register locations are passive RAM. Logging, delay and registration boundaries are explicit, and there is no sensor, DMA engine or peripheral status transition in the experiment. Camera bindings remain disabled. [Machine-readable results](evidence/750d-channel-status.json).
