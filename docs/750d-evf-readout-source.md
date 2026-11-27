# Canon 750D Live View readout event source

On firmware 1.1.0, Canon registers the producer of EVF event 5 with the `HEAD2` HD interrupt. The registration programs a line threshold. The callback subsequently posts a four-word message containing the EVF context, event number 5 and two zero words. The native task selects `evfReadOutDoneInterrupt` in states 3 through 6. The tested path gives the recorder a readout timing reference and leaves RAW channel completion and destination ownership to be verified separately.

## Registration and line interrupt

Three EVF call sites at `0xFE2B9832`, `0xFE2B9E00` and `0xFE2B9F3C` pass the callback at `0xFE2B8336` and the EVF context to `0xFE30A32A`. The latter checks the driver object's signature, reads a mode-dependent halfword via `0xFE2D0528` and requires a nonzero value on the tested registration path. It raises values below 524 to 524 before calling `RegisterHDInterruptCBR` at `0xFE2D0214`. The three scenarios supply 523, 524 and 900 respectively. The values written are 524, 524 and 900. These inputs cover the arithmetic and are separate from live camera mode measurements.

The first free callback slot leads to `0xFE2A1848`. It prepares the native IRQ registration request with the name `HEAD2`, interrupt index `0x20`, handler `0xFE2A182D` and zero argument. Its continuation publishes the callback and context at `0x30AF8` and `0x30B18`. It also puts the threshold's low 14 bits into the `HEAD2` register list. The primary boot copy at `0xFE0A00DA` derives that list at `0x30F54` from corresponding firmware data at `0xFED9223C`.

The native register-list writer places the threshold at `0xD0007064`, 4 at `0xD000705C` and 12 at `0xD0007060`. The PC probe copies the initialization lists from the main record and observes these stores against passive memory. Entering the `HEAD2` handler explicitly exercises its acknowledgment store of 4 to `0xD000705C` and its call through the registered callback. A null-callback control acknowledges and returns. Physical interrupt delivery and register behavior remain unverified.

## Message and task dispatch

The producer at `0xFE2B8336` calls a helper before preparing the event. Its reviewed continuation uses the task installed by the native EVF constructor and requests event 5. The primary low-kernel task constructor uses a 24-byte object with the EVF worker at offset 20. The native producer and low-kernel message wrapper, reached through the ARM veneer at `0xFE3CE01C`, write this envelope:

```text
[EVF context, 5, 0, 0]
```

The probe supplies that same envelope at the receive output slot, executes native extraction and runs the actual task loop, EVF worker and state dispatcher. All ten cases retain their old state:

- States 3 through 6 enter `evfReadOutDoneInterrupt` at `0xFE2B9536`. A post-logger slice sets context offset 56 to one.
- States 2, 7 and 8 enter `evfIgnore` at `0xFE2BA912`.
- States 0, 1 and 9 have no handler and return zero to the EVF worker.

The message carries neither a RAW destination nor a frame identifier. The checked `HEAD2` registration and dispatch slices access the head timing registers and the EVF task data. No RAW DMA status register is mapped during the probe.

## Effect on the recorder design

The [7D Mark II and DIGIC 7 implementations](similar-camera-raw.md) use old state 5 and input 5, call Canon's state transition, then redirect the upcoming buffer and process the previous buffer. The 750D has the same state/input pair. Its tested method rows can prepare the next `StartDriver` **inside** the state transition, and the HD interrupt supplies timing without a buffer identifier. A 750D adapter needs a qualified RAW DMA completion and its destination, with an observed reuse interval and a cache contract. The `StartDriver` submission boundary offers a specific point to test that ordering. [Actual 750D readout methods](750d-readout-methods.md).

The separately analyzed CCD channel-2 path enters `ShootCapture` still-image state handling. It has its own event-7 worker and remains useful as a comparison for registration and completion routing. [SCSState ownership](750d-scs-event.md).

## Reproduction

```sh
python scripts/probe_750d_evf_readout_source.py /private/750d-analysis/record-06.bin
```

Three registration cases, callback-present and callback-absent checks, and ten state-dispatch cases pass. The script requires Unicorn 2.1.4 and verifies the identified main record before importing it. Code and supplied writable memory are mapped separately. Each slice is limited to 192 instructions and 0.5 seconds, with checked execution and write ranges.

The probe uses bounded native execution with explicit cuts for allocation, hardware IRQ setup, logging, the callback's pre-post helper, mailbox transport, free and scheduling. It observes actual message construction and dispatch on either side of the delivery cut. No physical sensor readout, DMA transfer, RAW pixels or camera binding is exercised. [Machine-readable evidence](evidence/750d-evf-readout-source.json).
