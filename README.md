# Canon 750D RAW video research

Research into adding RAW video recording to Magic Lantern on the Canon EOS 750D / Rebel T6i, running Canon firmware **1.1.0**.

**RAW video recording is not implemented yet.** Development has taken place on a PC only. No experimental code has been installed or run on the project owner's camera.

## Current progress

- The copy-engine IRQ cleanup and notification paths now pass 53 native PC cases, including separately entered status decoding. The return slice maps both status 0 and 8 to zero, and reads a shared status word across channels; live synchronization remains unverified. No DMA completion is simulated. See [copy completion and limits](docs/750d-copy-completion.md).
- The primary copy candidate now builds and links actual descriptors in ten native PC scenarios; nine propagate those same structures into submission preparation, stopping before the controller start store. Register RAM and channel settings are artificial; no DMA transfer or completion is validated. See [copy descriptors and submission](docs/750d-copy-descriptor.md).
- A primary-core copy candidate at `0xFE133EB2` now passes 14 bounded native admission/classification/cache-dispatch checks. Its downstream path prepares source clean and destination clean/invalidate separately from the sensor RAW writer. No DMA copy, live channel availability or camera binding is validated. See [the copy candidate](docs/750d-copy-entry.md).
- Peer startup operand tracing now distinguishes the candidate RAW CPU alias `0x5C62C000` from DMA address `0x1C62C000`, consistent with ML's pointer convention. Thirty CP15-write boundaries are observed without executing them. Primary-core mapping and safe pixel reads remain unverified. See [address aliases and cache scope](docs/750d-raw-alias.md).
- Thirteen native PC sequences now verify counter-restricted RAW selection and propagate its result through actual publisher/configuration code into peer pending-address state. Zero takes the empty start path, which can still invoke a callback. Transport delivery, hardware completion and buffer ownership remain unverified. See [selection and buffer reuse](docs/750d-raw-selection.md).
- Sixteen native PC cases now connect RAW IRQ registration through a scoped peer-kernel page to its actual table, and separately verify dispatch from that natively written table and IRQ-enable bounds. Boot relocation and hardware completion remain unverified. See [IRQ registration and dispatch](docs/750d-irq-registration.md).
- Twelve native PC cases now execute the RAW channel IRQ body, register-write helpers and callback forwarding against artificial register RAM. Four first run native configuration/start, deriving the software flags used by the IRQ branch. Hardware IRQ qualification and completed-frame ownership remain unverified. See [the IRQ body and limits](docs/750d-raw-irq.md).
- Twenty-one native PC checks now verify the driver's ALL-bit start gate, preceding preparation wait and timer enable/cleanup slices. The enabled timer callback can satisfy either wait's bit condition, so neither wait alone proves RAW-DMA completion. See [the gate and limits](docs/750d-start-gate.md).
- Magic Lantern is pinned as a Git submodule at commit `142472e95054d73640f50789ac0fd66325499d82`.
- The upstream core and loader have been compiled and linked on Windows using Arm GNU Toolchain 13.3.Rel1, with `CONFIG_QEMU=y` and module/TCC support.
- A Windows build script and a read-only FIR inspection script are included.
- The official Canon 1.1.0 FIR has now been decrypted privately on the PC using an isolated component from a public 70D ROM. The decoded container checksum and main-code signature match; see [the plaintext milestone](docs/750d-plaintext-milestone.md).
- A public EOS M3 DIGIC 6 ROM now supplies a working PC crypto reference: native AES and CBC wrapper tests pass, but direct application to the 750D FIR fails length bounds. See [the experiment and limits](docs/m3-crypto-reference.md).
- The 7D Mark II frame-copying implementation has been reviewed as a possible reference for a future 750D port.
- The experimental ARM copy/queue/MLV path now writes synthetic clips through a PC filesystem test bridge, including queue overflow and partial-write rollback checks.
- Actual 750D RAW address-selection and parameter-publication code now passes seven bounded PC scenarios. This traces a preparation address; a completed sensor frame is not yet acquired. See [the target route](docs/750d-raw-address-route.md).
- Two actual 750D register-shadow readers now pass 28 synthetic-memory reads and four expected fault cases on the PC. Live-bank selection and RAW DMA completion remain unverified. See [the register shadows and message boundary](docs/750d-register-shadows.md).
- A reviewed RAW preparation branch now reaches candidate DMA destination `0xD0004108` in bounded native PC execution, stopping before the physical store. Four cases also verify callback registration/forwarding; no pixels or hardware events are emulated. See [the destination trace](docs/750d-raw-destination.md).
- Six native geometry cases now trace caller fields into configuration, row-size arithmetic and the DMA descriptor packer, including truncation/underflow cases. Real mode dimensions and pixel packing remain unverified. See [the geometry route](docs/750d-raw-geometry.md).
- Ten native completion scenarios distinguish RAW-component notification from seven-component aggregate completion; two task-request checks verify their separate event numbers. Timing and buffer ownership remain unverified. See [completion events](docs/750d-completion-events.md).
- Native task dispatch now maps aggregate event 6 to return operation 2 and RAW event 7 to operation 6. Ten supplied dispatch cases and four separate receiver checks pass; mode-dependent callback registrations still need a buffer-lifetime contract. See [completion dispatch](docs/750d-completion-dispatch.md).
- The separate RAW return callback now traces to EVF event 19, labeled `evfAfPathCompleteInterrupt`. Nine bounded native checks verify request preparation, handler branching and a small downstream result pool. This qualifies the notification as part of an AF consumer path; a recorder-ready frame and source-buffer lifetime are still unverified. See [the EVF event investigation](docs/750d-evf-raw-event.md).
- The candidate RAW preparation address now traces to ADST reservation slot 2 during EVF activation. Four native supplied-registry scenarios verify reservation, repeat diagnostics, teardown release and reacquisition. This is memory reservation, not a completed-frame lease. See [the RAW reservation route](docs/750d-raw-reservation.md).
- Native manager-to-descriptor propagation now verifies that the reviewed population path sets slot-2 count to one and supplies the RAW preparation pointer. Four scenarios check two address markers and two assertion inputs. Allocation and frame reuse timing remain unverified. See [RAW descriptor population](docs/750d-raw-population.md).
- The original manager address now traces to resource 22. Seven native cases verify pool-base alignment/publication and actual provider selection; reviewed configuration modes 1/2 compute a pool-relative address and report a 30,791,680-byte resource. Live configuration, image format and frame ownership remain unverified. See [the resource lookup](docs/750d-raw-resource.md).
- Five native boundary checks now trace the manager's asynchronous pool request and registered callback. The callback requires at least 90 MiB; this is not a measurement or guarantee of the actual pool capacity. OS allocation/delivery and frame timing remain unverified. See [the pool request](docs/750d-pool-request.md).
- A reviewed receiver branch now supplies firmware pool constants. Two native cases propagate them through six setup stages to candidate RAW preparation address `0x5C62C000`, with resource containment checked. Live branch activation and a completed-frame lease remain unverified; no platform binding is enabled. See [constant-pool provenance](docs/750d-pool-provenance.md).
- Native RAW start preparation now reaches both control/start store boundaries, stopping before MMIO, and a separate check verifies pending-address consumption. The actual EVF state-5/input-5 table entry names the readout-done handler used by the donor synchronization pattern; timing and copy safety remain unverified. See [RAW start and donor synchronization](docs/750d-raw-start.md).
- Readout-done tracing now verifies registered-method dispatch order and ten separate internal-phase fixtures. The handler invokes additional methods before returning, so its post-transition hook still needs a buffer-lifetime contract. See [readout completion](docs/750d-readout-done.md).
- Four native cases now execute real method rows 3/9. With a supplied active-driver flag, completion processing prepares `StartDriver` operation 2 before returning, stopping at transport entry. A post-transition copy interval therefore remains unproven. See [real readout methods](docs/750d-readout-methods.md).

Full-camera QEMU emulation has not been run. The separate experimental components execute under Unicorn ARM emulation. Camera modules and an installation ZIP have not been built. These tests do not validate RAW capture or operation on physical hardware.

## Getting the source

```sh
git clone --recurse-submodules https://github.com/Hetfielddd/750d-ml-raw-video.git
cd 750d-ml-raw-video
```

For an existing clone:

```sh
git submodule update --init
```

The `magiclantern` directory points to an exact upstream revision. Camera source code has not been modified. Future camera changes should be committed to a project-owned fork, followed by an update to this submodule reference.

## Documentation

- [Research status and remaining work](docs/status.md)
- [Windows build instructions](docs/build-windows.md)
- [Information needed from developers](docs/developer-request.md)
- [Read-only ROM inspection and November research refresh](docs/rom-analysis.md)
- [Read-only Thumb address-load candidate search](docs/thumb-xrefs.md)
- [Public M3 DIGIC 6 ROM and bounded native crypto experiment](docs/m3-crypto-reference.md)
- [750D plaintext recovery and first target-specific RAW function test](docs/750d-plaintext-milestone.md)
- [750D RAW address selection and parameter publication on the PC](docs/750d-raw-address-route.md)
- [750D register-shadow readers and the writer's message boundary](docs/750d-register-shadows.md)
- [750D candidate RAW DMA destination and channel callback route](docs/750d-raw-destination.md)
- [750D RAW geometry fields, row-size arithmetic and DMA packing](docs/750d-raw-geometry.md)
- [750D RAW-component versus aggregate completion notifications](docs/750d-completion-events.md)
- [How related cameras reached RAW video and the 750D port strategy](docs/similar-camera-raw.md)
- [Experimental C frame-copy component and ARM execution tests](docs/raw14-copy-core.md)
- [Experimental frame queue and writer ownership](docs/raw14-queue.md)
- [Experimental MLV writer and end-to-end verification](docs/raw14-mlv-writer.md)
- [ARM recording to PC files and Canon FIO integration findings](docs/raw14-disk-bridge.md)
- [FIO contract adapter and recording without truncation](docs/raw14-fio-adapter.md)
- [Completed-frame source ownership and donor callback analysis](docs/raw14-capture-source.md)
- `scripts/inspect_750d_fir.py`: read-only structural inspection of a locally supplied Canon update file.

## License and attribution

Magic Lantern is a separate upstream project. Its license notices and contributor attribution are retained in the submodule. Original project scripts are distributed under GPL-2.0-or-later; see [COPYING](COPYING).

Research, documentation, and original scripts were prepared with assistance from OpenAI Codex. No independent hardware validation has been performed.

Canon firmware, ROM dumps, downloaded toolchains, and project build outputs are not included. The upstream submodule retains its original tree, including upstream's historical binary resources.
