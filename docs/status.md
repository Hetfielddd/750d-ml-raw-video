# Research status

Last updated: November 25, 2026.

Target: Canon EOS 750D / Rebel T6i, Canon firmware 1.1.0.
Scope: PC-only research. The owner's camera and SD card have not been used.

## Completed

- Executed the RAW channel IRQ body and actual write helpers through application callback forwarding in eight supplied status/flag cases. Identified the separate secondary software array entry and verified control/start writes in artificial register RAM. All cases reach the driver callback, including zero status; controller delivery and the hardware meaning of this IRQ remain unverified. See [the RAW IRQ experiment](750d-raw-irq.md).

- Verified the driver's ALL-bit start gate, preceding preparation wait and timer enable/cleanup slices. Event-2 table/veneers establish preparation before start. Twenty-one bounded native cases pass. The timer can request all bits used by either wait; neither wait alone establishes RAW-DMA completion. Scheduling, live timing and frame ownership remain unverified. See [the start gate](750d-start-gate.md).

- Executed real readout method selection/publication and rows 3/9 in four native fixtures. Enabled-driver completion processing prepares `StartDriver` operation 2 before returning; disabled fixtures skip it. Transport and actual restart remain unexecuted. This identifies a concrete pre-submission interception boundary, not a frame lease. See [real readout methods](750d-readout-methods.md).

- Followed readout-done processing into four registered-method calls and a separate internal-phase slice. Three callback-dispatch cases and ten phase fixtures pass. The real methods remain unexecuted; internal phase is distinct from the VSYNC state-object state. Post-transition copy safety remains unverified. See [readout-done processing](750d-readout-done.md).

- Traced RAW start preparation to the control RMW at `0xD0004104` and start value 1 at `0xD0004100`, with four native cases stopping before physical stores. Separate native calls verify software pending-address consumption. Decoded the target EVF state-5/input-5 readout-done entry corresponding to the 7D2 synchronization pattern; a frame lease remains unverified. See [RAW start](750d-raw-start.md).

- Identified a message-37 receiver branch that supplies pool constants `0x58830000` / `0x06B48000`. Two bounded native cases propagate these through six setup stages to candidate RAW preparation address `0x5C62C000`. Service dispatch and resource configuration are supplied; live activation, pixels and per-frame ownership remain unverified. No platform binding enabled. See [constant-pool provenance](750d-pool-provenance.md).

- Identified the asynchronous pool request's actual callback, 48-byte service object and minimum-size contract. Five native boundary checks verify request/object preparation and callback publication versus undersized assertion. The 90 MiB threshold does not establish actual allocation capacity; OS allocation/delivery and per-frame timing remain unexecuted. See [the pool request](750d-pool-request.md).

- Identified the original manager address writer: resource-22 lookup, expected count one, actual class-2 provider for reviewed configuration modes 1/2. Seven native cases now include pool-base setup/alignment to 16 KiB, the pool-relative address, reported 30,791,680-byte resource size, skip and diagnostic behavior. Static mode-selection callers are identified; live configuration and sensor frames remain unobserved. See [the RAW resource route](750d-raw-resource.md).

- Followed manager resource fields `+0x710 -> +0x748` into ADST slot-2 descriptor population and EVF RAW preparation. The actual population code fixes the slot count at one. Four native scenarios pass, including zero/one assertion inputs; original allocation and per-frame timing are still unverified. See [descriptor population](750d-raw-population.md).

- Identified the producer of candidate RAW preparation word `0x26BEC`: EVF activation reserves ADST slot 2 and stores descriptor word zero there. Four bounded native supplied-registry scenarios verify acquisition, repeat diagnostics, end-handler release and reacquisition. This establishes reservation behavior, not per-frame ownership. See [RAW memory reservation](750d-raw-reservation.md).

- Traced the separately registered RAW return callback to EVF event 19 and the handler labeled `evfAfPathCompleteInterrupt`. Five bounded native stage checks and four independent small-pool checks pass; all ten table entries are decoded. This qualifies the earlier notification as an AF consumer path, with no proof of a recorder-ready frame or ownership of the earlier sensor buffer. See [the EVF RAW-return event](750d-evf-raw-event.md).

- Followed supplied completion events through the native task dispatcher and actual application table: event 6 prepares return operation 2, event 7 prepares operation 6. Ten dispatch cases and four separately invoked receiver checks pass. Static review identifies mode-dependent registration of the separate RAW callback. No queue/transport delivery or safe frame ownership is established. See [completion dispatch](750d-completion-dispatch.md).

- Distinguished RAW-component notification from seven-bit aggregate completion in the actual driver. Ten native synthetic-order scenarios verify callback ordering, repeated events and mask reset; two separate native checks identify application task events 7 and 6, stopping before queue delivery. This does not establish frame identity or buffer lifetime. See [completion events](750d-completion-events.md).

- Traced width, height and a row-size selector from the actual EVF caller structure through the native publisher and reviewed mode configuration into DMA descriptor arithmetic/packing. Six native PC fixtures pass, including deliberately invalid inputs that demonstrate truncation and height underflow. Physical register writes and real dimensions/packing remain unverified. See [the geometry route](750d-raw-geometry.md).

- Traced a reviewed preparation branch into a candidate DMA destination: channel index 1 / register base `0xD0004100`. Four native PC cases stop before the destination store, verify address alias clearing and zero-address skipping, and check channel callback registration/forwarding through an artificially invoked dispatch tail. No hardware interrupt, pixel capture or camera binding enabled. See [the destination trace and limits](750d-raw-destination.md).

- Identified two actual 750D register-shadow readers and executed their pointer setters, shadow-only writers and readers with synthetic RAM: 28 reads and four expected unmapped-read faults pass. Traced RAW parameter submission to a Postman mailbox sender; 12 native command-preparation cases pass, stopping before mailbox writes. Peer delivery and DMA completion are unverified. No camera binding enabled. See [register shadows and the message boundary](750d-register-shadows.md).

- Traced the RAW setter's consumers into the actual 750D Live View preparation handler. Seven bounded native-code PC cases verify flag-dependent address selection, counter restriction, fallback behavior and propagation into two parameter locations. The selected address is not established as a completed frame; DMA channel, geometry and ownership timing remain unverified. See [the address route](750d-raw-address-route.md).

- Decrypted the actual 750D 1.1.0 updater and nine-record firmware container using isolated native crypto from a public 70D 1.1.2 ROM. Both native verification calls pass, deliberately corrupted ciphertext is rejected, the decoded checksum matches, and main record 6 matches `SIG_750D_110`. Executed the target's identified `lv_save_raw` setter against synthetic RAM in four bounded cases. All 27 Python tests pass. This is readable target code and function-level evidence, not real-frame capture. See [the plaintext milestone](750d-plaintext-milestone.md).

- Distinguished the M3 FI2 wrapper from the target EOS FIR format using Canon's file description and CHDK source. Identified published cross-model unpacking evidence based on a 60D ROM, without obtaining a new EOS dump. Strengthened the actual 750D FIR inspector with region-map and extended-header alignment validation; 23 Python tests pass. See [the FIR follow-up](rom-analysis.md#fir-framing-follow-up-and-an-older-eos-reference-route).

- Obtained a public CHDK EOS M3 1.01A full ROM and traced its firmware-update parser to AES-128 and a CBC length wrapper. Native routines execute on the PC and pass a known-answer vector plus four generated-frame cases. Direct M3 key/IV/wrapper application to the 750D FIR fails length bounds; no 750D plaintext acquired. Added ADR candidate decoding with GNU assembler verification. Twenty-one Python tests, five ARM suites and 19 upstream layout assertions pass. See [the M3 experiment](m3-crypto-reference.md).

- Read the previously reader-blocked public 750D forum in a browser and found a specific external 2017 image lead, described in later posts as firmware 1.0.0. The external folder was blocked by browser site safety; no image acquired or validated. An older image cannot establish 1.1.0 stubs. See [forum follow-up](rom-analysis.md#public-forum-access-and-an-older-image-lead).

- Investigated the selected FIR-only/public-source route using primary DIGIC 6 research, the public installer dependency chain, and a local exact-marker scan of both actual ciphertext regions. No usable plaintext or decryption key acquired. Saved the bounded negative result and firmware-byte-free evidence in [ROM analysis](rom-analysis.md#fir-only-investigation-after-choosing-the-pc-only-route). Camera access remains outside scope.

- Followed the original contributor's RAW/d6 branches and upstream EDMAC cleanup branch; reviewed 750D files still lack the RAW channel/copy/shadow-reader implementation. Rechecked the actual Canon FIR with stronger section-bound checks and explicit legacy-XOR exclusion for its extended header. Nineteen Python tests pass. No plaintext firmware or validated capture address acquired; see [the bounded follow-up](rom-analysis.md#older-branches-and-the-actual-fir-boundary).

- Audited 750D history and current Tragic Lantern platform sources; no missing validated RAW addresses found in reviewed material. Excluded unsupported DIGIC 6 DMA-table decoding and a DIGIC 8 ROM-dependent decryptor as ready solutions. Added read-only Thumb address-load candidate scanning, checked against GNU-assembled instructions and a full artificial ROM fixture. Fifteen Python tests pass; see [source audit](rom-analysis.md) and [instruction candidate tool](thumb-xrefs.md).

- Added a completed-frame source lifecycle/lease layer, gated to PC synthetic sources. It validates fixed RAW14 geometry and sequence, holds source ownership through synchronous copy, releases dropped frames, and retries failed cleanup. Integrated it into all four disk scenarios with immediate source-buffer overwrite after release; recorded payloads remain correct. Five ARM suites pass. Traced donor callback ordering and startup ownership; no 750D firmware calls enabled. See [source integration](raw14-capture-source.md).

- Added a portable adapter for ML-style signed writes and absolute-position seeks, with verified unchanged-EOF checks when truncation is unavailable. Normal synthetic recording finalizes without truncation; partial-tail errors refuse false success. Four ARM suites and four real-PC-file scenarios pass. This uses injected operations, not camera firmware bindings. See [FIO adapter](raw14-fio-adapter.md).

- Executed the ARM recorder against real PC file operations through a test bridge. Independently verified all 36 recorded payloads from a 48-submission queue-overflow scenario and a separate partial-write recovery file. Reviewed upstream FIO contracts and identified the missing public truncation operation as an adapter design requirement. See [disk bridge and FIO findings](raw14-disk-bridge.md).

- Connected synthetic frames through the ARM copy core and queue to a C MLV writer with short-write handling, rollback, and error finalization. Exported a two-frame test clip to disk and independently checked payloads/metadata in Python. All three ARM suites, 19 actual-upstream wire-layout assertions, and nine Python tests pass. This is an offline pipeline, not sensor recording or verified editor compatibility. See [the MLV writer](raw14-mlv-writer.md).

- Added a fixed-buffer frame queue with successful-copy publication, FIFO writer ownership, explicit overflow handling, and stale-lease protection. Both the copy and queue C suites execute successfully under ARM emulation; the queue suite includes a 1,000-step reference-FIFO scenario. No camera/DMA/filesystem integration is implied. See [the queue contract](raw14-queue.md).

- Implemented an original experimental RAW14 full-width copy component in C, with explicit buffer bounds and an injected synchronous backend. Compiled it for Cortex-R4/Thumb and executed its C tests under Unicorn's Cortex-R5 ARMv7-R model. This is tested transfer logic, not yet integrated into Magic Lantern or Canon DMA. See [the component and tests](raw14-copy-core.md).

- Traced the 7D2 RAW-enabling commit and the shared stream/callback/copy/MLV path; compared DIGIC 7 alternatives on 200D/6D2 and same-generation 80D/5D4 configurations. Added a compile-only 750D RAW probe that fails as expected on seven missing identifiers. The 750D shadow-register reader also remains a zero-return placeholder. See [similar-camera implementation details](similar-camera-raw.md).

- Added a read-only ROM inspector with four synthetic tests. It checks the upstream additive firmware signature and searches selected RAW-related strings and literal pointer candidates. No real ROM was available for analysis; see [ROM analysis](rom-analysis.md).

- Downloaded the upstream source at commit `142472e95054d73640f50789ac0fd66325499d82`.
- Compiled and linked the QEMU-configured core and loader as ARM ELF files on Windows, using Arm GNU Toolchain 13.3.Rel1.
- Kept the default module-system and TCC support enabled.
- Reviewed the existing 750D platform definitions and compared them with the 7D Mark II implementation.
- Inspected the official Canon update container with both an existing parser and an independent read-only script.

## Existing source evidence

The 750D port defines `EVF_STATE` at `0x26b94`. This address has not been independently verified on hardware by this project.

The 7D2.112 port uses a Canon `_memcpy_fast` function to copy frames while bypassing parts of the incomplete EDMAC implementation. Its function address and behavior cannot be assumed to apply to the 750D.

The 750D port does not enable RAW recording. Some EDMAC functions are empty placeholders. Enabling the recording module alone is insufficient.

## Missing information

- A verified RAW Live View channel or buffer source, frame geometry, and pixel packing.
- A verified fast-copy function for 750D 1.1.0, including channel, alignment, cache, and calling-context constraints.
- Confirmation of frame synchronization and buffer lifetime.
- Complete boot/flash inputs for full-camera QEMU execution. The main-code update record is now available for cross-reference analysis; a full ROM dump has not been reconstructed.

### Distance to a first real RAW recording

The offline recorder logic is implemented and tested with synthetic frames. Its copy, queue, MLV writing, file-error handling and source-lifetime contracts are reusable work, but have not been integrated with Canon's actual capture events or filesystem.

The first real recording still depends on these uncompleted stages:

1. Readable target firmware is now obtained. Validate 750D 1.1.0-specific bindings beyond the small RAW-control setter already tested on the PC.
2. A RAW preparation-address route is now traced and tested. Identify its actual writer, stream geometry/packing, completed-frame event and buffer lifetime.
3. Integrate verified copying, cache handling and Canon file operations with the recorder.
4. With separate owner authorization for hardware work, capture and independently check a real frame, then a short sequence, then recording stability and throughput.

No real sensor frame has been acquired by this project. Additional synthetic tests and donor crypto execution do not complete stage 2. The current phase is firmware research and offline preparation; a percentage-to-finished or a reliable completion date is not supported by the evidence. The PC-only constraint remains in effect.

QEMU EOS test infrastructure requires `ROM1.BIN` for DIGIC 6 cameras. Existing 750D emulation patches bypass OmarInit; they do not demonstrate accurate RAW pipeline emulation.

## Official update inspection

File: `CCF23110.FIR`

- Size: 23,626,960 bytes.
- SHA-256: `91ae807b6ac27dcb9c2c6351557c131768cc06736957600fdd0f5014e5531450`.
- Model ID and firmware version match the 750D / 1.1.0 target.
- Structural checksum passes.
- Cryptographic signature authenticity has not been independently verified.
- The original update remains unchanged on disk. Its updater and firmware-record payload have now been decrypted privately; this is not a complete ROM dump. See [the successful extraction](750d-plaintext-milestone.md).

## Build validation and limitations

Produced the core ELF, its embedded binary image, and the loader ELF. The loader has no undefined symbols. The core symbol table lists six symbols forced by upstream linker flags; dependencies of every separate module have not been validated.

The linker reports RWX load segments. Bundled TCC uses its own warning settings. A reduced build with modules and TCC disabled failed to link because of `module_exec_cbr`; the successful configuration uses the default module support.

No full-camera QEMU execution, physical-camera execution, real RAW frame capture, camera recording throughput measurement, or camera stability test has occurred. Experimental C components have executed under Unicorn ARM emulation, including real PC file operations through a test bridge.
