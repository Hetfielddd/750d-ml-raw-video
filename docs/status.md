# Research status

Last updated: November 27, 2026.

Target: Canon EOS 750D / Rebel T6i, Canon firmware 1.1.0.
Scope: PC-only research. The owner's camera and SD card have not been used.

See the [eight-milestone roadmap](roadmap.md): three PC preparation milestones complete, two target research milestones partial, three camera-integration/recording milestones not complete. Five milestones remain open; this count is not a percentage of effort or an ETA.

## Completed

- Added a two-buffer PC source through the existing capture API. ARM tests verify rejection of delayed, duplicate and partial completions, including reuse of the same address, plus ordered output and source protection during copy. The test producer supplies transfer identity and byte count. [PC source checks](raw14-capture-source.md#pc-verification).

- Verified native callers of the physical DMA address reader, including the channel-1 Image2 diagnostic and SAF stop path. Two peer teardown routines prepare waits over mask `0x7F`. In separately entered tails the reviewed RAW helper writes its trigger word and the SAF helper reads addresses for logging. Nine PC checks pass with passive registers and explicit wait/cleanup cuts. [Native DMA address callers](750d-dma-address-callers.md).

- Executed the reviewed RAW setup and start for three supplied selectors, including the actual geometry writer and channel route store. RAW and IPC program different routes on the same channel. The target driver has separate native readers for the physical address, low two status bits and bit 2. The PC tests supply the register values. [RAW configuration comparison](750d-raw-command-order.md#native-raw-setup-compared-with-ipc).

- Connected the 750D RAW writer's physical register block to a separately configured Canon IPC receive path. Its two native polls accept status 2 exactly and read the physical address for logging while waiting. Sixteen PC checks cover diagnostics, both receive phases and configuration. IPC status behavior remains a candidate to compare with Live View. [Channel status checks](750d-channel-status.md).

- Executed four nested peer IRQ vector scenarios from controller read through the natively registered channel-1 handler, RAW flag update, controller write/readback and exception return. Supplied status 0 and 4 both set the RAW flag. Passive register RAM supplies IRQ `0x41`; real delivery and the physical completion condition remain open. [Peer vector checks](750d-raw-notification.md#peer-irq-vector-through-native-exception-return).

- Verified ten command-to-IRQ scenarios on passive register RAM with native start, address publication, stop request, shadow read and interrupt forwarding. The destination chosen at start and the next pending address can diverge. The checked IRQ path preserves both and forwards the registered context without identifying a transfer. Physical completion and buffer reuse remain unverified. [RAW interrupt address checks](750d-raw-command-order.md#destination-state-at-the-raw-interrupt).

- Confirmed the 750D EVF event-5 producer and traced it through `HEAD2` line timing, native message preparation and task dispatch. Three registration paths and all ten state entries were checked on the PC. Head timing, readout notification and RAW destination ownership are distinct parts of the recording path. The event supplies no destination or frame number. Canon signatures and handler diagnostics associate the preceding SCS work with still capture. [EVF readout source](750d-evf-readout-source.md).

- Added six native SCS flag/readiness/reset scenarios. Exact flag1 causes completion reentry, while 0/2 skip it without clearing the flag. Another handler natively publishes owner +56 readiness before rechecking the retained condition; reentry then reaches the nonzero completion branch's mode-query boundary. A separate actual reset slice clears the completion flag and another software field. Middle helpers, full handlers and live timing remain unexecuted; this is capture-job ordering, not a RAW lease. See [SCS flag lifecycle](750d-scs-event.md).

- Rechecked live upstream, 750D-focused and contributor branch heads and inspected key platform files. No new 750D RAW binding found in the checked sources. Compared 7D2's newer V3 full-width synchronous copy API with DIGIC7 V1/V2 and updated the integration plan without switching our baseline. See [November 26 source audit](upstream-review-2026-11-26.md).

- Executed the primary SCSState constructor/event7 matrix across 18 states plus two rejection controls, then six additional constructor/worker scenarios. Native publication links owner +8 to its queue and +12 to SCSState; the queue-selected worker resolves that same association through the real dispatcher. With owner +56 zero, a native post-logger branch sets a software flag and returns to the next receive boundary. Allocation, queue delivery, live ownership, other handler branches and a RAW-frame lease remain unverified. See [SCSState event7](750d-scs-event.md).

- Identified the primary ShtCapture receiver and actual operation-13/14 callback registrations in six PC scenarios. Two real caller slices publish different CMOS callbacks; a checked operation-13 continuation prepares primary task event 7 with zero payload. Separate receiver epilogues prepare flags `0x1000`/`0x2000`; native null-callback controls still reach those boundaries. No callback completion, query/logger return, OS clear/set, transport delivery or EVF/RAW-frame association is inferred. See [primary CCD completion receiver](750d-ccd-receiver.md).

- Traced CCD writer completion through actual callback registration, task-event preparation and separately entered native state dispatch in five PC cases. Conditional channel-2 writer callback reaches ShtCapture event/return operation 13; a separate callback reaches 14, both with zero payload. A native constructor slice publishes service `0x00010000`. The relationship to EVF readout/RAW channel 1 remains unverified; the later receiver checks above do not establish a frame identity or lease. See [CCD writer completion](750d-ccd-completion.md).

- Expanded the RAW IRQ probe to 20 cases plus two separate real stop-callback preparations. Eight sequences derive software request flag 1 through native configuration/start/stop-like request code, read status bit 2 with an actual helper and then invoke the shared IRQ body. The request flag remains set after notification. Two statically reviewed callers install dedicated callbacks and prepare semaphore waits; their native callbacks reach the signal boundary. Physical stopping, partial-frame validity, live IRQ delivery and the status bit's meaning remain unverified. See [channel stop and IRQ qualification](750d-channel-stop.md).

- Executed no-work RAW entry -> real driver callback -> actual kernel event lookup/update -> return in eight supplied-state/IRQ scenarios, plus two direct IRQ/forwarding controls. The no-work path sets bit `0x10` without any capture-register page mapped. With other bits explicitly preseeded, native ALL-bit wait first reaches its blocking boundary, and a separate post-notification wait returns zero. Application RAW/aggregate task callbacks are null; no task delivery, blocked wakeup, live stale-event sequence or completed sensor frame is asserted. See [RAW notification qualification](750d-raw-notification.md).

- Executed the complete reviewed non-alternate RAW software sub-handler in ten supplied-RAM scenarios, including actual address/control/command/format writers, native CPSR save/restore, pending clear and return. The six-bit format RMW follows the channel-command store; pending clear follows both command stores. Skip-address still permits command submission. Repeated invocation requires republication to emit another nonempty command sequence. This validates software ordering only, without peripheral acceptance, sensor pixels or a frame lease. See [RAW command order](750d-raw-command-order.md).

- Expanded native service `0x20002` routing checks to twelve cases. A separately entered real driver epilogue returns through the worker/task loop to the next receive without return transport, with parameter pages inaccessible; the omitted driver body is not executed. Two FIFO-accepted configurations consume stable A/B blocks in order but replace a single pending RAW address, so subsequent start preparation selects B. Queue acceptance therefore does not count captures. Existing FIFO/full/empty/rejection checks still pass. Allocation/free, mailbox delivery, full configuration, scheduling, consumption acknowledgment and image-buffer lifetime remain unverified. See [RAW parameter lifetime](750d-raw-param-lifetime.md) and [queue execution](750d-task-queue-order.md).

- Executed the real shared override-configuration setter and expanded the RAW redirection probe from eight to 19 scenarios. Native sequences verify repeat-override snapshot loss, a restore/configure/switch sequence, duplicate-restore overwrite and seven geometry boundaries. Bounded reference searches did not establish the intended caller. No channel start, sensor pixels, frame ownership or camera binding validated. See [override lifecycle and geometry](750d-raw-override-contract.md).

- Traced RAW destination overwrite and a native snapshot/override/restore mechanism. Eight PC scenarios verify pending-address precedence, the correct 44-byte flag-row stride, native flag-controlled suppression, ten-word restore and auxiliary state that remains changed. This is a destination-control candidate; channel start, physical completion, source lifetime and safe use remain unverified. See [RAW redirection](750d-raw-redirection.md).

- Executed actual primary semaphore fast paths and connected wrapper admission, native cache-dispatch/descriptor preparation, separately invoked IRQ signaling and actual take/result/unlock paths across an explicit omitted hardware-start store. Twenty-nine scenarios include zero-size, absent/stale signals, uninterrupted native IRQ unlock-to-callback preparation, channel initialization and Canon property-save channel-0 use. Corrected reversed source/destination labels in the earlier direct-builder probe. Scheduling, live context/channel ownership, cache coherence, pixels and hardware completion remain unverified. See [copy synchronization and channel use](750d-copy-sync.md).

- Executed copy-engine IRQ cleanup through signal/unlock boundaries, separately checked callback forwarding and all 16 post-wait status nibbles, and verified shared-status dependency across two supplied channel IRQs. All 53 cases pass. Zero and eight both decode to zero; OS synchronization and concurrency constraints are still required before treating any return as verified completion. No DMA or OS calls executed. See [copy completion](750d-copy-completion.md).

- Executed the actual primary copy descriptor builder, ARM zero helper, address conversion and linked-list publication in ten two-descriptor scenarios. Nine separately entered submission preparations consume those native-written structures and stop before the start store after six checked payload writes to artificial register RAM. No DMA transfer, OS synchronization or completion validated. See [copy descriptors and submission](750d-copy-descriptor.md).

- Identified primary copy candidate `0xFE133EB2`, its list core, address classifier and cache preparation route. Fourteen native cases verify admission, attribute decoding, two address conversions and cache-helper dispatch with explicit fixtures. OS wait, maintenance, DMA submission and completion remain unexecuted; no platform stub enabled. See [primary copy preparation](750d-copy-entry.md).

- Observed seven peer MPU-region preparations and two primary entry operands without executing CP15 writes. The peer assigns access `0x121` / `0x12C` to the cacheable/uncached candidate ranges respectively; the primary's inherited region boundaries remain unknown. This narrows the address/cache question without validating coherence or pixel reads. See [RAW aliases](750d-raw-alias.md).

- Thirteen selection sequences include VD counter updates and ten propagation/start checks: the native selected word passes through publisher, mode-3 configuration and separately invoked peer configuration into pending state. Zero skips destination submission but can notify the supplied callback. Transport/live ordering, full lifecycle, transfer completion and frame ownership remain unverified. See [counter-restricted selection](750d-raw-selection.md).

- Resolved the low IRQ-import mismatch with a distinct scoped peer-kernel page from source `0xFE744D60`. Sixteen native cases verify registration into slot `0x01ACB264`, IRQ-mask restoration, separate dispatch using that natively written slot and enable bounds. The dispatcher selects the RAW handler with channel argument 1. Boot relocation and physical controller delivery remain unverified. See [IRQ registration and dispatch](750d-irq-registration.md).

- Executed the RAW channel IRQ body and actual write helpers through application callback forwarding in 12 artificial-register cases. Four derive software flags from the actual configuration/start functions: both words become zero, selecting a narrower IRQ branch. The reviewed 7D2 registration overrides are empty and do not supply hardware IRQ semantics. Controller delivery and physical completion remain unverified. See [the RAW IRQ experiment](750d-raw-irq.md).

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
