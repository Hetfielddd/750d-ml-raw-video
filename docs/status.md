# Research status

Last updated: November 24, 2026.

Target: Canon EOS 750D / Rebel T6i, Canon firmware 1.1.0.
Scope: PC-only research. The owner's camera and SD card have not been used.

## Completed

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
- Plaintext firmware analysis material for cross-reference analysis and QEMU execution.

QEMU EOS test infrastructure requires `ROM1.BIN` for DIGIC 6 cameras. Existing 750D emulation patches bypass OmarInit; they do not demonstrate accurate RAW pipeline emulation.

## Official update inspection

File: `CCF23110.FIR`

- Size: 23,626,960 bytes.
- SHA-256: `91ae807b6ac27dcb9c2c6351557c131768cc06736957600fdd0f5014e5531450`.
- Model ID and firmware version match the 750D / 1.1.0 target.
- Structural checksum passes.
- Cryptographic signature authenticity has not been independently verified.
- The payload remains encrypted. The update file is not a plaintext ROM dump.

## Build validation and limitations

Produced the core ELF, its embedded binary image, and the loader ELF. The loader has no undefined symbols. The core symbol table lists six symbols forced by upstream linker flags; dependencies of every separate module have not been validated.

The linker reports RWX load segments. Bundled TCC uses its own warning settings. A reduced build with modules and TCC disabled failed to link because of `module_exec_cbr`; the successful configuration uses the default module support.

No full-camera QEMU execution, physical-camera execution, real RAW frame capture, camera recording throughput measurement, or camera stability test has occurred. Experimental C components have executed under Unicorn ARM emulation, including real PC file operations through a test bridge.
