# Research status

Last updated: October 31, 2026.

Target: Canon EOS 750D / Rebel T6i, Canon firmware 1.1.0.
Scope: PC-only research. The owner's camera and SD card have not been used.

## Completed

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

No emulator execution, physical-camera execution, RAW frame capture, recording throughput measurement, or stability test has occurred.
