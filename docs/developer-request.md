# Information request: Canon 750D firmware 1.1.0

We are researching RAW video support for the Canon EOS 750D / Rebel T6i using Magic Lantern. Work is PC-only; no experimental code has been run on the project owner's camera.

## Prepared baseline

- Upstream commit: `142472e95054d73640f50789ac0fd66325499d82`.
- Core and loader ELF successfully compiled and linked using Arm GNU Toolchain 13.3.Rel1, `CONFIG_QEMU=y`, and default module/TCC support.
- Official Canon 1.1.0 update container inspected; plaintext firmware is not available.

## Information needed

1. Existing owner-authorized 750D 1.1.0 ROM analysis material, or published disassembly/address findings. If a dump is available for analysis, its address mapping, size, acquisition method, and firmware version are needed.
2. A verified 750D equivalent of the 7D2 fast-copy function: address, calling code, signature, DMA-channel constraints, alignment, cache handling, and allowed calling contexts.
3. Verified RAW Live View buffer/channel information, frame geometry, and pixel packing. Still-photo CR2 buffers and YUV preview buffers are different data paths.
4. Confirmation of frame synchronization via EvfState. Upstream defines `EVF_STATE=0x26b94`; this project has not independently validated it.
5. QEMU prerequisites and known limitations for firmware 1.1.0, including any necessary serial-flash material. Older 750D scripts reference 750D.100 and bypass OmarInit.

Serial numbers, personal photos, user settings, and personal files are not needed. A full RAM dump is not required for the initial analysis.

## References

- [750D platform](https://github.com/reticulatedpines/magiclantern_simplified/tree/dev/platform/750D.110)
- [7D2 frame-copy reference](https://github.com/reticulatedpines/magiclantern_simplified/blob/dev/platform/7D2.112/function_overrides.c)
- [750D PTP registration work](https://github.com/reticulatedpines/magiclantern_simplified/pull/262): its author reports real-camera GetMemory testing on 1.1.0. This is evidence of external work, not a recommendation to run it on the project owner's camera.
- [Tragic Lantern](https://github.com/paweltokarz/tragiclantern): the reviewed description, platform stubs, and branch list did not provide a complete RAW implementation.
- [QEMU test infrastructure](https://github.com/reticulatedpines/qemu-eos/blob/qemu-eos-v4.2.1/magiclantern/ml_tests/cam.py)

As of October 31, 2026, the public-source search has not yielded a usable ROM or the missing verified RAW addresses. This does not establish that such material does not exist. The Magic Lantern forum returned HTTP 403 during attempted access. No external requests have been sent by this project.
