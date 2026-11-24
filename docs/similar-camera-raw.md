# How related cameras reached RAW video

Source baseline: Magic Lantern `142472e95054d73640f50789ac0fd66325499d82`. Reviewed November 24, 2026. These are source-code findings and developer reports, not tests performed on these cameras by this project.

## Forum and upstream refresh: November 25, 2026

The user supplied a [CineD overview](https://www.cined.com/magic-lantern-canon-2026-raw-video-film-roll-soup-engine-m-film/) and [750D Midsummer discussion](https://www.magiclantern.fm/forum/index.php?topic=27318.0). Both were read directly, along with the current camera-development board, latest 7D2 porting page, 7D2 Midsummer discussion, upstream update thread and 750D PTP/Lua thread. This is a bounded review of these sources and the repositories below, not an exhaustive forum or GitHub search.

CineD mainly covers established 5D3 RAW workflows and still-photo film-look projects (Soup Engine, Film Roll, M-Film and The Ritual). Its mention of ML support for the 750D does not announce RAW video support on that model. Its general mention of QEMU likewise does not establish emulation of the 750D sensor/DMA pipeline.

In the supplied [June 27, 2025 message](https://www.magiclantern.fm/forum/index.php?msg=247879), names_are_hard reports an early 7D2 RAW result and expects 750D RAW to be possible. This is a feasibility expectation, not a 750D implementation. The reviewed topic has 17 replies, ending August 29, 2025; later posts do not provide a RAW port.

The [September 2025 upstream summary](https://www.magiclantern.fm/forum/index.php?topic=26814.msg248197#msg248197) explains the actual 7D2 solution: a fast linear DryOS copy instead of a general rectangular EDMAC copy, full-width output, and a left black border removed in post. Reported full buffer widths are 1984 pixels in normal Live View and 3616 in 5x. These are 7D2 figures, not 750D targets. The [latest 7D2 porting page](https://www.magiclantern.fm/forum/index.php?topic=13746.625) also corrects an earlier approximately 599 MB/s copy benchmark: its sleep-based timing was wrong. The developer reports about 190 MB/s for the newly found function; this remains a donor measurement, not a 750D prediction. The open implementation commit is linked below in the existing donor analysis.

The [October 26, 2026 upstream summary](https://www.magiclantern.fm/forum/index.php?topic=26814.msg249014#msg249014) names exactly our pinned baseline, `142472e95054d73640f50789ac0fd66325499d82`. It reports repeated-recording crash fixes for 200D/7D2/6D2, `sd_uhs` becoming `sd_clock`, an experimental M6 II port, and `raw_vidx`. It explicitly identifies DIGIC 6 EDMAC operations via RPC as a reason for ongoing API work. This supports investigating the message boundary we found; it supplies no 750D-specific completed-frame binding.

The live GitHub checks found:

- Upstream `dev` still points to our pinned baseline. No baseline/submodule update is needed merely to obtain the October summary's code.
- Upstream `edmac_cleanup` points to `562c699589a98989e66ff2d0634748cf0f14bc44`, with 18 commits beyond the baseline. Commits dated November 21-22 reorganize copy APIs, move 7D2 copying into `src/edmac.c`, and select `CONFIG_EDMAC_COPY_RECT_V3` for the 7D2. [Pinned branch comparison](https://github.com/reticulatedpines/magiclantern_simplified/compare/142472e95054d73640f50789ac0fd66325499d82...562c699589a98989e66ff2d0634748cf0f14bc44).
- V3 keeps fast linear copying and rejects unequal row strides/widths or nonzero horizontal offsets. Its `copy_rectangle()` interface returns after copying; module call sites no longer manage the old copy-completion semaphore themselves. This is useful integration guidance, not full direct ICU control of Omar EDMAC.
- The comparison's only 750D platform-file change is an empty `platform/750D.110/edmac_per_cam.h`. The unmodified 750D shadow-reader placeholder still returns zero, and the reviewed platform does not gain RAW bindings from this branch.
- The latest reviewed `dev` change specific to `platform/750D.110` is [PTP registration stub `7abf37a`](https://github.com/reticulatedpines/magiclantern_simplified/commit/7abf37a643d3d15c3bfbe3f3cbdcfd10035acda1), already in our baseline. The [750D PTP/Lua forum topic](https://www.magiclantern.fm/forum/index.php?topic=27405.0) concerns experimental USB file/memory operations and Lua, not sensor RAW recording. The public Tragic Lantern head remains `aa224f0bc8e177a456c119eba00263488ee51f5a` in this check.
- Kitor's listed RAW draft and DIGIC 6 ROM-patching branch heads match the earlier recorded audit. A global GitHub commit search timed out; no claim about every public fork follows from this review.

The [pinned `raw_vidx` source](https://github.com/reticulatedpines/magiclantern_simplified/tree/142472e95054d73640f50789ac0fd66325499d82/modules/raw_video/raw_vidx) is already available locally. It separates VSYNC/event production, a serial worker and MLV serialization. It still relies on `raw_lv_request()`, geometry in `raw_info`, `raw_lv_redirect_edmac()` and a working platform copy backend. The event producer has test crop offsets x=200/y=100; this horizontal crop conflicts with V3's full-width restriction. It is therefore a useful reference to adapt, not a module that can simply be enabled on the 750D. In particular, a simplified recorder does not remove the frame-lifetime and geometry gaps.

Practical consequence: continue target-specific geometry/completion/copy analysis on the PC, use `raw_vidx` as an additional upstream lifecycle reference, and account for the newer copy API when implementing integration. Do not switch the upstream pin or enable a camera module without first validating the relevant bindings. No camera/SD access or communication with developers occurred during this review.

## Closest useful reference: 7D Mark II (DIGIC 6)

The 750D and 7D2 both select `CONFIG_DIGIC_VI`, Cortex-R4, ARMv7-R, Thumb, and long calls. The 7D2 also selects `CONFIG_DUAL_DIGIC`, unlike the 750D. The shared generation makes it useful as a design reference, but does not make firmware addresses or DMA channels interchangeable.

The decisive upstream change is [8d5b5c9: 7D2 mlv_lite raw video, full width only](https://github.com/reticulatedpines/magiclantern_simplified/commit/8d5b5c9d3e460594d02b6832fded0480532f1612). It replaces an unsuccessful copying approach with a fast Canon memcpy variant and deliberately sacrifices horizontal cropping. A preceding commit says that merely loading mlv_lite could hard-lock the camera. This is why successful module loading is not our completion criterion.

### End-to-end path

The completed-frame ownership layer now has [a deeper callback/lifecycle analysis and PC implementation](raw14-capture-source.md). In particular, the donor programs the upcoming DMA destination and processes the opposite buffer after startup skipping; reading the current channel pointer alone is not a completed-frame protocol.

1. `raw_lv_request()` reaches `raw_lv_enable()` in `src/raw.c`. After waiting for Live View to settle, the non-SLURP path calls Canon's named event procedure `lv_save_raw(1)`. It later disables the stream with `lv_save_raw(0)`. The principle is to ask Canon to produce its own RAW stream, rather than implement sensor readout from scratch. Availability and behavior on the 750D still require evidence.
2. The 7D2 defines `RAW_LV_EDMAC_CHANNEL_ADDR=0xd0004200`. The common backend reads `ram_addr` for the current buffer and `yn_xn`/`yb_xb` for geometry through `shamem_read`. This read function is essential; a zero-return placeholder cannot provide valid frame geometry or buffer pointers.
3. `CONFIG_EVF_STATE_SYNC` routes the `EVF_STATE` old-state 5 / input 5 transition to `vsync_func()`, which dispatches `CBR_VSYNC`. The recorder registers `raw_rec_vsync_cbr` for that callback. The exact state transition must be verified for the 750D.
4. `raw_rec_vsync_cbr` redirects capture to alternating full-size buffers, advances the buffer position, and processes the previous frame. In the non-SLURP backend, `raw_lv_redirect_edmac()` writes the channel's `ram_addr` field. This is an actual hardware-register write, not passive copying.
5. For uncompressed frames, `mlv_lite` calls `edmac_copy_rectangle_cbr_start()`. On 7D2 this is a platform wrapper using `_memcpy_fast(channel, dst, src, count)`, with channel 0 in the current implementation. The developer notes about 190 MB/s on 7D2 are not a measurement or promise for 750D.
6. The wrapper permits equal source/destination row strides and full-width rows, with zero horizontal offsets. Vertical offsets remain possible. It copies the contiguous region, then invokes `cbr_w` to clear the recorder's active-copy flag. The shared recorder writes filled slots to MLV through `FIO_WriteFile` in its recording task.

### Changes outside the platform wrapper

The successful 7D2 commit also changed `mlv_lite` resolution handling to force full-width output and changed the RAW left border to zero. Copying only the firmware stub and wrapper would omit these constraints. A 750D adaptation must coordinate row pitch, black borders, Bayer alignment, output width, and metadata.

The 7D2 platform has a real `shamem_read` stub (`0xfe6bc424`). Its comment notes that it belongs to a block copied to Omar and calls out uncertainty about ICU access. That value must not be reused on 750D.

The 7D2 whitelist additionally permits `PROP_LV_ACTION` to address repeated-recording lockups (referenced upstream issue 307). The 750D whitelist currently lacks it. This identifies a lifecycle dependency to investigate, not permission to enable an unverified property write.

## Why 200D (DIGIC 7) is a secondary reference

The 200D uses a higher-level Canon memory-to-memory EDMAC copy routine, taking source/destination region structures and channel/resource information. [02b3a2d](https://github.com/reticulatedpines/magiclantern_simplified/commit/02b3a2d615cf6d45ee9b5bb46e84104937de160c) documents this approach.

Its current wrapper uses channels 48 and 19. Comments explain that earlier default channels clashed with Live View and copying hung until Live View closed. Those channels were selected by logging actual device use. This is evidence that choosing apparently plausible channels is insufficient.

The 200D wrapper checks destination cache aliasing and flushes cached source data before copying. It uses region geometry to support rectangular crops, unlike the 7D2 contiguous-copy fallback. These contracts need explicit review when designing a 750D wrapper.

[017244e8](https://github.com/reticulatedpines/magiclantern_simplified/commit/017244e88b52d0a3879b5ef5dfcce0395c68e619) reports that 10/12-bit modes produced stuck or invalid alternating frames, while 14-bit produced good images on every frame. Therefore a first 750D prototype should target 14-bit output without assuming reduced-bit-depth modes work.

The 6D2 (also DIGIC 7) uses another memory-to-memory wrapper with semaphores, callbacks, power/resource locking, and cleanup that cannot all run in an interrupt context. Its source retains reliability warnings. It is a reference for concurrency and cleanup, not a ready DIGIC 6 driver.

## Same-generation ports that do not supply the missing solution

The reviewed 80D.103 and 5D4.133 configurations also select DIGIC 6 but do not enable `CONFIG_RAW_LIVEVIEW` at this baseline. They can inform shared boot and platform details, but they are not verified RAW-recording donors here. The checked 5D4 port still has placeholder memory-read functions.

## Confirmed 750D gaps

- Missing `RAW_LV_EDMAC_CHANNEL_ADDR`.
- `shamem_read()` in `function_overrides.c` returns zero.
- Missing verified fast-copy equivalent and its cache/channel contract.
- No `CONFIG_EVF_STATE_SYNC`, despite an existing `EVF_STATE` pointer definition.
- No full-width exception in the recorder for 750D.
- Missing `SHAD_GAIN_REGISTER` and no 750D branch defining `PACK32_MODE` / mode constants in `raw_lv_request_bpp()`.
- Recording lifecycle property handling and real frame geometry remain unvalidated.

Target firmware analysis now identifies [two register-shadow reader candidates](750d-register-shadows.md), with their native behavior tested on the PC. Their live-bank coherence and RAW-channel relevance are still unverified, so the platform placeholder remains in place.

A later [target destination trace](750d-raw-destination.md) follows a reviewed branch to channel index 1 / register base `0xD0004100`, stopping before the hardware store. This differs from the 7D2 donor's channel base. It remains a branch-specific candidate, not a platform binding validated for active camera modes.

## Compile-only probe performed

The Windows script now accepts `-ProbeRawBackend`. It compiles only `raw.c`, forcing `CONFIG_RAW_LIVEVIEW` through compiler flags in a separate build directory. It does not edit the camera source, supply invented register values, link a loader, or execute the result.

The probe currently fails as expected with seven undeclared identifiers: `RAW_LV_EDMAC_CHANNEL_ADDR`, `SHAD_GAIN_REGISTER`, `MODE_10BIT`, `MODE_12BIT`, `MODE_14BIT`, `MODE_16BIT`, and `PACK32_MODE`. This is compiler evidence of missing definitions, not a complete list of runtime requirements.

## Concrete initial port strategy

Start with the 7D2 design: Canon-provided RAW stream, verified shadow-register reads, confirmed EVF frame synchronization, full-width 14-bit frames, contiguous fast copy, and the existing MLV writer. Defer horizontal crop, reduced bit depth, and compression. Establish buffer lifetimes and cache behavior before redirecting DMA.

Before an implementation can be trusted, we still need 750D 1.1.0 disassembly or verified address findings for the shadow-reader, RAW channel, event procedure, and fast-copy function. The ROM inspector now includes search markers from the sibling ports: `[MEM1DEV] Addr=%#x Data=%#x`, `Mem1 is Not Complete`, `Nothing DMA ch now!`, and `ResInfo`. A marker is only a lead; the DMA error may identify the slower or unusable copy path, and markers found on DIGIC 7 need not exist on DIGIC 6.

## Source locations

- `platform/7D2.112/{internals.h,consts.h,stubs.S,function_overrides.c,property_whitelist.h}`
- `platform/750D.110/{internals.h,consts.h,function_overrides.c,property_whitelist.h}`
- `platform/200D.101/{consts.h,stubs.S,function_overrides.c}`
- `platform/6D2.111/function_overrides.c`
- `src/raw.c`, `src/state-object.c`
- `modules/raw_video/mlv_lite/mlv_lite.c`

All source locations refer to the pinned upstream commit named above. No code from another camera has been enabled on the 750D by this investigation.
