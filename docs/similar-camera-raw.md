# How related cameras reached RAW video

Source baseline: Magic Lantern `142472e95054d73640f50789ac0fd66325499d82`. Reviewed November 24, 2026. These are source-code findings and developer reports, not tests performed on these cameras by this project.

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
