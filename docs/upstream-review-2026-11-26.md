# Magic Lantern and donor source review: November 26, 2026

This is a fresh bounded read-only review, not a claim about every public fork. No camera files were installed, no developer was contacted, and our pinned upstream worktree was not switched. [Branch/file evidence](evidence/upstream-review-2026-11-26.json) records exact heads and relevant file identities.

## Upstream and 750D-focused branches

- [Upstream dev](https://github.com/reticulatedpines/magiclantern_simplified/tree/142472e95054d73640f50789ac0fd66325499d82) still resolves to our baseline `142472e95054d73640f50789ac0fd66325499d82`. The 750D platform does not enable `CONFIG_RAW_LIVEVIEW`, lacks `RAW_LV_EDMAC_CHANNEL_ADDR`, and its `shamem_read` still returns zero.
- [Upstream edmac_cleanup](https://github.com/reticulatedpines/magiclantern_simplified/tree/562c699589a98989e66ff2d0634748cf0f14bc44) remains at `562c699589a98989e66ff2d0634748cf0f14bc44`, the same head as the previous review. Comparing its actual Git tree against our baseline changes only one 750D platform path: an empty `edmac_per_cam.h`. It supplies no RAW binding.
- [Tragic Lantern main](https://github.com/paweltokarz/tragiclantern/tree/aa224f0bc8e177a456c119eba00263488ee51f5a) and `lua-750d-on-ptp` still resolve to `aa224f0bc8e177a456c119eba00263488ee51f5a`. The additional `upstream/750d-include-lua-module` and `upstream/750d-show-lua-module` heads were also enumerated and their three key platform files inspected. In all four branches, `internals.h`, `function_overrides.c` and `consts.h` have the same blob identities as our baseline. No RAW implementation was added in those files.
- Kitor's [raw_draft](https://github.com/kitor/magiclantern_simplified/tree/623fe9ce969510b5fa71a839448ebb7b372f5ff9), [raw_draft_v2](https://github.com/kitor/magiclantern_simplified/tree/26822466884ba43bc21cefc49346706638cb7fa3) and [d6_rom_patching](https://github.com/kitor/magiclantern_simplified/tree/fcc52129d9a65250d477af45e2ea4f974531fa8f) heads match the previously reviewed revisions. This head comparison does not claim inspection of every contributor branch.
- A search surfaced the [ChaseChanCN localization fork](https://github.com/ChaseChanCN/magiclantern/tree/a41f406a6c50b998089fa65dc1d70164d2da40b8). Its camera build listing and general RAW-feature description are not evidence of RAW on every listed camera. At the verified master head, the same three 750D files have baseline-identical blobs and the same missing bindings.

The GitHub connector successfully read repository/file content, but its branch-search action failed. Exact branch enumeration and the cleanup comparison therefore used Git directly. Only repository metadata/objects were fetched; the working baseline stayed pinned. The web reader returned HTTP403 for the 750D Midsummer forum topic, so no new forum posts are asserted in this review.

## Working-camera comparison

The closest reference remains **7D Mark II**, sharing DIGIC6/Cortex-R4 with the 750D while also having dual DIGIC hardware. At our pinned revision, its RAW recorder redirects the upcoming frame, processes the opposite buffer and uses a Canon fast linear copy wrapper. Our investigation has explicitly compared that ordering with the 750D readout/StartDriver path, rather than treating a RAW callback as proof of a frame lease.

The newer cleanup branch moves the 7D2 copy implementation from platform overrides into `src/edmac.c`, selects `CONFIG_EDMAC_MEMCPY` and **`CONFIG_EDMAC_COPY_RECT_V3`**, and provides synchronous `copy_rectangle()`. Its implementation uses `_memcpy_fast(channel, destination, source, bytes)` with channel 0. It retains equal-stride/full-width checks and rejects horizontal offsets. The channel's all-context safety remains qualified by an upstream comment. It does not resolve direct ICU control of Omar sensor EDMAC or provide 750D addresses.

For a future integration, the distinction matters: older module code manually waits for a copy callback/semaphore, while the cleanup API returns after copying and removes that responsibility from module call sites. Our experimental synchronous copy-engine contract is compatible with that architectural direction, but has no enabled Canon backend.

The same cleanup head selects **V1 on 200D** and **V2 on 6D2**, both DIGIC7. Their implementations use different region/resource/semaphore paths and retain uncacheable destination and source-cache handling. They are useful references for copy ownership and cleanup, not interchangeable DIGIC6 bindings. We do not transplant their channels, addresses or cache assumptions to the 750D.

`raw_vidx` also changes its worker to use `copy_rectangle()` and removes module-managed copy semaphore callbacks in this branch. A simpler recorder still depends on a valid RAW source, packing/geometry, destination redirection and a real copy backend. It does not bypass milestones 4/5 of the [roadmap](roadmap.md).

## Decision

Continue the target-specific capture/completion investigation, retain 7D2's full-width 14-bit/synchronous-copy approach as the first integration reference, and account for the newer copy API when writing the eventual adapter. No checked upstream change eliminates the 750D source/completion/cache gaps. The current baseline and disabled camera bindings remain unchanged.
