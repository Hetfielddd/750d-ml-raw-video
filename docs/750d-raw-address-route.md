# 750D RAW address preparation traced and tested on the PC

This step follows the actual 750D 1.1.0 main-code record recovered in the [plaintext milestone](750d-plaintext-milestone.md). A bounded experiment executes the RAW setter, the address-selection slice with its real getters, and the parameter publisher. Seven synthetic-state cases pass. No pixels, DMA registers or sensor events are emulated.

The important result is a traced preparation address, not a completed-frame source. The existing recorder's camera-source gate remains closed.

## Target-specific path

All runtime addresses below refer to the `0xFE000000` alias. The input is record 6 at `0xFE0A0000`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. File offsets in candidate reports are relative to that record.

1. The previously verified `lv_save_raw` setter at `0xFE308EB4` stores its argument at state `0x2AF78 + 4`. Getter `0xFE309CF0` reads that same word. Related getters expose offsets 8, 12 and 44.
2. Handler `0xFE2B90A2`, labeled by its debug text as `evfSetParamInterrupt`, loads the EVF state base `0x26B94` into R7. Its raw-related selection slice is `0xFE2B92AE..0xFE2B9324`.
3. The slice initially stores R8 as the fallback parameter at stack offset `0xDC`. It only considers the RAW state if caller field R4+`0x34` is nonzero.
4. When the RAW flag is enabled and the selection restriction at RAW-state offset 8 is zero, it loads EVF-state offset `0x58` into that stack parameter. If the restriction is enabled, RAW-state offset 44 must equal EVF-state offset `0x18`; a match chooses the address and clears the selection tag. A mismatch preserves the fallback. The EVF counter also increments in the earlier handler path; its complete lifecycle is not yet established.
5. Publisher `0xFE309F14`, reached through wrapper `0xFE30A0BC`, copies the selected input field at offset `0x1C` into global parameter locations `0x6B370` and `0x6B3E0`. The handler passes its stack block at `SP+0xC0`, making the field correspond to `SP+0xDC`.

Thus EVF-state word `0x26BEC` is an observed input to RAW preparation in this branch, while `0x6B370` and `0x6B3E0` are cached preparation parameters. None is established as a safe readable buffer containing a finished sensor frame. Their runtime values, allocation rules, cache attributes and reuse timing remain unknown.

## Native execution experiment

```sh
python scripts/probe_750d_raw_route.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and the exact identified main-code record. The experiment maps the record read/execute and explicit synthetic RAM regions read/write without execute permission. It first invokes the actual setter, enters the address-selection slice with specified incoming registers and stack, stops at its boundary, and invokes the actual publisher directly. The setter's getters are not replaced.

This is deliberately not execution of the entire `evfSetParamInterrupt` handler or its complete wrapper/caller chain. Incoming state is synthetic and intermediate setup is supplied by the experiment. Only debug logger `0xFE3CE0FC` is stubbed; it immediately returns without providing a modeled return value. No assertions, allocators, DMA functions, pixel buffers or filesystem operations are stubbed into successful capture.

An instruction-range guard rejects execution outside the identified routines/slice and logger. A write-range guard permits only the RAW state, expected parameter storage and scratch RAM. Each stage is limited to 2,000 instructions and one second.

Seven cases pass:

- RAW disabled, with and without a pending auxiliary word: retain fallback.
- RAW enabled without a selection restriction: choose the EVF-state candidate.
- RAW enabled with a nonzero auxiliary word: setter clears it and the candidate is chosen.
- Restricted selection with matching counter: choose the candidate and clear the tag.
- Restricted selection with a mismatching counter: retain fallback and preserve the tag.
- Caller route inactive: retain fallback even when RAW is enabled.

The two distinct address values are test markers, never mapped or dereferenced. In every case the selected marker reaches both native publisher destinations. [Machine-readable result](evidence/750d-raw-address-route.json).

## Downstream path and the remaining completion gap

Static analysis follows these parameters into global state beginning at `0x6B31C`, through `0xFE30A6CC` / `0xFE1C6C3E` and a mode-specific interface table. The table at `0xFEA559F4` has 72-byte entries; `0xFE2489C0` selects an entry by mode. Reviewed examples include paths labeled `Rec_FHD_60fps` and `Rec_FHD_LevelThree`. Those configuration methods copy prepared fields into their own driver structures. This does not establish which mode is active on the owner's camera or a physical DMA register binding.

The handler labeled `evfReadOutDoneInterrupt` starts at `0xFE2B9536` and calls a separate interface path through `0xFE30A6FC`. Its label alone is insufficient to establish that the RAW destination DMA has completed. We have not connected its timing to ownership of the selected memory region.

A literal matching the 7D2 donor's `0xD0004200` does occur in the target image. The directly reviewed reference is a diagnostic read, and another raw-byte match is inside an unrelated instruction encoding. Neither identifies the 750D RAW Live View channel. The donor address has not been copied into the camera platform.

The [next investigation](750d-register-shadows.md) identifies two target register-shadow readers and traces parameter submission into a Postman mailbox sender. It does not yet identify the peer's image writer or establish DMA completion.

Next work is to identify the writer that fills the selected region, its geometry/packing and a completion event with a demonstrable buffer lifetime. Only then can a real provider satisfy the offline recorder's completed-frame lease contract. No real frame acquisition, full-camera emulation, hardware execution or RAW recording is claimed here.
