# RAW start boundaries, pending-address consumption and donor synchronization

The [pointer-provenance investigation](750d-pool-provenance.md) established a conditional preparation-address candidate. This step follows the reviewed non-alternate RAW start route and compares its synchronization requirements with the pinned 7D Mark II implementation. It does not start DMA or prove a completed frame.

## Reviewed start sequence

Driver function source `0xFE750E1C` clears its component mask and chooses a branch using driver state offset 8. In the zero branch, it calls ARM veneer `0xFE74F118` at `0xFE750E52`; the stored target is `0x01BB725D`, corresponding to application source `0xFE8395C4` under the previously scoped mapping. The other branch calls `0xFE74F120`, target source `0xFE839642`. Surrounding OS event operations and the entire driver function are not executed by this experiment.

The non-alternate application path uses its pending address at state `0x01AC2220 + 36`. If nonzero, it calls the previously reviewed address setter, then channel-start veneer `0xFE86F878`. The latter points to runtime `0x8000C57F`, source `0xFE75395E`.

For supplied channel 1, the actual native start helper:

1. Clears software word `0x01AD81C4 + 4`.
2. Reads the control-register shadow for `0xD0004104`, ORs `0x20000000` into it, updates the shadow and prepares the matching physical store.
3. After that call, executes a data-synchronization barrier, prepares value **1** for channel register `0xD0004100`, and updates its shadow before the physical store.

The code order is established. The precise peripheral meaning of control bit 29 is not inferred here. Neither physical store executes: the control stage stops at runtime `0x8000C472` (source `0xFE753852`), and a separately entered post-control tail stops at `0x8000C430` (source `0xFE753810`). No successful hardware operation is modeled between the stages.

Three supplied initial control shadows (0, 8, all bits set) verify preservation of other bits. A fourth check verifies the start-command tail and its address/value. No MMIO region is mapped.

## Pending address is consumed by software

Separate native checks execute configuration setter `0xFE8396B0`, the reviewed post-command tail `0xFE83963C`, and the whole start handler with an empty pending address and null callback. They observe:

```text
configure 0x5C62C000 -> pending address is set
post-command tail  -> pending address becomes zero
empty invocation  -> returns without reaching a register writer
configure a different supplied address -> pending address is set again
post-command tail  -> pending address becomes zero
```

The post-command tail is entered with an explicit saved frame; physical commands and format-register/IRQ helpers before it remain unexecuted. Clearing this software field is not proof that DMA has completed. Another nonzero request requires configuration to repopulate it in this reviewed path. The helper does not itself establish a frame identity or safe copy interval.

## Comparison with 7D Mark II

In pinned Magic Lantern commit `142472e95054d73640f50789ac0fd66325499d82`:

- `platform/7D2.112/internals.h` enables `CONFIG_EVF_STATE_SYNC`.
- `src/state-object.c` invokes `vsync_func` after the original state transition for EVF old state **5**, input **5**.
- `src/raw.c` documents `raw_lv_redirect_edmac` as a VSYNC-hook operation; its ordinary path directly updates the channel address register.
- The 7D2 copy wrapper in `function_overrides.c` uses `_memcpy_fast` and permits whole-row copies with equal widths and zero horizontal offsets. Its comment still flags channel-0 safety across contexts as untested.

The actual 750D EVF table entry for old state 5/input 5 selects source `0xFE2B9536`, labeled `evfReadOutDoneInterrupt`, with next state 5. The probe decodes/checks this entry separately; it does not execute that transition. This is a concrete target-specific correspondence to investigate next. It does not prove that the RAW destination is stable at that hook or that the donor's direct register write is usable from the 750D primary core.

The earlier RAW return event **19**, labeled `evfAfPathCompleteInterrupt`, remains a separate path. It must not be substituted for this donor synchronization condition. No synchronization flag or camera hook is enabled by this comparison.

## Reproduce and limits

The [next investigation](750d-readout-done.md) follows readout-done method dispatch and internal-phase updates, identifying further work that occurs before return. It does not establish a safe copy interval.

```sh
python scripts/probe_750d_raw_start.py /private/750d-analysis/record-06.bin
```

Four start-boundary cases and the separate software pending-address sequence pass. [Machine-readable evidence](evidence/750d-raw-start.json).

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Gates precede Unicorn import. Cortex-A9 executes a compatible instruction subset, not a Cortex-R4 camera system. Scoped read/execute driver/table copies are explicit experiment mappings, not validated boot relocations. Supplied globals, shadows and stack are read/write without execute permission. Code/write guards and 64-instruction / 0.5-second stage limits apply. No native calls are stubbed, MMIO is unmapped, and no pixel memory is supplied.

Next: trace the 750D readout-done handler and next parameter submission to establish the ordering around destination reuse, then identify the cache/copy contract. Real DMA execution, frame contents, live timing and a completed-frame lease remain unverified.
