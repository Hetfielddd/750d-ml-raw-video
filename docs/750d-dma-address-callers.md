# Native callers of the 750D DMA address reader

The driver's current-address function at source `0xFE75501E` is called through ARM veneer `0xFE86F5F0`, whose literal selects runtime `0x8000DC3F`. Reviewed callers include an Image2 diagnostic and the Live View SAF path shutdown. Their uses establish when Canon samples the physical DMA address in these paths. The tested callers send those values to a logger.

## Live View shutdown

Two peer routines beginning at `0xFE822560` and `0xFE822C46` set their respective owner field at offset 32 to one with IRQs masked. They restore the previous mask and prepare a wait request using the handle at offset 36, mask `0x7F` and option 0. Both native prefix checks stop before the wait veneer `0xFE86F758`. Previously reviewed RAW component notifications can set one of these bits without a DMA transfer. [RAW event-flag comparison](750d-raw-notification.md).

Separate native shutdown tails beginning at `0xFE8225AC` and `0xFE822C9E` call the RAW helper at `0xFE839690` and then call `LV_SAF_PATH_Stop` at `0xFE83A724`. In the supplied non-alternate RAW case, the first helper writes `0x80000000` to `0xD0008090` and its shadow, preserving the pending RAW address. It performs no channel-address read. The supplied uninitialized RAW case skips the store. The physical effect of that command is outside the experiment.

When SAF is enabled, its stop routine reads the channels stored at SAF state offsets 40 and 36, in that order, through the actual address import and driver body. Those indices come from input offsets 16 and 4 at two independently entered native SAF publication slices. The two sampled words become the `LV_SAF_PATH_Stop` log arguments in the opposite order. Swapping the fixture's SAF channel indices swaps the physical reads and logged markers. When SAF is disabled, this routine returns without either read. The next native slice after the logger passes literal `2` to a helper. It does not compare the two logged addresses or compute a byte count there.

The probe supplies the code with initialized or inactive RAW and SAF state and SAF channel indices 1 and 2. Those indices exercise the data flow and do not establish which channels a camera mode chooses. The shutdown tails are entered after explicit cuts for the wait and intervening cleanup calls. Those cuts leave live wait satisfaction, scheduling, complete teardown and the timing of the samples relative to actual sensor DMA unresolved.

## Channel-1 Image2 diagnostic

The reviewed caller at `0xFE8255BA` selects channel 1, reads `0xD0004108` through the same import and passes the word to the `Image2 Wr Addr` logger. Static review identifies other calls in the same diagnostic family for additional channels. The PC check executes the channel-1 call through the real driver, up to the logger entry.

This confirms that Canon reads the physical word already identified on the RAW register block. The tested paths use the word for diagnostics, including during a neighboring Live View path's shutdown. A RAW recording adapter still needs an event and an address that refer to the same completed capture before a new start can reuse the buffer. [RAW setup and address shadow comparison](750d-raw-command-order.md#native-raw-setup-compared-with-ipc).

## Reproduction

```sh
python scripts/probe_750d_dma_address_callers.py /private/750d-analysis/record-06.bin
```

Nine checks pass, comprising two wait prefixes, six shutdown tails and one Image2 call. The exact main-record identity is verified before importing Unicorn 2.1.4. Execution and read/write guards bound the native slices to 160 instructions and 0.5 seconds. Register addresses are passive RAM with supplied values. Logging and subsequent helper calls are explicit boundaries. No native function is stubbed into success. DMA, pixels and camera bindings remain outside the experiment. [Machine-readable results](evidence/750d-dma-address-callers.json).
