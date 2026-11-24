# RAW geometry traced through the target configuration and DMA packer

The [candidate RAW destination](750d-raw-destination.md) investigation identified a reviewed channel-1 preparation branch. This step follows its geometry fields through actual 750D code and executes six synthetic-input cases on the PC. It establishes how values are propagated and encoded, not the dimensions of an active camera mode.

Input is the exact 750D 1.1.0 main-code record, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`, at the `0xFE0A0000` source alias. No firmware bytes or disassembly are published.

## Field route

The handler labeled `evfSetParamInterrupt` receives a dynamic caller structure in R0 and holds it in R4. Its slice `0xFE2B9280..0xFE2B92AE` copies caller offsets 108..136 into its stack block. The surrounding handler chooses this branch conditionally; the experiment enters it directly with supplied state.

For the reviewed RAW geometry fields:

- Caller +108 goes to stack +`0xEC`, then publisher-input +44, global configuration +124, driver parameters +148, and RAW-initializer parameter +4. This is a separate packing/control selector, not a bits-per-pixel count.
- Caller +112 goes through input +48, configuration +128, driver +152, and RAW-initializer parameter +8. Zero selects 14 for the native row-size calculation; the tested nonzero value 1 selects 16.
- Caller +116 goes through input +52, configuration +132, driver +156, and RAW-initializer parameter +12. It is the width multiplier for that row-size calculation.
- Caller +120 goes through input +56, configuration +136, driver +160, and RAW-initializer parameter +16. The native code subtracts one to prepare the DMA row-repeat count.
- Caller +124 goes through input +60 to configuration +140. In the reviewed mode-3 method, a nonzero value selects the auxiliary structure whose first word is channel index 1.

Publisher `0xFE309F14` receives the stack block at `SP+0xC0` and writes the configuration beginning at `0x6B31C+0x74`. Configuration slice `0xFE28D9F6..0xFE28DA36` then creates the driver block beginning at offset 144. This is the same structure that the previously traced driver initialization passes to the RAW initializer; that complete driver/initialization call chain is not executed in this experiment.

The native arithmetic at `0xFE83952C..0xFE839536` and `0xFE83954E..0xFE839560` produces:

```text
row_bit_multiplier = format_flag == 0 ? 14 : 16
line_bytes = (width * row_bit_multiplier) >> 3
yb = height - 1
```

The surrounding code also writes format/control registers, but those writes are not executed. A 16-bit arithmetic case is not proof of an enabled, usable 16-bit sensor-recording mode. Sensor bit depth, row packing, black borders and Bayer layout must still be checked against real image data when hardware work is separately authorized.

## Native DMA packing

The calculation writes `xb` at byte offset 24 and `yb` at offset 32 of a zeroed descriptor. Driver routine `0x8000C67E`, corresponding to source `0xFE753A5E` under the scoped alias reconstruction, reads that descriptor and prepares eight words for the channel registers. Its actual shadow-reader dependency executes as well.

For the simple supplied descriptor, the word intended for the channel's `yb_xb` register is:

```text
packed_yb_xb = (line_bytes | (yb << 16)) & 0x7FFFFFFE
```

The experiment stops at `0x8000C700`, before the packer invokes any physical-write helper. It neither writes geometry registers nor transfers pixels. The descriptor scratch is explicitly zeroed by the experiment to represent the surrounding initializer's cleared scratch; the initializer and its clearing call are not run.

## PC results

```sh
python scripts/probe_750d_raw_geometry.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and the exact record. All six cases pass their expected results:

- Supplied 2048 x 1080 with flag 0 produces 3584 bytes per row and `yb=1079`.
- The same supplied dimensions with flag 1 produce 4096 bytes per row.
- Supplied 1984 x 1080 and 2056 x 720 exercise different valid row sizes and heights.
- An intentionally invalid width of 9 at multiplier 14 first truncates to 15 bytes, then the packer's mask reduces the encoded row size to 14 bytes.
- An intentionally invalid height of zero underflows to `0xFFFFFFFF`; its encoded height-minus-one becomes 32767. These native slices do not reject it.

These dimensions are fixtures. In particular, the 1984-pixel case is not a measurement or resolution promise for 750D. The invalid cases characterize why native arithmetic alone cannot validate geometry; they are not supported modes or successful frame captures. [Machine-readable evidence](evidence/750d-raw-geometry.json).

The experiment executes separate native slices with explicit registers and synthetic RAM, without native-call stubs. Read/execute mappings contain the record and narrowly reconstructed driver/table aliases; only explicit state/scratch/shadow regions are writable and non-executable. Instruction-range and write-range guards plus 512-instruction / 0.5-second stage limits bound execution. No MMIO or pixel memory is mapped. Unicorn's Cortex-A9 model runs the compatible instruction subset, not a Cortex-R4 camera system.

## Consequence for the port

The target-specific route now explains where width, height and the row-size selector enter this branch, and how its DMA geometry word is formed. The remaining work is to establish the actual caller values and active-mode conditions, confirm the packing on pixels, and connect completion to safe buffer ownership. None of these synthetic tests establishes a live RAW frame. The platform and camera-source gate remain disabled.
