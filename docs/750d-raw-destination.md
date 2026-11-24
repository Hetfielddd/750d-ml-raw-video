# RAW preparation reaches a candidate DMA destination on the PC

Following the [message-boundary investigation](750d-register-shadows.md), a bounded native experiment now follows one reviewed 750D path from its configuration fields to the first physical DMA-address store. It stops before that store. It also verifies channel callback registration and forwarding through a separately invoked interrupt-dispatch tail.

The concrete result is **channel index 1, register base `0xD0004100`, destination register `0xD0004108` in this reviewed path**. This is stronger evidence than a register-looking literal or a donor address. It is not a validated Live View channel binding for every mode, and it has not been enabled in the camera platform.

Input is the identified 750D 1.1.0 main-code record at the `0xFE0A0000` alias, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`.

## Static route and scoped address correspondence

Further analysis finds an application handler table at `0xFE9744F4`, including handler `0xFE80FDF4`. That handler passes its argument through an ARM veneer at `0xFE86F298` to driver entry `0x80009B21`. An address correspondence places that driver body at source location `0xFE750F00`. The complete mailbox-to-state-machine dispatch has not been executed or validated.

Two scoped source/runtime correspondences make the reviewed absolute calls intelligible:

- In the reviewed application functions, source address equals runtime address plus `0xFCC82368`. For example, stored pointers `0x01B8401D` and `0x01B84039` correspond to the two dispatchers at `0xFE806384` and `0xFE8063A0`. Multiple stored callback pointers agree with that difference.
- In the reviewed imported driver functions and channel table, source address equals runtime address plus `0x7E7473E0`. Examples include imported entry `0x80009937` / source `0xFE750D16`, entry `0x8000C427` / source `0xFE753806`, and channel table `0x8000F8D4` / source `0xFE756CB4`. Channel-table callback pointer `0x8000D1ED` corresponds to the common interrupt handler at source `0xFE7545CC`.

The experiment copies only narrow function/table windows into these runtime aliases. This is an explicit reconstruction used by the experiment, not execution or proof of the boot loader's relocation process. No complete ROM image or contiguous application memory map is asserted.

## Configuration to address store

1. The mode-3 method previously identified as `Rec_FHD_60fps` copies input offset 80 into driver-parameter offset 200. Its slice `0xFE28D9D6..0xFE28DA36` also writes **1** to driver offset 144 when input offset 140 is nonzero, followed by related fields. The method's source label does not establish that the owner's camera exposes a 60 fps recording mode.
2. Driver initialization at source `0xFE750DA6` passes the structure beginning at driver offset 144 through veneer `0xFE74F110`. The corresponding application initializer is source `0xFE839410`. Its reviewed slice copies the first word into state `0x01AC2220 + 28`, the channel index. In this branch that word is 1.
3. Driver configuration at source `0xFE750F2C` passes driver offset 200 through veneer `0xFE74F130`, stored target `0x01BB7349`, to application body source `0xFE8396B0`. That body records the pending address at state offset 36 and the following parameter at state offset 44.
4. Application routine source `0xFE8395C4` checks the state. In the reviewed non-alternate branch it reads the pending address, passes channel index 1 and that address through veneer `0xFE86F858` to `0x8000C655`, source `0xFE753A34`.
5. That driver's channel classifier consults RAM. With the experiment's supplied normal-channel classification, it clears address bits 30 and 31, looks up table entry 1, adds 8 to its register base, and invokes the physical-plus-shadow word writer. The actual table entry has register base `0xD0004100`.
6. The writer first updates the register shadow and is then about to store the same word to `0xD0004108`. The experiment stops before the physical store at runtime `0x8000C430`.

The earlier 7D2 donor uses `0xD0004200`. It has not been copied into this port. The reviewed 750D mode-5/9 configuration method also statically writes 1 to offset 144 in its corresponding branch, but that complete path is not part of this native experiment. Mode selection, real initialization and hardware activity still require further validation.

## Channel callback evidence

The initializer's slice at source `0xFE839462` registers application callback `0x01BB709B` for this channel through driver entry `0x8000CF4B`, source `0xFE75432A`. The actual registration code stores the callback, argument and enable word in the channel-1 record at `0x01AD8350`. The experiment stops before the platform interrupt-registration call.

Static review of the common channel handler shows a physical status read, register acknowledgement/control writes, then a tail that selects the channel callback. The experiment invokes **only that tail**, at runtime `0x8000D23E`, using a supplied saved-register frame. It follows the actual registered application callback, which forwards to the function and argument in RAW state offsets 8 and 12. A distinct synthetic callback endpoint receives the expected argument.

This proves the reviewed callback-table and forwarding behavior. No physical interrupt, status check, acknowledgement or completed pixel transfer occurs. Even the zero-pending-address case can forward this artificially invoked tail, demonstrating why callback execution alone cannot establish a completed-frame lease.

## Native experiment and results

```sh
python scripts/probe_750d_raw_destination.py /private/750d-analysis/record-06.bin
```

Requires Unicorn 2.1.4 and the exact record. Four cases pass:

- A plain address marker reaches the pending state, shadow and prepared destination store.
- Markers with bit 30 or bit 31 set reach the same destination after the driver's actual alias-bit clearing.
- A zero pending address returns without an address-store attempt.

Each case also verifies the native channel callback record and argument forwarding through the artificial dispatch tail. [Machine-readable evidence](evidence/750d-raw-destination.json).

The stages execute separately with explicit incoming registers and synthetic RAM. The experiment does not execute the complete configuration method, complete initializer or mailbox transfer. Actual mixed ARM/Thumb veneers and reviewed helper functions execute without stubbing calls into success. Instruction/write guards and per-stage limits of 256 instructions / 0.5 seconds bound execution. The Cortex-A9 model executes this compatible instruction subset; it is not a Cortex-R4 camera model.

Code/table aliases are read/execute; scratch state and a synthetic shadow bank are read/write without execute permission. No MMIO or pixel buffers are mapped. The address values are markers, never buffers read for pixels. SHA-256 and size checks reject the wrong input before emulation.

## Remaining gap

We now have a firmware-derived candidate destination and a channel callback route for a specific branch. We still lack a verified active-mode selection and live memory map, frame geometry/packing, cache and reuse rules, and evidence connecting the callback to a complete stable sensor frame. The recorder's camera-source gate remains closed. The next useful steps are to trace the geometry inputs and the callback's actual callers/aggregation, rather than enable a register address from this experiment alone.
