# Experimental RAW14 frame-copy component

This is the first original C component intended for a future 750D RAW port. It implements a bounded, synchronous full-width frame-copy contract, following the *design constraints* of the 7D2 path. It is separate from upstream Magic Lantern and is not wired into the 750D recording module yet.

The project can implement and test this transfer logic without knowing Canon firmware addresses. A later camera adapter must supply an independently verified synchronous copy function, geometry, buffer capacities, cache handling, and serialization.

## Interface

`experimental/raw14_copy.h` defines frame descriptors (data, capacity, width, height, pitch, bit depth) and a copy engine with an injected synchronous backend.

`raw14_copy_rows()` supports:

- Packed 14-bit frames with four pixels per seven bytes and no row padding.
- Equal full source and destination widths.
- Vertical row selection with even source/destination offsets and an even row count, preserving Bayer parity relative to the input.
- Exactly one completion callback after successful backend completion, with the original callback context and copied byte count.
- Explicit status values for invalid arguments, unsupported geometry, buffer bounds, overlapping transfer ranges, reentrancy, missing backend, and backend failure.

The code checks multiplication and address-range overflow using 32-bit target limits before forming transfer pointers. Invalid requests never invoke the backend or completion. A failed backend does not publish completion and releases the engine for a subsequent submission. Backend failure can still leave partially modified destination bytes; the caller must discard that frame.

The busy flag detects nested calls from the backend and completion callback. It is **not** a concurrency lock. Camera integration needs external serialization, verified cache coherency, frame/DMA ownership, and an appropriate execution context. The component does not start or redirect DMA or infer a capacity from an untrusted pointer.

This intentionally has a different API from upstream `edmac_copy_rectangle_cbr_start`: that API does not receive explicit buffer capacities. Integration must obtain real allocation/geometry metadata instead of guessing sizes to fit this interface.

## ARM execution tests

Install the test dependency into your chosen development environment:

```sh
python -m pip install -r experimental/requirements-test.txt
```

Run with the Arm GNU 13.3.Rel1 bin directory:

```sh
python scripts/test_raw14_arm.py --toolchain /path/to/toolchain/bin
```

The runner compiles `raw14_copy.c` and its C test harness with `-mcpu=cortex-r4 -mthumb`, freestanding C99 and warnings as errors. It executes the resulting ARM ELF in Unicorn's Cortex-R5 CPU model, which provides the ARMv7-R instruction environment used here. It does not emulate Canon's Cortex-R4 peripherals or memory/cache timing.

The test backend copies bytes in a CPU loop. A synthetic frame tests full-width vertical selection, exact output bytes, unchanged guard areas, full-frame transfer, source/destination bounds, oversized row counts, unsupported bit depth/pitch/width/parity, missing arguments/backend, address overflow, overlap, backend failure/recovery, callback ordering/context, and nested calls. The emulated test has a fixed RAM map, instruction limit, and timeout; accidental access to camera MMIO is unmapped.

These tests execute the actual compiled C implementation with 32-bit ARM pointer arithmetic. They do not validate RAW capture, Canon DMA, performance, Bayer color interpretation, MLV output, or stability on a camera.

## Integration work remaining

A separate [frame queue](raw14-queue.md) now provides publication and writer ownership. The ARM test runner executes both suites; neither is wired into the upstream recorder yet.

1. Supply descriptors from verified Canon/ML buffer allocation metadata.
2. Wrap a verified 750D synchronous copy primitive with the correct cache and channel contract.
3. Connect the successful completion path to recorder slot publication; reject or discard failed frames.
4. Coordinate EVF synchronization and capture-buffer redirection with the recorder, using verified 750D register/function addresses.

Camera-side source and the pinned Magic Lantern submodule are unchanged. This component is GPL-2.0-or-later and was produced with OpenAI Codex assistance.
