# Real readout methods prepare StartDriver before completion processing returns

The [previous experiment](750d-readout-done.md) checked registered-method order using native observation leaves. This step selects two actual 750D method rows and executes their real functions. In the enabled-driver fixtures, the completion path prepares a `StartDriver` operation before returning from the completion helper.

This narrows the synchronization problem: a post-state-transition hook cannot be assumed to precede the next start request. It does not prove when the peer actually starts DMA or that copying at any earlier point is safe.

## Native selector and method installation

The method table begins at `0xFEA559F4`, identified through literal `0xFE248B50`. Each row is 72 bytes. The experiment executes the selector core at `0xFE248A12` with two supplied contexts:

- Context offset 0 = 1, offset 8 = 5, offset 4 = 0 selects row **3**.
- Context offset 0 = 2 selects row **9**.

It then executes the post-logging table-publication slice `0xFE2489D2`, which stores the actual row pointer at operation-table registration word `0x27258`. These contexts are fixtures, not measurements of the camera's active operating mode.

For dispatch offsets 32, 8, 28 and 4, row 3 selects source bodies `0xFE28D626`, `0xFE28D3D8`, `0xFE28D5F4` and `0xFE28D3B0`. Row 9 selects `0xFE28FE38`, `0xFE28F8E6`, `0xFE28FE02` and `0xFE28F8BE`.

Row-3 methods contain the legacy `FHD60` logging label. That label does not establish a supported 60 fps mode on the 750D.

## Enabled-driver path

Actual completion helper `0xFE30A6FC` invokes the selected real methods through the previously traced dispatchers. The mode-specific state bases are `0x2F244` for row 3 and `0x2F32C` for row 9. With supplied initialized state, preprocessor flag zero and driver flag at offset 12 equal to one:

1. Offset-32 method reaches its `StopDriver` logging path and returns after the reviewed logging continuation. In the reviewed body this path does not execute a physical stop or establish a DMA wait.
2. Offset-8 method returns through its disabled-preprocessor branch.
3. Offset-28 method enters its `StartDriver` path. It copies the first word at parameter-block address `0x6B380` to the first word of the descriptor referenced by mode state + 32.
4. It calls actual wrapper `0xFE380766`, which prepares service `0x20002`, operation **2**. Native execution continues through `0xFE443016` and stops at transport entry `0xFE48D25C` with arguments `[4, 2, 0x202, descriptor]`.

The offset-4 method and the remainder of completion processing have not yet been reached at that boundary. This proves command preparation occurs inside the completion path under these supplied conditions. No command is sent, delivered to the peer or executed by a DMA engine.

The descriptor's copied word is a parameter marker in the fixture. It is not interpreted as a verified RAW image address or frame identifier.

## Disabled-driver path

With driver flag zero, all four real methods return without submitting this command. The descriptor marker remains unchanged and execution reaches `0xFE2D1346`, the next downstream routine, where it stops. The fixture does not assert that a disabled-driver state occurs during real recording.

## Reproduction and scope

```sh
python scripts/probe_750d_readout_methods.py /private/750d-analysis/record-06.bin
```

Four cases pass: rows 3 and 9, each with supplied driver flag zero and one. [Machine-readable evidence](evidence/750d-readout-methods.json).

Requires Unicorn 2.1.4 and exact main-record size `0xCFB688`, SHA-256 `3e9839972e28d659275ce27f8013629fbea5a34ff47a00d4f0df0715118f53a2`. Input gates precede import. Cortex-A9 executes compatible instructions, not a Cortex-R4 camera system. Code is read/execute; supplied context, globals, descriptor and stack are read/write without execute permission. Guards restrict reviewed execution and writes to the registration word, descriptor word and stack. Each native stage is limited to 256 instructions / 0.5 seconds.

Selector and table-publication cores enter after their loggers with explicit registers/saved frames. During real method execution, the experiment stops before logging and resumes only at the two reviewed continuations, preserving the native call frames. The continuation code does not consume a logger return value. No CPU return is synthesized and no native function is stubbed into success.

The next useful interception candidate is before submission of `StartDriver`, together with a verified RAW-completion condition and cache contract. This is a research boundary, not an enabled hook or a guaranteed frame lease. Other methods, live activation, OS transport, peer timing, pixels and buffer reuse remain unverified. The [subsequent start-gate experiment](750d-start-gate.md) establishes why the driver's event wait alone cannot prove RAW-DMA completion.
