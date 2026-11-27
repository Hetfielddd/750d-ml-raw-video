# Roadmap to first Canon 750D RAW recording

Reviewed November 27, 2026. Target: 750D firmware 1.1.0. This consolidates the earlier plan and saved project status into eight acceptance milestones. It separates completed PC preparation from camera integration; the milestone count is not a percentage of development time.

## Completed on the PC: 3 milestones

1. **Source, donor research and build environment.** Pinned ML source, Windows ARM toolchain, core/loader builds and bounded native-code execution are available. The closest working reference is 7D2/DIGIC6; 200D/6D2 are secondary DIGIC7 references. Camera execution is not part of this acceptance criterion.
2. **Readable target code.** The identified 750D 1.1.0 main-code update record was recovered privately and is used by identity-gated probes. This is not a reconstructed full ROM or a booting camera emulator.
3. **Offline recording pipeline.** Original RAW14 copy/queue/MLV/FIO/source-lifetime components execute with synthetic frames, including overflow and partial-write handling. The PC disk bridge has independently checked 36 recorded payloads from 48 synthetic submissions. This is reusable recorder logic, not sensor recording.

## Partially complete: 2 milestones

4. **Target-specific capture and copy bindings.** Candidate RAW address/channel, parameter routing, register shadows, geometry arithmetic and a primary fast-copy candidate have been traced and tested in bounded fixtures. Live geometry, packing, active mode/channel ownership and safe calling context remain unverified. Camera bindings are disabled.
5. **Completed-frame ownership and safe copying.** Native command order, notification routes, stop-like requests, event flags and several candidate completion chains are characterized. A qualified whole-frame completion event, its exact buffer identity, safe reuse interval and cross-core/cache contract are not yet established. This is the principal research uncertainty before a real source adapter can be trusted.

   The native EVF event-5 message traces to `HEAD2` line timing with zero payload. Its downstream completion method can prepare the next `StartDriver` before returning. The remaining check is to associate RAW DMA completion with the address consumed at start and validate the copy interval. [EVF readout source](750d-evf-readout-source.md).

## Not complete: 3 milestones

6. **Camera recorder integration.** Connect verified capture/copy bindings and Canon file operations to the recorder, then build the camera-facing module. The source provider currently accepts PC synthetic sources only. Existing offline code does not complete this milestone.
7. **First real recording.** With separately authorized camera testing, obtain and independently inspect a real frame, then a short RAW sequence/MLV clip. Check packing, dimensions, frame order, image integrity and correct start/stop. No real sensor frame has been acquired by this project.
8. **Reliable usable recording.** Measure sustainable resolution/frame rate/card throughput, dropped frames, repeated start/stop, cleanup and longer-run stability. Synthetic timing cannot establish camera performance.

## What remains

Five milestones are not closed: two have partial research results, and three require integration/real-camera acceptance. The completed preparation milestones do not have the same effort or uncertainty as the remaining capture milestones. Counting native probes, lines of code or commits does not provide an honest percentage-to-working-RAW or a reliable calendar ETA.

The nearest useful research result is a justified completed-frame/copy contract for milestone 5, alongside validated format/copy requirements from milestone 4. It would make the camera source adapter concrete. It would still not substitute for milestone 7's image evidence.

The owner's PC-only constraint remains in force. No camera/SD installation or external contact is required by the current work. Real sensor recording cannot be validated by our bounded Unicorn fixtures; full-camera RAW emulation has not been demonstrated.

## Donor and upstream review

The [November 26 source audit](upstream-review-2026-11-26.md) rechecked upstream ML, the 750D-focused Tragic Lantern branches, relevant contributor branches and a localization fork. It also compared 7D2's newer V3 copy API with DIGIC7 V1/V2. No new 750D RAW implementation was found in the checked sources. The pinned baseline remains unchanged.
