# Canon 750D RAW video research

Research into adding RAW video recording to Magic Lantern on the Canon EOS 750D / Rebel T6i, running Canon firmware **1.1.0**.

**RAW video recording is not implemented yet.** Development has taken place on a PC only. No experimental code has been installed or run on the project owner's camera.

## Current progress

- Magic Lantern is pinned as a Git submodule at commit `142472e95054d73640f50789ac0fd66325499d82`.
- The upstream core and loader have been compiled and linked on Windows using Arm GNU Toolchain 13.3.Rel1, with `CONFIG_QEMU=y` and module/TCC support.
- A Windows build script and a read-only FIR inspection script are included.
- The official Canon 1.1.0 update container was inspected. Its structural checksum passes; the firmware payload remains encrypted.
- A public EOS M3 DIGIC 6 ROM now supplies a working PC crypto reference: native AES and CBC wrapper tests pass, but direct application to the 750D FIR fails length bounds. See [the experiment and limits](docs/m3-crypto-reference.md).
- The 7D Mark II frame-copying implementation has been reviewed as a possible reference for a future 750D port.
- The experimental ARM copy/queue/MLV path now writes synthetic clips through a PC filesystem test bridge, including queue overflow and partial-write rollback checks.

Full-camera QEMU emulation has not been run. The separate experimental components execute under Unicorn ARM emulation. Camera modules and an installation ZIP have not been built. These tests do not validate RAW capture or operation on physical hardware.

## Getting the source

```sh
git clone --recurse-submodules https://github.com/Hetfielddd/750d-ml-raw-video.git
cd 750d-ml-raw-video
```

For an existing clone:

```sh
git submodule update --init
```

The `magiclantern` directory points to an exact upstream revision. Camera source code has not been modified. Future camera changes should be committed to a project-owned fork, followed by an update to this submodule reference.

## Documentation

- [Research status and remaining work](docs/status.md)
- [Windows build instructions](docs/build-windows.md)
- [Information needed from developers](docs/developer-request.md)
- [Read-only ROM inspection and November research refresh](docs/rom-analysis.md)
- [Read-only Thumb address-load candidate search](docs/thumb-xrefs.md)
- [Public M3 DIGIC 6 ROM and bounded native crypto experiment](docs/m3-crypto-reference.md)
- [How related cameras reached RAW video and the 750D port strategy](docs/similar-camera-raw.md)
- [Experimental C frame-copy component and ARM execution tests](docs/raw14-copy-core.md)
- [Experimental frame queue and writer ownership](docs/raw14-queue.md)
- [Experimental MLV writer and end-to-end verification](docs/raw14-mlv-writer.md)
- [ARM recording to PC files and Canon FIO integration findings](docs/raw14-disk-bridge.md)
- [FIO contract adapter and recording without truncation](docs/raw14-fio-adapter.md)
- [Completed-frame source ownership and donor callback analysis](docs/raw14-capture-source.md)
- `scripts/inspect_750d_fir.py`: read-only structural inspection of a locally supplied Canon update file.

## License and attribution

Magic Lantern is a separate upstream project. Its license notices and contributor attribution are retained in the submodule. Original project scripts are distributed under GPL-2.0-or-later; see [COPYING](COPYING).

Research, documentation, and original scripts were prepared with assistance from OpenAI Codex. No independent hardware validation has been performed.

Canon firmware, ROM dumps, downloaded toolchains, and project build outputs are not included. The upstream submodule retains its original tree, including upstream's historical binary resources.
