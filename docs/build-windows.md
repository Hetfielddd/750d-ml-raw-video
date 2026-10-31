# Building on Windows

The script builds the QEMU-configured core and loader ELF. It does not access a camera or SD card and does not create an installation ZIP.

## Prerequisites

- Arm GNU Toolchain 13.3.Rel1 for Windows, extracted into your tools directory.
- GNU Make for Windows. The tested environment used mingw32-make 4.2.1.
- Python 3.13 and Git available to the build process.
- [BusyBox for Windows](https://frippery.org/busybox/).

The tools directory needs ordinary copies of BusyBox under these executable names:

```text
sh pwd mkdir cp mv stat grep awk date whoami printf touch sort
which cat echo rm head tail sed wc ls cmp find
```

Each name above needs the `.exe` extension. Also provide:

- A local copy of Python's `python.exe` named `python3.exe`. Set PythonHome to the original Python installation.
- A copy of `arm-none-eabi-readelf.exe` named `readelf.exe`.
- The native Windows `hostname.exe`, rather than a BusyBox alias.

The expected toolchain directory is:

```text
<tools>/arm-gnu-toolchain-13.3.rel1-mingw-w64-i686-arm-none-eabi/bin
```

Tools are not committed to this repository. The script changes PATH and PYTHONHOME only for its process and restores them afterward.

## Build

Adapt these paths to your machine:

```powershell
./scripts/build-windows.ps1 -ToolsDir C:/dev/tools -MakePath C:/dev/make/mingw32-make.exe -PythonHome C:/Python313
```

Output: `magiclantern/platform/750D.110/build-pc-full/autoexec`, an ELF file.

Exclude the generated build directory inside the submodule before staging any submodule changes. Use a fresh build directory or clean build when changing CONFIG options; upstream does not track those options as build dependencies.

## Inspect a Canon update file

Obtain the update independently from Canon, then run:

```powershell
python scripts/inspect_750d_fir.py C:/private/CCF23110.FIR
```

This performs structural validation only. It does not decrypt, execute, modify, or verify the cryptographic signature of the firmware.
