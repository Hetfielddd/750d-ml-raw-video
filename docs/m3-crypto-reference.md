# Public DIGIC 6 reference: EOS M3 1.01A

Later result: a separate EOS 70D reference [successfully decrypted the 750D update](750d-plaintext-milestone.md). The M3 FI2 experiment below remains a useful negative comparison, not the successful decoder.

On November 24, 2026, a readable 32 MiB EOS M3 ROM was obtained from the public CHDK firmware archive. This is a new analysis input, not the owner's camera and not a 750D ROM. A bounded experiment now executes its AES and CBC wrapper routines on the PC. Direct use of the M3 native key, IV and wrapper at the two identified 750D FIR payload starts fails the wrapper's length bounds.

At this stage the 750D 1.1.0 FIR remained encrypted. This result did not prove different keys, determine the 750D framing, or exclude additional transformations.

## Provenance

- Public archive entry point linked by CHDK developer documentation: <https://tinyurl.com/chdkfiles3>, under `DSLR FW Dumps`, file `m3_101a.7z`.
- Archive size: 9,900,517 bytes; SHA-256: `e370f90b4e0c163ad481b05e965da83e56c4e0f3f770032bf4882b1eaf604c5d`.
- Extracted `m3/sub/101a/PRIMARY.BIN`: 33,554,432 bytes; SHA-256: `0545a9a2996b9fbd96dfc2c54d80c0f1b17867e1d9c2803660be9ca16c511fa2`.
- The archive's `Info.txt` attributes the full dump to `c_joerg` and cites <https://chdk.setepontos.com/index.php?topic=12542.msg131233#msg131233>.
- The image contains `GM1.01A` at file offsets `0x1fcea5` and `0x435958`, and readable DryOS/code regions. These observations and a hash identify this analysis input; they do not cryptographically authenticate Canon's firmware.

The public archive was reached using its published link. No access request was sent. This M3 source is independent of the previously blocked 750D external-folder lead. Downloaded images, keys, IVs and disassembly are kept outside this repository.

## Path traced in the M3 image

All addresses below belong only to this M3 image, mapped at `0xFC000000`. They are not 750D platform stubs.

1. String `FirmUpgrade.c` at file offset `0x4501f8` has ADR references at `0x450146`, `0x45017a` and `0x4501c0`. GNU objdump confirms those instructions.
2. The routine at `0xFC450120` calls the header reader at `0xFC4CB60C`, then the section reader at `0xFC4CB6C4`.
3. The header reader reads a 16-byte prefix, calls `0xFC565DF0` to obtain its decoded length, and `0xFC565DDE` to round length plus four up to a 16-byte boundary. It then calls `0xFC565E2E` for the CBC-framed content.
4. `0xFC200FF8` expands a 128-bit key into 44 words. `0xFC2010C4` and `0xFC2012B6` implement AES block encryption and decryption. `0xFC565DF0` decrypts one block, XORs the IV, and interprets the first four bytes as a big-endian length.
5. The initialized updater state at RAM `0x3ef34` comes from ROM file offset `0xc9a6dc`, according to the copy loop at the main startup entry. Its first word is `0xFC000009`, a Thumb accessor returning a ROM key pointer. The IV pointer is read from the CBC routine's literal pool. The experiment reads these data privately and does not print them.

This reaches firmware-update code rather than inferring relevance from the many Wi-Fi AES strings also present in the image. It does not establish that M3 and EOS DSLR update containers have the same format.

## Reproducible bounded experiment

```sh
python scripts/probe_m3_fir_crypto.py /private/M3/PRIMARY.BIN /private/CCF23110.FIR
```

Requires Unicorn 2.1.4. Both input sizes and exact SHA-256 hashes are checked before executing any supplied bytes. ROM is mapped read/execute; the private RAM arena is read/write and non-executable. There are no camera or peripheral mappings, host filesystem callbacks or network operations. An instruction-address guard, 100,000-instruction limit and two-second timeout apply to each function call. No modified firmware file is produced.

The experiment uses Unicorn's Cortex-A9 model for these integer Thumb routines. Cortex-R5 rejected execution at this high ROM mapping in the tested setup; the cause was not isolated and no Canon MPU initialization has been emulated. This is a function-level crypto experiment, not M3 boot emulation or evidence about camera timing.

Validation completed:

- Native AES encryption and decryption match the public AES-128 known-answer vector: key `000102030405060708090a0b0c0d0e0f`, plaintext `00112233445566778899aabbccddeeff`, ciphertext `69c4e0d86a7b0430d8cdb78070b4c55a`.
- Generated CBC frames with 0, 12, 28 and 44 payload bytes round-trip through the native length and content wrappers. The latter sizes exercise chained blocks.
- Applied directly with the native M3 key/IV, the 750D updater prefix at file offset `0x120` gives candidate length 3,706,901,770, exceeding its 2,509,264-byte encrypted region. The firmware prefix at `0x264b70` gives candidate length 2,334,075,864, exceeding its 21,117,280-byte region.

The last two observations reject this precise direct-application hypothesis. Neither is decrypted firmware or a verification of the 750D algorithm. The machine-readable output is [saved here](evidence/m3-crypto-probe.json).

## Tool improvement and remaining work

The earlier Thumb candidate scanner missed these nearby strings because it did not implement ADR. It now handles T1, subtracting T2 and adding T3, with independent GNU assembler fixtures. Its 750D CLI identity check remains in place; the lower-level `scan()` function can examine a supplied donor segment. Candidate hits still require disassembly and context.

The next firmware-analysis question is how the EOS DSLR update framing or key selection differs from this working M3 reference. No unknown 750D address, event callback, DMA channel or completed-frame source has been validated. The existing recorder still accepts only synthetic PC frames.

## Follow-up: FI2 is not the 750D FIR framing

Canon's [M3 1.2.1 support page](https://www.canon.com.au/support/sims-content?cid=1908CE3C822A4ADA9947695627D40D89&pid=7b3db57141704e0a8d45bcd362e0d980) identifies its update as `M3_121.FI2`. The CHDK [FI2 encoder](https://github.com/Anda2012/CHDK/blob/09a9a48ba84df3f61a633c4f1bd55be757b2bd1f/tools/packfi2/fi2enc.c) describes an encrypted header with a big-endian length, block descriptors and separately compressed/encrypted blocks. Its DryOS r55 descriptor is 40 bytes, matching the stride seen in the M3 updater. This identifies the M3 wrapper as a FI2 reference, not an identified EOS FIR decoder.

The same mirror's [M3 platform configuration](https://github.com/Anda2012/CHDK/blob/09a9a48ba84df3f61a633c4f1bd55be757b2bd1f/platform/m3/makefile.inc) selects `KEYSYS=d4h` and disables FI2 startup for CHDK because of initialization issues. The key-family label is another reason not to infer common keys from the DIGIC number. Nothing was installed or started on a camera to check these observations.

The actual 750D FIR instead contains a readable main header, four region descriptors and two separate 112-byte encryption headers. Its structural inspector now reports and validates those boundaries; [the metadata-only result](evidence/fir-region-layout.json) is reproducible from the existing private input. This validates input geometry, not plaintext or signatures.

The public CHDK DSLR archive was rechecked: its visible entries include older 1000D/500D images and several EOS M models, but no 550D/60D reference was found in that folder. No claim is made about all public archives. The Canon M3 ZIP download did not complete through the web reader, so no official FI2 ciphertext was acquired or tested in this follow-up.
