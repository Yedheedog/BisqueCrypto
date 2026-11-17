# Android ARM64 Port Investigation

Status: experimental investigation only. No Android build or runtime test has passed yet.

## Scope

- Target: Linux userspace on Android ARM64 (Termux / Ubuntu under proot-distro).
- Keep this fork separate from the OPTC bot until the crypto routines are independently validated.
- Preserve upstream history; put all porting work on `android-arm64-port`.
- Do not contact live game services or use real account credentials as test fixtures.

## Provenance and permission

This repository is a fork of `techwhiz1/BisqueCrypto`. The upstream repository currently exposes no detected LICENSE file or declared GitHub license. Public visibility and the ability to fork do not themselves grant permission to redistribute or incorporate the source into another project.

A permission request should be made to the upstream author. Until an applicable license or explicit permission is confirmed, keep modifications and experiments isolated in this fork and do not merge or redistribute the code as part of the OPTC bot.

The source includes `defs.h` with Hex-Rays decompiler-output definitions. Treat the C++ implementation as reconstructed/decompiler-derived code, not as verified original source.

## Initial portability findings

- `BQ_Crypto/BisqueCrypto.h` includes Windows headers and zlib.
- `BQ_Crypto/BisqueCrypto.cpp` includes `intrin.h`; the `DecryptMD40S` path uses x86 SIMD and must not be assumed to work on ARM64.
- `BisquseDLL/interface.cpp` exposes a Windows DLL ABI and uses Windows-specific declarations/functions such as `__declspec`, `__cdecl`, `strcpy_s`, and `DllMain`.
- The Python bot expects DLL exports including `CreateFromKey`, `Encrypt`, `Decrypt`, `DecryptNTY`, `ReleaseBuffer`, and `ReleaseInst`. Confirm exact signatures against the bot wrapper before designing a portable C ABI.
- NTY decryption uses MD144 plus optional zlib inflation; validate lengths, inflate status, and output limits before accepting data.
- R-Base64 uses custom substitutions: `_` for `=`, `.` for `+`, and `,` for `/`.

## Validation gates

1. Inventory all methods used by the OPTC bot and map them to the source implementation.
2. Build a small host-side test harness without the Windows DLL wrapper or Windows-only test main.
3. Verify known-answer fixtures against the original DLL or trusted outputs where legally and technically available.
4. Test malformed input, empty input, block boundaries, key lengths, memory ownership, and repeated key initialization.
5. Compile for Android ARM64 only after host tests pass; verify the resulting shared library loads from Termux Python via ctypes.
6. Keep all fixtures synthetic or sanitized. Do not include account tokens, session keys, or private game data in commits.

## Not yet done

- No portable library implementation has been committed.
- No Linux or Android compile has been verified.
- No encryption/decryption compatibility test has passed.
- No integration into the OPTC bot has been performed.
