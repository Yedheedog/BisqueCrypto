# Android ARM64 Port Investigation

Status: experimental validation passed for the portable C ABI and Android ARM64 cross-compile; real-device validation and upstream permission remain outstanding.

## Scope

- Target: Linux userspace on Android ARM64 (Termux / Ubuntu under proot-distro).
- Keep this fork separate from the OPTC bot until device validation and permission are clear.
- Preserve upstream history; all porting work stays on `android-arm64-port`.
- Do not contact live game services or use real account credentials as test fixtures.

## Provenance and permission

This repository is a fork of `techwhiz1/BisqueCrypto`. The upstream repository currently has no LICENSE/COPYING/NOTICE file or declared GitHub license. Public visibility and the ability to fork do not themselves grant permission to redistribute or incorporate the source into another project.

A permission request is open:
https://github.com/techwhiz1/BisqueCrypto/issues/2

It asks for permission to adapt the C++ source for Android ARM64 and use it in a personal OPTC bot. There are currently no replies. Until an applicable license or explicit permission is confirmed, keep modifications and experiments isolated in this fork and do not integrate or redistribute the code as part of the OPTC bot.

The source includes `defs.h` with Hex-Rays decompiler-output definitions. Treat the C++ implementation as reconstructed/decompiler-derived code, not as verified original source.

## Portability findings and changes

- Added a portable C ABI exposing `CreateFromKey`, `Encrypt`, `Decrypt`, `DecryptNTY`, `ReleaseBuffer`, and `ReleaseInst`.
- Added a Python ctypes wrapper and smoke tests.
- Removed the Intel-only `DecryptMD40S` implementation from the temporary Android/Linux build copy; the core MD159/MD144 paths are the current focus.
- Added input-length and block-count checks, unaligned NTY header parsing, aligned payload handling, and a bounded zlib inflate path.
- Added allocation-failure checks for all three key-schedule allocations.
- Statically linked the C++ runtime so the Android `.so` does not depend on `libc++_shared.so`; it retains only Android system dependencies including `libz.so`.
- The Android/Linux build retains zlib-backed NTY inflation.
- The Windows comparison build defines `BISQUE_NO_ZLIB` and skips only compressed NTY inflation; it is used to compare the MD159 C ABI with the legacy DLL.

## Verified validation

Latest successful GitHub Actions run: [Run 70](https://github.com/Yedheedog/BisqueCrypto/actions/runs/44055863695).

- [x] Linux host compilation and MD159/R-Base64 round-trips.
- [x] Portable C ABI tested through Python ctypes.
- [x] Python wrapper round-trip.
- [x] Malformed-input rejection.
- [x] Unaligned NTY input path exercised.
- [x] Android NDK cross-compile for `aarch64-linux-android24`.
- [x] ELF verified as a 64-bit AArch64 Android shared object with no `libc++_shared.so` dependency.
- [x] C ABI validates native block counts and rejects failed native operations.
- [x] Accepts both custom R-Base64 and standard Base64 (including `+`, `/`, and `=`), matching the legacy database map-table path.
- [x] Direct comparison against the exact legacy Windows DLL: ciphertext matched and cross-decryption passed for four synthetic fixtures.
- [x] Published legacy decryption sample matched the original DLL by SHA-256 without logging its plaintext.
- [x] Captured a deterministic synthetic ciphertext vector for the eventual on-device compatibility smoke test.
- [x] Repeated key initialization (64 key changes on one MD159 instance) passed under AddressSanitizer with leak detection enabled.

Android artifact:
- Name: `libbisquecrypto-android-arm64`
- Artifact ID: `14315537321`
- Target: Android API 24, AArch64, NDK r27c.
- `libbisquecrypto.so` SHA-256: `5d94d347e904f956e7a00be080458c0614584b62ff900b12e548479278aefa6a`.
- The artifact is attached to Run 70 and is not committed to the OPTC bot.

## Remaining validation gates

1. Compare NTY decryption against a known-good original-DLL fixture.
2. Load and exercise the Android `.so` on a real ARM64 Android/Termux device.
3. Verify repeated key initialization and native memory ownership under device runtime.
4. Obtain clear upstream permission/licensing terms before integrating this reconstructed source into the OPTC bot or distributing binaries.

No real game login, account action, live game API request, or farming operation has been performed.
