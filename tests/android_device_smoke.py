"""Real-device smoke test for the Android ARM64 shared library.

Usage:
    python android_device_smoke.py /path/to/libbisquecrypto.so

Uses only a synthetic test key and plaintext. No network or OPTC account data.
"""
import ctypes
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: python android_device_smoke.py /path/to/libbisquecrypto.so")

library = ctypes.CDLL(sys.argv[1])
library.CreateFromKey.argtypes = [ctypes.c_char_p]
library.CreateFromKey.restype = ctypes.c_void_p
library.Encrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
library.Encrypt.restype = ctypes.c_void_p
library.Decrypt.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)
]
library.Decrypt.restype = ctypes.c_int
library.ReleaseBuffer.argtypes = [ctypes.c_void_p]
library.ReleaseBuffer.restype = None
library.ReleaseInst.argtypes = [ctypes.c_void_p]
library.ReleaseInst.restype = None

key = b"vuyWQSjlknpJF54ib36txVse"
plaintext = b"short"
expected_ciphertext = b"xk13,hfJ7OCxpCGi,jR8fA__"
expected_plaintext = plaintext + (b"\\0" * 11)

instance = library.CreateFromKey(key)
if not instance:
    raise RuntimeError("CreateFromKey returned NULL")

try:
    plaintext_buffer = ctypes.create_string_buffer(plaintext, len(plaintext) + 1)
    encrypted_ptr = library.Encrypt(
        instance, ctypes.cast(plaintext_buffer, ctypes.c_void_p), len(plaintext)
    )
    if not encrypted_ptr:
        raise RuntimeError("Encrypt returned NULL")
    try:
        encrypted = ctypes.string_at(encrypted_ptr)
    finally:
        library.ReleaseBuffer(encrypted_ptr)

    if encrypted != expected_ciphertext:
        raise AssertionError(
            f"Legacy DLL vector mismatch: {encrypted!r} != {expected_ciphertext!r}"
        )

    for label, ciphertext in (
        ("R-Base64", expected_ciphertext),
        ("standard Base64", expected_ciphertext.replace(b".", b"+").replace(b",", b"/").replace(b"_", b"=")),
    ):
        output = ctypes.c_void_p()
        size = library.Decrypt(instance, ciphertext, ctypes.byref(output))
        if size <= 0 or not output.value:
            raise RuntimeError(f"{label} Decrypt returned no output")
        try:
            result = ctypes.string_at(output, size)
        finally:
            library.ReleaseBuffer(output)
        if result != expected_plaintext:
            raise AssertionError(f"{label} decryption mismatch: {result!r}")
        print(f"{label} decrypt: PASS")

    print("Android ARM64 native library load: PASS")
    print("Legacy DLL-compatible encrypt vector: PASS")
finally:
    library.ReleaseInst(instance)
