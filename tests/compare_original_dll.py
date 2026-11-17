import ctypes
import hashlib
import sys
from pathlib import Path

original_path, portable_path = map(Path, sys.argv[1:3])
# SHA-1 of the downloaded DLL bytes (not the Git tree/blob object ID).
expected_sha1 = "9d2836af873cb751237fa88ec804f268ea8fd671"
actual_sha1 = hashlib.sha1(original_path.read_bytes()).hexdigest()
assert original_path.stat().st_size == 166912
assert actual_sha1 == expected_sha1, (actual_sha1, expected_sha1)

original = ctypes.CDLL(str(original_path.resolve()))
portable = ctypes.CDLL(str(portable_path.resolve()))


def configure(lib):
    lib.CreateFromKey.argtypes = [ctypes.c_char_p]
    lib.CreateFromKey.restype = ctypes.c_void_p
    lib.Encrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.Encrypt.restype = ctypes.c_void_p
    lib.Decrypt.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)
    ]
    lib.Decrypt.restype = ctypes.c_int
    lib.ReleaseBuffer.argtypes = [ctypes.c_void_p]
    lib.ReleaseBuffer.restype = None
    lib.ReleaseInst.argtypes = [ctypes.c_void_p]
    lib.ReleaseInst.restype = None


configure(original)
configure(portable)

key = b"vuyWQSjlknpJF54ib36txVse"
samples = [
    b"short",
    b"exactly-sixteen!",
    b"OPTC Android ARM64 compatibility test / UTF-8: \xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88",
    bytes(range(1, 64)),
]
old_ctx = original.CreateFromKey(key)
new_ctx = portable.CreateFromKey(key)
assert old_ctx and new_ctx, "could not create original/portable crypto contexts"


def encrypt(lib, ctx, payload):
    # The legacy implementation rounds the size up internally and reads a
    # complete final block. Supply a safely padded backing allocation while
    # passing the original, unpadded length exactly as the bot wrapper does.
    padded_size = (len(payload) + 15) & ~15
    backing = ctypes.create_string_buffer(
        payload + bytes(padded_size - len(payload)), padded_size + 1
    )
    ptr = lib.Encrypt(ctx, ctypes.cast(backing, ctypes.c_void_p), len(payload))
    assert ptr, "Encrypt returned NULL"
    try:
        return ctypes.string_at(ptr)
    finally:
        lib.ReleaseBuffer(ptr)


def decrypt(lib, ctx, ciphertext):
    output = ctypes.c_void_p()
    size = lib.Decrypt(ctx, ciphertext, ctypes.byref(output))
    assert size > 0 and output.value, "Decrypt returned no data"
    try:
        return ctypes.string_at(output, size)
    finally:
        lib.ReleaseBuffer(output)


try:
    for plain in samples:
        padded_size = (len(plain) + 15) & ~15
        padded = plain + bytes(padded_size - len(plain))
        old_cipher = encrypt(original, old_ctx, plain)
        new_cipher = encrypt(portable, new_ctx, plain)
        assert new_cipher == old_cipher, (
            "ciphertext mismatch", plain[:24], old_cipher, new_cipher
        )
        assert decrypt(portable, new_ctx, old_cipher) == decrypt(original, old_ctx, old_cipher)
        assert decrypt(portable, new_ctx, old_cipher) == padded
        assert decrypt(original, old_ctx, new_cipher) == padded
    # Exercise the repository's published decryption sample as a fixed
    # compatibility vector, not merely encrypt/decrypt round-trips.
    sample_ciphertext = (
        b"IbiObF5TlhPOGuMjZI,ukyvc9ZAshH..c6HTU2UeTuPBwAQNx6hUwx4HHAcS."
        b"7PHFdDn4dYUsBdPIHLQDDpdZ3oVWjdvFnes3Xy3sp9eb7JEBgXtRgzg."
        b"yotD22sDDnF2BiRtfE1LIRWXgj8uPKs63g2XAxNenLcrIZzVcbIv2R5a3Q1N7UYwAt"
        b"Akm0cKq.lgJS3RFdTQ3RkuxEIxUM3sw__"
    )
    old_sample = decrypt(original, old_ctx, sample_ciphertext)
    new_sample = decrypt(portable, new_ctx, sample_ciphertext)
    assert new_sample == old_sample, ("published sample decryption mismatch", old_sample, new_sample)
    print("Published sample plaintext SHA-256:", hashlib.sha256(new_sample).hexdigest())
    print("Published sample plaintext hex:", new_sample.hex())

    print("Original Windows DLL vs portable C ABI: PASS")
    print("Compared ciphertext and cross-decryption for", len(samples), "fixtures")
finally:
    original.ReleaseInst(old_ctx)
    portable.ReleaseInst(new_ctx)
