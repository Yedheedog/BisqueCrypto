import ctypes
import sys

library = ctypes.CDLL(sys.argv[1])
library.CreateFromKey.argtypes = [ctypes.c_char_p]
library.CreateFromKey.restype = ctypes.c_void_p
library.Encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
library.Encrypt.restype = ctypes.c_void_p
library.Decrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
library.Decrypt.restype = ctypes.c_int
library.ReleaseBuffer.argtypes = [ctypes.c_void_p]
library.ReleaseBuffer.restype = None
library.ReleaseInst.argtypes = [ctypes.c_void_p]
library.ReleaseInst.restype = None

key = b"vuyWQSjlknpJF54ib36txVse"
plain = b"portable C ABI / ctypes smoke test"
instance = library.CreateFromKey(key)
assert instance, "CreateFromKey returned NULL"
try:
    encrypted_ptr = library.Encrypt(instance, plain, len(plain))
    assert encrypted_ptr, "Encrypt returned NULL"
    try:
        encrypted = ctypes.string_at(encrypted_ptr)
    finally:
        library.ReleaseBuffer(encrypted_ptr)

    decrypted_ptr = ctypes.c_void_p()
    decrypted_size = library.Decrypt(instance, encrypted, ctypes.byref(decrypted_ptr))
    assert decrypted_size > 0 and decrypted_ptr.value, "Decrypt returned no output"
    try:
        decrypted = ctypes.string_at(decrypted_ptr, decrypted_size)
    finally:
        library.ReleaseBuffer(decrypted_ptr)

    expected = plain + (b"\0" * ((16 - len(plain) % 16) % 16))
    assert decrypted == expected, (decrypted, expected)

    # Reject malformed R-Base64 instead of silently decoding a partial block.
    for malformed in (b"!", b"A", b"AAAAAAAAAAAAAAAAAAAAAAAA"):
        bad_output = ctypes.c_void_p()
        bad_size = library.Decrypt(instance, malformed, ctypes.byref(bad_output))
        assert bad_size == 0 and not bad_output.value, (malformed, bad_size)

    # Reject NTY headers whose encrypted payload length is not block-aligned.
    library.DecryptNTY.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_bool
    ]
    library.DecryptNTY.restype = ctypes.c_int
    malformed_nty = bytearray(24)
    malformed_nty[7] = 7  # Big-endian payload size = 7, not an MD144 block.
    nty_buffer = ctypes.create_string_buffer(bytes(malformed_nty), len(malformed_nty))
    nty_output = ctypes.c_void_p()
    nty_size = library.DecryptNTY(
        instance, nty_buffer, len(malformed_nty), ctypes.byref(nty_output), False
    )
    assert nty_size == 0 and not nty_output.value, nty_size

    # Deliberately unaligned NTY header: this must fail cleanly, not fault.
    unaligned = ctypes.create_string_buffer(b"X" + bytes(malformed_nty), len(malformed_nty) + 1)
    unaligned_output = ctypes.c_void_p()
    unaligned_size = library.DecryptNTY(
        instance, ctypes.byref(unaligned, 1), len(malformed_nty),
        ctypes.byref(unaligned_output), False
    )
    assert unaligned_size == 0 and not unaligned_output.value, unaligned_size

    print("C ABI + Python ctypes round-trip: PASS")
    print("Malformed-input rejection: PASS")
    print("Unaligned NTY header handling: PASS")
finally:
    library.ReleaseInst(instance)

# Exercise the repository's higher-level Python wrapper as well.
sys.path.insert(0, "python")
from bisque_crypto import BisqueCrypto

with BisqueCrypto(sys.argv[1], key) as crypto:
    wrapped_ciphertext = crypto.encrypt(plain)
    wrapped_plaintext = crypto.decrypt(wrapped_ciphertext)
    assert wrapped_plaintext == expected, (wrapped_plaintext, expected)
print("Python wrapper round-trip: PASS")
