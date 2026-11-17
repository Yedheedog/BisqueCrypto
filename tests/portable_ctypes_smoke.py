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
    print("C ABI + Python ctypes round-trip: PASS")
finally:
    library.ReleaseInst(instance)
