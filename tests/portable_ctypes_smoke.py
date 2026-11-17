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

    # database.py historically uses Python's standard base64.b64encode()
    # for encrypted map tables, while API payloads use the R-Base64 alphabet.
    # Exercise deterministic blocks until both standard special characters
    # (+ and /) and standard padding (=) have appeared.
    standard_symbols = set()
    for value in range(256):
        database_plain = bytes([value]) * 16
        database_cipher = library.Encrypt(instance, database_plain, len(database_plain))
        assert database_cipher, "database fixture encryption failed"
        try:
            custom_text = ctypes.string_at(database_cipher)
        finally:
            library.ReleaseBuffer(database_cipher)
        standard_text = (
            custom_text.replace(b".", b"+").replace(b",", b"/").replace(b"_", b"=")
        )
        standard_symbols.update(byte for byte in standard_text if byte in b"+/=")
        standard_output = ctypes.c_void_p()
        standard_size = library.Decrypt(
            instance, standard_text, ctypes.byref(standard_output)
        )
        assert standard_size > 0 and standard_output.value, "standard Base64 was rejected"
        try:
            standard_plaintext = ctypes.string_at(standard_output, standard_size)
        finally:
            library.ReleaseBuffer(standard_output)
        assert standard_plaintext == database_plain, (standard_plaintext, database_plain)
        if standard_symbols == {ord("+"), ord("/"), ord("=")}:
            break
    assert standard_symbols == {ord("+"), ord("/"), ord("=")}, standard_symbols

    # Match database.py's 512-byte encrypted map-table input size.
    map_plaintext = bytes(range(256)) * 2
    map_buffer = ctypes.create_string_buffer(map_plaintext, len(map_plaintext) + 1)
    map_cipher_ptr = library.Encrypt(
        instance, ctypes.cast(map_buffer, ctypes.c_void_p), len(map_plaintext)
    )
    assert map_cipher_ptr, "512-byte map fixture encryption failed"
    try:
        map_custom = ctypes.string_at(map_cipher_ptr)
    finally:
        library.ReleaseBuffer(map_cipher_ptr)
    map_standard = map_custom.replace(b".", b"+").replace(b",", b"/").replace(b"_", b"=")
    map_output = ctypes.c_void_p()
    map_size = library.Decrypt(instance, map_standard, ctypes.byref(map_output))
    assert map_size == len(map_plaintext) and map_output.value, map_size
    try:
        map_decrypted = ctypes.string_at(map_output, map_size)
    finally:
        library.ReleaseBuffer(map_output)
    assert map_decrypted == map_plaintext

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

    # Exercise the actual MD144 path with a deliberately unaligned input buffer.
    valid_block_nty = bytearray(24)
    valid_block_nty[7] = 8  # One complete 8-byte MD144 block.
    valid_block_nty[16:24] = bytes(range(8))
    unaligned = ctypes.create_string_buffer(
        b"X" + bytes(valid_block_nty), len(valid_block_nty) + 1
    )
    unaligned_output = ctypes.c_void_p()
    unaligned_size = library.DecryptNTY(
        instance, ctypes.byref(unaligned, 1), len(valid_block_nty),
        ctypes.byref(unaligned_output), False
    )
    assert unaligned_size == 8 and unaligned_output.value, unaligned_size
    library.ReleaseBuffer(unaligned_output)

    print("C ABI + Python ctypes round-trip: PASS")
    print("Standard Base64 database payload compatibility: PASS")
    print("512-byte database map-table compatibility: PASS")
    print("Malformed-input rejection: PASS")
    print("Unaligned NTY decryption path: PASS")
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
