"""ctypes wrapper for the portable BisqueCrypto C ABI.

The shared library path is explicit so callers control where native code is loaded
from. The wrapper owns and releases all native buffers and key contexts.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]


class BisqueCryptoError(RuntimeError):
    """Raised when the native crypto library cannot complete an operation."""


class BisqueCrypto:
    def __init__(self, library_path: Union[str, Path], key: Union[str, bytes]):
        self._lib = ctypes.CDLL(str(Path(library_path).expanduser().resolve()))
        self._configure_signatures()
        key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        if not key_bytes or b"\0" in key_bytes:
            raise ValueError("key must be non-empty and contain no NUL bytes")
        self._instance = self._lib.CreateFromKey(key_bytes)
        if not self._instance:
            raise BisqueCryptoError("CreateFromKey rejected the supplied key")

    def _configure_signatures(self) -> None:
        lib = self._lib
        lib.CreateFromKey.argtypes = [ctypes.c_char_p]
        lib.CreateFromKey.restype = ctypes.c_void_p
        lib.Encrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        lib.Encrypt.restype = ctypes.c_void_p
        lib.Decrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)
        ]
        lib.Decrypt.restype = ctypes.c_int
        lib.DecryptNTY.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_bool
        ]
        lib.DecryptNTY.restype = ctypes.c_int
        lib.ReleaseBuffer.argtypes = [ctypes.c_void_p]
        lib.ReleaseBuffer.restype = None
        lib.ReleaseInst.argtypes = [ctypes.c_void_p]
        lib.ReleaseInst.restype = None

    def _require_open(self) -> None:
        if not self._instance:
            raise BisqueCryptoError("crypto context is closed")

    def encrypt(self, data: BytesLike) -> bytes:
        self._require_open()
        raw = bytes(data)
        if not raw:
            return b""
        if len(raw) > 0x7FFFFFFF:
            raise ValueError("input is too large")
        source = ctypes.create_string_buffer(raw, len(raw))
        result = self._lib.Encrypt(self._instance, source, len(raw))
        if not result:
            raise BisqueCryptoError("native Encrypt failed")
        try:
            return ctypes.string_at(result)
        finally:
            self._lib.ReleaseBuffer(result)

    def decrypt(self, encoded: Union[str, bytes]) -> bytes:
        self._require_open()
        raw = encoded.encode("ascii") if isinstance(encoded, str) else bytes(encoded)
        if not raw:
            return b""
        output = ctypes.c_void_p()
        size = self._lib.Decrypt(self._instance, raw, ctypes.byref(output))
        if size <= 0 or not output.value:
            raise BisqueCryptoError("native Decrypt failed")
        try:
            return ctypes.string_at(output, size)
        finally:
            self._lib.ReleaseBuffer(output)

    def decrypt_nty(self, data: BytesLike, compressed: bool = True) -> bytes:
        self._require_open()
        raw = bytes(data)
        if len(raw) < 16 or len(raw) > 0xFFFFFFFF:
            raise ValueError("NTY input length is outside the supported range")
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.c_void_p()
        size = self._lib.DecryptNTY(
            self._instance, source, len(raw), ctypes.byref(output), bool(compressed)
        )
        if size <= 0 or not output.value:
            raise BisqueCryptoError("native DecryptNTY failed")
        try:
            return ctypes.string_at(output, size)
        finally:
            self._lib.ReleaseBuffer(output)

    def close(self) -> None:
        if self._instance:
            self._lib.ReleaseInst(self._instance)
            self._instance = None

    def __enter__(self) -> "BisqueCrypto":
        self._require_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
