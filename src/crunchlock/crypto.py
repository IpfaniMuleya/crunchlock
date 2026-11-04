"""Chunked AES-256-GCM streaming encryption (STREAM construction) + Padmé padding.

Each chunk's plaintext is ``u32 data_len | data | zero padding``. The nonce is
``nonce_prefix(7) | counter u32 | last_flag u8`` so chunks cannot be reordered,
dropped, duplicated or truncated without detection. The full header is the
associated data for every chunk.
"""
from __future__ import annotations

import struct
from typing import BinaryIO, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import CorruptFileError

TAG_LEN = 16
_LEN = struct.Struct(">I")
MAX_CHUNKS = 2**32 - 1


def padme(length: int) -> int:
    """Padmé: pad to a size that leaks only O(log log n) bits (max ~12% overhead)."""
    if length < 2:
        return length
    e = length.bit_length() - 1
    s = e.bit_length()
    last_bits = e - s
    mask = (1 << last_bits) - 1
    return (length + mask) & ~mask


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter > MAX_CHUNKS:
        raise CorruptFileError("file too large")
    return prefix + _LEN.pack(counter) + (b"\x01" if last else b"\x00")


class EncryptWriter:
    """Push-style writer: ``write()`` plaintext, ``close()`` to finalize."""

    def __init__(self, target, header_bytes: bytes, file_key: bytes, chunk_size: int,
                 nonce_prefix: bytes, pad: bool = False):
        self._t = target
        self._aad = header_bytes
        self._aead = AESGCM(file_key)
        self._cs = chunk_size
        self._prefix = nonce_prefix
        self._pad = pad
        self._buf = bytearray()
        self._counter = 0
        self.data_bytes = 0
        self._closed = False
        target.write(header_bytes)

    def _emit(self, plaintext: bytes, last: bool) -> None:
        nonce = _nonce(self._prefix, self._counter, last)
        self._t.write(self._aead.encrypt(nonce, plaintext, self._aad))
        self._counter += 1

    def write(self, data) -> int:
        self._buf += data
        self.data_bytes += len(data)
        cs = self._cs
        # Keep at least one byte buffered so the final chunk is known at close().
        while len(self._buf) > cs:
            self._emit(_LEN.pack(cs) + bytes(self._buf[:cs]), last=False)
            del self._buf[:cs]
        return len(data)

    def flush(self) -> None:  # tarfile may call this
        pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        cs = self._cs
        rem = bytes(self._buf)
        self._buf.clear()
        extra = padme(self.data_bytes) - self.data_bytes if self._pad else 0
        fill = min(extra, cs - len(rem))
        extra -= fill
        self._emit(_LEN.pack(len(rem)) + rem + bytes(fill), last=extra == 0)
        while extra > 0:
            z = min(extra, cs)
            extra -= z
            self._emit(_LEN.pack(0) + bytes(z), last=extra == 0)
        if hasattr(self._t, "close"):
            self._t.close()


class DecryptReader:
    """Pull-style reader yielding authenticated plaintext."""

    def __init__(self, source: BinaryIO, header_bytes: bytes, file_key: bytes,
                 chunk_size: int, nonce_prefix: bytes,
                 progress: Callable[[int], None] | None = None):
        self._s = source
        self._aad = header_bytes
        self._aead = AESGCM(file_key)
        self._cs = chunk_size
        self._ct_len = 4 + chunk_size + TAG_LEN
        self._prefix = nonce_prefix
        self._counter = 0
        self._buf = bytearray()
        self._pending = b""
        self._done = False
        self._data_ended = False
        self._progress = progress
        self.bytes_in = 0

    def _read_ct(self, n: int) -> bytes:
        out = bytearray(self._pending)
        self._pending = b""
        while len(out) < n:
            b = self._s.read(n - len(out))
            if not b:
                break
            out += b
        self.bytes_in += len(out)
        return bytes(out)

    def _next_chunk(self) -> None:
        ct = self._read_ct(self._ct_len + 1)
        if len(ct) > self._ct_len:
            self._pending = ct[self._ct_len:]
            self.bytes_in -= len(self._pending)
            ct = ct[:self._ct_len]
            last = False
        else:
            last = True
        if len(ct) < 4 + TAG_LEN:
            raise CorruptFileError("file is truncated or damaged")
        try:
            pt = self._aead.decrypt(_nonce(self._prefix, self._counter, last), ct, self._aad)
        except InvalidTag:
            if last and len(ct) == self._ct_len:
                raise CorruptFileError("file is truncated, damaged or has been tampered with") from None
            raise CorruptFileError("file is damaged or has been tampered with "
                                   f"(chunk {self._counter} failed authentication)") from None
        self._counter += 1
        (n,) = _LEN.unpack_from(pt)
        if n > len(pt) - 4 or (self._data_ended and n):
            raise CorruptFileError("malformed chunk")
        if n:
            self._buf += pt[4:4 + n]
        if n < self._cs:
            self._data_ended = True
        if self._progress:
            self._progress(self.bytes_in)
        if last:
            self._done = True

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            while not self._done:
                self._next_chunk()
            out = bytes(self._buf)
            self._buf.clear()
            return out
        while len(self._buf) < n and not self._done:
            self._next_chunk()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def read_all_and_discard(self) -> None:
        while not self._done:
            self._next_chunk()
            self._buf.clear()

    @property
    def finished(self) -> bool:
        return self._done and not self._buf
