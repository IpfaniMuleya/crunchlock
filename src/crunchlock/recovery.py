"""Optional Reed-Solomon damage-recovery layer around a finished ``.clk`` stream.

Data is cut into segments; each segment is a matrix of ``K`` interleaved
RS(255,223) codewords (32 parity bytes each, ~14% overhead). Each codeword can
fix up to 16 corrupted bytes, and interleaving means a contiguous burst of up to
``16*K`` bytes (4 KiB with the default K=256) per segment is repairable.

Encoding and error *detection* are vectorized with numpy (GF(256) is linear, so
parity and syndromes are XOR-sums of table lookups). Only damaged codewords are
handed to the (slow, pure-Python) ``reedsolo`` decoder for correction.

Repair happens below the encryption layer, so the AES-GCM authentication still
verifies that the repaired data is exactly the original.
"""
from __future__ import annotations

import struct
import zlib
from functools import lru_cache

import numpy as np
import reedsolo

from .errors import CorruptFileError

MAGIC = b"CRLR"
VERSION = 1
NSYM = 32
N = 255
K_DATA = N - NSYM  # 223
DEFAULT_COLS = 256
_HDR = struct.Struct(">4sBHB")
HEADER_COPY_LEN = _HDR.size + 4
HEADER_LEN = 3 * HEADER_COPY_LEN


@lru_cache(maxsize=None)
def _tables():
    codec = reedsolo.RSCodec(NSYM)  # prim 0x11d, generator 2, fcr 0
    exp = np.zeros(512, dtype=np.int32)
    log = np.zeros(256, dtype=np.int32)
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    exp[255:510] = exp[:255]
    a = np.arange(256)
    mul = np.zeros((256, 256), dtype=np.uint8)
    nz = a[1:]
    mul[1:, 1:] = exp[(log[nz][:, None] + log[nz][None, :]) % 255]
    # Parity of the unit message x^p (p = power of the data position).
    unit_parity = np.zeros((K_DATA, NSYM), dtype=np.uint8)
    for p in range(K_DATA):
        msg = bytearray(p + 1)
        msg[0] = 1
        unit_parity[p] = np.frombuffer(bytes(codec.encode(msg))[-NSYM:], dtype=np.uint8)
    enc = mul[:, unit_parity].transpose(1, 0, 2).copy()           # [p, c, j]
    alpha_pow = exp[(np.arange(N)[:, None] * np.arange(NSYM)[None, :]) % 255]  # [p, j]
    syn = mul[:, alpha_pow].transpose(1, 0, 2).copy()             # [p, c, j]
    return codec, enc, syn


def _pack_header(cols: int) -> bytes:
    h = _HDR.pack(MAGIC, VERSION, cols, NSYM)
    return (h + struct.pack(">I", zlib.crc32(h))) * 3


def _parse_header(raw: bytes) -> int | None:
    for i in range(3):
        c = raw[i * HEADER_COPY_LEN:(i + 1) * HEADER_COPY_LEN]
        if len(c) < HEADER_COPY_LEN:
            continue
        h, crc = c[:_HDR.size], struct.unpack(">I", c[_HDR.size:])[0]
        if zlib.crc32(h) == crc:
            magic, ver, cols, nsym = _HDR.unpack(h)
            if magic == MAGIC and ver == VERSION and nsym == NSYM and 1 <= cols <= 4096:
                return cols
    return None


class RSWriter:
    def __init__(self, target, cols: int = DEFAULT_COLS):
        self._t = target
        self._cols = cols
        self._cap = K_DATA * cols - 2
        self._buf = bytearray()
        self._closed = False
        _tables()
        target.write(_pack_header(cols))

    def _segment(self, payload: bytes) -> None:
        _, enc, _ = _tables()
        cols = self._cols
        body = struct.pack(">H", len(payload)) + payload
        k = -(-len(body) // cols)
        body += bytes(k * cols - len(body))
        d = np.frombuffer(body, dtype=np.uint8).reshape(k, cols)
        powers = np.arange(k - 1, -1, -1)[:, None]
        parity = np.bitwise_xor.reduce(enc[powers, d], axis=0)       # (cols, NSYM)
        self._t.write(body + np.ascontiguousarray(parity.T).tobytes())

    def write(self, data) -> int:
        self._buf += data
        while len(self._buf) >= self._cap:
            self._segment(bytes(self._buf[:self._cap]))
            del self._buf[:self._cap]
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._buf:
            self._segment(bytes(self._buf))
        self._t.close()


class RSReader:
    """Reads a recovery-wrapped stream, repairing damage on the fly."""

    def __init__(self, source, cols: int):
        self._s = source
        self._cols = cols
        self._seg_len = N * cols
        self._buf = bytearray()
        self._eof = False
        self.corrected_bytes = 0

    def _read_segment(self) -> None:
        raw = bytearray()
        while len(raw) < self._seg_len:
            b = self._s.read(self._seg_len - len(raw))
            if not b:
                break
            raw += b
        if not raw:
            self._eof = True
            return
        cols = self._cols
        if len(raw) % cols or len(raw) // cols <= NSYM:
            raise CorruptFileError("recovery data is truncated and cannot be repaired")
        n = len(raw) // cols
        k = n - NSYM
        codec, _, syn = _tables()
        c = np.frombuffer(bytes(raw), dtype=np.uint8).reshape(n, cols)
        powers = np.arange(n - 1, -1, -1)[:, None]
        s = np.bitwise_xor.reduce(syn[powers, c], axis=0)            # (cols, NSYM)
        bad = np.nonzero(s.any(axis=1))[0]
        if bad.size:
            c = c.copy()
            for j in bad:
                try:
                    msg, _full, errata = codec.decode(bytearray(c[:, j].tobytes()))
                except reedsolo.ReedSolomonError:
                    raise CorruptFileError(
                        "file is too badly damaged to repair") from None
                c[:k, j] = np.frombuffer(bytes(msg), dtype=np.uint8)
                self.corrected_bytes += len(errata)
        body = c[:k].tobytes()
        (length,) = struct.unpack_from(">H", body)
        if length > len(body) - 2:
            raise CorruptFileError("recovery segment is malformed")
        self._buf += body[2:2 + length]
        if len(raw) < self._seg_len:
            self._eof = True

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            while not self._eof:
                self._read_segment()
            out = bytes(self._buf)
            self._buf.clear()
            return out
        while len(self._buf) < n and not self._eof:
            self._read_segment()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


class _Replay:
    def __init__(self, head: bytes, source):
        self._head = head
        self._s = source

    def read(self, n: int = -1) -> bytes:
        if self._head:
            if n is None or n < 0:
                out = self._head + self._s.read()
                self._head = b""
                return out
            out, self._head = self._head[:n], self._head[n:]
            if len(out) < n:
                out += self._s.read(n - len(out))
            return out
        return self._s.read(n)


def open_layer(source):
    """Return (stream, rs_reader_or_None) — unwraps recovery data when present."""
    head = source.read(HEADER_LEN)
    cols = _parse_header(head)
    if cols is not None:
        r = RSReader(source, cols)
        return r, r
    return _Replay(head, source), None
