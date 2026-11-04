"""Lossless PNG recompression: restores the *exact original file*, byte for byte.

A PNG stores its pixels as one zlib (deflate) stream, which zstd/xz can't
shrink any further. Most PNGs are written by the zlib library itself, so the
stream can be rebuilt exactly from the uncompressed data plus the settings
that produced it. We find those settings, keep the uncompressed data (which
the main compressor then packs much better than deflate did) and rebuild the
original deflate stream when unlocking.

Safety: every transcode is rebuilt immediately and compared with the original
bytes; files that don't come back identical (other encoders, odd chunks) are
stored unchanged. A CRC-32 of the original is kept and checked on restore.

Rebuilding needs the standard zlib library. Some Python builds use a different
deflate implementation (e.g. zlib-ng) whose output differs; there, a known-answer
check fails and PNG recompression is switched off, so every file we write can be
restored by any standard zlib.
"""
from __future__ import annotations

import functools
import hashlib
import struct
import zlib

from .errors import CorruptFileError

EXTENSIONS = {".png"}
MAX_BYTES = 128 * 1024 * 1024
MAX_RAW = 512 * 1024 * 1024
PAX_KEY = "CRUNCHLOCK.png"
PAX_SIZE = "CRUNCHLOCK.size"
PAX_CRC = "CRUNCHLOCK.crc"
SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAGIC = b"CLPNG1"

_CHUNK = struct.Struct(">I4s")
_HEAD = struct.Struct(">6sBBBBI")
_U32 = struct.Struct(">I")
_STRATEGIES = [zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED, zlib.Z_RLE, zlib.Z_FIXED,
               zlib.Z_HUFFMAN_ONLY]
_LEVELS_BY_FLEVEL = {0: [1, 0], 1: [5, 4, 3, 2], 2: [6], 3: [9, 8, 7]}
_MEM_LEVELS = [8, 9, 7, 6, 5, 4, 3, 2, 1]
_STEP = 64 * 1024


# SHA-256 prefixes of standard zlib's output for a fixed input (see available()).
_KNOWN_ANSWERS = {
    (6, 15, 8, zlib.Z_FILTERED): "a2168f79cd350ade5ac80696f49070de",
    (9, 15, 9, zlib.Z_DEFAULT_STRATEGY): "8c91b796c625107ea9be8122823e1e16",
    (1, 15, 8, zlib.Z_DEFAULT_STRATEGY): "45cd358edf59f45f39cb290357fa586f",
    (6, 15, 8, zlib.Z_DEFAULT_STRATEGY): "58366f22af26d6d6b8da60831f1ddd47",
    (6, 15, 8, zlib.Z_RLE): "70ca88315885943b2e451fb8e7da648f",
}


def _sample() -> bytes:
    x, out = 12345, bytearray()
    for i in range(60000):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out += bytes([(x >> 16) & 0x3F, i & 0xFF, (i * 7) & 0x1F])
    return bytes(out)


@functools.lru_cache(maxsize=1)
def available() -> bool:
    """True if this Python's zlib produces standard zlib output (checked once)."""
    try:
        sample = _sample()
        for (level, wbits, mem, strategy), digest in _KNOWN_ANSWERS.items():
            out = _deflate(sample, level, wbits, mem, strategy)
            if hashlib.sha256(out).hexdigest()[:32] != digest:
                return False
        return True
    except Exception:  # noqa: BLE001
        return False


def is_candidate(path, size: int) -> bool:
    return 0 < size <= MAX_BYTES and path.suffix.lower() in EXTENSIONS and available()


def _split(data: bytes):
    """Return (prefix, [idat payloads], suffix) or None if this isn't a plain PNG."""
    if not data.startswith(SIGNATURE):
        return None
    pos, first, last, idats = len(SIGNATURE), None, None, []
    while pos + 12 <= len(data):
        length, ctype = _CHUNK.unpack_from(data, pos)
        end = pos + 12 + length
        if end > len(data):
            return None
        if ctype == b"IDAT":
            if first is None:
                first = pos
            elif last != pos:
                return None  # IDAT chunks must be consecutive
            idats.append(data[pos + 8:pos + 8 + length])
            last = end
        pos = end
        if ctype == b"IEND":
            break
    if first is None:
        return None
    return data[:first], idats, data[last:]


def _deflate(raw: bytes, level: int, wbits: int, mem: int, strategy: int, expect: bytes | None = None):
    """Compress *raw*; with *expect*, stop (return None) at the first differing byte."""
    c = zlib.compressobj(level, zlib.DEFLATED, wbits, mem, strategy)
    out = bytearray()
    for i in range(0, len(raw), _STEP):
        out += c.compress(raw[i:i + _STEP])
        if expect is not None and out != expect[:len(out)]:
            return None
    out += c.flush()
    if expect is not None and out != expect:
        return None
    return bytes(out)


def _find_params(stream: bytes, raw: bytes):
    if len(stream) < 2 or stream[0] & 0x0F != 8 or ((stream[0] << 8) | stream[1]) % 31:
        return None
    wbits = (stream[0] >> 4) + 8
    if wbits > 15 or stream[1] & 0x20:  # preset dictionary: not produced by plain zlib
        return None
    for level in _LEVELS_BY_FLEVEL[stream[1] >> 6]:
        for mem in _MEM_LEVELS:
            for strategy in _STRATEGIES:
                if _deflate(raw, level, wbits, mem, strategy, stream) is not None:
                    return level, wbits, mem, strategy
    return None


def _build(prefix: bytes, idat_lengths: list[int], suffix: bytes, stream: bytes) -> bytes:
    out = bytearray(prefix)
    pos = 0
    for n in idat_lengths:
        part = stream[pos:pos + n]
        pos += n
        out += _U32.pack(n) + b"IDAT" + part + _U32.pack(zlib.crc32(part, zlib.crc32(b"IDAT")))
    if pos != len(stream):
        raise ValueError("IDAT layout does not match the stream")
    return bytes(out + suffix)


def transcode(data: bytes) -> bytes | None:
    """Return a payload holding the PNG's pixels uncompressed (packs smaller), or None."""
    if not available():
        return None
    try:
        parts = _split(data)
        if parts is None:
            return None
        prefix, idats, suffix = parts
        stream = b"".join(idats)
        d = zlib.decompressobj()
        raw = d.decompress(stream, MAX_RAW)
        if not d.eof or d.unused_data or d.unconsumed_tail:
            return None
        params = _find_params(stream, raw)
        if params is None:
            return None
        level, wbits, mem, strategy = params
        lengths = [len(x) for x in idats]
        if _build(prefix, lengths, suffix, _deflate(raw, *params)) != data:
            return None
        return (_HEAD.pack(MAGIC, level, wbits, mem, strategy, len(prefix)) + prefix
                + _U32.pack(len(suffix)) + suffix + _U32.pack(len(lengths))
                + b"".join(_U32.pack(n) for n in lengths) + raw)
    except (zlib.error, ValueError, struct.error, MemoryError):
        return None


def restore(payload: bytes, expected_size: int, expected_crc: int | None = None) -> bytes:
    try:
        magic, level, wbits, mem, strategy, plen = _HEAD.unpack_from(payload)
        if magic != MAGIC:
            raise ValueError("bad magic")
        pos = _HEAD.size
        prefix = payload[pos:pos + plen]
        pos += plen
        (slen,) = _U32.unpack_from(payload, pos)
        suffix = payload[pos + 4:pos + 4 + slen]
        pos += 4 + slen
        (count,) = _U32.unpack_from(payload, pos)
        pos += 4
        lengths = list(struct.unpack_from(f">{count}I", payload, pos))
        pos += 4 * count
        data = _build(prefix, lengths, suffix, _deflate(payload[pos:], level, wbits, mem, strategy))
    except (zlib.error, ValueError, struct.error) as e:
        raise CorruptFileError(f"malformed recompressed-PNG entry: {e}") from e
    if len(data) != expected_size or (expected_crc is not None and zlib.crc32(data) != expected_crc):
        raise CorruptFileError(
            "a recompressed PNG could not be rebuilt exactly with this computer's zlib "
            f"(version {zlib.ZLIB_RUNTIME_VERSION}); unlock it with the official Crunchlock app")
    return data
