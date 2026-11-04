"""Optional lossless compression (zstd / xz) as streaming push writers / pull readers.

The first plaintext byte inside the encrypted stream names the algorithm, so
which compressor was used is not visible without the key.
"""
from __future__ import annotations

import lzma

import zstandard as zstd

from .errors import CorruptFileError

NONE, ZSTD, LZMA = 0, 1, 2
NAMES = {NONE: "none", ZSTD: "zstd", LZMA: "xz"}
BY_NAME = {"none": NONE, "zstd": ZSTD, "xz": LZMA, "lzma": LZMA}
DEFAULT_LEVEL = {ZSTD: 19, LZMA: 9}
LEVEL_RANGE = {ZSTD: (1, 22), LZMA: (0, 9)}


def _zstd_params(level: int):
    # A 16 MiB job size lets the high levels use every CPU core with no loss in ratio.
    return zstd.ZstdCompressionParameters.from_level(
        level, enable_ldm=level >= 15, threads=-1, job_size=16 << 20, write_checksum=0)


class CompressWriter:
    def __init__(self, target, algo: int, level: int | None = None):
        self._t = target
        self.algo = algo
        if level is None:
            level = DEFAULT_LEVEL.get(algo, 0)
        if algo == ZSTD:
            self._obj = zstd.ZstdCompressor(compression_params=_zstd_params(level)).compressobj()
        elif algo == LZMA:
            self._obj = lzma.LZMACompressor(format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE,
                                            preset=level | lzma.PRESET_EXTREME)
        else:
            self._obj = None
        target.write(bytes([algo]))
        self._closed = False

    def write(self, data) -> int:
        if self._obj is None:
            self._t.write(data)
        else:
            out = self._obj.compress(bytes(data))
            if out:
                self._t.write(out)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._obj is not None:
            self._t.write(self._obj.flush())
        self._t.close()


class CountingSink:
    """Discards data, counting bytes (used to measure compressed size)."""

    def __init__(self):
        self.count = 0

    def write(self, data) -> int:
        self.count += len(data)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class DecompressReader:
    """Bounded-memory decompression of the inner stream."""

    def __init__(self, source):
        self._s = source
        head = source.read(1)
        if len(head) != 1 or head[0] not in NAMES:
            raise CorruptFileError("unknown compression method")
        self.algo = head[0]
        if self.algo == ZSTD:
            self._r = zstd.ZstdDecompressor(max_window_size=2**31).stream_reader(
                source, read_across_frames=False, closefd=False)
        elif self.algo == LZMA:
            self._d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            self._pending = b""

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = 1 << 62
        try:
            if self.algo == NONE:
                return self._s.read(n)
            if self.algo == ZSTD:
                return self._r.read(min(n, 1 << 24))
            return self._read_lzma(min(n, 1 << 24))
        except (zstd.ZstdError, lzma.LZMAError) as e:
            raise CorruptFileError(f"decompression failed: {e}") from e

    def _read_lzma(self, n: int) -> bytes:
        d = self._d
        while True:
            if d.eof:
                return b""
            if d.needs_input:
                data = self._s.read(1 << 20)
                if not data:
                    raise CorruptFileError("compressed data ended unexpectedly")
            else:
                data = b""
            out = d.decompress(data, max_length=n)
            if out:
                return out
