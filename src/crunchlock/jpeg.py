"""Lossless JPEG recompression via JPEG XL ("JPEG reconstruction").

A JPEG is transcoded to JPEG XL in a mode that keeps everything needed to
rebuild the *exact original file*, byte for byte. Typical saving: 15-22%,
on data that general-purpose compressors can't shrink at all.

Safety: every transcode is decoded again immediately and compared with the
original bytes; if anything differs (or the JPEG is unusual, e.g. CMYK), the
original file is stored unchanged instead.
"""
from __future__ import annotations

from pathlib import Path

from .errors import CorruptFileError, CrunchlockError

EXTENSIONS = {".jpg", ".jpeg", ".jpe", ".jfif"}
MAX_BYTES = 128 * 1024 * 1024
PAX_KEY = "CRUNCHLOCK.jxl"
PAX_SIZE = "CRUNCHLOCK.size"

try:
    # Import the codec module directly (not via imagecodecs' lazy loader) so that
    # bundlers like PyInstaller can see and include it.
    from imagecodecs._jpegxl import jpegxl_decode_jpeg, jpegxl_encode_jpeg
    AVAILABLE = True
except Exception:  # noqa: BLE001 - missing library or codec
    try:
        from imagecodecs import jpegxl_decode_jpeg, jpegxl_encode_jpeg
        AVAILABLE = True
    except Exception:  # noqa: BLE001
        AVAILABLE = False


def is_candidate(path: Path, size: int) -> bool:
    return AVAILABLE and 0 < size <= MAX_BYTES and path.suffix.lower() in EXTENSIONS


def transcode(data: bytes) -> bytes | None:
    """Return a smaller, exactly reversible JPEG XL version of *data*, or None."""
    if not AVAILABLE or not data.startswith(b"\xff\xd8\xff"):
        return None
    try:
        jxl = bytes(jpegxl_encode_jpeg(data))
        if len(jxl) >= len(data):
            return None
        if bytes(jpegxl_decode_jpeg(jxl)) != data:
            return None
    except Exception:  # noqa: BLE001 - unsupported JPEG variant: keep the original
        return None
    return jxl


def restore(jxl: bytes, expected_size: int) -> bytes:
    if not AVAILABLE:
        raise CrunchlockError("this file contains losslessly recompressed photos; "
                              "install the 'imagecodecs' package to unlock it")
    try:
        data = bytes(jpegxl_decode_jpeg(jxl))
    except Exception as e:  # noqa: BLE001
        raise CorruptFileError(f"could not restore a recompressed JPEG: {e}") from e
    if len(data) != expected_size or not data.startswith(b"\xff\xd8\xff"):
        raise CorruptFileError("a recompressed JPEG did not restore to its original size")
    return data
