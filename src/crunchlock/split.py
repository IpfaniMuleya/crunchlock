"""Output sinks (single file or multi-part ``.001 .002 ...``) with atomic commit."""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from .errors import CorruptFileError, CrunchlockError

_PART_RE = re.compile(r"^(.*)\.(\d{3,})$")


def parse_size(text: str) -> int:
    """'100M' -> 104857600. Accepts K/M/G/T suffixes (binary)."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?\s*", text.lower())
    if not m:
        raise CrunchlockError(f"invalid size {text!r} (examples: 500K, 100M, 4G)")
    mult = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}[m.group(2)]
    size = int(float(m.group(1)) * mult)
    if size < 64 * 1024:
        raise CrunchlockError("split size must be at least 64K")
    return size


def part_name(base: Path, index: int) -> Path:
    return base.with_name(f"{base.name}.{index:03d}")


class OutputSink:
    """Writes to temporary files; ``commit()`` renames them into place."""

    def __init__(self, base: Path, part_size: int | None = None, force: bool = False):
        self.base = Path(base)
        self.part_size = part_size
        self.force = force
        self._tmp: list[Path] = []
        self._final: list[Path] = []
        self._f = None
        self._written_in_part = 0
        self.total = 0
        if not force:
            if self.base.exists() or part_name(self.base, 1).exists():
                raise CrunchlockError(f"{self.base} already exists (use --force to overwrite)")
        self._open_next()

    def _open_next(self) -> None:
        if self._f:
            self._f.close()
        final = part_name(self.base, len(self._final) + 1) if self.part_size else self.base
        tmp = final.with_name(f".{final.name}.{secrets.token_hex(4)}.partial")
        self._f = open(tmp, "xb")
        self._tmp.append(tmp)
        self._final.append(final)
        self._written_in_part = 0

    def write(self, data) -> int:
        mv = memoryview(data)
        while mv:
            if self.part_size and self._written_in_part >= self.part_size:
                self._open_next()
            room = len(mv) if not self.part_size else self.part_size - self._written_in_part
            n = min(room, len(mv))
            self._f.write(mv[:n])
            self._written_in_part += n
            self.total += n
            mv = mv[n:]
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if self._f and not self._f.closed:
            self._f.flush()
            os.fsync(self._f.fileno())
            self._f.close()

    def commit(self) -> list[Path]:
        self.close()
        if self.force and self.part_size:
            # Remove stale parts from an earlier, longer split of the same name.
            i = len(self._final) + 1
            while part_name(self.base, i).exists():
                part_name(self.base, i).unlink()
                i += 1
        for tmp, final in zip(self._tmp, self._final):
            os.replace(tmp, final)
        return list(self._final)

    def abort(self) -> None:
        if self._f and not self._f.closed:
            self._f.close()
        for tmp in self._tmp:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass


def resolve_parts(path: Path) -> list[Path]:
    """Find the file(s) that make up a locked file (handles split parts)."""
    path = Path(path)
    m = _PART_RE.match(path.name)
    if m and part_name(path.with_name(m.group(1)), 1).exists():
        base = path.with_name(m.group(1))
    elif path.exists():
        return [path]
    elif part_name(path, 1).exists():
        base = path
    else:
        raise CrunchlockError(f"{path} not found")
    parts = []
    i = 1
    while part_name(base, i).exists():
        parts.append(part_name(base, i))
        i += 1
    if not parts:
        raise CrunchlockError(f"first part {part_name(base, 1)} not found")
    later = sorted(p for p in base.parent.glob(base.name + ".*")
                   if _PART_RE.match(p.name) and p not in parts)
    if later:
        raise CorruptFileError(f"part {part_name(base, i).name} is missing")
    return parts


class MultiReader:
    """Reads several files as one continuous stream."""

    def __init__(self, paths: list[Path]):
        self._paths = list(paths)
        self.total = sum(p.stat().st_size for p in self._paths)
        self._f = None
        self._i = 0

    def read(self, n: int = -1) -> bytes:
        out = bytearray()
        while n < 0 or len(out) < n:
            if self._f is None:
                if self._i >= len(self._paths):
                    break
                self._f = open(self._paths[self._i], "rb")
                self._i += 1
            b = self._f.read(-1 if n < 0 else n - len(out))
            if not b:
                self._f.close()
                self._f = None
                continue
            out += b
        return bytes(out)

    def close(self) -> None:
        if self._f:
            self._f.close()
            self._f = None
