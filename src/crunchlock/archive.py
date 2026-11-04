"""Pack many files/folders into a tar stream; extract safely."""
from __future__ import annotations

import io
import os
import shutil
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from . import jpeg
from .errors import CorruptFileError, CrunchlockError

if not hasattr(tarfile, "data_filter"):  # Python < 3.10.12 / 3.11.4
    raise ImportError("crunchlock needs a Python with tarfile extraction filters (3.10.12+)")

READ_BLOCK = 1 << 20


class _ProgressFile:
    def __init__(self, f, cb):
        self._f, self._cb = f, cb

    def read(self, n=-1):
        b = self._f.read(n)
        if self._cb:
            self._cb(len(b))
        return b


def total_size(paths: list[Path]) -> int:
    total = 0
    for p in paths:
        p = p.resolve()
        if p.is_file():
            total += p.stat().st_size
        elif p.is_dir():
            for root, _dirs, files in os.walk(p):
                for name in files:
                    fp = Path(root, name)
                    if not fp.is_symlink():
                        try:
                            total += fp.stat().st_size
                        except OSError:
                            pass
    return total


def check_inputs(paths: list[Path]) -> list[Path]:
    if not paths:
        raise CrunchlockError("nothing to lock")
    seen: dict[str, Path] = {}
    out = []
    for p in paths:
        p = Path(p)
        if not p.exists() and not p.is_symlink():
            raise CrunchlockError(f"{p} not found")
        name = p.resolve().name if p.name in ("", ".", "..") else p.name
        if name in seen:
            raise CrunchlockError(f"two inputs have the same name {name!r}: {seen[name]} and {p}")
        seen[name] = p
        out.append(p)
    return out


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


class PackStats:
    def __init__(self):
        self.warnings: list[str] = []
        self.jpeg_files = 0
        self.jpeg_saved = 0


class _JpegPrefetcher:
    """Transcodes upcoming JPEGs on worker threads, a bounded window ahead."""

    def __init__(self, items, enabled: bool):
        self._cands = []
        if enabled and jpeg.AVAILABLE:
            for i, (fs_path, _arc) in enumerate(items):
                try:
                    st = fs_path.lstat()
                except OSError:
                    continue
                if not fs_path.is_symlink() and fs_path.is_file() and jpeg.is_candidate(fs_path, st.st_size):
                    self._cands.append(i)
        self._items = items
        self._futures: dict[int, object] = {}
        self._next = 0
        self._window = max(2, 2 * (os.cpu_count() or 2))
        self._pool = ThreadPoolExecutor(max_workers=os.cpu_count() or 2) if self._cands else None
        self._fill()

    def _fill(self):
        while self._pool and self._next < len(self._cands) and len(self._futures) < self._window:
            i = self._cands[self._next]
            self._futures[i] = self._pool.submit(self._work, self._items[i][0])
            self._next += 1

    @staticmethod
    def _work(path: Path):
        try:
            data = path.read_bytes()
        except OSError:
            return None
        jxl = jpeg.transcode(data)
        return (len(data), jxl) if jxl is not None else None

    def get(self, i):
        fut = self._futures.pop(i, None)
        if fut is None:
            return None
        result = fut.result()
        self._fill()
        return result

    def close(self):
        if self._pool:
            for f in self._futures.values():
                f.cancel()
            self._pool.shutdown(wait=True)


def pack(paths: list[Path], writer, progress: Callable[[int], None] | None = None,
         jpeg_recompress: bool = False, stats: PackStats | None = None) -> list[str]:
    """Write a tar stream of *paths* into *writer* (any object with .write).

    Symlinks that point inside the locked folder are kept (made relative).
    Links pointing elsewhere can't be restored safely, so a link to a file is
    stored as a copy of that file and anything else is skipped. Returns
    human-readable warnings about such cases.
    """
    stats = stats if stats is not None else PackStats()
    warnings = stats.warnings
    with tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT,
                      bufsize=READ_BLOCK) as tf:

        def add_file(fs_path, arcname, info=None):
            if info is None:
                info = tf.gettarinfo(str(fs_path), arcname=arcname)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if info.isreg():
                with open(fs_path, "rb") as f:
                    tf.addfile(info, _ProgressFile(f, progress))
            elif info.isdir() or info.islnk():
                tf.addfile(info)

        for p in paths:
            arc_root = p.resolve().name if p.name in ("", ".", "..") else p.name
            real_root = p.resolve()  # a top-level symlink is followed: the user picked it
            if not real_root.exists():
                warnings.append(f"skipped {p}: broken link")
                continue
            items = [(real_root, arc_root)]
            if real_root.is_dir():
                for root, dirs, files in os.walk(real_root):
                    dirs.sort()
                    rel = Path(root).relative_to(real_root)
                    for name in dirs + sorted(files):
                        items.append((Path(root, name), str(Path(arc_root, rel, name))))
            pre = _JpegPrefetcher(items, jpeg_recompress)
            try:
                for i, (fs_path, arcname) in enumerate(items):
                    if not fs_path.is_symlink():
                        info = tf.gettarinfo(str(fs_path), arcname=arcname)
                        if info is None:  # sockets etc.
                            continue
                        jx = pre.get(i) if info.isreg() else None
                        if jx is not None and jx[0] == info.size:
                            orig_size, jxl = jx
                            info.uid = info.gid = 0
                            info.uname = info.gname = ""
                            info.size = len(jxl)
                            info.pax_headers = {jpeg.PAX_KEY: "1", jpeg.PAX_SIZE: str(orig_size)}
                            tf.addfile(info, io.BytesIO(jxl))
                            stats.jpeg_files += 1
                            stats.jpeg_saved += orig_size - len(jxl)
                            if progress:
                                progress(orig_size)
                        else:
                            add_file(fs_path, arcname, info)
                        continue
                    _add_link(tf, fs_path, arcname, real_root, add_file, warnings)
            finally:
                pre.close()
    return warnings


def _add_link(tf, fs_path: Path, arcname: str, real_root: Path, add_file, warnings: list[str]) -> None:
    """Store a symlink found inside a locked folder (see pack() for the rules)."""
    target = fs_path.resolve()
    if real_root.is_dir() and _within(target, real_root) and target.exists():
        info = tf.gettarinfo(str(fs_path), arcname=arcname)
        info.linkname = os.path.relpath(target, fs_path.parent.resolve())
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        tf.addfile(info)
    elif target.is_file():
        info = tf.gettarinfo(str(target), arcname=arcname)
        add_file(target, arcname, info)
        warnings.append(f"{arcname}: link to {target} outside the selection; stored a copy of the file")
    else:
        warnings.append(f"skipped link {arcname} -> {os.readlink(fs_path)} (points outside the selection)")


def _drain(stream) -> None:
    while stream.read(READ_BLOCK):
        pass


def _is_jxl(m: tarfile.TarInfo) -> bool:
    return m.isreg() and m.pax_headers.get(jpeg.PAX_KEY) == "1"


def _restore_jpeg(tf: tarfile.TarFile, m: tarfile.TarInfo) -> bytes:
    try:
        size = int(m.pax_headers.get(jpeg.PAX_SIZE, ""))
    except ValueError:
        raise CorruptFileError("malformed recompressed-JPEG entry") from None
    return jpeg.restore(tf.extractfile(m).read(), size)


def _extract_jpeg(tf: tarfile.TarFile, m: tarfile.TarInfo, staging: Path) -> None:
    try:
        safe = tarfile.data_filter(m, str(staging))
    except tarfile.FilterError as e:
        raise CorruptFileError(f"unsafe entry in archive: {e}") from e
    data = _restore_jpeg(tf, m)
    target = staging / safe.name
    target.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(target):
        target.unlink()
    with open(target, "xb") as f:
        f.write(data)
    if safe.mode is not None:
        os.chmod(target, safe.mode)
    if safe.mtime is not None:
        os.utime(target, (safe.mtime, safe.mtime))


def list_members(stream) -> list[tuple[str, int, bool]]:
    """Read the whole archive, validating every entry. Returns (name, size, is_dir)."""
    entries = []
    with tempfile.TemporaryDirectory() as fake_dest:
        try:
            with tarfile.open(fileobj=stream, mode="r|", bufsize=READ_BLOCK) as tf:
                for m in tf:
                    try:
                        tarfile.data_filter(m, fake_dest)
                    except tarfile.FilterError as e:
                        raise CorruptFileError(f"unsafe entry in archive: {e}") from e
                    if _is_jxl(m):
                        size = len(_restore_jpeg(tf, m))  # proves it restores exactly-sized
                    else:
                        size = m.size
                        if m.isreg():
                            f = tf.extractfile(m)
                            while f.read(READ_BLOCK):
                                pass
                    entries.append((m.name, size, m.isdir()))
        except tarfile.TarError as e:
            raise CorruptFileError(f"archive is malformed: {e}") from e
    _drain(stream)
    return entries


def extract(stream, dest: Path, force: bool = False, before_commit: Callable[[], None] | None = None) -> list[Path]:
    """Extract into a hidden staging dir, then move into *dest* only once complete.

    *before_commit* is called after the archive is fully read; it must raise if
    the data failed authentication. Nothing appears in *dest* until then.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".crunchlock-", dir=dest))
    try:
        try:
            with tarfile.open(fileobj=stream, mode="r|", bufsize=READ_BLOCK) as tf:
                for m in tf:
                    if _is_jxl(m):
                        _extract_jpeg(tf, m, staging)
                        continue
                    try:
                        tf.extract(m, staging, filter="data")
                    except tarfile.FilterError as e:
                        raise CorruptFileError(f"unsafe entry in archive: {e}") from e
        except tarfile.TarError as e:
            raise CorruptFileError(f"archive is malformed: {e}") from e
        _drain(stream)
        if before_commit:
            before_commit()
        names = sorted(os.listdir(staging))
        clashes = [n for n in names if os.path.lexists(dest / n)]
        if clashes and not force:
            raise CrunchlockError("refusing to overwrite existing: " + ", ".join(clashes)
                                  + " (use --force or choose another output folder)")
        out = []
        for n in names:
            target = dest / n
            if os.path.lexists(target):
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            os.replace(staging / n, target)
            out.append(target)
        return out
    finally:
        shutil.rmtree(staging, ignore_errors=True)
