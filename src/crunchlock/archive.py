"""Pack many files/folders into a tar stream; extract safely."""
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Callable

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


def pack(paths: list[Path], writer, progress: Callable[[int], None] | None = None) -> list[str]:
    """Write a tar stream of *paths* into *writer* (any object with .write).

    Symlinks that point inside the locked folder are kept (made relative).
    Links pointing elsewhere can't be restored safely, so a link to a file is
    stored as a copy of that file and anything else is skipped. Returns
    human-readable warnings about such cases.
    """
    warnings: list[str] = []
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
            for fs_path, arcname in items:
                if not fs_path.is_symlink():
                    info = tf.gettarinfo(str(fs_path), arcname=arcname)
                    if info is not None:  # None for sockets etc.
                        add_file(fs_path, arcname, info)
                    continue
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
    return warnings


def _drain(stream) -> None:
    while stream.read(READ_BLOCK):
        pass


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
                    if m.isreg():
                        f = tf.extractfile(m)
                        while f.read(READ_BLOCK):
                            pass
                    entries.append((m.name, m.size, m.isdir()))
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
