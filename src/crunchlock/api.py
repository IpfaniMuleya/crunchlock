"""High-level API: lock / unlock / verify / info."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from . import archive, compress, kdf, keys, recovery
from .crypto import DecryptReader, EncryptWriter
from .errors import CorruptFileError, CrunchlockError, WrongKeyError  # noqa: F401 (re-export)
from .format import Header, PasswordSlot, read_header
from .shred import shred
from .split import MultiReader, OutputSink, resolve_parts

CHUNK_SIZE = 1 << 20
SAMPLE_BYTES = 8 << 20
EXT = ".clk"

# progress(stage, done, total)
Progress = Callable[[str, int, int], None] | None


@dataclass
class LockResult:
    outputs: list[Path]
    input_bytes: int
    output_bytes: int
    compression: str
    compression_note: str = ""
    shredded: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def saved_percent(self) -> float:
        if not self.input_bytes:
            return 0.0
        return 100.0 * (1 - self.output_bytes / self.input_bytes)


@dataclass
class UnlockResult:
    extracted: list[Path]
    compression: str
    repaired_bytes: int = 0


@dataclass
class VerifyResult:
    entries: list[tuple[str, int, bool]]
    compression: str
    repaired_bytes: int = 0

    @property
    def total_bytes(self) -> int:
        return sum(e[1] for e in self.entries)


class _StopSampling(Exception):
    pass


class _Tee:
    """Feeds one stream to several writers (optionally only the first *limit* bytes)."""

    def __init__(self, targets, limit=None):
        self.targets, self.limit, self.raw = targets, limit, 0

    def write(self, data):
        if self.limit is not None and self.raw >= self.limit:
            raise _StopSampling
        for t in self.targets:
            t.write(data)
        self.raw += len(data)
        return len(data)

    def flush(self):
        pass


def default_output(paths: list[Path]) -> Path:
    first = Path(paths[0])
    name = first.resolve().name if first.name in ("", ".", "..") else first.name
    if len(paths) > 1:
        name = name + "-and-more"
    return first.resolve().parent / (name + EXT)


def _looks_incompressible(paths, progress: Progress) -> bool:
    """Quick check on the first few MB using a fast compressor."""
    sink = compress.CountingSink()
    w = compress.CompressWriter(sink, compress.ZSTD, 3)
    tap = _Tee([w], SAMPLE_BYTES)
    if progress:
        progress("analyzing", 0, 1)
    try:
        archive.pack(paths, tap)
    except _StopSampling:
        pass
    w.close()
    return tap.raw > 4096 and sink.count >= tap.raw * 0.98


def _validate_level(algo: int, level: int | None) -> None:
    if level is None or algo == compress.NONE:
        return
    lo, hi = compress.LEVEL_RANGE[algo]
    if not lo <= level <= hi:
        raise CrunchlockError(f"{compress.NAMES[algo]} level must be between {lo} and {hi}")


class _Pipeline:
    """tar bytes -> compress -> encrypt (+pad) -> [Reed-Solomon] -> file(s)."""

    def __init__(self, out: Path, algo: int, level: int | None, *, password, keyfile, recipients,
                 params, pad, recovery_data, split_size, force):
        self.file_key = keys.new_file_key()
        header = Header(chunk_size=CHUNK_SIZE, nonce_prefix=os.urandom(7))
        prefix = header.prefix()
        if password or keyfile is not None:
            header.slots.append(keys.make_password_slot(prefix, self.file_key, password, keyfile, params))
        for r in recipients:
            header.slots.append(keys.make_x25519_slot(prefix, self.file_key, r))
        self.algo = algo
        self.sink = OutputSink(out, split_size, force)
        try:
            target = recovery.RSWriter(self.sink) if recovery_data else self.sink
            enc = EncryptWriter(target, header.pack(), self.file_key, CHUNK_SIZE,
                                header.nonce_prefix, pad)
            self.writer = compress.CompressWriter(enc, algo, level)
        except BaseException:
            self.sink.abort()
            raise

    def write(self, data):
        return self.writer.write(data)

    def flush(self):
        pass

    def finish(self) -> None:
        self.writer.close()


def lock(paths: Iterable[str | Path], output: str | Path | None = None, *,
         password: str | None = None, keyfile: bytes | None = None,
         recipients: Iterable[X25519PublicKey] = (), compression: str = "zstd",
         level: int | None = None, kdf_profile: str | kdf.KdfParams = "standard",
         pad: bool = False, recovery_data: bool = False, split_size: int | None = None,
         shred_originals: bool = False, force: bool = False,
         progress: Progress = None) -> LockResult:
    """Compress (optionally) and encrypt *paths* into one ``.clk`` file (or parts).

    compression: "zstd" (default), "xz", "best" (tries both, keeps the smaller) or "none".
    """
    paths = archive.check_inputs([Path(p) for p in paths])
    recipients = list(recipients)
    if not password and keyfile is None and not recipients:
        raise CrunchlockError("give a password, keyfile and/or at least one recipient public key")
    params = kdf.PROFILES[kdf_profile] if isinstance(kdf_profile, str) else kdf_profile
    out = Path(output) if output else default_output(paths)
    for p in paths:
        rp = p.resolve()
        if out.resolve() == rp or (rp.is_dir() and rp in out.resolve().parents):
            raise CrunchlockError("the output file can't be inside what you're locking")

    mode = compression.lower()
    if mode not in ("best", *compress.BY_NAME):
        raise CrunchlockError(f"unknown compression {compression!r} (choose zstd, xz, best or none)")
    note = ""
    if mode == "none":
        algos = [compress.NONE]
    else:
        if mode != "best":
            _validate_level(compress.BY_NAME[mode], level)
        if _looks_incompressible(paths, progress):
            algos = [compress.NONE]
            note = "data looks already compressed (e.g. photos/videos/zip); stored without compression"
        elif mode == "best":
            algos = [compress.ZSTD, compress.LZMA]
        else:
            algos = [compress.BY_NAME[mode]]

    if progress:
        progress("deriving key", 0, 1)
    common = dict(password=password, keyfile=keyfile, recipients=recipients, params=params,
                  pad=pad, recovery_data=recovery_data, split_size=split_size, force=force)
    pipes: list[_Pipeline] = []
    try:
        if len(algos) == 1:
            pipes.append(_Pipeline(out, algos[0], level, **common))
        else:
            # "best": compress with both in one pass, into separate *encrypted* temp
            # outputs (no plaintext ever touches the disk), and keep the smaller one.
            pipes.append(_Pipeline(out, compress.ZSTD, level, **common))
            pipes.append(_Pipeline(out, compress.LZMA, None, **common))
        total = archive.total_size(paths)
        done = [0]

        def cb(n):
            done[0] += n
            if progress:
                progress("locking", done[0], total)

        warnings = archive.pack(paths, pipes[0] if len(pipes) == 1 else _Tee(pipes), cb)
        for pipe in pipes:
            pipe.finish()
        best = min(pipes, key=lambda pp: pp.sink.total)
        for pipe in pipes:
            if pipe is not best:
                pipe.sink.abort()
        outputs = best.sink.commit()
    except BaseException:
        for pipe in pipes:
            pipe.sink.abort()
        raise
    if len(pipes) > 1:
        sizes = {compress.NAMES[pp.algo]: pp.sink.total for pp in pipes}
        note = "best of " + ", ".join(f"{k} {v / 1048576:.2f} MB" for k, v in sizes.items()) \
            + f" -> kept {compress.NAMES[best.algo]}"

    result = LockResult(outputs, total, best.sink.total, compress.NAMES[best.algo], note,
                        warnings=warnings)
    if shred_originals:
        # Only destroy the originals after proving the new file opens correctly.
        if progress:
            progress("verifying", 0, 1)
        _open_and_verify(outputs, file_key=best.file_key)
        if warnings:
            result.warnings.append("originals NOT deleted because some links could not be "
                                   "stored exactly; delete them yourself after checking")
        else:
            for p in paths:
                shred(p)
                result.shredded.append(p)
    return result


def _open(path_or_parts, password=None, keyfile=None, identity=None, file_key=None, progress=None,
          stage="unlocking"):
    parts = path_or_parts if isinstance(path_or_parts, list) else resolve_parts(Path(path_or_parts))
    mr = MultiReader(parts)
    stream, rs = recovery.open_layer(mr)
    try:
        header, raw = read_header(stream)
    except CorruptFileError:
        mr.close()
        raise
    if file_key is None:
        if progress:
            progress("deriving key", 0, 1)
        file_key = keys.open_file_key(header, password, keyfile,
                                      identity.private if isinstance(identity, keys.Identity) else identity)
    total = mr.total

    def cb(n):
        if progress:
            progress(stage, min(n, total), total)

    dec = DecryptReader(stream, raw, file_key, header.chunk_size, header.nonce_prefix, cb)
    decomp = compress.DecompressReader(dec)

    def finish():
        if dec.read(1):
            raise CorruptFileError("unexpected data after the end of the compressed stream")
        dec.read_all_and_discard()
        if not dec.finished:
            raise CorruptFileError("file is truncated")
        mr.close()

    return decomp, finish, rs


def _open_and_verify(parts, **kw) -> VerifyResult:
    decomp, finish, rs = _open(parts, **kw)
    entries = archive.list_members(decomp)
    finish()
    return VerifyResult(entries, compress.NAMES[decomp.algo], rs.corrected_bytes if rs else 0)


def verify(path: str | Path, *, password=None, keyfile=None, identity=None,
           progress: Progress = None) -> VerifyResult:
    """Fully decrypt and check a file (integrity + password) without writing anything."""
    return _open_and_verify(Path(path), password=password, keyfile=keyfile, identity=identity,
                            progress=progress, stage="verifying")


def unlock(path: str | Path, dest: str | Path | None = None, *, password=None, keyfile=None,
           identity=None, force: bool = False, progress: Progress = None) -> UnlockResult:
    path = Path(path)
    dest = Path(dest) if dest else path.resolve().parent
    decomp, finish, rs = _open(path, password=password, keyfile=keyfile, identity=identity,
                               progress=progress)
    extracted = archive.extract(decomp, dest, force, before_commit=finish)
    return UnlockResult(extracted, compress.NAMES[decomp.algo], rs.corrected_bytes if rs else 0)


def info(path: str | Path) -> dict:
    """Describe a locked file without needing the password."""
    parts = resolve_parts(Path(path))
    mr = MultiReader(parts)
    try:
        stream, rs = recovery.open_layer(mr)
        header, raw = read_header(stream)
    finally:
        mr.close()
    slots = []
    for s in header.slots:
        if isinstance(s, PasswordSlot):
            slots.append({"type": "password" + (" + keyfile" if s.uses_keyfile else ""),
                          "kdf": "argon2id",
                          "time_cost": s.params.time_cost,
                          "memory_mib": s.params.memory_kib // 1024,
                          "parallelism": s.params.parallelism})
        else:
            slots.append({"type": "public key (X25519)"})
    return {
        "parts": [str(p) for p in parts],
        "size": sum(p.stat().st_size for p in parts),
        "format_version": header.version,
        "cipher": "AES-256-GCM (chunked)",
        "chunk_size": header.chunk_size,
        "recovery_data": rs is not None,
        "key_slots": slots,
        "needs_keyfile": keys.needs_keyfile(header),
    }


def load_identity(path: str | Path, passphrase: str) -> keys.Identity:
    return keys.load_private_key(Path(path).read_bytes(), passphrase)


def load_recipient(text_or_path: str) -> X25519PublicKey:
    p = Path(text_or_path)
    if not text_or_path.startswith(keys.PUB_PREFIX) and p.exists():
        text_or_path = p.read_text("utf-8")
    return keys.public_key_from_text(text_or_path)
