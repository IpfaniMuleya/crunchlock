"""Best-effort secure deletion of the original plaintext.

WARNING: on SSDs (wear levelling), copy-on-write filesystems (btrfs, ZFS, APFS),
journaling, snapshots, backups and cloud-synced folders, old copies of the data
may survive. Full-disk encryption is the only reliable protection there.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

WARNING = ("Secure delete is best-effort: SSDs, copy-on-write filesystems, snapshots "
           "and backups may keep old copies of the data.")


def _shred_file(p: Path) -> None:
    size = p.stat().st_size
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    with open(p, "r+b", buffering=0) as f:
        left = size
        while left > 0:
            n = min(left, 1 << 20)
            f.write(secrets.token_bytes(n))
            left -= n
        f.flush()
        os.fsync(f.fileno())
        f.truncate(0)
        os.fsync(f.fileno())
    renamed = p.with_name(secrets.token_hex(8))
    os.replace(p, renamed)
    renamed.unlink()


def shred(path: Path) -> None:
    path = Path(path)
    if path.is_symlink():
        path.unlink()  # never follow links
        return
    if path.is_dir():
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                fp = Path(root, name)
                if fp.is_symlink() or not fp.is_file():
                    fp.unlink()
                else:
                    _shred_file(fp)
            for name in dirs:
                dp = Path(root, name)
                if dp.is_symlink():
                    dp.unlink()
                else:
                    dp.rmdir()
        path.rmdir()
    else:
        _shred_file(path)
