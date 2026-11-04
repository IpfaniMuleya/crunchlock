"""Keep a single desktop-app window.

When several files are chosen in Explorer and "Lock with Crunchlock" is
clicked, Windows starts one process per file. The first one becomes the
window; later ones hand their paths to it over a localhost socket and exit.

The socket only accepts a random per-session token stored in a file that only
the current user can read, and the only thing a message can do is add paths to
the window's list (nothing is locked or opened without the user clicking).
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Callable

MAX_MESSAGE = 1 << 20


def state_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        d = base / "Crunchlock"
    elif sys.platform == "darwin":
        d = Path.home() / "Library" / "Application Support" / "Crunchlock"
    else:
        d = Path(os.environ.get("XDG_RUNTIME_DIR") or Path.home() / ".cache") / "crunchlock"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _info_path(d: Path | None = None) -> Path:
    return (d or state_dir()) / "instance.json"


def forward(paths: list[str], d: Path | None = None, timeout: float = 2.0) -> bool:
    """Send *paths* to a running window. Returns False if none is running."""
    try:
        info = json.loads(_info_path(d).read_text("utf-8"))
        with socket.create_connection(("127.0.0.1", int(info["port"])), timeout=timeout) as s:
            s.sendall(json.dumps({"token": info["token"], "paths": paths}).encode() + b"\n")
            s.shutdown(socket.SHUT_WR)
            return s.recv(16).startswith(b"ok")
    except (OSError, ValueError, KeyError):
        return False


class Server:
    """Listens for paths from later launches; calls *on_paths* on its own thread."""

    def __init__(self, on_paths: Callable[[list[str]], None], d: Path | None = None):
        self.on_paths = on_paths
        self.dir = d or state_dir()
        self.token = secrets.token_hex(16)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        tmp = self.dir / f".instance-{os.getpid()}.json"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"port": self.port, "token": self.token, "pid": os.getpid()}, f)
        os.replace(tmp, _info_path(self.dir))
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(2)
                    data = b""
                    while len(data) < MAX_MESSAGE:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    msg = json.loads(data.decode("utf-8"))
                    if not hmac.compare_digest(str(msg.get("token", "")), self.token):
                        continue
                    paths = [str(p) for p in msg.get("paths", [])][:10_000]
                    conn.sendall(b"ok")
                    self.on_paths(paths)
                except (OSError, ValueError, AttributeError):
                    continue

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass
        try:
            info = json.loads(_info_path(self.dir).read_text("utf-8"))
            if info.get("pid") == os.getpid():
                _info_path(self.dir).unlink()
        except (OSError, ValueError):
            pass


def hand_off_or_become_primary(paths: list[str], d: Path | None = None, wait: float = 4.0) -> bool:
    """True if another window took the paths (this process should exit).

    Several processes may start at once (multi-select in Explorer). A lock file
    elects one to open the window; the others wait for it and then forward.
    """
    d = d or state_dir()
    if forward(paths, d):
        return True
    lock = d / "starting.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        return False  # we start the window; release_startup_lock() once listening
    except FileExistsError:
        try:
            if time.time() - lock.stat().st_mtime > 20:  # left behind by a crash
                lock.unlink()
                return hand_off_or_become_primary(paths, d, wait)
        except OSError:
            pass
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        time.sleep(0.15)
        if forward(paths, d):
            return True
        if not lock.exists():
            break
    # The other starter seems to have died: take over.
    try:
        lock.unlink()
    except OSError:
        pass
    return False


def release_startup_lock(d: Path | None = None) -> None:
    try:
        ((d or state_dir()) / "starting.lock").unlink()
    except OSError:
        pass
