"""Remembered app preferences and recent files (never passwords or keys).

Stored as JSON in the per-user config folder:
  Windows  %APPDATA%\\Crunchlock\\settings.json
  macOS    ~/Library/Application Support/Crunchlock/settings.json
  Linux    $XDG_CONFIG_HOME/crunchlock/settings.json (default ~/.config)
Set CRUNCHLOCK_CONFIG_DIR to use another folder (tests do this).

Only option values, folders and recently opened .clk paths are stored. A corrupt
or unreadable file is ignored and the defaults are used.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

MAX_RECENT = 8

DEFAULTS: dict = {
    "theme": None,            # None = follow the system, else "light" / "dark"
    "compress": True,
    "preset": 0,              # index into gui.PRESETS
    "jpeg": True,
    "profile": "standard",
    "pad": False,
    "recovery": False,
    "split": False,
    "split_size": "100M",
    "each": False,
    "save_dir": "",           # last folder chosen for "lock each" output
    "extract_dir": "",        # last folder chosen to extract into
    "geometry": "",
    "recent": [],             # recently used .clk files, newest first
}
# Never persist these, whatever a caller passes in.
FORBIDDEN = {"password", "passphrase", "keyfile", "identity", "key", "pw"}


def config_dir() -> Path:
    override = os.environ.get("CRUNCHLOCK_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "Crunchlock"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Crunchlock"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "crunchlock"


class Settings:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else config_dir() / "settings.json"
        self.data = dict(DEFAULTS)
        self.data["recent"] = []
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for k, default in DEFAULTS.items():
            v = raw.get(k, default)
            if k == "theme":
                ok = v in (None, "light", "dark")
            else:
                # bool is a subclass of int: don't let True stand in for a number or vice versa
                ok = type(v) is type(default)
            if ok:
                self.data[k] = v
        self.data["recent"] = [r for r in self.data.get("recent", []) if isinstance(r, str)][:MAX_RECENT]

    def save(self) -> None:
        clean = {k: v for k, v in self.data.items() if k in DEFAULTS and k not in FORBIDDEN}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(clean, f, indent=1)
            os.replace(tmp, self.path)
        except OSError:
            pass  # settings are a convenience; never fail the app over them

    def get(self, key):
        return self.data.get(key, DEFAULTS.get(key))

    def set(self, key, value) -> None:
        if key in FORBIDDEN or key not in DEFAULTS:
            raise KeyError(f"not a remembered setting: {key}")
        self.data[key] = value

    # -- recent files
    def recent(self) -> list[str]:
        """Recent .clk files that still exist, newest first."""
        return [p for p in self.data["recent"] if os.path.exists(p)]

    def add_recent(self, path) -> None:
        p = str(Path(path).resolve())
        items = [r for r in self.data["recent"] if r != p]
        self.data["recent"] = [p] + items[:MAX_RECENT - 1]

    def clear_recent(self) -> None:
        self.data["recent"] = []

    def reset(self) -> None:
        self.data = dict(DEFAULTS)
        self.data["recent"] = []
        try:
            self.path.unlink()
        except OSError:
            pass
