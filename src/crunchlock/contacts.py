"""Named public keys ("contacts") so people can be picked by name.

Stored as JSON next to the settings (see settings.config_dir()). Only public
keys are kept here, never private keys or passwords.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import keys
from .errors import CrunchlockError
from .settings import config_dir


def _path() -> Path:
    return config_dir() / "contacts.json"


def load() -> dict[str, str]:
    """{name: public key text}. A missing or damaged file gives an empty list."""
    try:
        raw = json.loads(_path().read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    out = {}
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("name"), str) \
                    and isinstance(item.get("key"), str):
                try:
                    keys.parse_public_text(item["key"])
                except CrunchlockError:
                    continue
                out[item["name"]] = item["key"].strip()
    return out


def _save(data: dict[str, str]) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps([{"name": n, "key": k} for n, k in sorted(data.items(),
                               key=lambda x: x[0].lower())], indent=1), "utf-8")
    os.replace(tmp, p)


def add(name: str, key_text: str) -> None:
    name = name.strip()
    if not name or name.startswith((keys.PUB_PREFIX, keys.PUB2_PREFIX)) or len(name) > 80:
        raise CrunchlockError("give the contact a short name")
    keys.parse_public_text(key_text)  # validates
    data = load()
    data[name] = key_text.strip()
    _save(data)


def remove(name: str) -> None:
    data = load()
    if data.pop(name, None) is None:
        raise CrunchlockError(f"no contact named {name!r}")
    _save(data)


def find(name: str) -> str | None:
    """Public key text of a contact (exact name, then case-insensitive)."""
    data = load()
    if name in data:
        return data[name]
    for n, k in data.items():
        if n.lower() == name.strip().lower():
            return k
    return None


def name_for_verify_key(raw: bytes) -> str | None:
    """Which contact a signing key belongs to (only clkpub2 keys can match)."""
    for n, k in load().items():
        try:
            ed = keys.parse_public_text(k)[1]
        except CrunchlockError:
            continue
        if ed is not None and ed.public_bytes_raw() == raw:
            return n
    return None
