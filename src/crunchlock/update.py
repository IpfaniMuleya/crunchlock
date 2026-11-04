"""Optional check for a newer Crunchlock release (off unless the user turns it on).

Makes one HTTPS request to GitHub's public releases API and reads only the
latest version number. Nothing about the user or their files is sent, and
nothing is downloaded or installed automatically.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.request
from dataclasses import dataclass

from . import __version__

REPO = "IpfaniMuleya/crunchlock"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_URL = f"https://github.com/{REPO}/releases"
_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


@dataclass
class UpdateInfo:
    current: str
    latest: str
    url: str

    @property
    def newer(self) -> bool:
        return parse_version(self.latest) > parse_version(self.current)


def parse_version(text: str) -> tuple[int, int, int]:
    m = _TAG.match(text.strip())
    if not m:
        raise ValueError(f"not a version number: {text!r}")
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def _context() -> ssl.SSLContext:
    try:
        import certifi  # bundled builds may not see the system's certificates
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def check(timeout: float = 6.0, current: str = __version__, opener=None) -> UpdateInfo:
    """Ask GitHub for the latest release. Raises OSError/ValueError if that fails."""
    req = urllib.request.Request(API_URL, headers={
        "Accept": "application/vnd.github+json", "User-Agent": f"crunchlock/{current}"})
    if opener is None:
        resp = urllib.request.urlopen(req, timeout=timeout, context=_context())  # noqa: S310
    else:
        resp = opener(req, timeout)
    with resp:
        data = json.loads(resp.read(256 * 1024).decode("utf-8"))
    tag = str(data.get("tag_name", ""))
    parse_version(tag)  # only accept a plain version number
    latest = tag.lstrip("v")
    return UpdateInfo(current, latest, f"{RELEASES_URL}/tag/{tag}")
