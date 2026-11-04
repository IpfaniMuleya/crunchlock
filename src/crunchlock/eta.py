"""Time-remaining estimates for progress displays."""
from __future__ import annotations

import time


class Eta:
    """Smoothed time-remaining estimate; resets when the stage changes."""

    def __init__(self, warmup: float = 2.0, smoothing: float = 0.25):
        self.warmup = warmup
        self.smoothing = smoothing
        self._stage = None
        self._start = 0.0
        self._last_t = 0.0
        self._last_done = 0
        self._rate = None

    def update(self, stage: str, done: int, total: int, now: float | None = None) -> float | None:
        """Return estimated seconds left, or None while there's no good estimate yet."""
        now = time.monotonic() if now is None else now
        if stage != self._stage or done < self._last_done:
            self._stage, self._start, self._last_t, self._last_done, self._rate = stage, now, now, done, None
            return None
        dt = now - self._last_t
        if dt >= 0.5:
            inst = (done - self._last_done) / dt
            self._rate = inst if self._rate is None else (
                self.smoothing * inst + (1 - self.smoothing) * self._rate)
            self._last_t, self._last_done = now, done
        if now - self._start < self.warmup or not self._rate or not total or done >= total:
            return None
        return (total - done) / self._rate


def format_eta(seconds: float | None) -> str:
    if seconds is None:
        return ""
    s = int(seconds + 0.5)
    if s < 5:
        return "almost done"
    if s < 60:
        return f"about {s} s left"
    m, s = divmod(s, 60)
    if m < 60:
        return f"about {m} min {s:02d} s left" if m < 10 else f"about {m} min left"
    h, m = divmod(m, 60)
    return f"about {h} h {m:02d} min left"
