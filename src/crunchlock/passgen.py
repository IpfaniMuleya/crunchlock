"""Diceware-style passphrase generator and a simple strength estimate."""
from __future__ import annotations

import math
import re
import secrets
from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    text = resources.files("crunchlock").joinpath("data/eff_large_wordlist.txt").read_text("utf-8")
    words = tuple(w.strip() for w in text.splitlines() if w.strip())
    assert len(words) == 7776 and len(set(words)) == 7776, "wordlist damaged"
    return words


BITS_PER_WORD = math.log2(7776)  # ~12.9


def generate(words: int = 6, separator: str = "-") -> str:
    if not 4 <= words <= 20:
        raise ValueError("choose between 4 and 20 words")
    wl = wordlist()
    return separator.join(secrets.choice(wl) for _ in range(words))


def passphrase_bits(words: int) -> float:
    return words * BITS_PER_WORD


_COMMON = {
    "password", "123456", "12345678", "qwerty", "letmein", "iloveyou", "admin",
    "welcome", "monkey", "dragon", "football", "baseball", "abc123", "111111",
    "sunshine", "princess", "master", "shadow", "passw0rd", "trustno1", "secret",
}
_SEQS = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm")


def estimate_bits(pw: str) -> float:
    """Rough, conservative entropy estimate in bits."""
    if not pw:
        return 0.0
    tokens = [t for t in re.split(r"[\s\-_.,]+", pw.lower()) if t]
    wl = set(wordlist())
    if len(tokens) >= 3 and all(t in wl for t in tokens):
        return len(tokens) * BITS_PER_WORD
    low = pw.lower()
    if low in _COMMON or re.sub(r"\d+$", "", low) in _COMMON:
        return 10.0
    dict_bits = _dictionary_estimate(pw)
    if dict_bits is not None:
        return dict_bits
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        pool += 33
    # Collapse repeats and sequences, which add little real entropy.
    effective = 0
    prev = ""
    for i, ch in enumerate(low):
        if ch == prev:
            effective += 0.25
        elif i and any(low[i - 1:i + 1] in s for s in _SEQS):
            effective += 0.5
        else:
            effective += 1
        prev = ch
    bits = effective * math.log2(max(pool, 2))
    for w in _COMMON:
        if len(w) >= 4 and w in low:
            bits -= 4 * len(w)
    return max(bits, 0.0)


_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
                       "@": "a", "$": "s", "!": "i", "+": "t"})


@lru_cache(maxsize=1)
def _dictionary() -> frozenset:
    return frozenset(w for w in wordlist() if len(w) >= 4) | frozenset(_COMMON) | frozenset(_EXTRA_WORDS)


_EXTRA_WORDS = ("summer", "winter", "spring", "autumn", "troubador", "troubadour", "love",
                "hello", "money", "computer", "internet", "google", "admin", "login")


def _dictionary_estimate(pw: str) -> float | None:
    """If the password is mostly dictionary words (with leetspeak), estimate cheaply."""
    core = pw.lower().translate(_LEET)
    words = _dictionary()
    i, matched, bits = 0, 0, 0.0
    while i < len(core):
        best = 0
        for j in range(min(len(core), i + 12), i + 3, -1):
            if core[i:j] in words:
                best = j - i
                break
        if best:
            bits += 13 + 1  # one word from a big list + its leet/case variation
            matched += best
            i += best
        else:
            bits += math.log2(95) * 0.6  # leftover symbol/digit, often predictable
            i += 1
    if matched >= max(4, len(core) // 2):
        if pw != pw.lower():
            bits += 1
        return bits
    return None


def rating(bits: float) -> str:
    if bits < 45:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 75:
        return "strong"
    return "very strong"
