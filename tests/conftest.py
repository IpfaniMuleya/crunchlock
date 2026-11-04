import os

import pytest

from crunchlock import api

FAST = "insecure-test"


@pytest.fixture(autouse=True)
def _own_config_dir(tmp_path, monkeypatch):
    """Never read or write the real user's settings/contacts during tests."""
    monkeypatch.setenv("CRUNCHLOCK_CONFIG_DIR", str(tmp_path / "config"))


@pytest.fixture
def sample(tmp_path):
    src = tmp_path / "docs"
    (src / "sub").mkdir(parents=True)
    (src / "notes.txt").write_text("the quick brown fox jumps over the lazy dog\n" * 50_000)
    (src / "sub" / "random.bin").write_bytes(os.urandom(2_500_000))
    (src / "empty.txt").write_bytes(b"")
    return src


def lock(paths, out, **kw):
    kw.setdefault("password", "correct horse battery staple")
    kw.setdefault("kdf_profile", FAST)
    return api.lock(paths, out, **kw)


def same_tree(a, b):
    fa = sorted(p.relative_to(a) for p in a.rglob("*"))
    fb = sorted(p.relative_to(b) for p in b.rglob("*"))
    assert fa == fb
    for rel in fa:
        if (a / rel).is_file():
            assert (a / rel).read_bytes() == (b / rel).read_bytes(), rel
