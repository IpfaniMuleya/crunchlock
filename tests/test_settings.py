import json
import os

import pytest

from crunchlock.settings import MAX_RECENT, Settings


@pytest.fixture
def st(tmp_path):
    return Settings(tmp_path / "cfg" / "settings.json")


def test_defaults_and_roundtrip(tmp_path, st):
    assert st.get("compress") is True and st.get("theme") is None and st.recent() == []
    st.set("theme", "dark")
    st.set("recovery", True)
    st.set("split_size", "25M")
    st.save()
    again = Settings(st.path)
    assert again.get("theme") == "dark" and again.get("recovery") is True
    assert again.get("split_size") == "25M"
    if os.name == "posix":
        assert oct(st.path.stat().st_mode & 0o777) == "0o600"


def test_secrets_are_never_stored(st):
    for key in ("password", "keyfile", "identity", "passphrase"):
        with pytest.raises(KeyError):
            st.set(key, "secret")
    st.data["password"] = "hunter2"  # even if something sneaks into the dict
    st.save()
    assert "hunter2" not in st.path.read_text()


def test_corrupt_or_wrong_types_fall_back_to_defaults(st):
    st.path.parent.mkdir(parents=True)
    st.path.write_text("{not json")
    assert Settings(st.path).get("compress") is True
    st.path.write_text(json.dumps({"compress": "yes", "theme": "purple", "recent": [1, "/x.clk"]}))
    s2 = Settings(st.path)
    assert s2.get("compress") is True and s2.get("theme") is None
    assert s2.data["recent"] == ["/x.clk"]


def test_recent_files(tmp_path, st):
    files = []
    for i in range(MAX_RECENT + 3):
        f = tmp_path / f"f{i}.clk"
        f.write_bytes(b"x")
        files.append(f)
        st.add_recent(f)
    st.add_recent(files[2])  # re-opening moves it to the top, no duplicates
    recent = st.recent()
    assert len(recent) == MAX_RECENT and recent[0] == str(files[2].resolve())
    assert len(set(recent)) == len(recent)
    files[2].unlink()
    assert str(files[2].resolve()) not in st.recent()  # missing files are hidden
    st.clear_recent()
    assert st.recent() == []


def test_reset_removes_file(st):
    st.set("pad", True)
    st.save()
    st.reset()
    assert not st.path.exists() and st.get("pad") is False


def test_config_dir_override(tmp_path, monkeypatch):
    from crunchlock import settings
    monkeypatch.setenv("CRUNCHLOCK_CONFIG_DIR", str(tmp_path / "here"))
    assert Settings().path == tmp_path / "here" / "settings.json"
    assert settings.config_dir() == tmp_path / "here"
