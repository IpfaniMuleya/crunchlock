"""Tests for cancel, change-password (rekey), JPEG recompression and single-instance."""
import os
import queue
import time

import numpy as np
import pytest

from conftest import FAST, lock, same_tree
from crunchlock import api, cli, instance, jpeg
from crunchlock.errors import CancelledError
from crunchlock.format import read_header

PW = "correct horse battery staple"
needs_jpeg = pytest.mark.skipif(not jpeg.AVAILABLE, reason="imagecodecs JPEG XL not available")


def make_jpeg(path, seed=0, w=640, h=480, quality=90):
    from imagecodecs import jpeg8_encode
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w]
    base = np.stack([np.sin(x / 40) * 60 + 120, np.cos(y / 30) * 60 + 120, (x + y) % 255], -1)
    img = np.clip(base + rng.normal(0, 10, base.shape), 0, 255).astype(np.uint8)
    path.write_bytes(bytes(jpeg8_encode(img, level=quality)))
    return path


# ------------------------------------------------------------------- cancel

def _cancel_after(n):
    calls = [0]

    def progress(stage, done, total):
        calls[0] += 1
        if calls[0] > n:
            raise CancelledError("cancelled")
    return progress


def test_cancel_lock_leaves_nothing(tmp_path, sample):
    with pytest.raises(CancelledError):
        lock([sample], tmp_path / "c.clk", progress=_cancel_after(3), recovery_data=True)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["docs"]


def test_cancel_best_mode_leaves_nothing(tmp_path, sample):
    with pytest.raises(CancelledError):
        lock([sample], tmp_path / "c.clk", compression="best", progress=_cancel_after(3))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["docs"]


def test_cancel_unlock_writes_nothing(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(os.urandom(3 << 20))
    out = lock([f], tmp_path / "b.clk", compression="none").outputs[0]
    dest = tmp_path / "dest"
    with pytest.raises(CancelledError):
        api.unlock(out, dest, password=PW, progress=_cancel_after(2))
    assert not any(dest.iterdir())


def test_cancel_after_commit_is_ignored(tmp_path, sample):
    """Once the file is written, a late cancel must not prevent shredding/reporting."""
    def progress(stage, done, total):
        if stage == "verifying":
            raise CancelledError("too late")
    r = lock([sample], tmp_path / "s.clk", shred_originals=True, progress=progress)
    assert r.shredded and not sample.exists()


# -------------------------------------------------------------------- rekey

def test_rekey_changes_password(tmp_path, sample):
    out = lock([sample], tmp_path / "r.clk").outputs[0]
    r = api.rekey(out, password=PW, new_password="brand new phrase", kdf_profile=FAST)
    assert r.outputs == [out] and r.unlock_with == "password"
    with pytest.raises(api.WrongKeyError):
        api.verify(out, password=PW)
    api.unlock(out, tmp_path / "o", password="brand new phrase")
    same_tree(sample, tmp_path / "o" / "docs")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["docs", "o", "r.clk"]


def test_rekey_wrong_password_leaves_file_untouched(tmp_path, sample):
    out = lock([sample], tmp_path / "r.clk").outputs[0]
    before = out.read_bytes()
    with pytest.raises(api.WrongKeyError):
        api.rekey(out, password="wrong", new_password="x", kdf_profile=FAST)
    assert out.read_bytes() == before


def test_rekey_corrupt_file_leaves_file_untouched(tmp_path, sample):
    out = lock([sample], tmp_path / "r.clk").outputs[0]
    data = bytearray(out.read_bytes())
    data[len(data) // 2] ^= 1
    out.write_bytes(bytes(data))
    with pytest.raises(api.CorruptFileError):
        api.rekey(out, password=PW, new_password="x", kdf_profile=FAST)
    assert out.read_bytes() == bytes(data)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["docs", "r.clk"]


def test_rekey_cancel_leaves_file_untouched(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(os.urandom(3 << 20))
    out = lock([f], tmp_path / "b.clk", compression="none").outputs[0]
    before = out.read_bytes()
    with pytest.raises(CancelledError):
        api.rekey(out, password=PW, new_password="x", kdf_profile=FAST, progress=_cancel_after(3))
    assert out.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["b.clk", "big.bin"]


def test_rekey_recipients_and_remove_password(tmp_path, sample):
    from crunchlock import keys
    alice, bob = keys.generate_identity(), keys.generate_identity()
    out = lock([sample], tmp_path / "r.clk", recipients=[alice.public]).outputs[0]
    api.rekey(out, identity=alice, recipients=[bob.public], kdf_profile=FAST)
    api.verify(out, identity=bob)
    for bad in (dict(identity=alice), dict(password=PW)):
        with pytest.raises(api.WrongKeyError):
            api.verify(out, **bad)


def test_rekey_keeps_split_recovery_and_padding(tmp_path, sample):
    r = lock([sample], tmp_path / "s.clk", split_size=300_000, recovery_data=True, pad=True)
    sizes = [p.stat().st_size for p in r.outputs]
    k = api.rekey(r.outputs[0], password=PW, new_password="new", kdf_profile=FAST)
    assert [p.stat().st_size for p in k.outputs] == sizes
    assert api.info(k.outputs[0])["recovery_data"]
    api.unlock(k.outputs[0], tmp_path / "o", password="new")
    same_tree(sample, tmp_path / "o" / "docs")


def test_rekey_needs_some_access(tmp_path, sample):
    out = lock([sample], tmp_path / "r.clk").outputs[0]
    with pytest.raises(api.CrunchlockError):
        api.rekey(out, password=PW)


def test_cli_rekey(tmp_path, sample, monkeypatch):
    out = lock([sample], tmp_path / "r.clk").outputs[0]
    monkeypatch.setitem(api.kdf.PROFILES, "standard", api.kdf.PROFILES[FAST])
    monkeypatch.setenv(cli.ENV_PASSWORD, PW)
    monkeypatch.setenv(cli.ENV_PASSWORD + "_NEW", "cli new pass")
    assert cli.main(["rekey", str(out), "-q"]) == 0
    api.verify(out, password="cli new pass")


# --------------------------------------------------------------------- JPEG

@needs_jpeg
def test_jpeg_recompression_is_exact_and_smaller(tmp_path):
    album = tmp_path / "album"
    (album / "sub").mkdir(parents=True)
    pics = [make_jpeg(album / f"img{i}.jpg", seed=i) for i in range(3)]
    pics.append(make_jpeg(album / "sub" / "deep.JPEG", seed=9))
    (album / "fake.jpg").write_bytes(b"\xff\xd8\xff not really a jpeg" * 100)   # must fall back
    (album / "readme.txt").write_text("hello " * 1000)
    r = lock([album], tmp_path / "a.clk")
    assert r.jpeg_files == 4 and r.jpeg_saved > 0
    assert api.info(r.outputs[0])["jpeg_recompression"]
    v = api.verify(r.outputs[0], password=PW)
    sizes = {name: size for name, size, _ in v.entries}
    assert sizes["album/img0.jpg"] == pics[0].stat().st_size
    api.unlock(r.outputs[0], tmp_path / "o", password=PW)
    same_tree(album, tmp_path / "o" / "album")


@needs_jpeg
def test_jpeg_off_when_disabled_or_uncompressed(tmp_path):
    album = tmp_path / "album"
    album.mkdir()
    make_jpeg(album / "a.jpg")
    for kw in (dict(jpeg=False), dict(compression="none")):
        r = lock([album], tmp_path / f"x{len(kw)}{list(kw)[0]}.clk", **kw)
        assert r.jpeg_files == 0
        assert not api.info(r.outputs[0])["jpeg_recompression"]


def test_unknown_header_flags_are_refused(tmp_path, sample):
    out = lock([sample], tmp_path / "f.clk").outputs[0]
    data = bytearray(out.read_bytes())
    data[5] |= 0x80  # flags byte
    out.write_bytes(bytes(data))
    with pytest.raises(api.CrunchlockError, match="upgrade"):
        with open(out, "rb") as fh:
            read_header(fh)


def test_transcode_rejects_non_jpeg():
    assert jpeg.transcode(b"not a jpeg") is None
    assert jpeg.transcode(b"\xff\xd8\xff" + b"\x00" * 100) is None


# ---------------------------------------------------------- single instance

def test_single_instance_forwarding(tmp_path):
    got: queue.Queue = queue.Queue()
    assert not instance.forward(["x"], tmp_path)
    assert not instance.hand_off_or_become_primary(["first"], tmp_path)  # we become primary
    server = instance.Server(got.put, tmp_path)
    instance.release_startup_lock(tmp_path)
    try:
        assert instance.hand_off_or_become_primary(["/a/b.txt", "/c.clk"], tmp_path)
        assert got.get(timeout=2) == ["/a/b.txt", "/c.clk"]
        # a message with the wrong token is ignored
        import json
        import socket
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as s:
            s.sendall(json.dumps({"token": "nope", "paths": ["/evil"]}).encode())
            s.shutdown(socket.SHUT_WR)
            assert s.recv(16) == b""
        time.sleep(0.2)
        assert got.empty()
    finally:
        server.close()
    assert not (tmp_path / "instance.json").exists()


def test_stale_startup_lock_is_taken_over(tmp_path):
    lockfile = tmp_path / "starting.lock"
    lockfile.write_text("")
    old = time.time() - 60
    os.utime(lockfile, (old, old))
    assert not instance.hand_off_or_become_primary(["x"], tmp_path, wait=0.5)


# ------------------------------------------------------------------ self-test

def test_selftest_passes(tmp_path):
    from crunchlock import selftest
    result = tmp_path / "r.txt"
    assert selftest.main([str(result)], gui=False) == 0
    assert result.read_text().strip().endswith("OK")


def test_selftest_reports_broken_bundle(tmp_path, monkeypatch):
    from crunchlock import selftest

    def broken(report):
        raise ImportError("DLL load failed while importing _rust")
    monkeypatch.setattr(selftest, "_check_imports", broken)
    result = tmp_path / "r.txt"
    assert selftest.main([str(result)], gui=False) == 1
    text = result.read_text()
    assert "FAILED" in text and "DLL load failed" in text


# ---------------------------------------------------- browse / extract some

def test_unlock_only_selected_files(tmp_path, sample):
    out = lock([sample], tmp_path / "s.clk").outputs[0]
    names = [n for n, _, d in api.verify(out, password=PW).entries if not d]
    assert "docs/sub/random.bin" in names
    dest = tmp_path / "dest"
    r = api.unlock(out, dest, password=PW, only=["docs/notes.txt"])
    assert r.extracted == [dest / "docs" / "notes.txt"]
    assert (dest / "docs" / "notes.txt").read_bytes() == (sample / "notes.txt").read_bytes()
    assert not (dest / "docs" / "sub").exists()
    # a folder selects everything below it
    api.unlock(out, dest, password=PW, only=["docs/sub"])
    assert (dest / "docs" / "sub" / "random.bin").read_bytes() == (sample / "sub" / "random.bin").read_bytes()


def test_selective_unlock_merges_and_respects_existing(tmp_path, sample):
    out = lock([sample], tmp_path / "s.clk").outputs[0]
    dest = tmp_path / "dest"
    (dest / "docs").mkdir(parents=True)
    (dest / "docs" / "mine.txt").write_text("keep me")
    api.unlock(out, dest, password=PW, only=["docs/notes.txt"])
    assert (dest / "docs" / "mine.txt").read_text() == "keep me"  # folder not replaced
    with pytest.raises(api.CrunchlockError, match="overwrite"):
        api.unlock(out, dest, password=PW, only=["docs/notes.txt"])
    api.unlock(out, dest, password=PW, only=["docs/notes.txt"], force=True)


def test_unlock_only_unknown_name(tmp_path, sample):
    out = lock([sample], tmp_path / "s.clk").outputs[0]
    with pytest.raises(api.CrunchlockError, match="not found"):
        api.unlock(out, tmp_path / "d", password=PW, only=["docs/nope.txt"])
    assert not any((tmp_path / "d").iterdir())


@needs_jpeg
def test_unlock_only_restores_recompressed_jpeg(tmp_path):
    album = tmp_path / "album"
    album.mkdir()
    pic = make_jpeg(album / "a.jpg")
    (album / "b.txt").write_text("x")
    out = lock([album], tmp_path / "a.clk").outputs[0]
    api.unlock(out, tmp_path / "o", password=PW, only=["album/a.jpg"])
    assert (tmp_path / "o" / "album" / "a.jpg").read_bytes() == pic.read_bytes()
    assert not (tmp_path / "o" / "album" / "b.txt").exists()


# ------------------------------------------------------------ lock each

def test_lock_each(tmp_path, sample):
    a = tmp_path / "a.txt"
    a.write_text("alpha " * 1000)
    outdir = tmp_path / "out"
    results = api.lock_each([a, sample], outdir, password=PW, kdf_profile=FAST)
    assert [r.outputs[0] for r in results] == [outdir / "a.txt.clk", outdir / "docs.clk"]
    api.unlock(outdir / "a.txt.clk", tmp_path / "x", password=PW)
    assert (tmp_path / "x" / "a.txt").read_text() == "alpha " * 1000
    # default: next to each item
    results = api.lock_each([a], password=PW, kdf_profile=FAST)
    assert results[0].outputs[0] == tmp_path / "a.txt.clk"


def test_lock_each_cancel_keeps_finished(tmp_path, sample):
    a = tmp_path / "a.txt"
    a.write_text("alpha")
    calls = []

    def progress(stage, done, total):
        calls.append(stage)
        if "(2/2)" in stage and stage.startswith("locking"):
            raise CancelledError("cancelled")
    with pytest.raises(CancelledError) as ei:
        api.lock_each([a, sample], tmp_path / "out", password=PW, kdf_profile=FAST, progress=progress)
    assert [r.outputs[0].name for r in ei.value.done] == ["a.txt.clk"]
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["a.txt.clk"]


# --------------------------------------------------------------- repair

def _damage(path, offsets):
    data = bytearray(path.read_bytes())
    for start, n in offsets:
        data[start:start + n] = os.urandom(n)
    path.write_bytes(bytes(data))


def test_repair_writes_good_copy_without_password(tmp_path, sample):
    out = lock([sample], tmp_path / "r.clk", recovery_data=True).outputs[0]
    _damage(out, [(5000, 1500), (60_000, 10)])
    r = api.repair(out)
    assert r.was_damaged and r.repaired_bytes > 1000
    fixed = r.outputs[0]
    assert fixed == tmp_path / "r.repaired.clk"
    v = api.verify(fixed, password=PW)  # authentic, and needs no more repairs
    assert v.repaired_bytes == 0
    assert api.info(fixed)["recovery_data"]


def test_repair_clean_file_writes_nothing(tmp_path, sample):
    out = lock([sample], tmp_path / "r.clk", recovery_data=True).outputs[0]
    r = api.repair(out)
    assert not r.was_damaged and r.outputs == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["docs", "r.clk"]


def test_repair_split_and_without_recovery(tmp_path, sample):
    r = lock([sample], tmp_path / "s.clk", recovery_data=True, split_size=300_000)
    _damage(r.outputs[1], [(1000, 500)])
    fixed = api.repair(r.outputs[0])
    assert len(fixed.outputs) == len(r.outputs) and fixed.outputs[0].name == "s.repaired.clk.001"
    api.verify(fixed.outputs[0], password=PW)
    plain = lock([sample], tmp_path / "p.clk").outputs[0]
    with pytest.raises(api.CrunchlockError, match="no recovery data"):
        api.repair(plain)


def test_cli_list_only_repair(tmp_path, sample, monkeypatch, capsys):
    monkeypatch.setenv(cli.ENV_PASSWORD, PW)
    out = lock([sample], tmp_path / "c.clk", recovery_data=True).outputs[0]
    assert cli.main(["list", str(out), "-q"]) == 0
    assert "docs/notes.txt" in capsys.readouterr().out
    assert cli.main(["unlock", str(out), "-o", str(tmp_path / "o"), "--only", "docs/notes.txt", "-q"]) == 0
    assert (tmp_path / "o" / "docs" / "notes.txt").exists() and not (tmp_path / "o" / "docs" / "sub").exists()
    assert cli.main(["repair", str(out), "-q"]) == 0
    assert "no damage" in capsys.readouterr().out
    _damage(out, [(4000, 300)])
    assert cli.main(["repair", str(out), "-q"]) == 0
    assert (tmp_path / "c.repaired.clk").exists()


def test_cli_lock_each(tmp_path, sample, monkeypatch):
    monkeypatch.setenv(cli.ENV_PASSWORD, PW)
    monkeypatch.setitem(api.kdf.PROFILES, "light", api.kdf.PROFILES[FAST])
    a = tmp_path / "a.txt"
    a.write_text("x")
    assert cli.main(["lock", str(a), str(sample), "--each", "-o", str(tmp_path / "out"),
                     "--profile", "light", "-q"]) == 0
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["a.txt.clk", "docs.clk"]


# ------------------------------------------------------------------ ETA

def test_eta():
    from crunchlock.eta import Eta, format_eta
    e = Eta(warmup=1.0)
    assert e.update("locking", 0, 100, now=0.0) is None
    e.update("locking", 10, 100, now=1.0)
    left = e.update("locking", 20, 100, now=2.0)
    assert left is not None and 7 <= left <= 9
    assert e.update("verifying", 0, 100, now=3.0) is None  # new stage resets
    assert format_eta(None) == "" and format_eta(2) == "almost done"
    assert format_eta(45) == "about 45 s left" and format_eta(125) == "about 2 min 05 s left"
    assert format_eta(7300) == "about 2 h 01 min left"
