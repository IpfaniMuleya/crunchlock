import os

import pytest

from conftest import lock, same_tree
from crunchlock import api
from crunchlock.crypto import padme

PW = "correct horse battery staple"


@pytest.mark.parametrize("compression", ["zstd", "xz", "best", "none"])
@pytest.mark.parametrize("opts", [{}, {"pad": True}, {"recovery_data": True},
                                  {"split_size": 512 * 1024},
                                  {"pad": True, "recovery_data": True, "split_size": 300_000}])
def test_roundtrip_folder(tmp_path, sample, compression, opts):
    r = lock([sample], tmp_path / "out.clk", compression=compression, **opts)
    v = api.verify(r.outputs[0], password=PW)
    assert {e[0] for e in v.entries} >= {"docs/notes.txt", "docs/sub/random.bin", "docs/empty.txt"}
    u = api.unlock(r.outputs[0], tmp_path / "restored", password=PW)
    assert u.extracted == [tmp_path / "restored" / "docs"]
    same_tree(sample, tmp_path / "restored" / "docs")
    if opts.get("split_size"):
        assert len(r.outputs) > 1
        assert all(o.stat().st_size <= opts["split_size"] for o in r.outputs)


def test_compression_shrinks_text(tmp_path):
    f = tmp_path / "log.txt"
    f.write_text("".join(f"2026-11-04 12:00:{i % 60:02d} INFO request id={i} ok\n" for i in range(200_000)))
    r = lock([f], tmp_path / "log.clk")
    assert r.compression == "zstd"
    assert r.output_bytes < r.input_bytes * 0.1


def test_incompressible_falls_back_to_store(tmp_path):
    f = tmp_path / "noise.bin"
    f.write_bytes(os.urandom(1_000_000))
    r = lock([f], tmp_path / "n.clk", compression="zstd")
    assert r.compression == "none" and r.compression_note
    assert r.output_bytes < 1_000_000 + 64 * 1024


def test_multiple_inputs_and_single_files(tmp_path, sample):
    a = tmp_path / "a.txt"
    a.write_text("alpha")
    r = lock([a, sample, sample / "sub" / "random.bin"], tmp_path / "multi.clk")
    out = tmp_path / "o"
    api.unlock(r.outputs[0], out, password=PW)
    assert (out / "a.txt").read_text() == "alpha"
    assert (out / "random.bin").read_bytes() == (sample / "sub" / "random.bin").read_bytes()
    same_tree(sample, out / "docs")


def test_empty_file(tmp_path):
    e = tmp_path / "empty"
    e.write_bytes(b"")
    r = lock([e], tmp_path / "e.clk")
    api.unlock(r.outputs[0], tmp_path / "o", password=PW)
    assert (tmp_path / "o" / "empty").read_bytes() == b""


def test_duplicate_names_rejected(tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "y").mkdir()
    (tmp_path / "x" / "f").write_text("1")
    (tmp_path / "y" / "f").write_text("2")
    with pytest.raises(api.CrunchlockError):
        lock([tmp_path / "x" / "f", tmp_path / "y" / "f"], tmp_path / "d.clk")


def test_no_overwrite_without_force(tmp_path, sample):
    out = tmp_path / "o.clk"
    lock([sample], out)
    with pytest.raises(api.CrunchlockError):
        lock([sample], out)
    lock([sample], out, force=True)
    api.unlock(out, tmp_path / "x", password=PW)
    with pytest.raises(api.CrunchlockError, match="overwrite"):
        api.unlock(out, tmp_path / "x", password=PW)
    api.unlock(out, tmp_path / "x", password=PW, force=True)


def test_padding_hides_size(tmp_path):
    sizes = set()
    for n in range(600_000, 604_000, 500):
        f = tmp_path / f"f{n}"
        f.write_bytes(os.urandom(n))
        r = lock([f], tmp_path / f"f{n}.clk", compression="none", pad=True)
        sizes.add(r.output_bytes)
    assert len(sizes) <= 2  # 8 different sizes collapse into at most 2 buckets
    assert padme(1_000_000) >= 1_000_000 and padme(1_000_000) < 1_120_000


def test_keyfile(tmp_path, sample):
    kf = os.urandom(64)
    r = lock([sample], tmp_path / "k.clk", keyfile=kf)
    assert api.info(r.outputs[0])["needs_keyfile"]
    with pytest.raises(api.WrongKeyError):
        api.verify(r.outputs[0], password=PW)
    api.verify(r.outputs[0], password=PW, keyfile=kf)


def test_shred_after_verify(tmp_path, sample):
    r = lock([sample], tmp_path / "s.clk", shred_originals=True)
    assert not sample.exists()
    assert r.shredded == [sample]
    api.unlock(r.outputs[0], tmp_path / "back", password=PW)
    assert (tmp_path / "back" / "docs" / "notes.txt").exists()


def test_info_needs_no_password_and_leaks_no_names(tmp_path, sample):
    r = lock([sample], tmp_path / "i.clk")
    m = api.info(r.outputs[0])
    assert m["key_slots"][0]["type"] == "password"
    raw = r.outputs[0].read_bytes()
    assert b"notes.txt" not in raw and b"docs" not in raw


def test_symlinks(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("outside data")
    src = tmp_path / "proj"
    (src / "d").mkdir(parents=True)
    (src / "d" / "real.txt").write_text("inside data")
    os.symlink(src / "d" / "real.txt", src / "abs_inside")      # absolute, inside
    os.symlink("d/real.txt", src / "rel_inside")                 # relative, inside
    os.symlink(outside, src / "to_outside")                      # points outside
    os.symlink(tmp_path / "missing", src / "dangling")           # broken
    r = lock([src], tmp_path / "l.clk")
    assert len(r.warnings) == 2
    out = tmp_path / "o"
    api.unlock(r.outputs[0], out, password=PW)
    p = out / "proj"
    assert (p / "abs_inside").is_symlink() and (p / "abs_inside").read_text() == "inside data"
    assert (p / "rel_inside").is_symlink() and (p / "rel_inside").read_text() == "inside data"
    assert not (p / "to_outside").is_symlink() and (p / "to_outside").read_text() == "outside data"
    assert not os.path.lexists(p / "dangling")
    # With links that can't be stored exactly, originals are never shredded.
    r2 = lock([src], tmp_path / "l2.clk", shred_originals=True)
    assert src.exists() and not r2.shredded and any("NOT deleted" in w for w in r2.warnings)


def test_best_keeps_smaller_and_leaves_no_temp_files(tmp_path, sample):
    r = lock([sample], tmp_path / "b.clk", compression="best")
    assert "kept" in r.compression_note
    assert sorted(p.name for p in tmp_path.iterdir()) == ["b.clk", "docs"]
