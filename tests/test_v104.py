"""Tests for long-range compression, signatures, PNG repacking, update check and add."""
import io
import json
import os
import struct
import zlib

import pytest

from conftest import FAST, lock, same_tree
from crunchlock import api, cli, compress, crypto, keys, png, update
from crunchlock.errors import CorruptFileError, CrunchlockError, WrongKeyError

PW = "correct horse battery staple"


# --------------------------------------------------------------------- helpers

def _chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data))


def make_png(path, w=320, h=200, seed=0, level=6, strategy=zlib.Z_DEFAULT_STRATEGY,
             idat_size=8192, fake_flevel=None):
    """A screenshot-like RGB PNG written with plain zlib (like libpng does)."""
    rows = bytearray()
    for y in range(h):
        rows.append(1 if y % 3 else 0)  # mix of Sub and None filters
        for x in range(w):
            v = (x // 16 + y // 10 + seed) % 7
            rows += bytes(((v * 37) & 255, (v * 91 + seed) & 255, 200 if (x + y) % 40 < 3 else 30))
    c = zlib.compressobj(level, zlib.DEFLATED, 15, 8, strategy)
    stream = bytearray(c.compress(bytes(rows)) + c.flush())
    if fake_flevel is not None:  # header claims another level: no plain zlib setting matches
        cmf = stream[0]
        flg = (fake_flevel << 6)
        flg += 31 - ((cmf << 8) | flg) % 31
        stream[1] = flg
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    out = png.SIGNATURE + _chunk(b"IHDR", ihdr) + _chunk(b"tEXt", b"Comment\x00test image")
    for i in range(0, len(stream), idat_size):
        out += _chunk(b"IDAT", bytes(stream[i:i + idat_size]))
    out += _chunk(b"IEND", b"")
    path.write_bytes(out)
    return path


def identity_files(tmp_path, name):
    ident = keys.generate_identity()
    pub = tmp_path / f"{name}.clkpub"
    pub.write_text(keys.public_key_to_text(ident) + "\n")
    return ident, pub


# ------------------------------------------------------------------ 1. long range

def test_window_grows_with_the_data():
    base = compress.window_log(19, None)
    assert compress.window_log(19, 1000) == base
    assert compress.window_log(19, 50 << 20) == 26
    assert compress.window_log(19, 10 << 30) == compress.AUTO_WINDOW_LOG
    assert compress.window_log(19, 10 << 30, long_range=True) == compress.LONG_WINDOW_LOG


def test_long_range_finds_far_repeats(tmp_path):
    rng = os.urandom
    alphabet = bytes(range(0, 256, 16))  # 4 bits/byte: compressible, but not trivially
    block = bytes(alphabet[b & 15] for b in rng(12 << 20))
    src = tmp_path / "backup.img"
    src.write_bytes(block + bytes(alphabet[b & 15] for b in rng(10 << 20)) + block)
    plain = lock([src], tmp_path / "plain.clk", level=3)
    long = lock([src], tmp_path / "long.clk", level=3, long_range=True)
    assert long.output_bytes < plain.output_bytes * 0.8
    api.unlock(tmp_path / "long.clk", tmp_path / "out", password=PW)
    assert (tmp_path / "out" / "backup.img").read_bytes() == src.read_bytes()


# ------------------------------------------------------------------ 2. signatures

def test_signed_file_reports_signer_and_survives_rekey(tmp_path, sample):
    alice, alice_pub = identity_files(tmp_path, "alice")
    out = tmp_path / "s.clk"
    r = lock([sample], out, sign_with=alice)
    assert r.signed_by == keys.fingerprint(alice.verify_key)
    assert api.info(out)["signed"] is True
    v = api.verify(out, password=PW, signer=str(alice_pub))
    assert v.signed_by == r.signed_by
    u = api.unlock(out, tmp_path / "back", password=PW, signer=alice_pub.read_text())
    assert u.signed_by == r.signed_by
    same_tree(sample, tmp_path / "back" / "docs")
    # Changing the password keeps the signature valid (it covers the contents only).
    api.rekey(out, password=PW, new_password="new pw 123", kdf_profile=FAST)
    assert api.verify(out, password="new pw 123", signer=alice).signed_by == r.signed_by


def test_wrong_or_missing_signer_is_refused(tmp_path, sample):
    alice, _ = identity_files(tmp_path, "alice")
    mallory, mallory_pub = identity_files(tmp_path, "mallory")
    signed = tmp_path / "s.clk"
    lock([sample], signed, sign_with=mallory)
    with pytest.raises(CrunchlockError, match="not by the expected"):
        api.unlock(signed, tmp_path / "x", password=PW, signer=alice)
    assert not (tmp_path / "x").exists() or not any((tmp_path / "x").iterdir())
    unsigned = tmp_path / "u.clk"
    lock([sample], unsigned)
    assert api.verify(unsigned, password=PW).signed_by is None
    with pytest.raises(CrunchlockError, match="not signed"):
        api.verify(unsigned, password=PW, signer=mallory_pub)


def test_forged_signature_is_detected(tmp_path, sample, monkeypatch):
    alice, _ = identity_files(tmp_path, "alice")
    out = tmp_path / "f.clk"
    real = crypto._signed_message
    monkeypatch.setattr(crypto, "_signed_message", lambda d: real(bytes(64)))  # sign the wrong hash
    lock([sample], out, sign_with=alice)
    monkeypatch.setattr(crypto, "_signed_message", real)
    with pytest.raises(CorruptFileError, match="signature does not match"):
        api.unlock(out, tmp_path / "x", password=PW)
    assert not (tmp_path / "x").exists() or not any((tmp_path / "x").iterdir())


@pytest.mark.parametrize("pad", [False, True])
@pytest.mark.parametrize("size", [0, 1, 1024 - 4 - 96, 1024 - 4 - 95, 1023, 1024, 1025, 5000])
def test_signature_fits_at_every_chunk_boundary(size, pad):
    cs, key, prefix, head = 1024, os.urandom(32), os.urandom(7), b"header"
    signer = keys.generate_identity().signing_key
    sink = io.BytesIO()
    sink.close = lambda: None
    w = crypto.EncryptWriter(sink, head, key, cs, prefix, pad, signer)
    data = os.urandom(size)
    w.write(data)
    w.close()
    src = io.BytesIO(sink.getvalue()[len(head):])
    r = crypto.DecryptReader(src, head, key, cs, prefix, signed=True)
    assert r.read() == data
    assert r.signer == signer.public_key().public_bytes_raw()


def test_public_key_formats():
    ident = keys.generate_identity()
    text = keys.public_key_to_text(ident)
    assert text.startswith("clkpub2:")
    x, ed = keys.parse_public_text(text)
    assert x.public_bytes_raw() == ident.public.public_bytes_raw()
    assert ed.public_bytes_raw() == ident.verify_key.public_bytes_raw()
    old = keys.public_key_to_text(ident.public)
    assert old.startswith("clkpub1:")
    assert keys.public_key_from_text(old).public_bytes_raw() == ident.public.public_bytes_raw()
    with pytest.raises(CrunchlockError, match="older version"):
        keys.verify_key_from_text(old)
    # The signing key is derived, so a reloaded key file signs with the same key.
    again = keys.load_private_key(keys.save_private_key(ident, "pw", api.kdf.PROFILES[FAST]), "pw")
    assert again.verify_key.public_bytes_raw() == ident.verify_key.public_bytes_raw()


def test_recipient_can_be_given_as_clkpub2(tmp_path, sample):
    bob, bob_pub = identity_files(tmp_path, "bob")
    out = tmp_path / "r.clk"
    api.lock([sample], out, recipients=[api.load_recipient(str(bob_pub))], kdf_profile=FAST)
    api.verify(out, identity=bob)


# ------------------------------------------------------------------ 3. PNG

def test_png_round_trip_is_exact_and_smaller(tmp_path):
    src = tmp_path / "shots"
    src.mkdir()
    for i in range(3):
        make_png(src / f"s{i}.png", seed=i, strategy=[zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED,
                                                    zlib.Z_DEFAULT_STRATEGY][i], level=[6, 6, 9][i])
    make_png(src / "foreign.png", seed=9, level=9, fake_flevel=0)  # can't be rebuilt: kept as-is
    (src / "notes.txt").write_text("hello\n" * 100)
    with_png = lock([src], tmp_path / "a.clk")
    without = lock([src], tmp_path / "b.clk", png=False)
    assert with_png.png_files == 3
    assert "PNG" in with_png.compression_note
    assert with_png.output_bytes < without.output_bytes * 0.9
    assert api.info(tmp_path / "a.clk")["png_recompression"] is True
    api.unlock(tmp_path / "a.clk", tmp_path / "out", password=PW)
    same_tree(src, tmp_path / "out" / "shots")
    names = {n for n, _s, _d in api.verify(tmp_path / "a.clk", password=PW).entries}
    assert "shots/s0.png" in names


def test_png_transcode_rejects_what_it_cannot_rebuild(tmp_path):
    good = make_png(tmp_path / "g.png").read_bytes()
    payload = png.transcode(good)
    assert payload is not None and png.restore(payload, len(good), zlib.crc32(good)) == good
    assert png.transcode(make_png(tmp_path / "f.png", fake_flevel=0).read_bytes()) is None
    assert png.transcode(b"not a png") is None
    assert png.transcode(good[:-30]) is None  # truncated
    with pytest.raises(CorruptFileError, match="rebuilt exactly"):
        png.restore(payload, len(good), zlib.crc32(good) ^ 1)


def test_png_needs_standard_zlib():
    assert png.available()  # the zlib used for tests and official builds


def test_png_off_when_not_compressing(tmp_path):
    src = make_png(tmp_path / "a.png")
    r = lock([src], tmp_path / "a.clk", compression="none")
    assert r.png_files == 0 and not api.info(tmp_path / "a.clk")["png_recompression"]


# ------------------------------------------------------------------ 4. updates

def _fake_opener(payload):
    def opener(req, timeout):
        assert req.full_url == update.API_URL
        return io.BytesIO(json.dumps(payload).encode())
    return opener


def test_update_check_reports_newer():
    info = update.check(current="1.0.3", opener=_fake_opener({"tag_name": "v1.2.0"}))
    assert info.newer and info.latest == "1.2.0"
    assert info.url == "https://github.com/IpfaniMuleya/crunchlock/releases/tag/v1.2.0"
    same = update.check(current="1.2.0", opener=_fake_opener({"tag_name": "v1.2.0"}))
    assert not same.newer
    older = update.check(current="1.10.0", opener=_fake_opener({"tag_name": "v1.9.9"}))
    assert not older.newer


def test_update_check_rejects_odd_tags():
    for tag in ("v1.2", "latest", "v1.2.3<script>", ""):
        with pytest.raises(ValueError):
            update.check(opener=_fake_opener({"tag_name": tag}))


def test_cli_check_update(monkeypatch, capsys):
    monkeypatch.setattr(update, "check", lambda: update.UpdateInfo("1.0.3", "2.0.0", "https://x"))
    assert cli.main(["check-update"]) == 0
    assert "2.0.0 is available" in capsys.readouterr().out

    def fail():
        raise OSError("offline")
    monkeypatch.setattr(update, "check", fail)
    assert cli.main(["check-update"]) == 1


# ------------------------------------------------------------------ 5. add files

def test_add_files_keeps_everything_else(tmp_path, sample):
    out = tmp_path / "a.clk"
    lock([sample], out, recovery_data=True, pad=True)
    extra = tmp_path / "extra.txt"
    extra.write_text("added later\n" * 1000)
    photos = tmp_path / "pics"
    photos.mkdir()
    make_png(photos / "p.png")
    r = api.add(out, [extra, photos], password=PW)
    assert r.outputs == [out] and not r.replaced
    meta = api.info(out)
    assert meta["recovery_data"] and meta["png_recompression"]
    api.unlock(out, tmp_path / "back", password=PW)
    same_tree(sample, tmp_path / "back" / "docs")
    assert (tmp_path / "back" / "extra.txt").read_bytes() == extra.read_bytes()
    assert (tmp_path / "back" / "pics" / "p.png").read_bytes() == (photos / "p.png").read_bytes()


def test_add_name_clash_and_replace(tmp_path, sample):
    out = tmp_path / "a.clk"
    lock([sample], out)
    before = out.read_bytes()
    other = tmp_path / "other" / "docs"
    other.mkdir(parents=True)
    (other / "new.txt").write_text("replacement")
    with pytest.raises(CrunchlockError, match="already in the locked file"):
        api.add(out, [other], password=PW)
    assert out.read_bytes() == before  # untouched
    r = api.add(out, [other], password=PW, replace=True)
    assert r.replaced == ["docs"]
    api.unlock(out, tmp_path / "back", password=PW)
    assert sorted(p.name for p in (tmp_path / "back" / "docs").iterdir()) == ["new.txt"]


def test_add_wrong_password_and_split(tmp_path, sample):
    out = tmp_path / "a.clk"
    lock([sample], out, split_size=1 << 20)
    first = tmp_path / "a.clk.001"
    assert first.exists()
    extra = tmp_path / "x.txt"
    extra.write_text("x")
    with pytest.raises(WrongKeyError):
        api.add(first, [extra], password="wrong")
    api.add(first, [extra], password=PW)
    assert (tmp_path / "a.clk.002").exists()
    api.unlock(first, tmp_path / "back", password=PW)
    assert (tmp_path / "back" / "x.txt").read_text() == "x"


def test_add_with_recipients(tmp_path, sample):
    alice, alice_pub = identity_files(tmp_path, "alice")
    bob, _ = identity_files(tmp_path, "bob")
    out = tmp_path / "a.clk"
    api.lock([sample], out, recipients=[alice.public, bob.public], kdf_profile=FAST)
    extra = tmp_path / "x.txt"
    extra.write_text("x")
    # Shared with two keys; only Alice's own is known, so Bob's must be given again.
    with pytest.raises(CrunchlockError, match="add those public keys again"):
        api.add(out, [extra], identity=alice)
    api.add(out, [extra], identity=alice, recipients=[bob.public])
    api.verify(out, identity=bob)
    api.verify(out, identity=alice)


def test_add_checks_password_when_opened_with_key(tmp_path, sample):
    alice, _ = identity_files(tmp_path, "alice")
    out = tmp_path / "a.clk"
    api.lock([sample], out, password=PW, recipients=[alice.public], kdf_profile=FAST)
    extra = tmp_path / "x.txt"
    extra.write_text("x")
    with pytest.raises(CrunchlockError, match="enter it too"):
        api.add(out, [extra], identity=alice)
    with pytest.raises(WrongKeyError):
        api.add(out, [extra], identity=alice, password="not the password")
    api.add(out, [extra], identity=alice, password=PW)
    api.verify(out, password=PW)


def test_add_to_signed_file_warns_or_resigns(tmp_path, sample):
    alice, _ = identity_files(tmp_path, "alice")
    out = tmp_path / "a.clk"
    lock([sample], out, sign_with=alice)
    extra = tmp_path / "x.txt"
    extra.write_text("x")
    r = api.add(out, [extra], password=PW)
    assert any("signature was removed" in w for w in r.warnings)
    assert api.verify(out, password=PW).signed_by is None
    r = api.add(out, [tmp_path / "x.txt"], password=PW, replace=True, sign_with=alice)
    assert api.verify(out, password=PW, signer=alice).signed_by == r.signed_by


def test_add_refuses_the_file_itself(tmp_path, sample):
    out = sample / "inside.clk"
    lock([sample / "notes.txt"], out)
    with pytest.raises(CrunchlockError, match="itself"):
        api.add(out, [sample], password=PW)


def test_cli_add_sign_and_pubkey(tmp_path, sample, monkeypatch, capsys):
    monkeypatch.setenv(cli.ENV_PASSWORD, PW)
    monkeypatch.setitem(api.kdf.PROFILES, "light", api.kdf.PROFILES[FAST])
    monkeypatch.setitem(api.kdf.PROFILES, "standard", api.kdf.PROFILES[FAST])
    monkeypatch.setattr(cli, "ask_password", lambda *a, **k: PW)
    assert cli.main(["keygen", str(tmp_path / "me")]) == 0
    assert "signing fingerprint" in capsys.readouterr().out
    key, pub = tmp_path / "me.clkkey", tmp_path / "me.clkpub"
    assert pub.read_text().startswith("clkpub2:")
    out = tmp_path / "c.clk"
    assert cli.main(["lock", str(sample), "-o", str(out), "--sign", str(key), "-q"]) == 0
    assert cli.main(["verify", str(out), "--signer", str(pub), "-q"]) == 0
    assert "matches --signer" in capsys.readouterr().out
    extra = tmp_path / "x.txt"
    extra.write_text("x")
    assert cli.main(["add", str(out), str(extra), "--sign", str(key), "-q"]) == 0
    assert "added" in capsys.readouterr().out
    assert cli.main(["pubkey", str(key)]) == 0
    assert capsys.readouterr().out.startswith(pub.read_text().strip())
