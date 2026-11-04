import io
import os
import tarfile

import pytest

from conftest import FAST, lock
from crunchlock import api, compress, keys
from crunchlock.crypto import EncryptWriter
from crunchlock.format import Header

PW = "correct horse battery staple"


@pytest.fixture
def locked(tmp_path, sample):
    return lock([sample], tmp_path / "t.clk").outputs[0]


def test_wrong_password(locked):
    with pytest.raises(api.WrongKeyError):
        api.verify(locked, password="nope")


def _flip(path, offset):
    data = bytearray(path.read_bytes())
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))


@pytest.mark.parametrize("where", ["header_prefix", "slot", "middle", "end"])
def test_tamper_detected(locked, tmp_path, where):
    size = locked.stat().st_size
    offset = {"header_prefix": 8, "slot": 30, "middle": size // 2, "end": size - 3}[where]
    _flip(locked, offset)
    with pytest.raises((api.CorruptFileError, api.WrongKeyError)):
        api.unlock(locked, tmp_path / "out", password=PW)
    # Nothing must have been written on failure.
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())


CT = 4 + (1 << 20) + 16  # one full encrypted chunk


def _header_len(path):
    from crunchlock.format import read_header
    with open(path, "rb") as fh:
        return len(read_header(fh)[1])


def test_truncation_detected(locked):
    data = locked.read_bytes()
    for cut in (len(data) - 1, len(data) - 1000, len(data) // 2, 40):
        locked.write_bytes(data[:cut])
        with pytest.raises(api.CorruptFileError):
            api.verify(locked, password=PW)


def _big_locked(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(os.urandom(3 * (1 << 20) + 100))
    return lock([f], tmp_path / "big.clk", compression="none").outputs[0]


def test_chunk_boundary_truncation(tmp_path):
    """Dropping whole chunks from the end must be detected (last-chunk flag)."""
    out = _big_locked(tmp_path)
    data, h = out.read_bytes(), _header_len(out)
    n_full = (len(data) - h) // CT
    assert n_full >= 3
    for k in range(1, n_full + 1):
        out.write_bytes(data[:h + k * CT])
        with pytest.raises(api.CorruptFileError):
            api.verify(out, password=PW)


def test_swapped_chunks_detected(tmp_path):
    out = _big_locked(tmp_path)
    data, h = out.read_bytes(), _header_len(out)
    c0, c1 = data[h:h + CT], data[h + CT:h + 2 * CT]
    out.write_bytes(data[:h] + c1 + c0 + data[h + 2 * CT:])
    with pytest.raises(api.CorruptFileError):
        api.verify(out, password=PW)


def test_missing_split_part(tmp_path, sample):
    r = lock([sample], tmp_path / "s.clk", split_size=300_000)
    assert len(r.outputs) >= 3
    r.outputs[1].unlink()
    with pytest.raises(api.CorruptFileError, match="missing"):
        api.verify(r.outputs[0], password=PW)
    r.outputs[-1].unlink()
    with pytest.raises(api.CorruptFileError):
        api.verify(r.outputs[0], password=PW)


def test_recovery_repairs_damage(tmp_path, sample):
    out = lock([sample], tmp_path / "r.clk", recovery_data=True).outputs[0]
    data = bytearray(out.read_bytes())
    data[2] ^= 0xFF  # damage one header copy
    data[5000:7000] = os.urandom(2000)  # a 2 KB burst
    for i in range(50_000, len(data), 40_000):
        data[i] ^= 0x55
    out.write_bytes(bytes(data))
    v = api.verify(out, password=PW)
    assert v.repaired_bytes > 2000
    u = api.unlock(out, tmp_path / "o", password=PW)
    assert u.repaired_bytes > 2000
    assert (tmp_path / "o" / "docs" / "notes.txt").read_bytes() == (sample / "notes.txt").read_bytes()


def test_without_recovery_damage_is_detected_not_repaired(locked):
    _flip(locked, locked.stat().st_size // 3)
    with pytest.raises(api.CorruptFileError):
        api.verify(locked, password=PW)


def test_too_much_damage_fails_cleanly(tmp_path, sample):
    out = lock([sample], tmp_path / "r.clk", recovery_data=True).outputs[0]
    data = bytearray(out.read_bytes())
    data[100:30_000] = os.urandom(29_900)
    out.write_bytes(bytes(data))
    with pytest.raises(api.CorruptFileError):
        api.verify(out, password=PW)


def _craft(tmp_path, tar_bytes):
    """Build a validly-encrypted file containing an arbitrary (malicious) tar."""
    key = keys.new_file_key()
    h = Header(chunk_size=1 << 20, nonce_prefix=os.urandom(7))
    from crunchlock import kdf
    h.slots.append(keys.make_password_slot(h.prefix(), key, PW, None, kdf.PROFILES[FAST]))
    out = tmp_path / "evil.clk"

    class Sink(io.BytesIO):
        def close(self):
            out.write_bytes(self.getvalue())

    w = compress.CompressWriter(EncryptWriter(Sink(), h.pack(), key, 1 << 20, h.nonce_prefix),
                                compress.NONE)
    w.write(tar_bytes)
    w.close()
    return out


@pytest.mark.parametrize("name,kind", [("../escape.txt", "file"), ("a/../../escape.txt", "file"),
                                       ("link", "symlink")])
def test_path_traversal_rejected(tmp_path, name, kind):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name)
        if kind == "symlink":
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        else:
            info.size = 4
            tf.addfile(info, io.BytesIO(b"evil"))
    evil = _craft(tmp_path, buf.getvalue())
    dest = tmp_path / "dest"
    with pytest.raises(api.CorruptFileError, match="unsafe"):
        api.unlock(evil, dest, password=PW)
    with pytest.raises(api.CorruptFileError, match="unsafe"):
        api.verify(evil, password=PW)
    assert not (tmp_path / "escape.txt").exists()
    assert not dest.exists() or not any(dest.iterdir())


def test_absolute_paths_are_kept_inside_destination(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(str(tmp_path / "outside.txt"))
        info.size = 4
        tf.addfile(info, io.BytesIO(b"evil"))
    evil = _craft(tmp_path, buf.getvalue())
    dest = tmp_path / "dest"
    api.unlock(evil, dest, password=PW)
    assert not (tmp_path / "outside.txt").exists()
    assert list(dest.rglob("outside.txt"))


def test_hostile_kdf_params_rejected(tmp_path, locked):
    from crunchlock.format import read_header
    with open(locked, "rb") as fh:
        h, raw = read_header(fh)
    data = bytearray(locked.read_bytes())
    # memory field of first password slot: prefix(17) + count(1) + type(1) + time(4)
    data[17 + 1 + 1 + 4:17 + 1 + 1 + 8] = (0xFFFFFFFF).to_bytes(4, "big")
    locked.write_bytes(bytes(data))
    with pytest.raises(api.CorruptFileError, match="unreasonable"):
        api.verify(locked, password=PW)
    assert h and raw


def test_public_key_sharing(tmp_path, sample):
    alice, bob, eve = keys.generate_identity(), keys.generate_identity(), keys.generate_identity()
    r = lock([sample], tmp_path / "shared.clk", password=None,
             recipients=[alice.public, bob.public])
    for who in (alice, bob):
        api.verify(r.outputs[0], identity=who)
    with pytest.raises(api.WrongKeyError):
        api.verify(r.outputs[0], identity=eve)
    with pytest.raises(api.WrongKeyError, match="private key"):
        api.verify(r.outputs[0], password=PW)


def test_password_and_recipient_together(tmp_path, sample):
    alice = keys.generate_identity()
    r = lock([sample], tmp_path / "both.clk", recipients=[alice.public])
    api.verify(r.outputs[0], identity=alice)
    api.verify(r.outputs[0], password=PW)


def test_private_key_file_roundtrip():
    from crunchlock import kdf
    ident = keys.generate_identity()
    data = keys.save_private_key(ident, "pass phrase", kdf.PROFILES[FAST])
    again = keys.load_private_key(data, "pass phrase")
    assert again.public.public_bytes_raw() == ident.public.public_bytes_raw()
    with pytest.raises(api.WrongKeyError):
        keys.load_private_key(data, "wrong")
    txt = keys.public_key_to_text(ident.public)
    assert keys.public_key_from_text(txt).public_bytes_raw() == ident.public.public_bytes_raw()


def test_each_lock_is_unique(tmp_path, sample):
    a = lock([sample], tmp_path / "a.clk").outputs[0].read_bytes()
    b = lock([sample], tmp_path / "b.clk").outputs[0].read_bytes()
    assert a[:4] == b[:4] == b"CRLK"
    assert a[4:200] != b[4:200]
