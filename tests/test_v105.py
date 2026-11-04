"""Tests for contacts, storing duplicate files once, and standalone file signatures."""
import os

import pytest

from conftest import FAST, lock, same_tree
from crunchlock import api, cli, contacts, keys
from crunchlock.errors import CorruptFileError, CrunchlockError
from crunchlock.format import FLAG_DEDUP, read_header

PW = "correct horse battery staple"


def person(tmp_path, name):
    ident = keys.generate_identity()
    pub = tmp_path / f"{name}.clkpub"
    pub.write_text(keys.public_key_to_text(ident) + "\n")
    return ident, pub


# ------------------------------------------------------------------ contacts

def test_contacts_add_find_remove(tmp_path):
    alice, alice_pub = person(tmp_path, "alice")
    contacts.add("Alice", alice_pub.read_text())
    assert contacts.find("alice") == alice_pub.read_text().strip()
    assert contacts.name_for_verify_key(alice.verify_key.public_bytes_raw()) == "Alice"
    with pytest.raises(CrunchlockError):
        contacts.add("Bad", "clkpub2:nonsense")
    with pytest.raises(CrunchlockError):
        contacts.add("", alice_pub.read_text())
    contacts.remove("Alice")
    assert contacts.load() == {}
    with pytest.raises(CrunchlockError):
        contacts.remove("Alice")


def test_contact_names_work_as_recipient_and_signer(tmp_path, sample):
    alice, alice_pub = person(tmp_path, "alice")
    bob, bob_pub = person(tmp_path, "bob")
    contacts.add("Alice", alice_pub.read_text())
    contacts.add("Bob", bob_pub.read_text())
    out = tmp_path / "x.clk"
    api.lock([sample], out, recipients=[api.load_recipient("Bob")], sign_with=alice,
             kdf_profile=FAST)
    r = api.verify(out, identity=bob, signer="Alice")
    assert r.signer_name == "Alice"
    with pytest.raises(CrunchlockError, match="not by the expected"):
        api.verify(out, identity=bob, signer="Bob")
    with pytest.raises(CrunchlockError, match="contact name"):
        api.load_recipient("Nobody")


def test_cli_contacts(tmp_path, capsys):
    _, pub = person(tmp_path, "carol")
    assert cli.main(["contacts", "add", "Carol", str(pub)]) == 0
    assert cli.main(["contacts"]) == 0
    assert "Carol" in capsys.readouterr().out
    assert cli.main(["contacts", "remove", "Carol"]) == 0
    assert cli.main(["contacts", "remove", "Carol"]) == 1


# ------------------------------------------------------------------ duplicates

@pytest.fixture
def dupes(tmp_path):
    src = tmp_path / "photos"
    (src / "a").mkdir(parents=True)
    (src / "b").mkdir()
    blob = os.urandom(300_000)
    for p in ("a/one.bin", "b/two.bin", "three.bin"):
        (src / p).write_bytes(blob)
    (src / "near.bin").write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))  # same size, different
    (src / "small1.txt").write_text("x")
    (src / "small2.txt").write_text("x")
    return src


def test_duplicates_stored_once_and_restored_as_copies(tmp_path, dupes):
    # Already-compressed data (photos, videos) is where zstd can't help and dedup does.
    with_dedup = lock([dupes], tmp_path / "d.clk", compression="none")
    without = lock([dupes], tmp_path / "n.clk", compression="none", dedup=False)
    assert "2 duplicate file(s) stored once" in with_dedup.compression_note
    assert with_dedup.output_bytes < without.output_bytes - 550_000
    with open(tmp_path / "d.clk", "rb") as f:
        assert read_header(f)[0].flags & FLAG_DEDUP
    api.unlock(tmp_path / "d.clk", tmp_path / "out", password=PW)
    back = tmp_path / "out" / "photos"
    same_tree(dupes, back)
    assert os.stat(back / "a/one.bin").st_ino != os.stat(back / "b/two.bin").st_ino  # real copies
    sizes = {n: s for n, s, _d in api.verify(tmp_path / "d.clk", password=PW).entries}
    assert sizes["photos/b/two.bin"] == 300_000


def test_extract_only_a_duplicate(tmp_path, dupes):
    lock([dupes], tmp_path / "d.clk")
    api.unlock(tmp_path / "d.clk", tmp_path / "out", password=PW, only=["photos/b/two.bin"])
    out = tmp_path / "out"
    assert (out / "photos/b/two.bin").read_bytes() == (dupes / "b/two.bin").read_bytes()
    assert not (out / "photos/a").exists()
    assert [p.name for p in out.iterdir()] == ["photos"]  # no leftover hidden folders


def test_add_keeps_duplicates_working(tmp_path, dupes):
    out = tmp_path / "d.clk"
    lock([dupes], out)
    extra = tmp_path / "more"
    extra.mkdir()
    (extra / "x.bin").write_bytes((dupes / "three.bin").read_bytes())
    (extra / "y.bin").write_bytes((dupes / "three.bin").read_bytes())
    api.add(out, [extra], password=PW)
    api.unlock(out, tmp_path / "back", password=PW)
    same_tree(dupes, tmp_path / "back" / "photos")
    same_tree(extra, tmp_path / "back" / "more")


# ------------------------------------------------------------------ file signatures

def test_sign_and_verify_any_file(tmp_path):
    alice, alice_pub = person(tmp_path, "alice")
    _, bob_pub = person(tmp_path, "bob")
    f = tmp_path / "SHA256SUMS"
    f.write_text("abc  file.zip\n")
    sig = api.sign_file(f, alice)
    assert sig.name == "SHA256SUMS.clksig"
    r = api.verify_file(f, signer=str(alice_pub))
    assert r.signed_by == keys.fingerprint(alice.verify_key)
    with pytest.raises(CrunchlockError, match="not by the expected"):
        api.verify_file(f, signer=str(bob_pub))
    f.write_text("abc  evil.zip\n")
    with pytest.raises(CorruptFileError, match="changed"):
        api.verify_file(f)


def test_cli_sign_and_verify_file(tmp_path, monkeypatch, capsys):
    alice, alice_pub = person(tmp_path, "alice")
    key = tmp_path / "alice.clkkey"
    key.write_bytes(keys.save_private_key(alice, "pw", api.kdf.PROFILES[FAST]))
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    monkeypatch.setenv(cli.ENV_PASSWORD + "_KEY", "pw")
    assert cli.main(["sign-file", str(f), "--key", str(key)]) == 0
    contacts.add("Alice", alice_pub.read_text())
    assert cli.main(["verify-file", str(f), "--signer", "Alice"]) == 0
    assert "signed by Alice" in capsys.readouterr().out
    f.write_text("hello!")
    assert cli.main(["verify-file", str(f)]) == 1
