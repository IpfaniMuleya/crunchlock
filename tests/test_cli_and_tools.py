import math
import os

import pytest

from crunchlock import api, cli, passgen
from crunchlock.split import parse_size

PW = "correct horse battery staple"


def test_genpass():
    p = passgen.generate(6, separator=" ")  # a few EFF words contain "-" (e.g. felt-tip)
    words = p.split(" ")
    assert len(words) == 6 and all(w in passgen.wordlist() for w in words)
    assert passgen.generate(6).count("-") >= 5
    assert passgen.passphrase_bits(6) == pytest.approx(6 * math.log2(7776))
    assert len({passgen.generate(6) for _ in range(50)}) == 50


@pytest.mark.parametrize("pw,expected", [("password", "weak"), ("123456", "weak"),
                                         ("aaaaaaaaaaaa", "weak"), ("Tr0ub4dor&3", "weak"),
                                         ("Summer2024!", "weak"), ("x8#Kq!v2Lm&9pZ", "very strong")])
def test_strength(pw, expected):
    assert passgen.rating(passgen.estimate_bits(pw)) == expected


def test_hyphenated_words_are_handled():
    """Regression: words like "felt-tip" must not be counted as two words."""
    hyphenated = [w for w in passgen.wordlist() if "-" in w]
    assert hyphenated  # drop-down, felt-tip, t-shirt, yo-yo
    import random
    rng = random.Random(1)
    for _ in range(200):
        words = [rng.choice(passgen.wordlist()) for _ in range(5)] + [rng.choice(hyphenated)]
        assert len(" ".join(words).split(" ")) == 6


def test_strength_of_generated():
    assert passgen.rating(passgen.estimate_bits(passgen.generate(6))) == "very strong"


def test_parse_size():
    assert parse_size("100M") == 100 << 20
    assert parse_size("1.5G") == int(1.5 * (1 << 30))
    with pytest.raises(api.CrunchlockError):
        parse_size("10")


def test_cli_end_to_end(tmp_path, sample, monkeypatch, capsys):
    monkeypatch.setenv(cli.ENV_PASSWORD, PW)
    monkeypatch.setitem(api.kdf.PROFILES, "light", api.kdf.PROFILES["insecure-test"])
    out = tmp_path / "c.clk"
    assert cli.main(["lock", str(sample), "-o", str(out), "--profile", "light", "-q"]) == 0
    text = capsys.readouterr().out
    assert "smaller" in text
    assert cli.main(["info", str(out)]) == 0
    assert cli.main(["verify", str(out), "--list", "-q"]) == 0
    assert "notes.txt" in capsys.readouterr().out
    assert cli.main(["unlock", str(out), "-o", str(tmp_path / "back"), "-q"]) == 0
    assert (tmp_path / "back" / "docs" / "notes.txt").exists()
    monkeypatch.setenv(cli.ENV_PASSWORD, "wrong")
    assert cli.main(["verify", str(out), "-q"]) == 2
    capsys.readouterr()
    assert cli.main(["genpass", "-w", "7", "-s", " "]) == 0
    assert len(capsys.readouterr().out.strip().split(" ")) == 7


def test_cli_recipients(tmp_path, sample, monkeypatch, capsys):
    monkeypatch.setitem(api.kdf.PROFILES, "standard", api.kdf.PROFILES["insecure-test"])
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "key-pass-phrase-long")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    base = tmp_path / "alice"
    assert cli.main(["keygen", str(base)]) == 0
    if os.name == "posix":
        assert oct(os.stat(base.with_suffix(".clkkey")).st_mode & 0o777) == "0o600"
    out = tmp_path / "r.clk"
    assert cli.main(["lock", str(sample), "-o", str(out), "-r", str(base.with_suffix(".clkpub")),
                     "--split", "300K", "--recovery", "--pad", "-q"]) == 0
    assert cli.main(["unlock", str(out) + ".001", "-i", str(base.with_suffix(".clkkey")),
                     "-o", str(tmp_path / "o"), "-q"]) == 0
    assert (tmp_path / "o" / "docs" / "sub" / "random.bin").read_bytes() == \
        (sample / "sub" / "random.bin").read_bytes()
