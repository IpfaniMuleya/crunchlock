"""Command-line interface: ``crunchlock lock|unlock|verify|info|genpass|keygen``."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from . import __version__, api, compress, kdf, keys, passgen
from .errors import CrunchlockError, WrongKeyError
from .shred import WARNING as SHRED_WARNING
from .split import parse_size

ENV_PASSWORD = "CRUNCHLOCK_PASSWORD"


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class ProgressPrinter:
    def __init__(self, enabled: bool):
        self.enabled = enabled and sys.stderr.isatty()
        self.last = 0.0
        self.stage = None

    def __call__(self, stage: str, done: int, total: int) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if stage == self.stage and now - self.last < 0.1 and done < total:
            return
        self.last, self.stage = now, stage
        pct = f"{100 * done / total:5.1f}%" if total else ""
        sys.stderr.write(f"\r  {stage:<14} {pct} {human(done):>10}   ")
        sys.stderr.flush()

    def done(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 50 + "\r")


def read_keyfile(path: str | None) -> bytes | None:
    if not path:
        return None
    data = Path(path).read_bytes()
    if not data:
        raise CrunchlockError("keyfile is empty")
    return data


def ask_password(confirm: bool, prompt: str = "Password: ", allow_env: bool = True) -> str:
    if allow_env and os.environ.get(ENV_PASSWORD):
        return os.environ[ENV_PASSWORD]
    if not sys.stdin.isatty():
        raise CrunchlockError(f"no terminal to ask for a password (set {ENV_PASSWORD} for scripts)")
    pw = getpass.getpass(prompt)
    if confirm:
        bits = passgen.estimate_bits(pw)
        r = passgen.rating(bits)
        if r in ("weak", "fair"):
            print(f"  warning: this password looks {r} (~{bits:.0f} bits). "
                  "Try `crunchlock genpass` for a strong passphrase.", file=sys.stderr)
        if getpass.getpass("Repeat password: ") != pw:
            raise CrunchlockError("passwords do not match")
    return pw


# ---------------------------------------------------------------- commands

def cmd_lock(a) -> int:
    recipients = [api.load_recipient(r) for r in a.recipient or []]
    keyfile = read_keyfile(a.keyfile)
    password = None
    if not a.no_password and not (recipients and not a.password_too and keyfile is None):
        password = ask_password(confirm=True)
        if not password and keyfile is None:
            raise CrunchlockError("empty password")
    if a.shred:
        print(f"  note: {SHRED_WARNING}", file=sys.stderr)
    split = parse_size(a.split) if a.split else None
    prog = ProgressPrinter(not a.quiet)
    r = api.lock(a.paths, a.output, password=password or None, keyfile=keyfile,
                 recipients=recipients, compression="none" if a.no_compress else a.compress,
                 level=a.level, kdf_profile=a.profile, pad=a.pad, recovery_data=a.recovery,
                 split_size=split, shred_originals=a.shred, force=a.force, jpeg=not a.no_jpeg,
                 progress=prog)
    prog.done()
    for o in r.outputs:
        print(f"wrote {o}")
    print(f"  {human(r.input_bytes)} -> {human(r.output_bytes)}"
          + (f"  ({r.saved_percent:.1f}% smaller)" if r.saved_percent > 0 else "")
          + f"  [compression: {r.compression}]")
    if r.compression_note:
        print(f"  {r.compression_note}")
    for w in r.warnings:
        print(f"  warning: {w}", file=sys.stderr)
    for s in r.shredded:
        print(f"  securely deleted {s}")
    return 0


def _identity(a):
    if not getattr(a, "identity", None):
        return None
    pw = ask_password(False, "Private key passphrase: ", allow_env=False)
    return api.load_identity(a.identity, pw)


def _secrets_for_open(a):
    path = a.file
    meta = api.info(path)
    identity = _identity(a)
    keyfile = read_keyfile(a.keyfile)
    password = None
    has_pw_slot = any(s["type"].startswith("password") for s in meta["key_slots"])
    if has_pw_slot and identity is None:
        if meta["needs_keyfile"] and keyfile is None:
            print("  note: this file was locked with a keyfile (--keyfile)", file=sys.stderr)
        password = ask_password(False)
    return password, keyfile, identity


def cmd_unlock(a) -> int:
    password, keyfile, identity = _secrets_for_open(a)
    prog = ProgressPrinter(not a.quiet)
    r = api.unlock(a.file, a.output, password=password, keyfile=keyfile, identity=identity,
                   force=a.force, progress=prog)
    prog.done()
    if r.repaired_bytes:
        print(f"  repaired {r.repaired_bytes} damaged bytes using recovery data")
    for p in r.extracted:
        print(f"extracted {p}")
    return 0


def cmd_verify(a) -> int:
    password, keyfile, identity = _secrets_for_open(a)
    prog = ProgressPrinter(not a.quiet)
    r = api.verify(a.file, password=password, keyfile=keyfile, identity=identity, progress=prog)
    prog.done()
    files = [e for e in r.entries if not e[2]]
    print(f"OK: authentic and intact — {len(files)} file(s), {human(r.total_bytes)} "
          f"[compression: {r.compression}]")
    if r.repaired_bytes:
        print(f"  warning: {r.repaired_bytes} damaged bytes were repaired in memory; "
              "consider re-locking a fresh copy")
    if a.list:
        for name, size, is_dir in r.entries:
            print(f"  {name + '/' if is_dir else name}" + ("" if is_dir else f"  ({human(size)})"))
    return 0


def cmd_rekey(a) -> int:
    password, keyfile, identity = _secrets_for_open(a)
    recipients = [api.load_recipient(r) for r in a.recipient or []]
    new_keyfile = read_keyfile(a.new_keyfile)
    new_password = None
    if not a.no_password:
        if sys.stdin.isatty() and not os.environ.get(ENV_PASSWORD + "_NEW"):
            print("Choose the new password (press Enter twice to keep the current one).", file=sys.stderr)
            new_password = ask_password(True, "New password: ", allow_env=False) or password
        else:
            new_password = os.environ.get(ENV_PASSWORD + "_NEW") or password
        if not new_password and new_keyfile is None and not recipients:
            raise CrunchlockError("no new password given")
    prog = ProgressPrinter(not a.quiet)
    r = api.rekey(a.file, password=password, keyfile=keyfile, identity=identity,
                  new_password=new_password, new_keyfile=new_keyfile, recipients=recipients,
                  kdf_profile=a.profile, progress=prog)
    prog.done()
    print(f"updated {', '.join(str(o) for o in r.outputs)}")
    print(f"  now opens with: {r.unlock_with}")
    return 0


def cmd_info(a) -> int:
    m = api.info(a.file)
    print(f"file:          {', '.join(m['parts'])}")
    print(f"size:          {human(m['size'])}")
    print(f"format:        crunchlock v{m['format_version']}, {m['cipher']}")
    print(f"recovery data: {'yes' if m['recovery_data'] else 'no'}")
    print(f"JPEG recompr.: {'yes' if m['jpeg_recompression'] else 'no'}")
    for s in m["key_slots"]:
        extra = (f" (argon2id, {s['memory_mib']} MiB, t={s['time_cost']}, p={s['parallelism']})"
                 if "kdf" in s else "")
        print(f"unlock with:   {s['type']}{extra}")
    return 0


def cmd_genpass(a) -> int:
    for _ in range(a.count):
        print(passgen.generate(a.words, a.separator))
    print(f"  (~{passgen.passphrase_bits(a.words):.0f} bits of entropy each)", file=sys.stderr)
    return 0


def cmd_keygen(a) -> int:
    base = Path(a.name)
    priv, pub = base.with_suffix(".clkkey"), base.with_suffix(".clkpub")
    for p in (priv, pub):
        if p.exists() and not a.force:
            raise CrunchlockError(f"{p} already exists (use --force)")
    pw = ask_password(True, "Passphrase to protect the private key: ", allow_env=False)
    ident = keys.generate_identity()
    data = keys.save_private_key(ident, pw, kdf.PROFILES[a.profile])
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    pub.write_text(keys.public_key_to_text(ident.public) + "\n")
    print(f"private key: {priv}  (keep secret, keep a backup!)")
    print(f"public key:  {pub}  (share freely)")
    print(f"  {keys.public_key_to_text(ident.public)}")
    print(f"  fingerprint {keys.fingerprint(ident.public)}")
    return 0


# ------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crunchlock",
        description="Compress (optional, lossless) and encrypt files into small, secure .clk files.")
    p.add_argument("--version", action="version", version=f"crunchlock {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    profiles = [k for k in kdf.PROFILES if k != "insecure-test"]

    lk = sub.add_parser("lock", help="compress + encrypt files/folders into a .clk file")
    lk.add_argument("paths", nargs="+", help="files and/or folders")
    lk.add_argument("-o", "--output", help="output file (default: <first-input>.clk)")
    g = lk.add_mutually_exclusive_group()
    g.add_argument("-n", "--no-compress", action="store_true", help="encrypt only, don't compress")
    g.add_argument("-c", "--compress", default="zstd", choices=["zstd", "xz", "best"],
                   help="compressor (default zstd; 'best' tries both and keeps the smaller)")
    lk.add_argument("-l", "--level", type=int,
                    help=f"compression level (zstd 1-22, default {compress.DEFAULT_LEVEL[1]}; xz 0-9)")
    lk.add_argument("--profile", default="standard", choices=profiles,
                    help="password hardening: standard (256 MiB), paranoid (1 GiB), light (64 MiB)")
    lk.add_argument("--keyfile", help="also require this file to unlock (any file, keep it safe)")
    lk.add_argument("-r", "--recipient", action="append",
                    help="public key (clkpub1:... or .clkpub file) that can unlock; repeatable")
    lk.add_argument("--password-too", action="store_true",
                    help="with --recipient: also allow unlocking with a password")
    lk.add_argument("--no-password", action="store_true", help=argparse.SUPPRESS)
    lk.add_argument("--no-jpeg", action="store_true",
                    help="don't losslessly recompress JPEG photos (on by default, ~20%% smaller)")
    lk.add_argument("--pad", action="store_true", help="pad output to hide the exact size")
    lk.add_argument("--recovery", action="store_true",
                    help="add ~14%% Reed-Solomon data so damaged files can be repaired")
    lk.add_argument("--split", metavar="SIZE", help="split into parts of SIZE (e.g. 100M, 4G)")
    lk.add_argument("--shred", action="store_true",
                    help="securely delete the originals after verifying the new file")
    lk.add_argument("-f", "--force", action="store_true", help="overwrite existing output")
    lk.add_argument("-q", "--quiet", action="store_true")
    lk.set_defaults(func=cmd_lock)

    def opener(name, help_, func):
        s = sub.add_parser(name, help=help_)
        s.add_argument("file", help=".clk file (or its .001 part)")
        s.add_argument("--keyfile", help="keyfile used when locking")
        s.add_argument("-i", "--identity", help="your private key (.clkkey)")
        s.add_argument("-q", "--quiet", action="store_true")
        s.set_defaults(func=func)
        return s

    ul = opener("unlock", "decrypt + decompress a .clk file", cmd_unlock)
    ul.add_argument("-o", "--output", help="folder to extract into (default: next to the file)")
    ul.add_argument("-f", "--force", action="store_true", help="overwrite existing files")
    vf = opener("verify", "check password and integrity without extracting", cmd_verify)
    vf.add_argument("--list", action="store_true", help="list contents")

    rk = opener("rekey", "change the password, keyfile or recipients of a .clk file", cmd_rekey)
    rk.add_argument("--new-keyfile", help="require this keyfile from now on")
    rk.add_argument("-r", "--recipient", action="append",
                    help="public key that can unlock from now on; repeatable")
    rk.add_argument("--no-password", action="store_true",
                    help="remove the password (then only --new-keyfile / --recipient open it)")
    rk.add_argument("--profile", default="standard", choices=profiles)

    inf = sub.add_parser("info", help="show file details (no password needed)")
    inf.add_argument("file")
    inf.set_defaults(func=cmd_info)

    gp = sub.add_parser("genpass", help="generate a strong random passphrase")
    gp.add_argument("-w", "--words", type=int, default=6, help="number of words (default 6)")
    gp.add_argument("-s", "--separator", default="-")
    gp.add_argument("-c", "--count", type=int, default=1)
    gp.set_defaults(func=cmd_genpass)

    kg = sub.add_parser("keygen", help="create a key pair for public-key sharing")
    kg.add_argument("name", help="base name, e.g. 'alice' -> alice.clkkey + alice.clkpub")
    kg.add_argument("--profile", default="standard", choices=profiles)
    kg.add_argument("-f", "--force", action="store_true")
    kg.set_defaults(func=cmd_keygen)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except WrongKeyError as e:
        print(f"crunchlock: {e}", file=sys.stderr)
        return 2
    except (CrunchlockError, OSError, ValueError) as e:
        print(f"crunchlock: error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ncrunchlock: cancelled; nothing was written", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
