"""Command-line interface: ``crunchlock lock|unlock|verify|info|genpass|keygen``."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from . import __version__, api, compress, kdf, keys, passgen
from .eta import Eta, format_eta
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
        self.eta = Eta()

    def __call__(self, stage: str, done: int, total: int) -> None:
        if not self.enabled:
            return
        left = format_eta(self.eta.update(stage, done, total))
        now = time.monotonic()
        if stage == self.stage and now - self.last < 0.1 and done < total:
            return
        self.last, self.stage = now, stage
        pct = f"{100 * done / total:5.1f}%" if total else ""
        sys.stderr.write(f"\r  {stage:<14} {pct} {human(done):>10}   {left:<22}")
        sys.stderr.flush()

    def done(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 72 + "\r")


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

def _signing_identity(a):
    if not getattr(a, "sign", None):
        return None
    pw = ask_password(False, "Passphrase of the key you sign with: ", allow_env=False)
    return api.load_identity(a.sign, pw)


def cmd_lock(a) -> int:
    recipients = [api.load_recipient(r) for r in a.recipient or []]
    keyfile = read_keyfile(a.keyfile)
    signer = _signing_identity(a)
    password = None
    if not a.no_password and not (recipients and not a.password_too and keyfile is None):
        password = ask_password(confirm=True)
        if not password and keyfile is None:
            raise CrunchlockError("empty password")
    if a.shred:
        print(f"  note: {SHRED_WARNING}", file=sys.stderr)
    split = parse_size(a.split) if a.split else None
    prog = ProgressPrinter(not a.quiet)
    options = dict(password=password or None, keyfile=keyfile,
                   recipients=recipients, compression="none" if a.no_compress else a.compress,
                   level=a.level, kdf_profile=a.profile, pad=a.pad, recovery_data=a.recovery,
                   split_size=split, shred_originals=a.shred, force=a.force, jpeg=not a.no_jpeg,
                   png=not a.no_png, long_range=a.long, sign_with=signer)
    if a.each:
        results = api.lock_each(a.paths, a.output, progress=prog, **options)
        prog.done()
        for r in results:
            _print_lock_result(r)
        total_in = sum(r.input_bytes for r in results)
        total_out = sum(r.output_bytes for r in results)
        print(f"locked {len(results)} item(s) separately: {human(total_in)} -> {human(total_out)}")
        return 0
    r = api.lock(a.paths, a.output, progress=prog, **options)
    prog.done()
    _print_lock_result(r)
    return 0


def _print_lock_result(r) -> None:
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


def _print_signer(signed_by, expected, name=None) -> None:
    if signed_by and name:
        print(f"  signed by {name} (key {signed_by})" + ("  (matches --signer)" if expected else ""))
    elif signed_by:
        print(f"  signed by key {signed_by}" + ("  (matches --signer)" if expected else
                                                 "  (compare this with the sender's fingerprint)"))
    else:
        print("  not signed")


def cmd_unlock(a) -> int:
    password, keyfile, identity = _secrets_for_open(a)
    prog = ProgressPrinter(not a.quiet)
    r = api.unlock(a.file, a.output, password=password, keyfile=keyfile, identity=identity,
                   force=a.force, only=a.only, signer=a.signer, progress=prog)
    prog.done()
    if r.repaired_bytes:
        print(f"  repaired {r.repaired_bytes} damaged bytes using recovery data")
    for p in r.extracted:
        print(f"extracted {p}")
    _print_signer(r.signed_by, a.signer, r.signer_name)
    return 0


def cmd_verify(a) -> int:
    password, keyfile, identity = _secrets_for_open(a)
    prog = ProgressPrinter(not a.quiet)
    r = api.verify(a.file, password=password, keyfile=keyfile, identity=identity,
                   signer=a.signer, progress=prog)
    prog.done()
    files = [e for e in r.entries if not e[2]]
    print(f"OK: authentic and intact — {len(files)} file(s), {human(r.total_bytes)} "
          f"[compression: {r.compression}]")
    _print_signer(r.signed_by, a.signer, r.signer_name)
    if r.repaired_bytes:
        print(f"  warning: {r.repaired_bytes} damaged bytes were repaired in memory; "
              "consider re-locking a fresh copy")
    if a.list:
        for name, size, is_dir in r.entries:
            print(f"  {name + '/' if is_dir else name}" + ("" if is_dir else f"  ({human(size)})"))
    return 0


def cmd_add(a) -> int:
    meta = api.info(a.file)
    identity = _identity(a)
    keyfile = read_keyfile(a.keyfile)
    recipients = [api.load_recipient(r) for r in a.recipient or []]
    signer = _signing_identity(a)
    password = None
    if any(s["type"].startswith("password") for s in meta["key_slots"]):
        if meta["needs_keyfile"] and keyfile is None:
            print("  note: this file was locked with a keyfile (--keyfile)", file=sys.stderr)
        password = ask_password(False)
    prog = ProgressPrinter(not a.quiet)
    r = api.add(a.file, a.paths, password=password, keyfile=keyfile, identity=identity,
                recipients=recipients, replace=a.replace, sign_with=signer,
                jpeg=not a.no_jpeg, png=not a.no_png, progress=prog)
    prog.done()
    for p in r.added:
        print(f"added {p}")
    for name in r.replaced:
        print(f"  replaced {name}")
    print(f"updated {', '.join(str(o) for o in r.outputs)}  ({human(r.output_bytes)})")
    if r.signed_by:
        print(f"  signed by key {r.signed_by}")
    for w in r.warnings:
        print(f"  warning: {w}", file=sys.stderr)
    return 0


def cmd_pubkey(a) -> int:
    pw = ask_password(False, "Private key passphrase: ", allow_env=False)
    ident = api.load_identity(a.key, pw)
    text = keys.public_key_to_text(ident)
    if a.output:
        out = Path(a.output)
        if out.exists() and not a.force:
            raise CrunchlockError(f"{out} already exists (use --force)")
        out.write_text(text + "\n")
        print(f"wrote {out}")
    print(text)
    print(f"  fingerprint          {keys.fingerprint(ident.public)}")
    print(f"  signing fingerprint  {keys.fingerprint(ident.verify_key)}")
    return 0


def cmd_contacts(a) -> int:
    from . import contacts
    if a.action == "add":
        if not a.name or not a.key:
            raise CrunchlockError("usage: crunchlock contacts add NAME PUBLIC_KEY_OR_FILE")
        text = a.key if a.key.startswith((keys.PUB_PREFIX, keys.PUB2_PREFIX)) \
            else Path(a.key).read_text("utf-8")
        contacts.add(a.name, text)
        print(f"added {a.name}")
    elif a.action == "remove":
        if not a.name:
            raise CrunchlockError("usage: crunchlock contacts remove NAME")
        contacts.remove(a.name)
        print(f"removed {a.name}")
    else:
        data = contacts.load()
        if not data:
            print("no contacts yet (crunchlock contacts add NAME bob.clkpub)")
        for name, text in data.items():
            x, ed = keys.parse_public_text(text)
            sig = f"  signs as {keys.fingerprint(ed)}" if ed else "  (old key: can't check signatures)"
            print(f"{name}\t{keys.fingerprint(x)}{sig}")
    return 0


def cmd_sign_file(a) -> int:
    pw = os.environ.get(ENV_PASSWORD + "_KEY") or \
        ask_password(False, "Private key passphrase: ", allow_env=False)  # env var: for CI
    ident = api.load_identity(a.key, pw)
    out = api.sign_file(a.file, ident)
    print(f"wrote {out}  (signed by {keys.fingerprint(ident.verify_key)})")
    return 0


def cmd_verify_file(a) -> int:
    r = api.verify_file(a.file, a.signature, signer=a.signer)
    who = f"{r.signer_name} (key {r.signed_by})" if r.signer_name else f"key {r.signed_by}"
    print(f"OK: {a.file} is unchanged and was signed by {who}")
    return 0


def cmd_check_update(a) -> int:
    from . import update
    try:
        info = update.check()
    except (OSError, ValueError) as e:
        raise CrunchlockError(f"couldn't check for updates: {e}") from e
    if info.newer:
        print(f"Crunchlock {info.latest} is available (you have {info.current}): {info.url}")
    else:
        print(f"You have the latest version ({info.current}).")
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


def cmd_list(a) -> int:
    password, keyfile, identity = _secrets_for_open(a)
    prog = ProgressPrinter(not a.quiet)
    r = api.verify(a.file, password=password, keyfile=keyfile, identity=identity, progress=prog)
    prog.done()
    for name, size, is_dir in r.entries:
        print(f"{name}/" if is_dir else f"{name}\t{human(size)}")
    files = [e for e in r.entries if not e[2]]
    print(f"  {len(files)} file(s), {human(r.total_bytes)}; extract some with: "
          f"crunchlock unlock {a.file} --only <path>", file=sys.stderr)
    return 0


def cmd_repair(a) -> int:
    prog = ProgressPrinter(not a.quiet)
    r = api.repair(a.file, a.output, force=a.force, progress=prog)
    prog.done()
    if not r.was_damaged:
        print("no damage found; nothing written")
        return 0
    print(f"repaired {r.repaired_bytes} damaged bytes")
    for o in r.outputs:
        print(f"wrote {o}")
    print("  check it with: crunchlock verify " + str(r.outputs[0]))
    return 0


def cmd_info(a) -> int:
    m = api.info(a.file)
    print(f"file:          {', '.join(m['parts'])}")
    print(f"size:          {human(m['size'])}")
    print(f"format:        crunchlock v{m['format_version']}, {m['cipher']}")
    print(f"recovery data: {'yes' if m['recovery_data'] else 'no'}")
    print(f"JPEG recompr.: {'yes' if m['jpeg_recompression'] else 'no'}")
    print(f"PNG recompr.:  {'yes' if m['png_recompression'] else 'no'}")
    print(f"signed:        {'yes (unlock or verify to see by whom)' if m['signed'] else 'no'}")
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
    pub.write_text(keys.public_key_to_text(ident) + "\n")
    print(f"private key: {priv}  (keep secret, keep a backup!)")
    print(f"public key:  {pub}  (share freely)")
    print(f"  {keys.public_key_to_text(ident)}")
    print(f"  fingerprint         {keys.fingerprint(ident.public)}")
    print(f"  signing fingerprint {keys.fingerprint(ident.verify_key)}")
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
    lk.add_argument("-o", "--output",
                    help="output file (default: <first-input>.clk); with --each, a folder")
    lk.add_argument("--each", action="store_true",
                    help="lock every file/folder into its own .clk instead of one bundle")
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
                    help="public key (clkpub2:... or .clkpub file) that can unlock; repeatable")
    lk.add_argument("--password-too", action="store_true",
                    help="with --recipient: also allow unlocking with a password")
    lk.add_argument("--no-password", action="store_true", help=argparse.SUPPRESS)
    lk.add_argument("--sign", metavar="KEY",
                    help="sign with your private key (.clkkey) so recipients can check it's from you")
    lk.add_argument("--no-jpeg", action="store_true",
                    help="don't losslessly recompress JPEG photos (on by default, ~20%% smaller)")
    lk.add_argument("--no-png", action="store_true",
                    help="don't losslessly repack PNG images (on by default, often 20-50%% smaller)")
    lk.add_argument("--long", action="store_true",
                    help="find repeats up to 1 GiB apart (big backups/disk images); "
                         "unlocking needs up to 1 GiB of memory")
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

    signer_help = ("only accept the file if it was signed by this public key "
                   "(clkpub2:... or .clkpub file); nothing is extracted otherwise")
    ul = opener("unlock", "decrypt + decompress a .clk file", cmd_unlock)
    ul.add_argument("-o", "--output", help="folder to extract into (default: next to the file)")
    ul.add_argument("-f", "--force", action="store_true", help="overwrite existing files")
    ul.add_argument("--only", action="append", metavar="PATH",
                    help="extract just this file or folder (as shown by `crunchlock list`); repeatable")
    ul.add_argument("--signer", metavar="PUBKEY", help=signer_help)
    opener("list", "show the files inside a .clk (needs the password)", cmd_list)
    ad = opener("add", "add files/folders to an existing .clk (needs the password)", cmd_add)
    ad.add_argument("paths", nargs="+", help="files and/or folders to add")
    ad.add_argument("-r", "--recipient", action="append",
                    help="public key the file is shared with (they must be given again); repeatable")
    ad.add_argument("--replace", action="store_true",
                    help="replace items that already exist in the file under the same name")
    ad.add_argument("--sign", metavar="KEY", help="sign the updated file with your private key")
    ad.add_argument("--no-jpeg", action="store_true", help="don't recompress JPEG photos")
    ad.add_argument("--no-png", action="store_true", help="don't repack PNG images")
    rp = sub.add_parser("repair", help="write a repaired copy of a damaged file (needs recovery data; "
                                      "no password needed)")
    rp.add_argument("file", help=".clk file (or its .001 part)")
    rp.add_argument("-o", "--output", help="output file (default: <name>.repaired.clk)")
    rp.add_argument("-f", "--force", action="store_true", help="overwrite existing output")
    rp.add_argument("-q", "--quiet", action="store_true")
    rp.set_defaults(func=cmd_repair)
    vf = opener("verify", "check password and integrity without extracting", cmd_verify)
    vf.add_argument("--list", action="store_true", help="list contents")
    vf.add_argument("--signer", metavar="PUBKEY", help=signer_help)

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

    pk = sub.add_parser("pubkey", help="show (or save) the public key of your private key, "
                                       "including the key others use to check your signatures")
    pk.add_argument("key", help="your private key (.clkkey)")
    pk.add_argument("-o", "--output", help="save it to this .clkpub file")
    pk.add_argument("-f", "--force", action="store_true")
    pk.set_defaults(func=cmd_pubkey)

    ct = sub.add_parser("contacts", help="save people's public keys under a name "
                                         "(then use the name with -r / --signer)")
    ct.add_argument("action", nargs="?", default="list", choices=["list", "add", "remove"])
    ct.add_argument("name", nargs="?")
    ct.add_argument("key", nargs="?", help="public key text or .clkpub file (for add)")
    ct.set_defaults(func=cmd_contacts)

    sf = sub.add_parser("sign-file", help="sign any file (writes FILE.clksig)")
    sf.add_argument("file")
    sf.add_argument("--key", required=True, help="your private key (.clkkey)")
    sf.set_defaults(func=cmd_sign_file)
    vfl = sub.add_parser("verify-file", help="check a FILE.clksig signature (e.g. a download)")
    vfl.add_argument("file")
    vfl.add_argument("--signature", help="signature file (default: FILE.clksig)")
    vfl.add_argument("--signer", metavar="PUBKEY",
                     help="only accept this signer (public key, .clkpub file or contact name)")
    vfl.set_defaults(func=cmd_verify_file)

    cu = sub.add_parser("check-update", help="see if a newer version is out (contacts github.com)")
    cu.set_defaults(func=cmd_check_update)
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
