# crunchlock

**Lossless compression + strong encryption in one step.** Crunchlock turns files and folders
into a single small `.clk` file that can only be opened with your password (or your private
key), and restores them byte-for-byte.

- **Smaller files.** Optional lossless compression with zstd (level 19 by default) or xz, or
  `best` to try both and keep the smaller result. Text, logs, CSVs, source code and documents
  typically shrink by 75–95%. **JPEG photos are losslessly recompressed** (via JPEG XL) to about
  15–22% smaller, and **PNG images** (screenshots, diagrams) often 20–50% smaller. Both are
  restored byte-for-byte. Big inputs get a bigger match window automatically, and `--long` finds
  repeats up to 1 GiB apart (backups, disk images). Other data that is already compressed
  (videos, zip files) is detected and stored as-is.
- **Hard to crack.** AES-256-GCM authenticated encryption, with passwords hardened by
  **Argon2id** (256 MiB of RAM per guess by default, or 1 GiB with `--profile paranoid`).
  Any tampering, truncation or wrong password is detected. Nothing is ever silently corrupted.
- **Private metadata.** File names, sizes and folder structure are all inside the encryption.
- **Signed files.** Sign with your key so recipients can prove a file came from you and wasn't
  changed.
- **CLI and desktop app.** `crunchlock` on the command line, and `crunchlock-gui` for a simple
  window.

| Feature | How |
|---|---|
| Compress or not, your choice | `-c zstd` (default), `-c xz`, `-c best`, `-n/--no-compress` |
| Several files/folders in one archive | `crunchlock lock a.pdf photos/ notes.txt` |
| Strong passphrase generator | `crunchlock genpass` (6 random words ≈ 78 bits) |
| Check a file without extracting it | `crunchlock verify file.clk [--list]` |
| Share without sharing a password | `crunchlock keygen alice`, then `lock -r alice.clkpub` |
| Two-factor: password + keyfile | `--keyfile some-secret-file` |
| Split for email/upload limits | `--split 25M` → `file.clk.001`, `.002`, … |
| Hide the exact size | `--pad` (Padmé padding, ≤ 12% overhead) |
| Survive disk damage | `--recovery` (Reed-Solomon, +14%, repairs bursts up to 4 KB per 64 KB) |
| Remove the originals | `--shred` (only after the new file is verified) |
| Change the password / recipients | `crunchlock rekey file.clk` (no recompression needed) |
| Keep images untouched | `--no-jpeg`, `--no-png` (turn off lossless image recompression) |
| Big backups / disk images | `--long` (finds repeats up to 1 GiB apart; unlocking needs up to 1 GiB RAM) |
| Prove a file is from you | `lock --sign alice.clkkey`; the recipient runs `unlock --signer alice.clkpub` |
| Add files to a locked file | `crunchlock add file.clk new.pdf more/` (no unpacking to disk) |
| New version? | `crunchlock check-update`, or the opt-in check in the app |
| See what's inside / take out one file | `crunchlock list file.clk`, then `unlock file.clk --only docs/report.pdf` |
| Lock files one by one | `crunchlock lock *.pdf --each -o locked/` → one `.clk` per item |
| Fix a damaged file | `crunchlock repair file.clk` → `file.repaired.clk` (needs `--recovery`; no password needed) |

## Download (no Python needed)

Ready-to-run programs for **Windows (.exe)**, macOS and Linux are built automatically by
GitHub Actions:

- **Releases:** for each `v*` tag, the files are attached to the
  [Releases page](../../releases).
- **Latest build:** open the **Actions** tab, choose the newest *Test & build executables*
  run, and download `crunchlock-Windows` (or `-macOS` / `-Linux`) under *Artifacts*.

On Windows the easiest option is the **installer**, `Crunchlock-Setup-x.y.z.exe` (artifact
`crunchlock-Windows-installer`). It installs for your user without needing admin rights, and
adds:
- a Start-menu entry (plus a desktop shortcut if you want one);
- **right-click → "Lock with Crunchlock"** on any file or folder (selecting several files
  sends them all to the same window);
- **double-click a `.clk` file** to open it on the Unlock tab.

You can uninstall it from *Settings → Apps*. If you'd rather not install anything, the
`crunchlock-Windows` zip contains the same programs:
- `CrunchlockGUI.exe`: the desktop app. Double-click to run.
- `crunchlock.exe`: the command-line tool.

The programs aren't code-signed. Windows SmartScreen may show "Windows protected your PC";
click *More info → Run anyway*. On macOS, right-click the app and choose *Open* the first
time.

## Run it on your computer (from the source code)

First install **Python 3.10 or newer**. On Windows, get it from
[python.org](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"** in the
installer. Then open a terminal in the `crunchlock` folder (the one containing
`pyproject.toml`).

**Option A: run it directly**

```bash
py -m pip install .        # Windows   (macOS/Linux: python3 -m pip install .)
crunchlock-gui             # desktop app
crunchlock --help          # command-line tool
```

If `crunchlock-gui` isn't found, run `py -m crunchlock.gui` instead (or `python3 -m crunchlock.gui`).
On Debian/Ubuntu, install Tkinter first: `sudo apt install python3-tk`.

**Option B: build your own .exe**

- On Windows, double-click `packaging\build_windows.bat`. It creates a fresh private
  environment with **exactly the package versions used for the official release**, builds the
  programs, **self-tests both**, and opens the `dist` folder containing `CrunchlockGUI.exe` and
  `crunchlock.exe`. Python 3.12 is recommended.
- On any OS, you can instead run these:
  ```bash
  pip install -r packaging/requirements-build.txt
  pip install --no-deps .
  python packaging/build.py
  ```
  The programs are written to `dist/`. On a Linux machine without a display, use
  `xvfb-run python packaging/build.py`.

If the build stops with **"BUILD FAILED THE SELF-TEST"**, the error shown above that line is
the real cause; please report it. To check any copy of the app, run
`CrunchlockGUI --self-test result.txt` (or `crunchlock --self-test`). It loads every library the
app needs and does a lock/verify/unlock round trip; `result.txt` ends with `OK` if it all works.

## Command line

```bash
# Lock a folder: you'll be asked for a password twice
crunchlock lock ~/Documents/taxes
#   wrote /home/me/Documents/taxes.clk
#   40.8 MB -> 7.9 MB  (80.5% smaller)  [compression: zstd]

crunchlock lock big-folder -c best            # smallest possible output (slower)
crunchlock lock movie.mp4 -n                  # encrypt only
crunchlock lock project/ --recovery --split 100M --pad

crunchlock info taxes.clk                     # no password needed
crunchlock rekey taxes.clk                    # change the password (asks for old + new)
crunchlock rekey taxes.clk -r bob.clkpub --no-password   # from now on only Bob's key opens it
crunchlock verify taxes.clk --list
crunchlock unlock taxes.clk -o ~/restored

crunchlock add taxes.clk receipt.pdf          # add files (asks for the password)
crunchlock add taxes.clk docs/ --replace      # replace the docs/ folder inside

crunchlock genpass                            # e.g. cartoon-expenses-babble-disdain-eardrum-accurate

# Public-key sharing: Bob makes a key pair and sends you bob.clkpub
crunchlock keygen bob                         # (Bob) -> bob.clkkey (secret) + bob.clkpub (share)
crunchlock lock report.pdf -r bob.clkpub      # (you)
crunchlock unlock report.pdf.clk -i bob.clkkey  # (Bob)

# Signatures: Alice signs; Bob only accepts the file if Alice's key signed it
crunchlock lock report.pdf --sign alice.clkkey
crunchlock unlock report.pdf.clk --signer alice.clkpub
crunchlock pubkey alice.clkkey -o alice.clkpub  # re-export an older key's public key
```

Public keys made by version 1.0.4 and later start with `clkpub2:` and include the key used to
check signatures. Older `clkpub1:` keys still work for locking, but can't check signatures; run
`crunchlock pubkey` on the private key to get the new form (the private key doesn't change).

Passwords are never accepted as command-line arguments, because those leak into shell history
and process lists. For scripts you can set `CRUNCHLOCK_PASSWORD`, but it's less safe.

Exit codes: `0` ok, `1` error, `2` wrong password or key.

## Desktop app

```bash
crunchlock-gui
```

It follows your system's light or dark mode, and you can switch with the button in the header.
**Drag and drop** files or folders onto the window to lock them. Drop a `.clk` file to unlock
it. Long operations show a progress bar with the **time left** and a **Cancel** button; cancelling
removes any partial output.

It **remembers your choices** (compression preset, theme, recovery data, padding, split
size, folders and window size) and keeps a **Recent** list of locked files on the Unlock tab.
Passwords, keyfiles and keys are never saved, and *Passphrases & keys → Forget my settings*
clears it all. On the same tab you can turn on **Check for a new version when Crunchlock
starts** (off by default); when a newer release exists, a *Get version …* button appears in the
header. Settings live in `%APPDATA%\Crunchlock` (Windows), `~/Library/Application
Support/Crunchlock` (macOS) or `~/.config/crunchlock` (Linux).

**Keyboard:** the app can be used without a mouse. Press **F1** (or click *Shortcuts*) for the
list:
- Enter locks or unlocks from a password field; Ctrl+Enter does it from anywhere on the tab.
- Esc cancels the running job.
- Ctrl+O opens files; Ctrl+Shift+O adds a folder.
- Ctrl+1/2/3 or Alt+L/U/P switch tabs, and Tab moves between fields.

Tk's screen-reader support is limited, so labels and status messages are plain text, but full
screen-reader use isn't guaranteed.

The window has three tabs:
- **Lock:** add files/folders, choose a compression preset (or switch compression off), and
  optionally shrink JPEG/PNG images losslessly or find far-apart repeats in big files. Set a
  password (with a strength meter and *Generate* button). Under *Advanced options*: keyfile,
  recipients, **signature**, padding, recovery data, splitting and secure delete.
- **Unlock:** pick a `.clk` (or `.clk.001`), then *Check only* or *Unlock*. Click **Browse
  contents…** to see what's inside and extract only the files you pick. **Change the
  password or who can open the file**, **add files to this locked file**, **check who
  signed it**, or **repair a damaged file**, in the sections of those names.
- Under *Advanced options* on the Lock tab, **Lock each item into its own .clk file** turns a
  list of files into separate locked files instead of one bundle.
- **Passphrases & keys:** a passphrase generator (copied passphrases are cleared from the
  clipboard after 30 s) and key-pair creation.

## Security model

```
files ─ tar ─▶ zstd/xz (optional) ─▶ AES-256-GCM in 1 MiB chunks ─▶ [Reed-Solomon] ─▶ .clk / .clk.001…
                                       ▲
             random 256-bit file key ──┘  wrapped by: Argon2id(password [+ keyfile])
                                                     and/or X25519 for each recipient
```

- **Encryption:** AES-256-GCM using the STREAM construction. Each 1 MiB chunk has a unique nonce
  (`7-byte random prefix ‖ 32-bit counter ‖ last-chunk flag`), and the whole header is
  authenticated with every chunk. Reordering, dropping, duplicating or truncating chunks, and
  editing the header, are all detected.
- **Passwords:** Argon2id with a random 16-byte salt. Its parameters are stored in the file, so
  old files stay readable if the defaults change. The reader caps them (4 GiB of memory,
  t ≤ 64) so a malicious file can't exhaust your machine.
- **Public keys:** X25519 with an ephemeral key per file, HKDF-SHA256, and an AES-GCM-wrapped
  file key. The file doesn't say who the recipients are. Private keys are stored encrypted
  with your passphrase (Argon2id), with permissions `0600`.
- **Signatures:** Ed25519 over a SHA-512 hash of the file's plaintext stream, stored encrypted at
  the end of the last chunk (so only people who can open the file see who signed it). The
  signing key is derived from your private key with HKDF, so existing key files can sign. A
  signature survives `rekey` (it covers the contents, not the keys); adding files removes it
  unless you sign again. With `--signer`, nothing is extracted unless the signature checks out.
- **Nothing leaves your machine.** No telemetry, no cloud. The only network access is the
  opt-in update check, which asks GitHub for the latest version number and nothing else.
- **Safe extraction.** Files are extracted into a hidden staging folder, and only moved into
  place after the *entire* file has been authenticated. Path traversal (`../`), absolute paths,
  escaping symlinks and device files are rejected (Python's tarfile `data` filter). Existing
  files are never overwritten without `--force`.
- **Changing the password** (`rekey`) creates a brand-new file key and re-encrypts every chunk
  with it. The data is not decompressed, so it's fast, roughly disk speed. The original file is
  replaced only after every chunk has been authenticated, so a wrong password, damage or
  cancelling leaves it untouched. Old passwords and keys stop working.
- **JPEG recompression** is checked file by file: each photo is converted, decoded straight
  back, and compared byte-for-byte with the original. Anything that doesn't match exactly (for
  example CMYK JPEGs) is stored unchanged.
- **PNG repacking** keeps a PNG's pixel data uncompressed (zstd/xz then pack it much better
  than the PNG's own deflate) plus the zlib settings that rebuild the original stream exactly.
  Each PNG is rebuilt and compared byte-for-byte before it's stored that way, and a CRC-32 is
  checked on unlock. It needs the standard zlib library: Python builds that use a different
  deflate (for example zlib-ng) switch the feature off, and every official download is checked
  for this. PNGs made by other encoders are stored unchanged.
- **Adding files** (`add`) decrypts the old file and streams it, plus the new items, straight
  into a new file with a new key. Nothing is unpacked to disk, and the original is replaced
  only after it has been fully authenticated. Public keys can't be read back from a file, so if
  it's shared with other people's keys you must list them again (your own key is kept).
- **Symlinks** inside a locked folder are preserved. A link that points *outside* the selection
  is stored as a copy of its target file, or skipped. Either way you get a warning, and
  `--shred` will then not delete the originals.

### Limits: please read

- **Your password is the security.** No encryption can protect a guessable password. Use
  `crunchlock genpass` or a password manager. **There is no recovery or backdoor:** if you lose
  the password, keyfile or private key, the data is gone.
- `--shred` is best-effort. SSDs (wear levelling), copy-on-write filesystems (btrfs, ZFS, APFS),
  snapshots, backups and cloud-synced folders can keep old copies. Full-disk encryption is the
  real fix there.
- `--pad` hides the exact size, but not the rough size.
- Compression reveals *something* about content through the (padded) output size. This is
  harmless for files at rest, which is what crunchlock is for.

## File format (v1)

```
"CRLK" | version u8 | flags u8 | chunk_size u32 | nonce_prefix 7B | slot_count u8 | slots…
  flags: 0x01 = may contain JPEGs stored as JPEG XL (tar PAX header CRUNCHLOCK.jxl=1,
         original size in CRUNCHLOCK.size)
         0x02 = may contain PNGs stored unpacked (CRUNCHLOCK.png=1, .size, .crc)
         0x04 = signed: the last chunk ends with Ed25519 public key 32B ‖ signature 64B
         Unknown flags are refused, so older versions never mis-extract newer files.
  password slot: 1 | t u32 | mem_kib u32 | par u8 | keyfile u8 | salt 16B | nonce 12B | wrapped_key 48B
  X25519 slot:   2 | ephemeral_pub 32B | nonce 12B | wrapped_key 48B
chunks: AES-GCM( u32 data_len ‖ data ‖ zero padding ), 16-byte tag each, last one flagged in the nonce
inner stream: algorithm byte (0 none, 1 zstd, 2 xz) ‖ compressed tar (PAX)

Optional recovery wrapper: ("CRLR" | ver | cols u16 | nsym u8 | crc32) × 3, then segments of
cols × RS(255,223) interleaved codewords (shortened in the last segment).
```

## Development

```bash
pip install -e '.[dev]'
pytest -q
```

The tests cover round trips for every combination of options; wrong passwords and keys;
tampering, truncation, chunk swaps and missing split parts; repair of injected damage;
malicious archives (path traversal, escaping symlinks); hostile KDF parameters; and the CLI.
