# crunchlock

**Lossless compression + strong encryption in one step.** Crunchlock turns files and folders
into a single small `.clk` file that can only be opened with your password (or your private
key), and restores them byte-for-byte.

- **Smaller files.** Optional lossless compression with zstd (level 19 by default) or xz, or
  `best` to try both and keep the smaller result. Text, logs, CSVs, source code and documents
  typically shrink by 75–95%. Data that is already compressed (photos, videos, zip files) is
  detected and stored as-is.
- **Hard to crack.** AES-256-GCM authenticated encryption, with passwords hardened by
  **Argon2id** (256 MiB of RAM per guess by default, or 1 GiB with `--profile paranoid`).
  Any tampering, truncation or wrong password is detected. Nothing is ever silently corrupted.
- **Private metadata.** File names, sizes and folder structure are all inside the encryption.
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

## Download (no Python needed)

Ready-to-run programs for **Windows (.exe)**, macOS and Linux are built automatically by
GitHub Actions:

- **Releases:** for each `v*` tag, the files are attached to the
  [Releases page](../../releases).
- **Latest build:** open the **Actions** tab, choose the newest *Test & build executables*
  run, and download `crunchlock-Windows` (or `-macOS` / `-Linux`) under *Artifacts*.

Each download contains:
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

- On Windows, double-click `packaging\build_windows.bat`. It sets everything up and opens the
  `dist` folder containing `CrunchlockGUI.exe` and `crunchlock.exe`.
- On any OS, you can instead run `pip install . pyinstaller` and then
  `python packaging/build.py`. The programs are written to `dist/`.

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
crunchlock verify taxes.clk --list
crunchlock unlock taxes.clk -o ~/restored

crunchlock genpass                            # e.g. cartoon-expenses-babble-disdain-eardrum-accurate

# Public-key sharing: Bob makes a key pair and sends you bob.clkpub
crunchlock keygen bob                         # (Bob) -> bob.clkkey (secret) + bob.clkpub (share)
crunchlock lock report.pdf -r bob.clkpub      # (you)
crunchlock unlock report.pdf.clk -i bob.clkkey  # (Bob)
```

Passwords are never accepted as command-line arguments, because those leak into shell history
and process lists. For scripts you can set `CRUNCHLOCK_PASSWORD`, but it's less safe.

Exit codes: `0` ok, `1` error, `2` wrong password or key.

## Desktop app

```bash
crunchlock-gui
```

The window has three tabs:
- **Lock:** add files/folders, tick or untick *Compress*, set a password (with a strength meter
  and *Generate* button), and optionally add a keyfile or recipients, padding, recovery data,
  splitting or secure delete.
- **Unlock:** pick a `.clk` (or `.clk.001`), then *Verify only* or *Unlock*.
- **Passphrases & Keys:** a passphrase generator (copied passphrases are cleared from the
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
- **Nothing leaves your machine.** No network access, no telemetry, no cloud.
- **Safe extraction.** Files are extracted into a hidden staging folder, and only moved into
  place after the *entire* file has been authenticated. Path traversal (`../`), absolute paths,
  escaping symlinks and device files are rejected (Python's tarfile `data` filter). Existing
  files are never overwritten without `--force`.
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
