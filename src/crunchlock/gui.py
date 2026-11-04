"""Tkinter desktop app for crunchlock."""
from __future__ import annotations

import os
import queue
import sys
import threading
import traceback
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover
    tk = None

from . import __version__, api, kdf, keys, passgen
from .cli import human
from .errors import CrunchlockError, WrongKeyError
from .shred import WARNING as SHRED_WARNING
from .split import parse_size

CLIP_CLEAR_MS = 30_000
PAD = {"padx": 6, "pady": 4}


class Worker:
    """Runs a job on a background thread and reports back on the Tk thread."""

    def __init__(self, root, on_progress, on_done):
        self.root, self.on_progress, self.on_done = root, on_progress, on_done
        self.q: queue.Queue = queue.Queue()
        self.busy = False

    def start(self, fn):
        self.busy = True

        def progress(stage, done, total):
            self.q.put(("progress", stage, done, total))

        def run():
            try:
                self.q.put(("done", fn(progress), None))
            except Exception as e:  # noqa: BLE001 - reported to the user
                if not isinstance(e, (CrunchlockError, OSError, ValueError)):
                    traceback.print_exc()
                self.q.put(("done", None, e))

        threading.Thread(target=run, daemon=True).start()
        self.root.after(100, self._poll)

    def _poll(self):
        last = None
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "progress":
                    last = msg
                else:
                    if last:
                        self.on_progress(*last[1:])
                    self.busy = False
                    self.on_done(msg[1], msg[2])
                    return
        except queue.Empty:
            pass
        if last:
            self.on_progress(*last[1:])
        self.root.after(100, self._poll)


class PasswordBox(ttk.Frame):
    """Password (+ optional confirmation) with show toggle and strength meter."""

    def __init__(self, master, confirm: bool, label="Password"):
        super().__init__(master)
        self.pw = tk.StringVar()
        self.pw2 = tk.StringVar()
        self.show = tk.BooleanVar(value=False)
        ttk.Label(self, text=label).grid(row=0, column=0, sticky="w")
        self.e1 = ttk.Entry(self, textvariable=self.pw, show="•", width=38)
        self.e1.grid(row=0, column=1, sticky="we", **PAD)
        ttk.Checkbutton(self, text="Show", variable=self.show, command=self._toggle).grid(row=0, column=2)
        self.confirm = confirm
        if confirm:
            ttk.Label(self, text="Repeat").grid(row=1, column=0, sticky="w")
            self.e2 = ttk.Entry(self, textvariable=self.pw2, show="•", width=38)
            self.e2.grid(row=1, column=1, sticky="we", **PAD)
            ttk.Button(self, text="Generate", command=self.generate).grid(row=1, column=2, **PAD)
            self.meter = ttk.Progressbar(self, maximum=100, length=200)
            self.meter.grid(row=2, column=1, sticky="we", padx=6)
            self.rating = ttk.Label(self, text="")
            self.rating.grid(row=2, column=2, sticky="w")
            self.pw.trace_add("write", lambda *_: self._update_strength())
        self.columnconfigure(1, weight=1)

    def _toggle(self):
        ch = "" if self.show.get() else "•"
        self.e1.configure(show=ch)
        if self.confirm:
            self.e2.configure(show=ch)

    def _update_strength(self):
        bits = passgen.estimate_bits(self.pw.get())
        self.meter["value"] = min(100, bits / 100 * 100)
        self.rating["text"] = f"{passgen.rating(bits)} (~{bits:.0f} bits)" if self.pw.get() else ""

    def generate(self):
        p = passgen.generate(6)
        self.pw.set(p)
        self.pw2.set(p)
        self.show.set(True)
        self._toggle()
        copy_to_clipboard(self, p)
        messagebox.showinfo("Passphrase generated",
                            f"{p}\n\nCopied to the clipboard (cleared in 30 s).\n"
                            "Write it down or store it in a password manager — "
                            "there is NO way to recover a lost password.", parent=self)

    def value(self) -> str:
        if self.confirm and self.pw.get() != self.pw2.get():
            raise CrunchlockError("passwords do not match")
        return self.pw.get()

    def clear(self):
        self.pw.set("")
        self.pw2.set("")


def copy_to_clipboard(widget, text: str) -> None:
    root = widget.winfo_toplevel()
    root.clipboard_clear()
    root.clipboard_append(text)

    def clear():
        try:
            if root.clipboard_get() == text:
                root.clipboard_clear()
                root.clipboard_append("")
        except tk.TclError:
            pass

    root.after(CLIP_CLEAR_MS, clear)


def file_row(master, row, label, var, browse, width=48):
    ttk.Label(master, text=label).grid(row=row, column=0, sticky="w", **PAD)
    ttk.Entry(master, textvariable=var, width=width).grid(row=row, column=1, sticky="we", **PAD)
    ttk.Button(master, text="Browse…", command=browse).grid(row=row, column=2, **PAD)


class StatusBar(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.bar = ttk.Progressbar(self, maximum=1000)
        self.bar.pack(fill="x", padx=6, pady=(6, 2))
        self.label = ttk.Label(self, text="Ready", wraplength=640, justify="left")
        self.label.pack(fill="x", padx=6, pady=(0, 6))

    def progress(self, stage, done, total):
        if total and stage not in ("deriving key",):
            self.bar.configure(mode="determinate")
            self.bar.stop()
            self.bar["value"] = 1000 * done / total
            self.label["text"] = f"{stage.capitalize()}… {100 * done / total:.0f}%  ({human(done)})"
        else:
            self.bar.configure(mode="indeterminate")
            self.bar.start(15)
            self.label["text"] = f"{stage.capitalize()}… (this is deliberately slow to stop password guessing)"

    def set(self, text, value=None):
        self.bar.stop()
        self.bar.configure(mode="determinate")
        if value is not None:
            self.bar["value"] = value
        self.label["text"] = text


class LockTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        # Inputs
        box = ttk.LabelFrame(self, text="1. What to lock")
        box.pack(fill="x", **PAD)
        self.inputs = tk.Listbox(box, height=4, selectmode="extended")
        self.inputs.grid(row=0, column=0, rowspan=4, sticky="nsew", **PAD)
        for i, (t, c) in enumerate([("Add files…", self.add_files), ("Add folder…", self.add_folder),
                                    ("Remove", self.remove), ("Clear", lambda: self.inputs.delete(0, "end"))]):
            ttk.Button(box, text=t, command=c).grid(row=i // 2, column=1 + i % 2, sticky="we", padx=4, pady=2)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(3, weight=1)

        # Compression
        cbox = ttk.LabelFrame(self, text="2. Compression (lossless)")
        cbox.pack(fill="x", **PAD)
        self.compress = tk.BooleanVar(value=True)
        self.algo = tk.StringVar(value="zstd")
        self.level = tk.StringVar(value="19")
        ttk.Checkbutton(cbox, text="Compress", variable=self.compress, command=self._sync).grid(row=0, column=0, **PAD)
        ttk.Label(cbox, text="Method").grid(row=0, column=1)
        self.algo_cb = ttk.Combobox(cbox, textvariable=self.algo, values=["zstd", "xz", "best"],
                                    state="readonly", width=8)
        self.algo_cb.grid(row=0, column=2, **PAD)
        self.algo_cb.bind("<<ComboboxSelected>>", lambda e: self._sync())
        ttk.Label(cbox, text="Level").grid(row=0, column=3)
        self.level_sb = ttk.Spinbox(cbox, from_=1, to=22, textvariable=self.level, width=4)
        self.level_sb.grid(row=0, column=4, **PAD)
        self.chint = ttk.Label(cbox, text="", foreground="gray")
        self.chint.grid(row=0, column=5, sticky="w", **PAD)

        # Protection
        pbox = ttk.LabelFrame(self, text="3. Protection (always AES-256 encrypted)")
        pbox.pack(fill="x", **PAD)
        self.use_pw = tk.BooleanVar(value=True)
        ttk.Checkbutton(pbox, text="Password", variable=self.use_pw).grid(row=0, column=0, sticky="nw", **PAD)
        self.pwbox = PasswordBox(pbox, confirm=True, label="")
        self.pwbox.grid(row=0, column=1, columnspan=2, sticky="we")
        self.keyfile = tk.StringVar()
        file_row(pbox, 1, "Keyfile (optional)", self.keyfile,
                 lambda: self.keyfile.set(filedialog.askopenfilename(title="Choose keyfile") or self.keyfile.get()))
        ttk.Label(pbox, text="Recipients (optional)").grid(row=2, column=0, sticky="nw", **PAD)
        self.recipients = tk.Listbox(pbox, height=2)
        self.recipients.grid(row=2, column=1, sticky="we", **PAD)
        rb = ttk.Frame(pbox)
        rb.grid(row=2, column=2)
        ttk.Button(rb, text="Add .clkpub…", command=self.add_recipient).pack(fill="x")
        ttk.Button(rb, text="Remove", command=lambda: [self.recipients.delete(i) for i in
                                                        reversed(self.recipients.curselection())]).pack(fill="x")
        ttk.Label(pbox, text="Hardening").grid(row=3, column=0, sticky="w", **PAD)
        self.profile = tk.StringVar(value="standard")
        ttk.Combobox(pbox, textvariable=self.profile, values=["standard", "paranoid", "light"],
                     state="readonly", width=10).grid(row=3, column=1, sticky="w", **PAD)
        pbox.columnconfigure(1, weight=1)

        # Options
        obox = ttk.LabelFrame(self, text="4. Options")
        obox.pack(fill="x", **PAD)
        self.pad = tk.BooleanVar()
        self.recovery = tk.BooleanVar()
        self.split = tk.BooleanVar()
        self.split_size = tk.StringVar(value="100M")
        self.shred = tk.BooleanVar()
        ttk.Checkbutton(obox, text="Hide exact size (padding)", variable=self.pad).grid(row=0, column=0, sticky="w", **PAD)
        ttk.Checkbutton(obox, text="Add damage-recovery data (+14%)", variable=self.recovery).grid(row=0, column=1, sticky="w", **PAD)
        sp = ttk.Frame(obox)
        sp.grid(row=1, column=0, sticky="w", **PAD)
        ttk.Checkbutton(sp, text="Split into parts of", variable=self.split).pack(side="left")
        ttk.Entry(sp, textvariable=self.split_size, width=7).pack(side="left", padx=4)
        ttk.Checkbutton(obox, text="Securely delete originals afterwards", variable=self.shred).grid(row=1, column=1, sticky="w", **PAD)

        out = ttk.Frame(self)
        out.pack(fill="x", **PAD)
        self.output = tk.StringVar()
        file_row(out, 0, "Save as", self.output, self.browse_output)
        out.columnconfigure(1, weight=1)
        self.button = ttk.Button(self, text="🔒  Lock", command=self.run)
        self.button.pack(pady=4)
        self.status = StatusBar(self)
        self.status.pack(fill="x")
        self._sync()

    def _sync(self):
        on = self.compress.get()
        self.algo_cb.configure(state="readonly" if on else "disabled")
        algo = self.algo.get()
        if algo == "xz":
            self.level_sb.configure(from_=0, to=9)
            if int(self.level.get() or 0) > 9:
                self.level.set("9")
        else:
            self.level_sb.configure(from_=1, to=22)
        self.level_sb.configure(state="normal" if on else "disabled")
        self.chint["text"] = {"zstd": "fast, great ratio", "xz": "slower, often smaller",
                              "best": "tries both, keeps the smaller (slowest)"}[algo] if on else \
            "files will only be encrypted"

    def _add(self, paths):
        existing = set(self.inputs.get(0, "end"))
        for p in paths:
            if p and p not in existing:
                self.inputs.insert("end", p)
        if not self.output.get() and self.inputs.size():
            items = [Path(x) for x in self.inputs.get(0, "end")]
            self.output.set(str(api.default_output(items)))

    def add_files(self):
        self._add(filedialog.askopenfilenames(title="Choose files to lock"))

    def add_folder(self):
        self._add([filedialog.askdirectory(title="Choose a folder to lock")])

    def remove(self):
        for i in reversed(self.inputs.curselection()):
            self.inputs.delete(i)

    def add_recipient(self):
        for p in filedialog.askopenfilenames(title="Recipient public keys",
                                             filetypes=[("Crunchlock public key", "*.clkpub"), ("All", "*")]):
            try:
                pub = api.load_recipient(p)
                self.recipients.insert("end", f"{keys.fingerprint(pub)}  {p}")
            except CrunchlockError as e:
                messagebox.showerror("Invalid public key", str(e), parent=self)

    def browse_output(self):
        p = filedialog.asksaveasfilename(title="Save locked file as", defaultextension=".clk",
                                         filetypes=[("Crunchlock file", "*.clk")])
        if p:
            self.output.set(p)

    def run(self):
        if self.app.worker.busy:
            return
        try:
            paths = list(self.inputs.get(0, "end"))
            if not paths:
                raise CrunchlockError("add at least one file or folder")
            password = self.pwbox.value() if self.use_pw.get() else None
            keyfile = Path(self.keyfile.get()).read_bytes() if self.keyfile.get() else None
            recips = [api.load_recipient(r.split("  ", 1)[1]) for r in self.recipients.get(0, "end")]
            if self.use_pw.get() and not password and keyfile is None:
                raise CrunchlockError("enter a password (or untick Password and add a recipient)")
            bits = passgen.estimate_bits(password or "")
            if password and passgen.rating(bits) in ("weak", "fair"):
                if not messagebox.askyesno("Weak password",
                                           f"This password looks {passgen.rating(bits)} (~{bits:.0f} bits) "
                                           "and could be guessed. Use it anyway?", parent=self):
                    return
            if self.shred.get() and not messagebox.askyesno(
                    "Delete originals?", "After the locked file is created and verified, the original "
                    f"files will be overwritten and deleted.\n\n{SHRED_WARNING}\n\nContinue?",
                    icon="warning", parent=self):
                return
            split = parse_size(self.split_size.get()) if self.split.get() else None
            level = int(self.level.get()) if self.compress.get() and self.algo.get() != "best" else None
            output = self.output.get() or None
            force = False
            if output and (Path(output).exists()):
                if not messagebox.askyesno("Overwrite?", f"{output} exists. Overwrite?", parent=self):
                    return
                force = True
            kwargs = dict(password=password or None, keyfile=keyfile, recipients=recips,
                          compression=self.algo.get() if self.compress.get() else "none",
                          level=level, kdf_profile=self.profile.get(), pad=self.pad.get(),
                          recovery_data=self.recovery.get(), split_size=split,
                          shred_originals=self.shred.get(), force=force)
        except (CrunchlockError, OSError, ValueError) as e:
            messagebox.showerror("Can't lock", str(e), parent=self)
            return
        self.button.state(["disabled"])
        self.app.worker.on_progress = self.status.progress
        self.app.worker.on_done = self.done
        self.app.worker.start(lambda prog: api.lock(paths, output, progress=prog, **kwargs))

    def done(self, result, error):
        self.button.state(["!disabled"])
        if error:
            self.status.set(f"Failed: {error}", 0)
            messagebox.showerror("Lock failed", str(error), parent=self)
            return
        self.pwbox.clear()
        msg = (f"Locked {human(result.input_bytes)} → {human(result.output_bytes)}"
               + (f"  ({result.saved_percent:.1f}% smaller)" if result.saved_percent > 0 else "")
               + f"  [compression: {result.compression}]")
        if result.compression_note:
            msg += f"\n{result.compression_note}"
        msg += "\nSaved: " + ", ".join(str(o) for o in result.outputs)
        for w in result.warnings:
            msg += f"\n⚠ {w}"
        if result.shredded:
            msg += "\nOriginals securely deleted."
            self.inputs.delete(0, "end")
        self.status.set(msg, 1000)


class UnlockTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        box = ttk.LabelFrame(self, text="Locked file")
        box.pack(fill="x", **PAD)
        self.file = tk.StringVar()
        file_row(box, 0, "File", self.file, self.browse)
        self.info = ttk.Label(box, text="", foreground="gray", justify="left")
        self.info.grid(row=1, column=1, columnspan=2, sticky="w", **PAD)
        self.dest = tk.StringVar()
        file_row(box, 2, "Extract to", self.dest,
                 lambda: self.dest.set(filedialog.askdirectory(title="Extract into") or self.dest.get()))
        box.columnconfigure(1, weight=1)

        kbox = ttk.LabelFrame(self, text="Unlock with")
        kbox.pack(fill="x", **PAD)
        self.pwbox = PasswordBox(kbox, confirm=False)
        self.pwbox.grid(row=0, column=0, columnspan=3, sticky="we", **PAD)
        self.keyfile = tk.StringVar()
        file_row(kbox, 1, "Keyfile", self.keyfile,
                 lambda: self.keyfile.set(filedialog.askopenfilename(title="Keyfile") or self.keyfile.get()))
        self.identity = tk.StringVar()
        file_row(kbox, 2, "Private key", self.identity,
                 lambda: self.identity.set(filedialog.askopenfilename(
                     title="Private key", filetypes=[("Crunchlock key", "*.clkkey"), ("All", "*")])
                     or self.identity.get()))
        self.idpw = PasswordBox(kbox, confirm=False, label="Key passphrase")
        self.idpw.grid(row=3, column=0, columnspan=3, sticky="we", **PAD)
        kbox.columnconfigure(1, weight=1)

        self.force = tk.BooleanVar()
        ttk.Checkbutton(self, text="Overwrite existing files", variable=self.force).pack(anchor="w", **PAD)
        bb = ttk.Frame(self)
        bb.pack(pady=4)
        self.verify_btn = ttk.Button(bb, text="✔  Verify only", command=lambda: self.run(verify=True))
        self.verify_btn.pack(side="left", padx=6)
        self.unlock_btn = ttk.Button(bb, text="🔓  Unlock", command=self.run)
        self.unlock_btn.pack(side="left", padx=6)
        self.status = StatusBar(self)
        self.status.pack(fill="x")
        self.file.trace_add("write", lambda *_: self.show_info())

    def browse(self):
        p = filedialog.askopenfilename(title="Choose a locked file",
                                       filetypes=[("Crunchlock", "*.clk *.clk.001"), ("All", "*")])
        if p:
            self.file.set(p)
            if not self.dest.get():
                self.dest.set(str(Path(p).parent))

    def show_info(self):
        try:
            m = api.info(self.file.get())
        except (CrunchlockError, OSError):
            self.info["text"] = ""
            return
        how = ", ".join(sorted({s["type"] for s in m["key_slots"]}))
        self.info["text"] = (f"{human(m['size'])} in {len(m['parts'])} part(s) · unlock with: {how}"
                             + (" · has recovery data" if m["recovery_data"] else ""))

    def run(self, verify=False):
        if self.app.worker.busy:
            return
        try:
            f = self.file.get()
            if not f:
                raise CrunchlockError("choose a .clk file")
            keyfile = Path(self.keyfile.get()).read_bytes() if self.keyfile.get() else None
            identity = (api.load_identity(self.identity.get(), self.idpw.value())
                        if self.identity.get() else None)
            password = self.pwbox.value() or None
            dest = self.dest.get() or None
            force = self.force.get()
        except WrongKeyError as e:
            messagebox.showerror("Wrong passphrase", str(e), parent=self)
            return
        except (CrunchlockError, OSError) as e:
            messagebox.showerror("Can't unlock", str(e), parent=self)
            return
        for b in (self.verify_btn, self.unlock_btn):
            b.state(["disabled"])
        self.app.worker.on_progress = self.status.progress
        self.app.worker.on_done = lambda r, e: self.done(r, e, verify)
        if verify:
            job = lambda prog: api.verify(f, password=password, keyfile=keyfile,  # noqa: E731
                                          identity=identity, progress=prog)
        else:
            job = lambda prog: api.unlock(f, dest, password=password, keyfile=keyfile,  # noqa: E731
                                          identity=identity, force=force, progress=prog)
        self.app.worker.start(job)

    def done(self, result, error, verify):
        for b in (self.verify_btn, self.unlock_btn):
            b.state(["!disabled"])
        if error:
            self.status.set(f"Failed: {error}", 0)
            messagebox.showerror("Wrong key" if isinstance(error, WrongKeyError) else "Failed",
                                 str(error), parent=self)
            return
        self.pwbox.clear()
        self.idpw.clear()
        repaired = (f"\nRepaired {result.repaired_bytes} damaged bytes using recovery data."
                    if result.repaired_bytes else "")
        if verify:
            n = sum(1 for e in result.entries if not e[2])
            self.status.set(f"✔ Authentic and intact: {n} file(s), {human(result.total_bytes)} "
                            f"[compression: {result.compression}]{repaired}", 1000)
        else:
            self.status.set("Extracted: " + ", ".join(str(p) for p in result.extracted) + repaired, 1000)


class ToolsTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        g = ttk.LabelFrame(self, text="Passphrase generator")
        g.pack(fill="x", **PAD)
        self.words = tk.StringVar(value="6")
        ttk.Label(g, text="Words").grid(row=0, column=0, **PAD)
        ttk.Spinbox(g, from_=4, to=12, textvariable=self.words, width=4).grid(row=0, column=1, **PAD)
        ttk.Button(g, text="Generate", command=self.gen).grid(row=0, column=2, **PAD)
        ttk.Button(g, text="Copy (clears in 30 s)", command=lambda: copy_to_clipboard(self, self.phrase.get())).grid(row=0, column=3, **PAD)
        self.phrase = tk.StringVar()
        ttk.Entry(g, textvariable=self.phrase, width=70, state="readonly").grid(row=1, column=0, columnspan=4, sticky="we", **PAD)
        self.bits = ttk.Label(g, text="", foreground="gray")
        self.bits.grid(row=2, column=0, columnspan=4, sticky="w", **PAD)

        k = ttk.LabelFrame(self, text="Key pair for sharing (others lock files for you with your public key)")
        k.pack(fill="x", **PAD)
        self.kname = tk.StringVar(value=str(Path.home() / "my-crunchlock-key"))
        file_row(k, 0, "Save as", self.kname, self.browse_key)
        self.kpw = PasswordBox(k, confirm=True, label="Passphrase")
        self.kpw.grid(row=1, column=0, columnspan=3, sticky="we", **PAD)
        ttk.Button(k, text="Create key pair", command=self.keygen).grid(row=2, column=1, **PAD)
        self.pub = tk.StringVar()
        ttk.Entry(k, textvariable=self.pub, state="readonly", width=70).grid(row=3, column=0, columnspan=2, sticky="we", **PAD)
        ttk.Button(k, text="Copy public key", command=lambda: self.clipboard_put(self.pub.get())).grid(row=3, column=2, **PAD)
        k.columnconfigure(1, weight=1)
        ttk.Label(self, foreground="gray", wraplength=640, justify="left", text=(
            "Security notes: files are encrypted with AES-256-GCM; passwords are hardened with "
            "Argon2id so each guess costs hundreds of MB of RAM. There is no backdoor and no "
            "password recovery — if you lose the password, key or keyfile, the data is gone."
        )).pack(fill="x", **PAD)
        self.gen()

    def clipboard_put(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def gen(self):
        n = int(self.words.get() or 6)
        self.phrase.set(passgen.generate(n))
        self.bits["text"] = f"~{passgen.passphrase_bits(n):.0f} bits of entropy"

    def browse_key(self):
        p = filedialog.asksaveasfilename(title="Key pair base name")
        if p:
            self.kname.set(str(Path(p).with_suffix("")))

    def keygen(self):
        try:
            pw = self.kpw.value()
            if not pw:
                raise CrunchlockError("enter a passphrase to protect the private key")
            base = Path(self.kname.get())
            priv, pubf = base.with_suffix(".clkkey"), base.with_suffix(".clkpub")
            if (priv.exists() or pubf.exists()) and not messagebox.askyesno(
                    "Overwrite?", f"{priv.name} exists. Overwrite?", parent=self):
                return
        except CrunchlockError as e:
            messagebox.showerror("Can't create key", str(e), parent=self)
            return
        self.app.worker.on_progress = lambda *a: None

        def job(_prog):
            ident = keys.generate_identity()
            data = keys.save_private_key(ident, pw, kdf.PROFILES["standard"])
            fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            pubf.write_text(keys.public_key_to_text(ident.public) + "\n")
            return ident

        def done(ident, error):
            if error:
                messagebox.showerror("Can't create key", str(error), parent=self)
                return
            self.kpw.clear()
            self.pub.set(keys.public_key_to_text(ident.public))
            messagebox.showinfo("Key pair created",
                                f"Private key: {priv}\n(keep it secret and back it up)\n\n"
                                f"Public key: {pubf}\n(share it with people who send you files)\n\n"
                                f"Fingerprint: {keys.fingerprint(ident.public)}", parent=self)

        self.app.worker.on_done = done
        self.app.worker.start(job)


class App:
    def __init__(self, root):
        self.root = root
        root.title(f"Crunchlock {__version__}")
        root.minsize(720, 640)
        root.geometry("780x820")
        try:
            ttk.Style().theme_use("clam")
        except tk.TclError:
            pass
        self.worker = Worker(root, lambda *a: None, lambda *a: None)
        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True)
        self.lock_tab = LockTab(nb, self)
        self.unlock_tab = UnlockTab(nb, self)
        self.tools_tab = ToolsTab(nb, self)
        nb.add(self.lock_tab, text="  Lock  ")
        nb.add(self.unlock_tab, text="  Unlock  ")
        nb.add(self.tools_tab, text="  Passphrases & Keys  ")
        self.notebook = nb


def main(argv=None) -> int:
    if tk is None:
        print("crunchlock-gui needs Tkinter (e.g. `sudo apt install python3-tk`).", file=sys.stderr)
        return 1
    root = tk.Tk()
    app = App(root)
    for p in (argv if argv is not None else sys.argv[1:]):
        if p.endswith(".clk") or p.endswith(".001"):
            app.unlock_tab.file.set(p)
            app.notebook.select(app.unlock_tab)
        else:
            app.lock_tab._add([os.path.abspath(p)])
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
