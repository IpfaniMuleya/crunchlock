"""Tkinter desktop app for crunchlock (Sun Valley / Windows 11 style theme)."""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import traceback
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover
    tk = None

try:
    import sv_ttk
except ImportError:  # pragma: no cover - the app still works with the stock theme
    sv_ttk = None

from . import api, kdf, keys, passgen
from .cli import human
from .errors import CrunchlockError, WrongKeyError
from .shred import WARNING as SHRED_WARNING
from .split import parse_size

CLIP_CLEAR_MS = 30_000
GAP = 12

# (label, compression, level)
PRESETS = [
    ("Small: recommended (zstd 19)", "zstd", 19),
    ("Balanced: faster (zstd 9)", "zstd", 9),
    ("Fast (zstd 3)", "zstd", 3),
    ("Smallest: slower (xz)", "xz", 9),
    ("Try both, keep the smaller (slowest)", "best", None),
]
STRENGTH_COLORS = {"weak": "#d13438", "fair": "#e8a200", "strong": "#3a9a4a", "very strong": "#107c10"}


# ----------------------------------------------------------------- helpers

def windows_prefers_dark() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except OSError:
        return False


def enable_high_dpi() -> None:
    """Crisp (not blurry) text on scaled Windows displays."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # noqa: BLE001 - purely cosmetic
        pass


def open_in_file_manager(path: Path) -> None:
    path = Path(path)
    folder = path if path.is_dir() else path.parent
    try:
        if sys.platform == "win32":
            if path.exists() and not path.is_dir():
                subprocess.Popen(["explorer", "/select,", str(path)])
            else:
                os.startfile(folder)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", str(path)] if path.exists() else ["open", str(folder)])
        else:
            subprocess.Popen(["xdg-open", str(folder)])
    except OSError:
        pass


def lock_icon(size: int = 64) -> "tk.PhotoImage":
    """Draw a simple padlock icon (no image files needed)."""
    img = tk.PhotoImage(width=size, height=size)
    accent, dark = "#2b6fd6", "#1d4f9c"
    s = size / 64
    rows = []
    for y in range(size):
        row = []
        for x in range(size):
            fx, fy = x / s, y / s
            color = None
            # shackle: ring between radius 12 and 18 around (32, 26), top half only
            dx, dy = fx - 32, fy - 27
            r2 = dx * dx + dy * dy
            if fy <= 30 and 12 * 12 <= r2 <= 18 * 18:
                color = dark
            elif 14 <= fx <= 18 and 26 <= fy <= 32 or 46 <= fx <= 50 and 26 <= fy <= 32:
                color = dark
            # body: rounded rectangle 10..54 x 30..58
            if 10 <= fx <= 54 and 30 <= fy <= 58:
                cx = min(max(fx, 15), 49)
                cy = min(max(fy, 35), 53)
                if (fx - cx) ** 2 + (fy - cy) ** 2 <= 25:
                    color = accent
            # keyhole
            if (fx - 32) ** 2 + (fy - 42) ** 2 <= 16 or (30 <= fx <= 34 and 42 <= fy <= 50):
                if color == accent:
                    color = "#ffffff"
            row.append(color or "")
        rows.append(row)
    for y, row in enumerate(rows):
        for x, c in enumerate(row):
            if c:
                img.put(c, (x, y))
    return img


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


class Worker:
    """Runs a job on a background thread and reports back on the Tk thread."""

    def __init__(self, root):
        self.root = root
        self.on_progress = lambda *a: None
        self.on_done = lambda *a: None
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


# ----------------------------------------------------------------- widgets

class ScrollFrame(ttk.Frame):
    """A vertically scrollable area, so nothing is cut off on small screens."""

    def __init__(self, master):
        super().__init__(master)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        self.bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.body = ttk.Frame(self.canvas, padding=(GAP + 4, GAP, GAP + 4, GAP))
        self._win = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body.bind("<Configure>", self._update)
        self.canvas.bind("<Configure>", self._update)
        self.canvas.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self._wheel))
        self.canvas.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))

    def _update(self, _event=None):
        self.canvas.itemconfigure(self._win, width=self.canvas.winfo_width())
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        needs = self.body.winfo_reqheight() > self.canvas.winfo_height()
        if needs and not self.bar.winfo_ismapped():
            self.bar.pack(side="right", fill="y")
        elif not needs and self.bar.winfo_ismapped():
            self.bar.pack_forget()
            self.canvas.yview_moveto(0)

    def scroll_to_end(self):
        self.update_idletasks()
        self._update()
        self.canvas.yview_moveto(1.0)

    def _wheel(self, event):
        if self.bar.winfo_ismapped():
            self.canvas.yview_scroll(int(-event.delta / 120) or (-1 if event.delta > 0 else 1), "units")

    def recolor(self, bg):
        self.canvas.configure(background=bg)


def card(master, title: str, subtitle: str = "") -> ttk.Frame:
    """A titled, rounded card. Returns the inner frame to put widgets in."""
    outer = ttk.Frame(master, style="Card.TFrame", padding=(GAP + 4, GAP, GAP + 4, GAP + 2))
    outer.pack(fill="x", pady=(0, GAP))
    head = ttk.Frame(outer)
    head.pack(fill="x", pady=(0, 8))
    ttk.Label(head, text=title, style="CardTitle.TLabel").pack(side="left")
    if subtitle:
        ttk.Label(head, text=subtitle, style="Muted.TLabel").pack(side="left", padx=(10, 0), pady=(3, 0))
    inner = ttk.Frame(outer)
    inner.pack(fill="x")
    inner.header = head  # type: ignore[attr-defined]
    return inner


class StrengthBar(tk.Canvas):
    def __init__(self, master, app):
        super().__init__(master, height=6, highlightthickness=0, borderwidth=0)
        self.app = app
        self.fraction, self.color = 0.0, "#888"
        self.bind("<Configure>", lambda e: self.redraw())
        app.themed.append(self)

    def set(self, fraction: float, color: str):
        self.fraction, self.color = max(0.0, min(1.0, fraction)), color
        self.redraw()

    def redraw(self):
        self.delete("all")
        w = self.winfo_width()
        self.create_rectangle(0, 0, w, 6, fill=self.app.colors["track"], width=0)
        if self.fraction:
            self.create_rectangle(0, 0, int(w * self.fraction), 6, fill=self.color, width=0)

    def recolor(self, bg):
        self.configure(background=bg)
        self.redraw()


class PasswordBox(ttk.Frame):
    """Password (+ optional confirmation), show toggle, strength meter, generator."""

    def __init__(self, master, app, confirm: bool, label="Password", generate=True):
        super().__init__(master)
        self.app = app
        self.pw = tk.StringVar()
        self.pw2 = tk.StringVar()
        self.show = tk.BooleanVar(value=False)
        self.confirm = confirm
        ttk.Label(self, text=label, style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        self.e1 = ttk.Entry(self, textvariable=self.pw, show="•")
        self.e1.grid(row=0, column=1, sticky="we", padx=(10, 8), pady=4)
        ttk.Checkbutton(self, text="Show", variable=self.show, command=self._toggle).grid(row=0, column=2, sticky="w")
        if confirm:
            ttk.Label(self, text="Repeat", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=4)
            self.e2 = ttk.Entry(self, textvariable=self.pw2, show="•")
            self.e2.grid(row=1, column=1, sticky="we", padx=(10, 8), pady=4)
            self.match = ttk.Label(self, text="", style="Muted.TLabel")
            self.match.grid(row=1, column=2, sticky="w")
            self.bar = StrengthBar(self, app)
            self.bar.grid(row=2, column=1, sticky="we", padx=(10, 8), pady=(6, 0))
            self.rating = ttk.Label(self, text="", style="Muted.TLabel")
            self.rating.grid(row=3, column=1, sticky="w", padx=(10, 0), pady=(2, 0))
            if generate:
                ttk.Button(self, text="Generate a strong passphrase", command=self.generate).grid(
                    row=3, column=1, sticky="e", padx=(0, 8), pady=(4, 0))
            self.pw.trace_add("write", lambda *_: self._update())
            self.pw2.trace_add("write", lambda *_: self._update())
            self.after_idle(self._update)
        self.columnconfigure(1, weight=1)

    def _toggle(self):
        ch = "" if self.show.get() else "•"
        self.e1.configure(show=ch)
        if self.confirm:
            self.e2.configure(show=ch)

    def _update(self):
        pw = self.pw.get()
        bits = passgen.estimate_bits(pw)
        r = passgen.rating(bits)
        self.bar.set(bits / 90 if pw else 0, STRENGTH_COLORS[r])
        self.rating["text"] = f"{r.capitalize()} · about {bits:.0f} bits" if pw else \
            "Use 4+ random words, or click Generate"
        if self.pw2.get():
            ok = self.pw2.get() == pw
            self.match.configure(text="✓ match" if ok else "✗ different",
                                 foreground=STRENGTH_COLORS["very strong" if ok else "weak"])
        else:
            self.match.configure(text="")

    def generate(self):
        p = passgen.generate(6)
        self.pw.set(p)
        self.pw2.set(p)
        self.show.set(True)
        self._toggle()
        copy_to_clipboard(self, p)
        messagebox.showinfo("Passphrase generated",
                            f"{p}\n\nCopied to the clipboard (cleared in 30 seconds).\n\n"
                            "Write it down or save it in a password manager. "
                            "There is NO way to recover a lost password.", parent=self)

    def value(self) -> str:
        if self.confirm and self.pw.get() != self.pw2.get():
            raise CrunchlockError("the two passwords don't match")
        return self.pw.get()

    def clear(self):
        self.pw.set("")
        self.pw2.set("")


class Collapsible(ttk.Frame):
    def __init__(self, master, title: str):
        super().__init__(master)
        self.title = title
        self.open = tk.BooleanVar(value=False)
        self.toggle = ttk.Checkbutton(self, text="▸  " + title, variable=self.open,
                                      style="Toggle.TButton", command=self._flip)
        self.toggle.pack(fill="x")
        self.content = ttk.Frame(self)

    def _flip(self):
        if self.open.get():
            self.toggle.configure(text="▾  " + self.title)
            self.content.pack(fill="x", pady=(GAP, 0))
        else:
            self.toggle.configure(text="▸  " + self.title)
            self.content.pack_forget()


class Status(ttk.Frame):
    """Progress bar + message + an optional action button."""

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.bar = ttk.Progressbar(self, maximum=1000)
        self.label = ttk.Label(self, text="", wraplength=760, justify="left")
        self.action = ttk.Button(self, text="")
        self.label.pack(fill="x")

    def progress(self, stage, done, total):
        if not self.bar.winfo_ismapped():
            self.bar.pack(fill="x", pady=(0, 6), before=self.label)
        self.action.pack_forget()
        self.label.configure(style="TLabel")
        if total and stage != "deriving key":
            self.bar.configure(mode="determinate")
            self.bar.stop()
            self.bar["value"] = 1000 * done / total
            self.label["text"] = f"{stage.capitalize()}…  {100 * done / total:.0f}%  ({human(done)})"
        else:
            self.bar.configure(mode="indeterminate")
            self.bar.start(12)
            self.label["text"] = ("Securing the key… (deliberately slow, so password guessing is slow too)"
                                  if stage == "deriving key" else f"{stage.capitalize()}…")

    def show(self, text, kind="info", action=None):
        self.bar.stop()
        self.bar.pack_forget()
        style = {"ok": "Success.TLabel", "error": "Error.TLabel"}.get(kind, "TLabel")
        self.label.configure(text=text, style=style)
        self.action.pack_forget()
        if action:
            label, cb = action
            self.action.configure(text=label, command=cb)
            self.action.pack(anchor="w", pady=(6, 0))


def labeled_entry(master, row, label, var, browse=None, button="Browse…"):
    ttk.Label(master, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=4)
    ttk.Entry(master, textvariable=var).grid(row=row, column=1, sticky="we", padx=(10, 8), pady=4)
    if browse:
        ttk.Button(master, text=button, command=browse).grid(row=row, column=2, sticky="we", pady=4)
    master.columnconfigure(1, weight=1)


# --------------------------------------------------------------------- tabs

class LockTab(ScrollFrame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        b = self.body

        # Files
        files = card(b, "Files to lock", "files and folders go into one .clk")
        self.tree = ttk.Treeview(files, columns=("size",), show="tree headings", height=4,
                                 selectmode="extended")
        self.tree.heading("#0", text="Name", anchor="w")
        self.tree.heading("size", text="Size", anchor="e")
        self.tree.column("#0", stretch=True)
        self.tree.column("size", width=110, stretch=False, anchor="e")
        self.tree.grid(row=0, column=0, columnspan=4, sticky="nsew")
        self.empty = ttk.Label(files, text="Nothing added yet. Add files or a folder to get started.",
                               style="Muted.TLabel")
        self.empty.place(in_=self.tree, relx=0.5, rely=0.6, anchor="center")
        btns = ttk.Frame(files)
        btns.grid(row=1, column=0, columnspan=4, sticky="we", pady=(10, 0))
        ttk.Button(btns, text="＋  Add files", command=self.add_files).pack(side="left")
        ttk.Button(btns, text="＋  Add folder", command=self.add_folder).pack(side="left", padx=8)
        ttk.Button(btns, text="Remove", command=self.remove).pack(side="left")
        self.total = ttk.Label(btns, text="", style="Muted.TLabel")
        self.total.pack(side="right")
        files.columnconfigure(0, weight=1)
        self.paths: dict[str, str] = {}

        # Compression
        comp = card(b, "Size")
        self.compress = tk.BooleanVar(value=True)
        ttk.Checkbutton(comp, text="Compress (lossless: files come back exactly the same)",
                        variable=self.compress, style="Switch.TCheckbutton",
                        command=self._sync).grid(row=0, column=0, columnspan=2, sticky="w")
        self.preset = tk.StringVar(value=PRESETS[0][0])
        self.preset_cb = ttk.Combobox(comp, textvariable=self.preset, values=[p[0] for p in PRESETS],
                                      state="readonly", width=38)
        self.preset_cb.grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.chint = ttk.Label(comp, text="", style="Muted.TLabel")
        self.chint.grid(row=1, column=1, sticky="w", padx=10, pady=(10, 0))

        # Password
        prot = card(b, "Protection", "AES-256 encryption is always on")
        self.use_pw = tk.BooleanVar(value=True)
        self.pwbox = PasswordBox(prot, app, confirm=True)
        self.pwbox.pack(fill="x")

        # Advanced
        adv = Collapsible(b, "Advanced options")
        adv.pack(fill="x", pady=(0, GAP))
        a = adv.content
        sec = card(a, "Extra protection")
        self.keyfile = tk.StringVar()
        labeled_entry(sec, 0, "Keyfile", self.keyfile,
                      lambda: self.keyfile.set(filedialog.askopenfilename(title="Choose a keyfile")
                                               or self.keyfile.get()))
        ttk.Label(sec, text="Recipients", style="Card.TLabel").grid(row=1, column=0, sticky="nw", pady=6)
        self.recipients = ttk.Treeview(sec, show="tree", height=2)
        self.recipients.grid(row=1, column=1, sticky="we", padx=(10, 8), pady=6)
        rb = ttk.Frame(sec)
        rb.grid(row=1, column=2, sticky="n", pady=6)
        ttk.Button(rb, text="Add public key…", command=self.add_recipient).pack(fill="x")
        ttk.Button(rb, text="Remove", command=lambda: [self.recipients.delete(i) for i in
                                                        self.recipients.selection()]).pack(fill="x", pady=(6, 0))
        ttk.Checkbutton(sec, text="Also require the password (untick to unlock with private keys only)",
                        variable=self.use_pw).grid(row=2, column=1, columnspan=2, sticky="w")
        ttk.Label(sec, text="Hardening", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=(8, 4))
        self.profile = tk.StringVar(value="standard")
        ttk.Combobox(sec, textvariable=self.profile, values=["standard", "paranoid", "light"],
                     state="readonly", width=12).grid(row=3, column=1, sticky="w", padx=(10, 0), pady=(8, 4))
        self.recipient_paths: dict[str, str] = {}

        opt = card(a, "File options")
        self.pad = tk.BooleanVar()
        self.recovery = tk.BooleanVar()
        self.split = tk.BooleanVar()
        self.split_size = tk.StringVar(value="100M")
        self.shred = tk.BooleanVar()
        ttk.Checkbutton(opt, text="Hide the exact size (padding)", variable=self.pad).grid(row=0, column=0, sticky="w", pady=3)
        ttk.Checkbutton(opt, text="Add damage-recovery data (+14%)", variable=self.recovery).grid(row=0, column=1, sticky="w", pady=3, padx=(GAP, 0))
        sp = ttk.Frame(opt)
        sp.grid(row=1, column=0, sticky="w", pady=3)
        ttk.Checkbutton(sp, text="Split into parts of", variable=self.split).pack(side="left")
        ttk.Entry(sp, textvariable=self.split_size, width=7).pack(side="left", padx=6)
        ttk.Checkbutton(opt, text="Securely delete the originals afterwards", variable=self.shred).grid(row=1, column=1, sticky="w", pady=3, padx=(GAP, 0))

        # Output + action
        out = card(b, "Save as")
        self.output = tk.StringVar()
        ttk.Entry(out, textvariable=self.output).grid(row=0, column=0, sticky="we", padx=(0, 8))
        ttk.Button(out, text="Browse…", command=self.browse_output).grid(row=0, column=1)
        out.columnconfigure(0, weight=1)

        bar = ttk.Frame(b)
        bar.pack(fill="x")
        self.button = ttk.Button(bar, text="🔒   Lock", style="Accent.TButton", command=self.run, width=18)
        self.button.pack(side="right", ipady=4)
        self.status = Status(b, app)
        self.status.pack(fill="x", pady=(GAP, 0))
        self.preset_cb.bind("<<ComboboxSelected>>", lambda e: self._sync())
        self._sync()

    def _sync(self):
        on = self.compress.get()
        self.preset_cb.configure(state="readonly" if on else "disabled")
        self.chint["text"] = "" if on else "Files will only be encrypted."

    def _add(self, paths):
        for p in paths:
            if not p or p in self.paths.values():
                continue
            pp = Path(p)
            size = api.archive.total_size([pp])
            icon = "📁 " if pp.is_dir() else "📄 "
            iid = self.tree.insert("", "end", text=icon + pp.name, values=(human(size),))
            self.paths[iid] = str(pp)
        self._refresh()

    def _refresh(self):
        if self.paths:
            self.empty.place_forget()
            total = api.archive.total_size([Path(p) for p in self.paths.values()])
            self.total["text"] = f"{len(self.paths)} item(s) · {human(total)}"
            if not self.output.get():
                self.output.set(str(api.default_output([Path(p) for p in self.paths.values()])))
        else:
            self.empty.place(in_=self.tree, relx=0.5, rely=0.6, anchor="center")
            self.total["text"] = ""

    def add_files(self):
        self._add(filedialog.askopenfilenames(title="Choose files to lock"))

    def add_folder(self):
        self._add([filedialog.askdirectory(title="Choose a folder to lock")])

    def remove(self):
        for iid in self.tree.selection():
            self.tree.delete(iid)
            self.paths.pop(iid, None)
        self._refresh()

    def add_recipient(self):
        for p in filedialog.askopenfilenames(title="Recipient public keys",
                                             filetypes=[("Crunchlock public key", "*.clkpub"), ("All files", "*")]):
            try:
                pub = api.load_recipient(p)
            except CrunchlockError as e:
                messagebox.showerror("Invalid public key", str(e), parent=self)
                continue
            iid = self.recipients.insert("", "end", text=f"🔑 {Path(p).stem}  ({keys.fingerprint(pub)})")
            self.recipient_paths[iid] = p

    def browse_output(self):
        p = filedialog.asksaveasfilename(title="Save locked file as", defaultextension=".clk",
                                         filetypes=[("Crunchlock file", "*.clk")])
        if p:
            self.output.set(p)

    def run(self):
        if self.app.worker.busy:
            return
        try:
            paths = list(self.paths.values())
            if not paths:
                raise CrunchlockError("add at least one file or folder first")
            recips = [api.load_recipient(self.recipient_paths[i]) for i in self.recipients.get_children()]
            use_pw = self.use_pw.get() or not recips
            password = self.pwbox.value() if use_pw else None
            keyfile = Path(self.keyfile.get()).read_bytes() if self.keyfile.get() else None
            if use_pw and not password and keyfile is None:
                raise CrunchlockError("enter a password (or click Generate)")
            bits = passgen.estimate_bits(password or "")
            if password and passgen.rating(bits) in ("weak", "fair"):
                if not messagebox.askyesno("Weak password",
                                           f"This password looks {passgen.rating(bits)} (about {bits:.0f} bits) "
                                           "and could be guessed. Use it anyway?", parent=self):
                    return
            if self.shred.get() and not messagebox.askyesno(
                    "Delete originals?", "After the locked file is created and verified, the original "
                    f"files will be overwritten and deleted.\n\n{SHRED_WARNING}\n\nContinue?",
                    icon="warning", parent=self):
                return
            split = parse_size(self.split_size.get()) if self.split.get() else None
            _, algo, level = next(p for p in PRESETS if p[0] == self.preset.get())
            output = self.output.get() or None
            force = False
            if output and Path(output).exists():
                if not messagebox.askyesno("Replace file?", f"{output} already exists. Replace it?", parent=self):
                    return
                force = True
            kwargs = dict(password=password or None, keyfile=keyfile, recipients=recips,
                          compression=algo if self.compress.get() else "none",
                          level=level if self.compress.get() else None,
                          kdf_profile=self.profile.get(), pad=self.pad.get(),
                          recovery_data=self.recovery.get(), split_size=split,
                          shred_originals=self.shred.get(), force=force)
        except (CrunchlockError, OSError, ValueError) as e:
            self.status.show(f"Can't lock yet: {e}", "error")
            self.after(50, self.scroll_to_end)
            return
        self.button.state(["disabled"])
        self.app.worker.on_progress = self.status.progress
        self.app.worker.on_done = self.done
        self.app.worker.start(lambda prog: api.lock(paths, output, progress=prog, **kwargs))
        self.after(150, self.scroll_to_end)

    def done(self, result, error):
        self.button.state(["!disabled"])
        if error:
            self.status.show(f"Lock failed: {error}", "error")
            self.after(50, self.scroll_to_end)
            return
        self.pwbox.clear()
        msg = (f"✓  Locked  {human(result.input_bytes)} → {human(result.output_bytes)}"
               + (f"   ({result.saved_percent:.0f}% smaller)" if result.saved_percent > 0 else ""))
        if result.compression_note:
            msg += f"\n{result.compression_note}"
        if len(result.outputs) > 1:
            msg += f"\nSaved as {len(result.outputs)} parts: {result.outputs[0].name} … {result.outputs[-1].name}"
        else:
            msg += f"\nSaved as {result.outputs[0].name}"
        for w in result.warnings:
            msg += f"\n⚠ {w}"
        if result.shredded:
            msg += "\nOriginals securely deleted."
            self.tree.delete(*self.tree.get_children())
            self.paths.clear()
            self._refresh()
        first = result.outputs[0]
        self.status.show(msg, "ok", ("Show in folder", lambda: open_in_file_manager(first)))
        self.after(50, self.scroll_to_end)


class UnlockTab(ScrollFrame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        b = self.body
        f = card(b, "Locked file")
        self.file = tk.StringVar()
        labeled_entry(f, 0, "File", self.file, self.browse)
        self.info = ttk.Label(f, text="Choose a .clk file (or the .001 part of a split file).",
                              style="Muted.TLabel")
        self.info.grid(row=1, column=1, columnspan=2, sticky="w", padx=(10, 0), pady=(0, 4))
        self.dest = tk.StringVar()
        labeled_entry(f, 2, "Extract to", self.dest,
                      lambda: self.dest.set(filedialog.askdirectory(title="Extract into") or self.dest.get()))
        self.force = tk.BooleanVar()
        ttk.Checkbutton(f, text="Replace existing files with the same name", variable=self.force).grid(
            row=3, column=1, columnspan=2, sticky="w", padx=(10, 0), pady=(4, 0))

        k = card(b, "Password")
        self.pwbox = PasswordBox(k, app, confirm=False)
        self.pwbox.pack(fill="x")

        adv = Collapsible(b, "Locked with a keyfile or a private key?")
        adv.pack(fill="x", pady=(0, GAP))
        kk = card(adv.content, "Keyfile / private key")
        self.keyfile = tk.StringVar()
        labeled_entry(kk, 0, "Keyfile", self.keyfile,
                      lambda: self.keyfile.set(filedialog.askopenfilename(title="Keyfile") or self.keyfile.get()))
        self.identity = tk.StringVar()
        labeled_entry(kk, 1, "Private key", self.identity,
                      lambda: self.identity.set(filedialog.askopenfilename(
                          title="Private key", filetypes=[("Crunchlock private key", "*.clkkey"), ("All files", "*")])
                          or self.identity.get()))
        self.idpw = PasswordBox(kk, app, confirm=False, label="Key passphrase")
        self.idpw.grid(row=2, column=0, columnspan=3, sticky="we", pady=(4, 0))

        bar = ttk.Frame(b)
        bar.pack(fill="x")
        self.unlock_btn = ttk.Button(bar, text="🔓   Unlock", style="Accent.TButton", command=self.run, width=16)
        self.unlock_btn.pack(side="right", ipady=4)
        self.verify_btn = ttk.Button(bar, text="Check only", command=lambda: self.run(verify=True))
        self.verify_btn.pack(side="right", padx=8, ipady=4)
        self.status = Status(b, app)
        self.status.pack(fill="x", pady=(GAP, 0))
        self.file.trace_add("write", lambda *_: self.show_info())

    def browse(self):
        p = filedialog.askopenfilename(title="Choose a locked file",
                                       filetypes=[("Crunchlock", "*.clk *.clk.001"), ("All files", "*")])
        if p:
            self.file.set(p)
            if not self.dest.get():
                self.dest.set(str(Path(p).parent))

    def show_info(self):
        try:
            m = api.info(self.file.get())
        except (CrunchlockError, OSError):
            self.info["text"] = "Choose a .clk file (or the .001 part of a split file)."
            return
        how = ", ".join(sorted({s["type"] for s in m["key_slots"]}))
        self.info["text"] = (f"{human(m['size'])}"
                             + (f" in {len(m['parts'])} parts" if len(m["parts"]) > 1 else "")
                             + f" · opens with: {how}"
                             + (" · has recovery data" if m["recovery_data"] else ""))

    def run(self, verify=False):
        if self.app.worker.busy:
            return
        try:
            f = self.file.get()
            if not f:
                raise CrunchlockError("choose a .clk file first")
            keyfile = Path(self.keyfile.get()).read_bytes() if self.keyfile.get() else None
            identity = (api.load_identity(self.identity.get(), self.idpw.value())
                        if self.identity.get() else None)
            password = self.pwbox.value() or None
            dest = self.dest.get() or None
            force = self.force.get()
        except WrongKeyError as e:
            self.status.show(f"Wrong private-key passphrase: {e}", "error")
            return
        except (CrunchlockError, OSError) as e:
            self.status.show(f"Can't unlock yet: {e}", "error")
            return
        for btn in (self.verify_btn, self.unlock_btn):
            btn.state(["disabled"])
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
        for btn in (self.verify_btn, self.unlock_btn):
            btn.state(["!disabled"])
        if error:
            prefix = "Wrong password or key" if isinstance(error, WrongKeyError) else "Failed"
            self.status.show(f"{prefix}: {error}", "error")
            return
        self.pwbox.clear()
        self.idpw.clear()
        repaired = (f"\nRepaired {result.repaired_bytes} damaged bytes using the recovery data."
                    if result.repaired_bytes else "")
        if verify:
            n = sum(1 for e in result.entries if not e[2])
            self.status.show(f"✓  Authentic and intact: {n} file(s), {human(result.total_bytes)}{repaired}", "ok")
        else:
            names = ", ".join(p.name for p in result.extracted)
            first = result.extracted[0] if result.extracted else Path(self.dest.get() or ".")
            self.status.show(f"✓  Unlocked: {names}{repaired}", "ok",
                             ("Show in folder", lambda: open_in_file_manager(first)))


class ToolsTab(ScrollFrame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        b = self.body
        g = card(b, "Passphrase generator", "random words are easy to type and very hard to guess")
        self.phrase = tk.StringVar()
        ttk.Entry(g, textvariable=self.phrase, state="readonly", font=("Consolas", 12)).grid(
            row=0, column=0, columnspan=4, sticky="we", pady=(0, 10))
        ttk.Label(g, text="Words", style="Card.TLabel").grid(row=1, column=0, sticky="w")
        self.words = tk.StringVar(value="6")
        sb = ttk.Spinbox(g, from_=4, to=12, textvariable=self.words, width=4, command=self.gen)
        sb.grid(row=1, column=1, sticky="w", padx=8)
        self.bits = ttk.Label(g, text="", style="Muted.TLabel")
        self.bits.grid(row=1, column=2, sticky="w")
        bb = ttk.Frame(g)
        bb.grid(row=1, column=3, sticky="e")
        ttk.Button(bb, text="New", command=self.gen).pack(side="left")
        ttk.Button(bb, text="Copy (clears in 30 s)", style="Accent.TButton",
                   command=lambda: copy_to_clipboard(self, self.phrase.get())).pack(side="left", padx=(8, 0))
        g.columnconfigure(2, weight=1)

        k = card(b, "Your key pair", "let others lock files that only you can open")
        self.kname = tk.StringVar(value=str(Path.home() / "my-crunchlock-key"))
        labeled_entry(k, 0, "Save as", self.kname, self.browse_key)
        self.kpw = PasswordBox(k, app, confirm=True, label="Passphrase")
        self.kpw.grid(row=1, column=0, columnspan=3, sticky="we", pady=(6, 0))
        ttk.Button(k, text="Create key pair", style="Accent.TButton", command=self.keygen).grid(
            row=2, column=2, sticky="e", pady=(10, 0))
        self.pub = tk.StringVar()
        self.pub_row = ttk.Frame(k)
        ttk.Entry(self.pub_row, textvariable=self.pub, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(self.pub_row, text="Copy public key",
                   command=lambda: self.clipboard_put(self.pub.get())).pack(side="left", padx=(8, 0))

        n = card(b, "How your files are protected")
        ttk.Label(n, style="Card.TLabel", justify="left", wraplength=640, text=(
            "•  AES-256-GCM encryption; any change to a locked file is detected.\n"
            "•  Passwords are hardened with Argon2id: every guess costs hundreds of MB of memory.\n"
            "•  File names and sizes are hidden inside the encryption.\n"
            "•  No backdoor and no password reset: if you lose the password, key or keyfile, "
            "the data cannot be recovered."
        )).pack(fill="x")
        self.gen()

    def clipboard_put(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def gen(self):
        try:
            n = max(4, min(12, int(self.words.get() or 6)))
        except ValueError:
            n = 6
        self.phrase.set(passgen.generate(n))
        self.bits["text"] = f"about {passgen.passphrase_bits(n):.0f} bits"

    def browse_key(self):
        p = filedialog.asksaveasfilename(title="Key pair name")
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
                    "Replace key?", f"{priv.name} already exists. Replace it?", parent=self):
                return
        except CrunchlockError as e:
            messagebox.showerror("Can't create key", str(e), parent=self)
            return
        self.app.worker.on_progress = lambda *a: None

        def job(_prog):
            ident = keys.generate_identity()
            data = keys.save_private_key(ident, pw, kdf.PROFILES["standard"])
            fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            pubf.write_text(keys.public_key_to_text(ident.public) + "\n")
            return ident

        def done(ident, error):
            if error:
                messagebox.showerror("Can't create key", str(error), parent=self)
                return
            self.kpw.clear()
            self.pub.set(keys.public_key_to_text(ident.public))
            self.pub_row.grid(row=3, column=0, columnspan=3, sticky="we", pady=(10, 0))
            messagebox.showinfo("Key pair created",
                                f"Private key: {priv}\nKeep it secret and back it up.\n\n"
                                f"Public key: {pubf}\nShare it with people who send you files.\n\n"
                                f"Fingerprint: {keys.fingerprint(ident.public)}", parent=self)

        self.app.worker.on_done = done
        self.app.worker.start(job)


# ---------------------------------------------------------------------- app

class App:
    def __init__(self, root, dark: bool | None = None):
        self.root = root
        self.themed: list = []
        self.colors: dict = {}
        root.title("Crunchlock")
        try:
            self._icon = lock_icon(64)
            root.iconphoto(True, self._icon)
        except tk.TclError:
            pass
        self.dark = windows_prefers_dark() if dark is None else dark
        self._apply_theme()
        self.worker = Worker(root)

        header = ttk.Frame(root, padding=(GAP + 8, GAP + 2, GAP + 8, 4))
        header.pack(fill="x")
        ttk.Label(header, text="Crunchlock", style="AppTitle.TLabel").pack(side="left")
        ttk.Label(header, text="Make files smaller and lock them with a password",
                  style="Muted.TLabel").pack(side="left", padx=(12, 0), pady=(8, 0))
        self.mode_btn = ttk.Button(header, text="", command=self.toggle_theme, width=10)
        self.mode_btn.pack(side="right")
        self._mode_text()

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=GAP, pady=(4, GAP))
        self.lock_tab = LockTab(nb, self)
        self.unlock_tab = UnlockTab(nb, self)
        self.tools_tab = ToolsTab(nb, self)
        nb.add(self.lock_tab, text="  Lock  ")
        nb.add(self.unlock_tab, text="  Unlock  ")
        nb.add(self.tools_tab, text="  Passphrases & keys  ")
        self.notebook = nb
        self.themed += [self.lock_tab, self.unlock_tab, self.tools_tab]
        self._recolor()

        w = min(860, int(root.winfo_screenwidth() * 0.9))
        h = min(900, int(root.winfo_screenheight() * 0.88))
        root.geometry(f"{w}x{h}")
        root.minsize(640, 480)

    def _apply_theme(self):
        style = ttk.Style(self.root)
        if sv_ttk is not None:
            sv_ttk.set_theme("dark" if self.dark else "light", root=self.root)
        else:
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
            if not style.layout("Card.TFrame"):
                style.layout("Card.TFrame", style.layout("TFrame"))
        bg = style.lookup("TFrame", "background") or ("#1c1c1c" if self.dark else "#fafafa")
        muted = "#9a9a9a" if self.dark else "#6b6b6b"
        self.colors = {
            "bg": bg,
            "muted": muted,
            "track": "#3a3a3a" if self.dark else "#e3e3e3",
            "ok": "#6ccb5f" if self.dark else "#0f7b0f",
            "error": "#ff99a4" if self.dark else "#c42b1c",
        }
        base = ("Segoe UI", "Helvetica", "Arial")[0 if sys.platform == "win32" else 1]
        style.configure("AppTitle.TLabel", font=(base, 20, "bold"))
        style.configure("CardTitle.TLabel", font=(base, 12, "bold"))
        style.configure("Muted.TLabel", foreground=muted)
        style.configure("Success.TLabel", foreground=self.colors["ok"])
        style.configure("Error.TLabel", foreground=self.colors["error"])
        style.configure("Treeview", rowheight=28)
        if sv_ttk is None:
            style.configure("Card.TLabel")

    def _recolor(self):
        for w in self.themed:
            w.recolor(self.colors["bg"])

    def _mode_text(self):
        self.mode_btn.configure(text="☀  Light" if self.dark else "☾  Dark")

    def toggle_theme(self):
        self.dark = not self.dark
        self._apply_theme()
        self._mode_text()
        self._recolor()


def main(argv=None) -> int:
    # In a windowed executable (no console) stdout/stderr may be None.
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w"))
    if tk is None:
        print("crunchlock-gui needs Tkinter (e.g. `sudo apt install python3-tk`).", file=sys.stderr)
        return 1
    enable_high_dpi()
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
