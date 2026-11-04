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

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:  # noqa: BLE001 - drag and drop is optional
    TkinterDnD = None

from . import api, instance, jpeg, kdf, keys, passgen
from .settings import Settings
from .cli import human
from .errors import CancelledError, CrunchlockError, WrongKeyError
from .eta import Eta, format_eta
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
        self.cancelled = False

    def cancel(self):
        self.cancelled = True

    def start(self, fn):
        self.busy = True
        self.cancelled = False

        def progress(stage, done, total):
            if self.cancelled:
                raise CancelledError("cancelled")
            self.q.put(("progress", stage, done, total))

        def run():
            try:
                self.q.put(("done", fn(progress), None))
            except Exception as e:  # noqa: BLE001 - reported to the user
                if not isinstance(e, (CrunchlockError, OSError, ValueError, KeyboardInterrupt)):
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
        self.eta = Eta()

    def progress(self, stage, done, total):
        if not self.bar.winfo_ismapped():
            self.bar.pack(fill="x", pady=(0, 6), before=self.label)
        self.label.configure(style="TLabel")
        if not self.action.winfo_ismapped() or self.action["text"] != "Cancel":
            self.action.configure(text="Cancel", command=self._cancel, state="normal")
            self.action.pack(anchor="w", pady=(6, 0))
        if total and stage != "deriving key":
            self.bar.configure(mode="determinate")
            self.bar.stop()
            self.bar["value"] = 1000 * done / total
            left = format_eta(self.eta.update(stage, done, total))
            self.label["text"] = (f"{stage[:1].upper() + stage[1:]}…  {100 * done / total:.0f}%  "
                                  f"({human(done)})" + (f"  ·  {left}" if left else ""))
        else:
            self.bar.configure(mode="indeterminate")
            self.bar.start(12)
            self.label["text"] = ("Securing the key… (deliberately slow, so password guessing is slow too)"
                                  if stage == "deriving key" else f"{stage.capitalize()}…")

    def _cancel(self):
        self.app.worker.cancel()
        self.action.configure(text="Cancelling…", state="disabled")

    def cancelled(self):
        self.show("Cancelled. Nothing was written or changed.", "info")

    def show(self, text, kind="info", action=None):
        self.bar.stop()
        self.bar.pack_forget()
        style = {"ok": "Success.TLabel", "error": "Error.TLabel"}.get(kind, "TLabel")
        self.label.configure(text=text, style=style)
        self.action.pack_forget()
        if action:
            label, cb = action
            self.action.configure(text=label, command=cb, state="normal")
            self.action.pack(anchor="w", pady=(6, 0))


class RecipientList(ttk.Frame):
    """Public keys (.clkpub) of people who should be able to open the file."""

    def __init__(self, master):
        super().__init__(master)
        self.tree = ttk.Treeview(self, show="tree", height=2)
        self.tree.pack(side="left", fill="x", expand=True, padx=(0, 8))
        rb = ttk.Frame(self)
        rb.pack(side="left", anchor="n")
        ttk.Button(rb, text="Add public key…", command=self.add).pack(fill="x")
        ttk.Button(rb, text="Remove", command=self.remove).pack(fill="x", pady=(6, 0))
        self.paths: dict[str, str] = {}

    def add(self):
        for p in filedialog.askopenfilenames(title="Recipient public keys",
                                             filetypes=[("Crunchlock public key", "*.clkpub"), ("All files", "*")]):
            try:
                pub = api.load_recipient(p)
            except CrunchlockError as e:
                messagebox.showerror("Invalid public key", str(e), parent=self)
                continue
            iid = self.tree.insert("", "end", text=f"🔑 {Path(p).stem}  ({keys.fingerprint(pub)})")
            self.paths[iid] = p

    def remove(self):
        for iid in self.tree.selection():
            self.tree.delete(iid)
            self.paths.pop(iid, None)

    def keys(self):
        return [api.load_recipient(self.paths[i]) for i in self.tree.get_children()]


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
        self.empty = ttk.Label(files, text=("Drag files or folders here, or use the buttons below."
                                            if TkinterDnD else
                                            "Nothing added yet. Add files or a folder to get started."),
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
        self.jpeg = tk.BooleanVar(value=jpeg.AVAILABLE)
        self.jpeg_cb = ttk.Checkbutton(
            comp, variable=self.jpeg,
            text="Shrink JPEG photos losslessly (about 20% smaller, restored byte-for-byte)")
        self.jpeg_cb.grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))

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
        self.recipients = RecipientList(sec)
        self.recipients.grid(row=1, column=1, columnspan=2, sticky="we", padx=(10, 0), pady=6)
        ttk.Checkbutton(sec, text="Also require the password (untick to unlock with private keys only)",
                        variable=self.use_pw).grid(row=2, column=1, columnspan=2, sticky="w")
        ttk.Label(sec, text="Hardening", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=(8, 4))
        self.profile = tk.StringVar(value="standard")
        ttk.Combobox(sec, textvariable=self.profile, values=["standard", "paranoid", "light"],
                     state="readonly", width=12).grid(row=3, column=1, sticky="w", padx=(10, 0), pady=(8, 4))

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
        self.each = tk.BooleanVar()
        ttk.Checkbutton(opt, text="Lock each item into its own .clk file (instead of one bundle)",
                        variable=self.each, command=self._sync_output).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=3)

        # Output + action
        out = card(b, "Save as")
        self.out_title = out.header.winfo_children()[0]
        self.out_hint = ttk.Label(out, text="", style="Muted.TLabel")
        self.out_hint.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
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
        self.jpeg_cb.state(["!disabled"] if on and jpeg.AVAILABLE else ["disabled"])
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
            if not self.output.get() and not getattr(self, "each", tk.BooleanVar()).get():
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

    def _sync_output(self):
        if self.each.get():
            self.out_title.configure(text="Save to folder")
            self.out_hint.configure(text="Each item becomes <name>.clk. Leave empty to save each "
                                         "one next to the original.")
            self.output.set(self.app.settings.get("save_dir") if hasattr(self.app, "settings") else "")
        else:
            self.out_title.configure(text="Save as")
            self.out_hint.configure(text="")
            self._refresh()

    def browse_output(self):
        if self.each.get():
            p = filedialog.askdirectory(title="Save the locked files in",
                                        initialdir=self.output.get() or None)
            if p:
                self.output.set(p)
                self.app.settings.set("save_dir", p)
                self.app.settings.save()
            return
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
            recips = self.recipients.keys()
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
            each = self.each.get()
            if each:
                dests = [(Path(output) if output else Path(p).parent) / (Path(p).name + api.EXT)
                         for p in paths]
                existing = [d.name for d in dests if d.exists()]
                if existing and not messagebox.askyesno(
                        "Replace files?", "These already exist and will be replaced:\n"
                        + "\n".join(existing[:10]), parent=self):
                    return
                force = bool(existing)
            elif output and Path(output).exists():
                if not messagebox.askyesno("Replace file?", f"{output} already exists. Replace it?", parent=self):
                    return
                force = True
            kwargs = dict(password=password or None, keyfile=keyfile, recipients=recips,
                          compression=algo if self.compress.get() else "none",
                          level=level if self.compress.get() else None,
                          kdf_profile=self.profile.get(), pad=self.pad.get(),
                          recovery_data=self.recovery.get(), split_size=split,
                          shred_originals=self.shred.get(), force=force, jpeg=self.jpeg.get())
        except (CrunchlockError, OSError, ValueError) as e:
            self.status.show(f"Can't lock yet: {e}", "error")
            self.after(50, self.scroll_to_end)
            return
        self.button.state(["disabled"])
        self.app.worker.on_progress = self.status.progress
        self.app.worker.on_done = self.done
        if each:
            self.app.worker.start(lambda prog: api.lock_each(paths, output, progress=prog, **kwargs))
        else:
            self.app.worker.start(lambda prog: api.lock(paths, output, progress=prog, **kwargs))
        self.after(150, self.scroll_to_end)

    def done(self, result, error):
        self.button.state(["!disabled"])
        finished = getattr(error, "done", None) or []
        if isinstance(error, CancelledError):
            if finished:
                self.status.show(f"Cancelled after {len(finished)} item(s); those were kept, "
                                 "the one in progress was not written.", "info")
            else:
                self.status.cancelled()
            return
        if error:
            extra = f" ({len(finished)} item(s) before it were locked and kept)" if finished else ""
            self.status.show(f"Lock failed: {error}{extra}", "error")
            self.after(50, self.scroll_to_end)
            return
        self.pwbox.clear()
        outs = [r.outputs[0] for r in result] if isinstance(result, list) else [result.outputs[0]]
        for o in outs:
            self.app.settings.add_recent(o)
        self.app.settings.save()
        if isinstance(result, list):
            self._done_each(result)
            return
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


    def _done_each(self, results):
        total_in = sum(r.input_bytes for r in results)
        total_out = sum(r.output_bytes for r in results)
        saved = 100 * (1 - total_out / total_in) if total_in else 0
        msg = (f"✓  Locked {len(results)} item(s) separately  {human(total_in)} → {human(total_out)}"
               + (f"   ({saved:.0f}% smaller)" if saved > 0 else ""))
        for r in results[:8]:
            msg += f"\n  {r.outputs[0].name}  ({human(r.output_bytes)})"
        if len(results) > 8:
            msg += f"\n  … and {len(results) - 8} more"
        for w in [w for r in results for w in r.warnings]:
            msg += f"\n⚠ {w}"
        if any(r.shredded for r in results):
            msg += "\nOriginals securely deleted."
            self.tree.delete(*self.tree.get_children())
            self.paths.clear()
            self._refresh()
        first = results[0].outputs[0]
        self.status.show(msg, "ok", ("Show in folder", lambda: open_in_file_manager(first)))
        self.after(50, self.scroll_to_end)


class ContentsDialog(tk.Toplevel):
    """Shows the files inside a locked file and lets the user extract some of them."""

    def __init__(self, tab, entries):
        super().__init__(tab)
        self.tab = tab
        self.title("Contents")
        self.transient(tab.winfo_toplevel())
        self.geometry("620x480")
        body = ttk.Frame(self, padding=GAP)
        body.pack(fill="both", expand=True)
        files = [e for e in entries if not e[2]]
        ttk.Label(body, text=f"{len(files)} file(s), {human(sum(e[1] for e in files))}. "
                             "Select files or folders (Ctrl/Shift-click for several).",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        frame = ttk.Frame(body)
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=("size",), selectmode="extended")
        self.tree.heading("#0", text="Name", anchor="w")
        self.tree.heading("size", text="Size", anchor="e")
        self.tree.column("size", width=100, stretch=False, anchor="e")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._fill(entries)
        bar = ttk.Frame(body)
        bar.pack(fill="x", pady=(GAP, 0))
        ttk.Button(bar, text="Extract selected", style="Accent.TButton",
                   command=self.extract_selected).pack(side="right")
        ttk.Button(bar, text="Extract everything", command=self.extract_all).pack(side="right", padx=8)
        ttk.Button(bar, text="Close", command=self.destroy).pack(side="left")
        self.configure(background=tab.app.colors["bg"])

    def _fill(self, entries):
        def ensure(path: str):
            if not path or self.tree.exists(path):
                return
            parent = path.rsplit("/", 1)[0] if "/" in path else ""
            ensure(parent)
            self.tree.insert(parent, "end", iid=path, text="📁 " + path.rsplit("/", 1)[-1], open=False)
        for name, size, is_dir in entries:
            name = name.rstrip("/")
            if is_dir:
                ensure(name)
                continue
            parent = name.rsplit("/", 1)[0] if "/" in name else ""
            ensure(parent)
            if not self.tree.exists(name):
                self.tree.insert(parent, "end", iid=name, text="📄 " + name.rsplit("/", 1)[-1],
                                 values=(human(size),))
        for top in self.tree.get_children():
            self.tree.item(top, open=True)

    def extract_selected(self):
        chosen = list(self.tree.selection())
        if not chosen:
            messagebox.showinfo("Nothing selected", "Select one or more files or folders first.",
                                parent=self)
            return
        # Drop items already covered by a selected parent folder.
        chosen = [c for c in chosen if not any(c.startswith(o + "/") for o in chosen if o != c)]
        self.destroy()
        self.tab.run(only=chosen)

    def extract_all(self):
        self.destroy()
        self.tab.run()


class UnlockTab(ScrollFrame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        b = self.body
        f = card(b, "Locked file")
        self.recent_btn = ttk.Menubutton(f.header, text="Recent")
        self.recent_menu = tk.Menu(self.recent_btn, tearoff=False, postcommand=self._fill_recent)
        self.recent_btn["menu"] = self.recent_menu
        self.recent_btn.pack(side="right")
        self.file = tk.StringVar()
        labeled_entry(f, 0, "File", self.file, self.browse)
        self.info = ttk.Label(f, text="Choose a .clk file (or the .001 part of a split file).",
                              style="Muted.TLabel")
        self.info.grid(row=1, column=1, columnspan=2, sticky="w", padx=(10, 0), pady=(0, 4))
        self.dest = tk.StringVar()
        labeled_entry(f, 2, "Extract to", self.dest, self.browse_dest)
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
        self.browse_btn = ttk.Button(bar, text="Browse contents…", command=lambda: self.run(browse=True))
        self.browse_btn.pack(side="right", ipady=4)
        self.status = Status(b, app)
        self.status.pack(fill="x", pady=(GAP, 0))
        self.file.trace_add("write", lambda *_: self.show_info())

        change = Collapsible(b, "Change the password or who can open this file")
        change.pack(fill="x", pady=(GAP, 0))
        cc = card(change.content, "New access", "first enter the current password or key above")
        self.newpw = PasswordBox(cc, app, confirm=True, label="New password")
        self.newpw.grid(row=0, column=0, columnspan=3, sticky="we")
        ttk.Label(cc, text="Leave the new password blank to keep the current one.",
                  style="Muted.TLabel").grid(row=1, column=1, columnspan=2, sticky="w", padx=(10, 0))
        self.remove_pw = tk.BooleanVar()
        ttk.Checkbutton(cc, text="Remove the password (open only with the keyfile / public keys below)",
                        variable=self.remove_pw).grid(row=2, column=1, columnspan=2, sticky="w",
                                                      padx=(10, 0), pady=(6, 0))
        self.newkeyfile = tk.StringVar()
        labeled_entry(cc, 3, "New keyfile", self.newkeyfile,
                      lambda: self.newkeyfile.set(filedialog.askopenfilename(title="New keyfile")
                                                  or self.newkeyfile.get()))
        ttk.Label(cc, text="Recipients", style="Card.TLabel").grid(row=4, column=0, sticky="nw", pady=6)
        self.newrecips = RecipientList(cc)
        self.newrecips.grid(row=4, column=1, columnspan=2, sticky="we", padx=(10, 0), pady=6)
        self.apply_btn = ttk.Button(cc, text="Apply changes", style="Accent.TButton", command=self.rekey)
        self.apply_btn.grid(row=5, column=2, sticky="e", pady=(8, 0))

        damaged = Collapsible(b, "File damaged? Repair it")
        damaged.pack(fill="x", pady=(GAP, 0))
        dc = card(damaged.content, "Repair", "uses the file's damage-recovery data")
        ttk.Label(dc, style="Card.TLabel", justify="left", wraplength=640, text=(
            "Writes a repaired copy next to the file (name.repaired.clk); the original is not "
            "changed. No password is needed to repair. If you enter the password above, the "
            "copy is also checked. Only works for files locked with damage-recovery data."
        )).pack(fill="x")
        self.repair_btn = ttk.Button(dc, text="Repair", style="Accent.TButton", command=self.repair)
        self.repair_btn.pack(anchor="e", pady=(8, 0))

    def _current_secrets(self):
        keyfile = Path(self.keyfile.get()).read_bytes() if self.keyfile.get() else None
        identity = (api.load_identity(self.identity.get(), self.idpw.value())
                    if self.identity.get() else None)
        return self.pwbox.value() or None, keyfile, identity

    def _buttons(self, enabled: bool):
        for btn in (self.verify_btn, self.unlock_btn, self.apply_btn, self.browse_btn, self.repair_btn):
            btn.state(["!disabled"] if enabled else ["disabled"])

    def rekey(self):
        if self.app.worker.busy:
            return
        try:
            f = self.file.get()
            if not f:
                raise CrunchlockError("choose a .clk file first")
            password, keyfile, identity = self._current_secrets()
            new_pw = self.newpw.value()
            if self.remove_pw.get():
                new_pw = None
            elif not new_pw:
                new_pw = password
            new_keyfile = Path(self.newkeyfile.get()).read_bytes() if self.newkeyfile.get() else None
            recips = self.newrecips.keys()
            if not new_pw and new_keyfile is None and not recips:
                raise CrunchlockError("the file needs a password, keyfile or at least one public key")
            if new_pw and new_pw != password:
                bits = passgen.estimate_bits(new_pw)
                if passgen.rating(bits) in ("weak", "fair") and not messagebox.askyesno(
                        "Weak password", f"The new password looks {passgen.rating(bits)}. Use it anyway?",
                        parent=self):
                    return
            if not messagebox.askyesno(
                    "Change access?", f"From now on, {Path(f).name} will open ONLY with the new "
                    "settings. Old passwords/keys will stop working. Continue?", parent=self):
                return
        except WrongKeyError as e:
            self.status.show(f"Wrong private-key passphrase: {e}", "error")
            return
        except (CrunchlockError, OSError) as e:
            self.status.show(f"Can't change it yet: {e}", "error")
            return
        self._buttons(False)
        self.app.worker.on_progress = self.status.progress
        self.app.worker.on_done = self._rekey_done
        self.app.worker.start(lambda prog: api.rekey(
            f, password=password, keyfile=keyfile, identity=identity, new_password=new_pw,
            new_keyfile=new_keyfile, recipients=recips, progress=prog))

    def _rekey_done(self, result, error):
        self._buttons(True)
        if isinstance(error, CancelledError):
            self.status.cancelled()
            return
        if error:
            prefix = "Wrong password or key" if isinstance(error, WrongKeyError) else "Failed"
            self.status.show(f"{prefix}: {error}", "error")
            return
        for box in (self.pwbox, self.idpw, self.newpw):
            box.clear()
        self.remember(self.file.get())
        self.show_info()
        self.status.show(f"✓  Access updated. {Path(self.file.get()).name} now opens with: "
                         f"{result.unlock_with}", "ok")

    def _fill_recent(self):
        m = self.recent_menu
        m.delete(0, "end")
        recent = self.app.settings.recent()
        if not recent:
            m.add_command(label="No recent files yet", state="disabled")
            return
        for i, path in enumerate(recent, 1):
            p = Path(path)
            m.add_command(label=f"{i}  {p.name}   —   {p.parent}", underline=0,
                          command=lambda path=path: self.app.open_paths([path]))
        m.add_separator()
        m.add_command(label="Clear recent files", command=self._clear_recent)

    def _clear_recent(self):
        self.app.settings.clear_recent()
        self.app.settings.save()

    def remember(self, path):
        if path:
            self.app.settings.add_recent(path)
            self.app.settings.save()

    def browse_dest(self):
        p = filedialog.askdirectory(title="Extract into",
                                    initialdir=self.dest.get() or self.app.settings.get("extract_dir") or None)
        if p:
            self.dest.set(p)
            self.app.settings.set("extract_dir", p)
            self.app.settings.save()

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

    def repair(self):
        if self.app.worker.busy:
            return
        f = self.file.get()
        if not f:
            self.status.show("Choose a .clk file first.", "error")
            return
        try:
            password, keyfile, identity = self._current_secrets()
        except (CrunchlockError, OSError) as e:
            self.status.show(f"Can't repair yet: {e}", "error")
            return

        def job(prog):
            r = api.repair(f, progress=prog)
            check = None
            if r.was_damaged and (password or keyfile is not None or identity is not None):
                check = api.verify(r.outputs[0], password=password, keyfile=keyfile,
                                   identity=identity, progress=prog)
            return r, check

        self._buttons(False)
        self.app.worker.on_progress = self.status.progress
        self.app.worker.on_done = self._repair_done
        self.app.worker.start(job)

    def _repair_done(self, result, error):
        self._buttons(True)
        if isinstance(error, CancelledError):
            self.status.cancelled()
            return
        if error:
            prefix = "Wrong password or key" if isinstance(error, WrongKeyError) else "Couldn't repair"
            self.status.show(f"{prefix}: {error}", "error")
            return
        r, check = result
        if not r.was_damaged:
            self.status.show("✓  No damage found. The file is fine, so nothing was written.", "ok")
            return
        msg = f"✓  Repaired {r.repaired_bytes} damaged bytes  →  {r.outputs[0].name}"
        msg += ("\nThe repaired copy opens with your password and is authentic." if check else
                "\nEnter the password and click Check only on the repaired copy to confirm it.")
        first = r.outputs[0]
        self.file.set(str(first))
        self.remember(first)
        self.status.show(msg, "ok", ("Show in folder", lambda: open_in_file_manager(first)))

    def run(self, verify=False, browse=False, only=None):
        if self.app.worker.busy:
            return
        try:
            f = self.file.get()
            if not f:
                raise CrunchlockError("choose a .clk file first")
            password, keyfile, identity = self._current_secrets()
            dest = self.dest.get() or None
            force = self.force.get()
        except WrongKeyError as e:
            self.status.show(f"Wrong private-key passphrase: {e}", "error")
            return
        except (CrunchlockError, OSError) as e:
            self.status.show(f"Can't unlock yet: {e}", "error")
            return
        self._buttons(False)
        self.app.worker.on_progress = self.status.progress
        self.app.worker.on_done = lambda r, e: self.done(r, e, verify, browse)
        if verify or browse:
            job = lambda prog: api.verify(f, password=password, keyfile=keyfile,  # noqa: E731
                                          identity=identity, progress=prog)
        else:
            job = lambda prog: api.unlock(f, dest, password=password, keyfile=keyfile,  # noqa: E731
                                          identity=identity, force=force, only=only, progress=prog)
        self.app.worker.start(job)

    def done(self, result, error, verify, browse=False):
        self._buttons(True)
        if isinstance(error, CancelledError):
            self.status.cancelled()
            return
        if error:
            prefix = "Wrong password or key" if isinstance(error, WrongKeyError) else "Failed"
            self.status.show(f"{prefix}: {error}", "error")
            return
        self.remember(self.file.get())
        if browse:
            self.status.show("Opened. Pick what to extract in the window.", "ok")
            ContentsDialog(self, result.entries)
            return  # keep the password filled in for the extraction
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

        st = card(b, "App settings", "your choices are remembered between sessions")
        ttk.Label(st, style="Card.TLabel", justify="left", wraplength=640, text=(
            "Crunchlock remembers options like compression, theme, recovery data and folders, "
            "plus a list of recent locked files. Passwords, keyfiles and keys are never saved."
        )).pack(fill="x")
        ttk.Button(st, text="Forget my settings and recent files",
                   command=self.reset_settings).pack(anchor="e", pady=(8, 0))

        n = card(b, "How your files are protected")
        ttk.Label(n, style="Card.TLabel", justify="left", wraplength=640, text=(
            "•  AES-256-GCM encryption; any change to a locked file is detected.\n"
            "•  Passwords are hardened with Argon2id: every guess costs hundreds of MB of memory.\n"
            "•  File names and sizes are hidden inside the encryption.\n"
            "•  No backdoor and no password reset: if you lose the password, key or keyfile, "
            "the data cannot be recovered."
        )).pack(fill="x")
        self.gen()

    def reset_settings(self):
        if not messagebox.askyesno("Forget settings?",
                                   "Reset all options to their defaults and clear the recent "
                                   "files list?", parent=self):
            return
        self.app.settings.reset()
        self.app.apply_settings()
        messagebox.showinfo("Done", "Settings reset and recent files cleared.", parent=self)

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
    def __init__(self, root, dark: bool | None = None, settings: Settings | None = None):
        self.root = root
        self.settings = settings if settings is not None else Settings()
        self.themed: list = []
        self.colors: dict = {}
        root.title("Crunchlock")
        try:
            self._icon = lock_icon(64)
            root.iconphoto(True, self._icon)
        except tk.TclError:
            pass
        saved_theme = self.settings.get("theme")
        if dark is None:
            dark = (saved_theme == "dark") if saved_theme else windows_prefers_dark()
        self.dark = dark
        self._apply_theme()
        self.worker = Worker(root)

        header = ttk.Frame(root, padding=(GAP + 8, GAP + 2, GAP + 8, 4))
        header.pack(fill="x")
        ttk.Label(header, text="Crunchlock", style="AppTitle.TLabel").pack(side="left")
        ttk.Label(header, text="Make files smaller and lock them with a password",
                  style="Muted.TLabel").pack(side="left", padx=(12, 0), pady=(8, 0))
        self.mode_btn = ttk.Button(header, text="", command=self.toggle_theme, width=10)
        self.mode_btn.pack(side="right")
        ttk.Button(header, text="⌨  Shortcuts", command=self.show_shortcuts).pack(side="right", padx=(0, 8))
        self._mode_text()

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=GAP, pady=(4, GAP))
        self.lock_tab = LockTab(nb, self)
        self.unlock_tab = UnlockTab(nb, self)
        self.tools_tab = ToolsTab(nb, self)
        nb.add(self.lock_tab, text="  Lock  ", underline=2)
        nb.add(self.unlock_tab, text="  Unlock  ", underline=2)
        nb.add(self.tools_tab, text="  Passphrases & keys  ", underline=2)
        nb.enable_traversal()  # Ctrl+Tab / Ctrl+Shift+Tab, Alt+L / Alt+U / Alt+P
        self.notebook = nb
        self.themed += [self.lock_tab, self.unlock_tab, self.tools_tab]
        self._recolor()
        self.incoming: queue.Queue = queue.Queue()
        self._enable_drop(root)
        self._poll_job = root.after(200, self._poll_incoming)

        w = min(860, int(root.winfo_screenwidth() * 0.9))
        h = min(900, int(root.winfo_screenheight() * 0.88))
        geo = self.settings.get("geometry")
        root.geometry(geo if self._geometry_fits(geo) else f"{w}x{h}")
        root.minsize(640, 480)
        self.apply_settings()
        self._watch_settings()
        self._bind_keys()
        root.protocol("WM_DELETE_WINDOW", self.close)

    # -- remembered settings

    _LOCK_OPTIONS = ("compress", "jpeg", "profile", "pad", "recovery", "split", "split_size", "each")

    def _geometry_fits(self, geo) -> bool:
        try:
            size = geo.split("+")[0]
            w, h = (int(v) for v in size.split("x"))
        except (AttributeError, ValueError):
            return False
        return 640 <= w <= self.root.winfo_screenwidth() and 480 <= h <= self.root.winfo_screenheight()

    def apply_settings(self):
        st, lt = self.settings, self.lock_tab
        for name in self._LOCK_OPTIONS:
            getattr(lt, name).set(st.get(name))
        if not jpeg.AVAILABLE:
            lt.jpeg.set(False)
        idx = st.get("preset")
        lt.preset.set(PRESETS[idx][0] if 0 <= idx < len(PRESETS) else PRESETS[0][0])
        lt._sync()
        lt._sync_output()
        theme = st.get("theme")
        if theme and (theme == "dark") != self.dark:
            self.toggle_theme(save=False)

    def _watch_settings(self):
        lt = self.lock_tab
        self._save_job = None

        def changed(*_):
            st = self.settings
            for name in self._LOCK_OPTIONS:
                try:
                    st.set(name, getattr(lt, name).get())
                except tk.TclError:
                    pass
            st.set("preset", next((i for i, p in enumerate(PRESETS) if p[0] == lt.preset.get()), 0))
            if self._save_job:
                self.root.after_cancel(self._save_job)
            self._save_job = self.root.after(400, st.save)

        for name in self._LOCK_OPTIONS + ("preset",):
            getattr(lt, name).trace_add("write", changed)

    def close(self):
        try:
            self.settings.set("geometry", self.root.geometry())
            self.settings.save()
            for job in (getattr(self, "_poll_job", None), getattr(self, "_save_job", None)):
                if job:
                    self.root.after_cancel(job)
        finally:
            self.root.destroy()

    # -- keyboard

    def _current_tab(self):
        return self.root.nametowidget(self.notebook.select())

    def _primary_action(self, event=None):
        if self.worker.busy:
            return "break"
        tab = self._current_tab()
        if event is not None and event.keysym == "Return" and not (event.state & 0x4):
            focus = self.root.focus_get()
            # Plain Enter acts only from text fields / checkboxes, so it never
            # fights a focused button, list or the contents window.
            if focus is None or focus.winfo_toplevel() is not self.root or \
                    focus.winfo_class() not in ("TEntry", "Entry", "TCheckbutton", "TCombobox", "TSpinbox"):
                return None
        if tab is self.lock_tab:
            self.lock_tab.run()
        elif tab is self.unlock_tab:
            self.unlock_tab.run()
        return "break"

    def _open_shortcut(self, folder=False):
        tab = self._current_tab()
        if tab is self.unlock_tab:
            self.unlock_tab.browse()
        else:
            self.notebook.select(self.lock_tab)
            self.lock_tab.add_folder() if folder else self.lock_tab.add_files()
        return "break"

    def _escape(self, _event=None):
        if self.worker.busy:
            self.worker.cancel()
            return "break"
        return None

    def _bind_keys(self):
        r = self.root
        r.bind("<Return>", self._primary_action)
        r.bind("<KP_Enter>", self._primary_action)
        r.bind("<Control-Return>", self._primary_action)
        r.bind("<Escape>", self._escape)
        r.bind("<Control-o>", lambda e: self._open_shortcut())
        r.bind("<Control-O>", lambda e: self._open_shortcut(folder=True))  # Ctrl+Shift+O
        r.bind("<F1>", lambda e: self.show_shortcuts())
        for i, tab in enumerate((self.lock_tab, self.unlock_tab, self.tools_tab), 1):
            r.bind(f"<Control-Key-{i}>", lambda e, t=tab: (self.notebook.select(t), "break")[1])

    SHORTCUTS = [
        ("Enter", "Lock / Unlock (from a password or text field)"),
        ("Ctrl+Enter", "Lock / Unlock from anywhere on the tab"),
        ("Esc", "Cancel the running operation"),
        ("Ctrl+O", "Add files (Lock tab) or open a locked file (Unlock tab)"),
        ("Ctrl+Shift+O", "Add a folder to lock"),
        ("Ctrl+1 / 2 / 3", "Go to Lock / Unlock / Passphrases & keys"),
        ("Ctrl+Tab", "Next tab (Ctrl+Shift+Tab: previous)"),
        ("Tab / Shift+Tab", "Move between fields and buttons"),
        ("Space", "Press the focused button or tick the focused checkbox"),
        ("F1", "Show this list"),
    ]

    def show_shortcuts(self):
        win = tk.Toplevel(self.root)
        win.title("Keyboard shortcuts")
        win.transient(self.root)
        win.configure(background=self.colors["bg"])
        body = ttk.Frame(win, padding=GAP + 4)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Keyboard shortcuts", style="CardTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        for i, (keys_, what) in enumerate(self.SHORTCUTS, 1):
            ttk.Label(body, text=keys_, font=("TkFixedFont", 10, "bold")).grid(row=i, column=0, sticky="w", padx=(0, 16), pady=2)
            ttk.Label(body, text=what).grid(row=i, column=1, sticky="w", pady=2)
        close = ttk.Button(body, text="Close", command=win.destroy)
        close.grid(row=len(self.SHORTCUTS) + 1, column=1, sticky="e", pady=(GAP, 0))
        win.bind("<Escape>", lambda e: win.destroy())
        close.focus_set()
        return win

    # -- files arriving from drag and drop, the command line or other launches

    def open_paths(self, paths):
        paths = [os.path.abspath(p) for p in paths if p]
        locked = [p for p in paths if p.lower().endswith((".clk", ".clk.001"))]
        others = [p for p in paths if p not in locked]
        if locked and not others:
            self.unlock_tab.file.set(locked[0])
            if not self.unlock_tab.dest.get():
                self.unlock_tab.dest.set(str(Path(locked[0]).parent))
            self.notebook.select(self.unlock_tab)
            self.root.after(50, self.unlock_tab.pwbox.e1.focus_set)
        elif paths:
            self.lock_tab._add(paths)
            self.notebook.select(self.lock_tab)
            if not self.lock_tab.pwbox.pw.get():
                self.root.after(50, self.lock_tab.pwbox.e1.focus_set)

    def bring_to_front(self):
        r = self.root
        r.deiconify()
        r.lift()
        r.attributes("-topmost", True)
        r.after(300, lambda: r.attributes("-topmost", False))
        r.focus_force()

    def _poll_incoming(self):
        try:
            while True:
                paths = self.incoming.get_nowait()
                self.bring_to_front()
                self.open_paths(paths)
        except queue.Empty:
            pass
        self._poll_job = self.root.after(200, self._poll_incoming)

    def _enable_drop(self, root):
        if TkinterDnD is None or not hasattr(root, "drop_target_register"):
            return

        def on_drop(event):
            self.open_paths(root.tk.splitlist(event.data))
            return event.action

        def register(w):
            try:
                w.drop_target_register(DND_FILES)
                w.dnd_bind("<<Drop>>", on_drop)
            except (tk.TclError, AttributeError):
                pass
            for child in w.winfo_children():
                register(child)

        register(root)

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

    def toggle_theme(self, save: bool = True):
        self.dark = not self.dark
        self._apply_theme()
        self._mode_text()
        self._recolor()
        if save:
            self.settings.set("theme", "dark" if self.dark else "light")
            self.settings.save()


def main(argv=None) -> int:
    # In a windowed executable (no console) stdout/stderr may be None.
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w"))
    if tk is None:
        print("crunchlock-gui needs Tkinter (e.g. `sudo apt install python3-tk`).", file=sys.stderr)
        return 1
    paths = [os.path.abspath(p) for p in (argv if argv is not None else sys.argv[1:])]
    # If a window is already open, hand the files to it instead of opening another.
    single = os.environ.get("CRUNCHLOCK_MULTI_INSTANCE") != "1"
    if single and instance.hand_off_or_become_primary(paths):
        return 0
    enable_high_dpi()
    root = None
    if TkinterDnD is not None:
        try:
            root = TkinterDnD.Tk()
        except Exception:  # noqa: BLE001 - tkdnd library unavailable: no drag and drop
            root = None
    root = root or tk.Tk()
    app = App(root)
    server = None
    if single:
        try:
            server = instance.Server(app.incoming.put)
        except OSError:
            pass
        instance.release_startup_lock()
    app.open_paths(paths)
    try:
        root.mainloop()
    finally:
        if server:
            server.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
