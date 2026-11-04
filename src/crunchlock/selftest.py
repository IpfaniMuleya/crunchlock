"""Built-in self-test for packaged builds: ``crunchlock --self-test [RESULT_FILE]``.

Checks that every native library actually loads inside the bundle (a broken
PyInstaller build typically fails with "DLL load failed"), then runs a small
lock -> verify -> unlock round trip. A windowed executable has no console, so
the report can be written to RESULT_FILE. Exit code 0 means everything works.

Only the standard library is imported at module level, so that import errors
in the bundle are caught and reported instead of crashing.
"""
from __future__ import annotations

import base64
import platform
import sys
import tempfile
import traceback
from pathlib import Path

# A tiny real JPEG (48x32) to prove the JPEG XL codec works.
_TINY_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAA0JCgsKCA0LCgsODg0PEyAVExISEyccHhcgLikxMC4p"
    "LSwzOko+MzZGNywtQFdBRkxOUlNSMj5aYVpQYEpRUk//2wBDAQ4ODhMREyYVFSZPNS01T09PT09P"
    "T09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0//wAARCAAgADADASIA"
    "AhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA"
    "AAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3"
    "ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWm"
    "p6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEA"
    "AwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSEx"
    "BhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElK"
    "U1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3"
    "uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDzwDFO"
    "C09ImPY1ODaW4IvGkDdkjALfjkjHH/6qAIY4WkYKilmPYDJqwkSRhftEUuJTsRlTOG7Z/X16dKrT"
    "3luLaRbcMXdioLrjCevXqePXv7Gs6gDUlt3RmBQjb146VAR2NGnTsjPCQWjdGGCT8h4OR7kqo+n4"
    "EOfrQA5JWHc1OBaXAJvFkLdnjIDfjkHPH/66pg5pwagB89nbm2ka3LB0YsA7Zynp06jj07+wrOrS"
    "jmaNgyMVYdwcGrCSpIF+0Sy4iO9FV8Zbtn9fTr1oApadAzs8xJWNEY5IPzngYHuCyn6fgC5+tSy3"
    "DuzEuTu689agJ7mgD//Z"
)


def _check_imports(report: list[str]) -> None:
    import argon2.low_level  # noqa: F401
    import cryptography
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import numpy
    import reedsolo  # noqa: F401
    import zstandard

    X25519PrivateKey.generate()
    AESGCM(AESGCM.generate_key(256)).encrypt(b"\0" * 12, b"x", None)
    report.append(f"cryptography {cryptography.__version__}, zstandard {zstandard.__version__}, "
                  f"numpy {numpy.__version__}")
    from . import jpeg
    if not jpeg.AVAILABLE:
        raise RuntimeError("JPEG XL codec (imagecodecs._jpegxl) is not available")
    if bytes(jpeg.jpegxl_decode_jpeg(jpeg.jpegxl_encode_jpeg(_TINY_JPEG))) != _TINY_JPEG:
        raise RuntimeError("JPEG XL round trip is not exact")
    report.append("JPEG XL codec OK")


def _check_round_trip(report: list[str]) -> None:
    from . import api
    with tempfile.TemporaryDirectory(prefix="crunchlock-selftest-") as tmp:
        tmp = Path(tmp)
        src = tmp / "data"
        src.mkdir()
        (src / "notes.txt").write_text("crunchlock self-test\n" * 2000)
        (src / "photo.jpg").write_bytes(_TINY_JPEG)
        out = tmp / "t.clk"
        api.lock([src], out, password="self-test-passphrase", kdf_profile="light",
                 compression="best", recovery_data=True)
        api.verify(out, password="self-test-passphrase")
        api.unlock(out, tmp / "out", password="self-test-passphrase")
        for f in src.iterdir():
            if (tmp / "out" / "data" / f.name).read_bytes() != f.read_bytes():
                raise RuntimeError(f"round trip changed {f.name}")
    report.append("lock -> verify -> unlock round trip OK")


def _check_gui(report: list[str]) -> None:
    import tkinter as tk

    from . import gui
    root = None
    if gui.TkinterDnD is not None:
        root = gui.TkinterDnD.Tk()  # loads the native tkdnd library
        report.append(f"drag and drop OK (tkdnd {getattr(root, 'TkdndVersion', '?')})")
    root = root or tk.Tk()
    try:
        root.withdraw()
        if gui.sv_ttk is not None:
            gui.sv_ttk.set_theme("light", root=root)
            report.append("theme OK")
        root.update()
    finally:
        root.destroy()


def run(gui: bool = False) -> tuple[bool, str]:
    report = [f"crunchlock self-test on Python {platform.python_version()} "
              f"({platform.architecture()[0]}, {platform.platform()})"]
    try:
        _check_imports(report)
        _check_round_trip(report)
        if gui:
            _check_gui(report)
    except BaseException:  # noqa: BLE001 - the whole point is to report anything
        report.append("FAILED:\n" + traceback.format_exc())
        return False, "\n".join(report)
    report.append("OK")
    return True, "\n".join(report)


def main(args: list[str], gui: bool = False) -> int:
    ok, text = run(gui=gui)
    if args:
        Path(args[0]).write_text(text + "\n", encoding="utf-8")
    elif sys.stdout is not None:
        print(text)
    return 0 if ok else 1
