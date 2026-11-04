"""Build standalone executables with PyInstaller.

    pip install -r packaging/requirements-build.txt     # the exact versions CI uses
    pip install --no-deps .
    python packaging/build.py [--skip-self-test]

Produces, in dist/:
  crunchlock[.exe]      command-line tool
  CrunchlockGUI[.exe]   desktop app (no console window)

PyInstaller can't cross-compile: run this on Windows to get .exe files, on macOS
for macOS binaries, and so on. The GitHub Actions workflow does all three.

After building, both programs are started with --self-test, which loads every
native library inside the bundle and does a lock/verify/unlock round trip. A
broken build therefore fails here, with the real error, instead of on a user's PC.
"""
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMON = [
    "--noconfirm", "--clean", "--onefile",
    # UPX (if installed) can corrupt compiled extensions such as cryptography's
    # _rust.pyd, giving "DLL load failed" at startup. Never use it.
    "--noupx",
    "--paths", str(ROOT / "src"),
    "--collect-data", "crunchlock",   # bundles the passphrase wordlist
    "--collect-data", "sv_ttk",       # the Windows 11 style theme
    "--hidden-import", "imagecodecs._jpegxl",  # lossless JPEG recompression
    "--hidden-import", "imagecodecs._shared",
    "--hidden-import", "imagecodecs._shared_cython",
    "--distpath", str(ROOT / "dist"),
    "--workpath", str(ROOT / "build"),
    "--specpath", str(ROOT / "build"),
]


def run(*args: str) -> None:
    cmd = [sys.executable, "-m", "PyInstaller", *COMMON, *args]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def icon_args() -> list[str]:
    """Generate the app icon (needs Pillow); skipped quietly if Pillow is missing."""
    try:
        sys.path.insert(0, str(ROOT / "packaging"))
        import make_icon
    except ImportError:
        print("Pillow not installed: building without a custom icon")
        return []
    make_icon.main(str(ROOT / "build" / "icons"))
    ico = ROOT / "build" / "icons" / ("crunchlock.ico" if sys.platform != "darwin" else "crunchlock.png")
    return ["--icon", str(ico)]


def diagnostics() -> None:
    from importlib.metadata import PackageNotFoundError, version
    print(f"Python {platform.python_version()} ({platform.architecture()[0]}) at {sys.executable}")
    for pkg in ("pyinstaller", "pyinstaller-hooks-contrib", "cryptography", "imagecodecs",
                "numpy", "zstandard", "sv-ttk", "tkinterdnd2"):
        try:
            print(f"  {pkg} {version(pkg)}")
        except PackageNotFoundError:
            print(f"  {pkg} NOT INSTALLED")
    if sys.version_info[:2] != (3, 12):
        print("  note: release builds use Python 3.12; other versions are not tested")


def self_test(exe: Path, gui: bool) -> bool:
    exe = exe.with_suffix(".exe") if sys.platform == "win32" else exe
    with tempfile.TemporaryDirectory() as tmp:
        result = Path(tmp) / "result.txt"
        try:
            proc = subprocess.run([str(exe), "--self-test", str(result)], timeout=300)
            code = proc.returncode
        except (OSError, subprocess.TimeoutExpired) as e:
            code, text = -1, f"could not run: {e}"
        else:
            text = result.read_text("utf-8") if result.exists() else "(no result written)"
    status = "OK" if code == 0 else f"FAILED (exit {code})"
    print(f"\nSelf-test {exe.name}: {status}\n" + "\n".join("  " + ln for ln in text.splitlines()))
    return code == 0


def main() -> None:
    diagnostics()
    icon = icon_args()
    run("--name", "crunchlock", "--console", *icon, str(ROOT / "packaging" / "crunchlock_cli.py"))
    run("--name", "CrunchlockGUI", "--windowed", *icon, str(ROOT / "packaging" / "crunchlock_gui.py"))
    print("\nBuilt:")
    for p in sorted((ROOT / "dist").iterdir()):
        if p.is_file():
            print(f"  {p}  ({p.stat().st_size / 1e6:.1f} MB)")
    if "--skip-self-test" in sys.argv:
        print("\n(self-test skipped)")
        return
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        print("\nNo display: run under xvfb-run to self-test the GUI, or pass --skip-self-test.")
    ok = self_test(ROOT / "dist" / "crunchlock", gui=False)
    ok = self_test(ROOT / "dist" / "CrunchlockGUI", gui=True) and ok
    if not ok:
        sys.exit("\nBUILD FAILED THE SELF-TEST: the programs above would not work. "
                 "See the error shown, and please report it.")
    print("\nBoth programs passed the self-test.")


if __name__ == "__main__":
    main()
