"""Build standalone executables with PyInstaller.

    pip install pyinstaller
    python packaging/build.py

Produces, in dist/:
  crunchlock[.exe]      command-line tool
  CrunchlockGUI[.exe]   desktop app (no console window)

PyInstaller can't cross-compile: run this on Windows to get .exe files, on macOS
for macOS binaries, and so on. The GitHub Actions workflow does all three.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMON = [
    "--noconfirm", "--clean", "--onefile",
    "--paths", str(ROOT / "src"),
    "--collect-data", "crunchlock",   # bundles the passphrase wordlist
    "--distpath", str(ROOT / "dist"),
    "--workpath", str(ROOT / "build"),
    "--specpath", str(ROOT / "build"),
]


def run(*args: str) -> None:
    cmd = [sys.executable, "-m", "PyInstaller", *COMMON, *args]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main() -> None:
    run("--name", "crunchlock", "--console", str(ROOT / "packaging" / "crunchlock_cli.py"))
    run("--name", "CrunchlockGUI", "--windowed", str(ROOT / "packaging" / "crunchlock_gui.py"))
    print("\nBuilt:")
    for p in sorted((ROOT / "dist").iterdir()):
        print(f"  {p}  ({p.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
