"""PyInstaller entry point for the desktop app.

`CrunchlockGUI --self-test RESULT_FILE` checks the bundle instead of opening a window.
"""
import sys

if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        from crunchlock.selftest import main as selftest
        sys.exit(selftest(sys.argv[2:], gui=True))
    from crunchlock.gui import main
    sys.exit(main())
