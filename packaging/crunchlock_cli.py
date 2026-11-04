"""PyInstaller entry point for the command-line tool.

`crunchlock --self-test [RESULT_FILE]` checks the bundle.
"""
import sys

if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        from crunchlock.selftest import main as selftest
        sys.exit(selftest(sys.argv[2:], gui=False))
    from crunchlock.cli import main
    sys.exit(main())
