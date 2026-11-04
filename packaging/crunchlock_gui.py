"""PyInstaller entry point for the desktop app."""
import sys

from crunchlock.gui import main

if __name__ == "__main__":
    sys.exit(main())
