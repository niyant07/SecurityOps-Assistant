"""Optional desktop GUI entry point: ``python -m securityops.desktop``."""

from __future__ import annotations

import sys

from .app import run


def main() -> int:
    """Run the PySide desktop application."""
    return run()


if __name__ == "__main__":
    sys.exit(main())
