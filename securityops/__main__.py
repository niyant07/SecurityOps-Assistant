"""Console entry point: ``python -m securityops``."""

from __future__ import annotations

import sys


def main() -> int:
    """Run the GUI application."""
    from .app import run

    return run()


if __name__ == "__main__":
    sys.exit(main())
