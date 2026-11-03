"""Console entry point: ``python -m securityops``."""

from __future__ import annotations

import sys


def main() -> int:
    """Run the local browser application."""
    from .web import main as web_main

    return web_main()


if __name__ == "__main__":
    sys.exit(main())
