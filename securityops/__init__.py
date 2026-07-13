"""SecurityOps Assistant — offline, local-only security assessment desktop app.

This package is organized into layers that depend only downward:

    gui  ->  plugins  ->  core / models / ai / reporting

The ``core`` layer never imports from ``gui``; this keeps business logic
testable without a running Qt application.
"""

from __future__ import annotations

__version__ = "0.1.0"
__app_name__ = "SecurityOps Assistant"

__all__ = ["__version__", "__app_name__"]
