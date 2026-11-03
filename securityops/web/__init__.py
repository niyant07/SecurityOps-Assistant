"""Loopback-only browser interface for SecurityOps Assistant.

* :mod:`.server` — the HTTP server, loopback/CSRF protections, static files
* :mod:`.state`  — the current assessment (runs steps in background threads)
* :mod:`.api`    — the JSON endpoints used by the single assessment screen
"""

from __future__ import annotations

from .server import _make_handler, main
from .state import AssessmentSession

__all__ = ["AssessmentSession", "_make_handler", "main"]
