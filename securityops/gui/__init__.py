"""PySide6 GUI layer.

The GUI depends on the core services through :class:`~securityops.core.context.AppContext`
and renders plugin-contributed tabs. It should never be imported by the core.
"""

from __future__ import annotations

__all__ = ["theme", "main_window"]
