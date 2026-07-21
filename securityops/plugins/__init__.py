"""Built-in feature plugins.

Each module in this package exposes either a ``PLUGIN`` class (a
:class:`~securityops.core.plugins.PluginBase` subclass) or a ``get_plugin(context)``
factory. The :class:`~securityops.core.plugins.PluginManager` discovers them
automatically at startup and orders them by ``meta.priority``.

Third-party plugins can be added by dropping a module here (or extending the
discovery package), without modifying the core or GUI.
"""

from __future__ import annotations

__all__: list[str] = []
