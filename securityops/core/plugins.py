"""Modular plugin architecture.

A *plugin* contributes one feature area to the application — typically a tab in
the main window. Plugins subclass :class:`PluginBase`, declare metadata, and
build their widget on demand. The :class:`PluginManager` discovers plugin
modules inside the :mod:`securityops.plugins` package (any module exposing a
``PLUGIN`` attribute or a ``get_plugin()`` factory) and orders them by priority.

Core stays GUI-agnostic: :meth:`PluginBase.create_widget` is typed to return
``Any`` so this module need not import Qt.
"""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterable

from .context import AppContext
from .logging_config import get_logger

_LOG = get_logger("plugins")


@dataclass(frozen=True)
class PluginMeta:
    """Descriptive metadata for a plugin."""

    identifier: str          # unique, e.g. "tool_launcher"
    title: str               # tab label, e.g. "Tools"
    description: str = ""
    icon: str = ""           # optional theme icon name
    priority: int = 100      # lower sorts earlier (leftmost tab)


class PluginBase(ABC):
    """Base class all feature plugins inherit from."""

    #: Subclasses must override with a :class:`PluginMeta`.
    meta: PluginMeta

    def __init__(self, context: AppContext) -> None:
        self.context = context
        self.log = get_logger(f"plugin.{self.meta.identifier}")

    @abstractmethod
    def create_widget(self) -> Any:
        """Return the QWidget for this plugin's tab (built lazily)."""

    def on_project_changed(self, project_id: int | None) -> None:
        """Hook called when the active project changes. Override if needed."""

    def shutdown(self) -> None:
        """Hook called on application exit. Override to release resources."""


class PluginManager:
    """Discovers, instantiates, and holds feature plugins."""

    def __init__(self, context: AppContext) -> None:
        self._context = context
        self._plugins: list[PluginBase] = []

    def discover(self, package_name: str = "securityops.plugins") -> list[PluginBase]:
        """Import every submodule of *package_name* and collect its plugins."""
        try:
            package = importlib.import_module(package_name)
        except ModuleNotFoundError:
            _LOG.warning("Plugin package %s not found", package_name)
            return []

        found: list[PluginBase] = []
        for module_info in pkgutil.iter_modules(package.__path__):
            if module_info.name.startswith("_"):
                continue
            full_name = f"{package_name}.{module_info.name}"
            try:
                plugin = self._load_module(full_name)
            except Exception as exc:  # noqa: BLE001 - a bad plugin must not crash the app
                _LOG.exception("Failed to load plugin %s: %s", full_name, exc)
                continue
            if plugin is not None:
                found.append(plugin)

        found.sort(key=lambda p: (p.meta.priority, p.meta.title))
        self._plugins = found
        _LOG.info("Loaded %d plugin(s): %s", len(found), [p.meta.identifier for p in found])
        return found

    def _load_module(self, full_name: str) -> PluginBase | None:
        module = importlib.import_module(full_name)

        factory = getattr(module, "get_plugin", None)
        if callable(factory):
            return factory(self._context)  # type: ignore[no-any-return]

        plugin_cls = getattr(module, "PLUGIN", None)
        if plugin_cls is None:
            _LOG.debug("Module %s exposes no PLUGIN/get_plugin; skipping", full_name)
            return None
        if isinstance(plugin_cls, type) and issubclass(plugin_cls, PluginBase):
            return plugin_cls(self._context)

        _LOG.warning("Module %s PLUGIN is not a PluginBase subclass", full_name)
        return None

    # -- access ----------------------------------------------------------- #
    def plugins(self) -> list[PluginBase]:
        return list(self._plugins)

    def notify_project_changed(self, project_id: int | None) -> None:
        for plugin in self._plugins:
            try:
                plugin.on_project_changed(project_id)
            except Exception:  # noqa: BLE001
                self._safe_log(plugin, "on_project_changed")

    def shutdown_all(self) -> None:
        for plugin in self._plugins:
            try:
                plugin.shutdown()
            except Exception:  # noqa: BLE001
                self._safe_log(plugin, "shutdown")

    @staticmethod
    def _safe_log(plugin: PluginBase, hook: str) -> None:
        _LOG.exception("Plugin %s failed during %s", plugin.meta.identifier, hook)


def load_plugins(context: AppContext, package_name: str = "securityops.plugins") -> Iterable[PluginBase]:
    """Convenience wrapper returning discovered plugins for *context*."""
    manager = PluginManager(context)
    return manager.discover(package_name)
