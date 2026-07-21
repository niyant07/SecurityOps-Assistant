"""Application bootstrap.

Wires the core services into an :class:`AppContext`, applies the theme, and
shows the main window. Kept separate from ``__main__`` so it can be imported and
driven by tests or alternative front-ends.
"""

from __future__ import annotations

import sys

from .core import config as config_mod
from .core import paths
from .core.context import AppContext
from .core.database import Database
from .core.logging_config import configure_logging, get_logger
from .core.tasks import TaskManager
from .core.tools import ToolRegistry


def build_context() -> AppContext:
    """Construct the fully-wired application context (headless-safe)."""
    cfg = config_mod.load_config()
    configure_logging(cfg.section("logging"))
    log = get_logger("app")

    config_mod.write_default_user_config()

    db_name = cfg.get("database.filename", "securityops.db")
    db_path = ":memory:" if db_name == ":memory:" else paths.data_dir() / db_name
    database = Database(db_path)

    tools = ToolRegistry(extra_paths=list(cfg.get("tools.extra_paths", []) or []))
    tasks = TaskManager()

    context = AppContext(config=cfg, database=database, tasks=tasks, tools=tools)

    if cfg.get("assistant.enabled", True):
        from .ai import Assistant  # lazy import keeps core import-light

        context.assistant = Assistant(tools=tools)

    if cfg.get("llm.enabled", True):
        from .ai.llm import LLMConfig, LocalLLM  # lazy import

        context.llm = LocalLLM(LLMConfig(
            host=str(cfg.get("llm.host", "http://localhost:11434")),
            model=str(cfg.get("llm.model", "llama3")),
        ))

    log.info("Application context built (%d tools detected)", len(tools.installed()))
    return context


def run() -> int:
    """Launch the GUI application. Returns the process exit code."""
    # Qt imports are deferred so headless tooling can import build_context freely.
    from PySide6.QtWidgets import QApplication

    from .gui.main_window import MainWindow
    from .gui.theme import apply_theme

    context = build_context()

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("SecurityOps Assistant")
    apply_theme(app, str(context.config.get("ui.theme", "dark")))

    window = MainWindow(context)
    window.show()
    return app.exec()
