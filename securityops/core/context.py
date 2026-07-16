"""Application context shared with plugins and GUI widgets.

The context is the single dependency-injection seam of the app: it bundles the
long-lived services so plugins never construct their own database connections or
task pools. It deliberately holds no Qt widgets, keeping it importable in
headless tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .config import Config
from .database import Database
from .tasks import TaskManager
from .tools import ToolRegistry


@dataclass
class AppContext:
    """Container for core services injected into plugins and widgets."""

    config: Config
    database: Database
    tasks: TaskManager
    tools: ToolRegistry
    # The active project id, if one is selected. Plugins read this to scope data.
    active_project_id: Optional[int] = None
    # Populated lazily to avoid a hard import cycle with the ai package.
    assistant: object | None = field(default=None)
    # Optional local LLM client (securityops.ai.llm.LocalLLM); None when disabled
    # or unavailable. Kept as object to keep core free of ai imports.
    llm: object | None = field(default=None)

    def set_active_project(self, project_id: int | None) -> None:
        self.active_project_id = project_id
