# Writing a Plugin

Plugins add feature tabs without touching the core or GUI. A plugin is any
module in `securityops/plugins/` that exposes a `get_plugin(context)` factory
(or a `PLUGIN` class). The `PluginManager` discovers it at startup.

## Minimal example

Create `securityops/plugins/hello.py`:

```python
from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from ..core.plugins import PluginBase, PluginMeta


class HelloWidget(QWidget):
    def __init__(self, plugin: "HelloPlugin") -> None:
        super().__init__()
        self._ctx = plugin.context           # the AppContext
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Hello from a plugin!"))


class HelloPlugin(PluginBase):
    meta = PluginMeta(
        identifier="hello",                  # unique
        title="Hello",                       # tab label
        description="Demo plugin.",
        priority=200,                         # higher = further right
    )

    def create_widget(self) -> QWidget:
        self._widget = HelloWidget(self)
        return self._widget

    def on_project_changed(self, project_id: int | None) -> None:
        # Called whenever the active project changes. Reload your data here.
        ...


def get_plugin(context) -> HelloPlugin:
    return HelloPlugin(context)
```

Restart the app — a **Hello** tab appears automatically.

## The `AppContext`

Everything a plugin needs is on `self.context`:

| Attribute            | Type            | Use                                    |
|----------------------|-----------------|----------------------------------------|
| `config`             | `Config`        | dotted-key settings access             |
| `database`           | `Database`      | `.projects`, `.assets`, `.scans`, `.findings`, `.evidence` |
| `tasks`              | `TaskManager`   | run callables / external commands off-thread |
| `tools`              | `ToolRegistry`  | detected tools + command building      |
| `assistant`          | `Assistant`     | offline advisory helper (may be `None`)|
| `active_project_id`  | `int \| None`   | the currently selected project         |

## Lifecycle hooks

- `create_widget()` — build and return your tab's `QWidget` (lazy; called once).
- `on_project_changed(project_id)` — refresh your UI for the new project.
- `shutdown()` — release resources on app exit.

## Guidelines

- **Never run tools directly.** Use `context.tasks.run_command(program, argv)`
  and build commands via `context.tools`. Show the command for review first.
- **Respect scope.** Only operate on assets the user marked in-scope.
- **Fail safe.** Exceptions in a plugin are caught by the manager, but prefer to
  handle and surface errors in your own UI.
- **Stay off the GUI thread** for anything slow; marshal results back via Qt
  signals.
