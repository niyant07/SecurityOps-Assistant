# Architecture

SecurityOps Assistant is a layered, plugin-driven desktop application. The
guiding rule is **dependencies point downward only**:

```
        ┌─────────────────────────────────────────────┐
        │                    gui/                      │  PySide6 windows, theme
        └───────────────┬─────────────────────────────┘
                        │ uses AppContext
        ┌───────────────▼─────────────────────────────┐
        │                  plugins/                    │  feature tabs
        └───────────────┬─────────────────────────────┘
                        │
   ┌────────────────────┼──────────────────────┬───────────────┐
   ▼                    ▼                       ▼               ▼
 core/                models/                  ai/           reporting/
 config, logging,     dataclasses +            offline       Jinja2 HTML,
 database, tasks,     enums                    assistant     PDF, Markdown
 tools, plugins,
 context
```

The **core** layer never imports `gui`, so it can be exercised headlessly
(`pytest` runs the whole core, models, ai, and reporting layers without Qt).

## Key components

### `core.context.AppContext`
The single dependency-injection seam. It bundles the long-lived services
(config, database, task manager, tool registry, assistant) and the active
project id. Plugins and widgets receive this object rather than constructing
their own services.

### `core.database.Database`
A thread-safe SQLite wrapper. One connection is guarded by an `RLock` and shared
across worker threads (`check_same_thread=False`). Entity access goes through
per-type repositories (`db.projects`, `db.assets`, `db.scans`, `db.findings`,
`db.evidence`) that map dataclass records to rows. WAL journaling and foreign
keys are enabled; the schema is versioned via `PRAGMA user_version`.

### `core.tasks`
Two primitives over Qt's `QThreadPool`:
- **`Worker`** runs any callable off the GUI thread and emits `result`/`error`/
  `finished` signals.
- **`CommandRunner`** wraps `QProcess` to stream a launched tool's output line by
  line, with cancellation.

`TaskManager` owns the pool and keeps strong references to active runners so
they are not garbage-collected mid-run.

### `core.tools`
A **data-driven catalog** of Kali tools (`CATALOG`). Each `ToolSpec` declares a
binary, category, description, and a command *template*. `ToolRegistry` detects
installed tools with `shutil.which` (+ config `extra_paths`) and renders
templates into **review-only** command strings. Commands are split with
`shlex.split` and executed via `QProcess` — **never** through a shell.

**Interactive/launch-only tools** (`ToolSpec.interactive=True`) — Burp Suite,
Wireshark, Metasploit console, Hashcat, Hydra, John the Ripper, and the
aircrack-ng suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`) —
are discoverable and launchable from the Tool Launcher tab, but are structurally
excluded from the AI Workflow's automated planner via `workflow.planner._MANUAL_ONLY`,
regardless of the goal text. This is deliberate, not an oversight: these tools
either require credentials/wordlists/capture files only the operator has, or (in
the wireless case) are active attacks with a blast radius beyond the declared
target — deauthentication disconnects every client on the access point, not just
a test device. No automated command-selection logic is permitted to reach them;
the operator must open the terminal and drive each step themselves.

### `core.plugins`
`PluginManager` discovers modules in `securityops.plugins` that expose either a
`PLUGIN` class or a `get_plugin(context)` factory, orders them by
`meta.priority`, and instantiates them. A faulty plugin is logged and skipped —
it cannot crash the app.

### `ai`
A deterministic, **fully offline** assistant. `Assistant.ask()` routes questions
to handlers via keyword regexes over a curated knowledge base
(`ai/knowledge.py`: assessment phases, remediation templates, CVSS bands). It is
advisory only: anything runnable is returned as a suggested command for the
operator, and a safety gate refuses to "auto-exploit".

### `reporting`
`ReportGenerator` renders a `ReportBundle` (project + findings + assets + scans +
evidence) to HTML (Jinja2), Markdown (hand-rolled), or PDF (WeasyPrint,
optional). Screenshots are embedded as base64 data URIs so HTML/PDF reports are
self-contained.

## Data & config locations

Resolved by `core.paths` following XDG on Linux:

| Purpose  | Linux path                                   |
|----------|----------------------------------------------|
| Config   | `~/.config/securityops/config.yaml`          |
| Database | `~/.local/share/securityops/securityops.db`  |
| Evidence | `~/.local/share/securityops/evidence/`       |
| Reports  | `~/.local/share/securityops/reports/`        |
| Logs     | `~/.local/state/securityops/logs/`           |

## Threading model

The GUI thread owns all widgets. Long-running work (tool execution) happens in
`QProcess`/pool threads; results are marshaled back to the GUI thread through Qt
signals. Widgets never block on I/O.

## Testing

`tests/` covers the headless layers (config, database, tools, assistant,
reporting). Qt-dependent modules are intentionally excluded so the suite runs
anywhere. Run with `python -m pytest`.
