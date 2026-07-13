# SecurityOps Assistant

An **offline, local-only** desktop application for **authorized** security
assessments, built for Kali Linux. It provides project management, an asset /
scope inventory, a Kali tool launcher, scan history, evidence collection, an
offline knowledge-base "AI" assistant, and professional HTML/PDF/Markdown
report generation — all running entirely on your machine with **no cloud
services**.

> ⚖️ **Authorized use only.** This tool is designed exclusively for security
> assessments of systems you own or for which you have **explicit written
> permission** to test. You are responsible for complying with all applicable
> laws and the terms of your engagement. The application never performs
> exploitation or attacks on its own — it organizes work and launches
> operator-approved tools.

---

## Features

| Area | Capability |
|------|-----------|
| **Projects** | Create/manage engagements, stored in a local SQLite database |
| **Assets & Scope** | Inventory hosts/URLs, mark in-scope vs. out-of-scope |
| **Tool Launcher** | Auto-detects installed Kali tools; builds & launches commands |
| **Scan History** | Records every launched command, status, timing, and output |
| **Evidence** | Attach screenshots, files, and notes to findings |
| **Findings & Reporting** | Severity, CVSS, remediation, references → HTML/PDF/Markdown |
| **Assistant** | Offline knowledge base: explains tools, suggests next steps, drafts commands |
| **Automation** | Repeatable recon / enum / vuln / web-app workflows |
| **Plugins** | Drop-in modules add new tabs, tools, or report sections |

## Architecture

```
securityops/
├── core/          Config, logging, SQLite database, threading, plugin & tool managers
├── models/        Typed dataclasses for Project, Asset, Scan, Finding, Evidence
├── plugins/       Built-in feature plugins (tool launcher, scans, reporting, ...)
├── ai/            Offline knowledge-base assistant (no network calls)
├── reporting/     Jinja2 → HTML/PDF/Markdown report generator
├── gui/           PySide6 dark-themed main window and widgets
├── config/        Default YAML configuration
└── tests/         Unit tests (pytest)
```

The application is layered: the **core** knows nothing about the GUI, the
**GUI** talks to core services, and **plugins** extend the GUI through a stable
registration API. This keeps the codebase modular and testable.

## Requirements

- **Python 3.12+**
- **PySide6 6.6+**
- Linux (Kali) recommended for full tool integration; the core and reporting
  layers are cross-platform.

## Installation

**Kali Linux (recommended, incl. inside a VirtualBox VM):** run the installer,
which installs required system/Qt libraries via `apt`, creates a `.venv/`, and
installs Python dependencies:

```bash
git clone https://github.com/niyant07/SecurityOps-Assistant.git
cd SecurityOps-Assistant
./scripts/install.sh          # installs everything
./scripts/install.sh --run    # installs, then launches the app immediately
```

**Manual / other platforms:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# or: python -m pip install -e ".[dev]"
```

## Running

```bash
python -m securityops
```

On first launch the app creates its data directory at
`~/.local/share/securityops/` (database, logs, evidence) and a config file at
`~/.config/securityops/config.yaml`.

## Testing

```bash
python -m pytest
```

## Configuration

Configuration is loaded from, in order of precedence:

1. `~/.config/securityops/config.yaml` (user overrides)
2. `securityops/config/default_config.yaml` (shipped defaults)

Environment variable `SECURITYOPS_CONFIG` may point to an alternate file.

## Security & Privacy

- No telemetry, no network requests, no cloud APIs.
- All data stays in your local data directory.
- The assistant is a static, offline knowledge base — it does not call any LLM.
- Tools are only launched when you explicitly click **Launch**; commands are
  shown for review first.

## License

MIT — see headers. Provided "as is" for lawful, authorized use only.
