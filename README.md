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
| **AI Workflow** | Plain-English goal → reviewable plan → approve → background run → findings → plain-English explanation |
| **Projects** | Create/manage engagements, stored in a local SQLite database |
| **Assets & Scope** | Inventory hosts/URLs, mark in-scope vs. out-of-scope |
| **Tool Launcher** | Auto-detects installed Kali tools; builds & launches commands |
| **Scan History** | Records every launched command, status, timing, and output |
| **Evidence** | Attach screenshots, files, and notes to findings |
| **Findings & Reporting** | Severity, CVSS, remediation, references → HTML/PDF/Markdown |
| **Assistant** | Offline knowledge base: explains tools, suggests next steps, drafts commands |
| **Plugins** | Drop-in modules add new tabs, tools, or report sections |

### AI Workflow (natural language → safe execution)

Type a goal such as *"Identify the IP address and open ports of my website
example.com"*. The assistant then:

1. Analyzes the request and **refuses** anything harmful (phishing, malware,
   ransomware, credential theft, DoS).
2. Resolves the target and proposes an **ordered plan** of Kali tools, each with
   a rationale and the exact command — built from vetted templates, never from
   raw model text.
3. Waits for you to **approve** the specific steps (checkbox per step).
4. Runs approved steps in the **background**, streaming live output.
5. **Highlights findings** (open ports, services, discovered paths, reported
   issues) in a dashboard.
6. **Explains** each step and the overall result in plain English.
7. Persists every executed command and its output for **audit**.

Planning and explanation use a **local LLM (Ollama)** when one is running on
`localhost`; if none is available the app falls back to deterministic rules and
remains fully functional offline.

## Architecture

```
securityops/
├── core/          Config, logging, SQLite database, threading, plugin & tool managers
├── models/        Typed dataclasses for Project, Asset, Scan, Finding, Evidence
├── workflow/      AI workflow: plan model, NL planner, output parsers, engine, explainer
├── plugins/       Built-in feature plugins (AI workflow, tool launcher, scans, reporting, ...)
├── ai/            Offline knowledge-base assistant + local LLM client (no cloud calls)
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

### Optional: local LLM for the AI Workflow tab

The AI Workflow tab works out of the box using deterministic rules. For more
fluent planning and explanations, run a **local** [Ollama](https://ollama.com)
model — no data leaves your machine:

```bash
# install Ollama (see ollama.com), then:
ollama pull llama3
ollama serve      # usually already running as a service
```

The app auto-detects Ollama on `localhost:11434`. Change the model/host under
the `llm:` section of `config.yaml`, or set `llm.enabled: false` to force
rules-only mode.

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

- No telemetry, no cloud APIs. The only network calls are (a) to a **local**
  LLM on `localhost` if you enable one, and (b) to the targets you choose to
  assess.
- All data stays in your local data directory.
- The AI planner **refuses** harmful objectives and never executes a step
  without explicit per-step approval; commands are built from vetted templates,
  not from raw model output.
- Every executed command and its output is persisted for audit.
- Tools are only launched when you explicitly approve/launch them; commands are
  always shown for review first.

## License

MIT — see headers. Provided "as is" for lawful, authorized use only.
