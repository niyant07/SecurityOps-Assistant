# SecurityOps Assistant

An **AI-assisted, non-destructive website security assessment tool** for targets you own
or are explicitly authorized to assess. Enter a domain, confirm authorization, and the
app:

1. **Gathers information** — DNS records, HTTP/HTTPS responses, the TLS certificate,
   HTTP security headers and visible technologies.
2. **Analyzes it with AI** — explains each finding, why it matters, its severity, the
   evidence behind it and how to fix it, separating *confirmed* findings from
   *potential* risks.
3. **Generates a report** — a professional HTML report (and PDF where WeasyPrint is
   installed).

It runs on your own machine as a local web page at `http://127.0.0.1:8765`.

> ⚖️ **Authorized use only.** Assess only systems you own or have written permission
> to test. The tool performs no exploitation, brute force, credential attacks,
> stealth or persistence — only the kind of requests a normal browser makes.

---

## Setup

Requirements: **Python 3.10+**. Node.js is only needed if you change the frontend.

**Windows (PowerShell)**

```powershell
cd SecurityOps-Assistant
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python -m securityops
```

**Linux / macOS**

```bash
cd SecurityOps-Assistant
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m securityops
```

(`scripts/install.ps1 -Run` and `scripts/install.sh --run` do the same in one step.)

The browser opens at `http://127.0.0.1:8765`. Options: `--port 9000`, `--no-browser`.
Stop the server with **Ctrl+C**.

### AI provider (optional)

The AI analysis uses the provider set in `securityops/config/default_config.yaml`
(override in your user config file, `~/.config/securityops/config.yaml` on Linux or
`%APPDATA%\securityops\config.yaml` on Windows):

| `llm.provider` | What you need |
|---|---|
| `ollama` (default) | A local model: install [Ollama](https://ollama.com), then `ollama pull llama3` and keep `ollama serve` running. Nothing leaves your machine. |
| `anthropic` | `pip install anthropic` and set the `ANTHROPIC_API_KEY` environment variable. Model: `llm.api_model` (default `claude-opus-5-5`). Keys are never stored in config files. |
| `none` | No AI; rule-based analysis only. |

If the provider is unavailable, the app still shows all scan results and a rule-based
analysis, with a message explaining what to fix.

### PDF reports (optional)

PDF export uses WeasyPrint (`pip install weasyprint`; it also needs system libraries
on Windows/macOS). Without it, export the HTML report and use the browser's
**Print → Save as PDF**.

---

## Using the app

The single screen has three sections:

1. **Information gathering** — type a target (`example.com`, `https://example.com`, or a
   lab address like `127.0.0.1:8080`), tick *“I own this target or have explicit
   permission”*, and click **Start Assessment**. A progress list shows each step.
   Results appear as DNS, HTTP/HTTPS, TLS, security headers and technologies.
2. **AI security analysis** — click **Run AI Analysis**. Each finding shows a severity,
   whether it is *Confirmed* or a *Potential risk*, the evidence, why it matters, and
   the remediation.
3. **Report** — **Export HTML Report**, **Export PDF**, or **Preview**.

### Scope

Besides the per-assessment authorization checkbox, you can restrict targets in the
config:

```yaml
assessment:
  allowed_targets: ["*.mylab.test", "127.0.0.1", "10.0.0.0/24"]  # empty = any confirmed target
  blocked_targets: ["admin.mylab.test"]                           # always refused
```

---

## Architecture

```
Browser (React single page)
   │  JSON over http://127.0.0.1 only
   ▼
securityops/web/            loopback HTTP server + 5 JSON endpoints
   │
   ▼
securityops/assessment/
   ├── gather.py    Component 1: parse target → DNS → HTTP/HTTPS → TLS →
   │                security headers → technologies → summary   (ScanResult)
   ├── analysis.py  Component 2: rule-based findings → LLM provider → validated merge
   │                (Analysis)
   └── report.py    Component 3: Jinja2 HTML report (+ PDF via WeasyPrint)
```

| Path | Purpose |
|---|---|
| `securityops/assessment/gather.py` | All information gathering. Uses `dnspython`, `urllib`, `ssl` and `socket` — no external command-line tools. |
| `securityops/assessment/analysis.py` | Rule-based findings, the `LLMProvider` interface (`OllamaProvider`, `AnthropicProvider`), the prompt, and validation of the model's answer. |
| `securityops/assessment/report.py` + `reporting/templates/assessment_report.html` | Report rendering. |
| `securityops/web/server.py` | HTTP server: loopback-only, rejects cross-site requests, serves the UI. |
| `securityops/web/state.py` | `AssessmentSession`: runs gathering and analysis in background threads, enforces scope. |
| `securityops/web/api.py` | Endpoints: `GET /api/status`, `POST /api/assess`, `POST /api/analyze`, `POST /api/reset`, `GET /api/report`. |
| `web-ui/src/App.jsx` | The single assessment screen (built into `securityops/web/dist`). |
| `securityops/config/default_config.yaml` | Timeouts, scope, AI provider, report details. |

### How the AI is kept safe and honest

1. The app **collects results first**. The model receives the results as text and
   returns text; it has no tools and **cannot run commands**.
2. Fixed rules produce the baseline findings, each with the exact evidence that
   triggered it (for example *“the response has no Content-Security-Policy header”*).
3. The model's JSON answer is **validated**. It may improve explanations and adjust
   severity, but it **cannot change evidence**, cannot mark its own ideas as
   *Confirmed* (anything it adds becomes a *Potential risk*), and cannot remove rule
   findings. Invalid answers are discarded and the rule-based analysis is shown.

### Other code in the repository

The repository also contains an earlier, broader PySide6 desktop application
(`python -m securityops.desktop`) with tool launching, bug bounty and disclosure
modules. It is optional and not needed for the workflow above.

### Frontend development

```bash
cd web-ui
npm install
npm run build      # writes the bundle into securityops/web/dist
```

---

## Testing

```bash
pip install pytest
python -m pytest
```

`tests/test_assessment.py` covers target validation, information gathering (against a
local test web server), rule findings, AI-answer validation, the fallback when the model
is unavailable, and report contents. `tests/test_web.py` runs the full
gather → analyze → report workflow through the web API and checks the authorization,
scope and cross-site request protections.

---

## Limitations

- Passive checks only: DNS, the home page over HTTP/HTTPS, and one TLS handshake. No
  crawling, login, port scanning or exploitation, so application flaws such as SQL
  injection or broken access control are **out of scope**.
- Technology detection relies on public hints and can be incomplete or wrong.
- Results are a snapshot from your network location; CDNs and firewalls can change
  what is seen.
- AI explanations are assistive and can be imperfect. *Potential risk* findings must be
  verified manually.
- Assesses one target at a time; results are kept in memory until you export the
  report.

---

## Safe demo procedure (for the presentation)

Use targets you control, so the demo is safe and repeatable.

**1. A local lab site (works offline).** In a second terminal, start Python's built-in
web server:

```bash
python -m http.server 8080 --bind 127.0.0.1
```

In the app, enter `127.0.0.1:8080`, tick the authorization box and click **Start
Assessment**. Expected results: HTTP 200, all security headers missing, and the
`Server: SimpleHTTP/... Python/...` header flagged as a version disclosure (*Potential
risk*). TLS shows *“No TLS service reachable”*, since the lab has no HTTPS.

**2. Show the AI analysis.** Click **Run AI Analysis**. With Ollama running you get the
AI explanation. To show the safety fallback, stop Ollama and run it again: the
rule-based results still appear, with a clear message.

**3. Export the report.** Click **Export HTML Report** and open it to walk through
scope, executive summary, findings and evidence, severity, remediation and
limitations.

**4. (Optional) A real HTTPS site you own**, such as your own GitHub Pages site or a
personal domain, to show DNS records and TLS certificate details.

**5. Show the guard rails.** Try to start without ticking the authorization box (the
button stays disabled), and add a `blocked_targets` entry to show a refused target.

**Points to explain in the viva:** the three components and how data flows between
them; why the model only analyses collected data (no command execution); how
*Confirmed* differs from *Potential risk*; and why the checks are non-destructive.
