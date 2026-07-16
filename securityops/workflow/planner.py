"""Natural-language goal -> reviewable workflow plan.

Two planners share one command-building core:

* :class:`RuleBasedPlanner` classifies the goal by keyword intent and selects
  ordered tools. Fully deterministic and offline.
* :class:`LLMPlanner` asks a local LLM to choose and order tools, validates its
  answer against the catalog, and falls back to the rule-based planner. Crucially
  the *commands themselves are always built from vetted templates* — the model
  only influences tool selection and ordering, never the executed string.

A safety guardrail refuses goals that request harmful actions before any
planning happens.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from ..core.logging_config import get_logger
from ..core.tools import MissingParameterError, ToolRegistry
from .plan import StepStatus, WorkflowPlan, WorkflowStep

_LOG = get_logger("workflow.planner")

# Default wordlist shipped with Kali; used for content-discovery tools.
_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

# Tools that are interactive/manual and must not be auto-run in a workflow.
_MANUAL_ONLY = {"burpsuite", "wireshark", "metasploit", "hashcat", "hydra",
                "john", "aircrack"}

# Steps built from these tools carry a disruptive-operation warning.
_DISRUPTIVE = {
    "sqlmap": "Active injection testing — only run against parameters you are "
              "explicitly authorized to test.",
    "gobuster": "Generates many requests (brute force) — may be noisy or trip rate limits.",
    "ffuf": "High-volume fuzzing — may be noisy or trip rate limits.",
    "dirsearch": "Many automated requests — may be noisy against production systems.",
}


# --------------------------------------------------------------------------- #
# Safety guardrail
# --------------------------------------------------------------------------- #
_HARMFUL_PATTERNS = re.compile(
    r"\b(phish\w*|ransomware|deploy\s+malware|keylog\w*|steal\s+(?:credential|password"
    r"|data)|exfiltrat\w*|ddos|denial[\s-]of[\s-]service|botnet|backdoor\s+(?:a|the|their)"
    r"|spread\s+(?:a\s+)?virus|crack\s+(?:someone|their|his|her))\b",
    re.I,
)


def _harmful_reason(goal: str) -> str | None:
    match = _HARMFUL_PATTERNS.search(goal)
    if match:
        return (f"This request appears to involve a prohibited action "
                f"(\"{match.group(0)}\"). This assistant only supports authorized, "
                f"non-destructive assessment of systems you own or may test.")
    return None


# --------------------------------------------------------------------------- #
# Intent classification
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Intent:
    name: str
    pattern: re.Pattern[str]
    tool_keys: tuple[str, ...]


# Order matters: earlier intents are placed earlier in the plan.
_INTENTS: tuple[Intent, ...] = (
    Intent("subdomains",
           re.compile(r"\b(subdomain|sub-domain|attack surface|dns enum|osint|harvest"
                      r"|email address)\w*", re.I),
           ("subfinder", "amass", "dnsrecon", "theharvester")),
    Intent("ports_services",
           re.compile(r"\b(port|open port|service|os detect|operating system|scan the "
                      r"(?:host|network|ip)|network scan|version)\w*", re.I),
           ("nmap", "naabu")),
    Intent("web_fingerprint",
           re.compile(r"\b(technolog|fingerprint|what.?s? running|cms|framework|web server"
                      r"|http probe|which server)\w*", re.I),
           ("httpx", "whatweb")),
    Intent("content_discovery",
           re.compile(r"\b(director|hidden (?:file|path)|content discover|endpoint|fuzz"
                      r"|brute.?force path|find (?:file|page)|admin panel)\w*", re.I),
           ("gobuster", "ffuf", "dirsearch")),
    Intent("web_vuln",
           re.compile(r"\b(web vuln|nikto|misconfig|security header|outdated software"
                      r"|vulnerab)\w*", re.I),
           ("nikto",)),
    Intent("sql_injection",
           re.compile(r"\b(sql inject|sqli|database (?:vuln|inject))\w*", re.I),
           ("sqlmap",)),
    Intent("known_exploits",
           re.compile(r"\b(known exploit|exploit.?db|searchsploit|public exploit)\w*", re.I),
           ("searchsploit",)),
)

# When a goal is generic ("assess my website", "check my server"), use a sensible
# default recon+enum chain.
_DEFAULT_WEB_CHAIN = ("nmap", "whatweb", "nikto")
_DEFAULT_HOST_CHAIN = ("nmap",)

_GENERIC = re.compile(r"\b(assess|audit|check|test|analyz|review|look at|security of)\w*", re.I)


# --------------------------------------------------------------------------- #
# Target extraction
# --------------------------------------------------------------------------- #
_URL_RE = re.compile(r"https?://[^\s]+", re.I)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


@dataclass
class Target:
    raw: str
    resolved_ip: str | None = None
    is_url: bool = False

    @property
    def display(self) -> str:
        if self.resolved_ip and self.resolved_ip != self.raw:
            return f"{self.raw} ({self.resolved_ip})"
        return self.raw


def extract_target(goal: str) -> Target | None:
    """Find the first URL, IP, or hostname in the goal and try to resolve it."""
    url = _URL_RE.search(goal)
    if url:
        return _resolve(Target(raw=url.group(0).rstrip("/,."), is_url=True))
    ip = _IP_RE.search(goal)
    if ip:
        return Target(raw=ip.group(0), resolved_ip=ip.group(0))
    host = _HOST_RE.search(goal)
    if host:
        return _resolve(Target(raw=host.group(0)))
    return None


def _resolve(target: Target) -> Target:
    host = target.raw
    if target.is_url:
        host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    try:
        target.resolved_ip = socket.gethostbyname(host)
    except (OSError, UnicodeError):
        _LOG.info("Could not resolve %s (offline or invalid); keeping hostname.", host)
    return target


def _host_only(target: Target) -> str:
    host = target.raw
    if target.is_url:
        host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    return host


# --------------------------------------------------------------------------- #
# Planners
# --------------------------------------------------------------------------- #
class RuleBasedPlanner:
    """Deterministic keyword-driven planner."""

    def __init__(self, tools: ToolRegistry) -> None:
        self._tools = tools

    def plan(self, goal: str) -> WorkflowPlan:
        reason = _harmful_reason(goal)
        if reason:
            _LOG.warning("Refused goal: %s", goal)
            return WorkflowPlan(goal=goal, summary="Request refused.",
                                refused=True, refusal_reason=reason)

        target = extract_target(goal)
        tool_keys = self._select_tools(goal)
        return self._assemble(goal, target, tool_keys, source="rules")

    def _select_tools(self, goal: str) -> list[str]:
        selected: list[str] = []
        for intent in _INTENTS:
            if intent.pattern.search(goal):
                selected.extend(intent.tool_keys)
        if not selected:
            chain = _DEFAULT_WEB_CHAIN if _looks_web(goal) else _DEFAULT_HOST_CHAIN
            selected.extend(chain)
        # De-duplicate preserving order, drop manual-only tools from auto-workflow.
        ordered: list[str] = []
        for key in selected:
            if key in _MANUAL_ONLY:
                continue
            if key not in ordered:
                ordered.append(key)
        return ordered

    def _assemble(self, goal: str, target: Target | None, tool_keys: list[str],
                  source: str) -> WorkflowPlan:
        if target is None:
            return WorkflowPlan(
                goal=goal,
                summary=("I couldn't find a target (hostname, IP, or URL) in your "
                         "request. Add one, e.g. 'scan example.com for open ports'."),
                source=source,
            )

        steps: list[WorkflowStep] = []
        skipped_missing: list[str] = []
        for key in tool_keys:
            detected = self._tools.get(key)
            if detected is None:
                continue
            if not detected.installed:
                skipped_missing.append(detected.spec.name)
                continue
            step = self._build_step(key, target, goal)
            if step is not None:
                steps.append(step)

        summary = self._summarize(target, steps, skipped_missing, source)
        return WorkflowPlan(goal=goal, summary=summary, steps=steps, source=source)

    def _build_step(self, key: str, target: Target, goal: str) -> WorkflowStep | None:
        spec = self._tools.get(key).spec  # type: ignore[union-attr]
        # Web tools want the URL; network tools want the host/IP.
        if key in {"httpx", "whatweb", "nikto", "gobuster", "ffuf", "dirsearch", "sqlmap"}:
            cmd_target = target.raw if target.is_url else f"http://{_host_only(target)}"
        else:
            cmd_target = _host_only(target)

        params = {"wordlist": _DEFAULT_WORDLIST}
        try:
            command = self._tools.build_command(key, cmd_target, params)
        except (MissingParameterError, KeyError) as exc:
            _LOG.warning("Skipping %s: %s", key, exc)
            return None

        return WorkflowStep(
            tool_key=key,
            title=f"{spec.name}: {spec.category.value}",
            rationale=self._rationale(key, spec.description),
            command=command,
            target=cmd_target,
            warning=_DISRUPTIVE.get(key, ""),
        )

    @staticmethod
    def _rationale(key: str, description: str) -> str:
        intro = {
            "nmap": "Discover live hosts, open ports, services and OS.",
            "naabu": "Quickly enumerate open ports before deeper scanning.",
            "subfinder": "Passively enumerate subdomains to map the attack surface.",
            "amass": "Enumerate DNS and related infrastructure in depth.",
            "dnsrecon": "Enumerate DNS records and check for zone transfers.",
            "theharvester": "Gather public OSINT (emails, hosts, names).",
            "httpx": "Probe which HTTP services are live and their basic tech.",
            "whatweb": "Fingerprint web technologies, CMS and server software.",
            "gobuster": "Discover hidden directories and files.",
            "ffuf": "Fuzz for content and parameters.",
            "dirsearch": "Scan for hidden web paths.",
            "nikto": "Check the web server for known issues and misconfigurations.",
            "sqlmap": "Test for SQL injection on authorized parameters.",
            "searchsploit": "Search the offline Exploit-DB for matching known exploits.",
        }.get(key)
        return intro or description

    @staticmethod
    def _summarize(target: Target, steps: list[WorkflowStep],
                   skipped: list[str], source: str) -> str:
        if not steps:
            base = (f"Target {target.display} identified, but none of the suitable "
                    f"tools are installed on this system.")
        else:
            names = ", ".join(dict.fromkeys(s.title.split(":")[0] for s in steps))
            base = (f"Plan for {target.display}: {len(steps)} step(s) using {names}. "
                    f"Review each command below and approve the steps you want to run.")
        if skipped:
            base += f" (Skipped, not installed: {', '.join(sorted(set(skipped)))}.)"
        if source == "llm":
            base += " [Tool selection assisted by local LLM.]"
        return base


class LLMPlanner:
    """LLM-assisted tool selection layered over the rule-based command builder."""

    _SYSTEM = (
        "You are a cybersecurity assessment planner. Given a user's goal, choose an "
        "ordered list of tools to run from the ALLOWED list only. You never write "
        "commands, only select tool keys. Refuse anything harmful. Respond with "
        "strict JSON: {\"tools\": [\"key1\", \"key2\"]}. Use only keys from the "
        "allowed list."
    )

    def __init__(self, llm, tools: ToolRegistry) -> None:  # noqa: ANN001
        self._llm = llm
        self._tools = tools
        self._rules = RuleBasedPlanner(tools)

    def plan(self, goal: str) -> WorkflowPlan:
        reason = _harmful_reason(goal)
        if reason:
            return WorkflowPlan(goal=goal, summary="Request refused.",
                                refused=True, refusal_reason=reason)

        if self._llm is None or not self._llm.available():
            return self._rules.plan(goal)

        allowed = [d.spec.key for d in self._tools.installed()
                   if d.spec.key not in _MANUAL_ONLY]
        prompt = (f"ALLOWED tools: {allowed}\n\nUser goal: {goal}\n\n"
                  "Return JSON with an ordered 'tools' list.")
        data = self._llm.generate_json(prompt, system=self._SYSTEM)

        keys = self._validate(data, allowed)
        if not keys:
            _LOG.info("LLM returned no usable tools; falling back to rules.")
            return self._rules.plan(goal)

        target = extract_target(goal)
        return self._rules._assemble(goal, target, keys, source="llm")

    @staticmethod
    def _validate(data: object, allowed: list[str]) -> list[str]:
        if not isinstance(data, dict):
            return []
        raw = data.get("tools")
        if not isinstance(raw, list):
            return []
        allowed_set = set(allowed)
        return [k for k in raw if isinstance(k, str) and k in allowed_set]


def _looks_web(goal: str) -> bool:
    return bool(_URL_RE.search(goal) or re.search(
        r"\b(website|web app|web application|http|url|site|domain)\b", goal, re.I))


def make_planner(tools: ToolRegistry, llm=None) -> RuleBasedPlanner | LLMPlanner:  # noqa: ANN001
    """Return an LLM planner if a local model is configured, else the rule planner."""
    if llm is not None:
        return LLMPlanner(llm, tools)
    return RuleBasedPlanner(tools)
