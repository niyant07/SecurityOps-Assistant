"""Findings correlation & triage.

Turns the raw highlighted strings extracted from tool output into structured
*candidate* issues — each with a suggested title, severity, affected asset, and
evidence — flagged as requiring manual verification. Candidates are proposals,
not confirmed findings: the operator reviews them and promotes the real ones
into the project's Findings table (which then flow into the report).

Triage is deterministic and offline. If a local LLM is available it may be used
to enrich descriptions, but severity and classification never depend on it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Finding, Severity


@dataclass
class Candidate:
    """A potential security issue awaiting verification."""

    title: str
    severity: Severity
    description: str
    affected_asset: str
    source_tool: str
    evidence: str
    reproduction: str = ""
    references: str = ""
    requires_verification: bool = True
    #: Rough confidence 0-1 that this is worth reporting (for sorting).
    confidence: float = 0.5

    def to_finding(self, project_id: int) -> Finding:
        note = ("\n\n[Auto-triaged from tool output — verify manually before reporting.]"
                if self.requires_verification else "")
        return Finding(
            project_id=project_id,
            title=self.title,
            severity=self.severity,
            description=self.description + note,
            affected_asset=self.affected_asset,
            cvss_score=None,
            reproduction=self.reproduction,
            references=self.references,
        )


# --------------------------------------------------------------------------- #
# Classification rules
# --------------------------------------------------------------------------- #
_PORT = re.compile(r"Open port (\d+)/(tcp|udp) — (\S+)", re.I)
_OS = re.compile(r"^OS:\s*(.+)$", re.I)
_HTTP_PATH = re.compile(r"HTTP (\d{3}) — (/\S*)", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Services that warrant a closer look when exposed.
_SENSITIVE_SERVICES = {
    "telnet": Severity.MEDIUM, "ftp": Severity.MEDIUM, "microsoft-ds": Severity.MEDIUM,
    "smb": Severity.MEDIUM, "netbios-ssn": Severity.MEDIUM, "ms-wbt-server": Severity.MEDIUM,
    "rdp": Severity.MEDIUM, "vnc": Severity.MEDIUM, "rlogin": Severity.MEDIUM,
    "mysql": Severity.MEDIUM, "postgresql": Severity.MEDIUM, "mongodb": Severity.MEDIUM,
    "redis": Severity.MEDIUM, "memcached": Severity.MEDIUM,
}
# Web paths that are interesting if reachable.
_SENSITIVE_PATHS = ("/admin", "/.git", "/.env", "/backup", "/config", "/phpmyadmin",
                    "/wp-admin", "/server-status", "/actuator", "/debug")


def triage_step(source_tool: str, target: str, findings: list[str]) -> list[Candidate]:
    """Classify one step's highlighted findings into candidate issues."""
    out: list[Candidate] = []
    seen: set[tuple[str, str]] = set()

    for line in findings:
        cand = _classify(source_tool, target, line)
        if cand is None:
            continue
        key = (cand.title, cand.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(cand)
    return out


def triage_findings(steps: list) -> list[Candidate]:  # steps: list[WorkflowStep]
    """Triage all completed steps in a plan; returns candidates, most-severe first."""
    candidates: list[Candidate] = []
    for step in steps:
        if getattr(step, "findings", None):
            candidates.extend(triage_step(step.tool_key, step.target, step.findings))
    candidates.sort(key=lambda c: (c.severity.rank, c.confidence), reverse=True)
    return candidates


def _classify(tool: str, target: str, line: str) -> Candidate | None:
    text = line.strip()
    low = text.lower()

    m = _PORT.search(text)
    if m:
        port, proto, service = m.group(1), m.group(2), m.group(3).lower()
        sev = _SENSITIVE_SERVICES.get(service, Severity.LOW if service not in
                                      ("http", "https", "ssh") else Severity.INFO)
        return Candidate(
            title=f"Exposed service: {service} on port {port}/{proto}",
            severity=sev,
            description=f"Port {port}/{proto} is open and running '{service}'. "
                        f"Confirm the service is intended to be internet-facing and "
                        f"is patched and hardened.",
            affected_asset=target, source_tool=tool, evidence=text,
            reproduction=f"Run: nmap -sV -p {port} {target}",
            confidence=0.7 if sev.rank >= Severity.MEDIUM.rank else 0.4,
        )

    if _OS.search(text):
        return Candidate(
            title="Operating system / version disclosure",
            severity=Severity.INFO,
            description=f"Scanning disclosed OS details: {text}. Version disclosure "
                        f"can aid an attacker in targeting known vulnerabilities.",
            affected_asset=target, source_tool=tool, evidence=text, confidence=0.3)

    if _CVE.search(text):
        cves = ", ".join(sorted(set(_CVE.findall(text))))
        return Candidate(
            title="Potential known vulnerability (verify)",
            severity=Severity.HIGH,
            description=f"Tool output referenced {cves}. Manually verify whether the "
                        f"target is actually affected before reporting.",
            affected_asset=target, source_tool=tool, evidence=text,
            references=cves, confidence=0.6)

    if "directory indexing" in low or "index of /" in low:
        return Candidate(
            title="Directory listing enabled",
            severity=Severity.MEDIUM,
            description="The web server exposes directory listings, which can reveal "
                        "sensitive files. Disable auto-indexing.",
            affected_asset=target, source_tool=tool, evidence=text, confidence=0.7)

    if "header is not present" in low or re.search(r"x-frame-options|content-security|strict-transport", low):
        return Candidate(
            title="Missing or weak security header",
            severity=Severity.LOW,
            description=f"A security-relevant HTTP header appears missing/weak: {text}. "
                        f"Add appropriate headers (CSP, X-Frame-Options, HSTS).",
            affected_asset=target, source_tool=tool, evidence=text, confidence=0.6)

    m = _HTTP_PATH.search(text)
    if m:
        code, path = m.group(1), m.group(2).lower()
        if code in ("200", "301", "302", "401", "403") and any(p in path for p in _SENSITIVE_PATHS):
            return Candidate(
                title=f"Sensitive path reachable: {m.group(2)}",
                severity=Severity.MEDIUM,
                description=f"Content discovery found {m.group(2)} (HTTP {code}). "
                            f"Confirm whether this exposes administrative or sensitive "
                            f"functionality.",
                affected_asset=target, source_tool=tool, evidence=text,
                reproduction=f"Browse to {target.rstrip('/')}{m.group(2)}", confidence=0.65)
        return None

    if low.startswith("server:") or re.search(r"\b\d+\.\d+(\.\d+)?\b", low) and "nginx" in low or "apache" in low:
        return Candidate(
            title="Software / version banner disclosure",
            severity=Severity.INFO,
            description=f"A software banner or version was disclosed: {text}. Consider "
                        f"suppressing version banners.",
            affected_asset=target, source_tool=tool, evidence=text, confidence=0.3)

    return None
