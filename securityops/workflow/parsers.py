"""Findings extraction from raw tool output.

Each parser takes the combined stdout/stderr of a tool run and returns a list of
short, human-readable "finding" strings worth highlighting (open ports, detected
services, OS guesses, discovered paths, reported vulnerabilities). Parsing is
best-effort and regex-based — it never fails the run, it just surfaces signal.
"""

from __future__ import annotations

import re
from typing import Callable

# A parser maps raw output -> list of highlighted findings.
Parser = Callable[[str], list[str]]

# --------------------------------------------------------------------------- #
# Individual tool parsers
# --------------------------------------------------------------------------- #
_NMAP_PORT = re.compile(r"^(\d{1,5})/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(.*)$", re.M)
_NMAP_OS = re.compile(r"^(?:OS details|Running|Aggressive OS guesses):\s*(.+)$", re.M)
_NMAP_HOST = re.compile(r"Nmap scan report for\s+(.+)")


def parse_nmap(output: str) -> list[str]:
    findings: list[str] = []
    for host in _NMAP_HOST.findall(output):
        findings.append(f"Host up: {host.strip()}")
    for port, proto, state, service, extra in _NMAP_PORT.findall(output):
        detail = f" {extra.strip()}" if extra.strip() else ""
        findings.append(f"Open port {port}/{proto} — {service}{detail}".rstrip())
    for os_line in _NMAP_OS.findall(output):
        findings.append(f"OS: {os_line.strip()}")
    return findings


_HTTPX_LINE = re.compile(r"https?://\S+")


def parse_httpx(output: str) -> list[str]:
    findings: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if _HTTPX_LINE.search(line):
            findings.append(line)
    return findings[:50]


def parse_whatweb(output: str) -> list[str]:
    findings: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line and ("http" in line.lower()):
            findings.append(line)
    return findings[:50]


_NIKTO_ITEM = re.compile(r"^\+\s+(.*)$", re.M)


def parse_nikto(output: str) -> list[str]:
    items = [m.strip() for m in _NIKTO_ITEM.findall(output)]
    # Prioritize lines that look like actual issues.
    interesting = [i for i in items if re.search(
        r"OSVDB|CVE|vulnerab|outdated|disclos|default|X-Frame|header|admin|/\w", i, re.I)]
    return (interesting or items)[:60]


_PATH_HIT = re.compile(r"\b(?:Status:\s*)?(200|201|204|301|302|307|401|403)\b.*?(/\S*)", re.I)


def parse_web_paths(output: str) -> list[str]:
    """Generic parser for gobuster/ffuf/dirsearch-style path discovery."""
    findings: list[str] = []
    for code, path in _PATH_HIT.findall(output):
        findings.append(f"HTTP {code} — {path}")
    return findings[:100]


_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def parse_searchsploit(output: str) -> list[str]:
    findings: list[str] = []
    for line in output.splitlines():
        if "|" in line and "/" in line:  # title | path format
            findings.append(line.strip())
    return findings[:60]


def parse_generic(output: str) -> list[str]:
    """Fallback parser: surface CVE mentions and obvious error lines."""
    findings: list[str] = []
    seen: set[str] = set()
    for cve in _CVE.findall(output):
        up = cve.upper()
        if up not in seen:
            seen.add(up)
            findings.append(f"Reference: {up}")
    return findings[:40]


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
_PARSERS: dict[str, Parser] = {
    "nmap": parse_nmap,
    "httpx": parse_httpx,
    "whatweb": parse_whatweb,
    "nikto": parse_nikto,
    "gobuster": parse_web_paths,
    "ffuf": parse_web_paths,
    "dirsearch": parse_web_paths,
    "searchsploit": parse_searchsploit,
}


def extract_findings(tool_key: str, output: str) -> list[str]:
    """Extract highlighted findings for *tool_key* from raw *output*."""
    if not output:
        return []
    parser = _PARSERS.get(tool_key, parse_generic)
    try:
        results = parser(output)
    except Exception:  # noqa: BLE001 - parsing must never break a run
        results = []
    if not results and parser is not parse_generic:
        results = parse_generic(output)
    return results
