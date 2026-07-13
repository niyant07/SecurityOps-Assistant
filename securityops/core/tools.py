"""Kali tool catalog, detection, and safe command building.

The catalog is data-driven: each :class:`ToolSpec` describes a tool, how to
detect it, its category, a short description, and a *template* used to build a
suggested command line. Templates never run automatically — they are shown to
the operator for review and only executed on an explicit action.

Detection uses :func:`shutil.which` plus any ``extra_paths`` from config.
"""

from __future__ import annotations

import shlex
import shutil
from dataclasses import dataclass, field
from enum import Enum

from .logging_config import get_logger

_LOG = get_logger("tools")


class ToolCategory(str, Enum):
    RECON = "Reconnaissance"
    ENUM = "Enumeration"
    WEB = "Web Application"
    VULN = "Vulnerability"
    EXPLOIT = "Exploitation (launch only)"
    PASSWORD = "Password / Hash"
    WIRELESS = "Wireless"
    TRAFFIC = "Traffic Analysis"


@dataclass(frozen=True)
class ToolSpec:
    """Static description of an external security tool."""

    key: str
    name: str
    binary: str
    category: ToolCategory
    description: str
    # {target} is substituted with the chosen target. Extra {placeholders} are
    # filled from the params dict passed to build_command().
    template: str = "{binary} {target}"
    # Interactive/console tools should be launched inside a terminal emulator.
    interactive: bool = False
    # Free-form usage / safety notes surfaced by the assistant.
    notes: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
CATALOG: tuple[ToolSpec, ...] = (
    ToolSpec(
        "nmap", "Nmap", "nmap", ToolCategory.RECON,
        "Network mapper: host discovery, port scanning, service/version and OS detection.",
        template="{binary} -sV -sC -oN {outfile} {target}",
        notes="Use -Pn if hosts block ping. -T4 speeds scans on reliable networks.",
    ),
    ToolSpec(
        "amass", "Amass", "amass", ToolCategory.RECON,
        "In-depth DNS enumeration and attack-surface mapping.",
        template="{binary} enum -d {target}",
    ),
    ToolSpec(
        "subfinder", "Subfinder", "subfinder", ToolCategory.RECON,
        "Passive subdomain discovery using public sources.",
        template="{binary} -d {target}",
    ),
    ToolSpec(
        "theharvester", "theHarvester", "theHarvester", ToolCategory.RECON,
        "Gather emails, subdomains, hosts and names from public sources (OSINT).",
        template="{binary} -d {target} -b all",
        aliases=("theharvester",),
    ),
    ToolSpec(
        "dnsrecon", "DNSRecon", "dnsrecon", ToolCategory.RECON,
        "DNS enumeration: records, zone transfers, brute force.",
        template="{binary} -d {target}",
    ),
    ToolSpec(
        "naabu", "Naabu", "naabu", ToolCategory.ENUM,
        "Fast SYN/CONNECT port scanner.",
        template="{binary} -host {target}",
    ),
    ToolSpec(
        "httpx", "httpx", "httpx", ToolCategory.ENUM,
        "Fast multi-purpose HTTP toolkit; probes live web servers.",
        template="{binary} -u {target} -sc -title -tech-detect",
    ),
    ToolSpec(
        "whatweb", "WhatWeb", "whatweb", ToolCategory.ENUM,
        "Website fingerprinting: CMS, frameworks, servers, versions.",
        template="{binary} {target}",
    ),
    ToolSpec(
        "gobuster", "Gobuster", "gobuster", ToolCategory.WEB,
        "Directory/file, DNS and vhost brute forcing.",
        template="{binary} dir -u {target} -w {wordlist}",
        notes="Requires a wordlist, e.g. /usr/share/wordlists/dirb/common.txt.",
    ),
    ToolSpec(
        "ffuf", "ffuf", "ffuf", ToolCategory.WEB,
        "Fast web fuzzer for content and parameter discovery.",
        template="{binary} -u {target}/FUZZ -w {wordlist}",
    ),
    ToolSpec(
        "dirsearch", "Dirsearch", "dirsearch", ToolCategory.WEB,
        "Web path scanner for hidden files and directories.",
        template="{binary} -u {target}",
    ),
    ToolSpec(
        "nikto", "Nikto", "nikto", ToolCategory.VULN,
        "Web server scanner for known vulnerabilities and misconfigurations.",
        template="{binary} -h {target}",
    ),
    ToolSpec(
        "sqlmap", "sqlmap", "sqlmap", ToolCategory.VULN,
        "Automated SQL injection detection and exploitation.",
        template="{binary} -u {target} --batch",
        notes="Only test parameters you are authorized to. --batch uses defaults.",
    ),
    ToolSpec(
        "searchsploit", "Searchsploit", "searchsploit", ToolCategory.VULN,
        "Offline search of the Exploit-DB archive.",
        template="{binary} {target}",
    ),
    ToolSpec(
        "burpsuite", "Burp Suite", "burpsuite", ToolCategory.WEB,
        "Web proxy / application security testing suite (launch only).",
        template="{binary}", interactive=True,
        notes="Launched only; configure your browser proxy to intercept traffic.",
        aliases=("burp",),
    ),
    ToolSpec(
        "wireshark", "Wireshark", "wireshark", ToolCategory.TRAFFIC,
        "Network protocol analyzer (launch only).",
        template="{binary}", interactive=True,
    ),
    ToolSpec(
        "metasploit", "Metasploit Console", "msfconsole", ToolCategory.EXPLOIT,
        "Exploitation framework — launches the interactive console only.",
        template="{binary}", interactive=True,
        notes="Console is launched for manual, authorized use. No auto-exploitation.",
        aliases=("msfconsole", "msf"),
    ),
    ToolSpec(
        "hashcat", "Hashcat", "hashcat", ToolCategory.PASSWORD,
        "GPU-accelerated password hash cracking.",
        template="{binary} -m {mode} {hashfile} {wordlist}", interactive=True,
    ),
    ToolSpec(
        "hydra", "Hydra", "hydra", ToolCategory.PASSWORD,
        "Online login brute-forcer for many protocols.",
        template="{binary} -L {userlist} -P {passlist} {target}", interactive=True,
    ),
    ToolSpec(
        "john", "John the Ripper", "john", ToolCategory.PASSWORD,
        "Offline password hash cracker.",
        template="{binary} {hashfile}", interactive=True,
        aliases=("johntheripper",),
    ),
    ToolSpec(
        "aircrack", "Aircrack-ng", "aircrack-ng", ToolCategory.WIRELESS,
        "Wireless WEP/WPA key recovery suite.",
        template="{binary} {capturefile}", interactive=True,
        aliases=("aircrack-ng",),
    ),
)

CATALOG_BY_KEY: dict[str, ToolSpec] = {spec.key: spec for spec in CATALOG}


@dataclass
class DetectedTool:
    """A catalog entry paired with its detection result."""

    spec: ToolSpec
    path: str | None

    @property
    def installed(self) -> bool:
        return self.path is not None


class MissingParameterError(ValueError):
    """Raised when a command template needs a placeholder that was not supplied."""


class ToolRegistry:
    """Detects installed tools and builds review-only command lines."""

    def __init__(self, extra_paths: list[str] | None = None) -> None:
        self._extra_paths = extra_paths or []
        self._detected: dict[str, DetectedTool] = {}
        self.refresh()

    def refresh(self) -> None:
        """Re-scan the system for each catalog tool."""
        search_path = self._build_search_path()
        for spec in CATALOG:
            path = shutil.which(spec.binary, path=search_path)
            if path is None:
                for alias in spec.aliases:
                    path = shutil.which(alias, path=search_path)
                    if path:
                        break
            self._detected[spec.key] = DetectedTool(spec=spec, path=path)
        installed = sum(1 for d in self._detected.values() if d.installed)
        _LOG.info("Tool detection complete: %d/%d installed", installed, len(CATALOG))

    def _build_search_path(self) -> str | None:
        import os

        parts = [p for p in self._extra_paths if p]
        env_path = os.environ.get("PATH", "")
        if env_path:
            parts.append(env_path)
        return os.pathsep.join(parts) if parts else None

    # -- queries ---------------------------------------------------------- #
    def all(self) -> list[DetectedTool]:
        return list(self._detected.values())

    def installed(self) -> list[DetectedTool]:
        return [d for d in self._detected.values() if d.installed]

    def by_category(self) -> dict[ToolCategory, list[DetectedTool]]:
        grouped: dict[ToolCategory, list[DetectedTool]] = {}
        for detected in self._detected.values():
            grouped.setdefault(detected.spec.category, []).append(detected)
        return grouped

    def get(self, key: str) -> DetectedTool | None:
        return self._detected.get(key)

    # -- command building ------------------------------------------------- #
    def build_command(self, key: str, target: str, params: dict[str, str] | None = None) -> str:
        """Render a tool's command template into a review-only command string.

        Raises
        ------
        KeyError: unknown tool key.
        MissingParameterError: a required ``{placeholder}`` was not provided.
        """
        detected = self._detected.get(key)
        if detected is None:
            raise KeyError(f"Unknown tool: {key}")

        spec = detected.spec
        binary = detected.path or spec.binary
        values: dict[str, str] = {"binary": binary, "target": target}
        values.update(params or {})

        try:
            return spec.template.format(**values).strip()
        except KeyError as exc:
            missing = str(exc).strip("'")
            raise MissingParameterError(
                f"Tool '{spec.name}' needs a value for '{{{missing}}}'."
            ) from exc

    @staticmethod
    def split_command(command: str) -> list[str]:
        """Safely split a command string into argv without invoking a shell."""
        return shlex.split(command)
